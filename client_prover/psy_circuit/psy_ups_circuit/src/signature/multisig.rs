use k256::ecdsa::{Signature, VerifyingKey};
use plonky2::{
    field::{goldilocks_field::GoldilocksField as F, secp256k1_base::Secp256K1Base, secp256k1_scalar::Secp256K1Scalar, types::Field},
    gates::gate::GateRef,
    hash::{hash_types::HashOutTarget, poseidon::{PoseidonHash, PoseidonPermutation}},
    iop::{target::{BoolTarget, Target}, witness::{PartialWitness, WitnessWrite}},
    plonk::{circuit_builder::CircuitBuilder, circuit_data::{CircuitConfig, CircuitData, VerifierOnlyCircuitData}, config::PoseidonGoldilocksConfig as C},
};
use psy_client_common::data::{base_types::hash256::Hash256, qhashout::QHashOut, secp256k1::CompressedPublicKey};
use psy_client_data::config::store_config::{PsyPlonky2Config, PsyProof};
use psy_common_circuit::{
    builder::{comparison::CircuitBuilderComparison, connect::CircuitBuilderConnectHelpers, hash::core::CircuitBuilderHashCore, pad_circuit::{pad_circuit_degree, CircuitBuilderPsyCommonGates}},
    crypto::secp256k1::{ecdsa::gadgets::biguint::{BigUintTarget, CircuitBuilderBiguint}, gadget::Secp256K1Gadget},
    hash::base_types::hash256bytes::WitnessHash256Bytes,
    proof_minifier::pm_chain::PsyProofMinifierChain,
    traits::CreatableTarget,
    u32::{arithmetic_u32::U32Target, gates::comparison::ComparisonGate},
};
use psy_config::{network_constants::PSY_NETWORK_MAGIC, DEFAULT_USER_STATE_TREE_ROOT_U64};
use psy_crypto::signature::secp256k1::wallet::{hash_no_pad_compressed_public_key, validate_compressed_secp256k1_public_key};
use psy_network_circuit::{gadgets::qdata::{user::PsyUserLeafGadget, user_contract_state::SignContextGadget}, ups::gadgets::ups_signature_data::PsyUserProvingSessionSignatureDataCompactGadget};
use psy_vm::ups::multisig::{MultisigPolicy, MultisigSignatureInput, MULTISIG_POLICY_CONTRACT_ID};

use super::{software_defined::{compute_sig_hash, set_sig_hash_witness}, state_reader::StateReaderGadget};

fn canonical_bits(builder: &mut CircuitBuilder<F, 2>, value: Target) -> Vec<BoolTarget> {
    let bits = builder.split_le(value, 64);
    let limbs = BigUintTarget { limbs: bits.chunks_exact(32).map(|chunk| U32Target(builder.le_sum(chunk.iter()))).collect() };
    let maximum = builder.constant_biguint(&(F::order() - 1u32));
    let canonical = builder.cmp_biguint(&limbs, &maximum);
    builder.assert_one(canonical.target);
    bits
}

fn bits_less_than(builder: &mut CircuitBuilder<F, 2>, a: &[BoolTarget], b: &[BoolTarget]) -> BoolTarget {
    let mut less = builder._false();
    for (&a, &b) in a.iter().zip(b) {
        let equal = builder.is_equal(a.target, b.target);
        let not_a = builder.not(a);
        let bit_less = builder.and(not_a, b);
        let lower_less = builder.and(equal, less);
        less = builder.or(bit_less, lower_less);
    }
    less
}

#[derive(Debug)]
struct MultisigPolicyTarget {
    version: Target,
    threshold: Target,
    member_count: Target,
    member_hashes: [HashOutTarget; 8],
    commitment: HashOutTarget,
}

impl MultisigPolicyTarget {
    fn add_virtual_to(builder: &mut CircuitBuilder<F, 2>) -> Self {
        let version = builder.add_virtual_target();
        let threshold = builder.add_virtual_target();
        let member_count = builder.add_virtual_target();
        builder.range_check(version, 32);
        let two = builder.constant(F::from_canonical_u8(2));
        let three = builder.constant(F::from_canonical_u8(3));
        builder.connect(threshold, two);
        builder.connect(member_count, three);
        builder.assert_non_zero(version);
        let capacity = builder.constant(F::from_canonical_u8(8));
        let member_hashes = core::array::from_fn(|_| builder.add_virtual_hash());
        let mut previous_bits: Option<Vec<BoolTarget>> = None;
        let one = builder.one();
        for (i, member) in member_hashes.iter().enumerate() {
            let index = builder.constant(F::from_canonical_usize(i));
            let active = builder.is_less_than(8, index, member_count);
            let inactive = builder.not(active);
            let is_zero = builder.is_zero_hash(*member);
            builder.connect(is_zero.target, inactive.target);
            let mut bits = Vec::with_capacity(256);
            // Limb zero is most significant in the policy's lexical ordering.
            for limb in member.elements.iter().rev() {
                bits.extend(canonical_bits(builder, *limb));
            }
            if let Some(previous) = previous_bits.as_ref() {
                let increasing = bits_less_than(builder, previous, &bits);
                builder.connect_if_true(active, increasing.target, one);
            }
            previous_bits = Some(bits);
        }
        let domain = builder.constant(F::from_canonical_u32(0x4d534750));
        let mut fields = vec![domain, version, threshold, member_count, capacity];
        fields.extend(member_hashes.iter().flat_map(|hash| hash.elements));
        let commitment = builder.hash_n_to_hash_no_pad::<PoseidonHash>(fields);
        let is_zero = builder.is_zero_hash(commitment);
        builder.assert_zero(is_zero.target);
        Self { version, threshold, member_count, member_hashes, commitment }
    }

    fn set_witness(&self, pw: &mut PartialWitness<F>, policy: &MultisigPolicy) -> anyhow::Result<()> {
        pw.set_target(self.version, F::from_canonical_u32(policy.version))?;
        pw.set_target(self.threshold, F::from_canonical_u8(policy.threshold))?;
        pw.set_target(self.member_count, F::from_canonical_u8(policy.member_count))?;
        for (target, member) in self.member_hashes.iter().zip(&policy.member_hashes) {
            pw.set_hash_target(*target, member.0)?;
        }
        Ok(())
    }
}

fn constrain_signature(builder: &mut CircuitBuilder<F, 2>, signature: &Secp256K1Gadget) {
    let coordinate_maximum = builder.constant_biguint(&(Secp256K1Base::order() - 1u32));
    let scalar_maximum = builder.constant_biguint(&(Secp256K1Scalar::order() - 1u32));
    let low_s_maximum = builder.constant_biguint(&(Secp256K1Scalar::order() >> 1usize));
    let zero = builder.zero_biguint();
    for coordinate in [&signature.public_key_x_target, &signature.public_key_y_target] {
        for limb in &coordinate.limbs {
            builder.range_check(limb.0, 32);
        }
        let canonical = builder.cmp_biguint(coordinate, &coordinate_maximum);
        builder.assert_one(canonical.target);
    }
    for scalar in [&signature.signature_r_target, &signature.signature_s_target] {
        for limb in &scalar.limbs {
            builder.range_check(limb.0, 32);
        }
        let canonical = builder.cmp_biguint(scalar, &scalar_maximum);
        builder.assert_one(canonical.target);
        let is_zero = builder.is_equal_biguint(scalar, &zero);
        builder.assert_zero(is_zero.target);
    }
    let low_s = builder.cmp_biguint(&signature.signature_s_target, &low_s_maximum);
    builder.assert_one(low_s.target);
}

fn constrain_policy_transition(
    builder: &mut CircuitBuilder<F, 2>,
    initial: &MultisigPolicyTarget,
    current: &MultisigPolicyTarget,
    ending: &MultisigPolicyTarget,
    start_slots: [HashOutTarget; 4],
    end_slots: [HashOutTarget; 4],
    start_leaf: &PsyUserLeafGadget,
) {
    let mut bootstrap = builder._true();
    for slot in start_slots {
        let empty = builder.is_zero_hash(slot);
        bootstrap = builder.and(bootstrap, empty);
    }
    let initialized = builder.not(bootstrap);
    let one = builder.one();
    let zero = builder.zero();
    builder.connect(initial.version, one);
    builder.connect_if_true(bootstrap, start_leaf.nonce, zero);
    let default_root = builder.constant_hash(plonky2::hash::hash_types::HashOut {
        elements: DEFAULT_USER_STATE_TREE_ROOT_U64.map(F::from_canonical_u64),
    });
    builder.connect_hashes_if_true(bootstrap, start_leaf.user_state_tree_root, default_root);
    let initial_header = HashOutTarget { elements: [initial.version, initial.threshold, initial.member_count, zero] };
    let current_header = HashOutTarget { elements: [current.version, current.threshold, current.member_count, zero] };
    let ending_header = HashOutTarget { elements: [ending.version, ending.threshold, ending.member_count, zero] };
    for (current, initial) in core::iter::once(current_header).chain(current.member_hashes[..3].iter().copied()).zip(core::iter::once(initial_header).chain(initial.member_hashes[..3].iter().copied())) {
        builder.connect_hashes_if_true(bootstrap, current, initial);
    }
    let current_slots = [current_header, current.member_hashes[0], current.member_hashes[1], current.member_hashes[2]];
    let ending_slots = [ending_header, ending.member_hashes[0], ending.member_hashes[1], ending.member_hashes[2]];
    for i in 0..4 {
        builder.connect_hashes_if_true(initialized, start_slots[i], current_slots[i]);
        builder.connect_hashes(end_slots[i], ending_slots[i]);
        builder.connect_hashes_if_true(bootstrap, ending_slots[i], current_slots[i]);
    }
    let mut same_members = builder._true();
    for i in 0..3 {
        let equal = builder.is_equal_hash(current.member_hashes[i], ending.member_hashes[i]);
        same_members = builder.and(same_members, equal);
    }
    builder.connect_if_true(same_members, ending.version, current.version);
    let changed = builder.not(same_members);
    let replacement = builder.and(initialized, changed);
    let next_version = builder.add(current.version, one);
    builder.connect_if_true(replacement, ending.version, next_version);
}

#[derive(Debug)]
pub struct MultisigSignatureCircuit {
    contract_id: Target,
    initial: MultisigPolicyTarget,
    current: MultisigPolicyTarget,
    ending: MultisigPolicyTarget,
    start_reader: StateReaderGadget<F, 2>,
    end_reader: StateReaderGadget<F, 2>,
    sig_data: PsyUserProvingSessionSignatureDataCompactGadget,
    sign_context: SignContextGadget,
    start_user_leaf: PsyUserLeafGadget,
    nonce: Target,
    signatures: [Secp256K1Gadget; 2],
    member_indices: [Target; 2],
    circuit_data: CircuitData<F, C, 2>,
    minifier_chain: PsyProofMinifierChain<2, F, C>,
}

impl MultisigSignatureCircuit {
    pub fn new() -> anyhow::Result<Self> {
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_ecc_config());
        let sig_data = PsyUserProvingSessionSignatureDataCompactGadget::add_virtual_to(&mut builder);
        let sign_context = SignContextGadget::add_virtual_to(&mut builder);
        let start_user_leaf = PsyUserLeafGadget::create_virtual(&mut builder);
        let nonce = builder.add_virtual_target();
        let sighash = compute_sig_hash(&mut builder, &sig_data, &sign_context, &start_user_leaf, nonce);
        let contract_id = builder.constant(F::from_canonical_u32(MULTISIG_POLICY_CONTRACT_ID));
        let mut start_reader = StateReaderGadget::new(&mut builder, 4);
        let mut end_reader = StateReaderGadget::new(&mut builder, 4);
        for (reader, leaf) in [(&mut start_reader, start_user_leaf), (&mut end_reader, sign_context.user_leaf)] {
            reader.state.user_leaf.connect_to_other(&mut builder, leaf);
            builder.connect(reader.state.contract_id, contract_id);
            builder.connect_hashes(reader.state.checkpoint_tree_root, sign_context.checkpoint_tree_root);
            builder.connect_hashes(reader.checkpoint_leaf_hash, sig_data.checkpoint_leaf_hash);
        }
        builder.connect(start_reader.state.checkpoint_id, end_reader.state.checkpoint_id);
        let zero_hash = builder.constant_hash(QHashOut::<F>::ZERO.0);
        let mut start_slots = [zero_hash; 4];
        let mut end_slots = [zero_hash; 4];
        for i in 0..4 {
            start_slots[i] = start_reader.get_self_user_current_contract_state_slot_hash(&mut builder, F::from_canonical_usize(i))?;
            end_slots[i] = end_reader.get_self_user_current_contract_state_slot_hash(&mut builder, F::from_canonical_usize(i))?;
        }
        for reader in [&start_reader, &end_reader] {
            for i in 1..4 {
                let first = &reader.merkel_proofs[0];
                let next = &reader.merkel_proofs[2 * i];
                builder.connect_hashes(first.value, next.value);
                for (first, next) in first.siblings.iter().zip(&next.siblings) {
                    builder.connect_hashes(*first, *next);
                }
            }
        }
        let initial = MultisigPolicyTarget::add_virtual_to(&mut builder);
        let current = MultisigPolicyTarget::add_virtual_to(&mut builder);
        let ending = MultisigPolicyTarget::add_virtual_to(&mut builder);
        constrain_policy_transition(&mut builder, &initial, &current, &ending, start_slots, end_slots, &start_user_leaf);
        let domain = builder.constant(F::from_canonical_u32(0x4d534741));
        let zero = builder.zero();
        let height = builder.constant(F::from_canonical_u8(4));
        let param = builder.hash_n_to_hash_no_pad::<PoseidonHash>([vec![domain, contract_id, zero, height], initial.commitment.elements.to_vec()].concat());
        let pi = builder.hash_two_to_one::<PoseidonHash>(sighash, param);
        builder.register_public_inputs(&pi.elements);
        let message_bytes: Vec<_> = sighash.elements.iter().flat_map(|limb| {
            canonical_bits(&mut builder, *limb).chunks_exact(8).map(|bits| builder.le_sum(bits.iter())).collect::<Vec<_>>()
        }).rev().collect();
        let signatures: [Secp256K1Gadget; 2] = core::array::from_fn(|_| {
            let signature = Secp256K1Gadget::add_virtual_to::<PoseidonHash, F, 2>(&mut builder, b"");
            constrain_signature(&mut builder, &signature);
            for (target, byte) in signature.msg_bytes_target.iter().zip(&message_bytes) {
                builder.range_check(*target, 8);
                builder.connect(*target, *byte);
            }
            signature
        });
        let member_indices: [Target; 2] = builder.add_virtual_target_arr();
        for i in 0..2 {
            builder.range_check(member_indices[i], 2);
            let in_range = builder.is_less_than(2, member_indices[i], current.member_count);
            builder.assert_one(in_range.target);
            if i > 0 {
                let increasing = builder.is_less_than(2, member_indices[i - 1], member_indices[i]);
                builder.assert_one(increasing.target);
            }
            for j in 0..3 {
                let index = builder.constant(F::from_canonical_usize(j));
                let selected = builder.is_equal(member_indices[i], index);
                builder.connect_hashes_if_true(selected, signatures[i].public_key_hash, current.member_hashes[j]);
            }
        }
        builder.add_psy_type_b_common_gates();
        pad_circuit_degree::<F, 2>(&mut builder, 11);
        let circuit_data = builder.build::<C>();
        let gates = [GateRef::new(ComparisonGate::new(32, 16))];
        let minifier_chain = PsyProofMinifierChain::new_add_gates(&circuit_data.verifier_only, &circuit_data.common, 2, Some(&gates));
        Ok(Self { contract_id, initial, current, ending, start_reader, end_reader, sig_data, sign_context, start_user_leaf, nonce, signatures, member_indices, circuit_data, minifier_chain })
    }

    pub fn prove(&self, input: &MultisigSignatureInput, sighash: QHashOut<F>) -> anyhow::Result<PsyProof> {
        let witness = &input.witness;
        let param = witness.account.public_key_param()?;
        let (current, _) = witness.policies()?;
        let signatures = &input.signatures;
        anyhow::ensure!(signatures.signatures.len() == 2, "multisig requires exactly two signatures");
        anyhow::ensure!(signatures.member_indices.len() == signatures.signatures.len(), "multisig signature/index count mismatch");
        let expected = witness.sig_data.get_sig_action_for_user::<PoseidonHash>(PSY_NETWORK_MAGIC, witness.sign_context.user_leaf.user_id, witness.nonce, witness.sign_context.clone()).get_qhash::<PoseidonHash>();
        anyhow::ensure!(expected == sighash, "multisig sighash mismatch");
        anyhow::ensure!(witness.start_state.state.user_leaf == witness.start_session_user_leaf, "multisig start state leaf mismatch");
        anyhow::ensure!(witness.end_state.state.user_leaf == witness.sign_context.user_leaf, "multisig end state leaf mismatch");
        for state in [&witness.start_state, &witness.end_state] {
            anyhow::ensure!(state.state.contract_id == F::from_canonical_u32(witness.account.contract_id), "multisig state contract mismatch");
            anyhow::ensure!(state.state.checkpoint_tree_root == witness.sign_context.checkpoint_tree_root, "multisig state checkpoint mismatch");
            anyhow::ensure!(state.state_cmds == self.start_reader.state_cmds, "multisig state commands mismatch");
            anyhow::ensure!(state.merkel_proofs.len() == 8 && state.aux_user_leaves.is_empty(), "multisig self-state proof shape mismatch");
            for (proof, target) in state.merkel_proofs.iter().zip(&self.start_reader.merkel_proofs) {
                anyhow::ensure!(proof.siblings.len() == target.siblings.len(), "multisig state proof height mismatch");
            }
        }
        use plonky2::plonk::config::Hasher;
        let public_key = QHashOut(PoseidonHash::two_to_one(self.get_fingerprint().0, param.0));
        anyhow::ensure!(witness.start_session_user_leaf.public_key == public_key && witness.sign_context.user_leaf.public_key == public_key, "multisig account identity mismatch");
        let message = Hash256::from(sighash);
        for (i, (&index, signature)) in signatures.member_indices.iter().zip(&signatures.signatures).enumerate() {
            anyhow::ensure!(index < 3, "multisig member index out of range");
            anyhow::ensure!(i == 0 || signatures.member_indices[i - 1] < index, "multisig member indices must strictly increase");
            anyhow::ensure!(signature.message == message, "multisig external signature message mismatch");
            let key = validate_compressed_secp256k1_public_key(CompressedPublicKey(signature.public_key))?;
            let commitment = hash_no_pad_compressed_public_key::<F, PoseidonPermutation<F>>(key);
            anyhow::ensure!(commitment == current.member_hashes[index as usize], "multisig signer is not the selected member");
            let scalar = Signature::from_slice(&signature.signature)?;
            anyhow::ensure!(scalar.normalize_s().is_none(), "multisig signature must use low-S form");
        }
        self.minifier_chain.prove(&self.circuit_data.prove(self.set_witness(input)?)?)
    }

    fn set_witness(&self, input: &MultisigSignatureInput) -> anyhow::Result<PartialWitness<F>> {
        let witness = &input.witness;
        let signatures = &input.signatures;
        anyhow::ensure!(signatures.signatures.len() == 2 && signatures.member_indices.len() == 2, "multisig requires exactly two indexed signatures");
        let (current, ending) = witness.policies()?;
        let decoded = signatures.signatures.iter().map(|signature| {
            VerifyingKey::from_sec1_bytes(&signature.public_key).map(|key| key.to_encoded_point(false))
        }).collect::<Result<Vec<_>, _>>()?;
        let mut pw = PartialWitness::new();
        pw.set_target(self.contract_id, F::from_canonical_u32(witness.account.contract_id))?;
        self.initial.set_witness(&mut pw, &witness.account.initial_policy)?;
        self.current.set_witness(&mut pw, &current)?;
        self.ending.set_witness(&mut pw, &ending)?;
        set_sig_hash_witness(&mut pw, &self.sig_data, &self.sign_context, self.nonce, &self.start_user_leaf, &witness.sig_data, &witness.sign_context, witness.nonce, &witness.start_session_user_leaf)?;
        self.start_reader.set_witness(&mut pw, &witness.start_state)?;
        self.end_reader.set_witness(&mut pw, &witness.end_state)?;
        pw.set_hash_target(self.start_reader.checkpoint_leaf_hash, witness.sig_data.checkpoint_leaf_hash.0)?;
        pw.set_hash_target(self.end_reader.checkpoint_leaf_hash, witness.sig_data.checkpoint_leaf_hash.0)?;
        for i in 0..2 {
            let source = i;
            let signature = &signatures.signatures[source];
            let key = decoded[source].as_bytes();
            let gadget = &self.signatures[i];
            pw.set_target(self.member_indices[i], F::from_canonical_u8(signatures.member_indices[source]))?;
            pw.set_hash256_bytes_target(&gadget.msg_bytes_target, &signature.message.0)?;
            for (target, bytes) in [(&gadget.public_key_x_target, &key[1..33]), (&gadget.public_key_y_target, &key[33..65]), (&gadget.signature_r_target, &signature.signature[..32]), (&gadget.signature_s_target, &signature.signature[32..])] {
                for (limb, bytes) in target.limbs.iter().zip(bytes.rchunks_exact(4)) {
                    pw.set_target(limb.0, F::from_canonical_u32(u32::from_be_bytes(bytes.try_into()?)))?;
                }
            }
        }
        Ok(pw)
    }

    pub fn get_fingerprint(&self) -> QHashOut<F> {
        QHashOut(self.minifier_chain.get_fingerprint())
    }

    pub fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<PsyPlonky2Config, 2> {
        self.minifier_chain.get_verifier_data()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::types::{Field64, PrimeField64};
    use psy_client_data::config::store_config::PsyHasher;

    fn policy(version: u32) -> MultisigPolicy {
        let mut member_hashes = [QHashOut::ZERO; 8];
        member_hashes[0] = QHashOut::from_values(1, 0, 0, 0);
        member_hashes[1] = QHashOut::from_values(2, 0, 0, 0);
        member_hashes[2] = QHashOut::from_values(3, 0, 0, 0);
        MultisigPolicy { version, threshold: 2, member_count: 3, member_hashes }
    }

    fn policy_proof(policy: &MultisigPolicy) -> anyhow::Result<()> {
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let target = MultisigPolicyTarget::add_virtual_to(&mut builder);
        builder.register_public_inputs(&target.commitment.elements);
        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        target.set_witness(&mut pw, policy)?;
        let proof = data.prove(pw)?;
        use plonky2::plonk::config::Hasher;
        let mut fields = vec![F::from_canonical_u32(0x4d534750), F::from_canonical_u32(policy.version), F::from_canonical_u8(policy.threshold), F::from_canonical_u8(policy.member_count), F::from_canonical_u8(8)];
        fields.extend(policy.member_hashes.iter().flat_map(|hash| hash.0.elements));
        anyhow::ensure!(proof.public_inputs == PoseidonHash::hash_no_pad(&fields).elements, "policy encoding mismatch");
        data.verify(proof)
    }

    #[test]
    fn policy_constraints_reject_duplicates_padding_and_threshold() {
        let valid = policy(1);
        policy_proof(&valid).unwrap();
        let mut duplicate = valid.clone();
        duplicate.member_hashes[1] = duplicate.member_hashes[0];
        assert!(policy_proof(&duplicate).is_err());
        let mut padding = valid.clone();
        padding.member_hashes[7] = padding.member_hashes[0];
        assert!(policy_proof(&padding).is_err());
        let mut threshold = valid.clone();
        threshold.threshold = 3;
        assert!(policy_proof(&threshold).is_err());
        let mut reversed = valid;
        reversed.member_hashes.swap(0, 1);
        assert!(policy_proof(&reversed).is_err());
    }

    #[test]
    fn canonical_decomposition_rejects_modulus_alias() {
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let value = builder.add_virtual_target();
        let bits = canonical_bits(&mut builder, value);
        let data = builder.build::<C>();
        let mut valid = PartialWitness::new();
        valid.set_target(value, F::ZERO).unwrap();
        data.verify(data.prove(valid).unwrap()).unwrap();
        let mut alias = PartialWitness::new();
        alias.set_target(value, F::ZERO).unwrap();
        for (i, bit) in bits.iter().enumerate() {
            alias.set_bool_target(*bit, (F::ORDER >> i) & 1 == 1).unwrap();
        }
        assert!(data.prove(alias).is_err());
    }

    fn transition_proof(current: &MultisigPolicy, ending: &MultisigPolicy, bootstrap: bool, clear: bool, nonce: u64) -> anyhow::Result<()> {
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let initial = MultisigPolicyTarget::add_virtual_to(&mut builder);
        let current_target = MultisigPolicyTarget::add_virtual_to(&mut builder);
        let ending_target = MultisigPolicyTarget::add_virtual_to(&mut builder);
        let start_slot = core::array::from_fn(|_| builder.add_virtual_hash());
        let end_slot = core::array::from_fn(|_| builder.add_virtual_hash());
        let leaf = PsyUserLeafGadget::create_virtual(&mut builder);
        constrain_policy_transition(&mut builder, &initial, &current_target, &ending_target, start_slot, end_slot, &leaf);
        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        initial.set_witness(&mut pw, &policy(1))?;
        current_target.set_witness(&mut pw, current)?;
        ending_target.set_witness(&mut pw, ending)?;
        for (i, slot) in policy_slots(current).iter().enumerate() {
            pw.set_hash_target(start_slot[i], if bootstrap { QHashOut::ZERO.0 } else { slot.0 })?;
        }
        for (i, slot) in policy_slots(ending).iter().enumerate() {
            pw.set_hash_target(end_slot[i], if clear { QHashOut::ZERO.0 } else { slot.0 })?;
        }
        pw.set_target(leaf.nonce, F::from_canonical_u64(nonce))?;
        pw.set_hash_target(leaf.user_state_tree_root, plonky2::hash::hash_types::HashOut { elements: DEFAULT_USER_STATE_TREE_ROOT_U64.map(F::from_canonical_u64) })?;
        // Unused leaf fields are not inputs to the policy transition relation.
        pw.set_hash_target(leaf.public_key, QHashOut::ZERO.0)?;
        for target in [leaf.balance, leaf.last_checkpoint_id, leaf.event_index, leaf.user_id] {
            pw.set_target(target, F::ZERO)?;
        }
        data.verify(data.prove(pw)?)
    }

    #[test]
    fn policy_transition_rejects_clear_rollback_overflow_and_bootstrap_replay() {
        transition_proof(&policy(1), &policy(1), true, false, 0).unwrap();
        transition_proof(&policy(2), &policy(2), false, false, 1).unwrap();
        let mut replacement = policy(3);
        replacement.member_hashes[2] = QHashOut::from_values(4, 0, 0, 0);
        transition_proof(&policy(2), &replacement, false, false, 1).unwrap();
        assert!(transition_proof(&policy(2), &policy(3), false, false, 1).is_err());
        assert!(transition_proof(&policy(2), &policy(1), false, false, 1).is_err());
        assert!(transition_proof(&policy(2), &policy(2), false, true, 1).is_err());
        assert!(transition_proof(&policy(u32::MAX), &policy(1), false, false, 1).is_err());
        assert!(transition_proof(&policy(1), &policy(1), true, false, 1).is_err());
        assert!(transition_proof(&policy(1), &policy(2), true, false, 0).is_err());
        let mut changed = policy(2);
        changed.member_hashes[2] = QHashOut::from_values(4, 0, 0, 0);
        assert!(transition_proof(&policy(2), &changed, false, false, 1).is_err());
        let mut overflow = changed.clone();
        overflow.version = 1;
        assert!(transition_proof(&policy(u32::MAX), &overflow, false, false, 1).is_err());
    }

    fn policy_slots(policy: &MultisigPolicy) -> [QHashOut<F>; 4] {
        [QHashOut::from_values(policy.version as u64, policy.threshold as u64, policy.member_count as u64, 0), policy.member_hashes[0], policy.member_hashes[1], policy.member_hashes[2]]
    }

    #[test]
    fn real_ecdsa_rejects_wrong_message_high_s_and_noncanonical_coordinates() {
        use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
        use psy_common_circuit::crypto::secp256k1::ecdsa::gadgets::biguint::WitnessBigUint;
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_ecc_config());
        let gadget = Secp256K1Gadget::add_virtual_to::<PoseidonHash, F, 2>(&mut builder, b"");
        constrain_signature(&mut builder, &gadget);
        let sighash = QHashOut::<F>::from_values(1, 2, 3, 4);
        let expected_message = Hash256::from(sighash);
        for (target, byte) in gadget.msg_bytes_target.iter().zip(expected_message.0) {
            let expected = builder.constant(F::from_canonical_u8(byte));
            builder.range_check(*target, 8);
            builder.connect(*target, expected);
        }
        let data = builder.build::<C>();
        let key = SigningKey::from_slice(&[7; 32]).unwrap();
        let signature: Signature = key.sign_prehash(&expected_message.0).unwrap();
        let point = key.verifying_key().to_encoded_point(false);
        let signature_bytes = signature.to_bytes();
        let make_witness = |message: &[u8; 32], high_s: bool, noncanonical_x: bool| -> anyhow::Result<PartialWitness<F>> {
            let mut pw = PartialWitness::new();
            pw.set_hash256_bytes_target(&gadget.msg_bytes_target, message)?;
            for (index, (target, bytes)) in [(&gadget.public_key_x_target, &point.as_bytes()[1..33]), (&gadget.public_key_y_target, &point.as_bytes()[33..65]), (&gadget.signature_r_target, &signature_bytes[..32]), (&gadget.signature_s_target, &signature_bytes[32..])].into_iter().enumerate() {
                let mut value = Secp256K1Scalar::order() * 0u32;
                for byte in bytes {
                    value = (value << 8usize) + u32::from(*byte);
                }
                if high_s && index == 3 {
                    value = Secp256K1Scalar::order() - value;
                }
                if noncanonical_x && index == 0 {
                    value = Secp256K1Base::order();
                }
                pw.set_biguint_target(target, &value)?;
            }
            Ok(pw)
        };
        data.verify(data.prove(make_witness(&expected_message.0, false, false).unwrap()).unwrap()).unwrap();
        assert!(data.prove(make_witness(&expected_message.0, true, false).unwrap()).is_err());
        assert!(data.prove(make_witness(&expected_message.0, false, true).unwrap()).is_err());
        let unreversed = sighash.to_le_bytes();
        assert!(data.prove(make_witness(&unreversed, false, false).unwrap()).is_err());
    }

    fn full_input(circuit: &MultisigSignatureCircuit, bootstrap: bool, revoked: bool) -> (MultisigSignatureInput, QHashOut<F>) {
        use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
        use plonky2::{hash::hash_types::HashOut, plonk::config::Hasher};
        use psy_client_data::qdata::{user::PsyUserLeaf, user_contract_state::{SignContext, UserContractState}, ups_signature::PsyUserProvingSessionSignatureDataCompact};
        use psy_crypto::{hash::{merkle::core::MerkleProofCore, traits::{hasher::MerkleZeroHasher, qhashable::QFieldHashable}}, signature::secp256k1::core::PsyCompressedSecp256K1Signature};
        use psy_vm::ups::{multisig::{MultisigAccount, MultisigSignatures, MultisigSignatureWitness}, state_reader::StateReaderResults};
        let mut keys: Vec<_> = (1u8..=4).map(|byte| {
            let key = SigningKey::from_slice(&[byte; 32]).unwrap();
            let compressed: [u8; 33] = key.verifying_key().to_encoded_point(true).as_bytes().try_into().unwrap();
            let member = hash_no_pad_compressed_public_key::<F, PoseidonPermutation<F>>(CompressedPublicKey(compressed));
            (member, key, compressed)
        }).collect();
        keys.sort_by_key(|(member, _, _)| member.0.elements.map(|limb| limb.to_canonical_u64()));
        let mut initial = policy(1);
        for (i, (member, _, _)) in keys.iter().take(3).enumerate() {
            initial.member_hashes[i] = *member;
        }
        let account = MultisigAccount { contract_id: MULTISIG_POLICY_CONTRACT_ID, initial_policy: initial.clone() };
        let mut current = initial.clone();
        let mut ending = initial;
        if !bootstrap {
            ending.version = 2;
            for i in 0..3 { ending.member_hashes[i] = keys[i + 1].0; }
        }
        if revoked {
            current = ending.clone();
        }
        let public_key = QHashOut(PoseidonHash::two_to_one(circuit.get_fingerprint().0, account.public_key_param().unwrap().0));
        let leaf = PsyUserLeaf {
            public_key, user_state_tree_root: QHashOut::ZERO, balance: F::ZERO,
            nonce: if bootstrap { F::ZERO } else { F::ONE }, last_checkpoint_id: F::ONE,
            event_index: F::ZERO, user_id: F::from_canonical_u64(9),
        };
        let state = |slots: [QHashOut<F>; 4], uninitialized: bool| {
            let mut leaves = vec![QHashOut::ZERO; 16];
            leaves[..4].copy_from_slice(&slots);
            let mut levels = vec![leaves];
            for height in 0..4 {
                let parents = levels[height].chunks_exact(2).map(|pair| QHashOut(PoseidonHash::two_to_one(pair[0].0, pair[1].0))).collect();
                levels.push(parents);
            }
            let slot_root = levels[4][0];
            let contract_siblings: Vec<_> = (0..psy_config::network_constants::GLOBAL_CONTRACT_TREE_HEIGHT as usize).map(|height| QHashOut(<PoseidonHash as MerkleZeroHasher<HashOut<F>>>::get_zero_hash(height))).collect();
            let contract_value = if uninitialized { QHashOut::ZERO } else { slot_root };
            let contract_proof = MerkleProofCore::new_from_params::<PsyHasher>(MULTISIG_POLICY_CONTRACT_ID as u64, contract_value, contract_siblings);
            let user_root = contract_proof.root;
            let mut user_leaf = leaf;
            user_leaf.user_state_tree_root = user_root;
            let mut proofs = Vec::new();
            for i in 0..4 {
                let siblings = (0..4).map(|height| levels[height][(i >> height) ^ 1]).collect();
                proofs.push(contract_proof.clone());
                proofs.push(MerkleProofCore::new_from_params::<PsyHasher>(i as u64, slots[i], siblings));
            }
            StateReaderResults {
                state: UserContractState { checkpoint_tree_root: QHashOut::ZERO, user_leaf, start_contract_state_root: slot_root, contract_id: F::from_canonical_u32(MULTISIG_POLICY_CONTRACT_ID), checkpoint_id: F::ONE },
                user_tree_root: QHashOut::ZERO, checkpoint: None, aux_user_leaves: vec![],
                state_cmds: circuit.start_reader.state_cmds.clone(), merkel_proofs: proofs,
            }
        };
        let start_state = state(if bootstrap { [QHashOut::ZERO; 4] } else { policy_slots(&current) }, bootstrap);
        let end_state = state(policy_slots(&ending), false);
        let start_session_user_leaf = start_state.state.user_leaf;
        let sign_context = SignContext { checkpoint_tree_root: QHashOut::ZERO, user_leaf: end_state.state.user_leaf };
        let nonce = leaf.nonce + F::ONE;
        let mut final_leaf = sign_context.user_leaf;
        final_leaf.nonce = nonce;
        let sig_data = PsyUserProvingSessionSignatureDataCompact {
            start_user_leaf_hash: start_session_user_leaf.qfhash::<PoseidonHash>(),
            end_user_leaf_hash: final_leaf.qfhash::<PoseidonHash>(), checkpoint_leaf_hash: QHashOut::ZERO,
            tx_stack_hash: QHashOut::from_values(11, 12, 13, 14), tx_count: F::ONE,
        };
        let sighash = sig_data.get_sig_action_for_user::<PoseidonHash>(PSY_NETWORK_MAGIC, leaf.user_id, nonce, sign_context).get_qhash::<PoseidonHash>();
        let message = Hash256::from(sighash);
        let signatures = [0usize, 2].map(|index| {
            let signature: Signature = keys[index].1.sign_prehash(&message.0).unwrap();
            PsyCompressedSecp256K1Signature { public_key: keys[index].2, signature: signature.to_bytes().into(), message }
        });
        (MultisigSignatureInput {
            witness: MultisigSignatureWitness { account, start_state, end_state, sig_data, sign_context, start_session_user_leaf, nonce },
            signatures: MultisigSignatures { member_indices: vec![0, 2], signatures: signatures.to_vec() },
        }, sighash)
    }

    #[test]
    fn four_field_bootstrap_rotation_and_forged_witnesses() {
        let circuit = MultisigSignatureCircuit::new().unwrap();
        for bootstrap in [true, false] {
            let (input, sighash) = full_input(&circuit, bootstrap, false);
            circuit.prove(&input, sighash).unwrap();
            // Bypass prove's signature checks to exercise the ECDSA/member relation.
            let mut duplicate = input.clone();
            duplicate.signatures.member_indices[1] = duplicate.signatures.member_indices[0];
            duplicate.signatures.signatures[1] = duplicate.signatures.signatures[0];
            assert!(circuit.set_witness(&duplicate).and_then(|pw| circuit.circuit_data.prove(pw)).is_err());
            let mut forged_slot = input.clone();
            forged_slot.witness.start_state.merkel_proofs[3].value = QHashOut::from_values(9, 9, 9, 9);
            assert!(forged_slot.witness.policies().is_err());
            let mut forged_relation = circuit.set_witness(&input).unwrap();
            let slot_target = circuit.start_reader.merkel_proofs[3].value.elements[0];
            forged_relation.target_values.insert(slot_target, F::from_canonical_u64(9));
            assert!(circuit.circuit_data.prove(forged_relation).is_err());
            let mut wrong_index = input.clone();
            wrong_index.witness.end_state.merkel_proofs[7].index = 2;
            assert!(wrong_index.witness.policies().is_err());
            let mut wrong_anchor = input.clone();
            wrong_anchor.witness.end_state.merkel_proofs[4].root = QHashOut::ZERO;
            assert!(wrong_anchor.witness.policies().is_err());
            let mut wrong_identity = input.clone();
            wrong_identity.witness.account.initial_policy.member_hashes[2] = QHashOut::from_values(u64::MAX - (1u64 << 32), 0, 0, 0);
            assert!(circuit.prove(&wrong_identity, sighash).is_err());
            for count in [0, 1, 3] {
                let mut wrong_count = input.clone();
                wrong_count.signatures.signatures.resize(count, input.signatures.signatures[0]);
                wrong_count.signatures.member_indices.resize(count, 0);
                assert!(circuit.set_witness(&wrong_count).is_err());
            }
            let mut substituted_start = input.clone();
            substituted_start.witness.start_state = input.witness.end_state.clone();
            assert!(circuit.set_witness(&substituted_start).and_then(|pw| circuit.circuit_data.prove(pw)).is_err());
            let mut wrong_message = input.clone();
            wrong_message.signatures.signatures[0].message.0.reverse();
            assert!(circuit.set_witness(&wrong_message).and_then(|pw| circuit.circuit_data.prove(pw)).is_err());
        }
        let (revoked, _) = full_input(&circuit, false, true);
        assert!(circuit.set_witness(&revoked).and_then(|pw| circuit.circuit_data.prove(pw)).is_err());
    }
}
