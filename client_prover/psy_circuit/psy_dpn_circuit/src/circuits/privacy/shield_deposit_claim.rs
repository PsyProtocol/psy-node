use plonky2::{
    field::extension::Extendable,
    gates::gate::GateRef,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::privacy::shield_deposit_claim::ShieldDepositClaimInput;
use psy_common_circuit::{
    builder::{
        hash::core::CircuitBuilderHashCore,
        pad_circuit::{pad_circuit_degree, CircuitBuilderPsyCommonGates},
    },
    circuits::traits::qstandard::QStandardCircuit,
    hash::merkle::gadgets::merkle_proof::{MerkleProofGadget, OptionalMerkleProofGadget},
    proof_minifier::pm_chain::PsyProofMinifierChain,
    u32::gates::comparison::ComparisonGate,
};
use psy_crypto::shield_address::SHIELD_ADDRESS_DOMAIN;

const DEPOSIT_TREE_HEIGHT: usize = 32;

#[derive(Debug)]
pub struct ShieldDepositClaimGadget {
    pub nullifier_secret: [Target; 4],
    pub note_secret_hash: [Target; 4],
    pub user_id: Target,
    pub r0: Target,
    pub r1: Target,
    pub deposit_index: Target,
    pub source_chain_index: Target,
    pub deposit_proof: MerkleProofGadget,
    pub deposit_root: HashOutTarget,
    pub nullifier_hash: HashOutTarget,
    pub shield_address: HashOutTarget,
    pub deposit_commitment: HashOutTarget,
    pub token_address_words: [Target; 8],
    pub l2_token_contract_id_words: [Target; 8],
    pub amount_words: [Target; 8],
}

impl ShieldDepositClaimGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let nullifier_secret = std::array::from_fn(|_| builder.add_virtual_target());
        let note_secret_hash = std::array::from_fn(|_| builder.add_virtual_target());
        let user_id = builder.add_virtual_target();
        let r0 = builder.add_virtual_target();
        let r1 = builder.add_virtual_target();
        let deposit_index = builder.add_virtual_target();
        let source_chain_index = builder.add_virtual_target();
        let token_address_words = std::array::from_fn(|_| builder.add_virtual_target());
        let l2_token_contract_id_words = std::array::from_fn(|_| builder.add_virtual_target());
        let amount_words = std::array::from_fn(|_| builder.add_virtual_target());
        let shield_domain = builder.constant(F::from_canonical_u64(SHIELD_ADDRESS_DOMAIN));
        let two_pow_32 = builder.constant(F::from_canonical_u64(1u64 << 32));
        let zero = builder.zero();

        let nullifier_hash = builder.hash_n_to_hash_no_pad::<H>(nullifier_secret.to_vec());
        let shield_address = builder.hash_n_to_hash_no_pad::<H>(vec![user_id, shield_domain, r0, r1]);

        for word in amount_words.iter().take(6) {
            builder.connect(*word, zero);
        }

        // Shield address words use [hi, lo] ordering matching relayer bytes32_to_u32x8.
        // Relayer reads shield_address from L1 as bytes32 BE:
        //   bytes[0..4]=elem0.hi, bytes[4..8]=elem0.lo, bytes[8..12]=elem1.hi, ...
        // No element reversal needed — the bytes32 encoding preserves [f0,f1,f2,f3] order.
        let shield_address_words: [Target; 8] = std::array::from_fn(|i| {
            let elem_idx = i / 2;
            let (low, high) = builder.split_low_high(shield_address.elements[elem_idx], 32, 64);
            if i % 2 == 0 { high } else { low }
        });
        let note_secret_hash_words: [Target; 8] = std::array::from_fn(|i| {
            let elem_idx = i / 2;
            let (low, high) = builder.split_low_high(note_secret_hash[elem_idx], 32, 64);
            if i % 2 == 0 { high } else { low }
        });
        let mut deposit_commitment_preimage = Vec::with_capacity(41);
        deposit_commitment_preimage.extend_from_slice(&shield_address_words);
        deposit_commitment_preimage.extend_from_slice(&token_address_words);
        deposit_commitment_preimage.extend_from_slice(&l2_token_contract_id_words);
        deposit_commitment_preimage.extend_from_slice(&amount_words);
        deposit_commitment_preimage.push(source_chain_index);
        deposit_commitment_preimage.extend_from_slice(&note_secret_hash_words);
        let deposit_commitment = builder.hash_n_to_hash_no_pad::<H>(deposit_commitment_preimage);
        let deposit_proof = MerkleProofGadget::add_virtual_to_with_options::<H, F, D>(
            builder,
            DEPOSIT_TREE_HEIGHT,
            OptionalMerkleProofGadget {
                root: None,
                value: Some(deposit_commitment),
                index: Some(deposit_index),
                siblings: None,
            },
        );
        let deposit_root = deposit_proof.root;

        let public_inputs_hash = builder.hash_n_to_hash_no_pad::<H>(vec![
            shield_address.elements[0],
            shield_address.elements[1],
            shield_address.elements[2],
            shield_address.elements[3],
            amount_words[0],
            amount_words[1],
            amount_words[2],
            amount_words[3],
            amount_words[4],
            amount_words[5],
            amount_words[6],
            amount_words[7],
            token_address_words[0],
            token_address_words[1],
            token_address_words[2],
            token_address_words[3],
            token_address_words[4],
            token_address_words[5],
            token_address_words[6],
            token_address_words[7],
            l2_token_contract_id_words[0],
            l2_token_contract_id_words[1],
            l2_token_contract_id_words[2],
            l2_token_contract_id_words[3],
            l2_token_contract_id_words[4],
            l2_token_contract_id_words[5],
            l2_token_contract_id_words[6],
            l2_token_contract_id_words[7],
            source_chain_index,
            deposit_root.elements[0],
            deposit_root.elements[1],
            deposit_root.elements[2],
            deposit_root.elements[3],
            nullifier_hash.elements[0],
            nullifier_hash.elements[1],
            nullifier_hash.elements[2],
            nullifier_hash.elements[3],
        ]);
        builder.register_public_inputs(&public_inputs_hash.elements);

        Self {
            nullifier_secret,
            note_secret_hash,
            user_id,
            r0,
            r1,
            deposit_index,
            source_chain_index,
            deposit_proof,
            deposit_root,
            nullifier_hash,
            shield_address,
            deposit_commitment,
            token_address_words,
            l2_token_contract_id_words,
            amount_words,
        }
    }

    pub fn set_witness<F: RichField>(&self, pw: &mut PartialWitness<F>, input: &ShieldDepositClaimInput<F>) -> anyhow::Result<()> {
        for (target, value) in self.nullifier_secret.iter().zip(input.nullifier_secret) {
            pw.set_target(*target, value)?;
        }
        for (target, value) in self.note_secret_hash.iter().zip(input.note_secret_hash) {
            pw.set_target(*target, value)?;
        }
        pw.set_target(self.user_id, F::from_canonical_u64(input.user_id))?;
        pw.set_target(self.r0, input.r0)?;
        pw.set_target(self.r1, input.r1)?;
        pw.set_target(self.deposit_index, F::from_canonical_u64(input.deposit_index))?;
        pw.set_target(self.source_chain_index, F::from_canonical_u64(input.source_chain_index as u64))?;
        for (target, word) in self.token_address_words.iter().zip(input.token_address) {
            pw.set_target(*target, F::from_canonical_u64(word as u64))?;
        }
        for (target, word) in self.l2_token_contract_id_words.iter().zip(input.l2_token_contract_id) {
            pw.set_target(*target, F::from_canonical_u64(word as u64))?;
        }
        for (target, word) in self.amount_words.iter().zip(input.amount) {
            pw.set_target(*target, F::from_canonical_u64(word as u64))?;
        }
        // The value is already constrained in-circuit as `deposit_commitment`
        // (passed as `value: Some(deposit_commitment)` to
        // `add_virtual_to_with_options`).  Because the option flag is set,
        // `set_witness_core_proof_q` correctly skips the value, and we must
        // NOT set it here either – doing so would overwrite wires that the
        // Poseidon hash already assigned, causing "set twice" failures.
        self.deposit_proof.set_witness_core_proof_q(pw, &input.deposit_proof)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct ShieldDepositClaimCircuit<C: GenericConfig<D>, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    gadget: ShieldDepositClaimGadget,
    pub circuit_data: CircuitData<C::F, C, D>,
    pub minifier_chain: PsyProofMinifierChain<D, C::F, C>,
}

impl<C: GenericConfig<D>, const D: usize> ShieldDepositClaimCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        let gadget = ShieldDepositClaimGadget::add_virtual_to::<C::Hasher, C::F, D>(&mut builder);
        builder.add_psy_type_b_common_gates();
        pad_circuit_degree::<C::F, D>(&mut builder, 11);
        let circuit_data = builder.build::<C>();
        let added_gates_for_minifier = [GateRef::new(ComparisonGate::new(32, 16))];
        let minifier_chain =
            PsyProofMinifierChain::<D, C::F, C>::new_add_gates(&circuit_data.verifier_only, &circuit_data.common, 2, Some(&added_gates_for_minifier));
        Self {
            gadget,
            circuit_data,
            minifier_chain,
        }
    }

    pub fn prove(&self, input: &ShieldDepositClaimInput<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();
        self.gadget.set_witness(&mut pw, input)?;
        let base_proof = self.circuit_data.prove(pw)?;
        let minified_proof = self.minifier_chain.prove(&base_proof)?;
        Ok(minified_proof)
    }
}

impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D> for ShieldDepositClaimCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        QHashOut(self.minifier_chain.get_fingerprint())
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        self.minifier_chain.get_verifier_data()
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        self.minifier_chain.get_common_data()
    }
}

#[cfg(test)]
mod tests {
    use super::ShieldDepositClaimCircuit;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use psy_client_common::data::qhashout::QHashOut;
    use psy_common_circuit::circuits::traits::qstandard::QStandardCircuit;

    #[test]
    fn shield_claim_fingerprint_matches_compiler_constant() {
        let circuit = ShieldDepositClaimCircuit::<PoseidonGoldilocksConfig, 2>::new();
        let actual = circuit.get_fingerprint();
        // The circuit fingerprint MUST match the hardcoded shield_claim_fingerprint in
        // psy-precompiles/token/src/main.psy. If this test fails, update the contract's
        // fingerprint constant AND the expected value below to match the circuit.
        let expected = QHashOut::from_values(
            9035274454396793746,
            3283101489055486651,
            5463948716196243646,
            10960400114419786825,
        );
        assert_eq!(actual, expected);
    }
}
