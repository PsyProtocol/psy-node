use parth_core::pgoldilocks::QHashOut;
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::Field},
    hash::{hash_types::{HashOut, HashOutTarget, RichField}, poseidon::PoseidonHash},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig, Hasher},
        proof::ProofWithPublicInputs,
    },
};
use psy_plonky2_basic_helpers::{
    builder::comparison::CircuitBuilderComparison,
    builder::connect::CircuitBuilderConnectHelpers,
    u32::gadgets::arithmetic_u32::{CircuitBuilderU32, U32Target},
};

use crate::hash::merkle::gadgets::merkle_proof::{MerkleProofGadget, OptionalMerkleProofGadget};
use crate::hash::keccak::keccak256_u32_words_be_abi;

const WORDS_PER_BYTES32: usize = 8;
pub const MAX_WITHDRAWAL_CLAIM_BATCH_SIZE: usize = 32;
pub const WITHDRAWAL_BATCH_CLAIM_SLOT_WORDS: usize = 34;
pub const WITHDRAWAL_BATCH_CLAIM_PUBLIC_INPUTS_WORDS: usize =
    WORDS_PER_BYTES32 + 2 + WORDS_PER_BYTES32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithdrawalBatchClaimSlotInputs<F: RichField> {
    pub sender_user_id: u32,
    pub recipient: [u32; WORDS_PER_BYTES32],
    pub token: [u32; WORDS_PER_BYTES32],
    pub amount: [u32; WORDS_PER_BYTES32],
    pub nonce: [u32; WORDS_PER_BYTES32],
    pub destination_chain_index: u32,
    pub leaf_index: u32,
    pub siblings: Vec<QHashOut<F>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithdrawalBatchClaimInputs<F: RichField> {
    pub withdrawal_root: QHashOut<F>,
    pub bridge_user_id: u32,
    pub withdrawals: Vec<WithdrawalBatchClaimSlotInputs<F>>,
}

#[derive(Debug)]
pub struct WithdrawalBatchClaimSlotTargets {
    pub sender_user_id: U32Target,
    pub recipient: [U32Target; WORDS_PER_BYTES32],
    pub token: [U32Target; WORDS_PER_BYTES32],
    pub amount: [U32Target; WORDS_PER_BYTES32],
    pub nonce: [U32Target; WORDS_PER_BYTES32],
    pub destination_chain_index: U32Target,
    pub leaf_index: U32Target,
    pub leaf_hash: HashOutTarget,
}

#[derive(Debug)]
pub struct WithdrawalBatchClaimCircuit<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub merkle_proofs: Vec<MerkleProofGadget>,
    pub slot_targets: Vec<WithdrawalBatchClaimSlotTargets>,
    pub withdrawal_root_target: HashOutTarget,
    pub real_count_target: U32Target,
    pub bridge_user_id_target: U32Target,
    pub circuit_data: CircuitData<C::F, C, D>,
}

impl<C: GenericConfig<D, F = GoldilocksField> + 'static, const D: usize>
    WithdrawalBatchClaimCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
    C::F: RichField + Extendable<D>,
{
    pub fn build(tree_height: usize) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let withdrawal_root_target = builder.add_virtual_hash();
        let real_count_target = builder.add_virtual_u32_target();
        let bridge_user_id_target = builder.add_virtual_u32_target();
        let max_batch_const = builder.constant(C::F::from_noncanonical_u64(MAX_WITHDRAWAL_CLAIM_BATCH_SIZE as u64));
        builder.ensure_is_less_than_or_equal(32, real_count_target.0, max_batch_const);

        let zero = builder.zero();
        let zero_hash = builder.constant_hash(HashOut::ZERO);

        let mut merkle_proofs = Vec::with_capacity(MAX_WITHDRAWAL_CLAIM_BATCH_SIZE);
        let mut slot_targets = Vec::with_capacity(MAX_WITHDRAWAL_CLAIM_BATCH_SIZE);
        let mut batch_commit_words =
            Vec::with_capacity(MAX_WITHDRAWAL_CLAIM_BATCH_SIZE * WITHDRAWAL_BATCH_CLAIM_SLOT_WORDS);

        for i in 0..MAX_WITHDRAWAL_CLAIM_BATCH_SIZE {
            let sender_user_id = builder.add_virtual_u32_target();
            let recipient = add_virtual_u32x8(&mut builder);
            let token = add_virtual_u32x8(&mut builder);
            let amount = add_virtual_u32x8(&mut builder);
            let nonce = add_virtual_u32x8(&mut builder);
            let destination_chain_index = builder.add_virtual_u32_target();
            let leaf_index = builder.add_virtual_u32_target();

            let leaf_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
                std::iter::once(sender_user_id.0)
                    .chain(recipient.iter().map(|v| v.0))
                    .chain(token.iter().map(|v| v.0))
                    .chain(amount.iter().map(|v| v.0))
                    .chain(nonce.iter().map(|v| v.0))
                    .chain(std::iter::once(destination_chain_index.0))
                    .collect::<Vec<_>>(),
            );
            let slot_data_words = std::iter::once(sender_user_id.0)
                .chain(recipient.iter().map(|v| v.0))
                .chain(token.iter().map(|v| v.0))
                .chain(amount.iter().map(|v| v.0))
                .chain(nonce.iter().map(|v| v.0))
                .chain(std::iter::once(destination_chain_index.0))
                .collect::<Vec<_>>();

            let merkle_proof = MerkleProofGadget::add_virtual_to_with_options::<PoseidonHash, C::F, D>(
                &mut builder,
                tree_height,
                OptionalMerkleProofGadget {
                    root: None,
                    value: Some(leaf_hash),
                    index: Some(leaf_index.0),
                    siblings: None,
                },
            );

            let slot_index = builder.constant(C::F::from_noncanonical_u64(i as u64));
            let is_active = builder.is_less_than(32, slot_index, real_count_target.0);
            let is_inactive = builder.not(is_active);

            builder.connect_hashes_if_true(is_active, merkle_proof.root, withdrawal_root_target);

            // Zero sender_user_id for inactive padding slots (P2 fix).
            // The loop below starts at recipient and omits sender_user_id.
            builder.connect_zero_if_true(is_inactive, sender_user_id.0);
            for word in recipient
                .iter()
                .chain(token.iter())
                .chain(amount.iter())
                .chain(nonce.iter())
            {
                builder.connect_zero_if_true(is_inactive, word.0);
            }
            builder.connect_zero_if_true(is_inactive, destination_chain_index.0);
            builder.connect_zero_if_true(is_inactive, leaf_index.0);
            for sibling in &merkle_proof.siblings {
                builder.connect_hashes_if_false(is_active, *sibling, zero_hash);
            }

            merkle_proofs.push(merkle_proof);
            batch_commit_words.extend(slot_data_words);
            slot_targets.push(WithdrawalBatchClaimSlotTargets {
                sender_user_id,
                recipient,
                token,
                amount,
                nonce,
                destination_chain_index,
                leaf_index,
                leaf_hash,
            });
        }

        let batch_commit = keccak256_u32_words_be_abi(&mut builder, &batch_commit_words);
        register_hash_pi_as_u32x8_internal::<C::F, D>(&mut builder, withdrawal_root_target);
        builder.register_public_inputs(&[real_count_target.0, bridge_user_id_target.0]);
        builder.register_public_inputs(&batch_commit.map(|x| x.0));

        let circuit_data = builder.build::<C>();
        Self {
            merkle_proofs,
            slot_targets,
            withdrawal_root_target,
            real_count_target,
            bridge_user_id_target,
            circuit_data,
        }
    }

    pub fn generate_proof(
        &self,
        inputs: &WithdrawalBatchClaimInputs<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        anyhow::ensure!(
            inputs.withdrawals.len() <= MAX_WITHDRAWAL_CLAIM_BATCH_SIZE,
            "invalid batch length: expected <= {}, got {}",
            MAX_WITHDRAWAL_CLAIM_BATCH_SIZE,
            inputs.withdrawals.len()
        );

        let mut pw = PartialWitness::new();
        pw.set_hash_target(self.withdrawal_root_target, inputs.withdrawal_root.0)?;
        pw.set_target(
            self.real_count_target.0,
            C::F::from_canonical_u32(inputs.withdrawals.len() as u32),
        )?;
        pw.set_target(
            self.bridge_user_id_target.0,
            C::F::from_canonical_u32(inputs.bridge_user_id),
        )?;

        for (i, merkle_proof) in self.merkle_proofs.iter().enumerate() {
            let slot = &self.slot_targets[i];
            if let Some(real) = inputs.withdrawals.get(i) {
                anyhow::ensure!(
                    real.siblings.len() == merkle_proof.siblings.len(),
                    "invalid sibling length for slot {}: expected {}, got {}",
                    i,
                    merkle_proof.siblings.len(),
                    real.siblings.len()
                );
                pw.set_target(slot.sender_user_id.0, C::F::from_canonical_u32(real.sender_user_id))?;
                set_u32x8_targets::<C::F>(&mut pw, &slot.recipient, &real.recipient)?;
                set_u32x8_targets::<C::F>(&mut pw, &slot.token, &real.token)?;
                set_u32x8_targets::<C::F>(&mut pw, &slot.amount, &real.amount)?;
                set_u32x8_targets::<C::F>(&mut pw, &slot.nonce, &real.nonce)?;
                pw.set_target(
                    slot.destination_chain_index.0,
                    C::F::from_canonical_u32(real.destination_chain_index),
                )?;
                pw.set_target(slot.leaf_index.0, C::F::from_canonical_u32(real.leaf_index))?;
                merkle_proof.set_witness(
                    &mut pw,
                    C::F::from_canonical_u32(real.leaf_index),
                    poseidon_hash_u32_words(
                        std::iter::once(real.sender_user_id as u64)
                            .chain(real.recipient.iter().copied().map(|v| v as u64))
                            .chain(real.token.iter().copied().map(|v| v as u64))
                            .chain(real.amount.iter().copied().map(|v| v as u64))
                            .chain(real.nonce.iter().copied().map(|v| v as u64))
                            .chain(std::iter::once(real.destination_chain_index as u64)),
                    ),
                    &real.siblings,
                )?;
            } else {
                let zero_words = [0u32; WORDS_PER_BYTES32];
                let zero_siblings = vec![QHashOut::ZERO; merkle_proof.siblings.len()];
                pw.set_target(slot.sender_user_id.0, C::F::ZERO)?;
                set_u32x8_targets::<C::F>(&mut pw, &slot.recipient, &zero_words)?;
                set_u32x8_targets::<C::F>(&mut pw, &slot.token, &zero_words)?;
                set_u32x8_targets::<C::F>(&mut pw, &slot.amount, &zero_words)?;
                set_u32x8_targets::<C::F>(&mut pw, &slot.nonce, &zero_words)?;
                pw.set_target(slot.destination_chain_index.0, C::F::ZERO)?;
                pw.set_target(slot.leaf_index.0, C::F::ZERO)?;
                merkle_proof.set_witness(
                    &mut pw,
                    C::F::ZERO,
                    poseidon_hash_u32_words(std::iter::empty()),
                    &zero_siblings,
                )?;
            }
        }

        self.circuit_data.prove(pw)
    }
}

fn add_virtual_u32x8<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> [U32Target; WORDS_PER_BYTES32] {
    builder.add_virtual_u32_targets(WORDS_PER_BYTES32).try_into().unwrap()
}

fn set_u32x8_targets<F: RichField>(
    pw: &mut PartialWitness<F>,
    targets: &[U32Target; WORDS_PER_BYTES32],
    values: &[u32; WORDS_PER_BYTES32],
) -> anyhow::Result<()> {
    for (target, value) in targets.iter().zip(values.iter()) {
        pw.set_target(target.0, F::from_canonical_u32(*value))?;
    }
    Ok(())
}

fn register_hash_pi_as_u32x8_internal<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    hash: HashOutTarget,
) {
    let words = hash_target_to_u32x8_internal(builder, hash).map(|x| x.0);
    builder.register_public_inputs(&words);
}

fn hash_target_to_u32x8_internal<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    hash: HashOutTarget,
) -> [U32Target; WORDS_PER_BYTES32] {
    let (a_low, a_high) = builder.split_low_high(hash.elements[0], 32, 64);
    let (b_low, b_high) = builder.split_low_high(hash.elements[1], 32, 64);
    let (c_low, c_high) = builder.split_low_high(hash.elements[2], 32, 64);
    let (d_low, d_high) = builder.split_low_high(hash.elements[3], 32, 64);
    [
        U32Target(a_low),
        U32Target(a_high),
        U32Target(b_low),
        U32Target(b_high),
        U32Target(c_low),
        U32Target(c_high),
        U32Target(d_low),
        U32Target(d_high),
    ]
}

fn poseidon_hash_u32_words<F: RichField>(words: impl IntoIterator<Item = u64>) -> QHashOut<F> {
    let felts = words
        .into_iter()
        .map(F::from_noncanonical_u64)
        .collect::<Vec<_>>();
    QHashOut(PoseidonHash::hash_no_pad(&felts))
}

#[cfg(test)]
mod tests {
    use parth_core::{
        crypto::hash::{merkle_proof::compute_root_merkle_proof_generic, traits::MerkleHasher},
        pgoldilocks::QHashOut,
    };
    use plonky2::{
        field::types::{Field, PrimeField64},
        hash::poseidon::PoseidonHash,
        plonk::config::PoseidonGoldilocksConfig,
    };

    use super::{
        poseidon_hash_u32_words, WithdrawalBatchClaimCircuit, WithdrawalBatchClaimInputs,
        WithdrawalBatchClaimSlotInputs, WITHDRAWAL_BATCH_CLAIM_PUBLIC_INPUTS_WORDS,
    };

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as plonky2::plonk::config::GenericConfig<D>>::F;

    fn sample_words(seed: u32) -> [u32; 8] {
        [seed, seed + 1, seed + 2, seed + 3, seed + 4, seed + 5, seed + 6, seed + 7]
    }

    fn zero_siblings(height: usize) -> Vec<QHashOut<F>> {
        let mut siblings = Vec::with_capacity(height);
        let mut current = QHashOut::ZERO;
        for _ in 0..height {
            siblings.push(current);
            current = QHashOut(PoseidonHash::two_to_one(&current.0, &current.0));
        }
        siblings
    }

    #[test]
    fn withdrawal_batch_claim_circuit_proves_single_real_slot() {
        let circuit = WithdrawalBatchClaimCircuit::<C, D>::build(32);
        let recipient = sample_words(10);
        let token = sample_words(100);
        let amount = [0, 0, 0, 0, 0, 0, 0, 123];
        let sender_user_id = 42;
        let nonce = sample_words(77);
        let destination_chain_index = 0;
        let leaf_index = 0;
        let siblings = zero_siblings(32);
        let leaf = poseidon_hash_u32_words(
            std::iter::once(sender_user_id as u64)
                .chain(recipient.iter().copied().map(|v| v as u64))
                .chain(token.iter().copied().map(|v| v as u64))
                .chain(amount.iter().copied().map(|v| v as u64))
                .chain(nonce.iter().copied().map(|v| v as u64))
                .chain(std::iter::once(destination_chain_index as u64)),
        );
        let root = compute_root_merkle_proof_generic::<QHashOut<F>, PoseidonHash>(
            leaf,
            leaf_index as u64,
            &siblings,
        );
        let inputs = WithdrawalBatchClaimInputs::<F> {
            withdrawal_root: root,
            bridge_user_id: 524_288,
            withdrawals: vec![WithdrawalBatchClaimSlotInputs {
                sender_user_id,
                recipient,
                token,
                amount,
                nonce,
                destination_chain_index,
                leaf_index,
                siblings,
            }],
        };

        let proof = circuit.generate_proof(&inputs).unwrap();
        assert_eq!(
            proof.public_inputs.len(),
            WITHDRAWAL_BATCH_CLAIM_PUBLIC_INPUTS_WORDS
        );
    }

    #[test]
    fn withdrawal_batch_claim_circuit_zeroes_dummy_slots_in_public_inputs() {
        let circuit = WithdrawalBatchClaimCircuit::<C, D>::build(32);
        let recipient = sample_words(1);
        let token = sample_words(11);
        let amount = [0, 0, 0, 0, 0, 0, 0, 9];
        let sender_user_id = 7;
        let nonce = sample_words(1);
        let destination_chain_index = 0;
        let siblings = zero_siblings(32);
        let leaf = poseidon_hash_u32_words(
            std::iter::once(sender_user_id as u64)
                .chain(recipient.iter().copied().map(|v| v as u64))
                .chain(token.iter().copied().map(|v| v as u64))
                .chain(amount.iter().copied().map(|v| v as u64))
                .chain(nonce.iter().copied().map(|v| v as u64))
                .chain(std::iter::once(destination_chain_index as u64)),
        );
        let root = compute_root_merkle_proof_generic::<QHashOut<F>, PoseidonHash>(leaf, 0, &siblings);
        let inputs = WithdrawalBatchClaimInputs::<F> {
            withdrawal_root: root,
            bridge_user_id: 524_288,
            withdrawals: vec![WithdrawalBatchClaimSlotInputs {
                sender_user_id,
                recipient,
                token,
                amount,
                nonce,
                destination_chain_index,
                leaf_index: 0,
                siblings,
            }],
        };
        let proof = circuit.generate_proof(&inputs).unwrap();
        assert_eq!(proof.public_inputs.len(), WITHDRAWAL_BATCH_CLAIM_PUBLIC_INPUTS_WORDS);
    }
}
