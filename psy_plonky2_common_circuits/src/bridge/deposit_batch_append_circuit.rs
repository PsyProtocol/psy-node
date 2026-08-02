use parth_core::pgoldilocks::{PoseidonHasher, QHashOut};
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::{Field, PrimeField64}},
    hash::{hash_types::{HashOut, HashOutTarget, RichField}, poseidon::PoseidonHash},
    iop::{target::{BoolTarget, Target}, witness::{PartialWitness, WitnessWrite}},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig, Hasher},
        proof::ProofWithPublicInputs,
    },
};
use psy_plonky2_basic_helpers::{
    builder::{
        comparison::CircuitBuilderComparison, connect::CircuitBuilderConnectHelpers,
        select::CircuitBuilderSelectHelpers,
    },
    u32::gadgets::arithmetic_u32::{CircuitBuilderU32, U32Target},
};

use crate::{
    hash::{
        keccak::keccak256_u32_words_be_abi,
        merkle::gadgets::frontier_append::{compute_new_frontier, derive_frontier_siblings, FrontierAppendGadget},
    },
};

const WORDS_PER_BYTES32: usize = 8;
const TREE_HEIGHT_32: usize = 32;
pub const MAX_DEPOSIT_BATCH_SIZE: usize = 32;
pub const DEPOSIT_BATCH_APPEND_SLOT_WORDS: usize = 8 + 8 + 8 + 8 + 1 + 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositLeafData {
    pub shield_address: [u32; WORDS_PER_BYTES32],
    pub token: [u32; WORDS_PER_BYTES32],
    pub l2_token_contract_id: [u32; WORDS_PER_BYTES32],
    pub amount: [u32; WORDS_PER_BYTES32],
    pub chain_index: u32,
    pub note_commitment: [u32; WORDS_PER_BYTES32],
}

impl DepositLeafData {
    pub fn to_u32_words(&self) -> Vec<u32> {
        [
            self.shield_address.as_slice(),
            self.token.as_slice(),
            self.l2_token_contract_id.as_slice(),
            self.amount.as_slice(),
        ]
        .into_iter()
        .flatten()
        .copied()
        .chain([self.chain_index])
        .chain(self.note_commitment)
        .collect()
    }
}

pub fn compute_batch_slot_data_words(deposits: &[DepositLeafData]) -> Vec<u32> {
    let zero_deposit = DepositLeafData {
        shield_address: [0; WORDS_PER_BYTES32],
        token: [0; WORDS_PER_BYTES32],
        l2_token_contract_id: [0; WORDS_PER_BYTES32],
        amount: [0; WORDS_PER_BYTES32],
        chain_index: 0,
        note_commitment: [0; WORDS_PER_BYTES32],
    };
    let mut out = Vec::with_capacity(MAX_DEPOSIT_BATCH_SIZE * DEPOSIT_BATCH_APPEND_SLOT_WORDS);
    for i in 0..MAX_DEPOSIT_BATCH_SIZE {
        out.extend(
            deposits
                .get(i)
                .unwrap_or(&zero_deposit)
                .to_u32_words(),
        );
    }
    out
}

#[derive(Debug, Clone)]
pub struct BatchAppendInputs<F: RichField> {
    pub frontier: [QHashOut<F>; TREE_HEIGHT_32],
    pub from_index: u32,
    pub deposits: Vec<DepositLeafData>,
    pub bridge_user_id: u32,
}

#[derive(Debug, Clone)]
pub struct BatchAppendPreimage {
    pub old_root: QHashOut<GoldilocksField>,
    pub new_root: QHashOut<GoldilocksField>,
    pub from_index: u32,
    pub to_index: u32,
    pub effective_leaf_hashes: [[u32; WORDS_PER_BYTES32]; MAX_DEPOSIT_BATCH_SIZE],
    pub old_frontier: [QHashOut<GoldilocksField>; TREE_HEIGHT_32],
    pub new_frontier: [QHashOut<GoldilocksField>; TREE_HEIGHT_32],
    pub bridge_user_id: u32,
    pub batch_commit: [u32; WORDS_PER_BYTES32],
}

impl BatchAppendPreimage {
    pub fn to_u32_words(&self) -> Vec<u32> {
        let mut out = Vec::with_capacity(18 + MAX_DEPOSIT_BATCH_SIZE * 8 + TREE_HEIGHT_32 * 16 + 1 + 8);
        out.extend(qhash_to_u32x8_le_words(self.old_root));
        out.extend(qhash_to_u32x8_le_words(self.new_root));
        out.push(self.from_index);
        out.push(self.to_index);
        for i in 0..MAX_DEPOSIT_BATCH_SIZE {
            out.extend(self.effective_leaf_hashes[i]);
        }
        for frontier in &self.old_frontier {
            out.extend(qhash_to_u32x8_le_words(*frontier));
        }
        for frontier in &self.new_frontier {
            out.extend(qhash_to_u32x8_le_words(*frontier));
        }
        out.push(self.bridge_user_id);
        out.extend(self.batch_commit);
        out
    }
}

pub fn compute_batch_append_preimage(inputs: &BatchAppendInputs<GoldilocksField>) -> BatchAppendPreimage {
    let old_frontier = inputs.frontier;
    let old_root = frontier_root(&old_frontier, inputs.from_index);
    let mut current_frontier = old_frontier;
    let mut current_index = inputs.from_index;
    let mut effective_leaf_hashes = [[0u32; WORDS_PER_BYTES32]; MAX_DEPOSIT_BATCH_SIZE];
    let zero_deposit = DepositLeafData {
        shield_address: [0; WORDS_PER_BYTES32],
        token: [0; WORDS_PER_BYTES32],
        l2_token_contract_id: [0; WORDS_PER_BYTES32],
        amount: [0; WORDS_PER_BYTES32],
        chain_index: 0,
        note_commitment: [0; WORDS_PER_BYTES32],
    };
    let mut batch_commit_words =
        Vec::with_capacity(MAX_DEPOSIT_BATCH_SIZE * DEPOSIT_BATCH_APPEND_SLOT_WORDS);

    for i in 0..MAX_DEPOSIT_BATCH_SIZE {
        let deposit = inputs.deposits.get(i).unwrap_or(&zero_deposit);
        let leaf_hash = poseidon_hash_u32_words(deposit.to_u32_words().iter().map(|v| *v as u64));
        batch_commit_words.extend(deposit.to_u32_words());
        if i < inputs.deposits.len() {
            effective_leaf_hashes[i] = qhash_to_u32x8_le_words(leaf_hash);
            current_frontier = compute_new_frontier::<QHashOut<GoldilocksField>, PoseidonHasher>(
                &current_frontier,
                current_index as u64,
                leaf_hash,
            )
            .try_into()
            .unwrap();
            current_index += 1;
        } else {
            effective_leaf_hashes[i] = qhash_to_u32x8_le_words(QHashOut::<GoldilocksField>::ZERO);
        }
    }
    let batch_commit = keccak_u32_words_be(&batch_commit_words);

    BatchAppendPreimage {
        old_root,
        new_root: frontier_root(&current_frontier, current_index),
        from_index: inputs.from_index,
        to_index: current_index,
        effective_leaf_hashes,
        old_frontier,
        new_frontier: current_frontier,
        bridge_user_id: inputs.bridge_user_id,
        batch_commit,
    }
}

#[derive(Debug, Clone)]
pub struct DepositLeafTargets {
    pub shield_address: [Target; WORDS_PER_BYTES32],
    pub token: [Target; WORDS_PER_BYTES32],
    pub l2_token_contract_id: [Target; WORDS_PER_BYTES32],
    pub amount: [Target; WORDS_PER_BYTES32],
    pub chain_index: Target,
    pub note_commitment: [Target; WORDS_PER_BYTES32],
}

impl DepositLeafTargets {
    fn add_virtual<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self {
            shield_address: builder.add_virtual_targets(WORDS_PER_BYTES32).try_into().unwrap(),
            token: builder.add_virtual_targets(WORDS_PER_BYTES32).try_into().unwrap(),
            l2_token_contract_id: builder.add_virtual_targets(WORDS_PER_BYTES32).try_into().unwrap(),
            amount: builder.add_virtual_targets(WORDS_PER_BYTES32).try_into().unwrap(),
            chain_index: builder.add_virtual_target(),
            note_commitment: builder.add_virtual_targets(WORDS_PER_BYTES32).try_into().unwrap(),
        }
    }

    fn to_targets(&self) -> Vec<Target> {
        [
            self.shield_address.as_slice(),
            self.token.as_slice(),
            self.l2_token_contract_id.as_slice(),
            self.amount.as_slice(),
        ]
        .into_iter()
        .flatten()
        .copied()
        .chain([self.chain_index])
        .chain(self.note_commitment)
        .collect()
    }

    fn set_witness<F: RichField>(
        &self,
        pw: &mut PartialWitness<F>,
        value: &DepositLeafData,
    ) -> anyhow::Result<()> {
        for (target, word) in self.shield_address.iter().zip(value.shield_address.iter()) {
            pw.set_target(*target, F::from_canonical_u32(*word))?;
        }
        for (target, word) in self.token.iter().zip(value.token.iter()) {
            pw.set_target(*target, F::from_canonical_u32(*word))?;
        }
        for (target, word) in self
            .l2_token_contract_id
            .iter()
            .zip(value.l2_token_contract_id.iter())
        {
            pw.set_target(*target, F::from_canonical_u32(*word))?;
        }
        for (target, word) in self.amount.iter().zip(value.amount.iter()) {
            pw.set_target(*target, F::from_canonical_u32(*word))?;
        }
        pw.set_target(self.chain_index, F::from_canonical_u32(value.chain_index))?;
        for (target, word) in self.note_commitment.iter().zip(value.note_commitment.iter()) {
            pw.set_target(*target, F::from_canonical_u32(*word))?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct DepositBatchAppendCircuit<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub frontier_gadgets: Vec<FrontierAppendGadget>,
    pub active_targets: Vec<BoolTarget>,
    pub leaf_targets: Vec<DepositLeafTargets>,
    pub leaf_hash_targets: Vec<HashOutTarget>,
    pub old_root_target: HashOutTarget,
    pub new_root_target: HashOutTarget,
    pub old_frontier_targets: Vec<HashOutTarget>,
    pub new_frontier_targets: Vec<HashOutTarget>,
    pub from_index_target: Target,
    pub actual_batch_len_target: Target,
    pub to_index_target: Target,
    pub bridge_user_id_target: Target,
    pub circuit_data: CircuitData<C::F, C, D>,
}

impl<C: GenericConfig<D, F = GoldilocksField> + 'static, const D: usize> DepositBatchAppendCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
    C::F: RichField + Extendable<D>,
{
    pub fn build(max_batch_size: usize, tree_height: usize) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let from_index_target = builder.add_virtual_target();
        let actual_batch_len_target = builder.add_virtual_target();
        let bridge_user_id_target = builder.add_virtual_target();
        let max_batch_const = builder.constant(C::F::from_noncanonical_u64(max_batch_size as u64));
        builder.ensure_is_less_than_or_equal(32, actual_batch_len_target, max_batch_const);
        let one = builder.one();
        let zero = builder.zero();
        let zero_hash = builder.constant_hash(HashOut::ZERO);

        let mut frontier_gadgets = Vec::with_capacity(max_batch_size);
        let mut active_targets = Vec::with_capacity(max_batch_size);
        let mut leaf_targets = Vec::with_capacity(max_batch_size);
        let mut leaf_hash_targets = Vec::with_capacity(max_batch_size);
        let mut effective_leaf_hash_targets = Vec::with_capacity(max_batch_size);
        let mut batch_commit_words = Vec::with_capacity(max_batch_size * 41);

        let mut first_old_root = None;
        let mut last_effective_root = None;
        let mut first_old_frontier = None;
        let mut last_effective_frontier: Option<Vec<HashOutTarget>> = None;
        let mut current_index = from_index_target;

        for i in 0..max_batch_size {
            let leaf = DepositLeafTargets::add_virtual(&mut builder);
            let leaf_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(leaf.to_targets());
            let gadget = FrontierAppendGadget::add_virtual_to::<PoseidonHash, PoseidonHasher, C::F, D>(&mut builder, tree_height);
            let slot_index = builder.constant(C::F::from_noncanonical_u64(i as u64));
            let is_active = builder.is_less_than(32, slot_index, actual_batch_len_target);

            for limb in 0..4 {
                builder.connect(gadget.leaf_hash.elements[limb], leaf_hash.elements[limb]);
            }
            builder.connect(gadget.index, current_index);

            if let Some(prev_root) = last_effective_root {
                builder.connect_hashes(gadget.old_root, prev_root);
            } else {
                first_old_root = Some(gadget.old_root);
            }

            if let Some(prev_frontier) = last_effective_frontier.clone() {
                for (old_target, prev_target) in gadget.old_frontier.iter().zip(prev_frontier.iter()) {
                    builder.connect_hashes(*old_target, *prev_target);
                }
            } else {
                first_old_frontier = Some(gadget.old_frontier.clone());
            }

            let effective_leaf_hash = builder.select_hash(is_active, leaf_hash, zero_hash);
            let effective_new_root = builder.select_hash(is_active, gadget.new_root, gadget.old_root);
            let effective_new_frontier = gadget
                .new_frontier
                .iter()
                .zip(gadget.old_frontier.iter())
                .map(|(new_hash, old_hash)| builder.select_hash(is_active, *new_hash, *old_hash))
                .collect::<Vec<_>>();

            let slot_data_words = leaf.to_targets();
            let is_inactive = builder.not(is_active);
            for word in &slot_data_words {
                builder.connect_zero_if_true(is_inactive, *word);
            }

            let incremented_index = builder.add(current_index, one);
            current_index = builder.select(is_active, incremented_index, current_index);

            active_targets.push(is_active);
            leaf_hash_targets.push(leaf_hash);
            effective_leaf_hash_targets.push(effective_leaf_hash);
            batch_commit_words.extend(slot_data_words);
            last_effective_root = Some(effective_new_root);
            last_effective_frontier = Some(effective_new_frontier);
            leaf_targets.push(leaf);
            frontier_gadgets.push(gadget);
        }

        let old_root_target = first_old_root.unwrap();
        let new_root_target = last_effective_root.unwrap_or(old_root_target);
        let old_frontier_targets = first_old_frontier.unwrap_or_default();
        let new_frontier_targets = last_effective_frontier.unwrap_or_default();
        let to_index_target = current_index;

        let mut preimage_words = Vec::with_capacity(18 + max_batch_size * 8 + TREE_HEIGHT_32 * 16 + 1 + 8);
        preimage_words.extend(hash_target_to_u32x8_le(&mut builder, old_root_target).map(|x| x.0));
        preimage_words.extend(hash_target_to_u32x8_le(&mut builder, new_root_target).map(|x| x.0));
        preimage_words.push(from_index_target);
        preimage_words.push(to_index_target);
        for i in 0..max_batch_size {
            preimage_words.extend(hash_target_to_u32x8_le(&mut builder, effective_leaf_hash_targets[i]).map(|x| x.0));
        }
        for frontier in &old_frontier_targets {
            preimage_words.extend(hash_target_to_u32x8_le(&mut builder, *frontier).map(|x| x.0));
        }
        for frontier in &new_frontier_targets {
            preimage_words.extend(hash_target_to_u32x8_le(&mut builder, *frontier).map(|x| x.0));
        }
        preimage_words.push(bridge_user_id_target);
        let batch_commit = keccak256_u32_words_be_abi(&mut builder, &batch_commit_words);
        preimage_words.extend(batch_commit.map(|word| word.0));

        let commitment_words = keccak256_u32_words_be_abi(&mut builder, &preimage_words);
        builder.register_public_inputs(&commitment_words.map(|word| word.0));

        let circuit_data = builder.build::<C>();
        Self {
            frontier_gadgets,
            active_targets,
            leaf_targets,
            leaf_hash_targets,
            old_root_target,
            new_root_target,
            old_frontier_targets,
            new_frontier_targets,
            from_index_target,
            actual_batch_len_target,
            to_index_target,
            bridge_user_id_target,
            circuit_data,
        }
    }

    pub fn generate_proof(
        &self,
        inputs: &BatchAppendInputs<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        anyhow::ensure!(
            inputs.deposits.len() <= self.leaf_targets.len(),
            "batch size overflow: max {}, got {}",
            self.leaf_targets.len(),
            inputs.deposits.len()
        );

        let mut pw = PartialWitness::new();
        pw.set_target(
            self.from_index_target,
            C::F::from_canonical_u32(inputs.from_index),
        )?;
        pw.set_target(
            self.bridge_user_id_target,
            C::F::from_canonical_u32(inputs.bridge_user_id),
        )?;
        pw.set_target(
            self.actual_batch_len_target,
            C::F::from_canonical_u32(inputs.deposits.len() as u32),
        )?;

        let zero_deposit = DepositLeafData {
            shield_address: [0; WORDS_PER_BYTES32],
            note_commitment: [0; WORDS_PER_BYTES32],
            token: [0; WORDS_PER_BYTES32],
            l2_token_contract_id: [0; WORDS_PER_BYTES32],
            amount: [0; WORDS_PER_BYTES32],
            chain_index: 0,
            
        };
        for (i, targets) in self.leaf_targets.iter().enumerate() {
            let value = inputs.deposits.get(i).unwrap_or(&zero_deposit);
            targets.set_witness(&mut pw, value)?;
        }

        let mut frontier = inputs.frontier.to_vec();
        let mut index = inputs.from_index as u64;
        for (i, ((gadget, leaf_hash_target), value)) in self
            .frontier_gadgets
            .iter()
            .zip(self.leaf_hash_targets.iter())
            .zip(
                inputs
                    .deposits
                    .iter()
                    .cloned()
                    .chain(std::iter::repeat(zero_deposit.clone()))
                    .take(self.leaf_targets.len()),
            )
            .enumerate()
        {
            let leaf_hash = poseidon_hash_u32_words(value.to_u32_words().iter().map(|v| *v as u64));
            gadget.set_witness(&mut pw, &frontier, index, leaf_hash)?;
            pw.set_hash_target(*leaf_hash_target, leaf_hash.0)?;
            if i < inputs.deposits.len() {
                frontier = compute_new_frontier::<QHashOut<C::F>, PoseidonHasher>(&frontier, index, leaf_hash);
                index += 1;
            }
        }

        self.circuit_data.prove(pw)
    }
}

fn hash_target_to_u32x8_le<F: RichField + Extendable<D>, const D: usize>(
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

fn qhash_to_u32x8_le_words<F: RichField + PrimeField64>(hash: QHashOut<F>) -> [u32; WORDS_PER_BYTES32] {
    let limbs = hash
        .0
        .elements
        .map(|elt| elt.to_noncanonical_u64());
    let a = limbs[0];
    let b = limbs[1];
    let c = limbs[2];
    let d = limbs[3];
    [
        a as u32,
        (a >> 32) as u32,
        b as u32,
        (b >> 32) as u32,
        c as u32,
        (c >> 32) as u32,
        d as u32,
        (d >> 32) as u32,
    ]
}

fn frontier_root(frontier: &[QHashOut<GoldilocksField>; TREE_HEIGHT_32], next_index: u32) -> QHashOut<GoldilocksField> {
    use parth_core::crypto::hash::merkle_proof::compute_root_merkle_proof_generic;

    let siblings = derive_frontier_siblings::<QHashOut<GoldilocksField>, PoseidonHasher>(frontier, next_index as u64);
    compute_root_merkle_proof_generic::<QHashOut<GoldilocksField>, PoseidonHasher>(
        QHashOut::ZERO,
        next_index as u64,
        &siblings,
    )
}

fn poseidon_hash_u32_words<F: RichField>(words: impl IntoIterator<Item = u64>) -> QHashOut<F> {
    let felts = words
        .into_iter()
        .map(F::from_noncanonical_u64)
        .collect::<Vec<_>>();
    QHashOut(PoseidonHash::hash_no_pad(&felts))
}

fn keccak_u32_words_be(words: &[u32]) -> [u32; 8] {
    use tiny_keccak::{Hasher as _, Keccak};
    let mut buf = Vec::with_capacity(words.len() * 4);
    for word in words {
        buf.extend_from_slice(&word.to_be_bytes());
    }
    let mut keccak = Keccak::v256();
    keccak.update(&buf);
    let mut out = [0u8; 32];
    keccak.finalize(&mut out);
    std::array::from_fn(|i| {
        let start = i * 4;
        u32::from_be_bytes(out[start..start + 4].try_into().unwrap())
    })
}

#[cfg(test)]
mod tests {
    use parth_core::{
        crypto::hash::merkle_proof::compute_root_merkle_proof_generic,
        pgoldilocks::QHashOut,
    };
    use plonky2::{
        field::types::PrimeField64,
        hash::{hash_types::HashOut, poseidon::PoseidonHash},
        plonk::config::PoseidonGoldilocksConfig,
    };

    use super::{
        compute_batch_append_preimage, derive_frontier_siblings, keccak_u32_words_be, poseidon_hash_u32_words, BatchAppendInputs,
        DepositBatchAppendCircuit, DepositLeafData, MAX_DEPOSIT_BATCH_SIZE,
    };

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as plonky2::plonk::config::GenericConfig<D>>::F;

    fn sample_bytes32(seed: u32) -> [u32; 8] {
        [
            seed,
            seed + 1,
            seed + 2,
            seed + 3,
            seed + 4,
            seed + 5,
            seed + 6,
            seed + 7,
        ]
    }

    fn sample_deposit(seed: u32) -> DepositLeafData {
        DepositLeafData {
            shield_address: sample_bytes32(seed),
            note_commitment: sample_bytes32(seed + 10),
            token: sample_bytes32(seed + 20),
            l2_token_contract_id: sample_bytes32(seed + 30),
            amount: sample_bytes32(seed + 40),
            chain_index: seed + 50,
            
        }
    }

    #[test]
    fn test_single_append_pi_shape() {
        let circuit = DepositBatchAppendCircuit::<C, D>::build(MAX_DEPOSIT_BATCH_SIZE, 32);
        let inputs = BatchAppendInputs {
            frontier: [QHashOut::ZERO; 32],
            from_index: 0,
            deposits: vec![sample_deposit(1)],
            bridge_user_id: 7,
        };
        let proof = circuit.generate_proof(&inputs).unwrap();
        assert_eq!(proof.public_inputs.len(), 8);
    }

    #[test]
    fn test_chained_roots_match_native() {
        let circuit = DepositBatchAppendCircuit::<C, D>::build(MAX_DEPOSIT_BATCH_SIZE, 32);
        let deposits = vec![sample_deposit(11), sample_deposit(22)];
        let inputs = BatchAppendInputs {
            frontier: [QHashOut::ZERO; 32],
            from_index: 0,
            deposits: deposits.clone(),
            bridge_user_id: 9,
        };
        let proof = circuit.generate_proof(&inputs).unwrap();
        assert!(circuit.circuit_data.verify(proof).is_ok());

        let first_hash = poseidon_hash_u32_words::<F>(deposits[0].to_u32_words().into_iter().map(|v| v as u64));
        let first_siblings = derive_frontier_siblings::<QHashOut<F>, PoseidonHash>(&vec![QHashOut::ZERO; 32], 0);
        let first_root = compute_root_merkle_proof_generic::<QHashOut<F>, PoseidonHash>(first_hash, 0, &first_siblings);

        let second_frontier = super::compute_new_frontier::<QHashOut<F>, PoseidonHash>(&vec![QHashOut::ZERO; 32], 0, first_hash);
        let second_hash = poseidon_hash_u32_words::<F>(deposits[1].to_u32_words().into_iter().map(|v| v as u64));
        let second_siblings = derive_frontier_siblings::<QHashOut<F>, PoseidonHash>(&second_frontier, 1);
        let second_root = compute_root_merkle_proof_generic::<QHashOut<F>, PoseidonHash>(second_hash, 1, &second_siblings);

        assert_ne!(first_root, QHashOut(HashOut::ZERO));
        assert_ne!(second_root, QHashOut(HashOut::ZERO));
    }

    #[test]
    fn test_batch_public_inputs_are_interleaved_per_deposit() {
        let circuit = DepositBatchAppendCircuit::<C, D>::build(MAX_DEPOSIT_BATCH_SIZE, 32);
        let deposits = vec![sample_deposit(11), sample_deposit(22)];
        let inputs = BatchAppendInputs {
            frontier: [QHashOut::ZERO; 32],
            from_index: 0,
            deposits: deposits.clone(),
            bridge_user_id: 9,
        };
        let proof = circuit.generate_proof(&inputs).unwrap();
        let pis = &proof.public_inputs;
        let preimage = compute_batch_append_preimage(&inputs);
        let expected = keccak_u32_words_be(&preimage.to_u32_words());
        for i in 0..8 {
            assert_eq!(pis[i].to_canonical_u64() as u32, expected[i]);
        }
    }
}
