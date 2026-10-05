use parth_core::{crypto::hash::spiderman::SpidermanUpdateProof, pgoldilocks::QHashOut};
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::Field},
    hash::{hash_types::{HashOutTarget, RichField}, poseidon::PoseidonHash},
    iop::{target::Target, witness::{PartialWitness, WitnessWrite}},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_plonky2_basic_helpers::builder::{
    comparison::CircuitBuilderComparison, connect::CircuitBuilderConnectHelpers,
};

use crate::hash::merkle::gadgets::spiderman_append_proof::SpidermanAppendProofGadget;
use psy_client_data::bridge_aggregate::DepositLeaf;
use super::aggregate_commitment::{
    Bytes32Target, DepositLeafTarget, AggregateLeafTarget, U64Target, verify_deposit_leaf_path, word_address,
};

pub const DEPOSIT_SPIDERMAN_WEB_SIZE: usize = 32;
pub const DEPOSIT_SPIDERMAN_TOP_HEIGHT: usize = 27;
pub const DEPOSIT_SPIDERMAN_PI_WORDS: usize = 40;

fn constrain_append<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    append: &SpidermanAppendProofGadget,
    old_count: Target,
    leaf_count: Target,
    leaf_hashes: &[HashOutTarget; DEPOSIT_SPIDERMAN_WEB_SIZE],
) -> Target {
    let zero = builder.zero();
    let one = builder.one();
    let web_size = builder.constant(F::from_canonical_usize(DEPOSIT_SPIDERMAN_WEB_SIZE));
    let old_bits = builder.split_le(old_count, 32);
    let offset = builder.le_sum(old_bits[..5].iter());
    let top_index = builder.le_sum(old_bits[5..].iter());
    builder.connect(append.top_line_proof.index, top_index);
    builder.range_check(leaf_count, 32);
    builder.ensure_is_less_than_or_equal(32, one, leaf_count);
    let web_end = builder.add(offset, leaf_count);
    builder.ensure_is_less_than_or_equal(32, web_end, web_size);
    let new_count = builder.add(old_count, leaf_count);
    builder.range_check(new_count, 32);
    let base = builder.sub(old_count, offset);

    for j in 0..DEPOSIT_SPIDERMAN_WEB_SIZE {
        let position = builder.constant(F::from_canonical_usize(j));
        let absolute_position = builder.add(base, position);
        builder.range_check(absolute_position, 32);
        let existing = builder.is_less_than(32, position, offset);
        let before_end = builder.is_less_than(32, position, web_end);
        let not_existing = builder.not(existing);
        let active = builder.and(not_existing, before_end);
        let after_end = builder.not(before_end);
        let old_leaf = append.web_proof.old_leaves[j];
        let new_leaf = append.web_proof.new_leaves[j];
        builder.connect_hashes_if_true(existing, old_leaf, new_leaf);
        for limb in 0..4 {
            builder.connect_zero_if_true(not_existing, old_leaf.elements[limb]);
            builder.connect_zero_if_true(after_end, new_leaf.elements[limb]);
        }
        let is_zero = builder.is_zero_hash(new_leaf);
        builder.connect_zero_if_true(active, is_zero.target);
        builder.connect(append.web_proof.added_leaves[j].target, active.target);
    }

    for (i, leaf_hash) in leaf_hashes.iter().enumerate() {
        let ordinal = builder.constant(F::from_canonical_usize(i));
        let active = builder.is_less_than(32, ordinal, leaf_count);
        let position = builder.add(offset, ordinal);
        let selected_position = builder.select(active, position, zero);
        for limb in 0..4 {
            let leaves = append.web_proof.new_leaves.iter()
                .map(|leaf| leaf.elements[limb]).collect();
            let selected_leaf = builder.random_access(selected_position, leaves);
            builder.connect_if_true(active, selected_leaf, leaf_hash.elements[limb]);
        }
    }
    new_count
}

pub struct DepositSpidermanAppendInputs {
    pub config_hash: [u8; 32],
    pub end_checkpoint_id: u64,
    pub end_checkpoint_root: QHashOut<GoldilocksField>,
    pub chain_index: u8,
    pub old_count: u32,
    pub first_leaf: u32,
    pub global_deposit_leaf_root: [u8; 32],
    pub global_deposit_count: u32,
    pub leaf_paths: Vec<[[u8; 32]; 10]>,
    pub deposits: Vec<DepositLeaf>,
    pub append_proof: SpidermanUpdateProof<QHashOut<GoldilocksField>>,
}

pub struct DepositSpidermanAppendCircuit<C: GenericConfig<D>, const D: usize>
where C::Hasher: AlgebraicHasher<C::F> {
    pub circuit_data: CircuitData<C::F, C, D>,
    pub append: SpidermanAppendProofGadget,
    pub config_hash: Bytes32Target,
    pub end_checkpoint_id: U64Target,
    pub end_checkpoint_root: HashOutTarget,
    pub chain_index: Target,
    pub old_count: Target,
    pub new_count: Target,
    pub first_leaf: Target,
    pub leaf_count: Target,
    pub global_deposit_leaf_root: Bytes32Target,
    pub global_deposit_count: Target,
    pub leaf_paths: [[Bytes32Target; 10]; DEPOSIT_SPIDERMAN_WEB_SIZE],
    pub deposits: [DepositLeafTarget; DEPOSIT_SPIDERMAN_WEB_SIZE],
}

impl<C: GenericConfig<D, F = GoldilocksField> + 'static, const D: usize>
    DepositSpidermanAppendCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
    C::F: RichField + Extendable<D>,
{
    pub fn build() -> Self {
        let mut builder = CircuitBuilder::<C::F, D>::new(CircuitConfig::standard_recursion_config());
        let config_hash: Bytes32Target = std::array::from_fn(|_| builder.add_virtual_target());
        let end_checkpoint_id: U64Target = std::array::from_fn(|_| builder.add_virtual_target());
        let end_checkpoint_root = builder.add_virtual_hash();
        let chain_index = builder.add_virtual_target();
        let old_count = builder.add_virtual_target();
        let first_leaf = builder.add_virtual_target();
        let leaf_count = builder.add_virtual_target();
        let global_deposit_leaf_root: Bytes32Target = std::array::from_fn(|_| builder.add_virtual_target());
        let global_deposit_count = builder.add_virtual_target();
        builder.range_check(global_deposit_count, 32);
        let maximum_count = builder.constant(C::F::from_canonical_u32(1024));
        builder.ensure_is_less_than_or_equal(32, global_deposit_count, maximum_count);
        for target in global_deposit_leaf_root { builder.range_check(target, 32); }
        let leaf_paths: [[Bytes32Target; 10]; DEPOSIT_SPIDERMAN_WEB_SIZE] = std::array::from_fn(|_| {
            std::array::from_fn(|_| std::array::from_fn(|_| builder.add_virtual_target()))
        });
        for target in config_hash.into_iter().chain(end_checkpoint_id).chain([first_leaf]) {
            builder.range_check(target, 32);
        }
        builder.range_check(chain_index, 8);
        let leaf_end = builder.add(first_leaf, leaf_count);
        builder.range_check(leaf_end, 32);
        let append = SpidermanAppendProofGadget::add_virtual_to_allow_existing::<PoseidonHash, C::F, D>(
            &mut builder, DEPOSIT_SPIDERMAN_TOP_HEIGHT, 5,
        );
        let deposits: [DepositLeafTarget; DEPOSIT_SPIDERMAN_WEB_SIZE] = std::array::from_fn(|_| DepositLeafTarget {
            chain_index: builder.add_virtual_target(),
            absolute_index: builder.add_virtual_target(),
            shield_address: std::array::from_fn(|_| builder.add_virtual_target()),
            token: std::array::from_fn(|_| builder.add_virtual_target()),
            l2_token_contract_id: std::array::from_fn(|_| builder.add_virtual_target()),
            amount: std::array::from_fn(|_| builder.add_virtual_target()),
            note_commitment: std::array::from_fn(|_| builder.add_virtual_target()),
        });
        let leaf_hashes = std::array::from_fn(|i| {
            let leaf = deposits[i];
            let ordinal = builder.constant(C::F::from_canonical_usize(i));
            let active = builder.is_less_than(32, ordinal, leaf_count);
            let inactive = builder.not(active);
            let absolute_index = builder.add(old_count, ordinal);
            builder.connect_if_true(active, leaf.absolute_index, absolute_index);
            builder.connect_if_true(active, leaf.chain_index, chain_index);
            let aggregate_leaf = AggregateLeafTarget::Deposit(leaf);
            for target in aggregate_leaf.encode(&mut builder) {
                builder.connect_zero_if_true(inactive, target);
            }
            let commit = aggregate_leaf.leaf_commit(&mut builder);
            let zero = builder.zero();
            let commit = commit.map(|target| builder.select(active, target, zero));
            let global_ordinal = builder.add(first_leaf, ordinal);
            verify_deposit_leaf_path(&mut builder, active, global_deposit_leaf_root,
                global_deposit_count, global_ordinal, commit, leaf_paths[i]);
            let mut words = Vec::with_capacity(41);
            words.extend(leaf.shield_address);
            words.extend(word_address(&mut builder, leaf.token));
            words.extend(leaf.l2_token_contract_id);
            words.extend(leaf.amount);
            words.push(leaf.chain_index);
            words.extend(leaf.note_commitment);
            builder.hash_n_to_hash_no_pad::<PoseidonHash>(words)
        });
        let new_count = constrain_append(&mut builder, &append, old_count, leaf_count, &leaf_hashes);
        let prefix = [1, 1, 0, 0].map(|value| builder.constant(C::F::from_canonical_u32(value)));
        builder.register_public_inputs(&prefix);
        builder.register_public_inputs(&config_hash);
        builder.register_public_inputs(&end_checkpoint_id);
        builder.register_public_inputs(&end_checkpoint_root.elements);
        builder.register_public_inputs(&[chain_index, old_count, new_count]);
        builder.register_public_inputs(&append.old_root.elements);
        builder.register_public_inputs(&append.new_root.elements);
        builder.register_public_inputs(&[first_leaf, leaf_count]);
        builder.register_public_inputs(&global_deposit_leaf_root);
        builder.register_public_input(global_deposit_count);
        let circuit_data = builder.build::<C>();
        assert_eq!(circuit_data.common.num_public_inputs, DEPOSIT_SPIDERMAN_PI_WORDS);
        Self { circuit_data, append, config_hash, end_checkpoint_id, end_checkpoint_root,
            chain_index, old_count, new_count, first_leaf, leaf_count,
            global_deposit_leaf_root, global_deposit_count, leaf_paths, deposits }
    }

    pub fn set_witness(&self, witness: &mut PartialWitness<C::F>, inputs: &DepositSpidermanAppendInputs) -> anyhow::Result<()> {
        anyhow::ensure!(inputs.deposits.len() <= DEPOSIT_SPIDERMAN_WEB_SIZE, "too many deposits");
        anyhow::ensure!(inputs.leaf_paths.len() == inputs.deposits.len(), "one leaf path required per deposit");
        anyhow::ensure!(inputs.append_proof.top_line_proof.index == u64::from(inputs.old_count / 32),
            "deposit top index must equal old count divided by 32");
        anyhow::ensure!(inputs.append_proof.top_line_proof.siblings.len() == DEPOSIT_SPIDERMAN_TOP_HEIGHT,
            "deposit top path must have 27 siblings");
        anyhow::ensure!(inputs.append_proof.web_proof_old_leaves.len() == DEPOSIT_SPIDERMAN_WEB_SIZE
            && inputs.append_proof.web_proof_new_leaves.len() == DEPOSIT_SPIDERMAN_WEB_SIZE,
            "deposit web must have 32 leaves");
        set_bytes(witness, &self.config_hash, &inputs.config_hash)?;
        set_bytes(witness, &self.global_deposit_leaf_root, &inputs.global_deposit_leaf_root)?;
        witness.set_target(self.global_deposit_count, C::F::from_canonical_u32(inputs.global_deposit_count))?;
        for (i, path) in self.leaf_paths.iter().enumerate() {
            for (level, sibling) in path.iter().enumerate() {
                let bytes = inputs.leaf_paths.get(i).map(|path| path[level]).unwrap_or([0; 32]);
                set_bytes(witness, sibling, &bytes)?;
            }
        }
        witness.set_target(self.end_checkpoint_id[0], C::F::from_canonical_u32(inputs.end_checkpoint_id as u32))?;
        witness.set_target(self.end_checkpoint_id[1], C::F::from_canonical_u32((inputs.end_checkpoint_id >> 32) as u32))?;
        witness.set_hash_target(self.end_checkpoint_root, inputs.end_checkpoint_root.0)?;
        witness.set_target(self.chain_index, C::F::from_canonical_u32(inputs.chain_index as u32))?;
        witness.set_target(self.old_count, C::F::from_canonical_u32(inputs.old_count))?;
        witness.set_target(self.first_leaf, C::F::from_canonical_u32(inputs.first_leaf))?;
        witness.set_target(self.leaf_count, C::F::from_canonical_usize(inputs.deposits.len()))?;
        self.append.set_witness(witness, &inputs.append_proof)?;
        witness.set_hash_target(self.append.old_root, inputs.append_proof.top_line_proof.old_root.0)?;
        witness.set_hash_target(self.append.new_root, inputs.append_proof.top_line_proof.new_root.0)?;
        for (i, target) in self.deposits.iter().enumerate() {
            if let Some(leaf) = inputs.deposits.get(i) {
                witness.set_target(target.chain_index, C::F::from_canonical_u32(leaf.chain_index as u32))?;
                witness.set_target(target.absolute_index, C::F::from_canonical_u32(leaf.absolute_index))?;
                set_bytes(witness, &target.shield_address, &leaf.shield_address)?;
                set_bytes(witness, &target.token, &leaf.token)?;
                set_bytes(witness, &target.l2_token_contract_id, &leaf.l2_token_contract_id)?;
                set_bytes(witness, &target.amount, &leaf.amount)?;
                set_bytes(witness, &target.note_commitment, &leaf.note_commitment)?;
            } else {
                for target in [target.chain_index, target.absolute_index].into_iter()
                    .chain(target.shield_address).chain(target.token).chain(target.l2_token_contract_id)
                    .chain(target.amount).chain(target.note_commitment) {
                    witness.set_target(target, C::F::ZERO)?;
                }
            }
        }
        Ok(())
    }

    pub fn prove(&self, inputs: &DepositSpidermanAppendInputs) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut witness = PartialWitness::new();
        self.set_witness(&mut witness, inputs)?;
        self.circuit_data.prove(witness)
    }

    pub fn verify(&self, proof: ProofWithPublicInputs<C::F, C, D>) -> anyhow::Result<()> {
        self.circuit_data.verify(proof)
    }
}

fn set_bytes<F: RichField>(witness: &mut PartialWitness<F>, targets: &[Target], bytes: &[u8]) -> anyhow::Result<()> {
    for (target, word) in targets.iter().zip(bytes.chunks_exact(4)) {
        witness.set_target(*target, F::from_canonical_u32(u32::from_be_bytes(word.try_into().unwrap())))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use parth_core::{
        crypto::hash::{merkle_proof::DeltaMerkleProofCore, traits::{MerkleLeafHasher, MerkleZeroHasher}},
        pgoldilocks::PoseidonHasher,
    };
    use plonky2::{field::types::PrimeField64, plonk::config::{Hasher, PoseidonGoldilocksConfig}};
    use psy_client_data::bridge_aggregate::{deposit_leaf_tree, deposit_leaf_path};

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    fn custody_hash(leaf: &DepositLeaf) -> QHashOut<F> {
        let mut bytes = Vec::with_capacity(164);
        bytes.extend(leaf.shield_address);
        bytes.extend([0u8; 12]);
        bytes.extend(leaf.token);
        bytes.extend(leaf.l2_token_contract_id);
        bytes.extend(leaf.amount);
        bytes.extend((leaf.chain_index as u32).to_be_bytes());
        bytes.extend(leaf.note_commitment);
        let words: Vec<_> = bytes.chunks_exact(4)
            .map(|word| F::from_canonical_u32(u32::from_be_bytes(word.try_into().unwrap()))).collect();
        QHashOut(PoseidonHash::hash_no_pad(&words))
    }

    fn update_roots(inputs: &mut DepositSpidermanAppendInputs) {
        let proof = &mut inputs.append_proof;
        let old_value = PoseidonHasher::compute_root_from_leaves(&proof.web_proof_old_leaves).unwrap();
        let new_value = PoseidonHasher::compute_root_from_leaves(&proof.web_proof_new_leaves).unwrap();
        proof.top_line_proof = DeltaMerkleProofCore::from_params::<PoseidonHasher>(
            proof.top_line_proof.index, old_value, new_value, proof.top_line_proof.siblings.clone(),
        );
    }

    fn inputs(old_count: u32, count: usize) -> DepositSpidermanAppendInputs {
        inputs_at(old_count, count, 97)
    }

    fn inputs_at(old_count: u32, count: usize, first_leaf: u32) -> DepositSpidermanAppendInputs {
        let deposits: Vec<_> = (0..count).map(|i| DepositLeaf {
            chain_index: 7,
            absolute_index: old_count.checked_add(i as u32).unwrap(),
            shield_address: [0x11; 32], token: [0x22; 20], l2_token_contract_id: [0x33; 32],
            amount: [0x44; 32], note_commitment: [i as u8 + 1; 32],
        }).collect();
        let offset = old_count as usize % 32;
        let mut old_leaves = vec![QHashOut::ZERO; 32];
        for (i, leaf) in old_leaves[..offset].iter_mut().enumerate() {
            *leaf = QHashOut(PoseidonHash::hash_no_pad(&[F::from_canonical_usize(i + 1)]));
        }
        let mut new_leaves = old_leaves.clone();
        for (i, leaf) in deposits.iter().enumerate() {
            new_leaves[offset + i] = custody_hash(leaf);
        }
        let old_value = PoseidonHasher::compute_root_from_leaves(&old_leaves).unwrap();
        let new_value = PoseidonHasher::compute_root_from_leaves(&new_leaves).unwrap();
        let siblings = (5..32).map(PoseidonHasher::get_zero_hash).collect();
        let mut global_leaves: Vec<_> = (0..first_leaf).map(|index| DepositLeaf {
            chain_index: 1, absolute_index: index, shield_address: [0x11; 32],
            token: [0x22; 20], l2_token_contract_id: [0x33; 32], amount: [0x44; 32],
            note_commitment: [0x66; 32],
        }).collect();
        global_leaves.extend(deposits.iter().cloned());
        let commits: Vec<_> = global_leaves.iter().map(|leaf| leaf.leaf_commit().unwrap()).collect();
        let global_deposit_count = commits.len() as u32;
        let tree = deposit_leaf_tree(&commits).unwrap();
        let leaf_paths = (0..count).map(|i| {
            deposit_leaf_path(&tree, global_deposit_count, first_leaf + i as u32).unwrap()
        }).collect();
        DepositSpidermanAppendInputs {
            config_hash: [0x55; 32], end_checkpoint_id: (1u64 << 40) + 7,
            end_checkpoint_root: QHashOut(PoseidonHash::hash_no_pad(&[F::ONE])),
            chain_index: 7, old_count, first_leaf, deposits,
            global_deposit_leaf_root: tree[0], global_deposit_count, leaf_paths,
            append_proof: SpidermanUpdateProof {
                top_line_proof: DeltaMerkleProofCore::from_params::<PoseidonHasher>(
                    (old_count / 32) as u64, old_value, new_value, siblings,
                ), web_proof_old_leaves: old_leaves, web_proof_new_leaves: new_leaves,
            },
        }
    }

    fn reject(circuit: &DepositSpidermanAppendCircuit<C, 2>, inputs: &DepositSpidermanAppendInputs) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| circuit.prove(inputs)));
        assert!(!matches!(result, Ok(Ok(_))), "invalid append produced a proof");
    }

    #[test]
    fn positive_web_proofs_bind_records_context_and_u32_boundaries() {
        let circuit = DepositSpidermanAppendCircuit::<C, 2>::build();
        for (old_count, count) in [(0, 32), (30, 2), (u32::MAX - 1, 1)] {
            let input = inputs(old_count, count);
            let proof = circuit.prove(&input).unwrap();
            let pi = &proof.public_inputs;
            assert_eq!(pi.len(), DEPOSIT_SPIDERMAN_PI_WORDS);
            assert_eq!(pi[..4], [F::ONE, F::ONE, F::ZERO, F::ZERO]);
            assert_eq!(pi[12].to_canonical_u64(), 7);
            assert_eq!(pi[13].to_canonical_u64(), 256);
            assert_eq!(pi[14..18], input.end_checkpoint_root.0.elements);
            assert_eq!(pi[18].to_canonical_u64(), 7);
            assert_eq!(pi[19].to_canonical_u64(), old_count as u64);
            assert_eq!(pi[20].to_canonical_u64(), old_count as u64 + count as u64);
            assert_eq!(pi[21..25], input.append_proof.top_line_proof.old_root.0.elements);
            assert_eq!(pi[25..29], input.append_proof.top_line_proof.new_root.0.elements);
            assert_eq!(pi[29].to_canonical_u64(), 97);
            assert_eq!(pi[30].to_canonical_u64(), count as u64);
            assert_eq!(pi[39].to_canonical_u64(), input.global_deposit_count as u64);
            for (actual, expected) in pi[31..39].iter().zip(input.global_deposit_leaf_root.chunks_exact(4)) {
                assert_eq!(actual.to_canonical_u64(), u32::from_be_bytes(expected.try_into().unwrap()) as u64);
            }
            circuit.verify(proof.clone()).unwrap();
            for index in [4, 12, 14, 29, 31, 39] {
                let mut changed = proof.clone();
                changed.public_inputs[index] += F::ONE;
                assert!(circuit.verify(changed).is_err());
            }
        }

        let last_global_record = inputs_at(0, 1, 1023);
        let proof = circuit.prove(&last_global_record).unwrap();
        assert_eq!(proof.public_inputs[29].to_canonical_u64(), 1023);
        assert_eq!(proof.public_inputs[39].to_canonical_u64(), 1024);
        circuit.verify(proof).unwrap();
        let mut wrong_global_root = inputs(0, 1);
        wrong_global_root.global_deposit_leaf_root[0] ^= 1;
        reject(&circuit, &wrong_global_root);
        let mut wrong_global_count = inputs(0, 1);
        wrong_global_count.global_deposit_count += 1;
        reject(&circuit, &wrong_global_count);
        let mut oversized_global_count = inputs(0, 1);
        oversized_global_count.global_deposit_count = 1025;
        reject(&circuit, &oversized_global_count);
        let mut wrong_global_ordinal = inputs(0, 1);
        wrong_global_ordinal.first_leaf -= 1;
        reject(&circuit, &wrong_global_ordinal);
        let mut wrong_record_path = inputs(0, 1);
        wrong_record_path.leaf_paths[0][0][0] ^= 1;
        reject(&circuit, &wrong_record_path);
        let mut reordered_paths = inputs(0, 2);
        reordered_paths.leaf_paths.swap(0, 1);
        reject(&circuit, &reordered_paths);
        let mut unmatched_global_record = inputs(0, 1);
        unmatched_global_record.deposits[0].amount[31] ^= 1;
        unmatched_global_record.append_proof.web_proof_new_leaves[0] = custody_hash(&unmatched_global_record.deposits[0]);
        update_roots(&mut unmatched_global_record);
        reject(&circuit, &unmatched_global_record);

        let mut crossed_web = inputs(0, 2);
        crossed_web.old_count = 31;
        crossed_web.deposits[0].absolute_index = 31;
        crossed_web.deposits[1].absolute_index = 32;
        reject(&circuit, &crossed_web);
        reject(&circuit, &inputs(0, 0));
        reject(&circuit, &inputs(u32::MAX, 1));

        let mut wrong_record = inputs(30, 1);
        wrong_record.deposits[0].amount[31] ^= 1;
        reject(&circuit, &wrong_record);
        let mut wrong_index = inputs(30, 1);
        wrong_index.deposits[0].absolute_index += 1;
        reject(&circuit, &wrong_index);
        let mut wrong_chain = inputs(30, 1);
        wrong_chain.deposits[0].chain_index += 1;
        reject(&circuit, &wrong_chain);

        let mut overwrite = inputs(30, 1);
        overwrite.append_proof.web_proof_new_leaves[0] = custody_hash(&overwrite.deposits[0]);
        update_roots(&mut overwrite);
        reject(&circuit, &overwrite);
        let mut suffix = inputs(30, 1);
        suffix.append_proof.web_proof_new_leaves[31] = custody_hash(&suffix.deposits[0]);
        update_roots(&mut suffix);
        reject(&circuit, &suffix);
        let mut old_active = inputs(0, 1);
        old_active.append_proof.web_proof_old_leaves[0] = old_active.append_proof.web_proof_new_leaves[0];
        update_roots(&mut old_active);
        reject(&circuit, &old_active);
        let mut zero_new = inputs(0, 1);
        zero_new.append_proof.web_proof_new_leaves[0] = QHashOut::ZERO;
        update_roots(&mut zero_new);
        reject(&circuit, &zero_new);
        let mut wrong_path = inputs(0, 1);
        wrong_path.append_proof.top_line_proof.index = 1;
        update_roots(&mut wrong_path);
        reject(&circuit, &wrong_path);
        let mut aliased_path = inputs(0, 1);
        aliased_path.append_proof.top_line_proof.index = psy_client_data::bridge_aggregate::GOLDILOCKS_MODULUS;
        let mut witness = PartialWitness::new();
        assert!(circuit.set_witness(&mut witness, &aliased_path).is_err());
    }
}
