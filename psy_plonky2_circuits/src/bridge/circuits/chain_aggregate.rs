use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField as F, types::{Field, Field64}},
    iop::{target::{BoolTarget, Target}, witness::{PartialWitness, WitnessWrite}},
    plonk::{circuit_builder::CircuitBuilder, circuit_data::{CircuitConfig, CircuitData}, config::{AlgebraicHasher, GenericConfig}, proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget}},
    recursion::dummy_circuit::{dummy_circuit, dummy_proof},
};
use psy_client_data::bridge_aggregate::{ChainStart, DepositTransition, DepositLeafRange, NetworkConfig};
use psy_plonky2_basic_helpers::builder::{comparison::CircuitBuilderComparison, connect::CircuitBuilderConnectHelpers};
use psy_plonky2_common_circuits::bridge::{
    aggregate_commitment::{Bytes32Target, chain_rows_hash, encode_hash4, word, word_u64},
    aggregate_config::NetworkConfigTarget,
    deposit_spiderman_append::DepositSpidermanAppendCircuit,
};

pub const CHAIN_PI_WORDS: usize = 37;
pub const CHAIN_WEB_SLOTS: usize = 33;
pub const CHAIN_RECORD_CAPACITY: usize = 1024;
const CHAIN_VARIANT: u8 = 1;

#[derive(Clone, Debug)]
pub struct ChainContext {
    pub config_hash: [u8; 32],
    pub end_checkpoint_id: u64,
    pub end_checkpoint_root: [u64; 4],
    pub global_deposit_leaf_root: [u8; 32],
    pub global_deposit_count: u32,
}

#[derive(Clone, Debug)]
pub struct ChainRow {
    pub start: ChainStart,
    pub transition: DepositTransition,
    pub range: DepositLeafRange,
}

#[derive(Clone)]
pub struct ChainContextTarget {
    pub config_hash: Bytes32Target,
    pub end_id: [Target; 2],
    pub end_root: [Target; 4],
    pub global_deposit_leaf_root: Bytes32Target,
    pub global_deposit_count: Target,
}
impl ChainContextTarget {
    pub fn new<const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self where F: Extendable<D> {
        let value = Self { config_hash: builder.add_virtual_target_arr(), end_id: builder.add_virtual_target_arr(), end_root: builder.add_virtual_target_arr(), global_deposit_leaf_root: builder.add_virtual_target_arr(), global_deposit_count: builder.add_virtual_target() };
        for target in value.config_hash.into_iter().chain(value.end_id).chain(value.global_deposit_leaf_root).chain([value.global_deposit_count]) { builder.range_check(target, 32); }
        let maximum = builder.constant(F::from_canonical_usize(CHAIN_RECORD_CAPACITY));
        builder.ensure_is_less_than_or_equal(32, value.global_deposit_count, maximum);
        value
    }
    pub fn register<const D: usize>(&self, builder: &mut CircuitBuilder<F, D>, family: u32, variant: u8, level: u8) where F: Extendable<D> {
        let prefix = [1, family, variant as u32, level as u32].map(|v| builder.constant(F::from_canonical_u32(v)));
        builder.register_public_inputs(&prefix);
        builder.register_public_inputs(&self.config_hash);
        builder.register_public_inputs(&self.end_id);
        builder.register_public_inputs(&self.end_root);
    }
    pub fn connect_proof<const D: usize>(&self, builder: &mut CircuitBuilder<F, D>, pi: &[Target], active: BoolTarget) where F: Extendable<D> {
        for (left, right) in self.config_hash.into_iter().chain(self.end_id).chain(self.end_root).zip(&pi[4..18]) { builder.connect_if_true(active, left, *right); }
    }
    pub fn register_deposit_context<const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) where F: Extendable<D> {
        builder.register_public_inputs(&self.global_deposit_leaf_root);
        builder.register_public_input(self.global_deposit_count);
    }
    pub fn connect_deposit_context<const D: usize>(&self, builder: &mut CircuitBuilder<F, D>, root: &[Target], count: Target, active: BoolTarget) where F: Extendable<D> {
        assert_eq!(root.len(), 8);
        for (left, right) in self.global_deposit_leaf_root.into_iter().zip(root) { builder.connect_if_true(active, left, *right); }
        builder.connect_if_true(active, self.global_deposit_count, count);
    }
    pub fn set_witness(&self, witness: &mut PartialWitness<F>, context: &ChainContext) -> anyhow::Result<()> {
        super::settlement_aggregate::set_bytes(witness, &self.config_hash, &context.config_hash)?;
        set_u64(witness, self.end_id, context.end_checkpoint_id)?;
        set_hash(witness, self.end_root, context.end_checkpoint_root)?;
        super::settlement_aggregate::set_bytes(witness, &self.global_deposit_leaf_root, &context.global_deposit_leaf_root)?;
        witness.set_target(self.global_deposit_count, F::from_canonical_u32(context.global_deposit_count))
    }
}

#[derive(Clone)]
pub(crate) struct ChainRowTarget {
    pub(crate) chain_index: Target,
    pub(crate) start_id: [Target; 2],
    pub(crate) start_root: [Target; 4],
    pub(crate) old_root: [Target; 4],
    pub(crate) new_root: [Target; 4],
    pub(crate) old_count: Target,
    pub(crate) new_count: Target,
    pub(crate) first_leaf: Target,
    pub(crate) leaf_count: Target,
}
impl ChainRowTarget {
    pub(crate) fn new<const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self where F: Extendable<D> {
        Self {
            chain_index: builder.add_virtual_target(), start_id: builder.add_virtual_target_arr(), start_root: builder.add_virtual_target_arr(),
            old_root: builder.add_virtual_target_arr(), new_root: builder.add_virtual_target_arr(), old_count: builder.add_virtual_target(), new_count: builder.add_virtual_target(),
            first_leaf: builder.add_virtual_target(), leaf_count: builder.add_virtual_target(),
        }
    }
    pub(crate) fn encode<const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> Vec<Target> where F: Extendable<D> {
        let mut words = word(builder, self.chain_index, 8).to_vec();
        words.extend(word_u64(builder, self.start_id));
        words.extend(encode_hash4(builder, self.start_root));
        words.extend(word(builder, self.chain_index, 8));
        words.extend(encode_hash4(builder, self.old_root));
        words.extend(encode_hash4(builder, self.new_root));
        words.extend(word(builder, self.old_count, 32));
        words.extend(word(builder, self.new_count, 32));
        words.extend(word(builder, self.first_leaf, 32));
        words.extend(word(builder, self.leaf_count, 32));
        words
    }
    pub(crate) fn constrain<const D: usize>(&self, builder: &mut CircuitBuilder<F, D>, config: &NetworkConfigTarget, ordinal: Target, active: BoolTarget) where F: Extendable<D> {
        let zero = builder.zero();
        let mut selected = zero;
        let mut found = zero;
        for (i, chain) in config.chains.iter().enumerate() {
            let index = builder.constant(F::from_canonical_usize(i));
            let matches = builder.is_equal(ordinal, index);
            selected = builder.mul_add(matches.target, chain.chain_index, selected);
            found = builder.add(found, matches.target);
        }
        let one = builder.one();
        builder.connect_if_true(active, found, one);
        builder.connect_if_true(active, self.chain_index, selected);
        let end = builder.add(self.old_count, self.leaf_count);
        builder.range_check(end, 32);
        builder.connect_if_true(active, end, self.new_count);
        let leaf_end = builder.add(self.first_leaf, self.leaf_count);
        builder.range_check(leaf_end, 32);
        let inactive = builder.not(active);
        for target in self.encode(builder) { builder.connect_zero_if_true(inactive, target); }
    }
    pub(crate) fn set_witness(&self, witness: &mut PartialWitness<F>, row: &ChainRow) -> anyhow::Result<()> {
        anyhow::ensure!(row.start.chain_index == row.transition.chain_index, "chain row index mismatch");
        witness.set_target(self.chain_index, F::from_canonical_u8(row.start.chain_index))?;
        set_u64(witness, self.start_id, row.start.start_checkpoint_id)?;
        set_hash(witness, self.start_root, row.start.start_checkpoint_root)?;
        set_hash(witness, self.old_root, row.transition.old_root)?;
        set_hash(witness, self.new_root, row.transition.new_root)?;
        for (target, value) in [(self.old_count, row.transition.old_count), (self.new_count, row.transition.new_count), (self.first_leaf, row.range.first_leaf), (self.leaf_count, row.range.leaf_count)] {
            witness.set_target(target, F::from_canonical_u32(value))?;
        }
        Ok(())
    }
}

pub struct ChainAggregateCircuit<C: GenericConfig<D, F = F>, const D: usize> where F: Extendable<D>, C::Hasher: AlgebraicHasher<F> {
    pub circuit_data: CircuitData<F, C, D>,
    pub source_chain_count: usize,
    config: NetworkConfigTarget,
    context: ChainContextTarget,
    first: Target,
    row: ChainRowTarget,
    webs: Vec<ProofWithPublicInputsTarget<D>>,
    dummy: CircuitData<F, C, D>,
}

impl<C: GenericConfig<D, F = F> + 'static, const D: usize> ChainAggregateCircuit<C, D> where F: Extendable<D>, C::Hasher: AlgebraicHasher<F> {
    pub fn build(source_chain_count: usize, web: &DepositSpidermanAppendCircuit<C, D>) -> anyhow::Result<Self> {
        anyhow::ensure!((1..=8).contains(&source_chain_count), "source chain count must be 1..8");
        let mut builder = CircuitBuilder::new(CircuitConfig::standard_recursion_config());
        let context = ChainContextTarget::new(&mut builder);
        let config = NetworkConfigTarget::new(&mut builder, source_chain_count);
        let config_hash = config.hash(&mut builder);
        for (left, right) in config_hash.into_iter().zip(context.config_hash) { builder.connect(left, right); }
        let first = builder.add_virtual_target();
        builder.range_check(first, 32);
        let one = builder.one();
        let active = builder._true();
        let row = ChainRowTarget::new(&mut builder);
        row.constrain(&mut builder, &config, first, active);
        let web_dummy = dummy_circuit::<F, C, D>(&web.circuit_data.common);
        let webs = constrain_webs::<C, D>(&mut builder, &context, &row, &web.circuit_data, &web_dummy);
        let encoded = row.encode(&mut builder);
        let hash = chain_rows_hash(&mut builder, CHAIN_VARIANT, first, &[encoded], one);
        context.register(&mut builder, 9, CHAIN_VARIANT, 0);
        builder.register_public_inputs(&[first, one]);
        builder.register_public_inputs(&hash);
        context.register_deposit_context(&mut builder);
        let circuit_data = builder.build::<C>();
        debug_assert_eq!(circuit_data.common.num_public_inputs, CHAIN_PI_WORDS);
        Ok(Self { circuit_data, source_chain_count, config, context, first, row, webs, dummy: web_dummy })
    }
    pub fn set_witness(&self, witness: &mut PartialWitness<F>, config: &NetworkConfig, context: &ChainContext, first_chain_ordinal: u32, row: &ChainRow, web_proofs: &[ProofWithPublicInputs<F, C, D>]) -> anyhow::Result<()> {
        anyhow::ensure!(config.chains.len() == self.source_chain_count, "configuration chain count differs from source graph");
        anyhow::ensure!((first_chain_ordinal as usize) < self.source_chain_count, "chain ordinal outside source graph");
        self.config.set_witness(witness, config)?;
        self.context.set_witness(witness, context)?;
        witness.set_target(self.first, F::from_canonical_u32(first_chain_ordinal))?;
        self.row.set_witness(witness, row)?;
        let expected = active_web_count(row.transition.old_count, row.range.leaf_count as usize);
        anyhow::ensure!(web_proofs.len() == expected, "wrong active web proof count");
        let dummy_proof = dummy_proof(&self.dummy, Default::default())?;
        for (i, target) in self.webs.iter().enumerate() { witness.set_proof_with_pis_target(target, web_proofs.get(i).unwrap_or(&dummy_proof))?; }
        Ok(())
    }
    pub fn prove(&self, config: &NetworkConfig, context: &ChainContext, first_chain_ordinal: u32, row: &ChainRow, web_proofs: &[ProofWithPublicInputs<F, C, D>]) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut witness = PartialWitness::new();
        self.set_witness(&mut witness, config, context, first_chain_ordinal, row, web_proofs)?;
        self.circuit_data.prove(witness)
    }
}

pub fn active_web_count(old_count: u32, leaves: usize) -> usize { if leaves == 0 { 0 } else { ((old_count as usize & 31) + leaves).div_ceil(32) } }

fn constrain_webs<C: GenericConfig<D, F = F>, const D: usize>(builder: &mut CircuitBuilder<F, D>, context: &ChainContextTarget, row: &ChainRowTarget, web: &CircuitData<F, C, D>, dummy: &CircuitData<F, C, D>) -> Vec<ProofWithPublicInputsTarget<D>> where F: Extendable<D>, C::Hasher: AlgebraicHasher<F> {
    assert_eq!(web.common.num_public_inputs, 40);
    let zero = builder.zero();
    let real_vk = builder.constant_verifier_data(&web.verifier_only);
    let dummy_vk = builder.constant_verifier_data(&dummy.verifier_only);
    let old_bits = builder.split_le(row.old_count, 32);
    let offset = builder.le_sum(old_bits[..5].iter());
    let offset_count = builder.add(offset, row.leaf_count);
    let rounded = builder.add_const(offset_count, F::from_canonical_u32(31));
    let bits = builder.split_le(rounded, 11);
    let nonzero_count = builder.le_sum(bits[5..].iter());
    let empty = builder.is_equal(row.leaf_count, zero);
    let active_count = builder.select(empty, zero, nonzero_count);
    let mut consumed = zero;
    let mut rolling_count = row.old_count;
    let mut rolling_root = row.old_root;
    let mut proofs = Vec::with_capacity(CHAIN_WEB_SLOTS);
    for slot in 0..CHAIN_WEB_SLOTS {
        let ordinal = builder.constant(F::from_canonical_usize(slot));
        let active = builder.is_less_than(32, ordinal, active_count);
        let inactive = builder.not(active);
        let proof = builder.add_virtual_proof_with_pis(&web.common);
        builder.conditionally_verify_proof::<C>(active, &proof, &real_vk, &proof, &dummy_vk, &web.common);
        for &target in &proof.public_inputs { builder.connect_zero_if_true(inactive, target); }
        let pi = &proof.public_inputs;
        for (target, value) in pi[..4].iter().zip([1, 1, 0, 0]) { let expected = builder.constant(F::from_canonical_u32(value)); builder.connect_if_true(active, *target, expected); }
        context.connect_proof(builder, pi, active);
        context.connect_deposit_context(builder, &pi[31..39], pi[39], active);
        builder.connect_if_true(active, pi[18], row.chain_index);
        builder.connect_if_true(active, pi[19], rolling_count);
        for (target, expected) in pi[21..25].iter().zip(rolling_root) { builder.connect_if_true(active, *target, expected); }
        let first = builder.add(row.first_leaf, consumed);
        builder.range_check(first, 32);
        builder.connect_if_true(active, pi[29], first);
        let remaining = builder.sub(row.leaf_count, consumed);
        builder.range_check(remaining, 32);
        let rolling_bits = builder.split_le(rolling_count, 32);
        let offset = builder.le_sum(rolling_bits[..5].iter());
        let width = builder.constant(F::from_canonical_u32(32));
        let available = builder.sub(width, offset);
        let shorter = builder.is_less_than(32, remaining, available);
        let take = builder.select(shorter, remaining, available);
        let take = builder.select(active, take, zero);
        builder.connect_if_true(active, pi[30], take);
        consumed = builder.add(consumed, take);
        let next_count = builder.add(rolling_count, take);
        builder.range_check(next_count, 32);
        builder.connect_if_true(active, pi[20], next_count);
        rolling_count = next_count;
        rolling_root = std::array::from_fn(|i| builder.select(active, pi[25 + i], rolling_root[i]));
        proofs.push(proof);
    }
    builder.connect(consumed, row.leaf_count);
    builder.connect(rolling_count, row.new_count);
    for (left, right) in rolling_root.into_iter().zip(row.new_root) { builder.connect(left, right); }
    proofs
}

fn set_u64(witness: &mut PartialWitness<F>, targets: [Target; 2], value: u64) -> anyhow::Result<()> {
    witness.set_target(targets[0], F::from_canonical_u32(value as u32))?;
    witness.set_target(targets[1], F::from_canonical_u32((value >> 32) as u32))
}
fn set_hash(witness: &mut PartialWitness<F>, targets: [Target; 4], values: [u64; 4]) -> anyhow::Result<()> {
    for (target, value) in targets.into_iter().zip(values) { anyhow::ensure!(value < F::ORDER, "noncanonical Hash4"); witness.set_target(target, F::from_canonical_u64(value))?; }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use psy_client_data::bridge_aggregate::{ChainConfig, DepositLeaf, deposit_leaf_tree, deposit_leaf_path};
    type C = PoseidonGoldilocksConfig;

    fn fixture(count: usize) -> (NetworkConfig, ChainContext, Vec<ChainRow>) {
        let config = NetworkConfig {
            version: 1, network_magic: 1, bridge_user_id: 524288, circuit_set_hash: [3; 32],
            chains: (0..count).map(|i| { let mut chain_id = [0; 32]; chain_id[31] = (i + 1) as u8; ChainConfig { chain_index: i as u8, chain_id, bridge: [1; 20], state_manager: [2; 20], bootstrap_id: 0, bootstrap_root: [0; 4] } }).collect(),
            ethereum_index: 0, reward_payer: [4; 20], reward_token: [5; 20], reward_per_claim: [1; 32], reward_token_decimals: 18,
            reward_cutover: 1, reward_end_exclusive: 100, max_deposits: 1024, max_withdrawals: 1024, max_rewards: 1024,
        };
        let context = ChainContext { config_hash: config.config_hash().unwrap(), end_checkpoint_id: 1, end_checkpoint_root: [7; 4], global_deposit_leaf_root: deposit_leaf_tree(&[]).unwrap()[0], global_deposit_count: 0 };
        let rows = (0..count).map(|i| ChainRow {
            start: ChainStart { chain_index: i as u8, start_checkpoint_id: 0, start_checkpoint_root: [0; 4] },
            transition: DepositTransition { chain_index: i as u8, old_root: [9; 4], new_root: [9; 4], old_count: 3, new_count: 3 },
            range: DepositLeafRange { first_leaf: 0, leaf_count: 0 },
        }).collect();
        (config, context, rows)
    }

    fn rejects<T>(prove: impl FnOnce() -> anyhow::Result<T>) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(prove));
        assert!(result.is_err() || result.unwrap().is_err(), "tampered chain statement proved");
    }

    #[test]
    fn a_zero_append_uses_only_dummy_slots_and_rejects_changed_end() {
        let (config, context, rows) = fixture(1);
        let row = rows[0].clone();
        let web = DepositSpidermanAppendCircuit::<C, 2>::build();
        let circuit = ChainAggregateCircuit::build(1, &web).unwrap();
        let proof = circuit.prove(&config, &context, 0, &row, &[]).unwrap();
        circuit.circuit_data.verify(proof).unwrap();
        let mut changed = row.clone();
        changed.transition.new_root[0] += 1;
        rejects(|| circuit.prove(&config, &context, 0, &changed, &[]));
        let mut changed_context = context;
        changed_context.global_deposit_count = 1025;
        rejects(|| circuit.prove(&config, &changed_context, 0, &row, &[]));
    }

    #[test]
    fn a_real_web_binds_global_record_root_count_and_ordinal() {
        use parth_core::{crypto::hash::{merkle_proof::DeltaMerkleProofCore, spiderman::SpidermanUpdateProof, traits::{MerkleHasher, MerkleLeafHasher, MerkleZeroHasher}}, pgoldilocks::{PoseidonHasher, QHashOut}};
        use plonky2::{field::types::PrimeField64, hash::poseidon::PoseidonHash, plonk::config::Hasher};
        use psy_plonky2_common_circuits::bridge::deposit_spiderman_append::DepositSpidermanAppendInputs;
        let (config, mut context, rows) = fixture(1);
        let deposit = DepositLeaf { chain_index: 0, absolute_index: 31, shield_address: [1; 32], token: [2; 20], l2_token_contract_id: [3; 32], amount: [4; 32], note_commitment: [5; 32] };
        let mut commits = vec![[0; 32]; 98];
        commits[97] = deposit.leaf_commit().unwrap();
        let tree = deposit_leaf_tree(&commits).unwrap();
        context.global_deposit_leaf_root = tree[0];
        context.global_deposit_count = 98;
        let mut bytes = Vec::new();
        bytes.extend(deposit.shield_address); bytes.extend([0; 12]); bytes.extend(deposit.token);
        bytes.extend(deposit.l2_token_contract_id); bytes.extend(deposit.amount); bytes.extend(0u32.to_be_bytes()); bytes.extend(deposit.note_commitment);
        let words: Vec<_> = bytes.chunks_exact(4).map(|word| F::from_canonical_u32(u32::from_be_bytes(word.try_into().unwrap()))).collect();
        let mut old_leaves = vec![QHashOut::ZERO; 32];
        for leaf in &mut old_leaves[..31] { *leaf = QHashOut(PoseidonHash::hash_no_pad(&[F::ONE])); }
        let mut new_leaves = old_leaves.clone();
        new_leaves[31] = QHashOut(PoseidonHash::hash_no_pad(&words));
        let top = DeltaMerkleProofCore::from_params::<PoseidonHasher>(0, PoseidonHasher::compute_root_from_leaves(&old_leaves).unwrap(), PoseidonHasher::compute_root_from_leaves(&new_leaves).unwrap(), (5..32).map(PoseidonHasher::get_zero_hash).collect());
        let transition = DepositTransition { chain_index: 0, old_root: top.old_root.0.elements.map(|value| value.to_canonical_u64()), new_root: top.new_root.0.elements.map(|value| value.to_canonical_u64()), old_count: 31, new_count: 32 };
        let range = DepositLeafRange { first_leaf: 97, leaf_count: 1 };
        let row = ChainRow { start: rows[0].start.clone(), transition, range };
        let inputs = DepositSpidermanAppendInputs { config_hash: context.config_hash, end_checkpoint_id: context.end_checkpoint_id, end_checkpoint_root: QHashOut(plonky2::hash::hash_types::HashOut { elements: context.end_checkpoint_root.map(F::from_canonical_u64) }), chain_index: 0, old_count: 31, first_leaf: 97, deposits: vec![deposit], global_deposit_leaf_root: tree[0], global_deposit_count: 98, leaf_paths: vec![deposit_leaf_path(&tree, 98, 97).unwrap()], append_proof: SpidermanUpdateProof { top_line_proof: top, web_proof_old_leaves: old_leaves, web_proof_new_leaves: new_leaves } };
        let web = DepositSpidermanAppendCircuit::<C, 2>::build();
        let proof = web.prove(&inputs).unwrap();
        let circuit = ChainAggregateCircuit::build(1, &web).unwrap();
        let aggregate = circuit.prove(&config, &context, 0, &row, &[proof.clone()]).unwrap();
        circuit.circuit_data.verify(aggregate).unwrap();
        let mut changed = row.clone();
        changed.range.first_leaf += 1;
        rejects(|| circuit.prove(&config, &context, 0, &changed, &[proof.clone()]));
        for change_count in [false, true] {
            let mut changed_context = context.clone();
            if change_count { changed_context.global_deposit_count += 1; } else { changed_context.global_deposit_leaf_root[0] ^= 1; }
            rejects(|| circuit.prove(&config, &changed_context, 0, &row, &[proof.clone()]));
        }
    }

    #[test]
    fn web_capacity_boundaries() {
        assert_eq!(active_web_count(0, 0), 0);
        assert_eq!(active_web_count(31, 0), 0);
        assert_eq!(active_web_count(31, 1), 1);
        assert_eq!(active_web_count(31, 2), 2);
        assert_eq!(active_web_count(0, 1024), 32);
        assert_eq!(active_web_count(31, 1024), 33);
    }
}
