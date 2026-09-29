use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::Field},
    iop::{target::{BoolTarget, Target}, witness::{PartialWitness, WitnessWrite}},
    plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitData, config::{AlgebraicHasher, GenericConfig}, proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget}},
    recursion::dummy_circuit::{dummy_circuit, dummy_proof},
};
use psy_plonky2_basic_helpers::builder::comparison::CircuitBuilderComparison;
use psy_plonky2_common_circuits::bridge::aggregate_commitment::{self as hash, Bytes32Target, RecordTarget};
use super::record_batch::{connect_if, BatchStatementTarget};

type F = GoldilocksField;
pub const DEPOSIT_AGGREGATE_PI_LEN: usize = 12;

pub struct BatchCircuitSet<'a, C: GenericConfig<D, F = F>, const D: usize>
where F: Extendable<D> {
    pub real: [&'a CircuitData<F, C, D>; 6],
    pub empty: &'a CircuitData<F, C, D>,
}

pub(crate) struct BatchOpeningTarget {
    pub count: Target,
    pub chunks: Target,
    pub root: Bytes32Target,
    pub levels: [BoolTarget; 6],
}

pub(crate) fn less_words<const D: usize>(builder: &mut CircuitBuilder<F, D>, left: &[Target], right: &[Target]) -> BoolTarget
where F: Extendable<D> {
    assert_eq!(left.len(), right.len());
    let mut equal = builder._true();
    let mut less = builder._false();
    for (&a, &b) in left.iter().zip(right) {
        let next = builder.is_less_than(32, a, b);
        let selected = builder.and(equal, next);
        less = builder.or(less, selected);
        let same = builder.is_equal(a, b);
        equal = builder.and(equal, same);
    }
    less
}

impl BatchOpeningTarget {
    pub(crate) fn build<const D: usize>(builder: &mut CircuitBuilder<F, D>, config: Bytes32Target, end_id: [Target; 2], end_root: [Target; 4], records: &[RecordTarget], count: Target, maximum: Target) -> Self
    where F: Extendable<D> {
        assert_eq!(records.len(), 1024);
        let zero = builder.zero();
        let one = builder.one();
        builder.range_check(count, 11);
        let limit = builder.constant(F::from_canonical_u32(1024));
        builder.ensure_is_less_than_or_equal(11, count, limit);
        builder.ensure_is_less_than_or_equal(32, count, maximum);
        let mut nodes = Vec::with_capacity(32);
        let mut chunks = zero;
        for (j, records) in records.chunks_exact(32).enumerate() {
            let first = builder.constant(F::from_canonical_usize(j * 32));
            let active = builder.is_less_than(11, first, count);
            chunks = builder.add(chunks, active.target);
            let remaining = builder.sub(count, first);
            let full = builder.constant(F::from_canonical_u32(32));
            let end = builder.constant(F::from_canonical_usize((j + 1) * 32));
            let partial = builder.is_less_than(11, count, end);
            let take = builder.select(partial, remaining, full);
            let take = builder.select(active, take, one);
            let ordinal = builder.constant(F::from_canonical_usize(j));
            let digest = hash::batch_commit(builder, config, end_id, end_root, ordinal, records, take);
            let leaf = hash::batch_leaf(builder, records[0].family(), ordinal, digest);
            let empty = hash::batch_empty(builder, records[0].family(), ordinal);
            nodes.push(std::array::from_fn(|i| builder.select(active, leaf[i], empty[i])));
        }
        let levels = std::array::from_fn(|level| {
            let upper = builder.constant(F::from_canonical_usize(1 << level));
            let above = builder.is_less_than(6, upper, chunks);
            let below = builder.not(above);
            if level == 0 { below } else {
                let lower = builder.constant(F::from_canonical_usize(1 << (level - 1)));
                let positive = builder.is_less_than(6, lower, chunks);
                builder.and(below, positive)
            }
        });
        let selected = builder.add_many(levels.iter().map(|level| level.target));
        builder.assert_one(selected);
        let mut root = [zero; 8];
        for level in 0..6 {
            for i in 0..8 { root[i] = builder.mul_add(levels[level].target, nodes[0][i], root[i]); }
            if level < 5 {
                nodes = nodes.chunks_exact(2).map(|pair| hash::batch_node(builder, level as u8 + 1, pair[0], pair[1])).collect();
            }
        }
        Self { count, chunks, root, levels }
    }
}

pub(crate) struct BatchProofTargets<C: GenericConfig<D, F = F>, const D: usize>
where F: Extendable<D> {
    proofs: Vec<ProofWithPublicInputsTarget<D>>,
    dummies: Vec<CircuitData<F, C, D>>,
}

impl<C: GenericConfig<D, F = F>, const D: usize> BatchProofTargets<C, D>
where F: Extendable<D>, C::Hasher: AlgebraicHasher<F> {
    pub(crate) fn build(builder: &mut CircuitBuilder<F, D>, circuits: &BatchCircuitSet<'_, C, D>, family: u8, opening: &BatchOpeningTarget, context: &[Target], ends: Bytes32Target) -> Self {
        assert_eq!(context.len(), 14);
        assert_eq!(circuits.real[0].common, circuits.empty.common);
        let zero = builder.zero();
        let empty = builder.is_equal(opening.count, zero);
        let mut proofs = Vec::with_capacity(6);
        let mut dummies = Vec::with_capacity(6);
        for level in 0..6 {
            let circuit = circuits.real[level];
            assert_eq!(circuit.common.num_public_inputs, 38);
            let dummy = dummy_circuit::<F, C, D>(&circuit.common);
            assert_eq!(dummy.common, circuit.common);
            let real_vk = builder.constant_verifier_data(&circuit.verifier_only);
            let real_vk = if level == 0 {
                let empty_vk = builder.constant_verifier_data(&circuits.empty.verifier_only);
                builder.select_verifier_data(empty, &empty_vk, &real_vk)
            } else { real_vk };
            let dummy_vk = builder.constant_verifier_data(&dummy.verifier_only);
            let proof = builder.add_virtual_proof_with_pis(&circuit.common);
            let active = opening.levels[level];
            builder.conditionally_verify_proof::<C>(active, &proof, &real_vk, &proof, &dummy_vk, &circuit.common);
            let inactive = builder.not(active);
            for &target in &proof.public_inputs { connect_if(builder, inactive, target, zero); }
            let pi = &proof.public_inputs;
            let variant = builder.constant(F::from_canonical_u8(family));
            let variant = if level == 0 { builder.mul_const_add(F::from_canonical_u32(128), empty.target, variant) } else { variant };
            for (index, value) in [(0, 1), (1, if level == 0 { 7 } else { 8 }), (3, level)] {
                let expected = builder.constant(F::from_canonical_usize(value));
                connect_if(builder, active, pi[index], expected);
            }
            connect_if(builder, active, pi[2], variant);
            for (&a, &b) in pi[4..18].iter().zip(context) { connect_if(builder, active, a, b); }
            let statement = BatchStatementTarget::from_public_inputs(pi);
            for (a, b) in [(statement.first_chunk, zero), (statement.first_record, zero), (statement.real_chunks, opening.chunks), (statement.real_records, opening.count)] { connect_if(builder, active, a, b); }
            for i in 0..8 {
                connect_if(builder, active, statement.subtree_root[i], opening.root[i]);
                connect_if(builder, active, statement.chain_ends_hash[i], ends[i]);
            }
            proofs.push(proof);
            dummies.push(dummy);
        }
        Self { proofs, dummies }
    }

    pub(crate) fn set_witness(&self, witness: &mut PartialWitness<F>, count: usize, proof: &ProofWithPublicInputs<F, C, D>) -> anyhow::Result<()> {
        anyhow::ensure!(count <= 1024, "record capacity exceeded");
        let chunks = count.div_ceil(32);
        let selected = chunks.max(1).next_power_of_two().trailing_zeros() as usize;
        for level in 0..6 {
            if level == selected { witness.set_proof_with_pis_target(&self.proofs[level], proof)?; }
            else {
                let dummy = dummy_proof(&self.dummies[level], Default::default())?;
                witness.set_proof_with_pis_target(&self.proofs[level], &dummy)?;
            }
        }
        Ok(())
    }
}

use psy_client_data::bridge_aggregate::{AOpening, NetworkConfig, DepositRecordRange};
use psy_plonky2_common_circuits::bridge::{aggregate_config::NetworkConfigTarget, aggregate_commitment::{DepositLeafTarget, Domain}};
use super::chain_aggregate::{ChainContext, ChainContextTarget, ChainRow, ChainRowTarget, ChainVariant};

pub(crate) struct AOpeningTarget {
    pub config: NetworkConfigTarget,
    pub context: ChainContextTarget,
    pub rows: Vec<ChainRowTarget>,
    pub batch: BatchOpeningTarget,
    pub statement: Bytes32Target,
    records: Vec<Vec<Target>>,
}

impl AOpeningTarget {
    pub(crate) fn build<const D: usize>(builder: &mut CircuitBuilder<F, D>, chains: usize, variant: ChainVariant) -> Self
    where F: Extendable<D> {
        let config = NetworkConfigTarget::new(builder, chains);
        let context = ChainContextTarget::new(builder);
        let config_hash = config.hash(builder);
        for i in 0..8 { builder.connect(config_hash[i], context.config_hash[i]); }
        let zero = builder.zero();
        let active = builder._true();
        let count = builder.add_virtual_target();
        let mut records = Vec::with_capacity(1024);
        let mut leaves = Vec::with_capacity(1024);
        let mut commits = Vec::with_capacity(1024);
        let mut previous_key: Option<[Target; 2]> = None;
        for i in 0..1024 {
            let leaf = DepositLeafTarget { chain_index: builder.add_virtual_target(), absolute_index: builder.add_virtual_target(), shield_address: builder.add_virtual_target_arr(), token: builder.add_virtual_target_arr(), l2_token_contract_id: builder.add_virtual_target_arr(), amount: builder.add_virtual_target_arr(), note_commitment: builder.add_virtual_target_arr() };
            let record = RecordTarget::Deposit(leaf);
            let words = record.encode(builder);
            let ordinal = builder.constant(F::from_canonical_usize(i));
            let real = builder.is_less_than(11, ordinal, count);
            let inactive = builder.not(real);
            for &word in &words { connect_if(builder, inactive, word, zero); }
            let key = [leaf.chain_index, leaf.absolute_index];
            if let Some(previous) = previous_key {
                let ordered = less_words(builder, &previous, &key);
                let one = builder.one();
                connect_if(builder, real, ordered.target, one);
            }
            previous_key = Some(key);
            let commit = record.record_commit(builder);
            commits.push(std::array::from_fn(|word| builder.select(real, commit[word], zero)));
            records.push(words);
            leaves.push(record);
        }
        let commits: [Bytes32Target; 1024] = commits.try_into().unwrap();
        let global_root = hash::deposit_record_root(builder, &commits, count);
        for i in 0..8 { builder.connect(global_root[i], context.global_deposit_record_root[i]); }
        builder.connect(count, context.global_deposit_count);
        let batch = BatchOpeningTarget::build(builder, context.config_hash, context.end_id, context.end_root, &leaves, count, config.max_deposits);
        let mut rows = Vec::with_capacity(chains);
        let mut first = zero;
        let mut starts = Vec::new();
        let mut deposits = Vec::new();
        let end_key = [context.end_id[1], context.end_id[0]];
        for ordinal in 0..chains {
            let row = ChainRowTarget::new(builder, variant);
            let index = builder.constant(F::from_canonical_usize(ordinal));
            row.constrain(builder, &config, index, active);
            builder.connect(row.first_record, first);
            let next = builder.add(first, row.record_count);
            builder.ensure_is_less_than_or_equal(32, next, count);
            let start_key = [row.start_id[1], row.start_id[0]];
            let future = less_words(builder, &end_key, &start_key);
            builder.assert_zero(future.target);
            let before_bootstrap = less_words(builder, &start_key, &[config.chains[ordinal].bootstrap_id[1], config.chains[ordinal].bootstrap_id[0]]);
            builder.assert_zero(before_bootstrap.target);
            for (id, root) in [(context.end_id, context.end_root), (config.chains[ordinal].bootstrap_id, config.chains[ordinal].bootstrap_root)] {
                let low = builder.is_equal(row.start_id[0], id[0]);
                let high = builder.is_equal(row.start_id[1], id[1]);
                let equal = builder.and(low, high);
                for j in 0..4 { connect_if(builder, equal, row.start_root[j], root[j]); }
            }
            let empty = builder.is_equal(row.record_count, zero);
            for j in 0..4 { connect_if(builder, empty, row.old_root[j], row.new_root[j]); }
            let encoded = row.encode(builder);
            starts.extend_from_slice(&encoded[..48]);
            deposits.extend_from_slice(&encoded[48..136]);
            first = next;
            rows.push(row);
        }
        builder.connect(first, count);
        let chain_count = builder.constant(F::from_canonical_usize(chains));
        let mut window_body = context.config_hash.to_vec();
        window_body.extend(hash::word_u64(builder, context.end_id));
        window_body.extend(hash::encode_hash4(builder, context.end_root));
        window_body.extend(hash::word(builder, chain_count, 32));
        window_body.extend(starts.clone());
        window_body.extend(hash::word(builder, chain_count, 32));
        window_body.extend(deposits.clone());
        let window = hash::commitment(builder, Domain::Window, &window_body);
        let mut body = context.config_hash.to_vec();
        body.extend(window);
        body.extend(hash::word_u64(builder, context.end_id));
        body.extend(hash::encode_hash4(builder, context.end_root));
        body.extend(hash::word(builder, chain_count, 32));
        body.extend(starts);
        body.extend(hash::word(builder, chain_count, 32));
        body.extend(deposits);
        body.extend(hash::word(builder, count, 32));
        body.extend(hash::word(builder, batch.chunks, 32));
        body.extend(batch.root);
        let statement = hash::commitment(builder, Domain::A, &body);
        Self { config, context, rows, batch, statement, records }
    }

    pub(crate) fn set_witness(&self, witness: &mut PartialWitness<F>, config: &NetworkConfig, opening: &AOpening, ends: Option<&[psy_client_data::bridge_aggregate::ChainEnd]>) -> anyhow::Result<()> {
        opening.validate(config)?;
        self.config.set_witness(witness, config)?;
        let commits = opening.deposit_leaves.iter().map(|leaf| leaf.record_commit()).collect::<Result<Vec<_>, _>>()?;
        let tree = psy_client_data::bridge_aggregate::deposit_record_tree(&commits)?;
        self.context.set_witness(witness, &ChainContext { config_hash: opening.config_hash, end_checkpoint_id: opening.end_checkpoint_id, end_checkpoint_root: opening.end_checkpoint_root, global_deposit_record_root: tree[0], global_deposit_count: commits.len() as u32 })?;
        witness.set_target(self.batch.count, F::from_canonical_usize(opening.deposit_leaves.len()))?;
        let mut first = 0;
        for (i, target) in self.rows.iter().enumerate() {
            let transition = &opening.deposits[i];
            let count = (transition.new_count - transition.old_count) as usize;
            let range = DepositRecordRange { first_record: first as u32, record_count: count as u32 };
            let row = if let Some(ends) = ends { ChainRow::B { start: opening.starts[i].clone(), transition: transition.clone(), end: ends[i].clone(), range } }
                else { ChainRow::A { start: opening.starts[i].clone(), transition: transition.clone(), range } };
            target.set_witness(witness, Some(&row))?;
            first += count;
        }
        for (i, words) in self.records.iter().enumerate() {
            if let Some(record) = opening.deposit_leaves.get(i) { super::record_batch::set_bytes(witness, words, &record.encode()?)?; }
            else { for &word in words { witness.set_target(word, F::ZERO)?; } }
        }
        Ok(())
    }
}

pub(crate) fn chain_proof<C: GenericConfig<D, F = F>, const D: usize>(builder: &mut CircuitBuilder<F, D>, circuit: &CircuitData<F, C, D>, opening: &AOpeningTarget, variant: ChainVariant) -> ProofWithPublicInputsTarget<D>
where F: Extendable<D>, C::Hasher: AlgebraicHasher<F> {
    assert_eq!(circuit.common.num_public_inputs, 37);
    let proof = builder.add_virtual_proof_with_pis(&circuit.common);
    let verifier = builder.constant_verifier_data(&circuit.verifier_only);
    builder.verify_proof::<C>(&proof, &verifier, &circuit.common);
    let level = opening.rows.len().next_power_of_two().trailing_zeros();
    for (target, value) in proof.public_inputs[..4].iter().zip([1, if level == 0 { 9 } else { 10 }, variant.number() as u32, level]) {
        let expected = builder.constant(F::from_canonical_u32(value)); builder.connect(*target, expected);
    }
    let active = builder._true();
    opening.context.connect_proof(builder, &proof.public_inputs, active);
    let zero = builder.zero();
    builder.connect(proof.public_inputs[18], zero);
    let count = builder.constant(F::from_canonical_usize(opening.rows.len()));
    builder.connect(proof.public_inputs[19], count);
    let rows = opening.rows.iter().map(|row| row.encode(builder)).collect::<Vec<_>>();
    let digest = hash::chain_rows_hash(builder, variant.number(), zero, &rows, count);
    for i in 0..8 { builder.connect(proof.public_inputs[20 + i], digest[i]); }
    for i in 0..8 { builder.connect(proof.public_inputs[28 + i], opening.context.global_deposit_record_root[i]); }
    builder.connect(proof.public_inputs[36], opening.batch.count);
    proof
}

pub struct DepositAggregateCircuit<C: GenericConfig<D, F = F>, const D: usize>
where F: Extendable<D> {
    pub circuit_data: CircuitData<F, C, D>,
    opening: AOpeningTarget,
    batch: BatchProofTargets<C, D>,
    chain: ProofWithPublicInputsTarget<D>,
}

impl<C: GenericConfig<D, F = F>, const D: usize> DepositAggregateCircuit<C, D>
where F: Extendable<D>, C::Hasher: AlgebraicHasher<F> {
    pub fn new(chain_count: usize, batches: BatchCircuitSet<'_, C, D>, chain_root: &CircuitData<F, C, D>) -> Self {
        let mut builder = CircuitBuilder::new(plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config());
        let opening = AOpeningTarget::build(&mut builder, chain_count, ChainVariant::A);
        let context: Vec<_> = opening.context.config_hash.into_iter().chain(opening.context.end_id).chain(opening.context.end_root).collect();
        let zero = builder.zero();
        let batch = BatchProofTargets::build(&mut builder, &batches, 1, &opening.batch, &context, [zero; 8]);
        let chain = chain_proof(&mut builder, chain_root, &opening, ChainVariant::A);
        let prefix = [1, 11, 1, 0].map(|v| builder.constant(F::from_canonical_u32(v)));
        builder.register_public_inputs(&prefix);
        builder.register_public_inputs(&opening.statement);
        let circuit_data = builder.build::<C>();
        Self { circuit_data, opening, batch, chain }
    }

    pub fn prove(&self, config: &NetworkConfig, opening: &AOpening, batch: &ProofWithPublicInputs<F, C, D>, chain: &ProofWithPublicInputs<F, C, D>) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut witness = PartialWitness::new();
        self.opening.set_witness(&mut witness, config, opening, None)?;
        self.batch.set_witness(&mut witness, opening.deposit_leaves.len(), batch)?;
        witness.set_proof_with_pis_target(&self.chain, chain)?;
        self.circuit_data.prove(witness)
    }

    pub fn verify(&self, proof: ProofWithPublicInputs<F, C, D>) -> anyhow::Result<()> { self.circuit_data.verify(proof) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig};
    use psy_client_data::bridge_aggregate::{ChainConfig, ChainStart, DepositTransition};

    #[test]
    fn complete_opening_digest_and_bootstrap_mutation() {
        let config = NetworkConfig {
            version: 1, network_magic: 0, bridge_user_id: 524288, circuit_set_hash: [7; 32],
            chains: vec![ChainConfig { chain_index: 0, chain_id: [1; 32], bridge: [1; 20], state_manager: [2; 20], bootstrap_id: 0, bootstrap_root: [1, 2, 3, 4] }],
            ethereum_index: 0, reward_payer: [3; 20], reward_token: [4; 20], reward_per_claim: [1; 32], reward_token_decimals: 0, reward_cutover: 0, reward_end_exclusive: 100, max_deposits: 1024, max_withdrawals: 1024, max_rewards: 1024,
        };
        let mut opening = AOpening { config_hash: config.config_hash().unwrap(), window_id: [0; 32], end_checkpoint_id: 1, end_checkpoint_root: [5, 6, 7, 8], starts: vec![ChainStart { chain_index: 0, start_checkpoint_id: 0, start_checkpoint_root: [1, 2, 3, 4] }], deposits: vec![DepositTransition { chain_index: 0, old_root: [1, 2, 3, 4], new_root: [1, 2, 3, 4], old_count: 0, new_count: 0 }], deposit_leaves: vec![] };
        opening.window_id = opening.window_id().unwrap();
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let target = AOpeningTarget::build(&mut builder, 1, ChainVariant::A);
        builder.register_public_inputs(&target.statement);
        let data = builder.build::<PoseidonGoldilocksConfig>();
        let mut witness = PartialWitness::new();
        target.set_witness(&mut witness, &config, &opening, None).unwrap();
        let proof = data.prove(witness).unwrap();
        let digest = opening.statement_digest(&config).unwrap();
        let expected: Vec<_> = digest.chunks_exact(4).map(|word| F::from_canonical_u32(u32::from_be_bytes(word.try_into().unwrap()))).collect();
        assert_eq!(proof.public_inputs, expected);
        data.verify(proof).unwrap();
        let mut witness = PartialWitness::new();
        target.set_witness(&mut witness, &config, &opening, None).unwrap();
        witness.target_values.insert(target.rows[0].start_root[0], F::from_canonical_u32(99));
        assert!(data.prove(witness).is_err());
        for target_to_mutate in [target.context.global_deposit_record_root[0], target.context.global_deposit_count, target.rows[0].first_record, target.rows[0].record_count] {
            let mut witness = PartialWitness::new();
            target.set_witness(&mut witness, &config, &opening, None).unwrap();
            let original = witness.target_values[&target_to_mutate];
            witness.target_values.insert(target_to_mutate, original + F::ONE);
            assert!(data.prove(witness).is_err());
        }
    }
}
