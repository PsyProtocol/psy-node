use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::Field},
    iop::{target::Target, witness::{PartialWitness, WitnessWrite}},
    plonk::{circuit_builder::CircuitBuilder, circuit_data::{CircuitConfig, CircuitData}, config::{AlgebraicHasher, GenericConfig}, proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget}},
    recursion::dummy_circuit::{dummy_circuit, dummy_proof},
};
use psy_client_data::bridge_aggregate::{BOpening, NetworkConfig};
use psy_plonky2_basic_helpers::builder::comparison::CircuitBuilderComparison;
use psy_plonky2_common_circuits::bridge::aggregate_commitment::{self as hash, Domain, RecordTarget, WithdrawalLeafTarget, RewardLeafTarget};
use super::{chain_aggregate::ChainVariant, deposit_aggregate::{AOpeningTarget, BatchCircuitSet, BatchOpeningTarget, BatchProofTargets, chain_proof, less_words}, record_batch::{connect_if, set_bytes}};

type F = GoldilocksField;
pub const CHECKPOINT_AGGREGATE_PI_LEN: usize = 12;

pub struct CheckpointCircuitSet<'a, C: GenericConfig<D, F = F>, const D: usize>
where F: Extendable<D> {
    pub positive: &'a CircuitData<F, C, D>,
    pub identity: &'a CircuitData<F, C, D>,
    pub end: &'a CircuitData<F, C, D>,
}

pub struct CheckpointAggregateCircuit<C: GenericConfig<D, F = F>, const D: usize>
where F: Extendable<D> {
    pub circuit_data: CircuitData<F, C, D>,
    opening: AOpeningTarget,
    withdrawals: BatchOpeningTarget,
    rewards: BatchOpeningTarget,
    withdrawal_words: Vec<Vec<Target>>,
    reward_words: Vec<Vec<Target>>,
    withdrawal_proof: BatchProofTargets<C, D>,
    reward_proof: BatchProofTargets<C, D>,
    chain: ProofWithPublicInputsTarget<D>,
    end: ProofWithPublicInputsTarget<D>,
    ranges: Vec<ProofWithPublicInputsTarget<D>>,
    range_count: Target,
    range_indices: Vec<Target>,
    dummy: CircuitData<F, C, D>,
}

impl<C: GenericConfig<D, F = F>, const D: usize> CheckpointAggregateCircuit<C, D>
where F: Extendable<D>, C::Hasher: AlgebraicHasher<F> {
    pub fn new(chain_count: usize, withdrawals: BatchCircuitSet<'_, C, D>, rewards: BatchCircuitSet<'_, C, D>, chain_root: &CircuitData<F, C, D>, checkpoints: CheckpointCircuitSet<'_, C, D>) -> Self {
        assert_eq!(checkpoints.positive.common, checkpoints.identity.common);
        assert_eq!(checkpoints.positive.common.num_public_inputs, 28);
        assert_eq!(checkpoints.end.common.num_public_inputs, 30);
        let mut builder = CircuitBuilder::new(CircuitConfig::standard_recursion_config());
        let opening = AOpeningTarget::build(&mut builder, chain_count, ChainVariant::B);
        let zero = builder.zero();
        let one = builder.one();
        let active = builder._true();
        let ends: Vec<_> = opening.rows.iter().map(|row| row.end.unwrap()).collect();
        let ends_hash = hash::chain_ends_hash(&mut builder, &ends);
        let end = builder.add_virtual_proof_with_pis(&checkpoints.end.common);
        let end_vk = builder.constant_verifier_data(&checkpoints.end.verifier_only);
        builder.verify_proof::<C>(&end, &end_vk, &checkpoints.end.common);
        for (target, value) in end.public_inputs[..4].iter().zip([1, 6, 0, 0]) {
            let expected = builder.constant(F::from_canonical_u32(value)); builder.connect(*target, expected);
        }
        opening.context.connect_proof(&mut builder, &end.public_inputs, active);
        for i in 0..8 { builder.connect(end.public_inputs[22 + i], ends_hash[i]); }
        let range_count = builder.add_virtual_target();
        builder.range_check(range_count, 9);
        let maximum = builder.constant(F::from_canonical_usize(chain_count));
        builder.ensure_is_less_than_or_equal(9, one, range_count);
        builder.ensure_is_less_than_or_equal(9, range_count, maximum);
        let dummy = dummy_circuit::<F, C, D>(&checkpoints.positive.common);
        assert_eq!(dummy.common, checkpoints.positive.common);
        let positive_vk = builder.constant_verifier_data(&checkpoints.positive.verifier_only);
        let identity_vk = builder.constant_verifier_data(&checkpoints.identity.verifier_only);
        let dummy_vk = builder.constant_verifier_data(&dummy.verifier_only);
        let mut ranges: Vec<ProofWithPublicInputsTarget<D>> = Vec::with_capacity(chain_count);
        for i in 0..chain_count {
            let ordinal = builder.constant(F::from_canonical_usize(i));
            let real = builder.is_less_than(9, ordinal, range_count);
            let inactive = builder.not(real);
            let proof = builder.add_virtual_proof_with_pis(&checkpoints.positive.common);
            let pi = &proof.public_inputs;
            let start = [pi[19], pi[18]];
            let end_id = [opening.context.end_id[1], opening.context.end_id[0]];
            for &word in &pi[18..20] { builder.range_check(word, 32); }
            hash::encode_hash4(&mut builder, pi[20..24].try_into().unwrap());
            let positive = less_words(&mut builder, &start, &end_id);
            let future = less_words(&mut builder, &end_id, &start);
            connect_if(&mut builder, real, future.target, zero);
            let verifier = builder.select_verifier_data(positive, &positive_vk, &identity_vk);
            builder.conditionally_verify_proof::<C>(real, &proof, &verifier, &proof, &dummy_vk, &checkpoints.positive.common);
            for &target in pi { connect_if(&mut builder, inactive, target, zero); }
            for (target, value) in [pi[0], pi[1], pi[3]].into_iter().zip([1, 5, 0]) {
                let expected = builder.constant(F::from_canonical_u32(value)); connect_if(&mut builder, real, target, expected);
            }
            let identity = builder.not(positive);
            connect_if(&mut builder, real, pi[2], identity.target);
            opening.context.connect_proof(&mut builder, pi, real);
            for j in 0..4 { connect_if(&mut builder, real, pi[24 + j], end.public_inputs[18 + j]); }
            if let Some(previous) = ranges.last() {
                let previous = &previous.public_inputs;
                let mut left = vec![previous[19], previous[18]];
                let mut right = start.to_vec();
                for j in 0..4 {
                    let left_words = hash::encode_hash4(&mut builder, [previous[20 + j], zero, zero, zero]);
                    let right_words = hash::encode_hash4(&mut builder, [pi[20 + j], zero, zero, zero]);
                    left.extend_from_slice(&left_words[6..8]); right.extend_from_slice(&right_words[6..8]);
                }
                let ordered = less_words(&mut builder, &left, &right);
                connect_if(&mut builder, real, ordered.target, one);
            }
            ranges.push(proof);
        }
        let mut range_indices = Vec::with_capacity(chain_count);
        let mut used = vec![zero; chain_count];
        for row in &opening.rows {
            let index = builder.add_virtual_target();
            builder.range_check(index, 16);
            let valid = builder.is_less_than(16, index, range_count);
            builder.assert_one(valid.target);
            for (j, proof) in ranges.iter().enumerate() {
                let ordinal = builder.constant(F::from_canonical_usize(j));
                let selected = builder.is_equal(index, ordinal);
                used[j] = builder.add(used[j], selected.target);
                for k in 0..2 { connect_if(&mut builder, selected, row.start_id[k], proof.public_inputs[18 + k]); }
                for k in 0..4 { connect_if(&mut builder, selected, row.start_root[k], proof.public_inputs[20 + k]); }
            }
            range_indices.push(index);
        }
        for (i, count) in used.into_iter().enumerate() {
            let ordinal = builder.constant(F::from_canonical_usize(i));
            let real = builder.is_less_than(9, ordinal, range_count);
            let unused = builder.is_equal(count, zero);
            connect_if(&mut builder, real, unused.target, zero);
        }
        let mut family_words = Vec::new();
        let mut family_batches = Vec::new();
        for family in [2, 3] {
            let count = builder.add_virtual_target();
            let mut records = Vec::with_capacity(1024);
            let mut words = Vec::with_capacity(1024);
            let mut previous_key: Option<Vec<Target>> = None;
            for i in 0..1024 {
                let record = if family == 2 { RecordTarget::Withdrawal(WithdrawalLeafTarget { chain_index: builder.add_virtual_target(), sender_user_id: builder.add_virtual_target(), recipient: builder.add_virtual_target_arr(), token: builder.add_virtual_target_arr(), amount: builder.add_virtual_target_arr(), nonce: builder.add_virtual_target_arr() }) }
                    else { RecordTarget::Reward(RewardLeafTarget { claim_checkpoint_id: builder.add_virtual_target_arr(), user_id: builder.add_virtual_target(), height: builder.add_virtual_target(), path_index: builder.add_virtual_target(), nullifier_index: builder.add_virtual_target(), recipient: builder.add_virtual_target_arr() }) };
                let encoded = record.encode(&mut builder);
                let ordinal = builder.constant(F::from_canonical_usize(i));
                let real = builder.is_less_than(11, ordinal, count);
                let inactive = builder.not(real);
                for &word in &encoded { connect_if(&mut builder, inactive, word, zero); }
                let key = match record {
                    RecordTarget::Withdrawal(record) => {
                        let mut recipient_zero = builder._true();
                        let mut amount_zero = builder._true();
                        for word in record.recipient { let empty = builder.is_equal(word, zero); recipient_zero = builder.and(recipient_zero, empty); }
                        for word in record.amount { let empty = builder.is_equal(word, zero); amount_zero = builder.and(amount_zero, empty); }
                        connect_if(&mut builder, real, recipient_zero.target, zero);
                        connect_if(&mut builder, real, amount_zero.target, zero);
                        let modulus = [0, 0, 0, 0, 0, 0, 0xffff_ffff, 1].map(|word| builder.constant(F::from_canonical_u32(word)));
                        let canonical = less_words(&mut builder, &record.amount, &modulus);
                        connect_if(&mut builder, real, canonical.target, one);
                        let mut key = vec![record.chain_index]; key.extend(record.nonce); key
                    }
                    RecordTarget::Reward(record) => {
                        let claim = [record.claim_checkpoint_id[1], record.claim_checkpoint_id[0]];
                        let before = less_words(&mut builder, &claim, &[opening.config.reward_cutover[1], opening.config.reward_cutover[0]]);
                        connect_if(&mut builder, real, before.target, zero);
                        let eligible = less_words(&mut builder, &claim, &[opening.config.reward_end_exclusive[1], opening.config.reward_end_exclusive[0]]);
                        connect_if(&mut builder, real, eligible.target, one);
                        let future = less_words(&mut builder, &[opening.context.end_id[1], opening.context.end_id[0]], &claim);
                        connect_if(&mut builder, real, future.target, zero);
                        let mut recipient_zero = builder._true();
                        for word in record.recipient { let empty = builder.is_equal(word, zero); recipient_zero = builder.and(recipient_zero, empty); }
                        connect_if(&mut builder, real, recipient_zero.target, zero);
                        let mut valid_height = zero;
                        let mut path_limit = zero;
                        let mut nullifier_base = zero;
                        for height in 2..=21 {
                            let expected = builder.constant(F::from_canonical_usize(height));
                            let selected = builder.is_equal(record.height, expected);
                            valid_height = builder.add(valid_height, selected.target);
                            path_limit = builder.mul_const_add(F::from_canonical_u32(1 << (height - 2)), selected.target, path_limit);
                            nullifier_base = builder.mul_const_add(F::from_canonical_u32((1 << height) - 1), selected.target, nullifier_base);
                        }
                        connect_if(&mut builder, real, valid_height, one);
                        let in_path = builder.is_less_than(32, record.path_index, path_limit);
                        connect_if(&mut builder, real, in_path.target, one);
                        let nullifier = builder.add(nullifier_base, record.path_index);
                        connect_if(&mut builder, real, record.nullifier_index, nullifier);
                        vec![claim[0], claim[1], record.nullifier_index]
                    }
                    RecordTarget::Deposit(_) => unreachable!(),
                };
                if let Some(previous) = previous_key {
                    let ordered = less_words(&mut builder, &previous, &key);
                    connect_if(&mut builder, real, ordered.target, one);
                }
                previous_key = Some(key);
                records.push(record); words.push(encoded);
            }
            let maximum = if family == 2 { opening.config.max_withdrawals } else { opening.config.max_rewards };
            let batch = BatchOpeningTarget::build(&mut builder, opening.context.config_hash, opening.context.end_id, opening.context.end_root, &records, count, maximum);
            family_words.push(words); family_batches.push(batch);
        }
        let rewards_opening = family_batches.pop().unwrap();
        let withdrawals_opening = family_batches.pop().unwrap();
        let reward_words = family_words.pop().unwrap();
        let withdrawal_words = family_words.pop().unwrap();
        let context: Vec<_> = opening.context.config_hash.into_iter().chain(opening.context.end_id).chain(opening.context.end_root).collect();
        let withdrawal_proof = BatchProofTargets::build(&mut builder, &withdrawals, 2, &withdrawals_opening, &context, ends_hash);
        let reward_proof = BatchProofTargets::build(&mut builder, &rewards, 3, &rewards_opening, &context, [zero; 8]);
        let chain = chain_proof(&mut builder, chain_root, &opening, ChainVariant::B);
        let mut body = opening.statement.to_vec();
        body.extend(hash::word(&mut builder, maximum, 32));
        for end in ends { body.extend(end.encode(&mut builder)); }
        for batch in [&withdrawals_opening, &rewards_opening] {
            body.extend(hash::word(&mut builder, batch.count, 32));
            body.extend(hash::word(&mut builder, batch.chunks, 32));
            body.extend(batch.root);
        }
        let statement = hash::commitment(&mut builder, Domain::B, &body);
        let prefix = [1, 11, 2, 0].map(|v| builder.constant(F::from_canonical_u32(v)));
        builder.register_public_inputs(&prefix);
        builder.register_public_inputs(&statement);
        let circuit_data = builder.build::<C>();
        Self { circuit_data, opening, withdrawals: withdrawals_opening, rewards: rewards_opening, withdrawal_words, reward_words, withdrawal_proof, reward_proof, chain, end, ranges, range_count, range_indices, dummy }
    }

    pub fn prove(&self, config: &NetworkConfig, opening: &BOpening, withdrawal: &ProofWithPublicInputs<F, C, D>, reward: &ProofWithPublicInputs<F, C, D>, chain: &ProofWithPublicInputs<F, C, D>, end: &ProofWithPublicInputs<F, C, D>, ranges: &[ProofWithPublicInputs<F, C, D>]) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        opening.validate(config)?;
        let mut starts: Vec<_> = opening.a.starts.iter().map(|start| (start.start_checkpoint_id, start.start_checkpoint_root)).collect();
        starts.sort_unstable(); starts.dedup();
        anyhow::ensure!(ranges.len() == starts.len(), "one proof per distinct sorted start is required");
        let mut witness = PartialWitness::new();
        self.opening.set_witness(&mut witness, config, &opening.a, Some(&opening.ends))?;
        witness.set_target(self.range_count, F::from_canonical_usize(starts.len()))?;
        for (target, start) in self.range_indices.iter().zip(&opening.a.starts) {
            let index = starts.binary_search(&(start.start_checkpoint_id, start.start_checkpoint_root)).unwrap();
            witness.set_target(*target, F::from_canonical_usize(index))?;
        }
        for (i, target) in self.ranges.iter().enumerate() {
            if let Some(proof) = ranges.get(i) { witness.set_proof_with_pis_target(target, proof)?; }
            else { let proof = dummy_proof(&self.dummy, Default::default())?; witness.set_proof_with_pis_target(target, &proof)?; }
        }
        witness.set_target(self.withdrawals.count, F::from_canonical_usize(opening.withdrawals.len()))?;
        witness.set_target(self.rewards.count, F::from_canonical_usize(opening.rewards.len()))?;
        for i in 0..1024 {
            for (words, bytes) in [(&self.withdrawal_words[i], opening.withdrawals.get(i).map(|leaf| leaf.encode()).transpose()?), (&self.reward_words[i], opening.rewards.get(i).map(|leaf| leaf.encode()).transpose()?)] {
                if let Some(bytes) = bytes { set_bytes(&mut witness, words, &bytes)?; }
                else { for &word in words { witness.set_target(word, F::ZERO)?; } }
            }
        }
        self.withdrawal_proof.set_witness(&mut witness, opening.withdrawals.len(), withdrawal)?;
        self.reward_proof.set_witness(&mut witness, opening.rewards.len(), reward)?;
        witness.set_proof_with_pis_target(&self.chain, chain)?;
        witness.set_proof_with_pis_target(&self.end, end)?;
        self.circuit_data.prove(witness)
    }

    pub fn verify(&self, proof: ProofWithPublicInputs<F, C, D>) -> anyhow::Result<()> { self.circuit_data.verify(proof) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;

    #[test]
    fn global_record_order_rejects_duplicate_and_reverse_keys() {
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let left: [Target; 3] = builder.add_virtual_target_arr();
        let right: [Target; 3] = builder.add_virtual_target_arr();
        for word in left.into_iter().chain(right) { builder.range_check(word, 32); }
        let ordered = less_words(&mut builder, &left, &right);
        builder.assert_one(ordered.target);
        let data = builder.build::<PoseidonGoldilocksConfig>();
        let witness = |a: [u32; 3], b: [u32; 3]| {
            let mut witness = PartialWitness::new();
            for (target, value) in left.into_iter().chain(right).zip(a.into_iter().chain(b)) { witness.set_target(target, F::from_canonical_u32(value)).unwrap(); }
            witness
        };
        let proof = data.prove(witness([0, 501, 3], [0, 501, 4])).unwrap();
        data.verify(proof).unwrap();
        assert!(data.prove(witness([0, 501, 3], [0, 501, 3])).is_err());
        assert!(data.prove(witness([0, 502, 3], [0, 501, 4])).is_err());
    }
}
