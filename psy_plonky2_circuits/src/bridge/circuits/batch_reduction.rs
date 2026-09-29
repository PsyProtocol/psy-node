use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::Field},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{circuit_builder::CircuitBuilder, circuit_data::{CircuitConfig, CircuitData}, config::{AlgebraicHasher, GenericConfig}, proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget}},
};
use psy_plonky2_basic_helpers::builder::comparison::CircuitBuilderComparison;
use psy_plonky2_common_circuits::bridge::aggregate_commitment::batch_node;
use super::record_batch::{connect_context, connect_if, BatchFamily, BatchStatementTarget, RecordBatchCircuits, BATCH_PI_LEN};

type F = GoldilocksField;

pub struct BatchReductionCircuit<C: GenericConfig<D, F = F>, const D: usize>
where F: Extendable<D> {
    pub family: BatchFamily,
    pub level: u8,
    pub statement: BatchStatementTarget,
    pub circuit_data: CircuitData<F, C, D>,
    children: [ProofWithPublicInputsTarget<D>; 2],
}

impl<C: GenericConfig<D, F = F>, const D: usize> BatchReductionCircuit<C, D>
where F: Extendable<D>, C::Hasher: AlgebraicHasher<F> {
    pub fn build_base(bases: &RecordBatchCircuits<C, D>) -> anyhow::Result<Self> {
        anyhow::ensure!(bases.real.family == bases.empty.family && !bases.real.empty && bases.empty.empty, "invalid canonical batch pair");
        anyhow::ensure!(bases.real.circuit_data.common == bases.empty.circuit_data.common, "batch pair common data mismatch");
        Self::build(bases.real.family, 1, &bases.real.circuit_data, Some(&bases.empty.circuit_data))
    }

    pub fn build_next(child: &Self) -> anyhow::Result<Self> {
        Self::build(child.family, child.level + 1, &child.circuit_data, None)
    }

    fn build(family: BatchFamily, level: u8, child: &CircuitData<F, C, D>, empty: Option<&CircuitData<F, C, D>>) -> anyhow::Result<Self> {
        anyhow::ensure!((1..=5).contains(&level), "batch reduction level outside 1..=5");
        anyhow::ensure!(child.common.num_public_inputs == BATCH_PI_LEN, "batch child PI width mismatch");
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let zero = builder.zero();
        let children = std::array::from_fn(|_| builder.add_virtual_proof_with_pis(&child.common));
        let real_vk = builder.constant_verifier_data(&child.verifier_only);
        let empty_vk = empty.map(|data| builder.constant_verifier_data(&data.verifier_only));
        let span = 1u32 << (level - 1);
        let maximum = builder.constant(F::from_canonical_u32(span));
        for proof in &children {
            let pi = &proof.public_inputs;
            let statement = BatchStatementTarget::from_public_inputs(pi);
            for target in [statement.first_chunk, statement.real_chunks, statement.first_record, statement.real_records] { builder.range_check(target, 32); }
            builder.ensure_is_less_than_or_equal(32, statement.real_chunks, maximum);
            let is_empty = builder.is_equal(statement.real_records, zero);
            let active = builder.not(is_empty);
            if let Some(empty_vk) = &empty_vk {
                builder.conditionally_verify_proof::<C>(active, proof, &real_vk, proof, empty_vk, &child.common);
            } else {
                builder.verify_proof::<C>(proof, &real_vk, &child.common);
            }
            let expected_variant = if level == 1 {
                let real_variant = builder.constant(F::from_canonical_u8(family as u8));
                let empty_variant = builder.constant(F::from_canonical_u8(family as u8 | 128));
                builder.select(active, real_variant, empty_variant)
            } else { builder.constant(F::from_canonical_u8(family as u8)) };
            builder.connect(pi[2], expected_variant);
            for (target, value) in [(pi[0], 1), (pi[1], if level == 1 { 7 } else { 8 }), (pi[3], level - 1)] {
                let expected = builder.constant(F::from_canonical_u8(value));
                builder.connect(target, expected);
            }
            connect_if(&mut builder, is_empty, statement.real_chunks, zero);
            let capacity = builder.mul_const(F::from_canonical_u32(32), statement.real_chunks);
            builder.ensure_is_less_than_or_equal(32, statement.real_records, capacity);
            let previous_capacity = builder.sub(capacity, statement.real_records);
            let slack = builder.select(active, previous_capacity, zero);
            builder.range_check(slack, 5);
            let chunks_zero = builder.is_equal(statement.real_chunks, zero);
            builder.connect(chunks_zero.target, is_empty.target);
        }
        let left = BatchStatementTarget::from_public_inputs(&children[0].public_inputs);
        let right = BatchStatementTarget::from_public_inputs(&children[1].public_inputs);
        connect_context(&mut builder, &left, &right);
        let next_chunk = builder.add_const(left.first_chunk, F::from_canonical_u32(span));
        builder.connect(right.first_chunk, next_chunk);
        let first_bits = builder.split_le(left.first_chunk, 5);
        for bit in first_bits.iter().take(level as usize) { builder.assert_zero(bit.target); }
        let record_offset = builder.add(left.first_record, left.real_records);
        builder.connect(right.first_record, record_offset);
        let right_empty = builder.is_equal(right.real_records, zero);
        let right_active = builder.not(right_empty);
        connect_if(&mut builder, right_active, left.real_chunks, maximum);
        let full_left_records = builder.constant(F::from_canonical_u32(32 * span));
        connect_if(&mut builder, right_active, left.real_records, full_left_records);
        let real_chunks = builder.add(left.real_chunks, right.real_chunks);
        let real_records = builder.add(left.real_records, right.real_records);
        builder.range_check(real_chunks, 6);
        builder.range_check(real_records, 11);
        let subtree_root = batch_node(&mut builder, level, left.subtree_root, right.subtree_root);
        let statement = BatchStatementTarget { real_chunks, real_records, subtree_root, ..left };
        statement.register(&mut builder, 8, family as u8, level);
        let circuit_data = builder.build::<C>();
        Ok(Self { family, level, statement, circuit_data, children })
    }

    pub fn set_witness(&self, witness: &mut PartialWitness<F>, left: &ProofWithPublicInputs<F, C, D>, right: &ProofWithPublicInputs<F, C, D>) -> anyhow::Result<()> {
        anyhow::ensure!(left.public_inputs.len() == BATCH_PI_LEN && right.public_inputs.len() == BATCH_PI_LEN, "batch child PI width mismatch");
        witness.set_proof_with_pis_target(&self.children[0], left)?;
        witness.set_proof_with_pis_target(&self.children[1], right)
    }

    pub fn prove(&self, left: &ProofWithPublicInputs<F, C, D>, right: &ProofWithPublicInputs<F, C, D>) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut witness = PartialWitness::new();
        self.set_witness(&mut witness, left, right)?;
        self.circuit_data.prove(witness)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::record_batch::{BatchRecords, RecordBatchSource, tests::{context, deposit, digest, pi_digest, rejected, word, C}};
    use psy_client_data::bridge_aggregate::{domain_hash, Domain};

    #[test]
    fn reduction_authenticates_children_and_rejects_gaps_empty_prefix_and_context() {
        let bases = RecordBatchCircuits::<C, 2>::build(RecordBatchSource::Deposit).unwrap();
        let parent = BatchReductionCircuit::build_base(&bases).unwrap();
        let context = context();
        let records: Vec<_> = (0..32).map(deposit).collect();
        let left = bases.real.prove(&context, 0, 0, Some(&BatchRecords::Deposit(&records))).unwrap();
        let last = [deposit(32)];
        let right = bases.real.prove(&context, 1, 32, Some(&BatchRecords::Deposit(&last))).unwrap();
        let proof = parent.prove(&left, &right).unwrap();
        let mut body = domain_hash(Domain::Node).to_vec();
        body.extend(word(1)); body.extend(pi_digest(&left.public_inputs[22..30])); body.extend(pi_digest(&right.public_inputs[22..30]));
        assert_eq!(pi_digest(&proof.public_inputs[22..30]), digest(&body));
        assert_eq!(proof.public_inputs[19], F::from_canonical_u8(2));
        assert_eq!(proof.public_inputs[21], F::from_canonical_u8(33));
        parent.circuit_data.verify(proof).unwrap();
        let short = bases.real.prove(&context, 0, 0, Some(&BatchRecords::Deposit(&last))).unwrap();
        let trailing = bases.empty.prove(&context, 1, 1, None).unwrap();
        parent.circuit_data.verify(parent.prove(&short, &trailing).unwrap()).unwrap();
        let empty_prefix = bases.empty.prove(&context, 0, 0, None).unwrap();
        rejected(|| parent.prove(&empty_prefix, &right).and_then(|proof| parent.circuit_data.verify(proof)));
        rejected(|| parent.prove(&short, &right).and_then(|proof| parent.circuit_data.verify(proof)));
        let gap = bases.empty.prove(&context, 2, 32, None).unwrap();
        rejected(|| parent.prove(&left, &gap).and_then(|proof| parent.circuit_data.verify(proof)));
        let wrong_offset = bases.empty.prove(&context, 1, 31, None).unwrap();
        rejected(|| parent.prove(&left, &wrong_offset).and_then(|proof| parent.circuit_data.verify(proof)));
        let mut other_context = context.clone(); other_context.config_hash[0] ^= 1;
        let other = bases.empty.prove(&other_context, 1, 32, None).unwrap();
        rejected(|| parent.prove(&left, &other).and_then(|proof| parent.circuit_data.verify(proof)));
        let mut altered_count = left.clone(); altered_count.public_inputs[21] = F::from_canonical_u8(31);
        rejected(|| parent.prove(&altered_count, &right).and_then(|proof| parent.circuit_data.verify(proof)));
        let dummy = plonky2::recursion::dummy_circuit::dummy_circuit::<F, C, 2>(&bases.real.circuit_data.common);
        let forged = plonky2::recursion::dummy_circuit::dummy_proof(&dummy, left.public_inputs.iter().copied().enumerate().collect()).unwrap();
        rejected(|| parent.prove(&forged, &right).and_then(|proof| parent.circuit_data.verify(proof)));
        let higher = BatchReductionCircuit::build_next(&parent).unwrap();
        let e2 = bases.empty.prove(&context, 2, 33, None).unwrap();
        let e3 = bases.empty.prove(&context, 3, 33, None).unwrap();
        let empty_right = parent.prove(&e2, &e3).unwrap();
        let real_left = parent.prove(&left, &right).unwrap();
        higher.circuit_data.verify(higher.prove(&real_left, &empty_right).unwrap()).unwrap();
    }
}
