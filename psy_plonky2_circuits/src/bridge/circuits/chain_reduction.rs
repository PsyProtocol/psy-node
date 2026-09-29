use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField as F, types::Field},
    iop::{target::Target, witness::{PartialWitness, WitnessWrite}},
    plonk::{circuit_builder::CircuitBuilder, circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData}, config::{AlgebraicHasher, GenericConfig}, proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget}},
};
use psy_client_data::bridge_aggregate::NetworkConfig;
use psy_plonky2_basic_helpers::builder::{comparison::CircuitBuilderComparison, connect::CircuitBuilderConnectHelpers};
use psy_plonky2_common_circuits::bridge::{aggregate_commitment::chain_rows_hash, aggregate_config::NetworkConfigTarget};
use super::chain_aggregate::{ChainBaseCircuits, ChainContext, ChainContextTarget, ChainRow, ChainRowTarget, ChainVariant, CHAIN_PI_WORDS};

pub struct ChainReductionCircuit<C: GenericConfig<D, F = F>, const D: usize> where F: Extendable<D>, C::Hasher: AlgebraicHasher<F> {
    pub circuit_data: CircuitData<F, C, D>,
    pub variant: ChainVariant,
    pub level: u8,
    pub source_chain_count: usize,
    config: NetworkConfigTarget,
    context: ChainContextTarget,
    first: Target,
    rows: Vec<ChainRowTarget>,
    children: [ProofWithPublicInputsTarget<D>; 2],
}

impl<C: GenericConfig<D, F = F> + 'static, const D: usize> ChainReductionCircuit<C, D> where F: Extendable<D>, C::Hasher: AlgebraicHasher<F> {
    pub fn build_base(base: &ChainBaseCircuits<C, D>) -> anyhow::Result<Self> {
        anyhow::ensure!(base.real.circuit_data.common == base.empty.circuit_data.common, "chain base common data mismatch");
        Self::build(base.real.source_chain_count, base.real.variant, 1, &base.real.circuit_data.common, &base.real.circuit_data.verifier_only, Some(&base.empty.circuit_data.verifier_only))
    }
    pub fn build_next(child: &Self) -> anyhow::Result<Self> {
        Self::build(child.source_chain_count, child.variant, child.level + 1, &child.circuit_data.common, &child.circuit_data.verifier_only, None)
    }
    fn build(source_chain_count: usize, variant: ChainVariant, level: u8, common: &CommonCircuitData<F, D>, verifier: &VerifierOnlyCircuitData<C, D>, empty_verifier: Option<&VerifierOnlyCircuitData<C, D>>) -> anyhow::Result<Self> {
        anyhow::ensure!((1..=8).contains(&level) && common.num_public_inputs == CHAIN_PI_WORDS, "invalid chain reduction child shape");
        let capacity = 1usize << level;
        let half = capacity / 2;
        let mut builder = CircuitBuilder::new(CircuitConfig::standard_recursion_config());
        let zero = builder.zero();
        let one = builder.one();
        let context = ChainContextTarget::new(&mut builder);
        let config = NetworkConfigTarget::new(&mut builder, source_chain_count);
        let config_hash = config.hash(&mut builder);
        for (left, right) in config_hash.into_iter().zip(context.config_hash) { builder.connect(left, right); }
        let first = builder.add_virtual_target();
        let first_bits = builder.split_le(first, 32);
        for &bit in &first_bits[..level as usize] { builder.assert_zero(bit.target); }
        let limit = builder.constant(F::from_canonical_usize(source_chain_count.next_power_of_two()));
        builder.ensure_is_less_than(32, first, limit);
        let real_vk = builder.constant_verifier_data(verifier);
        let empty_vk = empty_verifier.map(|verifier| builder.constant_verifier_data(verifier));
        let children: [_; 2] = std::array::from_fn(|_| builder.add_virtual_proof_with_pis(common));
        let all_active = builder.constant_bool(true);
        let mut child_counts = Vec::with_capacity(2);
        for (side, child) in children.iter().enumerate() {
            let pi = &child.public_inputs;
            let offset = builder.constant(F::from_canonical_usize(side * half));
            let ordinal = builder.add(first, offset);
            builder.range_check(ordinal, 32);
            builder.connect(pi[18], ordinal);
            let mut expected_count = zero;
            for i in 0..half {
                let row_ordinal = builder.add_const(ordinal, F::from_canonical_usize(i));
                let configured = builder.constant(F::from_canonical_usize(source_chain_count));
                let active = builder.is_less_than(32, row_ordinal, configured);
                expected_count = builder.add(expected_count, active.target);
            }
            builder.connect(pi[19], expected_count);
            let is_real = builder.is_not_equal(expected_count, zero);
            if let Some(empty_vk) = &empty_vk {
                builder.conditionally_verify_proof::<C>(is_real, child, &real_vk, child, empty_vk, common);
            } else { builder.verify_proof::<C>(child, &real_vk, common); }
            let family = builder.constant(F::from_canonical_u32(if level == 1 { 9 } else { 10 }));
            let real_variant = builder.constant(F::from_canonical_u8(variant.number()));
            let selected_variant = if level == 1 {
                let empty_variant = builder.constant(F::from_canonical_u8(variant.number() | 128));
                builder.select(is_real, real_variant, empty_variant)
            } else { real_variant };
            let child_level = builder.constant(F::from_canonical_u8(level - 1));
            for (target, value) in pi[..4].iter().zip([one, family, selected_variant, child_level]) { builder.connect(*target, value); }
            context.connect_proof(&mut builder, pi, all_active);
            context.connect_deposit_context(&mut builder, &pi[28..36], pi[36], all_active);
            child_counts.push(expected_count);
        }
        let count = builder.add(child_counts[0], child_counts[1]);
        let rows: Vec<_> = (0..capacity).map(|_| ChainRowTarget::new(&mut builder, variant)).collect();
        let mut encoded = Vec::with_capacity(capacity);
        for (i, row) in rows.iter().enumerate() {
            let ordinal = builder.add_const(first, F::from_canonical_usize(i));
            let index = builder.constant(F::from_canonical_usize(i));
            let active = builder.is_less_than(32, index, count);
            row.constrain(&mut builder, &config, ordinal, active);
            encoded.push(row.encode(&mut builder));
        }
        for side in 0..2 {
            let pi = &children[side].public_inputs;
            let hash = chain_rows_hash(&mut builder, variant.number(), pi[18], &encoded[side * half..(side + 1) * half], child_counts[side]);
            for (left, right) in hash.into_iter().zip(&pi[20..28]) { builder.connect(left, *right); }
        }
        let hash = chain_rows_hash(&mut builder, variant.number(), first, &encoded, count);
        context.register(&mut builder, 10, variant.number(), level);
        builder.register_public_inputs(&[first, count]);
        builder.register_public_inputs(&hash);
        context.register_deposit_context(&mut builder);
        let circuit_data = builder.build::<C>();
        Ok(Self { circuit_data, variant, level, source_chain_count, config, context, first, rows, children })
    }
    pub fn set_witness(&self, witness: &mut PartialWitness<F>, config: &NetworkConfig, context: &ChainContext, first_ordinal: u32, rows: &[ChainRow], left: &ProofWithPublicInputs<F, C, D>, right: &ProofWithPublicInputs<F, C, D>) -> anyhow::Result<()> {
        let expected = self.source_chain_count.saturating_sub(first_ordinal as usize).min(self.rows.len());
        anyhow::ensure!(rows.len() == expected && rows.iter().all(|row| row.variant() == self.variant), "chain reduction rows mismatch");
        self.config.set_witness(witness, config)?;
        self.context.set_witness(witness, context)?;
        witness.set_target(self.first, F::from_canonical_u32(first_ordinal))?;
        for (i, target) in self.rows.iter().enumerate() { target.set_witness(witness, rows.get(i))?; }
        witness.set_proof_with_pis_target(&self.children[0], left)?;
        witness.set_proof_with_pis_target(&self.children[1], right)?;
        Ok(())
    }
    pub fn prove(&self, config: &NetworkConfig, context: &ChainContext, first_ordinal: u32, rows: &[ChainRow], left: &ProofWithPublicInputs<F, C, D>, right: &ProofWithPublicInputs<F, C, D>) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut witness = PartialWitness::new();
        self.set_witness(&mut witness, config, context, first_ordinal, rows, left, right)?;
        self.circuit_data.prove(witness)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::chain_aggregate::tests::{fixture, rejects, C};
    use super::super::chain_aggregate::DepositRangeEndpoints;

    #[test]
    fn reduction_rejects_nonadjacent_children_and_changed_row_preimages() {
        let (config, context, rows) = fixture(3);
        let bases = ChainBaseCircuits::<C, 2>::build_b(3).unwrap();
        let endpoints = DepositRangeEndpoints::zero();
        let leaves: Vec<_> = rows.iter().enumerate().map(|(i, row)| bases.real.prove(&config, &context, i as u32, Some(row), &[], Some(&endpoints)).unwrap()).collect();
        let empty = bases.empty.prove(&config, &context, 3, None, &[], None).unwrap();
        let reduction = ChainReductionCircuit::build_base(&bases).unwrap();
        let left = reduction.prove(&config, &context, 0, &rows[..2], &leaves[0], &leaves[1]).unwrap();
        let right = reduction.prove(&config, &context, 2, &rows[2..], &leaves[2], &empty).unwrap();
        rejects(|| reduction.prove(&config, &context, 0, &rows[..2], &leaves[0], &leaves[2]));
        rejects(|| reduction.prove(&config, &context, 0, &rows[..2], &leaves[1], &leaves[0]));
        let mut changed = rows[..2].to_vec();
        if let ChainRow::B { range, .. } = &mut changed[0] { range.first_record += 1; }
        rejects(|| reduction.prove(&config, &context, 0, &changed, &leaves[0], &leaves[1]));
        let root = ChainReductionCircuit::build_next(&reduction).unwrap();
        let proof = root.prove(&config, &context, 0, &rows, &left, &right).unwrap();
        root.circuit_data.verify(proof).unwrap();
        let mut changed = rows.clone();
        if let ChainRow::B { end, .. } = &mut changed[2] { end.withdrawal_root[0] += 1; }
        rejects(|| root.prove(&config, &context, 0, &changed, &left, &right));
        let mut changed_context = context.clone();
        changed_context.end_checkpoint_id += 1;
        rejects(|| root.prove(&config, &changed_context, 0, &rows, &left, &right));
        for change_count in [false, true] {
            let mut changed_context = context.clone();
            if change_count { changed_context.global_deposit_count = 1; } else { changed_context.global_deposit_record_root[0] ^= 1; }
            rejects(|| root.prove(&config, &changed_context, 0, &rows, &left, &right));
            let wrong_empty = bases.empty.prove(&config, &changed_context, 3, None, &[], None).unwrap();
            rejects(|| reduction.prove(&config, &context, 2, &rows[2..], &leaves[2], &wrong_empty));
        }
    }
}
