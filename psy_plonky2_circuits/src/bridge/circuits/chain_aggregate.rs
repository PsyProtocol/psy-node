use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField as F, types::{Field, Field64}},
    iop::{target::Target, witness::{PartialWitness, WitnessWrite}},
    plonk::circuit_builder::CircuitBuilder,
};
use psy_client_data::bridge_aggregate::{ChainStart, DepositTransition, DepositLeafRange, DEPOSIT_RECORD_CAPACITY};
use psy_plonky2_basic_helpers::builder::comparison::CircuitBuilderComparison;
use psy_plonky2_common_circuits::bridge::aggregate_commitment::Bytes32Target;

#[derive(Clone, Debug)]
pub struct ChainContext {
    pub config_hash: [u8; 32],
    pub end_checkpoint_id: u64,
    pub end_checkpoint_root: [u64; 4],
    pub global_deposit_count: u32,
}

#[derive(Clone, Debug)]
pub struct ChainRow {
    pub start: ChainStart,
    pub transition: DepositTransition,
    pub range: DepositLeafRange,
}

pub(crate) struct ChainContextTarget {
    pub config_hash: Bytes32Target,
    pub end_id: [Target; 2],
    pub end_root: [Target; 4],
    pub global_deposit_count: Target,
}
impl ChainContextTarget {
    pub fn new<const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self where F: Extendable<D> {
        let value = Self {
            config_hash: builder.add_virtual_target_arr(), end_id: builder.add_virtual_target_arr(),
            end_root: builder.add_virtual_target_arr(), global_deposit_count: builder.add_virtual_target(),
        };
        for target in value.config_hash.into_iter().chain(value.end_id) { builder.range_check(target, 32); }
        builder.range_check(value.global_deposit_count, 6);
        let maximum = builder.constant(F::from_canonical_usize(DEPOSIT_RECORD_CAPACITY));
        builder.ensure_is_less_than_or_equal(6, value.global_deposit_count, maximum);
        builder.assert_zero(value.end_id[1]);
        value
    }
    pub fn set_witness(&self, witness: &mut PartialWitness<F>, context: &ChainContext) -> anyhow::Result<()> {
        set_bytes(witness, &self.config_hash, &context.config_hash)?;
        set_u64(witness, self.end_id, context.end_checkpoint_id)?;
        set_hash(witness, self.end_root, context.end_checkpoint_root)?;
        witness.set_target(self.global_deposit_count, F::from_canonical_u32(context.global_deposit_count))
    }
}

pub(crate) struct ChainRowTarget {
    pub chain_index: Target,
    pub start_id: [Target; 2],
    pub start_root: [Target; 4],
    pub old_root: [Target; 4],
    pub new_root: [Target; 4],
    pub old_count: Target,
    pub new_count: Target,
    pub first_leaf: Target,
    pub leaf_count: Target,
}
impl ChainRowTarget {
    pub fn new<const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self where F: Extendable<D> {
        let row = Self {
            chain_index: builder.add_virtual_target(), start_id: builder.add_virtual_target_arr(), start_root: builder.add_virtual_target_arr(),
            old_root: builder.add_virtual_target_arr(), new_root: builder.add_virtual_target_arr(), old_count: builder.add_virtual_target(), new_count: builder.add_virtual_target(),
            first_leaf: builder.add_virtual_target(), leaf_count: builder.add_virtual_target(),
        };
        builder.range_check(row.chain_index, 8);
        for target in row.start_id.into_iter().chain([row.old_count, row.new_count]) { builder.range_check(target, 32); }
        builder.range_check(row.first_leaf, 6);
        builder.range_check(row.leaf_count, 6);
        let end = builder.add(row.old_count, row.leaf_count);
        builder.range_check(end, 32);
        builder.connect(end, row.new_count);
        row
    }
    pub fn register<const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) where F: Extendable<D> {
        builder.register_public_input(self.chain_index);
        builder.register_public_inputs(&self.start_id);
        builder.register_public_inputs(&self.start_root);
        builder.register_public_inputs(&self.old_root);
        builder.register_public_inputs(&self.new_root);
        builder.register_public_inputs(&[self.old_count, self.new_count]);
    }
    pub fn set_witness(&self, witness: &mut PartialWitness<F>, row: &ChainRow) -> anyhow::Result<()> {
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

fn set_u64(witness: &mut PartialWitness<F>, targets: [Target; 2], value: u64) -> anyhow::Result<()> {
    witness.set_target(targets[0], F::from_canonical_u32(value as u32))?;
    witness.set_target(targets[1], F::from_canonical_u32((value >> 32) as u32))
}
pub(super) fn set_bytes(witness: &mut PartialWitness<F>, targets: &[Target], bytes: &[u8]) -> anyhow::Result<()> {
    anyhow::ensure!(bytes.len() == targets.len() * 4, "byte/target width mismatch");
    for (target, bytes) in targets.iter().zip(bytes.chunks_exact(4)) {
        witness.set_target(*target, F::from_canonical_u32(u32::from_be_bytes(bytes.try_into()?)))?;
    }
    Ok(())
}
fn set_hash(witness: &mut PartialWitness<F>, targets: [Target; 4], values: [u64; 4]) -> anyhow::Result<()> {
    for (target, value) in targets.into_iter().zip(values) {
        anyhow::ensure!(value < F::ORDER, "noncanonical Hash4");
        witness.set_target(target, F::from_canonical_u64(value))?;
    }
    Ok(())
}
