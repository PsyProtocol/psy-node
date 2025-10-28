use plonky2::{field::extension::Extendable, hash::hash_types::RichField, iop::{generator::{GeneratedValues, SimpleGenerator}, target::Target, witness::{PartitionWitness, Witness, WitnessWrite}}, plonk::{circuit_builder::CircuitBuilder, circuit_data::CommonCircuitData}, util::serialization::{Buffer, IoResult, Read, Write}};

use psy_plonky2_basic_helpers::builder::{comparison::CircuitBuilderComparison, connect::CircuitBuilderConnectHelpers};

use super::merkle_proof::MerkleProofGadget;


pub fn merkle_array_helper<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    offset: Target,
    values: Vec<Target>,
    merkle_proofs: &[MerkleProofGadget],
) {
    assert!(values.len() <= merkle_proofs.len()*4, "not enough merkle proofs to use an array helper");

    let mut merkle_values = Vec::with_capacity(merkle_proofs.len()*4);
    for p in merkle_proofs.iter() {
        merkle_values.extend_from_slice(&p.value.elements);
    }

    builder.add_simple_generator(MerkleArrayGenerator{
        offset,
        merkle_values,
        values,
    });
}

pub fn merkle_array_helper_new_values<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    offset: Target,
    values_count: usize,
    merkle_proofs: &[MerkleProofGadget],
) -> Vec<Target> {
    let values = builder.add_virtual_targets(values_count);
    assert!(values.len() <= merkle_proofs.len()*4, "not enough merkle proofs to use an array helper");

    let mut merkle_values = Vec::with_capacity(merkle_proofs.len()*4);
    for p in merkle_proofs.iter() {
        merkle_values.extend_from_slice(&p.value.elements);
    }

    builder.add_simple_generator(MerkleArrayGenerator{
        offset,
        merkle_values,
        values: values.clone(),
    });

    values
}



pub fn enforce_merkle_array_helper_new_values_2_bit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    offset_lower_2_bits: Target,
    values_count: usize,
    merkle_proofs: &[MerkleProofGadget],
) -> Vec<Target> {
    // IMPORTANT SECURITY INFO: we assume you ALREADY range checked offset_lower_2_bits to be less than 4


    if values_count == merkle_proofs.len()*4 {
        // only enough values if it is zero aligned
        builder.assert_zero(offset_lower_2_bits);
        return merkle_array_helper_new_values(builder, offset_lower_2_bits, values_count, merkle_proofs);
    }

    assert!(values_count <= merkle_proofs.len()*4, "not enough merkle proofs to use an array helper");

    let values = builder.add_virtual_targets(values_count);

    let mut merkle_values = Vec::with_capacity(merkle_proofs.len()*4);
    for p in merkle_proofs.iter() {
        merkle_values.extend_from_slice(&p.value.elements);
    }

    let offset_is_0 = builder.is_zero(offset_lower_2_bits);
    let offset_is_1 = builder.is_equal_to_u64(offset_lower_2_bits, 1);
    let offset_is_2 = builder.is_equal_to_u64(offset_lower_2_bits, 2);
    let offset_is_0_or_1 = builder.or(offset_is_0, offset_is_1);
    let offset_is_0_or_1_or_2 = builder.or(offset_is_0_or_1, offset_is_2);
    let offset_is_3 = builder.not(offset_is_0_or_1_or_2);
    
    
    for (i, t) in values.iter().enumerate() {
        builder.connect_if_true(offset_is_0, *t, merkle_values[i]);
    }
    for (i, t) in values.iter().enumerate() {
        builder.connect_if_true(offset_is_1, *t, merkle_values[i+1]);
    }
    for (i, t) in values.iter().enumerate() {
        builder.connect_if_true(offset_is_2, *t, merkle_values[i+2]);
    }
    for (i, t) in values.iter().enumerate() {
        builder.connect_if_true(offset_is_3, *t, merkle_values[i+3]);
    }

    builder.add_simple_generator(MerkleArrayGenerator{
        offset: offset_lower_2_bits,
        merkle_values,
        values: values.clone(),
    });

    



    values
}

#[derive(Debug, Default)]
pub struct MerkleArrayGenerator {
    offset: Target,
    merkle_values: Vec<Target>,

    // generated
    values: Vec<Target>,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D> for MerkleArrayGenerator {
    fn id(&self) -> String {
        "MerkleArrayGenerator".to_string()
    }

    fn dependencies(&self) -> Vec<Target> {
        let mut new_vec = Vec::with_capacity(self.merkle_values.len() + self.values.len() + 1);
        new_vec.extend_from_slice(&self.merkle_values);
        new_vec.push(self.offset);
        new_vec
    }

    fn run_once(
        &self,
        witness: &PartitionWitness<F>,
        out_buffer: &mut GeneratedValues<F>,
    ) -> anyhow::Result<()> {
        let offset = (witness.get_target(self.offset).to_canonical_u64()) as usize;

        if offset + self.values.len() > self.merkle_values.len() {
            anyhow::bail!("tried to generate merkle array values without proving enough merkle leaves");
        }

        for (value, target) in self.merkle_values.iter().skip(offset).map(|v| witness.get_target(*v)).zip(self.values.iter()) {
            out_buffer.set_target(*target, value)?;
        }

        Ok(())
    }

    fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
        dst.write_target(self.offset)?;
        dst.write_target_vec(&self.merkle_values)?;
        dst.write_target_vec(&self.values)
    }

    fn deserialize(src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self> {
        let offset = src.read_target()?;
        let merkle_values = src.read_target_vec()?;
        let values = src.read_target_vec()?;
        Ok(Self {
            offset,
            merkle_values,
            values,
        })
    }
}
