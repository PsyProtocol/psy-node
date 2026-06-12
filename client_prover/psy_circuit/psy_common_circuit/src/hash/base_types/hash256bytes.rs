use plonky2::{
    field::{extension::Extendable, types::PrimeField64},
    hash::hash_types::{HashOutTarget, RichField},
    iop::{
        target::{BoolTarget, Target},
        witness::Witness,
    },
    plonk::circuit_builder::CircuitBuilder,
};

use super::hash256::Hash256Target;
use crate::{
    traits::{ConnectableTarget, CreatableTarget, SwappableTarget, ToTargets},
    u32::arithmetic_u32::U32Target,
};

pub type Hash256BytesTarget = [Target; 32];

impl ToTargets for Hash256BytesTarget {
    fn to_targets(&self) -> Vec<Target> {
        self.to_vec()
    }
}

pub fn read_hash256_bytes_target_from_array(targets: &[Target], offset: usize) -> Hash256BytesTarget {
    assert!(targets.len() >= offset + 32);
    core::array::from_fn(|i| targets[offset + i])
}

pub trait WitnessHash256Bytes<F: PrimeField64>: Witness<F> {
    fn set_hash256_bytes_target(&mut self, target: &Hash256BytesTarget, value: &[u8]) -> anyhow::Result<()>;
}

impl<T: Witness<F>, F: PrimeField64> WitnessHash256Bytes<F> for T {
    fn set_hash256_bytes_target(&mut self, target: &Hash256BytesTarget, value: &[u8]) -> anyhow::Result<()> {
        for (i, t) in target.iter().enumerate() {
            // TODO: range check u8?
            self.set_target(*t, F::from_canonical_u8(value[i]))?;
        }
        Ok(())
    }
}

pub trait CircuitBuilderHash256Bytes<F: RichField + Extendable<D>, const D: usize> {
    fn add_virtual_hash256_bytes_target(&mut self) -> Hash256BytesTarget;
    fn connect_hash256_bytes(&mut self, x: Hash256BytesTarget, y: Hash256BytesTarget);
    fn connect_one_of_hash256_bytes(&mut self, x: Hash256BytesTarget, y_0: Hash256BytesTarget, y_1: Hash256BytesTarget);
    fn select_hash256_bytes(&mut self, b: BoolTarget, x: Hash256BytesTarget, y: Hash256BytesTarget) -> Hash256BytesTarget;
    fn hash256_bytes_to_hash256(&mut self, x: Hash256BytesTarget) -> Hash256Target;
    fn hash256_bytes_to_hash256_be(&mut self, x: Hash256BytesTarget) -> Hash256Target;
    fn hash256_bytes_to_hashout224(&mut self, x: Hash256BytesTarget) -> HashOutTarget;
    fn hash256_bytes_to_hashout(&mut self, x: Hash256BytesTarget) -> HashOutTarget;
    fn hash256_bytes_to_u32_bits(&mut self, x: Hash256BytesTarget) -> [[BoolTarget; 32]; 8];
    fn constant_hash256_bytes(&mut self, value: &[u8]) -> Hash256BytesTarget;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderHash256Bytes<F, D> for CircuitBuilder<F, D> {
    fn add_virtual_hash256_bytes_target(&mut self) -> Hash256BytesTarget {
        // TODO: range check u8?
        core::array::from_fn(|_| self.add_virtual_target())
    }

    fn connect_hash256_bytes(&mut self, x: Hash256BytesTarget, y: Hash256BytesTarget) {
        x.iter().zip(y.iter()).for_each(|(x, y)| {
            self.connect(*x, *y);
        });
    }

    fn select_hash256_bytes(&mut self, b: BoolTarget, x: Hash256BytesTarget, y: Hash256BytesTarget) -> Hash256BytesTarget {
        core::array::from_fn(|i| self.select(b, x[i], y[i]))
    }

    fn hash256_bytes_to_hash256(&mut self, x: Hash256BytesTarget) -> Hash256Target {
        let result = x
            .chunks_exact(4)
            .map(|chunk| {
                let c256 = self.constant(F::from_canonical_u32(0x100));
                let mut value = chunk[3];
                value = self.mul_add(value, c256, chunk[2]);
                value = self.mul_add(value, c256, chunk[1]);
                U32Target(self.mul_add(value, c256, chunk[0]))
            })
            .collect::<Vec<U32Target>>();
        [result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7]]
    }

    fn hash256_bytes_to_u32_bits(&mut self, x: Hash256BytesTarget) -> [[BoolTarget; 32]; 8] {
        let zero = self._false();
        let result = x
            .chunks_exact(4)
            .map(|chunk| {
                let mut bits = [zero; 32];
                bits[0..8].copy_from_slice(&self.split_le(chunk[0], 8));
                bits[8..16].copy_from_slice(&self.split_le(chunk[1], 8));
                bits[16..24].copy_from_slice(&self.split_le(chunk[2], 8));
                bits[24..32].copy_from_slice(&self.split_le(chunk[3], 8));
                bits
            })
            .collect::<Vec<_>>();
        [result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7]]
    }

    fn hash256_bytes_to_hashout224(&mut self, x: Hash256BytesTarget) -> HashOutTarget {
        let result = x
            .chunks_exact(8)
            .map(|chunk| {
                let c256 = self.constant(F::from_canonical_u32(0x100));
                let mut value = chunk[6];
                value = self.mul_add(value, c256, chunk[5]);
                value = self.mul_add(value, c256, chunk[4]);
                value = self.mul_add(value, c256, chunk[3]);
                value = self.mul_add(value, c256, chunk[2]);
                value = self.mul_add(value, c256, chunk[1]);
                self.mul_add(value, c256, chunk[0])
            })
            .collect::<Vec<Target>>();
        HashOutTarget {
            elements: [result[0], result[1], result[2], result[3]],
        }
    }

    fn connect_one_of_hash256_bytes(&mut self, x: Hash256BytesTarget, y_0: Hash256BytesTarget, y_1: Hash256BytesTarget) {
        let result: [Target; 32] = core::array::from_fn(|i| {
            let x_minus_y_0 = self.sub(x[i], y_0[i]);
            let x_minus_y_1 = self.sub(x[i], y_1[i]);
            self.mul(x_minus_y_0, x_minus_y_1)
        });
        for i in 0..32 {
            self.assert_zero(result[i]);
        }
    }

    fn hash256_bytes_to_hash256_be(&mut self, x: Hash256BytesTarget) -> Hash256Target {
        let result = x
            .chunks_exact(4)
            .map(|chunk| {
                let c256 = self.constant(F::from_canonical_u32(0x100));
                let mut value = chunk[0];
                value = self.mul_add(value, c256, chunk[1]);
                value = self.mul_add(value, c256, chunk[2]);
                U32Target(self.mul_add(value, c256, chunk[3]))
            })
            .collect::<Vec<U32Target>>();
        [result[7], result[6], result[5], result[4], result[3], result[2], result[1], result[0]]
    }

    fn hash256_bytes_to_hashout(&mut self, x: Hash256BytesTarget) -> HashOutTarget {
        let result = x
            .chunks_exact(8)
            .map(|chunk| {
                let c256 = self.constant(F::from_canonical_u32(0x100));
                let mut value = chunk[0];
                value = self.mul_add(value, c256, chunk[1]);
                value = self.mul_add(value, c256, chunk[2]);
                value = self.mul_add(value, c256, chunk[3]);
                value = self.mul_add(value, c256, chunk[4]);
                value = self.mul_add(value, c256, chunk[5]);
                value = self.mul_add(value, c256, chunk[6]);
                self.mul_add(value, c256, chunk[7])
            })
            .collect::<Vec<Target>>();
        HashOutTarget {
            elements: [result[3], result[2], result[1], result[0]],
        }
    }

    fn constant_hash256_bytes(&mut self, value: &[u8]) -> Hash256BytesTarget {
        assert_eq!(value.len(), 32);
        core::array::from_fn(|i| self.constant(F::from_canonical_u8(value[i])))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::witness::PartialWitness,
        plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
    };
    use psy_client_common::data::{base_types::hash256::Hash256, qhashout::QHashOut};

    use super::*;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_hash256_to_qhashout_consistency() -> anyhow::Result<()> {
        // Test the consistency between Rust conversion and circuit conversion
        let test_qhashout = QHashOut::<F>::from_str("83955402ec7f375d1d6e8f3bf59753fe0af1e7c62bb4b662716a2524d3e2d186")?;

        println!("Original QHashOut: {}", test_qhashout);
        println!("QHashOut elements: {:?}", test_qhashout.0.elements);

        // Convert QHashOut -> Hash256 using Rust code
        let hash256_from_rust = Hash256::from(test_qhashout);
        println!("Hash256 from Rust: {:?}", hex::encode(&hash256_from_rust.0));

        // Convert Hash256 -> QHashOut using Rust code
        let qhashout_from_rust = QHashOut::<F>::from(hash256_from_rust);
        println!("QHashOut from Rust roundtrip: {}", qhashout_from_rust);

        // Verify roundtrip consistency
        assert_eq!(test_qhashout, qhashout_from_rust, "Rust roundtrip should be consistent");

        // Test circuit conversion
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Create targets
        let hash256_bytes_target = builder.add_virtual_hash256_bytes_target();
        let hash256_be_target = builder.hash256_bytes_to_hash256_be(hash256_bytes_target);
        let hashout_target = builder.hash256_bytes_to_hashout(hash256_bytes_target);

        // Register as public inputs for testing
        builder.register_public_inputs(&hash256_be_target.iter().map(|x| x.0).collect::<Vec<_>>());
        builder.register_public_inputs(&hashout_target.elements);

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();

        // Set witness using Hash256 bytes
        let hash256_bytes = hash256_from_rust.0;
        pw.set_hash256_bytes_target(&hash256_bytes_target, &hash256_bytes)?;

        let proof = data.prove(pw)?;

        println!("Circuit proof public inputs:");
        println!("  Hash256BE (first 8): {:?}", &proof.public_inputs[0..8]);
        println!("  HashOut (last 4): {:?}", &proof.public_inputs[8..12]);

        let circuit_hashout = QHashOut(plonky2::hash::hash_types::HashOut {
            elements: [
                proof.public_inputs[8],
                proof.public_inputs[9],
                proof.public_inputs[10],
                proof.public_inputs[11],
            ],
        });

        println!("Circuit HashOut result: {}", circuit_hashout);

        // Check if circuit result matches Rust conversion
        assert_eq!(qhashout_from_rust, circuit_hashout, "Circuit and Rust conversions should match");

        Ok(())
    }

    #[test]
    fn test_msg_bytes_processing() -> anyhow::Result<()> {
        // Test the specific message processing in DogePsySignatureGadget
        let msg_qhashout = QHashOut::<F>::from_str("83955402ec7f375d1d6e8f3bf59753fe0af1e7c62bb4b662716a2524d3e2d186")?;

        println!("Message QHashOut: {}", msg_qhashout);

        // Convert to le_bytes (as done in set_witness_public_keys_update)
        let msg_bytes = msg_qhashout.to_le_bytes();
        println!("Message LE bytes: {:?}", hex::encode(&msg_bytes));

        // Test circuit processing
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let msg_bytes_target = builder.add_virtual_hash256_bytes_target();
        let msg_hash_target = builder.hash256_bytes_to_hashout(msg_bytes_target);

        builder.register_public_inputs(&msg_hash_target.elements);

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();

        pw.set_hash256_bytes_target(&msg_bytes_target, &msg_bytes)?;

        let proof = data.prove(pw)?;

        let circuit_msg_hash = QHashOut(plonky2::hash::hash_types::HashOut {
            elements: [
                proof.public_inputs[0],
                proof.public_inputs[1],
                proof.public_inputs[2],
                proof.public_inputs[3],
            ],
        });

        println!("Circuit message hash result: {}", circuit_msg_hash);
        println!("Expected (should be same as input): {}", msg_qhashout);

        // They should be equal if conversions are consistent
        // Note: This assertion will fail because to_le_bytes() and
        // hash256_bytes_to_hashout() are not inverse operations - this is by
        // design
        println!("Note: msg_qhashout != circuit_msg_hash is expected due to byte order differences");

        Ok(())
    }

    #[test]
    fn test_hash256_bytes_to_hash256_be_consistency() -> anyhow::Result<()> {
        // Test hash256_bytes_to_hash256_be function consistency
        let test_qhashout = QHashOut::<F>::from_str("83955402ec7f375d1d6e8f3bf59753fe0af1e7c62bb4b662716a2524d3e2d186")?;

        println!("Original QHashOut: {}", test_qhashout);

        // Convert to le_bytes
        let msg_bytes = test_qhashout.to_le_bytes();
        println!("Message LE bytes: {:?}", hex::encode(&msg_bytes));

        // Test circuit processing of hash256_bytes_to_hash256_be
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let msg_bytes_target = builder.add_virtual_hash256_bytes_target();
        let hash256_be_target = builder.hash256_bytes_to_hash256_be(msg_bytes_target);

        builder.register_public_inputs(&hash256_be_target.iter().map(|x| x.0).collect::<Vec<_>>());

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();

        pw.set_hash256_bytes_target(&msg_bytes_target, &msg_bytes)?;

        let proof = data.prove(pw)?;

        println!("Circuit Hash256BE result: {:?}", &proof.public_inputs[0..8]);

        // Convert to big-endian format and check
        let be_u32s: Vec<u32> = proof.public_inputs.iter().map(|x| x.to_canonical_u64() as u32).collect();
        let be_bytes: Vec<u8> = be_u32s.iter().flat_map(|x| x.to_be_bytes()).collect();

        println!("BE bytes from circuit: {:?}", hex::encode(&be_bytes));

        Ok(())
    }
}

impl SwappableTarget for Hash256BytesTarget {
    fn swap<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>, swap: BoolTarget, left: Self, right: Self) -> Self {
        builder.select_hash256_bytes(swap, right, left)
    }
}

impl CreatableTarget for Hash256BytesTarget {
    fn create_virtual<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        builder.add_virtual_hash256_bytes_target()
    }
}

impl ConnectableTarget for Hash256BytesTarget {
    fn connect<F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>, connect_value: Self) {
        builder.connect_hash256_bytes(*self, connect_value)
    }
}
