//! Reward consumption only; the caller authenticates jobs/users and binds both root endpoints.

use std::sync::LazyLock;

use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::{Field, Field64, PrimeField64}},
    hash::{hash_types::{HashOut, HashOutTarget}, poseidon::PoseidonHash},
    iop::{target::Target, witness::WitnessWrite},
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};
use psy_plonky2_common_circuits::hash::merkle::gadgets::delta_merkle_proof::DeltaMerkleProofGadget;

type F = GoldilocksField;

pub const REWARD_NULLIFIER_INNER_HEIGHT: usize = 22;
pub const REWARD_NULLIFIER_OUTER_HEIGHT: usize = 32;
pub const REWARD_NULLIFIER_EMPTY_LEAF: HashOut<F> = HashOut { elements: [F::ZERO; 4] };
pub const REWARD_NULLIFIER_OCCUPIED_LEAF: HashOut<F> = HashOut {
    elements: [F::ONE, F::ZERO, F::ZERO, F::ZERO],
};

fn derive_empty_root(mut root: HashOut<F>, height: usize) -> HashOut<F> {
    for _ in 0..height {
        root = PoseidonHash::two_to_one(root, root);
    }
    root
}

pub static INNER_EMPTY_ROOT: LazyLock<HashOut<F>> = LazyLock::new(|| {
    derive_empty_root(REWARD_NULLIFIER_EMPTY_LEAF, REWARD_NULLIFIER_INNER_HEIGHT)
});
pub static REWARD_NULLIFIER_EMPTY_ROOT: LazyLock<HashOut<F>> = LazyLock::new(|| {
    derive_empty_root(*INNER_EMPTY_ROOT, REWARD_NULLIFIER_OUTER_HEIGHT)
});
pub static EMPTY_REWARD_NULLIFIER_ROOT: LazyLock<[u8; 32]> = LazyLock::new(|| {
    reward_nullifier_root_bytes(*REWARD_NULLIFIER_EMPTY_ROOT)
});

pub fn reward_nullifier_root_bytes(root: HashOut<F>) -> [u8; 32] {
    let mut bytes = [0; 32];
    for (output, limb) in bytes.chunks_exact_mut(8).zip(root.elements) {
        output.copy_from_slice(&limb.to_canonical_u64().to_be_bytes());
    }
    bytes
}

pub fn read_reward_nullifier_root(bytes: [u8; 32]) -> anyhow::Result<HashOut<F>> {
    let mut elements = [F::ZERO; 4];
    for (element, input) in elements.iter_mut().zip(bytes.chunks_exact(8)) {
        let mut limb_bytes = [0; 8];
        limb_bytes.copy_from_slice(input);
        let limb = u64::from_be_bytes(limb_bytes);
        anyhow::ensure!(limb < F::ORDER, "noncanonical reward nullifier root");
        *element = F::from_canonical_u64(limb);
    }
    Ok(HashOut { elements })
}

#[derive(Debug, Clone)]
pub struct RewardNullifierSourceTargets {
    pub outer: DeltaMerkleProofGadget,
    pub inner: Vec<DeltaMerkleProofGadget>,
}

#[derive(Debug, Clone)]
pub struct RewardNullifierSourceWitness {
    pub old_inner_root: HashOut<F>,
    pub outer_siblings: [HashOut<F>; REWARD_NULLIFIER_OUTER_HEIGHT],
    pub inner_siblings: Vec<[HashOut<F>; REWARD_NULLIFIER_INNER_HEIGHT]>,
}

impl RewardNullifierSourceTargets {
    pub fn set_witness(
        &self,
        witness: &mut impl WitnessWrite<F>,
        input: &RewardNullifierSourceWitness,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(self.inner.len() == input.inner_siblings.len(), "reward job path count mismatch");
        witness.set_hash_target(self.outer.old_value, input.old_inner_root)?;
        for (&target, &value) in self.outer.siblings.iter().zip(&input.outer_siblings) {
            witness.set_hash_target(target, value)?;
        }
        for (delta, siblings) in self.inner.iter().zip(&input.inner_siblings) {
            for (&target, &value) in delta.siblings.iter().zip(siblings) {
                witness.set_hash_target(target, value)?;
            }
        }
        Ok(())
    }
}

