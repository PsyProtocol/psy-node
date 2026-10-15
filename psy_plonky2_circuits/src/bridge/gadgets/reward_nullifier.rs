//! Claim-local reward nullifier. The caller authenticates the job and derives its index.

use anyhow::Context;
use std::{collections::HashMap, sync::LazyLock};

use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{hash_types::{HashOut, HashOutTarget}, poseidon::PoseidonHash},
    iop::{target::Target, witness::WitnessWrite},
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};
use psy_crypto::hash::traits::hasher::{MerkleHasher, MerkleZeroHasher};
use psy_plonky2_common_circuits::hash::merkle::gadgets::delta_merkle_proof::DeltaMerkleProofGadget;

type F = GoldilocksField;

pub const REWARD_NULLIFIER_HEIGHT: usize = 20;
pub const REWARD_NULLIFIER_EMPTY_LEAF: HashOut<F> = HashOut { elements: [F::ZERO; 4] };
pub const REWARD_NULLIFIER_OCCUPIED_LEAF: HashOut<F> = HashOut {
    elements: [F::ONE, F::ZERO, F::ZERO, F::ZERO],
};

pub static REWARD_NULLIFIER_EMPTY_ROOT: LazyLock<HashOut<F>> = LazyLock::new(|| {
    <PoseidonHash as MerkleZeroHasher<HashOut<F>>>::get_zero_hash(REWARD_NULLIFIER_HEIGHT)
});

/// Index of an authenticated GUTA coordinate in the height-20 claim tree.
pub fn nullifier_job_index(height: u8, path_index: u32) -> anyhow::Result<u32> {
    anyhow::ensure!((2..=21).contains(&height), "reward nullifier height is outside 2..=21");
    let path_bits = usize::from(height - 2);
    anyhow::ensure!(u64::from(path_index) < 1u64 << path_bits, "reward nullifier path exceeds its height");
    let index = ((1u32 << path_bits) - 1).checked_add(path_index).context("reward nullifier overflow")?;
    anyhow::ensure!(u64::from(index) <= (1u64 << REWARD_NULLIFIER_HEIGHT) - 2, "reward nullifier index exceeds its tree");
    Ok(index)
}

#[derive(Debug, Clone, Copy)]
pub struct RewardNullifierUpdate {
    pub old_nullifier_root: HashOut<F>,
    pub new_nullifier_root: HashOut<F>,
    pub nullifier_siblings: [HashOut<F>; REWARD_NULLIFIER_HEIGHT],
}

/// Touched nodes of one claim. Missing nodes are the empty subtree at that level.
#[derive(Debug, Clone)]
pub struct RewardNullifierTree {
    nodes: HashMap<(usize, u64), HashOut<F>>,
}

impl RewardNullifierTree {
    pub fn empty() -> Self {
        Self { nodes: HashMap::new() }
    }

    pub fn root(&self) -> HashOut<F> {
        self.node(REWARD_NULLIFIER_HEIGHT, 0)
    }

    /// Occupy the leaf for one authenticated job. A repeated coordinate fails.
    pub fn insert(&mut self, height: u8, path_index: u32) -> anyhow::Result<RewardNullifierUpdate> {
        let index = u64::from(nullifier_job_index(height, path_index)?);
        anyhow::ensure!(self.nodes.get(&(0, index)).is_none(), "reward nullifier already occupied");
        let old_nullifier_root = self.root();
        let nullifier_siblings = std::array::from_fn(|level| self.node(level, (index >> level) ^ 1));
        self.nodes.insert((0, index), REWARD_NULLIFIER_OCCUPIED_LEAF);
        let mut current = REWARD_NULLIFIER_OCCUPIED_LEAF;
        for level in 0..REWARD_NULLIFIER_HEIGHT {
            let position = index >> level;
            let left = self.node(level, position & !1);
            let right = self.node(level, position | 1);
            current = <PoseidonHash as MerkleHasher<HashOut<F>>>::two_to_one(&left, &right);
            self.nodes.insert((level + 1, position >> 1), current);
        }
        Ok(RewardNullifierUpdate { old_nullifier_root, new_nullifier_root: current, nullifier_siblings })
    }

    fn node(&self, level: usize, position: u64) -> HashOut<F> {
        self.nodes.get(&(level, position)).copied().unwrap_or_else(|| {
            <PoseidonHash as MerkleZeroHasher<HashOut<F>>>::get_zero_hash(level)
        })
    }
}

#[derive(Debug, Clone)]
pub struct RewardNullifierTargets {
    pub old_nullifier_root: HashOutTarget,
    pub new_nullifier_root: HashOutTarget,
    pub index: Target,
    pub nullifier_siblings: [HashOutTarget; REWARD_NULLIFIER_HEIGHT],
    old_leaf: HashOutTarget,
    new_leaf: HashOutTarget,
}

impl RewardNullifierTargets {
    /// One empty-to-occupied transition. The caller connects `index` to its derived coordinate.
    pub fn add(builder: &mut CircuitBuilder<F, 2>) -> Self {
        let empty = builder.constant_hash(REWARD_NULLIFIER_EMPTY_LEAF);
        let occupied = builder.constant_hash(REWARD_NULLIFIER_OCCUPIED_LEAF);
        let delta = DeltaMerkleProofGadget::add_virtual_to::<PoseidonHash, F, 2>(builder, REWARD_NULLIFIER_HEIGHT);
        builder.connect_hashes(delta.old_value, empty);
        builder.connect_hashes(delta.new_value, occupied);
        Self {
            old_nullifier_root: delta.old_root,
            new_nullifier_root: delta.new_root,
            index: delta.index,
            nullifier_siblings: std::array::from_fn(|level| delta.siblings[level]),
            old_leaf: delta.old_value,
            new_leaf: delta.new_value,
        }
    }

    pub fn set_witness(
        &self,
        witness: &mut impl WitnessWrite<F>,
        index: u32,
        nullifier_siblings: &[HashOut<F>; REWARD_NULLIFIER_HEIGHT],
    ) -> anyhow::Result<()> {
        witness.set_target(self.index, F::from_canonical_u32(index))?;
        witness.set_hash_target(self.old_leaf, REWARD_NULLIFIER_EMPTY_LEAF)?;
        witness.set_hash_target(self.new_leaf, REWARD_NULLIFIER_OCCUPIED_LEAF)?;
        for (&target, &value) in self.nullifier_siblings.iter().zip(nullifier_siblings) {
            witness.set_hash_target(target, value)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_index_bounds_and_duplicate_transition() {
        assert_eq!(nullifier_job_index(2, 0).unwrap(), 0);
        assert_eq!(nullifier_job_index(21, (1 << 19) - 1).unwrap(), (1 << 20) - 2);
        assert!(nullifier_job_index(1, 0).is_err());
        assert!(nullifier_job_index(22, 0).is_err());
        assert!(nullifier_job_index(6, 1 << 4).is_err());

        let mut tree = RewardNullifierTree::empty();
        assert_eq!(tree.root(), *REWARD_NULLIFIER_EMPTY_ROOT);
        let first = tree.insert(6, 0).unwrap();
        assert_eq!(first.old_nullifier_root, *REWARD_NULLIFIER_EMPTY_ROOT);
        assert_eq!(tree.root(), first.new_nullifier_root);
        assert_ne!(first.old_nullifier_root, first.new_nullifier_root);
        let second = tree.insert(6, 1).unwrap();
        assert_eq!(second.old_nullifier_root, first.new_nullifier_root);
        assert_eq!(tree.root(), second.new_nullifier_root);
        assert!(tree.insert(6, 0).is_err());
        assert_eq!(tree.root(), second.new_nullifier_root);
    }
}
