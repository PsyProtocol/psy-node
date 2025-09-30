use crate::{crypto::hash::traits::QHasher, protocol::core_types::QHashBase};

pub struct MerklePlanner<Hash: QHashBase, Hasher: QHasher<Hash>> {
    _marker: std::marker::PhantomData<(Hash, Hasher)>,
}

impl<Hash: QHashBase, Hasher: QHasher<Hash>> MerklePlanner<Hash, Hasher> {
    pub fn new() -> Self {
        Self {
            _marker: std::marker::PhantomData,
        }
    }
    pub fn plan_merkle_proof_indices(
        index: u64,
        level: u8,
        proof_height: u8,
    ) -> anyhow::Result<Vec<u64>> {
        if proof_height > level {
            anyhow::bail!("proof height cannot be greater than tree height");
        }
        let mut indices = Vec::with_capacity(proof_height as usize);
        let mut current_index = index;
        for _ in 0..proof_height {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };
            indices.push(sibling_index);
            current_index /= 2;
        }
        Ok(indices)
    }
}