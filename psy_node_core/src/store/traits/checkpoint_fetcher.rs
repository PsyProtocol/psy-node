use async_trait::async_trait;
use auto_impl::auto_impl;
use parth_common::memory_stores::{dash_tree_append_only::PsyDashMemoryAppendOnlyMerkleStore, mem_tree_recorder::SimpleMemoryMerkleRecorderStore};
use parth_core::crypto::hash::{merkle_proof::MerkleProofCore, traits::MerkleZeroHasher};

#[async_trait]
#[auto_impl(&, Box, Arc)]
pub trait PsyAppendOnlyTreeFetcherBase<Hash> {
    async fn get_merkle_proof_for_leaf(
        &self,
        leaf_index: u64,
    ) -> anyhow::Result<MerkleProofCore<Hash>>;
    async fn get_historical_merkle_proof_for_leaf(
        &self,
        leaf_index: u64,
    ) -> anyhow::Result<MerkleProofCore<Hash>>;
}

#[async_trait]
#[auto_impl(&, Box, Arc)]
pub trait PsyAppendOnlyTreeFetcher<Hash>: PsyAppendOnlyTreeFetcherBase<Hash> {
    async fn get_append_leaf_index_for_root(
        &self,
        checkpoint_tree_root: Hash,
    ) -> anyhow::Result<u64>;
}

#[async_trait]
impl<Hasher: MerkleZeroHasher<Hash> + Send + Sync, Hash: Copy + PartialEq + Default + Send + Sync>  PsyAppendOnlyTreeFetcherBase<Hash> for SimpleMemoryMerkleRecorderStore<Hasher, Hash> {
    async fn get_merkle_proof_for_leaf(
        &self,
        leaf_index: u64,
    ) -> anyhow::Result<MerkleProofCore<Hash>>{
        Ok(self.get_leaf(leaf_index))
    }

    async fn get_historical_merkle_proof_for_leaf(
        &self,
        leaf_index: u64,
    ) -> anyhow::Result<MerkleProofCore<Hash>> {
        Ok(self.get_historical_merkle_proof(leaf_index))
    }
}


