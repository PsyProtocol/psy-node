use plonky2::hash::hash_types::RichField;
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::hash::merkle::{
    core::{DeltaMerkleProofCore, MerkleProofCore},
    spiderman::SpidermanUpdateProof,
};

use super::qmetadata::{QMetaDataStoreReaderSync, QMetaDataStoreWriterSync};
use crate::qdata::checkpoint::PsyCheckpointGlobalStateRoots;

pub trait ActiveCheckpointReaderSync<F: RichField> {
    fn get_active_checkpoint(&self) -> anyhow::Result<u64>;
    fn get_active_checkpoint_f(&self) -> anyhow::Result<F>;
    fn get_active_writing_checkpoint(&self) -> anyhow::Result<u64>;
    fn get_active_writing_checkpoint_f(&self) -> anyhow::Result<F>;
}
pub trait ActiveCheckpointWriterSync<F: RichField> {
    fn set_active_checkpoint(&self, checkpoint_id: u64) -> anyhow::Result<u64>;
    fn set_active_checkpoint_f(&self, checkpoint_id: F) -> anyhow::Result<F>;
    fn set_active_writing_checkpoint(&self, checkpoint_id: u64) -> anyhow::Result<u64>;
    fn set_active_writing_checkpoint_f(&self, checkpoint_id: F) -> anyhow::Result<F>;

    fn set_active_checkpoint_mut(&mut self, checkpoint_id: u64) -> anyhow::Result<u64>;
    fn set_active_checkpoint_f_mut(&mut self, checkpoint_id: F) -> anyhow::Result<F>;
    fn set_active_writing_checkpoint_mut(&mut self, checkpoint_id: u64) -> anyhow::Result<u64>;
    fn set_active_writing_checkpoint_f_mut(&mut self, checkpoint_id: F) -> anyhow::Result<F>;
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
pub trait QTreeDataStoreReaderSync<F: RichField>: Send + Sync {
    async fn get_user_contract_state_tree_root(&self, checkpoint_id: u64, user_id: u64, contract_id: u32) -> anyhow::Result<QHashOut<F>>;
    async fn get_user_contract_state_tree_root_f(&self, checkpoint_id: F, user_id: F, contract_id: F) -> anyhow::Result<QHashOut<F>> {
        <Self as QTreeDataStoreReaderSync<F>>::get_user_contract_state_tree_root(
            self,
            checkpoint_id.to_canonical_u64(),
            user_id.to_canonical_u64(),
            contract_id.to_canonical_u64() as u32,
        )
        .await
    }
    async fn get_user_contract_state_tree_leaf_hash(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
        height: u8,
        leaf_id: u64,
    ) -> anyhow::Result<QHashOut<F>>;
    async fn get_user_contract_state_tree_leaf_hash_f(
        &self,
        checkpoint_id: F,
        user_id: F,
        contract_id: F,
        height: u8,
        leaf_id: F,
    ) -> anyhow::Result<QHashOut<F>> {
        <Self as QTreeDataStoreReaderSync<F>>::get_user_contract_state_tree_leaf_hash(
            self,
            checkpoint_id.to_canonical_u64(),
            user_id.to_canonical_u64(),
            contract_id.to_canonical_u64() as u32,
            height,
            leaf_id.to_canonical_u64(),
        )
        .await
    }
    async fn get_user_contract_state_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
        height: u8,
        leaf_id: u64,
    ) -> anyhow::Result<MerkleProofCore<QHashOut<F>>>;
    async fn get_user_contract_state_tree_merkle_proof_f(
        &self,
        checkpoint_id: F,
        user_id: F,
        contract_id: F,
        height: u8,
        leaf_id: F,
    ) -> anyhow::Result<MerkleProofCore<QHashOut<F>>> {
        <Self as QTreeDataStoreReaderSync<F>>::get_user_contract_state_tree_merkle_proof(
            self,
            checkpoint_id.to_canonical_u64(),
            user_id.to_canonical_u64(),
            contract_id.to_canonical_u64() as u32,
            height,
            leaf_id.to_canonical_u64(),
        )
        .await
    }

    async fn get_user_contract_tree_root(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<QHashOut<F>>;
    async fn get_user_contract_tree_root_f(&self, checkpoint_id: F, user_id: F) -> anyhow::Result<QHashOut<F>> {
        <Self as QTreeDataStoreReaderSync<F>>::get_user_contract_tree_root(self, checkpoint_id.to_canonical_u64(), user_id.to_canonical_u64()).await
    }
    async fn get_user_contract_tree_leaf_hash(&self, checkpoint_id: u64, user_id: u64, contract_id: u32) -> anyhow::Result<QHashOut<F>>;
    async fn get_user_contract_tree_leaf_hash_f(&self, checkpoint_id: F, user_id: F, contract_id: F) -> anyhow::Result<QHashOut<F>> {
        <Self as QTreeDataStoreReaderSync<F>>::get_user_contract_tree_leaf_hash(
            self,
            checkpoint_id.to_canonical_u64(),
            user_id.to_canonical_u64(),
            contract_id.to_canonical_u64() as u32,
        )
        .await
    }
    async fn get_user_contract_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
    ) -> anyhow::Result<MerkleProofCore<QHashOut<F>>>;
    async fn get_user_contract_tree_merkle_proof_f(
        &self,
        checkpoint_id: F,
        user_id: F,
        contract_id: F,
    ) -> anyhow::Result<MerkleProofCore<QHashOut<F>>> {
        <Self as QTreeDataStoreReaderSync<F>>::get_user_contract_tree_merkle_proof(
            self,
            checkpoint_id.to_canonical_u64(),
            user_id.to_canonical_u64(),
            contract_id.to_canonical_u64() as u32,
        )
        .await
    }

    async fn get_user_registration_tree_root(&self, checkpoint_id: u64) -> anyhow::Result<QHashOut<F>>;
    async fn get_user_registration_tree_root_f(&self, checkpoint_id: F) -> anyhow::Result<QHashOut<F>> {
        <Self as QTreeDataStoreReaderSync<F>>::get_user_registration_tree_root(self, checkpoint_id.to_canonical_u64()).await
    }
    async fn get_user_registration_tree_leaf_hash(&self, checkpoint_id: u64, leaf_index: u64) -> anyhow::Result<QHashOut<F>>;
    async fn get_user_registration_tree_leaf_hash_f(&self, checkpoint_id: F, leaf_index: F) -> anyhow::Result<QHashOut<F>> {
        <Self as QTreeDataStoreReaderSync<F>>::get_user_registration_tree_leaf_hash(
            self,
            checkpoint_id.to_canonical_u64(),
            leaf_index.to_canonical_u64(),
        )
        .await
    }
    async fn get_user_registration_tree_merkle_proof(&self, checkpoint_id: u64, leaf_index: u64) -> anyhow::Result<MerkleProofCore<QHashOut<F>>>;
    async fn get_user_registration_tree_merkle_proof_f(&self, checkpoint_id: F, leaf_index: F) -> anyhow::Result<MerkleProofCore<QHashOut<F>>> {
        <Self as QTreeDataStoreReaderSync<F>>::get_user_registration_tree_merkle_proof(
            self,
            checkpoint_id.to_canonical_u64(),
            leaf_index.to_canonical_u64(),
        )
        .await
    }

    async fn get_user_tree_root(&self, checkpoint_id: u64) -> anyhow::Result<QHashOut<F>>;
    async fn get_user_tree_root_f(&self, checkpoint_id: F) -> anyhow::Result<QHashOut<F>> {
        <Self as QTreeDataStoreReaderSync<F>>::get_user_tree_root(self, checkpoint_id.to_canonical_u64()).await
    }
    async fn get_user_tree_leaf_hash(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<QHashOut<F>>;
    async fn get_user_tree_leaf_hash_f(&self, checkpoint_id: F, user_id: F) -> anyhow::Result<QHashOut<F>> {
        <Self as QTreeDataStoreReaderSync<F>>::get_user_tree_leaf_hash(self, checkpoint_id.to_canonical_u64(), user_id.to_canonical_u64()).await
    }
    async fn get_user_tree_merkle_proof(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<MerkleProofCore<QHashOut<F>>>;
    async fn get_user_tree_merkle_proof_f(&self, checkpoint_id: F, user_id: F) -> anyhow::Result<MerkleProofCore<QHashOut<F>>> {
        <Self as QTreeDataStoreReaderSync<F>>::get_user_tree_merkle_proof(self, checkpoint_id.to_canonical_u64(), user_id.to_canonical_u64()).await
    }
    async fn get_user_sub_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        root_level: u8,
        leaf_level: u8,
        leaf_index: u64,
    ) -> anyhow::Result<MerkleProofCore<QHashOut<F>>>;

    async fn get_contract_function_tree_root(&self, checkpoint_id: u64, contract_id: u32) -> anyhow::Result<QHashOut<F>>;
    async fn get_contract_function_tree_root_f(&self, checkpoint_id: F, contract_id: F) -> anyhow::Result<QHashOut<F>> {
        <Self as QTreeDataStoreReaderSync<F>>::get_contract_function_tree_root(
            self,
            checkpoint_id.to_canonical_u64(),
            contract_id.to_canonical_u64() as u32,
        )
        .await
    }
    async fn get_contract_function_tree_leaf_hash(&self, checkpoint_id: u64, contract_id: u32, function_id: u32) -> anyhow::Result<QHashOut<F>>;
    async fn get_contract_function_tree_leaf_hash_f(&self, checkpoint_id: F, contract_id: F, function_id: F) -> anyhow::Result<QHashOut<F>> {
        <Self as QTreeDataStoreReaderSync<F>>::get_contract_function_tree_leaf_hash(
            self,
            checkpoint_id.to_canonical_u64(),
            contract_id.to_canonical_u64() as u32,
            function_id.to_canonical_u64() as u32,
        )
        .await
    }
    async fn get_contract_function_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        contract_id: u32,
        function_id: u32,
    ) -> anyhow::Result<MerkleProofCore<QHashOut<F>>>;
    async fn get_contract_function_tree_merkle_proof_f(
        &self,
        checkpoint_id: F,
        contract_id: F,
        function_id: F,
    ) -> anyhow::Result<MerkleProofCore<QHashOut<F>>> {
        <Self as QTreeDataStoreReaderSync<F>>::get_contract_function_tree_merkle_proof(
            self,
            checkpoint_id.to_canonical_u64(),
            contract_id.to_canonical_u64() as u32,
            function_id.to_canonical_u64() as u32,
        )
        .await
    }

    async fn get_contract_tree_root(&self, checkpoint_id: u64) -> anyhow::Result<QHashOut<F>>;
    async fn get_contract_tree_root_f(&self, checkpoint_id: F) -> anyhow::Result<QHashOut<F>> {
        <Self as QTreeDataStoreReaderSync<F>>::get_contract_tree_root(self, checkpoint_id.to_canonical_u64()).await
    }
    async fn get_contract_tree_leaf_hash(&self, checkpoint_id: u64, contract_id: u32) -> anyhow::Result<QHashOut<F>>;
    async fn get_contract_tree_leaf_hash_f(&self, checkpoint_id: F, contract_id: F) -> anyhow::Result<QHashOut<F>> {
        <Self as QTreeDataStoreReaderSync<F>>::get_contract_tree_leaf_hash(
            self,
            checkpoint_id.to_canonical_u64(),
            contract_id.to_canonical_u64() as u32,
        )
        .await
    }
    async fn get_contract_tree_merkle_proof(&self, checkpoint_id: u64, contract_id: u32) -> anyhow::Result<MerkleProofCore<QHashOut<F>>>;
    async fn get_contract_tree_merkle_proof_f(&self, checkpoint_id: F, contract_id: F) -> anyhow::Result<MerkleProofCore<QHashOut<F>>> {
        <Self as QTreeDataStoreReaderSync<F>>::get_contract_tree_merkle_proof(
            self,
            checkpoint_id.to_canonical_u64(),
            contract_id.to_canonical_u64() as u32,
        )
        .await
    }

    async fn get_withdrawal_tree_root(&self, checkpoint_id: u64) -> anyhow::Result<QHashOut<F>>;
    async fn get_withdrawal_tree_root_f(&self, checkpoint_id: F) -> anyhow::Result<QHashOut<F>> {
        <Self as QTreeDataStoreReaderSync<F>>::get_withdrawal_tree_root(self, checkpoint_id.to_canonical_u64()).await
    }

    async fn get_latest_checkpoint_tree_root(&self) -> anyhow::Result<QHashOut<F>>;
    async fn get_checkpoint_tree_root(&self, checkpoint_id: u64) -> anyhow::Result<QHashOut<F>>;
    async fn get_checkpoint_tree_root_f(&self, checkpoint_id: F) -> anyhow::Result<QHashOut<F>> {
        <Self as QTreeDataStoreReaderSync<F>>::get_checkpoint_tree_root(self, checkpoint_id.to_canonical_u64()).await
    }
    async fn get_checkpoint_tree_leaf_hash(&self, checkpoint_id: u64, leaf_checkpoint_id: u64) -> anyhow::Result<QHashOut<F>>;
    async fn get_checkpoint_tree_leaf_hash_f(&self, checkpoint_id: F, leaf_checkpoint_id: F) -> anyhow::Result<QHashOut<F>> {
        <Self as QTreeDataStoreReaderSync<F>>::get_checkpoint_tree_leaf_hash(
            self,
            checkpoint_id.to_canonical_u64(),
            leaf_checkpoint_id.to_canonical_u64(),
        )
        .await
    }
    async fn get_checkpoint_tree_merkle_proof(&self, checkpoint_id: u64, leaf_checkpoint_id: u64) -> anyhow::Result<MerkleProofCore<QHashOut<F>>>;
    async fn get_checkpoint_tree_merkle_proof_f(&self, checkpoint_id: F, leaf_checkpoint_id: F) -> anyhow::Result<MerkleProofCore<QHashOut<F>>> {
        <Self as QTreeDataStoreReaderSync<F>>::get_checkpoint_tree_merkle_proof(
            self,
            checkpoint_id.to_canonical_u64(),
            leaf_checkpoint_id.to_canonical_u64(),
        )
        .await
    }

    async fn get_user_event_tree_root(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<QHashOut<F>>;
    async fn get_user_event_tree_root_f(&self, checkpoint_id: F, user_id: F) -> anyhow::Result<QHashOut<F>> {
        <Self as QTreeDataStoreReaderSync<F>>::get_user_event_tree_root(self, checkpoint_id.to_canonical_u64(), user_id.to_canonical_u64()).await
    }
    async fn get_user_event_tree_leaf_hash(&self, checkpoint_id: u64, user_id: u64, event_index: u64) -> anyhow::Result<QHashOut<F>>;
    async fn get_user_event_tree_leaf_hash_f(&self, checkpoint_id: F, user_id: F, event_index: F) -> anyhow::Result<QHashOut<F>> {
        <Self as QTreeDataStoreReaderSync<F>>::get_user_event_tree_leaf_hash(
            self,
            checkpoint_id.to_canonical_u64(),
            user_id.to_canonical_u64(),
            event_index.to_canonical_u64(),
        )
        .await
    }
    async fn get_user_event_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        event_index: u64,
    ) -> anyhow::Result<MerkleProofCore<QHashOut<F>>>;
    async fn get_user_event_tree_merkle_proof_f(&self, checkpoint_id: F, user_id: F, event_index: F) -> anyhow::Result<MerkleProofCore<QHashOut<F>>> {
        <Self as QTreeDataStoreReaderSync<F>>::get_user_event_tree_merkle_proof(
            self,
            checkpoint_id.to_canonical_u64(),
            user_id.to_canonical_u64(),
            event_index.to_canonical_u64(),
        )
        .await
    }
}

pub trait QTreeDataStoreWriterSync<F: RichField> {
    fn batch_append_user_registration_tree(
        &self,
        checkpoint_id: u64,
        start_leaf_index: u64,
        sub_tree_height: u8,
        leaf_hashes: &[QHashOut<F>],
    ) -> anyhow::Result<(Vec<usize>, Vec<SpidermanUpdateProof<QHashOut<F>>>)>;
    fn batch_append_user_registration_tree_f(
        &self,
        checkpoint_id: F,
        start_leaf_index: F,
        sub_tree_height: u8,
        leaf_hashes: &[QHashOut<F>],
    ) -> anyhow::Result<(Vec<usize>, Vec<SpidermanUpdateProof<QHashOut<F>>>)> {
        <Self as QTreeDataStoreWriterSync<F>>::batch_append_user_registration_tree(
            self,
            checkpoint_id.to_canonical_u64(),
            start_leaf_index.to_canonical_u64(),
            sub_tree_height,
            leaf_hashes,
        )
    }

    fn set_user_state_tree_leaf_hash(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
        height: u8,
        leaf_id: u64,
        leaf_hash: QHashOut<F>,
    ) -> anyhow::Result<DeltaMerkleProofCore<QHashOut<F>>>;
    fn set_user_state_tree_leaf_hash_f(
        &self,
        checkpoint_id: F,
        user_id: F,
        contract_id: F,
        height: u8,
        leaf_id: F,
        leaf_hash: QHashOut<F>,
    ) -> anyhow::Result<DeltaMerkleProofCore<QHashOut<F>>> {
        <Self as QTreeDataStoreWriterSync<F>>::set_user_state_tree_leaf_hash(
            self,
            checkpoint_id.to_canonical_u64(),
            user_id.to_canonical_u64(),
            contract_id.to_canonical_u64() as u32,
            height,
            leaf_id.to_canonical_u64(),
            leaf_hash,
        )
    }

    fn set_user_contract_tree_leaf_hash(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
        leaf_hash: QHashOut<F>,
    ) -> anyhow::Result<DeltaMerkleProofCore<QHashOut<F>>>;
    fn set_user_contract_tree_leaf_hash_f(
        &self,
        checkpoint_id: F,
        user_id: F,
        contract_id: F,
        leaf_hash: QHashOut<F>,
    ) -> anyhow::Result<DeltaMerkleProofCore<QHashOut<F>>> {
        <Self as QTreeDataStoreWriterSync<F>>::set_user_contract_tree_leaf_hash(
            self,
            checkpoint_id.to_canonical_u64(),
            user_id.to_canonical_u64(),
            contract_id.to_canonical_u64() as u32,
            leaf_hash,
        )
    }

    fn set_user_tree_leaf_hash(&self, checkpoint_id: u64, user_id: u64, leaf_hash: QHashOut<F>) -> anyhow::Result<DeltaMerkleProofCore<QHashOut<F>>>;
    fn set_user_tree_leaf_hash_f(&self, checkpoint_id: F, user_id: F, leaf_hash: QHashOut<F>) -> anyhow::Result<DeltaMerkleProofCore<QHashOut<F>>> {
        <Self as QTreeDataStoreWriterSync<F>>::set_user_tree_leaf_hash(self, checkpoint_id.to_canonical_u64(), user_id.to_canonical_u64(), leaf_hash)
    }

    fn set_deposit_tree_leaf_hash(
        &self,
        checkpoint_id: u64,
        deposit_id: u64,
        leaf_hash: QHashOut<F>,
    ) -> anyhow::Result<DeltaMerkleProofCore<QHashOut<F>>>;
    fn set_deposit_tree_leaf_hash_f(
        &self,
        checkpoint_id: F,
        deposit_id: F,
        leaf_hash: QHashOut<F>,
    ) -> anyhow::Result<DeltaMerkleProofCore<QHashOut<F>>> {
        <Self as QTreeDataStoreWriterSync<F>>::set_deposit_tree_leaf_hash(
            self,
            checkpoint_id.to_canonical_u64(),
            deposit_id.to_canonical_u64(),
            leaf_hash,
        )
    }

    fn set_withdrawal_tree_leaf_hash(
        &self,
        checkpoint_id: u64,
        withdrawal_id: u64,
        leaf_hash: QHashOut<F>,
    ) -> anyhow::Result<DeltaMerkleProofCore<QHashOut<F>>>;
    fn set_withdrawal_tree_leaf_hash_f(
        &self,
        checkpoint_id: F,
        withdrawal_id: F,
        leaf_hash: QHashOut<F>,
    ) -> anyhow::Result<DeltaMerkleProofCore<QHashOut<F>>> {
        <Self as QTreeDataStoreWriterSync<F>>::set_withdrawal_tree_leaf_hash(
            self,
            checkpoint_id.to_canonical_u64(),
            withdrawal_id.to_canonical_u64(),
            leaf_hash,
        )
    }

    fn set_contract_function_whitelist(&self, checkpoint_id: u64, contract_id: u64, leaves: &[QHashOut<F>]) -> anyhow::Result<QHashOut<F>>;
    fn set_contract_function_whitelist_f(&self, checkpoint_id: F, contract_id: F, leaves: &[QHashOut<F>]) -> anyhow::Result<QHashOut<F>> {
        <Self as QTreeDataStoreWriterSync<F>>::set_contract_function_whitelist(
            self,
            checkpoint_id.to_canonical_u64(),
            contract_id.to_canonical_u64(),
            leaves,
        )
    }

    fn batch_append_contract_tree(
        &self,
        checkpoint_id: u64,
        start_leaf_index: u64,
        sub_tree_height: u8,
        leaf_hashes: &[QHashOut<F>],
    ) -> anyhow::Result<(Vec<usize>, Vec<SpidermanUpdateProof<QHashOut<F>>>)>;

    fn set_contract_tree_leaf_hash(
        &self,
        checkpoint_id: u64,
        contract_id: u64,
        leaf_hash: QHashOut<F>,
    ) -> anyhow::Result<DeltaMerkleProofCore<QHashOut<F>>>;
    fn set_contract_tree_leaf_hash_f(
        &self,
        checkpoint_id: F,
        contract_id: F,
        leaf_hash: QHashOut<F>,
    ) -> anyhow::Result<DeltaMerkleProofCore<QHashOut<F>>> {
        <Self as QTreeDataStoreWriterSync<F>>::set_contract_tree_leaf_hash(
            self,
            checkpoint_id.to_canonical_u64(),
            contract_id.to_canonical_u64(),
            leaf_hash,
        )
    }

    fn set_checkpoint_tree_leaf_hash(&self, checkpoint_id: u64, leaf_hash: QHashOut<F>) -> anyhow::Result<DeltaMerkleProofCore<QHashOut<F>>>;
    fn set_checkpoint_tree_leaf_hash_f(&self, checkpoint_id: F, leaf_hash: QHashOut<F>) -> anyhow::Result<DeltaMerkleProofCore<QHashOut<F>>> {
        <Self as QTreeDataStoreWriterSync<F>>::set_checkpoint_tree_leaf_hash(self, checkpoint_id.to_canonical_u64(), leaf_hash)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
pub trait PsyComboDataStoreReaderSync<F: RichField>: QMetaDataStoreReaderSync<F> + QTreeDataStoreReaderSync<F> {}
pub trait PsyComboDataStoreWriterSync<F: RichField>: QMetaDataStoreWriterSync<F> + QTreeDataStoreWriterSync<F> {}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
pub trait PsyComboDataStoreReaderWriterSync<F: RichField>: PsyComboDataStoreReaderSync<F> + PsyComboDataStoreWriterSync<F> {}
