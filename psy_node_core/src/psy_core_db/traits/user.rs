use async_trait::async_trait;
use parth_core::{data::db::row::QDatabaseKeyIdValueTableRow, felt::QFelt, protocol::core_types::QHashBase};
use psy_data::v1::qdata::{public_key::PZKPublicKeyInfo, user::PQEDUserLeaf};



#[async_trait]
pub trait QPsyDatabaseUserLeafReader<F: QFelt, Hash: QHashBase> {
    async fn get_latest_user_leaf(&self, user_id: u64) -> anyhow::Result<Option<PQEDUserLeaf<F, Hash>>>;
    async fn get_user_leaf_at_checkpoint(&self, user_id: u64, max_checkpoint_id: u64) -> anyhow::Result<Option<PQEDUserLeaf<F, Hash>>>;
    async fn get_latest_user_public_key(&self, user_id: u64) -> anyhow::Result<Option<PZKPublicKeyInfo<Hash>>>;
    async fn get_user_public_key_at_checkpoint(&self, user_id: u64, max_checkpoint_id: u64) -> anyhow::Result<Option<PZKPublicKeyInfo<Hash>>>;
}

#[async_trait]
pub trait QPsyDatabaseUserLeafWriter<F: QFelt, Hash: QHashBase> {
    async fn set_user_leaf_at_checkpoint(&self, checkpoint_id: u64, user_leaf: &PQEDUserLeaf<F, Hash>) -> anyhow::Result<()>;
    async fn set_user_leaves_at_checkpoint(&self, checkpoint_id: u64, user_leaves: &[PQEDUserLeaf<F, Hash>]) -> anyhow::Result<()>;
    async fn set_user_public_key_at_checkpoint(&self, checkpoint_id: u64, user_id: u64, public_key: &PZKPublicKeyInfo<Hash>) -> anyhow::Result<()>;
    async fn set_user_public_keys_at_checkpoint(&self, checkpoint_id: u64, user_public_keys: &[QDatabaseKeyIdValueTableRow<PZKPublicKeyInfo<Hash>>]) -> anyhow::Result<()>;
}
