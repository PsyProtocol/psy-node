use async_trait::async_trait;
use parth_core::node::realm_identifier::QRealmIdentifier;



#[async_trait]
pub trait QTempDBRewardsTreeReader<Hash, JobId> {
    async fn get_proof_miner_rewards_tree_value(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_id: JobId) -> anyhow::Result<Hash>;
    async fn get_proof_miner_rewards_tree_value_or_none(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_id: JobId) -> anyhow::Result<Option<Hash>>;
}

#[async_trait]
pub trait QTempDBRewardsTreeWriter<Hash, JobId> {
    async fn set_proof_miner_rewards_tree_value(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_id: JobId, value: Hash) -> anyhow::Result<Hash>;
}

pub trait QTempDBRewardsTreeStore<Hash, JobId>: QTempDBRewardsTreeReader<Hash, JobId> + QTempDBRewardsTreeWriter<Hash, JobId> {}
impl<T: QTempDBRewardsTreeReader<Hash, JobId> + QTempDBRewardsTreeWriter<Hash, JobId>, JobId, Hash> QTempDBRewardsTreeStore<Hash, JobId> for T {}








