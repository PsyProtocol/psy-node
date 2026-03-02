use async_trait::async_trait;
use parth_core::node::realm_identifier::QRealmIdentifier;
use psy_node_core::psy_temp_db::{
    QTempDBWorkerReputationReader, QTempDBWorkerReputationWriter,
};

use crate::constants::worker_reputation::{
    DEFAULT_JOB_DEADLINE_MS, DEFAULT_REPUTATION_REWARD, DEFAULT_REPUTATION_SLASH, MAX_REPUTATION,
};

#[async_trait]
pub trait WorkerReputationOps: QTempDBWorkerReputationReader + QTempDBWorkerReputationWriter {
    async fn apply_reputation_on_submit(
        &self,
        rid: &QRealmIdentifier,
        public_key: &[u8; 33],
        claim_time_ms: u64,
    ) -> anyhow::Result<()> {
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let on_time = now.saturating_sub(claim_time_ms) <= DEFAULT_JOB_DEADLINE_MS;
        let rep = self.get_worker_reputation(rid, public_key).await?;
        let new_rep = if on_time {
            (rep + DEFAULT_REPUTATION_REWARD).min(MAX_REPUTATION)
        } else {
            rep.saturating_sub(DEFAULT_REPUTATION_SLASH)
        };
        self.set_worker_reputation(rid, public_key, new_rep).await
    }

    async fn apply_reputation_slash_on_tag_mismatch(
        &self,
        rid: &QRealmIdentifier,
        public_key: &[u8; 33],
    ) -> anyhow::Result<()> {
        let rep = self.get_worker_reputation(rid, public_key).await?;
        let new_rep = rep.saturating_sub(DEFAULT_REPUTATION_SLASH);
        self.set_worker_reputation(rid, public_key, new_rep).await
    }
}

impl<T: QTempDBWorkerReputationReader + QTempDBWorkerReputationWriter> WorkerReputationOps for T {}
