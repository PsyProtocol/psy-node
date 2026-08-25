use async_trait::async_trait;
use parth_core::{node::realm_identifier::QRealmIdentifier, QJobIdBase};
use psy_node_core::psy_temp_db::{
    QTempDBJobClaimInfoReader, QTempDBJobClaimInfoWriter, QTempDBWorkerReputationMutation,
    QTempDBWorkerReputationReader, QTempDBWorkerReputationWriter, WorkerJobClaim,
};
use tokio::sync::Mutex;

use crate::constants::worker_reputation::{
    DEFAULT_JOB_DEADLINE_MS, DEFAULT_REPUTATION_REWARD, DEFAULT_REPUTATION_SLASH, MAX_REPUTATION,
};

#[async_trait]
pub trait WorkerReputationOps:
    QTempDBWorkerReputationReader + QTempDBWorkerReputationWriter + QTempDBWorkerReputationMutation
{
    async fn apply_reputation_on_submit(
        &self,
        rid: &QRealmIdentifier,
        public_key: &[u8; 33],
        claim_time_ms: u64,
    ) -> anyhow::Result<()> {
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let current_reputation = self.get_worker_reputation(rid, public_key).await?;
        let on_time = now.saturating_sub(claim_time_ms) <= DEFAULT_JOB_DEADLINE_MS;
        let new_reputation = if on_time {
            (current_reputation + DEFAULT_REPUTATION_REWARD).min(MAX_REPUTATION)
        } else {
            current_reputation.saturating_sub(DEFAULT_REPUTATION_SLASH)
        };
        self.set_worker_reputation(rid, public_key, new_reputation).await
    }

    async fn record_job_claim<JobId: QJobIdBase + 'static>(
        &self,
        update_lock: &Mutex<()>,
        rid: &QRealmIdentifier,
        unique_pending_id: u64,
        job_id: JobId,
        mut claim: WorkerJobClaim,
    ) -> anyhow::Result<()>
    where
        Self: QTempDBJobClaimInfoReader<JobId> + QTempDBJobClaimInfoWriter<JobId>,
        JobId: Copy + Send + Sync,
    {
        let _update_guard = update_lock.lock().await;
        if let Some(existing) = self.get_job_claim(rid, unique_pending_id, job_id).await? {
            claim.has_reputation_update = existing.has_reputation_update;
        }
        self.set_job_claim(rid, unique_pending_id, job_id, &claim).await
    }

    async fn apply_reputation_once<JobId: QJobIdBase + 'static>(
        &self,
        rid: &QRealmIdentifier,
        unique_pending_id: u64,
        job_id: JobId,
        claim: &mut WorkerJobClaim,
    ) -> anyhow::Result<()>
    where
        JobId: Copy + Send + Sync,
    {
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let on_time = now.saturating_sub(claim.claim_time_ms) <= DEFAULT_JOB_DEADLINE_MS;
        self.apply_worker_reputation_once(
            rid,
            &claim.public_key,
            unique_pending_id,
            &job_id.to_bytes_fixed(),
            on_time,
            DEFAULT_REPUTATION_REWARD,
            DEFAULT_REPUTATION_SLASH,
            MAX_REPUTATION,
        )
        .await?;
        claim.has_reputation_update = true;
        Ok(())
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

impl<T: QTempDBWorkerReputationReader + QTempDBWorkerReputationWriter + QTempDBWorkerReputationMutation>
    WorkerReputationOps for T
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use psy_core::job::job_id::{
        ProvingJobCircuitType, ProvingJobDataType, QJobTopic, QProvingJobDataID,
    };
    use psy_node_core::{
        memory_stores::simple_memory_temp_store::SimpleMemoryTempStore,
        psy_temp_db::{QTempDBJobClaimInfoReader, QTempDBJobClaimInfoWriter},
    };

    fn sample_job_id(data_index: u8) -> QProvingJobDataID {
        QProvingJobDataID {
            topic: QJobTopic::GenerateStandardProof,
            goal_id: 1,
            circuit_type: ProvingJobCircuitType::BatchDeployContractsAggregate,
            group_id: 2,
            sub_group_id: 3,
            task_index: 4,
            data_type: ProvingJobDataType::StandardProof,
            data_index,
        }
    }

    fn sample_claim(public_key: [u8; 33]) -> WorkerJobClaim {
        WorkerJobClaim {
            public_key,
            claim_time_ms: chrono::Utc::now().timestamp_millis() as u64,
            proc_checkpoint_unique_id: 5,
            reputation_at_claim: 5,
            is_finalized: false,
            has_reputation_update: false,
        }
    }

    #[tokio::test]
    async fn concurrent_retry_for_one_job_applies_one_reputation_update() {
        let store = SimpleMemoryTempStore::new();
        let update_lock = Mutex::new(());
        let realm = QRealmIdentifier::new(1, 2);
        let job_id = sample_job_id(6);
        let mut first_claim = sample_claim([3u8; 33]);
        let mut retry_claim = first_claim;
        store
            .set_job_claim(&realm, 7, job_id, &first_claim)
            .await
            .unwrap();

        let (first, retry) = tokio::join!(
            store.apply_reputation_once(&realm, 7, job_id, &mut first_claim),
            store.apply_reputation_once(&realm, 7, job_id, &mut retry_claim),
        );
        first.unwrap();
        retry.unwrap();

        assert_eq!(store.get_worker_reputation(&realm, &[3u8; 33]).await.unwrap(), 6);
        assert!(store
            .get_job_claim(&realm, 7, job_id)
            .await
            .unwrap()
            .unwrap()
            .has_reputation_update);
    }
    #[tokio::test]
    async fn redelivery_preserves_reputation_update_marker() {
        let store = SimpleMemoryTempStore::new();
        let update_lock = Mutex::new(());
        let realm = QRealmIdentifier::new(1, 2);
        let job_id = sample_job_id(6);
        let mut completed_claim = sample_claim([3u8; 33]);
        completed_claim.has_reputation_update = true;
        store
            .set_job_claim(&realm, 7, job_id, &completed_claim)
            .await
            .unwrap();

        let redelivered_claim = sample_claim([4u8; 33]);
        store
            .record_job_claim(&update_lock, &realm, 7, job_id, redelivered_claim)
            .await
            .unwrap();

        let stored_claim = store
            .get_job_claim(&realm, 7, job_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored_claim.public_key, [4u8; 33]);
        assert!(stored_claim.has_reputation_update);
    }


    #[tokio::test]
    async fn concurrent_distinct_jobs_accumulate_reputation() {
        let store = SimpleMemoryTempStore::new();
        let update_lock = Mutex::new(());
        let realm = QRealmIdentifier::new(1, 2);
        let first_job_id = sample_job_id(6);
        let second_job_id = sample_job_id(7);
        let mut first_claim = sample_claim([3u8; 33]);
        let mut second_claim = first_claim;
        store
            .set_job_claim(&realm, 8, first_job_id, &first_claim)
            .await
            .unwrap();
        store
            .set_job_claim(&realm, 8, second_job_id, &second_claim)
            .await
            .unwrap();

        let (first, second) = tokio::join!(
            store.apply_reputation_once(&realm, 8, first_job_id, &mut first_claim),
            store.apply_reputation_once(&realm, 8, second_job_id, &mut second_claim),
        );
        first.unwrap();
        second.unwrap();

        assert_eq!(store.get_worker_reputation(&realm, &[3u8; 33]).await.unwrap(), 7);
    }
}
