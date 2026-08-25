use async_trait::async_trait;
use parth_core::{node::realm_identifier::QRealmIdentifier, QCoreProcCheckpointUniqueId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerJobClaim {
    pub public_key: [u8; 33],
    pub claim_time_ms: u64,
    pub proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId,
    pub reputation_at_claim: u64,
    pub is_finalized: bool,
    pub has_reputation_update: bool,
}
#[async_trait]
pub trait QTempDBJobClaimInfoReader<JobId> {
    async fn get_job_claim(
        &self,
        rid: &QRealmIdentifier,
        unique_pending_id: u64,
        job_id: JobId,
    ) -> anyhow::Result<Option<WorkerJobClaim>>;
}

#[async_trait]
pub trait QTempDBJobClaimInfoWriter<JobId> {
    async fn set_job_claim(
        &self,
        rid: &QRealmIdentifier,
        unique_pending_id: u64,
        job_id: JobId,
        claim: &WorkerJobClaim,
    ) -> anyhow::Result<()>;
}

pub trait QTempDBJobClaimInfoStore<JobId>: QTempDBJobClaimInfoReader<JobId> + QTempDBJobClaimInfoWriter<JobId> {}
impl<T: QTempDBJobClaimInfoReader<JobId> + QTempDBJobClaimInfoWriter<JobId>, JobId> QTempDBJobClaimInfoStore<JobId> for T {}
