use async_trait::async_trait;
use parth_core::node::realm_identifier::QRealmIdentifier;

#[async_trait]
pub trait QTempDBJobClaimInfoReader<JobId> {
    async fn get_job_claim(
        &self,
        rid: &QRealmIdentifier,
        unique_pending_id: u64,
        job_id: JobId,
    ) -> anyhow::Result<Option<([u8; 33], u64)>>;
}

#[async_trait]
pub trait QTempDBJobClaimInfoWriter<JobId> {
    async fn set_job_claim(
        &self,
        rid: &QRealmIdentifier,
        unique_pending_id: u64,
        job_id: JobId,
        public_key: &[u8; 33],
        claim_time_ms: u64,
    ) -> anyhow::Result<()>;
}

pub trait QTempDBJobClaimInfoStore<JobId>: QTempDBJobClaimInfoReader<JobId> + QTempDBJobClaimInfoWriter<JobId> {}
impl<T: QTempDBJobClaimInfoReader<JobId> + QTempDBJobClaimInfoWriter<JobId>, JobId> QTempDBJobClaimInfoStore<JobId> for T {}
