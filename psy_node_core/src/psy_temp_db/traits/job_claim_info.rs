use async_trait::async_trait;
use parth_core::{node::realm_identifier::QRealmIdentifier, protocol::core_types::Q256BitHash};
use psy_data::protocol::chain_context::PendingContext;

#[async_trait]
pub trait QTempDBJobClaimInfoReader<Hash: Q256BitHash, JobId> {
    async fn get_job_claim(
        &self,
        rid: &QRealmIdentifier,
        context: &PendingContext<Hash>,
        job_id: JobId,
    ) -> anyhow::Result<Option<([u8; 33], u64)>>;
}

#[async_trait]
pub trait QTempDBJobClaimInfoWriter<Hash: Q256BitHash, JobId> {
    async fn set_job_claim(
        &self,
        rid: &QRealmIdentifier,
        context: &PendingContext<Hash>,
        job_id: JobId,
        public_key: &[u8; 33],
        claim_time_ms: u64,
    ) -> anyhow::Result<()>;
}

pub trait QTempDBJobClaimInfoStore<Hash: Q256BitHash, JobId>:
    QTempDBJobClaimInfoReader<Hash, JobId> + QTempDBJobClaimInfoWriter<Hash, JobId>
{
}
impl<
        T: QTempDBJobClaimInfoReader<Hash, JobId>
            + QTempDBJobClaimInfoWriter<Hash, JobId>,
        Hash: Q256BitHash,
        JobId,
    > QTempDBJobClaimInfoStore<Hash, JobId> for T
{
}
