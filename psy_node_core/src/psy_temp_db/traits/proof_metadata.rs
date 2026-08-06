use async_trait::async_trait;
use parth_core::{node::realm_identifier::QRealmIdentifier, protocol::core_types::Q256BitHash};
use psy_data::{
    protocol::chain_context::PendingContext,
    worker::metadata::PsyProvingJobMetadata,
};



#[async_trait]
pub trait QTempDBProvingJobMetadataReader<Hash: Q256BitHash, JobId> {
    async fn get_proving_job_metadata(
        &self,
        rid: &QRealmIdentifier,
        context: &PendingContext<Hash>,
        job_id: JobId,
    ) -> anyhow::Result<PsyProvingJobMetadata<Hash, JobId>>;
}

#[async_trait]
pub trait QTempDBProvingJobMetadataWriter<Hash: Q256BitHash, JobId> {
    async fn set_proving_job_metadata(
        &self,
        rid: &QRealmIdentifier,
        context: &PendingContext<Hash>,
        job_id: JobId,
        metadata: &PsyProvingJobMetadata<Hash, JobId>,
    ) -> anyhow::Result<()>;
    async fn set_proving_job_metadata_batch(
        &self,
        rid: &QRealmIdentifier,
        context: &PendingContext<Hash>,
        data: &[(JobId, PsyProvingJobMetadata<Hash, JobId>)],
    ) -> anyhow::Result<()>;
}

pub trait QTempDBProvingJobMetadataStore<Hash: Q256BitHash, JobId>:
    QTempDBProvingJobMetadataReader<Hash, JobId>
    + QTempDBProvingJobMetadataWriter<Hash, JobId>
{
}
impl<
        T: QTempDBProvingJobMetadataReader<Hash, JobId>
            + QTempDBProvingJobMetadataWriter<Hash, JobId>,
        Hash: Q256BitHash,
        JobId,
    > QTempDBProvingJobMetadataStore<Hash, JobId> for T
{
}







