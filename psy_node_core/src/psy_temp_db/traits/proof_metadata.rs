use async_trait::async_trait;
use parth_core::{node::realm_identifier::QRealmIdentifier};
use psy_data::worker::metadata::PsyProvingJobMetadata;



#[async_trait]
pub trait QTempDBProvingJobMetadataReader<Hash, JobId> {
    async fn get_proving_job_metadata(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_id: JobId) -> anyhow::Result<PsyProvingJobMetadata<Hash, JobId>>;
}

#[async_trait]
pub trait QTempDBProvingJobMetadataWriter<Hash, JobId> {
    async fn set_proving_job_metadata(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_id: JobId, metadata: &PsyProvingJobMetadata<Hash, JobId>) -> anyhow::Result<()>;
    async fn set_proving_job_metadata_batch(&self, rid: &QRealmIdentifier, unique_pending_id: u64, data: &[(JobId, PsyProvingJobMetadata<Hash, JobId>)]) -> anyhow::Result<()>;
}

pub trait QTempDBProvingJobMetadataStore<Hash, JobId>: QTempDBProvingJobMetadataReader<Hash, JobId> + QTempDBProvingJobMetadataWriter<Hash, JobId> {}
impl<T: QTempDBProvingJobMetadataReader<Hash, JobId> + QTempDBProvingJobMetadataWriter<Hash, JobId>, Hash, JobId> QTempDBProvingJobMetadataStore<Hash, JobId> for T {}








