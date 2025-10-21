use async_trait::async_trait;
use parth_core::{node::realm_identifier::QRealmIdentifier, QJobIdBase};



#[async_trait]
pub trait QTempDBExpectedPublicInputsReader<JobId: QJobIdBase, Hash> {
    async fn get_expected_public_inputs_hash(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_id: JobId) -> anyhow::Result<Hash>;
}

#[async_trait]
pub trait QTempDBExpectedPublicInputsWriter<JobId: QJobIdBase, Hash> {
    async fn set_expected_public_inputs_hash(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_id: JobId, hash: Hash) -> anyhow::Result<()>;
    async fn set_expected_public_inputs_hash_batch_fast_serialized(&self, rid: &QRealmIdentifier, unique_pending_id: u64, data: &[u8]) -> anyhow::Result<()>;
}

pub trait QTempDBExpectedPublicInputsStore<JobId: QJobIdBase, Hash>: QTempDBExpectedPublicInputsReader<JobId, Hash> + QTempDBExpectedPublicInputsWriter<JobId, Hash> {}
impl<T: QTempDBExpectedPublicInputsReader<JobId, Hash> + QTempDBExpectedPublicInputsWriter<JobId, Hash>, JobId: QJobIdBase, Hash> QTempDBExpectedPublicInputsStore<JobId, Hash> for T {}








