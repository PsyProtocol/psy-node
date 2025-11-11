use async_trait::async_trait;
use parth_core::{data::serializable::QProofWitnessSerializable, node::realm_identifier::QRealmIdentifier, QJobIdBase};



#[async_trait]
pub trait QTempDBProofWitnessReader<JobId: QJobIdBase> {
    async fn get_tdb_proof_witness<T: QProofWitnessSerializable>(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_id: JobId) -> anyhow::Result<T>;
    async fn get_tdb_proof_witness_bytes(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_id: JobId) -> anyhow::Result<Vec<u8>>;
}

#[async_trait]
pub trait QTempDBProofWitnessWriter<JobId: QJobIdBase> {
    async fn set_tdb_proof_witness<T: QProofWitnessSerializable>(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_id: JobId, witness: &T) -> anyhow::Result<()>;
    async fn set_tdb_proof_witnesses_tuple_owned<T: QProofWitnessSerializable>(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_witnesses: &[(JobId, T)]) -> anyhow::Result<()>;
    async fn set_tdb_proof_witnesses_tuple_owned_raw(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_witnesses: Vec<(JobId, Vec<u8>)>) -> anyhow::Result<()>;
}

pub trait QTempDBProofWitnessStore<JobId: QJobIdBase>: QTempDBProofWitnessReader<JobId> + QTempDBProofWitnessWriter<JobId> {}
impl<T: QTempDBProofWitnessReader<JobId> + QTempDBProofWitnessWriter<JobId>, JobId: QJobIdBase> QTempDBProofWitnessStore<JobId> for T {}








