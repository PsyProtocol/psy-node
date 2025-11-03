use async_trait::async_trait;
use auto_impl::auto_impl;
use parth_core::{data::serializable::QProofWitnessSerializable, node::realm_identifier::QRealmIdentifier, QJobIdBase};



#[async_trait]
pub trait QTempDBProofWitnessReader<JobId: QJobIdBase> {
    async fn get_tdb_proof_witness<T: QProofWitnessSerializable>(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_id: JobId) -> anyhow::Result<T>;
    async fn get_tdb_proof_witness_bytes(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_id: JobId) -> anyhow::Result<Vec<u8>>;
    async fn get_tdb_proof_expected_public_inputs_hash_raw_and_dependencies(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_id: JobId) -> anyhow::Result<([u8; 32], Vec<JobId>)>;
}

#[async_trait]
pub trait QTempDBProofWitnessWriter<JobId: QJobIdBase> {
    async fn set_tdb_proof_witness<T: QProofWitnessSerializable>(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_id: JobId, witness: &T) -> anyhow::Result<()>;
    async fn set_tdb_proof_witnesses_tuple_owned<T: QProofWitnessSerializable>(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_witnesses: &[(JobId, T)]) -> anyhow::Result<()>;
    async fn set_tdb_proof_expected_public_inputs_hash_and_dependencies_raw(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_id: JobId, expected_public_inputs_hash: [u8; 32], dependencies: &[JobId]) -> anyhow::Result<()>;
    async fn set_tdb_proof_expected_public_inputs_many_tuple_owned_hash_raw(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_public_inputs: Vec<(JobId, ([u8; 32], Vec<JobId>))>) -> anyhow::Result<()>;

}

pub trait QTempDBProofWitnessStore<JobId: QJobIdBase>: QTempDBProofWitnessReader<JobId> + QTempDBProofWitnessWriter<JobId> {}
impl<T: QTempDBProofWitnessReader<JobId> + QTempDBProofWitnessWriter<JobId>, JobId: QJobIdBase> QTempDBProofWitnessStore<JobId> for T {}








