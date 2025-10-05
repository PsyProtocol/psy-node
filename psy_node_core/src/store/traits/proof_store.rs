use async_trait::async_trait;
use parth_core::{data::serializable::QPDSerializable, QJobIdSerialized};

#[async_trait]
pub trait QParthProofStoreReader {
    async fn get_proof_bytes_by_job_id<J:  Into<QJobIdSerialized> + Copy + Send + Sync>(&self, job_id: J) -> anyhow::Result<Option<Vec<u8>>>;
    async fn get_proof_by_job_id<J: Into<QJobIdSerialized> + Copy + Send + Sync, P: QPDSerializable>(&self, job_id: J) -> anyhow::Result<Option<P>>;
    async fn contains_proof_for_job_id<J: Into<QJobIdSerialized> + Copy + Send + Sync>(&self, job_id: J) -> anyhow::Result<bool>;
}

#[async_trait]
pub trait QParthProofStoreWriter {
    async fn put_proof_bytes_for_job_id<J: Into<QJobIdSerialized> + Copy + Send + Sync>(&self, job_id: J, proof_bytes: &[u8]) -> anyhow::Result<()>;
    async fn put_proof_for_job_id<J: Into<QJobIdSerialized> + Copy + Send + Sync, P: QPDSerializable + Send + Sync>(&self, job_id: J, proof: &P) -> anyhow::Result<()>;
}

pub trait QParthProofStore: QParthProofStoreReader + QParthProofStoreWriter {}
impl<T: QParthProofStoreReader + QParthProofStoreWriter> QParthProofStore for T {}