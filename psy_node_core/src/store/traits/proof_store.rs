use async_trait::async_trait;
use parth_core::{data::serializable::QPDSerializable, QJobIdSerialized};

use crate::store::proof_namespace::{
    CanonicalProofStoreAddress, CanonicalProofStoreNamespace,
};

#[async_trait]
pub trait QParthProofStoreReader {
    async fn get_proof_bytes_by_job_id<J: Into<QJobIdSerialized> + Copy + Send + Sync>(
        &self,
        job_id: J,
        unique_pending_id: u64,
    ) -> anyhow::Result<Option<Vec<u8>>>;
    async fn get_proof_by_job_id<J: Into<QJobIdSerialized> + Copy + Send + Sync, P: QPDSerializable>(
        &self,
        job_id: J,
        unique_pending_id: u64,
    ) -> anyhow::Result<Option<P>>;
    async fn contains_proof_for_job_id<J: Into<QJobIdSerialized> + Copy + Send + Sync>(
        &self,
        job_id: J,
        unique_pending_id: u64,
    ) -> anyhow::Result<bool>;
}

#[async_trait]
pub trait QParthProofStoreWriter {
    async fn put_proof_bytes_for_job_id<J: Into<QJobIdSerialized> + Copy + Send + Sync>(
        &self,
        job_id: J,
        unique_pending_id: u64,
        proof_bytes: &[u8],
    ) -> anyhow::Result<()>;
    async fn put_proof_for_job_id<J: Into<QJobIdSerialized> + Copy + Send + Sync, P: QPDSerializable + Send + Sync>(
        &self,
        job_id: J,
        unique_pending_id: u64,
        proof: &P,
    ) -> anyhow::Result<()>;
    async fn delete_all_proofs_for_pending_id(&self, unique_pending_id: u64) -> anyhow::Result<()>;
}

pub trait QParthProofStore: QParthProofStoreReader + QParthProofStoreWriter {}
impl<T: QParthProofStoreReader + QParthProofStoreWriter> QParthProofStore for T {}

/// Exact proof-store access for the C-02b epoch-fenced namespace.
///
/// This trait deliberately has no method accepting a bare pending ID or raw
/// Redis key. Existing V1 traits remain available until the Worker rollout is
/// complete, but are not a substitute for this interface.
#[async_trait]
pub trait QCanonicalProofStoreV2 {
    async fn get_proof_bytes_exact(
        &self,
        address: &CanonicalProofStoreAddress,
    ) -> anyhow::Result<Option<Vec<u8>>>;

    async fn contains_proof_exact(
        &self,
        address: &CanonicalProofStoreAddress,
    ) -> anyhow::Result<bool>;

    async fn put_proof_bytes_exact(
        &self,
        address: &CanonicalProofStoreAddress,
        proof_bytes: &[u8],
    ) -> anyhow::Result<()>;

    async fn delete_proof_namespace_exact(
        &self,
        namespace: &CanonicalProofStoreNamespace,
    ) -> anyhow::Result<()>;
}
