use async_trait::async_trait;
use plonky2::plonk::{config::GenericConfig, proof::ProofWithPublicInputs};
use psy_core::{job::job_id::QProvingJobDataID, worker::traits::QNextGenWorkerGenericInfo};
use psy_plonky2_basic_helpers::verifier::circuit_library::CircuitInfoLibrary;

use crate::qstandard::proof_store::QProofStoreReaderAsync;




#[async_trait]
pub trait QNextGenWorkerGenericProverAsyncMut<
    S: QProofStoreReaderAsync + Send + Sync,
    L: CircuitInfoLibrary<C,D> + Send + Sync,
    C: GenericConfig<D>,
    const D: usize,
>: QNextGenWorkerGenericInfo<QProvingJobDataID> {
    async fn worker_prove_mut_async(
        &self,
        store: &S,
        library: &L,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
}
