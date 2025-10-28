use plonky2::plonk::config::GenericConfig;

use crate::verifier::circuit_library::CircuitInfoLibrary;



#[async_trait]
pub trait QNextGenWorkerGenericProverAsyncMut<
    S: QProofStoreReaderAsync + Send + Sync,
    L: CircuitInfoLibrary<C,D> + Send + Sync,
    C: GenericConfig<D>,
    const D: usize,
>: QNextGenWorkerGenericInfo {
    async fn worker_prove_mut_async(
        &self,
        store: &S,
        library: &L,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
}
