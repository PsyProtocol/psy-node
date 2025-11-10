use async_trait::async_trait;
use parth_core::pgoldilocks::QHashOut;
use plonky2::plonk::{
    circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
    config::GenericConfig,
    proof::ProofWithPublicInputs,
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse;
use psy_plonky2_basic_helpers::verifier::circuit_library::CircuitInfoLibrary;
use serde::{de::DeserializeOwned, Serialize};

use crate::qstandard::proof_store::{QProofStoreReaderAsync, QProofStoreReaderSync};

pub trait QPsyNetworkCircuitWithType {
    fn get_circuit_type(&self) -> ProvingJobCircuitType;
}
pub trait QStandardCircuit<C: GenericConfig<D>, const D: usize> {
    fn get_fingerprint(&self) -> QHashOut<C::F>;
    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D>;
    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D>;
    fn print_config(&self) {
        tracing::info!(
            "constants_sigmas_cap_height: {}",
            self.get_verifier_config_ref().constants_sigmas_cap.height()
        );
        tracing::info!("common_data: {:?}", self.get_common_circuit_data_ref());
    }
    fn print_config_with_name(&self, name: &str) {
        /*let common_data_bytes = self
            .get_common_circuit_data_ref()
            .to_bytes(&gate_serializer)
            .unwrap();
        let common_data_hash = CoreSha256Hasher::hash_bytes(&common_data_bytes).to_hex_string();
        tracing::info!(
            "[{}] {{constants_sigmas_cap_height: {}, common_data_hash: {}}}",
            name,
            self.get_verifier_config_ref().constants_sigmas_cap.height(),
            common_data_hash,
        );
        */
        /*
        tracing::info!(
            "[{}] common_data: {:?}",
            name,
            self.get_common_circuit_data_ref()
        );
        */

        /*tracing::info!(
            "[{}] {{constants_sigmas_cap_height: {}}}",
            name,
            self.get_verifier_config_ref().constants_sigmas_cap.height(),
        );*/
        tracing::info!("{}: \"{:?}\",", name, self.get_common_circuit_data_ref());
    }
    fn get_verifier_triplet(
        &self,
    ) -> (
        &CommonCircuitData<C::F, D>,
        &VerifierOnlyCircuitData<C, D>,
        QHashOut<C::F>,
    ) {
        (
            self.get_common_circuit_data_ref(),
            self.get_verifier_config_ref(),
            self.get_fingerprint(),
        )
    }
}
pub trait QStandardCircuitWithDefault {
    fn new_default(network_magic: u64) -> Self;
}
pub trait QStandardCircuitWithDefaultMinified {
    fn new_default_with_minifiers(network_magic: u64, n_minifiers: usize) -> Self;
}

pub trait QStandardCircuitProvableWithProofStoreSync<
    S: QProofStoreReaderSync,
    I: DeserializeOwned + Serialize + Clone,
    C: GenericConfig<D>,
    const D: usize,
>: QStandardCircuit<C, D>
{
    fn prove_with_proof_store_sync(
        &self,
        store: &S,
        input: &I,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
}
pub trait QStandardCircuitProvableSerializedWithProofStoreSync<
    S: QProofStoreReaderSync,
    C: GenericConfig<D>,
    const D: usize,
>: QStandardCircuit<C, D>
{
    fn prove_with_proof_store_sync(
        &self,
        store: &S,
        input: &[u8],
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
}
#[async_trait]
pub trait QStandardCircuitProvableWithProofStoreAsync<
    S: QProofStoreReaderAsync,
    I: Serialize + Clone,
    C: GenericConfig<D>,
    const D: usize,
>: QStandardCircuit<C, D>
{
    async fn prove_with_proof_store_async(
        &self,
        store: &S,
        input: &I,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
}


pub trait VerifierDataStore<C: GenericConfig<D>, const D: usize> {
    fn get_verifier_data_by_fingerprint(&self, fingerprint: QHashOut<C::F>) -> Option<&VerifierOnlyCircuitData<C, D>>;
}


#[async_trait]
pub trait QStandardCircuitProvableWithProofStoreAndRefLibraryAsync<
    S: QProofStoreReaderAsync + Send + Sync,
    L: CircuitInfoLibrary<C,D> + Send + Sync,
    C: GenericConfig<D>,
    const D: usize,
>: QStandardCircuit<C, D>
{
    async fn prove_with_proof_store_async(
        &self,
        store: &S,
        library: &L,
        job_id: QProvingJobDataID,
        worker_public_key: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
}




#[async_trait]
pub trait QStandardCircuitProvableWithRawProofsAndRefLibraryAsync<
    L: CircuitInfoLibrary<C,D> + Send + Sync,
    C: GenericConfig<D>,
    const D: usize,
>: QStandardCircuit<C, D>
{
    async fn prove_with_raw_proofs_and_ref_library_async(
        &self,
        library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<QHashOut<C::F>, QProvingJobDataID>,
        worker_reward_tag: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
}

