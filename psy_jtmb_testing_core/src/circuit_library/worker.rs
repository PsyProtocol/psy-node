use parth_common::secp256k1::MemorySecp256K1Wallet;
use std::sync::Arc;
use parth_core::
    data::hash::hash256::Hash256
;
use psy_core::{
    constants::{chain_id::PsyChainNetworkType, url_rotation::PsyAPIURLRotationStrategy},
    job::job_id::QProvingJobDataID,
};
use psy_worker_core::{
    api::{basic_job_fetcher::PsyWorkerBasicAPIJobFetcher},
    config::worker_config::WorkerStartupConfig,
    worker::manager::PsyProofMinerWorkerManager,
};

use crate::{
    circuit_library::core::get_jtmb_circuit_library_and_prover_for_network,
    proving::coordinator_helper::QEDCoordinatorCircuitManager,
    utils::{
        jtmb_standard_circuit::JTMBCircuitConfig,
        simple_circuit_info_library::JTMBSimpleCircuitLibrary,
    },
};

pub async fn get_simple_proof_miner_worker_for_network_jtmb<C: JTMBCircuitConfig + Send + Sync + 'static>(
    network: PsyChainNetworkType,
    config: WorkerStartupConfig,
) -> anyhow::Result<
    PsyProofMinerWorkerManager<
        C::Hash,
        QProvingJobDataID,
        PsyWorkerBasicAPIJobFetcher<C::Hash, QProvingJobDataID, MemorySecp256K1Wallet, C::Hasher>,
        JTMBSimpleCircuitLibrary<C>,
        QEDCoordinatorCircuitManager<C>,
    >,
> where C::Hasher: Send + Sync{
    let (verifier, manager) = get_jtmb_circuit_library_and_prover_for_network::<C>(network)?;

    let mut signer = MemorySecp256K1Wallet::new();
    let public_key = signer.add_private_key(Hash256(config.private_key))?;

    let job_fetcher = PsyWorkerBasicAPIJobFetcher::<C::Hash, QProvingJobDataID, MemorySecp256K1Wallet, C::Hasher>::new_with_backup_file_path(
        signer,
        public_key,
        config.miner_user_id,
        PsyAPIURLRotationStrategy::ContinueUntilFailure,
        config.worker_completed_jobs_log_file_path,
    ).await;

    job_fetcher.coordinator_api_url_manager.add_api_urls::<C::Hash, QProvingJobDataID>(&config.coordinator_api_urls).await?;
    job_fetcher.realm_api_url_manager.add_api_urls::<C::Hash, QProvingJobDataID>(&config.realm_api_urls).await?;

    let worker = PsyProofMinerWorkerManager::new(
        Arc::new(job_fetcher),
        Arc::new(verifier.library),
        Arc::new(manager),
    );

    Ok(worker)
}