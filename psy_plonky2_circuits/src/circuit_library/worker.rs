use anyhow::Ok;
use parth_common::secp256k1::MemorySecp256K1Wallet;
use parth_core::{
    crypto::hash::traits::{FieldQHasher, MerkleZeroHasher},
    data::hash::hash256::Hash256,
    felt::QFelt64,
    pgoldilocks::{PoseidonHasher, QGenericConfig, QHashOut, QRichField},
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use plonky2::{hash::hash_types::HashOut, plonk::config::AlgebraicHasher};
use psy_core::{
    constants::{chain_id::PsyChainNetworkType, url_rotation::PsyAPIURLRotationStrategy},
    job::job_id::QProvingJobDataID,
};
use psy_plonky2_basic_helpers::verifier::simple_circuit_library::SimpleCircuitLibrary;
use psy_worker_core::{
    api::basic_job_fetcher::PsyWorkerBasicAPIJobFetcher, config::worker_config::WorkerStartupConfig, worker::manager::PsyProofMinerWorkerManager,
};

use crate::{circuit_library::get_plonky2_circuit_library_and_prover_for_network, coordinator::coordinator_helper::QEDCoordinatorCircuitManager};

pub async fn get_simple_proof_miner_worker_for_network<C: QGenericConfig<D> + 'static, const D: usize>(
    network: PsyChainNetworkType,
    config: WorkerStartupConfig,
) -> anyhow::Result<
    PsyProofMinerWorkerManager<
        QHashOut<C::F>,
        QProvingJobDataID,
        PsyWorkerBasicAPIJobFetcher<QHashOut<C::F>, QProvingJobDataID, MemorySecp256K1Wallet, PoseidonHasher>,
        SimpleCircuitLibrary<C::F>,
        QEDCoordinatorCircuitManager<C, D>,
    >,
>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> + FieldQHasher<C::F, QHashOut<C::F>>,
    QHashOut<C::F>: Q256BitHash + QFHashBase<C::F>,
    C::F: QFelt64 + QRichField,
{
    let (gcv, coordinator_circuits) = get_plonky2_circuit_library_and_prover_for_network::<C, D>(network)?;

    let mut signer = MemorySecp256K1Wallet::new();
    let public_key = signer.add_private_key(Hash256(config.private_key))?;

    let job_fetcher = PsyWorkerBasicAPIJobFetcher::<QHashOut<C::F>, QProvingJobDataID, MemorySecp256K1Wallet, PoseidonHasher>::new(
        signer,
        public_key,
        config.miner_user_id,
        config.url_rotation_strategy.unwrap_or(PsyAPIURLRotationStrategy::ContinueUntilFailure),
    );

    job_fetcher
        .coordinator_api_url_manager
        .add_api_urls::<QHashOut<C::F>, QProvingJobDataID>(&config.coordinator_api_urls)
        .await?;
    job_fetcher
        .realm_api_url_manager
        .add_api_urls::<QHashOut<C::F>, QProvingJobDataID>(&config.realm_api_urls)
        .await?;
    let manager = PsyProofMinerWorkerManager::new(job_fetcher, gcv.library, coordinator_circuits);
    Ok(manager)
}
