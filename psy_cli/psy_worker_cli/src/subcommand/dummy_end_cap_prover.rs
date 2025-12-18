use std::time::Duration;

use cf_utils::log_indicator::print_cf_log_indicator;
use parth_core::protocol::core_types::QNetworkTypesConfigHelper;
use psy_core::{
    constants::{
        chain_id::{PsyChainNetworkType, PsyNetworkTypeInput},
        proving_backends::{PsyChainProvingBackendType, PsyChainProvingBackendTypeInput},
    },
    job::job_id::QProvingJobDataID,
    network_config::PsyNetworkLocalDevnetConstants,
};
use psy_dummy_prover::api::data_fetcher::PsyUserContractDataFetcher;
use psy_jtmb_testing_core::{
    end_cap::dummy_prover::create_jtmb_dummy_end_cap_prover,
    protocol_types::{JTMBPoseidonGoldilocksConfig, ZKTypesJTMBGoldilocksPoseidon},
};
use psy_plonky2_circuits::{end_cap::dummy_prover::create_plonky2_dummy_end_cap_prover, protocol_types::ZKTypesPlonky2GoldilocksPoseidon};
use tokio::time::sleep;
use tracing::{error, info};

type C = plonky2::plonk::config::PoseidonGoldilocksConfig;
const D: usize = 2;

fn print_banner() {
    println!(
        r#"
 ____              __  __ _
|  _ \ ___ _   _  |  \/  (_)_ __   ___ _ __
| |_) / __| | | | | |\/| | | '_ \ / _ \ '__|
|  __/\__ \ |_| | | |  | | | | | |  __/ |
|_|   |___/\__, | |_|  |_|_|_| |_|\___|_|
           |___/
    "#
    );
}

pub async fn run_worker_inner(
    coordinator_api_url: String,
    realm_api_url: String,
    min_state_updates: u32,
    max_state_updates: u32,
    max_contract_calls: u32,
    user_id: u64,
    proving_backend: PsyChainProvingBackendType,
    network: PsyChainNetworkType,
) -> anyhow::Result<()> {
    if proving_backend == PsyChainProvingBackendType::Plonky2PoseidonGoldilocks {
        info!("Using Plonky2 Poseidon Goldilocks proving backend for dummy end cap prover");
        type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
        let mut prover = create_plonky2_dummy_end_cap_prover::<N, C, D>(&coordinator_api_url, &realm_api_url)?;

        prover.query_contract_state_heights(0, 100).await?;
        info!("Queried contract state heights");

        let initial_checkpoint = prover.client.df_get_latest_checkpoint().await?;
        info!("Initial checkpoint: {}", initial_checkpoint);

        prover
            .prove_random_contract_calls_and_submit(user_id, max_contract_calls, max_state_updates, min_state_updates)
            .await?;
        info!("Proof submitted, waiting for new block...");

        loop {
            let current_checkpoint = prover.client.df_get_latest_checkpoint().await?;
            if current_checkpoint > initial_checkpoint {
                info!("New block generated, checkpoint: {}", current_checkpoint);
                break;
            }
            sleep(Duration::from_secs(1)).await;
        }
    } else if proving_backend == PsyChainProvingBackendType::JTMBPoseidonGoldilocks {

        info!("Using JTMB Poseidon Goldilocks proving backend for dummy end cap prover");
        type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesJTMBGoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
        
        
        let mut prover = create_jtmb_dummy_end_cap_prover::<N, JTMBPoseidonGoldilocksConfig>(&coordinator_api_url, &realm_api_url, network)?;

        prover.query_contract_state_heights(0, 100).await?;
        info!("Queried contract state heights");

        let initial_checkpoint = prover.client.df_get_latest_checkpoint().await?;
        info!("Initial checkpoint: {}", initial_checkpoint);

        prover
            .prove_random_contract_calls_and_submit(user_id, max_contract_calls, max_state_updates, min_state_updates)
            .await?;
        info!("Proof submitted, waiting for new block...");

        loop {
            let current_checkpoint = prover.client.df_get_latest_checkpoint().await?;
            if current_checkpoint > initial_checkpoint {
                info!("New block generated, checkpoint: {}", current_checkpoint);
                break;
            }
            sleep(Duration::from_secs(1)).await;
        }
    } else {
        anyhow::bail!("Unsupported proving backend for dummy end cap prover: {:?}", proving_backend);
    }

    Ok(())
}



pub async fn run(
    coordinator_api_url: String,
    realm_api_url: String,
    min_state_updates: u32,
    max_state_updates: u32,
    max_contract_calls: u32,
    user_id: u64,
    end_cap_count: u32,
    network: Option<PsyNetworkTypeInput>,
    proving_backend: Option<PsyChainProvingBackendTypeInput>,
) -> anyhow::Result<()> {
    print_banner();
    info!("Dummy end cap prover starting...");
    info!("realm api url: {} | coordinator api url: {}", realm_api_url, coordinator_api_url);
    let network = network.unwrap_or(PsyNetworkTypeInput::LocalDevnet).into();

    let mut end_caps_submitted = 0;
    print_cf_log_indicator("DUMMY_END_CAP_PROVER_STARTED", &format!("U{}",user_id));
    loop {
        let res = run_worker_inner(
            coordinator_api_url.clone(),
            realm_api_url.clone(),
            min_state_updates,
            max_state_updates,
            max_contract_calls,
            user_id,
            proving_backend.unwrap_or(PsyChainProvingBackendTypeInput::Plonky2PoseidonGoldilocks).into(),
            network,
        )
        .await;
        if let Err(e) = res {
            error!("Error in worker loop: {:?}", e);
            sleep(Duration::from_secs(6)).await;
        } else {
            info!("Proof submitted successfully, sleeping...");
        }
        end_caps_submitted += 1;
        if end_cap_count > 0 && end_caps_submitted >= end_cap_count {
            info!("Submitted {} end caps, exiting.", end_caps_submitted);
            break;
        }
    }
    print_cf_log_indicator("DUMMY_END_CAP_PROVER_STOPPED", &format!("U{}",user_id));
    Ok(())
}
