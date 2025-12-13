use std::
    time::Duration
;

use parth_core::protocol::core_types::QNetworkTypesConfigHelper;
use psy_core::{constants::chain_id::PsyNetworkTypeInput, job::job_id::QProvingJobDataID, network_config::PsyNetworkLocalDevnetConstants};
use psy_dummy_prover::api::data_fetcher::PsyUserContractDataFetcher;
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
    api_url: String,
    min_state_updates: u32,
    max_state_updates: u32,
    max_contract_calls: u32,
    user_id: u64,
) -> anyhow::Result<()> {
    type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
    let mut prover = create_plonky2_dummy_end_cap_prover::<N, C, D>(&api_url)?;

    prover.query_contract_state_heights(0, 100).await?;
    info!("Queried contract state heights");

    let initial_checkpoint = prover.client.df_get_latest_checkpoint().await?;
    info!("Initial checkpoint: {}", initial_checkpoint);

    prover.prove_random_contract_calls_and_submit(user_id, max_contract_calls, max_state_updates, min_state_updates).await?;
    info!("Proof submitted, waiting for new block...");

    loop {
        let current_checkpoint = prover.client.df_get_latest_checkpoint().await?;
        if current_checkpoint > initial_checkpoint {
            info!("New block generated, checkpoint: {}", current_checkpoint);
            break;
        }
        sleep(Duration::from_secs(1)).await;
    }

    Ok(())
}

pub async fn run(
    api_url: String,
    min_state_updates: u32,
    max_state_updates: u32,
    max_contract_calls: u32,
    user_id: u64,
    _network: Option<PsyNetworkTypeInput>,
) -> anyhow::Result<()> {
    print_banner();
    info!("Dummy end cap prover starting...");
    info!("api url: {}", api_url);

    loop {
        let res = run_worker_inner(
            api_url.clone(),
            min_state_updates,
            max_state_updates,
            max_contract_calls,
            user_id,
        ).await;
        if let Err(e) = res {
            error!("Error in worker loop: {:?}", e);
            sleep(Duration::from_secs(6)).await;
        } else {
            info!("Proof submitted successfully, sleeping...");
        }
    }
}
