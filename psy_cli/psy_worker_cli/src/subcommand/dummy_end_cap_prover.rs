use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use parth_core::{pgoldilocks::{PoseidonHasher, QHashOut}, protocol::core_types::{QNetworkConstantsCopier, QNetworkTreeConstants, QNetworkTypesConfigHelper, QNetworkZKTypesCopier}};
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::hash_types::HashOut,
    plonk::config::GenericHashOut,
};
use psy_api_core::coordinator::standard_edge_rpc::CoordinatorEdgeRpcClient;
use psy_core::{constants::chain_id::PsyNetworkTypeInput, job::job_id::QProvingJobDataID, network_config::PsyNetworkLocalDevnetConstants};
use psy_dummy_prover::{api::data_fetcher::PsyUserContractDataFetcher, dummy_ups_state::state::DummyUPSStateBuilder, traits::DummyUPSProver};
use psy_plonky2_circuits::{end_cap::dummy_prover::create_plonky2_dummy_end_cap_prover, protocol_types::ZKTypesPlonky2GoldilocksPoseidon};
use tokio::{signal, sync::Mutex, time::sleep};
use tracing::{error, info};

type C = plonky2::plonk::config::PoseidonGoldilocksConfig;
const D: usize = 2;
type F = GoldilocksField;
type Hash = QHashOut<F>;

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



    


        let res = prover.query_contract_state_heights(0, 100).await;
        if res.is_err() {
            tracing::error!("Error querying contract state heights: {:?}", res.err());
        } else {
            info!("Queried contract state heights");
        }

    let ctrl_c = signal::ctrl_c();
    tokio::select! {
        _ = ctrl_c => {
            info!("Ctrl-C signal received, shutting down dummy end cap prover...");
        }
        _ = async {
            loop {
                info!("Worker is running...");
                if let Err(e) = prover.prove_random_contract_calls_and_submit(user_id, 1, 2, 1).await {
                    tracing::error!("Error in prove: {:?}", e);
                }
                sleep(Duration::from_secs(5)).await;
            }
        } => {}
    }
    Ok(())
}

pub async fn run(
    api_url: String,
    min_state_updates: u32,
    max_state_updates: u32,
    max_contract_calls: u32,
    user_id: u64,
    network: Option<PsyNetworkTypeInput>,
) -> anyhow::Result<()> {
    print_banner();
    info!("Dummy end cap prover starting...");
    info!("api url: {}", api_url);
run_worker_inner(
        api_url,
        min_state_updates,
        max_state_updates,
        max_contract_calls,
        user_id,
    ).await?;
    info!("Worker exit.");
    Ok(())
}
