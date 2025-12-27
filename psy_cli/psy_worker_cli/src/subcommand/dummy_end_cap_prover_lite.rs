use cf_utils::log_indicator::print_cf_log_indicator;
use parth_core::protocol::core_types::QNetworkTypesConfigHelper;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use psy_core::{
    constants::{
        chain_id::{PsyChainNetworkType, PsyNetworkTypeInput},
        proving_backends::{PsyChainProvingBackendType, PsyChainProvingBackendTypeInput},
    },
    job::job_id::QProvingJobDataID,
    network_config::PsyNetworkLocalDevnetConstants,
};
use psy_jtmb_testing_core::{
    end_cap::dummy_prover::run_jtmb_dummy_prover_lite,
    protocol_types::{JTMBPoseidonGoldilocksConfig, ZKTypesJTMBGoldilocksPoseidon},
};
use psy_plonky2_circuits::{end_cap::dummy_prover::run_plonky2_dummy_prover_lite, protocol_types::ZKTypesPlonky2GoldilocksPoseidon};
// use psy_plonky2_circuits::protocol_types::ZKTypesPlonky2GoldilocksPoseidon;


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
    realm_api_url: String,
    coordinator_api_url: String,
    min_state_updates: u32,
    max_state_updates: u32,
    max_contract_calls: u32,
    start_user_id: u64,
    count: u64,
    batches: u32,
    proving_backend: PsyChainProvingBackendType,
    network: PsyChainNetworkType,
) -> anyhow::Result<()> {
    if proving_backend == PsyChainProvingBackendType::Plonky2PoseidonGoldilocks {
        tracing::info!("Using Plonky2 Poseidon Goldilocks proving backend for lite dummy end cap prover");
        type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
        run_plonky2_dummy_prover_lite::<N, PoseidonGoldilocksConfig, 2>(
            &realm_api_url,
            &coordinator_api_url,
            min_state_updates,
            max_state_updates,
            max_contract_calls,
            start_user_id,
            count,
            batches,
        ).await?;
        
    } else if proving_backend == PsyChainProvingBackendType::JTMBPoseidonGoldilocks {
        tracing::info!("Using JTMB Poseidon Goldilocks proving backend for lite dummy end cap prover");
        type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesJTMBGoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;

        run_jtmb_dummy_prover_lite::<N, JTMBPoseidonGoldilocksConfig>(
            &realm_api_url,
            &coordinator_api_url,
            min_state_updates,
            max_state_updates,
            max_contract_calls,
            start_user_id,
            count,
            batches,
            network,
        )
        .await?;
    } else {
        anyhow::bail!("Unsupported proving backend for dummy end cap prover: {:?}", proving_backend);
    }

    Ok(())
}

pub async fn run(
    realm_api_url: String,
    coordinator_api_url: String,
    min_state_updates: u32,
    max_state_updates: u32,
    max_contract_calls: u32,
    start_user_id: u64,
    count: u64,
    batches: u32,
    network: Option<PsyNetworkTypeInput>,
    proving_backend: Option<PsyChainProvingBackendTypeInput>,
) -> anyhow::Result<()> {
    print_banner();
    tracing::info!("Dummy lite end cap prover starting...");
    tracing::info!("realm api url: {} | coordinator api url: {}", realm_api_url, coordinator_api_url);
    let network = network.unwrap_or(PsyNetworkTypeInput::LocalDevnet).into();

    print_cf_log_indicator("LITE_DUMMY_END_CAP_PROVER_STARTED", "");
    run_worker_inner(
        realm_api_url.clone(),
        coordinator_api_url.clone(),
        min_state_updates,
        max_state_updates,
        max_contract_calls,
        start_user_id,
        count,
        batches,
        proving_backend
            .unwrap_or(PsyChainProvingBackendTypeInput::Plonky2PoseidonGoldilocks)
            .into(),
        network,
    )
    .await?;
    print_cf_log_indicator("LITE_DUMMY_END_CAP_PROVER_STOPPED", "");
    Ok(())
}
