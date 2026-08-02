use plonky2::plonk::config::PoseidonGoldilocksConfig;
use psy_core::constants::{
    chain_id::{PsyChainNetworkType, PsyNetworkTypeInput},
    proving_backends::{PsyChainProvingBackendType, PsyChainProvingBackendTypeInput},
    url_rotation::PsyAPIURLRotationStrategyInput,
};
use psy_jtmb_testing_core::{circuit_library::worker::get_simple_proof_miner_worker_for_network_jtmb, protocol_types::JTMBPoseidonGoldilocksConfig};
use psy_plonky2_circuits::circuit_library::get_simple_proof_miner_worker_for_network;
use psy_worker_core::config::{worker_cli_config::WorkerCliConfig, worker_config::WorkerStartupConfig};
use tracing::{error, info};

fn print_banner() {
    println!(
        r#"
               7PB&?                         ..........                                             
               G@@@!                        ~####&&&&##BPJ~                                         
               Y@@&^                        !@@@#PPPPGB&@@@B7                                       
        .      ?@@#.      .                 !@@@5      :!B@@@J                                      
   !?Y5G#P.    !@@G    ^?P#G.               !@@@5        :&@@@^       ...                           
   ^!J&@@&^    ^@@P    !&@@@J               !@@@5         P@@@!   ~YG#&&#BGY^ ~GGG?         ~GGG?   
      5@@&^    :@@Y     !@@@P               !@@@5        .#@@@^ .5@@@BP5PG#@!  5@@@!       .B@@&^   
      P@@#.    :&@J      B@@G               !@@@5       ^P@@@5  7@@@?     .^.  .G@@#:      Y@@@!    
      B@@B     :&@?      G@@J               !@@@BJJJJY5B@@@&Y   !@@@P~.         :#@@G     !@@@J     
      #@@#:    :&@?     :&@#.               !@@@@@@@@@@&#P?^     7B@@@&GY!.      ~&@@J   :#@@P      
      Y@@@?    :@@?    .G@#~                !@@@P^^^^^^:.          ~JG#@@@&5^     ?@@@!  5@@#:      
      .G@@@J:  :@@?   ~B@G^                 !@@@5                     .~J&@@&^     Y@@#:7@@&~       
        ?B@@&GYY@@5?5B@B7                   !@@@5               .:       ?@@@?      G@@B#@@?        
          ~?5GB&@@&G5?^                     !@@@5               J@GJ7~~!J#@@#:      :#@@@@P         
               Y@@5                         !&@@5               ?B&@@@@@@@#Y:        !@@@B:         
               P@@B                         .::::                 :^~!!!~^.          5@@&~          
              .B@@&.                                                                ?@@@?           
              ^&&BP:                                                               !@@@5            
               ^:                                                                 ^#@@B.            
                                                                                  P@@&~             
    "#
    );
}

pub async fn run_worker_inner(
    network: PsyChainNetworkType,
    config: WorkerStartupConfig,
    proving_backend: PsyChainProvingBackendType,
    batch_size: usize,
) -> anyhow::Result<()> {
    // Placeholder for actual worker logic

    if proving_backend == PsyChainProvingBackendType::Plonky2PoseidonGoldilocks {
        type C = PoseidonGoldilocksConfig;
        const D: usize = 2;
        let worker = get_simple_proof_miner_worker_for_network::<C, D>(network, config).await?;

        worker.run_worker_loop(100, batch_size).await?;
    } else if proving_backend == PsyChainProvingBackendType::JTMBPoseidonGoldilocks {
        let worker = get_simple_proof_miner_worker_for_network_jtmb::<JTMBPoseidonGoldilocksConfig>(network, config).await?;
        worker.run_worker_loop(100, batch_size).await?;
    }
    Ok(())
}

pub async fn run(
    config: Option<String>,
    private_key: Option<String>,
    keystore_path: Option<String>,
    wallet_password: Option<String>,
    recipient: Option<u64>,
    network: Option<PsyNetworkTypeInput>,
    proving_backend: Option<PsyChainProvingBackendTypeInput>,
    completed_jobs_log_file: Option<String>,
    realm_api_urls: Vec<String>,
    coordinator_api_urls: Vec<String>,
    url_rotation_strategy: PsyAPIURLRotationStrategyInput,
    batch_size: usize,
) -> anyhow::Result<()> {
    print_banner();
    info!("Worker starting...");
    let config = WorkerCliConfig::get_start_config(
        config,
        private_key,
        keystore_path,
        wallet_password,
        recipient,
        network,
        completed_jobs_log_file,
        coordinator_api_urls,
        realm_api_urls,
        url_rotation_strategy,
    )
    .await?.with_unique_api_urls();
    let network = config.network.clone();

    let mut handles = Vec::new();

    let proving_backend = proving_backend
            .unwrap_or(PsyChainProvingBackendTypeInput::Plonky2PoseidonGoldilocks)
            .into();
    let handle = tokio::spawn(run_worker_inner(
        network,
        config,
        proving_backend,
        batch_size,
    ));
    handles.push(handle);
    /*

    for coordinator_config in &network.coordinator_configs {
        for rpc_url in &coordinator_config.rpc_url {
            let handle = tokio::spawn(run_worker(
                rpc_url.clone(),
                JobLocation::Coordinator,
                job_tracker.clone(),
                prover.clone(),
                proof_verifier.clone(),
                wallet.clone(),
                worker_public_key.clone(),
                user_id,
            ));
            handles.push(handle);
        }
    }

    for realm_config in &network.realm_configs {
        for rpc_url in &realm_config.rpc_url {
            let handle = tokio::spawn(run_worker(
                rpc_url.clone(),
                JobLocation::Realm(realm_config.id),
                job_tracker.clone(),
                prover.clone(),
                proof_verifier.clone(),
                wallet.clone(),
                worker_public_key.clone(),
                user_id,
            ));
            handles.push(handle);
        }
    }*/

    info!("Started {} worker threads", handles.len());

    let ctrl_c = tokio::signal::ctrl_c();
    tokio::select! {
        _ = ctrl_c => {
            info!("Ctrl-C signal received, cleaning up...");
        }
        _ = async {
            for handle in handles {
                if let Err(e) = handle.await {
                    error!("Worker thread failed: {:?}", e);
                }
            }
        } => {
            info!("All worker threads completed");
        }
    }

    info!("Worker exit.");
    Ok(())
}
