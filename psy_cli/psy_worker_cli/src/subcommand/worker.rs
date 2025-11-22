
use cf_utils::option::resolve_one_of_two_options_or_error;
use plonky2::
    plonk::config::PoseidonGoldilocksConfig
;
use psy_core::constants::chain_id::{PsyChainNetworkType, PsyNetworkTypeInput};
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

pub async fn run_worker_inner(network: PsyChainNetworkType, config: WorkerStartupConfig) -> anyhow::Result<()> {
    // Placeholder for actual worker logic
    
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;
    let worker = get_simple_proof_miner_worker_for_network::<C, D>(network, config).await?;

    worker.run_worker_loop(100).await?;
    Ok(())
}

pub async fn run(
    config: String,
    private_key: Option<String>,
    _keystore_path: Option<String>,
    _wallet_password: Option<String>,
    recipient: Option<u64>,
    network: Option<PsyNetworkTypeInput>,
) -> anyhow::Result<()> {
    print_banner();
    info!("Worker starting...");
    info!("Loading config from: {}", config);
    let config_data = WorkerCliConfig::load_from_file(&config).await?;

    let network: PsyChainNetworkType = resolve_one_of_two_options_or_error::<PsyNetworkTypeInput>(&network, &config_data.network, "Network configuration is required")?.into();
    let user_id = resolve_one_of_two_options_or_error::<u64>(&recipient, &config_data.user, "User ID of miner is required")?;
    let private_key_string = resolve_one_of_two_options_or_error::<String>(&private_key, &config_data.private_key, "API Private key for miner is required")?;
    let private_key_bytes = hex::decode(private_key_string.trim_start_matches("0x"))?;
    if private_key_bytes.len() != 32 {
        anyhow::bail!("Private key must be 32 bytes (64 hex characters)");
    }
    let private_key_bytes: [u8; 32] = private_key_bytes.try_into().map_err(|_| anyhow::anyhow!("private key must be 32 bytes (64 hex characters)"))?;
    let config = WorkerStartupConfig {
        miner_user_id: user_id,
        network: network,
        private_key: private_key_bytes,
        worker_completed_jobs_log_file_path: config_data.completed_jobs_log_file.clone(),
        coordinator_api_urls: config_data.coordinator_api_urls,
        realm_api_urls: config_data.realm_api_urls,
    };
    info!("Using network: {:?}", network);




    let mut handles = Vec::new();

    let handle = tokio::spawn(run_worker_inner(network, config));
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
