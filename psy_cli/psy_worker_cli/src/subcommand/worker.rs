use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::hash_types::HashOut,
    plonk::config::GenericHashOut,
};
use psy_core::constants::chain_id::PsyNetworkTypeInput;
use tokio::{sync::Mutex, time::sleep};
use tracing::{error, info};


type C = plonky2::plonk::config::PoseidonGoldilocksConfig;
const D: usize = 2;
type F = GoldilocksField;

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

pub async fn run_worker_inner() -> anyhow::Result<()> {
    // Placeholder for actual worker logic
    loop {
        info!("Worker is running...");
        sleep(Duration::from_secs(5)).await;
    }
    Ok(())
}

pub async fn run(
    config: String,
    private_key: Option<String>,
    keystore_path: Option<String>,
    wallet_password: Option<String>,
    recipient: Option<u64>,
    network: Option<PsyNetworkTypeInput>,
) -> anyhow::Result<()> {
    print_banner();
    info!("Worker starting...");
    info!("Loading config from: {}", config);
    let mut handles = Vec::new();

    let handle = tokio::spawn(run_worker_inner());
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
