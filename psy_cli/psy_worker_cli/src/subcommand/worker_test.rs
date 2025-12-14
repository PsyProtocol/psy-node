use std::
    time::Duration
;

use psy_core::constants::{chain_id::PsyNetworkTypeInput, proving_backends::PsyChainProvingBackendTypeInput};
use tokio::time::sleep;
use tracing::{error, info};



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

pub async fn run_worker_inner() -> anyhow::Result<()> {
    // Placeholder for actual worker logic
    loop {
        info!("Worker is running...");
        sleep(Duration::from_secs(5)).await;
    }
}

pub async fn run(
    config: String,
    _private_key: Option<String>,
    _keystore_path: Option<String>,
    _wallet_password: Option<String>,
    _recipient: Option<u64>,
    _network: Option<PsyNetworkTypeInput>,
    _proving_backend: Option<PsyChainProvingBackendTypeInput>,
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
