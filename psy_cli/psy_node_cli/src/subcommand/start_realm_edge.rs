use psy_core::constants::proving_backends::PsyChainProvingBackendType;
use psy_node_cli::node::{
    startup_edge_jtmb_scylla::run_startup_jtmb_poseidon_goldilocks_scylla_realm_edge_node,
    startup_edge_plonky2_scylla::run_startup_plonky2_scylla_realm_edge_node,
};
use psy_node_core::config::node_start_config::RealmEdgeStartConfig;
use tokio::signal;
use tracing::info;

fn print_banner() {
    println!(
        r#"

            ░▓▓░                    ░▓▓▓▓▓▓▓▓░░\
            ▒▓▓░                    ░▓▓░░░░▓▓▓▓▓░\
            ▒▓▓▓                    ░▓▓░     ░▓▓▓░
  🬨▓▓▓▓▓▒   ▓▓▓▓  🭁░▓▓▓             ░▓▓░      ░▓▓▓▒    🮞▓▓▓..
     ░▓▓▒    ▓▓▓   ▓▓▓▓             ░▓▓░      ░▓▓▓▒ ▒░▓▓▓▓▓▓▓░ ░▓▓░       ▓▓▓▒
     ░▓▓▒    ▓▓▓    ░▓▓░            ░▓▓░      ░▓▓░🮜 ▓▓▓▒    ▓░   ▓▓░     ▓▓▓░
     ▓▓▓▓    ▓▓▓    ░▓▓             ░▓▓░░░░░░▓▓▓▓░ ░▓▓▓▓         ▓▓▓    ▒▓▓▓▓
     ▓▓▓▒    ▓▓▓    ▓▓▒              ▓▓▓▓▓▓▓▓▓░░    ▓▓▓▓▓▓▓▒     ░▓▓     ▓▓▒
     ░▓▓░    ▓▓▓   ░▓▓              ░▓▓░               ▓░▓▓▓▓░    ░▓▓. .▓▓░
      ░▓▓▓▓ ▓▓▓▓ ░▓▓░               ░▓▓░                  ▓▓▓▓░    ░▓▓ ▓▓░
       ▒░▓▓▓▓▓▓▓▓▓░░                ░▓▓░           .░▓    ░▓▓▓░    ░▓▓▓▓▓▓
            ▒▓▓▓                    ░▓▓░           ▓▓▓▓▓▓▓▓▓▓▒      ▒▓▓▓░
            ▒▓▓▓                                      ▓▓▓▓▓         ▒▓▓░
            ▒▓▓▓                                                   ░▓▓▓▒
            ▒▓▓🭡                                                   ░▓▓▓▒
                                                                   ▓▓░
    "#
    );
}

pub async fn run(config: RealmEdgeStartConfig, proving_backend: PsyChainProvingBackendType) -> anyhow::Result<()> {
    print_banner();
    info!("Using network: {:?} and proving backend: {:?}", config.network, proving_backend);

    info!("Realm edge starting...");
    if proving_backend == PsyChainProvingBackendType::Plonky2PoseidonGoldilocks {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Ctrl-C received, shutting down realm edge...");
            }
            res = run_startup_plonky2_scylla_realm_edge_node(&config) => {
                res?;
            }
        }
    } else if proving_backend == PsyChainProvingBackendType::JTMBPoseidonGoldilocks {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Ctrl-C received, shutting down realm edge...");
            }
            res = run_startup_jtmb_poseidon_goldilocks_scylla_realm_edge_node(&config) => {
                res?;
            }
        }
    } else {
        anyhow::bail!("Unsupported proving backend for realm edge node: {:?}", proving_backend);
    }

    info!("Realm Edge exit.");
    Ok(())
}
