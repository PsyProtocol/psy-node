use psy_core::constants::proving_backends::PsyChainProvingBackendType;
use psy_node_cli::node::{
    startup_plonky2_scylla::run_startup_plonky2_scylla_coordinator_processor_node,
    startup_processor_jtmb_scylla::run_startup_jtmb_poseidon_goldilocks_scylla_coordinator_processor_node,
};
use psy_node_core::config::node_start_config::CoordinatorProcessorStartConfig;
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

pub async fn run(config: CoordinatorProcessorStartConfig, proving_backend: PsyChainProvingBackendType) -> anyhow::Result<()> {
    print_banner();
    info!("Using network: {:?} and proving backend: {:?}", config.network, proving_backend);

    if proving_backend == PsyChainProvingBackendType::Plonky2PoseidonGoldilocks {
        run_startup_plonky2_scylla_coordinator_processor_node(&config).await?;
    } else if proving_backend == PsyChainProvingBackendType::JTMBPoseidonGoldilocks {
        run_startup_jtmb_poseidon_goldilocks_scylla_coordinator_processor_node(&config).await?;
    } else {
        anyhow::bail!("Unsupported proving backend for coordinator processor node: {:?}", proving_backend);
    }
    info!("Coordinator Processor exit.");
    Ok(())
}
