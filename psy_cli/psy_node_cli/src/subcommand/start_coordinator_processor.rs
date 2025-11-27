
use psy_node_cli::node::startup_plonky2_scylla::run_startup_plonky2_scylla_processor_node;
use psy_node_core::config::node_start_config::CoordinatorProcessorStartConfig;
use tracing::{error, info};

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

pub async fn run_coordinator_processor_inner(config: CoordinatorProcessorStartConfig) -> anyhow::Result<()> {
    // Placeholder for actual worker logic
    println!("Starting Coordinator Processor with config: {:?}", config);
    loop {
        info!("Coordinator Processor is running...");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

pub async fn run(config: CoordinatorProcessorStartConfig) -> anyhow::Result<()> {
    print_banner();
    info!("Using network: {:?}", config.network);

    run_startup_plonky2_scylla_processor_node(&config).await?;
    info!("Coordinator Processor exit.");
    Ok(())
}
