
use psy_node_core::config::node_start_config::CoordinatorEdgeStartConfig;
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

pub async fn run_coordinator_edge_inner(config: CoordinatorEdgeStartConfig) -> anyhow::Result<()> {
    // Placeholder for actual worker logic
    println!("Starting Coordinator Edge with config: {:?}", config);
    loop {
        info!("Coordinator Edge is running...");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

pub async fn run(
    config: CoordinatorEdgeStartConfig,
) -> anyhow::Result<()> {
    print_banner();
    info!("Using network: {:?}", config.network);
    
    Ok(())
}
