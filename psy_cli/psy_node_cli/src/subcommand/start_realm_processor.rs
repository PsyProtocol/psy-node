
use psy_node_cli::node::startup_plonky2_scylla::run_startup_plonky2_scylla_realm_processor_node;
use psy_node_core::config::node_start_config::RealmProcessorStartConfig;
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


pub async fn run(config: RealmProcessorStartConfig) -> anyhow::Result<()> {
    print_banner();
    info!("Using network: {:?}", config.network);

    run_startup_plonky2_scylla_realm_processor_node(&config).await?;
    info!("Coordinator Processor exit.");
    Ok(())
}
