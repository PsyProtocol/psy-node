use psy_client_common::args::PsyFaucetServerArgs;

pub async fn run(args: PsyFaucetServerArgs) -> anyhow::Result<()> {
    tokio::select! {
        result = psy_prover::run_psy_faucet_server(args) => result,
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("psy faucet server shutdown requested");
            Ok(())
        }
    }
}
