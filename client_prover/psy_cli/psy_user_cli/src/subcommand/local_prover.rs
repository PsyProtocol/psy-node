use psy_client_common::args::ProverArgs;

#[allow(dead_code)]
pub async fn run(args: ProverArgs) -> anyhow::Result<()> {
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::select! {
        result = psy_prover::run_server(args) => {
            match result {
                Ok(()) => tracing::warn!("Local prover server exit."),
                Err(e) => tracing::error!("Local prover server exit error: {:?}", e),
            }
        }
        _ = ctrl_c => {
            tracing::warn!("Ctrl-C signal received, cleaning up...");
        }
    }
    Ok(())
}
