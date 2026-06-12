use psy_client_common::args::ProveProxyArgs;

pub async fn run(args: ProveProxyArgs) -> anyhow::Result<()> {
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::select! {
        result = psy_prover::run_prove_proxy_server(args) => result,
        _ = ctrl_c => {
            tracing::warn!("Ctrl-C signal received, cleaning up...");
            Ok(())
        }
    }
}
