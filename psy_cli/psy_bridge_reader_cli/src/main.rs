mod config;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use parking_lot::Mutex;
use psy_bridge_reader_core::admission::Admission;
use psy_bridge_reader_core::follow::run_follow;
use psy_bridge_reader_core::metrics::Metrics;
use psy_bridge_reader_core::model::Model;
use psy_bridge_reader_core::server::{router, ServerState};
use psy_bridge_reader_core::source::PgSource;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;

const LOG_TARGET: &str = "psy_bridge_reader";
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();
    let config = config::Config::parse();
    config.validate().map_err(anyhow::Error::msg)?;
    let budgets = config.budgets().map_err(anyhow::Error::msg)?;
    let follow_config = config.follow_config().map_err(anyhow::Error::msg)?;
    let token = config.read_token().map_err(anyhow::Error::msg)?;
    tracing::info!(target: LOG_TARGET, ?config, "configuration valid");
    let mut terminate = signal(SignalKind::terminate()).context("install the SIGTERM handler")?;
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("bind {}", config.listen))?;

    let metrics = Metrics::new(config.memory_budget_bytes);
    let model = Arc::new(Mutex::new(Model::new()));
    let state = ServerState {
        view: model.lock().view_handle(),
        admission: Arc::new(Admission::new(&budgets)),
        token: Arc::from(token),
        metrics: metrics.clone(),
    };
    let (stop, shutdown) = watch::channel(false);
    let pg_config = config.pg_config();
    let connect = move || {
        let pg_config = pg_config.clone();
        async move { PgSource::connect(&pg_config).await }
    };
    let mut follow = tokio::spawn(run_follow(connect, model, follow_config, metrics, shutdown.clone()));
    let mut server_shutdown = shutdown;
    let serve = axum::serve(listener, router(state)).with_graceful_shutdown(async move {
        let _ = server_shutdown.wait_for(|is_stopping| *is_stopping).await;
    });
    let mut server = tokio::spawn(async move { serve.await });
    tracing::info!(target: LOG_TARGET, listen = %config.listen, "bridge reader started");

    tokio::select! {
        r = tokio::signal::ctrl_c() => r.context("wait for ctrl_c")?,
        _ = terminate.recv() => {}
        r = &mut follow => anyhow::bail!("follow loop stopped before shutdown: {r:?}"),
        r = &mut server => anyhow::bail!("server stopped before shutdown: {r:?}"),
    }
    tracing::info!(target: LOG_TARGET, "shutdown requested");
    stop.send_replace(true);
    match tokio::time::timeout(SHUTDOWN_GRACE, async { (follow.await, server.await) }).await {
        Ok((follow_result, server_result)) => {
            follow_result.context("follow task")?;
            server_result.context("server task")?.context("server")?;
            tracing::info!(target: LOG_TARGET, "bridge reader stopped");
        }
        Err(_) => tracing::warn!(target: LOG_TARGET, grace = ?SHUTDOWN_GRACE, "tasks still running after the shutdown grace; exiting"),
    }
    Ok(())
}
