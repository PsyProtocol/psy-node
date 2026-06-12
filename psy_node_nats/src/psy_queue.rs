

use std::{env, time::Duration};

use async_nats::
    jetstream::{
        self,
        consumer::pull::Config as PullConfig,
    }
;
use crate::queue::NatsJetStreamClient;

fn env_u64_ms(name: &str, default_value: u64) -> anyhow::Result<u64> {
    match env::var(name) {
        Ok(value) => value.parse::<u64>().map_err(|err| {
            anyhow::anyhow!(
                "invalid {} value {:?}; expected milliseconds as u64: {}",
                name,
                value,
                err
            )
        }),
        Err(env::VarError::NotPresent) => Ok(default_value),
        Err(err) => Err(anyhow::anyhow!("failed to read {}: {}", name, err)),
    }
}

pub async fn setup_nats_psy_queue_from_connection_str(
    connection_str: &str,
    base_namespace: &str,
) -> anyhow::Result<NatsJetStreamClient> {

    if connection_str.is_empty() {
        anyhow::bail!("Scylla Connection string is empty");
    }
    let addresses = connection_str.split(",").map(|s| s.to_string()).collect::<Vec<String>>();

    let ephemeral_timeout_ms = env_u64_ms("NATS_EPHEMERAL_ACK_WAIT_MS", 5000)?;
    let ephemeral_inactive_threshold_ms = env_u64_ms("NATS_EPHEMERAL_INACTIVE_THRESHOLD_MS", 600_000)?;
    let standard_ephemeral_queue_pull_config: PullConfig = PullConfig {
        ack_policy: jetstream::consumer::AckPolicy::All,
        ack_wait: Duration::from_millis(ephemeral_timeout_ms),
        inactive_threshold: Duration::from_millis(ephemeral_inactive_threshold_ms),
        max_deliver: 1,
        replay_policy: jetstream::consumer::ReplayPolicy::Instant,
        deliver_policy: jetstream::consumer::DeliverPolicy::All,
        max_ack_pending: 100000,
        ..Default::default()
    };
    let worker_timeout_ms = env_u64_ms("NATS_WORKER_ACK_WAIT_MS", 30000)?;
    let worker_inactive_threshold_ms = env_u64_ms("NATS_WORKER_INACTIVE_THRESHOLD_MS", 3_600_000)?;
    let worker_queue_pull_config = PullConfig {
        ack_policy: jetstream::consumer::AckPolicy::Explicit,
        ack_wait: Duration::from_millis(worker_timeout_ms),
        inactive_threshold: Duration::from_millis(worker_inactive_threshold_ms),
        max_deliver: 2400,
        replay_policy: jetstream::consumer::ReplayPolicy::Instant,
        deliver_policy: jetstream::consumer::DeliverPolicy::All,
        max_ack_pending: 100000,
        ..Default::default()
    };
    let standard_jet_stream_config = jetstream::stream::Config { ..Default::default() };
    let client = NatsJetStreamClient::new_connection(
        base_namespace.to_string(),
        addresses,
        standard_ephemeral_queue_pull_config,
        worker_queue_pull_config,
        standard_jet_stream_config,
    )
    .await?;

    Ok(client)

}
