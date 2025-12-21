

use std::time::Duration;

use async_nats::
    jetstream::{
        self,
        consumer::pull::Config as PullConfig,
    }
;
use crate::queue::NatsJetStreamClient;

pub async fn setup_nats_psy_queue_from_connection_str(
    connection_str: &str,
    base_namespace: &str,
) -> anyhow::Result<NatsJetStreamClient> {

    if connection_str.is_empty() {
        anyhow::bail!("Scylla Connection string is empty");
    }
    let addresses = connection_str.split(",").map(|s| s.to_string()).collect::<Vec<String>>();

    let ephemeral_timeout_ms = 5000u64;
    let standard_ephemeral_queue_pull_config: PullConfig = PullConfig {
        ack_policy: jetstream::consumer::AckPolicy::All,
        ack_wait: Duration::from_millis(ephemeral_timeout_ms),
        max_deliver: 1,
        replay_policy: jetstream::consumer::ReplayPolicy::Instant,
        deliver_policy: jetstream::consumer::DeliverPolicy::All,
        max_ack_pending: 100000,
        ..Default::default()
    };
    let worker_timeout_ms = 3000u64;
    let worker_queue_pull_config = PullConfig {
        ack_policy: jetstream::consumer::AckPolicy::Explicit,
        ack_wait: Duration::from_millis(worker_timeout_ms),
        max_deliver: 20,
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
