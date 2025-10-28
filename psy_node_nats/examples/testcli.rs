use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use async_nats::{
    jetstream::{
        self,
        consumer::{pull::Config as PullConfig, PullConsumer},
        kv::Store,
    },
    Subject, ToServerAddrs,
};
use async_trait::async_trait;
use bytes::Bytes;
use futures::{future::try_join_all, stream::StreamExt};
use parth_core::{
    data::queue::queue_key::{PCoreQueueItemBase, PCoreStandardQueueKeyForRealm, QPBaseQueueType},
    QCoreProcCheckpointUniqueId,
};
use parth_node_nats::queue::NatsJetStreamClient;
use psy_node_core::queue::{
    ephemeral::{QStandardEphemeralQueuePublisher, QStandardEphemeralQueueSubscriber},
    worker_queue::{QStandardWorkerQueuePublisher, QStandardWorkerQueueSubscriber},
};

// **FIX:** main now returns anyhow::Result
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let base_namespace = "EX_JOB_STREAM".to_string();
    let realm_id = 1u64;
    let realm_sub_id = 1u64;
    let ex_queue_type = 1337u32;
    let task_group = 1u64;

    let timeout_ms = 5000u64;
    let standard_ephemeral_queue_pull_config: PullConfig = PullConfig {
        ack_policy: jetstream::consumer::AckPolicy::All,
        ack_wait: Duration::from_millis(timeout_ms),
        max_deliver: 1,
        replay_policy: jetstream::consumer::ReplayPolicy::Instant,
        deliver_policy: jetstream::consumer::DeliverPolicy::All,
        max_ack_pending: 100000,
        ..Default::default()
    };
    let worker_queue_pull_config = PullConfig {
        ack_policy: jetstream::consumer::AckPolicy::Explicit,
        max_deliver: 20,
        replay_policy: jetstream::consumer::ReplayPolicy::Instant,
        deliver_policy: jetstream::consumer::DeliverPolicy::All,
        max_ack_pending: 100000,
        ..Default::default()
    };
    let standard_jet_stream_config = jetstream::stream::Config { ..Default::default() };
    let client = NatsJetStreamClient::new_connection(
        base_namespace,
        "localhost:4222".to_string(),
        standard_ephemeral_queue_pull_config,
        worker_queue_pull_config,
        standard_jet_stream_config,
        timeout_ms,
    )
    .await?;

    Ok(())
}
