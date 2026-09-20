

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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn env_u64_ms_uses_default_when_unset() {
        let name = "PSY_NATS_TEST_UNSET_MS_A1B2";
        std::env::remove_var(name);
        assert_eq!(env_u64_ms(name, 5000).unwrap(), 5000);
    }

    #[test]
    fn env_u64_ms_parses_valid_value() {
        let name = "PSY_NATS_TEST_SET_MS_C3D4";
        std::env::set_var(name, "1234");
        let got = env_u64_ms(name, 1).unwrap();
        std::env::remove_var(name);
        assert_eq!(got, 1234);
    }

    #[test]
    fn env_u64_ms_rejects_non_integer() {
        let name = "PSY_NATS_TEST_BAD_MS_E5F6";
        std::env::set_var(name, "not-a-number");
        let err = env_u64_ms(name, 1).unwrap_err();
        std::env::remove_var(name);
        assert!(err.to_string().contains(name));
    }

    #[tokio::test]
    async fn setup_rejects_empty_connection_string() {
        let result = setup_nats_psy_queue_from_connection_str("", "ns").await;
        assert!(result.is_err());
        if let Err(err) = result {
            assert!(err.to_string().contains("empty"));
        }
    }
}
