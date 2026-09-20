use std::{marker::PhantomData, time::SystemTime};

use parth_core::data::queue::queue_key::{
    PCoreQueueItemBase, PCoreSubjectQueueBase, QPBaseQueueType, QPStandardUniqueIdQueueKey,
};
use psy_node_core::queue::{
    ephemeral::{QStandardEphemeralQueuePublisher, QStandardEphemeralQueueSubscriber},
    infrastructure::QStandardQueueBase,
    worker_queue::{QStandardWorkerQueuePublisher, QStandardWorkerQueueSubscriber},
};
use psy_node_nats::{
    psy_queue::setup_nats_psy_queue_from_connection_str,
    queue::{JetStreamAckMode, NatsJetStreamClient, NatsWorkerQueuePublishBarrier},
};

#[derive(Clone, Debug, PartialEq, Eq)]
struct TestJob(u64);

impl PCoreQueueItemBase for TestJob {
    fn is_queue_item(data: &[u8]) -> bool {
        data.len() == 8
    }
    fn decode_queue_item_ref(data: &[u8]) -> anyhow::Result<Self> {
        let bytes: [u8; 8] = data.try_into()?;
        Ok(Self(u64::from_le_bytes(bytes)))
    }
    fn encode_queue_item_vec(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.0.to_le_bytes().to_vec())
    }
    fn get_restorable_job_id(&self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }
    fn get_size_hint() -> usize {
        8
    }
    fn has_fixed_size() -> bool {
        true
    }
}

type EphKey = QPStandardUniqueIdQueueKey<991_338, TestJob>;

fn eph_key(unique_id: u128) -> EphKey {
    EphKey {
        realm_id: 7,
        realm_sub_id: 11,
        unique_id,
        task_group: 0,
        queue_type: QPBaseQueueType::StandardEphemeral,
        _phantom_queue_item: PhantomData,
    }
}

fn nats_url() -> Option<String> {
    std::env::var("NATS_INTEGRATION_URL").ok().filter(|s| !s.is_empty())
}

async fn connect() -> anyhow::Result<(NatsJetStreamClient, u128, EphKey)> {
    let url = nats_url().ok_or_else(|| anyhow::anyhow!("NATS_INTEGRATION_URL unset"))?;
    let suffix = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_nanos();
    let namespace = format!("nats_live_surface_{suffix}");
    let client = setup_nats_psy_queue_from_connection_str(&url, &namespace).await?;
    client.ensure_stream().await?;
    client.ensure_stream().await?;
    let key = eph_key(suffix);
    <NatsJetStreamClient as QStandardQueueBase>::ensure_stream_consumer(
        &client, &key, 7, 11, suffix, 0,
    )
    .await?;
    Ok((client, suffix, key))
}

#[tokio::test]
#[ignore = "Requires isolated NATS_INTEGRATION_URL"]
async fn setup_rejects_unreachable_server() {
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        setup_nats_psy_queue_from_connection_str("nats://127.0.0.1:1", "ns_unreachable"),
    ).await.expect("a refused local connection must fail promptly");
    assert!(result.is_err(), "an unreachable server must not produce a usable client");
}

#[tokio::test]
#[ignore = "Requires isolated NATS_INTEGRATION_URL"]
async fn ephemeral_publish_wait_dump_and_ack_modes() -> anyhow::Result<()> {
    let Some(_) = nats_url() else {
        panic!("NATS_INTEGRATION_URL must identify an isolated test server");
    };
    let (client, unique_id, key) = connect().await?;

    let eph_cfg = client.get_pull_config_for_queue_type(QPBaseQueueType::StandardEphemeral);
    let worker_cfg = client.get_pull_config_for_queue_type(QPBaseQueueType::WorkerQueue);
    assert_ne!(eph_cfg.max_deliver, worker_cfg.max_deliver);

    client
        .wait_until_all_jobs_complete_or_timeout_dq(
            "unused",
            "unused",
            QPBaseQueueType::WorkerQueue,
            &NatsWorkerQueuePublishBarrier::default(),
            50,
        )
        .await?;

    let dumped = client
        .dump_queue_dq_bytes_ephemeral(
            "no.such.subject",
            "missing-durable",
            JetStreamAckMode::AckEach,
            10,
            10,
            None,
            &mut Vec::new(),
        )
        .await?;
    assert_eq!(dumped, 0);
    assert!(client
        .get_message_if_exists_dq_bytes_ephemeral("no.such.subject", "missing-durable", JetStreamAckMode::AckEach)
        .await?
        .is_none());
    assert!(client
        .report_message_completed_dq("no.such.subject", b"nope")
        .await?
        == false);

    <NatsJetStreamClient as QStandardEphemeralQueuePublisher>::publish_ephemeral_queue_item_ref(
        &client, &key, 7, 11, unique_id, 0, &TestJob(1),
    )
    .await?;
    let got = client
        .wait_for_ephemeral_queue_item(&key, 7, 11, unique_id, 0, 2_000)
        .await?
        .expect("ephemeral item");
    assert_eq!(got, TestJob(1));

    client
        .publish_ephemeral_queue_item_owned(&key, 7, 11, unique_id, 0, TestJob(2))
        .await?;
    client
        .publish_many_ephemeral_queue_items(&key, 7, 11, unique_id, 0, &[TestJob(3), TestJob(4)])
        .await?;
    client
        .publish_many_ephemeral_queue_items_owned(&key, 7, 11, unique_id, 0, vec![TestJob(5)])
        .await?;
    let refs = [TestJob(6)];
    client
        .publish_many_ephemeral_queue_items_ref(&key, 7, 11, unique_id, 0, &refs.iter().collect::<Vec<_>>())
        .await?;
    client
        .publish_ephemeral_queue_item_bytes_ref(&key, 7, 11, unique_id, 0, &TestJob(7).encode_queue_item_vec()?)
        .await?;
    client
        .publish_ephemeral_queue_item_owned_bytes(&key, 7, 11, unique_id, 0, TestJob(8).encode_queue_item_vec()?)
        .await?;
    client
        .publish_many_ephemeral_queue_items_bytes_ref(
            &key,
            7,
            11,
            unique_id,
            0,
            &[&TestJob(9).encode_queue_item_vec()?[..]],
        )
        .await?;
    client
        .publish_many_ephemeral_queue_items_owned_bytes(
            &key,
            7,
            11,
            unique_id,
            0,
            vec![TestJob(10).encode_queue_item_vec()?],
        )
        .await?;

    let dumped_items = client
        .dump_entire_ephemeral_queue(&key, 7, 11, unique_id, 0, 100)
        .await?;
    assert_eq!(dumped_items, (2..=10).map(TestJob).collect::<Vec<_>>());

    let none = client
        .wait_for_ephemeral_queue_item_bytes(&key, 7, 11, unique_id, 0, 150)
        .await?;
    assert!(none.is_none());

    let subject = key.get_queue_subject(&client.base_namespace, 7, 11, unique_id, 0);
    let durable = key.get_durable_name(&client.base_namespace, 7, 11, unique_id, 0);

    client
        .push_messages_dq_bytes(&subject, &[b"abcdefgh".as_slice()])
        .await?;
    client
        .push_messages_dq_bytes_vec(&subject, &[b"ijklmnop".to_vec()])
        .await?;
    client
        .push_messages_dq_bytes_sized(&subject, &[[b'z'; 8]])
        .await?;
    client
        .push_message_dq_qi_ref(&subject, &TestJob(21))
        .await?;
    client
        .push_messages_dq_qi(&subject, &[TestJob(22)])
        .await?;
    let job23 = TestJob(23);
    client
        .push_messages_dq_qi_ref(&subject, &[&job23])
        .await?;
    client
        .push_messages_dq_qi_owned(&subject, TestJob(24))
        .await?;

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let mut bytes = Vec::new();
    let n = client
        .dump_queue_dq_bytes_ephemeral(
            &subject,
            &durable,
            JetStreamAckMode::AckEach,
            10,
            3,
            Some(8),
            &mut bytes,
        )
        .await?;
    assert_eq!(n, 3);
    assert_eq!(bytes, vec![b"abcdefgh".to_vec(), b"ijklmnop".to_vec(), vec![b'z'; 8]]);

    let mut bytes = Vec::new();
    client
        .dump_queue_dq_bytes_ephemeral(
            &subject,
            &durable,
            JetStreamAckMode::NoAck,
            10,
            2,
            None,
            &mut bytes,
        )
        .await?;
    assert_eq!(bytes, vec![TestJob(21).encode_queue_item_vec()?, TestJob(22).encode_queue_item_vec()?]);

    let mut bytes = Vec::new();
    client
        .dump_queue_dq_bytes_ephemeral(
            &subject,
            &durable,
            JetStreamAckMode::AckBatchLast,
            10,
            10,
            None,
            &mut bytes,
        )
        .await?;
    assert_eq!(bytes, vec![TestJob(23).encode_queue_item_vec()?, TestJob(24).encode_queue_item_vec()?]);

    let zero = client
        .dump_queue_dq_bytes_ephemeral(
            &subject,
            &durable,
            JetStreamAckMode::AckEach,
            10,
            0,
            None,
            &mut Vec::new(),
        )
        .await?;
    assert_eq!(zero, 0);

    let maybe = client
        .get_message_if_exists_dq_bytes_ephemeral_qi::<TestJob>(
            &subject,
            &durable,
            JetStreamAckMode::AckEach,
        )
        .await?;
    assert_eq!(maybe, None);

    <NatsJetStreamClient as QStandardQueueBase>::recreate_consumer(
        &client, &key, 7, 11, unique_id, 0,
    )
    .await?;
    <NatsJetStreamClient as QStandardQueueBase>::recreate_consumer(
        &client, &key, 7, 11, unique_id, 0,
    )
    .await?;

    Ok(())
}

type WorkerKey = QPStandardUniqueIdQueueKey<991_339, TestJob>;

fn worker_key(unique_id: u128) -> WorkerKey {
    WorkerKey {
        realm_id: 7,
        realm_sub_id: 11,
        unique_id,
        task_group: 0,
        queue_type: QPBaseQueueType::WorkerQueue,
        _phantom_queue_item: PhantomData,
    }
}

#[tokio::test]
#[ignore = "Requires isolated NATS_INTEGRATION_URL"]
async fn worker_dump_kv_timeouts_and_consumers() -> anyhow::Result<()> {
    let Some(_) = nats_url() else {
        panic!("NATS_INTEGRATION_URL must identify an isolated test server");
    };
    let (client, unique_id, eph) = connect().await?;
    let wkey = worker_key(unique_id + 7);
    <NatsJetStreamClient as QStandardQueueBase>::ensure_stream_consumer(
        &client, &wkey, 7, 11, unique_id + 7, 0,
    )
    .await?;

    let empty = client
        .dump_entire_ephemeral_queue(&eph, 7, 11, unique_id, 0, 0)
        .await?;
    assert!(empty.is_empty());
    let empty_w = client
        .dump_entire_worker_queue(&wkey, 7, 11, unique_id + 7, 0, 0)
        .await?;
    assert!(empty_w.is_empty());
    assert!(client
        .wait_for_worker_queue_item(&wkey, 7, 11, unique_id + 7, 0, 120)
        .await?
        .is_none());
    assert!(client
        .get_next_worker_queue_item_or_none(&wkey, 7, 11, unique_id + 7, 0)
        .await?
        .is_none());
    assert!(client
        .consume_ephemeral_queue_item_or_none(&eph, 7, 11, unique_id, 0)
        .await?
        .is_none());
    assert!(client
        .consume_ephemeral_queue_item_or_none_bytes(&eph, 7, 11, unique_id, 0)
        .await?
        .is_none());

    let subject = eph.get_queue_subject(&client.base_namespace, 7, 11, unique_id, 0);
    let durable = eph.get_durable_name(&client.base_namespace, 7, 11, unique_id, 0);
    client
        .ensure_consumer(&subject, &durable, QPBaseQueueType::StandardEphemeral)
        .await?;
    client
        .ensure_consumer(&subject, &durable, QPBaseQueueType::StandardEphemeral)
        .await?;
    client
        .ensure_stream_consumer(&subject, &durable, QPBaseQueueType::StandardEphemeral)
        .await?;

    client
        .publish_ephemeral_queue_item_ref(&eph, 7, 11, unique_id, 0, &TestJob(40))
        .await?;
    let consumed = client
        .consume_ephemeral_queue_item_or_none(&eph, 7, 11, unique_id, 0)
        .await?
        .expect("consumed job");
    assert_eq!(consumed, TestJob(40));
    client
        .publish_ephemeral_queue_item_bytes_ref(&eph, 7, 11, unique_id, 0, &TestJob(41).encode_queue_item_vec()?)
        .await?;
    assert_eq!(client
        .consume_ephemeral_queue_item_or_none_bytes(&eph, 7, 11, unique_id, 0)
        .await?, Some(TestJob(41).encode_queue_item_vec()?));

    for i in 0..8u64 {
        client
            .publish_ephemeral_queue_item_owned(&eph, 7, 11, unique_id, 0, TestJob(100 + i))
            .await?;
    }
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    let dumped_bytes = client
        .dump_entire_ephemeral_queue_bytes(&eph, 7, 11, unique_id, 0, 100)
        .await?;
    assert_eq!(dumped_bytes, (100..108).map(|i| TestJob(i).encode_queue_item_vec().unwrap()).collect::<Vec<_>>());

    let short_id = unique_id + 99;
    let short_key = eph_key(short_id);
    <NatsJetStreamClient as QStandardQueueBase>::ensure_stream_consumer(
        &client, &short_key, 7, 11, short_id, 0,
    )
    .await?;
    let short_subject = short_key.get_queue_subject(&client.base_namespace, 7, 11, short_id, 0);
    let short_durable = short_key.get_durable_name(&client.base_namespace, 7, 11, short_id, 0);
    client
        .push_messages_dq_bytes(&short_subject, &[b"short".as_slice()])
        .await?;
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    let err = client
        .dump_queue_dq_bytes_ephemeral(
            &short_subject,
            &short_durable,
            JetStreamAckMode::AckEach,
            10,
            10,
            Some(8),
            &mut Vec::new(),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("Invalid queue item data length"));

    client
        .publish_ephemeral_queue_item_owned(&eph, 7, 11, unique_id, 0, TestJob(50))
        .await?;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let peeked = client
        .get_message_if_exists_dq_bytes_ephemeral(&subject, &durable, JetStreamAckMode::NoAck)
        .await?;
    assert_eq!(peeked, Some(TestJob(50).encode_queue_item_vec()?));
    client
        .publish_ephemeral_queue_item_owned(&eph, 7, 11, unique_id, 0, TestJob(51))
        .await?;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let peeked_qi = client
        .get_message_if_exists_dq_bytes_ephemeral_qi::<TestJob>(
            &subject,
            &durable,
            JetStreamAckMode::AckEach,
        )
        .await?;
    assert_eq!(peeked_qi, Some(TestJob(51)));

    client
        .delete_ephemeral_queue_consumer(&eph, 7, 11, unique_id, 0)
        .await?;
    client
        .delete_ephemeral_queue_consumer(&eph, 7, 11, unique_id, 0)
        .await?;

    let barrier = client
        .publish_worker_queue_item_ref(&wkey, 7, 11, unique_id + 7, 0, &TestJob(60))
        .await?;
    client
        .publish_many_worker_queue_items(&wkey, 7, 11, unique_id + 7, 0, &[TestJob(61), TestJob(62)])
        .await?;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let dumped = client
        .dump_entire_worker_queue(&wkey, 7, 11, unique_id + 7, 0, 10)
        .await?;
    assert_eq!(dumped, vec![TestJob(60), TestJob(61), TestJob(62)]);
    for job in &dumped {
        assert!(client
            .worker_queue_report_job_completed(&wkey, 7, 11, unique_id + 7, 0, job)
            .await?);
    }

    let wsubject = wkey.get_queue_subject(&client.base_namespace, 7, 11, unique_id + 7, 0);
    let wdurable = wkey.get_durable_name(&client.base_namespace, 7, 11, unique_id + 7, 0);
    let mut batch = Vec::new();
    client.publish_worker_queue_item_owned(&wkey, 7, 11, unique_id + 7, 0, TestJob(65)).await?;
    client
        .dump_queue_dq_qi_batch(&wkey, &wsubject, &wdurable, 10, 10, &mut batch)
        .await?;
    assert_eq!(batch, vec![TestJob(65)]);
    assert!(client.worker_queue_report_job_completed(&wkey, 7, 11, unique_id + 7, 0, &batch[0]).await?);

    let barrier2 = client
        .publish_worker_queue_item_owned(&wkey, 7, 11, unique_id + 7, 0, TestJob(70))
        .await?;
    let timed_out = client
        .wait_until_all_jobs_complete_or_timeout_worker(
            &wkey,
            7,
            11,
            unique_id + 7,
            0,
            &barrier2,
            80,
        )
        .await;
    assert!(timed_out.is_err());
    let got = client
        .wait_for_worker_queue_item(&wkey, 7, 11, unique_id + 7, 0, 2_000)
        .await?
        .expect("worker job");
    assert_eq!(got, TestJob(70));
    assert!(
        client
            .worker_queue_report_job_completed(&wkey, 7, 11, unique_id + 7, 0, &got)
            .await?
    );
    client
        .wait_until_all_jobs_complete_or_timeout_worker(
            &wkey,
            7,
            11,
            unique_id + 7,
            0,
            &barrier2,
            2_000,
        )
        .await?;

    client.wait_until_all_jobs_complete_or_timeout_worker(&wkey, 7, 11, unique_id + 7, 0, &barrier, 2_000).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires isolated NATS_INTEGRATION_URL"]
async fn ack_modes_change_server_pending_state() -> anyhow::Result<()> {
    use std::time::Duration;
    let (client, unique_id, _) = connect().await?;
    for (offset, mode) in [JetStreamAckMode::AckEach, JetStreamAckMode::NoAck, JetStreamAckMode::AckBatchLast].into_iter().enumerate() {
        let id = unique_id + 1000 + offset as u128;
        let key = eph_key(id);
        <NatsJetStreamClient as QStandardQueueBase>::ensure_stream_consumer(&client, &key, 7, 11, id, 0).await?;
        let subject = key.get_queue_subject(&client.base_namespace, 7, 11, id, 0);
        let durable = key.get_durable_name(&client.base_namespace, 7, 11, id, 0);
        let jobs = vec![TestJob(201), TestJob(202), TestJob(203)];
        client.publish_many_ephemeral_queue_items(&key, 7, 11, id, 0, &jobs).await?;
        let mut bytes = Vec::new();
        assert_eq!(client.dump_queue_dq_bytes_ephemeral(&subject, &durable, mode, 3, 3, Some(8), &mut bytes).await?, 3);
        assert_eq!(bytes, jobs.iter().map(|j| j.encode_queue_item_vec().unwrap()).collect::<Vec<_>>());
        let mut consumer = client.jetstream.get_consumer_from_stream::<async_nats::jetstream::consumer::pull::Config, _, _>(&durable, &client.stream_name).await?;
        let expected_unacked = if mode == JetStreamAckMode::NoAck { 3 } else { 0 };
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let info = consumer.info().await?;
                if info.num_pending == 0 && info.num_ack_pending == expected_unacked { break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok::<_, anyhow::Error>(())
        }).await??;

    }
    Ok(())
}

#[tokio::test]
#[ignore = "Requires isolated NATS_INTEGRATION_URL"]
async fn zero_limit_does_not_fetch_or_hide_waiting_messages() -> anyhow::Result<()> {
    let (client, id, key) = connect().await?;
    let subject = key.get_queue_subject(&client.base_namespace, 7, 11, id, 0);
    let durable = key.get_durable_name(&client.base_namespace, 7, 11, id, 0);
    client.publish_ephemeral_queue_item_owned(&key, 7, 11, id, 0, TestJob(91)).await?;
    let mut bytes = Vec::new();
    assert_eq!(client.dump_queue_dq_bytes_ephemeral(&subject, &durable, JetStreamAckMode::AckEach, 10, 0, None, &mut bytes).await?, 0);
    assert!(bytes.is_empty());
    assert_eq!(client.wait_for_ephemeral_queue_item(&key, 7, 11, id, 0, 1000).await?, Some(TestJob(91)));
    client.publish_ephemeral_queue_item_owned(&key, 7, 11, id, 0, TestJob(92)).await?;
    assert_eq!(client.dump_queue_dq_bytes_ephemeral(&subject, &durable, JetStreamAckMode::AckEach, 0, 10, None, &mut bytes).await?, 0);
    let mut jobs = Vec::new();
    client.dump_queue_dq_qi_batch(&key, &subject, &durable, 10, 0, &mut jobs).await?;
    client.dump_queue_dq_qi_batch(&key, &subject, &durable, 0, 10, &mut jobs).await?;
    assert!(jobs.is_empty());
    assert_eq!(client.wait_for_ephemeral_queue_item(&key, 7, 11, id, 0, 1000).await?, Some(TestJob(92)));
    Ok(())
}

#[tokio::test]
#[ignore = "Requires isolated NATS_INTEGRATION_URL"]
async fn worker_unacked_job_redelivers_and_ack_completes_barrier() -> anyhow::Result<()> {
    let (mut client, id, _) = connect().await?;
    // Keep production Explicit ACK / multi-delivery policy; shorten only the timer.
    client.worker_queue_pull_config.ack_wait = std::time::Duration::from_millis(100);
    let key = worker_key(id);
    <NatsJetStreamClient as QStandardQueueBase>::ensure_stream_consumer(&client, &key, 7, 11, id, 0).await?;
    let barrier = client.publish_worker_queue_item_owned(&key, 7, 11, id, 0, TestJob(301)).await?;
    let first = client.wait_for_worker_queue_item(&key, 7, 11, id, 0, 2000).await?;
    assert_eq!(first, Some(TestJob(301)));
    let retried = client.wait_for_worker_queue_item(&key, 7, 11, id, 0, 2000).await?;
    assert_eq!(retried, first, "an unacknowledged worker job must be retried");
    assert!(client.worker_queue_report_job_completed(&key, 7, 11, id, 0, &retried.unwrap()).await?);
    client.wait_until_all_jobs_complete_or_timeout_worker(&key, 7, 11, id, 0, &barrier, 2000).await?;
    Ok(())
}
