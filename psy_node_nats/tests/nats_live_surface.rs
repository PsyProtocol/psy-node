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
    )
    .await;
    match result {
        Err(_) => {}
        Ok(Err(_)) => {}
        Ok(Ok(_)) => panic!("expected connection to unused port to fail"),
    }
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
    assert!(dumped_items.len() >= 8, "got {:?}", dumped_items);

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
    assert_eq!(n, bytes.len());
    assert!(n > 0);

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
    let _ = maybe;

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
    assert!(client
        .consume_ephemeral_queue_item_or_none_bytes(&eph, 7, 11, unique_id, 0)
        .await?
        .is_some());

    for i in 0..8u64 {
        client
            .publish_ephemeral_queue_item_owned(&eph, 7, 11, unique_id, 0, TestJob(100 + i))
            .await?;
    }
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    let dumped_bytes = client
        .dump_entire_ephemeral_queue_bytes(&eph, 7, 11, unique_id, 0, 100)
        .await?;
    let _ = dumped_bytes;

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
    assert!(peeked.is_some());
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
    assert!(peeked_qi.is_some());

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
    assert!(dumped.len() >= 1, "worker dump got {:?}", dumped);
    for job in &dumped {
        let _ = client
            .worker_queue_report_job_completed(&wkey, 7, 11, unique_id + 7, 0, job)
            .await?;
    }

    let wsubject = wkey.get_queue_subject(&client.base_namespace, 7, 11, unique_id + 7, 0);
    let wdurable = wkey.get_durable_name(&client.base_namespace, 7, 11, unique_id + 7, 0);
    let mut batch = Vec::new();
    client
        .dump_queue_dq_qi_batch(&wkey, &wsubject, &wdurable, 10, 10, &mut batch)
        .await?;

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

    let _ = barrier;
    Ok(())
}
