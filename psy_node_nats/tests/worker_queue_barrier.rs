use std::{marker::PhantomData, time::{Duration, SystemTime}};

use parth_core::data::queue::queue_key::{
    PCoreQueueItemBase, PCoreSubjectQueueBase, QPBaseQueueType, QPStandardUniqueIdQueueKey,
};
use psy_node_core::queue::{
    infrastructure::QStandardQueueBase,
    worker_queue::{QStandardWorkerQueuePublisher, QStandardWorkerQueueSubscriber},
};
use psy_node_nats::{
    psy_queue::setup_nats_psy_queue_from_connection_str,
    queue::{NatsJetStreamClient, NatsWorkerQueuePublishBarrier},
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

#[tokio::test]
#[ignore = "requires an isolated JetStream server at NATS_INTEGRATION_URL"]
async fn pending_consumers_survive_idle_and_upgrade_without_losing_ack_state() -> anyhow::Result<()> {
    let url = std::env::var("NATS_INTEGRATION_URL")?;
    let id = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_nanos();
    let mut client = setup_nats_psy_queue_from_connection_str(&url, &format!("lifetime_{id}")).await?;
    assert_eq!(client.standard_ephemeral_queue_pull_config.inactive_threshold, Duration::ZERO);
    assert_eq!(client.worker_queue_pull_config.inactive_threshold, Duration::ZERO);
    assert_eq!(client.worker_queue_pull_config.max_deliver, -1);
    client.ensure_stream().await?;

    // Seed the old policy, including the cached handle. Use a short lease to
    // reproduce a long operator repair without an hour-long test.
    client.worker_queue_pull_config.inactive_threshold = Duration::from_secs(2);
    client.worker_queue_pull_config.ack_wait = Duration::from_millis(100);
    client.worker_queue_pull_config.max_deliver = 2;
    let key = queue_key(id);
    let durable = key.get_durable_name(&client.base_namespace, 7, 11, id, 0);
    <NatsJetStreamClient as QStandardQueueBase>::ensure_consumer(&client, &key, 7, 11, id, 0).await?;
    let barrier = client.publish_many_worker_queue_items_owned(&key, 7, 11, id, 0,
        vec![TestJob(1), TestJob(2)]).await?;
    consume_and_ack(&client, &key, id, &[TestJob(1)]).await?;
    let failed_job = client.wait_for_worker_queue_item(&key, 7, 11, id, 0, 2_000).await?.unwrap();
    assert_eq!(failed_job, TestJob(2));
    // The failed job deliberately does not ACK. Upgrade before the old delivery
    // cap is exhausted; changing MaxDeliver cannot revive already exhausted jobs.
    let before = client.jetstream.get_consumer_from_stream::<async_nats::jetstream::consumer::pull::Config, _, _>(
        &durable, &client.stream_name).await?.get_info().await?;
    assert_eq!(before.ack_floor.stream_sequence, barrier.max_stream_sequence().unwrap() - 1);

    client.worker_queue_pull_config.inactive_threshold = Duration::ZERO;
    client.worker_queue_pull_config.max_deliver = -1;
    <NatsJetStreamClient as QStandardQueueBase>::ensure_consumer(&client, &key, 7, 11, id, 0).await?;
    let after = client.jetstream.get_consumer_from_stream::<async_nats::jetstream::consumer::pull::Config, _, _>(
        &durable, &client.stream_name).await?.get_info().await?;
    assert_eq!(before.created, after.created);
    assert_eq!(before.ack_floor, after.ack_floor);
    assert_eq!(before.delivered, after.delivered);
    assert_eq!(after.config.inactive_threshold, Duration::ZERO);
    assert_eq!(after.config.max_deliver, -1);

    // Fail repeatedly beyond the previous cap, without publishing a replacement.
    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert_eq!(client.wait_for_worker_queue_item(&key, 7, 11, id, 0, 2_000).await?, Some(TestJob(2)));
    }

    let future_key = queue_key(id + 1);
    <NatsJetStreamClient as QStandardQueueBase>::ensure_consumer(&client, &future_key, 7, 11, id + 1, 0).await?;
    let mut gathering_key = queue_key(id + 2);
    gathering_key.queue_type = QPBaseQueueType::StandardEphemeral;
    <NatsJetStreamClient as QStandardQueueBase>::ensure_consumer(&client, &gathering_key, 7, 11, id + 2, 0).await?;
    // No keepalive, consumer info polling, or worker fetches during the repair.
    tokio::time::sleep(Duration::from_secs(3)).await;
    consume_and_ack(&client, &key, id, &[TestJob(2)]).await?;
    client.wait_until_all_jobs_complete_or_timeout_worker(&key, 7, 11, id, 0, &barrier, 2_000).await?;

    // The pre-created successor consumer must still exist when its turn arrives.
    let next = client.publish_worker_queue_item_owned(&future_key, 7, 11, id + 1, 0, TestJob(3)).await?;
    consume_and_ack(&client, &future_key, id + 1, &[TestJob(3)]).await?;
    client.wait_until_all_jobs_complete_or_timeout_worker(&future_key, 7, 11, id + 1, 0, &next, 2_000).await?;
    let gathering_durable = gathering_key.get_durable_name(&client.base_namespace, 7, 11, id + 2, 0);
    client.jetstream.get_consumer_from_stream::<async_nats::jetstream::consumer::pull::Config, _, _>(
        &gathering_durable, &client.stream_name).await?;

    client.delete_worker_queue_consumer(&key, 7, 11, id, 0).await?;
    assert!(client.jetstream.get_consumer_from_stream::<async_nats::jetstream::consumer::pull::Config, _, _>(
        &durable, &client.stream_name).await.is_err());
    // A missing consumer still cannot be mistaken for a completed publication.
    assert!(client.wait_until_all_jobs_complete_or_timeout_worker(&key, 7, 11, id, 0, &barrier, 100).await.is_err());
    client.jetstream.delete_stream(&client.stream_name).await?;
    client.jetstream.delete_key_value(format!("{}_kv", client.base_namespace)).await?;
    Ok(())
}

type TestQueueKey = QPStandardUniqueIdQueueKey<991_337, TestJob>;

#[tokio::test]
#[ignore = "requires an isolated JetStream server at NATS_INTEGRATION_URL"]
async fn ensure_handles_cold_cache_and_missing_cached_consumer() -> anyhow::Result<()> {
    let url = std::env::var("NATS_INTEGRATION_URL")?;
    let id = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_nanos();
    let namespace = format!("ensure_lifetime_{id}");
    let mut old_client = setup_nats_psy_queue_from_connection_str(&url, &namespace).await?;
    old_client.standard_ephemeral_queue_pull_config.inactive_threshold = Duration::from_secs(2);
    old_client.ensure_stream().await?;
    let mut key = queue_key(id);
    key.queue_type = QPBaseQueueType::StandardEphemeral;
    let durable = key.get_durable_name(&namespace, 7, 11, id, 0);
    <NatsJetStreamClient as QStandardQueueBase>::ensure_consumer(&old_client, &key, 7, 11, id, 0).await?;
    let before = old_client.jetstream.get_consumer_from_stream::<async_nats::jetstream::consumer::pull::Config, _, _>(
        &durable, &old_client.stream_name).await?.get_info().await?;
    let client = setup_nats_psy_queue_from_connection_str(&url, &namespace).await?;
    <NatsJetStreamClient as QStandardQueueBase>::ensure_consumer(&client, &key, 7, 11, id, 0).await?;
    let after = client.jetstream.get_consumer_from_stream::<async_nats::jetstream::consumer::pull::Config, _, _>(
        &durable, &client.stream_name).await?.get_info().await?;
    assert_eq!(before.created, after.created);
    assert_eq!(after.config.inactive_threshold, Duration::ZERO);

    // Model deletion before any work is published. The generic Processor entry
    // must not report success just because its local cache contains a handle.
    client.jetstream.delete_consumer_from_stream(&durable, &client.stream_name).await?;
    <NatsJetStreamClient as QStandardQueueBase>::ensure_consumer(&client, &key, 7, 11, id, 0).await?;
    let replacement = client.jetstream.get_consumer_from_stream::<async_nats::jetstream::consumer::pull::Config, _, _>(
        &durable, &client.stream_name).await?.get_info().await?;
    assert_ne!(before.created, replacement.created);
    assert_eq!(replacement.config.inactive_threshold, Duration::ZERO);
    client.jetstream.delete_stream(&client.stream_name).await?;
    client.jetstream.delete_key_value(format!("{namespace}_kv")).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated NATS_INTEGRATION_URL and REDIS_INTEGRATION_URL"]
async fn witness_repair_resumes_dependency_pipeline_without_republishing_jobs() -> anyhow::Result<()> {
    use parth_core::{QJobIdSerialized, QJOB_ID_SERIALIZED_SIZE};
    use psy_node_core::store::traits::{
        proof_store::{QParthProofStoreReader, QParthProofStoreWriter},
        temp_db::{QTempDatabaseRawKVReaderBase, QTempDatabaseRawKVWriterBase},
    };
    use psy_node_redis::store::{new_redis_async_pool, StandardRedisStore};

    // This tests the real storage/transport adapters and dependency order, not
    // cryptography or the full Processor. Proof payloads below are test doubles.
    let url = std::env::var("NATS_INTEGRATION_URL")?;
    let redis_url = std::env::var("REDIS_INTEGRATION_URL")?;
    let id = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_nanos();
    let namespace = format!("witness_repair_{id}");
    let mut client = setup_nats_psy_queue_from_connection_str(&url, &namespace).await?;
    client.worker_queue_pull_config.ack_wait = Duration::from_millis(100);
    client.ensure_stream().await?;
    let store = StandardRedisStore::new(new_redis_async_pool(&redis_url, 2).await?, namespace, 7, 11);
    let key = queue_key(id);
    let next_key = queue_key(id + 1);
    <NatsJetStreamClient as QStandardQueueBase>::ensure_consumer(&client, &key, 7, 11, id, 0).await?;
    <NatsJetStreamClient as QStandardQueueBase>::ensure_consumer(&client, &next_key, 7, 11, id + 1, 0).await?;
    let proof_a: QJobIdSerialized = [1; QJOB_ID_SERIALIZED_SIZE];
    let proof_b: QJobIdSerialized = [2; QJOB_ID_SERIALIZED_SIZE];
    let proof_parent: QJobIdSerialized = [3; QJOB_ID_SERIALIZED_SIZE];
    let pending_id = 71;
    store.qtdb_raw_kv_put_value(b"witness-b", b"invalid").await?;
    let children = client.publish_many_worker_queue_items_owned(&key, 7, 11, id, 0,
        vec![TestJob(1), TestJob(2)]).await?;
    assert_eq!(client.wait_for_worker_queue_item(&key, 7, 11, id, 0, 2_000).await?, Some(TestJob(1)));
    store.put_proof_bytes_for_job_id(proof_a, pending_id, b"verified-child-a").await?;
    assert!(client.worker_queue_report_job_completed(&key, 7, 11, id, 0, &TestJob(1)).await?);
    for _ in 0..3 {
        assert_eq!(client.wait_for_worker_queue_item(&key, 7, 11, id, 0, 2_000).await?, Some(TestJob(2)));
        assert_eq!(store.qtdb_raw_kv_get_value(b"witness-b").await?, Some(b"invalid".to_vec()));
        // Failed proving does not store output and does not ACK.
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    assert!(client.wait_until_all_jobs_complete_or_timeout_worker(&key, 7, 11, id, 0, &children, 50).await.is_err());
    assert!(!store.contains_proof_for_job_id(proof_b, pending_id).await?);
    assert!(!store.contains_proof_for_job_id(proof_parent, pending_id).await?);
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Operator repairs just the witness. Same client, same consumer, same job,
    // no Processor restart, queue recreation, or replay of successful work.
    store.qtdb_raw_kv_put_value(b"witness-b", b"corrected").await?;
    assert_eq!(client.wait_for_worker_queue_item(&key, 7, 11, id, 0, 2_000).await?, Some(TestJob(2)));
    assert_eq!(store.qtdb_raw_kv_get_value(b"witness-b").await?, Some(b"corrected".to_vec()));
    assert_eq!(store.get_proof_bytes_by_job_id(proof_a, pending_id).await?, Some(b"verified-child-a".to_vec()));
    store.put_proof_bytes_for_job_id(proof_b, pending_id, b"verified-child-b").await?;
    assert!(client.worker_queue_report_job_completed(&key, 7, 11, id, 0, &TestJob(2)).await?);
    client.wait_until_all_jobs_complete_or_timeout_worker(&key, 7, 11, id, 0, &children, 2_000).await?;
    let mut stream = client.jetstream.get_stream(&client.stream_name).await?;
    assert_eq!(stream.info().await?.state.messages, 2, "repair must not republish successful or failed jobs");

    let parent = client.publish_worker_queue_item_owned(&key, 7, 11, id, 0, TestJob(3)).await?;
    assert_eq!(client.wait_for_worker_queue_item(&key, 7, 11, id, 0, 2_000).await?, Some(TestJob(3)));
    assert!(store.contains_proof_for_job_id(proof_a, pending_id).await?);
    assert!(store.contains_proof_for_job_id(proof_b, pending_id).await?);
    store.put_proof_bytes_for_job_id(proof_parent, pending_id, b"verified-parent").await?;
    assert!(client.worker_queue_report_job_completed(&key, 7, 11, id, 0, &TestJob(3)).await?);
    client.wait_until_all_jobs_complete_or_timeout_worker(&key, 7, 11, id, 0, &parent, 2_000).await?;

    let next = client.publish_worker_queue_item_owned(&next_key, 7, 11, id + 1, 0, TestJob(4)).await?;
    consume_and_ack(&client, &next_key, id + 1, &[TestJob(4)]).await?;
    client.wait_until_all_jobs_complete_or_timeout_worker(&next_key, 7, 11, id + 1, 0, &next, 2_000).await?;
    store.delete_all_proofs_for_pending_id(pending_id).await?;
    store.qtdb_raw_kv_delete_key(b"witness-b").await?;
    client.delete_worker_queue_consumer(&key, 7, 11, id, 0).await?;
    client.delete_worker_queue_consumer(&next_key, 7, 11, id + 1, 0).await?;
    client.jetstream.delete_stream(&client.stream_name).await?;
    client.jetstream.delete_key_value(format!("{}_kv", client.base_namespace)).await?;
    Ok(())
}

fn queue_key(unique_id: u128) -> TestQueueKey {
    TestQueueKey {
        realm_id: 7,
        realm_sub_id: 11,
        unique_id,
        task_group: 0,
        queue_type: QPBaseQueueType::WorkerQueue,
        _phantom_queue_item: PhantomData,
    }
}

async fn consume_and_ack(
    client: &NatsJetStreamClient,
    key: &TestQueueKey,
    unique_id: u128,
    expected: &[TestJob],
) -> anyhow::Result<()> {
    for expected_job in expected {
        let job = client
            .wait_for_worker_queue_item(key, 7, 11, unique_id, 0, 2_000)
            .await?
            .ok_or_else(|| anyhow::anyhow!("worker did not receive expected job"))?;
        anyhow::ensure!(&job == expected_job, "worker received unexpected job");
        anyhow::ensure!(
            client
                .worker_queue_report_job_completed(key, 7, 11, unique_id, 0, &job)
                .await?,
            "worker job ACK could not be reported"
        );
    }
    Ok(())
}

fn assert_next_barrier(
    barrier: &NatsWorkerQueuePublishBarrier,
    expected_count: usize,
    previous_max: &mut u64,
) {
    assert_eq!(barrier.message_count(), expected_count);
    let max = barrier
        .max_stream_sequence()
        .expect("non-empty publication must have a stream sequence");
    assert!(max > *previous_max);
    *previous_max = max;
}

#[tokio::test]
async fn all_publish_forms_ack_and_completion_tracks_their_barrier() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .try_init();
    let Ok(nats_url) = std::env::var("NATS_INTEGRATION_URL") else {
        eprintln!("skipping: NATS_INTEGRATION_URL is not set");
        return Ok(());
    };

    let suffix = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_nanos();
    let namespace = format!("worker_barrier_test_{suffix}");
    let client = setup_nats_psy_queue_from_connection_str(&nats_url, &namespace).await?;
    client.ensure_stream().await?;

    let unique_id = suffix;
    let key = queue_key(unique_id);
    <NatsJetStreamClient as QStandardQueueBase>::ensure_consumer(
        &client, &key, 7, 11, unique_id, 0,
    )
    .await?;

    let mut previous_max = 0;

    let job1 = TestJob(1);
    let barrier = client
        .publish_worker_queue_item_ref(&key, 7, 11, unique_id, 0, &job1)
        .await?;
    assert_next_barrier(&barrier, 1, &mut previous_max);
    assert!(client
        .wait_until_all_jobs_complete_or_timeout_worker(
            &key, 7, 11, unique_id, 0, &barrier, 50,
        )
        .await
        .is_err());
    let fetched = client
        .wait_for_worker_queue_item(&key, 7, 11, unique_id, 0, 2_000)
        .await?
        .expect("single ref job should be delivered");
    assert_eq!(fetched, job1);
    assert!(client
        .wait_until_all_jobs_complete_or_timeout_worker(
            &key, 7, 11, unique_id, 0, &barrier, 50,
        )
        .await
        .is_err());
    assert!(client
        .worker_queue_report_job_completed(&key, 7, 11, unique_id, 0, &fetched)
        .await?);
    client
        .wait_until_all_jobs_complete_or_timeout_worker(
            &key, 7, 11, unique_id, 0, &barrier, 2_000,
        )
        .await?;

    let refs = [TestJob(2), TestJob(3)];
    let ref_items = refs.iter().collect::<Vec<_>>();
    let barrier = client
        .publish_many_worker_queue_items_ref(&key, 7, 11, unique_id, 0, &ref_items)
        .await?;
    assert_next_barrier(&barrier, 2, &mut previous_max);
    consume_and_ack(&client, &key, unique_id, &refs).await?;
    client
        .wait_until_all_jobs_complete_or_timeout_worker(
            &key, 7, 11, unique_id, 0, &barrier, 2_000,
        )
        .await?;

    let owned = TestJob(4);
    let barrier = client
        .publish_worker_queue_item_owned(&key, 7, 11, unique_id, 0, owned.clone())
        .await?;
    assert_next_barrier(&barrier, 1, &mut previous_max);
    consume_and_ack(&client, &key, unique_id, &[owned]).await?;
    client
        .wait_until_all_jobs_complete_or_timeout_worker(
            &key, 7, 11, unique_id, 0, &barrier, 2_000,
        )
        .await?;

    let owned_batch = vec![TestJob(5), TestJob(6)];
    let barrier = client
        .publish_many_worker_queue_items_owned(
            &key,
            7,
            11,
            unique_id,
            0,
            owned_batch.clone(),
        )
        .await?;
    assert_next_barrier(&barrier, 2, &mut previous_max);
    consume_and_ack(&client, &key, unique_id, &owned_batch).await?;
    client
        .wait_until_all_jobs_complete_or_timeout_worker(
            &key, 7, 11, unique_id, 0, &barrier, 2_000,
        )
        .await?;

    let batch = [TestJob(7), TestJob(8)];
    let barrier = client
        .publish_many_worker_queue_items(&key, 7, 11, unique_id, 0, &batch)
        .await?;
    assert_next_barrier(&barrier, 2, &mut previous_max);
    consume_and_ack(&client, &key, unique_id, &batch).await?;
    client
        .wait_until_all_jobs_complete_or_timeout_worker(
            &key, 7, 11, unique_id, 0, &barrier, 2_000,
        )
        .await?;

    let missing_consumer_id = unique_id + 1;
    let missing_consumer_key = queue_key(missing_consumer_id);
    let barrier = client
        .publish_worker_queue_item_ref(
            &missing_consumer_key,
            7,
            11,
            missing_consumer_id,
            0,
            &TestJob(9),
        )
        .await?;
    assert!(client
        .wait_until_all_jobs_complete_or_timeout_worker(
            &missing_consumer_key,
            7,
            11,
            missing_consumer_id,
            0,
            &barrier,
            100,
        )
        .await
        .is_err());

    client
        .delete_worker_queue_consumer(&key, 7, 11, unique_id, 0)
        .await?;
    Ok(())
}
