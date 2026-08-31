use std::{marker::PhantomData, time::SystemTime};

use parth_core::data::queue::queue_key::{
    PCoreQueueItemBase, QPBaseQueueType, QPStandardUniqueIdQueueKey,
};
use psy_node_core::queue::{
    infrastructure::QStandardQueueBase,
    worker_queue::{QStandardWorkerQueuePublisher, QStandardWorkerQueueSubscriber},
};
use psy_node_nats::{
    psy_queue::{setup_nats_psy_queue_from_connection_str, NatsSetupMode},
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

type TestQueueKey = QPStandardUniqueIdQueueKey<991_337, TestJob>;

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
    let client = setup_nats_psy_queue_from_connection_str(&nats_url, &namespace, NatsSetupMode::CreateIfMissing).await?;
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
