use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use parth_node_v1::jobhq::nats::core::{random_job_data, NatsJetStreamClient, QueueJobData};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

use async_nats::jetstream::stream;
use async_nats::Client;

const SERVER_URL: &str = "nats://127.0.0.1:4222";
const BASE_NAMESPACE: &str = "bench";
const TIMEOUT_MS: u64 = 5000;
const REALM_ID: u64 = 1;
const REALM_SUB_ID: u64 = 1;
const QUEUE_TYPE: u32 = 1;
const UNIQUE_TOPIC: u128 = 1;
const TASK_GROUP: u64 = 1;

/// Helper function to set up a clean NatsJetStreamClient for each benchmark run.
/// This ensures that tests are isolated and don't interfere with each other.
/// It creates a new stream and purges any existing messages.
async fn setup_client_async() -> NatsJetStreamClient {
    let client = NatsJetStreamClient::new_connection(
        BASE_NAMESPACE.to_string(),
        SERVER_URL.to_string(),
        10_000, // 10-second timeout for jobs in benchmark
    )
    .await
    .expect("Failed to connect to NATS");
    let subject = client.get_queue_subject (REALM_ID, REALM_SUB_ID, QUEUE_TYPE, UNIQUE_TOPIC, TASK_GROUP);

    // To ensure a clean slate, we try to delete the stream first.
    // This is useful when running benchmarks multiple times.
    let stream_name = format!("{}_stream", BASE_NAMESPACE.replace('.', "_"));
    let _ = client.jetstream.delete_stream(&stream_name).await;

    // We must ensure the stream and a base consumer exist for the operations.
    client.ensure_stream().await.expect("Failed to ensure stream");

    let durable_name = subject.replace('.', "_");
    client
        .ensure_consumer(&subject, &durable_name)
        .await
        .expect("Failed to ensure consumer");
    
    // Purge the stream to make sure we start with an empty queue
    let stream = client.jetstream.get_stream(&stream_name).await.unwrap();
    stream.purge().await.unwrap();


    client
}

fn setup_client(rt: &tokio::runtime::Runtime) -> NatsJetStreamClient {
    rt.block_on(setup_client_async())
}

pub fn client_push_throughput(c: &mut Criterion) {
    let counts = [1000u64, 10000u64, 50000u64];
    let mut group = c.benchmark_group("client::push_throughput");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));

    for &count in counts.iter() {
        group.throughput(Throughput::Elements(count));
        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &count,
            |b, &count| {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let client = setup_client(&rt);
                let client = Arc::new(client);

                b.to_async(rt)
                    .iter_with_large_drop(move || {
                        let client = client.clone();
                        let data: Vec<QueueJobData> =
                            (0..count).map(|_| random_job_data()).collect();
                        async move {
                            client
                                .push_messages(
                                    REALM_ID,
                                    REALM_SUB_ID,
                                    QUEUE_TYPE,
                                    UNIQUE_TOPIC,
                                    TASK_GROUP,
                                    &data,
                                )
                                .await
                                .unwrap();
                        }
                    });
            },
        );
    }
    group.finish();
}

pub fn client_ack_throughput(c: &mut Criterion) {
    let counts = [1000u64, 10000u64, 50000u64];
    let mut group = c.benchmark_group("client::ack_throughput");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));

    for &count in counts.iter() {
        group.throughput(Throughput::Elements(count));
        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &count,
            |b, &count| {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let client = setup_client(&rt);
                let client = Arc::new(client);

                b.to_async(rt)
                    .iter_with_large_drop(move || {
                        let client = client.clone();
                        let data: Vec<QueueJobData> =
                            (0..count).map(|_| random_job_data()).collect();
                        async move {
                            // Push to populate queue and KV (via simulated fetch below)
                            client
                                .push_messages(
                                    REALM_ID,
                                    REALM_SUB_ID,
                                    QUEUE_TYPE,
                                    UNIQUE_TOPIC,
                                    TASK_GROUP,
                                    &data,
                                )
                                .await
                                .unwrap();

                            // Simulate fetches to populate KV with replies
                            for &job in &data {
                                let _ = client
                                    .get_message_if_exists(
                                        REALM_ID,
                                        REALM_SUB_ID,
                                        QUEUE_TYPE,
                                        UNIQUE_TOPIC,
                                        TASK_GROUP,
                                    )
                                    .await;
                            }

                            // Now ack all
                            for &job in &data {
                                client
                                    .report_message_completed(
                                        REALM_ID,
                                        REALM_SUB_ID,
                                        QUEUE_TYPE,
                                        UNIQUE_TOPIC,
                                        TASK_GROUP,
                                        job,
                                    )
                                    .await
                                    .unwrap();
                            }
                        }
                    });
            },
        );
    }
    group.finish();
}

pub fn client_poll_empty_throughput(c: &mut Criterion) {
    let poll_counts = [1000u64, 10000u64, 50000u64];
    let mut group = c.benchmark_group("client::poll_empty_throughput");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));

    for &poll_count in poll_counts.iter() {
        group.throughput(Throughput::Elements(poll_count));
        group.bench_with_input(
            BenchmarkId::from_parameter(poll_count),
            &poll_count,
            |b, &poll_count| {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let client = setup_client(&rt);
                let client = Arc::new(client);

                b.to_async(rt)
                    .iter_with_large_drop(move || {
                        let client = client.clone();
                        async move {
                            for _ in 0..poll_count {
                                let _ = client
                                    .get_message_if_exists(
                                        REALM_ID,
                                        REALM_SUB_ID,
                                        QUEUE_TYPE,
                                        UNIQUE_TOPIC,
                                        TASK_GROUP,
                                    )
                                    .await;
                            }
                        }
                    });
            },
        );
    }
    group.finish();
}

pub fn client_concurrent_poll(c: &mut Criterion) {
    let num_workers = [50usize, 200usize, 500usize]; // Simulate varying worker concurrency
    let polls_per_worker = 100u64;
    let mut group = c.benchmark_group("client::concurrent_poll");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));

    for &workers in num_workers.iter() {
        let total_polls = polls_per_worker * workers as u64;
        group.throughput(Throughput::Elements(total_polls));
        group.bench_with_input(
            BenchmarkId::from_parameter(workers),
            &workers,
            |b, &workers| {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let client = setup_client(&rt);
                let client = Arc::new(client);

                b.to_async(rt)
                    .iter_with_large_drop(move || {
                        let client = client.clone();
                        async move {
                            let mut handles = vec![];
                            for _ in 0..workers {
                                let client = client.clone();
                                let handle = tokio::spawn(async move {
                                    for _ in 0..polls_per_worker {
                                        let _ = client
                                            .get_message_if_exists(
                                                REALM_ID,
                                                REALM_SUB_ID,
                                                QUEUE_TYPE,
                                                UNIQUE_TOPIC,
                                                TASK_GROUP,
                                            )
                                            .await;
                                    }
                                });
                                handles.push(handle);
                            }
                            for handle in handles {
                                handle.await.unwrap();
                            }
                        }
                    });
            },
        );
    }
    group.finish();
}

pub fn client_wait_completion(c: &mut Criterion) {
    let counts = [1000u64, 10000u64, 50000u64];
    let mut group = c.benchmark_group("client::wait_completion");
    group.sample_size(5); // Fewer samples due to higher variance with simulated delays
    group.warm_up_time(Duration::from_secs(2));
    group.measurement_time(Duration::from_secs(10));

    for &count in counts.iter() {
        group.throughput(Throughput::Elements(count));
        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &count,
            |b, &count| {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let client = setup_client(&rt);
                let client = Arc::new(client);

                b.to_async(rt)
                    .iter_with_large_drop(move || {
                        let client = client.clone();
                        let data: Vec<QueueJobData> =
                            (0..count).map(|_| random_job_data()).collect();
                        async move {
                            // Push jobs
                            client
                                .push_messages(
                                    REALM_ID,
                                    REALM_SUB_ID,
                                    QUEUE_TYPE,
                                    UNIQUE_TOPIC,
                                    TASK_GROUP,
                                    &data,
                                )
                                .await
                                .unwrap();

                            // Simulate concurrent fetches to populate KV and "assign" jobs
                            let mut fetch_handles = vec![];
                            for chunk in data.chunks(100) { // Batch to simulate distribution
                                let client_chunk = client.clone();
                                let chunk_data: Vec<QueueJobData> = chunk.to_vec();
                                let handle = tokio::spawn(async move {
                                    for &job in &chunk_data {
                                        // get_message_if_exists consumes one, but since batched, approximate
                                        let _ = client_chunk
                                            .get_message_if_exists(
                                                REALM_ID,
                                                REALM_SUB_ID,
                                                QUEUE_TYPE,
                                                UNIQUE_TOPIC,
                                                TASK_GROUP,
                                            )
                                            .await;
                                    }
                                });
                                fetch_handles.push(handle);
                            }
                            for handle in fetch_handles {
                                handle.await.unwrap();
                            }

                            // Simulate worker processing delay (3-4 seconds) before acks
                            // Spawn delayed ack tasks to simulate real-world async completion
                            let mut ack_handles = vec![];
                            for &job in &data {
                                let client_ack = client.clone();
                                let ack_handle = tokio::spawn(async move {
                                    sleep(Duration::from_secs(3)).await; // Simulate 3s job time
                                    client_ack
                                        .report_message_completed(
                                            REALM_ID,
                                            REALM_SUB_ID,
                                            QUEUE_TYPE,
                                            UNIQUE_TOPIC,
                                            TASK_GROUP,
                                            job,
                                        )
                                        .await
                                        .unwrap();
                                });
                                ack_handles.push(ack_handle);
                            }

                            // Start wait immediately after pushes and fetches
                            let wait_handle = tokio::spawn({
                                let client_wait = client.clone();
                                async move {
                                    client_wait
                                        .wait_until_all_jobs_complete_or_timeout(
                                            REALM_ID,
                                            REALM_SUB_ID,
                                            QUEUE_TYPE,
                                            UNIQUE_TOPIC,
                                            TASK_GROUP,
                                        )
                                        .await
                                        .unwrap();
                                }
                            });

                            // Wait for all acks to complete
                            for handle in ack_handles {
                                handle.await.unwrap();
                            }

                            // Wait for the wait to finish
                            wait_handle.await.unwrap();
                        }
                    });
            },
        );
    }
    group.finish();
}