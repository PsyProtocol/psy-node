use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use parth_node_v1::jobhq::nats::core::{random_job_data, NatsJetStreamClient, QueueJobData};
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;

// Assuming your client code is in a library crate.
// Replace `your_crate_name` with the actual name of your crate.

// --- Configuration ---
const NATS_URL: &str = "nats://127.0.0.1:4222";
const BASE_NAMESPACE: &str = "benchmark.qp_network";

/// Helper function to set up a clean NatsJetStreamClient for each benchmark run.
/// This ensures that tests are isolated and don't interfere with each other.
/// It creates a new stream and purges any existing messages.
async fn setup_client_for_benchmark(subject: &str) -> NatsJetStreamClient {
    let client = NatsJetStreamClient::new_connection(
        BASE_NAMESPACE.to_string(),
        NATS_URL.to_string(),
        10_000, // 10-second timeout for jobs in benchmark
    )
    .await
    .expect("Failed to connect to NATS");

    // To ensure a clean slate, we try to delete the stream first.
    // This is useful when running benchmarks multiple times.
    let stream_name = format!("{}_stream", BASE_NAMESPACE.replace('.', "_"));
    let _ = client.jetstream.delete_stream(&stream_name).await;

    // We must ensure the stream and a base consumer exist for the operations.
    client.ensure_stream().await.expect("Failed to ensure stream");

    let durable_name = subject.replace('.', "_");
    client
        .ensure_consumer(subject, &durable_name)
        .await
        .expect("Failed to ensure consumer");
    
    // Purge the stream to make sure we start with an empty queue
    let stream = client.jetstream.get_stream(&stream_name).await.unwrap();
    stream.purge().await.unwrap();


    client
}

/// ## Benchmark 1: `push_messages_dq` Throughput
///
/// This benchmark measures the raw publishing speed of your `push_messages_dq` function.
/// It is designed to simulate the Realm Processor publishing a large number of jobs
/// for the workers at the beginning of each checkpoint.
///
/// It is parameterized by the number of messages pushed in a single call to understand
/// how batching affects performance.
pub fn bench_push_messages(c: &mut Criterion) {
    let mut group = c.benchmark_group("NatsJetStreamClient::push_messages_dq");

    let rt = Runtime::new().unwrap();

    // We test with different batch sizes to see how performance scales.
    for size in [100, 1_000, 10_000].iter() {
        let subject = "benchmark.push";
        let data: Vec<QueueJobData> = (0..*size).map(|_| random_job_data()).collect();

        // This tells criterion to report the results in "elements/second".
        group.throughput(Throughput::Elements(*size as u64));

        group.bench_with_input(criterion::BenchmarkId::from_parameter(size), size, |b, &s| {
            // A fresh client is created for each sample to ensure isolation.
            let client = rt.block_on(async {
                setup_client_for_benchmark(subject).await
            });
            let data_slice = &data[..s];

            b.to_async(&rt).iter(|| async {
                client.push_messages_dq(subject, data_slice).await.unwrap();
            });
        });
    }
    group.finish();
}

/// ## Benchmark 2: End-to-End Job Processing
///
/// This is the most critical benchmark as it simulates the entire application workflow:
/// 1. A batch of jobs is published.
/// 2. A pool of concurrent "workers" fetches jobs using `get_message_if_exists_dq`.
/// 3. Each worker simulates doing work by sleeping for a short period. **This delay is crucial**
///    as it models the real-world scenario where jobs are not acknowledged instantly, leading
///    to a high number of `ack_pending` messages in JetStream.
/// 4. After the delay, the worker calls `report_message_completed_dq` to acknowledge the job.
/// 5. The benchmark measures the total time taken to process the entire batch of jobs.
///
/// This test will reveal how well your system handles high concurrency and delayed ACKs,
/// which is a core requirement of your architecture.
pub fn bench_end_to_end_processing(c: &mut Criterion) {
    let mut group = c.benchmark_group("NatsJetStreamClient::EndToEnd_Processing");
    // This is a slow, complex test, so we take fewer samples.
    group.sample_size(10);

    let rt = Runtime::new().unwrap();
    let subject = "benchmark.e2e_processing";
    
    // NOTE: This delay simulates worker processing time. In a real scenario, this might be
    // 3-4 seconds. For a benchmark that runs in a reasonable time, we use a shorter
    // duration. You can increase this to better match your production environment.
    let job_simulation_delay = Duration::from_millis(200);

    // We parameterize the benchmark by the number of jobs and the number of concurrent workers.
    for &(num_messages, num_workers) in [(1000, 100), (5000, 500)].iter() {
        group.throughput(Throughput::Elements(num_messages as u64));
        let benchmark_id = format!("{}_messages_{}_workers", num_messages, num_workers);

        group.bench_with_input(
            criterion::BenchmarkId::new("Full_Workflow", benchmark_id),
            &(num_messages, num_workers),
            |b, &(messages_count, worker_count)| {
                // `iter_custom` is used for complex async scenarios where setup should
                // not be part of the measurement.
                b.to_async(&rt).iter_custom(|iters| async move {
                    let mut total_duration = Duration::new(0, 0);
                    for _ in 0..iters {
                        // --- Setup (not measured) ---
                        let client = setup_client_for_benchmark(subject).await;
                        let data: Vec<QueueJobData> =
                            (0..messages_count).map(|_| random_job_data()).collect();
                        client.push_messages_dq(subject, &data).await.unwrap();
                        let client = Arc::new(client);

                        // --- Measurement starts here ---
                        let start = std::time::Instant::now();

                        let mut worker_handles = Vec::new();
                        for _ in 0..worker_count {
                            let worker_client = client.clone();
                            let handle = tokio::spawn(async move {
                                // Each worker continuously polls for jobs until the stream is empty.
                                while let Ok(Some(job_data)) =
                                    worker_client.get_message_if_exists_dq(subject).await
                                {
                                    // 2. Simulate doing work.
                                    tokio::time::sleep(job_simulation_delay).await;
                                    // 3. Report completion, which sends the ACK.
                                    worker_client
                                        .report_message_completed_dq(subject, job_data)
                                        .await
                                        .unwrap();
                                }
                            });
                            worker_handles.push(handle);
                        }

                        // Wait for all worker tasks to complete.
                        futures::future::join_all(worker_handles).await;

                        // As a final check (mirroring the Realm Processor), wait until the
                        // consumer confirms there are no more pending or unacknowledged messages.
                        client
                            .wait_until_all_jobs_complete_or_timeout_dq(subject)
                            .await
                            .unwrap();
                        
                        total_duration += start.elapsed();
                        // --- Measurement ends here ---
                    }
                    total_duration
                });
            },
        );
    }
    group.finish();
}

/// ## Benchmark 3: `wait_until_all_jobs_complete_or_timeout_dq` Overhead
///
/// This benchmark measures the performance of the waiting logic itself.
/// It calls `wait_until_all_jobs_complete_or_timeout_dq` on an already empty queue.
/// This tells you the baseline overhead of checking the consumer state, which is useful
/// for understanding the cost of the final check in the Realm Processor's logic.
pub fn bench_wait_until_complete(c: &mut Criterion) {
    let mut group = c.benchmark_group("NatsJetStreamClient::wait_until_all_jobs_complete_or_timeout_dq");
    let rt = Runtime::new().unwrap();
    let subject = "benchmark.wait";

    group.bench_function("On_Empty_Queue", |b| {
        let client = rt.block_on(async {
            setup_client_for_benchmark(subject).await
        });

        // The benchmark repeatedly calls the function to measure its latency.
        b.to_async(&rt).iter(|| async {
            client
                .wait_until_all_jobs_complete_or_timeout_dq(subject)
                .await
                .unwrap();
        });
    });

    group.finish();
}
