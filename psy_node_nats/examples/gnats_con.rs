use std::{
    env,
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
use bytes::Bytes;
use futures::{stream::FuturesUnordered, StreamExt};
use parth_core::data::queue::queue_key::{PCoreSubjectQueueBase, QPBaseQueueType, QPStandardUniqueIdQueueKey};
use parth_node_nats::queue::{JetStreamAckMode, NatsJetStreamClient};
use psy_core::job::job_id::QProvingJobDataID;
use tokio::task::JoinSet;

type QueueKey = QPStandardUniqueIdQueueKey<1, QProvingJobDataID>;
#[tokio::main]
async fn main() -> Result<(), async_nats::Error> {
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
    let mut streams = Vec::with_capacity(4);
    let unique_id = 12u128;

    let qk = QueueKey {
        realm_id,
        realm_sub_id,
        unique_id: 12u128,
        task_group,
        queue_type: QPBaseQueueType::StandardEphemeral,
        _phantom_queue_item: std::marker::PhantomData,
    };
    let subject = qk.get_queue_subject(&base_namespace, realm_id, realm_sub_id, unique_id, task_group as u32);
    let durable_name = qk.get_durable_name(&base_namespace, realm_id, realm_sub_id, unique_id, task_group as u32);

    for i in 0..=4 {
        let client = NatsJetStreamClient::new_connection(
            base_namespace.clone(),
            "localhost:4222".to_string(),
            standard_ephemeral_queue_pull_config.clone(),
            worker_queue_pull_config.clone(),
            standard_jet_stream_config.clone(),
            timeout_ms,
        )
        .await?;

        client
            .ensure_stream_consumer(&subject, &durable_name, QPBaseQueueType::StandardEphemeral)
            .await?;

        // Create a stream and a consumer.
        // We can chain the methods.
        // First we create a stream and bind to it.
        streams.push(client);
    }
    //let stream_name = String::from("EVENTS");

    /*

    */

    let payload = Bytes::from(vec![0; 1000]);

    let mut join_set = JoinSet::new();

    // We'll collect statistics from each task
    let start_time_overall = Instant::now();
    // Spawn a task for each stream to publish messages concurrently
    for (idx, client) in streams.into_iter().enumerate() {
        let subject = subject.clone();
        let durable_name = durable_name.clone();
        join_set.spawn(async move {
            // Statistics collections
            let mut consumer_latencies = Vec::with_capacity(1000);
            let producer_start_time = Instant::now();
            // Track overall timing for producers, consumers are measured per batch
            let mut total_consumed = 0;

            for _ in 0..1000 {
                // Consumer measurements
                let consumer_batch_start = Instant::now();
                let mut output_vec: Vec<Vec<u8>> = Vec::with_capacity(10000);
                client
                    .dump_queue_dq_bytes_ephemeral(
                        &subject,
                        &durable_name,
                        JetStreamAckMode::AckBatchLast,
                        1000,
                        100000,
                        None,
                        &mut output_vec,
                    )
                    .await
                    .unwrap();

                let consumed_count = output_vec.len();
                let consumer_batch_elapsed = consumer_batch_start.elapsed();
                consumer_latencies.push(consumer_batch_elapsed.as_micros() as u64);
                total_consumed += consumed_count;
            }

            // Calculate overall stats for this stream
            let total_producer_duration = producer_start_time.elapsed();
            let producer_tput = total_consumed as f64 / total_producer_duration.as_secs_f64();

            // Sort latencies for percentile calculation
            consumer_latencies.sort_unstable();

            // Calculate percentiles
            let producer_p50 = 0;
            let producer_p99 = 0;

            let consumer_p50 = if !consumer_latencies.is_empty() {
                consumer_latencies[consumer_latencies.len() / 2]
            } else {
                0
            };

            let consumer_p99 = if !consumer_latencies.is_empty() {
                consumer_latencies[(consumer_latencies.len() * 99) / 100]
            } else {
                0
            };

            // Convert throughput to MBps (assuming 1KB payload)
            let producer_mbps = producer_tput * 1000.0 / (1024.0 * 1024.0); // 1000 bytes per message / (1024*1024) for MB
            let consumer_mbps = producer_tput * 1000.0 / (1024.0 * 1024.0);

            // Convert latencies from microseconds to milliseconds
            let producer_p50_ms = producer_p50 as f64 / 1000.0;
            let producer_p99_ms = producer_p99 as f64 / 1000.0;
            let consumer_p50_ms = consumer_p50 as f64 / 1000.0;
            let consumer_p99_ms = consumer_p99 as f64 / 1000.0;

            // Return the stats for this stream
            (
                idx,
                total_consumed,
                producer_mbps,
                producer_p50_ms,
                producer_p99_ms,
                total_consumed,
                consumer_mbps,
                consumer_p50_ms,
                consumer_p99_ms,
            )
        });
    }

    // Wait for all publishing tasks to complete and collect statistics
    let mut all_stats = Vec::new();
    while let Some(result) = join_set.join_next().await {
        match result {
            Ok(stats) => {
                let (idx, total_produced, producer_tput, producer_p50, producer_p99, total_consumed, consumer_tput, consumer_p50, consumer_p99) =
                    stats;
                println!("Stream {} completed", idx);
                all_stats.push((
                    idx,
                    total_produced,
                    producer_tput,
                    producer_p50,
                    producer_p99,
                    total_consumed,
                    consumer_tput,
                    consumer_p50,
                    consumer_p99,
                ));
            }
            Err(e) => eprintln!("A stream task failed: {}", e),
        }
    }
    let end_time_overall = Instant::now();
    let overall_duration = end_time_overall.duration_since(start_time_overall);
    let messages_per_sec = all_stats
        .iter()
        .map(|(_, _, _, _, _, total_consumed, _, _, _)| *total_consumed)
        .sum::<usize>() as f64
        / overall_duration.as_secs_f64();

    println!("total messages consumed per second: {:.2}", messages_per_sec);
    println!("Overall time taken: {:?}, across {} streams", overall_duration, all_stats.len());
    println!(
        "total messages consumed: {}",
        all_stats
            .iter()
            .map(|(_, _, _, _, _, total_consumed, _, _, _)| *total_consumed)
            .sum::<usize>()
    );

    // Print summary statistics
    println!("\n===== BENCHMARK RESULTS =====");
    println!("Stream | Produced | Producer Throughput | P50 Latency (ms) | P99 Latency (ms) | Consumed | Consumer Throughput | P50 Latency (ms) | P99 Latency (ms)");
    println!("       |          |       (MB/s)       |                  |                  |          |       (MB/s)       |                  |                  ");
    println!("-------|----------|-------------------|-----------------|-----------------|----------|-------------------|-----------------|------------------");

    let mut total_producer_throughput = 0.0;
    let mut total_consumer_throughput = 0.0;
    let mut max_producer_p99 = 0.0;
    let mut max_consumer_p99 = 0.0;

    for (idx, total_produced, producer_mbps, producer_p50_ms, producer_p99_ms, total_consumed, consumer_mbps, consumer_p50_ms, consumer_p99_ms) in
        all_stats
    {
        println!(
            "{:6} | {:8} | {:17.2} | {:16.2} | {:16.2} | {:8} | {:17.2} | {:16.2} | {:16.2}",
            idx, total_produced, producer_mbps, producer_p50_ms, producer_p99_ms, total_consumed, consumer_mbps, consumer_p50_ms, consumer_p99_ms
        );

        total_producer_throughput += producer_mbps;
        total_consumer_throughput += consumer_mbps;
        max_producer_p99 = f64::max(max_producer_p99, producer_p99_ms);
        max_consumer_p99 = f64::max(max_consumer_p99, consumer_p99_ms);
    }

    println!("-------|----------|-------------------|-----------------|-----------------|----------|-------------------|-----------------|------------------");
    println!(
        "TOTAL  |          | {:17.2} |                  | {:16.2} |          | {:17.2} |                  | {:16.2}",
        total_producer_throughput, max_producer_p99, total_consumer_throughput, max_consumer_p99
    );
    println!("========================================");

    Ok(())
}
