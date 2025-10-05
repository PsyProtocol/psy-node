use async_nats::jetstream::{
    self,
    consumer::{PullConsumer, PushConsumer},
};
use bytes::Bytes;
use futures::{StreamExt, stream::FuturesUnordered};
use parth_node_v1::jobhq::nats::core::{random_job_data, NatsJetStreamClient};
use std::{env, time::{Duration, Instant}};
use tokio::task::JoinSet;

#[tokio::main]
async fn main() -> Result<(), async_nats::Error> {
    let nats_url = "nats://localhost:4222".to_string();
    let base_namespace = "EX_JOB_STREAM".to_string();
    let timeout_ms = 20000;
    let realm_id = 1u64;
    let realm_sub_id = 1u64;
    let ex_queue_type = 1337u32;
    let task_group = 1u64;
    let unique_topic = 123u128;
    let mut streams = Vec::with_capacity(4);
    for i in 0..=4 {
        let client = NatsJetStreamClient::new_connection(base_namespace.clone(), nats_url.clone(), timeout_ms).await?;
        let subject = client.get_queue_subject(realm_id, realm_sub_id, ex_queue_type, unique_topic, task_group);
        client.ensure_stream_consumer(&subject).await?;



        // Create a stream and a consumer.
        // We can chain the methods.
        // First we create a stream and bind to it.
        streams.push(client);
    }
    /*

    */

    let payload = Bytes::from(vec![0; 1000]);

    let mut join_set = JoinSet::new();


    let start_time_overall = Instant::now();


    // We'll collect statistics from each task
    
    // Spawn a task for each stream to publish messages concurrently
    for (idx, stream) in streams.into_iter().enumerate() {
        join_set.spawn(async move {
            // Statistics collections
            let mut producer_latencies = Vec::with_capacity(1000 * 1000);
            let producer_start_time = Instant::now();
            // Track overall timing for producers, consumers are measured per batch
            let mut total_produced = 0;
            
            for _ in 0..1000 {
                let random_job_data: [[u8; 24]; 1000] = core::array::from_fn(|_| random_job_data());
                let msg_start = Instant::now();
                stream.push_messages(realm_id, realm_sub_id, ex_queue_type, unique_topic, task_group, &random_job_data).await.unwrap();
                let batch_elapsed = msg_start.elapsed();
                total_produced += random_job_data.len();
                producer_latencies.push(batch_elapsed.as_micros() as u64);
                
                
                // Consumer measurements
                
            }
            
            // Calculate overall stats for this stream
            let total_producer_duration = producer_start_time.elapsed();
            let producer_tput = total_produced as f64 / total_producer_duration.as_secs_f64();
            
            // Sort latencies for percentile calculation
            producer_latencies.sort_unstable();
            
            // Calculate percentiles
            let producer_p50 = producer_latencies[producer_latencies.len() / 2];
            let producer_p99 = producer_latencies[(producer_latencies.len() * 99) / 100];
            
            let consumer_p50 = 0;
            
            let consumer_p99 = 0;
            
            // Convert throughput to MBps (assuming 1KB payload)
            let producer_mbps = producer_tput * 1000.0 / (1024.0 * 1024.0); // 1000 bytes per message / (1024*1024) for MB
            let consumer_mbps = producer_tput * 1000.0 / (1024.0 * 1024.0);
            
            // Convert latencies from microseconds to milliseconds
            let producer_p50_ms = producer_p50 as f64 / 1000.0;
            let producer_p99_ms = producer_p99 as f64 / 1000.0;
            let consumer_p50_ms = consumer_p50 as f64 / 1000.0;
            let consumer_p99_ms = consumer_p99 as f64 / 1000.0;
            
            // Return the stats for this stream
            (idx, 
             total_produced, producer_mbps, producer_p50_ms, producer_p99_ms,
             0, consumer_mbps, consumer_p50_ms, consumer_p99_ms)
        });
    }

    // Wait for all publishing tasks to complete and collect statistics
    let mut all_stats = Vec::new();
    while let Some(result) = join_set.join_next().await {
        match result {
            Ok(stats) => {
                let (idx, total_produced, producer_tput, producer_p50, producer_p99,
                     total_consumed, consumer_tput, consumer_p50, consumer_p99) = stats;
                println!("Stream {} completed", idx);
                all_stats.push((idx, total_produced, producer_tput, producer_p50, producer_p99,
                                total_consumed, consumer_tput, consumer_p50, consumer_p99));
            },
            Err(e) => eprintln!("A stream task failed: {}", e),
        }
    }

    let end_time_overall = Instant::now();
    let overall_duration = end_time_overall.duration_since(start_time_overall);
    println!("Overall time taken: {:?}, across {} streams", overall_duration, all_stats.len());
    let messages_per_sec = all_stats.iter().map(|(_, produced, _, _, _, _, _, _, _)| *produced).sum::<usize>() as f64 / overall_duration.as_secs_f64();
    println!("Overall throughput: {:.2} tx/sec", messages_per_sec); 
    
    // Print summary statistics
    println!("\n===== BENCHMARK RESULTS =====");
    println!("Stream | Produced | Producer Throughput | P50 Latency (ms) | P99 Latency (ms) | Consumed | Consumer Throughput | P50 Latency (ms) | P99 Latency (ms)");
    println!("       |          |       (MB/s)       |                  |                  |          |       (MB/s)       |                  |                  ");
    println!("-------|----------|-------------------|-----------------|-----------------|----------|-------------------|-----------------|------------------");
    
    let mut total_producer_throughput = 0.0;
    let mut total_consumer_throughput = 0.0;
    let mut max_producer_p99 = 0.0;
    let mut max_consumer_p99 = 0.0;
    
    for (idx, total_produced, producer_mbps, producer_p50_ms, producer_p99_ms,
         total_consumed, consumer_mbps, consumer_p50_ms, consumer_p99_ms) in all_stats {
        println!("{:6} | {:8} | {:17.2} | {:16.2} | {:16.2} | {:8} | {:17.2} | {:16.2} | {:16.2}",
                idx, total_produced, producer_mbps, producer_p50_ms, producer_p99_ms,
                total_consumed, consumer_mbps, consumer_p50_ms, consumer_p99_ms);
                
        total_producer_throughput += producer_mbps;
        total_consumer_throughput += consumer_mbps;
        max_producer_p99 = f64::max(max_producer_p99, producer_p99_ms);
        max_consumer_p99 = f64::max(max_consumer_p99, consumer_p99_ms);
    }
    
    println!("-------|----------|-------------------|-----------------|-----------------|----------|-------------------|-----------------|------------------");
    println!("TOTAL  |          | {:17.2} |                  | {:16.2} |          | {:17.2} |                  | {:16.2}",
            total_producer_throughput, max_producer_p99, total_consumer_throughput, max_consumer_p99);
    println!("========================================");

    Ok(())
}

