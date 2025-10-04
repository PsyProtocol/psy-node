use async_nats::jetstream::{
    self,
    consumer::{PullConsumer, PushConsumer}, message,
};
use bytes::Bytes;
use futures::{StreamExt, stream::FuturesUnordered};
use std::{env, time::{Duration, Instant}};
use tokio::task::JoinSet;

#[tokio::main]
async fn main() -> Result<(), async_nats::Error> {
    let nats_url = env::var("NATS_URL").unwrap_or_else(|_| "nats://localhost:4222".to_string());
    let mut streams = Vec::with_capacity(4);
    for i in 0..=4 {
        let client = async_nats::connect(&nats_url).await?;
        let jetstream = jetstream::new(client);
        let stream_name = String::from(format!("EVENTS-{}", i));
        let consumer: PullConsumer = jetstream
            .create_stream(jetstream::stream::Config {
                name: stream_name,
                subjects: vec![format!("events.{}", i)],
                ..Default::default()
            })
            .await?
            // Then, on that `Stream` use method to create Consumer and bind to it too.
            .create_consumer(jetstream::consumer::pull::Config {
                durable_name: Some(format!("consumer-{}", i)),
            ack_policy: jetstream::consumer::AckPolicy::Explicit,
            ack_wait: Duration::from_millis(1000),
            max_deliver: 20,
            replay_policy: jetstream::consumer::ReplayPolicy::Instant,
            deliver_policy: jetstream::consumer::DeliverPolicy::All,
            max_ack_pending: 100000,
                ..Default::default()
            })
            .await?;

        // Create a stream and a consumer.
        // We can chain the methods.
        // First we create a stream and bind to it.
        streams.push((jetstream, consumer));
    }
    //let stream_name = String::from("EVENTS");

    /*

    */

    let payload = Bytes::from(vec![0; 1000]);

    let mut join_set = JoinSet::new();

    // We'll collect statistics from each task
    let start_time_overall = Instant::now();
    // Spawn a task for each stream to publish messages concurrently
    for (idx, (stream, consumer)) in streams.into_iter().enumerate() {
        join_set.spawn(async move {
            // Statistics collections
            let mut consumer_latencies = Vec::with_capacity(1000);
            let producer_start_time = Instant::now();
            // Track overall timing for producers, consumers are measured per batch
            let mut total_produced = 0;
            let mut total_consumed = 0;
            
            for _ in 0..1000 {
                
                // Consumer measurements
                let consumer_batch_start = Instant::now();
                let mut messages = consumer.batch().max_messages(1000).messages().await.unwrap();
                let mut consumed_count = 0;
                
                let mut idx = 0;
                while let Some(message) = messages.next().await {
                    let message = message.unwrap();
                    // acknowledge the message
                    message.ack().await.unwrap();
                    consumed_count += 1;
                }
                
                let consumer_batch_elapsed = consumer_batch_start.elapsed();
                consumer_latencies.push(consumer_batch_elapsed.as_micros() as u64);
                total_consumed += consumed_count;
                
            }
            
            // Calculate overall stats for this stream
            let total_producer_duration = producer_start_time.elapsed();
            let producer_tput = total_produced as f64 / total_producer_duration.as_secs_f64();
            
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
            (idx, 
             total_produced, producer_mbps, producer_p50_ms, producer_p99_ms,
             total_consumed, consumer_mbps, consumer_p50_ms, consumer_p99_ms)
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
    let messages_per_sec = all_stats.iter().map(|(_, _, _, _, _,
                                total_consumed, _, _, _)| *total_consumed).sum::<usize>() as f64 / overall_duration.as_secs_f64();

    println!("total messages consumed per second: {:.2}", messages_per_sec);
    println!("Overall time taken: {:?}, across {} streams", overall_duration, all_stats.len());
    println!("total messages consumed: {}", all_stats.iter().map(|(_, _, _, _, _,
                                total_consumed, _, _, _)| *total_consumed).sum::<usize>());
    
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

