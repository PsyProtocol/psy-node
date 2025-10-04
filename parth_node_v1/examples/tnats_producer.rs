use async_nats::jetstream::{
    self,
    consumer::{PullConsumer, PushConsumer},
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
        // Create a stream and a consumer.
        // We can chain the methods.
        // First we create a stream and bind to it.
        streams.push(jetstream);
    }
    //let stream_name = String::from("EVENTS");

    /*

    */

    let payload = Bytes::from(vec![0; 1000]);

    let mut join_set = JoinSet::new();


    let start_time_overall = Instant::now();


    // We'll collect statistics from each task
    
    // Spawn a task for each stream to publish messages concurrently
    for (idx, stream) in streams.into_iter().enumerate() {
        let stream_payload = payload.clone();
        join_set.spawn(async move {
            // Statistics collections
            let mut producer_latencies = Vec::with_capacity(1000 * 1000);
            let producer_start_time = Instant::now();
            // Track overall timing for producers, consumers are measured per batch
            let mut total_produced = 0;
            
            for _ in 0..1000 {
                let msg_start = Instant::now();
                for i in 0..1000 {
                    let res = stream
                        .publish(format!("events.{}", idx), stream_payload.clone())
                        .await
                        .unwrap();
                    
                    if i == 999 {
                        // Get acknowledgment for the last message in each batch
                        res.await.unwrap();
                    }
                    
                    total_produced += 1;
                }
                let batch_elapsed = msg_start.elapsed();
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
    println!("Overall throughput: {:.2} messages/sec", messages_per_sec); 
    
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

