use anyhow::Result;
use cf_utils::timer::DebugTimer;
use parth_core::data::hash::hash256::Hash256;
use parth_core::data::hash::merkle_node_key::SimpleMerkleNode;
use parth_core::utils::signed_helpers::u64_to_i64_exact;
use parth_core::utils::QPGenRandom;
use parth_node_scylla::utils::{convert_checkpoint_id_to_i64, u8_to_i8_exact};
use scylla::client::session::Session;
use scylla::client::session_builder::SessionBuilder;
use std::env;
use std::sync::Arc;

use tokio::sync::Semaphore;


const fn get_bucket_for_node(_level: u8, node_index: u64) -> i32 {
    // Simple example bucket function: combine level and node_index to create a bucket
    // This is just an example; real implementations may use more complex logic
    (node_index&0xffffu64) as i32
}
#[tokio::main]
async fn main() -> Result<()> {
    let uri = env::var("SCYLLA_URI").unwrap_or_else(|_| "127.0.0.1:9042".to_string());

    println!("Connecting to {uri} ...");

    let session: Session = SessionBuilder::new().known_node(uri).build().await?;
    let session = Arc::new(session);

    let keyspace = format!("examples_ks_{}",rand::random::<u64>());
    let table_name = "zid6_with_bucket";
    session.query_unpaged(format!("CREATE KEYSPACE IF NOT EXISTS {} WITH REPLICATION = {{'class' : 'NetworkTopologyStrategy', 'replication_factor' : 1}}", keyspace), &[]).await?;

    session
        .query_unpaged(
            
                format!(
                    "CREATE TABLE IF NOT EXISTS {}.{} (
                    level TINYINT,
                    bucket INT,
                    node_index BIGINT,
                    checkpoint_id BIGINT,
                    value BLOB,
                    PRIMARY KEY ((level, bucket), node_index, checkpoint_id)
                ) WITH CLUSTERING ORDER BY (node_index ASC, checkpoint_id DESC)",
                    keyspace, table_name
                ),
            &[],
        )
        .await?;
        session.await_schema_agreement().await?;

    let prepared = Arc::new(
        session
            .prepare(format!("INSERT INTO {}.{} (level, bucket, node_index, checkpoint_id, value) VALUES (?, ?, ?, ?, ?)", keyspace, table_name))
            .await?,
    );
    println!("Prepared statement: {prepared:#?}");

    let parallelism = 2048;
    let sem = Arc::new(Semaphore::new(parallelism));
    let mut debug_timer = DebugTimer::new(&format!("scylla_parallel_{}_{}", parallelism, table_name));

    let count = 1_000_000usize;
    debug_timer.event(format!("generating {count} merkle nodes"));
    let nodes = SimpleMerkleNode::<Hash256>::qp_rand_gen_vec(count);
    debug_timer.event(format!("generated {count} merkle nodes"));

    debug_timer.event(format!("inserting {count} rows with parallelism {parallelism}"));


    let checkpoint_id_i64 = convert_checkpoint_id_to_i64(1337);

    for i in 0..count {
        if i % 10000 == 0 {
            println!("{i}");
        }
        let session = session.clone();
        let prepared = prepared.clone();
        let permit = sem.clone().acquire_owned().await;
        let node = nodes[i].clone();
        tokio::task::spawn(async move {
            let level_i8 = u8_to_i8_exact(node.key.level);
            let bucket = get_bucket_for_node(node.key.level, node.key.index);
            let node_index_i64 = u64_to_i64_exact(node.key.index);
            let value = node.value.0;
            session
                .execute_unpaged(&prepared, (level_i8, bucket, node_index_i64, checkpoint_id_i64, value))
                .await
                .unwrap();

            let _permit = permit;
        });
    }

    // Wait for all in-flight requests to finish
    for _ in 0..parallelism {
        sem.acquire().await.unwrap().forget();
    }
    debug_timer.event_batch_item_ref(format!("insert_{count}_with_paralellism_{parallelism}"), "row", count);

    println!("Done.");

    Ok(())
}