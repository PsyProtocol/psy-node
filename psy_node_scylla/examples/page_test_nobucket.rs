use anyhow::Result;
use cf_utils::timer::DebugTimer;
use futures::StreamExt;
use parth_core::data::hash::hash256::Hash256;
use parth_core::data::hash::merkle_node_key::SimpleMerkleNode;
use parth_core::protocol::core_types::Q256BitHash;
use parth_core::utils::signed_helpers::{i64_to_u64_exact, u64_to_i64_exact};
use parth_core::utils::QPGenRandom;
use parth_node_scylla::utils::{convert_checkpoint_id_to_i64, i8_to_u8_exact};
use scylla::client::session::Session;
use scylla::client::session_builder::SessionBuilder;
use scylla::response::PagingState;
use scylla::statement::Statement;
use std::collections::HashMap;
use std::env;
use std::ops::ControlFlow;
use std::sync::Arc;

use tokio::sync::Semaphore;


const fn _get_bucket_for_node(_level: u8, node_index: u64) -> i32 {
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
    let table_name = "zid6_nobucket";
    session.query_unpaged(format!("CREATE KEYSPACE IF NOT EXISTS {} WITH REPLICATION = {{'class' : 'NetworkTopologyStrategy', 'replication_factor' : 1}}", keyspace), &[]).await?;

    session
        .query_unpaged(
            
                format!(
                    "CREATE TABLE IF NOT EXISTS {}.{} (
                    level TINYINT,
                    node_index BIGINT,
                    checkpoint_id BIGINT,
                    value BLOB,
                    PRIMARY KEY ((level), node_index, checkpoint_id)
                ) WITH CLUSTERING ORDER BY (node_index ASC, checkpoint_id DESC)",
                    keyspace, table_name
                ),
            &[],
        )
        .await?;
        session.await_schema_agreement().await?;

    let prepared = Arc::new(
        session
            .prepare(format!("INSERT INTO {}.{} (level, node_index, checkpoint_id, value) VALUES (?, ?, ?, ?)", keyspace, table_name))
            .await?,
    );
    println!("Prepared statement: {prepared:#?}");

    let parallelism = 2048;
    let sem = Arc::new(Semaphore::new(parallelism));
    let mut debug_timer = DebugTimer::new(&format!("scylla_parallel_{}_{}", parallelism, table_name));

    let count = 16777216usize;
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
            let level_i8 = 31i8 + (i&1) as i8; // simulate lots of leaf nodes
            //let bucket = get_bucket_for_node(node.key.level, node.key.index);
            let node_index_i64 = u64_to_i64_exact(node.key.index);
            let value = node.value.0;
            session
                .execute_unpaged(&prepared, (level_i8, node_index_i64, checkpoint_id_i64, value))
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




    // Iterate through select result with paging
    let mut rows_stream = session
        .query_iter(format!("SELECT level, node_index, value FROM {}.{}", keyspace, table_name), &[])
        .await?
        .rows_stream::<(i8, i64, Vec<u8>)>()?;

        let mut ctr = 0;
    let mut results = Vec::with_capacity(count);

    while let Some(next_row_res) = rows_stream.next().await {
        let (level_i8, index_i64, data) = next_row_res?;
        results.push(SimpleMerkleNode::new(i8_to_u8_exact(level_i8), i64_to_u64_exact(index_i64), Hash256::from_owned_32bytes(data.try_into().unwrap())));

        // Process each row
        ctr+=1;
    }
    debug_timer.event_batch(format!("read_{}",ctr), "row".to_string(), ctr);


    // Iterate through select result with paging
    let mut rows_stream = session
        .query_iter(format!("SELECT level, node_index, checkpoint_id, value FROM {}.{}", keyspace, table_name), &[])
        .await?
        .rows_stream::<(i8, i64, i64, Vec<u8>)>()?;

        let mut ctr = 0;
    let mut results = Vec::with_capacity(count);

    let mut seen_node_at_checkpoint_id_i64 = HashMap::<(i8,i64), i64>::new();
    let max_checkpoint_id_i64 = convert_checkpoint_id_to_i64(133799);

    while let Some(next_row_res) = rows_stream.next().await {
        let (level_i8, index_i64, g_checkpoint_id_i64, data) = next_row_res?;
        if level_i8 != 32 || g_checkpoint_id_i64 > max_checkpoint_id_i64 || g_checkpoint_id_i64 < *seen_node_at_checkpoint_id_i64.get(&(level_i8,index_i64)).unwrap_or(&i64::MIN) {
            continue;
        }
        seen_node_at_checkpoint_id_i64.insert((level_i8,index_i64), g_checkpoint_id_i64);
        results.push(SimpleMerkleNode::new(i8_to_u8_exact(level_i8), i64_to_u64_exact(index_i64), Hash256::from_owned_32bytes(data.try_into().unwrap())));

        // Process each row
        ctr+=1;
    }
    debug_timer.event_batch(format!("read_w_chkid_{}",ctr), "row".to_string(), ctr);



    // Iterate through select result with paging
    let mut rows_stream = session
        .query_iter(format!("SELECT level, node_index, value FROM {}.{} WHERE level = ? ALLOW FILTERING", keyspace, table_name), (32i8,))
        .await?
        .rows_stream::<(i8, i64, Vec<u8>)>()?;

        let mut ctr = 0;
    let mut results = Vec::with_capacity(count);

    while let Some(next_row_res) = rows_stream.next().await {
        let (level_i8, index_i64, data) = next_row_res?;
        results.push(SimpleMerkleNode::new(i8_to_u8_exact(level_i8), i64_to_u64_exact(index_i64), Hash256::from_owned_32bytes(data.try_into().unwrap())));

        // Process each row
        ctr+=1;
    }
    debug_timer.event_batch(format!("read_where_level_eq_{}",ctr), "row".to_string(), ctr);




    let paged_prepared = Arc::new(
        session
            .prepare(Statement::new(format!("SELECT level, node_index, value FROM {}.{}", keyspace, table_name)).with_page_size(100))
            .await?,
    );
    debug_timer.lap("Prepared paged select statement");
    // Manual paging in a loop, prepared statement.
    let mut paging_state = PagingState::default();
    let mut total_rows_fetched = 0;
    loop {
        let (res, paging_state_response) = session
            .execute_single_page(&paged_prepared, &[], paging_state)
            .await?;

        let res = res.into_rows_result()?;

        total_rows_fetched += res.rows_num();
        /*println!(
            "Paging state from the prepared statement execution: {:#?} ({} rows)",
            paging_state_response,
            res.rows_num(),
        );*/

        match paging_state_response.into_paging_control_flow() {
            ControlFlow::Break(()) => {
                // No more pages to be fetched.
                break;
            }
            ControlFlow::Continue(new_paging_state) => {
                // Update paging paging state from the response, so that query
                // will be resumed from where it ended the last time.
                paging_state = new_paging_state;
            }
        }
    }
    debug_timer.event_batch_item_ref(
        format!("fetched_all_pages_prepared_statement"),
        "row",
        total_rows_fetched,
    );

    println!("Ok.");

    Ok(())
}