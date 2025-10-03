use parth_common_v0::data::hash::merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey};
use parth_node_v1::jobhq::nats::core::{random_job_data, NatsJetStreamClient};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let base_namespace = "EX_JOB_STREAM".to_string();
    let realm_id = 1u64;
    let realm_sub_id = 1u64;
    let ex_queue_type = 1337u32;
    let task_group = 1u64;
    let unique_topic = 123u128;

    let client = NatsJetStreamClient::new_connection(
        base_namespace, 
        "localhost:4222".to_string(), 
        5000
    ).await?;

    let jobs = (0..1000).map(|x|random_job_data()).collect::<Vec<_>>();

    println!("Pushing {} jobs to NATS JetStream", jobs.len());
    client.push_messages(realm_id, realm_sub_id, ex_queue_type, unique_topic, task_group, &jobs).await?;
    println!("pushed jobs, waiting for completion...");
    client.wait_until_all_jobs_complete_or_timeout(realm_id, realm_sub_id, ex_queue_type, unique_topic, task_group).await?;
    println!("All jobs completed!");




    Ok(())
}