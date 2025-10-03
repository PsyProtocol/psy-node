use parth_common_v0::data::hash::merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey};
use parth_node_v1::jobhq::nats::core::NatsJetStreamClient;

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

    let start_time = std::time::Instant::now();

    let total_jobs_to_proc = 5000;
    let mut got_jobs = 0;
    while got_jobs < total_jobs_to_proc {
        let result = client.get_message_if_exists(realm_id, realm_sub_id, ex_queue_type, unique_topic, task_group).await?;
        if let Some(job) = result {
            
        //println!("report_message_completed for job: {}", hex::encode(job));
        client.report_message_completed(realm_id, realm_sub_id, ex_queue_type, unique_topic, task_group, job).await?;
            got_jobs += 1;
            //println!("Got job {}", hex::encode(&job));
        } else {
            println!("No more jobs available, waiting a bit...");
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }
    let end_time = std::time::Instant::now();
    let duration = end_time.duration_since(start_time);
    println!("Time taken to process {} jobs: {:?}, {} jobs per second", got_jobs, duration, got_jobs as f64 / duration.as_secs_f64());
    /* 
    for job in jobs_vec.iter() {
        println!("report_message_completed for job: {}", hex::encode(job));
        client.report_message_completed(realm_id, realm_sub_id, ex_queue_type, unique_topic, task_group, *job).await?;
    }*/


    println!("Processed {} jobs", got_jobs);
    Ok(())
}