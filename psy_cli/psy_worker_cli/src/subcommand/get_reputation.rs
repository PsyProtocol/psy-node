//! Query worker reputation from realm or coordinator edge RPC.

use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use parth_core::PHash;
use psy_api_core::worker::standard_worker_rpc::NodeEdgeWorkerRpcClient;
use psy_core::job::job_id::QProvingJobDataID;

pub async fn run(url: &str, public_key_hex: &str) -> anyhow::Result<()> {
    let public_key_bytes = hex::decode(public_key_hex.trim().trim_start_matches("0x"))?;
    if public_key_bytes.len() != 33 {
        anyhow::bail!(
            "public_key must be 33 bytes (compressed secp256k1), got {} bytes (hex length {})",
            public_key_bytes.len(),
            public_key_hex.len()
        );
    }
    let client: HttpClient = HttpClientBuilder::default().build(url)?;
    let reputation = NodeEdgeWorkerRpcClient::<PHash, QProvingJobDataID>::get_worker_reputation(
        &client,
        public_key_bytes,
    )
    .await?;
    println!("reputation: {}", reputation);
    Ok(())
}
