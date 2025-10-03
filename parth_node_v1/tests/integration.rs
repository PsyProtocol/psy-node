use anyhow::Result;
use parth_core::data::hash::hash256::Hash256;
use parth_crypto::hash::sha256::CoreSha256Hasher;
use parth_node_v1::store::scylla::core::ScyllaCoreStore;


#[tokio::test]
async fn test_set_get_correctness() -> Result<()> {
    let realm_id = 1;
    let realm_sub_id = 1;
    let keyspace_prefix = format!("test_set_get_correctness_{}_{}", realm_id, realm_sub_id);

    let _store = ScyllaCoreStore::<Hash256, CoreSha256Hasher>::new(realm_id, realm_sub_id, keyspace_prefix, &["127.0.0.1:9042".to_string()]).await?;

    
    Ok(())
}
