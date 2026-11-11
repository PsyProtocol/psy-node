use std::time::SystemTime;

use fred::interfaces::*;
use parth_core::{QJobIdSerialized, QJOB_ID_SERIALIZED_SIZE};
use psy_node_core::store::traits::proof_store::{QParthProofStoreReader, QParthProofStoreWriter};
use psy_node_redis::store::{new_redis_async_pool, StandardFredRedisStore};

#[tokio::test]
#[ignore = "requires an isolated Redis 7.4+ instance at REDIS_INTEGRATION_URL"]
async fn proofs_remain_until_explicit_pending_id_cleanup() -> anyhow::Result<()> {
    let url = std::env::var("REDIS_INTEGRATION_URL")?;
    let prefix = format!("proof_lifetime_{}", SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_nanos());
    let pool = new_redis_async_pool(&url, 2).await?;
    let store = StandardFredRedisStore::new(pool, prefix.clone(), 0, 0);
    let a: QJobIdSerialized = [1; QJOB_ID_SERIALIZED_SIZE];
    let b: QJobIdSerialized = [2; QJOB_ID_SERIALIZED_SIZE];
    let bucket = format!("TMPPSV1-{prefix}-0-0-17");
    store.put_proof_bytes_for_job_id(a, 17, b"child-proof").await?;
    store.put_proof_for_job_id(b, 17, &42_u64).await?;
    store.put_proof_bytes_for_job_id(a, 18, b"next-batch-proof").await?;
    let fields = vec![fred::types::Key::from(&a[..]), fred::types::Key::from(&b[..])];
    let ttl: Vec<i64> = store.client.httl(&bucket, fields).await?;
    assert_eq!(ttl, vec![-1, -1], "both proof writer APIs must retain uncommitted dependencies");

    // Replacing an old expiring field also clears its legacy field TTL.
    let changed: Vec<i64> = store.client.hexpire(&bucket, 1, None, fred::types::Key::from(&a[..])).await?;
    assert_eq!(changed, vec![1]);
    store.put_proof_bytes_for_job_id(a, 17, b"child-proof").await?;
    let ttl: Vec<i64> = store.client.httl(&bucket, fred::types::Key::from(&a[..])).await?;
    assert_eq!(ttl, vec![-1]);
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    assert_eq!(store.get_proof_bytes_by_job_id(a, 17).await?, Some(b"child-proof".to_vec()));
    assert_eq!(store.get_proof_by_job_id::<_, u64>(b, 17).await?, Some(42));

    store.delete_all_proofs_for_pending_id(17).await?;
    store.delete_all_proofs_for_pending_id(17).await?;
    assert!(!store.contains_proof_for_job_id(a, 17).await?);
    assert!(!store.contains_proof_for_job_id(b, 17).await?);
    assert_eq!(store.get_proof_bytes_by_job_id(a, 18).await?, Some(b"next-batch-proof".to_vec()));
    store.delete_all_proofs_for_pending_id(18).await?;
    store.client.quit().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires an isolated Redis 7.4+ instance at REDIS_INTEGRATION_URL"]
async fn deleting_consumed_proofs_keeps_the_rest_of_the_bucket() -> anyhow::Result<()> {
    let url = std::env::var("REDIS_INTEGRATION_URL")?;
    let prefix = format!("proof_reclaim_{}", SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_nanos());
    let pool = new_redis_async_pool(&url, 2).await?;
    let store = StandardFredRedisStore::new(pool, prefix.clone(), 0, 1);
    let consumed: QJobIdSerialized = [3; QJOB_ID_SERIALIZED_SIZE];
    let deferred: QJobIdSerialized = [4; QJOB_ID_SERIALIZED_SIZE];
    let output: QJobIdSerialized = [5; QJOB_ID_SERIALIZED_SIZE];
    store.put_proof_bytes_for_job_id(consumed, 8, b"consumed-end-cap").await?;
    store.put_proof_bytes_for_job_id(deferred, 8, b"deferred-end-cap").await?;
    store.put_proof_bytes_for_job_id(output, 10, b"block-output").await?;

    store.delete_proofs_for_job_ids(8, &[consumed]).await?;
    store.delete_proofs_for_job_ids(10, &[output, consumed]).await?;
    // Idempotent, and a missing bucket or an empty list is not an error.
    store.delete_proofs_for_job_ids(10, &[output]).await?;
    store.delete_proofs_for_job_ids::<QJobIdSerialized>(8, &[]).await?;

    assert!(!store.contains_proof_for_job_id(consumed, 8).await?);
    assert_eq!(store.get_proof_bytes_by_job_id(deferred, 8).await?, Some(b"deferred-end-cap".to_vec()));
    let emptied: i64 = store.client.exists(format!("TMPPSV1-{prefix}-0-1-10")).await?;
    assert_eq!(emptied, 0, "an emptied bucket must not remain as a key");
    store.delete_all_proofs_for_pending_id(8).await?;
    store.client.quit().await?;
    Ok(())
}
