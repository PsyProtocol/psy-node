use std::sync::Arc;

use psy_node_core::store::traits::temp_db::{
    QTempDatabaseRawKVCompareAndSet, QTempDatabaseRawKVReaderBase, QTempDatabaseRawKVWriterBase,
};
use psy_node_redis::store::{new_redis_async_pool, StandardRedisStore};
use rand::{distributions::Alphanumeric, Rng};

async fn new_store() -> anyhow::Result<StandardRedisStore> {
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".into());
    let pool = new_redis_async_pool(&redis_url, 4).await?;
    // a random prefix and ids keep each test in its own hash
    let prefix: String = rand::thread_rng().sample_iter(&Alphanumeric).take(8).map(char::from).collect();
    let mut rng = rand::thread_rng();
    Ok(StandardRedisStore::new(pool, prefix, rng.gen(), rng.gen()))
}

#[tokio::test]
#[ignore = "Requires a running Redis instance at REDIS_URL"]
async fn redis_compare_and_set_follows_the_expected_value() -> anyhow::Result<()> {
    let store = new_store().await?;

    // absent key: expecting a value refuses, expecting absence sets
    assert!(!store.qtdb_raw_kv_compare_and_set(b"k", Some(b"v0"), b"v1").await?);
    assert_eq!(store.qtdb_raw_kv_get_value(b"k").await?, None);
    assert!(store.qtdb_raw_kv_compare_and_set(b"k", None, b"v1").await?);
    assert_eq!(store.qtdb_raw_kv_get_value(b"k").await?, Some(b"v1".to_vec()));

    // present key: only the matching expected value replaces it
    assert!(!store.qtdb_raw_kv_compare_and_set(b"k", None, b"v2").await?);
    assert!(!store.qtdb_raw_kv_compare_and_set(b"k", Some(b"other"), b"v2").await?);
    assert!(store.qtdb_raw_kv_compare_and_set(b"k", Some(b"v1"), b"v2").await?);
    assert_eq!(store.qtdb_raw_kv_get_value(b"k").await?, Some(b"v2".to_vec()));

    // binary values with embedded zero bytes compare byte for byte
    let a = [0u8, 1, 0, 255, 0];
    let b = [0u8, 1, 0, 255, 1];
    assert!(store.qtdb_raw_kv_compare_and_set(b"bin", None, &a).await?);
    assert!(!store.qtdb_raw_kv_compare_and_set(b"bin", Some(&b), &b).await?);
    assert!(store.qtdb_raw_kv_compare_and_set(b"bin", Some(&a), &b).await?);
    assert_eq!(store.qtdb_raw_kv_get_value(b"bin").await?, Some(b.to_vec()));
    Ok(())
}

#[tokio::test]
#[ignore = "Requires a running Redis instance at REDIS_URL"]
async fn redis_compare_and_set_treats_an_empty_value_as_absent() -> anyhow::Result<()> {
    let store = new_store().await?;
    store.qtdb_raw_kv_put_value(b"k", b"").await?;
    // the reader already reports the empty field as absent
    assert_eq!(store.qtdb_raw_kv_get_value(b"k").await?, None);
    assert!(store.qtdb_raw_kv_compare_and_set(b"k", None, b"v1").await?);
    assert_eq!(store.qtdb_raw_kv_get_value(b"k").await?, Some(b"v1".to_vec()));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "Requires a running Redis instance at REDIS_URL"]
async fn redis_only_one_of_many_concurrent_claims_from_absent_wins() -> anyhow::Result<()> {
    let store = Arc::new(new_store().await?);
    let claims = (0..32u8).map(|i| {
        let store = Arc::clone(&store);
        tokio::spawn(async move { store.qtdb_raw_kv_compare_and_set(b"k", None, &[i + 1]).await })
    });
    let mut wins = 0;
    for claim in claims {
        if claim.await?? {
            wins += 1;
        }
    }
    assert_eq!(wins, 1);
    Ok(())
}
