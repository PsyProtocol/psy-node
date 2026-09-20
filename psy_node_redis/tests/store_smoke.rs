use std::time::{SystemTime, UNIX_EPOCH};

use parth_core::data::serializable::QPDPair;
use psy_node_core::store::traits::temp_db::{
    QTempDatabaseRawCounterReaderBase, QTempDatabaseRawCounterWriterBase,
    QTempDatabaseRawKVReaderBase, QTempDatabaseRawKVWriterBase,
};
use psy_node_redis::store::{new_redis_async_pool, StandardFredRedisStore};

fn redis_url() -> Option<String> {
    std::env::var("REDIS_URL").ok().filter(|s| !s.is_empty())
}

#[tokio::test]
#[ignore = "Requires REDIS_URL"]
async fn redis_kv_counter_and_buffer_smoke() {
    let Some(url) = redis_url() else {
        panic!("REDIS_URL must be set for ignored live tests");
    };
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let pool = new_redis_async_pool(&url, 2).await.unwrap();
    let store = StandardFredRedisStore::new(pool, format!("smoke{suffix}"), 1, 2);
    assert_eq!(
        store.kv_store_namespace,
        format!("TKVSV1-smoke{suffix}-1-2")
    );
    assert_eq!(
        store.proof_store_namespace,
        format!("TMPPSV1-smoke{suffix}-1-2")
    );

    store.qtdb_raw_kv_put_value(b"k1", b"v1").await.unwrap();
    assert_eq!(
        store.qtdb_raw_kv_get_value(b"k1").await.unwrap().as_deref(),
        Some(&b"v1"[..])
    );
    assert!(store.qtdb_raw_kv_contains_key(b"k1").await.unwrap());
    assert!(!store.qtdb_raw_kv_contains_key(b"missing").await.unwrap());

    store
        .qtdb_raw_kv_put_many_values(&[QPDPair {
            key: b"k2".to_vec(),
            value: b"v2".to_vec(),
        }])
        .await
        .unwrap();
    store
        .qtdb_raw_kv_put_many_values_tuple(&[(b"k3".to_vec(), b"v3".to_vec())])
        .await
        .unwrap();
    store
        .qtdb_raw_kv_put_many_values_tuple_ref(&[(b"k4".as_slice(), b"v4".as_slice())])
        .await
        .unwrap();
    store
        .qtdb_raw_kv_put_many_values_tuple_owned(vec![(b"k5".to_vec(), b"v5".to_vec())])
        .await
        .unwrap();

    let many = store
        .qtdb_raw_kv_get_many_values(&[b"k1".as_slice(), b"k2".as_slice(), b"nope".as_slice()])
        .await
        .unwrap();
    assert_eq!(many[0].as_deref(), Some(&b"v1"[..]));
    assert_eq!(many[1].as_deref(), Some(&b"v2"[..]));
    assert!(many[2].is_none());

    let owned = store
        .qtdb_raw_kv_get_many_values_vec_owned(vec![b"k3".to_vec()])
        .await
        .unwrap();
    assert_eq!(owned[0].as_deref(), Some(&b"v3"[..]));
    let vec_ref = store
        .qtdb_raw_kv_get_many_values_vec(&[b"k4".to_vec()])
        .await
        .unwrap();
    assert_eq!(vec_ref[0].as_deref(), Some(&b"v4"[..]));

    store
        .qtdb_raw_kv_put_many_values_buffer::<2, 2>(b"aabbccdd")
        .await
        .unwrap();
    assert_eq!(
        store.qtdb_raw_kv_get_value(b"aa").await.unwrap().as_deref(),
        Some(&b"bb"[..])
    );
    store
        .qtdb_raw_kv_put_many_values_buffer::<2, 2>(b"")
        .await
        .unwrap();
    let err = store
        .qtdb_raw_kv_put_many_values_buffer::<3, 1>(b"xx")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("multiple"));

    store.qtdb_raw_counter_set_value(b"c", 10).await.unwrap();
    assert_eq!(store.qtdb_raw_counter_get_value(b"c").await.unwrap(), 10);
    assert_eq!(
        store.qtdb_raw_counter_increment_by(b"c", 3).await.unwrap(),
        13
    );

    store.qtdb_raw_kv_delete_key(b"k1").await.unwrap();
    assert!(store.qtdb_raw_kv_get_value(b"k1").await.unwrap().is_none());
}
