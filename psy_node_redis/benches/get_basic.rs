use criterion::{Criterion, Throughput};
use parth_core::{QCoreProcCheckpointUniqueId, node::realm_identifier::QRealmIdentifier};
use psy_node_core::{psy_temp_db::tt_get_unique_pending_id_key, store::traits::temp_db::{QTempDatabaseRawKVReaderBase, QTempDatabaseRawKVWriterBase}};
use psy_node_redis::store::{new_redis_async_pool, StandardRedisStore};
use tokio::runtime::Runtime;


async fn setup_redis_store(url: &str) -> StandardRedisStore {
    let pool = new_redis_async_pool(url, 5).await.unwrap();
    let store = StandardRedisStore::new(pool, format!("rlm_{}", rand::random::<u32>()) , 1, 1337);

    store

}
async fn setup_with_redis_store_set_unique_pending_ids(url: &str, rid: &QRealmIdentifier, unique_pending_id: u64, proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId) -> StandardRedisStore {
    let store = setup_redis_store(url).await;
    let key = tt_get_unique_pending_id_key(rid.realm_id, rid.realm_sub_id);
    let mut value_bytes = Vec::with_capacity(24);
    value_bytes.extend_from_slice(&unique_pending_id.to_le_bytes());
    value_bytes.extend_from_slice(&proc_checkpoint_unique_id.to_le_bytes());
    store.qtdb_raw_kv_put_value(&key, &value_bytes).await.unwrap();
    store
}
    async fn get_unique_pending_ids(store: &StandardRedisStore, rid: &QRealmIdentifier) -> anyhow::Result<(u64, QCoreProcCheckpointUniqueId)> {
        let key = tt_get_unique_pending_id_key(rid.realm_id, rid.realm_sub_id);
        let value_bytes = store.qtdb_raw_kv_get_value(&key).await?;
        if value_bytes.is_some() {
            let value_bytes = value_bytes.unwrap();
            if value_bytes.len() != 24 {
                return Err(anyhow::anyhow!("Invalid value length for unique pending ids"));
            }
            let unique_pending_id = u64::from_le_bytes(value_bytes[0..8].try_into().unwrap());
            let proc_checkpoint_unique_id = QCoreProcCheckpointUniqueId::from_le_bytes(value_bytes[8..24].try_into().unwrap());
            Ok((unique_pending_id, proc_checkpoint_unique_id))
        } else {
            anyhow::bail!("Unique pending ids not found");
        }
    }
pub fn criterion_benchmark_g(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let rid = QRealmIdentifier {
        realm_id: 42,
        realm_sub_id: 7,
    };

    let unique_pending_id: u64 = 123456;
    let proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId = 9876543210;

    let store = rt.block_on(setup_with_redis_store_set_unique_pending_ids("redis://127.0.0.1/", &rid, unique_pending_id, proc_checkpoint_unique_id));


    let mut group = c.benchmark_group("zkv_store");
    group.throughput(Throughput::Elements(1));
    group.bench_function("get_checkpoint_id", |b| {
        b.to_async(&rt).iter(|| async {
            let (upid, pcui) = get_unique_pending_ids(&store, &rid).await.unwrap();
            assert_eq!(upid, unique_pending_id);
            assert_eq!(pcui, proc_checkpoint_unique_id);
        })
    });

    group.finish();
}