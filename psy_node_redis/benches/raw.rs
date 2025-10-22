use criterion::{black_box, BatchSize, Criterion, Throughput};
use psy_node_core::store::traits::temp_db::{QTempDatabaseRawKVReaderBase, QTempDatabaseRawKVWriterBase};
use psy_node_redis::store::{new_redis_async_pool, StandardRedisStore};
use tokio::runtime::Runtime;


async fn setup_redis_store(url: &str) -> StandardRedisStore {
    let pool = new_redis_async_pool(url, 5).await.unwrap();
    let store = StandardRedisStore::new(pool, format!("rlm_{}", rand::random::<u32>()) , 1, 1337);

    store

}

pub fn criterion_benchmark_g(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let store = rt.block_on(setup_redis_store("redis://127.0.0.1/"));

    let batch_size: u64 = 1000;
    let key_prefix = b"bench_key_";
    let value = vec![0u8; 100]; // 100-byte values

    let mut group = c.benchmark_group("zkv_store");
    group.throughput(Throughput::Elements(batch_size));

    group.bench_function("put_many_owned", |b| {
        b.to_async(&rt).iter_batched(
            || {
                let keys: Vec<Vec<u8>> = (0..batch_size).map(|i| [key_prefix, &i.to_be_bytes()[..]].concat()).collect();
                let values: Vec<Vec<u8>> = vec![value.clone(); batch_size as usize];
                keys.into_iter().zip(values.into_iter()).collect::<Vec<(Vec<u8>, Vec<u8>)>>()
            },
            |entries| black_box(async { store.qtdb_raw_kv_put_many_values_tuple_owned(entries).await.unwrap() }),
            BatchSize::SmallInput,
        )
    });

    // Populate data for gets
    rt.block_on(async {
        let keys: Vec<Vec<u8>> = (0..batch_size).map(|i| [key_prefix, &i.to_be_bytes()[..]].concat()).collect();
        let values: Vec<Vec<u8>> = vec![value.clone(); batch_size as usize];
        let entries =
            keys.into_iter().zip(values.into_iter()).collect::<Vec<(Vec<u8>, Vec<u8>)>>();
        store.qtdb_raw_kv_put_many_values_tuple(&entries).await.unwrap();
    });

    group.bench_function("get_many_owned", |b| {
        b.to_async(&rt).iter_batched(
            || {
                let keys: Vec<Vec<u8>> = (0..batch_size).map(|i| [key_prefix, &i.to_be_bytes()[..]].concat()).collect();
                keys
            },
            |k| black_box(async { store.qtdb_raw_kv_get_many_values_vec_owned(k).await.unwrap() }),
            BatchSize::SmallInput,
        )
    });

    group.finish();
}