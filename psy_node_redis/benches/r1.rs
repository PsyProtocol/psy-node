/*use criterion::{async_executor::FuturesExecutor, criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use redis::{aio::MultiplexedConnection, Client, RedisResult};
use rand::{distributions::Alphanumeric, Rng};
use std::time::Duration;
use async_trait::async_trait;
use redis::{self, AsyncCommands, Cmd};
use redis::RedisError;
use redis::ErrorKind;

type Result<T> = RedisResult<T>;
#[derive(Clone)]
struct QKVStore {
    conn: MultiplexedConnection,
}
#[async_trait]
pub trait QKVStoreBase {
    async fn put_ref(&self, key: &[u8], value: &[u8]) -> Result<()>;
    async fn put_owned(&self, key: Vec<u8>, value: Vec<u8>) -> Result<()>;
    async fn put_many_ref(&self, keys: &[&[u8]], values: &[&[u8]]) -> Result<()>;
    async fn put_many_owned(&self, keys: Vec<Vec<u8>>, values: Vec<Vec<u8>>) -> Result<()>;
    async fn put_many_tuples_ref(&self, items: &[(&[u8], &[u8])]) -> Result<()>;
    async fn put_many_tuples_owned(&self, items: Vec<(Vec<u8>, Vec<u8>)>) -> Result<()>;
    async fn get_ref(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;
    async fn get_owned(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>>;
    async fn get_many_ref(&self, keys: &[&[u8]]) -> Result<Vec<Option<Vec<u8>>>>;
    async fn get_many_owned(&self, keys: Vec<Vec<u8>>) -> Result<Vec<Option<Vec<u8>>>>;
}
#[async_trait]
impl QKVStoreBase for QKVStore {
    async fn put_ref(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let mut conn = self.conn.clone();
        conn.set(key, value).await
    }

    async fn put_owned(&self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        let mut cmd = Cmd::new();
        cmd.arg("SET").arg(key).arg(value);
        let mut conn = self.conn.clone();
        cmd.query_async(&mut conn).await
    }

    async fn put_many_ref(&self, keys: &[&[u8]], values: &[&[u8]]) -> Result<()> {
        if keys.len() != values.len() {
            return Err(RedisError::from((ErrorKind::InvalidClientConfig, "Keys and values length mismatch.")));
        }
        let mut cmd = redis::cmd("MSET");
        for (&k, &v) in keys.iter().zip(values.iter()) {
            cmd.arg(k);
            cmd.arg(v);
        }
        let mut conn = self.conn.clone();
        cmd.query_async(&mut conn).await
    }

    async fn put_many_owned(&self, keys: Vec<Vec<u8>>, values: Vec<Vec<u8>>) -> Result<()> {
        if keys.len() != values.len() {
            return Err(RedisError::from((ErrorKind::InvalidClientConfig, "Keys and values length mismatch.")));
        }
        let mut cmd = Cmd::new();
        cmd.arg("MSET");
        for (k, v) in keys.into_iter().zip(values.into_iter()) {
            cmd.arg(k);
            cmd.arg(v);
        }
        let mut conn = self.conn.clone();
        cmd.query_async(&mut conn).await
    }

    async fn put_many_tuples_ref(&self, items: &[(&[u8], &[u8])]) -> Result<()> {
        let mut conn = self.conn.clone();
        conn.mset(items).await
    }

    async fn put_many_tuples_owned(&self, items: Vec<(Vec<u8>, Vec<u8>)>) -> Result<()> {
        let mut cmd = Cmd::new();
        cmd.arg("MSET");
        for (k, v) in items.into_iter() {
            cmd.arg(k);
            cmd.arg(v);
        }
        let mut conn = self.conn.clone();
        cmd.query_async(&mut conn).await
    }

    async fn get_ref(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut conn = self.conn.clone();
        conn.get(key).await
    }

    async fn get_owned(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>> {
        let mut cmd = Cmd::new();
        cmd.arg("GET").arg(key);
        let mut conn = self.conn.clone();
        cmd.query_async(&mut conn).await
    }

    async fn get_many_ref(&self, keys: &[&[u8]]) -> Result<Vec<Option<Vec<u8>>>> {
        let mut conn = self.conn.clone();
        conn.mget(keys).await
    }

    async fn get_many_owned(&self, keys: Vec<Vec<u8>>) -> Result<Vec<Option<Vec<u8>>>> {
        let mut cmd = Cmd::new();
        cmd.arg("MGET");
        for k in keys.into_iter() {
            cmd.arg(k);
        }
        let mut conn = self.conn.clone();
        cmd.query_async(&mut conn).await
    }
}
async fn setup_connection() -> RedisResult<MultiplexedConnection> {
    let client = Client::open("redis://127.0.0.1/")?;
    client.get_multiplexed_async_connection().await
}

fn generate_random_data(size: usize) -> Vec<u8> {
    rand::thread_rng().sample_iter(&Alphanumeric).take(size).collect()
}

fn benches(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let conn = rt.block_on(setup_connection()).unwrap();
    let store = QKVStore { conn };

    let key_size = 16;
    let value_size = 64;
    let batch_size = 1000;

    // Single put_ref
    c.bench_function("put_ref_single", |b| {
        b.to_async(FuturesExecutor).iter(|| async {
            let key = generate_random_data(key_size);
            let value = generate_random_data(value_size);
            store.put_ref(&key, &value).await.unwrap();
        })
    });

    // Single put_owned
    c.bench_function("put_owned_single", |b| {
        b.to_async(FuturesExecutor).iter(|| async {
            let key = generate_random_data(key_size);
            let value = generate_random_data(value_size);
            store.put_owned(key, value).await.unwrap();
        })
    });

    // Batch put_many_ref
    let mut group = c.benchmark_group("put_many_ref");
    group.throughput(Throughput::Elements(batch_size as u64));
    group.bench_function("batch", |b| {
        b.to_async(FuturesExecutor).iter_batched(
            || {
                let keys: Vec<Vec<u8>> = (0..batch_size).map(|_| generate_random_data(key_size)).collect();
                let values: Vec<Vec<u8>> = (0..batch_size).map(|_| generate_random_data(value_size)).collect();
                (keys, values)
            },
            |(keys, values)| async move {
                let keys_ref: Vec<&[u8]> = keys.iter().map(|k| k.as_slice()).collect();
                let values_ref: Vec<&[u8]> = values.iter().map(|v| v.as_slice()).collect();
                store.put_many_ref(&keys_ref, &values_ref).await.unwrap();
            },
            BatchSize::SmallInput,
        )
    });
    group.finish();

    // Batch put_many_owned
    let mut group = c.benchmark_group("put_many_owned");
    group.throughput(Throughput::Elements(batch_size as u64));
    group.bench_function("batch", |b| {
        b.to_async(FuturesExecutor).iter_batched(
            || {
                let keys: Vec<Vec<u8>> = (0..batch_size).map(|_| generate_random_data(key_size)).collect();
                let values: Vec<Vec<u8>> = (0..batch_size).map(|_| generate_random_data(value_size)).collect();
                (keys, values)
            },
            |(keys, values)| async {
                store.put_many_owned(keys, values).await.unwrap();
            },
            BatchSize::SmallInput,
        )
    });
    group.finish();

    // Batch put_many_tuples_ref
    let mut group = c.benchmark_group("put_many_tuples_ref");
    group.throughput(Throughput::Elements(batch_size as u64));
    group.bench_function("batch", |b| {
        b.to_async(FuturesExecutor).iter_batched(
            || {
                let keys: Vec<Vec<u8>> = (0..batch_size).map(|_| generate_random_data(key_size)).collect();
                let values: Vec<Vec<u8>> = (0..batch_size).map(|_| generate_random_data(value_size)).collect();
                (keys, values)
            },
            |(keys, values)| async move {
                let items: Vec<(&[u8], &[u8])> = keys.iter().zip(values.iter()).map(|(k, v)| (k.as_slice(), v.as_slice())).collect();
                store.put_many_tuples_ref(&items).await.unwrap();
            },
            BatchSize::SmallInput,
        )
    });
    group.finish();

    // Batch put_many_tuples_owned
    let mut group = c.benchmark_group("put_many_tuples_owned");
    group.throughput(Throughput::Elements(batch_size as u64));
    group.bench_function("batch", |b| {
        b.to_async(FuturesExecutor).iter_batched(
            || {
                let items: Vec<(Vec<u8>, Vec<u8>)> = (0..batch_size)
                    .map(|_| (generate_random_data(key_size), generate_random_data(value_size)))
                    .collect();
                items
            },
            |items| async {
                store.put_many_tuples_owned(items).await.unwrap();
            },
            BatchSize::SmallInput,
        )
    });
    group.finish();

    // Prepare keys for gets
    let prepared_keys: Vec<Vec<u8>> = rt.block_on(async {
        let mut keys = Vec::with_capacity(batch_size);
        for _ in 0..batch_size {
            let key = generate_random_data(key_size);
            let value = generate_random_data(value_size);
            store.put_ref(&key, &value).await.unwrap();
            keys.push(key);
        }
        keys
    });

    // Single get_ref
    c.bench_function("get_ref_single", |b| {
        let key = prepared_keys[0].clone();
        b.to_async(FuturesExecutor).iter(|| async {
            store.get_ref(&key).await.unwrap();
        })
    });

    // Single get_owned
    c.bench_function("get_owned_single", |b| {
        let key = prepared_keys[0].clone();
        b.to_async(FuturesExecutor).iter(|| async {
            store.get_owned(key.clone()).await.unwrap();
        })
    });

    // Batch get_many_ref
    let mut group = c.benchmark_group("get_many_ref");
    group.throughput(Throughput::Elements(batch_size as u64));
    group.bench_function("batch", |b| {
        let keys_ref: Vec<&[u8]> = prepared_keys.iter().map(|k| k.as_slice()).collect();
        b.to_async(FuturesExecutor).iter(|| async {
            store.get_many_ref(&keys_ref).await.unwrap();
        })
    });
    group.finish();

    // Batch get_many_owned
    let mut group = c.benchmark_group("get_many_owned");
    group.throughput(Throughput::Elements(batch_size as u64));
    group.bench_function("batch", |b| {
        let keys = prepared_keys.clone();
        b.to_async(FuturesExecutor).iter(|| async {
            store.get_many_owned(keys.clone()).await.unwrap();
        })
    });
    group.finish();
}

criterion_group!(benches_group, benches);
criterion_main!(benches_group);*/