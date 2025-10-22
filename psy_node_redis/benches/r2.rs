
use criterion::{black_box, BatchSize, Criterion, Throughput};
use redis::{self, AsyncCommands, RedisResult};
use tokio::runtime::Runtime;

#[async_trait::async_trait]
pub trait QKVStoreBase {
    async fn put_ref(&self, key: &[u8], value: &[u8]) -> Result<(), redis::RedisError>;
    async fn put_owned(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), redis::RedisError>;
    async fn put_many_ref(&self, keys: &[&[u8]], values: &[&[u8]]) -> Result<(), redis::RedisError>;
    async fn put_many_owned(&self, keys: Vec<Vec<u8>>, values: Vec<Vec<u8>>) -> Result<(), redis::RedisError>;
    async fn put_many_tuples_ref(&self, items: &[(&[u8], &[u8])]) -> Result<(), redis::RedisError>;
    async fn put_many_tuples_owned(&self, items: Vec<(Vec<u8>, Vec<u8>)>) -> Result<(), redis::RedisError>;
    async fn get_ref(&self, key: &[u8]) -> Result<Option<Vec<u8>>, redis::RedisError>;
    async fn get_owned(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>, redis::RedisError>;
    async fn get_many_ref(&self, keys: &[&[u8]]) -> Result<Vec<Option<Vec<u8>>>, redis::RedisError>;
    async fn get_many_owned(&self, keys: Vec<Vec<u8>>) -> Result<Vec<Option<Vec<u8>>>, redis::RedisError>;
}

struct QKVStore {
    conn: redis::aio::MultiplexedConnection,
}

impl QKVStore {
    pub async fn new(url: &str) -> RedisResult<Self> {
        let client = redis::Client::open(url)?;
        let conn = client.get_multiplexed_async_connection().await?;
        Ok(Self { conn })
    }
}

#[async_trait::async_trait]
impl QKVStoreBase for QKVStore {
    async fn put_ref(&self, key: &[u8], value: &[u8]) -> Result<(), redis::RedisError> {
        let mut conn = self.conn.clone();
        conn.set(key, value).await
    }

    async fn put_owned(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), redis::RedisError> {
        self.put_ref(&key, &value).await
    }

    async fn put_many_ref(&self, keys: &[&[u8]], values: &[&[u8]]) -> Result<(), redis::RedisError> {
        if keys.len() != values.len() {
            return Err(redis::RedisError::from((redis::ErrorKind::ClientError, "Mismatched lengths")));
        }
        let items: Vec<(&[u8], &[u8])> = keys.iter().zip(values.iter()).map(|(&k, &v)| (k, v)).collect();
        let mut conn = self.conn.clone();
        conn.mset(&items).await
    }

    async fn put_many_owned(&self, keys: Vec<Vec<u8>>, values: Vec<Vec<u8>>) -> Result<(), redis::RedisError> {
        let keys_ref: Vec<&[u8]> = keys.iter().map(|v| &v[..]).collect();
        let values_ref: Vec<&[u8]> = values.iter().map(|v| &v[..]).collect();
        self.put_many_ref(&keys_ref, &values_ref).await
    }

    async fn put_many_tuples_ref(&self, items: &[(&[u8], &[u8])]) -> Result<(), redis::RedisError> {
        let mut conn = self.conn.clone();
        conn.mset(items).await
    }

    async fn put_many_tuples_owned(&self, items: Vec<(Vec<u8>, Vec<u8>)>) -> Result<(), redis::RedisError> {
        let items_ref: Vec<(&[u8], &[u8])> = items.iter().map(|(k, v)| (&k[..], &v[..])).collect();
        self.put_many_tuples_ref(&items_ref).await
    }

    async fn get_ref(&self, key: &[u8]) -> Result<Option<Vec<u8>>, redis::RedisError> {
        let mut conn = self.conn.clone();
        conn.get(key).await
    }

    async fn get_owned(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>, redis::RedisError> {
        self.get_ref(&key).await
    }

    async fn get_many_ref(&self, keys: &[&[u8]]) -> Result<Vec<Option<Vec<u8>>>, redis::RedisError> {
        let mut conn = self.conn.clone();
        conn.mget(keys).await
    }

    async fn get_many_owned(&self, keys: Vec<Vec<u8>>) -> Result<Vec<Option<Vec<u8>>>, redis::RedisError> {
        let keys_ref: Vec<&[u8]> = keys.iter().map(|v| &v[..]).collect();
        self.get_many_ref(&keys_ref).await
    }
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let store = rt.block_on(QKVStore::new("redis://127.0.0.1/")).unwrap();

    let batch_size: u64 = 1000;
    let key_prefix = b"bench_key_";
    let value = vec![0u8; 100]; // 100-byte values

    let mut group = c.benchmark_group("kv_store");
    group.throughput(Throughput::Elements(batch_size));

    group.bench_function("put_many_owned", |b| {
        b.to_async(&rt).iter_batched(
            || {
                let keys: Vec<Vec<u8>> = (0..batch_size).map(|i| [key_prefix, &i.to_be_bytes()[..]].concat()).collect();
                let values: Vec<Vec<u8>> = vec![value.clone(); batch_size as usize];
                (keys, values)
            },
            |(keys, values)| black_box(async { store.put_many_owned(keys, values).await.unwrap() }),
            BatchSize::SmallInput,
        )
    });

    // Populate data for gets
    rt.block_on(async {
        let keys: Vec<Vec<u8>> = (0..batch_size).map(|i| [key_prefix, &i.to_be_bytes()[..]].concat()).collect();
        let values: Vec<Vec<u8>> = vec![value.clone(); batch_size as usize];
        store.put_many_owned(keys, values).await.unwrap();
    });

    group.bench_function("get_many_owned", |b| {
        b.to_async(&rt).iter_batched(
            || {
                let keys: Vec<Vec<u8>> = (0..batch_size).map(|i| [key_prefix, &i.to_be_bytes()[..]].concat()).collect();
                keys
            },
            |keys| black_box(async { store.get_many_owned(keys).await.unwrap() }),
            BatchSize::SmallInput,
        )
    });

    group.finish();
}