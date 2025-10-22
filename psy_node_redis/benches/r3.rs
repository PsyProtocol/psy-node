
use anyhow::Result;
use async_trait::async_trait;
use criterion::{
 black_box, Criterion, Throughput,
};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use redis::{aio::MultiplexedConnection, AsyncCommands};

//==================================================================================//
// START: Library Code (QKVStore implementation)
//==================================================================================//

#[async_trait]
pub trait QKVStoreBase {
    async fn put_owned(&self, key: Vec<u8>, value: Vec<u8>) -> Result<()>;
    async fn put_many_tuples_owned(&self, items: Vec<(Vec<u8>, Vec<u8>)>) -> Result<()>;
    async fn get_owned(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>>;
    async fn get_many_owned(&self, keys: Vec<Vec<u8>>) -> Result<Vec<Option<Vec<u8>>>>;
}

#[derive(Clone)]
pub struct QKVStore {
    conn: MultiplexedConnection,
}

impl QKVStore {
    pub async fn new(connection_string: &str) -> Result<Self> {
        let client = redis::Client::open(connection_string)?;
        let conn = client.get_multiplexed_async_connection().await?;
        Ok(QKVStore { conn })
    }
}

#[async_trait]
impl QKVStoreBase for QKVStore {
    async fn put_owned(&self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        let mut conn = self.conn.clone();
        conn.set(key, value).await?;
        Ok(())
    }

    async fn put_many_tuples_owned(&self, items: Vec<(Vec<u8>, Vec<u8>)>) -> Result<()> {
        let mut conn = self.conn.clone();
        let item_slices: Vec<(&[u8], &[u8])> =
            items.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect();
        redis::pipe().mset(&item_slices).query_async(&mut conn).await?;
        Ok(())
    }

    async fn get_owned(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>> {
        let mut conn = self.conn.clone();
        let value: Option<Vec<u8>> = conn.get(key).await?;
        Ok(value)
    }

    async fn get_many_owned(&self, keys: Vec<Vec<u8>>) -> Result<Vec<Option<Vec<u8>>>> {
        let mut conn = self.conn.clone();
        let values: Vec<Option<Vec<u8>>> = conn.get(keys).await?;
        Ok(values)
    }
}

//==================================================================================//
// END: Library Code
//==================================================================================//


//==================================================================================//
// START: Benchmark Code
//==================================================================================//

/// Generates a random alphanumeric string of a given length.
fn generate_random_string(len: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

/// Generates a vector of random key-value pairs.
fn generate_kv_data(count: usize, key_len: usize, val_len: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
    (0..count)
        .map(|_| {
            (
                generate_random_string(key_len).into_bytes(),
                generate_random_string(val_len).into_bytes(),
            )
        })
        .collect()
}

/// Defines the benchmark suite.
pub fn kv_store_benches(c: &mut Criterion) {
    // --- Setup ---
    const CONNECTION_STRING: &str = "redis://127.0.0.1:6379/";
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let store = runtime.block_on(QKVStore::new(CONNECTION_STRING)).unwrap();

    // --- Single Operation Benchmarks (Latency-Bound) ---
    let mut group = c.benchmark_group("Single Operations");

    let rt = tokio::runtime::Runtime::new().unwrap();
    // Benchmark a single PUT operation
    group.bench_function("put_single", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap()  ).iter_batched(
            || generate_kv_data(1, 16, 128)[0].clone(), // Setup: generate one KV pair
            |kv| async {
                store.put_owned(kv.0, kv.1).await.unwrap();
            }, // The routine to benchmark
            criterion::BatchSize::NumBatches(1000)
        );
    });

    // Benchmark a single GET operation
    group.bench_function("get_single", |b| {
        let data = generate_kv_data(1, 16, 128);
        runtime.block_on(store.put_owned(data[0].0.clone(), data[0].1.clone())).unwrap();
        b.to_async(tokio::runtime::Runtime::new().unwrap() ).iter_batched(
            || data[0].0.clone(), // Setup: provide the key to get
            |key| async {
                let _ = store.get_owned(key).await.unwrap();
            }, // The routine to benchmark
            criterion::BatchSize::NumBatches(1000)
        );
    });

    group.finish();

    // --- Batch Operation Benchmarks (Throughput-Bound) ---
    const BATCH_SIZE: u64 = 1_000;
    let mut group = c.benchmark_group("Batch Operations");

    // Set the throughput to be measured in "elements" (i.e., keys) per second.
    group.throughput(Throughput::Elements(BATCH_SIZE));

    // Benchmark a batch PUT of 1000 items.
    group.bench_function("put_batch_1000", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap() ).iter_batched(
            || generate_kv_data(BATCH_SIZE as usize, 16, 128), // Setup: Generate 1000 KV pairs
            |items| async {
                store.put_many_tuples_owned(black_box(items)).await.unwrap();
            }, // The routine to benchmark
            criterion::BatchSize::NumBatches(1000)
        );
    });

    // Benchmark a batch GET of 1000 items.
    group.bench_function("get_batch_1000", |b| {
        // Pre-load the data for the GET benchmark
        let data = generate_kv_data(BATCH_SIZE as usize, 16, 128);
        runtime.block_on(store.put_many_tuples_owned(data.clone())).unwrap();
        let keys: Vec<Vec<u8>> = data.into_iter().map(|(k, _)| k).collect();

        b.to_async(tokio::runtime::Runtime::new().unwrap() ).iter_batched(
            || keys.clone(), // Setup: provide the keys to fetch
            |keys_to_get| async {
                let _ = store.get_many_owned(black_box(keys_to_get)).await.unwrap();
            }, // The routine to benchmark
            criterion::BatchSize::NumBatches(1000)
        );
    });

    group.finish();
}