use anyhow::Context;
use crossbeam_skiplist::SkipMap;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use hex_literal::hex; // <-- FIX: Import from the correct crate for the main function

// A trait for types that can be serialized to and from bytes for the KV store.
// Using bincode here for simplicity.
pub trait KeyValueSerializable: Sized + Clone + Serialize + DeserializeOwned {
    fn to_serialized_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    fn from_serialized_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).context("Failed to deserialize value")
    }
}

// Blanket implementation for any type that meets the bounds.
impl<T: Sized + Clone + Serialize + DeserializeOwned> KeyValueSerializable for T {}

// The definition of our store trait.
pub trait ExampleStore: Send + Sync {
    fn get_raw_value(&self, key: &[u8]) -> Option<Vec<u8>>;
    fn insert_raw_value(&self, key: &[u8], value: &[u8]);
    fn get_value<V: KeyValueSerializable>(&self, key: &[u8]) -> Option<V>;
    fn insert_value<V: KeyValueSerializable>(&self, key: &[u8], value: &V);
    fn insert_checkpointed_value<V: KeyValueSerializable>(
        &self,
        key_prefix: &[u8],
        version: u64,
        value: &V,
    );
    fn get_checkpointed_value<V: KeyValueSerializable>(
        &self,
        key_prefix: &[u8],
        max_version: u64,
    ) -> Option<V>;
}

// Our implementation using crossbeam_skiplist::SkipMap
#[derive(Debug, Clone)]
pub struct ExampleSkipListStore {
    store: Arc<SkipMap<Vec<u8>, Vec<u8>>>,
}

impl ExampleSkipListStore {
    pub fn new() -> Self {
        Self {
            store: Arc::new(SkipMap::new()),
        }
    }
}

impl ExampleStore for ExampleSkipListStore {
    fn get_raw_value(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.store.get(key).map(|entry| entry.value().clone())
    }

    fn insert_raw_value(&self, key: &[u8], value: &[u8]) {
        self.store.insert(key.to_vec(), value.to_vec());
    }

    fn get_value<V: KeyValueSerializable>(&self, key: &[u8]) -> Option<V> {
        self.get_raw_value(key)
            .and_then(|bytes| V::from_serialized_bytes(&bytes).ok())
    }

    fn insert_value<V: KeyValueSerializable>(&self, key: &[u8], value: &V) {
        self.insert_raw_value(key, &value.to_serialized_bytes());
    }

    fn insert_checkpointed_value<V: KeyValueSerializable>(
        &self,
        key_prefix: &[u8],
        version: u64,
        value: &V,
    ) {
        let mut key = Vec::with_capacity(key_prefix.len() + 8);
        key.extend_from_slice(key_prefix);
        key.extend_from_slice(&version.to_be_bytes());
        self.insert_value(&key, value);
    }

    fn get_checkpointed_value<V: KeyValueSerializable>(
        &self,
        key_prefix: &[u8],
        max_version: u64,
    ) -> Option<V> {
        let mut start_key = Vec::with_capacity(key_prefix.len() + 8);
        start_key.extend_from_slice(key_prefix);
        start_key.extend_from_slice(&0u64.to_be_bytes());

        let mut end_key = Vec::with_capacity(key_prefix.len() + 8);
        end_key.extend_from_slice(key_prefix);
        end_key.extend_from_slice(&max_version.to_be_bytes());

        self.store
            .range(start_key..=end_key)
            .next_back()
            .and_then(|entry| V::from_serialized_bytes(entry.value()).ok())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct MyValue {
    message: String,
    data: u32,
}

#[tokio::main]
async fn main() {
    let store = Arc::new(ExampleSkipListStore::new());
    let key_prefix = hex!("1122334455667788");

    let mut handles = vec![];
    for i in 0..5 {
        let store_clone = Arc::clone(&store);
        let handle = tokio::spawn(async move {
            // FIX: Explicitly cast `i` to u64 for the version.
            let version = 100 + i as u64;
            let value = MyValue {
                message: format!("Hello from task {}", i),
                // FIX: Explicitly cast `i` to u32 for the data field.
                data: i as u32,
            };
            println!(
                "THREAD {}: Inserting value for key_prefix with version {}",
                i, version
            );
            store_clone.insert_checkpointed_value(&key_prefix, version, &value);
            sleep(Duration::from_millis(10)).await;
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }

    println!("\n----- All values inserted -----");
    println!("Store contains {} entries.", store.store.len());
    println!("\n----- Performing Queries -----");

    println!("Querying for latest value at version 99...");
    let val_at_99 = store.get_checkpointed_value::<MyValue>(&key_prefix, 99);
    assert_eq!(val_at_99, None);
    println!("Result: None (Correct)\n");

    println!("Querying for latest value at version 100...");
    let val_at_100 = store.get_checkpointed_value::<MyValue>(&key_prefix, 100).unwrap();
    assert_eq!(val_at_100.data, 0);
    println!("Result: {:?} (Correct)\n", val_at_100);

    println!("Querying for latest value at version 102...");
    let val_at_102 = store.get_checkpointed_value::<MyValue>(&key_prefix, 102).unwrap();
    assert_eq!(val_at_102.data, 2);
    println!("Result: {:?} (Correct)\n", val_at_102);

    println!("Querying for latest value at version 500...");
    let val_at_500 = store.get_checkpointed_value::<MyValue>(&key_prefix, 500).unwrap();
    assert_eq!(val_at_500.data, 4);
    println!("Result: {:?} (Correct)\n", val_at_500);
}


#[cfg(test)]
mod tests {
    use super::*;
    // FIX: Import `hex` macro from the correct crate for tests.
    use hex_literal::hex;
    use std::thread;

    fn setup() -> ExampleSkipListStore {
        ExampleSkipListStore::new()
    }

    #[test]
    fn test_raw_insert_and_get() {
        let store = setup();
        let key = b"hello";
        let value = b"world";
        assert_eq!(store.get_raw_value(key), None);
        store.insert_raw_value(key, value);
        let retrieved = store.get_raw_value(key).expect("Value should exist");
        assert_eq!(retrieved, value);
    }

    #[test]
    fn test_serialized_insert_and_get() {
        let store = setup();
        let key = b"user:123";
        let value = MyValue {
            message: "Test Message".to_string(),
            data: 42,
        };
        assert_eq!(store.get_value::<MyValue>(key), None);
        store.insert_value(key, &value);
        let retrieved = store
            .get_value::<MyValue>(key)
            .expect("Value should deserialize correctly");
        assert_eq!(retrieved, value);
    }

    #[test]
    fn test_checkpointed_get_latest_value() {
        let store = setup();
        let key_prefix = hex!("DEADBEEF");
        store.insert_checkpointed_value(&key_prefix, 10, &MyValue { message: "v10".into(), data: 10 });
        store.insert_checkpointed_value(&key_prefix, 30, &MyValue { message: "v30".into(), data: 30 });
        store.insert_checkpointed_value(&key_prefix, 20, &MyValue { message: "v20".into(), data: 20 });
        let result = store.get_checkpointed_value::<MyValue>(&key_prefix, 5);
        assert_eq!(result, None);
        let result = store.get_checkpointed_value::<MyValue>(&key_prefix, 10).unwrap();
        assert_eq!(result.data, 10);
        let result = store.get_checkpointed_value::<MyValue>(&key_prefix, 25).unwrap();
        assert_eq!(result.data, 20);
        let result = store.get_checkpointed_value::<MyValue>(&key_prefix, 30).unwrap();
        assert_eq!(result.data, 30);
        let result = store.get_checkpointed_value::<MyValue>(&key_prefix, 999).unwrap();
        assert_eq!(result.data, 30);
    }
    
    #[test]
    fn test_checkpointed_key_isolation() {
        let store = setup();
        let key_prefix_1 = hex!("AAAA");
        let key_prefix_2 = hex!("BBBB");
        store.insert_checkpointed_value(&key_prefix_1, 100, &MyValue { message: "key1-v100".into(), data: 1100 });
        store.insert_checkpointed_value(&key_prefix_2, 150, &MyValue { message: "key2-v150".into(), data: 2150 });
        store.insert_checkpointed_value(&key_prefix_1, 200, &MyValue { message: "key1-v200".into(), data: 1200 });
        let result1 = store.get_checkpointed_value::<MyValue>(&key_prefix_1, 999).unwrap();
        assert_eq!(result1.data, 1200);
        let result2 = store.get_checkpointed_value::<MyValue>(&key_prefix_2, 999).unwrap();
        assert_eq!(result2.data, 2150);
        let result3 = store.get_checkpointed_value::<MyValue>(&key_prefix_2, 100);
        assert_eq!(result3, None);
    }

    #[test]
    fn test_checkpointed_overwrite_version() {
        let store = setup();
        let key_prefix = hex!("CAFE");
        store.insert_checkpointed_value(&key_prefix, 50, &MyValue { message: "first".into(), data: 1 });
        let result1 = store.get_checkpointed_value::<MyValue>(&key_prefix, 100).unwrap();
        assert_eq!(result1.message, "first");
        store.insert_checkpointed_value(&key_prefix, 50, &MyValue { message: "second".into(), data: 2 });
        let result2 = store.get_checkpointed_value::<MyValue>(&key_prefix, 100).unwrap();
        assert_eq!(result2.message, "second");
        assert_eq!(result2.data, 2);
    }

    #[test]
    fn concurrency_smoke_test() {
        let store = Arc::new(setup());
        let num_threads = 8;
        let inserts_per_thread = 100;

        let mut handles = vec![];

        for i in 0..num_threads {
            let store_clone = Arc::clone(&store);
            let handle = thread::spawn(move || {
                // Each thread gets its own key prefix to avoid overwriting
                let mut key_prefix = vec![0u8; 4];
                
                // FIX: Explicitly cast `i` to `u32` to match the 4-byte buffer.
                // This resolves the ambiguity and prevents a potential runtime panic.
                key_prefix.copy_from_slice(&(i as u32).to_be_bytes());

                for j in 0..inserts_per_thread {
                    let version = j as u64;
                    let value = MyValue { message: format!("t{}-v{}", i, j), data: (i * 1000 + j) as u32 };
                    store_clone.insert_checkpointed_value(&key_prefix, version, &value);
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Verification
        assert_eq!(store.store.len(), num_threads * inserts_per_thread, "All items should be present in the store");

        for i in 0..num_threads {
            let mut key_prefix = vec![0u8; 4];
            
            // FIX: Use the same cast here for consistency during verification.
            key_prefix.copy_from_slice(&(i as u32).to_be_bytes());
            
            let latest_version = (inserts_per_thread - 1) as u64;
            let expected_data = (i * 1000 + latest_version as usize) as u32;

            let value = store.get_checkpointed_value::<MyValue>(&key_prefix, latest_version)
                .expect("Last value for thread should exist");

            assert_eq!(value.data, expected_data, "Mismatch in data for thread {}", i);
        }
    }
}