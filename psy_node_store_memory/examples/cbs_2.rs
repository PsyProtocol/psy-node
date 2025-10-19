use anyhow::anyhow;
use crossbeam_skiplist::SkipMap;
use hex_literal::hex;
use std::sync::Arc;

pub trait KeyValueSerializable: Sized + Clone {
    fn to_serialized_bytes(&self) -> Vec<u8>;
    fn from_serialized_bytes(bytes: &[u8]) -> anyhow::Result<Self>;
}

// Implement for String for demonstration purposes
impl KeyValueSerializable for String {
    fn to_serialized_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    fn from_serialized_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        String::from_utf8(bytes.to_vec()).map_err(|e| anyhow!(e))
    }
}

#[derive(Clone)]
pub struct MyExampleStore {
    store: Arc<SkipMap<Vec<u8>, Vec<u8>>>,
}

impl MyExampleStore {
    pub fn new() -> Self {
        Self {
            store: Arc::new(SkipMap::new()),
        }
    }
}

impl ExampleStore for MyExampleStore {
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

    fn insert_checkpointed_value<V: KeyValueSerializable>(&self, key_prefix: &[u8], version: u64, value: &V) {
        let mut key = key_prefix.to_vec();
        key.extend_from_slice(&version.to_be_bytes());
        self.insert_value(&key, value);
    }

    fn get_checkpointed_value<V: KeyValueSerializable>(&self, key_prefix: &[u8], max_version: u64) -> Option<V> {
        let mut start_key = key_prefix.to_vec();
        start_key.extend_from_slice(&0u64.to_be_bytes());

        let mut end_key = key_prefix.to_vec();
        end_key.extend_from_slice(&max_version.to_be_bytes());

        self.store
            .range(start_key..=end_key)
            .last()
            .and_then(|entry| V::from_serialized_bytes(entry.value()).ok())
    }
}

#[tokio::main]
async fn main() {
    let store = MyExampleStore::new();

    // Insert some data
    store.insert_checkpointed_value(
        &hex!("1122334455667788"),
        3,
        &"hello world".to_string(),
    );
    store.insert_checkpointed_value(
        &hex!("1122334455667788"),
        9,
        &"good bye".to_string(),
    );
    store.insert_checkpointed_value(
        &hex!("1122334455667788"),
        255,
        &"nice to meet you".to_string(),
    );
    store.insert_checkpointed_value(
        &hex!("1122334455667722"),
        0,
        &"sup dawg".to_string(),
    );
     store.insert_checkpointed_value(
        &hex!("1122334455667789"),
        0,
        &"foobar".to_string(),
    );


    // Perform a range query
    let result = store.get_checkpointed_value::<String>(
        &hex!("1122334455667788"),
        100, // Get the latest version up to version 100
    );

    assert_eq!(result, Some("good bye".to_string()));
    println!("Found value: {:?}", result);

    let result2 = store.get_checkpointed_value::<String>(
        &hex!("1122334455667788"),
        2, // Get the latest version up to version 2 (none exists)
    );
     assert_eq!(result2, None);
     println!("Found value: {:?}", result2);


     let result3 = store.get_checkpointed_value::<String>(
        &hex!("1122334455667788"),
        u64::MAX, // Get the latest version
    );
    assert_eq!(result3, Some("nice to meet you".to_string()));
    println!("Found value: {:?}", result3);
}

pub trait ExampleStore {
    fn get_raw_value(&self, key: &[u8]) -> Option<Vec<u8>>;
    fn insert_raw_value(&self, key: &[u8], value: &[u8]);
    fn get_value<V: KeyValueSerializable>(&self, key: &[u8]) -> Option<V>;
    fn insert_value<V: KeyValueSerializable>(&self, key: &[u8], value: &V);
    fn insert_checkpointed_value<V: KeyValueSerializable>(&self, key_prefix: &[u8], version: u64, value: &V);
    fn get_checkpointed_value<V: KeyValueSerializable>(&self, key_prefix: &[u8], max_version: u64) -> Option<V>;
}



#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use serde::{Deserialize, Serialize};
    use std::time::Duration;

    // A helper function to set up a store with predefined data for tests.
    fn setup_store() -> MyExampleStore {
        let store = MyExampleStore::new();

        // Key Prefix 1: 1122...7788
        store.insert_checkpointed_value(
            &hex!("1122334455667788"),
            3,
            &"hello world".to_string(),
        );
        store.insert_checkpointed_value(
            &hex!("1122334455667788"),
            9,
            &"good bye".to_string(),
        );
        store.insert_checkpointed_value(
            &hex!("1122334455667788"),
            255,
            &"nice to meet you".to_string(),
        );

        // Key Prefix 2: 1122...7722
        store.insert_checkpointed_value(
            &hex!("1122334455667722"),
            0,
            &"sup dawg".to_string(),
        );

        // Key Prefix 3: 1122...7789
        store.insert_checkpointed_value(
            &hex!("1122334455667789"),
            0,
            &"foobar".to_string(),
        );

        store
    }

    #[test]
    fn test_raw_insert_and_get() {
        let store = MyExampleStore::new();
        let key = b"raw_key";
        let value = b"raw_value";

        // Test getting a non-existent value
        assert_eq!(store.get_raw_value(key), None);

        // Test inserting and then getting the value
        store.insert_raw_value(key, value);
        assert_eq!(store.get_raw_value(key), Some(value.to_vec()));
    }

    #[test]
    fn test_serializable_insert_and_get() {
        let store = MyExampleStore::new();
        let key = b"string_key";
        let value = "this is a string value".to_string();

        // Test getting a non-existent value
        assert_eq!(store.get_value::<String>(key), None);

        // Test inserting and then getting the value
        store.insert_value(key, &value);
        assert_eq!(store.get_value::<String>(key), Some(value));
    }

    #[test]
    fn test_get_checkpointed_value_latest() {
        let store = setup_store();
        let key_prefix = &hex!("1122334455667788");

        // Requesting with a max_version that is higher than any existing version
        // should return the value of the highest available version (255).
        let result = store.get_checkpointed_value::<String>(key_prefix, u64::MAX);
        assert_eq!(result, Some("nice to meet you".to_string()));
    }

    #[test]
    fn test_get_checkpointed_value_in_between() {
        let store = setup_store();
        let key_prefix = &hex!("1122334455667788");

        // Requesting with a max_version of 100 should return the value
        // from the highest key with version <= 100, which is version 9.
        let result = store.get_checkpointed_value::<String>(key_prefix, 100);
        assert_eq!(result, Some("good bye".to_string()));
    }

    #[test]
    fn test_get_checkpointed_value_exact_match() {
        let store = setup_store();
        let key_prefix = &hex!("1122334455667788");

        // Requesting with a max_version that exactly matches an existing version
        // should return the value of that version.
        let result = store.get_checkpointed_value::<String>(key_prefix, 9);
        assert_eq!(result, Some("good bye".to_string()));
    }

    #[test]
    fn test_get_checkpointed_value_before_first() {
        let store = setup_store();
        let key_prefix = &hex!("1122334455667788");

        // Requesting with a max_version lower than any existing version
        // for that prefix should return None.
        let result = store.get_checkpointed_value::<String>(key_prefix, 2);
        assert_eq!(result, None);
    }

    #[test]
    fn test_get_checkpointed_value_non_existent_prefix() {
        let store = setup_store();
        let key_prefix = &hex!("0000000000000000");

        // Requesting a value for a key prefix that has no entries should return None.
        let result = store.get_checkpointed_value::<String>(key_prefix, u64::MAX);
        assert_eq!(result, None);
    }

    #[test]
    fn test_get_checkpointed_value_single_version() {
        let store = setup_store();
        let key_prefix = &hex!("1122334455667722");

        // Test on a key prefix that only has one version.
        let result = store.get_checkpointed_value::<String>(key_prefix, u64::MAX);
        assert_eq!(result, Some("sup dawg".to_string()));

        // Test getting that single version with an exact match
        let result_exact = store.get_checkpointed_value::<String>(key_prefix, 0);
        assert_eq!(result_exact, Some("sup dawg".to_string()));
    }

    // -- Test with a custom struct to ensure generics work --

    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    struct UserProfile {
        id: u32,
        username: String,
        is_active: bool,
    }

    impl KeyValueSerializable for UserProfile {
        fn to_serialized_bytes(&self) -> Vec<u8> {
            bincode::serialize(self).unwrap()
        }

        fn from_serialized_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
            bincode::deserialize(bytes).map_err(|e| anyhow!(e))
        }
    }

    #[test]
    fn test_checkpointed_with_custom_struct() {
        let store = MyExampleStore::new();
        let key_prefix = b"user_profile_123";

        let profile_v1 = UserProfile {
            id: 123,
            username: "testuser".to_string(),
            is_active: false,
        };

        let profile_v2 = UserProfile {
            id: 123,
            username: "testuser".to_string(),
            is_active: true, // User is now active
        };

        store.insert_checkpointed_value(key_prefix, 10, &profile_v1);
        store.insert_checkpointed_value(key_prefix, 20, &profile_v2);

        // Get the latest version
        assert_eq!(
            store.get_checkpointed_value::<UserProfile>(key_prefix, 100),
            Some(profile_v2.clone())
        );

        // Get the version at time 15 (should be v1)
        assert_eq!(
            store.get_checkpointed_value::<UserProfile>(key_prefix, 15),
            Some(profile_v1.clone())
        );

        // Get the version at time 5 (should be None)
        assert_eq!(
            store.get_checkpointed_value::<UserProfile>(key_prefix, 5),
            None
        );
    }

    // -- Concurrency Test --

    #[tokio::test]
    async fn test_concurrent_reads_and_writes() {
        let store = setup_store();
        let key_prefix = Arc::new(hex!("1122334455667788").to_vec());

        let mut handles = vec![];

        // Spawn reader tasks
        for _ in 0..10 {
            let store_clone = store.clone();
            let key_prefix_clone = Arc::clone(&key_prefix);
            handles.push(tokio::spawn(async move {
                // Readers will continuously query for the latest value up to version 100.
                // They should consistently get "good bye".
                let value = store_clone.get_checkpointed_value::<String>(&key_prefix_clone, 100);
                assert_eq!(value, Some("good bye".to_string()));
                tokio::time::sleep(Duration::from_millis(10)).await;
                let value_latest = store_clone.get_checkpointed_value::<String>(&key_prefix_clone, u64::MAX);
                // Depending on when this runs, it could be the old or new value.
                assert!(value_latest.is_some());
            }));
        }

        // Spawn a writer task that adds a new, later version after a short delay
        let store_clone = store.clone();
        let key_prefix_clone = Arc::clone(&key_prefix);
        handles.push(tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(5)).await;
            store_clone.insert_checkpointed_value(
                &key_prefix_clone,
                300,
                &"a new concurrent value".to_string(),
            );
        }));

        // Wait for all tasks to complete
        for handle in handles {
            handle.await.unwrap();
        }

        // After all tasks are done, verify the final state.
        // The new value written by the writer task should now be the latest.
        let final_value = store.get_checkpointed_value::<String>(&key_prefix, u64::MAX);
        assert_eq!(final_value, Some("a new concurrent value".to_string()));

        // The value at version 100 should remain unchanged.
        let historical_value = store.get_checkpointed_value::<String>(&key_prefix, 100);
        assert_eq!(historical_value, Some("good bye".to_string()));
    }
}