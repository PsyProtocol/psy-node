use serde::{Deserialize, Serialize};

use crate::common::traits::serializable::{QPDPair, QPDSerializable};
use async_trait::async_trait;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QPDCheckpointedKey<Key: QPDSerializable> {
    pub key: Key,
    pub checkpoint_id: u64,
}

impl<Key: QPDSerializable> QPDCheckpointedKey<Key> {
    pub fn new(checkpoint_id: u64, key: Key) -> Self {
        Self {
            key,
            checkpoint_id,
        }
    }
}
impl<Key: QPDSerializable> QPDSerializable for QPDCheckpointedKey<Key> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes.extend(self.key.to_bytes()?);
        // big endian
        bytes.extend(&self.checkpoint_id.to_be_bytes());
        Ok(bytes)
    }
    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let bytes_len = bytes.len();
        if bytes_len < 8 {
            return Err(anyhow::anyhow!("bytes too short"));
        }
        let key = Key::from_bytes(&bytes[0..(bytes_len-8)])?;
        // big endian
        let checkpoint_id = u64::from_be_bytes(bytes[(bytes_len-8)..bytes_len].try_into().unwrap());
        Ok(Self {
            checkpoint_id,
            key,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QPDCheckpointedKV<Key: QPDSerializable, Value: QPDSerializable> {
    pub checkpoint_id: u64,
    pub key: Key,
    pub value: Value,
}

impl<Key: QPDSerializable, Value: QPDSerializable> QPDCheckpointedKV<Key, Value> {
    pub fn new(checkpoint_id: u64, key: Key, value: Value) -> Self {
        Self {
            checkpoint_id,
            key,
            value,
        }
    }
}
impl<Key: QPDSerializable, Value: QPDSerializable> QPDSerializable for QPDCheckpointedKV<Key, Value> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        // big endian
        bytes.extend(&self.checkpoint_id.to_be_bytes());
        bytes.extend(self.key.to_bytes()?);
        bytes.extend(self.value.to_bytes()?);
        Ok(bytes)
    }
    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() < 8 {
            return Err(anyhow::anyhow!("bytes too short"));
        }
        // big endian
        let checkpoint_id = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
        let key = Key::from_bytes(&bytes[8..])?;
        let value = Value::from_bytes(&bytes[8 + key.to_bytes()?.len()..])?;
        Ok(Self {
            checkpoint_id,
            key,
            value,
        })
    }
}


pub trait CheckpointedStoreReaderSync<Key: QPDSerializable, Value: QPDSerializable> {
    fn contains_key(&self, key: &Key) -> anyhow::Result<bool>;
    fn contains_keys(&self, keys: &[Key]) -> anyhow::Result<Vec<bool>>;

    // contains a value for the key at checkpoint_id >= max_checkpoint_id
    fn contains_key_leq_checkpoint(&self, max_checkpoint_id: u64, key: &Key) -> anyhow::Result<bool>;
    fn contains_keys_leq_checkpoint(&self, max_checkpoint_id: u64, keys: &[Key]) -> anyhow::Result<Vec<bool>>;

    // contains a key at exactly checkpoint_id
    fn contains_key_exact(&self, checkpoint_id: u64, key: &Key) -> anyhow::Result<bool>;
    fn contains_keys_exact(&self, checkpoint_id: u64, keys: &[Key]) -> anyhow::Result<Vec<bool>>;


    // anyhow error if not found
    fn get_value_latest(&self, key: &Key) -> anyhow::Result<Value>;
    fn get_value_latest_or_none(&self, key: &Key) -> anyhow::Result<Option<Value>>;
    fn get_value_latest_or(&self, key: &Key, default: Value) -> anyhow::Result<Value> {
        match self.get_value_latest_or_none(key)? {
            Some(v) => Ok(v),
            None => Ok(default),
        }
    }
    fn get_value_latest_and_checkpoint(&self, key: &Key) -> anyhow::Result<QPDCheckpointedKey<Key>>;
    fn get_value_latest_and_checkpoint_or_none(&self, key: &Key) -> anyhow::Result<Option<QPDCheckpointedKey<Key>>>;
    fn get_value_latest_and_checkpoint_or(&self, key: &Key, default: QPDCheckpointedKey<Key>) -> anyhow::Result<QPDCheckpointedKey<Key>> {
        match self.get_value_latest_and_checkpoint_or_none(key)? {
            Some(v) => Ok(v),
            None => Ok(default),
        }
    }
    
    fn get_value_exact(&self, checkpoint_id: u64, key: &Key) -> anyhow::Result<Value>;
    fn get_value_exact_or_none(&self, checkpoint_id: u64, key: &Key) -> anyhow::Result<Option<Value>>;
    fn get_value_exact_or(&self, checkpoint_id: u64, key: &Key, default: Value) -> anyhow::Result<Value> {
        match self.get_value_exact_or_none(checkpoint_id, key)? {
            Some(v) => Ok(v),
            None => Ok(default),
        }
    }

    fn get_values_exact(&self, checkpoint_id: u64, keys: &[Key]) -> anyhow::Result<Vec<Value>>;
    fn get_values_exact_or_none(&self, checkpoint_id: u64, keys: &[Key]) -> anyhow::Result<Vec<Option<Value>>>;
    fn get_values_exact_or(&self, checkpoint_id: u64, keys: &[Key], default: Value) -> anyhow::Result<Vec<Value>> {
        let mut results = Vec::new();
        for opt in self.get_values_exact_or_none(checkpoint_id, keys)? {
            match opt {
                Some(v) => results.push(v),
                None => results.push(default.clone()),
            }
        }
        Ok(results)
    }
    fn get_value_leq_checkpoint(&self, max_checkpoint_id: u64, key: &Key) -> anyhow::Result<Value>;
    fn get_value_leq_checkpoint_or_none(&self, max_checkpoint_id: u64, key: &Key) -> anyhow::Result<Option<Value>>;
    fn get_value_leq_checkpoint_or(&self, max_checkpoint_id: u64, key: &Key, default: Value) -> anyhow::Result<Value> {
        match self.get_value_leq_checkpoint_or_none(max_checkpoint_id, key)? {
            Some(v) => Ok(v),
            None => Ok(default),
        }
    }
    fn get_values_leq_checkpoint(&self, max_checkpoint_id: u64, keys: &[Key]) -> anyhow::Result<Vec<Value>>;
    fn get_values_leq_checkpoint_or_none(&self, max_checkpoint_id: u64, keys: &[Key]) -> anyhow::Result<Vec<Option<Value>>>;
    fn get_values_leq_checkpoint_or(&self, max_checkpoint_id: u64, keys: &[Key], default: Value) -> anyhow::Result<Vec<Value>> {
        let mut results = Vec::new();
        for opt in self.get_values_leq_checkpoint_or_none(max_checkpoint_id, keys)? {
            match opt {
                Some(v) => results.push(v),
                None => results.push(default.clone()),
            }
        }
        Ok(results)
    }

    fn get_kvs_latest(&self, keys: &[Key]) -> anyhow::Result<Vec<QPDPair<Key, Value>>>;
    fn get_kvs_latest_or_none(&self, keys: &[Key]) -> anyhow::Result<Vec<Option<QPDPair<Key, Value>>>>;
    fn get_kvs_latest_or(&self, keys: &[Key], default: QPDPair<Key, Value>) -> anyhow::Result<Vec<QPDPair<Key, Value>>> {
        let mut results = Vec::new();
        for opt in self.get_kvs_latest_or_none(keys)? {
            match opt {
                Some(v) => results.push(v),
                None => results.push(default.clone()),
            }
        }
        Ok(results)
    }



}
pub trait CheckpointedStoreWriterSyncMut<Key: QPDSerializable, Value: QPDSerializable> {
    fn set_value_mut(&mut self, key: &Key, value: &Value) -> anyhow::Result<()>;
    fn set_many_mut(&mut self, entries: &[QPDPair<Key, Value>]) -> anyhow::Result<()>;
    fn set_many_split_mut(&mut self, keys: &[Key], values: &[Value]) -> anyhow::Result<()>;
    fn delete_mut(&mut self, key: &Key) -> anyhow::Result<()>;
    fn delete_many_mut(&mut self, keys: &[Key]) -> anyhow::Result<()>;
}
pub trait CheckpointedStoreWriterSyncImm<Key: QPDSerializable, Value: QPDSerializable> {
    fn set_value_imm(&self, key: &Key, value: &Value) -> anyhow::Result<()>;
    fn set_many_imm(&self, entries: &[QPDPair<Key, Value>]) -> anyhow::Result<()>;
    fn set_many_split_imm(&self, keys: &[Key], values: &[Value]) -> anyhow::Result<()>;
    fn delete_imm(&self, key: &Key) -> anyhow::Result<()>;
    fn delete_many_imm(&self, keys: &[Key]) -> anyhow::Result<()>;
}

pub trait CheckpointedStoreSyncMut<Key: QPDSerializable, Value: QPDSerializable>: CheckpointedStoreReaderSync<Key, Value> + CheckpointedStoreWriterSyncMut<Key, Value> {
}


pub trait CheckpointedStoreSyncImm<Key: QPDSerializable, Value: QPDSerializable>: CheckpointedStoreReaderSync<Key, Value> + CheckpointedStoreWriterSyncImm<Key, Value> {
}

#[async_trait]
pub trait CheckpointedStoreReaderAsync<Key: QPDSerializable + Send + Sync, Value: QPDSerializable + Send + Sync> {
    async fn contains_key_async(&self, key: &Key) -> anyhow::Result<bool>;
    async fn contains_keys_async(&self, keys: &[Key]) -> anyhow::Result<Vec<bool>>;

    // Contains a value for the key at checkpoint_id >= max_checkpoint_id
    async fn contains_key_leq_checkpoint_async(&self, max_checkpoint_id: u64, key: &Key) -> anyhow::Result<bool>;
    async fn contains_keys_leq_checkpoint_async(&self, max_checkpoint_id: u64, keys: &[Key]) -> anyhow::Result<Vec<bool>>;

    // Contains a key at exactly checkpoint_id
    async fn contains_key_exact_async(&self, checkpoint_id: u64, key: &Key) -> anyhow::Result<bool>;
    async fn contains_keys_exact_async(&self, checkpoint_id: u64, keys: &[Key]) -> anyhow::Result<Vec<bool>>;

    // Returns error if not found
    async fn get_value_latest_async(&self, key: &Key) -> anyhow::Result<Value>;
    async fn get_value_latest_or_none_async(&self, key: &Key) -> anyhow::Result<Option<Value>>;
    async fn get_value_latest_or_async(&self, key: &Key, default: Value) -> anyhow::Result<Value>;
    async fn get_value_latest_and_checkpoint_async(&self, key: &Key) -> anyhow::Result<QPDCheckpointedKey<Key>>;
    async fn get_value_latest_and_checkpoint_or_none_async(&self, key: &Key) -> anyhow::Result<Option<QPDCheckpointedKey<Key>>>;
    async fn get_value_latest_and_checkpoint_or_async(&self, key: &Key, default: QPDCheckpointedKey<Key>) -> anyhow::Result<QPDCheckpointedKey<Key>>;

    async fn get_value_exact_async(&self, checkpoint_id: u64, key: &Key) -> anyhow::Result<Value>;
    async fn get_value_exact_or_none_async(&self, checkpoint_id: u64, key: &Key) -> anyhow::Result<Option<Value>>;
    async fn get_value_exact_or_async(&self, checkpoint_id: u64, key: &Key, default: Value) -> anyhow::Result<Value>;
    async fn get_values_exact_async(&self, checkpoint_id: u64, keys: &[Key]) -> anyhow::Result<Vec<Value>>;
    async fn get_values_exact_or_none_async(&self, checkpoint_id: u64, keys: &[Key]) -> anyhow::Result<Vec<Option<Value>>>;
    async fn get_values_exact_or_async(&self, checkpoint_id: u64, keys: &[Key], default: Value) -> anyhow::Result<Vec<Value>>;

    async fn get_value_leq_checkpoint_async(&self, max_checkpoint_id: u64, key: &Key) -> anyhow::Result<Value>;
    async fn get_value_leq_checkpoint_or_none_async(&self, max_checkpoint_id: u64, key: &Key) -> anyhow::Result<Option<Value>>;
    async fn get_value_leq_checkpoint_or_async(&self, max_checkpoint_id: u64, key: &Key, default: Value) -> anyhow::Result<Value>;

    async fn get_values_leq_checkpoint_async(&self, max_checkpoint_id: u64, keys: &[Key]) -> anyhow::Result<Vec<Value>>;
    async fn get_values_leq_checkpoint_or_none_async(&self, max_checkpoint_id: u64, keys: &[Key]) -> anyhow::Result<Vec<Option<Value>>>;
    async fn get_values_leq_checkpoint_or_async(&self, max_checkpoint_id: u64, keys: &[Key], default: Value) -> anyhow::Result<Vec<Value>>;

    async fn get_kvs_latest_async(&self, keys: &[Key]) -> anyhow::Result<Vec<QPDPair<Key, Value>>>;
    async fn get_kvs_latest_or_none_async(&self, keys: &[Key]) -> anyhow::Result<Vec<Option<QPDPair<Key, Value>>>>;
    async fn get_kvs_latest_or_async(&self, keys: &[Key], default: QPDPair<Key, Value>) -> anyhow::Result<Vec<QPDPair<Key, Value>>>;
}

#[async_trait]
pub trait CheckpointedStoreWriterAsyncMut<Key: QPDSerializable + Send + Sync, Value: QPDSerializable + Send + Sync> {
    async fn set_value_mut_async(&mut self, key: &Key, value: &Value) -> anyhow::Result<()>;
    async fn set_many_mut_async(&mut self, entries: &[QPDPair<Key, Value>]) -> anyhow::Result<()>;
    async fn set_many_split_mut_async(&mut self, keys: &[Key], values: &[Value]) -> anyhow::Result<()>;
    async fn delete_mut_async(&mut self, key: &Key) -> anyhow::Result<()>;
    async fn delete_many_mut_async(&mut self, keys: &[Key]) -> anyhow::Result<()>;
}

#[async_trait]
pub trait CheckpointedStoreWriterAsyncImm<Key: QPDSerializable + Send + Sync, Value: QPDSerializable + Send + Sync> {
    async fn set_value_imm_async(&self, key: &Key, value: &Value) -> anyhow::Result<()>;
    async fn set_many_imm_async(&self, entries: &[QPDPair<Key, Value>]) -> anyhow::Result<()>;
    async fn set_many_split_imm_async(&self, keys: &[Key], values: &[Value]) -> anyhow::Result<()>;
    async fn delete_imm_async(&self, key: &Key) -> anyhow::Result<()>;
    async fn delete_many_imm_async(&self, keys: &[Key]) -> anyhow::Result<()>;
}

#[async_trait]
pub trait CheckpointedStoreAsyncMut<Key: QPDSerializable + Send + Sync, Value: QPDSerializable + Send + Sync>:
    CheckpointedStoreReaderAsync<Key, Value> + CheckpointedStoreWriterAsyncMut<Key, Value>
{
}

#[async_trait]
pub trait CheckpointedStoreAsyncImm<Key: QPDSerializable + Send + Sync, Value: QPDSerializable + Send + Sync>:
    CheckpointedStoreReaderAsync<Key, Value> + CheckpointedStoreWriterAsyncImm<Key, Value>
{
}