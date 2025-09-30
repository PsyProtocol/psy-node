use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use async_trait::async_trait;

use anyhow::{anyhow, Result};
use crate::common::core::{serializable::{QPDPair, QPDSerializable, QPDSerializableFixed}, store::qpd_store::{unwrap_kv_result, unwrap_kv_vec_result, QPDBinaryStoreReaderAsync, QPDBinaryStoreWriterAsync}};

// use this!!!
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QPDCheckpointedKey<Key: QPDSerializable> {
    pub checkpoint_id: u64,
    pub key: Key,
}

impl<Key: QPDSerializable> QPDCheckpointedKey<Key> {
    pub fn new(checkpoint_id: u64, key: Key) -> Self {
        Self {
            checkpoint_id,
            key,
        }
    }
}
impl<Key: QPDSerializable> QPDSerializable for QPDCheckpointedKey<Key> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        // big endian
        bytes.extend(&self.checkpoint_id.to_be_bytes());
        bytes.extend(self.key.to_bytes()?);
        Ok(bytes)
    }
    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() < 8 {
            return Err(anyhow::anyhow!("bytes too short"));
        }
        // big endian
        let checkpoint_id = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
        let key = Key::from_bytes(&bytes[8..])?;
        Ok(Self {
            checkpoint_id,
            key,
        })
    }
}

impl<Key: QPDSerializableFixed> QPDSerializableFixed for QPDCheckpointedKey<Key> {
    fn get_fixed_size() -> usize {
        8 + Key::get_fixed_size()
    }
}

// use this!!!
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





#[async_trait]
pub trait CheckpointedStoreReaderAsync<Key: QPDSerializable + Send + Sync, Value: QPDSerializable + Send + Sync> {
    async fn contains_key_async(&self, key: &Key) -> anyhow::Result<bool>;
    async fn contains_keys_async(&self, keys: &[Key]) -> anyhow::Result<Vec<bool>>;

    // contains a value for the key at checkpoint_id >= max_checkpoint_id
    async fn contains_key_leq_checkpoint_async(&self, max_checkpoint_id: u64, key: &Key) -> anyhow::Result<bool>;
    async fn contains_keys_leq_checkpoint_async(&self, max_checkpoint_id: u64, keys: &[Key]) -> anyhow::Result<Vec<bool>>;

    // contains a key at exactly checkpoint_id
    async fn contains_key_exact_async(&self, checkpoint_id: u64, key: &Key) -> anyhow::Result<bool>;
    async fn contains_keys_exact_async(&self, checkpoint_id: u64, keys: &[Key]) -> anyhow::Result<Vec<bool>>;


    // anyhow error if not found
    async fn get_value_latest_async(&self, key: &Key) -> anyhow::Result<Value>;
    async fn get_value_latest_or_none_async(&self, key: &Key) -> anyhow::Result<Option<Value>>;
    async fn get_value_latest_or_async(&self, key: &Key, default: Value) -> anyhow::Result<Value>;
    async fn get_value_latest_and_checkpoint_async(&self, key: &Key) -> anyhow::Result<QPDCheckpointedKV<Key, Value>>;
    async fn get_value_latest_and_checkpoint_or_none_async(&self, key: &Key) -> anyhow::Result<Option<QPDCheckpointedKV<Key, Value>>>;
    async fn get_value_latest_and_checkpoint_or_async(&self, key: &Key, default: QPDCheckpointedKV<Key, Value>) -> anyhow::Result<QPDCheckpointedKV<Key, Value>>;
    
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
impl<Key, Value, S> CheckpointedStoreReaderAsync<Key, Value> for S
where
    Key: QPDSerializableFixed + Send + Sync + Clone + PartialEq + Debug,
    Value: QPDSerializable + Send + Sync + Clone,
    S: QPDBinaryStoreReaderAsync + Send + Sync,
{
    async fn contains_key_async(&self, key: &Key) -> Result<bool> {
        Ok(<S as CheckpointedStoreReaderAsync<Key, Value>>::get_value_latest_or_none_async(self, key).await?.is_some())
    }

    async fn contains_keys_async(&self, keys: &[Key]) -> Result<Vec<bool>> {
        let opts = <S as CheckpointedStoreReaderAsync<Key, Value>>::get_kvs_latest_or_none_async(self, keys).await?;
        Ok(opts.into_iter().map(|opt| opt.is_some()).collect())
    }

    async fn contains_key_leq_checkpoint_async(&self, max_checkpoint_id: u64, key: &Key) -> Result<bool> {
        Ok(<S as CheckpointedStoreReaderAsync<Key, Value>>::get_value_leq_checkpoint_or_none_async(self, max_checkpoint_id, key).await?.is_some())
    }

    async fn contains_keys_leq_checkpoint_async(&self, max_checkpoint_id: u64, keys: &[Key]) -> Result<Vec<bool>> {
        let opts = <S as CheckpointedStoreReaderAsync<Key, Value>>::get_values_leq_checkpoint_or_none_async(self, max_checkpoint_id, keys).await?;
        Ok(opts.into_iter().map(|opt| opt.is_some()).collect())
    }

    async fn contains_key_exact_async(&self, checkpoint_id: u64, key: &Key) -> Result<bool> {
        Ok(<S as CheckpointedStoreReaderAsync<Key, Value>>::get_value_exact_or_none_async(self, checkpoint_id, key).await?.is_some())
    }

    async fn contains_keys_exact_async(&self, checkpoint_id: u64, keys: &[Key]) -> Result<Vec<bool>> {
        let opts = <S as CheckpointedStoreReaderAsync<Key, Value>>::get_values_exact_or_none_async(self, checkpoint_id, keys).await?;
        Ok(opts.into_iter().map(|opt| opt.is_some()).collect())
    }

    async fn get_value_latest_async(&self, key: &Key) -> Result<Value> {
        unwrap_kv_result(<S as CheckpointedStoreReaderAsync<Key, Value>>::get_value_latest_or_none_async(self, key).await?)
    }

    async fn get_value_latest_or_none_async(&self, key: &Key) -> Result<Option<Value>> {
        let ck_key = QPDCheckpointedKey::new(u64::MAX, key.clone());
        let full_key = ck_key.to_bytes()?;
        let opt_pair = self.get_leq_kv_async(&full_key, 0).await?;
        match opt_pair {
            None => Ok(None),
            Some(pair) => {
                if pair.key.len() != 8 + Key::get_fixed_size() {
                    return Ok(None);
                }
                let ck_parsed = QPDCheckpointedKey::<Key>::from_bytes(&pair.key)?;
                if ck_parsed.key != *key {
                    return Ok(None);
                }
                let val = Value::from_bytes(&pair.value)?;
                Ok(Some(val))
            }
        }
    }

    async fn get_value_latest_or_async(&self, key: &Key, default: Value) -> Result<Value> {
        match <S as CheckpointedStoreReaderAsync<Key, Value>>::get_value_latest_or_none_async(self, key).await? {
            Some(v) => Ok(v),
            None => Ok(default),
        }
    }

    async fn get_value_latest_and_checkpoint_async(&self, key: &Key) -> Result<QPDCheckpointedKV<Key, Value>> {
        unwrap_kv_result(<S as CheckpointedStoreReaderAsync<Key, Value>>::get_value_latest_and_checkpoint_or_none_async(self, key).await?)
    }

    async fn get_value_latest_and_checkpoint_or_none_async(&self, key: &Key) -> Result<Option<QPDCheckpointedKV<Key, Value>>> {
        let ck_key = QPDCheckpointedKey::new(u64::MAX, key.clone());
        let full_key = ck_key.to_bytes()?;
        let opt_pair = self.get_leq_kv_async(&full_key, 0).await?;
        match opt_pair {
            None => Ok(None),
            Some(pair) => {
                if pair.key.len() != 8 + Key::get_fixed_size() {
                    return Ok(None);
                }
                let ck_parsed = QPDCheckpointedKey::<Key>::from_bytes(&pair.key)?;
                if ck_parsed.key != *key {
                    return Ok(None);
                }
                let val = Value::from_bytes(&pair.value)?;
                let kv = QPDCheckpointedKV::new(ck_parsed.checkpoint_id, ck_parsed.key, val);
                Ok(Some(kv))
            }
        }
    }

    async fn get_value_latest_and_checkpoint_or_async(&self, key: &Key, default: QPDCheckpointedKV<Key, Value>) -> Result<QPDCheckpointedKV<Key, Value>> {
        match <S as CheckpointedStoreReaderAsync<Key, Value>>::get_value_latest_and_checkpoint_or_none_async(self, key).await? {
            Some(v) => Ok(v),
            None => Ok(default),
        }
    }
    
    async fn get_value_exact_async(&self, checkpoint_id: u64, key: &Key) -> Result<Value> {
        unwrap_kv_result(<S as CheckpointedStoreReaderAsync<Key, Value>>::get_value_exact_or_none_async(self, checkpoint_id, key).await?)
    }

    async fn get_value_exact_or_none_async(&self, checkpoint_id: u64, key: &Key) -> Result<Option<Value>> {
        let ck_key = QPDCheckpointedKey::new(checkpoint_id, key.clone());
        let full_key = ck_key.to_bytes()?;
        let opt_v_bytes = self.get_exact_if_exists_async(&full_key).await?;
        match opt_v_bytes {
            None => Ok(None),
            Some(v_bytes) => Ok(Some(Value::from_bytes(&v_bytes)?)),
        }
    }

    async fn get_value_exact_or_async(&self, checkpoint_id: u64, key: &Key, default: Value) -> Result<Value> {
        match <S as CheckpointedStoreReaderAsync<Key, Value>>::get_value_exact_or_none_async(self, checkpoint_id, key).await? {
            Some(v) => Ok(v),
            None => Ok(default),
        }
    }

    async fn get_values_exact_async(&self, checkpoint_id: u64, keys: &[Key]) -> Result<Vec<Value>> {
        unwrap_kv_vec_result(<S as CheckpointedStoreReaderAsync<Key, Value>>::get_values_exact_or_none_async(self, checkpoint_id, keys).await?)
    }

    async fn get_values_exact_or_none_async(&self, checkpoint_id: u64, keys: &[Key]) -> Result<Vec<Option<Value>>> {
        let mut res = Vec::with_capacity(keys.len());
        for key in keys {
            res.push(<S as CheckpointedStoreReaderAsync<Key, Value>>::get_value_exact_or_none_async(self, checkpoint_id, key).await?);
        }
        Ok(res)
    }

    async fn get_values_exact_or_async(&self, checkpoint_id: u64, keys: &[Key], default: Value) -> Result<Vec<Value>> {
        let mut results = Vec::new();
        for opt in <S as CheckpointedStoreReaderAsync<Key, Value>>::get_values_exact_or_none_async(self, checkpoint_id, keys).await? {
            match opt {
                Some(v) => results.push(v),
                None => results.push(default.clone()),
            }
        }
        Ok(results)
    }

    async fn get_value_leq_checkpoint_async(&self, max_checkpoint_id: u64, key: &Key) -> Result<Value> {
        unwrap_kv_result(<S as CheckpointedStoreReaderAsync<Key, Value>>::get_value_leq_checkpoint_or_none_async(self, max_checkpoint_id, key).await?)
    }

    async fn get_value_leq_checkpoint_or_none_async(&self, max_checkpoint_id: u64, key: &Key) -> Result<Option<Value>> {
        let ck_key = QPDCheckpointedKey::new(max_checkpoint_id, key.clone());
        let full_key = ck_key.to_bytes()?;
        let opt_pair = self.get_leq_kv_async(&full_key, 0).await?;
        match opt_pair {
            None => Ok(None),
            Some(pair) => {
                if pair.key.len() != 8 + Key::get_fixed_size() {
                    return Ok(None);
                }
                let ck_parsed = QPDCheckpointedKey::<Key>::from_bytes(&pair.key)?;
                if ck_parsed.key != *key {
                    return Ok(None);
                }
                let val = Value::from_bytes(&pair.value)?;
                Ok(Some(val))
            }
        }
    }

    async fn get_value_leq_checkpoint_or_async(&self, max_checkpoint_id: u64, key: &Key, default: Value) -> Result<Value> {
        match <S as CheckpointedStoreReaderAsync<Key, Value>>::get_value_leq_checkpoint_or_none_async(self, max_checkpoint_id, key).await? {
            Some(v) => Ok(v),
            None => Ok(default),
        }
    }

    async fn get_values_leq_checkpoint_async(&self, max_checkpoint_id: u64, keys: &[Key]) -> Result<Vec<Value>> {
        unwrap_kv_vec_result(<S as CheckpointedStoreReaderAsync<Key, Value>>::get_values_leq_checkpoint_or_none_async(self, max_checkpoint_id, keys).await?)
    }

    async fn get_values_leq_checkpoint_or_none_async(&self, max_checkpoint_id: u64, keys: &[Key]) -> Result<Vec<Option<Value>>> {
        let mut full_keys = Vec::with_capacity(keys.len());
        for key in keys {
            let ck_key = QPDCheckpointedKey::new(max_checkpoint_id, key.clone());
            full_keys.push(ck_key.to_bytes()?);
        }
        let opt_pairs = self.get_many_leq_kv_async(&full_keys, 0).await?;
        let mut results = Vec::with_capacity(keys.len());
        for (i, opt_pair) in opt_pairs.into_iter().enumerate() {
            match opt_pair {
                None => results.push(None),
                Some(pair) => {
                    if pair.key.len() != 8 + Key::get_fixed_size() {
                        results.push(None);
                        continue;
                    }
                    let ck_parsed = QPDCheckpointedKey::<Key>::from_bytes(&pair.key)?;
                    if ck_parsed.key != keys[i] {
                        results.push(None);
                        continue;
                    }
                    let val = Value::from_bytes(&pair.value)?;
                    results.push(Some(val));
                }
            }
        }
        Ok(results)
    }

    async fn get_values_leq_checkpoint_or_async(&self, max_checkpoint_id: u64, keys: &[Key], default: Value) -> Result<Vec<Value>> {
        let mut results = Vec::new();
        for opt in <S as CheckpointedStoreReaderAsync<Key, Value>>::get_values_leq_checkpoint_or_none_async(self, max_checkpoint_id, keys).await? {
            match opt {
                Some(v) => results.push(v),
                None => results.push(default.clone()),
            }
        }
        Ok(results)
    }

    async fn get_kvs_latest_async(&self, keys: &[Key]) -> Result<Vec<QPDPair<Key, Value>>> {
        unwrap_kv_vec_result(<S as CheckpointedStoreReaderAsync<Key, Value>>::get_kvs_latest_or_none_async(self, keys).await?)
    }

    async fn get_kvs_latest_or_none_async(&self, keys: &[Key]) -> Result<Vec<Option<QPDPair<Key, Value>>>> {
        let mut full_keys = Vec::with_capacity(keys.len());
        for key in keys {
            let ck_key = QPDCheckpointedKey::new(u64::MAX, key.clone());
            full_keys.push(ck_key.to_bytes()?);
        }
        let opt_pairs = self.get_many_leq_kv_async(&full_keys, 0).await?;
        let mut results = Vec::with_capacity(keys.len());
        for (i, opt_pair) in opt_pairs.into_iter().enumerate() {
            match opt_pair {
                None => results.push(None),
                Some(pair) => {
                    if pair.key.len() != 8 + Key::get_fixed_size() {
                        results.push(None);
                        continue;
                    }
                    let ck_parsed = QPDCheckpointedKey::<Key>::from_bytes(&pair.key)?;
                    if ck_parsed.key != keys[i] {
                        results.push(None);
                        continue;
                    }
                    let val = Value::from_bytes(&pair.value)?;
                    results.push(Some(QPDPair { key: ck_parsed.key, value: val }));
                }
            }
        }
        Ok(results)
    }

    async fn get_kvs_latest_or_async(&self, keys: &[Key], default: QPDPair<Key, Value>) -> Result<Vec<QPDPair<Key, Value>>> {
        let mut results = Vec::new();
        for opt in <S as CheckpointedStoreReaderAsync<Key, Value>>::get_kvs_latest_or_none_async(self, keys).await? {
            match opt {
                Some(v) => results.push(v),
                None => results.push(default.clone()),
            }
        }
        Ok(results)
    }
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
impl<Key, Value, S> CheckpointedStoreWriterAsyncImm<Key, Value> for S
where
    Key: QPDSerializableFixed + Send + Sync + Clone + PartialEq + Debug,
    Value: QPDSerializable + Send + Sync + Clone,
    S: QPDBinaryStoreWriterAsync + Send + Sync,
{
    async fn set_value_imm_async(&self, checkpoint_id: u64, key: &Key, value: &Value) -> Result<()> {
        let ck_key = QPDCheckpointedKey::new(checkpoint_id, key.clone());
        let full_key = ck_key.to_bytes()?;
        let value_bytes = value.to_bytes()?;
        self.set_ref_async(&full_key, &value_bytes).await
    }

    async fn set_many_imm_async(&self, checkpoint_id: u64, entries: &[QPDPair<Key, Value>]) -> Result<()> {
        let mut full_keys = Vec::with_capacity(entries.len());
        let mut value_bytes_vec = Vec::with_capacity(entries.len());
        for entry in entries {
            let ck_key = QPDCheckpointedKey::new(checkpoint_id, entry.key.clone());
            full_keys.push(ck_key.to_bytes()?);
            value_bytes_vec.push(entry.value.to_bytes()?);
        }
        self.set_many_split_ref_async(&full_keys, &value_bytes_vec).await
    }

    async fn set_many_split_imm_async(&self, checkpoint_id: u64, keys: &[Key], values: &[Value]) -> Result<()> {
        if keys.len() != values.len() {
            return Err(anyhow!("keys and values must have the same length"));
        }
        let mut full_keys = Vec::with_capacity(keys.len());
        let mut value_bytes_vec = Vec::with_capacity(keys.len());
        for i in 0..keys.len() {
            let ck_key = QPDCheckpointedKey::new(checkpoint_id, keys[i].clone());
            full_keys.push(ck_key.to_bytes()?);
            value_bytes_vec.push(values[i].to_bytes()?);
        }
        self.set_many_split_ref_async(&full_keys, &value_bytes_vec).await
    }

    async fn delete_imm_async(&self, checkpoint_id: u64, key: &Key) -> Result<()> {
        let ck_key = QPDCheckpointedKey::new(checkpoint_id, key.clone());
        let full_key = ck_key.to_bytes()?;
        let _ = self.delete_async(&full_key).await?;
        Ok(())
    }

    async fn delete_many_imm_async(&self, checkpoint_id: u64, keys: &[Key]) -> Result<()> {
        let mut full_keys = Vec::with_capacity(keys.len());
        for key in keys {
            let ck_key = QPDCheckpointedKey::new(checkpoint_id, key.clone());
            full_keys.push(ck_key.to_bytes()?);
        }
        let _ = self.delete_many_async(&full_keys).await?;
        Ok(())
    }
}
