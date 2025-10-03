use parth_common_v0::data::serializable::{QPDPair, QPDSerializable, QPDSerializableFixed};


use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use strum_macros::{Display, FromRepr};




#[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord, FromRepr, Display)]
#[repr(u8)]
pub enum QPEphemeralQueueType {
    UserUpdateInRealm = 1,
    UserRegistrationInRealm = 2,
    RealmUpdateInCoordinator = 3,
}

pub trait QPTempStoreTableType: Sized + Send + Sync + Copy {
    fn to_table_type_u32(&self) -> u32;
}


#[async_trait]
pub trait QPBasicStoreKVReader {
    async fn get_exact_bytes<TT: QPTempStoreTableType>(&self, table_type: TT, key: &[u8]) -> anyhow::Result<Vec<u8>>;
    async fn get_exact_bytes_many<TT: QPTempStoreTableType>(&self, table_type: TT, keys: &[Vec<u8>]) -> anyhow::Result<Vec<Vec<u8>>>;

    async fn get_exact_object_key_bytes<TT: QPTempStoreTableType, K: QPDSerializableFixed + Sync>(&self, table_type: TT, key: &K) -> anyhow::Result<Vec<u8>> {
        self.get_exact_bytes(table_type, &key.to_bytes()?).await
    }
    async fn get_exact_object<TT: QPTempStoreTableType, K: QPDSerializableFixed + Sync, V: QPDSerializable>(&self, table_type: TT, key: &K) -> anyhow::Result<V> {
        let key_bytes = self.get_exact_object_key_bytes::<_, _>(table_type, key).await?;
        let value_bytes = self.get_exact_bytes::<_>(table_type, &key_bytes).await?;
        let value = V::from_bytes(&value_bytes)?;
        Ok(value)
    }
    async fn get_exact_object_or_none<TT: QPTempStoreTableType, K: QPDSerializableFixed + Sync, V: QPDSerializable>(&self, table_type: TT, key: &K) -> anyhow::Result<Option<V>> {
        let key_bytes = self.get_exact_object_key_bytes(table_type, key).await?;
        let value_bytes = self.get_exact_bytes(table_type, &key_bytes).await;
        match value_bytes {
            Ok(bytes) => {
                let value = V::from_bytes(&bytes)?;
                Ok(Some(value))
            },
            Err(_) => Ok(None),
        }
    }
    async fn get_exact_object_key_bytes_many<TT: QPTempStoreTableType, K: QPDSerializableFixed + Sync>(&self, table_type: TT, keys: &[K]) -> anyhow::Result<Vec<Vec<u8>>> {
        let key_bytes: Vec<Vec<u8>> = keys.iter().map(|k| k.to_bytes()).collect::<Result<_, _>>()?;
        self.get_exact_bytes_many(table_type, &key_bytes).await
    }
    async fn get_exact_object_many<TT: QPTempStoreTableType, K: QPDSerializableFixed + Sync, V: QPDSerializable>(&self, table_type: TT, keys: &[K]) -> anyhow::Result<Vec<V>> {
        let key_bytes: Vec<Vec<u8>> = keys.iter().map(|k| k.to_bytes()).collect::<Result<_, _>>()?;
        let value_bytes = self.get_exact_bytes_many(table_type, &key_bytes).await?;
        value_bytes.into_iter().map(|bytes| V::from_bytes(&bytes)).collect()
    }
}



#[async_trait]
pub trait QPBasicStoreKVWriter {
    async fn set_exact_bytes(&self, table_type: u32, key: &[u8], value: &[u8]) -> anyhow::Result<()>;
    async fn set_exact_object_key_bytes<K: QPDSerializableFixed + Sync>(&self, table_type: u32, key: &K, value: &[u8]) -> anyhow::Result<()> {
        self.set_exact_bytes(table_type, &key.to_bytes()?, value).await
    }
    async fn set_exact_object<K: QPDSerializableFixed + Sync, V: QPDSerializable + Sync>(&self, table_type: u32, key: &K, value: &V) -> anyhow::Result<()> {
        let key_bytes = key.to_bytes()?;
        let value_bytes = value.to_bytes()?;
        self.set_exact_bytes(table_type, &key_bytes, &value_bytes).await
    }
    async fn set_exact_bytes_many(&self, table_type: u32, entries: &[QPDPair<Vec<u8>, Vec<u8>>]) -> anyhow::Result<()>;
    async fn set_exact_object_key_bytes_many<K: QPDSerializableFixed + Sync>(&self, table_type: u32, entries: &[QPDPair<K, Vec<u8>>]) -> anyhow::Result<()> {
        let key_bytes: Vec<QPDPair<Vec<u8>, Vec<u8>>> = entries.iter().map(|e| QPDPair { key: e.key.to_bytes().unwrap(), value: e.value.clone() }).collect();
        self.set_exact_bytes_many(table_type, &key_bytes).await
    }
    async fn set_exact_object_many<K: QPDSerializableFixed + Sync, V: QPDSerializable + Sync>(&self, table_type: u32, entries: &[QPDPair<K, V>]) -> anyhow::Result<()> {
        let key_bytes: Vec<QPDPair<Vec<u8>, Vec<u8>>> = entries.iter().map(|e| QPDPair { key: e.key.to_bytes().unwrap(), value: e.value.to_bytes().unwrap() }).collect();
        self.set_exact_bytes_many(table_type, &key_bytes).await
    }
}


#[async_trait]
pub trait QPTempStoreKVU64Reader {
    async fn get_iu64_generic<TT: QPTempStoreTableType>(&self, table_type: TT, key: &[u8]) -> anyhow::Result<u64>;
    async fn get_iu64_object_key_bytes<TT: QPTempStoreTableType, K: QPDSerializableFixed + Sync>(&self, table_type: TT, key: &K) -> anyhow::Result<u64> {
        self.get_iu64_generic(table_type, &key.to_bytes()?).await
    }
    async fn get_iu64_object<TT: QPTempStoreTableType, K: QPDSerializableFixed + Sync>(&self, table_type: TT, key: &K) -> anyhow::Result<u64> {
        self.get_iu64_generic(table_type, &key.to_bytes()?).await
    }
}

#[async_trait]
pub trait QPTempStoreKVU64Writer {
    async fn set_iu64_generic<TT: QPTempStoreTableType>(&self, table_type: TT, key: &[u8], value: u64) -> anyhow::Result<()>;
    async fn inc_iu64_generic<TT: QPTempStoreTableType>(&self, table_type: TT, key: &[u8], delta: i64) -> anyhow::Result<u64>;
    async fn set_iu64_object_key_bytes<TT: QPTempStoreTableType, K: QPDSerializableFixed + Sync>(&self, table_type: TT, key: &K, value: u64) -> anyhow::Result<()> {
        self.set_iu64_generic(table_type, &key.to_bytes()?, value).await
    }
    async fn inc_iu64_object_key_bytes<TT: QPTempStoreTableType, K: QPDSerializableFixed + Sync>(&self, table_type: TT, key: &K, delta: i64) -> anyhow::Result<u64> {
        self.inc_iu64_generic(table_type, &key.to_bytes()?, delta).await
    }
}


#[async_trait]
pub trait QPTempQueueEmphemeralPublisher {
    async fn push_bytes_to_ephemeral_queue(&self, queue_type: QPEphemeralQueueType, unique_id: u128, value: &[u8]) -> anyhow::Result<()>;
    async fn push_obj_to_ephemeral_queue<T: QPDSerializable + Sync>(&self, queue_type: QPEphemeralQueueType, unique_id: u128, value: &T) -> anyhow::Result<()> {
        self.push_bytes_to_ephemeral_queue(queue_type, unique_id, &value.to_bytes()?).await
    }
    async fn push_s_obj_to_ephemeral_queue<T: Serialize + Sync>(&self, queue_type: QPEphemeralQueueType, unique_id: u128, value: &T) -> anyhow::Result<()> {
        self.push_bytes_to_ephemeral_queue(queue_type, unique_id, &bincode::serialize(value)?).await
    }
    async fn push_many_bytes_to_ephemeral_queue(&self, queue_type: QPEphemeralQueueType, unique_id: u128, values: &[Vec<u8>]) -> anyhow::Result<()>;
    async fn push_many_objs_to_ephemeral_queue<T: QPDSerializable + Sync>(&self, queue_type: QPEphemeralQueueType, unique_id: u128, values: &[T]) -> anyhow::Result<()> {
        let value_bytes: Vec<Vec<u8>> = values.iter().map(|v| v.to_bytes().unwrap()).collect();
        self.push_many_bytes_to_ephemeral_queue(queue_type, unique_id, &value_bytes).await
    }
    async fn push_many_s_objs_to_ephemeral_queue<T: Serialize + Sync>(&self, queue_type: QPEphemeralQueueType, unique_id: u128, values: &[T]) -> anyhow::Result<()> {
        let value_bytes: Vec<Vec<u8>> = values.iter().map(|v| bincode::serialize(v).unwrap()).collect();
        self.push_many_bytes_to_ephemeral_queue(queue_type, unique_id, &value_bytes).await
    }
}


#[async_trait]
pub trait QPTempQueueEmphemeralSubscriber {
    async fn pop_bytes_from_emphemeral_queue_or_none(&self, queue_type: QPEphemeralQueueType, unique_id: u128) -> anyhow::Result<Option<Vec<u8>>>;
    async fn pop_obj_from_emphemeral_queue_or_none<T: QPDSerializable + Sync>(&self, queue_type: QPEphemeralQueueType, unique_id: u128) -> anyhow::Result<Option<T>> {
        let bytes = self.pop_bytes_from_emphemeral_queue_or_none(queue_type, unique_id).await?;
        match bytes {
            Some(b) => Ok(Some(T::from_bytes(&b)?)),
            None => Ok(None),
        }
    }
    async fn pop_s_obj_from_emphemeral_queue_or_none<T: DeserializeOwned>(&self, queue_type: QPEphemeralQueueType, unique_id: u128) -> anyhow::Result<Option<T>> {
        let bytes = self.pop_bytes_from_emphemeral_queue_or_none(queue_type, unique_id).await?;
        match bytes {
            Some(b) => Ok(Some(pser::deserialize(&b)?)),
            None => Ok(None),
        }
    }
    async fn wait_for_pop_bytes_from_emphemeral_queue(&self, queue_type: QPEphemeralQueueType, unique_id: u128, timeout_ms: u64) -> anyhow::Result<Vec<u8>>;
    async fn wait_for_pop_obj_from_emphemeral_queue<T: QPDSerializable + Sync>(&self, queue_type: QPEphemeralQueueType, unique_id: u128, timeout_ms: u64) -> anyhow::Result<T> {
        let bytes = self.wait_for_pop_bytes_from_emphemeral_queue(queue_type, unique_id, timeout_ms).await?;
        Ok(T::from_bytes(&bytes)?)
    }
    async fn wait_for_pop_s_obj_from_emphemeral_queue<T: DeserializeOwned>(&self, queue_type: QPEphemeralQueueType, unique_id: u128, timeout_ms: u64) -> anyhow::Result<T> {
        let bytes = self.wait_for_pop_bytes_from_emphemeral_queue(queue_type, unique_id, timeout_ms).await?;
        Ok(pser::deserialize(&bytes)?)
    }
}