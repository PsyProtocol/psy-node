use async_trait::async_trait;
use parth_core::data::serializable::QPDSerializable;
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

#[async_trait]
pub trait QPTempQueueEmphemeralPublisher {
    async fn push_bytes_to_ephemeral_queue(&self, queue_type: QPEphemeralQueueType, unique_id: u128, value: &[u8]) -> anyhow::Result<()>;
    async fn push_obj_to_ephemeral_queue<T: QPDSerializable + Sync>(&self, queue_type: QPEphemeralQueueType, unique_id: u128, value: &T) -> anyhow::Result<()> {
        self.push_bytes_to_ephemeral_queue(queue_type, unique_id, &value.to_bytes()?).await
    }
    async fn push_s_obj_to_ephemeral_queue<T: Serialize + Sync>(&self, queue_type: QPEphemeralQueueType, unique_id: u128, value: &T) -> anyhow::Result<()> {
        self.push_bytes_to_ephemeral_queue(queue_type, unique_id, &pser::serialize(value)?).await
    }
    async fn push_many_bytes_to_ephemeral_queue(&self, queue_type: QPEphemeralQueueType, unique_id: u128, values: &[Vec<u8>]) -> anyhow::Result<()>;
    async fn push_many_objs_to_ephemeral_queue<T: QPDSerializable + Sync>(&self, queue_type: QPEphemeralQueueType, unique_id: u128, values: &[T]) -> anyhow::Result<()> {
        let value_bytes: Vec<Vec<u8>> = values.iter().map(|v| v.to_bytes().unwrap()).collect();
        self.push_many_bytes_to_ephemeral_queue(queue_type, unique_id, &value_bytes).await
    }
    async fn push_many_s_objs_to_ephemeral_queue<T: Serialize + Sync>(&self, queue_type: QPEphemeralQueueType, unique_id: u128, values: &[T]) -> anyhow::Result<()> {
        let value_bytes: Vec<Vec<u8>> = values.iter().map(|v| pser::serialize(v).unwrap()).collect();
        self.push_many_bytes_to_ephemeral_queue(queue_type, unique_id, &value_bytes).await
    }
}


#[async_trait]
pub trait QPTempQueueEmphemeralSubscriber {
    async fn dump_entire_ephemeral_queue(&self, queue_type: QPEphemeralQueueType, unique_id: u128) -> anyhow::Result<Vec<Vec<u8>>>;
    async fn dump_entire_ephemeral_queue_as_objs<T: QPDSerializable>(&self, queue_type: QPEphemeralQueueType, unique_id: u128) -> anyhow::Result<Vec<T>> {
        let bytes = self.dump_entire_ephemeral_queue(queue_type, unique_id).await?;
        bytes.into_iter().map(|b| T::from_bytes(&b)).collect()
    }
    async fn dump_entire_ephemeral_queue_as_s_objs<T: DeserializeOwned>(&self, queue_type: QPEphemeralQueueType, unique_id: u128) -> anyhow::Result<Vec<T>> {
        let bytes = self.dump_entire_ephemeral_queue(queue_type, unique_id).await?;
        bytes.into_iter().map(|b| pser::deserialize(&b).map_err(|e| anyhow::anyhow!(e))).collect()
    }
    async fn pop_bytes_from_emphemeral_queue_or_none(&self, queue_type: QPEphemeralQueueType, unique_id: u128) -> anyhow::Result<Option<Vec<u8>>>;
    async fn pop_obj_from_emphemeral_queue_or_none<T: QPDSerializable>(&self, queue_type: QPEphemeralQueueType, unique_id: u128) -> anyhow::Result<Option<T>> {
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
    async fn wait_for_pop_obj_from_emphemeral_queue<T: QPDSerializable>(&self, queue_type: QPEphemeralQueueType, unique_id: u128, timeout_ms: u64) -> anyhow::Result<T> {
        let bytes = self.wait_for_pop_bytes_from_emphemeral_queue(queue_type, unique_id, timeout_ms).await?;
        Ok(T::from_bytes(&bytes)?)
    }
    async fn wait_for_pop_s_obj_from_emphemeral_queue<T: DeserializeOwned>(&self, queue_type: QPEphemeralQueueType, unique_id: u128, timeout_ms: u64) -> anyhow::Result<T> {
        let bytes = self.wait_for_pop_bytes_from_emphemeral_queue(queue_type, unique_id, timeout_ms).await?;
        Ok(pser::deserialize(&bytes)?)
    }
}