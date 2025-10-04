use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::data::serializable::{QPDSerializable, QPDSerializableFixed};


#[pderive::serialize_copy_default]
pub struct QDoubleIdKey {
    pub obj_id: u64,
    pub secondary_id: u64,
}
impl QPDSerializable for QDoubleIdKey {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(16);
        bytes.extend_from_slice(&self.obj_id.to_be_bytes());
        bytes.extend_from_slice(&self.secondary_id.to_be_bytes());
        Ok(bytes)
    }
    fn from_bytes(data: &[u8]) -> anyhow::Result<Self> where Self: Sized {
        if data.len() != 16 {
            anyhow::bail!("Invalid data length for QDoubleIdKey: expected 16, got {}", data.len());
        }
        let obj_id = u64::from_be_bytes(data[0..8].try_into().unwrap());
        let secondary_id = u64::from_be_bytes(data[8..16].try_into().unwrap());
        Ok(Self { obj_id, secondary_id })
    }
}
impl QPDSerializableFixed for QDoubleIdKey {
    fn get_fixed_size() -> usize {
        16
    }
}
impl From<(u64, u64)> for QDoubleIdKey {
    fn from(value: (u64, u64)) -> Self {
        Self {
            obj_id: value.0,
            secondary_id: value.1,
        }
    }
}
impl From<QDoubleIdKey> for (u64, u64) {
    fn from(value: QDoubleIdKey) -> Self {
        (value.obj_id, value.secondary_id)
    }
}

pub trait QDatabaseSingleIdTableRowNoCheckpointIdLike<V: Serialize + DeserializeOwned> {
    fn get_row_obj_id(&self) -> u64;
    fn get_row_value_ref(&self) -> &V;
}
pub trait QDatabaseSingleIdTableRowLike<V: Serialize + DeserializeOwned>: QDatabaseSingleIdTableRowNoCheckpointIdLike<V> {
    fn get_row_checkpoint_id(&self) -> u64;
}


pub trait QDatabaseDoubleIdTableRowNoCheckpointIdLike<V: Serialize + DeserializeOwned> {
    fn get_row_obj_id(&self) -> u64;
    fn get_row_secondary_id(&self) -> u64;
    fn get_row_value_ref(&self) -> &V;
}
pub trait QDatabaseDoubleIdTableRowLike<V: Serialize + DeserializeOwned>: QDatabaseDoubleIdTableRowNoCheckpointIdLike<V> {
    fn get_row_checkpoint_id(&self) -> u64;
}

pub trait QDatabaseKeyIdValueTableRowLike<V: Serialize + DeserializeOwned> {
    fn get_row_obj_id(&self) -> u64;
    fn get_row_value_ref(&self) -> &V;
}
pub trait QDatabaseSingleIdTableRowCreatable<V> {
    fn create_from_single_row(obj_id: u64, checkpoint_id: u64, value: V) -> Self;
}

pub trait QDatabaseDoubleIdTableRowCreatable<V> {
    fn create_from_double_row(obj_id: u64, secondary_id: u64, checkpoint_id: u64, value: V) -> Self;
}

pub trait QDatabaseKeyIdValueTableRowCreatable<V> {
    fn create_from_key_id_value_row(obj_id: u64, value: V) -> Self;
}

#[pderive::serialize_clone]
pub struct QDatabaseSingleIdTableRow<V> {
    pub obj_id: u64,
    pub checkpoint_id: u64,
    pub value: V,
}
impl<V: Serialize + DeserializeOwned> QDatabaseSingleIdTableRowNoCheckpointIdLike<V> for QDatabaseSingleIdTableRow<V> {
    fn get_row_obj_id(&self) -> u64 {
        self.obj_id
    }
    fn get_row_value_ref(&self) -> &V {
        &self.value
    }
}

impl<V: Serialize + DeserializeOwned> QDatabaseSingleIdTableRowLike<V> for QDatabaseSingleIdTableRow<V> {
    fn get_row_checkpoint_id(&self) -> u64 {
        self.checkpoint_id
    }
}


#[pderive::serialize_clone]
pub struct QDatabaseSingleIdTableRowNoCheckpointId<V: Serialize> {
    pub obj_id: u64,
    pub value: V,
}
impl <V: Serialize + DeserializeOwned> QDatabaseSingleIdTableRowNoCheckpointIdLike<V> for QDatabaseSingleIdTableRowNoCheckpointId<V> {
    fn get_row_obj_id(&self) -> u64 {
        self.obj_id
    }
    fn get_row_value_ref(&self) -> &V {
        &self.value
    }
}

#[pderive::serialize_clone]
pub struct QDatabaseDoubleIdTableRow<V> {
    pub obj_id: u64,
    pub secondary_id: u64,
    pub checkpoint_id: u64,
    pub value: V,
}
impl <V: Serialize + DeserializeOwned> QDatabaseDoubleIdTableRowNoCheckpointIdLike<V> for QDatabaseDoubleIdTableRow<V> {
    fn get_row_obj_id(&self) -> u64 {
        self.obj_id
    }
    fn get_row_secondary_id(&self) -> u64 {
        self.secondary_id
    }
    fn get_row_value_ref(&self) -> &V {
        &self.value
    }
}
impl <V: Serialize + DeserializeOwned> QDatabaseDoubleIdTableRowLike<V> for QDatabaseDoubleIdTableRow<V> {
    fn get_row_checkpoint_id(&self) -> u64 {
        self.checkpoint_id
    }
}

#[pderive::serialize_clone]
pub struct QDatabaseDoubleIdTableRowNoCheckpointId<V: Serialize> {
    pub obj_id: u64,
    pub secondary_id: u64,
    pub value: V,
}
impl <V: Serialize + DeserializeOwned> QDatabaseDoubleIdTableRowNoCheckpointIdLike<V> for QDatabaseDoubleIdTableRowNoCheckpointId<V> {
    fn get_row_obj_id(&self) -> u64 {
        self.obj_id
    }
    fn get_row_secondary_id(&self) -> u64 {
        self.secondary_id
    }
    fn get_row_value_ref(&self) -> &V {
        &self.value
    }
}

#[pderive::serialize_clone]
pub struct QDatabaseKeyIdValueTableRow<V> {
    pub obj_id: u64,
    pub value: V,
}

impl <V: Serialize + DeserializeOwned> QDatabaseKeyIdValueTableRowLike<V> for QDatabaseKeyIdValueTableRow<V> {
    fn get_row_obj_id(&self) -> u64 {
        self.obj_id
    }
    fn get_row_value_ref(&self) -> &V {
        &self.value
    }
}
impl<V: Serialize> QDatabaseSingleIdTableRowCreatable<V> for QDatabaseSingleIdTableRow<V> {
    fn create_from_single_row(obj_id: u64, checkpoint_id: u64, value: V) -> Self {
        Self {
            obj_id,
            checkpoint_id,
            value,
        }
    }
}
impl<V: Serialize> QDatabaseDoubleIdTableRowCreatable<V> for QDatabaseDoubleIdTableRow<V> {
    fn create_from_double_row(obj_id: u64, secondary_id: u64, checkpoint_id: u64, value: V) -> Self {
        Self {
            obj_id,
            secondary_id,
            checkpoint_id,
            value,
        }
    }
}
impl<V: Serialize> QDatabaseKeyIdValueTableRowCreatable<V> for QDatabaseKeyIdValueTableRow<V> {
    fn create_from_key_id_value_row(obj_id: u64, value: V) -> Self {
        Self {
            obj_id,
            value,
        }
    }
}
