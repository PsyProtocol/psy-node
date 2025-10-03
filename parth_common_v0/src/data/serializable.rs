
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde::Serialize;
use serde_with::serde_as;

use crate::data::db::row::QDatabaseDoubleIdTableRowNoCheckpointIdLike;
use crate::data::db::row::QDatabaseKeyIdValueTableRowCreatable;
use crate::data::db::row::QDatabaseKeyIdValueTableRowLike;
use crate::data::db::row::QDatabaseSingleIdTableRowCreatable;
use crate::data::db::row::QDatabaseSingleIdTableRowNoCheckpointIdLike;
use crate::data::db::row::QDoubleIdKey;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QPDPairWithCheckpointId<K: Serialize + Clone, V: Serialize + Clone> {
    pub pair: QPDPair<K, V>,
    pub checkpoint_id: u64,
}

impl<V: Serialize + Clone> QDatabaseSingleIdTableRowCreatable<V> for QPDPairWithCheckpointId<u64,V> {
    fn create_from_single_row(obj_id: u64, checkpoint_id: u64, value: V) -> Self {
        Self { pair: QPDPair { key: obj_id, value }, checkpoint_id }
    }
} 

#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq, PartialOrd, Ord)]
pub struct BinaryKVWithCheckpointId {
    #[serde_as(as = "serde_with::hex::Hex")]
    pub key: Vec<u8>,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub value: Vec<u8>,

    pub checkpoint_id: u64,
}


#[derive(Debug, Clone, PartialEq)]
pub struct QPDPair<K, V> {
    pub key: K,
    pub value: V,
}
impl<V: Serialize + DeserializeOwned> QDatabaseSingleIdTableRowNoCheckpointIdLike<V> for QPDPair<u64, V> {
    fn get_row_obj_id(&self) -> u64 {
        self.key
    }
    fn get_row_value_ref(&self) -> &V {
        &self.value
    }
}
impl<V: Serialize + DeserializeOwned> QDatabaseDoubleIdTableRowNoCheckpointIdLike<V> for QPDPair<QDoubleIdKey, V> {
    fn get_row_obj_id(&self) -> u64 {
        self.key.obj_id
    }

    fn get_row_secondary_id(&self) -> u64 {
        self.key.secondary_id
    }

    fn get_row_value_ref(&self) -> &V {
        &self.value
    }
}

impl<V> QDatabaseKeyIdValueTableRowCreatable<V> for QPDPair<u64, V> {
    fn create_from_key_id_value_row(obj_id: u64, value: V) -> Self {
        Self { key: obj_id, value }
    }
}
impl<V: Serialize + Clone + DeserializeOwned> QDatabaseKeyIdValueTableRowLike<V> for QPDPair<u64, V> {
    fn get_row_obj_id(&self) -> u64 {
        self.key
    }
    fn get_row_value_ref(&self) -> &V {
        &self.value
    }
}
impl<K: Copy, V: Copy> Copy for QPDPair<K,V>{}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct QPDPairSerializable<K, V> {
    pub key: K,
    pub value: V,
}
impl<K: Serialize + Clone, V: Serialize + Clone> Serialize for QPDPair<K, V> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let serializable = QPDPairSerializable {
            key: self.key.clone(),
            value: self.value.clone(),
        };
        serializable.serialize(serializer)
    }
}
impl<'de, K: Deserialize<'de>, V: Deserialize<'de>> Deserialize<'de> for QPDPair<K, V> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = QPDPairSerializable::deserialize(deserializer)?;
        Ok(QPDPair {
            key: raw.key,
            value: raw.value,
        })
    }
}

pub trait QPDSerializable: Clone + PartialEq {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>>;
    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self>;
}
impl<const N: usize> QPDSerializable for [u8; N] {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.to_vec())
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != N {
            anyhow::bail!("invalid size, expected {} bytes, got {}", N, bytes.len());
        }

        let mut inner_data = [0u8; N];
        inner_data.copy_from_slice(bytes);
        Ok(inner_data)
    }
}
pub trait QPDSerializableFixed: QPDSerializable + Sized {
    fn get_fixed_size() -> usize;
}
impl<const N: usize> QPDSerializableFixed for [u8; N] {
    fn get_fixed_size() -> usize {
        N
    }
}


#[derive(Serialize, Deserialize, PartialEq, Clone, Copy, PartialOrd, Ord, Debug, Eq, Hash, rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, speedy::Readable, speedy::Writable)]
#[serde(bound = "for<'de2> K: Deserialize<'de2>")]
pub struct FastQPDPair<K: Serialize + DeserializeOwned + Clone + Copy, V: Serialize + DeserializeOwned + Clone> {
    pub key: K,
    pub value: V,
}

