
use psy_serialize::PsySerializeCanonicalAsyncSafe;
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


pub trait QPDSizedPairKey: Sized + Copy + Clone + QPDSerializableFixed + Serialize + DeserializeOwned {}
pub struct QPDSizedPair<K: Sized + Copy + , V: QPDSerializableFixed> {
    pub key: K,
    pub value: V,
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

/* 
pub trait GFastFixedSerializable: Sized + Copy {
    /// The exact size of the serialized type in bytes.
    const SIZE: usize;

    /// Creates an instance from a fixed-size byte array.
    fn ffs_from_bytes(data: [u8; Self::SIZE]) -> Self;

    /// Converts the instance into a fixed-size byte array.
    fn ffs_to_bytes(&self) -> [u8; Self::SIZE];

    // Optional helper, not strictly required by PsyCanonicalSer
    fn ffs_try_from_slice(data: &[u8]) -> io::Result<Self> {
        if data.len() != Self::SIZE {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Slice wrong length for FFS"));
        }
        // This is safe because we checked the length.
        let arr_ptr = data.as_ptr() as *const [u8; Self::SIZE];
        // SAFETY: We have checked the slice length is exactly Self::SIZE.
        let arr = unsafe { &*arr_ptr };
        Ok(Self::ffs_from_bytes(*arr))
    }
}
    */


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

impl QPDSerializableFixed for u64 {
    fn get_fixed_size() -> usize {
        8
    }
}
impl QPDSerializable for u64 {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.to_le_bytes().to_vec())
    }
    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 8 {
            anyhow::bail!("invalid size, expected 8 bytes, got {}", bytes.len());
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes[0..8]);
        Ok(u64::from_le_bytes(arr))
    }
}


impl QPDSerializableFixed for u32 {
    fn get_fixed_size() -> usize {
        4
    }
}
impl QPDSerializable for u32 {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.to_le_bytes().to_vec())
    }
    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 4 {
            anyhow::bail!("invalid size, expected 4 bytes, got {}", bytes.len());
        }
        let mut arr = [0u8; 4];
        arr.copy_from_slice(&bytes[0..4]);
        Ok(u32::from_le_bytes(arr))
    }
}


impl QPDSerializableFixed for u128 {
    fn get_fixed_size() -> usize {
        16
    }
}
impl QPDSerializable for u128 {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.to_le_bytes().to_vec())
    }
    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 16 {
            anyhow::bail!("invalid size, expected 16 bytes, got {}", bytes.len());
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes[0..16]);
        Ok(u128::from_le_bytes(arr))
    }
}



#[pderive::serialize_copy]
#[serde(bound = "for<'de2> K: Deserialize<'de2>")]
pub struct FastQPDPair<K: Serialize + DeserializeOwned + Clone + Copy, V: Serialize + DeserializeOwned + Clone> {
    pub key: K,
    pub value: V,
}



pub trait QProofWitnessSerializable: Send + Sync + PsySerializeCanonicalAsyncSafe + Clone {}
impl<T: Send + Sync + PsySerializeCanonicalAsyncSafe + Clone> QProofWitnessSerializable for T {}