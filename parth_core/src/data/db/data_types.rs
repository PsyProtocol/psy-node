use serde::{de::DeserializeOwned, Serialize};
use std::hash::Hash;

use crate::data::serializable::{QPDSerializable, QPDSerializableFixed};


pub trait CoreDatabaseValueDeserialize: DeserializeOwned + Send + Sync + Serialize {

}
impl<V: DeserializeOwned + Send + Sync + Serialize> CoreDatabaseValueDeserialize for V {

}

pub trait QDatabasePrimitiveKey: Send + Sync + Copy + Eq + PartialEq + Ord + PartialOrd + Clone + Hash + serde::Serialize + serde::de::DeserializeOwned + QPDSerializable + QPDSerializableFixed {}
impl<T: Send + Sync + Copy + Eq + PartialEq + Ord + PartialOrd + Clone + Hash + serde::Serialize + serde::de::DeserializeOwned + QPDSerializable + QPDSerializableFixed> QDatabasePrimitiveKey for T {}


#[pderive::serialize_copy]
#[serde(bound = "for<'de2> K1: serde::Deserialize<'de2>, for<'de2> K2: serde::Deserialize<'de2>")]
pub struct BiDirectionalMappingRow<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey> {
    pub k1: K1,
    pub k2: K2,
}

impl<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey> BiDirectionalMappingRow<K1, K2> {
    pub fn new(k1: K1, k2: K2) -> Self {
        Self { k1, k2 }
    }
}

