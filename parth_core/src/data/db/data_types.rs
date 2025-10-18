use psy_serialize::PsySerializeCanonical;
use serde::{de::DeserializeOwned, Serialize};
use std::hash::Hash;

use crate::utils::QPGenRandom;


pub trait CoreDatabaseValueDeserialize: DeserializeOwned + Send + Sync + Serialize + PartialEq + Clone {

}
impl<V: DeserializeOwned + Send + Sync + Serialize + PartialEq + Clone> CoreDatabaseValueDeserialize for V {

}
pub trait QDatabasePrimitiveKey: Send + Sync + Copy + Eq + PartialEq + Ord + PartialOrd + Clone + Hash + PsySerializeCanonical{}
impl<T: Send + Sync + Copy + Eq + PartialEq + Ord + PartialOrd + Clone + Hash + PsySerializeCanonical> QDatabasePrimitiveKey for T {}


#[pderive::serialize_copy]
#[serde(bound = "for<'de2> K1: serde::Deserialize<'de2> + serde::Serialize, for<'de2> K2: serde::Deserialize<'de2> + serde::Serialize")]
pub struct BiDirectionalMappingRow<K1, K2> {
    pub k1: K1,
    pub k2: K2,
}

impl<K1, K2> BiDirectionalMappingRow<K1, K2> {
    pub fn new(k1: K1, k2: K2) -> Self {
        Self { k1, k2 }
    }
}

impl<K1: QPGenRandom, K2: QPGenRandom> QPGenRandom for BiDirectionalMappingRow<K1, K2> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self { k1: K1::qp_rand_gen(), k2: K2::qp_rand_gen() }
    }
}