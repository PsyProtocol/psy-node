
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq)]
pub struct QPDPair<K, V> {
    pub key: K,
    pub value: V,
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
pub trait QPDSerializableFixed: QPDSerializable + Sized {
    fn get_fixed_size() -> usize;
}