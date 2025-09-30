
use serde::Deserialize;
use serde::Serialize;
use serde_with::serde_as;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QPDPairWithCheckpointId<K: Serialize + Clone, V: Serialize + Clone> {
    pub pair: QPDPair<K, V>,
    pub checkpoint_id: u64,
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


