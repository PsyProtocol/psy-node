use kvq::traits::{KVQSerializable, ScyllaKey};
use plonky2::hash::hash_types::{HashOut, RichField};
use psy_client_common::data::qhashout::QHashOut;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Hash4x64Key<const TABLE_TYPE: u16> {
    pub elements: [u64; 4],
}

impl<const TABLE_TYPE: u16> KVQSerializable for Hash4x64Key<TABLE_TYPE> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut result = Vec::with_capacity(34);
        result.push((TABLE_TYPE >> 8) as u8);
        result.push((TABLE_TYPE & 0xff) as u8);
        result.extend_from_slice(&u64::to_be_bytes(self.elements[0]));
        result.extend_from_slice(&u64::to_be_bytes(self.elements[1]));
        result.extend_from_slice(&u64::to_be_bytes(self.elements[2]));
        result.extend_from_slice(&u64::to_be_bytes(self.elements[3]));
        Ok(result)
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 34 {
            anyhow::bail!("expected 34 bytes for deserializing Hash4x64Key, got {} bytes", bytes.len());
        }

        let elements_0 = u64::from_be_bytes(bytes[2..10].try_into().unwrap());
        let elements_1 = u64::from_be_bytes(bytes[10..18].try_into().unwrap());
        let elements_2 = u64::from_be_bytes(bytes[18..26].try_into().unwrap());
        let elements_3 = u64::from_be_bytes(bytes[26..34].try_into().unwrap());

        Ok(Self {
            elements: [elements_0, elements_1, elements_2, elements_3],
        })
    }
}
impl<const TABLE_TYPE: u16> Hash4x64Key<TABLE_TYPE> {
    pub fn new(elements: [u64; 4]) -> Self {
        Self { elements }
    }
    pub fn from_qhash<F: RichField>(hash: QHashOut<F>) -> Self {
        let elements = [
            hash.0.elements[0].to_canonical_u64(),
            hash.0.elements[1].to_canonical_u64(),
            hash.0.elements[2].to_canonical_u64(),
            hash.0.elements[3].to_canonical_u64(),
        ];
        Self { elements }
    }
}

impl<F: RichField, const TABLE_TYPE: u16> From<QHashOut<F>> for Hash4x64Key<TABLE_TYPE> {
    fn from(value: QHashOut<F>) -> Self {
        Self::from_qhash(value)
    }
}

impl<F: RichField, const TABLE_TYPE: u16> From<Hash4x64Key<TABLE_TYPE>> for QHashOut<F> {
    fn from(value: Hash4x64Key<TABLE_TYPE>) -> Self {
        Self(HashOut {
            elements: [
                F::from_noncanonical_u64(value.elements[0]),
                F::from_noncanonical_u64(value.elements[1]),
                F::from_noncanonical_u64(value.elements[2]),
                F::from_noncanonical_u64(value.elements[3]),
            ],
        })
    }
}

impl<const TABLE_TYPE: u16> ScyllaKey for Hash4x64Key<TABLE_TYPE> {
    fn get_partition_key(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(32);
        for element in &self.elements {
            result.extend_from_slice(&element.to_be_bytes());
        }
        result
    }

    fn get_clustering_key(&self) -> Option<Vec<u8>> {
        None
    }

    fn get_table_type(&self) -> u16 {
        TABLE_TYPE
    }
}
