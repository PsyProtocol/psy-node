use kvq::traits::{KVQSerializable, ScyllaKey};
use plonky2::hash::hash_types::RichField;
use psy_client_common::data::qhashout::QHashOut;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct StagingDeltaRecordKey<F: RichField, const TABLE_TYPE: u16> {
    pub realm_root: QHashOut<F>,
    pub realm_id: u32,
}

impl<F: RichField, const TABLE_TYPE: u16> KVQSerializable for StagingDeltaRecordKey<F, TABLE_TYPE> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut result = Vec::with_capacity(38);
        result.push((TABLE_TYPE >> 8) as u8);
        result.push((TABLE_TYPE & 0xff) as u8);

        for element in self.realm_root.0.elements {
            result.extend_from_slice(&element.to_canonical_u64().to_be_bytes());
        }

        result.extend_from_slice(&self.realm_id.to_be_bytes());
        Ok(result)
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 38 {
            anyhow::bail!("expected 38 bytes for deserializing StagingDeltaRecordKey, got {} bytes", bytes.len());
        }

        let elements = [
            F::from_canonical_u64(u64::from_be_bytes(bytes[2..10].try_into().unwrap())),
            F::from_canonical_u64(u64::from_be_bytes(bytes[10..18].try_into().unwrap())),
            F::from_canonical_u64(u64::from_be_bytes(bytes[18..26].try_into().unwrap())),
            F::from_canonical_u64(u64::from_be_bytes(bytes[26..34].try_into().unwrap())),
        ];

        let realm_root = QHashOut(plonky2::hash::hash_types::HashOut { elements });
        let realm_id = u32::from_be_bytes(bytes[34..38].try_into().unwrap());

        Ok(StagingDeltaRecordKey { realm_root, realm_id })
    }
}

impl<F: RichField, const TABLE_TYPE: u16> StagingDeltaRecordKey<F, TABLE_TYPE> {
    pub fn new(realm_root: QHashOut<F>, realm_id: u32) -> Self {
        StagingDeltaRecordKey { realm_root, realm_id }
    }
}

impl<F: RichField, const TABLE_TYPE: u16> ScyllaKey for StagingDeltaRecordKey<F, TABLE_TYPE> {
    fn get_partition_key(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(36);
        for element in self.realm_root.0.elements {
            result.extend_from_slice(&element.to_canonical_u64().to_be_bytes());
        }
        result.extend_from_slice(&self.realm_id.to_be_bytes());
        result
    }

    fn get_clustering_key(&self) -> Option<Vec<u8>> {
        None
    }

    fn get_table_type(&self) -> u16 {
        TABLE_TYPE
    }
}
