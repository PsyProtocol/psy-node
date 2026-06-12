use kvq::traits::{KVQSerializable, ScyllaKey};
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::GenericHashOut};
use psy_client_common::data::qhashout::QHashOut;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RealmSnapshotKey<const TABLE_TYPE: u16> {
    pub realm_root: QHashOut<GoldilocksField>,
    pub version: u64,
}

impl<const TABLE_TYPE: u16> KVQSerializable for RealmSnapshotKey<TABLE_TYPE> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let root_bytes = KVQSerializable::to_bytes(&self.realm_root)?;
        let version_bytes = self.version.to_be_bytes();

        let mut result = Vec::with_capacity(2 + root_bytes.len() + 8);
        result.push((TABLE_TYPE >> 8) as u8);
        result.push((TABLE_TYPE & 0xff) as u8);
        result.extend_from_slice(&root_bytes);
        result.extend_from_slice(&version_bytes);
        Ok(result)
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() < 42 {
            // 2 (table type) + 32 (hash) + 8 (version)
            anyhow::bail!("expected at least 42 bytes for deserializing RealmSnapshotKey, got {} bytes", bytes.len());
        }

        let root_bytes = &bytes[2..34];
        let realm_root = <QHashOut<GoldilocksField> as KVQSerializable>::from_bytes(root_bytes)?;
        let version = u64::from_be_bytes(bytes[34..42].try_into().unwrap());

        Ok(RealmSnapshotKey { realm_root, version })
    }
}

impl<const TABLE_TYPE: u16> RealmSnapshotKey<TABLE_TYPE> {
    pub fn new(realm_root: QHashOut<GoldilocksField>, version: u64) -> Self {
        RealmSnapshotKey { realm_root, version }
    }
}

impl<const TABLE_TYPE: u16> ScyllaKey for RealmSnapshotKey<TABLE_TYPE> {
    fn get_partition_key(&self) -> Vec<u8> {
        GenericHashOut::to_bytes(&self.realm_root)
    }

    fn get_clustering_key(&self) -> Option<Vec<u8>> {
        Some(self.version.to_be_bytes().to_vec())
    }

    fn get_table_type(&self) -> u16 {
        TABLE_TYPE
    }
}
