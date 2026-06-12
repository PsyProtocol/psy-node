use kvq::traits::{KVQBinaryStore, KVQSerializable};
use plonky2::hash::hash_types::RichField;
use psy_client_common::{data::qhashout::QHashOut, utils::math::ceil_div_usize};
use psy_config::network_constants::REALM_USER_TREE_HEIGHT;

use crate::qdata::staging_delta_record_key::StagingDeltaRecordKey;

pub struct StagingDeltaRecordModelCore<const TABLE_TYPE: u16, S, IDKVA> {
    _idkva: IDKVA,
    _store: S,
}

impl<const TABLE_TYPE: u16, S, IDKVA> StagingDeltaRecordModelCore<TABLE_TYPE, S, IDKVA> {
    pub fn set_delta_record<F: RichField, T: serde::Serialize, Store: KVQBinaryStore>(
        store: &Store,
        realm_root: QHashOut<F>,
        realm_id: u32,
        update: &T,
    ) -> anyhow::Result<()> {
        let key = StagingDeltaRecordKey::<F, TABLE_TYPE>::new(realm_root, realm_id);
        let value_bytes = bincode::serialize(update)?;
        store.set(key.to_bytes()?, value_bytes)?;
        Ok(())
    }

    pub fn get_delta_records_for_realm_root<F: RichField, T: serde::de::DeserializeOwned, Store: KVQBinaryStore>(
        store: &Store,
        realm_root: QHashOut<F>,
    ) -> anyhow::Result<Vec<T>> {
        let real_max_realm_id = (1u32 << (REALM_USER_TREE_HEIGHT as u32)) - 1;
        let realm_id_bytes = ceil_div_usize(REALM_USER_TREE_HEIGHT as usize, 8);

        let max_key = StagingDeltaRecordKey::<F, TABLE_TYPE>::new(realm_root, real_max_realm_id);

        let kv_pairs = store.get_fuzzy_range_leq_kv(&max_key.to_bytes()?, realm_id_bytes)?;

        let mut records = Vec::new();
        for kv_pair in kv_pairs {
            let record: T = bincode::deserialize(&kv_pair.value)?;
            records.push(record);
        }

        Ok(records)
    }

    pub fn delete_delta_records_for_realm_root<F: RichField, Store: KVQBinaryStore>(store: &Store, realm_root: QHashOut<F>) -> anyhow::Result<usize> {
        let real_max_realm_id = (1u32 << (REALM_USER_TREE_HEIGHT as u32)) - 1;
        let realm_id_bytes = ceil_div_usize(REALM_USER_TREE_HEIGHT as usize, 8);

        let max_key = StagingDeltaRecordKey::<F, TABLE_TYPE>::new(realm_root, real_max_realm_id);

        let kv_pairs = store.get_fuzzy_range_leq_kv(&max_key.to_bytes()?, realm_id_bytes)?;

        let keys_to_delete: Vec<_> = kv_pairs.iter().map(|kv| kv.key.clone()).collect();
        let deletion_results = store.delete_many(&keys_to_delete)?;
        let deleted_count = deletion_results.iter().filter(|&&result| result).count();

        Ok(deleted_count)
    }

    pub fn get_delta_record<F: RichField, T: serde::de::DeserializeOwned, Store: KVQBinaryStore>(
        store: &Store,
        realm_root: QHashOut<F>,
        realm_id: u32,
    ) -> anyhow::Result<Option<T>> {
        let key = StagingDeltaRecordKey::<F, TABLE_TYPE>::new(realm_root, realm_id);
        if let Some(value_bytes) = store.get_exact_if_exists(&key.to_bytes()?)? {
            let record: T = bincode::deserialize(&value_bytes)?;
            Ok(Some(record))
        } else {
            Ok(None)
        }
    }

    pub fn delete_delta_record<F: RichField, Store: KVQBinaryStore>(store: &Store, realm_root: QHashOut<F>, realm_id: u32) -> anyhow::Result<bool> {
        let key = StagingDeltaRecordKey::<F, TABLE_TYPE>::new(realm_root, realm_id);
        store.delete(&key.to_bytes()?)
    }
}
