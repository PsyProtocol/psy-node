use async_trait::async_trait;
use auto_impl::auto_impl;
use parth_core::{
    data::{
        db::temp_db::{
            TTPSerializeValue, TempTableDefintion, TempTablePrefixIdentifierBaseForKey,
        },
        serializable::QPDPair,
    },
    utils::auto_implement::QAutoImplementGeneric,
};
use crate::psy_temp_db::{
    TEMP_TABLE_ID_DEPLOY_CONTRACT_CODE_DEFINITION_BYTES, TEMP_TABLE_ID_JOB_CLAIM_BYTES,
    TEMP_TABLE_ID_JOB_STATS_BYTES, TEMP_TABLE_ID_PROOF_CLAIM_TAG_BYTES,
    TEMP_TABLE_ID_PROOF_WITNESS_DATA_BYTES, TEMP_TABLE_ID_SUBMIT_STATUS_BYTES,
    TEMP_TABLE_ID_TAG_TREE_VALUES_BYTES, TEMP_TABLE_ID_USER_CONTRACT_TREE_UPDATES_BYTES,
    TEMP_TABLE_ID_USER_END_CAP_SLOT_UPDATES_BYTES, TEMP_TABLE_ID_WORKER_PROOF_METADATA_BYTES,
};



#[async_trait]
#[auto_impl(&, Arc)]
pub trait QTempDatabaseRawKVReaderBase {
    async fn qtdb_raw_kv_get_value(&self, key: &[u8]) -> anyhow::Result<Option<Vec<u8>>>;
    async fn qtdb_raw_kv_get_many_values(&self, keys: &[&[u8]]) -> anyhow::Result<Vec<Option<Vec<u8>>>>;
    async fn qtdb_raw_kv_get_many_values_vec(&self, keys: &[Vec<u8>]) -> anyhow::Result<Vec<Option<Vec<u8>>>>;
    async fn qtdb_raw_kv_get_many_values_vec_owned(&self, keys: Vec<Vec<u8>>) -> anyhow::Result<Vec<Option<Vec<u8>>>>;
    async fn qtdb_raw_kv_contains_key(&self, key: &[u8]) -> anyhow::Result<bool>;
}




#[async_trait]
#[auto_impl(&, Arc)]
pub trait QTempDatabaseRawKVWriterBase {
    async fn qtdb_raw_kv_put_value(&self, key: &[u8], value: &[u8]) -> anyhow::Result<()>;
    async fn qtdb_raw_kv_put_value_if_absent(&self, key: &[u8], value: &[u8]) -> anyhow::Result<bool>;
    async fn qtdb_raw_kv_delete_key(&self, key: &[u8]) -> anyhow::Result<()>;
    async fn qtdb_raw_kv_put_many_values(&self, entries: &[QPDPair<Vec<u8>, Vec<u8>>]) -> anyhow::Result<()>;
    async fn qtdb_raw_kv_put_many_values_tuple(&self, entries: &[(Vec<u8>, Vec<u8>)]) -> anyhow::Result<()>;
    async fn qtdb_raw_kv_put_many_values_tuple_owned(&self, entries: Vec<(Vec<u8>, Vec<u8>)>) -> anyhow::Result<()>;
    async fn qtdb_raw_kv_put_many_values_tuple_ref<'a>(&self, entries: &[(&'a [u8], &'a [u8])]) -> anyhow::Result<()>;
    async fn qtdb_raw_kv_put_many_values_buffer<const KEY_SIZE: usize, const VALUE_SIZE: usize>(
        &self,
        data: &[u8],
    ) -> anyhow::Result<()>;
}

#[async_trait]
pub trait QTempDatabaseRawCounterReaderBase {
    async fn qtdb_raw_counter_get_value(&self, key: &[u8]) -> anyhow::Result<i64>;
}

#[async_trait]
pub trait QTempDatabaseRawCounterWriterBase {
    async fn qtdb_raw_counter_increment_by(&self, key: &[u8], increment_by: i64) -> anyhow::Result<i64>;
    async fn qtdb_raw_counter_set_value(&self, key: &[u8], value: i64) -> anyhow::Result<()>;
}

pub trait QTempDatabaseRawCounterStore: QTempDatabaseRawCounterReaderBase + QTempDatabaseRawCounterWriterBase {}
impl<T: QTempDatabaseRawCounterReaderBase + QTempDatabaseRawCounterWriterBase> QTempDatabaseRawCounterStore for T {}
pub trait QTempDatabaseRawKVStore: QTempDatabaseRawKVReaderBase + QTempDatabaseRawKVWriterBase {}
impl<T: QTempDatabaseRawKVReaderBase + QTempDatabaseRawKVWriterBase> QTempDatabaseRawKVStore for T {}
pub trait QTempDatabaseRawStoreReader: QTempDatabaseRawKVReaderBase + QTempDatabaseRawCounterReaderBase {}
impl<T: QTempDatabaseRawKVReaderBase + QTempDatabaseRawCounterReaderBase> QTempDatabaseRawStoreReader for T {}
pub trait QTempDatabaseRawStoreWriter: QTempDatabaseRawKVWriterBase + QTempDatabaseRawCounterWriterBase {}
impl<T: QTempDatabaseRawKVWriterBase + QTempDatabaseRawCounterWriterBase> QTempDatabaseRawStoreWriter for T {}
pub trait QTempDatabaseRawStore: QTempDatabaseRawStoreReader + QTempDatabaseRawStoreWriter {}
impl<T: QTempDatabaseRawStoreReader + QTempDatabaseRawStoreWriter> QTempDatabaseRawStore for T {}
// Physical pending KV field: LE realm_id:u32 | realm_sub_id:u16 | table_id:u16 | pending_id:u64 | suffix (not BE TempTablePrefixIdentifierRealm).
// Namespaces EP/PW/SS/CU/SU/TV/DC/JC/JS/CT; PI/GP/PS (no pending), WR (retained), SC (counter) excluded. CT table-id bytes spell TC.
pub const PENDING_TEMP_KV_PREFIX_LEN: usize = 16;

pub const PENDING_KEYED_TEMP_TABLE_ID_BYTES: &[[u8; 2]] = &[
    TEMP_TABLE_ID_WORKER_PROOF_METADATA_BYTES,
    TEMP_TABLE_ID_PROOF_WITNESS_DATA_BYTES,
    TEMP_TABLE_ID_SUBMIT_STATUS_BYTES,
    TEMP_TABLE_ID_USER_CONTRACT_TREE_UPDATES_BYTES,
    TEMP_TABLE_ID_USER_END_CAP_SLOT_UPDATES_BYTES,
    TEMP_TABLE_ID_TAG_TREE_VALUES_BYTES,
    TEMP_TABLE_ID_DEPLOY_CONTRACT_CODE_DEFINITION_BYTES,
    TEMP_TABLE_ID_JOB_CLAIM_BYTES,
    TEMP_TABLE_ID_JOB_STATS_BYTES,
    TEMP_TABLE_ID_PROOF_CLAIM_TAG_BYTES,
];

pub fn pending_temp_kv_prefix(
    realm_id: u32,
    realm_sub_id: u16,
    table_id_bytes: [u8; 2],
    pending_id: u64,
) -> [u8; PENDING_TEMP_KV_PREFIX_LEN] {
    let mut prefix = [0u8; PENDING_TEMP_KV_PREFIX_LEN];
    prefix[0..4].copy_from_slice(&realm_id.to_le_bytes());
    prefix[4..6].copy_from_slice(&realm_sub_id.to_le_bytes());
    prefix[6..8].copy_from_slice(&table_id_bytes);
    prefix[8..16].copy_from_slice(&pending_id.to_le_bytes());
    prefix
}

pub fn filter_temp_kv_fields_by_pending(
    fields: &[Vec<u8>],
    realm_id: u32,
    realm_sub_id: u16,
    pending_id: u64,
) -> Vec<Vec<u8>> {
    let realm_le = realm_id.to_le_bytes();
    let sub_le = realm_sub_id.to_le_bytes();
    let pending_le = pending_id.to_le_bytes();
    let mut matched = Vec::new();
    for field in fields {
        if field.len() < PENDING_TEMP_KV_PREFIX_LEN {
            continue;
        }
        if field[0..4] != realm_le || field[4..6] != sub_le || field[8..16] != pending_le {
            continue;
        }
        let table_id_bytes = [field[6], field[7]];
        if PENDING_KEYED_TEMP_TABLE_ID_BYTES.contains(&table_id_bytes) {
            matched.push(field.clone());
        }
    }
    matched
}

#[derive(Debug, Clone)]
pub struct TempKvScanPage {
    pub next_cursor: u64,
    pub fields: Vec<Vec<u8>>,
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait QTempDatabaseRawKVEnumeratorBase {
    async fn qtdb_raw_kv_scan_fields(
        &self,
        cursor: u64,
        count: u32,
    ) -> anyhow::Result<TempKvScanPage>;
}


#[async_trait]
pub trait QTempDatabaseKVReaderBase {
    async fn get_temp_database_value<const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        key: &T::Key,
    ) -> anyhow::Result<Option<T::Value>>;
    async fn get_temp_database_value_raw<const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        key: &T::Key,
    ) -> anyhow::Result<Option<Vec<u8>>>;
    async fn get_many_temp_database_values_key_refs_raw<const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        keys: &[T::Key],
    ) -> anyhow::Result<Vec<Option<Vec<u8>>>>;
    async fn get_many_temp_database_values_key_refs<const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        keys: &[T::Key],
    ) -> anyhow::Result<Vec<Option<T::Value>>>;
    async fn get_many_temp_database_values<'a, const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        keys: &'a [T::Key],
    ) -> anyhow::Result<Vec<Option<T::Value>>>;
    async fn contains_temp_database_key<const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        key: &T::Key,
    ) -> anyhow::Result<bool>;
}

#[async_trait]
pub trait QTempDatabaseKVWriterBase {
    async fn put_temp_database_value<const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        key: &T::Key,
        value: &T::Value,
    ) -> anyhow::Result<()>;
    async fn put_temp_database_value_raw<const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        key: &T::Key,
        value: &[u8],
    ) -> anyhow::Result<()>;
    async fn put_temp_database_value_raw_owned<const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        key: &T::Key,
        value: Vec<u8>,
    ) -> anyhow::Result<()>;
    async fn delete_temp_database_key<const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        key: &T::Key,
    ) -> anyhow::Result<()>;
    async fn put_many_temp_database_values_raw_tuple<const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        entries: &[(T::Key, Vec<u8>)],
    ) -> anyhow::Result<()>;
    async fn put_many_temp_database_values<const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        entries: &[QPDPair<T::Key, T::Value>],
    ) -> anyhow::Result<()>;
    async fn put_many_temp_database_values_tuple<const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        entries: &[(T::Key, T::Value)],
    ) -> anyhow::Result<()>;
}

#[async_trait]
pub trait QTempDatabaseCounterReaderBase {
    async fn get_temp_database_counter<const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        key: &T::Key,
    ) -> anyhow::Result<i64>;
}
#[async_trait]
pub trait QTempDatabaseCounterWriterBase {
    async fn increment_temp_database_counter<const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        key: &T::Key,
        increment_by: i64,
    ) -> anyhow::Result<i64>;
    async fn set_temp_database_counter<const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        key: &T::Key,
        value: i64,
    ) -> anyhow::Result<()>;
}

#[async_trait]
impl<DB: QTempDatabaseRawKVReaderBase + QAutoImplementGeneric + Send + Sync> QTempDatabaseKVReaderBase for DB {
    async fn get_temp_database_value<const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        key: &T::Key,
    ) -> anyhow::Result<Option<T::Value>> {
        let bytes = self.qtdb_raw_kv_get_value(&table.get_key_prefix().ttp_get_full_key_vec(key)).await?;
        match bytes {
            Some(b) => {
                let v = T::Value::ttp_from_bytes(&b)?;
                Ok(Some(v))
            }
            None => Ok(None),
        }
    }
    async fn get_many_temp_database_values_key_refs_raw<const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        keys: &[T::Key],
    ) -> anyhow::Result<Vec<Option<Vec<u8>>>>{
        let key_bytes = keys.iter().map(|k| table.get_key_prefix().ttp_get_full_key_vec(k)).collect::<Vec<_>>();
        let results = self
            .qtdb_raw_kv_get_many_values_vec(&key_bytes)
            .await?;
        Ok(results)
    }
    async fn get_temp_database_value_raw<const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        key: &T::Key,
    ) -> anyhow::Result<Option<Vec<u8>>>{
        self.qtdb_raw_kv_get_value(&table.get_key_prefix().ttp_get_full_key_vec(key)).await
    }
    async fn get_many_temp_database_values_key_refs<const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        keys: &[T::Key],
    ) -> anyhow::Result<Vec<Option<T::Value>>>{
        let key_bytes = keys.iter().map(|k| table.get_key_prefix().ttp_get_full_key_vec(k)).collect::<Vec<_>>();
        let results = self
            .qtdb_raw_kv_get_many_values_vec(&key_bytes)
            .await?
            .into_iter()
            .map(|opt_bytes| match opt_bytes {
                Some(b) => {
                    let v = T::Value::ttp_from_bytes(&b)?;
                    Ok(Some(v))
                }
                None => Ok(None),
            })
            .collect::<Result<Vec<Option<T::Value>>, anyhow::Error>>()?;
        Ok(results)

    }
    async fn get_many_temp_database_values<'a, const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        keys: &'a [T::Key],
    ) -> anyhow::Result<Vec<Option<T::Value>>> {
        let key_bytes = keys.iter().map(|k| table.get_key_prefix().ttp_get_full_key_vec(k)).collect::<Vec<_>>();
        let results = self
            .qtdb_raw_kv_get_many_values_vec(&key_bytes)
            .await?
            .into_iter()
            .map(|opt_bytes| match opt_bytes {
                Some(b) => {
                    let v = T::Value::ttp_from_bytes(&b)?;
                    Ok(Some(v))
                }
                None => Ok(None),
            })
            .collect::<Result<Vec<Option<T::Value>>, anyhow::Error>>()?;
        Ok(results)
    }
    async fn contains_temp_database_key<const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        key: &T::Key,
    ) -> anyhow::Result<bool> {
        self.qtdb_raw_kv_contains_key(&table.get_key_prefix().ttp_get_full_key_vec(key)).await
    }
}

#[async_trait]
impl<DB: QTempDatabaseRawKVWriterBase + QAutoImplementGeneric + Send + Sync> QTempDatabaseKVWriterBase for DB {
    async fn put_temp_database_value<const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        key: &T::Key,
        value: &T::Value,
    ) -> anyhow::Result<()> {
        let key_bytes = table.get_key_prefix().ttp_get_full_key_vec(key);
        let value_bytes = value.ttp_to_bytes()?;
        self.qtdb_raw_kv_put_value(&key_bytes, &value_bytes).await
    }
    async fn put_temp_database_value_raw<const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        key: &T::Key,
        value: &[u8],
    ) -> anyhow::Result<()>{
        let key_bytes = table.get_key_prefix().ttp_get_full_key_vec(key);
        self.qtdb_raw_kv_put_value(&key_bytes, value).await
    }

    async fn put_temp_database_value_raw_owned<const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        key: &T::Key,
        value: Vec<u8>,
    ) -> anyhow::Result<()>{
        let key_bytes = table.get_key_prefix().ttp_get_full_key_vec(key);
        self.qtdb_raw_kv_put_value(&key_bytes, &value).await
    }
    async fn delete_temp_database_key<const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        key: &T::Key,
    ) -> anyhow::Result<()> {
        let key_bytes = table.get_key_prefix().ttp_get_full_key_vec(key);
        self.qtdb_raw_kv_delete_key(&key_bytes).await
    }
    async fn put_many_temp_database_values<const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        entries: &[QPDPair<T::Key, T::Value>],
    ) -> anyhow::Result<()> {
        let kv_bytes = entries
            .iter()
            .map(|entry| {
                let key_bytes = table.get_key_prefix().ttp_get_full_key_vec(&entry.key);
                let value_bytes = entry.value.ttp_to_bytes()?;
                Ok(QPDPair {
                    key: key_bytes,
                    value: value_bytes,
                })
            })
            .collect::<Result<Vec<QPDPair<Vec<u8>, Vec<u8>>>, anyhow::Error>>()?;
        self.qtdb_raw_kv_put_many_values(&kv_bytes).await
    }
    async fn put_many_temp_database_values_tuple<const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        entries: &[(T::Key, T::Value)],
    ) -> anyhow::Result<()> {
        let kv_bytes = entries
            .iter()
            .map(|(key, value)| {
                let key_bytes = table.get_key_prefix().ttp_get_full_key_vec(key);
                let value_bytes = value.ttp_to_bytes()?;
                Ok((key_bytes, value_bytes))
            })
            .collect::<Result<Vec<(Vec<u8>, Vec<u8>)>, anyhow::Error>>()?;
        self.qtdb_raw_kv_put_many_values_tuple(&kv_bytes).await
    }

    async fn put_many_temp_database_values_raw_tuple<const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        entries: &[(T::Key, Vec<u8>)],
    ) -> anyhow::Result<()>{
        let kv_bytes = entries
            .iter()
            .map(|(key, value)| {
                let key_bytes = table.get_key_prefix().ttp_get_full_key_vec(key);
                Ok((key_bytes, value.clone()))
            })
            .collect::<Result<Vec<(Vec<u8>, Vec<u8>)>, anyhow::Error>>()?;
        self.qtdb_raw_kv_put_many_values_tuple(&kv_bytes).await
    }
}

#[async_trait]
impl<DB: QTempDatabaseRawCounterReaderBase + QAutoImplementGeneric + Send + Sync> QTempDatabaseCounterReaderBase for DB {
    async fn get_temp_database_counter<const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        key: &T::Key,
    ) -> anyhow::Result<i64> {
        let key_bytes = table.get_key_prefix().ttp_get_full_key_vec(key);
        self.qtdb_raw_counter_get_value(&key_bytes).await
    }
}
#[async_trait]
impl<DB: QTempDatabaseRawCounterWriterBase + QAutoImplementGeneric + Send + Sync> QTempDatabaseCounterWriterBase for DB {
    async fn increment_temp_database_counter<const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        key: &T::Key,
        increment_by: i64,
    ) -> anyhow::Result<i64> {
        let key_bytes = table.get_key_prefix().ttp_get_full_key_vec(key);
        self.qtdb_raw_counter_increment_by(&key_bytes, increment_by).await
    }
    async fn set_temp_database_counter<const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        key: &T::Key,
        value: i64,
    ) -> anyhow::Result<()> {
        let key_bytes = table.get_key_prefix().ttp_get_full_key_vec(key);
        self.qtdb_raw_counter_set_value(&key_bytes, value).await
    }
}

#[cfg(test)]
mod rollback_enum_tests {
    use super::{
        filter_temp_kv_fields_by_pending, pending_temp_kv_prefix, PENDING_KEYED_TEMP_TABLE_ID_BYTES,
        PENDING_TEMP_KV_PREFIX_LEN, QTempDatabaseRawKVEnumeratorBase, QTempDatabaseRawKVReaderBase,
        QTempDatabaseRawKVWriterBase, TempKvScanPage,
    };
    use crate::memory_stores::simple_memory_temp_store::SimpleMemoryTempStore;
    use crate::psy_temp_db::{
        tt_get_job_claim_key_from_bytes, tt_get_job_stats_count_key, tt_get_proof_claim_tag_key,
        tt_get_proving_job_metadata_key, tt_get_submit_status_key, tt_get_unique_pending_id_key,
        tt_get_worker_reputation_key, TEMP_TABLE_ID_JOB_STATS_BYTES,
        TEMP_TABLE_ID_PROOF_CLAIM_TAG_BYTES, TEMP_TABLE_ID_WORKER_PROOF_METADATA_BYTES,
    };
    use crate::psy_temp_db::{
        tt_get_contract_updates_key, tt_get_deploy_contract_code_definition_key,
        tt_get_proof_witness_data_key, tt_get_rewards_tag_tree_value_key,
        tt_get_user_end_cap_slot_updates_key,
    };
    use parth_core::QJobIdSerialized;
    use std::collections::HashSet;

    const REALM: u32 = 3;
    const SUB: u16 = 0;
    const PENDING: u64 = 88;

    fn job_id(seed: u8) -> QJobIdSerialized {
        let mut j = [0u8; 24];
        j[0] = seed;
        j
    }

    async fn seed_store(store: &SimpleMemoryTempStore) -> Vec<Vec<u8>> {
        let mut expected = Vec::new();

        let pending_keys: Vec<Vec<u8>> = vec![
            tt_get_proving_job_metadata_key(REALM, SUB, PENDING, &job_id(1)).to_vec(),
            tt_get_proving_job_metadata_key(REALM, SUB, PENDING, &job_id(2)).to_vec(),
            tt_get_proof_witness_data_key(REALM, SUB, PENDING, &job_id(3)).to_vec(),
            tt_get_submit_status_key(REALM, SUB, PENDING, 777).to_vec(),
            tt_get_contract_updates_key(REALM, SUB, PENDING, 11).to_vec(),
            tt_get_user_end_cap_slot_updates_key(REALM, SUB, PENDING, 12).to_vec(),
            tt_get_rewards_tag_tree_value_key(REALM, SUB, PENDING, &job_id(4)).to_vec(),
            tt_get_deploy_contract_code_definition_key(REALM, SUB, PENDING, &[7u8; 16]).to_vec(),
            tt_get_job_claim_key_from_bytes(REALM, SUB, PENDING, &job_id(5)).to_vec(),
            tt_get_job_stats_count_key(REALM, SUB, PENDING).to_vec(),
            tt_get_proof_claim_tag_key(REALM, SUB, PENDING, &job_id(6)).to_vec(),
        ];
        for k in &pending_keys {
            store.qtdb_raw_kv_put_value(k, b"v").await.unwrap();
        }
        expected.extend(pending_keys);

        let other_pending = tt_get_proving_job_metadata_key(REALM, SUB, PENDING + 1, &job_id(9)).to_vec();
        store.qtdb_raw_kv_put_value(&other_pending, b"v").await.unwrap();

        let other_realm = tt_get_submit_status_key(REALM + 1, SUB, PENDING, 1).to_vec();
        store.qtdb_raw_kv_put_value(&other_realm, b"v").await.unwrap();

        let other_sub = tt_get_submit_status_key(REALM, SUB + 1, PENDING, 1).to_vec();
        store.qtdb_raw_kv_put_value(&other_sub, b"v").await.unwrap();

        let pi = tt_get_unique_pending_id_key(REALM, SUB).to_vec();
        store.qtdb_raw_kv_put_value(&pi, b"v").await.unwrap();

        let mut pk = [0u8; 33];
        pk[0] = 0x02;
        let wr = tt_get_worker_reputation_key(REALM, SUB, &pk).to_vec();
        store.qtdb_raw_kv_put_value(&wr, b"v").await.unwrap();

        let mut short = vec![0u8; PENDING_TEMP_KV_PREFIX_LEN - 1];
        short[0..4].copy_from_slice(&REALM.to_le_bytes());
        short[4..6].copy_from_slice(&SUB.to_le_bytes());
        short[6..8].copy_from_slice(&PENDING_KEYED_TEMP_TABLE_ID_BYTES[0]);
        store.qtdb_raw_kv_put_value(&short, b"v").await.unwrap();

        expected
    }

    async fn enumerate_all(store: &SimpleMemoryTempStore, count: u32) -> Vec<Vec<u8>> {
        let mut all = Vec::new();
        let mut cursor = 0u64;
        loop {
            let TempKvScanPage { next_cursor, fields } =
                store.qtdb_raw_kv_scan_fields(cursor, count).await.unwrap();
            all.extend(fields);
            cursor = next_cursor;
            if cursor == 0 {
                break;
            }
        }
        all
    }

    #[tokio::test]
    async fn prefix_builder_is_little_endian() {
        let prefix = pending_temp_kv_prefix(REALM, SUB, TEMP_TABLE_ID_WORKER_PROOF_METADATA_BYTES, PENDING);
        let ep = tt_get_proving_job_metadata_key(REALM, SUB, PENDING, &job_id(1));
        assert_eq!(prefix.as_slice(), &ep[0..PENDING_TEMP_KV_PREFIX_LEN]);
        assert_eq!(&prefix[0..4], &REALM.to_le_bytes());
        assert_eq!(&prefix[4..6], &SUB.to_le_bytes());
        assert_eq!(&prefix[6..8], b"EP");
        assert_eq!(&prefix[8..16], &PENDING.to_le_bytes());
    }

    #[tokio::test]
    async fn exact_prefix_filter_includes_js_and_ct_rejects_decoys() {
        let store = SimpleMemoryTempStore::new();
        let expected = seed_store(&store).await;

        let all = enumerate_all(&store, 64).await;
        let matched = filter_temp_kv_fields_by_pending(&all, REALM, SUB, PENDING);

        let matched_set: HashSet<Vec<u8>> = matched.iter().cloned().collect();
        let expected_set: HashSet<Vec<u8>> = expected.iter().cloned().collect();
        assert_eq!(matched_set, expected_set, "filter must keep exactly the pending-keyed fields");
        assert!(matched.iter().any(|f| &f[6..8] == TEMP_TABLE_ID_JOB_STATS_BYTES), "JS must be included");
        assert!(matched.iter().any(|f| &f[6..8] == TEMP_TABLE_ID_PROOF_CLAIM_TAG_BYTES), "CT (proof claim tag) must be included");

        assert!(!matched.iter().any(|f| &f[6..8] == b"PI"), "PI singleton must not match");
        assert!(!matched.iter().any(|f| &f[6..8] == b"WR"), "WR must not match");
        assert!(matched.iter().all(|f| f.len() >= PENDING_TEMP_KV_PREFIX_LEN), "short fields rejected");
        assert!(matched.iter().all(|f| &f[0..4] == &REALM.to_le_bytes() && &f[4..6] == &SUB.to_le_bytes() && &f[8..16] == &PENDING.to_le_bytes()));
    }

    #[tokio::test]
    async fn pagination_collects_all_fields_without_duplicates() {
        let store = SimpleMemoryTempStore::new();
        seed_store(&store).await;

        let collected = enumerate_all(&store, 2).await;

        let set: HashSet<Vec<u8>> = collected.iter().cloned().collect();
        assert_eq!(set.len(), collected.len(), "no duplicate fields across pages");

        let big = enumerate_all(&store, 1024).await;
        let big_set: HashSet<Vec<u8>> = big.iter().cloned().collect();
        assert_eq!(set, big_set, "pagination must enumerate the same fields as a single page");
    }

    #[tokio::test]
    async fn empty_store_enumerates_one_terminated_page() {
        let store = SimpleMemoryTempStore::new();
        let page = store.qtdb_raw_kv_scan_fields(0, 10).await.unwrap();
        assert_eq!(page.next_cursor, 0);
        assert!(page.fields.is_empty());
    }

    #[tokio::test]
    async fn hdel_filtered_fields_never_touches_other_rows_or_the_hash() {
        let store = SimpleMemoryTempStore::new();
        let expected = seed_store(&store).await;

        let all = enumerate_all(&store, 64).await;
        let matched = filter_temp_kv_fields_by_pending(&all, REALM, SUB, PENDING);

        for field in &matched {
            store.qtdb_raw_kv_delete_key(field).await.unwrap();
        }

        for field in &matched {
            assert!(!store.qtdb_raw_kv_contains_key(field).await.unwrap(), "filtered field must be HDELed");
        }

        let pi = tt_get_unique_pending_id_key(REALM, SUB).to_vec();
        let other_pending = tt_get_proving_job_metadata_key(REALM, SUB, PENDING + 1, &job_id(9)).to_vec();
        let other_realm = tt_get_submit_status_key(REALM + 1, SUB, PENDING, 1).to_vec();
        assert!(store.qtdb_raw_kv_contains_key(&pi).await.unwrap(), "PI singleton survives");
        assert!(store.qtdb_raw_kv_contains_key(&other_pending).await.unwrap(), "other-pending row survives");
        assert!(store.qtdb_raw_kv_contains_key(&other_realm).await.unwrap(), "other-realm row survives");

        let remaining = enumerate_all(&store, 1024).await;
        assert!(!remaining.is_empty(), "hash must still contain surviving rows");
        assert_eq!(remaining.len(), 6, "exactly the 6 decoys remain");
        let _ = expected;
    }
}
