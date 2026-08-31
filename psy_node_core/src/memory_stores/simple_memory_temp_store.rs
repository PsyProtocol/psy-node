use async_trait::async_trait;
use parth_core::{
    data::{
        db::temp_db::{TempTableDefintion, TempTablePrefixIdentifierBaseForKey},
        serializable::{QPDPair, QPDSerializable},
    },
    utils::auto_implement::QAutoImplementGeneric,
    QJobIdSerialized,
};
use std::{collections::HashMap, sync::{Arc, RwLock}};

use crate::store::traits::{proof_store::{QParthProofBucketPresenceReader, QParthProofStoreReader, QParthProofStoreWriter}, temp_db::{QTempDatabaseCounterReaderBase, QTempDatabaseCounterWriterBase, QTempDatabaseRawKVEnumeratorBase, QTempDatabaseRawKVReaderBase, QTempDatabaseRawKVWriterBase, TempKvScanPage}};

#[derive(Debug, Clone)]
pub struct SimpleMemoryTempStore {
    pub kv_map: Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>>,
    pub counter_map: Arc<RwLock<HashMap<Vec<u8>, i64>>>,
    pub proof_map: Arc<RwLock<HashMap<u64, HashMap<Vec<u8>, Vec<u8>>>>>,
}
impl SimpleMemoryTempStore {
    pub fn new() -> Self {
        Self {
            kv_map: Arc::new(RwLock::new(HashMap::new())),
            counter_map: Arc::new(RwLock::new(HashMap::new())),
            proof_map: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl QParthProofStoreReader for SimpleMemoryTempStore {

    async fn get_proof_bytes_by_job_id<J: Into<QJobIdSerialized> + Copy + Send + Sync>(&self, job_id: J, unique_pending_id: u64) -> anyhow::Result<Option<Vec<u8>>>{
        let job_id_bytes = job_id.into().to_vec();
        let guard = self.proof_map.read().map_err(|e| anyhow::anyhow!(e.to_string()))?;
        Ok(guard.get(&unique_pending_id).and_then(|bucket| bucket.get(&job_id_bytes).cloned()))
    }
    async fn get_proof_by_job_id<J: Into<QJobIdSerialized> + Copy + Send + Sync, P: QPDSerializable>(&self, job_id: J, unique_pending_id: u64) -> anyhow::Result<Option<P>>{
        let job_id_bytes = job_id.into().to_vec();
        let guard = self.proof_map.read().map_err(|e| anyhow::anyhow!(e.to_string()))?;
        if let Some(data) = guard.get(&unique_pending_id).and_then(|bucket| bucket.get(&job_id_bytes)) {
            let proof = P::from_bytes(data)?;
            Ok(Some(proof))
        } else {
            Ok(None)
        }
    }
    async fn contains_proof_for_job_id<J:  Into<QJobIdSerialized> + Copy + Send + Sync>(&self, job_id: J, unique_pending_id: u64) -> anyhow::Result<bool> {
        let job_id_bytes = job_id.into().to_vec();
        let guard = self.proof_map.read().map_err(|e| anyhow::anyhow!(e.to_string()))?;
        Ok(guard
            .get(&unique_pending_id)
            .map(|bucket| bucket.contains_key(&job_id_bytes))
            .unwrap_or(false))
    }

}

#[async_trait]
impl QParthProofStoreWriter for SimpleMemoryTempStore {
    async fn put_proof_bytes_for_job_id<J: Into<QJobIdSerialized> + Copy + Send + Sync>(&self, job_id: J, unique_pending_id: u64, proof_bytes: &[u8]) -> anyhow::Result<()>{
        let job_id_bytes = job_id.into().to_vec();
        let mut guard = self.proof_map.write().map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let bucket = guard.entry(unique_pending_id).or_insert_with(HashMap::new);
        bucket.insert(job_id_bytes, proof_bytes.to_vec());
        Ok(())

    }
    async fn put_proof_for_job_id<J: Into<QJobIdSerialized> + Copy + Send + Sync, P: QPDSerializable + Send + Sync>(&self, job_id: J, unique_pending_id: u64, proof: &P) -> anyhow::Result<()> {
        let proof_bytes = proof.to_bytes()?;
        let job_id_bytes = job_id.into().to_vec();
        let mut guard = self.proof_map.write().map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let bucket = guard.entry(unique_pending_id).or_insert_with(HashMap::new);
        bucket.insert(job_id_bytes, proof_bytes);
        Ok(())
    }
    async fn delete_all_proofs_for_pending_id(&self, unique_pending_id: u64) -> anyhow::Result<()> {
        self.proof_map
            .write()
            .map_err(|e| anyhow::anyhow!(e.to_string()))?
            .remove(&unique_pending_id);
        Ok(())
    }
}

#[async_trait]
impl QParthProofBucketPresenceReader for SimpleMemoryTempStore {
    async fn contains_proofs_for_pending_id(&self, unique_pending_id: u64) -> anyhow::Result<bool> {
        let guard = self.proof_map.read().map_err(|e| anyhow::anyhow!(e.to_string()))?;
        Ok(guard.get(&unique_pending_id).map(|b| !b.is_empty()).unwrap_or(false))
    }
}


#[async_trait]
impl QTempDatabaseCounterReaderBase for SimpleMemoryTempStore {
    async fn get_temp_database_counter<const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        key: &T::Key,
    ) -> anyhow::Result<i64> {
        Ok(*self.counter_map.read().map_err(|e| anyhow::anyhow!(e.to_string()))?.get(&table.get_key_prefix().ttp_get_full_key_vec(key)).unwrap_or(&0))
    }
}

#[async_trait]
impl QTempDatabaseCounterWriterBase for SimpleMemoryTempStore {
    async fn increment_temp_database_counter<const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        key: &T::Key,
        increment_by: i64,
    ) -> anyhow::Result<i64> {
        let full_key = table.get_key_prefix().ttp_get_full_key_vec(key);
        let mut counter_map = self.counter_map.write().map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let counter = counter_map.entry(full_key).or_insert(0);
        *counter += increment_by;
        Ok(*counter)
    }
    async fn set_temp_database_counter<const CKS: usize, const KS: usize, T: TempTableDefintion<CKS, KS>>(
        &self,
        table: &T,
        key: &T::Key,
        value: i64,
    ) -> anyhow::Result<()>{
        let full_key = table.get_key_prefix().ttp_get_full_key_vec(key);
        self.counter_map.write().map_err(|e| anyhow::anyhow!(e.to_string()))?.insert(full_key, value);
        Ok(())
    }
}

/*



#[async_trait]
pub trait QTempDatabaseRawKVReaderBase {
    async fn qtdb_raw_kv_get_value(&self, key: &[u8]) -> anyhow::Result<Option<Vec<u8>>>;
    async fn qtdb_raw_kv_get_many_values(&self, keys: &[&[u8]]) -> anyhow::Result<Vec<Option<Vec<u8>>>>;
    async fn qtdb_raw_kv_get_many_values_vec(&self, keys: &[Vec<u8>]) -> anyhow::Result<Vec<Option<Vec<u8>>>>;
    async fn qtdb_raw_kv_contains_key(&self, key: &[u8]) -> anyhow::Result<bool>;
}

#[async_trait]
pub trait QTempDatabaseRawKVWriterBase {
    async fn qtdb_raw_kv_put_value(&self, key: &[u8], value: &[u8]) -> anyhow::Result<()>;
    async fn qtdb_raw_kv_delete_key(&self, key: &[u8]) -> anyhow::Result<()>;
    async fn qtdb_raw_kv_put_many_values(&self, entries: &[QPDPair<Vec<u8>, Vec<u8>>]) -> anyhow::Result<()>;
    async fn qtdb_raw_kv_put_many_values_tuple(&self, entries: &[(Vec<u8>, Vec<u8>)]) -> anyhow::Result<()>;
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
    
*/

#[async_trait]
impl QTempDatabaseRawKVReaderBase for SimpleMemoryTempStore {
    async fn qtdb_raw_kv_get_value(&self, key: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self.kv_map.read().map_err(|e| anyhow::anyhow!(e.to_string()))?.get(key).cloned())
    }
    async fn qtdb_raw_kv_get_many_values(&self, keys: &[&[u8]]) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
        let kv_map = self.kv_map.read().map_err(|e| anyhow::anyhow!(e.to_string()))?;
        Ok(keys.iter().map(|key| kv_map.get(*key).cloned()).collect())
    }
    async fn qtdb_raw_kv_get_many_values_vec(&self, keys: &[Vec<u8>]) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
        let kv_map = self.kv_map.read().map_err(|e| anyhow::anyhow!(e.to_string()))?;
        Ok(keys.iter().map(|key| kv_map.get(key).cloned()).collect())
    }
    async fn qtdb_raw_kv_get_many_values_vec_owned(&self, keys: Vec<Vec<u8>>) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
        let kv_map = self.kv_map.read().map_err(|e| anyhow::anyhow!(e.to_string()))?;
        Ok(keys.iter().map(|key| kv_map.get(key).cloned()).collect())
    }
    async fn qtdb_raw_kv_contains_key(&self, key: &[u8]) -> anyhow::Result<bool> {
        Ok(self.kv_map.read().map_err(|e| anyhow::anyhow!(e.to_string()))?.contains_key(key))
    }
}
#[async_trait]
impl QTempDatabaseRawKVWriterBase for SimpleMemoryTempStore {
    async fn qtdb_raw_kv_put_value(&self, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
        self.kv_map.write().map_err(|e| anyhow::anyhow!(e.to_string()))?.insert(key.to_vec(), value.to_vec());
        Ok(())
    }
    async fn qtdb_raw_kv_delete_key(&self, key: &[u8]) -> anyhow::Result<()> {
        self.kv_map.write().map_err(|e| anyhow::anyhow!(e.to_string()))?.remove(key);
        Ok(())
    }
    async fn qtdb_raw_kv_put_many_values(&self, entries: &[QPDPair<Vec<u8>, Vec<u8>>]) -> anyhow::Result<()> {
        let mut kv_map = self.kv_map.write().map_err(|e| anyhow::anyhow!(e.to_string()))?;
        for entry in entries {
            kv_map.insert(entry.key.clone(), entry.value.clone());
        }
        Ok(())
    }
    async fn qtdb_raw_kv_put_many_values_tuple_owned(&self, entries: Vec<(Vec<u8>, Vec<u8>)>) -> anyhow::Result<()> {
        let mut kv_map = self.kv_map.write().map_err(|e| anyhow::anyhow!(e.to_string()))?;
        for (key, value) in entries {
            kv_map.insert(key, value);
        }
        Ok(())
    }

    async fn qtdb_raw_kv_put_many_values_tuple(&self, entries: &[(Vec<u8>, Vec<u8>)]) -> anyhow::Result<()> {
        let mut kv_map = self.kv_map.write().map_err(|e| anyhow::anyhow!(e.to_string()))?;
        for (key, value) in entries {
            kv_map.insert(key.clone(), value.clone());
        }
        Ok(())
    }

    async fn qtdb_raw_kv_put_many_values_tuple_ref<'a>(&self, entries: &[(&'a [u8], &'a [u8])]) -> anyhow::Result<()>{
        let mut kv_map = self.kv_map.write().map_err(|e| anyhow::anyhow!(e.to_string()))?;
        for (key, value) in entries {
            kv_map.insert(key.to_vec(), value.to_vec());
        }
        Ok(())
    }

    async fn qtdb_raw_kv_put_many_values_buffer<const KEY_SIZE: usize, const VALUE_SIZE: usize>(
        &self,
        data: &[u8],
    ) -> anyhow::Result<()>{
        let combined_size: usize = KEY_SIZE + VALUE_SIZE;
        if data.len() % combined_size != 0 {
            return Err(anyhow::anyhow!("Data length is not a multiple of combined key and value size"));
        }
        if data.len() == 0 {
            return Ok(());
        }
        let entry_count = data.len() / combined_size;
        for i in 0..entry_count {
            let start = i * combined_size;
            let key = &data[start..start + KEY_SIZE];
            let value = &data[start + KEY_SIZE..start + combined_size];
            self.kv_map.write().map_err(|e| anyhow::anyhow!(e.to_string()))?.insert(key.to_vec(), value.to_vec());
        }
        Ok(())

    }
}

#[async_trait]
impl QTempDatabaseRawKVEnumeratorBase for SimpleMemoryTempStore {
    async fn qtdb_raw_kv_scan_fields(&self, cursor: u64, count: u32) -> anyhow::Result<TempKvScanPage> {
        // Sorted kv_map keys with a synthetic index cursor; nothing is invented.
        let mut keys: Vec<Vec<u8>> = self
            .kv_map
            .read()
            .map_err(|e| anyhow::anyhow!(e.to_string()))?
            .keys()
            .cloned()
            .collect();
        keys.sort();
        let total = keys.len();
        let start = (cursor as usize).min(total);
        let page = (count as usize).max(1);
        let end = (start + page).min(total);
        let fields = keys[start..end].to_vec();
        let next_cursor = if end >= total { 0 } else { end as u64 };
        Ok(TempKvScanPage { next_cursor, fields })
    }
}

impl QAutoImplementGeneric for SimpleMemoryTempStore {}


#[cfg(test)]
mod tests {
    use parth_core::data::{db::temp_db::{QPDFixedSizeSerializableTempTableInnerAutoKey, QSTempTableDefintionRealm}, fixed_serializable::QPDFixedSizeSerializable};

    use crate::{memory_stores::simple_memory_temp_store::SimpleMemoryTempStore, store::traits::temp_db::{QTempDatabaseCounterReaderBase, QTempDatabaseCounterWriterBase}};

    #[derive(Debug, Clone, PartialEq, Eq, Hash, Copy, PartialOrd, Ord)]
    struct TableDefAInnerKey {
        pub a: u64,
        pub b: u32,
    }
    impl QPDFixedSizeSerializable<12> for TableDefAInnerKey {
        fn to_fixed_size_bytes(&self) -> [u8; 12] {
            let mut buffer = [0u8; 12];
            buffer[0..8].copy_from_slice(&self.a.to_le_bytes());
            buffer[8..12].copy_from_slice(&self.b.to_le_bytes());
            buffer
        }
    
        fn from_fixed_size_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
            if bytes.len() != 12 {
                anyhow::bail!("invalid size, expected 12 bytes, got {}", bytes.len());
            }
            let mut arr8 = [0u8; 8];
            arr8.copy_from_slice(&bytes[0..8]);
            let a = u64::from_le_bytes(arr8);
            let mut arr4 = [0u8; 4];
            arr4.copy_from_slice(&bytes[8..12]);
            let b = u32::from_le_bytes(arr4);
            Ok(Self { a, b })
        }
    }
    
    impl QPDFixedSizeSerializableTempTableInnerAutoKey<12> for TableDefAInnerKey {}
    
    type SimpleCounterTableDef = QSTempTableDefintionRealm<123, 20, 12, TableDefAInnerKey, u64>;

    #[tokio::test]
    async fn test_counter() {
        let store = SimpleMemoryTempStore::new();
        let counter_table: SimpleCounterTableDef = QSTempTableDefintionRealm::new(1,2);
        assert_eq!(0, store.get_temp_database_counter(&counter_table, &TableDefAInnerKey { a: 1, b: 2 }).await.unwrap());
        store.increment_temp_database_counter(&counter_table, &TableDefAInnerKey { a: 1, b: 2 }, 5).await.unwrap();
        assert_eq!(5, store.get_temp_database_counter(&counter_table, &TableDefAInnerKey { a: 1, b: 2 }).await.unwrap());
        store.increment_temp_database_counter(&counter_table, &TableDefAInnerKey { a: 1, b: 2 }, 3).await.unwrap();
        assert_eq!(8, store.get_temp_database_counter(&counter_table, &TableDefAInnerKey { a: 1, b: 2 }).await.unwrap());
        store.set_temp_database_counter(&counter_table, &TableDefAInnerKey { a: 1, b: 2 }, 42).await.unwrap();
        assert_eq!(42, store.get_temp_database_counter(&counter_table, &TableDefAInnerKey { a: 1, b: 2 }).await.unwrap());
    }

    #[tokio::test]
    async fn test_proof_bucket_presence_empty_missing_false() {
        use crate::store::traits::proof_store::{
            QParthProofBucketPresenceReader, QParthProofStoreWriter,
        };
        use parth_core::utils::QPGenRandom;
        use psy_core::job::job_id::QProvingJobDataID;

        let store = SimpleMemoryTempStore::new();
        let pending_id = 42u64;

        assert!(!store.contains_proofs_for_pending_id(pending_id).await.unwrap());

        let job_id = QProvingJobDataID::qp_rand_gen();
        store
            .put_proof_bytes_for_job_id(job_id, pending_id, b"proof")
            .await
            .unwrap();
        assert!(store.contains_proofs_for_pending_id(pending_id).await.unwrap());

        store.delete_all_proofs_for_pending_id(pending_id).await.unwrap();
        assert!(!store.contains_proofs_for_pending_id(pending_id).await.unwrap());

        assert!(!store.contains_proofs_for_pending_id(pending_id + 1).await.unwrap());
    }


} 
