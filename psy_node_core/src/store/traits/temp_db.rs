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
