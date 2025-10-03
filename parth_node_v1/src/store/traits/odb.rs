use parth_common_v0::data::serializable::{QPDPair, QPDSerializable, QPDSerializableFixed};


use async_trait::async_trait;



#[async_trait]
pub trait QPBasicStoreKVReader {
    async fn get_exact_bytes(&self, namespace: u64, realm_id: u64, table_type: u32, key: &[u8]) -> anyhow::Result<Vec<u8>>;
    async fn get_exact_bytes_many(&self, namespace: u64, realm_id: u64, table_type: u32, keys: &[Vec<u8>]) -> anyhow::Result<Vec<Vec<u8>>>;

    async fn get_exact_object_key_bytes<K: QPDSerializableFixed + Sync>(&self, namespace: u64, realm_id: u64, table_type: u32, key: &K) -> anyhow::Result<Vec<u8>> {
        self.get_exact_bytes(namespace, realm_id, table_type, &key.to_bytes()?).await
    }
    async fn get_exact_object<K: QPDSerializableFixed + Sync, V: QPDSerializable>(&self, namespace: u64, realm_id: u64, table_type: u32, key: &K) -> anyhow::Result<V> {
        let key_bytes = self.get_exact_object_key_bytes(namespace, realm_id, table_type, key).await?;
        let value_bytes = self.get_exact_bytes(namespace, realm_id, table_type, &key_bytes).await?;
        let value = V::from_bytes(&value_bytes)?;
        Ok(value)
    }
    async fn get_exact_object_or_none<K: QPDSerializableFixed + Sync, V: QPDSerializable>(&self, namespace: u64, realm_id: u64, table_type: u32, key: &K) -> anyhow::Result<Option<V>> {
        let key_bytes = self.get_exact_object_key_bytes(namespace, realm_id, table_type, key).await?;
        let value_bytes = self.get_exact_bytes(namespace, realm_id, table_type, &key_bytes).await;
        match value_bytes {
            Ok(bytes) => {
                let value = V::from_bytes(&bytes)?;
                Ok(Some(value))
            },
            Err(_) => Ok(None),
        }
    }
    async fn get_exact_object_key_bytes_many<K: QPDSerializableFixed + Sync>(&self, namespace: u64, realm_id: u64, table_type: u32, keys: &[K]) -> anyhow::Result<Vec<Vec<u8>>> {
        let key_bytes: Vec<Vec<u8>> = keys.iter().map(|k| k.to_bytes()).collect::<Result<_, _>>()?;
        self.get_exact_bytes_many(namespace, realm_id, table_type, &key_bytes).await
    }
    async fn get_exact_object_many<K: QPDSerializableFixed + Sync, V: QPDSerializable>(&self, namespace: u64, realm_id: u64, table_type: u32, keys: &[K]) -> anyhow::Result<Vec<V>> {
        let key_bytes: Vec<Vec<u8>> = keys.iter().map(|k| k.to_bytes()).collect::<Result<_, _>>()?;
        let value_bytes = self.get_exact_bytes_many(namespace, realm_id, table_type, &key_bytes).await?;
        value_bytes.into_iter().map(|bytes| V::from_bytes(&bytes)).collect()
    }
}



#[async_trait]
pub trait QPBasicStoreKVWriter {
    async fn set_exact_bytes(&self, namespace: u64, realm_id: u64, table_type: u32, key: &[u8], value: &[u8]) -> anyhow::Result<()>;
    async fn set_exact_object_key_bytes<K: QPDSerializableFixed + Sync>(&self, namespace: u64, realm_id: u64, table_type: u32, key: &K, value: &[u8]) -> anyhow::Result<()> {
        self.set_exact_bytes(namespace, realm_id, table_type, &key.to_bytes()?, value).await
    }
    async fn set_exact_object<K: QPDSerializableFixed + Sync, V: QPDSerializable + Sync>(&self, namespace: u64, realm_id: u64, table_type: u32, key: &K, value: &V) -> anyhow::Result<()> {
        let key_bytes = key.to_bytes()?;
        let value_bytes = value.to_bytes()?;
        self.set_exact_bytes(namespace, realm_id, table_type, &key_bytes, &value_bytes).await
    }
    async fn set_exact_bytes_many(&self, namespace: u64, realm_id: u64, table_type: u32, entries: &[QPDPair<Vec<u8>, Vec<u8>>]) -> anyhow::Result<()>;
    async fn set_exact_object_key_bytes_many<K: QPDSerializableFixed + Sync>(&self, namespace: u64, realm_id: u64, table_type: u32, entries: &[QPDPair<K, Vec<u8>>]) -> anyhow::Result<()> {
        let key_bytes: Vec<QPDPair<Vec<u8>, Vec<u8>>> = entries.iter().map(|e| QPDPair { key: e.key.to_bytes().unwrap(), value: e.value.clone() }).collect();
        self.set_exact_bytes_many(namespace, realm_id, table_type, &key_bytes).await
    }
    async fn set_exact_object_many<K: QPDSerializableFixed + Sync, V: QPDSerializable + Sync>(&self, namespace: u64, realm_id: u64, table_type: u32, entries: &[QPDPair<K, V>]) -> anyhow::Result<()> {
        let key_bytes: Vec<QPDPair<Vec<u8>, Vec<u8>>> = entries.iter().map(|e| QPDPair { key: e.key.to_bytes().unwrap(), value: e.value.to_bytes().unwrap() }).collect();
        self.set_exact_bytes_many(namespace, realm_id, table_type, &key_bytes).await
    }
}


#[async_trait]
pub trait QPTempStoreKVU64Reader {
    async fn get_iu64_generic(&self, namespace: u64, realm_id: u64, table_type: u32, key: &[u8]) -> anyhow::Result<u64>;
    async fn get_iu64_object_key_bytes<K: QPDSerializableFixed + Sync>(&self, namespace: u64, realm_id: u64, table_type: u32, key: &K) -> anyhow::Result<u64> {
        self.get_iu64_generic(namespace, realm_id, table_type, &key.to_bytes()?).await
    }
    async fn get_iu64_object<K: QPDSerializableFixed + Sync>(&self, namespace: u64, realm_id: u64, table_type: u32, key: &K) -> anyhow::Result<u64> {
        self.get_iu64_generic(namespace, realm_id, table_type, &key.to_bytes()?).await
    }
}

#[async_trait]
pub trait QPTempStoreKVU64Writer {
    async fn set_iu64_generic(&self, namespace: u64, realm_id: u64, table_type: u32, key: &[u8], value: u64) -> anyhow::Result<()>;
    async fn inc_iu64_generic(&self, namespace: u64, realm_id: u64, table_type: u32, key: &[u8], delta: i64) -> anyhow::Result<u64>;
    async fn set_iu64_object_key_bytes<K: QPDSerializableFixed + Sync>(&self, namespace: u64, realm_id: u64, table_type: u32, key: &K, value: u64) -> anyhow::Result<()> {
        self.set_iu64_generic(namespace, realm_id, table_type, &key.to_bytes()?, value).await
    }
    async fn inc_iu64_object_key_bytes<K: QPDSerializableFixed + Sync>(&self, namespace: u64, realm_id: u64, table_type: u32, key: &K, delta: i64) -> anyhow::Result<u64> {
        self.inc_iu64_generic(namespace, realm_id, table_type, &key.to_bytes()?, delta).await
    }
}