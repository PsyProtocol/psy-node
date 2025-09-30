use async_trait::async_trait;

use crate::{data::serializable::{QPDPair, QPDSerializable}, store::{basic_kv_store::{BasicAsyncKVStoreReader, BasicAsyncKVStoreWriter}, temporary_store::{QPTemporaryStoreReader, QPTemporaryStoreWriter}}};


pub fn unwrap_kv_vec_result<T>(results: Vec<Option<T>>) -> anyhow::Result<Vec<T>> {
    let mut result: Vec<T> = Vec::with_capacity(results.len());

    for item_opt in results {
        if let Some(item) = item_opt {
            result.push(item);
        } else {
            return Err(anyhow::anyhow!("Missing value in unwrapped Vec result!"));
        }
    }
    Ok(result)
}
pub fn unwrap_kv_result<T>(item_opt: Option<T>) -> anyhow::Result<T> {
    if let Some(item) = item_opt {
        Ok(item)
    } else {
        return Err(anyhow::anyhow!("Missing value in unwrapped Vec result!"));
    }
}

pub trait QPDStoreAdapterReader<S, K: QPDSerializable, V: QPDSerializable> {
    fn get_exact_if_exists(s: &S, key: &K) -> anyhow::Result<Option<V>>;
    fn get_exact(s: &S, key: &K) -> anyhow::Result<V>;
    fn get_many_exact(s: &S, keys: &[K]) -> anyhow::Result<Vec<V>>;

    fn get_fuzzy_range_leq_kv(s: &S, key: &K, fuzzy_bytes: usize) -> anyhow::Result<Vec<QPDPair<K, V>>>;
    fn get_leq(s: &S, key: &K, fuzzy_bytes: usize) -> anyhow::Result<Option<V>>;
    fn get_leq_kv(s: &S, key: &K, fuzzy_bytes: usize) -> anyhow::Result<Option<QPDPair<K, V>>>;

    fn get_many_leq(s: &S, keys: &[K], fuzzy_bytes: usize) -> anyhow::Result<Vec<Option<V>>>;
    fn get_many_leq_kv(
        s: &S,
        keys: &[K],
        fuzzy_bytes: usize,
    ) -> anyhow::Result<Vec<Option<QPDPair<K, V>>>>;

    fn get_many_leq_u(s: &S, keys: &[K], fuzzy_bytes: usize) -> anyhow::Result<Vec<V>> {
        let results = Self::get_many_leq(s, keys, fuzzy_bytes)?;
        unwrap_kv_vec_result(results)
    }
    fn get_many_leq_kv_u(
        s: &S,
        keys: &[K],
        fuzzy_bytes: usize,
    ) -> anyhow::Result<Vec<QPDPair<K, V>>> {
        let results = Self::get_many_leq_kv(s, keys, fuzzy_bytes)?;
        unwrap_kv_vec_result(results)
    }
}

#[async_trait]
pub trait QPDStoreAdapterReaderAsync<S: Sync, K: QPDSerializable + Sync, V: QPDSerializable> {
    async fn get_exact_if_exists(s: &S, key: &K) -> anyhow::Result<Option<V>>;
    async fn get_exact(s: &S, key: &K) -> anyhow::Result<V>;
    async fn get_many_exact(s: &S, keys: &[K]) -> anyhow::Result<Vec<V>>;

    async fn get_fuzzy_range_leq_kv(s: &S, key: &K, fuzzy_bytes: usize) -> anyhow::Result<Vec<QPDPair<K, V>>>;
    async fn get_leq(s: &S, key: &K, fuzzy_bytes: usize) -> anyhow::Result<Option<V>>;
    async fn get_leq_kv(s: &S, key: &K, fuzzy_bytes: usize) -> anyhow::Result<Option<QPDPair<K, V>>>;

    async fn get_many_leq(s: &S, keys: &[K], fuzzy_bytes: usize) -> anyhow::Result<Vec<Option<V>>>;
    async fn get_many_leq_kv(
        s: &S,
        keys: &[K],
        fuzzy_bytes: usize,
    ) -> anyhow::Result<Vec<Option<QPDPair<K, V>>>>;

    async fn get_many_leq_u(s: &S, keys: &[K], fuzzy_bytes: usize) -> anyhow::Result<Vec<V>> {
        let results = Self::get_many_leq(s, keys, fuzzy_bytes).await?;
        unwrap_kv_vec_result(results)
    }
    async fn get_many_leq_kv_u(
        s: &S,
        keys: &[K],
        fuzzy_bytes: usize,
    ) -> anyhow::Result<Vec<QPDPair<K, V>>> {
        let results = Self::get_many_leq_kv(s, keys, fuzzy_bytes).await?;
        unwrap_kv_vec_result(results)
    }
}

#[async_trait]
pub trait QPDStoreAdapterAsync<S: Sync, K: QPDSerializable + Sync, V: QPDSerializable + Sync>:
    QPDStoreAdapterReaderAsync<S, K, V>
{
    async fn set(s: &S, key: K, value: V) -> anyhow::Result<()>;
    async fn set_ref(s: &S, key: &K, value: &V) -> anyhow::Result<()>;
    async fn set_many_ref<'a>(s: &S, items: &[QPDPair<&'a K, &'a V>]) -> anyhow::Result<()> where K: 'a, V: 'a;
    async fn set_many_split_ref(s: &S, keys: &[K], values: &[V]) -> anyhow::Result<()>;
    async fn set_many(s: &S, items: &[QPDPair<K, V>]) -> anyhow::Result<()>;

    async fn delete(s: &S, key: &K) -> anyhow::Result<bool>;
    async fn delete_many(s: &S, keys: &[K]) -> anyhow::Result<Vec<bool>>;
}

pub trait QPDStoreAdapter<S, K: QPDSerializable, V: QPDSerializable>:
    QPDStoreAdapterReader<S, K, V>
{
    fn set(s: &S, key: K, value: V) -> anyhow::Result<()>;
    fn set_ref(s: &S, key: &K, value: &V) -> anyhow::Result<()>;
    fn set_many_ref<'a>(s: &S, items: &[QPDPair<&'a K, &'a V>]) -> anyhow::Result<()>;
    fn set_many_split_ref(s: &S, keys: &[K], values: &[V]) -> anyhow::Result<()>;
    fn set_many(s: &S, items: &[QPDPair<K, V>]) -> anyhow::Result<()>;

    fn delete(s: &S, key: &K) -> anyhow::Result<bool>;
    fn delete_many(s: &S, keys: &[K]) -> anyhow::Result<Vec<bool>>;
    //fn delete_many_sized<const SIZE: usize>(s: &S, keys: &[K; SIZE]) ->
    // anyhow::Result<[bool; SIZE]>;
}

pub trait QPDStoreAdapterWithHelpers<S, K: QPDSerializable, V: QPDSerializable>:
    QPDStoreAdapter<S, K, V>
{
    fn set_many_ref_clone_batch<'a>(
        s: &mut S,
        items: &[QPDPair<&'a K, &'a V>],
    ) -> anyhow::Result<()> {
        let mut items_owned = Vec::with_capacity(items.len());
        for item in items {
            items_owned.push(QPDPair {
                key: item.key.clone(),
                value: item.value.clone(),
            });
        }
        Self::set_many(s, &items_owned)
    }
    fn set_many_ref_serial<'a>(s: &mut S, items: &[QPDPair<&'a K, &'a V>]) -> anyhow::Result<()> {
        for item in items {
            Self::set(s, item.key.clone(), item.value.clone())?;
        }
        Ok(())
    }
}


pub trait QPDBinaryStoreReader: Send + Sync {
    // Read operations
    fn get_exact_if_exists(&self, key: &Vec<u8>) -> anyhow::Result<Option<Vec<u8>>>;
    fn get_exact(&self, key: &Vec<u8>) -> anyhow::Result<Vec<u8>>;
    fn get_many_exact(&self, keys: &[Vec<u8>]) -> anyhow::Result<Vec<Vec<u8>>>;

    fn get_leq(&self, key: &Vec<u8>, fuzzy_bytes: usize) -> anyhow::Result<Option<Vec<u8>>>;
    fn get_fuzzy_range_leq_kv(&self, key: &Vec<u8>, fuzzy_bytes: usize) -> anyhow::Result<Vec<QPDPair<Vec<u8>, Vec<u8>>>>;
    fn get_leq_kv(
        &self,
        key: &Vec<u8>,
        fuzzy_bytes: usize,
    ) -> anyhow::Result<Option<QPDPair<Vec<u8>, Vec<u8>>>>;

    fn get_many_leq(
        &self,
        keys: &[Vec<u8>],
        fuzzy_bytes: usize,
    ) -> anyhow::Result<Vec<Option<Vec<u8>>>>;
    fn get_many_leq_kv(
        &self,
        keys: &[Vec<u8>],
        fuzzy_bytes: usize,
    ) -> anyhow::Result<Vec<Option<QPDPair<Vec<u8>, Vec<u8>>>>>;

    fn get_leq_u(&self, key: &Vec<u8>, fuzzy_bytes: usize) -> anyhow::Result<Vec<u8>> {
        unwrap_kv_result(self.get_leq(key, fuzzy_bytes)?)
    }
    fn get_leq_kv_u(
        &self,
        key: &Vec<u8>,
        fuzzy_bytes: usize,
    ) -> anyhow::Result<QPDPair<Vec<u8>, Vec<u8>>> {
        unwrap_kv_result(self.get_leq_kv(key, fuzzy_bytes)?)
    }

    fn get_many_leq_u(&self, keys: &[Vec<u8>], fuzzy_bytes: usize) -> anyhow::Result<Vec<Vec<u8>>> {
        unwrap_kv_vec_result(self.get_many_leq(keys, fuzzy_bytes)?)
    }
    fn get_many_leq_kv_u(
        &self,
        keys: &[Vec<u8>],
        fuzzy_bytes: usize,
    ) -> anyhow::Result<Vec<QPDPair<Vec<u8>, Vec<u8>>>> {
        unwrap_kv_vec_result(self.get_many_leq_kv(keys, fuzzy_bytes)?)
    }
}

//pub type QPDStoreAdapter<K: QPDSerializable, V: QPDSerializable> =
// QPDStoreAdapter<QPDBinaryStore, K, V>;
pub trait QPDBinaryStoreWriter: Send + Sync + QPDBinaryStoreReader {

    // Write operations
    fn set(&self, key: Vec<u8>, value: Vec<u8>) -> anyhow::Result<()>;
    fn set_ref(&self, key: &Vec<u8>, value: &Vec<u8>) -> anyhow::Result<()>;
    fn set_many_ref<'a>(
        &self,
        items: &[QPDPair<&'a Vec<u8>, &'a Vec<u8>>],
    ) -> anyhow::Result<()>;
    fn set_many_vec(&self, items: Vec<QPDPair<Vec<u8>, Vec<u8>>>) -> anyhow::Result<()>;
    fn set_many_split_ref(&self, keys: &[Vec<u8>], values: &[Vec<u8>]) -> anyhow::Result<()>;

    fn delete(&self, key: &Vec<u8>) -> anyhow::Result<bool>;
    fn delete_many(&self, keys: &[Vec<u8>]) -> anyhow::Result<Vec<bool>>;

    fn set_and_delete_many(
        &self,
        keys_to_set: &[QPDPair<&Vec<u8>, &Vec<u8>>],
        keys_to_delete: &[Vec<u8>]
    ) -> anyhow::Result<()> {
        self.set_many_ref(keys_to_set)?;
        self.delete_many(keys_to_delete)?;
        Ok(())
    }

}
pub trait QPDBinaryStore: Send + Sync + QPDBinaryStoreReader + QPDBinaryStoreWriter {
}

impl<S: QPDBinaryStoreReader + QPDBinaryStoreWriter> QPDBinaryStore for S
{
}

#[async_trait]
pub trait QPDBinaryStoreReaderAsync {
    // Read operations
    async fn get_exact_if_exists_async(&self, key: &Vec<u8>) -> anyhow::Result<Option<Vec<u8>>>;
    async fn get_exact_async(&self, key: &Vec<u8>) -> anyhow::Result<Vec<u8>>;
    async fn get_many_exact_async(&self, keys: &[Vec<u8>]) -> anyhow::Result<Vec<Vec<u8>>>;

    async fn get_leq_async(&self, key: &Vec<u8>, fuzzy_bytes: usize) -> anyhow::Result<Option<Vec<u8>>>;
    async fn get_fuzzy_range_leq_kv_async(&self, key: &Vec<u8>, fuzzy_bytes: usize) -> anyhow::Result<Vec<QPDPair<Vec<u8>, Vec<u8>>>>;
    async fn get_leq_kv_async(
        &self,
        key: &Vec<u8>,
        fuzzy_bytes: usize,
    ) -> anyhow::Result<Option<QPDPair<Vec<u8>, Vec<u8>>>>;

    async fn get_many_leq_async(
        &self,
        keys: &[Vec<u8>],
        fuzzy_bytes: usize,
    ) -> anyhow::Result<Vec<Option<Vec<u8>>>>;
    async fn get_many_leq_kv_async(
        &self,
        keys: &[Vec<u8>],
        fuzzy_bytes: usize,
    ) -> anyhow::Result<Vec<Option<QPDPair<Vec<u8>, Vec<u8>>>>>;

    async fn get_leq_u_async(&self, key: &Vec<u8>, fuzzy_bytes: usize) -> anyhow::Result<Vec<u8>> {
        unwrap_kv_result(self.get_leq_async(key, fuzzy_bytes).await?)
    }
    async fn get_leq_kv_u_async(
        &self,
        key: &Vec<u8>,
        fuzzy_bytes: usize,
    ) -> anyhow::Result<QPDPair<Vec<u8>, Vec<u8>>> {
        unwrap_kv_result(self.get_leq_kv_async(key, fuzzy_bytes).await?)
    }

    async fn get_many_leq_u_async(&self, keys: &[Vec<u8>], fuzzy_bytes: usize) -> anyhow::Result<Vec<Vec<u8>>> {
        unwrap_kv_vec_result(self.get_many_leq_async(keys, fuzzy_bytes).await?)
    }
    async fn get_many_leq_kv_u_async(
        &self,
        keys: &[Vec<u8>],
        fuzzy_bytes: usize,
    ) -> anyhow::Result<Vec<QPDPair<Vec<u8>, Vec<u8>>>> {
        unwrap_kv_vec_result(self.get_many_leq_kv_async(keys, fuzzy_bytes).await?)
    }
}

#[async_trait]
pub trait QPDBinaryStoreWriterAsync {

    // Write operations
    async fn set_async(&self, key: Vec<u8>, value: Vec<u8>) -> anyhow::Result<()>;
    async fn set_ref_async(&self, key: &Vec<u8>, value: &Vec<u8>) -> anyhow::Result<()>;
    async fn set_many_ref_async<'a>(
        &self,
        items: &[QPDPair<&'a Vec<u8>, &'a Vec<u8>>],
    ) -> anyhow::Result<()>;
    async fn set_many_vec_async(&self, items: Vec<QPDPair<Vec<u8>, Vec<u8>>>) -> anyhow::Result<()>;
    async fn set_many_split_ref_async(&self, keys: &[Vec<u8>], values: &[Vec<u8>]) -> anyhow::Result<()>;

    async fn delete_async(&self, key: &Vec<u8>) -> anyhow::Result<bool>;
    async fn delete_many_async(&self, keys: &[Vec<u8>]) -> anyhow::Result<Vec<bool>>;

    async fn set_and_delete_many_async(
        &self,
        keys_to_set: &[QPDPair<&Vec<u8>, &Vec<u8>>],
        keys_to_delete: &[Vec<u8>]
    ) -> anyhow::Result<()> {
        self.set_many_ref_async(keys_to_set).await?;
        self.delete_many_async(keys_to_delete).await?;
        Ok(())
    }
}


pub trait QPDBinaryStoreAsync: QPDBinaryStoreReaderAsync + QPDBinaryStoreWriterAsync {
}

impl<S: QPDBinaryStoreReaderAsync + QPDBinaryStoreWriterAsync> QPDBinaryStoreAsync for S
{
}


pub trait QPDBinaryStoreReaderWithAutoAsync: QPDBinaryStoreReader
{
}
pub trait QPDBinaryStoreWriterWithAutoAsync: QPDBinaryStoreWriter
{
}

pub trait QPDBinaryStoreWithAutoAsync: QPDBinaryStoreReaderWithAutoAsync + QPDBinaryStoreWriterWithAutoAsync
{
}
#[async_trait]
impl<SyncStore: QPDBinaryStoreWithAutoAsync> QPDBinaryStoreReaderAsync for SyncStore
{
    // Read operations
    async fn get_exact_if_exists_async(&self, key: &Vec<u8>) -> anyhow::Result<Option<Vec<u8>>> {
        self.get_exact_if_exists(key)
    }
    async fn get_exact_async(&self, key: &Vec<u8>) -> anyhow::Result<Vec<u8>> {
        self.get_exact(key)
    }
    async fn get_many_exact_async(&self, keys: &[Vec<u8>]) -> anyhow::Result<Vec<Vec<u8>>> {
        self.get_many_exact(keys)
    }

    async fn get_leq_async(&self, key: &Vec<u8>, fuzzy_bytes: usize) -> anyhow::Result<Option<Vec<u8>>> {
        self.get_leq(key, fuzzy_bytes)
    }
    async fn get_fuzzy_range_leq_kv_async(&self, key: &Vec<u8>, fuzzy_bytes: usize) -> anyhow::Result<Vec<QPDPair<Vec<u8>, Vec<u8>>>> {
        self.get_fuzzy_range_leq_kv(key, fuzzy_bytes)
    }
    async fn get_leq_kv_async(
        &self,
        key: &Vec<u8>,
        fuzzy_bytes: usize,
    ) -> anyhow::Result<Option<QPDPair<Vec<u8>, Vec<u8>>>> {
        self.get_leq_kv(key, fuzzy_bytes)
    }

    async fn get_many_leq_async(
        &self,
        keys: &[Vec<u8>],
        fuzzy_bytes: usize,
    ) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
        self.get_many_leq(keys, fuzzy_bytes)
    }
    async fn get_many_leq_kv_async(
        &self,
        keys: &[Vec<u8>],
        fuzzy_bytes: usize,
    ) -> anyhow::Result<Vec<Option<QPDPair<Vec<u8>, Vec<u8>>>>> {
        self.get_many_leq_kv(keys, fuzzy_bytes)
    }
}

#[async_trait]
impl<SyncStore: QPDBinaryStoreWithAutoAsync> QPDBinaryStoreWriterAsync for SyncStore
{

    // Write operations
    async fn set_async(&self, key: Vec<u8>, value: Vec<u8>) -> anyhow::Result<()> {
        self.set(key, value)
    }
    async fn set_ref_async(&self, key: &Vec<u8>, value: &Vec<u8>) -> anyhow::Result<()> {
        self.set_ref(key, value)
    }
    async fn set_many_ref_async<'a>(
        &self,
        items: &[QPDPair<&'a Vec<u8>, &'a Vec<u8>>],
    ) -> anyhow::Result<()> {
        self.set_many_ref(items)
    }
    
    async fn set_many_vec_async(&self, items: Vec<QPDPair<Vec<u8>, Vec<u8>>>) -> anyhow::Result<()> {
        self.set_many_vec(items)
    }
    
    async fn set_many_split_ref_async(&self, keys: &[Vec<u8>], values: &[Vec<u8>]) -> anyhow::Result<()> {
        self.set_many_split_ref(keys, values)
    }
    
    async fn delete_async(&self, key: &Vec<u8>) -> anyhow::Result<bool> {
        self.delete(key)
    }
    
    async fn delete_many_async(&self, keys: &[Vec<u8>]) -> anyhow::Result<Vec<bool>> {
        self.delete_many(keys)
    }
}

#[async_trait]
impl<T: QPDBinaryStoreReaderAsync + Sync> BasicAsyncKVStoreReader for T {
    async fn bkv_contains_key(&self, key: &[u8]) -> anyhow::Result<bool>{
        Ok(self.bkv_get_or_none(key).await?.is_some())
    }
    async fn bkv_get_or_none(&self, key: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        self.get_exact_if_exists_async(&key.to_vec()).await
    }
    async fn bkv_get(&self, key: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.get_exact_async(&key.to_vec()).await
    }
    async fn bkv_get_many_or_none(&self, keys: &[Vec<u8>]) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
        self.get_many_exact_async(keys).await
            .map(|vals| {
                vals.into_iter().map(Some).collect()
            })
    }
    async fn bkv_get_many(&self, keys: &[Vec<u8>]) -> anyhow::Result<Vec<Vec<u8>>> {
        self.get_many_exact_async(keys).await
    }
}

#[async_trait]
impl<T: QPDBinaryStoreWriterAsync + Sync> BasicAsyncKVStoreWriter for T {
    async fn bkv_set(&self, key: Vec<u8>, value: Vec<u8>) -> anyhow::Result<()> {
        self.set_async(key, value).await
    }
    async fn bkv_set_ref(&self, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
        self.set_async(key.to_vec(), value.to_vec()).await
    }
    async fn bkv_set_many_pairs(&self, items: Vec<(Vec<u8>, Vec<u8>)>) -> anyhow::Result<()> {
        let qpd_items: Vec<QPDPair<Vec<u8>, Vec<u8>>> = items.into_iter()
            .map(|(k, v)| QPDPair { key: k, value: v })
            .collect();
        self.set_many_vec_async(qpd_items).await
    }
    async fn bkv_set_many_pairs_ref(&self, items: &[(Vec<u8>, Vec<u8>)]) -> anyhow::Result<()> {
        let qpd_items: Vec<QPDPair<&Vec<u8>, &Vec<u8>>> = items.iter()
            .map(|(k, v)| QPDPair { key: k, value: v })
            .collect();
        self.set_many_ref_async(&qpd_items).await
    }
}

#[async_trait]
impl<T: QPDBinaryStoreReaderAsync + Sync> QPTemporaryStoreReader for T {
    async fn contains_key(&self, key: &[u8]) -> anyhow::Result<bool> {
        let k = key.to_vec();
        Ok(self.get_exact_if_exists_async(&k).await?.is_some())
    }
    async fn get_bytes(&self, key: &[u8]) -> anyhow::Result<Vec<u8>> {
        let k = key.to_vec();
        self.get_exact_async(&k).await  
    }
    async fn get_bytes_batch(&self, keys: &[Vec<u8>]) -> anyhow::Result<Vec<Vec<u8>>> {
        let k = keys.to_vec();
        self.get_many_exact_async(&k).await
    }
    async fn get_counter_by_key(&self, key: &[u8]) -> anyhow::Result<u64> {
        let k = key.to_vec();
        self.get_exact_async(&k).await
            .and_then(|v| {
                if v.len() != 8 {
                    return Err(anyhow::anyhow!("Invalid counter length"));
                }
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&v);
                Ok(u64::from_le_bytes(arr))
            })
    }
}

#[async_trait]
impl<T: QPDBinaryStoreWriterAsync + Sync + QPDBinaryStoreReaderAsync + QPTemporaryStoreReader> QPTemporaryStoreWriter for T {
    async fn delete_key(&self, key: &[u8]) -> anyhow::Result<()>{
        let k = key.to_vec();
        self.delete_async(&k).await?;
        Ok(())
    }
    async fn set_bytes(&self, key: Vec<u8>, value: Vec<u8>) -> anyhow::Result<()>{
        self.set_async(key, value).await?;
        Ok(())
    }
    async fn set_bytes_ref(&self, key: &[u8], value: &[u8]) -> anyhow::Result<()>{
        self.set_async(key.to_vec(), value.to_vec()).await?;
        Ok(())
    }
    async fn set_bytes_batch(&self, items: Vec<QPDPair<Vec<u8>, Vec<u8>>>) -> anyhow::Result<()>{
        self.set_many_vec_async(items).await?;
        Ok(())
    }
    async fn set_counter_by_key(&self, key: &[u8], value: u64) -> anyhow::Result<()>{
        let k = key.to_vec();
        self.set_async(k, value.to_le_bytes().to_vec()).await?;
        Ok(())
    }
    async fn inc_counter_by_key(&self, key: &[u8]) -> anyhow::Result<u64>{
        // use this for testing ONLY, beware of race conditions!!!
        let k = key.to_vec();
        if self.contains_key(&k).await? == false {
            self.set_counter_by_key(&k, 1).await?;
            Ok(1)
        }else{
            let current = self.get_counter_by_key(&k).await?;
            self.set_counter_by_key(&k, current + 1).await?;
            Ok(current + 1)
        }
    }
}