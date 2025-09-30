use async_trait::async_trait;


#[async_trait]
pub trait BasicAsyncKVStoreReader {
    async fn bkv_contains_key(&self, key: &[u8]) -> anyhow::Result<bool>;
    async fn bkv_get_or_none(&self, key: &[u8]) -> anyhow::Result<Option<Vec<u8>>>;
    async fn bkv_get(&self, key: &[u8]) -> anyhow::Result<Vec<u8>>;
    async fn bkv_get_many_or_none(&self, keys: &[Vec<u8>]) -> anyhow::Result<Vec<Option<Vec<u8>>>>;
    async fn bkv_get_many(&self, keys: &[Vec<u8>]) -> anyhow::Result<Vec<Vec<u8>>>;
}

#[async_trait]
pub trait BasicAsyncKVStoreWriter {
    async fn bkv_set(&self, key: Vec<u8>, value: Vec<u8>) -> anyhow::Result<()>;
    async fn bkv_set_ref(&self, key: &[u8], value: &[u8]) -> anyhow::Result<()>;
    async fn bkv_set_many_pairs(&self, items: Vec<(Vec<u8>, Vec<u8>)>) -> anyhow::Result<()>;
    async fn bkv_set_many_pairs_ref(&self, items: &[(Vec<u8>, Vec<u8>)]) -> anyhow::Result<()>;
}

pub trait BasicAsyncKVStore: BasicAsyncKVStoreReader + BasicAsyncKVStoreWriter {}

impl<T: BasicAsyncKVStoreReader + BasicAsyncKVStoreWriter> BasicAsyncKVStore for T {}

