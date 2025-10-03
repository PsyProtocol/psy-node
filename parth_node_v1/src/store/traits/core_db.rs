use async_trait::async_trait;
use parth_common_v0::data::serializable::{QPDPair, QPDSerializable, QPDSerializableFixed};

#[async_trait]
pub trait CheckpointedBlobReader {
    async fn get_checkpoint_blob_latest(&self, key: &[u8]) -> anyhow::Result<Vec<u8>>;
    async fn get_checkpoint_blob_max_checkpoint(&self, key: &[u8], max_checkpoint_id: u64) -> anyhow::Result<Vec<u8>>;
    async fn get_checkpoint_blob_exact(&self, key: &[u8], checkpoint_id: u64) -> anyhow::Result<Vec<u8>>;
    async fn get_many_checkpoint_blob_latest(&self, keys: &[Vec<u8>]) -> anyhow::Result<Vec<Vec<u8>>>;
    async fn get_many_checkpoint_blob_max_checkpoint(&self, keys: &[Vec<u8>], max_checkpoint_id: u64) -> anyhow::Result<Vec<Vec<u8>>>;
    async fn get_many_checkpoint_blob_exact(&self, keys: &[Vec<u8>], checkpoint_id: u64) -> anyhow::Result<Vec<Vec<u8>>>;

    async fn get_checkpoint_blob_latest_object_key_bytes<K: QPDSerializableFixed + Sync>(&self, key: &K) -> anyhow::Result<Vec<u8>> {
        self.get_checkpoint_blob_latest(&key.to_bytes()?).await
    }
    async fn get_checkpoint_blob_max_checkpoint_object_key_bytes<K: QPDSerializableFixed + Sync>(&self, key: &K, max_checkpoint_id: u64) -> anyhow::Result<Vec<u8>> {
        self.get_checkpoint_blob_max_checkpoint(&key.to_bytes()?, max_checkpoint_id).await
    }
    async fn get_checkpoint_blob_exact_object_key_bytes<K: QPDSerializableFixed + Sync>(&self, key: &K, checkpoint_id: u64) -> anyhow::Result<Vec<u8>> {
        self.get_checkpoint_blob_exact(&key.to_bytes()?, checkpoint_id).await
    }
    async fn get_many_checkpoint_blob_latest_object_key_bytes<K: QPDSerializableFixed + Sync>(&self, keys: &[K]) -> anyhow::Result<Vec<Vec<u8>>> {
        let key_bytes: Vec<Vec<u8>> = keys.iter().map(|k| k.to_bytes()).collect::<Result<_, _>>()?;
        self.get_many_checkpoint_blob_latest(&key_bytes).await
    }
    async fn get_many_checkpoint_blob_max_checkpoint_object_key_bytes<K: QPDSerializableFixed + Sync>(&self, keys: &[K], max_checkpoint_id: u64) -> anyhow::Result<Vec<Vec<u8>>> {
        let key_bytes: Vec<Vec<u8>> = keys.iter().map(|k| k.to_bytes()).collect::<Result<_, _>>()?;
        self.get_many_checkpoint_blob_max_checkpoint(&key_bytes, max_checkpoint_id).await
    }
    async fn get_many_checkpoint_blob_exact_object_key_bytes<K: QPDSerializableFixed + Sync>(&self, keys: &[K], checkpoint_id: u64) -> anyhow::Result<Vec<Vec<u8>>> {
        let key_bytes: Vec<Vec<u8>> = keys.iter().map(|k| k.to_bytes()).collect::<Result<_, _>>()?;
        self.get_many_checkpoint_blob_exact(&key_bytes, checkpoint_id).await
    }
}


#[async_trait]
pub trait CheckpointedBlobWriter {
    async fn set_checkpoint_blob(&self, key: &[u8], checkpoint_id: u64, value: &[u8]) -> anyhow::Result<()>;
    async fn set_many_checkpoint_blob(&self, checkpoint_id: u64, entries: &[QPDPair<Vec<u8>, Vec<u8>>]) -> anyhow::Result<()>;
    async fn set_many_checkpoint_blob_object<K: QPDSerializableFixed + Sync, V: QPDSerializable>(&self, entries: &[QPDPair<K, V>]) -> anyhow::Result<()>;


    async fn set_checkpoint_blob_object_key_bytes<K: QPDSerializableFixed + Sync>(&self, key: &K, checkpoint_id: u64, value: &[u8]) -> anyhow::Result<()> {
        self.set_checkpoint_blob(&key.to_bytes()?, checkpoint_id, value).await
    }
}


pub trait CheckpointedBlobStore: CheckpointedBlobReader + CheckpointedBlobWriter {}

impl<T: CheckpointedBlobReader + CheckpointedBlobWriter> CheckpointedBlobStore for T {}