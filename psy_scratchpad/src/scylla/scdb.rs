use crate::scylla::traits::ScyllaSerializable;



pub struct QPDPair<K, V> {
    pub key: K,
    pub value: V,
}

pub struct ObjectWriterWithSingleI64Id<V: ScyllaSerializable> {
    // [START] any data we need to store in the struct such as prepared statements or similar
    // ...
    // [END] any data we need to store in the struct such as prepared statements or similar


    _phantom_value: std::marker::PhantomData<V: ScyllaSerializable>,
}

#[async_trait]
pub trait BasicKeyIdValueStore<V: ScyllaSerializable> {
    async fn get_value(&self, id: i64) -> anyhow::Result<Option<V>>;
    async fn set_value(&self, id: i64, value: &V) -> anyhow::Result<()>;
    async fn delete_value(&self, id: i64) -> anyhow::Result<()>;
}