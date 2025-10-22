use std::sync::Arc;

use async_trait::async_trait;
use psy_node_core::test_helpers::basic_1::{run_all_tests_for_factory, StoreFactory};
use psy_node_redis::store::{new_redis_async_pool, StandardRedisStore};
use rand::{distributions::Alphanumeric, Rng};

// --- StandardRedisStore Factory ---
pub struct RedisStoreFactory {
    redis_url: String,
}
impl RedisStoreFactory {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            redis_url: std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".into()),
        })
    }
}
#[async_trait]
impl StoreFactory for RedisStoreFactory {
    type Store = StandardRedisStore;
    async fn new_store(&self) -> Self::Store {
        let pool = new_redis_async_pool(&self.redis_url, 10).await.unwrap();
        let rng = rand::thread_rng();
        // Use a random prefix and IDs to ensure test isolation
        let prefix: String = rng.sample_iter(&Alphanumeric).take(8).map(char::from).collect();
        let mut rng = rand::thread_rng();

        let realm_id: u64 = rng.gen();
        let realm_sub_id: u64 = rng.gen();

        StandardRedisStore::new(pool, prefix, realm_id, realm_sub_id)
    }
    fn name(&self) -> &'static str {
        "StandardRedisStore"
    }
}

#[tokio::test]
#[ignore = "Requires a running Redis instance at REDIS_URL"]
pub async fn test_redis_store_implementation() {
    let factory = Arc::new(RedisStoreFactory::new().unwrap());
    run_all_tests_for_factory(factory).await;
}
