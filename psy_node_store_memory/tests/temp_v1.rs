use std::sync::Arc;

use async_trait::async_trait;
use psy_node_core::
    test_helpers::basic_1::{run_all_tests_for_factory, StoreFactory}
;
use psy_node_store_memory::temp_store::InMemoryTempStore;


// --- InMemoryStore Factory ---
pub struct InMemoryStoreFactory;
#[async_trait]
impl StoreFactory for InMemoryStoreFactory {
    type Store = InMemoryTempStore;
    async fn new_store(&self) -> Self::Store {
        InMemoryTempStore::new("test".to_string(), 1, 1)
    }
    fn name(&self) -> &'static str {
        "InMemoryStore"
    }
}
#[tokio::test]
pub async fn test_in_memory_store_implementation() {
    let factory = Arc::new(InMemoryStoreFactory);
    run_all_tests_for_factory(factory).await;
}
