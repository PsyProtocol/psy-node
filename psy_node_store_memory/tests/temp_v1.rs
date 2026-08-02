use std::sync::Arc;

use async_trait::async_trait;
use parth_core::node::realm_identifier::QRealmIdentifier;
use psy_node_core::{
    psy_temp_db::QTempDBJobStatsStore,
    test_helpers::basic_1::{run_all_tests_for_factory, StoreFactory},
};
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

#[tokio::test]
pub async fn test_job_stats_are_aggregated_and_isolated_by_pending_id() {
    let store = InMemoryTempStore::new("job-stats-test".to_string(), 1, 1);
    let realm = QRealmIdentifier::new(1, 2);

    assert!(store.get_job_stats(&realm, 42).await.unwrap().is_none());

    store.increment_job_stats(&realm, 42, 200).await.unwrap();
    store.increment_job_stats(&realm, 42, 100).await.unwrap();
    store.increment_job_stats(&realm, 42, 350).await.unwrap();

    let stats = store.get_job_stats(&realm, 42).await.unwrap().unwrap();
    assert_eq!(stats.total_completed, 3);
    assert_eq!(stats.total_duration_ms, 650);
    assert_eq!(stats.min_duration_ms, Some(100));
    assert_eq!(stats.max_duration_ms, Some(350));
    assert!(store.get_job_stats(&realm, 43).await.unwrap().is_none());

    store.clear_job_stats(&realm, 42).await.unwrap();
    assert!(store.get_job_stats(&realm, 42).await.unwrap().is_none());
}
