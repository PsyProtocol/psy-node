use std::marker::PhantomData;

use crate::store::traits::core_db::{CoreDatabaseBidirectionalU64U128MappingStore, CoreDatabaseSingleIdCheckpointedStore};

pub struct BidirectionalU64U128TestHelper<TableIdentifier: Clone + Send + Sync,  S: CoreDatabaseBidirectionalU64U128MappingStore<TableIdentifier>> {
    pub store: PhantomData<S>,
    pub table: PhantomData<TableIdentifier>,
}




impl <TableIdentifier: Clone + Send + Sync, S: CoreDatabaseBidirectionalU64U128MappingStore<TableIdentifier>> BidirectionalU64U128TestHelper<TableIdentifier, S> {
    pub fn new() -> Self {
        Self {
            store: PhantomData,
            table: PhantomData,
        }
    }
}

impl <TableIdentifier: Clone + Send + Sync, S: CoreDatabaseBidirectionalU64U128MappingStore<TableIdentifier>> BidirectionalU64U128TestHelper<TableIdentifier, S> {
    
    pub async fn basic_select_behavior_u128(store: &S, table: &TableIdentifier, k2: u128) -> anyhow::Result<Option<u64>> {
        let result = store.db_select_one_u64_key_by_u128(table, k2).await?;
        if result.is_some() {
            let existing_value = result.unwrap();
            let reverse_lookup = store.db_select_one_u128_value_by_u64(table, existing_value).await?;
            assert!(reverse_lookup.is_some());
            assert_eq!(reverse_lookup.unwrap(), k2);
            Ok(result)
        } else {
            Ok(None)
        }
    }
    pub async fn basic_select_behavior_u64(store: &S, table: &TableIdentifier, k1: u64) -> anyhow::Result<Option<u128>> {
        let result = store.db_select_one_u128_value_by_u64(table, k1).await?;
        if result.is_some() {
            let existing_value = result.unwrap();
            let reverse_lookup = store.db_select_one_u64_key_by_u128(table, existing_value).await?;
            assert!(reverse_lookup.is_some());
            assert_eq!(reverse_lookup.unwrap(), k1);
            Ok(result)
        } else {
            Ok(None)
        }
    }
}