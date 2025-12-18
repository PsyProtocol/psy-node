use std::sync::Arc;

use async_trait::async_trait;
use parth_core::data::db::{data_types::BiDirectionalMappingRow, table::QDatabaseTableRoutingKey};
use scylla::
    client::session::Session
;

use crate::
    tables::{traits::ScyllaStandardPreparedTableStatements, u64_table::{u64_to_u128::ScyllaU64ToU128TablePreparedStatements, u128_to_u64::ScyllaU128ToU64TablePreparedStatements}}
;

#[derive(Clone)]
pub struct ScyllaBidirectionalU64U128MappingPreparedStatements {
    pub u64_to_u128: ScyllaU64ToU128TablePreparedStatements,
    pub u128_to_u64: ScyllaU128ToU64TablePreparedStatements,
}

impl ScyllaBidirectionalU64U128MappingPreparedStatements {
    pub async fn new_from_session(
        session: Arc<Session>,
        keyspace: &str,
        table_name_u64_to_u128: &str,
        table_name_u128_to_u64: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<Self> {
        let u64_to_u128 = ScyllaU64ToU128TablePreparedStatements::new_from_session(
            session.clone(),
            keyspace,
            table_name_u64_to_u128,
            table_key.clone(),
        )
        .await?;
        let u128_to_u64 = ScyllaU128ToU64TablePreparedStatements::new_from_session(
            session.clone(),
            keyspace,
            table_name_u128_to_u64,
            table_key.clone(),
        )
        .await?;
        Ok(Self {
            u64_to_u128,
            u128_to_u64,
        })
    }
    pub async fn create_tables(
        session: Arc<Session>,
        keyspace: &str,
        table_name_u64_to_u128: &str,
        table_name_u128_to_u64: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<()> {
        ScyllaU64ToU128TablePreparedStatements::create_table(session.clone(), keyspace, table_name_u64_to_u128, table_key.clone()).await?;
        ScyllaU128ToU64TablePreparedStatements::create_table(session.clone(), keyspace, table_name_u128_to_u64, table_key.clone()).await?;
        Ok(())
    }
    pub async fn new_create_from_session(
        session: Arc<Session>,
        keyspace: &str,
        table_name_u64_to_u128: &str,
        table_name_u128_to_u64: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<Self> {
        Self::create_tables(
            session.clone(),
            keyspace,
            table_name_u64_to_u128,
            table_name_u128_to_u64,
            table_key.clone(),
        )
        .await?;
        Self::new_from_session(
            session.clone(),
            keyspace,
            table_name_u64_to_u128,
            table_name_u128_to_u64,
            table_key.clone(),
        )
        .await
    }
}



#[async_trait]
impl ScyllaStandardPreparedTableStatements for ScyllaBidirectionalU64U128MappingPreparedStatements {
    async fn create_table_standard(
        session: Arc<Session>,
        keyspace: &str,
        table_name: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<Self> {
        Self::new_create_from_session(
            session,
            keyspace,
            &format!("{}_u64_to_u128", table_name),
            &format!("{}_u128_to_u64", table_name),
            table_key,
        )
        .await
    }
}

impl ScyllaBidirectionalU64U128MappingPreparedStatements {
    pub async fn insert_u64_u128_mapping_pair(&self, session: &Session, k1: u64, k2: u128) -> anyhow::Result<()> {
        let fut1 = self.u64_to_u128.set_or_insert_one(session, k1, k2);
        let fut2 = self.u128_to_u64.set_or_insert_one(session, k2, k1);
        let (res1, res2) = tokio::join!(fut1, fut2);
        res1?;
        res2?;
        Ok(())
    }
    pub async fn insert_u64_u128_mapping_pairs(&self, session: &Session, keys: &[BiDirectionalMappingRow<u64, u128>]) -> anyhow::Result<()> {
        let entries_1: Vec<(u64, u128)> = keys.iter().map(|x| (x.k1.clone(), x.k2.clone())).collect();
        let entries_2: Vec<(u128, u64)> = keys.iter().map(|x| (x.k2.clone(), x.k1.clone())).collect();
        let fut1 = self.u64_to_u128.set_or_insert_many(session, &entries_1);
        let fut2 = self.u128_to_u64.set_or_insert_many(session, &entries_2);
        let (res1, res2) = tokio::join!(fut1, fut2);
        res1?;
        res2?;
        Ok(())
    }
    pub async fn get_k2_from_k1(&self, session: &Session, k1: u64) -> anyhow::Result<Option<u128>> {
        self.u64_to_u128.select_one_single(session, k1).await
    }
    pub async fn get_k1_from_k2(&self, session: &Session, k2: u128) -> anyhow::Result<Option<u64>> {
        self.u128_to_u64.select_one_single(session, k2).await
    }
    pub async fn get_k2s_from_k1s(&self, session: Arc<Session>, k1s: &[u64]) -> anyhow::Result<Vec<Option<u128>>> {
        self.u64_to_u128.select_many_values(session, k1s).await
    }
    pub async fn get_k1s_from_k2s(&self, session: Arc<Session>, k2s: &[u128]) -> anyhow::Result<Vec<Option<u64>>> {
        self.u128_to_u64.select_many_values(session, k2s).await
    }
}
