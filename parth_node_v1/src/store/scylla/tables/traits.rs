use std::sync::Arc;

use async_trait::async_trait;
use parth_core::data::db::table::QDatabaseTableRoutingKey;
use scylla::client::session::Session;
#[async_trait]
pub trait ScyllaStandardPreparedTableStatements: Sized {
    async fn create_table_standard(session: Arc<Session>, keyspace: &str, table_name: &str, table_key: QDatabaseTableRoutingKey) -> anyhow::Result<Self>;
}