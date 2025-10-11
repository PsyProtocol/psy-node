use std::sync::Arc;

use parth_core::{crypto::hash::traits::MerkleZeroHasher, data::db::table::QDatabaseTableRoutingKey, protocol::core_types::QHashBase};
use scylla::client::session::{Session, SessionConfig};

use crate::tables::traits::ScyllaStandardPreparedTableStatements;

#[derive(Clone)]
pub struct ScyllaCoreStore<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>> {
    pub session: Arc<Session>,
    pub keyspace: String,
    pub realm_id: u64,
    pub realm_sub_id: u64,
    _phantom_hash: std::marker::PhantomData<Hash>,
    _phantom_hasher: std::marker::PhantomData<Hasher>,
}

impl<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>> ScyllaCoreStore<Hash, Hasher> {
    pub async fn new(realm_id: u64, realm_sub_id: u64, keyspace: String, known_nodes: &[String]) -> anyhow::Result<Self> {
        let mut config = SessionConfig::new();
        config.add_known_nodes(known_nodes.iter());
        let session = Arc::new(Session::connect(config).await?);

        // Create keyspace and table if not exists
        session
            .query_unpaged(
                format!(
                    "CREATE KEYSPACE IF NOT EXISTS {} WITH replication = {{'class': 'SimpleStrategy', 'replication_factor': 1}}",
                    &keyspace
                ),
                &[],
            )
            .await?;
        session.await_schema_agreement().await?;
        Ok(Self {
            session,
            keyspace,
            realm_id,
            realm_sub_id,
            _phantom_hash: std::marker::PhantomData,
            _phantom_hasher: std::marker::PhantomData,
        })
    }
    pub async fn init_std_table<T: ScyllaStandardPreparedTableStatements>(
        &self,
        table_name: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<T> {
        T::create_table_standard(self.session.clone(), &self.keyspace, table_name, table_key).await
    }
}
