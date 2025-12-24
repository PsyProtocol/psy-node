use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;
use scylla::client::execution_profile::ExecutionProfile;
use scylla::client::PoolSize;
use parth_core::{crypto::hash::traits::MerkleZeroHasher, data::db::table::QDatabaseTableRoutingKey, protocol::core_types::QHashBase};
use scylla::client::session::Session;
use scylla::client::session_builder::SessionBuilder;
use tokio::time::sleep;
use crate::tables::{merkle::ScyllaMerkleNodesZeroPreparedStatements, traits::ScyllaStandardPreparedTableStatements};
use crate::tables::traits::ScyllaNoTabletPreparedTableStatements;

#[derive(Clone)]
pub struct ScyllaCoreStore<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>> {
    pub session: Arc<Session>,
    pub keyspace: String,
    pub no_tablet_keyspace: String,
    pub realm_id: u64,
    pub realm_sub_id: u64,
    _phantom_hash: std::marker::PhantomData<Hash>,
    _phantom_hasher: std::marker::PhantomData<Hasher>,
}

impl<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>> ScyllaCoreStore<Hash, Hasher> {
    pub async fn new(realm_id: u64, realm_sub_id: u64, keyspace: String, known_nodes: &[String]) -> anyhow::Result<Self> {
        let mut execution_profile = ExecutionProfile::builder()
            .request_timeout(Some(Duration::from_secs(120)));
        if known_nodes.len() == 1 {
                execution_profile = execution_profile.consistency(scylla::statement::Consistency::One)
        };
        let execution_profile = execution_profile.build();
        let session = SessionBuilder::new()
            .known_nodes(known_nodes.iter())
            .default_execution_profile_handle(execution_profile.into_handle())
            .connection_timeout(Duration::from_secs(60))
            .keepalive_timeout(Duration::from_secs(60))
            .keepalive_interval(Duration::from_secs(30))
            .pool_size(PoolSize::PerHost(NonZeroUsize::new(5).unwrap()))
            .build()
            .await?;
        let session = Arc::new(session);

        let no_tablet_keyspace = format!("{}_no_tablet", keyspace);

        println!("creating keyspaces: {} and {}", &keyspace, &no_tablet_keyspace);

        // Create keyspace and table if not exists

        let create_standard_keyspace = session
            .query_unpaged(
                format!(
                    "CREATE KEYSPACE IF NOT EXISTS {} WITH replication = {{'class': 'NetworkTopologyStrategy', 'replication_factor': 1}}",
                    &keyspace
                ),
                &[],
            );
        let create_no_tablet_keyspace = session
            .query_unpaged(
                format!(
                    "CREATE KEYSPACE IF NOT EXISTS {} WITH replication = {{'class': 'NetworkTopologyStrategy', 'replication_factor': 1}} AND tablets = {{ 'enabled': false }}",
                    &no_tablet_keyspace
                ),
                &[],
            );

        let (res_std, res_no_tablet) = tokio::join!(create_standard_keyspace, create_no_tablet_keyspace);

        let _ = res_std?;
        let _ = res_no_tablet?;
        session.await_schema_agreement().await?;
        Ok(Self {
            session,
            keyspace,
            no_tablet_keyspace,
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
        println!("intializing table: {}", table_name);
        T::create_table_standard(self.session.clone(), &self.keyspace, table_name, table_key).await
    }
    pub async fn init_no_tablet_table<T: ScyllaNoTabletPreparedTableStatements>(
        &self,
        table_name: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<T> {
        println!("intializing no-tablet table: {}", table_name);
        T::create_table_no_tablet(self.session.clone(), &self.no_tablet_keyspace, table_name, table_key).await
    }
    pub async fn init_zero_id_merkle_table(
        &self,
        table_name: &str,
        table_key: QDatabaseTableRoutingKey,
        tree_height: u8,
    ) -> anyhow::Result<ScyllaMerkleNodesZeroPreparedStatements> {
        println!("intializing zero id merkle table: {}", table_name);
        ScyllaMerkleNodesZeroPreparedStatements::new_create_from_session(self.session.clone(), &self.keyspace, table_name, table_key, tree_height).await
    }
}
