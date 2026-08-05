use std::num::NonZeroUsize;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use async_trait::async_trait;
use scylla::client::execution_profile::ExecutionProfile;
use scylla::client::PoolSize;
use parth_core::{crypto::hash::traits::MerkleZeroHasher, data::db::table::QDatabaseTableRoutingKey, protocol::core_types::{Q256BitHash, QHashBase}};
use psy_node_core::store::canonical_head::{
    CanonicalHeadBootstrap, CanonicalHeadReadState, CanonicalHeadWriteOutcome,
    CoordinatorCanonicalHeadReader, CoordinatorCanonicalHeadStore, NetworkId,
    SealedCanonicalHeadCas,
};
use psy_node_core::store::rollback_admission::{
    CoordinatorRollbackAdmissionReader, CoordinatorRollbackAdmissionStore,
    RollbackAdmissionSlotBootstrap, RollbackAdmissionSlotReadState,
    RollbackAdmissionSlotWriteOutcome, SealedRollbackAdmissionSlotCas,
};
use scylla::client::session::Session;
use scylla::client::session_builder::SessionBuilder;
use crate::rollback::{
    CanonicalHeadNoTabletKeyspace, ScyllaCanonicalHeadStore,
    ScyllaRollbackAdmissionStore,
};
use crate::tables::{merkle::ScyllaMerkleNodesZeroPreparedStatements, traits::ScyllaStandardPreparedTableStatements};
use crate::tables::traits::ScyllaNoTabletPreparedTableStatements;

#[derive(Clone)]
pub struct ScyllaCoreStore<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>> {
    pub session: Arc<Session>,
    pub keyspace: String,
    pub no_tablet_keyspace: String,
    pub realm_id: u64,
    pub realm_sub_id: u64,
    canonical_head_store: Arc<OnceLock<Arc<ScyllaCanonicalHeadStore>>>,
    rollback_admission_store: Arc<OnceLock<Arc<ScyllaRollbackAdmissionStore>>>,
    _phantom_hash: std::marker::PhantomData<Hash>,
    _phantom_hasher: std::marker::PhantomData<Hasher>,
}

impl<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>> ScyllaCoreStore<Hash, Hasher> {
    pub async fn new(realm_id: u64, realm_sub_id: u64, keyspace: String, known_nodes: &[String]) -> anyhow::Result<Self> {
        let mut execution_profile = ExecutionProfile::builder()
            .request_timeout(Some(Duration::from_secs(300)));
        if known_nodes.len() == 1 {
                execution_profile = execution_profile.consistency(scylla::statement::Consistency::One)
        };
        let execution_profile = execution_profile.build();
        let session = SessionBuilder::new()
            .known_nodes(known_nodes.iter())
            .default_execution_profile_handle(execution_profile.into_handle())
            .connection_timeout(Duration::from_secs(120))
            .keepalive_timeout(Duration::from_secs(60))
            .keepalive_interval(Duration::from_secs(30))
            .pool_size(PoolSize::PerHost(NonZeroUsize::new(1).unwrap()))
            .build()
            .await?;
        let session = Arc::new(session);

        let no_tablet_keyspace = format!("{}_no_tablet", keyspace);

        println!("creating keyspaces: {} and {}", &keyspace, &no_tablet_keyspace);

        // Create keyspace and table if not exists

        let create_standard_keyspace = session
            .query_unpaged(
                format!(
                    "CREATE KEYSPACE IF NOT EXISTS {} WITH replication = {{'class': 'NetworkTopologyStrategy', 'replication_factor': 1}} AND tablets = {{ 'enabled': false }}",
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
            canonical_head_store: Arc::new(OnceLock::new()),
            rollback_admission_store: Arc::new(OnceLock::new()),
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

    pub async fn init_std_table_prepare_only<T: ScyllaStandardPreparedTableStatements>(
        &self,
        table_name: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<T> {
        println!("preparing statements for table: {}", table_name);
        T::prepare_only_standard(self.session.clone(), &self.keyspace, table_name, table_key).await
    }

    pub async fn init_no_tablet_table_prepare_only<T: ScyllaNoTabletPreparedTableStatements>(
        &self,
        table_name: &str,
        table_key: QDatabaseTableRoutingKey,
    ) -> anyhow::Result<T> {
        println!("preparing statements for no-tablet table: {}", table_name);
        T::prepare_only_no_tablet(self.session.clone(), &self.no_tablet_keyspace, table_name, table_key).await
    }

    pub async fn init_zero_id_merkle_table_prepare_only(
        &self,
        table_name: &str,
        table_key: QDatabaseTableRoutingKey,
        tree_height: u8,
    ) -> anyhow::Result<ScyllaMerkleNodesZeroPreparedStatements> {
        println!("preparing statements for zero id merkle table: {}", table_name);
        ScyllaMerkleNodesZeroPreparedStatements::new_from_session(self.session.clone(), &self.keyspace, table_name, table_key, tree_height).await
    }

    /// Initialize the Coordinator-only canonical-head authority in the
    /// existing no-tablet keyspace. Generic Realm/Edge setup never calls this.
    pub async fn initialize_coordinator_canonical_head(
        &self,
        create_schema: bool,
    ) -> anyhow::Result<()> {
        let keyspace = CanonicalHeadNoTabletKeyspace::try_new(
            self.no_tablet_keyspace.clone(),
        )?;
        if create_schema {
            ScyllaCanonicalHeadStore::create_schema(&self.session, &keyspace).await?;
        }
        let adapter = Arc::new(
            ScyllaCanonicalHeadStore::prepare(self.session.clone(), keyspace).await?,
        );
        self.canonical_head_store
            .set(adapter)
            .map_err(|_| anyhow::anyhow!("Coordinator canonical-head store initialized more than once"))?;
        Ok(())
    }

    /// Initialize the Coordinator-only durable admin-to-Processor inbox in
    /// the same no-tablet control keyspace as the canonical-head authority.
    pub async fn initialize_coordinator_rollback_admission(
        &self,
        create_schema: bool,
    ) -> anyhow::Result<()> {
        let keyspace = CanonicalHeadNoTabletKeyspace::try_new(
            self.no_tablet_keyspace.clone(),
        )?;
        if create_schema {
            ScyllaRollbackAdmissionStore::create_schema(&self.session, &keyspace).await?;
        }
        let adapter = Arc::new(
            ScyllaRollbackAdmissionStore::prepare(self.session.clone(), keyspace).await?,
        );
        self.rollback_admission_store
            .set(adapter)
            .map_err(|_| anyhow::anyhow!("Coordinator rollback-admission store initialized more than once"))?;
        Ok(())
    }

    fn coordinator_canonical_head(&self) -> anyhow::Result<&ScyllaCanonicalHeadStore> {
        self.canonical_head_store
            .get()
            .map(Arc::as_ref)
            .ok_or_else(|| anyhow::anyhow!(
                "Coordinator canonical-head store was not initialized by Coordinator setup"
            ))
    }

    fn coordinator_rollback_admission(
        &self,
    ) -> anyhow::Result<&ScyllaRollbackAdmissionStore> {
        self.rollback_admission_store
            .get()
            .map(Arc::as_ref)
            .ok_or_else(|| anyhow::anyhow!(
                "Coordinator rollback-admission store was not initialized by Coordinator setup"
            ))
    }
}

#[async_trait]
impl<Hash, Hasher> CoordinatorCanonicalHeadReader<Hash> for ScyllaCoreStore<Hash, Hasher>
where
    Hash: QHashBase + Q256BitHash,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
{
    async fn read_canonical_head(
        &self,
        network: NetworkId,
    ) -> anyhow::Result<CanonicalHeadReadState<Hash>> {
        Ok(self.coordinator_canonical_head()?.read(network).await?)
    }
}

#[async_trait]
impl<Hash, Hasher> CoordinatorCanonicalHeadStore<Hash> for ScyllaCoreStore<Hash, Hasher>
where
    Hash: QHashBase + Q256BitHash,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
{
    async fn bootstrap_canonical_head(
        &self,
        bootstrap: &CanonicalHeadBootstrap<Hash>,
    ) -> anyhow::Result<CanonicalHeadWriteOutcome<Hash>> {
        Ok(self
            .coordinator_canonical_head()?
            .bootstrap(bootstrap)
            .await?)
    }

    async fn compare_and_set_canonical_head(
        &self,
        sealed: &SealedCanonicalHeadCas<Hash>,
    ) -> anyhow::Result<CanonicalHeadWriteOutcome<Hash>> {
        Ok(self
            .coordinator_canonical_head()?
            .compare_and_set(sealed)
            .await?)
    }
}

#[async_trait]
impl<Hash, Hasher> CoordinatorRollbackAdmissionReader<Hash>
    for ScyllaCoreStore<Hash, Hasher>
where
    Hash: QHashBase + Q256BitHash,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
{
    async fn read_rollback_admission_slot(
        &self,
        network: NetworkId,
    ) -> anyhow::Result<RollbackAdmissionSlotReadState<Hash>> {
        Ok(self.coordinator_rollback_admission()?.read(network).await?)
    }
}

#[async_trait]
impl<Hash, Hasher> CoordinatorRollbackAdmissionStore<Hash>
    for ScyllaCoreStore<Hash, Hasher>
where
    Hash: QHashBase + Q256BitHash,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
{
    async fn bootstrap_rollback_admission_slot(
        &self,
        bootstrap: &RollbackAdmissionSlotBootstrap<Hash>,
    ) -> anyhow::Result<RollbackAdmissionSlotWriteOutcome<Hash>> {
        Ok(self
            .coordinator_rollback_admission()?
            .bootstrap(bootstrap)
            .await?)
    }

    async fn compare_and_set_rollback_admission_slot(
        &self,
        sealed: &SealedRollbackAdmissionSlotCas<Hash>,
    ) -> anyhow::Result<RollbackAdmissionSlotWriteOutcome<Hash>> {
        Ok(self
            .coordinator_rollback_admission()?
            .compare_and_set(sealed)
            .await?)
    }
}
