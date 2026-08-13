use std::num::NonZeroUsize;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use async_trait::async_trait;
use scylla::client::execution_profile::ExecutionProfile;
use scylla::client::PoolSize;
use parth_core::{crypto::hash::traits::MerkleZeroHasher, data::db::table::QDatabaseTableRoutingKey, felt::QFelt64, protocol::core_types::{Q256BitHash, QFHashBase, QHashBase}};
use psy_node_core::queue::realm_user_update_publish::GlobalUserTreeHeight;
use psy_node_core::queue::coordinator_guta_durable_submission::CoordinatorGutaDurableSubmissionStore;
use psy_node_core::queue::coordinator_processor_durable_capture::CoordinatorProcessorDurableCaptureFactory;
use psy_node_core::store::canonical_head::{
    CanonicalHeadBootstrap, CanonicalHeadReadState, CanonicalHeadWriteOutcome,
    CoordinatorCanonicalHeadReader, CoordinatorCanonicalHeadStore, NetworkId,
    SealedCanonicalHeadCas,
};
use psy_node_core::store::coordinator_commit_source::{
    CoordinatorCommitSource, CoordinatorCommitSourceStore,
    CoordinatorRollbackFloor,
};
use psy_node_core::store::rollback_admission::{
    CoordinatorRollbackAdmissionReader, CoordinatorRollbackAdmissionStore,
    RollbackAdmissionSlotBootstrap, RollbackAdmissionSlotReadState,
    RollbackAdmissionSlotWriteOutcome, SealedRollbackAdmissionSlotCas,
};
use psy_node_core::store::realm_processor_startup::{
    RealmProcessorStartupError, RealmProcessorStartupExpectation,
    RealmProcessorStartupPreflightProvider,
};
use scylla::client::session::Session;
use scylla::client::session_builder::SessionBuilder;
use psy_node_nats::queue::NatsJetStreamClient;
use crate::rollback::{
    BranchExactSchemaReady, BranchExactSchemaReadyView,
    BranchExactSchemaSetupError, BranchExactSchemaSetupMode,
    BranchExactSchemaSetupOutcome,
    CanonicalHeadNoTabletKeyspace, ScyllaCanonicalHeadStore,
    ScyllaBranchExactSchemaSetupGate, ScyllaRollbackAdmissionStore,
    ScyllaBranchExactShadowReader, PendingQueueSidecarKeyspaces,
    PendingQueueSidecarLifecycleError, PendingQueueSidecarReady,
    PendingQueueSidecarReadyView, PendingQueueSidecarSetupMode,
    PendingQueueSidecarSetupOutcome, ScyllaPendingQueueSidecarSetupGate,
    ScyllaCoordinatorGutaDurableSubmissionStore,
    ScyllaCoordinatorProcessorDurableCaptureFactory,
    ScyllaCoordinatorCommitSourceStore,
};
use crate::rollback::branch_exact_startup_preflight::ScyllaRealmProcessorStartupPreflightProvider;
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
    coordinator_commit_source_store:
        Arc<OnceLock<Arc<ScyllaCoordinatorCommitSourceStore>>>,
    rollback_admission_store: Arc<OnceLock<Arc<ScyllaRollbackAdmissionStore>>>,
    branch_exact_schema_ready: Arc<OnceLock<Arc<BranchExactSchemaReady>>>,
    pending_queue_sidecar_ready: Arc<OnceLock<Arc<PendingQueueSidecarReady>>>,
    _phantom_hash: std::marker::PhantomData<Hash>,
    _phantom_hasher: std::marker::PhantomData<Hasher>,
}

/// Connect to an existing Scylla cluster without creating any keyspace or
/// table. Operator-only schema deployment paths use this instead of
/// `ScyllaCoreStore::new`, whose legacy bootstrap contract creates keyspaces.
pub(crate) async fn connect_existing_scylla_session(
    known_nodes: &[String],
) -> anyhow::Result<Arc<Session>> {
    if known_nodes.is_empty() || known_nodes.iter().any(|node| node.trim().is_empty()) {
        anyhow::bail!("at least one non-empty Scylla node address is required");
    }

    let mut execution_profile =
        ExecutionProfile::builder().request_timeout(Some(Duration::from_secs(300)));
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
    Ok(Arc::new(session))
}

async fn require_existing_keyspace(
    session: &Session,
    keyspace: &str,
) -> anyhow::Result<()> {
    let row = session
        .query_unpaged(
            "SELECT keyspace_name FROM system_schema.keyspaces WHERE keyspace_name = ?",
            (keyspace,),
        )
        .await?
        .into_rows_result()?
        .maybe_first_row::<(String,)>()?;
    if row.is_none() {
        anyhow::bail!(
            "required Scylla keyspace {keyspace:?} does not exist; prepare-only setup refuses to create it"
        );
    }
    Ok(())
}

impl<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>> ScyllaCoreStore<Hash, Hasher> {
    pub async fn new(realm_id: u64, realm_sub_id: u64, keyspace: String, known_nodes: &[String]) -> anyhow::Result<Self> {
        let session = connect_existing_scylla_session(known_nodes).await?;

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
        Ok(Self::from_session(
            session,
            keyspace,
            no_tablet_keyspace,
            realm_id,
            realm_sub_id,
        ))
    }

    /// Open an already-deployed Realm store without creating keyspaces.
    ///
    /// Prepare-only Edge, inspection and startup-preflight paths must use this
    /// constructor so a typo cannot silently create an empty RF=1 keyspace.
    pub(crate) async fn new_existing(
        realm_id: u64,
        realm_sub_id: u64,
        keyspace: String,
        known_nodes: &[String],
    ) -> anyhow::Result<Self> {
        let session = connect_existing_scylla_session(known_nodes).await?;
        let no_tablet_keyspace = format!("{}_no_tablet", keyspace);
        require_existing_keyspace(&session, &keyspace).await?;
        require_existing_keyspace(&session, &no_tablet_keyspace).await?;
        Ok(Self::from_session(
            session,
            keyspace,
            no_tablet_keyspace,
            realm_id,
            realm_sub_id,
        ))
    }

    fn from_session(
        session: Arc<Session>,
        keyspace: String,
        no_tablet_keyspace: String,
        realm_id: u64,
        realm_sub_id: u64,
    ) -> Self {
        Self {
            session,
            keyspace,
            no_tablet_keyspace,
            realm_id,
            realm_sub_id,
            canonical_head_store: Arc::new(OnceLock::new()),
            coordinator_commit_source_store: Arc::new(OnceLock::new()),
            rollback_admission_store: Arc::new(OnceLock::new()),
            branch_exact_schema_ready: Arc::new(OnceLock::new()),
            pending_queue_sidecar_ready: Arc::new(OnceLock::new()),
            _phantom_hash: std::marker::PhantomData,
            _phantom_hasher: std::marker::PhantomData,
        }
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
            ScyllaCoordinatorCommitSourceStore::create_schema(&self.session, &keyspace)
                .await?;
        }
        let adapter = Arc::new(
            ScyllaCanonicalHeadStore::prepare(self.session.clone(), keyspace.clone()).await?,
        );
        let commit_sources = Arc::new(
            ScyllaCoordinatorCommitSourceStore::prepare(
                self.session.clone(),
                keyspace,
            )
            .await?,
        );
        self.canonical_head_store
            .set(adapter)
            .map_err(|_| anyhow::anyhow!("Coordinator canonical-head store initialized more than once"))?;
        self.coordinator_commit_source_store
            .set(commit_sources)
            .map_err(|_| anyhow::anyhow!(
                "Coordinator commit-source store initialized more than once"
            ))?;
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

    /// Default-off branch-exact schema setup gate. `Disabled` performs no
    /// branch-exact CQL. `RequireVerified` only prepares opaque read
    /// statements after exact durable BACKFILL_VERIFIED and live-schema
    /// checks; it does not expose reader/writer/cutover authority.
    pub async fn initialize_branch_exact_schema_setup(
        &self,
        expected_authority: psy_node_core::store::branch_exact_schema::AuthorityScope,
        mode: BranchExactSchemaSetupMode,
    ) -> Result<BranchExactSchemaSetupOutcome, BranchExactSchemaSetupError> {
        let BranchExactSchemaSetupMode::RequireVerified(request) = mode else {
            if self.branch_exact_schema_ready.get().is_some() {
                return Err(
                    BranchExactSchemaSetupError::AlreadyInitializedWithDifferentReceipt,
                );
            }
            return Ok(BranchExactSchemaSetupOutcome::Disabled);
        };
        let candidate = Arc::new(
            ScyllaBranchExactSchemaSetupGate::authorize(
                self.session.clone(),
                &self.keyspace,
                &self.no_tablet_keyspace,
                expected_authority,
                &request,
            )
            .await?,
        );
        match self.branch_exact_schema_ready.set(candidate.clone()) {
            Ok(()) => Ok(BranchExactSchemaSetupOutcome::Ready(
                candidate.view().clone(),
            )),
            Err(_) => {
                let current = self
                    .branch_exact_schema_ready
                    .get()
                    .expect("OnceLock rejected set but has no current value");
                if current.view() == candidate.view() {
                    Ok(BranchExactSchemaSetupOutcome::Idempotent(
                        current.view().clone(),
                    ))
                } else {
                    Err(
                        BranchExactSchemaSetupError::AlreadyInitializedWithDifferentReceipt,
                    )
                }
            }
        }
    }

    pub fn branch_exact_schema_setup_view(
        &self,
    ) -> Option<BranchExactSchemaReadyView> {
        self.branch_exact_schema_ready
            .get()
            .map(|ready| ready.view().clone())
    }

    pub(crate) fn require_branch_exact_schema_ready(
        &self,
    ) -> Result<&BranchExactSchemaReady, BranchExactSchemaSetupError> {
        self.branch_exact_schema_ready.get().map(Arc::as_ref).ok_or(
            BranchExactSchemaSetupError::LifecycleUninitialized,
        )
    }

    /// Default-off queue-sidecar setup. Disabled mode executes no queue CQL;
    /// enabled mode is inspect-only and requires an operator-created VERIFIED
    /// lifecycle plus the exact twenty-two-table v18 schema.
    pub async fn initialize_pending_queue_sidecar_setup(
        &self,
        authority: psy_data::protocol::chain_context::AuthorityScope,
        mode: PendingQueueSidecarSetupMode,
    ) -> Result<PendingQueueSidecarSetupOutcome, PendingQueueSidecarLifecycleError> {
        let PendingQueueSidecarSetupMode::RequireVerified = mode else {
            if self.pending_queue_sidecar_ready.get().is_some() {
                return Err(PendingQueueSidecarLifecycleError::AlreadyInitializedWithDifferentReceipt);
            }
            return Ok(PendingQueueSidecarSetupOutcome::Disabled);
        };
        let keyspaces = PendingQueueSidecarKeyspaces::try_new(
            self.keyspace.clone(),
            self.no_tablet_keyspace.clone(),
        )
        .map_err(|error| {
            PendingQueueSidecarLifecycleError::InvalidKeyspace(error.to_string())
        })?;
        let candidate = Arc::new(
            ScyllaPendingQueueSidecarSetupGate::authorize(
                self.session.clone(),
                keyspaces,
                authority,
            )
            .await?,
        );
        match self.pending_queue_sidecar_ready.set(candidate.clone()) {
            Ok(()) => Ok(PendingQueueSidecarSetupOutcome::Ready(
                candidate.view().clone(),
            )),
            Err(_) => {
                let current = self
                    .pending_queue_sidecar_ready
                    .get()
                    .expect("OnceLock rejected set but has no current value");
                if current.view() == candidate.view() {
                    Ok(PendingQueueSidecarSetupOutcome::Idempotent(
                        current.view().clone(),
                    ))
                } else {
                    Err(PendingQueueSidecarLifecycleError::AlreadyInitializedWithDifferentReceipt)
                }
            }
        }
    }

    pub fn pending_queue_sidecar_setup_view(
        &self,
    ) -> Option<PendingQueueSidecarReadyView> {
        self.pending_queue_sidecar_ready
            .get()
            .map(|ready| ready.view().clone())
    }

    /// Explicit Realm Edge publisher composition. Existing node setup never
    pub(crate) fn require_pending_queue_sidecar_ready(
        &self,
    ) -> Result<Arc<PendingQueueSidecarReady>, RealmProcessorStartupError> {
        self.pending_queue_sidecar_ready.get().cloned().ok_or_else(|| {
            RealmProcessorStartupError::DurableEvidenceNotVerified(
                "pending queue sidecar setup capability is disabled".to_owned(),
            )
        })
    }

    /// Prepare the Coordinator GUTA durable submission authority only after
    /// this exact process has consumed a VERIFIED v18 sidecar capability for
    /// Coordinator scope. The returned trait exposes no Session or DDL.
    pub async fn prepare_coordinator_guta_durable_submission_store(
        &self,
        network: psy_data::protocol::canonical_chain::NetworkId,
    ) -> Result<Arc<dyn CoordinatorGutaDurableSubmissionStore<Hash>>, anyhow::Error>
    where
        Hash: Q256BitHash + Send + Sync + 'static,
        Hasher: Send + Sync + 'static,
    {
        let ready = self.require_pending_queue_sidecar_ready()?;
        if ready.view().authority()
            != psy_data::protocol::chain_context::AuthorityScope::Coordinator
        {
            anyhow::bail!("Coordinator GUTA durable store requires Coordinator sidecar readiness");
        }
        let keyspaces = PendingQueueSidecarKeyspaces::try_new(
            self.keyspace.clone(),
            self.no_tablet_keyspace.clone(),
        )?;
        Ok(Arc::new(
            ScyllaCoordinatorGutaDurableSubmissionStore::prepare(
                self.session.clone(),
                keyspaces.control().clone(),
                network,
                *ready.view().ready_digest(),
            )
            .await?,
        ))
    }

    /// Prepare the storage-owned three-source Coordinator capture factory.
    /// The current activation is selected from the verified durable pipeline;
    /// callers cannot supply activation, pending or proc identity.
    pub async fn prepare_coordinator_processor_durable_capture_factory(
        &self,
        network: psy_data::protocol::canonical_chain::NetworkId,
        nats: Arc<NatsJetStreamClient>,
    ) -> Result<Arc<dyn CoordinatorProcessorDurableCaptureFactory>, anyhow::Error>
    where
        Hash: Q256BitHash + Send + Sync + 'static,
        Hasher: Send + Sync + 'static,
    {
        let ready = self.require_pending_queue_sidecar_ready()?;
        if ready.view().authority()
            != psy_data::protocol::chain_context::AuthorityScope::Coordinator
        {
            anyhow::bail!(
                "Coordinator durable capture requires Coordinator sidecar readiness"
            );
        }
        Ok(Arc::new(
            ScyllaCoordinatorProcessorDurableCaptureFactory::<Hash>::prepare(
                self.session.clone(),
                network,
                ready.as_ref(),
                nats,
            )
            .await?,
        ))
    }

    /// Explicit h21 tooling hook.  Opening a shadow reader requires the exact
    /// h20 setup capability; it is never invoked by normal node setup.
    pub async fn prepare_branch_exact_shadow_reader(
        &self,
    ) -> Result<ScyllaBranchExactShadowReader<Hash>, crate::rollback::BranchExactShadowReadError>
    where
        Hash: Q256BitHash,
    {
        let ready = self.require_branch_exact_schema_ready().map_err(|error| {
            crate::rollback::BranchExactShadowReadError::Driver(error.to_string())
        })?;
        ScyllaBranchExactShadowReader::prepare_from_ready(
            self.session.clone(),
            &self.keyspace,
            ready,
        )
        .await
    }

    /// Prepare the only production-shaped Scylla provider accepted by an
    /// enabled Realm startup. The factory is gated by the h20 in-memory ready
    /// capability and returns only the driver-independent trait object; raw
    /// Session ownership remains inside this crate.
    ///
    /// Disabled/legacy setup never calls this method. A Coordinator-ready store or
    /// a store whose physical Realm identity differs from the expectation is
    /// rejected before any statement preparation.
    pub async fn prepare_realm_processor_startup_preflight(
        &self,
        expectation: RealmProcessorStartupExpectation,
    ) -> Result<Arc<dyn RealmProcessorStartupPreflightProvider>, RealmProcessorStartupError>
    where
        Hash: Q256BitHash + Send + Sync + 'static,
        Hasher: Send + Sync + 'static,
    {
        let provider = self
            .prepare_realm_processor_startup_provider(expectation)
            .await?;
        Ok(Arc::new(provider))
    }

    /// Execute only the deterministic Scylla recovery subset before a fresh
    /// run attempt is sealed. This method never returns a startup provider or
    /// run permit, so recovery evidence cannot be reused as serving authority.
    pub(crate) async fn recover_realm_processor_startup(
        &self,
        recovery_expectation: RealmProcessorStartupExpectation,
    ) -> Result<(), RealmProcessorStartupError>
    where
        Hash: Q256BitHash + Send + Sync + 'static,
        Hasher: Send + Sync + 'static,
    {
        self.prepare_realm_processor_startup_provider(recovery_expectation)
            .await?
            .recover_isolated(recovery_expectation)
            .await
    }

    pub(crate) async fn prepare_realm_processor_startup_provider(
        &self,
        expectation: RealmProcessorStartupExpectation,
    ) -> Result<ScyllaRealmProcessorStartupPreflightProvider<Hash>, RealmProcessorStartupError>
    where
        Hash: Q256BitHash + Send + Sync + 'static,
        Hasher: Send + Sync + 'static,
    {
        let setup_ready = self
            .branch_exact_schema_ready
            .get()
            .cloned()
            .ok_or_else(|| {
                RealmProcessorStartupError::DurableEvidenceNotVerified(
                    "branch-exact schema setup capability is disabled".to_owned(),
                )
            })?;
        let queue_ready = self.require_pending_queue_sidecar_ready()?;
        let authority = require_realm_startup_factory_identity(
            self.realm_id,
            self.realm_sub_id,
            setup_ready.view().authority(),
            expectation,
        )?;
        ScyllaRealmProcessorStartupPreflightProvider::<Hash>::prepare(
            self.session.clone(),
            &self.keyspace,
            &self.no_tablet_keyspace,
            expectation.network(),
            authority,
            setup_ready,
            queue_ready,
        )
        .await
    }

    pub(crate) async fn prepare_realm_processor_startup_provider_with_capture<F>(
        &self,
        expectation: RealmProcessorStartupExpectation,
        nats: Arc<NatsJetStreamClient>,
        global_user_tree_height: GlobalUserTreeHeight,
    ) -> Result<ScyllaRealmProcessorStartupPreflightProvider<Hash>, RealmProcessorStartupError>
    where
        F: QFelt64 + Send + Sync + 'static,
        Hash: Q256BitHash + QFHashBase<F> + Send + Sync + 'static,
        Hasher: Send + Sync + 'static,
    {
        let setup_ready = self
            .branch_exact_schema_ready
            .get()
            .cloned()
            .ok_or_else(|| {
                RealmProcessorStartupError::DurableEvidenceNotVerified(
                    "branch-exact schema setup capability is disabled".to_owned(),
                )
            })?;
        let queue_ready = self.require_pending_queue_sidecar_ready()?;
        let authority = require_realm_startup_factory_identity(
            self.realm_id,
            self.realm_sub_id,
            setup_ready.view().authority(),
            expectation,
        )?;
        ScyllaRealmProcessorStartupPreflightProvider::<Hash>::prepare_with_capture::<F>(
            self.session.clone(),
            &self.keyspace,
            &self.no_tablet_keyspace,
            expectation.network(),
            authority,
            setup_ready,
            queue_ready,
            nats,
            global_user_tree_height,
        )
        .await
    }

    fn coordinator_canonical_head(&self) -> anyhow::Result<&ScyllaCanonicalHeadStore> {
        self.canonical_head_store
            .get()
            .map(Arc::as_ref)
            .ok_or_else(|| anyhow::anyhow!(
                "Coordinator canonical-head store was not initialized by Coordinator setup"
            ))
    }

    fn coordinator_commit_sources(
        &self,
    ) -> anyhow::Result<&ScyllaCoordinatorCommitSourceStore> {
        self.coordinator_commit_source_store
            .get()
            .map(Arc::as_ref)
            .ok_or_else(|| anyhow::anyhow!(
                "Coordinator commit-source store was not initialized by Coordinator setup"
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
impl<Hash, Hasher> CoordinatorCommitSourceStore<Hash>
    for ScyllaCoreStore<Hash, Hasher>
where
    Hash: QHashBase + Q256BitHash,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
{
    async fn persist_coordinator_rollback_floor(
        &self,
        floor: &CoordinatorRollbackFloor<Hash>,
    ) -> anyhow::Result<()> {
        Ok(self
            .coordinator_commit_sources()?
            .persist_floor_and_readback(floor)
            .await?)
    }

    async fn read_coordinator_rollback_floor(
        &self,
        network: NetworkId,
        chain_epoch: u64,
    ) -> anyhow::Result<Option<CoordinatorRollbackFloor<Hash>>> {
        Ok(self
            .coordinator_commit_sources()?
            .read_floor(network, chain_epoch)
            .await?)
    }

    async fn persist_coordinator_commit_source(
        &self,
        source: &CoordinatorCommitSource<Hash>,
    ) -> anyhow::Result<()> {
        Ok(self
            .coordinator_commit_sources()?
            .persist_and_readback(source)
            .await?)
    }

    async fn read_coordinator_commit_source(
        &self,
        candidate: &psy_data::protocol::canonical_chain::CanonicalChainRef<Hash>,
    ) -> anyhow::Result<Option<CoordinatorCommitSource<Hash>>> {
        Ok(self
            .coordinator_commit_sources()?
            .read_source(candidate)
            .await?)
    }

    async fn mark_coordinator_commit_source_committed(
        &self,
        source: &CoordinatorCommitSource<Hash>,
    ) -> anyhow::Result<()> {
        Ok(self
            .coordinator_commit_sources()?
            .mark_committed_and_readback(source)
            .await?)
    }
}

fn require_realm_startup_factory_identity(
    store_realm_id: u64,
    store_realm_sub_id: u64,
    setup_authority: psy_node_core::store::branch_exact_schema::AuthorityScope,
    expectation: RealmProcessorStartupExpectation,
) -> Result<psy_node_core::store::branch_exact_schema::AuthorityScope, RealmProcessorStartupError>
{
    let authority = psy_node_core::store::branch_exact_schema::AuthorityScope::Realm {
        realm_id: expectation.realm_id(),
        realm_sub_id: expectation.realm_sub_id(),
    };
    if setup_authority != authority
        || store_realm_id != u64::from(expectation.realm_id())
        || store_realm_sub_id != u64::from(expectation.realm_sub_id())
    {
        return Err(RealmProcessorStartupError::AuthorityMismatch);
    }
    Ok(authority)
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

#[cfg(test)]
mod branch_exact_startup_factory_tests {
    use psy_node_core::store::branch_exact_schema::AuthorityScope;

    use super::*;

    #[test]
    fn prepare_only_constructor_requires_existing_keyspaces_without_ddl() {
        let source = include_str!("core.rs");
        let constructor = source
            .split("pub(crate) async fn new_existing")
            .nth(1)
            .unwrap()
            .split("fn from_session")
            .next()
            .unwrap();
        assert!(constructor.contains("connect_existing_scylla_session"));
        assert_eq!(constructor.matches("require_existing_keyspace").count(), 2);
        assert!(!constructor.contains("CREATE KEYSPACE"));
        assert!(!constructor.contains("await_schema_agreement"));
    }

    fn expectation(
        realm_id: u32,
        realm_sub_id: u16,
    ) -> RealmProcessorStartupExpectation {
        RealmProcessorStartupExpectation::try_new(
            NetworkId::try_from_chain_id(1337).unwrap(),
            realm_id,
            realm_sub_id,
            5,
            [1; 32],
            [2; 32],
            [3; 32],
        )
        .unwrap()
    }

    #[test]
    fn factory_identity_requires_store_setup_and_expectation_to_match() {
        let expected = AuthorityScope::Realm {
            realm_id: 7,
            realm_sub_id: 3,
        };
        assert_eq!(
            require_realm_startup_factory_identity(
                7,
                3,
                expected,
                expectation(7, 3),
            )
            .unwrap(),
            expected
        );
        for (store_realm, store_sub, setup) in [
            (8, 3, expected),
            (7, 4, expected),
            (7, 3, AuthorityScope::Coordinator),
            (
                7,
                3,
                AuthorityScope::Realm {
                    realm_id: 7,
                    realm_sub_id: 4,
                },
            ),
        ] {
            assert_eq!(
                require_realm_startup_factory_identity(
                    store_realm,
                    store_sub,
                    setup,
                    expectation(7, 3),
                )
                .unwrap_err(),
                RealmProcessorStartupError::AuthorityMismatch
            );
        }
    }

    #[test]
    fn factory_returns_confined_trait_objects_and_is_confined_to_startup_composition() {
        let source = include_str!("core.rs");
        let factory = source
            .split("pub async fn prepare_realm_processor_startup_preflight")
            .nth(1)
            .unwrap()
            .split("fn coordinator_canonical_head")
            .next()
            .unwrap();
        assert!(factory.contains("Arc<dyn RealmProcessorStartupPreflightProvider>"));
        assert!(!factory.contains("Arc<Session>"));
        assert!(factory.contains("branch_exact_schema_ready"));
        assert!(factory.contains("pending_queue_sidecar_ready"));
        assert!(factory.contains("recover_realm_processor_startup"));
        assert!(factory.contains("recover_isolated(recovery_expectation)"));
        let provider_helper = factory
            .split("pub(crate) async fn prepare_realm_processor_startup_provider")
            .nth(1)
            .unwrap();
        assert!(
            provider_helper.find("branch_exact_schema_ready").unwrap()
                < provider_helper
                    .find("ScyllaRealmProcessorStartupPreflightProvider::<Hash>::prepare")
                    .unwrap()
        );
        assert!(
            provider_helper.find("require_pending_queue_sidecar_ready").unwrap()
                < provider_helper
                    .find("ScyllaRealmProcessorStartupPreflightProvider::<Hash>::prepare")
                    .unwrap()
        );

        let setup = include_str!("psy_setup.rs");
        let composition = setup
            .split("pub async fn setup_realm_processor_scylla_startup_composition")
            .nth(1)
            .unwrap()
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(composition.contains("prepare_realm_processor_startup_provider_with_capture"));
        assert!(composition.contains("RealmBranchExactCommitRuntimeInstaller"));
        assert_eq!(
            setup
                .matches(".prepare_realm_processor_startup_provider_with_capture(")
                .count(),
            1
        );

        let plonky = include_str!(
            "../../psy_cli/psy_node_cli/src/node/startup_plonky2_scylla.rs"
        );
        let jtmb = include_str!(
            "../../psy_cli/psy_node_cli/src/node/startup_processor_jtmb_scylla.rs"
        );
        for cli in [plonky, jtmb] {
            assert!(cli.contains("setup_realm_processor_scylla_startup_composition"));
            assert!(!cli.contains(".prepare_realm_processor_startup_preflight("));
        }
    }
}
