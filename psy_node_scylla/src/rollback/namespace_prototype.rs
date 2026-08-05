//! Isolated, production-shaped G0-03 Scylla namespace/catalog/binding spike.
//!
//! The module is deliberately not wired into `ScyllaCoreStore`, `psy_setup`,
//! Coordinator, Realm, or any current writer. It proves durable binding and
//! crash semantics for three representative physical schemas only.

use std::{error::Error, fmt};

use psy_node_core::store::{
    timestamp::CommitWriteTimestampUs,
    typed::{CheckpointId, LogicalMutation, MerkleNode, MutationValue, NodeIndex, TypedTableKey},
};
use scylla::{
    client::session::Session,
    statement::{prepared::PreparedStatement, Consistency, SerialConsistency},
};

use super::{
    seal_commit_put, AuthorityStorageBinding, AuthorityStorageNamespace, BindingGeneration,
    CheckpointLeafSnapshotRow, CqlKeyspaceName, GlobalUserMerkleSnapshotRow, LoadingRecoveryNamespace,
    NamespaceCheckpointHash, NamespaceModelError, NoTabletCounterSnapshotRow, RecoveryNamespaceDescriptor,
    RecoveryNamespaceId, RecoveryNamespaceIntent, RecoveryNamespaceStatus, RepresentativeDataset,
    RepresentativeDatasetDigest, RepresentativeRowCounts, RepresentativeStateRoot, StorageAuthority,
    StorageAuthorityKind, TimestampPrototypeAdapter, VerifiedRecoveryNamespace,
};

const CATALOG_TABLE: &str = "g003_recovery_namespace_catalog";
const BINDING_TABLE: &str = "g003_authority_active_binding";
const CHECKPOINT_LEAF_TABLE: &str = "checkpoint_leaf_table";
const GLOBAL_USER_TREE_TABLE: &str = "global_user_tree_table";
const COUNTER_TABLE: &str = "u64_counter_singleton_table";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceLwtContract {
    regular: Consistency,
    serial: SerialConsistency,
}

impl NamespaceLwtContract {
    pub const fn rf3_default() -> Self {
        Self {
            regular: Consistency::Quorum,
            serial: SerialConsistency::LocalSerial,
        }
    }

    pub const fn regular(self) -> Consistency {
        self.regular
    }

    pub const fn serial(self) -> SerialConsistency {
        self.serial
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceControlQueries {
    create_catalog: String,
    create_binding: String,
    insert_catalog_if_absent: String,
    select_catalog: String,
    transition_catalog_status: String,
    insert_binding_if_absent: String,
    select_binding: String,
    cutover_binding: String,
}

impl NamespaceControlQueries {
    pub fn new(control_keyspace: &CqlKeyspaceName) -> Self {
        let catalog = format!("{}.{CATALOG_TABLE}", control_keyspace.as_str());
        let binding = format!("{}.{BINDING_TABLE}", control_keyspace.as_str());
        Self {
            create_catalog: format!(
                "CREATE TABLE IF NOT EXISTS {catalog} (\
                 network_id text, authority_kind tinyint, authority_id bigint, namespace_id blob, \
                 standard_namespace text, no_tablet_namespace text, target_checkpoint_id bigint, \
                 target_checkpoint_hash blob, state_root blob, dataset_digest blob, \
                 checkpoint_leaf_rows bigint, global_user_merkle_rows bigint, no_tablet_counter_rows bigint, \
                 expected_generation bigint, status tinyint, created_at_unix_ms bigint, verified_at_unix_ms bigint, \
                 PRIMARY KEY ((network_id, authority_kind, authority_id), namespace_id))"
            ),
            create_binding: format!(
                "CREATE TABLE IF NOT EXISTS {binding} (\
                 network_id text, authority_kind tinyint, authority_id bigint, binding_generation bigint, \
                 namespace_id blob, standard_namespace text, no_tablet_namespace text, checkpoint_id bigint, \
                 checkpoint_hash blob, state_root blob, dataset_digest blob, updated_at_unix_ms bigint, \
                 PRIMARY KEY ((network_id, authority_kind, authority_id)))"
            ),
            insert_catalog_if_absent: format!(
                "INSERT INTO {catalog} (network_id, authority_kind, authority_id, namespace_id, \
                 standard_namespace, no_tablet_namespace, target_checkpoint_id, target_checkpoint_hash, \
                 state_root, dataset_digest, checkpoint_leaf_rows, global_user_merkle_rows, \
                 no_tablet_counter_rows, expected_generation, status, created_at_unix_ms, verified_at_unix_ms) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) IF NOT EXISTS"
            ),
            select_catalog: format!(
                "SELECT network_id, authority_kind, authority_id, namespace_id, standard_namespace, \
                 no_tablet_namespace, target_checkpoint_id, target_checkpoint_hash, state_root, dataset_digest, \
                 checkpoint_leaf_rows, global_user_merkle_rows, no_tablet_counter_rows, expected_generation, \
                 status, created_at_unix_ms, verified_at_unix_ms FROM {catalog} \
                 WHERE network_id = ? AND authority_kind = ? AND authority_id = ? AND namespace_id = ?"
            ),
            transition_catalog_status: format!(
                "UPDATE {catalog} SET status = ?, verified_at_unix_ms = ? \
                 WHERE network_id = ? AND authority_kind = ? AND authority_id = ? AND namespace_id = ? \
                 IF status = ?"
            ),
            insert_binding_if_absent: format!(
                "INSERT INTO {binding} (network_id, authority_kind, authority_id, binding_generation, \
                 namespace_id, standard_namespace, no_tablet_namespace, checkpoint_id, checkpoint_hash, \
                 state_root, dataset_digest, updated_at_unix_ms) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) IF NOT EXISTS"
            ),
            select_binding: format!(
                "SELECT network_id, authority_kind, authority_id, binding_generation, namespace_id, \
                 standard_namespace, no_tablet_namespace, checkpoint_id, checkpoint_hash, state_root, dataset_digest, \
                 updated_at_unix_ms FROM {binding} \
                 WHERE network_id = ? AND authority_kind = ? AND authority_id = ?"
            ),
            cutover_binding: format!(
                "UPDATE {binding} SET binding_generation = ?, namespace_id = ?, standard_namespace = ?, \
                 no_tablet_namespace = ?, checkpoint_id = ?, checkpoint_hash = ?, state_root = ?, \
                 dataset_digest = ?, updated_at_unix_ms = ? \
                 WHERE network_id = ? AND authority_kind = ? AND authority_id = ? \
                 IF binding_generation = ? AND namespace_id = ? AND standard_namespace = ? AND no_tablet_namespace = ? \
                 AND checkpoint_id = ? AND checkpoint_hash = ? AND state_root = ? AND dataset_digest = ?"
            ),
        }
    }

    pub fn create_catalog(&self) -> &str {
        &self.create_catalog
    }

    pub fn create_binding(&self) -> &str {
        &self.create_binding
    }

    pub fn insert_catalog_if_absent(&self) -> &str {
        &self.insert_catalog_if_absent
    }

    pub fn select_catalog(&self) -> &str {
        &self.select_catalog
    }

    pub fn transition_catalog_status(&self) -> &str {
        &self.transition_catalog_status
    }

    pub fn insert_binding_if_absent(&self) -> &str {
        &self.insert_binding_if_absent
    }

    pub fn select_binding(&self) -> &str {
        &self.select_binding
    }

    pub fn cutover_binding(&self) -> &str {
        &self.cutover_binding
    }

    pub fn render_golden(&self) -> String {
        format!(
            "CREATE_CATALOG\n{}\nCREATE_BINDING\n{}\nINSERT_CATALOG_IF_ABSENT\n{}\nSELECT_CATALOG\n{}\nTRANSITION_CATALOG_STATUS\n{}\nINSERT_BINDING_IF_ABSENT\n{}\nSELECT_BINDING\n{}\nCUTOVER_BINDING\n{}\n",
            self.create_catalog,
            self.create_binding,
            self.insert_catalog_if_absent,
            self.select_catalog,
            self.transition_catalog_status,
            self.insert_binding_if_absent,
            self.select_binding,
            self.cutover_binding,
        )
    }
}

#[derive(scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct CatalogInsertValues {
    network_id: String,
    authority_kind: i8,
    authority_id: i64,
    namespace_id: Vec<u8>,
    standard_namespace: String,
    no_tablet_namespace: String,
    target_checkpoint_id: i64,
    target_checkpoint_hash: Vec<u8>,
    state_root: Vec<u8>,
    dataset_digest: Vec<u8>,
    checkpoint_leaf_rows: i64,
    global_user_merkle_rows: i64,
    no_tablet_counter_rows: i64,
    expected_generation: i64,
    status: i8,
    created_at_unix_ms: i64,
    verified_at_unix_ms: Option<i64>,
}

#[derive(scylla::DeserializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct CatalogDbRow {
    network_id: String,
    authority_kind: i8,
    authority_id: i64,
    namespace_id: Vec<u8>,
    standard_namespace: String,
    no_tablet_namespace: String,
    target_checkpoint_id: i64,
    target_checkpoint_hash: Vec<u8>,
    state_root: Vec<u8>,
    dataset_digest: Vec<u8>,
    checkpoint_leaf_rows: i64,
    global_user_merkle_rows: i64,
    no_tablet_counter_rows: i64,
    expected_generation: i64,
    status: i8,
    created_at_unix_ms: i64,
    verified_at_unix_ms: Option<i64>,
}

#[derive(scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct BindingCasValues {
    new_generation: i64,
    new_namespace_id: Vec<u8>,
    new_standard_namespace: String,
    new_no_tablet_namespace: String,
    new_checkpoint_id: i64,
    new_checkpoint_hash: Vec<u8>,
    new_state_root: Vec<u8>,
    new_dataset_digest: Vec<u8>,
    updated_at_unix_ms: i64,
    network_id: String,
    authority_kind: i8,
    authority_id: i64,
    expected_generation: i64,
    expected_namespace_id: Vec<u8>,
    expected_standard_namespace: String,
    expected_no_tablet_namespace: String,
    expected_checkpoint_id: i64,
    expected_checkpoint_hash: Vec<u8>,
    expected_state_root: Vec<u8>,
    expected_dataset_digest: Vec<u8>,
}

#[derive(scylla::DeserializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct BindingDbRow {
    network_id: String,
    authority_kind: i8,
    authority_id: i64,
    binding_generation: i64,
    namespace_id: Vec<u8>,
    standard_namespace: String,
    no_tablet_namespace: String,
    checkpoint_id: i64,
    checkpoint_hash: Vec<u8>,
    state_root: Vec<u8>,
    dataset_digest: Vec<u8>,
    updated_at_unix_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceCatalogSnapshot {
    descriptor: RecoveryNamespaceDescriptor,
    status: RecoveryNamespaceStatus,
    created_at_unix_ms: i64,
    verified_at_unix_ms: Option<i64>,
}

impl NamespaceCatalogSnapshot {
    pub fn descriptor(&self) -> &RecoveryNamespaceDescriptor {
        &self.descriptor
    }

    pub const fn status(&self) -> RecoveryNamespaceStatus {
        self.status
    }

    pub const fn created_at_unix_ms(&self) -> i64 {
        self.created_at_unix_ms
    }

    pub const fn verified_at_unix_ms(&self) -> Option<i64> {
        self.verified_at_unix_ms
    }
}

pub struct NamespaceControlAdapter {
    queries: NamespaceControlQueries,
    contract: NamespaceLwtContract,
    insert_catalog: PreparedStatement,
    select_catalog: PreparedStatement,
    transition_catalog_status: PreparedStatement,
    insert_binding: PreparedStatement,
    select_binding: PreparedStatement,
    cutover_binding: PreparedStatement,
}

impl NamespaceControlAdapter {
    pub async fn create_schema(
        session: &Session,
        control_keyspace: &CqlKeyspaceName,
    ) -> Result<(), NamespacePrototypeError> {
        create_rf3_keyspace(session, control_keyspace).await?;
        let queries = NamespaceControlQueries::new(control_keyspace);
        session
            .query_unpaged(queries.create_catalog(), &[])
            .await
            .map_err(cql_error)?;
        session
            .query_unpaged(queries.create_binding(), &[])
            .await
            .map_err(cql_error)?;
        session.await_schema_agreement().await.map_err(cql_error)?;
        Ok(())
    }

    pub async fn prepare(
        session: &Session,
        control_keyspace: CqlKeyspaceName,
    ) -> Result<Self, NamespacePrototypeError> {
        let contract = NamespaceLwtContract::rf3_default();
        let queries = NamespaceControlQueries::new(&control_keyspace);
        Ok(Self {
            insert_catalog: prepare_lwt(session, queries.insert_catalog_if_absent(), contract).await?,
            select_catalog: prepare_read(session, queries.select_catalog(), contract.regular()).await?,
            transition_catalog_status: prepare_lwt(session, queries.transition_catalog_status(), contract).await?,
            insert_binding: prepare_lwt(session, queries.insert_binding_if_absent(), contract).await?,
            select_binding: prepare_read(session, queries.select_binding(), contract.regular()).await?,
            cutover_binding: prepare_lwt(session, queries.cutover_binding(), contract).await?,
            queries,
            contract,
        })
    }

    pub const fn queries(&self) -> &NamespaceControlQueries {
        &self.queries
    }

    pub const fn lwt_contract(&self) -> NamespaceLwtContract {
        self.contract
    }

    pub fn prepared_lwt_contracts(&self) -> [(Option<Consistency>, Option<SerialConsistency>); 4] {
        [
            (self.insert_catalog.get_consistency(), self.insert_catalog.get_serial_consistency()),
            (
                self.transition_catalog_status.get_consistency(),
                self.transition_catalog_status.get_serial_consistency(),
            ),
            (self.insert_binding.get_consistency(), self.insert_binding.get_serial_consistency()),
            (self.cutover_binding.get_consistency(), self.cutover_binding.get_serial_consistency()),
        ]
    }

    pub async fn begin_loading(
        &self,
        session: &Session,
        descriptor: RecoveryNamespaceDescriptor,
        created_at_unix_ms: i64,
    ) -> Result<LoadingRecoveryNamespace, NamespacePrototypeError> {
        descriptor.validate_identity()?;
        let values = catalog_insert_values(&descriptor, created_at_unix_ms)?;
        session
            .execute_unpaged(&self.insert_catalog, values)
            .await
            .map_err(cql_error)?;
        let current = self
            .get_catalog(session, descriptor.intent().authority(), descriptor.namespace().id())
            .await?
            .ok_or(NamespacePrototypeError::CatalogMissingAfterWrite)?;
        if current.descriptor != descriptor {
            return Err(NamespacePrototypeError::CatalogIdentityConflict);
        }
        match current.status {
            RecoveryNamespaceStatus::Loading => Ok(LoadingRecoveryNamespace::new(descriptor)),
            RecoveryNamespaceStatus::Verified => Err(NamespacePrototypeError::CatalogAlreadyVerified),
            RecoveryNamespaceStatus::Failed => Err(NamespacePrototypeError::CatalogAlreadyFailed),
        }
    }

    pub async fn get_catalog(
        &self,
        session: &Session,
        authority: &StorageAuthority,
        namespace_id: RecoveryNamespaceId,
    ) -> Result<Option<NamespaceCatalogSnapshot>, NamespacePrototypeError> {
        let result = session
            .execute_unpaged(
                &self.select_catalog,
                (
                    authority.network_id(),
                    authority.kind().as_i8(),
                    to_i64("authority_id", authority.authority_id())?,
                    namespace_id.as_bytes().as_slice(),
                ),
            )
            .await
            .map_err(cql_error)?;
        let row = result
            .into_rows_result()
            .map_err(cql_error)?
            .maybe_first_row::<CatalogDbRow>()
            .map_err(cql_error)?;
        row.map(catalog_snapshot_from_db).transpose()
    }

    pub async fn get_verified(
        &self,
        session: &Session,
        authority: &StorageAuthority,
        namespace_id: RecoveryNamespaceId,
    ) -> Result<VerifiedRecoveryNamespace, NamespacePrototypeError> {
        let snapshot = self
            .get_catalog(session, authority, namespace_id)
            .await?
            .ok_or(NamespacePrototypeError::CatalogNotFound)?;
        if snapshot.status != RecoveryNamespaceStatus::Verified {
            return Err(NamespacePrototypeError::NamespaceNotVerified(snapshot.status));
        }
        let verified_at = snapshot
            .verified_at_unix_ms
            .ok_or(NamespacePrototypeError::VerifiedTimestampMissing)?;
        Ok(VerifiedRecoveryNamespace::new(snapshot.descriptor, verified_at))
    }

    async fn mark_verified(
        &self,
        session: &Session,
        loading: &LoadingRecoveryNamespace,
        verified_at_unix_ms: i64,
    ) -> Result<VerifiedRecoveryNamespace, NamespacePrototypeError> {
        self.transition_status(
            session,
            loading.descriptor(),
            RecoveryNamespaceStatus::Verified,
            Some(verified_at_unix_ms),
        )
        .await?;
        self.get_verified(
            session,
            loading.descriptor().intent().authority(),
            loading.descriptor().namespace().id(),
        )
        .await
    }

    pub async fn mark_failed(
        &self,
        session: &Session,
        loading: &LoadingRecoveryNamespace,
    ) -> Result<(), NamespacePrototypeError> {
        self.transition_status(
            session,
            loading.descriptor(),
            RecoveryNamespaceStatus::Failed,
            None,
        )
        .await
    }

    async fn transition_status(
        &self,
        session: &Session,
        descriptor: &RecoveryNamespaceDescriptor,
        desired: RecoveryNamespaceStatus,
        verified_at_unix_ms: Option<i64>,
    ) -> Result<(), NamespacePrototypeError> {
        let authority = descriptor.intent().authority();
        session
            .execute_unpaged(
                &self.transition_catalog_status,
                (
                    desired.as_i8(),
                    verified_at_unix_ms,
                    authority.network_id(),
                    authority.kind().as_i8(),
                    to_i64("authority_id", authority.authority_id())?,
                    descriptor.namespace().id().as_bytes().as_slice(),
                    RecoveryNamespaceStatus::Loading.as_i8(),
                ),
            )
            .await
            .map_err(cql_error)?;
        let current = self
            .get_catalog(session, authority, descriptor.namespace().id())
            .await?
            .ok_or(NamespacePrototypeError::CatalogNotFound)?;
        if current.descriptor != *descriptor {
            return Err(NamespacePrototypeError::CatalogIdentityConflict);
        }
        if current.status != desired {
            return Err(NamespacePrototypeError::CatalogTransitionConflict {
                expected: desired,
                actual: current.status,
            });
        }
        Ok(())
    }

    pub async fn initialize_binding(
        &self,
        session: &Session,
        verified: &VerifiedRecoveryNamespace,
        generation: BindingGeneration,
        updated_at_unix_ms: i64,
    ) -> Result<BindingInitializationOutcome, NamespacePrototypeError> {
        let descriptor = verified.descriptor();
        let authority = descriptor.intent().authority();
        self.require_durable_verified(session, verified).await?;
        if descriptor.intent().expected_generation() != generation {
            return Err(NamespacePrototypeError::ExpectedGenerationMismatch {
                descriptor: descriptor.intent().expected_generation().get(),
                binding: generation.get(),
            });
        }
        let desired = binding_from_descriptor(descriptor, generation, updated_at_unix_ms);
        session
            .execute_unpaged(
                &self.insert_binding,
                (
                    authority.network_id(),
                    authority.kind().as_i8(),
                    to_i64("authority_id", authority.authority_id())?,
                    to_i64("binding_generation", generation.get())?,
                    descriptor.namespace().id().as_bytes().as_slice(),
                    descriptor.namespace().standard().as_str(),
                    descriptor.namespace().no_tablet().as_str(),
                    to_i64("checkpoint_id", descriptor.intent().target_checkpoint().get())?,
                    descriptor.intent().target_checkpoint_hash().as_bytes().as_slice(),
                    descriptor.intent().state_root().as_bytes().as_slice(),
                    descriptor.intent().dataset_digest().as_bytes().as_slice(),
                    updated_at_unix_ms,
                ),
            )
            .await
            .map_err(cql_error)?;
        let current = self
            .get_binding(session, authority)
            .await?
            .ok_or(NamespacePrototypeError::BindingMissingAfterWrite)?;
        if binding_semantically_equal(&current, &desired) {
            Ok(BindingInitializationOutcome::InitializedOrAlreadyPresent(current))
        } else {
            Ok(BindingInitializationOutcome::Conflict(current))
        }
    }

    pub async fn get_binding(
        &self,
        session: &Session,
        authority: &StorageAuthority,
    ) -> Result<Option<AuthorityStorageBinding>, NamespacePrototypeError> {
        let result = session
            .execute_unpaged(
                &self.select_binding,
                (
                    authority.network_id(),
                    authority.kind().as_i8(),
                    to_i64("authority_id", authority.authority_id())?,
                ),
            )
            .await
            .map_err(cql_error)?;
        result
            .into_rows_result()
            .map_err(cql_error)?
            .maybe_first_row::<BindingDbRow>()
            .map_err(cql_error)?
            .map(binding_from_db)
            .transpose()
    }

    pub async fn cutover(
        &self,
        session: &Session,
        expected: &AuthorityStorageBinding,
        verified: &VerifiedRecoveryNamespace,
        updated_at_unix_ms: i64,
    ) -> Result<BindingCasOutcome, NamespacePrototypeError> {
        let descriptor = verified.descriptor();
        self.require_durable_verified(session, verified).await?;
        if descriptor.intent().authority() != expected.authority() {
            return Err(NamespacePrototypeError::AuthorityMismatch);
        }
        if descriptor.intent().expected_generation() != expected.generation() {
            return Err(NamespacePrototypeError::ExpectedGenerationMismatch {
                descriptor: descriptor.intent().expected_generation().get(),
                binding: expected.generation().get(),
            });
        }
        let next = expected.generation().checked_next()?;
        let desired = binding_from_descriptor(descriptor, next, updated_at_unix_ms);
        let values = binding_cas_values(expected, &desired)?;
        let execution = session.execute_unpaged(&self.cutover_binding, values).await;
        let current = self
            .get_binding(session, expected.authority())
            .await?
            .ok_or(NamespacePrototypeError::BindingNotFound)?;
        if binding_semantically_equal(&current, &desired) {
            return Ok(BindingCasOutcome::AppliedOrReconciled(current));
        }
        if let Err(error) = execution {
            return Err(cql_error(error));
        }
        Ok(BindingCasOutcome::Conflict(current))
    }

    async fn require_durable_verified(
        &self,
        session: &Session,
        provided: &VerifiedRecoveryNamespace,
    ) -> Result<(), NamespacePrototypeError> {
        let descriptor = provided.descriptor();
        let durable = self
            .get_verified(
                session,
                descriptor.intent().authority(),
                descriptor.namespace().id(),
            )
            .await?;
        if &durable != provided {
            return Err(NamespacePrototypeError::VerifiedCatalogMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BindingInitializationOutcome {
    InitializedOrAlreadyPresent(AuthorityStorageBinding),
    Conflict(AuthorityStorageBinding),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BindingCasOutcome {
    AppliedOrReconciled(AuthorityStorageBinding),
    Conflict(AuthorityStorageBinding),
}

impl BindingCasOutcome {
    pub fn current(&self) -> &AuthorityStorageBinding {
        match self {
            Self::AppliedOrReconciled(current) | Self::Conflict(current) => current,
        }
    }

    pub const fn was_applied_or_reconciled(&self) -> bool {
        matches!(self, Self::AppliedOrReconciled(_))
    }
}

pub struct RepresentativeNamespaceStore {
    namespace: AuthorityStorageNamespace,
    timestamp_adapter: TimestampPrototypeAdapter,
    counter_put: PreparedStatement,
    checkpoint_leaf_select_all: PreparedStatement,
    global_user_merkle_select_all: PreparedStatement,
    counter_select_all: PreparedStatement,
}

impl RepresentativeNamespaceStore {
    pub async fn create_schema(
        session: &Session,
        namespace: &AuthorityStorageNamespace,
    ) -> Result<(), NamespacePrototypeError> {
        create_rf3_keyspace(session, namespace.standard()).await?;
        create_rf3_keyspace(session, namespace.no_tablet()).await?;
        for cql in [
            format!(
                "CREATE TABLE IF NOT EXISTS {}.{CHECKPOINT_LEAF_TABLE} \
                 (obj_id bigint, value blob, PRIMARY KEY ((obj_id)))",
                namespace.standard().as_str()
            ),
            format!(
                "CREATE TABLE IF NOT EXISTS {}.{GLOBAL_USER_TREE_TABLE} \
                 (level tinyint, node_index bigint, checkpoint_id bigint, value blob, \
                 PRIMARY KEY ((level), node_index, checkpoint_id)) \
                 WITH CLUSTERING ORDER BY (node_index ASC, checkpoint_id DESC)",
                namespace.standard().as_str()
            ),
            format!(
                "CREATE TABLE IF NOT EXISTS {}.{COUNTER_TABLE} \
                 (obj_id bigint, value bigint, PRIMARY KEY ((obj_id)))",
                namespace.no_tablet().as_str()
            ),
        ] {
            session.query_unpaged(cql, &[]).await.map_err(cql_error)?;
        }
        session.await_schema_agreement().await.map_err(cql_error)?;
        Ok(())
    }

    pub async fn prepare(
        session: &Session,
        namespace: AuthorityStorageNamespace,
        consistency: Consistency,
    ) -> Result<Self, NamespacePrototypeError> {
        let timestamp_adapter =
            TimestampPrototypeAdapter::prepare_with_consistency(session, namespace.standard().clone(), consistency)
                .await
                .map_err(cql_error)?;
        let counter_put = prepare_read(
            session,
            &format!(
                "INSERT INTO {}.{COUNTER_TABLE} (obj_id, value) VALUES (?, ?) USING TIMESTAMP ?",
                namespace.no_tablet().as_str()
            ),
            consistency,
        )
        .await?;
        let checkpoint_leaf_select_all = prepare_read(
            session,
            &format!(
                "SELECT obj_id, value FROM {}.{CHECKPOINT_LEAF_TABLE}",
                namespace.standard().as_str()
            ),
            consistency,
        )
        .await?;
        let global_user_merkle_select_all = prepare_read(
            session,
            &format!(
                "SELECT level, node_index, checkpoint_id, value FROM {}.{GLOBAL_USER_TREE_TABLE}",
                namespace.standard().as_str()
            ),
            consistency,
        )
        .await?;
        let counter_select_all = prepare_read(
            session,
            &format!("SELECT obj_id, value FROM {}.{COUNTER_TABLE}", namespace.no_tablet().as_str()),
            consistency,
        )
        .await?;
        Ok(Self {
            namespace,
            timestamp_adapter,
            counter_put,
            checkpoint_leaf_select_all,
            global_user_merkle_select_all,
            counter_select_all,
        })
    }

    pub fn namespace(&self) -> &AuthorityStorageNamespace {
        &self.namespace
    }

    pub async fn load_checkpoint_leaves(
        &self,
        session: &Session,
        rows: &[CheckpointLeafSnapshotRow],
        timestamp: CommitWriteTimestampUs,
    ) -> Result<(), NamespacePrototypeError> {
        for row in rows {
            let sealed = seal_commit_put(
                LogicalMutation::Put {
                    key: TypedTableKey::CheckpointLeaf(row.checkpoint()),
                    value: MutationValue::PsyCanonicalBytes(row.value().to_vec()),
                },
                timestamp,
            )
            .map_err(|error| NamespacePrototypeError::TypedMutation(error.to_string()))?;
            self.timestamp_adapter
                .put_checkpoint_leaf(session, &sealed)
                .await
                .map_err(cql_error)?;
        }
        Ok(())
    }

    pub async fn load_global_user_merkle(
        &self,
        session: &Session,
        rows: &[GlobalUserMerkleSnapshotRow],
        timestamp: CommitWriteTimestampUs,
    ) -> Result<(), NamespacePrototypeError> {
        for row in rows {
            let sealed = seal_commit_put(
                LogicalMutation::Put {
                    key: TypedTableKey::GlobalUserMerkle {
                        node: row.node(),
                        checkpoint: row.checkpoint(),
                    },
                    value: MutationValue::PsyCanonicalBytes(row.value().to_vec()),
                },
                timestamp,
            )
            .map_err(|error| NamespacePrototypeError::TypedMutation(error.to_string()))?;
            self.timestamp_adapter
                .put_global_user_merkle(session, &sealed)
                .await
                .map_err(cql_error)?;
        }
        Ok(())
    }

    pub async fn load_no_tablet_counters(
        &self,
        session: &Session,
        rows: &[NoTabletCounterSnapshotRow],
        timestamp: CommitWriteTimestampUs,
    ) -> Result<(), NamespacePrototypeError> {
        for row in rows {
            session
                .execute_unpaged(
                    &self.counter_put,
                    (
                        to_i64("counter_obj_id", row.obj_id())?,
                        to_i64("counter_value", row.value())?,
                        timestamp.as_i64(),
                    ),
                )
                .await
                .map_err(cql_error)?;
        }
        Ok(())
    }

    pub async fn load_dataset(
        &self,
        session: &Session,
        loading: &LoadingRecoveryNamespace,
        dataset: &RepresentativeDataset,
        timestamp: CommitWriteTimestampUs,
    ) -> Result<(), NamespacePrototypeError> {
        require_dataset_matches_descriptor(loading.descriptor(), dataset)?;
        if loading.descriptor().namespace() != &self.namespace {
            return Err(NamespacePrototypeError::StoreNamespaceMismatch);
        }
        self.load_checkpoint_leaves(session, dataset.checkpoint_leaves(), timestamp)
            .await?;
        self.load_global_user_merkle(session, dataset.global_user_merkle(), timestamp)
            .await?;
        self.load_no_tablet_counters(session, dataset.no_tablet_counters(), timestamp)
            .await
    }

    pub async fn read_dataset(&self, session: &Session) -> Result<RepresentativeDataset, NamespacePrototypeError> {
        let mut leaves = Vec::new();
        let rows = session
            .execute_unpaged(&self.checkpoint_leaf_select_all, &[])
            .await
            .map_err(cql_error)?
            .into_rows_result()
            .map_err(cql_error)?;
        for row in rows.rows::<(i64, Vec<u8>)>().map_err(cql_error)? {
            let (checkpoint, stored) = row.map_err(cql_error)?;
            let checkpoint = CheckpointId::try_new(from_i64("checkpoint_id", checkpoint)?)?;
            let value = crate::compression::decompress(&stored).map_err(cql_error)?;
            leaves.push(CheckpointLeafSnapshotRow::try_new(checkpoint, value)?);
        }

        let mut merkle = Vec::new();
        let rows = session
            .execute_unpaged(&self.global_user_merkle_select_all, &[])
            .await
            .map_err(cql_error)?
            .into_rows_result()
            .map_err(cql_error)?;
        for row in rows.rows::<(i8, i64, i64, Vec<u8>)>().map_err(cql_error)? {
            let (level, node_index, checkpoint, value) = row.map_err(cql_error)?;
            if level < 0 {
                return Err(NamespacePrototypeError::NegativeCqlValue {
                    field: "level",
                    value: level as i64,
                });
            }
            let value: [u8; 32] = value
                .try_into()
                .map_err(|value: Vec<u8>| NamespacePrototypeError::InvalidMerkleValueLength(value.len()))?;
            merkle.push(GlobalUserMerkleSnapshotRow::new(
                MerkleNode::new(level as u8, NodeIndex::new(from_i64("node_index", node_index)?)),
                CheckpointId::try_new(from_i64("checkpoint_id", checkpoint)?)?,
                value,
            ));
        }

        let mut counters = Vec::new();
        let rows = session
            .execute_unpaged(&self.counter_select_all, &[])
            .await
            .map_err(cql_error)?
            .into_rows_result()
            .map_err(cql_error)?;
        for row in rows.rows::<(i64, i64)>().map_err(cql_error)? {
            let (obj_id, value) = row.map_err(cql_error)?;
            counters.push(NoTabletCounterSnapshotRow::try_new(
                from_i64("counter_obj_id", obj_id)?,
                from_i64("counter_value", value)?,
            )?);
        }
        RepresentativeDataset::try_new(leaves, merkle, counters).map_err(Into::into)
    }

    pub async fn verify_and_mark(
        &self,
        session: &Session,
        control: &NamespaceControlAdapter,
        loading: &LoadingRecoveryNamespace,
        expected: &RepresentativeDataset,
        verified_at_unix_ms: i64,
    ) -> Result<VerifiedRecoveryNamespace, NamespacePrototypeError> {
        require_dataset_matches_descriptor(loading.descriptor(), expected)?;
        if loading.descriptor().namespace() != &self.namespace {
            return Err(NamespacePrototypeError::StoreNamespaceMismatch);
        }
        let actual = match self.read_dataset(session).await {
            Ok(actual) => actual,
            Err(error) => {
                let _ = control.mark_failed(session, loading).await;
                return Err(error);
            }
        };
        if &actual != expected {
            control.mark_failed(session, loading).await?;
            return Err(NamespacePrototypeError::DatasetVerificationMismatch {
                expected_digest: expected.digest(),
                actual_digest: actual.digest(),
                expected_counts: expected.counts(),
                actual_counts: actual.counts(),
            });
        }
        control.mark_verified(session, loading, verified_at_unix_ms).await
    }
}

/// Immutable representative handle constructed from one durable binding. No
/// API exists to replace an individual table/keyspace member.
pub struct BoundAuthorityStore {
    binding: AuthorityStorageBinding,
    representative: RepresentativeNamespaceStore,
}

impl BoundAuthorityStore {
    pub async fn bind_active(
        session: &Session,
        control: &NamespaceControlAdapter,
        authority: &StorageAuthority,
        consistency: Consistency,
    ) -> Result<Self, NamespacePrototypeError> {
        let binding = control
            .get_binding(session, authority)
            .await?
            .ok_or(NamespacePrototypeError::BindingNotFound)?;
        let verified = control
            .get_verified(session, authority, binding.namespace().id())
            .await?;
        if !binding_matches_descriptor(&binding, verified.descriptor()) {
            return Err(NamespacePrototypeError::BindingCatalogMismatch);
        }
        let representative =
            RepresentativeNamespaceStore::prepare(session, binding.namespace().clone(), consistency).await?;
        Ok(Self {
            binding,
            representative,
        })
    }

    pub const fn binding(&self) -> &AuthorityStorageBinding {
        &self.binding
    }

    pub fn namespace(&self) -> &AuthorityStorageNamespace {
        self.representative.namespace()
    }

    pub async fn assert_serving_current(
        &self,
        session: &Session,
        control: &NamespaceControlAdapter,
    ) -> Result<(), NamespacePrototypeError> {
        let current = control
            .get_binding(session, self.binding.authority())
            .await?
            .ok_or(NamespacePrototypeError::BindingNotFound)?;
        if current == self.binding {
            Ok(())
        } else {
            Err(NamespacePrototypeError::StaleBoundStore {
                bound_generation: self.binding.generation().get(),
                current_generation: current.generation().get(),
            })
        }
    }

    pub async fn read_serving_dataset(
        &self,
        session: &Session,
        control: &NamespaceControlAdapter,
    ) -> Result<RepresentativeDataset, NamespacePrototypeError> {
        self.assert_serving_current(session, control).await?;
        self.representative.read_dataset(session).await
    }
}

async fn create_rf3_keyspace(
    session: &Session,
    keyspace: &CqlKeyspaceName,
) -> Result<(), NamespacePrototypeError> {
    session
        .query_unpaged(
            format!(
                "CREATE KEYSPACE IF NOT EXISTS {} WITH replication = \
                 {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}} \
                 AND tablets = {{'enabled': false}}",
                keyspace.as_str()
            ),
            &[],
        )
        .await
        .map_err(cql_error)?;
    Ok(())
}

async fn prepare_lwt(
    session: &Session,
    cql: &str,
    contract: NamespaceLwtContract,
) -> Result<PreparedStatement, NamespacePrototypeError> {
    let mut statement = session.prepare(cql).await.map_err(cql_error)?;
    statement.set_consistency(contract.regular());
    statement.set_serial_consistency(Some(contract.serial()));
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_read(
    session: &Session,
    cql: &str,
    consistency: Consistency,
) -> Result<PreparedStatement, NamespacePrototypeError> {
    let mut statement = session.prepare(cql).await.map_err(cql_error)?;
    statement.set_consistency(consistency);
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn catalog_insert_values(
    descriptor: &RecoveryNamespaceDescriptor,
    created_at_unix_ms: i64,
) -> Result<CatalogInsertValues, NamespacePrototypeError> {
    let intent = descriptor.intent();
    let authority = intent.authority();
    let counts = descriptor.row_counts();
    Ok(CatalogInsertValues {
        network_id: authority.network_id().to_owned(),
        authority_kind: authority.kind().as_i8(),
        authority_id: to_i64("authority_id", authority.authority_id())?,
        namespace_id: descriptor.namespace().id().as_bytes().to_vec(),
        standard_namespace: descriptor.namespace().standard().as_str().to_owned(),
        no_tablet_namespace: descriptor.namespace().no_tablet().as_str().to_owned(),
        target_checkpoint_id: to_i64("target_checkpoint_id", intent.target_checkpoint().get())?,
        target_checkpoint_hash: intent.target_checkpoint_hash().as_bytes().to_vec(),
        state_root: intent.state_root().as_bytes().to_vec(),
        dataset_digest: intent.dataset_digest().as_bytes().to_vec(),
        checkpoint_leaf_rows: to_i64("checkpoint_leaf_rows", counts.checkpoint_leaf())?,
        global_user_merkle_rows: to_i64("global_user_merkle_rows", counts.global_user_merkle())?,
        no_tablet_counter_rows: to_i64("no_tablet_counter_rows", counts.no_tablet_counter())?,
        expected_generation: to_i64("expected_generation", intent.expected_generation().get())?,
        status: RecoveryNamespaceStatus::Loading.as_i8(),
        created_at_unix_ms,
        verified_at_unix_ms: None,
    })
}

fn catalog_snapshot_from_db(row: CatalogDbRow) -> Result<NamespaceCatalogSnapshot, NamespacePrototypeError> {
    let authority = StorageAuthority::try_new(
        row.network_id,
        StorageAuthorityKind::try_from_i8(row.authority_kind)?,
        from_i64("authority_id", row.authority_id)?,
    )?;
    let namespace_id = RecoveryNamespaceId::from_bytes(array_32("namespace_id", row.namespace_id)?);
    let namespace = AuthorityStorageNamespace::validate_persisted_pair(
        namespace_id,
        row.standard_namespace,
        row.no_tablet_namespace,
    )?;
    let intent = RecoveryNamespaceIntent::new(
        authority,
        CheckpointId::try_new(from_i64("target_checkpoint_id", row.target_checkpoint_id)?)?,
        NamespaceCheckpointHash::new(array_32("target_checkpoint_hash", row.target_checkpoint_hash)?),
        RepresentativeDatasetDigest::new(array_32("dataset_digest", row.dataset_digest)?),
        RepresentativeStateRoot::new(array_32("state_root", row.state_root)?),
        BindingGeneration::try_new(from_i64("expected_generation", row.expected_generation)?)?,
    );
    let counts = RepresentativeRowCounts::try_new(
        from_i64("checkpoint_leaf_rows", row.checkpoint_leaf_rows)?,
        from_i64("global_user_merkle_rows", row.global_user_merkle_rows)?,
        from_i64("no_tablet_counter_rows", row.no_tablet_counter_rows)?,
    )?;
    let descriptor = RecoveryNamespaceDescriptor::from_persisted(intent, namespace, counts)?;
    Ok(NamespaceCatalogSnapshot {
        descriptor,
        status: RecoveryNamespaceStatus::try_from_i8(row.status)?,
        created_at_unix_ms: row.created_at_unix_ms,
        verified_at_unix_ms: row.verified_at_unix_ms,
    })
}

fn binding_from_db(row: BindingDbRow) -> Result<AuthorityStorageBinding, NamespacePrototypeError> {
    let authority = StorageAuthority::try_new(
        row.network_id,
        StorageAuthorityKind::try_from_i8(row.authority_kind)?,
        from_i64("authority_id", row.authority_id)?,
    )?;
    let namespace_id = RecoveryNamespaceId::from_bytes(array_32("namespace_id", row.namespace_id)?);
    let namespace = AuthorityStorageNamespace::validate_persisted_pair(
        namespace_id,
        row.standard_namespace,
        row.no_tablet_namespace,
    )?;
    Ok(AuthorityStorageBinding::new(
        authority,
        BindingGeneration::try_new(from_i64("binding_generation", row.binding_generation)?)?,
        namespace,
        CheckpointId::try_new(from_i64("checkpoint_id", row.checkpoint_id)?)?,
        NamespaceCheckpointHash::new(array_32("checkpoint_hash", row.checkpoint_hash)?),
        RepresentativeStateRoot::new(array_32("state_root", row.state_root)?),
        RepresentativeDatasetDigest::new(array_32("dataset_digest", row.dataset_digest)?),
        row.updated_at_unix_ms,
    ))
}

fn binding_from_descriptor(
    descriptor: &RecoveryNamespaceDescriptor,
    generation: BindingGeneration,
    updated_at_unix_ms: i64,
) -> AuthorityStorageBinding {
    let intent = descriptor.intent();
    AuthorityStorageBinding::new(
        intent.authority().clone(),
        generation,
        descriptor.namespace().clone(),
        intent.target_checkpoint(),
        intent.target_checkpoint_hash(),
        intent.state_root(),
        intent.dataset_digest(),
        updated_at_unix_ms,
    )
}

fn binding_cas_values(
    expected: &AuthorityStorageBinding,
    desired: &AuthorityStorageBinding,
) -> Result<BindingCasValues, NamespacePrototypeError> {
    Ok(BindingCasValues {
        new_generation: to_i64("new_generation", desired.generation().get())?,
        new_namespace_id: desired.namespace().id().as_bytes().to_vec(),
        new_standard_namespace: desired.namespace().standard().as_str().to_owned(),
        new_no_tablet_namespace: desired.namespace().no_tablet().as_str().to_owned(),
        new_checkpoint_id: to_i64("new_checkpoint_id", desired.checkpoint().get())?,
        new_checkpoint_hash: desired.checkpoint_hash().as_bytes().to_vec(),
        new_state_root: desired.state_root().as_bytes().to_vec(),
        new_dataset_digest: desired.dataset_digest().as_bytes().to_vec(),
        updated_at_unix_ms: desired.updated_at_unix_ms(),
        network_id: expected.authority().network_id().to_owned(),
        authority_kind: expected.authority().kind().as_i8(),
        authority_id: to_i64("authority_id", expected.authority().authority_id())?,
        expected_generation: to_i64("expected_generation", expected.generation().get())?,
        expected_namespace_id: expected.namespace().id().as_bytes().to_vec(),
        expected_standard_namespace: expected.namespace().standard().as_str().to_owned(),
        expected_no_tablet_namespace: expected.namespace().no_tablet().as_str().to_owned(),
        expected_checkpoint_id: to_i64("expected_checkpoint_id", expected.checkpoint().get())?,
        expected_checkpoint_hash: expected.checkpoint_hash().as_bytes().to_vec(),
        expected_state_root: expected.state_root().as_bytes().to_vec(),
        expected_dataset_digest: expected.dataset_digest().as_bytes().to_vec(),
    })
}

fn binding_semantically_equal(left: &AuthorityStorageBinding, right: &AuthorityStorageBinding) -> bool {
    left.authority() == right.authority()
        && left.generation() == right.generation()
        && left.namespace() == right.namespace()
        && left.checkpoint() == right.checkpoint()
        && left.checkpoint_hash() == right.checkpoint_hash()
        && left.state_root() == right.state_root()
        && left.dataset_digest() == right.dataset_digest()
}

fn binding_matches_descriptor(
    binding: &AuthorityStorageBinding,
    descriptor: &RecoveryNamespaceDescriptor,
) -> bool {
    binding.authority() == descriptor.intent().authority()
        && binding.namespace() == descriptor.namespace()
        && binding.checkpoint() == descriptor.intent().target_checkpoint()
        && binding.checkpoint_hash() == descriptor.intent().target_checkpoint_hash()
        && binding.state_root() == descriptor.intent().state_root()
        && binding.dataset_digest() == descriptor.intent().dataset_digest()
}

fn require_dataset_matches_descriptor(
    descriptor: &RecoveryNamespaceDescriptor,
    dataset: &RepresentativeDataset,
) -> Result<(), NamespacePrototypeError> {
    if descriptor.intent().dataset_digest() != dataset.digest()
        || descriptor.intent().state_root() != dataset.state_root()
        || descriptor.row_counts() != dataset.counts()
    {
        return Err(NamespacePrototypeError::DatasetDoesNotMatchCatalogIntent);
    }
    Ok(())
}

fn array_32(field: &'static str, value: Vec<u8>) -> Result<[u8; 32], NamespacePrototypeError> {
    let actual = value.len();
    value
        .try_into()
        .map_err(|_| NamespacePrototypeError::InvalidDigestLength { field, actual })
}

fn to_i64(field: &'static str, value: u64) -> Result<i64, NamespacePrototypeError> {
    i64::try_from(value).map_err(|_| NamespacePrototypeError::IntegerOutOfCqlRange { field, value })
}

fn from_i64(field: &'static str, value: i64) -> Result<u64, NamespacePrototypeError> {
    u64::try_from(value).map_err(|_| NamespacePrototypeError::NegativeCqlValue { field, value })
}

fn cql_error(error: impl fmt::Display) -> NamespacePrototypeError {
    NamespacePrototypeError::Cql(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NamespacePrototypeError {
    Model(NamespaceModelError),
    Cql(String),
    TypedMutation(String),
    CatalogMissingAfterWrite,
    CatalogNotFound,
    CatalogIdentityConflict,
    CatalogAlreadyVerified,
    CatalogAlreadyFailed,
    CatalogTransitionConflict {
        expected: RecoveryNamespaceStatus,
        actual: RecoveryNamespaceStatus,
    },
    NamespaceNotVerified(RecoveryNamespaceStatus),
    VerifiedTimestampMissing,
    VerifiedCatalogMismatch,
    BindingMissingAfterWrite,
    BindingNotFound,
    BindingCatalogMismatch,
    AuthorityMismatch,
    ExpectedGenerationMismatch {
        descriptor: u64,
        binding: u64,
    },
    StoreNamespaceMismatch,
    DatasetDoesNotMatchCatalogIntent,
    DatasetVerificationMismatch {
        expected_digest: RepresentativeDatasetDigest,
        actual_digest: RepresentativeDatasetDigest,
        expected_counts: RepresentativeRowCounts,
        actual_counts: RepresentativeRowCounts,
    },
    StaleBoundStore {
        bound_generation: u64,
        current_generation: u64,
    },
    InvalidDigestLength {
        field: &'static str,
        actual: usize,
    },
    InvalidMerkleValueLength(usize),
    IntegerOutOfCqlRange {
        field: &'static str,
        value: u64,
    },
    NegativeCqlValue {
        field: &'static str,
        value: i64,
    },
}

impl fmt::Display for NamespacePrototypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Model(error) => error.fmt(f),
            Self::Cql(error) => write!(f, "Scylla namespace prototype failed: {error}"),
            Self::TypedMutation(error) => write!(f, "typed representative mutation failed: {error}"),
            Self::CatalogMissingAfterWrite => write!(f, "catalog row missing after IF NOT EXISTS"),
            Self::CatalogNotFound => write!(f, "recovery namespace catalog row not found"),
            Self::CatalogIdentityConflict => write!(f, "namespace ID already belongs to different immutable catalog content"),
            Self::CatalogAlreadyVerified => write!(f, "recovery namespace is already VERIFIED"),
            Self::CatalogAlreadyFailed => write!(f, "recovery namespace is already FAILED"),
            Self::CatalogTransitionConflict { expected, actual } => {
                write!(f, "catalog transition expected {expected:?}, durable status is {actual:?}")
            }
            Self::NamespaceNotVerified(status) => write!(f, "namespace cannot cut over while catalog status is {status:?}"),
            Self::VerifiedTimestampMissing => write!(f, "VERIFIED catalog row has no verified timestamp"),
            Self::VerifiedCatalogMismatch => {
                write!(f, "provided VERIFIED namespace does not match this control catalog")
            }
            Self::BindingMissingAfterWrite => write!(f, "active binding row missing after IF NOT EXISTS"),
            Self::BindingNotFound => write!(f, "authority active binding row not found"),
            Self::BindingCatalogMismatch => write!(f, "active binding does not match its immutable VERIFIED catalog descriptor"),
            Self::AuthorityMismatch => write!(f, "verified namespace and expected binding belong to different authorities"),
            Self::ExpectedGenerationMismatch { descriptor, binding } => write!(
                f,
                "namespace was derived for expected generation {descriptor}, but binding is at {binding}"
            ),
            Self::StoreNamespaceMismatch => write!(f, "representative store handle and loading descriptor use different namespaces"),
            Self::DatasetDoesNotMatchCatalogIntent => write!(f, "dataset digest/root/counts do not match the immutable catalog intent"),
            Self::DatasetVerificationMismatch {
                expected_digest,
                actual_digest,
                expected_counts,
                actual_counts,
            } => write!(
                f,
                "read-back verification mismatch: digest {:?}!={:?}, counts {:?}!={:?}",
                expected_digest, actual_digest, expected_counts, actual_counts
            ),
            Self::StaleBoundStore {
                bound_generation,
                current_generation,
            } => write!(
                f,
                "bound store generation {bound_generation} is stale; durable active generation is {current_generation}"
            ),
            Self::InvalidDigestLength { field, actual } => write!(f, "{field} must be 32 bytes, got {actual}"),
            Self::InvalidMerkleValueLength(actual) => write!(f, "Merkle representative value must be 32 bytes, got {actual}"),
            Self::IntegerOutOfCqlRange { field, value } => write!(f, "{field}={value} exceeds CQL BIGINT"),
            Self::NegativeCqlValue { field, value } => write!(f, "{field} unexpectedly contains negative CQL value {value}"),
        }
    }
}

impl Error for NamespacePrototypeError {}

impl From<NamespaceModelError> for NamespacePrototypeError {
    fn from(value: NamespaceModelError) -> Self {
        Self::Model(value)
    }
}

impl From<psy_node_core::store::typed::CheckpointIdOutOfRange> for NamespacePrototypeError {
    fn from(value: psy_node_core::store::typed::CheckpointIdOutOfRange) -> Self {
        Self::Model(value.into())
    }
}
