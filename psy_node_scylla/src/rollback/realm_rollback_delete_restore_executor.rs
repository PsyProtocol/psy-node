//! Realm hot-suffix deletion and exact target restoration.
//!
//! The executor is available only after the global archive barrier has moved
//! the Coordinator head to `DELETING`.  Its row set, target, and timestamps
//! are selected from that storage-private authority plus immutable Realm
//! inventory/archive state.  It never publishes a Realm or Coordinator head;
//! that remains a later all-participant barrier operation.

#![allow(dead_code)]

use std::{collections::BTreeMap, error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{canonical_chain::CanonicalChainRef, chain_context::AuthorityScope};
use psy_node_core::store::{
    authority_local_head::AuthorityLocalHeadReadState,
    branch_exact_dual_write::BranchExactDualWriteMutationKind,
    canonical_head::CanonicalHeadReadState,
    rollback_participant_plan::RollbackRealmParticipant,
    typed::{CheckpointId, LogicalMutation, MutationOperation, TypedTableKey},
};
use scylla::{
    client::session::Session,
    statement::{prepared::PreparedStatement, Consistency},
};
use sha2::{Digest, Sha256};
use strum::IntoEnumIterator;
use uuid::Uuid;

use super::{
    coordinator_commit_physical_archive_store::CoordinatorCommitPhysicalReadBinding,
    physical_descriptor, seal_new_branch_put, CqlKeyspaceName,
    ResolvedScyllaKey, ScyllaAuthorityLocalHeadStore, ScyllaCanonicalHeadStore,
    ScyllaPhysicalTableId, ScyllaSchemaFamily, SealedTimestampedPut,
    realm_full_commit_scylla::RealmFullCommitScyllaExecutor,
    realm_rollback_physical_archive_owner::{
        RealmRollbackPhysicalArchiveOwnerError,
        ScyllaRealmRollbackPhysicalArchiveOwner,
        SelectedRealmRollbackPostBarrierArchive,
    },
    realm_rollback_physical_archive_store::{
        PersistedRealmRollbackDeleteCompletion,
        RealmRollbackPhysicalArchiveStoreError,
        ScyllaRealmRollbackPhysicalArchiveStore,
    },
    realm_rollback_physical_before_image::RealmRollbackPhysicalBeforeImage,
    realm_rollback_physical_catalog::{
        RealmRollbackPhysicalAction, RealmRollbackPhysicalCatalogEntry,
        RealmRollbackPhysicalKey, RealmRollbackTargetRestore,
    },
    rollback_global_archive_barrier::DeletingRollbackGlobalArchiveBarrier,
};

const POST_STATE_DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.realm-delete-restore-post-state.v1\0";

struct PreparedTypedDelete {
    statement: PreparedStatement,
}

struct RealmTypedDeleteAdapter {
    session: Arc<Session>,
    statements: BTreeMap<ScyllaPhysicalTableId, PreparedTypedDelete>,
}

struct PreparedNarrowDelete {
    delete: PreparedStatement,
    read: PreparedStatement,
}

struct RealmNarrowDeleteAdapter {
    session: Arc<Session>,
    statements: BTreeMap<BranchExactDualWriteMutationKind, PreparedNarrowDelete>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RealmTypedDeleteBinding {
    Common(CoordinatorCommitPhysicalReadBinding),
    ImtLeaf(i64, i64, i64, i64),
    ImtIndex(i64, i64, i16, Vec<u8>),
    ImtCursor(i64, i64),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RealmNarrowDeleteBinding {
    BigInt(i64),
    Uuid(Uuid),
    Object(i64, i64),
    BranchToPending(Vec<u8>, i64),
    PendingToBranch(i64, Vec<u8>),
}

/// Non-Clone exact post-state observation for one Realm.  It can later be
/// persisted as a delete completion but cannot publish either head.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct ExecutedRealmRollbackSuffix<Hash> {
    authority: AuthorityScope,
    target: CanonicalChainRef<Hash>,
    participant_plan_digest: [u8; 32],
    barrier_digest: [u8; 32],
    archive_completion_slot: [u8; 32],
    archive_completion_digest: [u8; 32],
    catalog_digest: [u8; 32],
    post_state_digest: [u8; 32],
    physical_delete_count: u64,
    restored_row_count: u64,
}

impl<Hash> ExecutedRealmRollbackSuffix<Hash> {
    pub(super) const fn authority(&self) -> AuthorityScope { self.authority }
    pub(super) const fn target(&self) -> &CanonicalChainRef<Hash> { &self.target }
    pub(super) const fn participant_plan_digest(&self) -> &[u8; 32] { &self.participant_plan_digest }
    pub(super) const fn barrier_digest(&self) -> &[u8; 32] { &self.barrier_digest }
    pub(super) const fn archive_completion_slot(&self) -> &[u8; 32] { &self.archive_completion_slot }
    pub(super) const fn archive_completion_digest(&self) -> &[u8; 32] { &self.archive_completion_digest }
    pub(super) const fn catalog_digest(&self) -> &[u8; 32] { &self.catalog_digest }
    pub(super) const fn post_state_digest(&self) -> &[u8; 32] { &self.post_state_digest }
    pub(super) const fn physical_delete_count(&self) -> u64 { self.physical_delete_count }
    pub(super) const fn restored_row_count(&self) -> u64 { self.restored_row_count }
}

pub(super) struct ScyllaRealmRollbackDeleteRestoreExecutor {
    session: Arc<Session>,
    canonical_head: Arc<ScyllaCanonicalHeadStore>,
    local_head: Arc<ScyllaAuthorityLocalHeadStore>,
    archive_owner: ScyllaRealmRollbackPhysicalArchiveOwner,
    archive: ScyllaRealmRollbackPhysicalArchiveStore,
    typed: RealmFullCommitScyllaExecutor,
    typed_delete: RealmTypedDeleteAdapter,
    narrow_delete: RealmNarrowDeleteAdapter,
}

impl ScyllaRealmRollbackDeleteRestoreExecutor {
    pub(super) async fn prepare(
        session: Arc<Session>,
        canonical_head: Arc<ScyllaCanonicalHeadStore>,
        local_head: Arc<ScyllaAuthorityLocalHeadStore>,
        archive_owner: ScyllaRealmRollbackPhysicalArchiveOwner,
        source_keyspace: CqlKeyspaceName,
        archive_keyspace: CqlKeyspaceName,
    ) -> Result<Self, RealmRollbackDeleteRestoreExecutorError> {
        let typed = RealmFullCommitScyllaExecutor::prepare_with_consistency(
            &session,
            source_keyspace.clone(),
            Consistency::Quorum,
        ).await.map_err(backend)?;
        Ok(Self {
            archive: ScyllaRealmRollbackPhysicalArchiveStore::prepare(
                session.clone(), archive_keyspace,
            ).await?,
            typed_delete: RealmTypedDeleteAdapter::prepare(
                session.clone(), &source_keyspace,
            ).await?,
            narrow_delete: RealmNarrowDeleteAdapter::prepare(
                session.clone(), &source_keyspace,
            ).await?,
            session,
            canonical_head,
            local_head,
            archive_owner,
            typed,
        })
    }

    /// Execute/recover the fixed Realm mutation set, persist its immutable
    /// participant completion, then run the same storage-selected operation a
    /// second time as a post-persist fence.  The result still cannot publish a
    /// Realm or Coordinator head.
    pub(super) async fn execute_and_persist<Hash: Q256BitHash>(
        &mut self,
        authority: &DeletingRollbackGlobalArchiveBarrier<Hash>,
        participant: RollbackRealmParticipant,
    ) -> Result<PersistedRealmRollbackDeleteCompletion<Hash>, RealmRollbackDeleteRestoreExecutorError> {
        let first = self.execute(authority, participant).await?;
        let receipt = self.archive.persist_delete_completion(&first).await?;
        let second = self.execute(authority, participant).await?;
        if first != second {
            return Err(RealmRollbackDeleteRestoreExecutorError::PostStateChanged);
        }
        self.archive.revalidate_delete_completion(&receipt).await?;
        Ok(receipt)
    }

    pub(super) async fn execute<Hash: Q256BitHash>(
        &mut self,
        authority: &DeletingRollbackGlobalArchiveBarrier<Hash>,
        participant: RollbackRealmParticipant,
    ) -> Result<ExecutedRealmRollbackSuffix<Hash>, RealmRollbackDeleteRestoreExecutorError> {
        let plan = authority.participant_plan();
        if !plan.realms().contains(&participant) {
            return Err(RealmRollbackDeleteRestoreExecutorError::ParticipantNotPlanned);
        }
        let realm = AuthorityScope::Realm {
            realm_id: participant.realm_id(),
            realm_sub_id: participant.realm_sub_id(),
        };
        self.require_deleting_head(authority).await?;
        let selected = self.archive_owner
            .select_post_barrier_archive(
                plan.target().network_id(), realm, plan,
            ).await?;
        self.validate_selection(authority, realm, &selected)?;
        self.require_local_head(selected.completion().completion().source_head()).await?;

        let delete_fence = plan.fence_window().delete_fence().as_i64();
        let target_checkpoint = CheckpointId::try_new(
            plan.target().checkpoint().checkpoint_id().get(),
        ).map_err(|_| RealmRollbackDeleteRestoreExecutorError::TargetCheckpointOutOfRange)?;
        let new_branch = plan.fence_window().new_branch_write();
        for entry in selected.catalog().entries() {
            let image = self.read_image(authority, &selected, entry).await?;
            if image.source().writetime_us() >= delete_fence {
                return Err(RealmRollbackDeleteRestoreExecutorError::FenceNotAfterSource);
            }
            if entry.action() == RealmRollbackPhysicalAction::ArchiveThenRestoreTarget
                && self
                    .is_restored_image(entry, target_checkpoint, new_branch)
                    .await
            {
                continue;
            }
            self.delete_image(entry, &image, delete_fence).await?;
        }
        self.require_deleting_head(authority).await?;
        self.require_local_head(selected.completion().completion().source_head()).await?;

        for entry in selected.catalog().entries() {
            if entry.action() != RealmRollbackPhysicalAction::ArchiveThenRestoreTarget {
                continue;
            }
            let image = self.read_image(authority, &selected, entry).await?;
            self.restore_image(entry, &image, target_checkpoint, new_branch).await?;
        }
        self.require_deleting_head(authority).await?;
        self.require_local_head(selected.completion().completion().source_head()).await?;

        // Full post-state pass.  This makes a successful result independent
        // of every individual driver response and catches a concurrent writer.
        for entry in selected.catalog().entries() {
            let image = self.read_image(authority, &selected, entry).await?;
            self.require_post_state(entry, &image, target_checkpoint, new_branch).await?;
        }
        let after = self.archive_owner
            .select_post_barrier_archive(plan.target().network_id(), realm, plan)
            .await?;
        self.validate_selection(authority, realm, &after)?;
        if after.catalog() != selected.catalog()
            || after.completion().completion()
                != selected.completion().completion()
        {
            return Err(RealmRollbackDeleteRestoreExecutorError::ArchiveChanged);
        }
        self.require_deleting_head(authority).await?;
        self.require_local_head(selected.completion().completion().source_head()).await?;

        let completion = selected.completion().completion();
        Ok(ExecutedRealmRollbackSuffix {
            authority: realm,
            target: *plan.target(),
            participant_plan_digest: *plan.digest(),
            barrier_digest: *authority.barrier().digest(),
            archive_completion_slot: *completion.slot(),
            archive_completion_digest: *completion.digest(),
            catalog_digest: *selected.catalog().digest(),
            post_state_digest: post_state_digest(
                authority.barrier().digest(),
                realm,
                selected.catalog().digest(),
                delete_fence,
                new_branch.as_commit_timestamp().as_i64(),
                selected.catalog().entries(),
            ),
            physical_delete_count: u64::try_from(selected.catalog().entries().len())
                .map_err(|_| RealmRollbackDeleteRestoreExecutorError::LengthOverflow)?,
            restored_row_count: selected.catalog().restore_count(),
        })
    }

    fn validate_selection<Hash: Q256BitHash>(
        &self,
        authority: &DeletingRollbackGlobalArchiveBarrier<Hash>,
        realm: AuthorityScope,
        selected: &SelectedRealmRollbackPostBarrierArchive<Hash>,
    ) -> Result<(), RealmRollbackDeleteRestoreExecutorError> {
        let completion = selected.completion().completion();
        let local_target = completion.target();
        let global_target = authority.barrier().target();
        if completion.authority() != realm
            || completion.participant_plan_digest()
                != authority.barrier().participant_plan_digest()
            || local_target.network_id() != global_target.network_id()
            || local_target.chain_epoch() != global_target.chain_epoch()
            || local_target.checkpoint().checkpoint_id()
                != global_target.checkpoint().checkpoint_id()
            || completion.catalog_digest() != selected.catalog().digest()
            || completion.archive_store_fingerprint() != self.archive.fingerprint()
            || completion.entry_count()
                != u64::try_from(selected.catalog().entries().len())
                    .map_err(|_| RealmRollbackDeleteRestoreExecutorError::LengthOverflow)?
            || completion.delete_count() != selected.catalog().delete_count()
            || completion.restore_count() != selected.catalog().restore_count()
        {
            return Err(RealmRollbackDeleteRestoreExecutorError::BindingMismatch);
        }
        Ok(())
    }

    async fn read_image<Hash: Q256BitHash>(
        &self,
        authority: &DeletingRollbackGlobalArchiveBarrier<Hash>,
        selected: &SelectedRealmRollbackPostBarrierArchive<Hash>,
        entry: &RealmRollbackPhysicalCatalogEntry,
    ) -> Result<RealmRollbackPhysicalBeforeImage<Hash>, RealmRollbackDeleteRestoreExecutorError> {
        Ok(self.archive.read_catalog_image(
            *authority.barrier().participant_plan_digest(),
            selected.catalog(),
            entry,
        ).await?)
    }

    async fn delete_image<Hash: Q256BitHash>(
        &self,
        entry: &RealmRollbackPhysicalCatalogEntry,
        image: &RealmRollbackPhysicalBeforeImage<Hash>,
        delete_fence: i64,
    ) -> Result<(), RealmRollbackDeleteRestoreExecutorError> {
        match entry.key() {
            RealmRollbackPhysicalKey::Typed(key) => {
                let current = entry.current_put()
                    .ok_or(RealmRollbackDeleteRestoreExecutorError::MissingCurrentPut)?;
                let execution = self.typed_delete.delete(key, delete_fence).await;
                let present = self.typed
                    .read_inventory_put_physical_optional(&self.session, current)
                    .await.map_err(backend);
                match (execution, present) {
                    (_, Ok(None)) => {}
                    (Ok(()), Ok(Some(_))) => {
                        return Err(RealmRollbackDeleteRestoreExecutorError::PostStateMismatch);
                    }
                    (Err(execute), Ok(Some(_))) => {
                        return Err(RealmRollbackDeleteRestoreExecutorError::Indeterminate(
                            execute.to_string(),
                        ));
                    }
                    (Err(execute), Err(read)) => {
                        return Err(RealmRollbackDeleteRestoreExecutorError::Indeterminate(
                            format!("execute={execute}; read={read}"),
                        ));
                    }
                    (Ok(()), Err(read)) => return Err(read),
                }
            }
            RealmRollbackPhysicalKey::Narrow { kind, primary_key, .. } => {
                self.narrow_delete.delete_and_require_absent(
                    *kind,
                    primary_key,
                    image.source().logical_value(),
                    delete_fence,
                ).await?;
            }
        }
        Ok(())
    }

    async fn restore_image<Hash: Q256BitHash>(
        &self,
        entry: &RealmRollbackPhysicalCatalogEntry,
        image: &RealmRollbackPhysicalBeforeImage<Hash>,
        target_checkpoint: CheckpointId,
        timestamp: psy_node_core::store::timestamp::NewBranchWriteTimestampUs,
    ) -> Result<(), RealmRollbackDeleteRestoreExecutorError> {
        let current = entry.current_put()
            .ok_or(RealmRollbackDeleteRestoreExecutorError::MissingCurrentPut)?;
        match entry.target_restore() {
            Some(RealmRollbackTargetRestore::ExactPut(target)) => {
                let resealed = reseal_target_put(target, timestamp)?;
                self.typed.restore_inventory_put_exact(
                    &self.session,
                    &resealed,
                    target_checkpoint,
                    image.source().logical_value(),
                ).await.map_err(backend)?;
            }
            Some(RealmRollbackTargetRestore::ImtCursorBefore(value)) => {
                self.typed.restore_imt_cursor_exact(
                    &self.session,
                    current,
                    target_checkpoint,
                    *value,
                    timestamp,
                ).await.map_err(backend)?;
            }
            None => return Err(RealmRollbackDeleteRestoreExecutorError::MissingTargetRestore),
        }
        Ok(())
    }

    /// A retry runs after target rows may already have been restored at the
    /// post-fence timestamp. The older delete fence cannot and must not erase
    /// those rows; recognize their exact typed state before attempting the
    /// suffix delete again.
    async fn is_restored_image(
        &self,
        entry: &RealmRollbackPhysicalCatalogEntry,
        target_checkpoint: CheckpointId,
        timestamp: psy_node_core::store::timestamp::NewBranchWriteTimestampUs,
    ) -> bool {
        let Some(current) = entry.current_put() else {
            return false;
        };
        match entry.target_restore() {
            Some(RealmRollbackTargetRestore::ExactPut(target)) => {
                let Ok(resealed) = reseal_target_put(target, timestamp) else {
                    return false;
                };
                self.typed
                    .read_inventory_put_physical_exact(&self.session, &resealed)
                    .await
                    .is_ok()
            }
            Some(RealmRollbackTargetRestore::ImtCursorBefore(value)) => self
                .typed
                .require_imt_cursor_exact(
                    &self.session,
                    current,
                    target_checkpoint,
                    *value,
                    timestamp,
                )
                .await
                .is_ok(),
            None => false,
        }
    }

    async fn require_post_state<Hash: Q256BitHash>(
        &self,
        entry: &RealmRollbackPhysicalCatalogEntry,
        image: &RealmRollbackPhysicalBeforeImage<Hash>,
        target_checkpoint: CheckpointId,
        timestamp: psy_node_core::store::timestamp::NewBranchWriteTimestampUs,
    ) -> Result<(), RealmRollbackDeleteRestoreExecutorError> {
        match entry.action() {
            RealmRollbackPhysicalAction::ArchiveThenDelete => match entry.key() {
                RealmRollbackPhysicalKey::Typed(_) => {
                    let current = entry.current_put()
                        .ok_or(RealmRollbackDeleteRestoreExecutorError::MissingCurrentPut)?;
                    if self.typed.read_inventory_put_physical_optional(
                        &self.session, current,
                    ).await.map_err(backend)?.is_some() {
                        return Err(RealmRollbackDeleteRestoreExecutorError::PostStateMismatch);
                    }
                }
                RealmRollbackPhysicalKey::Narrow { kind, primary_key, .. } => {
                    if self.narrow_delete.is_present(
                        *kind, primary_key, image.source().logical_value(),
                    ).await? {
                        return Err(RealmRollbackDeleteRestoreExecutorError::PostStateMismatch);
                    }
                }
            },
            RealmRollbackPhysicalAction::ArchiveThenRestoreTarget => {
                let current = entry.current_put()
                    .ok_or(RealmRollbackDeleteRestoreExecutorError::MissingCurrentPut)?;
                match entry.target_restore() {
                    Some(RealmRollbackTargetRestore::ExactPut(target)) => {
                        let resealed = reseal_target_put(target, timestamp)?;
                        self.typed.read_inventory_put_physical_exact(
                            &self.session, &resealed,
                        ).await.map_err(backend)?;
                    }
                    Some(RealmRollbackTargetRestore::ImtCursorBefore(value)) => {
                        self.typed.require_imt_cursor_exact(
                            &self.session,
                            current,
                            target_checkpoint,
                            *value,
                            timestamp,
                        ).await.map_err(backend)?;
                    }
                    None => return Err(RealmRollbackDeleteRestoreExecutorError::MissingTargetRestore),
                }
            }
        }
        Ok(())
    }

    async fn require_deleting_head<Hash: Q256BitHash>(
        &self,
        authority: &DeletingRollbackGlobalArchiveBarrier<Hash>,
    ) -> Result<(), RealmRollbackDeleteRestoreExecutorError> {
        match self.canonical_head
            .read(authority.deleting_head().canonical_ref().network_id())
            .await.map_err(backend)?
        {
            CanonicalHeadReadState::Current(current)
                if &current == authority.deleting_head() => Ok(()),
            CanonicalHeadReadState::Current(_) => Err(RealmRollbackDeleteRestoreExecutorError::HeadChanged),
            CanonicalHeadReadState::Uninitialized => Err(RealmRollbackDeleteRestoreExecutorError::HeadMissing),
        }
    }

    async fn require_local_head<Hash: Q256BitHash>(
        &self,
        expected: &psy_node_core::store::authority_local_head::StoredAuthorityLocalHead<Hash>,
    ) -> Result<(), RealmRollbackDeleteRestoreExecutorError> {
        match self.local_head.read(expected.head().key()).await.map_err(backend)? {
            AuthorityLocalHeadReadState::Current(current) if &current == expected => Ok(()),
            AuthorityLocalHeadReadState::Current(_) => Err(RealmRollbackDeleteRestoreExecutorError::LocalHeadChanged),
            AuthorityLocalHeadReadState::Uninitialized => Err(RealmRollbackDeleteRestoreExecutorError::LocalHeadMissing),
        }
    }
}

impl RealmTypedDeleteAdapter {
    async fn prepare(
        session: Arc<Session>,
        keyspace: &CqlKeyspaceName,
    ) -> Result<Self, RealmRollbackDeleteRestoreExecutorError> {
        let mut statements = BTreeMap::new();
        for table in ScyllaPhysicalTableId::iter() {
            let family = physical_descriptor(table).schema_family;
            if matches!(family, ScyllaSchemaFamily::Counter | ScyllaSchemaFamily::TagTree) {
                continue;
            }
            if let Ok(cql) = typed_delete_cql(keyspace, table, family) {
                statements.insert(table, PreparedTypedDelete {
                    statement: prepare(&session, &cql).await?,
                });
            }
        }
        Ok(Self { session, statements })
    }

    async fn delete(
        &self,
        key: &ResolvedScyllaKey,
        timestamp: i64,
    ) -> Result<(), RealmRollbackDeleteRestoreExecutorError> {
        let prepared = self.statements.get(&key.physical_table())
            .ok_or(RealmRollbackDeleteRestoreExecutorError::UnsupportedTypedKey)?;
        let binding = RealmTypedDeleteBinding::try_for_key(key)?;
        let result = match binding {
            RealmTypedDeleteBinding::Common(common) => match common {
                CoordinatorCommitPhysicalReadBinding::BigInt(value, _) => self.session.execute_unpaged(&prepared.statement, (timestamp, value)).await,
                CoordinatorCommitPhysicalReadBinding::Blob(value) => self.session.execute_unpaged(&prepared.statement, (timestamp, value)).await,
                CoordinatorCommitPhysicalReadBinding::Uuid(value) => self.session.execute_unpaged(&prepared.statement, (timestamp, value)).await,
                CoordinatorCommitPhysicalReadBinding::ObjectSingle(a, b) => self.session.execute_unpaged(&prepared.statement, (timestamp, a, b)).await,
                CoordinatorCommitPhysicalReadBinding::HashToMany(a, b) => self.session.execute_unpaged(&prepared.statement, (timestamp, a, b)).await,
                CoordinatorCommitPhysicalReadBinding::MerkleZero(a, b, c) => self.session.execute_unpaged(&prepared.statement, (timestamp, a, b, c)).await,
                CoordinatorCommitPhysicalReadBinding::MerkleSingle(a, b, c, d) => self.session.execute_unpaged(&prepared.statement, (timestamp, a, b, c, d)).await,
                CoordinatorCommitPhysicalReadBinding::MerkleDouble(a, b, c, d, e) => self.session.execute_unpaged(&prepared.statement, (timestamp, a, b, c, d, e)).await,
            },
            RealmTypedDeleteBinding::ImtLeaf(a, b, c, d) => self.session.execute_unpaged(&prepared.statement, (timestamp, a, b, c, d)).await,
            RealmTypedDeleteBinding::ImtIndex(a, b, c, d) => self.session.execute_unpaged(&prepared.statement, (timestamp, a, b, c, d)).await,
            RealmTypedDeleteBinding::ImtCursor(a, b) => self.session.execute_unpaged(&prepared.statement, (timestamp, a, b)).await,
        };
        result.map_err(cql)?;
        Ok(())
    }
}

impl RealmTypedDeleteBinding {
    fn try_for_key(key: &ResolvedScyllaKey) -> Result<Self, RealmRollbackDeleteRestoreExecutorError> {
        match key.typed_key() {
            TypedTableKey::ImtLeaf { tree, tree_sub, leaf, checkpoint } => Ok(Self::ImtLeaf(
                exact_i64(tree.get())?, exact_i64(tree_sub.get())?, exact_i64(leaf.get())?, exact_i64(checkpoint.get())?,
            )),
            TypedTableKey::ImtKeyIndex { tree, tree_sub, encoded_key } => Ok(Self::ImtIndex(
                exact_i64(tree.get())?, exact_i64(tree_sub.get())?, encoded_key.cql_bucket(), encoded_key.as_bytes().to_vec(),
            )),
            TypedTableKey::ImtCursor { tree, tree_sub } => Ok(Self::ImtCursor(
                exact_i64(tree.get())?, exact_i64(tree_sub.get())?,
            )),
            _ => Ok(Self::Common(
                CoordinatorCommitPhysicalReadBinding::try_for_key(key)
                    .map_err(|error| RealmRollbackDeleteRestoreExecutorError::Backend(error.to_string()))?,
            )),
        }
    }
}

impl RealmNarrowDeleteAdapter {
    async fn prepare(
        session: Arc<Session>,
        keyspace: &CqlKeyspaceName,
    ) -> Result<Self, RealmRollbackDeleteRestoreExecutorError> {
        let mut statements = BTreeMap::new();
        for kind in BranchExactDualWriteMutationKind::REALM {
            let (delete, read) = narrow_delete_cql(keyspace, kind);
            statements.insert(kind, PreparedNarrowDelete {
                delete: prepare(&session, &delete).await?,
                read: prepare(&session, &read).await?,
            });
        }
        Ok(Self { session, statements })
    }

    async fn delete_and_require_absent(
        &self,
        kind: BranchExactDualWriteMutationKind,
        primary_key: &[u8],
        logical_value: &[u8],
        timestamp: i64,
    ) -> Result<(), RealmRollbackDeleteRestoreExecutorError> {
        let prepared = self.prepared(kind)?;
        let binding = RealmNarrowDeleteBinding::try_new(kind, primary_key, logical_value)?;
        let execution = binding.execute(&self.session, &prepared.delete, Some(timestamp)).await;
        let present = self.is_present_binding(prepared, &binding).await;
        match (execution, present) {
            (_, Ok(false)) => Ok(()),
            (Ok(()), Ok(true)) => Err(RealmRollbackDeleteRestoreExecutorError::PostStateMismatch),
            (Err(execute), Ok(true)) => Err(RealmRollbackDeleteRestoreExecutorError::Indeterminate(execute)),
            (Err(execute), Err(read)) => Err(RealmRollbackDeleteRestoreExecutorError::Indeterminate(format!("execute={execute}; read={read}"))),
            (Ok(()), Err(read)) => Err(read),
        }
    }

    async fn is_present(
        &self,
        kind: BranchExactDualWriteMutationKind,
        primary_key: &[u8],
        logical_value: &[u8],
    ) -> Result<bool, RealmRollbackDeleteRestoreExecutorError> {
        let prepared = self.prepared(kind)?;
        let binding = RealmNarrowDeleteBinding::try_new(kind, primary_key, logical_value)?;
        self.is_present_binding(prepared, &binding).await
    }

    async fn is_present_binding(
        &self,
        prepared: &PreparedNarrowDelete,
        binding: &RealmNarrowDeleteBinding,
    ) -> Result<bool, RealmRollbackDeleteRestoreExecutorError> {
        let result = binding.execute_read(&self.session, &prepared.read).await?;
        Ok(result.into_rows_result().map_err(cql)?.rows_num() != 0)
    }

    fn prepared(&self, kind: BranchExactDualWriteMutationKind) -> Result<&PreparedNarrowDelete, RealmRollbackDeleteRestoreExecutorError> {
        self.statements.get(&kind).ok_or(RealmRollbackDeleteRestoreExecutorError::UnsupportedNarrowKey)
    }
}

impl RealmNarrowDeleteBinding {
    fn try_new(
        kind: BranchExactDualWriteMutationKind,
        primary_key: &[u8],
        logical_value: &[u8],
    ) -> Result<Self, RealmRollbackDeleteRestoreExecutorError> {
        use BranchExactDualWriteMutationKind as K;
        Ok(match kind {
            K::LegacyCheckpointToPending | K::LegacyPendingToCheckpoint
            | K::LegacyPendingToProc | K::TargetPendingRewardProof => {
                Self::BigInt(decode_i64(primary_key)?)
            }
            K::LegacyProcToPending => {
                let bytes: [u8; 16] = primary_key.try_into()
                    .map_err(|_| RealmRollbackDeleteRestoreExecutorError::InvalidNarrowKey)?;
                Self::Uuid(Uuid::from_bytes(bytes))
            }
            K::LegacyPendingRewardProof => {
                if primary_key.len() != 16 { return Err(RealmRollbackDeleteRestoreExecutorError::InvalidNarrowKey); }
                Self::Object(decode_i64(&primary_key[..8])?, decode_i64(&primary_key[8..])?)
            }
            K::TargetBranchToPending => {
                Self::BranchToPending(primary_key.to_vec(), decode_i64(logical_value)?)
            }
            K::TargetPendingToBranch => {
                Self::PendingToBranch(decode_i64(primary_key)?, logical_value.to_vec())
            }
        })
    }

    async fn execute(
        &self,
        session: &Session,
        statement: &PreparedStatement,
        timestamp: Option<i64>,
    ) -> Result<(), String> {
        let result = match (self, timestamp) {
            (Self::BigInt(a), Some(ts)) => session.execute_unpaged(statement, (ts, *a)).await,
            (Self::Uuid(a), Some(ts)) => session.execute_unpaged(statement, (ts, *a)).await,
            (Self::Object(a, b), Some(ts)) => session.execute_unpaged(statement, (ts, *a, *b)).await,
            (Self::BranchToPending(a, b), Some(ts)) => session.execute_unpaged(statement, (ts, a.as_slice(), *b)).await,
            (Self::PendingToBranch(a, b), Some(ts)) => session.execute_unpaged(statement, (ts, *a, b.as_slice())).await,
            _ => return Err("narrow delete is missing its timestamp".to_owned()),
        };
        result.map(|_| ()).map_err(|error| error.to_string())
    }

    async fn execute_read(
        &self,
        session: &Session,
        statement: &PreparedStatement,
    ) -> Result<scylla::response::query_result::QueryResult, RealmRollbackDeleteRestoreExecutorError> {
        match self {
            Self::BigInt(a) => session.execute_unpaged(statement, (*a,)).await,
            Self::Uuid(a) => session.execute_unpaged(statement, (*a,)).await,
            Self::Object(a, b) => session.execute_unpaged(statement, (*a, *b)).await,
            Self::BranchToPending(a, b) => session.execute_unpaged(statement, (a.as_slice(), *b)).await,
            Self::PendingToBranch(a, b) => session.execute_unpaged(statement, (*a, b.as_slice())).await,
        }.map_err(cql)
    }
}

fn typed_delete_cql(
    keyspace: &CqlKeyspaceName,
    table: ScyllaPhysicalTableId,
    family: ScyllaSchemaFamily,
) -> Result<String, RealmRollbackDeleteRestoreExecutorError> {
    let where_clause = match family {
        ScyllaSchemaFamily::Kiv | ScyllaSchemaFamily::Blob | ScyllaSchemaFamily::U64
        | ScyllaSchemaFamily::U64ToU128 | ScyllaSchemaFamily::U128ToU64 => "obj_id = ?",
        ScyllaSchemaFamily::ObjectSingle => "obj_id = ? AND checkpoint_id = ?",
        ScyllaSchemaFamily::HashToMany => "hash_id = ? AND value_u64 = ?",
        ScyllaSchemaFamily::MerkleZero => "level = ? AND node_index = ? AND checkpoint_id = ?",
        ScyllaSchemaFamily::MerkleSingle => "tree_id = ? AND level = ? AND node_index = ? AND checkpoint_id = ?",
        ScyllaSchemaFamily::MerkleDouble => "tree_id = ? AND tree_sub_id = ? AND level = ? AND node_index = ? AND checkpoint_id = ?",
        ScyllaSchemaFamily::ImtLeaf => "tree_id = ? AND tree_sub_id = ? AND leaf_index = ? AND checkpoint_id = ?",
        ScyllaSchemaFamily::ImtKeyIndex => "tree_id = ? AND tree_sub_id = ? AND key_bucket = ? AND encoded_key = ?",
        ScyllaSchemaFamily::ImtCursor => "tree_id = ? AND tree_sub_id = ?",
        ScyllaSchemaFamily::Counter | ScyllaSchemaFamily::TagTree => return Err(RealmRollbackDeleteRestoreExecutorError::UnsupportedTypedKey),
    };
    Ok(format!(
        "DELETE FROM {}.{} USING TIMESTAMP ? WHERE {where_clause}",
        keyspace.as_str(), physical_descriptor(table).physical_name,
    ))
}

fn narrow_delete_cql(
    keyspace: &CqlKeyspaceName,
    kind: BranchExactDualWriteMutationKind,
) -> (String, String) {
    use BranchExactDualWriteMutationKind as K;
    let table = format!("{}.{}", keyspace.as_str(), kind.table_name());
    let (select, where_clause) = match kind {
        K::LegacyCheckpointToPending | K::LegacyPendingToCheckpoint
        | K::LegacyPendingToProc => ("obj_id", "obj_id = ?"),
        K::LegacyProcToPending => ("obj_id", "obj_id = ?"),
        K::LegacyPendingRewardProof => ("obj_id, checkpoint_id", "obj_id = ? AND checkpoint_id = ?"),
        K::TargetBranchToPending => ("canonical_ref, pending_id", "canonical_ref = ? AND pending_id = ?"),
        K::TargetPendingToBranch => ("pending_id, canonical_ref", "pending_id = ? AND canonical_ref = ?"),
        K::TargetPendingRewardProof => ("pending_id", "pending_id = ?"),
    };
    (
        format!("DELETE FROM {table} USING TIMESTAMP ? WHERE {where_clause}"),
        format!("SELECT {select} FROM {table} WHERE {where_clause}"),
    )
}

fn reseal_target_put(
    target: &SealedTimestampedPut,
    timestamp: psy_node_core::store::timestamp::NewBranchWriteTimestampUs,
) -> Result<SealedTimestampedPut, RealmRollbackDeleteRestoreExecutorError> {
    let mutation = target.resolved().mutation();
    let MutationOperation::Put(value) = mutation.operation() else {
        return Err(RealmRollbackDeleteRestoreExecutorError::MissingTargetRestore);
    };
    Ok(seal_new_branch_put(
        LogicalMutation::Put { key: mutation.key().clone(), value: value.clone() },
        timestamp,
    ).map_err(|error| RealmRollbackDeleteRestoreExecutorError::Backend(error.to_string()))?)
}

fn post_state_digest(
    barrier_digest: &[u8; 32],
    authority: AuthorityScope,
    catalog_digest: &[u8; 32],
    delete_fence: i64,
    new_branch_write: i64,
    entries: &[RealmRollbackPhysicalCatalogEntry],
) -> [u8; 32] {
    let AuthorityScope::Realm { realm_id, realm_sub_id } = authority else { unreachable!() };
    let mut hasher = Sha256::new();
    hasher.update(POST_STATE_DIGEST_DOMAIN);
    hasher.update(barrier_digest);
    hasher.update(realm_id.to_be_bytes());
    hasher.update(realm_sub_id.to_be_bytes());
    hasher.update(catalog_digest);
    hasher.update(delete_fence.to_be_bytes());
    hasher.update(new_branch_write.to_be_bytes());
    hasher.update((entries.len() as u64).to_be_bytes());
    for entry in entries {
        hasher.update([entry.action() as u8]);
        hasher.update((entry.key().locator_bytes().len() as u64).to_be_bytes());
        hasher.update(entry.key().locator_bytes());
        match entry.target_restore() {
            None => hasher.update([0]),
            Some(RealmRollbackTargetRestore::ExactPut(put)) => {
                hasher.update([1]);
                hasher.update(put.intent_digest().as_bytes());
            }
            Some(RealmRollbackTargetRestore::ImtCursorBefore(value)) => {
                hasher.update([2]);
                hasher.update(value.to_be_bytes());
            }
        }
    }
    hasher.finalize().into()
}

async fn prepare(
    session: &Session,
    cql_text: &str,
) -> Result<PreparedStatement, RealmRollbackDeleteRestoreExecutorError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn exact_i64(value: u64) -> Result<i64, RealmRollbackDeleteRestoreExecutorError> {
    i64::try_from(value).map_err(|_| RealmRollbackDeleteRestoreExecutorError::IntegerOutOfCqlRange)
}

fn decode_i64(bytes: &[u8]) -> Result<i64, RealmRollbackDeleteRestoreExecutorError> {
    let bytes: [u8; 8] = bytes.try_into()
        .map_err(|_| RealmRollbackDeleteRestoreExecutorError::InvalidNarrowKey)?;
    Ok(i64::from_be_bytes(bytes))
}

fn backend(error: impl fmt::Display) -> RealmRollbackDeleteRestoreExecutorError {
    RealmRollbackDeleteRestoreExecutorError::Backend(error.to_string())
}

fn cql(error: impl fmt::Display) -> RealmRollbackDeleteRestoreExecutorError {
    RealmRollbackDeleteRestoreExecutorError::Cql(error.to_string())
}

#[derive(Debug)]
pub(super) enum RealmRollbackDeleteRestoreExecutorError {
    ParticipantNotPlanned,
    BindingMismatch,
    ArchiveChanged,
    FenceNotAfterSource,
    MissingCurrentPut,
    MissingTargetRestore,
    UnsupportedTypedKey,
    UnsupportedNarrowKey,
    InvalidNarrowKey,
    TargetCheckpointOutOfRange,
    IntegerOutOfCqlRange,
    PostStateMismatch,
    PostStateChanged,
    HeadMissing,
    HeadChanged,
    LocalHeadMissing,
    LocalHeadChanged,
    LengthOverflow,
    Indeterminate(String),
    Backend(String),
    Cql(String),
    ArchiveOwner(RealmRollbackPhysicalArchiveOwnerError),
    Archive(RealmRollbackPhysicalArchiveStoreError),
}

impl From<RealmRollbackPhysicalArchiveOwnerError> for RealmRollbackDeleteRestoreExecutorError {
    fn from(value: RealmRollbackPhysicalArchiveOwnerError) -> Self { Self::ArchiveOwner(value) }
}
impl From<RealmRollbackPhysicalArchiveStoreError> for RealmRollbackDeleteRestoreExecutorError {
    fn from(value: RealmRollbackPhysicalArchiveStoreError) -> Self { Self::Archive(value) }
}
impl fmt::Display for RealmRollbackDeleteRestoreExecutorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Realm delete/restore executor error: {self:?}")
    }
}
impl Error for RealmRollbackDeleteRestoreExecutorError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_delete_queries_are_exact_and_timestamped() {
        let keyspace = CqlKeyspaceName::try_new("rollback_test").unwrap();
        for (table, family, expected) in [
            (ScyllaPhysicalTableId::CheckpointLeaf, ScyllaSchemaFamily::Kiv, "obj_id = ?"),
            (ScyllaPhysicalTableId::UserLeaf, ScyllaSchemaFamily::ObjectSingle, "obj_id = ? AND checkpoint_id = ?"),
            (ScyllaPhysicalTableId::ImtLeaf, ScyllaSchemaFamily::ImtLeaf, "tree_id = ? AND tree_sub_id = ? AND leaf_index = ? AND checkpoint_id = ?"),
            (ScyllaPhysicalTableId::ImtKeyIndex, ScyllaSchemaFamily::ImtKeyIndex, "tree_id = ? AND tree_sub_id = ? AND key_bucket = ? AND encoded_key = ?"),
            (ScyllaPhysicalTableId::ImtNextAppendIndex, ScyllaSchemaFamily::ImtCursor, "tree_id = ? AND tree_sub_id = ?"),
        ] {
            let cql = typed_delete_cql(&keyspace, table, family).unwrap();
            assert!(cql.contains("DELETE FROM rollback_test."));
            assert!(cql.contains("USING TIMESTAMP ?"));
            assert!(cql.ends_with(expected));
        }
    }

    #[test]
    fn narrow_delete_queries_use_complete_primary_keys() {
        let keyspace = CqlKeyspaceName::try_new("rollback_test").unwrap();
        for kind in BranchExactDualWriteMutationKind::REALM {
            let (delete, read) = narrow_delete_cql(&keyspace, kind);
            assert!(delete.contains("USING TIMESTAMP ?"));
            assert!(read.starts_with("SELECT "));
            match kind {
                BranchExactDualWriteMutationKind::TargetBranchToPending => {
                    assert!(delete.contains("canonical_ref = ? AND pending_id = ?"));
                }
                BranchExactDualWriteMutationKind::TargetPendingToBranch => {
                    assert!(delete.contains("pending_id = ? AND canonical_ref = ?"));
                }
                BranchExactDualWriteMutationKind::LegacyPendingRewardProof => {
                    assert!(delete.contains("obj_id = ? AND checkpoint_id = ?"));
                }
                _ => {}
            }
        }
    }

    #[test]
    fn executor_has_no_head_publish_or_rotation_api() {
        let source = include_str!("realm_rollback_delete_restore_executor.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in ["publish_target", "complete_rollback(", "seal_rotation", "compare_and_set("] {
            assert!(!production.contains(forbidden), "forbidden {forbidden}");
        }
        assert!(production.contains("select_post_barrier_archive"));
        assert!(production.contains("delete_fence"));
        assert!(production.contains("new_branch_write"));
    }
}
