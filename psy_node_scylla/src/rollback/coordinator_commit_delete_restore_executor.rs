//! Coordinator hot-suffix deletion and target-singleton restoration.
//!
//! This is the first post-PONR physical executor.  Its only authority input is
//! the storage-private global-barrier receipt in `DELETING`; callers cannot
//! supply a row list, target value, timestamp, or physical table name.  Every
//! mutation uses the immutable plan's fixed timestamp fence and is followed by
//! an exact QUORUM read.  The operations are therefore restart-idempotent, but
//! any error after a mutation attempt must still be treated as
//! commit-indeterminate and retried through a freshly reconstructed owner.

#![allow(dead_code)]

use std::{collections::BTreeMap, error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::canonical_chain::CanonicalChainRef;
use psy_node_core::store::{
    canonical_head::{CanonicalHeadReadState, StoredCanonicalHead},
    typed::{LatestInfoSlot, TypedTableKey, U64SingletonSlot},
};
use scylla::{
    client::session::Session,
    statement::{prepared::PreparedStatement, Consistency},
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    coordinator_commit_delete_restore_plan::{
        CoordinatorCommitDeleteRestoreAction, CoordinatorCommitDeleteRestoreEntry,
    },
    coordinator_commit_delete_restore_plan_store::{
        CoordinatorCommitDeleteRestorePlanStoreError,
        ScyllaCoordinatorCommitDeleteRestorePlanStore,
    },
    coordinator_commit_physical_archive_store::{
        CoordinatorCommitPhysicalArchiveStoreError,
        CoordinatorCommitPhysicalReadBinding,
        ScyllaCoordinatorCommitPostBarrierArchiveReader,
    },
    coordinator_commit_target_restore::{
        CoordinatorCommitTargetRestoreError, CoordinatorCommitTargetRestorePayload,
    },
    coordinator_rollback_delete_completion_store::{
        CoordinatorRollbackDeleteCompletionStoreError,
        PersistedCoordinatorRollbackDeleteCompletion,
        ScyllaCoordinatorRollbackDeleteCompletionStore,
    },
    physical_descriptor, CqlKeyspaceName,
    ResolvedScyllaKey, ScyllaCanonicalHeadStore, ScyllaPhysicalTableId,
    ScyllaSchemaFamily,
};
use super::rollback_global_archive_barrier::DeletingRollbackGlobalArchiveBarrier;

const POST_STATE_DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.coordinator-delete-restore-post-state.v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
enum ObservedHotRow {
    Value { bytes: Vec<u8>, writetime_us: i64 },
    KeyOnly,
}

struct PreparedPhysicalMutation {
    family: ScyllaSchemaFamily,
    read: PreparedStatement,
    delete: PreparedStatement,
}

struct CoordinatorCommitDeleteRestoreAdapter {
    session: Arc<Session>,
    mutations: BTreeMap<ScyllaPhysicalTableId, PreparedPhysicalMutation>,
    restore_latest_l2: PreparedStatement,
    restore_latest_checkpoint: PreparedStatement,
}

/// In-memory, non-clone proof that this Coordinator participant has reached
/// the exact post-delete/post-restore state while the global control row stayed
/// in the same `DELETING` revision.  A later slice persists a participant
/// completion from this value; it cannot publish the target head itself.
#[derive(Debug)]
pub(super) struct ExecutedCoordinatorRollbackSuffix<Hash> {
    deleting_head: StoredCanonicalHead<Hash>,
    target: CanonicalChainRef<Hash>,
    participant_plan_digest: [u8; 32],
    barrier_digest: [u8; 32],
    delete_plan_store_fingerprint: [u8; 32],
    delete_plan_slot: [u8; 32],
    delete_plan_digest: [u8; 32],
    target_restore_digest: [u8; 32],
    post_state_digest: [u8; 32],
    physical_delete_count: u64,
    restored_singleton_count: u64,
}

impl<Hash> ExecutedCoordinatorRollbackSuffix<Hash> {
    pub(super) const fn deleting_head(&self) -> &StoredCanonicalHead<Hash> {
        &self.deleting_head
    }

    pub(super) const fn target(&self) -> &CanonicalChainRef<Hash> {
        &self.target
    }

    pub(super) const fn participant_plan_digest(&self) -> &[u8; 32] {
        &self.participant_plan_digest
    }

    pub(super) const fn barrier_digest(&self) -> &[u8; 32] {
        &self.barrier_digest
    }

    pub(super) const fn delete_plan_store_fingerprint(&self) -> &[u8; 32] {
        &self.delete_plan_store_fingerprint
    }

    pub(super) const fn delete_plan_slot(&self) -> &[u8; 32] {
        &self.delete_plan_slot
    }

    pub(super) const fn delete_plan_digest(&self) -> &[u8; 32] {
        &self.delete_plan_digest
    }

    pub(super) const fn target_restore_digest(&self) -> &[u8; 32] {
        &self.target_restore_digest
    }

    pub(super) const fn post_state_digest(&self) -> &[u8; 32] {
        &self.post_state_digest
    }

    pub(super) const fn physical_delete_count(&self) -> u64 {
        self.physical_delete_count
    }

    pub(super) const fn restored_singleton_count(&self) -> u64 {
        self.restored_singleton_count
    }
}

pub(super) struct ScyllaCoordinatorCommitDeleteRestoreExecutor {
    session: Arc<Session>,
    canonical_head: Arc<ScyllaCanonicalHeadStore>,
    archive_keyspace: CqlKeyspaceName,
    source_keyspace: CqlKeyspaceName,
}

impl ScyllaCoordinatorCommitDeleteRestoreExecutor {
    pub(super) fn new(
        session: Arc<Session>,
        canonical_head: Arc<ScyllaCanonicalHeadStore>,
        archive_keyspace: CqlKeyspaceName,
        source_keyspace: CqlKeyspaceName,
    ) -> Self {
        Self {
            session,
            canonical_head,
            archive_keyspace,
            source_keyspace,
        }
    }

    /// Execute or recover the exact physical mutation set, persist its
    /// immutable participant completion, then execute the same fixed-timestamp
    /// plan once more as an exact post-persist fence.  No head publication is
    /// available from this method.
    pub(super) async fn execute_and_persist<Hash: Q256BitHash>(
        &self,
        authority: DeletingRollbackGlobalArchiveBarrier<Hash>,
    ) -> Result<
        PersistedCoordinatorRollbackDeleteCompletion<Hash>,
        CoordinatorCommitDeleteRestoreExecutorError,
    > {
        let first = self.execute(&authority).await?;
        let store = ScyllaCoordinatorRollbackDeleteCompletionStore::prepare(
            self.session.clone(),
            &self.archive_keyspace,
        )
        .await?;
        let receipt = store.persist_or_recover(&first).await?;
        let second = self.execute(&authority).await?;
        if first.deleting_head != second.deleting_head
            || first.target != second.target
            || first.participant_plan_digest != second.participant_plan_digest
            || first.barrier_digest != second.barrier_digest
            || first.delete_plan_store_fingerprint
                != second.delete_plan_store_fingerprint
            || first.delete_plan_slot != second.delete_plan_slot
            || first.delete_plan_digest != second.delete_plan_digest
            || first.target_restore_digest != second.target_restore_digest
            || first.post_state_digest != second.post_state_digest
            || first.physical_delete_count != second.physical_delete_count
            || first.restored_singleton_count != second.restored_singleton_count
        {
            return Err(CoordinatorCommitDeleteRestoreExecutorError::PostStateChanged);
        }
        store.revalidate(&receipt).await?;
        Ok(receipt)
    }

    pub(super) async fn execute<Hash: Q256BitHash>(
        &self,
        authority: &DeletingRollbackGlobalArchiveBarrier<Hash>,
    ) -> Result<ExecutedCoordinatorRollbackSuffix<Hash>, CoordinatorCommitDeleteRestoreExecutorError>
    {
        let barrier = authority.barrier();
        let deleting_head = *authority.deleting_head();
        let plan_receipt = authority.delete_plan();
        let plan = plan_receipt.plan();
        if plan.archiving_head() != barrier.archiving_head()
            || plan.target() != barrier.target()
            || plan.pre_barrier_readiness_digest()
                != barrier.coordinator_readiness_digest()
            || plan.target_restore_slot()
                != barrier.coordinator_target_restore_slot()
            || plan.target_restore_digest()
                != barrier.coordinator_target_restore_digest()
        {
            return Err(CoordinatorCommitDeleteRestoreExecutorError::BindingMismatch);
        }
        self.require_deleting_head(&deleting_head).await?;
        let plan_store = ScyllaCoordinatorCommitDeleteRestorePlanStore::prepare(
            self.session.clone(),
            &self.archive_keyspace,
        )
        .await?;
        plan_store.revalidate(plan_receipt).await?;

        let archive_reader = ScyllaCoordinatorCommitPostBarrierArchiveReader::prepare(
            self.session.clone(),
            &self.archive_keyspace,
        )
        .await?;
        let target_restore = archive_reader
            .read_target_restore(
                barrier.archiving_head(),
                barrier.target(),
                plan.catalog_digest(),
                barrier.coordinator_target_restore_slot(),
                barrier.coordinator_target_restore_digest(),
            )
            .await?;
        if target_restore.participant_completion_slot()
            != barrier.coordinator_completion_slot()
            || target_restore.participant_completion_digest()
                != barrier.coordinator_completion_digest()
        {
            return Err(CoordinatorCommitDeleteRestoreExecutorError::BindingMismatch);
        }
        validate_target_restore(plan.target(), &target_restore)?;

        let adapter = CoordinatorCommitDeleteRestoreAdapter::prepare(
            self.session.clone(),
            &self.source_keyspace,
            plan.entries(),
        )
        .await?;
        let delete_fence = plan.fence_window().delete_fence().as_i64();
        for entry in plan.entries() {
            adapter.delete_and_readback(entry.key(), delete_fence).await?;
        }
        self.require_deleting_head(&deleting_head).await?;

        let new_branch_write = plan
            .fence_window()
            .new_branch_write()
            .as_commit_timestamp()
            .as_i64();
        for entry in plan.entries() {
            if entry.action()
                == CoordinatorCommitDeleteRestoreAction::RestoreTargetSingleton
            {
                adapter
                    .restore_and_readback(
                        entry.key(),
                        &target_restore,
                        new_branch_write,
                    )
                    .await?;
            }
        }
        self.require_deleting_head(&deleting_head).await?;

        // A full post-state pass makes a successful return independent of the
        // mutation response path and detects any concurrent/newer writer.
        for entry in plan.entries() {
            match entry.action() {
                CoordinatorCommitDeleteRestoreAction::DeleteHotRow => {
                    if adapter.read_current(entry.key()).await?.is_some() {
                        return Err(
                            CoordinatorCommitDeleteRestoreExecutorError::PostStateMismatch,
                        );
                    }
                }
                CoordinatorCommitDeleteRestoreAction::RestoreTargetSingleton => {
                    adapter
                        .require_restored(
                            entry.key(),
                            &target_restore,
                            new_branch_write,
                        )
                        .await?;
                }
            }
        }
        plan_store.revalidate(plan_receipt).await?;
        let target_restore_after = archive_reader
            .read_target_restore(
                barrier.archiving_head(),
                barrier.target(),
                plan.catalog_digest(),
                barrier.coordinator_target_restore_slot(),
                barrier.coordinator_target_restore_digest(),
            )
            .await?;
        if target_restore_after != target_restore {
            return Err(CoordinatorCommitDeleteRestoreExecutorError::TargetRestoreChanged);
        }
        self.require_deleting_head(&deleting_head).await?;

        let physical_delete_count = u64::try_from(plan.entries().len())
            .map_err(|_| CoordinatorCommitDeleteRestoreExecutorError::LengthOverflow)?;
        Ok(ExecutedCoordinatorRollbackSuffix {
            deleting_head,
            target: *barrier.target(),
            participant_plan_digest: *barrier.participant_plan_digest(),
            barrier_digest: *barrier.digest(),
            delete_plan_store_fingerprint: *plan_receipt.store_fingerprint(),
            delete_plan_slot: *plan_receipt.slot(),
            delete_plan_digest: *plan.digest(),
            target_restore_digest: *target_restore.digest(),
            post_state_digest: post_state_digest(
                barrier.digest(),
                plan.digest(),
                &target_restore,
                delete_fence,
                new_branch_write,
                plan.entries(),
            ),
            physical_delete_count,
            restored_singleton_count: plan.restore_count(),
        })
    }

    async fn require_deleting_head<Hash: Q256BitHash>(
        &self,
        expected: &StoredCanonicalHead<Hash>,
    ) -> Result<(), CoordinatorCommitDeleteRestoreExecutorError> {
        match self
            .canonical_head
            .read(expected.canonical_ref().network_id())
            .await
            .map_err(backend)?
        {
            CanonicalHeadReadState::Current(current) if &current == expected => Ok(()),
            CanonicalHeadReadState::Current(_) => {
                Err(CoordinatorCommitDeleteRestoreExecutorError::HeadChanged)
            }
            CanonicalHeadReadState::Uninitialized => {
                Err(CoordinatorCommitDeleteRestoreExecutorError::HeadMissing)
            }
        }
    }
}

impl CoordinatorCommitDeleteRestoreAdapter {
    async fn prepare(
        session: Arc<Session>,
        keyspace: &CqlKeyspaceName,
        entries: &[CoordinatorCommitDeleteRestoreEntry],
    ) -> Result<Self, CoordinatorCommitDeleteRestoreExecutorError> {
        let mut mutations = BTreeMap::new();
        for entry in entries {
            let key = entry.key();
            if mutations.contains_key(&key.physical_table()) {
                continue;
            }
            let read_spec = super::CoordinatorCommitPhysicalReadSpec::try_for_key(
                keyspace, key,
            )?;
            let binding = CoordinatorCommitPhysicalReadBinding::try_for_key(key)?;
            if read_spec.bind_shape() != binding.shape() {
                return Err(CoordinatorCommitDeleteRestoreExecutorError::BindingMismatch);
            }
            mutations.insert(
                key.physical_table(),
                PreparedPhysicalMutation {
                    family: key.schema_family(),
                    read: prepare_read(&session, read_spec.cql()).await?,
                    delete: prepare_write(&session, &delete_cql(keyspace, key)?).await?,
                },
            );
        }
        let latest_l2 = physical_descriptor(ScyllaPhysicalTableId::LatestInfo);
        let latest_checkpoint = physical_descriptor(ScyllaPhysicalTableId::U64Singleton);
        Ok(Self {
            restore_latest_l2: prepare_write(
                &session,
                &format!(
                    "INSERT INTO {}.{} (obj_id, value) VALUES (?, ?) USING TIMESTAMP ?",
                    keyspace.as_str(), latest_l2.physical_name,
                ),
            )
            .await?,
            restore_latest_checkpoint: prepare_write(
                &session,
                &format!(
                    "INSERT INTO {}.{} (obj_id, value) VALUES (?, ?) USING TIMESTAMP ?",
                    keyspace.as_str(), latest_checkpoint.physical_name,
                ),
            )
            .await?,
            session,
            mutations,
        })
    }

    async fn delete_and_readback(
        &self,
        key: &ResolvedScyllaKey,
        timestamp_us: i64,
    ) -> Result<(), CoordinatorCommitDeleteRestoreExecutorError> {
        let prepared = self.prepared(key)?;
        let binding = CoordinatorCommitPhysicalReadBinding::try_for_key(key)?;
        let execution = match binding {
            CoordinatorCommitPhysicalReadBinding::BigInt(value, _) => self
                .session
                .execute_unpaged(&prepared.delete, (timestamp_us, value))
                .await,
            CoordinatorCommitPhysicalReadBinding::Blob(value) => self
                .session
                .execute_unpaged(&prepared.delete, (timestamp_us, value))
                .await,
            CoordinatorCommitPhysicalReadBinding::Uuid(value) => self
                .session
                .execute_unpaged(&prepared.delete, (timestamp_us, value))
                .await,
            CoordinatorCommitPhysicalReadBinding::ObjectSingle(object, checkpoint) => self
                .session
                .execute_unpaged(
                    &prepared.delete,
                    (timestamp_us, object, checkpoint),
                )
                .await,
            CoordinatorCommitPhysicalReadBinding::HashToMany(hash, value) => self
                .session
                .execute_unpaged(&prepared.delete, (timestamp_us, hash, value))
                .await,
            CoordinatorCommitPhysicalReadBinding::MerkleZero(level, node, checkpoint) => self
                .session
                .execute_unpaged(
                    &prepared.delete,
                    (timestamp_us, level, node, checkpoint),
                )
                .await,
            CoordinatorCommitPhysicalReadBinding::MerkleSingle(
                tree,
                level,
                node,
                checkpoint,
            ) => self
                .session
                .execute_unpaged(
                    &prepared.delete,
                    (timestamp_us, tree, level, node, checkpoint),
                )
                .await,
            CoordinatorCommitPhysicalReadBinding::MerkleDouble(
                tree,
                tree_sub,
                level,
                node,
                checkpoint,
            ) => self
                .session
                .execute_unpaged(
                    &prepared.delete,
                    (timestamp_us, tree, tree_sub, level, node, checkpoint),
                )
                .await,
        };
        let current = self.read_current(key).await;
        match (execution, current) {
            (_, Ok(None)) => Ok(()),
            (Ok(_), Ok(Some(_))) => {
                Err(CoordinatorCommitDeleteRestoreExecutorError::PostStateMismatch)
            }
            (Err(execute), Ok(Some(_))) => Err(
                CoordinatorCommitDeleteRestoreExecutorError::Indeterminate(
                    execute.to_string(),
                ),
            ),
            (Err(execute), Err(read)) => Err(
                CoordinatorCommitDeleteRestoreExecutorError::Indeterminate(format!(
                    "execute={execute}; read={read}",
                )),
            ),
            (Ok(_), Err(read)) => Err(read),
        }
    }

    async fn restore_and_readback<Hash: Q256BitHash>(
        &self,
        key: &ResolvedScyllaKey,
        target: &CoordinatorCommitTargetRestorePayload<Hash>,
        timestamp_us: i64,
    ) -> Result<(), CoordinatorCommitDeleteRestoreExecutorError> {
        let execution = match key.typed_key() {
            TypedTableKey::LatestInfo(LatestInfoSlot::LatestL2BlockState) => self
                .session
                .execute_unpaged(
                    &self.restore_latest_l2,
                    (
                        i64::from(LatestInfoSlot::LatestL2BlockState as u8),
                        target.target_l2_stored_value(),
                        timestamp_us,
                    ),
                )
                .await,
            TypedTableKey::U64Singleton(U64SingletonSlot::LatestCheckpoint) => {
                let checkpoint = i64::try_from(target.latest_checkpoint()).map_err(|_| {
                    CoordinatorCommitDeleteRestoreExecutorError::IntegerOutOfCqlRange
                })?;
                self.session
                    .execute_unpaged(
                        &self.restore_latest_checkpoint,
                        (
                            i64::from(U64SingletonSlot::LatestCheckpoint as u8),
                            checkpoint,
                            timestamp_us,
                        ),
                    )
                    .await
            }
            _ => return Err(CoordinatorCommitDeleteRestoreExecutorError::RestoreSetMismatch),
        };
        let readback = self.require_restored(key, target, timestamp_us).await;
        match (execution, readback) {
            (_, Ok(())) => Ok(()),
            (Ok(_), Err(error)) => Err(error),
            (Err(execute), Err(read)) => Err(
                CoordinatorCommitDeleteRestoreExecutorError::Indeterminate(format!(
                    "execute={execute}; read={read}",
                )),
            ),
        }
    }

    async fn require_restored<Hash: Q256BitHash>(
        &self,
        key: &ResolvedScyllaKey,
        target: &CoordinatorCommitTargetRestorePayload<Hash>,
        timestamp_us: i64,
    ) -> Result<(), CoordinatorCommitDeleteRestoreExecutorError> {
        let expected = match key.typed_key() {
            TypedTableKey::LatestInfo(LatestInfoSlot::LatestL2BlockState) => {
                target.target_l2_stored_value().to_vec()
            }
            TypedTableKey::U64Singleton(U64SingletonSlot::LatestCheckpoint) => {
                let checkpoint = i64::try_from(target.latest_checkpoint()).map_err(|_| {
                    CoordinatorCommitDeleteRestoreExecutorError::IntegerOutOfCqlRange
                })?;
                checkpoint.to_be_bytes().to_vec()
            }
            _ => return Err(CoordinatorCommitDeleteRestoreExecutorError::RestoreSetMismatch),
        };
        match self.read_current(key).await? {
            Some(ObservedHotRow::Value { bytes, writetime_us })
                if bytes == expected && writetime_us == timestamp_us => Ok(()),
            _ => Err(CoordinatorCommitDeleteRestoreExecutorError::PostStateMismatch),
        }
    }

    async fn read_current(
        &self,
        key: &ResolvedScyllaKey,
    ) -> Result<Option<ObservedHotRow>, CoordinatorCommitDeleteRestoreExecutorError> {
        let prepared = self.prepared(key)?;
        let binding = CoordinatorCommitPhysicalReadBinding::try_for_key(key)?;
        if binding.family() != prepared.family {
            return Err(CoordinatorCommitDeleteRestoreExecutorError::BindingMismatch);
        }
        match binding {
            CoordinatorCommitPhysicalReadBinding::BigInt(value, _) => {
                self.read_bound(&prepared.read, (value,), prepared.family, None).await
            }
            CoordinatorCommitPhysicalReadBinding::Blob(value) => {
                self.read_bound(&prepared.read, (value,), prepared.family, None).await
            }
            CoordinatorCommitPhysicalReadBinding::Uuid(value) => {
                self.read_bound(&prepared.read, (value,), prepared.family, None).await
            }
            CoordinatorCommitPhysicalReadBinding::ObjectSingle(object, checkpoint) => self
                .read_bound(
                    &prepared.read,
                    (object, checkpoint),
                    prepared.family,
                    None,
                )
                .await,
            CoordinatorCommitPhysicalReadBinding::HashToMany(hash, value) => self
                .read_bound(&prepared.read, (hash, value), prepared.family, Some(value))
                .await,
            CoordinatorCommitPhysicalReadBinding::MerkleZero(level, node, checkpoint) => self
                .read_bound(
                    &prepared.read,
                    (level, node, checkpoint),
                    prepared.family,
                    None,
                )
                .await,
            CoordinatorCommitPhysicalReadBinding::MerkleSingle(
                tree,
                level,
                node,
                checkpoint,
            ) => self
                .read_bound(
                    &prepared.read,
                    (tree, level, node, checkpoint),
                    prepared.family,
                    None,
                )
                .await,
            CoordinatorCommitPhysicalReadBinding::MerkleDouble(
                tree,
                tree_sub,
                level,
                node,
                checkpoint,
            ) => self
                .read_bound(
                    &prepared.read,
                    (tree, tree_sub, level, node, checkpoint),
                    prepared.family,
                    None,
                )
                .await,
        }
    }

    async fn read_bound<V: scylla::serialize::row::SerializeRow>(
        &self,
        statement: &PreparedStatement,
        bind: V,
        family: ScyllaSchemaFamily,
        expected_key_only: Option<i64>,
    ) -> Result<Option<ObservedHotRow>, CoordinatorCommitDeleteRestoreExecutorError> {
        let rows = self
            .session
            .execute_unpaged(statement, bind)
            .await
            .map_err(cql)?
            .into_rows_result()
            .map_err(cql)?;
        use ScyllaSchemaFamily as F;
        match family {
            F::Kiv | F::Blob | F::ObjectSingle | F::MerkleZero | F::MerkleSingle
            | F::MerkleDouble => rows
                .maybe_first_row::<(Option<Vec<u8>>, Option<i64>)>()
                .map_err(cql)?
                .map(|(value, writetime)| {
                    Ok(ObservedHotRow::Value {
                        bytes: value.ok_or(
                            CoordinatorCommitDeleteRestoreExecutorError::MissingColumn,
                        )?,
                        writetime_us: writetime.ok_or(
                            CoordinatorCommitDeleteRestoreExecutorError::MissingColumn,
                        )?,
                    })
                })
                .transpose(),
            F::U64 | F::U128ToU64 => rows
                .maybe_first_row::<(Option<i64>, Option<i64>)>()
                .map_err(cql)?
                .map(|(value, writetime)| {
                    Ok(ObservedHotRow::Value {
                        bytes: value
                            .ok_or(CoordinatorCommitDeleteRestoreExecutorError::MissingColumn)?
                            .to_be_bytes()
                            .to_vec(),
                        writetime_us: writetime
                            .ok_or(CoordinatorCommitDeleteRestoreExecutorError::MissingColumn)?,
                    })
                })
                .transpose(),
            F::U64ToU128 => rows
                .maybe_first_row::<(Option<Uuid>, Option<i64>)>()
                .map_err(cql)?
                .map(|(value, writetime)| {
                    Ok(ObservedHotRow::Value {
                        bytes: value
                            .ok_or(CoordinatorCommitDeleteRestoreExecutorError::MissingColumn)?
                            .as_bytes()
                            .to_vec(),
                        writetime_us: writetime
                            .ok_or(CoordinatorCommitDeleteRestoreExecutorError::MissingColumn)?,
                    })
                })
                .transpose(),
            F::HashToMany => rows
                .maybe_first_row::<(Option<i64>,)>()
                .map_err(cql)?
                .map(|(value,)| {
                    if value != expected_key_only {
                        Err(CoordinatorCommitDeleteRestoreExecutorError::PostStateMismatch)
                    } else {
                        Ok(ObservedHotRow::KeyOnly)
                    }
                })
                .transpose(),
            F::Counter | F::TagTree | F::ImtLeaf | F::ImtKeyIndex | F::ImtCursor => {
                Err(CoordinatorCommitDeleteRestoreExecutorError::UnsupportedFamily)
            }
        }
    }

    fn prepared(
        &self,
        key: &ResolvedScyllaKey,
    ) -> Result<&PreparedPhysicalMutation, CoordinatorCommitDeleteRestoreExecutorError> {
        self.mutations
            .get(&key.physical_table())
            .ok_or(CoordinatorCommitDeleteRestoreExecutorError::MissingPreparedMutation)
    }
}

fn delete_cql(
    keyspace: &CqlKeyspaceName,
    key: &ResolvedScyllaKey,
) -> Result<String, CoordinatorCommitDeleteRestoreExecutorError> {
    let table = physical_descriptor(key.physical_table()).physical_name;
    let where_clause = match key.schema_family() {
        ScyllaSchemaFamily::Kiv
        | ScyllaSchemaFamily::Blob
        | ScyllaSchemaFamily::U64
        | ScyllaSchemaFamily::U64ToU128
        | ScyllaSchemaFamily::U128ToU64 => "obj_id = ?",
        ScyllaSchemaFamily::ObjectSingle => "obj_id = ? AND checkpoint_id = ?",
        ScyllaSchemaFamily::HashToMany => "hash_id = ? AND value_u64 = ?",
        ScyllaSchemaFamily::MerkleZero => {
            "level = ? AND node_index = ? AND checkpoint_id = ?"
        }
        ScyllaSchemaFamily::MerkleSingle => {
            "tree_id = ? AND level = ? AND node_index = ? AND checkpoint_id = ?"
        }
        ScyllaSchemaFamily::MerkleDouble => {
            "tree_id = ? AND tree_sub_id = ? AND level = ? AND node_index = ? AND checkpoint_id = ?"
        }
        ScyllaSchemaFamily::Counter
        | ScyllaSchemaFamily::TagTree
        | ScyllaSchemaFamily::ImtLeaf
        | ScyllaSchemaFamily::ImtKeyIndex
        | ScyllaSchemaFamily::ImtCursor => {
            return Err(CoordinatorCommitDeleteRestoreExecutorError::UnsupportedFamily)
        }
    };
    Ok(format!(
        "DELETE FROM {}.{table} USING TIMESTAMP ? WHERE {where_clause}",
        keyspace.as_str(),
    ))
}

fn validate_target_restore<Hash: Q256BitHash>(
    expected_target: &psy_data::protocol::canonical_chain::CanonicalChainRef<Hash>,
    target: &CoordinatorCommitTargetRestorePayload<Hash>,
) -> Result<(), CoordinatorCommitDeleteRestoreExecutorError> {
    if target.target() != expected_target
        || target.latest_checkpoint()
            != expected_target.checkpoint().checkpoint_id().get()
        || target.target_l2_stored_value().is_empty()
    {
        return Err(CoordinatorCommitDeleteRestoreExecutorError::TargetRestoreMismatch);
    }
    Ok(())
}

fn post_state_digest<Hash: Q256BitHash>(
    barrier_digest: &[u8; 32],
    plan_digest: &[u8; 32],
    target: &CoordinatorCommitTargetRestorePayload<Hash>,
    delete_fence: i64,
    new_branch_write: i64,
    entries: &[CoordinatorCommitDeleteRestoreEntry],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(POST_STATE_DIGEST_DOMAIN);
    hasher.update(barrier_digest);
    hasher.update(plan_digest);
    hasher.update(target.digest());
    hasher.update(delete_fence.to_be_bytes());
    hasher.update(new_branch_write.to_be_bytes());
    hasher.update((entries.len() as u64).to_be_bytes());
    for entry in entries {
        hasher.update([entry.action() as u8]);
        hasher.update((entry.key().locator_bytes().len() as u64).to_be_bytes());
        hasher.update(entry.key().locator_bytes());
        if entry.action()
            == CoordinatorCommitDeleteRestoreAction::RestoreTargetSingleton
        {
            match entry.key().typed_key() {
                TypedTableKey::LatestInfo(LatestInfoSlot::LatestL2BlockState) => {
                    hasher.update((target.target_l2_stored_value().len() as u64).to_be_bytes());
                    hasher.update(target.target_l2_stored_value());
                }
                TypedTableKey::U64Singleton(U64SingletonSlot::LatestCheckpoint) => {
                    hasher.update(8_u64.to_be_bytes());
                    hasher.update(target.latest_checkpoint().to_be_bytes());
                }
                _ => {}
            }
        }
    }
    hasher.finalize().into()
}

async fn prepare_read(
    session: &Session,
    cql_text: &str,
) -> Result<PreparedStatement, CoordinatorCommitDeleteRestoreExecutorError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_write(
    session: &Session,
    cql_text: &str,
) -> Result<PreparedStatement, CoordinatorCommitDeleteRestoreExecutorError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn backend(error: impl fmt::Display) -> CoordinatorCommitDeleteRestoreExecutorError {
    CoordinatorCommitDeleteRestoreExecutorError::Backend(error.to_string())
}

fn cql(error: impl fmt::Display) -> CoordinatorCommitDeleteRestoreExecutorError {
    CoordinatorCommitDeleteRestoreExecutorError::Cql(error.to_string())
}

#[derive(Debug)]
pub(super) enum CoordinatorCommitDeleteRestoreExecutorError {
    BindingMismatch,
    TargetRestoreMismatch,
    TargetRestoreChanged,
    PostStateChanged,
    RestoreSetMismatch,
    PostStateMismatch,
    MissingPreparedMutation,
    MissingColumn,
    UnsupportedFamily,
    HeadMissing,
    HeadChanged,
    LengthOverflow,
    IntegerOutOfCqlRange,
    Indeterminate(String),
    Backend(String),
    Cql(String),
    PlanStore(CoordinatorCommitDeleteRestorePlanStoreError),
    Archive(CoordinatorCommitPhysicalArchiveStoreError),
    TargetRestore(CoordinatorCommitTargetRestoreError),
    BeforeImage(super::CoordinatorCommitPhysicalBeforeImageError),
    Completion(CoordinatorRollbackDeleteCompletionStoreError),
}

impl From<CoordinatorCommitDeleteRestorePlanStoreError>
    for CoordinatorCommitDeleteRestoreExecutorError
{
    fn from(value: CoordinatorCommitDeleteRestorePlanStoreError) -> Self {
        Self::PlanStore(value)
    }
}

impl From<CoordinatorCommitPhysicalArchiveStoreError>
    for CoordinatorCommitDeleteRestoreExecutorError
{
    fn from(value: CoordinatorCommitPhysicalArchiveStoreError) -> Self {
        Self::Archive(value)
    }
}

impl From<CoordinatorCommitTargetRestoreError>
    for CoordinatorCommitDeleteRestoreExecutorError
{
    fn from(value: CoordinatorCommitTargetRestoreError) -> Self {
        Self::TargetRestore(value)
    }
}

impl From<super::CoordinatorCommitPhysicalBeforeImageError>
    for CoordinatorCommitDeleteRestoreExecutorError
{
    fn from(value: super::CoordinatorCommitPhysicalBeforeImageError) -> Self {
        Self::BeforeImage(value)
    }
}

impl From<CoordinatorRollbackDeleteCompletionStoreError>
    for CoordinatorCommitDeleteRestoreExecutorError
{
    fn from(value: CoordinatorRollbackDeleteCompletionStoreError) -> Self {
        Self::Completion(value)
    }
}

impl fmt::Display for CoordinatorCommitDeleteRestoreExecutorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "coordinator delete/restore executor error: {self:?}")
    }
}

impl Error for CoordinatorCommitDeleteRestoreExecutorError {}

#[cfg(test)]
mod tests {
    use super::*;
    use psy_node_core::store::typed::{CheckpointId, TypedTableKey};

    #[test]
    fn delete_queries_are_exact_and_timestamped() {
        let keyspace = CqlKeyspaceName::try_new("rollback_test").unwrap();
        let cases = [
            TypedTableKey::CheckpointLeaf(CheckpointId::try_new(7).unwrap()),
            TypedTableKey::CheckpointedObject(
                psy_node_core::store::typed::CheckpointedObjectKey::GlobalUserProofAtCheckpoint(
                    CheckpointId::try_new(7).unwrap(),
                ),
            ),
            TypedTableKey::LatestInfo(LatestInfoSlot::LatestL2BlockState),
        ];
        for typed in cases {
            let key = super::super::describe_existing_key(&typed);
            let cql = delete_cql(&keyspace, &key).unwrap();
            assert!(cql.starts_with("DELETE FROM rollback_test."));
            assert!(cql.contains(" USING TIMESTAMP ? WHERE "));
            assert!(!cql.contains("ALLOW FILTERING"));
        }
    }

    #[test]
    fn executor_has_no_public_target_or_timestamp_input() {
        let source = include_str!("coordinator_commit_delete_restore_executor.rs");
        let start = source.find("pub(super) async fn execute").unwrap();
        let signature = &source[start..start + source[start..].find("{\n").unwrap()];
        assert!(!signature.contains("target:"));
        assert!(!signature.contains("timestamp"));
        assert!(!signature.contains("entries:"));
        assert!(source.contains("delete_and_readback"));
        assert!(source.contains("restore_and_readback"));
        assert!(source.contains("require_deleting_head"));
    }
}
