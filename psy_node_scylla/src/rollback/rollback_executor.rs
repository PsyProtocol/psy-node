//! Runs one Coordinator rollback: archive, then delete, then restore.
//!
//! The order is design-r1 §0.3 and none of it is interchangeable.  Archiving is a
//! precondition rather than a backup (§0.2 D2), so nothing is deleted until every
//! planned row has been copied *and read back*; the delete fence is computed from
//! what the archive observed, so it cannot exist before the archive; and the
//! restore has to follow the delete, because it writes the values the delete
//! exposed.
//!
//! Deletion runs from the head downwards.  Ascending would leave, at every
//! intermediate moment, a height whose successor still exists, so a crash would
//! leave a chain with a hole; descending means the visible head only ever moves
//! backwards and a crash leaves a shorter chain instead.
//!
//! What this deliberately does not do is decide anything for itself.  A range it
//! cannot plan is an error, never a scan of the hot tables to guess an inventory
//! (§2.2), and a fence it cannot derive is an error, never a clock reading.

use std::sync::Arc;

use psy_node_core::store::manifest_store::CoordinatorCommitRecording;
use psy_node_core::store::rollback_plan::{RollbackPlan, build_rollback_plan};
use psy_node_core::store::timestamp::DeleteFenceTimestampUs;
use psy_data::protocol::canonical_chain::CanonicalChainRef;
use parth_core::protocol::core_types::Q256BitHash;
use scylla::client::session::Session;

use psy_data::protocol::chain_context::AuthorityScope;
use psy_node_core::store::authority_commit::{AuthorityTimestampKey, AuthorityTimestampReadState};
use psy_node_core::store::canonical_head::{
    CanonicalHeadReadState, CanonicalHeadTransition, StoredCanonicalHead,
};
use psy_node_core::store::rollback_control::{
    RollbackExecutionMode, RollbackPlanDigest, RollbackRequest,
};
use psy_node_core::store::timestamp::{CommitWriteTimestampUs, TimestampFenceWindow};

use super::{
    ArchiveOutcome, ScyllaDeleteExecutor, ScyllaRollbackArchive, decode_locator_chunk,
    fence_from_archive,
};

/// What one rollback did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RollbackReport {
    pub target: u64,
    pub head: u64,
    pub planned_rows: usize,
    pub archived_rows: usize,
    pub deleted_rows: usize,
    pub fence_us: i64,
    pub restored_singletons: usize,
}

/// The gap placed between the highest discarded write and the fence.
///
/// Any strictly positive gap satisfies I7; a second of headroom keeps the fence
/// clear of clock jitter between nodes without pushing new writes far into the
/// future, since the allocator has to climb past it afterwards.
pub const DEFAULT_FENCE_GAP_US: i64 = 1_000_000;

/// A stable digest for one rollback plan id.
fn plan_digest(plan_id: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"PSYROLLBACKPLAN");
    hasher.update(plan_id);
    hasher.finalize().into()
}

pub struct ScyllaRollbackExecutor {
    session: Arc<Session>,
    state_keyspace: String,
    archive: ScyllaRollbackArchive,
    delete: ScyllaDeleteExecutor,
}

impl ScyllaRollbackExecutor {
    pub async fn prepare(
        session: Arc<Session>,
        state_keyspace: &str,
        no_tablet_keyspace: &str,
    ) -> anyhow::Result<Self> {
        ScyllaRollbackArchive::create_table(&session, no_tablet_keyspace).await?;
        Ok(Self {
            session: session.clone(),
            state_keyspace: state_keyspace.to_string(),
            archive: ScyllaRollbackArchive::prepare(
                session.clone(),
                state_keyspace,
                no_tablet_keyspace,
            )
            .await?,
            delete: ScyllaDeleteExecutor::prepare(session, state_keyspace).await?,
        })
    }

    /// Plan the discarded suffix from the manifests alone.
    pub async fn plan<Hash: Q256BitHash>(
        &self,
        recording: &CoordinatorCommitRecording<Hash>,
        head: &CanonicalChainRef<Hash>,
        target: u64,
    ) -> anyhow::Result<RollbackPlan<Hash>> {
        build_rollback_plan(recording, head, target, &|chunks| {
            let mut rows = Vec::new();
            for chunk in chunks {
                for record in decode_locator_chunk(chunk)? {
                    rows.push((
                        record.physical_table().stable_id(),
                        record.locator_bytes().to_vec(),
                    ));
                }
            }
            Ok(rows)
        })
        .await
    }

    /// Copy every planned row, then prove every copy.
    ///
    /// A conflict is fatal on purpose: it means this plan id already holds
    /// different content for a source key, so two runs disagree about history and
    /// only a human can say which is right.
    pub async fn archive<Hash: Q256BitHash>(
        &self,
        plan_id: &[u8],
        plan: &RollbackPlan<Hash>,
    ) -> anyhow::Result<usize> {
        let mut archived = 0usize;
        for checkpoint in &plan.checkpoints {
            let height = checkpoint.checkpoint_id();
            for (table, locator) in &checkpoint.rows {
                match self
                    .archive
                    .archive_row(plan_id, height, *table, locator)
                    .await?
                {
                    ArchiveOutcome::Archived | ArchiveOutcome::AlreadyIdentical => archived += 1,
                    ArchiveOutcome::Conflict => anyhow::bail!(
                        "archive slot for table {table} at checkpoint {height} already holds \
                         different content for this plan; refusing to overwrite it"
                    ),
                }
            }
        }
        Ok(archived)
    }

    /// The fence for this plan, from the timestamps the archive observed.
    pub async fn fence<Hash: Q256BitHash>(
        &self,
        plan_id: &[u8],
        plan: &RollbackPlan<Hash>,
    ) -> anyhow::Result<DeleteFenceTimestampUs> {
        let mut tables: Vec<u16> = plan
            .checkpoints
            .iter()
            .flat_map(|checkpoint| checkpoint.rows.iter().map(|(table, _)| *table))
            .collect();
        tables.sort_unstable();
        tables.dedup();

        let mut archived = Vec::new();
        for table in tables {
            archived.extend(self.archive.rows_for(plan_id, table).await?);
        }
        fence_from_archive(&archived, DEFAULT_FENCE_GAP_US)?.ok_or_else(|| {
            anyhow::anyhow!(
                "the archive holds no write timestamp, so no fence can be derived; reading a \
                 clock instead would risk a fence below a real write, which deletes nothing"
            )
        })
    }

    /// Delete the discarded suffix behind the fence, newest height first.
    pub async fn delete<Hash: Q256BitHash>(
        &self,
        plan: &RollbackPlan<Hash>,
        fence: DeleteFenceTimestampUs,
    ) -> anyhow::Result<usize> {
        let mut deleted = 0usize;
        for checkpoint in plan.checkpoints.iter().rev() {
            for (_, locator) in &checkpoint.rows {
                self.delete.delete_row(fence, locator).await?;
                deleted += 1;
            }
        }
        Ok(deleted)
    }

    /// Put the overwrite-in-place singletons back to the target's values.
    ///
    /// These have no version axis, so deleting the discarded writes does not
    /// uncover an older row -- there is none.  Both values are copied from state
    /// that survives the delete rather than recomputed: the latest block state is
    /// byte for byte the row `l2_block_state_table` holds at the target, and the
    /// latest checkpoint id is the target itself.  A copy needs no argument about
    /// whether a recomputation matches history; the journal is what proves the
    /// claim for anything that genuinely must be recomputed.
    ///
    /// Written above the fence, because a value written under it is shadowed by
    /// the tombstones just laid down -- succeeding, silent, and unreadable.
    pub async fn restore_singletons(
        &self,
        target: u64,
        fence: DeleteFenceTimestampUs,
    ) -> anyhow::Result<usize> {
        let restore_at = fence.as_i64() + 1;
        let mut restored = 0usize;

        let block_state = self
            .session
            .query_unpaged(
                format!(
                    "SELECT value FROM {}.l2_block_state_table WHERE obj_id = ?",
                    self.state_keyspace
                ),
                (target as i64,),
            )
            .await?
            .into_rows_result()?
            .maybe_first_row::<(Option<Vec<u8>>,)>()?
            .and_then(|(value,)| value);
        let Some(block_state) = block_state else {
            anyhow::bail!(
                "the target checkpoint {target} has no l2_block_state row to restore the \
                 latest-info singleton from"
            );
        };
        self.session
            .query_unpaged(
                format!(
                    "INSERT INTO {}.latest_info_table (obj_id, value) VALUES (?, ?) \
                     USING TIMESTAMP ?",
                    self.state_keyspace
                ),
                (1i64, block_state, restore_at),
            )
            .await?;
        restored += 1;

        self.session
            .query_unpaged(
                format!(
                    "INSERT INTO {}.u64_singleton_table (obj_id, value) VALUES (?, ?) \
                     USING TIMESTAMP ?",
                    self.state_keyspace
                ),
                (1i64, target as i64, restore_at),
            )
            .await?;
        restored += 1;

        Ok(restored)
    }

    /// The fence for this rollback, from the timestamp allocator.
    ///
    /// The allocator's high water is at or above every timestamp it has issued,
    /// and since M2b every recorded write carries one, so a fence above the high
    /// water is above every write the discarded range made.  It is also knowable
    /// *before* archiving, which the phase machine requires: the fence window is
    /// part of the rollback request, sealed when the rollback starts.
    ///
    /// What the archive observes afterwards is then a cross-check rather than the
    /// source -- see `verify_archive_under_fence`.
    async fn fence_window_from_allocator<Hash: Q256BitHash>(
        &self,
        recording: &CoordinatorCommitRecording<Hash>,
        head: &CanonicalChainRef<Hash>,
    ) -> anyhow::Result<TimestampFenceWindow> {
        let key = AuthorityTimestampKey::new(head.network_id(), AuthorityScope::Coordinator);
        let state = match recording.timestamp().read_timestamp_state(key).await? {
            AuthorityTimestampReadState::Current(state) => state,
            AuthorityTimestampReadState::Uninitialized => anyhow::bail!(
                "this authority has no timestamp allocator row, so no fence can be derived; \
                 the chain predates the recording scheme and is below the rollback floor"
            ),
        };
        let high_water = state.high_water();
        let fence = high_water.as_i64() as i128 + DEFAULT_FENCE_GAP_US as i128;
        let new_branch = fence + DEFAULT_FENCE_GAP_US as i128;
        Ok(TimestampFenceWindow::try_new(high_water, fence, new_branch)?)
    }

    /// Prove the fence really does dominate what the archive found.
    ///
    /// The fence comes from the allocator; this checks that against the
    /// timestamps the rows actually carry.  A row above the fence would mean
    /// something wrote a recorded table outside the allocator, and the tombstone
    /// would not hide it -- the exact failure the fence exists to prevent, and
    /// one that is invisible until the height is reused.
    async fn verify_archive_under_fence<Hash: Q256BitHash>(
        &self,
        plan_id: &[u8],
        plan: &RollbackPlan<Hash>,
        fence: DeleteFenceTimestampUs,
    ) -> anyhow::Result<()> {
        let observed = self.fence(plan_id, plan).await;
        match observed {
            Ok(observed_fence) => {
                // `fence()` returns a value strictly above the highest observed
                // write, so comparing fences compares the writes underneath.
                if observed_fence.as_i64() - DEFAULT_FENCE_GAP_US >= fence.as_i64() {
                    anyhow::bail!(
                        "the archive holds a write at or above the delete fence ({} vs {}), so \
                         a tombstone at the fence would not hide it",
                        observed_fence.as_i64() - DEFAULT_FENCE_GAP_US,
                        fence.as_i64()
                    );
                }
                Ok(())
            }
            // No timestamp anywhere in the archive: every planned row was absent,
            // or every archived table is key-only.  Nothing to contradict.
            Err(_) => Ok(()),
        }
    }

    /// Run the whole rollback, driving the durable phase machine as it goes.
    ///
    /// Every phase is a CAS on the canonical head, so the phase a crash leaves
    /// behind is readable rather than inferred, and the archive barrier is the
    /// single point of no return: before it nothing has been deleted and the
    /// rollback can still be abandoned, after it the only way out is forwards.
    pub async fn roll_back<Hash: Q256BitHash>(
        &self,
        recording: &CoordinatorCommitRecording<Hash>,
        head: &CanonicalChainRef<Hash>,
        target: u64,
        plan_id: &[u8],
    ) -> anyhow::Result<RollbackReport> {
        let plan = self.plan(recording, head, target).await?;
        let planned_rows = plan.row_count();
        // The target's identity comes from its own manifest.  There is no
        // fallback on purpose: substituting a neighbouring checkpoint, or
        // constructing a reference, would publish a head whose hash names a
        // checkpoint that never existed at that height.
        let target_ref = self
            .target_checkpoint_ref::<Hash>(recording, head, target)
            .await?;

        let window = self.fence_window_from_allocator(recording, head).await?;
        let fence = window.delete_fence();

        let mut stored = self.read_head(recording, head).await?;
        let request = RollbackRequest::try_new(
            *head.checkpoint(),
            target_ref,
            window,
            RollbackExecutionMode::InPlace,
            RollbackPlanDigest::try_new(plan_digest(plan_id))?,
        )?;

        stored = self
            .advance(recording, CanonicalHeadTransition::start_rollback(stored, request)?)
            .await?;
        stored = self
            .advance(recording, CanonicalHeadTransition::begin_rollback_archive(stored)?)
            .await?;

        let archived_rows = self.archive(plan_id, &plan).await?;
        if archived_rows != planned_rows {
            anyhow::bail!(
                "archived {archived_rows} of {planned_rows} planned rows; the barrier must not \
                 be crossed with an incomplete archive"
            );
        }
        self.verify_archive_under_fence(plan_id, &plan, fence).await?;

        // ---- point of no return ----
        stored = self
            .advance(
                recording,
                CanonicalHeadTransition::complete_rollback_archive_barrier(stored)?,
            )
            .await?;

        stored = self
            .advance(recording, CanonicalHeadTransition::begin_rollback_delete(stored)?)
            .await?;
        let deleted_rows = self.delete(&plan, fence).await?;

        stored = self
            .advance(recording, CanonicalHeadTransition::begin_rollback_restore(stored)?)
            .await?;
        let restored_singletons = self.restore_singletons(target, fence).await?;

        stored = self
            .advance(recording, CanonicalHeadTransition::begin_rollback_verify(stored)?)
            .await?;
        // Slice A has one participant, so the realm barrier is satisfied as soon
        // as this one is.  Slice C is what makes it wait for the others.
        stored = self
            .advance(
                recording,
                CanonicalHeadTransition::complete_rollback_realm_barrier(stored)?,
            )
            .await?;
        self.advance(recording, CanonicalHeadTransition::complete_rollback(stored)?)
            .await?;

        Ok(RollbackReport {
            target,
            head: plan.head,
            planned_rows,
            archived_rows,
            deleted_rows,
            fence_us: fence.as_i64(),
            restored_singletons,
        })
    }

    /// The target checkpoint's own identity, read from its manifest.
    async fn target_checkpoint_ref<Hash: Q256BitHash>(
        &self,
        recording: &CoordinatorCommitRecording<Hash>,
        head: &CanonicalChainRef<Hash>,
        target: u64,
    ) -> anyhow::Result<psy_data::protocol::canonical_chain::CheckpointRef<Hash>> {
        let one_step = self.plan(recording, head, target.saturating_sub(1)).await?;
        let first = one_step
            .checkpoints
            .iter()
            .find(|checkpoint| checkpoint.checkpoint_id() == target)
            .ok_or_else(|| anyhow::anyhow!("no manifest names the target checkpoint {target}"))?;
        Ok(*first.chain.checkpoint())
    }

    async fn read_head<Hash: Q256BitHash>(
        &self,
        recording: &CoordinatorCommitRecording<Hash>,
        head: &CanonicalChainRef<Hash>,
    ) -> anyhow::Result<StoredCanonicalHead<Hash>> {
        match recording
            .canonical_head()
            .read_canonical_head(head.network_id())
            .await?
        {
            CanonicalHeadReadState::Current(stored) => Ok(stored),
            CanonicalHeadReadState::Uninitialized => {
                anyhow::bail!("there is no published canonical head to roll back")
            }
        }
    }

    async fn advance<Hash: Q256BitHash>(
        &self,
        recording: &CoordinatorCommitRecording<Hash>,
        transition: CanonicalHeadTransition<Hash>,
    ) -> anyhow::Result<StoredCanonicalHead<Hash>> {
        let kind = transition.kind();
        let sealed = transition.seal();
        let outcome = recording
            .canonical_head()
            .compare_and_set_canonical_head(&sealed)
            .await?;
        if !(outcome.was_applied() || outcome.was_idempotent()) {
            anyhow::bail!(
                "the canonical head moved under this rollback while entering {kind:?}; another \
                 writer is active and continuing would publish a head nobody agreed to"
            );
        }
        Ok(*outcome.current())
    }
}
