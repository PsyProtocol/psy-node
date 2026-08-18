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

    /// Archive, fence, delete, restore -- in that order, for one target.
    pub async fn roll_back<Hash: Q256BitHash>(
        &self,
        recording: &CoordinatorCommitRecording<Hash>,
        head: &CanonicalChainRef<Hash>,
        target: u64,
        plan_id: &[u8],
    ) -> anyhow::Result<RollbackReport> {
        let plan = self.plan(recording, head, target).await?;
        let planned_rows = plan.row_count();
        let archived_rows = self.archive(plan_id, &plan).await?;
        if archived_rows != planned_rows {
            anyhow::bail!(
                "archived {archived_rows} of {planned_rows} planned rows; the barrier must not \
                 be crossed with an incomplete archive"
            );
        }
        let fence = self.fence(plan_id, &plan).await?;
        let deleted_rows = self.delete(&plan, fence).await?;
        let restored_singletons = self.restore_singletons(target, fence).await?;
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
}
