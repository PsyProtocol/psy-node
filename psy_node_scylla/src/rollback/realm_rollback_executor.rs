//! Runs one Realm's half of a rollback (design-r1 §6.3).
//!
//! A Realm holds three kinds of state and each is undone differently.  Treating
//! them alike is what produced the two defects this design corrects.
//!
//! | what | who writes it | how it is undone |
//! |---|---|---|
//! | user leaves, contract state, the IMT, pending mappings | `commit_state` | archive, then delete what the manifest names |
//! | checkpoint leaves, state roots, root mappings, block states | `sync` | re-fetched from the Coordinator |
//! | latest checkpoint id, latest block state | `sync`, mostly | the marker itself; moved by `reset_for_rollback_to` |
//!
//! The middle row is the one that is easy to get wrong.  Those rows are copies
//! of checkpoints the Coordinator published, so their old values are not lost
//! when they are overwritten -- the authority still has them.  Restoring them
//! from an archive would be reconstructing what can simply be fetched, and
//! recording them in a manifest would put two mechanisms on one row.
//!
//! The bottom row is the one that is dangerous to get wrong.  Those singletons
//! have no version axis, so a manifest-driven delete destroys the only copy, and
//! the delete fences the key: `sync` writes it afterwards with a plain clock,
//! lands under the fence, and the write succeeds while staying unreadable.  The
//! marker then reads as frozen while the chain advances past it.

use std::sync::Arc;

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::canonical_chain::CanonicalChainRef;
use psy_data::protocol::chain_context::AuthorityScope;
use psy_node_core::store::commit_window::CommitFreeze;
use psy_node_core::store::authority_commit::{AuthorityTimestampKey, AuthorityTimestampReadState};
use psy_node_core::store::realm_commit_recording::RealmCommitRecording;
use psy_node_core::store::rollback_plan::{
    ManifestCompletionMarker, RollbackPlan, build_rollback_plan_for,
};
use psy_node_core::store::rollback_coordination::{
    ObservedRollbackPhase, RollbackParticipantView,
};
use psy_node_core::store::rollback_participants::{
    ArchiveReceipt, FreezeReceipt, RollbackParticipant,
};
use psy_node_core::store::timestamp::{DeleteFenceTimestampUs, TimestampFenceWindow};
use scylla::client::session::Session;

use super::{
    ArchiveOutcome, ScyllaDeleteExecutor, ScyllaRollbackArchive, plan_rows_from_chunks,
    fence_from_archive,
};

/// What one Realm rollback did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmRollbackReport {
    pub target: u64,
    pub head: u64,
    pub planned_rows: usize,
    pub archived_rows: usize,
    pub deleted_rows: usize,
    pub fence_us: i64,
}

/// The gap between the highest discarded write and the fence.
pub const REALM_FENCE_GAP_US: i64 = 1_000_000;

pub struct ScyllaRealmRollbackExecutor {
    archive: ScyllaRollbackArchive,
    delete: ScyllaDeleteExecutor,
}

impl ScyllaRealmRollbackExecutor {
    pub async fn prepare(
        session: Arc<Session>,
        state_keyspace: &str,
        no_tablet_keyspace: &str,
    ) -> anyhow::Result<Self> {
        ScyllaRollbackArchive::create_table(&session, no_tablet_keyspace).await?;
        Ok(Self {
            archive: ScyllaRollbackArchive::prepare(
                session.clone(),
                state_keyspace,
                no_tablet_keyspace,
            )
            .await?,
            delete: ScyllaDeleteExecutor::prepare(session, state_keyspace).await?,
        })
    }

    /// Plan this Realm's discarded suffix.
    ///
    /// SEALED is the completion mark, not COMMITTED: a Realm never publishes a
    /// head, so it never produces the receipt COMMITTED requires.  Asking for
    /// COMMITTED here would find none and call every Realm commit unfinished.
    pub async fn plan<Hash: Q256BitHash>(
        &self,
        recording: &RealmCommitRecording<Hash>,
        realm_id: u32,
        realm_sub_id: u16,
        head: &CanonicalChainRef<Hash>,
        target: u64,
    ) -> anyhow::Result<RollbackPlan<Hash>> {
        build_rollback_plan_for(
            recording.manifest(),
            recording.manifest_artifact(),
            AuthorityScope::Realm {
                realm_id,
                realm_sub_id,
            },
            ManifestCompletionMarker::Sealed,
            head,
            target,
            &|chunks| Ok(plan_rows_from_chunks(chunks)?),
        )
        .await
    }

    /// The fence for this Realm, from its own allocator.
    ///
    /// Its own, not the Coordinator's: the two write different keyspaces with
    /// different sessions, so the Coordinator's high water says nothing about
    /// what this Realm has issued.
    pub async fn fence_window<Hash: Q256BitHash>(
        &self,
        recording: &RealmCommitRecording<Hash>,
        head: &CanonicalChainRef<Hash>,
        realm_id: u32,
        realm_sub_id: u16,
    ) -> anyhow::Result<TimestampFenceWindow> {
        let key = AuthorityTimestampKey::new(
            head.network_id(),
            AuthorityScope::Realm {
                realm_id,
                realm_sub_id,
            },
        );
        let state = match recording.timestamp().read_timestamp_state(key).await? {
            AuthorityTimestampReadState::Current(state) => state,
            AuthorityTimestampReadState::Uninitialized => anyhow::bail!(
                "this Realm has no timestamp allocator row, so no fence can be derived; it has \
                 committed nothing under the recording scheme"
            ),
        };
        let high_water = state.high_water();
        let fence = high_water.as_i64() as i128 + REALM_FENCE_GAP_US as i128;
        Ok(TimestampFenceWindow::try_new(
            high_water,
            fence,
            fence + REALM_FENCE_GAP_US as i128,
        )?)
    }

    /// Copy every planned row, then prove every copy.
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
                        "the Realm archive slot for table {table} at checkpoint {height} already \
                         holds different content for this plan"
                    ),
                }
            }
        }
        Ok(archived)
    }

    /// Delete this Realm's own rows behind the fence, newest height first.
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

    /// Prove the fence dominates what the archive observed.
    async fn verify_archive_under_fence<Hash: Q256BitHash>(
        &self,
        plan_id: &[u8],
        plan: &RollbackPlan<Hash>,
        fence: DeleteFenceTimestampUs,
    ) -> anyhow::Result<()> {
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
        if let Some(observed) = fence_from_archive(&archived, REALM_FENCE_GAP_US)? {
            if observed.as_i64() - REALM_FENCE_GAP_US >= fence.as_i64() {
                anyhow::bail!(
                    "this Realm's archive holds a write at or above the delete fence ({} vs {}), \
                     so a tombstone at the fence would not hide it",
                    observed.as_i64() - REALM_FENCE_GAP_US,
                    fence.as_i64()
                );
            }
        }
        Ok(())
    }

    /// Archive, fence, delete -- the manifest-driven half of a Realm rollback.
    ///
    /// The sync-driven half is not here: pointing the Realm back at the target
    /// needs its processor, which owns the checkpoint tree and the marker.  The
    /// caller runs `reset_for_rollback_to` after this returns, and the order
    /// matters -- lowering the marker first would let a sync race the delete and
    /// re-fetch heights this is about to remove.
    /// Run this Realm's half of a rollback, taking each step only when the
    /// Coordinator has published the phase that permits it.
    ///
    /// The participant view is how a Realm learns where the rollback is; it can
    /// read the phase and file receipts, and there is deliberately no way from
    /// it to advance one (§6.2).  Without this gate a Realm could archive
    /// against a head the Coordinator had not frozen, or -- much worse -- delete
    /// before the global archive barrier, which is I6 breached from the
    /// participant side: the Coordinator's own barrier check cannot see it,
    /// because the rows are gone from a keyspace it does not read.
    pub async fn roll_back<Hash: Q256BitHash>(
        &self,
        recording: &RealmCommitRecording<Hash>,
        realm_id: u32,
        realm_sub_id: u16,
        head: &CanonicalChainRef<Hash>,
        target: u64,
        plan_id: &[u8],
        view: &dyn RollbackParticipantView<Hash>,
    ) -> anyhow::Result<RealmRollbackReport> {
        let me = RollbackParticipant::new(AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        });

        // ---- freeze ----
        let phase = view.observe_phase(head).await?;
        let ObservedRollbackPhase::Freeze { head: frozen_head } = phase else {
            anyhow::bail!(
                "this Realm was asked to roll back to {target} while the Coordinator has \
                 published {phase:?}; a participant follows the published phase rather than \
                 deciding for itself when to start"
            );
        };
        if frozen_head != head.checkpoint().checkpoint_id().get() {
            anyhow::bail!(
                "the Coordinator froze head {frozen_head} but this Realm was asked to roll back \
                 from {}",
                head.checkpoint().checkpoint_id().get(),
            );
        }

        // Stop the head before reporting that it stopped.  Until this call the
        // freeze was a phase the Coordinator had published and a receipt this
        // Realm was about to file -- nothing that prevented the processor from
        // committing the next checkpoint into the range being planned.
        recording.freeze_for_rollback();
        super::drain_in_flight_commit(recording).await?;

        let plan = self
            .plan(recording, realm_id, realm_sub_id, head, target)
            .await?;
        let planned_rows = plan.row_count();
        let window = self
            .fence_window(recording, head, realm_id, realm_sub_id)
            .await?;
        let fence = window.delete_fence();
        view.file_freeze_receipt(&FreezeReceipt::new(
            me,
            plan.head,
            head.checkpoint()
                .checkpoint_hash()
                .as_inner()
                .into_owned_32bytes(),
        ))
        .await?;

        // ---- archive ----
        //
        // Waiting for the Coordinator to publish ARCHIVING rather than starting
        // on the strength of having filed a freeze receipt: the freeze barrier
        // is met when *everyone* has filed, and only the Coordinator knows that.
        let phase = view.observe_phase(head).await?;
        let ObservedRollbackPhase::Archive { .. } = phase else {
            anyhow::bail!(
                "this Realm froze at {} and is waiting to archive, but the Coordinator has \
                 published {phase:?}",
                plan.head,
            );
        };
        let archived_rows = self.archive(plan_id, &plan).await?;
        if archived_rows != planned_rows {
            anyhow::bail!(
                "archived {archived_rows} of {planned_rows} planned Realm rows; the barrier must \
                 not be crossed with an incomplete archive"
            );
        }
        self.verify_archive_under_fence(plan_id, &plan, fence).await?;
        view.file_archive_receipt(&ArchiveReceipt::new(
            me,
            target,
            plan.head,
            archived_rows as u64,
            super::rollback_executor::plan_digest(plan_id),
        ))
        .await?;

        // ---- delete ----
        //
        // `permits_destruction` answers this in one place so no caller has to
        // read it off a phase name.  Only DELETING says yes, and DELETING is
        // published only after the Coordinator sealed the archive barrier with
        // the receipt filed just above.
        let phase = view.observe_phase(head).await?;
        if !phase.permits_destruction() {
            anyhow::bail!(
                "this Realm archived {archived_rows} rows and is waiting to delete, but the \
                 Coordinator has published {phase:?}; deleting here would breach the global \
                 archive barrier from the side the Coordinator cannot see"
            );
        }
        let deleted_rows = self.delete(&plan, fence).await?;

        Ok(RealmRollbackReport {
            target,
            head: plan.head,
            planned_rows,
            archived_rows,
            deleted_rows,
            fence_us: fence.as_i64(),
        })
    }
}
