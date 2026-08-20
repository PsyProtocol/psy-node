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
use psy_data::protocol::canonical_chain::{CanonicalChainRef, CheckpointId, CheckpointRef};
use psy_data::protocol::chain_context::AuthorityScope;
use psy_node_core::store::commit_window::CommitFreeze;
use psy_node_core::store::rollback_control::{PHASE_ORDINAL_ARCHIVING, PHASE_ORDINAL_DELETING};
use psy_node_core::store::authority_commit::{AuthorityTimestampKey, AuthorityTimestampReadState};
use psy_node_core::store::realm_commit_recording::RealmCommitRecording;
use psy_node_core::store::rollback_plan::{
    ManifestCompletionMarker, RollbackPlan, build_rollback_plan_for,
};
use psy_node_core::store::rollback_coordination::{
    ObservedRollbackPhase, RollbackParticipantView,
};
use psy_node_core::store::rollback_participants::{
    ArchiveReceipt, FreezeReceipt, RollbackParticipant, VerifyReceipt,
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
    /// Puts back rows the plan deleted that existed before the range began.
    /// This is the side the defect actually shows on: the Coordinator writes
    /// each of its axis-less mappings once and never rewrites one, so it never
    /// meets the case at all.
    restore: super::ScyllaRestoreExecutor,
    reader: super::ScyllaRowImageReader,
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
            delete: ScyllaDeleteExecutor::prepare(session.clone(), state_keyspace).await?,
            restore: super::ScyllaRestoreExecutor::prepare(session.clone(), state_keyspace).await?,
            reader: super::ScyllaRowImageReader::prepare(session, state_keyspace).await?,
        })
    }

    /// Put back the rows this Realm's plan deleted that existed before the
    /// range began.  See `restore_executor` for why this is per row.
    pub async fn restore_rewritten_rows<Hash: Q256BitHash>(
        &self,
        recording: &RealmCommitRecording<Hash>,
        plan: &RollbackPlan<Hash>,
        target: u64,
        fence: DeleteFenceTimestampUs,
        // The epoch the discarded range was produced under, not the one this
        // rollback opened.  Checkpoint heights are reused, so a height that has
        // been rolled back before carries observations from every branch that
        // ever reached it, and restoring without naming the branch writes back
        // rows belonging to a chain that no longer exists.
        discarded_epoch: u64,
    ) -> anyhow::Result<usize> {
        let Some(journal) = recording.journal() else {
            anyhow::bail!(
                "a Realm rollback cannot restore rewritten rows without the verification \
                 journal; run the chain with PSY_ROLLBACK_VERIFICATION_JOURNAL set"
            );
        };
        let mut first_touch: std::collections::BTreeMap<Vec<u8>, (Vec<u8>, Vec<u8>)> =
            std::collections::BTreeMap::new();
        for checkpoint in (target + 1)..=plan.head {
            for (_, locator, before) in journal
                .rewritten_before_images(checkpoint, discarded_epoch)
                .await? {
                let Ok(resolved) = super::decode_locator_canonical(&locator) else {
                    continue;
                };
                let Ok(position) = self.reader.position_key(&resolved) else {
                    continue;
                };
                first_touch.entry(position).or_insert((locator, before));
            }
        }
        let mut restored = 0usize;
        for (locator, before) in first_touch.values() {
            self.restore.restore_row(fence, locator, before).await?;
            restored += 1;
        }
        Ok(restored)
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
                    // An earlier attempt of this same recovery archived the row
                    // and then deleted and restored it, so the live row has
                    // moved and cannot match the copy any more.  The copy is
                    // the one taken before anything was destroyed; keeping it is
                    // the whole point.  The Coordinator never reaches this
                    // because it skips archiving once the barrier is behind it
                    // -- a Realm re-running its own recovery has no phase to
                    // skip on, and reached it on every retry, once a second,
                    // for eight hundred and sixteen tries while the chain stood
                    // still.
                    ArchiveOutcome::AlreadyArchivedByAnEarlierAttempt => {
                        tracing::warn!(
                            table,
                            height,
                            "keeping the copy an earlier attempt of this recovery archived; the \
                             live row has since been rolled back by that attempt"
                        );
                        archived += 1;
                    }
                    ArchiveOutcome::Conflict => anyhow::bail!(
                        "the Realm archive slot for table {table} at checkpoint {height} was \
                         written by this run and already reads back differently; something else \
                         is writing the archive"
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
        let ObservedRollbackPhase::Freeze { head: frozen_head, .. } = phase else {
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
        // The fence is derived only when there is something to delete.  A Realm
        // that has never committed has no allocator row to derive one from, and
        // demanding one would make it unable to take part at all -- which is
        // backwards: a Realm with nothing of its own in the range is the one
        // participant that can be certain it has nothing to lose.  It still
        // files every receipt, because the barriers are counting participants,
        // not rows.
        let fence = if planned_rows > 0 {
            Some(
                self.fence_window(recording, head, realm_id, realm_sub_id)
                    .await?
                    .delete_fence(),
            )
        } else {
            None
        };
        crash_realm_step("BeforeFreezeReceipt");
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
        crash_realm_step("AfterFreezeReceipt");
        wait_for_phase(view, head, "ARCHIVING", PHASE_ORDINAL_ARCHIVING).await?;
        crash_realm_step("BeforeArchive");
        let archived_rows = self.archive(plan_id, &plan).await?;
        crash_realm_step("AfterArchive");
        if archived_rows != planned_rows {
            anyhow::bail!(
                "archived {archived_rows} of {planned_rows} planned Realm rows; the barrier must \
                 not be crossed with an incomplete archive"
            );
        }
        if let Some(fence) = fence {
            self.verify_archive_under_fence(plan_id, &plan, fence).await?;
        }
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
        crash_realm_step("AfterArchiveReceipt");
        wait_for_phase(view, head, "DELETING", PHASE_ORDINAL_DELETING).await?;
        crash_realm_step("BeforeDelete");
        let deleted_rows = match fence {
            Some(fence) => self.delete(&plan, fence).await?,
            None => 0,
        };
        if let Some(fence) = fence {
            let restored = self
                .restore_rewritten_rows(
                    recording,
                    &plan,
                    target,
                    fence,
                    head.chain_epoch().get(),
                )
                .await?;
            if restored > 0 {
                tracing::warn!(
                    "restored {restored} rows this Realm's discarded range had rewritten rather \
                     than created; deleting them destroyed the only copy of their previous value"
                );
            }
        }

        // ---- verify ----
        //
        // The last receipt, and without it PUBLISH_ALL waits forever: the
        // Coordinator will not announce the new epoch until every participant
        // has said it reached the target.  Filed here, once this Realm's rows
        // above the target are gone, which is the claim it is making.  Resetting
        // its sync markers follows and is bookkeeping -- the state the chain
        // cares about is already correct.
        //
        // The digest is this Realm's own plan, not a value shared with the
        // others.  Each participant is answering for what it restored, and the
        // barrier counts participants rather than comparing their answers.
        view.file_verify_receipt(&VerifyReceipt::new(
            me,
            target,
            super::rollback_executor::plan_digest(plan_id),
        ))
        .await?;

        Ok(RealmRollbackReport {
            target,
            head: plan.head,
            planned_rows,
            archived_rows,
            deleted_rows,
            fence_us: fence.map(|f| f.as_i64()).unwrap_or(0),
        })
    }
}

#[async_trait::async_trait]
impl<Hash: Q256BitHash> psy_node_core::store::realm_self_rollback::RealmSelfRollback<Hash>
    for ScyllaRealmRollbackExecutor
{
    async fn recover_own_state_to(
        &self,
        recording: &RealmCommitRecording<Hash>,
        realm_id: u32,
        realm_sub_id: u16,
        search_head: &CanonicalChainRef<Hash>,
        target: u64,
    ) -> anyhow::Result<psy_node_core::store::realm_self_rollback::RealmSelfRollbackReport> {
        use psy_node_core::store::authority_commit::AuthorityTimestampKey;
        use psy_node_core::store::manifest_record::AuthorityManifestIdentity;
        use psy_node_core::store::realm_self_rollback::RealmSelfRollbackReport;

        let scope = AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        };
        // A search range at or below the target has nothing above the target in
        // it, which is the answer rather than a failure.  The manifest store
        // rejects an empty range, and it is right to -- a planner asking for one
        // has lost track of what it is planning -- but here it is the ordinary
        // case: a Realm whose sync markers have already been reset to the target
        // is asking whether anything is left, and the shape of the question
        // already says no.
        let search_height = search_head.checkpoint().checkpoint_id().get();
        if search_height <= target {
            return Ok(RealmSelfRollbackReport {
                own_head: target,
                target,
                ..Default::default()
            });
        }
        // The Realm's own head, from its own manifest.  Reading the whole
        // suffix above the target costs one query and answers the question that
        // decides everything else: a Realm with no rows of its own up there --
        // the ordinary case -- stops here.
        let identity = AuthorityManifestIdentity::try_new(
            AuthorityTimestampKey::new(search_head.network_id(), scope),
            *search_head,
        )?;
        let own = recording
            .manifest()
            .read_manifest_suffix(
                &identity,
                target,
                search_head.checkpoint().checkpoint_id().get(),
            )
            .await?;
        let Some(own_head) = own.iter().map(|row| row.checkpoint_id).max() else {
            return Ok(RealmSelfRollbackReport {
                own_head: target,
                target,
                ..Default::default()
            });
        };

        // Plan against the Realm's own head, which is above the Coordinator's
        // right after a rollback.  The chain reference only carries the height
        // the planner bounds by; its hash is the Coordinator's coordinate and is
        // not consulted for a Realm's own manifest.
        let head_ref = CanonicalChainRef::new(
            search_head.network_id(),
            search_head.chain_epoch(),
            CheckpointRef::new(
                CheckpointId::new(own_head),
                *search_head.checkpoint().checkpoint_hash(),
            ),
        );
        let plan = self
            .plan(recording, realm_id, realm_sub_id, &head_ref, target)
            .await?;
        let planned_rows = plan.row_count();
        let window = self
            .fence_window(recording, &head_ref, realm_id, realm_sub_id)
            .await?;
        let fence = window.delete_fence();

        // The plan id names the recovery rather than the rollback, because this
        // Realm was not present for the rollback and cannot know what the id
        // was.  Encoding the range keeps a second attempt at the same recovery
        // from colliding with a different one in the archive.
        let plan_id = format!("realm-recovery-{realm_id}-{realm_sub_id}-{own_head}-{target}")
            .into_bytes();
        let archived_rows = self.archive(&plan_id, &plan).await?;
        let deleted_rows = self.delete(&plan, fence).await?;
        // The recovery path needs this as much as the participation one: it
        // deletes the same rows and would destroy the same only copies.
        self.restore_rewritten_rows(recording, &plan, target, fence, head_ref.chain_epoch().get())
            .await?;

        Ok(RealmSelfRollbackReport {
            own_head,
            target,
            planned_rows,
            archived_rows,
            deleted_rows,
        })
    }
}

#[async_trait::async_trait]
impl<Hash: Q256BitHash>
    psy_node_core::store::realm_self_rollback::RealmRollbackParticipation<Hash>
    for ScyllaRealmRollbackExecutor
{
    async fn take_part_in_rollback(
        &self,
        recording: &RealmCommitRecording<Hash>,
        realm_id: u32,
        realm_sub_id: u16,
        head: &CanonicalChainRef<Hash>,
        target: u64,
    ) -> anyhow::Result<psy_node_core::store::realm_self_rollback::RealmSelfRollbackReport> {
        use psy_node_core::store::realm_self_rollback::RealmSelfRollbackReport;

        let Some(view) = recording.participant_view() else {
            anyhow::bail!(
                "this Realm cannot take part in a rollback without a view of the Coordinator's \
                 control row; it can only recover after the fact"
            );
        };
        // Derived rather than agreed.  Every participant archives into its own
        // keyspace, so the id only has to be stable for this Realm and this
        // range; correlating the pieces afterwards is what the (target, head)
        // pair in the receipts and the rollback event are for.
        let plan_id =
            format!("realm-{realm_id}-{realm_sub_id}-{}-{target}", head.checkpoint().checkpoint_id().get())
                .into_bytes();
        let report = self
            .roll_back(recording, realm_id, realm_sub_id, head, target, &plan_id, view)
            .await?;
        Ok(RealmSelfRollbackReport {
            own_head: report.head,
            target: report.target,
            planned_rows: report.planned_rows,
            archived_rows: report.archived_rows,
            deleted_rows: report.deleted_rows,
        })
    }

    async fn confirm_target_reached(
        &self,
        recording: &RealmCommitRecording<Hash>,
        realm_id: u32,
        realm_sub_id: u16,
        search_head: &CanonicalChainRef<Hash>,
        target: u64,
    ) -> anyhow::Result<()> {
        use psy_node_core::store::realm_self_rollback::RealmSelfRollback;

        let Some(view) = recording.participant_view() else {
            anyhow::bail!("this Realm cannot file a verify receipt without a participant view");
        };
        // Undoes whatever is left, and does nothing when nothing is -- which is
        // the ordinary case by the time this runs.
        let report = self
            .recover_own_state_to(recording, realm_id, realm_sub_id, search_head, target)
            .await?;
        if report.changed_anything() {
            tracing::warn!(
                "[REALM_ROLLBACK] {} rows above {target} were still here when the verify receipt \
                 was due; they have been undone",
                report.deleted_rows
            );
        }
        crash_realm_step("BeforeVerifyReceipt");
        view.file_verify_receipt(&VerifyReceipt::new(
            RollbackParticipant::new(AuthorityScope::Realm {
                realm_id,
                realm_sub_id,
            }),
            target,
            super::rollback_executor::plan_digest(
                format!("realm-{realm_id}-{realm_sub_id}-verify-{target}").as_bytes(),
            ),
        ))
        .await?;
        Ok(())
    }
}

/// Wait until the rollback has reached a phase this Realm may act on.
///
/// At-or-past, not exactly-equal.  The Coordinator guarantees its own
/// consistency and does not wait for Realms; it publishes a path and each Realm
/// walks it at its own pace.  So by the time a Realm looks, the phase it needed
/// has usually gone by, and insisting on the exact one made a Realm able to take
/// part only in a rollback it happened to be in step with.
///
/// Idle counts as past everything.  A rollback is never abandoned once
/// requested, so a Realm that already joined sees Idle only after the rollback
/// it joined has finished -- and everything it still owes is in its own
/// keyspace, which the Coordinator finishing can only have authorised more of.
///
/// The deadline remains for the one case that is neither: a rollback that has
/// not reached this step and is not moving.  A Realm blocked there is not
/// keeping up with anything and should say so rather than sit.
async fn wait_for_phase<Hash: Q256BitHash>(
    view: &dyn RollbackParticipantView<Hash>,
    head: &CanonicalChainRef<Hash>,
    expected: &str,
    required: u8,
) -> anyhow::Result<()> {
    let started = std::time::Instant::now();
    let limit = super::barrier_wait_limit();
    loop {
        let phase = view.observe_phase(head).await?;
        if phase.permits_work_of(required) {
            return Ok(());
        }
        if started.elapsed() >= limit {
            anyhow::bail!(
                "this Realm waited {}s to reach {expected} and the rollback has published \
                 {phase:?}",
                limit.as_secs()
            );
        }
        tokio::time::sleep(super::BARRIER_POLL).await;
    }
}

/// Abort at a named point in a Realm's part of a rollback.
///
/// The Realm has no phase transitions of its own to hang a hook on: it observes
/// the phases the Coordinator publishes and files receipts that let the
/// barriers close.  So the points are named after what it is about to do, and
/// the interesting ones are the gaps -- a Realm that dies after observing
/// DELETING and before filing its verify receipt leaves the Coordinator waiting
/// on a barrier that can never close, which no Coordinator-side crash can
/// produce.
fn crash_realm_step(point: &str) {
    super::rollback_executor::crash_if_named("PSY_ROLLBACK_REALM_CRASH_AT", point);
}
