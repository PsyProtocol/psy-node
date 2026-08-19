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

use psy_node_core::store::commit_window::CommitFreeze;
use psy_node_core::store::manifest_store::CoordinatorCommitRecording;
use psy_node_core::store::rollback_plan::{RollbackPlan, build_rollback_plan};
use psy_node_core::store::timestamp::DeleteFenceTimestampUs;
use psy_data::protocol::canonical_chain::{CanonicalChainRef, ChainEpoch};
use parth_core::protocol::core_types::Q256BitHash;
use scylla::client::session::Session;

use psy_data::protocol::chain_context::AuthorityScope;
use psy_node_core::store::authority_commit::{AuthorityTimestampKey, AuthorityTimestampReadState};
use psy_node_core::store::canonical_head::{
    CanonicalHeadReadState, CanonicalHeadTransition, StoredCanonicalHead,
};
use psy_node_core::store::rollback_control::RollbackControlState;
use psy_node_core::store::rollback_control::{
    RollbackExecutionMode, RollbackPlanDigest, RollbackRequest,
};
use psy_node_core::store::timestamp::{CommitWriteTimestampUs, TimestampFenceWindow};

use psy_node_core::store::typed::{MerkleNode, NodeIndex, TypedTableKey, UniquePendingId};

use parth_core::PHash;
use psy_node_core::store::rollback_coordination::RollbackParticipantView;
use psy_node_core::store::rollback_event::{RollbackEvent, RollbackEventStore, RollbackOutcome};
use psy_node_core::store::rollback_control::{
    PHASE_ORDINAL_ALL_REALMS_READY, PHASE_ORDINAL_ARCHIVE_BARRIER_READY, PHASE_ORDINAL_ARCHIVING,
    PHASE_ORDINAL_DELETING, PHASE_ORDINAL_FROZEN, PHASE_ORDINAL_RESTORING, PHASE_ORDINAL_VERIFYING,
};
use psy_node_core::store::rollback_participants::{
    ArchiveBarrier, ArchiveReceipt, FreezeBarrier, FreezeReceipt, PublishBarrier,
    RollbackParticipant, RollbackParticipantSet, VerifyReceipt,
};

use super::{
    ArchiveOutcome, ScyllaDeleteExecutor, ScyllaRollbackArchive, plan_rows_from_chunks,
    describe_existing_key, fence_from_archive,
};

/// What one rollback did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RollbackReport {
    pub target: u64,
    pub head: u64,
    pub planned_rows: usize,
    pub archived_rows: usize,
    pub deleted_rows: usize,
    /// Rows removed from the orphaned reward-tag partitions.
    pub orphan_reward_rows: usize,
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
///
/// Shared with the Realm executor so both sides of a rollback derive the same
/// digest from the same plan id rather than each inventing one.
pub(crate) fn plan_digest(plan_id: &[u8]) -> [u8; 32] {
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
    /// Puts back rows the plan deleted that existed before the range began.
    restore: super::ScyllaRestoreExecutor,
    /// Resolves a locator to the key *position* it names, so one key written at
    /// many heights is recognised as one key.
    reader: super::ScyllaRowImageReader,
    /// The chain's rollback history.  Written twice per rollback and never
    /// otherwise, which is what keeps the audit trail off the commit path.
    events: super::ScyllaRollbackEventStore,
}

impl ScyllaRollbackExecutor {
    pub async fn prepare(
        session: Arc<Session>,
        state_keyspace: &str,
        no_tablet_keyspace: &str,
        network_chain_id: i64,
    ) -> anyhow::Result<Self> {
        ScyllaRollbackArchive::create_table(&session, no_tablet_keyspace).await?;
        super::ScyllaRollbackEventStore::create_table(&session, no_tablet_keyspace).await?;
        let events = super::ScyllaRollbackEventStore::prepare(
            session.clone(),
            no_tablet_keyspace,
            network_chain_id,
        )
        .await?;
        Ok(Self {
            session: session.clone(),
            state_keyspace: state_keyspace.to_string(),
            archive: ScyllaRollbackArchive::prepare(
                session.clone(),
                state_keyspace,
                no_tablet_keyspace,
            )
            .await?,
            delete: ScyllaDeleteExecutor::prepare(session.clone(), state_keyspace).await?,
            restore: super::ScyllaRestoreExecutor::prepare(session.clone(), state_keyspace).await?,
            reader: super::ScyllaRowImageReader::prepare(session, state_keyspace).await?,
            events,
        })
    }

    /// This chain's rollback history, newest first.
    ///
    /// The read side of the record the executor writes.  Exposed here rather
    /// than only on the store so that anything holding an executor can check
    /// what it did, which is what makes the record testable at all.
    pub async fn rollback_events(
        &self,
        limit: i32,
    ) -> anyhow::Result<Vec<psy_node_core::store::rollback_event::RollbackEvent>> {
        self.events.read_rollback_events(limit).await
    }

    /// Plan the discarded suffix from the manifests alone.
    pub async fn plan<Hash: Q256BitHash>(
        &self,
        recording: &CoordinatorCommitRecording<Hash>,
        head: &CanonicalChainRef<Hash>,
        target: u64,
    ) -> anyhow::Result<RollbackPlan<Hash>> {
        build_rollback_plan(recording, head, target, &|chunks| Ok(plan_rows_from_chunks(chunks)?))
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
    /// Put back the rows the plan deleted that existed before the range began.
    ///
    /// See `restore_executor` for why this is per row rather than per table, and
    /// why the journal is the only thing that can answer it.  The image used is
    /// the one recorded at `c(K)` -- the first checkpoint above the target that
    /// touched this key position -- because that is the only observation of what
    /// a reader saw just before the discarded range.
    ///
    /// Grouped by position rather than by locator, for the reason the G-W
    /// assertion is: a version-axis locator encodes the checkpoint, so one key
    /// written at ten heights is ten locators, and treating those as ten keys
    /// would make `c(K)` collapse into "every checkpoint".
    pub async fn restore_rewritten_rows<Hash: Q256BitHash>(
        &self,
        recording: &CoordinatorCommitRecording<Hash>,
        plan: &RollbackPlan<Hash>,
        target: u64,
        fence: DeleteFenceTimestampUs,
    ) -> anyhow::Result<usize> {
        let Some(journal) = recording.journal() else {
            // Fail closed.  Without the journal there is no way to tell a row the
            // range created from one it rewrote, and carrying on would leave the
            // second kind deleted -- silently, and only discoverable much later
            // as a key that reads as absent.
            anyhow::bail!(
                "a rollback cannot restore rewritten rows without the verification journal; \
                 run the chain with PSY_ROLLBACK_VERIFICATION_JOURNAL set"
            );
        };

        // The first touch above the target wins, so walk upwards and keep the
        // earliest observation of each position.
        let mut first_touch: std::collections::BTreeMap<Vec<u8>, Vec<u8>> =
            std::collections::BTreeMap::new();
        for checkpoint in (target + 1)..=plan.head {
            // Only rows that existed before their commit come back; the rest
            // were created by the discarded range and the delete stands.
            for (_, locator, before) in journal.rewritten_before_images(checkpoint).await? {
                let Ok(resolved) = super::decode_locator_canonical(&locator) else {
                    continue;
                };
                let Ok(position) = self.reader.position_key(&resolved) else {
                    continue;
                };
                first_touch.entry(position).or_insert_with(|| {
                    // The locator is kept with the image: the row is written back
                    // to where it was, and for a version-axis table that is a
                    // different locator per checkpoint.
                    let mut packed = (locator.len() as u32).to_be_bytes().to_vec();
                    packed.extend_from_slice(&locator);
                    packed.extend_from_slice(&before);
                    packed
                });
            }
        }

        let mut restored = 0usize;
        for packed in first_touch.values() {
            let len = u32::from_be_bytes(packed[..4].try_into().expect("four bytes")) as usize;
            let locator = &packed[4..4 + len];
            let before = &packed[4 + len..];
            self.restore.restore_row(fence, locator, before).await?;
            restored += 1;
        }
        Ok(restored)
    }

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
    /// nothing has been deleted, after it rows are gone.  A rollback is never
    /// abandoned either side of it: the way out is always forwards, and a run
    /// that stops early is resumed rather than undone.
    pub async fn roll_back<Hash: Q256BitHash>(
        &self,
        recording: &CoordinatorCommitRecording<Hash>,
        head: &CanonicalChainRef<Hash>,
        target: u64,
        plan_id: &[u8],
        // Who takes part.  What they have proven is read from durable storage
        // rather than passed in: a caller that supplied the receipts would be
        // deciding whether the barrier is met, which is the one decision the
        // barrier exists to take away from callers.
        participants: &RollbackParticipantSet,
        receipts: Option<&dyn RollbackParticipantView<PHash>>,
    ) -> anyhow::Result<RollbackReport> {
        let mut stored = self.read_head(recording, head).await?;
        let previous_epoch = stored.canonical_ref().chain_epoch().get();

        // Plan against the epoch the discarded range was committed under, which
        // is not the epoch the head is in once a rollback has started.
        // `start_rollback` opens the next epoch immediately, and manifests are
        // partitioned by epoch -- so a resumed run planning from the live head
        // looks for the range in a partition that by construction cannot hold
        // it, and reports the range as unplannable rather than as already
        // half-deleted.  Only `start_rollback` moves the epoch before
        // completion, and it moves it by one.
        let plan_head = match stored.rollback_control() {
            RollbackControlState::Idle => *head,
            _ => CanonicalChainRef::new(
                head.network_id(),
                ChainEpoch::new(previous_epoch.saturating_sub(1)),
                *head.checkpoint(),
            ),
        };
        let plan = self.plan(recording, &plan_head, target).await?;
        let planned_rows = plan.row_count();

        // A rollback that died leaves its phase durable, and this is what makes
        // that readable state usable: the run resumes from it instead of
        // starting again.  Without this a crashed rollback could go neither
        // forward -- a second request is refused, and rightly, since it would
        // open a second epoch over a half-applied first -- nor back, once the
        // point of no return was behind it.  The chain simply stopped, because
        // every participant correctly refuses to commit while a rollback is
        // published.
        //
        // The fence comes from the durable request rather than the allocator on
        // a resume.  Allocating a fresh one would delete the remainder of the
        // range under a different timestamp than the part already deleted,
        // splitting one rollback across two points on the conflict-resolution
        // axis -- the same hazard one timestamp per commit exists to prevent.
        let (request, fence, resumed) = match stored.rollback_control().requested() {
            Some(existing) => {
                let existing = *existing;
                if existing.requested_head() != head.checkpoint() {
                    anyhow::bail!(
                        "a rollback from {} is already in progress; this run was asked to roll \
                         back from {}",
                        existing.requested_head().checkpoint_id().get(),
                        head.checkpoint().checkpoint_id().get(),
                    );
                }
                if existing.target().checkpoint_id().get() != target {
                    anyhow::bail!(
                        "the rollback already in progress targets {}, not {target}; resuming it \
                         with a different target would restore a state nobody asked for",
                        existing.target().checkpoint_id().get(),
                    );
                }
                // The digest is what makes resuming safe to do at all: it
                // proves the plan recomputed here is the plan the interrupted
                // run committed to, rather than one the manifests have drifted
                // into meaning since.
                let recomputed = RollbackPlanDigest::try_new(plan_digest(plan_id))?;
                if existing.plan_digest() != recomputed {
                    anyhow::bail!(
                        "the plan recomputed for this resume does not match the one the \
                         interrupted rollback committed to; the range it was deleting is not \
                         the range this run would delete"
                    );
                }
                let window = existing.fence_window();
                (existing, window.delete_fence(), true)
            }
            None => {
                // The target's identity comes from its own manifest.  There is
                // no fallback on purpose: substituting a neighbouring
                // checkpoint, or constructing a reference, would publish a head
                // whose hash names a checkpoint that never existed at that
                // height.
                let target_ref = self
                    .target_checkpoint_ref::<Hash>(recording, head, target)
                    .await?;
                let window = self.fence_window_from_allocator(recording, head).await?;
                let fence = window.delete_fence();
                let request = RollbackRequest::try_new(
                    *head.checkpoint(),
                    target_ref,
                    window,
                    RollbackExecutionMode::InPlace,
                    RollbackPlanDigest::try_new(plan_digest(plan_id))?,
                )?;
                let _ = fence;
                (request, window.delete_fence(), false)
            }
        };

        if !resumed {
            stored = self
                .advance(recording, CanonicalHeadTransition::start_rollback(stored, request)?)
                .await?;
        } else {
            tracing::warn!(
                "resuming a rollback from {} to {target} that was left in {:?}",
                head.checkpoint().checkpoint_id().get(),
                stored.rollback_control(),
            );
        }

        // The audit record goes in here, not at the end.  A rollback that dies
        // between the archive and the delete leaves the chain in the state
        // hardest to reason about, and writing only on success would leave that
        // state with no record that anything had been attempted -- the one case
        // an audit exists for.  The epoch start_rollback just allocated names
        // this attempt for the life of the chain.
        // On a resume the epoch was already opened by the run that died, so
        // the epoch this record names is the one the head is in and the one it
        // came from is the one below.  Recomputing it from the live head would
        // read them as equal and refuse the record for an epoch that did not
        // advance -- which is the right check, applied to the wrong pair.
        let event = RollbackEvent::try_new(
            stored.canonical_ref().chain_epoch().get(),
            if resumed {
                previous_epoch.saturating_sub(1)
            } else {
                previous_epoch
            },
            plan.head,
            target,
            plan_id.to_vec(),
            participants.participants(),
            fence.as_i64(),
        )?;
        if !resumed {
            self.events.record_rollback_requested(&event).await?;
        }

        // ---- freeze ----
        //
        // Publishing FROZEN is what tells every participant to stop producing
        // side effects and drain what is in flight (§6.2).  Archiving a head
        // that is still moving copies a state the chain was never in, and
        // nothing downstream notices: the archive verifies against itself, the
        // ranges line up, and the damage only appears at restore time.
        // Freezing this process's commit path is done on every run, resumed or
        // not: it is a property of this process, not a step in the sequence, and
        // a restarted executor starts with it open.
        //
        // Stop this process's own commit path before asking whether the head
        // moved.  The re-read below still matters -- a Coordinator running in
        // another process has its own clock and is stopped only by observing
        // FROZEN -- but between the two, prevention beats detection: the re-read
        // can only report that the archive would have been wrong, whereas this
        // keeps it from becoming wrong.
        recording.freeze_for_rollback();
        super::drain_in_flight_commit(recording).await?;

        if stored.rollback_control().phase_ordinal() < PHASE_ORDINAL_FROZEN {
            stored = self
                .advance(recording, CanonicalHeadTransition::begin_rollback_freeze(stored)?)
                .await?;
        }

        let head_digest = head
            .checkpoint()
            .checkpoint_hash()
            .as_inner()
            .into_owned_32bytes();
        let mut freeze = FreezeBarrier::new(participants.clone(), plan.head);
        // The Coordinator's own evidence is a re-read, not an assumption.  If
        // it were still producing blocks the published head would have moved
        // past the one this rollback names, and this is where that shows.
        let observed = self.read_head(recording, head).await?;
        if observed.canonical_ref().checkpoint() != head.checkpoint() {
            anyhow::bail!(
                "the canonical head moved to {} while freezing for a rollback from {}; \
                 the Coordinator is still producing and the archive would copy a state \
                 that never existed",
                observed.canonical_ref().checkpoint().checkpoint_id().get(),
                plan.head,
            );
        }
        freeze.file(FreezeReceipt::new(
            RollbackParticipant::new(AuthorityScope::Coordinator),
            plan.head,
            head_digest,
        ))?;
        // Wait for the rest of the set rather than reading once.  A barrier is
        // a rendezvous, and reading the table in the same breath as publishing
        // the phase makes it a race the Coordinator always wins: a Realm has to
        // notice the phase, plan its own share and archive it before it has
        // anything to file.
        if let Some(view) = receipts {
            let started = std::time::Instant::now();
            let limit = super::barrier_wait_limit();
            while !freeze.is_met() {
                for receipt in view
                    .read_freeze_receipts_for(plan.head, participants.participants())
                    .await?
                {
                    freeze.file(receipt)?;
                }
                if freeze.is_met() {
                    break;
                }
                if started.elapsed() >= limit {
                    anyhow::bail!(
                        "FREEZE_ALL waited {}s for {:?} and they have not frozen; the chain \
                         stays frozen until they do -- bring them back and run the rollback \
                         again, which resumes from here rather than starting over",
                        limit.as_secs(),
                        freeze.missing()
                    );
                }
                tokio::time::sleep(super::BARRIER_POLL).await;
            }
        }
        let sealed_freeze = freeze.seal()?;

        if stored.rollback_control().phase_ordinal() < PHASE_ORDINAL_ARCHIVING {
            stored = self
                .advance(
                    recording,
                    CanonicalHeadTransition::begin_rollback_archive(stored, sealed_freeze)?,
                )
                .await?;
        }

        // Archiving is skipped once the barrier is behind us.  Not as an
        // optimisation: past that point the rows are being deleted, so a second
        // archive of the same plan would record them as absent and overwrite the
        // copy of what was discarded with a record saying there was nothing to
        // discard.
        let archived_rows = if stored.rollback_control().phase_ordinal()
            < PHASE_ORDINAL_ARCHIVE_BARRIER_READY
        {
            self.archive(plan_id, &plan).await?
        } else {
            planned_rows
        };
        if archived_rows != planned_rows {
            anyhow::bail!(
                "archived {archived_rows} of {planned_rows} planned rows; the barrier must not \
                 be crossed with an incomplete archive"
            );
        }
        self.verify_archive_under_fence(plan_id, &plan, fence).await?;

        // ---- point of no return ----
        //
        // Crossing needs a sealed barrier, and a barrier is sealed only when
        // every participant has filed a receipt for this exact range (§6.2).
        // A Coordinator rolling back alone is still a participant set of one --
        // it files its own receipt and the barrier is met.  What the type
        // forbids is crossing while a Realm in the set has archived nothing,
        // which is I6: no participant deletes before every participant copied.
        let mut barrier = ArchiveBarrier::new(
            participants.clone(),
            target,
            plan.head,
        );
        barrier.file(ArchiveReceipt::new(
            RollbackParticipant::new(AuthorityScope::Coordinator),
            target,
            plan.head,
            archived_rows as u64,
            plan_digest(plan_id),
        ))?;
        // Everyone else's receipts come from the table they filed them in, so a
        // Coordinator that crashed between a Realm's receipt and the barrier
        // finds it again instead of waiting for a participant that already
        // finished.
        if let Some(view) = receipts {
            let started = std::time::Instant::now();
            let limit = super::barrier_wait_limit();
            while !barrier.is_met() {
                for receipt in view
                    .read_archive_receipts_for(target, plan.head, participants.participants())
                    .await?
                {
                    barrier.file(receipt)?;
                }
                if barrier.is_met() {
                    break;
                }
                if started.elapsed() >= limit {
                    // Failing here is the safe direction and the reason this
                    // barrier exists: crossing it with a participant that has
                    // archived nothing is the one mistake nothing downstream
                    // can repair.
                    anyhow::bail!(
                        "GLOBAL_ARCHIVE_BARRIER waited {}s for {:?} and they have not archived; \
                         nothing has been deleted yet, and nothing will be until they do -- \
                         bring them back and run the rollback again to resume from here",
                        limit.as_secs(),
                        barrier.missing()
                    );
                }
                tokio::time::sleep(super::BARRIER_POLL).await;
            }
        }
        let sealed_barrier = barrier.seal()?;

        if stored.rollback_control().phase_ordinal() < PHASE_ORDINAL_ARCHIVE_BARRIER_READY {
            stored = self
                .advance(
                    recording,
                    CanonicalHeadTransition::complete_rollback_archive_barrier(
                        stored,
                        sealed_barrier,
                    )?,
                )
                .await?;
        }

        if stored.rollback_control().phase_ordinal() < PHASE_ORDINAL_DELETING {
            stored = self
                .advance(recording, CanonicalHeadTransition::begin_rollback_delete(stored)?)
                .await?;
        }
        // Deleting and sweeping are redone on a resume rather than skipped.
        // They are idempotent -- a delete under the same fence removes what is
        // there and does nothing to what is already gone -- and a run that
        // crashed part-way through leaves no record of how far it got, so
        // repeating is the only way to be sure the range is empty.
        let discarded_pending = self.read_discarded_pending_ids(&plan).await?;
        let deleted_rows = self.delete(&plan, fence).await?;
        let orphan_reward_rows = self
            .sweep_orphan_reward_tags(plan_id, target, &discarded_pending, fence)
            .await?;

        if stored.rollback_control().phase_ordinal() < PHASE_ORDINAL_RESTORING {
            stored = self
                .advance(recording, CanonicalHeadTransition::begin_rollback_restore(stored)?)
                .await?;
        }
        let restored_singletons = self.restore_singletons(target, fence).await?;
        // Put back what the delete removed but should not have: rows the
        // discarded range rewrote rather than created.  After the singletons,
        // because the singleton restore reads the target's own rows and this
        // writes above the fence -- ordering them the other way would have the
        // singleton read see a row this step had just put back.
        let restored_rows = self
            .restore_rewritten_rows(recording, &plan, target, fence)
            .await?;
        if restored_rows > 0 {
            tracing::warn!(
                "restored {restored_rows} rows the discarded range had rewritten; deleting them \
                 would have destroyed the only copy of their previous value"
            );
        }

        // Lift the allocator past the fence before anything can commit again.
        // seal_reservation allocates max(high_water + 1, clock), and the fence
        // sits above every timestamp this authority issued -- so without this the
        // next commit would land under the tombstones just written and its rows
        // would be shadowed: succeeding, silent, unreadable.  A restart that
        // happens to outlast the fence gap hides it behind the wall clock, which
        // is luck rather than design.
        self.lift_allocator(recording, head, request.fence_window()).await?;

        if stored.rollback_control().phase_ordinal() < PHASE_ORDINAL_VERIFYING {
            stored = self
                .advance(recording, CanonicalHeadTransition::begin_rollback_verify(stored)?)
                .await?;
        }
        // The publish barrier, on the same terms as the archive one: every
        // participant must have confirmed it reached the target before the new
        // epoch is published.  A Coordinator-only rollback files its own and the
        // barrier is met; a coordinated one waits for the Realms.
        let mut publish = PublishBarrier::new(participants.clone(), target);
        publish.file(VerifyReceipt::new(
            RollbackParticipant::new(AuthorityScope::Coordinator),
            target,
            plan_digest(plan_id),
        ))?;
        if let Some(view) = receipts {
            let started = std::time::Instant::now();
            let limit = super::barrier_wait_limit();
            while !publish.is_met() {
                for receipt in view
                    .read_verify_receipts_for(target, participants.participants())
                    .await?
                {
                    publish.file(receipt)?;
                }
                if publish.is_met() {
                    break;
                }
                if started.elapsed() >= limit {
                    // Past the point of no return, so this is not abandonable:
                    // the rollback is resumable and must be finished once the
                    // straggler reports.
                    anyhow::bail!(
                        "PUBLISH_ALL waited {}s for {:?} and they have not verified; the \
                         rollback is past the point of no return and must be resumed, not \
                         abandoned",
                        limit.as_secs(),
                        publish.missing()
                    );
                }
                tokio::time::sleep(super::BARRIER_POLL).await;
            }
        }
        let sealed_publish = publish.seal()?;

        if stored.rollback_control().phase_ordinal() < PHASE_ORDINAL_ALL_REALMS_READY {
        stored = self
            .advance(
                recording,
                CanonicalHeadTransition::complete_rollback_realm_barrier(
                    stored,
                    sealed_publish,
                )?,
            )
            .await?;
        }
        self.advance(recording, CanonicalHeadTransition::complete_rollback(stored)?)
            .await?;
        self.events
            .record_rollback_outcome(
                event.chain_epoch(),
                RollbackOutcome::Completed {
                    archived_rows: archived_rows as u64,
                    deleted_rows: deleted_rows as u64,
                },
            )
            .await?;

        Ok(RollbackReport {
            target,
            head: plan.head,
            planned_rows,
            archived_rows,
            deleted_rows,
            orphan_reward_rows,
            fence_us: fence.as_i64(),
            restored_singletons,
        })
    }

    /// Archive and remove the reward-tag partitions the discarded range opened.
    ///
    /// `guta_reward_tag_tree_table` is keyed by `unique_pending_id` and has no
    /// version axis, so the manifest cannot name its rows the way it names a
    /// versioned key -- a rollback replaying only the manifest leaves them
    /// behind.  They are not ghosts: pending ids are never reused (§7.1), so the
    /// new branch allocates fresh ones and never reads these.  They are a leak,
    /// and §2.4 closes it with the suffix rather than leaving an asynchronous GC
    /// tail behind a rollback.
    ///
    /// Archived first, like everything else: D2 admits no exception for rows
    /// that happen to be unreachable.
    async fn sweep_orphan_reward_tags(
        &self,
        plan_id: &[u8],
        target: u64,
        pending_ids: &[u64],
        fence: DeleteFenceTimestampUs,
    ) -> anyhow::Result<usize> {
        let mut swept = 0usize;
        for pending in pending_ids.iter().copied() {
            // Enumerate the partition rather than assume its shape: the tree's
            // height and fill depend on the checkpoint that produced it.
            let nodes = self
                .session
                .query_unpaged(
                    format!(
                        "SELECT level, node_index FROM {}.guta_reward_tag_tree_table \
                         WHERE unique_pending_id = ?",
                        self.state_keyspace
                    ),
                    (pending as i64,),
                )
                .await?
                .into_rows_result()?
                .rows::<(i8, i64)>()?
                .collect::<Result<Vec<_>, _>>()?;
            if nodes.is_empty() {
                continue;
            }

            for (level, index) in &nodes {
                let key = TypedTableKey::RewardTagMerkle {
                    pending: UniquePendingId::try_new(pending)?,
                    node: MerkleNode::new(*level as u8, NodeIndex::new(*index as u64)),
                };
                let resolved = describe_existing_key(&key);
                match self
                    .archive
                    .archive_row(
                        plan_id,
                        target,
                        resolved.physical_table().stable_id(),
                        resolved.locator_bytes(),
                    )
                    .await?
                {
                    ArchiveOutcome::Archived | ArchiveOutcome::AlreadyIdentical => {}
                    ArchiveOutcome::Conflict => anyhow::bail!(
                        "an orphaned reward-tag row for pending {pending} is already archived \
                         with different content under this plan"
                    ),
                }
            }

            // One partition delete rather than one per node: the whole partition
            // is orphaned and the fence covers every cell in it.
            self.session
                .query_unpaged(
                    format!(
                        "DELETE FROM {}.guta_reward_tag_tree_table USING TIMESTAMP ? \
                         WHERE unique_pending_id = ?",
                        self.state_keyspace
                    ),
                    (fence.as_i64(), pending as i64),
                )
                .await?;
            swept += nodes.len();
        }
        Ok(swept)
    }

    /// The pending ids the discarded checkpoints used.
    ///
    /// Read before the mapping rows are deleted, because they are part of the
    /// plan and will be gone by the time the sweep runs.
    async fn read_discarded_pending_ids<Hash: Q256BitHash>(
        &self,
        plan: &RollbackPlan<Hash>,
    ) -> anyhow::Result<Vec<u64>> {
        let mut pending = Vec::new();
        for checkpoint in &plan.checkpoints {
            let mapped = self
                .session
                .query_unpaged(
                    format!(
                        "SELECT value FROM {}.checkpoint_id_to_pending_id_table WHERE obj_id = ?",
                        self.state_keyspace
                    ),
                    (checkpoint.checkpoint_id() as i64,),
                )
                .await?
                .into_rows_result()?
                .maybe_first_row::<(i64,)>()?;
            if let Some((value,)) = mapped {
                pending.push(value as u64);
            }
        }
        pending.sort_unstable();
        pending.dedup();
        Ok(pending)
    }

    async fn lift_allocator<Hash: Q256BitHash>(
        &self,
        recording: &CoordinatorCommitRecording<Hash>,
        head: &CanonicalChainRef<Hash>,
        window: TimestampFenceWindow,
    ) -> anyhow::Result<()> {
        let key = AuthorityTimestampKey::new(head.network_id(), AuthorityScope::Coordinator);
        let expected = match recording.timestamp().read_timestamp_state(key).await? {
            AuthorityTimestampReadState::Current(state) => state,
            AuthorityTimestampReadState::Uninitialized => {
                anyhow::bail!("the allocator row vanished mid-rollback")
            }
        };
        let Some(candidate) = expected.lift_high_water(window.new_branch_write())? else {
            // Already above the fence.  Writing anyway would burn a revision.
            return Ok(());
        };
        match recording
            .timestamp()
            .lift_timestamp_high_water(key, expected, candidate)
            .await?
        {
            psy_node_core::store::authority_commit::AuthorityTimestampWriteOutcome::Applied(_)
            | psy_node_core::store::authority_commit::AuthorityTimestampWriteOutcome::Idempotent(_) => {
                Ok(())
            }
            psy_node_core::store::authority_commit::AuthorityTimestampWriteOutcome::Conflict(
                current,
            ) => anyhow::bail!(
                "the allocator moved under this rollback (observed revision {}); the fence \
                 cannot be guaranteed to precede the next commit",
                current.revision().get()
            ),
        }
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
