//! Slice A acceptance: roll a real chain back and prove it landed on history.
//!
//! design-r1 §11.4 admits one kind of evidence.  The chain must have been built
//! by the real `commit_state()`, not seeded; the discarded range must end up in
//! the archive and out of the hot tables; and the G-W assertion must hold against
//! the verification journal, because a root check cannot distinguish "restored to
//! history" from "recomputed into something self-consistent".
//!
//! Point it at a keyspace where a journalled chain has run:
//!
//! ```text
//! PSY_ROLLBACK_LIVE_KEYSPACE=rollback_r1_verify \
//!   cargo test -p psy_node_scylla --test rollback_acceptance -- --ignored --nocapture
//! ```

use std::collections::BTreeMap;
use std::sync::Arc;

use parth_core::PHash;
use psy_core::constants::chain_id::PsyChainNetworkType;
use psy_data::protocol::canonical_chain::{CanonicalChainRef, NetworkId};
use psy_node_core::store::canonical_head::CanonicalHeadReadState;
use psy_data::protocol::chain_context::AuthorityScope;
use psy_node_core::store::manifest_store::CoordinatorCommitRecording;
use psy_node_core::store::rollback_participants::{RollbackParticipant, RollbackParticipantSet};
use psy_node_scylla::rollback::{
    CanonicalHeadNoTabletKeyspace, CoordinatorRollbackControlPlane, RollbackControlKeyspaces,
    ScyllaCanonicalHeadStore, ScyllaRollbackExecutor, ScyllaRollbackParticipantView,
    ScyllaRowImageReader, decode_locator_canonical,
};
use scylla::client::session::Session;
use scylla::client::session_builder::SessionBuilder;

fn known_nodes() -> Vec<String> {
    vec![std::env::var("PSY_SCYLLA_URL").unwrap_or_else(|_| "127.0.0.1:9042".to_string())]
}

async fn session() -> anyhow::Result<Arc<Session>> {
    Ok(Arc::new(
        SessionBuilder::new()
            .known_nodes(known_nodes().iter())
            .build()
            .await?,
    ))
}

/// One journal observation, as the assertion needs it.
struct Witness {
    checkpoint_id: u64,
    locator: Vec<u8>,
    before: Option<Vec<u8>>,
}

/// Every key *position* the discarded range touched, with the state observed
/// just before the first checkpoint above the target that touched it.
///
/// Grouping is by position, not by locator.  A version-axis locator encodes the
/// checkpoint, so one tree node written at ten heights encodes to ten locators --
/// and treating those as ten keys makes "the first checkpoint above the target
/// that touched K" collapse into "every checkpoint", which asserts the wrong
/// thing: at c the before image is the value at c-1, while after a rollback to T
/// a read returns the value at T.  Those agree only for the first touch, which is
/// exactly what `c(K)` means.
async fn witnesses_first_touch(
    session: &Session,
    keyspace: &str,
    reader: &ScyllaRowImageReader,
    target: u64,
    head: u64,
    // The branch these observations belong to.  Heights are reused after a
    // rollback, so a height discarded three times holds four branches' worth,
    // and comparing this branch's live state against a witness from a branch
    // that no longer exists fails an assertion that nothing is wrong with --
    // which is how this check started reporting GlobalUserTree mismatches on a
    // healthy chain.
    chain_epoch: u64,
) -> anyhow::Result<Vec<Witness>> {
    let mut first: BTreeMap<Vec<u8>, Witness> = BTreeMap::new();
    for checkpoint in (target + 1)..=head {
        let rows = session
            .query_unpaged(
                format!(
                    "SELECT locator, before_image, before_present FROM \
                     {keyspace}.rollback_verification_journal_by_epoch \
                     WHERE checkpoint_id = ? AND chain_epoch = ?"
                ),
                (checkpoint as i64, chain_epoch as i64),
            )
            .await?
            .into_rows_result()?;
        for row in rows.rows::<(Vec<u8>, Option<Vec<u8>>, Option<bool>)>()? {
            let (locator, before, present) = row?;
            let Ok(resolved) = decode_locator_canonical(&locator) else {
                continue;
            };
            let Ok(position) = reader.position_key(&resolved) else {
                continue;
            };
            first.entry(position).or_insert(Witness {
                checkpoint_id: checkpoint,
                locator,
                before: before.filter(|_| present.unwrap_or(false)),
            });
        }
    }
    Ok(first.into_values().collect())
}

fn network() -> NetworkId {
    NetworkId::from_network_type(PsyChainNetworkType::LocalDevnet)
}

/// The control plane, built against an already-running chain's keyspaces.
///
/// No commit window is opened here: the rollback path writes with an explicit
/// fence timestamp of its own, and borrowing a commit's window would stamp
/// tombstones with a commit's timestamp instead of one above every discarded
/// write.
async fn control_plane(
    session: Arc<Session>,
    keyspace: &str,
    no_tablet: &str,
) -> anyhow::Result<CoordinatorRollbackControlPlane> {
    let keyspaces = RollbackControlKeyspaces::try_new(keyspace, no_tablet)?;
    let clock = Arc::new(psy_node_core::store::commit_window::CommitWindowClock::new());
    CoordinatorRollbackControlPlane::prepare(session, clock, &keyspaces).await
}

/// The head the chain actually published, read rather than constructed, so the
/// plan walks the manifests it really wrote.
async fn read_head_chain_ref(
    control: &CoordinatorRollbackControlPlane,
) -> anyhow::Result<CanonicalChainRef<PHash>> {
    let recording = control.recording::<PHash>();
    match recording.canonical_head().read_canonical_head(network()).await? {
        CanonicalHeadReadState::Current(head) => Ok(*head.canonical_ref()),
        CanonicalHeadReadState::Uninitialized => {
            anyhow::bail!("the keyspace has no published canonical head to roll back from")
        }
    }
}

#[tokio::test]
#[ignore = "requires a keyspace holding a journalled chain"]
async fn a_rollback_restores_exactly_what_was_observed_before() -> anyhow::Result<()> {
    let keyspace = std::env::var("PSY_ROLLBACK_LIVE_KEYSPACE")
        .expect("set PSY_ROLLBACK_LIVE_KEYSPACE to a keyspace with a journalled chain");
    let no_tablet = format!("{keyspace}_no_tablet");
    let session = session().await?;

    // Optional, because between DELETING and RESTORING the Coordinator has no
    // head singleton at all: the delete has taken it and restore_singletons has
    // not yet put it back.  A rollback interrupted in that window is exactly the
    // one most in need of resuming, and insisting on this row made the attempt
    // fail in twenty milliseconds with "no rows were returned" -- before
    // reaching the request that still says, durably, what to finish.  Anything
    // that derives the head from this table cannot operate in that window; the
    // canonical head row can, and is read below.
    let head = session
        .query_unpaged(
            format!("SELECT value FROM {keyspace}.u64_singleton_table WHERE obj_id = 1"),
            &[],
        )
        .await?
        .into_rows_result()?
        .maybe_first_row::<(i64,)>()?
        .map(|row| row.0 as u64);

    // A rollback already under way is finished rather than replaced.  Deriving
    // a fresh target from the live head would compute one *below* the
    // interrupted rollback's, because the head has already been deleted down to
    // it -- and the executor rightly refuses to resume something towards a
    // target nobody asked for.  Finishing it is also the operator's real
    // workflow after a crash.
    // Also picks up the epoch the range being discarded was committed under,
    // by the same rule the executor plans with: `start_rollback` opens the next
    // epoch straight away, so once a rollback is under way the branch that
    // produced the range is one below the live head's.
    let (in_progress, discarded_epoch) = {
        let control = control_plane(session.clone(), &keyspace, &no_tablet).await;
        match control {
            Ok(control) => {
                let recording = control.recording::<PHash>();
                match recording.canonical_head().read_canonical_head(network()).await? {
                    CanonicalHeadReadState::Current(stored) => {
                        let epoch = stored.canonical_ref().chain_epoch().get();
                        match stored.rollback_control().requested() {
                            Some(r) => (
                                Some((
                                    r.requested_head().checkpoint_id().get(),
                                    r.target().checkpoint_id().get(),
                                )),
                                epoch.saturating_sub(1),
                            ),
                            None => (None, epoch),
                        }
                    }
                    CanonicalHeadReadState::Uninitialized => (None, 0),
                }
            }
            Err(_) => (None, 0),
        }
    };
    let (head, target) = match in_progress {
        Some((resume_head, resume_target)) => {
            println!("finishing the rollback already under way: {resume_head} -> {resume_target}");
            (resume_head, resume_target)
        }
        None => {
            let head = head.expect(
                "no rollback is in progress and the chain has no head singleton; \
                 this keyspace holds no chain to roll back",
            );
            // Roll back far enough that the range spans many commits, but leave
            // a deep history below the target so the fallback has somewhere to
            // land.  `PSY_ROLLBACK_TARGET` overrides it, for checking that a
            // *particular* write is undone -- a table only some contract calls
            // touch will not fall inside a fixed ten-checkpoint window.
            let target = std::env::var("PSY_ROLLBACK_TARGET")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| head.saturating_sub(10));
            assert!(target > 5, "the chain is too short to roll back meaningfully");
            println!("rolling back from {head} to {target}");
            (head, target)
        }
    };

    let reader = ScyllaRowImageReader::prepare(session.clone(), &keyspace).await?;
    let witnesses =
        witnesses_first_touch(&session, &keyspace, &reader, target, head, discarded_epoch).await?;
    assert!(
        !witnesses.is_empty(),
        "the journal recorded nothing for the discarded range; run the chain with \
         PSY_ROLLBACK_VERIFICATION_JOURNAL set"
    );
    println!("{} distinct key positions were touched above the target", witnesses.len());

    let executor =
        ScyllaRollbackExecutor::prepare(
            session.clone(),
            &keyspace,
            &no_tablet,
            network().chain_id() as i64,
        )
        .await?;

    // The chain reference the plan starts from.  Read from the committed head
    // rather than constructed, so the plan walks the manifests the chain really
    // wrote.
    // Read the pending ids the discarded range used before the rollback removes
    // the mapping rows, so the sweep can be checked afterwards.
    let mut discarded_pending: Vec<u64> = Vec::new();
    for checkpoint in (target + 1)..=head {
        if let Some((value,)) = session
            .query_unpaged(
                format!(
                    "SELECT value FROM {keyspace}.checkpoint_id_to_pending_id_table WHERE obj_id = ?"
                ),
                (checkpoint as i64,),
            )
            .await?
            .into_rows_result()?
            .maybe_first_row::<(i64,)>()?
        {
            discarded_pending.push(value as u64);
        }
    }
    assert!(
        !discarded_pending.is_empty() || in_progress.is_some(),
        "the discarded range has no pending mappings, so the orphan sweep would prove nothing"
    );

    let control = control_plane(session.clone(), &keyspace, &no_tablet).await?;
    let recording: CoordinatorCommitRecording<PHash> = control.recording::<PHash>();
    let head_ref = read_head_chain_ref(&control).await?;
    let plan_id = format!("acceptance-{head}-{target}").into_bytes();

    // A Coordinator rolling back alone is a participant set of one, and that
    // set is why the barriers looked correct for so long: it files its own
    // receipt and every seal succeeds immediately.  Naming the Realms is what
    // makes the barriers wait for evidence they did not produce themselves.
    //
    // `PSY_ROLLBACK_PARTICIPANT_REALMS=0:1,1:1` adds them, spelled realm:sub.
    let coordinator = RollbackParticipant::new(AuthorityScope::Coordinator);
    let mut set = vec![coordinator];
    if let Ok(spec) = std::env::var("PSY_ROLLBACK_PARTICIPANT_REALMS") {
        for entry in spec.split(',').filter(|e| !e.trim().is_empty()) {
            let (realm, sub) = entry
                .split_once(':')
                .unwrap_or_else(|| panic!("participant {entry} is not realm:sub"));
            set.push(RollbackParticipant::new(AuthorityScope::Realm {
                realm_id: realm.trim().parse().expect("realm id"),
                realm_sub_id: sub.trim().parse().expect("realm sub id"),
            }));
        }
    }
    println!("participant set: {} member(s)", set.len());
    let participants = RollbackParticipantSet::try_new(set)?;

    // The receipt view.  Passing None left every barrier reading nothing and
    // sealing on the Coordinator's own receipt, which is a barrier in name
    // only once anyone else is in the set.
    let head_reader = ScyllaCanonicalHeadStore::prepare(
        session.clone(),
        CanonicalHeadNoTabletKeyspace::try_new(&no_tablet)?,
    )
    .await?;
    let view = ScyllaRollbackParticipantView::<PHash>::prepare(
        session.clone(),
        &no_tablet,
        network().chain_id() as i64,
        std::sync::Arc::new(head_reader),
    )
    .await?;
    // Verification that can only run in the same process as the rollback it
    // checks cannot be repeated when it fails, which is exactly when its detail
    // is needed.  This runs the assertion alone against a chain already rolled
    // back.
    if std::env::var("PSY_ROLLBACK_VERIFY_ONLY").is_err() {
        let report = executor
            .roll_back(&recording, &head_ref, target, &plan_id, &participants, Some(&view))
            .await?;
        println!("{report:?}");
        assert_eq!(report.target, target);
        // Against a live chain the head moves between the test reading it and
        // the executor planning from the manifests, so the plan legitimately
        // covers more than the test saw.  The dangerous direction is the other
        // one: a plan starting *below* the published head leaves rows above the
        // target that nothing will ever delete.
        assert!(
            report.head >= head,
            "the plan must not start below the published head: planned from {} but {head} was \
             already published",
            report.head
        );
        assert_eq!(report.archived_rows, report.planned_rows);
        assert_eq!(report.deleted_rows, report.planned_rows);

        // The audit record has to agree with what actually happened.  A history
        // that merely exists is worth nothing: the whole reason to keep one is
        // to be believed later, by someone who was not here and cannot check.
        let events = executor.rollback_events(1).await?;
        let recorded = events
            .first()
            .expect("a completed rollback leaves a record of itself");
        assert_eq!(recorded.head(), report.head);
        assert_eq!(recorded.target(), target);
        assert_eq!(recorded.discarded_checkpoints(), report.head - target);
        assert_eq!(
            recorded.outcome(),
            psy_node_core::store::rollback_event::RollbackOutcome::Completed {
                archived_rows: report.archived_rows as u64,
                deleted_rows: report.deleted_rows as u64,
            },
            "the record must say what the rollback did, not what it was asked to do"
        );
        assert!(
            recorded.includes(psy_node_core::store::rollback_participants::RollbackParticipant::new(
                psy_data::protocol::chain_context::AuthorityScope::Coordinator
            )),
            "the Coordinator took part in its own rollback and the record must say so"
        );
        assert_eq!(recorded.plan_id(), plan_id.as_slice());
        println!(
            "recorded as epoch {} (was {}), {} checkpoints discarded",
            recorded.chain_epoch(),
            recorded.previous_epoch(),
            recorded.discarded_checkpoints()
        );
    }

    // G-W: every key the range touched must now read back as it was observed
    // before the first commit above the target that wrote it.
    let mut mismatches = Vec::new();
    let mut checked = 0usize;
    for witness in &witnesses {
        let Ok(resolved) = decode_locator_canonical(&witness.locator) else {
            continue;
        };
        let live = match reader.read_as_of(&resolved, target).await {
            Ok(live) => live,
            Err(_) => continue,
        };
        checked += 1;
        let live_bytes = live.as_ref().map(|image| image.canonical_bytes());
        if live_bytes != witness.before {
            // The locator is what makes a mismatch investigable: without it
            // the report names a table and a height, and the row it is actually
            // talking about cannot be found again.
            mismatches.push(format!(
                "{:?} at c={} key={} : live={:?} before={:?}",
                resolved.physical_table(),
                witness.checkpoint_id,
                hex::encode(&witness.locator),
                live_bytes.as_ref().map(hex::encode),
                witness.before.as_ref().map(hex::encode),
            ));
        }
    }
    println!("G-W checked {checked} keys");
    assert!(checked > 0, "no key could be checked, so the assertion proved nothing");
    assert!(
        mismatches.is_empty(),
        "G-W failed for {} of {checked} keys:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );

    // The orphaned reward-tag partitions are gone.  They are keyed by pending id
    // with no version axis, so nothing in the manifest names them and a rollback
    // that only replayed the manifest would leave them behind -- a leak rather
    // than a ghost, since pending ids are never reused, but §2.4 closes it with
    // the suffix instead of leaving an asynchronous GC tail.
    let mut orphan_rows = 0i64;
    for pending in &discarded_pending {
        orphan_rows += session
            .query_unpaged(
                format!(
                    "SELECT count(*) FROM {keyspace}.guta_reward_tag_tree_table \
                     WHERE unique_pending_id = ?"
                ),
                (*pending as i64,),
            )
            .await?
            .into_rows_result()?
            .first_row::<(i64,)>()?
            .0;
    }
    assert_eq!(
        orphan_rows, 0,
        "the discarded range's reward-tag partitions still hold {orphan_rows} rows"
    );
    println!(
        "the discarded range's {} pending ids hold no reward-tag rows",
        discarded_pending.len()
    );

    // The head singleton really moved back.
    let restored_head = session
        .query_unpaged(
            format!("SELECT value FROM {keyspace}.u64_singleton_table WHERE obj_id = 1"),
            &[],
        )
        .await?
        .into_rows_result()?
        .first_row::<(i64,)>()?
        .0 as u64;
    assert_eq!(restored_head, target, "the latest checkpoint singleton was not restored");

    Ok(())
}
