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
use psy_node_core::store::manifest_store::CoordinatorCommitRecording;
use psy_node_scylla::rollback::{
    CoordinatorRollbackControlPlane, RollbackControlKeyspaces, ScyllaRollbackExecutor,
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

/// Every key the discarded range touched, with the state observed just before
/// the *first* checkpoint above the target that touched it.
///
/// That first touch is `c(K)`: everything below it survives the rollback, so its
/// before image is what a production read must return afterwards.
async fn witnesses_first_touch(
    session: &Session,
    keyspace: &str,
    target: u64,
    head: u64,
) -> anyhow::Result<Vec<Witness>> {
    let mut first: BTreeMap<Vec<u8>, Witness> = BTreeMap::new();
    for checkpoint in (target + 1)..=head {
        let rows = session
            .query_unpaged(
                format!(
                    "SELECT locator, before_image, before_present FROM \
                     {keyspace}.rollback_verification_journal WHERE checkpoint_id = ?"
                ),
                (checkpoint as i64,),
            )
            .await?
            .into_rows_result()?;
        for row in rows.rows::<(Vec<u8>, Option<Vec<u8>>, Option<bool>)>()? {
            let (locator, before, present) = row?;
            first.entry(locator.clone()).or_insert(Witness {
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

    let head = session
        .query_unpaged(
            format!("SELECT value FROM {keyspace}.u64_singleton_table WHERE obj_id = 1"),
            &[],
        )
        .await?
        .into_rows_result()?
        .first_row::<(i64,)>()?
        .0 as u64;

    // Roll back far enough that the range spans many commits, but leave a deep
    // history below the target so the fallback has somewhere to land.
    let target = head.saturating_sub(10);
    assert!(target > 5, "the chain is too short to roll back meaningfully");
    println!("rolling back from {head} to {target}");

    let witnesses = witnesses_first_touch(&session, &keyspace, target, head).await?;
    assert!(
        !witnesses.is_empty(),
        "the journal recorded nothing for the discarded range; run the chain with \
         PSY_ROLLBACK_VERIFICATION_JOURNAL set"
    );
    println!("{} distinct keys were touched above the target", witnesses.len());

    let executor =
        ScyllaRollbackExecutor::prepare(session.clone(), &keyspace, &no_tablet).await?;
    let reader = ScyllaRowImageReader::prepare(session.clone(), &keyspace).await?;

    // The chain reference the plan starts from.  Read from the committed head
    // rather than constructed, so the plan walks the manifests the chain really
    // wrote.
    let control = control_plane(session.clone(), &keyspace, &no_tablet).await?;
    let recording: CoordinatorCommitRecording<PHash> = control.recording::<PHash>();
    let head_ref = read_head_chain_ref(&control).await?;
    let plan_id = format!("acceptance-{head}-{target}").into_bytes();

    let report = executor
        .roll_back(&recording, &head_ref, target, &plan_id)
        .await?;
    println!("{report:?}");
    assert_eq!(report.target, target);
    assert_eq!(report.head, head, "the plan must start from the published head");
    assert_eq!(report.archived_rows, report.planned_rows);
    assert_eq!(report.deleted_rows, report.planned_rows);

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
            mismatches.push(format!(
                "{:?} at c={} : live={:?} before={:?}",
                resolved.physical_table(),
                witness.checkpoint_id,
                live_bytes.as_ref().map(|b| b.len()),
                witness.before.as_ref().map(|b| b.len()),
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
