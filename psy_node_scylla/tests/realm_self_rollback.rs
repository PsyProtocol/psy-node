//! Undoing a Realm's own committed state, against a real Realm keyspace.
//!
//! The case this covers is the one an idle chain never reaches: a Realm that
//! actually committed something inside a range the Coordinator later discarded.
//! Until that state is undone the Coordinator and the Realm disagree about the
//! Realm's root forever -- the Coordinator reports the last change it still
//! knows about, the Realm reports the discarded one, and every sync fails.
//!
//! ```text
//! PSY_ROLLBACK_REALM_KEYSPACE=realm_0 PSY_ROLLBACK_REALM_TARGET=65 \
//!   cargo test -p psy_node_scylla --test realm_self_rollback -- --ignored --nocapture
//! ```

use std::sync::Arc;

use parth_core::PHash;
use psy_core::constants::chain_id::PsyChainNetworkType;
use psy_data::protocol::canonical_chain::{
    CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef, NetworkId,
};
use psy_node_core::store::realm_commit_recording::RealmCommitRecording;
use psy_node_core::store::realm_self_rollback::RealmSelfRollback;
use psy_node_scylla::core::ScyllaCoreStore;
use psy_node_scylla::rollback::{RealmRollbackControlPlane, ScyllaRealmRollbackExecutor};
use parth_core::pgoldilocks::PoseidonHasher;

const REALM_ID: u32 = 0;
/// The deployment runs realms with sub id 1; a test guessing 0 reads a partition
/// nothing ever wrote and concludes the Realm committed nothing.
const REALM_SUB_ID: u16 = 1;

fn known_nodes() -> Vec<String> {
    vec![std::env::var("PSY_SCYLLA_URL").unwrap_or_else(|_| "127.0.0.1:9042".to_string())]
}

fn network() -> NetworkId {
    NetworkId::from_network_type(PsyChainNetworkType::LocalDevnet)
}

#[tokio::test]
#[ignore = "requires a Realm keyspace holding state above a discarded target"]
async fn a_realm_gives_back_what_it_wrote_above_the_target() -> anyhow::Result<()> {
    let keyspace = std::env::var("PSY_ROLLBACK_REALM_KEYSPACE")
        .expect("set PSY_ROLLBACK_REALM_KEYSPACE to the Realm whose state must be undone");
    let target: u64 = std::env::var("PSY_ROLLBACK_REALM_TARGET")
        .expect("set PSY_ROLLBACK_REALM_TARGET to the height the chain was rolled back to")
        .parse()?;
    let realm_sub_id: u16 = std::env::var("PSY_ROLLBACK_REALM_SUB_ID")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(REALM_SUB_ID);

    let core = Arc::new(
        ScyllaCoreStore::<PHash, PoseidonHasher>::new(0, 0, keyspace.clone(), &known_nodes())
            .await?,
    );
    let control =
        RealmRollbackControlPlane::setup(core.as_ref(), network().chain_id() as i64).await?;
    let recording: RealmCommitRecording<PHash> = control.recording();
    let executor = ScyllaRealmRollbackExecutor::prepare(
        core.session.clone(),
        &keyspace,
        &format!("{keyspace}_no_tablet"),
    )
    .await?;

    // Bounds how far up the Realm's own manifest is searched.  The Realm's
    // actual head comes out of that search -- right after a rollback the
    // Coordinator sits at the target, and a Realm planning against *that* would
    // find nothing and quietly keep everything.
    let search_head: u64 = std::env::var("PSY_ROLLBACK_REALM_SEARCH_HEAD")
        .expect("set PSY_ROLLBACK_REALM_SEARCH_HEAD to a height at or above this Realm's own")
        .parse()?;
    let network_ref = CanonicalChainRef::new(
        network(),
        ChainEpoch::new(0),
        CheckpointRef::new(
            CheckpointId::new(search_head),
            CheckpointHash::from_last_chain_hash(PHash::from_values(0, 0, 0, 0)),
        ),
    );

    let report = executor
        .recover_own_state_to(&recording, REALM_ID, realm_sub_id, &network_ref, target)
        .await?;
    println!("{report:?}");
    assert_eq!(report.target, target);
    assert_eq!(
        report.archived_rows, report.planned_rows,
        "nothing may be deleted that was not first copied"
    );
    assert_eq!(report.deleted_rows, report.planned_rows);

    // A second recovery is refused, and that is the guarantee rather than a
    // limitation to work around.  A rollback does not delete the manifest, so
    // re-planning finds the same rows -- but they are gone now, so their images
    // differ from what the archive holds.  Letting the second run through would
    // overwrite the audit copy of what was discarded with a record saying there
    // was nothing there.
    //
    // The cost is that a crash between the delete and whatever records the
    // recovery as done leaves an operation that cannot simply be retried.
    let again = executor
        .recover_own_state_to(&recording, REALM_ID, realm_sub_id, &network_ref, target)
        .await;
    let refusal = again
        .err()
        .expect("a second recovery must not overwrite the first one's archive")
        .to_string();
    assert!(
        refusal.contains("already holds different content"),
        "the refusal must name the archive slot conflict, not fail for some other reason: \
         {refusal}"
    );

    Ok(())
}
