//! The commit recording path against a real Scylla.
//!
//! Everything up to this point was checked without a database: codecs, key
//! mappers, plan coverage, LWT classification.  None of that shows that the
//! nine control tables can be created, that a manifest round-trips through CQL,
//! or that the timestamp lease is actually exclusive when two writers race --
//! those are properties of the driver and the schema, not of the models.
//!
//! Scope: the durable layer, not `commit_state`.  Driving the real processor
//! needs genesis data, queues, a proof store and a temp database, and that
//! scaffolding belongs with the §11.4 acceptance test.  What is proven here is
//! that every store the commit path depends on behaves as its model says.
//!
//! Ignored by default; run with `--ignored` against a reachable Scylla.

use std::sync::Arc;

use parth_core::protocol::core_types::Q256BitHash;
use parth_core::{PHash, pgoldilocks::PoseidonHasher};
use psy_core::constants::chain_id::PsyChainNetworkType;
use psy_data::protocol::canonical_chain::{
    CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef, NetworkId,
};
use psy_data::protocol::chain_context::{
    AuthorityScope, AuthorityStateCheckpointId, AuthorityStateRoot,
};
use psy_node_core::store::authority_commit::{
    AuthorityClockSampleUs, AuthorityTimestampBootstrapReason, AuthorityTimestampKey,
    AuthorityTimestampReadState, AuthorityTimestampWriteOutcome,
};
use psy_node_core::store::commit_planner::CoordinatorCommitPlanInputs;
use psy_node_core::store::commit_recording_flow::prepare_commit_recording;
use psy_node_core::store::manifest_intent::{AuthorityHeadPayload, AuthorityStateTransition};
use psy_node_core::psy_core_db::core_implementation::constants::{
    LATEST_INFO_TABLE_OBJ_ID_LATEST_CHECKPOINT_TREE_ROOT,
    LATEST_INFO_TABLE_OBJ_ID_LATEST_L2_BLOCK_STATE, U64_SINGLETON_TABLE_OBJ_ID_CHECKPOINT_ID,
};
use psy_node_core::store::canonical_head::StoredCanonicalHead;
use psy_node_core::store::timestamp::CommitWriteTimestampUs;
use psy_node_core::store::manifest_record::ManifestRevision;
use psy_node_core::store::rollback_control::RollbackControlState;
use psy_node_core::store::manifest_store::ManifestArtifactKind;
use psy_node_scylla::core::ScyllaCoreStore;
use psy_node_scylla::rollback::{
    CoordinatorRollbackControlPlane, ScyllaRollbackRequestStore, decode_locator_chunk,
};
use psy_node_core::store::rollback_request::{PickupDecision, StaleReason, decide_pickup};

const CHECKPOINT_TREE_HEIGHT: u8 = 32;

fn known_nodes() -> Vec<String> {
    vec![
        std::env::var("PSY_TEST_SCYLLA")
            .unwrap_or_else(|_| "127.0.0.1:9042".to_string()),
    ]
}

/// A keyspace nobody else is using, so a leftover row cannot make a run pass.
fn unique_keyspace(tag: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    format!("psy_rec_{tag}_{}", nanos % 1_000_000_000)
}

async fn bring_up(
    tag: &str,
) -> anyhow::Result<(
    Arc<ScyllaCoreStore<PHash, PoseidonHasher>>,
    CoordinatorRollbackControlPlane,
    String,
)> {
    let keyspace = unique_keyspace(tag);
    let core = Arc::new(
        ScyllaCoreStore::<PHash, PoseidonHasher>::new(
            0,
            0,
            keyspace.clone(),
            &known_nodes(),
        )
        .await?,
    );
    // The state tables have to exist before the control plane can be prepared:
    // the floor's singleton anchor reads two of them.  Only those two are needed
    // here, and their shape mirrors tables/object/kiv.rs and
    // tables/u64_table/u64_to_u64.rs -- the full state setup is generic over the
    // network config and is exercised by the acceptance test instead.
    for ddl in [
        format!(
            "CREATE TABLE IF NOT EXISTS {keyspace}.latest_info_table \
             (obj_id BIGINT, value BLOB, PRIMARY KEY ((obj_id)))"
        ),
        format!(
            "CREATE TABLE IF NOT EXISTS {keyspace}.u64_singleton_table \
             (obj_id BIGINT, value BIGINT, PRIMARY KEY ((obj_id)))"
        ),
    ] {
        core.session.query_unpaged(ddl, &[]).await?;
    }
    core.session.await_schema_agreement().await?;

    // Seed the singletons the floor's anchor observes.  A real chain has these by
    // the time the first recorded commit happens -- genesis writes them -- and the
    // anchor fails closed without them, because a floor whose singleton values
    // exist nowhere cannot be restored to.  Seeding here reproduces a post-genesis
    // chain rather than working around the check.
    for ddl in [
        format!(
            "INSERT INTO {keyspace}.latest_info_table (obj_id, value) VALUES ({}, 0x{})",
            LATEST_INFO_TABLE_OBJ_ID_LATEST_L2_BLOCK_STATE,
            "aa".repeat(64)
        ),
        format!(
            "INSERT INTO {keyspace}.latest_info_table (obj_id, value) VALUES ({}, 0x{})",
            LATEST_INFO_TABLE_OBJ_ID_LATEST_CHECKPOINT_TREE_ROOT,
            "bb".repeat(32)
        ),
        format!(
            "INSERT INTO {keyspace}.u64_singleton_table (obj_id, value) VALUES ({}, 2000)",
            U64_SINGLETON_TABLE_OBJ_ID_CHECKPOINT_ID
        ),
    ] {
        core.session.query_unpaged(ddl, &[]).await?;
    }

    let control = CoordinatorRollbackControlPlane::setup(core.as_ref()).await?;
    Ok((core, control, keyspace))
}

async fn drop_keyspaces(
    core: &ScyllaCoreStore<PHash, PoseidonHasher>,
) {
    for keyspace in [core.keyspace.clone(), core.no_tablet_keyspace.clone()] {
        let _ = core
            .session
            .query_unpaged(format!("DROP KEYSPACE IF EXISTS {keyspace}"), &[])
            .await;
    }
}

fn network() -> NetworkId {
    NetworkId::from_network_type(PsyChainNetworkType::LocalDevnet)
}

fn hash(seed: u64) -> PHash {
    PHash::from_values(seed, seed + 1, seed + 2, seed + 3)
}

fn chain(checkpoint: u64, seed: u64) -> CanonicalChainRef<PHash> {
    CanonicalChainRef::new(
        network(),
        ChainEpoch::new(0),
        CheckpointRef::new(
            CheckpointId::new(checkpoint),
            CheckpointHash::from_last_chain_hash(hash(seed)),
        ),
    )
}

/// The stored head a commit advances from, at a given revision.
///
/// There is no public constructor by design: durable head material has to cross
/// `decode_persisted`, so building one here goes through the same validation a
/// real read does rather than around it.
fn stored_head(checkpoint: u64, seed: u64, revision: i64) -> StoredCanonicalHead<PHash> {
    let control: RollbackControlState<PHash> = RollbackControlState::Idle;
    StoredCanonicalHead::decode_persisted(
        network(),
        revision,
        &chain(checkpoint, seed).to_canonical_bytes(),
        &control.to_canonical_bytes(),
    )
    .expect("a head this test built must decode")
}

/// A canonical prepared-update payload stand-in.
///
/// The recording layer never interprets it -- it only has to survive byte-exact
/// -- so a fixed pattern is enough to prove the round trip.
fn source_payload(checkpoint: u64) -> Vec<u8> {
    checkpoint.to_le_bytes().repeat(8)
}

fn plan_inputs(checkpoint_id: u64, root: &[u8]) -> CoordinatorCommitPlanInputs<'_> {
    CoordinatorCommitPlanInputs {
        checkpoint_id,
        unique_pending_id: checkpoint_id + 500,
        next_contract_id: 0,
        new_contract_code_definition_count: 0,
        update_global_contract_tree_nodes_ffs: &[],
        update_contract_function_tree_nodes_ffs: &[],
        new_contract_leaves_ffs: &[],
        update_user_registration_tree_nodes_ffs: &[],
        new_user_public_keys_ffs: &[],
        new_public_key_hash_to_user_id_rows_ffs: &[],
        update_global_user_tree_nodes_ffs: &[],
        new_realm_guta_reward_tree_node_keys_ffs: &[],
        checkpoint_root_bytes: root,
        checkpoint_tree_height: CHECKPOINT_TREE_HEIGHT,
    }
}

fn clock() -> AuthorityClockSampleUs {
    AuthorityClockSampleUs::try_from_i128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_micros() as i128,
    )
    .expect("clock in range")
}

fn transition(previous: u64, checkpoint: u64) -> AuthorityStateTransition<PHash> {
    AuthorityStateTransition::Changed {
        previous_checkpoint: AuthorityStateCheckpointId::new(previous),
        checkpoint: AuthorityStateCheckpointId::new(checkpoint),
        old_root: AuthorityStateRoot::from_local_state_root(hash(previous)),
        new_root: AuthorityStateRoot::from_local_state_root(hash(checkpoint)),
    }
}

#[tokio::test]
#[ignore = "requires a reachable Scylla"]
async fn the_control_plane_creates_every_table_it_declares() -> anyhow::Result<()> {
    let (core, _control, keyspace) = bring_up("ddl").await?;
    let no_tablet = format!("{keyspace}_no_tablet");
    let rows = core
        .session
        .query_unpaged(
            "SELECT table_name FROM system_schema.tables WHERE keyspace_name = ?",
            (no_tablet.as_str(),),
        )
        .await?
        .into_rows_result()?;
    let mut present: Vec<String> = Vec::new();
    for row in rows.rows::<(String,)>()? {
        present.push(row?.0);
    }
    for declared in psy_node_scylla::rollback::COORDINATOR_ROLLBACK_CONTROL_TABLES {
        assert!(
            present.iter().any(|name| name == declared),
            "{declared} was declared but not created; created: {present:?}"
        );
    }
    drop_keyspaces(&core).await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires a reachable Scylla"]
async fn a_recorded_commit_round_trips_through_cql() -> anyhow::Result<()> {
    let (core, control, _keyspace) = bring_up("roundtrip").await?;
    let recording = control.recording::<PHash>();
    let key = AuthorityTimestampKey::new(network(), AuthorityScope::Coordinator);
    let root = hash(9).into_owned_32bytes();

    let prepared = prepare_commit_recording(
        &recording,
        key,
        &plan_inputs(1001, &root),
        stored_head(1000, 1, 1),
        chain(1001, 2),
        transition(1000, 1001),
        AuthorityHeadPayload::try_new(vec![7u8; 64])?,
        clock(),
        source_payload(1),
        7u32,
        vec![0xABu8; 96],
        AuthorityTimestampBootstrapReason::ControlledWriterCutover,
    )
    .await?;

    // The PREPARED row must read back byte-identically: it is what a restart
    // classifies on, so a codec that survived only in memory would be useless.
    let row = recording
        .manifest()
        .read_manifest_row(prepared.identity(), ManifestRevision::prepared())
        .await?
        .expect("PREPARED row must be readable after prepare");
    assert_eq!(row.checkpoint_id, 1001);
    assert_eq!(row.digest, prepared.record().digest().as_bytes());
    assert_eq!(row.payload, prepared.record().encode_canonical());

    // And the artifact must reassemble into the exact planned locator set.
    let chunk_count = prepared
        .record()
        .intent()
        .artifacts()
        .locator_chunk_count();
    let chunks = recording
        .manifest_artifact()
        .read_artifact_chunks(
            prepared.identity(),
            ManifestArtifactKind::Locator,
            chunk_count,
        )
        .await?;
    let mut rows = 0usize;
    for chunk in &chunks {
        rows += decode_locator_chunk(chunk)?.len();
    }
    assert_eq!(
        rows as u64,
        prepared.record().intent().artifacts().affected_row_count(),
        "the artifact must hold exactly the rows the manifest committed to"
    );

    drop_keyspaces(&core).await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires a reachable Scylla"]
async fn a_second_writer_cannot_take_a_held_lease() -> anyhow::Result<()> {
    let (core, control, _keyspace) = bring_up("lease").await?;
    let recording = control.recording::<PHash>();
    let key = AuthorityTimestampKey::new(network(), AuthorityScope::Coordinator);
    let root = hash(3).into_owned_32bytes();

    let _first = prepare_commit_recording(
        &recording,
        key,
        &plan_inputs(2001, &root),
        stored_head(2000, 1, 1),
        chain(2001, 2),
        transition(2000, 2001),
        AuthorityHeadPayload::try_new(vec![1u8; 32])?,
        clock(),
        source_payload(1),
        7u32,
        vec![0xABu8; 96],
        AuthorityTimestampBootstrapReason::ControlledWriterCutover,
    )
    .await?;

    // Exclusivity is the whole reason the lease exists: two Coordinators must not
    // both believe they own a checkpoint.  The model refuses a reservation while
    // one is active; this checks the durable row enforces it too.
    let second = prepare_commit_recording(
        &recording,
        key,
        &plan_inputs(2002, &root),
        stored_head(2001, 2, 1),
        chain(2002, 3),
        transition(2001, 2002),
        AuthorityHeadPayload::try_new(vec![2u8; 32])?,
        clock(),
        source_payload(1),
        7u32,
        vec![0xABu8; 96],
        AuthorityTimestampBootstrapReason::ControlledWriterCutover,
    )
    .await;
    assert!(
        second.is_err(),
        "a second commit must not reserve while a lease is held"
    );

    drop_keyspaces(&core).await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires a reachable Scylla"]
async fn releasing_a_lease_lets_the_next_commit_reserve() -> anyhow::Result<()> {
    let (core, control, _keyspace) = bring_up("release").await?;
    let recording = control.recording::<PHash>();
    let key = AuthorityTimestampKey::new(network(), AuthorityScope::Coordinator);
    let root = hash(5).into_owned_32bytes();

    let first = prepare_commit_recording(
        &recording,
        key,
        &plan_inputs(3001, &root),
        stored_head(3000, 1, 1),
        chain(3001, 2),
        transition(3000, 3001),
        AuthorityHeadPayload::try_new(vec![1u8; 32])?,
        clock(),
        source_payload(1),
        7u32,
        vec![0xABu8; 96],
        AuthorityTimestampBootstrapReason::ControlledWriterCutover,
    )
    .await?;
    let first_timestamp = first.lease().timestamp();

    let state = match recording.timestamp().read_timestamp_state(key).await? {
        AuthorityTimestampReadState::Current(state) => state,
        AuthorityTimestampReadState::Uninitialized => panic!("row must exist"),
    };
    let completion = state.seal_completion(key, first.lease())?;
    assert!(matches!(
        recording.timestamp().complete_timestamp(&completion).await?,
        AuthorityTimestampWriteOutcome::Applied(_)
            | AuthorityTimestampWriteOutcome::Idempotent(_)
    ));

    let second = prepare_commit_recording(
        &recording,
        key,
        &plan_inputs(3002, &root),
        stored_head(3001, 2, 1),
        chain(3002, 3),
        transition(3001, 3002),
        AuthorityHeadPayload::try_new(vec![2u8; 32])?,
        clock(),
        source_payload(1),
        7u32,
        vec![0xABu8; 96],
        AuthorityTimestampBootstrapReason::ControlledWriterCutover,
    )
    .await?;

    // Strictly increasing, which is what the delete fence rests on: a fence above
    // every discarded write is only definable if timestamps never repeat.
    assert!(
        second.lease().timestamp().as_i64() > first_timestamp.as_i64(),
        "the next commit must allocate a strictly later timestamp"
    );

    drop_keyspaces(&core).await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires a reachable Scylla"]
async fn an_identical_retry_converges_instead_of_conflicting() -> anyhow::Result<()> {
    let (core, control, _keyspace) = bring_up("retry").await?;
    let recording = control.recording::<PHash>();
    let root = hash(11).into_owned_32bytes();
    let inputs = plan_inputs(4001, &root);

    // Persisting the same artifact twice models a caller that lost the response
    // and retried.  It has to converge: an append-only store that treated its own
    // earlier write as a conflict would make every response loss fatal.
    let sink = psy_node_core::store::commit_planner::CollectingPhysicalMutationSink::new();
    let planner = psy_node_scylla::rollback::ScyllaCoordinatorCommitPlanner::new();
    psy_node_core::store::commit_planner::CoordinatorCommitPlanner::plan_coordinator_commit(
        &planner, &inputs, &sink,
    )?;
    let planned =
        psy_node_core::store::commit_planner::CoordinatorCommitPlanner::encode_planned_locators(
            &planner,
            sink.take(),
        )?;

    let identity = psy_node_core::store::manifest_record::AuthorityManifestIdentity::try_new(
        AuthorityTimestampKey::new(network(), AuthorityScope::Coordinator),
        chain(4001, 4),
    )?;
    for _ in 0..2 {
        recording
            .manifest_artifact()
            .persist_artifact_chunks(
                &identity,
                ManifestArtifactKind::Locator,
                &planned.chunks,
            )
            .await?;
    }
    let read = recording
        .manifest_artifact()
        .read_artifact_chunks(
            &identity,
            ManifestArtifactKind::Locator,
            planned.chunk_count(),
        )
        .await?;
    assert_eq!(read, planned.chunks);

    drop_keyspaces(&core).await;
    Ok(())
}

/// Every control table a PREPARED commit is responsible for must hold a row.
///
/// This test exists because two real defects hid in exactly the gap it closes.
/// A run committed eight checkpoints with complete PREPARED/SEALED/COMMITTED
/// manifests while `coordinator_commit_source_header` and
/// `coordinator_rollback_floor` stayed empty: `prepare_commit_recording` simply
/// never called them.  Nothing failed -- neither write is on the path of any
/// assertion a commit makes about itself -- so the commits succeeded and were
/// silently unrollbackable, and only counting rows per table found it.
///
/// The exemption list below is the point.  It is closed and named, so a new
/// control table is checked by default and can only be excluded by saying so
/// here, with a reason.  A test that listed the tables it *does* check would
/// have gone on passing through both defects.
#[tokio::test]
#[ignore = "requires a reachable Scylla"]
async fn a_prepared_commit_populates_every_control_table_it_owns() -> anyhow::Result<()> {
    let (core, control, keyspace) = bring_up("populated").await?;
    let no_tablet = format!("{keyspace}_no_tablet");
    let recording = control.recording::<PHash>();
    let key = AuthorityTimestampKey::new(network(), AuthorityScope::Coordinator);
    let root = hash(21).into_owned_32bytes();

    // Revision 1 both in the head and in the floor's activation: the anchor can
    // only be minted while the head still stands where the floor was activated.
    let prepared = prepare_commit_recording(
        &recording,
        key,
        &plan_inputs(2001, &root),
        stored_head(2000, 11, 1),
        chain(2001, 12),
        transition(2000, 2001),
        AuthorityHeadPayload::try_new(vec![3u8; 64])?,
        clock(),
        source_payload(2001),
        7u32,
        vec![0x5Au8; 128],
        AuthorityTimestampBootstrapReason::ControlledWriterCutover,
    )
    .await?;
    assert_eq!(prepared.record().identity().authority(), AuthorityScope::Coordinator);

    // Written only by `complete_commit_record`, once the state writes have
    // landed and the head CAS has been classified.  A PREPARED commit that had
    // already marked itself committed would be a lie.
    const ONLY_AFTER_COMMIT: [&str; 2] = [
        "coordinator_commit_source_committed",
        "coordinator_canonical_head",
    ];

    let mut empty: Vec<&str> = Vec::new();
    for table in psy_node_scylla::rollback::COORDINATOR_ROLLBACK_CONTROL_TABLES {
        let count = core
            .session
            .query_unpaged(format!("SELECT count(*) FROM {no_tablet}.{table}"), &[])
            .await?
            .into_rows_result()?
            .first_row::<(i64,)>()?
            .0;
        if ONLY_AFTER_COMMIT.contains(table) {
            assert_eq!(count, 0, "{table} must stay empty until the commit completes");
        } else if count == 0 {
            empty.push(table);
        }
    }
    assert!(
        empty.is_empty(),
        "a prepared commit left these control tables empty: {empty:?}"
    );

    drop_keyspaces(&core).await;
    Ok(())
}

/// A commit window really does decide the write timestamp of the rows it covers.
///
/// The driver takes a statement's own timestamp and otherwise calls the session
/// generator, in the connection layer below every statement kind.  That is read
/// from the driver's source; this checks it against a running Scylla, because the
/// whole timestamp design rests on it and a misreading would be invisible until a
/// fence silently shadowed a live row.
///
/// `WRITETIME()` is the assertion that cannot be fooled by the code path: it
/// reports what the row actually carries.
#[tokio::test]
#[ignore = "requires a reachable Scylla"]
async fn a_commit_window_decides_the_write_timestamp_of_its_rows() -> anyhow::Result<()> {
    let (core, control, keyspace) = bring_up("writetime").await?;
    let recording = control.recording::<PHash>();

    core.session
        .query_unpaged(
            format!(
                "CREATE TABLE IF NOT EXISTS {keyspace}.window_probe_table \
                 (obj_id BIGINT, value BLOB, PRIMARY KEY ((obj_id)))"
            ),
            &[],
        )
        .await?;
    core.session.await_schema_agreement().await?;

    // A timestamp no wall clock would produce right now, so a row carrying it
    // can only have got it from the window.
    const WINDOW_US: i64 = 1_600_000_000_000_123;
    let stamp = CommitWriteTimestampUs::try_from_i128(WINDOW_US as i128)?;

    {
        let _window = recording.open_commit_window(4242, stamp)?;
        assert_eq!(recording.require_commit_window(4242)?, stamp);
        // Two statements, one window: a commit is one point on the axis, not a
        // spread, so both must come back identical.
        for obj_id in [1i64, 2i64] {
            core.session
                .query_unpaged(
                    format!(
                        "INSERT INTO {keyspace}.window_probe_table (obj_id, value) VALUES (?, ?)"
                    ),
                    (obj_id, vec![9u8; 8]),
                )
                .await?;
        }
    }

    // Outside the window the generator falls back to the clock, which is where
    // the edge and query paths live.
    core.session
        .query_unpaged(
            format!("INSERT INTO {keyspace}.window_probe_table (obj_id, value) VALUES (?, ?)"),
            (3i64, vec![9u8; 8]),
        )
        .await?;

    let mut stamps = Vec::new();
    for obj_id in [1i64, 2i64, 3i64] {
        let written = core
            .session
            .query_unpaged(
                format!(
                    "SELECT WRITETIME(value) FROM {keyspace}.window_probe_table WHERE obj_id = ?"
                ),
                (obj_id,),
            )
            .await?
            .into_rows_result()?
            .first_row::<(i64,)>()?
            .0;
        stamps.push(written);
    }

    assert_eq!(
        stamps[0], WINDOW_US,
        "a row written inside the window must carry the window's timestamp"
    );
    assert_eq!(
        stamps[1], WINDOW_US,
        "every row of one commit shares one timestamp"
    );
    assert!(
        stamps[2] > WINDOW_US,
        "a row written outside the window must come from the clock, not the window \
         (got {}, window was {WINDOW_US})",
        stamps[2]
    );

    // And the window really closed, rather than merely stopping being consulted.
    assert!(recording.require_commit_window(4242).is_err());

    drop_keyspaces(&core).await;
    Ok(())
}

/// Re-sending is the operator's retry, so two attempts are two rows.
///
/// A request that is not taken up expires on its own -- it names the head the
/// operator saw -- so the retry has to be a *new* request naming the new head,
/// not an edit of the old one.  Both stay on the record: "asked three times
/// before the chain took it up" is exactly the kind of thing someone reading
/// this table afterwards needs to be able to see.
#[tokio::test]
#[ignore = "requires a reachable Scylla"]
async fn resending_a_request_records_both_and_offers_the_newest() -> anyhow::Result<()> {
    let (core, _control, keyspace) = bring_up("request_inbox").await?;
    let no_tablet = format!("{keyspace}_no_tablet");
    ScyllaRollbackRequestStore::create_table(&core.session, &no_tablet).await?;
    let store =
        ScyllaRollbackRequestStore::prepare(core.session.clone(), &no_tablet, 0).await?;

    assert!(
        store.newest().await?.is_none(),
        "a chain nobody has asked to roll back has an empty mailbox"
    );

    let first = store.submit(90, 100, "operator-a").await?;
    let second = store.submit(90, 104, "operator-a").await?;
    assert!(second > first, "the retry must sort above the first attempt");

    let newest = store.newest().await?.expect("a request was submitted");
    assert_eq!(newest.expected_head, 104, "the newest request is the one that counts");
    assert_eq!(newest.target, 90);
    assert_eq!(newest.requested_by, "operator-a");
    assert_eq!(newest.consumed_epoch, None);
    assert_eq!(store.recent(10).await?.len(), 2, "both attempts stay on the record");

    drop_keyspaces(&core).await;
    Ok(())
}

/// Marking an entry consumed cannot invent one.
///
/// The same lesson as `set_outcome` on the event table: a bare UPDATE creates
/// the row, so a mark that arrived for an entry nobody wrote would leave a
/// half-row carrying a consumed epoch and no request -- and the mailbox would
/// then offer a request that was never made.
#[tokio::test]
#[ignore = "requires a reachable Scylla"]
async fn a_consumed_request_is_not_offered_again() -> anyhow::Result<()> {
    let (core, _control, keyspace) = bring_up("request_consumed").await?;
    let no_tablet = format!("{keyspace}_no_tablet");
    ScyllaRollbackRequestStore::create_table(&core.session, &no_tablet).await?;
    let store =
        ScyllaRollbackRequestStore::prepare(core.session.clone(), &no_tablet, 0).await?;

    let at = store.submit(90, 100, "operator-a").await?;
    assert!(
        matches!(
            decide_pickup(&store.newest().await?.unwrap(), 100),
            PickupDecision::Take { target: 90 }
        ),
        "an unconsumed request against the head it named must be taken up"
    );

    store.mark_consumed(at, 1).await?;
    let after = store.newest().await?.expect("the row is still there");
    assert_eq!(after.consumed_epoch, Some(1));
    assert!(matches!(
        decide_pickup(&after, 100),
        PickupDecision::Stale {
            reason: StaleReason::AlreadyConsumed
        }
    ));

    // A mark for an entry that does not exist must not create one.
    store.mark_consumed(at + 1_000_000, 2).await?;
    assert_eq!(
        store.recent(10).await?.len(),
        1,
        "marking an absent entry consumed must not invent it"
    );

    drop_keyspaces(&core).await;
    Ok(())
}
