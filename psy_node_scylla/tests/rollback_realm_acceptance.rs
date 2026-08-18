//! Slice B acceptance: roll a Realm back and prove it landed on history.
//!
//! Structurally the Coordinator's acceptance test, with the three differences
//! §6.3 requires: SEALED rather than COMMITTED as the completion mark, no head
//! to republish, and a re-sync rather than a restore for the checkpoint copies.
//!
//! ## What this needs that the Coordinator's did not
//!
//! A Realm produces no manifest until it actually commits, and it only commits
//! when it has transactions of its own -- in a load without them it reports "No
//! GUTA jobs to process" and advances purely by syncing.  So this test needs a
//! chain where a Realm has committed, which needs funded users, which needs
//! balance, which does not come from genesis: genesis users carry `balance: 0`
//! and funds arrive from L1 through the bridge.  A Realm chain therefore needs
//! anvil, the relayer, a faucet holding the generated operator wallets, and
//! prove-proxy.
//!
//! The existing local testnet cannot stand in for that: it deploys parth rather
//! than this branch, and it pins its genesis hashes precisely so a deployment
//! cannot create a different genesis identity -- while this branch's genesis has
//! to match its own baseline circuits.  They are different networks and one's
//! funds do not exist in the other.
//!
//! Until that environment exists this test is written but unrun, and slice B is
//! code-complete and unit-tested rather than verified.  It is committed anyway
//! so the gap is a test that has not run rather than a test nobody wrote.
//!
//! ```text
//! PSY_ROLLBACK_REALM_KEYSPACE=rollback_r1_realm \
//!   cargo test -p psy_node_scylla --test rollback_realm_acceptance -- --ignored --nocapture
//! ```

use std::collections::BTreeMap;
use std::sync::Arc;

use parth_core::PHash;
use psy_core::constants::chain_id::PsyChainNetworkType;
use psy_data::protocol::canonical_chain::{
    CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef, NetworkId,
};
use psy_node_core::store::realm_commit_recording::RealmCommitRecording;
use psy_node_scylla::rollback::{
    RealmRollbackControlPlane, ScyllaRealmRollbackExecutor, ScyllaRowImageReader,
    decode_locator_canonical,
};
use psy_node_scylla::core::ScyllaCoreStore;
use parth_core::pgoldilocks::PoseidonHasher;
use scylla::client::session::Session;
use scylla::client::session_builder::SessionBuilder;

const REALM_ID: u32 = 0;
const REALM_SUB_ID: u16 = 0;

fn known_nodes() -> Vec<String> {
    vec![std::env::var("PSY_SCYLLA_URL").unwrap_or_else(|_| "127.0.0.1:9042".to_string())]
}

fn network() -> NetworkId {
    NetworkId::from_network_type(PsyChainNetworkType::LocalDevnet)
}

/// One journal observation, keyed by position rather than locator.
struct Witness {
    locator: Vec<u8>,
    before: Option<Vec<u8>>,
}

/// Every key position the discarded range touched, with the state observed just
/// before the first checkpoint above the target that touched it.
///
/// Grouped by position for the reason the Coordinator's test records: a
/// version-axis locator encodes the checkpoint, so one node written at ten
/// heights is ten locators, and treating those as ten keys makes `c(K)` collapse
/// into "every checkpoint" and assert the wrong thing.
async fn witnesses_first_touch(
    session: &Session,
    keyspace: &str,
    reader: &ScyllaRowImageReader,
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
            let Ok(resolved) = decode_locator_canonical(&locator) else {
                continue;
            };
            let Ok(position) = reader.position_key(&resolved) else {
                continue;
            };
            first.entry(position).or_insert(Witness {
                locator,
                before: before.filter(|_| present.unwrap_or(false)),
            });
        }
    }
    Ok(first.into_values().collect())
}

#[tokio::test]
#[ignore = "requires a Realm chain with committed transactions; see the module note"]
async fn a_realm_rollback_restores_exactly_what_was_observed_before() -> anyhow::Result<()> {
    let keyspace = std::env::var("PSY_ROLLBACK_REALM_KEYSPACE")
        .expect("set PSY_ROLLBACK_REALM_KEYSPACE to a Realm keyspace with committed transactions");
    let no_tablet = format!("{keyspace}_no_tablet");
    let session = Arc::new(
        SessionBuilder::new()
            .known_nodes(known_nodes().iter())
            .build()
            .await?,
    );

    // The Realm's own committed height, which is not the height it has synced
    // to: syncing advances the marker without the Realm committing anything.
    let realm_committed: Vec<u64> = session
        .query_unpaged(
            format!(
                "SELECT checkpoint_id FROM {no_tablet}.authority_manifest \
                 WHERE network_chain_id = ? ALLOW FILTERING"
            ),
            (network().chain_id() as i32,),
        )
        .await?
        .into_rows_result()?
        .rows::<(i64,)>()?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|(id,)| id as u64)
        .collect();
    assert!(
        !realm_committed.is_empty(),
        "this Realm has never committed, so there is nothing to roll back; it needs a chain \
         with transactions of its own, not merely one it has synced"
    );

    let head = *realm_committed.iter().max().expect("non-empty");
    let target = realm_committed
        .iter()
        .copied()
        .filter(|height| *height < head)
        .max()
        .expect("a Realm that committed twice");
    println!("rolling this Realm back from {head} to {target}");

    let core = Arc::new(
        ScyllaCoreStore::<PHash, PoseidonHasher>::new(0, 0, keyspace.clone(), &known_nodes())
            .await?,
    );
    let control = RealmRollbackControlPlane::setup(core.as_ref()).await?;
    let recording: RealmCommitRecording<PHash> = control.recording();
    let reader = ScyllaRowImageReader::prepare(session.clone(), &keyspace).await?;
    let executor =
        ScyllaRealmRollbackExecutor::prepare(session.clone(), &keyspace, &no_tablet).await?;

    let witnesses = witnesses_first_touch(&session, &keyspace, &reader, target, head).await?;
    assert!(
        !witnesses.is_empty(),
        "the journal recorded nothing for this Realm's discarded range; run the chain with \
         PSY_ROLLBACK_VERIFICATION_JOURNAL set"
    );
    println!("{} distinct key positions were touched", witnesses.len());

    // The chain reference the Realm recorded is the Coordinator's, so the plan
    // is built from the same coordinate the Coordinator's manifests name.
    let head_ref = CanonicalChainRef::new(
        network(),
        ChainEpoch::new(0),
        CheckpointRef::new(
            CheckpointId::new(head),
            CheckpointHash::from_last_chain_hash(PHash::from_values(0, 0, 0, 0)),
        ),
    );
    let plan_id = format!("realm-acceptance-{head}-{target}").into_bytes();
    let report = executor
        .roll_back(
            &recording,
            REALM_ID,
            REALM_SUB_ID,
            &head_ref,
            target,
            &plan_id,
        )
        .await?;
    println!("{report:?}");
    assert_eq!(report.archived_rows, report.planned_rows);
    assert_eq!(report.deleted_rows, report.planned_rows);

    // G-W on the Realm's own state.  The checkpoint copies are deliberately not
    // asserted here: they are re-fetched rather than restored, so their content
    // after a rollback is whatever the Coordinator now publishes, not what this
    // Realm observed before.
    let mut mismatches = Vec::new();
    let mut checked = 0usize;
    for witness in &witnesses {
        let Ok(resolved) = decode_locator_canonical(&witness.locator) else {
            continue;
        };
        let Ok(live) = reader.read_as_of(&resolved, target).await else {
            continue;
        };
        checked += 1;
        let live_bytes = live.as_ref().map(|image| image.canonical_bytes());
        if live_bytes != witness.before {
            mismatches.push(format!("{:?}", resolved.physical_table()));
        }
    }
    println!("G-W checked {checked} Realm key positions");
    assert!(checked > 0, "no key could be checked, so the assertion proved nothing");
    assert!(
        mismatches.is_empty(),
        "G-W failed for {} of {checked} Realm keys: {mismatches:?}",
        mismatches.len()
    );

    Ok(())
}
