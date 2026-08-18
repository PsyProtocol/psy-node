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
use psy_node_core::store::rollback_coordination::{
    ObservedRollbackPhase, RollbackParticipantView,
};
use psy_node_core::store::rollback_participants::{
    ArchiveReceipt, FreezeReceipt, RollbackParticipant, VerifyReceipt,
};
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
/// The deployment runs realms with sub id 1, not 0.  The allocator and the
/// manifest are partitioned by the exact scope, so a test guessing 0 looks in a
/// partition nothing ever wrote and reports the Realm as having committed
/// nothing.  Overridable, because a differently configured deployment would
/// place them somewhere else again.
const REALM_SUB_ID: u16 = 1;

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
    let realm_sub_id: u16 = std::env::var("PSY_ROLLBACK_REALM_SUB_ID")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(REALM_SUB_ID);
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
            (network().chain_id() as i64,),
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
    // A Realm only ever follows phases the Coordinator published, so driving it
    // needs something to publish them.  This stands in for a Coordinator
    // rollback running against the same chain, advancing on each observation in
    // the order §4.1 lays out.
    let view = ScriptedCoordinator::new(head, target);
    let report = executor
        .roll_back(
            &recording,
            REALM_ID,
            realm_sub_id,
            &head_ref,
            target,
            &plan_id,
            &view,
        )
        .await?;
    assert_eq!(
        view.filed(),
        vec![
            "freeze".to_string(),
            "archive".to_string()
        ],
        "a Realm files a receipt at each barrier it reaches"
    );
    println!("{report:?}");
    assert_eq!(report.archived_rows, report.planned_rows);
    assert_eq!(view.observations(), 3, "one observation per phase gate");
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

/// A Coordinator that publishes the rollback phases in order, one per look.
///
/// The Realm side is what this test is about; what it needs from a Coordinator
/// is only that FROZEN, then ARCHIVING, then DELETING become visible, and that
/// its receipts are accepted.  Advancing on each observation is what a real
/// Coordinator does once every participant has filed -- with one Realm in the
/// set, that is immediately.
struct ScriptedCoordinator {
    head: u64,
    target: u64,
    looks: std::sync::atomic::AtomicUsize,
    filed: std::sync::Mutex<Vec<String>>,
}

impl ScriptedCoordinator {
    fn new(head: u64, target: u64) -> Self {
        Self {
            head,
            target,
            looks: std::sync::atomic::AtomicUsize::new(0),
            filed: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn filed(&self) -> Vec<String> {
        self.filed.lock().expect("not poisoned").clone()
    }

    fn observations(&self) -> usize {
        self.looks.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl RollbackParticipantView<PHash> for ScriptedCoordinator {
    async fn observe_phase(
        &self,
        _coordinator_head: &CanonicalChainRef<PHash>,
    ) -> anyhow::Result<ObservedRollbackPhase> {
        let look = self.looks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(match look {
            0 => ObservedRollbackPhase::Freeze { head: self.head },
            1 => ObservedRollbackPhase::Archive {
                target: self.target,
                head: self.head,
            },
            _ => ObservedRollbackPhase::Delete {
                target: self.target,
                head: self.head,
            },
        })
    }

    async fn file_archive_receipt(&self, _receipt: &ArchiveReceipt) -> anyhow::Result<()> {
        self.filed.lock().expect("not poisoned").push("archive".into());
        Ok(())
    }

    async fn read_archive_receipts_for(
        &self,
        _target: u64,
        _head: u64,
        _expected: &[RollbackParticipant],
    ) -> anyhow::Result<Vec<ArchiveReceipt>> {
        Ok(Vec::new())
    }

    async fn file_freeze_receipt(&self, _receipt: &FreezeReceipt) -> anyhow::Result<()> {
        self.filed.lock().expect("not poisoned").push("freeze".into());
        Ok(())
    }

    async fn read_freeze_receipts_for(
        &self,
        _head: u64,
        _expected: &[RollbackParticipant],
    ) -> anyhow::Result<Vec<FreezeReceipt>> {
        Ok(Vec::new())
    }

    async fn file_verify_receipt(&self, _receipt: &VerifyReceipt) -> anyhow::Result<()> {
        self.filed.lock().expect("not poisoned").push("verify".into());
        Ok(())
    }

    async fn read_verify_receipts_for(
        &self,
        _target: u64,
        _expected: &[RollbackParticipant],
    ) -> anyhow::Result<Vec<VerifyReceipt>> {
        Ok(Vec::new())
    }
}
