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
    /// What the discarded branch left in the row. Only the resync assertion
    /// uses it, and it uses it to say that value must be gone.
    after: Option<Vec<u8>>,
}

/// Which of a Realm's rows an assertion is about.
///
/// A Realm's rows above the target come from two places and are undone two
/// different ways, on opposite schedules. Asking one question of both is what
/// made this assertion report eight failures that were not failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RealmAssertion {
    /// Rows the Realm's own manifest names: the rollback plan deletes or
    /// restores them, so they are settled the moment the rollback returns and
    /// must be checked **before the Realm moves again**.
    ManifestNamed,
    /// Rows the Realm wrote while merely syncing. No manifest names them; they
    /// are undone by re-fetching from the Coordinator, which only happens once
    /// the Realm is running and has caught up. Checking these while the Realm
    /// is stopped asks whether a thing has happened that has been deliberately
    /// prevented from happening.
    Resynced,
}

impl RealmAssertion {
    fn from_env() -> Self {
        // Named rather than defaulted: the two need opposite timing, so a
        // caller that has not said which one it wants has not thought about
        // when it is running.
        match std::env::var("PSY_ROLLBACK_REALM_ASSERT").as_deref() {
            Ok("manifest") => Self::ManifestNamed,
            Ok("resync") => Self::Resynced,
            Ok(other) => panic!(
                "PSY_ROLLBACK_REALM_ASSERT={other:?}; expected \"manifest\" (run with the Realm \
                 stopped, straight after the rollback) or \"resync\" (run once it has caught up)"
            ),
            Err(_) => Self::ManifestNamed,
        }
    }
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
    // Checkpoint heights are reused after a rollback, so a height carries an
    // observation per branch that ever reached it. Reading them together
    // compares this branch against one that no longer exists.
    chain_epoch: u64,
) -> anyhow::Result<Vec<Witness>> {
    let mut first: BTreeMap<Vec<u8>, Witness> = BTreeMap::new();
    for checkpoint in (target + 1)..=head {
        let rows = session
            .query_unpaged(
                format!(
                    "SELECT locator, before_image, before_present, after_image, after_present \
                     FROM {keyspace}.rollback_verification_journal_by_epoch \
                     WHERE checkpoint_id = ? AND chain_epoch = ?"
                ),
                (checkpoint as i64, chain_epoch as i64),
            )
            .await?
            .into_rows_result()?;
        for row in rows
            .rows::<(Vec<u8>, Option<Vec<u8>>, Option<bool>, Option<Vec<u8>>, Option<bool>)>()?
        {
            let (locator, before, present, after, after_present) = row?;
            let Ok(resolved) = decode_locator_canonical(&locator) else {
                continue;
            };
            let Ok(position) = reader.position_key(&resolved) else {
                continue;
            };
            first.entry(position).or_insert(Witness {
                locator,
                before: before.filter(|_| present.unwrap_or(false)),
                after: after.filter(|_| after_present.unwrap_or(false)),
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

    // Overridable so a Coordinator-driven rollback can hand over the range it
    // just discarded. Left to itself this test picks a range out of the Realm's
    // own history, which is the right choice when it drives the rollback and
    // the wrong one when it is checking somebody else's.
    let explicit_range = std::env::var("PSY_ROLLBACK_HEAD").is_ok();
    let head = std::env::var("PSY_ROLLBACK_HEAD")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| *realm_committed.iter().max().expect("non-empty"));
    let target = std::env::var("PSY_ROLLBACK_TARGET")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| {
            realm_committed
                .iter()
                .copied()
                .filter(|height| *height < head)
                .max()
                .expect("a Realm that committed twice")
        });
    println!("rolling this Realm back from {head} to {target}");

    let core = Arc::new(
        ScyllaCoreStore::<PHash, PoseidonHasher>::new(0, 0, keyspace.clone(), &known_nodes())
            .await?,
    );
    let control =
        RealmRollbackControlPlane::setup(core.as_ref(), network().chain_id() as i64).await?;
    let recording: RealmCommitRecording<PHash> = control.recording();
    let reader = ScyllaRowImageReader::prepare(session.clone(), &keyspace).await?;
    let executor =
        ScyllaRealmRollbackExecutor::prepare(session.clone(), &keyspace, &no_tablet).await?;

    // Taken from the Realm's own manifest at the head, not assumed. This was
    // `ChainEpoch::new(0)` below, written when the chain had never rolled back;
    // on a chain at epoch 49 it planned against a partition that by
    // construction holds nothing.
    // The branch the range was committed under. Overridable because after a
    // rollback the head carries manifests from both branches, and taking the
    // greater one would compare this Realm against the branch that replaced the
    // discarded range rather than the discarded range itself. The Coordinator's
    // report names it: "recorded as epoch N (was M)" -- M is this.
    let chain_epoch: u64 = match std::env::var("PSY_ROLLBACK_CHAIN_EPOCH")
        .ok()
        .and_then(|value| value.parse().ok())
    {
        Some(epoch) => epoch,
        None => session
        .query_unpaged(
            format!(
                "SELECT chain_epoch FROM {no_tablet}.authority_manifest \
                 WHERE network_chain_id = ? AND checkpoint_id = ? ALLOW FILTERING"
            ),
            (network().chain_id() as i64, head as i64),
        )
        .await?
        .into_rows_result()?
        .rows::<(i64,)>()?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
            .map(|(epoch,)| epoch as u64)
            .max()
            .expect("the head this Realm committed has a manifest"),
    };
    println!("Realm branch: chain_epoch {chain_epoch}");
    let witnesses =
        witnesses_first_touch(&session, &keyspace, &reader, target, head, chain_epoch).await?;
    // A Realm commits at every checkpoint but changes state only when it has
    // transactions, so a Coordinator-driven range may legitimately contain none
    // of this Realm's writes. Saying so and stopping is right; asserting would
    // fail a Realm for being idle. The caller aggregates -- a run where *no*
    // round ever checked anything is the one that proves nothing, and only the
    // caller can see that.
    if explicit_range && witnesses.is_empty() {
        println!("G-W checked 0 Realm key positions: this Realm wrote nothing in that range");
        return Ok(());
    }
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
        ChainEpoch::new(chain_epoch),
        CheckpointRef::new(
            CheckpointId::new(head),
            CheckpointHash::from_last_chain_hash(PHash::from_values(0, 0, 0, 0)),
        ),
    );
    // Skipping the destructive half lets the G-W assertion be re-run against a
    // Realm that has already been rolled back.  Verification that can only run
    // in the same process as the rollback it checks cannot be repeated when it
    // fails, which is exactly when it is needed.
    let verify_only = std::env::var("PSY_ROLLBACK_VERIFY_ONLY").is_ok();
    let plan_id = format!("realm-acceptance-{head}-{target}").into_bytes();
    // A Realm only ever follows phases the Coordinator published, so driving it
    // needs something to publish them.  This stands in for a Coordinator
    // rollback running against the same chain, advancing on each observation in
    // the order §4.1 lays out.
    let view = ScriptedCoordinator::new(head, target);
    if !verify_only {
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
            "archive".to_string(),
            // The last one, and the one PUBLISH_ALL waits for: without it the
            // Coordinator never announces the new epoch.
            "verify".to_string()
        ],
        "a Realm files a receipt at each barrier it reaches"
    );
    println!("{report:?}");
    assert_eq!(report.archived_rows, report.planned_rows);
    assert_eq!(report.deleted_rows, report.planned_rows);
    assert_eq!(view.observations(), 3, "one observation per phase gate");
    }

    // G-W on the Realm's own state, split in two because a Realm's rows above
    // the target come from two places and are undone two different ways.
    //
    // The rollback plan names what this Realm committed itself: those rows are
    // deleted or restored, and are settled the moment the rollback returns.
    // Everything else it wrote while syncing, and that is undone by re-fetching
    // from the Coordinator -- which cannot have happened yet if the Realm is
    // stopped, and must have happened once it has caught up.
    //
    // Asking one question of both is what made this report eight failures out
    // of 351 that were not failures.
    let assertion = RealmAssertion::from_env();
    let planned: std::collections::HashSet<Vec<u8>> = executor
        .plan(&recording, REALM_ID, realm_sub_id, &head_ref, target)
        .await?
        .checkpoints
        .iter()
        .flat_map(|checkpoint| checkpoint.rows.iter().map(|(_, locator)| locator.clone()))
        .collect();
    println!("the Realm's plan names {} rows", planned.len());

    let mut mismatches = Vec::new();
    let mut checked = 0usize;
    for witness in &witnesses {
        let named = planned.contains(&witness.locator);
        let wanted = match assertion {
            RealmAssertion::ManifestNamed => named,
            RealmAssertion::Resynced => !named,
        };
        if !wanted {
            continue;
        }
        let Ok(resolved) = decode_locator_canonical(&witness.locator) else {
            continue;
        };
        let Ok(live) = reader.read_as_of(&resolved, target).await else {
            continue;
        };
        checked += 1;
        let live_bytes = live.as_ref().map(|image| image.canonical_bytes());
        let wrong = match assertion {
            // What was there before must be back, byte for byte, and a key the
            // range created must be gone.
            RealmAssertion::ManifestNamed => live_bytes != witness.before,
            // Nothing to restore here -- the Coordinator's copy is authoritative
            // and the Realm re-fetches it. What must be true is that the
            // discarded branch's value is no longer what the row holds.
            //
            // Stated as "not the old value" rather than "the new value",
            // because this test does not know what the new branch wrote. It
            // would miss a re-fetch that happened to write the same bytes; the
            // tables actually in this set are keyed by pending id and IMT key,
            // and neither is ever reused, so that case does not arise here.
            RealmAssertion::Resynced => {
                witness.after.is_some() && live_bytes == witness.after
            }
        };
        if wrong {
            println!(
                "MISMATCH table={:?} locator={} before={:?} after={:?} live={:?}",
                resolved.physical_table(),
                hex::encode(&witness.locator),
                witness.before.as_ref().map(hex::encode),
                witness.after.as_ref().map(hex::encode),
                live_bytes.as_ref().map(hex::encode),
            );
            mismatches.push(format!("{:?}", resolved.physical_table()));
        }
    }
    println!("G-W checked {checked} Realm key positions ({assertion:?})");
    // A run that checked nothing proves nothing, and the two assertions cover
    // disjoint sets -- so each has to say for itself whether it had anything to
    // look at, and the caller aggregates across rounds.
    if checked == 0 {
        println!("nothing in this range belongs to {assertion:?}");
        return Ok(());
    }
    assert!(
        mismatches.is_empty(),
        "G-W ({assertion:?}) failed for {} of {checked} Realm keys: {mismatches:?}",
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
    async fn read_rollback_targets_after(
        &self,
        _epoch: u64,
    ) -> anyhow::Result<Vec<(u64, u64)>> {
        // The stand-in drives one rollback and keeps no history; the recovery
        // path that reads this runs against a real Coordinator.
        Ok(Vec::new())
    }

    async fn observe_published_head(
        &self,
        coordinator_head: &CanonicalChainRef<PHash>,
    ) -> anyhow::Result<Option<CanonicalChainRef<PHash>>> {
        // The stand-in publishes whatever it was handed; the Realm's recovery
        // path is exercised against a real control row, not this.
        Ok(Some(*coordinator_head))
    }

    async fn observe_phase(
        &self,
        _coordinator_head: &CanonicalChainRef<PHash>,
    ) -> anyhow::Result<ObservedRollbackPhase> {
        let look = self.looks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(match look {
            0 => ObservedRollbackPhase::Freeze { head: self.head, target: self.target },
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
