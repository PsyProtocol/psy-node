//! Drive a rollback from outside the chain.
//!
//! Everything here talks to Scylla and nothing else.  No RPC reaches a
//! processor, by design: the phase machine lives in the canonical head row, the
//! processors watch it, and this is the one writer that moves it.  That is also
//! what makes the tool usable when a processor is wedged -- the state it needs
//! is in the database, not in a process that may not be answering.
//!
//! It is not only a conductor. Archiving, deleting, restoring the singletons and
//! putting back rewritten rows all happen here, in this process, while the
//! Coordinator is frozen and the Realms follow the published phase. One writer
//! holds the authority for the whole operation; splitting the work from the
//! decision is what a barrier exists to prevent.
//!
//! Replaces `cargo test --test rollback_acceptance -- --ignored`, which drove
//! the same code through a test harness that could not be given arguments, could
//! not be run twice against one range, and reported through assertions.

use std::sync::Arc;

use clap::{Args, Subcommand};
use parth_core::PHash;
use psy_data::protocol::canonical_chain::{CanonicalChainRef, NetworkId};
use psy_data::protocol::chain_context::AuthorityScope;
use psy_core::constants::chain_id::PsyChainNetworkType;
use psy_node_core::store::canonical_head::{CanonicalHeadModelError, CanonicalHeadReadState};
use psy_node_core::store::rollback_participants::{RollbackParticipant, RollbackParticipantSet};
use psy_node_scylla::rollback::{
    CanonicalHeadNoTabletKeyspace, CoordinatorRollbackControlPlane, RollbackControlKeyspaces,
    ScyllaCanonicalHeadStore, ScyllaRollbackExecutor, ScyllaRollbackParticipantView,
    ScyllaRowImageReader, decode_locator_canonical,
};
use scylla::client::session::Session;
use scylla::client::session_builder::SessionBuilder;

#[derive(Args)]
pub struct RollbackArgs {
    #[command(subcommand)]
    pub command: RollbackCommand,

    #[arg(long, env = "PSY_SCYLLA_URL", default_value = "127.0.0.1:9042")]
    pub scylla_url: String,

    /// The Coordinator's state keyspace. Its `_no_tablet` sibling is derived,
    /// because the two are always named together and letting them be given
    /// separately is a way to point them at different chains.
    #[arg(long, default_value = "coordinator")]
    pub keyspace: String,

    /// Realms that take part, as `realm:sub`, comma separated.
    ///
    /// Empty means the Coordinator seals every barrier on its own receipt --
    /// a barrier in name only. Name the Realms that are actually running.
    #[arg(long, default_value = "0:1,1:1")]
    pub realms: String,

    #[arg(long, default_value = "local-devnet")]
    pub network: String,
}

#[derive(Subcommand)]
pub enum RollbackCommand {
    /// What the chain is doing: phase, epoch, heights, recent rollbacks.
    Status,
    /// Discard everything above a height.
    To(ToArgs),
    /// Check that a rollback restored what was there before.
    ///
    /// The G-W assertion of design-r1 §11: every physical key the discarded
    /// range touched reads, byte for byte, as it did before the range wrote it,
    /// and every key the range created no longer exists.
    Verify(VerifyArgs),
    /// Carry an interrupted rollback to Idle.
    ///
    /// Separate from `to` so that finishing one is never something that happens
    /// because a height was mistyped: past the archive barrier the range is
    /// already decided, and a resume that took a target would invite giving it
    /// a different one.
    Resume,
}

#[derive(Args)]
pub struct VerifyArgs {
    /// Which keyspace's own state to check. `coordinator`, or `0` / `1` for a
    /// Realm.
    #[arg(long, default_value = "coordinator")]
    pub who: String,

    /// For a Realm, which of its two kinds of row.
    ///
    /// A Realm's rows above the target come from two places and are undone two
    /// different ways, on opposite schedules, and one question cannot be asked
    /// of both.
    ///
    /// `manifest` covers what the Realm committed itself, which the rollback
    /// plan deletes or restores. Those are settled the moment the rollback
    /// returns and must be checked **before the Realm runs again** -- the tables
    /// have no version axis, so an as-of read returns whatever is stored now and
    /// a Realm that has resynced a few heights has overwritten the answer.
    ///
    /// `resync` covers what it wrote while merely syncing. No manifest names it;
    /// it is undone by re-fetching from the Coordinator, which cannot have
    /// happened while the Realm is stopped and must have happened once it has
    /// caught up. So that one runs **after** recovery, and asks the question
    /// that fits: the discarded branch's value must no longer be what the row
    /// holds.
    #[arg(long, default_value = "manifest")]
    pub assert: String,

    /// The range and branch. Taken from the most recent rollback when omitted,
    /// which is what an operator checking the rollback they just ran wants.
    #[arg(long)]
    pub head: Option<u64>,
    #[arg(long)]
    pub target: Option<u64>,
    /// The epoch the discarded range was committed under -- **not** the one the
    /// rollback opened. After a rollback a height carries manifests from both
    /// branches, and taking the later one compares this chain against the branch
    /// that replaced the discarded range: it passes, and proves nothing.
    #[arg(long)]
    pub epoch: Option<u64>,
}

#[derive(Args)]
pub struct ToArgs {
    /// The last height to keep.
    pub target: u64,
}

fn network_id(name: &str) -> anyhow::Result<NetworkId> {
    let kind = match name {
        "local-devnet" => PsyChainNetworkType::LocalDevnet,
        "psy-mainnet" => PsyChainNetworkType::PsyMainnet,
        "psy-public-testnet" => PsyChainNetworkType::PsyPublicTestnet,
        other => anyhow::bail!("unknown network {other}"),
    };
    Ok(NetworkId::from(kind))
}

fn participants(spec: &str) -> anyhow::Result<RollbackParticipantSet> {
    let mut set = vec![RollbackParticipant::new(AuthorityScope::Coordinator)];
    for entry in spec.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let (realm, sub) = entry
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("participant {entry:?} is not realm:sub"))?;
        set.push(RollbackParticipant::new(AuthorityScope::Realm {
            realm_id: realm.trim().parse()?,
            realm_sub_id: sub.trim().parse()?,
        }));
    }
    Ok(RollbackParticipantSet::try_new(set)?)
}

struct Chain {
    session: Arc<Session>,
    control: CoordinatorRollbackControlPlane,
    keyspace: String,
    no_tablet: String,
    network: NetworkId,
}

impl Chain {
    async fn open(args: &RollbackArgs) -> anyhow::Result<Self> {
        // The verification journal is what a restore reads to tell a row the
        // discarded range *created* from one it *rewrote*; without it the
        // restore fails closed and the rollback cannot finish. The control
        // plane switches it on from the environment, which is right for a
        // processor -- it is a per-deployment choice there -- and wrong for
        // this, where there is no rollback to be had without it. Set here so
        // the tool cannot be run in the one configuration that guarantees it
        // will stop halfway.
        //
        // The chain must still have been *running* with it set: this turns on
        // reading the journal, not writing it, and a range committed without it
        // has no observations to read.
        // SAFETY: single-threaded startup, before any task is spawned.
        unsafe { std::env::set_var("PSY_ROLLBACK_VERIFICATION_JOURNAL", "1") };

        let session = Arc::new(
            SessionBuilder::new()
                .known_nodes([args.scylla_url.clone()].iter())
                .build()
                .await?,
        );
        let no_tablet = format!("{}_no_tablet", args.keyspace);
        let keyspaces = RollbackControlKeyspaces::try_new(&args.keyspace, &no_tablet)?;
        let clock = Arc::new(psy_node_core::store::commit_window::CommitWindowClock::new());
        let control =
            CoordinatorRollbackControlPlane::prepare(session.clone(), clock, &keyspaces).await?;
        Ok(Self {
            session,
            control,
            keyspace: args.keyspace.clone(),
            no_tablet,
            network: network_id(&args.network)?,
        })
    }

    async fn head(&self) -> anyhow::Result<Option<CanonicalChainRef<PHash>>> {
        let recording = self.control.recording::<PHash>();
        Ok(
            match recording.canonical_head().read_canonical_head(self.network).await? {
                CanonicalHeadReadState::Current(stored) => Some(*stored.canonical_ref()),
                CanonicalHeadReadState::Uninitialized => None,
            },
        )
    }

    /// The height a keyspace has published, or `None` when the row is absent.
    ///
    /// Absent is a real state, not an error: between DELETING and RESTORING the
    /// Coordinator has no head singleton at all, and a rollback interrupted
    /// there is the one most in need of being finished.
    async fn published_height(&self, keyspace: &str) -> anyhow::Result<Option<u64>> {
        let rows = self
            .session
            .query_unpaged(
                format!("SELECT value FROM {keyspace}.u64_singleton_table WHERE obj_id = 1"),
                &[],
            )
            .await?
            .into_rows_result()?;
        Ok(rows.maybe_first_row::<(i64,)>()?.map(|row| row.0 as u64))
    }

    /// The chain epoch a Realm last reconciled itself to.
    ///
    /// The one thing that separates a Realm holding the current branch from one
    /// holding a branch that was discarded.  Heights cannot: once the
    /// Coordinator has produced past the old head the two agree and only the
    /// contents differ, which is exactly when a stale Realm looks healthiest.
    ///
    /// Absent means a Realm that has never synced, not one at epoch zero.
    async fn synced_epoch(&self, keyspace: &str) -> anyhow::Result<Option<u64>> {
        let rows = self
            .session
            .query_unpaged(
                format!(
                    "SELECT chain_epoch FROM {keyspace}_no_tablet.realm_sync_epoch \
                     WHERE network_chain_id = ?"
                ),
                (self.network.get() as i64,),
            )
            .await?
            .into_rows_result()?;
        Ok(rows.maybe_first_row::<(i64,)>()?.map(|row| row.0 as u64))
    }

    async fn in_flight(&self) -> anyhow::Result<Option<(u64, u64)>> {
        let recording = self.control.recording::<PHash>();
        Ok(
            match recording.canonical_head().read_canonical_head(self.network).await? {
                CanonicalHeadReadState::Current(stored) => {
                    stored.rollback_control().requested().map(|request| {
                        (
                            request.requested_head().checkpoint_id().get(),
                            request.target().checkpoint_id().get(),
                        )
                    })
                }
                CanonicalHeadReadState::Uninitialized => None,
            },
        )
    }
}

/// Print a line, and do not mind if nobody is listening.
///
/// `println!` panics when the write fails, and a closed stdout is what
/// `| head -2` looks like from in here. Reporting a chain's state should not
/// end in a backtrace because the reader had seen enough.
fn line(text: impl AsRef<str>) {
    use std::io::Write;
    let _ = writeln!(std::io::stdout().lock(), "{}", text.as_ref());
}

pub async fn run(args: RollbackArgs) -> anyhow::Result<()> {
    let chain = Chain::open(&args).await?;
    match &args.command {
        RollbackCommand::Status => status(&chain, &args).await,
        RollbackCommand::To(to) => roll_back(&chain, &args, Some(to.target)).await,
        RollbackCommand::Resume => roll_back(&chain, &args, None).await,
        RollbackCommand::Verify(verify) => run_verify(&chain, &args, verify).await,
    }
}

async fn status(chain: &Chain, args: &RollbackArgs) -> anyhow::Result<()> {
    let Some(head) = chain.head().await? else {
        line(format!("no canonical head in {}: this keyspace holds no chain", chain.keyspace));
        return Ok(());
    };
    let recording = chain.control.recording::<PHash>();
    let stored = match recording.canonical_head().read_canonical_head(chain.network).await? {
        CanonicalHeadReadState::Current(stored) => stored,
        CanonicalHeadReadState::Uninitialized => unreachable!("head was just read"),
    };
    line(format!(
        "chain      epoch {} at checkpoint {}",
        head.chain_epoch().get(),
        head.checkpoint().checkpoint_id().get()
    ));
    line(format!("phase      {}", stored.rollback_control().phase_name()));

    let mut heights = format!(
        "heights    {}={}",
        chain.keyspace,
        match chain.published_height(&chain.keyspace).await? {
            Some(height) => height.to_string(),
            // Only ever seen mid-rollback, and worth naming rather than printing
            // a dash: it is the fingerprint of a run interrupted between the
            // delete and the restore.
            None => "(none: delete has run, restore has not)".to_string(),
        }
    );
    for entry in args.realms.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        if let Some((realm, _)) = entry.split_once(':') {
            let keyspace = format!("realm_{}", realm.trim());
            let height = chain.published_height(&keyspace).await?;
            heights.push_str(&format!(
                "  {keyspace}={}",
                height.map(|h| h.to_string()).unwrap_or_else(|| "-".into())
            ));
        }
    }
    line(heights);

    // Heights alone say nothing about which branch a Realm is on, and after the
    // Coordinator has produced past the old head they agree while the contents
    // do not.  So the epoch each Realm last reconciled to is printed next to
    // the Coordinator's, and a Realm behind it is named as being behind rather
    // than left to look healthy.
    let mut epochs = format!("epochs     {}={}", chain.keyspace, head.chain_epoch().get());
    let mut behind: Vec<String> = Vec::new();
    for entry in args.realms.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        if let Some((realm, _)) = entry.split_once(':') {
            let keyspace = format!("realm_{}", realm.trim());
            match chain.synced_epoch(&keyspace).await {
                Ok(Some(epoch)) => {
                    epochs.push_str(&format!("  {keyspace}={epoch}"));
                    if epoch < head.chain_epoch().get() {
                        behind.push(keyspace);
                    }
                }
                Ok(None) => epochs.push_str(&format!("  {keyspace}=(never synced)")),
                // Not fatal: a keyspace that is not there is a Realm this chain
                // does not run, and status is the wrong place to insist on it.
                Err(_) => epochs.push_str(&format!("  {keyspace}=?")),
            }
        }
    }
    line(epochs);
    if !behind.is_empty() {
        line(format!(
            "BEHIND     {} on a branch this chain discarded; answers from there are stale \
             until each one reconciles",
            behind.join(", ")
        ));
    }

    match chain.in_flight().await? {
        Some((head, target)) => {
            line(format!("in flight  {head} -> {target}; finish it with `rollback resume`"))
        }
        None => line("in flight  none"),
    }
    Ok(())
}

async fn roll_back(chain: &Chain, args: &RollbackArgs, target: Option<u64>) -> anyhow::Result<()> {
    let in_flight = chain.in_flight().await?;
    let target = match (target, in_flight) {
        (Some(asked), Some((head, target))) => anyhow::bail!(
            "a rollback from {head} to {target} is already in flight; finish it with `rollback \
             resume` rather than starting one to {asked}. Past the archive barrier the range is \
             decided and a second target would restore a state nobody asked for"
        ),
        (Some(asked), None) => asked,
        (None, Some((_, target))) => {
            println!("resuming the rollback already in flight, to {target}");
            target
        }
        (None, None) => anyhow::bail!("no rollback is in flight; give a target with `rollback to`"),
    };

    let Some(head_ref) = chain.head().await? else {
        anyhow::bail!("no canonical head in {}", chain.keyspace);
    };
    let head = head_ref.checkpoint().checkpoint_id().get();
    if target >= head {
        anyhow::bail!("target {target} is not below the published head {head}");
    }

    let recording = chain.control.recording::<PHash>();
    let executor = ScyllaRollbackExecutor::prepare(
        chain.session.clone(),
        &chain.keyspace,
        &chain.no_tablet,
        chain.network.chain_id() as i64,
    )
    .await?;

    // The receipt view. Without it every barrier reads nothing and seals on the
    // Coordinator's own receipt, which is a barrier in name only once anyone
    // else is in the set.
    let head_reader = ScyllaCanonicalHeadStore::prepare(
        chain.session.clone(),
        CanonicalHeadNoTabletKeyspace::try_new(&chain.no_tablet)?,
    )
    .await?;
    let view = ScyllaRollbackParticipantView::<PHash>::prepare(
        chain.session.clone(),
        &chain.no_tablet,
        chain.network.chain_id() as i64,
        Arc::new(head_reader),
    )
    .await?;
    let participants = participants(&args.realms)?;

    // The head moves between reading it and asking to roll back from it, and on
    // a busy chain it moves often. The executor requires the request to name the
    // exact current head -- rightly, since a request naming a stale one would
    // leave the checkpoints above it undiscarded -- so the answer is to read it
    // again and ask again, not to treat an ordinary block as a failure.
    let mut head_ref = head_ref;
    let mut head = head;
    let mut attempt = 0;
    let report = loop {
        attempt += 1;
        line(format!(
            "rolling back from {head} to {target}, {} participant(s)",
            participants.participants().len()
        ));
        let plan_id = format!("dev-cli-{head}-{target}").into_bytes();
        match executor
            .roll_back(&recording, &head_ref, target, &plan_id, &participants, Some(&view))
            .await
        {
            Ok(report) => break report,
            Err(error) => {
                let moved = matches!(
                    error.downcast_ref::<CanonicalHeadModelError>(),
                    Some(CanonicalHeadModelError::RollbackRequestedHeadMismatch)
                );
                if !moved || attempt >= 5 {
                    return Err(error);
                }
                let Some(current) = chain.head().await? else {
                    return Err(error);
                };
                head_ref = current;
                head = head_ref.checkpoint().checkpoint_id().get();
                if target >= head {
                    anyhow::bail!("target {target} is no longer below the head {head}");
                }
                line(format!("  the head moved while asking; retrying from {head}"));
            }
        }
    };
    line(format!("{report:?}"));
    if report.head < head {
        anyhow::bail!(
            "the plan started below the published head: planned from {} but {head} was already \
             published, so rows above {target} would be left that nothing will delete",
            report.head
        );
    }
    line("done; the Coordinator and Realms restart themselves from here");
    Ok(())
}

/// One journal observation, as the assertion needs it.
struct Witness {
    locator: Vec<u8>,
    before: Option<Vec<u8>>,
    /// What the discarded branch left in the row. Only the resync assertion uses
    /// it, and it uses it to say that value must be gone.
    after: Option<Vec<u8>>,
    /// The checkpoint an as-of read landed on when the before image was taken,
    /// and set **only** for tables with a version axis.
    ///
    /// That makes it the discriminator for whether this key can still be judged
    /// once the chain has moved on. A version-axis row is still readable as it
    /// was at the target, because the earlier version is a different row the
    /// rollback left standing. An axis-less row has one row and one value, so
    /// the moment the chain re-produces the range it holds the new branch's
    /// value and the question can no longer be asked.
    versioned: bool,
}

/// The last rollback the chain recorded, as (head, target, discarded epoch).
async fn last_rollback(chain: &Chain) -> anyhow::Result<(u64, u64, u64)> {
    let rows = chain
        .session
        .query_unpaged(
            format!(
                "SELECT chain_epoch, previous_epoch, head, target FROM {}.rollback_event \
                 WHERE network_chain_id = ? LIMIT 8",
                chain.no_tablet
            ),
            (chain.network.chain_id() as i64,),
        )
        .await?
        .into_rows_result()?;
    // Nullable because a rollback whose request was never recorded leaves a row
    // with an outcome and nothing else; skipping those beats refusing to read
    // the table.
    for row in rows.rows::<(i64, Option<i64>, Option<i64>, Option<i64>)>()? {
        let (_, previous, head, target) = row?;
        if let (Some(previous), Some(head), Some(target)) = (previous, head, target) {
            return Ok((head as u64, target as u64, previous as u64));
        }
    }
    anyhow::bail!("this chain has no complete rollback record to check")
}

/// Every key position the discarded range touched, with what was there just
/// before the first commit above the target that wrote it.
///
/// Keyed by **position**, not by locator. A version-axis table encodes the
/// checkpoint into the locator, so one tree node written at ten heights is ten
/// locators; treating those as ten keys collapses "the first checkpoint above
/// the target that touched K" into "every checkpoint", which asserts the wrong
/// thing. At `c` the before image is the value at `c - 1`, while after a
/// rollback to T a read returns the value at T, and those agree only for the
/// first touch.
async fn witnesses_first_touch(
    chain: &Chain,
    keyspace: &str,
    reader: &ScyllaRowImageReader,
    target: u64,
    head: u64,
    chain_epoch: u64,
) -> anyhow::Result<Vec<Witness>> {
    let mut first: std::collections::BTreeMap<Vec<u8>, Witness> = std::collections::BTreeMap::new();
    for checkpoint in (target + 1)..=head {
        let rows = chain
            .session
            .query_unpaged(
                format!(
                    "SELECT locator, before_image, before_present, after_image, after_present \
                     , before_version FROM {keyspace}.rollback_verification_journal_by_epoch \
                     WHERE checkpoint_id = ? AND chain_epoch = ?"
                ),
                (checkpoint as i64, chain_epoch as i64),
            )
            .await?
            .into_rows_result()?;
        for row in rows.rows::<(
            Vec<u8>,
            Option<Vec<u8>>,
            Option<bool>,
            Option<Vec<u8>>,
            Option<bool>,
            Option<i64>,
        )>()?
        {
            let (locator, before, present, after, after_present, before_version) = row?;
            let Ok(resolved) = decode_locator_canonical(&locator) else { continue };
            let Ok(position) = reader.position_key(&resolved) else { continue };
            first.entry(position).or_insert(Witness {
                locator,
                before: before.filter(|_| present.unwrap_or(false)),
                after: after.filter(|_| after_present.unwrap_or(false)),
                versioned: before_version.is_some_and(|version| version >= 0),
            });
        }
    }
    Ok(first.into_values().collect())
}

async fn run_verify(chain: &Chain, args: &RollbackArgs, verify: &VerifyArgs) -> anyhow::Result<()> {
    let (head, target, epoch) = match (verify.head, verify.target, verify.epoch) {
        (Some(h), Some(t), Some(e)) => (h, t, e),
        (None, None, None) => {
            let found = last_rollback(chain).await?;
            line(format!(
                "checking the last rollback: {} -> {} on epoch {}",
                found.0, found.1, found.2
            ));
            found
        }
        _ => anyhow::bail!("give all three of --head, --target and --epoch, or none of them"),
    };

    let realm: Option<u32> = match verify.who.as_str() {
        "coordinator" => None,
        other => Some(other.parse().map_err(|_| {
            anyhow::anyhow!("--who takes `coordinator` or a realm id, not {other:?}")
        })?),
    };
    let keyspace = match realm {
        None => chain.keyspace.clone(),
        Some(id) => format!("realm_{id}"),
    };

    let reader = ScyllaRowImageReader::prepare(chain.session.clone(), &keyspace).await?;
    let witnesses = witnesses_first_touch(chain, &keyspace, &reader, target, head, epoch).await?;
    if witnesses.is_empty() {
        // Not a failure. A Realm changes state only when it has transactions,
        // so a range may hold none of its writes -- but a caller running this
        // over many rounds and never seeing a key checked is being told nothing,
        // and only that caller can tell the difference.
        line(format!("nothing in ({target}, {head}] on epoch {epoch} belongs to {keyspace}"));
        line("G-W checked 0 key positions");
        return Ok(());
    }

    // For a Realm, which half of its rows this run is about.
    let planned: Option<std::collections::HashSet<Vec<u8>>> = match realm {
        None => None,
        Some(realm_id) => {
            let sub_id: u16 = 1;
            let core = std::sync::Arc::new(
                psy_node_scylla::core::ScyllaCoreStore::<PHash, parth_core::pgoldilocks::PoseidonHasher>::new(
                    0,
                    0,
                    keyspace.clone(),
                    &[args.scylla_url.clone()],
                )
                .await?,
            );
            let control = psy_node_scylla::rollback::RealmRollbackControlPlane::setup(
                core.as_ref(),
                chain.network.chain_id() as i64,
            )
            .await?;
            let recording: psy_node_core::store::realm_commit_recording::RealmCommitRecording<PHash> =
                control.recording();
            let executor = psy_node_scylla::rollback::ScyllaRealmRollbackExecutor::prepare(
                chain.session.clone(),
                &keyspace,
                &format!("{keyspace}_no_tablet"),
            )
            .await?;
            // The head of the range being checked, not the chain's head now.
            // After the rollback the live head *is* the target, and planning
            // from it asks a Realm to undo a range of zero length. The hash is
            // the Coordinator's coordinate and is not consulted for a Realm's
            // own manifest, so carrying the current one over is harmless; the
            // height is what bounds the search.
            let live = chain
                .head()
                .await?
                .ok_or_else(|| anyhow::anyhow!("no canonical head"))?;
            let head_ref = CanonicalChainRef::new(
                chain.network,
                psy_data::protocol::canonical_chain::ChainEpoch::new(epoch),
                psy_data::protocol::canonical_chain::CheckpointRef::new(
                    psy_data::protocol::canonical_chain::CheckpointId::new(head),
                    *live.checkpoint().checkpoint_hash(),
                ),
            );
            let plan = executor
                .plan(&recording, realm_id, sub_id, &head_ref, target)
                .await?;
            let set: std::collections::HashSet<Vec<u8>> = plan
                .checkpoints
                .iter()
                .flat_map(|c| c.rows.iter().map(|(_, locator)| locator.clone()))
                .collect();
            line(format!("the Realm's plan names {} rows", set.len()));
            Some(set)
        }
    };

    // Whether the chain has already re-produced the range. An axis-less row has
    // one row and one value, so once the range is back the row holds the new
    // branch's value and no question can be asked of it -- which is not a
    // mismatch, though it reads exactly like one. The same `verify` passed on
    // 746 keys and then failed on a CheckpointLeaf a minute later, with nothing
    // changed but the clock.
    let live_head = chain
        .published_height(&chain.keyspace)
        .await?
        .unwrap_or(target);
    let too_late = live_head > target;
    if too_late {
        line(format!(
            "the chain has re-produced past the target ({live_head} > {target}), so rows in              tables without a version axis now hold the new branch's value; they are skipped"
        ));
    }

    let manifest_named = verify.assert == "manifest";
    if realm.is_some() && !matches!(verify.assert.as_str(), "manifest" | "resync") {
        anyhow::bail!("--assert takes `manifest` or `resync`, not {:?}", verify.assert);
    }

    let mut checked = 0usize;
    let mut skipped = 0usize;
    let mut wrong = Vec::new();
    for witness in &witnesses {
        if let Some(planned) = &planned {
            let named = planned.contains(&witness.locator);
            if named != manifest_named {
                continue;
            }
        }
        if too_late && !witness.versioned {
            skipped += 1;
            continue;
        }
        let Ok(resolved) = decode_locator_canonical(&witness.locator) else { continue };
        let Ok(live) = reader.read_as_of(&resolved, target).await else { continue };
        checked += 1;
        let live_bytes = live.as_ref().map(|image| image.canonical_bytes());
        let bad = if planned.is_some() && !manifest_named {
            // Nothing to restore here: the Coordinator's copy is authoritative
            // and the Realm re-fetches it. What must be true is that the
            // discarded branch's value is no longer what the row holds. Said
            // that way round rather than "the new value", because this does not
            // know what the new branch wrote.
            witness.after.is_some() && live_bytes == witness.after
        } else {
            live_bytes != witness.before
        };
        if bad {
            line(format!(
                "MISMATCH {:?} locator={} before={:?} after={:?} live={:?}",
                resolved.physical_table(),
                hex::encode(&witness.locator),
                witness.before.as_ref().map(hex::encode),
                witness.after.as_ref().map(hex::encode),
                live_bytes.as_ref().map(hex::encode),
            ));
            wrong.push(format!("{:?}", resolved.physical_table()));
        }
    }

    line(format!("G-W checked {checked} key positions in {keyspace}"));
    if skipped > 0 {
        line(format!(
            "  {skipped} skipped: no version axis, and the range has already been re-produced.              Run verify before the chain comes back to judge those."
        ));
    }
    if checked == 0 {
        line("nothing in this range belongs to the half being checked");
        return Ok(());
    }
    if !wrong.is_empty() {
        anyhow::bail!(
            "G-W failed for {} of {checked} keys in {keyspace}: {wrong:?}",
            wrong.len()
        );
    }
    line("G-W passed");
    Ok(())
}
