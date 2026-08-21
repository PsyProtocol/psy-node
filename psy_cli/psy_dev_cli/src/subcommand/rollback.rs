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
use psy_node_core::store::canonical_head::CanonicalHeadReadState;
use psy_node_core::store::rollback_participants::{RollbackParticipant, RollbackParticipantSet};
use psy_node_scylla::rollback::{
    CanonicalHeadNoTabletKeyspace, CoordinatorRollbackControlPlane, RollbackControlKeyspaces,
    ScyllaCanonicalHeadStore, ScyllaRollbackExecutor, ScyllaRollbackParticipantView,
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
    /// Carry an interrupted rollback to Idle.
    ///
    /// Separate from `to` so that finishing one is never something that happens
    /// because a height was mistyped: past the archive barrier the range is
    /// already decided, and a resume that took a target would invite giving it
    /// a different one.
    Resume,
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

    // Names this run in the archive. The range is in it so a second attempt at
    // the same rollback lands on the same rows, and a different one does not
    // collide with it.
    let plan_id = format!("dev-cli-{head}-{target}").into_bytes();

    println!("rolling back from {head} to {target}, {} participant(s)", participants.participants().len());
    let report = executor
        .roll_back(&recording, &head_ref, target, &plan_id, &participants, Some(&view))
        .await?;
    println!("{report:?}");
    if report.head < head {
        anyhow::bail!(
            "the plan started below the published head: planned from {} but {head} was already \
             published, so rows above {target} would be left that nothing will delete",
            report.head
        );
    }
    println!("done; the Coordinator and Realms restart themselves from here");
    Ok(())
}
