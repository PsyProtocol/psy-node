//! The Redis namespaces and NATS streams a chain has left behind.
//!
//! Every rollback moves a node onto `{db_namespace}_e{epoch}` for its Redis
//! stores and its JetStream stream, which is what makes the discarded branch's
//! queue messages and temp state unreachable rather than merely unlikely to be
//! hit.  What it does not do is remove them.  That is the deliberate half of the
//! trade: a purge that runs during a rollback has to be crash-safe and has to
//! remember every store, and forgetting one costs the chain -- forgetting to
//! collect garbage costs disk.
//!
//! So collection is a separate, deliberate act, and this is it.
//!
//! The one thing it must not do is delete a branch something is still on.  A
//! Realm the grace window left behind is still working on the older epoch, on
//! purpose, and its queue lives there; taking it away would strand work that was
//! going to be finished or discarded on its own.  So every participant is asked
//! which epoch it is on first, and those are refused.

use clap::{Parser, Subcommand};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Parser, Debug)]
pub struct BranchesArgs {
    #[command(subcommand)]
    pub command: BranchesCommand,

    #[arg(long, env = "PSY_SCYLLA_URL", default_value = "127.0.0.1:9042")]
    pub scylla_url: String,

    #[arg(long, env = "PSY_REDIS_URL", default_value = "redis://127.0.0.1:6379")]
    pub redis_url: String,

    #[arg(long, env = "PSY_NATS_URL", default_value = "nats://127.0.0.1:4222")]
    pub nats_url: String,

    /// The Coordinator's state keyspace.
    #[arg(long, default_value = "coordinator")]
    pub keyspace: String,

    /// Realms that are part of this chain, as `realm:sub`, comma separated.
    #[arg(long, default_value = "0:1,1:1")]
    pub realms: String,

    #[arg(long, default_value = "0")]
    pub network_chain_id: i64,
}

#[derive(Subcommand, Debug)]
pub enum BranchesCommand {
    /// What branches exist, and which of them anything is still on.
    List,
    /// Delete the branches nothing is on.
    Prune {
        /// How many retired branches to keep, newest first.
        ///
        /// One by default, because the branch a chain has just left is the one
        /// an investigation into the rollback that left it will want.
        #[arg(long, default_value = "1")]
        keep: usize,
        /// Actually delete. Without it this says what it would delete and stops.
        #[arg(long)]
        yes: bool,
    },
}

/// A namespace as it appears in Redis or NATS, split back into what it was
/// built from.
///
/// Named by parsing rather than by asking, because the point is to find what is
/// *there* -- including branches from a deployment that is no longer running,
/// which nothing can be asked about.
fn split_branch(name: &str) -> Option<(String, u64)> {
    let (base, epoch) = name.rsplit_once("_e")?;
    Some((base.to_string(), epoch.parse().ok()?))
}

pub async fn run(args: BranchesArgs) -> anyhow::Result<()> {
    let live = live_epochs(&args).await?;
    println!("live branches (nothing here may be deleted)");
    for (ns, epoch) in &live {
        println!("  {ns:<16} epoch {epoch}");
    }

    let redis = redis::Client::open(args.redis_url.as_str())?;
    let mut conn = redis.get_multiplexed_async_connection().await?;
    let keys: Vec<String> = redis::cmd("KEYS").arg("*").query_async(&mut conn).await?;

    let nats = async_nats::connect(&args.nats_url).await?;
    let js = async_nats::jetstream::new(nats);
    let mut streams = Vec::new();
    {
        use futures::StreamExt;
        let mut names = js.stream_names();
        while let Some(name) = names.next().await {
            streams.push(name?);
        }
    }

    // Grouped by branch, because a branch is what gets kept or dropped: its
    // Redis hashes and its stream go together or the leftovers are worse than
    // either -- a stream with no temp state behind it looks like a live branch
    // and is not.
    let mut found: BTreeMap<(String, u64), (Vec<String>, Vec<String>)> = BTreeMap::new();
    for key in &keys {
        // TKVSV1-{branch}-{realm}-{sub} and TMPPSV1-{branch}-{realm}-{sub}-{pending}
        let Some(rest) = key.split_once('-').map(|(_, rest)| rest) else { continue };
        let base = rest.split('-').next().unwrap_or("");
        let Some(branch) = split_branch(base) else { continue };
        found.entry(branch).or_default().0.push(key.clone());
    }
    for stream in &streams {
        let Some(base) = stream.strip_suffix("_stream") else { continue };
        let Some(branch) = split_branch(base) else { continue };
        found.entry(branch).or_default().1.push(stream.clone());
    }

    let retired: Vec<_> = found
        .iter()
        .filter(|((ns, epoch), _)| live.get(ns.as_str()).is_none_or(|live| live != epoch))
        .collect();

    println!("\nretired branches ({} found)", retired.len());
    for ((ns, epoch), (redis_keys, stream_names)) in &retired {
        println!(
            "  {ns}_e{epoch:<6} {} redis key(s), {} stream(s)",
            redis_keys.len(),
            stream_names.len()
        );
    }

    let BranchesCommand::Prune { keep, yes } = args.command else {
        return Ok(());
    };

    // Newest kept, because a rollback under investigation is a recent one.
    let mut by_age: Vec<_> = retired.iter().map(|(branch, _)| (*branch).clone()).collect();
    by_age.sort_by_key(|(ns, epoch)| (ns.clone(), std::cmp::Reverse(*epoch)));
    let mut kept_per_ns: BTreeMap<String, usize> = BTreeMap::new();
    let mut doomed = Vec::new();
    for (ns, epoch) in by_age {
        let seen = kept_per_ns.entry(ns.clone()).or_default();
        if *seen < keep {
            *seen += 1;
            continue;
        }
        doomed.push((ns, epoch));
    }

    if doomed.is_empty() {
        println!("\nnothing to prune: every retired branch is within the {keep} kept per namespace");
        return Ok(());
    }
    println!("\n{} branch(es) would be deleted:", doomed.len());
    for (ns, epoch) in &doomed {
        println!("  {ns}_e{epoch}");
    }
    if !yes {
        println!("\nnothing was deleted. Pass --yes to do it.");
        return Ok(());
    }

    for branch in &doomed {
        let (redis_keys, stream_names) = &found[branch];
        for key in redis_keys {
            let _: i64 = redis::cmd("DEL").arg(key).query_async(&mut conn).await?;
        }
        for name in stream_names {
            js.delete_stream(name).await?;
        }
        println!(
            "deleted {}_e{}: {} redis key(s), {} stream(s)",
            branch.0,
            branch.1,
            redis_keys.len(),
            stream_names.len()
        );
    }
    Ok(())
}

/// The epoch each participant is on right now.
///
/// Read from each participant's own keyspace, the same way each of them reads
/// it at startup to decide which branch to come up on -- so what this refuses to
/// delete is exactly what they are using, including a Realm that is behind.
async fn live_epochs(args: &BranchesArgs) -> anyhow::Result<BTreeMap<String, u64>> {
    use scylla::client::session_builder::SessionBuilder;
    let session = SessionBuilder::new()
        .known_nodes(args.scylla_url.split(',').map(str::trim).collect::<Vec<_>>())
        .build()
        .await?;

    let mut live = BTreeMap::new();
    let epoch = psy_node_scylla::rollback::coordinator_chain_epoch(
        &session,
        &format!("{}_no_tablet", args.keyspace),
        args.network_chain_id,
    )
    .await?;
    live.insert(args.keyspace.clone(), epoch);

    let mut seen = BTreeSet::new();
    for entry in args.realms.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let Some((realm, _)) = entry.split_once(':') else { continue };
        if !seen.insert(realm.to_string()) {
            continue;
        }
        let keyspace = format!("realm_{}", realm.trim());
        let epoch = psy_node_scylla::rollback::realm_chain_epoch(
            &session,
            &format!("{keyspace}_no_tablet"),
            args.network_chain_id,
        )
        .await?;
        live.insert(keyspace, epoch);
    }
    Ok(live)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_branch_is_the_name_and_the_epoch() {
        assert_eq!(split_branch("coordinator_e17"), Some(("coordinator".into(), 17)));
        assert_eq!(split_branch("realm_0_e3"), Some(("realm_0".into(), 3)));
    }

    #[test]
    fn a_namespace_from_before_branches_is_not_one() {
        // Chains that ran before the epoch was part of the name still have
        // these, and they are not epoch zero -- there is no telling which branch
        // they belong to, so they are left alone rather than guessed at.
        assert_eq!(split_branch("coordinator"), None);
        assert_eq!(split_branch("realm_0"), None);
    }
}
