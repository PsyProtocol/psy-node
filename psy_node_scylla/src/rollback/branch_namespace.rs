//! The name a node's branch-local stores answer to.
//!
//! A rollback puts the Scylla keyspaces back to a checkpoint that really
//! existed.  It does nothing at all to the stores that are not keyspaces: the
//! NATS stream and its subjects, the Redis KV store, the Redis proof-store
//! buckets.  Those keep holding the discarded branch's work, and because they
//! are keyed by ids the new branch issues again -- pending ids, gathering
//! cursors, job ids -- the old entries do not look old.  They look like this
//! branch's.
//!
//! That cost the chain a full stop, twice over in one afternoon.  A deploy job
//! left in the stream referenced a contract-code row the rollback had deleted,
//! so it could never complete, was never acked, and sat at the head of the
//! queue while the Coordinator waited on it for good.  A Realm resumed a
//! gathering cursor Redis still held from the discarded branch, re-submitted an
//! end cap the Edge had already recorded, and parked.  Every keyspace passed
//! G-W.  All three heights agreed.  The chain was dead.
//!
//! So these stores get a name that carries the branch, and the branch is the
//! chain epoch -- the same discriminator manifests and the verification journal
//! are already partitioned by.  After a rollback a node comes up on a name
//! nothing has ever written to, and the discarded branch's work is not cleaned
//! up so much as made unreachable.  Nothing has to remember to purge it, which
//! matters because purging is the kind of thing that gets one store right and
//! forgets the next.  What is left behind is garbage, and garbage costs disk;
//! what was left behind before was a poison message, and that cost the chain.
//!
//! **Scylla keyspaces keep their plain names.**  They hold the rolled-back
//! state itself -- the thing that was repaired rather than abandoned -- and
//! renaming them per epoch would orphan the chain at every rollback.

use scylla::client::session::Session;

/// What the Redis stores and the NATS stream are named for this branch.
///
/// One string, because one string already drives all of them: it is the Redis
/// KV namespace, the Redis proof-store namespace, the JetStream stream name,
/// and the first token of every queue subject.
pub fn branch_namespace(db_namespace: &str, chain_epoch: u64) -> String {
    format!("{db_namespace}_e{chain_epoch}")
}

/// The epoch a Coordinator is on, read from its own canonical head.
///
/// Read-only and free of the control plane, which prepares statements and
/// creates tables -- reasonable for a processor and wrong for an Edge that only
/// wants to know which branch it is serving.
///
/// The canonical ref is a fixed 65-byte codec whose layout is declared in
/// `psy_data::protocol::canonical_chain`; the epoch is bytes 14..22, and the
/// magic and version are checked rather than assumed so a layout change is a
/// startup failure instead of a namespace nobody can find.
pub async fn coordinator_chain_epoch(
    session: &Session,
    no_tablet_keyspace: &str,
    network_chain_id: i64,
) -> anyhow::Result<u64> {
    use psy_data::protocol::canonical_chain::{
        CANONICAL_CHAIN_REF_CODEC_VERSION, CANONICAL_CHAIN_REF_MAGIC,
    };

    let query = session
        .query_unpaged(
            format!(
                "SELECT canonical_ref FROM {no_tablet_keyspace}.\
                 {} WHERE network_chain_id = ?",
                super::COORDINATOR_CANONICAL_HEAD_TABLE
            ),
            (network_chain_id,),
        )
        .await;
    // A keyspace that is not there yet is genesis, not a failure.  This runs
    // before the store that creates the schema -- it has to, the name it
    // returns is what the store is built with -- so on a chain being started
    // for the first time the table it reads does not exist.  Answering with an
    // error there stops every fresh chain from ever starting.
    let Some(rows) = row_or_genesis(query)? else {
        return Ok(0);
    };
    // No row is a chain that has not started, not a chain at a strange epoch:
    // genesis is epoch zero and that is the right name to come up on.
    let Some((Some(bytes),)) = rows.maybe_first_row::<(Option<Vec<u8>>,)>()? else {
        return Ok(0);
    };
    if bytes.len() < 22 || bytes[0..8] != CANONICAL_CHAIN_REF_MAGIC {
        anyhow::bail!(
            "the canonical head in {no_tablet_keyspace} is not a canonical chain ref; this node \
             cannot tell which branch it is on and would come up on a namespace shared with a \
             branch that was discarded"
        );
    }
    let version = u16::from_le_bytes([bytes[8], bytes[9]]);
    if version != CANONICAL_CHAIN_REF_CODEC_VERSION {
        anyhow::bail!(
            "the canonical head in {no_tablet_keyspace} is codec version {version}, and this \
             build only knows {CANONICAL_CHAIN_REF_CODEC_VERSION}"
        );
    }
    Ok(u64::from_le_bytes(bytes[14..22].try_into()?))
}

/// The epoch a Realm is on, read from the epoch it last reconciled itself to.
///
/// Its own, deliberately, and not the Coordinator's.  A Realm that has been
/// left behind by a rollback is still working on the older branch and its
/// queued work belongs there; pulling its stores out from under it mid-flight
/// would strand that work rather than let it finish or be discarded with the
/// rest.  When it does reconcile it restarts, and comes back on the new name
/// along with everything else.
///
/// Absent means a Realm that has never synced, which has no discarded branch to
/// avoid.
pub async fn realm_chain_epoch(
    session: &Session,
    no_tablet_keyspace: &str,
    network_chain_id: i64,
) -> anyhow::Result<u64> {
    let query = session
        .query_unpaged(
            format!(
                "SELECT chain_epoch FROM {no_tablet_keyspace}.{} WHERE network_chain_id = ?",
                super::REALM_SYNC_EPOCH_TABLE
            ),
            (network_chain_id,),
        )
        .await;
    // As above: on a chain being started for the first time this table does not
    // exist yet, and a Realm that has never synced is at genesis.
    let Some(rows) = row_or_genesis(query)? else {
        return Ok(0);
    };
    Ok(rows.maybe_first_row::<(i64,)>()?.map(|row| row.0 as u64).unwrap_or(0))
}

/// `None` when the table is not there yet, the error when it is something else.
///
/// Only "this keyspace or table does not exist" is forgiven, and only because a
/// node reads its branch *before* the store that creates the schema -- it has
/// to, since the name this returns is what that store is built with.  Every
/// other failure is still a failure: a node that cannot tell which branch it is
/// on must not come up on a guess.
fn row_or_genesis(
    result: Result<scylla::response::query_result::QueryResult, scylla::errors::ExecutionError>,
) -> anyhow::Result<Option<scylla::response::query_result::QueryRowsResult>> {
    use scylla::errors::{DbError, ExecutionError, RequestAttemptError};
    match result {
        Ok(result) => Ok(Some(result.into_rows_result()?)),
        Err(ExecutionError::LastAttemptError(RequestAttemptError::DbError(
            DbError::Invalid,
            _,
        ))) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// The branch namespace a Coordinator node should come up on, and the epoch it
/// names.
///
/// Both, because an Edge needs the epoch afterwards to notice it has changed --
/// see `watch_branch_and_reload` -- and re-reading it separately would let the
/// two disagree across a rollback that landed in between.
///
/// Opens its own short-lived session rather than borrowing the node's, because
/// this has to answer *before* the stores it names are built, and on an Edge
/// the node's Scylla store is built after them.  One connection at startup, for
/// one row.
pub async fn coordinator_branch_namespace(
    scylla_url: &str,
    db_namespace: &str,
    network_chain_id: i64,
) -> anyhow::Result<(String, u64)> {
    let session = open_reader_session(scylla_url).await?;
    let epoch =
        coordinator_chain_epoch(&session, &format!("{db_namespace}_no_tablet"), network_chain_id)
            .await?;
    Ok((branch_namespace(db_namespace, epoch), epoch))
}

/// The branch namespace a Realm node should come up on, and the epoch it names.
pub async fn realm_branch_namespace(
    scylla_url: &str,
    db_namespace: &str,
    network_chain_id: i64,
) -> anyhow::Result<(String, u64)> {
    let session = open_reader_session(scylla_url).await?;
    let epoch =
        realm_chain_epoch(&session, &format!("{db_namespace}_no_tablet"), network_chain_id).await?;
    Ok((branch_namespace(db_namespace, epoch), epoch))
}

/// Restart this process when the branch changes under it.
///
/// For Edges, and only for Edges.  A processor already restarts on its own
/// schedule -- it knows when it has finished its share of a rollback, and a
/// watcher racing that would cut it off part way.  An Edge has no such moment:
/// it holds the stores it opened at startup, and after a rollback the processor
/// beside it comes back on a name the Edge has never heard of.  Workers then ask
/// an Edge that is still serving the discarded branch's queue, find nothing, and
/// the chain stalls with every part of it apparently healthy.
///
/// Restarting is the whole response, because the supervisor already restarts on
/// exit 75 and startup already reads the branch.  Nothing here needs to know
/// what changed.
///
/// A read that fails is not a change: the branch is only ever declared to have
/// moved on an epoch this actually read, so a database blip costs a poll rather
/// than a restart.
pub fn watch_branch_and_reload(
    scylla_url: String,
    db_namespace: String,
    network_chain_id: i64,
    realm: bool,
    started_on: u64,
) {
    tokio::spawn(async move {
        let no_tablet = format!("{db_namespace}_no_tablet");
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            let Ok(session) = open_reader_session(&scylla_url).await else {
                continue;
            };
            let now = if realm {
                realm_chain_epoch(&session, &no_tablet, network_chain_id).await
            } else {
                coordinator_chain_epoch(&session, &no_tablet, network_chain_id).await
            };
            let std::result::Result::Ok(now) = now else {
                continue;
            };
            if now != started_on {
                tracing::warn!(
                    "[EDGE] the chain moved from epoch {} to {} while this Edge was serving \
                     epoch {}; restarting so its queue and Redis namespaces are the ones the \
                     processor is now using (exit {})",
                    started_on,
                    now,
                    started_on,
                    psy_node_core::store::rollback_reload::EXIT_CODE_ROLLBACK_RELOAD
                );
                // Given a moment to reach the log before the process goes.
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                std::process::exit(
                    psy_node_core::store::rollback_reload::EXIT_CODE_ROLLBACK_RELOAD,
                );
            }
        }
    });
}

/// A plain session for one read.
///
/// Deliberately without the commit-window timestamp generator the node's own
/// session carries: nothing here writes, and borrowing that machinery would
/// tie the question "which branch am I on" to the clock a commit uses.
pub(crate) async fn open_reader_session(scylla_url: &str) -> anyhow::Result<Session> {
    use scylla::client::session_builder::SessionBuilder;
    Ok(SessionBuilder::new()
        .known_nodes(scylla_url.split(',').map(str::trim).collect::<Vec<_>>())
        .connection_timeout(std::time::Duration::from_secs(120))
        .build()
        .await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_branch_is_part_of_the_name() {
        assert_eq!(branch_namespace("coordinator", 0), "coordinator_e0");
        assert_eq!(branch_namespace("realm_0", 15), "realm_0_e15");
    }

    #[test]
    fn two_epochs_never_share_a_name() {
        // The whole point: the discarded branch's queue and Redis entries are
        // unreachable from the new one rather than merely unlikely to be hit.
        assert_ne!(branch_namespace("coordinator", 14), branch_namespace("coordinator", 15));
    }
}
