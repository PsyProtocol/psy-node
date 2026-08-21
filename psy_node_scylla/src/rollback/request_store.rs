//! Where an operator's request to roll back is written down.
//!
//! The request arrives at an edge and is carried out by the Coordinator
//! processor, so something durable has to sit between them.  It is a table
//! rather than a queue for two reasons.  A queue that a rollback can clear --
//! and §8.3 rotates the Redis namespaces on every rollback -- can lose the very
//! request that started it.  And a request is worth keeping: `rollback_event`
//! records what a rollback did, and this records that somebody asked for it,
//! which together are the whole story.
//!
//! ## One partition, newest first
//!
//! The same shape as `rollback_event`, and for the same reason: "is there
//! anything for me" is asked once per block attempt and must be a bounded read
//! of one partition's head, not a scan.
//!
//! ## Rows are never deleted or rewritten
//!
//! Re-sending is the operator's ordinary retry -- a request that was not picked
//! up before the chain produced expires on its own, and the fix is a new request
//! naming the new head.  So attempts accumulate, and `consumed_epoch` is the
//! only column that is ever written after the fact.

use std::sync::Arc;

use psy_node_core::store::rollback_request::RollbackRequestEntry;
use scylla::client::session::Session;
use scylla::response::query_result::QueryResult;
use scylla::statement::prepared::PreparedStatement;
use scylla::value::{CqlValue, Row};

pub const COORDINATOR_ROLLBACK_REQUEST_TABLE: &str = "coordinator_rollback_request";

/// How many microseconds to walk forward looking for a free slot.
///
/// Two requests in the same microsecond would otherwise be one row, and the
/// second operator's would be the one that vanished.  Bounded rather than
/// unbounded because if this many consecutive slots are taken, something other
/// than a clock collision is going on and quietly spinning would hide it.
const MAX_SLOT_PROBES: i64 = 32;

pub struct ScyllaRollbackRequestStore {
    session: Arc<Session>,
    network_chain_id: i64,
    insert: PreparedStatement,
    mark_consumed: PreparedStatement,
    read_recent: PreparedStatement,
}

impl ScyllaRollbackRequestStore {
    pub async fn create_table(session: &Session, no_tablet_keyspace: &str) -> anyhow::Result<()> {
        session
            .query_unpaged(
                format!(
                    "CREATE TABLE IF NOT EXISTS \
                     {no_tablet_keyspace}.{COORDINATOR_ROLLBACK_REQUEST_TABLE} (
                        network_chain_id BIGINT,
                        requested_at_us BIGINT,
                        target BIGINT,
                        expected_head BIGINT,
                        requested_by TEXT,
                        consumed_epoch BIGINT,
                        PRIMARY KEY ((network_chain_id), requested_at_us)
                    ) WITH CLUSTERING ORDER BY (requested_at_us DESC)"
                ),
                &[],
            )
            .await?;
        session.await_schema_agreement().await?;
        Ok(())
    }

    pub async fn prepare(
        session: Arc<Session>,
        no_tablet_keyspace: &str,
        network_chain_id: i64,
    ) -> anyhow::Result<Self> {
        // `IF NOT EXISTS` so a second request in the same microsecond is
        // refused rather than silently overwriting the first.
        let insert = session
            .prepare(format!(
                "INSERT INTO {no_tablet_keyspace}.{COORDINATOR_ROLLBACK_REQUEST_TABLE} \
                 (network_chain_id, requested_at_us, target, expected_head, requested_by) \
                 VALUES (?, ?, ?, ?, ?) IF NOT EXISTS"
            ))
            .await?;
        // `IF EXISTS` for the reason `set_outcome` on the event table learned:
        // a bare UPDATE creates the row, and a mark that arrived for an entry
        // nobody wrote would leave a request with a consumed epoch and no
        // request in it.
        let mark_consumed = session
            .prepare(format!(
                "UPDATE {no_tablet_keyspace}.{COORDINATOR_ROLLBACK_REQUEST_TABLE} \
                 SET consumed_epoch = ? \
                 WHERE network_chain_id = ? AND requested_at_us = ? IF EXISTS"
            ))
            .await?;
        let read_recent = session
            .prepare(format!(
                "SELECT requested_at_us, target, expected_head, requested_by, consumed_epoch \
                 FROM {no_tablet_keyspace}.{COORDINATOR_ROLLBACK_REQUEST_TABLE} \
                 WHERE network_chain_id = ? LIMIT ?"
            ))
            .await?;
        Ok(Self {
            session,
            network_chain_id,
            insert,
            mark_consumed,
            read_recent,
        })
    }

    /// Write down a request, and return the microsecond that identifies it.
    ///
    /// Nothing here judges the request.  Whether it still stands when the
    /// processor gets to it is `decide_pickup`'s answer, and whether the range
    /// can be planned at all is the planner's -- a store that refused requests
    /// would be a third opinion, and the quiet one always drifts.
    pub async fn submit(
        &self,
        target: u64,
        expected_head: u64,
        requested_by: &str,
    ) -> anyhow::Result<i64> {
        let target = i64::try_from(target)?;
        let expected_head = i64::try_from(expected_head)?;
        let mut at = now_us()?;
        for _ in 0..MAX_SLOT_PROBES {
            let result = self
                .session
                .execute_unpaged(
                    &self.insert,
                    (
                        self.network_chain_id,
                        at,
                        target,
                        expected_head,
                        requested_by,
                    ),
                )
                .await?;
            if lwt_applied(result)? {
                return Ok(at);
            }
            at += 1;
        }
        anyhow::bail!(
            "{MAX_SLOT_PROBES} consecutive request slots from {at} are taken; the mailbox is not \
             accepting requests"
        )
    }

    /// The request that counts: the most recent one written.
    pub async fn newest(&self) -> anyhow::Result<Option<RollbackRequestEntry>> {
        Ok(self.recent(1).await?.into_iter().next())
    }

    /// The last `limit` requests, newest first.
    pub async fn recent(&self, limit: i32) -> anyhow::Result<Vec<RollbackRequestEntry>> {
        let rows = self
            .session
            .execute_unpaged(&self.read_recent, (self.network_chain_id, limit))
            .await?
            .into_rows_result()?;
        let mut entries = Vec::new();
        for row in rows.rows::<(i64, i64, i64, String, Option<i64>)>()? {
            let (requested_at_us, target, expected_head, requested_by, consumed_epoch) = row?;
            entries.push(RollbackRequestEntry {
                requested_at_us,
                target: target as u64,
                expected_head: expected_head as u64,
                requested_by,
                consumed_epoch: consumed_epoch.map(|epoch| epoch as u64),
            });
        }
        Ok(entries)
    }

    /// Record that a rollback was started for this request, in this epoch.
    ///
    /// Written after `start_rollback` has succeeded rather than before.  A mark
    /// written first and then not followed by a rollback would retire a request
    /// nothing acted on, and the operator would have to notice that by
    /// themselves; this way the worst case is a request taken up twice, and the
    /// head it names already prevents that.
    pub async fn mark_consumed(&self, requested_at_us: i64, chain_epoch: u64) -> anyhow::Result<()> {
        let chain_epoch = i64::try_from(chain_epoch)?;
        self.session
            .execute_unpaged(
                &self.mark_consumed,
                (chain_epoch, self.network_chain_id, requested_at_us),
            )
            .await?;
        Ok(())
    }
}

/// Read the `[applied]` column of an LWT result.
///
/// By name and out of an untyped row, the same way `authority_timestamp_store`
/// does it: a refused LWT also returns the row that refused it, so the result
/// has as many columns as the table and a fixed tuple cannot type-check against
/// both outcomes.
fn lwt_applied(result: QueryResult) -> anyhow::Result<bool> {
    let rows = result.into_rows_result()?;
    let applied_column = rows
        .column_specs()
        .get_by_name("[applied]")
        .ok_or_else(|| anyhow::anyhow!("an LWT result carried no [applied] column"))?;
    let row = rows.single_row::<Row>()?;
    match row.columns.get(applied_column.0) {
        Some(Some(CqlValue::Boolean(applied))) => Ok(*applied),
        other => anyhow::bail!("an LWT [applied] column held {other:?} rather than a boolean"),
    }
}

fn now_us() -> anyhow::Result<i64> {
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| anyhow::anyhow!("system clock is before the Unix epoch: {error}"))?
        .as_micros();
    Ok(i64::try_from(micros)?)
}
