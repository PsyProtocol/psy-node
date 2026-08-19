//! Where a chain's rollback history lives.
//!
//! One partition per network and one row per rollback, clustered by the epoch
//! that rollback allocated, descending.  That ordering is in the schema rather
//! than in a query, so "what were the last few rollbacks" is a bounded read of
//! one partition's head instead of a scan -- which matters because this is the
//! table someone reaches for when the chain is already in a state they do not
//! understand.
//!
//! The participant set is stored as the concatenated canonical scope bytes, the
//! same encoding manifests, allocator rows and receipts partition by.  Storing
//! it any other way would create a second spelling of an authority's identity,
//! and then an audit could disagree with the evidence it is auditing.

use std::sync::Arc;

use psy_data::protocol::chain_context::AUTHORITY_SCOPE_LEN;
use psy_node_core::store::rollback_event::{RollbackEvent, RollbackEventStore, RollbackOutcome};
use scylla::client::session::Session;
use scylla::statement::prepared::PreparedStatement;

pub const ROLLBACK_EVENT_TABLE: &str = "rollback_event";

/// The set is the concatenation of its members' canonical scope bytes.
const SCOPE_BYTES: usize = AUTHORITY_SCOPE_LEN;

pub struct ScyllaRollbackEventStore {
    session: Arc<Session>,
    network_chain_id: i64,
    insert: PreparedStatement,
    set_outcome: PreparedStatement,
    read_recent: PreparedStatement,
}

impl ScyllaRollbackEventStore {
    pub async fn create_table(session: &Session, no_tablet_keyspace: &str) -> anyhow::Result<()> {
        session
            .query_unpaged(
                format!(
                    "CREATE TABLE IF NOT EXISTS {no_tablet_keyspace}.{ROLLBACK_EVENT_TABLE} (
                        network_chain_id BIGINT,
                        chain_epoch BIGINT,
                        previous_epoch BIGINT,
                        head BIGINT,
                        target BIGINT,
                        plan_id BLOB,
                        participants BLOB,
                        outcome SMALLINT,
                        archived_rows BIGINT,
                        deleted_rows BIGINT,
                        requested_at_us BIGINT,
                        PRIMARY KEY ((network_chain_id), chain_epoch)
                    ) WITH CLUSTERING ORDER BY (chain_epoch DESC)"
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
        let insert = session
            .prepare(format!(
                "INSERT INTO {no_tablet_keyspace}.{ROLLBACK_EVENT_TABLE} \
                 (network_chain_id, chain_epoch, previous_epoch, head, target, plan_id, \
                  participants, outcome, archived_rows, deleted_rows, requested_at_us) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            ))
            .await?;
        // Only the outcome columns, so completing a rollback cannot rewrite the
        // range it was asked for.  What the request said and what happened are
        // different claims and an audit needs to be able to compare them.
        let set_outcome = session
            .prepare(format!(
                "UPDATE {no_tablet_keyspace}.{ROLLBACK_EVENT_TABLE} \
                 SET outcome = ?, archived_rows = ?, deleted_rows = ? \
                 WHERE network_chain_id = ? AND chain_epoch = ?"
            ))
            .await?;
        let read_recent = session
            .prepare(format!(
                "SELECT chain_epoch, previous_epoch, head, target, plan_id, participants, \
                        outcome, archived_rows, deleted_rows, requested_at_us \
                 FROM {no_tablet_keyspace}.{ROLLBACK_EVENT_TABLE} \
                 WHERE network_chain_id = ? LIMIT ?"
            ))
            .await?;
        Ok(Self {
            session,
            network_chain_id,
            insert,
            set_outcome,
            read_recent,
        })
    }

    fn encode_scopes(scopes: &[[u8; SCOPE_BYTES]]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(scopes.len() * SCOPE_BYTES);
        for scope in scopes {
            bytes.extend_from_slice(scope);
        }
        bytes
    }

    /// Split the set back into scopes, refusing anything that is not a whole
    /// number of them.
    ///
    /// A truncated tail would otherwise be dropped silently and the audit would
    /// report fewer participants than took part -- the direction that makes a
    /// rollback look more agreed-upon than it was.  The scopes are carried out
    /// as bytes rather than decoded into authorities, so nothing here can name
    /// an authority that was never a participant.
    fn split_scopes(bytes: &[u8]) -> anyhow::Result<Vec<[u8; SCOPE_BYTES]>> {
        if bytes.len() % SCOPE_BYTES != 0 {
            anyhow::bail!(
                "a stored participant set is {} bytes, which is not a whole number of \
                 {SCOPE_BYTES}-byte scopes",
                bytes.len()
            );
        }
        Ok(bytes
            .chunks_exact(SCOPE_BYTES)
            .map(|chunk| {
                let mut scope = [0u8; SCOPE_BYTES];
                scope.copy_from_slice(chunk);
                scope
            })
            .collect())
    }
}

#[async_trait::async_trait]
impl RollbackEventStore for ScyllaRollbackEventStore {
    async fn record_rollback_requested(&self, event: &RollbackEvent) -> anyhow::Result<()> {
        self.session
            .execute_unpaged(
                &self.insert,
                (
                    self.network_chain_id,
                    event.chain_epoch() as i64,
                    event.previous_epoch() as i64,
                    event.head() as i64,
                    event.target() as i64,
                    event.plan_id().to_vec(),
                    Self::encode_scopes(event.participant_scopes()),
                    event.outcome().code(),
                    0i64,
                    0i64,
                    event.requested_at_us(),
                ),
            )
            .await?;
        Ok(())
    }

    async fn record_rollback_outcome(
        &self,
        chain_epoch: u64,
        outcome: RollbackOutcome,
    ) -> anyhow::Result<()> {
        let (archived, deleted) = match outcome {
            RollbackOutcome::Completed {
                archived_rows,
                deleted_rows,
            } => (archived_rows as i64, deleted_rows as i64),
            RollbackOutcome::Started | RollbackOutcome::Aborted => (0, 0),
        };
        self.session
            .execute_unpaged(
                &self.set_outcome,
                (
                    outcome.code(),
                    archived,
                    deleted,
                    self.network_chain_id,
                    chain_epoch as i64,
                ),
            )
            .await?;
        Ok(())
    }

    async fn read_rollback_events(&self, limit: i32) -> anyhow::Result<Vec<RollbackEvent>> {
        let rows = self
            .session
            .execute_unpaged(&self.read_recent, (self.network_chain_id, limit))
            .await?
            .into_rows_result()?
            .rows::<(i64, i64, i64, i64, Vec<u8>, Vec<u8>, i16, i64, i64, i64)>()?
            .collect::<Result<Vec<_>, _>>()?;

        rows.into_iter()
            .map(
                |(
                    chain_epoch,
                    previous_epoch,
                    head,
                    target,
                    plan_id,
                    participants,
                    outcome,
                    archived_rows,
                    deleted_rows,
                    requested_at_us,
                )| {
                    let outcome = RollbackOutcome::from_code(
                        outcome,
                        archived_rows as u64,
                        deleted_rows as u64,
                    )?;
                    Ok(RollbackEvent::from_stored(
                        chain_epoch as u64,
                        previous_epoch as u64,
                        head as u64,
                        target as u64,
                        plan_id,
                        Self::split_scopes(&participants)?,
                        outcome,
                        requested_at_us,
                    )?)
                },
            )
            .collect()
    }
}
