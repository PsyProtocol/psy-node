//! A participant's durable view of a rollback (design-r1 §6.2).
//!
//! Receipts live in the Coordinator's no-tablet keyspace, beside the control row
//! they are evidence for, because that is where the barrier is aggregated and a
//! barrier that had to read every Realm's keyspace would need each of them
//! reachable at exactly the moment the Coordinator decides to cross.
//!
//! They are written with `IF NOT EXISTS`.  A participant that retries after a
//! lost response must converge rather than overwrite, and two *different*
//! receipts from one participant must collide visibly instead of the later one
//! winning silently -- the aggregation refuses both, and it can only do that if
//! both are still there to compare.

use std::sync::Arc;

use async_trait::async_trait;
use parth_core::PHash;
use psy_data::protocol::canonical_chain::CanonicalChainRef;
use psy_data::protocol::chain_context::AuthorityScope;
use psy_node_core::store::canonical_head::CoordinatorCanonicalHeadReader;
use psy_node_core::store::rollback_coordination::{
    ObservedRollbackPhase, RollbackParticipantView, phase_from_head_state,
};
use psy_node_core::store::rollback_participants::{
    ArchiveReceipt, FreezeReceipt, RollbackParticipant, VerifyReceipt,
};
use scylla::client::session::Session;
use scylla::statement::prepared::PreparedStatement;

pub const ROLLBACK_ARCHIVE_RECEIPT_TABLE: &str = "rollback_archive_receipt";
pub const ROLLBACK_VERIFY_RECEIPT_TABLE: &str = "rollback_verify_receipt";
pub const ROLLBACK_FREEZE_RECEIPT_TABLE: &str = "rollback_freeze_receipt";

/// Reads the Coordinator's phase and files this participant's receipts.
pub struct ScyllaRollbackParticipantView {
    session: Arc<Session>,
    head_reader: Arc<dyn CoordinatorCanonicalHeadReader<PHash>>,
    insert: PreparedStatement,
    read_range: PreparedStatement,
    insert_verify: PreparedStatement,
    read_verify: PreparedStatement,
    insert_freeze: PreparedStatement,
    read_freeze: PreparedStatement,
}

impl ScyllaRollbackParticipantView {
    pub async fn create_table(session: &Session, no_tablet_keyspace: &str) -> anyhow::Result<()> {
        session
            .query_unpaged(
                format!(
                    "CREATE TABLE IF NOT EXISTS {no_tablet_keyspace}.{ROLLBACK_ARCHIVE_RECEIPT_TABLE} (
                        network_chain_id BIGINT,
                        target BIGINT,
                        head BIGINT,
                        authority_scope BLOB,
                        archived_rows BIGINT,
                        archive_digest BLOB,
                        PRIMARY KEY ((network_chain_id, target, head), authority_scope)
                    )"
                ),
                &[],
            )
            .await?;
        session
            .query_unpaged(
                format!(
                    "CREATE TABLE IF NOT EXISTS {no_tablet_keyspace}.{ROLLBACK_VERIFY_RECEIPT_TABLE} (
                        network_chain_id BIGINT,
                        target BIGINT,
                        authority_scope BLOB,
                        state_root BLOB,
                        PRIMARY KEY ((network_chain_id, target), authority_scope)
                    )"
                ),
                &[],
            )
            .await?;
        session
            .query_unpaged(
                format!(
                    "CREATE TABLE IF NOT EXISTS {no_tablet_keyspace}.{ROLLBACK_FREEZE_RECEIPT_TABLE} (
                        network_chain_id BIGINT,
                        head BIGINT,
                        authority_scope BLOB,
                        head_digest BLOB,
                        PRIMARY KEY ((network_chain_id, head), authority_scope)
                    )"
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
        head_reader: Arc<dyn CoordinatorCanonicalHeadReader<PHash>>,
    ) -> anyhow::Result<Self> {
        let insert = session
            .prepare(format!(
                "INSERT INTO {no_tablet_keyspace}.{ROLLBACK_ARCHIVE_RECEIPT_TABLE} \
                 (network_chain_id, target, head, authority_scope, archived_rows, archive_digest) \
                 VALUES (?, ?, ?, ?, ?, ?) IF NOT EXISTS"
            ))
            .await?;
        let read_range = session
            .prepare(format!(
                "SELECT authority_scope, archived_rows, archive_digest FROM \
                 {no_tablet_keyspace}.{ROLLBACK_ARCHIVE_RECEIPT_TABLE} \
                 WHERE network_chain_id = ? AND target = ? AND head = ?"
            ))
            .await?;
        let insert_verify = session
            .prepare(format!(
                "INSERT INTO {no_tablet_keyspace}.{ROLLBACK_VERIFY_RECEIPT_TABLE} \
                 (network_chain_id, target, authority_scope, state_root) \
                 VALUES (?, ?, ?, ?) IF NOT EXISTS"
            ))
            .await?;
        let read_verify = session
            .prepare(format!(
                "SELECT authority_scope, state_root FROM \
                 {no_tablet_keyspace}.{ROLLBACK_VERIFY_RECEIPT_TABLE} \
                 WHERE network_chain_id = ? AND target = ?"
            ))
            .await?;
        let insert_freeze = session
            .prepare(format!(
                "INSERT INTO {no_tablet_keyspace}.{ROLLBACK_FREEZE_RECEIPT_TABLE} \
                 (network_chain_id, head, authority_scope, head_digest) \
                 VALUES (?, ?, ?, ?) IF NOT EXISTS"
            ))
            .await?;
        let read_freeze = session
            .prepare(format!(
                "SELECT authority_scope, head_digest FROM \
                 {no_tablet_keyspace}.{ROLLBACK_FREEZE_RECEIPT_TABLE} \
                 WHERE network_chain_id = ? AND head = ?"
            ))
            .await?;
        Ok(Self {
            session,
            head_reader,
            insert,
            read_range,
            insert_verify,
            read_verify,
            insert_freeze,
            read_freeze,
        })
    }
}

#[async_trait]
impl RollbackParticipantView<PHash> for ScyllaRollbackParticipantView {
    async fn observe_phase(
        &self,
        coordinator_head: &CanonicalChainRef<PHash>,
    ) -> anyhow::Result<ObservedRollbackPhase> {
        let state = self
            .head_reader
            .read_canonical_head(coordinator_head.network_id())
            .await?;
        Ok(phase_from_head_state(&state))
    }

    async fn file_archive_receipt(&self, receipt: &ArchiveReceipt) -> anyhow::Result<()> {
        // The scope's canonical bytes are the clustering key, the same encoding
        // manifests and allocator rows partition by, so a participant's receipt
        // and its evidence cannot end up under different identities.
        let scope = receipt.participant().scope().to_canonical_bytes().to_vec();
        self.session
            .execute_unpaged(
                &self.insert,
                (
                    0i64,
                    receipt.target() as i64,
                    receipt.head() as i64,
                    scope,
                    receipt.archived_rows() as i64,
                    receipt.archive_digest().to_vec(),
                ),
            )
            .await?;
        Ok(())
    }

    /// Receipts for one range, resolved against the participants the caller
    /// expects.
    ///
    /// A stored row names its participant by the scope's canonical bytes, and
    /// those are matched against the caller's set rather than decoded into
    /// whatever scope they happen to describe.  Matching cannot invent a
    /// participant: a row naming an authority outside the set finds no slot and
    /// leaves the barrier unmet, which is the safe direction.  Decoding could,
    /// and the barrier's whole job is to refuse evidence from outside the set.
    async fn read_archive_receipts_for(
        &self,
        target: u64,
        head: u64,
        expected: &[RollbackParticipant],
    ) -> anyhow::Result<Vec<ArchiveReceipt>> {
        let rows = self
            .session
            .execute_unpaged(&self.read_range, (0i64, target as i64, head as i64))
            .await?
            .into_rows_result()?;
        let mut receipts = Vec::new();
        for row in rows.rows::<(Vec<u8>, i64, Vec<u8>)>()? {
            let (scope_bytes, archived_rows, digest) = row?;
            let Some(participant) = expected
                .iter()
                .copied()
                .find(|p| p.scope().to_canonical_bytes().as_slice() == scope_bytes.as_slice())
            else {
                continue;
            };
            let mut archive_digest = [0u8; 32];
            if digest.len() == 32 {
                archive_digest.copy_from_slice(&digest);
            }
            receipts.push(ArchiveReceipt::new(
                participant,
                target,
                head,
                archived_rows as u64,
                archive_digest,
            ));
        }
        Ok(receipts)
    }

    async fn file_verify_receipt(&self, receipt: &VerifyReceipt) -> anyhow::Result<()> {
        let scope = receipt.participant().scope().to_canonical_bytes().to_vec();
        self.session
            .execute_unpaged(
                &self.insert_verify,
                (
                    0i64,
                    receipt.target() as i64,
                    scope,
                    receipt.state_root().to_vec(),
                ),
            )
            .await?;
        Ok(())
    }

    async fn read_verify_receipts_for(
        &self,
        target: u64,
        expected: &[RollbackParticipant],
    ) -> anyhow::Result<Vec<VerifyReceipt>> {
        let rows = self
            .session
            .execute_unpaged(&self.read_verify, (0i64, target as i64))
            .await?
            .into_rows_result()?;
        let mut receipts = Vec::new();
        for row in rows.rows::<(Vec<u8>, Vec<u8>)>()? {
            let (scope_bytes, root) = row?;
            let Some(participant) = expected
                .iter()
                .copied()
                .find(|p| p.scope().to_canonical_bytes().as_slice() == scope_bytes.as_slice())
            else {
                continue;
            };
            let mut state_root = [0u8; 32];
            if root.len() == 32 {
                state_root.copy_from_slice(&root);
            }
            receipts.push(VerifyReceipt::new(participant, target, state_root));
        }
        Ok(receipts)
    }

    async fn file_freeze_receipt(&self, receipt: &FreezeReceipt) -> anyhow::Result<()> {
        let scope = receipt.participant().scope().to_canonical_bytes().to_vec();
        self.session
            .execute_unpaged(
                &self.insert_freeze,
                (
                    0i64,
                    receipt.head() as i64,
                    scope,
                    receipt.head_digest().to_vec(),
                ),
            )
            .await?;
        Ok(())
    }

    async fn read_freeze_receipts_for(
        &self,
        head: u64,
        expected: &[RollbackParticipant],
    ) -> anyhow::Result<Vec<FreezeReceipt>> {
        let rows = self
            .session
            .execute_unpaged(&self.read_freeze, (0i64, head as i64))
            .await?
            .into_rows_result()?;
        let mut receipts = Vec::new();
        for row in rows.rows::<(Vec<u8>, Vec<u8>)>()? {
            let (scope_bytes, digest) = row?;
            let Some(participant) = expected
                .iter()
                .copied()
                .find(|p| p.scope().to_canonical_bytes().as_slice() == scope_bytes.as_slice())
            else {
                continue;
            };
            let mut head_digest = [0u8; 32];
            if digest.len() == 32 {
                head_digest.copy_from_slice(&digest);
            }
            receipts.push(FreezeReceipt::new(participant, head, head_digest));
        }
        Ok(receipts)
    }
}
