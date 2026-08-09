//! Isolated no-tablet LWT adapter for the complete pending pipeline row.
//!
//! The h22d3a0 identity-only ledger is superseded by this single durable row;
//! production must never maintain both rows as authorities.

#![allow(dead_code)]

use std::{error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::NetworkId,
    chain_context::AuthorityScope,
};
use psy_node_core::store::{
    pending_generation_identity::{
        PendingGenerationActivationDigest, PendingGenerationContext,
        PendingGenerationLedgerKey,
    },
    pending_generation_pipeline::{
        PendingPipelineBootstrap, PendingPipelineError,
        PendingPipelineReadState, PendingPipelineRevision,
        PendingPipelineWriteOutcome, SealedPendingPipelineTransition,
        StoredPendingPipeline, PendingProcessingState,
        PendingQueueCloseIntentDigest,
    },
};
use psy_node_core::queue::recoverable_ephemeral::PendingQueueCaptureContext;
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{
        prepared::PreparedStatement, Consistency, SerialConsistency,
    },
    value::{CqlValue, Row},
};
use sha2::{Digest, Sha256};

use super::BranchExactDeploymentNoTabletKeyspace;

pub(super) const PIPELINE_TABLE: &str = "branch_exact_pending_pipeline_v2";
pub(super) const RETIRED_V1_PIPELINE_TABLE: &str = "branch_exact_pending_pipeline_v1";
const STORE_FINGERPRINT_DOMAIN: &[u8] =
    b"psy/rollback/pending-pipeline-store/v1";
const CLOSE_RECEIPT_DOMAIN: &[u8] =
    b"psy/rollback/pending-pipeline-close-receipt/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingPipelineStoreFingerprint([u8; 32]);

impl PendingPipelineStoreFingerprint {
    pub const fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}

/// Exact readback of the durable pipeline's current `Sealing(close)` state.
/// It is deliberately non-Clone and has no public constructor: executable
/// queue Seal and semantic terminal paths must consume this authority rather
/// than accept a caller-supplied close digest.
#[derive(Debug)]
pub struct PersistedPendingQueueCloseReceipt {
    store_fingerprint: PendingPipelineStoreFingerprint,
    key: PendingGenerationLedgerKey,
    revision: PendingPipelineRevision,
    activation_digest: PendingGenerationActivationDigest,
    processing: PendingGenerationContext,
    close_intent: PendingQueueCloseIntentDigest,
    receipt_digest: [u8; 32],
}

impl PersistedPendingQueueCloseReceipt {
    pub const fn store_fingerprint(&self) -> PendingPipelineStoreFingerprint {
        self.store_fingerprint
    }

    pub const fn revision(&self) -> PendingPipelineRevision { self.revision }

    pub const fn close_intent(&self) -> PendingQueueCloseIntentDigest {
        self.close_intent
    }

    pub const fn receipt_digest(&self) -> &[u8; 32] { &self.receipt_digest }

    pub fn matches_context(&self, context: PendingQueueCaptureContext) -> bool {
        self.key == context.key()
            && self.activation_digest == context.activation()
            && self.processing == context.processing()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingPipelineQueries {
    create: String,
    read: String,
    bootstrap: String,
    cas: String,
}

impl PendingPipelineQueries {
    pub fn new(keyspace: &BranchExactDeploymentNoTabletKeyspace) -> Self {
        let table = format!("{}.{PIPELINE_TABLE}", keyspace.as_str());
        let authority = "network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ?";
        Self {
            create: format!(
                "CREATE TABLE IF NOT EXISTS {table} (network_chain_id bigint, authority_kind tinyint, realm_id bigint, realm_sub_id int, revision bigint, pipeline blob, PRIMARY KEY ((network_chain_id, authority_kind, realm_id, realm_sub_id)))"
            ),
            read: format!(
                "SELECT network_chain_id, authority_kind, realm_id, realm_sub_id, revision, pipeline FROM {table} WHERE {authority}"
            ),
            bootstrap: format!(
                "INSERT INTO {table} (network_chain_id, authority_kind, realm_id, realm_sub_id, revision, pipeline) VALUES (?, ?, ?, ?, ?, ?) IF NOT EXISTS"
            ),
            cas: format!(
                "UPDATE {table} SET revision = ?, pipeline = ? WHERE {authority} IF revision = ? AND pipeline = ?"
            ),
        }
    }

    pub fn golden(&self) -> String {
        format!(
            "create\n{}\n\nread\n{}\nBIGINT,TINYINT,BIGINT,INT\n\nbootstrap\n{}\nBIGINT,TINYINT,BIGINT,INT,BIGINT,BLOB\n\ncas\n{}\nBIGINT,BLOB,BIGINT,TINYINT,BIGINT,INT,BIGINT,BLOB\n",
            self.create, self.read, self.bootstrap, self.cas,
        )
    }
}

pub struct ScyllaPendingPipelineStore {
    session: Arc<Session>,
    fingerprint: PendingPipelineStoreFingerprint,
    read: PreparedStatement,
    bootstrap: PreparedStatement,
    cas: PreparedStatement,
}

impl ScyllaPendingPipelineStore {
    pub async fn create_schema(
        session: &Session,
        keyspace: &BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<(), PendingPipelineStoreError> {
        let queries = PendingPipelineQueries::new(keyspace);
        session
            .query_unpaged(queries.create.as_str(), &[])
            .await
            .map_err(cql)?;
        session.await_schema_agreement().await.map_err(cql)?;
        Ok(())
    }

    pub async fn prepare(
        session: Arc<Session>,
        keyspace: BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<Self, PendingPipelineStoreError> {
        let queries = PendingPipelineQueries::new(&keyspace);
        let fingerprint = pipeline_store_fingerprint(&keyspace, &queries);
        Ok(Self {
            read: prepare_read(&session, queries.read).await?,
            bootstrap: prepare_lwt(&session, queries.bootstrap).await?,
            cas: prepare_lwt(&session, queries.cas).await?,
            fingerprint,
            session,
        })
    }

    pub const fn fingerprint(&self) -> PendingPipelineStoreFingerprint {
        self.fingerprint
    }

    pub async fn read_queue_close_exact<Hash: Q256BitHash>(
        &self,
        context: PendingQueueCaptureContext,
    ) -> Result<PersistedPendingQueueCloseReceipt, PendingPipelineStoreError> {
        let PendingPipelineReadState::Current(current) =
            self.read::<Hash>(context.key()).await?
        else {
            return Err(PendingPipelineStoreError::Uninitialized);
        };
        if current.activation_digest() != context.activation()
            || current.processing() != context.processing()
            || current.blocked_reason().is_some()
        {
            return Err(PendingPipelineStoreError::CloseContextMismatch);
        }
        let PendingProcessingState::Sealing(close_intent) =
            current.processing_state()
        else {
            return Err(PendingPipelineStoreError::PipelineNotSealing);
        };
        let mut hasher = Sha256::new();
        hasher.update(CLOSE_RECEIPT_DOMAIN);
        hasher.update(self.fingerprint.as_bytes());
        hasher.update(context.digest().as_bytes());
        hasher.update(current.revision().as_i64().to_be_bytes());
        hasher.update(close_intent.as_bytes());
        let receipt_digest: [u8; 32] = hasher.finalize().into();
        if receipt_digest == [0; 32] {
            return Err(PendingPipelineStoreError::EmptyReceiptDigest);
        }
        Ok(PersistedPendingQueueCloseReceipt {
            store_fingerprint: self.fingerprint,
            key: current.key(),
            revision: current.revision(),
            activation_digest: current.activation_digest(),
            processing: current.processing(),
            close_intent,
            receipt_digest,
        })
    }

    pub async fn revalidate_queue_close_exact<Hash: Q256BitHash>(
        &self,
        context: PendingQueueCaptureContext,
        receipt: &PersistedPendingQueueCloseReceipt,
    ) -> Result<(), PendingPipelineStoreError> {
        if receipt.store_fingerprint != self.fingerprint
            || !receipt.matches_context(context)
        {
            return Err(PendingPipelineStoreError::CloseReceiptStoreMismatch);
        }
        let current = self.read_queue_close_exact::<Hash>(context).await?;
        if current.revision != receipt.revision
            || current.close_intent != receipt.close_intent
            || current.receipt_digest != receipt.receipt_digest
        {
            return Err(PendingPipelineStoreError::CloseReceiptStale);
        }
        Ok(())
    }

    pub async fn read<Hash: Q256BitHash>(
        &self,
        key: PendingGenerationLedgerKey,
    ) -> Result<PendingPipelineReadState<Hash>, PendingPipelineStoreError> {
        let (network, kind, realm, sub) = bind_key(key);
        let selected = self
            .session
            .execute_unpaged(&self.read, (network, kind, realm, sub))
            .await
            .map_err(cql)?
            .into_rows_result()
            .map_err(cql)?
            .maybe_first_row::<(
                i64,
                i8,
                i64,
                i32,
                Option<i64>,
                Option<Vec<u8>>,
            )>()
            .map_err(cql)?;
        let Some((network, kind, realm, sub, revision, payload)) = selected else {
            return Ok(PendingPipelineReadState::Uninitialized);
        };
        if decode_key(network, kind, realm, sub)? != key {
            return Err(PendingPipelineStoreError::SelectedKeyMismatch);
        }
        let current = StoredPendingPipeline::<Hash>::decode_persisted(
            key,
            revision.ok_or(PendingPipelineStoreError::MissingRevision)?,
            payload
                .as_deref()
                .ok_or(PendingPipelineStoreError::MissingPayload)?,
        )
        .map_err(model)?;
        Ok(PendingPipelineReadState::Current(current))
    }

    pub(crate) async fn bootstrap<Hash: Q256BitHash>(
        &self,
        bootstrap: &PendingPipelineBootstrap<Hash>,
    ) -> Result<PendingPipelineWriteOutcome<Hash>, PendingPipelineStoreError> {
        let candidate = bootstrap.candidate();
        let key = candidate.key();
        let (network, kind, realm, sub) = bind_key(key);
        let execution = self
            .session
            .execute_unpaged(
                &self.bootstrap,
                (
                    network,
                    kind,
                    realm,
                    sub,
                    candidate.revision().as_i64(),
                    bootstrap.candidate_payload().as_slice(),
                ),
            )
            .await;
        self.finish(execution, key, candidate).await
    }

    pub(crate) async fn apply<Hash: Q256BitHash>(
        &self,
        transition: &SealedPendingPipelineTransition<Hash>,
    ) -> Result<PendingPipelineWriteOutcome<Hash>, PendingPipelineStoreError> {
        let expected = transition.expected();
        let candidate = transition.candidate();
        let key = expected.key();
        if candidate.key() != key {
            return Err(PendingPipelineStoreError::TransitionKeyMismatch);
        }
        let (network, kind, realm, sub) = bind_key(key);
        let execution = self
            .session
            .execute_unpaged(
                &self.cas,
                (
                    candidate.revision().as_i64(),
                    transition.candidate_payload().as_slice(),
                    network,
                    kind,
                    realm,
                    sub,
                    expected.revision().as_i64(),
                    transition.expected_payload().as_slice(),
                ),
            )
            .await;
        self.finish(execution, key, candidate).await
    }

    async fn finish<Hash: Q256BitHash>(
        &self,
        execution: Result<QueryResult, scylla::errors::ExecutionError>,
        key: PendingGenerationLedgerKey,
        candidate: &StoredPendingPipeline<Hash>,
    ) -> Result<PendingPipelineWriteOutcome<Hash>, PendingPipelineStoreError> {
        let applied = match execution {
            Ok(result) => decode_applied(result)?,
            Err(execute) => {
                return match self.read::<Hash>(key).await {
                    Ok(PendingPipelineReadState::Current(current))
                        if &current == candidate =>
                    {
                        Ok(PendingPipelineWriteOutcome::Idempotent(current))
                    }
                    Ok(PendingPipelineReadState::Current(current)) => {
                        Err(PendingPipelineStoreError::Indeterminate {
                            execute: execute.to_string(),
                            observed_revision: Some(current.revision()),
                        })
                    }
                    Ok(PendingPipelineReadState::Uninitialized) => {
                        Err(PendingPipelineStoreError::Indeterminate {
                            execute: execute.to_string(),
                            observed_revision: None,
                        })
                    }
                    Err(read) => Err(PendingPipelineStoreError::IndeterminateReadFailed {
                        execute: execute.to_string(),
                        read: read.to_string(),
                    }),
                };
            }
        };
        let PendingPipelineReadState::Current(current) = self.read::<Hash>(key).await? else {
            return Err(PendingPipelineStoreError::MissingAfterLwt);
        };
        if applied && &current != candidate {
            return Err(PendingPipelineStoreError::AppliedStateMismatch);
        }
        Ok(if applied {
            PendingPipelineWriteOutcome::Applied(current)
        } else if &current == candidate {
            PendingPipelineWriteOutcome::Idempotent(current)
        } else {
            PendingPipelineWriteOutcome::Conflict(current)
        })
    }
}

fn bind_key(key: PendingGenerationLedgerKey) -> (i64, i8, i64, i32) {
    let (kind, realm, sub) = authority_parts(key.authority());
    (i64::from(key.network().chain_id()), kind, realm, sub)
}

fn pipeline_store_fingerprint(
    keyspace: &BranchExactDeploymentNoTabletKeyspace,
    queries: &PendingPipelineQueries,
) -> PendingPipelineStoreFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(STORE_FINGERPRINT_DOMAIN);
    hasher.update((keyspace.as_str().len() as u64).to_be_bytes());
    hasher.update(keyspace.as_str().as_bytes());
    let golden = queries.golden();
    hasher.update((golden.len() as u64).to_be_bytes());
    hasher.update(golden.as_bytes());
    PendingPipelineStoreFingerprint(hasher.finalize().into())
}

fn authority_parts(authority: AuthorityScope) -> (i8, i64, i32) {
    match authority {
        AuthorityScope::Coordinator => (1, 0, 0),
        AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } => (2, i64::from(realm_id), i32::from(realm_sub_id)),
    }
}

fn decode_key(
    network: i64,
    kind: i8,
    realm: i64,
    sub: i32,
) -> Result<PendingGenerationLedgerKey, PendingPipelineStoreError> {
    let network = NetworkId::try_from_chain_id(
        u32::try_from(network).map_err(|_| PendingPipelineStoreError::SelectedKeyOutOfRange)?,
    )
    .map_err(|_| PendingPipelineStoreError::SelectedKeyOutOfRange)?;
    let authority = match (kind, realm, sub) {
        (1, 0, 0) => AuthorityScope::Coordinator,
        (2, realm, sub) => AuthorityScope::Realm {
            realm_id: u32::try_from(realm)
                .map_err(|_| PendingPipelineStoreError::SelectedKeyOutOfRange)?,
            realm_sub_id: u16::try_from(sub)
                .map_err(|_| PendingPipelineStoreError::SelectedKeyOutOfRange)?,
        },
        _ => return Err(PendingPipelineStoreError::InvalidAuthority),
    };
    Ok(PendingGenerationLedgerKey::new(network, authority))
}

async fn prepare_read(
    session: &Session,
    cql_text: String,
) -> Result<PreparedStatement, PendingPipelineStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_lwt(
    session: &Session,
    cql_text: String,
) -> Result<PreparedStatement, PendingPipelineStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_applied(result: QueryResult) -> Result<bool, PendingPipelineStoreError> {
    let rows = result.into_rows_result().map_err(cql)?;
    let column = rows
        .column_specs()
        .get_by_name("[applied]")
        .ok_or(PendingPipelineStoreError::MissingAppliedColumn)?;
    let row = rows.single_row::<Row>().map_err(cql)?;
    match row.columns.get(column.0) {
        Some(Some(CqlValue::Boolean(value))) => Ok(*value),
        _ => Err(PendingPipelineStoreError::InvalidAppliedColumn),
    }
}

fn cql(error: impl fmt::Display) -> PendingPipelineStoreError {
    PendingPipelineStoreError::Cql(error.to_string())
}

fn model(error: PendingPipelineError) -> PendingPipelineStoreError {
    PendingPipelineStoreError::Model(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingPipelineStoreError {
    Cql(String),
    Model(String),
    SelectedKeyOutOfRange,
    InvalidAuthority,
    SelectedKeyMismatch,
    MissingRevision,
    MissingPayload,
    MissingAppliedColumn,
    InvalidAppliedColumn,
    TransitionKeyMismatch,
    Uninitialized,
    CloseContextMismatch,
    PipelineNotSealing,
    EmptyReceiptDigest,
    CloseReceiptStoreMismatch,
    CloseReceiptStale,
    MissingAfterLwt,
    AppliedStateMismatch,
    Indeterminate {
        execute: String,
        observed_revision: Option<PendingPipelineRevision>,
    },
    IndeterminateReadFailed { execute: String, read: String },
}

impl fmt::Display for PendingPipelineStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for PendingPipelineStoreError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries_use_one_no_tablet_revision_and_payload_cas_row() {
        let keyspace = BranchExactDeploymentNoTabletKeyspace::try_new(
            "psy_h22d3_no_tablet".to_owned(),
        )
        .unwrap();
        let golden = PendingPipelineQueries::new(&keyspace).golden();
        assert!(golden.contains(PIPELINE_TABLE));
        assert!(golden.contains("IF NOT EXISTS"));
        assert!(golden.contains("IF revision = ? AND pipeline = ?"));
        assert!(golden.contains("PRIMARY KEY ((network_chain_id, authority_kind, realm_id, realm_sub_id))"));
        assert!(!golden.contains("proc_namespace_prefix_claim"));
        assert!(!golden.contains(RETIRED_V1_PIPELINE_TABLE));
    }

    #[test]
    fn v1_table_is_never_read_or_mutated_by_the_v2_adapter() {
        let keyspace = BranchExactDeploymentNoTabletKeyspace::try_new(
            "psy_h22d3_no_tablet".to_owned(),
        )
        .unwrap();
        let golden = PendingPipelineQueries::new(&keyspace).golden();
        assert_eq!(golden.matches(PIPELINE_TABLE).count(), 4);
        assert_eq!(golden.matches(RETIRED_V1_PIPELINE_TABLE).count(), 0);
    }

    #[test]
    fn production_setup_does_not_create_or_prepare_the_pipeline() {
        let setup = include_str!("../psy_setup.rs");
        assert!(!setup.contains(PIPELINE_TABLE));
        assert!(!setup.contains("ScyllaPendingPipelineStore"));
    }
}
