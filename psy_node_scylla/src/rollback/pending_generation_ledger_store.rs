//! No-tablet LWT substrate for pending-generation pipeline recovery.
//!
//! A random non-zero 64-bit proc prefix is claimed once per authority. Each
//! generation then derives `proc_id = prefix || pending_id`, eliminating
//! per-generation collision claims and making retries deterministic. Neither
//! table is registered by production setup in this slice.

#![allow(dead_code)]

use std::{error::Error, fmt, sync::Arc};

use psy_data::protocol::{
    canonical_chain::NetworkId,
    chain_context::AuthorityScope,
};
use psy_node_core::store::{
    pending_generation::{ProcNamespacePrefix, ReservedPendingGeneration},
    pending_generation_ledger::{
        PendingGenerationActivationDigest, PendingGenerationLedgerBootstrap,
        PendingGenerationLedgerError, PendingGenerationLedgerKey,
        PendingGenerationLedgerReadState, PendingGenerationLedgerRevision,
        PendingGenerationLedgerWriteOutcome, SealedPendingGenerationRotation,
        StoredPendingGenerationLedger,
    },
};
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

const LEDGER_TABLE: &str = "branch_exact_pending_generation_ledger_v1";
const CLAIM_TABLE: &str = "branch_exact_proc_namespace_prefix_claim_v1";
const CLAIM_MAGIC: [u8; 8] = *b"PSYPGCLM";
const CLAIM_VERSION: u16 = 1;
const CLAIM_PAYLOAD_LEN: usize = 8 + 2 + 4 + 1 + 4 + 2 + 32 + 8;
const CLAIM_DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/pending-generation-claim/v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingGenerationLedgerQueries {
    create_ledger: String,
    create_claim: String,
    read_ledger: String,
    bootstrap_ledger: String,
    cas_ledger: String,
    read_claim: String,
    claim_proc: String,
}

impl PendingGenerationLedgerQueries {
    pub fn new(keyspace: &BranchExactDeploymentNoTabletKeyspace) -> Self {
        let ledger = format!("{}.{LEDGER_TABLE}", keyspace.as_str());
        let claim = format!("{}.{CLAIM_TABLE}", keyspace.as_str());
        let authority = "network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ?";
        Self {
            create_ledger: format!(
                "CREATE TABLE IF NOT EXISTS {ledger} (network_chain_id bigint, authority_kind tinyint, realm_id bigint, realm_sub_id int, revision bigint, ledger blob, PRIMARY KEY ((network_chain_id, authority_kind, realm_id, realm_sub_id)))"
            ),
            create_claim: format!(
                "CREATE TABLE IF NOT EXISTS {claim} (prefix bigint PRIMARY KEY, claim blob)"
            ),
            read_ledger: format!(
                "SELECT network_chain_id, authority_kind, realm_id, realm_sub_id, revision, ledger FROM {ledger} WHERE {authority}"
            ),
            bootstrap_ledger: format!(
                "INSERT INTO {ledger} (network_chain_id, authority_kind, realm_id, realm_sub_id, revision, ledger) VALUES (?, ?, ?, ?, ?, ?) IF NOT EXISTS"
            ),
            cas_ledger: format!(
                "UPDATE {ledger} SET revision = ?, ledger = ? WHERE {authority} IF revision = ? AND ledger = ?"
            ),
            read_claim: format!(
                "SELECT claim FROM {claim} WHERE prefix = ?"
            ),
            claim_proc: format!(
                "INSERT INTO {claim} (prefix, claim) VALUES (?, ?) IF NOT EXISTS"
            ),
        }
    }

    pub fn golden(&self) -> String {
        format!(
            "create_ledger\n{}\n\ncreate_claim\n{}\n\nread_ledger\n{}\nBIGINT,TINYINT,BIGINT,INT\n\nbootstrap_ledger\n{}\nBIGINT,TINYINT,BIGINT,INT,BIGINT,BLOB\n\ncas_ledger\n{}\nBIGINT,BLOB,BIGINT,TINYINT,BIGINT,INT,BIGINT,BLOB\n\nread_claim\n{}\nBIGINT\n\nclaim_proc\n{}\nBIGINT,BLOB\n",
            self.create_ledger,
            self.create_claim,
            self.read_ledger,
            self.bootstrap_ledger,
            self.cas_ledger,
            self.read_claim,
            self.claim_proc,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingGenerationClaimDigest([u8; 32]);

impl PendingGenerationClaimDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Exact readback of an independent proc namespace claim. Fields are private;
/// a raw counter reservation cannot be used where this receipt is required.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableProcNamespaceReceipt {
    key: PendingGenerationLedgerKey,
    activation_digest: PendingGenerationActivationDigest,
    prefix: ProcNamespacePrefix,
    claim_payload: Vec<u8>,
    claim_digest: PendingGenerationClaimDigest,
}

impl DurableProcNamespaceReceipt {
    pub const fn key(&self) -> PendingGenerationLedgerKey {
        self.key
    }

    pub const fn activation_digest(&self) -> PendingGenerationActivationDigest {
        self.activation_digest
    }

    pub const fn prefix(&self) -> ProcNamespacePrefix {
        self.prefix
    }

    pub const fn claim_digest(&self) -> PendingGenerationClaimDigest {
        self.claim_digest
    }
}

pub struct ScyllaPendingGenerationLedgerStore {
    session: Arc<Session>,
    read_ledger: PreparedStatement,
    bootstrap_ledger: PreparedStatement,
    cas_ledger: PreparedStatement,
    read_claim: PreparedStatement,
    claim_proc: PreparedStatement,
}

impl ScyllaPendingGenerationLedgerStore {
    pub async fn create_schema(
        session: &Session,
        keyspace: &BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<(), PendingGenerationLedgerStoreError> {
        let queries = PendingGenerationLedgerQueries::new(keyspace);
        session
            .query_unpaged(queries.create_ledger.as_str(), &[])
            .await
            .map_err(cql)?;
        session
            .query_unpaged(queries.create_claim.as_str(), &[])
            .await
            .map_err(cql)?;
        session.await_schema_agreement().await.map_err(cql)?;
        Ok(())
    }

    pub async fn prepare(
        session: Arc<Session>,
        keyspace: BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<Self, PendingGenerationLedgerStoreError> {
        let queries = PendingGenerationLedgerQueries::new(&keyspace);
        Ok(Self {
            read_ledger: prepare_read(&session, queries.read_ledger).await?,
            bootstrap_ledger: prepare_lwt(
                &session,
                queries.bootstrap_ledger,
            )
            .await?,
            cas_ledger: prepare_lwt(&session, queries.cas_ledger).await?,
            read_claim: prepare_read(&session, queries.read_claim).await?,
            claim_proc: prepare_lwt(&session, queries.claim_proc).await?,
            session,
        })
    }

    pub async fn read(
        &self,
        key: PendingGenerationLedgerKey,
    ) -> Result<PendingGenerationLedgerReadState, PendingGenerationLedgerStoreError>
    {
        let (network, kind, realm, sub) = bind_key(key);
        let selected = self
            .session
            .execute_unpaged(
                &self.read_ledger,
                (network, kind, realm, sub),
            )
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
        let Some((network, kind, realm, sub, revision, payload)) = selected
        else {
            return Ok(PendingGenerationLedgerReadState::Uninitialized);
        };
        let selected_key = decode_key(network, kind, realm, sub)?;
        if selected_key != key {
            return Err(PendingGenerationLedgerStoreError::SelectedKeyMismatch);
        }
        let current = StoredPendingGenerationLedger::decode_persisted(
            key,
            revision.ok_or(PendingGenerationLedgerStoreError::MissingRevision)?,
            payload
                .as_deref()
                .ok_or(PendingGenerationLedgerStoreError::MissingPayload)?,
        )
        .map_err(model)?;
        Ok(PendingGenerationLedgerReadState::Current(current))
    }

    pub(crate) async fn claim_prefix(
        &self,
        key: PendingGenerationLedgerKey,
        activation_digest: PendingGenerationActivationDigest,
        prefix: ProcNamespacePrefix,
    ) -> Result<DurableProcNamespaceReceipt, PendingGenerationLedgerStoreError>
    {
        let payload = encode_claim(key, activation_digest, prefix);
        let prefix_i64 = prefix.get() as i64;
        let execution = self
            .session
            .execute_unpaged(
                &self.claim_proc,
                (prefix_i64, payload.as_slice()),
            )
            .await;
        let applied = match execution {
            Ok(result) => decode_applied(result)?,
            Err(execute) => {
                return match self.read_claim(prefix_i64).await {
                    Ok(Some(observed)) if observed == payload => {
                        Ok(receipt(key, activation_digest, prefix, payload))
                    }
                    Ok(_) => Err(PendingGenerationLedgerStoreError::IndeterminateClaim(
                        execute.to_string(),
                    )),
                    Err(read) => Err(
                        PendingGenerationLedgerStoreError::IndeterminateReadFailed {
                            execute: execute.to_string(),
                            read: read.to_string(),
                        },
                    ),
                };
            }
        };
        let observed = self
            .read_claim(prefix_i64)
            .await?
            .ok_or(PendingGenerationLedgerStoreError::ClaimMissingAfterLwt)?;
        if observed != payload {
            return Err(PendingGenerationLedgerStoreError::ProcClaimConflict);
        }
        let _ = applied;
        Ok(receipt(key, activation_digest, prefix, payload))
    }

    pub(crate) async fn bootstrap(
        &self,
        bootstrap: &PendingGenerationLedgerBootstrap,
        claimed: &DurableProcNamespaceReceipt,
    ) -> Result<PendingGenerationLedgerWriteOutcome, PendingGenerationLedgerStoreError>
    {
        let candidate = bootstrap.candidate();
        let key = candidate.key();
        let observed_claim = self
            .read_claim(claimed.prefix.get() as i64)
            .await?;
        validate_claim(candidate, claimed, observed_claim.as_deref())?;
        let (network, kind, realm, sub) = bind_key(key);
        let execution = self
            .session
            .execute_unpaged(
                &self.bootstrap_ledger,
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
        self.finish_ledger(execution, key, candidate).await
    }

    pub(crate) async fn rotate(
        &self,
        expected: StoredPendingGenerationLedger,
        claimed: &DurableProcNamespaceReceipt,
        reservation: ReservedPendingGeneration,
    ) -> Result<PendingGenerationLedgerWriteOutcome, PendingGenerationLedgerStoreError>
    {
        let observed_claim = self
            .read_claim(claimed.prefix.get() as i64)
            .await?;
        validate_claim(&expected, claimed, observed_claim.as_deref())?;
        let sealed = SealedPendingGenerationRotation::try_new(
            expected,
            reservation,
        )
        .map_err(model)?;
        let key = expected.key();
        let (network, kind, realm, sub) = bind_key(key);
        let execution = self
            .session
            .execute_unpaged(
                &self.cas_ledger,
                (
                    sealed.candidate().revision().as_i64(),
                    sealed.candidate_payload().as_slice(),
                    network,
                    kind,
                    realm,
                    sub,
                    sealed.expected().revision().as_i64(),
                    sealed.expected_payload().as_slice(),
                ),
            )
            .await;
        self.finish_ledger(execution, key, sealed.candidate()).await
    }

    async fn read_claim(
        &self,
        prefix: i64,
    ) -> Result<Option<Vec<u8>>, PendingGenerationLedgerStoreError> {
        self.session
            .execute_unpaged(&self.read_claim, (prefix,))
            .await
            .map_err(cql)?
            .into_rows_result()
            .map_err(cql)?
            .maybe_first_row::<(Option<Vec<u8>>,)>()
            .map_err(cql)
            .map(|row| row.and_then(|(payload,)| payload))
    }

    async fn finish_ledger(
        &self,
        execution: Result<QueryResult, scylla::errors::ExecutionError>,
        key: PendingGenerationLedgerKey,
        candidate: &StoredPendingGenerationLedger,
    ) -> Result<PendingGenerationLedgerWriteOutcome, PendingGenerationLedgerStoreError>
    {
        let applied = match execution {
            Ok(result) => decode_applied(result)?,
            Err(execute) => {
                return match self.read(key).await {
                    Ok(PendingGenerationLedgerReadState::Current(current))
                        if &current == candidate =>
                    {
                        Ok(PendingGenerationLedgerWriteOutcome::Idempotent(
                            current,
                        ))
                    }
                    Ok(PendingGenerationLedgerReadState::Current(current)) => {
                        Err(PendingGenerationLedgerStoreError::IndeterminateLedger {
                            execute: execute.to_string(),
                            observed_revision: Some(current.revision()),
                        })
                    }
                    Ok(PendingGenerationLedgerReadState::Uninitialized) => Err(
                        PendingGenerationLedgerStoreError::IndeterminateLedger {
                            execute: execute.to_string(),
                            observed_revision: None,
                        },
                    ),
                    Err(read) => Err(
                        PendingGenerationLedgerStoreError::IndeterminateReadFailed {
                            execute: execute.to_string(),
                            read: read.to_string(),
                        },
                    ),
                };
            }
        };
        let PendingGenerationLedgerReadState::Current(current) =
            self.read(key).await?
        else {
            return Err(PendingGenerationLedgerStoreError::LedgerMissingAfterLwt);
        };
        if applied && &current != candidate {
            return Err(PendingGenerationLedgerStoreError::AppliedStateMismatch);
        }
        Ok(if applied {
            PendingGenerationLedgerWriteOutcome::Applied(current)
        } else if &current == candidate {
            PendingGenerationLedgerWriteOutcome::Idempotent(current)
        } else {
            PendingGenerationLedgerWriteOutcome::Conflict(current)
        })
    }
}

fn receipt(
    key: PendingGenerationLedgerKey,
    activation_digest: PendingGenerationActivationDigest,
    prefix: ProcNamespacePrefix,
    claim_payload: Vec<u8>,
) -> DurableProcNamespaceReceipt {
    let mut hasher = Sha256::new();
    hasher.update(CLAIM_DIGEST_DOMAIN);
    hasher.update(&claim_payload);
    DurableProcNamespaceReceipt {
        key,
        activation_digest,
        prefix,
        claim_payload,
        claim_digest: PendingGenerationClaimDigest(hasher.finalize().into()),
    }
}

fn validate_claim(
    ledger: &StoredPendingGenerationLedger,
    claimed: &DurableProcNamespaceReceipt,
    observed_payload: Option<&[u8]>,
) -> Result<(), PendingGenerationLedgerStoreError> {
    if ledger.key() != claimed.key
        || ledger.activation_digest() != claimed.activation_digest
        || ledger.proc_namespace_prefix() != claimed.prefix
    {
        return Err(PendingGenerationLedgerStoreError::ClaimLedgerMismatch);
    }
    let observed_payload = observed_payload
        .ok_or(PendingGenerationLedgerStoreError::ClaimMissingAfterLwt)?;
    if observed_payload != claimed.claim_payload {
        return Err(PendingGenerationLedgerStoreError::ClaimLedgerMismatch);
    }
    Ok(())
}

fn encode_claim(
    key: PendingGenerationLedgerKey,
    activation_digest: PendingGenerationActivationDigest,
    prefix: ProcNamespacePrefix,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(CLAIM_PAYLOAD_LEN);
    payload.extend_from_slice(&CLAIM_MAGIC);
    payload.extend_from_slice(&CLAIM_VERSION.to_be_bytes());
    payload.extend_from_slice(&key.network().chain_id().to_be_bytes());
    let (kind, realm, sub) = authority_parts(key.authority());
    payload.push(kind as u8);
    payload.extend_from_slice(&(realm as u32).to_be_bytes());
    payload.extend_from_slice(&(sub as u16).to_be_bytes());
    payload.extend_from_slice(activation_digest.as_bytes());
    payload.extend_from_slice(&prefix.get().to_be_bytes());
    debug_assert_eq!(payload.len(), CLAIM_PAYLOAD_LEN);
    payload
}

fn bind_key(key: PendingGenerationLedgerKey) -> (i64, i8, i64, i32) {
    let (kind, realm, sub) = authority_parts(key.authority());
    (
        i64::from(key.network().chain_id()),
        kind,
        realm,
        sub,
    )
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
) -> Result<PendingGenerationLedgerKey, PendingGenerationLedgerStoreError> {
    let network = NetworkId::try_from_chain_id(
        u32::try_from(network)
            .map_err(|_| PendingGenerationLedgerStoreError::SelectedKeyOutOfRange)?,
    )
    .map_err(|_| PendingGenerationLedgerStoreError::SelectedKeyOutOfRange)?;
    let authority = match (kind, realm, sub) {
        (1, 0, 0) => AuthorityScope::Coordinator,
        (2, realm, sub) => AuthorityScope::Realm {
            realm_id: u32::try_from(realm)
                .map_err(|_| PendingGenerationLedgerStoreError::SelectedKeyOutOfRange)?,
            realm_sub_id: u16::try_from(sub)
                .map_err(|_| PendingGenerationLedgerStoreError::SelectedKeyOutOfRange)?,
        },
        _ => return Err(PendingGenerationLedgerStoreError::InvalidAuthority),
    };
    Ok(PendingGenerationLedgerKey::new(network, authority))
}

async fn prepare_read(
    session: &Session,
    cql_text: String,
) -> Result<PreparedStatement, PendingGenerationLedgerStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_lwt(
    session: &Session,
    cql_text: String,
) -> Result<PreparedStatement, PendingGenerationLedgerStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_applied(
    result: QueryResult,
) -> Result<bool, PendingGenerationLedgerStoreError> {
    let rows = result.into_rows_result().map_err(cql)?;
    let column = rows
        .column_specs()
        .get_by_name("[applied]")
        .ok_or(PendingGenerationLedgerStoreError::MissingAppliedColumn)?;
    let row = rows.single_row::<Row>().map_err(cql)?;
    match row.columns.get(column.0) {
        Some(Some(CqlValue::Boolean(value))) => Ok(*value),
        _ => Err(PendingGenerationLedgerStoreError::InvalidAppliedColumn),
    }
}

fn cql(error: impl fmt::Display) -> PendingGenerationLedgerStoreError {
    PendingGenerationLedgerStoreError::Cql(error.to_string())
}

fn model(error: PendingGenerationLedgerError) -> PendingGenerationLedgerStoreError {
    PendingGenerationLedgerStoreError::Model(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingGenerationLedgerStoreError {
    Cql(String),
    Model(String),
    SelectedKeyOutOfRange,
    InvalidAuthority,
    SelectedKeyMismatch,
    MissingRevision,
    MissingPayload,
    MissingAppliedColumn,
    InvalidAppliedColumn,
    ClaimMissingAfterLwt,
    ProcClaimConflict,
    ClaimLedgerMismatch,
    LedgerMissingAfterLwt,
    AppliedStateMismatch,
    IndeterminateClaim(String),
    IndeterminateLedger {
        execute: String,
        observed_revision: Option<PendingGenerationLedgerRevision>,
    },
    IndeterminateReadFailed { execute: String, read: String },
}

impl fmt::Display for PendingGenerationLedgerStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for PendingGenerationLedgerStoreError {}

#[cfg(test)]
mod tests {
    use super::*;

    use psy_node_core::store::pending_generation_ledger::{
        PendingGenerationBootstrapReason, PendingGenerationContext,
    };

    fn bootstrap_fixture() -> (
        PendingGenerationLedgerBootstrap,
        DurableProcNamespaceReceipt,
    ) {
        let key = PendingGenerationLedgerKey::new(
            NetworkId::try_from_chain_id(0x6979_7350).unwrap(),
            AuthorityScope::Coordinator,
        );
        let activation =
            PendingGenerationActivationDigest::try_new([7; 32]).unwrap();
        let prefix = ProcNamespacePrefix::try_new(42).unwrap();
        let zero = PendingGenerationContext::try_from_legacy(0, 0).unwrap();
        let bootstrap = PendingGenerationLedgerBootstrap::try_new(
            key,
            activation,
            prefix,
            PendingGenerationBootstrapReason::Genesis,
            zero,
            zero,
        )
        .unwrap();
        let claim_payload = encode_claim(key, activation, prefix);
        let claim = receipt(key, activation, prefix, claim_payload);
        (bootstrap, claim)
    }

    #[test]
    fn queries_are_no_tablet_lwt_and_compare_revision_plus_payload() {
        let keyspace = BranchExactDeploymentNoTabletKeyspace::try_new(
            "psy_h22d3_no_tablet".to_owned(),
        )
        .unwrap();
        let golden = PendingGenerationLedgerQueries::new(&keyspace).golden();
        assert!(golden.contains(LEDGER_TABLE));
        assert!(golden.contains(CLAIM_TABLE));
        assert!(golden.contains("IF NOT EXISTS"));
        assert!(golden.contains("IF revision = ? AND ledger = ?"));
        assert!(golden.contains("PRIMARY KEY ((network_chain_id, authority_kind, realm_id, realm_sub_id))"));
        assert!(golden.contains("prefix bigint PRIMARY KEY"));
    }

    #[test]
    fn production_setup_does_not_create_or_prepare_the_ledger() {
        let setup = include_str!("../psy_setup.rs");
        assert!(!setup.contains(LEDGER_TABLE));
        assert!(!setup.contains(CLAIM_TABLE));
        assert!(!setup.contains("ScyllaPendingGenerationLedgerStore"));
    }

    #[test]
    fn bootstrap_requires_an_exact_durable_prefix_claim() {
        let (bootstrap, claim) = bootstrap_fixture();
        assert_eq!(
            validate_claim(
                bootstrap.candidate(),
                &claim,
                Some(claim.claim_payload.as_slice()),
            ),
            Ok(())
        );
        assert_eq!(
            validate_claim(bootstrap.candidate(), &claim, None),
            Err(PendingGenerationLedgerStoreError::ClaimMissingAfterLwt)
        );
        assert_eq!(
            validate_claim(bootstrap.candidate(), &claim, Some(&[9; 3])),
            Err(PendingGenerationLedgerStoreError::ClaimLedgerMismatch)
        );

        let other_prefix = ProcNamespacePrefix::try_new(43).unwrap();
        let other_payload = encode_claim(
            claim.key,
            claim.activation_digest,
            other_prefix,
        );
        let other_claim = receipt(
            claim.key,
            claim.activation_digest,
            other_prefix,
            other_payload,
        );
        assert_eq!(
            validate_claim(
                bootstrap.candidate(),
                &other_claim,
                Some(other_claim.claim_payload.as_slice()),
            ),
            Err(PendingGenerationLedgerStoreError::ClaimLedgerMismatch)
        );
    }
}
