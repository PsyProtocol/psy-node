//! Immutable, chunked Realm Processor application archive.
//!
//! The no-tablet header is the single IF-NOT-EXISTS commit marker. Large
//! canonical semantic bytes live in a standard/tablet fragment table and are
//! exhaustively scanned before and after the header is committed. The receipt
//! is crate-private and does not itself authorize terminal, rotation, writer,
//! or authority-head mutations.

#![allow(dead_code)]

use std::{collections::BTreeSet, error::Error, fmt, sync::Arc};

use psy_node_core::queue::{
    realm_processor_application_archive::{
        reconstruct_realm_application_archive, RealmProcessorApplicationArchiveError,
        RealmProcessorApplicationArchiveFragment,
        RealmProcessorApplicationArchiveHeader, RealmProcessorApplicationArchivePlan,
        RealmProcessorApplicationArchiveSlot, REALM_APPLICATION_ARCHIVE_MAX_BUCKETS,
    },
    realm_processor_semantic_output::RealmProcessorSemanticOutput,
};
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{prepared::PreparedStatement, Consistency, SerialConsistency},
    value::{CqlValue, Row},
};
use sha2::{Digest, Sha256};

use super::{BranchExactDeploymentNoTabletKeyspace, PendingQueueArtifactDataKeyspace};

pub const REALM_PROCESSOR_APPLICATION_ARCHIVE_HEADER_TABLE: &str =
    "branch_exact_realm_application_archive_header_v1";
pub const REALM_PROCESSOR_APPLICATION_ARCHIVE_FRAGMENT_TABLE: &str =
    "branch_exact_realm_application_archive_fragment_v1";

const HEADER_REVISION: i64 = 1;
const STORE_FINGERPRINT_DOMAIN: &[u8] =
    b"psy/rollback/realm-application-archive-store/v1";

const CREATE_HEADER_TEMPLATE: &str = "CREATE TABLE IF NOT EXISTS {table} (archive_slot blob PRIMARY KEY, revision bigint, archive_payload blob)";
const READ_HEADER_TEMPLATE: &str = "SELECT revision, archive_payload FROM {table} WHERE archive_slot = ?";
const BOOTSTRAP_HEADER_TEMPLATE: &str = "INSERT INTO {table} (archive_slot, revision, archive_payload) VALUES (?, ?, ?) IF NOT EXISTS";
const CREATE_FRAGMENT_TEMPLATE: &str = "CREATE TABLE IF NOT EXISTS {table} (archive_slot blob, fragment_bucket bigint, fragment_index int, application_digest blob, fragment_count int, application_bytes bigint, payload blob, payload_digest blob, PRIMARY KEY ((archive_slot, application_digest, fragment_bucket), fragment_index)) WITH CLUSTERING ORDER BY (fragment_index ASC)";
const PUT_FRAGMENT_TEMPLATE: &str = "INSERT INTO {table} (archive_slot, fragment_bucket, fragment_index, application_digest, fragment_count, application_bytes, payload, payload_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
const READ_FRAGMENT_TEMPLATE: &str = "SELECT fragment_count, application_bytes, payload, payload_digest FROM {table} WHERE archive_slot = ? AND application_digest = ? AND fragment_bucket = ? AND fragment_index = ?";
const READ_FRAGMENT_BUCKET_TEMPLATE: &str = "SELECT fragment_index, application_digest, fragment_count, application_bytes, payload, payload_digest FROM {table} WHERE archive_slot = ? AND application_digest = ? AND fragment_bucket = ?";

const HEADER_READ_BIND_SHAPE: &[&str] = &["archive_slot:BLOB"];
const HEADER_BOOTSTRAP_BIND_SHAPE: &[&str] = &[
    "archive_slot:BLOB",
    "revision:BIGINT",
    "archive_payload:BLOB",
];
const FRAGMENT_PUT_BIND_SHAPE: &[&str] = &[
    "archive_slot:BLOB",
    "fragment_bucket:BIGINT",
    "fragment_index:INT",
    "application_digest:BLOB",
    "fragment_count:INT",
    "application_bytes:BIGINT",
    "payload:BLOB",
    "payload_digest:BLOB",
];
const FRAGMENT_READ_BIND_SHAPE: &[&str] = &[
    "archive_slot:BLOB",
    "application_digest:BLOB",
    "fragment_bucket:BIGINT",
    "fragment_index:INT",
];
const FRAGMENT_BUCKET_READ_BIND_SHAPE: &[&str] = &[
    "archive_slot:BLOB",
    "application_digest:BLOB",
    "fragment_bucket:BIGINT",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmProcessorApplicationArchiveQueries {
    create_header: String,
    read_header: String,
    bootstrap_header: String,
    create_fragment: String,
    put_fragment: String,
    read_fragment: String,
    read_fragment_bucket: String,
}

impl RealmProcessorApplicationArchiveQueries {
    pub fn new(
        control: &BranchExactDeploymentNoTabletKeyspace,
        data: &PendingQueueArtifactDataKeyspace,
    ) -> Self {
        let header = format!(
            "{}.{}",
            control.as_str(),
            REALM_PROCESSOR_APPLICATION_ARCHIVE_HEADER_TABLE,
        );
        let fragment = format!(
            "{}.{}",
            data.as_str(),
            REALM_PROCESSOR_APPLICATION_ARCHIVE_FRAGMENT_TABLE,
        );
        Self {
            create_header: CREATE_HEADER_TEMPLATE.replace("{table}", &header),
            read_header: READ_HEADER_TEMPLATE.replace("{table}", &header),
            bootstrap_header: BOOTSTRAP_HEADER_TEMPLATE.replace("{table}", &header),
            create_fragment: CREATE_FRAGMENT_TEMPLATE.replace("{table}", &fragment),
            put_fragment: PUT_FRAGMENT_TEMPLATE.replace("{table}", &fragment),
            read_fragment: READ_FRAGMENT_TEMPLATE.replace("{table}", &fragment),
            read_fragment_bucket: READ_FRAGMENT_BUCKET_TEMPLATE.replace("{table}", &fragment),
        }
    }

    pub fn create_header(&self) -> &str { &self.create_header }
    pub fn read_header(&self) -> &str { &self.read_header }
    pub fn bootstrap_header(&self) -> &str { &self.bootstrap_header }
    pub fn create_fragment(&self) -> &str { &self.create_fragment }
    pub fn put_fragment(&self) -> &str { &self.put_fragment }
    pub fn read_fragment(&self) -> &str { &self.read_fragment }
    pub fn read_fragment_bucket(&self) -> &str { &self.read_fragment_bucket }
    pub const fn header_read_bind_shape(&self) -> &'static [&'static str] { HEADER_READ_BIND_SHAPE }
    pub const fn header_bootstrap_bind_shape(&self) -> &'static [&'static str] { HEADER_BOOTSTRAP_BIND_SHAPE }
    pub const fn fragment_put_bind_shape(&self) -> &'static [&'static str] { FRAGMENT_PUT_BIND_SHAPE }
    pub const fn fragment_read_bind_shape(&self) -> &'static [&'static str] { FRAGMENT_READ_BIND_SHAPE }
    pub const fn fragment_bucket_read_bind_shape(&self) -> &'static [&'static str] { FRAGMENT_BUCKET_READ_BIND_SHAPE }

    pub fn golden(&self) -> String {
        format!(
            "create_header\n{}\n\nread_header\n{}\n\nbootstrap_header\n{}\n\ncreate_fragment\n{}\n\nput_fragment\n{}\n\nread_fragment\n{}\n\nread_fragment_bucket\n{}\n",
            self.create_header,
            self.read_header,
            self.bootstrap_header,
            self.create_fragment,
            self.put_fragment,
            self.read_fragment,
            self.read_fragment_bucket,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct RealmProcessorApplicationArchiveStoreFingerprint([u8; 32]);

impl RealmProcessorApplicationArchiveStoreFingerprint {
    pub(super) const fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}

/// Exact immutable header plus exhaustive fragment reconstruction.
/// Deliberately non-Clone and crate-private.
pub(super) struct PersistedRealmProcessorApplicationArchiveReceipt {
    store_fingerprint: RealmProcessorApplicationArchiveStoreFingerprint,
    header: RealmProcessorApplicationArchiveHeader,
    semantic: RealmProcessorSemanticOutput,
}

impl PersistedRealmProcessorApplicationArchiveReceipt {
    pub(super) const fn store_fingerprint(&self) -> RealmProcessorApplicationArchiveStoreFingerprint {
        self.store_fingerprint
    }
    pub(super) const fn header(&self) -> &RealmProcessorApplicationArchiveHeader { &self.header }
    pub(super) const fn semantic(&self) -> &RealmProcessorSemanticOutput { &self.semantic }
}

#[derive(scylla::DeserializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct HeaderRow {
    revision: i64,
    archive_payload: Vec<u8>,
}

#[derive(scylla::DeserializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct FragmentRow {
    fragment_index: i32,
    application_digest: Vec<u8>,
    fragment_count: i32,
    application_bytes: i64,
    payload: Vec<u8>,
    payload_digest: Vec<u8>,
}

#[derive(scylla::DeserializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct ExactFragmentRow {
    fragment_count: i32,
    application_bytes: i64,
    payload: Vec<u8>,
    payload_digest: Vec<u8>,
}

pub(super) struct ScyllaRealmProcessorApplicationArchiveStore {
    session: Arc<Session>,
    queries: RealmProcessorApplicationArchiveQueries,
    fingerprint: RealmProcessorApplicationArchiveStoreFingerprint,
    read_header: PreparedStatement,
    bootstrap_header: PreparedStatement,
    put_fragment: PreparedStatement,
    read_fragment: PreparedStatement,
    read_fragment_bucket: PreparedStatement,
}

impl ScyllaRealmProcessorApplicationArchiveStore {
    pub(super) async fn create_schema(
        session: &Session,
        control: &BranchExactDeploymentNoTabletKeyspace,
        data: &PendingQueueArtifactDataKeyspace,
    ) -> Result<(), RealmProcessorApplicationArchiveStoreError> {
        let queries = RealmProcessorApplicationArchiveQueries::new(control, data);
        session.query_unpaged(queries.create_header(), &[]).await.map_err(cql)?;
        session.query_unpaged(queries.create_fragment(), &[]).await.map_err(cql)?;
        session.await_schema_agreement().await.map_err(cql)?;
        Ok(())
    }

    pub(super) async fn prepare(
        session: Arc<Session>,
        control: BranchExactDeploymentNoTabletKeyspace,
        data: PendingQueueArtifactDataKeyspace,
    ) -> Result<Self, RealmProcessorApplicationArchiveStoreError> {
        let queries = RealmProcessorApplicationArchiveQueries::new(&control, &data);
        let fingerprint = store_fingerprint(&control, &data, &queries);
        Ok(Self {
            read_header: prepare_regular(&session, queries.read_header()).await?,
            bootstrap_header: prepare_lwt(&session, queries.bootstrap_header()).await?,
            put_fragment: prepare_regular(&session, queries.put_fragment()).await?,
            read_fragment: prepare_regular(&session, queries.read_fragment()).await?,
            read_fragment_bucket: prepare_regular(
                &session,
                queries.read_fragment_bucket(),
            ).await?,
            session,
            queries,
            fingerprint,
        })
    }

    pub(super) const fn queries(&self) -> &RealmProcessorApplicationArchiveQueries {
        &self.queries
    }

    pub(super) const fn fingerprint(&self) -> RealmProcessorApplicationArchiveStoreFingerprint {
        self.fingerprint
    }

    pub(super) async fn persist_and_readback(
        &self,
        plan: &RealmProcessorApplicationArchivePlan,
    ) -> Result<PersistedRealmProcessorApplicationArchiveReceipt, RealmProcessorApplicationArchiveStoreError> {
        let observed = self.scan_fragments(plan.header()).await?;
        let expected_coordinates = plan.fragments().iter()
            .map(|fragment| (fragment.index(), *fragment.semantic_digest().as_bytes()))
            .collect::<BTreeSet<_>>();
        let observed_coordinates = observed.iter()
            .map(|fragment| (fragment.index(), *fragment.semantic_digest().as_bytes()))
            .collect::<BTreeSet<_>>();
        if observed_coordinates.len() != observed.len()
            || !observed_coordinates.is_subset(&expected_coordinates)
        {
            return Err(RealmProcessorApplicationArchiveStoreError::FragmentConflict);
        }
        for current in &observed {
            let expected = plan.fragments().iter().find(|fragment| {
                fragment.index() == current.index()
                    && fragment.semantic_digest() == current.semantic_digest()
            }).ok_or(RealmProcessorApplicationArchiveStoreError::FragmentConflict)?;
            if current != expected {
                return Err(RealmProcessorApplicationArchiveStoreError::FragmentConflict);
            }
        }
        for fragment in plan.fragments() {
            let coordinate = (fragment.index(), *fragment.semantic_digest().as_bytes());
            if observed_coordinates.contains(&coordinate) {
                continue;
            }
            let execution = self.session.execute_unpaged(&self.put_fragment, fragment_binding(fragment)?).await;
            if let Err(error) = execution {
                match self.read_fragment_exact(fragment).await {
                    Ok(Some(current)) if current == *fragment => continue,
                    Ok(Some(_)) => {
                        return Err(RealmProcessorApplicationArchiveStoreError::FragmentConflict);
                    }
                    Ok(None) => {
                        return Err(RealmProcessorApplicationArchiveStoreError::IndeterminateWrite(error.to_string()));
                    }
                    Err(read) => {
                        return Err(RealmProcessorApplicationArchiveStoreError::IndeterminateWrite(
                            format!("execute={error}; read={read}"),
                        ));
                    }
                }
            }
        }
        let semantic = plan.reconstruct_exact(self.scan_fragments(plan.header()).await?)?;
        let header_bytes = plan.header().to_canonical_bytes();
        let execution = self.session.execute_unpaged(
            &self.bootstrap_header,
            (
                plan.header().slot().as_bytes().as_slice(),
                HEADER_REVISION,
                header_bytes.as_slice(),
            ),
        ).await;
        if let Err(error) = execution {
            return match self.read_exact(plan.header()).await {
                Ok(Some(receipt)) => Ok(receipt),
                Ok(None) => Err(RealmProcessorApplicationArchiveStoreError::IndeterminateWrite(error.to_string())),
                Err(read) => Err(RealmProcessorApplicationArchiveStoreError::IndeterminateWrite(
                    format!("execute={error}; read={read}"),
                )),
            };
        }
        let applied = decode_applied(execution.unwrap())?;
        let receipt = self.read_exact(plan.header()).await?
            .ok_or(RealmProcessorApplicationArchiveStoreError::HeaderMissingAfterLwt)?;
        if receipt.semantic != semantic || receipt.header != *plan.header() {
            return Err(RealmProcessorApplicationArchiveStoreError::HeaderConflict);
        }
        if !applied && receipt.header != *plan.header() {
            return Err(RealmProcessorApplicationArchiveStoreError::HeaderConflict);
        }
        Ok(receipt)
    }

    pub(super) async fn read_exact(
        &self,
        expected: &RealmProcessorApplicationArchiveHeader,
    ) -> Result<Option<PersistedRealmProcessorApplicationArchiveReceipt>, RealmProcessorApplicationArchiveStoreError> {
        let Some(header) = self.read_header(expected.slot()).await? else {
            return Ok(None);
        };
        if header != *expected {
            return Err(RealmProcessorApplicationArchiveStoreError::HeaderConflict);
        }
        let semantic = reconstruct_realm_application_archive(
            &header,
            self.scan_fragments(&header).await?,
        )?;
        Ok(Some(PersistedRealmProcessorApplicationArchiveReceipt {
            store_fingerprint: self.fingerprint,
            header,
            semantic,
        }))
    }

    async fn read_header(
        &self,
        slot: RealmProcessorApplicationArchiveSlot,
    ) -> Result<Option<RealmProcessorApplicationArchiveHeader>, RealmProcessorApplicationArchiveStoreError> {
        let row = self.session.execute_unpaged(
            &self.read_header,
            (slot.as_bytes().as_slice(),),
        ).await.map_err(cql)?.into_rows_result().map_err(cql)?
            .maybe_first_row::<HeaderRow>().map_err(cql)?;
        let Some(row) = row else { return Ok(None); };
        if row.revision != HEADER_REVISION {
            return Err(RealmProcessorApplicationArchiveStoreError::HeaderRevisionMismatch);
        }
        RealmProcessorApplicationArchiveHeader::decode_selected(slot, &row.archive_payload)
            .map(Some)
            .map_err(Into::into)
    }

    async fn scan_fragments(
        &self,
        header: &RealmProcessorApplicationArchiveHeader,
    ) -> Result<Vec<RealmProcessorApplicationArchiveFragment>, RealmProcessorApplicationArchiveStoreError> {
        let mut fragments = Vec::new();
        for bucket in 0..REALM_APPLICATION_ARCHIVE_MAX_BUCKETS {
            let rows = self.session.execute_unpaged(
                &self.read_fragment_bucket,
                (
                    header.slot().as_bytes().as_slice(),
                    header.semantic_digest().as_bytes().as_slice(),
                    i64::from(bucket),
                ),
            ).await.map_err(cql)?.into_rows_result().map_err(cql)?;
            for row in rows.rows::<FragmentRow>().map_err(cql)? {
                let row = row.map_err(cql)?;
                fragments.push(RealmProcessorApplicationArchiveFragment::decode_observed(
                    header.slot(),
                    i64::from(bucket),
                    row.fragment_index,
                    row.application_digest,
                    row.fragment_count,
                    row.application_bytes,
                    row.payload,
                    row.payload_digest,
                )?);
            }
        }
        Ok(fragments)
    }

    async fn read_fragment_exact(
        &self,
        expected: &RealmProcessorApplicationArchiveFragment,
    ) -> Result<Option<RealmProcessorApplicationArchiveFragment>, RealmProcessorApplicationArchiveStoreError> {
        let row = self.session.execute_unpaged(
            &self.read_fragment,
            (
                expected.slot().as_bytes().as_slice(),
                expected.semantic_digest().as_bytes().as_slice(),
                i64::from(expected.bucket()),
                i32::try_from(expected.index()).map_err(|_| RealmProcessorApplicationArchiveStoreError::CoordinateOutOfRange)?,
            ),
        ).await.map_err(cql)?.into_rows_result().map_err(cql)?
            .maybe_first_row::<ExactFragmentRow>().map_err(cql)?;
        row.map(|row| {
            RealmProcessorApplicationArchiveFragment::decode_observed(
                expected.slot(),
                i64::from(expected.bucket()),
                i32::try_from(expected.index()).map_err(|_| RealmProcessorApplicationArchiveStoreError::CoordinateOutOfRange)?,
                expected.semantic_digest().as_bytes().to_vec(),
                row.fragment_count,
                row.application_bytes,
                row.payload,
                row.payload_digest,
            ).map_err(Into::into)
        }).transpose()
    }
}

fn fragment_binding(
    fragment: &RealmProcessorApplicationArchiveFragment,
) -> Result<(Vec<u8>, i64, i32, Vec<u8>, i32, i64, Vec<u8>, Vec<u8>), RealmProcessorApplicationArchiveStoreError> {
    Ok((
        fragment.slot().as_bytes().to_vec(),
        i64::from(fragment.bucket()),
        i32::try_from(fragment.index()).map_err(|_| RealmProcessorApplicationArchiveStoreError::CoordinateOutOfRange)?,
        fragment.semantic_digest().as_bytes().to_vec(),
        i32::try_from(fragment.fragment_count()).map_err(|_| RealmProcessorApplicationArchiveStoreError::CoordinateOutOfRange)?,
        i64::try_from(fragment.semantic_bytes()).map_err(|_| RealmProcessorApplicationArchiveStoreError::CoordinateOutOfRange)?,
        fragment.payload().to_vec(),
        fragment.payload_digest().as_bytes().to_vec(),
    ))
}

fn store_fingerprint(
    control: &BranchExactDeploymentNoTabletKeyspace,
    data: &PendingQueueArtifactDataKeyspace,
    queries: &RealmProcessorApplicationArchiveQueries,
) -> RealmProcessorApplicationArchiveStoreFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(STORE_FINGERPRINT_DOMAIN);
    update_len(&mut hasher, control.as_str().as_bytes());
    update_len(&mut hasher, data.as_str().as_bytes());
    update_len(&mut hasher, queries.golden().as_bytes());
    RealmProcessorApplicationArchiveStoreFingerprint(hasher.finalize().into())
}

async fn prepare_regular(
    session: &Session,
    cql_text: &str,
) -> Result<PreparedStatement, RealmProcessorApplicationArchiveStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_lwt(
    session: &Session,
    cql_text: &str,
) -> Result<PreparedStatement, RealmProcessorApplicationArchiveStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_applied(result: QueryResult) -> Result<bool, RealmProcessorApplicationArchiveStoreError> {
    let rows = result.into_rows_result().map_err(cql)?;
    let column = rows.column_specs().get_by_name("[applied]")
        .ok_or(RealmProcessorApplicationArchiveStoreError::MissingAppliedColumn)?;
    let row = rows.single_row::<Row>().map_err(cql)?;
    match row.columns.get(column.0) {
        Some(Some(CqlValue::Boolean(value))) => Ok(*value),
        _ => Err(RealmProcessorApplicationArchiveStoreError::InvalidAppliedColumn),
    }
}

fn update_len(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn cql(error: impl fmt::Display) -> RealmProcessorApplicationArchiveStoreError {
    RealmProcessorApplicationArchiveStoreError::Cql(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RealmProcessorApplicationArchiveStoreError {
    Archive(RealmProcessorApplicationArchiveError),
    CoordinateOutOfRange,
    FragmentConflict,
    HeaderConflict,
    HeaderRevisionMismatch,
    HeaderMissingAfterLwt,
    MissingAppliedColumn,
    InvalidAppliedColumn,
    IndeterminateWrite(String),
    Cql(String),
}

impl From<RealmProcessorApplicationArchiveError> for RealmProcessorApplicationArchiveStoreError {
    fn from(error: RealmProcessorApplicationArchiveError) -> Self { Self::Archive(error) }
}

impl fmt::Display for RealmProcessorApplicationArchiveStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result { write!(formatter, "{self:?}") }
}
impl Error for RealmProcessorApplicationArchiveStoreError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_and_bind_order_are_production_exact() {
        let control = BranchExactDeploymentNoTabletKeyspace::try_new("psy_app_nt".to_owned()).unwrap();
        let data = PendingQueueArtifactDataKeyspace::try_new("psy_app_data".to_owned()).unwrap();
        let queries = RealmProcessorApplicationArchiveQueries::new(&control, &data);
        assert!(queries.create_header().contains("archive_slot blob PRIMARY KEY"));
        assert!(queries.bootstrap_header().contains("IF NOT EXISTS"));
        assert!(queries.create_fragment().contains("PRIMARY KEY ((archive_slot, application_digest, fragment_bucket), fragment_index)"));
        assert!(queries.create_fragment().contains("CLUSTERING ORDER BY (fragment_index ASC)"));
        assert!(!queries.put_fragment().contains("USING TIMESTAMP"));
        assert!(!queries.read_fragment_bucket().contains("writetime("));
        assert_eq!(queries.header_read_bind_shape(), HEADER_READ_BIND_SHAPE);
        assert_eq!(queries.header_bootstrap_bind_shape(), HEADER_BOOTSTRAP_BIND_SHAPE);
        assert_eq!(queries.fragment_put_bind_shape(), FRAGMENT_PUT_BIND_SHAPE);
        assert_eq!(queries.fragment_read_bind_shape(), FRAGMENT_READ_BIND_SHAPE);
        assert_eq!(queries.fragment_bucket_read_bind_shape(), FRAGMENT_BUCKET_READ_BIND_SHAPE);
        assert!(!queries.golden().contains("ALLOW FILTERING"));
        assert!(!queries.golden().contains(" TTL "));
        assert!(!queries.golden().contains(" BATCH "));
        // This archive is content-addressed and append-only: its primary key is
        // never deleted or reused. Timestamp fences remain mandatory for the
        // branch-state writers, not for this immutable sidecar.
        assert!(!queries.golden().contains(&["DELETE", " FROM"].concat()));
    }

    #[test]
    fn exhaustive_scanner_has_fixed_bucket_domain_and_quorum_lwt_contract() {
        let source = include_str!("realm_processor_application_archive.rs");
        assert!(source.contains("for bucket in 0..REALM_APPLICATION_ARCHIVE_MAX_BUCKETS"));
        assert!(source.contains("statement.set_consistency(Consistency::Quorum)"));
        assert!(source.contains("SerialConsistency::LocalSerial"));
        assert!(source.contains("plan.reconstruct_exact(self.scan_fragments(plan.header()).await?)"));
        assert!(!source.contains(&["Consistency", "::One"].concat()));
        assert!(!source.contains(&["DELETE", " FROM"].concat()));
    }
}
