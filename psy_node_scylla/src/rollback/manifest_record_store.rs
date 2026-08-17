//! Durable Scylla adapter for the PREPARED / SEALED / COMMITTED manifest rows.
//!
//! The manifest is what rollback consumes: it is the only record of which
//! physical rows a commit wrote, and §2.2.1 explains why keys alone are enough.
//! This module stores the lifecycle rows; the locator chunks they commit to
//! live in the artifact store.
//!
//! Addressing follows design-r1 §2.2.  One partition holds
//! `AUTHORITY_MANIFEST_CHECKPOINT_BUCKET_SIZE` checkpoints for one authority in
//! one epoch, clustered by `(checkpoint_id, revision)`.  That shape is chosen
//! for the read rollback actually performs: enumerating the discarded suffix
//! `(T, old_head]` is then a bounded clustering range over a small, known set of
//! partitions rather than a scan.
//!
//! Every write is `IF NOT EXISTS` at `QUORUM` / `LOCAL_SERIAL` followed by a
//! point read, for the reason given in `commit_source_store`: an unapplied LWT
//! cannot distinguish our own retry from a divergent writer until the bytes are
//! compared.  There is no `UPDATE`, `DELETE`, `TTL` or explicit timestamp here —
//! a lifecycle advance appends a new revision rather than mutating a row.

use std::{error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::chain_context::AuthorityScope;
use psy_node_core::store::{
    manifest_lifecycle::{CommittedAuthorityManifest, SealedAuthorityManifest},
    manifest_store::{AuthorityManifestStore, PersistedManifestRow},
    manifest_record::{
        AUTHORITY_MANIFEST_CHECKPOINT_BUCKET_SIZE, AuthorityManifestIdentity,
        AuthorityManifestStatus, ManifestRevision, PreparedAuthorityManifestRecord,
    },
};
use scylla::{
    client::session::Session,
    statement::{Consistency, SerialConsistency, prepared::PreparedStatement},
};

use super::{CqlKeyspaceName, InvalidCqlKeyspaceName};

pub const AUTHORITY_MANIFEST_TABLE: &str = "authority_manifest";

/// Explicit trust boundary for a keyspace provisioned with tablets disabled.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ManifestNoTabletKeyspace(CqlKeyspaceName);

impl ManifestNoTabletKeyspace {
    pub fn try_new(name: impl Into<String>) -> Result<Self, ManifestStoreError> {
        let name = name.into();
        if !name.ends_with("_no_tablet") {
            return Err(ManifestStoreError::KeyspaceIsNotNoTablet(name));
        }
        Ok(Self(CqlKeyspaceName::try_new(name)?))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifestStoreError {
    KeyspaceIsNotNoTablet(String),
    InvalidKeyspace(InvalidCqlKeyspaceName),
    /// One `(identity, revision)` already holds a different manifest.  Never
    /// overwrite: two different commits would be claiming one canonical
    /// candidate at one lifecycle phase.
    Conflict {
        checkpoint_id: u64,
        revision: u64,
        detail: String,
    },
    MissingAfterWrite {
        checkpoint_id: u64,
        revision: u64,
    },
    UnexpectedStatus {
        checkpoint_id: u64,
        revision: u64,
        status: i8,
    },
    /// The requested range crosses a bucket boundary.  Callers must iterate
    /// buckets explicitly rather than silently reading a partial suffix.
    RangeCrossesBucket {
        from_checkpoint: u64,
        to_checkpoint: u64,
    },
    EmptyRange {
        from_checkpoint: u64,
        to_checkpoint: u64,
    },
}

impl From<InvalidCqlKeyspaceName> for ManifestStoreError {
    fn from(error: InvalidCqlKeyspaceName) -> Self {
        Self::InvalidKeyspace(error)
    }
}

impl fmt::Display for ManifestStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyspaceIsNotNoTablet(name) => write!(
                f,
                "manifest rows require a no-tablet keyspace, got {name:?}"
            ),
            Self::InvalidKeyspace(error) => error.fmt(f),
            Self::Conflict {
                checkpoint_id,
                revision,
                detail,
            } => write!(
                f,
                "manifest at checkpoint {checkpoint_id} revision {revision} \
                 already holds different content: {detail}"
            ),
            Self::MissingAfterWrite {
                checkpoint_id,
                revision,
            } => write!(
                f,
                "manifest at checkpoint {checkpoint_id} revision {revision} \
                 is absent immediately after a write"
            ),
            Self::UnexpectedStatus {
                checkpoint_id,
                revision,
                status,
            } => write!(
                f,
                "manifest at checkpoint {checkpoint_id} revision {revision} \
                 carries unknown status {status}"
            ),
            Self::RangeCrossesBucket {
                from_checkpoint,
                to_checkpoint,
            } => write!(
                f,
                "({from_checkpoint}, {to_checkpoint}] spans more than one \
                 checkpoint bucket; iterate buckets explicitly"
            ),
            Self::EmptyRange {
                from_checkpoint,
                to_checkpoint,
            } => write!(f, "({from_checkpoint}, {to_checkpoint}] is empty"),
        }
    }
}

impl Error for ManifestStoreError {}

pub struct ManifestQueries {
    pub create_table: String,
    pub insert_row: String,
    pub read_row: String,
    pub read_range: String,
}

impl ManifestQueries {
    pub fn new(keyspace: &ManifestNoTabletKeyspace) -> Self {
        let table = format!("{}.{AUTHORITY_MANIFEST_TABLE}", keyspace.as_str());
        Self {
            create_table: format!(
                "CREATE TABLE IF NOT EXISTS {table} (network_chain_id bigint, \
                 authority_scope blob, chain_epoch bigint, checkpoint_bucket bigint, \
                 checkpoint_id bigint, revision bigint, status tinyint, digest blob, \
                 payload blob, PRIMARY KEY ((network_chain_id, authority_scope, chain_epoch, \
                 checkpoint_bucket), checkpoint_id, revision)) \
                 WITH CLUSTERING ORDER BY (checkpoint_id ASC, revision ASC)"
            ),
            insert_row: format!(
                "INSERT INTO {table} (network_chain_id, authority_scope, chain_epoch, \
                 checkpoint_bucket, checkpoint_id, revision, status, digest, payload) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) IF NOT EXISTS"
            ),
            read_row: format!(
                "SELECT status, digest, payload FROM {table} WHERE network_chain_id = ? \
                 AND authority_scope = ? AND chain_epoch = ? AND checkpoint_bucket = ? \
                 AND checkpoint_id = ? AND revision = ?"
            ),
            // Half-open on the left: rollback keeps the target checkpoint and
            // discards everything above it.
            read_range: format!(
                "SELECT checkpoint_id, revision, status, digest, payload FROM {table} \
                 WHERE network_chain_id = ? AND authority_scope = ? AND chain_epoch = ? \
                 AND checkpoint_bucket = ? AND checkpoint_id > ? AND checkpoint_id <= ?"
            ),
        }
    }
}

pub struct ScyllaAuthorityManifestStore {
    session: Arc<Session>,
    insert_row: PreparedStatement,
    read_row: PreparedStatement,
    read_range: PreparedStatement,
}

/// Partition coordinates for one manifest identity.
struct ManifestPartition {
    network_chain_id: i64,
    authority_scope: Vec<u8>,
    chain_epoch: i64,
    checkpoint_bucket: i64,
}

impl ScyllaAuthorityManifestStore {
    pub async fn create_tables(
        session: &Session,
        keyspace: &ManifestNoTabletKeyspace,
    ) -> anyhow::Result<()> {
        session
            .query_unpaged(ManifestQueries::new(keyspace).create_table, &[])
            .await?;
        session.await_schema_agreement().await?;
        Ok(())
    }

    pub async fn prepare(
        session: Arc<Session>,
        keyspace: &ManifestNoTabletKeyspace,
    ) -> anyhow::Result<Self> {
        let queries = ManifestQueries::new(keyspace);
        let mut insert_row = session.prepare(queries.insert_row).await?;
        insert_row.set_consistency(Consistency::Quorum);
        insert_row.set_serial_consistency(Some(SerialConsistency::LocalSerial));
        let mut read_row = session.prepare(queries.read_row).await?;
        read_row.set_consistency(Consistency::Quorum);
        let mut read_range = session.prepare(queries.read_range).await?;
        read_range.set_consistency(Consistency::Quorum);
        Ok(Self {
            session,
            insert_row,
            read_row,
            read_range,
        })
    }

    fn partition<Hash: Q256BitHash>(
        identity: &AuthorityManifestIdentity<Hash>,
    ) -> ManifestPartition {
        ManifestPartition {
            network_chain_id: i64::from(identity.network().chain_id()),
            authority_scope: identity.authority().to_canonical_bytes().to_vec(),
            chain_epoch: identity.chain_epoch().get() as i64,
            checkpoint_bucket: identity.checkpoint_bucket() as i64,
        }
    }

    async fn read_row(
        &self,
        partition: &ManifestPartition,
        checkpoint_id: u64,
        revision: ManifestRevision,
    ) -> anyhow::Result<Option<PersistedManifestRow>> {
        let rows = self
            .session
            .execute_unpaged(
                &self.read_row,
                (
                    partition.network_chain_id,
                    partition.authority_scope.clone(),
                    partition.chain_epoch,
                    partition.checkpoint_bucket,
                    checkpoint_id as i64,
                    revision.as_i64(),
                ),
            )
            .await?
            .into_rows_result()?;
        let Some(row) = rows.rows::<(i8, Vec<u8>, Vec<u8>)>()?.next().transpose()? else {
            return Ok(None);
        };
        let (status, digest, payload) = row;
        Ok(Some(PersistedManifestRow {
            checkpoint_id,
            revision,
            status: AuthorityManifestStatus::try_from(status).map_err(|_| {
                ManifestStoreError::UnexpectedStatus {
                    checkpoint_id,
                    revision: revision.get(),
                    status,
                }
            })?,
            digest,
            payload,
        }))
    }

    async fn append_row<Hash: Q256BitHash>(
        &self,
        identity: &AuthorityManifestIdentity<Hash>,
        revision: ManifestRevision,
        status: AuthorityManifestStatus,
        digest: &[u8],
        payload: &[u8],
    ) -> anyhow::Result<()> {
        let partition = Self::partition(identity);
        let checkpoint_id = identity.checkpoint().checkpoint_id().get();
        self.session
            .execute_unpaged(
                &self.insert_row,
                (
                    partition.network_chain_id,
                    partition.authority_scope.clone(),
                    partition.chain_epoch,
                    partition.checkpoint_bucket,
                    checkpoint_id as i64,
                    revision.as_i64(),
                    status as i8,
                    digest.to_vec(),
                    payload.to_vec(),
                ),
            )
            .await?;
        match self.read_row(&partition, checkpoint_id, revision).await? {
            Some(row) if row.digest == digest && row.payload == payload => Ok(()),
            Some(row) => Err(ManifestStoreError::Conflict {
                checkpoint_id,
                revision: revision.get(),
                detail: format!(
                    "stored digest {} payload {} bytes vs offered digest {} payload {} bytes",
                    hex_prefix(&row.digest),
                    row.payload.len(),
                    hex_prefix(digest),
                    payload.len(),
                ),
            }
            .into()),
            None => Err(ManifestStoreError::MissingAfterWrite {
                checkpoint_id,
                revision: revision.get(),
            }
            .into()),
        }
    }

    /// Append the PREPARED row.  It must exist before any hot-table write, so a
    /// crash can never leave physical rows no manifest names (design-r1 §3).
    async fn append_prepared_row<Hash: Q256BitHash>(
        &self,
        prepared: &PreparedAuthorityManifestRecord<Hash>,
    ) -> anyhow::Result<()> {
        self.append_row(
            prepared.identity(),
            prepared.revision(),
            prepared.status(),
            prepared.digest().as_bytes(),
            prepared.encode_canonical(),
        )
        .await
    }

    async fn append_sealed_row<Hash: Q256BitHash>(
        &self,
        sealed: &SealedAuthorityManifest<Hash>,
    ) -> anyhow::Result<()> {
        self.append_row(
            sealed.prepared().identity(),
            sealed.revision(),
            sealed.status(),
            sealed.lifecycle_digest().as_bytes(),
            sealed.encode_canonical(),
        )
        .await
    }

    async fn append_committed_row<Hash: Q256BitHash>(
        &self,
        committed: &CommittedAuthorityManifest<Hash>,
    ) -> anyhow::Result<()> {
        self.append_row(
            committed.sealed().prepared().identity(),
            committed.revision(),
            committed.status(),
            committed.lifecycle_digest().as_bytes(),
            committed.encode_canonical(),
        )
        .await
    }

    async fn read_identity_row<Hash: Q256BitHash>(
        &self,
        identity: &AuthorityManifestIdentity<Hash>,
        revision: ManifestRevision,
    ) -> anyhow::Result<Option<PersistedManifestRow>> {
        let partition = Self::partition(identity);
        let checkpoint_id = identity.checkpoint().checkpoint_id().get();
        self.read_row(&partition, checkpoint_id, revision).await
    }

    /// Enumerate every lifecycle row in `(from_checkpoint, to_checkpoint]`.
    ///
    /// This is the read the rollback planner performs over the discarded
    /// suffix.  The range is rejected rather than truncated when it crosses a
    /// bucket boundary: silently returning a partial suffix would let the
    /// planner believe it had the whole discarded set and delete less than it
    /// archived.
    async fn read_identity_suffix<Hash: Q256BitHash>(
        &self,
        identity: &AuthorityManifestIdentity<Hash>,
        from_checkpoint: u64,
        to_checkpoint: u64,
    ) -> anyhow::Result<Vec<PersistedManifestRow>> {
        let bucket = suffix_range_bucket(from_checkpoint, to_checkpoint)?;
        let mut partition = Self::partition(identity);
        partition.checkpoint_bucket = bucket as i64;
        let rows = self
            .session
            .execute_unpaged(
                &self.read_range,
                (
                    partition.network_chain_id,
                    partition.authority_scope.clone(),
                    partition.chain_epoch,
                    partition.checkpoint_bucket,
                    from_checkpoint as i64,
                    to_checkpoint as i64,
                ),
            )
            .await?
            .into_rows_result()?;
        let mut out = Vec::new();
        for row in rows.rows::<(i64, i64, i8, Vec<u8>, Vec<u8>)>()? {
            let (checkpoint_id, revision, status, digest, payload) = row?;
            let checkpoint_id = checkpoint_id as u64;
            let revision = ManifestRevision::try_from_i64(revision)?;
            out.push(PersistedManifestRow {
                checkpoint_id,
                revision,
                status: AuthorityManifestStatus::try_from(status).map_err(|_| {
                    ManifestStoreError::UnexpectedStatus {
                        checkpoint_id,
                        revision: revision.get(),
                        status,
                    }
                })?,
                digest,
                payload,
            });
        }
        Ok(out)
    }
}

fn hex_prefix(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(4)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Bucket a checkpoint the way the partition key does.
pub const fn manifest_checkpoint_bucket(checkpoint_id: u64) -> u64 {
    checkpoint_id / AUTHORITY_MANIFEST_CHECKPOINT_BUCKET_SIZE
}

/// The single partition a `(from, to]` suffix read may touch.
///
/// Kept separate from the query so the rule is testable without a session.
/// Rejecting a crossing range matters more than it looks: a truncated result
/// would let the rollback planner believe it had enumerated the whole discarded
/// suffix and then delete less than it archived.
pub fn suffix_range_bucket(
    from_checkpoint: u64,
    to_checkpoint: u64,
) -> Result<u64, ManifestStoreError> {
    if to_checkpoint <= from_checkpoint {
        return Err(ManifestStoreError::EmptyRange {
            from_checkpoint,
            to_checkpoint,
        });
    }
    let first = manifest_checkpoint_bucket(from_checkpoint + 1);
    let last = manifest_checkpoint_bucket(to_checkpoint);
    if first != last {
        return Err(ManifestStoreError::RangeCrossesBucket {
            from_checkpoint,
            to_checkpoint,
        });
    }
    Ok(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keyspace() -> ManifestNoTabletKeyspace {
        ManifestNoTabletKeyspace::try_new("psy_no_tablet").unwrap()
    }

    #[test]
    fn manifest_rows_require_a_no_tablet_keyspace() {
        assert!(ManifestNoTabletKeyspace::try_new("psy").is_err());
        assert!(ManifestNoTabletKeyspace::try_new("psy_no_tablet").is_ok());
    }

    #[test]
    fn addressing_supports_a_bounded_suffix_range_not_a_scan() {
        let queries = ManifestQueries::new(&keyspace());
        assert!(queries.create_table.contains(
            "PRIMARY KEY ((network_chain_id, authority_scope, chain_epoch, \
             checkpoint_bucket), checkpoint_id, revision)"
        ));
        assert!(
            queries
                .create_table
                .contains("CLUSTERING ORDER BY (checkpoint_id ASC, revision ASC)")
        );
        // The suffix read must be half-open on the left: the target survives.
        assert!(
            queries
                .read_range
                .contains("checkpoint_id > ? AND checkpoint_id <= ?")
        );
    }

    #[test]
    fn a_lifecycle_advance_appends_a_revision_and_never_mutates() {
        let queries = ManifestQueries::new(&keyspace());
        assert!(queries.insert_row.starts_with("INSERT INTO"));
        assert!(queries.insert_row.ends_with("IF NOT EXISTS"));
        for statement in [
            &queries.create_table,
            &queries.insert_row,
            &queries.read_row,
            &queries.read_range,
        ] {
            for forbidden in ["UPDATE ", "DELETE ", " USING TTL", " USING TIMESTAMP"] {
                assert!(
                    !statement.contains(forbidden),
                    "{forbidden:?} must not appear in {statement}"
                );
            }
        }
    }

    #[test]
    fn bucketing_matches_the_contract_constant() {
        assert_eq!(AUTHORITY_MANIFEST_CHECKPOINT_BUCKET_SIZE, 4096);
        assert_eq!(manifest_checkpoint_bucket(0), 0);
        assert_eq!(manifest_checkpoint_bucket(4095), 0);
        assert_eq!(manifest_checkpoint_bucket(4096), 1);
        assert_eq!(manifest_checkpoint_bucket(8191), 1);
    }

    #[test]
    fn suffix_range_is_confined_to_one_bucket_or_rejected() {
        let size = AUTHORITY_MANIFEST_CHECKPOINT_BUCKET_SIZE;
        // Whole range inside bucket 0.
        assert_eq!(suffix_range_bucket(0, size - 1), Ok(0));
        // The boundary checkpoint alone still sits in exactly one bucket.
        assert_eq!(suffix_range_bucket(size - 1, size), Ok(1));
        assert_eq!(suffix_range_bucket(size, size + 5), Ok(1));
        // Crossing the boundary must fail rather than silently truncate.
        assert!(matches!(
            suffix_range_bucket(size - 2, size),
            Err(ManifestStoreError::RangeCrossesBucket { .. })
        ));
        assert!(matches!(
            suffix_range_bucket(0, size),
            Err(ManifestStoreError::RangeCrossesBucket { .. })
        ));
        // A rollback to the current head discards nothing and is not a range.
        assert!(matches!(
            suffix_range_bucket(7, 7),
            Err(ManifestStoreError::EmptyRange { .. })
        ));
        assert!(matches!(
            suffix_range_bucket(8, 7),
            Err(ManifestStoreError::EmptyRange { .. })
        ));
    }

    #[test]
    fn authority_scope_partitions_coordinator_and_realms_apart() {
        let coordinator = AuthorityScope::Coordinator.to_canonical_bytes();
        let realm = AuthorityScope::Realm {
            realm_id: 10,
            realm_sub_id: 0,
        }
        .to_canonical_bytes();
        let other_realm = AuthorityScope::Realm {
            realm_id: 11,
            realm_sub_id: 0,
        }
        .to_canonical_bytes();
        assert_ne!(coordinator, realm);
        assert_ne!(realm, other_realm);
    }
}

#[async_trait::async_trait]
impl<Hash: Q256BitHash> AuthorityManifestStore<Hash> for ScyllaAuthorityManifestStore {
    async fn append_prepared(
        &self,
        prepared: &PreparedAuthorityManifestRecord<Hash>,
    ) -> anyhow::Result<()> {
        self.append_prepared_row(prepared).await
    }

    async fn append_sealed(&self, sealed: &SealedAuthorityManifest<Hash>) -> anyhow::Result<()> {
        self.append_sealed_row(sealed).await
    }

    async fn append_committed(
        &self,
        committed: &CommittedAuthorityManifest<Hash>,
    ) -> anyhow::Result<()> {
        self.append_committed_row(committed).await
    }

    async fn read_manifest_row(
        &self,
        identity: &AuthorityManifestIdentity<Hash>,
        revision: ManifestRevision,
    ) -> anyhow::Result<Option<PersistedManifestRow>> {
        self.read_identity_row(identity, revision).await
    }

    async fn read_manifest_suffix(
        &self,
        identity: &AuthorityManifestIdentity<Hash>,
        from_checkpoint: u64,
        to_checkpoint: u64,
    ) -> anyhow::Result<Vec<PersistedManifestRow>> {
        self.read_identity_suffix(identity, from_checkpoint, to_checkpoint)
            .await
    }
}
