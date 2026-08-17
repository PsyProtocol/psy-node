//! Durable Scylla adapter for the Coordinator normal-commit source.
//!
//! Satisfies `psy_node_core::store::coordinator_commit_source::
//! CoordinatorCommitSourceStore` against a no-tablet keyspace (design-r1 §2.2).
//!
//! Every write is `IF NOT EXISTS` at `QUORUM` / `LOCAL_SERIAL`; there is no
//! `UPDATE`, `DELETE`, `TTL` or explicit timestamp anywhere in this module.  A
//! retry that observes its own earlier write converges; the same physical
//! identity carrying different content is a hard conflict.  The raw `Session`
//! stays private to this composition.

use std::{error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::canonical_chain::{CanonicalChainRef, NetworkId};
use psy_node_core::store::coordinator_commit_source::{
    CoordinatorCommitSource, CoordinatorCommitSourceCommitted, CoordinatorCommitSourceStore,
};
use scylla::{
    client::session::Session,
    statement::{Consistency, SerialConsistency, prepared::PreparedStatement},
};

use super::{CqlKeyspaceName, InvalidCqlKeyspaceName};

pub const COORDINATOR_COMMIT_SOURCE_HEADER_TABLE: &str = "coordinator_commit_source_header";
pub const COORDINATOR_COMMIT_SOURCE_FRAGMENT_TABLE: &str = "coordinator_commit_source_fragment";
pub const COORDINATOR_COMMIT_SOURCE_COMMITTED_TABLE: &str = "coordinator_commit_source_committed";

/// Row-format revision for every table in this module.  It is not a CAS
/// generation: these tables are append-only, so the column exists purely so a
/// future codec change is detectable rather than silently misread.
const SOURCE_ROW_REVISION: i64 = 1;

/// Explicit trust boundary for a keyspace provisioned with tablets disabled.
/// LWT is only linearizable there, and every write in this module is an LWT.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CommitSourceNoTabletKeyspace(CqlKeyspaceName);

impl CommitSourceNoTabletKeyspace {
    pub fn try_new(name: impl Into<String>) -> Result<Self, CommitSourceStoreError> {
        let name = name.into();
        if !name.ends_with("_no_tablet") {
            return Err(CommitSourceStoreError::KeyspaceIsNotNoTablet(name));
        }
        Ok(Self(CqlKeyspaceName::try_new(name)?))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Debug)]
pub enum CommitSourceStoreError {
    KeyspaceIsNotNoTablet(String),
    InvalidKeyspace(InvalidCqlKeyspaceName),
    /// The same physical identity already holds different content.  Never
    /// overwrite: a divergent source means two different commits claimed one
    /// canonical candidate.
    Conflict {
        table: &'static str,
        detail: String,
    },
    UnexpectedRowRevision {
        table: &'static str,
        revision: i64,
    },
    MissingAfterWrite {
        table: &'static str,
    },
    FragmentGap {
        expected: usize,
        found: usize,
    },
}

impl From<InvalidCqlKeyspaceName> for CommitSourceStoreError {
    fn from(error: InvalidCqlKeyspaceName) -> Self {
        Self::InvalidKeyspace(error)
    }
}

impl fmt::Display for CommitSourceStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyspaceIsNotNoTablet(name) => write!(
                f,
                "commit-source control tables require a no-tablet keyspace, got {name:?}"
            ),
            Self::InvalidKeyspace(error) => error.fmt(f),
            Self::Conflict { table, detail } => {
                write!(f, "{table} already holds different content: {detail}")
            }
            Self::UnexpectedRowRevision { table, revision } => {
                write!(f, "{table} row revision {revision} is not a known codec")
            }
            Self::MissingAfterWrite { table } => {
                write!(f, "{table} row is absent immediately after an applied write")
            }
            Self::FragmentGap { expected, found } => write!(
                f,
                "commit source expects {expected} contiguous fragments, found {found}"
            ),
        }
    }
}

impl Error for CommitSourceStoreError {}

/// The CQL this module owns.  Kept as one struct so the DDL and the statements
/// that read it cannot drift apart.
pub struct CommitSourceQueries {
    pub create_header: String,
    pub create_fragment: String,
    pub create_committed: String,
    pub read_header: String,
    pub read_fragments: String,
    pub insert_header: String,
    pub insert_fragment: String,
    pub read_committed: String,
    pub insert_committed: String,
}

impl CommitSourceQueries {
    pub fn new(keyspace: &CommitSourceNoTabletKeyspace) -> Self {
        let ks = keyspace.as_str();
        let header = format!("{ks}.{COORDINATOR_COMMIT_SOURCE_HEADER_TABLE}");
        let fragment = format!("{ks}.{COORDINATOR_COMMIT_SOURCE_FRAGMENT_TABLE}");
        let committed = format!("{ks}.{COORDINATOR_COMMIT_SOURCE_COMMITTED_TABLE}");
        Self {
            create_header: format!(
                "CREATE TABLE IF NOT EXISTS {header} (network_chain_id bigint, chain_epoch bigint, \
                 checkpoint_id bigint, revision bigint, source_slot blob, header blob, \
                 PRIMARY KEY ((network_chain_id, chain_epoch), checkpoint_id))"
            ),
            create_fragment: format!(
                "CREATE TABLE IF NOT EXISTS {fragment} (source_slot blob, fragment_index int, \
                 revision bigint, fragment blob, PRIMARY KEY ((source_slot), fragment_index))"
            ),
            create_committed: format!(
                "CREATE TABLE IF NOT EXISTS {committed} (network_chain_id bigint, chain_epoch bigint, \
                 checkpoint_id bigint, revision bigint, marker blob, \
                 PRIMARY KEY ((network_chain_id, chain_epoch), checkpoint_id))"
            ),
            read_header: format!(
                "SELECT revision, source_slot, header FROM {header} \
                 WHERE network_chain_id = ? AND chain_epoch = ? AND checkpoint_id = ?"
            ),
            read_fragments: format!(
                "SELECT fragment_index, revision, fragment FROM {fragment} WHERE source_slot = ?"
            ),
            insert_header: format!(
                "INSERT INTO {header} (network_chain_id, chain_epoch, checkpoint_id, revision, \
                 source_slot, header) VALUES (?, ?, ?, ?, ?, ?) IF NOT EXISTS"
            ),
            insert_fragment: format!(
                "INSERT INTO {fragment} (source_slot, fragment_index, revision, fragment) \
                 VALUES (?, ?, ?, ?) IF NOT EXISTS"
            ),
            read_committed: format!(
                "SELECT revision, marker FROM {committed} \
                 WHERE network_chain_id = ? AND chain_epoch = ? AND checkpoint_id = ?"
            ),
            insert_committed: format!(
                "INSERT INTO {committed} (network_chain_id, chain_epoch, checkpoint_id, revision, \
                 marker) VALUES (?, ?, ?, ?, ?) IF NOT EXISTS"
            ),
        }
    }

    pub fn create_statements(&self) -> [&str; 3] {
        [
            &self.create_header,
            &self.create_fragment,
            &self.create_committed,
        ]
    }
}

pub struct ScyllaCoordinatorCommitSourceStore {
    session: Arc<Session>,
    read_header: PreparedStatement,
    read_fragments: PreparedStatement,
    insert_header: PreparedStatement,
    insert_fragment: PreparedStatement,
    read_committed: PreparedStatement,
    insert_committed: PreparedStatement,
}

impl ScyllaCoordinatorCommitSourceStore {
    /// Idempotent DDL.  Callers own replication configuration.
    pub async fn create_tables(
        session: &Session,
        keyspace: &CommitSourceNoTabletKeyspace,
    ) -> anyhow::Result<()> {
        for statement in CommitSourceQueries::new(keyspace).create_statements() {
            session.query_unpaged(statement, &[]).await?;
        }
        session.await_schema_agreement().await?;
        Ok(())
    }

    pub async fn prepare(
        session: Arc<Session>,
        keyspace: &CommitSourceNoTabletKeyspace,
    ) -> anyhow::Result<Self> {
        let queries = CommitSourceQueries::new(keyspace);
        let read = |sql: &str| {
            let sql = sql.to_owned();
            let session = session.clone();
            async move {
                let mut prepared = session.prepare(sql).await?;
                prepared.set_consistency(Consistency::Quorum);
                anyhow::Ok(prepared)
            }
        };
        let lwt = |sql: &str| {
            let sql = sql.to_owned();
            let session = session.clone();
            async move {
                let mut prepared = session.prepare(sql).await?;
                prepared.set_consistency(Consistency::Quorum);
                prepared.set_serial_consistency(Some(SerialConsistency::LocalSerial));
                anyhow::Ok(prepared)
            }
        };
        Ok(Self {
            read_header: read(&queries.read_header).await?,
            read_fragments: read(&queries.read_fragments).await?,
            insert_header: lwt(&queries.insert_header).await?,
            insert_fragment: lwt(&queries.insert_fragment).await?,
            read_committed: read(&queries.read_committed).await?,
            insert_committed: lwt(&queries.insert_committed).await?,
            session,
        })
    }

    fn partition<Hash: Q256BitHash>(candidate: &CanonicalChainRef<Hash>) -> (i64, i64, i64) {
        (
            i64::from(candidate.network_id().chain_id()),
            candidate.chain_epoch().get() as i64,
            candidate.checkpoint().checkpoint_id().get() as i64,
        )
    }

    /// Run an `IF NOT EXISTS` insert, then point-read what the row actually
    /// holds and require it to equal `expected` byte for byte.
    ///
    /// The applied flag alone is not enough.  An unapplied LWT means somebody
    /// else won the row, and a retry of our own earlier write is indistinguish-
    /// able from a genuinely divergent writer until the bytes are compared.
    /// Reading back also satisfies the per-fragment point read design-r1 §3
    /// requires, so it is not an extra round trip on the happy path either.
    async fn insert_then_verify<Read>(
        &self,
        insert: &PreparedStatement,
        insert_values: impl scylla::serialize::row::SerializeRow,
        table: &'static str,
        expected: &[u8],
        read_back: Read,
    ) -> anyhow::Result<()>
    where
        Read: AsyncFnOnce() -> anyhow::Result<Option<Vec<u8>>>,
    {
        self.session.execute_unpaged(insert, insert_values).await?;
        match read_back().await? {
            Some(bytes) if bytes == expected => Ok(()),
            Some(bytes) => Err(CommitSourceStoreError::Conflict {
                table,
                detail: format!("{} stored bytes vs {} offered", bytes.len(), expected.len()),
            }
            .into()),
            None => Err(CommitSourceStoreError::MissingAfterWrite { table }.into()),
        }
    }

    async fn read_one_fragment(&self, slot: Vec<u8>, index: i32) -> anyhow::Result<Option<Vec<u8>>> {
        let rows = self
            .session
            .execute_unpaged(&self.read_fragments, (slot,))
            .await?
            .into_rows_result()?;
        for row in rows.rows::<(i32, i64, Vec<u8>)>()? {
            let (stored_index, revision, fragment) = row?;
            if stored_index != index {
                continue;
            }
            if revision != SOURCE_ROW_REVISION {
                return Err(CommitSourceStoreError::UnexpectedRowRevision {
                    table: COORDINATOR_COMMIT_SOURCE_FRAGMENT_TABLE,
                    revision,
                }
                .into());
            }
            return Ok(Some(fragment));
        }
        Ok(None)
    }

    /// The header row carries the source slot, which is how the fragment
    /// partition is addressed.  Both callers need it, so read it once here.
    async fn read_header_row(
        &self,
        network: i64,
        epoch: i64,
        checkpoint: i64,
    ) -> anyhow::Result<Option<(Vec<u8>, Vec<u8>)>> {
        let rows = self
            .session
            .execute_unpaged(&self.read_header, (network, epoch, checkpoint))
            .await?
            .into_rows_result()?;
        let Some(row) = rows
            .rows::<(i64, Vec<u8>, Vec<u8>)>()?
            .next()
            .transpose()?
        else {
            return Ok(None);
        };
        let (revision, slot, header) = row;
        if revision != SOURCE_ROW_REVISION {
            return Err(CommitSourceStoreError::UnexpectedRowRevision {
                table: COORDINATOR_COMMIT_SOURCE_HEADER_TABLE,
                revision,
            }
            .into());
        }
        Ok(Some((slot, header)))
    }

    async fn read_header_bytes(
        &self,
        network: i64,
        epoch: i64,
        checkpoint: i64,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self
            .read_header_row(network, epoch, checkpoint)
            .await?
            .map(|(_slot, header)| header))
    }

    async fn read_marker_bytes(
        &self,
        network: i64,
        epoch: i64,
        checkpoint: i64,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let rows = self
            .session
            .execute_unpaged(&self.read_committed, (network, epoch, checkpoint))
            .await?
            .into_rows_result()?;
        let Some(row) = rows.rows::<(i64, Vec<u8>)>()?.next().transpose()? else {
            return Ok(None);
        };
        let (revision, marker) = row;
        if revision != SOURCE_ROW_REVISION {
            return Err(CommitSourceStoreError::UnexpectedRowRevision {
                table: COORDINATOR_COMMIT_SOURCE_COMMITTED_TABLE,
                revision,
            }
            .into());
        }
        Ok(Some(marker))
    }

    async fn read_source_bytes<Hash: Q256BitHash>(
        &self,
        candidate: &CanonicalChainRef<Hash>,
    ) -> anyhow::Result<Option<(Vec<u8>, Vec<Vec<u8>>)>> {
        let (network, epoch, checkpoint) = Self::partition(candidate);
        let Some((slot, header)) = self.read_header_row(network, epoch, checkpoint).await? else {
            return Ok(None);
        };
        let fragment_rows = self
            .session
            .execute_unpaged(&self.read_fragments, (slot,))
            .await?
            .into_rows_result()?;
        let mut indexed: Vec<(i32, Vec<u8>)> = Vec::new();
        for row in fragment_rows.rows::<(i32, i64, Vec<u8>)>()? {
            let (index, revision, fragment) = row?;
            if revision != SOURCE_ROW_REVISION {
                return Err(CommitSourceStoreError::UnexpectedRowRevision {
                    table: COORDINATOR_COMMIT_SOURCE_FRAGMENT_TABLE,
                    revision,
                }
                .into());
            }
            indexed.push((index, fragment));
        }
        indexed.sort_by_key(|(index, _)| *index);
        // The fragment partition is addressed by source slot alone, so a gap or
        // a duplicate index means the object is not whole; decoding a partial
        // object would hand a truncated prepared update to the caller.
        for (position, (index, _)) in indexed.iter().enumerate() {
            if *index as usize != position {
                return Err(CommitSourceStoreError::FragmentGap {
                    expected: position,
                    found: *index as usize,
                }
                .into());
            }
        }
        Ok(Some((
            header,
            indexed.into_iter().map(|(_, fragment)| fragment).collect(),
        )))
    }
}

#[async_trait::async_trait]
impl<Hash: Q256BitHash> CoordinatorCommitSourceStore<Hash> for ScyllaCoordinatorCommitSourceStore {
    /// Fragments first, then the header.  A crash between the two leaves
    /// fragments that no header names, which the suffix scanner treats as an
    /// incomplete object rather than as history (design-r1 §2.2, §9).
    async fn persist_coordinator_commit_source(
        &self,
        source: &CoordinatorCommitSource<Hash>,
    ) -> anyhow::Result<()> {
        let (network, epoch, checkpoint) = Self::partition(source.candidate());
        let slot = source.slot().as_bytes().to_vec();
        for (index, fragment) in source.fragments().enumerate() {
            let index = index as i32;
            self.insert_then_verify(
                &self.insert_fragment,
                (
                    slot.clone(),
                    index,
                    SOURCE_ROW_REVISION,
                    fragment.to_vec(),
                ),
                COORDINATOR_COMMIT_SOURCE_FRAGMENT_TABLE,
                fragment,
                async || self.read_one_fragment(slot.clone(), index).await,
            )
            .await?;
        }
        let header = source.encode_header();
        self.insert_then_verify(
            &self.insert_header,
            (
                network,
                epoch,
                checkpoint,
                SOURCE_ROW_REVISION,
                slot.clone(),
                header.clone(),
            ),
            COORDINATOR_COMMIT_SOURCE_HEADER_TABLE,
            &header,
            async || self.read_header_bytes(network, epoch, checkpoint).await,
        )
        .await?;

        // Exact read-back: the object must reassemble to the same identity we
        // offered.  Nothing downstream may assume persistence without this.
        let reassembled = self
            .read_coordinator_commit_source(source.candidate())
            .await?
            .ok_or(CommitSourceStoreError::MissingAfterWrite {
                table: COORDINATOR_COMMIT_SOURCE_HEADER_TABLE,
            })?;
        if reassembled.digest() != source.digest() {
            return Err(CommitSourceStoreError::Conflict {
                table: COORDINATOR_COMMIT_SOURCE_HEADER_TABLE,
                detail: "read-back digest differs from the persisted object".to_owned(),
            }
            .into());
        }
        Ok(())
    }

    async fn read_coordinator_commit_source(
        &self,
        candidate: &CanonicalChainRef<Hash>,
    ) -> anyhow::Result<Option<CoordinatorCommitSource<Hash>>> {
        let Some((header, fragments)) = self.read_source_bytes(candidate).await? else {
            return Ok(None);
        };
        Ok(Some(CoordinatorCommitSource::decode_persisted(
            &header, fragments,
        )?))
    }

    /// The marker is not delete authority; it records that this exact object
    /// was the one committed.  It may only be written once the whole object
    /// reads back, so a marker can never outlive its source.
    async fn mark_coordinator_commit_source_committed(
        &self,
        source: &CoordinatorCommitSource<Hash>,
    ) -> anyhow::Result<()> {
        let reassembled = self
            .read_coordinator_commit_source(source.candidate())
            .await?
            .ok_or(CommitSourceStoreError::MissingAfterWrite {
                table: COORDINATOR_COMMIT_SOURCE_HEADER_TABLE,
            })?;
        if reassembled.digest() != source.digest() {
            return Err(CommitSourceStoreError::Conflict {
                table: COORDINATOR_COMMIT_SOURCE_HEADER_TABLE,
                detail: "marker would bind a different object than the stored source".to_owned(),
            }
            .into());
        }
        let (network, epoch, checkpoint) = Self::partition(source.candidate());
        let marker = source.committed_marker().encode_canonical().to_vec();
        self.insert_then_verify(
            &self.insert_committed,
            (
                network,
                epoch,
                checkpoint,
                SOURCE_ROW_REVISION,
                marker.clone(),
            ),
            COORDINATOR_COMMIT_SOURCE_COMMITTED_TABLE,
            &marker,
            async || self.read_marker_bytes(network, epoch, checkpoint).await,
        )
        .await
    }
}

impl ScyllaCoordinatorCommitSourceStore {
    /// Read the COMMITTED marker for one candidate.  A source without a marker
    /// is a crash remnant and must not enter a rollback catalog (design-r1 §9).
    pub async fn read_committed_marker<Hash: Q256BitHash>(
        &self,
        candidate: &CanonicalChainRef<Hash>,
    ) -> anyhow::Result<Option<CoordinatorCommitSourceCommitted>> {
        let (network, epoch, checkpoint) = Self::partition(candidate);
        let rows = self
            .session
            .execute_unpaged(&self.read_committed, (network, epoch, checkpoint))
            .await?
            .into_rows_result()?;
        let Some(row) = rows.rows::<(i64, Vec<u8>)>()?.next().transpose()? else {
            return Ok(None);
        };
        let (revision, marker) = row;
        if revision != SOURCE_ROW_REVISION {
            return Err(CommitSourceStoreError::UnexpectedRowRevision {
                table: COORDINATOR_COMMIT_SOURCE_COMMITTED_TABLE,
                revision,
            }
            .into());
        }
        Ok(Some(CoordinatorCommitSourceCommitted::decode_canonical(
            &marker,
        )?))
    }
}

/// Read-only description of the network binding, so callers can reason about
/// the partition without reaching for the session.
pub fn commit_source_partition<Hash: Q256BitHash>(
    candidate: &CanonicalChainRef<Hash>,
) -> (NetworkId, u64, u64) {
    (
        candidate.network_id(),
        candidate.chain_epoch().get(),
        candidate.checkpoint().checkpoint_id().get(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keyspace() -> CommitSourceNoTabletKeyspace {
        CommitSourceNoTabletKeyspace::try_new("psy_no_tablet").unwrap()
    }

    #[test]
    fn control_tables_require_a_no_tablet_keyspace() {
        assert!(CommitSourceNoTabletKeyspace::try_new("psy").is_err());
        assert!(CommitSourceNoTabletKeyspace::try_new("psy_no_tablet").is_ok());
    }

    #[test]
    fn ddl_matches_the_addressing_the_design_specifies() {
        let queries = CommitSourceQueries::new(&keyspace());
        assert!(queries.create_header.contains(
            "PRIMARY KEY ((network_chain_id, chain_epoch), checkpoint_id)"
        ));
        assert!(
            queries
                .create_fragment
                .contains("PRIMARY KEY ((source_slot), fragment_index)")
        );
        assert!(queries.create_committed.contains(
            "PRIMARY KEY ((network_chain_id, chain_epoch), checkpoint_id)"
        ));
    }

    #[test]
    fn every_write_is_an_append_only_lwt() {
        let queries = CommitSourceQueries::new(&keyspace());
        for statement in [
            &queries.insert_header,
            &queries.insert_fragment,
            &queries.insert_committed,
        ] {
            assert!(statement.starts_with("INSERT INTO"), "{statement}");
            assert!(statement.ends_with("IF NOT EXISTS"), "{statement}");
        }
        // design-r1 §2.2: no UPDATE / DELETE / TTL / explicit timestamp here.
        for statement in [
            &queries.create_header,
            &queries.create_fragment,
            &queries.create_committed,
            &queries.read_header,
            &queries.read_fragments,
            &queries.insert_header,
            &queries.insert_fragment,
            &queries.read_committed,
            &queries.insert_committed,
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
    fn qualified_names_stay_inside_the_validated_keyspace() {
        let queries = CommitSourceQueries::new(&keyspace());
        assert!(
            queries
                .read_header
                .contains("psy_no_tablet.coordinator_commit_source_header")
        );
        assert!(
            queries
                .read_fragments
                .contains("psy_no_tablet.coordinator_commit_source_fragment")
        );
        assert!(
            queries
                .read_committed
                .contains("psy_no_tablet.coordinator_commit_source_committed")
        );
    }
}
