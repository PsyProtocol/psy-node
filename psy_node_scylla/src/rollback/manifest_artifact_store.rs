//! Durable Scylla adapter for the chunked artifacts a manifest commits to.
//!
//! The manifest record says *that* a commit wrote a set of rows and commits to
//! its digest; these chunks say *which* rows.  Rollback reads them to build the
//! delete plan for the discarded suffix.
//!
//! Chunks are addressed by an artifact slot derived from the manifest's exact
//! canonical chain reference plus the artifact kind.  Two commits at the same
//! height on different branches therefore land in different partitions, because
//! the reference includes both the chain epoch and the checkpoint hash.
//!
//! Append-only, `IF NOT EXISTS` at `QUORUM` / `LOCAL_SERIAL`, each write followed
//! by a point read — the same discipline and the same reason as
//! `commit_source_store`.

use std::{error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_node_core::store::{
    manifest_record::AuthorityManifestIdentity,
    manifest_store::{ManifestArtifactKind, ManifestArtifactStore},
};
use scylla::{
    client::session::Session,
    statement::{Consistency, SerialConsistency, prepared::PreparedStatement},
};
use sha2::{Digest, Sha256};

use super::{CqlKeyspaceName, InvalidCqlKeyspaceName};

pub const AUTHORITY_MANIFEST_ARTIFACT_TABLE: &str = "authority_manifest_artifact";

const ARTIFACT_SLOT_DOMAIN: &[u8] = b"psy.rollback.manifest-artifact-slot.v1\0";
const ARTIFACT_ROW_REVISION: i64 = 1;

/// Explicit trust boundary for a keyspace provisioned with tablets disabled.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ManifestArtifactNoTabletKeyspace(CqlKeyspaceName);

impl ManifestArtifactNoTabletKeyspace {
    pub fn try_new(name: impl Into<String>) -> Result<Self, ManifestArtifactStoreError> {
        let name = name.into();
        if !name.ends_with("_no_tablet") {
            return Err(ManifestArtifactStoreError::KeyspaceIsNotNoTablet(name));
        }
        Ok(Self(CqlKeyspaceName::try_new(name)?))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifestArtifactStoreError {
    KeyspaceIsNotNoTablet(String),
    InvalidKeyspace(InvalidCqlKeyspaceName),
    Conflict {
        kind: ManifestArtifactKind,
        chunk_index: u32,
        stored_len: usize,
        offered_len: usize,
    },
    MissingAfterWrite {
        kind: ManifestArtifactKind,
        chunk_index: u32,
    },
    UnexpectedRowRevision {
        chunk_index: u32,
        revision: i64,
    },
    /// A chunk index is absent or repeated.  The artifact partition is keyed by
    /// slot alone, so a gap means the set is not whole, and handing rollback a
    /// short mutation set would delete less than was archived.
    ChunkGap {
        kind: ManifestArtifactKind,
        expected: u32,
        found: u32,
    },
    /// The store holds a different number of chunks than the manifest committed
    /// to.  Trusting the stored count would let a lost chunk pass unnoticed.
    ChunkCountMismatch {
        kind: ManifestArtifactKind,
        committed: u32,
        found: u32,
    },
    EmptyArtifact {
        kind: ManifestArtifactKind,
    },
}

impl From<InvalidCqlKeyspaceName> for ManifestArtifactStoreError {
    fn from(error: InvalidCqlKeyspaceName) -> Self {
        Self::InvalidKeyspace(error)
    }
}

impl fmt::Display for ManifestArtifactStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for ManifestArtifactStoreError {}

/// Stable partition identity for one artifact of one manifest.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ManifestArtifactSlot([u8; 32]);

impl ManifestArtifactSlot {
    pub fn for_manifest<Hash: Q256BitHash>(
        identity: &AuthorityManifestIdentity<Hash>,
        kind: ManifestArtifactKind,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(ARTIFACT_SLOT_DOMAIN);
        hasher.update(identity.canonical_chain().to_canonical_bytes());
        hasher.update(identity.authority().to_canonical_bytes());
        hasher.update([kind as u8]);
        Self(hasher.finalize().into())
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub struct ManifestArtifactQueries {
    pub create_table: String,
    pub insert_chunk: String,
    pub read_chunk: String,
    pub read_all_chunks: String,
}

impl ManifestArtifactQueries {
    pub fn new(keyspace: &ManifestArtifactNoTabletKeyspace) -> Self {
        let table = format!(
            "{}.{AUTHORITY_MANIFEST_ARTIFACT_TABLE}",
            keyspace.as_str()
        );
        Self {
            create_table: format!(
                "CREATE TABLE IF NOT EXISTS {table} (artifact_slot blob, chunk_index int, \
                 revision bigint, chunk blob, PRIMARY KEY ((artifact_slot), chunk_index)) \
                 WITH CLUSTERING ORDER BY (chunk_index ASC)"
            ),
            insert_chunk: format!(
                "INSERT INTO {table} (artifact_slot, chunk_index, revision, chunk) \
                 VALUES (?, ?, ?, ?) IF NOT EXISTS"
            ),
            read_chunk: format!(
                "SELECT revision, chunk FROM {table} \
                 WHERE artifact_slot = ? AND chunk_index = ?"
            ),
            read_all_chunks: format!(
                "SELECT chunk_index, revision, chunk FROM {table} WHERE artifact_slot = ?"
            ),
        }
    }
}

pub struct ScyllaManifestArtifactStore {
    session: Arc<Session>,
    insert_chunk: PreparedStatement,
    read_chunk: PreparedStatement,
    read_all_chunks: PreparedStatement,
}

impl ScyllaManifestArtifactStore {
    pub async fn create_tables(
        session: &Session,
        keyspace: &ManifestArtifactNoTabletKeyspace,
    ) -> anyhow::Result<()> {
        session
            .query_unpaged(ManifestArtifactQueries::new(keyspace).create_table, &[])
            .await?;
        session.await_schema_agreement().await?;
        Ok(())
    }

    pub async fn prepare(
        session: Arc<Session>,
        keyspace: &ManifestArtifactNoTabletKeyspace,
    ) -> anyhow::Result<Self> {
        let queries = ManifestArtifactQueries::new(keyspace);
        let mut insert_chunk = session.prepare(queries.insert_chunk).await?;
        insert_chunk.set_consistency(Consistency::Quorum);
        insert_chunk.set_serial_consistency(Some(SerialConsistency::LocalSerial));
        let mut read_chunk = session.prepare(queries.read_chunk).await?;
        read_chunk.set_consistency(Consistency::Quorum);
        let mut read_all_chunks = session.prepare(queries.read_all_chunks).await?;
        read_all_chunks.set_consistency(Consistency::Quorum);
        Ok(Self {
            session,
            insert_chunk,
            read_chunk,
            read_all_chunks,
        })
    }

    async fn read_one_chunk(
        &self,
        slot: &ManifestArtifactSlot,
        chunk_index: u32,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let rows = self
            .session
            .execute_unpaged(
                &self.read_chunk,
                (slot.as_bytes().to_vec(), chunk_index as i32),
            )
            .await?
            .into_rows_result()?;
        let Some(row) = rows.rows::<(i64, Vec<u8>)>()?.next().transpose()? else {
            return Ok(None);
        };
        let (revision, chunk) = row;
        if revision != ARTIFACT_ROW_REVISION {
            return Err(ManifestArtifactStoreError::UnexpectedRowRevision {
                chunk_index,
                revision,
            }
            .into());
        }
        Ok(Some(chunk))
    }

    /// Persist every chunk of one artifact and read each back.
    ///
    /// Chunks are written before the manifest record that commits to them, so a
    /// crash in between leaves chunks no manifest names, which reads as an
    /// unfinished commit rather than as history.
    async fn persist_chunks_for<Hash: Q256BitHash>(
        &self,
        identity: &AuthorityManifestIdentity<Hash>,
        kind: ManifestArtifactKind,
        chunks: &[Vec<u8>],
    ) -> anyhow::Result<ManifestArtifactSlot> {
        if chunks.is_empty() {
            return Err(ManifestArtifactStoreError::EmptyArtifact { kind }.into());
        }
        let slot = ManifestArtifactSlot::for_manifest(identity, kind);
        for (chunk_index, chunk) in chunks.iter().enumerate() {
            let chunk_index = chunk_index as u32;
            self.session
                .execute_unpaged(
                    &self.insert_chunk,
                    (
                        slot.as_bytes().to_vec(),
                        chunk_index as i32,
                        ARTIFACT_ROW_REVISION,
                        chunk.clone(),
                    ),
                )
                .await?;
            match self.read_one_chunk(&slot, chunk_index).await? {
                Some(stored) if stored == *chunk => {}
                Some(stored) => {
                    return Err(ManifestArtifactStoreError::Conflict {
                        kind,
                        chunk_index,
                        stored_len: stored.len(),
                        offered_len: chunk.len(),
                    }
                    .into());
                }
                None => {
                    return Err(ManifestArtifactStoreError::MissingAfterWrite { kind, chunk_index }
                        .into());
                }
            }
        }
        Ok(slot)
    }

    /// Read the whole artifact back in order.
    ///
    /// `committed_chunk_count` comes from the manifest's artifact set
    /// commitment, not from the store.  Trusting whatever the store happens to
    /// hold would let a lost chunk pass as a shorter mutation set, and rollback
    /// would then delete less than it archived.
    async fn read_chunks_for<Hash: Q256BitHash>(
        &self,
        identity: &AuthorityManifestIdentity<Hash>,
        kind: ManifestArtifactKind,
        committed_chunk_count: u32,
    ) -> anyhow::Result<Vec<Vec<u8>>> {
        let slot = ManifestArtifactSlot::for_manifest(identity, kind);
        let rows = self
            .session
            .execute_unpaged(&self.read_all_chunks, (slot.as_bytes().to_vec(),))
            .await?
            .into_rows_result()?;
        let mut indexed: Vec<(u32, Vec<u8>)> = Vec::new();
        for row in rows.rows::<(i32, i64, Vec<u8>)>()? {
            let (chunk_index, revision, chunk) = row?;
            let chunk_index = chunk_index as u32;
            if revision != ARTIFACT_ROW_REVISION {
                return Err(ManifestArtifactStoreError::UnexpectedRowRevision {
                    chunk_index,
                    revision,
                }
                .into());
            }
            indexed.push((chunk_index, chunk));
        }
        indexed.sort_by_key(|(index, _)| *index);
        verify_chunk_sequence(kind, committed_chunk_count, &indexed)?;
        Ok(indexed.into_iter().map(|(_, chunk)| chunk).collect())
    }
}

/// The stored chunk indices must be exactly `0..committed`.
///
/// Split out so the rule is testable without a session; it is the check that
/// stops a partially written or partially lost artifact from being read as a
/// complete one.
pub fn verify_chunk_sequence(
    kind: ManifestArtifactKind,
    committed_chunk_count: u32,
    indexed: &[(u32, Vec<u8>)],
) -> Result<(), ManifestArtifactStoreError> {
    if committed_chunk_count == 0 {
        return Err(ManifestArtifactStoreError::EmptyArtifact { kind });
    }
    if indexed.len() as u32 != committed_chunk_count {
        return Err(ManifestArtifactStoreError::ChunkCountMismatch {
            kind,
            committed: committed_chunk_count,
            found: indexed.len() as u32,
        });
    }
    for (position, (chunk_index, _)) in indexed.iter().enumerate() {
        if *chunk_index != position as u32 {
            return Err(ManifestArtifactStoreError::ChunkGap {
                kind,
                expected: position as u32,
                found: *chunk_index,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keyspace() -> ManifestArtifactNoTabletKeyspace {
        ManifestArtifactNoTabletKeyspace::try_new("psy_no_tablet").unwrap()
    }

    fn chunks(indices: &[u32]) -> Vec<(u32, Vec<u8>)> {
        indices.iter().map(|index| (*index, vec![*index as u8])).collect()
    }

    #[test]
    fn artifacts_require_a_no_tablet_keyspace() {
        assert!(ManifestArtifactNoTabletKeyspace::try_new("psy").is_err());
        assert!(ManifestArtifactNoTabletKeyspace::try_new("psy_no_tablet").is_ok());
    }

    #[test]
    fn chunks_are_append_only_and_ordered() {
        let queries = ManifestArtifactQueries::new(&keyspace());
        assert!(
            queries
                .create_table
                .contains("PRIMARY KEY ((artifact_slot), chunk_index)")
        );
        assert!(
            queries
                .create_table
                .contains("CLUSTERING ORDER BY (chunk_index ASC)")
        );
        assert!(queries.insert_chunk.ends_with("IF NOT EXISTS"));
        for statement in [
            &queries.create_table,
            &queries.insert_chunk,
            &queries.read_chunk,
            &queries.read_all_chunks,
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
    fn a_complete_sequence_is_accepted() {
        assert_eq!(
            verify_chunk_sequence(ManifestArtifactKind::Locator, 3, &chunks(&[0, 1, 2])),
            Ok(())
        );
    }

    #[test]
    fn a_lost_chunk_is_rejected_rather_than_read_as_a_shorter_set() {
        // The dangerous case: the store holds fewer chunks than the manifest
        // committed to, so a naive reader would build a delete plan missing
        // rows that were archived.
        assert_eq!(
            verify_chunk_sequence(ManifestArtifactKind::Locator, 3, &chunks(&[0, 1])),
            Err(ManifestArtifactStoreError::ChunkCountMismatch {
                kind: ManifestArtifactKind::Locator,
                committed: 3,
                found: 2,
            })
        );
    }

    #[test]
    fn a_gap_is_rejected_even_when_the_count_happens_to_match() {
        assert_eq!(
            verify_chunk_sequence(ManifestArtifactKind::Locator, 3, &chunks(&[0, 1, 3])),
            Err(ManifestArtifactStoreError::ChunkGap {
                kind: ManifestArtifactKind::Locator,
                expected: 2,
                found: 3,
            })
        );
    }

    #[test]
    fn an_extra_chunk_is_rejected() {
        assert_eq!(
            verify_chunk_sequence(ManifestArtifactKind::Locator, 2, &chunks(&[0, 1, 2])),
            Err(ManifestArtifactStoreError::ChunkCountMismatch {
                kind: ManifestArtifactKind::Locator,
                committed: 2,
                found: 3,
            })
        );
    }

    #[test]
    fn a_zero_chunk_commitment_is_rejected() {
        // An artifact always has at least one chunk, even for an empty commit.
        assert_eq!(
            verify_chunk_sequence(ManifestArtifactKind::Locator, 0, &[]),
            Err(ManifestArtifactStoreError::EmptyArtifact {
                kind: ManifestArtifactKind::Locator,
            })
        );
    }
}

#[async_trait::async_trait]
impl<Hash: Q256BitHash> ManifestArtifactStore<Hash> for ScyllaManifestArtifactStore {
    async fn persist_artifact_chunks(
        &self,
        identity: &AuthorityManifestIdentity<Hash>,
        kind: ManifestArtifactKind,
        chunks: &[Vec<u8>],
    ) -> anyhow::Result<()> {
        self.persist_chunks_for(identity, kind, chunks).await?;
        Ok(())
    }

    async fn read_artifact_chunks(
        &self,
        identity: &AuthorityManifestIdentity<Hash>,
        kind: ManifestArtifactKind,
        committed_chunk_count: u32,
    ) -> anyhow::Result<Vec<Vec<u8>>> {
        self.read_chunks_for(identity, kind, committed_chunk_count)
            .await
    }
}
