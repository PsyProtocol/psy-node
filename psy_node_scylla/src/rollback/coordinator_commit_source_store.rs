//! Append-only Scylla store for normal Coordinator commit sources.
//!
//! This adapter stores source fragments before the visible header, and writes
//! the independent COMMITTED marker only after an exact source reread. It has
//! no hot-table delete, rollback barrier, or canonical-head mutation API.

use std::{error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::canonical_chain::{CanonicalChainRef, NetworkId};
use psy_node_core::store::coordinator_commit_source::{
    CoordinatorCommitSource, CoordinatorCommitSourceCommitted,
    CoordinatorCommitSourcePayload,
    COORDINATOR_COMMIT_SOURCE_MAX_FRAGMENTS,
};
use scylla::{
    client::session::Session,
    statement::{prepared::PreparedStatement, Consistency, SerialConsistency},
};

use super::CanonicalHeadNoTabletKeyspace;

pub(crate) const COORDINATOR_COMMIT_SOURCE_HEADER_TABLE: &str =
    "coordinator_commit_source_header_v1";
pub(crate) const COORDINATOR_COMMIT_SOURCE_FRAGMENT_TABLE: &str =
    "coordinator_commit_source_fragment_v1";
pub(crate) const COORDINATOR_COMMIT_SOURCE_COMMITTED_TABLE: &str =
    "coordinator_commit_source_committed_v1";
const ROW_REVISION: i64 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CoordinatorCommitSourceQueries {
    create_header: String,
    create_fragment: String,
    create_committed: String,
    read_header: String,
    read_fragments: String,
    insert_header: String,
    insert_fragment: String,
    read_committed: String,
    insert_committed: String,
    scan_headers: String,
}

impl CoordinatorCommitSourceQueries {
    pub(crate) fn new(keyspace: &CanonicalHeadNoTabletKeyspace) -> Self {
        let prefix = keyspace.as_str();
        let header = format!("{prefix}.{COORDINATOR_COMMIT_SOURCE_HEADER_TABLE}");
        let fragment = format!("{prefix}.{COORDINATOR_COMMIT_SOURCE_FRAGMENT_TABLE}");
        let committed = format!("{prefix}.{COORDINATOR_COMMIT_SOURCE_COMMITTED_TABLE}");
        Self {
            create_header: format!(
                "CREATE TABLE IF NOT EXISTS {header} (network_chain_id bigint, chain_epoch bigint, checkpoint_id bigint, revision bigint, source_slot blob, header blob, PRIMARY KEY ((network_chain_id, chain_epoch), checkpoint_id))"
            ),
            create_fragment: format!(
                "CREATE TABLE IF NOT EXISTS {fragment} (source_slot blob, fragment_index int, revision bigint, fragment blob, PRIMARY KEY ((source_slot), fragment_index))"
            ),
            create_committed: format!(
                "CREATE TABLE IF NOT EXISTS {committed} (network_chain_id bigint, chain_epoch bigint, checkpoint_id bigint, revision bigint, marker blob, PRIMARY KEY ((network_chain_id, chain_epoch), checkpoint_id))"
            ),
            read_header: format!(
                "SELECT revision, source_slot, header FROM {header} WHERE network_chain_id = ? AND chain_epoch = ? AND checkpoint_id = ?"
            ),
            read_fragments: format!(
                "SELECT fragment_index, revision, fragment FROM {fragment} WHERE source_slot = ?"
            ),
            insert_header: format!(
                "INSERT INTO {header} (network_chain_id, chain_epoch, checkpoint_id, revision, source_slot, header) VALUES (?, ?, ?, ?, ?, ?) IF NOT EXISTS"
            ),
            insert_fragment: format!(
                "INSERT INTO {fragment} (source_slot, fragment_index, revision, fragment) VALUES (?, ?, ?, ?) IF NOT EXISTS"
            ),
            read_committed: format!(
                "SELECT revision, marker FROM {committed} WHERE network_chain_id = ? AND chain_epoch = ? AND checkpoint_id = ?"
            ),
            insert_committed: format!(
                "INSERT INTO {committed} (network_chain_id, chain_epoch, checkpoint_id, revision, marker) VALUES (?, ?, ?, ?, ?) IF NOT EXISTS"
            ),
            scan_headers: format!(
                "SELECT checkpoint_id, revision, source_slot, header FROM {header} WHERE network_chain_id = ? AND chain_epoch = ? AND checkpoint_id > ? AND checkpoint_id <= ?"
            ),
        }
    }
}

pub(crate) struct ScyllaCoordinatorCommitSourceStore {
    session: Arc<Session>,
    queries: CoordinatorCommitSourceQueries,
    read_header: PreparedStatement,
    read_fragments: PreparedStatement,
    insert_header: PreparedStatement,
    insert_fragment: PreparedStatement,
    read_committed: PreparedStatement,
    insert_committed: PreparedStatement,
    scan_headers: PreparedStatement,
}

impl ScyllaCoordinatorCommitSourceStore {
    pub(crate) async fn create_schema(
        session: &Session,
        keyspace: &CanonicalHeadNoTabletKeyspace,
    ) -> Result<(), CoordinatorCommitSourceStoreError> {
        let queries = CoordinatorCommitSourceQueries::new(keyspace);
        for query in [
            &queries.create_header,
            &queries.create_fragment,
            &queries.create_committed,
        ] {
            session
                .query_unpaged(query.as_str(), &[])
                .await
                .map_err(driver)?;
        }
        session.await_schema_agreement().await.map_err(driver)?;
        Ok(())
    }

    pub(crate) async fn prepare(
        session: Arc<Session>,
        keyspace: CanonicalHeadNoTabletKeyspace,
    ) -> Result<Self, CoordinatorCommitSourceStoreError> {
        let queries = CoordinatorCommitSourceQueries::new(&keyspace);
        Ok(Self {
            read_header: prepare_regular(&session, &queries.read_header).await?,
            read_fragments: prepare_regular(&session, &queries.read_fragments).await?,
            insert_header: prepare_lwt(&session, &queries.insert_header).await?,
            insert_fragment: prepare_lwt(&session, &queries.insert_fragment).await?,
            read_committed: prepare_regular(&session, &queries.read_committed).await?,
            insert_committed: prepare_lwt(&session, &queries.insert_committed).await?,
            scan_headers: prepare_regular(&session, &queries.scan_headers).await?,
            session,
            queries,
        })
    }

    pub(crate) const fn queries(&self) -> &CoordinatorCommitSourceQueries {
        &self.queries
    }

    pub(crate) async fn persist_and_readback<Hash: Q256BitHash>(
        &self,
        source: &CoordinatorCommitSource<Hash>,
    ) -> Result<(), CoordinatorCommitSourceStoreError> {
        let slot = source.slot().as_bytes();
        for (index, fragment) in source.fragments().enumerate() {
            let index = i32::try_from(index)
                .map_err(|_| CoordinatorCommitSourceStoreError::IntegerOutOfRange)?;
            let execution = self.session.execute_unpaged(
                &self.insert_fragment,
                (slot.as_slice(), index, ROW_REVISION, fragment),
            ).await;
            if let Err(error) = execution {
                let current = self.read_fragments_for_slot(slot).await;
                match current {
                    Ok(current) if current.get(index as usize).map(Vec::as_slice) == Some(fragment) => {}
                    Ok(_) => return Err(CoordinatorCommitSourceStoreError::IndeterminateWrite(error.to_string())),
                    Err(read) => return Err(CoordinatorCommitSourceStoreError::IndeterminateWrite(
                        format!("execute={error}; read={read}"),
                    )),
                }
            }
            let current = self.read_fragments_for_slot(slot).await?;
            if current.get(index as usize).map(Vec::as_slice) != Some(fragment) {
                return Err(CoordinatorCommitSourceStoreError::FragmentConflict);
            }
        }
        let key = source_key(source.candidate())?;
        let header = source.encode_header();
        let execution = self.session.execute_unpaged(
            &self.insert_header,
            (key.0, key.1, key.2, ROW_REVISION, slot.as_slice(), header.as_slice()),
        ).await;
        if let Err(error) = execution {
            return match self.read_source(source.candidate()).await {
                Ok(Some(current)) if current == *source => Ok(()),
                Ok(Some(_)) => Err(CoordinatorCommitSourceStoreError::SourceConflict),
                Ok(None) => Err(CoordinatorCommitSourceStoreError::IndeterminateWrite(error.to_string())),
                Err(read) => Err(CoordinatorCommitSourceStoreError::IndeterminateWrite(
                    format!("execute={error}; read={read}"),
                )),
            };
        }
        match self.read_source(source.candidate()).await? {
            Some(current) if current == *source => Ok(()),
            Some(_) => Err(CoordinatorCommitSourceStoreError::SourceConflict),
            None => Err(CoordinatorCommitSourceStoreError::SourceMissingAfterWrite),
        }
    }

    pub(crate) async fn mark_committed_and_readback<Hash: Q256BitHash>(
        &self,
        source: &CoordinatorCommitSource<Hash>,
    ) -> Result<(), CoordinatorCommitSourceStoreError> {
        match self.read_source(source.candidate()).await? {
            Some(current) if current == *source => {}
            Some(_) => return Err(CoordinatorCommitSourceStoreError::SourceConflict),
            None => return Err(CoordinatorCommitSourceStoreError::SourceMissingBeforeCommit),
        }
        let marker = source.committed_marker();
        let marker_bytes = marker.encode_canonical();
        let key = source_key(source.candidate())?;
        let execution = self.session.execute_unpaged(
            &self.insert_committed,
            (key.0, key.1, key.2, ROW_REVISION, marker_bytes.as_slice()),
        ).await;
        if let Err(error) = execution {
            return match self.read_committed(source.candidate()).await {
                Ok(Some(current)) if current == marker => Ok(()),
                Ok(Some(_)) => Err(CoordinatorCommitSourceStoreError::CommittedConflict),
                Ok(None) => Err(CoordinatorCommitSourceStoreError::IndeterminateWrite(error.to_string())),
                Err(read) => Err(CoordinatorCommitSourceStoreError::IndeterminateWrite(
                    format!("execute={error}; read={read}"),
                )),
            };
        }
        match self.read_committed(source.candidate()).await? {
            Some(current) if current == marker => Ok(()),
            Some(_) => Err(CoordinatorCommitSourceStoreError::CommittedConflict),
            None => Err(CoordinatorCommitSourceStoreError::CommittedMissingAfterWrite),
        }
    }

    pub(crate) async fn read_source<Hash: Q256BitHash>(
        &self,
        candidate: &CanonicalChainRef<Hash>,
    ) -> Result<Option<CoordinatorCommitSource<Hash>>, CoordinatorCommitSourceStoreError> {
        let key = source_key(candidate)?;
        let row = self.session.execute_unpaged(&self.read_header, key).await
            .map_err(driver)?
            .into_rows_result().map_err(driver)?
            .maybe_first_row::<(i64, Vec<u8>, Vec<u8>)>().map_err(driver)?;
        let Some((revision, slot, header)) = row else { return Ok(None); };
        if revision != ROW_REVISION || slot.len() != 32 {
            return Err(CoordinatorCommitSourceStoreError::MalformedRow);
        }
        let slot: [u8; 32] = slot.try_into().map_err(|_| CoordinatorCommitSourceStoreError::MalformedRow)?;
        let fragments = self.read_fragments_for_slot(slot).await?;
        let source = CoordinatorCommitSource::decode_persisted(&header, fragments)
            .map_err(|error| CoordinatorCommitSourceStoreError::Codec(error.to_string()))?;
        CoordinatorCommitSourcePayload::decode_canonical(source.prepared_update())
            .map_err(|error| CoordinatorCommitSourceStoreError::Codec(error.to_string()))?;
        if source.candidate() != candidate || source.slot().as_bytes() != slot {
            return Err(CoordinatorCommitSourceStoreError::IdentityMismatch);
        }
        Ok(Some(source))
    }

    pub(crate) async fn read_committed<Hash: Q256BitHash>(
        &self,
        candidate: &CanonicalChainRef<Hash>,
    ) -> Result<Option<CoordinatorCommitSourceCommitted>, CoordinatorCommitSourceStoreError> {
        let key = source_key(candidate)?;
        let row = self.session.execute_unpaged(&self.read_committed, key).await
            .map_err(driver)?
            .into_rows_result().map_err(driver)?
            .maybe_first_row::<(i64, Vec<u8>)>().map_err(driver)?;
        let Some((revision, bytes)) = row else { return Ok(None); };
        if revision != ROW_REVISION {
            return Err(CoordinatorCommitSourceStoreError::MalformedRow);
        }
        CoordinatorCommitSourceCommitted::decode_canonical(&bytes)
            .map(Some)
            .map_err(|error| CoordinatorCommitSourceStoreError::Codec(error.to_string()))
    }

    /// Select a suffix in stable checkpoint order, requiring each row to have
    /// an exact marker. Source-only crash remnants are never returned.
    pub(crate) async fn scan_committed_suffix<Hash: Q256BitHash>(
        &self,
        network: NetworkId,
        epoch: u64,
        target_exclusive: u64,
        old_head_inclusive: u64,
    ) -> Result<Vec<CoordinatorCommitSource<Hash>>, CoordinatorCommitSourceStoreError> {
        if target_exclusive >= old_head_inclusive {
            return Ok(Vec::new());
        }
        let rows_result = self.session.execute_unpaged(
            &self.scan_headers,
            (
                i64::from(network.chain_id()),
                to_i64(epoch)?,
                to_i64(target_exclusive)?,
                to_i64(old_head_inclusive)?,
            ),
        ).await.map_err(driver)?.into_rows_result().map_err(driver)?;
        let rows = rows_result
            .rows::<(i64, i64, Vec<u8>, Vec<u8>)>().map_err(driver)?;
        let mut checkpoints = Vec::new();
        for row in rows {
            let (checkpoint, revision, slot, _header) = row.map_err(driver)?;
            if revision != ROW_REVISION || slot.len() != 32 || checkpoint < 0 {
                return Err(CoordinatorCommitSourceStoreError::MalformedRow);
            }
            checkpoints.push(checkpoint as u64);
        }
        checkpoints.sort_unstable();
        if checkpoints.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(CoordinatorCommitSourceStoreError::DuplicateCheckpoint);
        }
        let expected_count = old_head_inclusive - target_exclusive;
        if checkpoints.len() as u64 != expected_count {
            return Err(CoordinatorCommitSourceStoreError::IncompleteCommittedSuffix {
                expected: expected_count,
                actual: checkpoints.len() as u64,
            });
        }
        let mut sources = Vec::with_capacity(checkpoints.len());
        for (offset, checkpoint) in checkpoints.into_iter().enumerate() {
            let expected_checkpoint = target_exclusive + 1 + offset as u64;
            if checkpoint != expected_checkpoint {
                return Err(CoordinatorCommitSourceStoreError::IncompleteCommittedSuffix {
                    expected: expected_count,
                    actual: sources.len() as u64,
                });
            }
            // Header contains the full canonical ref, so decode it first using
            // its physical key rather than synthesizing a checkpoint hash.
            let source = self.read_source_by_coordinates::<Hash>(network, epoch, checkpoint).await?
                .ok_or(CoordinatorCommitSourceStoreError::SourceMissingAfterScan)?;
            let marker = self.read_committed(source.candidate()).await?
                .ok_or(CoordinatorCommitSourceStoreError::CommittedMarkerMissing)?;
            if !marker.matches(&source) {
                return Err(CoordinatorCommitSourceStoreError::CommittedConflict);
            }
            sources.push(source);
        }
        Ok(sources)
    }

    async fn read_source_by_coordinates<Hash: Q256BitHash>(
        &self,
        network: NetworkId,
        epoch: u64,
        checkpoint: u64,
    ) -> Result<Option<CoordinatorCommitSource<Hash>>, CoordinatorCommitSourceStoreError> {
        let key = (i64::from(network.chain_id()), to_i64(epoch)?, to_i64(checkpoint)?);
        let row = self.session.execute_unpaged(&self.read_header, key).await
            .map_err(driver)?.into_rows_result().map_err(driver)?
            .maybe_first_row::<(i64, Vec<u8>, Vec<u8>)>().map_err(driver)?;
        let Some((revision, slot, header)) = row else { return Ok(None); };
        if revision != ROW_REVISION || slot.len() != 32 {
            return Err(CoordinatorCommitSourceStoreError::MalformedRow);
        }
        let slot: [u8; 32] = slot.try_into().map_err(|_| CoordinatorCommitSourceStoreError::MalformedRow)?;
        let source = CoordinatorCommitSource::decode_persisted(
            &header,
            self.read_fragments_for_slot(slot).await?,
        ).map_err(|error| CoordinatorCommitSourceStoreError::Codec(error.to_string()))?;
        CoordinatorCommitSourcePayload::decode_canonical(source.prepared_update())
            .map_err(|error| CoordinatorCommitSourceStoreError::Codec(error.to_string()))?;
        if source.candidate().network_id() != network
            || source.candidate().chain_epoch().get() != epoch
            || source.candidate().checkpoint().checkpoint_id().get() != checkpoint
            || source.slot().as_bytes() != slot
        {
            return Err(CoordinatorCommitSourceStoreError::IdentityMismatch);
        }
        Ok(Some(source))
    }

    async fn read_fragments_for_slot(
        &self,
        slot: [u8; 32],
    ) -> Result<Vec<Vec<u8>>, CoordinatorCommitSourceStoreError> {
        let rows_result = self.session.execute_unpaged(&self.read_fragments, (slot.as_slice(),)).await
            .map_err(driver)?.into_rows_result().map_err(driver)?;
        let rows = rows_result
            .rows::<(i32, i64, Vec<u8>)>().map_err(driver)?;
        let mut fragments = Vec::new();
        for row in rows {
            let (index, revision, fragment) = row.map_err(driver)?;
            if index < 0
                || index as usize >= COORDINATOR_COMMIT_SOURCE_MAX_FRAGMENTS
                || revision != ROW_REVISION
                || fragments.len() >= COORDINATOR_COMMIT_SOURCE_MAX_FRAGMENTS
            {
                return Err(CoordinatorCommitSourceStoreError::MalformedRow);
            }
            fragments.push((index as usize, fragment));
        }
        fragments.sort_by_key(|(index, _)| *index);
        for (expected, (actual, _)) in fragments.iter().enumerate() {
            if expected != *actual {
                return Err(CoordinatorCommitSourceStoreError::FragmentIndexGap);
            }
        }
        Ok(fragments.into_iter().map(|(_, fragment)| fragment).collect())
    }
}

fn source_key<Hash: Q256BitHash>(
    candidate: &CanonicalChainRef<Hash>,
) -> Result<(i64, i64, i64), CoordinatorCommitSourceStoreError> {
    Ok((
        i64::from(candidate.network_id().chain_id()),
        to_i64(candidate.chain_epoch().get())?,
        to_i64(candidate.checkpoint().checkpoint_id().get())?,
    ))
}

fn to_i64(value: u64) -> Result<i64, CoordinatorCommitSourceStoreError> {
    i64::try_from(value).map_err(|_| CoordinatorCommitSourceStoreError::IntegerOutOfRange)
}

async fn prepare_regular(
    session: &Session,
    query: &str,
) -> Result<PreparedStatement, CoordinatorCommitSourceStoreError> {
    let mut statement = session.prepare(query).await.map_err(driver)?;
    statement.set_consistency(Consistency::Quorum);
    Ok(statement)
}

async fn prepare_lwt(
    session: &Session,
    query: &str,
) -> Result<PreparedStatement, CoordinatorCommitSourceStoreError> {
    let mut statement = prepare_regular(session, query).await?;
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    Ok(statement)
}

fn driver(error: impl ToString) -> CoordinatorCommitSourceStoreError {
    CoordinatorCommitSourceStoreError::Driver(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CoordinatorCommitSourceStoreError {
    Driver(String),
    Codec(String),
    IntegerOutOfRange,
    MalformedRow,
    IdentityMismatch,
    FragmentIndexGap,
    FragmentConflict,
    SourceConflict,
    SourceMissingAfterWrite,
    SourceMissingBeforeCommit,
    SourceMissingAfterScan,
    CommittedConflict,
    CommittedMissingAfterWrite,
    CommittedMarkerMissing,
    DuplicateCheckpoint,
    IncompleteCommittedSuffix { expected: u64, actual: u64 },
    IndeterminateWrite(String),
}

impl fmt::Display for CoordinatorCommitSourceStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Coordinator commit source store error: {self:?}")
    }
}

impl Error for CoordinatorCommitSourceStoreError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries_are_append_only_lwt_and_suffix_addressable() {
        let keyspace = CanonicalHeadNoTabletKeyspace::try_new("control_nt").unwrap();
        let queries = CoordinatorCommitSourceQueries::new(&keyspace);
        assert!(queries.insert_header.contains("IF NOT EXISTS"));
        assert!(queries.insert_fragment.contains("IF NOT EXISTS"));
        assert!(queries.insert_committed.contains("IF NOT EXISTS"));
        let all = format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
            queries.create_header,
            queries.create_fragment,
            queries.create_committed,
            queries.read_header,
            queries.read_fragments,
            queries.insert_header,
            queries.insert_fragment,
            queries.read_committed,
            queries.insert_committed,
            queries.scan_headers,
        );
        for forbidden in [" UPDATE ", " DELETE ", " TTL ", " TIMESTAMP "] {
            assert!(!all.contains(forbidden));
        }
        assert!(queries.scan_headers.contains("checkpoint_id > ? AND checkpoint_id <= ?"));
        assert!(queries.create_header.contains(
            "PRIMARY KEY ((network_chain_id, chain_epoch), checkpoint_id)"
        ));
    }

    #[test]
    fn production_api_does_not_expose_delete_or_head_mutation() {
        let source = include_str!("coordinator_commit_source_store.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(!source.contains("DELETE FROM"));
        assert!(!source.contains("compare_and_set_canonical_head"));
        assert!(!source.contains("global_archive_barrier"));
    }
}
