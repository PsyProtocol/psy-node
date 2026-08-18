//! Canonical encoding for the locator chunks a manifest commits to.
//!
//! A locator record is the whole answer to "which physical row did this commit
//! write".  design-r1 §2.2.1 explains why that is keys only: on a version-axis
//! table the target's value is still in the table, so deleting the discarded
//! version restores it, and values would be a copy of data the database already
//! holds.
//!
//! The commit write timestamp is deliberately absent from each record.  D4 gives
//! one commit exactly one timestamp, carried once on the manifest itself;
//! repeating it per record would add 8 bytes to each of the ~20k rows a busy
//! Realm commit touches.

use std::{error::Error, fmt};

use super::{ScyllaPhysicalTableId, UnknownScyllaPhysicalTableId, decode_locator_canonical};

pub const MUTATION_LOCATOR_CHUNK_MAGIC: [u8; 8] = *b"PSYMLOC1";
pub const MUTATION_LOCATOR_CHUNK_CODEC_VERSION: u16 = 1;

/// Chunk payload cap, matching the commit source fragment size so both use one
/// Scylla value-size budget.
pub const MUTATION_LOCATOR_CHUNK_BYTES: usize = 4 * 1024 * 1024;

const HEADER_LEN: usize = 8 + 2 + 4;
const RECORD_FIXED_LEN: usize = 2 + 1 + 4;

/// What the commit did to one physical row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RecordedOperation {
    Put = 1,
    Delete = 2,
}

impl TryFrom<u8> for RecordedOperation {
    type Error = UnknownRecordedOperation;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Put),
            2 => Ok(Self::Delete),
            other => Err(UnknownRecordedOperation(other)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnknownRecordedOperation(pub u8);

impl fmt::Display for UnknownRecordedOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown recorded operation {}", self.0)
    }
}

impl Error for UnknownRecordedOperation {}

/// One physical row a commit touched.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationLocatorRecord {
    physical_table: ScyllaPhysicalTableId,
    operation: RecordedOperation,
    locator_bytes: Vec<u8>,
}

impl MutationLocatorRecord {
    /// The locator must round-trip through the typed registry before it is
    /// recorded.  A locator that cannot be resolved back to a key is useless to
    /// rollback, and discovering that at delete time is far too late.
    pub fn try_new(
        physical_table: ScyllaPhysicalTableId,
        operation: RecordedOperation,
        locator_bytes: Vec<u8>,
    ) -> Result<Self, MutationLocatorError> {
        if locator_bytes.is_empty() {
            return Err(MutationLocatorError::EmptyLocator);
        }
        let resolved = decode_locator_canonical(&locator_bytes)
            .map_err(|reason| MutationLocatorError::UnresolvableLocator {
                physical_table,
                reason,
            })?;
        if resolved.physical_table() != physical_table {
            return Err(MutationLocatorError::LocatorTableMismatch {
                declared: physical_table,
                encoded: resolved.physical_table(),
            });
        }
        Ok(Self {
            physical_table,
            operation,
            locator_bytes,
        })
    }

    pub const fn physical_table(&self) -> ScyllaPhysicalTableId {
        self.physical_table
    }

    pub const fn operation(&self) -> RecordedOperation {
        self.operation
    }

    pub fn locator_bytes(&self) -> &[u8] {
        &self.locator_bytes
    }

    fn encoded_len(&self) -> usize {
        RECORD_FIXED_LEN + self.locator_bytes.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MutationLocatorError {
    EmptyLocator,
    UnresolvableLocator {
        physical_table: ScyllaPhysicalTableId,
        reason: &'static str,
    },
    LocatorTableMismatch {
        declared: ScyllaPhysicalTableId,
        encoded: ScyllaPhysicalTableId,
    },
    /// One record cannot fit a chunk on its own, so no split can help.
    RecordExceedsChunk {
        encoded_len: usize,
    },
    InvalidChunkMagic,
    UnknownChunkVersion(u16),
    TruncatedChunk,
    TrailingChunkBytes,
    UnknownPhysicalTable(UnknownScyllaPhysicalTableId),
    UnknownOperation(UnknownRecordedOperation),
}

impl From<UnknownScyllaPhysicalTableId> for MutationLocatorError {
    fn from(error: UnknownScyllaPhysicalTableId) -> Self {
        Self::UnknownPhysicalTable(error)
    }
}

impl From<UnknownRecordedOperation> for MutationLocatorError {
    fn from(error: UnknownRecordedOperation) -> Self {
        Self::UnknownOperation(error)
    }
}

impl fmt::Display for MutationLocatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for MutationLocatorError {}

/// Split records into canonical chunks, each at most
/// `MUTATION_LOCATOR_CHUNK_BYTES`.
///
/// Chunk boundaries carry no meaning: a record never straddles two chunks, so a
/// chunk decodes on its own and a missing chunk is detectable as a gap rather
/// than as a silently shorter mutation set.
pub fn encode_locator_chunks(
    records: &[MutationLocatorRecord],
) -> Result<Vec<Vec<u8>>, MutationLocatorError> {
    encode_locator_chunks_with_limit(records, MUTATION_LOCATOR_CHUNK_BYTES)
}

/// Same, with an explicit cap.
///
/// Exposed so the split path can be exercised for real.  With the production
/// 4 MiB cap a test would need hundreds of thousands of records to reach a
/// second chunk, and a "splitting" test that never splits proves nothing.
pub fn encode_locator_chunks_with_limit(
    records: &[MutationLocatorRecord],
    chunk_bytes: usize,
) -> Result<Vec<Vec<u8>>, MutationLocatorError> {
    let mut chunks = Vec::new();
    let mut current: Vec<&MutationLocatorRecord> = Vec::new();
    let mut current_len = HEADER_LEN;
    for record in records {
        let encoded_len = record.encoded_len();
        if HEADER_LEN + encoded_len > chunk_bytes {
            return Err(MutationLocatorError::RecordExceedsChunk { encoded_len });
        }
        if current_len + encoded_len > chunk_bytes {
            chunks.push(encode_one_chunk(&current));
            current.clear();
            current_len = HEADER_LEN;
        }
        current_len += encoded_len;
        current.push(record);
    }
    // An empty mutation set still gets one chunk: "this commit wrote nothing"
    // is a fact rollback needs, and an absent chunk is indistinguishable from a
    // lost one.
    if !current.is_empty() || chunks.is_empty() {
        chunks.push(encode_one_chunk(&current));
    }
    Ok(chunks)
}

fn encode_one_chunk(records: &[&MutationLocatorRecord]) -> Vec<u8> {
    let capacity = HEADER_LEN + records.iter().map(|r| r.encoded_len()).sum::<usize>();
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(&MUTATION_LOCATOR_CHUNK_MAGIC);
    out.extend_from_slice(&MUTATION_LOCATOR_CHUNK_CODEC_VERSION.to_be_bytes());
    out.extend_from_slice(&(records.len() as u32).to_be_bytes());
    for record in records {
        out.extend_from_slice(&(record.physical_table as u16).to_be_bytes());
        out.push(record.operation as u8);
        out.extend_from_slice(&(record.locator_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&record.locator_bytes);
    }
    out
}

pub fn decode_locator_chunk(
    bytes: &[u8],
) -> Result<Vec<MutationLocatorRecord>, MutationLocatorError> {
    if bytes.len() < HEADER_LEN {
        return Err(MutationLocatorError::TruncatedChunk);
    }
    if bytes[..8] != MUTATION_LOCATOR_CHUNK_MAGIC {
        return Err(MutationLocatorError::InvalidChunkMagic);
    }
    let version = u16::from_be_bytes([bytes[8], bytes[9]]);
    if version != MUTATION_LOCATOR_CHUNK_CODEC_VERSION {
        return Err(MutationLocatorError::UnknownChunkVersion(version));
    }
    let count = u32::from_be_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]) as usize;
    let mut cursor = HEADER_LEN;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if cursor + RECORD_FIXED_LEN > bytes.len() {
            return Err(MutationLocatorError::TruncatedChunk);
        }
        let table = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]);
        let operation = RecordedOperation::try_from(bytes[cursor + 2])?;
        let locator_len = u32::from_be_bytes([
            bytes[cursor + 3],
            bytes[cursor + 4],
            bytes[cursor + 5],
            bytes[cursor + 6],
        ]) as usize;
        cursor += RECORD_FIXED_LEN;
        let end = cursor
            .checked_add(locator_len)
            .ok_or(MutationLocatorError::TruncatedChunk)?;
        if end > bytes.len() {
            return Err(MutationLocatorError::TruncatedChunk);
        }
        out.push(MutationLocatorRecord::try_new(
            ScyllaPhysicalTableId::try_from(table)?,
            operation,
            bytes[cursor..end].to_vec(),
        )?);
        cursor = end;
    }
    if cursor != bytes.len() {
        return Err(MutationLocatorError::TrailingChunkBytes);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rollback::describe_existing_key;
    use psy_node_core::store::typed::{CheckpointId, TypedTableKey};

    fn record(checkpoint: u64, operation: RecordedOperation) -> MutationLocatorRecord {
        let key = TypedTableKey::CheckpointLeaf(CheckpointId::try_new(checkpoint).unwrap());
        let resolved = describe_existing_key(&key);
        MutationLocatorRecord::try_new(
            resolved.physical_table(),
            operation,
            resolved.locator_bytes().to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn planning_carries_every_row_the_manifest_names() {
        // Including the pending mappings.  Leaving those out was tried and made
        // the Coordinator fail G-W on ten keys the discarded range created; see
        // the open problem on `plan_rows_from_chunks`.
        let pending = psy_node_core::store::typed::UniquePendingId::try_new(615).unwrap();
        let rows = vec![
            from_key(TypedTableKey::PendingToProc(pending)),
            from_key(TypedTableKey::PendingToCheckpoint(pending)),
            from_key(TypedTableKey::CheckpointToPending(
                CheckpointId::try_new(296).unwrap(),
            )),
            record(7, RecordedOperation::Put),
        ];
        let chunks = encode_locator_chunks(&rows).unwrap();
        assert_eq!(plan_rows_from_chunks(&chunks).unwrap().len(), rows.len());
    }

    fn from_key(key: TypedTableKey) -> MutationLocatorRecord {
        let resolved = describe_existing_key(&key);
        MutationLocatorRecord::try_new(
            resolved.physical_table(),
            RecordedOperation::Put,
            resolved.locator_bytes().to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn records_round_trip_through_a_chunk() {
        let records = vec![
            record(1, RecordedOperation::Put),
            record(2, RecordedOperation::Delete),
            record(3, RecordedOperation::Put),
        ];
        let chunks = encode_locator_chunks(&records).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(decode_locator_chunk(&chunks[0]).unwrap(), records);
    }

    #[test]
    fn an_empty_commit_still_produces_one_chunk() {
        // "this commit wrote nothing" is a fact rollback needs; an absent chunk
        // is indistinguishable from a lost one.
        let chunks = encode_locator_chunks(&[]).unwrap();
        assert_eq!(chunks.len(), 1);
        assert!(decode_locator_chunk(&chunks[0]).unwrap().is_empty());
    }

    #[test]
    fn a_locator_that_does_not_resolve_is_rejected_at_record_time() {
        assert_eq!(
            MutationLocatorRecord::try_new(
                ScyllaPhysicalTableId::CheckpointLeaf,
                RecordedOperation::Put,
                Vec::new(),
            ),
            Err(MutationLocatorError::EmptyLocator),
        );
        assert!(matches!(
            MutationLocatorRecord::try_new(
                ScyllaPhysicalTableId::CheckpointLeaf,
                RecordedOperation::Put,
                vec![0xff; 12],
            ),
            Err(MutationLocatorError::UnresolvableLocator { .. }),
        ));
    }

    #[test]
    fn a_locator_whose_table_disagrees_with_its_declaration_is_rejected() {
        let resolved = describe_existing_key(&TypedTableKey::CheckpointLeaf(
            CheckpointId::try_new(9).unwrap(),
        ));
        assert!(matches!(
            MutationLocatorRecord::try_new(
                ScyllaPhysicalTableId::L2BlockState,
                RecordedOperation::Put,
                resolved.locator_bytes().to_vec(),
            ),
            Err(MutationLocatorError::LocatorTableMismatch { .. }),
        ));
    }

    #[test]
    fn a_truncated_or_extended_chunk_fails_closed() {
        let chunks = encode_locator_chunks(&[record(4, RecordedOperation::Put)]).unwrap();
        let chunk = &chunks[0];
        for cut in 1..chunk.len() {
            assert!(
                decode_locator_chunk(&chunk[..cut]).is_err(),
                "prefix of {cut} bytes must not decode"
            );
        }
        let mut extended = chunk.clone();
        extended.push(0);
        assert_eq!(
            decode_locator_chunk(&extended),
            Err(MutationLocatorError::TrailingChunkBytes),
        );
    }

    #[test]
    fn a_wrong_magic_or_version_fails_closed() {
        let chunks = encode_locator_chunks(&[record(5, RecordedOperation::Put)]).unwrap();
        let mut wrong_magic = chunks[0].clone();
        wrong_magic[0] ^= 0xff;
        assert_eq!(
            decode_locator_chunk(&wrong_magic),
            Err(MutationLocatorError::InvalidChunkMagic),
        );
        let mut wrong_version = chunks[0].clone();
        wrong_version[9] = 9;
        assert_eq!(
            decode_locator_chunk(&wrong_version),
            Err(MutationLocatorError::UnknownChunkVersion(9)),
        );
    }

    #[test]
    fn records_are_split_without_straddling_a_chunk_boundary() {
        let records: Vec<_> = (1..=200)
            .map(|checkpoint| record(checkpoint, RecordedOperation::Put))
            .collect();
        // A cap just above one record forces a split at almost every record, so
        // the boundary logic is actually exercised rather than skipped.
        let limit = HEADER_LEN + records[0].encoded_len() * 3;
        let chunks = encode_locator_chunks_with_limit(&records, limit).unwrap();
        assert!(
            chunks.len() > 1,
            "the split path must run; got {} chunk(s)",
            chunks.len()
        );
        let mut rebuilt = Vec::new();
        for chunk in &chunks {
            assert!(chunk.len() <= limit);
            // Every chunk decodes on its own, so a missing chunk shows up as a
            // gap rather than as a silently shorter mutation set.
            rebuilt.extend(decode_locator_chunk(chunk).unwrap());
        }
        assert_eq!(rebuilt, records);
    }

    #[test]
    fn a_record_larger_than_the_cap_is_rejected_rather_than_split() {
        let records = vec![record(6, RecordedOperation::Put)];
        assert!(matches!(
            encode_locator_chunks_with_limit(&records, HEADER_LEN + 1),
            Err(MutationLocatorError::RecordExceedsChunk { .. })
        ));
    }

    #[test]
    fn the_production_cap_holds_a_realistic_realm_commit_in_few_chunks() {
        // design-r1 §2.2.1 sizes a busy Realm commit at roughly 20k rows.
        let records: Vec<_> = (1..=20_000)
            .map(|checkpoint| record(checkpoint, RecordedOperation::Put))
            .collect();
        let chunks = encode_locator_chunks(&records).unwrap();
        assert_eq!(chunks.len(), 1, "20k locators must not need chunking");
        assert!(chunks[0].len() < 1024 * 1024, "expected well under 1 MiB");
    }
}

/// Turn manifest locator chunks into the rows a rollback plan will act on.
///
/// One function for both authorities, so the Coordinator and a Realm cannot
/// drift into planning different things from the same manifest.
///
/// # An open problem this does not solve
///
/// Every row the manifest names is planned for deletion.  For a table with a
/// version axis that is exactly right: deleting the discarded version leaves
/// the earlier one, and a read at the target finds it.  For a table without
/// one, deletion is right only when the discarded commit **created** the row.
/// When it **rewrote** an existing row, deleting destroys the only copy and the
/// earlier value is gone with it.
///
/// This is not hypothetical.  A Realm rollback on the local testnet deleted
/// `pending_id_to_pending_proc_id_table_u64_to_u128` at pending id 615, a row
/// the discarded commit had rewritten rather than created; G-W failed on
/// exactly that one key out of 160.  The Coordinator never sees it because it
/// writes each pending mapping once -- the same shape as every other Realm
/// defect this work has turned up, where a property that always holds on the
/// Coordinator was taken for universal.
///
/// Excluding those tables is **not** the fix: it was tried, and the Coordinator
/// then failed G-W on ten keys the discarded range had *created*, which must be
/// deleted for "a hot read after a rollback sees only T" to hold.  Created and
/// rewritten need opposite treatment, and the manifest records neither -- it
/// names the locator and the operation, not whether anything was there before.
///
/// Resolving it means the archive carrying the before-image for axis-less
/// tables, so RESTORING can put back what a rewrite overwrote.  That is a
/// design change rather than a patch, and it is recorded here rather than
/// papered over.
pub fn plan_rows_from_chunks(
    chunks: &[Vec<u8>],
) -> Result<Vec<(u16, Vec<u8>)>, MutationLocatorError> {
    let mut rows = Vec::new();
    for chunk in chunks {
        for record in decode_locator_chunk(chunk)? {
            rows.push((
                record.physical_table().stable_id(),
                record.locator_bytes().to_vec(),
            ));
        }
    }
    Ok(rows)
}
