//! Point-reads one recorded row by its typed key, with each column's WRITETIME.
//!
//! Three later steps need exactly this and nothing more.  The verification
//! journal (design-r1 §2.2.2) reads a row before and after a commit touches it;
//! the archive (§2.3) stores "the full physical PK, the raw value, and each
//! column's own WRITETIME"; and the delete path has to locate the same row it
//! recorded.  Building it once means the journal exercises the reader before the
//! archive depends on it.
//!
//! ## Why this matches on the typed key
//!
//! A locator decodes back to a `ResolvedScyllaKey`, which already carries the
//! primary-key field values in canonical order -- so a reader could bind them
//! positionally by schema family in seven arms instead of thirty-nine.  It does
//! not, because that mapping would then exist twice: once where the key is built
//! and once here, free to drift apart silently.  Matching the typed key makes the
//! compiler enumerate every domain, and a table that is not on the recorded
//! commit path has to say so out loud.
//!
//! ## The codec is production's, never a copy
//!
//! design-r1 §2.2.2 requires the journal to reuse the production key codec,
//! because a verification layer that encodes keys its own way verifies itself.
//! That is not a formality here.  The two blob-keyed halves of the checkpoint
//! root mapping store their primary key as `psy_ser_to_bytes_vec()` of the typed
//! value, and the two halves disagree about what that means: `_k1` holds a hash's
//! raw 32 bytes, while `_k2` holds a `u64` **little-endian** -- whereas the
//! locator encodes the very same `u64` big-endian.  A reader that assumed either
//! byte order would read a key that does not exist and report the row missing,
//! which in a journal reads as "this row was born here" and in an archive reads
//! as "nothing to save".  Both failures are silent.  So the conversion goes
//! through the same serializer the writer used.

use std::collections::HashMap;
use std::sync::Arc;

use psy_node_core::store::typed::TypedTableKey;
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
use scylla::client::session::Session;
use scylla::statement::prepared::PreparedStatement;
use scylla::value::CqlValue;

use strum::IntoEnumIterator;

use super::{ResolvedScyllaKey, ScyllaPhysicalTableId, physical_descriptor};

/// One regular column of a row, as stored.
///
/// `value` is `None` for a null column, which is distinct from an absent row --
/// the journal has to tell "this key was born at this checkpoint" from "this key
/// existed with a null column".
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RowColumn {
    pub name: &'static str,
    pub value: Option<Vec<u8>>,
    /// The cell's write timestamp, which the archive stores per column and the
    /// delete fence must dominate.  `None` where CQL cannot report one: a row
    /// whose columns are all primary key has no cell to ask about.
    pub write_time_us: Option<i64>,
}

/// Every regular column of one row, in schema order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RowImage {
    columns: Vec<RowColumn>,
}

impl RowImage {
    pub fn columns(&self) -> &[RowColumn] {
        &self.columns
    }

    /// True when the row exists but carries no regular column at all.
    ///
    /// `public_key_hash_to_user_ids_table` is entirely primary key, so its rows
    /// are presence and nothing else.  A journal comparing images must treat
    /// this as a real state rather than as an empty read.
    pub fn is_key_only(&self) -> bool {
        self.columns.is_empty()
    }

    /// A canonical encoding for byte-exact comparison.
    ///
    /// The journal's assertion is `live(K) == journal[c(K)].before` compared byte
    /// for byte, so the encoding has to distinguish a null column from an empty
    /// one and preserve column order.  WRITETIME is deliberately excluded: a
    /// restored row is the same row even though it was written later, and
    /// including the timestamp would make every comparison fail.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + self.columns.len() * 24);
        out.extend_from_slice(b"PSYROW01");
        out.push(self.columns.len() as u8);
        for column in &self.columns {
            match &column.value {
                None => out.push(0),
                Some(bytes) => {
                    out.push(1);
                    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                    out.extend_from_slice(bytes);
                }
            }
        }
        out
    }
}

/// How a physical table's regular columns are read back.
struct TableRead {
    prepared: PreparedStatement,
    columns: &'static [(&'static str, ColumnKind)],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ColumnKind {
    Blob,
    BigInt,
}

/// The regular columns of one recorded table.
///
/// Only the regular columns live here.  The primary key comes from the registry
/// (`cql_primary_key()`), which already declares partition and clustering columns
/// per schema family -- copying them into a second list here is precisely the
/// kind of duplicate that drifts, and the drift would be silent: a stale column
/// name reads a row that does not exist and reports it absent.
struct TableShape {
    value_columns: &'static [(&'static str, ColumnKind)],
}

/// The primary-key column names of a table, partition first, in CQL order.
///
/// The registry declares them as `"name TYPE"` (with a clustering direction
/// suffix), so the name is the leading token.
fn key_column_names(table: ScyllaPhysicalTableId) -> Vec<&'static str> {
    let shape = physical_descriptor(table).cql_primary_key();
    shape
        .partition
        .iter()
        .chain(shape.clustering.iter())
        .map(|declaration| {
            declaration
                .split_whitespace()
                .next()
                .expect("a declared key column has a name")
        })
        .collect()
}

const BLOB_VALUE: &[(&str, ColumnKind)] = &[("value", ColumnKind::Blob)];
const BIGINT_VALUE: &[(&str, ColumnKind)] = &[("value", ColumnKind::BigInt)];
const NO_VALUE: &[(&str, ColumnKind)] = &[];

/// Every table the Coordinator commit path records, and nothing else.
///
/// Exhaustive over `ScyllaPhysicalTableId`: a table added to the recorded set
/// without a shape here fails to compile rather than failing to be read.
fn table_shape(table: ScyllaPhysicalTableId) -> Option<TableShape> {
    use ScyllaPhysicalTableId as P;
    let shape = match table {
        // Key/id/value: one bigint key, one blob value.
        P::CheckpointLeaf | P::L2BlockState | P::CheckpointStateRoots
        | P::CheckpointZkProofAndTransition | P::LatestInfo => TableShape {
            value_columns: BLOB_VALUE,
        },
        // The content-keyed and height-keyed halves of the root mapping.  Both
        // store the primary key as a blob; see the module note on their codecs.
        P::CheckpointRootToCheckpointIdK1 | P::CheckpointRootToCheckpointIdK2 => TableShape {
            value_columns: BLOB_VALUE,
        },
        // Bigint to bigint.
        P::U64Singleton | P::CheckpointIdToPendingId | P::PendingIdToCheckpointId => TableShape {
            value_columns: BIGINT_VALUE,
        },
        // Versioned objects: the checkpoint is a clustering column.
        P::ContractLeaf | P::UserPublicKey | P::ContractCodeDefinition
        | P::ContractStateTreeHeight | P::RealmRewardsTreeNodeKey => TableShape {
            value_columns: BLOB_VALUE,
        },
        // Merkle trees partitioned by level.
        P::GlobalUserTree | P::GlobalContractTree | P::GlobalCheckpointTree
        | P::UserRegistrationTree => TableShape {
            value_columns: BLOB_VALUE,
        },
        // Merkle trees partitioned by tree id.
        P::ContractFunctionTree => TableShape {
            value_columns: BLOB_VALUE,
        },
        // Entirely primary key: the row is its own content.
        P::PublicKeyHashToUserIds => TableShape {
            value_columns: NO_VALUE,
        },
        _ => return None,
    };
    Some(shape)
}

/// Reads recorded rows back by typed key.
pub struct ScyllaRowImageReader {
    session: Arc<Session>,
    reads: HashMap<ScyllaPhysicalTableId, TableRead>,
}

#[derive(Debug)]
pub enum RowImageError {
    /// The key names a table the Coordinator commit path does not record, so
    /// there is no shape to read it with.  Failing here rather than returning
    /// "absent" keeps a journal from recording a row as newly born.
    UnrecordedTable(ScyllaPhysicalTableId),
    /// The primary key could not be re-encoded with the production codec.
    KeyCodec(String),
}

impl std::fmt::Display for RowImageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnrecordedTable(table) => write!(
                f,
                "physical table {table:?} is not on the recorded commit path, so it has no \
                 read shape; reading it would report a row that exists as absent"
            ),
            Self::KeyCodec(detail) => write!(f, "primary key could not be encoded: {detail}"),
        }
    }
}

impl std::error::Error for RowImageError {}

impl ScyllaRowImageReader {
    /// Prepare a point read for every recorded table.
    pub async fn prepare(session: Arc<Session>, keyspace: &str) -> anyhow::Result<Self> {
        let mut reads = HashMap::new();
        for table in ScyllaPhysicalTableId::iter() {
            let Some(shape) = table_shape(table) else {
                continue;
            };
            let name = physical_descriptor(table).physical_name;
            let key_columns = key_column_names(table);
            let selected = if shape.value_columns.is_empty() {
                // Nothing to project but the row's own existence.  Selecting a
                // key column is the only way to ask "is it there".
                key_columns[0].to_string()
            } else {
                shape
                    .value_columns
                    .iter()
                    .map(|(column, _)| format!("{column}, WRITETIME({column})"))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let predicate = key_columns
                .iter()
                .map(|column| format!("{column} = ?"))
                .collect::<Vec<_>>()
                .join(" AND ");
            let cql = format!("SELECT {selected} FROM {keyspace}.{name} WHERE {predicate}");
            reads.insert(
                table,
                TableRead {
                    prepared: session.prepare(cql).await?,
                    columns: shape.value_columns,
                },
            );
        }
        Ok(Self { session, reads })
    }

    /// Read one row, or `None` when it does not exist.
    pub async fn read(&self, key: &ResolvedScyllaKey) -> anyhow::Result<Option<RowImage>> {
        let table = key.physical_table();
        let read = self
            .reads
            .get(&table)
            .ok_or(RowImageError::UnrecordedTable(table))?;
        let values = cql_key_values(key.typed_key())?;
        let rows = self
            .session
            .execute_unpaged(&read.prepared, values)
            .await?
            .into_rows_result()?;

        if read.columns.is_empty() {
            // Key-only table: presence is the whole image.
            return Ok(rows
                .rows::<(Option<Vec<u8>>,)>()?
                .next()
                .transpose()?
                .map(|_| RowImage { columns: Vec::new() }));
        }

        // One (value, WRITETIME) pair per regular column, in schema order.
        let mut iter = rows.rows::<(Option<CqlValue>, Option<i64>)>()?;
        let Some(row) = iter.next().transpose()? else {
            return Ok(None);
        };
        let (raw, write_time_us) = row;
        let (name, kind) = read.columns[0];
        Ok(Some(RowImage {
            columns: vec![RowColumn {
                name,
                value: raw.map(|value| encode_cell(value, kind)),
                write_time_us,
            }],
        }))
    }
}

fn encode_cell(value: CqlValue, kind: ColumnKind) -> Vec<u8> {
    match (value, kind) {
        (CqlValue::Blob(bytes), ColumnKind::Blob) => bytes,
        (CqlValue::BigInt(number), ColumnKind::BigInt) => number.to_be_bytes().to_vec(),
        // The shape table and the schema disagree.  Encoding the debug form keeps
        // the comparison honest -- it will differ from any correctly typed image
        // rather than silently matching.
        (other, _) => format!("{other:?}").into_bytes(),
    }
}

/// The CQL primary-key values for one typed key, in column order.
///
/// Exhaustive on purpose: a new key domain must state how it is read, and a
/// domain the Coordinator does not record must say so rather than fall through.
fn cql_key_values(key: &TypedTableKey) -> Result<Vec<CqlValue>, RowImageError> {
    use TypedTableKey as K;
    let values = match key {
        K::CheckpointLeaf(checkpoint)
        | K::L2BlockState(checkpoint)
        | K::CheckpointStateRoots(checkpoint)
        | K::CheckpointZkProof(checkpoint)
        | K::CheckpointToPending(checkpoint) => {
            vec![CqlValue::BigInt(checkpoint.get() as i64)]
        }
        K::PendingToCheckpoint(pending) => vec![CqlValue::BigInt(pending.get() as i64)],
        K::LatestInfo(slot) => vec![CqlValue::BigInt(*slot as u8 as i64)],
        K::U64Singleton(slot) => vec![CqlValue::BigInt(*slot as u8 as i64)],
        // Blob-keyed halves of the root mapping.  The hash arrives as the bytes
        // the writer stored; the checkpoint has to go back through the writer's
        // own serializer, which is little-endian and not the locator's order.
        K::CheckpointRootByHash(root) => vec![CqlValue::Blob(root.as_bytes().to_vec())],
        K::CheckpointRootByCheckpoint(checkpoint) => {
            let encoded = checkpoint
                .get()
                .psy_ser_to_bytes_vec()
                .map_err(|error| RowImageError::KeyCodec(error.to_string()))?;
            vec![CqlValue::Blob(encoded)]
        }
        K::ContractLeaf { contract, checkpoint }
        | K::ContractCodeDefinition { contract, checkpoint }
        | K::ContractStateTreeHeight { contract, checkpoint } => vec![
            CqlValue::BigInt(contract.get() as i64),
            CqlValue::BigInt(checkpoint.get() as i64),
        ],
        K::UserPublicKey { user, checkpoint } => vec![
            CqlValue::BigInt(user.get() as i64),
            CqlValue::BigInt(checkpoint.get() as i64),
        ],
        K::RealmRewardNode { realm, pending } => vec![
            CqlValue::BigInt(realm.get() as i64),
            CqlValue::BigInt(pending.get() as i64),
        ],
        K::GlobalUserMerkle { node, checkpoint }
        | K::GlobalCheckpointMerkle { node, checkpoint }
        | K::UserRegistrationMerkle { node, checkpoint }
        | K::GlobalContractMerkle { node, checkpoint } => vec![
            CqlValue::TinyInt(node.level() as i8),
            CqlValue::BigInt(node.index().get() as i64),
            CqlValue::BigInt(checkpoint.get() as i64),
        ],
        K::ContractFunctionMerkle { contract, node, checkpoint } => vec![
            CqlValue::BigInt(contract.get() as i64),
            CqlValue::TinyInt(node.level() as i8),
            CqlValue::BigInt(node.index().get() as i64),
            CqlValue::BigInt(checkpoint.get() as i64),
        ],
        K::PublicKeyToUser { public_key_hash, user } => vec![
            CqlValue::Blob(public_key_hash.as_bytes().to_vec()),
            CqlValue::BigInt(user.get() as i64),
        ],
        // Not written by the Coordinator commit path, so never recorded and
        // never read here.  Slice B and the IMT work will each add their own.
        K::CheckpointLeafByHash(_)
        | K::CheckpointLeafByCheckpoint(_)
        | K::UnusedCheckpointRealmRoot(_)
        | K::CheckpointedObject(_)
        | K::UserLeaf { .. }
        | K::U64Counter(_)
        | K::PendingToProc(_)
        | K::ProcToPending(_)
        | K::UserContractMerkle { .. }
        | K::ContractStateMerkle { .. }
        | K::RewardTagMerkle { .. }
        | K::ImtLeaf { .. }
        | K::ImtKeyIndex { .. }
        | K::ImtCursor { .. } => {
            return Err(RowImageError::UnrecordedTable(
                super::describe_existing_key(key).physical_table(),
            ));
        }
    };
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_null_column_and_an_empty_column_encode_differently() {
        // The journal compares images byte for byte, so conflating these would
        // let a cleared value pass as an absent one.
        let null = RowImage {
            columns: vec![RowColumn { name: "value", value: None, write_time_us: Some(1) }],
        };
        let empty = RowImage {
            columns: vec![RowColumn {
                name: "value",
                value: Some(Vec::new()),
                write_time_us: Some(1),
            }],
        };
        assert_ne!(null.canonical_bytes(), empty.canonical_bytes());
    }

    #[test]
    fn the_write_time_is_not_part_of_the_image() {
        // A restored row is the same row even though it was written later.
        let early = RowImage {
            columns: vec![RowColumn {
                name: "value",
                value: Some(vec![7, 7]),
                write_time_us: Some(100),
            }],
        };
        let late = RowImage {
            columns: vec![RowColumn {
                name: "value",
                value: Some(vec![7, 7]),
                write_time_us: Some(900_000),
            }],
        };
        assert_eq!(early.canonical_bytes(), late.canonical_bytes());
    }

    #[test]
    fn a_key_only_row_is_a_state_not_an_absence() {
        let present = RowImage { columns: Vec::new() };
        assert!(present.is_key_only());
        // It still encodes to something, so `Some(image)` and `None` stay
        // distinguishable for a table whose rows are pure primary key.
        assert!(!present.canonical_bytes().is_empty());
    }

    /// One representative typed key per recorded table.
    fn recorded_samples() -> Vec<TypedTableKey> {
        use psy_node_core::store::typed::*;
        let checkpoint = CheckpointId::try_new(11).unwrap();
        let pending = UniquePendingId::try_new(12).unwrap();
        let node = MerkleNode::new(3, NodeIndex::new(9));
        vec![
            TypedTableKey::CheckpointLeaf(checkpoint),
            TypedTableKey::L2BlockState(checkpoint),
            TypedTableKey::CheckpointStateRoots(checkpoint),
            TypedTableKey::CheckpointZkProof(checkpoint),
            TypedTableKey::LatestInfo(LatestInfoSlot::LatestL2BlockState),
            TypedTableKey::CheckpointRootByHash(CheckpointRootKey::new(vec![0xab; 32])),
            TypedTableKey::CheckpointRootByCheckpoint(checkpoint),
            TypedTableKey::U64Singleton(U64SingletonSlot::LatestCheckpoint),
            TypedTableKey::CheckpointToPending(checkpoint),
            TypedTableKey::PendingToCheckpoint(pending),
            TypedTableKey::ContractLeaf { contract: ContractId::new(4), checkpoint },
            TypedTableKey::UserPublicKey { user: UserId::new(5), checkpoint },
            TypedTableKey::ContractCodeDefinition { contract: ContractId::new(4), checkpoint },
            TypedTableKey::ContractStateTreeHeight { contract: ContractId::new(4), checkpoint },
            TypedTableKey::RealmRewardNode { realm: RealmId::new(0), pending },
            TypedTableKey::GlobalUserMerkle { node, checkpoint },
            TypedTableKey::GlobalContractMerkle { node, checkpoint },
            TypedTableKey::GlobalCheckpointMerkle { node, checkpoint },
            TypedTableKey::UserRegistrationMerkle { node, checkpoint },
            TypedTableKey::ContractFunctionMerkle { contract: ContractId::new(4), node, checkpoint },
            TypedTableKey::PublicKeyToUser {
                public_key_hash: PublicKeyHash::new(vec![7; 33]),
                user: UserId::new(5),
            },
        ]
    }

    #[test]
    fn a_bound_key_has_exactly_the_registry_declared_columns() {
        // The reader builds its WHERE clause from the registry's column list and
        // binds values from the typed key.  If those two disagree in length the
        // statement will not even prepare; if they disagree in *order* it will
        // prepare and read the wrong row, so the count is the cheap half of the
        // check and the round-trip test against a real Scylla is the other half.
        for key in recorded_samples() {
            let resolved = super::super::describe_existing_key(&key);
            let bound = cql_key_values(&key).expect("a recorded key must bind");
            let declared = key_column_names(resolved.physical_table());
            assert_eq!(
                bound.len(),
                declared.len(),
                "{:?} binds {} values for {} declared key columns {declared:?}",
                resolved.physical_table(),
                bound.len(),
                declared.len()
            );
        }
    }

    #[test]
    fn a_key_the_commit_path_never_records_is_refused() {
        // Returning "absent" for these would read, in a journal, as "this row was
        // born at this checkpoint" -- inventing history rather than reporting a
        // gap.
        let key = TypedTableKey::ImtCursor {
            tree: psy_node_core::store::typed::TreeId::new(1),
            tree_sub: psy_node_core::store::typed::TreeSubId::new(2),
        };
        assert!(matches!(
            cql_key_values(&key),
            Err(RowImageError::UnrecordedTable(_))
        ));
    }

    #[test]
    fn every_recorded_table_has_a_read_shape() {
        // The planner records these; a missing shape would make the journal
        // report their rows as newly born and the archive save nothing.
        use ScyllaPhysicalTableId as P;
        for table in [
            P::CheckpointLeaf, P::L2BlockState, P::CheckpointStateRoots,
            P::CheckpointZkProofAndTransition, P::LatestInfo,
            P::CheckpointRootToCheckpointIdK1, P::CheckpointRootToCheckpointIdK2,
            P::U64Singleton, P::CheckpointIdToPendingId, P::PendingIdToCheckpointId,
            P::ContractLeaf, P::UserPublicKey, P::ContractCodeDefinition,
            P::ContractStateTreeHeight, P::RealmRewardsTreeNodeKey,
            P::GlobalUserTree, P::GlobalContractTree, P::GlobalCheckpointTree,
            P::UserRegistrationTree, P::ContractFunctionTree, P::PublicKeyHashToUserIds,
        ] {
            assert!(
                table_shape(table).is_some(),
                "{table:?} is recorded by the commit planner but has no read shape"
            );
        }
    }
}
