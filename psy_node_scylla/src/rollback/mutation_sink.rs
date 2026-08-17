//! Where a table adapter hands over the rows it is about to write.
//!
//! design-r1 §2.1 requires executing a batch and producing its manifest to be
//! one action.  A caller cannot enumerate what a commit writes: the Merkle
//! writers take a fast-serialized blob and only the adapter, once it decodes
//! that blob, knows how many nodes there are and at which `(level, index)`.
//! Re-deriving that in the caller would duplicate adapter logic, and the only
//! thing that could police the duplication is a source-text assertion, which
//! design-r1 §11.5 forbids.
//!
//! So the adapter records.  It already materialises the exact row set before
//! issuing any write, and this is the seam where that set is captured.

use std::sync::Mutex;

use psy_node_core::store::typed::{
    CheckpointId, CheckpointLeafKey, CheckpointRootKey, ContractId, LatestInfoSlot, MerkleNode,
    NodeIndex, TypedTableKey, UniquePendingId, UserId,
};

use super::{
    MutationLocatorRecord, RecordedOperation, ScyllaPhysicalTableId, describe_existing_key,
    physical_descriptor,
};
use strum::IntoEnumIterator;

/// Resolve a physical table from the name an adapter carries.
///
/// Adapters are constructed with a keyspace and a table name, so this is how a
/// generic adapter -- one Rust type serving several physical tables -- learns
/// which table it is without a second source of truth.
pub fn physical_table_by_name(physical_name: &str) -> Option<ScyllaPhysicalTableId> {
    ScyllaPhysicalTableId::iter().find(|id| physical_descriptor(*id).physical_name == physical_name)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnsupportedZeroMerkleTable(pub ScyllaPhysicalTableId);

impl std::fmt::Display for UnsupportedZeroMerkleTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?} is not a zero-id Merkle table and has no node key",
            self.0
        )
    }
}

impl std::error::Error for UnsupportedZeroMerkleTable {}

/// Typed key for one node of a zero-id Merkle table.
///
/// `ScyllaMerkleNodesZeroPreparedStatements` serves four physical tables, and
/// each has its own key variant.  Mapping by physical id rather than by
/// position keeps a node from being recorded against a neighbouring tree, which
/// would delete the wrong rows on rollback while every digest still matched.
pub fn zero_merkle_node_key(
    physical: ScyllaPhysicalTableId,
    level: u8,
    node_index: u64,
    checkpoint: CheckpointId,
) -> Result<TypedTableKey, UnsupportedZeroMerkleTable> {
    let node = MerkleNode::new(level, NodeIndex::new(node_index));
    match physical {
        ScyllaPhysicalTableId::GlobalUserTree => Ok(TypedTableKey::GlobalUserMerkle {
            node,
            checkpoint,
        }),
        ScyllaPhysicalTableId::GlobalCheckpointTree => {
            Ok(TypedTableKey::GlobalCheckpointMerkle { node, checkpoint })
        }
        ScyllaPhysicalTableId::UserRegistrationTree => {
            Ok(TypedTableKey::UserRegistrationMerkle { node, checkpoint })
        }
        ScyllaPhysicalTableId::GlobalContractTree => {
            Ok(TypedTableKey::GlobalContractMerkle { node, checkpoint })
        }
        other => Err(UnsupportedZeroMerkleTable(other)),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnsupportedSingleMerkleTable(pub ScyllaPhysicalTableId);

impl std::fmt::Display for UnsupportedSingleMerkleTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?} is not a single-id Merkle table and has no node key",
            self.0
        )
    }
}

impl std::error::Error for UnsupportedSingleMerkleTable {}

/// Typed key for one node of a single-id Merkle table.
///
/// The partition id means different things per table -- a user for
/// `user_contract_tree`, a contract for `contract_function_tree` -- so it is
/// interpreted by physical table rather than carried as a bare number.
pub fn single_merkle_node_key(
    physical: ScyllaPhysicalTableId,
    tree_id: u64,
    level: u8,
    node_index: u64,
    checkpoint: CheckpointId,
) -> Result<TypedTableKey, UnsupportedSingleMerkleTable> {
    let node = MerkleNode::new(level, NodeIndex::new(node_index));
    match physical {
        ScyllaPhysicalTableId::UserContractTree => Ok(TypedTableKey::UserContractMerkle {
            user: UserId::new(tree_id),
            node,
            checkpoint,
        }),
        ScyllaPhysicalTableId::ContractFunctionTree => {
            Ok(TypedTableKey::ContractFunctionMerkle {
                contract: ContractId::new(tree_id),
                node,
                checkpoint,
            })
        }
        other => Err(UnsupportedSingleMerkleTable(other)),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsupportedVersionedObjectTable {
    /// Not a versioned single-id object table at all.
    NotAnObjectTable(ScyllaPhysicalTableId),
    /// `checkpointed_object_table` carries both a checkpoint and a pending axis
    /// in one clustering column, and `realm_rewards_tree_node_key_table` names
    /// its clustering column `checkpoint_id` while the value is a pending id
    /// (inventory §9 B2 and B3).  A generic `(obj_id, checkpoint)` key would be
    /// wrong for both, and wrong in a way nothing downstream could detect, so
    /// they are refused here until their axes are modelled explicitly.
    MixedAxisNeedsExplicitDomain(ScyllaPhysicalTableId),
}

impl std::fmt::Display for UnsupportedVersionedObjectTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAnObjectTable(id) => {
                write!(f, "{id:?} is not a versioned single-id object table")
            }
            Self::MixedAxisNeedsExplicitDomain(id) => write!(
                f,
                "{id:?} mixes checkpoint and pending axes and needs an explicit domain key"
            ),
        }
    }
}

impl std::error::Error for UnsupportedVersionedObjectTable {}

/// Typed key for one row of a versioned single-id object table.
///
/// `obj_id` means a different thing per table -- a user, a contract -- so it is
/// interpreted by physical table rather than carried as a bare number.
pub fn versioned_object_key(
    physical: ScyllaPhysicalTableId,
    obj_id: u64,
    checkpoint: CheckpointId,
) -> Result<TypedTableKey, UnsupportedVersionedObjectTable> {
    match physical {
        ScyllaPhysicalTableId::UserLeaf => Ok(TypedTableKey::UserLeaf {
            user: UserId::new(obj_id),
            checkpoint,
        }),
        ScyllaPhysicalTableId::UserPublicKey => Ok(TypedTableKey::UserPublicKey {
            user: UserId::new(obj_id),
            checkpoint,
        }),
        ScyllaPhysicalTableId::ContractStateTreeHeight => {
            Ok(TypedTableKey::ContractStateTreeHeight {
                contract: ContractId::new(obj_id),
                checkpoint,
            })
        }
        ScyllaPhysicalTableId::ContractLeaf => Ok(TypedTableKey::ContractLeaf {
            contract: ContractId::new(obj_id),
            checkpoint,
        }),
        ScyllaPhysicalTableId::ContractCodeDefinition => {
            Ok(TypedTableKey::ContractCodeDefinition {
                contract: ContractId::new(obj_id),
                checkpoint,
            })
        }
        ScyllaPhysicalTableId::CheckpointedObject
        | ScyllaPhysicalTableId::RealmRewardsTreeNodeKey => Err(
            UnsupportedVersionedObjectTable::MixedAxisNeedsExplicitDomain(physical),
        ),
        other => Err(UnsupportedVersionedObjectTable::NotAnObjectTable(other)),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsupportedKeyIdValueTable {
    NotAKeyIdValueTable(ScyllaPhysicalTableId),
    /// `latest_info_table` shares the key-id-value shape but its `obj_id` is a
    /// singleton slot, not a checkpoint, and only slots 1..=3 exist.
    UnknownLatestInfoSlot(u64),
}

impl std::fmt::Display for UnsupportedKeyIdValueTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAKeyIdValueTable(id) => {
                write!(f, "{id:?} is not a key-id-value table")
            }
            Self::UnknownLatestInfoSlot(slot) => {
                write!(f, "latest_info slot {slot} is not a known singleton slot")
            }
        }
    }
}

impl std::error::Error for UnsupportedKeyIdValueTable {}

/// Typed key for one row of a key-id-value table.
///
/// These tables all look identical -- `PRIMARY KEY ((obj_id))` -- but `obj_id`
/// is a checkpoint in five of them and a singleton slot in `latest_info_table`.
/// Treating a slot as a checkpoint would produce a locator naming checkpoint 1,
/// 2 or 3, which is a real row in another table, so the distinction is made here
/// rather than left to the caller.
pub fn key_id_value_key(
    physical: ScyllaPhysicalTableId,
    obj_id: u64,
) -> Result<TypedTableKey, UnsupportedKeyIdValueTable> {
    let checkpoint = |obj_id: u64| CheckpointId::try_new(obj_id);
    match physical {
        ScyllaPhysicalTableId::CheckpointLeaf => checkpoint(obj_id)
            .map(TypedTableKey::CheckpointLeaf)
            .map_err(|_| UnsupportedKeyIdValueTable::NotAKeyIdValueTable(physical)),
        ScyllaPhysicalTableId::L2BlockState => checkpoint(obj_id)
            .map(TypedTableKey::L2BlockState)
            .map_err(|_| UnsupportedKeyIdValueTable::NotAKeyIdValueTable(physical)),
        ScyllaPhysicalTableId::CheckpointStateRoots => checkpoint(obj_id)
            .map(TypedTableKey::CheckpointStateRoots)
            .map_err(|_| UnsupportedKeyIdValueTable::NotAKeyIdValueTable(physical)),
        ScyllaPhysicalTableId::CheckpointZkProofAndTransition => checkpoint(obj_id)
            .map(TypedTableKey::CheckpointZkProof)
            .map_err(|_| UnsupportedKeyIdValueTable::NotAKeyIdValueTable(physical)),
        ScyllaPhysicalTableId::CheckpointIdToRealmRoot => checkpoint(obj_id)
            .map(TypedTableKey::UnusedCheckpointRealmRoot)
            .map_err(|_| UnsupportedKeyIdValueTable::NotAKeyIdValueTable(physical)),
        ScyllaPhysicalTableId::LatestInfo => match obj_id {
            1 => Ok(TypedTableKey::LatestInfo(LatestInfoSlot::LatestL2BlockState)),
            2 => Ok(TypedTableKey::LatestInfo(
                LatestInfoSlot::LatestCheckpointTreeRoot,
            )),
            3 => Ok(TypedTableKey::LatestInfo(
                LatestInfoSlot::RealmAuthorityObservation,
            )),
            other => Err(UnsupportedKeyIdValueTable::UnknownLatestInfoSlot(other)),
        },
        other => Err(UnsupportedKeyIdValueTable::NotAKeyIdValueTable(other)),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsupportedU64MappingTable {
    NotAU64MappingTable(ScyllaPhysicalTableId),
    ObjIdOutOfRange(u64),
}

impl std::fmt::Display for UnsupportedU64MappingTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAU64MappingTable(id) => write!(f, "{id:?} is not a u64 mapping table"),
            Self::ObjIdOutOfRange(value) => {
                write!(f, "{value} is outside the CQL bigint alias range")
            }
        }
    }
}

impl std::error::Error for UnsupportedU64MappingTable {}

/// Typed key for one row of a u64-to-u64 mapping table.
///
/// The two directions are separate logical tables, not a pair:
/// `checkpoint_id_to_pending_id_table` is keyed by a reusable checkpoint height
/// and `pending_id_to_checkpoint_id_table` by a monotonic pending id.  Their
/// `obj_id` columns hold different kinds of number, and mixing them up would
/// name a real row of the other table.
pub fn u64_mapping_key(
    physical: ScyllaPhysicalTableId,
    obj_id: u64,
) -> Result<TypedTableKey, UnsupportedU64MappingTable> {
    match physical {
        ScyllaPhysicalTableId::CheckpointIdToPendingId => CheckpointId::try_new(obj_id)
            .map(TypedTableKey::CheckpointToPending)
            .map_err(|_| UnsupportedU64MappingTable::ObjIdOutOfRange(obj_id)),
        ScyllaPhysicalTableId::PendingIdToCheckpointId => UniquePendingId::try_new(obj_id)
            .map(TypedTableKey::PendingToCheckpoint)
            .map_err(|_| UnsupportedU64MappingTable::ObjIdOutOfRange(obj_id)),
        other => Err(UnsupportedU64MappingTable::NotAU64MappingTable(other)),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UnsupportedBidirectionalTable {
    NotABidirectionalPair(ScyllaPhysicalTableId),
    CheckpointOutOfRange(u64),
}

impl std::fmt::Display for UnsupportedBidirectionalTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotABidirectionalPair(id) => {
                write!(f, "{id:?} is not one direction of a bidirectional pair")
            }
            Self::CheckpointOutOfRange(value) => {
                write!(f, "{value} is outside the CQL bigint alias range")
            }
        }
    }
}

impl std::error::Error for UnsupportedBidirectionalTable {}

/// One logical bidirectional write, as the two physical rows it really is.
///
/// This is the gap that made bidirectional tables worth singling out.  A caller
/// sees one `set_or_insert_one_qpk`, but two rows land in two tables, and the
/// content-keyed direction is the dangerous one: after a rollback reuses a
/// height, a surviving `root -> id` row maps a discarded root onto a live
/// checkpoint with different content, and no root check can see it because the
/// row is not part of any tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BidirectionalPairKeys {
    /// Keyed by content: the root or leaf hash.
    pub by_content: TypedTableKey,
    /// Keyed by height: the checkpoint.
    pub by_checkpoint: TypedTableKey,
}

/// Typed keys for both physical rows of one bidirectional mapping write.
///
/// Returning both together is deliberate: a caller cannot record one direction
/// and forget the other.
pub fn bidirectional_pair_keys(
    logical_by_content: ScyllaPhysicalTableId,
    content_bytes: Vec<u8>,
    checkpoint_id: u64,
) -> Result<BidirectionalPairKeys, UnsupportedBidirectionalTable> {
    let checkpoint = CheckpointId::try_new(checkpoint_id)
        .map_err(|_| UnsupportedBidirectionalTable::CheckpointOutOfRange(checkpoint_id))?;
    match logical_by_content {
        ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK1 => Ok(BidirectionalPairKeys {
            by_content: TypedTableKey::CheckpointRootByHash(CheckpointRootKey::new(content_bytes)),
            by_checkpoint: TypedTableKey::CheckpointRootByCheckpoint(checkpoint),
        }),
        ScyllaPhysicalTableId::CheckpointLeafToCheckpointIdK1 => Ok(BidirectionalPairKeys {
            by_content: TypedTableKey::CheckpointLeafByHash(CheckpointLeafKey::new(content_bytes)),
            by_checkpoint: TypedTableKey::CheckpointLeafByCheckpoint(checkpoint),
        }),
        other => Err(UnsupportedBidirectionalTable::NotABidirectionalPair(other)),
    }
}

/// Receives every physical row an adapter writes, in write order.
///
/// Implementations must be cheap: this sits on the commit path, and a busy
/// Realm commit hands over roughly twenty thousand rows.
pub trait CommitMutationSink: Send + Sync {
    fn record(&self, record: MutationLocatorRecord);
}

/// A sink that keeps the records, for one commit.
#[derive(Default)]
pub struct CollectingMutationSink {
    records: Mutex<Vec<MutationLocatorRecord>>,
}

impl CollectingMutationSink {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records in write order.
    pub fn take(&self) -> Vec<MutationLocatorRecord> {
        std::mem::take(&mut self.records.lock().expect("sink mutex poisoned"))
    }

    pub fn len(&self) -> usize {
        self.records.lock().expect("sink mutex poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl CommitMutationSink for CollectingMutationSink {
    fn record(&self, record: MutationLocatorRecord) {
        self.records
            .lock()
            .expect("sink mutex poisoned")
            .push(record);
    }
}

/// Record a put of one zero-id Merkle node.
///
/// Kept here rather than inline in the adapter so the locator is built through
/// the registry in exactly one place.
pub fn record_zero_merkle_put(
    sink: &dyn CommitMutationSink,
    physical: ScyllaPhysicalTableId,
    level: u8,
    node_index: u64,
    checkpoint: CheckpointId,
) -> anyhow::Result<()> {
    let key = zero_merkle_node_key(physical, level, node_index, checkpoint)?;
    let resolved = describe_existing_key(&key);
    sink.record(MutationLocatorRecord::try_new(
        resolved.physical_table(),
        RecordedOperation::Put,
        resolved.locator_bytes().to_vec(),
    )?);
    Ok(())
}

/// Record a put of one single-id Merkle node.
pub fn record_single_merkle_put(
    sink: &dyn CommitMutationSink,
    physical: ScyllaPhysicalTableId,
    tree_id: u64,
    level: u8,
    node_index: u64,
    checkpoint: CheckpointId,
) -> anyhow::Result<()> {
    let key = single_merkle_node_key(physical, tree_id, level, node_index, checkpoint)?;
    let resolved = describe_existing_key(&key);
    sink.record(MutationLocatorRecord::try_new(
        resolved.physical_table(),
        RecordedOperation::Put,
        resolved.locator_bytes().to_vec(),
    )?);
    Ok(())
}

/// Record a put of one versioned single-id object row.
pub fn record_versioned_object_put(
    sink: &dyn CommitMutationSink,
    physical: ScyllaPhysicalTableId,
    obj_id: u64,
    checkpoint: CheckpointId,
) -> anyhow::Result<()> {
    let key = versioned_object_key(physical, obj_id, checkpoint)?;
    let resolved = describe_existing_key(&key);
    sink.record(MutationLocatorRecord::try_new(
        resolved.physical_table(),
        RecordedOperation::Put,
        resolved.locator_bytes().to_vec(),
    )?);
    Ok(())
}

/// Record a put of one key-id-value row.
pub fn record_key_id_value_put(
    sink: &dyn CommitMutationSink,
    physical: ScyllaPhysicalTableId,
    obj_id: u64,
) -> anyhow::Result<()> {
    let key = key_id_value_key(physical, obj_id)?;
    let resolved = describe_existing_key(&key);
    sink.record(MutationLocatorRecord::try_new(
        resolved.physical_table(),
        RecordedOperation::Put,
        resolved.locator_bytes().to_vec(),
    )?);
    Ok(())
}

/// Record a put of one u64-to-u64 mapping row.
pub fn record_u64_mapping_put(
    sink: &dyn CommitMutationSink,
    physical: ScyllaPhysicalTableId,
    obj_id: u64,
) -> anyhow::Result<()> {
    let key = u64_mapping_key(physical, obj_id)?;
    let resolved = describe_existing_key(&key);
    sink.record(MutationLocatorRecord::try_new(
        resolved.physical_table(),
        RecordedOperation::Put,
        resolved.locator_bytes().to_vec(),
    )?);
    Ok(())
}

/// Record both physical rows of one bidirectional mapping write.
///
/// There is no single-direction variant on purpose.  Recording only the
/// height-keyed row is the mistake that leaves an orphan `root -> id` mapping
/// behind after a rollback.
pub fn record_bidirectional_pair_put(
    sink: &dyn CommitMutationSink,
    logical_by_content: ScyllaPhysicalTableId,
    content_bytes: Vec<u8>,
    checkpoint_id: u64,
) -> anyhow::Result<()> {
    let keys = bidirectional_pair_keys(logical_by_content, content_bytes, checkpoint_id)?;
    for key in [&keys.by_content, &keys.by_checkpoint] {
        let resolved = describe_existing_key(key);
        sink.record(MutationLocatorRecord::try_new(
            resolved.physical_table(),
            RecordedOperation::Put,
            resolved.locator_bytes().to_vec(),
        )?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO_MERKLE_TABLES: [ScyllaPhysicalTableId; 4] = [
        ScyllaPhysicalTableId::GlobalUserTree,
        ScyllaPhysicalTableId::GlobalCheckpointTree,
        ScyllaPhysicalTableId::UserRegistrationTree,
        ScyllaPhysicalTableId::GlobalContractTree,
    ];

    #[test]
    fn every_physical_name_resolves_and_does_so_uniquely() {
        // The reverse lookup is how a generic adapter learns which table it is,
        // so a duplicate or missing name would silently misattribute rows.
        let mut seen = std::collections::BTreeSet::new();
        for id in ScyllaPhysicalTableId::iter() {
            let name = physical_descriptor(id).physical_name;
            assert_eq!(physical_table_by_name(name), Some(id), "{name}");
            assert!(seen.insert(name), "{name} appears twice in the registry");
        }
        assert_eq!(seen.len(), 35);
        assert_eq!(physical_table_by_name("not_a_table"), None);
    }

    #[test]
    fn each_zero_merkle_table_gets_its_own_key_variant() {
        let checkpoint = CheckpointId::try_new(9).unwrap();
        let mut locators = std::collections::BTreeSet::new();
        for physical in ZERO_MERKLE_TABLES {
            let key = zero_merkle_node_key(physical, 3, 17, checkpoint).unwrap();
            let resolved = describe_existing_key(&key);
            // The recorded locator must name the table it came from, or rollback
            // deletes rows of a neighbouring tree while every digest still matches.
            assert_eq!(resolved.physical_table(), physical);
            assert!(
                locators.insert(resolved.locator_bytes().to_vec()),
                "{physical:?} shares a locator with another zero-id tree"
            );
        }
        assert_eq!(locators.len(), 4);
    }

    #[test]
    fn one_bidirectional_write_records_two_rows_in_two_tables() {
        // The correctness gap: a caller sees one write, but two rows land.
        // Recording only the height-keyed one leaves the discarded branch's
        // root mapped onto a reused height, and no root check can see it
        // because that row belongs to no tree.
        let sink = CollectingMutationSink::new();
        record_bidirectional_pair_put(
            &sink,
            ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK1,
            vec![9u8; 32],
            1001,
        )
        .unwrap();
        let records = sink.take();
        assert_eq!(records.len(), 2);
        let tables: Vec<_> = records.iter().map(|r| r.physical_table()).collect();
        assert!(tables.contains(&ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK1));
        assert!(tables.contains(&ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK2));
    }

    #[test]
    fn the_content_keyed_direction_does_not_depend_on_the_height() {
        // Two branches at one height carry different roots, so their
        // content-keyed rows are different rows and both must be deletable.
        // The height-keyed row, by contrast, is the same row overwritten.
        let keys_a =
            bidirectional_pair_keys(
                ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK1,
                vec![1u8; 32],
                1001,
            )
            .unwrap();
        let keys_b =
            bidirectional_pair_keys(
                ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK1,
                vec![2u8; 32],
                1001,
            )
            .unwrap();
        assert_ne!(
            describe_existing_key(&keys_a.by_content).locator_bytes(),
            describe_existing_key(&keys_b.by_content).locator_bytes(),
        );
        assert_eq!(
            describe_existing_key(&keys_a.by_checkpoint).locator_bytes(),
            describe_existing_key(&keys_b.by_checkpoint).locator_bytes(),
        );
    }

    #[test]
    fn the_root_and_leaf_pairs_are_distinct_tables() {
        let root = bidirectional_pair_keys(
            ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK1,
            vec![5u8; 32],
            7,
        )
        .unwrap();
        let leaf = bidirectional_pair_keys(
            ScyllaPhysicalTableId::CheckpointLeafToCheckpointIdK1,
            vec![5u8; 32],
            7,
        )
        .unwrap();
        assert_ne!(
            describe_existing_key(&root.by_content).physical_table(),
            describe_existing_key(&leaf.by_content).physical_table(),
        );
        assert_ne!(
            describe_existing_key(&root.by_checkpoint).physical_table(),
            describe_existing_key(&leaf.by_checkpoint).physical_table(),
        );
    }

    #[test]
    fn the_two_pending_mapping_directions_never_share_a_locator() {
        // One is keyed by a reusable checkpoint height, the other by a
        // monotonic pending id.  The same number appears in both, so confusing
        // them would name a real row of the other table -- and after a rollback
        // reuses a height, exactly the wrong real row.
        let by_checkpoint = describe_existing_key(
            &u64_mapping_key(ScyllaPhysicalTableId::CheckpointIdToPendingId, 77).unwrap(),
        );
        let by_pending = describe_existing_key(
            &u64_mapping_key(ScyllaPhysicalTableId::PendingIdToCheckpointId, 77).unwrap(),
        );
        assert_eq!(
            by_checkpoint.physical_table(),
            ScyllaPhysicalTableId::CheckpointIdToPendingId
        );
        assert_eq!(
            by_pending.physical_table(),
            ScyllaPhysicalTableId::PendingIdToCheckpointId
        );
        assert_ne!(by_checkpoint.locator_bytes(), by_pending.locator_bytes());
    }

    #[test]
    fn a_u64_mapping_obj_id_outside_the_cql_alias_range_is_refused() {
        // The physical column is a signed bigint, so anything above i64::MAX
        // would wrap to a negative key rather than fail.
        assert_eq!(
            u64_mapping_key(
                ScyllaPhysicalTableId::PendingIdToCheckpointId,
                i64::MAX as u64 + 1
            ),
            Err(UnsupportedU64MappingTable::ObjIdOutOfRange(
                i64::MAX as u64 + 1
            ))
        );
    }

    #[test]
    fn a_latest_info_slot_is_never_read_as_a_checkpoint() {
        // The trap in this family: every key-id-value table has the same
        // PRIMARY KEY ((obj_id)), but latest_info stores a slot there.  Reading
        // slot 1 as checkpoint 1 would name a row that exists in a different
        // table, so the two must not share a locator.
        let slot = describe_existing_key(
            &key_id_value_key(ScyllaPhysicalTableId::LatestInfo, 1).unwrap(),
        );
        let checkpoint = describe_existing_key(
            &key_id_value_key(ScyllaPhysicalTableId::CheckpointLeaf, 1).unwrap(),
        );
        assert_eq!(slot.physical_table(), ScyllaPhysicalTableId::LatestInfo);
        assert_eq!(
            checkpoint.physical_table(),
            ScyllaPhysicalTableId::CheckpointLeaf
        );
        assert_ne!(slot.locator_bytes(), checkpoint.locator_bytes());
        // Only the three declared slots exist.
        assert_eq!(
            key_id_value_key(ScyllaPhysicalTableId::LatestInfo, 4),
            Err(UnsupportedKeyIdValueTable::UnknownLatestInfoSlot(4))
        );
    }

    #[test]
    fn each_checkpoint_keyed_table_gets_its_own_locator() {
        let mut locators = std::collections::BTreeSet::new();
        for physical in [
            ScyllaPhysicalTableId::CheckpointLeaf,
            ScyllaPhysicalTableId::L2BlockState,
            ScyllaPhysicalTableId::CheckpointStateRoots,
            ScyllaPhysicalTableId::CheckpointZkProofAndTransition,
            ScyllaPhysicalTableId::CheckpointIdToRealmRoot,
        ] {
            let resolved = describe_existing_key(&key_id_value_key(physical, 500).unwrap());
            assert_eq!(resolved.physical_table(), physical);
            assert!(
                locators.insert(resolved.locator_bytes().to_vec()),
                "{physical:?} shares a locator with another key-id-value table"
            );
        }
        assert_eq!(locators.len(), 5);
    }

    #[test]
    fn each_versioned_object_table_reads_its_obj_id_differently() {
        let checkpoint = CheckpointId::try_new(3).unwrap();
        let mut locators = std::collections::BTreeSet::new();
        for physical in [
            ScyllaPhysicalTableId::UserLeaf,
            ScyllaPhysicalTableId::UserPublicKey,
            ScyllaPhysicalTableId::ContractStateTreeHeight,
            ScyllaPhysicalTableId::ContractLeaf,
            ScyllaPhysicalTableId::ContractCodeDefinition,
        ] {
            let resolved =
                describe_existing_key(&versioned_object_key(physical, 42, checkpoint).unwrap());
            assert_eq!(resolved.physical_table(), physical);
            assert!(
                locators.insert(resolved.locator_bytes().to_vec()),
                "{physical:?} shares a locator with another object table"
            );
        }
        assert_eq!(locators.len(), 5);
    }

    #[test]
    fn the_mixed_axis_object_tables_are_refused_rather_than_keyed_generically() {
        // inventory §9 B2/B3.  checkpointed_object_table carries both a
        // checkpoint and a pending axis in one clustering column, and
        // realm_rewards_tree_node_key_table calls its clustering column
        // checkpoint_id while storing a pending id.  A generic (obj_id,
        // checkpoint) key would be wrong for both, and wrong invisibly.
        for physical in [
            ScyllaPhysicalTableId::CheckpointedObject,
            ScyllaPhysicalTableId::RealmRewardsTreeNodeKey,
        ] {
            assert_eq!(
                versioned_object_key(physical, 1, CheckpointId::try_new(1).unwrap()),
                Err(UnsupportedVersionedObjectTable::MixedAxisNeedsExplicitDomain(
                    physical
                ))
            );
        }
    }

    #[test]
    fn each_single_merkle_table_reads_its_partition_id_differently() {
        // user_contract_tree partitions by user, contract_function_tree by
        // contract.  The same numeric id must therefore produce different
        // locators, or a rollback would delete a user subtree while thinking it
        // was deleting a contract's.
        let checkpoint = CheckpointId::try_new(6).unwrap();
        let user_tree = describe_existing_key(
            &single_merkle_node_key(
                ScyllaPhysicalTableId::UserContractTree,
                12,
                1,
                2,
                checkpoint,
            )
            .unwrap(),
        );
        let contract_tree = describe_existing_key(
            &single_merkle_node_key(
                ScyllaPhysicalTableId::ContractFunctionTree,
                12,
                1,
                2,
                checkpoint,
            )
            .unwrap(),
        );
        assert_eq!(
            user_tree.physical_table(),
            ScyllaPhysicalTableId::UserContractTree
        );
        assert_eq!(
            contract_tree.physical_table(),
            ScyllaPhysicalTableId::ContractFunctionTree
        );
        assert_ne!(user_tree.locator_bytes(), contract_tree.locator_bytes());
    }

    #[test]
    fn the_single_merkle_tree_id_is_part_of_the_locator() {
        let checkpoint = CheckpointId::try_new(6).unwrap();
        let locator = |tree_id: u64| {
            describe_existing_key(
                &single_merkle_node_key(
                    ScyllaPhysicalTableId::UserContractTree,
                    tree_id,
                    1,
                    2,
                    checkpoint,
                )
                .unwrap(),
            )
            .locator_bytes()
            .to_vec()
        };
        assert_ne!(locator(1), locator(2));
    }

    #[test]
    fn a_non_single_merkle_table_is_refused_rather_than_guessed() {
        assert_eq!(
            single_merkle_node_key(
                ScyllaPhysicalTableId::GlobalUserTree,
                0,
                0,
                0,
                CheckpointId::try_new(1).unwrap()
            ),
            Err(UnsupportedSingleMerkleTable(
                ScyllaPhysicalTableId::GlobalUserTree
            ))
        );
    }

    #[test]
    fn a_non_zero_merkle_table_is_refused_rather_than_guessed() {
        assert_eq!(
            zero_merkle_node_key(
                ScyllaPhysicalTableId::UserLeaf,
                0,
                0,
                CheckpointId::try_new(1).unwrap()
            ),
            Err(UnsupportedZeroMerkleTable(ScyllaPhysicalTableId::UserLeaf))
        );
    }

    #[test]
    fn recorded_puts_keep_write_order_and_round_trip() {
        let sink = CollectingMutationSink::new();
        let checkpoint = CheckpointId::try_new(4).unwrap();
        for (level, index) in [(0u8, 7u64), (1, 3), (2, 1)] {
            record_zero_merkle_put(
                &sink,
                ScyllaPhysicalTableId::GlobalUserTree,
                level,
                index,
                checkpoint,
            )
            .unwrap();
        }
        let records = sink.take();
        assert_eq!(records.len(), 3);
        assert!(sink.is_empty(), "take must drain the sink");
        for (record, (level, index)) in records.iter().zip([(0u8, 7u64), (1, 3), (2, 1)]) {
            assert_eq!(
                record.physical_table(),
                ScyllaPhysicalTableId::GlobalUserTree
            );
            assert_eq!(record.operation(), RecordedOperation::Put);
            let expected = describe_existing_key(
                &zero_merkle_node_key(
                    ScyllaPhysicalTableId::GlobalUserTree,
                    level,
                    index,
                    checkpoint,
                )
                .unwrap(),
            );
            assert_eq!(record.locator_bytes(), expected.locator_bytes());
        }
    }

    #[test]
    fn distinct_nodes_never_share_a_locator() {
        // A collision would make two rows look like one, so rollback would
        // delete fewer rows than it archived.
        let checkpoint = CheckpointId::try_new(11).unwrap();
        let mut locators = std::collections::BTreeSet::new();
        for level in 0u8..8 {
            for index in 0u64..8 {
                let resolved = describe_existing_key(
                    &zero_merkle_node_key(
                        ScyllaPhysicalTableId::GlobalUserTree,
                        level,
                        index,
                        checkpoint,
                    )
                    .unwrap(),
                );
                assert!(
                    locators.insert(resolved.locator_bytes().to_vec()),
                    "level {level} index {index} collides"
                );
            }
        }
        assert_eq!(locators.len(), 64);
    }

    #[test]
    fn the_checkpoint_is_part_of_the_locator() {
        // Two versions of one node must be distinguishable, otherwise a rollback
        // that deletes the discarded version would also name the target's.
        let node = |checkpoint: u64| {
            describe_existing_key(
                &zero_merkle_node_key(
                    ScyllaPhysicalTableId::GlobalUserTree,
                    2,
                    5,
                    CheckpointId::try_new(checkpoint).unwrap(),
                )
                .unwrap(),
            )
            .locator_bytes()
            .to_vec()
        };
        assert_ne!(node(100), node(101));
    }
}
