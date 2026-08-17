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

use psy_node_core::store::typed::{CheckpointId, MerkleNode, NodeIndex, TypedTableKey};

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
