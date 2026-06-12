use kvq::traits::KVQSerializable;
use plonky2::{field::goldilocks_field::GoldilocksField, hash::hash_types::RichField};
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::hash::merkle::core::{DeltaMerkleProofCore, MerkleProofCore};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::imt_contract_state::IMTContractStateLeaf;

/// Membership proof: proves key K exists in the IMT with value V.
///
/// Verification:
/// 1. Compute leaf_hash = hash(leaf preimage)
/// 2. Verify merkle_proof.value == leaf_hash
/// 3. Verify merkle_proof against the known tree root
/// 4. Confirm leaf.key == target_key
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct IMTMembershipProof<F: RichField> {
    /// The full leaf preimage (key, value, next_key, next_index)
    pub leaf: IMTContractStateLeaf<F>,
    /// Standard merkle proof of the leaf hash
    pub merkle_proof: MerkleProofCore<QHashOut<F>>,
}

impl<F: RichField> KVQSerializable for IMTMembershipProof<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

/// Non-membership proof: proves key K does NOT exist in the IMT.
///
/// Verification:
/// 1. Compute pred_hash = hash(predecessor_leaf preimage)
/// 2. Verify merkle_proof.value == pred_hash
/// 3. Verify merkle_proof against the known tree root
/// 4. Confirm predecessor_leaf.key < target_key
/// 5. Confirm predecessor_leaf.next_key > target_key OR
///    predecessor_leaf.next_key == 0 (end)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct IMTNonMembershipProof<F: RichField> {
    /// The predecessor leaf: pred.key < target_key < pred.next_key
    pub predecessor_leaf: IMTContractStateLeaf<F>,
    /// Proof of the predecessor's leaf hash in the merkle tree
    pub merkle_proof: MerkleProofCore<QHashOut<F>>,
}

impl<F: RichField> KVQSerializable for IMTNonMembershipProof<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

/// Predecessor result: used by clients to construct insertion transaction
/// deltas.
///
/// Contains the predecessor leaf, its merkle proof, and the next append index.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct IMTPredecessorResult<F: RichField> {
    /// Position of the predecessor leaf in the tree
    pub predecessor_leaf_index: u64,
    /// Full preimage of the predecessor leaf
    pub predecessor_leaf: IMTContractStateLeaf<F>,
    /// Merkle proof of the predecessor leaf hash
    pub predecessor_merkle_proof: MerkleProofCore<QHashOut<F>>,
    /// Where the next leaf will be appended
    pub next_append_index: u64,
}

impl<F: RichField> KVQSerializable for IMTPredecessorResult<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

/// For IMT contracts, each state update is either an insert or an update.
/// This is used in the end cap submission and circuit verification.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub enum IMTContractStateUpdate<F: RichField> {
    /// Value update: key already exists, only value changes.
    /// Produces one delta merkle proof.
    Update {
        old_preimage: IMTContractStateLeaf<F>,
        new_preimage: IMTContractStateLeaf<F>,
        delta_proof: DeltaMerkleProofCore<QHashOut<F>>,
    },
    /// Key insertion: new key added, predecessor pointers updated.
    /// Produces two delta merkle proofs applied sequentially.
    Insert {
        predecessor_old_preimage: IMTContractStateLeaf<F>,
        predecessor_new_preimage: IMTContractStateLeaf<F>,
        new_leaf_preimage: IMTContractStateLeaf<F>,
        predecessor_delta_proof: DeltaMerkleProofCore<QHashOut<F>>,
        new_leaf_delta_proof: DeltaMerkleProofCore<QHashOut<F>>,
    },
}

impl<F: RichField> IMTContractStateUpdate<F> {
    /// Get the old root before this update.
    pub fn old_root(&self) -> QHashOut<F> {
        match self {
            IMTContractStateUpdate::Update { delta_proof, .. } => delta_proof.old_root,
            IMTContractStateUpdate::Insert { predecessor_delta_proof, .. } => predecessor_delta_proof.old_root,
        }
    }

    /// Get the new root after this update.
    pub fn new_root(&self) -> QHashOut<F> {
        match self {
            IMTContractStateUpdate::Update { delta_proof, .. } => delta_proof.new_root,
            IMTContractStateUpdate::Insert { new_leaf_delta_proof, .. } => new_leaf_delta_proof.new_root,
        }
    }
}

/// Contract state update history using Indexed Merkle Trees.
/// Replaces the positional `PsyContractStateUpdateHistory` for all contracts.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct IMTContractStateUpdateHistory<F: RichField> {
    /// Proof that updates the user's contract tree (maps contract_id -> state
    /// root)
    pub user_contract_tree_update_proof: DeltaMerkleProofCore<QHashOut<F>>,
    /// IMT contract state tree updates (insert or update operations)
    pub imt_updates: Vec<IMTContractStateUpdate<F>>,
}

impl<F: RichField> IMTContractStateUpdateHistory<F> {
    /// Validate basic consistency of the IMT state update chain.
    ///
    /// When `sentinel_tree_root` is provided, it is used to validate first-time
    /// contract state initialization (UCT old_value == ZERO). This is needed to
    /// prevent malicious provers from claiming arbitrary old roots for
    /// first-time contract state: without this check, a prover could submit
    /// a fabricated old_root that doesn't correspond to a valid
    /// empty/sentinel-only tree, potentially allowing them to "prove" state
    /// transitions from a fake starting state. By requiring the first
    /// old_root to equal the known sentinel-only tree root, we guarantee
    /// the state chain starts from a legitimate empty tree.
    pub fn ensure_basic_consistency(&self, sentinel_tree_root: Option<QHashOut<F>>) -> anyhow::Result<()> {
        if self.imt_updates.is_empty() {
            anyhow::bail!("imt_updates cannot be empty");
        }

        // First update's old_root must match UCT old_value
        let first_old_root = self.imt_updates[0].old_root();
        if first_old_root != self.user_contract_tree_update_proof.old_value {
            if self.user_contract_tree_update_proof.old_value == QHashOut::ZERO {
                // First-time contract state: UCT old_value is ZERO because the
                // contract has never been written to before. Instead of accepting
                // ANY IMT old root (which would let a malicious prover fabricate
                // state), require that the first old_root equals the hash of a
                // tree containing only the sentinel leaf. The caller must provide
                // this expected root via `sentinel_tree_root`.
                if let Some(expected_root) = sentinel_tree_root {
                    if first_old_root != expected_root {
                        anyhow::bail!(
                            "first-time contract state: first IMT old_root does not match \
                             the expected sentinel-only tree root"
                        );
                    }
                } else {
                    anyhow::bail!(
                        "first-time contract state (UCT old_value is ZERO) but no \
                         sentinel_tree_root provided for validation"
                    );
                }
            } else {
                anyhow::bail!("first IMT update old_root does not match UCT old_value");
            }
        }

        // Last update's new_root must match UCT new_value
        let last_new_root = self.imt_updates.last().unwrap().new_root();
        if last_new_root != self.user_contract_tree_update_proof.new_value {
            anyhow::bail!("last IMT update new_root does not match UCT new_value");
        }

        // Sequential consistency: each update's old_root == previous update's new_root
        for i in 1..self.imt_updates.len() {
            if self.imt_updates[i].old_root() != self.imt_updates[i - 1].new_root() {
                anyhow::bail!("IMT update chain broken at index {}: old_root != previous new_root", i);
            }
        }

        Ok(())
    }
}

impl<F: RichField> IMTContractStateUpdateHistory<F> {
    /// Extract IMT slot updates from the update history.
    /// Returns a list of key-level changes for downstream processing.
    pub fn get_imt_slot_updates(&self) -> anyhow::Result<crate::qblock::cmds::deploy_contract::PsyIMTContractSlotUpdates<F>> {
        use crate::qblock::cmds::deploy_contract::{PsyIMTContractSlotUpdates, PsyIMTSlotUpdate};

        let slot_updates = self
            .imt_updates
            .iter()
            .map(|update| match update {
                IMTContractStateUpdate::Update {
                    old_preimage, new_preimage, ..
                } => PsyIMTSlotUpdate {
                    key: old_preimage.key,
                    old_value: old_preimage.value,
                    new_value: new_preimage.value,
                    is_insert: false,
                },
                IMTContractStateUpdate::Insert { new_leaf_preimage, .. } => PsyIMTSlotUpdate {
                    key: new_leaf_preimage.key,
                    old_value: QHashOut::ZERO,
                    new_value: new_leaf_preimage.value,
                    is_insert: true,
                },
            })
            .collect::<Vec<_>>();

        let contract_id = self.user_contract_tree_update_proof.index as u32;
        Ok(PsyIMTContractSlotUpdates { contract_id, slot_updates })
    }
}

impl<F: RichField> KVQSerializable for IMTContractStateUpdateHistory<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

/// FFS serialization format for IMT leaf preimage entries.
/// Each entry is a fixed-size record that flows through the GUTA pipeline.
///
/// Format (161 bytes per entry):
/// ```text
/// Offset  Size  Field
/// ------  ----  -----
/// 0       8     tree_id (u64, LE)       — user_id
/// 8       8     tree_sub_id (u64, LE)   — contract_id
/// 16      8     leaf_index (u64, LE)    — append position in tree
/// 24      32    leaf_hash ([u8; 32])    — computed hash of the leaf preimage
/// 56      32    leaf_key ([u8; 32])     — the storage key
/// 88      32    leaf_value ([u8; 32])   — the storage value
/// 120     32    next_key ([u8; 32])     — successor key in sorted order
/// 152     8     next_index (u64, LE)    — successor leaf index
/// 160     1     is_new_key (u8)         — 1 = new insertion, 0 = value update
/// ```
pub const IMT_LEAF_FFS_ENTRY_SIZE: usize = 161;

/// Serialize an IMT leaf preimage entry to the FFS format.
pub fn serialize_imt_leaf_ffs_entry<F: RichField>(
    tree_id: u64,
    tree_sub_id: u64,
    leaf_index: u64,
    leaf_hash: &QHashOut<F>,
    leaf: &IMTContractStateLeaf<F>,
    is_new_key: bool,
) -> [u8; IMT_LEAF_FFS_ENTRY_SIZE] {
    let mut buf = [0u8; IMT_LEAF_FFS_ENTRY_SIZE];
    buf[0..8].copy_from_slice(&tree_id.to_le_bytes());
    buf[8..16].copy_from_slice(&tree_sub_id.to_le_bytes());
    buf[16..24].copy_from_slice(&leaf_index.to_le_bytes());

    // leaf_hash as 32 bytes (4 x u64 LE)
    write_qhashout_le(&mut buf[24..56], leaf_hash);

    // leaf_key
    write_qhashout_le(&mut buf[56..88], &leaf.key);

    // leaf_value
    write_qhashout_le(&mut buf[88..120], &leaf.value);

    // next_key
    write_qhashout_le(&mut buf[120..152], &leaf.next_key);

    // next_index
    buf[152..160].copy_from_slice(&leaf.next_index.to_canonical_u64().to_le_bytes());

    // is_new_key
    buf[160] = if is_new_key { 1 } else { 0 };

    buf
}

/// Deserialize an IMT leaf preimage entry from the FFS format.
pub fn deserialize_imt_leaf_ffs_entry<F: RichField>(data: &[u8]) -> anyhow::Result<(u64, u64, u64, QHashOut<F>, IMTContractStateLeaf<F>, bool)> {
    if data.len() < IMT_LEAF_FFS_ENTRY_SIZE {
        anyhow::bail!("IMT leaf FFS entry too short: expected {}, got {}", IMT_LEAF_FFS_ENTRY_SIZE, data.len());
    }

    let tree_id = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let tree_sub_id = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let leaf_index = u64::from_le_bytes(data[16..24].try_into().unwrap());
    let leaf_hash = read_qhashout_le::<F>(&data[24..56]);
    let key = read_qhashout_le::<F>(&data[56..88]);
    let value = read_qhashout_le::<F>(&data[88..120]);
    let next_key = read_qhashout_le::<F>(&data[120..152]);
    let next_index_u64 = u64::from_le_bytes(data[152..160].try_into().unwrap());
    let is_new_key = data[160] != 0;

    let leaf = IMTContractStateLeaf {
        key,
        value,
        next_key,
        next_index: F::from_canonical_u64(next_index_u64),
    };

    Ok((tree_id, tree_sub_id, leaf_index, leaf_hash, leaf, is_new_key))
}

/// Helper: write a QHashOut as 32 bytes (4 x u64 LE) into a buffer slice.
fn write_qhashout_le<F: RichField>(buf: &mut [u8], hash: &QHashOut<F>) {
    for i in 0..4 {
        let val = hash.0.elements[i].to_canonical_u64();
        buf[i * 8..(i + 1) * 8].copy_from_slice(&val.to_le_bytes());
    }
}

/// Helper: read a QHashOut from 32 bytes (4 x u64 LE).
fn read_qhashout_le<F: RichField>(data: &[u8]) -> QHashOut<F> {
    let e0 = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let e1 = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let e2 = u64::from_le_bytes(data[16..24].try_into().unwrap());
    let e3 = u64::from_le_bytes(data[24..32].try_into().unwrap());
    QHashOut::from_values(e0, e1, e2, e3)
}

#[cfg(test)]
mod tests {
    use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};
    use psy_crypto::hash::traits::{hasher::FieldQHasher, qhashable::QFieldHashable};

    use super::*;

    type F = GoldilocksField;

    #[test]
    fn test_ffs_serialization_roundtrip() {
        let leaf = IMTContractStateLeaf::<F>::new(
            QHashOut::from_values(10, 20, 30, 40),
            QHashOut::from_values(50, 60, 70, 80),
            QHashOut::from_values(90, 100, 110, 120),
            F::from_canonical_u64(7),
        );
        let leaf_hash: QHashOut<F> = QHashOut::from_values(999, 888, 777, 666);

        let entry = serialize_imt_leaf_ffs_entry(42, 13, 5, &leaf_hash, &leaf, true);
        assert_eq!(entry.len(), IMT_LEAF_FFS_ENTRY_SIZE);

        let (tree_id, tree_sub_id, leaf_index, restored_hash, restored_leaf, is_new) = deserialize_imt_leaf_ffs_entry::<F>(&entry).unwrap();

        assert_eq!(tree_id, 42);
        assert_eq!(tree_sub_id, 13);
        assert_eq!(leaf_index, 5);
        assert_eq!(restored_hash, leaf_hash);
        assert_eq!(restored_leaf, leaf);
        assert!(is_new);
    }

    #[test]
    fn test_ffs_serialization_update_flag() {
        let leaf = IMTContractStateLeaf::<F>::sentinel();
        let leaf_hash = QHashOut::ZERO;

        let entry = serialize_imt_leaf_ffs_entry(1, 2, 0, &leaf_hash, &leaf, false);
        let (_, _, _, _, _, is_new) = deserialize_imt_leaf_ffs_entry::<F>(&entry).unwrap();
        assert!(!is_new);
    }

    #[test]
    fn test_membership_proof_serialization() {
        let proof = IMTMembershipProof::<F> {
            leaf: IMTContractStateLeaf::sentinel(),
            merkle_proof: MerkleProofCore {
                root: QHashOut::ZERO,
                value: QHashOut::ZERO,
                index: 0,
                siblings: vec![],
            },
        };
        let bytes = proof.to_bytes().unwrap();
        let restored = IMTMembershipProof::<F>::from_bytes(&bytes).unwrap();
        assert_eq!(proof, restored);
    }

    #[test]
    fn test_non_membership_proof_serialization() {
        let proof = IMTNonMembershipProof::<F> {
            predecessor_leaf: IMTContractStateLeaf::sentinel(),
            merkle_proof: MerkleProofCore {
                root: QHashOut::ZERO,
                value: QHashOut::ZERO,
                index: 0,
                siblings: vec![],
            },
        };
        let bytes = proof.to_bytes().unwrap();
        let restored = IMTNonMembershipProof::<F>::from_bytes(&bytes).unwrap();
        assert_eq!(proof, restored);
    }

    #[test]
    fn test_predecessor_result_serialization() {
        let result = IMTPredecessorResult::<F> {
            predecessor_leaf_index: 3,
            predecessor_leaf: IMTContractStateLeaf::sentinel(),
            predecessor_merkle_proof: MerkleProofCore {
                root: QHashOut::ZERO,
                value: QHashOut::ZERO,
                index: 0,
                siblings: vec![],
            },
            next_append_index: 7,
        };
        let bytes = result.to_bytes().unwrap();
        let restored = IMTPredecessorResult::<F>::from_bytes(&bytes).unwrap();
        assert_eq!(result, restored);
    }

    #[test]
    fn test_imt_update_history_consistency_valid() {
        let root_a: QHashOut<F> = QHashOut::from_values(1, 0, 0, 0);
        let root_b: QHashOut<F> = QHashOut::from_values(2, 0, 0, 0);
        let root_c: QHashOut<F> = QHashOut::from_values(3, 0, 0, 0);

        let history = IMTContractStateUpdateHistory::<F> {
            user_contract_tree_update_proof: DeltaMerkleProofCore {
                old_root: QHashOut::ZERO,
                old_value: root_a,
                new_root: QHashOut::ZERO,
                new_value: root_c,
                index: 0,
                siblings: vec![],
            },
            imt_updates: vec![
                IMTContractStateUpdate::Update {
                    old_preimage: IMTContractStateLeaf::sentinel(),
                    new_preimage: IMTContractStateLeaf::sentinel(),
                    delta_proof: DeltaMerkleProofCore {
                        old_root: root_a,
                        old_value: QHashOut::ZERO,
                        new_root: root_b,
                        new_value: QHashOut::ZERO,
                        index: 0,
                        siblings: vec![],
                    },
                },
                IMTContractStateUpdate::Update {
                    old_preimage: IMTContractStateLeaf::sentinel(),
                    new_preimage: IMTContractStateLeaf::sentinel(),
                    delta_proof: DeltaMerkleProofCore {
                        old_root: root_b,
                        old_value: QHashOut::ZERO,
                        new_root: root_c,
                        new_value: QHashOut::ZERO,
                        index: 1,
                        siblings: vec![],
                    },
                },
            ],
        };
        // Non-first-time: UCT old_value matches first old_root, no sentinel root needed
        assert!(history.ensure_basic_consistency(None).is_ok());
    }

    #[test]
    fn test_imt_update_history_consistency_first_time_with_sentinel_root() {
        let sentinel_root: QHashOut<F> = QHashOut::from_values(42, 0, 0, 0);
        let root_b: QHashOut<F> = QHashOut::from_values(2, 0, 0, 0);

        let history = IMTContractStateUpdateHistory::<F> {
            user_contract_tree_update_proof: DeltaMerkleProofCore {
                old_root: QHashOut::ZERO,
                old_value: QHashOut::ZERO, // first-time: UCT old_value is ZERO
                new_root: QHashOut::ZERO,
                new_value: root_b,
                index: 0,
                siblings: vec![],
            },
            imt_updates: vec![IMTContractStateUpdate::Update {
                old_preimage: IMTContractStateLeaf::sentinel(),
                new_preimage: IMTContractStateLeaf::sentinel(),
                delta_proof: DeltaMerkleProofCore {
                    old_root: sentinel_root, // must match the provided sentinel_tree_root
                    old_value: QHashOut::ZERO,
                    new_root: root_b,
                    new_value: QHashOut::ZERO,
                    index: 0,
                    siblings: vec![],
                },
            }],
        };
        // Should pass when correct sentinel root is provided
        assert!(history.ensure_basic_consistency(Some(sentinel_root)).is_ok());
        // Should fail when wrong sentinel root is provided
        let wrong_root = QHashOut::from_values(999, 0, 0, 0);
        assert!(history.ensure_basic_consistency(Some(wrong_root)).is_err());
        // Should fail when no sentinel root is provided for first-time state
        assert!(history.ensure_basic_consistency(None).is_err());
    }

    #[test]
    fn test_imt_update_history_consistency_broken_chain() {
        let root_a: QHashOut<F> = QHashOut::from_values(1, 0, 0, 0);
        let root_b: QHashOut<F> = QHashOut::from_values(2, 0, 0, 0);
        let root_c: QHashOut<F> = QHashOut::from_values(3, 0, 0, 0);
        let root_d: QHashOut<F> = QHashOut::from_values(4, 0, 0, 0);

        let history = IMTContractStateUpdateHistory::<F> {
            user_contract_tree_update_proof: DeltaMerkleProofCore {
                old_root: QHashOut::ZERO,
                old_value: root_a,
                new_root: QHashOut::ZERO,
                new_value: root_c,
                index: 0,
                siblings: vec![],
            },
            imt_updates: vec![
                IMTContractStateUpdate::Update {
                    old_preimage: IMTContractStateLeaf::sentinel(),
                    new_preimage: IMTContractStateLeaf::sentinel(),
                    delta_proof: DeltaMerkleProofCore {
                        old_root: root_a,
                        old_value: QHashOut::ZERO,
                        new_root: root_b,
                        new_value: QHashOut::ZERO,
                        index: 0,
                        siblings: vec![],
                    },
                },
                IMTContractStateUpdate::Update {
                    old_preimage: IMTContractStateLeaf::sentinel(),
                    new_preimage: IMTContractStateLeaf::sentinel(),
                    delta_proof: DeltaMerkleProofCore {
                        old_root: root_d, // broken: should be root_b
                        old_value: QHashOut::ZERO,
                        new_root: root_c,
                        new_value: QHashOut::ZERO,
                        index: 1,
                        siblings: vec![],
                    },
                },
            ],
        };
        assert!(history.ensure_basic_consistency(None).is_err());
    }
}
