//! Serializable proof tree metadata for stateless step-by-step proving.
//!
//! `ProofTreeMeta` captures the state of `PortableQTreeRecursionManager` that
//! is needed between prove steps — without the proof blobs. It is KB-level,
//! passed to/from WASM per step, and reconstructable from persisted
//! `leaf_records` on crash recovery.

use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::poseidon::PoseidonHash,
    plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
};
use psy_client_common::data::qhashout::QHashOut;
use psy_common_circuit::treeprover::qrecursion::standard::manager::portable::core::PortableQTreeRecursionManager;
use psy_crypto::{
    common::witnesses::qrecursion::proof_data::TreeAwareTreeProofRecord,
    hash::{
        merkle::{core::DeltaMerkleProofCore, utils::common::SimpleMerkleNodeKey},
        traits::hasher::MerkleZeroHasher,
    },
};
use serde::{Deserialize, Serialize};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

// Re-export the existing baton type under the spec name.
pub type LastStepProofInfo = TreeAwareTreeProofRecord<F>;

/// Serializable representation of a SimpleMerkleTree node map.
/// Keys are (level, index), values are QHashOut.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SimpleMerkleTreeJson {
    pub nodes: Vec<((u8, u64), QHashOut<F>)>,
    pub height: u8,
    pub zero_value_hashes: Vec<QHashOut<F>>,
}

/// Per-leaf metadata (no proof blob — caller persists blobs separately).
/// Contains the insertion proof (DeltaMerkleProofCore) so finalize can
/// reconstruct LeafProofRecord without re-deriving it from the tree.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeafRecordMeta {
    pub leaf_index: u64,
    pub fingerprint: QHashOut<F>,
    pub circuit_type: String,
    pub leaf_circuit_type_id: u64,
    /// Insertion proof captured at leaf insertion time.
    /// ~500 bytes (height × 32-byte siblings + 6 hashes/u64).
    /// Needed by finalize_tree to run aggregation circuits.
    pub insertion_proof: DeltaMerkleProofCore<QHashOut<F>>,
}

/// Serializable proof tree state for step-by-step proving.
/// Contains only hashes and indices — no proof blobs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofTreeMeta {
    pub proof_tree: SimpleMerkleTreeJson,
    pub next_leaf_index: u64,
    pub root_history: Vec<QHashOut<F>>,
    pub q_recursion_tree_height: usize,
    pub leaf_records: Vec<LeafRecordMeta>,
}

impl ProofTreeMeta {
    /// Create empty proof tree meta from a tree height.
    pub fn new(q_recursion_tree_height: usize) -> Self {
        let height = q_recursion_tree_height as u8;
        let zero_value_hashes: Vec<QHashOut<F>> = (0..(height + 1)).map(|h| PoseidonHash::get_zero_hash((height - h) as usize)).collect();

        Self {
            proof_tree: SimpleMerkleTreeJson {
                nodes: Vec::new(),
                height,
                zero_value_hashes,
            },
            next_leaf_index: 0,
            root_history: Vec::new(),
            q_recursion_tree_height,
            leaf_records: Vec::new(),
        }
    }

    /// Extract ProofTreeMeta from a PortableQTreeRecursionManager.
    /// This is called after each prove step to snapshot the tree state.
    /// Populates `leaf_records` with per-leaf metadata including
    /// insertion_proof.
    pub fn from_portable_manager(manager: &PortableQTreeRecursionManager<C, D>) -> Self {
        let nodes = manager
            .proof_tree
            .nodes_iter()
            .map(|(key, value)| ((key.level, key.index), *value))
            .collect();

        let height = manager.proof_tree.get_height();
        let zero_value_hashes = manager.proof_tree.get_zero_value_hashes().to_vec();

        // Extract leaf metadata (leaf_circuit_type, fingerprint, insertion_proof)
        // from the manager's leaf_proofs queue. Proof blobs and verifier_data are
        // NOT included — callers persist proof blobs separately and verifier data
        // remains in the circuit manager.
        let leaf_metadata = manager.extract_leaf_metadata();
        let leaf_records: Vec<LeafRecordMeta> = leaf_metadata
            .into_iter()
            .map(|(circuit_type_id, fingerprint, insertion_proof)| {
                let circuit_type_str = match circuit_type_id {
                    1 => "UPS_STEP",
                    2 => "CFC",
                    3 => "ZK_SIG",
                    4 => "EXTERNAL_PROOF",
                    _ => "UNKNOWN",
                };
                LeafRecordMeta {
                    leaf_index: insertion_proof.index,
                    fingerprint,
                    circuit_type: circuit_type_str.to_string(),
                    leaf_circuit_type_id: circuit_type_id,
                    insertion_proof,
                }
            })
            .collect();

        Self {
            proof_tree: SimpleMerkleTreeJson {
                nodes,
                height,
                zero_value_hashes,
            },
            next_leaf_index: manager.next_proof_index(),
            root_history: manager.root_history.clone(),
            q_recursion_tree_height: manager.q_recursion_tree_height(),
            leaf_records,
        }
    }

    /// Reconstruct a SimpleMerkleTree from the JSON representation.
    pub fn to_merkle_tree(
        &self,
    ) -> psy_crypto::hash::merkle::utils::simple_merkle_tree::SimpleMerkleTree<<C as GenericConfig<D>>::Hasher, QHashOut<F>> {
        use psy_crypto::hash::merkle::utils::simple_merkle_tree::SimpleMerkleTree;

        let mut tree = SimpleMerkleTree::new(self.proof_tree.height);

        // Restore zero value hashes
        tree.set_zero_value_hashes(self.proof_tree.zero_value_hashes.clone());

        // Restore all nodes
        for ((level, index), value) in &self.proof_tree.nodes {
            tree.set_node_value(
                SimpleMerkleNodeKey {
                    level: *level,
                    index: *index,
                },
                *value,
            );
        }

        tree
    }

    /// Get the current proof tree root.
    pub fn get_root(&self) -> QHashOut<F> {
        self.to_merkle_tree().get_root()
    }

    /// Insert a leaf value at the given index (crash recovery / skip).
    /// Returns the old root before insertion.
    pub fn insert_leaf_value(&mut self, leaf_value: QHashOut<F>, leaf_index: u64) -> QHashOut<F> {
        let mut tree = self.to_merkle_tree();
        let old_root = tree.get_root();
        tree.set_leaf(leaf_index, leaf_value);
        self.proof_tree.nodes = tree.nodes_iter().map(|(key, value)| ((key.level, key.index), *value)).collect();
        self.root_history.push(old_root);
        if leaf_index >= self.next_leaf_index {
            self.next_leaf_index = leaf_index + 1;
        }
        old_root
    }
}
