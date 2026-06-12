use plonky2::hash::hash_types::RichField;
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::hash::merkle::core::MerkleProofCore;
use serde::{Deserialize, Serialize};

use crate::qdata::user::PsyUserLeaf;

/// Input data for the privacy note existence circuit.
///
/// This is what Alice(sender) provides offline to generate a ZK proof that her
/// commitment exists in the global user tree. Bob(receiver) later uses the
/// resulting proof to call `private_claim`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct PrivateNoteInclusionInput<F: RichField> {
    /// Nullifier secret (4 field elements), used to derive nullifier_hash.
    pub nullifier_secret: QHashOut<F>,

    /// Alice's user ID (index in the global user tree)
    pub sender_user_id: u64,

    /// The PSY Token contract ID (index in the user's contract state tree)
    pub contract_id: u64,

    /// The complete user leaf data for Alice
    pub user_leaf: PsyUserLeaf<F>,

    /// Note owner commitment:
    /// owner = Hash(receiver_public_key, [receiver_user_id, 0, 0, 0]) (4 field
    /// elements)
    pub owner: QHashOut<F>,

    /// Transfer amount
    pub amount: F,

    /// Commitment randomness / nonce (4 field elements)
    pub randomness: QHashOut<F>,

    /// Merkle proof: note_index -> note_root. `index` is embedded in this
    /// proof.
    pub note_membership_proof: MerkleProofCore<QHashOut<F>>,

    /// Fixed slot index of note_root in the sender's contract state tree.
    pub note_root_slot: u64,

    /// Merkle proof: note_root_slot -> contract_state_root.
    pub note_root_slot_proof: MerkleProofCore<QHashOut<F>>,

    /// Merkle proof: contract_id -> user_state_tree_root
    pub contract_proof: MerkleProofCore<QHashOut<F>>,

    /// Merkle proof: sender_user_id -> global_user_tree_root
    pub user_tree_proof: MerkleProofCore<QHashOut<F>>,

    /// The checkpoint ID associated with the user tree root
    pub checkpoint_id: F,
}
