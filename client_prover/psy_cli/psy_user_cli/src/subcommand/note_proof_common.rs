use plonky2::field::types::PrimeField64;
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::config::store_config::F;
use psy_crypto::hash::merkle::core::MerkleProofCore;
use serde::{Deserialize, Serialize};

pub fn qhash_to_u64x4(value: QHashOut<F>) -> [u64; 4] {
    [
        value.0.elements[0].to_canonical_u64(),
        value.0.elements[1].to_canonical_u64(),
        value.0.elements[2].to_canonical_u64(),
        value.0.elements[3].to_canonical_u64(),
    ]
}

/// Serialized output - receiver reads this to call private_claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteProofOutput {
    // Inputs for private_claim contract call
    pub nullifier: [u64; 4],
    // receiver shield address
    pub owner: [u64; 4],
    pub amount: u64,
    pub user_tree_root: [u64; 4],
    pub checkpoint_id: u64,
    pub note_root_slot: u64,

    // PrivateNoteInclusionCircuit proof (for receiver's add_external_proof)
    pub note_proof_fingerprint: [u64; 4],
    pub note_proof_bincode_b64: String,
}

pub fn build_private_claim_inputs(
    note_data: &NoteProofOutput,
    leaf_proof: &MerkleProofCore<QHashOut<F>>,
    leaf_index: u64,
    random0: u64,
    random1: u64,
) -> Vec<u64> {
    let mut inputs: Vec<u64> = Vec::new();
    inputs.extend_from_slice(&note_data.nullifier);
    inputs.extend_from_slice(&note_data.owner);
    inputs.push(note_data.amount);
    inputs.extend_from_slice(&note_data.user_tree_root);
    inputs.push(note_data.checkpoint_id);
    inputs.push(note_data.note_root_slot);
    inputs.push(random0);
    inputs.push(random1);
    for s in &leaf_proof.siblings {
        inputs.extend_from_slice(&qhash_to_u64x4(*s));
    }
    inputs.push(leaf_index);
    inputs
}
