use plonky2::field::types::PrimeField64;
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::config::store_config::F;
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
    // Canonical decimal-string token contract identity bound into the proof.
    pub token_contract_id: String,

    // PrivateNoteInclusionCircuit proof (for receiver's add_external_proof)
    pub note_proof_fingerprint: [u64; 4],
    pub note_proof: Vec<u8>,
}
