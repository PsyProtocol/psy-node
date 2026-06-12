use plonky2::hash::hash_types::RichField;
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::hash::merkle::core::MerkleProofCore;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct ShieldDepositClaimInput<F: RichField> {
    pub nullifier_secret: [F; 4],
    pub note_secret_hash: [F; 4],
    pub r0: F,
    pub r1: F,
    pub user_id: u64,
    pub deposit_index: u64,
    pub token_address: [u32; 8],
    pub l2_token_contract_id: [u32; 8],
    pub amount: [u32; 8],
    pub source_chain_index: u32,
    pub deposit_root: QHashOut<F>,
    pub deposit_proof: MerkleProofCore<QHashOut<F>>,
}
