use plonky2::hash::hash_types::RichField;
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::hash::merkle::core::MerkleProofCore;
use serde::{Deserialize, Serialize};

/// Input data for the sender-side deposit inclusion proof.
///
/// This proves that the deposit commitment derived from the public deposit
/// metadata and sender-generated note material exists in the deposit tree. It
/// intentionally does not include r0/r1/user_id; claim_deposit verifies
/// receiver ownership in the contract using get_user_id(), r0, and r1.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct DepositInclusionInput<F: RichField> {
    pub nullifier_secret: [F; 4],
    pub note_secret: [F; 4],
    pub shield_address: QHashOut<F>,
    pub deposit_index: u64,
    pub token_address: [u32; 8],
    pub l2_token_contract_id: [u32; 8],
    pub amount: [u32; 8],
    pub source_chain_index: u32,
    pub deposit_root: QHashOut<F>,
    pub deposit_proof: MerkleProofCore<QHashOut<F>>,
}
/// Permanent dual-name seam: wire/protocol uses `shield_deposit_claim`; data
/// layer uses `DepositInclusion`. This alias exports the old protocol name.
pub type ShieldDepositClaimInput<F> = DepositInclusionInput<F>;
