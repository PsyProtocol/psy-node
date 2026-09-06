use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::poseidon::PoseidonHash,
};
use psy_client_data::qdata::{
    ups_signature::PsyUserProvingSessionSignatureDataCompact, user::PsyUserLeaf, user_contract_state::SignContext,
};
use psy_client_data::ups::ups_context_input::UserProvingSessionHeader;
use psy_crypto::hash::traits::qhashable::QFieldHashable;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::vm::cfc_input::DapenContractFunctionCircuitInput;

type GF = GoldilocksField;

/// Same field assembly as `UserProvingSessionManager::compute_sighash_from_header`.
pub fn sig_hash_fields_from_header<H: psy_crypto::hash::traits::hasher::FieldQHasher<GF>>(
    current_header: &UserProvingSessionHeader<GF>,
    nonce: GF,
) -> (PsyUserProvingSessionSignatureDataCompact<GF>, SignContext<GF>, PsyUserLeaf<GF>) {
    let mut end_user_leaf = current_header.current_state.user_leaf.clone();
    end_user_leaf.nonce = nonce;

    let sig_data = PsyUserProvingSessionSignatureDataCompact {
        start_user_leaf_hash: current_header.session_start_context.start_session_user_leaf.qfhash::<H>(),
        end_user_leaf_hash: end_user_leaf.qfhash::<H>(),
        checkpoint_leaf_hash: current_header.session_start_context.checkpoint_leaf_hash,
        tx_stack_hash: current_header.current_state.tx_hash_stack,
        tx_count: current_header.current_state.tx_count,
    };

    let sign_context = SignContext {
        checkpoint_tree_root: current_header.session_start_context.checkpoint_tree_root,
        user_leaf: current_header.current_state.user_leaf.clone(),
    };

    (
        sig_data,
        sign_context,
        current_header.session_start_context.start_session_user_leaf.clone(),
    )
}

pub fn sig_hash_fields_from_header_poseidon(
    current_header: &UserProvingSessionHeader<GF>,
    nonce: GF,
) -> (PsyUserProvingSessionSignatureDataCompact<GF>, SignContext<GF>, PsyUserLeaf<GF>) {
    sig_hash_fields_from_header::<PoseidonHash>(current_header, nonce)
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct DPNSoftwareDefinedSignatureInput {
    pub cfc_input: DapenContractFunctionCircuitInput<GF>,
    pub sig_data: PsyUserProvingSessionSignatureDataCompact<GF>,
    pub sign_context: SignContext<GF>,
    pub start_session_user_leaf: PsyUserLeaf<GF>,
    pub nonce: GF,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plonky2SoftwareDefinedSignatureInput {
    pub state_reader_results: crate::ups::state_reader::StateReaderResults<GoldilocksField>,
    pub circuit_inputs: Vec<GoldilocksField>,
    pub sig_data: PsyUserProvingSessionSignatureDataCompact<GF>,
    pub sign_context: SignContext<GF>,
    pub start_session_user_leaf: PsyUserLeaf<GF>,
    pub nonce: GF,
}
