use parth_core::crypto::hash::spiderman::SpidermanUpdateProof;

use crate::{agg::{AggStateTrackableInput, AggStateTransition}, v1::qdata::contract::PQEDContractLeaf};




#[pderive::serialize_clone_f_hash]
pub struct QCBatchDeployContractsCircuitInput<F, Hash> {
    pub deploy_contract_circuit_whitelist: Hash,
    pub spiderman_append_proof: SpidermanUpdateProof<Hash>,
    pub contract_leaves: Vec<PQEDContractLeaf<F, Hash>>,
}

impl<F, Hash: Copy> AggStateTrackableInput<Hash> for QCBatchDeployContractsCircuitInput<F, Hash> {
    fn get_state_transition(&self) -> AggStateTransition<Hash> {
        AggStateTransition {
            state_transition_start: self.spiderman_append_proof.top_line_proof.old_root,
            state_transition_end: self.spiderman_append_proof.top_line_proof.new_root,
        }
    }
}
