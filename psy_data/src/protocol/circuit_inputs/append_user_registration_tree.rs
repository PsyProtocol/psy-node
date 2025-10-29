use parth_core::crypto::hash::spiderman::SpidermanUpdateProof;

use crate::agg::{AggStateTrackableInput, AggStateTransition};






#[pderive::serialize_clone_hash]
pub struct QCAppendUserRegistrationTreeCircuitInput<Hash> {
    pub register_users_circuit_whitelist: Hash,
    pub spiderman_append_proofs: Vec<SpidermanUpdateProof<Hash>>,
}

impl<Hash: Copy> AggStateTrackableInput<Hash> for QCAppendUserRegistrationTreeCircuitInput<Hash> {
    fn get_state_transition(&self) -> AggStateTransition<Hash> {
        AggStateTransition {
            state_transition_start: self.spiderman_append_proofs[0].top_line_proof.old_root,
            state_transition_end: self.spiderman_append_proofs[self.spiderman_append_proofs.len()-1].top_line_proof.new_root,
        }
    }
}
