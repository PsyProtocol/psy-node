use kvq::traits::KVQSerializable;
use plonky2::hash::hash_types::RichField;
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::hash::merkle::{
    spiderman::SpidermanUpdateProof,
    treeprover::{AggStateTrackableInput, AggStateTransition},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct QCAppendUserRegistrationTreeCircuitInput<F: RichField> {
    pub register_users_circuit_whitelist: QHashOut<F>,
    pub spiderman_append_proofs: Vec<SpidermanUpdateProof<QHashOut<F>>>,
}

impl<F: RichField> AggStateTrackableInput<F> for QCAppendUserRegistrationTreeCircuitInput<F> {
    fn get_state_transition(&self) -> AggStateTransition<F> {
        AggStateTransition {
            state_transition_start: self.spiderman_append_proofs[0].top_line_proof.old_root,
            state_transition_end: self.spiderman_append_proofs[self.spiderman_append_proofs.len() - 1]
                .top_line_proof
                .new_root,
        }
    }
}

impl<F: RichField> KVQSerializable for QCAppendUserRegistrationTreeCircuitInput<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}
