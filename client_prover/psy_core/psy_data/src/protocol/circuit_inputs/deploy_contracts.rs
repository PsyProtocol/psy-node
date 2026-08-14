use kvq::traits::KVQSerializable;
use plonky2::hash::hash_types::RichField;
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::hash::merkle::{
    spiderman::SpidermanUpdateProof,
    treeprover::{AggStateTrackableInput, AggStateTransition},
};
use serde::{Deserialize, Serialize};

use crate::qdata::contract::PsyContractLeaf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct QCBatchDeployContractsCircuitInput<F: RichField> {
    pub deploy_contract_circuit_whitelist: QHashOut<F>,
    pub spiderman_append_proof: SpidermanUpdateProof<QHashOut<F>>,
    pub contract_ids: Vec<u64>,
    pub contract_leaves: Vec<PsyContractLeaf<F>>,
    pub initial_layout_proofs: Vec<Vec<u8>>,
}

impl<F: RichField> AggStateTrackableInput<F> for QCBatchDeployContractsCircuitInput<F> {
    fn get_state_transition(&self) -> AggStateTransition<F> {
        AggStateTransition {
            state_transition_start: self.spiderman_append_proof.top_line_proof.old_root,
            state_transition_end: self.spiderman_append_proof.top_line_proof.new_root,
        }
    }
}

impl<F: RichField> KVQSerializable for QCBatchDeployContractsCircuitInput<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}
