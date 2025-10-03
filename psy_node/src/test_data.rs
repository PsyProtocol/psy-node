use parth_core::crypto::hash::merkle_proof::DeltaMerkleProofCore;
use plonky2::hash::hash_types::RichField;
use serde::{Deserialize, Serialize};

use crate::core::hash::qhashout::QHashOut;


#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, speedy::Readable, speedy::Writable)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct QEDContractStateUpdateHistory<F: RichField> {
    pub user_contract_tree_update_proof: DeltaMerkleProofCore<QHashOut<F>>,
    pub contract_state_tree_updates: Vec<DeltaMerkleProofCore<QHashOut<F>>>,
}