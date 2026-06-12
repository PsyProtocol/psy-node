use kvq::traits::KVQSerializable;
use plonky2::{field::goldilocks_field::GoldilocksField, hash::hash_types::RichField};
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::hash::merkle::core::MerkleProofCore;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::ups_context_input::UserProvingSessionHeader;
use crate::qdata::checkpoint::{PsyCheckpointGlobalStateRoots, PsyCheckpointLeaf};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct UPSStartStepInput<F: RichField> {
    pub ups_header: UserProvingSessionHeader<F>,
    pub checkpoint_leaf: PsyCheckpointLeaf<F>,
    pub state_roots: PsyCheckpointGlobalStateRoots<F>,
    pub checkpoint_tree_proof: MerkleProofCore<QHashOut<F>>,
    pub user_tree_proof: MerkleProofCore<QHashOut<F>>,
}

impl<F: RichField> KVQSerializable for UPSStartStepInput<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}
