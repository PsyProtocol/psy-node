use kvq::traits::KVQSerializable;
use plonky2::{field::goldilocks_field::GoldilocksField, hash::hash_types::RichField};
use psy_client_common::data::qhashout::QHashOut;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::hash::{
    merkle::core::{compute_historical_and_current_merkle_roots_core, MerkleProofCore},
    traits::{
        hasher::{FieldQHasher, MerkleZeroHasher},
        qhashable::QFieldHashable,
    },
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Copy, Default, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QRecursionAggStandardHeader<F: RichField> {
    pub state_transition_start: QHashOut<F>,
    pub state_transition_end: QHashOut<F>,
    pub agg_circuit_whitelist_root: QHashOut<F>,
}

impl<F: RichField> KVQSerializable for QRecursionAggStandardHeader<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

impl<F: RichField> QFieldHashable<F> for QRecursionAggStandardHeader<F> {
    fn qfhash<H: FieldQHasher<F>>(&self) -> QHashOut<F> {
        let state_combo = H::q_two_to_one(self.state_transition_start, self.state_transition_end);
        H::q_two_to_one(self.agg_circuit_whitelist_root, state_combo)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct AttestProofInTreeInput<F: RichField> {
    pub fingerprint: QHashOut<F>,
    pub public_inputs_hash: QHashOut<F>,
    pub inclusion_proof: MerkleProofCore<QHashOut<F>>,
}

impl<F: RichField> KVQSerializable for AttestProofInTreeInput<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Default, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct AttestTreeAwareProofInTreeInput<F: RichField> {
    pub fingerprint: QHashOut<F>,
    pub inner_public_inputs_hash: QHashOut<F>,
    pub historical_root_proof: MerkleProofCore<QHashOut<F>>,
    pub inclusion_proof: MerkleProofCore<QHashOut<F>>,
}
impl<F: RichField> AttestTreeAwareProofInTreeInput<F> {
    pub fn get_public_inputs_hash<H: MerkleZeroHasher<QHashOut<F>>>(&self) -> QHashOut<F> {
        let (historical_root, _) = compute_historical_and_current_merkle_roots_core::<QHashOut<F>, H>(&self.historical_root_proof);
        H::two_to_one(&historical_root, &self.inner_public_inputs_hash)
    }
    pub fn verify<H: MerkleZeroHasher<QHashOut<F>>>(&self) -> bool {
        if self.historical_root_proof.verify::<H>()
            && self.inclusion_proof.verify::<H>()
            && self.historical_root_proof.root == self.inclusion_proof.root
        {
            let (historical_root, current_root) = compute_historical_and_current_merkle_roots_core::<QHashOut<F>, H>(&self.historical_root_proof);
            let public_inputs_hash = H::two_to_one(&historical_root, &self.inner_public_inputs_hash);
            let expected_leaf_value = H::two_to_one(&self.fingerprint, &public_inputs_hash);
            if expected_leaf_value == self.inclusion_proof.value && current_root == self.historical_root_proof.root {
                return true;
            }
        }
        false
    }
}
impl<F: RichField> KVQSerializable for AttestTreeAwareProofInTreeInput<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}
