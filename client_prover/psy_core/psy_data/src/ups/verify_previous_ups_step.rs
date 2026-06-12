use kvq::traits::KVQSerializable;
use plonky2::{field::goldilocks_field::GoldilocksField, hash::hash_types::RichField};
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::{common::witnesses::qrecursion::header::AttestTreeAwareProofInTreeInput, hash::merkle::core::MerkleProofCore};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::ups_context_input::{UserProvingSessionCurrentState, UserProvingSessionHeader};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct VerifyPreviousUPSStepProofInProofTreeInput<F: RichField> {
    pub proof_attestation_witness: AttestTreeAwareProofInTreeInput<F>,
    pub previous_step_header: UserProvingSessionHeader<F>,
    pub ups_circuit_whitelist_merkle_proof: MerkleProofCore<QHashOut<F>>,
}

impl<F: RichField> KVQSerializable for VerifyPreviousUPSStepProofInProofTreeInput<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct VerifyPreviousUPSStepProofInProofTreePartialInput<F: RichField> {
    pub proof_attestation_witness: AttestTreeAwareProofInTreeInput<F>,
    pub previous_step_state: UserProvingSessionCurrentState<F>,
    pub ups_circuit_whitelist_merkle_proof: MerkleProofCore<QHashOut<F>>,
}

impl<F: RichField> KVQSerializable for VerifyPreviousUPSStepProofInProofTreePartialInput<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}
