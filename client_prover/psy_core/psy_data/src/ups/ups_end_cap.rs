use kvq::traits::KVQSerializable;
use plonky2::{field::goldilocks_field::GoldilocksField, hash::hash_types::RichField};
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::common::witnesses::qrecursion::header::AttestProofInTreeInput;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::verify_previous_ups_step::VerifyPreviousUPSStepProofInProofTreeInput;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct UPSEndCapFromProofTreeGadgetInput<F: RichField> {
    pub verify_previous_ups_step_input: VerifyPreviousUPSStepProofInProofTreeInput<F>,
    pub verify_zk_signature_proof_input: AttestProofInTreeInput<F>,
    pub user_public_key_param: QHashOut<F>,
    pub nonce: F,
    pub slots_modified: F,
    pub second_to_last_tx_hash_stack: QHashOut<F>,
}

impl<F: RichField> KVQSerializable for UPSEndCapFromProofTreeGadgetInput<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}
