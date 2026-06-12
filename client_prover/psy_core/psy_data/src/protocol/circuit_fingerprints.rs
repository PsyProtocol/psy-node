use plonky2::hash::hash_types::RichField;
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::hash::merkle::treeprover::TPCircuitFingerprintConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct PsyWorkerToolboxCoreCircuitFingerprints<F: RichField> {
    pub network_magic: u64,

    pub zk_signature_wrapper: QHashOut<F>,
    pub secp256k1_signature: QHashOut<F>,

    // state transition operations
    pub op_register_user: TPCircuitFingerprintConfig<F>,
    pub op_deploy_contract: TPCircuitFingerprintConfig<F>,
    pub op_claim_deposit: TPCircuitFingerprintConfig<F>,
    pub op_transfer: TPCircuitFingerprintConfig<F>,
    pub op_add_withdrawal: TPCircuitFingerprintConfig<F>,

    // state transition with events operations
    pub op_add_deposit: TPCircuitFingerprintConfig<F>,
    pub op_process_withdrawal: TPCircuitFingerprintConfig<F>,

    // operation aggregators
    pub agg_state_transition: QHashOut<F>,
    pub agg_state_transition_with_events: QHashOut<F>,
    pub agg_state_transition_dummy: QHashOut<F>,
    pub agg_state_transition_with_events_dummy: QHashOut<F>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct CRWorkerToolboxRootCircuitFingerprints<F: RichField> {
    pub network_magic: u64,

    pub block_agg_register_claim_deposit_transfer: QHashOut<F>,
    pub block_agg_add_process_withdrawal_add_deposit: QHashOut<F>,
    pub block_state_transition: QHashOut<F>,
}
