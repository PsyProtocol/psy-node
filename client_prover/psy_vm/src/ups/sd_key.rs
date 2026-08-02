use plonky2::field::goldilocks_field::GoldilocksField;
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::dpn::sd_key::{SDKeySecp256k1WitnessSlot, SDKeyTransactionInfo};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::ups::state_reader::StateReaderResults;

type GF = GoldilocksField;

/// Complete input for an SD key circuit prover.
///
/// Contains all witness data needed to generate a proof that the key
/// authorization logic is satisfied for a given set of transactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SDKeyCircuitWitnessInput {
    /// User-provided circuit inputs (from the key authorization function
    /// parameters).
    pub circuit_inputs: Vec<GF>,

    /// Transaction info for each introspectable transaction slot.
    /// Length must match `config.num_introspectable_transactions`.
    pub transaction_infos: Vec<SDKeyTransactionInfo<GF>>,

    /// The hash chain of transactions (tx_stack_hash).
    /// This is built by hashing each transaction's compact call data
    /// into a running hash: h(h(h(zero, tx0), tx1), tx2) ...
    pub tx_stack_hash: QHashOut<GF>,

    /// Total transaction count in the proving session.
    pub tx_count: GF,

    /// State reader results if state reading is enabled.
    pub state_reader_results: Option<StateReaderResults<GF>>,

    /// Secp256k1 signature witness slots.
    pub secp256k1_slots: Vec<SDKeySecp256k1WitnessSlot<GF>>,

    /// Checkpoint id at the time of signing.
    pub checkpoint_id: GF,

    /// User id of the signer.
    pub user_id: GF,
}

/// The output of proving an SD key circuit.
///
/// Contains the public inputs that can be verified:
/// - hash(sig_hash, public_key_param) -- same format as existing ZK signatures
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct SDKeyProofOutput {
    /// The combined hash of sig_hash and public_key_param.
    pub public_inputs_hash: QHashOut<GF>,

    /// The circuit fingerprint (acts as the key type identifier).
    pub fingerprint: QHashOut<GF>,
}
