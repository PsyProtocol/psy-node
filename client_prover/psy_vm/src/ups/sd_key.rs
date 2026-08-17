use plonky2::{field::goldilocks_field::GoldilocksField, hash::hash_types::RichField};
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::{
    dpn::sd_key::{SDKeySecp256k1WitnessSlot, SDKeyTransactionInfo},
    qdata::{
        checkpoint::{PsyCheckpointGlobalStateRoots, PsyCheckpointLeafStats},
        ups_signature::PsyUserProvingSessionSignatureDataCompact,
        user::PsyUserLeaf,
    },
};
use psy_crypto::hash::merkle::core::MerkleProofCore;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{ups::state_reader::StateReaderResults, vm::exec::PsyCmdWithInputAndWitness};

type GF = GoldilocksField;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "F: Serialize + serde::de::DeserializeOwned")]
pub struct SDKeyDPNStateReaderContext<F: RichField> {
    pub user_contract_tree_state_root: QHashOut<F>,
    pub deferred_tx_tree_root: QHashOut<F>,
    pub session_proof_tree_root: QHashOut<F>,
    pub checkpoint_tree_root: QHashOut<F>,
    pub chain_state_roots: PsyCheckpointGlobalStateRoots<F>,
    pub checkpoint_stats: PsyCheckpointLeafStats<F>,
}

/// UPS end-cap signature preimage used to anchor programmable state reads to
/// the same session context as `sig_hash`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "F: Serialize + serde::de::DeserializeOwned")]
pub struct SDKeySignatureContext<F: RichField> {
    pub signature_data: PsyUserProvingSessionSignatureDataCompact<F>,
    pub current_user_leaf: PsyUserLeaf<F>,
    pub nonce: F,
    pub checkpoint_tree_root: QHashOut<F>,
}

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

    /// Raw input field elements for each transaction.
    ///
    /// `transaction_inputs[i]` corresponds to `transaction_infos[i]`. Each
    /// inner vector must have length equal to the transaction's actual input
    /// count; the prover pads with zeros to match the circuit's
    /// `max_inputs_per_tx` capacity.
    pub transaction_inputs: Vec<Vec<GF>>,

    /// The hash chain of transactions (tx_stack_hash).
    /// This is built by hashing each transaction's compact call data
    /// into a running hash: h(h(h(zero, tx0), tx1), tx2) ...
    pub tx_stack_hash: QHashOut<GF>,

    /// Total transaction count in the proving session.
    pub tx_count: GF,

    /// State reader results if state reading is enabled.
    pub state_reader_results: Option<StateReaderResults<GF>>,

    /// DPN VM state-command witnesses used by programmable SDKey functions.
    /// Fixed-policy SDKeys leave this empty and use `state_reader_results`.
    #[serde(default)]
    pub dpn_state_command_witnesses: Vec<PsyCmdWithInputAndWitness<GF>>,

    /// Roots and checkpoint data required by the VM StateReaderGadget for
    /// external, other-user, IMT, and checkpoint reads.
    #[serde(default)]
    pub dpn_state_reader_context: Option<SDKeyDPNStateReaderContext<GF>>,

    /// Required when a programmable SDKey reads state. The circuit recomputes
    /// the UPS sighash from this preimage and binds its roots to the VM reader.
    #[serde(default)]
    pub signature_context: Option<SDKeySignatureContext<GF>>,

    /// Inclusion proof that `start_contract_state_root` is the value at the
    /// configured contract id in the signed user contract tree.
    #[serde(default)]
    pub contract_state_root_proof: Option<MerkleProofCore<QHashOut<GF>>>,

    /// The contract state tree root at the start of the proving session. The
    /// circuit binds this to the state reader's root when state reading is
    /// enabled.
    pub start_contract_state_root: QHashOut<GF>,

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
