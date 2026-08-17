use kvq::traits::KVQSerializable;
use plonky2::{field::goldilocks_field::GoldilocksField, hash::hash_types::RichField};
use psy_client_common::{
    data::qhashout::QHashOut,
    traits::to_qfelts::{QFeltSized, ToQFelts},
};
use psy_crypto::hash::traits::{hasher::FieldQHasher, qhashable::QFieldHashable};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::dpn::proving_session::DPNProvingSessionCompactMethodCall;

/// Maximum number of transactions available to transaction introspection.
pub const MAX_INTROSPECTABLE_TRANSACTIONS: u32 = 32;

/// Maximum number of Felt words available from each transaction's calldata.
pub const SDKEY_MAX_CALLDATA_WORDS: u32 = 128;

/// Backwards-compatible name for the calldata capacity limit.
pub const SDKEY_MAX_INPUTS_PER_TX: u32 = SDKEY_MAX_CALLDATA_WORDS;

/// Compact transaction info for SD key introspection.
///
/// Each transaction in a proving session can be introspected by the SD key
/// circuit at a compile-time-constant index. This struct holds the information
/// available for each transaction: the contract being called, the method,
/// and a hash of the inputs.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Default, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct SDKeyTransactionInfo<F: RichField> {
    /// Which contract this transaction calls.
    pub contract_id: F,
    /// The method ordinal (method_id) of the contract function being called.
    pub method_id: F,
    /// The calling contract id (or default caller for user-initiated txs).
    pub caller_contract_id: F,
    /// Number of inputs to the function call.
    pub inputs_length: F,
    /// Hash of the inputs.
    pub inputs_hash: QHashOut<F>,
}

impl<F: RichField> From<DPNProvingSessionCompactMethodCall<F>> for SDKeyTransactionInfo<F> {
    fn from(call: DPNProvingSessionCompactMethodCall<F>) -> Self {
        Self {
            contract_id: call.contract_id,
            method_id: call.method_id,
            caller_contract_id: call.caller_contract_id,
            inputs_length: call.inputs_length,
            inputs_hash: call.inputs_hash,
        }
    }
}

impl<F: RichField> QFeltSized for SDKeyTransactionInfo<F> {
    fn q_felt_size() -> usize {
        8
    }
}

impl<F: RichField> ToQFelts<F> for SDKeyTransactionInfo<F> {
    fn to_qfelts(&self) -> Vec<F> {
        vec![
            self.contract_id,
            self.method_id,
            self.caller_contract_id,
            self.inputs_length,
            self.inputs_hash.0.elements[0],
            self.inputs_hash.0.elements[1],
            self.inputs_hash.0.elements[2],
            self.inputs_hash.0.elements[3],
        ]
    }

    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != 8 {
            panic!("Invalid number of elements for SDKeyTransactionInfo, expected 8, got {}", felts.len());
        }
        Self {
            contract_id: felts[0],
            method_id: felts[1],
            caller_contract_id: felts[2],
            inputs_length: felts[3],
            inputs_hash: QHashOut::from_felt_slice(&felts[4..]),
        }
    }
}

impl<F: RichField> QFieldHashable<F> for SDKeyTransactionInfo<F> {
    fn qfhash<H: FieldQHasher<F>>(&self) -> QHashOut<F> {
        H::q_hash_many(&self.to_qfelts())
    }
}

impl<F: RichField> KVQSerializable for SDKeyTransactionInfo<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

/// Configuration for a software-defined key circuit.
///
/// Defines what capabilities the key circuit has and what it can introspect.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Default, TS)]
#[ts(export)]
pub struct SDKeyConfig {
    /// Number of transactions the key circuit can introspect.
    pub num_introspectable_transactions: u32,

    /// Whether this key circuit can read contract state at the current
    /// checkpoint.
    pub can_read_state: bool,

    /// Height of the contract state tree if state reading is enabled.
    pub contract_state_tree_height: u8,

    /// Whether this key circuit verifies secp256k1 signatures.
    pub requires_secp256k1: bool,

    /// Number of secp256k1 signature verification slots in the circuit.
    pub num_secp256k1_slots: u32,

    /// Contract id used for DPN state reads.
    pub contract_id: u64,
}

/// Compiled output of an SD key definition.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[ts(export)]
pub struct SDKeyDefinition {
    /// The compiled authorization logic as a DPN function circuit.
    pub authorization_circuit: Vec<u8>,
    /// SD key configuration.
    pub config: SDKeyConfig,
    /// Name of the key definition.
    pub name: String,
}

impl KVQSerializable for SDKeyDefinition {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

/// Secp256k1 signature data provided as witness to the SD key circuit.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Default, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct SDKeySecp256k1WitnessSlot<F: RichField> {
    pub public_key: [F; 16],
    pub msg_hash: QHashOut<F>,
    pub signature: [F; 16],
}

impl<F: RichField> KVQSerializable for SDKeySecp256k1WitnessSlot<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}
