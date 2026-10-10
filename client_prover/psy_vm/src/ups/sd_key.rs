use plonky2::{field::goldilocks_field::GoldilocksField, hash::hash_types::RichField};
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::{
    dpn::sd_key::{SDKeyConfig, SDKeySecp256k1WitnessSlot, SDKeyTransactionInfo, MAX_INTROSPECTABLE_TRANSACTIONS},
    qdata::{
        checkpoint::{PsyCheckpointGlobalStateRoots, PsyCheckpointLeafStats},
        ups_signature::PsyUserProvingSessionSignatureDataCompact,
        user::PsyUserLeaf,
    },
};
use psy_crypto::hash::merkle::core::MerkleProofCore;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    dpn::{
        ops::op_types::{encode_indexed_op_id, DPNBuiltInDataType, DPNIndexedVarDef, DPNOpType},
        vm::def::DPNFunctionCircuitDefinition,
    },
    ups::state_reader::StateReaderResults,
    vm::exec::PsyCmdWithInputAndWitness,
};

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
pub struct SDKeyDpnCircuitWitnessInput {
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
    /// Stateless authorization functions leave this empty.
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

const SD_KEY_DPN_TRACE_WITNESS_JSON_V1: &[u8] = b"SDKEY_DPN_JSON_V1\0";

impl SDKeyDpnCircuitWitnessInput {
    /// State command witnesses contain serde types that bincode cannot decode.
    /// Keep the format tagged so older stateless bincode traces remain readable.
    pub fn to_trace_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut bytes = SD_KEY_DPN_TRACE_WITNESS_JSON_V1.to_vec();
        bytes.extend(serde_json::to_vec(self)?);
        Ok(bytes)
    }

    pub fn from_trace_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if let Some(json) = bytes.strip_prefix(SD_KEY_DPN_TRACE_WITNESS_JSON_V1) {
            Ok(serde_json::from_slice(json)?)
        } else {
            Ok(bincode::deserialize(bytes)?)
        }
    }
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

/// Expand the allow-method policy lists into concrete (contract_id, method_id)
/// pairs. The two lists must have the same length, or one of them must contain
/// exactly one value, which is broadcast across the other list.
fn allowed_contract_method_pairs(allowed_contract_ids: &[u64], allowed_method_ids: &[u32]) -> anyhow::Result<Vec<(u64, u32)>> {
    if allowed_contract_ids.is_empty() {
        anyhow::bail!("SD key allowed contract_id list must not be empty");
    }
    if allowed_method_ids.is_empty() {
        anyhow::bail!("SD key allowed method_id list must not be empty");
    }

    if allowed_contract_ids.len() == allowed_method_ids.len() {
        return Ok(allowed_contract_ids.iter().copied().zip(allowed_method_ids.iter().copied()).collect());
    }

    if allowed_contract_ids.len() == 1 {
        return Ok(allowed_method_ids
            .iter()
            .copied()
            .map(|method_id| (allowed_contract_ids[0], method_id))
            .collect());
    }

    if allowed_method_ids.len() == 1 {
        return Ok(allowed_contract_ids
            .iter()
            .copied()
            .map(|contract_id| (contract_id, allowed_method_ids[0]))
            .collect());
    }

    anyhow::bail!("SD key allowed contract_id and method_id lists must have the same length, or one list must contain exactly one value");
}

/// Allocates canonical dense definition indices while building a
/// [`DPNFunctionCircuitDefinition`] by hand.
struct DpnDefBuilder {
    definitions: Vec<DPNIndexedVarDef>,
    next_target: usize,
    next_bool: usize,
}

impl DpnDefBuilder {
    fn new() -> Self {
        Self {
            definitions: Vec::new(),
            next_target: 0,
            next_bool: 0,
        }
    }

    fn push(&mut self, data_type: DPNBuiltInDataType, index: usize, op_type: DPNOpType, inputs: Vec<u64>) -> u64 {
        self.definitions.push(DPNIndexedVarDef {
            data_type,
            index,
            op_type,
            inputs,
        });
        encode_indexed_op_id(data_type, index)
    }

    fn target(&mut self, op_type: DPNOpType, inputs: Vec<u64>) -> u64 {
        let index = self.next_target;
        self.next_target += 1;
        self.push(DPNBuiltInDataType::Target, index, op_type, inputs)
    }

    fn bool_op(&mut self, op_type: DPNOpType, inputs: Vec<u64>) -> u64 {
        let index = self.next_bool;
        self.next_bool += 1;
        self.push(DPNBuiltInDataType::Bool, index, op_type, inputs)
    }
}

/// Build the read-only DPN authorization function equivalent of the legacy
/// fixed allow-method SD key policy: every introspectable transaction slot must
/// call one of the allowed (contract_id, method_id) pairs, and the session
/// transaction count must equal `expected_tx_count`.
///
/// The result is an ordinary read-only DPN function definition, so it can be
/// registered through the same programmable SD key entry point
/// (`SDKeyDpnCircuitGadget::build_from_dpn_function`) and proven with the shared
/// `SDKeyDpnCircuitWitnessInput`.
pub fn build_allow_method_policy_function(
    allowed_contract_ids: &[u64],
    allowed_method_ids: &[u32],
    expected_tx_count: u64,
) -> anyhow::Result<DPNFunctionCircuitDefinition> {
    if expected_tx_count == 0 {
        anyhow::bail!("SD key expected_tx_count must be greater than zero");
    }
    if expected_tx_count > MAX_INTROSPECTABLE_TRANSACTIONS as u64 {
        anyhow::bail!(
            "SD key expected_tx_count {} exceeds MAX_INTROSPECTABLE_TRANSACTIONS {}",
            expected_tx_count,
            MAX_INTROSPECTABLE_TRANSACTIONS
        );
    }
    let pairs = allowed_contract_method_pairs(allowed_contract_ids, allowed_method_ids)?;

    let mut builder = DpnDefBuilder::new();

    // Per-slot: OR over pairs of (contract_id == c AND method_id == m).
    let mut slot_allowed_ids = Vec::with_capacity(expected_tx_count as usize);
    for tx_index in 0..expected_tx_count {
        let tx_index_id = builder.target(DPNOpType::Constant, vec![tx_index]);
        let contract_id_id = builder.target(DPNOpType::GetTransactionContractId, vec![tx_index_id]);
        let method_id_id = builder.target(DPNOpType::GetTransactionMethodId, vec![tx_index_id]);

        let mut slot_allowed: Option<u64> = None;
        for (contract_id, method_id) in &pairs {
            let expected_contract_id = builder.target(DPNOpType::Constant, vec![*contract_id]);
            let expected_method_id = builder.target(DPNOpType::Constant, vec![*method_id as u64]);
            let contract_matches = builder.bool_op(DPNOpType::Eq, vec![contract_id_id, expected_contract_id]);
            let method_matches = builder.bool_op(DPNOpType::Eq, vec![method_id_id, expected_method_id]);
            let pair_matches = builder.bool_op(DPNOpType::BoolAnd, vec![contract_matches, method_matches]);
            slot_allowed = Some(match slot_allowed {
                None => pair_matches,
                Some(previous) => builder.bool_op(DPNOpType::BoolOr, vec![previous, pair_matches]),
            });
        }
        slot_allowed_ids.push(slot_allowed.expect("allowed pair list is non-empty"));
    }

    // AND across slots, and require the exact transaction count.
    let mut all_slots = slot_allowed_ids[0];
    for slot_allowed in &slot_allowed_ids[1..] {
        all_slots = builder.bool_op(DPNOpType::BoolAnd, vec![all_slots, *slot_allowed]);
    }
    let tx_count_id = builder.target(DPNOpType::GetTransactionCount, vec![]);
    let expected_count_id = builder.target(DPNOpType::Constant, vec![expected_tx_count]);
    let count_matches = builder.bool_op(DPNOpType::Eq, vec![tx_count_id, expected_count_id]);
    let authorized = builder.bool_op(DPNOpType::BoolAnd, vec![all_slots, count_matches]);

    Ok(DPNFunctionCircuitDefinition {
        name: "allow_method_sd_key_policy".to_string(),
        method_id: 0,
        circuit_inputs: vec![],
        circuit_outputs: vec![authorized],
        state_commands: vec![],
        state_command_resolution_indices: vec![],
        assertions: vec![],
        definitions: builder.definitions,
        events: vec![],
    })
}

/// Build an allow-method DPN function and its SD-key registration config.
/// Callers register the returned pair through `register_sd_key_dpn_circuit`.
pub fn build_allow_method_policy(
    allowed_contract_ids: &[u64],
    allowed_method_ids: &[u32],
    expected_tx_count: u64,
) -> anyhow::Result<(DPNFunctionCircuitDefinition, SDKeyConfig)> {
    let function = build_allow_method_policy_function(allowed_contract_ids, allowed_method_ids, expected_tx_count)?;
    let config = SDKeyConfig {
        num_introspectable_transactions: expected_tx_count as u32,
        transaction_count_policy: None,
        can_read_state: false,
        contract_state_tree_height: psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT,
        requires_secp256k1: false,
        num_secp256k1_slots: 0,
        contract_id: allowed_contract_ids.first().copied().unwrap_or(0),
    };
    Ok((function, config))
}

/// Build an allow-method policy and circuit configuration with a variable
/// transaction count bounded by the inclusive `[min_tx_count, max_tx_count]`
/// range. `max_tx_count` determines the fixed circuit capacity.
pub fn build_allow_method_policy_range(
    allowed_contract_ids: &[u64],
    allowed_method_ids: &[u32],
    min_tx_count: u64,
    max_tx_count: u64,
) -> anyhow::Result<(DPNFunctionCircuitDefinition, SDKeyConfig)> {
    if min_tx_count > max_tx_count {
        anyhow::bail!("SD key min_tx_count {} exceeds max_tx_count {}", min_tx_count, max_tx_count);
    }
    if max_tx_count == 0 {
        anyhow::bail!("SD key max_tx_count must be greater than zero");
    }
    if max_tx_count > MAX_INTROSPECTABLE_TRANSACTIONS as u64 {
        anyhow::bail!(
            "SD key max_tx_count {} exceeds MAX_INTROSPECTABLE_TRANSACTIONS {}",
            max_tx_count,
            MAX_INTROSPECTABLE_TRANSACTIONS
        );
    }
    anyhow::ensure!(
        !allowed_contract_ids.is_empty(),
        "SD key allow-method policy requires at least one allowed contract id"
    );
    anyhow::ensure!(
        !allowed_method_ids.is_empty(),
        "SD key allow-method policy requires at least one allowed method id"
    );
    if min_tx_count == max_tx_count {
        return build_allow_method_policy(allowed_contract_ids, allowed_method_ids, max_tx_count);
    }
    let pairs = allowed_contract_method_pairs(allowed_contract_ids, allowed_method_ids)?;
    let mut builder = DpnDefBuilder::new();
    let authorized = builder.bool_op(DPNOpType::ConstantTrue, vec![]);
    let function = DPNFunctionCircuitDefinition {
        name: "allow_method_sd_key_policy".to_string(),
        method_id: 0,
        circuit_inputs: vec![],
        circuit_outputs: vec![authorized],
        state_commands: vec![],
        state_command_resolution_indices: vec![],
        assertions: vec![],
        definitions: builder.definitions,
        events: vec![],
    };
    let config = SDKeyConfig {
        num_introspectable_transactions: max_tx_count as u32,
        transaction_count_policy: Some(psy_client_data::dpn::sd_key::SDKeyTransactionCountPolicy {
            min_tx_count: min_tx_count as u32,
            max_tx_count: max_tx_count as u32,
            allowed_calls: pairs
                .into_iter()
                .map(|(contract_id, method_id)| psy_client_data::dpn::sd_key::SDKeyAllowedTransactionCall {
                    contract_id,
                    method_id,
                    caller_contract_id: None,
                })
                .collect(),
        }),
        can_read_state: false,
        contract_state_tree_height: psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT,
        requires_secp256k1: false,
        num_secp256k1_slots: 0,
        contract_id: allowed_contract_ids.first().copied().unwrap_or(0),
    };
    Ok((function, config))
}

/// Like `build_allow_method_policy_range`, but each allowed call also has a
/// required caller contract. User-initiated calls use
/// `DEFAULT_CALLER_CONTRACT_ID_U64`; deferred calls use the invoking contract.
pub fn build_allow_caller_and_method_policy_range(
    allowed_caller_contract_ids: &[u64],
    allowed_contract_ids: &[u64],
    allowed_method_ids: &[u32],
    min_tx_count: u64,
    max_tx_count: u64,
) -> anyhow::Result<(DPNFunctionCircuitDefinition, SDKeyConfig)> {
    let pairs = allowed_contract_method_pairs(allowed_contract_ids, allowed_method_ids)?;
    anyhow::ensure!(
        allowed_caller_contract_ids.len() == pairs.len(),
        "SD key caller_id list must have one entry per allowed (contract_id, method_id) pair"
    );
    let (_, mut config) = build_allow_method_policy_range(allowed_contract_ids, allowed_method_ids, min_tx_count, max_tx_count)?;
    config.transaction_count_policy = Some(psy_client_data::dpn::sd_key::SDKeyTransactionCountPolicy {
        min_tx_count: min_tx_count as u32,
        max_tx_count: max_tx_count as u32,
        allowed_calls: pairs
            .into_iter()
            .zip(allowed_caller_contract_ids.iter().copied())
            .map(|((contract_id, method_id), caller_contract_id)| psy_client_data::dpn::sd_key::SDKeyAllowedTransactionCall {
                contract_id,
                method_id,
                caller_contract_id: Some(caller_contract_id),
            })
            .collect(),
    });
    let mut builder = DpnDefBuilder::new();
    let authorized = builder.bool_op(DPNOpType::ConstantTrue, vec![]);
    let function = DPNFunctionCircuitDefinition {
        name: "allow_caller_and_method_sd_key_policy".to_string(),
        method_id: 0,
        circuit_inputs: vec![],
        circuit_outputs: vec![authorized],
        state_commands: vec![],
        state_command_resolution_indices: vec![],
        assertions: vec![],
        definitions: builder.definitions,
        events: vec![],
    };
    Ok((function, config))
}

/// Derive the registration config for an arbitrary compiled read-only DPN
/// authorization function, mirroring what the SD-key compiler computes from
/// the source program: the introspectable transaction count follows the
/// highest transaction slot the function actually reads, state reading uses
/// the maximum contract state tree height, and the remaining capabilities are
/// disabled.
///
/// Transaction slot arguments are resolved through `Constant` definitions;
/// non-constant slot arguments leave the count at zero so the caller should
/// prefer compiler-produced `SDKeyConfig` values when available.
pub fn sd_key_config_for_dpn_function(definition: &DPNFunctionCircuitDefinition) -> SDKeyConfig {
    let constant_by_id: std::collections::HashMap<u64, u64> = definition
        .definitions
        .iter()
        .filter(|def| def.op_type == DPNOpType::Constant)
        .filter_map(|def| def.inputs.first().map(|value| (def.get_combined_data_type_index(), *value)))
        .collect();

    let tx_slot_of = |def: &DPNIndexedVarDef| -> Option<u64> {
        let slot_ref = def.inputs.first()?;
        constant_by_id.get(slot_ref).copied()
    };

    let mut num_introspectable_transactions: u32 = 0;
    for def in &definition.definitions {
        let slot = match def.op_type {
            DPNOpType::GetTransactionContractId
            | DPNOpType::GetTransactionCallerContractId
            | DPNOpType::GetTransactionMethodId
            | DPNOpType::GetTransactionInputsHash
            | DPNOpType::GetTransactionInputLength
            | DPNOpType::GetTransactionInputWord => tx_slot_of(def),
            _ => None,
        };
        if let Some(slot) = slot {
            num_introspectable_transactions = num_introspectable_transactions.max(slot as u32 + 1);
        }
    }

    SDKeyConfig {
        num_introspectable_transactions,
        transaction_count_policy: None,
        can_read_state: false,
        contract_state_tree_height: if definition.state_commands.is_empty() {
            0
        } else {
            psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT
        },
        requires_secp256k1: false,
        num_secp256k1_slots: 0,
        contract_id: psy_config::network_constants::DEFAULT_CALLER_CONTRACT_ID_U64,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn allow_method_policy_function_validates_inputs() {
        let error = build_allow_method_policy_function(&[1], &[2], 0).unwrap_err();
        assert!(error.to_string().contains("greater than zero"));

        let error = build_allow_method_policy_function(&[1], &[2], MAX_INTROSPECTABLE_TRANSACTIONS as u64 + 1).unwrap_err();
        assert!(error.to_string().contains("MAX_INTROSPECTABLE_TRANSACTIONS"));

        assert!(build_allow_method_policy_function(&[], &[2], 1).unwrap_err().to_string().contains("contract_id list"));
        assert!(build_allow_method_policy_function(&[1], &[], 1).unwrap_err().to_string().contains("method_id list"));
        assert!(build_allow_method_policy_function(&[1, 2], &[3, 4, 5], 1)
            .unwrap_err()
            .to_string()
            .contains("same length"));
    }

    #[test]
    fn allow_method_policy_range_accepts_protocol_capacity() {
        let (_, config) = build_allow_method_policy_range(&[5, 0, 0], &[3375543263, 2789897329, 3998182541], 3, 64).unwrap();
        assert_eq!(config.num_introspectable_transactions, 64);
        let policy = config.transaction_count_policy.unwrap();
        assert_eq!((policy.min_tx_count, policy.max_tx_count), (3, 64));
        assert!(build_allow_method_policy_range(&[5], &[3375543263], 3, 65)
            .unwrap_err()
            .to_string()
            .contains("MAX_INTROSPECTABLE_TRANSACTIONS"));
    }

    #[test]
    fn allow_caller_and_method_policy_range_requires_aligned_callers() {
        let (_, config) = build_allow_caller_and_method_policy_range(&[7, 5], &[5, 0], &[10, 20], 1, 3).unwrap();
        let calls = config.transaction_count_policy.unwrap().allowed_calls;
        assert_eq!(calls[0].caller_contract_id, Some(7));
        assert_eq!(calls[1].caller_contract_id, Some(5));
        assert!(build_allow_caller_and_method_policy_range(&[7], &[5, 0], &[10, 20], 1, 3)
            .unwrap_err()
            .to_string()
            .contains("one entry per allowed"));
    }

    #[test]
    fn allow_method_policy_function_builds_canonical_definition() {
        let definition = build_allow_method_policy_function(&[7], &[10, 20], 2).unwrap();
        // read-only, view-only, canonical dense indices
        definition.validate_sd_key_read_only().unwrap();
        assert!(definition.is_view_function());
        assert!(definition.state_commands.is_empty());
        assert_eq!(definition.circuit_outputs.len(), 1);
        assert!(definition.circuit_inputs.is_empty());
        // 2 slots x (1 tx-index const + 2 tx gets) + 2 slots x 2 pairs x 2 consts
        // + GetTransactionCount + expected-count const
        let target_count = definition
            .definitions
            .iter()
            .filter(|def| def.data_type == DPNBuiltInDataType::Target)
            .count();
        assert_eq!(target_count, 2 * 3 + 2 * 2 * 2 + 2);
    }

    #[test]
    fn allow_method_policy_function_broadcasts_single_contract_across_methods() {
        let definition = build_allow_method_policy_function(&[7], &[10, 20], 1).unwrap();
        definition.validate_sd_key_read_only().unwrap();
    }

    #[test]
    fn sd_key_config_for_dpn_function_counts_introspected_slots() {
        let definition = build_allow_method_policy_function(&[7], &[10, 20], 3).unwrap();
        let config = sd_key_config_for_dpn_function(&definition);
        assert_eq!(config.num_introspectable_transactions, 3);
        assert!(!config.can_read_state);
        assert_eq!(config.contract_state_tree_height, 0);
        assert_eq!(config.contract_id, psy_config::network_constants::DEFAULT_CALLER_CONTRACT_ID_U64);

        let empty = build_allow_method_policy_function(&[7], &[10], 1).unwrap();
        let mut empty = empty;
        empty.definitions.retain(|def| !matches!(def.op_type, DPNOpType::GetTransactionContractId | DPNOpType::GetTransactionMethodId));
        let config = sd_key_config_for_dpn_function(&empty);
        assert_eq!(config.num_introspectable_transactions, 0);
    }
}
