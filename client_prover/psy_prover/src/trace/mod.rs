use plonky2::field::{goldilocks_field::GoldilocksField, types::PrimeField64};
use psy_client_common::{
    args::DPNSoftwareDefinedCallData,
    data::{alt::AltVerifierOnlyCircuitData, qhashout::QHashOut},
};
use psy_client_data::{
    dpn::cfc_context_input::DapenCFCUserTransactionInputContext,
    guta::{api::ContractStateUpdate, end_cap_input::SubmitUserEndCapNonProofInput, stats::GUTAStats},
    qdata::{
        checkpoint::{PsyCheckpointGlobalStateRoots, PsyCheckpointLeaf},
        contract_inclusion::PsyContractFunctionInclusionProof,
        imt_proof::IMTContractStateUpdate,
    },
    qstore::imm::cmd_processor::DPNStateCmdWitness,
    ups::ups_context_input::UserProvingSessionHeader,
};
use psy_crypto::hash::merkle::core::{DeltaMerkleProofCore, MerkleProofCore};
use psy_vm::{
    dpn::ops::state_cmd::data::DPNStateCmd,
    vm::{cfc_input::DapenContractFunctionCircuitInput, exec::PsyCmdWithInputAndWitness},
};
use serde::{Deserialize, Serialize};

type F = GoldilocksField;

fn default_plonky2_sdc_contract_state_tree_height() -> u8 {
    psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[serde(transparent)]
pub struct TraceStepId(pub usize);

impl From<usize> for TraceStepId {
    fn from(value: usize) -> Self {
        TraceStepId(value)
    }
}

impl From<TraceStepId> for usize {
    fn from(value: TraceStepId) -> Self {
        value.0
    }
}

// ---------------------------------------------------------------------------
// Top-level trace
// ---------------------------------------------------------------------------

/// One UPS session's complete execution trace.
/// Produced by `generate_tx_trace`, consumed by `prove_tx_trace`.
/// Self-contained for lps-free step proving: no lps queries, no re-execution.
#[derive(Clone, Serialize, Deserialize)]
pub struct TxTrace {
    pub meta: TraceMeta,
    pub anchor: SessionAnchor,
    pub ups_start_witness: UpsStartWitness,

    /// Contract code definitions needed to register CFC circuits before prove.
    pub contract_codes: Vec<TraceContractCode>,

    /// Arena: index = TraceStepId.0 = prove order.
    pub steps: Vec<TraceStep>,

    /// Final submit material (nonce-applied end-cap input, sign call, tx hash).
    pub finalization: TxFinalization,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TraceMeta {
    pub network_magic: u64,
    pub user_id: u64,
    pub public_key: QHashOut<F>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SessionAnchor {
    pub start_checkpoint_id: u64,
    pub checkpoint_leaf: PsyCheckpointLeaf<F>,
    pub global_state_roots: PsyCheckpointGlobalStateRoots<F>,
    pub ups_step_circuit_whitelist_root: QHashOut<F>,
}

impl GeneratedTxTraceJson {
    pub fn from_trace(trace: &TxTrace, call_data_json: serde_json::Value) -> anyhow::Result<Self> {
        let payload = serde_json::to_string(trace).map_err(|e| anyhow::anyhow!("failed to serialize trace: {}", e))?;
        Ok(GeneratedTxTraceJson {
            user_id: trace.meta.user_id.to_string(),
            pk_hash: trace.meta.public_key.to_string(),
            sig_hash: trace.finalization.sig_hash.to_string(),
            tx_hash: trace.finalization.tx_hash.to_string(),
            call_data: call_data_json,
            tx_count: trace.steps.len() as u64,
            trace: TracePayload {
                encoding: "json".to_string(),
                payload,
            },
        })
    }
}

impl ProvedTxResultJson {
    pub fn new(sig_hash: String, tx_hash: String, checkpoint_id: Option<u64>, status: String) -> Self {
        ProvedTxResultJson {
            sig_hash,
            tx_hash,
            checkpoint_id,
            status,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
/// Minimal envelope returned by generate-tx-trace.
pub struct GeneratedTxTraceJson {
    pub user_id: String,
    pub pk_hash: String,
    pub sig_hash: String,
    pub tx_hash: String,
    pub call_data: serde_json::Value,
    pub tx_count: u64,
    pub trace: TracePayload,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TracePayload {
    pub encoding: String,
    pub payload: String,
}

#[derive(Clone, Serialize, Deserialize)]
/// Envelope returned by prove-tx-trace.
pub struct ProvedTxResultJson {
    pub sig_hash: String,
    pub tx_hash: String,
    pub checkpoint_id: Option<u64>,
    pub status: String,
}

// ---------------------------------------------------------------------------
// Simulation metadata
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxStorageRead {
    pub user_id: u64,
    pub contract_id: u64,
    pub slot_index: u64,
    pub value: QHashOut<F>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxStorageWrite {
    pub user_id: u64,
    pub contract_id: u64,
    pub slot_index: u64,
    pub old_value: QHashOut<F>,
    pub new_value: QHashOut<F>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TxStorageData {
    pub reads: Vec<TxStorageRead>,
    pub writes: Vec<TxStorageWrite>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContractCallResultArgs {
    pub contract_id: u64,
    pub method_name: String,
    pub inputs: Vec<u64>,
    pub outputs: Vec<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContractCallResultData {
    pub contract_calls: Vec<ContractCallResultArgs>,
    pub software_defined_call: DPNSoftwareDefinedCallData,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxEndCapData {
    pub checkpoint_id: u64,
    pub user_id: u64,
    pub global_user_tree_height: u8,
    pub start_user_leaf_hash: QHashOut<F>,
    pub end_user_leaf_hash: QHashOut<F>,
    pub checkpoint_tree_root_hash: QHashOut<F>,
    pub stats: GUTAStats<F>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxMetadata {
    pub tx_hash: QHashOut<F>,
    pub end_cap_data: TxEndCapData,
    pub contract_call_data: ContractCallResultData,
    pub storage_data: TxStorageData,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SimulatedTxMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<QHashOut<F>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_cap_data: Option<TxEndCapData>,
    pub contract_call_data: ContractCallResultData,
    pub storage_data: TxStorageData,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SimulatedTxJson {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated: Option<GeneratedTxTraceJson>,
    pub metadata: SimulatedTxMetadata,
}

impl TxEndCapData {
    pub fn from_user_ec_input(input: &SubmitUserEndCapNonProofInput<F>) -> Self {
        Self {
            checkpoint_id: input.core.checkpoint_id.to_canonical_u64(),
            user_id: input.core.state_transition.user_id.to_canonical_u64(),
            global_user_tree_height: psy_config::network_constants::GLOBAL_USER_TREE_HEIGHT,
            start_user_leaf_hash: input.core.state_transition.start_user_leaf_hash,
            end_user_leaf_hash: input.core.state_transition.end_user_leaf_hash,
            checkpoint_tree_root_hash: input.core.state_transition.checkpoint_tree_root_hash,
            stats: input.core.stats,
        }
    }
}

impl TxStorageData {
    pub(crate) fn from_steps(current_user_id: u64, steps: &[TraceStep]) -> Self {
        let mut storage = TxStorageData::default();
        for step in steps {
            let Some(cfc) = step.as_cfc() else {
                continue;
            };
            storage.extend_from_cmd_witnesses(current_user_id, cfc.contract_id, &cfc.cfc_witness.cmd_witnesses);
        }
        storage
    }

    pub fn from_trace(trace: &TxTrace) -> Self {
        let mut storage = Self::from_steps(trace.meta.user_id, &trace.steps);
        storage.extend_from_user_ec_input(&trace.finalization.submit_end_cap_input);
        storage
    }

    fn extend_from_user_ec_input(&mut self, input: &SubmitUserEndCapNonProofInput<F>) {
        let user_id = input.core.state_transition.user_id.to_canonical_u64();
        for contract_update in &input.contract_state_updates {
            let contract_id = contract_update.user_contract_tree_update_proof.index;
            for update in &contract_update.contract_state_tree_updates {
                match update {
                    ContractStateUpdate::Positional { delta_proof } => {
                        self.push_write(user_id, contract_id, delta_proof.index, delta_proof.old_value, delta_proof.new_value);
                    }
                    ContractStateUpdate::IMT { update } => match update {
                        IMTContractStateUpdate::Update { delta_proof, .. } => {
                            self.push_write(user_id, contract_id, delta_proof.index, delta_proof.old_value, delta_proof.new_value);
                        }
                        IMTContractStateUpdate::Insert {
                            predecessor_delta_proof,
                            new_leaf_delta_proof,
                            ..
                        } => {
                            self.push_write(
                                user_id,
                                contract_id,
                                predecessor_delta_proof.index,
                                predecessor_delta_proof.old_value,
                                predecessor_delta_proof.new_value,
                            );
                            self.push_write(
                                user_id,
                                contract_id,
                                new_leaf_delta_proof.index,
                                new_leaf_delta_proof.old_value,
                                new_leaf_delta_proof.new_value,
                            );
                        }
                    },
                }
            }
        }
    }

    fn extend_from_cmd_witnesses(&mut self, current_user_id: u64, current_contract_id: u64, cmd_witnesses: &[PsyCmdWithInputAndWitness<F>]) {
        for cmd_witness in cmd_witnesses {
            match (&cmd_witness.state_cmd, &cmd_witness.witness) {
                (DPNStateCmd::GetSelfUserCurrentContractStateSlotHash(_), DPNStateCmdWitness::MerkleProof(proof))
                | (DPNStateCmd::GetSelfUserCurrentContractStateSlotSingle(_), DPNStateCmdWitness::MerkleProof(proof)) => {
                    self.push_read(current_user_id, current_contract_id, proof.index, proof.value);
                }
                (DPNStateCmd::GetSelfUserCurrentContractStateSlotRange(_), DPNStateCmdWitness::MerkleProofArray(proofs)) => {
                    for proof in proofs {
                        self.push_read(current_user_id, current_contract_id, proof.index, proof.value);
                    }
                }
                (DPNStateCmd::GetSelfUserExternalContractStateSlotHash(cmd), DPNStateCmdWitness::MerkleProofArray(proofs)) => {
                    for proof in proofs.iter().skip(1) {
                        self.push_read(current_user_id, cmd.contract_id, proof.index, proof.value);
                    }
                }
                (DPNStateCmd::GetSelfUserExternalContractStateSlotSingle(cmd), DPNStateCmdWitness::MerkleProofArray(proofs)) => {
                    for proof in proofs.iter().skip(1) {
                        self.push_read(current_user_id, cmd.contract_id, proof.index, proof.value);
                    }
                }
                (DPNStateCmd::GetSelfUserExternalContractStateSlotRange(cmd), DPNStateCmdWitness::MerkleProofArray(proofs)) => {
                    for proof in proofs.iter().skip(1) {
                        self.push_read(current_user_id, cmd.contract_id, proof.index, proof.value);
                    }
                }
                (DPNStateCmd::GetOtherUserContractStateSlotHash(cmd), DPNStateCmdWitness::ReadOtherUserContractState(read)) => {
                    for proof in &read.state_slot_proofs {
                        self.push_read(cmd.user_id, cmd.contract_id, proof.index, proof.value);
                    }
                }
                (DPNStateCmd::GetOtherUserContractStateSlotSingle(cmd), DPNStateCmdWitness::ReadOtherUserContractState(read)) => {
                    for proof in &read.state_slot_proofs {
                        self.push_read(cmd.user_id, cmd.contract_id, proof.index, proof.value);
                    }
                }
                (DPNStateCmd::GetOtherUserContractStateSlotRange(cmd), DPNStateCmdWitness::ReadOtherUserContractState(read)) => {
                    for proof in &read.state_slot_proofs {
                        self.push_read(cmd.user_id, cmd.contract_id, proof.index, proof.value);
                    }
                }
                (DPNStateCmd::GetSelfUserCurrentIMTContractStateValue(_), DPNStateCmdWitness::IMTRead(read)) => {
                    self.push_read(current_user_id, current_contract_id, read.merkle_proof.index, read.merkle_proof.value);
                }
                (DPNStateCmd::GetSelfUserExternalIMTContractStateValue(cmd), DPNStateCmdWitness::IMTSelfUserExternalRead(read)) => {
                    self.push_read(current_user_id, cmd.contract_id, read.state_slot_proof.index, read.state_slot_proof.value);
                }
                (DPNStateCmd::GetOtherUserIMTContractStateValue(cmd), DPNStateCmdWitness::IMTOtherUserRead(read)) => {
                    self.push_read(cmd.user_id, cmd.contract_id, read.state_slot_proof.index, read.state_slot_proof.value);
                }
                (DPNStateCmd::ContainsSelfUserCurrentIMTContractStateValue(_), DPNStateCmdWitness::IMTContains(read)) => {
                    self.push_read(current_user_id, current_contract_id, read.merkle_proof.index, read.merkle_proof.value);
                }
                (DPNStateCmd::ContainsOtherUserIMTContractStateValue(cmd), DPNStateCmdWitness::IMTContainsOtherUser(read)) => {
                    self.push_read(cmd.user_id, cmd.contract_id, read.state_slot_proof.index, read.state_slot_proof.value);
                }
                _ => {}
            }
        }
    }

    fn push_read(&mut self, user_id: u64, contract_id: u64, slot_index: u64, value: QHashOut<F>) {
        self.reads.push(TxStorageRead {
            user_id,
            contract_id,
            slot_index,
            value,
        });
    }

    fn push_write(&mut self, user_id: u64, contract_id: u64, slot_index: u64, old_value: QHashOut<F>, new_value: QHashOut<F>) {
        if old_value == new_value {
            return;
        }
        self.writes.push(TxStorageWrite {
            user_id,
            contract_id,
            slot_index,
            old_value,
            new_value,
        });
    }
}

fn contract_call_results(steps: &[TraceStep]) -> Vec<ContractCallResultArgs> {
    steps
        .iter()
        .filter_map(|step| match step {
            TraceStep::Standard(cfc) | TraceStep::Inlined(cfc) | TraceStep::Deferred(cfc) => Some(ContractCallResultArgs {
                contract_id: cfc.contract_id,
                method_name: cfc.method_name.clone(),
                inputs: cfc.cfc_witness.inputs.iter().map(|v| v.to_canonical_u64()).collect(),
                outputs: cfc.cfc_witness.outputs.iter().map(|v| v.to_canonical_u64()).collect(),
            }),
            TraceStep::BurnFee(_) | TraceStep::ExternalProof(_) | TraceStep::ZkSign(_) => None,
        })
        .collect()
}

impl TxMetadata {
    pub fn from_trace(trace: &TxTrace) -> Self {
        TxMetadata {
            tx_hash: trace.finalization.tx_hash,
            end_cap_data: TxEndCapData::from_user_ec_input(&trace.finalization.submit_end_cap_input),
            contract_call_data: ContractCallResultData {
                contract_calls: contract_call_results(&trace.steps),
                software_defined_call: trace.finalization.software_defined_call.clone(),
            },
            storage_data: TxStorageData::from_trace(trace),
        }
    }
}

impl SimulatedTxMetadata {
    pub fn from_view_steps(user_id: u64, steps: &[TraceStep], software_defined_call: DPNSoftwareDefinedCallData) -> anyhow::Result<Self> {
        let storage_data = TxStorageData::from_steps(user_id, steps);
        anyhow::ensure!(storage_data.writes.is_empty(), "fee-free view simulation produced storage writes");
        Ok(Self {
            tx_hash: None,
            end_cap_data: None,
            contract_call_data: ContractCallResultData {
                contract_calls: contract_call_results(steps),
                software_defined_call,
            },
            storage_data,
        })
    }
}

impl From<TxMetadata> for SimulatedTxMetadata {
    fn from(metadata: TxMetadata) -> Self {
        Self {
            tx_hash: Some(metadata.tx_hash),
            end_cap_data: Some(metadata.end_cap_data),
            contract_call_data: metadata.contract_call_data,
            storage_data: metadata.storage_data,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct UpsStartWitness {
    pub ups_header: UserProvingSessionHeader<F>,
    #[serde(default)]
    pub state_roots: PsyCheckpointGlobalStateRoots<F>,
    pub checkpoint_tree_proof: MerkleProofCore<QHashOut<F>>,
    pub user_tree_proof: MerkleProofCore<QHashOut<F>>,
    pub user_registration_tree_proof: Option<MerkleProofCore<QHashOut<F>>>,

    /// Filled once the ups_start leaf proof has been produced; `None` means
    /// this proving unit is still pending. On re-prove a `Some(_)` is
    /// re-injected instead of re-proven.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<UpsStartProofRecord>,
}

/// Persisted leaf proof for the `ups_start` proving unit. Verifier data and
/// fingerprint are recovered from the circuit manager on re-prove, so only the
/// proof bytes are stored here.
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct UpsStartProofRecord {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proof: Vec<u8>,
}

/// Persisted leaf proofs for one CFC proving unit (standard or deferred). A CFC
/// step ingests two proof-tree leaves: the contract-function-call proof and
/// the UPS step proof.
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct CfcProofRecord {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cfc_proof: Vec<u8>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ups_proof: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TraceContractCode {
    pub contract_id: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub code: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Arena steps
// ---------------------------------------------------------------------------

/// Arena step variant. `TxTrace.steps[id.0]` owns the step body.
/// CFC steps carry explicit parent/inlined/deferred arena links.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum TraceStep {
    #[serde(rename = "standard")]
    Standard(CfcStep),

    #[serde(rename = "burn_fee")]
    BurnFee(CfcStep),

    #[serde(rename = "inlined")]
    Inlined(CfcStep),

    #[serde(rename = "deferred")]
    Deferred(CfcStep),

    #[serde(rename = "external_proof")]
    ExternalProof(ExternalProofStep),

    #[serde(rename = "zk_sign")]
    ZkSign(ZkSignStep),
}

impl TraceStep {
    pub fn contract_id(&self) -> Option<u64> {
        match self {
            TraceStep::Standard(c) | TraceStep::BurnFee(c) | TraceStep::Inlined(c) | TraceStep::Deferred(c) => Some(c.contract_id),
            _ => None,
        }
    }

    pub fn as_cfc(&self) -> Option<&CfcStep> {
        match self {
            TraceStep::Standard(c) | TraceStep::BurnFee(c) | TraceStep::Inlined(c) | TraceStep::Deferred(c) => Some(c),
            _ => None,
        }
    }

    pub fn as_cfc_mut(&mut self) -> Option<&mut CfcStep> {
        match self {
            TraceStep::Standard(c) | TraceStep::BurnFee(c) | TraceStep::Inlined(c) | TraceStep::Deferred(c) => Some(c),
            _ => None,
        }
    }
}

/// Shared CFC step for standard / inlined / deferred / burn_fee.
/// `parent`, `inlined`, and `deferred` are arena ids into `TxTrace.steps`.
#[derive(Clone, Serialize, Deserialize)]
pub struct CfcStep {
    pub id: TraceStepId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<TraceStepId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inlined: Vec<TraceStepId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deferred: Vec<TraceStepId>,

    pub contract_id: u64,
    pub fn_id: u32,
    pub method_id: u32,
    pub method_name: String,
    pub cfc_fingerprint: QHashOut<F>,
    pub ups_fingerprint: QHashOut<F>,

    // Prove-tree root bookends (prove must assert before/after)
    pub proof_tree_start_root: QHashOut<F>,
    pub proof_tree_end_root: QHashOut<F>,

    // Witness — self-contained for prove_contract_call
    pub cfc_witness: DapenContractFunctionCircuitInput<F>,

    // State delta — performed during execution, consumed by UPS step circuit
    pub state_delta: CfcStateDelta,

    // Contract/function tree inclusion proof (checkpoint-bound)
    pub cfc_inclusion_proof: PsyContractFunctionInclusionProof<F>,

    // Session header after this UPS step is proven
    pub end_header: UserProvingSessionHeader<F>,

    // Some(_) for deferred steps; None for standard/inlined/burn_fee
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debt_removal_proof: Option<DeltaMerkleProofCore<QHashOut<F>>>,

    /// Filled once this step's leaf proofs have been produced; `None` means
    /// this proving unit is still pending. On re-prove a `Some(_)` is
    /// re-injected instead of re-proven.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<CfcProofRecord>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CfcStateDelta {
    pub cfc_transaction_input_context: DapenCFCUserTransactionInputContext<F>,
    pub user_contract_tree_update_proof: DeltaMerkleProofCore<QHashOut<F>>,
    pub deferred_tx_debt_pivot_proof: MerkleProofCore<QHashOut<F>>,
    pub inline_tx_debt_pivot_proof: MerkleProofCore<QHashOut<F>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ExternalProofStep {
    pub fingerprint: QHashOut<F>,
    pub proof_tree_start_root: QHashOut<F>,
    pub proof_tree_end_root: QHashOut<F>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proof: Vec<u8>,
    pub verifier_data_alt: AltVerifierOnlyCircuitData<F>,
    pub siblings: Vec<[String; 4]>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ZkSignStep {
    pub fingerprint: QHashOut<F>,
    pub proof_tree_start_root: QHashOut<F>,
    pub proof_tree_end_root: QHashOut<F>,
    pub sign_circuit_source: TraceSignCircuitSource,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sign_witness: Vec<u8>,
    pub public_key_param: QHashOut<F>,
    pub sign_verifier_data_alt: AltVerifierOnlyCircuitData<F>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TraceSignCircuitSource {
    ZkBuiltin,
    SecpBuiltin,
    SdKey {
        allowed_contract_ids: Vec<u64>,
        allowed_method_ids: Vec<u32>,
        expected_tx_count: u64,
    },
    Plonky2SoftwareDefined {
        #[serde(default = "default_plonky2_sdc_contract_state_tree_height")]
        contract_state_tree_height: u8,
        #[serde(default)]
        input_len: usize,
    },
    PsySoftwareDefined {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        circuit_def: Vec<u8>,
        force_four_align: bool,
    },
}

impl From<psy_client_data::ups::ups_standard_cfc_input::UPSCFCStandardStateDeltaInput<F>> for CfcStateDelta {
    fn from(d: psy_client_data::ups::ups_standard_cfc_input::UPSCFCStandardStateDeltaInput<F>) -> Self {
        CfcStateDelta {
            cfc_transaction_input_context: d.cfc_transaction_input_context,
            user_contract_tree_update_proof: d.user_contract_tree_update_proof,
            deferred_tx_debt_pivot_proof: d.deferred_tx_debt_pivot_proof,
            inline_tx_debt_pivot_proof: d.inline_tx_debt_pivot_proof,
        }
    }
}

impl From<CfcStateDelta> for psy_client_data::ups::ups_standard_cfc_input::UPSCFCStandardStateDeltaInput<F> {
    fn from(d: CfcStateDelta) -> Self {
        psy_client_data::ups::ups_standard_cfc_input::UPSCFCStandardStateDeltaInput {
            cfc_transaction_input_context: d.cfc_transaction_input_context,
            user_contract_tree_update_proof: d.user_contract_tree_update_proof,
            deferred_tx_debt_pivot_proof: d.deferred_tx_debt_pivot_proof,
            inline_tx_debt_pivot_proof: d.inline_tx_debt_pivot_proof,
        }
    }
}

// ---------------------------------------------------------------------------
// Finalization — submit material
// ---------------------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize)]
pub struct TxFinalization {
    pub submit_end_cap_input: SubmitUserEndCapNonProofInput<F>,
    pub nonce: F,
    pub tx_hash: QHashOut<F>,
    pub software_defined_call: DPNSoftwareDefinedCallData,
    pub sig_hash: QHashOut<F>,
}
pub mod proof_schedule;
pub mod proof_tree_meta;

#[cfg(test)]
mod ordering_tests;

#[cfg(test)]
mod simulation_tests {
    use super::*;

    #[test]
    fn fee_free_view_response_omits_provable_transaction_fields() {
        let response = SimulatedTxJson {
            generated: None,
            metadata: SimulatedTxMetadata {
                tx_hash: None,
                end_cap_data: None,
                contract_call_data: ContractCallResultData {
                    contract_calls: vec![ContractCallResultArgs {
                        contract_id: 6,
                        method_name: "get_counter".to_string(),
                        inputs: Vec::new(),
                        outputs: vec![42],
                    }],
                    software_defined_call: DPNSoftwareDefinedCallData::default(),
                },
                storage_data: TxStorageData::default(),
            },
        };

        let json = serde_json::to_value(response).unwrap();
        assert!(json.get("generated").is_none());
        assert!(json["metadata"].get("tx_hash").is_none());
        assert!(json["metadata"].get("end_cap_data").is_none());
        assert_eq!(json["metadata"]["contract_call_data"]["contract_calls"][0]["outputs"][0], 42);
        assert_eq!(json["metadata"]["storage_data"]["writes"], serde_json::json!([]));
    }
}
