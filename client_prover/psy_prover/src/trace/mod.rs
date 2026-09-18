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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ViewCallResult {
    pub checkpoint_id: u64,
    pub contract_calls: Vec<ContractCallResultArgs>,
    pub storage_reads: Vec<TxStorageRead>,
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

    pub(crate) fn from_call_witnesses(
        current_user_id: u64,
        current_contract_id: u64,
        cmd_witnesses: &[PsyCmdWithInputAndWitness<F>],
    ) -> Self {
        let mut storage = TxStorageData::default();
        storage.extend_from_cmd_witnesses(current_user_id, current_contract_id, cmd_witnesses);
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
    pub fn from_view_steps(
        user_id: u64,
        steps: &[TraceStep],
        software_defined_call: DPNSoftwareDefinedCallData,
    ) -> anyhow::Result<Self> {
        let storage_data = TxStorageData::from_steps(user_id, steps);
        anyhow::ensure!(
            storage_data.writes.is_empty(),
            "fee-free view simulation produced storage writes"
        );
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
    EthPersonalSecpBuiltin,
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
#[cfg_attr(coverage_nightly, coverage(off))]
mod ordering_tests;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod simulation_tests {
    use plonky2::field::types::Field;
    use psy_client_data::guta::api::PsyContractStateUpdateHistory;

    use super::*;

    #[test]
    fn trace_step_id_round_trips_through_usize() {
        let id = TraceStepId::from(17usize);
        assert_eq!(id.0, 17);
        assert_eq!(usize::from(id), 17);
    }

    #[test]
    fn proved_result_constructor_preserves_all_fields() {
        let result = ProvedTxResultJson::new("sig".to_string(), "tx".to_string(), Some(9), "submitted".to_string());
        assert_eq!(result.sig_hash, "sig");
        assert_eq!(result.tx_hash, "tx");
        assert_eq!(result.checkpoint_id, Some(9));
        assert_eq!(result.status, "submitted");
    }

    #[test]
    fn sign_circuit_source_serde_applies_defaults_and_tags() {
        let plonky: TraceSignCircuitSource = serde_json::from_value(serde_json::json!({
            "kind": "plonky2_software_defined"
        }))
        .unwrap();
        match plonky {
            TraceSignCircuitSource::Plonky2SoftwareDefined {
                contract_state_tree_height,
                input_len,
            } => {
                assert_eq!(contract_state_tree_height, psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT);
                assert_eq!(input_len, 0);
            }
            _ => panic!("unexpected sign circuit source"),
        }

        for kind in ["zk_builtin", "secp_builtin", "eth_personal_secp_builtin"] {
            let source: TraceSignCircuitSource = serde_json::from_value(serde_json::json!({ "kind": kind })).unwrap();
            assert_eq!(serde_json::to_value(source).unwrap()["kind"], kind);
        }

        let sd_key = TraceSignCircuitSource::SdKey {
            allowed_contract_ids: vec![1, 2],
            allowed_method_ids: vec![3],
            expected_tx_count: 4,
        };
        let json = serde_json::to_value(sd_key).unwrap();
        assert_eq!(json["kind"], "sd_key");
        assert_eq!(json["expected_tx_count"], 4);

        let psy = TraceSignCircuitSource::PsySoftwareDefined {
            circuit_def: Vec::new(),
            force_four_align: true,
        };
        let json = serde_json::to_value(psy).unwrap();
        assert!(json.get("circuit_def").is_none());
        assert_eq!(json["force_four_align"], true);
    }

    #[test]
    fn persisted_proof_records_omit_empty_byte_vectors() {
        assert_eq!(serde_json::to_value(UpsStartProofRecord::default()).unwrap(), serde_json::json!({}));
        assert_eq!(serde_json::to_value(CfcProofRecord::default()).unwrap(), serde_json::json!({}));

        let code = TraceContractCode {
            contract_id: 7,
            code: Vec::new(),
        };
        assert_eq!(serde_json::to_value(code).unwrap(), serde_json::json!({ "contract_id": 7 }));
    }

    #[test]
    fn simulation_and_view_json_have_disjoint_required_fields() {
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

        let view = serde_json::to_value(ViewCallResult {
            checkpoint_id: 1,
            contract_calls: Vec::new(),
            storage_reads: Vec::new(),
        })
        .unwrap();
        assert_eq!(view.as_object().unwrap().len(), 3);
        assert!(view.get("checkpoint_id").is_some());
        assert!(view.get("contract_calls").is_some());
        assert!(view.get("storage_reads").is_some());
        assert!(view.get("generated").is_none());
        assert!(view.get("metadata").is_none());
        assert!(view.get("tx_hash").is_none());
    }

    fn qhash(seed: u64) -> QHashOut<F> {
        QHashOut::from_values(seed, seed + 1, seed + 2, seed + 3)
    }

    fn state_delta_proof(index: u64, old_value: QHashOut<F>, new_value: QHashOut<F>) -> DeltaMerkleProofCore<QHashOut<F>> {
        DeltaMerkleProofCore {
            old_root: QHashOut::ZERO,
            old_value,
            new_root: QHashOut::ZERO,
            new_value,
            index,
            siblings: Vec::new(),
        }
    }

    fn cfc_state_delta() -> CfcStateDelta {
        CfcStateDelta {
            cfc_transaction_input_context: Default::default(),
            user_contract_tree_update_proof: state_delta_proof(21, qhash(60), qhash(61)),
            deferred_tx_debt_pivot_proof: Default::default(),
            inline_tx_debt_pivot_proof: Default::default(),
        }
    }

    fn alt_verifier_data() -> AltVerifierOnlyCircuitData<F> {
        AltVerifierOnlyCircuitData {
            constants_sigmas_cap: Vec::new(),
            circuit_digest: QHashOut::ZERO,
        }
    }

    fn cfc_step(id: usize, contract_id: u64, method_name: &str) -> TraceStep {
        TraceStep::Standard(CfcStep {
            id: TraceStepId(id),
            parent: None,
            inlined: Vec::new(),
            deferred: Vec::new(),
            contract_id,
            fn_id: 1,
            method_id: 2,
            method_name: method_name.to_string(),
            cfc_fingerprint: QHashOut::ZERO,
            ups_fingerprint: QHashOut::ZERO,
            proof_tree_start_root: QHashOut::ZERO,
            proof_tree_end_root: QHashOut::ZERO,
            cfc_witness: DapenContractFunctionCircuitInput {
                inputs: vec![F::from_canonical_u64(7), F::from_canonical_u64(8)],
                outputs: vec![F::from_canonical_u64(9)],
                ..Default::default()
            },
            state_delta: cfc_state_delta(),
            cfc_inclusion_proof: Default::default(),
            end_header: Default::default(),
            debt_removal_proof: None,
            proof: None,
        })
    }

    fn external_proof_step() -> TraceStep {
        TraceStep::ExternalProof(ExternalProofStep {
            fingerprint: QHashOut::ZERO,
            proof_tree_start_root: QHashOut::ZERO,
            proof_tree_end_root: QHashOut::ZERO,
            proof: Vec::new(),
            verifier_data_alt: alt_verifier_data(),
            siblings: Vec::new(),
        })
    }

    fn zk_sign_step() -> TraceStep {
        TraceStep::ZkSign(ZkSignStep {
            fingerprint: QHashOut::ZERO,
            proof_tree_start_root: QHashOut::ZERO,
            proof_tree_end_root: QHashOut::ZERO,
            sign_circuit_source: TraceSignCircuitSource::ZkBuiltin,
            sign_witness: Vec::new(),
            public_key_param: QHashOut::ZERO,
            sign_verifier_data_alt: alt_verifier_data(),
        })
    }

    fn end_cap_input(user_id: u64) -> SubmitUserEndCapNonProofInput<F> {
        let mut input = SubmitUserEndCapNonProofInput::<F>::default();
        input.core.checkpoint_id = F::from_canonical_u64(33);
        input.core.state_transition.user_id = F::from_canonical_u64(user_id);
        input.core.state_transition.start_user_leaf_hash = qhash(1);
        input.core.state_transition.end_user_leaf_hash = qhash(2);
        input.core.state_transition.checkpoint_tree_root_hash = qhash(3);
        input.contract_state_updates = vec![PsyContractStateUpdateHistory {
            user_contract_tree_update_proof: state_delta_proof(11, qhash(70), qhash(71)),
            contract_state_tree_updates: vec![
                ContractStateUpdate::Positional {
                    delta_proof: state_delta_proof(1, qhash(10), qhash(11)),
                },
                ContractStateUpdate::IMT {
                    update: IMTContractStateUpdate::Update {
                        old_preimage: Default::default(),
                        new_preimage: Default::default(),
                        delta_proof: state_delta_proof(2, qhash(20), qhash(21)),
                    },
                },
                ContractStateUpdate::IMT {
                    update: IMTContractStateUpdate::Insert {
                        predecessor_old_preimage: Default::default(),
                        predecessor_new_preimage: Default::default(),
                        new_leaf_preimage: Default::default(),
                        predecessor_delta_proof: state_delta_proof(3, qhash(30), qhash(31)),
                        new_leaf_delta_proof: state_delta_proof(4, qhash(40), qhash(41)),
                    },
                },
                // no-op positional update: old == new must be skipped
                ContractStateUpdate::Positional {
                    delta_proof: state_delta_proof(5, qhash(50), qhash(50)),
                },
            ],
        }];
        input
    }

    fn trace_with(steps: Vec<TraceStep>, finalization: TxFinalization) -> TxTrace {
        TxTrace {
            meta: TraceMeta {
                network_magic: 1,
                user_id: 2,
                public_key: qhash(90),
            },
            anchor: SessionAnchor {
                start_checkpoint_id: 3,
                checkpoint_leaf: Default::default(),
                global_state_roots: Default::default(),
                ups_step_circuit_whitelist_root: QHashOut::ZERO,
            },
            ups_start_witness: UpsStartWitness {
                ups_header: Default::default(),
                state_roots: Default::default(),
                checkpoint_tree_proof: Default::default(),
                user_tree_proof: Default::default(),
                user_registration_tree_proof: None,
                proof: Some(UpsStartProofRecord { proof: vec![1] }),
            },
            contract_codes: Vec::new(),
            steps,
            finalization,
        }
    }

    fn finalization(end_cap: SubmitUserEndCapNonProofInput<F>) -> TxFinalization {
        TxFinalization {
            submit_end_cap_input: end_cap,
            nonce: F::from_canonical_u64(1),
            tx_hash: qhash(80),
            software_defined_call: DPNSoftwareDefinedCallData::default(),
            sig_hash: qhash(81),
        }
    }

    #[test]
    fn generated_trace_json_envelopes_and_round_trips_the_trace() {
        let trace = trace_with(
            vec![cfc_step(0, 5, "set_value"), external_proof_step(), zk_sign_step()],
            finalization(end_cap_input(2)),
        );

        let envelope = GeneratedTxTraceJson::from_trace(&trace, serde_json::json!({"calls": 1})).unwrap();
        assert_eq!(envelope.user_id, "2");
        assert_eq!(envelope.pk_hash, qhash(90).to_string());
        assert_eq!(envelope.sig_hash, qhash(81).to_string());
        assert_eq!(envelope.tx_hash, qhash(80).to_string());
        assert_eq!(envelope.tx_count, 3);
        assert_eq!(envelope.call_data, serde_json::json!({"calls": 1}));
        assert_eq!(envelope.trace.encoding, "json");

        let decoded: TxTrace = serde_json::from_str(&envelope.trace.payload).unwrap();
        assert_eq!(decoded.meta.user_id, 2);
        assert_eq!(decoded.steps.len(), 3);
        assert_eq!(decoded.finalization.tx_hash, qhash(80));
    }

    #[test]
    fn contract_call_results_include_callable_cfc_kinds_and_filter_burn_fee() {
        let base = match cfc_step(0, 5, "standard") {
            TraceStep::Standard(cfc) => cfc,
            _ => unreachable!(),
        };
        let mut inlined = base.clone();
        inlined.id = TraceStepId(1);
        inlined.method_name = "inlined".to_string();
        let mut deferred = base.clone();
        deferred.id = TraceStepId(2);
        deferred.method_name = "deferred".to_string();
        let mut burn = base.clone();
        burn.id = TraceStepId(3);
        burn.method_name = "burn".to_string();

        let calls = contract_call_results(&[
            TraceStep::Standard(base),
            TraceStep::Inlined(inlined),
            TraceStep::Deferred(deferred),
            TraceStep::BurnFee(burn),
            external_proof_step(),
            zk_sign_step(),
        ]);

        assert_eq!(calls.len(), 3);
        assert_eq!(
            calls.iter().map(|call| call.method_name.as_str()).collect::<Vec<_>>(),
            vec!["standard", "inlined", "deferred"]
        );
        assert!(calls.iter().all(|call| call.contract_id == 5));
        assert!(calls.iter().all(|call| call.inputs == vec![7, 8] && call.outputs == vec![9]));
    }

    #[test]
    fn tx_metadata_collects_end_cap_storage_and_contract_call_results() {
        let trace = trace_with(
            vec![cfc_step(0, 5, "set_value"), external_proof_step(), zk_sign_step()],
            finalization(end_cap_input(9)),
        );

        let metadata = TxMetadata::from_trace(&trace);

        assert_eq!(metadata.tx_hash, qhash(80));
        assert_eq!(metadata.end_cap_data.checkpoint_id, 33);
        assert_eq!(metadata.end_cap_data.user_id, 9);
        assert_eq!(metadata.end_cap_data.start_user_leaf_hash, qhash(1));
        assert_eq!(metadata.end_cap_data.end_user_leaf_hash, qhash(2));
        assert_eq!(metadata.end_cap_data.checkpoint_tree_root_hash, qhash(3));
        assert_eq!(
            metadata.end_cap_data.global_user_tree_height,
            psy_config::network_constants::GLOBAL_USER_TREE_HEIGHT
        );

        // only the CFC step contributes a call result
        assert_eq!(metadata.contract_call_data.contract_calls.len(), 1);
        let call = &metadata.contract_call_data.contract_calls[0];
        assert_eq!(call.contract_id, 5);
        assert_eq!(call.method_name, "set_value");
        assert_eq!(call.inputs, vec![7, 8]);
        assert_eq!(call.outputs, vec![9]);

        // storage writes: positional + IMT update + IMT insert (two proofs);
        // the no-op positional update (old == new) is skipped
        assert!(metadata.storage_data.reads.is_empty());
        let writes = &metadata.storage_data.writes;
        assert_eq!(writes.len(), 4);
        for write in writes {
            assert_eq!(write.user_id, 9);
            assert_eq!(write.contract_id, 11);
        }
        assert_eq!(writes[0].slot_index, 1);
        assert_eq!(writes[0].old_value, qhash(10));
        assert_eq!(writes[0].new_value, qhash(11));
        assert_eq!(writes[1].slot_index, 2);
        assert_eq!(writes[2].slot_index, 3);
        assert_eq!(writes[3].slot_index, 4);
        assert_eq!(writes[3].old_value, qhash(40));
        assert_eq!(writes[3].new_value, qhash(41));
    }

    #[test]
    fn cfc_state_delta_converts_to_and_from_ups_standard_delta_input() {
        let delta = cfc_state_delta();
        let ups: psy_client_data::ups::ups_standard_cfc_input::UPSCFCStandardStateDeltaInput<F> = delta.clone().into();
        assert_eq!(ups.user_contract_tree_update_proof.index, 21);
        assert_eq!(ups.user_contract_tree_update_proof.old_value, qhash(60));

        let round_tripped: CfcStateDelta = ups.into();
        assert_eq!(serde_json::to_value(&delta).unwrap(), serde_json::to_value(&round_tripped).unwrap());
    }
}
