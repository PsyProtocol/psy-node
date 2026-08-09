use std::borrow::Cow;

use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::hash_types::RichField,
    plonk::{
        config::{GenericConfig, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_client_common::{
    data::{
        alt::AltVerifierOnlyCircuitData,
        base_types::{hash160::Hash160, hash256::Hash256},
        qhashout::QHashOut,
    },
    job::id::QProvingJobDataIDWithRewardPath,
};
use psy_client_data::{
    guta::{api::SubmitGUTARealmResultAPINoProofInput, end_cap_input::SubmitUserEndCapNonProofInput},
    qblock::cmds::deploy_contract::QBCDeployContract,
    qdata::{
        checkpoint::{PsyBlockState, PsyCheckpointLeaf},
        contract::{ContractCodeDefinition, PsyContractLeaf},
        user::PsyUserLeaf,
    },
    ups::{
        start_step::UPSStartStepInput,
        start_step_register_user::UPSStartStepRegisterUserInput,
        ups_cfc_standard_step::{UPSCFCDeferredTransactionCircuitInput, UPSCFCStandardTransactionCircuitInput},
        ups_end_cap::UPSEndCapFromProofTreeGadgetInput,
    },
};
use psy_crypto::{
    common::witnesses::qrecursion::{header::QRecursionAggStandardHeader, proof_data::QStandardBinaryTreeCircuitType},
    hash::merkle::core::{DeltaMerkleProofCore, MerkleProofCore},
    signature::{secp256k1::core::PsyCompressedSecp256K1Signature, zk::data::ZKPublicKeyInfo},
};
// Use types from psy_vm
pub use psy_vm::ups::signature::{DPNSoftwareDefinedSignatureInput, Plonky2SoftwareDefinedSignatureInput};
use psy_vm::{dpn::vm::def::DPNFunctionCircuitDefinition, vm::cfc_input::DapenContractFunctionCircuitInput};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::serde_as;
use ts_rs::TS;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;

/// Represents the version of the RPC protocol
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum Version {
    #[serde(rename = "2.0")]
    V2,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Id {
    String(String),
    Number(i64),
    Null,
}

#[serde_as]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
#[serde(tag = "method", content = "params")]
pub enum RequestParams<F: RichField> {
    /// for coordinator edge
    #[serde(rename = "psy_deploy_contract")]
    DeployContract(QDeployContractRPCRequest<F>),
    #[serde(rename = "psy_register_user")]
    RegisterUser(QRegisterUserRPCRequest<F>),
    #[serde(rename = "psy_build_block")]
    ProduceBlock,
    #[serde(rename = "psy_get_user_ids_for_public_key")]
    GetUserIds(QGetUserIdsRPCRequest<F>),
    #[serde(rename = "psy_submit_guta")]
    SubmitGuta(QSubmitGutaRPCRequest<F>),
    #[serde(rename = "psy_get_latest_checkpoint")]
    GetLatestCheckpoint,
    #[serde(rename = "psy_latest_checkpoint")]
    LatestCheckpoint,
    #[serde(rename = "psy_get_latest_checkpoint_id")]
    GetLatestCheckpointId,
    #[serde(rename = "psy_get_checkpoint_sync_info")]
    GetCheckpointSyncInfo(QGetCheckpointSyncInfoRPCRequest),
    #[serde(rename = "psy_get_checkpoint_sync_info_compact")]
    GetCheckpointSyncInfoCompact(QGetCheckpointSyncInfoCompactRPCRequest),

    /// for realm edge
    TokenTransfer(QTokenTransferRPCRequest),
    #[serde(rename = "psy_claim_deposit")]
    ClaimDeposit(QClaimDepositRPCRequest),
    #[serde(rename = "psy_add_withdrawal")]
    AddWithdrawal(QAddWithdrawalRPCRequest),
    #[serde(rename = "psy_submit_user_end_cap")]
    SubmitEndCap(QSubmitEndCapRPCRequest<F>),
    #[serde(rename = "psy_submit_user_end_cap_batch")]
    SubmitEndCapProofs(Vec<Vec<(SubmitUserEndCapNonProofInput<F>, Vec<u8>)>>),
    #[serde(rename = "psy_get_user_end_cap_slot_updates")]
    GetUserEndCapSlotUpdates(QGetUserEndCapSlotUpdatesRPCRequest),

    #[serde(rename = "psy_get_tx_status")]
    GetTxStatus(QGetTxStatusRPCRequest),

    // QTreeDataStoreReaderSync
    #[serde(rename = "psy_get_user_contract_state_tree_root")]
    GetUserContractStateTreeRoot(QUserContractStateTreeRootRPCRequest),
    #[serde(rename = "psy_get_user_contract_state_tree_root_f")]
    GetUserContractStateTreeRootF(QUserContractStateTreeRootFRPCRequest<F>),
    #[serde(rename = "psy_get_user_contract_state_tree_leaf_hash")]
    GetUserContractStateTreeLeafHash(QUserContractStateTreeLeafHashRPCRequest),
    #[serde(rename = "psy_get_user_contract_state_tree_leaf_hash_f")]
    GetUserContractStateTreeLeafHashF(QUserContractStateTreeLeafHashFRPCRequest<F>),
    #[serde(rename = "psy_get_user_contract_state_tree_merkle_proof")]
    GetUserContractStateTreeMerkleProof(QUserContractStateTreeMerkleProofRPCRequest),
    #[serde(rename = "psy_get_user_contract_state_tree_merkle_proof_f")]
    GetUserContractStateTreeMerkleProofF(QUserContractStateTreeMerkleProofFRPCRequest<F>),

    #[serde(rename = "psy_get_user_contract_tree_root")]
    GetUserContractTreeRoot(QUserContractTreeRootRPCRequest),
    #[serde(rename = "psy_get_user_contract_tree_root_f")]
    GetUserContractTreeRootF(QUserContractTreeRootFRPCRequest<F>),
    #[serde(rename = "psy_get_user_contract_tree_leaf_hash")]
    GetUserContractTreeLeafHash(QUserContractTreeLeafHashRPCRequest),
    #[serde(rename = "psy_get_user_contract_tree_leaf_hash_f")]
    GetUserContractTreeLeafHashF(QUserContractTreeLeafHashFRPCRequest<F>),
    #[serde(rename = "psy_get_user_contract_tree_merkle_proof")]
    GetUserContractTreeMerkleProof(QUserContractTreeMerkleProofRPCRequest),
    #[serde(rename = "psy_get_user_contract_tree_merkle_proof_f")]
    GetUserContractTreeMerkleProofF(QUserContractTreeMerkleProofFRPCRequest<F>),

    #[serde(rename = "psy_get_user_registration_tree_root")]
    GetUserRegistrationTreeRoot(QUserRegistrationTreeRootRPCRequest),
    #[serde(rename = "psy_get_user_registration_tree_root_f")]
    GetUserRegistrationTreeRootF(QUserRegistrationTreeRootFRPCRequest<F>),
    #[serde(rename = "psy_get_user_registration_tree_leaf_hash")]
    GetUserRegistrationTreeLeafHash(QUserRegistrationTreeLeafHashRPCRequest),
    #[serde(rename = "psy_get_user_registration_tree_leaf_hash_f")]
    GetUserRegistrationTreeLeafHashF(QUserRegistrationTreeLeafHashFRPCRequest<F>),
    #[serde(rename = "psy_get_user_registration_tree_merkle_proof")]
    GetUserRegistrationTreeMerkleProof(QUserRegistrationTreeMerkleProofRPCRequest),
    #[serde(rename = "psy_get_user_registration_tree_merkle_proof_f")]
    GetUserRegistrationTreeMerkleProofF(QUserRegistrationTreeMerkleProofFRPCRequest<F>),

    #[serde(rename = "psy_get_user_tree_root")]
    GetUserTreeRoot(QUserTreeRootRPCRequest),
    #[serde(rename = "psy_get_user_tree_root_f")]
    GetUserTreeRootF(QUserTreeRootFRPCRequest<F>),
    #[serde(rename = "psy_get_user_tree_leaf_hash")]
    GetUserTreeLeafHash(QUserTreeLeafHashRPCRequest),
    #[serde(rename = "psy_get_user_tree_leaf_hash_f")]
    GetUserTreeLeafHashF(QUserTreeLeafHashFRPCRequest<F>),
    #[serde(rename = "psy_get_user_tree_merkle_proof")]
    GetUserTreeMerkleProof(QUserTreeMerkleProofRPCRequest),
    #[serde(rename = "psy_get_user_tree_merkle_proof_f")]
    GetUserTreeMerkleProofF(QUserTreeMerkleProofFRPCRequest<F>),
    #[serde(rename = "psy_get_user_sub_tree_merkle_proof")]
    GetUserSubTreeMerkleProof(QUserSubTreeMerkleProofRPCRequest),

    #[serde(rename = "psy_get_user_event_tree_root")]
    GetUserEventTreeRoot(QUserEventTreeRootRPCRequest),
    #[serde(rename = "psy_get_user_event_tree_root_f")]
    GetUserEventTreeRootF(QUserEventTreeRootFRPCRequest<F>),
    #[serde(rename = "psy_get_user_event_tree_leaf_hash")]
    GetUserEventTreeLeafHash(QUserEventTreeLeafHashRPCRequest),
    #[serde(rename = "psy_get_user_event_tree_leaf_hash_f")]
    GetUserEventTreeLeafHashF(QUserEventTreeLeafHashFRPCRequest<F>),
    #[serde(rename = "psy_get_user_event_tree_merkle_proof")]
    GetUserEventTreeMerkleProof(QUserEventTreeMerkleProofRPCRequest),
    #[serde(rename = "psy_get_user_event_tree_merkle_proof_f")]
    GetUserEventTreeMerkleProofF(QUserEventTreeMerkleProofFRPCRequest<F>),

    #[serde(rename = "psy_get_contract_function_tree_root")]
    GetContractFunctionTreeRoot(QContractFunctionTreeRootRPCRequest),
    #[serde(rename = "psy_get_contract_function_tree_root_f")]
    GetContractFunctionTreeRootF(QContractFunctionTreeRootFRPCRequest<F>),
    #[serde(rename = "psy_get_contract_function_tree_leaf_hash")]
    GetContractFunctionTreeLeafHash(QContractFunctionTreeLeafHashRPCRequest),
    #[serde(rename = "psy_get_contract_function_tree_leaf_hash_f")]
    GetContractFunctionTreeLeafHashF(QContractFunctionTreeLeafHashFRPCRequest<F>),
    #[serde(rename = "psy_get_contract_function_tree_merkle_proof")]
    GetContractFunctionTreeMerkleProof(QContractFunctionTreeMerkleProofRPCRequest),
    #[serde(rename = "psy_get_contract_function_tree_merkle_proof_f")]
    GetContractFunctionTreeMerkleProofF(QContractFunctionTreeMerkleProofFRPCRequest<F>),

    #[serde(rename = "psy_get_contract_tree_root")]
    GetContractTreeRoot(QContractTreeRootRPCRequest),
    #[serde(rename = "psy_get_contract_tree_root_f")]
    GetContractTreeRootF(QContractTreeRootFRPCRequest<F>),
    #[serde(rename = "psy_get_contract_tree_leaf_hash")]
    GetContractTreeLeafHash(QContractTreeLeafHashRPCRequest),
    #[serde(rename = "psy_get_contract_tree_leaf_hash_f")]
    GetContractTreeLeafHashF(QContractTreeLeafHashFRPCRequest<F>),
    #[serde(rename = "psy_get_contract_tree_merkle_proof")]
    GetContractTreeMerkleProof(QContractTreeMerkleProofRPCRequest),
    #[serde(rename = "psy_get_contract_tree_merkle_proof_f")]
    GetContractTreeMerkleProofF(QContractTreeMerkleProofFRPCRequest<F>),

    #[serde(rename = "psy_get_withdrawal_tree_root")]
    GetWithdrawalTreeRoot(QWithdrawalTreeRootRPCRequest),
    #[serde(rename = "psy_get_withdrawal_tree_root_f")]
    GetWithdrawalTreeRootF(QWithdrawalTreeRootFRPCRequest<F>),

    #[serde(rename = "psy_get_latest_checkpoint_tree_root")]
    GetLatestCheckpointTreeRoot(QLatestCheckpointTreeRootRPCRequest),
    #[serde(rename = "psy_get_checkpoint_tree_root")]
    GetCheckpointTreeRoot(QCheckpointTreeRootRPCRequest),
    #[serde(rename = "psy_get_checkpoint_tree_root_f")]
    GetCheckpointTreeRootF(QCheckpointTreeRootFRPCRequest<F>),
    #[serde(rename = "psy_get_checkpoint_tree_leaf_hash")]
    GetCheckpointTreeLeafHash(QCheckpointTreeLeafHashRPCRequest),
    #[serde(rename = "psy_get_checkpoint_tree_leaf_hash_f")]
    GetCheckpointTreeLeafHashF(QCheckpointTreeLeafHashFRPCRequest<F>),
    #[serde(rename = "psy_get_checkpoint_tree_merkle_proof")]
    GetCheckpointTreeMerkleProof(QCheckpointTreeMerkleProofRPCRequest),
    #[serde(rename = "psy_get_checkpoint_tree_merkle_proof_f")]
    GetCheckpointTreeMerkleProofF(QCheckpointTreeMerkleProofFRPCRequest<F>),

    #[serde(rename = "psy_get_checkpoint_global_state_roots")]
    GetCheckpointGlobalStateRoots(QCheckpointGlobalStateRootsRPCRequest),

    #[serde(rename = "psy_get_checkpoint_state_transition_proof")]
    GetCheckpointStateTransitionProof(QCheckpointStateTransitionProofRPCRequest),

    // QMetaDataStoreReaderSync
    #[serde(rename = "psy_get_user_leaf_data")]
    GetUserLeafData(QUserLeafDataRPCRequest),
    #[serde(rename = "psy_get_user_leaf_data_f")]
    GetUserLeafFData(QUserLeafDataFRPCRequest<F>),
    #[serde(rename = "psy_get_contract_leaf_data")]
    GetContractLeafData(QContractLeafDataRPCRequest),
    #[serde(rename = "psy_get_contract_leaf_data_f")]
    GetContractLeafDataF(QContractLeafDataFRPCRequest<F>),
    #[serde(rename = "psy_get_checkpoint_leaf_data")]
    GetCheckpointLeafData(QCheckpointLeafDataRPCRequest),
    #[serde(rename = "psy_get_checkpoint_leaf_data_f")]
    GetCheckpointLeafDataF(QCheckpointLeafDataFRPCRequest<F>),
    #[serde(rename = "psy_get_contract_code_definition")]
    GetContractCodeDefinition(QContractCodeDefinitionRPCRequest),
    #[serde(rename = "psy_get_contract_code_definition_f")]
    GetContractCodeDefinitionF(QContractCodeDefinitionFRPCRequest<F>),
    #[serde(rename = "psy_get_latest_l2_block_state")]
    GetLatestBlockState(QLatestBlockStateRPCRequest),
    #[serde(rename = "psy_get_l2_block_state")]
    GetBlockState(QBlockStateRPCRequest),
    #[serde(rename = "psy_get_block_state_f")]
    GetBlockStateF(QBlockStateFRPCRequest<F>),
    #[serde(rename = "psy_get_user_event_data")]
    GetUserEventData(QUserEventDataRPCRequest),
    #[serde(rename = "psy_get_user_event_data_f")]
    GetUserEventDataF(QUserEventDataFRPCRequest<F>),

    /// IMT contract state
    #[serde(rename = "psy_get_imt_leaf_preimage")]
    GetIMTLeafPreimage(QIMTLeafPreimageRPCRequest),
    #[serde(rename = "psy_get_imt_leaf_index_for_key")]
    GetIMTLeafIndexForKey(QIMTLeafIndexForKeyRPCRequest<F>),
    #[serde(rename = "psy_find_imt_predecessor")]
    FindIMTPredecessor(QFindIMTPredecessorRPCRequest<F>),
    #[serde(rename = "psy_get_imt_next_append_index")]
    GetIMTNextAppendIndex(QIMTNextAppendIndexRPCRequest),

    /// generate proof
    #[serde(rename = "psy_get_circuits_data")]
    GetCircuitsData(),
    #[serde(rename = "psy_prove_ups_start")]
    ProveUpsStart(QProveUpsStartRPCRequest<F>),
    #[serde(rename = "psy_prove_ups_start_register_user")]
    ProveUpsStartRegisterUser(QProveUpsStartRegisterUserRPCRequest<F>),
    #[serde(rename = "psy_register_contract_circuits")]
    RegisterCircuits(QRegisterCircuitsRPCRequest),
    #[serde(rename = "psy_get_fn_id")]
    GetFnId(QGetFnIdRPCRequest),
    #[serde(rename = "psy_resolve_contract_function_by_method_name")]
    ResolveContractFunctionByMethodName(QResolveContractFunctionByMethodNameRPCRequest),
    #[serde(rename = "psy_resolve_contract_function_by_method_id")]
    ResolveContractFunctionByMethodId(QResolveContractFunctionByMethodIdRPCRequest),
    #[serde(rename = "psy_get_contract_method_common_data")]
    GetContractMethodCommonData(QGetContractMethodCommonDataRPCRequest),
    #[serde(rename = "psy_prove_contract_call")]
    ProveContractCall(QProveContractCallRPCRequest<F>),
    #[serde(rename = "psy_prove_ups_cfc_standard_tx")]
    UpsCfcStandardTx(QUpsCfcStandardTxRPCRequest<F>),
    #[serde(rename = "psy_prove_ups_cfc_deferred_tx")]
    UpsCfcDeferredTx(QUpsCfcDeferredTxRPCRequest<F>),
    #[serde(rename = "psy_prove_zk_sign")]
    ZKSignatureProof(QSignatureProofRPCRequest<F>),
    #[serde(rename = "psy_prove_zk_sign_inner")]
    ZKSignatureInnerProof(QSignatureInnerProofRPCRequest<F>),
    #[serde(rename = "psy_prove_zk_sign_minifier")]
    ZKSignatureMinifierProof(QSignatureMinifierProofRPCRequest),
    #[serde(rename = "psy_prove_private_note_inclusion_minifier")]
    PrivateNoteInclusionMinifierProof(QBaseProofMinifierRPCRequest),
    #[serde(rename = "psy_prove_shield_deposit_claim_minifier")]
    ShieldDepositClaimMinifierProof(QBaseProofMinifierRPCRequest),
    #[serde(rename = "psy_prove_secp_sign")]
    SECPSignatureProof(QSecpSignatureProofRPCRequest),
    #[serde(rename = "psy_prove_eth_personal_secp_sign")]
    EthPersonalSECPSignatureProof(QSecpSignatureProofRPCRequest),
    #[serde(rename = "psy_register_dpn_software_defined_circuit")]
    RegisterDPNSoftwareDefinedCircuit(QRegisterDPNSoftwareDefinedCircuitRPCRequest),
    #[serde(rename = "psy_register_plonky2_software_defined_circuit")]
    RegisterPlonky2SoftwareDefinedCircuit(QRegisterPlonky2SoftwareDefinedCircuitRPCRequest),
    #[serde(rename = "psy_prove_dpn_software_defined_sign")]
    DPNSoftwareDefinedSignatureProof(DPNSoftwareDefinedSignatureProofRPCRequest<F>),
    #[serde(rename = "psy_prove_plonky2_software_defined_sign")]
    Plonky2SoftwareDefinedSignatureProof(Plonky2SoftwareDefinedSignatureProofRPCRequest<F>),
    // #[serde(rename = "psy_finalize_tree")]
    // FinalizeTree,
    // #[serde(rename = "psy_prove_ups_end_cap")]
    // UpsEndCap(QUpsEndCapRPCRequest<F>),

    // tree proof
    // #[serde(rename = "psy_prove_single_leaf_circuit")]
    // SingleLeaf(QSingleLeafRpcRequest<F>),
    // #[serde(rename = "psy_prove_two_leaf_circuit")]
    // TwoLeaf(QTwoLeafRpcRequest<F>),
    // #[serde(rename = "psy_prove_two_agg_circuit")]
    // TwoAgg(QTwoAggRpcRequset<F>),
    // #[serde(rename = "psy_prove_left_leaf_right_agg_circuit")]
    // LeftLeafRightAgg(QLeftLeafRightAggRpcRequest<F>),
    // #[serde(rename = "psy_prove_left_agg_right_leaf_circuit")]
    // LeftAggRightLeaf(QLeftAggRightLeafRpcRequest<F>),
    #[serde(rename = "psy_get_checkpoint_id_for_unique_pending_id")]
    GetCheckpointIdForUniquePendingId(QGetCheckpointIdForUniquePendingIdRPCRequest),

    #[serde(rename = "psy_generate_batch_proof_miner_reward_proofs")]
    GenerateBatchProofMinerRewardProofs(QGenerateBatchProofMinerRewardProofsRPCRequest),
}

#[serde_as]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
#[serde(tag = "method", content = "params")]
pub enum RequestParamsV2<C: GenericConfig<D>, const D: usize> {
    #[serde(rename = "psy_prove_ups_end_cap")]
    UpsEndCap(QUpsEndCapRPCRequestV2<C, D>),

    // tree proof
    #[serde(rename = "psy_prove_single_leaf_circuit")]
    SingleLeaf(QSingleLeafRpcRequestV2<C, D>),
    #[serde(rename = "psy_prove_two_leaf_circuit")]
    TwoLeaf(QTwoLeafRpcRequestV2<C, D>),
    #[serde(rename = "psy_prove_two_agg_circuit")]
    TwoAgg(QTwoAggRpcRequsetV2<C, D>),
    #[serde(rename = "psy_prove_left_leaf_right_agg_circuit")]
    LeftLeafRightAgg(QLeftLeafRightAggRpcRequestV2<C, D>),
    #[serde(rename = "psy_prove_left_agg_right_leaf_circuit")]
    LeftAggRightLeaf(QLeftAggRightLeafRpcRequestV2<C, D>),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "T: Serialize, for<'de2> T: Deserialize<'de2>")]
#[serde(deny_unknown_fields)]
pub struct RpcRequest<T> {
    /// The version of the protocol
    pub jsonrpc: Version,
    #[serde(flatten)]
    pub request: T,
    /// The name of the method to execute
    /// The identifier for this request issued by the client,
    /// An [Id] must be a String, null or a number.
    /// If missing it's considered a notification in [Version::V2]
    pub id: Id,
}

/// Response of a _single_ rpc call
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcResponse<T> {
    // JSON RPC version
    pub jsonrpc: Version,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Id>,
    #[serde(flatten)]
    pub result: ResponseResult<T>,
}

/// Represents the result of a call either success or error
#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum ResponseResult<T> {
    #[serde(rename = "result")]
    Success(T),
    #[serde(rename = "error")]
    Error(RpcError),
}

type F = GoldilocksField;
#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum LPSResponse {
    // Batch(PsyReadCommandBatchOutput<F>),
    // QTreeDataStoreReaderSync
    GetHash(QHashOut<F>),
    GetMerkleProof(MerkleProofCore<QHashOut<F>>),

    // QMetaDataStoreReaderSync
    GetUserLeaf(PsyUserLeaf<F>),
    GetContractLeaf(PsyContractLeaf<F>),
    GetContractCode(ContractCodeDefinition),
    GetCheckpointLeaf(PsyCheckpointLeaf<F>),
    GetBlockState(PsyBlockState),
    // GetLatestBlockState(PsyBlockState),
    GetUserId(u64),
}

#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum ProofGeneratorResponse {
    GetProof(ProofWithPublicInputs<F, C, D>),
}

/// Represents a JSON-RPC error
#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RpcError {
    pub code: ErrorCode,
    /// error message
    pub message: Cow<'static, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// List of JSON-RPC error codes
#[derive(Debug, Copy, PartialEq, Eq, Clone)]
pub enum ErrorCode {
    /// Server received Invalid JSON.
    /// server side error while parsing JSON
    ParseError,
    /// send invalid request object.
    InvalidRequest,
    /// method does not exist or valid
    MethodNotFound,
    /// invalid method parameter.
    InvalidParams,
    /// internal call error
    InternalError,
    /// Used for server specific errors.
    ServerError(i64),
}

impl ErrorCode {
    /// Returns the error code as `i64`
    pub fn code(&self) -> i64 {
        match *self {
            ErrorCode::ParseError => -32700,
            ErrorCode::InvalidRequest => -32600,
            ErrorCode::MethodNotFound => -32601,
            ErrorCode::InvalidParams => -32602,
            ErrorCode::InternalError => -32603,
            ErrorCode::ServerError(c) => c,
        }
    }

    /// Returns the message associated with the error
    pub const fn message(&self) -> &'static str {
        match *self {
            ErrorCode::ParseError => "Parse error",
            ErrorCode::InvalidRequest => "Invalid request",
            ErrorCode::MethodNotFound => "Method not found",
            ErrorCode::InvalidParams => "Invalid params",
            ErrorCode::InternalError => "Internal error",
            ErrorCode::ServerError(_) => "Server error",
        }
    }
}

impl Serialize for ErrorCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_i64(self.code())
    }
}

impl<'a> Deserialize<'a> for ErrorCode {
    fn deserialize<D>(deserializer: D) -> Result<ErrorCode, D::Error>
    where
        D: Deserializer<'a>,
    {
        i64::deserialize(deserializer).map(Into::into)
    }
}

impl From<i64> for ErrorCode {
    fn from(code: i64) -> Self {
        match code {
            -32700 => ErrorCode::ParseError,
            -32600 => ErrorCode::InvalidRequest,
            -32601 => ErrorCode::MethodNotFound,
            -32602 => ErrorCode::InvalidParams,
            -32603 => ErrorCode::InternalError,
            _ => ErrorCode::ServerError(code),
        }
    }
}

impl From<ErrorCode> for RpcError {
    fn from(value: ErrorCode) -> Self {
        Self {
            code: value,
            message: Cow::Borrowed(value.message()),
            data: None,
        }
    }
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct QTokenTransferRPCRequest {
    pub user_id: u64,
    pub to: u64,
    pub value: u64,
    pub nonce: u64,

    #[ts(as = "String")]
    #[serde_as(as = "serde_with::hex::Hex")]
    pub signature_proof: Vec<u8>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct QClaimDepositRPCRequest {
    pub user_id: u64,
    pub deposit_id: u64,
    pub chain_id: u64,
    pub value: u64,

    #[ts(as = "String")]
    pub txid: Hash256,

    #[ts(as = "String")]
    #[serde_as(as = "serde_with::hex::Hex")]
    pub public_key: [u8; 33],

    #[ts(as = "String")]
    #[serde_as(as = "serde_with::hex::Hex")]
    pub signature_proof: Vec<u8>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct QAddWithdrawalRPCRequest {
    pub user_id: u64,
    pub value: u64,
    pub nonce: u64,

    pub destination_type: u8,

    #[ts(type = "String")]
    pub destination: Hash160,

    #[ts(type = "String")]
    #[serde_as(as = "serde_with::hex::Hex")]
    pub signature_proof: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, TS)]
#[ts(export, concrete(F = GoldilocksField))]
#[serde(bound = "")]
pub struct QRegisterUserRPCRequest<F: RichField> {
    pub public_key: ZKPublicKeyInfo<F>,
}

impl<F: RichField> QRegisterUserRPCRequest<F> {
    pub fn new_batch(public_keys: &[ZKPublicKeyInfo<F>]) -> Vec<Self> {
        public_keys.iter().map(|pk| QRegisterUserRPCRequest { public_key: *pk }).collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, concrete(F = GoldilocksField))]
#[serde(bound = "")]
pub struct QDeployContractRPCRequest<F: RichField> {
    pub deploy_contract: QBCDeployContract<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, concrete(F = GoldilocksField))]
#[serde(bound = "")]
pub struct QSubmitEndCapRPCRequest<F: RichField> {
    pub user_ec_input: SubmitUserEndCapNonProofInput<F>,
    #[ts(type = "any")]
    // pub proof: ProofWithPublicInputs<GoldilocksField, C, D>,
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
pub struct QGetTxStatusRPCRequest {
    pub user_id: u64,
    pub nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, concrete(F = GoldilocksField))]
#[serde(bound = "")]
pub struct QSubmitGutaRPCRequest<F: RichField> {
    #[ts(type = "any")]
    pub input: SubmitGUTARealmResultAPINoProofInput<F>,
    #[ts(type = "any")]
    pub proof: ProofWithPublicInputs<GoldilocksField, C, D>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, concrete(F = GoldilocksField))]
#[serde(bound = "")]
pub struct QGetUserIdsRPCRequest<F: RichField>(pub QHashOut<F>, pub u64, pub u64);

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct QGetCheckpointSyncInfoRPCRequest {
    pub realm_id: u32,
    pub checkpoint_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct QGetCheckpointSyncInfoCompactRPCRequest {
    pub checkpoint_id: u64,
}

// lps
// QTreeDataStoreReaderSync
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QUserContractStateTreeRootRPCRequest {
    pub checkpoint_id: u64,
    pub user_id: u64,
    pub contract_id: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, concrete(F = GoldilocksField))]
#[serde(bound = "")]
pub struct QUserContractStateTreeRootFRPCRequest<F: RichField> {
    pub checkpoint_id: F,
    pub user_id: F,
    pub contract_id: F,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(bound = "")]
pub struct QUserContractStateTreeLeafHashRPCRequest {
    pub checkpoint_id: u64,
    pub user_id: u64,
    pub contract_id: u32,
    pub height: u8,
    pub leaf_id: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, concrete(F = GoldilocksField))]
#[serde(bound = "")]
pub struct QUserContractStateTreeLeafHashFRPCRequest<F: RichField> {
    pub checkpoint_id: F,
    pub user_id: F,
    pub contract_id: F,
    pub height: u8,
    pub leaf_id: F,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(bound = "")]
pub struct QUserContractStateTreeMerkleProofRPCRequest {
    pub checkpoint_id: u64,
    pub user_id: u64,
    pub contract_id: u32,
    pub height: u8,
    pub leaf_id: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, concrete(F = GoldilocksField))]
#[serde(bound = "")]
pub struct QUserContractStateTreeMerkleProofFRPCRequest<F: RichField> {
    pub checkpoint_id: F,
    pub user_id: F,
    pub contract_id: F,
    pub height: u8,
    pub leaf_id: F,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, concrete(F = GoldilocksField))]
#[serde(bound = "")]
pub struct QUserContractTreeRootRPCRequest {
    pub checkpoint_id: u64,
    pub user_id: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, concrete(F = GoldilocksField))]
#[serde(bound = "")]
pub struct QUserContractTreeRootFRPCRequest<F: RichField> {
    pub checkpoint_id: F,
    pub user_id: F,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(bound = "")]
pub struct QUserContractTreeLeafHashRPCRequest {
    pub checkpoint_id: u64,
    pub user_id: u64,
    pub contract_id: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, concrete(F = GoldilocksField))]
#[serde(bound = "")]
pub struct QUserContractTreeLeafHashFRPCRequest<F: RichField> {
    pub checkpoint_id: F,
    pub user_id: F,
    pub contract_id: F,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(bound = "")]
pub struct QUserContractTreeMerkleProofRPCRequest {
    pub checkpoint_id: u64,
    pub user_id: u64,
    pub contract_id: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, concrete(F = GoldilocksField))]
#[serde(bound = "")]
pub struct QUserContractTreeMerkleProofFRPCRequest<F: RichField> {
    pub checkpoint_id: F,
    pub user_id: F,
    pub contract_id: F,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(bound = "")]
pub struct QUserRegistrationTreeRootRPCRequest {
    pub checkpoint_id: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, concrete(F = GoldilocksField))]
#[serde(bound = "")]
pub struct QUserRegistrationTreeRootFRPCRequest<F: RichField> {
    pub checkpoint_id: F,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(bound = "")]
pub struct QUserRegistrationTreeLeafHashRPCRequest {
    pub checkpoint_id: u64,
    pub leaf_index: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, concrete(F = GoldilocksField))]
#[serde(bound = "")]
pub struct QUserRegistrationTreeLeafHashFRPCRequest<F: RichField> {
    pub checkpoint_id: F,
    pub leaf_index: F,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(bound = "")]
pub struct QUserRegistrationTreeMerkleProofRPCRequest {
    pub checkpoint_id: u64,
    pub leaf_index: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, concrete(F = GoldilocksField))]
#[serde(bound = "")]
pub struct QUserRegistrationTreeMerkleProofFRPCRequest<F: RichField> {
    pub checkpoint_id: F,
    pub leaf_index: F,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QUserTreeRootRPCRequest {
    pub checkpoint_id: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QUserTreeRootFRPCRequest<F: RichField> {
    pub checkpoint_id: F,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QUserTreeLeafHashRPCRequest {
    pub checkpoint_id: u64,
    pub user_id: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QUserTreeLeafHashFRPCRequest<F: RichField> {
    pub checkpoint_id: F,
    pub user_id: F,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QUserTreeMerkleProofRPCRequest {
    pub checkpoint_id: u64,
    pub user_id: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QUserTreeMerkleProofFRPCRequest<F: RichField> {
    pub checkpoint_id: F,
    pub user_id: F,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QUserSubTreeMerkleProofRPCRequest {
    pub checkpoint_id: u64,
    pub root_level: u8,
    pub leaf_level: u8,
    pub leaf_index: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QUserEventTreeRootRPCRequest {
    pub checkpoint_id: u64,
    pub user_id: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QUserEventTreeRootFRPCRequest<F: RichField> {
    pub checkpoint_id: F,
    pub user_id: F,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QUserEventTreeLeafHashRPCRequest {
    pub checkpoint_id: u64,
    pub user_id: u64,
    pub event_index: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QUserEventTreeLeafHashFRPCRequest<F: RichField> {
    pub checkpoint_id: F,
    pub user_id: F,
    pub event_index: F,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QUserEventTreeMerkleProofRPCRequest {
    pub checkpoint_id: u64,
    pub user_id: u64,
    pub event_index: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QUserEventTreeMerkleProofFRPCRequest<F: RichField> {
    pub checkpoint_id: F,
    pub user_id: F,
    pub event_index: F,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QContractFunctionTreeRootRPCRequest {
    pub checkpoint_id: u64,
    pub contract_id: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QContractFunctionTreeRootFRPCRequest<F: RichField> {
    pub checkpoint_id: F,
    pub contract_id: F,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QContractFunctionTreeLeafHashRPCRequest {
    pub checkpoint_id: u64,
    pub contract_id: u32,
    pub function_id: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QContractFunctionTreeLeafHashFRPCRequest<F: RichField> {
    pub checkpoint_id: F,
    pub contract_id: F,
    pub function_id: F,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QContractFunctionTreeMerkleProofRPCRequest {
    pub checkpoint_id: u64,
    pub contract_id: u32,
    pub function_id: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QContractFunctionTreeMerkleProofFRPCRequest<F: RichField> {
    pub checkpoint_id: F,
    pub contract_id: F,
    pub function_id: F,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QContractTreeRootRPCRequest {
    pub checkpoint_id: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QContractTreeRootFRPCRequest<F: RichField> {
    pub checkpoint_id: F,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QContractTreeLeafHashRPCRequest {
    pub checkpoint_id: u64,
    pub contract_id: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QContractTreeLeafHashFRPCRequest<F: RichField> {
    pub checkpoint_id: F,
    pub contract_id: F,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QContractTreeMerkleProofRPCRequest {
    pub checkpoint_id: u64,
    pub contract_id: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QContractTreeMerkleProofFRPCRequest<F: RichField> {
    pub checkpoint_id: F,
    pub contract_id: F,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QDepositTreeLeafHashRPCRequest {
    pub checkpoint_id: u64,
    pub deposit_id: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QDepositTreeLeafHashFRPCRequest<F: RichField> {
    pub checkpoint_id: F,
    pub deposit_id: F,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QDepositTreeMerkleProofRPCRequest {
    pub checkpoint_id: u64,
    pub deposit_id: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QDepositTreeMerkleProofFRPCRequest<F: RichField> {
    pub checkpoint_id: F,
    pub deposit_id: F,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QWithdrawalTreeRootRPCRequest {
    pub checkpoint_id: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QWithdrawalTreeRootFRPCRequest<F: RichField> {
    pub checkpoint_id: F,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QWithdrawalTreeLeafHashRPCRequest {
    pub checkpoint_id: u64,
    pub withdrawal_id: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QWithdrawalTreeLeafHashFRPCRequest<F: RichField> {
    pub checkpoint_id: F,
    pub withdrawal_id: F,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QWithdrawalTreeMerkleProofRPCRequest {
    pub checkpoint_id: u64,
    pub withdrawal_id: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QWithdrawalTreeMerkleProofFRPCRequest<F: RichField> {
    pub checkpoint_id: F,
    pub withdrawal_id: F,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QLatestCheckpointTreeRootRPCRequest {}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QCheckpointTreeRootRPCRequest {
    pub checkpoint_id: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QCheckpointTreeRootFRPCRequest<F: RichField> {
    pub checkpoint_id: F,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QCheckpointTreeLeafHashRPCRequest {
    pub checkpoint_id: u64,
    pub leaf_checkpoint_id: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QCheckpointTreeLeafHashFRPCRequest<F: RichField> {
    pub checkpoint_id: F,
    pub leaf_checkpoint_id: F,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QCheckpointTreeMerkleProofRPCRequest {
    pub checkpoint_id: u64,
    pub leaf_checkpoint_id: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QCheckpointTreeMerkleProofFRPCRequest<F: RichField> {
    pub checkpoint_id: F,
    pub leaf_checkpoint_id: F,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QCheckpointGlobalStateRootsRPCRequest {
    pub checkpoint_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QCheckpointStateTransitionProofRPCRequest {
    pub checkpoint_id: u64,
}

// QMetaDataStoreReaderSync
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QUserLeafDataRPCRequest {
    pub checkpoint_id: u64,
    pub user_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QUserLeafDataFRPCRequest<F: RichField> {
    pub checkpoint_id: F,
    pub user_id: F,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QContractLeafDataRPCRequest {
    pub contract_id: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QContractLeafDataFRPCRequest<F: RichField> {
    pub contract_id: F,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QCheckpointLeafDataRPCRequest {
    pub checkpoint_id: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QCheckpointLeafDataFRPCRequest<F: RichField> {
    pub checkpoint_id: F,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QContractCodeDefinitionRPCRequest {
    pub contract_id: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QContractCodeDefinitionFRPCRequest<F: RichField> {
    pub contract_id: F,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QLatestBlockStateRPCRequest {}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QBlockStateRPCRequest {
    pub checkpoint_id: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QBlockStateFRPCRequest<F: RichField> {
    pub checkpoint_id: F,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
pub struct QUserEventDataRPCRequest {
    pub checkpoint_id: u64,
    pub user_id: u64,
    pub event_index: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QUserEventDataFRPCRequest<F: RichField> {
    pub checkpoint_id: F,
    pub user_id: F,
    pub event_index: F,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QIMTLeafPreimageRPCRequest {
    pub checkpoint_id: u64,
    pub user_id: u64,
    pub contract_id: u64,
    pub leaf_index: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QIMTLeafIndexForKeyRPCRequest<F: RichField> {
    pub checkpoint_id: u64,
    pub user_id: u64,
    pub contract_id: u64,
    pub key: QHashOut<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QFindIMTPredecessorRPCRequest<F: RichField> {
    pub checkpoint_id: u64,
    pub user_id: u64,
    pub contract_id: u64,
    pub key: QHashOut<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QIMTNextAppendIndexRPCRequest {
    pub user_id: u64,
    pub contract_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QFindIMTPredecessorResponse<F: RichField> {
    pub leaf_index: u64,
    pub leaf: psy_client_data::qdata::imt_contract_state::IMTContractStateLeaf<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QProveUpsStartRPCRequest<F: RichField> {
    pub input: UPSStartStepInput<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QProveUpsStartRegisterUserRPCRequest<F: RichField> {
    pub input: UPSStartStepRegisterUserInput<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QRegisterCircuitsRPCRequest {
    pub contract_id: u64,
    pub contract_code: ContractCodeDefinition,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QGetFnIdRPCRequest {
    pub contract_id: u64,
    pub method_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QResolveContractFunctionByMethodNameRPCRequest {
    pub contract_id: u64,
    pub contract_code: ContractCodeDefinition,
    pub method_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QResolveContractFunctionByMethodIdRPCRequest {
    pub contract_id: u64,
    pub contract_code: ContractCodeDefinition,
    pub method_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export)]
pub struct QGetContractMethodCommonDataRPCRequest {
    pub contract_id: u64,
    pub fn_id: u32,
    // pub fingerprint: QHashOut<F>,
    // pub method_name: AltVerifierOnlyCircuitData<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QProveContractCallRPCRequest<F: RichField> {
    pub contract_id: u64,
    pub fn_id: u32,
    pub input: DapenContractFunctionCircuitInput<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QUpsCfcStandardTxRPCRequest<F: RichField> {
    pub input: UPSCFCStandardTransactionCircuitInput<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QUpsCfcDeferredTxRPCRequest<F: RichField> {
    pub input: UPSCFCDeferredTransactionCircuitInput<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QSignatureProofRPCRequest<F: RichField> {
    pub private_key: QHashOut<F>,
    pub sig_hash: QHashOut<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QSignatureInnerProofRPCRequest<F: RichField> {
    pub private_key: QHashOut<F>,
    pub sig_hash: QHashOut<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
pub struct QSignatureMinifierProofRPCRequest {
    pub inner_proof: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
pub struct QBaseProofMinifierRPCRequest {
    pub base_proof: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
// #[ts(export, concrete(F = GoldilocksField))]
pub struct QSecpSignatureProofRPCRequest {
    pub signature: PsyCompressedSecp256K1Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
// #[ts(export, concrete(F = GoldilocksField))]
pub struct QRegisterDPNSoftwareDefinedCircuitRPCRequest {
    pub fn_def: DPNFunctionCircuitDefinition,
    pub contract_id: u64,
    pub contract_state_tree_height: u8,
    pub session_proof_tree_height: u8,
    pub force_four_align: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
// #[ts(export, concrete(F = GoldilocksField))]
pub struct QRegisterPlonky2SoftwareDefinedCircuitRPCRequest {
    pub contract_state_tree_height: u8,
    pub input_len: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct DPNSoftwareDefinedSignatureProofRPCRequest<F: RichField> {
    pub fingerprint: QHashOut<F>,
    pub private_key: QHashOut<F>,
    pub input: DPNSoftwareDefinedSignatureInput,
    pub sig_hash: QHashOut<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct Plonky2SoftwareDefinedSignatureProofRPCRequest<F: RichField> {
    pub fingerprint: QHashOut<F>,
    pub private_key: QHashOut<F>,
    pub circuit_inputs: Vec<GoldilocksField>,
    pub sig_hash: QHashOut<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QAggProofRecord<F: RichField> {
    pub circuit_type: QStandardBinaryTreeCircuitType,
    pub fingerprint: QHashOut<F>,
    pub agg_header: QRecursionAggStandardHeader<F>,
    pub proof: String,
}

use psy_crypto::common::witnesses::qrecursion::proof_data::AggProofRecord;
impl<C: GenericConfig<D>, const D: usize> From<AggProofRecord<C, D>> for QAggProofRecord<C::F> {
    fn from(agg_proof_record: AggProofRecord<C, D>) -> Self {
        Self {
            circuit_type: agg_proof_record.circuit_type,
            fingerprint: agg_proof_record.fingerprint,
            agg_header: agg_proof_record.agg_header,
            proof: serde_json::to_string(&agg_proof_record.proof).unwrap(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QUpsEndCapRPCRequest<F: RichField> {
    pub end_cap_from_proof_tree_input: UPSEndCapFromProofTreeGadgetInput<F>,
    pub agg_proof_record: QAggProofRecord<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct QUpsEndCapRPCRequestV2<C: GenericConfig<D>, const D: usize> {
    pub end_cap_from_proof_tree_input: UPSEndCapFromProofTreeGadgetInput<C::F>,
    // AggProofRecord
    pub circuit_type: QStandardBinaryTreeCircuitType,
    pub fingerprint: QHashOut<C::F>,
    pub agg_header: QRecursionAggStandardHeader<C::F>,
    pub proof: ProofWithPublicInputs<C::F, C, D>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QSingleLeafRpcRequest<F: RichField> {
    pub agg_circuit_whitelist_root: QHashOut<F>,
    pub single_insert_leaf_proof: DeltaMerkleProofCore<QHashOut<F>>,
    pub single_proof: String,
    pub single_verifier_data: AltVerifierOnlyCircuitData<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct QSingleLeafRpcRequestV2<C: GenericConfig<D>, const D: usize> {
    pub agg_circuit_whitelist_root: QHashOut<C::F>,
    pub single_insert_leaf_proof: DeltaMerkleProofCore<QHashOut<C::F>>,
    pub single_proof: ProofWithPublicInputs<C::F, C, D>,
    pub single_verifier_data: AltVerifierOnlyCircuitData<C::F>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QTwoLeafRpcRequest<F: RichField> {
    pub agg_circuit_whitelist_root: QHashOut<F>,
    pub left_insert_leaf_proof: DeltaMerkleProofCore<QHashOut<F>>,
    pub left_proof: String,
    pub left_verifier_data: AltVerifierOnlyCircuitData<F>,
    pub right_insert_leaf_proof: DeltaMerkleProofCore<QHashOut<F>>,
    pub right_proof: String,
    pub right_verifier_data: AltVerifierOnlyCircuitData<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct QTwoLeafRpcRequestV2<C: GenericConfig<D>, const D: usize> {
    pub agg_circuit_whitelist_root: QHashOut<C::F>,
    pub left_insert_leaf_proof: DeltaMerkleProofCore<QHashOut<C::F>>,
    pub left_proof: ProofWithPublicInputs<C::F, C, D>,
    pub left_verifier_data: AltVerifierOnlyCircuitData<C::F>,
    pub right_insert_leaf_proof: DeltaMerkleProofCore<QHashOut<C::F>>,
    pub right_proof: ProofWithPublicInputs<C::F, C, D>,
    pub right_verifier_data: AltVerifierOnlyCircuitData<C::F>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QTwoAggRpcRequset<F: RichField> {
    pub left_agg_whitelist_merkle_proof: MerkleProofCore<QHashOut<F>>,
    pub left_agg_proof_header: QRecursionAggStandardHeader<F>,
    pub left_proof: String,
    pub left_verifier_data: AltVerifierOnlyCircuitData<F>,
    pub right_agg_whitelist_merkle_proof: MerkleProofCore<QHashOut<F>>,
    pub right_agg_proof_header: QRecursionAggStandardHeader<F>,
    pub right_proof: String,
    pub right_verifier_data: AltVerifierOnlyCircuitData<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct QTwoAggRpcRequsetV2<C: GenericConfig<D>, const D: usize> {
    pub left_agg_whitelist_merkle_proof: MerkleProofCore<QHashOut<C::F>>,
    pub left_agg_proof_header: QRecursionAggStandardHeader<C::F>,
    pub left_proof: ProofWithPublicInputs<C::F, C, D>,
    pub left_verifier_data: AltVerifierOnlyCircuitData<C::F>,
    pub right_agg_whitelist_merkle_proof: MerkleProofCore<QHashOut<C::F>>,
    pub right_agg_proof_header: QRecursionAggStandardHeader<C::F>,
    pub right_proof: ProofWithPublicInputs<C::F, C, D>,
    pub right_verifier_data: AltVerifierOnlyCircuitData<C::F>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QLeftLeafRightAggRpcRequest<F: RichField> {
    pub left_insert_leaf_proof: DeltaMerkleProofCore<QHashOut<F>>,
    pub left_proof: String,
    pub left_verifier_data: AltVerifierOnlyCircuitData<F>,
    pub right_agg_whitelist_merkle_proof: MerkleProofCore<QHashOut<F>>,
    pub right_agg_proof_header: QRecursionAggStandardHeader<F>,
    pub right_proof: String,
    pub right_verifier_data: AltVerifierOnlyCircuitData<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct QLeftLeafRightAggRpcRequestV2<C: GenericConfig<D>, const D: usize> {
    pub left_insert_leaf_proof: DeltaMerkleProofCore<QHashOut<C::F>>,
    pub left_proof: ProofWithPublicInputs<C::F, C, D>,
    pub left_verifier_data: AltVerifierOnlyCircuitData<C::F>,
    pub right_agg_whitelist_merkle_proof: MerkleProofCore<QHashOut<C::F>>,
    pub right_agg_proof_header: QRecursionAggStandardHeader<C::F>,
    pub right_proof: ProofWithPublicInputs<C::F, C, D>,
    pub right_verifier_data: AltVerifierOnlyCircuitData<C::F>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QLeftAggRightLeafRpcRequest<F: RichField> {
    pub left_agg_whitelist_merkle_proof: MerkleProofCore<QHashOut<F>>,
    pub left_agg_proof_header: QRecursionAggStandardHeader<F>,
    pub left_proof: String,
    pub left_verifier_data: AltVerifierOnlyCircuitData<F>,
    pub right_insert_leaf_proof: DeltaMerkleProofCore<QHashOut<F>>,
    pub right_proof: String,
    pub right_verifier_data: AltVerifierOnlyCircuitData<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct QLeftAggRightLeafRpcRequestV2<C: GenericConfig<D>, const D: usize> {
    pub left_agg_whitelist_merkle_proof: MerkleProofCore<QHashOut<C::F>>,
    pub left_agg_proof_header: QRecursionAggStandardHeader<C::F>,
    pub left_proof: ProofWithPublicInputs<C::F, C, D>,
    pub left_verifier_data: AltVerifierOnlyCircuitData<C::F>,
    pub right_insert_leaf_proof: DeltaMerkleProofCore<QHashOut<C::F>>,
    pub right_proof: ProofWithPublicInputs<C::F, C, D>,
    pub right_verifier_data: AltVerifierOnlyCircuitData<C::F>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QGetUserEndCapSlotUpdatesRPCRequest {
    pub unique_pending_id: u64,
    pub user_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealmSlotUpdate {
    pub slot: u64,
    pub old_value: u64,
    pub new_value: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealmContractSlotUpdates {
    pub contract_id: u32,
    pub slot_updates: Vec<RealmSlotUpdate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealmEndCapSlotUpdates {
    pub realm_id: u64,
    pub realm_sub_id: u64,
    pub unique_pending_id: u64,
    pub user_id: u64,
    pub contracts: Vec<RealmContractSlotUpdates>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
pub struct QGetCheckpointIdForUniquePendingIdRPCRequest {
    pub unique_pending_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct QGenerateBatchProofMinerRewardProofsRPCRequest {
    pub unique_pending_id: u64,
    pub job_ids: Vec<QProvingJobDataIDWithRewardPath>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(bound = "")]
#[serde(untagged)]
#[ts(export, concrete(F = GoldilocksField))]
pub enum QRPCRequest<F: RichField> {
    QTokenTransferRPCRequest((u32, QTokenTransferRPCRequest)),
    QClaimDepositRPCRequest((u32, QClaimDepositRPCRequest)),
    QAddWithdrawalRPCRequest((u32, QAddWithdrawalRPCRequest)),
    QRegisterUserRPCRequest((u32, QRegisterUserRPCRequest<F>)),
    QDeployContractRPCRequest((u32, QDeployContractRPCRequest<F>)),
    QProduceBlockRPCRequest((u32, ())),
    QSubmitEndCapRPCRequest((u32, QSubmitEndCapRPCRequest<F>)),

    // QTreeDataStoreReaderSync
    QUserContractStateTreeRootRPCRequest((u32, QUserContractStateTreeRootRPCRequest)),
    QUserContractStateTreeRootFRPCRequest((u32, QUserContractStateTreeRootFRPCRequest<F>)),
    QUserContractStateTreeLeafHashRPCRequest((u32, QUserContractStateTreeLeafHashRPCRequest)),
    QUserContractStateTreeLeafHashFRPCRequest((u32, QUserContractStateTreeLeafHashFRPCRequest<F>)),
    QUserContractStateTreeMerkleProofRPCRequest((u32, QUserContractStateTreeMerkleProofRPCRequest)),
    QUserContractStateTreeMerkleProofFRPCRequest((u32, QUserContractStateTreeMerkleProofFRPCRequest<F>)),

    QUserContractTreeRootRPCRequest((u32, QUserContractTreeRootRPCRequest)),
    QUserContractTreeRootFRPCRequest((u32, QUserContractTreeRootFRPCRequest<F>)),
    QUserContractTreeLeafHashRPCRequest((u32, QUserContractTreeLeafHashRPCRequest)),
    QUserContractTreeLeafHashFRPCRequest((u32, QUserContractTreeLeafHashFRPCRequest<F>)),
    QUserContractTreeMerkleProofRPCRequest((u32, QUserContractTreeMerkleProofRPCRequest)),
    QUserContractTreeMerkleProofFRPCRequest((u32, QUserContractTreeMerkleProofFRPCRequest<F>)),
    QUserRegistrationTreeRootRPCRequest((u32, QUserRegistrationTreeRootRPCRequest)),
    QUserRegistrationTreeRootFRPCRequest((u32, QUserRegistrationTreeRootFRPCRequest<F>)),
    QUserRegistrationTreeLeafHashRPCRequest((u32, QUserRegistrationTreeLeafHashRPCRequest)),
    QUserRegistrationTreeLeafHashFRPCRequest((u32, QUserRegistrationTreeLeafHashFRPCRequest<F>)),
    QUserRegistrationTreeMerkleProofRPCRequest((u32, QUserRegistrationTreeMerkleProofRPCRequest)),
    QUserRegistrationTreeMerkleProofFRPCRequest((u32, QUserRegistrationTreeMerkleProofFRPCRequest<F>)),
    QUserTreeRootRPCRequest((u32, QUserTreeRootRPCRequest)),
    QUserTreeRootFRPCRequest((u32, QUserTreeRootFRPCRequest<F>)),
    QUserTreeLeafHashRPCRequest((u32, QUserTreeLeafHashRPCRequest)),
    QUserTreeLeafHashFRPCRequest((u32, QUserTreeLeafHashFRPCRequest<F>)),

    QUserSubTreeMerkleProofRPCRequest((u32, QUserSubTreeMerkleProofRPCRequest)),
    QContractFunctionTreeRootRPCRequest((u32, QContractFunctionTreeRootRPCRequest)),
    QContractFunctionTreeRootFRPCRequest((u32, QContractFunctionTreeRootFRPCRequest<F>)),
    QContractFunctionTreeLeafHashRPCRequest((u32, QContractFunctionTreeLeafHashRPCRequest)),
    QContractFunctionTreeLeafHashFRPCRequest((u32, QContractFunctionTreeLeafHashFRPCRequest<F>)),
    QContractFunctionTreeMerkleProofRPCRequest((u32, QContractFunctionTreeMerkleProofRPCRequest)),
    QContractFunctionTreeMerkleProofFRPCRequest((u32, QContractFunctionTreeMerkleProofFRPCRequest<F>)),
    QContractTreeRootRPCRequest((u32, QContractTreeRootRPCRequest)),
    QContractTreeRootFRPCRequest((u32, QContractTreeRootFRPCRequest<F>)),
    QContractTreeLeafHashRPCRequest((u32, QContractTreeLeafHashRPCRequest)),
    QContractTreeLeafHashFRPCRequest((u32, QContractTreeLeafHashFRPCRequest<F>)),
    QContractTreeMerkleProofRPCRequest((u32, QContractTreeMerkleProofRPCRequest)),
    QContractTreeMerkleProofFRPCRequest((u32, QContractTreeMerkleProofFRPCRequest<F>)),
    QDepositTreeLeafHashRPCRequest((u32, QDepositTreeLeafHashRPCRequest)),
    QDepositTreeLeafHashFRPCRequest((u32, QDepositTreeLeafHashFRPCRequest<F>)),
    QDepositTreeMerkleProofRPCRequest((u32, QDepositTreeMerkleProofRPCRequest)),
    QDepositTreeMerkleProofFRPCRequest((u32, QDepositTreeMerkleProofFRPCRequest<F>)),
    QWithdrawalTreeRootRPCRequest((u32, QWithdrawalTreeRootRPCRequest)),
    QWithdrawalTreeRootFRPCRequest((u32, QWithdrawalTreeRootFRPCRequest<F>)),
    QWithdrawalTreeLeafHashRPCRequest((u32, QWithdrawalTreeLeafHashRPCRequest)),
    QWithdrawalTreeLeafHashFRPCRequest((u32, QWithdrawalTreeLeafHashFRPCRequest<F>)),
    QWithdrawalTreeMerkleProofRPCRequest((u32, QWithdrawalTreeMerkleProofRPCRequest)),
    QWithdrawalTreeMerkleProofFRPCRequest((u32, QWithdrawalTreeMerkleProofFRPCRequest<F>)),
    QLatestCheckpointTreeRootRPCRequest((u32, QLatestCheckpointTreeRootRPCRequest)),
    QCheckpointTreeRootRPCRequest((u32, QCheckpointTreeRootRPCRequest)),
    QCheckpointTreeRootFRPCRequest((u32, QCheckpointTreeRootFRPCRequest<F>)),
    QCheckpointTreeLeafHashRPCRequest((u32, QCheckpointTreeLeafHashRPCRequest)),
    QCheckpointTreeLeafHashFRPCRequest((u32, QCheckpointTreeLeafHashFRPCRequest<F>)),
    QCheckpointTreeMerkleProofRPCRequest((u32, QCheckpointTreeMerkleProofRPCRequest)),
    QCheckpointTreeMerkleProofFRPCRequest((u32, QCheckpointTreeMerkleProofFRPCRequest<F>)),
    QCheckpointGlobalStateRootsRPCRequest((u32, QCheckpointGlobalStateRootsRPCRequest)),

    // QMetaDataStoreReaderSync
    QUserLeafDataRPCRequest((u32, QUserLeafDataRPCRequest)),
    QUserLeafDataFRPCRequest((u32, QUserLeafDataFRPCRequest<F>)),
    QContractLeafDataRPCRequest((u32, QContractLeafDataRPCRequest)),
    QContractLeafDataFRPCRequest((u32, QContractLeafDataFRPCRequest<F>)),
    QCheckpointLeafDataRPCRequest((u32, QCheckpointLeafDataRPCRequest)),
    QCheckpointLeafDataFRPCRequest((u32, QCheckpointLeafDataFRPCRequest<F>)),
    QContractCodeDefinitionRPCRequest((u32, QContractCodeDefinitionRPCRequest)),
    QContractCodeDefinitionFRPCRequest((u32, QContractCodeDefinitionFRPCRequest<F>)),
    QLatestBlockStateRPCRequest((u32, QLatestBlockStateRPCRequest)),
    QBlockStateRPCRequest((u32, QBlockStateRPCRequest)),
    QBlockStateFRPCRequest((u32, QBlockStateFRPCRequest<F>)),

    // genetate proof
    QProveUpsStartRPCRequest((u32, QProveUpsStartRPCRequest<F>)),
    QProveContractCallRPCRequest((u32, QProveContractCallRPCRequest<F>)),
    QUpsCfcStandardTxRPCRequest((u32, QUpsCfcStandardTxRPCRequest<F>)),
    QSignatureProofRPCRequest((u32, QSignatureProofRPCRequest<F>)),
    QUpsEndCapRPCRequest((u32, QUpsEndCapRPCRequest<F>)),

    // tree proof
    QSingleLeafRpcRequest((u32, QSingleLeafRpcRequest<F>)),
    QTwoLeafRpcRequest((u32, QTwoLeafRpcRequest<F>)),
    QTwoAggRpcRequset((u32, QTwoAggRpcRequset<F>)),
    QLeftLeafRightAggRpcRequest((u32, QLeftLeafRightAggRpcRequest<F>)),
    QLeftAggRightLeafRpcRequest((u32, QLeftAggRightLeafRpcRequest<F>)),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eth_personal_signature_request_round_trip_preserves_exact_bytes() {
        let signature = PsyCompressedSecp256K1Signature {
            public_key: core::array::from_fn(|index| index as u8),
            signature: core::array::from_fn(|index| (index + 33) as u8),
            message: Hash256(core::array::from_fn(|index| (255 - index) as u8)),
        };
        let request = RpcRequest {
            jsonrpc: Version::V2,
            request: RequestParams::<GoldilocksField>::EthPersonalSECPSignatureProof(QSecpSignatureProofRPCRequest { signature }),
            id: Id::Number(7),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"method\":\"psy_prove_eth_personal_secp_sign\""));
        let decoded: RpcRequest<RequestParams<GoldilocksField>> = serde_json::from_str(&json).unwrap();
        match decoded.request {
            RequestParams::EthPersonalSECPSignatureProof(decoded_request) => assert_eq!(decoded_request.signature, signature),
            _ => panic!("wrong request variant after round trip"),
        }
    }
}
