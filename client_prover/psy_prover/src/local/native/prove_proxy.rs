use std::{
    path::PathBuf,
    sync::Arc,
};

use jsonrpsee::{
    core::async_trait,
    proc_macros::rpc,
    types::{ErrorObject, ErrorObjectOwned},
};
use parth_core::pgoldilocks::QHashOut as ParthQHashOut;
use plonky2::{
    field::types::Field,
    hash::hash_types::HashOut,
    plonk::{
        config::{GenericConfig, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_client_common::data::{alt::AltVerifierOnlyCircuitData, qhashout::QHashOut};
use psy_client_data::{
    qdata::contract::ContractCodeDefinition,
    qstore::{
        controllers::session_info::SessionCircuitInfoStore,
        imm::{cmd::QSRCmdGetContractCodeDefinition, cmd_processor::PsyReadCommandProcessorSync},
    },
    ups::{
        start_step::UPSStartStepInput,
        start_step_register_user::UPSStartStepRegisterUserInput,
        ups_cfc_standard_step::{UPSCFCDeferredTransactionCircuitInput, UPSCFCStandardTransactionCircuitInput},
        ups_end_cap::UPSEndCapFromProofTreeGadgetInput,
    },
};
use psy_common_circuit::circuits::traits::qstandard::QStandardCircuit;
use psy_crypto::{
    common::witnesses::qrecursion::{header::QRecursionAggStandardHeader, proof_data::QStandardBinaryTreeCircuitType},
    hash::merkle::core::{DeltaMerkleProofCore, MerkleProofCore},
    signature::secp256k1::core::PsyCompressedSecp256K1Signature,
};
use psy_plonky2_circuits::{
    bridge::circuits::bridge_wrap::{
        DepositBatchWrapCircuit, SharedGroth16Wrapper, UncompressedGroth16ProofData, WithdrawalClaimWrapCircuit,
    },
    proof_minifier::pm_chain::QEDProofMinifierChain,
};
use psy_plonky2_common_circuits::bridge::{
    deposit_batch_append_circuit::{
        compute_batch_append_preimage, BatchAppendInputs as DepositBatchAppendInputs, DepositBatchAppendCircuit,
        DepositLeafData as DepositBatchLeafData, MAX_DEPOSIT_BATCH_SIZE,
    },
    withdrawal_batch_claim_circuit::{
        WithdrawalBatchClaimCircuit, WithdrawalBatchClaimInputs, WithdrawalBatchClaimSlotInputs, MAX_WITHDRAWAL_CLAIM_BATCH_SIZE,
        WITHDRAWAL_BATCH_CLAIM_PUBLIC_INPUTS_WORDS, WITHDRAWAL_BATCH_CLAIM_SLOT_WORDS,
    },
};
use psy_provider::{
    provider::{LocalCommonCircuitsData, QCommonCircuitData, RpcProvider},
    request::{DPNSoftwareDefinedSignatureInput, QRegisterDPNSoftwareDefinedCircuitRPCRequest, QRegisterPlonky2SoftwareDefinedCircuitRPCRequest},
};
use psy_ups_circuit::circuit_manager::core::PsyUPSStepCircuitManager;
use psy_vm::{
    ups::{circuit_manager::UPSCircuitManager, signature::Plonky2SoftwareDefinedSignatureInput},
    vm::cfc_input::DapenContractFunctionCircuitInput,
};

use crate::local::native::DPNFunctionCircuitDefinition;

type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;
const D: usize = 2;
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BridgeWithdrawalWitnessInput {
    pub withdrawal_root: String,
    pub sender_user_id: u32,
    pub recipient: [u32; 8],
    pub token: [u32; 8],
    pub amount: [u32; 8],
    pub nonce: [u32; 8],
    pub destination_chain_index: u32,
    pub leaf_index: u32,
    pub bridge_user_id: u32,
    pub siblings: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BridgeWithdrawalBatchWitnessInput {
    pub bridge_user_id: u32,
    pub withdrawals: Vec<BridgeWithdrawalWitnessInput>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BridgeWithdrawalBatchGroth16Proof {
    pub solidity_proof: [String; 8],
    pub public_inputs: Vec<u64>,
    pub slot_data: Vec<u64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BridgeDepositLeafInput {
    pub shield_address: [u32; 8],
    pub token: [u32; 8],
    pub l2_token_contract_id: [u32; 8],
    pub amount: [u32; 8],
    pub chain_index: u32,
    pub note_commitment: [u32; 8],
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BridgeDepositBatchWitnessInput {
    pub from_index: u32,
    pub bridge_user_id: u32,
    pub old_frontier: Vec<String>,
    pub deposits: Vec<BridgeDepositLeafInput>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BridgeDepositBatchGroth16Proof {
    pub solidity_proof: [String; 8],
    pub public_inputs: Vec<u64>,
}

fn parse_hex_qhashout(hex: &str) -> anyhow::Result<ParthQHashOut<F>> {
    let hex = hex.trim_start_matches("0x");
    anyhow::ensure!(hex.len() == 64, "expected 64 hex chars, got {}", hex.len());
    let bytes = hex::decode(hex)?;
    let mut elems = [0u64; 4];
    for i in 0..4 {
        let reverse_i = 3 - i;
        let hi = u32::from_be_bytes(bytes[reverse_i * 8..reverse_i * 8 + 4].try_into()?);
        let lo = u32::from_be_bytes(bytes[reverse_i * 8 + 4..reverse_i * 8 + 8].try_into()?);
        elems[i] = ((hi as u64) << 32) | (lo as u64);
    }
    Ok(ParthQHashOut(HashOut {
        elements: elems.map(F::from_canonical_u64),
    }))
}


fn g16_proof_to_solidity_words(groth16: &UncompressedGroth16ProofData) -> [String; 8] {
    let with_0x = |s: &str| -> String {
        if s.starts_with("0x") {
            s.to_string()
        } else {
            format!("0x{}", s)
        }
    };
    [
        with_0x(&groth16.pi_a[0]),
        with_0x(&groth16.pi_a[1]),
        with_0x(&groth16.pi_b[0][1]),
        with_0x(&groth16.pi_b[0][0]),
        with_0x(&groth16.pi_b[1][1]),
        with_0x(&groth16.pi_b[1][0]),
        with_0x(&groth16.pi_c[0]),
        with_0x(&groth16.pi_c[1]),
    ]
}

#[rpc(server, client, namespace = "psy")]
pub trait ProveProxyRpc {
    /// local proving proof generate
    #[method(name = "prove_ups_start")]
    async fn prove_ups_start(&self, input: UPSStartStepInput<F>) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned>;
    #[method(name = "prove_ups_start_register_user")]
    async fn prove_ups_start_register_user(
        &self,
        input: UPSStartStepRegisterUserInput<F>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned>;

    #[method(name = "get_circuits_data")]
    async fn get_circuits_data(&self) -> Result<String, ErrorObjectOwned>;

    #[method(name = "get_fn_id")]
    async fn get_fn_id(&self, contract_id: u64, method_name: String) -> Result<u64, ErrorObjectOwned>;

    #[method(name = "get_fn_id_and_circuit_def")]
    async fn get_fn_id_and_circuit_def(&self, contract_id: u64, method_name: String)
        -> Result<(u64, DPNFunctionCircuitDefinition), ErrorObjectOwned>;

    #[method(name = "get_contract_method_common_data")]
    async fn get_contract_method_common_data(&self, contract_id: u64, fn_id: u32) -> Result<QCommonCircuitData<F>, ErrorObjectOwned>;

    #[method(name = "register_contract_circuits")]
    async fn register_contract_circuits(&self, contract_id: u64, contract_code: ContractCodeDefinition) -> Result<(), ErrorObjectOwned>;

    #[method(name = "resolve_contract_function_by_method_name")]
    async fn resolve_contract_function_by_method_name(
        &self,
        contract_id: u64,
        contract_code: ContractCodeDefinition,
        method_name: String,
    ) -> Result<(u64, DPNFunctionCircuitDefinition), ErrorObjectOwned>;

    #[method(name = "resolve_contract_function_by_method_id")]
    async fn resolve_contract_function_by_method_id(
        &self,
        contract_id: u64,
        contract_code: ContractCodeDefinition,
        method_id: u32,
    ) -> Result<(u64, DPNFunctionCircuitDefinition), ErrorObjectOwned>;

    #[method(name = "prove_contract_call")]
    async fn prove_contract_call(
        &self,
        contract_id: u64,
        fn_id: u32,
        input: DapenContractFunctionCircuitInput<F>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned>;

    #[method(name = "prove_ups_cfc_standard_tx")]
    async fn prove_ups_cfc_standard_tx(
        &self,
        input: UPSCFCStandardTransactionCircuitInput<F>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned>;

    #[method(name = "prove_ups_cfc_deferred_tx")]
    async fn prove_ups_cfc_deferred_tx(
        &self,
        input: UPSCFCDeferredTransactionCircuitInput<F>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned>;

    #[method(name = "prove_zk_sign_minifier")]
    async fn prove_zk_sign_minifier(&self, inner_proof: String) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned>;

    #[method(name = "prove_private_note_inclusion_minifier")]
    async fn prove_private_note_inclusion_minifier(&self, base_proof: String) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned>;

    #[method(name = "prove_shield_deposit_claim_minifier")]
    async fn prove_shield_deposit_claim_minifier(&self, base_proof: String) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned>;

    #[method(name = "prove_secp_sign")]
    async fn prove_secp_sign(&self, signature: PsyCompressedSecp256K1Signature) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned>;

    #[method(name = "prove_eth_personal_secp_sign")]
    async fn prove_eth_personal_secp_sign(
        &self,
        signature: PsyCompressedSecp256K1Signature,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned>;

    #[method(name = "register_dpn_software_defined_circuit")]
    async fn register_dpn_software_defined_circuit(
        &self,
        request: QRegisterDPNSoftwareDefinedCircuitRPCRequest,
    ) -> Result<QHashOut<F>, ErrorObjectOwned>;

    #[method(name = "register_plonky2_software_defined_circuit")]
    async fn register_plonky2_software_defined_circuit(
        &self,
        request: QRegisterPlonky2SoftwareDefinedCircuitRPCRequest,
    ) -> Result<QHashOut<F>, ErrorObjectOwned>;

    #[method(name = "prove_dpn_software_defined_sign")]
    async fn prove_dpn_software_defined_sign(
        &self,
        fingerprint: QHashOut<F>,
        private_key: QHashOut<F>,
        input: DPNSoftwareDefinedSignatureInput,
        sig_hash: QHashOut<F>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned>;

    #[method(name = "prove_plonky2_software_defined_sign")]
    async fn prove_plonky2_software_defined_sign(
        &self,
        fingerprint: QHashOut<F>,
        private_key: QHashOut<F>,
        input: Plonky2SoftwareDefinedSignatureInput,
        sig_hash: QHashOut<F>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned>;

    // #[method(name = "finalize_tree")]
    // async fn finalize_tree(&self) -> Result<ProofWithPublicInputs<F, C, D>,
    // ErrorObjectOwned>;

    #[method(name = "prove_ups_end_cap")]
    async fn prove_ups_end_cap(
        &self,
        end_cap_from_proof_tree_input: UPSEndCapFromProofTreeGadgetInput<F>,
        // AggProofRecord
        circuit_type: QStandardBinaryTreeCircuitType,
        fingerprint: QHashOut<F>,
        agg_header: QRecursionAggStandardHeader<F>,
        proof: ProofWithPublicInputs<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned>;

    // #[method(name = "get_verifier_data_by_type")]
    // async fn get_verifier_data_by_type(
    //     &self,
    //     circuit_type: QStandardBinaryTreeCircuitType,
    // ) -> ResultAltVerifierOnlyCircuitData;

    #[method(name = "prove_single_leaf_circuit")]
    async fn prove_single_leaf_circuit(
        &self,
        agg_circuit_whitelist_root: QHashOut<F>,
        single_insert_leaf_proof: DeltaMerkleProofCore<QHashOut<F>>,
        single_proof: ProofWithPublicInputs<F, C, D>,
        single_verifier_data: AltVerifierOnlyCircuitData<F>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned>;

    #[method(name = "prove_two_leaf_circuit")]
    async fn prove_two_leaf_circuit(
        &self,
        agg_circuit_whitelist_root: QHashOut<F>,
        left_insert_leaf_proof: DeltaMerkleProofCore<QHashOut<F>>,
        left_proof: ProofWithPublicInputs<F, C, D>,
        left_verifier_data: AltVerifierOnlyCircuitData<F>,
        right_insert_leaf_proof: DeltaMerkleProofCore<QHashOut<F>>,
        right_proof: ProofWithPublicInputs<F, C, D>,
        right_verifier_data: AltVerifierOnlyCircuitData<F>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned>;

    #[method(name = "prove_two_agg_circuit")]
    async fn prove_two_agg_circuit(
        &self,
        left_agg_whitelist_merkle_proof: MerkleProofCore<QHashOut<F>>,
        left_agg_proof_header: QRecursionAggStandardHeader<F>,
        left_proof: ProofWithPublicInputs<F, C, D>,
        left_verifier_data: AltVerifierOnlyCircuitData<F>,
        right_agg_whitelist_merkle_proof: MerkleProofCore<QHashOut<F>>,
        right_agg_proof_header: QRecursionAggStandardHeader<F>,
        right_proof: ProofWithPublicInputs<F, C, D>,
        right_verifier_data: AltVerifierOnlyCircuitData<F>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned>;

    #[method(name = "prove_left_leaf_right_agg_circuit")]
    async fn prove_left_leaf_right_agg_circuit(
        &self,
        left_insert_leaf_proof: DeltaMerkleProofCore<QHashOut<F>>,
        left_proof: ProofWithPublicInputs<F, C, D>,
        left_verifier_data: AltVerifierOnlyCircuitData<F>,
        right_agg_whitelist_merkle_proof: MerkleProofCore<QHashOut<F>>,
        right_agg_proof_header: QRecursionAggStandardHeader<F>,
        right_proof: ProofWithPublicInputs<F, C, D>,
        right_verifier_data: AltVerifierOnlyCircuitData<F>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned>;

    #[method(name = "prove_left_agg_right_leaf_circuit")]
    async fn prove_left_agg_right_leaf_circuit(
        &self,
        left_agg_whitelist_merkle_proof: MerkleProofCore<QHashOut<F>>,
        left_agg_proof_header: QRecursionAggStandardHeader<F>,
        left_proof: ProofWithPublicInputs<F, C, D>,
        left_verifier_data: AltVerifierOnlyCircuitData<F>,
        right_insert_leaf_proof: DeltaMerkleProofCore<QHashOut<F>>,
        right_proof: ProofWithPublicInputs<F, C, D>,
        right_verifier_data: AltVerifierOnlyCircuitData<F>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned>;

    #[method(name = "prove_withdrawal_batch_claim_groth16")]
    async fn prove_withdrawal_batch_claim_groth16(
        &self,
        input: BridgeWithdrawalBatchWitnessInput,
    ) -> Result<BridgeWithdrawalBatchGroth16Proof, ErrorObjectOwned>;

    #[method(name = "prove_deposit_batch_append_groth16")]
    async fn prove_deposit_batch_append_groth16(
        &self,
        input: BridgeDepositBatchWitnessInput,
    ) -> Result<BridgeDepositBatchGroth16Proof, ErrorObjectOwned>;

}

pub struct ProveProxyServerProvider {
    pub rpc_provider: RpcProvider,
    pub circuit_manager: Arc<PsyUPSStepCircuitManager<C, D>>,
    pub circuit_info: Arc<SessionCircuitInfoStore<F>>,
    pub circuits_data: LocalCommonCircuitsData<F>,
    pub keystore_dir: Option<PathBuf>,
    pub deployments_network: String,
    /// Pre-built wrapping circuits shared across all prove requests.
    pub deposit_batch_wrap_circuit: Arc<DepositBatchWrapCircuit>,
    pub withdrawal_claim_wrap_circuit: Arc<WithdrawalClaimWrapCircuit>,
    pub deposit_batch_groth16_wrapper: Arc<SharedGroth16Wrapper>,
    pub withdrawal_claim_groth16_wrapper: Arc<SharedGroth16Wrapper>,
    /// Warmup-built base circuits reused verbatim by prove requests.
    pub deposit_append_circuit: Arc<DepositBatchAppendCircuit<C, D>>,
    pub deposit_batch_minifier: Arc<QEDProofMinifierChain<D, F, C>>,
    pub withdrawal_claim_circuit: Arc<WithdrawalBatchClaimCircuit<C, D>>,
}

impl ProveProxyServerProvider {
    pub async fn new_with_config(rpc_config: psy_config::NetworkConfigGoldilocks, network_magic: u64) -> anyhow::Result<Self> {
        use psy_client_data::qstore::controllers::session_info::SessionCircuitInfoStore;
        use psy_common_circuit::circuits::traits::qstandard::QStandardCircuit;
        use psy_plonky2_circuits::qstandard::QStandardCircuit as PlonkyQStandardCircuit;

        let rpc_provider = RpcProvider::new_with_config(&rpc_config)?;

        let circuit_manager = PsyUPSStepCircuitManager::<C, D>::new_with_config(network_magic);
        let mut circuit_info = SessionCircuitInfoStore::new();

        // circuit_info.register_circuit(
        //     LocalCircuitType::SimpleZKSignature.into(),
        //     zk_circuit.get_fingerprint(),
        //     zk_circuit.get_verifier_config_ref().into(),
        // );
        // circuit_info.register_circuit(
        //     LocalCircuitType::SimpleSecp256K1.into(),
        //     secp_circuit.get_fingerprint(),
        //     secp_circuit.get_verifier_config_ref().into(),
        // );

        circuit_manager.register_info(&mut circuit_info).await;

        let circuits_data = LocalCommonCircuitsData {
            ups_start: QCommonCircuitData {
                fingerprint: circuit_manager.ups_start.get_fingerprint(),
                verifier_config: circuit_manager.ups_start.get_verifier_config_ref().into(),
            },
            ups_start_register_user: QCommonCircuitData {
                fingerprint: circuit_manager.ups_start_register_user.get_fingerprint(),
                verifier_config: circuit_manager.ups_start_register_user.get_verifier_config_ref().into(),
            },
            ups_cfc_standard_tx: QCommonCircuitData {
                fingerprint: circuit_manager.ups_cfc_standard_tx.get_fingerprint(),
                verifier_config: circuit_manager.ups_cfc_standard_tx.get_verifier_config_ref().into(),
            },
            ups_cfc_deferred_tx: QCommonCircuitData {
                fingerprint: circuit_manager.ups_cfc_deferred_tx.get_fingerprint(),
                verifier_config: circuit_manager.ups_cfc_deferred_tx.get_verifier_config_ref().into(),
            },
            ups_end_cap: QCommonCircuitData {
                fingerprint: circuit_manager.ups_end_cap.get_fingerprint(),
                verifier_config: circuit_manager.ups_end_cap.get_verifier_config_ref().into(),
            },
            ups_circuit_whitelist_root: circuit_manager.ups_circuit_whitelist_root.clone(),
            ups_start_whitelist_proof: circuit_manager.ups_start_whitelist_proof.clone(),
            ups_start_register_user_whitelist_proof: circuit_manager.ups_start_register_user_whitelist_proof.clone(),
            ups_cfc_standard_tx_whitelist_proof: circuit_manager.ups_cfc_standard_tx_whitelist_proof.clone(),
            ups_cfc_deferred_tx_whitelist_proof: circuit_manager.ups_cfc_deferred_tx_whitelist_proof.clone(),
            single_leaf_circuit: QCommonCircuitData {
                fingerprint: circuit_manager.proof_tree_agg_circuits.circuit_set.single_leaf_circuit.get_fingerprint(),
                verifier_config: circuit_manager
                    .proof_tree_agg_circuits
                    .circuit_set
                    .single_leaf_circuit
                    .get_verifier_config_ref()
                    .into(),
            },
            two_leaf_circuit: QCommonCircuitData {
                fingerprint: circuit_manager.proof_tree_agg_circuits.circuit_set.two_leaf_circuit.get_fingerprint(),
                verifier_config: circuit_manager
                    .proof_tree_agg_circuits
                    .circuit_set
                    .two_leaf_circuit
                    .get_verifier_config_ref()
                    .into(),
            },
            two_agg_circuit: QCommonCircuitData {
                fingerprint: circuit_manager.proof_tree_agg_circuits.circuit_set.two_agg_circuit.get_fingerprint(),
                verifier_config: circuit_manager
                    .proof_tree_agg_circuits
                    .circuit_set
                    .two_agg_circuit
                    .get_verifier_config_ref()
                    .into(),
            },
            left_leaf_right_agg_circuit: QCommonCircuitData {
                fingerprint: circuit_manager
                    .proof_tree_agg_circuits
                    .circuit_set
                    .left_leaf_right_agg_circuit
                    .get_fingerprint(),
                verifier_config: circuit_manager
                    .proof_tree_agg_circuits
                    .circuit_set
                    .left_leaf_right_agg_circuit
                    .get_verifier_config_ref()
                    .into(),
            },
            left_agg_right_leaf_circuit: QCommonCircuitData {
                fingerprint: circuit_manager
                    .proof_tree_agg_circuits
                    .circuit_set
                    .left_agg_right_leaf_circuit
                    .get_fingerprint(),
                verifier_config: circuit_manager
                    .proof_tree_agg_circuits
                    .circuit_set
                    .left_agg_right_leaf_circuit
                    .get_verifier_config_ref()
                    .into(),
            },
            leaf_circuit_config_id: circuit_manager.proof_tree_agg_circuits.circuit_set.leaf_circuit_config_id,
            leaf_verifier_data_cap_height: circuit_manager.proof_tree_agg_circuits.circuit_set.leaf_verifier_data_cap_height,
            agg_verifier_data_cap_height: circuit_manager.proof_tree_agg_circuits.circuit_set.agg_verifier_data_cap_height,
            circuit_inclusion_proofs: circuit_manager.proof_tree_agg_circuits.circuit_inclusion_proofs.clone(),
            zk_circuit: QCommonCircuitData {
                fingerprint: circuit_manager.zk_signature_minifier_fingerprint().await?.clone(),
                verifier_config: circuit_manager.zk_signature_minifier_verifier_config().await?.into(),
            },
            secp_circuit: QCommonCircuitData {
                fingerprint: circuit_manager.secp_circuit().get_fingerprint(),
                verifier_config: circuit_manager.secp_circuit().get_verifier_config_ref().into(),
            },
            private_note_inclusion_minifier: QCommonCircuitData {
                fingerprint: circuit_manager.private_note_inclusion_minifier_circuit().get_fingerprint(),
                verifier_config: circuit_manager.private_note_inclusion_minifier_circuit().get_verifier_config_ref().into(),
            },
            shield_deposit_claim_minifier: QCommonCircuitData {
                fingerprint: circuit_manager.shield_deposit_claim_minifier_circuit().get_fingerprint(),
                verifier_config: circuit_manager.shield_deposit_claim_minifier_circuit().get_verifier_config_ref().into(),
            },
            eth_personal_secp_circuit: Some(QCommonCircuitData {
                fingerprint: circuit_manager.eth_personal_secp_circuit().get_fingerprint(),
                verifier_config: circuit_manager.eth_personal_secp_circuit().get_verifier_config_ref().into(),
            }),
        };

        // ── Pre-build Groth16 wrapping circuits (shared across all threads) ──
        // These depend only on the inner circuit structure, not on runtime data.
        // Building once at startup saves ~200ms per request (CircuitBuilder::new +
        // builder.build).

        tracing::info!("Pre-building DepositBatchWrapCircuit...");
        let deposit_template = Arc::new(DepositBatchAppendCircuit::<C, D>::build(MAX_DEPOSIT_BATCH_SIZE, 32));
        let deposit_minifier = Arc::new(QEDProofMinifierChain::<D, F, C>::new(
            &deposit_template.circuit_data.verifier_only,
            &deposit_template.circuit_data.common,
            2,
        ));
        let deposit_fp = ParthQHashOut(deposit_minifier.get_fingerprint());
        let deposit_batch_wrap_circuit = Arc::new(DepositBatchWrapCircuit::new(
            deposit_minifier.get_common_data(),
            deposit_fp,
            deposit_minifier.get_verifier_data().constants_sigmas_cap.height(),
        ));
        let deposit_batch_groth16_wrapper = Arc::new(
            DepositBatchWrapCircuit::new(
                deposit_minifier.get_common_data(),
                deposit_fp,
                deposit_minifier.get_verifier_data().constants_sigmas_cap.height(),
            )
            .into_shared_groth16_wrapper(format!("{}/.psy/keystore/deposit_append/", dirs::home_dir().unwrap().display())),
        );

        tracing::info!("Pre-building WithdrawalClaimWrapCircuit...");
        let withdrawal_template = Arc::new(WithdrawalBatchClaimCircuit::<C, D>::build(32));
        let withdrawal_fp = ParthQHashOut(psy_plonky2_circuits::proof_minifier::pm_core::get_circuit_fingerprint_generic(
            &withdrawal_template.circuit_data.verifier_only,
        ));
        let withdrawal_claim_wrap_circuit = Arc::new(WithdrawalClaimWrapCircuit::new(
            &withdrawal_template.circuit_data.common,
            withdrawal_fp,
            withdrawal_template.circuit_data.verifier_only.constants_sigmas_cap.height(),
        ));
        let withdrawal_claim_groth16_wrapper = Arc::new(
            WithdrawalClaimWrapCircuit::new(
                &withdrawal_template.circuit_data.common,
                withdrawal_fp,
                withdrawal_template.circuit_data.verifier_only.constants_sigmas_cap.height(),
            )
            .into_shared_groth16_wrapper(format!("{}/.psy/keystore/withdrawal_claim/", dirs::home_dir().unwrap().display())),
        );
        tracing::info!("Groth16 wrapping circuits pre-built successfully.");

        // Preload Groth16 keystores into the gnark Go runtime so the first proof
        // request doesn't pay the ~15s cold-start penalty (ReadCircuit +
        // ReadProvingKey). Each keystore is ~500MB–800MB on disk; loading
        // lazily on first request causes relayer claim-proof-fetch timeouts.
        tracing::info!("Preloading Groth16 keystores...");
        for (label, keystore_path) in [
            ("deposit_append", &deposit_batch_groth16_wrapper.keystore_path),
            ("withdrawal_claim", &withdrawal_claim_groth16_wrapper.keystore_path),
        ] {
            let keystore_dir = std::path::Path::new(keystore_path);
            if keystore_dir.join("circuit_groth16.bin").exists()
                && keystore_dir.join("pk_groth16.bin").exists()
                && keystore_dir.join("vk_groth16.bin").exists()
            {
                tracing::info!(keystore = label, path = keystore_path, "preloading Groth16 setup");
                gnark_plonky2_verifier_ffi::initialize(keystore_path);
                tracing::info!(keystore = label, "Groth16 setup preloaded");
            } else {
                tracing::warn!(keystore = label, path = keystore_path, "skipping preload — keystore files missing");
            }
        }
        tracing::info!("All Groth16 keystores preloaded.");

        Ok(Self {
            rpc_provider,
            circuit_manager: Arc::new(circuit_manager),
            circuit_info: Arc::new(circuit_info),
            circuits_data,
            keystore_dir: None,
            deployments_network: "localhost".to_string(),
            deposit_batch_wrap_circuit,
            withdrawal_claim_wrap_circuit,
            deposit_batch_groth16_wrapper,
            withdrawal_claim_groth16_wrapper,
            deposit_append_circuit: deposit_template,
            deposit_batch_minifier: deposit_minifier,
            withdrawal_claim_circuit: withdrawal_template,
        })
    }

    async fn register_contract_circuits_inner(&self, contract_id: u64) -> anyhow::Result<()> {
        tracing::debug!("register_contract_circuits contract_id: {}", contract_id);
        let contract_code = self
            .rpc_provider
            .resolve_get_contract_code(&QSRCmdGetContractCodeDefinition { contract_id })
            .await?;
        self.circuit_manager
            .register_contract_circuits(contract_id, &contract_code)
            .await
            .map_err(|err| ErrorObjectOwned::owned(1, "register contract circuits error", Some(err.to_string())))?;
        Ok(())
    }
}

#[async_trait]
impl ProveProxyRpcServer for ProveProxyServerProvider {
    async fn prove_withdrawal_batch_claim_groth16(
        &self,
        input: BridgeWithdrawalBatchWitnessInput,
    ) -> Result<BridgeWithdrawalBatchGroth16Proof, ErrorObjectOwned> {
        tracing::debug!("prove_withdrawal_batch_claim_groth16 count={}", input.withdrawals.len());

        let wrap_circuit = self.withdrawal_claim_wrap_circuit.clone();
        let groth16_wrapper = self.withdrawal_claim_groth16_wrapper.clone();
        let circuit = self.withdrawal_claim_circuit.clone();
        tokio::task::spawn_blocking(move || {
            anyhow::ensure!(
                input.withdrawals.len() <= MAX_WITHDRAWAL_CLAIM_BATCH_SIZE,
                "withdrawal batch too large: got {}, max {}",
                input.withdrawals.len(),
                MAX_WITHDRAWAL_CLAIM_BATCH_SIZE
            );
            anyhow::ensure!(!input.withdrawals.is_empty(), "withdrawal batch must include at least one withdrawal");

            let mut slot_data = vec![0u64; MAX_WITHDRAWAL_CLAIM_BATCH_SIZE * WITHDRAWAL_BATCH_CLAIM_SLOT_WORDS];
            let mut root: Option<ParthQHashOut<F>> = None;
            let mut withdrawals = Vec::with_capacity(input.withdrawals.len());
            for (i, withdrawal) in input.withdrawals.iter().enumerate() {
                anyhow::ensure!(
                    withdrawal.siblings.len() == 32,
                    "withdrawal[{}] expected 32 siblings, got {}",
                    i,
                    withdrawal.siblings.len()
                );
                let parsed_root = parse_hex_qhashout(&withdrawal.withdrawal_root)?;
                if let Some(existing) = root {
                    anyhow::ensure!(existing == parsed_root, "withdrawal[{}] root mismatch within batch", i);
                } else {
                    root = Some(parsed_root);
                }
                let siblings = withdrawal
                    .siblings
                    .iter()
                    .map(|hex| parse_hex_qhashout(hex))
                    .collect::<anyhow::Result<Vec<_>>>()?;
                let slot_offset = i * WITHDRAWAL_BATCH_CLAIM_SLOT_WORDS;
                slot_data[slot_offset] = withdrawal.sender_user_id as u64;
                for (j, word) in withdrawal.recipient.iter().enumerate() {
                    slot_data[slot_offset + 1 + j] = *word as u64;
                }
                for (j, word) in withdrawal.token.iter().enumerate() {
                    slot_data[slot_offset + 9 + j] = *word as u64;
                }
                for (j, word) in withdrawal.amount.iter().enumerate() {
                    slot_data[slot_offset + 17 + j] = *word as u64;
                }
                for (j, word) in withdrawal.nonce.iter().enumerate() {
                    slot_data[slot_offset + 25 + j] = *word as u64;
                }
                slot_data[slot_offset + 33] = withdrawal.destination_chain_index as u64;
                withdrawals.push(WithdrawalBatchClaimSlotInputs::<F> {
                    sender_user_id: withdrawal.sender_user_id,
                    recipient: withdrawal.recipient,
                    token: withdrawal.token,
                    amount: withdrawal.amount,
                    nonce: withdrawal.nonce,
                    destination_chain_index: withdrawal.destination_chain_index,
                    leaf_index: withdrawal.leaf_index,
                    siblings,
                });
            }

            let proof = circuit.generate_proof(&WithdrawalBatchClaimInputs::<F> {
                withdrawal_root: root.expect("non-empty batch ensured above"),
                bridge_user_id: input.bridge_user_id,
                withdrawals,
            })?;
            let groth16 = wrap_circuit.prove_groth16_with_shared_wrapper(&groth16_wrapper, &circuit.circuit_data.verifier_only, &proof)?;
            tracing::warn!(
                withdrawal_claim_gnark_public_inputs = ?groth16.public_inputs,
                "withdrawal claim gnark returned public inputs"
            );

            Ok::<_, anyhow::Error>(BridgeWithdrawalBatchGroth16Proof {
                solidity_proof: g16_proof_to_solidity_words(&groth16),
                public_inputs: {
                    let pis = proof.public_inputs.iter().map(|x| x.to_noncanonical_u64()).collect::<Vec<_>>();
                    anyhow::ensure!(
                        pis.len() == WITHDRAWAL_BATCH_CLAIM_PUBLIC_INPUTS_WORDS,
                        "expected {} withdrawal batch public inputs, got {}",
                        WITHDRAWAL_BATCH_CLAIM_PUBLIC_INPUTS_WORDS,
                        pis.len()
                    );
                    pis
                },
                slot_data,
            })
        })
        .await
        .map_err(|join_err| {
            ErrorObjectOwned::owned(
                1,
                "prove_withdrawal_batch_claim_groth16: task schedule failed",
                Some(format!("Thread pool task execution failed: {}", join_err)),
            )
        })?
        .map_err(|err| ErrorObjectOwned::owned(1, "prove_withdrawal_batch_claim_groth16 proving error", Some(err.to_string())))
    }

    async fn prove_deposit_batch_append_groth16(
        &self,
        input: BridgeDepositBatchWitnessInput,
    ) -> Result<BridgeDepositBatchGroth16Proof, ErrorObjectOwned> {
        tracing::debug!(
            "prove_deposit_batch_append_groth16 from_index={} count={}",
            input.from_index,
            input.deposits.len()
        );

        let wrap_circuit = self.deposit_batch_wrap_circuit.clone();
        let groth16_wrapper = self.deposit_batch_groth16_wrapper.clone();
        let circuit = self.deposit_append_circuit.clone();
        let minifier = self.deposit_batch_minifier.clone();
        tokio::task::spawn_blocking(move || {
            anyhow::ensure!(
                input.old_frontier.len() == 32,
                "expected 32 frontier nodes, got {}",
                input.old_frontier.len()
            );
            anyhow::ensure!(!input.deposits.is_empty(), "deposit batch must include at least one deposit");

            let old_frontier_vec = input
                .old_frontier
                .iter()
                .map(|hex| parse_hex_qhashout(hex))
                .collect::<anyhow::Result<Vec<_>>>()?;
            let old_frontier: [ParthQHashOut<F>; 32] = old_frontier_vec
                .try_into()
                .map_err(|v: Vec<ParthQHashOut<F>>| anyhow::anyhow!("invalid frontier length: {}", v.len()))?;
            let deposits = input
                .deposits
                .into_iter()
                .map(|leaf| DepositBatchLeafData {
                    shield_address: leaf.shield_address,
                    token: leaf.token,
                    l2_token_contract_id: leaf.l2_token_contract_id,
                    amount: leaf.amount,
                    chain_index: leaf.chain_index,
                    note_commitment: leaf.note_commitment,
                })
                .collect::<Vec<_>>();
            let batch_inputs = DepositBatchAppendInputs {
                frontier: old_frontier,
                from_index: input.from_index,
                deposits,
                bridge_user_id: input.bridge_user_id,
            };

            let proof = circuit.generate_proof(&batch_inputs)?;
            let preimage = compute_batch_append_preimage(&batch_inputs);
            let minified_proof = minifier.prove(&proof)?;
            let groth16 = wrap_circuit.prove_groth16_with_shared_wrapper(&groth16_wrapper, minifier.get_verifier_data(), &minified_proof)?;

            Ok::<_, anyhow::Error>(BridgeDepositBatchGroth16Proof {
                solidity_proof: g16_proof_to_solidity_words(&groth16),
                public_inputs: preimage.to_u32_words().into_iter().map(|x| x as u64).collect(),
            })
        })
        .await
        .map_err(|join_err| {
            ErrorObjectOwned::owned(
                1,
                "prove_deposit_batch_append_groth16: task schedule failed",
                Some(format!("Thread pool task execution failed: {}", join_err)),
            )
        })?
        .map_err(|err| ErrorObjectOwned::owned(1, "prove_deposit_batch_append_groth16 proving error", Some(err.to_string())))
    }


    async fn prove_ups_start(&self, input: UPSStartStepInput<F>) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned> {
        tracing::debug!("prove_ups_start input");

        let circuit_manager = self.circuit_manager.clone();
        let input = input.clone();

        let proof_join_handle = tokio::task::spawn_blocking(move || circuit_manager.ups_start.prove_base(&input));

        let proof_result = proof_join_handle.await.map_err(|join_err| {
            ErrorObjectOwned::owned(
                1,
                "prove_ups_start: task schedule failed",
                Some(format!("Thread pool task execution failed: {}", join_err)),
            )
        })?;

        proof_result.map_err(|prove_err| {
            ErrorObjectOwned::owned(
                1,
                "prove_ups_start proving error",
                Some(format!("ZK proof generation failed: {}", prove_err)),
            )
        })
    }

    async fn prove_ups_start_register_user(
        &self,
        input: UPSStartStepRegisterUserInput<F>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned> {
        tracing::debug!("prove_ups_start_register_user input");

        let circuit_manager = self.circuit_manager.clone();
        let input = input.clone();

        let proof_join_handle = tokio::task::spawn_blocking(move || circuit_manager.ups_start_register_user.prove_base(&input));

        let proof_result = proof_join_handle.await.map_err(|join_err| {
            ErrorObjectOwned::owned(
                1,
                "prove_ups_start_register_user: task schedule failed",
                Some(format!("Thread pool task execution failed: {}", join_err)),
            )
        })?;

        proof_result.map_err(|prove_err| {
            ErrorObjectOwned::owned(
                1,
                "prove_ups_start_register_user proving error",
                Some(format!("ZK proof generation failed: {}", prove_err)),
            )
        })
    }

    async fn register_contract_circuits(&self, contract_id: u64, _contract_code: ContractCodeDefinition) -> Result<(), ErrorObjectOwned> {
        self.register_contract_circuits_inner(contract_id)
            .await
            .map_err(|err| ErrorObjectOwned::owned(1, "register contract circuits error", Some(err.to_string())))
    }

    async fn resolve_contract_function_by_method_name(
        &self,
        contract_id: u64,
        contract_code: ContractCodeDefinition,
        method_name: String,
    ) -> Result<(u64, DPNFunctionCircuitDefinition), ErrorObjectOwned> {
        self.circuit_manager
            .resolve_contract_function_by_method_name(contract_id, &contract_code, method_name)
            .await
            .map_err(|err| ErrorObjectOwned::owned(1, "resolve contract function by method name error", Some(err.to_string())))
    }

    async fn resolve_contract_function_by_method_id(
        &self,
        contract_id: u64,
        contract_code: ContractCodeDefinition,
        method_id: u32,
    ) -> Result<(u64, DPNFunctionCircuitDefinition), ErrorObjectOwned> {
        self.circuit_manager
            .resolve_contract_function_by_method_id(contract_id, &contract_code, method_id)
            .await
            .map_err(|err| ErrorObjectOwned::owned(1, "resolve contract function by method id error", Some(err.to_string())))
    }

    async fn get_circuits_data(&self) -> Result<String, ErrorObjectOwned> {
        tracing::debug!("get_circuits_data");

        Ok(serde_json::to_string(&self.circuits_data).unwrap())
    }

    async fn get_fn_id(&self, contract_id: u64, method_name: String) -> Result<u64, ErrorObjectOwned> {
        let (fn_id, _) = self.get_fn_id_and_circuit_def(contract_id, method_name.clone()).await?;
        Ok(fn_id)
    }

    async fn get_fn_id_and_circuit_def(
        &self,
        contract_id: u64,
        method_name: String,
    ) -> Result<(u64, DPNFunctionCircuitDefinition), ErrorObjectOwned> {
        tracing::debug!("get_fn_id contract_id: {}, method_name: {}", contract_id, method_name);
        let contract_code = self
            .rpc_provider
            .resolve_get_contract_code(&QSRCmdGetContractCodeDefinition { contract_id })
            .await
            .map_err(|err| ErrorObjectOwned::owned(1, "get contract code error", Some(err.to_string())))?;
        self.circuit_manager
            .resolve_contract_function_by_method_name(contract_id, &contract_code, method_name)
            .await
            .map_err(|err| ErrorObjectOwned::owned(1, "get_fn_id error", Some(err.to_string())))
    }

    async fn get_contract_method_common_data(&self, contract_id: u64, fn_id: u32) -> Result<QCommonCircuitData<F>, ErrorObjectOwned> {
        tracing::debug!("get_contract_method_common_data contract_id: {}, fn_id: {}", contract_id, fn_id);
        if self.circuit_manager.contract_circuits.get(&(contract_id, fn_id)).is_none() {
            tracing::warn!("contract {} is not registered, can not get fn id", contract_id);
            tracing::warn!("register contract {} first", contract_id);
            self.register_contract_circuits_inner(contract_id)
                .await
                .map_err(|err| ErrorObjectOwned::owned(1, "register contract circuits error", Some(err.to_string())))?;
        }

        if let Some(circuit) = self.circuit_manager.contract_circuits.get(&(contract_id, fn_id)) {
            tracing::info!(
                "get contract {} method {} common data, fingerprint: {}",
                contract_id,
                fn_id,
                circuit.get_fingerprint(),
            );
            return Ok(QCommonCircuitData {
                fingerprint: circuit.get_fingerprint(),
                verifier_config: circuit.get_verifier_config_ref().clone().into(),
            });
        }
        Err(ErrorObjectOwned::owned(
            1,
            format!("contract {} method {} is not found", contract_id, fn_id),
            Some(format!("fn_id: {}", fn_id)),
        ))
    }

    async fn prove_contract_call(
        &self,
        contract_id: u64,
        fn_id: u32,
        input: DapenContractFunctionCircuitInput<F>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned> {
        tracing::debug!("prove_contract_call contract_id: {}, fn_id: {}", contract_id, fn_id);
        if self.circuit_manager.contract_circuits.get(&(contract_id, fn_id)).is_none() {
            tracing::warn!("contract {} is not registered, can not get fn id", contract_id);
            tracing::warn!("register contract {} first", contract_id);
            self.register_contract_circuits_inner(contract_id)
                .await
                .map_err(|err| ErrorObjectOwned::owned(1, "register contract circuits error", Some(err.to_string())))?;
        }
        if let Some(fn_circuit) = self.circuit_manager.contract_circuits.get(&(contract_id, fn_id)) {
            let input = input.clone();
            let fn_circuit = fn_circuit.clone();

            tokio::task::spawn_blocking(move || {
                fn_circuit
                    .prove_base(&input)
                    .map_err(|err| ErrorObjectOwned::owned(1, "fn_circuit proving error", Some(err.to_string())))
            })
            .await
            .map_err(|join_err| {
                ErrorObjectOwned::owned(
                    1,
                    "prove_contract_call: task schedule failed",
                    Some(format!("Thread pool task execution failed: {}", join_err)),
                )
            })?
        } else {
            Err(ErrorObjectOwned::owned(
                1,
                format!("contract {} method {} is not found", contract_id, fn_id),
                Some(format!("fn_id: {}", fn_id)),
            ))
        }
    }

    async fn prove_ups_cfc_standard_tx(
        &self,
        input: UPSCFCStandardTransactionCircuitInput<F>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned> {
        tracing::debug!("prove_ups_cfc_standard_tx");

        let circuit_manager = self.circuit_manager.clone();
        let input = input.clone();

        let proof_join_handle = tokio::task::spawn_blocking(move || circuit_manager.ups_cfc_standard_tx.prove_base(&input));

        let proof_result = proof_join_handle.await.map_err(|join_err| {
            ErrorObjectOwned::owned(
                1,
                "ups_cfc_standard_tx: task schedule failed",
                Some(format!("Thread pool task execution failed: {}", join_err)),
            )
        })?;

        proof_result.map_err(|prove_err| {
            ErrorObjectOwned::owned(
                1,
                "ups_cfc_standard_tx proving error",
                Some(format!("ZK proof generation failed: {}", prove_err)),
            )
        })
    }

    async fn prove_ups_cfc_deferred_tx(
        &self,
        input: UPSCFCDeferredTransactionCircuitInput<F>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned> {
        tracing::debug!("prove_ups_cfc_deferred_tx");

        let circuit_manager = self.circuit_manager.clone();
        let input = input.clone();

        let proof_join_handle = tokio::task::spawn_blocking(move || circuit_manager.ups_cfc_deferred_tx.prove_base(&input));

        let proof_result = proof_join_handle.await.map_err(|join_err| {
            ErrorObjectOwned::owned(
                1,
                "prove_ups_cfc_deferred_tx: task schedule failed",
                Some(format!("Thread pool task execution failed: {}", join_err)),
            )
        })?;

        proof_result.map_err(|prove_err| {
            ErrorObjectOwned::owned(
                1,
                "prove_ups_cfc_deferred_tx proving error",
                Some(format!("ZK proof generation failed: {}", prove_err)),
            )
        })
    }

    async fn prove_zk_sign_minifier(&self, inner_proof: String) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned> {
        tracing::debug!("prove_zk_sign_minifier");

        let inner_proof = serde_json::from_str::<ProofWithPublicInputs<F, C, D>>(&inner_proof).map_err(|err| {
            ErrorObjectOwned::owned(
                1,
                "prove_zk_sign_minifier: inner_proof deserialize error",
                Some(format!("ZK proof deserialize failed: {}", err)),
            )
        })?;

        let circuit_manager = self.circuit_manager.clone();
        let proof_join_handle = tokio::task::spawn_blocking(move || {
            tokio::runtime::Handle::current().block_on(async move { circuit_manager.prove_zk_sign_minifier(inner_proof).await })
        });

        let proof_result = proof_join_handle.await.map_err(|join_err| {
            ErrorObjectOwned::owned(
                1,
                "prove_zk_sign_minifier: task schedule failed",
                Some(format!("Thread pool task execution failed: {}", join_err)),
            )
        })?;

        proof_result.map_err(|prove_err| {
            ErrorObjectOwned::owned(
                1,
                "prove_zk_sign_minifier proving error",
                Some(format!("ZK proof generation failed: {}", prove_err)),
            )
        })
    }

    async fn prove_private_note_inclusion_minifier(&self, base_proof: String) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned> {
        tracing::debug!("prove_private_note_inclusion_minifier");
        let circuit_manager = self.circuit_manager.clone();
        let base_proof = serde_json::from_str::<ProofWithPublicInputs<F, C, D>>(&base_proof).map_err(|err| {
            ErrorObjectOwned::owned(
                1,
                "prove_private_note_inclusion_minifier: base_proof deserialize error",
                Some(err.to_string()),
            )
        })?;

        let proof_join_handle =
            tokio::task::spawn_blocking(move || circuit_manager.private_note_inclusion_minifier_circuit().prove_minifier(base_proof));
        let proof_result = proof_join_handle.await.map_err(|join_err| {
            ErrorObjectOwned::owned(
                1,
                "prove_private_note_inclusion_minifier: task schedule failed",
                Some(join_err.to_string()),
            )
        })?;
        proof_result
            .map_err(|prove_err| ErrorObjectOwned::owned(1, "prove_private_note_inclusion_minifier proving error", Some(prove_err.to_string())))
    }

    async fn prove_shield_deposit_claim_minifier(&self, base_proof: String) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned> {
        tracing::debug!("prove_shield_deposit_claim_minifier");
        let circuit_manager = self.circuit_manager.clone();
        let base_proof = serde_json::from_str::<ProofWithPublicInputs<F, C, D>>(&base_proof).map_err(|err| {
            ErrorObjectOwned::owned(
                1,
                "prove_shield_deposit_claim_minifier: base_proof deserialize error",
                Some(err.to_string()),
            )
        })?;

        let proof_join_handle =
            tokio::task::spawn_blocking(move || circuit_manager.shield_deposit_claim_minifier_circuit().prove_minifier(base_proof));
        let proof_result = proof_join_handle.await.map_err(|join_err| {
            ErrorObjectOwned::owned(1, "prove_shield_deposit_claim_minifier: task schedule failed", Some(join_err.to_string()))
        })?;
        proof_result.map_err(|prove_err| ErrorObjectOwned::owned(1, "prove_shield_deposit_claim_minifier proving error", Some(prove_err.to_string())))
    }

    async fn prove_secp_sign(&self, signature: PsyCompressedSecp256K1Signature) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned> {
        tracing::debug!("prove_secp_sign");

        let circuit_manager = self.circuit_manager.clone();

        let proof_join_handle = tokio::task::spawn_blocking(move || circuit_manager.secp_circuit().prove(&signature));

        let proof_result = proof_join_handle.await.map_err(|join_err| {
            ErrorObjectOwned::owned(
                1,
                "prove_secp_sign: task schedule failed",
                Some(format!("Thread pool task execution failed: {}", join_err)),
            )
        })?;

        proof_result.map_err(|prove_err| {
            ErrorObjectOwned::owned(
                1,
                "prove_secp_sign proving error",
                Some(format!("ZK proof generation failed: {}", prove_err)),
            )
        })
    }

    async fn prove_eth_personal_secp_sign(
        &self,
        signature: PsyCompressedSecp256K1Signature,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned> {
        tracing::info!("prove_eth_personal_secp_sign");

        let circuit_manager = self.circuit_manager.clone();

        let proof_join_handle = tokio::task::spawn_blocking(move || circuit_manager.eth_personal_secp_circuit().prove(&signature));

        let proof_result = proof_join_handle.await.map_err(|join_err| {
            ErrorObjectOwned::owned(
                1,
                "prove_eth_personal_secp_sign: task schedule failed",
                Some(format!("Thread pool task execution failed: {}", join_err)),
            )
        })?;

        proof_result.map_err(|prove_err| {
            ErrorObjectOwned::owned(
                1,
                "prove_eth_personal_secp_sign proving error",
                Some(format!("ZK proof generation failed: {}", prove_err)),
            )
        })
    }

    async fn register_dpn_software_defined_circuit(
        &self,
        _request: QRegisterDPNSoftwareDefinedCircuitRPCRequest,
    ) -> Result<QHashOut<F>, ErrorObjectOwned> {
        todo!("register_dpn_software_defined_circuit");
    }

    async fn register_plonky2_software_defined_circuit(
        &self,
        _request: QRegisterPlonky2SoftwareDefinedCircuitRPCRequest,
    ) -> Result<QHashOut<F>, ErrorObjectOwned> {
        todo!("register_plonky2_software_defined_circuit");
        // let input = SoftwareDefinedSignatureInput::Psy(input);
        // let sdc = SoftwareDefinedSignatureCircuit::new(&input).await;

        // let fingerprint = sdc.get_fingerprint();
        // tracing::info!("register software defined circuit: {}",
        // fingerprint.to_string()); if let Some(_) =
        // self.software_defined_circuits.insert(fingerprint, sdc) {
        //     tracing::warn!("software defined circuit `{}` is already
        // registered", fingerprint.to_string()); };
        // Ok(fingerprint)
    }

    async fn prove_dpn_software_defined_sign(
        &self,
        fingerprint: QHashOut<F>,
        private_key: QHashOut<F>,
        input: DPNSoftwareDefinedSignatureInput,
        sig_hash: QHashOut<F>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned> {
        tracing::debug!("prove_dpn_software_defined_sign");
        self.circuit_manager
            .prove_dpn_software_defined_sign(fingerprint, private_key, input, sig_hash)
            .await
            .map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))
    }

    async fn prove_plonky2_software_defined_sign(
        &self,
        fingerprint: QHashOut<F>,
        private_key: QHashOut<F>,
        input: Plonky2SoftwareDefinedSignatureInput,
        sig_hash: QHashOut<F>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned> {
        tracing::debug!("prove_plonky2_software_defined_sign");
        self.circuit_manager
            .prove_plonky2_software_defined_sign(fingerprint, private_key, input, sig_hash)
            .await
            .map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))
    }

    async fn prove_ups_end_cap(
        &self,
        end_cap_from_proof_tree_input: UPSEndCapFromProofTreeGadgetInput<F>,
        circuit_type: QStandardBinaryTreeCircuitType,
        fingerprint: QHashOut<F>,
        agg_header: QRecursionAggStandardHeader<F>,
        proof: ProofWithPublicInputs<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned> {
        tracing::debug!("prove_ups_end_cap");

        let circuit_manager = self.circuit_manager.clone();
        let circuit_info = self.circuit_info.clone();

        let proof_join_handle = tokio::task::spawn_blocking(move || {
            let agg_whitelist_merkle_proof = circuit_manager
                .proof_tree_agg_circuits
                .circuit_inclusion_proofs
                .get_inclusion_proof_for_type(circuit_type);
            let agg_root_verifier_data = circuit_info
                .get_circuit_info_by_fingerprint(fingerprint)
                .map_err(|err| ErrorObjectOwned::owned(1, "get_circuit_info_by_fingerprint error", Some(err.to_string())))?
                .verifier_data
                .to_verifier_data::<C, D>();

            circuit_manager.ups_end_cap.prove_base(
                &end_cap_from_proof_tree_input,
                &agg_whitelist_merkle_proof,
                &agg_header,
                &proof,
                &agg_root_verifier_data,
            )
        });

        let proof_result = proof_join_handle.await.map_err(|join_err| {
            ErrorObjectOwned::owned(
                1,
                "ups_end_cap: task schedule failed",
                Some(format!("Thread pool task execution failed: {}", join_err)),
            )
        })?;

        proof_result
            .map_err(|prove_err| ErrorObjectOwned::owned(1, "ups_end_cap proving error", Some(format!("ZK proof generation failed: {}", prove_err))))
    }

    async fn prove_single_leaf_circuit(
        &self,
        agg_circuit_whitelist_root: QHashOut<F>,
        single_insert_leaf_proof: DeltaMerkleProofCore<QHashOut<F>>,
        single_proof: ProofWithPublicInputs<F, C, D>,
        single_verifier_data: AltVerifierOnlyCircuitData<F>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned> {
        tracing::debug!("prove_single_leaf_circuit");

        let circuit_manager = self.circuit_manager.clone();

        let proof_join_handle = tokio::task::spawn_blocking(move || {
            circuit_manager.proof_tree_agg_circuits.circuit_set.single_leaf_circuit.prove_base(
                agg_circuit_whitelist_root,
                &single_insert_leaf_proof,
                &single_proof,
                &single_verifier_data.to_verifier_data(),
            )
        });

        let proof_result = proof_join_handle.await.map_err(|join_err| {
            ErrorObjectOwned::owned(
                1,
                "single_leaf_circuit: task schedule failed",
                Some(format!("Thread pool task execution failed: {}", join_err)),
            )
        })?;

        proof_result.map_err(|prove_err| {
            ErrorObjectOwned::owned(
                1,
                "single_leaf_circuit proving error",
                Some(format!("ZK proof generation failed: {}", prove_err)),
            )
        })
    }

    async fn prove_two_leaf_circuit(
        &self,
        agg_circuit_whitelist_root: QHashOut<F>,
        left_insert_leaf_proof: DeltaMerkleProofCore<QHashOut<F>>,
        left_proof: ProofWithPublicInputs<F, C, D>,
        left_verifier_data: AltVerifierOnlyCircuitData<F>,
        right_insert_leaf_proof: DeltaMerkleProofCore<QHashOut<F>>,
        right_proof: ProofWithPublicInputs<F, C, D>,
        right_verifier_data: AltVerifierOnlyCircuitData<F>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned> {
        tracing::debug!("prove_two_leaf_circuit");

        let circuit_manager = self.circuit_manager.clone();

        let proof_join_handle = tokio::task::spawn_blocking(move || {
            circuit_manager.proof_tree_agg_circuits.circuit_set.two_leaf_circuit.prove_base(
                agg_circuit_whitelist_root,
                &left_insert_leaf_proof,
                &left_proof,
                &left_verifier_data.to_verifier_data(),
                &right_insert_leaf_proof,
                &right_proof,
                &right_verifier_data.to_verifier_data(),
            )
        });

        let proof_result = proof_join_handle.await.map_err(|join_err| {
            ErrorObjectOwned::owned(
                1,
                "two_leaf_circuit: task schedule failed",
                Some(format!("Thread pool task execution failed: {}", join_err)),
            )
        })?;

        proof_result.map_err(|prove_err| {
            ErrorObjectOwned::owned(
                1,
                "two_leaf_circuit proving error",
                Some(format!("ZK proof generation failed: {}", prove_err)),
            )
        })
    }

    async fn prove_two_agg_circuit(
        &self,
        left_agg_whitelist_merkle_proof: MerkleProofCore<QHashOut<F>>,
        left_agg_proof_header: QRecursionAggStandardHeader<F>,
        left_proof: ProofWithPublicInputs<F, C, D>,
        left_verifier_data: AltVerifierOnlyCircuitData<F>,
        right_agg_whitelist_merkle_proof: MerkleProofCore<QHashOut<F>>,
        right_agg_proof_header: QRecursionAggStandardHeader<F>,
        right_proof: ProofWithPublicInputs<F, C, D>,
        right_verifier_data: AltVerifierOnlyCircuitData<F>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned> {
        tracing::debug!("prove_two_agg_circuit");

        let circuit_manager = self.circuit_manager.clone();

        let proof_join_handle = tokio::task::spawn_blocking(move || {
            circuit_manager.proof_tree_agg_circuits.circuit_set.two_agg_circuit.prove_base(
                &left_agg_whitelist_merkle_proof,
                &left_agg_proof_header,
                &left_proof,
                &left_verifier_data.to_verifier_data(),
                &right_agg_whitelist_merkle_proof,
                &right_agg_proof_header,
                &right_proof,
                &right_verifier_data.to_verifier_data(),
            )
        });

        let proof_result = proof_join_handle.await.map_err(|join_err| {
            ErrorObjectOwned::owned(
                1,
                "two_agg_circuit: task schedule failed",
                Some(format!("Thread pool task execution failed: {}", join_err)),
            )
        })?;

        proof_result.map_err(|prove_err| {
            ErrorObjectOwned::owned(
                1,
                "two_agg_circuit proving error",
                Some(format!("ZK proof generation failed: {}", prove_err)),
            )
        })
    }

    async fn prove_left_leaf_right_agg_circuit(
        &self,
        left_insert_leaf_proof: DeltaMerkleProofCore<QHashOut<F>>,
        left_proof: ProofWithPublicInputs<F, C, D>,
        left_verifier_data: AltVerifierOnlyCircuitData<F>,
        right_agg_whitelist_merkle_proof: MerkleProofCore<QHashOut<F>>,
        right_agg_proof_header: QRecursionAggStandardHeader<F>,
        right_proof: ProofWithPublicInputs<F, C, D>,
        right_verifier_data: AltVerifierOnlyCircuitData<F>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned> {
        tracing::debug!("prove_left_leaf_right_agg_circuit");

        let circuit_manager = self.circuit_manager.clone();

        let proof_join_handle = tokio::task::spawn_blocking(move || {
            circuit_manager
                .proof_tree_agg_circuits
                .circuit_set
                .left_leaf_right_agg_circuit
                .prove_base(
                    &left_insert_leaf_proof,
                    &left_proof,
                    &left_verifier_data.to_verifier_data(),
                    &right_agg_whitelist_merkle_proof,
                    &right_agg_proof_header,
                    &right_proof,
                    &right_verifier_data.to_verifier_data(),
                )
        });

        let proof_result = proof_join_handle.await.map_err(|join_err| {
            ErrorObjectOwned::owned(
                1,
                "left_leaf_right_agg_circuit: task schedule failed",
                Some(format!("Thread pool task execution failed: {}", join_err)),
            )
        })?;

        proof_result.map_err(|prove_err| {
            ErrorObjectOwned::owned(
                1,
                "left_leaf_right_agg_circuit proving error",
                Some(format!("ZK proof generation failed: {}", prove_err)),
            )
        })
    }

    async fn prove_left_agg_right_leaf_circuit(
        &self,
        left_agg_whitelist_merkle_proof: MerkleProofCore<QHashOut<F>>,
        left_agg_proof_header: QRecursionAggStandardHeader<F>,
        left_proof: ProofWithPublicInputs<F, C, D>,
        left_verifier_data: AltVerifierOnlyCircuitData<F>,
        right_insert_leaf_proof: DeltaMerkleProofCore<QHashOut<F>>,
        right_proof: ProofWithPublicInputs<F, C, D>,
        right_verifier_data: AltVerifierOnlyCircuitData<F>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ErrorObjectOwned> {
        tracing::debug!("prove_left_agg_right_leaf_circuit");

        let circuit_manager = self.circuit_manager.clone();

        let proof_join_handle = tokio::task::spawn_blocking(move || {
            circuit_manager
                .proof_tree_agg_circuits
                .circuit_set
                .left_agg_right_leaf_circuit
                .prove_base(
                    &left_agg_whitelist_merkle_proof,
                    &left_agg_proof_header,
                    &left_proof,
                    &left_verifier_data.to_verifier_data(),
                    &right_insert_leaf_proof,
                    &right_proof,
                    &right_verifier_data.to_verifier_data(),
                )
        });

        let proof_result = proof_join_handle.await.map_err(|join_err| {
            ErrorObjectOwned::owned(
                1,
                "left_agg_right_leaf_circuit: task schedule failed",
                Some(format!("Thread pool task execution failed: {}", join_err)),
            )
        })?;

        proof_result.map_err(|prove_err| {
            ErrorObjectOwned::owned(
                1,
                "left_agg_right_leaf_circuit proving error",
                Some(format!("ZK proof generation failed: {}", prove_err)),
            )
        })
    }
}

