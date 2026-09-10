use std::sync::Arc;

use jsonrpsee::{
    core::async_trait,
    proc_macros::rpc,
    types::{ErrorObject, ErrorObjectOwned},
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
use psy_provider::{
    provider::{LocalCommonCircuitsData, QCommonCircuitData, RpcProvider},
    request::{DPNSoftwareDefinedSignatureInput, QRegisterDPNSoftwareDefinedCircuitRPCRequest, QRegisterPlonky2SoftwareDefinedCircuitRPCRequest},
};
use psy_ups_circuit::circuit_manager::core::PsyUPSStepCircuitManager;
use psy_vm::{
    ups::{circuit_manager::UPSCircuitManager, signature::Plonky2SoftwareDefinedSignatureInput},
    vm::cfc_input::DapenContractFunctionCircuitInput,
};
use plonky2::plonk::proof::ProofWithPublicInputs;

use super::{C, D, F};
use crate::local::native::DPNFunctionCircuitDefinition;

#[rpc(server, client, namespace = "psy")]
pub trait ProveProxyUserRpc {
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

}

pub struct UserProveProvider {
    pub rpc_provider: RpcProvider,
    pub circuit_manager: Arc<PsyUPSStepCircuitManager<C, D>>,
    pub circuit_info: Arc<SessionCircuitInfoStore<F>>,
    pub circuits_data: LocalCommonCircuitsData<F>,
}

impl UserProveProvider {
    pub async fn new_with_config(rpc_config: psy_config::NetworkConfigGoldilocks, network_magic: u64) -> anyhow::Result<Self> {
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


        Ok(Self {
            rpc_provider,
            circuit_manager: Arc::new(circuit_manager),
            circuit_info: Arc::new(circuit_info),
            circuits_data,
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
impl ProveProxyUserRpcServer for UserProveProvider {
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
