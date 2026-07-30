use anyhow;
use maybe_async::maybe_async;
use plonky2::{
    hash::hash_types::HashOut,
    plonk::{
        circuit_data::VerifierOnlyCircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::{
    qdata::contract::ContractCodeDefinition,
    qstore::controllers::session_info::SessionCircuitInfoStore,
    ups::{
        start_step::UPSStartStepInput,
        start_step_register_user::UPSStartStepRegisterUserInput,
        ups_cfc_standard_step::{UPSCFCDeferredTransactionCircuitInput, UPSCFCStandardTransactionCircuitInput},
        ups_end_cap::UPSEndCapFromProofTreeGadgetInput,
    },
};
use psy_crypto::{
    common::witnesses::qrecursion::{
        header::QRecursionAggStandardHeader,
        proof_data::{AggProofRecord, QStandardBinaryTreeCircuitType, SimpleQTreeRecursionManagerInclusionProofs},
    },
    hash::{
        merkle::core::{DeltaMerkleProofCore, MerkleProofCore},
        traits::hasher::MerkleZeroHasherWithMarkedLeaf,
    },
    signature::secp256k1::core::PsyCompressedSecp256K1Signature,
};

use crate::{
    dpn::vm::def::DPNFunctionCircuitDefinition,
    ups::signature::{DPNSoftwareDefinedSignatureInput, Plonky2SoftwareDefinedSignatureInput},
    vm::cfc_input::DapenContractFunctionCircuitInput,
};

#[cfg_attr(not(target_arch = "wasm32"), maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async(?Send))]
pub trait UPSCircuitManager<C: GenericConfig<D>, const D: usize>: Send + Sync + PortableQTreeRecursion<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    async fn register_info(&self, info_store: &mut SessionCircuitInfoStore<C::F>);
    async fn prove_ups_start(&self, input: &UPSStartStepInput<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
    async fn prove_ups_start_register_user(&self, input: &UPSStartStepRegisterUserInput<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;

    async fn register_contract_circuits(&self, contract_id: u64, contract_code: &ContractCodeDefinition) -> anyhow::Result<()>;

    async fn get_fn_id(&self, contract_id: u64, method_name: String) -> anyhow::Result<u64>;

    // Combine register_contract_circuits and get_fn_id
    async fn resolve_contract_function_by_method_name(
        &self,
        contract_id: u64,
        contract_code: &ContractCodeDefinition,
        method_name: String,
    ) -> anyhow::Result<(u64, DPNFunctionCircuitDefinition)>;

    async fn resolve_contract_function_by_method_id(
        &self,
        contract_id: u64,
        contract_code: &ContractCodeDefinition,
        method_id: u32,
    ) -> anyhow::Result<(u64, DPNFunctionCircuitDefinition)>;

    async fn get_contract_method_common_data(&self, contract_id: u64, fn_id: u32) -> anyhow::Result<(QHashOut<C::F>, VerifierOnlyCircuitData<C, D>)>;

    async fn prove_contract_call(
        &self,
        contract_id: u64,
        fn_id: u32,
        input: &DapenContractFunctionCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;

    async fn prove_ups_cfc_standard_tx(
        &self,
        input: &UPSCFCStandardTransactionCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;

    async fn prove_ups_cfc_deferred_tx(
        &self,
        input: &UPSCFCDeferredTransactionCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;

    async fn prove_zk_sign_minifier(&self, inner_proof: ProofWithPublicInputs<C::F, C, D>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;

    async fn zk_signature_minifier_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>>;

    async fn zk_signature_minifier_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>>;

    async fn prove_private_note_inclusion_minifier(
        &self,
        base_proof: ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;

    async fn private_note_inclusion_minifier_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>>;

    async fn private_note_inclusion_minifier_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>>;

    async fn prove_shield_deposit_claim_minifier(
        &self,
        base_proof: ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;

    async fn shield_deposit_claim_minifier_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>>;

    async fn shield_deposit_claim_minifier_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>>;

    async fn prove_secp_sign(&self, signature: PsyCompressedSecp256K1Signature) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;

    async fn prove_eth_personal_secp_sign(&self, signature: PsyCompressedSecp256K1Signature) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;

    async fn register_dpn_software_defined_circuit(
        &self,
        fn_def: DPNFunctionCircuitDefinition,
        contract_id: u64,
        contract_state_tree_height: u8,
        session_proof_tree_height: u8,
        force_four_align: bool,
    ) -> anyhow::Result<QHashOut<C::F>>;

    async fn register_plonky2_software_defined_circuit(&self, contract_state_tree_height: u8, input_len: usize) -> anyhow::Result<QHashOut<C::F>>;

    async fn prove_dpn_software_defined_sign(
        &self,
        fingerprint: QHashOut<C::F>,
        private_key: QHashOut<C::F>,
        input: DPNSoftwareDefinedSignatureInput,
        sig_hash: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;

    async fn prove_plonky2_software_defined_sign(
        &self,
        fingerprint: QHashOut<C::F>,
        private_key: QHashOut<C::F>,
        input: Plonky2SoftwareDefinedSignatureInput,
        sig_hash: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;

    async fn prove_ups_end_cap(
        &self,
        circuit_info: &SessionCircuitInfoStore<C::F>,
        end_cap_from_proof_tree_input: &UPSEndCapFromProofTreeGadgetInput<C::F>,
        agg_proof_record: &AggProofRecord<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;

    async fn ups_start_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>>;

    async fn ups_start_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>>;

    async fn ups_start_register_user_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>>;

    async fn ups_start_register_user_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>>;

    async fn ups_cfc_standard_tx_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>>;

    async fn ups_cfc_standard_tx_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>>;

    async fn ups_cfc_deferred_tx_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>>;

    async fn ups_cfc_deferred_tx_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>>;

    async fn ups_end_cap_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>>;

    async fn ups_end_cap_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>>;

    async fn ups_circuit_whitelist_root(&self) -> anyhow::Result<QHashOut<C::F>>;

    async fn secp_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>>;

    async fn secp_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>>;

    async fn eth_personal_secp_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>>;

    async fn eth_personal_secp_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>>;
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async(?Send))]
impl<C: GenericConfig<D>, const D: usize, T> UPSCircuitManager<C, D> for &T
where
    T: UPSCircuitManager<C, D> + Sync,
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    async fn register_info(&self, info_store: &mut SessionCircuitInfoStore<C::F>) {
        (**self).register_info(info_store).await
    }

    async fn prove_ups_start(&self, input: &UPSStartStepInput<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self).prove_ups_start(input).await
    }
    async fn prove_ups_start_register_user(&self, input: &UPSStartStepRegisterUserInput<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self).prove_ups_start_register_user(input).await
    }

    async fn register_contract_circuits(&self, contract_id: u64, contract_code: &ContractCodeDefinition) -> anyhow::Result<()> {
        (**self).register_contract_circuits(contract_id, contract_code).await
    }

    async fn get_fn_id(&self, contract_id: u64, method_name: String) -> anyhow::Result<u64> {
        (**self).get_fn_id(contract_id, method_name).await
    }

    async fn resolve_contract_function_by_method_name(
        &self,
        contract_id: u64,
        contract_code: &ContractCodeDefinition,
        method_name: String,
    ) -> anyhow::Result<(u64, DPNFunctionCircuitDefinition)> {
        (**self)
            .resolve_contract_function_by_method_name(contract_id, contract_code, method_name)
            .await
    }

    async fn resolve_contract_function_by_method_id(
        &self,
        contract_id: u64,
        contract_code: &ContractCodeDefinition,
        method_id: u32,
    ) -> anyhow::Result<(u64, DPNFunctionCircuitDefinition)> {
        (**self)
            .resolve_contract_function_by_method_id(contract_id, contract_code, method_id)
            .await
    }

    async fn get_contract_method_common_data(&self, contract_id: u64, fn_id: u32) -> anyhow::Result<(QHashOut<C::F>, VerifierOnlyCircuitData<C, D>)> {
        (**self).get_contract_method_common_data(contract_id, fn_id).await
    }

    async fn prove_contract_call(
        &self,
        contract_id: u64,
        fn_id: u32,
        input: &DapenContractFunctionCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self).prove_contract_call(contract_id, fn_id, input).await
    }

    async fn prove_ups_cfc_standard_tx(
        &self,
        input: &UPSCFCStandardTransactionCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self).prove_ups_cfc_standard_tx(input).await
    }

    async fn prove_ups_cfc_deferred_tx(
        &self,
        input: &UPSCFCDeferredTransactionCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self).prove_ups_cfc_deferred_tx(input).await
    }

    async fn prove_zk_sign_minifier(&self, inner_proof: ProofWithPublicInputs<C::F, C, D>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self).prove_zk_sign_minifier(inner_proof).await
    }

    async fn zk_signature_minifier_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        (**self).zk_signature_minifier_fingerprint().await
    }

    async fn zk_signature_minifier_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        (**self).zk_signature_minifier_verifier_config().await
    }

    async fn prove_private_note_inclusion_minifier(
        &self,
        base_proof: ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self).prove_private_note_inclusion_minifier(base_proof).await
    }

    async fn private_note_inclusion_minifier_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        (**self).private_note_inclusion_minifier_fingerprint().await
    }

    async fn private_note_inclusion_minifier_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        (**self).private_note_inclusion_minifier_verifier_config().await
    }

    async fn prove_shield_deposit_claim_minifier(
        &self,
        base_proof: ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self).prove_shield_deposit_claim_minifier(base_proof).await
    }

    async fn shield_deposit_claim_minifier_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        (**self).shield_deposit_claim_minifier_fingerprint().await
    }

    async fn shield_deposit_claim_minifier_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        (**self).shield_deposit_claim_minifier_verifier_config().await
    }

    async fn prove_secp_sign(&self, signature: PsyCompressedSecp256K1Signature) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self).prove_secp_sign(signature).await
    }

    async fn prove_eth_personal_secp_sign(&self, signature: PsyCompressedSecp256K1Signature) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self).prove_eth_personal_secp_sign(signature).await
    }

    async fn register_dpn_software_defined_circuit(
        &self,
        fn_def: DPNFunctionCircuitDefinition,
        contract_id: u64,
        contract_state_tree_height: u8,
        session_proof_tree_height: u8,
        force_four_align: bool,
    ) -> anyhow::Result<QHashOut<C::F>> {
        (**self)
            .register_dpn_software_defined_circuit(
                fn_def,
                contract_id,
                contract_state_tree_height,
                session_proof_tree_height,
                force_four_align,
            )
            .await
    }

    async fn register_plonky2_software_defined_circuit(&self, contract_state_tree_height: u8, input_len: usize) -> anyhow::Result<QHashOut<C::F>> {
        (**self)
            .register_plonky2_software_defined_circuit(contract_state_tree_height, input_len)
            .await
    }

    async fn prove_dpn_software_defined_sign(
        &self,
        fingerprint: QHashOut<C::F>,
        private_key: QHashOut<C::F>,
        input: DPNSoftwareDefinedSignatureInput,
        sig_hash: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self).prove_dpn_software_defined_sign(fingerprint, private_key, input, sig_hash).await
    }

    async fn prove_plonky2_software_defined_sign(
        &self,
        fingerprint: QHashOut<C::F>,
        private_key: QHashOut<C::F>,
        input: Plonky2SoftwareDefinedSignatureInput,
        sig_hash: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self)
            .prove_plonky2_software_defined_sign(fingerprint, private_key, input, sig_hash)
            .await
    }

    async fn prove_ups_end_cap(
        &self,
        circuit_info: &SessionCircuitInfoStore<C::F>,
        end_cap_from_proof_tree_input: &UPSEndCapFromProofTreeGadgetInput<C::F>,
        agg_proof_record: &AggProofRecord<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self)
            .prove_ups_end_cap(circuit_info, end_cap_from_proof_tree_input, agg_proof_record)
            .await
    }

    async fn ups_start_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        (**self).ups_start_circuit_fingerprint().await
    }

    async fn ups_start_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        (**self).ups_start_circuit_verifier_config().await
    }

    async fn ups_start_register_user_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        (**self).ups_start_register_user_circuit_fingerprint().await
    }

    async fn ups_start_register_user_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        (**self).ups_start_register_user_circuit_verifier_config().await
    }

    async fn ups_cfc_standard_tx_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        (**self).ups_cfc_standard_tx_circuit_fingerprint().await
    }

    async fn ups_cfc_standard_tx_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        (**self).ups_cfc_standard_tx_circuit_verifier_config().await
    }

    async fn ups_cfc_deferred_tx_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        (**self).ups_cfc_deferred_tx_circuit_fingerprint().await
    }

    async fn ups_cfc_deferred_tx_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        (**self).ups_cfc_deferred_tx_circuit_verifier_config().await
    }

    async fn ups_end_cap_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        (**self).ups_end_cap_circuit_fingerprint().await
    }

    async fn ups_end_cap_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        (**self).ups_end_cap_circuit_verifier_config().await
    }

    async fn ups_circuit_whitelist_root(&self) -> anyhow::Result<QHashOut<C::F>> {
        (**self).ups_circuit_whitelist_root().await
    }

    async fn secp_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        (**self).secp_circuit_fingerprint().await
    }

    async fn secp_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        (**self).secp_circuit_verifier_config().await
    }

    async fn eth_personal_secp_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        (**self).eth_personal_secp_circuit_fingerprint().await
    }

    async fn eth_personal_secp_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        (**self).eth_personal_secp_circuit_verifier_config().await
    }
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async(?Send))]
impl<C: GenericConfig<D>, const D: usize> UPSCircuitManager<C, D> for Box<dyn UPSCircuitManager<C, D>>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    async fn register_info(&self, info_store: &mut SessionCircuitInfoStore<C::F>) {
        (**self).register_info(info_store).await
    }

    async fn prove_ups_start(&self, input: &UPSStartStepInput<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self).prove_ups_start(input).await
    }

    async fn prove_ups_start_register_user(&self, input: &UPSStartStepRegisterUserInput<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self).prove_ups_start_register_user(input).await
    }

    async fn register_contract_circuits(&self, contract_id: u64, contract_code: &ContractCodeDefinition) -> anyhow::Result<()> {
        (**self).register_contract_circuits(contract_id, contract_code).await
    }

    async fn get_fn_id(&self, contract_id: u64, method_name: String) -> anyhow::Result<u64> {
        (**self).get_fn_id(contract_id, method_name).await
    }

    async fn resolve_contract_function_by_method_name(
        &self,
        contract_id: u64,
        contract_code: &ContractCodeDefinition,
        method_name: String,
    ) -> anyhow::Result<(u64, DPNFunctionCircuitDefinition)> {
        (**self)
            .resolve_contract_function_by_method_name(contract_id, contract_code, method_name)
            .await
    }

    async fn resolve_contract_function_by_method_id(
        &self,
        contract_id: u64,
        contract_code: &ContractCodeDefinition,
        method_id: u32,
    ) -> anyhow::Result<(u64, DPNFunctionCircuitDefinition)> {
        (**self)
            .resolve_contract_function_by_method_id(contract_id, contract_code, method_id)
            .await
    }

    async fn get_contract_method_common_data(&self, contract_id: u64, fn_id: u32) -> anyhow::Result<(QHashOut<C::F>, VerifierOnlyCircuitData<C, D>)> {
        (**self).get_contract_method_common_data(contract_id, fn_id).await
    }

    async fn prove_contract_call(
        &self,
        contract_id: u64,
        fn_id: u32,
        input: &DapenContractFunctionCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self).prove_contract_call(contract_id, fn_id, input).await
    }

    async fn prove_ups_cfc_standard_tx(
        &self,
        input: &UPSCFCStandardTransactionCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self).prove_ups_cfc_standard_tx(input).await
    }

    async fn prove_ups_cfc_deferred_tx(
        &self,
        input: &UPSCFCDeferredTransactionCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self).prove_ups_cfc_deferred_tx(input).await
    }

    async fn prove_zk_sign_minifier(&self, inner_proof: ProofWithPublicInputs<C::F, C, D>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self).prove_zk_sign_minifier(inner_proof).await
    }

    async fn zk_signature_minifier_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        (**self).zk_signature_minifier_fingerprint().await
    }

    async fn zk_signature_minifier_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        (**self).zk_signature_minifier_verifier_config().await
    }

    async fn prove_private_note_inclusion_minifier(
        &self,
        base_proof: ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self).prove_private_note_inclusion_minifier(base_proof).await
    }

    async fn private_note_inclusion_minifier_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        (**self).private_note_inclusion_minifier_fingerprint().await
    }

    async fn private_note_inclusion_minifier_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        (**self).private_note_inclusion_minifier_verifier_config().await
    }

    async fn prove_shield_deposit_claim_minifier(
        &self,
        base_proof: ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self).prove_shield_deposit_claim_minifier(base_proof).await
    }

    async fn shield_deposit_claim_minifier_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        (**self).shield_deposit_claim_minifier_fingerprint().await
    }

    async fn shield_deposit_claim_minifier_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        (**self).shield_deposit_claim_minifier_verifier_config().await
    }

    async fn prove_secp_sign(&self, signature: PsyCompressedSecp256K1Signature) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self).prove_secp_sign(signature).await
    }

    async fn prove_eth_personal_secp_sign(&self, signature: PsyCompressedSecp256K1Signature) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self).prove_eth_personal_secp_sign(signature).await
    }

    async fn register_dpn_software_defined_circuit(
        &self,
        fn_def: DPNFunctionCircuitDefinition,
        contract_id: u64,
        contract_state_tree_height: u8,
        session_proof_tree_height: u8,
        force_four_align: bool,
    ) -> anyhow::Result<QHashOut<C::F>> {
        (**self)
            .register_dpn_software_defined_circuit(
                fn_def,
                contract_id,
                contract_state_tree_height,
                session_proof_tree_height,
                force_four_align,
            )
            .await
    }

    async fn register_plonky2_software_defined_circuit(&self, contract_state_tree_height: u8, input_len: usize) -> anyhow::Result<QHashOut<C::F>> {
        (**self)
            .register_plonky2_software_defined_circuit(contract_state_tree_height, input_len)
            .await
    }

    async fn prove_dpn_software_defined_sign(
        &self,
        fingerprint: QHashOut<C::F>,
        private_key: QHashOut<C::F>,
        input: DPNSoftwareDefinedSignatureInput,
        sig_hash: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self).prove_dpn_software_defined_sign(fingerprint, private_key, input, sig_hash).await
    }

    async fn prove_plonky2_software_defined_sign(
        &self,
        fingerprint: QHashOut<C::F>,
        private_key: QHashOut<C::F>,
        input: Plonky2SoftwareDefinedSignatureInput,
        sig_hash: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self)
            .prove_plonky2_software_defined_sign(fingerprint, private_key, input, sig_hash)
            .await
    }

    async fn prove_ups_end_cap(
        &self,
        circuit_info: &SessionCircuitInfoStore<C::F>,
        end_cap_from_proof_tree_input: &UPSEndCapFromProofTreeGadgetInput<C::F>,
        agg_proof_record: &AggProofRecord<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self)
            .prove_ups_end_cap(circuit_info, end_cap_from_proof_tree_input, agg_proof_record)
            .await
    }

    async fn ups_start_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        (**self).ups_start_circuit_fingerprint().await
    }

    async fn ups_start_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        (**self).ups_start_circuit_verifier_config().await
    }

    async fn ups_start_register_user_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        (**self).ups_start_register_user_circuit_fingerprint().await
    }

    async fn ups_start_register_user_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        (**self).ups_start_register_user_circuit_verifier_config().await
    }

    async fn ups_cfc_standard_tx_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        (**self).ups_cfc_standard_tx_circuit_fingerprint().await
    }

    async fn ups_cfc_standard_tx_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        (**self).ups_cfc_standard_tx_circuit_verifier_config().await
    }

    async fn ups_cfc_deferred_tx_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        (**self).ups_cfc_deferred_tx_circuit_fingerprint().await
    }

    async fn ups_cfc_deferred_tx_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        (**self).ups_cfc_deferred_tx_circuit_verifier_config().await
    }

    async fn ups_end_cap_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        (**self).ups_end_cap_circuit_fingerprint().await
    }

    async fn ups_end_cap_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        (**self).ups_end_cap_circuit_verifier_config().await
    }

    async fn ups_circuit_whitelist_root(&self) -> anyhow::Result<QHashOut<C::F>> {
        (**self).ups_circuit_whitelist_root().await
    }

    async fn secp_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        (**self).secp_circuit_fingerprint().await
    }

    async fn secp_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        (**self).secp_circuit_verifier_config().await
    }

    async fn eth_personal_secp_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        (**self).eth_personal_secp_circuit_fingerprint().await
    }

    async fn eth_personal_secp_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        (**self).eth_personal_secp_circuit_verifier_config().await
    }
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
pub trait PortableQTreeRecursion<C: GenericConfig<D>, const D: usize>:
    PortableQTreeRecursionCircuitsData<C, D> + PortableQTreeRecursionCircuitsProve<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    async fn circuit_inclusion_proofs(&self) -> &SimpleQTreeRecursionManagerInclusionProofs<C::F>;
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
pub trait PortableQTreeRecursionCircuitsData<C: GenericConfig<D>, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    async fn single_leaf_circuit_fingerprint(&self) -> QHashOut<C::F>;
    async fn two_leaf_circuit_fingerprint(&self) -> QHashOut<C::F>;
    async fn two_agg_circuit_fingerprint(&self) -> QHashOut<C::F>;
    async fn left_leaf_right_agg_circuit_fingerprint(&self) -> QHashOut<C::F>;
    async fn left_agg_right_leaf_circuit_fingerprint(&self) -> QHashOut<C::F>;
    async fn single_leaf_circuit_verifier_config(&self) -> VerifierOnlyCircuitData<C, D>;
    async fn two_leaf_circuit_verifier_config(&self) -> VerifierOnlyCircuitData<C, D>;
    async fn two_agg_circuit_verifier_config(&self) -> VerifierOnlyCircuitData<C, D>;
    async fn left_leaf_right_agg_circuit_verifier_config(&self) -> VerifierOnlyCircuitData<C, D>;
    async fn left_agg_right_leaf_circuit_verifier_config(&self) -> VerifierOnlyCircuitData<C, D>;
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
pub trait PortableQTreeRecursionCircuitsProve<C: GenericConfig<D>, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    async fn get_verifier_data_by_type(&self, circuit_type: QStandardBinaryTreeCircuitType) -> VerifierOnlyCircuitData<C, D>;
    async fn prove_single_leaf_circuit(
        &self,
        agg_circuit_whitelist_root: QHashOut<C::F>,
        single_insert_leaf_proof: &DeltaMerkleProofCore<QHashOut<C::F>>,
        single_proof: &ProofWithPublicInputs<C::F, C, D>,
        single_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
    async fn prove_two_leaf_circuit(
        &self,
        agg_circuit_whitelist_root: QHashOut<C::F>,
        left_insert_leaf_proof: &DeltaMerkleProofCore<QHashOut<C::F>>,
        left_proof: &ProofWithPublicInputs<C::F, C, D>,
        left_verifier_data: &VerifierOnlyCircuitData<C, D>,
        right_insert_leaf_proof: &DeltaMerkleProofCore<QHashOut<C::F>>,
        right_proof: &ProofWithPublicInputs<C::F, C, D>,
        right_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
    async fn prove_two_agg_circuit(
        &self,
        left_agg_whitelist_merkle_proof: &MerkleProofCore<QHashOut<C::F>>,
        left_agg_proof_header: &QRecursionAggStandardHeader<C::F>,
        left_proof: &ProofWithPublicInputs<C::F, C, D>,
        left_verifier_data: &VerifierOnlyCircuitData<C, D>,
        right_agg_whitelist_merkle_proof: &MerkleProofCore<QHashOut<C::F>>,
        right_agg_proof_header: &QRecursionAggStandardHeader<C::F>,
        right_proof: &ProofWithPublicInputs<C::F, C, D>,
        right_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
    async fn prove_left_leaf_right_agg_circuit(
        &self,
        left_insert_leaf_proof: &DeltaMerkleProofCore<QHashOut<C::F>>,
        left_proof: &ProofWithPublicInputs<C::F, C, D>,
        left_verifier_data: &VerifierOnlyCircuitData<C, D>,
        right_agg_whitelist_merkle_proof: &MerkleProofCore<QHashOut<C::F>>,
        right_agg_proof_header: &QRecursionAggStandardHeader<C::F>,
        right_proof: &ProofWithPublicInputs<C::F, C, D>,
        right_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
    async fn prove_left_agg_right_leaf_circuit(
        &self,
        left_agg_whitelist_merkle_proof: &MerkleProofCore<QHashOut<C::F>>,
        left_agg_proof_header: &QRecursionAggStandardHeader<C::F>,
        left_proof: &ProofWithPublicInputs<C::F, C, D>,
        left_verifier_data: &VerifierOnlyCircuitData<C, D>,
        right_insert_leaf_proof: &DeltaMerkleProofCore<QHashOut<C::F>>,
        right_proof: &ProofWithPublicInputs<C::F, C, D>,
        right_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
}

// Blanket implementations for &T and Box<dyn UPSCircuitManager>
#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl<T, C: GenericConfig<D>, const D: usize> PortableQTreeRecursionCircuitsData<C, D> for &T
where
    T: PortableQTreeRecursionCircuitsData<C, D> + Sync,
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    async fn single_leaf_circuit_fingerprint(&self) -> QHashOut<C::F> {
        (**self).single_leaf_circuit_fingerprint().await
    }
    async fn two_leaf_circuit_fingerprint(&self) -> QHashOut<C::F> {
        (**self).two_leaf_circuit_fingerprint().await
    }
    async fn two_agg_circuit_fingerprint(&self) -> QHashOut<C::F> {
        (**self).two_agg_circuit_fingerprint().await
    }
    async fn left_leaf_right_agg_circuit_fingerprint(&self) -> QHashOut<C::F> {
        (**self).left_leaf_right_agg_circuit_fingerprint().await
    }
    async fn left_agg_right_leaf_circuit_fingerprint(&self) -> QHashOut<C::F> {
        (**self).left_agg_right_leaf_circuit_fingerprint().await
    }
    async fn single_leaf_circuit_verifier_config(&self) -> VerifierOnlyCircuitData<C, D> {
        (**self).single_leaf_circuit_verifier_config().await
    }
    async fn two_leaf_circuit_verifier_config(&self) -> VerifierOnlyCircuitData<C, D> {
        (**self).two_leaf_circuit_verifier_config().await
    }
    async fn two_agg_circuit_verifier_config(&self) -> VerifierOnlyCircuitData<C, D> {
        (**self).two_agg_circuit_verifier_config().await
    }
    async fn left_leaf_right_agg_circuit_verifier_config(&self) -> VerifierOnlyCircuitData<C, D> {
        (**self).left_leaf_right_agg_circuit_verifier_config().await
    }
    async fn left_agg_right_leaf_circuit_verifier_config(&self) -> VerifierOnlyCircuitData<C, D> {
        (**self).left_agg_right_leaf_circuit_verifier_config().await
    }
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl<T, C: GenericConfig<D>, const D: usize> PortableQTreeRecursionCircuitsProve<C, D> for &T
where
    T: PortableQTreeRecursionCircuitsProve<C, D> + Sync,
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    async fn get_verifier_data_by_type(&self, circuit_type: QStandardBinaryTreeCircuitType) -> VerifierOnlyCircuitData<C, D> {
        (**self).get_verifier_data_by_type(circuit_type).await
    }
    async fn prove_single_leaf_circuit(
        &self,
        agg_circuit_whitelist_root: QHashOut<C::F>,
        single_insert_leaf_proof: &DeltaMerkleProofCore<QHashOut<C::F>>,
        single_proof: &ProofWithPublicInputs<C::F, C, D>,
        single_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self)
            .prove_single_leaf_circuit(agg_circuit_whitelist_root, single_insert_leaf_proof, single_proof, single_verifier_data)
            .await
    }
    async fn prove_two_leaf_circuit(
        &self,
        agg_circuit_whitelist_root: QHashOut<C::F>,
        left_insert_leaf_proof: &DeltaMerkleProofCore<QHashOut<C::F>>,
        left_proof: &ProofWithPublicInputs<C::F, C, D>,
        left_verifier_data: &VerifierOnlyCircuitData<C, D>,
        right_insert_leaf_proof: &DeltaMerkleProofCore<QHashOut<C::F>>,
        right_proof: &ProofWithPublicInputs<C::F, C, D>,
        right_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self)
            .prove_two_leaf_circuit(
                agg_circuit_whitelist_root,
                left_insert_leaf_proof,
                left_proof,
                left_verifier_data,
                right_insert_leaf_proof,
                right_proof,
                right_verifier_data,
            )
            .await
    }
    async fn prove_two_agg_circuit(
        &self,
        left_agg_whitelist_merkle_proof: &MerkleProofCore<QHashOut<C::F>>,
        left_agg_proof_header: &QRecursionAggStandardHeader<C::F>,
        left_proof: &ProofWithPublicInputs<C::F, C, D>,
        left_verifier_data: &VerifierOnlyCircuitData<C, D>,
        right_agg_whitelist_merkle_proof: &MerkleProofCore<QHashOut<C::F>>,
        right_agg_proof_header: &QRecursionAggStandardHeader<C::F>,
        right_proof: &ProofWithPublicInputs<C::F, C, D>,
        right_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self)
            .prove_two_agg_circuit(
                left_agg_whitelist_merkle_proof,
                left_agg_proof_header,
                left_proof,
                left_verifier_data,
                right_agg_whitelist_merkle_proof,
                right_agg_proof_header,
                right_proof,
                right_verifier_data,
            )
            .await
    }
    async fn prove_left_leaf_right_agg_circuit(
        &self,
        left_insert_leaf_proof: &DeltaMerkleProofCore<QHashOut<C::F>>,
        left_proof: &ProofWithPublicInputs<C::F, C, D>,
        left_verifier_data: &VerifierOnlyCircuitData<C, D>,
        right_agg_whitelist_merkle_proof: &MerkleProofCore<QHashOut<C::F>>,
        right_agg_proof_header: &QRecursionAggStandardHeader<C::F>,
        right_proof: &ProofWithPublicInputs<C::F, C, D>,
        right_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self)
            .prove_left_leaf_right_agg_circuit(
                left_insert_leaf_proof,
                left_proof,
                left_verifier_data,
                right_agg_whitelist_merkle_proof,
                right_agg_proof_header,
                right_proof,
                right_verifier_data,
            )
            .await
    }
    async fn prove_left_agg_right_leaf_circuit(
        &self,
        left_agg_whitelist_merkle_proof: &MerkleProofCore<QHashOut<C::F>>,
        left_agg_proof_header: &QRecursionAggStandardHeader<C::F>,
        left_proof: &ProofWithPublicInputs<C::F, C, D>,
        left_verifier_data: &VerifierOnlyCircuitData<C, D>,
        right_insert_leaf_proof: &DeltaMerkleProofCore<QHashOut<C::F>>,
        right_proof: &ProofWithPublicInputs<C::F, C, D>,
        right_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self)
            .prove_left_agg_right_leaf_circuit(
                left_agg_whitelist_merkle_proof,
                left_agg_proof_header,
                left_proof,
                left_verifier_data,
                right_insert_leaf_proof,
                right_proof,
                right_verifier_data,
            )
            .await
    }
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl<T, C: GenericConfig<D>, const D: usize> PortableQTreeRecursion<C, D> for &T
where
    T: PortableQTreeRecursion<C, D> + Sync,
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    async fn circuit_inclusion_proofs(&self) -> &SimpleQTreeRecursionManagerInclusionProofs<C::F> {
        (**self).circuit_inclusion_proofs().await
    }
}

// Blanket implementations for Box<dyn UPSCircuitManager>
#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl<C: GenericConfig<D>, const D: usize> PortableQTreeRecursion<C, D> for Box<dyn UPSCircuitManager<C, D>>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    async fn circuit_inclusion_proofs(&self) -> &SimpleQTreeRecursionManagerInclusionProofs<C::F> {
        (**self).circuit_inclusion_proofs().await
    }
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl<C: GenericConfig<D>, const D: usize> PortableQTreeRecursionCircuitsData<C, D> for Box<dyn UPSCircuitManager<C, D>>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    async fn single_leaf_circuit_fingerprint(&self) -> QHashOut<C::F> {
        (**self).single_leaf_circuit_fingerprint().await
    }
    async fn two_leaf_circuit_fingerprint(&self) -> QHashOut<C::F> {
        (**self).two_leaf_circuit_fingerprint().await
    }
    async fn two_agg_circuit_fingerprint(&self) -> QHashOut<C::F> {
        (**self).two_agg_circuit_fingerprint().await
    }
    async fn left_leaf_right_agg_circuit_fingerprint(&self) -> QHashOut<C::F> {
        (**self).left_leaf_right_agg_circuit_fingerprint().await
    }
    async fn left_agg_right_leaf_circuit_fingerprint(&self) -> QHashOut<C::F> {
        (**self).left_agg_right_leaf_circuit_fingerprint().await
    }
    async fn single_leaf_circuit_verifier_config(&self) -> VerifierOnlyCircuitData<C, D> {
        (**self).single_leaf_circuit_verifier_config().await
    }
    async fn two_leaf_circuit_verifier_config(&self) -> VerifierOnlyCircuitData<C, D> {
        (**self).two_leaf_circuit_verifier_config().await
    }
    async fn two_agg_circuit_verifier_config(&self) -> VerifierOnlyCircuitData<C, D> {
        (**self).two_agg_circuit_verifier_config().await
    }
    async fn left_leaf_right_agg_circuit_verifier_config(&self) -> VerifierOnlyCircuitData<C, D> {
        (**self).left_leaf_right_agg_circuit_verifier_config().await
    }
    async fn left_agg_right_leaf_circuit_verifier_config(&self) -> VerifierOnlyCircuitData<C, D> {
        (**self).left_agg_right_leaf_circuit_verifier_config().await
    }
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl<C: GenericConfig<D>, const D: usize> PortableQTreeRecursionCircuitsProve<C, D> for Box<dyn UPSCircuitManager<C, D>>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    async fn get_verifier_data_by_type(&self, circuit_type: QStandardBinaryTreeCircuitType) -> VerifierOnlyCircuitData<C, D> {
        (**self).get_verifier_data_by_type(circuit_type).await
    }
    async fn prove_single_leaf_circuit(
        &self,
        agg_circuit_whitelist_root: QHashOut<C::F>,
        single_insert_leaf_proof: &DeltaMerkleProofCore<QHashOut<C::F>>,
        single_proof: &ProofWithPublicInputs<C::F, C, D>,
        single_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self)
            .prove_single_leaf_circuit(agg_circuit_whitelist_root, single_insert_leaf_proof, single_proof, single_verifier_data)
            .await
    }
    async fn prove_two_leaf_circuit(
        &self,
        agg_circuit_whitelist_root: QHashOut<C::F>,
        left_insert_leaf_proof: &DeltaMerkleProofCore<QHashOut<C::F>>,
        left_proof: &ProofWithPublicInputs<C::F, C, D>,
        left_verifier_data: &VerifierOnlyCircuitData<C, D>,
        right_insert_leaf_proof: &DeltaMerkleProofCore<QHashOut<C::F>>,
        right_proof: &ProofWithPublicInputs<C::F, C, D>,
        right_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self)
            .prove_two_leaf_circuit(
                agg_circuit_whitelist_root,
                left_insert_leaf_proof,
                left_proof,
                left_verifier_data,
                right_insert_leaf_proof,
                right_proof,
                right_verifier_data,
            )
            .await
    }
    async fn prove_two_agg_circuit(
        &self,
        left_agg_whitelist_merkle_proof: &MerkleProofCore<QHashOut<C::F>>,
        left_agg_proof_header: &QRecursionAggStandardHeader<C::F>,
        left_proof: &ProofWithPublicInputs<C::F, C, D>,
        left_verifier_data: &VerifierOnlyCircuitData<C, D>,
        right_agg_whitelist_merkle_proof: &MerkleProofCore<QHashOut<C::F>>,
        right_agg_proof_header: &QRecursionAggStandardHeader<C::F>,
        right_proof: &ProofWithPublicInputs<C::F, C, D>,
        right_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self)
            .prove_two_agg_circuit(
                left_agg_whitelist_merkle_proof,
                left_agg_proof_header,
                left_proof,
                left_verifier_data,
                right_agg_whitelist_merkle_proof,
                right_agg_proof_header,
                right_proof,
                right_verifier_data,
            )
            .await
    }
    async fn prove_left_leaf_right_agg_circuit(
        &self,
        left_insert_leaf_proof: &DeltaMerkleProofCore<QHashOut<C::F>>,
        left_proof: &ProofWithPublicInputs<C::F, C, D>,
        left_verifier_data: &VerifierOnlyCircuitData<C, D>,
        right_agg_whitelist_merkle_proof: &MerkleProofCore<QHashOut<C::F>>,
        right_agg_proof_header: &QRecursionAggStandardHeader<C::F>,
        right_proof: &ProofWithPublicInputs<C::F, C, D>,
        right_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self)
            .prove_left_leaf_right_agg_circuit(
                left_insert_leaf_proof,
                left_proof,
                left_verifier_data,
                right_agg_whitelist_merkle_proof,
                right_agg_proof_header,
                right_proof,
                right_verifier_data,
            )
            .await
    }
    async fn prove_left_agg_right_leaf_circuit(
        &self,
        left_agg_whitelist_merkle_proof: &MerkleProofCore<QHashOut<C::F>>,
        left_agg_proof_header: &QRecursionAggStandardHeader<C::F>,
        left_proof: &ProofWithPublicInputs<C::F, C, D>,
        left_verifier_data: &VerifierOnlyCircuitData<C, D>,
        right_insert_leaf_proof: &DeltaMerkleProofCore<QHashOut<C::F>>,
        right_proof: &ProofWithPublicInputs<C::F, C, D>,
        right_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        (**self)
            .prove_left_agg_right_leaf_circuit(
                left_agg_whitelist_merkle_proof,
                left_agg_proof_header,
                left_proof,
                left_verifier_data,
                right_insert_leaf_proof,
                right_proof,
                right_verifier_data,
            )
            .await
    }
}
