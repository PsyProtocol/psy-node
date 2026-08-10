use std::sync::{Arc, OnceLock};

use plonky2::{
    hash::hash_types::{HashOut, RichField},
    plonk::{
        circuit_data::VerifierOnlyCircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_client_common::{data::qhashout::QHashOut, ups::circuits::LocalCircuitType};
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
use psy_common_circuit::{
    circuits::{
        secp256k1_signature::{EthPersonalSignSecp256K1SignatureCircuit, Secp256K1SignatureCircuit},
        traits::qstandard::QStandardCircuit,
        zk_signature3::core::PsyBasicZKSignatureCircuit,
    },
    treeprover::qrecursion::standard::manager::{
        leaf_circuit_set::QStandardBinaryRecursionTreeCircuitSet, portable::circuits::PortableQTreeRecursionCircuits,
    },
};
use psy_config::network_constants::{
    GLOBAL_CONTRACT_TREE_HEIGHT, GLOBAL_USER_TREE_HEIGHT, MAX_CONTRACT_STATE_TREE_HEIGHT, PRIVATE_NOTE_TREE_HEIGHT,
    UPS_CIRCUIT_WHITELIST_TREE_HEIGHT, UPS_SESSION_PROOF_TREE_HEIGHT,
};
use psy_crypto::{
    common::witnesses::qrecursion::proof_data::{AggProofRecord, SimpleQTreeRecursionManagerInclusionProofs},
    hash::{
        merkle::{core::MerkleProofCore, utils::simple_merkle_tree::SimpleMerkleTree},
        traits::hasher::MerkleZeroHasherWithMarkedLeaf,
    },
    signature::secp256k1::core::PsyCompressedSecp256K1Signature,
};
use psy_dpn_circuit::circuits::{
    cfc::DapenContractFunctionCircuit,
    privacy::{private_note_inclusion::PrivateNoteInclusionCircuit, shield_deposit_claim::ShieldDepositClaimCircuit},
};
use psy_network_circuit::ups::circuits::{
    end_cap::UPSStandardEndCapCircuit, ups_cfc_deferred_tx::UPSCFCDeferredTransactionCircuit, ups_cfc_standard::UPSCFCStandardTransactionCircuit,
    ups_start::UPSStartSessionCircuit, ups_start_register_user::UPSStartSessionRegisterUserCircuit,
};
use psy_vm::{
    dpn::{contract::cfc_code_definition_to_dapen_fc, vm::def::DPNFunctionCircuitDefinition},
    ups::circuit_manager::{PortableQTreeRecursion, PortableQTreeRecursionCircuitsData, PortableQTreeRecursionCircuitsProve, UPSCircuitManager},
    vm::cfc_input::DapenContractFunctionCircuitInput,
};
use quick_cache::sync::Cache;
use serde::Serialize;

#[derive(Debug)]
pub struct PsyUPSStepCircuitManager<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    pub ups_start: UPSStartSessionCircuit<C, D>,
    pub ups_start_register_user: UPSStartSessionRegisterUserCircuit<C, D>,
    pub proof_tree_agg_circuits: PortableQTreeRecursionCircuits<C, D>,
    pub ups_cfc_standard_tx: UPSCFCStandardTransactionCircuit<C, D>,
    pub ups_cfc_deferred_tx: UPSCFCDeferredTransactionCircuit<C, D>,
    pub ups_end_cap: UPSStandardEndCapCircuit<C, D>,

    pub ups_circuit_whitelist_root: QHashOut<C::F>,
    pub ups_start_whitelist_proof: MerkleProofCore<QHashOut<C::F>>,
    pub ups_cfc_standard_tx_whitelist_proof: MerkleProofCore<QHashOut<C::F>>,
    pub ups_cfc_deferred_tx_whitelist_proof: MerkleProofCore<QHashOut<C::F>>,
    pub ups_start_register_user_whitelist_proof: MerkleProofCore<QHashOut<C::F>>,

    // contract circuits, lazily cached by (contract_id, fn_id)
    pub contract_circuits: Cache<(u64, u32), Arc<DapenContractFunctionCircuit<C, D>>>,
    // method name index, cached by (contract_id, method_name)
    pub contract_method_ids: Cache<(u64, String), u32>,

    zk_signature_minifier_circuit: OnceLock<PsyBasicZKSignatureCircuit<C, D>>,
    secp_circuit: OnceLock<Secp256K1SignatureCircuit<C, D>>,
    eth_personal_secp_circuit: OnceLock<EthPersonalSignSecp256K1SignatureCircuit<C, D>>,
    // Server-side minifier circuits (base+minifier) for the wallet's base-only privacy
    // proofs. The wallet produces base proofs; these minify them.
    private_note_inclusion_minifier_circuit: OnceLock<PrivateNoteInclusionCircuit<C, D>>,
    shield_deposit_claim_minifier_circuit: OnceLock<ShieldDepositClaimCircuit<C, D>>,
}

impl<C: GenericConfig<D> + 'static, const D: usize> PsyUPSStepCircuitManager<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    pub fn new_with_config(
        //coset_gate: &GateRef<C::F, D>,
        network_magic: u64,
    ) -> Self {
        let ups_start = UPSStartSessionCircuit::new();
        let ups_start_register_user = UPSStartSessionRegisterUserCircuit::new();
        let ups_cfc_standard_tx = UPSCFCStandardTransactionCircuit::new();
        let ups_cfc_deferred_tx = UPSCFCDeferredTransactionCircuit::new();

        let mut ups_circuit_whitelist_proofs = SimpleMerkleTree::<C::Hasher, QHashOut<C::F>>::gen_fast_tree_inclusion_proofs(
            UPS_CIRCUIT_WHITELIST_TREE_HEIGHT,
            &[
                ups_start.get_fingerprint(),
                ups_cfc_standard_tx.get_fingerprint(),
                ups_cfc_deferred_tx.get_fingerprint(),
                ups_start_register_user.get_fingerprint(),
            ],
        )
        .unwrap();

        let ups_start_register_user_whitelist_proof = ups_circuit_whitelist_proofs.pop().unwrap();
        let ups_cfc_deferred_tx_whitelist_proof = ups_circuit_whitelist_proofs.pop().unwrap();
        let ups_cfc_standard_tx_whitelist_proof = ups_circuit_whitelist_proofs.pop().unwrap();
        let ups_start_whitelist_proof = ups_circuit_whitelist_proofs.pop().unwrap();

        let ups_circuit_whitelist_root = ups_cfc_standard_tx_whitelist_proof.root;

        let proof_tree_agg_circuits = PortableQTreeRecursionCircuits::new(
            UPS_SESSION_PROOF_TREE_HEIGHT as usize,
            1,
            ups_cfc_deferred_tx.circuit_data.verifier_only.constants_sigmas_cap.height(),
            &ups_cfc_deferred_tx.circuit_data.common,
        );
        let ups_end_cap = UPSStandardEndCapCircuit::new_with_minifier(
            &proof_tree_agg_circuits.circuit_set.two_agg_circuit.circuit_data.common,
            proof_tree_agg_circuits
                .circuit_set
                .two_agg_circuit
                .get_verifier_config_ref()
                .constants_sigmas_cap
                .height(),
            network_magic,
            ups_circuit_whitelist_root,
            proof_tree_agg_circuits.circuit_inclusion_proofs.circuit_whitelist_tree_root,
        );

        /*
        let ups_end_cap = UPSStandardEndCapCircuit::new_with_minifier(
            proof_tree_agg_circuits.root_circuit.get_common_circuit_data_ref(),
            proof_tree_agg_circuits.root_circuit.get_verifier_config_ref(),
            network_magic,
            ups_circuit_whitelist_root,
        );*/

        Self {
            ups_start,
            ups_start_register_user,
            proof_tree_agg_circuits,
            ups_cfc_standard_tx,
            ups_cfc_deferred_tx,
            ups_end_cap,
            ups_circuit_whitelist_root,
            ups_start_whitelist_proof,
            ups_cfc_standard_tx_whitelist_proof,
            ups_cfc_deferred_tx_whitelist_proof,
            ups_start_register_user_whitelist_proof,
            contract_circuits: Cache::new(200),
            contract_method_ids: Cache::new(1000),
            zk_signature_minifier_circuit: OnceLock::new(),
            secp_circuit: OnceLock::new(),
            eth_personal_secp_circuit: OnceLock::new(),
            private_note_inclusion_minifier_circuit: OnceLock::new(),
            shield_deposit_claim_minifier_circuit: OnceLock::new(),
        }
    }

    fn zk_signature_minifier_circuit(&self) -> &PsyBasicZKSignatureCircuit<C, D> {
        self.zk_signature_minifier_circuit.get_or_init(PsyBasicZKSignatureCircuit::<C, D>::new)
    }

    pub fn secp_circuit(&self) -> &Secp256K1SignatureCircuit<C, D> {
        self.secp_circuit.get_or_init(Secp256K1SignatureCircuit::new)
    }

    pub fn eth_personal_secp_circuit(&self) -> &EthPersonalSignSecp256K1SignatureCircuit<C, D> {
        self.eth_personal_secp_circuit
            .get_or_init(EthPersonalSignSecp256K1SignatureCircuit::new)
    }

    pub fn private_note_inclusion_minifier_circuit(&self) -> &PrivateNoteInclusionCircuit<C, D> {
        self.private_note_inclusion_minifier_circuit.get_or_init(|| {
            PrivateNoteInclusionCircuit::<C, D>::new(
                GLOBAL_USER_TREE_HEIGHT as usize,
                GLOBAL_CONTRACT_TREE_HEIGHT as usize,
                MAX_CONTRACT_STATE_TREE_HEIGHT as usize,
                PRIVATE_NOTE_TREE_HEIGHT,
            )
        })
    }

    pub fn shield_deposit_claim_minifier_circuit(&self) -> &ShieldDepositClaimCircuit<C, D> {
        self.shield_deposit_claim_minifier_circuit
            .get_or_init(ShieldDepositClaimCircuit::<C, D>::new)
    }

    pub fn print_common_config(&self) {
        println!(
            "\n\n\n\n================================\n[ups_start.common]:\n{:?}",
            self.ups_start.get_common_circuit_data_ref()
        );
        println!(
            "================================\n[ups_cfc_standard_tx.common]:\n{:?}",
            self.ups_cfc_standard_tx.get_common_circuit_data_ref()
        );
        println!(
            "================================\n[ups_cfc_deferred_tx.common]:\n{:?}",
            self.ups_cfc_deferred_tx.get_common_circuit_data_ref()
        );
        println!(
            "\n\n\n\n================================\n[ups_start.common]:\n{:?}",
            self.ups_start.get_common_circuit_data_ref()
        );
        println!(
            "\n\n\n\n================================\n[ups_start_register_user.common]:\n{:?}",
            self.ups_start_register_user.get_common_circuit_data_ref()
        );
        println!(
            "================================\n[ups_end_cap.common]:\n{:?}",
            self.ups_end_cap.get_common_circuit_data_ref()
        );

        println!("===============================\n\n\n\n");
        self.proof_tree_agg_circuits.circuit_set.print_common_data();
    }
}

impl<C: GenericConfig<D> + 'static, const D: usize> PsyUPSStepCircuitManager<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    async fn register_contract_method_circuit(&self, contract_id: u64, contract_code: &ContractCodeDefinition, fn_id: u32) -> anyhow::Result<()> {
        // Fast-path: already cached
        if self.contract_circuits.get(&(contract_id, fn_id)).is_some() {
            return Ok(());
        }

        // Prepare function definition (done outside get_with to avoid
        // re-executing it for concurrent callers that lose the race)
        let func = contract_code
            .functions
            .get(fn_id as usize)
            .ok_or_else(|| anyhow::anyhow!("contract {} method {} is not found", contract_id, fn_id))?;
        let dapen_fc = cfc_code_definition_to_dapen_fc(func)?;
        let fn_name = dapen_fc.name.clone();

        tracing::info!("register contract {} function {}", contract_id, fn_name);

        // Use get_or_insert_with for atomic check-then-insert: only one thread
        // compiles per (contract_id, fn_id); all others block and receive the
        // cached Arc via the guard mechanism.
        let state_tree_height = contract_code.state_tree_height as usize;
        self.contract_circuits
            .get_or_insert_with(&(contract_id, fn_id), || {
                Ok::<Arc<DapenContractFunctionCircuit<C, D>>, std::convert::Infallible>(Arc::new(DapenContractFunctionCircuit::<C, D>::new(
                    &dapen_fc,
                    state_tree_height,
                    UPS_SESSION_PROOF_TREE_HEIGHT as usize,
                    false,
                )))
            })
            .ok();

        self.contract_method_ids.insert((contract_id, fn_name), fn_id);
        Ok(())
    }

    fn resolve_fn_id_by_method_name(&self, contract_code: &ContractCodeDefinition, method_name: &str) -> anyhow::Result<u32> {
        for (fn_id, func) in contract_code.functions.iter().enumerate() {
            let dapen_fc = cfc_code_definition_to_dapen_fc(func)?;
            if dapen_fc.name == method_name {
                return Ok(fn_id as u32);
            }
        }
        Err(anyhow::format_err!("method {} is not found in contract", method_name))
    }
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl<C: GenericConfig<D> + 'static + Serialize, const D: usize> UPSCircuitManager<C, D> for PsyUPSStepCircuitManager<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    async fn register_info(&self, info_store: &mut SessionCircuitInfoStore<C::F>) {
        info_store.register_circuit(
            LocalCircuitType::UPSStart.into(),
            self.ups_start.get_fingerprint(),
            self.ups_start.get_verifier_config_ref().into(),
        );
        info_store.register_circuit(
            LocalCircuitType::UPSCFCStandard.into(),
            self.ups_cfc_standard_tx.get_fingerprint(),
            self.ups_cfc_standard_tx.get_verifier_config_ref().into(),
        );
        info_store.register_circuit(
            LocalCircuitType::UPSCFCDeferred.into(),
            self.ups_cfc_deferred_tx.get_fingerprint(),
            self.ups_cfc_deferred_tx.get_verifier_config_ref().into(),
        );
        info_store.register_circuit(
            LocalCircuitType::UPSEndCap.into(),
            self.ups_end_cap.get_fingerprint(),
            self.ups_end_cap.get_verifier_config_ref().into(),
        );
        info_store.register_circuit(
            LocalCircuitType::UPSStartRegisterUser.into(),
            self.ups_start_register_user.get_fingerprint(),
            self.ups_start_register_user.get_verifier_config_ref().into(),
        );
        info_store.register_circuit(
            LocalCircuitType::UPSEndCap.into(),
            self.ups_end_cap.get_fingerprint(),
            self.ups_end_cap.get_verifier_config_ref().into(),
        );

        info_store.register_whitelist_merkle_proof(LocalCircuitType::UPSStart.into(), self.ups_start_whitelist_proof.clone());
        info_store.register_whitelist_merkle_proof(LocalCircuitType::UPSCFCStandard.into(), self.ups_cfc_standard_tx_whitelist_proof.clone());
        info_store.register_whitelist_merkle_proof(LocalCircuitType::UPSCFCDeferred.into(), self.ups_cfc_deferred_tx_whitelist_proof.clone());
        info_store.register_whitelist_merkle_proof(
            LocalCircuitType::UPSStartRegisterUser.into(),
            self.ups_start_register_user_whitelist_proof.clone(),
        );

        register_qtree_recursion_circuits(&self.proof_tree_agg_circuits.circuit_set, info_store);
        register_qtree_recursion_circuits_whitelist_proofs(&self.proof_tree_agg_circuits.circuit_inclusion_proofs, info_store);
    }

    async fn prove_ups_start(&self, input: &UPSStartStepInput<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.ups_start.prove_base(input)
    }
    async fn prove_ups_start_register_user(&self, input: &UPSStartStepRegisterUserInput<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.ups_start_register_user.prove_base(input)
    }

    async fn register_contract_circuits(&self, contract_id: u64, contract_code: &ContractCodeDefinition) -> anyhow::Result<()> {
        for (fn_id, _) in contract_code.functions.iter().enumerate() {
            self.register_contract_method_circuit(contract_id, contract_code, fn_id as u32).await?;
        }
        Ok(())
    }

    async fn get_fn_id(&self, contract_id: u64, method_name: String) -> anyhow::Result<u64> {
        if let Some(fn_id) = self.contract_method_ids.get(&(contract_id, method_name.clone())) {
            return Ok(fn_id as u64);
        }
        Err(anyhow::format_err!("contract {} method {} is not found", contract_id, method_name))
    }

    async fn resolve_contract_function_by_method_name(
        &self,
        contract_id: u64,
        contract_code: &ContractCodeDefinition,
        method_name: String,
    ) -> anyhow::Result<(u64, DPNFunctionCircuitDefinition)> {
        let fn_id = self.resolve_fn_id_by_method_name(contract_code, &method_name)?;
        self.register_contract_method_circuit(contract_id, contract_code, fn_id).await?;
        self.contract_method_ids.insert((contract_id, method_name), fn_id);
        let fn_code_def = contract_code
            .functions
            .get(fn_id as usize)
            .ok_or_else(|| anyhow::format_err!("contract {} method {} is not found", contract_id, fn_id))?;
        let fn_circuit_def = cfc_code_definition_to_dapen_fc(fn_code_def)?;

        Ok((fn_id as u64, fn_circuit_def))
    }

    async fn resolve_contract_function_by_method_id(
        &self,
        contract_id: u64,
        contract_code: &ContractCodeDefinition,
        method_id: u32,
    ) -> anyhow::Result<(u64, DPNFunctionCircuitDefinition)> {
        let (fn_id, fn_code_def) = contract_code
            .functions
            .iter()
            .enumerate()
            .find_map(|(fn_id, f)| if f.method_id == method_id { Some((fn_id, f)) } else { None })
            .ok_or_else(|| anyhow::anyhow!("method ({}) not found in contract", method_id))?;
        let fn_id = fn_id as u32;
        self.register_contract_method_circuit(contract_id, contract_code, fn_id).await?;
        let dapen_fc = cfc_code_definition_to_dapen_fc(fn_code_def)?;
        self.contract_method_ids.insert((contract_id, dapen_fc.name.clone()), fn_id);
        let fn_circuit_def = dapen_fc;

        Ok((fn_id as u64, fn_circuit_def))
    }

    async fn get_contract_method_common_data(&self, contract_id: u64, fn_id: u32) -> anyhow::Result<(QHashOut<C::F>, VerifierOnlyCircuitData<C, D>)> {
        let key = (contract_id, fn_id);
        let circuit = self
            .contract_circuits
            .get(&key)
            .ok_or_else(|| anyhow::format_err!("contract {} method {} is not found", contract_id, fn_id))?;
        tracing::info!("get contract {} method {} common data", contract_id, fn_id);
        Ok((circuit.get_fingerprint(), circuit.get_verifier_config_ref().clone()))
    }

    async fn prove_contract_call(
        &self,
        contract_id: u64,
        fn_id: u32,
        input: &DapenContractFunctionCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let key = (contract_id, fn_id);
        let fn_circuit = self
            .contract_circuits
            .get(&key)
            .ok_or_else(|| anyhow::format_err!("contract {} method {} is not found", contract_id, fn_id))?;
        fn_circuit.prove_base(&input)
    }

    async fn prove_ups_cfc_standard_tx(
        &self,
        input: &UPSCFCStandardTransactionCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.ups_cfc_standard_tx.prove_base(&input)
    }

    async fn prove_ups_cfc_deferred_tx(
        &self,
        input: &UPSCFCDeferredTransactionCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.ups_cfc_deferred_tx.prove_base(&input)
    }

    async fn prove_zk_sign_minifier(&self, inner_proof: ProofWithPublicInputs<C::F, C, D>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.zk_signature_minifier_circuit().prove_minifier(inner_proof)
    }

    async fn zk_signature_minifier_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        Ok(self.zk_signature_minifier_circuit().get_fingerprint())
    }

    async fn zk_signature_minifier_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        Ok(self.zk_signature_minifier_circuit().get_verifier_config_ref().clone())
    }

    async fn prove_private_note_inclusion_minifier(
        &self,
        base_proof: ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.private_note_inclusion_minifier_circuit().prove_minifier(base_proof)
    }

    async fn private_note_inclusion_minifier_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        Ok(self.private_note_inclusion_minifier_circuit().get_fingerprint())
    }

    async fn private_note_inclusion_minifier_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        Ok(self.private_note_inclusion_minifier_circuit().get_verifier_config_ref().clone())
    }

    async fn prove_shield_deposit_claim_minifier(
        &self,
        base_proof: ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.shield_deposit_claim_minifier_circuit().prove_minifier(base_proof)
    }

    async fn shield_deposit_claim_minifier_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        Ok(self.shield_deposit_claim_minifier_circuit().get_fingerprint())
    }

    async fn shield_deposit_claim_minifier_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        Ok(self.shield_deposit_claim_minifier_circuit().get_verifier_config_ref().clone())
    }

    async fn prove_secp_sign(&self, signature: PsyCompressedSecp256K1Signature) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.secp_circuit().prove(&signature)
    }

    async fn prove_eth_personal_secp_sign(
        &self,
        signature: PsyCompressedSecp256K1Signature,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.eth_personal_secp_circuit()
            .prove(&signature)
            .map_err(|error| anyhow::anyhow!("failed to prove EIP-191 secp256k1 signature: {error}"))
    }

    async fn register_dpn_software_defined_circuit(
        &self,
        _fn_def: psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition,
        _contract_id: u64,
        _contract_state_tree_height: u8,
        _session_proof_tree_height: u8,
        _force_four_align: bool,
    ) -> anyhow::Result<QHashOut<C::F>> {
        unimplemented!("register_dpn_software_defined_circuit");
    }

    async fn register_plonky2_software_defined_circuit(&self, _contract_state_tree_height: u8, _input_len: usize) -> anyhow::Result<QHashOut<C::F>> {
        unimplemented!("register_plonky2_software_defined_circuit");
    }

    async fn prove_dpn_software_defined_sign(
        &self,
        _fingerprint: QHashOut<C::F>,
        _private_key: QHashOut<C::F>,
        _input: psy_vm::ups::signature::DPNSoftwareDefinedSignatureInput,
        _sig_hash: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        unimplemented!("prove_dpn_software_defined_sign");
    }

    async fn prove_plonky2_software_defined_sign(
        &self,
        _fingerprint: QHashOut<C::F>,
        _private_key: QHashOut<C::F>,
        _input: psy_vm::ups::signature::Plonky2SoftwareDefinedSignatureInput,
        _sig_hash: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        unimplemented!("prove_plonky2_software_defined_sign");
    }

    async fn prove_ups_end_cap(
        &self,
        circuit_info: &SessionCircuitInfoStore<C::F>,
        end_cap_from_proof_tree_input: &UPSEndCapFromProofTreeGadgetInput<C::F>,
        agg_proof_record: &AggProofRecord<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let agg_whitelist_merkle_proof = self
            .proof_tree_agg_circuits
            .circuit_inclusion_proofs
            .get_inclusion_proof_for_type(agg_proof_record.circuit_type);
        let agg_root_verifier_data = circuit_info
            .get_circuit_info_by_fingerprint(agg_proof_record.fingerprint)?
            .verifier_data
            .to_verifier_data::<C, D>();

        self.ups_end_cap.prove_base(
            &end_cap_from_proof_tree_input,
            agg_whitelist_merkle_proof,
            &agg_proof_record.agg_header,
            &agg_proof_record.proof,
            &agg_root_verifier_data,
        )
    }

    async fn ups_start_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        Ok(self.ups_start.get_fingerprint())
    }

    async fn ups_start_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        Ok(self.ups_start.get_verifier_config_ref().clone().into())
    }
    async fn ups_start_register_user_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        Ok(self.ups_start_register_user.get_fingerprint())
    }

    async fn ups_start_register_user_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        Ok(self.ups_start_register_user.get_verifier_config_ref().clone().into())
    }

    async fn ups_cfc_standard_tx_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        Ok(self.ups_cfc_standard_tx.get_fingerprint())
    }

    async fn ups_cfc_standard_tx_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        Ok(self.ups_cfc_standard_tx.get_verifier_config_ref().clone().into())
    }

    async fn ups_cfc_deferred_tx_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        Ok(self.ups_cfc_deferred_tx.get_fingerprint())
    }

    async fn ups_cfc_deferred_tx_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        Ok(self.ups_cfc_deferred_tx.get_verifier_config_ref().clone().into())
    }

    async fn ups_end_cap_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        Ok(self.ups_end_cap.get_fingerprint())
    }

    async fn ups_end_cap_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        Ok(self.ups_end_cap.get_verifier_config_ref().clone().into())
    }

    async fn ups_circuit_whitelist_root(&self) -> anyhow::Result<QHashOut<C::F>> {
        Ok(self.ups_circuit_whitelist_root)
    }

    async fn secp_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        Ok(self.secp_circuit().get_fingerprint())
    }

    async fn secp_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        Ok(self.secp_circuit().get_verifier_config_ref().clone().into())
    }

    async fn eth_personal_secp_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        Ok(self.eth_personal_secp_circuit().get_fingerprint())
    }


    async fn eth_personal_secp_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        Ok(self.eth_personal_secp_circuit().get_verifier_config_ref().clone().into())
    }
}
#[cfg(test)]
mod eth_personal_tests {
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        plonk::config::PoseidonGoldilocksConfig,
    };
    use psy_client_common::data::qhashout::QHashOut;
    use psy_common_circuit::circuits::traits::qstandard::QStandardCircuit;

    use super::PsyUPSStepCircuitManager;

    #[test]
    fn eth_personal_fingerprint_matches_public_constant() {
        let manager = PsyUPSStepCircuitManager::<PoseidonGoldilocksConfig, 2>::new_with_config(1);
        let expected = psy_prover_fingerprint::<GoldilocksField>();
        assert_eq!(manager.eth_personal_secp_circuit().get_fingerprint(), expected);
    }

    fn psy_prover_fingerprint<F: plonky2::hash::hash_types::RichField>() -> QHashOut<F> {
        QHashOut(plonky2::hash::hash_types::HashOut {
            elements: [
                F::from_canonical_u64(11893467277170771781),
                F::from_canonical_u64(15629858611769664357),
                F::from_canonical_u64(5241938694879225188),
                F::from_canonical_u64(5545361160027968854),
            ],
        })
    }
}

pub fn register_qtree_recursion_circuits<C: GenericConfig<D>, const D: usize>(
    circuit_set: &QStandardBinaryRecursionTreeCircuitSet<C, D>,
    info_store: &mut SessionCircuitInfoStore<C::F>,
) where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>>,
{
    info_store.register_circuit(
        LocalCircuitType::PTAggSingle.into(),
        circuit_set.single_leaf_circuit.get_fingerprint(),
        circuit_set.single_leaf_circuit.get_verifier_config_ref().into(),
    );
    info_store.register_circuit(
        LocalCircuitType::PTAggTwoLeaf.into(),
        circuit_set.two_leaf_circuit.get_fingerprint(),
        circuit_set.two_leaf_circuit.get_verifier_config_ref().into(),
    );
    info_store.register_circuit(
        LocalCircuitType::PTAggTwoAgg.into(),
        circuit_set.two_agg_circuit.get_fingerprint(),
        circuit_set.two_agg_circuit.get_verifier_config_ref().into(),
    );
    info_store.register_circuit(
        LocalCircuitType::PTAggLeftAggRightLeaf.into(),
        circuit_set.left_agg_right_leaf_circuit.get_fingerprint(),
        circuit_set.left_agg_right_leaf_circuit.get_verifier_config_ref().into(),
    );
    info_store.register_circuit(
        LocalCircuitType::PTAggLeftLeafRightAgg.into(),
        circuit_set.left_leaf_right_agg_circuit.get_fingerprint(),
        circuit_set.left_leaf_right_agg_circuit.get_verifier_config_ref().into(),
    );
}
pub fn register_qtree_recursion_circuits_whitelist_proofs<F: RichField>(
    inclusion_proofs: &SimpleQTreeRecursionManagerInclusionProofs<F>,
    info_store: &mut SessionCircuitInfoStore<F>,
) {
    info_store.register_whitelist_merkle_proof(
        LocalCircuitType::PTAggSingle.into(),
        inclusion_proofs.single_leaf_circuit_merkle_proof.clone(),
    );
    info_store.register_whitelist_merkle_proof(
        LocalCircuitType::PTAggTwoLeaf.into(),
        inclusion_proofs.two_leaf_circuit_merkle_proof.clone(),
    );
    info_store.register_whitelist_merkle_proof(
        LocalCircuitType::PTAggTwoAgg.into(),
        inclusion_proofs.two_agg_circuit_merkle_proof.clone(),
    );
    info_store.register_whitelist_merkle_proof(
        LocalCircuitType::PTAggLeftAggRightLeaf.into(),
        inclusion_proofs.left_agg_right_leaf_circuit_merkle_proof.clone(),
    );
    info_store.register_whitelist_merkle_proof(
        LocalCircuitType::PTAggLeftLeafRightAgg.into(),
        inclusion_proofs.left_leaf_right_agg_circuit_merkle_proof.clone(),
    );
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl<C: GenericConfig<D>, const D: usize> PortableQTreeRecursionCircuitsData<C, D> for PsyUPSStepCircuitManager<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    async fn single_leaf_circuit_fingerprint(&self) -> QHashOut<C::F> {
        self.proof_tree_agg_circuits.single_leaf_circuit_fingerprint().await
    }

    async fn two_leaf_circuit_fingerprint(&self) -> QHashOut<C::F> {
        self.proof_tree_agg_circuits.two_leaf_circuit_fingerprint().await
    }

    async fn two_agg_circuit_fingerprint(&self) -> QHashOut<C::F> {
        self.proof_tree_agg_circuits.two_agg_circuit_fingerprint().await
    }

    async fn left_leaf_right_agg_circuit_fingerprint(&self) -> QHashOut<C::F> {
        self.proof_tree_agg_circuits.left_leaf_right_agg_circuit_fingerprint().await
    }

    async fn left_agg_right_leaf_circuit_fingerprint(&self) -> QHashOut<C::F> {
        self.proof_tree_agg_circuits.left_agg_right_leaf_circuit_fingerprint().await
    }

    async fn single_leaf_circuit_verifier_config(&self) -> VerifierOnlyCircuitData<C, D> {
        self.proof_tree_agg_circuits.single_leaf_circuit_verifier_config().await
    }

    async fn two_leaf_circuit_verifier_config(&self) -> VerifierOnlyCircuitData<C, D> {
        self.proof_tree_agg_circuits.two_leaf_circuit_verifier_config().await
    }

    async fn two_agg_circuit_verifier_config(&self) -> VerifierOnlyCircuitData<C, D> {
        self.proof_tree_agg_circuits.two_agg_circuit_verifier_config().await
    }

    async fn left_leaf_right_agg_circuit_verifier_config(&self) -> VerifierOnlyCircuitData<C, D> {
        self.proof_tree_agg_circuits.left_leaf_right_agg_circuit_verifier_config().await
    }

    async fn left_agg_right_leaf_circuit_verifier_config(&self) -> VerifierOnlyCircuitData<C, D> {
        self.proof_tree_agg_circuits.left_agg_right_leaf_circuit_verifier_config().await
    }
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl<C: GenericConfig<D>, const D: usize> PortableQTreeRecursionCircuitsProve<C, D> for PsyUPSStepCircuitManager<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    async fn get_verifier_data_by_type(
        &self,
        circuit_type: psy_crypto::common::witnesses::qrecursion::proof_data::QStandardBinaryTreeCircuitType,
    ) -> VerifierOnlyCircuitData<C, D> {
        self.proof_tree_agg_circuits.get_verifier_data_by_type(circuit_type).await
    }

    async fn prove_single_leaf_circuit(
        &self,
        agg_circuit_whitelist_root: QHashOut<C::F>,
        single_insert_leaf_proof: &psy_crypto::hash::merkle::core::DeltaMerkleProofCore<QHashOut<C::F>>,
        single_proof: &ProofWithPublicInputs<C::F, C, D>,
        single_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.proof_tree_agg_circuits
            .prove_single_leaf_circuit(agg_circuit_whitelist_root, single_insert_leaf_proof, single_proof, single_verifier_data)
            .await
    }

    async fn prove_two_leaf_circuit(
        &self,
        agg_circuit_whitelist_root: QHashOut<C::F>,
        left_insert_leaf_proof: &psy_crypto::hash::merkle::core::DeltaMerkleProofCore<QHashOut<C::F>>,
        left_proof: &ProofWithPublicInputs<C::F, C, D>,
        left_verifier_data: &VerifierOnlyCircuitData<C, D>,
        right_insert_leaf_proof: &psy_crypto::hash::merkle::core::DeltaMerkleProofCore<QHashOut<C::F>>,
        right_proof: &ProofWithPublicInputs<C::F, C, D>,
        right_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.proof_tree_agg_circuits
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
        left_agg_proof_header: &psy_crypto::common::witnesses::qrecursion::header::QRecursionAggStandardHeader<C::F>,
        left_proof: &ProofWithPublicInputs<C::F, C, D>,
        left_verifier_data: &VerifierOnlyCircuitData<C, D>,
        right_agg_whitelist_merkle_proof: &MerkleProofCore<QHashOut<C::F>>,
        right_agg_proof_header: &psy_crypto::common::witnesses::qrecursion::header::QRecursionAggStandardHeader<C::F>,
        right_proof: &ProofWithPublicInputs<C::F, C, D>,
        right_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.proof_tree_agg_circuits
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
        left_insert_leaf_proof: &psy_crypto::hash::merkle::core::DeltaMerkleProofCore<QHashOut<C::F>>,
        left_proof: &ProofWithPublicInputs<C::F, C, D>,
        left_verifier_data: &VerifierOnlyCircuitData<C, D>,
        right_agg_whitelist_merkle_proof: &MerkleProofCore<QHashOut<C::F>>,
        right_agg_proof_header: &psy_crypto::common::witnesses::qrecursion::header::QRecursionAggStandardHeader<C::F>,
        right_proof: &ProofWithPublicInputs<C::F, C, D>,
        right_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.proof_tree_agg_circuits
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
        left_agg_proof_header: &psy_crypto::common::witnesses::qrecursion::header::QRecursionAggStandardHeader<C::F>,
        left_proof: &ProofWithPublicInputs<C::F, C, D>,
        left_verifier_data: &VerifierOnlyCircuitData<C, D>,
        right_insert_leaf_proof: &psy_crypto::hash::merkle::core::DeltaMerkleProofCore<QHashOut<C::F>>,
        right_proof: &ProofWithPublicInputs<C::F, C, D>,
        right_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.proof_tree_agg_circuits
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
impl<C: GenericConfig<D>, const D: usize> PortableQTreeRecursion<C, D> for PsyUPSStepCircuitManager<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    async fn circuit_inclusion_proofs(&self) -> &SimpleQTreeRecursionManagerInclusionProofs<C::F> {
        &self.proof_tree_agg_circuits.circuit_inclusion_proofs
    }
}

pub type QCircuitManager<C, const D: usize> = Box<dyn UPSCircuitManager<C, D>>;
