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
    GLOBAL_CONTRACT_TREE_HEIGHT, GLOBAL_USER_TREE_HEIGHT, PRIVATE_NOTE_TREE_HEIGHT, TOKEN_CONTRACT_STATE_TREE_HEIGHT,
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
use quick_cache::{
    sync::{Cache, DefaultLifecycle},
    DefaultHashBuilder, OptionsBuilder, Weighter,
};
use serde::Serialize;

/// Upper bound on registered contract functions whose verifier data is kept.
const CONTRACT_FUNCTION_INFO_CAPACITY: usize = 10_000;
/// Default memory budget for cached contract prover circuits. One circuit is
/// ~0.11 GiB for an ordinary token method and 1.1-2.1 GiB for bridge methods.
/// Natively the budget holds the prove proxy's working set: on arc99x3 the 20
/// most requested functions (three bridge methods among them) total ~6.5 GiB,
/// and all 68 functions requested over five days ~11.9 GiB.
#[cfg(not(target_arch = "wasm32"))]
const DEFAULT_CONTRACT_PROVER_CACHE_BYTES: u64 = 10 << 30;
/// In the browser nothing is evicted by default, which keeps the wallet's
/// behaviour as it was until a budget has been measured there; a wallet sets
/// one per prover instance with `set_contract_prover_cache_bytes`.
#[cfg(target_arch = "wasm32")]
const DEFAULT_CONTRACT_PROVER_CACHE_BYTES: u64 = u64::MAX / 4;
/// Overrides the prover-circuit budget in bytes (native builds only). A budget
/// smaller than a circuit means that circuit is rebuilt on every proof; 0
/// disables the prover-circuit cache.
#[cfg(not(target_arch = "wasm32"))]
const CONTRACT_PROVER_CACHE_BYTES_ENV: &str = "PSY_CONTRACT_PROVER_CACHE_BYTES";

fn contract_prover_cache_bytes() -> u64 {
    #[cfg(not(target_arch = "wasm32"))]
    if let Some(bytes) = std::env::var(CONTRACT_PROVER_CACHE_BYTES_ENV).ok().and_then(|value| value.parse::<u64>().ok()) {
        return bytes;
    }
    DEFAULT_CONTRACT_PROVER_CACHE_BYTES
}

/// What a registered contract function needs to stay answerable without its
/// prover data: the verifier-side facts clients ask for, and the inputs that
/// rebuild the prover circuit on demand.
#[derive(Debug)]
pub struct ContractFunctionCircuitInfo<C: GenericConfig<D>, const D: usize> {
    pub fn_def: DPNFunctionCircuitDefinition,
    pub state_tree_height: usize,
    pub fingerprint: QHashOut<C::F>,
    pub verifier_only: VerifierOnlyCircuitData<C, D>,
}

/// A cached prover circuit with its weight computed once at insertion.
#[derive(Debug)]
pub struct ContractProverCircuit<C: GenericConfig<D>, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    circuit: Arc<DapenContractFunctionCircuit<C, D>>,
    estimated_bytes: u64,
}

impl<C: GenericConfig<D>, const D: usize> Clone for ContractProverCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn clone(&self) -> Self {
        Self {
            circuit: self.circuit.clone(),
            estimated_bytes: self.estimated_bytes,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ContractProverCircuitWeighter;

type ContractProverCircuitCache<C, const D: usize> = Cache<(u64, u32), ContractProverCircuit<C, D>, ContractProverCircuitWeighter>;

fn new_contract_prover_circuit_cache<C: GenericConfig<D>, const D: usize>() -> ContractProverCircuitCache<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    // One shard: quick_cache splits the byte budget evenly across shards and
    // drops any item heavier than one shard's share, which would silently keep
    // a ~2 GiB bridge circuit out of a budget only twice its size.
    let options = OptionsBuilder::new()
        .estimated_items_capacity(64)
        .weight_capacity(contract_prover_cache_bytes())
        .shards(1)
        .build()
        .expect("contract prover cache options set every required field");
    Cache::with_options(options, ContractProverCircuitWeighter, DefaultHashBuilder::default(), DefaultLifecycle::default())
}

impl<C: GenericConfig<D>, const D: usize> Weighter<(u64, u32), ContractProverCircuit<C, D>> for ContractProverCircuitWeighter
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn weight(&self, _key: &(u64, u32), value: &ContractProverCircuit<C, D>) -> u64 {
        // Zero-weight entries would never be evicted.
        value.estimated_bytes.max(1)
    }
}

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

    // Verifier data of every registered contract function, by (contract_id, fn_id).
    contract_function_infos: Cache<(u64, u32), Arc<ContractFunctionCircuitInfo<C, D>>>,
    // Full prover circuits, bounded by estimated bytes and rebuilt from the
    // function info when evicted. Keeping every compiled circuit (~0.11-2 GiB
    // each) is what grew the user prove proxy past 20 GiB.
    contract_circuits: ContractProverCircuitCache<C, D>,
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
            contract_function_infos: Cache::new(CONTRACT_FUNCTION_INFO_CAPACITY),
            contract_circuits: new_contract_prover_circuit_cache(),
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
                TOKEN_CONTRACT_STATE_TREE_HEIGHT as usize,
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
        let func = contract_code
            .functions
            .get(fn_id as usize)
            .ok_or_else(|| anyhow::anyhow!("contract {} method {} is not found", contract_id, fn_id))?;
        let dapen_fc = cfc_code_definition_to_dapen_fc(func)?;
        let fn_name = dapen_fc.name.clone();
        let state_tree_height = contract_code.state_tree_height as usize;

        let key = (contract_id, fn_id);

        // Fast-path: already registered and still valid (function definition and
        // state tree height are the inputs that determine the compiled circuit).
        if let Some(info) = self.contract_function_infos.get(&key) {
            if info.fn_def == dapen_fc && info.state_tree_height == state_tree_height {
                return Ok(());
            }
            // Stale: function definition or state tree height changed.
            self.contract_function_infos.remove(&key);
            self.contract_circuits.remove(&key);
        }

        let circuit = self.contract_prover_circuit(key, &dapen_fc, state_tree_height);
        let (cached_bytes, budget_bytes, cached_circuits) = self.contract_prover_cache_usage();
        tracing::info!(
            "register contract {} function {} estimated prover bytes {}; prover cache {} of {} bytes in {} circuits",
            contract_id,
            fn_name,
            circuit.estimated_prover_bytes(),
            cached_bytes,
            budget_bytes,
            cached_circuits
        );
        self.contract_function_infos.insert(
            key,
            Arc::new(ContractFunctionCircuitInfo {
                fn_def: dapen_fc,
                state_tree_height,
                fingerprint: circuit.get_fingerprint(),
                verifier_only: circuit.get_verifier_config_ref().clone(),
            }),
        );

        self.contract_method_ids.insert((contract_id, fn_name), fn_id);
        Ok(())
    }

    /// Returns a prover circuit compiled from exactly these inputs, from the
    /// cache when possible. Only one thread compiles per key; concurrent callers
    /// wait on the same entry.
    fn contract_prover_circuit(
        &self,
        key: (u64, u32),
        fn_def: &DPNFunctionCircuitDefinition,
        state_tree_height: usize,
    ) -> Arc<DapenContractFunctionCircuit<C, D>> {
        let compile = || {
            Arc::new(DapenContractFunctionCircuit::<C, D>::new(
                fn_def,
                state_tree_height,
                UPS_SESSION_PROOF_TREE_HEIGHT as usize,
                false,
            ))
        };
        let compiled_from_inputs = |circuit: &DapenContractFunctionCircuit<C, D>| {
            circuit.fn_def == *fn_def && circuit.fn_builder_gadget.state_reader.contract_state_tree_height == state_tree_height
        };
        for _ in 0..3 {
            if let Some(cached) = self.contract_circuits.get(&key) {
                if compiled_from_inputs(&cached.circuit) {
                    return cached.circuit;
                }
                self.contract_circuits.remove(&key);
            }
            let entry = match self.contract_circuits.get_or_insert_with(&key, || {
                let circuit = compile();
                let estimated_bytes = circuit.estimated_prover_bytes();
                Ok::<_, std::convert::Infallible>(ContractProverCircuit { circuit, estimated_bytes })
            }) {
                Ok(entry) => entry,
                Err(never) => match never {},
            };
            // A concurrent caller holding a different definition of the same
            // function may have filled this key; get_or_insert_with hands back
            // whatever it inserted, so check before trusting it.
            if compiled_from_inputs(&entry.circuit) {
                return entry.circuit;
            }
        }
        // Still contended by another definition: compile privately, uncached.
        compile()
    }

    /// Changes the memory budget of the prover-circuit cache; circuits over the
    /// new budget are evicted and rebuilt on their next proof.
    pub fn set_contract_prover_cache_bytes(&self, bytes: u64) {
        self.contract_circuits.set_capacity(bytes);
    }

    /// Estimated bytes held, byte budget and entry count of the prover-circuit cache.
    pub fn contract_prover_cache_usage(&self) -> (u64, u64, usize) {
        (self.contract_circuits.weight(), self.contract_circuits.capacity(), self.contract_circuits.len())
    }

    /// Verifier data of a registered contract function, if registered.
    pub fn contract_function_info(&self, contract_id: u64, fn_id: u32) -> Option<Arc<ContractFunctionCircuitInfo<C, D>>> {
        self.contract_function_infos.get(&(contract_id, fn_id))
    }

    /// Prover circuit of a registered contract function, rebuilt from its
    /// registration if it was evicted from the prover-circuit cache. Compiling
    /// can take seconds; call it from a blocking context.
    pub fn contract_function_circuit(&self, contract_id: u64, fn_id: u32) -> anyhow::Result<Arc<DapenContractFunctionCircuit<C, D>>> {
        let info = self
            .contract_function_info(contract_id, fn_id)
            .ok_or_else(|| anyhow::format_err!("contract {} method {} is not found", contract_id, fn_id))?;
        Ok(self.contract_prover_circuit((contract_id, fn_id), &info.fn_def, info.state_tree_height))
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
        let info = self
            .contract_function_info(contract_id, fn_id)
            .ok_or_else(|| anyhow::format_err!("contract {} method {} is not found", contract_id, fn_id))?;
        tracing::info!("get contract {} method {} common data", contract_id, fn_id);
        Ok((info.fingerprint, info.verifier_only.clone()))
    }

    async fn prove_contract_call(
        &self,
        contract_id: u64,
        fn_id: u32,
        input: &DapenContractFunctionCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let fn_circuit = self.contract_function_circuit(contract_id, fn_id)?;
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
#[cfg(all(test, not(target_arch = "wasm32")))]
mod contract_cache_tests {
    use super::*;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;

    // No production witness or private transaction data is needed for cache
    // identity tests. Full proof replay remains a separate deployment gate.
    fn definition() -> DPNFunctionCircuitDefinition {
        DPNFunctionCircuitDefinition {
            name: "cache_identity".into(),
            method_id: 1,
            circuit_inputs: vec![],
            circuit_outputs: vec![],
            state_commands: vec![],
            state_command_resolution_indices: vec![],
            assertions: vec![],
            definitions: vec![],
            events: vec![],
        }
    }

    #[test]
    fn contract_cache_rebuild_preserves_identity_and_coalesces_misses() {
        let manager = PsyUPSStepCircuitManager::<PoseidonGoldilocksConfig, 2>::new_with_config(1);
        manager.set_contract_prover_cache_bytes(1 << 30);
        let key = (42, 1);
        let def = definition();
        let first = manager.contract_prover_circuit(key, &def, 4);
        assert!(first.estimated_prover_bytes() > 0);
        assert!(Arc::ptr_eq(&first, &manager.contract_prover_circuit(key, &def, 4)));
        let fingerprint = first.get_fingerprint();
        let verifier = serde_json::to_value(first.get_verifier_config_ref()).unwrap();
        manager.contract_function_infos.insert(key, Arc::new(ContractFunctionCircuitInfo {
            fn_def: def.clone(),
            state_tree_height: 4,
            fingerprint,
            verifier_only: first.get_verifier_config_ref().clone(),
        }));

        manager.set_contract_prover_cache_bytes(0);
        assert_eq!(manager.contract_prover_cache_usage(), (0, 0, 0));
        assert!(manager.contract_function_info(key.0, key.1).is_some());
        let rebuilt = manager.contract_function_circuit(key.0, key.1).unwrap();
        assert!(!Arc::ptr_eq(&first, &rebuilt));
        assert_eq!(rebuilt.get_fingerprint(), fingerprint);
        assert_eq!(serde_json::to_value(rebuilt.get_verifier_config_ref()).unwrap(), verifier);
        assert_eq!(manager.contract_prover_cache_usage(), (0, 0, 0));
        assert!(manager.contract_function_circuit(999, 1).is_err());

        manager.set_contract_prover_cache_bytes(1 << 30);
        let barrier = std::sync::Barrier::new(4);
        let circuits = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..4).map(|_| scope.spawn(|| {
                barrier.wait();
                manager.contract_function_circuit(key.0, key.1).unwrap()
            })).collect();
            handles.into_iter().map(|handle| handle.join().unwrap()).collect::<Vec<_>>()
        });
        for circuit in &circuits {
            assert!(Arc::ptr_eq(&circuits[0], circuit));
            assert_eq!(circuit.get_fingerprint(), fingerprint);
        }

        let changed = manager.contract_prover_circuit(key, &def, 5);
        assert_eq!(changed.fn_builder_gadget.state_reader.contract_state_tree_height, 5);
        assert!(!Arc::ptr_eq(&circuits[0], &changed));
        // A cached different definition must not poison the registered inputs.
        let restored = manager.contract_function_circuit(key.0, key.1).unwrap();
        assert_eq!(restored.get_fingerprint(), fingerprint);
        assert_eq!(serde_json::to_value(restored.get_verifier_config_ref()).unwrap(), verifier);
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
