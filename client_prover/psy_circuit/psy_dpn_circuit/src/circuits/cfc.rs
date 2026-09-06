use plonky2::{
    gates::gate::GateRef,
    hash::hash_types::HashOut,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_client_common::{data::qhashout::QHashOut, job::traits::QProofStoreReaderSync};
use psy_common_circuit::{
    builder::{
        hash::core::CircuitBuilderHashCore,
        pad_circuit::{pad_circuit_degree, CircuitBuilderPsyCommonGates},
    },
    circuits::traits::qstandard::{provable::QStandardCircuitProvable, QStandardCircuit, QStandardCircuitProvableWithProofStoreSync},
    proof_minifier::pm_chain::PsyProofMinifierChain,
    u32::gates::comparison::ComparisonGate,
};
use psy_crypto::hash::traits::hasher::MerkleZeroHasher;
use psy_vm::{dpn::vm::def::DPNFunctionCircuitDefinition, vm::cfc_input::DapenContractFunctionCircuitInput};

use crate::vm::compile::PsyContractFunctionBuilderGadget;

#[derive(Debug)]
pub struct DapenContractFunctionCircuit<C: GenericConfig<D>, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub inputs: Vec<Target>,
    pub fn_builder_gadget: PsyContractFunctionBuilderGadget,

    // end circuit targets
    pub circuit_data: CircuitData<C::F, C, D>,
    // pub fingerprint: QHashOut<C::F>,
    pub minifier_chain: PsyProofMinifierChain<D, C::F, C>,

    // end circuit data
    pub fn_def: DPNFunctionCircuitDefinition,
}

impl<C: GenericConfig<D>, const D: usize> Clone for DapenContractFunctionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn clone(&self) -> Self {
        Self::new(
            &self.fn_def,
            self.fn_builder_gadget.state_reader.contract_state_tree_height,
            self.fn_builder_gadget.state_reader.session_proof_tree_height,
            self.fn_builder_gadget.state_reader.force_four_align,
        )
    }
}

impl<C: GenericConfig<D>, const D: usize> DapenContractFunctionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub fn new(
        //coset_gate: &GateRef<C::F, D>,
        fn_def: &DPNFunctionCircuitDefinition,
        contract_state_tree_height: usize,
        session_proof_tree_height: usize,
        force_four_align: bool,
    ) -> Self {
        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        let inputs = builder.add_virtual_targets(fn_def.circuit_inputs.len());
        let fn_builder_gadget = PsyContractFunctionBuilderGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            fn_def,
            contract_state_tree_height,
            session_proof_tree_height,
            inputs.clone(),
            force_four_align,
            None,
        );

        let inner_public_inputs_hash = fn_builder_gadget.tx_ctx_header.to_hash::<C::Hasher, C::F, D>(&mut builder);
        let public_inputs_hash = builder.hash_two_to_one::<C::Hasher>(fn_builder_gadget.session_proof_tree_root, inner_public_inputs_hash);

        builder.register_public_inputs(&public_inputs_hash.elements);
        //builder.add_psy_type_a_common_gates(Some(coset_gate.clone()));
        builder.add_psy_type_b_common_gates();
        pad_circuit_degree::<C::F, D>(&mut builder, 11);

        let circuit_data = builder.build::<C>();

        // let fingerprint =
        // QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));

        let added_gates_for_minifier = [GateRef::new(ComparisonGate::new(32, 16))];

        let minifier_chain =
            PsyProofMinifierChain::<D, C::F, C>::new_add_gates(&circuit_data.verifier_only, &circuit_data.common, 2, Some(&added_gates_for_minifier));

        Self {
            inputs,
            fn_builder_gadget,
            circuit_data,
            // fingerprint,
            fn_def: fn_def.clone(),
            minifier_chain,
        }
    }
    pub fn prove_base(&self, cfc_input: &DapenContractFunctionCircuitInput<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();

        pw.set_target_arr(&self.inputs, &cfc_input.inputs)?;

        pw.set_hash_target(self.fn_builder_gadget.session_proof_tree_root, cfc_input.session_proof_tree_root.0)?;

        self.fn_builder_gadget.tx_ctx_header.set_witness(&mut pw, &cfc_input.tx_input_ctx)?;
        self.fn_builder_gadget.state_reader.set_witness(&mut pw, cfc_input, &self.fn_def)?;

        let base_proof = self.circuit_data.prove(pw)?;
        let minified_proof = self.minifier_chain.prove(&base_proof)?;
        Ok(minified_proof)
    }
}

impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D> for DapenContractFunctionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        QHashOut(self.minifier_chain.get_fingerprint())
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        self.minifier_chain.get_verifier_data()
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        self.minifier_chain.get_common_data()
    }
}
impl<C: GenericConfig<D>, const D: usize> QStandardCircuitProvable<DapenContractFunctionCircuitInput<C::F>, C, D>
    for DapenContractFunctionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_standard(&self, input: &DapenContractFunctionCircuitInput<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_base(input)
    }
}

impl<S: QProofStoreReaderSync, C: GenericConfig<D>, const D: usize>
    QStandardCircuitProvableWithProofStoreSync<S, DapenContractFunctionCircuitInput<C::F>, C, D> for DapenContractFunctionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_with_proof_store_sync(
        &self,
        _store: &S,
        input: &DapenContractFunctionCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_standard(input)
    }
}

#[cfg(test)]
mod ucon_leaf_prove_tests {
    use super::*;
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        field::types::Field,
        hash::poseidon::PoseidonHash,
        plonk::config::PoseidonGoldilocksConfig,
    };
    use psy_client_common::data::qhashout::QHashOut;
    use psy_client_data::dpn::{
        cfc_context_input::{
            DapenCFCProvingSessionStartContext, DapenCFCUserTransactionCallStartContext, DapenCFCUserTransactionEndContext,
            DapenCFCUserTransactionInputContext,
        },
        proving_session::DPNProvingSessionCompactMethodCall,
    };
    use psy_client_data::qdata::{
        checkpoint::{PsyCheckpointGlobalStateRoots, PsyCheckpointLeaf},
        user::PsyUserLeaf,
    };
    use psy_config::network_constants::{DEFERRED_TRANSACTION_TREE_HEIGHT, GLOBAL_CONTRACT_TREE_HEIGHT, UPS_SESSION_PROOF_TREE_HEIGHT};
    use psy_crypto::hash::{
        merkle::core::MerkleProofCore,
        traits::hasher::{FieldQHasher, MerkleZeroHasher},
        traits::qhashable::QFieldHashable,
        utils::safe_hash_fixed_length,
    };

    const D: usize = 2;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    type Hasher = <C as GenericConfig<D>>::Hasher;

    const CONTRACT_STATE_TREE_HEIGHT: usize = 31;
    const UCON_LEAF_INDEX: u64 = 5;

    /// UCON proof for an untouched leaf in an otherwise empty user contract tree:
    /// every sibling is the level's zero hash, so the root folds from `value` alone.
    fn ucon_proof(value: QHashOut<F>) -> MerkleProofCore<QHashOut<F>> {
        let siblings: Vec<QHashOut<F>> = (0..GLOBAL_CONTRACT_TREE_HEIGHT as usize).map(|i| PoseidonHash::get_zero_hash(i)).collect();
        MerkleProofCore::new_from_params::<PoseidonHash>(UCON_LEAF_INDEX, value, siblings)
    }

    /// Full fn_circuit input for a first-ever call on contract 5 with no state commands.
    /// `start_contract_state_root` mirrors get_call_start_data: the empty-tree root of the
    /// contract's height when the UCON leaf is still ZERO (proving_session.rs ZERO branch).
    fn prove_input(uct_leaf_value: QHashOut<F>, start_contract_state_root: QHashOut<F>) -> DapenContractFunctionCircuitInput<F> {
        let state_roots = PsyCheckpointGlobalStateRoots::default();
        let mut checkpoint_leaf = PsyCheckpointLeaf::default();
        checkpoint_leaf.global_chain_root = state_roots.qfhash::<PoseidonHash>();
        let empty_data_hash = safe_hash_fixed_length::<PoseidonHash, F>(&[]);
        let empty_debt_root = PoseidonHash::get_zero_hash(DEFERRED_TRANSACTION_TREE_HEIGHT as usize);

        DapenContractFunctionCircuitInput {
            inputs: vec![],
            outputs: vec![],
            events: vec![],
            cmd_witnesses: vec![],
            session_proof_tree_root: QHashOut::ZERO,
            current_contract_proof: ucon_proof(uct_leaf_value),
            tx_input_ctx: DapenCFCUserTransactionInputContext {
                proving_session_start_ctx: DapenCFCProvingSessionStartContext {
                    checkpoint_id: F::ZERO,
                    checkpoint_tree_root: QHashOut::ZERO,
                    checkpoint_leaf,
                    state_roots,
                    start_session_user_leaf: PsyUserLeaf::default(),
                },
                transaction_call_start_ctx: DapenCFCUserTransactionCallStartContext {
                    start_user_contract_tree_root: ucon_proof(uct_leaf_value).root,
                    start_contract_state_tree_root: start_contract_state_root,
                    call_data: DPNProvingSessionCompactMethodCall {
                        caller_contract_id: F::ZERO,
                        contract_id: F::from_canonical_u64(UCON_LEAF_INDEX),
                        method_id: F::from_canonical_u64(3375543263),
                        inputs_length: F::ZERO,
                        inputs_hash: empty_data_hash,
                    },
                    start_deferred_tx_debt_tree_root: empty_debt_root,
                    start_user_balance: F::ZERO,
                    start_user_event_index: F::ZERO,
                },
                transaction_end_ctx: DapenCFCUserTransactionEndContext {
                    end_contract_state_tree_root: start_contract_state_root,
                    end_deferred_tx_debt_tree_root: empty_debt_root,
                    outputs_hash: empty_data_hash,
                    outputs_length: F::ZERO,
                    total_events_emitted: F::ZERO,
                    total_balance_spent: F::ZERO,
                },
            },
        }
    }

    fn empty_fn_def() -> DPNFunctionCircuitDefinition {
        DPNFunctionCircuitDefinition {
            name: "ucon_leaf_probe".to_string(),
            method_id: 3375543263,
            circuit_inputs: Vec::new(),
            circuit_outputs: Vec::new(),
            state_commands: Vec::new(),
            state_command_resolution_indices: Vec::new(),
            assertions: Vec::new(),
            definitions: Vec::new(),
            events: Vec::new(),
        }
    }

    #[test]
    fn uninitialized_ucon_leaf_fn_circuit_proves() {
        let fn_def = empty_fn_def();
        let circuit = DapenContractFunctionCircuit::<C, D>::new(&fn_def, CONTRACT_STATE_TREE_HEIGHT, UPS_SESSION_PROOF_TREE_HEIGHT as usize, false);
        let start_root = PoseidonHash::get_zero_hash(CONTRACT_STATE_TREE_HEIGHT);
        // UCON leaf ZERO (never-initialized contract): the start root is the default
        // empty-tree root, exactly the combination that failed with "set twice" before
        // the is-zero switch (zero_hash(31)[0] == 8603459983426387388).
        let input = prove_input(QHashOut::ZERO, start_root);
        circuit.prove_base(&input).expect("empty-UCON-leaf fn_circuit must prove");
    }

    #[test]
    fn initialized_ucon_leaf_fn_circuit_proves() {
        let fn_def = empty_fn_def();
        let circuit = DapenContractFunctionCircuit::<C, D>::new(&fn_def, CONTRACT_STATE_TREE_HEIGHT, UPS_SESSION_PROOF_TREE_HEIGHT as usize, false);
        let start_root = PoseidonHash::get_zero_hash(CONTRACT_STATE_TREE_HEIGHT);
        // Initialized contract: the UCON leaf value IS the start contract state root.
        let input = prove_input(start_root, start_root);
        circuit.prove_base(&input).expect("initialized-UCON-leaf fn_circuit must prove");
    }

}
