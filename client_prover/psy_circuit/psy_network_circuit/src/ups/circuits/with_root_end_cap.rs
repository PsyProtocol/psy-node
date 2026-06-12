use plonky2::{
    hash::hash_types::HashOut,
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_common_circuit::{
    builder::hash::core::CircuitBuilderHashCore,
    circuits::traits::qstandard::QStandardCircuit,
    proof_minifier::{
        pm_chain_dynamic::PsyProofMinifierDynamicChain, pm_core::get_circuit_fingerprint_generic,
    },
    treeprover::qrecursion::standard::gadgets::{verify_agg_proof::VerifyAggProofGadget, verify_agg_root::VerifyAggRootGadget},
};
use psy_client_common::{
    config::network_constants::{UPS_CIRCUIT_WHITELIST_TREE_HEIGHT, UPS_SESSION_PROOF_TREE_HEIGHT},
    data::qhashout::QHashOut,
};
use psy_crypto::{
    common::witnesses::qrecursion::header::QRecursionAggStandardHeader,
    hash::{
        merkle::
            core::MerkleProofCore
        ,
        traits::hasher::MerkleZeroHasher,
    },
};
use psy_client_data::ups::ups_end_cap::UPSEndCapFromProofTreeGadgetInput;

use crate::ups::gadgets::ups_end_cap_tree::UPSEndCapFromProofTreeGadget;

#[derive(Debug)]
pub struct UPSStandardEndCapCircuit<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub end_cap_from_proof_tree_gadget: UPSEndCapFromProofTreeGadget,
    pub verify_proof_tree_root_gadget: VerifyAggRootGadget<D>,

    // end circuit targets
    pub base_circuit_data: CircuitData<C::F, C, D>,
    pub base_fingerprint: QHashOut<C::F>,
    pub minifier_chain: Option<PsyProofMinifierDynamicChain<D, C::F, C>>,
    pub enable_minifier: bool,
    // end circuit data
}

impl<C: GenericConfig<D> + 'static, const D: usize> UPSStandardEndCapCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn is_minifier_enabled(&self) -> bool {
        self.enable_minifier && self.minifier_chain.is_some()
    }
}
impl<C: GenericConfig<D> + 'static, const D: usize> UPSStandardEndCapCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub fn new_with_minifier(
        proof_tree_root_common_data: &CommonCircuitData<C::F, D>,
        proof_tree_root_verifier_data: &VerifierOnlyCircuitData<C,D>,
        network_magic: u64,
        known_ups_circuit_whitelist_root: QHashOut<C::F>,
    ) -> Self {
        Self::new_with_config(
            proof_tree_root_common_data,
            proof_tree_root_verifier_data,
            UPS_SESSION_PROOF_TREE_HEIGHT as usize,
            UPS_CIRCUIT_WHITELIST_TREE_HEIGHT as usize,
            network_magic,
            known_ups_circuit_whitelist_root,
            true,
        )
    }
    pub fn new_without_minifier(
        proof_tree_root_common_data: &CommonCircuitData<C::F, D>,
        proof_tree_root_verifier_data: &VerifierOnlyCircuitData<C,D>,
        network_magic: u64,
        known_ups_circuit_whitelist_root: QHashOut<C::F>,
    ) -> Self {
        Self::new_with_config(
            proof_tree_root_common_data,
            proof_tree_root_verifier_data,
            UPS_SESSION_PROOF_TREE_HEIGHT as usize,
            UPS_CIRCUIT_WHITELIST_TREE_HEIGHT as usize,
            network_magic,
            known_ups_circuit_whitelist_root,
            false,
        )
    }
    pub fn new_with_config(
        proof_tree_root_common_data: &CommonCircuitData<C::F, D>,
        proof_tree_root_verifier_data: &VerifierOnlyCircuitData<C,D>,
        //coset_gate: &GateRef<C::F, D>,
        ups_session_proof_tree_height: usize,
        ups_circuit_whitelist_tree_height: usize,
        network_magic: u64,
        known_ups_circuit_whitelist_root: QHashOut<C::F>,
        has_minifier: bool,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let verify_proof_tree_root_gadget = VerifyAggRootGadget::add_virtual_to::<C, C::F>(
            &mut builder,
            proof_tree_root_common_data,
            proof_tree_root_verifier_data,
        );

        /*let known_proof_tree_circuit_whitelist_root_target =
            builder.constant_qhash(known_proof_tree_circuit_whitelist_root);

        // ensure the proof tree is using the correct, unmodified aggregation circuits
        builder.connect_hashes(
            known_proof_tree_circuit_whitelist_root_target,
            verify_proof_tree_root_gadget
                .agg_whitelist_merkle_proof
                .root,
        );
*/
        let end_cap_from_proof_tree_gadget =
            UPSEndCapFromProofTreeGadget::add_virtual_to::<C::Hasher, C::F, D>(
                &mut builder,
                ups_session_proof_tree_height,
                ups_circuit_whitelist_tree_height,
                network_magic,
            );

        let known_ups_circuit_whitelist_root_target =
            builder.constant_qhash(known_ups_circuit_whitelist_root);

        // ensure the ups steps are using the correct ups circuit whitelist root
        builder.connect_hashes(
            known_ups_circuit_whitelist_root_target,
            end_cap_from_proof_tree_gadget
                .verify_previous_ups_step_gadget
                .ups_step_circuit_whitelist_root,
        );

        // ensure the proof tree proof's root matches the ups gadget's root
        builder.connect_hashes(
            verify_proof_tree_root_gadget
                .proof_tree_root_hash,
            end_cap_from_proof_tree_gadget.current_proof_tree_root,
        );

        let state_transition_pi_hash = end_cap_from_proof_tree_gadget
            .end_cap_core_gadget
            .end_cap_result_gadget
            .to_hash::<C::Hasher, C::F, D>(&mut builder);
        let guta_stats_pi_hash = end_cap_from_proof_tree_gadget
            .end_cap_core_gadget
            .guta_stats
            .to_hash::<C::Hasher, C::F, D>(&mut builder);

        let public_inputs_hash =
            builder.hash_two_to_one::<C::Hasher>(state_transition_pi_hash, guta_stats_pi_hash);

        builder.register_public_inputs(&public_inputs_hash.elements);

        let base_circuit_data = builder.build::<C>();

        let base_fingerprint = QHashOut(get_circuit_fingerprint_generic(
            &base_circuit_data.verifier_only,
        ));

        let minifier_chain = if has_minifier {
            Some(
                PsyProofMinifierDynamicChain::<D, C::F, C>::new_with_dynamic_constant_verifier(
                    &base_circuit_data.verifier_only,
                    &base_circuit_data.common,
                    &[true, true, false],
                ),
            )
        } else {
            None
        };

        Self {
            base_circuit_data,
            base_fingerprint,
            minifier_chain,
            enable_minifier: has_minifier,
            end_cap_from_proof_tree_gadget,
            verify_proof_tree_root_gadget,
        }
    }

    fn prove_base_inner(
        &self,
        end_cap_from_proof_tree_input: &UPSEndCapFromProofTreeGadgetInput<C::F>,
        //agg_whitelist_merkle_proof: &MerkleProofCore<QHashOut<C::F>>,
        //agg_proof_header: &QRecursionAggStandardHeader<C::F>,
        agg_root_proof: &ProofWithPublicInputs<C::F, C, D>,
        //agg_root_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();

        self.end_cap_from_proof_tree_gadget
            .set_witness(&mut pw, end_cap_from_proof_tree_input);
        self.verify_proof_tree_root_gadget.set_witness(
            &mut pw, agg_root_proof
        );

        self.base_circuit_data.prove(pw)
    }
    pub fn prove_base(
        &self,
        end_cap_from_proof_tree_input: &UPSEndCapFromProofTreeGadgetInput<C::F>,
        //agg_whitelist_merkle_proof: &MerkleProofCore<QHashOut<C::F>>,
        //agg_proof_header: &QRecursionAggStandardHeader<C::F>,
        agg_root_proof: &ProofWithPublicInputs<C::F, C, D>,
        //agg_root_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        if self.is_minifier_enabled() {
            let base_proof = self.prove_base_inner(
                end_cap_from_proof_tree_input,
                agg_root_proof,
            )?;
            self.minifier_chain.as_ref().unwrap().prove(&base_proof)
        } else {
            self.prove_base_inner(
                end_cap_from_proof_tree_input,agg_root_proof
            )
        }
    }

    pub fn verify_proof(&self, proof_with_pis: ProofWithPublicInputs<C::F, C, D>,) -> anyhow::Result<()> {
        if self.is_minifier_enabled() {
            self.minifier_chain.as_ref().unwrap().verify(proof_with_pis)
        }else{
            self.base_circuit_data.verify(proof_with_pis)
        }
    }
}
impl<C: GenericConfig<D> + 'static, const D: usize> QStandardCircuit<C, D>
    for UPSStandardEndCapCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        if self.is_minifier_enabled() {
            QHashOut(self.minifier_chain.as_ref().unwrap().get_fingerprint())
        } else {
            self.base_fingerprint
        }
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        if self.is_minifier_enabled() {
            self.minifier_chain.as_ref().unwrap().get_verifier_data()
        } else {
            &self.base_circuit_data.verifier_only
        }
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        if self.is_minifier_enabled() {
            self.minifier_chain.as_ref().unwrap().get_common_data()
        } else {
            &self.base_circuit_data.common
        }
    }
}

/*
impl<C: GenericConfig<D>, const D: usize>
    QStandardCircuitProvable<CFCPlaceholderCircuitInput<C::F>, C, D>
    for CFCPlaceholderCircuit<C, D>
where
    C::Hasher:AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_standard(
        &self,
        input: &CFCPlaceholderCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        Ok(self.prove_base(
            input
        ))
    }
}

impl<S: QProofStoreReaderSync, C: GenericConfig<D>, const D: usize>
    QStandardCircuitProvableWithProofStoreSync<S, CFCPlaceholderCircuitInput<C::F>, C, D>
    for CFCPlaceholderCircuit<C, D>
where
    C::Hasher:AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_with_proof_store_sync(
        &self,
        _store: &S,
        input: &CFCPlaceholderCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_standard(input)
    }
}
*/
