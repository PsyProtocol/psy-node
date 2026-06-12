use plonky2::{
    gates::{constant::ConstantGate, gate::GateRef},
    hash::hash_types::HashOut,
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::{
    common::witnesses::qrecursion::header::QRecursionAggStandardHeader,
    hash::{
        merkle::core::{DeltaMerkleProofCore, MerkleProofCore},
        traits::hasher::MerkleZeroHasher,
    },
};

use crate::{
    circuits::traits::qstandard::QStandardCircuit,
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    treeprover::qrecursion::standard::gadgets::{
        agg_proof_header::QRecursionAggStandardHeaderGadget, verify_agg_proof::VerifyAggProofGadget, verify_leaf_proof::VerifyLeafProofGadget,
    },
};

#[derive(Debug)]
pub struct QRecursionStandardLeftAggRightLeafCircuit<C: GenericConfig<D>, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub left_agg_gadget: VerifyAggProofGadget<D>,
    pub right_leaf_gadget: VerifyLeafProofGadget<D>,
    pub self_header_gadget: QRecursionAggStandardHeaderGadget,

    // end circuit targets
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
    // end circuit data
}
impl<C: GenericConfig<D>, const D: usize> QRecursionStandardLeftAggRightLeafCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub fn new(
        //coset_gate: &GateRef<C::F, D>,
        q_recursion_tree_height: usize,
        verifier_data_cap_height: usize,
        child_common_data: &CommonCircuitData<C::F, D>,
    ) -> Self {
        Self::new_multi(
            q_recursion_tree_height,
            verifier_data_cap_height,
            child_common_data,
            verifier_data_cap_height,
            child_common_data,
        )
    }
    pub fn new_multi(
        //coset_gate: &GateRef<C::F, D>,
        q_recursion_tree_height: usize,
        leaf_verifier_data_cap_height: usize,
        leaf_child_common_data: &CommonCircuitData<C::F, D>,
        agg_verifier_data_cap_height: usize,
        agg_child_common_data: &CommonCircuitData<C::F, D>,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let left_agg_gadget = VerifyAggProofGadget::<D>::add_virtual_to::<C, C::F>(&mut builder, agg_child_common_data, agg_verifier_data_cap_height);
        let right_leaf_gadget = VerifyLeafProofGadget::<D>::add_virtual_to::<C, C::F>(
            &mut builder,
            q_recursion_tree_height,
            leaf_child_common_data,
            leaf_verifier_data_cap_height,
        );

        // left agg and right leaf insertion should be back to back
        builder.connect_hashes(
            left_agg_gadget.agg_proof_header_gadget.state_transition_end,
            right_leaf_gadget.insert_leaf_proof.old_root,
        );

        // use the agg_circuit_whitelist_root from the left agg proof
        let agg_circuit_whitelist_root = left_agg_gadget.agg_whitelist_merkle_proof.root;

        let self_header_gadget = QRecursionAggStandardHeaderGadget {
            state_transition_start: left_agg_gadget.agg_proof_header_gadget.state_transition_start,
            state_transition_end: right_leaf_gadget.insert_leaf_proof.new_root,
            agg_circuit_whitelist_root,
        };
        let self_public_inputs_hash = self_header_gadget.get_combined_hash::<C::Hasher, C::F, D>(&mut builder);

        builder.register_public_inputs(&self_public_inputs_hash.elements);
        //builder.add_psy_type_a_common_gates(Some(coset_gate.clone()));
        //pad_circuit_degree::<C::F, D>(&mut builder, 12);

        builder.add_gate_to_gate_set(GateRef::new(ConstantGate::new(builder.config.num_constants)));
        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));

        Self {
            left_agg_gadget,
            right_leaf_gadget,
            self_header_gadget,
            circuit_data,
            fingerprint,
        }
    }
    pub fn prove_base(
        &self,
        left_agg_whitelist_merkle_proof: &MerkleProofCore<QHashOut<C::F>>,
        left_agg_proof_header: &QRecursionAggStandardHeader<C::F>,
        left_proof: &ProofWithPublicInputs<C::F, C, D>,
        left_verifier_data: &VerifierOnlyCircuitData<C, D>,

        right_insert_leaf_proof: &DeltaMerkleProofCore<QHashOut<C::F>>,
        right_proof: &ProofWithPublicInputs<C::F, C, D>,
        right_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();

        self.left_agg_gadget.set_witness(
            &mut pw,
            left_agg_whitelist_merkle_proof,
            left_agg_proof_header,
            left_proof,
            left_verifier_data,
        )?;

        self.right_leaf_gadget
            .set_witness(&mut pw, right_insert_leaf_proof, right_proof, right_verifier_data)?;

        self.circuit_data.prove(pw)
    }
}

impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D> for QRecursionStandardLeftAggRightLeafCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        self.fingerprint
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        &self.circuit_data.verifier_only
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        &self.circuit_data.common
    }
}

/*
impl<C: GenericConfig<D>, const D: usize>
    QStandardCircuitProvable<QRecursionStandardLeftAggRightLeafCircuitInput<C::F>, C, D>
    for QRecursionStandardLeftAggRightLeafCircuit<C, D>
where
    C::Hasher:AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_standard(
        &self,
        input: &QRecursionStandardLeftAggRightLeafCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        Ok(self.prove_base(
            input
        ))
    }
}

impl<S: QProofStoreReaderSync, C: GenericConfig<D>, const D: usize>
    QStandardCircuitProvableWithProofStoreSync<S, QRecursionStandardLeftAggRightLeafCircuitInput<C::F>, C, D>
    for QRecursionStandardLeftAggRightLeafCircuit<C, D>
where
    C::Hasher:AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_with_proof_store_sync(
        &self,
        _store: &S,
        input: &QRecursionStandardLeftAggRightLeafCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_standard(input)
    }
}
*/
