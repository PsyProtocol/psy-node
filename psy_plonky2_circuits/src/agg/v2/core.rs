use parth_core::{crypto::hash::{tag_tree::hash_tag_tree_node, traits::{FieldQHasher, MerkleHasher}}, felt::QFelt64, pgoldilocks::{QGenericConfig, QHashOut}, protocol::core_types::{Q256BitHash, QFHashBase}};
use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOutTarget, RichField},
        poseidon::PoseidonHash,
    },
    iop::{target::Target, witness::{PartialWitness, Witness, WitnessWrite}},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget,
            VerifierOnlyCircuitData,
        },
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::{agg::{AggStateTransitionInput, AggStateTransitionInputV2, AggStateWitnessV2}, worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse};
use psy_plonky2_basic_helpers::{builder::{hash::core::CircuitBuilderHashCore, pad_circuit::{pad_circuit_degree, CircuitBuilderQEDCommonGates}, verify::CircuitBuilderVerifyProofHelpers}, verifier::circuit_library::CircuitInfoLibrary};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::{agg::{ common::compute_agg_state_trackable_final_public_inputs}, proof_minifier::pm_core::get_circuit_fingerprint_generic, qstandard::{QStandardCircuit, QStandardCircuitProvableWithRawProofsAndRefLibrary}, utils::proof_serialization::deserialize_plonky2_proof};

#[derive(Debug, Clone)]
pub struct AggStateTrackableCircuitHeaderGadget {
    pub left_state_transition_start: HashOutTarget,
    pub left_state_transition_end: HashOutTarget,
    pub right_state_transition_start: HashOutTarget,
    pub right_state_transition_end: HashOutTarget,
    pub leaf_fingerprint: HashOutTarget,
    pub agg_fingerprint: HashOutTarget,

    // end inputs
    // start outputs
    pub expected_left_child_transition_hash: HashOutTarget,
    pub expected_right_child_transition_hash: HashOutTarget,
    pub allowed_circuit_hashes_root: HashOutTarget,
    pub state_transition_hash: HashOutTarget,
}
impl AggStateTrackableCircuitHeaderGadget {
    pub fn add_virtual_to<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let left_state_transition_start = builder.add_virtual_hash();
        let left_state_transition_end = builder.add_virtual_hash();
        let right_state_transition_start = builder.add_virtual_hash();
        let right_state_transition_end = builder.add_virtual_hash();
        let leaf_fingerprint = builder.add_virtual_hash();
        let agg_fingerprint = builder.add_virtual_hash();

        let allowed_circuit_hashes_root =
            builder.hash_two_to_one::<H>(leaf_fingerprint, agg_fingerprint);

        let expected_left_child_transition_hash =
            builder.hash_two_to_one::<H>(left_state_transition_start, left_state_transition_end);

        let expected_right_child_transition_hash =
            builder.hash_two_to_one::<H>(right_state_transition_start, right_state_transition_end);

        let state_transition_hash =
            builder.hash_two_to_one::<H>(left_state_transition_start, right_state_transition_end);

        // start constraints
        builder.connect_hashes(left_state_transition_end, right_state_transition_start);
        // end constraints

        Self {
            left_state_transition_start,
            left_state_transition_end,
            right_state_transition_start,
            right_state_transition_end,
            leaf_fingerprint,
            agg_fingerprint,

            expected_left_child_transition_hash,
            expected_right_child_transition_hash,
            allowed_circuit_hashes_root,
            state_transition_hash,
        }
    }
    pub fn set_witness<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        input: &AggStateTransitionInput<QHashOut<F>>,
        agg_fingerprint: QHashOut<F>,
        leaf_fingerprint: QHashOut<F>,
    ) -> anyhow::Result<()> {
        //tracing::info!("set_witness: {}", serde_json::to_string(input).unwrap());
        witness.set_hash_target(self.agg_fingerprint, agg_fingerprint.0)?;
        witness.set_hash_target(self.leaf_fingerprint, leaf_fingerprint.0)?;

        witness.set_hash_target(
            self.left_state_transition_start,
            input.left_input.state_transition_start.0,
        )?;
        witness.set_hash_target(
            self.left_state_transition_end,
            input.left_input.state_transition_end.0,
        )?;
        witness.set_hash_target(
            self.right_state_transition_start,
            input.right_input.state_transition_start.0,
        )?;
        witness.set_hash_target(
            self.right_state_transition_end,
            input.right_input.state_transition_end.0,
        )
    }
}

#[derive(Debug, Clone)]
pub struct AggStateTrackableCircuitHeaderGadgetV2 {
    pub state_transition: AggStateTrackableCircuitHeaderGadget,
    pub left_proving_rewards_tag_value: HashOutTarget,
    pub right_proving_rewards_tag_value: HashOutTarget,
    pub worker_reward_tag: HashOutTarget,

    pub left_proofs_generated_total: Target,
    pub right_proofs_generated_total: Target,

    // end inputs
    // start outputs
    pub expected_left_public_inputs_hash: HashOutTarget,
    pub expected_right_public_inputs_hash: HashOutTarget,
    pub new_public_inputs_hash: HashOutTarget,
}
impl AggStateTrackableCircuitHeaderGadgetV2 {
    pub fn add_virtual_to<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let state_transition_gadget = AggStateTrackableCircuitHeaderGadget::add_virtual_to::<H, F, D>(builder);

        let left_proofs_generated_total = builder.add_virtual_target();
        let right_proofs_generated_total = builder.add_virtual_target();
        let left_proving_rewards_tag_value = builder.add_virtual_hash();
        let right_proving_rewards_tag_value = builder.add_virtual_hash();
        let worker_reward_tag = builder.add_virtual_hash();

        let expected_left_public_inputs_hash = compute_agg_state_trackable_final_public_inputs::<H, F, D>(
            builder,
            state_transition_gadget.allowed_circuit_hashes_root,
            state_transition_gadget.expected_left_child_transition_hash,
            left_proving_rewards_tag_value,
            left_proofs_generated_total,
        );

        let expected_right_public_inputs_hash = compute_agg_state_trackable_final_public_inputs::<H, F, D>(
            builder,
            state_transition_gadget.allowed_circuit_hashes_root,
            state_transition_gadget.expected_right_child_transition_hash,
            right_proving_rewards_tag_value,
            right_proofs_generated_total,
        );

        let rewards_tree_value_combo = builder.hash_two_to_one::<H>(
            left_proving_rewards_tag_value,
            right_proving_rewards_tag_value,
        );
        let rewards_tree_final_new_value = builder.hash_two_to_one::<H>(
            rewards_tree_value_combo,
            worker_reward_tag,
        );

        let child_total_proofs = builder.add(left_proofs_generated_total, right_proofs_generated_total);
        let one = builder.one();
        let new_total_proofs = builder.add(child_total_proofs, one);

        let new_public_inputs_hash = compute_agg_state_trackable_final_public_inputs::<H, F, D>(
            builder,
            state_transition_gadget.allowed_circuit_hashes_root,
            state_transition_gadget.state_transition_hash,
            rewards_tree_final_new_value,
            new_total_proofs,
        );

        Self {
            state_transition: state_transition_gadget,
            left_proving_rewards_tag_value,
            right_proving_rewards_tag_value,
            worker_reward_tag,
            left_proofs_generated_total,
            right_proofs_generated_total,
            expected_left_public_inputs_hash,
            expected_right_public_inputs_hash,
            new_public_inputs_hash,
        }
    }
    pub fn set_witness<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        agg_fingerprint: QHashOut<F>,
        leaf_fingerprint: QHashOut<F>,
        input: &AggStateTransitionInputV2<QHashOut<F>>,
        left_proving_rewards_tag_value: QHashOut<F>,
        right_proving_rewards_tag_value: QHashOut<F>,
        worker_reward_tag: QHashOut<F>,
    ) -> anyhow::Result<()> {

        let left_proofs_generated_total_f = F::from_noncanonical_u64(input.left_input.total_proofs_generated);
        let right_proofs_generated_total_f = F::from_noncanonical_u64(input.right_input.total_proofs_generated);
        //tracing::info!("set_witness: {}", serde_json::to_string(input).unwrap());
        self.state_transition.set_witness(witness, &input.to_v1_input(), agg_fingerprint, leaf_fingerprint)?;

        witness.set_hash_target(self.left_proving_rewards_tag_value, left_proving_rewards_tag_value.0)?;
        witness.set_hash_target(self.right_proving_rewards_tag_value, right_proving_rewards_tag_value.0)?;
        witness.set_hash_target(self.worker_reward_tag, worker_reward_tag.0)?;
        witness.set_target(self.left_proofs_generated_total, left_proofs_generated_total_f)?;
        witness.set_target(self.right_proofs_generated_total, right_proofs_generated_total_f)
    }
}

#[derive(Debug)]
pub struct AggStateTransitionCircuitV2<C: GenericConfig<D>, const D: usize> {
    pub header_gadget: AggStateTrackableCircuitHeaderGadgetV2,

    pub left_proof: ProofWithPublicInputsTarget<D>,
    pub left_verifier_data: VerifierCircuitTarget,

    pub right_proof: ProofWithPublicInputsTarget<D>,
    pub right_verifier_data: VerifierCircuitTarget,

    // end circuit targets
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}
impl<C: GenericConfig<D>, const D: usize> Clone for AggStateTransitionCircuitV2<C, D>
where
    C::Hasher:AlgebraicHasher<C::F>,
{
    fn clone(&self) -> Self {
        Self::new(
            &self.circuit_data.common,
            self.circuit_data
                .verifier_only
                .constants_sigmas_cap
                .height(),
        )
    }
}
impl<C: GenericConfig<D>, const D: usize> AggStateTransitionCircuitV2<C, D>
where
    C::Hasher:AlgebraicHasher<C::F>,
{

    pub fn new(child_common_data: &CommonCircuitData<C::F, D>, verifier_cap_height: usize) -> Self {
        Self::new_base(child_common_data, verifier_cap_height)
    }
    pub fn new_base(
        child_common_data: &CommonCircuitData<C::F, D>,
        verifier_cap_height: usize,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let header_gadget =
            AggStateTrackableCircuitHeaderGadgetV2::add_virtual_to::<PoseidonHash, C::F, D>(
                &mut builder,
            );


        let left_proof = builder.add_virtual_proof_with_pis(child_common_data);
        let left_verifier_data = builder.add_virtual_verifier_data(verifier_cap_height);

        let right_proof = builder.add_virtual_proof_with_pis(child_common_data);
        let right_verifier_data = builder.add_virtual_verifier_data(verifier_cap_height);

        builder.verify_proof_with_fingerprint_enum::<C>(
            &left_proof,
            &left_verifier_data,
            child_common_data,
            &[
                header_gadget.state_transition.agg_fingerprint,
                header_gadget.state_transition.leaf_fingerprint,
            ],
        );
        builder.verify_proof_with_fingerprint_enum::<C>(
            &right_proof,
            &right_verifier_data,
            child_common_data,
            &[
                header_gadget.state_transition.agg_fingerprint,
                header_gadget.state_transition.leaf_fingerprint,
            ],
        );

        assert_eq!(left_proof.public_inputs.len(), 4);
        assert_eq!(right_proof.public_inputs.len(), 4);
        builder.connect_hashes(
            HashOutTarget {
                elements: [
                    left_proof.public_inputs[0],
                    left_proof.public_inputs[1],
                    left_proof.public_inputs[2],
                    left_proof.public_inputs[3],
                ],
            },
            header_gadget.expected_left_public_inputs_hash,
        );
        builder.connect_hashes(
            HashOutTarget {
                elements: [
                    right_proof.public_inputs[0],
                    right_proof.public_inputs[1],
                    right_proof.public_inputs[2],
                    right_proof.public_inputs[3],
                ],
            },
            header_gadget.expected_right_public_inputs_hash,
        );

        builder.register_public_inputs(&header_gadget.new_public_inputs_hash.elements);
        builder.add_qed_type_d_common_gates();
        debug_assert!(
            builder.num_gates() < 1 << 13,
            "AggStateTransitionCircuitV2 gate count {} crossed 2^13; the padded degree would grow and desynchronize this circuit's common data from the circuits that bake it in (baseline 8036)",
            builder.num_gates()
        );
        pad_circuit_degree(&mut builder, 12);
        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));

        Self {
            header_gadget,
            left_proof,
            left_verifier_data,
            right_proof,
            right_verifier_data,
            circuit_data,
            fingerprint,
        }
    }
    pub fn prove_base(
        &self,
        agg_fingerprint: QHashOut<C::F>,
        agg_verifier_data: &VerifierOnlyCircuitData<C, D>,
        leaf_fingerprint: QHashOut<C::F>,
        leaf_verifier_data: &VerifierOnlyCircuitData<C, D>,
        left_proof: &ProofWithPublicInputs<C::F, C, D>,
        right_proof: &ProofWithPublicInputs<C::F, C, D>,
        input: &AggStateTransitionInputV2<QHashOut<C::F>>,
        left_proving_rewards_tag_value: QHashOut<C::F>,
        right_proving_rewards_tag_value: QHashOut<C::F>,
        worker_reward_tag: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();
        
        self.header_gadget
            .set_witness(&mut pw, agg_fingerprint, leaf_fingerprint, input, left_proving_rewards_tag_value, right_proving_rewards_tag_value, worker_reward_tag)?;

        pw.set_proof_with_pis_target(&self.left_proof, left_proof)?;
        pw.set_verifier_data_target(
            &self.left_verifier_data,
            if input.left_proof_is_leaf {
                leaf_verifier_data
            } else {
                agg_verifier_data
            },
        )?;
        pw.set_proof_with_pis_target(&self.right_proof, right_proof)?;
        pw.set_verifier_data_target(
            &self.right_verifier_data,
            if input.right_proof_is_leaf {
                leaf_verifier_data
            } else {
                agg_verifier_data
            },
        )?;
        let result = self.circuit_data.prove(pw);

        if result.is_err() {
            tracing::info!("error: {}", serde_json::to_string(&input).unwrap());
        }
        result
    }
}
impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D>
    for AggStateTransitionCircuitV2<C, D>
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





impl<
        L: CircuitInfoLibrary<C, D>,
        C: QGenericConfig<D>,
        const D: usize,
    > QStandardCircuitProvableWithRawProofsAndRefLibrary<L, C, D>
    for AggStateTransitionCircuitV2<C, D>
where
    C::Hasher: FieldQHasher<C::F, QHashOut<C::F>> + AlgebraicHasher<C::F>, QHashOut<C::F>: Q256BitHash + QFHashBase<C::F>, C::F: QFelt64,
{

    fn prove_with_raw_proofs_and_ref_library(
        &self,
        library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<QHashOut<C::F>, QProvingJobDataID>,
        worker_reward_tag: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>{

        let leaf_circuit_type = input.base.job.job_id.circuit_type.get_agg_leaf_circuit_type_or_err()?;

        let agg_verifier_data = self.get_verifier_config_ref();
        let leaf_verifier_data = library.get_verifier_data(leaf_circuit_type)?;

        let leaf_fingerprint = library.get_fingerprint(input.base.job.job_id.circuit_type.get_agg_leaf_circuit_type_or_err()?)?;
        let agg_fingerprint = self.get_fingerprint();

        if input.input_proofs.len() != 2 {
            anyhow::bail!("invalid child proof tag values count in two end guta input");
        }
        if input.base.child_proof_tag_values.len() != 2 {
            anyhow::bail!("invalid child proof tag values count in two end guta input");
        }

        let left_proof =  deserialize_plonky2_proof::<C,D>(&input.input_proofs[0])?;
        let right_proof = deserialize_plonky2_proof::<C,D>(&input.input_proofs[1])?;

        let left_proving_rewards_tag_value = input.base.child_proof_tag_values[0];
        let right_proving_rewards_tag_value = input.base.child_proof_tag_values[1];


        let witness = AggStateTransitionInputV2::<QHashOut<C::F>>::psy_ser_from_slice(&input.base.witness)?;


        let new_rewards_root = hash_tag_tree_node::<QHashOut<C::F>, C::Hasher>(&left_proving_rewards_tag_value, &right_proving_rewards_tag_value, &worker_reward_tag);

        println!("witness: {:#?}", witness); 


        
        let whitelist = C::Hasher::two_to_one(
            &leaf_fingerprint,
            &agg_fingerprint
        );

        let agg_state_transition_combined = witness.condense_add_one();
        println!("agg_state_transition_combined: {:#?}", agg_state_transition_combined);
    
        let expected_public_inputs_hash_before_reward_tag = witness.get_public_inputs_hash_no_tag_tree::<C::Hasher>(whitelist);
        println!("expected_public_inputs_hash_before_reward_tag: {:#?}", expected_public_inputs_hash_before_reward_tag);
        let metadata_expected_public_inputs_hash_before_reward_tag = input.base.job.metadata.expected_public_inputs_hash;
        println!("metadata_expected_public_inputs_hash_before_reward_tag: {:#?}", metadata_expected_public_inputs_hash_before_reward_tag);
        if expected_public_inputs_hash_before_reward_tag != metadata_expected_public_inputs_hash_before_reward_tag {
            tracing::error!("expected_public_inputs_hash_before_reward_tag does not match metadata! expected: {:#?}, got: {:#?}", metadata_expected_public_inputs_hash_before_reward_tag, expected_public_inputs_hash_before_reward_tag);
        }
        println!("new_rewards_root: {:#?}", new_rewards_root);
        let expected_public_inputs_hash = C::Hasher::two_to_one(
            &expected_public_inputs_hash_before_reward_tag,
            &new_rewards_root,
        );
        println!("expected_public_inputs_hash: {:#?}", expected_public_inputs_hash);
        let result = self.prove_base(agg_fingerprint, agg_verifier_data, leaf_fingerprint, &leaf_verifier_data, &left_proof, &right_proof, &witness, left_proving_rewards_tag_value, right_proving_rewards_tag_value, worker_reward_tag)?;


        println!("got_public_inputs: {:#?}", result.public_inputs);
        Ok(result)

    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agg::v2::dummy::AggStateTransitionDummyCircuitV2;
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        hash::hash_types::HashOut,
        iop::generator::generate_partial_witness,
        plonk::config::{Hasher, PoseidonGoldilocksConfig},
    };
    use psy_data::agg::AggStateTransitionWithStats;

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    fn tag(seed: u64) -> QHashOut<F> {
        QHashOut(HashOut {
            elements: [
                F::from_canonical_u64(seed),
                F::from_canonical_u64(seed + 1),
                F::from_canonical_u64(seed + 2),
                F::from_canonical_u64(seed + 3),
            ],
        })
    }

    fn poseidon_two_to_one(a: &HashOut<F>, b: &HashOut<F>) -> HashOut<F> {
        <PoseidonHash as Hasher<F>>::two_to_one(*a, *b)
    }

    /// The leaf's reward-tag tree value: `H(H(0,0), worker_tag)`, matching the
    /// formula baked into `AggStateTransitionDummyCircuitV2`.
    fn leaf_tag_tree_value(worker_tag: &HashOut<F>) -> HashOut<F> {
        let zero = HashOut::ZERO;
        poseidon_two_to_one(&poseidon_two_to_one(&zero, &zero), worker_tag)
    }

    /// Native replica of `compute_agg_state_trackable_final_public_inputs_leaf`
    /// as built into `AggStateTransitionDummyCircuitV2` (total proofs = 1).
    fn expected_leaf_public_inputs(
        whitelist: &HashOut<F>,
        state_root: &HashOut<F>,
        worker_tag: &HashOut<F>,
    ) -> HashOut<F> {
        let transition_hash = poseidon_two_to_one(state_root, state_root);
        let allowed_and_transition = poseidon_two_to_one(whitelist, &transition_hash);
        let pi_without_reward_tag = <PoseidonHash as Hasher<F>>::hash_no_pad(&[
            allowed_and_transition.elements[0],
            allowed_and_transition.elements[1],
            allowed_and_transition.elements[2],
            allowed_and_transition.elements[3],
            F::ONE,
        ]);
        poseidon_two_to_one(
            &pi_without_reward_tag,
            &leaf_tag_tree_value(worker_tag),
        )
    }

    fn build_circuits() -> (
        AggStateTransitionDummyCircuitV2<C, D>,
        AggStateTransitionCircuitV2<C, D>,
    ) {
        let leaf = AggStateTransitionDummyCircuitV2::<C, D>::new();
        let agg = AggStateTransitionCircuitV2::<C, D>::new(
            &leaf.circuit_data.common,
            leaf.circuit_data
                .verifier_only
                .constants_sigmas_cap
                .height(),
        );
        // The circuit builds at 8036 gates and lands on a 2^13 degree; if the
        // count ever crossed 2^13 the degree would grow and desynchronize this
        // circuit's common data from the child common data it verifies against.
        assert_eq!(agg.circuit_data.common.degree(), 1 << 13);
        (leaf, agg)
    }

    fn two_leaf_transitions(state_root: QHashOut<F>) -> AggStateTransitionInputV2<QHashOut<F>> {
        AggStateTransitionInputV2 {
            left_input: AggStateTransitionWithStats {
                state_transition_start: state_root,
                state_transition_end: state_root,
                total_proofs_generated: 1,
            },
            right_input: AggStateTransitionWithStats {
                state_transition_start: state_root,
                state_transition_end: state_root,
                total_proofs_generated: 1,
            },
            left_proof_is_leaf: true,
            right_proof_is_leaf: true,
        }
    }

    #[test]
    fn honest_aggregation_with_two_leaf_proofs_proves() -> anyhow::Result<()> {
        let (leaf, agg) = build_circuits();
        let whitelist = QHashOut(poseidon_two_to_one(&leaf.fingerprint.0, &agg.fingerprint.0));
        let state_root = tag(100);
        let left_worker_tag = tag(200);
        let right_worker_tag = tag(300);
        let worker_reward_tag = tag(400);

        let left_leaf_proof = leaf.prove_base(whitelist, state_root, left_worker_tag)?;
        let right_leaf_proof = leaf.prove_base(whitelist, state_root, right_worker_tag)?;
        assert_eq!(left_leaf_proof.public_inputs.len(), 4);
        assert_eq!(right_leaf_proof.public_inputs.len(), 4);
        assert_ne!(
            left_leaf_proof.public_inputs, right_leaf_proof.public_inputs,
            "tags must differ so the two children are distinguishable"
        );

        // Harness cross-check: the leaf's actual public inputs equal the
        // natively recomputed leaf formula.
        assert_eq!(
            left_leaf_proof.public_inputs.as_slice(),
            expected_leaf_public_inputs(&whitelist.0, &state_root.0, &left_worker_tag.0).elements,
            "harness must agree with the leaf circuit formula"
        );

        let input = two_leaf_transitions(state_root);
        let agg_proof = agg.prove_base(
            agg.fingerprint,
            &agg.circuit_data.verifier_only,
            leaf.fingerprint,
            &leaf.circuit_data.verifier_only,
            &left_leaf_proof,
            &right_leaf_proof,
            &input,
            QHashOut(leaf_tag_tree_value(&left_worker_tag.0)),
            QHashOut(leaf_tag_tree_value(&right_worker_tag.0)),
            worker_reward_tag,
        )?;
        assert_eq!(agg_proof.public_inputs.len(), 4);
        agg.circuit_data.verify(agg_proof)?;
        Ok(())
    }

    #[test]
    fn child_public_inputs_replacement_rejected_by_binding() -> anyhow::Result<()> {
        let (leaf, agg) = build_circuits();
        let whitelist = QHashOut(poseidon_two_to_one(&leaf.fingerprint.0, &agg.fingerprint.0));
        let state_root = tag(100);
        let left_worker_tag = tag(200);
        let right_worker_tag = tag(300);
        let worker_reward_tag = tag(400);

        let left_leaf_proof = leaf.prove_base(whitelist, state_root, left_worker_tag)?;
        let right_leaf_proof = leaf.prove_base(whitelist, state_root, right_worker_tag)?;
        assert_ne!(
            left_leaf_proof.public_inputs, right_leaf_proof.public_inputs,
            "the substituted public inputs must differ from the expected ones"
        );
        let input = two_leaf_transitions(state_root);
        let left_tag_tree = QHashOut(leaf_tag_tree_value(&left_worker_tag.0));
        let right_tag_tree = QHashOut(leaf_tag_tree_value(&right_worker_tag.0));

        let make_witness = |replace_left_pis: bool| -> anyhow::Result<PartialWitness<F>> {
            let mut pw = PartialWitness::<F>::new();
            agg.header_gadget.set_witness(
                &mut pw,
                agg.fingerprint,
                leaf.fingerprint,
                &input,
                left_tag_tree,
                right_tag_tree,
                worker_reward_tag,
            )?;
            pw.set_verifier_data_target(&agg.left_verifier_data, &leaf.circuit_data.verifier_only)?;
            pw.set_verifier_data_target(
                &agg.right_verifier_data,
                &leaf.circuit_data.verifier_only,
            )?;
            if replace_left_pis {
                // Attack: the left child's public inputs are replaced by a
                // different valid proof's (the right child's) public inputs.
                pw.set_proof_target(&agg.left_proof.proof, &left_leaf_proof.proof)?;
                for (&target, &value) in agg
                    .left_proof
                    .public_inputs
                    .iter()
                    .zip(&right_leaf_proof.public_inputs)
                {
                    pw.set_target(target, value)?;
                }
            } else {
                pw.set_proof_with_pis_target(&agg.left_proof, &left_leaf_proof)?;
            }
            pw.set_proof_with_pis_target(&agg.right_proof, &right_leaf_proof)?;
            Ok(pw)
        };

        // Honest witness: every connected pair agrees in the partition witness.
        let honest = generate_partial_witness(
            make_witness(false)?,
            &agg.circuit_data.prover_only,
            &agg.circuit_data.common,
        )?;
        for i in 0..4 {
            assert_eq!(
                honest.get_target(agg.left_proof.public_inputs[i]),
                honest.get_target(agg.header_gadget.expected_left_public_inputs_hash.elements[i]),
                "left child PI wire {} must equal the expected hash wire",
                i
            );
            assert_eq!(
                honest.get_target(agg.right_proof.public_inputs[i]),
                honest.get_target(
                    agg.header_gadget.expected_right_public_inputs_hash.elements[i]
                ),
                "right child PI wire {} must equal the expected hash wire",
                i
            );
        }

        // Mutated witness: the binding fires at witness generation.
        let err = agg
            .circuit_data
            .prove(make_witness(true)?)
            .expect_err("replaced child public inputs must be rejected");
        assert!(
            err.to_string().contains("set twice with different values"),
            "unexpected error: {err:#}"
        );
        Ok(())
    }

    #[test]
    fn two_level_aggregation_proves_with_condensed_totals() -> anyhow::Result<()> {
        let (leaf, agg_left) = build_circuits();
        let agg_right = AggStateTransitionCircuitV2::<C, D>::new(
            &leaf.circuit_data.common,
            leaf.circuit_data
                .verifier_only
                .constants_sigmas_cap
                .height(),
        );
        let agg_top = AggStateTransitionCircuitV2::<C, D>::new(
            &agg_left.circuit_data.common,
            agg_left.circuit_data
                .verifier_only
                .constants_sigmas_cap
                .height(),
        );

        // One global whitelist threaded through every level, exactly as
        // `plan_jobs_for_tree_agg` does: the level-1 agg and the leaf circuit
        // are the two child types allowed under the top node.
        let whitelist = QHashOut(poseidon_two_to_one(&leaf.fingerprint.0, &agg_left.fingerprint.0));
        let state_root = tag(100);
        let worker_a = tag(500);
        let worker_b = tag(501);
        let worker_top = tag(502);
        let leaf_tags = [tag(200), tag(300), tag(600), tag(601)];

        let leaf_proof = |worker_tag: QHashOut<F>| -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
            leaf.prove_base(whitelist, state_root, worker_tag)
        };
        let level_one_input = two_leaf_transitions(state_root);

        let proof_a = agg_left.prove_base(
            agg_left.fingerprint,
            &agg_left.circuit_data.verifier_only,
            leaf.fingerprint,
            &leaf.circuit_data.verifier_only,
            &leaf_proof(leaf_tags[0])?,
            &leaf_proof(leaf_tags[1])?,
            &level_one_input,
            QHashOut(leaf_tag_tree_value(&leaf_tags[0].0)),
            QHashOut(leaf_tag_tree_value(&leaf_tags[1].0)),
            worker_a,
        )?;
        let proof_b = agg_right.prove_base(
            agg_right.fingerprint,
            &agg_right.circuit_data.verifier_only,
            leaf.fingerprint,
            &leaf.circuit_data.verifier_only,
            &leaf_proof(leaf_tags[2])?,
            &leaf_proof(leaf_tags[3])?,
            &level_one_input,
            QHashOut(leaf_tag_tree_value(&leaf_tags[2].0)),
            QHashOut(leaf_tag_tree_value(&leaf_tags[3].0)),
            worker_b,
        )?;

        // Each level-1 job reports its condensed stats (left + right + 1) to
        // the parent, matching the corrected gatherer convention for agg
        // children; a stale count would trip the binding at witness generation.
        let level_two_input = AggStateTransitionInputV2 {
            left_input: AggStateTransitionWithStats {
                state_transition_start: state_root,
                state_transition_end: state_root,
                total_proofs_generated: 3,
            },
            right_input: AggStateTransitionWithStats {
                state_transition_start: state_root,
                state_transition_end: state_root,
                total_proofs_generated: 3,
            },
            left_proof_is_leaf: false,
            right_proof_is_leaf: false,
        };
        let a_tag_tree = poseidon_two_to_one(
            &poseidon_two_to_one(
                &leaf_tag_tree_value(&leaf_tags[0].0),
                &leaf_tag_tree_value(&leaf_tags[1].0),
            ),
            &worker_a.0,
        );
        let b_tag_tree = poseidon_two_to_one(
            &poseidon_two_to_one(
                &leaf_tag_tree_value(&leaf_tags[2].0),
                &leaf_tag_tree_value(&leaf_tags[3].0),
            ),
            &worker_b.0,
        );

        let proof_top = agg_top.prove_base(
            agg_left.fingerprint,
            &agg_left.circuit_data.verifier_only,
            leaf.fingerprint,
            &leaf.circuit_data.verifier_only,
            &proof_a,
            &proof_b,
            &level_two_input,
            QHashOut(a_tag_tree),
            QHashOut(b_tag_tree),
            worker_top,
        )?;
        assert_eq!(proof_top.public_inputs.len(), 4);
        agg_top.circuit_data.verify(proof_top)?;
        Ok(())
    }
}
