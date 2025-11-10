use async_trait::async_trait;
use parth_core::{pgoldilocks::QHashOut, protocol::core_types::Q256BitHash};
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
use psy_data::{agg::AggStateTransitionInputV2, worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse};
use psy_plonky2_basic_helpers::{builder::{hash::core::CircuitBuilderHashCore, pad_circuit::CircuitBuilderQEDCommonGates, verify::CircuitBuilderVerifyProofHelpers}, verifier::circuit_library::CircuitInfoLibrary};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::{agg::{circuits::core::AggStateTrackableCircuitHeaderGadget, common::compute_agg_state_trackable_final_public_inputs}, proof_minifier::pm_core::get_circuit_fingerprint_generic, qstandard::{QStandardCircuit, QStandardCircuitProvableWithRawProofsAndRefLibraryAsync}};

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

        builder.register_public_inputs(&header_gadget.new_public_inputs_hash.elements);
        builder.add_qed_type_d_common_gates();
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





#[async_trait]
impl<
        L: CircuitInfoLibrary<C, D> + Send + Sync,
        C: GenericConfig<D>,
        const D: usize,
    > QStandardCircuitProvableWithRawProofsAndRefLibraryAsync<L, C, D>
    for AggStateTransitionCircuitV2<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>, QHashOut<C::F>: Q256BitHash,
{

    async fn prove_with_raw_proofs_and_ref_library_async(
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

        let left_proof =  bincode::deserialize::<ProofWithPublicInputs<C::F, C, D>>(&input.input_proofs[0])?;
        let right_proof = bincode::deserialize::<ProofWithPublicInputs<C::F, C, D>>(&input.input_proofs[1])?;

        let left_proving_rewards_tag_value = input.base.child_proof_tag_values[0];
        let right_proving_rewards_tag_value = input.base.child_proof_tag_values[1];


        let witness = AggStateTransitionInputV2::<QHashOut<C::F>>::psy_ser_from_slice(&input.base.witness)?;
        self.prove_base(agg_fingerprint, agg_verifier_data, leaf_fingerprint, &leaf_verifier_data, &left_proof, &right_proof, &witness, left_proving_rewards_tag_value, right_proving_rewards_tag_value, worker_reward_tag)

    }
}
