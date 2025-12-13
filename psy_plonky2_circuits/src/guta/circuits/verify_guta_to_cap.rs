use plonky2::{
    gates::{constant::ConstantGate, gate::GateRef}, hash::hash_types::{HashOut, HashOutTarget}, iop::
        witness::{PartialWitness, WitnessWrite}, plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    }
};
use parth_core::{
    crypto::hash::{merkle_proof::MerkleProofCore, traits::MerkleZeroHasher}, felt::QFelt64, pgoldilocks::QHashOut, protocol::core_types::Q256BitHash
};
use psy_core::
    job::job_id::{ProvingJobCircuitType, QProvingJobDataID}
;
use psy_data::{
    guta::header::GlobalUserTreeAggregatorHeader,
    proof_input::guta::VerifyGUTAToCapCircuitInputSimple, worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse
    ,
};
use psy_plonky2_basic_helpers::{
    builder::
        pad_circuit::pad_circuit_degree
    ,
    verifier::circuit_library::CircuitInfoLibrary,
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::{
    guta::gadgets::
        verify_guta_proof_to_line::VerifyGUTAProofToLineGadget
    ,
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    qstandard::{QPsyNetworkCircuitWithType, QStandardCircuit, QStandardCircuitProvableWithRawProofsAndRefLibrary}, utils::proof_library::get_single_child_proof_for_api_response_with_inclusion_proof,
};


#[derive(Debug)]
pub struct GUTAVerifyGUTAToCapCircuit<C: GenericConfig<D>, const D: usize>
{
    pub verify_to_line_gadget: VerifyGUTAProofToLineGadget<D>,
    pub worker_rewards_tree_tag_target: HashOutTarget,

    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}

impl<C: GenericConfig<D>, const D: usize> QPsyNetworkCircuitWithType for GUTAVerifyGUTAToCapCircuit<C, D>
{
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::GUTAVerifyToCap
    }
}

impl<C: GenericConfig<D>, const D: usize> GUTAVerifyGUTAToCapCircuit<C, D>
where
    C::Hasher:AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> {
        pub fn new(
            guta_proof_common_data: &CommonCircuitData<C::F, D>,
            guta_proof_verifier_data_cap_height: usize,
            global_user_tree_coordinator_height: usize,
            global_user_tree_height: usize,
            guta_circuit_whitelist_tree_height: u8,
        ) -> Self {


        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);


        let verify_to_line_gadget = VerifyGUTAProofToLineGadget::<D>::add_virtual_to::<C, C::F>(
            &mut builder,
            guta_proof_common_data,
            guta_proof_verifier_data_cap_height,
            global_user_tree_coordinator_height,
            global_user_tree_height,
            guta_circuit_whitelist_tree_height
        );

        // generate public inputs hash from worker rewards tree tag and child rewards tree value
        let worker_rewards_tree_tag_target = builder.add_virtual_hash();
        let child_proof_rewards_tree_value = verify_to_line_gadget.verify_guta_proof_gadget.rewards_tree_value;
        let public_inputs_hash = verify_to_line_gadget.get_guta_header_line().get_public_inputs_hash_single_child::<C::Hasher, C::F, D>(
            &mut builder,
            child_proof_rewards_tree_value,
            worker_rewards_tree_tag_target
        );
        builder.register_public_inputs(&public_inputs_hash.elements);

        builder.add_gate_to_gate_set(GateRef::new(ConstantGate::new(builder.config.num_constants)));
        pad_circuit_degree(&mut builder, 12);
        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(
            &circuit_data.verifier_only,
        ));

        Self {
            circuit_data,
            fingerprint,
            verify_to_line_gadget,
            worker_rewards_tree_tag_target,
        }
    }

    pub fn prove_base(
        &self,
        guta_whitelist_merkle_proof: &MerkleProofCore<QHashOut<C::F>>,
        guta_proof_header: &GlobalUserTreeAggregatorHeader<C::F, QHashOut<C::F>>,
        proof: &ProofWithPublicInputs<C::F, C, D>,
        verifier_data: &VerifierOnlyCircuitData<C, D>,
        top_line_siblings: &[QHashOut<C::F>],
        worker_rewards_tree_tag: QHashOut<C::F>,
        child_proof_rewards_tree_value: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {

        let mut pw = PartialWitness::<C::F>::new();

        self.verify_to_line_gadget.set_witness(
            &mut pw,
            guta_whitelist_merkle_proof,
            guta_proof_header,
            proof,
            verifier_data,
            top_line_siblings,
            child_proof_rewards_tree_value,
        )?;

        pw.set_hash_target(self.worker_rewards_tree_tag_target, worker_rewards_tree_tag.0)?;

        self.circuit_data.prove(pw)

    }
}


impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D>
    for GUTAVerifyGUTAToCapCircuit<C, D>
where
    C::Hasher:AlgebraicHasher<C::F>,
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
        C: GenericConfig<D>,
        const D: usize,
    > QStandardCircuitProvableWithRawProofsAndRefLibrary<L, C, D>
    for GUTAVerifyGUTAToCapCircuit<C, D>
where
     C::Hasher:AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>, QHashOut<C::F>: Q256BitHash, C::F: QFelt64,
{

    fn prove_with_raw_proofs_and_ref_library(
        &self,
        library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<QHashOut<C::F>, QProvingJobDataID>,
        worker_reward_tag: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>{

        let child_proof_result = get_single_child_proof_for_api_response_with_inclusion_proof::<L, C, D>(
            library,
            &input,
        )?;


        let witness = VerifyGUTAToCapCircuitInputSimple::<C::F, QHashOut<C::F>>::psy_ser_from_slice(&input.base.witness)?;
        
        self.prove_base(
            &child_proof_result.whitelist_inclusion_proof,
            &witness.guta_proof_header,
            &child_proof_result.zk_proof,
            &child_proof_result.verifier_data,
            &witness.top_line_siblings,
            worker_reward_tag,
            child_proof_result.reward_tag_tree_value
        )
    }
}
