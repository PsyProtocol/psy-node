use async_trait::async_trait;
use parth_core::{crypto::hash::{merkle_proof::MerkleProofCore, traits::MerkleZeroHasher}, data::proof_input::CircuitInputWithDependencies, felt::QFelt64, pgoldilocks::QHashOut, protocol::core_types::Q256BitHash};
use plonky2::{
    gates::{constant::ConstantGate, gate::GateRef}, hash::hash_types::{HashOut, HashOutTarget}, iop::
        witness::{PartialWitness, WitnessWrite}, plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    }
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{guta::header::GlobalUserTreeAggregatorHeader, proof_input::guta::{GUTARegisterUserFullInput, VerifyGUTARegisterUsersCircuitInputSimple}, worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse};
use psy_plonky2_basic_helpers::
    verifier::circuit_library::CircuitInfoLibrary
   
;
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
use crate::{proof_minifier::pm_core::get_circuit_fingerprint_generic, qstandard::{QPsyNetworkCircuitWithType, QStandardCircuit, QStandardCircuitProvableWithProofStoreAndRefLibraryAsync, QStandardCircuitProvableWithRawProofsAndRefLibraryAsync, proof_store::QProofStoreReaderAsync}, utils::proof_llbrary::get_single_child_proof_for_api_response_with_inclusion_proof};

use crate::{guta::gadgets::guta_register_users_batch::GUTARegisterUsersBatchGadget};

#[derive(Debug)]
pub struct GUTAVerifyGUTARegisterUsersCircuit<C: GenericConfig<D>, const D: usize>
{
    pub register_batch_gadget: GUTARegisterUsersBatchGadget<D>,
    pub worker_rewards_tree_tag_target: HashOutTarget,

    pub default_user_state_tree_root: QHashOut<C::F>,
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,

}


impl<C: GenericConfig<D>, const D: usize> QPsyNetworkCircuitWithType for GUTAVerifyGUTARegisterUsersCircuit<C, D>
{
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::GUTARegisterUsers
    }
}

impl<C: GenericConfig<D>, const D: usize> GUTAVerifyGUTARegisterUsersCircuit<C, D>
where
    C::Hasher:AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> {
        pub fn new(
            guta_proof_common_data: &CommonCircuitData<C::F, D>,
            guta_proof_verifier_data_cap_height: usize,
            max_users: usize,
            global_user_tree_realm_height: usize,
            global_user_tree_height: usize,
            group_realm_height: usize,
            default_user_state_tree_root: QHashOut<C::F>,
            guta_circuit_whitelist_tree_height: u8,
        ) -> Self {


            println!("GUTAVerifyGUTARegisterUsersCircuit: guta_proof_verifier_data_cap_height: {guta_proof_verifier_data_cap_height}, max_users: {max_users}, global_user_tree_realm_height: {global_user_tree_realm_height}, global_user_tree_height: {global_user_tree_height}, group_realm_height: {group_realm_height}, guta_circuit_whitelist_tree_height: {guta_circuit_whitelist_tree_height}");

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);



        let register_batch_gadget = GUTARegisterUsersBatchGadget::<D>::add_virtual_to::<C, C::F>(
            &mut builder,
            guta_proof_common_data,
            guta_proof_verifier_data_cap_height,
            global_user_tree_realm_height,
            global_user_tree_height,
            group_realm_height,
            default_user_state_tree_root,
            max_users,
            guta_circuit_whitelist_tree_height,
        );

        tracing::debug!("📊 register_batch_gadget.new_guta_header: {:?}", register_batch_gadget.new_guta_header);
        let worker_rewards_tree_tag = builder.add_virtual_hash();

        let public_inputs_hash = register_batch_gadget.new_guta_header.get_public_inputs_hash_single_child::<C::Hasher, C::F, D>(&mut builder, register_batch_gadget.verify_to_line_gadget.verify_guta_proof_gadget.rewards_tree_value, worker_rewards_tree_tag);


        builder.register_public_inputs(&public_inputs_hash.elements);

        builder.add_gate_to_gate_set(GateRef::new(ConstantGate::new(builder.config.num_constants)));
        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(
            &circuit_data.verifier_only,
        ));

        Self {
            circuit_data,
            fingerprint,
            register_batch_gadget,
            default_user_state_tree_root,
            worker_rewards_tree_tag_target: worker_rewards_tree_tag,
        }
    }

    pub fn prove_base(
        &self,
        worker_rewards_tree_tag: QHashOut<C::F>,
        guta_whitelist_merkle_proof: &MerkleProofCore<QHashOut<C::F>>,
        guta_proof_header: &GlobalUserTreeAggregatorHeader<C::F, QHashOut<C::F>>,
        proof: &ProofWithPublicInputs<C::F, C, D>,
        verifier_data: &VerifierOnlyCircuitData<C, D>,
        top_line_siblings: &[QHashOut<C::F>],
        guta_register_user_inputs: &[GUTARegisterUserFullInput<QHashOut<C::F>>],
        child_proof_rewards_tree_value: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();

        pw.set_hash_target(self.worker_rewards_tree_tag_target, worker_rewards_tree_tag.0)?;



        self.register_batch_gadget.set_witness_params(
            &mut pw,
            guta_whitelist_merkle_proof,
            guta_proof_header,
            proof,
            verifier_data,
            top_line_siblings,
            guta_register_user_inputs,
            self.default_user_state_tree_root,
            child_proof_rewards_tree_value,
        )?;

        self.circuit_data.prove(pw)
    }
}


impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D>
    for GUTAVerifyGUTARegisterUsersCircuit<C, D>
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



#[async_trait]
impl<
        S: QProofStoreReaderAsync + Send + Sync,
        L: CircuitInfoLibrary<C, D> + Send + Sync,
        C: GenericConfig<D> + 'static,
        const D: usize,
    > QStandardCircuitProvableWithProofStoreAndRefLibraryAsync<S, L, C, D>
    for GUTAVerifyGUTARegisterUsersCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    async fn prove_with_proof_store_async(
        &self,
        store: &S,
        library: &L,
        job_id: QProvingJobDataID,
        worker_rewards_tree_tag: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let r: CircuitInputWithDependencies<VerifyGUTARegisterUsersCircuitInputSimple<C::F, QHashOut<C::F>>, QProvingJobDataID> =
            bincode::deserialize(&store.get_bytes_by_id(job_id.get_input_witness_id()).await?)
                .map_err(|e| anyhow::anyhow!(e))?;
        tracing::debug!("GUTAVerifyGUTARegisterUsersInput: {}", serde_json::to_string_pretty(&r)?);

        if r.dependencies.len() != 1 {
            anyhow::bail!("invalid dependency count in two end guta input");
        }

        let child_a_proof = store.get_proof_by_id(r.dependencies[0]).await?;

        let dep_a_type = r.dependencies[0].circuit_type;

        let child_a_verifier_data = library.get_verifier_data(dep_a_type)?;
        let guta_inclusion_proof_a =
            library.get_group_inclusion_proof(job_id.circuit_type, dep_a_type)?;

        let result = self.prove_base(
            worker_rewards_tree_tag,
            &guta_inclusion_proof_a,
            &r.input.guta_proof_header,
            &child_a_proof,
            &child_a_verifier_data,
            &r.input.top_line_siblings,
            &r.input.guta_register_user_inputs,
            todo!(), // child_proof_rewards_tree_value
        )?;

        Ok(result)
    }
}


#[async_trait]
impl<
        L: CircuitInfoLibrary<C, D> + Send + Sync,
        C: GenericConfig<D>,
        const D: usize,
    > QStandardCircuitProvableWithRawProofsAndRefLibraryAsync<L, C, D>
    for GUTAVerifyGUTARegisterUsersCircuit<C, D>
where
     C::Hasher:AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>, QHashOut<C::F>: Q256BitHash, C::F: QFelt64,
{

    async fn prove_with_raw_proofs_and_ref_library_async(
        &self,
        library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<QHashOut<C::F>, QProvingJobDataID>,
        worker_reward_tag: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>{

        let child_proof_result = get_single_child_proof_for_api_response_with_inclusion_proof::<L, C, D>(
            library,
            &input,
        )?;


        let witness:VerifyGUTARegisterUsersCircuitInputSimple<C::F, QHashOut<C::F>> = VerifyGUTARegisterUsersCircuitInputSimple::<C::F, QHashOut<C::F>>::psy_ser_from_slice(&input.base.witness)?;
        
        self.prove_base(
            worker_reward_tag,
            &child_proof_result.whitelist_inclusion_proof,
            &witness.guta_proof_header,
            &child_proof_result.zk_proof,
            &child_proof_result.verifier_data,
            &witness.top_line_siblings,
            &witness.guta_register_user_inputs,
            child_proof_result.reward_tag_tree_value
        )
    }
}
