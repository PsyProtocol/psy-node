use async_trait::async_trait;
use parth_core::{crypto::hash::{merkle_proof::MerkleProofCore, traits::MerkleZeroHasher}, data::proof_input::CircuitInputWithDependencies, pgoldilocks::QHashOut};
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
use psy_data::{guta::header::GlobalUserTreeAggregatorHeader, proof_input::guta::{GUTARegisterUserFullInput, VerifyGUTARegisterUsersCircuitInputSimple}};
use psy_plonky2_basic_helpers::{
    builder::hash::core::CircuitBuilderHashCore, verifier::circuit_library::CircuitInfoLibrary,
   
};
use psy_plonky2_common_circuits::traits::ToTargets;
use crate::{gadgets::qdata::pm_jobs_completed_stats::PMJobsCompletedStatsGadget, proof_minifier::pm_core::get_circuit_fingerprint_generic, qstandard::{proof_store::QProofStoreReaderAsync, QStandardCircuit, QStandardCircuitProvableWithProofStoreAndRefLibraryAsync, QPsyNetworkCircuitWithType}};

use crate::{guta::gadgets::guta_register_users_batch::GUTARegisterUsersBatchGadget};

#[derive(Debug)]
pub struct GUTAVerifyGUTARegisterUsersCircuit<C: GenericConfig<D>, const D: usize>
{
    pub register_batch_gadget: GUTARegisterUsersBatchGadget<D>,
    pub worker_public_key_target: HashOutTarget,
    pub pm_jobs_completed: PMJobsCompletedStatsGadget,

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

        let public_inputs_hash = register_batch_gadget.new_guta_header.to_hash::<C::Hasher, C::F, D>(&mut builder);

        let worker_public_key = builder.add_virtual_hash();

        // builder.assert_non_zero_hash(worker_public_key);

        let child_commitment = HashOutTarget {
            elements: [
                register_batch_gadget.verify_to_line_gadget.verify_guta_proof_gadget.proof_target.public_inputs[0],
                register_batch_gadget.verify_to_line_gadget.verify_guta_proof_gadget.proof_target.public_inputs[1],
                register_batch_gadget.verify_to_line_gadget.verify_guta_proof_gadget.proof_target.public_inputs[2],
                register_batch_gadget.verify_to_line_gadget.verify_guta_proof_gadget.proof_target.public_inputs[3],
            ]
        };
        let child_worker_public_key = HashOutTarget {
            elements: [
                register_batch_gadget.verify_to_line_gadget.verify_guta_proof_gadget.proof_target.public_inputs[4],
                register_batch_gadget.verify_to_line_gadget.verify_guta_proof_gadget.proof_target.public_inputs[5],
                register_batch_gadget.verify_to_line_gadget.verify_guta_proof_gadget.proof_target.public_inputs[6],
                register_batch_gadget.verify_to_line_gadget.verify_guta_proof_gadget.proof_target.public_inputs[7],
            ]
        };

        let child_pm_jobs_completed = [
            register_batch_gadget.verify_to_line_gadget.verify_guta_proof_gadget.proof_target.public_inputs[8],
            register_batch_gadget.verify_to_line_gadget.verify_guta_proof_gadget.proof_target.public_inputs[9],
            register_batch_gadget.verify_to_line_gadget.verify_guta_proof_gadget.proof_target.public_inputs[10],
        ];

        let one = builder.one();
        let final_gutas = builder.add(child_pm_jobs_completed[2], one);
        let pm_jobs_completed = PMJobsCompletedStatsGadget {
            deploy_contracts_completed: child_pm_jobs_completed[0],
            register_users_completed: child_pm_jobs_completed[1],
            gutas_completed: final_gutas,
        };

        let zero_hash = builder.constant_hash(HashOut::ZERO);
        let commitment = builder.hash_two_to_one::<C::Hasher>(child_commitment, child_worker_public_key);
        let final_commitment = builder.hash_two_to_one::<C::Hasher>(commitment, zero_hash);

        builder.register_public_inputs(&final_commitment.elements);
        builder.register_public_inputs(&worker_public_key.elements);
        builder.register_public_inputs(&pm_jobs_completed.to_targets());
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
            worker_public_key_target: worker_public_key,
            pm_jobs_completed,
        }
    }

    pub fn prove_base(
        &self,
        worker_public_key: QHashOut<C::F>,
        guta_whitelist_merkle_proof: &MerkleProofCore<QHashOut<C::F>>,
        guta_proof_header: &GlobalUserTreeAggregatorHeader<C::F, QHashOut<C::F>>,
        proof: &ProofWithPublicInputs<C::F, C, D>,
        verifier_data: &VerifierOnlyCircuitData<C, D>,
        top_line_siblings: &[QHashOut<C::F>],
        guta_register_user_inputs: &[GUTARegisterUserFullInput<QHashOut<C::F>>],
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();

        pw.set_hash_target(self.worker_public_key_target, worker_public_key.0)?;



        self.register_batch_gadget.set_witness_params(
            &mut pw,
            guta_whitelist_merkle_proof,
            guta_proof_header,
            proof,
            verifier_data,
            top_line_siblings,
            guta_register_user_inputs,
            self.default_user_state_tree_root
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
        worker_public_key: QHashOut<C::F>,
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
            worker_public_key,
            &guta_inclusion_proof_a,
            &r.input.guta_proof_header,
            &child_a_proof,
            &child_a_verifier_data,
            &r.input.top_line_siblings,
            &r.input.guta_register_user_inputs,
        )?;

        Ok(result)
    }
}
