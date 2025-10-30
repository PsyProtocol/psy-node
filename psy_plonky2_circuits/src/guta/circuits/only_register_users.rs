use async_trait::async_trait;
use parth_core::{crypto::hash::traits::MerkleZeroHasher, pgoldilocks::QHashOut};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget}, iop::
        witness::{PartialWitness, WitnessWrite}, plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    }, field::types::Field
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{proof_input::guta::{GUTAOnlyRegisterUsersInput, GUTARegisterUserFullInput}, v1::qdata::pm_jobs_completed_stats::PPMJobsCompletedStats};
use psy_plonky2_basic_helpers::{
    builder::{hash::core::CircuitBuilderHashCore, pad_circuit::CircuitBuilderQEDCommonGates}, verifier::circuit_library::CircuitInfoLibrary,
   
};
use psy_plonky2_common_circuits::traits::ToTargets;
use crate::{gadgets::qdata::pm_jobs_completed_stats::PMJobsCompletedStatsGadget, guta::gadgets::guta_only_register_users_gadget::GUTAOnlyRegisterUsersGadget, proof_minifier::pm_core::get_circuit_fingerprint_generic, qstandard::{proof_store::QProofStoreReaderAsync, QStandardCircuit, QStandardCircuitProvableWithProofStoreAndRefLibraryAsync, QPsyNetworkCircuitWithType}};

#[derive(Debug)]
pub struct GUTAOnlyRegisterUsersCircuit<C: GenericConfig<D>, const D: usize>
{
    register_batch_gadget: GUTAOnlyRegisterUsersGadget,
    guta_circuit_whitelist: HashOutTarget,
    checkpoint_tree_root: HashOutTarget,
    worker_public_key: HashOutTarget,
    pm_jobs_completed: PMJobsCompletedStatsGadget,

    default_user_state_tree_root: QHashOut<C::F>,

    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}
impl<C: GenericConfig<D>, const D: usize> QPsyNetworkCircuitWithType for GUTAOnlyRegisterUsersCircuit<C, D>
{
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::GUTAOnlyRegisterUsers
    }
}

impl<C: GenericConfig<D>, const D: usize> GUTAOnlyRegisterUsersCircuit<C, D>
where
    C::Hasher:AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> {
        pub fn new(
            max_users: usize,
            global_user_tree_realm_height: usize,
            global_user_tree_height: usize,
            group_realm_height: usize,
            default_user_state_tree_root: QHashOut<C::F>,

        ) -> Self {


        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let guta_circuit_whitelist = builder.add_virtual_hash();
        let checkpoint_tree_root = builder.add_virtual_hash();



        let register_batch_gadget = GUTAOnlyRegisterUsersGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            guta_circuit_whitelist,
            checkpoint_tree_root,

            global_user_tree_realm_height,
            global_user_tree_height,
            group_realm_height,
            default_user_state_tree_root,
            max_users,
        );

        let worker_public_key = builder.add_virtual_hash();

        // builder.assert_non_zero_hash(worker_public_key);

        let zero_hash = builder.constant_hash(HashOut::ZERO);
        let commitment = builder.hash_two_to_one::<C::Hasher>(zero_hash, zero_hash);

        let count = builder.one();
        let pm_jobs_completed = PMJobsCompletedStatsGadget::new_register_users(&mut builder, count);

        let public_inputs_hash = register_batch_gadget.new_guta_header.to_hash::<C::Hasher, C::F, D>(&mut builder);

        // Register 15 public inputs: commitment, worker_public_key, pm_jobs_completed_stats, header_hash
        builder.register_public_inputs(&commitment.elements);
        builder.register_public_inputs(&worker_public_key.elements);
        builder.register_public_inputs(&pm_jobs_completed.to_targets());
        builder.register_public_inputs(&public_inputs_hash.elements);
        builder.add_qed_type_c_common_gates();
        //builder.add_gate_to_gate_set(GateRef::new(ConstantGate::new(builder.config.num_constants)));
        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(
            &circuit_data.verifier_only,
        ));

        Self {
            register_batch_gadget,
            guta_circuit_whitelist,
            checkpoint_tree_root,
            worker_public_key,
            pm_jobs_completed,
            default_user_state_tree_root,

            circuit_data,
            fingerprint,
        }
    }

    pub fn prove_base(
        &self,
        worker_public_key: QHashOut<C::F>,
        guta_circuit_whitelist_root: QHashOut<C::F>,
        checkpoint_tree_root: QHashOut<C::F>,
        guta_register_user_inputs: &[GUTARegisterUserFullInput<QHashOut<C::F>>],
        default_user_state_tree_root: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();



        pw.set_hash_target(
            self.guta_circuit_whitelist,
            guta_circuit_whitelist_root.0,
        )?;
        pw.set_hash_target(
            self.checkpoint_tree_root,
            checkpoint_tree_root.0,
        )?;
        pw.set_hash_target(
            self.worker_public_key,
            worker_public_key.0,
        )?;


        self.register_batch_gadget.set_witness_params::<C::Hasher, C::F, D>(
            &mut pw,
            guta_register_user_inputs,
            default_user_state_tree_root,
        )?;

        pw.set_hash_target(self.worker_public_key, worker_public_key.0)?;

        let pm_stats = PPMJobsCompletedStats::new_register_users_with_zero(C::F::ZERO, C::F::ONE);
        self.pm_jobs_completed.set_witness(&mut pw, &pm_stats)?;

        let p = self.circuit_data.prove(pw)?;
        Ok(p)
    }
}


impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D>
    for GUTAOnlyRegisterUsersCircuit<C, D>
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
    for GUTAOnlyRegisterUsersCircuit<C, D>
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
        let r: GUTAOnlyRegisterUsersInput<QHashOut<C::F>> =
            bincode::deserialize(&store.get_bytes_by_id(job_id.get_input_witness_id()).await?)
                .map_err(|e| anyhow::anyhow!(e))?;

        tracing::debug!("GUTAOnlyRegisterUsersInput: {}", serde_json::to_string_pretty(&r)?);


        let guta_whitelist_root: QHashOut<C::F> =
            library.get_group_inclusion_proof(ProvingJobCircuitType::GUTATwoGUTA, ProvingJobCircuitType::GUTATwoGUTA)?.root;


        let result = self.prove_base(
            worker_public_key,
            guta_whitelist_root,
            r.checkpoint_tree_root,
            &r.guta_register_user_inputs,
            self.default_user_state_tree_root,
        )?;

        Ok(result)
    }
}
