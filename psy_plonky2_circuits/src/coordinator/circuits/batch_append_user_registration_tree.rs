use async_trait::async_trait;
use parth_core::{crypto::hash::{merkle_proof::MerkleProofCore, spiderman::SpidermanUpdateProof, traits::MerkleZeroHasher}, data::proof_input::CircuitInputWithDependencies, pgoldilocks::QHashOut};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget}, iop::
        witness::{PartialWitness, WitnessWrite}, plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    }, field::types::Field
};
use psy_core::{constants::protocol::{get_default_worker_public_key, DEFAULT_USER_STATE_TREE_ROOT_U64}, job::job_id::{ProvingJobCircuitType, QProvingJobDataID}};
use psy_data::{agg::{AggStateTransition, TPAltCircuitFingerprintConfig}, guta::header::GlobalUserTreeAggregatorHeader, proof_input::guta::{GUTANoChangeFullInput, GUTAOnlyRegisterUsersInput, GUTARegisterUserFullInput}, protocol::circuit_inputs::{agg_part_1::QCAggUserRegistartionDeployContractsGUTAInput, append_user_registration_tree::QCAppendUserRegistrationTreeCircuitInput}, v1::qdata::{checkpoint::PQEDCheckpointLeafCompactWithStateRoots, pm_jobs_completed_stats::PPMJobsCompletedStats}};
use psy_plonky2_basic_helpers::{
    builder::{comparison::CircuitBuilderComparison, hash::core::CircuitBuilderHashCore, pad_circuit::{pad_circuit_degree, CircuitBuilderQEDCommonGates}}, verifier::circuit_library::CircuitInfoLibrary,
   
};
use psy_plonky2_common_circuits::traits::ToTargets;
use crate::{gadgets::qdata::pm_jobs_completed_stats::PMJobsCompletedStatsGadget, guta::gadgets::guta_only_register_users_gadget::GUTAOnlyRegisterUsersGadget, proof_minifier::{pm_chain_dynamic::QEDProofMinifierDynamicChain, pm_core::get_circuit_fingerprint_generic}, qstandard::{proof_store::{QProofStoreReaderAsync, QProofStoreReaderSync}, provable::QStandardCircuitProvable, QStandardCircuit, QStandardCircuitProvableWithProofStoreAndRefLibraryAsync, QStandardCircuitProvableWithProofStoreSync}};

use crate::coordinator::gadgets::append_user_registration_tree::BatchAppendUserRegistrationTreeGadget;

use crate::{coordinator::gadgets::verify_agg_user_registration_deploy_guta::VerifyAggUserRegistartionDeployContractsGUTAGadget};

#[derive(Debug)]
pub struct BatchAppendUserRegistrationTreeCircuit<C: GenericConfig<D>, const D: usize>
{
    pub batch_append_gadget: BatchAppendUserRegistrationTreeGadget,
    pub register_users_circuit_whitelist: HashOutTarget,
    pub worker_public_key: HashOutTarget,
    pub commitment: HashOutTarget,
    pub pm_jobs_completed: PMJobsCompletedStatsGadget,

    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}

impl<C: GenericConfig<D>, const D: usize> BatchAppendUserRegistrationTreeCircuit<C, D>
where
    C::Hasher:AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> {
        pub fn new(
            user_registration_tree_height: usize,
            batch_sub_tree_height: usize,
            max_sub_trees: usize,
        ) -> Self {


        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);


        let register_users_circuit_whitelist = builder.add_virtual_hash();
        let worker_public_key = builder.add_virtual_hash();

        // builder.assert_non_zero_hash(worker_public_key);

        let batch_append_gadget = BatchAppendUserRegistrationTreeGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            user_registration_tree_height,
            batch_sub_tree_height,
            max_sub_trees,
        );
        let state_transition_hash = builder.hash_two_to_one::<C::Hasher>(
            batch_append_gadget.old_root,
            batch_append_gadget.new_root,
        );

        let zero_hash = builder.constant_hash(HashOut::ZERO);
        let commitment = builder.hash_two_to_one::<C::Hasher>(zero_hash, zero_hash);

        let one = builder.one();
        let pm_jobs_completed = PMJobsCompletedStatsGadget::new_register_users(&mut builder, one);

        builder.register_public_inputs(&commitment.elements);
        builder.register_public_inputs(&worker_public_key.elements);
        builder.register_public_inputs(&pm_jobs_completed.to_targets());
        builder.register_public_inputs(&register_users_circuit_whitelist.elements);
        builder.register_public_inputs(&state_transition_hash.elements);

        builder.add_qed_type_d_common_gates();
        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(
            &circuit_data.verifier_only,
        ));

        Self {
            register_users_circuit_whitelist,
            worker_public_key,
            pm_jobs_completed,
            commitment,
            batch_append_gadget,
            circuit_data,
            fingerprint,
        }
    }

    pub fn prove_base(
        &self,
        register_users_circuit_whitelist: QHashOut<C::F>,
        worker_public_key: QHashOut<C::F>,
        spiderman_append_proofs: &[SpidermanUpdateProof<QHashOut<C::F>>],
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();
        pw.set_hash_target(self.register_users_circuit_whitelist, register_users_circuit_whitelist.0)?;
        pw.set_hash_target(self.worker_public_key, worker_public_key.0)?;

        let jobs_completed_stats = PPMJobsCompletedStats::new_register_users_with_zero(C::F::ZERO, C::F::ONE);
        self.pm_jobs_completed.set_witness(&mut pw, &jobs_completed_stats);

        self.batch_append_gadget.set_witness_params(
            &mut pw,
            spiderman_append_proofs
        )?;

        self.circuit_data.prove(pw)
    }
}


impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D>
    for BatchAppendUserRegistrationTreeCircuit<C, D>
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


impl<C: GenericConfig<D>, const D: usize>
    QStandardCircuitProvable<QCAppendUserRegistrationTreeCircuitInput<QHashOut<C::F>>, C, D> for BatchAppendUserRegistrationTreeCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_standard(
        &self,
        input: &QCAppendUserRegistrationTreeCircuitInput<QHashOut<C::F>>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_base(
            input.register_users_circuit_whitelist,
            get_default_worker_public_key(),
            &input.spiderman_append_proofs,
        )
    }
}

impl<S: QProofStoreReaderSync, C: GenericConfig<D>, const D: usize>
    QStandardCircuitProvableWithProofStoreSync<S, QCAppendUserRegistrationTreeCircuitInput<QHashOut<C::F>>, C, D>
    for BatchAppendUserRegistrationTreeCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_with_proof_store_sync(
        &self,
        _store: &S,
        input: &QCAppendUserRegistrationTreeCircuitInput<QHashOut<C::F>>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_standard(input)
    }
}



#[async_trait]
impl<
        S: QProofStoreReaderAsync + Send + Sync,
        L: CircuitInfoLibrary<C, D> + Send + Sync,
        C: GenericConfig<D> + 'static,
        const D: usize,
    > QStandardCircuitProvableWithProofStoreAndRefLibraryAsync<S, L, C, D>
    for BatchAppendUserRegistrationTreeCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    async fn prove_with_proof_store_async(
        &self,
        store: &S,
        _library: &L,
        job_id: QProvingJobDataID,
        worker_public_key: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let input: QCAppendUserRegistrationTreeCircuitInput<QHashOut<C::F>> = bincode::deserialize(&store.get_bytes_by_id(job_id.get_input_witness_id()).await?)
                .map_err(|e| anyhow::anyhow!(e))?;
        tracing::debug!("QCAppendUserRegistrationTreeCircuitInput: {}", serde_json::to_string_pretty(&input).unwrap());

        let result = self.prove_base(
            input.register_users_circuit_whitelist,
            worker_public_key,
            &input.spiderman_append_proofs,
        )?;

        Ok(result)
    }
}
