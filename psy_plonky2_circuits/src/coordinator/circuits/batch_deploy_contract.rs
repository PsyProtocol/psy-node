use async_trait::async_trait;
use parth_core::{crypto::hash::{spiderman::SpidermanUpdateProof, traits::MerkleZeroHasher}, pgoldilocks::QHashOut};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget}, iop::
        witness::{PartialWitness, WitnessWrite}, plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    }, field::types::Field
};
use psy_core::{constants::protocol::get_default_worker_public_key, job::job_id::{ProvingJobCircuitType, QProvingJobDataID}};
use psy_data::{protocol::circuit_inputs::deploy_contracts::QCBatchDeployContractsCircuitInput, v1::qdata::{contract::PQEDContractLeaf, pm_jobs_completed_stats::PPMJobsCompletedStats}};
use psy_plonky2_basic_helpers::{
    builder::{hash::core::CircuitBuilderHashCore, pad_circuit::{pad_circuit_degree, CircuitBuilderQEDCommonGates}}, verifier::circuit_library::CircuitInfoLibrary,
   
};
use psy_plonky2_common_circuits::traits::ToTargets;
use crate::{coordinator::gadgets::deploy_contract::BatchDeployContractsGadget, gadgets::qdata::pm_jobs_completed_stats::PMJobsCompletedStatsGadget, proof_minifier::pm_core::get_circuit_fingerprint_generic, qstandard::{proof_store::{QProofStoreReaderAsync, QProofStoreReaderSync}, provable::QStandardCircuitProvable, QStandardCircuit, QStandardCircuitProvableWithProofStoreAndRefLibraryAsync, QStandardCircuitProvableWithProofStoreSync, QPsyNetworkCircuitWithType}};


#[derive(Debug)]
pub struct BatchDeployContractsCircuit<C: GenericConfig<D>, const D: usize>
{
    pub deploy_contract_batch_gadget: BatchDeployContractsGadget,
    pub deploy_contract_circuit_whitelist: HashOutTarget,
    pub worker_public_key: HashOutTarget,
    pub commitment: HashOutTarget,
    pub pm_jobs_completed: PMJobsCompletedStatsGadget,

    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}

impl<C: GenericConfig<D>, const D: usize> QPsyNetworkCircuitWithType for BatchDeployContractsCircuit<C, D>
{
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::BatchDeployContracts
    }
}
impl<C: GenericConfig<D>, const D: usize> BatchDeployContractsCircuit<C, D>
where
    C::Hasher:AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> {
        pub fn new(
            contract_tree_height: usize,
            batch_sub_tree_height: usize,
            max_contract_state_tree_height: usize,
        ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);


        let deploy_contract_circuit_whitelist = builder.add_virtual_hash();
        let worker_public_key = builder.add_virtual_hash();

        // builder.assert_non_zero_hash(worker_public_key);

        let deploy_contract_batch_gadget = BatchDeployContractsGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            contract_tree_height,
            batch_sub_tree_height,
            max_contract_state_tree_height
        );

        let state_transition_hash = builder.hash_two_to_one::<C::Hasher>(
            deploy_contract_batch_gadget.spiderman_gadget.old_root,
            deploy_contract_batch_gadget.spiderman_gadget.new_root,
        );

        let zero_hash = builder.constant_hash(HashOut::ZERO);
        let commitment = builder.hash_two_to_one::<C::Hasher>(zero_hash, zero_hash);

        let one = builder.one();
        let pm_jobs_completed = PMJobsCompletedStatsGadget::new_deploy_contracts(&mut builder, one);

        builder.register_public_inputs(&commitment.elements);
        builder.register_public_inputs(&worker_public_key.elements);
        builder.register_public_inputs(&pm_jobs_completed.to_targets());
        builder.register_public_inputs(&deploy_contract_circuit_whitelist.elements);
        builder.register_public_inputs(&state_transition_hash.elements);
        builder.add_qed_type_d_common_gates();
        pad_circuit_degree(&mut builder, 12);

        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(
            &circuit_data.verifier_only,
        ));

        Self {
            deploy_contract_circuit_whitelist,
            worker_public_key,
            commitment,
            pm_jobs_completed,
            deploy_contract_batch_gadget,
            circuit_data,
            fingerprint,
        }
    }

    pub fn prove_base(
        &self,
        deploy_contract_circuit_whitelist: QHashOut<C::F>,
        worker_public_key: QHashOut<C::F>,
        spiderman_append_proof: &SpidermanUpdateProof<QHashOut<C::F>>,
        contract_leaves: &[PQEDContractLeaf<C::F, QHashOut<C::F>>],
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();
        pw.set_hash_target(self.deploy_contract_circuit_whitelist, deploy_contract_circuit_whitelist.0)?;
        pw.set_hash_target(self.worker_public_key, worker_public_key.0)?;

        let jobs_completed_stats = PPMJobsCompletedStats::new_deploy_contracts_with_zero(C::F::ZERO, C::F::ONE);
        self.pm_jobs_completed.set_witness(&mut pw, &jobs_completed_stats)?;

        self.deploy_contract_batch_gadget.set_witness_params(
            &mut pw,
            spiderman_append_proof,
            contract_leaves,
        )?;

        self.circuit_data.prove(pw)
    }
}


impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D>
    for BatchDeployContractsCircuit<C, D>
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
    QStandardCircuitProvable<QCBatchDeployContractsCircuitInput<C::F, QHashOut<C::F>>, C, D> for BatchDeployContractsCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_standard(
        &self,
        input: &QCBatchDeployContractsCircuitInput<C::F, QHashOut<C::F>>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_base(
            input.deploy_contract_circuit_whitelist,
            get_default_worker_public_key(),
            &input.spiderman_append_proof,
            &input.contract_leaves,
        )
    }
}

impl<S: QProofStoreReaderSync, C: GenericConfig<D>, const D: usize>
    QStandardCircuitProvableWithProofStoreSync<S, QCBatchDeployContractsCircuitInput<C::F, QHashOut<C::F>>, C, D>
    for BatchDeployContractsCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_with_proof_store_sync(
        &self,
        _store: &S,
        input: &QCBatchDeployContractsCircuitInput<C::F, QHashOut<C::F>>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_standard(input)
    }
}



#[async_trait]
impl<
        S: QProofStoreReaderAsync + Send + Sync,
        L: CircuitInfoLibrary<C, D> + Send + Sync,
        C: GenericConfig<D>,
        const D: usize,
    > QStandardCircuitProvableWithProofStoreAndRefLibraryAsync<S, L, C, D>
    for BatchDeployContractsCircuit<C, D>
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
        let input: QCBatchDeployContractsCircuitInput<C::F, QHashOut<C::F>> = bincode::deserialize(&store.get_bytes_by_id(job_id.get_input_witness_id()).await?)
                .map_err(|e| anyhow::anyhow!(e))?;
        tracing::debug!("QCBatchDeployContractsCircuitInput: {}", serde_json::to_string_pretty(&input).unwrap());

        let result = self.prove_base(
            input.deploy_contract_circuit_whitelist,
            worker_public_key,
            &input.spiderman_append_proof,
            &input.contract_leaves,
        )?;

        Ok(result)
    }
}
