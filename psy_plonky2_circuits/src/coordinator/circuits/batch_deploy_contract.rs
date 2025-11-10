use async_trait::async_trait;
use parth_core::{crypto::hash::{spiderman::SpidermanUpdateProof, traits::MerkleZeroHasher}, felt::QFelt64, pgoldilocks::QHashOut, protocol::core_types::Q256BitHash};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget}, iop::
        witness::{PartialWitness, WitnessWrite}, plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    }
};
use psy_core::{constants::protocol::get_default_worker_public_key, job::job_id::{ProvingJobCircuitType, QProvingJobDataID}};
use psy_data::{protocol::circuit_inputs::deploy_contracts::QCBatchDeployContractsCircuitInput, v1::qdata::contract::PQEDContractLeaf, worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse};
use psy_plonky2_basic_helpers::{
    builder::{hash::core::CircuitBuilderHashCore, pad_circuit::{pad_circuit_degree, CircuitBuilderQEDCommonGates}}, verifier::circuit_library::CircuitInfoLibrary,
   
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
use crate::{agg::common::compute_agg_state_trackable_final_public_inputs_leaf, coordinator::gadgets::deploy_contract::BatchDeployContractsGadget, proof_minifier::pm_core::get_circuit_fingerprint_generic, qstandard::{QPsyNetworkCircuitWithType, QStandardCircuit, QStandardCircuitProvableWithProofStoreAndRefLibraryAsync, QStandardCircuitProvableWithProofStoreSync, QStandardCircuitProvableWithRawProofsAndRefLibraryAsync, proof_store::{QProofStoreReaderAsync, QProofStoreReaderSync}, provable::QStandardCircuitProvable}};


#[derive(Debug)]
pub struct BatchDeployContractsCircuit<C: GenericConfig<D>, const D: usize>
{
    pub deploy_contract_batch_gadget: BatchDeployContractsGadget,
    pub deploy_contract_circuit_whitelist: HashOutTarget,
    pub worker_reward_tag: HashOutTarget,


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
        let worker_reward_tag = builder.add_virtual_hash();

        // builder.assert_non_zero_hash(worker_reward_tag);

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


        let public_inputs_hash = compute_agg_state_trackable_final_public_inputs_leaf::<C::Hasher, C::F, D>(
            &mut builder,
            deploy_contract_circuit_whitelist,
            state_transition_hash,
            worker_reward_tag,
        );
        builder.register_public_inputs(&public_inputs_hash.elements);
        builder.add_qed_type_d_common_gates();
        pad_circuit_degree(&mut builder, 12);

        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(
            &circuit_data.verifier_only,
        ));

        Self {
            deploy_contract_circuit_whitelist,
            worker_reward_tag,
            deploy_contract_batch_gadget,
            circuit_data,
            fingerprint,
        }
    }

    pub fn prove_base(
        &self,
        deploy_contract_circuit_whitelist: QHashOut<C::F>,
        worker_reward_tag: QHashOut<C::F>,
        spiderman_append_proof: &SpidermanUpdateProof<QHashOut<C::F>>,
        contract_leaves: &[PQEDContractLeaf<C::F, QHashOut<C::F>>],
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();
        pw.set_hash_target(self.deploy_contract_circuit_whitelist, deploy_contract_circuit_whitelist.0)?;
        pw.set_hash_target(self.worker_reward_tag, worker_reward_tag.0)?;


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
        worker_reward_tag: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let input: QCBatchDeployContractsCircuitInput<C::F, QHashOut<C::F>> = bincode::deserialize(&store.get_bytes_by_id(job_id.get_input_witness_id()).await?)
                .map_err(|e| anyhow::anyhow!(e))?;
        tracing::debug!("QCBatchDeployContractsCircuitInput: {}", serde_json::to_string_pretty(&input).unwrap());

        let result = self.prove_base(
            input.deploy_contract_circuit_whitelist,
            worker_reward_tag,
            &input.spiderman_append_proof,
            &input.contract_leaves,
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
    for BatchDeployContractsCircuit<C, D>
where
     C::Hasher:AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>, QHashOut<C::F>: Q256BitHash, C::F: QFelt64,
{

    async fn prove_with_raw_proofs_and_ref_library_async(
        &self,
        _library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<QHashOut<C::F>, QProvingJobDataID>,
        worker_reward_tag: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>{

        let witness = QCBatchDeployContractsCircuitInput::<C::F, QHashOut<C::F>>::psy_ser_from_slice(&input.base.witness)?;
        self.prove_base(
            witness.deploy_contract_circuit_whitelist,
            worker_reward_tag,
            &witness.spiderman_append_proof,
            &witness.contract_leaves,
        )
    }
}
