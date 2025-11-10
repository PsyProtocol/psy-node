use async_trait::async_trait;
use parth_core::pgoldilocks::QHashOut;
use plonky2::{
    hash::
        hash_types::{HashOut, HashOutTarget}
    ,
    iop::{target::Target, witness::{PartialWitness, WitnessWrite}},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData,
        },
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_core::{constants::protocol::get_default_worker_public_key, job::job_id::QProvingJobDataID};
use psy_data::agg::DummyAggStateTransition;
use psy_plonky2_basic_helpers::{builder::{hash::core::CircuitBuilderHashCore, pad_circuit::{pad_circuit_degree, CircuitBuilderQEDCommonGates}}, verifier::circuit_library::CircuitInfoLibrary};

use crate::{proof_minifier::pm_core::get_circuit_fingerprint_generic, qstandard::{proof_store::{QProofStoreReaderAsync, QProofStoreReaderSync}, provable::QStandardCircuitProvable, QStandardCircuit, QStandardCircuitProvableWithProofStoreAndRefLibraryAsync, QStandardCircuitProvableWithProofStoreSync}};
use plonky2::field::types::Field;


#[derive(Debug)]
pub struct AggStateTransitionDummyCircuit<C: GenericConfig<D>, const D: usize>
{
    pub state_transition_hash: HashOutTarget,
    pub allowed_circuit_hashes_root: HashOutTarget,
    pub worker_public_key: HashOutTarget,
    pub is_deploy_contracts: Target,
    pub is_register_users: Target,
    pub pm_jobs_completed: [Target; 3],

    // end circuit targets
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}
impl<C: GenericConfig<D>, const D: usize> AggStateTransitionDummyCircuit<C, D>
where
    C::Hasher:AlgebraicHasher<C::F>,
{
    pub fn new() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let state_transition_hash = builder.add_virtual_hash();
        let allowed_circuit_hashes_root = builder.add_virtual_hash();
        let worker_public_key = builder.add_virtual_hash();
        let is_deploy_contracts = builder.add_virtual_target();
        let is_register_users = builder.add_virtual_target();

        let sum = builder.add(is_deploy_contracts, is_register_users);
        let one = builder.one();
        builder.connect(sum, one);

        let zero = builder.zero();
        let pm_jobs_completed = [
            is_deploy_contracts,
            is_register_users,
            zero,
        ];

        // builder.assert_non_zero_hash(worker_public_key);

        let zero_hash = builder.constant_hash(HashOut::ZERO);
        let commitment = builder.hash_two_to_one::<C::Hasher>(zero_hash, zero_hash);

        let transition =
            builder.hash_two_to_one::<C::Hasher>(state_transition_hash, state_transition_hash);

        builder.register_public_inputs(&commitment.elements);
        builder.register_public_inputs(&worker_public_key.elements);
        builder.register_public_inputs(&pm_jobs_completed);
        builder.register_public_inputs(&allowed_circuit_hashes_root.elements);
        builder.register_public_inputs(&transition.elements);

        builder.add_qed_type_d_common_gates();
        pad_circuit_degree::<C::F, D>(&mut builder, 12);
        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));

        Self {
            state_transition_hash,
            allowed_circuit_hashes_root,
            worker_public_key,
            is_deploy_contracts,
            is_register_users,
            pm_jobs_completed,
            circuit_data,
            fingerprint,
        }
    }
    pub fn prove_base(
        &self,
        worker_public_key: QHashOut<C::F>,
        state_transition_hash: QHashOut<C::F>,
        allowed_circuit_hashes_root: QHashOut<C::F>,
        is_deploy_contracts: bool,
        is_register_users: bool,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();
        pw.set_hash_target(self.worker_public_key, worker_public_key.0)?;
        pw.set_hash_target(self.state_transition_hash, state_transition_hash.0)?;
        pw.set_hash_target(
            self.allowed_circuit_hashes_root,
            allowed_circuit_hashes_root.0,
        )?;
        pw.set_target(self.is_deploy_contracts, if is_deploy_contracts { C::F::ONE } else { C::F::ZERO })?;
        pw.set_target(self.is_register_users, if is_register_users { C::F::ONE } else { C::F::ZERO })?;
        self.circuit_data.prove(pw)
    }
}

/*
impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D>
    for AggStateTransitionDummyCircuit<C, D>
where
    C::Hasher:AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        QHashOut(self.minifier_chain.get_fingerprint())
    }
    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        self.minifier_chain.get_verifier_data()
    }
    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        self.minifier_chain.get_common_data()
    }
}
*/

impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D>
    for AggStateTransitionDummyCircuit<C, D>
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
    QStandardCircuitProvable<DummyAggStateTransition<QHashOut<C::F>>, C, D>
    for AggStateTransitionDummyCircuit<C, D>
where
    C::Hasher:AlgebraicHasher<C::F>,
{
    fn prove_standard(
        &self,
        input: &DummyAggStateTransition<QHashOut<C::F>>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_base(
            get_default_worker_public_key(),
            input.unmodified_state_tree_root,
            input.allowed_circuit_hashes_root,
            input.is_deploy_contracts,
            input.is_register_users,
        )
    }
}

impl<S: QProofStoreReaderSync, C: GenericConfig<D>, const D: usize>
    QStandardCircuitProvableWithProofStoreSync<S, DummyAggStateTransition<QHashOut<C::F>>, C, D>
    for AggStateTransitionDummyCircuit<C, D>
where
    C::Hasher:AlgebraicHasher<C::F>,
{
    fn prove_with_proof_store_sync(
        &self,
        _store: &S,
        input: &DummyAggStateTransition<QHashOut<C::F>>,
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
    for AggStateTransitionDummyCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>
{
    async fn prove_with_proof_store_async(
        &self,
        store: &S,
        _library: &L,
        job_id: QProvingJobDataID,
        worker_public_key: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let r: DummyAggStateTransition<QHashOut<C::F>> =
            bincode::deserialize(&store.get_bytes_by_id(job_id.get_input_witness_id()).await?)
                .map_err(|e| anyhow::anyhow!(e))?;
        self.prove_base(
            worker_public_key,
            r.unmodified_state_tree_root,
            r.allowed_circuit_hashes_root,
            r.is_deploy_contracts,
            r.is_register_users,
        )
    }
}
