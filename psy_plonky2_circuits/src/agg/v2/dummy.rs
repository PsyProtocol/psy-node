use async_trait::async_trait;
use parth_core::{pgoldilocks::QHashOut, protocol::core_types::Q256BitHash};
use plonky2::{
    hash::
        hash_types::HashOutTarget
    ,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData,
        },
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::{agg::DummyAggStateTransition, worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse};
use psy_plonky2_basic_helpers::{builder::{hash::core::CircuitBuilderHashCore, pad_circuit::{pad_circuit_degree, CircuitBuilderQEDCommonGates}}, verifier::circuit_library::CircuitInfoLibrary};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::{agg::common::compute_agg_state_trackable_final_public_inputs_leaf, proof_minifier::pm_core::get_circuit_fingerprint_generic, qstandard::{QStandardCircuit, QStandardCircuitProvableWithRawProofsAndRefLibraryAsync}};


#[derive(Debug)]
pub struct AggStateTransitionDummyCircuitV2<C: GenericConfig<D>, const D: usize>
{
    pub allowed_circuit_hashes_root: HashOutTarget,
    pub unmodified_state_root: HashOutTarget,
    pub worker_reward_tag: HashOutTarget,
    // end circuit targets
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}
impl<C: GenericConfig<D>, const D: usize> AggStateTransitionDummyCircuitV2<C, D>
where
    C::Hasher:AlgebraicHasher<C::F>,
{
    pub fn new() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let allowed_circuit_hashes_root = builder.add_virtual_hash();
        let unmodified_state_root = builder.add_virtual_hash();
        let state_transition_hash = builder.hash_two_to_one::<C::Hasher>(unmodified_state_root, unmodified_state_root);
        let worker_reward_tag = builder.add_virtual_hash();

        let public_inputs_hash = compute_agg_state_trackable_final_public_inputs_leaf::<C::Hasher, C::F, D>(
            &mut builder,
            allowed_circuit_hashes_root,
            state_transition_hash,
            worker_reward_tag,
        );

        builder.register_public_inputs(&public_inputs_hash.elements);

        builder.add_qed_type_d_common_gates();
        pad_circuit_degree::<C::F, D>(&mut builder, 12);
        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));

        Self {
            unmodified_state_root,
            allowed_circuit_hashes_root,
            circuit_data,
            fingerprint,
            worker_reward_tag,
        }
    }
    pub fn prove_base(
        &self,
        allowed_circuit_hashes_root: QHashOut<C::F>,
        unmodified_state_root: QHashOut<C::F>,
        worker_reward_tag: QHashOut<C::F>,


    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();
        pw.set_hash_target(self.allowed_circuit_hashes_root, allowed_circuit_hashes_root.0)?;
        pw.set_hash_target(self.unmodified_state_root, unmodified_state_root.0)?;
        pw.set_hash_target(
            self.allowed_circuit_hashes_root,
            allowed_circuit_hashes_root.0,
        )?;
        pw.set_hash_target(self.worker_reward_tag, worker_reward_tag.0)?;

        self.circuit_data.prove(pw)
    }
}

/*
impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D>
    for AggStateTransitionDummyCircuitV2<C, D>
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
    for AggStateTransitionDummyCircuitV2<C, D>
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
        L: CircuitInfoLibrary<C, D> + Send + Sync,
        C: GenericConfig<D>,
        const D: usize,
    > QStandardCircuitProvableWithRawProofsAndRefLibraryAsync<L, C, D>
    for AggStateTransitionDummyCircuitV2<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>, QHashOut<C::F>: Q256BitHash,
{

    async fn prove_with_raw_proofs_and_ref_library_async(
        &self,
        _library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<QHashOut<C::F>, QProvingJobDataID>,
        worker_reward_tag: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>{
        let witness = DummyAggStateTransition::<QHashOut<C::F>>::psy_ser_from_slice(&input.base.witness)?;
        self.prove_base(witness.allowed_circuit_hashes_root, witness.unmodified_state_tree_root, worker_reward_tag)

    }
}

