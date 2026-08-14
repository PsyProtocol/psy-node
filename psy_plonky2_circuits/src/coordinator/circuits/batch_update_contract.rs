use parth_core::{
    crypto::hash::{
        spiderman::SpidermanUpdateProof,
        traits::{FieldQHasher, MerkleHasher},
    },
    felt::QFelt64,
    pgoldilocks::QHashOut,
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use plonky2::{
    hash::hash_types::HashOutTarget,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData,
            VerifierOnlyCircuitData,
        },
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use psy_data::{
    protocol::circuit_inputs::update_contracts::QCBatchUpdateContractsCircuitInput,
    v1::qdata::contract::PQEDContractLeafV2,
    worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse,
};
use psy_core::job::job_id::ProvingJobCircuitType;
use psy_plonky2_basic_helpers::builder::{
    hash::core::CircuitBuilderHashCore,
    pad_circuit::{pad_circuit_degree, CircuitBuilderQEDCommonGates},
};

use crate::{
    agg::common::compute_agg_state_trackable_final_public_inputs_leaf,
    coordinator::gadgets::update_contract::BatchUpdateContractsGadget,
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    qstandard::{
        QPsyNetworkCircuitWithType, QStandardCircuit,
        QStandardCircuitProvableWithRawProofsAndRefLibrary,
    },
    utils::proof_serialization::deserialize_plonky2_proof,
};
use psy_core::job::job_id::QProvingJobDataID;
use psy_plonky2_basic_helpers::verifier::circuit_library::CircuitInfoLibrary;
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

/// Standalone contract-update leaf circuit.
///
/// This deliberately has a separate Rust type and constructor from the V1
/// circuit, so deployments must explicitly select layout-aware verifier data.
#[derive(Debug)]
pub struct BatchUpdateContractsCircuit<
    C: GenericConfig<D>,
    const D: usize,
> {
    pub update_contract_batch_gadget: BatchUpdateContractsGadget<D>,
    pub update_contract_circuit_whitelist: HashOutTarget,
    pub worker_reward_tag: HashOutTarget,
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}

impl<C: GenericConfig<D>, const D: usize> QPsyNetworkCircuitWithType
    for BatchUpdateContractsCircuit<C, D>
{
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::BatchUpdateContracts
    }
}

impl<C: GenericConfig<D>, const D: usize>
    BatchUpdateContractsCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new(
        contract_tree_height: usize,
        batch_sub_tree_height: usize,
        layout_common_data: &CommonCircuitData<C::F, D>,
        layout_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> Self {
        let mut builder = CircuitBuilder::<C::F, D>::new(
            CircuitConfig::standard_recursion_config(),
        );
        let update_contract_circuit_whitelist =
            builder.add_virtual_hash();
        let worker_reward_tag = builder.add_virtual_hash();
        let update_contract_batch_gadget =
            BatchUpdateContractsGadget::add_virtual_to::<C>(
                &mut builder,
                contract_tree_height,
                batch_sub_tree_height,
                layout_common_data,
                layout_verifier_data,
            );
        let state_transition_hash =
            builder.hash_two_to_one::<C::Hasher>(
                update_contract_batch_gadget.spiderman.old_root,
                update_contract_batch_gadget.spiderman.new_root,
            );
        let public_inputs_hash =
            compute_agg_state_trackable_final_public_inputs_leaf::<
                C::Hasher,
                C::F,
                D,
            >(
                &mut builder,
                update_contract_circuit_whitelist,
                state_transition_hash,
                worker_reward_tag,
        );
        builder.register_public_inputs(&public_inputs_hash.elements);
        // Keep the layout-aware job on the protocol Type-D common-data shape.
        // Without this normalization every V2 leaf creates a new common-data
        // entry even though it belongs to the same recursive circuit family.
        builder.add_qed_type_d_common_gates();
        pad_circuit_degree(&mut builder, 12);
        let circuit_data = builder.build::<C>();
        let fingerprint = QHashOut(
            get_circuit_fingerprint_generic(
                &circuit_data.verifier_only,
            ),
        );
        Self {
            update_contract_batch_gadget,
            update_contract_circuit_whitelist,
            worker_reward_tag,
            circuit_data,
            fingerprint,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prove(
        &self,
        update_contract_circuit_whitelist: QHashOut<C::F>,
        worker_reward_tag: QHashOut<C::F>,
        spiderman_update_proof: &SpidermanUpdateProof<QHashOut<C::F>>,
        old_contract_leaves: &[PQEDContractLeafV2<C::F, QHashOut<C::F>>],
        new_contract_leaves: &[PQEDContractLeafV2<C::F, QHashOut<C::F>>],
        updated_contract_ids: &[u64],
        changed_layout_proofs: &[ProofWithPublicInputs<C::F, C, D>],
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut witness = PartialWitness::new();
        witness.set_hash_target(
            self.update_contract_circuit_whitelist,
            update_contract_circuit_whitelist.0,
        )?;
        witness
            .set_hash_target(self.worker_reward_tag, worker_reward_tag.0)?;
        self.update_contract_batch_gadget.set_witness::<C>(
            &mut witness,
            spiderman_update_proof,
            old_contract_leaves,
            new_contract_leaves,
            updated_contract_ids,
            changed_layout_proofs,
        )?;
        self.circuit_data.prove(witness)
    }

    pub fn layout_proof_targets(
        &self,
    ) -> &[ProofWithPublicInputsTarget<D>] {
        &self.update_contract_batch_gadget.layout_proofs
    }
}

impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D>
    for BatchUpdateContractsCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        self.fingerprint
    }

    fn get_verifier_config_ref(
        &self,
    ) -> &VerifierOnlyCircuitData<C, D> {
        &self.circuit_data.verifier_only
    }

    fn get_common_circuit_data_ref(
        &self,
    ) -> &CommonCircuitData<C::F, D> {
        &self.circuit_data.common
    }
}

impl<
        L: CircuitInfoLibrary<C, D>,
        C: GenericConfig<D>,
        const D: usize,
    > QStandardCircuitProvableWithRawProofsAndRefLibrary<L, C, D>
    for BatchUpdateContractsCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>
        + FieldQHasher<C::F, QHashOut<C::F>>
        + MerkleHasher<QHashOut<C::F>>,
    QHashOut<C::F>: Q256BitHash + QFHashBase<C::F>,
    C::F: QFelt64,
{
    fn prove_with_raw_proofs_and_ref_library(
        &self,
        _library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<
            QHashOut<C::F>,
            QProvingJobDataID,
        >,
        worker_reward_tag: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let witness: QCBatchUpdateContractsCircuitInput<
            C::F,
            QHashOut<C::F>,
        > = QCBatchUpdateContractsCircuitInput::psy_ser_from_slice(
            &input.base.witness,
        )?;
        witness.validate::<C::Hasher>()?;
        let layout_proofs = witness
            .layout_update_proofs
            .iter()
            .map(|proof| deserialize_plonky2_proof::<C, D>(proof))
            .collect::<anyhow::Result<Vec<_>>>()?;
        self.prove(
            witness.update_contract_circuit_whitelist,
            worker_reward_tag,
            &witness.spiderman_update_proof,
            &witness.old_contract_leaves,
            &witness.new_contract_leaves,
            &witness.updated_contract_ids,
            &layout_proofs,
        )
    }
}
