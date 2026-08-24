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
        proof::ProofWithPublicInputs,
    },
};
use psy_data::{
    protocol::circuit_inputs::deploy_contracts::QCBatchDeployContractsCircuitInput,
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
    coordinator::gadgets::deploy_contract_v2::BatchDeployContractsGadget,
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

/// Standalone layout-aware deploy leaf circuit.
#[derive(Debug)]
pub struct BatchDeployContractsCircuit<
    C: GenericConfig<D>,
    const D: usize,
> {
    pub deploy_gadget: BatchDeployContractsGadget<D>,
    pub deploy_contract_circuit_whitelist: HashOutTarget,
    pub worker_reward_tag: HashOutTarget,
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}

impl<C: GenericConfig<D>, const D: usize> QPsyNetworkCircuitWithType
    for BatchDeployContractsCircuit<C, D>
{
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::BatchDeployContracts
    }
}

impl<C: GenericConfig<D>, const D: usize>
    BatchDeployContractsCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_tree_height: usize,
        batch_sub_tree_height: usize,
        state_layout_tree_height: usize,
        max_contract_state_tree_height: usize,
        layout_common_data: &CommonCircuitData<C::F, D>,
        layout_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> Self {
        let mut builder = CircuitBuilder::<C::F, D>::new(
            CircuitConfig::standard_recursion_config(),
        );
        let deploy_contract_circuit_whitelist =
            builder.add_virtual_hash();
        let worker_reward_tag = builder.add_virtual_hash();
        let deploy_gadget =
            BatchDeployContractsGadget::add_virtual_to::<C>(
                &mut builder,
                contract_tree_height,
                batch_sub_tree_height,
                state_layout_tree_height,
                max_contract_state_tree_height,
                layout_common_data,
                layout_verifier_data,
            );
        let transition_hash =
            builder.hash_two_to_one::<C::Hasher>(
                deploy_gadget.spiderman.old_root,
                deploy_gadget.spiderman.new_root,
            );
        let public_inputs_hash =
            compute_agg_state_trackable_final_public_inputs_leaf::<
                C::Hasher,
                C::F,
                D,
            >(
                &mut builder,
                deploy_contract_circuit_whitelist,
                transition_hash,
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
            deploy_gadget,
            deploy_contract_circuit_whitelist,
            worker_reward_tag,
            circuit_data,
            fingerprint,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prove(
        &self,
        deploy_contract_circuit_whitelist: QHashOut<C::F>,
        worker_reward_tag: QHashOut<C::F>,
        spiderman_proof: &SpidermanUpdateProof<QHashOut<C::F>>,
        contract_ids: &[u64],
        contract_leaves: &[PQEDContractLeafV2<C::F, QHashOut<C::F>>],
        layout_proofs: &[ProofWithPublicInputs<C::F, C, D>],
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut witness = PartialWitness::new();
        witness.set_hash_target(
            self.deploy_contract_circuit_whitelist,
            deploy_contract_circuit_whitelist.0,
        )?;
        witness.set_hash_target(
            self.worker_reward_tag,
            worker_reward_tag.0,
        )?;
        self.deploy_gadget.set_witness::<C>(
            &mut witness,
            spiderman_proof,
            contract_ids,
            contract_leaves,
            layout_proofs,
        )?;
        self.circuit_data.prove(witness)
    }
}

impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D>
    for BatchDeployContractsCircuit<C, D>
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
    for BatchDeployContractsCircuit<C, D>
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
        let witness =
            QCBatchDeployContractsCircuitInput::<
                C::F,
                QHashOut<C::F>,
            >::psy_ser_from_slice(&input.base.witness)?;
        witness.validate::<C::Hasher>()?;
        let layout_proofs = witness
            .initial_layout_proofs
            .iter()
            .map(|proof| deserialize_plonky2_proof::<C, D>(proof))
            .collect::<anyhow::Result<Vec<_>>>()?;
        self.prove(
            witness.deploy_contract_circuit_whitelist,
            worker_reward_tag,
            &witness.spiderman_append_proof,
            &witness.contract_ids,
            &witness.contract_leaves,
            &layout_proofs,
        )
    }
}

#[cfg(test)]
mod tests {
    use plonky2::plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::PoseidonGoldilocksConfig,
    };

    use super::*;
    use crate::gadgets::qdata::state_layout::LayoutAppendPublicInputsGadget;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    fn dummy_layout_circuit() -> CircuitData<
        <C as GenericConfig<D>>::F,
        C,
        D,
    > {
        let mut builder = CircuitBuilder::new(
            CircuitConfig::standard_recursion_config(),
        );
        for _ in 0..LayoutAppendPublicInputsGadget::PUBLIC_INPUT_COUNT {
            builder.add_virtual_public_input();
        }
        builder.build::<C>()
    }

    #[test]
    fn builds_distinct_v2_deploy_circuit_with_layout_proofs() {
        let layout = dummy_layout_circuit();
        let circuit = BatchDeployContractsCircuit::<C, D>::new(
            4,
            1,
            3,
            8,
            &layout.common,
            &layout.verifier_only,
        );
        assert_eq!(circuit.deploy_gadget.contract_leaves.len(), 2);
        assert_eq!(circuit.deploy_gadget.layout_proofs.len(), 2);
        assert_eq!(circuit.circuit_data.common.num_public_inputs, 4);
    }
}
