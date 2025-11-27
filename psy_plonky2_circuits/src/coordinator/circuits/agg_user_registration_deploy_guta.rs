use async_trait::async_trait;
use parth_core::{
    crypto::hash::{merkle_proof::MerkleProofCore, traits::MerkleZeroHasher},
    felt::QFelt64,
    pgoldilocks::{QHashOut, QRichField},
    protocol::core_types::Q256BitHash,
};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{
    agg::{AggStateTransition, TPAltCircuitFingerprintConfig},
    guta::header::GlobalUserTreeAggregatorHeader,
    protocol::circuit_inputs::agg_part_1::QCAggUserRegistartionDeployContractsGUTAInput,
    worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse,
};
use psy_plonky2_basic_helpers::{builder::pad_circuit::CircuitBuilderQEDCommonGates, verifier::circuit_library::CircuitInfoLibrary};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::{
    coordinator::gadgets::verify_agg_user_registration_deploy_guta::VerifyAggUserRegistartionDeployContractsGUTAGadget,
    proof_minifier::{pm_chain_dynamic::QEDProofMinifierDynamicChain, pm_core::get_circuit_fingerprint_generic},
    qstandard::{
        QPsyNetworkCircuitWithType, QStandardCircuit, QStandardCircuitProvableWithRawProofsAndRefLibrary,
    },
    utils::proof_serialization::deserialize_plonky2_proof,
};

#[derive(Debug)]
pub struct VerifyAggUserRegistartionDeployContractsGUTACircuit<C: GenericConfig<D>, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub verifier_gadget: VerifyAggUserRegistartionDeployContractsGUTAGadget<D>,

    pub worker_rewards_tree_tag_target: HashOutTarget,

    pub base_circuit_data: CircuitData<C::F, C, D>,
    pub base_fingerprint: QHashOut<C::F>,
    pub minifier_chain: Option<QEDProofMinifierDynamicChain<D, C::F, C>>,
    pub enable_minifier: bool,
}

impl<C: GenericConfig<D>, const D: usize> QPsyNetworkCircuitWithType for VerifyAggUserRegistartionDeployContractsGUTACircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::AggUserRegisterDeployContractsGUTA
    }
}
impl<C: GenericConfig<D>, const D: usize> VerifyAggUserRegistartionDeployContractsGUTACircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> + MerkleZeroHasher<QHashOut<C::F>>,
    C::F: QRichField,
{
    pub fn new(
        user_reg_proof_common_data: &CommonCircuitData<C::F, D>,
        user_reg_transition_circuit_config: &TPAltCircuitFingerprintConfig<QHashOut<C::F>>,

        deploy_contracts_proof_common_data: &CommonCircuitData<C::F, D>,
        deploy_contracts_transition_circuit_config: &TPAltCircuitFingerprintConfig<QHashOut<C::F>>,

        guta_proof_common_data: &CommonCircuitData<C::F, D>,
        guta_verifier_data_cap_height: usize,
        guta_circuit_whitelist_tree_height: u8,
        guta_circuit_whitelist_root: QHashOut<C::F>,
    ) -> Self {
        Self::new_with_config(
            user_reg_proof_common_data,
            user_reg_transition_circuit_config,
            deploy_contracts_proof_common_data,
            deploy_contracts_transition_circuit_config,
            guta_proof_common_data,
            guta_verifier_data_cap_height,
            guta_circuit_whitelist_tree_height,
            guta_circuit_whitelist_root,
            false,
        )
    }
    pub fn new_with_config(
        user_reg_proof_common_data: &CommonCircuitData<C::F, D>,
        user_reg_transition_circuit_config: &TPAltCircuitFingerprintConfig<QHashOut<C::F>>,

        deploy_contracts_proof_common_data: &CommonCircuitData<C::F, D>,
        deploy_contracts_transition_circuit_config: &TPAltCircuitFingerprintConfig<QHashOut<C::F>>,

        guta_proof_common_data: &CommonCircuitData<C::F, D>,
        guta_verifier_data_cap_height: usize,
        guta_circuit_whitelist_tree_height: u8,
        guta_circuit_whitelist_root: QHashOut<C::F>,

        has_minifier: bool,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let verifier_gadget = VerifyAggUserRegistartionDeployContractsGUTAGadget::<D>::add_virtual_to::<C, C::F>(
            &mut builder,
            user_reg_proof_common_data,
            user_reg_transition_circuit_config,
            deploy_contracts_proof_common_data,
            deploy_contracts_transition_circuit_config,
            guta_proof_common_data,
            guta_verifier_data_cap_height,
            guta_circuit_whitelist_root,
            guta_circuit_whitelist_tree_height,
        );

        // compute public inputs hash
        let guta_proof_rewards_tree_value = verifier_gadget.verify_guta_gadget.rewards_tree_value;
        let register_users_proof_rewards_tree_value = verifier_gadget.verify_register_users_gadget.rewards_tree_value;
        let deploy_contracts_proof_rewards_tree_value = verifier_gadget.verify_deploy_contract_gadget.rewards_tree_value;
        let worker_rewards_tree_tag_target = builder.add_virtual_hash();
        let public_inputs_hash = verifier_gadget.header.get_public_inputs_hash::<C::Hasher, C::F, D>(
            &mut builder,
            worker_rewards_tree_tag_target,
            guta_proof_rewards_tree_value,
            register_users_proof_rewards_tree_value,
            deploy_contracts_proof_rewards_tree_value,
        );
        builder.add_qed_type_f_common_gates();
        
        builder.register_public_inputs(&public_inputs_hash.elements);

        let base_circuit_data = builder.build::<C>();

        let base_fingerprint = QHashOut(get_circuit_fingerprint_generic(&base_circuit_data.verifier_only));
        //println!("base_fingerprint: {:?}",base_fingerprint);

        let minifier_chain = if has_minifier {
            Some(QEDProofMinifierDynamicChain::<D, C::F, C>::new_with_dynamic_constant_verifier(
                &base_circuit_data.verifier_only,
                &base_circuit_data.common,
                &[false, false],
            ))
        } else {
            None
        };

        Self {
            verifier_gadget,
            worker_rewards_tree_tag_target,
            base_circuit_data,
            base_fingerprint,
            minifier_chain,
            enable_minifier: has_minifier,
        }
    }

    pub fn prove_base(
        &self,
        worker_reward_tag: QHashOut<C::F>,
        register_users_state_transition: &AggStateTransition<QHashOut<C::F>>,
        register_users_proof: &ProofWithPublicInputs<C::F, C, D>,
        register_users_verifier_data: &VerifierOnlyCircuitData<C, D>,
        register_users_proof_rewards_tree_value: QHashOut<C::F>,
        register_users_total_proofs_generated: C::F,

        deploy_contracts_state_transition: &AggStateTransition<QHashOut<C::F>>,
        deploy_contracts_proof: &ProofWithPublicInputs<C::F, C, D>,
        deploy_contracts_verifier_data: &VerifierOnlyCircuitData<C, D>,
        deploy_contracts_proof_rewards_tree_value: QHashOut<C::F>,
        deploy_contracts_total_proofs_generated: C::F,

        guta_whitelist_merkle_proof: &MerkleProofCore<QHashOut<C::F>>,
        guta_proof_header: &GlobalUserTreeAggregatorHeader<C::F, QHashOut<C::F>>,
        guta_proof: &ProofWithPublicInputs<C::F, C, D>,
        guta_verifier_data: &VerifierOnlyCircuitData<C, D>,
        guta_proof_rewards_tree_value: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();

        tracing::debug!(
            "register_users_state_transition: {}",
            register_users_state_transition.get_combined_hash::<C::Hasher>()
        );
        tracing::debug!(
            "deploy_contracts_state_transition: {}",
            deploy_contracts_state_transition.get_combined_hash::<C::Hasher>()
        );

        pw.set_hash_target(self.worker_rewards_tree_tag_target, worker_reward_tag.0)?;

        self.verifier_gadget.set_witness_params(
            &mut pw,
            register_users_state_transition,
            register_users_proof,
            register_users_verifier_data,
            register_users_proof_rewards_tree_value,
            register_users_total_proofs_generated,
            deploy_contracts_state_transition,
            deploy_contracts_proof,
            deploy_contracts_verifier_data,
            deploy_contracts_proof_rewards_tree_value,
            deploy_contracts_total_proofs_generated,
            guta_whitelist_merkle_proof,
            guta_proof_header,
            guta_proof,
            guta_verifier_data,
            guta_proof_rewards_tree_value,
        )?;

        let res = self.base_circuit_data.prove(pw)?;

        if self.enable_minifier {
            self.minifier_chain.as_ref().unwrap().prove(&res)
        } else {
            Ok(res)
        }
    }
}

impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D> for VerifyAggUserRegistartionDeployContractsGUTACircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        if self.enable_minifier {
            QHashOut(self.minifier_chain.as_ref().unwrap().get_fingerprint())
        } else {
            self.base_fingerprint
        }
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        if self.enable_minifier {
            self.minifier_chain.as_ref().unwrap().get_verifier_data()
        } else {
            &self.base_circuit_data.verifier_only
        }
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        if self.enable_minifier {
            self.minifier_chain.as_ref().unwrap().get_common_data()
        } else {
            &self.base_circuit_data.common
        }
    }
}

impl<L: CircuitInfoLibrary<C, D>, C: GenericConfig<D>, const D: usize> QStandardCircuitProvableWithRawProofsAndRefLibrary<L, C, D>
    for VerifyAggUserRegistartionDeployContractsGUTACircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> + MerkleZeroHasher<QHashOut<C::F>>,
    QHashOut<C::F>: Q256BitHash,
    C::F: QFelt64 + QRichField,
{
    fn prove_with_raw_proofs_and_ref_library(
        &self,
        library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<QHashOut<C::F>, QProvingJobDataID>,
        worker_reward_tag: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        input.ensure_expected_child_proof_count_with_tags(3)?;
        let witness = QCAggUserRegistartionDeployContractsGUTAInput::<C::F, QHashOut<C::F>>::psy_ser_from_slice(&input.base.witness)?;

        let guta_zk_proof = deserialize_plonky2_proof::<C, D>(&input.input_proofs[0])?;
        let guta_zk_proof_verifier_data = library.get_verifier_data(input.get_child_proof_circuit_type(0)?)?;
        let guta_inclusion_proof = library.get_group_inclusion_proof(ProvingJobCircuitType::GUTATwoGUTA, input.get_child_proof_circuit_type(0)?)?;
        let guta_proof_rewards_tree_value = input.base.child_proof_tag_values[0];

        let user_registration_zk_proof = deserialize_plonky2_proof::<C, D>(&input.input_proofs[1])?;
        let user_registration_zk_proof_verifier_data = library.get_verifier_data(input.get_child_proof_circuit_type(1)?)?;
        let register_users_proof_rewards_tree_value = input.base.child_proof_tag_values[1];

        let deploy_contracts_zk_proof = deserialize_plonky2_proof::<C, D>(&input.input_proofs[2])?;
        let deploy_contracts_zk_proof_verifier_data = library.get_verifier_data(input.get_child_proof_circuit_type(2)?)?;
        let deploy_contracts_proof_rewards_tree_value = input.base.child_proof_tag_values[2];


        let (register_users_state_transition, register_users_total_proofs_generated) =
            witness.register_users_state_transition.get_agg_state_transition_and_f::<C::F>();
        let (deploy_contracts_state_transition, deploy_contracts_total_proofs_generated) =
            witness.deploy_contracts_state_transition.get_agg_state_transition_and_f::<C::F>();

        self.prove_base(
            worker_reward_tag,
            &register_users_state_transition,
            &user_registration_zk_proof,
            &user_registration_zk_proof_verifier_data,
            register_users_proof_rewards_tree_value,
            register_users_total_proofs_generated,
            &deploy_contracts_state_transition,
            &deploy_contracts_zk_proof,
            &deploy_contracts_zk_proof_verifier_data,
            deploy_contracts_proof_rewards_tree_value,
            deploy_contracts_total_proofs_generated,
            &guta_inclusion_proof,
            &witness.guta_proof_header,
            &guta_zk_proof,
            &guta_zk_proof_verifier_data,
            guta_proof_rewards_tree_value,
        )
    }
}
