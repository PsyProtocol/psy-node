use parth_core::{crypto::hash::merkle_proof::MerkleProofCore, pgoldilocks::QHashOut};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_data::{
    agg::{AggStateTransition, TPAltCircuitFingerprintConfig},
    guta::header::GlobalUserTreeAggregatorHeader,
};
use psy_plonky2_basic_helpers::builder::hash::core::CircuitBuilderHashCore;

use crate::{
    gadgets::{
        qdata::pm_jobs_completed_stats::PMJobsCompletedStatsGadget, tag_tree::hash_tag_tree_node_four_circuit, treeprover::{AggStateTransitionGadget, VerifyStateTransitionProofGadget}
    },
    guta::gadgets::{guta_header::GlobalUserTreeAggregatorHeaderGadget, verify_guta_proof::VerifyGUTAProofGadget},
};
#[derive(Debug, Clone)]
pub struct VerifyAggUserRegistartionDeployContractsGUTAHeaderGadget {
    pub user_registration_tree_delta: AggStateTransitionGadget,
    pub global_contract_tree_delta: AggStateTransitionGadget,
    pub global_user_tree_delta: GlobalUserTreeAggregatorHeaderGadget,
    pub combined_pm_jobs_completed: PMJobsCompletedStatsGadget,
}

impl VerifyAggUserRegistartionDeployContractsGUTAHeaderGadget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        let user_registration_tree_delta = AggStateTransitionGadget::add_virtual_to(builder);
        let global_contract_tree_delta = AggStateTransitionGadget::add_virtual_to(builder);
        let global_user_tree_delta = GlobalUserTreeAggregatorHeaderGadget::add_virtual_to(builder);


        let combined_pm_jobs_completed = PMJobsCompletedStatsGadget {
            deploy_contracts_completed: builder.add_virtual_target(),
            register_users_completed: builder.add_virtual_target(),
            gutas_completed:global_user_tree_delta.total_aggregation_proofs_generated,
        };
        Self {
            user_registration_tree_delta,
            global_contract_tree_delta,
            global_user_tree_delta,
            combined_pm_jobs_completed,
        }
    }
    pub fn add_virtual_to_known_completions<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>, deploy_contracts_completed: Target, register_users_completed: Target) -> Self {
        let user_registration_tree_delta = AggStateTransitionGadget::add_virtual_to(builder);
        let global_contract_tree_delta = AggStateTransitionGadget::add_virtual_to(builder);
        let global_user_tree_delta = GlobalUserTreeAggregatorHeaderGadget::add_virtual_to(builder);


        let combined_pm_jobs_completed = PMJobsCompletedStatsGadget {
            deploy_contracts_completed,
            register_users_completed,
            gutas_completed:global_user_tree_delta.total_aggregation_proofs_generated,
        };
        Self {
            user_registration_tree_delta,
            global_contract_tree_delta,
            global_user_tree_delta,
            combined_pm_jobs_completed,
        }
    }

    pub fn get_combined_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        let user_regsitration_deploy_contract_start = builder.hash_two_to_one::<H>(
            self.user_registration_tree_delta.state_transition_start,
            self.global_contract_tree_delta.state_transition_start,
        );
        let user_regsitration_deploy_contract_end = builder.hash_two_to_one::<H>(
            self.user_registration_tree_delta.state_transition_end,
            self.global_contract_tree_delta.state_transition_end,
        );
        let user_regsitration_deploy_contract_combo =
            builder.hash_two_to_one::<H>(user_regsitration_deploy_contract_start, user_regsitration_deploy_contract_end);

        let guta_hash = self.global_user_tree_delta.to_hash::<H, F, D>(builder);
        

        let combo_without_stats = builder.hash_two_to_one::<H>(user_regsitration_deploy_contract_combo, guta_hash);
        let stats_hash = HashOutTarget {
            elements: [
                self.combined_pm_jobs_completed.deploy_contracts_completed,
                self.combined_pm_jobs_completed.register_users_completed,
                self.combined_pm_jobs_completed.gutas_completed,
                builder.zero(),
            ]
        };
        builder.hash_two_to_one::<H>(combo_without_stats, stats_hash)
    }

    pub fn get_expected_public_inputs_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        rewards_tree_value: HashOutTarget,
    ) -> HashOutTarget {
        let verify_agg_user_registration_deploy_guta_header_hash = self.get_combined_hash::<H, F, D>(builder);
        builder.hash_two_to_one::<H>(verify_agg_user_registration_deploy_guta_header_hash, rewards_tree_value)
    }
    pub fn get_public_inputs_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        worker_reward_tag: HashOutTarget,
        guta_proof_rewards_tree_value: HashOutTarget,
        register_users_proof_rewards_tree_value: HashOutTarget,
        deploy_contracts_proof_rewards_tree_value: HashOutTarget,
        update_contracts_proof_rewards_tree_value: HashOutTarget,
    ) -> HashOutTarget {
        let verify_agg_user_registration_deploy_guta_header_hash = self.get_combined_hash::<H, F, D>(builder);

        let tag_tree_value = hash_tag_tree_node_four_circuit::<H, F, D>(
            builder,
            guta_proof_rewards_tree_value,
            register_users_proof_rewards_tree_value,
            deploy_contracts_proof_rewards_tree_value,
            update_contracts_proof_rewards_tree_value,
            worker_reward_tag,
        );
        builder.hash_two_to_one::<H>(verify_agg_user_registration_deploy_guta_header_hash, tag_tree_value)
    }
    pub fn set_witness_params<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        user_registration_tree_delta: &AggStateTransition<QHashOut<F>>,
        global_contract_tree_delta: &AggStateTransition<QHashOut<F>>,
        global_user_tree_delta: &GlobalUserTreeAggregatorHeader<F, QHashOut<F>>,
        deploy_contracts_completed: F,
        register_users_completed: F,
    ) -> anyhow::Result<()> {
        self.user_registration_tree_delta.set_witness(witness, user_registration_tree_delta)?;
        self.global_contract_tree_delta.set_witness(witness, global_contract_tree_delta)?;
        self.global_user_tree_delta.set_witness(witness, global_user_tree_delta)?;
        witness.set_target(
            self.combined_pm_jobs_completed.deploy_contracts_completed,
            deploy_contracts_completed,
        )?;
        witness.set_target(
            self.combined_pm_jobs_completed.register_users_completed,
            register_users_completed,
        )?;

        Ok(())
    }

    pub fn set_witness_params_known_completions<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        user_registration_tree_delta: &AggStateTransition<QHashOut<F>>,
        global_contract_tree_delta: &AggStateTransition<QHashOut<F>>,
        global_user_tree_delta: &GlobalUserTreeAggregatorHeader<F, QHashOut<F>>,
    ) -> anyhow::Result<()> {
        self.user_registration_tree_delta.set_witness(witness, user_registration_tree_delta)?;
        self.global_contract_tree_delta.set_witness(witness, global_contract_tree_delta)?;
        self.global_user_tree_delta.set_witness(witness, global_user_tree_delta)?;

        Ok(())
    }
}

// we keep this separate from DPNProvingSessionCompactMethodCallGadget incase it
// changes in the future
#[derive(Debug, Clone)]
pub struct VerifyAggUserRegistartionDeployContractsGUTAGadget<const D: usize> {
    pub verify_register_users_gadget: VerifyStateTransitionProofGadget<D>,
    pub verify_deploy_contract_gadget: VerifyStateTransitionProofGadget<D>,
    pub verify_update_contract_gadget: VerifyStateTransitionProofGadget<D>,
    pub verify_guta_gadget: VerifyGUTAProofGadget<D>,

    // computed
    pub header: VerifyAggUserRegistartionDeployContractsGUTAHeaderGadget,
}

impl<const D: usize> VerifyAggUserRegistartionDeployContractsGUTAGadget<D> {
    pub fn add_virtual_to<C: GenericConfig<D, F = F>, F: RichField + Extendable<D>>(
        builder: &mut CircuitBuilder<F, D>,

        user_reg_proof_common_data: &CommonCircuitData<F, D>,
        user_reg_transition_circuit_config: &TPAltCircuitFingerprintConfig<QHashOut<F>>,

        deploy_contracts_proof_common_data: &CommonCircuitData<F, D>,
        deploy_contracts_transition_circuit_config: &TPAltCircuitFingerprintConfig<QHashOut<F>>,

        update_contracts_proof_common_data: &CommonCircuitData<F, D>,
        update_contracts_transition_circuit_config: &TPAltCircuitFingerprintConfig<QHashOut<F>>,

        guta_proof_common_data: &CommonCircuitData<F, D>,
        guta_verifier_data_cap_height: usize,
        guta_circuit_whitelist_root: QHashOut<F>,
        guta_circuit_whitelist_tree_height: u8,
    ) -> Self
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        let verify_register_users_gadget = VerifyStateTransitionProofGadget::<D>::add_virtual_to_with_config::<C, F>(
            builder,
            user_reg_proof_common_data,
            user_reg_transition_circuit_config,
        );
        let verify_deploy_contract_gadget = VerifyStateTransitionProofGadget::<D>::add_virtual_to_with_config::<C, F>(
            builder,
            deploy_contracts_proof_common_data,
            deploy_contracts_transition_circuit_config,
        );
        let verify_update_contract_gadget = VerifyStateTransitionProofGadget::<D>::add_virtual_to_with_config::<C, F>(
            builder,
            update_contracts_proof_common_data,
            update_contracts_transition_circuit_config,
        );

        let verify_guta_gadget = VerifyGUTAProofGadget::<D>::add_virtual_to::<C, F>(
            builder,
            guta_proof_common_data,
            guta_verifier_data_cap_height,
            guta_circuit_whitelist_tree_height,
        );

        let guta_circuit_whitelist_root_target = builder.constant_qhash(guta_circuit_whitelist_root);
        builder.connect_hashes(guta_circuit_whitelist_root_target, verify_guta_gadget.guta_whitelist_merkle_proof.root);

        // the update contracts transition must start where the deploy
        // contracts transition ended (for blocks without updates both are
        // equal, i.e. the update transition is a no-op)
        builder.connect_hashes(
            verify_deploy_contract_gadget.state_transition.state_transition_end,
            verify_update_contract_gadget.state_transition.state_transition_start,
        );

        let deploy_contracts_completed = verify_deploy_contract_gadget.total_proofs_generated;
        let register_users_completed = verify_register_users_gadget.total_proofs_generated;
        let header: VerifyAggUserRegistartionDeployContractsGUTAHeaderGadget = VerifyAggUserRegistartionDeployContractsGUTAHeaderGadget {
            user_registration_tree_delta: verify_register_users_gadget.state_transition,
            // the combined contract tree transition chains deploy then update
            global_contract_tree_delta: AggStateTransitionGadget {
                state_transition_start: verify_deploy_contract_gadget.state_transition.state_transition_start,
                state_transition_end: verify_update_contract_gadget.state_transition.state_transition_end,
            },
            global_user_tree_delta: verify_guta_gadget.guta_proof_header_gadget,
            combined_pm_jobs_completed: PMJobsCompletedStatsGadget {
                deploy_contracts_completed,
                register_users_completed,
                gutas_completed: verify_guta_gadget.guta_proof_header_gadget.total_aggregation_proofs_generated,
            },
        };

        Self {
            verify_register_users_gadget,
            verify_deploy_contract_gadget,
            verify_update_contract_gadget,
            verify_guta_gadget,
            header,
        }
    }
    
    pub fn set_witness_params<C: GenericConfig<D, F = F>, F: RichField + Extendable<D>>(
        &self,
        witness: &mut impl Witness<F>,
        register_users_state_transition: &AggStateTransition<QHashOut<F>>,
        register_users_proof: &ProofWithPublicInputs<F, C, D>,
        register_users_verifier_data: &VerifierOnlyCircuitData<C, D>,
        register_users_proof_rewards_tree_value: QHashOut<F>,
        register_users_total_proofs_generated: F,

        deploy_contracts_state_transition: &AggStateTransition<QHashOut<F>>,
        deploy_contracts_proof: &ProofWithPublicInputs<F, C, D>,
        deploy_contracts_verifier_data: &VerifierOnlyCircuitData<C, D>,
        deploy_contracts_proof_rewards_tree_value: QHashOut<F>,
        deploy_contracts_total_proofs_generated: F,

        update_contracts_state_transition: &AggStateTransition<QHashOut<F>>,
        update_contracts_proof: &ProofWithPublicInputs<F, C, D>,
        update_contracts_verifier_data: &VerifierOnlyCircuitData<C, D>,
        update_contracts_proof_rewards_tree_value: QHashOut<F>,
        update_contracts_total_proofs_generated: F,

        guta_whitelist_merkle_proof: &MerkleProofCore<QHashOut<F>>,
        guta_proof_header: &GlobalUserTreeAggregatorHeader<F, QHashOut<F>>,
        guta_proof: &ProofWithPublicInputs<F, C, D>,
        guta_verifier_data: &VerifierOnlyCircuitData<C, D>,
        guta_proof_rewards_tree_value: QHashOut<F>,
    ) -> anyhow::Result<()>
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        tracing::info!("🏭 Agg User Registration Deploy Contracts GUTA set_witness - register_users public_inputs: {}, deploy_contracts public_inputs: {}, guta_proof public_inputs: {}",
            serde_json::to_string_pretty(&register_users_proof.public_inputs).unwrap(),
            serde_json::to_string_pretty(&deploy_contracts_proof.public_inputs).unwrap(),
            serde_json::to_string_pretty(&guta_proof.public_inputs).unwrap());

        tracing::info!(
            "🏭 Agg User Registration Deploy Contracts GUTA set_witness - guta_proof_header: {}",
            serde_json::to_string_pretty(guta_proof_header).unwrap()
        );

        tracing::info!(
            "register_users_state_transition={}",
            serde_json::to_string_pretty(&register_users_state_transition).unwrap()
        );
        self.verify_register_users_gadget.set_witness::<F, C>(
            witness,
            register_users_state_transition,
            register_users_proof_rewards_tree_value,
            register_users_total_proofs_generated,
            register_users_proof,
            register_users_verifier_data,
        )?;
        tracing::info!(
            "deploy_contracts_state_transition={}",
            serde_json::to_string_pretty(&deploy_contracts_state_transition).unwrap()
        );
        self.verify_deploy_contract_gadget.set_witness::<F, C>(
            witness,
            deploy_contracts_state_transition,
            deploy_contracts_proof_rewards_tree_value,
            deploy_contracts_total_proofs_generated,
            deploy_contracts_proof,
            deploy_contracts_verifier_data,
        )?;
        tracing::info!(
            "update_contracts_state_transition={}",
            serde_json::to_string_pretty(&update_contracts_state_transition).unwrap()
        );
        self.verify_update_contract_gadget.set_witness::<F, C>(
            witness,
            update_contracts_state_transition,
            update_contracts_proof_rewards_tree_value,
            update_contracts_total_proofs_generated,
            update_contracts_proof,
            update_contracts_verifier_data,
        )?;

        self.verify_guta_gadget.set_witness(
            witness,
            guta_whitelist_merkle_proof,
            guta_proof_header,
            guta_proof,
            guta_verifier_data,
            guta_proof_rewards_tree_value,
        )?;

        Ok(())
    }
}
