use parth_core::{crypto::hash::merkle_proof::MerkleProofCore, pgoldilocks::QHashOut};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::witness::Witness,
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
        qdata::pm_jobs_completed_stats::PMJobsCompletedStatsGadget,
        treeprover::{AggStateTransitionGadget, VerifyStateTransitionProofGadget},
    },
    guta::gadgets::{guta_header::GlobalUserTreeAggregatorHeaderGadget, verify_guta_proof::VerifyGUTAProofGadget},
};

#[derive(Debug, Clone)]
pub struct VerifyAggUserRegistartionDeployContractsGUTAHeaderGadget {
    pub user_registration_tree_delta: AggStateTransitionGadget,
    pub global_contract_tree_delta: AggStateTransitionGadget,
    pub global_user_tree_delta: GlobalUserTreeAggregatorHeaderGadget,
}

impl VerifyAggUserRegistartionDeployContractsGUTAHeaderGadget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        let user_registration_tree_delta = AggStateTransitionGadget::add_virtual_to(builder);
        let global_contract_tree_delta = AggStateTransitionGadget::add_virtual_to(builder);
        let global_user_tree_delta = GlobalUserTreeAggregatorHeaderGadget::add_virtual_to(builder);

        Self {
            user_registration_tree_delta,
            global_contract_tree_delta,
            global_user_tree_delta,
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

        builder.hash_two_to_one::<H>(user_regsitration_deploy_contract_combo, guta_hash)
    }

    pub fn set_witness_params<F: RichField>(
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
    pub verify_guta_gadget: VerifyGUTAProofGadget<D>,

    // computed
    pub header: VerifyAggUserRegistartionDeployContractsGUTAHeaderGadget,
    pub combined_pm_jobs_completed: PMJobsCompletedStatsGadget,
}

impl<const D: usize> VerifyAggUserRegistartionDeployContractsGUTAGadget<D> {
    pub fn add_virtual_to<C: GenericConfig<D, F = F>, F: RichField + Extendable<D>>(
        builder: &mut CircuitBuilder<F, D>,

        user_reg_proof_common_data: &CommonCircuitData<F, D>,
        user_reg_transition_circuit_config: &TPAltCircuitFingerprintConfig<QHashOut<F>>,

        deploy_contracts_proof_common_data: &CommonCircuitData<F, D>,
        deploy_contracts_transition_circuit_config: &TPAltCircuitFingerprintConfig<QHashOut<F>>,

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
        tracing::debug!("verify_register_users_gadget={:#?}", verify_register_users_gadget);
        let verify_deploy_contract_gadget = VerifyStateTransitionProofGadget::<D>::add_virtual_to_with_config::<C, F>(
            builder,
            deploy_contracts_proof_common_data,
            deploy_contracts_transition_circuit_config,
        );
        tracing::debug!("verify_deploy_contract_gadget={:#?}", verify_deploy_contract_gadget);

        let verify_guta_gadget = VerifyGUTAProofGadget::<D>::add_virtual_to::<C, F>(
            builder,
            guta_proof_common_data,
            guta_verifier_data_cap_height,
            guta_circuit_whitelist_tree_height,
        );
        tracing::debug!("verify_guta_gadget={:#?}", verify_guta_gadget);

        let guta_circuit_whitelist_root_target = builder.constant_qhash(guta_circuit_whitelist_root);
        builder.connect_hashes(guta_circuit_whitelist_root_target, verify_guta_gadget.guta_whitelist_merkle_proof.root);

        let header = VerifyAggUserRegistartionDeployContractsGUTAHeaderGadget {
            user_registration_tree_delta: verify_register_users_gadget.state_transition,
            global_contract_tree_delta: verify_deploy_contract_gadget.state_transition,
            global_user_tree_delta: verify_guta_gadget.guta_proof_header_gadget,
        };

        let combined_pm_jobs_completed = PMJobsCompletedStatsGadget {
            deploy_contracts_completed: builder.add_many([
                verify_register_users_gadget.proof_target.public_inputs[8],
                verify_deploy_contract_gadget.proof_target.public_inputs[8],
                verify_guta_gadget.proof_target.public_inputs[8],
            ]),
            register_users_completed: builder.add_many([
                verify_register_users_gadget.proof_target.public_inputs[9],
                verify_deploy_contract_gadget.proof_target.public_inputs[9],
                verify_guta_gadget.proof_target.public_inputs[9],
            ]),
            gutas_completed: builder.add_many([
                verify_register_users_gadget.proof_target.public_inputs[10],
                verify_deploy_contract_gadget.proof_target.public_inputs[10],
                verify_guta_gadget.proof_target.public_inputs[10],
            ]),
        };

        Self {
            verify_register_users_gadget,
            verify_deploy_contract_gadget,
            verify_guta_gadget,
            header,
            combined_pm_jobs_completed,
        }
    }
    pub fn set_witness_params<C: GenericConfig<D, F = F>, F: RichField + Extendable<D>>(
        &self,
        witness: &mut impl Witness<F>,
        register_users_state_transition: &AggStateTransition<QHashOut<F>>,
        register_users_proof: &ProofWithPublicInputs<F, C, D>,
        register_users_verifier_data: &VerifierOnlyCircuitData<C, D>,

        deploy_contracts_state_transition: &AggStateTransition<QHashOut<F>>,
        deploy_contracts_proof: &ProofWithPublicInputs<F, C, D>,
        deploy_contracts_verifier_data: &VerifierOnlyCircuitData<C, D>,

        guta_whitelist_merkle_proof: &MerkleProofCore<QHashOut<F>>,
        guta_proof_header: &GlobalUserTreeAggregatorHeader<F, QHashOut<F>>,
        guta_proof: &ProofWithPublicInputs<F, C, D>,
        guta_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<()>
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        tracing::debug!("🏭 Agg User Registration Deploy Contracts GUTA set_witness - register_users public_inputs: {}, deploy_contracts public_inputs: {}, guta_proof public_inputs: {}",
            serde_json::to_string_pretty(&register_users_proof.public_inputs).unwrap(),
            serde_json::to_string_pretty(&deploy_contracts_proof.public_inputs).unwrap(),
            serde_json::to_string_pretty(&guta_proof.public_inputs).unwrap());

        tracing::debug!(
            "🏭 Agg User Registration Deploy Contracts GUTA set_witness - guta_proof_header: {}",
            serde_json::to_string_pretty(guta_proof_header).unwrap()
        );

        tracing::debug!(
            "register_users_state_transition={}",
            serde_json::to_string_pretty(&register_users_state_transition).unwrap()
        );
        self.verify_register_users_gadget.set_witness::<F, C>(
            witness,
            register_users_state_transition,
            register_users_proof,
            register_users_verifier_data,
        )?;
        tracing::debug!(
            "deploy_contracts_state_transition={}",
            serde_json::to_string_pretty(&deploy_contracts_state_transition).unwrap()
        );
        self.verify_deploy_contract_gadget.set_witness::<F, C>(
            witness,
            deploy_contracts_state_transition,
            deploy_contracts_proof,
            deploy_contracts_verifier_data,
        )?;

        self.verify_guta_gadget
            .set_witness(witness, guta_whitelist_merkle_proof, guta_proof_header, guta_proof, guta_verifier_data)?;

        Ok(())
    }
}
