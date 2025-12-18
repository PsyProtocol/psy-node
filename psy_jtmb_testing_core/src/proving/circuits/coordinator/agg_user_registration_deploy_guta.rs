use parth_core::{
    crypto::hash::{
        merkle_proof::MerkleProofCore,
        tag_tree::hash_tag_tree_node_three,
        traits::{MerkleHasher, QFieldHashable},
    },
    felt::FromPrimitiveValuesFelt,
};

use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{
    agg::{AggStateTransition, TPAltCircuitFingerprintConfig},
    guta::header::GlobalUserTreeAggregatorHeader,
    protocol::circuit_inputs::agg_part_1::QCAggUserRegistartionDeployContractsGUTAInput,
    worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse,
};
use parth_core::crypto::hash::traits::HashTo4Felts;
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
use crate::{
    proof::{PsyTestJTMBProof, PsyTestJTMBProofVerifierData},
    proving::{
        gadgets::{
            coordinator::agg_state::compute_agg_public_inputs,
            guta::verify_guta_proof::verify_guta_proof,
        },
        utils::connect::jtmb_connect_ref,
    },
    utils::{
        circuit_info_library::PsyJTMBCircuitInfoLibrary, jtmb_standard_circuit::{JTMBCircuitConfig, QJTMBProofCircuit, QJTMBProofCircuitBase}, proof_library::get_reward_tags_ensure_expected_child_proof_count, proof_serialization::deserialize_jtmb_proof
    },
};
use parth_common::secp256k1::MemorySecp256K1SinglePrivateKeyWallet;

#[derive(Debug, Clone)]
pub struct VerifyAggUserRegistartionDeployContractsGUTACircuit<C: JTMBCircuitConfig> {
    pub private_key: MemorySecp256K1SinglePrivateKeyWallet,
    pub verifier_data: PsyTestJTMBProofVerifierData,
    pub fingerprint: C::Hash,

    pub user_reg_transition_circuit_config: TPAltCircuitFingerprintConfig<C::Hash>,
    pub deploy_contracts_transition_circuit_config: TPAltCircuitFingerprintConfig<C::Hash>,
    pub guta_circuit_whitelist_root: C::Hash,
    pub guta_circuit_whitelist_tree_height: u8,
}

impl<C: JTMBCircuitConfig> QJTMBProofCircuitBase<C::Hash> for VerifyAggUserRegistartionDeployContractsGUTACircuit<C> {
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::AggUserRegisterDeployContractsGUTA
    }
    fn get_verifier_data(&self) -> &PsyTestJTMBProofVerifierData {
        &self.verifier_data
    }
    fn get_fingerprint(&self) -> C::Hash {
        self.fingerprint
    }
}

impl<C: JTMBCircuitConfig> VerifyAggUserRegistartionDeployContractsGUTACircuit<C> {
    pub fn new(
        private_key: &MemorySecp256K1SinglePrivateKeyWallet,
        user_reg_transition_circuit_config: TPAltCircuitFingerprintConfig<C::Hash>,
        deploy_contracts_transition_circuit_config: TPAltCircuitFingerprintConfig<C::Hash>,
        guta_circuit_whitelist_root: C::Hash,
        guta_circuit_whitelist_tree_height: u8,
    ) -> Self {
        let circuit_type = ProvingJobCircuitType::AggUserRegisterDeployContractsGUTA;
        let verifier_data = PsyTestJTMBProofVerifierData::new_from_compressed_public_key(
            circuit_type as u32,
            [0u8; 32],
            &private_key.get_public_key(),
        );
        let fingerprint = verifier_data.get_fingerprint::<C::Hash, C::Hasher, C::F>();
        Self {
            private_key: private_key.clone(),
            verifier_data,
            fingerprint,
            user_reg_transition_circuit_config,
            deploy_contracts_transition_circuit_config,
            guta_circuit_whitelist_root,
            guta_circuit_whitelist_tree_height,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prove_base(
        &self,
        worker_reward_tag: C::Hash,
        
        register_users_state_transition: &AggStateTransition<C::Hash>,
        register_users_total_proofs: u64,
        register_users_proof: &PsyTestJTMBProof<C::Hash>,
        register_users_verifier_data: &PsyTestJTMBProofVerifierData,
        register_users_rewards: C::Hash,

        deploy_contracts_state_transition: &AggStateTransition<C::Hash>,
        deploy_contracts_total_proofs: u64,
        deploy_contracts_proof: &PsyTestJTMBProof<C::Hash>,
        deploy_contracts_verifier_data: &PsyTestJTMBProofVerifierData,
        deploy_contracts_rewards: C::Hash,

        guta_whitelist_merkle_proof: &MerkleProofCore<C::Hash>,
        guta_proof_header: &GlobalUserTreeAggregatorHeader<C::F, C::Hash>,
        guta_proof: &PsyTestJTMBProof<C::Hash>,
        guta_verifier_data: &PsyTestJTMBProofVerifierData,
        guta_rewards: C::Hash,

    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        //println!("input guta header: {:#?}", guta_proof_header);
        //println!("input guta rewards: {:?}", guta_rewards);
        
        // 1. Verify Register Users
        let reg_whitelist = C::Hasher::two_to_one(&self.user_reg_transition_circuit_config.leaf_fingerprint, &self.user_reg_transition_circuit_config.aggregator_fingerprint);
        let expected_reg_pi = compute_agg_public_inputs::<C::Hash, C::F, C::Hasher>(
            reg_whitelist,
            register_users_state_transition,
            C::F::from_u64_value(register_users_total_proofs),
            register_users_rewards,
        );
        jtmb_connect_ref(&expected_reg_pi, &register_users_proof.public_inputs_hash, "register users public inputs mismatch")?;
        register_users_verifier_data.verify_proof::<C::Hasher, C::Hash, C::F>(register_users_proof)?;
        
        // Fingerprint check
        let reg_fp = register_users_verifier_data.get_fingerprint::<C::Hash, C::Hasher, C::F>();
        if reg_fp != self.user_reg_transition_circuit_config.leaf_fingerprint 
            && reg_fp != self.user_reg_transition_circuit_config.aggregator_fingerprint
            && reg_fp != self.user_reg_transition_circuit_config.dummy_fingerprint 
        {
            anyhow::bail!("Register users proof fingerprint not allowed");
        }

        // 2. Verify Deploy Contracts
        let deploy_whitelist = C::Hasher::two_to_one(&self.deploy_contracts_transition_circuit_config.leaf_fingerprint, &self.deploy_contracts_transition_circuit_config.aggregator_fingerprint);
        let expected_deploy_pi = compute_agg_public_inputs::<C::Hash, C::F, C::Hasher>(
            deploy_whitelist,
            deploy_contracts_state_transition,
            C::F::from_u64_value(deploy_contracts_total_proofs),
            deploy_contracts_rewards,
        );
        jtmb_connect_ref(&expected_deploy_pi, &deploy_contracts_proof.public_inputs_hash, "deploy contracts public inputs mismatch")?;
        deploy_contracts_verifier_data.verify_proof::<C::Hasher, C::Hash, C::F>(deploy_contracts_proof)?;

        let deploy_fp = deploy_contracts_verifier_data.get_fingerprint::<C::Hash, C::Hasher, C::F>();
        if deploy_fp != self.deploy_contracts_transition_circuit_config.leaf_fingerprint 
            && deploy_fp != self.deploy_contracts_transition_circuit_config.aggregator_fingerprint
            && deploy_fp != self.deploy_contracts_transition_circuit_config.dummy_fingerprint 
        {
            anyhow::bail!("Deploy contracts proof fingerprint not allowed");
        }

        // 3. Verify GUTA
        jtmb_connect_ref(&guta_whitelist_merkle_proof.root, &self.guta_circuit_whitelist_root, "guta whitelist root mismatch")?;
        verify_guta_proof::<C>(
            self.guta_circuit_whitelist_tree_height,
            guta_whitelist_merkle_proof,
            guta_proof_header,
            guta_proof,
            guta_verifier_data,
            guta_rewards,
        )?;

        let user_reg_contract_start = C::Hasher::two_to_one(&register_users_state_transition.state_transition_start, &deploy_contracts_state_transition.state_transition_start);
        let user_reg_contract_end = C::Hasher::two_to_one(&register_users_state_transition.state_transition_end, &deploy_contracts_state_transition.state_transition_end);
        let user_reg_contract_combo = C::Hasher::two_to_one(&user_reg_contract_start, &user_reg_contract_end);

        let guta_hash = guta_proof_header.qfhash::<C::Hasher>();
        
        let combo_without_stats = C::Hasher::two_to_one(&user_reg_contract_combo, &guta_hash);

        let zero_felt = C::F::from_u64_value(0);
        let stats_hash = C::Hash::from_4_felts(
            [
                C::F::from_u64_value(deploy_contracts_total_proofs),
                C::F::from_u64_value(register_users_total_proofs),
                guta_proof_header.total_aggregation_proofs_generated,
                zero_felt
            ]
        );

        let pi_no_rewards = C::Hasher::two_to_one(&combo_without_stats, &stats_hash);

        let rewards_val = hash_tag_tree_node_three::<C::Hash, C::Hasher>(
            &guta_rewards,
            &register_users_rewards,
            &deploy_contracts_rewards,
            &worker_reward_tag,
        );

        let final_pi_hash = C::Hasher::two_to_one(&pi_no_rewards, &rewards_val);

        self.verifier_data.generate_proof_with_signer::<C::Hasher, C::Hash, C::F, _>(
            final_pi_hash,
            &self.private_key,
        )
    }
}

impl<L: PsyJTMBCircuitInfoLibrary<C::Hash>, C: JTMBCircuitConfig> QJTMBProofCircuit<C, L> for VerifyAggUserRegistartionDeployContractsGUTACircuit<C> {
    fn jtmb_prove_with_raw_proofs_and_ref_library(
        &self,
        library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<C::Hash, QProvingJobDataID>,
        worker_reward_tag: C::Hash,
    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        let rewards = get_reward_tags_ensure_expected_child_proof_count(3, &input)?;
        let witness = QCAggUserRegistartionDeployContractsGUTAInput::<C::F, C::Hash>::psy_ser_from_slice(&input.base.witness)?;

        let guta_proof = deserialize_jtmb_proof::<C::Hash>(&input.input_proofs[0])?;
        let guta_circuit_type = input.base.job.metadata.dependencies[0].circuit_type;
        let guta_inclusion_proof = library.get_group_inclusion_proof(ProvingJobCircuitType::GUTATwoGUTA, guta_circuit_type)?;
        let guta_verifier_data = library.get_verifier_data(guta_circuit_type)?;

        let reg_proof = deserialize_jtmb_proof::<C::Hash>(&input.input_proofs[1])?;
        let reg_circuit_type = input.base.job.metadata.dependencies[1].circuit_type;
        let reg_verifier_data = library.get_verifier_data(reg_circuit_type)?;

        let deploy_proof = deserialize_jtmb_proof::<C::Hash>(&input.input_proofs[2])?;
        let deploy_circuit_type = input.base.job.metadata.dependencies[2].circuit_type;
        let deploy_verifier_data = library.get_verifier_data(deploy_circuit_type)?;

        self.prove_base(
            worker_reward_tag,
            
            &witness.register_users_state_transition.get_agg_state_transition(),
            witness.register_users_state_transition.total_proofs_generated,
            &reg_proof,
            &reg_verifier_data,
            rewards[1],

            &witness.deploy_contracts_state_transition.get_agg_state_transition(),
            witness.deploy_contracts_state_transition.total_proofs_generated,
            &deploy_proof,
            &deploy_verifier_data,
            rewards[2],

            &guta_inclusion_proof,
            &witness.guta_proof_header,
            &guta_proof,
            &guta_verifier_data,
            rewards[0],
        )
    }
}