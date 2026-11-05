use parth_core::{
    crypto::hash::{
        merkle_proof::MerkleProofCore,
        tag_tree::hash_tag_tree_node_four,
        traits::{FieldQHasher, MerkleHasher, QFieldHashable},
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
use parth_core::protocol::core_types::Q256BitHash;
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
    pub update_contracts_transition_circuit_config: TPAltCircuitFingerprintConfig<C::Hash>,
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
        update_contracts_transition_circuit_config: TPAltCircuitFingerprintConfig<C::Hash>,
        guta_circuit_whitelist_root: C::Hash,
        guta_circuit_whitelist_tree_height: u8,
    ) -> Self {
        let mut config = vec![C::F::from_u64_value(1)];
        for child in [&user_reg_transition_circuit_config, &deploy_contracts_transition_circuit_config, &update_contracts_transition_circuit_config] {
            config.extend(child.leaf_fingerprint.to_4_felts());
            config.extend(child.aggregator_fingerprint.to_4_felts());
            config.extend(child.dummy_fingerprint.to_4_felts());
            config.push(C::F::from_u64_value(child.verifier_data_cap_height as u64));
        }
        config.extend(guta_circuit_whitelist_root.to_4_felts());
        config.push(C::F::from_u64_value(guta_circuit_whitelist_tree_height as u64));
        let config_hash = C::Hasher::q_hash_many(&config);
        let circuit_type = ProvingJobCircuitType::AggUserRegisterDeployContractsGUTA;
        let verifier_data = PsyTestJTMBProofVerifierData::new_from_compressed_public_key(
            circuit_type as u32,
            config_hash.into_owned_32bytes(),
            &private_key.get_public_key(),
        );
        let fingerprint = verifier_data.get_fingerprint::<C::Hash, C::Hasher, C::F>();
        Self {
            private_key: private_key.clone(),
            verifier_data,
            fingerprint,
            user_reg_transition_circuit_config,
            deploy_contracts_transition_circuit_config,
            update_contracts_transition_circuit_config,
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

        update_contracts_state_transition: &AggStateTransition<C::Hash>,
        update_contracts_total_proofs: u64,
        update_contracts_proof: &PsyTestJTMBProof<C::Hash>,
        update_contracts_verifier_data: &PsyTestJTMBProofVerifierData,
        update_contracts_rewards: C::Hash,

        guta_whitelist_merkle_proof: &MerkleProofCore<C::Hash>,
        guta_proof_header: &GlobalUserTreeAggregatorHeader<C::F, C::Hash>,
        guta_proof: &PsyTestJTMBProof<C::Hash>,
        guta_verifier_data: &PsyTestJTMBProofVerifierData,
        guta_rewards: C::Hash,

    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        jtmb_connect_ref(&deploy_contracts_state_transition.state_transition_end,
            &update_contracts_state_transition.state_transition_start, "deploy/update contract root chain mismatch")?;
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

        // 3. Verify Update Contracts
        let update_whitelist = C::Hasher::two_to_one(&self.update_contracts_transition_circuit_config.leaf_fingerprint, &self.update_contracts_transition_circuit_config.aggregator_fingerprint);
        let expected_update_pi = compute_agg_public_inputs::<C::Hash, C::F, C::Hasher>(
            update_whitelist,
            update_contracts_state_transition,
            C::F::from_u64_value(update_contracts_total_proofs),
            update_contracts_rewards,
        );
        jtmb_connect_ref(&expected_update_pi, &update_contracts_proof.public_inputs_hash, "update contracts public inputs mismatch")?;
        update_contracts_verifier_data.verify_proof::<C::Hasher, C::Hash, C::F>(update_contracts_proof)?;

        let update_fp = update_contracts_verifier_data.get_fingerprint::<C::Hash, C::Hasher, C::F>();
        if update_fp != self.update_contracts_transition_circuit_config.leaf_fingerprint
            && update_fp != self.update_contracts_transition_circuit_config.aggregator_fingerprint
            && update_fp != self.update_contracts_transition_circuit_config.dummy_fingerprint
        {
            anyhow::bail!("Update contracts proof fingerprint not allowed");
        }

        // 4. Verify GUTA
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
        let user_reg_contract_end = C::Hasher::two_to_one(&register_users_state_transition.state_transition_end, &update_contracts_state_transition.state_transition_end);
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

        let rewards_val = hash_tag_tree_node_four::<C::Hash, C::Hasher>(
            &guta_rewards,
            &register_users_rewards,
            &deploy_contracts_rewards,
            &update_contracts_rewards,
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
        let rewards = get_reward_tags_ensure_expected_child_proof_count(4, &input)?;
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

        let update_proof = deserialize_jtmb_proof::<C::Hash>(&input.input_proofs[3])?;
        let update_circuit_type = input.base.job.metadata.dependencies[3].circuit_type;
        let update_verifier_data = library.get_verifier_data(update_circuit_type)?;

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

            &witness.update_contracts_state_transition.get_agg_state_transition(),
            witness.update_contracts_state_transition.total_proofs_generated,
            &update_proof,
            &update_verifier_data,
            rewards[3],

            &guta_inclusion_proof,
            &witness.guta_proof_header,
            &guta_proof,
            &guta_verifier_data,
            rewards[0],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parth_common::realm_rotation::RealmRotationConfig;
    use parth_core::{PF, PHash, pgoldilocks::PoseidonHasher};
    use psy_data::{agg::AggStateTransitionWithStats, guta::{stats::GUTAStats, sub_tree_transition::SubTreeNodeStateTransition}};
    use crate::{protocol_types::JTMBPoseidonGoldilocksConfig, proving::coordinator_helper::QEDCoordinatorCircuitManager};

    #[test]
    fn four_children_bind_contract_chain_rewards_and_verifier_policy() -> anyhow::Result<()> {
        type Hash = PHash;
        type Hasher = PoseidonHasher;
        type C = JTMBPoseidonGoldilocksConfig;
        let h = |value| Hash::from_values(value, 0, 0, 0);
        let key = MemorySecp256K1SinglePrivateKeyWallet::new_from_private_key_bytes(&[7; 32])?;
        let manager = QEDCoordinatorCircuitManager::<C>::new(&key, 4, 4, 4, 8, 1, 32, 64, 1, 2, 8, 2, 4, h(1),
            RealmRotationConfig { checkpoints_per_epoch: 32, validator_sub_ids: vec![1, 2, 3] });
        let circuit = &manager.agg_user_register_deploy_contracts_guta;
        let reg = AggStateTransition { state_transition_start: h(1), state_transition_end: h(2) };
        let deploy = AggStateTransition { state_transition_start: h(3), state_transition_end: h(4) };
        let update = AggStateTransition { state_transition_start: h(4), state_transition_end: h(5) };
        let rewards = [h(9), h(10), h(11), h(12)];
        let worker = h(13);
        let header = GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: manager.guta_circuits.guta_circuit_whitelist_root, checkpoint_tree_root: h(6),
            state_transition: SubTreeNodeStateTransition { old_node_value: h(7), new_node_value: h(8), node_index: PF::from_u64_value(0), node_level: PF::from_u64_value(0) },
            stats: GUTAStats::get_zero_value(), total_aggregation_proofs_generated: PF::from_u64_value(1),
        };
        let sign = |verifier: &PsyTestJTMBProofVerifierData, pi| verifier.generate_proof_with_signer::<Hasher, Hash, PF, _>(pi, &key);
        let reg_pi = compute_agg_public_inputs::<Hash, PF, Hasher>(manager.append_register_users_circuit_whitelist, &reg, PF::from_u64_value(1), rewards[0]);
        let deploy_pi = compute_agg_public_inputs::<Hash, PF, Hasher>(manager.batch_deploy_contracts_circuit_whitelist, &deploy, PF::from_u64_value(1), rewards[1]);
        let update_whitelist = Hasher::two_to_one(&manager.batch_update_contracts.fingerprint, &manager.agg_state_transition.fingerprint);
        let reg_proof = sign(&manager.append_user_registration_tree.verifier_data, reg_pi)?;
        let deploy_proof = sign(&manager.batch_deploy_contracts.verifier_data, deploy_pi)?;
        let guta_proof = sign(manager.guta_circuits.no_change.get_verifier_data(), Hasher::two_to_one(&header.qfhash::<Hasher>(), &rewards[3]))?;
        let prove = |transition: &AggStateTransition<Hash>, reward: Hash| {
            let update_pi = compute_agg_public_inputs::<Hash, PF, Hasher>(update_whitelist, transition, PF::from_u64_value(1), reward);
            let update_proof = sign(&manager.batch_update_contracts.verifier_data, update_pi)?;
            circuit.prove_base(worker, &reg, 1, &reg_proof, &manager.append_user_registration_tree.verifier_data, rewards[0],
                &deploy, 1, &deploy_proof, &manager.batch_deploy_contracts.verifier_data, rewards[1],
                transition, 1, &update_proof, &manager.batch_update_contracts.verifier_data, reward,
                &manager.guta_circuits.no_change_whitelist_proof, &header, &guta_proof, manager.guta_circuits.no_change.get_verifier_data(), rewards[3])
        };
        let proved = prove(&update, rewards[2])?;
        let with_stats = |t: &AggStateTransition<Hash>| AggStateTransitionWithStats {
            state_transition_start: t.state_transition_start, state_transition_end: t.state_transition_end, total_proofs_generated: 1,
        };
        let input = QCAggUserRegistartionDeployContractsGUTAInput {
            register_users_state_transition: with_stats(&reg), deploy_contracts_state_transition: with_stats(&deploy),
            update_contracts_state_transition: with_stats(&update), guta_proof_header: header,
        };
        let reward = hash_tag_tree_node_four::<Hash, Hasher>(&rewards[3], &rewards[0], &rewards[1], &rewards[2], &worker);
        assert_eq!(proved.public_inputs_hash, Hasher::two_to_one(&input.get_public_inputs_hash_no_rewards_tag::<Hasher>(), &reward));
        let disconnected = AggStateTransition { state_transition_start: h(99), state_transition_end: h(5) };
        assert!(prove(&disconnected, rewards[2]).unwrap_err().to_string().contains("root chain mismatch"));
        assert_ne!(proved.public_inputs_hash, prove(&update, h(14))?.public_inputs_hash);
        let mut policy = circuit.update_contracts_transition_circuit_config.clone();
        policy.leaf_fingerprint = h(99);
        let other = VerifyAggUserRegistartionDeployContractsGUTACircuit::<C>::new(&key,
            circuit.user_reg_transition_circuit_config.clone(), circuit.deploy_contracts_transition_circuit_config.clone(), policy,
            circuit.guta_circuit_whitelist_root, circuit.guta_circuit_whitelist_tree_height);
        assert_ne!(other.fingerprint, circuit.fingerprint);
        let other_checkpoint = crate::proving::circuits::coordinator::checkpoint_state_transition::QEDCheckpointStateTransitionCircuit::<C>::new(
            &key, 8, other.fingerprint, manager.genesis_checkpoint_root_transition.fingerprint);
        assert_ne!(other_checkpoint.fingerprint, manager.checkpoint_root_transition.fingerprint);
        let legacy = PsyTestJTMBProofVerifierData::new_from_compressed_public_key(ProvingJobCircuitType::AggUserRegisterDeployContractsGUTA as u32, [0; 32], &key.get_public_key());
        assert_ne!(legacy.get_fingerprint::<Hash, Hasher, PF>(), circuit.fingerprint);
        Ok(())
    }
}
