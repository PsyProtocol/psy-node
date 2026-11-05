use parth_core::{
    crypto::hash::traits::{MerkleHasher, MerkleZeroHasher, ZeroableHash},
    felt::{FromPrimitiveValuesFelt, ZeroableFelt},
    pgoldilocks::{PoseidonHasher, QHashOut},
};
use psy_core::{constants::{chain_id::PsyChainNetworkType, protocol::DA_CHALLENGE_WINDOW}, job::job_id::ProvingJobCircuitType};
use psy_data::{
    config::network_config::PsyNodeCircuitFingerprintConfig,
    genesis::genesis_block_setup::PsyGenesisBlockSetupData,
    v1::qdata::{checkpoint::PQEDCheckpointLeafStats, pm_jobs_completed_stats::PPMJobsCompletedStats, pm_rewards_commitment::PPMRewardCommitment},
};

use crate::{circuit_library::core::get_jtmb_circuit_library_and_prover_for_network, protocol_types::JTMBPoseidonGoldilocksConfig, utils::circuit_info_library::PsyJTMBCircuitInfoLibraryCore};

type F = parth_core::PF;
type Hash = parth_core::PHash;
type Hasher = PoseidonHasher;
pub fn get_psy_node_jtmb_poseidon_goldilocks_config_for_network(network: PsyChainNetworkType) -> anyhow::Result<PsyNodeCircuitFingerprintConfig<Hash>> {
    let (verifier, _circuit_manager) = get_jtmb_circuit_library_and_prover_for_network::<JTMBPoseidonGoldilocksConfig>(network)?;

    get_psy_node_jtmb_poseidon_goldilocks_config_from_library(&verifier.library)
}

fn get_psy_node_jtmb_poseidon_goldilocks_config_from_library(lib: &impl PsyJTMBCircuitInfoLibraryCore<Hash>) -> anyhow::Result<PsyNodeCircuitFingerprintConfig<Hash>> {
    let guta_circuit_whitelist_root = lib
        .get_group_inclusion_proof(ProvingJobCircuitType::GUTATwoGUTALinearUpgradeCheckpoint, ProvingJobCircuitType::GUTATwoGUTALinear)?
        .root;
    println!("get_psy_node_jtmb_poseidon_goldilocks_config_for_network: guta_circuit_whitelist_root: {:?}", guta_circuit_whitelist_root);

    let append_user_registration_tree_fingerprint = lib.get_fingerprint(ProvingJobCircuitType::AppendUserRegistrationTree)?;
    let batch_deploy_contracts_fingerprint = lib.get_fingerprint(ProvingJobCircuitType::BatchDeployContracts)?;
    let agg_state_transition_fingerprint = lib.get_fingerprint(ProvingJobCircuitType::BatchDeployContractsAggregate)?;

    let register_users_circuit_whitelist_root = Hasher::two_to_one(&append_user_registration_tree_fingerprint, &agg_state_transition_fingerprint);

    let deploy_contracts_circuit_whitelist_root = Hasher::two_to_one(&batch_deploy_contracts_fingerprint, &agg_state_transition_fingerprint);

    let batch_update_contracts_fingerprint = lib.get_fingerprint(ProvingJobCircuitType::BatchUpdateContracts)?;
    let update_contracts_circuit_whitelist_root = Hasher::two_to_one(&batch_update_contracts_fingerprint, &agg_state_transition_fingerprint);

    let checkpoint_state_transition_circuit_fingerprint = lib.get_fingerprint(ProvingJobCircuitType::GenerateRollupStateTransitionProof)?;
    let genesis_checkpoint_state_transition_fingerprint = lib.get_fingerprint(ProvingJobCircuitType::GenesisBlockCheckpointStateTransition)?;

    Ok(PsyNodeCircuitFingerprintConfig {
        guta_circuit_whitelist_root,
        register_users_circuit_whitelist_root,
        deploy_contracts_circuit_whitelist_root,
        update_contracts_circuit_whitelist_root,
        checkpoint_state_transition_circuit_fingerprint,
        genesis_checkpoint_state_transition_fingerprint,
    })
}

pub fn get_genesis_block_setup_data_for_local_devnet_default() -> anyhow::Result<PsyGenesisBlockSetupData<F, Hash>> {
    Ok(PsyGenesisBlockSetupData {
        contracts: vec![],
        users: vec![],
        checkpoint_stats: PQEDCheckpointLeafStats {
            guta_fees_collected: F::ZERO_VALUE,
            da_fees_collected: F::ZERO_VALUE,
            user_ops_processed: F::ZERO_VALUE,
            total_transactions: F::ZERO_VALUE,
            slots_modified: F::ZERO_VALUE,
            pm_jobs_completed: PPMJobsCompletedStats {
                deploy_contracts_completed: F::ZERO_VALUE,
                register_users_completed: F::ZERO_VALUE,
                gutas_completed: F::ZERO_VALUE,
            },
            block_time: F::from_u64_value(1_764_248_609u64),
            random_seed: QHashOut::from_values(1, 2, 3, 4),
            pm_rewards_commitment: PPMRewardCommitment {
                register_users_root: Hash::get_zero_value(),
                gutas_root: Hash::get_zero_value(),
                deploy_contracts_root: Hash::get_zero_value(),
            },
            da_challenges_claimed: [F::ZERO_VALUE; DA_CHALLENGE_WINDOW],
        },
        deposit_tree_root: PoseidonHasher::get_zero_hash(32),
        withdrawal_tree_root: PoseidonHasher::get_zero_hash(32),
        validators: vec![],
    })
}

pub fn get_genesis_block_setup_data_for_local_devnet(genesis_data_path: Option<String>) -> anyhow::Result<PsyGenesisBlockSetupData<F, Hash>> {
    match genesis_data_path {
        None => get_genesis_block_setup_data_for_local_devnet_default(),
        Some(path) => {
            let genesis_data = serde_json::from_str::<PsyGenesisBlockSetupData<F, Hash>>(&std::fs::read_to_string(path)?)?;
            Ok(genesis_data)
        }
    }
}

#[cfg(test)]
mod tests {
    use parth_core::felt::ToU64Value;

    use super::*;

    #[test]
    fn local_devnet_genesis_block_time_uses_unix_seconds() -> anyhow::Result<()> {
        let genesis = get_genesis_block_setup_data_for_local_devnet_default()?;
        assert_eq!(
            genesis.checkpoint_stats.block_time.to_u64_value(),
            1_764_248_609
        );
        Ok(())
    }
    #[test]
    fn update_contract_whitelist_matches_coordinator_verifier() -> anyhow::Result<()> {
        use crate::{proving::coordinator_helper::QEDCoordinatorCircuitManager, utils::{simple_circuit_info_library::JTMBSimpleCircuitLibrary, jtmb_standard_circuit::QJTMBProofCircuitBase}};
        use parth_common::{secp256k1::MemorySecp256K1SinglePrivateKeyWallet, realm_rotation::RealmRotationConfig};
        let key = MemorySecp256K1SinglePrivateKeyWallet::new_from_private_key_bytes(&[7; 32])?;
        let manager = QEDCoordinatorCircuitManager::<JTMBPoseidonGoldilocksConfig>::new(
            &key, 4, 4, 4, 8, 1, 32, 64, 1, 2, 8, 2, 4, Hash::from_values(1, 2, 3, 4),
            RealmRotationConfig { checkpoints_per_epoch: 32, validator_sub_ids: vec![1, 2, 3] });
        let mut library = JTMBSimpleCircuitLibrary::<JTMBPoseidonGoldilocksConfig>::new();
        manager.register_library(&mut library);
        let config = get_psy_node_jtmb_poseidon_goldilocks_config_from_library(&library)?;
        let expected = Hasher::two_to_one(
            &manager.batch_update_contracts.get_fingerprint(),
            &manager.agg_state_transition.get_fingerprint(),
        );
        assert_ne!(expected, Hash::get_zero_value());
        assert_eq!(config.update_contracts_circuit_whitelist_root, expected);
        Ok(())
    }
}
