use parth_core::{
    crypto::hash::traits::{MerkleHasher, MerkleZeroHasher, ZeroableHash},
    felt::{FromPrimitiveValuesFelt, ZeroableFelt},
    pgoldilocks::{PoseidonHasher, QHashOut},
};
use plonky2::{hash::hash_types::RichField, plonk::config::AlgebraicHasher};
use psy_core::{constants::protocol::DA_CHALLENGE_WINDOW, job::job_id::ProvingJobCircuitType};
use psy_data::{
    config::network_config::PsyNodeCircuitFingerprintConfig,
    genesis::genesis_block_setup::PsyGenesisBlockSetupData,
    v1::qdata::{checkpoint::PQEDCheckpointLeafStats, pm_jobs_completed_stats::PPMJobsCompletedStats, pm_rewards_commitment::PPMRewardCommitment},
};
use psy_plonky2_basic_helpers::verifier::circuit_library::CircuitInfoLibraryCore;

use crate::generated::cached_circuit_library::get_cached_circuit_library;
type F = parth_core::PF;
type Hash = parth_core::PHash;
type Hasher = PoseidonHasher;
pub fn get_psy_node_circuit_config_for_local_devnet() -> anyhow::Result<PsyNodeCircuitFingerprintConfig<Hash>> {
    let lib = get_cached_circuit_library::<F>();
    let guta_circuit_whitelist_root = lib
        .get_group_inclusion_proof(ProvingJobCircuitType::GUTATwoGUTA, ProvingJobCircuitType::GUTATwoGUTA)?
        .root;

    let append_user_registration_tree_fingerprint = lib.get_fingerprint(ProvingJobCircuitType::AppendUserRegistrationTree)?;
    let batch_deploy_contracts_fingerprint = lib.get_fingerprint(ProvingJobCircuitType::BatchDeployContracts)?;
    let agg_state_transition_fingerprint = lib.get_fingerprint(ProvingJobCircuitType::BatchDeployContractsAggregate)?;

    let register_users_circuit_whitelist_root = Hasher::two_to_one(&append_user_registration_tree_fingerprint, &agg_state_transition_fingerprint);

    let deploy_contracts_circuit_whitelist_root = Hasher::two_to_one(&batch_deploy_contracts_fingerprint, &agg_state_transition_fingerprint);

    let checkpoint_state_transition_circuit_fingerprint = lib.get_fingerprint(ProvingJobCircuitType::GenerateRollupStateTransitionProof)?;

    Ok(PsyNodeCircuitFingerprintConfig {
        guta_circuit_whitelist_root,
        register_users_circuit_whitelist_root,
        deploy_contracts_circuit_whitelist_root,
        checkpoint_state_transition_circuit_fingerprint,
    })
}

pub fn get_genesis_block_setup_data_for_local_devnet_default() -> anyhow::Result<PsyGenesisBlockSetupData<F, Hash>> {
    Ok(PsyGenesisBlockSetupData {
        contracts: vec![],
        users: vec![],
        checkpoint_stats: PQEDCheckpointLeafStats {
            fees_collected: F::ZERO_VALUE,
            user_ops_processed: F::ZERO_VALUE,
            total_transactions: F::ZERO_VALUE,
            slots_modified: F::ZERO_VALUE,
            pm_jobs_completed: PPMJobsCompletedStats {
                deploy_contracts_completed: F::ZERO_VALUE,
                register_users_completed: F::ZERO_VALUE,
                gutas_completed: F::ZERO_VALUE,
            },
            block_time: F::from_u64_value(1764248609350u64),
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
    })
}

pub fn get_genesis_block_setup_data_for_local_devnet(genesis_data_path: Option<String>) -> anyhow::Result<PsyGenesisBlockSetupData<F, Hash>> {
    match genesis_data_path {
        None => get_genesis_block_setup_data_for_local_devnet_default(),
        Some(path) => {
            let genesis_data = serde_json::from_str::<PsyGenesisBlockSetupData<F, Hash>>(
                &std::fs::read_to_string(path).map_err(|err| anyhow::format_err!("reading genesis file error: {}", err))?,
            )
            .map_err(|err| anyhow::format_err!("parsing genesis file error: {}", err))?;
            Ok(genesis_data)
        }
    }
}

pub static PRIVATE_KEY_CONSTANTS: [u64; 20] = [
    0x778e50b9dd8594bbu64,
    0xed002cebe1ee4f45u64,
    0x892f65737845d0e7u64,
    0x943cd37231de09f1u64,
    0xaf006f1eab88773eu64,
    0x5d42870ae2270fb3u64,
    0xe7694b0d45f52b0du64,
    0x51133e2ed8491c34u64,
    0x56e76757187dede1u64,
    0x79d0eed9ddf5670bu64,
    0x3e642be8e3b3e541u64,
    0x492c60967aaa688fu64,
    0xa7460ab3f6fee8ffu64,
    0x29dfc928bf4e29acu64,
    0x37d15e6391bb8841u64,
    0xeace73452965c4e8u64,
    0x75841f6eea927c6fu64,
    0x8823d0f893734f95u64,
    0x83c02d4b34e8a6d4u64,
    0x5b22e8cfb5b1a0abu64,
];

pub const ZK_FINGERPRINT_U64: [u64; 4] = [10809942084296272720, 6801881445144280090, 13901098532226573745, 7340892251884443121];

pub fn get_public_key_param<F: RichField, H: AlgebraicHasher<F>>(private_key: QHashOut<F>) -> QHashOut<F> {
    QHashOut(H::hash_no_pad(&[
        F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[0]),
        F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[1]),
        F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[2]),
        F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[19]),
        private_key.0.elements[1],
        F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[1]),
        F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[2]),
        F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[3]),
        F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[4]),
        F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[5]),
        F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[6]),
        private_key.0.elements[0],
        F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[7]),
        private_key.0.elements[2],
        F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[8]),
        F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[9]),
        F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[10]),
        F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[11]),
        F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[12]),
        private_key.0.elements[3],
        F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[13]),
        F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[14]),
        F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[15]),
        F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[16]),
        F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[17]),
        F::from_canonical_u64(PRIVATE_KEY_CONSTANTS[18]),
    ]))
}

mod tests {
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        hash::poseidon::PoseidonHash,
        plonk::config::Hasher,
    };
    use psy_data::{
        user::complete_user_record::PsyCompactUserDefinition,
        v1::qdata::{
            contract::{ContractCodeDefinition, PQBCDeployContract},
            public_key::{self, PZKPublicKeyInfo},
        },
    };

    use super::*;

    type F = GoldilocksField;
    type Hash = QHashOut<F>;

    #[test]
    fn test_generate_genesis_block_setup_data_for_local_devnet() -> anyhow::Result<()> {
        let contracts = serde_json::from_str::<Vec<PQBCDeployContract<QHashOut<F>>>>(include_str!("../../../../../token.deploy.json"))?;
        let mut users = Vec::with_capacity(1<<19);
        let mut private_keys = Vec::with_capacity(1<<19);

        let zk_fingerprint = QHashOut::<F>::from_values(ZK_FINGERPRINT_U64[0], ZK_FINGERPRINT_U64[1], ZK_FINGERPRINT_U64[2], ZK_FINGERPRINT_U64[3]);

        for i in 0..1 << 19 {
            let private_key = QHashOut(PoseidonHash::hash_no_pad(&[F::from_canonical_u64(i)]));
            private_keys.push(private_key);
            let public_key_param = get_public_key_param::<F, PoseidonHash>(private_key);
            users.push(PsyCompactUserDefinition {
                public_key_info: PZKPublicKeyInfo {
                    public_key_param,
                    fingerprint: zk_fingerprint,
                },
                balance: 0,
                nonce: 0,
                last_checkpoint_id: 0,
                event_index: 0,
                constract_state_tree_records: vec![],
            });
        }

        let genesis_data = PsyGenesisBlockSetupData {
            contracts,
            users,
            checkpoint_stats: PQEDCheckpointLeafStats {
                fees_collected: F::ZERO_VALUE,
                user_ops_processed: F::ZERO_VALUE,
                total_transactions: F::ZERO_VALUE,
                slots_modified: F::ZERO_VALUE,
                pm_jobs_completed: PPMJobsCompletedStats {
                    deploy_contracts_completed: F::ZERO_VALUE,
                    register_users_completed: F::ZERO_VALUE,
                    gutas_completed: F::ZERO_VALUE,
                },
                block_time: F::from_u64_value(1764248609350u64),
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
        };

        let project_dir = env!("CARGO_MANIFEST_DIR");

        std::fs::write(&format!("{}/../genesis.json", project_dir), serde_json::to_string_pretty(&genesis_data)?)?;
        std::fs::write(&format!("{}/../private_keys.json", project_dir), serde_json::to_string_pretty(&private_keys)?)?;

        Ok(())
    }
}
