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
    let batch_update_contracts_fingerprint = lib.get_fingerprint(ProvingJobCircuitType::BatchUpdateContracts)?;

    let register_users_circuit_whitelist_root = Hasher::two_to_one(&append_user_registration_tree_fingerprint, &agg_state_transition_fingerprint);

    let deploy_contracts_circuit_whitelist_root = Hasher::two_to_one(&batch_deploy_contracts_fingerprint, &agg_state_transition_fingerprint);

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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use parth_core::data::hash::merkle_node_nest::{MerkleLeafNode, MerkleNodeNest};
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::{Field, PrimeField64}},
        hash::poseidon::PoseidonHash,
        plonk::config::Hasher,
    };
    use psy_cli_common::key_utils::{load_wallet_key_info, WalletSourceArgs};
    use psy_client_common::args::SignType;
    use psy_core::user_id::{UserIdBitsStrategy5, UserIdGeneratorStrategy};
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
    fn local_devnet_genesis_block_time_uses_unix_seconds() -> anyhow::Result<()> {
        let genesis = get_genesis_block_setup_data_for_local_devnet_default()?;
        assert_eq!(
            genesis.checkpoint_stats.block_time.to_canonical_u64(),
            1_764_248_609
        );
        Ok(())
    }

    fn deterministic_private_key(slot: u64) -> QHashOut<F> {
        // Stable per-slot key derivation for local devnet artifacts.
        QHashOut::from_values(
            0x9e37_79b9_7f4a_7c15u64 ^ slot.wrapping_mul(0xbf58_476d_1ce4_e5b9u64),
            0x243f_6a88_85a3_08d3u64 ^ slot.wrapping_mul(0x94d0_49bb_1331_11ebu64),
            0xb7e1_5162_8aed_2a6bu64 ^ slot.wrapping_mul(0xda94_2042_e4dd_58b5u64),
            0xc6ef_372f_e94f_82beu64 ^ slot.wrapping_mul(0x9e37_79b9_7f4a_7c15u64),
        )
    }

    fn read_env(name: &str) -> Option<String> {
        std::env::var(name)
            .ok()
            .map(|raw| raw.trim().to_string())
            .filter(|raw| !raw.is_empty())
    }

    fn first_existing_explicit_keystore_path(paths: [Option<String>; 2]) -> Option<String> {
        for path in paths.into_iter().flatten() {
            if std::path::Path::new(&path).exists() {
                return Some(path);
            }
        }
        None
    }

    fn resolve_bridge_relayer_private_key() -> anyhow::Result<Option<QHashOut<F>>> {
        let private_key = read_env("PRIVATE_KEY").or_else(|| read_env("BRIDGE_RELAYER_L2_PRIVATE_KEY"));
        let keystore_path = first_existing_explicit_keystore_path([
            read_env("KEYSTORE_PATH"),
            read_env("BRIDGE_RELAYER_KEYSTORE_PATH"),
        ])
            .or_else(|| {
                // Use the daemon default only when it actually exists. A
                // missing default keystore should not block fresh genesis
                // generation; deployments without an explicit relayer key can
                // still create a random genesis key.
                let default = format!("{}/.psy/keystore/bridge-relayer", std::env::var("HOME").ok()?);
                std::path::Path::new(&default).exists().then_some(default)
            });
        let wallet_password = read_env("WALLET_PASSWORD");

        if private_key.is_none() && keystore_path.is_none() {
            return Ok(None);
        }

        let wallet_args = WalletSourceArgs {
            sign_type: SignType::ZKSign,
            private_key,
            keystore_path,
            wallet_password,
            fingerprint: None,
            sd_key_allowed_contract_id: vec![5, 0, 0],
            sd_key_allowed_method_id: vec![3375543263, 354447671, 2923993647],
            sd_key_expected_tx_count: 3,
        };
        let info = load_wallet_key_info(&wallet_args, false)?;
        Ok(Some(QHashOut::<F>::from_str(&info.private_key.to_string())?))
    }

    #[test]
    fn explicit_bridge_relayer_keystore_must_exist() -> anyhow::Result<()> {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let existing_path = std::env::temp_dir().join(format!(
            "psy-bridge-relayer-keystore-{}-{unique}",
            std::process::id()
        ));
        let missing_path = existing_path.with_extension("missing");
        std::fs::write(&existing_path, b"test")?;
        let existing_path = existing_path.to_string_lossy().into_owned();
        let missing_path = missing_path.to_string_lossy().into_owned();

        assert_eq!(
            first_existing_explicit_keystore_path([Some(missing_path.clone()), Some(existing_path.clone())]),
            Some(existing_path.clone())
        );
        assert_eq!(
            first_existing_explicit_keystore_path([Some(existing_path.clone()), Some(missing_path.clone())]),
            Some(existing_path.clone())
        );
        assert_eq!(first_existing_explicit_keystore_path([Some(missing_path), None]), None);

        std::fs::remove_file(existing_path)?;
        Ok(())
    }

    #[test]
    fn test_generate_genesis_block_setup_data_for_local_devnet() -> anyhow::Result<()> {
        let genesis_bytes: &[u8] = include_bytes!("../../../../../psy-genesis/genesis_contracts.json");
        let contracts: Vec<PQBCDeployContract<QHashOut<F>>> = match serde_json::from_slice(genesis_bytes) {
            Ok(v) => v,
            Err(_) => {
                let decoded = zstd::stream::decode_all(genesis_bytes)?;
                serde_json::from_slice(&decoded)?
            }
        };
        let mut users = Vec::with_capacity(1 << 19);
        let mut private_keys = Vec::with_capacity(1 << 19);

        let zk_fingerprint = QHashOut::<F>::from_values(ZK_FINGERPRINT_U64[0], ZK_FINGERPRINT_U64[1], ZK_FINGERPRINT_U64[2], ZK_FINGERPRINT_U64[3]);
        let sd_key_fingerprint = QHashOut::<F>::from_str("38755910c4dfb3c9bef528a4af697edced7e2607a6b769d054c4985a7000f0eb")?;

        let relayer_private_key = resolve_bridge_relayer_private_key()?;

        for i in 0..1 << 2 {
            let private_key = if i == 2 {
                relayer_private_key.unwrap_or_else(|| deterministic_private_key(i as u64))
            } else {
                deterministic_private_key(i as u64)
            };
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
                constract_state_tree_records: vec![MerkleNodeNest {
                    parent_index: 0,
                    children: vec![MerkleLeafNode {
                        index: 0,
                        value: QHashOut::<F>::from_values(1_000_000_000_000_000, 0, 0, 0),
                    }],
                }],
            });
        }

        for i in 0..10 {
            let private_key = deterministic_private_key(((1 << 2) + i) as u64);
            private_keys.push(private_key);
            let public_key_param = get_public_key_param::<F, PoseidonHash>(private_key);
            users.push(PsyCompactUserDefinition {
                public_key_info: PZKPublicKeyInfo {
                    public_key_param,
                    fingerprint: sd_key_fingerprint,
                },
                balance: 0,
                nonce: 0,
                last_checkpoint_id: 0,
                event_index: 0,
                constract_state_tree_records: vec![MerkleNodeNest {
                    parent_index: 0,
                    children: vec![MerkleLeafNode {
                        index: 0,
                        value: QHashOut::<F>::from_values(1_000_000_000_000_000, 0, 0, 0),
                    }],
                }],
            });
        }

        let genesis_data = PsyGenesisBlockSetupData {
            contracts,
            users,
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
        };

        let project_dir = env!("CARGO_MANIFEST_DIR");
        let genesis_output_path = std::env::var("PSY_GENESIS_OUTPUT_PATH")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::Path::new(project_dir).join("../genesis.json"));
        let private_keys_output_path = std::env::var("PSY_PRIVATE_KEYS_OUTPUT_PATH")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::Path::new(project_dir).join("../private_keys.json"));
        for output_path in [&genesis_output_path, &private_keys_output_path] {
            if let Some(parent) = output_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
        }
        std::fs::write(genesis_output_path, serde_json::to_string_pretty(&genesis_data)?)?;
        std::fs::write(private_keys_output_path, serde_json::to_string_pretty(&private_keys)?)?;

        // Emit faucet operator config for psy-privacy-bridge. The 10 sd-key
        // users above (slots 4..14) are the faucet operators; their userId in
        // the indexer is the Strategy5-mapped registration id, and `address`
        // is the same Poseidon public key param the genesis user record uses.
        #[derive(serde::Serialize)]
        struct FaucetOperatorJson {
            #[serde(rename = "userId")]
            user_id: String,
            address: String,
            #[serde(rename = "privateKey")]
            private_key: String,
            fingerprint: String,
            #[serde(rename = "signType")]
            sign_type: String,
        }

        #[derive(serde::Serialize)]
        struct FaucetOperatorsJson {
            #[serde(rename = "faucetContractId")]
            faucet_contract_id: u64,
            #[serde(rename = "faucetMethodName")]
            faucet_method_name: String,
            #[serde(rename = "faucetMethodId")]
            faucet_method_id: u64,
            #[serde(rename = "faucetPerClaimAmount")]
            faucet_per_claim_amount: String,
            #[serde(rename = "sdKeyExpectedTxCount")]
            sd_key_expected_tx_count: u32,
            #[serde(rename = "sdKeyAllowedContractIds")]
            sd_key_allowed_contract_ids: Vec<u64>,
            #[serde(rename = "sdKeyAllowedMethodIds")]
            sd_key_allowed_method_ids: Vec<u32>,
            operators: Vec<FaucetOperatorJson>,
        }

        const LOCAL_DEVNET_COORDINATOR_GLOBAL_USER_TREE_HEIGHT: u8 = 12;
        const LOCAL_DEVNET_REALM_GLOBAL_USER_TREE_HEIGHT: u8 = 20;
        const LOCAL_DEVNET_GROUP_REALM_HEIGHT: u8 = 1;
        const FAUCET_OPERATOR_SLOT_START: usize = 4;
        const FAUCET_OPERATOR_COUNT: usize = 10;

        let operators: Vec<FaucetOperatorJson> = (0..FAUCET_OPERATOR_COUNT)
            .map(|i| {
                let slot = FAUCET_OPERATOR_SLOT_START + i;
                let pk = private_keys[slot];
                let user_id = UserIdBitsStrategy5::get_user_id_from_user_registration_id(
                    slot as u64,
                    LOCAL_DEVNET_COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
                    LOCAL_DEVNET_REALM_GLOBAL_USER_TREE_HEIGHT,
                    LOCAL_DEVNET_GROUP_REALM_HEIGHT,
                );
                let public_key_param = get_public_key_param::<F, PoseidonHash>(pk);
                let pk_info = PZKPublicKeyInfo {
                    fingerprint: sd_key_fingerprint,
                    public_key_param,
                };
                let address = pk_info.to_hash::<PoseidonHasher>();
                FaucetOperatorJson {
                    user_id: user_id.to_string(),
                    address: format!("{}", address),
                    private_key: format!("{}", pk),
                    fingerprint: format!("{}", sd_key_fingerprint),
                    sign_type: "sd-key".to_string(),
                }
            })
            .collect();

        let faucet_operators = FaucetOperatorsJson {
            faucet_contract_id: 5,
            faucet_method_name: "faucet".to_string(),
            faucet_method_id: 3375543263,
            faucet_per_claim_amount: "1000000000000".to_string(),
            sd_key_expected_tx_count: 3,
            sd_key_allowed_contract_ids: vec![5, 0, 0],
            sd_key_allowed_method_ids: vec![3375543263, 354447671, 2923993647],
            operators,
        };

        let faucet_operators_path = std::env::var("PSY_FAUCET_OPERATORS_OUTPUT_PATH")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                std::path::Path::new(project_dir)
                    .join("../psy-dapp/apps/bridge/src/config/faucetOperators.json")
            });
        if let Some(parent) = faucet_operators_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(
            faucet_operators_path,
            serde_json::to_string_pretty(&faucet_operators)?,
        )?;

        Ok(())
    }
}
