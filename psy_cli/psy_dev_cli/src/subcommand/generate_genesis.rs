use std::{path::{Path, PathBuf}, str::FromStr};

use anyhow::{Context, ensure};
use clap::Parser;
use parth_core::{
    crypto::hash::traits::{MerkleHasher, MerkleZeroHasher, ZeroableHash},
    data::hash::merkle_node_nest::{MerkleLeafNode, MerkleNodeNest},
    felt::{FromPrimitiveValuesFelt, ZeroableFelt},
    pgoldilocks::{PoseidonHasher, QHashOut},
};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::poseidon::PoseidonHash,
};
use psy_cli_common::key_utils::{load_wallet_key_info, WalletSourceArgs};
use psy_client_common::args::SignType;
use psy_core::{
    constants::protocol::DA_CHALLENGE_WINDOW,
    user_id::{UserIdBitsStrategy5, UserIdGeneratorStrategy},
};
use psy_data::{
    genesis::genesis_block_setup::PsyGenesisBlockSetupData,
    user::complete_user_record::PsyCompactUserDefinition,
    v1::qdata::{
        checkpoint::PQEDCheckpointLeafStats,
        contract::PQBCDeployContract,
        pm_jobs_completed_stats::PPMJobsCompletedStats,
        pm_rewards_commitment::PPMRewardCommitment,
        public_key::PZKPublicKeyInfo,
    },
};
use psy_plonky2_circuits::node::config::networks::local_devnet::{
    get_public_key_param, ZK_FINGERPRINT_U64,
};

type F = GoldilocksField;
type Hash = QHashOut<F>;

const DEFAULT_SD_KEY_FINGERPRINT: &str = "38755910c4dfb3c9bef528a4af697edced7e2607a6b769d054c4985a7000f0eb";
const DEFAULT_VALIDATOR_SLOTS: &[&str] = &["0,1,0", "1,1,1", "1,2,3", "0,2,4"];

#[derive(Clone, Debug)]
struct ValidatorSlot {
    realm_id: u64,
    sub_id: u64,
    registration_id: u64,
}

impl FromStr for ValidatorSlot {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(',').map(str::trim).collect();
        ensure!(
            parts.len() == 3,
            "validator slot {s:?} must be realm,sub,registration"
        );
        Ok(Self {
            realm_id: parts[0].parse().context("realm id")?,
            sub_id: parts[1].parse().context("sub id")?,
            registration_id: parts[2].parse().context("registration id")?,
        })
    }
}

#[derive(Parser, Debug)]
pub struct GenerateGenesisDataArgs {
    /// Repository root used to resolve default input and output paths.
    #[arg(long = "repo-root", default_value = ".")]
    pub repo_root: PathBuf,

    /// Compressed or plain genesis_contracts.json. Defaults to <repo-root>/psy-genesis/genesis_contracts.json.
    #[arg(long = "genesis-contracts")]
    pub genesis_contracts: Option<PathBuf>,

    /// Encrypted UTC JSON for the relayer registration. First set of PSY_BRIDGE_RELAYER_KEYSTORE_PATH, BRIDGE_RELAYER_KEYSTORE_PATH, KEYSTORE_PATH wins.
    #[arg(long = "keystore-path", env = "KEYSTORE_PATH")]
    pub keystore_path: Option<String>,

    #[arg(long = "psy-bridge-relayer-keystore-path", env = "PSY_BRIDGE_RELAYER_KEYSTORE_PATH", hide = true)]
    pub psy_bridge_relayer_keystore_path: Option<String>,

    #[arg(long = "bridge-relayer-keystore-path", env = "BRIDGE_RELAYER_KEYSTORE_PATH", hide = true)]
    pub bridge_relayer_keystore_path: Option<String>,

    /// Decrypts the UTC JSON. Required when a keystore path is used.
    #[arg(long = "wallet-password", env = "WALLET_PASSWORD")]
    pub wallet_password: Option<String>,

    /// Hex Poseidon secret for the relayer registration. Ignored when a set keystore env/flag is present.
    #[arg(long = "private-key", env = "PRIVATE_KEY")]
    pub private_key: Option<String>,

    #[arg(long = "bridge-relayer-l2-private-key", env = "BRIDGE_RELAYER_L2_PRIVATE_KEY", hide = true)]
    pub bridge_relayer_l2_private_key: Option<String>,

    /// Dense registration index of the bridge relayer.
    #[arg(long = "relayer-registration-id", default_value_t = 2)]
    pub relayer_registration_id: u64,

    /// Strategy5 user_id of the bridge relayer for the tree heights below.
    #[arg(long = "relayer-user-id", default_value_t = 524_288)]
    pub relayer_user_id: u64,

    #[arg(long = "coordinator-global-user-tree-height", default_value_t = 12)]
    pub coordinator_global_user_tree_height: u8,

    #[arg(long = "realm-global-user-tree-height", default_value_t = 20)]
    pub realm_global_user_tree_height: u8,

    #[arg(long = "group-realm-height", default_value_t = 1)]
    pub group_realm_height: u8,

    /// Validator placements as realm,sub,registration. Repeat or comma-separate groups with --validator-slot.
    #[arg(long = "validator-slot", value_delimiter = ';', default_values_t = DEFAULT_VALIDATOR_SLOTS.iter().map(|s| s.to_string()).collect::<Vec<_>>())]
    pub validator_slots: Vec<String>,

    #[arg(long = "faucet-operator-count", default_value_t = 10)]
    pub faucet_operator_count: usize,

    #[arg(long = "sd-key-fingerprint", default_value = DEFAULT_SD_KEY_FINGERPRINT)]
    pub sd_key_fingerprint: String,

    /// Hex Poseidon fingerprint for ZK users. Empty uses the local-devnet circuit constant.
    #[arg(long = "zk-fingerprint", default_value = "")]
    pub zk_fingerprint: String,

    #[arg(long = "block-time", default_value_t = 1_764_248_609u64)]
    pub block_time: u64,

    #[arg(long = "initial-fee-balance", default_value_t = 1_000_000_000_000_000u64)]
    pub initial_fee_balance: u64,

    #[arg(long = "genesis-out")]
    pub genesis_out: Option<PathBuf>,

    #[arg(long = "private-keys-out")]
    pub private_keys_out: Option<PathBuf>,

    #[arg(long = "faucet-operators-out")]
    pub faucet_operators_out: Option<PathBuf>,

    #[arg(long = "skip-faucet-operators", default_value_t = false)]
    pub skip_faucet_operators: bool,

    #[arg(long = "faucet-contract-id", default_value_t = 5)]
    pub faucet_contract_id: u64,

    #[arg(long = "faucet-method-name", default_value = "faucet")]
    pub faucet_method_name: String,

    #[arg(long = "faucet-method-id", default_value_t = 3375543263)]
    pub faucet_method_id: u64,

    #[arg(long = "faucet-per-claim-amount", default_value = "1000000000000")]
    pub faucet_per_claim_amount: String,

    #[arg(long = "sd-key-expected-tx-count", default_value_t = 3)]
    pub sd_key_expected_tx_count: u64,

    #[arg(long = "sd-key-allowed-contract-id", default_values_t = vec![5u64, 0, 0])]
    pub sd_key_allowed_contract_ids: Vec<u64>,

    #[arg(long = "sd-key-allowed-method-id", default_values_t = vec![3375543263u32, 354447671, 2923993647])]
    pub sd_key_allowed_method_ids: Vec<u32>,
}

pub async fn run(args: GenerateGenesisDataArgs) -> anyhow::Result<()> {
    generate_local_devnet_genesis(&args)
}

fn read_trimmed(raw: Option<String>) -> Option<String> {
    raw.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn require_existing_keystore_file(name: &str, path: String) -> anyhow::Result<String> {
    ensure!(
        Path::new(&path).exists(),
        "{name} is set to {path} but that file does not exist"
    );
    Ok(path)
}

fn resolve_set_keystore_path(
    psy_bridge: Option<String>,
    bridge: Option<String>,
    keystore: Option<String>,
) -> anyhow::Result<Option<String>> {
    for (name, path) in [
        ("PSY_BRIDGE_RELAYER_KEYSTORE_PATH", psy_bridge),
        ("BRIDGE_RELAYER_KEYSTORE_PATH", bridge),
        ("KEYSTORE_PATH", keystore),
    ] {
        if let Some(path) = path {
            return Ok(Some(require_existing_keystore_file(name, path)?));
        }
    }
    Ok(None)
}

fn deterministic_private_key(slot: u64) -> QHashOut<F> {
    QHashOut::from_values(
        0x9e37_79b9_7f4a_7c15u64 ^ slot.wrapping_mul(0xbf58_476d_1ce4_e5b9u64),
        0x243f_6a88_85a3_08d3u64 ^ slot.wrapping_mul(0x94d0_49bb_1331_11ebu64),
        0xb7e1_5162_8aed_2a6bu64 ^ slot.wrapping_mul(0xda94_2042_e4dd_58b5u64),
        0xc6ef_372f_e94f_82beu64 ^ slot.wrapping_mul(0x9e37_79b9_7f4a_7c15u64),
    )
}

fn resolve_bridge_relayer_private_key(args: &GenerateGenesisDataArgs) -> anyhow::Result<Option<QHashOut<F>>> {
    let set_keystore = resolve_set_keystore_path(
        read_trimmed(args.psy_bridge_relayer_keystore_path.clone()),
        read_trimmed(args.bridge_relayer_keystore_path.clone()),
        read_trimmed(args.keystore_path.clone()),
    )?;
    let private_key = if set_keystore.is_some() {
        None
    } else {
        read_trimmed(args.private_key.clone())
            .or_else(|| read_trimmed(args.bridge_relayer_l2_private_key.clone()))
    };
    let keystore_path = match set_keystore {
        Some(path) => Some(path),
        None if private_key.is_none() => std::env::var("HOME").ok().and_then(|home| {
            let default = format!("{home}/.psy/keystore/bridge-relayer");
            Path::new(&default).exists().then_some(default)
        }),
        None => None,
    };
    if private_key.is_none() && keystore_path.is_none() {
        return Ok(None);
    }
    let wallet_args = WalletSourceArgs {
        sign_type: SignType::ZKSign,
        private_key,
        keystore_path,
        wallet_password: read_trimmed(args.wallet_password.clone()),
        fingerprint: None,
        sd_key_allowed_contract_id: args.sd_key_allowed_contract_ids.clone(),
        sd_key_allowed_method_id: args.sd_key_allowed_method_ids.clone(),
        sd_key_expected_tx_count: args.sd_key_expected_tx_count,
    };
    let info = load_wallet_key_info(&wallet_args, false)?;
    Ok(Some(QHashOut::<F>::from_str(&info.private_key.to_string())?))
}

fn load_contracts(path: &Path) -> anyhow::Result<Vec<PQBCDeployContract<QHashOut<F>>>> {
    let genesis_bytes = std::fs::read(path)
        .with_context(|| format!("reading genesis contracts {}", path.display()))?;
    match serde_json::from_slice(&genesis_bytes) {
        Ok(v) => Ok(v),
        Err(_) => {
            let decoded = zstd::stream::decode_all(genesis_bytes.as_slice())
                .context("decoding zstd genesis_contracts.json")?;
            serde_json::from_slice(&decoded).context("parsing genesis_contracts.json")
        }
    }
}

fn parse_qhash(hex: &str) -> anyhow::Result<QHashOut<F>> {
    QHashOut::<F>::from_str(hex.trim()).with_context(|| format!("invalid hash {hex}"))
}

fn zk_fingerprint(args: &GenerateGenesisDataArgs) -> anyhow::Result<QHashOut<F>> {
    if args.zk_fingerprint.trim().is_empty() {
        Ok(QHashOut::<F>::from_values(
            ZK_FINGERPRINT_U64[0],
            ZK_FINGERPRINT_U64[1],
            ZK_FINGERPRINT_U64[2],
            ZK_FINGERPRINT_U64[3],
        ))
    } else {
        parse_qhash(&args.zk_fingerprint)
    }
}

fn parse_validator_slots(raw: &[String]) -> anyhow::Result<Vec<ValidatorSlot>> {
    raw.iter().map(|s| s.parse()).collect()
}

fn user_id_for(args: &GenerateGenesisDataArgs, registration_id: u64) -> u64 {
    UserIdBitsStrategy5::get_user_id_from_user_registration_id(
        registration_id,
        args.coordinator_global_user_tree_height,
        args.realm_global_user_tree_height,
        args.group_realm_height,
    )
}

fn compact_user(
    fingerprint: QHashOut<F>,
    private_key: QHashOut<F>,
    initial_fee_balance: u64,
) -> PsyCompactUserDefinition<Hash> {
    let public_key_param = get_public_key_param::<F, PoseidonHash>(private_key);
    PsyCompactUserDefinition {
        public_key_info: PZKPublicKeyInfo {
            public_key_param,
            fingerprint,
        },
        balance: 0,
        nonce: 0,
        last_checkpoint_id: 0,
        event_index: 0,
        constract_state_tree_records: vec![MerkleNodeNest {
            parent_index: 0,
            children: vec![MerkleLeafNode {
                index: 0,
                value: QHashOut::<F>::from_values(initial_fee_balance, 0, 0, 0),
            }],
        }],
    }
}

fn generate_local_devnet_genesis(args: &GenerateGenesisDataArgs) -> anyhow::Result<()> {
    let repo_root = args.repo_root.canonicalize().with_context(|| {
        format!("repo-root {} does not exist", args.repo_root.display())
    })?;
    let contracts_path = args.genesis_contracts.clone().unwrap_or_else(|| {
        repo_root.join("psy-genesis/genesis_contracts.json")
    });
    let contracts = load_contracts(&contracts_path)?;
    let validator_slots = parse_validator_slots(&args.validator_slots)?;
    let zk_fingerprint = zk_fingerprint(args)?;
    let sd_key_fingerprint = parse_qhash(&args.sd_key_fingerprint)?;
    let relayer_private_key = resolve_bridge_relayer_private_key(args)?;

    let special_zk_user_count = validator_slots.len() + 1;
    let mut users = Vec::with_capacity(special_zk_user_count + args.faucet_operator_count);
    let mut private_keys = Vec::with_capacity(special_zk_user_count + args.faucet_operator_count);

    let mut next_registration: u64 = 0;
    let mut validator_iter = validator_slots.iter().peekable();
    while next_registration < special_zk_user_count as u64 {
        if next_registration == args.relayer_registration_id {
            let relayer_key = relayer_private_key
                .unwrap_or_else(|| deterministic_private_key(args.relayer_registration_id));
            private_keys.push(relayer_key);
            users.push(compact_user(zk_fingerprint, relayer_key, args.initial_fee_balance));
            let user_id = user_id_for(args, args.relayer_registration_id);
            ensure!(
                user_id == args.relayer_user_id,
                "relayer registration {} maps to user_id {user_id}, not --relayer-user-id {}",
                args.relayer_registration_id,
                args.relayer_user_id
            );
            next_registration += 1;
            continue;
        }

        let slot = validator_iter
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing --validator-slot for registration {next_registration}"))?;
        ensure!(
            slot.registration_id == next_registration,
            "validator slot registration {} does not match dense cursor {next_registration}",
            slot.registration_id
        );
        let private_key = deterministic_private_key(slot.registration_id);
        private_keys.push(private_key);
        users.push(compact_user(zk_fingerprint, private_key, args.initial_fee_balance));
        let user_id = user_id_for(args, slot.registration_id);
        let realm_start = slot.realm_id << args.realm_global_user_tree_height;
        let realm_end = (slot.realm_id + 1) << args.realm_global_user_tree_height;
        ensure!(
            (realm_start..realm_end).contains(&user_id),
            "reserved validator registration {} maps to user_id {user_id} outside realm {}",
            slot.registration_id,
            slot.realm_id
        );
        let _ = slot.sub_id;
        next_registration += 1;
    }
    ensure!(validator_iter.next().is_none(), "unused --validator-slot values remain");

    for i in 0..args.faucet_operator_count {
        let slot = special_zk_user_count + i;
        let private_key = deterministic_private_key(slot as u64);
        private_keys.push(private_key);
        users.push(compact_user(sd_key_fingerprint, private_key, args.initial_fee_balance));
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
            block_time: F::from_u64_value(args.block_time),
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
    };

    let genesis_path = args.genesis_out.clone().unwrap_or_else(|| repo_root.join("genesis.json"));
    let private_keys_path = args.private_keys_out.clone().unwrap_or_else(|| repo_root.join("private_keys.json"));
    if let Some(parent) = genesis_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Some(parent) = private_keys_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&genesis_path, serde_json::to_string_pretty(&genesis_data)?)
        .with_context(|| format!("writing {}", genesis_path.display()))?;
    std::fs::write(&private_keys_path, serde_json::to_string_pretty(&private_keys)?)
        .with_context(|| format!("writing {}", private_keys_path.display()))?;

    let mut faucet_operators_written = None;
    if !args.skip_faucet_operators {
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
            sd_key_expected_tx_count: u64,
            #[serde(rename = "sdKeyAllowedContractIds")]
            sd_key_allowed_contract_ids: Vec<u64>,
            #[serde(rename = "sdKeyAllowedMethodIds")]
            sd_key_allowed_method_ids: Vec<u32>,
            operators: Vec<FaucetOperatorJson>,
        }

        let operators: Vec<FaucetOperatorJson> = (0..args.faucet_operator_count)
            .map(|i| {
                let slot = special_zk_user_count + i;
                let pk = private_keys[slot];
                let user_id = user_id_for(args, slot as u64);
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
            faucet_contract_id: args.faucet_contract_id,
            faucet_method_name: args.faucet_method_name.clone(),
            faucet_method_id: args.faucet_method_id,
            faucet_per_claim_amount: args.faucet_per_claim_amount.clone(),
            sd_key_expected_tx_count: args.sd_key_expected_tx_count,
            sd_key_allowed_contract_ids: args.sd_key_allowed_contract_ids.clone(),
            sd_key_allowed_method_ids: args.sd_key_allowed_method_ids.clone(),
            operators,
        };
        let faucet_operators_path = args.faucet_operators_out.clone().unwrap_or_else(|| {
            repo_root.join("psy-dapp/apps/bridge/src/config/faucetOperators.json")
        });
        if let Some(parent) = faucet_operators_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(
            &faucet_operators_path,
            serde_json::to_string_pretty(&faucet_operators)?,
        )
        .with_context(|| format!("writing {}", faucet_operators_path.display()))?;
        faucet_operators_written = Some(faucet_operators_path);
    }

    tracing::info!(
        genesis = %genesis_path.display(),
        private_keys = %private_keys_path.display(),
        faucet_operators = ?faucet_operators_written.as_ref().map(|p| p.display().to_string()),
        relayer_from_keystore = relayer_private_key.is_some(),
        "wrote local-devnet genesis artifacts"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_keystore_fails_closed_when_missing() {
        let err = resolve_set_keystore_path(
            Some("/definitely-missing-psy-relayer-keystore".into()),
            Some("/tmp".into()),
            None,
        )
        .expect_err("missing first-set path must not skip to a later existing path");
        assert!(err.to_string().contains("does not exist"), "{err}");
    }

    #[test]
    fn first_set_keystore_alias_wins() {
        let path = resolve_set_keystore_path(None, Some("/tmp".into()), Some("/nonexistent".into()))
            .expect("second alias exists");
        assert_eq!(path.as_deref(), Some("/tmp"));
    }

    #[test]
    fn unset_aliases_are_none() {
        assert_eq!(resolve_set_keystore_path(None, None, None).unwrap(), None);
    }

    #[test]
    fn default_relayer_registration_maps_to_default_user_id() {
        let user_id = UserIdBitsStrategy5::get_user_id_from_user_registration_id(2, 12, 20, 1);
        assert_eq!(user_id, 524_288);
    }

    #[test]
    fn validator_slot_parses_realm_sub_registration() {
        let slot: ValidatorSlot = "1,2,3".parse().unwrap();
        assert_eq!((slot.realm_id, slot.sub_id, slot.registration_id), (1, 2, 3));
    }
}
