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
use plonky2::field::types::Field64;
use psy_ups_circuit::signature::multisig::MultisigSignatureCircuit;
use psy_vm::ups::multisig::{MultisigAccount, MultisigPolicy};
use psy_client_common::data::qhashout::QHashOut as ClientHash;
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

    /// Public initial two-of-three account JSON; never a signer secret.
    #[arg(long = "relayer-multisig-account")]
    pub relayer_multisig_account: PathBuf,

    /// Approved local compiler multisig_policy artifact, including its ABI.
    #[arg(long = "multisig-policy-artifact")]
    pub multisig_policy_artifact: PathBuf,

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


fn deterministic_private_key(slot: u64) -> QHashOut<F> {
    QHashOut::from_values(
        0x9e37_79b9_7f4a_7c15u64 ^ slot.wrapping_mul(0xbf58_476d_1ce4_e5b9u64),
        0x243f_6a88_85a3_08d3u64 ^ slot.wrapping_mul(0x94d0_49bb_1331_11ebu64),
        0xb7e1_5162_8aed_2a6bu64 ^ slot.wrapping_mul(0xda94_2042_e4dd_58b5u64),
        0xc6ef_372f_e94f_82beu64 ^ slot.wrapping_mul(0x9e37_79b9_7f4a_7c15u64),
    )
}

fn decode_relayer_multisig_account(bytes: &[u8]) -> anyhow::Result<MultisigAccount> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PublicPolicy {
        version: u32,
        threshold: u8,
        member_count: u8,
        member_hashes: [ClientHash<F>; 8],
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PublicAccount {
        contract_id: u32,
        initial_policy: PublicPolicy,
    }
    let input: PublicAccount = serde_json::from_slice(bytes).context("invalid public multisig account")?;
    let account = MultisigAccount {
        contract_id: input.contract_id,
        initial_policy: MultisigPolicy {
            version: input.initial_policy.version,
            threshold: input.initial_policy.threshold,
            member_count: input.initial_policy.member_count,
            member_hashes: input.initial_policy.member_hashes,
        },
    };
    account.public_key_param()?;
    Ok(account)
}

fn read_public_input(repo_root: &Path, path: &Path) -> anyhow::Result<Vec<u8>> {
    ensure!(!path.as_os_str().is_empty(), "public input path must not be empty");
    let path = repo_root.join(path);
    ensure!(path.is_file(), "public input {} must be an existing regular file", path.display());
    std::fs::read(&path).with_context(|| format!("reading public input {}", path.display()))
}

fn initialized_multisig_user(
    account: &MultisigAccount,
    circuit: &MultisigSignatureCircuit,
    initial_fee_balance: u64,
) -> anyhow::Result<PsyCompactUserDefinition<Hash>> {
    ensure!(initial_fee_balance > 0 && initial_fee_balance < F::ORDER, "initial fee balance must be nonzero and canonical");
    let public_key_info = PZKPublicKeyInfo {
        fingerprint: QHashOut(circuit.get_fingerprint().0),
        public_key_param: QHashOut(account.public_key_param()?.0),
    };
    let mut policy_slots = vec![MerkleLeafNode { index: 0, value: QHashOut::from_values(1, 2, 3, 0) }];
    policy_slots.extend(account.initial_policy.member_hashes[..3].iter().enumerate().map(|(index, member)| {
        MerkleLeafNode { index: index as u64 + 1, value: QHashOut(member.0) }
    }));
    Ok(PsyCompactUserDefinition {
        public_key_info, balance: 0, nonce: 0, last_checkpoint_id: 0, event_index: 0,
        constract_state_tree_records: vec![
            MerkleNodeNest { parent_index: 0, children: vec![MerkleLeafNode {
                index: 0, value: QHashOut::from_values(initial_fee_balance, 0, 0, 0),
            }] },
            MerkleNodeNest { parent_index: u64::from(account.contract_id), children: policy_slots },
        ],
    })
}

fn validate_multisig_policy_artifact(
    contracts: &[PQBCDeployContract<Hash>],
    bytes: &[u8],
) -> anyhow::Result<()> {
    use psy_client_data::config::store_config::{C, D};
    use psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition;
    #[derive(serde::Deserialize)]
    struct PolicyArtifact {
        state_tree_height: u16,
        circuit_definitions: Vec<DPNFunctionCircuitDefinition>,
        abi: serde_json::Value,
    }
    let artifact: PolicyArtifact = serde_json::from_slice(bytes).context("invalid multisig policy compiler artifact")?;
    ensure!(artifact.state_tree_height == 4, "multisig policy artifact must declare height 4");
    ensure!(artifact.circuit_definitions.len() == 2
        && ["get_policy", "set_policy"].iter().all(|name| artifact.circuit_definitions.iter().filter(|definition| definition.name == *name).count() == 1),
        "multisig policy artifact requires exactly get_policy and set_policy");
    ensure!(artifact.abi.pointer("/contract/state_tree_height").and_then(serde_json::Value::as_u64) == Some(4),
        "multisig policy ABI must declare height 4");
    let methods = artifact.abi.pointer("/contract/methods").and_then(serde_json::Value::as_array)
        .context("multisig policy ABI methods are missing")?;
    ensure!(methods.len() == 2, "multisig policy ABI must declare two methods");
    for definition in &artifact.circuit_definitions {
        let mut matches = methods.iter().filter(|method| method["name"].as_str() == Some(definition.name.as_str()));
        let method = matches.next().context("multisig policy ABI method is missing")?;
        ensure!(matches.next().is_none(), "multisig policy ABI method is duplicated");
        ensure!(method["method_id"].as_u64() == Some(u64::from(definition.method_id))
            && method["input_felt_count"].as_u64() == Some(definition.circuit_inputs.len() as u64)
            && method["output_felt_count"].as_u64() == Some(definition.circuit_outputs.len() as u64)
            && method["state_mutability"].as_str() == Some(if definition.is_view_function() { "view" } else { "external" }),
            "multisig policy ABI differs from compiled method");
    }
    validate_policy_abi_slots(&artifact.abi)?;
    let contract = contracts.get(6).context("Genesis contracts must contain multisig policy contract 6")?;
    ensure!(contract.code_definition.state_tree_height == 4, "Genesis policy contract must declare height 4");
    let (_, expected) = psy_prover::session::gen_contract_deploy_and_circuits_for_functions::<C, D>(
        contract.deployer, 4, &artifact.circuit_definitions,
    )?;
    let expected: PQBCDeployContract<Hash> = serde_json::from_value(serde_json::to_value(expected)?)?;
    ensure!(contract == &expected, "Genesis policy code/functions differ from approved compiler artifact");
    Ok(())
}

fn validate_policy_abi_slots(abi: &serde_json::Value) -> anyhow::Result<()> {
    ensure!(abi["schema_version"].as_str() == Some("2.0.0"), "multisig policy requires ABI 2.0.0");
    let fields = abi.pointer("/contract/state").and_then(serde_json::Value::as_array)
        .context("multisig policy ABI state is missing")?;
    let hash_type = serde_json::json!({"kind":"primitive","name":"Hash"});
    let members_type = serde_json::json!({"kind":"array","item":hash_type,"length":3,"item_felt_size":4});
    ensure!(fields.len() == 2 && fields[0]["name"].as_str() == Some("header")
        && fields[0]["offset"].as_u64() == Some(0) && fields[0]["felt_size"].as_u64() == Some(4)
        && fields[0]["type"] == hash_type
        && fields[1]["name"].as_str() == Some("members") && fields[1]["offset"].as_u64() == Some(4)
        && fields[1]["felt_size"].as_u64() == Some(12) && fields[1]["type"] == members_type,
        "multisig policy ABI must expose header and three members at slots 0 through 3");
    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GenesisContractsArtifactStamp {
    compiler_revision: String,
    compiler_sources_hash: String,
    artifact_sha256: String,
    artifact_byte_size: u64,
    token_artifact_sha256: String,
    token_artifact_byte_size: u64,
    token_update_artifact_sha256: String,
    token_update_artifact_byte_size: u64,
}

fn validate_contracts_stamp(bytes: &[u8], bundle: &[u8]) -> anyhow::Result<()> {
    use sha2::{Digest, Sha256};
    ensure!(bytes.len() <= 65_536, "Genesis compiler stamp exceeds 65536 bytes");
    let stamp: GenesisContractsArtifactStamp = serde_json::from_slice(bytes).context("invalid Genesis compiler stamp")?;
    for (value, length) in [(&stamp.compiler_revision, 40), (&stamp.compiler_sources_hash, 64),
        (&stamp.artifact_sha256, 64), (&stamp.token_artifact_sha256, 64), (&stamp.token_update_artifact_sha256, 64)] {
        ensure!(value.len() == length && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "Genesis compiler stamp requires lowercase fixed-width hexadecimal identities");
    }
    let _ = (stamp.token_artifact_byte_size, stamp.token_update_artifact_byte_size);
    ensure!(stamp.artifact_byte_size == u64::try_from(bundle.len())?, "Genesis compiler stamp byte size mismatch");
    ensure!(stamp.artifact_sha256 == hex::encode(Sha256::digest(bundle)), "Genesis compiler stamp SHA-256 mismatch");
    Ok(())
}

fn load_contracts(path: &Path) -> anyhow::Result<Vec<PQBCDeployContract<Hash>>> {
    use std::io::Read;
    let genesis_bytes = std::fs::read(path)
        .with_context(|| format!("reading genesis contracts {}", path.display()))?;
    let stamp_path = path.parent().context("Genesis contracts path has no parent")?.join(".genesis_contracts.compiler-artifact.json");
    let stamp_file = std::fs::File::open(&stamp_path).context("opening locally approved Genesis compiler stamp")?;
    let metadata = stamp_file.metadata()?;
    ensure!(metadata.is_file() && metadata.len() <= 65_536, "Genesis compiler stamp must be a regular file of at most 65536 bytes");
    let mut stamp_bytes = Vec::with_capacity(metadata.len() as usize);
    (&stamp_file).take(65_536).read_to_end(&mut stamp_bytes)?;
    ensure!(stamp_file.metadata()?.len() == stamp_bytes.len() as u64, "Genesis compiler stamp changed size while reading");
    validate_contracts_stamp(&stamp_bytes, &genesis_bytes)?;
    let decoded;
    let json = if genesis_bytes.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        decoded = zstd::stream::decode_all(genesis_bytes.as_slice()).context("decoding zstd genesis_contracts.json")?;
        decoded.as_slice()
    } else {
        genesis_bytes.as_slice()
    };
    #[derive(serde::Deserialize)]
    struct NamedDeployment {
        name: String,
        #[serde(flatten)]
        deployment: PQBCDeployContract<Hash>,
    }
    let named: Vec<NamedDeployment> = serde_json::from_slice(json).context("parsing flat named Genesis deployments")?;
    let mut names = std::collections::HashSet::with_capacity(named.len());
    for entry in &named {
        ensure!(!entry.name.trim().is_empty() && names.insert(entry.name.as_str()), "Genesis contract names must be nonempty and unique");
    }
    ensure!(named.get(6).map(|entry| entry.name.as_str()) == Some("multisig_policy"), "Genesis contract 6 must be multisig_policy");
    Ok(named.into_iter().map(|entry| entry.deployment).collect())
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

fn genesis_users(
    args: &GenerateGenesisDataArgs,
    relayer: PsyCompactUserDefinition<Hash>,
) -> anyhow::Result<(Vec<PsyCompactUserDefinition<Hash>>, Vec<Option<Hash>>)> {
    let validator_slots = parse_validator_slots(&args.validator_slots)?;
    let zk_fingerprint = zk_fingerprint(args)?;
    let sd_key_fingerprint = parse_qhash(&args.sd_key_fingerprint)?;
    ensure!(args.relayer_registration_id == 2 && args.relayer_user_id == 524_288,
        "public multisig Genesis requires registration 2 and user 524288");
    ensure!(args.coordinator_global_user_tree_height == 12 && args.realm_global_user_tree_height == 20 && args.group_realm_height == 1,
        "public multisig Genesis requires local-devnet Strategy5 tree heights");
    ensure!(validator_slots.len() >= 2, "dense registration 2 requires preceding validator registrations");
    let mut relayer = Some(relayer);
    let special_zk_user_count = validator_slots.len() + 1;
    let mut users = Vec::with_capacity(special_zk_user_count + args.faucet_operator_count);
    let mut private_keys: Vec<Option<Hash>> = Vec::with_capacity(special_zk_user_count + args.faucet_operator_count);

    let mut next_registration: u64 = 0;
    let mut validator_iter = validator_slots.iter().peekable();
    while next_registration < special_zk_user_count as u64 {
        if next_registration == args.relayer_registration_id {
            private_keys.push(None);
            users.push(relayer.take().context("relayer registration already consumed")?);
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
        private_keys.push(Some(private_key));
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
        private_keys.push(Some(private_key));
        users.push(compact_user(sd_key_fingerprint, private_key, args.initial_fee_balance));
    }
    Ok((users, private_keys))
}

fn generate_local_devnet_genesis(args: &GenerateGenesisDataArgs) -> anyhow::Result<()> {
    let repo_root = args.repo_root.canonicalize().with_context(|| {
        format!("repo-root {} does not exist", args.repo_root.display())
    })?;
    let account = decode_relayer_multisig_account(&read_public_input(&repo_root, &args.relayer_multisig_account)?)?;
    let contracts_path = args.genesis_contracts.clone().unwrap_or_else(|| {
        repo_root.join("psy-genesis/genesis_contracts.json")
    });
    let contracts = load_contracts(&contracts_path)?;
    let sd_key_fingerprint = parse_qhash(&args.sd_key_fingerprint)?;
    validate_multisig_policy_artifact(&contracts, &read_public_input(&repo_root, &args.multisig_policy_artifact)?)?;
    let multisig_circuit = MultisigSignatureCircuit::new()?;
    let relayer = initialized_multisig_user(&account, &multisig_circuit, args.initial_fee_balance)?;
    let (users, private_keys) = genesis_users(args, relayer)?;
    let special_zk_user_count = users.len() - args.faucet_operator_count;


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
                let pk = private_keys.get(slot).copied().flatten()
                    .with_context(|| format!("faucet registration {slot} requires a private key"))?;
                let user_id = user_id_for(args, slot as u64);
                let public_key_param = get_public_key_param::<F, PoseidonHash>(pk);
                let pk_info = PZKPublicKeyInfo {
                    fingerprint: sd_key_fingerprint,
                    public_key_param,
                };
                let address = pk_info.to_hash::<PoseidonHasher>();
                Ok(FaucetOperatorJson {
                    user_id: user_id.to_string(),
                    address: format!("{}", address),
                    private_key: format!("{}", pk),
                    fingerprint: format!("{}", sd_key_fingerprint),
                    sign_type: "sd-key".to_string(),
                })
            })
            .collect::<anyhow::Result<_>>()?;

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
        "wrote local-devnet genesis artifacts"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn policy_abi_requires_exact_visible_four_slot_storage() {
        let abi = serde_json::json!({"schema_version":"2.0.0","contract":{"state":[
            {"name":"header","offset":0,"felt_size":4,"type":{"kind":"primitive","name":"Hash"}},
            {"name":"members","offset":4,"felt_size":12,"type":{"kind":"array","item":{"kind":"primitive","name":"Hash"},"length":3,"item_felt_size":4}}
        ]}});
        validate_policy_abi_slots(&abi).unwrap();
        for (index, field, value) in [(0, "offset", 4), (1, "offset", 8), (1, "felt_size", 16)] {
            let mut invalid = abi.clone();
            invalid["contract"]["state"][index][field] = serde_json::json!(value);
            assert!(validate_policy_abi_slots(&invalid).is_err());
        }
        let mut invalid = abi.clone();
        invalid["contract"]["state"][1]["type"]["length"] = serde_json::json!(4);
        assert!(validate_policy_abi_slots(&invalid).is_err());
        let mut missing = abi;
        missing["contract"].as_object_mut().unwrap().remove("state");
        assert!(validate_policy_abi_slots(&missing).is_err());
    }

    use super::*;
    #[test]
    fn contract_loader_preserves_flat_deployments_and_order() {
        let root = std::env::temp_dir().join(format!("psy-genesis-flat-{}", rand::random::<u64>()));
        std::fs::create_dir(&root).unwrap();
        let entries: Vec<_> = (0..7).map(|index| serde_json::json!({
            "name": if index == 6 { "multisig_policy".to_string() } else { format!("contract{index}") },
            "deployer": Hash::from_values(index, 0, 0, 0),
            "code_definition": {"state_tree_height":4,"functions":[]},
            "function_whitelist":[],"code_root":Hash::get_zero_value()
        })).collect();
        let path = root.join("contracts.json");
        let bundle = serde_json::to_vec(&entries).unwrap();
        std::fs::write(&path, &bundle).unwrap();
        std::fs::write(root.join(".genesis_contracts.compiler-artifact.json"), serde_json::to_vec(&stamp_fixture(&bundle)).unwrap()).unwrap();
        let contracts = load_contracts(&path).unwrap();
        for (index, contract) in contracts.iter().enumerate() {
            assert_eq!(contract.deployer, Hash::from_values(index as u64, 0, 0, 0));
        }
        assert_eq!(contracts.len(), entries.len());
        std::fs::remove_dir_all(root).unwrap();
    }

    fn stamp_fixture(bundle: &[u8]) -> serde_json::Value {
        use sha2::{Digest, Sha256};
        serde_json::json!({
            "compilerRevision": "a".repeat(40), "compilerSourcesHash": "b".repeat(64),
            "artifactSha256": hex::encode(Sha256::digest(bundle)), "artifactByteSize": bundle.len(),
            "tokenArtifactSha256": "c".repeat(64), "tokenArtifactByteSize": 0,
            "tokenUpdateArtifactSha256": "d".repeat(64), "tokenUpdateArtifactByteSize": 0,
        })
    }

    #[test]
    fn provenance_binds_raw_bytes_and_rejects_ambiguous_stamp() {
        let bundle = b"[]";
        let stamp = stamp_fixture(bundle);
        let valid = serde_json::to_vec(&stamp).unwrap();
        validate_contracts_stamp(&valid, bundle).unwrap();
        assert!(validate_contracts_stamp(&valid, b"[ ]").is_err());
        for field in ["compilerRevision", "compilerSourcesHash", "artifactSha256", "tokenArtifactSha256", "tokenUpdateArtifactSha256"] {
            let mut invalid = stamp.clone();
            invalid[field] = serde_json::json!("A".repeat(if field == "compilerRevision" { 40 } else { 64 }));
            assert!(validate_contracts_stamp(&serde_json::to_vec(&invalid).unwrap(), bundle).is_err());
        }
        for field in stamp.as_object().unwrap().keys() {
            let mut missing = stamp.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(validate_contracts_stamp(&serde_json::to_vec(&missing).unwrap(), bundle).is_err());
        }
        let mut unknown = stamp.clone();
        unknown["extra"] = serde_json::json!(true);
        assert!(validate_contracts_stamp(&serde_json::to_vec(&unknown).unwrap(), bundle).is_err());
        let text = String::from_utf8(valid).unwrap();
        let duplicate = text.replacen("\"artifactByteSize\":2", "\"artifactByteSize\":2,\"artifactByteSize\":2", 1);
        assert!(validate_contracts_stamp(duplicate.as_bytes(), bundle).is_err());
        assert!(validate_contracts_stamp(&vec![b' '; 65_537], bundle).is_err());
    }
    #[test]
    fn contract_loader_rejects_missing_policy_and_wrapped_records_even_with_matching_stamp() {
        let root = std::env::temp_dir().join(format!("psy-genesis-bundle-reject-{}", rand::random::<u64>()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("contracts.json");
        for bundle in [br#"[{"name":"multisig_policy","deployer":"00","code_definition":{"state_tree_height":4,"functions":[]},"function_whitelist":[],"code_root":"00"}]"#.as_slice(),
            br#"[{"name":"multisig_policy","contract":{"deployment":{}}}]"#.as_slice()] {
            std::fs::write(&path, bundle).unwrap();
            std::fs::write(root.join(".genesis_contracts.compiler-artifact.json"), serde_json::to_vec(&stamp_fixture(bundle)).unwrap()).unwrap();
            assert!(load_contracts(&path).is_err());
        }
        std::fs::remove_file(root.join(".genesis_contracts.compiler-artifact.json")).unwrap();
        assert!(load_contracts(&path).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }


    #[test]
    fn dense_export_keeps_validator_and_faucet_indices_without_relayer_secret() {
        let args = GenerateGenesisDataArgs::try_parse_from(["generate-genesis-data", "--relayer-multisig-account", "account.json", "--multisig-policy-artifact", "policy.json"]).unwrap();
        let account = account_fixture();
        let relayer = PsyCompactUserDefinition {
            public_key_info: PZKPublicKeyInfo { fingerprint: Hash::get_zero_value(), public_key_param: QHashOut(account.public_key_param().unwrap().0) },
            balance: 0, nonce: 0, last_checkpoint_id: 0, event_index: 0, constract_state_tree_records: vec![],
        };
        let (users, keys) = genesis_users(&args, relayer).unwrap();
        assert_eq!(keys.len(), users.len());
        assert_eq!(keys.len(), 15);
        assert!(keys[2].is_none());
        let exported = serde_json::to_value(&keys).unwrap();
        assert!(exported[2].is_null());
        for registration in (0..keys.len()).filter(|index| *index != 2) {
            let key = keys[registration].expect("validator/faucet key must remain at its registration");
            assert_eq!(key, deterministic_private_key(registration as u64));
            assert_eq!(users[registration].public_key_info.public_key_param, get_public_key_param::<F, PoseidonHash>(key));
        }
    }

    #[test]
    #[ignore = "requires approved PSY_GENESIS_CONTRACTS and PSY_MULTISIG_POLICY_ARTIFACT; run explicitly in QA"]
    fn initialized_genesis_roots_authorize_first_ordinary_nonce_one() {
        use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
        use plonky2::{field::types::{Field, PrimeField64}, hash::poseidon::PoseidonPermutation};
        use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
        use parth_core::protocol::core_types::{QNetworkTreeConstants, QNetworkTreeCircuitSpecificConstants};
        use psy_core::network_config::PsyNetworkLocalDevnetConstants as N;
        use psy_node_core::genesis::genesis_db_data_builder::GenesisDatabaseDataBuilder;
        use psy_client_common::data::{base_types::hash256::Hash256, secp256k1::CompressedPublicKey};
        use psy_client_data::qdata::{user::PsyUserLeaf, user_contract_state::{SignContext, UserContractState}, ups_signature::PsyUserProvingSessionSignatureDataCompact};
        use psy_crypto::{hash::traits::qhashable::QFieldHashable, signature::secp256k1::{core::PsyCompressedSecp256K1Signature, wallet::hash_no_pad_compressed_public_key}};
        use psy_vm::{dpn::ops::state_cmd::data::{DPNStateCmd, DPNStateCmdGetSelfUserCurrentContractStateSlotHash}, ups::{state_reader::StateReaderResults, multisig::{MultisigSignatureInput, MultisigSignatureWitness, MultisigSignatures}}};
        let circuit = MultisigSignatureCircuit::new().unwrap();
        let mut keys: Vec<_> = (1u8..=3).map(|byte| {
            let key = SigningKey::from_slice(&[byte; 32]).unwrap();
            let compressed: [u8; 33] = key.verifying_key().to_encoded_point(true).as_bytes().try_into().unwrap();
            let member = hash_no_pad_compressed_public_key::<F, PoseidonPermutation<F>>(CompressedPublicKey(compressed));
            (member, key, compressed)
        }).collect();
        keys.sort_by_key(|(member, _, _)| member.0.elements.map(|limb| limb.to_canonical_u64()));
        let mut account = account_fixture();
        for (member, key) in account.initial_policy.member_hashes[..3].iter_mut().zip(&keys) { *member = key.0; }
        let user = initialized_multisig_user(&account, &circuit, 100).unwrap();
        assert!(initialized_multisig_user(&account, &circuit, 0).is_err());
        assert!(initialized_multisig_user(&account, &circuit, F::ORDER).is_err());
        let contracts_path = std::env::var_os("PSY_GENESIS_CONTRACTS").expect("QA must supply approved Genesis contracts");
        let artifact_path = std::env::var_os("PSY_MULTISIG_POLICY_ARTIFACT").expect("QA must supply approved multisig compiler artifact");
        let contracts = load_contracts(Path::new(&contracts_path)).unwrap();
        let artifact_bytes = std::fs::read(artifact_path).unwrap();
        validate_multisig_policy_artifact(&contracts, &artifact_bytes).unwrap();
        let mut wrong_height = contracts.clone();
        wrong_height[6].code_definition.state_tree_height = 5;
        assert!(validate_multisig_policy_artifact(&wrong_height, &artifact_bytes).is_err());
        let mut wrong_code = contracts.clone();
        wrong_code[6].code_root = Hash::get_zero_value();
        assert!(validate_multisig_policy_artifact(&wrong_code, &artifact_bytes).is_err());
        let stats = PQEDCheckpointLeafStats::<F, Hash>::new_empty();
        let genesis: PsyGenesisBlockSetupData<F, Hash> = serde_json::from_value(serde_json::json!({
            "contracts": contracts,
            "users": [compact_user(Hash::get_zero_value(), deterministic_private_key(0), 100), compact_user(Hash::get_zero_value(), deterministic_private_key(1), 100), user],
            "checkpoint_stats": stats, "deposit_tree_root": Hash::get_zero_value(), "withdrawal_tree_root": Hash::get_zero_value(), "validators": []
        })).unwrap();
        let mut builder = GenesisDatabaseDataBuilder::new(genesis.deposit_tree_root, genesis.withdrawal_tree_root, genesis.checkpoint_stats.clone());
        builder.setup_contracts::<PoseidonHasher, N>(&genesis, true).unwrap();
        use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
        use psy_data::v1::qdata::contract::{PQEDContractLeafV2, CONTRACT_LEAF_SERIALIZED_SIZE};
        let mut contract_tree = SimpleMemoryMerkleRecorderStore::<PoseidonHasher, Hash>::new(N::GLOBAL_CONTRACT_TREE_HEIGHT);
        for row in builder.contract_leaves_ffs.chunks_exact(8 + CONTRACT_LEAF_SERIALIZED_SIZE) {
            let id = u64::from_le_bytes(row[..8].try_into().unwrap());
            let leaf = PQEDContractLeafV2::<F, Hash>::psy_ser_from_slice(&row[8..]).unwrap();
            let expected = &genesis.contracts[id as usize];
            assert_eq!(leaf.deployer, expected.deployer);
            assert_eq!(leaf.code_root, expected.code_root);
            assert_eq!(leaf.state_tree_height.to_canonical_u64(), u64::from(expected.code_definition.state_tree_height));
            contract_tree.set_leaf_no_proof(id, parth_core::crypto::hash::traits::QFieldHashable::qfhash::<PoseidonHasher>(&leaf));
        }
        assert_eq!(contract_tree.get_root(), builder.global_contract_tree_root);
        assert!(contract_tree.get_leaf(6).verify::<PoseidonHasher>());
        builder.setup_users::<PoseidonHasher, N>(&genesis, None, true, true).unwrap();
        let mut global = SimpleMemoryMerkleRecorderStore::<PoseidonHasher, Hash>::new(N::GLOBAL_USER_TREE_HEIGHT);
        let mut relayer_state = None;
        for (registration, compact) in genesis.users.iter().enumerate() {
            let mut ucon = SimpleMemoryMerkleRecorderStore::<PoseidonHasher, Hash>::new(N::GLOBAL_CONTRACT_TREE_HEIGHT);
            let mut state_trees = Vec::new();
            for record in &compact.constract_state_tree_records {
                let mut tree = SimpleMemoryMerkleRecorderStore::<PoseidonHasher, Hash>::new(genesis.get_contract_state_tree_height(record.parent_index).unwrap());
                for slot in &record.children { tree.set_leaf_no_proof(slot.index, slot.value); }
                ucon.set_leaf_no_proof(record.parent_index, tree.get_root());
                state_trees.push((record.parent_index, tree));
            }
            let leaf = PsyUserLeaf {
                public_key: ClientHash(compact.public_key_info.to_hash::<PoseidonHasher>().0),
                user_state_tree_root: ClientHash(ucon.get_root().0), balance: F::from_canonical_u64(compact.balance),
                nonce: F::from_canonical_u64(compact.nonce), last_checkpoint_id: F::from_canonical_u64(compact.last_checkpoint_id),
                event_index: F::from_canonical_u64(compact.event_index),
                user_id: F::from_canonical_u64(UserIdBitsStrategy5::get_user_id_from_user_registration_id(registration as u64, 12, 20, 1)),
            };
            global.set_leaf_no_proof(leaf.user_id.to_canonical_u64(), QHashOut(leaf.qfhash::<PoseidonHash>().0));
            if registration == 2 {
                let fee = &state_trees.iter().find(|(id, _)| *id == 0).unwrap().1;
                assert!(ucon.get_leaf(0).verify::<PoseidonHasher>());
                assert_eq!(ucon.get_leaf(0).value, fee.get_root());
                assert!(fee.get_leaf(0).verify::<PoseidonHasher>());
                assert_eq!(fee.get_leaf(0).value, Hash::from_values(100, 0, 0, 0));
                let policy = &state_trees.iter().find(|(id, _)| *id == 6).unwrap().1;
                let mut proofs = Vec::new();
                for slot in 0..4 {
                    proofs.push(serde_json::from_value(serde_json::to_value(ucon.get_leaf(6)).unwrap()).unwrap());
                    proofs.push(serde_json::from_value(serde_json::to_value(policy.get_leaf(slot)).unwrap()).unwrap());
                }
                relayer_state = Some(StateReaderResults {
                    state: UserContractState { checkpoint_tree_root: ClientHash::ZERO, user_leaf: leaf, start_contract_state_root: ClientHash(policy.get_root().0), contract_id: F::from_canonical_u32(6), checkpoint_id: F::ZERO },
                    user_tree_root: ClientHash::ZERO, checkpoint: None, aux_user_leaves: vec![],
                    state_cmds: (0..4).map(|slot| DPNStateCmd::GetSelfUserCurrentContractStateSlotHash(DPNStateCmdGetSelfUserCurrentContractStateSlotHash { slot_index: F::from_canonical_u64(slot) })).collect(),
                    merkel_proofs: proofs,
                });
            }
        }
        assert_eq!(global.get_root(), builder.global_user_tree_root);
        let inclusion = global.get_leaf(524_288);
        assert!(inclusion.verify::<PoseidonHasher>());
        let mut start_state = relayer_state.unwrap();
        start_state.user_tree_root = ClientHash(builder.global_user_tree_root.0);
        let leaf = start_state.state.user_leaf;
        assert_eq!(inclusion.value, QHashOut(leaf.qfhash::<PoseidonHash>().0));
        assert_eq!(leaf.nonce, F::ZERO);
        assert_ne!(leaf.user_state_tree_root, ClientHash::from_values(N::DEFAULT_USER_STATE_TREE_ROOT_HASH_U64_X4[0], N::DEFAULT_USER_STATE_TREE_ROOT_HASH_U64_X4[1], N::DEFAULT_USER_STATE_TREE_ROOT_HASH_U64_X4[2], N::DEFAULT_USER_STATE_TREE_ROOT_HASH_U64_X4[3]));
        let sign_context = SignContext { checkpoint_tree_root: ClientHash::ZERO, user_leaf: leaf };
        let mut ending = leaf;
        ending.nonce = F::ONE;
        let sig_data = PsyUserProvingSessionSignatureDataCompact {
            start_user_leaf_hash: leaf.qfhash::<PoseidonHash>(), end_user_leaf_hash: ending.qfhash::<PoseidonHash>(),
            checkpoint_leaf_hash: ClientHash::ZERO, tx_stack_hash: ClientHash::from_values(11, 12, 13, 14), tx_count: F::ONE,
        };
        let sighash = sig_data.get_sig_action_for_user::<PoseidonHash>(psy_config::network_constants::PSY_NETWORK_MAGIC, leaf.user_id, F::ONE, sign_context).get_qhash::<PoseidonHash>();
        let message = Hash256::from(sighash);
        let signatures = [0usize, 2].map(|index| {
            let signature: Signature = keys[index].1.sign_prehash(&message.0).unwrap();
            PsyCompressedSecp256K1Signature { public_key: keys[index].2, signature: signature.to_bytes().into(), message }
        });
        let input = MultisigSignatureInput {
            witness: MultisigSignatureWitness { account: account.clone(), start_state: start_state.clone(), end_state: start_state, sig_data, sign_context, start_session_user_leaf: leaf, nonce: F::ONE },
            signatures: MultisigSignatures { member_indices: vec![0, 2], signatures: signatures.to_vec() },
        };
        assert_eq!(input.witness.policies().unwrap(), (account.initial_policy.clone(), account.initial_policy));
        circuit.prove(&input, sighash).unwrap();
        let mut forged = input;
        forged.witness.start_state.merkel_proofs[3].value = ClientHash::ZERO;
        assert!(circuit.prove(&forged, sighash).is_err());
    }

    fn account_fixture() -> MultisigAccount {
        let mut member_hashes = [ClientHash::ZERO; 8];
        for (index, member) in member_hashes[..3].iter_mut().enumerate() {
            *member = ClientHash::from_values(index as u64 + 1, 0, 0, 0);
        }
        MultisigAccount { contract_id: 6, initial_policy: MultisigPolicy {
            version: 1, threshold: 2, member_count: 3, member_hashes,
        } }
    }

    #[test]
    fn public_account_rejects_secret_unknown_duplicate_and_invalid_policy() {
        let account = account_fixture();
        let valid = serde_json::to_vec(&account).unwrap();
        assert_eq!(decode_relayer_multisig_account(&valid).unwrap().public_key_param().unwrap(), account.public_key_param().unwrap());
        for field in ["private_key", "fingerprint", "public_key_param"] {
            let mut value = serde_json::to_value(&account).unwrap();
            value[field] = serde_json::json!("not-an-account-field");
            assert!(decode_relayer_multisig_account(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        let text = String::from_utf8(valid).unwrap();
        let duplicate = text.replacen("\"contract_id\":6", "\"contract_id\":6,\"contract_id\":6", 1);
        assert!(decode_relayer_multisig_account(duplicate.as_bytes()).is_err());
        let duplicate = text.replacen("\"version\":1", "\"version\":1,\"version\":1", 1);
        assert!(decode_relayer_multisig_account(duplicate.as_bytes()).is_err());
        let mut value = serde_json::to_value(&account).unwrap();
        value["initial_policy"]["secret"] = serde_json::json!(true);
        assert!(decode_relayer_multisig_account(&serde_json::to_vec(&value).unwrap()).is_err());
        for (field, invalid) in [("version", 0), ("version", 2), ("threshold", 1), ("member_count", 4)] {
            let mut value = serde_json::to_value(&account).unwrap();
            value["initial_policy"][field] = serde_json::json!(invalid);
            assert!(decode_relayer_multisig_account(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        for index in [0, 1, 7] {
            let mut invalid = account.clone();
            invalid.initial_policy.member_hashes[index] = if index == 0 { ClientHash::ZERO } else { invalid.initial_policy.member_hashes[0] };
            assert!(decode_relayer_multisig_account(&serde_json::to_vec(&invalid).unwrap()).is_err());
        }
        let mut invalid = account;
        invalid.contract_id = 5;
        assert!(decode_relayer_multisig_account(&serde_json::to_vec(&invalid).unwrap()).is_err());
    }

    #[test]
    fn cli_requires_both_public_inputs_and_rejects_secret_flags() {
        assert!(GenerateGenesisDataArgs::try_parse_from(["generate-genesis-data"]).is_err());
        let public_args = ["generate-genesis-data", "--relayer-multisig-account", "account.json", "--multisig-policy-artifact", "policy.json"];
        assert!(GenerateGenesisDataArgs::try_parse_from(public_args).is_ok());
        for flag in ["--private-key", "--bridge-relayer-l2-private-key", "--keystore-path", "--psy-bridge-relayer-keystore-path", "--bridge-relayer-keystore-path", "--wallet-password"] {
            let mut args = public_args.to_vec();
            args.extend([flag, "must-not-be-consumed"]);
            assert!(GenerateGenesisDataArgs::try_parse_from(args).is_err());
        }
        assert!(GenerateGenesisDataArgs::try_parse_from(&public_args[..3]).is_err());
    }

    #[test]
    fn missing_or_directory_public_inputs_fail_closed() {
        assert!(read_public_input(Path::new("."), Path::new("")).is_err());
        assert!(read_public_input(Path::new("."), Path::new(".")).is_err());
        assert!(read_public_input(Path::new("."), Path::new("/definitely-missing-public-multisig-account")).is_err());
        assert!(validate_multisig_policy_artifact(&[], br#"{"state_tree_height":4,"circuit_definitions":[]}"#).is_err());
    }

    #[test]
    fn malformed_public_account_does_not_create_outputs() {
        let root = std::env::temp_dir().join(format!("psy-public-genesis-reject-{}", rand::random::<u64>()));
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("account.json"), b"{}").unwrap();
        std::fs::write(root.join("contracts.json"), b"[]").unwrap();
        let args = GenerateGenesisDataArgs::try_parse_from([
            "generate-genesis-data", "--repo-root", root.to_str().unwrap(),
            "--genesis-contracts", root.join("contracts.json").to_str().unwrap(),
            "--relayer-multisig-account", "account.json", "--multisig-policy-artifact", "absent.json",
        ]).unwrap();
        assert!(generate_local_devnet_genesis(&args).is_err());
        assert!(!root.join("genesis.json").exists());
        assert!(!root.join("private_keys.json").exists());
        assert!(!root.join("psy-dapp").exists());
        std::fs::remove_dir_all(root).unwrap();
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
