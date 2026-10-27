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
use psy_ups_circuit::signature::sd_key_dpn::SDKeyDpnCircuitGadget;
use psy_vm::ups::multisig::{MultisigAccount, MULTISIG_POLICY_CONTRACT_ID};
use psy_core::{
    constants::protocol::{DA_CHALLENGE_WINDOW, TOKEN_BURN_METHOD_ID},
    user_id::{UserIdBitsStrategy5, UserIdGeneratorStrategy},
};
use psy_data::{
    genesis::genesis_block_setup::{PsyGenesisBlockSetupData, PsyGenesisContract},
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

mod accounts;
mod guardians_root;
pub use guardians_root::preflight_fresh_devnet_inputs;

type F = GoldilocksField;
type Hash = QHashOut<F>;

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

    #[arg(long, help = "Generate validator and faucet private keys from OS entropy; required outside localhost")]
    pub random_private_keys: bool,

    /// Existing dense private-key array; reuse identities without generating keys.
    #[arg(long = "private-keys-in", requires_all = ["private_keys_sha256", "accounts_genesis_in", "accounts_genesis_sha256"], conflicts_with = "random_private_keys")]
    pub private_keys_in: Option<PathBuf>,

    #[arg(long = "private-keys-sha256", requires = "private_keys_in")]
    pub private_keys_sha256: Option<String>,

    /// Public Genesis whose account identities and validator roles must be retained.
    #[arg(long = "accounts-genesis-in", requires_all = ["private_keys_in", "accounts_genesis_sha256"])]
    pub accounts_genesis_in: Option<PathBuf>,

    #[arg(long = "accounts-genesis-sha256", requires = "accounts_genesis_in")]
    pub accounts_genesis_sha256: Option<String>,

    /// Optional assertion against the fingerprint derived from the faucet SDKey policy.
    #[arg(long = "sd-key-fingerprint", default_value = "")]
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

    #[arg(long = "sd-key-min-tx-count", default_value_t = 1)]
    pub sd_key_min_tx_count: u64,

    #[arg(long = "sd-key-max-tx-count", default_value_t = 64)]
    pub sd_key_max_tx_count: u64,

    #[arg(long = "sd-key-allowed-contract-id", default_values_t = vec![5u64, 0, 0])]
    pub sd_key_allowed_contract_ids: Vec<u64>,

    /// Faucet, token transfer, and fee burn methods from the current precompile ABI.
    #[arg(long = "sd-key-allowed-method-id", default_values_t = vec![3375543263u32, 2789897329, TOKEN_BURN_METHOD_ID])]
    pub sd_key_allowed_method_ids: Vec<u32>,

    /// Caller for each allowed contract/method pair; Transfer must come from the faucet contract.
    #[arg(long = "sd-key-allowed-caller-contract-id", default_values_t = vec![psy_config::network_constants::DEFAULT_CALLER_CONTRACT_ID_U64, 5, psy_config::network_constants::DEFAULT_CALLER_CONTRACT_ID_U64])]
    pub sd_key_allowed_caller_contract_ids: Vec<u64>,
}

pub async fn run(args: GenerateGenesisDataArgs) -> anyhow::Result<()> {
    generate_local_devnet_genesis(&args)
}

fn ensure_private_key_mode(network: &str, random_private_keys: bool, has_existing_private_keys: bool) -> anyhow::Result<()> {
    ensure!(!(random_private_keys && has_existing_private_keys),
        "existing private keys and random private keys are mutually exclusive");
    ensure!(network == "localhost" || random_private_keys || has_existing_private_keys,
        "network {network} requires --random-private-keys or --private-keys-in; deterministic Genesis private keys are localhost-only");
    Ok(())
}

fn ensure_faucet_output(args: &GenerateGenesisDataArgs) -> anyhow::Result<()> {
    ensure!(!(args.random_private_keys || args.private_keys_in.is_some()) || args.skip_faucet_operators || args.faucet_operators_out.is_some(),
        "secure private-key modes require --skip-faucet-operators or --faucet-operators-out");
    Ok(())
}

fn random_private_key(rng: &mut (impl rand::RngCore + rand::CryptoRng)) -> anyhow::Result<Hash> {
    for _ in 0..128 {
        let mut bytes = [0u8; 32];
        rng.try_fill_bytes(&mut bytes).context("OS entropy unavailable for Genesis private keys")?;
        let limbs: [u64; 4] = std::array::from_fn(|index| {
            u64::from_le_bytes(bytes[index * 8..index * 8 + 8].try_into().unwrap())
        });
        if limbs.iter().all(|limb| *limb < F::ORDER) && limbs != [0; 4] {
            return Ok(Hash::from_values(limbs[0], limbs[1], limbs[2], limbs[3]));
        }
    }
    anyhow::bail!("OS entropy did not produce a nonzero canonical Genesis private key")
}

fn deterministic_private_key(slot: u64) -> QHashOut<F> {
    QHashOut::from_values(
        0x9e37_79b9_7f4a_7c15u64 ^ slot.wrapping_mul(0xbf58_476d_1ce4_e5b9u64),
        0x243f_6a88_85a3_08d3u64 ^ slot.wrapping_mul(0x94d0_49bb_1331_11ebu64),
        0xb7e1_5162_8aed_2a6bu64 ^ slot.wrapping_mul(0xda94_2042_e4dd_58b5u64),
        0xc6ef_372f_e94f_82beu64 ^ slot.wrapping_mul(0x9e37_79b9_7f4a_7c15u64),
    )
}


/// The bridge-relayer multisig user: the read-only network policy members,
/// the Rust multisig fingerprint getter, and the fee balance slot.
fn initialized_multisig_user(
    account: &MultisigAccount,
    initial_fee_balance: u64,
) -> anyhow::Result<PsyCompactUserDefinition<Hash>> {
    ensure!(initial_fee_balance > 0 && initial_fee_balance < F::ORDER, "initial fee balance must be nonzero and canonical");
    let public_key_info = PZKPublicKeyInfo {
        fingerprint: QHashOut(guardian_common::protocol::multisig_fingerprint()
            .map_err(|error| anyhow::anyhow!("multisig fingerprint: {error}"))?.0),
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
    compiled: &CompiledContract,
) -> anyhow::Result<()> {
    require_abi_method_agreement(compiled)?;
    require_policy_contract(compiled)?;
    let contract = contracts.get(MULTISIG_POLICY_CONTRACT_ID as usize).context("Genesis contracts must contain multisig policy contract 1")?;
    require_deployment_roots(compiled, contract)
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
/// One compiled precompile, read once from the sibling compiler checkout.
struct CompiledContract {
    /// Raw compiler JSON bytes; the approval records their SHA-256, never a copy.
    raw: Vec<u8>,
    state_tree_height: u16,
    circuit_definitions: Vec<psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition>,
    abi: serde_json::Value,
}

fn compiler_checkout(repo_root: &Path) -> anyhow::Result<PathBuf> {
    let root = match std::env::var_os("PSY_PROJECTS_DIR") {
        Some(dir) => PathBuf::from(dir).join("psy-compiler"),
        None => repo_root.join("../psy-compiler"),
    };
    root.canonicalize().with_context(|| format!("sibling psy-compiler checkout {} is missing", root.display()))
}

fn read_compiler_contract(compiler_root: &Path, stem: &str) -> anyhow::Result<CompiledContract> {
    let path = compiler_root.join(format!("psy-precompiles/{stem}/target/{stem}.json"));
    let raw = std::fs::read(&path).with_context(|| format!("reading compiler artifact {}", path.display()))?;
    #[derive(serde::Deserialize)]
    struct Artifact {
        state_tree_height: u16,
        circuit_definitions: Vec<psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition>,
        abi: serde_json::Value,
    }
    let artifact: Artifact = serde_json::from_slice(&raw).with_context(|| format!("parsing compiler artifact {}", path.display()))?;
    Ok(CompiledContract { raw, state_tree_height: artifact.state_tree_height, circuit_definitions: artifact.circuit_definitions, abi: artifact.abi })
}

fn abi_methods(abi: &serde_json::Value) -> anyhow::Result<&Vec<serde_json::Value>> {
    abi.pointer("/contract/methods").and_then(serde_json::Value::as_array).context("compiler ABI methods are missing")
}

/// ABI schema 2.0.0, one ABI method per compiled definition, matching method id,
/// input and output felt counts, and view/external mutability.
fn require_abi_method_agreement(compiled: &CompiledContract) -> anyhow::Result<()> {
    ensure!(compiled.abi["schema_version"].as_str() == Some("2.0.0"), "compiler artifact requires ABI 2.0.0");
    ensure!(compiled.abi.pointer("/contract/state_tree_height").and_then(serde_json::Value::as_u64) == Some(u64::from(compiled.state_tree_height)),
        "compiler ABI height differs from the artifact height");
    let methods = abi_methods(&compiled.abi)?;
    ensure!(!compiled.circuit_definitions.is_empty() && methods.len() == compiled.circuit_definitions.len(),
        "compiler ABI and compiled method counts must agree and be nonempty");
    let mut seen = std::collections::BTreeSet::new();
    let mut method_ids = std::collections::BTreeSet::new();
    for definition in &compiled.circuit_definitions {
        ensure!(seen.insert(definition.name.as_str()), "compiled method {} is duplicated", definition.name);
        ensure!(method_ids.insert(definition.method_id), "compiled method id {} is duplicated", definition.method_id);
        let mut matches = methods.iter().filter(|method| method["name"].as_str() == Some(definition.name.as_str()));
        let method = matches.next().with_context(|| format!("compiler ABI omits method {}", definition.name))?;
        ensure!(matches.next().is_none(), "compiler ABI method {} is duplicated", definition.name);
        ensure!(method["method_id"].as_u64() == Some(u64::from(definition.method_id))
            && method["input_felt_count"].as_u64() == Some(definition.circuit_inputs.len() as u64)
            && method["output_felt_count"].as_u64() == Some(definition.circuit_outputs.len() as u64)
            && method["state_mutability"].as_str() == Some(if definition.is_view_function() { "view" } else { "external" }),
            "compiler ABI method {} differs from its compiled definition", definition.name);
    }
    Ok(())
}

/// Deployment code root and function roots must equal the compiled definitions.
fn require_deployment_roots(compiled: &CompiledContract, deployment: &PQBCDeployContract<Hash>) -> anyhow::Result<()> {
    use psy_client_data::config::store_config::{C, D};
    ensure!(u64::from(deployment.code_definition.state_tree_height) == u64::from(compiled.state_tree_height),
        "Genesis deployment height differs from the compiler artifact");
    let (_, expected) = psy_prover::session::gen_contract_deploy_and_circuits_for_functions::<C, D>(
        deployment.deployer, u8::try_from(compiled.state_tree_height).context("compiler state tree height exceeds u8")?, &compiled.circuit_definitions,
    )?;
    let expected: PQBCDeployContract<Hash> = serde_json::from_value(serde_json::to_value(expected)?)?;
    ensure!(deployment == &expected, "Genesis deployment code and function roots differ from the compiler artifact");
    Ok(())
}

fn require_policy_contract(compiled: &CompiledContract) -> anyhow::Result<()> {
    ensure!(compiled.state_tree_height == 4, "multisig policy artifact must declare height 4");
    ensure!(["get_policy", "set_policy"].iter().all(|name| compiled.circuit_definitions.iter().filter(|definition| definition.name == *name).count() == 1)
        && compiled.circuit_definitions.len() == 2, "multisig policy artifact requires exactly get_policy and set_policy");
    validate_policy_abi_slots(&compiled.abi)
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
    ensure!(named.iter().map(|entry| entry.name.as_str()).eq(GENESIS_CONTRACT_NAMES),
        "Genesis requires token, multisig_policy, deposit_tree, withdrawal_tree, usdt_token, faucet in that order");
    Ok(named.into_iter().map(|entry| entry.deployment).collect())
}

const GENESIS_CONTRACT_NAMES: [&str; 6] = [
    "token", "multisig_policy", "deposit_tree", "withdrawal_tree", "usdt_token", "faucet",
];

fn require_full_token_methods(compiled: &CompiledContract) -> anyhow::Result<()> {
    const METHODS: [(&str, u32); 10] = [
        ("withdraw", 3055054724), ("claim_deposit", 1577908089),
        ("mint", 3374273625), ("transfer", 2789897329), ("claim", 3824212239),
        ("batch_transfer_2", 1656917177), ("batch_transfer_5", 1394667333),
        ("burn", 3998182541), ("private_transfer", 1325380837), ("private_claim", 635905178),
    ];
    ensure!(compiled.circuit_definitions.iter().map(|definition|
        (definition.name.as_str(), definition.method_id)).eq(METHODS),
        "Genesis token requires the complete ordered methods including mint and fee burn");
    Ok(())
}

fn genesis_contract_from_compiled(
    contract_id: usize,
    deployment: PQBCDeployContract<Hash>,
    compiled: &CompiledContract,
) -> anyhow::Result<PsyGenesisContract<Hash>> {
    use psy_data::v1::qdata::contract::{
        canonical_layout_manifest_from_compiler_abi_json,
        CANONICAL_TYPE_LAYOUT_STRUCT_TREE_HEIGHT,
    };
    require_abi_method_agreement(compiled)?;
    if contract_id == 0 || contract_id == 4 {
        require_full_token_methods(compiled)?;
    }
    if contract_id == MULTISIG_POLICY_CONTRACT_ID as usize {
        require_policy_contract(compiled)?;
    }
    let state_layout = canonical_layout_manifest_from_compiler_abi_json::<PoseidonHasher, F, Hash>(
        &serde_json::to_string(&compiled.abi)?,
        psy_core::constants::protocol::STATE_LAYOUT_TREE_HEIGHT,
        CANONICAL_TYPE_LAYOUT_STRUCT_TREE_HEIGHT,
    )?;
    let layout = state_layout.validate::<PoseidonHasher, F>()?;
    ensure!(layout.state_layout_field_count > 0, "Genesis precompile must declare its nonempty state layout");
    let abi_state = compiled.abi.pointer("/contract/state").and_then(serde_json::Value::as_array)
        .context("compiler ABI state fields are missing")?;
    let layout_fields = compiled.abi.pointer("/contract/state_layout/fields").and_then(serde_json::Value::as_array)
        .context("compiler ABI canonical layout fields are missing")?;
    ensure!(abi_state.len() == layout.fields.len(), "compiler ABI state and canonical layout field counts differ");
    for ((state, declared), field) in abi_state.iter().zip(layout_fields).zip(&layout.fields) {
        ensure!(state["type"] == declared["type"]
            && state["offset"].as_u64() == field.start_slot.checked_add(field.payload_offset)
            && state["felt_size"].as_u64() == field.slot_count.checked_sub(field.payload_offset),
            "compiler ABI state does not match canonical layout payload");
    }
    require_deployment_roots(compiled, &deployment)?;
    ensure!(state_layout.state_tree_height == deployment.code_definition.state_tree_height,
        "Genesis canonical layout height differs from deployment");
    Ok(PsyGenesisContract { deploy_contract: deployment, state_layout })
}

fn load_genesis_contracts(path: &Path, compiler_root: &Path) -> anyhow::Result<Vec<PsyGenesisContract<Hash>>> {
    let contracts = load_contracts(path)?;
    contracts.into_iter().zip(GENESIS_CONTRACT_NAMES).enumerate()
        .map(|(id, (deployment, name))| {
            let compiled = read_compiler_contract(compiler_root, name)?;
            genesis_contract_from_compiled(id, deployment, &compiled)
                .with_context(|| format!("validating Genesis contract {id} ({name})"))
        }).collect()
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
    sd_key_fingerprint: Hash,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
) -> anyhow::Result<(Vec<PsyCompactUserDefinition<Hash>>, Vec<Option<Hash>>)> {
    let validator_slots = parse_validator_slots(&args.validator_slots)?;
    let zk_fingerprint = zk_fingerprint(args)?;
    ensure!(args.relayer_registration_id == 2 && args.relayer_user_id == 524_288,
        "public multisig Genesis requires registration 2 and user 524288");
    ensure!(args.coordinator_global_user_tree_height == 12 && args.realm_global_user_tree_height == 20 && args.group_realm_height == 1,
        "public multisig Genesis requires local-devnet Strategy5 tree heights");
    ensure!(validator_slots.len() >= 2, "dense registration 2 requires preceding validator registrations");
    let mut relayer = Some(relayer);
    let special_zk_user_count = validator_slots.len() + 1;
    let imported = match (&args.private_keys_in, &args.private_keys_sha256) {
        (Some(path), Some(digest)) => Some(accounts::read_private_keys(
            path, digest, special_zk_user_count + args.faucet_operator_count,
            usize::try_from(args.relayer_registration_id)?,
        )?),
        (None, None) => None,
        _ => anyhow::bail!("existing private keys require both input path and SHA-256"),
    };
    let mut get_private_key = |registration: u64| -> anyhow::Result<Hash> {
        match &imported {
            Some(keys) => keys.get(usize::try_from(registration)?).copied().flatten()
                .context("existing private key registration is missing"),
            None if args.random_private_keys => random_private_key(rng),
            None => Ok(deterministic_private_key(registration)),
        }
    };
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
        let private_key = get_private_key(slot.registration_id)?;
        ensure!(!private_keys.contains(&Some(private_key)), "duplicate Genesis private key");
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
        let private_key = get_private_key(slot as u64)?;
        ensure!(!private_keys.contains(&Some(private_key)), "duplicate Genesis private key");
        private_keys.push(Some(private_key));
        users.push(compact_user(sd_key_fingerprint, private_key, args.initial_fee_balance));
    }
    Ok((users, private_keys))
}

fn faucet_sd_key_fingerprint(args: &GenerateGenesisDataArgs) -> anyhow::Result<Hash> {
    ensure!(args.sd_key_min_tx_count >= 1 && args.sd_key_max_tx_count <= 64,
        "faucet SDKey transaction count must be within 1..=64");
    let (function, config) = psy_vm::ups::sd_key::build_allow_caller_and_method_policy_range(
        &args.sd_key_allowed_caller_contract_ids,
        &args.sd_key_allowed_contract_ids,
        &args.sd_key_allowed_method_ids,
        args.sd_key_min_tx_count,
        args.sd_key_max_tx_count,
    )?;
    for call in &config.transaction_count_policy.as_ref().context("faucet SDKey requires a transaction count policy")?.allowed_calls {
        if call.contract_id == 0 && call.method_id == 2789897329 {
            ensure!(call.caller_contract_id == Some(args.faucet_contract_id),
                "faucet SDKey Transfer must be called by the faucet contract");
        }
    }
    let circuit = SDKeyDpnCircuitGadget::build_from_dpn_function(&function, &config)?;
    let sd_key_fingerprint: QHashOut<F> = serde_json::from_value(serde_json::to_value(circuit.get_fingerprint())?)?;
    if !args.sd_key_fingerprint.trim().is_empty() {
        ensure!(parse_qhash(&args.sd_key_fingerprint)? == sd_key_fingerprint,
            "--sd-key-fingerprint does not match the faucet SDKey policy");
    }
    Ok(sd_key_fingerprint)
}

fn validate_imported_accounts(args: &GenerateGenesisDataArgs, users: &[PsyCompactUserDefinition<Hash>]) -> anyhow::Result<()> {
    if args.private_keys_in.is_none() {
        ensure!(args.accounts_genesis_in.is_none() && args.accounts_genesis_sha256.is_none(),
            "account identity source requires imported private keys");
        return Ok(());
    }
    let path = args.accounts_genesis_in.as_ref().context("import requires the public account Genesis")?;
    let digest = args.accounts_genesis_sha256.as_deref().context("import requires the account Genesis SHA-256")?;
    let (retained, validators) = accounts::read_genesis_accounts(path, digest)?;
    ensure!(retained.len() == users.len(), "imported account role/count mismatch");
    ensure!(retained.iter().zip(users).all(|(before, after)| before.public_key_info == after.public_key_info),
        "imported account fingerprint or public key changed");
    let slots = parse_validator_slots(&args.validator_slots)?;
    let requested = slots.iter().map(|slot| (slot.realm_id, user_id_for(args, slot.registration_id)))
        .collect::<std::collections::BTreeSet<_>>();
    let previous = validators.iter().map(|validator| (u64::from(validator.realm_id), validator.validator_user_id))
        .collect::<std::collections::BTreeSet<_>>();
    ensure!(requested.len() == slots.len() && previous.len() == validators.len() && requested == previous,
        "imported validator registration or Realm roles changed");
    Ok(())
}

fn generate_local_devnet_genesis(args: &GenerateGenesisDataArgs) -> anyhow::Result<()> {
    ensure_private_key_mode(psy_config::CURRENT_NETWORK, args.random_private_keys, args.private_keys_in.is_some())?;
    ensure_faucet_output(args)?;
    let repo_root = args.repo_root.canonicalize().with_context(|| {
        format!("repo-root {} does not exist", args.repo_root.display())
    })?;
    let network = guardians_root::read_canonical_network(&repo_root)?;
    let account = guardian_common::protocol::initial_account(&network).map_err(|error| {
        anyhow::anyhow!("networks.{}.guardian_initial_member_hashes must be the three guardian member commitments: {error}", psy_config::CURRENT_NETWORK)
    })?;
    let contracts_path = args.genesis_contracts.clone().unwrap_or_else(|| {
        repo_root.join("psy-genesis/genesis_contracts.json")
    });
    let contracts = load_genesis_contracts(&contracts_path, &compiler_checkout(&repo_root)?)?;
    let sd_key_fingerprint = faucet_sd_key_fingerprint(args)?;
    let relayer = initialized_multisig_user(&account, args.initial_fee_balance)?;
    let (users, private_keys) = genesis_users(args, relayer, sd_key_fingerprint, &mut rand::rngs::OsRng)?;
    validate_imported_accounts(args, &users)?;
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
    let private_keys_path = args.private_keys_out.clone().unwrap_or_else(|| default_private_keys_path(&repo_root));
    let faucet_operators_path = (!args.skip_faucet_operators).then(|| args.faucet_operators_out.clone().unwrap_or_else(|| {
        default_faucet_operators_path(&repo_root)
    }));
    // Every body is serialized before the first output is opened, so a later
    // failure cannot leave an earlier output truncated.
    let genesis_body = serde_json::to_vec_pretty(&genesis_data)?;
    let private_keys_body = serde_json::to_vec_pretty(&private_keys)?;
    let faucet_body = faucet_operators_path.as_ref().map(|_| faucet_operators_body(args, &private_keys, special_zk_user_count, sd_key_fingerprint)).transpose()?;

    save_genesis_outputs(
        args.random_private_keys || args.private_keys_in.is_some(),
        (&genesis_path, &genesis_body),
        (&private_keys_path, &private_keys_body),
        faucet_operators_path.as_deref().zip(faucet_body.as_deref()),
    )?;
    let faucet_operators_written = faucet_operators_path;

    tracing::info!(
        genesis = %genesis_path.display(),
        private_keys = %private_keys_path.display(),
        faucet_operators = ?faucet_operators_written.as_ref().map(|p| p.display().to_string()),
        "wrote genesis artifacts"
    );
    Ok(())
}

fn faucet_operators_body(args: &GenerateGenesisDataArgs, private_keys: &[Option<Hash>], special_zk_user_count: usize, sd_key_fingerprint: Hash) -> anyhow::Result<Vec<u8>> {
    #[derive(serde::Serialize)]
    struct FaucetOperatorJson { #[serde(rename = "userId")] user_id: String, address: String, #[serde(rename = "privateKey")] private_key: String, fingerprint: String, #[serde(rename = "signType")] sign_type: String }
    #[derive(serde::Serialize)]
    struct FaucetOperatorsJson { #[serde(rename = "faucetContractId")] faucet_contract_id: u64, #[serde(rename = "faucetMethodName")] faucet_method_name: String, #[serde(rename = "faucetMethodId")] faucet_method_id: u64, #[serde(rename = "faucetPerClaimAmount")] faucet_per_claim_amount: String, #[serde(rename = "sdKeyMinTxCount")] sd_key_min_tx_count: u64, #[serde(rename = "sdKeyMaxTxCount")] sd_key_max_tx_count: u64, #[serde(rename = "sdKeyAllowedContractIds")] sd_key_allowed_contract_ids: Vec<u64>, #[serde(rename = "sdKeyAllowedMethodIds")] sd_key_allowed_method_ids: Vec<u32>, #[serde(rename = "sdKeyAllowedCallerContractIds")] sd_key_allowed_caller_contract_ids: Vec<u64>, operators: Vec<FaucetOperatorJson> }
    let operators = (0..args.faucet_operator_count).map(|i| {
        let slot = special_zk_user_count + i;
        let pk = private_keys.get(slot).copied().flatten().with_context(|| format!("faucet registration {slot} requires a private key"))?;
        let public_key_param = get_public_key_param::<F, PoseidonHash>(pk);
        let address = PZKPublicKeyInfo { fingerprint: sd_key_fingerprint, public_key_param }.to_hash::<PoseidonHasher>();
        Ok(FaucetOperatorJson { user_id: user_id_for(args, slot as u64).to_string(), address: format!("{address}"), private_key: format!("{pk}"), fingerprint: format!("{sd_key_fingerprint}"), sign_type: "sd-key".to_string() })
    }).collect::<anyhow::Result<Vec<_>>>()?;
    serde_json::to_vec_pretty(&FaucetOperatorsJson { faucet_contract_id: args.faucet_contract_id, faucet_method_name: args.faucet_method_name.clone(), faucet_method_id: args.faucet_method_id, faucet_per_claim_amount: args.faucet_per_claim_amount.clone(), sd_key_min_tx_count: args.sd_key_min_tx_count, sd_key_max_tx_count: args.sd_key_max_tx_count, sd_key_allowed_contract_ids: args.sd_key_allowed_contract_ids.clone(), sd_key_allowed_method_ids: args.sd_key_allowed_method_ids.clone(), sd_key_allowed_caller_contract_ids: args.sd_key_allowed_caller_contract_ids.clone(), operators }).context("serializing faucet operators")
}

fn save_genesis_outputs(random_private_keys: bool, genesis: (&Path, &[u8]), private_keys: (&Path, &[u8]), faucet: Option<(&Path, &[u8])>) -> anyhow::Result<()> {
    let mut outputs = vec![private_keys];
    outputs.extend(faucet);
    outputs.push(genesis);
    let cwd = std::env::current_dir()?;
    let mut paths = Vec::<PathBuf>::new();
    for (path, _) in &outputs {
        ensure!(!path.components().any(|component| component == std::path::Component::ParentDir),
            "Genesis output paths must not contain parent components");
        let absolute = if path.is_absolute() { path.to_path_buf() } else { cwd.join(path) };
        let normalized: PathBuf = absolute.components().collect();
        ensure!(!paths.iter().any(|other| normalized.starts_with(other) || other.starts_with(&normalized)),
            "Genesis output paths must be distinct and must not contain another output");
        if random_private_keys || *path == genesis.0 {
            preflight_new_destination(path)?;
        } else {
            preflight_owned_regular_destination(path)?;
        }
        paths.push(normalized);
    }
    // Publish Genesis last: a failed secret write must never expose a usable new network snapshot.
    for (path, body) in outputs {
        if random_private_keys || path == genesis.0 {
            write_exclusive(path, body)?;
        } else {
            write_owned_regular(path, body)?;
        }
    }
    Ok(())
}

fn require_missing_at(directory: &std::fs::File, name: &std::ffi::OsStr, path: &Path) -> anyhow::Result<()> {
    use std::os::unix::{ffi::OsStrExt, io::AsRawFd};
    let name = std::ffi::CString::new(name.as_bytes()).context("output name contains NUL")?;
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe { libc::fstatat(directory.as_raw_fd(), name.as_ptr(), metadata.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) };
    ensure!(result != 0, "refusing to overwrite existing Genesis output {}", path.display());
    let error = std::io::Error::last_os_error();
    ensure!(error.raw_os_error() == Some(libc::ENOENT), "checking {} failed: {error}", path.display());
    Ok(())
}

fn preflight_new_destination(path: &Path) -> anyhow::Result<()> {
    let name = path.file_name().context("output path has no file name")?;
    if let Some(directory) = open_usable_parent(output_parent(path))? {
        require_missing_at(&directory, name, path)?;
    }
    Ok(())
}

fn create_output_parent(parent: &Path) -> anyhow::Result<std::fs::File> {
    use std::{path::Component, os::unix::{ffi::OsStrExt, io::AsRawFd}};
    let mut directory = std::fs::File::open(if parent.is_absolute() { "/" } else { "." })?;
    for component in parent.components() {
        let name = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => name,
            _ => anyhow::bail!("output parent must not contain parent components"),
        };
        directory = match open_nofollow_directory_at(&directory, name)? {
            Some(child) => child,
            None => {
                let name_c = std::ffi::CString::new(name.as_bytes()).context("output parent contains NUL")?;
                if unsafe { libc::mkdirat(directory.as_raw_fd(), name_c.as_ptr(), 0o700) } != 0 {
                    let error = std::io::Error::last_os_error();
                    ensure!(error.raw_os_error() == Some(libc::EEXIST), "creating output directory failed: {error}");
                }
                directory.sync_all()?;
                open_nofollow_directory_at(&directory, name)?.context("output directory disappeared")?
            }
        };
    }
    Ok(directory)
}

fn default_private_keys_path(repo_root: &Path) -> PathBuf {
    repo_root.join("private_keys.json")
}

fn default_faucet_operators_path(repo_root: &Path) -> PathBuf {
    repo_root.join("psy-dapp/apps/bridge/src/config/faucetOperators.json")
}

/// Default secret outputs of an unflagged `generate_local_devnet_genesis`.
/// `genesis.json` is omitted: fresh reset deletes it through cleanup.
fn fresh_devnet_secret_outputs(repo_root: &Path) -> [PathBuf; 2] {
    [default_private_keys_path(repo_root), default_faucet_operators_path(repo_root)]
}

fn output_parent(path: &Path) -> &Path {
    path.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or(Path::new("."))
}

/// Metadata-only acceptance of one secret output. A missing file is a first
/// generation. A missing parent is allowed because `write_owned_regular`
/// creates it through directory descriptors; an existing component must
/// already be a real directory opened with `O_NOFOLLOW`. An existing file must
/// be one regular link owned by this user in mode 0600. File bytes are not read.
fn preflight_owned_regular_destination(path: &Path) -> anyhow::Result<()> {
    let name = path.file_name().context("output path has no file name")?;
    let Some(directory) = open_usable_parent(output_parent(path))? else { return Ok(()) };
    require_owned_regular_at(&directory, name, path)
}

fn open_nofollow_directory_at(parent: &std::fs::File, name: &std::ffi::OsStr) -> anyhow::Result<Option<std::fs::File>> {
    use std::os::unix::{ffi::OsStrExt, io::{AsRawFd, FromRawFd}};
    ensure!(!name.is_empty() && !name.as_bytes().contains(&b'/') && name != "." && name != "..", "invalid output parent component");
    let c_name = std::ffi::CString::new(name.as_bytes()).context("output parent contains NUL")?;
    let flags = libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_RDONLY;
    let fd = unsafe { libc::openat(parent.as_raw_fd(), c_name.as_ptr(), flags, 0) };
    if fd >= 0 { return Ok(Some(unsafe { std::fs::File::from_raw_fd(fd) })); }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOENT) { return Ok(None); }
    Err(error).context("output parent is not a usable directory")
}

fn open_usable_parent(parent: &Path) -> anyhow::Result<Option<std::fs::File>> {
    use std::path::Component;
    let mut directory = if parent.is_absolute() {
        std::fs::File::open("/").context("opening /")?
    } else {
        std::fs::File::open(".").context("opening .")?
    };
    let mut missing = false;
    for component in parent.components() {
        let name = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => name,
            _ => anyhow::bail!("output parent {} must not contain parent components", parent.display()),
        };
        if missing { continue; }
        match open_nofollow_directory_at(&directory, name)? {
            Some(child) => directory = child,
            None => missing = true,
        }
    }
    Ok(if missing { None } else { Some(directory) })
}

fn require_owned_regular_at(directory: &std::fs::File, name: &std::ffi::OsStr, path: &Path) -> anyhow::Result<()> {
    use std::os::unix::{ffi::OsStrExt, fs::MetadataExt, io::{AsRawFd, FromRawFd}};
    let destination = std::ffi::CString::new(name.as_bytes()).context("output name contains NUL")?;
    let flags = libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_RDONLY;
    let existing = unsafe { libc::openat(directory.as_raw_fd(), destination.as_ptr(), flags, 0) };
    if existing >= 0 {
        let existing = unsafe { std::fs::File::from_raw_fd(existing) };
        let metadata = existing.metadata().with_context(|| format!("reading {}", path.display()))?;
        ensure!(metadata.is_file() && metadata.nlink() == 1 && metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o777 == 0o600,
            "{} must be a single regular file owned by this user in mode 0600", path.display());
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ELOOP) {
        anyhow::bail!("{} must be a single regular file owned by this user in mode 0600, not a symlink", path.display());
    }
    ensure!(error.raw_os_error() == Some(libc::ENOENT), "opening {} failed: {}", path.display(), error);
    Ok(())
}

fn write_owned_regular(path: &Path, body: &[u8]) -> anyhow::Result<()> {
    write_genesis_file(path, body, true)
}

fn write_exclusive(path: &Path, body: &[u8]) -> anyhow::Result<()> {
    write_genesis_file(path, body, false)
}

fn write_genesis_file(path: &Path, body: &[u8], replace_owned: bool) -> anyhow::Result<()> {
    use std::os::unix::{ffi::OsStrExt, fs::MetadataExt, io::{AsRawFd, FromRawFd}};
    if replace_owned { preflight_owned_regular_destination(path)?; } else { preflight_new_destination(path)?; }
    let parent = output_parent(path);
    let name = path.file_name().context("output path has no file name")?;
    let directory = create_output_parent(parent)?;
    if replace_owned { require_owned_regular_at(&directory, name, path)?; } else { require_missing_at(&directory, name, path)?; }
    let destination = std::ffi::CString::new(name.as_bytes()).context("output name contains NUL")?;
    let temporary = std::ffi::CString::new(format!(".{}.tmp", name.to_string_lossy())).context("temporary name contains NUL")?;
    let created = unsafe { libc::openat(directory.as_raw_fd(), temporary.as_ptr(), libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, 0o600) };
    ensure!(created >= 0, "reserving a temporary for {} failed: {}", path.display(), std::io::Error::last_os_error());
    let mut file = unsafe { std::fs::File::from_raw_fd(created) };
    let publish = (|| {
        let metadata = file.metadata()?;
        ensure!(metadata.is_file() && metadata.nlink() == 1 && metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o777 == 0o600,
            "Genesis temporary output must be an owned single regular file in mode 0600");
        std::io::Write::write_all(&mut file, body)?;
        file.sync_all()?;
        if replace_owned {
            require_owned_regular_at(&directory, name, path)?;
            ensure!(unsafe { libc::renameat(directory.as_raw_fd(), temporary.as_ptr(), directory.as_raw_fd(), destination.as_ptr()) } == 0,
                "replacing {} failed: {}", path.display(), std::io::Error::last_os_error());
        } else {
            ensure!(unsafe { libc::linkat(directory.as_raw_fd(), temporary.as_ptr(), directory.as_raw_fd(), destination.as_ptr(), 0) } == 0,
                "publishing {} failed: {}", path.display(), std::io::Error::last_os_error());
            ensure!(unsafe { libc::unlinkat(directory.as_raw_fd(), temporary.as_ptr(), 0) } == 0,
                "removing Genesis temporary output failed: {}", std::io::Error::last_os_error());
        }
        Ok(directory.sync_all()?)
    })();
    if publish.is_err() { unsafe { libc::unlinkat(directory.as_raw_fd(), temporary.as_ptr(), 0) }; }
    publish.with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt;

    struct KeyBytesRng(std::collections::VecDeque<[u64; 4]>);

    impl rand::CryptoRng for KeyBytesRng {}

    impl rand::RngCore for KeyBytesRng {
        fn next_u32(&mut self) -> u32 { panic!("key generation must use fallible bytes") }
        fn next_u64(&mut self) -> u64 { panic!("key generation must use fallible bytes") }
        fn fill_bytes(&mut self, _: &mut [u8]) { panic!("key generation must propagate entropy failures") }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            assert_eq!(dest.len(), 32);
            let limbs = self.0.pop_front().ok_or_else(|| rand::Error::new(
                std::io::Error::new(std::io::ErrorKind::Other, "fixture entropy exhausted"),
            ))?;
            for (chunk, limb) in dest.chunks_exact_mut(8).zip(limbs) { chunk.copy_from_slice(&limb.to_le_bytes()); }
            Ok(())
        }
    }

    #[test]
    fn public_network_requires_random_private_keys() {
        let default = GenerateGenesisDataArgs::try_parse_from(["generate-genesis-data"]).unwrap();
        assert!(!default.random_private_keys);
        assert!(ensure_private_key_mode("localhost", default.random_private_keys, false).is_ok());
        for network in ["testnet", "mainnet", "unknown", ""] {
            assert!(ensure_private_key_mode(network, default.random_private_keys, false).unwrap_err().to_string().contains("--random-private-keys"));
        }
        let random = GenerateGenesisDataArgs::try_parse_from(["generate-genesis-data", "--random-private-keys"]).unwrap();
        assert!(random.random_private_keys);
        for network in ["localhost", "testnet", "mainnet"] {
            assert!(ensure_private_key_mode(network, random.random_private_keys, false).is_ok());
        }
        if psy_config::CURRENT_NETWORK != "localhost" {
            assert!(generate_local_devnet_genesis(&default).unwrap_err().to_string().contains("--random-private-keys"));
        }
    }

    #[test]
    fn random_faucet_output_requires_explicit_destination_or_skip() {
        let deterministic = GenerateGenesisDataArgs::try_parse_from(["generate-genesis-data"]).unwrap();
        assert!(ensure_faucet_output(&deterministic).is_ok());
        let mut random = GenerateGenesisDataArgs::try_parse_from(["generate-genesis-data", "--random-private-keys"]).unwrap();
        assert!(ensure_faucet_output(&random).unwrap_err().to_string().contains("--faucet-operators-out"));
        random.skip_faucet_operators = true;
        assert!(ensure_faucet_output(&random).is_ok());
        random.skip_faucet_operators = false;
        random.faucet_operators_out = Some(PathBuf::from("explicit-faucet.json"));
        assert!(ensure_faucet_output(&random).is_ok());
    }

    #[test]
    fn imported_private_keys_require_hash_and_exclude_random_generation() {
        assert!(GenerateGenesisDataArgs::try_parse_from([
            "generate-genesis-data", "--private-keys-in", "keys.json",
        ]).is_err());
        assert!(GenerateGenesisDataArgs::try_parse_from([
            "generate-genesis-data", "--private-keys-sha256", &"0".repeat(64),
        ]).is_err());
        assert!(GenerateGenesisDataArgs::try_parse_from([
            "generate-genesis-data", "--private-keys-in", "keys.json",
            "--private-keys-sha256", &"0".repeat(64), "--random-private-keys",
        ]).is_err());
        assert!(ensure_private_key_mode("testnet", false, true).is_ok());
        assert!(ensure_private_key_mode("testnet", true, true).is_err());
    }

    #[test]
    fn imported_genesis_keys_preserve_all_accounts_without_entropy() {
        use std::os::unix::fs::DirBuilderExt;
        use sha2::{Digest, Sha256};
        let root = std::env::current_dir().unwrap().join(format!(".genesis-import-{}", rand::random::<u64>()));
        std::fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let path = root.join("keys.json");
        let mut args = GenerateGenesisDataArgs::try_parse_from([
            "generate-genesis-data", "--faucet-operator-count", "100",
            "--validator-slot", "0,1,0;1,1,1;1,2,3;0,2,4;1,3,5;0,3,6",
        ]).unwrap();
        let keys: Vec<Option<Hash>> = (0..107u64).map(|registration|
            (registration != 2).then(|| Hash::from_values(registration + 1, 2, 3, 4)),
        ).collect();
        let bytes = serde_json::to_vec(&keys).unwrap();
        write_exclusive(&path, &bytes).unwrap();
        args.private_keys_in = Some(path.clone());
        args.private_keys_sha256 = Some(hex::encode(Sha256::digest(&bytes)));
        let fingerprint = Hash::from_values(21, 22, 23, 24);
        let (users, imported) = genesis_users(
            &args, relayer_fixture(), fingerprint, &mut KeyBytesRng(Default::default()),
        ).unwrap();
        assert!(imported == keys);
        assert_eq!(users.len(), 107);
        for (registration, key) in keys.iter().enumerate() {
            if let Some(key) = key {
                assert!(users[registration].public_key_info.public_key_param
                    == get_public_key_param::<F, PoseidonHash>(*key));
            }
        }
        assert!(std::fs::read(&path).unwrap() == bytes);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn imported_accounts_reject_fingerprint_and_role_changes() {
        use std::os::unix::fs::DirBuilderExt;
        use sha2::{Digest, Sha256};
        let root = std::env::current_dir().unwrap().join(format!(".genesis-identity-{}", rand::random::<u64>()));
        std::fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let path = root.join("public-genesis.json");
        let mut args = GenerateGenesisDataArgs::try_parse_from(["generate-genesis-data"]).unwrap();
        let fingerprint = Hash::from_values(21, 22, 23, 24);
        let (users, _) = genesis_users(&args, relayer_fixture(), fingerprint, &mut KeyBytesRng(Default::default())).unwrap();
        let slots = parse_validator_slots(&args.validator_slots).unwrap();
        let validators = slots.iter().map(|slot| serde_json::json!({
            "realm_id": slot.realm_id, "validator_user_id": user_id_for(&args, slot.registration_id),
        })).collect::<Vec<_>>();
        let source = serde_json::json!({"users": users, "validators": validators, "contracts": "ignored"});
        let bytes = serde_json::to_vec(&source).unwrap();
        write_exclusive(&path, &bytes).unwrap();
        args.private_keys_in = Some(root.join("keys-not-opened-by-identity-check.json"));
        args.accounts_genesis_in = Some(path);
        args.accounts_genesis_sha256 = Some(hex::encode(Sha256::digest(&bytes)));
        validate_imported_accounts(&args, &users).unwrap();
        let mut changed = users.clone();
        changed[5].public_key_info.fingerprint = Hash::from_values(1, 2, 3, 4);
        assert!(validate_imported_accounts(&args, &changed).is_err());
        args.validator_slots[0] = "1,1,0".to_string();
        assert!(validate_imported_accounts(&args, &users).is_err());
        assert!(std::fs::read(&args.accounts_genesis_in.unwrap()).unwrap() == bytes);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn random_private_keys_reject_noncanonical_zero_and_failed_entropy() {
        let mut rng = KeyBytesRng([[0; 4], [F::ORDER, 1, 2, 3], [1, 2, 3, F::ORDER - 1]].into());
        assert_eq!(random_private_key(&mut rng).unwrap(), Hash::from_values(1, 2, 3, F::ORDER - 1));
        assert!(random_private_key(&mut rng).unwrap_err().to_string().contains("OS entropy unavailable"));
        let mut zero_rng = KeyBytesRng(vec![[0; 4]; 128].into());
        assert!(random_private_key(&mut zero_rng).unwrap_err().to_string().contains("nonzero canonical"));
    }

    fn relayer_fixture() -> PsyCompactUserDefinition<Hash> {
        let account = account_fixture();
        PsyCompactUserDefinition {
            public_key_info: PZKPublicKeyInfo { fingerprint: Hash::get_zero_value(), public_key_param: QHashOut(account.public_key_param().unwrap().0) },
            balance: 0, nonce: 0, last_checkpoint_id: 0, event_index: 0, constract_state_tree_records: vec![],
        }
    }

    #[test]
    fn faucet_sd_policy_derived_fingerprint_binds_genesis_and_operator_output() {
        let args = GenerateGenesisDataArgs::try_parse_from([
            "generate-genesis-data", "--sd-key-min-tx-count", "2", "--sd-key-max-tx-count", "2",
            "--faucet-operator-count", "1",
        ]).unwrap();
        assert!(args.sd_key_fingerprint.is_empty());
        let fingerprint = faucet_sd_key_fingerprint(&args).unwrap();
        assert_ne!(fingerprint, Hash::get_zero_value());
        let (users, keys) = genesis_users(&args, relayer_fixture(), fingerprint, &mut KeyBytesRng(Default::default())).unwrap();
        assert_eq!(users[5].public_key_info.fingerprint, fingerprint);
        let faucet: serde_json::Value = serde_json::from_slice(&faucet_operators_body(&args, &keys, 5, fingerprint).unwrap()).unwrap();
        let operator = &faucet["operators"][0];
        assert_eq!(operator["fingerprint"], fingerprint.to_string());
        assert_eq!(operator["address"], users[5].public_key_info.to_hash::<PoseidonHasher>().to_string());
        assert_eq!(operator["privateKey"], keys[5].unwrap().to_string());
        assert_eq!(faucet["sdKeyMinTxCount"], 2);
        assert_eq!(faucet["sdKeyMaxTxCount"], 2);
        assert_eq!(faucet["sdKeyAllowedCallerContractIds"], serde_json::json!(args.sd_key_allowed_caller_contract_ids));
        assert!(faucet.get("sdKeyExpectedTxCount").is_none());
        let mut asserted = args;
        asserted.sd_key_fingerprint = fingerprint.to_string();
        assert_eq!(faucet_sd_key_fingerprint(&asserted).unwrap(), fingerprint);
        asserted.sd_key_fingerprint = Hash::get_zero_value().to_string();
        assert!(faucet_sd_key_fingerprint(&asserted).unwrap_err().to_string().contains("does not match"));
    }

    #[test]
    fn faucet_sd_policy_rejects_invalid_ranges_and_direct_transfer() {
        let mut args = GenerateGenesisDataArgs::try_parse_from(["generate-genesis-data"]).unwrap();
        assert_eq!((args.sd_key_min_tx_count, args.sd_key_max_tx_count), (1, 64));
        assert!(args.sd_key_fingerprint.is_empty());
        for (min, max) in [(0, 64), (1, 65), (3, 2)] {
            args.sd_key_min_tx_count = min;
            args.sd_key_max_tx_count = max;
            assert!(faucet_sd_key_fingerprint(&args).is_err());
        }
        args.sd_key_min_tx_count = 1;
        args.sd_key_max_tx_count = 64;
        args.sd_key_allowed_caller_contract_ids[1] = psy_config::network_constants::DEFAULT_CALLER_CONTRACT_ID_U64;
        assert!(faucet_sd_key_fingerprint(&args).unwrap_err().to_string().contains("Transfer must be called by the faucet contract"));
    }

    #[test]
    fn random_genesis_keys_keep_registration_and_faucet_bindings() {
        let args = GenerateGenesisDataArgs::try_parse_from(["generate-genesis-data", "--random-private-keys"]).unwrap();
        let sd_key_fingerprint = Hash::from_values(21, 22, 23, 24);
        let mut rng = KeyBytesRng((1..=14).map(|index| [index, 11, 12, 13]).collect());
        let (users, keys) = genesis_users(&args, relayer_fixture(), sd_key_fingerprint, &mut rng).unwrap();
        assert_eq!(keys.len(), 15);
        assert_eq!(users.len(), keys.len());
        assert!(keys[2].is_none());
        assert!(rng.0.is_empty());
        for (registration, key) in keys.iter().enumerate().filter_map(|(index, key)| key.map(|key| (index, key))) {
            assert_eq!(users[registration].public_key_info.public_key_param, get_public_key_param::<F, PoseidonHash>(key));
            assert_ne!(key, deterministic_private_key(registration as u64));
            assert!(!keys[..registration].contains(&Some(key)));
        }
        let faucet: serde_json::Value = serde_json::from_slice(&faucet_operators_body(
            &args, &keys, 5, sd_key_fingerprint,
        ).unwrap()).unwrap();
        let operators = faucet["operators"].as_array().unwrap();
        assert_eq!(operators.len(), 10);
        for (index, operator) in operators.iter().enumerate() {
            assert_eq!(operator["privateKey"], keys[index + 5].unwrap().to_string());
            assert_eq!(operator["userId"], user_id_for(&args, (index + 5) as u64).to_string());
            assert_eq!(operator["address"], users[index + 5].public_key_info.to_hash::<PoseidonHasher>().to_string());
        }
        let mut duplicate = KeyBytesRng([[1, 2, 3, 4]; 2].into());
        assert!(genesis_users(&args, relayer_fixture(), sd_key_fingerprint, &mut duplicate).unwrap_err().to_string().contains("duplicate Genesis private key"));
        assert!(genesis_users(&args, relayer_fixture(), sd_key_fingerprint, &mut rng).unwrap_err().to_string().contains("OS entropy unavailable"));
    }

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
    use psy_client_common::data::qhashout::QHashOut as ClientHash;
    use psy_ups_circuit::signature::multisig::MultisigSignatureCircuit;
    use psy_vm::ups::multisig::MultisigPolicy;
    #[test]
    fn contract_loader_preserves_flat_deployments_and_order() {
        let root = std::env::temp_dir().join(format!("psy-genesis-flat-{}", rand::random::<u64>()));
        std::fs::create_dir(&root).unwrap();
        let entries: Vec<_> = GENESIS_CONTRACT_NAMES.iter().enumerate().map(|(index, name)| serde_json::json!({
            "name": name,
            "deployer": index,
            "code_definition": {"state_tree_height":4,"functions":[]},
            "function_whitelist":[],"code_root":Hash::get_zero_value()
        })).collect();
        let path = root.join("contracts.json");
        let bundle = serde_json::to_vec(&entries).unwrap();
        std::fs::write(&path, &bundle).unwrap();
        std::fs::write(root.join(".genesis_contracts.compiler-artifact.json"), serde_json::to_vec(&stamp_fixture(&bundle)).unwrap()).unwrap();
        let contracts = load_contracts(&path).unwrap();
        for (index, contract) in contracts.iter().enumerate() {
            assert_eq!(contract.deployer, index as u64);
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
        let args = GenerateGenesisDataArgs::try_parse_from(["generate-genesis-data"]).unwrap();
        let (users, keys) = genesis_users(&args, relayer_fixture(), Hash::from_values(21, 22, 23, 24), &mut KeyBytesRng(Default::default())).unwrap();
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
    #[ignore = "requires approved PSY_GENESIS_CONTRACTS and the sibling compiler checkout; run explicitly in QA"]
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
        let keys: Vec<_> = (1u8..=3).map(|byte| {
            let key = SigningKey::from_slice(&[byte; 32]).unwrap();
            let compressed: [u8; 33] = key.verifying_key().to_encoded_point(true).as_bytes().try_into().unwrap();
            let member = hash_no_pad_compressed_public_key::<F, PoseidonPermutation<F>>(CompressedPublicKey(compressed));
            (member, key, compressed)
        }).collect();
        let mut account = account_fixture();
        for (member, key) in account.initial_policy.member_hashes[..3].iter_mut().zip(&keys) { *member = key.0; }
        let user = initialized_multisig_user(&account, 100).unwrap();
        assert!(initialized_multisig_user(&account, 0).is_err());
        assert!(initialized_multisig_user(&account, F::ORDER).is_err());
        let contracts_path = std::env::var_os("PSY_GENESIS_CONTRACTS").expect("QA must supply approved Genesis contracts");
        let contracts = load_contracts(Path::new(&contracts_path)).unwrap();
        let compiled = read_compiler_contract(&compiler_checkout(Path::new("..")).expect("sibling psy-compiler checkout"), "multisig_policy").unwrap();
        validate_multisig_policy_artifact(&contracts, &compiled).unwrap();
        let mut wrong_height = contracts.clone();
        wrong_height[MULTISIG_POLICY_CONTRACT_ID as usize].code_definition.state_tree_height = 5;
        assert!(validate_multisig_policy_artifact(&wrong_height, &compiled).is_err());
        let mut wrong_code = contracts.clone();
        wrong_code[MULTISIG_POLICY_CONTRACT_ID as usize].code_root = Hash::get_zero_value();
        assert!(validate_multisig_policy_artifact(&wrong_code, &compiled).is_err());
        let contracts = load_genesis_contracts(
            Path::new(&contracts_path), &compiler_checkout(Path::new("..")).unwrap(),
        ).unwrap();
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
            assert_eq!(leaf.deployer, F::from_u64_value(expected.deployer));
            assert_eq!(leaf.code_root, expected.code_root);
            assert_eq!(leaf.state_tree_height.to_canonical_u64(), u64::from(expected.code_definition.state_tree_height));
            contract_tree.set_leaf_no_proof(id, parth_core::crypto::hash::traits::QFieldHashable::qfhash::<PoseidonHasher>(&leaf));
        }
        assert_eq!(contract_tree.get_root(), builder.global_contract_tree_root);
        assert!(contract_tree.get_leaf(u64::from(MULTISIG_POLICY_CONTRACT_ID)).verify::<PoseidonHasher>());
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
                let policy = &state_trees.iter().find(|(id, _)| *id == u64::from(MULTISIG_POLICY_CONTRACT_ID)).unwrap().1;
                let mut proofs = Vec::new();
                for slot in 0..4 {
                    proofs.push(serde_json::from_value(serde_json::to_value(ucon.get_leaf(u64::from(MULTISIG_POLICY_CONTRACT_ID))).unwrap()).unwrap());
                    proofs.push(serde_json::from_value(serde_json::to_value(policy.get_leaf(slot)).unwrap()).unwrap());
                }
                relayer_state = Some(StateReaderResults {
                    state: UserContractState { checkpoint_tree_root: ClientHash::ZERO, user_leaf: leaf, start_contract_state_root: ClientHash(policy.get_root().0), contract_id: F::from_canonical_u32(MULTISIG_POLICY_CONTRACT_ID), checkpoint_id: F::ZERO },
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
        MultisigAccount { contract_id: MULTISIG_POLICY_CONTRACT_ID, initial_policy: MultisigPolicy {
            version: 1, threshold: 2, member_count: 3, member_hashes,
        } }
    }

    #[test]
    fn cli_defaults_and_rejects_secret_flags() {
        assert!(GenerateGenesisDataArgs::try_parse_from(["generate-genesis-data"]).is_ok());
        let public_args = ["generate-genesis-data"];
        for flag in ["--private-key", "--bridge-relayer-l2-private-key", "--keystore-path", "--psy-bridge-relayer-keystore-path", "--bridge-relayer-keystore-path", "--wallet-password", "--multisig-policy-artifact"] {
            let mut args = public_args.to_vec();
            args.extend([flag, "must-not-be-consumed"]);
            assert!(GenerateGenesisDataArgs::try_parse_from(args).is_err());
        }
    }

    #[test]
    fn missing_compiler_checkout_fails_closed() {
        assert!(compiler_checkout(Path::new("/definitely-missing-compiler-parent")).is_err());
    }

    fn canonical_network_fixture() -> serde_json::Value {
        let mut members = [ClientHash::<F>::ZERO; 3];
        for (index, member) in members.iter_mut().enumerate() { *member = ClientHash::from_values(index as u64 + 1, 0, 0, 0); }
        serde_json::json!({
            "magic": "0x1337CF514544CF69", "users_per_realm": 1, "global_user_tree_height": 1,
            "realm_user_tree_height": 1, "group_realm_height": 1,
            "guardian_initial_member_hashes": members,
            "realm_configs": [], "p2p": {"checkpoints_per_epoch": 1}, "coordinator_configs": [],
            "prove_proxy_url": [], "faucet_rpc_url": [], "nostr_relay_url": "",
            "native_currency": "", "native_currency_decimal": 0, "native_currency_name": "",
            "fees": {"register_user_fee": 0, "deploy_contract_fee": 0, "guta_fee": 0, "da_fee": 0}
        })
    }

    fn write_canonical_network(root: &std::path::Path, network: &serde_json::Value) {
        let mut config = serde_json::json!({"defaultNetwork": psy_config::CURRENT_NETWORK, "networks": {}});
        config["networks"][psy_config::CURRENT_NETWORK] = network.clone();
        std::fs::write(root.join("psy-genesis/config.json"), serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    }

    #[test]
    fn missing_canonical_policy_fails_before_outputs() {
        let root = std::env::temp_dir().join(format!("psy-public-genesis-reject-{}", rand::random::<u64>()));
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir_all(root.join("psy-genesis")).unwrap();
        let mut network = canonical_network_fixture();
        network.as_object_mut().unwrap().remove("guardian_initial_member_hashes");
        write_canonical_network(&root, &network);
        let args = GenerateGenesisDataArgs::try_parse_from([
            "generate-genesis-data", "--random-private-keys", "--skip-faucet-operators", "--repo-root", root.to_str().unwrap(),
        ]).unwrap();
        let error = format!("{:?}", generate_local_devnet_genesis(&args).unwrap_err());
        assert!(error.contains(&format!("networks.{}.guardian_initial_member_hashes", psy_config::CURRENT_NETWORK)));
        assert!(!root.join("genesis.json").exists());
        assert!(!root.join("private_keys.json").exists());
        assert!(!root.join("psy-dapp").exists());
        std::fs::remove_dir_all(root).unwrap();
    }


    #[test]
    fn duplicate_selected_network_fails_before_outputs() {
        let root = std::env::temp_dir().join(format!("psy-duplicate-network-{}", rand::random::<u64>()));
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir_all(root.join("psy-genesis")).unwrap();
        std::fs::write(root.join("psy-genesis/config.json"),
            r#"{"networks":{"localhost":{},"localhost":{}}}"#).unwrap();
        let args = GenerateGenesisDataArgs::try_parse_from([
            "generate-genesis-data", "--random-private-keys", "--skip-faucet-operators", "--repo-root", root.to_str().unwrap(),
        ]).unwrap();
        let error = format!("{:?}", generate_local_devnet_genesis(&args).unwrap_err());
        assert!(error.contains("not duplicate-free JSON"));
        assert!(!root.join("genesis.json").exists());
        assert!(!root.join("private_keys.json").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn duplicate_guardian_member_keys_fail_before_outputs() {
        let root = std::env::temp_dir().join(format!("psy-duplicate-members-{}", rand::random::<u64>()));
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir_all(root.join("psy-genesis")).unwrap();
        let network = canonical_network_fixture().to_string();
        let key = "\"guardian_initial_member_hashes\":";
        let at = network.find(key).expect("canonical fixture keeps guardian member hashes");
        let duped = format!("{}{key}0,{}", &network[..at], &network[at..]);
        let network_name = psy_config::CURRENT_NETWORK;
        let config = format!(r#"{{"defaultNetwork":"{network_name}","networks":{{"{network_name}":{duped}}}}}"#);
        std::fs::write(root.join("psy-genesis/config.json"), config).unwrap();
        let args = GenerateGenesisDataArgs::try_parse_from([
            "generate-genesis-data", "--random-private-keys", "--skip-faucet-operators", "--repo-root", root.to_str().unwrap(),
        ]).unwrap();
        assert!(generate_local_devnet_genesis(&args).is_err());
        assert!(!root.join("genesis.json").exists());
        assert!(!root.join("private_keys.json").exists());
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

    #[test]
    fn compiler_checkout_requires_the_sibling_repository() {
        assert!(compiler_checkout(Path::new("/definitely-missing-compiler-parent")).is_err());
        let parent = std::env::temp_dir().join(format!("psy-compiler-parent-{}", rand::random::<u64>()));
        std::fs::create_dir(&parent).unwrap();
        assert!(read_compiler_contract(&parent, "token").is_err());
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn descriptor_rejects_a_stamp_disagreement_and_a_changed_hash() {
        let bundle = b"[]";
        let mut stamp = stamp_fixture(bundle);
        stamp["artifactSha256"] = serde_json::json!("e".repeat(64));
        assert!(validate_contracts_stamp(&serde_json::to_vec(&stamp).unwrap(), bundle).is_err());
        stamp["artifactByteSize"] = serde_json::json!(bundle.len() + 1);
        stamp["artifactSha256"] = stamp_fixture(bundle)["artifactSha256"].clone();
        assert!(validate_contracts_stamp(&serde_json::to_vec(&stamp).unwrap(), bundle).is_err());
    }

    #[test]
    fn localhost_regeneration_replaces_owned_secrets_but_not_genesis() {
        let root = std::env::temp_dir().join(format!("psy-genesis-local-reset-{}", rand::random::<u64>()));
        std::fs::create_dir(&root).unwrap();
        let genesis = root.join("genesis.json");
        let keys = root.join("private_keys.json");
        let faucet = root.join("faucetOperators.json");
        write_owned_regular(&keys, b"old keys").unwrap();
        write_owned_regular(&faucet, b"old faucet").unwrap();
        let old_keys = std::fs::File::open(&keys).unwrap();
        let old_faucet = std::fs::File::open(&faucet).unwrap();
        save_genesis_outputs(false, (&genesis, b"genesis"), (&keys, b"new keys"), Some((&faucet, b"new faucet"))).unwrap();
        assert_ne!(old_keys.metadata().unwrap().ino(), std::fs::metadata(&keys).unwrap().ino());
        assert_ne!(old_faucet.metadata().unwrap().ino(), std::fs::metadata(&faucet).unwrap().ino());
        assert!(save_genesis_outputs(false, (&genesis, b"other genesis"), (&keys, b"other keys"), Some((&faucet, b"other faucet"))).is_err());
        for (path, body) in [(&genesis, b"genesis".as_slice()), (&keys, b"new keys".as_slice()), (&faucet, b"new faucet".as_slice())] {
            assert_eq!(std::fs::read(path).unwrap(), body);
            let metadata = std::fs::metadata(path).unwrap();
            assert_eq!(metadata.mode() & 0o777, 0o600);
            assert_eq!(metadata.nlink(), 1);
            assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        }
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 3);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn parent_components_fail_before_any_genesis_output_write() {
        let root = std::env::temp_dir().join(format!("psy-genesis-parent-preflight-{}", rand::random::<u64>()));
        std::fs::create_dir(&root).unwrap();
        let genesis = root.join("genesis.json");
        let keys = root.join("private_keys.json");
        let faucet = root.join("missing/../faucet.json");
        for random_private_keys in [false, true] {
            assert!(save_genesis_outputs(random_private_keys, (&genesis, b"genesis"), (&keys, b"keys"), Some((&faucet, b"faucet"))).is_err());
            assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn genesis_outputs_reject_existing_files_aliases_and_symlink_parents() {
        use std::os::unix::fs::symlink;
        let root = std::env::temp_dir().join(format!("psy-genesis-exclusive-{}", rand::random::<u64>()));
        std::fs::create_dir(&root).unwrap();
        let genesis = root.join("genesis.json");
        let keys = root.join("private_keys.json");
        let faucet = root.join("faucetOperators.json");
        for existing in [&genesis, &keys, &faucet] {
            write_owned_regular(existing, b"retained").unwrap();
            assert!(save_genesis_outputs(true, (&genesis, b"new genesis"), (&keys, b"new keys"), Some((&faucet, b"new faucet"))).is_err());
            assert_eq!(std::fs::read(existing).unwrap(), b"retained");
            for absent in [&genesis, &keys, &faucet].into_iter().filter(|path| path != &existing) {
                assert!(!absent.exists());
            }
            std::fs::remove_file(existing).unwrap();
        }
        assert!(save_genesis_outputs(true, (&genesis, b"genesis"), (&genesis, b"keys"), None).is_err());
        assert!(save_genesis_outputs(true, (&genesis, b"genesis"), (&root.join("./genesis.json"), b"keys"), None).is_err());
        assert!(save_genesis_outputs(true, (&genesis, b"genesis"), (&genesis.join("keys"), b"keys"), None).is_err());
        assert!(!genesis.exists());
        let real_parent = root.join("real");
        std::fs::create_dir(&real_parent).unwrap();
        let linked_parent = root.join("linked");
        symlink(&real_parent, &linked_parent).unwrap();
        assert!(save_genesis_outputs(true, (&genesis, b"genesis"), (&keys, b"keys"), Some((&linked_parent.join("faucet.json"), b"faucet"))).is_err());
        assert!(!keys.exists());
        assert!(!genesis.exists());
        assert_eq!(std::fs::read_dir(&real_parent).unwrap().count(), 0);
        let dangling = root.join("dangling.json");
        symlink(root.join("absent.json"), &dangling).unwrap();
        assert!(write_owned_regular(&dangling, b"must not follow").is_err());
        assert!(!root.join("absent.json").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn genesis_is_published_only_after_all_secret_outputs_succeed() {
        let root = std::env::temp_dir().join(format!("psy-genesis-last-{}", rand::random::<u64>()));
        std::fs::create_dir(&root).unwrap();
        let genesis = root.join("genesis.json");
        let keys = root.join("private_keys.json");
        let faucet = root.join("faucetOperators.json");
        let blocked = root.join(".faucetOperators.json.tmp");
        std::fs::write(&blocked, b"another writer").unwrap();
        assert!(save_genesis_outputs(true, (&genesis, b"genesis"), (&keys, b"keys"), Some((&faucet, b"faucet"))).is_err());
        assert_eq!(std::fs::read(&blocked).unwrap(), b"another writer");
        assert_eq!(std::fs::read(&keys).unwrap(), b"keys");
        assert!(!faucet.exists());
        assert!(!genesis.exists());
        assert!(!root.join(".private_keys.json.tmp").exists());
        std::fs::remove_file(&blocked).unwrap();
        assert!(save_genesis_outputs(true, (&genesis, b"genesis"), (&keys, b"replacement"), Some((&faucet, b"faucet"))).is_err());
        assert_eq!(std::fs::read(&keys).unwrap(), b"keys");
        assert!(!genesis.exists());
        let fresh = root.join("fresh");
        let new_genesis = fresh.join("genesis.json");
        let new_keys = fresh.join("private_keys.json");
        let new_faucet = fresh.join("faucetOperators.json");
        save_genesis_outputs(true, (&new_genesis, b"genesis"), (&new_keys, b"keys"), Some((&new_faucet, b"faucet"))).unwrap();
        for (path, body) in [(&new_genesis, b"genesis".as_slice()), (&new_keys, b"keys".as_slice()), (&new_faucet, b"faucet".as_slice())] {
            assert_eq!(std::fs::read(path).unwrap(), body);
            let metadata = std::fs::metadata(path).unwrap();
            assert_eq!(metadata.mode() & 0o777, 0o600);
            assert_eq!(metadata.nlink(), 1);
        }
        assert_eq!(std::fs::read_dir(&fresh).unwrap().count(), 3);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn first_publish_creates_missing_outputs_and_failed_replace_preserves() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("psy-owned-regular-{}", rand::random::<u64>()));
        std::fs::create_dir(&root).unwrap();
        let private_keys = root.join("private_keys.json");
        write_owned_regular(&private_keys, b"first body").expect("first fresh publish needs no pre-created destination");
        let metadata = std::fs::metadata(&private_keys).unwrap();
        assert!(metadata.is_file() && metadata.nlink() == 1 && metadata.mode() & 0o777 == 0o600);
        assert_eq!(std::fs::read(&private_keys).unwrap(), b"first body");
        write_owned_regular(&private_keys, b"second body").unwrap();
        assert_eq!(std::fs::read(&private_keys).unwrap(), b"second body");
        let faucet = root.join("faucetOperators.json");
        std::fs::write(&faucet, b"retained").unwrap();
        std::fs::set_permissions(&faucet, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(write_owned_regular(&faucet, b"replacement").is_err());
        assert_eq!(std::fs::read(&faucet).unwrap(), b"retained");
        assert!(!root.join(".faucetOperators.json.tmp").exists());
        let owned = root.join("owned.json");
        write_owned_regular(&owned, b"public").unwrap();
        let link = root.join("linked.json");
        std::os::unix::fs::symlink(&owned, &link).unwrap();
        assert!(write_owned_regular(&link, b"replacement").is_err());
        assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read(&owned).unwrap(), b"public");
        let hard_source = root.join("hard-source.json");
        let hard_dest = root.join("hard-dest.json");
        std::fs::write(&hard_source, b"public").unwrap();
        std::fs::set_permissions(&hard_source, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&hard_source, &hard_dest).unwrap();
        assert!(write_owned_regular(&hard_dest, b"replacement").is_err());
        assert_eq!(std::fs::metadata(&hard_dest).unwrap().nlink(), 2);
        assert_eq!(std::fs::read(&hard_dest).unwrap(), b"public");
        let nested = root.join("psy-dapp/apps/bridge/src/config/faucetOperators.json");
        write_owned_regular(&nested, b"created").expect("missing faucet parent is created at publication");
        assert_eq!(std::fs::metadata(&nested).unwrap().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read(&nested).unwrap(), b"created");
        std::fs::remove_dir_all(root).unwrap();
    }
}
