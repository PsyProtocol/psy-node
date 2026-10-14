//! `--guardians-root` branch of `generate-genesis-data` (frozen design §4).
//!
//! `--guardians-root` verifies the supplied public account, compiler artifact and
//! approved contract inputs against the EXISTING `genesis.json`, recomputes the
//! offline checkpoint-0 identity through the populated node-side builder, and
//! writes exactly one public config plus the version-1 authorization
//! archive/index. It never calls `generate_local_devnet_genesis`, never writes
//! `genesis.json`, `private_keys.json`, or `faucetOperators.json`, and never
//! reads or copies keystore contents — only their file metadata.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::OpenOptions,
    io::Write,
    net::SocketAddr,
    os::unix::{
        ffi::OsStrExt,
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
        io::{AsRawFd, FromRawFd},
    },
    path::{Component, Path, PathBuf},
};

use anyhow::{anyhow, ensure, Context};
use clap::Parser as _;
use parth_core::{
    crypto::hash::traits::QFieldHashable,
    felt::FromPrimitiveValuesFelt,
    pgoldilocks::PoseidonHasher,
    protocol::core_types::QNetworkTreeConstants,
};
use psy_core::user_id::UserIdGeneratorStrategy;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::poseidon::PoseidonHash,
    plonk::config::Hasher,
};
use psy_client_common::data::{base_types::hash256::Hash256, qhashout::QHashOut as ClientHash};
use psy_config::{NetworkConfigGoldilocks, PsyConfigGoldilocks, GUTA_FEE, DA_FEE};
use psy_core::network_config::PsyNetworkLocalDevnetConstants as N;
use psy_data::genesis::genesis_block_setup::PsyGenesisBlockSetupData;
use psy_node_core::genesis::genesis_db_data_builder::GenesisDatabaseDataBuilder;
use plonky2::field::types::PrimeField64;
use guardian_common::{
    endcap::approved_endcap_max_proof_bytes,
    protocol::{
        self, ApprovedContract, ChainAuthorization, ChainEndpoint, GuardianAuthorization,
        GuardianAuthorizationIndex, GuardianAuthorizationVersion, GuardianClientConfig,
        GuardianConfig, GuardianSignerConfig, Hex, JsonText, BRIDGE_USER_ID,
    },
};
use psy_ups_circuit::signature::multisig::MultisigSignatureCircuit;
use psy_vm::ups::multisig::MultisigAccount;

use super::{
    decode_relayer_multisig_account, read_public_input, validate_multisig_policy_artifact,
    GUARDIANS_ROOT_MAX_FEE_DEFAULT, GenerateGenesisDataArgs, Hash, PsyCompactUserDefinition,
};

const GUARDIAN_FIRST_LISTEN_PORT: u16 = 15441;
const CLIENT_HISTORY_LISTEN_PORT: u16 = 15450;
const GUARDIANS_ROOT_CONFIG_FILE: &str = "config.json";
const GUARDIANS_ROOT_AUTHORIZATION_DIR: &str = "authorization";
const GUARDIANS_ROOT_ARCHIVE_JOURNAL_DIR: &str = "archive/relayer-journal";

type F = GoldilocksField;

/// Runs the --guardians-root branch; the publish branch is untouched elsewhere.
pub fn run_guardians_root(args: &GenerateGenesisDataArgs) -> anyhow::Result<()> {
    let guardians_root = args
        .guardians_root
        .as_ref()
        .context("--guardians-root is required for the --guardians-root branch")?;
    require_ceremony_inputs(args)?;
    let repo_root = args.repo_root.canonicalize().with_context(|| {
        format!("repo-root {} does not exist", args.repo_root.display())
    })?;

    // 1. The existing genesis is only read; it is never rewritten or re-derived.
    let genesis = load_existing_genesis(args, &repo_root)?;

    // 2. Public inputs and their identity against the existing genesis.
    let account = decode_relayer_multisig_account(&read_public_input(
        &repo_root,
        &args.relayer_multisig_account,
    )?)?;
    ensure!(account.contract_id == 6, "public multisig account must name contract 6");
    validate_multisig_policy_artifact(
        &genesis.contracts,
        &read_public_input(&repo_root, &args.multisig_policy_artifact)?,
    )?;
    let circuit = MultisigSignatureCircuit::new()?;
    let user = locate_genesis_multisig_user(args, &genesis.users)?;
    verify_genesis_user_identity(&account, &circuit, user)?;

    // 3. Offline checkpoint 0 through the node-side populated builder.
    validate_compiled_dimensions(args)?;
    let genesis_hash = checkpoint0_genesis_hash(&genesis)?;

    // 4. Authorization inputs, fee cap, and the complete shared validator.
    let chains: Vec<ChainAuthorization> = decode_canonical(
        &read_public_input(&repo_root, args.chains.as_ref().context("--chains")?)?,
        "--chains",
    )?;
    let l1_endpoints: Vec<ChainEndpoint> = decode_canonical(
        &read_public_input(&repo_root, args.l1_endpoints.as_ref().context("--l1-endpoints")?)?,
        "--l1-endpoints",
    )?;
    let approved_contracts: Vec<ApprovedContract> = decode_canonical(
        &read_public_input(
            &repo_root,
            args.approved_contracts.as_ref().context("--approved-contracts")?,
        )?,
        "--approved-contracts",
    )?;
    require_exact_l1_endpoint_coverage(&chains, &l1_endpoints)?;
    for endpoint in &l1_endpoints {
        validate_l1_endpoint(&endpoint.rpc_url)
            .with_context(|| format!("L1 endpoint for chain {}", endpoint.chain_index))?;
    }
    let max_fee = args.max_fee.unwrap_or(GUARDIANS_ROOT_MAX_FEE_DEFAULT);
    validate_fee_cap(max_fee)?;
    let proof_bound = approved_endcap_max_proof_bytes()?;
    let authorization = build_authorization(
        &account,
        &circuit,
        &genesis_hash,
        max_fee,
        chains,
        approved_contracts,
        proof_bound,
    )?;
    authorization
        .validate(GUTA_FEE, DA_FEE, proof_bound)
        .map_err(|error| anyhow!("guardian authorization validation: {error}"))?;

    // 5. One public config: typed network projection plus fixed listeners.
    let network = load_network_projection(&repo_root)?;
    let client = GuardianClientConfig {
        endpoints: std::array::from_fn(|index| guardian_endpoint(index as u8 + 1)),
        archive_path: PathBuf::from(GUARDIANS_ROOT_ARCHIVE_JOURNAL_DIR),
        listen_address: SocketAddr::from(([127, 0, 0, 1], CLIENT_HISTORY_LISTEN_PORT)),
        l1_endpoints,
    };
    for endpoint in &client.endpoints {
        validate_http_origin(endpoint).context("generated guardian client endpoint")?;
    }
    let config = GuardianConfig {
        network,
        guardians: guardian_signers()?,
        client,
    };
    config
        .validate()
        .map_err(|error| anyhow!("generated guardian config validation: {error}"))?;

    // 6. Secret metadata walk only; keystore contents are never opened.
    verify_secret_metadata()?;

    // 7. Exclusive outputs, modes, and parent-directory syncs.
    write_outputs(guardians_root, &config, &authorization)?;
    Ok(())
}

/// Fails closed when ceremony-only flags leak into the unchanged publish branch.
pub fn reject_publish_branch_flags(args: &GenerateGenesisDataArgs) -> anyhow::Result<()> {
    for (present, flag) in [
        (args.chains.is_some(), "--chains"),
        (args.l1_endpoints.is_some(), "--l1-endpoints"),
        (args.approved_contracts.is_some(), "--approved-contracts"),
        (args.max_fee.is_some(), "--max-fee"),
    ] {
        ensure!(!present, "{flag} is only valid together with --guardians-root");
    }
    Ok(())
}

fn require_ceremony_inputs(args: &GenerateGenesisDataArgs) -> anyhow::Result<()> {
    for (present, flag) in [
        (args.chains.is_some(), "--chains"),
        (args.l1_endpoints.is_some(), "--l1-endpoints"),
        (args.approved_contracts.is_some(), "--approved-contracts"),
    ] {
        ensure!(present, "{flag} is required together with --guardians-root");
    }
    Ok(())
}

fn load_existing_genesis(
    args: &GenerateGenesisDataArgs,
    repo_root: &Path,
) -> anyhow::Result<PsyGenesisBlockSetupData<F, Hash>> {
    let genesis_path = match &args.genesis_out {
        Some(path) if path.is_absolute() => path.clone(),
        Some(path) => repo_root.join(path),
        None => repo_root.join("genesis.json"),
    };
    let bytes = std::fs::read(&genesis_path)
        .with_context(|| format!("reading existing genesis {}", genesis_path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing existing genesis {}", genesis_path.display()))
}

/// Locates registration 2 through the same Strategy5 dimensions the node builder uses.
fn locate_genesis_multisig_user<'a>(
    args: &GenerateGenesisDataArgs,
    users: &'a [PsyCompactUserDefinition<Hash>],
) -> anyhow::Result<&'a PsyCompactUserDefinition<Hash>> {
    ensure!(
        args.relayer_registration_id == 2 && args.relayer_user_id == BRIDGE_USER_ID,
        "guardian ceremony requires the fixed public registration 2 and user {BRIDGE_USER_ID}"
    );
    ensure!(
        args.coordinator_global_user_tree_height == N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT
            && args.realm_global_user_tree_height == N::REALM_GLOBAL_USER_TREE_HEIGHT
            && args.group_realm_height == N::GROUP_REALM_HEIGHT,
        "ceremony Strategy5 dimensions must equal the local-devnet builder dimensions"
    );
    let (registration, user) = users
        .iter()
        .enumerate()
        .find(|(registration, _)| builder_user_id(*registration as u64) == BRIDGE_USER_ID)
        .context(
            "existing genesis has no user at the builder Strategy5 mapping of the fixed public registration",
        )?;
    ensure!(
        registration == 2,
        "builder Strategy5 maps user {BRIDGE_USER_ID} to registration {registration}, not registration 2"
    );
    Ok(user)
}

fn builder_user_id(registration_id: u64) -> u64 {
    psy_core::user_id::UserIdBitsStrategy5::get_user_id_from_user_registration_id(
        registration_id,
        N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
        N::REALM_GLOBAL_USER_TREE_HEIGHT,
        N::GROUP_REALM_HEIGHT,
    )
}

/// Requires every policy field of the supplied account against the genesis user
/// and the freshly constructed circuit fingerprint.
fn verify_genesis_user_identity(
    account: &MultisigAccount,
    circuit: &MultisigSignatureCircuit,
    user: &PsyCompactUserDefinition<Hash>,
) -> anyhow::Result<()> {
    let policy = &account.initial_policy;
    policy
        .validate()
        .context("supplied multisig initial policy failed the existing policy validator")?;
    ensure!(policy.version == 1, "multisig initial policy must be version 1");
    for (index, member) in policy.member_hashes.iter().enumerate() {
        ensure!(
            member.0.elements.iter().all(|limb| limb.to_canonical_u64() < protocol::GOLDILOCKS_MODULUS),
            "multisig member commitment {index} must use canonical field limbs"
        );
    }

    let fingerprint = circuit.get_fingerprint();
    ensure!(
        user.public_key_info.fingerprint.0 == fingerprint.0,
        "genesis user fingerprint differs from the supplied multisig circuit"
    );
    let param = account.public_key_param().context("supplied multisig account key parameter")?;
    ensure!(
        user.public_key_info.public_key_param.0 == param.0,
        "genesis user public key parameter differs from the supplied account"
    );

    let record = user
        .constract_state_tree_records
        .iter()
        .find(|record| record.parent_index == u64::from(account.contract_id))
        .context("genesis user lacks the multisig policy contract record")?;
    ensure!(record.children.len() == 4, "genesis policy record must hold header plus three members");
    for (slot, child) in record.children.iter().enumerate() {
        ensure!(child.index == slot as u64, "genesis policy slot {} is misplaced", slot);
    }
    ensure!(
        record.children[0].value == Hash::from_values(1, 2, 3, 0),
        "genesis policy header slot does not match [1, 2, 3, 0]"
    );
    for (slot, member) in policy.member_hashes[..3].iter().enumerate() {
        ensure!(
            record.children[slot + 1].value.0 == member.0,
            "genesis policy member slot {} differs from the supplied account",
            slot + 1
        );
    }
    Ok(())
}

/// Fails closed unless compiled dimensions and caller Strategy5 dimensions equal the node builder.
fn validate_compiled_dimensions(args: &GenerateGenesisDataArgs) -> anyhow::Result<()> {
    use psy_config::network_constants::{
        CHECKPOINT_TREE_HEIGHT, CONTRACT_FUNCTION_TREE_HEIGHT, COORDINATOR_USER_TREE_HEIGHT,
        GLOBAL_CONTRACT_TREE_HEIGHT, GLOBAL_USER_TREE_HEIGHT, GROUP_REALM_HEIGHT,
        MAX_CONTRACT_STATE_TREE_HEIGHT, REALM_USER_TREE_HEIGHT,
    };
    for (compiled, node, name) in [
        (GLOBAL_USER_TREE_HEIGHT, N::GLOBAL_USER_TREE_HEIGHT, "global user tree"),
        (GLOBAL_CONTRACT_TREE_HEIGHT, N::GLOBAL_CONTRACT_TREE_HEIGHT, "global contract tree"),
        (CHECKPOINT_TREE_HEIGHT, N::CHECKPOINT_TREE_HEIGHT, "checkpoint tree"),
        (CONTRACT_FUNCTION_TREE_HEIGHT, N::CONTRACT_FUNCTION_TREE_HEIGHT, "contract function tree"),
        (MAX_CONTRACT_STATE_TREE_HEIGHT, N::MAX_CONTRACT_STATE_TREE_HEIGHT, "contract state tree"),
        (COORDINATOR_USER_TREE_HEIGHT, N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT, "coordinator user tree"),
        (REALM_USER_TREE_HEIGHT, N::REALM_GLOBAL_USER_TREE_HEIGHT, "realm user tree"),
        (GROUP_REALM_HEIGHT, N::GROUP_REALM_HEIGHT, "group realm"),
    ] {
        ensure!(
            u64::from(compiled) == u64::from(node),
            "compiled {name} height {compiled} differs from the local-devnet builder height {node}"
        );
    }
    ensure!(
        args.coordinator_global_user_tree_height == N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT
            && args.realm_global_user_tree_height == N::REALM_GLOBAL_USER_TREE_HEIGHT
            && args.group_realm_height == N::GROUP_REALM_HEIGHT,
        "ceremony Strategy5 dimensions must equal the local-devnet builder dimensions"
    );
    Ok(())
}

/// Recomputes checkpoint 0 exactly as the node coordinator does, with the
/// node-side hasher, and converts it to the client 32-byte genesis identity.
fn checkpoint0_genesis_hash(genesis: &PsyGenesisBlockSetupData<F, Hash>) -> anyhow::Result<Hash256> {
    let mut builder = GenesisDatabaseDataBuilder::new(
        genesis.deposit_tree_root,
        genesis.withdrawal_tree_root,
        genesis.checkpoint_stats.clone(),
    );
    builder.setup_contracts::<PoseidonHasher, N>(genesis, true)?;
    let _ = builder.setup_users::<PoseidonHasher, N>(genesis, None, true, false)?;
    builder.setup_validators::<PoseidonHasher>(
        genesis,
        psy_config::PSY_NETWORK_MAGIC,
        N::REALM_GLOBAL_USER_TREE_HEIGHT,
    )?;
    let node_hash = builder
        .get_populated_checkpoint_leaf::<PoseidonHasher>()
        .to_checkpoint_leaf::<PoseidonHasher>()
        .qfhash::<PoseidonHasher>();
    Ok(Hash256::from(ClientHash(node_hash.0)))
}

fn validate_fee_cap(max_fee: u64) -> anyhow::Result<()> {
    let floor = GUTA_FEE
        .checked_add(DA_FEE)
        .context("compiled GUTA_FEE + DA_FEE overflow")?;
    ensure!(max_fee >= floor, "--max-fee {max_fee} is below the required floor {floor}");
    Ok(())
}

fn require_exact_l1_endpoint_coverage(
    chains: &[ChainAuthorization],
    endpoints: &[ChainEndpoint],
) -> anyhow::Result<()> {
    let authorized = chains.iter().map(|chain| chain.chain_index).collect::<BTreeSet<_>>();
    ensure!(
        authorized.len() == chains.len(),
        "authorized chains contain a duplicate chain index"
    );
    let supplied = endpoints.iter().map(|endpoint| endpoint.chain_index).collect::<BTreeSet<_>>();
    ensure!(
        supplied.len() == endpoints.len(),
        "L1 endpoints contain a duplicate chain index"
    );
    ensure!(
        authorized == supplied,
        "L1 endpoints must contain exactly one endpoint for every authorized chain index"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_authorization(
    account: &MultisigAccount,
    circuit: &MultisigSignatureCircuit,
    genesis_hash: &Hash256,
    max_fee: u64,
    chains: Vec<ChainAuthorization>,
    approved_contracts: Vec<ApprovedContract>,
    proof_bound: u32,
) -> anyhow::Result<GuardianAuthorization> {
    let fingerprint = circuit.get_fingerprint();
    let param = account.public_key_param().context("multisig account key parameter")?;
    let manager = psy_ups_circuit::circuit_manager::core::PsyUPSStepCircuitManager::<plonky2::plonk::config::PoseidonGoldilocksConfig, 2>::new_with_config(psy_config::PSY_NETWORK_MAGIC);
    let verifier = manager.ups_end_cap.minifier_chain.as_ref().context("endcap verifier unavailable")?.get_verifier_data();
    let endcap_verifier_fingerprint = ClientHash(psy_plonky2_circuits::proof_minifier::pm_core::get_circuit_fingerprint_generic::<2, F, plonky2::plonk::config::PoseidonGoldilocksConfig>(verifier));
    Ok(GuardianAuthorization {
        version: 1,
        network_magic: psy_config::PSY_NETWORK_MAGIC,
        genesis_hash: Hex(genesis_hash.0),
        user_id: BRIDGE_USER_ID,
        account_json: JsonText::from_value(account).map_err(|error| anyhow!("account JSON: {error}"))?,
        account_public_key: ClientHash(PoseidonHash::two_to_one(fingerprint.0, param.0)),
        multisig_fingerprint: ClientHash(fingerprint.0),
        deposit_contract_id: 2,
        withdrawal_contract_id: 3,
        fee_contract_id: 0,
        guta_fee: GUTA_FEE,
        da_fee: DA_FEE,
        max_fee,
        max_endcap_proof_bytes: proof_bound,
        endcap_verifier_fingerprint,
        approved_contracts,
        chains,
    })
}
/// Loads `<repo-root>/psy-genesis/config.json` at the compiled stage, not the
/// file's default stage, and keeps the configured `prove_proxy_url`.
fn load_network_projection(repo_root: &Path) -> anyhow::Result<NetworkConfigGoldilocks> {
    let config_path = repo_root.join("psy-genesis/config.json");
    let config = PsyConfigGoldilocks::builder()
        .path(config_path.to_str().context("psy-genesis config path must be UTF-8")?)
        .network(psy_config::CURRENT_NETWORK)
        .build()
        .map_err(|error| anyhow!("loading {}: {error}", config_path.display()))?;
    let mut network = config
        .get_network(psy_config::CURRENT_NETWORK)
        .map_err(|error| anyhow!("selecting {} from {}: {error}", psy_config::CURRENT_NETWORK, config_path.display()))?
        .clone();
    Ok(network)
}

/// Serializes the public config and re-inserts `system_prove_proxy_url` so the
/// field is present even when the pool is empty.
fn config_bytes(config: &GuardianConfig) -> anyhow::Result<Vec<u8>> {
    let mut value = serde_json::to_value(config).context("serializing guardian config")?;
    let system_prove_proxy_url = serde_json::to_value(&config.network.system_prove_proxy_url)
        .context("serializing system prove proxy URLs")?;
    let object = value
        .as_object_mut()
        .context("guardian config must serialize to a JSON object")?;
    let network = object
        .get_mut("network")
        .context("guardian config must serialize a network object")?
        .as_object_mut()
        .context("guardian config network must be a JSON object")?;
    network.insert("system_prove_proxy_url".to_owned(), system_prove_proxy_url);
    let mut bytes = serde_json::to_vec_pretty(&value).context("serializing guardian config JSON")?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn guardian_listen_address(id: u8) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], GUARDIAN_FIRST_LISTEN_PORT + u16::from(id) - 1))
}

fn guardian_endpoint(id: u8) -> String {
    format!("http://127.0.0.1:{}/", GUARDIAN_FIRST_LISTEN_PORT + u16::from(id) - 1)
}

fn guardian_signers() -> anyhow::Result<BTreeMap<u8, GuardianSignerConfig>> {
    let mut guardians = BTreeMap::new();
    for id in 1..=3u8 {
        let (signing_key_secret_path, signing_key_password_secret_path) = keystore_secret_paths(id)?;
        guardians.insert(
            id,
            GuardianSignerConfig {
                listen_address: guardian_listen_address(id),
                signing_key_secret_path,
                signing_key_password_secret_path,
            },
        );
    }
    Ok(guardians)
}

fn keystore_secret_paths(id: u8) -> anyhow::Result<(PathBuf, PathBuf)> {
    let home = home::home_dir().context("home directory is required for guardian keystore metadata")?;
    let keystore = home.join(".psy").join("keystore");
    Ok((
        keystore.join(format!("guardian-{id}.keystore.json")),
        keystore.join(format!("guardian-{id}.password")),
    ))
}

fn validate_http_origin(value: &str) -> anyhow::Result<()> {
    let url = url::Url::parse(value).context("parsing guardian HTTP origin")?;
    ensure!(url.scheme() == "http", "guardian endpoints must be HTTP origins");
    ensure!(url.host().is_some(), "guardian endpoints require a host");
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "guardian endpoints must be credential-free"
    );
    ensure!(
        url.query().is_none() && url.fragment().is_none(),
        "guardian endpoints must not carry a query or fragment"
    );
    ensure!(matches!(url.path(), "" | "/"), "guardian endpoints must not carry a path");
    Ok(())
}

fn validate_l1_endpoint(value: &str) -> anyhow::Result<()> {
    let url = url::Url::parse(value).context("parsing L1 endpoint")?;
    let loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(host)) => host == "localhost",
        None => false,
    };
    ensure!(
        (url.scheme() == "https" || (url.scheme() == "http" && loopback))
            && url.host().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none(),
        "L1 endpoint must be a credential-free https or loopback http URL"
    );
    Ok(())
}

/// Walks each keystore path's metadata without following symlinks and without
/// ever opening the final file.
fn verify_secret_metadata() -> anyhow::Result<()> {
    for id in 1..=3u8 {
        let (key, password) = keystore_secret_paths(id)?;
        verify_protected_file(&key)
            .with_context(|| format!("guardian {id} keystore metadata {}", key.display()))?;
        verify_protected_file(&password)
            .with_context(|| format!("guardian {id} password metadata {}", password.display()))?;
    }
    Ok(())
}

fn verify_protected_file(path: &Path) -> anyhow::Result<()> {
    let components = normal_absolute_components(path, "secret metadata")?;
    let effective_uid = current_uid()?;
    let mut directory = open_directory(Path::new("/"))?;
    for (index, name) in components.iter().enumerate() {
        let c_name = CString::new(name.as_bytes()).context("protected path contains NUL")?;
        let final_file = index + 1 == components.len();
        if final_file {
            let metadata = nofollow_metadata(directory.as_raw_fd(), &c_name)?;
            ensure!(
                metadata.is_file() && metadata.uid == effective_uid && metadata.mode & 0o7777 == 0o600,
                "secret metadata {} must be an effective-uid regular file in mode 0600",
                path.display()
            );
        } else {
            directory = open_protected_child(directory, &c_name, effective_uid, true)?;
        }
    }
    Ok(())
}

fn normal_absolute_components(path: &Path, what: &str) -> anyhow::Result<Vec<std::ffi::OsString>> {
    ensure!(path.is_absolute(), "{what} {path:?} must be absolute");
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => components.push(name.to_os_string()),
            _ => anyhow::bail!("{what} {path:?} must contain only normal components"),
        }
    }
    ensure!(!components.is_empty(), "{what} {path:?} must not be filesystem root");
    Ok(components)
}

fn current_uid() -> anyhow::Result<u32> {
    // SAFETY: `geteuid` has no failure mode and no side effects.
    Ok(unsafe { libc::geteuid() })
}

fn write_outputs(
    root: &Path,
    config: &GuardianConfig,
    authorization: &GuardianAuthorization,
) -> anyhow::Result<()> {
    let components = normal_absolute_components(root, "--guardians-root")?;
    let effective_uid = current_uid()?;
    let mut parent = open_directory(Path::new("/"))?;
    for name in &components[..components.len() - 1] {
        let c_name = CString::new(name.as_bytes()).context("guardians root contains NUL")?;
        parent = open_protected_child(parent, &c_name, effective_uid, true)?;
    }
    let root_name = CString::new(components.last().context("guardians root missing")?.as_bytes())
        .context("guardians root contains NUL")?;
    let root_exists = nofollow_exists(parent.as_raw_fd(), &root_name)?;
    if root_exists {
        let root_dir = open_nofollow_directory(&parent, &root_name)?;
        verify_directory_descriptor(&root_dir, effective_uid, false)?;
        reject_existing_output(&root_dir, GUARDIANS_ROOT_CONFIG_FILE)?;
        reject_existing_output(&root_dir, GUARDIANS_ROOT_AUTHORIZATION_DIR)?;
        reject_existing_output(&root_dir, "archive")?;
    }

    let config_body = config_bytes(config)?;
    let authorization_body = authorization_bytes(authorization)?;
    let index = GuardianAuthorizationIndex {
        active_version: 1,
        versions: vec![GuardianAuthorizationVersion {
            version: 1,
            sha256: protocol::sha256(&authorization_body),
        }],
    };
    let mut index_bytes = serde_json::to_vec_pretty(&index).context("serializing authorization index")?;
    index_bytes.push(b'\n');

    let root_dir = open_or_create_directory(parent, &root_name, effective_uid, true)?;
    let authorization_dir = exclusive_child_directory(&root_dir, GUARDIANS_ROOT_AUTHORIZATION_DIR, effective_uid)?;
    let versions_dir = exclusive_child_directory(&authorization_dir, "versions", effective_uid)?;
    let archive_dir = exclusive_child_directory(&root_dir, "archive", effective_uid)?;
    let journal_dir = exclusive_child_directory(&archive_dir, "relayer-journal", effective_uid)?;
    drop(journal_dir);
    write_new_at(&root_dir, GUARDIANS_ROOT_CONFIG_FILE, &config_body)?;
    write_new_at(&versions_dir, "1.json", &authorization_body)?;
    write_new_at(&authorization_dir, "index.json", &index_bytes)?;
    Ok(())
}

fn authorization_bytes(authorization: &GuardianAuthorization) -> anyhow::Result<Vec<u8>> {
    let text = JsonText::<GuardianAuthorization>::from_value(authorization)
        .map_err(|error| anyhow!("serializing guardian authorization: {error}"))?
        .as_str()
        .to_owned();
    let mut bytes = text.into_bytes();
    bytes.push(b'\n');
    Ok(bytes)
}

fn exclusive_child_directory(
    parent: &std::fs::File,
    name: &str,
    effective_uid: u32,
) -> anyhow::Result<std::fs::File> {
    let c_name = CString::new(name).context("output directory name contains NUL")?;
    open_or_create_directory(parent.try_clone()?, &c_name, effective_uid, false)
}

fn open_or_create_directory(
    mut parent: std::fs::File,
    name: &CString,
    effective_uid: u32,
    allow_existing: bool,
) -> anyhow::Result<std::fs::File> {
    let flags = libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_RDONLY | libc::O_DIRECTORY;
    let existing = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags, 0) };
    if existing >= 0 {
        let directory = unsafe { std::fs::File::from_raw_fd(existing) };
        ensure!(allow_existing, "output directory already exists; refusing to overwrite a retained partial output");
        verify_directory_descriptor(&directory, effective_uid, false)?;
        return Ok(directory);
    }
    let error = std::io::Error::last_os_error();
    ensure!(
        error.raw_os_error() == Some(libc::ENOENT),
        "opening protected directory failed: {error}"
    );
    let created = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
    ensure!(created == 0, "creating protected directory failed: {}", std::io::Error::last_os_error());
    parent.sync_all().context("syncing parent after directory creation")?;
    let directory = open_nofollow_directory(&parent, name)?;
    verify_directory_descriptor(&directory, effective_uid, false)?;
    Ok(directory)
}

fn open_protected_child(
    parent: std::fs::File,
    name: &CString,
    effective_uid: u32,
    ancestor: bool,
) -> anyhow::Result<std::fs::File> {
    let child = open_nofollow_directory(&parent, name)?;
    verify_directory_descriptor(&child, effective_uid, ancestor)?;
    Ok(child)
}

fn open_nofollow_directory(parent: &std::fs::File, name: &CString) -> anyhow::Result<std::fs::File> {
    let flags = libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_RDONLY | libc::O_DIRECTORY;
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags, 0) };
    ensure!(fd >= 0, "opening protected directory failed: {}", std::io::Error::last_os_error());
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

fn verify_directory_descriptor(
    directory: &std::fs::File,
    effective_uid: u32,
    ancestor: bool,
) -> anyhow::Result<()> {
    let metadata = directory.metadata().context("reading protected directory descriptor")?;
    let mode = metadata.mode() & 0o777;
    let protected = metadata.is_dir()
        && [0, effective_uid].contains(&metadata.uid())
        && metadata.mode() & 0o022 == 0;
    ensure!(protected, "protected directory owner or mode is unsuitable");
    if !ancestor {
        ensure!(metadata.uid() == effective_uid && mode == 0o700, "output directory must be effective-uid owned mode 0700");
    }
    Ok(())
}

struct NoFollowMetadata {
    mode: u32,
    uid: u32,
    file_type: libc::mode_t,
}

impl NoFollowMetadata {
    fn is_file(&self) -> bool { (self.file_type & libc::S_IFMT) == libc::S_IFREG }
}

fn nofollow_metadata(directory: libc::c_int, name: &CString) -> anyhow::Result<NoFollowMetadata> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe { libc::fstatat(directory, name.as_ptr(), stat.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) };
    ensure!(result == 0, "reading protected metadata failed: {}", std::io::Error::last_os_error());
    let stat = unsafe { stat.assume_init() };
    ensure!((stat.st_mode & libc::S_IFMT) != libc::S_IFLNK, "protected path must not be a symlink");
    Ok(NoFollowMetadata { mode: stat.st_mode, uid: stat.st_uid, file_type: stat.st_mode })
}

fn nofollow_exists(directory: libc::c_int, name: &CString) -> anyhow::Result<bool> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe { libc::fstatat(directory, name.as_ptr(), stat.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) };
    if result == 0 { return Ok(true); }
    let error = std::io::Error::last_os_error();
    ensure!(error.raw_os_error() == Some(libc::ENOENT), "reading output collision failed: {error}");
    Ok(false)
}

fn reject_existing_output(directory: &std::fs::File, name: &str) -> anyhow::Result<()> {
    let c_name = CString::new(name).context("output name contains NUL")?;
    ensure!(
        !nofollow_exists(directory.as_raw_fd(), &c_name)?,
        "output {name} already exists; refusing to overwrite a retained partial output"
    );
    Ok(())
}

fn write_new_at(directory: &std::fs::File, name: &str, body: &[u8]) -> anyhow::Result<()> {
    let c_name = CString::new(name).context("output file name contains NUL")?;
    let flags = libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL;
    let fd = unsafe { libc::openat(directory.as_raw_fd(), c_name.as_ptr(), flags, 0o600) };
    ensure!(fd >= 0, "reserving {name} failed: {}", std::io::Error::last_os_error());
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    file.write_all(body).with_context(|| format!("writing {name}"))?;
    file.sync_all().with_context(|| format!("syncing {name}"))?;
    let metadata = file.metadata().with_context(|| format!("reading {name}"))?;
    ensure!(metadata.is_file() && metadata.mode() & 0o777 == 0o600, "reserved {name} lost mode 0600");
    drop(file);
    directory.sync_all().with_context(|| format!("syncing parent after writing {name}"))
}

fn open_directory(path: &Path) -> anyhow::Result<std::fs::File> {
    let file = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    ensure!(file.metadata()?.is_dir(), "{} must be a directory", path.display());
    Ok(file)
}

/// Parses a canonical-JSON array input, rejecting duplicate and unknown keys
/// through the shared canonical decoder.
fn decode_canonical<T>(bytes: &[u8], what: &str) -> anyhow::Result<T>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let text = String::from_utf8(bytes.to_vec())
        .with_context(|| format!("{what} must be UTF-8 JSON"))?;
    JsonText::<T>::parse(text)
        .map_err(|error| anyhow!("{what} is not canonical JSON: {error}"))?
        .decode()
        .map_err(|error| anyhow!("{what} is not valid JSON: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use parth_core::crypto::hash::traits::ZeroableHash;
    use psy_data::v1::qdata::public_key::PZKPublicKeyInfo;

    fn ceremony_args() -> GenerateGenesisDataArgs {
        GenerateGenesisDataArgs::try_parse_from([
            "generate-genesis-data",
            "--relayer-multisig-account", "account.json",
            "--multisig-policy-artifact", "policy.json",
            "--guardians-root", "/tmp/guardians",
            "--chains", "chains.json",
            "--l1-endpoints", "l1.json",
            "--approved-contracts", "approved.json",
        ])
        .expect("ceremony flags parse")
    }

    fn compact_user(marker: u64) -> PsyCompactUserDefinition<Hash> {
        PsyCompactUserDefinition {
            public_key_info: PZKPublicKeyInfo {
                fingerprint: Hash::from_values(marker, 0, 0, 0),
                public_key_param: Hash::get_zero_value(),
            },
            balance: 0,
            nonce: 0,
            last_checkpoint_id: 0,
            event_index: 0,
            constract_state_tree_records: vec![],
        }
    }

    #[test]
    fn fee_cap_requires_at_least_the_compiled_floor() {
        let floor = GUTA_FEE.checked_add(DA_FEE).expect("compiled fees add");
        assert!(validate_fee_cap(floor - 1).is_err());
        for cap in [floor, floor + 1, GUARDIANS_ROOT_MAX_FEE_DEFAULT] {
            assert!(validate_fee_cap(cap).is_ok(), "cap {cap} must be valid");
        }
    }

    #[test]
    fn ceremony_flags_are_required_together_and_rejected_without_guardians_root() {
        let args = ceremony_args();
        require_ceremony_inputs(&args).expect("complete ceremony flags");
        let mut partial = ceremony_args();
        partial.chains = None;
        assert!(require_ceremony_inputs(&partial).is_err());
        let mut publish = ceremony_args();
        publish.guardians_root = None;
        assert!(reject_publish_branch_flags(&publish).is_err());
        let mut fee_only = ceremony_args();
        fee_only.guardians_root = None;
        fee_only.chains = None;
        fee_only.l1_endpoints = None;
        fee_only.approved_contracts = None;
        fee_only.max_fee = Some(GUARDIANS_ROOT_MAX_FEE_DEFAULT);
        assert!(reject_publish_branch_flags(&fee_only).is_err());
        fee_only.max_fee = None;
    }

    #[test]
    fn genesis_multisig_user_is_located_at_registration_two() {
        let args = ceremony_args();
        assert_eq!(builder_user_id(2), BRIDGE_USER_ID);
        let mut users = vec![compact_user(1), compact_user(2), compact_user(3)];
        let located = locate_genesis_multisig_user(&args, &users).expect("registration 2");
        assert_eq!(located.public_key_info.fingerprint, users[2].public_key_info.fingerprint);
        let mut wrong_dimensions = ceremony_args();
        wrong_dimensions.group_realm_height = 2;
        assert!(locate_genesis_multisig_user(&wrong_dimensions, &users).is_err());
        users[2].public_key_info.fingerprint = Hash::from_values(9, 0, 0, 0);
        let located_after = locate_genesis_multisig_user(&args, &users).expect("registration remains two");
        assert_eq!(located_after.public_key_info.fingerprint, Hash::from_values(9, 0, 0, 0));
    }

    #[test]
    fn l1_endpoints_must_match_authorized_chain_indexes_exactly() {
        let chain = |chain_index| ChainAuthorization {
            chain_index,
            chain_id: alloy_primitives::U256::from(1u8),
            genesis_hash: Hex([1; 32]),
            bridge: Hex([2; 20]),
            state_manager: Hex([3; 20]),
            bridge_code_hash: Hex([4; 32]),
            bridge_implementation: Hex([5; 20]),
            bridge_implementation_code_hash: Hex([6; 32]),
            state_manager_code_hash: Hex([7; 32]),
            state_manager_implementation: Hex([8; 20]),
            state_manager_implementation_code_hash: Hex([9; 32]),
            deployment_block: 1,
            token_mappings: vec![],
        };
        let endpoint = |chain_index| ChainEndpoint { chain_index, rpc_url: "https://example.invalid".into() };
        require_exact_l1_endpoint_coverage(&[chain(1), chain(2)], &[endpoint(2), endpoint(1)])
            .expect("exact coverage");
        assert!(require_exact_l1_endpoint_coverage(&[chain(1)], &[]).is_err());
        assert!(require_exact_l1_endpoint_coverage(&[chain(1)], &[endpoint(1), endpoint(2)]).is_err());
        assert!(require_exact_l1_endpoint_coverage(&[chain(1)], &[endpoint(1), endpoint(1)]).is_err());
        assert!(require_exact_l1_endpoint_coverage(&[chain(1), chain(1)], &[endpoint(1)]).is_err());
    }

    #[test]
    fn system_prove_proxy_url_is_materialized_by_config_serializer() {
        let fixture = serde_json::json!({
            "network": {
                "magic": "0", "users_per_realm": 1, "global_user_tree_height": 1,
                "realm_user_tree_height": 1, "group_realm_height": 1, "realm_configs": [],
                "p2p": {"checkpoints_per_epoch": 1}, "coordinator_configs": [],
                "prove_proxy_url": [], "faucet_rpc_url": [], "nostr_relay_url": "",
                "native_currency": "", "native_currency_decimal": 0, "native_currency_name": "",
                "fees": {"register_user_fee": 0, "deploy_contract_fee": 0, "guta_fee": 0, "da_fee": 0}
            },
            "guardians": {},
            "client": {
                "endpoints": ["", "", ""], "archive_path": "",
                "listen_address": "127.0.0.1:1", "l1_endpoints": []
            }
        });
        let config: GuardianConfig = serde_json::from_value(fixture).expect("public JSON fixture");
        let bytes = config_bytes(&config).expect("production serializer");
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("serialized config");
        assert!(value["network"]["system_prove_proxy_url"].as_array().expect("field").is_empty());
    }
    #[test]
    fn guardian_listeners_and_endpoints_are_fixed_and_distinct() {
        let endpoints: Vec<String> = (1..=3u8).map(guardian_endpoint).collect();
        assert_eq!(endpoints, vec!["http://127.0.0.1:15441/", "http://127.0.0.1:15442/", "http://127.0.0.1:15443/"]);
        for id in 1..=3u8 {
            let address = guardian_listen_address(id);
            assert_eq!(address.to_string(), format!("127.0.0.1:{}", GUARDIAN_FIRST_LISTEN_PORT + u16::from(id) - 1));
        }
        let client = SocketAddr::from(([127, 0, 0, 1], CLIENT_HISTORY_LISTEN_PORT));
        assert_eq!(client.to_string(), "127.0.0.1:15450");
    }

    #[test]
    fn http_origins_are_validated_and_l1_endpoints_keep_the_existing_policy() {
        validate_http_origin("http://127.0.0.1:15441/").expect("plain http origin");
        for invalid in [
            "https://127.0.0.1:15441/",
            "http://user:pass@127.0.0.1:15441/",
            "http://127.0.0.1:15441/history",
            "http://127.0.0.1:15441/?a=b",
            "http://127.0.0.1:15441/#x",
            "not a url",
        ] {
            assert!(validate_http_origin(invalid).is_err(), "{invalid} must be rejected");
        }
        validate_l1_endpoint("https://example.invalid/rpc").expect("https l1 endpoint");
        validate_l1_endpoint("http://localhost:8545").expect("loopback http l1 endpoint");
        assert!(validate_l1_endpoint("http://example.invalid/rpc").is_err());
        assert!(validate_l1_endpoint("https://user:pass@example.invalid").is_err());
    }

    #[test]
    fn duplicate_or_unknown_keys_fail_canonical_array_inputs() {
        let valid = r#"[{"chain_index":1,"rpc_url":"http://localhost:8545"}]"#;
        let decoded: Vec<ChainEndpoint> =
            decode_canonical(valid.as_bytes(), "--l1-endpoints").expect("valid array");
        assert_eq!(decoded[0].chain_index, 1);
        let duplicate = r#"[{"chain_index":1,"chain_index":1,"rpc_url":"http://localhost:8545"}]"#;
        assert!(decode_canonical::<Vec<ChainEndpoint>>(duplicate.as_bytes(), "--l1-endpoints").is_err());
        let unknown = r#"[{"chain_index":1,"rpc_url":"http://localhost:8545","extra":true}]"#;
        assert!(decode_canonical::<Vec<ChainEndpoint>>(unknown.as_bytes(), "--l1-endpoints").is_err());
    }

    #[test]
    fn relative_or_non_normal_secret_metadata_is_rejected_without_io() {
        assert!(verify_protected_file(Path::new("relative/guardian-1.keystore.json")).is_err());
        assert!(verify_protected_file(Path::new("/home/u/../u/guardian-1.keystore.json")).is_err());
        assert!(verify_protected_file(Path::new("/home/u/./../u/guardian-1.keystore.json")).is_err());
    }
}
