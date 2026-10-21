//! `--guardians-root` branch of `generate-genesis-data`.
//!
//! `--guardians-root` verifies the canonical signing policy and the sibling compiler
//! artifacts against the EXISTING `genesis.json`, derives the approved
//! contracts and the chain authorization from the deployment output and the
//! canonical network, recomputes the offline checkpoint-0 identity through the
//! populated node-side builder, and publishes the authorization into the
//! selected network of `psy-genesis/config.json`. It never
//! calls `generate_local_devnet_genesis`, never writes `genesis.json`,
//! `private_keys.json`, `faucetOperators.json`, or any public `config.json`,
//! and never reads keystore contents — only their file metadata, at the
//! `guardian_secret_paths` locations derived from `$HOME`.

use std::{
    collections::BTreeSet,
    ffi::CString,
    io::Write,
    os::unix::{
        ffi::OsStrExt,
        fs::MetadataExt,
        io::{AsRawFd, FromRawFd},
    },
    path::{Component, Path, PathBuf},
};

use anyhow::{anyhow, ensure, Context};
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
use psy_config::{ChainEndpoint, NetworkConfigGoldilocks, PsyConfigGoldilocks, GUTA_FEE, DA_FEE};
use psy_core::network_config::PsyNetworkLocalDevnetConstants as N;
use psy_data::genesis::genesis_block_setup::PsyGenesisBlockSetupData;
use psy_node_core::genesis::genesis_db_data_builder::GenesisDatabaseDataBuilder;
use plonky2::field::types::PrimeField64;
use guardian_common::{
    protocol::{
        self, ApprovedContract, ChainAuthorization, GuardianAuthorization,
        Hex, JsonText, BRIDGE_USER_ID,
    },
    runtime::guardian_secret_paths,
};
use psy_ups_circuit::signature::multisig::MultisigSignatureCircuit;
use psy_vm::ups::multisig::{MultisigAccount, MULTISIG_POLICY_CONTRACT_ID};

use super::{
    compiler_checkout, decode_relayer_multisig_account, derive_withdrawal_layout, read_compiler_contract,
    require_abi_method_agreement, require_deployment_roots, require_policy_contract, validate_multisig_policy_artifact,
    CompiledContract, GUARDIANS_ROOT_MAX_FEE_DEFAULT, GenerateGenesisDataArgs, Hash, PsyCompactUserDefinition,
};

const GUARDIANS_ROOT_DB_DIR: &str = "db";


type F = GoldilocksField;

/// Runs the --guardians-root branch; the publish branch is untouched elsewhere.
pub fn run_guardians_root(args: &GenerateGenesisDataArgs) -> anyhow::Result<()> {
    let guardians_root = args
        .guardians_root
        .as_ref()
        .context("--guardians-root is required for the --guardians-root branch")?;
    let repo_root = args.repo_root.canonicalize().with_context(|| {
        format!("repo-root {} does not exist", args.repo_root.display())
    })?;

    // 1. The existing genesis is only read; it is never rewritten or re-derived.
    let genesis = load_existing_genesis(args, &repo_root)?;

    // 2. Canonical signing policy and the sibling compiler artifacts, read once.
    let (account, policy) = checked_canonical_policy(&repo_root)?;
    let compiler_root = compiler_checkout(&repo_root)?;
    let compiled = [
        read_compiler_contract(&compiler_root, "token")?,
        read_compiler_contract(&compiler_root, "multisig_policy")?,
        read_compiler_contract(&compiler_root, "deposit_tree")?,
        read_compiler_contract(&compiler_root, "withdrawal_tree")?,
        read_compiler_contract(&compiler_root, "usdt_token")?,
        read_compiler_contract(&compiler_root, "faucet")?,
    ];
    validate_multisig_policy_artifact(&genesis.contracts, &compiled[1])?;
    let circuit = MultisigSignatureCircuit::new()?;
    let user = locate_genesis_multisig_user(args, &genesis.users)?;
    verify_genesis_user_identity(&account, &circuit, user)?;

    // 3. Offline checkpoint 0 through the node-side populated builder.
    validate_compiled_dimensions(args)?;
    let genesis_hash = checkpoint0_genesis_hash(&genesis)?;

    // 4. Derived authorization, fee cap, and the complete shared validator.
    // The selected canonical network's public L1 endpoints are the only L1
    // source; a network without them is rejected without fallback.
    let network = load_network_projection(&repo_root)?;
    let l1_endpoints = canonical_l1_endpoints(&network)?;
    for endpoint in &l1_endpoints {
        validate_l1_endpoint(&endpoint.rpc_url)
            .with_context(|| format!("L1 endpoint for chain {}", endpoint.chain_index))?;
    }
    let chains = derive_chain_authorizations(&repo_root, &l1_endpoints)?;
    let authorization = prepare_authorization(&policy, &circuit, &genesis_hash, &genesis.contracts, &compiled, chains, args.max_fee)?;

    // 5. Secret metadata walk only; keystore contents are never opened.
    verify_secret_metadata()?;

    // 6. Exclusive outputs. Every input above is settled before the first write.
    publish_guardian_authorization(&repo_root, &authorization)?;
    ensure_runtime_db(guardians_root)?;
    Ok(())
}

/// Builds the authorization from inputs already read. No chain call and no write.
fn prepare_authorization(
    policy: &JsonText<MultisigAccount>,
    circuit: &MultisigSignatureCircuit,
    genesis_hash: &Hash256,
    deployments: &[super::PQBCDeployContract<Hash>],
    compiled: &[CompiledContract],
    chains: Vec<ChainAuthorization>,
    max_fee: Option<u64>,
) -> anyhow::Result<GuardianAuthorization> {
    let approved_contracts = derive_approved_contracts(deployments, compiled)?;
    let max_fee = max_fee.unwrap_or(GUARDIANS_ROOT_MAX_FEE_DEFAULT);
    validate_fee_cap(max_fee)?;
    build_authorization(policy, circuit, genesis_hash, max_fee, chains, approved_contracts)
}

/// Creates `<guardians-root>/db` mode 0700 when absent and keeps it when the
/// runtime already owns databases there. The runtime creates the `.redb` files.
fn ensure_runtime_db(root: &Path) -> anyhow::Result<()> {
    let components = normal_absolute_components(root, "--guardians-root")?;
    let effective_uid = current_uid()?;
    let mut parent = open_directory(Path::new("/"))?;
    for name in &components[..components.len() - 1] {
        let c_name = CString::new(name.as_bytes()).context("guardians root contains NUL")?;
        parent = open_protected_child(parent, &c_name, effective_uid, true)?;
    }
    let root_name = CString::new(components.last().context("guardians root missing")?.as_bytes()).context("guardians root contains NUL")?;
    let root_dir = open_or_create_directory(parent, &root_name, effective_uid, true)?;
    drop(open_or_create_directory(root_dir, &CString::new(GUARDIANS_ROOT_DB_DIR).unwrap(), effective_uid, true)?);
    Ok(())
}

/// Checks default secret-output metadata, the canonical signing policy, and
/// the sibling compiler artifacts before any reset. `private_keys.json` and
/// `faucetOperators.json` are metadata only: an existing path must be one
/// regular file owned by this user in mode 0600 and is opened without following
/// symlinks. A missing file is a first generation. A missing parent is allowed
/// because publication creates it with `create_dir_all`; an existing parent
/// component must already be a real directory. `genesis.json` is not checked
/// here — reset removes it under the separate cleanup mode rule. This does not
/// read genesis, those secret files, deployment output, or a chain. The
/// selected network's `guardian_authorization` may be incomplete before deploy;
/// only its `bridge_relayer_signing_policy` is decoded here, strictly.
pub fn preflight_fresh_devnet_inputs(repo_root: &Path) -> anyhow::Result<()> {
    for path in super::fresh_devnet_secret_outputs(repo_root) {
        super::preflight_owned_regular_destination(&path)
            .with_context(|| format!("fresh output {}", path.display()))?;
    }
    checked_canonical_policy(repo_root)?;
    let compiler_root = compiler_checkout(repo_root)?;
    for stem in ["token", "multisig_policy", "deposit_tree", "withdrawal_tree", "usdt_token", "faucet"] {
        let compiled = read_compiler_contract(&compiler_root, stem)?;
        require_abi_method_agreement(&compiled)?;
        if stem == "multisig_policy" { require_policy_contract(&compiled)?; }
        if compiled.circuit_definitions.iter().any(|definition| definition.name == "withdraw") { derive_withdrawal_layout(&compiled)?; }
    }
    Ok(())
}

fn checked_policy(policy_bytes: &[u8]) -> anyhow::Result<MultisigAccount> {
    let account = decode_relayer_multisig_account(policy_bytes)?;
    ensure!(account.contract_id == MULTISIG_POLICY_CONTRACT_ID, "public multisig account must name contract 1");
    account.initial_policy.validate().context("supplied multisig initial policy failed the existing policy validator")?;
    Ok(account)
}

/// The strict canonical policy: the existing public account decoder for the
/// typed account plus the exact retained string for byte-preserving publish.
fn checked_policy_text(policy_bytes: &[u8]) -> anyhow::Result<(MultisigAccount, JsonText<MultisigAccount>)> {
    let account = checked_policy(policy_bytes)?;
    let text = std::str::from_utf8(policy_bytes).context("canonical signing policy must be UTF-8")?;
    let policy = JsonText::<MultisigAccount>::parse(text.to_owned())
        .map_err(|error| anyhow!("canonical signing policy is not canonical MultisigAccount JSON: {error}"))?;
    Ok((account, policy))
}

/// The exact string value of the selected network's
/// `guardian_authorization.bridge_relayer_signing_policy`, decode-only: the
/// remaining authorization fields may be absent before the deploy.
fn extract_policy_string(config: &serde_json::Value) -> anyhow::Result<String> {
    let field = format!("networks.{}.guardian_authorization.bridge_relayer_signing_policy", psy_config::CURRENT_NETWORK);
    let pointer = format!("/networks/{}/guardian_authorization/bridge_relayer_signing_policy", psy_config::CURRENT_NETWORK);
    let value = config.pointer(&pointer).with_context(|| format!(
        "canonical config psy-genesis/config.json is missing {field}: the checked-in public MultisigAccount signing policy is a required prerequisite before generation or publish"
    ))?;
    value.as_str().map(str::to_owned)
        .with_context(|| format!("{field} must be the public MultisigAccount JSON string"))
}

/// Reads the canonical config and returns the strict signing-policy bytes; the
/// single policy input for both generator branches.
pub fn canonical_policy_bytes(repo_root: &Path) -> anyhow::Result<Vec<u8>> {
    extract_policy_string(&require_canonical_config(repo_root)?).map(String::into_bytes)
}

/// Reads and strictly validates the canonical policy exactly as the postdeploy
/// builder does — before any reset or output — so an accepted policy can never
/// be rejected at the authorize phase. The retained string stays publishable
/// byte-for-byte, and noncanonical JSON (unpadded hashes, unknown or duplicate
/// fields) is rejected here with the field path.
pub fn checked_canonical_policy(repo_root: &Path) -> anyhow::Result<(MultisigAccount, JsonText<MultisigAccount>)> {
    checked_policy_text(&canonical_policy_bytes(repo_root)?).map_err(|error| {
        anyhow!("{error}; networks.{}.guardian_authorization.bridge_relayer_signing_policy must be the canonical public MultisigAccount JSON string", psy_config::CURRENT_NETWORK)
    })
}

/// Pins the canonical config file identity (device and inode) and its full
/// bytes, including the selected-network signing-policy string, before any
/// reset. Revalidation fails closed before publish; the helper's own
/// `publish_guardian_authorization_unchanged` is the only authorized writer of
/// the postdeploy authorization update.
pub struct CanonicalPolicyPin {
    device: u64,
    inode: u64,
    config_bytes: Vec<u8>,
    policy_bytes: Vec<u8>,
}

impl CanonicalPolicyPin {
    /// No-follow read of the canonical config with strict policy validation.
    pub fn pin(repo_root: &Path) -> anyhow::Result<Self> {
        let path = canonical_config_path(repo_root);
        let file = open_canonical_config(&path)?;
        let metadata = file.metadata().with_context(|| format!("reading {}", path.display()))?;
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut &file, &mut bytes).with_context(|| format!("reading {}", path.display()))?;
        let config = duplicate_free_config(&bytes)?;
        let policy = extract_policy_string(&config)?;
        checked_policy(policy.as_bytes())?;
        Ok(Self { device: metadata.dev(), inode: metadata.ino(), config_bytes: bytes, policy_bytes: policy.into_bytes() })
    }

    /// The pinned signing-policy bytes for `build_fresh_devnet_authorization`.
    pub fn policy_bytes(&self) -> &[u8] { &self.policy_bytes }

    /// Fails closed when the canonical config was replaced or any pinned byte,
    /// including the signing-policy string, changed in place.
    pub fn validate(&self, repo_root: &Path) -> anyhow::Result<()> {
        let path = canonical_config_path(repo_root);
        let file = open_canonical_config(&path)?;
        let metadata = file.metadata().with_context(|| format!("reading {}", path.display()))?;
        ensure!(metadata.dev() == self.device && metadata.ino() == self.inode, "canonical config {} was replaced during fresh startup", path.display());
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut &file, &mut bytes).with_context(|| format!("reading {}", path.display()))?;
        ensure!(bytes == self.config_bytes.as_slice(),
            "canonical config {} changed during fresh startup; only this helper's publish may update networks.{}.guardian_authorization.bridge_relayer_signing_policy",
            path.display(), psy_config::CURRENT_NETWORK);
        Ok(())
    }
}

/// The typed authorization for the selected network, built after the L1 deploy.
/// `policy_bytes` are the caller's already-read policy. This writes nothing.
fn authorization_envelope(args: &GenerateGenesisDataArgs, policy_bytes: &[u8]) -> anyhow::Result<GuardianAuthorization> {
    let repo_root = args.repo_root.canonicalize().context("repo-root does not exist")?;
    let genesis = load_existing_genesis(args, &repo_root)?;
    let (account, policy) = checked_policy_text(policy_bytes)?;
    let compiler_root = compiler_checkout(&repo_root)?;
    let compiled = [
        read_compiler_contract(&compiler_root, "token")?, read_compiler_contract(&compiler_root, "multisig_policy")?,
        read_compiler_contract(&compiler_root, "deposit_tree")?, read_compiler_contract(&compiler_root, "withdrawal_tree")?,
        read_compiler_contract(&compiler_root, "usdt_token")?, read_compiler_contract(&compiler_root, "faucet")?,
    ];
    validate_multisig_policy_artifact(&genesis.contracts, &compiled[1])?;
    let circuit = MultisigSignatureCircuit::new()?;
    verify_genesis_user_identity(&account, &circuit, locate_genesis_multisig_user(args, &genesis.users)?)?;
    validate_compiled_dimensions(args)?;
    let genesis_hash = checkpoint0_genesis_hash(&genesis)?;
    let network = load_network_projection(&repo_root)?;
    let endpoints = canonical_l1_endpoints(&network)?;
    for endpoint in &endpoints { validate_l1_endpoint(&endpoint.rpc_url)?; }
    let chains = derive_chain_authorizations(&repo_root, &endpoints)?;
    prepare_authorization(&policy, &circuit, &genesis_hash, &genesis.contracts, &compiled, chains, args.max_fee)
}

/// The typed authorization from the pinned policy bytes read before the reset;
/// the policy string is preserved byte-for-byte in the published authorization.
pub fn build_fresh_devnet_authorization(repo_root: &Path, policy_bytes: &[u8]) -> anyhow::Result<GuardianAuthorization> {
    let args = clap::Parser::try_parse_from([
        "generate-genesis-data", "--repo-root", repo_root.to_str().context("repo-root must be UTF-8")?,
    ])?;
    authorization_envelope(&args, policy_bytes)
}

fn canonical_config_path(repo_root: &Path) -> PathBuf { repo_root.join("psy-genesis/config.json") }

/// The runtime's strict duplicate-free decoder: every public config read goes
/// through it, so duplicate keys fail closed instead of last-wins.
fn duplicate_free_config(bytes: &[u8]) -> anyhow::Result<serde_json::Value> {
    guardian_common::protocol::parse_duplicate_free_json(bytes)
        .map_err(|error| anyhow!("canonical config is not duplicate-free JSON: {error}"))
}
fn require_canonical_config(repo_root: &Path) -> anyhow::Result<serde_json::Value> {
    let path = canonical_config_path(repo_root);
    let file = open_canonical_config(&path)?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut &file, &mut bytes).with_context(|| format!("reading {}", path.display()))?;
    let config = duplicate_free_config(&bytes)?;
    Ok(config)
}

/// Sets `networks[CURRENT_NETWORK].guardian_authorization` and republishes the
/// canonical config. Every other field and network is kept.
pub fn publish_guardian_authorization(repo_root: &Path, authorization: &GuardianAuthorization) -> anyhow::Result<()> {
    let path = canonical_config_path(repo_root);
    let parent = open_directory(path.parent().context("canonical config has no parent")?)?;
    let mut config = require_canonical_config(repo_root)?;
    config.pointer_mut(&format!("/networks/{}", psy_config::CURRENT_NETWORK)).context("selected network missing")?["guardian_authorization"] =
        serde_json::to_value(authorization).context("serializing the guardian authorization")?;
    publish_replaced(&parent, &path, &serde_json::to_vec_pretty(&config).context("serializing the canonical config")?, 0o644)
}

/// Publishes only when the canonical config still holds the pinned bytes. The
/// final identity+bytes compare runs through the held parent descriptor
/// immediately before the `renameat`, leaving a one-syscall window that is
/// trusted to the same-uid mutator: this is a changed-content rejection, not an
/// atomic compare-and-swap promise.
pub fn publish_guardian_authorization_unchanged(
    repo_root: &Path,
    pin: &CanonicalPolicyPin,
    authorization: &GuardianAuthorization,
) -> anyhow::Result<()> {
    let path = canonical_config_path(repo_root);
    let parent = open_directory(path.parent().context("canonical config has no parent")?)?;
    let name = CString::new(path.file_name().context("canonical config has no name")?.as_bytes()).context("canonical config contains NUL")?;
    let read_current = |parent: &std::fs::File| -> anyhow::Result<(std::fs::Metadata, Vec<u8>)> {
        let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_RDONLY, 0) };
        ensure!(fd >= 0, "reading {} failed: {}", path.display(), std::io::Error::last_os_error());
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let metadata = file.metadata().with_context(|| format!("reading {}", path.display()))?;
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut &file, &mut bytes).with_context(|| format!("reading {}", path.display()))?;
        Ok((metadata, bytes))
    };
    let unchanged = |current: &(std::fs::Metadata, Vec<u8>)| -> bool {
        current.0.dev() == pin.device && current.0.ino() == pin.inode && current.1.as_slice() == pin.config_bytes.as_slice()
    };
    let current = read_current(&parent)?;
    ensure!(unchanged(&current),
        "canonical config {} changed during fresh startup; only this helper's publish may update networks.{}.guardian_authorization.bridge_relayer_signing_policy",
        path.display(), psy_config::CURRENT_NETWORK);
    let mut config = duplicate_free_config(&current.1)?;
    config.pointer_mut(&format!("/networks/{}", psy_config::CURRENT_NETWORK)).context("selected network missing")?["guardian_authorization"] =
        serde_json::to_value(authorization).context("serializing the guardian authorization")?;
    let body = serde_json::to_vec_pretty(&config).context("serializing the canonical config")?;
    // The last compare through the held parent descriptor precedes the rename by
    // the one trusted same-uid window documented above.
    let current = read_current(&parent)?;
    ensure!(unchanged(&current),
        "canonical config {} changed during fresh startup; only this helper's publish may update networks.{}.guardian_authorization.bridge_relayer_signing_policy",
        path.display(), psy_config::CURRENT_NETWORK);
    publish_replaced(&parent, &path, &body, 0o644)
}
/// No-follow open of the canonical config; the returned descriptor backs every
/// read and metadata check so a symlink swap cannot redirect them.
fn open_canonical_config(path: &Path) -> anyhow::Result<std::fs::File> {
    let directory = open_directory(path.parent().context("canonical config has no parent")?)?;
    let name = CString::new(path.file_name().context("canonical config has no name")?.as_bytes()).context("canonical config contains NUL")?;
    let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_RDONLY, 0) };
    ensure!(fd >= 0, "reading {} failed: {}", path.display(), std::io::Error::last_os_error());
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

fn publish_replaced(parent: &std::fs::File, path: &Path, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
    let name = CString::new(path.file_name().context("output has no name")?.as_bytes()).context("output contains NUL")?;
    let temporary = CString::new(format!(".{}.tmp", path.file_name().unwrap().to_string_lossy())).unwrap();
    reject_existing_output(&parent, &temporary.to_string_lossy())?;
    let fd = unsafe { libc::openat(parent.as_raw_fd(), temporary.as_ptr(), libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, mode) };
    ensure!(fd >= 0, "reserving {} failed: {}", path.display(), std::io::Error::last_os_error());
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let publish = (|| { file.write_all(bytes)?; file.sync_all()?;
        ensure!(unsafe { libc::renameat(parent.as_raw_fd(), temporary.as_ptr(), parent.as_raw_fd(), name.as_ptr()) } == 0, "publishing {} failed: {}", path.display(), std::io::Error::last_os_error());
        Ok(parent.sync_all()?) })();
    if publish.is_err() { unsafe { libc::unlinkat(parent.as_raw_fd(), temporary.as_ptr(), 0) }; }
    publish.with_context(|| format!("publishing {}", path.display()))
}


/// Fails closed when the guardians-root fee cap leaks into the unchanged publish branch.
pub fn reject_publish_branch_flags(args: &GenerateGenesisDataArgs) -> anyhow::Result<()> {
    ensure!(args.max_fee.is_none(), "--max-fee is only valid together with --guardians-root");
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
        "guardians-root requires the fixed public registration 2 and user {BRIDGE_USER_ID}"
    );
    ensure!(
        args.coordinator_global_user_tree_height == N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT
            && args.realm_global_user_tree_height == N::REALM_GLOBAL_USER_TREE_HEIGHT
            && args.group_realm_height == N::GROUP_REALM_HEIGHT,
        "guardians-root Strategy5 dimensions must equal the local-devnet builder dimensions"
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
        "guardians-root Strategy5 dimensions must equal the local-devnet builder dimensions"
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

/// The calls the relayer and guardian actually make, by contract id. A contract
/// with no entry is approved with an empty method list.
const CALLED_METHODS: [(u32, &[&str]); 3] = [
    (1, &["set_policy"]),
    (2, &["set_chain_root"]),
    (3, &["append_withdrawal", "batch_append_withdrawals_2", "batch_append_withdrawals_5"]),
];

/// Method bindings for the calls this contract serves, taken from the compiled
/// definitions. The name is the generator's expected name; the method id and the
/// input count come from the compiler, and the ABI must report the same count.
fn approved_methods(contract_id: u32, artifact: &CompiledContract) -> anyhow::Result<Vec<protocol::ApprovedMethod>> {
    let expected = CALLED_METHODS.iter().find(|(id, _)| *id == contract_id).map(|(_, names)| *names).unwrap_or(&[]);
    let abi_methods = artifact.abi.pointer("/contract/methods").and_then(serde_json::Value::as_array).context("compiler ABI methods missing")?;
    expected.iter().map(|name| {
        let definition = artifact.circuit_definitions.iter().find(|definition| definition.name == *name)
            .with_context(|| format!("contract {contract_id} compiler artifact has no {name} definition"))?;
        let abi = abi_methods.iter().find(|method| method["name"].as_str() == Some(*name))
            .with_context(|| format!("contract {contract_id} ABI has no {name} method"))?;
        let input_felt_count = u32::try_from(definition.circuit_inputs.len()).context("input count exceeds u32")?;
        ensure!(abi["input_felt_count"].as_u64() == Some(u64::from(input_felt_count)), "ABI input count for {name} differs from the compiled definition");
        Ok(protocol::ApprovedMethod { name: (*name).to_owned(), method_id: definition.method_id, input_felt_count })
    }).collect()
}

/// One approved contract per genesis deployment. The record keeps the leaf, the
/// called method bindings, and the raw compiler bytes' SHA-256; the compiler
/// JSON stays in its own directory.
fn derive_approved_contracts(
    deployments: &[super::PQBCDeployContract<Hash>],
    compiled: &[CompiledContract],
) -> anyhow::Result<Vec<ApprovedContract>> {
    ensure!(deployments.len() == compiled.len(), "Genesis deployments and compiler artifacts differ in count");
    ensure!(deployments.len() == compiled.len(), "Genesis deployments and compiler artifacts differ in count");
    let mut approved = Vec::with_capacity(compiled.len());
    for (contract_id, (deployment, artifact)) in deployments.iter().zip(compiled).enumerate() {
        let contract_id = u32::try_from(contract_id).context("contract id exceeds u32")?;
        require_abi_method_agreement(artifact)?;
        require_deployment_roots(artifact, deployment)?;
        let withdrawal_layout = if artifact.circuit_definitions.iter().any(|definition| definition.name == "withdraw") {
            Some(derive_withdrawal_layout(artifact)?)
        } else {
            None
        };
        approved.push(ApprovedContract {
            contract_id,
            contract_leaf_json: JsonText::from_value(&contract_leaf(deployment)).map_err(|error| anyhow!("contract leaf JSON: {error}"))?,
            methods: approved_methods(contract_id, artifact)?,
            withdrawal_layout,
        });
    }
    Ok(approved)
}

/// Deployment directory for one canonical chain index, in the order the
/// launcher deploys the local cohort.
const DEPLOYMENT_NETWORKS: [&str; 3] = ["localhost", "localhostBsc", "localhostBase"];

/// Chain authorization from the already built deployment output. The L1 genesis
/// hash is the one field no file carries, so it comes from block 0 of the
/// canonical endpoint for that chain index.
fn derive_chain_authorizations(repo_root: &Path, endpoints: &[ChainEndpoint]) -> anyhow::Result<Vec<ChainAuthorization>> {
    let mut chains = Vec::with_capacity(endpoints.len());
    for endpoint in endpoints {
        let network = DEPLOYMENT_NETWORKS.get(usize::from(endpoint.chain_index)).with_context(|| {
            format!("canonical chain index {} has no deployment directory", endpoint.chain_index)
        })?;
        let directory = repo_root.join(format!("psy-contracts/deployments/{network}"));
        let summary = read_json(&directory.join("deployed-contracts.json"))?;
        let chain_index = summary.pointer("/protocol/chain/l1ChainIndex").and_then(serde_json::Value::as_u64)
            .context("deployment summary omits l1ChainIndex")?;
        ensure!(chain_index == u64::from(endpoint.chain_index), "deployment {network} chain index {chain_index} differs from the canonical endpoint");
        let chain_id = summary["chainId"].as_str().context("deployment summary omits chainId")?.parse::<u64>()
            .context("deployment chainId is not a number")?;
        let reported = rpc_quantity(&endpoint.rpc_url, "eth_chainId", serde_json::json!([]))?;
        ensure!(reported == chain_id, "canonical endpoint for chain {chain_index} reports chain id {reported}, not the deployed {chain_id}");
        let genesis_hash = rpc_block_hash(&endpoint.rpc_url, "0x0")?;
        let deployment_block = ["Bridge_Proxy", "StateManager_Proxy"].into_iter().map(|name| {
            let receipt = read_json(&directory.join(format!("{name}.json")))?;
            receipt.pointer("/receipt/blockNumber").and_then(serde_json::Value::as_u64)
                .with_context(|| format!("{name} receipt omits its block number"))
        }).collect::<anyhow::Result<Vec<_>>>()?.into_iter().max().context("deployment receipts missing")?;
        let bridge = address_field(&summary, "/proxies/Bridge_Proxy")?;
        let state_manager = address_field(&summary, "/proxies/StateManager_Proxy")?;
        let mut token_mappings = summary.pointer("/protocol/tokens").and_then(serde_json::Value::as_object)
            .context("deployment summary omits tokens")?.values().map(|token| {
            let token_address = address_field(token, "/l1Address")?;
            let contract_id = token["l2TokenContractId"].as_str().context("token omits l2TokenContractId")?;
            let words = hex::decode(contract_id.trim_start_matches("0x")).context("token contract id is not hex")?;
            let l2_contract_id = words.last().copied().context("token contract id is empty")? as u32;
            ensure!(words[..words.len() - 1].iter().all(|word| *word == 0), "token contract id uses more than one byte");
            Ok(protocol::TokenMapping { token: token_address, l2_contract_id })
        }).collect::<anyhow::Result<Vec<_>>>()?;
        token_mappings.sort_by_key(|mapping| mapping.token);
        chains.push(ChainAuthorization {
            chain_index: endpoint.chain_index, chain_id: alloy_primitives::U256::from(chain_id), genesis_hash: Hex(genesis_hash),
            bridge, state_manager, deployment_block, token_mappings,
        });
    }
    Ok(chains)
}

fn read_json(path: &Path) -> anyhow::Result<serde_json::Value> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
}

fn address_field(value: &serde_json::Value, pointer: &str) -> anyhow::Result<Hex<20>> {
    let text = value.pointer(pointer).and_then(serde_json::Value::as_str).with_context(|| format!("{pointer} is missing"))?;
    let bytes = hex::decode(text.trim_start_matches("0x")).with_context(|| format!("{pointer} is not hex"))?;
    let bytes: [u8; 20] = bytes.try_into().map_err(|_| anyhow!("{pointer} is not a 20 byte address"))?;
    ensure!(bytes != [0; 20], "{pointer} is the zero address");
    Ok(Hex(bytes))
}

fn rpc_quantity(url: &str, method: &str, params: serde_json::Value) -> anyhow::Result<u64> {
    let result = rpc_result(url, method, params)?;
    let text = result.as_str().with_context(|| format!("{method} returned no quantity"))?;
    u64::from_str_radix(text.trim_start_matches("0x"), 16).with_context(|| format!("{method} quantity is not hex"))
}

fn rpc_block_hash(url: &str, block: &str) -> anyhow::Result<[u8; 32]> {
    let result = rpc_result(url, "eth_getBlockByNumber", serde_json::json!([block, false]))?;
    let text = result["hash"].as_str().context("block 0 has no hash")?;
    let bytes = hex::decode(text.trim_start_matches("0x")).context("block 0 hash is not hex")?;
    bytes.try_into().map_err(|_| anyhow!("block 0 hash is not 32 bytes"))
}

fn rpc_result(url: &str, method: &str, params: serde_json::Value) -> anyhow::Result<serde_json::Value> {
    let response = reqwest::blocking::Client::new()
        .post(url)
        .json(&serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
        .send()
        .with_context(|| format!("calling {method} on {url}"))?;
    let body: serde_json::Value = response.json().with_context(|| format!("reading {method} response from {url}"))?;
    body.get("result").filter(|result| !result.is_null()).cloned().with_context(|| format!("{method} on {url} returned no result: {body}"))
}

fn contract_leaf(deployment: &super::PQBCDeployContract<Hash>) -> psy_client_data::qdata::contract::PsyContractLeaf<F> {
    use plonky2::field::types::Field;
    let mut function_tree = parth_common::memory_stores::mem_tree_v3::SimpleMemoryMerkleStoreV3::<PoseidonHasher, Hash>::new(
        psy_config::network_constants::CONTRACT_FUNCTION_TREE_HEIGHT,
    );
    for (index, leaf) in deployment.function_whitelist.iter().enumerate() {
        function_tree.set_leaf_no_proof(index as u64, *leaf);
    }
    psy_client_data::qdata::contract::PsyContractLeaf {
        deployer: F::from_canonical_u64(deployment.deployer),
        function_tree_root: ClientHash(function_tree.get_root().0),
        code_root: ClientHash(deployment.code_root.0),
        state_tree_height: F::from_canonical_u64(u64::from(deployment.code_definition.state_tree_height)),
        // Genesis deployments carry no compiler layout metadata, so the leaf
        // uses the same empty layout the node builder records.
        state_layout_root: ClientHash::default(),
        state_layout_field_count: F::ZERO,
        state_layout_slot_count: F::ZERO,
    }
}

fn build_authorization(
    policy: &JsonText<MultisigAccount>,
    circuit: &MultisigSignatureCircuit,
    genesis_hash: &Hash256,
    max_fee: u64,
    chains: Vec<ChainAuthorization>,
    approved_contracts: Vec<ApprovedContract>,
) -> anyhow::Result<GuardianAuthorization> {
    let fingerprint = circuit.get_fingerprint();
    let manager = psy_ups_circuit::circuit_manager::core::PsyUPSStepCircuitManager::<plonky2::plonk::config::PoseidonGoldilocksConfig, 2>::new_with_config(psy_config::PSY_NETWORK_MAGIC);
    let verifier = manager.ups_end_cap.minifier_chain.as_ref().context("endcap verifier unavailable")?.get_verifier_data();
    let endcap_verifier_fingerprint = ClientHash(psy_plonky2_circuits::proof_minifier::pm_core::get_circuit_fingerprint_generic::<2, F, plonky2::plonk::config::PoseidonGoldilocksConfig>(verifier));
    Ok(GuardianAuthorization {
        genesis_hash: Hex(genesis_hash.0),
        bridge_relayer_signing_policy: policy.clone(),
        multisig_fingerprint: ClientHash(fingerprint.0),
        endcap_verifier_fingerprint,
        max_fee,
        approved_contracts,
        chains,
    })
}
/// Loads `<repo-root>/psy-genesis/config.json` at the compiled stage, not the
/// file's default stage, keeping the configured `prove_proxy_url` and the
/// canonical network's public guardian endpoints.
fn load_network_projection(repo_root: &Path) -> anyhow::Result<NetworkConfigGoldilocks> {
    let config_path = repo_root.join("psy-genesis/config.json");
    let config = PsyConfigGoldilocks::builder()
        .path(config_path.to_str().context("psy-genesis config path must be UTF-8")?)
        .network(psy_config::CURRENT_NETWORK)
        .build()
        .map_err(|error| anyhow!("loading {}: {error}", config_path.display()))?;
    let network = config
        .get_network(psy_config::CURRENT_NETWORK)
        .map_err(|error| anyhow!("selecting {} from {}: {error}", psy_config::CURRENT_NETWORK, config_path.display()))?
        .clone();
    Ok(network)
}

/// Canonical selected network `l1_endpoints` replace the former --l1-endpoints
/// input; a network without guardian L1 endpoints is rejected without fallback.
fn canonical_l1_endpoints(network: &NetworkConfigGoldilocks) -> anyhow::Result<Vec<ChainEndpoint>> {
    ensure!(
        !network.l1_endpoints.is_empty(),
        "canonical network {} must declare nonempty l1_endpoints for the --guardians-root branch",
        psy_config::CURRENT_NETWORK
    );
    Ok(network.l1_endpoints.clone())
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
        let (key, password) = guardian_secret_paths(id).map_err(|error| anyhow!("guardian {id} keystore metadata: {error}"))?;
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

    fn guardians_root_args() -> GenerateGenesisDataArgs {
        GenerateGenesisDataArgs::try_parse_from([
            "generate-genesis-data",
            "--guardians-root", "/tmp/guardians",
        ])
        .expect("guardians-root flags parse")
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
    fn guardians_root_fee_cap_is_rejected_on_the_publish_branch() {
        let mut publish = GenerateGenesisDataArgs::try_parse_from([
            "generate-genesis-data", "--guardians-root", "/tmp/guardians", "--max-fee", "2000000000",
        ])
        .expect("publish-branch args carrying the guardians-root fee cap parse");
        publish.guardians_root = None;
        assert!(reject_publish_branch_flags(&publish).is_err());
        publish.max_fee = None;
        assert!(reject_publish_branch_flags(&publish).is_ok());
        for flag in ["--chains", "--approved-contracts", "--multisig-policy-artifact"] {
            let mut args = vec!["generate-genesis-data", "--guardians-root", "/tmp/guardians"];
            args.extend([flag, "removed.json"]);
            assert!(GenerateGenesisDataArgs::try_parse_from(args).is_err());
        }
    }

    #[test]
    fn genesis_multisig_user_is_located_at_registration_two() {
        let args = guardians_root_args();
        assert_eq!(builder_user_id(2), BRIDGE_USER_ID);
        let mut users = vec![compact_user(1), compact_user(2), compact_user(3)];
        let located = locate_genesis_multisig_user(&args, &users).expect("registration 2");
        assert_eq!(located.public_key_info.fingerprint, users[2].public_key_info.fingerprint);
        let mut wrong_dimensions = guardians_root_args();
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
    fn l1_endpoints_keep_the_existing_policy() {
        validate_l1_endpoint("https://example.invalid/rpc").expect("https l1 endpoint");
        validate_l1_endpoint("http://localhost:8545").expect("loopback http l1 endpoint");
        assert!(validate_l1_endpoint("http://example.invalid/rpc").is_err());
        assert!(validate_l1_endpoint("https://user:pass@example.invalid").is_err());
    }

    fn canonical_network(l1_endpoints: serde_json::Value) -> anyhow::Result<NetworkConfigGoldilocks> {
        let mut value = serde_json::json!({
            "magic": "0", "users_per_realm": 1, "global_user_tree_height": 1,
            "realm_user_tree_height": 1, "group_realm_height": 1, "realm_configs": [],
            "p2p": {"checkpoints_per_epoch": 1}, "coordinator_configs": [],
            "prove_proxy_url": [], "faucet_rpc_url": [], "nostr_relay_url": "",
            "native_currency": "", "native_currency_decimal": 0, "native_currency_name": "",
            "fees": {"register_user_fee": 0, "deploy_contract_fee": 0, "guta_fee": 0, "da_fee": 0}
        });
        value["l1_endpoints"] = l1_endpoints;
        serde_json::from_value(value).map_err(|error| anyhow!(error))
    }

    #[test]
    fn canonical_network_l1_endpoints_replace_the_former_flag_input() {
        let endpoints = canonical_network(serde_json::json!([
            {"chain_index": 0, "rpc_url": "http://127.0.0.1:8545"},
            {"chain_index": 1, "rpc_url": "http://127.0.0.1:9545"},
            {"chain_index": 2, "rpc_url": "http://127.0.0.1:10545"},
        ])).expect("canonical network");
        let decoded = canonical_l1_endpoints(&endpoints).expect("canonical l1 endpoints");
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0].chain_index, 0);
        assert_eq!(decoded[0].rpc_url, "http://127.0.0.1:8545");
        let missing = canonical_network(serde_json::json!([])).expect("canonical network");
        assert!(canonical_l1_endpoints(&missing).is_err());
    }

    #[test]
    fn duplicate_or_unknown_keys_fail_canonical_array_inputs() {
        let valid = "[{\"chain_index\":1,\"rpc_url\":\"http://localhost:8545\"}]";
        let decoded: Vec<ChainEndpoint> =
            decode_canonical(valid.as_bytes(), "--l1-endpoints").expect("valid array");
        assert_eq!(decoded[0].chain_index, 1);
        let duplicate = "[{\"chain_index\":1,\"chain_index\":1,\"rpc_url\":\"http://localhost:8545\"}]";
        assert!(decode_canonical::<Vec<ChainEndpoint>>(duplicate.as_bytes(), "--l1-endpoints").is_err());
        let unknown = "[{\"chain_index\":1,\"rpc_url\":\"http://localhost:8545\",\"extra\":true}]";
        assert!(decode_canonical::<Vec<ChainEndpoint>>(unknown.as_bytes(), "--l1-endpoints").is_err());
    }

    #[test]
    fn relative_or_non_normal_secret_metadata_is_rejected_without_io() {
        assert!(verify_protected_file(Path::new("relative/guardian-1.keystore.json")).is_err());
        assert!(verify_protected_file(Path::new("/home/u/../u/guardian-1.keystore.json")).is_err());
        assert!(verify_protected_file(Path::new("/home/u/./../u/guardian-1.keystore.json")).is_err());
    }

    fn deployment_fixture(root: &Path, chain_id: u64, block: u64) {
        let directory = root.join("psy-contracts/deployments/localhost");
        std::fs::create_dir_all(&directory).unwrap();
        let summary = serde_json::json!({
            "chainId": chain_id.to_string(),
            "protocol": {"chain": {"l1ChainIndex": 0}, "tokens": {"PSY": {"l1Address": "0x1111111111111111111111111111111111111111", "l2TokenContractId": "0x0000000000000000000000000000000000000000000000000000000000000000"}}},
            "proxies": {"Bridge_Proxy": "0x2222222222222222222222222222222222222222", "StateManager_Proxy": "0x3333333333333333333333333333333333333333"}
        });
        std::fs::write(directory.join("deployed-contracts.json"), serde_json::to_vec(&summary).unwrap()).unwrap();
        for name in ["Bridge_Proxy", "StateManager_Proxy"] {
            std::fs::write(directory.join(format!("{name}.json")), serde_json::to_vec(&serde_json::json!({"receipt": {"blockNumber": block}})).unwrap()).unwrap();
        }
    }

    #[test]
    fn chain_authorization_requires_the_deployment_output() {
        let root = std::env::temp_dir().join(format!("psy-deploy-missing-{}", rand::random::<u64>()));
        std::fs::create_dir(&root).unwrap();
        let endpoints = vec![ChainEndpoint { chain_index: 0, rpc_url: "http://127.0.0.1:1".into() }];
        assert!(derive_chain_authorizations(&root, &endpoints).is_err());
        deployment_fixture(&root, 31337, 55);
        // The endpoint is closed, so the chain id cross-check fails before any database exists.
        assert!(derive_chain_authorizations(&root, &endpoints).is_err());
        assert!(!root.join("db").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    fn canonical_policy_config() -> serde_json::Value {
        let mut member_hashes = [ClientHash::ZERO; 8];
        for (index, member) in member_hashes[..3].iter_mut().enumerate() {
            *member = ClientHash::from_values(index as u64 + 1, 0, 0, 0);
        }
        let policy = serde_json::to_string(&MultisigAccount {
            contract_id: MULTISIG_POLICY_CONTRACT_ID,
            initial_policy: psy_vm::ups::multisig::MultisigPolicy { version: 1, threshold: 2, member_count: 3, member_hashes },
        })
        .unwrap();
        let mut config = serde_json::json!({ "networks": {} });
        config["networks"][psy_config::CURRENT_NETWORK]["guardian_authorization"]["bridge_relayer_signing_policy"] = serde_json::json!(policy);
        config
    }

    #[test]
    fn canonical_policy_pin_detects_replacement_and_in_place_change() {
        let root = std::env::temp_dir().join(format!("psy-policy-pin-{}", rand::random::<u64>()));
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir_all(root.join("psy-genesis")).unwrap();
        let write_config = |config: &serde_json::Value| {
            std::fs::write(root.join("psy-genesis/config.json"), serde_json::to_vec_pretty(config).unwrap()).unwrap();
        };
        write_config(&canonical_policy_config());
        let pin = CanonicalPolicyPin::pin(&root).expect("pin canonical policy");
        pin.validate(&root).expect("unchanged config validates");
        let mut changed = canonical_policy_config();
        changed["networks"][psy_config::CURRENT_NETWORK]["guardian_authorization"]["bridge_relayer_signing_policy"] = serde_json::json!("{}");
        write_config(&changed);
        assert!(pin.validate(&root).is_err());
        std::fs::remove_file(root.join("psy-genesis/config.json")).unwrap();
        write_config(&canonical_policy_config());
        assert!(pin.validate(&root).is_err());
        let mut missing = canonical_policy_config();
        missing["networks"][psy_config::CURRENT_NETWORK].as_object_mut().unwrap().remove("guardian_authorization");
        write_config(&missing);
        let Err(error) = CanonicalPolicyPin::pin(&root) else { panic!("pin must reject a config without the signing policy") };
        let error = format!("{error:?}");
        assert!(error.contains(&format!("networks.{}.guardian_authorization.bridge_relayer_signing_policy", psy_config::CURRENT_NETWORK)));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn preflight_reports_the_missing_policy_field_path_before_any_reset() {
        let root = std::env::temp_dir().join(format!("psy-policy-preflight-{}", rand::random::<u64>()));
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir_all(root.join("psy-genesis")).unwrap();
        std::fs::write(root.join("psy-genesis/config.json"), serde_json::to_vec_pretty(&serde_json::json!({ "networks": {} })).unwrap()).unwrap();
        let error = format!("{:?}", preflight_fresh_devnet_inputs(&root).unwrap_err());
        assert!(error.contains(&format!("networks.{}.guardian_authorization.bridge_relayer_signing_policy", psy_config::CURRENT_NETWORK)));
        std::fs::remove_dir_all(root).unwrap();
    }

    fn secret_preflight_root() -> std::path::PathBuf {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let root = std::env::temp_dir().join(format!("psy-secret-preflight-{}", rand::random::<u64>()));
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("genesis.json"), b"retained genesis").unwrap();
        std::fs::set_permissions(root.join("genesis.json"), std::fs::Permissions::from_mode(0o644)).unwrap();
        let marker = root.join("guardians-root/db/guardian-1.redb");
        std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&marker).unwrap();
        std::io::Write::write_all(&mut file, b"retained business rows").unwrap();
        root
    }

    fn assert_business_untouched(root: &std::path::Path) {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(std::fs::read(root.join("genesis.json")).unwrap(), b"retained genesis");
        assert_eq!(std::fs::metadata(root.join("genesis.json")).unwrap().mode() & 0o777, 0o644);
        assert_eq!(std::fs::read(root.join("guardians-root/db/guardian-1.redb")).unwrap(), b"retained business rows");
        assert!(!root.join(".private_keys.json.tmp").exists());
        assert!(!root.join("psy-dapp/apps/bridge/src/config/.faucetOperators.json.tmp").exists());
    }

    #[test]
    fn invalid_secret_outputs_fail_before_prepared_without_business_mutations() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let fixture = std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../psy-dapp/apps/account/src/config/faucetOperators.example.json")).expect("real public faucetOperators example");
        let policy = format!("networks.{}.guardian_authorization.bridge_relayer_signing_policy", psy_config::CURRENT_NETWORK);
        let faucet = |root: &std::path::Path| root.join("psy-dapp/apps/bridge/src/config/faucetOperators.json");

        let allowed = secret_preflight_root();
        let keys = allowed.join("private_keys.json");
        std::fs::write(&keys, &fixture).unwrap();
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(super::super::preflight_owned_regular_destination(&keys).is_ok());
        assert!(super::super::preflight_owned_regular_destination(&faucet(&allowed)).is_ok());
        let error = format!("{:?}", preflight_fresh_devnet_inputs(&allowed).unwrap_err());
        assert!(error.contains(&policy), "{error}");
        assert_eq!(std::fs::read(&keys).unwrap(), fixture);
        assert!(!allowed.join("psy-dapp").exists());
        assert_business_untouched(&allowed);
        std::fs::remove_dir_all(&allowed).unwrap();

        let bad_mode = secret_preflight_root();
        std::fs::create_dir_all(faucet(&bad_mode).parent().unwrap()).unwrap();
        std::fs::write(faucet(&bad_mode), &fixture).unwrap();
        std::fs::set_permissions(faucet(&bad_mode), std::fs::Permissions::from_mode(0o664)).unwrap();
        let error = format!("{:?}", preflight_fresh_devnet_inputs(&bad_mode).unwrap_err());
        assert!(error.contains("faucetOperators.json") && error.contains("mode 0600") && !error.contains(&policy), "{error}");
        assert_eq!(std::fs::read(faucet(&bad_mode)).unwrap(), fixture);
        assert_eq!(std::fs::metadata(faucet(&bad_mode)).unwrap().mode() & 0o777, 0o664);
        assert_business_untouched(&bad_mode);
        std::fs::remove_dir_all(&bad_mode).unwrap();

        let linked = secret_preflight_root();
        let source = linked.join("public-fixture.json");
        std::fs::write(&source, &fixture).unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&source, linked.join("private_keys.json")).unwrap();
        let error = format!("{:?}", preflight_fresh_devnet_inputs(&linked).unwrap_err());
        assert!(error.contains("symlink") && error.contains("private_keys.json") && !error.contains(&policy), "{error}");
        assert!(std::fs::symlink_metadata(linked.join("private_keys.json")).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read(&source).unwrap(), fixture);
        assert_business_untouched(&linked);
        std::fs::remove_dir_all(&linked).unwrap();

        let hard = secret_preflight_root();
        std::fs::create_dir_all(faucet(&hard).parent().unwrap()).unwrap();
        let hard_source = hard.join("public-fixture.json");
        std::fs::write(&hard_source, &fixture).unwrap();
        std::fs::set_permissions(&hard_source, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&hard_source, faucet(&hard)).unwrap();
        let error = format!("{:?}", preflight_fresh_devnet_inputs(&hard).unwrap_err());
        assert!(error.contains("faucetOperators.json") && error.contains("single regular file") && !error.contains(&policy), "{error}");
        assert_eq!(std::fs::metadata(faucet(&hard)).unwrap().nlink(), 2);
        assert_eq!(std::fs::metadata(faucet(&hard)).unwrap().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read(&hard_source).unwrap(), fixture);
        assert_business_untouched(&hard);
        std::fs::remove_dir_all(&hard).unwrap();

        let parent_link = secret_preflight_root();
        let real = parent_link.join("real-config");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::write(real.join("faucetOperators.json"), &fixture).unwrap();
        std::fs::set_permissions(real.join("faucetOperators.json"), std::fs::Permissions::from_mode(0o600)).unwrap();
        let src = parent_link.join("psy-dapp/apps/bridge/src");
        std::fs::create_dir_all(&src).unwrap();
        symlink(&real, src.join("config")).unwrap();
        let error = format!("{:?}", preflight_fresh_devnet_inputs(&parent_link).unwrap_err());
        assert!(error.contains("usable directory") && !error.contains(&policy), "{error}");
        assert!(std::fs::symlink_metadata(src.join("config")).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read(real.join("faucetOperators.json")).unwrap(), fixture);
        assert_business_untouched(&parent_link);
        std::fs::remove_dir_all(&parent_link).unwrap();
    }

}
