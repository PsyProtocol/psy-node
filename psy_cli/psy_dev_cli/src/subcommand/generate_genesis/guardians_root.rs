//! Read-only preflight inputs for `fresh-devnet-state` and the canonical
//! network policy source of `generate-local-devnet-genesis`.
//!
//! The canonical `psy-genesis/config.json` is read-only everywhere in this
//! module: it is opened no-follow, read and parsed strictly (duplicate-free)
//! during preflight, and never written or patched in place. The
//! guardian policy is derived from the selected network's read-only
//! `guardian_initial_member_hashes` (through the shared account derivation);
//! no policy string, authorization object, or digest
//! is read or produced. Keystore contents are never opened — only their file
//! metadata, at the `guardian_keystore_path` locations derived from `$HOME`.
//! Keystore passwords are environment-only and are never inspected here.

use std::{
    ffi::CString,
    os::unix::{
        ffi::OsStrExt,
        fs::MetadataExt,
        io::{AsRawFd, FromRawFd},
    },
    path::{Component, Path, PathBuf},
};

use anyhow::{anyhow, ensure, Context};
use psy_config::{NetworkConfigGoldilocks, PsyConfigGoldilocks};

use super::{compiler_checkout, read_compiler_contract, require_abi_method_agreement, require_policy_contract};

/// Runs the fresh reset's read-only preflight. The default secret outputs are
/// accepted by metadata only; an existing path must be one regular file owned
/// by this user in mode 0600 and is never opened. The stable canonical config
/// is then read and parsed strictly and its read-only guardian policy fields
/// are validated, followed by the three guardian keystore metadata paths and
/// the multisig policy compiler artifact. `genesis.json` is not checked here
/// — reset removes it under the separate cleanup mode rule. This does not
/// read genesis, secret contents, deployment output, a chain, or any
/// environment value.
pub fn preflight_fresh_devnet_inputs(repo_root: &Path) -> anyhow::Result<()> {
    for path in super::fresh_devnet_secret_outputs(repo_root) {
        super::preflight_owned_regular_destination(&path)
            .with_context(|| format!("fresh output {}", path.display()))?;
    }
    checked_canonical_network_policy(&read_canonical_network(repo_root)?)?;
    verify_secret_metadata()?;
    let compiler_root = compiler_checkout(repo_root)?;
    let compiled = read_compiler_contract(&compiler_root, "multisig_policy")?;
    require_abi_method_agreement(&compiled)?;
    require_policy_contract(&compiled)?;
    Ok(())
}

fn canonical_config_path(repo_root: &Path) -> PathBuf { repo_root.join("psy-genesis/config.json") }

/// The runtime's strict duplicate-free decoder: every public config read goes
/// through it, so duplicate keys fail closed instead of last-wins.
fn duplicate_free_config(bytes: &[u8]) -> anyhow::Result<serde_json::Value> {
    guardian_common::protocol::parse_duplicate_free_json(bytes)
        .map_err(|error| anyhow!("canonical config is not duplicate-free JSON: {error}"))
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

/// The selected compiled network of the canonical config, decoded strictly.
/// The single read-only policy input of the generator branches.
pub fn read_canonical_network(repo_root: &Path) -> anyhow::Result<psy_config::NetworkConfigGoldilocks> {
    let path = canonical_config_path(repo_root);
    let mut file = open_canonical_config(&path)?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut bytes).with_context(|| format!("reading {}", path.display()))?;
    let config = PsyConfigGoldilocks::from_json(&duplicate_free_config(&bytes)?.to_string())
        .map_err(|error| anyhow!("canonical config {} is not a valid psy config: {error}", path.display()))?;
    config.get_network(psy_config::CURRENT_NETWORK).map(|network| network.clone()).map_err(|_| {
        anyhow!("canonical config {} is missing networks.{}", path.display(), psy_config::CURRENT_NETWORK)
    })
}

/// The read-only guardian policy input of the selected canonical network:
/// exactly three distinct nonzero member commitment hashes, derived through
/// the shared `initial_account` and consumed, never written.
fn checked_canonical_network_policy(network: &NetworkConfigGoldilocks) -> anyhow::Result<()> {
    let field = format!("networks.{}", psy_config::CURRENT_NETWORK);
    guardian_common::protocol::initial_account(network).map_err(|error| {
        anyhow!("{field}.guardian_initial_member_hashes must be exactly three distinct nonzero member commitments: {error}")
    })?;
    let members = network.guardian_initial_member_hashes.expect("members validated by initial_account");
    ensure!(
        members[0] != members[1] && members[0] != members[2] && members[1] != members[2],
        "{field}.guardian_initial_member_hashes members must be distinct"
    );
    Ok(())
}


/// Walks each guardian keystore path's metadata without following symlinks and
/// without ever opening the final file. There are exactly three encrypted
/// keystores; keystore passwords are environment-only and are never inspected.
fn verify_secret_metadata() -> anyhow::Result<()> {
    for id in 1..=3u8 {
        let key = guardian_common::runtime::guardian_keystore_path(id)
            .map_err(|error| anyhow!("guardian {id} keystore path: {error}"))?;
        verify_protected_file(&key)
            .with_context(|| format!("guardian {id} keystore metadata {}", key.display()))?;
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
    let protected = metadata.is_dir()
        && [0, effective_uid].contains(&metadata.uid())
        && metadata.mode() & 0o022 == 0;
    ensure!(protected, "protected directory owner or mode is unsuitable");
    if !ancestor {
        ensure!(metadata.uid() == effective_uid && metadata.mode() & 0o777 == 0o700, "output directory must be effective-uid owned mode 0700");
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

fn open_directory(path: &Path) -> anyhow::Result<std::fs::File> {
    let file = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    ensure!(file.metadata()?.is_dir(), "{} must be a directory", path.display());
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parth_core::crypto::hash::traits::ZeroableHash;

    type Hash4 = psy_client_common::data::qhashout::QHashOut<plonky2::field::goldilocks_field::GoldilocksField>;

    /// A complete valid selected network, with the guardian policy fields.
    fn canonical_network_config() -> serde_json::Value {
        let mut members = [Hash4::ZERO; 3];
        for (index, member) in members.iter_mut().enumerate() {
            *member = Hash4::from_values(index as u64 + 1, 0, 0, 0);
        }
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

    fn write_canonical_config(root: &Path, network: serde_json::Value) {
        let mut config = serde_json::json!({"defaultNetwork": psy_config::CURRENT_NETWORK, "networks": {}});
        config["networks"][psy_config::CURRENT_NETWORK] = network;
        std::fs::create_dir_all(root.join("psy-genesis")).unwrap();
        std::fs::write(root.join("psy-genesis/config.json"), serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    }

    #[test]
    fn preflight_reports_the_missing_policy_field_before_any_reset() {
        let root = std::env::temp_dir().join(format!("psy-policy-preflight-{}", rand::random::<u64>()));
        std::fs::create_dir(&root).unwrap();
        let mut network = canonical_network_config();
        network.as_object_mut().unwrap().remove("guardian_initial_member_hashes");
        write_canonical_config(&root, network);
        let error = format!("{:?}", preflight_fresh_devnet_inputs(&root).unwrap_err());
        assert!(error.contains(&format!("networks.{}.guardian_initial_member_hashes", psy_config::CURRENT_NETWORK)));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn relative_or_non_normal_secret_metadata_is_rejected_without_io() {
        assert!(verify_protected_file(Path::new("relative/guardian-1.keystore.json")).is_err());
        assert!(verify_protected_file(Path::new("/home/u/../u/guardian-1.keystore.json")).is_err());
        assert!(verify_protected_file(Path::new("/home/u/./../u/guardian-1.keystore.json")).is_err());
    }

    fn secret_preflight_root() -> std::path::PathBuf {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let root = std::env::temp_dir().join(format!("psy-secret-preflight-{}", rand::random::<u64>()));
        std::fs::create_dir(&root).unwrap();
        write_canonical_config(&root, canonical_network_config());
        std::fs::write(root.join("genesis.json"), b"retained genesis").unwrap();
        std::fs::set_permissions(root.join("genesis.json"), std::fs::Permissions::from_mode(0o644)).unwrap();
        let marker = root.join("guardians-root/db/guardian-1.redb");
        std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&marker).unwrap();
        std::io::Write::write_all(&mut file, b"retained business rows").unwrap();
        root
    }

    fn assert_business_untouched(root: &std::path::Path) {
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
        let policy = format!("networks.{}.guardian_initial_member_hashes", psy_config::CURRENT_NETWORK);
        let faucet = |root: &std::path::Path| root.join("psy-dapp/apps/bridge/src/config/faucetOperators.json");

        let allowed = secret_preflight_root();
        let keys = allowed.join("private_keys.json");
        std::fs::write(&keys, &fixture).unwrap();
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(super::super::preflight_owned_regular_destination(&keys).is_ok());
        assert!(super::super::preflight_owned_regular_destination(&faucet(&allowed)).is_ok());
        let error = format!("{:?}", preflight_fresh_devnet_inputs(&allowed).unwrap_err());
        assert!(error.contains("psy-compiler"), "{error}");
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
