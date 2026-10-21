use std::{collections::BTreeSet, ffi::CString, fs::File, io::Read, os::{fd::{AsRawFd, FromRawFd}, unix::fs::MetadataExt}, path::{Component, Path, PathBuf}, sync::Arc, time::{Duration, SystemTime, UNIX_EPOCH}};

use zeroize::Zeroizing;
use super::protocol::*;

type Result<T, E = GuardianSignError> = std::result::Result<T, E>;

fn protected_file_at(directory: &Path, relative: &Path, file_flags: i32, allowed_modes: &[u32]) -> Result<(File, File)> {
    if relative.as_os_str().is_empty() || relative.components().any(|part| !matches!(part, Component::Normal(_))) {
        return Err(GuardianSignError::AuthorizationMismatch);
    }
    let directory = if directory.is_absolute() { directory.to_path_buf() } else {
        std::env::current_dir().map_err(|_| GuardianSignError::KeyUnavailable)?.join(directory)
    };
    let path = directory.join(relative);
    let mut current = File::open("/").map_err(|_| GuardianSignError::KeyUnavailable)?;
    let parts = path.components().filter(|part| !matches!(part, Component::RootDir | Component::CurDir)).collect::<Vec<_>>();
    let uid = unsafe { libc::geteuid() };
    for (index, part) in parts.iter().enumerate() {
        let Component::Normal(name) = part else { return Err(GuardianSignError::AuthorizationMismatch); };
        use std::os::unix::ffi::OsStrExt;
        let name = CString::new(name.as_bytes()).map_err(|_| GuardianSignError::AuthorizationMismatch)?;
        let final_file = index + 1 == parts.len();
        let flags = libc::O_CLOEXEC | libc::O_NOFOLLOW | if final_file { file_flags } else { libc::O_RDONLY | libc::O_DIRECTORY };
        let fd = unsafe { libc::openat(current.as_raw_fd(), name.as_ptr(), flags, 0o600 as libc::mode_t) };
        if fd < 0 { return Err(GuardianSignError::KeyUnavailable); }
        let opened = unsafe { File::from_raw_fd(fd) };
        let metadata = opened.metadata().map_err(|_| GuardianSignError::KeyUnavailable)?;
        if final_file {
            if !metadata.is_file() || metadata.uid() != uid || !allowed_modes.contains(&(metadata.mode() & 0o7777)) {
                return Err(GuardianSignError::KeyUnavailable);
            }
            return Ok((opened, current));
        } else if !metadata.is_dir() || ![0, uid].contains(&metadata.uid()) || metadata.mode() & 0o022 != 0 {
            return Err(GuardianSignError::KeyUnavailable);
        }
        current = opened;
    }
    Err(GuardianSignError::AuthorizationMismatch)
}

fn protected_file(directory: &Path, relative: &Path) -> Result<File> {
    protected_file_at(directory, relative, libc::O_RDONLY, &[0o600]).map(|(file, _)| file)
}

pub fn open_db_file(directory: &Path, relative: &Path) -> Result<File> {
    protected_file_at(directory, relative, libc::O_RDWR, &[0o600]).map(|(file, _)| file)
}

pub fn create_db_file(directory: &Path, relative: &Path) -> Result<(File, File)> {
    protected_file_at(directory, relative, libc::O_RDWR | libc::O_CREAT | libc::O_EXCL, &[0o600])
}

fn read_file(file: &mut File, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let before = file.metadata().map_err(|_| GuardianSignError::KeyUnavailable)?;
    if before.len() == 0 || before.len() > limit as u64 { return Err(GuardianSignError::KeyUnavailable); }
    let mut bytes = Zeroizing::new(Vec::with_capacity(before.len() as usize));
    file.take(limit as u64 + 1).read_to_end(&mut bytes).map_err(|_| GuardianSignError::KeyUnavailable)?;
    let after = file.metadata().map_err(|_| GuardianSignError::KeyUnavailable)?;
    if bytes.len() > limit || before.len() != bytes.len() as u64 || before.len() != after.len()
        || before.dev() != after.dev() || before.ino() != after.ino() || before.mode() != after.mode()
        || before.uid() != after.uid() || before.mtime() != after.mtime() || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime() || before.ctime_nsec() != after.ctime_nsec() {
        return Err(GuardianSignError::KeyUnavailable);
    }
    Ok(bytes)
}

pub fn read_protected_file(directory: &Path, relative: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    read_file(&mut protected_file(directory, relative)?, limit)
}

fn secret_text(bytes: &[u8], password: bool) -> Result<&str> {
    let text = std::str::from_utf8(bytes).map_err(|_| GuardianSignError::KeyUnavailable)?;
    if text.is_empty() || text.bytes().any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
        || (password && text.starts_with('\u{feff}')) { return Err(GuardianSignError::KeyUnavailable); }
    Ok(text)
}



fn guardian_root_path(root: &Path) -> Result<PathBuf> {
    if root.as_os_str().is_empty() || root.components().any(|part| matches!(part, Component::ParentDir | Component::Prefix(_))) {
        return Err(GuardianSignError::AuthorizationMismatch);
    }
    if root.is_absolute() { Ok(root.to_path_buf()) } else {
        Ok(std::env::current_dir().map_err(|_| GuardianSignError::KeyUnavailable)?.join(root))
    }
}

fn split_protected(path: &Path) -> Result<(PathBuf, PathBuf)> {
    let normal = path.components().filter(|part| !matches!(part, Component::RootDir | Component::CurDir)).collect::<Vec<_>>();
    if !path.is_absolute() || normal.is_empty() || normal.iter().any(|part| !matches!(part, Component::Normal(_))) {
        return Err(GuardianSignError::AuthorizationMismatch);
    }
    let relative = normal.iter().collect::<PathBuf>();
    Ok((PathBuf::from("/"), relative))
}

pub fn guardian_secret_paths(guardian_id: u8) -> Result<(PathBuf, PathBuf)> {
    if !(1..=3).contains(&guardian_id) { return Err(GuardianSignError::AuthorizationMismatch); }
    let directory = home::home_dir().ok_or(GuardianSignError::KeyUnavailable)?.join(".psy/keystore");
    let key = directory.join(format!("guardian-{guardian_id}.keystore.json"));
    let password = directory.join(format!("guardian-{guardian_id}.password"));
    split_protected(&key)?;
    split_protected(&password)?;
    Ok((key, password))
}

fn advertised_origin(listen_address: std::net::SocketAddr, rpc_url: Option<&str>) -> Result<String> {
    if listen_address.port() == 0 { return Err(GuardianSignError::AuthorizationMismatch); }
    match rpc_url {
        Some(url) => { http_origin(url)?; Ok(url.to_owned()) }
        None => history_origin(listen_address),
    }
}

impl GuardianConfig {
    pub fn load(rpc_config: &Path, guardian_root: &Path) -> Result<Self> {
        let mut file = File::open(rpc_config).map_err(|_| GuardianSignError::AuthorizationMismatch)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|_| GuardianSignError::MalformedRequest)?;
        let parsed = parse_duplicate_free_json(&bytes)?;
        let mut config: psy_config::Config<plonky2::field::goldilocks_field::GoldilocksField> =
            serde_json::from_value(parsed).map_err(|_| GuardianSignError::MalformedRequest)?;
        let network = config.networks.remove(psy_config::CURRENT_NETWORK).ok_or(GuardianSignError::AuthorizationMismatch)?;
        Self::from_network(network, guardian_root)
    }

    fn from_network(mut network: psy_config::NetworkConfigGoldilocks, guardian_root: &Path) -> Result<Self> {
        let value = network.guardian_authorization.take().ok_or(GuardianSignError::AuthorizationMismatch)?;
        let authorization: GuardianAuthorization = serde_json::from_value(value).map_err(|_| GuardianSignError::MalformedRequest)?;
        authorization.validate(network.fees.guta_fee, network.fees.da_fee)?;
        let authorization = Arc::new(authorization);
        let mut endpoints = [String::new(), String::new(), String::new()];
        if network.guardian_configs.len() != 3 { return Err(GuardianSignError::AuthorizationMismatch); }
        let mut origins = BTreeSet::new();
        for guardian in &network.guardian_configs {
            if !(1..=3).contains(&guardian.id) { return Err(GuardianSignError::AuthorizationMismatch); }
            let endpoint = &mut endpoints[usize::from(guardian.id - 1)];
            if !endpoint.is_empty() { return Err(GuardianSignError::AuthorizationMismatch); }
            *endpoint = advertised_origin(guardian.listen_address, guardian.rpc_url.as_deref())?;
            if !origins.insert(http_origin(endpoint)?) { return Err(GuardianSignError::AuthorizationMismatch); }
        }
        let history = network.guardian_history.as_ref().ok_or(GuardianSignError::AuthorizationMismatch)?;
        let history_url = advertised_origin(history.listen_address, history.rpc_url.as_deref())?;
        if network.l1_endpoints.is_empty() { return Err(GuardianSignError::AuthorizationMismatch); }
        let mut chains = BTreeSet::new();
        for endpoint in &network.l1_endpoints {
            if !chains.insert(endpoint.chain_index) { return Err(GuardianSignError::AuthorizationMismatch); }
            validate_endpoint(&endpoint.rpc_url, false, false)?;
        }
        Ok(Self { network, authorization, guardian_root: guardian_root_path(guardian_root)?, endpoints, history_url })
    }

    pub fn network_magic(&self) -> Result<u64> {
        let magic = psy_config::parse_magic_hex(&self.network.magic).map_err(|_| GuardianSignError::AuthorizationMismatch)?;
        if magic == 0 || magic >= GOLDILOCKS_MODULUS { return Err(GuardianSignError::AuthorizationMismatch); }
        Ok(magic)
    }

    pub fn build_runtime_config(&self, guardian_id: u8) -> Result<GuardianRuntimeConfig> {
        let signer = self.network.guardian_configs.iter().find(|entry| entry.id == guardian_id).ok_or(GuardianSignError::AuthorizationMismatch)?;
        let (key, password) = guardian_secret_paths(guardian_id)?;
        let db = self.guardian_root.join("db").join(format!("guardian-{guardian_id}.redb"));
        let l2 = self.network.coordinator_configs.first().and_then(|entry| entry.rpc_url.first()).ok_or(GuardianSignError::AuthorizationMismatch)?;
        let mut seen = BTreeSet::from([http_origin(&self.history_url)?]);
        let mut history = vec![self.history_url.clone()];
        for endpoint in &self.endpoints {
            if seen.insert(http_origin(endpoint)?) { history.push(endpoint.clone()); }
        }
        Ok(GuardianRuntimeConfig {
            listen_address: signer.listen_address.to_string(),
            db_path: db.to_string_lossy().into_owned(),
            signing_key_secret_path: key.to_string_lossy().into_owned(),
            signing_key_password_secret_path: password.to_string_lossy().into_owned(),
            l2_rpc_url: l2.clone(),
            l1_rpc_urls: self.network.l1_endpoints.clone(),
            history_urls: history,
        })
    }
}

pub fn load_network(config: &GuardianConfig, authorization: &GuardianAuthorization) -> Result<psy_provider::provider::RpcProvider> {
    let network = &config.network;
    validate_l1_coverage(&network.l1_endpoints, &authorization.chains)?;
    if config.network_magic()? != psy_config::PSY_NETWORK_MAGIC
        || network.users_per_realm != psy_config::USERS_PER_REALM || network.global_user_tree_height != psy_config::GLOBAL_USER_TREE_HEIGHT
        || network.realm_user_tree_height != psy_config::REALM_USER_TREE_HEIGHT || network.group_realm_height != psy_config::GROUP_REALM_HEIGHT
        || network.fees.guta_fee != psy_config::GUTA_FEE || network.fees.da_fee != psy_config::DA_FEE
        || network.coordinator_configs.first().map(|entry| entry.id) != Some(0) || network.coordinator_configs.first().and_then(|entry| entry.rpc_url.first()).is_none() {
        return Err(GuardianSignError::AuthorizationMismatch);
    }
    if !(1..=8).contains(&network.prove_proxy_url.len()) {
        return Err(GuardianSignError::AuthorizationMismatch);
    }
    let proxy_urls: Vec<_> = network.prove_proxy_url.iter().map(|url| url.trim()).collect();
    if proxy_urls.iter().any(|url| url.is_empty() || crate::protocol::validate_endpoint(url, true, false).is_err()) {
        return Err(GuardianSignError::AuthorizationMismatch);
    }
    let mut clients = std::collections::HashMap::new();
    let mut coordinator_ids = BTreeSet::new();
    let mut realm_ids = BTreeSet::new();
    let mut install = |url: &String, clients: &mut std::collections::HashMap<String, std::sync::Arc<reqwest::Client>>| -> Result<()> {
        if !clients.contains_key(url) { clients.insert(url.clone(), std::sync::Arc::new(http_client()?)); }
        Ok(())
    };
    for entry in &network.coordinator_configs {
        if !coordinator_ids.insert(entry.id) || entry.rpc_url.is_empty() { return Err(GuardianSignError::AuthorizationMismatch); }
        for url in &entry.rpc_url { install(url, &mut clients)?; }
    }
    for entry in &network.realm_configs {
        if !realm_ids.insert(entry.id) || entry.rpc_url.is_empty() { return Err(GuardianSignError::AuthorizationMismatch); }
        for url in &entry.rpc_url { install(url, &mut clients)?; }
    }
    let realm_count = 1u64.checked_shl(u32::from(psy_config::COORDINATOR_USER_TREE_HEIGHT)).ok_or(GuardianSignError::AuthorizationMismatch)?;
    if realm_ids.is_empty() || realm_ids.iter().any(|id| *id >= realm_count) || !realm_ids.contains(&(authorization.user_id() / network.users_per_realm)) {
        return Err(GuardianSignError::AuthorizationMismatch);
    }
    psy_provider::provider::RpcProvider::new_with_endpoint_clients(network, clients).map_err(|_| GuardianSignError::AuthorizationMismatch)
}


fn validate_l1_coverage(endpoints: &[psy_config::ChainEndpoint], chains: &[ChainAuthorization]) -> Result<()> {
    let configured = endpoints.iter().map(|endpoint| endpoint.chain_index).collect::<BTreeSet<_>>();
    let authorized = chains.iter().map(|chain| chain.chain_index).collect::<BTreeSet<_>>();
    if configured.is_empty() || configured.len() != endpoints.len() || authorized.len() != chains.len() || configured != authorized {
        return Err(GuardianSignError::AuthorizationMismatch);
    }
    Ok(())
}

fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10)).timeout(Duration::from_secs(360)).build().map_err(|_| GuardianSignError::AuthorizationMismatch)
}

pub fn load_signing_key(config: &GuardianRuntimeConfig) -> Result<psy_provider::wallet::secp_wallet::Wallet> {
    let (password_directory, password_relative) = split_protected(Path::new(&config.signing_key_password_secret_path))?;
    let (key_directory, key_relative) = split_protected(Path::new(&config.signing_key_secret_path))?;
    let password = read_protected_file(&password_directory, &password_relative, 4096)?;
    let mut file = protected_file(&key_directory, &key_relative)?;
    let before = file.metadata().map_err(|_| GuardianSignError::KeyUnavailable)?;
    let _encrypted = read_file(&mut file, 1024 * 1024)?;
    let fd_path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
    let key = psy_provider::wallet::secp_wallet::Wallet::load_encrypted_keystore(&fd_path, secret_text(&password, true)?).map_err(|_| GuardianSignError::KeyUnavailable)?;
    let after = file.metadata().map_err(|_| GuardianSignError::KeyUnavailable)?;
    if before.len() != after.len() || before.mtime() != after.mtime() || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime() || before.ctime_nsec() != after.ctime_nsec() { return Err(GuardianSignError::KeyUnavailable); }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn private_test_directory(label: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let uid = unsafe { libc::geteuid() };
        let runtime = PathBuf::from("/run/user").join(uid.to_string());
        let base = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).filter(|path| path.is_dir())
            .or_else(|| runtime.is_dir().then_some(runtime))
            .unwrap_or_else(|| std::env::current_dir().expect("workspace test working directory"));
        let directory = base.join(format!("guardian-runtime-test-{label}-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir(&directory).expect("private test directory under XDG_RUNTIME_DIR, /run/user/$UID, or the workspace");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        for ancestor in directory.ancestors().skip(1) {
            let metadata = ancestor.metadata().expect("ancestor metadata for the protected-path walk");
            assert!([0, uid].contains(&metadata.uid()) && metadata.mode() & 0o022 == 0,
                "ancestor {} must be root/euid-owned and not group/other-writable for the protected-path walk", ancestor.display());
        }
        directory
    }

    #[test]
    fn selected_network_requires_one_typed_authorization_without_version_envelopes() {
        let mut missing = network();
        missing.guardian_authorization = None;
        assert!(GuardianConfig::from_network(missing, Path::new("/guardians-root")).is_err());
        let mut old = network();
        old.guardian_authorization.as_mut().unwrap()["version"] = serde_json::json!(1);
        assert!(GuardianConfig::from_network(old, Path::new("/guardians-root")).is_err());
        let config = GuardianConfig::from_network(network(), Path::new("/guardians-root")).unwrap();
        assert!(config.network.guardian_authorization.is_none());
        assert_eq!(config.authorization.user_id(), BRIDGE_USER_ID);
        assert_eq!(config.network_magic().unwrap(), 1);
    }

    #[test]
    fn protected_reader_rejects_symlinks_modes_traversal_and_keeps_open_inode() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let directory = private_test_directory("protected-reader");
        let file = directory.join("protected-reader-input");
        let moved = directory.join("protected-reader-retained");
        let link = directory.join("protected-reader-link");
        std::fs::write(&file, b"approved").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(&**read_protected_file(&directory, Path::new("protected-reader-input"), 8).unwrap(), b"approved");
        assert!(read_protected_file(&directory, Path::new("protected-reader-input"), 7).is_err());
        assert!(read_protected_file(&directory, Path::new("../protected-reader-input"), 8).is_err());
        std::fs::write(directory.join("protected-reader-empty"), b"").unwrap();
        std::fs::set_permissions(directory.join("protected-reader-empty"), std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_protected_file(&directory, Path::new("protected-reader-empty"), 8).is_err());
        symlink(&file, &link).unwrap();
        assert!(read_protected_file(&directory, Path::new("protected-reader-link"), 8).is_err());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(read_protected_file(&directory, Path::new("protected-reader-input"), 8).is_err());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut held = protected_file(&directory, Path::new("protected-reader-input")).unwrap();
        std::fs::rename(&file, &moved).unwrap();
        std::fs::write(&file, b"replaced").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(&**read_file(&mut held, 8).unwrap(), b"approved");
        for path in [file, moved, link] { std::fs::remove_file(path).unwrap(); }
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn db_files_are_created_exclusively_and_reopened_without_replacement() {
        use std::io::Write;
        use std::os::unix::fs::{symlink, PermissionsExt};
        let directory = private_test_directory("db-files");
        let name = format!("guardian-db-{}-{}.redb", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos());
        let relative = Path::new(&name);
        assert!(open_db_file(&directory, relative).is_err());
        let (mut file, parent) = create_db_file(&directory, relative).unwrap();
        file.write_all(b"retained").unwrap(); file.sync_all().unwrap(); parent.sync_all().unwrap();
        assert!(create_db_file(&directory, relative).is_err());
        assert_eq!(std::fs::read(directory.join(relative)).unwrap(), b"retained");
        let reopened = open_db_file(&directory, relative).unwrap();
        assert_eq!(reopened.metadata().unwrap().ino(), file.metadata().unwrap().ino());
        assert!(create_db_file(&directory, Path::new("../escape.redb")).is_err());
        std::fs::set_permissions(directory.join(relative), std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(open_db_file(&directory, relative).is_err());
        std::fs::set_permissions(directory.join(relative), std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = format!("{name}.link"); symlink(relative, directory.join(&link)).unwrap();
        assert!(open_db_file(&directory, Path::new(&link)).is_err());
        assert!(create_db_file(&directory, Path::new(&link)).is_err());
        drop(reopened); drop(file);
        std::fs::remove_file(directory.join(link)).unwrap(); std::fs::remove_file(directory.join(relative)).unwrap();
        std::fs::remove_dir_all(&directory).unwrap();
    }
    fn network() -> psy_config::NetworkConfigGoldilocks {
        serde_json::from_value(serde_json::json!({
            "magic": "0x1", "users_per_realm": 1, "global_user_tree_height": 1, "realm_user_tree_height": 1, "group_realm_height": 1,
            "guardian_authorization": super::super::protocol::approval_tests::authorization_fixture(),
            "realm_configs": [], "p2p": {"checkpoints_per_epoch": 1}, "coordinator_configs": [{"id": 0, "rpc_url": ["http://coordinator/"]}],
            "prove_proxy_url": [], "faucet_rpc_url": [], "nostr_relay_url": "", "native_currency": "", "native_currency_decimal": 0,
            "native_currency_name": "", "fees": {"register_user_fee": 0, "deploy_contract_fee": 0, "guta_fee": 0, "da_fee": 0},
            "guardian_configs": [
                {"id": 3, "listen_address": "127.0.0.1:15443"},
                {"id": 1, "listen_address": "127.0.0.1:15441"},
                {"id": 2, "listen_address": "127.0.0.1:15442"}
            ],
            "guardian_history": {"listen_address": "127.0.0.1:15450"},
            "l1_endpoints": [{"chain_index": 7, "rpc_url": "https://chain.example/rpc"}]
        })).unwrap()
    }

    #[test]
    fn guardian_ids_are_exact_unique_and_order_independent() {
        let config = GuardianConfig::from_network(network(), Path::new("/guardians-root")).unwrap();
        assert_eq!(config.endpoints, ["http://127.0.0.1:15441/", "http://127.0.0.1:15442/", "http://127.0.0.1:15443/"]);
        for id in [0, 1, 2, 4, 255] {
            let mut changed = network();
            changed.guardian_configs[0].id = id;
            assert!(GuardianConfig::from_network(changed, Path::new("/guardians-root")).is_err());
        }
        let mut missing = network();
        missing.guardian_configs.pop();
        assert!(GuardianConfig::from_network(missing, Path::new("/guardians-root")).is_err());
    }

    #[test]
    fn missing_public_configuration_never_falls_back() {
        let mut missing = network();
        missing.guardian_configs.clear();
        assert!(GuardianConfig::from_network(missing, Path::new("/guardians-root")).is_err());
        let mut missing = network();
        missing.guardian_history = None;
        assert!(GuardianConfig::from_network(missing, Path::new("/guardians-root")).is_err());
        let mut missing = network();
        missing.l1_endpoints.clear();
        assert!(GuardianConfig::from_network(missing, Path::new("/guardians-root")).is_err());
        let mut duplicate = network();
        duplicate.l1_endpoints.push(duplicate.l1_endpoints[0].clone());
        assert!(GuardianConfig::from_network(duplicate, Path::new("/guardians-root")).is_err());
    }

    #[test]
    fn wildcard_binds_require_explicit_valid_dial_origins() {
        for bind in ["0.0.0.0:15441", "[::]:15441"] {
            assert!(advertised_origin(bind.parse().unwrap(), None).is_err());
            assert_eq!(advertised_origin(bind.parse().unwrap(), Some("http://remote.example/")).unwrap(), "http://remote.example/");
        }
        for url in ["http://user:password@remote/", "http://remote/path", "http://remote/?query", "https://remote/", "http://remote:0/", "http://0.0.0.0:15441/", "http://[::]:15441/"] {
            assert!(advertised_origin("0.0.0.0:15441".parse().unwrap(), Some(url)).is_err());
        }
        assert!(advertised_origin("127.0.0.1:0".parse().unwrap(), Some("http://remote/")).is_err());
        assert_eq!(advertised_origin("[::1]:15441".parse().unwrap(), None).unwrap(), "http://[::1]:15441/");
        let mut duplicate = network();
        duplicate.guardian_configs[0].rpc_url = Some("http://example/".into());
        duplicate.guardian_configs[1].rpc_url = Some("http://EXAMPLE:80/".into());
        assert!(GuardianConfig::from_network(duplicate, Path::new("/guardians-root")).is_err());
    }

    #[test]
    fn runtime_paths_derive_only_from_root_and_guardian_id() {
        let mut public = network();
        public.guardian_history.as_mut().unwrap().rpc_url = Some("http://127.0.0.1:15441/".into());
        let config = GuardianConfig::from_network(public, Path::new("/guardians-root")).unwrap();
        for id in 1..=3 {
            let runtime = config.build_runtime_config(id).unwrap();
            assert_eq!(runtime.db_path, format!("/guardians-root/db/guardian-{id}.redb"));
            let (key, password) = guardian_secret_paths(id).unwrap();
            assert_eq!(key.file_name().unwrap(), format!("guardian-{id}.keystore.json").as_str());
            assert_eq!(password.file_name().unwrap(), format!("guardian-{id}.password").as_str());
            assert_eq!(key.parent().unwrap(), home::home_dir().unwrap().join(".psy/keystore"));
            assert_eq!(Path::new(&runtime.signing_key_secret_path), key);
            assert_eq!(Path::new(&runtime.signing_key_password_secret_path), password);
            assert_eq!(runtime.history_urls.len(), 3);
        }
        for id in [0, 4, 255] {
            assert!(guardian_secret_paths(id).is_err());
            assert!(config.build_runtime_config(id).is_err());
        }
        for root in ["", "../root", "/root/../other"] { assert!(guardian_root_path(Path::new(root)).is_err()); }
        assert_eq!(guardian_root_path(Path::new("relative-root")).unwrap(), std::env::current_dir().unwrap().join("relative-root"));
    }

    #[test]
    fn public_loader_selects_compiled_network_without_secret_file_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("guardian-public-config-{}-{}.json", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        let mut networks = serde_json::Map::new();
        networks.insert(psy_config::CURRENT_NETWORK.into(), serde_json::to_value(network()).unwrap());
        let mut other = network();
        other.guardian_configs.clear();
        networks.insert("not-the-compiled-network".into(), serde_json::to_value(other).unwrap());
        let mut document = serde_json::json!({"defaultNetwork": "not-the-compiled-network", "networks": networks});
        std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(GuardianConfig::load(&path, Path::new("/guardians-root")).is_ok());
        let selected_name = serde_json::to_string(psy_config::CURRENT_NETWORK).unwrap();
        let selected = serde_json::to_string(&network()).unwrap();
        let duplicate = format!("{{\n  \"defaultNetwork\": {selected_name},\n  \"networks\": {{ {selected_name}: {selected}, {selected_name}: {selected} }}\n}}");
        std::fs::write(&path, duplicate).unwrap();
        assert!(matches!(GuardianConfig::load(&path, Path::new("/guardians-root")), Err(GuardianSignError::MalformedRequest)));
        std::fs::write(&path, serde_json::to_string_pretty(&document).unwrap()).unwrap();
        assert!(GuardianConfig::load(&path, Path::new("/guardians-root")).is_ok());
        document["networks"].as_object_mut().unwrap().remove(psy_config::CURRENT_NETWORK);
        std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
        assert!(GuardianConfig::load(&path, Path::new("/guardians-root")).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn l1_coverage_rejects_empty_missing_extra_and_duplicate_chains() {
        let chain = ChainAuthorization {
            chain_index: 7, chain_id: alloy_primitives::U256::from(7), genesis_hash: Hex([1; 32]),
            bridge: Hex([1; 20]), state_manager: Hex([2; 20]), deployment_block: 1, token_mappings: vec![],
        };
        let endpoints = network().l1_endpoints;
        assert!(validate_l1_coverage(&endpoints, &[chain.clone()]).is_ok());
        assert!(validate_l1_coverage(&[], &[]).is_err());
        assert!(validate_l1_coverage(&[], &[chain.clone()]).is_err());
        assert!(validate_l1_coverage(&endpoints, &[]).is_err());
        assert!(validate_l1_coverage(&[endpoints[0].clone(), endpoints[0].clone()], &[chain.clone()]).is_err());
        assert!(validate_l1_coverage(&endpoints, &[chain.clone(), chain.clone()]).is_err());
        let mut other = chain.clone();
        other.chain_index = 42;
        assert!(validate_l1_coverage(&endpoints, &[other.clone()]).is_err());
        let mut both = endpoints;
        both.push(psy_config::ChainEndpoint { chain_index: 42, rpc_url: "https://other.example/rpc".into() });
        assert!(validate_l1_coverage(&both, &[chain, other]).is_ok());
    }

    #[test]
    fn password_grammar_never_trims_or_accepts_line_separators() {
        for bytes in [b"".as_slice(), b"secret\n", b"secret\r", b"secret\0", b"\xef\xbb\xbfsecret", b"\xff"] {
            assert!(secret_text(bytes, true).is_err());
        }
        assert_eq!(secret_text(b" secret ", true).unwrap(), " secret ");
    }

    #[test]
    fn network_magic_requires_nonzero_hex_below_goldilocks_modulus() {
        let mut config = GuardianConfig::from_network(network(), Path::new("/guardians-root")).unwrap();
        for magic in ["", "0x0", "0X0", "garbage", "0xg", "-1", "0x1_0", "0xffffffff00000001", "0xffffffff00000002"] {
            config.network.magic = magic.into();
            assert!(config.network_magic().is_err(), "{magic}");
        }
        for (magic, expected) in [("0x1", 1u64), ("0X10", 16), ("90101", 0x90101), ("0xffffffff00000000", GOLDILOCKS_MODULUS - 1)] {
            config.network.magic = magic.into();
            assert_eq!(config.network_magic().unwrap(), expected, "{magic}");
        }
    }
}
