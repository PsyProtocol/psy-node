use std::{collections::{BTreeMap, BTreeSet}, ffi::CString, fs::File, io::Read, os::{fd::{AsRawFd, FromRawFd}, unix::fs::MetadataExt}, path::{Component, Path, PathBuf}, time::{Duration, SystemTime, UNIX_EPOCH}};

use zeroize::Zeroizing;
use super::protocol::*;

type Result<T, E = GuardianSignError> = std::result::Result<T, E>;

fn protected_file_at(directory: &Path, relative: &Path, file_flags: i32) -> Result<(File, File)> {
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
            if !metadata.is_file() || metadata.uid() != uid || metadata.mode() & 0o7777 != 0o600 {
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
    protected_file_at(directory, relative, libc::O_RDONLY).map(|(file, _)| file)
}

pub fn open_db_file(directory: &Path, relative: &Path) -> Result<File> {
    protected_file_at(directory, relative, libc::O_RDWR).map(|(file, _)| file)
}

pub fn create_db_file(directory: &Path, relative: &Path) -> Result<(File, File)> {
    protected_file_at(directory, relative, libc::O_RDWR | libc::O_CREAT | libc::O_EXCL)
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

pub struct AuthorizationArchive {
    pub index: GuardianAuthorizationIndex,
    entries: BTreeMap<u32, (GuardianAuthorization, Vec<u8>)>,
}
impl AuthorizationArchive {
    pub fn load(directory: &Path, proof_bound: u32) -> Result<Self> {
        let bytes = read_protected_file(directory, Path::new("authorization/index.json"), MAX_BODY_BYTES)?;
        let index = GuardianAuthorizationIndex::parse(&bytes)?;
        let mut entries = BTreeMap::new();
        for version in &index.versions {
            let path = index.archive_file(Path::new("authorization/versions"), version.version)?;
            let bytes = read_protected_file(directory, &path, MAX_BODY_BYTES)?;
            let authorization = index.resolve(version.version, &bytes)?;
            authorization.validate(psy_config::GUTA_FEE, psy_config::DA_FEE, proof_bound)?;
            entries.insert(version.version, (authorization, bytes.to_vec()));
        }
        Ok(Self { index, entries })
    }
    pub fn active(&self) -> &(GuardianAuthorization, Vec<u8>) { &self.entries[&self.index.active_version] }
    pub fn resolve(&self, version: u32) -> Result<&(GuardianAuthorization, Vec<u8>)> {
        self.entries.get(&version).ok_or(GuardianSignError::HistoryUnavailable)
    }
    pub fn authorizations(&self) -> Vec<GuardianAuthorization> { self.entries.values().map(|entry| entry.0.clone()).collect() }
}

pub const AUTHORIZATION_INDEX_PATH: &str = "authorization/index.json";
pub const AUTHORIZATION_ARCHIVE_PATH: &str = "authorization/versions";

fn config_directory(config_path: &Path) -> Result<PathBuf> {
    let path = if config_path.is_absolute() { config_path.to_path_buf() } else {
        std::env::current_dir().map_err(|_| GuardianSignError::KeyUnavailable)?.join(config_path)
    };
    path.parent().filter(|parent| !parent.as_os_str().is_empty()).map(Path::to_path_buf).ok_or(GuardianSignError::AuthorizationMismatch)
}

fn split_protected(path: &Path) -> Result<(PathBuf, PathBuf)> {
    let normal = path.components().filter(|part| !matches!(part, Component::RootDir | Component::CurDir)).collect::<Vec<_>>();
    if !path.is_absolute() || normal.is_empty() || normal.iter().any(|part| !matches!(part, Component::Normal(_))) {
        return Err(GuardianSignError::AuthorizationMismatch);
    }
    let relative = normal.iter().collect::<PathBuf>();
    Ok((PathBuf::from("/"), relative))
}

pub fn resolve_operator_db_path(config_path: &Path, db_path: &Path) -> Result<(PathBuf, PathBuf)> {
    let directory = config_directory(config_path)?;
    let raw = std::os::unix::ffi::OsStrExt::as_bytes(db_path.as_os_str());
    if raw.is_empty() || raw.ends_with(b"/") || raw.ends_with(b"/.") || db_path.components().next_back().is_none_or(|part| !matches!(part, Component::Normal(_))) {
        return Err(GuardianSignError::AuthorizationMismatch);
    }
    if db_path.is_absolute() { return split_protected(db_path); }
    if db_path.components().any(|part| !matches!(part, Component::Normal(_) | Component::CurDir)) {
        return Err(GuardianSignError::AuthorizationMismatch);
    }
    let relative = directory.components().filter(|part| !matches!(part, Component::RootDir | Component::CurDir))
        .chain(db_path.components().filter(|part| !matches!(part, Component::CurDir))).collect::<PathBuf>();
    if relative.as_os_str().is_empty() { return Err(GuardianSignError::AuthorizationMismatch); }
    Ok((PathBuf::from("/"), relative))
}

fn standard_secret_path(guardian_id: u8, password: bool) -> Result<PathBuf> {
    if !(1..=3).contains(&guardian_id) { return Err(GuardianSignError::AuthorizationMismatch); }
    let home = home::home_dir().ok_or(GuardianSignError::KeyUnavailable)?;
    let name = if password { format!("guardian-{guardian_id}.password") } else { format!("guardian-{guardian_id}.keystore.json") };
    Ok(home.join(".psy").join("keystore").join(name))
}

pub(crate) fn decode_guardian_config(bytes: &[u8]) -> Result<GuardianConfig> {
    let parsed = parse_duplicate_free_json(bytes)?;
    if guardian_ids(&parsed)? != [1, 2, 3] { return Err(GuardianSignError::MalformedRequest); }
    serde_json::from_value(parsed).map_err(|_| GuardianSignError::MalformedRequest)
}

fn guardian_ids(value: &serde_json::Value) -> Result<Vec<u8>, GuardianSignError> {
    let keys = value.get("guardians").and_then(serde_json::Value::as_object).ok_or(GuardianSignError::MalformedRequest)?;
    let mut ids = Vec::new();
    for key in keys.keys() {
        if key.as_bytes().first() == Some(&b'0') || !key.bytes().all(|byte| byte.is_ascii_digit()) { return Err(GuardianSignError::MalformedRequest); }
        let id = key.parse::<u8>().map_err(|_| GuardianSignError::MalformedRequest)?;
        ids.push(id);
    }
    ids.sort_unstable();
    Ok(ids)
}

impl GuardianConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let absolute = if path.is_absolute() { path.to_path_buf() } else {
            std::env::current_dir().map_err(|_| GuardianSignError::KeyUnavailable)?.join(path)
        };
        let (directory, relative) = split_protected(&absolute)?;
        let bytes = read_protected_file(&directory, &relative, MAX_BODY_BYTES)?;
        let config = decode_guardian_config(&bytes)?;
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        if self.guardians.keys().copied().collect::<Vec<_>>() != vec![1, 2, 3] { return Err(GuardianSignError::AuthorizationMismatch); }
        for (id, signer) in &self.guardians {
            let key = standard_secret_path(*id, false)?;
            let password = standard_secret_path(*id, true)?;
            if signer.signing_key_secret_path != key || signer.signing_key_password_secret_path != password {
                return Err(GuardianSignError::AuthorizationMismatch);
            }
            let _ = split_protected(&key)?;
            let _ = split_protected(&password)?;
        }
        if self.client.archive_path != Path::new("archive/relayer-journal") { return Err(GuardianSignError::AuthorizationMismatch); }
        if self.client.endpoints.len() != 3 { return Err(GuardianSignError::AuthorizationMismatch); }
        let mut endpoints = BTreeSet::new();
        for endpoint in &self.client.endpoints {
            if !endpoints.insert(http_origin(endpoint)?) { return Err(GuardianSignError::AuthorizationMismatch); }
        }
        history_origin(self.client.listen_address)?;
        let mut chains = BTreeSet::new();
        for endpoint in &self.client.l1_endpoints {
            if !chains.insert(endpoint.chain_index) { return Err(GuardianSignError::AuthorizationMismatch); }
            validate_endpoint(&endpoint.rpc_url, false, false)?;
        }
        Ok(())
    }
    pub fn build_runtime_config(&self, config_path: &Path, guardian_id: u8, db_path: &Path, index: &GuardianAuthorizationIndex) -> Result<GuardianRuntimeConfig> {
        let signer = self.guardians.get(&guardian_id).ok_or(GuardianSignError::AuthorizationMismatch)?;
        let (db_directory, db_relative) = resolve_operator_db_path(config_path, db_path)?;
        let db = db_directory.join(&db_relative);
        let authorization_path = index.archive_file(Path::new(AUTHORIZATION_ARCHIVE_PATH), index.active_version)?;
        let l2 = self.network.coordinator_configs.first().and_then(|entry| entry.rpc_url.first()).ok_or(GuardianSignError::AuthorizationMismatch)?;
        let listener = history_origin(self.client.listen_address)?;
        let mut seen = BTreeSet::from([http_origin(&listener)?]);
        let mut history = vec![listener];
        for endpoint in &self.client.endpoints {
            if seen.insert(http_origin(endpoint)?) { history.push(endpoint.clone()); }
        }
        let runtime = GuardianRuntimeConfig {
            authorization_path: authorization_path.to_string_lossy().into_owned(),
            authorization_archive_path: AUTHORIZATION_ARCHIVE_PATH.into(),
            authorization_index_path: AUTHORIZATION_INDEX_PATH.into(),
            listen_address: signer.listen_address.to_string(),
            db_path: db.to_string_lossy().into_owned(),
            signing_key_secret_path: signer.signing_key_secret_path.to_string_lossy().into_owned(),
            signing_key_password_secret_path: signer.signing_key_password_secret_path.to_string_lossy().into_owned(),
            l2_rpc_url: l2.clone(),
            l1_rpc_urls: self.client.l1_endpoints.clone(),
            history_urls: history,
        };
        Ok(runtime)
    }
    pub fn validate_rpc_network(&self, network: &psy_config::NetworkConfigGoldilocks) -> Result<()> {
        let mut embedded = serde_json::to_value(&self.network).map_err(|_| GuardianSignError::AuthorizationMismatch)?;
        let mut external = serde_json::to_value(network).map_err(|_| GuardianSignError::AuthorizationMismatch)?;
        for value in [&mut embedded, &mut external] {
            value.as_object_mut().ok_or(GuardianSignError::AuthorizationMismatch)?
                .entry("system_prove_proxy_url").or_insert_with(|| serde_json::Value::Array(Vec::new()));
        }
        if embedded != external { return Err(GuardianSignError::AuthorizationMismatch); }
        Ok(())
    }
}

pub fn load_network(config: &GuardianConfig, authorization: &GuardianAuthorization) -> Result<psy_provider::provider::RpcProvider> {
    let network = &config.network;
    let magic = match network.magic.strip_prefix("0x").or_else(|| network.magic.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(), None => network.magic.parse::<u64>().ok(),
    };
    if magic != Some(authorization.network_magic) || authorization.network_magic != psy_config::PSY_NETWORK_MAGIC
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
    if realm_ids.is_empty() || realm_ids.iter().any(|id| *id >= realm_count) || !realm_ids.contains(&(authorization.user_id / network.users_per_realm)) {
        return Err(GuardianSignError::AuthorizationMismatch);
    }
    psy_provider::provider::RpcProvider::new_with_endpoint_clients(network, clients).map_err(|_| GuardianSignError::AuthorizationMismatch)
}

pub fn load_authorization_archive(config_path: &Path, proof_bound: u32) -> Result<AuthorizationArchive> {
    AuthorizationArchive::load(&config_directory(config_path)?, proof_bound)
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

    #[test]
    #[ignore = "requires operator-owned 0700 GUARDIAN_RUNTIME_TEST_DIRECTORY and QA approval"]
    fn protected_reader_rejects_symlinks_modes_traversal_and_keeps_open_inode() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let directory = PathBuf::from(std::env::var_os("GUARDIAN_RUNTIME_TEST_DIRECTORY").expect("explicit disposable test directory"));
        let file = directory.join("protected-reader-input");
        let moved = directory.join("protected-reader-retained");
        let link = directory.join("protected-reader-link");
        std::fs::write(&file, b"approved").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(&**read_protected_file(&directory, Path::new("protected-reader-input"), 8).unwrap(), b"approved");
        assert!(read_protected_file(&directory, Path::new("protected-reader-input"), 7).is_err());
        assert!(read_protected_file(&directory, Path::new("../protected-reader-input"), 8).is_err());
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
    }

    #[test]
    #[ignore = "requires operator-owned 0700 GUARDIAN_RUNTIME_TEST_DIRECTORY and QA approval"]
    fn db_files_are_created_exclusively_and_reopened_without_replacement() {
        use std::io::Write;
        use std::os::unix::fs::{symlink, PermissionsExt};
        let directory = PathBuf::from(std::env::var_os("GUARDIAN_RUNTIME_TEST_DIRECTORY").expect("explicit disposable test directory"));
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
    }
    fn minimal_guardian_config() -> serde_json::Value {
        serde_json::json!({
            "network": {
                "magic": "0x1", "users_per_realm": 1, "global_user_tree_height": 1, "realm_user_tree_height": 1, "group_realm_height": 1,
                "realm_configs": [], "p2p": {"checkpoints_per_epoch": 1}, "coordinator_configs": [], "prove_proxy_url": [],
                "faucet_rpc_url": [], "nostr_relay_url": "", "native_currency": "", "native_currency_decimal": 0, "native_currency_name": "",
                "fees": {"register_user_fee": 0, "deploy_contract_fee": 0, "guta_fee": 0, "da_fee": 0}
            },
            "guardians": {
                "1": {"listen_address": "127.0.0.1:1", "signing_key_secret_path": "/keys/1.json", "signing_key_password_secret_path": "/keys/1.password"},
                "2": {"listen_address": "127.0.0.1:2", "signing_key_secret_path": "/keys/2.json", "signing_key_password_secret_path": "/keys/2.password"},
                "3": {"listen_address": "127.0.0.1:3", "signing_key_secret_path": "/keys/3.json", "signing_key_password_secret_path": "/keys/3.password"}
            },
            "client": {"endpoints": ["http://a/", "http://b/", "http://c/"], "archive_path": "archive/relayer-journal", "listen_address": "127.0.0.1:9", "l1_endpoints": []}
        })
    }

    #[test]
    fn guardian_config_keeps_empty_system_proxy_and_nested_network_fields() {
        let mut value = minimal_guardian_config();
        value["network"]["system_prove_proxy_url"] = serde_json::json!([]);
        value["network"]["unknown_nested"] = serde_json::json!({"kept": false});
        let config = decode_guardian_config(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(config.network.system_prove_proxy_url.is_empty());
        assert!(config.network.prove_proxy_url.is_empty());
        let mut outer = value;
        outer["db_path"] = serde_json::json!("guardian.redb");
        assert!(decode_guardian_config(&serde_json::to_vec(&outer).unwrap()).is_err());
        let mut duplicate = serde_json::to_vec(&minimal_guardian_config()).unwrap();
        let brace = duplicate.iter().position(|byte| *byte == b'{').unwrap();
        let member = br#""client":{"endpoints":["http://a/","http://b/","http://c/"],"archive_path":"archive/relayer-journal","listen_address":"127.0.0.1:9","l1_endpoints":[]},"#;
        duplicate.splice(brace + 1..brace + 1, member.iter().copied());
        assert!(decode_guardian_config(&duplicate).is_err());
        let mut repeated = serde_json::to_vec(&minimal_guardian_config()).unwrap();
        let marker = br#","3":"#;
        let at = repeated.windows(marker.len()).rposition(|window| window == marker).unwrap();
        let repeated_member = br#""2":{"listen_address":"127.0.0.1:2","signing_key_secret_path":"/keys/2.json","signing_key_password_secret_path":"/keys/2.password"},"#;
        repeated.splice(at + 1..at + 1, repeated_member.iter().copied());
        serde_json::from_slice::<serde_json::Value>(&repeated).expect("syntactically valid duplicate-key JSON");
        assert!(decode_guardian_config(&repeated).is_err());
        let mut nonempty = minimal_guardian_config();
        nonempty["network"]["system_prove_proxy_url"] = serde_json::json!(["http://system/"]);
        assert_eq!(decode_guardian_config(&serde_json::to_vec(&nonempty).unwrap()).unwrap().network.system_prove_proxy_url, vec!["http://system/"]);
    }

    #[test]
    fn operator_db_paths_reject_traversal_and_resolve_absolute_or_config_relative() {
        let config = Path::new("/guardians-root/config.json");
        assert!(resolve_operator_db_path(config, Path::new("../escape.redb")).is_err());
        assert!(resolve_operator_db_path(config, Path::new("journal/")).is_err());
        assert!(resolve_operator_db_path(config, Path::new("journal/.")).is_err());
        assert!(resolve_operator_db_path(config, Path::new("/var/guardian/journal/")).is_err());
        assert!(resolve_operator_db_path(config, Path::new("/.")).is_err());
        assert!(resolve_operator_db_path(config, Path::new("")).is_err());
        assert_eq!(resolve_operator_db_path(config, Path::new("/var/guardian/journal.redb")).unwrap().1, Path::new("var/guardian/journal.redb"));
        assert_eq!(resolve_operator_db_path(config, Path::new("journal.redb")).unwrap().1, Path::new("guardians-root/journal.redb"));
    }

    fn configured(endpoints: [&str; 3], bind: &str) -> GuardianConfig {
        let home = home::home_dir().unwrap();
        let mut guardians = BTreeMap::new();
        for id in 1..=3 {
            guardians.insert(id, GuardianSignerConfig {
                listen_address: bind.parse().unwrap(),
                signing_key_secret_path: home.join(format!(".psy/keystore/guardian-{id}.keystore.json")),
                signing_key_password_secret_path: home.join(format!(".psy/keystore/guardian-{id}.password")),
            });
        }
        let network = serde_json::from_value(serde_json::json!({
            "magic": "0x1", "users_per_realm": 1, "global_user_tree_height": 1, "realm_user_tree_height": 1, "group_realm_height": 1,
            "realm_configs": [], "p2p": {"checkpoints_per_epoch": 1}, "coordinator_configs": [{"id": 0, "rpc_url": ["http://coordinator/"]}],
            "prove_proxy_url": [], "faucet_rpc_url": [], "nostr_relay_url": "", "native_currency": "", "native_currency_decimal": 0,
            "native_currency_name": "", "fees": {"register_user_fee": 0, "deploy_contract_fee": 0, "guta_fee": 0, "da_fee": 0}
        })).unwrap();
        GuardianConfig { network, guardians, client: GuardianClientConfig {
            endpoints: endpoints.map(str::to_owned), archive_path: PathBuf::from("archive/relayer-journal"),
            listen_address: "127.0.0.1:9".parse().unwrap(), l1_endpoints: vec![],
        } }
    }

    #[test]
    fn advertised_origins_normalize_while_equal_binds_and_duplicate_history_origins_are_distinct_rules() {
        assert!(configured(["http://example/", "http://EXAMPLE:80/", "http://other/"], "0.0.0.0:15441").validate().is_err());
        let config = configured(["http://127.0.0.1:9", "http://b/", "http://c/"], "0.0.0.0:15441");
        assert!(config.validate().is_ok());
        assert!(config.guardians.values().map(|signer| signer.listen_address).all(|address| address == config.guardians[&1].listen_address));
        let index = GuardianAuthorizationIndex { active_version: 1, versions: vec![GuardianAuthorizationVersion { version: 1, sha256: Hex([1; 32]) }] };
        let runtime = config.build_runtime_config(Path::new("/guardians-root/config.json"), 1, Path::new("journal.redb"), &index).unwrap();
        assert_eq!(runtime.history_urls, vec!["http://127.0.0.1:9/".to_owned(), "http://b/".to_owned(), "http://c/".to_owned()]);
    }

    #[test]
    fn guardian_json_keys_reject_alternate_numeric_spellings() {
        for text in [r#"{"guardians":{"01":{},"2":{},"3":{}}}"#, r#"{"guardians":{"1":{},"2":{},"2":{}}}"#, r#"{"guardians":{"1":{},"2":{},"4":{}}}"#] {
            let value: serde_json::Value = serde_json::from_str(text).unwrap_or(serde_json::json!({"guardians":{}}));
            assert!(guardian_ids(&value).map(|ids| ids == [1, 2, 3]).unwrap_or(false) == false);
        }
        let value = serde_json::json!({"guardians":{"3":{},"1":{},"2":{}}});
        assert_eq!(guardian_ids(&value).unwrap(), [1, 2, 3]);
    }

    #[test]
    fn rpc_projection_requires_matching_user_proxy() {
        let embedded = serde_json::json!({
            "magic": "0x1", "users_per_realm": 1, "global_user_tree_height": 1, "realm_user_tree_height": 1, "group_realm_height": 1,
            "realm_configs": [], "p2p": {"checkpoints_per_epoch": 1}, "coordinator_configs": [], "prove_proxy_url": ["http://127.0.0.1:9999/"],
            "faucet_rpc_url": [], "nostr_relay_url": "", "native_currency": "", "native_currency_decimal": 0, "native_currency_name": "",
            "fees": {"register_user_fee": 0, "deploy_contract_fee": 0, "guta_fee": 0, "da_fee": 0}
        });
        let network: psy_config::NetworkConfigGoldilocks = serde_json::from_value(embedded.clone()).unwrap();
        let config = GuardianConfig { network: network.clone(), guardians: BTreeMap::new(), client: GuardianClientConfig {
            endpoints: ["http://a/".into(), "http://b/".into(), "http://c/".into()], archive_path: PathBuf::from("archive/relayer-journal"),
            listen_address: "127.0.0.1:1".parse().unwrap(), l1_endpoints: vec![],
        } };
        assert!(config.validate_rpc_network(&network).is_ok());
        let mut embedded_proxy = embedded.clone();
        embedded_proxy["prove_proxy_url"] = serde_json::json!(["http://embedded-user/"]);
        let embedded_config = GuardianConfig { network: serde_json::from_value(embedded_proxy).unwrap(), guardians: BTreeMap::new(), client: config.client.clone() };
        assert!(embedded_config.validate_rpc_network(&network).is_err());
        let mut external = embedded.clone();
        external["prove_proxy_url"] = serde_json::json!([]);
        assert!(config.validate_rpc_network(&serde_json::from_value(external.clone()).unwrap()).is_err());
        external["system_prove_proxy_url"] = serde_json::json!(["http://system/"]);
        assert!(config.validate_rpc_network(&serde_json::from_value(external).unwrap()).is_err());
        external = embedded;
        external["coordinator_configs"] = serde_json::json!([{"id": 0, "rpc_url": ["http://changed/"]}]);
        assert!(config.validate_rpc_network(&serde_json::from_value(external).unwrap()).is_err());
    }

    #[test]
    fn password_grammar_never_trims_or_accepts_line_separators() {
        for bytes in [b"".as_slice(), b"secret\n", b"secret\r", b"secret\0", b"\xef\xbb\xbfsecret", b"\xff"] {
            assert!(secret_text(bytes, true).is_err());
        }
        assert_eq!(secret_text(b" secret ", true).unwrap(), " secret ");
    }
}
