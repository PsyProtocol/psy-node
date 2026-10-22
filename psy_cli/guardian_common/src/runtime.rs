use std::{collections::BTreeSet, ffi::CString, fs::File, io::Read, os::{fd::{AsRawFd, FromRawFd}, unix::fs::MetadataExt}, path::{Component, Path, PathBuf}, time::{Duration, SystemTime, UNIX_EPOCH}};

use alloy_primitives::U256;
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

pub fn guardian_password_env(guardian_id: u8) -> Result<&'static str> {
    match guardian_id {
        1 => Ok("GUARDIAN_1_KEYSTORE_PASSWORD"),
        2 => Ok("GUARDIAN_2_KEYSTORE_PASSWORD"),
        3 => Ok("GUARDIAN_3_KEYSTORE_PASSWORD"),
        _ => Err(GuardianSignError::AuthorizationMismatch),
    }
}

pub fn guardian_keystore_path(guardian_id: u8) -> Result<PathBuf> {
    if !(1..=3).contains(&guardian_id) { return Err(GuardianSignError::AuthorizationMismatch); }
    let key = home::home_dir().ok_or(GuardianSignError::KeyUnavailable)?.join(".psy/keystore").join(format!("guardian-{guardian_id}.keystore.json"));
    split_protected(&key)?;
    Ok(key)
}

fn advertised_origin(listen_address: std::net::SocketAddr, rpc_url: Option<&str>) -> Result<String> {
    if listen_address.port() == 0 { return Err(GuardianSignError::AuthorizationMismatch); }
    match rpc_url {
        Some(url) => { http_origin(url)?; Ok(url.to_owned()) }
        None => history_origin(listen_address),
    }
}

impl GuardianConfig {
    pub async fn load(rpc_config: &Path, guardian_root: &Path, local_documents: &[PathBuf]) -> anyhow::Result<Self> {
        let mut file = File::open(rpc_config).map_err(|_| GuardianSignError::AuthorizationMismatch)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|_| GuardianSignError::MalformedRequest)?;
        let parsed = parse_duplicate_free_json(&bytes)?;
        let mut config: psy_config::Config<plonky2::field::goldilocks_field::GoldilocksField> =
            serde_json::from_value(parsed).map_err(|_| GuardianSignError::MalformedRequest)?;
        let network = config.networks.remove(psy_config::CURRENT_NETWORK).ok_or(GuardianSignError::AuthorizationMismatch)?;
        let documents = chain_documents(&network, local_documents).await?;
        Ok(Self::from_network(network, guardian_root, documents)?)
    }

    fn from_network(network: psy_config::NetworkConfigGoldilocks, guardian_root: &Path, documents: Vec<(serde_json::Value, Option<serde_json::Value>)>) -> Result<Self> {
        let members = network.guardian_initial_member_hashes.ok_or(GuardianSignError::AuthorizationMismatch)?;
        if members.iter().any(|member| *member == Hash4::ZERO) || members[0] == members[1] || members[0] == members[2] || members[1] == members[2] {
            return Err(GuardianSignError::AuthorizationMismatch);
        }

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
        let l1_chains = parse_chain_documents(&documents)?;
        Ok(Self { network, guardian_root: guardian_root_path(guardian_root)?, endpoints, history_url, l1_chains })
    }

    pub fn network_magic(&self) -> Result<u64> {
        let magic = psy_config::parse_magic_hex(&self.network.magic).map_err(|_| GuardianSignError::AuthorizationMismatch)?;
        if magic == 0 || magic >= GOLDILOCKS_MODULUS { return Err(GuardianSignError::AuthorizationMismatch); }
        Ok(magic)
    }

    pub fn build_runtime_config(&self, guardian_id: u8) -> Result<GuardianRuntimeConfig> {
        let signer = self.network.guardian_configs.iter().find(|entry| entry.id == guardian_id).ok_or(GuardianSignError::AuthorizationMismatch)?;
        let key = guardian_keystore_path(guardian_id)?;
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
            signing_key_password_env: guardian_password_env(guardian_id)?.to_owned(),
            l2_rpc_url: l2.clone(),
            l1_rpc_urls: self.l1_chains.clone(),
            history_urls: history,
        })
    }
}

/// Local summaries use their sibling Hardhat proxy receipt; registry entries must
/// already carry deployment_block. Missing metadata never means block zero.
async fn chain_documents(network: &psy_config::NetworkConfigGoldilocks, local_documents: &[PathBuf]) -> anyhow::Result<Vec<(serde_json::Value, Option<serde_json::Value>)>> {
    use anyhow::Context;
    if !local_documents.is_empty() {
        let mut documents = Vec::with_capacity(local_documents.len());
        for path in local_documents {
            let document = parse_duplicate_free_json(&std::fs::read(path).with_context(|| format!("read deployment summary {}", path.display()))?)?;
            let proxy = if document.get("l1_chains").is_none() {
                let proxy_path = path.with_file_name("Bridge_Proxy.json");
                let bytes = std::fs::read(&proxy_path).with_context(|| format!("read Bridge deployment receipt {} (required for {})", proxy_path.display(), path.display()))?;
                Some(parse_duplicate_free_json(&bytes).with_context(|| format!("decode Bridge deployment receipt {}", proxy_path.display()))?)
            } else { None };
            let selected = (document, proxy);
            parse_chain_documents(std::slice::from_ref(&selected)).with_context(|| format!("invalid deployment metadata for {}: require matching Bridge_Proxy.json address and receipt.blockNumber, or l1_chains[].deployment_block", path.display()))?;
            documents.push(selected);
        }
        return Ok(documents);
    }
    let endpoint = network.l1_config_url.as_deref().ok_or(GuardianSignError::AuthorizationMismatch)?;
    validate_endpoint(endpoint, false, false)?;
    let response = reqwest::Client::builder().build().map_err(|_| GuardianSignError::L1RpcUnavailable)?
        .get(endpoint).timeout(Duration::from_secs(10)).send().await.map_err(|_| GuardianSignError::L1RpcUnavailable)?;
    if !response.status().is_success() { return Err(GuardianSignError::L1RpcUnavailable.into()); }
    let bytes = response.bytes().await.map_err(|_| GuardianSignError::MalformedRequest)?;
    let documents = vec![(parse_duplicate_free_json(&bytes)?, None)];
    parse_chain_documents(&documents).context("selected remote deployment metadata requires l1_chains[].deployment_block; no Bridge deployment receipt or known deployment transaction is supplied")?;
    Ok(documents)
}

fn parse_chain_documents(documents: &[(serde_json::Value, Option<serde_json::Value>)]) -> Result<Vec<ChainEndpoint>> {
    if documents.is_empty() { return Err(GuardianSignError::AuthorizationMismatch); }
    let mut chains = Vec::new();
    let mut indexes = BTreeSet::new();
    let mut chain_ids = BTreeSet::new();
    for (document, proxy) in documents {
        let parsed = if document.get("l1_chains").is_some() {
            if documents.len() != 1 || document.get("protocol").is_some() || document.get("core").is_some() || document.get("contracts").is_some() {
                return Err(GuardianSignError::AuthorizationMismatch);
            }
            parse_l1_chains(document)?
        } else {
            vec![parse_deployment(document, proxy.as_ref().ok_or(GuardianSignError::MalformedRequest)?)?]
        };
        for chain in parsed {
            if !indexes.insert(chain.chain_index) || !chain_ids.insert(chain.chain_id) { return Err(GuardianSignError::AuthorizationMismatch); }
            chains.push(chain);
        }
    }
    if chains.is_empty() { return Err(GuardianSignError::AuthorizationMismatch); }
    Ok(chains)
}

fn json_text<'a>(value: &'a serde_json::Value, pointer: &str) -> Result<&'a str> {
    value.pointer(pointer).and_then(serde_json::Value::as_str).filter(|text| !text.trim().is_empty()).ok_or(GuardianSignError::MalformedRequest)
}

fn chain_identity(index: &serde_json::Value, id: &serde_json::Value) -> Result<(u8, U256)> {
    let chain_index = u8::try_from(index.as_u64().ok_or(GuardianSignError::MalformedRequest)?).map_err(|_| GuardianSignError::MalformedRequest)?;
    let raw = id.as_str().map(str::to_owned).or_else(|| id.as_u64().map(|number| number.to_string())).ok_or(GuardianSignError::MalformedRequest)?;
    let chain_id = U256::from_str_radix(psy_config::parse_chain_id(&raw).map_err(|_| GuardianSignError::MalformedRequest)?.trim_start_matches("0x"), 16)
        .map_err(|_| GuardianSignError::MalformedRequest)?;
    Ok((chain_index, chain_id))
}

fn bridge_from(text: &str) -> Result<Hex20> {
    Ok(Hex(psy_config::parse_bridge_address(text).map_err(|_| GuardianSignError::MalformedRequest)?))
}

fn deployment_block(value: &serde_json::Value) -> Result<u64> {
    if let Some(number) = value.as_u64() { return Ok(number); }
    let text = value.as_str().ok_or(GuardianSignError::MalformedRequest)?;
    let (digits, radix) = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(digits) => (digits, 16),
        None => (text, 10),
    };
    if digits.is_empty() || !digits.bytes().all(|digit| if radix == 16 { digit.is_ascii_hexdigit() } else { digit.is_ascii_digit() }) {
        return Err(GuardianSignError::MalformedRequest);
    }
    u64::from_str_radix(digits, radix).map_err(|_| GuardianSignError::MalformedRequest)
}

fn proxy_deployment_block(proxy: &serde_json::Value, bridge: Hex20) -> Result<u64> {
    if bridge_from(json_text(proxy, "/address")?)? != bridge { return Err(GuardianSignError::AuthorizationMismatch); }
    deployment_block(proxy.pointer("/receipt/blockNumber").ok_or(GuardianSignError::MalformedRequest)?)
}

fn parse_l1_chains(document: &serde_json::Value) -> Result<Vec<ChainEndpoint>> {
    let entries = document.get("l1_chains").and_then(serde_json::Value::as_array).ok_or(GuardianSignError::MalformedRequest)?;
    if entries.is_empty() { return Err(GuardianSignError::AuthorizationMismatch); }
    let mut chains = Vec::with_capacity(entries.len());
    for entry in entries {
        let (chain_index, chain_id) = chain_identity(
            entry.get("chain_index").ok_or(GuardianSignError::MalformedRequest)?,
            entry.get("chain_id").ok_or(GuardianSignError::MalformedRequest)?,
        )?;
        let rpc_url = entry.get("rpc_url").and_then(serde_json::Value::as_str).ok_or(GuardianSignError::MalformedRequest)?;
        validate_endpoint(rpc_url, false, false)?;
        let bridge = entry.get("contracts").and_then(|contracts| contracts.get("Bridge")).and_then(serde_json::Value::as_str).ok_or(GuardianSignError::MalformedRequest)?;
        let deployment_block = deployment_block(entry.get("deployment_block").ok_or(GuardianSignError::MalformedRequest)?)?;
        chains.push(ChainEndpoint { chain_index, chain_id, bridge: bridge_from(bridge)?, deployment_block, rpc_url: rpc_url.to_owned() });
    }
    Ok(chains)
}

fn parse_deployment(document: &serde_json::Value, proxy: &serde_json::Value) -> Result<ChainEndpoint> {
    if document.get("l1_chains").is_some() { return Err(GuardianSignError::MalformedRequest); }
    let chain = document.pointer("/protocol/chain").ok_or(GuardianSignError::MalformedRequest)?;
    let (chain_index, chain_id) = chain_identity(
        chain.get("l1ChainIndex").ok_or(GuardianSignError::MalformedRequest)?,
        chain.get("l1ChainId").or_else(|| document.get("chainId")).ok_or(GuardianSignError::MalformedRequest)?,
    )?;
    if let Some(exported) = document.get("chainId") {
        if chain_identity(&serde_json::json!(0), exported)?.1 != chain_id { return Err(GuardianSignError::AuthorizationMismatch); }
    }
    let rpc_url = chain.get("defaultRpcUrl").and_then(serde_json::Value::as_str).ok_or(GuardianSignError::MalformedRequest)?;
    validate_endpoint(rpc_url, false, false)?;
    let core_text = document.pointer("/core/Bridge").and_then(serde_json::Value::as_str);
    let contracts_text = document.pointer("/contracts/Bridge").and_then(serde_json::Value::as_str);
    let bridge = core_text.or(contracts_text).ok_or(GuardianSignError::MalformedRequest)?;
    if let (Some(core), Some(contracts)) = (core_text, contracts_text) {
        if bridge_from(core)? != bridge_from(contracts)? { return Err(GuardianSignError::AuthorizationMismatch); }
    }
    json_text(document, "/network")?;
    let bridge = bridge_from(bridge)?;
    let deployment_block = proxy_deployment_block(proxy, bridge)?;
    Ok(ChainEndpoint { chain_index, chain_id, bridge, deployment_block, rpc_url: rpc_url.to_owned() })
}


pub fn load_network(config: &GuardianConfig) -> Result<psy_provider::provider::RpcProvider> {
    let network = &config.network;
    let configured = config.l1_chains.iter().map(|endpoint| endpoint.chain_index).collect::<BTreeSet<_>>();
    if configured.is_empty() || configured.len() != config.l1_chains.len() {
        return Err(GuardianSignError::AuthorizationMismatch);
    }
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
    let bridge_realm = BRIDGE_USER_ID.checked_div(network.users_per_realm).ok_or(GuardianSignError::AuthorizationMismatch)?;
    if realm_ids.is_empty() || realm_ids.iter().any(|id| *id >= realm_count) || !realm_ids.contains(&bridge_realm) {
        return Err(GuardianSignError::AuthorizationMismatch);
    }
    psy_provider::provider::RpcProvider::new_with_endpoint_clients(network, clients).map_err(|_| GuardianSignError::AuthorizationMismatch)
}

fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10)).timeout(Duration::from_secs(360)).build().map_err(|_| GuardianSignError::AuthorizationMismatch)
}

pub fn load_signing_key(config: &GuardianRuntimeConfig) -> Result<psy_provider::wallet::secp_wallet::Wallet> {
    let env_name = config.signing_key_password_env.as_str();
    if !matches!(env_name, "GUARDIAN_1_KEYSTORE_PASSWORD" | "GUARDIAN_2_KEYSTORE_PASSWORD" | "GUARDIAN_3_KEYSTORE_PASSWORD") {
        return Err(GuardianSignError::KeyUnavailable);
    }
    let password = Zeroizing::new(std::env::var(env_name).map_err(|_| GuardianSignError::KeyUnavailable)?);
    let (key_directory, key_relative) = split_protected(Path::new(&config.signing_key_secret_path))?;
    let mut file = protected_file(&key_directory, &key_relative)?;
    let before = file.metadata().map_err(|_| GuardianSignError::KeyUnavailable)?;
    let _encrypted = read_file(&mut file, 1024 * 1024)?;
    let fd_path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
    let key = psy_provider::wallet::secp_wallet::Wallet::load_encrypted_keystore(&fd_path, secret_text(password.as_bytes(), true)?).map_err(|_| GuardianSignError::KeyUnavailable)?;
    let after = file.metadata().map_err(|_| GuardianSignError::KeyUnavailable)?;
    if before.len() != after.len() || before.mtime() != after.mtime() || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime() || before.ctime_nsec() != after.ctime_nsec() { return Err(GuardianSignError::KeyUnavailable); }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_block_numbers_are_unsigned_and_never_default() {
        for value in [serde_json::json!(56), serde_json::json!("56"), serde_json::json!("0x38"), serde_json::json!("0X38")] {
            assert_eq!(deployment_block(&value).unwrap(), 56);
        }
        for value in [serde_json::json!(0), serde_json::json!("0"), serde_json::json!("0x0")] {
            assert_eq!(deployment_block(&value).unwrap(), 0);
        }
        assert_eq!(deployment_block(&serde_json::json!(u64::MAX)).unwrap(), u64::MAX);
        for value in [serde_json::Value::Null, serde_json::json!(-1), serde_json::json!(1.5), serde_json::json!(""), serde_json::json!("+1"), serde_json::json!(" 56"), serde_json::json!("0x"), serde_json::json!("0x10000000000000000"), serde_json::json!("18446744073709551616")] {
            assert!(deployment_block(&value).is_err(), "{value}");
        }
    }

    #[tokio::test]
    async fn local_summary_requires_matching_sibling_proxy_receipt() {
        const BRIDGE: &str = "0x0DCd1Bf9A1b36cE34237eEaFef220932846BCD82";
        let directory = std::env::temp_dir().join(format!("guardian-deployment-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("deployed-contracts.json");
        let proxy_path = directory.join("Bridge_Proxy.json");
        let summary = serde_json::json!({"network":"localhost", "chainId":"31337", "protocol":{"chain":{"l1ChainIndex":0,"l1ChainId":31337,"defaultRpcUrl":"http://127.0.0.1:8545"}}, "core":{"Bridge":BRIDGE}, "contracts":{"Bridge":BRIDGE.to_ascii_lowercase()}});
        std::fs::write(&path, serde_json::to_vec(&summary).unwrap()).unwrap();
        let paths = [path];
        assert!(chain_documents(&network(), &paths).await.unwrap_err().to_string().contains("Bridge_Proxy.json"));
        let mut proxy = serde_json::json!({"address":BRIDGE.to_ascii_lowercase(), "receipt":{"blockNumber":56,"contractAddress":BRIDGE}});
        for block in [serde_json::json!(56), serde_json::json!("56"), serde_json::json!("0x38"), serde_json::json!(0)] {
            proxy["receipt"]["blockNumber"] = block.clone();
            std::fs::write(&proxy_path, serde_json::to_vec(&proxy).unwrap()).unwrap();
            let documents = chain_documents(&network(), &paths).await.unwrap();
            let parsed = parse_chain_documents(&documents).unwrap();
            assert_eq!(parsed[0].deployment_block, deployment_block(&block).unwrap());
            assert_eq!(parsed[0].bridge, bridge_from(BRIDGE).unwrap());
        }
        proxy["receipt"].as_object_mut().unwrap().remove("blockNumber");
        std::fs::write(&proxy_path, serde_json::to_vec(&proxy).unwrap()).unwrap();
        assert!(chain_documents(&network(), &paths).await.unwrap_err().to_string().contains("receipt.blockNumber"));
        proxy["receipt"]["blockNumber"] = serde_json::json!(56);
        proxy["address"] = serde_json::json!("0x1111111111111111111111111111111111111111");
        std::fs::write(&proxy_path, serde_json::to_vec(&proxy).unwrap()).unwrap();
        assert!(chain_documents(&network(), &paths).await.is_err());
        let mut registry = chains().remove(0);
        registry["l1_chains"][0].as_object_mut().unwrap().remove("deployment_block");
        assert!(parse_chain_documents(&[(registry, None)]).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

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
    fn selected_network_requires_distinct_members_and_chain_identity() {
        let mut missing = network();
        missing.guardian_initial_member_hashes = None;
        assert!(loaded(missing, chains()).is_err());
        let mut same = network();
        same.guardian_initial_member_hashes.as_mut().unwrap()[1] = same.guardian_initial_member_hashes.unwrap()[0];
        assert!(loaded(same, chains()).is_err());
        let mut zero = network();
        zero.guardian_initial_member_hashes.as_mut().unwrap()[0] = Hash4::ZERO;
        assert!(loaded(zero, chains()).is_err());
        let config = loaded(network(), chains()).unwrap();
        assert_eq!(config.network.guardian_initial_member_hashes.unwrap()[0], Hash4::from_values(1, 0, 0, 0));
        assert_eq!(config.network_magic().unwrap(), 1);
        assert_eq!(config.l1_chains[0].chain_index, 7);
        assert_eq!(config.l1_chains[0].chain_id, U256::from(7u8));
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
            "guardian_initial_member_hashes": [
                Hash4::from_values(1, 0, 0, 0),
                Hash4::from_values(2, 0, 0, 0),
                Hash4::from_values(3, 0, 0, 0)
            ],

            "realm_configs": [], "p2p": {"checkpoints_per_epoch": 1}, "coordinator_configs": [{"id": 0, "rpc_url": ["http://coordinator/"]}],
            "prove_proxy_url": [], "faucet_rpc_url": [], "nostr_relay_url": "", "native_currency": "", "native_currency_decimal": 0,
            "native_currency_name": "", "fees": {"register_user_fee": 0, "deploy_contract_fee": 0, "guta_fee": 0, "da_fee": 0},
            "guardian_configs": [
                {"id": 3, "listen_address": "127.0.0.1:15443"},
                {"id": 1, "listen_address": "127.0.0.1:15441"},
                {"id": 2, "listen_address": "127.0.0.1:15442"}
            ],
            "guardian_history": {"listen_address": "127.0.0.1:15450"}
        })).unwrap()
    }
    fn chains() -> Vec<serde_json::Value> {
        vec![serde_json::json!({
            "l1_chains": [{"chain_index": 7, "chain_id": "7", "deployment_block": 56, "rpc_url": "https://chain.example/rpc", "contracts": {"Bridge": "0x1111111111111111111111111111111111111111"}}]
        })]
    }
    fn loaded(network: psy_config::NetworkConfigGoldilocks, documents: Vec<serde_json::Value>) -> Result<GuardianConfig> {
        let documents = documents.into_iter().map(|document| {
            let proxy = document.pointer("/core/Bridge").or_else(|| document.pointer("/contracts/Bridge")).map(|bridge| serde_json::json!({"address": bridge, "receipt": {"blockNumber": 56}}));
            (document, proxy)
        }).collect();
        GuardianConfig::from_network(network, Path::new("/guardians-root"), documents)
    }

    #[test]
    fn guardian_ids_are_exact_unique_and_order_independent() {
        let config = loaded(network(), chains()).unwrap();
        assert_eq!(config.endpoints, ["http://127.0.0.1:15441/", "http://127.0.0.1:15442/", "http://127.0.0.1:15443/"]);
        for id in [0, 1, 2, 4, 255] {
            let mut changed = network();
            changed.guardian_configs[0].id = id;
            assert!(loaded(changed, chains()).is_err());
        }
        let mut missing = network();
        missing.guardian_configs.pop();
        assert!(loaded(missing, chains()).is_err());
    }

    #[test]
    fn missing_public_configuration_never_falls_back() {
        let mut missing = network();
        missing.guardian_configs.clear();
        assert!(loaded(missing, chains()).is_err());
        let mut missing = network();
        missing.guardian_history = None;
        assert!(loaded(missing, chains()).is_err());
        assert!(loaded(network(), vec![serde_json::json!({"l1_chains": []})]).is_err());
        assert!(loaded(network(), vec![serde_json::json!({"l1_chains": [{"chain_index": 7, "rpc_url": "https://chain.example/rpc", "contracts": {"Bridge": "0x1111111111111111111111111111111111111111"}}]})]).is_err());
        assert!(loaded(network(), vec![serde_json::json!({"l1_chains": [{"chain_index": 7, "chain_id": "7", "rpc_url": "https://chain.example/rpc", "contracts": {}}]})]).is_err());
        assert!(loaded(network(), chains()).is_ok());
        assert!(loaded(network(), vec![serde_json::json!({"l1_chains": [{"chain_index": 7, "chain_id": "0", "rpc_url": "https://chain.example/rpc", "contracts": {"Bridge": "0x1111111111111111111111111111111111111111"}}]})]).is_err());
        assert!(loaded(network(), vec![serde_json::json!({"l1_chains": [{"chain_index": 7, "chain_id": "7", "rpc_url": "https://chain.example/rpc", "contracts": {"Bridge": "0x0000000000000000000000000000000000000000"}}]})]).is_err());
        let mut duplicate = chains();
        let repeated = duplicate[0]["l1_chains"][0].clone();
        duplicate[0]["l1_chains"].as_array_mut().unwrap().push(repeated);
        assert!(loaded(network(), duplicate).is_err());
        assert!(loaded(network(), vec![]).is_err());
        assert!(loaded(network(), vec![serde_json::json!({"unexpected": true})]).is_err());

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
        assert!(loaded(duplicate, chains()).is_err());
    }

    #[test]
    fn runtime_paths_derive_only_from_root_and_guardian_id() {
        let mut public = network();
        public.guardian_history.as_mut().unwrap().rpc_url = Some("http://127.0.0.1:15441/".into());
        let config = loaded(public, chains()).unwrap();
        for id in 1..=3 {
            let runtime = config.build_runtime_config(id).unwrap();
            assert_eq!(runtime.db_path, format!("/guardians-root/db/guardian-{id}.redb"));
            let key = guardian_keystore_path(id).unwrap();
            assert_eq!(key.file_name().unwrap(), format!("guardian-{id}.keystore.json").as_str());
            assert_eq!(key.parent().unwrap(), home::home_dir().unwrap().join(".psy/keystore"));
            assert_eq!(Path::new(&runtime.signing_key_secret_path), key);
            assert_eq!(runtime.signing_key_password_env, guardian_password_env(id).unwrap());
            assert!(!runtime.signing_key_password_env.contains('/') && !runtime.signing_key_password_env.ends_with(".password"));
            assert_eq!(runtime.history_urls.len(), 3);
        }
        for id in [0, 4, 255] {
            assert!(guardian_keystore_path(id).is_err());
            assert!(guardian_password_env(id).is_err());
        }
        for root in ["", "../root", "/root/../other"] { assert!(guardian_root_path(Path::new(root)).is_err()); }
        assert_eq!(guardian_root_path(Path::new("relative-root")).unwrap(), std::env::current_dir().unwrap().join("relative-root"));
    }


    #[tokio::test]
    async fn public_loader_selects_compiled_network_without_secret_file_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("guardian-public-config-{}-{}.json", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        let chains_path = std::env::temp_dir().join(format!("guardian-chains-{}-{}.json", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::write(&chains_path, serde_json::to_vec(&chains()[0]).unwrap()).unwrap();
        let mut networks = serde_json::Map::new();
        networks.insert(psy_config::CURRENT_NETWORK.into(), serde_json::to_value(network()).unwrap());
        let mut other = network();
        other.guardian_configs.clear();
        networks.insert("not-the-compiled-network".into(), serde_json::to_value(other).unwrap());
        let mut document = serde_json::json!({"defaultNetwork": "not-the-compiled-network", "networks": networks});
        std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let local = [chains_path.clone()];
        assert!(GuardianConfig::load(&path, Path::new("/guardians-root"), &local).await.is_ok());
        let selected_name = serde_json::to_string(psy_config::CURRENT_NETWORK).unwrap();
        let selected = serde_json::to_string(&network()).unwrap();
        let duplicate = format!("{{\n  \"defaultNetwork\": {selected_name},\n  \"networks\": {{ {selected_name}: {selected}, {selected_name}: {selected} }}\n}}");
        std::fs::write(&path, duplicate).unwrap();
        assert!(GuardianConfig::load(&path, Path::new("/guardians-root"), &local).await.unwrap_err().downcast_ref::<GuardianSignError>().is_some_and(|error| matches!(error, GuardianSignError::MalformedRequest)));
        std::fs::write(&path, serde_json::to_string_pretty(&document).unwrap()).unwrap();
        assert!(GuardianConfig::load(&path, Path::new("/guardians-root"), &local).await.is_ok());
        document["networks"].as_object_mut().unwrap().remove(psy_config::CURRENT_NETWORK);
        std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
        assert!(GuardianConfig::load(&path, Path::new("/guardians-root"), &local).await.is_err());
        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(chains_path).unwrap();
    }

    #[test]
    fn chain_documents_reject_empty_duplicates_and_conflicting_identities() {
        let config = loaded(network(), chains()).unwrap();
        let indexes = config.l1_chains.iter().map(|endpoint| endpoint.chain_index).collect::<BTreeSet<_>>();
        assert_eq!(indexes.len(), config.l1_chains.len());
        assert!(loaded(network(), vec![serde_json::json!({"l1_chains": []})]).is_err());
        let mut duplicate = chains();
        let repeated = duplicate[0]["l1_chains"][0].clone();
        duplicate[0]["l1_chains"].as_array_mut().unwrap().push(repeated);
        assert!(loaded(network(), duplicate).is_err());
        let deployment = serde_json::json!({"network": "localhost", "chainId": "7", "protocol": {"chain": {"l1ChainIndex": 7, "l1ChainId": 7, "defaultRpcUrl": "https://chain.example/rpc"}}, "core": {"Bridge": "0x1111111111111111111111111111111111111111"}, "contracts": {"Bridge": "0x1111111111111111111111111111111111111111"}});
        assert_eq!(loaded(network(), vec![deployment.clone()]).unwrap().l1_chains, config.l1_chains);
        assert!(loaded(network(), vec![chains()[0].clone(), deployment.clone()]).is_err());
        let mut conflicting = deployment.clone();
        conflicting["contracts"]["Bridge"] = serde_json::json!("0x2222222222222222222222222222222222222222");
        assert!(loaded(network(), vec![conflicting]).is_err());
        // Public Hardhat Bridge: EIP-55 in core, lowercase in contracts, same 20 bytes.
        const PUBLIC_BRIDGE: &str = "0x0DCd1Bf9A1b36cE34237eEaFef220932846BCD82";
        let mixed = serde_json::json!({"network": "localhost", "chainId": "7", "protocol": {"chain": {"l1ChainIndex": 7, "l1ChainId": 7, "defaultRpcUrl": "https://chain.example/rpc"}}, "core": {"Bridge": PUBLIC_BRIDGE}, "contracts": {"Bridge": PUBLIC_BRIDGE.to_ascii_lowercase()}});
        let accepted = loaded(network(), vec![mixed]).unwrap();
        assert_eq!(accepted.l1_chains[0].bridge.0, psy_config::parse_bridge_address(PUBLIC_BRIDGE).unwrap());
        assert_eq!(accepted.l1_chains[0].bridge.0, psy_config::parse_bridge_address(&PUBLIC_BRIDGE.to_ascii_lowercase()).unwrap());
        let different = serde_json::json!({"network": "localhost", "chainId": "7", "protocol": {"chain": {"l1ChainIndex": 7, "l1ChainId": 7, "defaultRpcUrl": "https://chain.example/rpc"}}, "core": {"Bridge": PUBLIC_BRIDGE}, "contracts": {"Bridge": "0x1111111111111111111111111111111111111111"}});
        assert!(loaded(network(), vec![different]).is_err());
        let unknown = serde_json::json!({"network": "not-a-known-source", "chainId": "9", "protocol": {"chain": {"l1ChainIndex": 9, "l1ChainId": 9, "defaultRpcUrl": "https://unknown.example/rpc"}}, "unexpected": {"Bridge": PUBLIC_BRIDGE}});
        assert!(loaded(network(), vec![unknown]).is_err());
        let second = serde_json::json!({"network": "localhostBsc", "chainId": "8", "protocol": {"chain": {"l1ChainIndex": 8, "l1ChainId": 8, "defaultRpcUrl": "https://chain2.example/rpc"}}, "core": {"Bridge": "0x2222222222222222222222222222222222222222"}});
        assert_eq!(loaded(network(), vec![deployment, second.clone()]).unwrap().l1_chains.len(), 2);
        assert!(loaded(network(), vec![second.clone(), second]).is_err());
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
        let mut config = loaded(network(), chains()).unwrap();
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
