use std::{collections::{BTreeMap, BTreeSet, HashMap}, ffi::CString, fs::File, io::{BufReader, Read}, os::{fd::{AsRawFd, FromRawFd}, unix::fs::MetadataExt}, path::{Component, Path, PathBuf}, sync::Arc, time::{Duration, SystemTime, UNIX_EPOCH}};

use serde::{Deserialize, Serialize};
use tokio_rustls::rustls::{self, client::{danger::{ServerCertVerified, ServerCertVerifier, HandshakeSignatureValid}, WebPkiServerVerifier}, pki_types::{CertificateDer, ServerName, UnixTime}, RootCertStore};
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
    pub fn load(directory: &Path, config: &GuardianRuntimeConfig, proof_bound: u32) -> Result<Self> {
        let bytes = read_protected_file(directory, Path::new(&config.authorization_index_path), MAX_BODY_BYTES)?;
        let index = GuardianAuthorizationIndex::parse(&bytes)?;
        let mut entries = BTreeMap::new();
        for version in &index.versions {
            let path = index.archive_file(Path::new(&config.authorization_archive_path), version.version)?;
            let bytes = read_protected_file(directory, &path, MAX_BODY_BYTES)?;
            let authorization = index.resolve(version.version, &bytes)?;
            authorization.validate(psy_config::GUTA_FEE, psy_config::DA_FEE, proof_bound)?;
            entries.insert(version.version, (authorization, bytes.to_vec()));
        }
        let archive = Self { index, entries };
        config.validate(&archive.active().0, &archive.index)?;
        Ok(archive)
    }
    pub fn active(&self) -> &(GuardianAuthorization, Vec<u8>) {
        &self.entries[&self.index.active_version]
    }
    pub fn resolve(&self, version: u32) -> Result<&(GuardianAuthorization, Vec<u8>)> {
        self.entries.get(&version).ok_or(GuardianSignError::HistoryUnavailable)
    }
    pub fn authorizations(&self) -> Vec<GuardianAuthorization> {
        self.entries.values().map(|entry| entry.0.clone()).collect()
    }
}

pub struct SigningAuthorizationFile {
    directory: PathBuf,
    config: GuardianRuntimeConfig,
    bytes: Zeroizing<Vec<u8>>,
    db_device: u64,
    db_inode: u64,
    public_key: Hex33,
    last_time: u64,
}
impl SigningAuthorizationFile {
    pub fn load(directory: &Path, config: &GuardianRuntimeConfig, public_key: Hex33, db_file: &File) -> Result<Self> {
        let bytes = read_protected_file(directory, Path::new(&config.signing_authorization_path), MAX_BODY_BYTES)?;
        let metadata = db_file.metadata().map_err(|_| GuardianSignError::KeyUnavailable)?;
        Ok(Self { directory: directory.to_path_buf(), config: config.clone(), bytes, db_device: metadata.dev(), db_inode: metadata.ino(), public_key, last_time: 0 })
    }
    pub fn check(&mut self, authorization: &GuardianAuthorization) -> Result<()> {
        let bytes = read_protected_file(&self.directory, Path::new(&self.config.signing_authorization_path), MAX_BODY_BYTES)?;
        if *bytes != *self.bytes { return Err(GuardianSignError::AccountHalted); }
        let approval: SigningAuthorization = parse_canonical_json(&bytes).map_err(|_| GuardianSignError::KeyUnavailable)?;
        if approval.revoked || !approval.exclusive_key_use || !approval.complete_journal { return Err(GuardianSignError::AccountHalted); }
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| GuardianSignError::KeyUnavailable)?.as_secs();
        approval.validate(authorization, &self.config, self.public_key, now)?;
        if now < self.last_time {
            return Err(GuardianSignError::KeyUnavailable);
        }
        self.last_time = now;
        let file = protected_file(&self.directory, Path::new(&self.config.db_path))?;
        let metadata = file.metadata().map_err(|_| GuardianSignError::KeyUnavailable)?;
        if metadata.dev() != self.db_device || metadata.ino() != self.db_inode { return Err(GuardianSignError::KeyUnavailable); }
        Ok(())
    }
}

pub fn load_signing_key(directory: &Path, config: &GuardianRuntimeConfig) -> Result<psy_provider::wallet::secp_wallet::Wallet> {
    let password = read_protected_file(directory, Path::new(&config.signing_key_password_secret_path), 4096)?;
    let mut file = protected_file(directory, Path::new(&config.signing_key_secret_path))?;
    let before = file.metadata().map_err(|_| GuardianSignError::KeyUnavailable)?;
    let _encrypted = read_file(&mut file, 1024 * 1024)?;
    let fd_path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
    let key = psy_provider::wallet::secp_wallet::Wallet::load_encrypted_keystore(&fd_path, secret_text(&password, true)?)
        .map_err(|_| GuardianSignError::KeyUnavailable)?;
    let after = file.metadata().map_err(|_| GuardianSignError::KeyUnavailable)?;
    if before.len() != after.len() || before.mtime() != after.mtime() || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime() || before.ctime_nsec() != after.ctime_nsec() { return Err(GuardianSignError::KeyUnavailable); }
    Ok(key)
}


#[derive(Debug)]
struct PinnedCertificate {
    verifier: Arc<WebPkiServerVerifier>,
    pin: Hex32,
}
impl ServerCertVerifier for PinnedCertificate {
    fn verify_server_cert(&self, certificate: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], name: &ServerName<'_>, ocsp: &[u8], now: UnixTime) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let verified = self.verifier.verify_server_cert(certificate, intermediates, name, ocsp, now)?;
        if sha256(certificate.as_ref()) != self.pin {
            return Err(rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure));
        }
        Ok(verified)
    }
    fn verify_tls12_signature(&self, message: &[u8], certificate: &CertificateDer<'_>, signature: &rustls::DigitallySignedStruct) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.verifier.verify_tls12_signature(message, certificate, signature)
    }
    fn verify_tls13_signature(&self, message: &[u8], certificate: &CertificateDer<'_>, signature: &rustls::DigitallySignedStruct) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.verifier.verify_tls13_signature(message, certificate, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> { self.verifier.supported_verify_schemes() }
}

fn endpoint_client(pin: Option<Hex32>, ca: &[u8]) -> Result<reqwest::Client> {
    let builder = reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10)).timeout(Duration::from_secs(30));
    let builder = if let Some(pin) = pin {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        for certificate in rustls_pemfile::certs(&mut BufReader::new(ca)) {
            roots.add(certificate.map_err(|_| GuardianSignError::AuthorizationMismatch)?)
                .map_err(|_| GuardianSignError::AuthorizationMismatch)?;
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build().map_err(|_| GuardianSignError::AuthorizationMismatch)?;
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions().map_err(|_| GuardianSignError::AuthorizationMismatch)?
            .dangerous().with_custom_certificate_verifier(Arc::new(PinnedCertificate { verifier, pin }))
            .with_no_client_auth();
        builder.use_preconfigured_tls(config)
    } else { builder };
    builder.build().map_err(|_| GuardianSignError::AuthorizationMismatch)
}

pub fn load_network(directory: &Path, runtime: &GuardianRuntimeConfig, authorization: &GuardianAuthorization) -> Result<(psy_config::NetworkConfigGoldilocks, psy_provider::provider::RpcProvider)> {
    let bytes = read_protected_file(directory, Path::new(&runtime.rpc_config_path), MAX_BODY_BYTES)?;
    let config: psy_config::NetworkConfigGoldilocks = parse_canonical_json(&bytes)?;
    let magic = match config.magic.strip_prefix("0x").or_else(|| config.magic.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => config.magic.parse::<u64>().ok(),
    };
    if magic != Some(authorization.network_magic) || authorization.network_magic != psy_config::PSY_NETWORK_MAGIC
        || config.users_per_realm != psy_config::USERS_PER_REALM || config.global_user_tree_height != psy_config::GLOBAL_USER_TREE_HEIGHT
        || config.realm_user_tree_height != psy_config::REALM_USER_TREE_HEIGHT || config.group_realm_height != psy_config::GROUP_REALM_HEIGHT
        || config.fees.guta_fee != psy_config::GUTA_FEE || config.fees.da_fee != psy_config::DA_FEE || !config.prove_proxy_url.is_empty()
        || config.coordinator_configs.first().and_then(|entry| entry.rpc_url.first()) != Some(&runtime.l2_rpc_url)
        || config.coordinator_configs.first().map(|entry| entry.id) != Some(0) {
        return Err(GuardianSignError::AuthorizationMismatch);
    }
    let mut routes = BTreeSet::new();
    let mut realm_ids = BTreeSet::new();
    let mut coordinator_ids = BTreeSet::new();
    for entry in &config.coordinator_configs {
        if !coordinator_ids.insert(entry.id) || entry.rpc_url.is_empty() { return Err(GuardianSignError::AuthorizationMismatch); }
        for url in &entry.rpc_url { if !routes.insert((0u8, entry.id, url.clone())) { return Err(GuardianSignError::AuthorizationMismatch); } }
    }
    for entry in &config.realm_configs {
        if !realm_ids.insert(entry.id) || entry.rpc_url.is_empty() { return Err(GuardianSignError::AuthorizationMismatch); }
        for url in &entry.rpc_url { if !routes.insert((1u8, entry.id, url.clone())) { return Err(GuardianSignError::AuthorizationMismatch); } }
    }
    let realm_count = 1u64.checked_shl(u32::from(psy_config::COORDINATOR_USER_TREE_HEIGHT)).ok_or(GuardianSignError::AuthorizationMismatch)?;
    if realm_ids.is_empty() || realm_ids.iter().any(|id| *id >= realm_count)
        || !realm_ids.contains(&(authorization.user_id / config.users_per_realm)) { return Err(GuardianSignError::AuthorizationMismatch); }
    let ca = read_protected_file(directory, Path::new(&runtime.client_ca_path), MAX_BODY_BYTES)?;
    let mut clients = HashMap::new();
    let mut url_pins = HashMap::new();
    for pin in &runtime.l2_rpc_endpoint_pins {
        pin.validate()?;
        if !routes.remove(&(pin.role as u8, pin.config_id, pin.rpc_url.clone())) { return Err(GuardianSignError::AuthorizationMismatch); }
        if let Some(previous) = url_pins.insert(pin.rpc_url.clone(), pin.tls_certificate_sha256) {
            if previous != pin.tls_certificate_sha256 { return Err(GuardianSignError::AuthorizationMismatch); }
        }
        if !clients.contains_key(&pin.rpc_url) {
            clients.insert(pin.rpc_url.clone(), Arc::new(endpoint_client(pin.tls_certificate_sha256, &ca)?));
        }
    }
    if !routes.is_empty() { return Err(GuardianSignError::AuthorizationMismatch); }
    let provider = psy_provider::provider::RpcProvider::new_with_endpoint_clients(&config, clients)
        .map_err(|_| GuardianSignError::AuthorizationMismatch)?;
    Ok((config, provider))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires QA HTTPS fixture GUARDIAN_TLS_TEST_URL, CA_PEM and LEAF_DER paths"]
    async fn pinned_client_accepts_approved_leaf_and_rejects_wrong_leaf() {
        let url = std::env::var("GUARDIAN_TLS_TEST_URL").expect("QA HTTPS endpoint");
        assert!(url.starts_with("https://"));
        let ca = std::fs::read(std::env::var_os("GUARDIAN_TLS_TEST_CA_PEM").expect("QA CA certificate")).unwrap();
        let leaf = std::fs::read(std::env::var_os("GUARDIAN_TLS_TEST_LEAF_DER").expect("QA leaf certificate")).unwrap();
        let pin = sha256(&leaf);
        let approved = endpoint_client(Some(pin), &ca).unwrap();
        assert!(approved.get(&url).send().await.is_ok());
        let mut wrong = pin;
        wrong.0[0] ^= 1;
        assert!(endpoint_client(Some(wrong), &ca).unwrap().get(&url).send().await.is_err());
    }

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
    #[test]
    #[ignore = "requires operator-owned 0700 GUARDIAN_RUNTIME_TEST_DIRECTORY and QA approval"]
    fn signing_authorization_allows_db_writes_but_rejects_replacement_and_revocation() {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let directory = PathBuf::from(std::env::var_os("GUARDIAN_RUNTIME_TEST_DIRECTORY").expect("explicit disposable test directory"));
        let name = format!("guardian-signing-authorization-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos());
        let db_path = format!("{name}.redb"); let approval_path = format!("{name}.json"); let retained_path = format!("{name}.retained");
        let config = GuardianRuntimeConfig {
            authorization_path: "archive/1.json".into(), authorization_archive_path: "archive".into(), authorization_index_path: "index.json".into(),
            rpc_config_path: "rpc.json".into(), listen_address: "127.0.0.1:9000".into(), tls_certificate_path: "tls.crt".into(),
            tls_private_key_path: "tls.key".into(), client_ca_path: "ca.crt".into(), allowed_client_certificate_sha256: vec![Hex([1; 32])],
            db_path: db_path.clone(), signing_key_secret_path: "key.json".into(), signing_key_password_secret_path: "password".into(), signing_authorization_path: approval_path.clone(),
            l2_rpc_url: "http://127.0.0.1:9001/".into(), l2_rpc_endpoint_pins: vec![], l1_rpc_urls: vec![], history_urls: vec![],
        };
        let account = psy_vm::ups::multisig::MultisigAccount { contract_id: 6, initial_policy: psy_vm::ups::multisig::MultisigPolicy {
            version: 1, threshold: 2, member_count: 3, member_hashes: [Hash4::ZERO; 8],
        } };
        let authorization = GuardianAuthorization {
            version: 1, network_magic: 90101, genesis_hash: Hex([1; 32]), user_id: BRIDGE_USER_ID,
            account_json: JsonText::from_value(&account).unwrap(), account_public_key: Hash4::ZERO, multisig_fingerprint: Hash4::ZERO,
            deposit_contract_id: 2, withdrawal_contract_id: 3, fee_contract_id: 0, guta_fee: 1, da_fee: 1, max_fee: 100,
            max_endcap_proof_bytes: 1024, approved_contracts: vec![], chains: vec![],
        };
        let public_key = Hex([2; 33]);
        let mut approval = SigningAuthorization { network_magic: 90101, user_id: BRIDGE_USER_ID, public_key, db_path: db_path.clone(),
            not_before_unix: 0, expires_at_unix: u64::MAX, exclusive_key_use: true, complete_journal: true, revoked: false };
        let mut approval_file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(directory.join(&approval_path)).unwrap();
        approval_file.write_all(&serde_json::to_vec(&approval).unwrap()).unwrap();
        let (mut file, parent) = create_db_file(&directory, Path::new(&db_path)).unwrap();
        parent.sync_all().unwrap();
        let mut signing_authorization_file = SigningAuthorizationFile::load(&directory, &config, public_key, &file).unwrap();
        assert_eq!(signing_authorization_file.check(&authorization), Ok(()));
        file.write_all(b"durable database changes").unwrap(); file.sync_all().unwrap();
        assert_eq!(signing_authorization_file.check(&authorization), Ok(()));
        std::fs::rename(directory.join(&db_path), directory.join(&retained_path)).unwrap();
        assert_eq!(signing_authorization_file.check(&authorization), Err(GuardianSignError::KeyUnavailable));
        let (replacement, _) = create_db_file(&directory, Path::new(&db_path)).unwrap();
        assert_eq!(signing_authorization_file.check(&authorization), Err(GuardianSignError::KeyUnavailable));
        drop(replacement); std::fs::remove_file(directory.join(&db_path)).unwrap();
        std::fs::rename(directory.join(&retained_path), directory.join(&db_path)).unwrap();
        approval.revoked = true;
        std::fs::write(directory.join(&approval_path), serde_json::to_vec(&approval).unwrap()).unwrap();
        assert_eq!(signing_authorization_file.check(&authorization), Err(GuardianSignError::AccountHalted));
        drop(file); drop(approval_file);
        std::fs::remove_file(directory.join(db_path)).unwrap(); std::fs::remove_file(directory.join(approval_path)).unwrap();
    }

    #[test]
    fn password_grammar_never_trims_or_accepts_line_separators() {
        for bytes in [b"".as_slice(), b"secret\n", b"secret\r", b"secret\0", b"\xef\xbb\xbfsecret", b"\xff"] {
            assert!(secret_text(bytes, true).is_err());
        }
        assert_eq!(secret_text(b" secret ", true).unwrap(), " secret ");
    }
}
