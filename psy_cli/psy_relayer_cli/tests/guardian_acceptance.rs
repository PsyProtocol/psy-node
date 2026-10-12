//! Real guardian acceptance; execution PENDING the independent reviewer/QA gate.
//!
//! Explicit invocation (missing fixture is an error, never a successful skip):
//! GUARDIAN_ACCEPTANCE_FIXTURE=/protected/disposable-fixture cargo test -p
//! psy_relayer_cli --test guardian_acceptance -- --ignored --exact guardian_acceptance
//!
//! Provision a disposable network, real Plonky2 artifacts, L1 custody, and indexed
//! withdrawals beforehand. The three guardian database paths must be absent; this
//! driver creates each one once with `guardian-create-db` and never opens PostgreSQL.
//! User 524288 must have the public-only initialized Genesis policy, account nonce
//! zero, and positive fee balance. No other process may submit for this account.
//! This driver neither provisions nor purges the network, starts node services, nor
//! touches existing devnet services. Guardian/history listener ports must be unused.
//!
//! GUARDIAN_ACCEPTANCE_FIXTURE names an absolute, euid-owned 0700 directory with
//! protected ancestors (not /tmp). Its 0600 manifest.json contains:
//! - disposable: true; network_magic: integer
//! - relayer_rpc_config, relayer_guardian_config, relayer_daemon_config,
//!   relayer_archive, next_members: fixture-relative paths
//! - guardians, db_files: three fixture-relative paths each
//! - guardian_listen_addresses: three numeric loopback socket addresses
//! - relayer_history_listen_address: numeric loopback socket address
//! - timeouts: optional service_ready_secs (120), session_secs (600)
//!
//! Configured files are 0600 and directories 0700, with no symlinks or traversal.
//! Each `db_files` entry must be absent; its parent directory must already exist
//! and be protected. Archive is an empty 0700 directory. Guardian runtime config
//! `db_path`, joined to that config's parent, must equal the matching `db_files`
//! entry. Guardian/runtime paths, authorization archives, encrypted keys/passwords,
//! signing authorizations, TLS pins, and RPC configurations must satisfy production
//! protected-file checks. Runtime history_urls must include the relayer and peer
//! guardian origins, so retained history remains available between one-shot CLI
//! commands. next_members holds canonical [Hash4;3] JSON changing at least one
//! initial member. Rotation is LAST; no replacement signing key is needed after
//! it. The daemon must use these same RPC/guardian configs, fixture-local
//! proof/output paths, a bounded scan containing at least one genuine unconsumed
//! withdrawal, and no subsequent incoming work. Configure no automatic external
//! claim/provisioning operation.
//!
//! Source mapping: main.rs GuardianService/GuardianPolicy/GuardianCreateDb;
//! bridge/daemon.rs submit_guardian_operation, recover_guardian_inclusion;
//! bridge/guardian_client.rs RelayerArchive and the existing mTLS client;
//! guardian/db.rs guardian_signed and guardian_session.
//! ProposeWithdrawals only discovers work and is deliberately NOT used here.
//!
//! The database is exclusively owned. Readiness uses the existing mutually
//! authenticated signing and session endpoints. Durable rows are decoded only
//! after the owning service is stopped and reaped, through a normal read/write
//! descriptor and a read transaction. The reader is dropped before that owner
//! restarts. Engine recovery may rewrite metadata; this driver writes no rows.
//!
//! Flow: create three databases -> authenticate initialized nonce-zero Genesis
//! -> C and B offline, A-only durable decision -> kill/restart daemon with B
//! restored -> real bridge inclusion -> lost receipt using the ORIGINAL pending
//! inode -> exact archive recovery -> C imports with no invented decision ->
//! B offline, A+C authorize final policy rotation. Bridge is ordinary nonce1;
//! rotation is nonce2. There is no bootstrap command for this initialized
//! fixture. Genuine empty-account bootstrap remains covered by its separate
//! core/empty-fixture acceptance; bootstrap constraints are unchanged. Child
//! output is fully redacted (discarded), not heuristically scrubbed. Failed
//! assertions print labels only, never config, traces, rows, or proof bytes.
//! Durable acceptance evidence, including the created database files, is
//! retained; only children created here and the driver's pending hard link are
//! cleaned up. No fixture purge on success/failure.

use std::{fs, net::SocketAddr, os::unix::fs::{MetadataExt, OpenOptionsExt}, path::{Component, Path, PathBuf}, process::Stdio, time::Duration};

use anyhow::{ensure, Context};
use bincode::Options;
use plonky2::field::{goldilocks_field::GoldilocksField, types::PrimeField64};
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::{config::store_config::PsyHasher, traits::qdatastore::{qmetadata::QMetaDataStoreReaderSync, qtreedata::QTreeDataStoreReaderSync}};
use psy_crypto::hash::traits::qhashable::QFieldHashable;
use psy_provider::provider::RpcProvider;
use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle};
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::{net::TcpStream, process::{Child, Command}, time::{sleep, timeout, Instant}};

#[path = "../src/guardian/protocol.rs"]
mod protocol;

use protocol::{parse_canonical_json, GuardianAccount, GuardianAccountState, GuardianSession, GuardianSessionsResponse, GuardianSignRequest, GuardianSignResponse, GuardianSigned, BRIDGE_USER_ID, MAX_BODY_BYTES};

const CLI: &str = env!("CARGO_BIN_EXE_psy_relayer_cli");
const USER: u64 = BRIDGE_USER_ID;
const SIGNER: TableDefinition<'_, (), [u8; 33]> = TableDefinition::new("guardian_signer");
const ACCOUNT: TableDefinition<'_, (u64, u64), &[u8]> = TableDefinition::new("guardian_account");
const SIGNED: TableDefinition<'_, (u64, u64, u64), &[u8]> = TableDefinition::new("guardian_signed");
const SESSION: TableDefinition<'_, (u64, u64, u64), &[u8]> = TableDefinition::new("guardian_session");

fn read(path: &Path) -> anyhow::Result<Vec<u8>> {
    fs::read(path).map_err(|_| anyhow::anyhow!("fixture/archive read failed (details redacted)"))
}

fn json(bytes: &[u8]) -> anyhow::Result<Value> {
    serde_json::from_slice(bytes).map_err(|_| anyhow::anyhow!("invalid fixture/archive JSON (details redacted)"))
}

fn protected(path: &Path, directory: bool) -> anyhow::Result<()> {
    let meta = fs::symlink_metadata(path).map_err(|_| anyhow::anyhow!("missing protected fixture entry"))?;
    let uid = unsafe { libc::geteuid() };
    ensure!(meta.uid() == uid && !meta.file_type().is_symlink(), "fixture ownership/symlink violation");
    ensure!(if directory { meta.is_dir() && meta.mode() & 0o7777 == 0o700 } else { meta.is_file() && meta.mode() & 0o7777 == 0o600 }, "fixture mode/type violation");
    for ancestor in path.parent().into_iter().flat_map(Path::ancestors) {
        let meta = fs::symlink_metadata(ancestor).map_err(|_| anyhow::anyhow!("fixture ancestor unavailable"))?;
        ensure!(meta.is_dir() && (meta.uid() == uid || meta.uid() == 0) && meta.mode() & 0o022 == 0, "unprotected fixture ancestor");
    }
    Ok(())
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> anyhow::Result<T> {
    bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes().deserialize(bytes).map_err(|_| anyhow::anyhow!("durable row decode failed (details redacted)"))
}

struct Journal {
    signed: Vec<GuardianSigned>,
    sessions: Vec<GuardianSession>,
    account: GuardianAccount,
}

impl Journal {
    fn read(path: &Path, network: u64, nonces: &[u64]) -> anyhow::Result<Self> {
        protected(path, false)?;
        let file = fs::OpenOptions::new().read(true).write(true).custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW).open(path).map_err(|_| anyhow::anyhow!("database open failed (details redacted)"))?;
        ensure!(file.metadata().map_err(|_| anyhow::anyhow!("database metadata unavailable"))?.len() > 0, "database file is empty");
        let mut magic = [0; 9];
        std::io::Read::read_exact(&mut &file, &mut magic).map_err(|_| anyhow::anyhow!("database header unavailable"))?;
        ensure!(magic == [b'r', b'e', b'd', b'b', 0x1A, 0x0A, 0xA9, 0x0D, 0x0A], "database is not a redb file");
        let db = Database::builder().create_file(file).map_err(|_| anyhow::anyhow!("database open failed (details redacted)"))?;
        let txn = db.begin_read().map_err(|_| anyhow::anyhow!("database read failed (details redacted)"))?;
        let mut names = txn.list_tables().map_err(|_| anyhow::anyhow!("database tables unavailable"))?.map(|table| table.name().to_owned()).collect::<Vec<_>>();
        names.sort();
        ensure!(names == ["guardian_account", "guardian_session", "guardian_signed", "guardian_signer"], "database table set mismatch");
        ensure!(txn.list_multimap_tables().map_err(|_| anyhow::anyhow!("database tables unavailable"))?.next().is_none(), "database contains a multimap table");
        let (account, signed, retained_sessions) = {
            let signer = txn.open_table(SIGNER).map_err(|_| anyhow::anyhow!("signer table unavailable"))?;
            let accounts = txn.open_table(ACCOUNT).map_err(|_| anyhow::anyhow!("account table unavailable"))?;
            let signed_table = txn.open_table(SIGNED).map_err(|_| anyhow::anyhow!("decision table unavailable"))?;
            let sessions = txn.open_table(SESSION).map_err(|_| anyhow::anyhow!("session table unavailable"))?;
            let signer_count = signer.len().map_err(|_| anyhow::anyhow!("signer count unavailable"))?;
            let signer_key = signer.get(()).map_err(|_| anyhow::anyhow!("signer row unavailable"))?.map(|row| row.value());
            ensure!(signer_count == 1 && signer_key.is_some_and(|key| matches!(key[0], 2 | 3)), "immutable signer missing");
            let account_bytes = accounts.get((network, USER)).map_err(|_| anyhow::anyhow!("account row unavailable"))?.map(|row| row.value().to_vec());
            let account = decode::<GuardianAccount>(account_bytes.as_deref().context("fixture account missing")?)?;
            account.validate().map_err(|_| anyhow::anyhow!("account row rejected"))?;
            ensure!(account.network_magic == network && account.user_id == USER, "account key differs from encoded identity");
            let mut signed = Vec::new();
            let mut retained_sessions = Vec::new();
            for nonce in nonces {
                let key = (network, USER, *nonce);
                if let Some(bytes) = signed_table.get(key).map_err(|_| anyhow::anyhow!("decision row unavailable"))?.map(|row| row.value().to_vec()) {
                    let decoded = decode::<GuardianSigned>(&bytes)?;
                    decoded.validate().map_err(|_| anyhow::anyhow!("decision row rejected"))?;
                    ensure!((decoded.network_magic, decoded.user_id, decoded.nonce) == key, "decision key differs from encoded identity");
                    signed.push(decoded);
                }
                if let Some(bytes) = sessions.get(key).map_err(|_| anyhow::anyhow!("session row unavailable"))?.map(|row| row.value().to_vec()) {
                    let decoded = decode::<GuardianSession>(&bytes)?;
                    ensure!((decoded.network_magic, decoded.user_id, decoded.nonce) == key, "session key differs from encoded identity");
                    ensure!(decoded.record.request_json.decode().map_err(|_| anyhow::anyhow!("session request rejected"))?.session_nonce == decoded.nonce, "session request nonce mismatch");
                    retained_sessions.push(decoded);
                }
            }
            (account, signed, retained_sessions)
        };
        drop(txn);
        drop(db);
        Ok(Self { signed, sessions: retained_sessions, account })
    }

    fn signed(&self, nonce: u64) -> anyhow::Result<Vec<&GuardianSigned>> {
        Ok(self.signed.iter().filter(|row| row.nonce == nonce).collect())
    }
}

struct Fixture {
    root: PathBuf,
    manifest: Value,
    archive: PathBuf,
    ready: Duration,
    session: Duration,
}

impl Fixture {
    fn load() -> anyhow::Result<Self> {
        let root = PathBuf::from(std::env::var_os("GUARDIAN_ACCEPTANCE_FIXTURE").context("GUARDIAN_ACCEPTANCE_FIXTURE is required; provision the disposable fixture documented in this test")?);
        ensure!(root.is_absolute(), "fixture must be absolute");
        protected(&root, true)?;
        protected(&root.join("manifest.json"), false)?;
        let manifest = json(&read(&root.join("manifest.json"))?)?;
        ensure!(manifest["disposable"] == true, "fixture must explicitly declare disposable=true");
        ensure!(manifest.get("journal_database_files").is_none(), "PostgreSQL journal files are not part of this fixture");
        let mut fixture = Self { root, manifest, archive: PathBuf::new(), ready: Duration::from_secs(120), session: Duration::from_secs(600) };
        fixture.archive = fixture.path("relayer_archive")?;
        protected(&fixture.archive, true)?;
        ensure!(fs::read_dir(&fixture.archive).map_err(|_| anyhow::anyhow!("archive unavailable"))?.next().is_none(), "archive must be empty; never reuse/purge an existing fixture");
        for (key, limit) in [("service_ready_secs", &mut fixture.ready), ("session_secs", &mut fixture.session)] {
            if let Some(seconds) = fixture.manifest["timeouts"][key].as_u64() {
                ensure!((1..=7200).contains(&seconds), "fixture timeout outside 1..7200 seconds");
                *limit = Duration::from_secs(seconds);
            }
        }
        ensure!(fixture.manifest["network_magic"].as_u64().is_some_and(|n| n > 0 && n < 0xffff_ffff_0000_0001), "invalid network magic");
        for key in ["guardians", "db_files", "guardian_listen_addresses"] {
            ensure!(fixture.manifest[key].as_array().is_some_and(|v| v.len() == 3), "fixture requires exactly three guardians/databases/listeners");
        }
        let mut databases = Vec::new();
        for index in 0..3 {
            let path = fixture.item("db_files", index)?;
            ensure!(fs::symlink_metadata(&path).is_err(), "database path already exists; never replace retained evidence");
            protected(path.parent().context("database parent missing")?, true)?;
            databases.push(path);
        }
        ensure!(databases.windows(2).all(|pair| pair[0] != pair[1]) && databases[0] != databases[2], "database paths must be distinct");
        for key in ["relayer_rpc_config", "relayer_guardian_config", "relayer_daemon_config", "next_members"] {
            protected(&fixture.path(key)?, false)?;
        }
        let client_path = fixture.path("relayer_guardian_config")?;
        let client = json(&read(&client_path)?)?;
        ensure!(client_path.parent().context("client config parent missing")?.join(client["archive_path"].as_str().context("client archive missing")?) == fixture.archive, "manifest/client archive mismatch");
        ensure!(client["listen_address"] == fixture.manifest["relayer_history_listen_address"], "manifest/client history listener mismatch");
        ensure!(client["endpoints"].as_array().is_some_and(|v| v.len() == 3), "client requires three guardian endpoints");
        ensure!(client["tls_identity_path"].as_str().is_some() && client["server_ca_path"].as_str().is_some(), "client TLS identity/CA missing");
        let daemon_bytes = read(&fixture.path("relayer_daemon_config")?)?;
        let daemon: toml::Value = toml::from_str(std::str::from_utf8(&daemon_bytes).map_err(|_| anyhow::anyhow!("daemon config not UTF-8"))?).map_err(|_| anyhow::anyhow!("invalid daemon TOML"))?;
        for (key, manifest_key) in [("guardian_config", "relayer_guardian_config"), ("rpc_config", "relayer_rpc_config")] {
            let configured = fixture.root.join(daemon[key].as_str().context("daemon config path missing")?);
            ensure!(configured == fixture.path(manifest_key)?, "daemon/manifest config mismatch");
        }
        for index in 0..3 {
            let path = fixture.item("guardians", index)?;
            protected(&path, false)?;
            let config = json(&read(&path)?)?;
            ensure!(config.get("postgres_connection_secret_path").is_none(), "guardian config still names a PostgreSQL secret");
            ensure!(config["listen_address"] == fixture.manifest["guardian_listen_addresses"][index], "guardian listener mismatch");
            ensure!(path.parent().context("runtime config parent missing")?.join(config["db_path"].as_str().context("database path missing")?) == databases[index], "guardian database mismatch");
        }
        Ok(fixture)
    }

    fn relative(&self, value: &Value) -> anyhow::Result<PathBuf> {
        let path = Path::new(value.as_str().context("missing fixture relative path")?);
        ensure!(!path.as_os_str().is_empty() && path.components().all(|c| matches!(c, Component::Normal(_))), "fixture paths must be relative without traversal");
        Ok(self.root.join(path))
    }

    fn path(&self, key: &str) -> anyhow::Result<PathBuf> { self.relative(&self.manifest[key]) }

    fn item(&self, key: &str, index: usize) -> anyhow::Result<PathBuf> { self.relative(&self.manifest[key][index]) }

    fn nonce(&self, nonce: u64, file: &str) -> PathBuf { self.archive.join(nonce.to_string()).join(file) }

    fn network(&self) -> u64 { self.manifest["network_magic"].as_u64().unwrap() }

    fn command(&self) -> Command {
        let mut command = Command::new(CLI);
        command.current_dir(&self.root).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true);
        command
    }

    fn policy(&self, operation: &str) -> anyhow::Result<Command> {
        let mut command = self.command();
        command.arg(operation).arg("--rpc-config").arg(self.path("relayer_rpc_config")?).arg("--guardian-config").arg(self.path("relayer_guardian_config")?);
        Ok(command)
    }

    fn daemon(&self) -> anyhow::Result<Command> {
        let mut command = self.command();
        command.arg("--config").arg(self.path("relayer_daemon_config")?);
        Ok(command)
    }

    fn guardian(&self, index: usize) -> anyhow::Result<Command> {
        let path = self.item("guardians", index)?;
        protected(&path, false)?;
        let mut command = self.command();
        command.arg("guardian-service").arg("--runtime-config").arg(path);
        Ok(command)
    }

    fn create_db(&self, index: usize) -> anyhow::Result<Command> {
        let path = self.item("guardians", index)?;
        protected(&path, false)?;
        let mut command = self.command();
        command.arg("guardian-create-db").arg("--runtime-config").arg(path);
        Ok(command)
    }
}

struct Children(Vec<Child>);

impl Children {
    fn start(&mut self, mut command: Command) -> anyhow::Result<usize> {
        let child = command.spawn().map_err(|_| anyhow::anyhow!("CLI spawn failed (details redacted)"))?;
        self.0.push(child);
        Ok(self.0.len() - 1)
    }

    fn alive(&mut self, index: usize) -> anyhow::Result<()> {
        ensure!(self.0[index].try_wait().map_err(|_| anyhow::anyhow!("child status unavailable"))?.is_none(), "CLI exited before required condition (all output redacted)");
        Ok(())
    }

    async fn stop(&mut self, index: usize) -> anyhow::Result<()> {
        if self.0[index].try_wait().map_err(|_| anyhow::anyhow!("child status unavailable"))?.is_none() {
            self.0[index].start_kill().map_err(|_| anyhow::anyhow!("owned child kill failed"))?;
        }
        timeout(Duration::from_secs(15), self.0[index].wait()).await.context("owned child reap timed out")?.map_err(|_| anyhow::anyhow!("owned child reap failed"))?;
        Ok(())
    }

    async fn ready(&mut self, index: usize, address: SocketAddr, bound: Duration) -> anyhow::Result<()> {
        let deadline = Instant::now() + bound;
        loop {
            self.alive(index)?;
            if matches!(timeout(Duration::from_secs(1), TcpStream::connect(address)).await, Ok(Ok(_))) { return Ok(()); }
            ensure!(Instant::now() < deadline, "CLI listener readiness timed out");
            sleep(Duration::from_millis(100)).await;
        }
    }

    async fn success(&mut self, index: usize, bound: Duration) -> anyhow::Result<()> {
        let status = timeout(bound, self.0[index].wait()).await.context("policy CLI timed out")?.map_err(|_| anyhow::anyhow!("policy child wait failed"))?;
        ensure!(status.success(), "policy CLI failed (all output redacted)");
        Ok(())
    }
}

struct PendingLink(PathBuf);
impl Drop for PendingLink {
    fn drop(&mut self) { let _ = fs::remove_file(&self.0); }
}

struct Sessions {
    http: reqwest::Client,
    origins: [url::Url; 3],
}

impl Sessions {
    fn load(fixture: &Fixture) -> anyhow::Result<Self> {
        let config_path = fixture.path("relayer_guardian_config")?;
        let parent = config_path.parent().context("client config parent missing")?;
        let config = json(&read(&config_path)?)?;
        let identity = protected_relative(parent, config["tls_identity_path"].as_str().context("client identity missing")?)?;
        let ca = protected_relative(parent, config["server_ca_path"].as_str().context("client CA missing")?)?;
        let http = reqwest::Client::builder().use_rustls_tls().tls_built_in_root_certs(false).no_proxy()
            .add_root_certificate(reqwest::Certificate::from_pem(&read(&ca)?).map_err(|_| anyhow::anyhow!("client CA rejected"))?)
            .identity(reqwest::Identity::from_pem(&read(&identity)?).map_err(|_| anyhow::anyhow!("client identity rejected"))?)
            .redirect(reqwest::redirect::Policy::none()).connect_timeout(Duration::from_secs(10)).timeout(Duration::from_secs(30)).build()
            .map_err(|_| anyhow::anyhow!("session client unavailable"))?;
        let mut origins = Vec::new();
        for value in config["endpoints"].as_array().context("client endpoints missing")? {
            let url = url::Url::parse(value.as_str().context("client endpoint missing")?).map_err(|_| anyhow::anyhow!("client endpoint invalid"))?;
            ensure!(url.scheme() == "https" && url.host().is_some() && url.username().is_empty() && url.password().is_none() && url.path() == "/" && url.query().is_none() && url.fragment().is_none(), "guardian endpoint must be a fixed HTTPS origin");
            origins.push(url);
        }
        ensure!(origins.len() == 3 && origins[0] != origins[1] && origins[0] != origins[2] && origins[1] != origins[2], "guardian origins must be distinct");
        Ok(Self { http, origins: origins.try_into().map_err(|_| anyhow::anyhow!("three guardian endpoints required"))? })
    }

    async fn post_signature(&self, index: usize, request: &[u8]) -> anyhow::Result<Option<GuardianSignResponse>> {
        let response = self.http.post(self.origins[index].join("v1/sign-session").map_err(|_| anyhow::anyhow!("signing URL unavailable"))?)
            .header(reqwest::header::CONTENT_TYPE, "application/json").body(request.to_vec()).send().await;
        let Ok(mut response) = response else { return Ok(None); };
        if !response.status().is_success() { return Ok(None); }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| anyhow::anyhow!("signing response interrupted"))? {
            ensure!(body.len().checked_add(chunk.len()).is_some_and(|n| n <= MAX_BODY_BYTES), "signing response exceeds transport bound");
            body.extend_from_slice(&chunk);
        }
        Ok(parse_canonical_json(&body).ok())
    }

    async fn durable_signature(&self, children: &mut Children, daemon: usize, index: usize, fixture: &Fixture) -> anyhow::Result<GuardianSignResponse> {
        let deadline = Instant::now() + fixture.session;
        let request_path = fixture.nonce(1, "request.json");
        loop {
            children.alive(daemon)?;
            if request_path.is_file() { break; }
            ensure!(Instant::now() < deadline, "lone guardian durable signature timed out");
            sleep(Duration::from_secs(1)).await;
        }
        loop {
            children.alive(daemon)?;
            let request = read(&request_path)?;
            ensure!(request.len() <= MAX_BODY_BYTES, "archived request exceeds transport bound");
            if let Some(response) = self.post_signature(index, &request).await? {
                let parsed = GuardianSignRequest::parse(&request).map_err(|_| anyhow::anyhow!("archived request rejected"))?;
                if response.validate_context(&parsed).is_ok() && response.session_nonce == 1 && response.signature.0.iter().any(|byte| *byte != 0) {
                    return Ok(response);
                }
            }
            ensure!(Instant::now() < deadline, "lone guardian durable signature timed out");
            sleep(Duration::from_secs(1)).await;
        }
    }

    async fn session(&self, index: usize, nonce: u64) -> anyhow::Result<Option<protocol::GuardianSessionRecord>> {
        let mut url = self.origins[index].clone();
        url.set_path("/v1/sessions");
        url.query_pairs_mut().append_pair("after_nonce", &(nonce - 1).to_string()).append_pair("limit", "1");
        let Ok(mut response) = self.http.get(url).send().await else { return Ok(None); };
        if !response.status().is_success() { return Ok(None); }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| anyhow::anyhow!("session response interrupted"))? {
            ensure!(body.len().checked_add(chunk.len()).is_some_and(|n| n <= MAX_BODY_BYTES), "session response exceeds transport bound");
            body.extend_from_slice(&chunk);
        }
        let page = parse_canonical_json::<GuardianSessionsResponse>(&body).map_err(|_| anyhow::anyhow!("session page rejected"))?;
        page.validate_page(nonce - 1, 1).map_err(|_| anyhow::anyhow!("session page rejected"))?;
        Ok(page.sessions.into_iter().find(|record| record.request_json.decode().is_ok_and(|request| request.session_nonce == nonce)))
    }

    async fn wait_session(&self, children: &mut Children, child: usize, index: usize, fixture: &Fixture, nonce: u64) -> anyhow::Result<()> {
        let deadline = Instant::now() + fixture.session;
        loop {
            children.alive(child)?;
            if self.session(index, nonce).await?.is_some() { return Ok(()); }
            ensure!(Instant::now() < deadline, "guardian canonical catch-up timed out");
            sleep(Duration::from_millis(200)).await;
        }
    }
}

fn protected_relative(parent: &Path, value: &str) -> anyhow::Result<PathBuf> {
    let relative = Path::new(value);
    ensure!(!relative.as_os_str().is_empty() && relative.components().all(|c| matches!(c, Component::Normal(_))), "client path must be protected relative path");
    let path = parent.join(relative);
    protected(&path, false)?;
    Ok(path)
}

async fn wait_receipt(children: &mut Children, child: usize, fixture: &Fixture, nonce: u64) -> anyhow::Result<()> {
    let deadline = Instant::now() + fixture.session;
    loop {
        children.alive(child)?;
        if fixture.nonce(nonce, "included.json").is_file() && !fixture.archive.join("pending.json").exists() { return Ok(()); }
        ensure!(Instant::now() < deadline, "canonical relayer inclusion timed out");
        sleep(Duration::from_millis(100)).await;
    }
}

async fn verify_inclusion(provider: &RpcProvider, fixture: &Fixture, nonce: u64, operation: &str) -> anyhow::Result<Value> {
    let envelope = json(&read(&fixture.nonce(nonce, "included.json"))?)?;
    let request_bytes = read(&fixture.nonce(nonce, "request.json"))?;
    let signature_bytes = read(&fixture.nonce(nonce, "signatures.json"))?;
    ensure!(envelope["request_json"].as_str().map(str::as_bytes) == Some(request_bytes.as_slice()), "receipt changed exact archived request");
    ensure!(envelope["signatures_json"].as_str().map(str::as_bytes) == Some(signature_bytes.as_slice()), "receipt changed exact archived signatures");
    let proof = read(&fixture.nonce(nonce, "endcap.bin"))?;
    ensure!(!proof.is_empty() && envelope["endcap_proof_hex"] == format!("0x{}", hex::encode(&proof)), "receipt proof mismatch");
    let request = json(&request_bytes)?;
    ensure!(request["session_nonce"] == nonce && request["user_id"] == USER && request["network_magic"] == fixture.manifest["network_magic"] && request["operation"] == operation, "included request context mismatch");
    let signatures = json(&signature_bytes)?;
    let indices = signatures["member_indices"].as_array().context("missing signature indices")?;
    ensure!(indices.len() == 2 && indices[0].as_u64() < indices[1].as_u64() && indices[1].as_u64().is_some_and(|n| n < 3), "not a distinct two-member quorum");
    let checkpoint = envelope["included_checkpoint_id"].as_u64().context("missing included checkpoint")?;
    let input = json(envelope["endcap_input_json"].as_str().context("missing EndCap input")?.as_bytes())?;
    let expected_leaf: psy_client_data::qdata::user::PsyUserLeaf<GoldilocksField> = serde_json::from_value(input["core"]["new_user_leaf"].clone()).map_err(|_| anyhow::anyhow!("invalid included user leaf"))?;
    let leaf = provider.get_user_leaf_data(checkpoint, USER).await.map_err(|_| anyhow::anyhow!("included user leaf unavailable"))?;
    ensure!(leaf.nonce.to_canonical_u64() == nonce && leaf.qfhash::<PsyHasher>() == expected_leaf.qfhash::<PsyHasher>(), "canonical account transition differs from EndCap");
    let path = provider.get_user_tree_merkle_proof(checkpoint, USER).await.map_err(|_| anyhow::anyhow!("included account path unavailable"))?;
    ensure!(path.index == USER && path.value == leaf.qfhash::<PsyHasher>() && path.verify::<PsyHasher>(), "canonical account membership invalid");
    let roots = provider.get_checkpoint_global_state_roots(checkpoint).await.map_err(|_| anyhow::anyhow!("checkpoint roots unavailable"))?;
    let checkpoint_leaf = provider.get_checkpoint_leaf_data(checkpoint).await.map_err(|_| anyhow::anyhow!("checkpoint leaf unavailable"))?;
    let checkpoint_path = provider.get_checkpoint_tree_merkle_proof(checkpoint, checkpoint).await.map_err(|_| anyhow::anyhow!("checkpoint path unavailable"))?;
    let root = provider.get_checkpoint_tree_root(checkpoint).await.map_err(|_| anyhow::anyhow!("checkpoint root unavailable"))?;
    ensure!(path.root == roots.user_tree_root && roots.qfhash::<PsyHasher>() == checkpoint_leaf.global_chain_root && checkpoint_path.index == checkpoint && checkpoint_path.value == checkpoint_leaf.qfhash::<PsyHasher>() && checkpoint_path.root == root && checkpoint_path.verify::<PsyHasher>(), "account inclusion not bound to canonical checkpoint");
    let receipt_hash: QHashOut<GoldilocksField> = serde_json::from_value(envelope["included_checkpoint_hash"].clone()).map_err(|_| anyhow::anyhow!("invalid receipt checkpoint hash"))?;
    ensure!(receipt_hash == checkpoint_path.value, "receipt names another checkpoint");
    Ok(request)
}

async fn verify_policy(provider: &RpcProvider, checkpoint: u64, version: u64, members: Option<&Value>) -> anyhow::Result<Vec<QHashOut<GoldilocksField>>> {
    let user = provider.get_user_leaf_data(checkpoint, USER).await.map_err(|_| anyhow::anyhow!("policy account unavailable"))?;
    let contract = provider.get_user_contract_tree_merkle_proof(checkpoint, USER, 6).await.map_err(|_| anyhow::anyhow!("policy contract path unavailable"))?;
    ensure!(contract.index == 6 && contract.root == user.user_state_tree_root && contract.verify::<PsyHasher>(), "policy contract not bound to included account");
    let mut slots = Vec::new();
    for slot in 0..4 {
        let path = provider.get_user_contract_state_tree_merkle_proof(checkpoint, USER, 6, 4, slot).await.map_err(|_| anyhow::anyhow!("onchain policy path unavailable"))?;
        ensure!(path.index == slot && path.root == contract.value && path.verify::<PsyHasher>(), "policy slot membership invalid");
        slots.push(path.value);
    }
    ensure!(slots[0].0.elements.map(|x| x.to_canonical_u64()) == [version, 2, 3, 0], "onchain policy header mismatch");
    if let Some(members) = members {
        let expected: Vec<QHashOut<GoldilocksField>> = serde_json::from_value(members.clone()).map_err(|_| anyhow::anyhow!("invalid replacement commitments"))?;
        ensure!(slots[1..] == expected, "onchain replacement members mismatch");
    }
    Ok(slots)
}

async fn verify_genesis(provider: &RpcProvider, fixture: &Fixture) -> anyhow::Result<Vec<QHashOut<GoldilocksField>>> {
    let config_path = fixture.path("relayer_guardian_config")?;
    let config = json(&read(&config_path)?)?;
    let authorization_path = protected_relative(config_path.parent().context("config parent missing")?, config["authorization_path"].as_str().context("authorization path missing")?)?;
    let authorization = json(&read(&authorization_path)?)?;
    let account = json(authorization["account_json"].as_str().context("initial account missing")?.as_bytes())?;
    let hashes = account["initial_policy"]["member_hashes"].as_array().context("initial members missing")?;
    ensure!(hashes.len() == 8 && account["contract_id"] == 6, "initial account shape mismatch");
    let members = Value::Array(hashes[..3].to_vec());
    let user = provider.get_user_leaf_data(0, USER).await.map_err(|_| anyhow::anyhow!("Genesis account unavailable"))?;
    let public_key: QHashOut<GoldilocksField> = serde_json::from_value(authorization["account_public_key"].clone()).map_err(|_| anyhow::anyhow!("invalid approved account public key"))?;
    ensure!(user.nonce.to_canonical_u64() == 0 && user.user_id.to_canonical_u64() == USER && user.public_key == public_key, "initialized Genesis account identity/nonce mismatch");
    let path = provider.get_user_tree_merkle_proof(0, USER).await.map_err(|_| anyhow::anyhow!("Genesis account path unavailable"))?;
    let roots = provider.get_checkpoint_global_state_roots(0).await.map_err(|_| anyhow::anyhow!("Genesis roots unavailable"))?;
    let checkpoint = provider.get_checkpoint_leaf_data(0).await.map_err(|_| anyhow::anyhow!("Genesis checkpoint unavailable"))?;
    let checkpoint_path = provider.get_checkpoint_tree_merkle_proof(0, 0).await.map_err(|_| anyhow::anyhow!("Genesis checkpoint path unavailable"))?;
    let root = provider.get_checkpoint_tree_root(0).await.map_err(|_| anyhow::anyhow!("Genesis checkpoint root unavailable"))?;
    ensure!(path.index == USER && path.value == user.qfhash::<PsyHasher>() && path.root == roots.user_tree_root && path.verify::<PsyHasher>() && roots.qfhash::<PsyHasher>() == checkpoint.global_chain_root && checkpoint_path.index == 0 && checkpoint_path.value == checkpoint.qfhash::<PsyHasher>() && checkpoint_path.root == root && checkpoint_path.verify::<PsyHasher>(), "Genesis account not authenticated to checkpoint zero");
    let genesis_hash = psy_client_common::data::base_types::hash256::Hash256::from(checkpoint.qfhash::<PsyHasher>());
    ensure!(authorization["genesis_hash"] == format!("0x{}", hex::encode(genesis_hash.0)), "Genesis checkpoint differs from approved identity");
    let contract = provider.get_user_contract_tree_merkle_proof(0, USER, 0).await.map_err(|_| anyhow::anyhow!("Genesis fee contract unavailable"))?;
    let fee_contract = authorization["approved_contracts"].as_array().context("approved contracts missing")?.iter().find(|contract| contract["contract_id"] == 0).context("approved fee contract missing")?;
    let fee_leaf: psy_client_data::qdata::contract::PsyContractLeaf<GoldilocksField> = serde_json::from_str(fee_contract["contract_leaf_json"].as_str().context("approved fee contract leaf missing")?).map_err(|_| anyhow::anyhow!("invalid approved fee contract leaf"))?;
    let fee_height = u8::try_from(fee_leaf.state_tree_height.to_canonical_u64()).map_err(|_| anyhow::anyhow!("invalid fee contract height"))?;
    let fee = provider.get_user_contract_state_tree_merkle_proof(0, USER, 0, fee_height, 0).await.map_err(|_| anyhow::anyhow!("Genesis fee balance unavailable"))?;
    ensure!(contract.index == 0 && contract.root == user.user_state_tree_root && contract.verify::<PsyHasher>() && fee.index == 0 && fee.root == contract.value && fee.verify::<PsyHasher>() && fee.value.0.elements[0].to_canonical_u64() > 0, "Genesis lacks authenticated fee funding");
    verify_policy(provider, 0, 1, Some(&members)).await
}

fn require_imported(journal: &Journal, nonce: u64, request: &[u8], signatures: &[u8]) -> anyhow::Result<GuardianSession> {
    ensure!(journal.account.state == GuardianAccountState::Active && journal.account.halt_reason.is_none(), "guardian unexpectedly halted");
    ensure!(journal.account.imported_nonce.is_some_and(|cursor| cursor >= nonce), "guardian imported cursor behind retained session");
    let matched = journal.sessions.iter().filter(|session| session.nonce == nonce).collect::<Vec<_>>();
    ensure!(matched.len() == 1, "retained session count mismatch");
    let session = matched[0].clone();
    ensure!(session.record.request_json.as_str().as_bytes() == request, "imported envelope changed archived request");
    ensure!(session.record.signatures_json.as_str().as_bytes() == signatures, "imported envelope changed archived signatures");
    Ok(session)
}

async fn scenario(fixture: &Fixture, children: &mut Children) -> anyhow::Result<()> {
    let mut addresses = Vec::new();
    for value in fixture.manifest["guardian_listen_addresses"].as_array().unwrap().iter().chain(std::iter::once(&fixture.manifest["relayer_history_listen_address"])) {
        let address: SocketAddr = value.as_str().context("missing listener")?.parse().map_err(|_| anyhow::anyhow!("listener must be numeric loopback"))?;
        ensure!(address.ip().is_loopback() && address.port() != 0 && !addresses.contains(&address), "invalid/duplicate fixture listener");
        ensure!(matches!(timeout(Duration::from_secs(1), TcpStream::connect(address)).await, Ok(Err(_))), "fixture listener already occupied or unavailable; no existing service will be used");
        addresses.push(address);
    }
    let provider = RpcProvider::new_with_config_path(fixture.path("relayer_rpc_config")?.to_str().context("RPC path not UTF-8")?).map_err(|_| anyhow::anyhow!("fixture RPC configuration invalid"))?;
    let initial_policy = verify_genesis(&provider, fixture).await?;
    let sessions = Sessions::load(fixture)?;
    let mut databases = Vec::new();
    for index in 0..3 {
        let path = fixture.item("db_files", index)?;
        ensure!(fs::symlink_metadata(&path).is_err(), "database path already exists; never replace retained evidence");
        let created = children.start(fixture.create_db(index)?)?;
        children.success(created, fixture.ready).await?;
        protected(&path, false)?;
        ensure!(fs::metadata(&path).map_err(|_| anyhow::anyhow!("created database unavailable"))?.size() > 0, "created database is empty");
        databases.push(path);
    }
    let mut guardians = Vec::new();
    for index in 0..3 {
        let child = children.start(fixture.guardian(index)?)?;
        children.ready(child, addresses[index], fixture.ready).await?;
        guardians.push(child);
    }
    children.stop(guardians[1]).await?;
    children.stop(guardians[2]).await?;
    let daemon = children.start(fixture.daemon()?)?;
    children.ready(daemon, addresses[3], fixture.ready).await?;
    let response = sessions.durable_signature(children, daemon, 0, fixture).await?;
    children.stop(daemon).await?;
    children.stop(guardians[0]).await?;
    ensure!(!fixture.nonce(1, "signatures.json").exists() && !fixture.nonce(1, "included.json").exists(), "one guardian unexpectedly obtained quorum");
    let request = read(&fixture.nonce(1, "request.json"))?;
    ensure!(read(&fixture.archive.join("pending.json"))? == request, "pending differs from original request");
    let original = Journal::read(&databases[0], fixture.network(), &[1])?;
    let decisions = original.signed(1)?;
    ensure!(decisions.len() == 1 && decisions[0].request_bytes == GuardianSignRequest::parse(&request).map_err(|_| anyhow::anyhow!("archived request rejected"))?.canonical_bytes().map_err(|_| anyhow::anyhow!("archived request rejected"))? && decisions[0].signature == Some(response.signature.0), "durable decision differs from archived request and signing response");
    let original_decision = (decisions[0].request_bytes.clone(), decisions[0].signature);
    drop(original);
    let link_path = fixture.archive.join("acceptance-original-pending.json");
    fs::hard_link(fixture.archive.join("pending.json"), &link_path).map_err(|_| anyhow::anyhow!("cannot retain original pending inode"))?;
    let pending = PendingLink(link_path);
    guardians[0] = children.start(fixture.guardian(0)?)?;
    children.ready(guardians[0], addresses[0], fixture.ready).await?;
    guardians[1] = children.start(fixture.guardian(1)?)?;
    children.ready(guardians[1], addresses[1], fixture.ready).await?;
    let daemon = children.start(fixture.daemon()?)?;
    children.ready(daemon, addresses[3], fixture.ready).await?;
    wait_receipt(children, daemon, fixture, 1).await?;
    children.stop(daemon).await?;
    ensure!(!fixture.nonce(2, "request.json").exists(), "fixture produced extra work; bounded one-session scan required");
    let bridge = verify_inclusion(&provider, fixture, 1, "bridge").await?;
    ensure!(bridge["withdrawal_records"].as_array().is_some_and(|v| !v.is_empty()), "bridge did not consume a genuine withdrawal");
    let bridge_receipt = json(&read(&fixture.nonce(1, "included.json"))?)?;
    let checkpoint = bridge_receipt["included_checkpoint_id"].as_u64().context("bridge checkpoint missing")?;
    let user = provider.get_user_leaf_data(checkpoint, USER).await.map_err(|_| anyhow::anyhow!("bridge account unavailable"))?;
    let contract = provider.get_user_contract_tree_merkle_proof(checkpoint, USER, 3).await.map_err(|_| anyhow::anyhow!("withdrawal contract path unavailable"))?;
    ensure!(contract.index == 3 && contract.root == user.user_state_tree_root && contract.verify::<PsyHasher>(), "withdrawal contract not bound to included account");
    let mut counts = std::collections::BTreeMap::<u64, u64>::new();
    for burn in bridge["withdrawal_records"].as_array().context("missing bridge burns")? {
        *counts.entry(burn["destination_chain_index"].as_u64().context("missing burn destination")?).or_default() += 1;
    }
    for (chain, count) in counts {
        let subslot = 65544 + chain;
        let path = provider.get_user_contract_state_tree_merkle_proof(checkpoint, USER, 3, 32, subslot / 4).await.map_err(|_| anyhow::anyhow!("withdrawal count path unavailable"))?;
        ensure!(path.index == subslot / 4 && path.root == contract.value && path.verify::<PsyHasher>() && path.value.0.elements[(subslot % 4) as usize].to_canonical_u64() == count, "onchain withdrawal count did not include requested burns exactly once");
    }
    let signatures = read(&fixture.nonce(1, "signatures.json"))?;
    let proof = read(&fixture.nonce(1, "endcap.bin"))?;
    // Only this run's nonce-1 receipt is removed. No signatures/proofs/rows
    // are rewritten, and the pending marker is the original inode, not new JSON.
    fs::hard_link(&pending.0, fixture.archive.join("pending.json")).map_err(|_| anyhow::anyhow!("cannot restore original pending marker"))?;
    fs::remove_file(fixture.nonce(1, "included.json")).map_err(|_| anyhow::anyhow!("cannot remove own inclusion receipt"))?;
    let daemon = children.start(fixture.daemon()?)?;
    children.ready(daemon, addresses[3], fixture.ready).await?;
    wait_receipt(children, daemon, fixture, 1).await?;
    ensure!(read(&fixture.nonce(1, "request.json"))? == request && read(&fixture.nonce(1, "signatures.json"))? == signatures && read(&fixture.nonce(1, "endcap.bin"))? == proof, "crash recovery changed archived request/signatures/proof");
    verify_inclusion(&provider, fixture, 1, "bridge").await?;
    sessions.wait_session(children, guardians[0], 0, fixture, 1).await?;
    sessions.wait_session(children, guardians[1], 1, fixture, 1).await?;
    children.stop(guardians[0]).await?;
    let recovered = Journal::read(&databases[0], fixture.network(), &[1])?;
    let recovered_session = require_imported(&recovered, 1, &request, &signatures)?;
    let after = recovered.signed(1)?;
    ensure!(after.len() == 1 && after[0].request_bytes == original_decision.0 && after[0].signature == original_decision.1, "crash recovery changed durable decision/signature");
    drop(recovered);
    guardians[0] = children.start(fixture.guardian(0)?)?;
    children.ready(guardians[0], addresses[0], fixture.ready).await?;
    children.stop(guardians[1]).await?;
    let imported_b = Journal::read(&databases[1], fixture.network(), &[1])?;
    let imported_b_session = require_imported(&imported_b, 1, &request, &signatures)?;
    ensure!(imported_b_session.withdrawal_appends == recovered_session.withdrawal_appends, "guardians disagree about canonical withdrawal history");
    drop(imported_b);
    guardians[1] = children.start(fixture.guardian(1)?)?;
    children.ready(guardians[1], addresses[1], fixture.ready).await?;
    let offline = Journal::read(&databases[2], fixture.network(), &[1])?;
    ensure!(offline.signed(1)?.is_empty(), "offline guardian acquired a signing decision");
    ensure!(offline.sessions.iter().all(|session| session.nonce != 1), "offline guardian retained a session before restart");
    drop(offline);
    guardians[2] = children.start(fixture.guardian(2)?)?;
    children.ready(guardians[2], addresses[2], fixture.ready).await?;
    sessions.wait_session(children, guardians[2], 2, fixture, 1).await?;
    children.stop(guardians[2]).await?;
    let learned = Journal::read(&databases[2], fixture.network(), &[1])?;
    ensure!(learned.signed(1)?.is_empty(), "catch-up fabricated an own decision");
    let learned_session = require_imported(&learned, 1, &request, &signatures)?;
    let records = bridge["withdrawal_records"].as_array().context("missing burns")?;
    let appends = &learned_session.withdrawal_appends;
    ensure!(appends.len() == records.len() && appends.iter().zip(records).all(|(append, burn)| serde_json::to_value(&append.burn).ok().as_ref() == Some(burn)), "canonical appends differ from requested burns");
    ensure!(learned_session.withdrawal_appends == recovered_session.withdrawal_appends && imported_b_session.withdrawal_appends == recovered_session.withdrawal_appends, "guardians disagree about canonical withdrawal history");
    drop(learned);
    guardians[2] = children.start(fixture.guardian(2)?)?;
    children.ready(guardians[2], addresses[2], fixture.ready).await?;
    children.stop(daemon).await?;
    ensure!(!fixture.nonce(2, "request.json").exists(), "recovery advanced account instead of recovering nonce one");
    children.stop(guardians[1]).await?;
    let members_bytes = read(&fixture.path("next_members")?)?;
    let members = json(&members_bytes)?;
    let mut rotation = fixture.policy("guardian-policy")?;
    rotation.arg("--intent").arg("replace");
    rotation.arg("--next-members-json").arg(std::str::from_utf8(&members_bytes).map_err(|_| anyhow::anyhow!("replacement members not UTF-8"))?.trim());
    let rotation = children.start(rotation)?;
    children.success(rotation, fixture.session).await?;
    verify_inclusion(&provider, fixture, 2, "replace_policy").await?;
    let receipt = json(&read(&fixture.nonce(2, "included.json"))?)?;
    let next_policy = verify_policy(&provider, receipt["included_checkpoint_id"].as_u64().context("rotation checkpoint missing")?, 2, Some(&members)).await?;
    ensure!(initial_policy[1..] != next_policy[1..], "rotation did not change members");
    children.stop(guardians[0]).await?;
    children.stop(guardians[2]).await?;
    let stopped_b = Journal::read(&databases[1], fixture.network(), &[2])?;
    ensure!(stopped_b.signed(2)?.is_empty(), "offline B signed rotation");
    drop(stopped_b);
    for index in [0, 2] {
        let journal = Journal::read(&databases[index], fixture.network(), &[2])?;
        let decisions = journal.signed(2)?;
        ensure!(decisions.len() == 1 && decisions[0].signature.is_some(), "A+C did not sign after C caught up");
        drop(journal);
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires explicitly provisioned disposable real-network fixture; execution pending QA gate"]
async fn guardian_acceptance() {
    let fixture = Fixture::load().unwrap_or_else(|error| panic!("guardian fixture rejected: {error}"));
    let mut children = Children(Vec::new());
    let result = timeout(fixture.session * 12, scenario(&fixture, &mut children)).await;
    let mut cleanup_ok = true;
    for index in (0..children.0.len()).rev() {
        cleanup_ok &= children.stop(index).await.is_ok();
    }
    assert!(cleanup_ok, "could not reap an owned acceptance child");
    match result {
        Ok(Ok(())) => (),
        Ok(Err(error)) => panic!("guardian acceptance failed: {error}"),
        Err(_) => panic!("guardian acceptance overall deadline exceeded"),
    }
}
