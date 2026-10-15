//! Real guardian acceptance; execution PENDING the independent reviewer/QA gate.
//!
//! Explicit invocation (missing fixture is an error, never a successful skip):
//! GUARDIAN_ACCEPTANCE_FIXTURE=/protected/disposable-fixture cargo test -p
//! psy_relayer_cli --test guardian_acceptance -- --ignored --exact guardian_acceptance
//!
//! The runner never provisions or purges the stack. It requires the authorized
//! disposable Plonky2 stack, services/indexer, real system proving endpoint,
//! funded L1 depositor and claimant, nonce-zero user 524288, and three
//! never-used guardian keys. Databases are absent; first service start creates
//! each one. There is no create-db command and no TLS.
//!
//! The public manifest.json stays outside guardians-root outputs. See §4.5 for its
//! exact field set. Secret-consuming user APIs run in the ignored
//! `guardian_user_operation` child of this executable. The parent passes only
//! the manifest directory and operation name; the child writes
//! `operations/<operation>.json` at mode 0600.

use std::{fs, io::Write, net::SocketAddr, os::unix::fs::{MetadataExt, OpenOptionsExt}, path::{Component, Path, PathBuf}, process::Stdio, time::Duration};

use anyhow::{ensure, Context};
use bincode::Options;
use guardian_common::{endcap::approved_endcap_max_proof_bytes, protocol::{parse_canonical_json, ChainEndpoint, GuardianAccount, GuardianAccountState, GuardianConfig, GuardianOperation, GuardianSession, GuardianSessionsResponse, GuardianSignRequest, GuardianSignResponse, GuardianSigned, TokenMapping, BRIDGE_USER_ID, MAX_BODY_BYTES}, runtime::{load_authorization_archive, AuthorizationArchive}};
use plonky2::field::{goldilocks_field::GoldilocksField, types::{Field, PrimeField64}};
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::{config::store_config::PsyHasher, traits::qdatastore::{qmetadata::QMetaDataStoreReaderSync, qtreedata::QTreeDataStoreReaderSync}};
use psy_crypto::hash::{merkle::core::MerkleProofCore, traits::{hasher::{FieldQHasher, MerkleZeroHasher}, qhashable::QFieldHashable}};
use alloy_sol_types::{sol, SolCall, SolEvent};
use psy_provider::{provider::RpcProvider, wallet::secp_wallet::Wallet};
use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use tokio::{net::TcpStream, process::{Child, Command}, time::{sleep, timeout, Instant}};

const CLI: &str = env!("CARGO_BIN_EXE_psy_relayer_cli");
const USER: u64 = BRIDGE_USER_ID;
// Test-only ABI, matching psy-contracts/src/{StateManager,Bridge}.sol.
sol! {
    function lastFinalizedCheckpointId() external view returns (uint64);
    function knownWithdrawalSubtreeRoots(bytes32 root) external view returns (bool);
    event DepositRecorded(uint32 indexed index, bytes32 shieldAddress, address indexed token, bytes32 l2TokenContractId, uint256 amount, uint8 chainIndex, bytes32 noteCommitment, bytes32 leafHash);
}
const SIGNER: TableDefinition<'_, (), [u8; 33]> = TableDefinition::new("guardian_signer");
const ACCOUNT: TableDefinition<'_, (u64, u64), &[u8]> = TableDefinition::new("guardian_account");
const SIGNED: TableDefinition<'_, (u64, u64, u64), &[u8]> = TableDefinition::new("guardian_signed");
const SESSION: TableDefinition<'_, (u64, u64, u64), &[u8]> = TableDefinition::new("guardian_session");

fn read(path: &Path) -> anyhow::Result<Vec<u8>> {
    fs::read(path).map_err(|_| anyhow::anyhow!("fixture/archive read failed (details redacted)"))
}

fn json_value(bytes: &[u8]) -> anyhow::Result<Value> {
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

fn normal_relative(value: &str) -> anyhow::Result<&Path> {
    let path = Path::new(value);
    ensure!(!path.as_os_str().is_empty() && path.components().all(|component| matches!(component, Component::Normal(_))), "path must be relative without traversal");
    Ok(path)
}

fn write_exclusive(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() { fs::create_dir_all(parent).map_err(|_| anyhow::anyhow!("operation output parent unavailable"))?; }
    let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).map_err(|_| anyhow::anyhow!("operation output already exists or is unavailable"))?;
    file.write_all(bytes).map_err(|_| anyhow::anyhow!("operation output write failed"))?;
    file.sync_all().map_err(|_| anyhow::anyhow!("operation output sync failed"))?;
    Ok(())
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
            ensure!(signer.len().map_err(|_| anyhow::anyhow!("signer count unavailable"))? == 1, "immutable signer missing");
            ensure!(signer.get(()).map_err(|_| anyhow::anyhow!("signer row unavailable"))?.is_some_and(|row| matches!(row.value()[0], 2 | 3)), "immutable signer missing");
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

struct Flow {
    mapping: TokenMapping,
    l1: ChainEndpoint,
    services_url: String,
    prove_proxy_url: String,
    router: String,
}

struct Fixture {
    root: PathBuf,
    manifest: Value,
    config_path: PathBuf,
    config: GuardianConfig,
    archive: AuthorizationArchive,
    archive_dir: PathBuf,
    ready: Duration,
    session: Duration,
    flow: Flow,
}

impl Fixture {
    fn load() -> anyhow::Result<Self> { Self::load_config(true, true) }


    fn load_config(require_absent_journals: bool, require_absent_proof: bool) -> anyhow::Result<Self> {
        let root = PathBuf::from(std::env::var_os("GUARDIAN_ACCEPTANCE_FIXTURE").context("GUARDIAN_ACCEPTANCE_FIXTURE is required; provision the disposable fixture documented in this test")?);
        ensure!(root.is_absolute(), "fixture must be absolute");
        protected(&root, true)?;
        let manifest_path = root.join("manifest.json");
        protected(&manifest_path, false)?;
        let manifest = json_value(&read(&manifest_path)?)?;
        ensure!(manifest["disposable"] == true, "fixture must explicitly declare disposable=true");
        for removed in ["journal_database_files", "guardians", "guardian_listen_addresses", "relayer_history_listen_address", "relayer_guardian_config", "relayer_archive"] {
            ensure!(manifest.get(removed).is_none(), "obsolete manifest field present");
        }
        let config_path = root.join(normal_relative(manifest["guardian_config"].as_str().context("guardian config missing")?)?);
        protected(&config_path, false)?;
        let bound = approved_endcap_max_proof_bytes().map_err(|_| anyhow::anyhow!("endcap proof bound unavailable"))?;
        let config = GuardianConfig::load(&config_path).map_err(|_| anyhow::anyhow!("guardian config rejected"))?;
        config.validate().map_err(|_| anyhow::anyhow!("guardian config rejected"))?;
        let archive = load_authorization_archive(&config_path, bound).map_err(|_| anyhow::anyhow!("authorization archive rejected"))?;
        let archive_dir = config_path.parent().context("config parent missing")?.join(&config.client.archive_path);
        let mut ready = Duration::from_secs(120);
        let mut session = Duration::from_secs(600);
        for (key, limit) in [("service_ready_secs", &mut ready), ("session_secs", &mut session)] {
            if let Some(seconds) = manifest["timeouts"][key].as_u64() {
                ensure!((1..=7200).contains(&seconds), "fixture timeout outside 1..7200 seconds");
                *limit = Duration::from_secs(seconds);
            }
        }
        let mut fixture = Self { root, manifest, config_path, config, archive, archive_dir, ready, session, flow: Flow { mapping: TokenMapping { token: guardian_common::protocol::Hex([0; 20]), l2_contract_id: 0 }, l1: ChainEndpoint { chain_index: 0, rpc_url: String::new() }, services_url: String::new(), prove_proxy_url: String::new(), router: String::new() } };
        protected(&fixture.archive_dir, true)?;
        ensure!(fixture.manifest["network_magic"].as_u64() == Some(fixture.archive.active().0.network_magic), "manifest/archive network mismatch");
        ensure!(fixture.manifest["db_files"].as_array().is_some_and(|values| values.len() == 3), "fixture requires exactly three databases");
        let mut databases = Vec::new();
        for index in 0..3 {
            let path = fixture.database(index)?;
            if require_absent_journals {
                ensure!(fs::symlink_metadata(&path).is_err(), "database path already exists; never replace retained evidence");
                protected(path.parent().context("database parent missing")?, true)?;
            } else {
                protected(&path, false)?;
                ensure!(fs::metadata(&path).map_err(|_| anyhow::anyhow!("existing database unavailable"))?.len() > 0, "existing database is empty");
            }
            databases.push(path);
        }
        ensure!(databases.windows(2).all(|pair| pair[0] != pair[1]) && databases[0] != databases[2], "database paths must be distinct");
        for key in ["relayer_rpc_config", "relayer_daemon_config", "next_members", "claimant_keystore_path", "claimant_password_path", "l1_keystore_path", "l1_password_path", "deposit_secrets_path"] {
            protected(&fixture.path(key)?, false)?;
        }
        let proof_output = fixture.path("deposit_proof_path")?;
        if require_absent_proof {
            ensure!(fs::symlink_metadata(&proof_output).is_err(), "deposit proof output already exists");
        } else {
            protected(&proof_output, false)?;
        }
        protected(proof_output.parent().context("deposit proof parent missing")?, true)?;
        let external = PsyConfig::load(&fixture.path("relayer_rpc_config")?)?;
        fixture.config.validate_rpc_network(&external).map_err(|_| anyhow::anyhow!("RPC projection mismatch"))?;
        let daemon_bytes = read(&fixture.path("relayer_daemon_config")?)?;
        let daemon: toml::Value = toml::from_str(std::str::from_utf8(&daemon_bytes).map_err(|_| anyhow::anyhow!("daemon config not UTF-8"))?).map_err(|_| anyhow::anyhow!("invalid daemon TOML"))?;
        ensure!(fixture.manifest_path(daemon["guardian_config"].as_str().context("daemon guardian config missing")?)? == fixture.config_path, "daemon/manifest guardian config mismatch");
        ensure!(fixture.manifest_path(daemon["rpc_config"].as_str().context("daemon rpc config missing")?)? == fixture.path("relayer_rpc_config")?, "daemon/manifest rpc config mismatch");
        fixture.flow = fixture.select_flow()?;
        ensure!(fixture.claimant()? != USER, "claimant must not be the bridge user");
        ensure!(fixture.amount()? > 0, "amount must be positive");
        ensure!(fixture.manifest["chain_index"].as_u64() == Some(u64::from(fixture.flow.l1.chain_index)), "manifest/mapping chain mismatch");
        hex20(&fixture.text("token")?)?;
        hex20(&fixture.text("recipient")?)?;
        hex32(&fixture.text("withdrawal_nonce")?)?;
        Ok(fixture)
    }

    fn select_flow(&self) -> anyhow::Result<Flow> {
        let chain_index = u8::try_from(self.manifest["chain_index"].as_u64().context("chain index missing")?).map_err(|_| anyhow::anyhow!("chain index out of range"))?;
        let token = hex20(self.manifest["token"].as_str().context("token missing")?)?;
        let authorization = &self.archive.active().0;
        let chain = authorization.chain(chain_index).map_err(|_| anyhow::anyhow!("authorized chain missing"))?;
        let matches = chain.token_mappings.iter().filter(|mapping| mapping.token == token).collect::<Vec<_>>();
        ensure!(matches.len() == 1, "authorized token mapping is not unique");
        let services = self.config.network.api_services_url.as_ref().and_then(|urls| urls.iter().find(|url| !url.is_empty())).context("services URL missing")?;
        let prove = self.config.network.system_prove_proxy_url.iter().find(|url| !url.is_empty()).context("system prove proxy missing")?;
        let l1 = self.config.client.l1_endpoints.iter().find(|endpoint| endpoint.chain_index == chain_index).context("L1 endpoint missing")?;
        ensure!(self.manifest["router_address"].as_str().is_some_and(|value| !value.is_empty()), "router missing");
        Ok(Flow { mapping: matches[0].clone(), l1: l1.clone(), services_url: services.clone(), prove_proxy_url: prove.clone(), router: self.manifest["router_address"].as_str().unwrap().to_string() })
    }

    fn manifest_path(&self, value: &str) -> anyhow::Result<PathBuf> {
        let path = Path::new(value);
        if path.is_absolute() { Ok(path.to_path_buf()) } else { Ok(self.root.join(normal_relative(value)?)) }
    }
    fn located(&self, value: &Value) -> anyhow::Result<PathBuf> {
        self.manifest_path(value.as_str().context("missing fixture path")?)
    }
    fn path(&self, key: &str) -> anyhow::Result<PathBuf> { self.located(&self.manifest[key]) }
    fn database(&self, index: usize) -> anyhow::Result<PathBuf> {
        let (_, relative) = guardian_common::runtime::resolve_operator_db_path(&self.config_path, Path::new(self.manifest["db_files"][index].as_str().context("database path missing")?)).map_err(|_| anyhow::anyhow!("database path rejected"))?;
        Ok(PathBuf::from("/").join(relative))
    }
    fn nonce(&self, nonce: u64, file: &str) -> PathBuf { self.archive_dir.join(nonce.to_string()).join(file) }
    fn network(&self) -> u64 { self.archive.active().0.network_magic }
    fn text(&self, key: &str) -> anyhow::Result<String> { self.manifest[key].as_str().context("missing manifest text").map(str::to_string) }
    fn claimant(&self) -> anyhow::Result<u64> { self.manifest["claimant_user_id"].as_u64().context("claimant missing") }
    fn amount(&self) -> anyhow::Result<u64> { self.manifest["amount"].as_u64().context("amount missing") }
    fn limbs(&self, key: &str) -> anyhow::Result<String> {
        let values = json_value(&read(&self.path("deposit_secrets_path")?)?)?[key].as_array().context("secret limbs missing")?.clone();
        ensure!(values.len() == 4 && values.iter().all(|value| value.as_u64().is_some()), "secret must be four canonical limbs");
        Ok(values.iter().map(|value| value.as_u64().unwrap().to_string()).collect::<Vec<_>>().join(","))
    }

    fn command(&self) -> Command {
        let mut command = Command::new(CLI);
        command.current_dir(&self.root).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true);
        command
    }

    fn guardian(&self, index: usize) -> anyhow::Result<Command> {
        let mut command = self.command();
        command.arg("guardian-service").arg("--config").arg(&self.config_path).arg("--guardian-id").arg((index + 1).to_string()).arg("--db-path").arg(self.database(index)?);
        Ok(command)
    }

    fn daemon(&self) -> anyhow::Result<Command> {
        let mut command = self.command();
        command.arg("--config").arg(self.path("relayer_daemon_config")?);
        Ok(command)
    }

    fn policy(&self) -> anyhow::Result<Command> {
        let path = self.path("next_members")?;
        protected(&path, false)?;
        let bytes = read(&path)?;
        ensure!(bytes.len() <= MAX_BODY_BYTES, "replacement members exceed transport bound");
        let members = parse_canonical_json::<[guardian_common::protocol::Hash4; 3]>(&bytes).map_err(|_| anyhow::anyhow!("replacement members rejected"))?;
        ensure!(members.iter().all(|member| guardian_common::protocol::validate_hash(*member).is_ok()), "replacement member is not canonical");
        let serialized = serde_json::to_string(&members).map_err(|_| anyhow::anyhow!("replacement members rejected"))?;
        let mut command = self.command();
        command.arg("guardian-policy").arg("--rpc-config").arg(self.path("relayer_rpc_config")?).arg("--guardian-config").arg(&self.config_path).arg("--intent").arg("replace").arg("--next-members-json").arg(serialized);
        Ok(command)
    }

    fn listeners(&self) -> anyhow::Result<Vec<SocketAddr>> {
        let mut addresses = self.config.guardians.values().map(|signer| signer.listen_address).collect::<Vec<_>>();
        addresses.push(self.config.client.listen_address);
        ensure!(addresses.iter().all(|address| address.ip().is_loopback() && address.port() != 0), "listener must be numeric loopback");
        ensure!(addresses.windows(2).all(|pair| pair[0] != pair[1]) && addresses[0] != addresses[2], "listeners must be distinct");
        Ok(addresses)
    }
}

struct PsyConfig;
impl PsyConfig {
    fn load(path: &Path) -> anyhow::Result<psy_config::NetworkConfigGoldilocks> {
        let settings = psy_config::PsyConfigGoldilocks::builder().path(path.to_str().context("RPC path not UTF-8")?).network(psy_config::CURRENT_NETWORK).build().map_err(|_| anyhow::anyhow!("external RPC config rejected"))?;
        Ok(settings.get_current_network().map_err(|_| anyhow::anyhow!("external RPC stage rejected"))?.clone())
    }
}


fn hex20(value: &str) -> anyhow::Result<guardian_common::protocol::Hex<20>> {
    let bytes = hex::decode(value.trim_start_matches("0x")).map_err(|_| anyhow::anyhow!("invalid address"))?;
    let bytes: [u8; 20] = bytes.try_into().map_err(|_| anyhow::anyhow!("invalid address"))?;
    Ok(guardian_common::protocol::Hex(bytes))
}
fn hex32(value: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(value.trim_start_matches("0x")).map_err(|_| anyhow::anyhow!("invalid 32-byte value"))?;
    bytes.try_into().map_err(|_| anyhow::anyhow!("invalid 32-byte value"))
}

fn words8(bytes: [u8; 32]) -> [u32; 8] {
    let mut words = [0; 8];
    for (index, chunk) in bytes.chunks(4).enumerate() { words[index] = u32::from_be_bytes(chunk.try_into().unwrap()); }
    words
}
fn left_pad20(value: &str) -> anyhow::Result<[u8; 32]> {
    let mut padded = [0; 32];
    padded[12..].copy_from_slice(&hex20(value)?.0);
    Ok(padded)
}

fn replacement_members(fixture: &Fixture) -> anyhow::Result<psy_vm::ups::multisig::MultisigPolicy> {
    let hashes = parse_canonical_json::<[guardian_common::protocol::Hash4; 3]>(&read(&fixture.path("next_members")?)?).map_err(|_| anyhow::anyhow!("replacement members rejected"))?;
    let mut member_hashes = [guardian_common::protocol::Hash4::ZERO; 8];
    member_hashes[..3].copy_from_slice(&hashes);
    let policy = psy_vm::ups::multisig::MultisigPolicy { version: 2, threshold: 2, member_count: 3, member_hashes };
    policy.validate().map_err(|_| anyhow::anyhow!("replacement policy rejected"))?;
    Ok(policy)
}


struct Children(Vec<Child>);
impl Children {
    fn start(&mut self, mut command: Command) -> anyhow::Result<usize> {
        self.0.push(command.spawn().map_err(|_| anyhow::anyhow!("CLI spawn failed (details redacted)"))?);
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
            ensure!(Instant::now() < deadline, "CLI listener readiness timed out: child {index} at {address}");
            sleep(Duration::from_millis(100)).await;
        }
    }
    async fn success(&mut self, index: usize, bound: Duration) -> anyhow::Result<()> {
        let status = timeout(bound, self.0[index].wait()).await.context("CLI timed out")?.map_err(|_| anyhow::anyhow!("child wait failed"))?;
        ensure!(status.success(), "CLI failed (all output redacted)");
        Ok(())
    }
}

struct PendingLink(PathBuf);
impl Drop for PendingLink { fn drop(&mut self) { let _ = fs::remove_file(&self.0); } }

struct Sessions { http: reqwest::Client, origins: [url::Url; 3] }
impl Sessions {
    fn load(fixture: &Fixture) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).connect_timeout(Duration::from_secs(10)).timeout(Duration::from_secs(30)).build().map_err(|_| anyhow::anyhow!("session client unavailable"))?;
        let mut origins = Vec::new();
        for value in &fixture.config.client.endpoints {
            let url = url::Url::parse(value).map_err(|_| anyhow::anyhow!("client endpoint invalid"))?;
            ensure!(url.scheme() == "http" && url.host().is_some() && url.username().is_empty() && url.password().is_none() && (url.path() == "/" || url.path().is_empty()) && url.query().is_none() && url.fragment().is_none(), "guardian endpoint must be a fixed HTTP origin");
            origins.push(url);
        }
        Ok(Self { http, origins: origins.try_into().map_err(|_| anyhow::anyhow!("three guardian endpoints required"))? })
    }

    async fn body(&self, response: Result<reqwest::Response, reqwest::Error>) -> anyhow::Result<Option<Vec<u8>>> {
        let Ok(mut response) = response else { return Ok(None); };
        if !response.status().is_success() { return Ok(None); }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| anyhow::anyhow!("response interrupted"))? {
            ensure!(body.len().checked_add(chunk.len()).is_some_and(|length| length <= MAX_BODY_BYTES), "response exceeds transport bound");
            body.extend_from_slice(&chunk);
        }
        Ok(Some(body))
    }

    async fn post_signature(&self, index: usize, request: &[u8]) -> anyhow::Result<Option<GuardianSignResponse>> {
        let response = self.http.post(self.origins[index].join("v1/sign-session").map_err(|_| anyhow::anyhow!("signing URL unavailable"))?).header(reqwest::header::CONTENT_TYPE, "application/json").body(request.to_vec()).send().await;
        Ok(self.body(response).await?.and_then(|bytes| parse_canonical_json(&bytes).ok()))
    }

    async fn durable_signature(&self, children: &mut Children, daemon: usize, index: usize, fixture: &Fixture, nonce: u64) -> anyhow::Result<GuardianSignResponse> {
        let deadline = Instant::now() + fixture.session;
        let request_path = fixture.nonce(nonce, "request.json");
        loop {
            children.alive(daemon)?;
            if request_path.is_file() { break; }
            ensure!(Instant::now() < deadline, "durable signature timed out");
            sleep(Duration::from_secs(1)).await;
        }
        loop {
            children.alive(daemon)?;
            let request = read(&request_path)?;
            ensure!(request.len() <= MAX_BODY_BYTES, "archived request exceeds transport bound");
            if let Some(response) = self.post_signature(index, &request).await? {
                let parsed = GuardianSignRequest::parse(&request).map_err(|_| anyhow::anyhow!("archived request rejected"))?;
                if response.validate_context(&parsed).is_ok() && response.session_nonce == nonce && response.signature.0.iter().any(|byte| *byte != 0) { return Ok(response); }
            }
            ensure!(Instant::now() < deadline, "durable signature timed out");
            sleep(Duration::from_secs(1)).await;
        }
    }

    async fn session(&self, index: usize, nonce: u64) -> anyhow::Result<Option<guardian_common::protocol::GuardianSessionRecord>> {
        let mut url = self.origins[index].clone();
        url.set_path("/v1/sessions");
        url.query_pairs_mut().append_pair("after_nonce", &(nonce - 1).to_string()).append_pair("limit", "1");
        let Some(body) = self.body(self.http.get(url).send().await).await? else { return Ok(None); };
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

async fn wait_receipt(children: &mut Children, child: usize, fixture: &Fixture, nonce: u64) -> anyhow::Result<()> {
    let deadline = Instant::now() + fixture.session;
    loop {
        children.alive(child)?;
        if fixture.nonce(nonce, "included.json").is_file() && !fixture.archive_dir.join("pending.json").exists() { return Ok(()); }
        ensure!(Instant::now() < deadline, "canonical relayer inclusion timed out");
        sleep(Duration::from_millis(100)).await;
    }
}

async fn verify_inclusion(provider: &RpcProvider, fixture: &Fixture, nonce: u64, operation: GuardianOperation) -> anyhow::Result<Value> {
    let envelope = json_value(&read(&fixture.nonce(nonce, "included.json"))?)?;
    let request_bytes = read(&fixture.nonce(nonce, "request.json"))?;
    let signature_bytes = read(&fixture.nonce(nonce, "signatures.json"))?;
    ensure!(envelope["request_json"].as_str().map(str::as_bytes) == Some(request_bytes.as_slice()), "receipt changed exact archived request");
    ensure!(envelope["signatures_json"].as_str().map(str::as_bytes) == Some(signature_bytes.as_slice()), "receipt changed exact archived signatures");
    let proof = read(&fixture.nonce(nonce, "endcap.bin"))?;
    ensure!(!proof.is_empty() && envelope["endcap_proof_hex"] == format!("0x{}", hex::encode(&proof)), "receipt proof mismatch");
    let request = GuardianSignRequest::parse(&request_bytes).map_err(|_| anyhow::anyhow!("included request rejected"))?;
    ensure!(request.session_nonce == nonce && request.user_id == USER && request.network_magic == fixture.network() && request.operation == operation, "included request context mismatch");
    let signatures = json_value(&signature_bytes)?;
    let indices = signatures["member_indices"].as_array().context("missing signature indices")?;
    ensure!(indices.len() == 2 && indices[0].as_u64() < indices[1].as_u64() && indices[1].as_u64().is_some_and(|value| value < 3), "not a distinct two-member quorum");
    let checkpoint = envelope["included_checkpoint_id"].as_u64().context("missing included checkpoint")?;
    let input = json_value(envelope["endcap_input_json"].as_str().context("missing EndCap input")?.as_bytes())?;
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
    Ok(json_value(&request_bytes)?)
}

async fn contract_root(provider: &RpcProvider, fixture: &Fixture, checkpoint: u64, user: u64, contract: u32) -> anyhow::Result<(guardian_common::protocol::Hash4, u8)> {
    let account = provider.get_user_leaf_data(checkpoint, user).await.map_err(|_| anyhow::anyhow!("token account unavailable"))?;
    let user_path = provider.get_user_tree_merkle_proof(checkpoint, user).await.map_err(|_| anyhow::anyhow!("token account path unavailable"))?;
    ensure!(user_path.index == user && user_path.value == account.qfhash::<PsyHasher>() && user_path.verify::<PsyHasher>(), "token account membership invalid");
    let roots = provider.get_checkpoint_global_state_roots(checkpoint).await.map_err(|_| anyhow::anyhow!("token checkpoint roots unavailable"))?;
    let checkpoint_leaf = provider.get_checkpoint_leaf_data(checkpoint).await.map_err(|_| anyhow::anyhow!("token checkpoint leaf unavailable"))?;
    let checkpoint_path = provider.get_checkpoint_tree_merkle_proof(checkpoint, checkpoint).await.map_err(|_| anyhow::anyhow!("token checkpoint path unavailable"))?;
    let root = provider.get_checkpoint_tree_root(checkpoint).await.map_err(|_| anyhow::anyhow!("token checkpoint root unavailable"))?;
    ensure!(user_path.root == roots.user_tree_root && roots.qfhash::<PsyHasher>() == checkpoint_leaf.global_chain_root && checkpoint_path.index == checkpoint && checkpoint_path.value == checkpoint_leaf.qfhash::<PsyHasher>() && checkpoint_path.root == root && checkpoint_path.verify::<PsyHasher>(), "token account not bound to canonical checkpoint");
    let contract_path = provider.get_user_contract_tree_merkle_proof(checkpoint, user, contract).await.map_err(|_| anyhow::anyhow!("token contract path unavailable"))?;
    ensure!(contract_path.index == u64::from(contract) && contract_path.root == account.user_state_tree_root && contract_path.verify::<PsyHasher>(), "token contract not bound to account");
    let approved = fixture.archive.active().0.approved_contracts.iter().find(|item| item.contract_id == contract).context("approved token contract missing")?;
    let leaf = approved.contract_leaf_json.decode().map_err(|_| anyhow::anyhow!("approved token leaf rejected"))?;
    let height = u8::try_from(leaf.state_tree_height.to_canonical_u64()).map_err(|_| anyhow::anyhow!("token contract height invalid"))?;
    let global_contract = provider.get_contract_tree_merkle_proof(checkpoint, contract).await.map_err(|_| anyhow::anyhow!("global contract path unavailable"))?;
    ensure!(global_contract.index == u64::from(contract) && global_contract.value == leaf.qfhash::<PsyHasher>() && global_contract.root == roots.contract_tree_root && global_contract.verify::<PsyHasher>(), "contract code/layout not bound to checkpoint");
    let state_root = if contract_path.value == guardian_common::protocol::Hash4::ZERO { <PsyHasher as MerkleZeroHasher<guardian_common::protocol::Hash4>>::get_zero_hash(height as usize) } else { contract_path.value };
    Ok((state_root, height))
}

async fn state_subslots(provider: &RpcProvider, fixture: &Fixture, checkpoint: u64, user: u64, contract: u32, start: u64, count: usize) -> anyhow::Result<Vec<u64>> {
    let (root, height) = contract_root(provider, fixture, checkpoint, user, contract).await?;
    let end = start.checked_add(count as u64).context("state range overflow")?;
    let mut values = Vec::with_capacity(count);
    for index in start / 4..end.div_ceil(4) {
        let proof = provider.get_user_contract_state_tree_merkle_proof(checkpoint, user, contract, height, index).await.map_err(|_| anyhow::anyhow!("state slot unavailable"))?;
        ensure!(proof.index == index && proof.root == root && proof.siblings.len() == usize::from(height) && proof.verify::<PsyHasher>(), "state slot not bound to checkpoint");
        for (offset, field) in proof.value.0.elements.iter().enumerate() {
            if (start..end).contains(&(index * 4 + offset as u64)) { values.push(field.to_canonical_u64()); }
        }
    }
    Ok(values)
}

async fn token_balance(provider: &RpcProvider, fixture: &Fixture, checkpoint: u64, user: u64, contract: u32) -> anyhow::Result<u64> {
    Ok(state_subslots(provider, fixture, checkpoint, user, contract, 0, 1).await?[0])
}

async fn erc20_balance(endpoint: &str, token: &str, holder: &str) -> anyhow::Result<u128> {
    let data = format!("0x70a08231{:0>64}", holder.trim_start_matches("0x"));
    let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to": token, "data": data}, "latest"]});
    let response = reqwest::Client::new().post(endpoint).json(&body).send().await.map_err(|_| anyhow::anyhow!("ERC20 balance unavailable"))?;
    let value: Value = response.json().await.map_err(|_| anyhow::anyhow!("ERC20 balance rejected"))?;
    let hex_value = value["result"].as_str().context("ERC20 balance missing")?;
    u128::from_str_radix(hex_value.trim_start_matches("0x"), 16).map_err(|_| anyhow::anyhow!("ERC20 balance rejected"))
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

fn operation_result(root: &Path, operation: &str) -> anyhow::Result<Value> {
    let path = root.join("operations").join(format!("{operation}.json"));
    protected(&path, false)?;
    let value = json_value(&read(&path)?)?;
    ensure!(value["operation"] == operation && value["status"].as_str().is_some(), "operation result schema mismatch");
    Ok(value)
}

fn start_user_operation(fixture: &Fixture, children: &mut Children, operation: &str) -> anyhow::Result<usize> {
    let mut command = Command::new(std::env::current_exe().map_err(|_| anyhow::anyhow!("acceptance executable unavailable"))?);
    command.arg("--ignored").arg("--exact").arg("guardian_user_operation").env("GUARDIAN_ACCEPTANCE_FIXTURE", &fixture.root).env("GUARDIAN_ACCEPTANCE_OPERATION", operation).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true);
    children.start(command)
}

async fn user_operation_status(fixture: &Fixture, children: &mut Children, child: usize, operation: &str) -> anyhow::Result<Value> {
    children.success(child, fixture.session).await?;
    operation_result(&fixture.root, operation)
}

async fn user_operation(fixture: &Fixture, children: &mut Children, operation: &str) -> anyhow::Result<Value> {
    let child = start_user_operation(fixture, children, operation)?;
    user_operation_status(fixture, children, child, operation).await
}

async fn scenario(fixture: &Fixture, children: &mut Children) -> anyhow::Result<()> {
    let addresses = fixture.listeners()?;
    for address in &addresses {
        ensure!(matches!(timeout(Duration::from_secs(1), TcpStream::connect(*address)).await, Ok(Err(_))), "fixture listener already occupied");
    }
    let provider = RpcProvider::new_with_config_path(fixture.path("relayer_rpc_config")?.to_str().context("RPC path not UTF-8")?).map_err(|_| anyhow::anyhow!("fixture RPC configuration invalid"))?;
    let latest = provider.get_coordinator_latest_block_state().await.map_err(|_| anyhow::anyhow!("latest checkpoint unavailable"))?.checkpoint_id;
    let bridge_leaf = provider.get_user_leaf_data(latest, USER).await.map_err(|_| anyhow::anyhow!("initial bridge account unavailable"))?;
    ensure!(bridge_leaf.nonce.to_canonical_u64() == 0 && !fixture.archive_dir.join("pending.json").exists() && !fixture.archive_dir.join("1").exists(), "acceptance requires a pristine bridge account/session archive");
    let baseline_chain_count = state_subslots(&provider, fixture, latest, USER, 3, 65544 + u64::from(fixture.flow.l1.chain_index), 1).await?[0];
    let baseline_global_count = state_subslots(&provider, fixture, latest, USER, 3, 65800, 1).await?[0];
    let expected = expected_burn(fixture)?;
    let before_claimant = token_balance(&provider, fixture, latest, fixture.claimant()?, fixture.flow.mapping.l2_contract_id).await?;
    let claimant_nonce = provider.get_user_leaf_data(latest, fixture.claimant()?).await.map_err(|_| anyhow::anyhow!("initial claimant unavailable"))?.nonce.to_canonical_u64();
    let before_erc20 = erc20_balance(&fixture.flow.l1.rpc_url, fixture.manifest["token"].as_str().unwrap(), fixture.manifest["recipient"].as_str().context("recipient missing")?).await?;
    let sessions = Sessions::load(fixture)?;
    let mut databases = Vec::new();
    let mut guardians = Vec::new();
    for index in [2, 1, 0] {
        let path = fixture.database(index)?;
        let child = children.start(fixture.guardian(index)?)?;
        children.ready(child, addresses[index], fixture.ready).await?;
        protected(&path, false)?;
        ensure!(fs::metadata(&path).map_err(|_| anyhow::anyhow!("created database unavailable"))?.len() > 0, "first-create database is empty");
        databases.push(path);
        guardians.push(child);
        if index != 0 { children.stop(child).await?; }
    }
    databases.reverse();
    guardians.reverse();
    let deposit = start_user_operation(fixture, children, "deposit")?;
    let daemon = children.start(fixture.daemon()?)?;
    children.ready(daemon, addresses[3], fixture.ready).await?;
    let response = sessions.durable_signature(children, daemon, 0, fixture, 1).await?;
    children.stop(daemon).await?;
    children.stop(guardians[0]).await?;
    ensure!(!fixture.nonce(1, "signatures.json").exists() && !fixture.nonce(1, "included.json").exists(), "one guardian unexpectedly obtained quorum");
    let request = read(&fixture.nonce(1, "request.json"))?;
    ensure!(read(&fixture.archive_dir.join("pending.json"))? == request, "pending differs from original request");
    let original = Journal::read(&databases[0], fixture.network(), &[1])?;
    let decisions = original.signed(1)?;
    ensure!(decisions.len() == 1 && decisions[0].request_bytes == GuardianSignRequest::parse(&request).map_err(|_| anyhow::anyhow!("archived request rejected"))?.canonical_bytes().map_err(|_| anyhow::anyhow!("archived request rejected"))? && decisions[0].signature == Some(response.signature.0), "durable decision differs from archived request and signing response");
    let original_decision = (decisions[0].request_bytes.clone(), decisions[0].signature);
    drop(original);
    let link_path = fixture.archive_dir.join("acceptance-original-pending.json");
    fs::hard_link(fixture.archive_dir.join("pending.json"), &link_path).map_err(|_| anyhow::anyhow!("cannot retain original pending inode"))?;
    let pending = PendingLink(link_path);
    guardians[0] = children.start(fixture.guardian(0)?)?;
    children.ready(guardians[0], addresses[0], fixture.ready).await?;
    guardians[1] = children.start(fixture.guardian(1)?)?;
    children.ready(guardians[1], addresses[1], fixture.ready).await?;
    let daemon = children.start(fixture.daemon()?)?;
    children.ready(daemon, addresses[3], fixture.ready).await?;
    wait_receipt(children, daemon, fixture, 1).await?;
    children.stop(daemon).await?;
    let bridge = verify_inclusion(&provider, fixture, 1, GuardianOperation::Bridge).await?;
    ensure!(bridge["deposit_anchors"].as_array().is_some_and(|anchors| !anchors.is_empty()), "nonce 1 has no deposit anchor");
    let session1_records: Vec<guardian_common::protocol::WithdrawalBurnRecord> = serde_json::from_value(bridge["withdrawal_records"].clone()).map_err(|_| anyhow::anyhow!("first-session burn records rejected"))?;
    ensure!(!session1_records.contains(&expected), "manifest withdrawal predates the claimant withdraw step");
    let signatures = read(&fixture.nonce(1, "signatures.json"))?;
    let proof = read(&fixture.nonce(1, "endcap.bin"))?;
    fs::hard_link(&pending.0, fixture.archive_dir.join("pending.json")).map_err(|_| anyhow::anyhow!("cannot restore original pending marker"))?;
    fs::remove_file(fixture.nonce(1, "included.json")).map_err(|_| anyhow::anyhow!("cannot remove own inclusion receipt"))?;
    let daemon = children.start(fixture.daemon()?)?;
    children.ready(daemon, addresses[3], fixture.ready).await?;
    wait_receipt(children, daemon, fixture, 1).await?;
    ensure!(read(&fixture.nonce(1, "request.json"))? == request && read(&fixture.nonce(1, "signatures.json"))? == signatures && read(&fixture.nonce(1, "endcap.bin"))? == proof, "crash recovery changed archived request/signatures/proof");
    verify_inclusion(&provider, fixture, 1, GuardianOperation::Bridge).await?;
    sessions.wait_session(children, guardians[0], 0, fixture, 1).await?;
    sessions.wait_session(children, guardians[1], 1, fixture, 1).await?;
    children.stop(guardians[0]).await?;
    let recovered = Journal::read(&databases[0], fixture.network(), &[1])?;
    let recovered_session = require_imported(&recovered, 1, &request, &signatures)?;
    verify_initial_appends(&provider, fixture, latest, baseline_chain_count, baseline_global_count, &recovered_session, &session1_records).await?;
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
    let offline = Journal::read(&databases[2], fixture.network(), &[1])?;
    ensure!(offline.signed(1)?.is_empty() && offline.sessions.iter().all(|session| session.nonce != 1), "offline guardian retained a decision or session");
    drop(offline);
    guardians[2] = children.start(fixture.guardian(2)?)?;
    children.ready(guardians[2], addresses[2], fixture.ready).await?;
    sessions.wait_session(children, guardians[2], 2, fixture, 1).await?;
    children.stop(guardians[2]).await?;
    let learned = Journal::read(&databases[2], fixture.network(), &[1])?;
    ensure!(learned.signed(1)?.is_empty(), "catch-up fabricated an own decision");
    let learned_session = require_imported(&learned, 1, &request, &signatures)?;
    ensure!(learned_session.withdrawal_appends == recovered_session.withdrawal_appends, "offline import changed first-session burns");
    drop(learned);
    let deposit = user_operation_status(fixture, children, deposit, "deposit").await?;
    let deposit_hash = deposit["transaction_hash"].as_str().context("deposit hash missing")?.to_string();
    ensure!(deposit["status"] == "confirmed", "deposit did not confirm");
    let deposit_index = verify_deposit_event(fixture, &deposit_hash).await?;
    let claim = user_operation(fixture, children, "claim-deposit").await?;
    ensure!(claim["status"] == "included" && claim["transaction_hash"].as_str().is_some(), "claim-deposit was not included");
    let proof = json_value(&read(&fixture.path("deposit_proof_path")?)?)?;
    ensure!(proof["deposit_index"].as_str().and_then(|value| value.parse::<u64>().ok()) == Some(u64::from(deposit_index)), "proof index differs from mined deposit event");
    let anchors = bridge["deposit_anchors"].as_array().context("deposit anchors missing")?;
    ensure!(anchors.iter().any(|anchor| anchor["chain_index"].as_u64() == Some(u64::from(fixture.flow.l1.chain_index)) && anchor["old_count"].as_u64().is_some_and(|old| old <= u64::from(deposit_index)) && anchor["new_count"].as_u64().is_some_and(|new| u64::from(deposit_index) < new)), "nonce 1 does not cover the mined deposit index");
    let claimant = fixture.claimant()?;
    let amount = fixture.amount()?;
    let claimed_checkpoint = claimant_checkpoint(&provider, fixture, &claim, claimant, claimant_nonce + 1).await?;
    let after_claim = token_balance(&provider, fixture, claimed_checkpoint, claimant, fixture.flow.mapping.l2_contract_id).await?;
    ensure!(after_claim == before_claimant + amount, "claimant token delta is not +amount");
    children.stop(daemon).await?;
    let withdrawal = user_operation(fixture, children, "withdraw").await?;
    ensure!(withdrawal["status"] == "included" && withdrawal["transaction_hash"].as_str().is_some(), "withdraw was not included");
    let withdrawn_checkpoint = claimant_checkpoint(&provider, fixture, &withdrawal, claimant, claimant_nonce + 2).await?;
    let after_withdraw = token_balance(&provider, fixture, withdrawn_checkpoint, claimant, fixture.flow.mapping.l2_contract_id).await?;
    ensure!(after_withdraw + amount == after_claim, "claimant token delta is not -amount");
    guardians[2] = children.start(fixture.guardian(2)?)?;
    children.ready(guardians[2], addresses[2], fixture.ready).await?;
    let burn_daemon = children.start(fixture.daemon()?)?;
    children.ready(burn_daemon, addresses[3], fixture.ready).await?;
    let burn_nonce = next_archive_nonce(fixture, 1).await?;
    wait_receipt(children, burn_daemon, fixture, burn_nonce).await?;
    let burn = verify_inclusion(&provider, fixture, burn_nonce, GuardianOperation::Bridge).await?;
    let records = burn["withdrawal_records"].as_array().context("burn records missing")?;
    ensure!(records.len() == 1 && burn_matches(&records[0], &expected)?, "burn session does not contain the exact manifest withdrawal");
    verify_token_burn(&provider, fixture, withdrawn_checkpoint, &expected).await?;
    let mut observed = Vec::new();
    for index in [0, 2] {
        sessions.wait_session(children, guardians[index], index, fixture, burn_nonce).await?;
        children.stop(guardians[index]).await?;
        let journal = Journal::read(&databases[index], fixture.network(), &[burn_nonce])?;
        let session = require_imported(&journal, burn_nonce, &read(&fixture.nonce(burn_nonce, "request.json"))?, &read(&fixture.nonce(burn_nonce, "signatures.json"))?)?;
        ensure!(session.withdrawal_appends.len() == 1 && session.withdrawal_appends[0].burn == expected, "authenticated burn append differs");
        verify_withdrawal_append(&provider, fixture, &session).await?;
        observed.push(session.withdrawal_appends);
    }
    ensure!(observed[0] == observed[1], "A and C disagree about the burn append");
    let offline_burn = Journal::read(&databases[1], fixture.network(), &[burn_nonce])?;
    ensure!(offline_burn.signed(burn_nonce)?.is_empty() && offline_burn.sessions.iter().all(|session| session.nonce != burn_nonce), "offline B retained a burn decision or session");
    drop(offline_burn);
    guardians[1] = children.start(fixture.guardian(1)?)?;
    children.ready(guardians[1], addresses[1], fixture.ready).await?;
    sessions.wait_session(children, guardians[1], 1, fixture, burn_nonce).await?;
    children.stop(guardians[1]).await?;
    let imported_burn = Journal::read(&databases[1], fixture.network(), &[burn_nonce])?;
    ensure!(imported_burn.signed(burn_nonce)?.is_empty(), "offline burn import fabricated a decision");
    let imported_session = require_imported(&imported_burn, burn_nonce, &read(&fixture.nonce(burn_nonce, "request.json"))?, &read(&fixture.nonce(burn_nonce, "signatures.json"))?)?;
    ensure!(imported_session.withdrawal_appends == observed[0], "offline burn import changed the append");
    drop(imported_burn);
    guardians[0] = children.start(fixture.guardian(0)?)?;
    children.ready(guardians[0], addresses[0], fixture.ready).await?;
    guardians[2] = children.start(fixture.guardian(2)?)?;
    children.ready(guardians[2], addresses[2], fixture.ready).await?;
    wait_indexed_claim(fixture, &provider).await?;
    let claim_l1 = user_operation(fixture, children, "claim-withdrawal").await?;
    ensure!(claim_l1["status"] == "confirmed" && claim_l1["transaction_hash"].as_str().is_some(), "L1 claim was not confirmed");
    let claim_hash = claim_l1["transaction_hash"].as_str().context("claim hash missing")?;
    let receipt: Value = reqwest::Client::new().post(&fixture.flow.l1.rpc_url).json(&json!({"jsonrpc":"2.0","id":1,"method":"eth_getTransactionReceipt","params":[claim_hash]})).send().await?.json().await?;
    ensure!(receipt["result"]["status"] == "0x1" && receipt["result"]["transactionHash"].as_str().is_some_and(|hash| hash.eq_ignore_ascii_case(claim_hash)) && receipt["result"]["blockHash"].as_str().is_some(), "L1 claim lacks a successful mined receipt");
    let after_erc20 = erc20_balance(&fixture.flow.l1.rpc_url, fixture.manifest["token"].as_str().unwrap(), fixture.manifest["recipient"].as_str().unwrap()).await?;
    ensure!(after_erc20 == before_erc20 + u128::from(amount), "recipient ERC20 delta is not +amount");
    children.stop(burn_daemon).await?;
    let members = replacement_members(fixture)?;
    let rotation = children.start(fixture.policy()?)?;
    children.success(rotation, fixture.session).await?;
    let policy_nonce = next_archive_nonce(fixture, burn_nonce).await?;
    verify_inclusion(&provider, fixture, policy_nonce, GuardianOperation::ReplacePolicy).await?;
    let policy_receipt = json_value(&read(&fixture.nonce(policy_nonce, "included.json"))?)?;
    let policy_checkpoint = policy_receipt["included_checkpoint_id"].as_u64().context("policy checkpoint missing")?;
    let slots = state_subslots(&provider, fixture, policy_checkpoint, USER, 6, 0, 16).await?;
    let hashes: Vec<guardian_common::protocol::Hash4> = slots.chunks_exact(4).map(|fields| {
        let fields: [u64; 4] = fields.try_into().unwrap();
        guardian_common::protocol::Hash4::try_from(&fields).map_err(|_| anyhow::anyhow!("policy slot rejected"))
    }).collect::<anyhow::Result<_>>()?;
    let ending = psy_vm::ups::multisig::StoredMultisigPolicy { header: hashes[0], members: [hashes[1], hashes[2], hashes[3]] }.policy()?;
    let initial = fixture.archive.active().0.account_json.decode().map_err(|_| anyhow::anyhow!("account rejected"))?.initial_policy;
    ensure!(ending == members && ending.member_hashes != initial.member_hashes, "committed replacement policy differs or is unchanged");
    let stopped_b = Journal::read(&databases[1], fixture.network(), &[policy_nonce])?;
    ensure!(stopped_b.signed(policy_nonce)?.is_empty(), "offline B signed rotation");
    for index in [0, 2] {
        children.stop(guardians[index]).await?;
        let journal = Journal::read(&databases[index], fixture.network(), &[policy_nonce])?;
        ensure!(journal.signed(policy_nonce)?.len() == 1, "A+C did not sign rotation");
    }
    Ok(())
}
async fn claimant_checkpoint(provider: &RpcProvider, fixture: &Fixture, operation: &Value, user: u64, expected_nonce: u64) -> anyhow::Result<u64> {
    let hash = operation["transaction_hash"].as_str().context("operation hash missing")?;
    let url = format!("{}/api/v1/transaction/hash/{}", fixture.flow.services_url.trim_end_matches('/'), hash.trim_start_matches("0x"));
    let deadline = Instant::now() + fixture.session;
    let client = reqwest::Client::new();
    loop {
        let response: Value = client.get(&url).send().await?.json().await?;
        let data = &response["data"];
        if response["success"] == true && data["status"] == "included" {
            ensure!(data["content_hash"].as_str().is_some_and(|value| value.eq_ignore_ascii_case(hash.trim_start_matches("0x"))) && data["owner_user_id"].as_u64() == Some(user), "indexed claimant transaction identity differs");
            let checkpoint = data["included_checkpoint_id"].as_u64().context("included claimant checkpoint missing")?;
            let leaf = provider.get_user_leaf_data(checkpoint, user).await.map_err(|_| anyhow::anyhow!("claimant leaf unavailable"))?;
            ensure!(leaf.user_id.to_canonical_u64() == user && leaf.nonce.to_canonical_u64() == expected_nonce, "claimant checkpoint has another nonce");
            return Ok(checkpoint);
        }
        ensure!(Instant::now() < deadline, "claimant transaction inclusion unavailable");
        sleep(Duration::from_millis(200)).await;
    }
}

async fn next_archive_nonce(fixture: &Fixture, previous: u64) -> anyhow::Result<u64> {
    let deadline = Instant::now() + fixture.session;
    loop {
        let mut nonce = previous + 1;
        while fixture.nonce(nonce, "included.json").is_file() { nonce += 1; }
        if nonce > previous + 1 { return Ok(nonce - 1); }
        ensure!(Instant::now() < deadline, "next archive nonce unavailable");
        sleep(Duration::from_millis(200)).await;
    }
}

fn expected_burn(fixture: &Fixture) -> anyhow::Result<guardian_common::protocol::WithdrawalBurnRecord> {
    Ok(guardian_common::protocol::WithdrawalBurnRecord {
        sender_user_id: u32::try_from(fixture.claimant()?).map_err(|_| anyhow::anyhow!("claimant exceeds burn word"))?,
        token_contract_id: fixture.flow.mapping.l2_contract_id,
        destination_chain_index: fixture.flow.l1.chain_index,
        token: words8(left_pad20(&fixture.text("token")?)?),
        amount: words8({ let mut bytes = [0; 32]; bytes[24..].copy_from_slice(&fixture.amount()?.to_be_bytes()); bytes }),
        recipient: words8(left_pad20(&fixture.text("recipient")?)?),
        nonce: words8(hex32(&fixture.text("withdrawal_nonce")?)?),
    })
}

fn burn_matches(value: &Value, expected: &guardian_common::protocol::WithdrawalBurnRecord) -> anyhow::Result<bool> {
    let parsed = serde_json::from_value::<guardian_common::protocol::WithdrawalBurnRecord>(value.clone()).map_err(|_| anyhow::anyhow!("burn record rejected"))?;
    Ok(parsed == *expected)
}

async fn verify_deposit_event(fixture: &Fixture, tx_hash: &str) -> anyhow::Result<u32> {
    let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"eth_getTransactionReceipt","params":[tx_hash]});
    let response = reqwest::Client::new().post(&fixture.flow.l1.rpc_url).json(&body).send().await.map_err(|_| anyhow::anyhow!("deposit receipt unavailable"))?;
    let receipt: Value = response.json().await.map_err(|_| anyhow::anyhow!("deposit receipt rejected"))?;
    ensure!(receipt["result"]["status"] == "0x1" && receipt["result"]["transactionHash"].as_str().is_some_and(|hash| hash.eq_ignore_ascii_case(tx_hash)), "deposit receipt identity/status differs");
    let chain = fixture.archive.active().0.chain(fixture.flow.l1.chain_index).map_err(|_| anyhow::anyhow!("authorized chain missing"))?;
    let logs: Vec<alloy_rpc_types_eth::Log> = serde_json::from_value(receipt["result"]["logs"].clone()).map_err(|_| anyhow::anyhow!("deposit logs rejected"))?;
    let mut found = None;
    for log in logs {
        if log.address().as_slice() != chain.bridge.0 || log.topics().first() != Some(&DepositRecorded::SIGNATURE_HASH) { continue; }
        let decoded = log.log_decode::<DepositRecorded>().map_err(|_| anyhow::anyhow!("deposit event rejected"))?;
        let event = decoded.data();
        ensure!(!log.removed && event.token.as_slice() == fixture.flow.mapping.token.0 && event.chainIndex == fixture.flow.l1.chain_index && event.amount == alloy_primitives::U256::from(fixture.amount()?) && event.l2TokenContractId.0[..28] == [0; 28] && u32::from_be_bytes(event.l2TokenContractId.0[28..].try_into().unwrap()) == fixture.flow.mapping.l2_contract_id, "deposit event differs from manifest mapping/amount");
        ensure!(found.replace(event.index).is_none(), "deposit receipt has ambiguous matching events");
    }
    if let Some(index) = found { return Ok(index); }
    anyhow::bail!("authorized DepositRecorded event missing")
}

// Same public Poseidon derivation as guardian/verify.rs::withdrawal_key/withdrawal_leaf.
// The relayer is a binary crate: keep this test-only rather than exporting production internals.
fn withdrawal_key(record: &guardian_common::protocol::WithdrawalBurnRecord) -> guardian_common::protocol::Hash4 {
    let nonce = PsyHasher::q_hash_many(&record.nonce.map(GoldilocksField::from_canonical_u32));
    let mut fields = [GoldilocksField::ZERO; 5];
    fields[0] = GoldilocksField::from_canonical_u64(6);
    fields[1..].copy_from_slice(&nonce.0.elements);
    PsyHasher::q_hash_many(&fields)
}

fn withdrawal_leaf(record: &guardian_common::protocol::WithdrawalBurnRecord) -> guardian_common::protocol::Hash4 {
    let mut fields = [GoldilocksField::ZERO; 34];
    fields[0] = GoldilocksField::from_canonical_u32(record.sender_user_id);
    for (target, words) in fields[1..33].chunks_exact_mut(8).zip([record.recipient, record.token, record.amount, record.nonce]) {
        for (field, word) in target.iter_mut().zip(words) { *field = GoldilocksField::from_canonical_u32(word); }
    }
    fields[33] = GoldilocksField::from_canonical_u8(record.destination_chain_index);
    PsyHasher::q_hash_many(&fields)
}

async fn verify_token_burn(provider: &RpcProvider, fixture: &Fixture, checkpoint: u64, record: &guardian_common::protocol::WithdrawalBurnRecord) -> anyhow::Result<()> {
    let approved = fixture.archive.active().0.approved_contracts.iter().find(|item| item.contract_id == record.token_contract_id).context("approved burn contract missing")?;
    let artifact = approved.compiler_artifact().map_err(|_| anyhow::anyhow!("approved token ABI rejected"))?;
    let fields = artifact.abi.pointer("/contract/state").and_then(Value::as_array).context("token state ABI missing")?;
    let maps = fields.iter().filter(|field| field["name"] == "state_map").collect::<Vec<_>>();
    ensure!(maps.len() == 1, "token state_map is not unique");
    let base = maps[0]["offset"].as_u64().context("token map offset missing")?;
    let capacity = maps[0]["type"]["capacity"].as_u64().context("token map capacity missing")?;
    ensure!(base % 4 == 0 && capacity > 0 && maps[0]["type"]["map_kind"] == "map" && maps[0]["type"]["value_felt_size"] == 4, "token map layout differs");
    let input = psy_provider::request::QIMTMembershipProofRPCRequest { checkpoint_id: checkpoint, user_id: u64::from(record.sender_user_id), contract_id: record.token_contract_id, key: withdrawal_key(record), state_slot_base: base / 4, capacity };
    let proof = provider.get_withdrawal_burn_proof(input.clone()).await.map_err(|_| anyhow::anyhow!("withdrawal burn proof unavailable"))?;
    let (root, height) = contract_root(provider, fixture, checkpoint, u64::from(record.sender_user_id), record.token_contract_id).await?;
    let membership = &proof.record_membership;
    input.validate_indices(membership.merkle_proof.index, membership.leaf.next_index.to_canonical_u64()).map_err(|_| anyhow::anyhow!("burn map index differs"))?;
    ensure!(proof.checkpoint_id == checkpoint && membership.leaf.key == input.key && membership.leaf.value == withdrawal_leaf(record) && membership.merkle_proof.value == membership.leaf.qfhash::<PsyHasher>() && membership.merkle_proof.root == root && membership.merkle_proof.siblings.len() == usize::from(height) && membership.merkle_proof.verify::<PsyHasher>(), "exact token burn is not authenticated");
    Ok(())
}

fn hash_from_words(words: &[u64]) -> anyhow::Result<guardian_common::protocol::Hash4> {
    ensure!(words.len() == 8 && words.iter().all(|word| *word <= u64::from(u32::MAX)), "hash words out of range");
    let fields: [u64; 4] = std::array::from_fn(|index| words[index * 2] | (words[index * 2 + 1] << 32));
    ensure!(fields.iter().all(|field| *field < guardian_common::protocol::GOLDILOCKS_MODULUS), "noncanonical hash words");
    guardian_common::protocol::Hash4::try_from(&fields).map_err(|_| anyhow::anyhow!("noncanonical hash words"))
}

// Existing queued burns may share the first deposit session; retain and account
// for every record instead of assuming an empty withdrawal tree or hiding burns.
async fn verify_initial_appends(provider: &RpcProvider, fixture: &Fixture, baseline_checkpoint: u64, baseline_chain_count: u64, baseline_global_count: u64, session: &GuardianSession, records: &[guardian_common::protocol::WithdrawalBurnRecord]) -> anyhow::Result<()> {
    ensure!(session.withdrawal_appends.len() == records.len(), "first-session append/record count differs");
    let mut counts = std::collections::BTreeMap::from([(fixture.flow.l1.chain_index, baseline_chain_count)]);
    for (append, record) in session.withdrawal_appends.iter().zip(records) {
        ensure!(append.burn == *record && append.chain_index == record.destination_chain_index, "first-session append differs from authenticated request");
        if !counts.contains_key(&append.chain_index) {
            let baseline = state_subslots(provider, fixture, baseline_checkpoint, USER, 3, 65544 + u64::from(append.chain_index), 1).await?[0];
            counts.insert(append.chain_index, baseline);
        }
        let count = counts.get_mut(&append.chain_index).context("first-session chain count missing")?;
        ensure!(u64::from(append.append_index) == *count, "first-session append index is not baseline-contiguous");
        *count = count.checked_add(1).context("first-session chain count overflow")?;
    }
    for (chain, expected_count) in counts {
        let committed = state_subslots(provider, fixture, session.record.included_checkpoint_id, USER, 3, 65544 + u64::from(chain), 1).await?[0];
        ensure!(committed == expected_count, "first-session committed chain count differs from retained burns");
    }
    let committed_global = state_subslots(provider, fixture, session.record.included_checkpoint_id, USER, 3, 65800, 1).await?[0];
    ensure!(Some(committed_global) == baseline_global_count.checked_add(records.len() as u64), "first-session committed global count differs from retained burns");
    Ok(())
}

async fn verify_withdrawal_append(provider: &RpcProvider, fixture: &Fixture, session: &GuardianSession) -> anyhow::Result<()> {
    let request = session.record.request_json.decode().map_err(|_| anyhow::anyhow!("append request rejected"))?;
    let trace = request.decode_trace().map_err(|_| anyhow::anyhow!("append trace rejected"))?;
    let before = trace.anchor.start_checkpoint_id;
    let after = session.record.included_checkpoint_id;
    ensure!(session.withdrawal_appends.len() == 1, "expected one withdrawal append");
    let append = &session.withdrawal_appends[0];
    let chain = u64::from(append.chain_index);
    // PsyWithdrawalTreeContract ABI: frontiers=8, chain_counts=65544,
    // global_count=65800, chain_roots=65804; all offsets are FELT subslots.
    let old_count = state_subslots(provider, fixture, before, USER, 3, 65544 + chain, 1).await?[0];
    let new_count = state_subslots(provider, fixture, after, USER, 3, 65544 + chain, 1).await?[0];
    ensure!(old_count == u64::from(append.append_index) && new_count == old_count + 1, "withdrawal chain count/index differs");
    let old_global = state_subslots(provider, fixture, before, USER, 3, 65800, 1).await?[0];
    let new_global = state_subslots(provider, fixture, after, USER, 3, 65800, 1).await?[0];
    ensure!(new_global == old_global + 1, "withdrawal global count differs");
    let frontier = state_subslots(provider, fixture, before, USER, 3, 8 + chain * 32 * 8, 32 * 8).await?;
    let root = hash_from_words(&state_subslots(provider, fixture, after, USER, 3, 65804 + chain * 8, 8).await?)?;
    let mut zero = guardian_common::protocol::Hash4::ZERO;
    let mut siblings = Vec::with_capacity(32);
    for (level, words) in frontier.chunks_exact(8).enumerate() {
        siblings.push(if (append.append_index >> level) & 1 == 0 { zero } else { hash_from_words(words)? });
        zero = PsyHasher::q_two_to_one(zero, zero);
    }
    let membership = MerkleProofCore { root, index: u64::from(append.append_index), value: withdrawal_leaf(&append.burn), siblings };
    ensure!(membership.verify::<PsyHasher>(), "exact withdrawal leaf is not in the committed WITHDRAWAL_TREE");
    Ok(())
}

async fn wait_indexed_claim(fixture: &Fixture, provider: &RpcProvider) -> anyhow::Result<()> {
    let deadline = Instant::now() + fixture.session;
    let amount = format!("0x{:064x}", fixture.amount()?);
    let nonce = format!("0x{}", hex::encode(hex32(&fixture.text("withdrawal_nonce")?)?));
    let url = format!("{}/api/v1/bridge/withdrawal-claim-proof?recipient=0x{}&token_address=0x{}&amount={}&nonce={}&destination_chain_index={}&sender_user_id={}", fixture.flow.services_url.trim_end_matches('/'), hex::encode(left_pad20(&fixture.text("recipient")?)?), hex::encode(left_pad20(&fixture.text("token")?)?), amount, nonce, fixture.flow.l1.chain_index, fixture.claimant()?);
    loop {
        if let Ok(response) = reqwest::Client::new().get(&url).send().await {
            if let Ok(value) = response.json::<Value>().await {
                if value["success"] == true && value["data"]["found"] == true {
                    let data = &value["data"];
                    let checkpoint = data["checkpoint_id"].as_u64().context("indexed checkpoint missing")?;
                    let decode = |value: &Value| -> anyhow::Result<guardian_common::protocol::Hash4> {
                        hash_from_words(&words8(hex32(value.as_str().context("indexed hash missing")?)?).map(u64::from))
                    };
                    let expected = expected_burn(fixture)?;
                    let root = decode(&data["withdrawal_root"])?;
                    let index = data["leaf_index"].as_u64().context("indexed leaf index missing")?;
                    let siblings = data["siblings"].as_array().context("indexed siblings missing")?.iter().map(decode).collect::<anyhow::Result<Vec<_>>>()?;
                    let path = MerkleProofCore { root, index, value: decode(&data["leaf_hash"])?, siblings };
                    ensure!(path.siblings.len() == 32 && index < (1u64 << 32) && path.value == withdrawal_leaf(&expected) && data["withdrawal"]["sender_user_id"].as_u64() == Some(fixture.claimant()?) && path.verify::<PsyHasher>(), "indexed proof does not authenticate the exact withdrawal");
                    let count = state_subslots(provider, fixture, checkpoint, USER, 3, 65544 + u64::from(fixture.flow.l1.chain_index), 1).await?[0];
                    let committed_root = hash_from_words(&state_subslots(provider, fixture, checkpoint, USER, 3, 65804 + u64::from(fixture.flow.l1.chain_index) * 8, 8).await?)?;
                    ensure!(index < count && root == committed_root, "indexed withdrawal root differs from committed bridge state");
                    // L1 uses internal bytes32 order; the services API uses u32x8 order.
                    let internal = alloy_primitives::B256::from(hex32(&root.to_string())?);
                    if finalized_checkpoint(fixture, checkpoint).await? && l1_view(fixture, knownWithdrawalSubtreeRootsCall { root: internal }).await? { return Ok(()); }
                }
            }
        }
        ensure!(Instant::now() < deadline, "indexed withdrawal claim proof unavailable");
        sleep(Duration::from_secs(1)).await;
    }
}

async fn l1_view<Call: SolCall>(fixture: &Fixture, call: Call) -> anyhow::Result<Call::Return> {
    let chain = fixture.archive.active().0.chain(fixture.flow.l1.chain_index).map_err(|_| anyhow::anyhow!("authorized chain missing"))?;
    let body = json!({"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to": format!("0x{}", hex::encode(chain.state_manager.0)), "data": format!("0x{}", hex::encode(call.abi_encode()))}, "latest"]});
    let value: Value = reqwest::Client::new().post(&fixture.flow.l1.rpc_url).json(&body).send().await?.json().await?;
    ensure!(value.get("error").is_none(), "StateManager call failed");
    let bytes = hex::decode(value["result"].as_str().context("StateManager result missing")?.trim_start_matches("0x"))?;
    Call::abi_decode_returns(&bytes).map_err(|_| anyhow::anyhow!("StateManager ABI return rejected"))
}

async fn finalized_checkpoint(fixture: &Fixture, required: u64) -> anyhow::Result<bool> {
    Ok(l1_view(fixture, lastFinalizedCheckpointIdCall {}).await? >= required)
}

#[tokio::test]
#[ignore = "requires explicitly provisioned disposable real-network fixture; execution pending QA gate"]
async fn guardian_acceptance() {
    let fixture = Fixture::load().unwrap_or_else(|error| panic!("guardian fixture rejected: {error}"));
    let mut children = Children(Vec::new());
    let result = timeout(fixture.session * 12, scenario(&fixture, &mut children)).await;
    let mut cleanup_ok = true;
    for index in (0..children.0.len()).rev() { cleanup_ok &= children.stop(index).await.is_ok(); }
    assert!(cleanup_ok, "could not reap an owned acceptance child");
    match result {
        Ok(Ok(())) => (),
        Ok(Err(error)) => panic!("guardian acceptance failed: {error}"),
        Err(_) => panic!("guardian acceptance overall deadline exceeded"),
    }
}

#[tokio::test]
#[ignore = "typed secret-consuming child of guardian acceptance; parent supplies only manifest path and operation name"]
async fn guardian_user_operation() {
    let operation = std::env::var("GUARDIAN_ACCEPTANCE_OPERATION").unwrap_or_else(|_| panic!("operation name missing"));
    let fixture = Fixture::load_config(false, operation == "deposit").unwrap_or_else(|error| panic!("guardian fixture rejected: {error}"));
    let result = run_user_operation(&fixture, &operation).await;
    let (status, hash) = match &result {
        Ok(value) => (value.status.clone(), value.transaction_hash.clone()),
        Err(_) => ("failed".to_string(), None),
    };
    let path = fixture.root.join("operations").join(format!("{operation}.json"));
    write_exclusive(&path, serde_json::to_vec(&json!({"operation": operation, "transaction_hash": hash, "status": status})).unwrap_or_default().as_slice()).unwrap_or_else(|error| panic!("operation evidence rejected: {error}"));
    result.unwrap_or_else(|error| panic!("user operation failed: {error}"));
}

struct OperationOutput { status: String, transaction_hash: Option<String> }

async fn run_user_operation(fixture: &Fixture, operation: &str) -> anyhow::Result<OperationOutput> {
    let rpc = fixture.path("relayer_rpc_config")?;
    let note = fixture.limbs("note_secret")?;
    let nullifier = fixture.limbs("nullifier_secret")?;
    let claimant = fixture.claimant()?;
    let amount = fixture.amount()?;
    let l1_password = String::from_utf8(read(&fixture.path("l1_password_path")?)?).map_err(|_| anyhow::anyhow!("L1 password rejected"))?;
    let l1 = Wallet::load_encrypted_keystore(&fixture.path("l1_keystore_path")?, l1_password.trim()).map_err(|_| anyhow::anyhow!("L1 keystore rejected"))?;
    let claimant_password = String::from_utf8(read(&fixture.path("claimant_password_path")?)?).map_err(|_| anyhow::anyhow!("claimant password rejected"))?;
    let wallet = psy_client_common::args::WalletSourceArgs { sign_type: psy_client_common::args::SignType::ZKSign, private_key: None, keystore_path: Some(fixture.path("claimant_keystore_path")?.display().to_string()), wallet_password: Some(claimant_password.trim().to_string()), fingerprint: None, sd_key_allowed_contract_id: Vec::new(), sd_key_allowed_method_id: Vec::new(), sd_key_expected_tx_count: 2 };
    match operation {
        "deposit" => {
            let result = psy_user_cli::subcommand::deposit::run(psy_user_cli::subcommand::args::DepositArgs {
                l1_rpc_url: fixture.flow.l1.rpc_url.clone(), private_key: Some(l1.private_key_hex()), router_address: fixture.flow.router.clone(), token: fixture.text("token")?, amount: amount.to_string(), shield_address: String::new(), r0: fixture.manifest["r0"].as_u64(), r1: fixture.manifest["r1"].as_u64(), user_id: Some(claimant), note_commitment: None, note_secret: Some(note), nullifier_secret: Some(nullifier), recipient_npub: None, nostr_relay: "wss://relay.nostr.band".to_string(), l2_token_contract_id: fixture.flow.mapping.l2_contract_id.to_string(), source_chain_index: u32::from(fixture.flow.l1.chain_index), rpc_config: rpc.display().to_string(), deposit_proof_output: Some(fixture.path("deposit_proof_path")?.display().to_string()), resume_deposit_index: None, resume_tx_hash: None, resume_chain_id: None,
            }).await?;
            l1_status(result)
        }
        "claim-deposit" => {
            let proof = json_value(&read(&fixture.path("deposit_proof_path")?)?)?;
            let deposit_index = proof["deposit_index"].as_str().context("deposit index missing")?.parse::<u64>().map_err(|_| anyhow::anyhow!("deposit index rejected"))?;
            let result = psy_user_cli::subcommand::claim_deposit::run(psy_user_cli::subcommand::args::ClaimDepositArgs {
                rpc_config: rpc.display().to_string(), wallet, l1_rpc_url: fixture.flow.l1.rpc_url.clone(), token_l1_address: fixture.text("token")?, amount, source_chain_index: u32::from(fixture.flow.l1.chain_index), user_id: claimant, deposit_index, checkpoint_id: None, r0: fixture.manifest["r0"].as_u64().context("r0 missing")?, r1: fixture.manifest["r1"].as_u64().context("r1 missing")?, note_secret: None, nullifier_secret: None, deposit_proof: fixture.path("deposit_proof_path")?.display().to_string(),
            }).await?;
            included_status(result)
        }
        "withdraw" => {
            let result = psy_user_cli::subcommand::withdraw::run(psy_user_cli::subcommand::args::WithdrawArgs {
                rpc_config: rpc.display().to_string(), wallet, destination_chain_index: u64::from(fixture.flow.l1.chain_index), token_address: fixture.text("token")?, amount, recipient: fixture.text("recipient")?, nonce: fixture.text("withdrawal_nonce")?, l1_rpc_url: fixture.flow.l1.rpc_url.clone(), contract_id: Some(u64::from(fixture.flow.mapping.l2_contract_id)),
            }).await?;
            included_status(result)
        }
        "claim-withdrawal" => {
            let result = psy_user_cli::subcommand::claim_withdrawal::run(psy_user_cli::subcommand::args::ClaimWithdrawalArgs {
                rpc_config: rpc.display().to_string(), services_url: fixture.flow.services_url.clone(), l1_rpc_url: fixture.flow.l1.rpc_url.clone(), private_key: l1.private_key_hex(), recipient: fixture.text("recipient")?, token_address: fixture.text("token")?, amount: amount.to_string(), nonce: fixture.text("withdrawal_nonce")?, destination_chain_index: u64::from(fixture.flow.l1.chain_index), sender_user_id: Some(claimant), prove_proxy_url: Some(fixture.flow.prove_proxy_url.clone()), prove_proxy_token: None,
            }).await?;
            confirmed_claim(result)
        }
        _ => anyhow::bail!("unknown user operation"),
    }
}

fn l1_status(result: psy_user_cli::result::CommandResult) -> anyhow::Result<OperationOutput> {
    match result {
        psy_user_cli::result::CommandResult::L1Transaction(value) => Ok(OperationOutput { status: format!("{:?}", value.status).to_ascii_lowercase(), transaction_hash: value.transaction_hash }),
        _ => anyhow::bail!("unexpected command result"),
    }
}
fn included_status(result: psy_user_cli::result::CommandResult) -> anyhow::Result<OperationOutput> {
    match result {
        psy_user_cli::result::CommandResult::Transaction(value) if matches!(value.status, psy_user_cli::result::TransactionStatus::Confirmed) => Ok(OperationOutput { status: "included".to_string(), transaction_hash: Some(value.transaction_hash.to_string()) }),
        _ => anyhow::bail!("claimant operation was not included"),
    }
}
fn confirmed_claim(result: psy_user_cli::result::CommandResult) -> anyhow::Result<OperationOutput> {
    match result {
        psy_user_cli::result::CommandResult::L1Transaction(value) if matches!(value.status, psy_user_cli::result::L1TransactionStatus::Confirmed) && value.transaction_hash.is_some() => Ok(OperationOutput { status: "confirmed".to_string(), transaction_hash: value.transaction_hash }),
        psy_user_cli::result::CommandResult::L1Transaction(_) => anyhow::bail!("L1 claim was not a confirmed mined transaction"),
        _ => anyhow::bail!("unexpected command result"),
    }
}
