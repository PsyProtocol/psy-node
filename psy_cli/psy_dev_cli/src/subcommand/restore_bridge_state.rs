//! Offline replacement of all four bridge journals with authenticated checkpoint state.
use std::{collections::{BTreeMap, BTreeSet}, ffi::{CString, OsStr}, fs::File, io::{Read, Seek, SeekFrom, Write}, os::{fd::{AsRawFd, FromRawFd}, unix::fs::MetadataExt}, path::PathBuf};
use anyhow::{Context, ensure};
use bincode::Options;
use clap::Args;
use guardian_common::protocol::{decode_record, parse_canonical_json, validate_changed_deposit_tree_states, DepositTreeState, GuardianAccount, GuardianAccountState, GuardianConfig, GuardianSession, GuardianSessionRecord, GuardianSignRequest, GuardianSigned, BRIDGE_USER_ID};
use redb::{ReadableTable, ReadableTableMetadata, TableHandle};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use super::{bridge_database::*, bridge_state_snapshot::{self, BridgeJournalSnapshot}, rollback::{ProcessorConfig, ProcessorRole, require_shutdown_sentinel, endpoint_is_reachable, MAX_PROBE_TIMEOUT_MS}};

#[derive(Args, Debug)]
pub struct RestoreBridgeStateArgs {
    #[arg(long = "processor-config", required = true)]
    pub processor_configs: Vec<PathBuf>,
    /// Explicit roles, in processor-config order.
    #[arg(long = "processor-role", value_enum, required = true)]
    pub processor_roles: Vec<ProcessorRole>,
    #[arg(long = "rp-path", required = true)]
    pub rp_paths: Vec<PathBuf>,
    #[arg(long)]
    pub target: u64,
    #[arg(long = "stop-sentinel")]
    pub stop_sentinel: PathBuf,
    #[arg(long = "guardians-root")]
    pub guardians_root: PathBuf,
    #[arg(long = "proof-dir")]
    pub proof_dir: PathBuf,
    #[arg(long = "rpc-config")]
    pub rpc_config: PathBuf,
    #[arg(long = "chain-document", required = true)]
    pub chain_documents: Vec<PathBuf>,
    #[arg(long = "coordinator-endpoint", required = true)]
    pub coordinator_endpoints: Vec<String>,
    #[arg(long = "realm-endpoint", required = true)]
    pub realm_endpoints: Vec<String>,
    #[arg(long = "probe-timeout-ms", default_value_t = 500)]
    pub probe_timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct FileIdentity { device: u64, inode: u64, digest: String }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RestoreOperation {
    operation_id: String,
    target_digest: String,
    journals: Vec<FileIdentity>,
    backups: Vec<String>,
    proofs: BTreeMap<String, FileIdentity>,
    proof_directory: (u64, u64),
}

#[derive(Serialize, Deserialize)]
struct BackupIdentity { original: FileIdentity, logical_digest: String }

fn table_digest<K: redb::Key + 'static, V: redb::Value + 'static>(transaction: &redb::ReadTransaction, definition: redb::TableDefinition<K,V>, hash: &mut Sha256) -> anyhow::Result<()> {
    hash.update(definition.name().as_bytes());
    let table = transaction.open_table(definition)?;
    hash.update(table.len()?.to_le_bytes());
    for row in table.iter()? {
        let (key,value) = row?;
        let key = key.value(); let value = value.value();
        let key_bytes = K::as_bytes(&key); let value_bytes = V::as_bytes(&value);
        for bytes in [key_bytes.as_ref(),value_bytes.as_ref()] { hash.update((bytes.len() as u64).to_le_bytes()); hash.update(bytes); }
    }
    Ok(())
}

fn journal_digest(database: &redb::Database, relayer: bool) -> anyhow::Result<String> {
    let transaction = database.begin_read()?; let mut hash = Sha256::new();
    table_digest(&transaction,GUARDIAN_ACCOUNT,&mut hash)?;
    if relayer {
        table_digest(&transaction,JOURNAL_SCHEMA,&mut hash)?;
        table_digest(&transaction,RELAYER_REQUEST,&mut hash)?;
        table_digest(&transaction,CHAIN_CLAIMS,&mut hash)?;
        table_digest(&transaction,FINALIZATION_BATCH,&mut hash)?;
        table_digest(&transaction,RELAYER_DEPOSIT_TREE_STATES,&mut hash)?;
        table_digest(&transaction,RELAYER_INCLUDED_WITHDRAWAL_BURNS,&mut hash)?;
        table_digest(&transaction,RELAYER_WITHDRAWAL_NONCE,&mut hash)?;
    } else {
        table_digest(&transaction,GUARDIAN_SCHEMA,&mut hash)?;
        table_digest(&transaction,GUARDIAN_SIGNER,&mut hash)?;
        table_digest(&transaction,GUARDIAN_SIGNED,&mut hash)?;
        table_digest(&transaction,GUARDIAN_SESSION,&mut hash)?;
        table_digest(&transaction,GUARDIAN_DEPOSIT_TREE_STATES,&mut hash)?;
        table_digest(&transaction,GUARDIAN_INCLUDED_WITHDRAWAL_BURNS,&mut hash)?;
        table_digest(&transaction,GUARDIAN_WITHDRAWAL_NONCE,&mut hash)?;
    }
    Ok(hex::encode(hash.finalize()))
}

pub async fn run(args: RestoreBridgeStateArgs) -> anyhow::Result<()> {
    ensure!((1..=MAX_PROBE_TIMEOUT_MS).contains(&args.probe_timeout_ms), "invalid probe timeout");
    require_shutdown_sentinel(&args.stop_sentinel).await?;
    let config = GuardianConfig::load(&args.rpc_config, &args.guardians_root, &args.chain_documents).await?;
    let (processors, inventory_digest) = load_inventory(&args, &config).await?;
    reject_reachable(&args, &config).await?;
    let snapshot = bridge_state_snapshot::build_bridge_journal_snapshot(args.target, &processors, &config).await?;
    validate_snapshot(&snapshot, &config, args.target)?;
    let root = open_absolute_directory(&absolute_path(&args.guardians_root)?)?;
    let directory = open_at(&root, OsStr::new("db"), libc::O_RDONLY | libc::O_DIRECTORY)?.context("missing journal directory")?;
    validate_directory(&directory, true)?;
    let proofs = open_absolute_directory(&absolute_path(&args.proof_dir)?)?;
    let databases = open_databases(&directory)?;
    check_database_bindings(&directory, &databases, true)?;
    validate_signers(&databases, &config)?;
    // Locks remain held through done publication. Recheck offline attestation after reconstruction.
    require_shutdown_sentinel(&args.stop_sentinel).await?;
    reject_reachable(&args, &config).await?;
    let digest = snapshot_digest(&snapshot)?;
    let operation_id = operation_id(&config, &inventory_digest, &digest, &directory, &proofs)?;
    apply(&directory, &proofs, &databases, &snapshot, &operation_id, &digest, &config)?;
    println!("Journal restore complete at checkpoint {} (operation {}). L1 is unchanged. Erasing local rows does not revoke external signature copies. Nonces at or below the restored nonce remain consumed; erased history is no longer locally fetchable. A guardian missing that history needs offline recovery. Pre-existing unclaimed withdrawals are not re-queued. This is not full bridge recovery.", args.target, operation_id);
    Ok(())
}

fn encode<T: Serialize>(value: &T) -> anyhow::Result<Vec<u8>> {
    Ok(bincode::options().with_fixint_encoding().reject_trailing_bytes().serialize(value)?)
}
fn snapshot_digest(snapshot: &BridgeJournalSnapshot) -> anyhow::Result<String> {
    Ok(hex::encode(Sha256::digest(encode(&(&snapshot.account, &snapshot.deposits, &snapshot.withdrawals))?)))
}
fn inclusion_metadata(snapshot: &BridgeJournalSnapshot) -> anyhow::Result<(BTreeMap<[u8; 56], u64>, BTreeMap<[u8; 49], u64>)> {
    let mut burns = BTreeMap::new();
    let mut nonces = BTreeMap::new();
    for (append, nonce) in &snapshot.withdrawals {
        let burn = &append.burn;
        let burn_key = withdrawal_burn_key_bytes(snapshot.account.network_magic, snapshot.account.user_id, burn.sender_user_id, burn.token_contract_id, &burn.nonce);
        let nonce_key = nonce_key_bytes(snapshot.account.network_magic, snapshot.account.user_id, append.chain_index, &burn.nonce);
        burns.insert(burn_key, burns.get(&burn_key).copied().unwrap_or(0).max(*nonce));
        nonces.insert(nonce_key, nonces.get(&nonce_key).copied().unwrap_or(0).max(*nonce));
    }
    Ok((burns, nonces))
}
fn validate_snapshot(snapshot: &BridgeJournalSnapshot, config: &GuardianConfig, target: u64) -> anyhow::Result<()> {
    snapshot.account.validate()?;
    ensure!(snapshot.account.state == GuardianAccountState::Active && snapshot.account.last_checkpoint_id == target && snapshot.account.network_magic == config.network_magic()? && snapshot.account.account_public_key == config.account_public_key()? && snapshot.account.user_id == config.user_id(), "snapshot identity mismatch");
    let mut chains = BTreeSet::new();
    for state in &snapshot.deposits {
        state.validate()?;
        config.chain(state.anchor.chain_index)?;
        ensure!(chains.insert(state.anchor.chain_index), "duplicate deposit chain");
    }
    let mut coordinates = BTreeSet::new();
    let mut counts = BTreeMap::<u8,u32>::new();
    for (append, nonce) in &snapshot.withdrawals {
        ensure!(*nonce > 0 && Some(*nonce) <= snapshot.account.imported_nonce, "invalid inclusion nonce");
        ensure!(append.chain_index == append.burn.destination_chain_index, "withdrawal chain mismatch");
        ensure!(coordinates.insert((append.chain_index, append.append_index)), "duplicate append coordinate");
        let count = counts.entry(append.chain_index).or_default();
        ensure!(*count == append.append_index, "withdrawal indexes are not contiguous");
        *count = count.checked_add(1).context("withdrawal count overflow")?;
    }
    let expected: BTreeMap<_,_> = snapshot.account.withdrawal_chains.iter().filter(|(_,count,_,_)| *count > 0).map(|(chain,count,_,_)| (*chain,*count)).collect();
    ensure!(counts == expected, "withdrawal index coverage differs from authenticated account");
    Ok(())
}

fn validate_signers(databases: &[HeldDatabase], config: &GuardianConfig) -> anyhow::Result<()> {
    for (index, held) in databases.iter().take(3).enumerate() {
        let transaction = held.database.as_ref().context("missing guardian")?.begin_read()?;
        let table = transaction.open_table(GUARDIAN_SIGNER)?;
        ensure!(table.len()? == 1, "guardian signer missing");
        let signer = table.get(())?.context("guardian signer missing")?.value();
        use plonky2::{field::goldilocks_field::GoldilocksField, hash::poseidon::PoseidonPermutation};
        use psy_crypto::signature::secp256k1::wallet::hash_no_pad_compressed_public_key;
        let hash = hash_no_pad_compressed_public_key::<GoldilocksField, PoseidonPermutation<GoldilocksField>>(psy_client_common::data::secp256k1::CompressedPublicKey::new_from_slice(&signer));
        ensure!(hash == config.network.guardian_initial_member_hashes.context("configured guardian members missing")?[index], "guardian signer differs from configured identity");
    }
    Ok(())
}
fn canonical_codec() -> impl bincode::Options { bincode::options().with_fixint_encoding().reject_trailing_bytes() }
fn canonical_bincode<T: Serialize + for<'de> Deserialize<'de>>(bytes: &[u8]) -> anyhow::Result<T> {
    let value: T = canonical_codec().deserialize(bytes)?;
    ensure!(canonical_codec().serialize(&value)?.as_slice() == bytes, "durable row is not canonical");
    Ok(value)
}
fn canonical_json<T: Serialize + for<'de> Deserialize<'de>>(bytes: &[u8]) -> anyhow::Result<T> {
    let value: T = serde_json::from_slice(bytes).context("durable row rejected")?;
    ensure!(serde_json::to_vec(&value)? == bytes, "durable row is not canonical");
    Ok(value)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum RelayerRequest {
    Request { request: String, deposit_tree_states: Vec<DepositTreeState> },
    Signed { request: String, deposit_tree_states: Vec<DepositTreeState>, signatures: String },
    Proved { request: String, deposit_tree_states: Vec<DepositTreeState>, signatures: String, endcap: Vec<u8> },
    Included { record: GuardianSessionRecord },
}
fn relayer_request_nonce(bytes: &[u8], key: u64, config: &GuardianConfig) -> anyhow::Result<u64> {
    ensure!(key != 0, "relayer request row rejects nonce zero");
    let json = decode_record(bytes).map_err(|error| anyhow::anyhow!(error)).context("relayer request row rejected")?;
    let value: RelayerRequest = canonical_json(&json)?;
    let (text, states, signatures) = match &value {
        RelayerRequest::Request { request, deposit_tree_states } => (request, deposit_tree_states, None),
        RelayerRequest::Signed { request, deposit_tree_states, signatures } => (request, deposit_tree_states, Some(signatures.as_str())),
        RelayerRequest::Proved { request, deposit_tree_states, signatures, endcap } => {
            ensure!(!endcap.is_empty(), "archived proof is empty");
            (request, deposit_tree_states, Some(signatures.as_str()))
        }
        RelayerRequest::Included { record } => {
            let nonce = record.validate(config).map_err(|error| anyhow::anyhow!(error))?.session_nonce;
            ensure!(nonce == key, "archived guardian request nonce mismatch");
            return Ok(nonce);
        }
    };
    let parsed = GuardianSignRequest::parse_retained(text.as_bytes()).map_err(|error| anyhow::anyhow!(error))?;
    parsed.validate_authorization(config).map_err(|error| anyhow::anyhow!(error))?;
    validate_changed_deposit_tree_states(&parsed, states).map_err(|error| anyhow::anyhow!(error))?;
    if let Some(signatures) = signatures {
        let parsed: serde_json::Value = parse_canonical_json(signatures.as_bytes()).map_err(|error| anyhow::anyhow!(error))?;
        ensure!(parsed.is_object(), "relayer signature row is not canonical");
    }
    ensure!(parsed.session_nonce == key, "archived guardian request nonce mismatch");
    Ok(parsed.session_nonce)
}
fn account_cursor(account: &GuardianAccount, config: &GuardianConfig, target: &GuardianAccount) -> anyhow::Result<u64> {
    account.validate().map_err(|error| anyhow::anyhow!(error))?;
    ensure!(account.state == GuardianAccountState::Active && account.halt_reason.is_none(), "journal account is not active");
    ensure!(account.network_magic == target.network_magic && account.user_id == target.user_id && account.account_public_key == config.account_public_key().context("configured account key")?, "journal account identity mismatch");
    let nonce = account.imported_nonce.unwrap_or(0);
    let bound = target.imported_nonce.context("nonce-zero restore is unsupported until an authenticated starting leaf is carried separately")?;
    ensure!(nonce <= bound, "journal cursor {nonce} is above authenticated bridge nonce {bound}; restoring would reuse a signing nonce");
    if nonce == bound {
        ensure!(account.imported_nonce.is_some() && account.imported_ending_leaf == target.imported_ending_leaf, "journal ending leaf at nonce {bound} differs from the authenticated leaf");
    }
    Ok(bound)
}
fn refuse_signed_boundary(database: &redb::Database, relayer: bool, config: &GuardianConfig, target: &GuardianAccount) -> anyhow::Result<()> {
    let transaction = database.begin_read()?;
    let accounts = transaction.open_table(GUARDIAN_ACCOUNT)?;
    ensure!(accounts.len()? == 1, "journal account missing");
    let (key, row) = accounts.iter()?.next().transpose()?.context("journal account missing")?;
    let account: GuardianAccount = canonical_bincode(row.value())?;
    ensure!(key.value() == (account.network_magic, account.user_id), "account key differs from encoded identity");
    let bound = account_cursor(&account, config, target)?;
    if relayer {
        for row in transaction.open_table(RELAYER_REQUEST)?.iter()? {
            let (key, value) = row?;
            ensure!(relayer_request_nonce(value.value(), key.value(), config)? <= bound, "retained relayer request is above the authenticated bridge nonce");
        }
    } else {
        for row in transaction.open_table(GUARDIAN_SIGNED)?.iter()? {
            let (key, value) = row?;
            let key = key.value();
            let inner = decode_record(value.value()).map_err(|error| anyhow::anyhow!(error))?;
            let signed: GuardianSigned = canonical_bincode(&inner)?;
            signed.validate().map_err(|error| anyhow::anyhow!(error))?;
            config.validate_signed(&signed).map_err(|error| anyhow::anyhow!(error))?;
            ensure!((signed.network_magic, signed.user_id, signed.nonce) == key, "signed key differs from encoded identity");
            ensure!(signed.nonce <= bound, "retained signed row is above the authenticated bridge nonce");
        }
        for row in transaction.open_table(GUARDIAN_SESSION)?.iter()? {
            let (key, value) = row?;
            let key = key.value();
            let inner = decode_record(value.value()).map_err(|error| anyhow::anyhow!(error))?;
            let session: GuardianSession = canonical_bincode(&inner)?;
            session.validate(config).map_err(|error| anyhow::anyhow!(error))?;
            ensure!((session.network_magic, session.user_id, session.nonce) == key && session.user_id == BRIDGE_USER_ID, "session key differs from encoded identity");
            ensure!(session.nonce <= bound, "retained session is above the authenticated bridge nonce");
        }
    }
    Ok(())
}
struct InspectionCopy { directory: File, name: String }
impl InspectionCopy {
    fn remove(mut self) -> anyhow::Result<()> {
        let result = remove_file(&self.directory, &self.name).with_context(|| format!("removing inspection copy {}", self.name));
        self.name.clear();
        result
    }
}
impl Drop for InspectionCopy { fn drop(&mut self) { if !self.name.is_empty() { let _ = remove_file(&self.directory, &self.name); } } }
fn inspect_backup(directory: &File, backup: &File, name: &str, expected_digest: &str, relayer: bool, config: &GuardianConfig, target: &GuardianAccount) -> anyhow::Result<()> {
    validate_database_file(backup, true)?;
    ensure!(identity(backup)?.digest == expected_digest, "immutable backup digest mismatch");
    let copy_name = format!(".inspect-{name}");
    let parent = directory.try_clone().context("cloning journal directory")?;
    remove_file(&parent, &copy_name)?;
    let mut copy = open_at(&parent, OsStr::new(&copy_name), libc::O_RDWR | libc::O_CREAT | libc::O_EXCL)?.context("inspection copy creation failed")?;
    let retained = InspectionCopy { directory: parent, name: copy_name };
    let mut reader = backup.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let copied = std::io::copy(&mut reader, &mut copy)?;
    copy.sync_all()?;
    ensure!(copied == backup.metadata()?.len() && identity(&copy)?.digest == expected_digest, "inspection copy differs from immutable backup");
    let database = redb::Database::builder().create_file(copy).context("opening inspection copy")?;
    let checked = refuse_signed_boundary(&database, relayer, config, target);
    drop(database);
    retained.remove()?;
    checked
}
fn validate_original_backups(directory: &File, databases: &[HeldDatabase], operation: &RestoreOperation, config: &GuardianConfig, target: &GuardianAccount) -> anyhow::Result<()> {
    for (index, held) in databases.iter().enumerate() {
        let backup = open_at(directory, OsStr::new(&operation.backups[index]), libc::O_RDONLY)?.context("immutable backup missing")?;
        inspect_backup(directory, &backup, &operation.backups[index], &operation.journals[index].digest, is_relayer(held.name), config, target)?;
    }
    Ok(())
}

fn replace_snapshot(database: &redb::Database, relayer: bool, snapshot: &BridgeJournalSnapshot) -> anyhow::Result<()> {
    let transaction = database.begin_write()?;
    for table in transaction.list_tables()?.collect::<Vec<_>>() {
        if table.name() != "guardian_signer" { transaction.delete_table(table)?; }
    }
    let account = &snapshot.account;
    transaction.open_table(GUARDIAN_ACCOUNT)?.insert((account.network_magic,account.user_id), encode(account)?.as_slice())?;
    if relayer {
        transaction.open_table(JOURNAL_SCHEMA)?.insert((), JOURNAL_SCHEMA_VERSION)?;
        transaction.open_table(RELAYER_REQUEST)?;
        transaction.open_table(CHAIN_CLAIMS)?;
        transaction.open_table(FINALIZATION_BATCH)?;
        let mut deposits = transaction.open_table(RELAYER_DEPOSIT_TREE_STATES)?;
        let mut burns = transaction.open_table(RELAYER_INCLUDED_WITHDRAWAL_BURNS)?;
        let mut nonces = transaction.open_table(RELAYER_WITHDRAWAL_NONCE)?;
        for state in &snapshot.deposits { deposits.insert(RelayerDepositTreeKey(deposit_tree_key_bytes(account.network_magic,account.user_id,state.anchor.chain_index)), encode(state)?.as_slice())?; }
        let (burn_map, nonce_map) = inclusion_metadata(snapshot)?;
        for (key, nonce) in burn_map { burns.insert(RelayerWithdrawalBurnKey(key), nonce)?; }
        for (key, nonce) in nonce_map { nonces.insert(RelayerWithdrawalNonceKey(key), nonce)?; }
    } else {
        transaction.open_table(GUARDIAN_SCHEMA)?.insert((), GUARDIAN_SCHEMA_VERSION)?;
        transaction.open_table(GUARDIAN_SIGNED)?;
        transaction.open_table(GUARDIAN_SESSION)?;
        let mut deposits = transaction.open_table(GUARDIAN_DEPOSIT_TREE_STATES)?;
        let mut burns = transaction.open_table(GUARDIAN_INCLUDED_WITHDRAWAL_BURNS)?;
        let mut nonces = transaction.open_table(GUARDIAN_WITHDRAWAL_NONCE)?;
        for state in &snapshot.deposits { deposits.insert(GuardianDepositTreeKey(deposit_tree_key_bytes(account.network_magic,account.user_id,state.anchor.chain_index)), encode(state)?.as_slice())?; }
        let (burn_map, nonce_map) = inclusion_metadata(snapshot)?;
        for (key, nonce) in burn_map { burns.insert(GuardianWithdrawalBurnKey(key), nonce)?; }
        for (key, nonce) in nonce_map { nonces.insert(GuardianWithdrawalNonceKey(key), nonce)?; }
    }
    transaction.commit()?;
    Ok(())
}

fn verify_snapshot(database: &redb::Database, relayer: bool, snapshot: &BridgeJournalSnapshot) -> anyhow::Result<()> {
    validate_database(database, relayer)?;
    let transaction = database.begin_read()?;
    let accounts = transaction.open_table(GUARDIAN_ACCOUNT)?;
    let account = &snapshot.account;
    let account_bytes = encode(account)?;
    ensure!(accounts.len()? == 1 && accounts.get((account.network_magic,account.user_id))?.is_some_and(|row| row.value() == account_bytes.as_slice()), "account readback mismatch");
    macro_rules! verify_rows {
        ($deposits:expr, $burns:expr, $nonces:expr, $deposit_key:ident, $burn_key:ident, $nonce_key:ident) => {{
            let deposits = transaction.open_table($deposits)?;
            let burns = transaction.open_table($burns)?;
            let nonces = transaction.open_table($nonces)?;
            let (burn_map, nonce_map) = inclusion_metadata(snapshot)?;
            ensure!(deposits.len()? == snapshot.deposits.len() as u64 && burns.len()? == burn_map.len() as u64 && nonces.len()? == nonce_map.len() as u64, "snapshot row count mismatch");
            for state in &snapshot.deposits {
                let key = $deposit_key(deposit_tree_key_bytes(account.network_magic,account.user_id,state.anchor.chain_index));
                let bytes = encode(state)?;
                ensure!(deposits.get(key)?.is_some_and(|row|row.value() == bytes.as_slice()), "deposit readback mismatch");
            }
            for (key, nonce) in &burn_map {
                ensure!(burns.get($burn_key(*key))?.is_some_and(|row|row.value() == *nonce), "burn readback mismatch");
            }
            for (key, nonce) in &nonce_map {
                ensure!(nonces.get($nonce_key(*key))?.is_some_and(|row|row.value() == *nonce), "nonce readback mismatch");
            }
        }};
    }
    if relayer {
        ensure!(transaction.open_table(RELAYER_REQUEST)?.is_empty()? && transaction.open_table(CHAIN_CLAIMS)?.is_empty()? && transaction.open_table(FINALIZATION_BATCH)?.is_empty()?, "relayer runtime rows remain");
        verify_rows!(RELAYER_DEPOSIT_TREE_STATES,RELAYER_INCLUDED_WITHDRAWAL_BURNS,RELAYER_WITHDRAWAL_NONCE,RelayerDepositTreeKey,RelayerWithdrawalBurnKey,RelayerWithdrawalNonceKey);
    } else {
        ensure!(transaction.open_table(GUARDIAN_SIGNED)?.is_empty()? && transaction.open_table(GUARDIAN_SESSION)?.is_empty()?, "guardian session rows remain");
        verify_rows!(GUARDIAN_DEPOSIT_TREE_STATES,GUARDIAN_INCLUDED_WITHDRAWAL_BURNS,GUARDIAN_WITHDRAWAL_NONCE,GuardianDepositTreeKey,GuardianWithdrawalBurnKey,GuardianWithdrawalNonceKey);
    }
    Ok(())
}

fn operation_id(config: &GuardianConfig, inventory_digest: &str, digest: &str, directory: &File, proofs: &File) -> anyhow::Result<String> {
    let mut hash = Sha256::new();
    hash.update(b"psy-bridge-reset-operation-v1");
    hash.update(digest);
    hash.update(inventory_digest);
    hash.update(Sha256::digest(serde_json::to_vec(&config.network)?));
    for chain in &config.l1_chains {
        hash.update(Sha256::digest(serde_json::to_vec(&(chain.chain_index,chain.chain_id,chain.bridge,chain.deployment_block,&chain.rpc_url))?));
    }
    for file in [directory, proofs] { let metadata = file.metadata()?; hash.update(metadata.dev().to_le_bytes()); hash.update(metadata.ino().to_le_bytes()); }
    Ok(hex::encode(hash.finalize()))
}
fn identity(file: &File) -> anyhow::Result<FileIdentity> {
    let metadata = file.metadata()?;
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop { let size = reader.read(&mut buffer)?; if size == 0 { break; } hash.update(&buffer[..size]); }
    Ok(FileIdentity { device: metadata.dev(), inode: metadata.ino(), digest: hex::encode(hash.finalize()) })
}
fn read_operation(directory: &File, name: &str) -> anyhow::Result<Option<RestoreOperation>> {
    let Some(mut file) = open_at(directory, OsStr::new(name), libc::O_RDONLY)? else { return Ok(None); };
    validate_database_file(&file, true)?;
    let mut bytes = Vec::new(); file.read_to_end(&mut bytes)?;
    Ok(Some(serde_json::from_slice(&bytes)?))
}
fn create_file(directory: &File, name: &str) -> anyhow::Result<File> {
    let name = CString::new(name)?;
    let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o600) };
    ensure!(fd >= 0, "exclusive artifact creation failed: {}", std::io::Error::last_os_error());
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn remove_file(directory: &File, name: &str) -> anyhow::Result<()> {
    let name = CString::new(name)?;
    let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
    if result != 0 { let error = std::io::Error::last_os_error(); if error.kind() != std::io::ErrorKind::NotFound { return Err(error.into()); } }
    Ok(())
}
fn publish(directory: &File, name: &str, bytes: &[u8]) -> anyhow::Result<()> {
    let temporary = format!("{name}.tmp");
    // Temporary files are never authoritative; no journal commit precedes published intent.
    remove_file(directory, &temporary)?;
    let mut file = create_file(directory, &temporary)?;
    file.write_all(bytes)?; file.sync_all()?;
    let from = CString::new(temporary)?; let to = CString::new(name)?;
    let result = unsafe { libc::renameat2(directory.as_raw_fd(),from.as_ptr(),directory.as_raw_fd(),to.as_ptr(),libc::RENAME_NOREPLACE) };
    ensure!(result == 0, "artifact publication failed: {}", std::io::Error::last_os_error());
    directory.sync_all()?;
    Ok(())
}
fn proof_target(name: &str) -> Option<u64> {
    let stem = name.strip_prefix("bridge_proof_")?.strip_suffix(".json")?;
    let (checkpoint, chain) = stem.split_once("_chain_").map_or((stem,None), |(checkpoint,chain)| (checkpoint,Some(chain)));
    if let Some(chain) = chain { chain.parse::<u8>().ok()?; }
    checkpoint.parse().ok()
}
fn collect_proofs(directory: &File, target: u64) -> anyhow::Result<BTreeMap<String, FileIdentity>> {
    let mut proofs = BTreeMap::new();
    for name in directory_names(directory)? {
        let Some(name) = name.to_str() else { continue; };
        if !proof_target(name).is_some_and(|checkpoint| checkpoint > target) { continue; }
        let file = open_at(directory, OsStr::new(name), libc::O_RDONLY)?.context("proof disappeared")?;
        let metadata = file.metadata()?;
        ensure!(metadata.is_file() && metadata.nlink() == 1 && metadata.uid() == unsafe { libc::geteuid() }, "untrusted proof file");
        proofs.insert(name.to_owned(), identity(&file)?);
    }
    Ok(proofs)
}
fn apply(directory: &File, proofs: &File, databases: &[HeldDatabase], snapshot: &BridgeJournalSnapshot, operation_id: &str, digest: &str, config: &GuardianConfig) -> anyhow::Result<()> {
    let intent_name = "bridge-restore.intent.json";
    let done_name = format!("bridge-restore.{operation_id}.done.json");
    let prior = read_operation(directory, intent_name)?;
    if let Some(done) = read_operation(directory, &done_name)? {
        ensure!(prior.as_ref().is_none_or(|intent| intent == &done), "another restore is incomplete");
        ensure!(done.operation_id == operation_id && done.target_digest == digest, "done identity conflict");
        validate_artifacts(directory,proofs,databases,&done)?;
        validate_original_backups(directory, databases, &done, config, &snapshot.account)?;
        for held in databases { verify_snapshot(held.database.as_ref().context("journal missing")?, is_relayer(held.name), snapshot)?; }
        ensure!(collect_proofs(proofs,snapshot.account.last_checkpoint_id)?.is_empty(), "new proofs appeared after completed restore");
        if prior.is_some() { remove_file(directory,intent_name)?; directory.sync_all()?; }
        return Ok(());
    }
    let resumed = prior.is_some();
    if !resumed {
        for held in databases { refuse_signed_boundary(held.database.as_ref().context("journal missing")?, is_relayer(held.name), config, &snapshot.account)?; }
    }
    let operation = if let Some(prior) = prior {
        ensure!(prior.operation_id == operation_id && prior.target_digest == digest, "another restore is incomplete");
        prior
    } else {
        let mut journals = Vec::new(); let mut backups = Vec::new();
        for held in databases {
            let source = held.file.as_ref().context("journal missing")?;
            let mut original = identity(source)?;
            let logical_digest = journal_digest(held.database.as_ref().context("journal missing")?,is_relayer(held.name))?;
            let backup_name = format!("{}.pre-restore-{operation_id}", held.name);
            let metadata_name = format!("{backup_name}.identity.json");
            if let Some(backup) = open_at(directory, OsStr::new(&backup_name), libc::O_RDONLY)? {
                validate_database_file(&backup,true)?;
                let mut metadata_file = open_at(directory,OsStr::new(&metadata_name),libc::O_RDONLY)?.context("backup identity missing")?;
                validate_database_file(&metadata_file,true)?;
                let mut bytes = Vec::new(); metadata_file.read_to_end(&mut bytes)?;
                let saved: BackupIdentity = serde_json::from_slice(&bytes)?;
                ensure!(saved.logical_digest == logical_digest && (saved.original.device,saved.original.inode) == (original.device,original.inode), "pre-intent journal contents changed");
                ensure!(identity(&backup)?.digest == saved.original.digest, "pre-intent backup digest mismatch");
                original = saved.original;
            } else {
                // No published backup exists, so a stale pre-backup identity is not original evidence.
                remove_file(directory,&metadata_name)?;
                publish(directory,&metadata_name,&serde_json::to_vec(&BackupIdentity { original: original.clone(), logical_digest })?)?;
                let temporary = format!("{backup_name}.tmp");
                remove_file(directory, &temporary)?;
                let mut backup = create_file(directory, &temporary)?;
                let mut reader = source.try_clone()?; reader.seek(SeekFrom::Start(0))?;
                std::io::copy(&mut reader,&mut backup)?; backup.sync_all()?;
                let from = CString::new(temporary)?; let to = CString::new(backup_name.as_str())?;
                ensure!(unsafe { libc::renameat2(directory.as_raw_fd(),from.as_ptr(),directory.as_raw_fd(),to.as_ptr(),libc::RENAME_NOREPLACE) } == 0, "backup publication failed");
                directory.sync_all()?;
            }
            journals.push(original); backups.push(backup_name);
        }
        let metadata = proofs.metadata()?;
        let operation = RestoreOperation { operation_id: operation_id.to_owned(), target_digest: digest.to_owned(), journals, backups, proofs: collect_proofs(proofs,snapshot.account.last_checkpoint_id)?, proof_directory: (metadata.dev(),metadata.ino()) };
        publish(directory,intent_name,&serde_json::to_vec(&operation)?)?;
        operation
    };
    validate_artifacts(directory,proofs,databases,&operation)?;
    validate_original_backups(directory, databases, &operation, config, &snapshot.account)?;
    let remaining = collect_proofs(proofs,snapshot.account.last_checkpoint_id)?;
    ensure!(remaining.iter().all(|(name,identity)| operation.proofs.get(name) == Some(identity)), "proof set changed since intent");
    check_database_bindings(directory,databases,true)?;
    for held in databases {
        let database = held.database.as_ref().context("journal missing")?;
        replace_snapshot(database,is_relayer(held.name),snapshot)?;
        verify_snapshot(database,is_relayer(held.name),snapshot)?;
    }
    check_database_bindings(directory,databases,true)?;
    for (name, expected) in &operation.proofs {
        if let Some(file) = open_at(proofs,OsStr::new(name),libc::O_RDONLY)? {
            let metadata = file.metadata()?;
            ensure!(metadata.is_file() && metadata.nlink() == 1 && metadata.uid() == unsafe { libc::geteuid() }, "untrusted proof file");
            ensure!(identity(&file)? == *expected, "proof identity changed");
            remove_file(proofs,name)?;
        }
    }
    proofs.sync_all()?;
    ensure!(collect_proofs(proofs,snapshot.account.last_checkpoint_id)?.is_empty(), "proof files appeared during restore");
    publish(directory,&done_name,&serde_json::to_vec(&operation)?)?;
    remove_file(directory,intent_name)?; directory.sync_all()?;
    Ok(())
}

fn validate_artifacts(directory: &File, proofs: &File, databases: &[HeldDatabase], operation: &RestoreOperation) -> anyhow::Result<()> {
    ensure!(operation.journals.len() == 4 && operation.backups.len() == 4, "invalid journal inventory in intent");
    let metadata = proofs.metadata()?;
    ensure!(operation.proof_directory == (metadata.dev(),metadata.ino()), "proof directory identity changed");
    for (index,held) in databases.iter().enumerate() {
        let current = held.file.as_ref().context("journal missing")?.metadata()?;
        ensure!((current.dev(),current.ino()) == (operation.journals[index].device,operation.journals[index].inode), "journal inode changed");
        ensure!(operation.backups[index] == format!("{}.pre-restore-{}",held.name,operation.operation_id), "backup name conflict");
        let backup = open_at(directory,OsStr::new(&operation.backups[index]),libc::O_RDONLY)?.context("immutable backup missing")?;
        validate_database_file(&backup,true)?;
        ensure!(identity(&backup)?.digest == operation.journals[index].digest, "immutable backup digest mismatch");
    }
    check_database_bindings(directory,databases,true)?;
    Ok(())
}

async fn reject_reachable(args: &RestoreBridgeStateArgs, config: &GuardianConfig) -> anyhow::Result<()> {
    let timeout = std::time::Duration::from_millis(args.probe_timeout_ms);
    for endpoint in args.coordinator_endpoints.iter().chain(&args.realm_endpoints).chain(config.network.coordinator_configs.iter().flat_map(|entry| &entry.rpc_url)).chain(config.network.realm_configs.iter().flat_map(|entry| &entry.rpc_url)) {
        ensure!(!endpoint_is_reachable(endpoint,timeout).await?, "processor endpoint remains reachable");
    }
    Ok(())
}

async fn load_inventory(args: &RestoreBridgeStateArgs, config: &GuardianConfig) -> anyhow::Result<(Vec<ProcessorConfig>, String)> {
    use psy_node_common::rollback::{read_rollback_plan,validate_rollback_plan,RollbackPhaseStatus};
    ensure!(args.processor_configs.len() == args.rp_paths.len() && args.processor_roles.len() == args.rp_paths.len(), "processor roles/configs/plans must have equal lengths");
    let mut expected = BTreeSet::new();
    for coordinator in &config.network.coordinator_configs { ensure!(expected.insert((0,coordinator.id,0u16)), "duplicate configured coordinator"); }
    ensure!(expected.len() == 1, "exactly one configured coordinator is required");
    for realm in &config.network.realm_configs {
        ensure!(!realm.validators.is_empty(), "configured realm has no processor validator inventory");
        for index in 0..realm.validators.len() { ensure!(expected.insert((1,realm.id,u16::try_from(index+1)?)), "duplicate configured realm processor"); }
    }
    let mut seen = BTreeSet::new(); let mut processors = Vec::new();
    let mut digest = Sha256::new(); digest.update(b"psy-bridge-reset-inventory-v1");
    for ((path, role), rp_path) in args.processor_configs.iter().zip(&args.processor_roles).zip(&args.rp_paths) {
        let path = path.to_str().context("invalid processor config path")?.to_owned();
        let processor = match role {
            ProcessorRole::Coordinator => ProcessorConfig::Coordinator(psy_node_core::config::node_cli_config::CoordinatorProcessorCliConfig::get_start_config(Some(path),None,None,None,None,None,None,None,false,None,None).await?),
            ProcessorRole::Realm => {
                let loaded = psy_node_core::config::node_cli_config::RealmProcessorCliConfig::get_start_config(Some(path),None,None,None,None,None,None,false,None,Vec::new(),None,None,None,None,None).await?;
                let sub = psy_node_cli::node::realm_p2p::resolve_processor_sub_id(&loaded)?;
                ProcessorConfig::Realm(loaded.with_derived_realm_sub_id(sub))
            }
        };
        ensure!(processor.network() == psy_core::constants::chain_id::PsyChainNetworkType::LocalDevnet, "restore requires local devnet");
        let (realm,sub) = processor.realm_identity();
        let identity = (if *role == ProcessorRole::Coordinator {0} else {1},realm,sub);
        ensure!(expected.contains(&identity) && seen.insert(identity), "unexpected or duplicate processor");
        let plan = read_rollback_plan(rp_path).await?; validate_rollback_plan(&plan)?;
        ensure!(plan.role == (*role).into() && plan.realm_id == realm && plan.realm_sub_id == u64::from(sub) && plan.target_checkpoint_id == args.target && plan.phases.iter().all(|phase|phase.status == RollbackPhaseStatus::Completed), "rollback plan is not completed for configured processor at target");
        verify_marker(&processor,args.target).await?;
        let loaded = match &processor { ProcessorConfig::Coordinator(value) => serde_json::to_vec(value)?, ProcessorConfig::Realm(value) => serde_json::to_vec(value)? };
        digest.update([identity.0]);
        digest.update(Sha256::digest(loaded));
        digest.update(Sha256::digest(serde_json::to_vec(&plan)?));
        processors.push(processor);
    }
    ensure!(seen == expected, "complete configured processor inventory is required");
    Ok((processors, hex::encode(digest.finalize())))
}

async fn verify_marker(processor: &ProcessorConfig, target: u64) -> anyhow::Result<()> {
    use psy_node_core::psy_core_db::traits::full::PsyNodeCheckpointObjectDatabaseReader;
    type Network = parth_core::protocol::core_types::QNetworkTypesConfigHelper<psy_core::job::job_id::QProvingJobDataID,psy_plonky2_circuits::protocol_types::ZKTypesPlonky2GoldilocksPoseidon,psy_core::network_config::PsyNetworkLocalDevnetConstants>;
    let (namespace,url) = match processor { ProcessorConfig::Coordinator(config) => (&config.db_namespace,&config.scylla_db_url), ProcessorConfig::Realm(config) => (&config.db_namespace,&config.scylla_db_url) };
    let store = psy_node_scylla::psy_setup::setup_psy_scylla_database_store_from_connection_string::<Network>(namespace,url,false).await.context("opening configured rollback store")?;
    ensure!(store.get_latest_checkpoint_id().await? == target, "configured processor marker differs from target");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::{OpenOptionsExt, PermissionsExt}, time::{SystemTime, UNIX_EPOCH}};
    use guardian_common::protocol::{accumulate_deposit_leaf, encode_record, DepositAnchor, GuardianSession, GuardianSessionRecord, Hash4, Hex, JsonText, WithdrawalAppendRecord, WithdrawalBurnRecord};
    use alloy_primitives::U256;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use psy_client_common::{args::ContractCallData, data::base_types::hash256::Hash256};
    use psy_crypto::signature::secp256k1::core::PsyCompressedSecp256K1Signature;
    use psy_prover::trace::{GeneratedTxTraceJson, SessionAnchor, TraceMeta, TxFinalization, TxTrace, UpsStartWitness};
    use psy_vm::ups::multisig::MultisigSignatures;
    use redb::Database;

    struct TestDirectory(PathBuf);
    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("restore-boundary-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
        fn open(&self) -> File { File::open(&self.0).unwrap() }
        fn dir(&self, name: &str) -> PathBuf {
            let path = self.0.join(name);
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            path
        }
    }
    impl Drop for TestDirectory { fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); } }

    fn leaf(value: u64) -> Hash4 { Hash4::from_values(value, 0, 0, 0) }
    fn config() -> GuardianConfig {
        let network = serde_json::from_value(serde_json::json!({
            "magic": "0x16015", "users_per_realm": 1, "global_user_tree_height": 1, "realm_user_tree_height": 1, "group_realm_height": 1,
            "guardian_initial_member_hashes": [leaf(1), leaf(2), leaf(3)],
            "realm_configs": [], "p2p": {"checkpoints_per_epoch": 1}, "coordinator_configs": [{"id": 0, "rpc_url": ["http://coordinator/"]}],
            "prove_proxy_url": [], "faucet_rpc_url": [], "nostr_relay_url": "", "native_currency": "", "native_currency_decimal": 0,
            "native_currency_name": "", "fees": {"register_user_fee": 0, "deploy_contract_fee": 0, "guta_fee": 0, "da_fee": 0},
            "guardian_configs": [], "guardian_history": {"listen_address": "127.0.0.1:15450"}
        })).unwrap();
        GuardianConfig { network, guardian_root: PathBuf::new(), endpoints: std::array::from_fn(|_| "http://127.0.0.1/".into()), history_url: "http://127.0.0.1/".into(), l1_chains: Vec::new() }
    }
    fn account(config: &GuardianConfig, nonce: Option<u64>, ending: Option<Hash4>) -> GuardianAccount {
        GuardianAccount { network_magic: config.network_magic().unwrap(), user_id: BRIDGE_USER_ID, state: GuardianAccountState::Active, last_checkpoint_id: 4, last_checkpoint_hash: leaf(4), imported_nonce: nonce, account_public_key: config.account_public_key().unwrap(), imported_ending_leaf: ending, withdrawal_chains: Vec::new(), halt_reason: None }
    }
    fn request(config: &GuardianConfig, nonce: u64) -> (GuardianSignRequest, String) {
        let trace = TxTrace { meta: TraceMeta { network_magic: config.network_magic().unwrap(), user_id: BRIDGE_USER_ID, public_key: config.account_public_key().unwrap() }, anchor: SessionAnchor { start_checkpoint_id: 0, checkpoint_leaf: Default::default(), global_state_roots: Default::default(), ups_step_circuit_whitelist_root: Hash4::ZERO }, ups_start_witness: UpsStartWitness { ups_header: Default::default(), state_roots: Default::default(), checkpoint_tree_proof: Default::default(), user_tree_proof: Default::default(), user_registration_tree_proof: None, proof: None }, contract_codes: vec![], steps: vec![], finalization: TxFinalization { submit_end_cap_input: Default::default(), nonce: GoldilocksField(nonce), tx_hash: Hash4::ZERO, software_defined_call: Default::default(), sig_hash: Hash4::ZERO } };
        let generated = GeneratedTxTraceJson::from_trace(&trace, serde_json::to_value(ContractCallData::new(vec![])).unwrap()).unwrap();
        let request = GuardianSignRequest { schema_version: 3, network_magic: config.network_magic().unwrap(), user_id: BRIDGE_USER_ID, session_nonce: nonce, operation: guardian_common::protocol::GuardianOperation::Bootstrap, trace_json: JsonText::from_value(&generated).unwrap(), deposit_anchors: vec![], withdrawal_records: vec![] };
        let text = String::from_utf8(serde_json::to_vec(&request).unwrap()).unwrap();
        (request, text)
    }
    fn signed_row(config: &GuardianConfig, nonce: u64, signature: Option<[u8; 64]>) -> Vec<u8> {
        let (request, _) = request(config, nonce);
        let signed = GuardianSigned { network_magic: config.network_magic().unwrap(), user_id: BRIDGE_USER_ID, nonce, request_bytes: request.canonical_bytes().unwrap(), starting_leaf_hash: leaf(8), ending_leaf_hash: leaf(9), message: [1; 32], deposit_tree_states: vec![], signature };
        encode_record(&encode(&signed).unwrap()).unwrap()
    }
    fn request_row(config: &GuardianConfig, nonce: u64) -> Vec<u8> {
        let (_, text) = request(config, nonce);
        let body = serde_json::json!({"Request": {"request": text, "deposit_tree_states": []}});
        encode_record(&serde_json::to_vec(&body).unwrap()).unwrap()
    }
    fn create(directory: &TestDirectory, name: &str, relayer: bool, account: &GuardianAccount, row: Option<(u64, Vec<u8>)>) -> Database {
        let file = std::fs::OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(directory.0.join(name)).unwrap();
        let database = Database::builder().create_file(file).unwrap();
        let transaction = database.begin_write().unwrap();
        transaction.open_table(GUARDIAN_ACCOUNT).unwrap().insert((account.network_magic, account.user_id), encode(account).unwrap().as_slice()).unwrap();
        if relayer {
            transaction.open_table(JOURNAL_SCHEMA).unwrap().insert((), JOURNAL_SCHEMA_VERSION).unwrap();
            let mut requests = transaction.open_table(RELAYER_REQUEST).unwrap();
            if let Some((nonce, bytes)) = &row { requests.insert(*nonce, bytes.as_slice()).unwrap(); }
            drop(requests);
            transaction.open_table(CHAIN_CLAIMS).unwrap();
            transaction.open_table(FINALIZATION_BATCH).unwrap();
            transaction.open_table(RELAYER_DEPOSIT_TREE_STATES).unwrap();
            transaction.open_table(RELAYER_INCLUDED_WITHDRAWAL_BURNS).unwrap();
            transaction.open_table(RELAYER_WITHDRAWAL_NONCE).unwrap();
        } else {
            transaction.open_table(GUARDIAN_SCHEMA).unwrap().insert((), GUARDIAN_SCHEMA_VERSION).unwrap();
            transaction.open_table(GUARDIAN_SIGNER).unwrap().insert((), &[2u8; 33]).unwrap();
            let mut signed = transaction.open_table(GUARDIAN_SIGNED).unwrap();
            if let Some((nonce, bytes)) = &row { signed.insert((account.network_magic, account.user_id, *nonce), bytes.as_slice()).unwrap(); }
            drop(signed);
            transaction.open_table(GUARDIAN_SESSION).unwrap();
            transaction.open_table(GUARDIAN_DEPOSIT_TREE_STATES).unwrap();
            transaction.open_table(GUARDIAN_INCLUDED_WITHDRAWAL_BURNS).unwrap();
            transaction.open_table(GUARDIAN_WITHDRAWAL_NONCE).unwrap();
        }
        transaction.commit().unwrap();
        database
    }
    fn gate(database: &Database, relayer: bool, config: &GuardianConfig, target: &GuardianAccount) -> anyhow::Result<()> { refuse_signed_boundary(database, relayer, config, target) }
    fn deposit_state(chain: u8) -> DepositTreeState {
        let mut state = DepositTreeState::empty(chain);
        let root = accumulate_deposit_leaf(&mut state.frontier, &mut state.occupied_partial_page_hashes, 0, leaf(20 + u64::from(chain)));
        state.count = 1;
        state.root = root;
        state.anchor = DepositAnchor { chain_index: chain, block_number: 40 + u64::from(chain), block_hash: Hex([chain.wrapping_add(1); 32]), old_count: 0, new_count: 1 };
        state.event_block = 30 + u64::from(chain);
        state.previous_count = 0;
        state.previous_root = DepositTreeState::empty(chain).root;
        state
    }
    fn burn(chain: u8, word: u32) -> WithdrawalBurnRecord {
        let mut nonce = [0; 8];
        nonce[7] = word;
        WithdrawalBurnRecord { sender_user_id: 11, token_contract_id: 4, destination_chain_index: chain, token: [0; 8], amount: [0, 0, 0, 0, 0, 0, 0, 1], recipient: [0, 0, 0, 0, 0, 0, 0, 1], nonce }
    }
    fn append(chain: u8, index: u32) -> WithdrawalAppendRecord {
        WithdrawalAppendRecord { chain_index: chain, append_index: index, burn: burn(chain, 70 + u32::from(chain) * 10 + index) }
    }
    fn withdrawal_frontier(chain: u8) -> (u8, u32, [Hash4; 32], Hash4) {
        let mut frontier = [Hash4::ZERO; 32];
        let first = accumulate_deposit_leaf(&mut frontier, &mut Vec::new(), 0, leaf(80 + u64::from(chain)));
        let root = accumulate_deposit_leaf(&mut frontier, &mut Vec::new(), 1, leaf(90 + u64::from(chain)));
        assert_ne!(first, root);
        (chain, 2, frontier, root)
    }
    fn snapshot(config: &GuardianConfig) -> BridgeJournalSnapshot {
        let mut target = account(config, Some(5), Some(leaf(5)));
        let chains = [withdrawal_frontier(0), withdrawal_frontier(1)];
        target.withdrawal_chains = chains.to_vec();
        BridgeJournalSnapshot { account: target, deposits: vec![deposit_state(0), deposit_state(1)], withdrawals: vec![(append(0, 0), 3), (append(0, 1), 4), (append(1, 0), 2), (append(1, 1), 5)] }
    }
    fn signer_bytes(index: usize) -> [u8; 33] {
        let mut bytes = [2u8; 33];
        bytes[1] = u8::try_from(index).unwrap();
        bytes
    }
    fn session_row(config: &GuardianConfig, nonce: u64) -> Vec<u8> {
        let (request, _) = request(config, nonce);
        let record = GuardianSessionRecord {
            request_json: JsonText::from_value(&request).unwrap(),
            signatures_json: JsonText::from_value(&MultisigSignatures { member_indices: vec![0, 1], signatures: vec![PsyCompressedSecp256K1Signature { public_key: [2; 33], signature: [1; 64], message: Hash256([0; 32]) }; 2] }).unwrap(),
            endcap_input_json: JsonText::from_value(&request.decode_trace().unwrap().finalization.submit_end_cap_input).unwrap(),
            endcap_proof_hex: "0x00".into(), included_checkpoint_id: nonce, included_checkpoint_hash: leaf(4),
        };
        record.validate(config).unwrap();
        let session = GuardianSession { network_magic: config.network_magic().unwrap(), user_id: BRIDGE_USER_ID, nonce, record, starting_leaf_hash: leaf(8), ending_leaf_hash: leaf(9), withdrawal_appends: Vec::new() };
        session.validate(config).unwrap();
        encode_record(&encode(&session).unwrap()).unwrap()
    }
    fn included_row(config: &GuardianConfig, nonce: u64) -> Vec<u8> {
        let (request, _) = request(config, nonce);
        let record = GuardianSessionRecord {
            request_json: JsonText::from_value(&request).unwrap(),
            signatures_json: JsonText::from_value(&MultisigSignatures { member_indices: vec![0, 2], signatures: vec![PsyCompressedSecp256K1Signature { public_key: [3; 33], signature: [4; 64], message: Hash256([5; 32]) }; 2] }).unwrap(),
            endcap_input_json: JsonText::from_value(&request.decode_trace().unwrap().finalization.submit_end_cap_input).unwrap(),
            endcap_proof_hex: "0x01".into(), included_checkpoint_id: nonce, included_checkpoint_hash: leaf(6),
        };
        let body = serde_json::to_vec(&RelayerRequest::Included { record }).unwrap();
        let bytes = encode_record(&body).unwrap();
        assert_eq!(relayer_request_nonce(&bytes, nonce, config).unwrap(), nonce);

        bytes
    }
    fn seed(directory: &TestDirectory, name: &str, relayer: bool, account: &GuardianAccount, successor: Option<u64>, signer: [u8; 33], transient: bool, config: &GuardianConfig) {
        let database = create(directory, name, relayer, account, None);
        let transaction = database.begin_write().unwrap();
        if relayer {
            if let Some(nonce) = successor { transaction.open_table(RELAYER_REQUEST).unwrap().insert(nonce, included_row(config, nonce).as_slice()).unwrap(); }
            if transient {
                transaction.open_table(CHAIN_CLAIMS).unwrap().insert(9u8, br#"{"stale":true}"#.as_slice()).unwrap();
                transaction.open_table(FINALIZATION_BATCH).unwrap().insert((), br#"{"stale":true}"#.as_slice()).unwrap();
            }
            transaction.open_table(RELAYER_DEPOSIT_TREE_STATES).unwrap().insert(RelayerDepositTreeKey(deposit_tree_key_bytes(account.network_magic, account.user_id, 9)), b"old-deposit".as_slice()).unwrap();
            transaction.open_table(RELAYER_INCLUDED_WITHDRAWAL_BURNS).unwrap().insert(RelayerWithdrawalBurnKey([9; 56]), 1u64).unwrap();
            transaction.open_table(RELAYER_WITHDRAWAL_NONCE).unwrap().insert(RelayerWithdrawalNonceKey([8; 49]), 1u64).unwrap();
        } else {
            transaction.open_table(GUARDIAN_SIGNER).unwrap().insert((), signer).unwrap();
            if let Some(nonce) = successor {
                transaction.open_table(GUARDIAN_SIGNED).unwrap().insert((account.network_magic, account.user_id, nonce), signed_row(config, nonce, Some([9; 64])).as_slice()).unwrap();
                transaction.open_table(GUARDIAN_SESSION).unwrap().insert((account.network_magic, account.user_id, nonce), session_row(config, nonce).as_slice()).unwrap();
            }
            transaction.open_table(GUARDIAN_DEPOSIT_TREE_STATES).unwrap().insert(GuardianDepositTreeKey(deposit_tree_key_bytes(account.network_magic, account.user_id, 9)), b"old-deposit".as_slice()).unwrap();
            transaction.open_table(GUARDIAN_INCLUDED_WITHDRAWAL_BURNS).unwrap().insert(GuardianWithdrawalBurnKey([7; 56]), 1u64).unwrap();
            transaction.open_table(GUARDIAN_WITHDRAWAL_NONCE).unwrap().insert(GuardianWithdrawalNonceKey([6; 49]), 1u64).unwrap();
        }
        transaction.commit().unwrap();
        drop(database);
    }
    fn proof_file(directory: &PathBuf, name: &str, bytes: &[u8]) {
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(directory.join(name)).unwrap();
        file.write_all(bytes).unwrap();
    }
    fn configured(members: [[u8; 33]; 3]) -> GuardianConfig {
        use plonky2::hash::poseidon::PoseidonPermutation;
        use psy_crypto::signature::secp256k1::wallet::hash_no_pad_compressed_public_key;
        let mut config = config();
        let hashes = members.map(|bytes| hash_no_pad_compressed_public_key::<GoldilocksField, PoseidonPermutation<GoldilocksField>>(psy_client_common::data::secp256k1::CompressedPublicKey::new_from_slice(&bytes)));
        config.network.guardian_initial_member_hashes = Some(hashes);
        config.l1_chains = vec![
            guardian_common::protocol::ChainEndpoint { chain_index: 0, chain_id: U256::from(7u8), bridge: Hex([0x11; 20]), deployment_block: 0, rpc_url: "https://chain0.example/rpc".into() },
            guardian_common::protocol::ChainEndpoint { chain_index: 1, chain_id: U256::from(8u8), bridge: Hex([0x22; 20]), deployment_block: 0, rpc_url: "https://chain1.example/rpc".into() },
        ];
        config
    }
    struct RestoreFixture { directory: TestDirectory, config: GuardianConfig, snapshot: BridgeJournalSnapshot, signers: [[u8; 33]; 3] }
    impl RestoreFixture {
        fn safe() -> Self { Self::build(None) }
        fn unsafe_at(position: usize) -> Self { Self::build(Some(position)) }
        fn build(successor: Option<usize>) -> Self {
            let signers = [0, 1, 2].map(signer_bytes);
            let config = configured(signers);
            let snapshot = snapshot(&config);
            let directory = TestDirectory::new();
            let current = if successor.is_some() { account(&config, Some(8), Some(leaf(8))) } else { account(&config, Some(4), Some(leaf(4))) };
            for (index, name) in DATABASES.iter().enumerate() {
                seed(&directory, name, index == 3, &current, successor.filter(|position| *position == index).map(|_| 6), signers.get(index).copied().unwrap_or([2; 33]), index == 3, &config);
            }
            Self { directory, config, snapshot, signers }
        }
        fn open(&self) -> (File, File, Vec<HeldDatabase>) {
            let parent = self.directory.open();
            let proofs = File::open(self.directory.dir("proofs")).unwrap();
            let databases = open_databases(&parent).unwrap();
            (parent, proofs, databases)
        }
    }
    fn logical_hashes(databases: &[HeldDatabase]) -> Vec<String> {
        databases.iter().map(|held| journal_digest(held.database.as_ref().unwrap(), is_relayer(held.name)).unwrap()).collect()
    }
    fn backup_bytes(directory: &TestDirectory, operation: &str) -> Vec<Vec<u8>> {
        DATABASES.iter().map(|name| fs::read(directory.0.join(format!("{name}.pre-restore-{operation}"))).unwrap()).collect()
    }
    fn assert_reconstructed(databases: &[HeldDatabase], snapshot: &BridgeJournalSnapshot, signers: [[u8; 33]; 3]) {
        for (index, held) in databases.iter().enumerate() {
            let relayer = is_relayer(held.name);
            let database = held.database.as_ref().unwrap();
            verify_snapshot(database, relayer, snapshot).unwrap();
            let transaction = database.begin_read().unwrap();
            if relayer {
                assert!(transaction.open_table(RELAYER_REQUEST).unwrap().is_empty().unwrap());
                assert!(transaction.open_table(CHAIN_CLAIMS).unwrap().is_empty().unwrap());
                assert!(transaction.open_table(FINALIZATION_BATCH).unwrap().is_empty().unwrap());
            } else {
                assert_eq!(transaction.open_table(GUARDIAN_SIGNER).unwrap().get(()).unwrap().unwrap().value(), signers[index]);
                assert!(transaction.open_table(GUARDIAN_SIGNED).unwrap().is_empty().unwrap());
                assert!(transaction.open_table(GUARDIAN_SESSION).unwrap().is_empty().unwrap());
            }
        }
    }
    fn assert_proofs(proofs: &PathBuf, retained: &str, removed: &[&str]) {
        assert_eq!(fs::read(proofs.join(retained)).unwrap(), b"kept");
        for name in removed { assert!(!proofs.join(name).exists(), "{name}"); }
    }
    fn repeated_snapshot(config: &GuardianConfig) -> BridgeJournalSnapshot {
        let mut target = account(config, Some(9), Some(leaf(9)));
        let chains = [withdrawal_frontier(0), withdrawal_frontier(1)];
        target.withdrawal_chains = chains.to_vec();
        let repeated = append(0, 0);
        let mut later = append(0, 1);
        later.burn = repeated.burn.clone();
        let mut cross = append(1, 0);
        cross.burn.nonce = repeated.burn.nonce;
        cross.burn.sender_user_id = repeated.burn.sender_user_id + 1;
        BridgeJournalSnapshot { account: target, deposits: vec![deposit_state(0), deposit_state(1)], withdrawals: vec![(repeated, 7), (later, 4), (cross, 8), (append(1, 1), 2)] }
    }

    #[test]
    fn duplicate_leaves_keep_distinct_indexes_and_maximum_inclusion_nonce() {
        let config = configured([0, 1, 2].map(signer_bytes));
        let snapshot = repeated_snapshot(&config);
        validate_snapshot(&snapshot, &config, 4).unwrap();
        let (burns, nonces) = inclusion_metadata(&snapshot).unwrap();
        let repeated = &snapshot.withdrawals[0].0.burn;
        let cross = &snapshot.withdrawals[2].0.burn;
        let burn_key = withdrawal_burn_key_bytes(snapshot.account.network_magic, snapshot.account.user_id, repeated.sender_user_id, repeated.token_contract_id, &repeated.nonce);
        let cross_key = withdrawal_burn_key_bytes(snapshot.account.network_magic, snapshot.account.user_id, cross.sender_user_id, cross.token_contract_id, &cross.nonce);
        let early = nonce_key_bytes(snapshot.account.network_magic, snapshot.account.user_id, 0, &repeated.nonce);
        let later = nonce_key_bytes(snapshot.account.network_magic, snapshot.account.user_id, 1, &cross.nonce);
        assert_ne!(burn_key, cross_key);
        assert_eq!(burns.len(), 3);
        assert_eq!(nonces.len(), 3);
        assert_eq!(burns[&burn_key], 7);
        assert_eq!(burns[&cross_key], 8);
        assert_eq!(nonces[&early], 7);
        assert_eq!(nonces[&later], 8);
        let directory = TestDirectory::new();
        for relayer in [false, true] {
            let database = create(&directory, if relayer { "relayer-repeat.redb" } else { "guardian-repeat.redb" }, relayer, &snapshot.account, None);
            replace_snapshot(&database, relayer, &snapshot).unwrap();
            verify_snapshot(&database, relayer, &snapshot).unwrap();
        }
        let mut collided = repeated_snapshot(&config);
        collided.withdrawals[1].0.append_index = 0;
        assert!(validate_snapshot(&collided, &config, 4).unwrap_err().to_string().contains("duplicate append coordinate"));
    }
    #[test]
    fn restore_refuses_future_signed_successor() {
        let config = config();
        let directory = TestDirectory::new();
        let current = account(&config, Some(5), Some(leaf(5)));
        let database = create(&directory, "guardian-signed.redb", false, &current, Some((6, signed_row(&config, 6, Some([9; 64])))));
        let before = journal_digest(&database, false).unwrap();
        assert!(gate(&database, false, &config, &account(&config, Some(5), Some(leaf(5)))).is_err());
        assert_eq!(journal_digest(&database, false).unwrap(), before);
    }



    #[test]
    fn cursor_above_target_refuses_after_its_row_was_pruned() {
        let config = config();
        let directory = TestDirectory::new();
        let current = account(&config, Some(8), Some(leaf(8)));
        let database = create(&directory, "guardian-1.redb", false, &current, None);
        let before = journal_digest(&database, false).unwrap();
        assert!(gate(&database, false, &config, &account(&config, Some(5), Some(leaf(5)))).is_err());
        assert_eq!(journal_digest(&database, false).unwrap(), before);
    }
    #[test]
    fn retained_signed_and_unsigned_successor_refuse_and_matching_equal_accepts() {
        let config = config();
        let directory = TestDirectory::new();
        let current = account(&config, Some(5), Some(leaf(5)));
        let target = account(&config, Some(5), Some(leaf(5)));
        let signed = create(&directory, "signed.redb", false, &current, Some((6, signed_row(&config, 6, Some([9; 64])))));
        let unsigned = create(&directory, "unsigned.redb", false, &current, Some((6, signed_row(&config, 6, None))));
        let pending = create(&directory, "relayer.redb", true, &current, Some((6, request_row(&config, 6))));
        let equal = create(&directory, "equal.redb", false, &current, Some((5, signed_row(&config, 5, Some([9; 64])))));
        for database in [&signed, &unsigned] { let before = journal_digest(database, false).unwrap(); assert!(gate(database, false, &config, &target).is_err()); assert_eq!(journal_digest(database, false).unwrap(), before); }
        let before = journal_digest(&pending, true).unwrap();
        assert!(gate(&pending, true, &config, &target).is_err());
        assert_eq!(journal_digest(&pending, true).unwrap(), before);
        assert!(gate(&equal, false, &config, &target).is_ok());
    }
    #[test]
    fn equal_nonce_with_different_ending_leaf_refuses() {
        let config = config();
        let directory = TestDirectory::new();
        let database = create(&directory, "guardian-1.redb", false, &account(&config, Some(5), Some(leaf(7))), None);
        let before = journal_digest(&database, false).unwrap();
        assert!(gate(&database, false, &config, &account(&config, Some(5), Some(leaf(5)))).is_err());
        assert_eq!(journal_digest(&database, false).unwrap(), before);
    }
    #[test]
    fn backup_copy_accepts_safe_original_and_refuses_higher_cursor() {
        let config = config();
        let directory = TestDirectory::new();
        let safe_account = account(&config, Some(5), Some(leaf(5)));
        let safe = create(&directory, "safe.redb", false, &safe_account, None);
        let source = File::open(directory.0.join("safe.redb")).unwrap();
        let mut safe_backup = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(directory.0.join("safe.pre-restore-op")).unwrap();
        std::io::copy(&mut source.try_clone().unwrap(), &mut safe_backup).unwrap();
        drop((source, safe_backup, safe));
        let high = create(&directory, "high.redb", false, &account(&config, Some(8), Some(leaf(8))), None);
        let source = File::open(directory.0.join("high.redb")).unwrap();
        let mut high_backup = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(directory.0.join("high.pre-restore-op")).unwrap();
        std::io::copy(&mut source.try_clone().unwrap(), &mut high_backup).unwrap();
        drop((source, high_backup, high));
        let parent = directory.open();
        let safe_file = open_at(&parent, OsStr::new("safe.pre-restore-op"), libc::O_RDONLY).unwrap().unwrap();
        let safe_digest = identity(&safe_file).unwrap().digest;
        let safe_bytes = fs::read(directory.0.join("safe.pre-restore-op")).unwrap();
        inspect_backup(&parent, &safe_file, "safe.pre-restore-op", &safe_digest, false, &config, &safe_account).unwrap();
        assert_eq!(identity(&safe_file).unwrap().digest, safe_digest);
        assert_eq!(fs::read(directory.0.join("safe.pre-restore-op")).unwrap(), safe_bytes);
        let high_file = open_at(&parent, OsStr::new("high.pre-restore-op"), libc::O_RDONLY).unwrap().unwrap();
        let high_digest = identity(&high_file).unwrap().digest;
        let high_bytes = fs::read(directory.0.join("high.pre-restore-op")).unwrap();
        let error = inspect_backup(&parent, &high_file, "high.pre-restore-op", &high_digest, false, &config, &safe_account).unwrap_err();
        assert!(error.to_string().contains("journal cursor 8 is above authenticated bridge nonce 5"), "{error:#}");
        assert_eq!(identity(&high_file).unwrap().digest, high_digest);
        assert_eq!(fs::read(directory.0.join("high.pre-restore-op")).unwrap(), high_bytes);
        assert!(!directory.0.join(".inspect-safe.pre-restore-op").exists());
        assert!(!directory.0.join(".inspect-high.pre-restore-op").exists());
    }
    #[test]
    fn completed_apply_refuses_original_backup_above_restored_nonce() {
        let config = config();
        let directory = TestDirectory::new();
        let target = account(&config, Some(5), Some(leaf(5)));
        let snapshot = BridgeJournalSnapshot { account: target.clone(), deposits: Vec::new(), withdrawals: Vec::new() };
        for (index, name) in DATABASES.iter().enumerate() {
            let original = create(&directory, name, index == 3, &account(&config, Some(8), Some(leaf(8))), None);
            drop(original);
            let source = File::open(directory.0.join(name)).unwrap();
            let mut backup = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(directory.0.join(format!("{name}.pre-restore-op"))).unwrap();
            std::io::copy(&mut source.try_clone().unwrap(), &mut backup).unwrap();
            drop((source, backup));
            std::fs::remove_file(directory.0.join(name)).unwrap();
            let restored = create(&directory, &format!("{name}.restored"), index == 3, &target, None);
            drop(restored);
            std::fs::rename(directory.0.join(format!("{name}.restored")), directory.0.join(name)).unwrap();
        }
        let parent = directory.open();
        let databases = open_databases(&parent).unwrap();
        let mut journals = Vec::new();
        for name in DATABASES {
            let backup = open_at(&parent, OsStr::new(&format!("{name}.pre-restore-op")), libc::O_RDONLY).unwrap().unwrap();
            let mut saved = identity(&backup).unwrap();
            let live = databases.iter().find(|held| held.name == name).unwrap().file.as_ref().unwrap();
            let current = live.metadata().unwrap();
            saved.device = current.dev();
            saved.inode = current.ino();
            journals.push(saved);
        }
        let proofs = directory.dir("proofs");
        let proof_dir = File::open(&proofs).unwrap();
        let metadata = proof_dir.metadata().unwrap();
        let operation = RestoreOperation { operation_id: "op".into(), target_digest: snapshot_digest(&snapshot).unwrap(), journals, backups: DATABASES.map(|name| format!("{name}.pre-restore-op")).into(), proofs: BTreeMap::new(), proof_directory: (metadata.dev(), metadata.ino()) };
        fs::write(directory.0.join("bridge-restore.op.done.json"), serde_json::to_vec(&operation).unwrap()).unwrap();
        fs::set_permissions(directory.0.join("bridge-restore.op.done.json"), fs::Permissions::from_mode(0o600)).unwrap();
        let before = databases.iter().map(|held| journal_digest(held.database.as_ref().unwrap(), is_relayer(held.name)).unwrap()).collect::<Vec<_>>();
        let error = apply(&parent, &proof_dir, &databases, &snapshot, "op", &operation.target_digest, &config).unwrap_err();
        assert!(error.to_string().contains("journal cursor 8 is above authenticated bridge nonce 5"), "{error:#}");
        let after = databases.iter().map(|held| journal_digest(held.database.as_ref().unwrap(), is_relayer(held.name)).unwrap()).collect::<Vec<_>>();
        assert_eq!(before, after);
        assert!(directory.0.join("bridge-restore.op.done.json").exists());
    }
    #[test]
    fn apply_replaces_four_journals_and_retry_completes_each_interrupted_commit() {
        let fixture = RestoreFixture::safe();
        let (parent, proofs, databases) = fixture.open();
        let proof_path = fixture.directory.0.join("proofs");
        proof_file(&proof_path, "bridge_proof_4.json", b"kept");
        proof_file(&proof_path, "bridge_proof_5.json", b"remove-shared");
        proof_file(&proof_path, "bridge_proof_9_chain_1.json", b"remove-chain");
        proof_file(&proof_path, "bridge_proof_3_chain_0.json", b"older");
        let digest = snapshot_digest(&fixture.snapshot).unwrap();
        let operation = "restore-four";
        validate_signers(&databases, &fixture.config).unwrap();
        let before = logical_hashes(&databases);
        apply(&parent, &proofs, &databases, &fixture.snapshot, operation, &digest, &fixture.config).unwrap();
        let backups = backup_bytes(&fixture.directory, operation);
        let after = logical_hashes(&databases);
        assert_eq!(after.len(), 4);
        assert!(after.iter().zip(&before).all(|(next, prior)| next != prior));
        assert_eq!(logical_hashes(&databases), after);
        assert_reconstructed(&databases, &fixture.snapshot, fixture.signers);
        validate_signers(&databases, &fixture.config).unwrap();
        assert_proofs(&proof_path, "bridge_proof_4.json", &["bridge_proof_5.json", "bridge_proof_9_chain_1.json"]);
        assert_eq!(fs::read(proof_path.join("bridge_proof_3_chain_0.json")).unwrap(), b"older");
        assert!(!fixture.directory.0.join("bridge-restore.intent.json").exists());
        assert!(fixture.directory.0.join(format!("bridge-restore.{operation}.done.json")).exists());
        for backup in DATABASES.map(|name| format!("{name}.pre-restore-{operation}")) { assert_eq!(fs::metadata(fixture.directory.0.join(&backup)).unwrap().permissions().mode() & 0o777, 0o600); }
        apply(&parent, &proofs, &databases, &fixture.snapshot, operation, &digest, &fixture.config).unwrap();
        assert_eq!(backup_bytes(&fixture.directory, operation), backups);
        assert_reconstructed(&databases, &fixture.snapshot, fixture.signers);
        drop((parent, proofs, databases));

        for stop in 0..4 {
            let fixture = RestoreFixture::safe();
            let (parent, proofs, databases) = fixture.open();
            let proof_path = fixture.directory.0.join("proofs");
            proof_file(&proof_path, "bridge_proof_4.json", b"kept");
            proof_file(&proof_path, "bridge_proof_5.json", b"remove-shared");
            proof_file(&proof_path, "bridge_proof_9_chain_1.json", b"remove-chain");
            let before = logical_hashes(&databases);
            let metadata = proofs.metadata().unwrap();
            let mut journals = Vec::new();
            let mut originals = Vec::new();
            for (index, held) in databases.iter().enumerate() {
                let source = held.file.as_ref().unwrap();
                let saved = identity(source).unwrap();
                let mut reader = source.try_clone().unwrap();
                reader.seek(SeekFrom::Start(0)).unwrap();
                let mut bytes = Vec::new();
                reader.read_to_end(&mut bytes).unwrap();
                originals.push(bytes);
                let backup_name = format!("{}.pre-restore-{operation}", held.name);
                publish(&parent, &format!("{backup_name}.identity.json"), &serde_json::to_vec(&BackupIdentity { original: saved.clone(), logical_digest: before[index].clone() }).unwrap()).unwrap();
                let temporary = format!("{backup_name}.tmp");
                let mut backup = create_file(&parent, &temporary).unwrap();
                backup.write_all(&originals[index]).unwrap();
                backup.sync_all().unwrap();
                let from = CString::new(temporary).unwrap();
                let to = CString::new(backup_name).unwrap();
                assert_eq!(unsafe { libc::renameat2(parent.as_raw_fd(), from.as_ptr(), parent.as_raw_fd(), to.as_ptr(), libc::RENAME_NOREPLACE) }, 0);
                journals.push(saved);
            }
            parent.sync_all().unwrap();
            let committed = backup_bytes(&fixture.directory, operation);
            for (index, held) in databases.iter().enumerate().take(stop) {
                replace_snapshot(held.database.as_ref().unwrap(), is_relayer(held.name), &fixture.snapshot).unwrap();
                verify_snapshot(held.database.as_ref().unwrap(), is_relayer(held.name), &fixture.snapshot).unwrap();
                assert_ne!(journal_digest(held.database.as_ref().unwrap(), is_relayer(held.name)).unwrap(), before[index]);
            }
            for held in databases.iter().skip(stop) {
                assert_eq!(journal_digest(held.database.as_ref().unwrap(), is_relayer(held.name)).unwrap(), before[DATABASES.iter().position(|name| *name == held.name).unwrap()]);
            }
            let intent = RestoreOperation { operation_id: operation.into(), target_digest: digest.clone(), journals, backups: DATABASES.map(|name| format!("{name}.pre-restore-{operation}")).into(), proofs: collect_proofs(&proofs, fixture.snapshot.account.last_checkpoint_id).unwrap(), proof_directory: (metadata.dev(), metadata.ino()) };
            publish(&parent, "bridge-restore.intent.json", &serde_json::to_vec(&intent).unwrap()).unwrap();
            apply(&parent, &proofs, &databases, &fixture.snapshot, operation, &digest, &fixture.config).unwrap();
            assert_eq!(backup_bytes(&fixture.directory, operation), committed);
            for (bytes, saved) in originals.iter().zip(&committed) { assert_eq!(bytes, saved); }
            assert_reconstructed(&databases, &fixture.snapshot, fixture.signers);
            validate_signers(&databases, &fixture.config).unwrap();
            assert_proofs(&proof_path, "bridge_proof_4.json", &["bridge_proof_5.json", "bridge_proof_9_chain_1.json"]);
            assert!(!fixture.directory.0.join("bridge-restore.intent.json").exists());
            assert!(fixture.directory.0.join(format!("bridge-restore.{operation}.done.json")).exists());
            let completed = logical_hashes(&databases);
            apply(&parent, &proofs, &databases, &fixture.snapshot, operation, &digest, &fixture.config).unwrap();
            assert_eq!(logical_hashes(&databases), completed);
            assert_eq!(backup_bytes(&fixture.directory, operation), committed);
        }
    }
    #[test]
    fn unsafe_original_at_every_position_refuses_before_any_business_write() {
        let operation = "restore-four";
        for position in 0..4 {
            for resumed in [false, true] {
                let fixture = RestoreFixture::unsafe_at(position);
                let (parent, proofs, databases) = fixture.open();
                let digest = snapshot_digest(&fixture.snapshot).unwrap();
                let before = logical_hashes(&databases);
                if resumed {
                    let metadata = proofs.metadata().unwrap();
                    let mut journals = Vec::new();
                    for (index, held) in databases.iter().enumerate() {
                        let source = held.file.as_ref().unwrap();
                        let saved = identity(source).unwrap();
                        let mut reader = source.try_clone().unwrap();
                        reader.seek(SeekFrom::Start(0)).unwrap();
                        let mut bytes = Vec::new();
                        reader.read_to_end(&mut bytes).unwrap();
                        let backup_name = format!("{}.pre-restore-{operation}", held.name);
                        publish(&parent, &format!("{backup_name}.identity.json"), &serde_json::to_vec(&BackupIdentity { original: saved.clone(), logical_digest: before[index].clone() }).unwrap()).unwrap();
                        let temporary = format!("{backup_name}.tmp");
                        let mut backup = create_file(&parent, &temporary).unwrap();
                        backup.write_all(&bytes).unwrap();
                        backup.sync_all().unwrap();
                        let from = CString::new(temporary).unwrap();
                        let to = CString::new(backup_name).unwrap();
                        assert_eq!(unsafe { libc::renameat2(parent.as_raw_fd(), from.as_ptr(), parent.as_raw_fd(), to.as_ptr(), libc::RENAME_NOREPLACE) }, 0);
                        journals.push(saved);
                    }
                    parent.sync_all().unwrap();
                    let intent = RestoreOperation { operation_id: operation.into(), target_digest: digest.clone(), journals, backups: DATABASES.map(|name| format!("{name}.pre-restore-{operation}")).into(), proofs: BTreeMap::new(), proof_directory: (metadata.dev(), metadata.ino()) };
                    publish(&parent, "bridge-restore.intent.json", &serde_json::to_vec(&intent).unwrap()).unwrap();
                }
                let error = apply(&parent, &proofs, &databases, &fixture.snapshot, operation, &digest, &fixture.config).unwrap_err();
                assert!(error.to_string().contains("journal cursor 8 is above authenticated bridge nonce 5"), "{error:#}");
                assert_eq!(logical_hashes(&databases), before);
                if !resumed {
                    for name in DATABASES { assert!(!fixture.directory.0.join(format!("{name}.pre-restore-{operation}")).exists()); }
                }
                assert!(!fixture.directory.0.join(format!("bridge-restore.{operation}.done.json")).exists());
            }
            let fixture = RestoreFixture::unsafe_at(position);
            for (index, name) in DATABASES.iter().enumerate() {
                let source = File::open(fixture.directory.0.join(name)).unwrap();
                let mut backup = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(fixture.directory.0.join(format!("{name}.pre-restore-{operation}"))).unwrap();
                std::io::copy(&mut source.try_clone().unwrap(), &mut backup).unwrap();
                drop((source, backup));
                std::fs::remove_file(fixture.directory.0.join(name)).unwrap();
                let restored = create(&fixture.directory, &format!("{name}.restored"), index == 3, &fixture.snapshot.account, None);
                if index < 3 {
                    let transaction = restored.begin_write().unwrap();
                    transaction.open_table(GUARDIAN_SIGNER).unwrap().insert((), fixture.signers[index]).unwrap();
                    transaction.commit().unwrap();
                }
                replace_snapshot(&restored, index == 3, &fixture.snapshot).unwrap();
                drop(restored);
                std::fs::rename(fixture.directory.0.join(format!("{name}.restored")), fixture.directory.0.join(name)).unwrap();
            }
            let (parent, proofs, databases) = fixture.open();
            let mut journals = Vec::new();
            for name in DATABASES {
                let backup = open_at(&parent, OsStr::new(&format!("{name}.pre-restore-{operation}")), libc::O_RDONLY).unwrap().unwrap();
                let mut saved = identity(&backup).unwrap();
                let live = databases.iter().find(|held| held.name == name).unwrap().file.as_ref().unwrap();
                let current = live.metadata().unwrap();
                saved.device = current.dev();
                saved.inode = current.ino();
                journals.push(saved);
            }
            let metadata = proofs.metadata().unwrap();
            let digest = snapshot_digest(&fixture.snapshot).unwrap();
            let done = RestoreOperation { operation_id: operation.into(), target_digest: digest.clone(), journals, backups: DATABASES.map(|name| format!("{name}.pre-restore-{operation}")).into(), proofs: BTreeMap::new(), proof_directory: (metadata.dev(), metadata.ino()) };
            fs::write(fixture.directory.0.join(format!("bridge-restore.{operation}.done.json")), serde_json::to_vec(&done).unwrap()).unwrap();
            fs::set_permissions(fixture.directory.0.join(format!("bridge-restore.{operation}.done.json")), fs::Permissions::from_mode(0o600)).unwrap();
            let before = logical_hashes(&databases);
            let error = apply(&parent, &proofs, &databases, &fixture.snapshot, operation, &digest, &fixture.config).unwrap_err();
            assert!(error.to_string().contains("journal cursor 8 is above authenticated bridge nonce 5"), "{error:#}");
            assert_eq!(logical_hashes(&databases), before);
            assert!(fixture.directory.0.join(format!("bridge-restore.{operation}.done.json")).exists());
        }
    }
}
