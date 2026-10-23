//! One redb file belongs to exactly one guardian signing key.
//! The caller supplies the exclusive file descriptor; dropping this value releases it.
//! Schema 3 stores the same runtime identity. Signed and session rows are `PSYGR001` envelopes. Legacy journals require explicit operator-controlled migration.

use std::collections::BTreeSet;
use std::fs::File;
use std::ops::Bound;
use std::sync::Arc;

use bincode::Options;
use redb::{Database, Key, ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle, TypeName, Value};
use serde::de::DeserializeOwned;
use serde::Serialize;


use super::protocol::{advance_included_account, decode_record, encode_record, DepositTreeState, GuardianAccount, GuardianAccountState, GuardianConfig, GuardianSession, GuardianSessionRecord, GuardianSignError, GuardianSigned, HaltReason, MAX_BODY_BYTES, MAX_SESSION_RECORD_BYTES};

type Result<T, E = GuardianSignError> = std::result::Result<T, E>;

const GUARDIAN_SIGNER: TableDefinition<(), [u8; 33]> = TableDefinition::new("guardian_signer");
const GUARDIAN_SCHEMA: TableDefinition<(), u32> = TableDefinition::new("guardian_schema");
const SCHEMA_VERSION: u32 = 3;
const RAW_SCHEMA_VERSION: u32 = 2;
const GUARDIAN_ACCOUNT: TableDefinition<(u64, u64), &[u8]> = TableDefinition::new("guardian_account");
const GUARDIAN_SIGNED: TableDefinition<(u64, u64, u64), &[u8]> = TableDefinition::new("guardian_signed");
const GUARDIAN_SESSION: TableDefinition<(u64, u64, u64), &[u8]> = TableDefinition::new("guardian_session");
const DEPOSIT_TREE_STATES: TableDefinition<DepositTreeKey, &[u8]> = TableDefinition::new("deposit_tree_states");
const INCLUDED_WITHDRAWAL_BURNS: TableDefinition<WithdrawalBurnKey, u64> = TableDefinition::new("included_withdrawal_burns");
const WITHDRAWAL_NONCE: TableDefinition<NonceKey, u64> = TableDefinition::new("guardian_withdrawal_nonce");
const TABLE_NAMES: [&str; 8] = ["deposit_tree_states", "guardian_account", "guardian_schema", "guardian_session", "guardian_signed", "guardian_signer", "guardian_withdrawal_nonce", "included_withdrawal_burns"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DepositTreeKey(u64, u64, u8);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WithdrawalBurnKey(u64, u64, u32, u32, [u32; 8]);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NonceKey(u64, u64, u8, [u32; 8]);

fn put_u32s(bytes: &mut Vec<u8>, words: &[u32]) { for word in words { bytes.extend_from_slice(&word.to_le_bytes()); } }
fn read_u32s<const N: usize>(bytes: &[u8]) -> [u32; N] { std::array::from_fn(|index| u32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap())) }

impl Value for DepositTreeKey {
    type SelfType<'a> = Self; type AsBytes<'a> = [u8; 17];
    fn fixed_width() -> Option<usize> { Some(17) }
    fn from_bytes<'a>(data: &'a [u8]) -> Self where Self: 'a { Self(u64::from_le_bytes(data[..8].try_into().unwrap()), u64::from_le_bytes(data[8..16].try_into().unwrap()), data[16]) }
    fn as_bytes<'a, 'b: 'a>(value: &'a Self) -> [u8; 17] where Self: 'a, Self: 'b { let mut bytes = [0; 17]; bytes[..8].copy_from_slice(&value.0.to_le_bytes()); bytes[8..16].copy_from_slice(&value.1.to_le_bytes()); bytes[16] = value.2; bytes }
    fn type_name() -> TypeName { TypeName::new("guardian_common::DepositTreeKey") }
}
impl Key for DepositTreeKey { fn compare(a: &[u8], b: &[u8]) -> std::cmp::Ordering { a.cmp(b) } }
impl Value for WithdrawalBurnKey {
    type SelfType<'a> = Self; type AsBytes<'a> = Vec<u8>;
    fn fixed_width() -> Option<usize> { Some(56) }
    fn from_bytes<'a>(data: &'a [u8]) -> Self where Self: 'a { Self(u64::from_le_bytes(data[..8].try_into().unwrap()), u64::from_le_bytes(data[8..16].try_into().unwrap()), u32::from_le_bytes(data[16..20].try_into().unwrap()), u32::from_le_bytes(data[20..24].try_into().unwrap()), read_u32s(&data[24..56])) }
    fn as_bytes<'a, 'b: 'a>(value: &'a Self) -> Vec<u8> where Self: 'a, Self: 'b { let mut bytes = Vec::with_capacity(56); bytes.extend_from_slice(&value.0.to_le_bytes()); bytes.extend_from_slice(&value.1.to_le_bytes()); bytes.extend_from_slice(&value.2.to_le_bytes()); bytes.extend_from_slice(&value.3.to_le_bytes()); put_u32s(&mut bytes, &value.4); bytes }
    fn type_name() -> TypeName { TypeName::new("guardian_common::WithdrawalBurnKey") }
}
impl Key for WithdrawalBurnKey { fn compare(a: &[u8], b: &[u8]) -> std::cmp::Ordering { a.cmp(b) } }
impl Value for NonceKey {
    type SelfType<'a> = Self; type AsBytes<'a> = Vec<u8>;
    fn fixed_width() -> Option<usize> { Some(49) }
    fn from_bytes<'a>(data: &'a [u8]) -> Self where Self: 'a { Self(u64::from_le_bytes(data[..8].try_into().unwrap()), u64::from_le_bytes(data[8..16].try_into().unwrap()), data[16], read_u32s(&data[17..49])) }
    fn as_bytes<'a, 'b: 'a>(value: &'a Self) -> Vec<u8> where Self: 'a, Self: 'b { let mut bytes = Vec::with_capacity(49); bytes.extend_from_slice(&value.0.to_le_bytes()); bytes.extend_from_slice(&value.1.to_le_bytes()); bytes.push(value.2); put_u32s(&mut bytes, &value.3); bytes }
    fn type_name() -> TypeName { TypeName::new("guardian_common::NonceKey") }
}
impl Key for NonceKey { fn compare(a: &[u8], b: &[u8]) -> std::cmp::Ordering { a.cmp(b) } }


fn unavailable(_: impl std::fmt::Display) -> GuardianSignError { GuardianSignError::DatabaseUnavailable }

fn codec() -> impl bincode::Options {
    bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes()
}

fn canonical_bytes<T: Serialize + DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let value: T = codec().deserialize(bytes).map_err(unavailable)?;
    let encoded = codec().serialize(&value).map_err(unavailable)?;
    if encoded.as_slice() != bytes { return Err(GuardianSignError::DatabaseUnavailable); }
    Ok(value)
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> { codec().serialize(value).map_err(unavailable) }

fn decode_account(key: (u64, u64), bytes: &[u8]) -> Result<GuardianAccount> {
    let value: GuardianAccount = canonical_bytes(bytes)?;
    if (value.network_magic, value.user_id) != key { return Err(GuardianSignError::DatabaseUnavailable); }
    value.validate()?;
    Ok(value)
}

fn decode_signed(key: (u64, u64, u64), bytes: &[u8]) -> Result<GuardianSigned> {
    let inner = decode_record(bytes, MAX_BODY_BYTES)?;
    let value: GuardianSigned = canonical_bytes(&inner)?;
    if (value.network_magic, value.user_id, value.nonce) != key { return Err(GuardianSignError::DatabaseUnavailable); }
    value.validate()?;
    Ok(value)
}

fn decode_session(key: (u64, u64, u64), bytes: &[u8]) -> Result<GuardianSession> {
    let inner = decode_record(bytes, MAX_SESSION_RECORD_BYTES)?;
    let value: GuardianSession = canonical_bytes(&inner)?;
    if (value.network_magic, value.user_id, value.nonce) != key { return Err(GuardianSignError::DatabaseUnavailable); }
    Ok(value)
}

fn open_database(file: File) -> Result<Database> {
    Database::builder().create_file(file).map_err(|error| match error {
        redb::DatabaseError::DatabaseAlreadyOpen => GuardianSignError::KeyUnavailable,
        _ => GuardianSignError::DatabaseUnavailable,
    })
}

fn nonce_bounds(network: u64, user: u64, after: u64) -> (Bound<(u64, u64, u64)>, Bound<(u64, u64, u64)>) {
    (Bound::Excluded((network, user, after)), Bound::Included((network, user, u64::MAX)))
}

pub struct GuardianDb { db: Arc<Database>, public_key: [u8; 33], config: Arc<GuardianConfig> }

impl GuardianDb {
    /// Same redb instance. The reader can only load sessions; it is not a second file or a cache.
    pub fn session_reader(&self) -> GuardianSessionReader {
        GuardianSessionReader { db: Arc::clone(&self.db), config: Arc::clone(&self.config) }
    }
}

/// Read-only session page and one-account readiness over the writer's `Arc<Database>`. No write methods.
pub struct GuardianSessionReader { db: Arc<Database>, config: Arc<GuardianConfig> }
impl GuardianSessionReader {
    pub async fn load_sessions(&self, network: u64, user: u64, after_nonce: Option<u64>, limit: u32) -> Result<Vec<GuardianSession>> {
        load_sessions(&self.db, network, user, after_nonce, limit).await
    }

    /// HTTP page: at most one canonical row, plus whether another key exists. One read transaction.
    /// The next key is not copied or decoded. Open and import already authorized every stored request.
    pub async fn load_session_page(&self, network: u64, user: u64, after_nonce: u64) -> Result<(Option<(u64, GuardianSessionRecord)>, bool)> {
        let tx = self.db.begin_read().map_err(unavailable)?;
        if !runtime_tables_present(&tx)? { return Ok((None, false)); }
        let sessions = tx.open_table(GUARDIAN_SESSION).map_err(unavailable)?;
        let mut range = sessions.range(nonce_bounds(network, user, after_nonce)).map_err(unavailable)?;
        let Some(first) = range.next() else { return Ok((None, false)); };
        let (key, value) = first.map_err(unavailable)?;
        let nonce = key.value().2;
        let session = decode_session(key.value(), value.value())?;
        let has_more = range.next().transpose().map_err(unavailable)?.is_some();
        Ok((Some((nonce, session.record)), has_more))
    }

    /// Schema-3 presence plus the single configured account. No session or signed-row scan.
    pub async fn readiness(&self) -> Result<GuardianReadiness> {
        let network = self.config.network_magic()?;
        let user = self.config.user_id();
        let tx = self.db.begin_read().map_err(unavailable)?;
        if !runtime_tables_present(&tx)? { return Ok(GuardianReadiness { schema_version: SCHEMA_VERSION, network_magic: network, user_id: user, runtime_initialized: false, halted: false }); }
        let account = {
            let accounts = tx.open_table(GUARDIAN_ACCOUNT).map_err(unavailable)?;
            if accounts.len().map_err(unavailable)? != 1 { return Err(GuardianSignError::DatabaseUnavailable); }
            let row = accounts.get((network, user)).map_err(unavailable)?.ok_or(GuardianSignError::DatabaseUnavailable)?;
            decode_account((network, user), row.value())?
        };
        if account.account_public_key != self.config.account_public_key()? { return Err(GuardianSignError::AccountIdentityConflict); }
        Ok(GuardianReadiness { schema_version: SCHEMA_VERSION, network_magic: network, user_id: user, runtime_initialized: true, halted: account.state == GuardianAccountState::Halted })
    }
}

/// Bounded operational status. `halted` is the account state, not a second readiness flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuardianReadiness {
    pub schema_version: u32,
    pub network_magic: u64,
    pub user_id: u64,
    pub runtime_initialized: bool,
    pub halted: bool,
}


impl GuardianDb {
    /// Creates an uninitialized database from an exclusively created protected empty file.
    pub async fn create(file: File, public_key: [u8; 33], config: Arc<GuardianConfig>) -> Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata().map_err(unavailable)?;
        if metadata.len() != 0 || !metadata.is_file() || metadata.mode() & 0o7777 != 0o600
            || metadata.uid() != unsafe { libc::geteuid() } || metadata.nlink() != 1 { return Err(GuardianSignError::DatabaseUnavailable); }
        Ok(Self { db: Arc::new(open_database(file)?), public_key, config })
    }

    /// Commits signer, initial account, and the empty deposit-tree and nonce-index tables atomically.
    /// The caller must first validate its key slot and checkpoint against the selected network.
    /// Existing or partial runtime tables are never repaired or reinitialized.
    pub async fn initialize_runtime(&mut self, account: &GuardianAccount) -> Result<()> {
        account.validate()?;
        if account.state != GuardianAccountState::Active || account.halt_reason.is_some() || account.imported_nonce.is_some()
            || account.imported_ending_leaf.is_some() || !account.withdrawal_chains.is_empty()
            || account.account_public_key != self.config.account_public_key()? || account.network_magic != self.config.network_magic()? { return Err(GuardianSignError::StateMismatch); }
        if self.runtime_initialized()? { return Err(GuardianSignError::StateMismatch); }
        let tx = self.db.begin_write().map_err(unavailable)?;
        {
            if account.user_id != self.config.user_id() {
                return Err(GuardianSignError::AccountIdentityConflict);
            }
            tx.open_table(GUARDIAN_SCHEMA).map_err(unavailable)?.insert((), SCHEMA_VERSION).map_err(unavailable)?;
            let mut signer = tx.open_table(GUARDIAN_SIGNER).map_err(unavailable)?;
            signer.insert((), &self.public_key).map_err(unavailable)?;
            let mut accounts = tx.open_table(GUARDIAN_ACCOUNT).map_err(unavailable)?;
            let bytes = encode(account)?;
            accounts.insert((account.network_magic, account.user_id), bytes.as_slice()).map_err(unavailable)?;
            let _signed = tx.open_table(GUARDIAN_SIGNED).map_err(unavailable)?;
            let _sessions = tx.open_table(GUARDIAN_SESSION).map_err(unavailable)?;
            let _deposit_tree_states = tx.open_table(DEPOSIT_TREE_STATES).map_err(unavailable)?;
            let _included_withdrawal_burns = tx.open_table(INCLUDED_WITHDRAWAL_BURNS).map_err(unavailable)?;
            let _nonces = tx.open_table(WITHDRAWAL_NONCE).map_err(unavailable)?;
        }
        tx.commit().map_err(unavailable)
    }


    pub fn validate_signed(&self, signed: &GuardianSigned) -> Result<()> {
        self.config.validate_signed(signed)
    }

    pub fn runtime_initialized(&self) -> Result<bool> {
        let tx = self.db.begin_read().map_err(unavailable)?;
        runtime_tables_present(&tx)
    }

    /// Opens an existing valid redb with zero or exactly eight schema-3 runtime tables.
    /// Legacy, partial, and unknown schemas are rejected without migration or writes.
    pub async fn open(file: File, public_key: [u8; 33], config: Arc<GuardianConfig>) -> Result<Self> {
        if file.metadata().map_err(unavailable)?.len() == 0 { return Err(GuardianSignError::DatabaseUnavailable); }
        let db = Arc::new(open_database(file)?);
        let tx = db.begin_read().map_err(unavailable)?;
        if !runtime_tables_present(&tx)? { return Ok(Self { db, public_key, config }); }
        {
            let signer = tx.open_table(GUARDIAN_SIGNER).map_err(unavailable)?;
            if signer.len().map_err(unavailable)? != 1 { return Err(GuardianSignError::DatabaseUnavailable); }
            let retained = signer.get(()).map_err(unavailable)?.ok_or(GuardianSignError::DatabaseUnavailable)?;
            if retained.value() != public_key { return Err(GuardianSignError::AccountIdentityConflict); }
        }
        let mut rows = Vec::new();
        {
            let accounts = tx.open_table(GUARDIAN_ACCOUNT).map_err(unavailable)?;
            for entry in accounts.range::<(u64, u64)>(..).map_err(unavailable)? {
                let (key, value) = entry.map_err(unavailable)?;
                rows.push((key.value(), value.value().to_vec()));
            }
        }
        if rows.len() != 1 { return Err(GuardianSignError::DatabaseUnavailable); }
        let account = decode_account(rows[0].0, &rows[0].1).map_err(|_| GuardianSignError::LegacyJournalSchema)?;
        if account.account_public_key != config.account_public_key()? || account.network_magic != config.network_magic()? { return Err(GuardianSignError::AccountIdentityConflict); }
        {
            let signed = tx.open_table(GUARDIAN_SIGNED).map_err(unavailable)?;
            for row in signed.iter().map_err(unavailable)? {
                let (key, bytes) = row.map_err(unavailable)?;
                let value = decode_signed(key.value(), bytes.value()).map_err(|_| GuardianSignError::LegacyJournalSchema)?;
                config.validate_signed(&value)?;
            }
            let sessions = tx.open_table(GUARDIAN_SESSION).map_err(unavailable)?;
            for row in sessions.iter().map_err(unavailable)? {
                let (key, bytes) = row.map_err(unavailable)?;
                let value = decode_session(key.value(), bytes.value()).map_err(|_| GuardianSignError::LegacyJournalSchema)?;
                value.validate(&config)?;
            }
        }
        drop(tx.open_table(DEPOSIT_TREE_STATES).map_err(unavailable)?);
        drop(tx.open_table(INCLUDED_WITHDRAWAL_BURNS).map_err(unavailable)?);
        drop(tx.open_table(WITHDRAWAL_NONCE).map_err(unavailable)?);
        Ok(Self { db, public_key, config })
    }



    pub async fn load_account(&mut self, network: u64, user: u64) -> Result<GuardianAccount> {
        let tx = self.db.begin_read().map_err(unavailable)?;
        let bytes = {
            let accounts = tx.open_table(GUARDIAN_ACCOUNT).map_err(unavailable)?;
            accounts.get((network, user)).map_err(unavailable)?.ok_or(GuardianSignError::DatabaseUnavailable)?.value().to_vec()
        };
        decode_account((network, user), &bytes)
    }

    pub async fn load_sessions(&self, network: u64, user: u64, after_nonce: Option<u64>, limit: u32) -> Result<Vec<GuardianSession>> {
        load_sessions(&self.db, network, user, after_nonce, limit).await
    }

    pub async fn load_signed(&mut self, network: u64, user: u64, after_nonce: Option<u64>, limit: u32) -> Result<Vec<GuardianSigned>> {
        validate_limit(limit)?;
        if !self.runtime_initialized()? { return Ok(Vec::new()); }
        let tx = self.db.begin_read().map_err(unavailable)?;
        let rows = {
            let signed = tx.open_table(GUARDIAN_SIGNED).map_err(unavailable)?;
            let mut rows = Vec::new();
            for entry in signed.range(nonce_bounds(network, user, after_nonce.unwrap_or(0))).map_err(unavailable)? {
                if rows.len() == limit as usize { break; }
                let (key, value) = entry.map_err(unavailable)?;
                rows.push((key.value(), value.value().to_vec()));
            }
            rows
        };
        rows.into_iter().map(|(key, bytes)| {
            let signed = decode_signed(key, &bytes)?;
            self.config.validate_signed(&signed)?;
            Ok(signed)
        }).collect()
    }

    pub async fn reserve_guardian_nonce(&mut self, value: &GuardianSigned) -> Result<GuardianSigned> {
        value.validate()?;
        if value.signature.is_some() { return Err(GuardianSignError::StateMismatch); }
        let tx = self.db.begin_write().map_err(unavailable)?;
        ensure_signer(&tx, self.public_key)?;
        let account = account_in(&tx, value.network_magic, value.user_id)?;
        ensure_active(&account)?;
        if let Some(existing) = signed_in(&tx, &self.config, value.network_magic, value.user_id, value.nonce)? {
            if !same_reservation(&existing, value) { return Err(GuardianSignError::NonceConflict); }
            if existing.signature.is_none() && account.imported_nonce.is_some_and(|nonce| nonce >= value.nonce) {
                return Err(GuardianSignError::NonceConflict);
            }
            tx.commit().map_err(unavailable)?;
            return Ok(existing);
        }
        // An imported nonce was consumed; pruning removed its signed row, so classify
        // the re-reservation exactly like the retained-row branch above.
        if account.imported_nonce.is_some_and(|nonce| nonce >= value.nonce) { return Err(GuardianSignError::NonceConflict); }
        let request = super::protocol::GuardianSignRequest::from_canonical_bytes(&value.request_bytes)?;
        if request.decode_trace()?.meta.public_key != account.account_public_key { return Err(GuardianSignError::AccountIdentityConflict); }
        if account.imported_ending_leaf.is_some_and(|leaf| leaf != value.starting_leaf_hash) { return Err(GuardianSignError::StateMismatch); }
        if value.nonce != account.imported_nonce.unwrap_or(0).checked_add(1).ok_or(GuardianSignError::NonceConflict)? {
            return Err(GuardianSignError::SessionHistoryUnavailable);
        }
        self.config.validate_signed(value)?;
        insert_signed(&tx, value)?;
        tx.commit().map_err(unavailable)?;
        Ok(value.clone())
    }

    pub async fn save_guardian_signature(&mut self, network: u64, user: u64, nonce: u64, request_bytes: &[u8], signature: [u8; 64]) -> Result<GuardianSigned> {
        let tx = self.db.begin_write().map_err(unavailable)?;
        ensure_signer(&tx, self.public_key)?;
        let account = account_in(&tx, network, user)?;
        ensure_active(&account)?;
        let mut value = signed_in(&tx, &self.config, network, user, nonce)?.ok_or(GuardianSignError::NonceConflict)?;
        if value.request_bytes != request_bytes { return Err(GuardianSignError::NonceConflict); }
        if let Some(saved) = value.signature {
            if saved != signature { return Err(GuardianSignError::NonceConflict); }
        } else {
            if account.imported_nonce.is_some_and(|imported| imported >= nonce) { return Err(GuardianSignError::NonceConflict); }
            value.signature = Some(signature);
            value.validate()?;
            insert_signed(&tx, &value)?;
        }
        tx.commit().map_err(unavailable)?;
        Ok(value)
    }

    /// The closure must not perform I/O; its result is withheld until commit succeeds.
    pub async fn authorize_response<T, F>(&mut self, network: u64, user: u64, nonce: u64, request_bytes: &[u8], serialize: F) -> Result<T>
    where F: FnOnce(&GuardianSigned, &GuardianConfig) -> Result<T> {
        let tx = self.db.begin_write().map_err(unavailable)?;
        ensure_signer(&tx, self.public_key)?;
        ensure_active(&account_in(&tx, network, user)?)?;
        let value = {
            let table = tx.open_table(GUARDIAN_SIGNED).map_err(unavailable)?;
            let bytes = table.get((network, user, nonce)).map_err(unavailable)?.ok_or(GuardianSignError::NonceConflict)?;
            decode_signed((network, user, nonce), bytes.value())?
        };
        if value.request_bytes != request_bytes || value.signature.is_none() { return Err(GuardianSignError::NonceConflict); }
        self.config.validate_signed(&value)?;
        let response = serialize(&value, &self.config)?;
        tx.commit().map_err(unavailable)?;
        Ok(response)
    }

    pub async fn halt_account(&mut self, network: u64, user: u64, reason: HaltReason) -> Result<()> {
        let tx = self.db.begin_write().map_err(unavailable)?;
        ensure_signer(&tx, self.public_key)?;
        let account = account_in(&tx, network, user)?;
        if account.state == GuardianAccountState::Active { write_halt(&tx, &account, reason)?; }
        tx.commit().map_err(unavailable)
    }

    pub async fn save_account(&mut self, value: &GuardianAccount) -> Result<()> {
        value.validate()?;
        let tx = self.db.begin_write().map_err(unavailable)?;
        ensure_signer(&tx, self.public_key)?;
        let old = account_in(&tx, value.network_magic, value.user_id)?;
        ensure_active(&old)?;
        if value.state != GuardianAccountState::Active || value.halt_reason.is_some() || value.imported_nonce != old.imported_nonce
            || value.imported_ending_leaf != old.imported_ending_leaf || value.account_public_key != old.account_public_key
            || value.withdrawal_chains != old.withdrawal_chains || value.last_checkpoint_id < old.last_checkpoint_id {
            return Err(GuardianSignError::StateMismatch);
        }
        if value.last_checkpoint_id == old.last_checkpoint_id && value.last_checkpoint_hash != old.last_checkpoint_hash {
            write_halt(&tx, &old, HaltReason::CheckpointConflict)?;
            tx.commit().map_err(unavailable)?;
            return Err(GuardianSignError::AccountHalted);
        }
        insert_account(&tx, value)?;
        tx.commit().map_err(unavailable)
    }

    /// The service must authenticate the record and derive its deltas before calling.
    /// This transaction checks durable continuity; it does not assert provider trust.
    /// The caller proved the session and that `checkpoint_hash` is its bound checkpoint leaf.
    /// One write commits the session, included deposit tree states, both nonce indexes, the sole account checkpoint, and drops this account's signed and session rows older than the imported nonce.
    pub async fn import_session(&mut self, value: &GuardianSession, deposit_tree_states: &[DepositTreeState], checkpoint_id: u64, checkpoint_hash: super::protocol::Hash4) -> Result<GuardianSession> {
        let request = value.record.request_json.decode()?;
        request.validate_authorization(&self.config)?;
        if (request.network_magic, request.user_id, request.session_nonce) != (value.network_magic, value.user_id, value.nonce) {
            return Err(GuardianSignError::StateMismatch);
        }
        if value.withdrawal_appends.len() != request.withdrawal_records.len()
            || value.withdrawal_appends.iter().zip(&request.withdrawal_records).any(|(append, burn)| &append.burn != burn) {
            return Err(GuardianSignError::StateMismatch);
        }
        super::protocol::validate_changed_deposit_tree_states(&request, deposit_tree_states)?;
        let request_bytes = request.canonical_bytes()?;
        let tx = self.db.begin_write().map_err(unavailable)?;
        ensure_signer(&tx, self.public_key)?;
        let account = account_in(&tx, value.network_magic, value.user_id)?;
        ensure_active(&account)?;
        if request.decode_trace()?.meta.public_key != account.account_public_key { return Err(GuardianSignError::AccountIdentityConflict); }
        if account.imported_nonce.is_some_and(|nonce| value.nonce < nonce) { return Err(GuardianSignError::NonceConflict); }
        if let Some(existing) = session_in(&tx, value.network_magic, value.user_id, value.nonce)? {
            if serde_json::to_string(&existing).map_err(unavailable)? != serde_json::to_string(value).map_err(unavailable)? {
                write_halt(&tx, &account, HaltReason::NonceConsumedDifferently)?;
                tx.commit().map_err(unavailable)?;
                return Err(GuardianSignError::AccountHalted);
            }
            if let Some(own) = signed_in(&tx, &self.config, value.network_magic, value.user_id, value.nonce)? {
                if own.request_bytes != request_bytes || own.deposit_tree_states != deposit_tree_states { return Err(GuardianSignError::NonceConflict); }
            }
            return Ok(existing);
        }
        if account.imported_nonce.is_some_and(|nonce| value.nonce <= nonce) { return Err(GuardianSignError::SessionHistoryUnavailable); }
        if checkpoint_id < account.last_checkpoint_id { return Err(GuardianSignError::StateMismatch); }
        if checkpoint_id == account.last_checkpoint_id && checkpoint_hash != account.last_checkpoint_hash {
            write_halt(&tx, &account, HaltReason::CheckpointConflict)?;
            tx.commit().map_err(unavailable)?;
            return Err(GuardianSignError::AccountHalted);
        }
        if account.imported_ending_leaf.is_some_and(|leaf| leaf != value.starting_leaf_hash) {
            write_halt(&tx, &account, HaltReason::IncludedTransitionMissing)?;
            tx.commit().map_err(unavailable)?;
            return Err(GuardianSignError::AccountHalted);
        }
        if let Some(own) = signed_in(&tx, &self.config, value.network_magic, value.user_id, value.nonce)? {
            if own.request_bytes != request_bytes || own.deposit_tree_states != deposit_tree_states
                || own.starting_leaf_hash != value.starting_leaf_hash || own.ending_leaf_hash != value.ending_leaf_hash {
                write_halt(&tx, &account, HaltReason::NonceConsumedDifferently)?;
                tx.commit().map_err(unavailable)?;
                return Err(GuardianSignError::AccountHalted);
            }
        }
        if let Err(error) = verify_batch_indexes(&tx, value) {
            if matches!(error, GuardianSignError::WithdrawalNonceConflict | GuardianSignError::StateMismatch) {
                write_halt(&tx, &account, HaltReason::AppendHistoryMismatch)?;
                tx.commit().map_err(unavailable)?;
                return Err(GuardianSignError::AccountHalted);
            }
            return Err(error);
        }
        let included = deposit_tree_states_in(&tx, value.network_magic, value.user_id)?;
        let (advanced, included) = match advance_included_account(&account, &included, value, deposit_tree_states, checkpoint_id, checkpoint_hash) {
            Ok(advanced) => advanced,
            Err(GuardianSignError::StateMismatch) => {
                write_halt(&tx, &account, HaltReason::IncludedTransitionMissing)?;
                tx.commit().map_err(unavailable)?;
                return Err(GuardianSignError::AccountHalted);
            }
            Err(error) => return Err(error),
        };
        insert_session(&tx, value)?;
        replace_deposit_tree_states(&tx, value.network_magic, value.user_id, &included)?;
        insert_batch_indexes(&tx, value)?;
        insert_account(&tx, &advanced)?;
        prune_imported_history(&tx, value.network_magic, value.user_id, value.nonce)?;
        tx.commit().map_err(unavailable)?;
        Ok(value.clone())
    }

    pub async fn load_deposit_tree_states(&mut self, network: u64, user: u64) -> Result<Vec<DepositTreeState>> {
        let tx = self.db.begin_read().map_err(unavailable)?;
        deposit_tree_states_in_read(&tx, network, user)
    }

    pub async fn contains_included_withdrawal_burn(&mut self, network: u64, user: u64, sender: u32, contract: u32, nonce: [u32; 8]) -> Result<bool> {
        let tx = self.db.begin_read().map_err(unavailable)?;
        let table = tx.open_table(INCLUDED_WITHDRAWAL_BURNS).map_err(unavailable)?;
        Ok(table.get(WithdrawalBurnKey(network, user, sender, contract, nonce)).map_err(unavailable)?.is_some())
    }

    pub async fn contains_withdrawal_nonce(&mut self, network: u64, user: u64, chain: u8, nonce: [u32; 8]) -> Result<bool> {
        let tx = self.db.begin_read().map_err(unavailable)?;
        let table = tx.open_table(WITHDRAWAL_NONCE).map_err(unavailable)?;
        Ok(table.get(NonceKey(network, user, chain, nonce)).map_err(unavailable)?.is_some())
    }


    pub async fn lookup_signed(&mut self, network: u64, user: u64, nonce: u64) -> Result<Option<GuardianSigned>> {
        let tx = self.db.begin_read().map_err(unavailable)?;
        let bytes = {
            let signed = tx.open_table(GUARDIAN_SIGNED).map_err(unavailable)?;
            signed.get((network, user, nonce)).map_err(unavailable)?.map(|row| row.value().to_vec())
        };
        bytes.as_deref().map(|bytes| {
            let signed = decode_signed((network, user, nonce), bytes)?;
            self.config.validate_signed(&signed)?;
            Ok(signed)
        }).transpose()
    }
}
/// Rows rewritten, or already stored, as `PSYGR001` envelopes. `rewritten` is false when schema 3 needed no write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuardianJournalMigration { pub signed: u64, pub sessions: u64, pub rewritten: bool }

/// Schema 2 becomes schema 3 in one transaction: only signed and session values change, and only into envelopes of their original bytes.
/// Keys are collected first. Each value is read, compressed, checked, and replaced before the next row, so history is not copied.
/// Schema 3 is checked and left untouched. Any other marker, including an empty file, is rejected without a write.
pub fn migrate_guardian_journal(db: &Database, public_key: [u8; 33], config: &GuardianConfig) -> Result<GuardianJournalMigration> {
    let marker = journal_marker(db)?;
    if marker == SCHEMA_VERSION {
        let (signed, sessions) = validate_current_journal(db, public_key, config)?;
        return Ok(GuardianJournalMigration { signed, sessions, rewritten: false });
    }
    if marker != RAW_SCHEMA_VERSION { return Err(GuardianSignError::LegacyJournalSchema); }
    let account_key = schema2_account(db, public_key, config)?;
    let (signed_keys, session_keys) = schema2_keys(db)?;
    let tx = db.begin_write().map_err(unavailable)?;
    if journal_marker_in_write(&tx)? != RAW_SCHEMA_VERSION { return Err(GuardianSignError::LegacyJournalSchema); }
    let signed = rewrite_signed_rows(&tx, &signed_keys, account_key, config)?;
    let sessions = rewrite_session_rows(&tx, &session_keys, account_key, config)?;
    tx.open_table(GUARDIAN_SCHEMA).map_err(unavailable)?.insert((), SCHEMA_VERSION).map_err(unavailable)?;
    tx.commit().map_err(unavailable)?;
    let (checked_signed, checked_sessions) = validate_current_journal(db, public_key, config)?;
    if checked_signed != signed || checked_sessions != sessions { return Err(GuardianSignError::DatabaseUnavailable); }
    Ok(GuardianJournalMigration { signed, sessions, rewritten: true })
}

fn journal_marker(db: &Database) -> Result<u32> {
    let tx = db.begin_read().map_err(|_| GuardianSignError::LegacyJournalSchema)?;
    if tx.list_multimap_tables().map_err(unavailable)?.next().is_some() { return Err(GuardianSignError::LegacyJournalSchema); }
    let names = tx.list_tables().map_err(unavailable)?.map(|table| table.name().to_owned()).collect::<BTreeSet<_>>();
    if names.is_empty() || names != TABLE_NAMES.into_iter().map(str::to_owned).collect() { return Err(GuardianSignError::LegacyJournalSchema); }
    let marker = {
        let schema = tx.open_table(GUARDIAN_SCHEMA).map_err(|_| GuardianSignError::LegacyJournalSchema)?;
        if schema.len().map_err(unavailable)? != 1 { return Err(GuardianSignError::LegacyJournalSchema); }
        let value = schema.get(()).map_err(unavailable)?;
        match value { Some(row) => Some(row.value()), None => None }
    };
    marker.ok_or(GuardianSignError::LegacyJournalSchema)
}

fn journal_marker_in_write(tx: &redb::WriteTransaction) -> Result<u32> {
    let marker = {
        let schema = tx.open_table(GUARDIAN_SCHEMA).map_err(|_| GuardianSignError::LegacyJournalSchema)?;
        if schema.len().map_err(unavailable)? != 1 { return Err(GuardianSignError::LegacyJournalSchema); }
        let value = schema.get(()).map_err(unavailable)?;
        match value { Some(row) => Some(row.value()), None => None }
    };
    marker.ok_or(GuardianSignError::LegacyJournalSchema)
}

fn validate_current_journal(db: &Database, public_key: [u8; 33], config: &GuardianConfig) -> Result<(u64, u64)> {
    let tx = db.begin_read().map_err(unavailable)?;
    if !runtime_tables_present(&tx)? { return Err(GuardianSignError::LegacyJournalSchema); }
    {
        let signer = tx.open_table(GUARDIAN_SIGNER).map_err(unavailable)?;
        if signer.len().map_err(unavailable)? != 1 || signer.get(()).map_err(unavailable)?.is_none_or(|row| row.value() != public_key) {
            return Err(GuardianSignError::AccountIdentityConflict);
        }
    }
    let accounts = tx.open_table(GUARDIAN_ACCOUNT).map_err(unavailable)?;
    if accounts.len().map_err(unavailable)? != 1 { return Err(GuardianSignError::DatabaseUnavailable); }
    let mut account_key = None;
    for row in accounts.iter().map_err(unavailable)? {
        let (key, bytes) = row.map_err(unavailable)?;
        let account = decode_account(key.value(), bytes.value()).map_err(|_| GuardianSignError::LegacyJournalSchema)?;
        if account.account_public_key != config.account_public_key()? || account.network_magic != config.network_magic()? {
            return Err(GuardianSignError::AccountIdentityConflict);
        }
        account_key = Some(key.value());
    }
    let account_key = account_key.ok_or(GuardianSignError::DatabaseUnavailable)?;
    let mut signed_count = 0u64;
    let signed = tx.open_table(GUARDIAN_SIGNED).map_err(unavailable)?;
    for row in signed.iter().map_err(unavailable)? {
        let (key, bytes) = row.map_err(unavailable)?;
        let value = decode_signed(key.value(), bytes.value()).map_err(|_| GuardianSignError::LegacyJournalSchema)?;
        if (value.network_magic, value.user_id) != account_key { return Err(GuardianSignError::DatabaseUnavailable); }
        config.validate_signed(&value)?;
        signed_count += 1;
    }
    let mut session_count = 0u64;
    let sessions = tx.open_table(GUARDIAN_SESSION).map_err(unavailable)?;
    for row in sessions.iter().map_err(unavailable)? {
        let (key, bytes) = row.map_err(unavailable)?;
        let value = decode_session(key.value(), bytes.value()).map_err(|_| GuardianSignError::LegacyJournalSchema)?;
        if (value.network_magic, value.user_id) != account_key { return Err(GuardianSignError::DatabaseUnavailable); }
        value.validate(config).map_err(|_| GuardianSignError::LegacyJournalSchema)?;
        session_count += 1;
    }
    Ok((signed_count, session_count))
}

fn schema2_account(db: &Database, public_key: [u8; 33], config: &GuardianConfig) -> Result<(u64, u64)> {
    let tx = db.begin_read().map_err(|_| GuardianSignError::LegacyJournalSchema)?;
    {
        let signer = tx.open_table(GUARDIAN_SIGNER).map_err(|_| GuardianSignError::LegacyJournalSchema)?;
        if signer.len().map_err(unavailable)? != 1 || signer.get(()).map_err(unavailable)?.is_none_or(|row| row.value() != public_key) {
            return Err(GuardianSignError::AccountIdentityConflict);
        }
    }
    let accounts = tx.open_table(GUARDIAN_ACCOUNT).map_err(|_| GuardianSignError::LegacyJournalSchema)?;
    if accounts.len().map_err(unavailable)? != 1 { return Err(GuardianSignError::DatabaseUnavailable); }
    let mut account_key = None;
    for row in accounts.iter().map_err(unavailable)? {
        let (key, bytes) = row.map_err(unavailable)?;
        let account = decode_account(key.value(), bytes.value()).map_err(|_| GuardianSignError::LegacyJournalSchema)?;
        if account.account_public_key != config.account_public_key()? || account.network_magic != config.network_magic()? {
            return Err(GuardianSignError::AccountIdentityConflict);
        }
        account_key = Some(key.value());
    }
    drop(tx.open_table(DEPOSIT_TREE_STATES).map_err(|_| GuardianSignError::LegacyJournalSchema)?);
    drop(tx.open_table(INCLUDED_WITHDRAWAL_BURNS).map_err(|_| GuardianSignError::LegacyJournalSchema)?);
    drop(tx.open_table(WITHDRAWAL_NONCE).map_err(|_| GuardianSignError::LegacyJournalSchema)?);
    account_key.ok_or(GuardianSignError::DatabaseUnavailable)
}

fn schema2_keys(db: &Database) -> Result<(Vec<(u64, u64, u64)>, Vec<(u64, u64, u64)>)> {
    let tx = db.begin_read().map_err(|_| GuardianSignError::LegacyJournalSchema)?;
    let mut signed = Vec::new();
    for row in tx.open_table(GUARDIAN_SIGNED).map_err(|_| GuardianSignError::LegacyJournalSchema)?.iter().map_err(unavailable)? {
        signed.push(row.map_err(unavailable)?.0.value());
    }
    let mut sessions = Vec::new();
    for row in tx.open_table(GUARDIAN_SESSION).map_err(|_| GuardianSignError::LegacyJournalSchema)?.iter().map_err(unavailable)? {
        sessions.push(row.map_err(unavailable)?.0.value());
    }
    Ok((signed, sessions))
}

fn rewrite_signed_rows(tx: &redb::WriteTransaction, keys: &[(u64, u64, u64)], account_key: (u64, u64), config: &GuardianConfig) -> Result<u64> {
    let mut table = tx.open_table(GUARDIAN_SIGNED).map_err(unavailable)?;
    for key in keys {
        let guard = table.get(*key).map_err(unavailable)?.ok_or(GuardianSignError::LegacyJournalSchema)?;
        if guard.value().len() > MAX_BODY_BYTES { return Err(GuardianSignError::LegacyJournalSchema); }
        let raw = guard.value().to_vec();
        drop(guard);
        let value: GuardianSigned = canonical_bytes(&raw).map_err(|_| GuardianSignError::LegacyJournalSchema)?;
        if (value.network_magic, value.user_id, value.nonce) != *key || (value.network_magic, value.user_id) != account_key {
            return Err(GuardianSignError::LegacyJournalSchema);
        }
        value.validate().map_err(|_| GuardianSignError::LegacyJournalSchema)?;
        config.validate_signed(&value).map_err(|_| GuardianSignError::LegacyJournalSchema)?;
        let request_id = super::protocol::GuardianSignRequest::from_canonical_bytes(&value.request_bytes).map_err(|_| GuardianSignError::LegacyJournalSchema)?.request_id().map_err(|_| GuardianSignError::LegacyJournalSchema)?;
        let frame = encode_record(&raw, MAX_BODY_BYTES).map_err(|_| GuardianSignError::LegacyJournalSchema)?;
        let decoded = decode_signed(*key, &frame).map_err(|_| GuardianSignError::LegacyJournalSchema)?;
        if decoded.request_bytes != value.request_bytes
            || super::protocol::GuardianSignRequest::from_canonical_bytes(&decoded.request_bytes).map_err(|_| GuardianSignError::LegacyJournalSchema)?.request_id().map_err(|_| GuardianSignError::LegacyJournalSchema)? != request_id {
            return Err(GuardianSignError::LegacyJournalSchema);
        }
        table.insert(*key, frame.as_slice()).map_err(unavailable)?;
    }
    Ok(keys.len() as u64)
}

fn rewrite_session_rows(tx: &redb::WriteTransaction, keys: &[(u64, u64, u64)], account_key: (u64, u64), config: &GuardianConfig) -> Result<u64> {
    let mut table = tx.open_table(GUARDIAN_SESSION).map_err(unavailable)?;
    for key in keys {
        let guard = table.get(*key).map_err(unavailable)?.ok_or(GuardianSignError::LegacyJournalSchema)?;
        if guard.value().len() > MAX_SESSION_RECORD_BYTES { return Err(GuardianSignError::LegacyJournalSchema); }
        let raw = guard.value().to_vec();
        drop(guard);
        let value: GuardianSession = canonical_bytes(&raw).map_err(|_| GuardianSignError::LegacyJournalSchema)?;
        if (value.network_magic, value.user_id, value.nonce) != *key || (value.network_magic, value.user_id) != account_key {
            return Err(GuardianSignError::LegacyJournalSchema);
        }
        let request = value.record.request_json.decode().map_err(|_| GuardianSignError::LegacyJournalSchema)?;
        value.validate(config).map_err(|_| GuardianSignError::LegacyJournalSchema)?;
        let request_id = request.request_id().map_err(|_| GuardianSignError::LegacyJournalSchema)?;
        let frame = encode_record(&raw, MAX_SESSION_RECORD_BYTES).map_err(|_| GuardianSignError::LegacyJournalSchema)?;
        let decoded = decode_session(*key, &frame).map_err(|_| GuardianSignError::LegacyJournalSchema)?;
        if decoded.record.request_json.as_str() != value.record.request_json.as_str()
            || decoded.record.request_json.decode().map_err(|_| GuardianSignError::LegacyJournalSchema)?.request_id().map_err(|_| GuardianSignError::LegacyJournalSchema)? != request_id {
            return Err(GuardianSignError::LegacyJournalSchema);
        }
        table.insert(*key, frame.as_slice()).map_err(unavailable)?;
    }
    Ok(keys.len() as u64)
}


async fn load_sessions(db: &Database, network: u64, user: u64, after_nonce: Option<u64>, limit: u32) -> Result<Vec<GuardianSession>> {
    validate_limit(limit)?;
    let tx = db.begin_read().map_err(unavailable)?;
    if !runtime_tables_present(&tx)? { return Ok(Vec::new()); }
    let sessions = tx.open_table(GUARDIAN_SESSION).map_err(unavailable)?;
    let mut rows = Vec::new();
    for entry in sessions.range(nonce_bounds(network, user, after_nonce.unwrap_or(0))).map_err(unavailable)? {
        if rows.len() == limit as usize { break; }
        let (key, value) = entry.map_err(unavailable)?;
        rows.push(decode_session(key.value(), value.value())?);
    }
    Ok(rows)
}


fn runtime_tables_present(tx: &redb::ReadTransaction) -> Result<bool> {
    let names = tx.list_tables().map_err(unavailable)?.map(|table| table.name().to_owned()).collect::<BTreeSet<_>>();
    if tx.list_multimap_tables().map_err(unavailable)?.next().is_some() { return Err(GuardianSignError::LegacyJournalSchema); }
    if names.is_empty() { return Ok(false); }
    if names != TABLE_NAMES.into_iter().map(str::to_owned).collect() { return Err(GuardianSignError::LegacyJournalSchema); }
    let schema = tx.open_table(GUARDIAN_SCHEMA).map_err(|_| GuardianSignError::LegacyJournalSchema)?;
    if schema.len().map_err(unavailable)? != 1 || schema.get(()).map_err(unavailable)?.map(|row| row.value()) != Some(SCHEMA_VERSION) { return Err(GuardianSignError::LegacyJournalSchema); }
    drop(tx.open_table(GUARDIAN_SIGNER).map_err(unavailable)?);
    drop(tx.open_table(GUARDIAN_ACCOUNT).map_err(unavailable)?);
    drop(tx.open_table(GUARDIAN_SIGNED).map_err(unavailable)?);
    drop(tx.open_table(GUARDIAN_SESSION).map_err(unavailable)?);
    drop(tx.open_table(DEPOSIT_TREE_STATES).map_err(unavailable)?);
    drop(tx.open_table(INCLUDED_WITHDRAWAL_BURNS).map_err(unavailable)?);
    drop(tx.open_table(WITHDRAWAL_NONCE).map_err(unavailable)?);
    Ok(true)
}

fn ensure_signer(tx: &redb::WriteTransaction, public_key: [u8; 33]) -> Result<()> {
    let retained = {
        let signer = tx.open_table(GUARDIAN_SIGNER).map_err(unavailable)?;
        let row = signer.get(()).map_err(unavailable)?.ok_or(GuardianSignError::DatabaseUnavailable)?;
        row.value()
    };
    if retained != public_key { return Err(GuardianSignError::DatabaseUnavailable); }
    Ok(())
}

fn account_in(tx: &redb::WriteTransaction, network: u64, user: u64) -> Result<GuardianAccount> {
    let bytes = {
        let accounts = tx.open_table(GUARDIAN_ACCOUNT).map_err(unavailable)?;
        let row = accounts.get((network, user)).map_err(unavailable)?.ok_or(GuardianSignError::DatabaseUnavailable)?;
        row.value().to_vec()
    };
    decode_account((network, user), &bytes)
}

fn signed_in(tx: &redb::WriteTransaction, config: &GuardianConfig, network: u64, user: u64, nonce: u64) -> Result<Option<GuardianSigned>> {
    let bytes = {
        let signed = tx.open_table(GUARDIAN_SIGNED).map_err(unavailable)?;
        let row = signed.get((network, user, nonce)).map_err(unavailable)?;
        row.map(|guard| guard.value().to_vec())
    };
    bytes.as_deref().map(|bytes| {
        let signed = decode_signed((network, user, nonce), bytes)?;
        config.validate_signed(&signed)?;
        Ok(signed)
    }).transpose()
}

fn session_in(tx: &redb::WriteTransaction, network: u64, user: u64, nonce: u64) -> Result<Option<GuardianSession>> {
    let bytes = {
        let sessions = tx.open_table(GUARDIAN_SESSION).map_err(unavailable)?;
        let row = sessions.get((network, user, nonce)).map_err(unavailable)?;
        row.map(|guard| guard.value().to_vec())
    };
    bytes.as_deref().map(|bytes| decode_session((network, user, nonce), bytes)).transpose()
}

fn insert_account(tx: &redb::WriteTransaction, value: &GuardianAccount) -> Result<()> {
    let mut accounts = tx.open_table(GUARDIAN_ACCOUNT).map_err(unavailable)?;
    let bytes = encode(value)?;
    accounts.insert((value.network_magic, value.user_id), bytes.as_slice()).map_err(unavailable)?;
    Ok(())
}

fn insert_signed(tx: &redb::WriteTransaction, value: &GuardianSigned) -> Result<()> {
    let mut signed = tx.open_table(GUARDIAN_SIGNED).map_err(unavailable)?;
    let bytes = encode_record(&encode(value)?, MAX_BODY_BYTES)?;
    signed.insert((value.network_magic, value.user_id, value.nonce), bytes.as_slice()).map_err(unavailable)?;
    Ok(())
}

fn insert_session(tx: &redb::WriteTransaction, value: &GuardianSession) -> Result<()> {
    let mut sessions = tx.open_table(GUARDIAN_SESSION).map_err(unavailable)?;
    let bytes = encode_record(&encode(value)?, MAX_SESSION_RECORD_BYTES)?;
    sessions.insert((value.network_magic, value.user_id, value.nonce), bytes.as_slice()).map_err(unavailable)?;
    Ok(())
}

/// Drops signed decisions through `nonce` and imported sessions strictly older than `nonce`.
/// Session `nonce`, later signed rows, deposits, the account, and withdrawal indexes stay.
fn prune_imported_history(tx: &redb::WriteTransaction, network: u64, user: u64, nonce: u64) -> Result<()> {
    let through = (Bound::Included((network, user, 0)), Bound::Included((network, user, nonce)));
    let older = (Bound::Included((network, user, 0)), Bound::Excluded((network, user, nonce)));
    for (table, range) in [(GUARDIAN_SIGNED, through), (GUARDIAN_SESSION, older)] {
        let mut rows = tx.open_table(table).map_err(unavailable)?;
        let keys = rows.range(range).map_err(unavailable)?.map(|entry| entry.map(|(key, _)| key.value())).collect::<std::result::Result<Vec<_>, _>>().map_err(unavailable)?;
        for key in keys { rows.remove(key).map_err(unavailable)?; }
    }
    Ok(())
}

fn write_halt(tx: &redb::WriteTransaction, account: &GuardianAccount, reason: HaltReason) -> Result<()> {
    let mut halted = account.clone();
    halted.state = GuardianAccountState::Halted;
    halted.halt_reason = Some(reason);
    halted.validate()?;
    insert_account(tx, &halted)
}


fn ensure_active(account: &GuardianAccount) -> Result<()> {
    if account.state == GuardianAccountState::Halted { return Err(GuardianSignError::AccountHalted); }
    Ok(())
}

fn validate_limit(limit: u32) -> Result<()> {
    if !(1..=64).contains(&limit) { return Err(GuardianSignError::MalformedRequest); }
    Ok(())
}

fn same_reservation(a: &GuardianSigned, b: &GuardianSigned) -> bool {
    a.network_magic == b.network_magic && a.user_id == b.user_id && a.nonce == b.nonce
        && a.request_bytes == b.request_bytes && a.deposit_tree_states == b.deposit_tree_states
        && a.starting_leaf_hash == b.starting_leaf_hash && a.ending_leaf_hash == b.ending_leaf_hash
        && a.message == b.message
}

fn deposit_tree_states_in(tx: &redb::WriteTransaction, network: u64, user: u64) -> Result<Vec<DepositTreeState>> {
    let table = tx.open_table(DEPOSIT_TREE_STATES).map_err(unavailable)?;
    let mut rows = Vec::new();
    for chain in 0..=u8::MAX {
        if let Some(row) = table.get(DepositTreeKey(network, user, chain)).map_err(unavailable)? { rows.push((chain, row.value().to_vec())); }
    }
    decode_deposit_tree_states(rows)
}

fn deposit_tree_states_in_read(tx: &redb::ReadTransaction, network: u64, user: u64) -> Result<Vec<DepositTreeState>> {
    let table = tx.open_table(DEPOSIT_TREE_STATES).map_err(unavailable)?;
    let mut rows = Vec::new();
    for chain in 0..=u8::MAX {
        if let Some(row) = table.get(DepositTreeKey(network, user, chain)).map_err(unavailable)? { rows.push((chain, row.value().to_vec())); }
    }
    decode_deposit_tree_states(rows)
}

fn decode_deposit_tree_states(rows: Vec<(u8, Vec<u8>)>) -> Result<Vec<DepositTreeState>> {
    rows.into_iter().map(|(chain, bytes)| {
        let deposit_tree_state: DepositTreeState = canonical_bytes(&bytes)?;
        if chain != deposit_tree_state.anchor.chain_index { return Err(GuardianSignError::DatabaseUnavailable); }
        deposit_tree_state.validate()?;
        Ok(deposit_tree_state)
    }).collect()
}
fn replace_deposit_tree_states(tx: &redb::WriteTransaction, network: u64, user: u64, deposit_tree_states: &[DepositTreeState]) -> Result<()> {
    let mut table = tx.open_table(DEPOSIT_TREE_STATES).map_err(unavailable)?;
    for deposit_tree_state in deposit_tree_states {
        deposit_tree_state.validate()?;
        let bytes = encode(deposit_tree_state)?;
        table.insert(DepositTreeKey(network, user, deposit_tree_state.anchor.chain_index), bytes.as_slice()).map_err(unavailable)?;
    }
    Ok(())
}

fn verify_batch_indexes(tx: &redb::WriteTransaction, value: &GuardianSession) -> Result<()> {
    let mut identities = BTreeSet::new();
    let mut nonces = BTreeSet::new();
    let included_withdrawal_burns = tx.open_table(INCLUDED_WITHDRAWAL_BURNS).map_err(unavailable)?;
    let nonces_table = tx.open_table(WITHDRAWAL_NONCE).map_err(unavailable)?;
    for append in &value.withdrawal_appends {
        let burn = &append.burn;
        if append.chain_index != burn.destination_chain_index
            || !identities.insert((burn.sender_user_id, burn.token_contract_id, burn.nonce))
            || !nonces.insert((append.chain_index, burn.nonce))
            || included_withdrawal_burns.get(WithdrawalBurnKey(value.network_magic, value.user_id, burn.sender_user_id, burn.token_contract_id, burn.nonce)).map_err(unavailable)?.is_some()
            || nonces_table.get(NonceKey(value.network_magic, value.user_id, append.chain_index, burn.nonce)).map_err(unavailable)?.is_some() {
            return Err(GuardianSignError::WithdrawalNonceConflict);
        }
    }
    Ok(())
}

fn insert_batch_indexes(tx: &redb::WriteTransaction, value: &GuardianSession) -> Result<()> {
    let mut included_withdrawal_burns = tx.open_table(INCLUDED_WITHDRAWAL_BURNS).map_err(unavailable)?;
    let mut nonces = tx.open_table(WITHDRAWAL_NONCE).map_err(unavailable)?;
    for append in &value.withdrawal_appends {
        let burn = &append.burn;
        included_withdrawal_burns.insert(WithdrawalBurnKey(value.network_magic, value.user_id, burn.sender_user_id, burn.token_contract_id, burn.nonce), value.nonce).map_err(unavailable)?;
        nonces.insert(NonceKey(value.network_magic, value.user_id, append.chain_index, burn.nonce), value.nonce).map_err(unavailable)?;
    }
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use super::super::protocol::{GuardianOperation, GuardianSessionRecord, Hash4, JsonText, WithdrawalAppendRecord, WithdrawalBurnRecord};
    use psy_client_common::data::base_types::hash256::Hash256;
    use psy_crypto::signature::secp256k1::core::PsyCompressedSecp256K1Signature;
    use psy_vm::ups::multisig::MultisigSignatures;
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    const KEY: [u8; 33] = [2; 33];

    struct TestDb { db: Option<GuardianDb>, path: PathBuf }

    impl TestDb {
        async fn create(account: &GuardianAccount) -> Self {
            let path = std::env::temp_dir().join(format!("guardian-db-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            let file = OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&path).expect("disposable database");
            let mut db = GuardianDb::create(file, KEY, Arc::new(super::super::protocol::codec_config_fixture(account.network_magic))).await.unwrap();
            db.initialize_runtime(account).await.expect("initialize runtime");
            Self { db: Some(db), path }
        }

        fn db(&mut self) -> &mut GuardianDb { self.db.as_mut().expect("open database") }

        fn reopen(&mut self) -> File {
            self.db.take();
            OpenOptions::new().read(true).write(true).open(&self.path).expect("reopen")
        }
    }

    impl Drop for TestDb {
        fn drop(&mut self) {
            self.db.take();
            let _ = std::fs::remove_file(&self.path);
        }
    }

    static NEXT: AtomicU64 = AtomicU64::new(1);

    fn approval() -> Arc<GuardianConfig> { Arc::new(super::super::protocol::codec_config_fixture(90101)) }

    fn change_request_identity(signed: &mut GuardianSigned) {
        let mut request = super::super::protocol::GuardianSignRequest::from_canonical_bytes(&signed.request_bytes).unwrap();
        let mut trace = request.decode_trace().unwrap();
        trace.meta.public_key = Hash4::from_values(99, 0, 0, 0);
        let mut generated = request.trace_json.decode().unwrap();
        generated.pk_hash = trace.meta.public_key.to_string();
        generated.trace.payload = serde_json::to_string(&trace).unwrap();
        request.trace_json = JsonText::from_value(&generated).unwrap();
        signed.request_bytes = request.canonical_bytes().unwrap();
    }

    async fn uninitialized_database() -> TestDb {
        let path = std::env::temp_dir().join(format!("guardian-approval-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        let file = OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&path).unwrap();
        let db = GuardianDb::create(file, KEY, approval()).await.unwrap();
        TestDb { db: Some(db), path }
    }


    #[tokio::test]
    async fn runtime_initializes_once_and_aborted_write_leaves_no_tables() {
        let mut owned = uninitialized_database().await;
        assert!(!owned.db().runtime_initialized().unwrap());
        assert!(owned.db().load_sessions(90101, 524288, None, 1).await.unwrap().is_empty());
        assert!(owned.db().load_signed(90101, 524288, None, 1).await.unwrap().is_empty());
        assert_eq!(owned.db().db.begin_read().unwrap().list_tables().unwrap().count(), 0);
        let original = owned.db().config.account_public_key().unwrap();
        {
            let tx = owned.db().db.begin_write().unwrap();
            tx.open_table(GUARDIAN_SIGNER).unwrap().insert((), &KEY).unwrap();
            tx.open_table(GUARDIAN_ACCOUNT).unwrap();
            tx.abort().unwrap();
        }
        let file = owned.reopen();
        owned.db = Some(GuardianDb::open(file, KEY, approval()).await.unwrap());
        assert!(!owned.db().runtime_initialized().unwrap());
        let mut wrong = active(90101, 0); wrong.user_id += 1;
        assert!(owned.db().initialize_runtime(&wrong).await.is_err());
        assert!(!owned.db().runtime_initialized().unwrap());
        owned.db().initialize_runtime(&active(90101, 0)).await.unwrap();
        assert!(owned.db().runtime_initialized().unwrap());
        let names = owned.db().db.begin_read().unwrap().list_tables().unwrap().map(|table| table.name().to_owned()).collect::<BTreeSet<_>>();
        assert_eq!(names, TABLE_NAMES.into_iter().map(str::to_owned).collect());
        assert!(owned.db().initialize_runtime(&active(90101, 0)).await.is_err());
        assert_eq!(owned.db().config.account_public_key().unwrap(), original);
        let file = owned.reopen();
        owned.db = Some(GuardianDb::open(file, KEY, approval()).await.unwrap());
        assert!(owned.db().runtime_initialized().unwrap());
    }
    /// A session reader shares the writer's database and returns while that write is open.
    #[tokio::test]
    async fn session_reader_returns_while_write_transaction_is_held() {
        let mut owned = TestDb::create(&active(90101, 0)).await;
        let reader = owned.db().session_reader();
        let held = owned.db().db.begin_write().unwrap();
        let page = tokio::time::timeout(std::time::Duration::from_secs(2), reader.load_sessions(90101, 524288, Some(0), 1)).await
            .expect("session read blocked on the held write").unwrap();
        assert!(page.is_empty());
        drop(held);
    }
    #[tokio::test]
    async fn readiness_reads_the_single_account_without_scanning_sessions() {
        let mut owned = TestDb::create(&active(90101, 0)).await;
        let reader = owned.db().session_reader();
        let ready = reader.readiness().await.expect("initialized account");
        assert_eq!(ready, GuardianReadiness { schema_version: SCHEMA_VERSION, network_magic: 90101, user_id: 524288, runtime_initialized: true, halted: false });
        owned.db().halt_account(90101, 524288, HaltReason::FinalityConflict).await.expect("halt");
        let halted = reader.readiness().await.expect("halted account");
        assert!(halted.runtime_initialized && halted.halted);
        let mut empty = uninitialized_database().await;
        let unread = empty.db().session_reader().readiness().await.expect("uninitialized");
        assert!(!unread.runtime_initialized && !unread.halted);
        assert_eq!(unread.schema_version, SCHEMA_VERSION);
    }



    #[tokio::test]
    async fn partial_runtime_unknown_tables_and_wrong_table_types_are_not_repaired() {
        for damage in 0..4 {
            let mut owned = uninitialized_database().await;
            let tx = owned.db().db.begin_write().unwrap();
            match damage {
                0 => { tx.open_table(GUARDIAN_SIGNER).unwrap(); }
                1 => { tx.open_table(TableDefinition::<(), u64>::new("unexpected")).unwrap(); }
                2 => { tx.open_multimap_table(redb::MultimapTableDefinition::<u64, u64>::new("unexpected")).unwrap(); }
                _ => {
                    tx.open_table(TableDefinition::<u64, u64>::new("guardian_signer")).unwrap();
                    tx.open_table(GUARDIAN_ACCOUNT).unwrap();
                    tx.open_table(GUARDIAN_SIGNED).unwrap();
                    tx.open_table(GUARDIAN_SESSION).unwrap();
                    tx.open_table(DEPOSIT_TREE_STATES).unwrap();
                    tx.open_table(INCLUDED_WITHDRAWAL_BURNS).unwrap();
                    tx.open_table(WITHDRAWAL_NONCE).unwrap();
                }
            }
            tx.commit().unwrap();
            assert!(owned.db().runtime_initialized().is_err());
            assert!(owned.db().initialize_runtime(&active(90101, 0)).await.is_err());
            let file = owned.reopen();
            assert!(GuardianDb::open(file, KEY, approval()).await.is_err());
        }
    }


    fn active(network: u64, checkpoint: u64) -> GuardianAccount {
        GuardianAccount {
            network_magic: network, user_id: 524288, state: GuardianAccountState::Active,
            last_checkpoint_id: checkpoint, last_checkpoint_hash: Hash4::default(), imported_nonce: None,
            account_public_key: approval().account_public_key().expect("account public key"), imported_ending_leaf: None,
            withdrawal_chains: Vec::new(), halt_reason: None,
        }
    }

    /// Persistence-boundary fixture: synthetic typed signature bytes, no private key material.
    /// Production verifies multisig inclusion cryptographically; the journal only needs the
    /// canonical typed shape that `GuardianSession::validate` checks structurally.
    fn signatures() -> MultisigSignatures {
        MultisigSignatures {
            member_indices: vec![0, 1],
            signatures: vec![PsyCompressedSecp256K1Signature { public_key: [2; 33], signature: [1; 64], message: Hash256([0; 32]) }; 2],
        }
    }

    fn history(network: u64, nonce: u64, appends: Vec<WithdrawalAppendRecord>) -> GuardianSession {
        let mut request = super::super::protocol::codec_request_fixture();
        request.network_magic = network;
        request.session_nonce = nonce;
        request.withdrawal_records = appends.iter().map(|append| append.burn.clone()).collect();
        if !appends.is_empty() { request.operation = GuardianOperation::Bridge; }
        let mut trace = super::super::protocol::codec_request_fixture().decode_trace().expect("typed trace");
        trace.meta.network_magic = network;
        trace.finalization.nonce = plonky2::field::goldilocks_field::GoldilocksField(nonce);
        let mut generated = request.trace_json.decode().expect("trace envelope");
        generated.trace.payload = serde_json::to_string(&trace).expect("trace JSON");
        request.trace_json = JsonText::from_value(&generated).expect("canonical trace envelope");
        request.validate().expect("structural request");
        GuardianSession {
            network_magic: network, user_id: 524288, nonce,
            record: GuardianSessionRecord {
                request_json: JsonText::from_value(&request).expect("request JSON"),
                signatures_json: JsonText::from_value(&signatures()).expect("signature container"),
                endcap_input_json: JsonText::from_value(&trace.finalization.submit_end_cap_input).expect("EndCap input"),
                endcap_proof_hex: "0x00".to_owned(), included_checkpoint_id: nonce,
                included_checkpoint_hash: Hash4::default(),
            },
            starting_leaf_hash: Hash4::default(), ending_leaf_hash: Hash4::default(), withdrawal_appends: appends,
        }
    }

    fn append(index: u32, sender: u32, nonce: u32) -> WithdrawalAppendRecord {
        let mut amount = [0; 8]; amount[7] = 1;
        let mut recipient = [0; 8]; recipient[7] = 1;
        let mut words = [0; 8]; words[7] = nonce;
        WithdrawalAppendRecord { chain_index: 0, append_index: index, burn: WithdrawalBurnRecord {
            sender_user_id: sender, token_contract_id: 4, destination_chain_index: 0,
            token: [0; 8], amount, recipient, nonce: words,
        } }
    }

    fn reserved() -> GuardianSigned {
        let request = super::super::protocol::codec_request_fixture();
        GuardianSigned {
            network_magic: request.network_magic, user_id: request.user_id, nonce: request.session_nonce,
            request_bytes: request.canonical_bytes().expect("canonical request"),
            starting_leaf_hash: Hash4::default(), ending_leaf_hash: Hash4::default(), message: [3; 32],
            deposit_tree_states: Vec::new(), signature: None,
        }
    }


    #[tokio::test]
    async fn changed_initial_members_reject_retained_identity_after_reopen() {
        let signed = reserved();
        let mut owned = TestDb::create(&active(signed.network_magic, 0)).await;
        owned.db().reserve_guardian_nonce(&signed).await.unwrap();
        owned.db().save_guardian_signature(signed.network_magic, signed.user_id, signed.nonce, &signed.request_bytes, [5; 64]).await.unwrap();
        let mut changed = (*approval()).clone();
        changed.network.guardian_initial_member_hashes.as_mut().unwrap()[0] = Hash4::from_values(7, 0, 0, 0);
        let file = owned.reopen();
        assert!(matches!(GuardianDb::open(file, KEY, Arc::new(changed)).await, Err(GuardianSignError::AccountIdentityConflict)));
    }

    #[tokio::test]
    async fn invalid_account_identity_cannot_reserve_a_nonce() {
        let mut signed = reserved();
        let mut owned = TestDb::create(&active(signed.network_magic, 0)).await;
        change_request_identity(&mut signed);
        assert!(matches!(owned.db().reserve_guardian_nonce(&signed).await, Err(GuardianSignError::AccountIdentityConflict)));
        assert!(owned.db().lookup_signed(signed.network_magic, signed.user_id, signed.nonce).await.unwrap().is_none());
    }

    async fn assert_halted_cursor(db: &mut GuardianDb, network: u64, nonce: u64) {
        let saved = db.load_account(network, 524288).await.expect("durable halt");
        assert_eq!(saved.state, GuardianAccountState::Halted);
        assert_eq!(saved.imported_nonce, Some(nonce));
        assert!(db.load_sessions(network, 524288, Some(nonce), 1).await.expect("no conflicting insert").is_empty());
    }

    #[test]
    fn reservation_compares_full_bytes_not_only_digest() {
        let original = reserved();
        let mut retry = original.clone();
        retry.request_bytes.push(9);
        assert!(!same_reservation(&original, &retry));
        retry = original.clone();
        change_request_identity(&mut retry);
        assert!(!same_reservation(&original, &retry));
        retry = original.clone();
        retry.signature = Some([8; 64]);
        assert!(same_reservation(&original, &retry));
    }

    #[tokio::test]
    async fn reservation_survives_reopen_and_halt_is_terminal() {
        let value = reserved();
        let mut owned = TestDb::create(&active(value.network_magic, u64::MAX)).await;
        let contender = OpenOptions::new().read(true).write(true).open(&owned.path).expect("contender");
        assert!(matches!(GuardianDb::open(contender, KEY, approval()).await, Err(GuardianSignError::KeyUnavailable)));
        owned.db().reserve_guardian_nonce(&value).await.expect("reserve");
        let mut different = value.clone();
        change_request_identity(&mut different);
        assert!(matches!(owned.db().reserve_guardian_nonce(&different).await, Err(GuardianSignError::NonceConflict)));
        let file = owned.reopen();
        assert!(matches!(GuardianDb::open(file, [3; 33], approval()).await, Err(GuardianSignError::AccountIdentityConflict)));
        let mut db = GuardianDb::open(owned.reopen(), KEY, approval()).await.expect("reopen");
        let saved = db.reserve_guardian_nonce(&value).await.expect("durable retry");
        assert!(saved.signature.is_none());
        assert_eq!(db.load_account(value.network_magic, value.user_id).await.expect("load").last_checkpoint_id, u64::MAX);
        let signed = db.save_guardian_signature(value.network_magic, value.user_id, value.nonce, &value.request_bytes, [3; 64]).await.expect("save");
        assert_eq!(signed.signature, Some([3; 64]));
        assert!(matches!(db.save_guardian_signature(value.network_magic, value.user_id, value.nonce, &value.request_bytes, [4; 64]).await, Err(GuardianSignError::NonceConflict)));
        assert_eq!(db.lookup_signed(value.network_magic, value.user_id, value.nonce).await.expect("unchanged").expect("decision").signature, Some([3; 64]));
        db.halt_account(value.network_magic, value.user_id, HaltReason::AppendHistoryMismatch).await.expect("halt");
        assert!(matches!(db.authorize_response(value.network_magic, value.user_id, value.nonce, &value.request_bytes, |_, _| Ok(())).await, Err(GuardianSignError::AccountHalted)));
        assert!(matches!(db.save_account(&active(value.network_magic, u64::MAX)).await, Err(GuardianSignError::AccountHalted)));
        assert_eq!(db.load_account(value.network_magic, value.user_id).await.expect("load halted").state, GuardianAccountState::Halted);
        drop(db);
        let mut restored = GuardianDb::open(OpenOptions::new().read(true).write(true).open(&owned.path).expect("restored"), KEY, approval()).await.expect("halt reopened");
        assert_eq!(restored.load_account(value.network_magic, value.user_id).await.expect("retained halt").state, GuardianAccountState::Halted);
    }

    #[tokio::test]
    async fn signed_reservation_survives_differing_request_and_reuse_returns_signature() {
        let value = reserved();
        let mut owned = TestDb::create(&active(value.network_magic, u64::MAX)).await;
        owned.db().reserve_guardian_nonce(&value).await.expect("reserve");
        owned.db().save_guardian_signature(value.network_magic, value.user_id, value.nonce, &value.request_bytes, [5; 64]).await.expect("sign");
        let mut differing = value.clone();
        change_request_identity(&mut differing);
        assert!(matches!(owned.db().reserve_guardian_nonce(&differing).await, Err(GuardianSignError::NonceConflict)));
        let retained = owned.db().lookup_signed(value.network_magic, value.user_id, value.nonce).await.expect("lookup").expect("signed reservation");
        assert_eq!(retained.signature, Some([5; 64]));
        assert!(same_reservation(&retained, &value));
        let reused = owned.db().reserve_guardian_nonce(&value).await.expect("same-request reuse");
        assert_eq!(reused.signature, Some([5; 64]));
        assert_eq!(owned.db().lookup_signed(value.network_magic, value.user_id, value.nonce).await.expect("unchanged").expect("decision").signature, Some([5; 64]));
    }

    #[tokio::test]
    async fn import_conflicts_halt_without_advancing_cursor() {
        let mut first = TestDb::create(&active(90102, 0)).await;
        let initial = history(90102, 1, vec![]);
        first.db().import_session(&initial, &[], 1, Hash4::default()).await.expect("offline import");
        first.db().import_session(&initial, &[], 1, Hash4::default()).await.expect("idempotent import");
        assert!(first.db().lookup_signed(90102, 524288, 1).await.expect("no fabricated decision").is_none());
        assert_eq!(first.db().load_sessions(90102, 524288, None, 64).await.expect("history").len(), 1);
        assert!(matches!(first.db().import_session(&history(90102, 3, vec![]), &[], 3, Hash4::default()).await, Err(GuardianSignError::SessionHistoryUnavailable)));
        assert_eq!(first.db().load_account(90102, 524288).await.expect("rollback").imported_nonce, Some(1));
        first.db().import_session(&history(90102, 2, vec![]), &[], 2, Hash4::default()).await.expect("contiguous import");
        let mut wrong_root = history(90102, 3, vec![]);
        wrong_root.starting_leaf_hash = Hash4::try_from(&[1, 0, 0, 0]).expect("hash");
        assert!(matches!(first.db().import_session(&wrong_root, &[], 3, Hash4::default()).await, Err(GuardianSignError::AccountHalted)));
        assert_halted_cursor(first.db(), 90102, 2).await;

        let mut consumed = TestDb::create(&active(90103, 0)).await;
        let consumed_history = history(90103, 1, vec![]);
        let mut own = reserved();
        own.network_magic = 90103;
        own.request_bytes = consumed_history.record.request_json.decode().expect("request").canonical_bytes().expect("bytes");
        consumed.db().reserve_guardian_nonce(&own).await.expect("reserve before other quorum");
        consumed.db().import_session(&consumed_history, &[], 1, Hash4::default()).await.expect("other quorum consumed reservation");
        assert!(consumed.db().lookup_signed(90103, 524288, 1).await.expect("lookup").is_none());
        assert_eq!(consumed.db().load_sessions(90103, 524288, None, 64).await.expect("session N").iter().map(|session| session.nonce).collect::<Vec<_>>(), vec![1]);
        assert!(matches!(consumed.db().reserve_guardian_nonce(&own).await, Err(GuardianSignError::NonceConflict)));
        assert!(matches!(consumed.db().save_guardian_signature(90103, 524288, 1, &own.request_bytes, [3; 64]).await, Err(GuardianSignError::NonceConflict)));
        assert!(consumed.db().lookup_signed(90103, 524288, 1).await.expect("still pruned").is_none());
        let mut different = consumed_history.clone();
        different.record.endcap_proof_hex = "0x01".to_owned();
        match consumed.db().import_session(&different, &[], 1, Hash4::default()).await {
            Err(error) => assert_eq!(error, GuardianSignError::AccountHalted),
            Ok(_) => panic!("unexpected success: different consumed session must halt"),
        }
        assert_halted_cursor(consumed.db(), 90103, 1).await;

        let mut repeated_identity = append(0, 10, 1);
        repeated_identity.chain_index = 1;
        repeated_identity.burn.destination_chain_index = 1;
        // Identity keys omit the chain; nonce keys omit the sender and token contract.
        for (network, conflicting, identity_present, nonce_present) in [
            (90104, append(3, 10, 2), false, false), // append gap, both keys new
            (90105, repeated_identity, true, false), // existing identity, new chain nonce
            (90106, append(1, 11, 1), false, true), // new identity, existing chain nonce
            (90110, append(1, 10, 1), true, true), // both keys already included
        ] {
            let mut owned = TestDb::create(&active(network, 0)).await;
            owned.db().import_session(&history(network, 1, vec![append(0, 10, 1)]), &[], 1, Hash4::default()).await.expect("first append");
            let saved = owned.db().load_account(network, 524288).await.expect("included account");
            let error = owned.db().import_session(&history(network, 2, vec![conflicting.clone()]), &[], 2, Hash4::default()).await
                .expect_err("conflicting append must halt without committing either index");
            assert_eq!(error, GuardianSignError::AccountHalted, "network {network}: append {conflicting:?}");
            assert_halted_cursor(owned.db(), network, 1).await;
            let halted = owned.db().load_account(network, 524288).await.expect("halted account");
            assert_eq!(halted.last_checkpoint_id, saved.last_checkpoint_id, "network {network}: checkpoint must not advance");
            assert_eq!(halted.withdrawal_chains, saved.withdrawal_chains, "network {network}: withdrawal frontier must not advance");
            let burn = append(0, 10, 1).burn;
            assert!(owned.db().contains_included_withdrawal_burn(network, 524288, burn.sender_user_id, burn.token_contract_id, burn.nonce).await.expect("retained identity"));
            assert!(owned.db().contains_withdrawal_nonce(network, 524288, 0, burn.nonce).await.expect("retained nonce"));
            let burn = &conflicting.burn;
            assert_eq!(owned.db().contains_included_withdrawal_burn(network, 524288, burn.sender_user_id, burn.token_contract_id, burn.nonce).await.expect("conflicting identity point"), identity_present,
                "network {network}: only previously included identity keys may remain");
            assert_eq!(owned.db().contains_withdrawal_nonce(network, 524288, conflicting.chain_index, burn.nonce).await.expect("conflicting nonce point"), nonce_present,
                "network {network}: only previously included chain nonce keys may remain");
        }

        let mut advanced = TestDb::create(&active(90107, 0)).await;
        advanced.db().import_session(&history(90107, 1, vec![append(0, 10, 1)]), &[], 1, Hash4::default()).await.expect("initial append");
        advanced.db().import_session(&history(90107, 2, vec![append(1, 10, 2)]), &[], 2, Hash4::default()).await.expect("next append");
        let saved = advanced.db().load_sessions(90107, 524288, Some(1), 1).await.expect("append history");
        assert_eq!(saved[0].withdrawal_appends, vec![append(1, 10, 2)]);
        let account = advanced.db().load_account(90107, 524288).await.expect("active observation");
        assert_eq!(account.withdrawal_chains.len(), 1);
        assert_eq!(account.withdrawal_chains[0].0, 0);
        assert_eq!(account.withdrawal_chains[0].1, 2);
        assert_eq!(account.imported_ending_leaf, Some(Hash4::default()));
        let mut moved = account.clone();
        moved.last_checkpoint_id = 7;
        moved.last_checkpoint_hash = Hash4::try_from(&[7, 0, 0, 0]).expect("checkpoint hash");
        advanced.db().save_account(&moved).await.expect("legal checkpoint advancement");
        let saved = advanced.db().load_account(90107, 524288).await.expect("advanced observation");
        assert_eq!((saved.last_checkpoint_id, saved.last_checkpoint_hash, saved.imported_nonce, saved.state), (7, moved.last_checkpoint_hash, Some(2), GuardianAccountState::Active));

        let mut conflict = TestDb::create(&active(90108, 0)).await;
        let mut conflicting = history(90108, 1, vec![]);
        let mut own = reserved();
        own.network_magic = 90108;
        let mut request = conflicting.record.request_json.decode().expect("original request");
        own.request_bytes = request.canonical_bytes().expect("original bytes");
        conflict.db().reserve_guardian_nonce(&own).await.expect("unconsumed reservation");
        request.trace_json = JsonText::parse(format!(" {} ", request.trace_json.as_str())).expect("distinct exact request");
        conflicting.record.request_json = JsonText::from_value(&request).expect("conflicting request JSON");
        assert!(matches!(conflict.db().import_session(&conflicting, &[], 1, Hash4::default()).await, Err(GuardianSignError::AccountHalted)));
        let saved = conflict.db().load_account(90108, 524288).await.expect("conflict observation");
        assert_eq!(saved.state, GuardianAccountState::Halted);
        assert_eq!(saved.halt_reason, Some(HaltReason::NonceConsumedDifferently));
        assert_eq!(saved.imported_nonce, None);
        assert!(conflict.db().load_sessions(90108, 524288, None, 1).await.expect("no import").is_empty());
        assert!(conflict.db().load_deposit_tree_states(90108, 524288).await.expect("no deposit tree states").is_empty());
        let retained = conflict.db().lookup_signed(90108, 524288, 1).await.expect("retained decision").expect("reservation");
        assert!(same_reservation(&own, &retained));
        assert!(retained.signature.is_none());
    }

    #[tokio::test]
    async fn deposit_tree_state_extension_and_index_conflict_survive_reopen() {
        let mut owned = TestDb::create(&active(90109, 0)).await;
        let first = history(90109, 1, vec![append(0, 10, 1)]);
        let mut deposit_tree_state = DepositTreeState::empty(0);
        deposit_tree_state.root = super::super::protocol::append_merkle_leaf(&mut deposit_tree_state.frontier, 0, Hash4::default());
        deposit_tree_state.count = 1;
        deposit_tree_state.occupied_partial_page_hashes = vec![Hash4::default()];
        let mut anchor = super::super::protocol::DepositAnchor { chain_index: 0, block_number: 4, block_hash: super::super::protocol::Hex([9; 32]), old_count: 0, new_count: 1 };
        let mut changed = deposit_tree_state.clone();
        changed.anchor = anchor.clone(); changed.previous_count = 0; changed.previous_root = DepositTreeState::empty(0).root;
        let mut request = first.record.request_json.decode().expect("request");
        request.operation = super::super::protocol::GuardianOperation::Bridge;
        request.deposit_anchors = vec![anchor.clone()];
        request.withdrawal_records = vec![append(0, 10, 1).burn];
        let mut signed = reserved();
        signed.network_magic = 90109;
        signed.request_bytes = request.canonical_bytes().expect("bytes");
        signed.deposit_tree_states = vec![changed.clone()];
        owned.db().reserve_guardian_nonce(&signed).await.expect("reserve deposit tree state");
        let mut drifted = signed.clone();
        // The baseline leaf is zero: assigning zero again would be an identical retry.
        let leaf = Hash4::try_from(&[1, 0, 0, 0]).expect("different canonical leaf");
        drifted.deposit_tree_states[0].root = super::super::protocol::append_merkle_leaf(&mut drifted.deposit_tree_states[0].frontier, 0, leaf);
        drifted.deposit_tree_states[0].occupied_partial_page_hashes[0] = leaf;
        drifted.validate().expect("drifted deposit tree state must be valid, not malformed");
        assert_eq!(drifted.nonce, signed.nonce, "retry must target the reserved nonce");
        assert_eq!(drifted.request_bytes, signed.request_bytes, "only the deposit tree state may differ");
        assert_ne!(drifted.deposit_tree_states, signed.deposit_tree_states, "fixture must change the deposit tree state");
        assert!(!same_reservation(&signed, &drifted), "reservation comparison must include the complete deposit tree state vector");
        let error = match owned.db().reserve_guardian_nonce(&drifted).await {
            Err(error) => error,
            Ok(_) => panic!("different valid deposit tree state at the reserved nonce must conflict"),
        };
        assert_eq!(error, GuardianSignError::NonceConflict, "valid deposit tree state drift must not be accepted or treated as malformed");
        let retained = owned.db().reserve_guardian_nonce(&signed).await.expect("original deposit tree state remains retryable");
        assert!(same_reservation(&retained, &signed), "conflict must not replace the original reservation");
        let mut session = first.clone();
        session.record.request_json = JsonText::from_value(&request).expect("request json");
        owned.db().import_session(&session, &[changed.clone()], 1, Hash4::default()).await.expect("first deposit tree state");
        let saved = owned.db().load_deposit_tree_states(90109, 524288).await.expect("deposit tree state");
        assert_eq!(saved, vec![changed.clone()]);
        anchor.old_count = 1; anchor.new_count = 2; anchor.block_number = 5;
        let mut next_deposit_tree_state = changed.clone();
        next_deposit_tree_state.count = 2; next_deposit_tree_state.previous_count = 1; next_deposit_tree_state.previous_root = changed.root; next_deposit_tree_state.anchor = anchor.clone(); next_deposit_tree_state.occupied_partial_page_hashes.push(Hash4::default());
        next_deposit_tree_state.root = super::super::protocol::append_merkle_leaf(&mut next_deposit_tree_state.frontier, 1, Hash4::default());
        let mut next = history(90109, 2, vec![append(1, 11, 2)]);
        let mut next_request = next.record.request_json.decode().expect("next request");
        next_request.operation = super::super::protocol::GuardianOperation::Bridge;
        next_request.deposit_anchors = vec![anchor];
        next_request.withdrawal_records = vec![append(1, 11, 2).burn];
        next.record.request_json = JsonText::from_value(&next_request).expect("next request json");
        let broken = DepositTreeState { previous_root: Hash4::default(), ..next_deposit_tree_state.clone() };
        broken.validate().expect("broken extension must still be a structurally valid deposit tree state");
        let error = owned.db().import_session(&next, &[broken], 2, Hash4::default()).await.expect_err("wrong previous root must halt deposit tree state extension");
        assert_eq!(error, GuardianSignError::AccountHalted, "valid deposit tree state with conflicting history must halt");
        assert_halted_cursor(owned.db(), 90109, 1).await;

        assert_eq!(owned.db().load_deposit_tree_states(90109, 524288).await.expect("unchanged deposit tree state"), vec![changed]);
        let file = owned.reopen();
        let mut restored = GuardianDb::open(file, KEY, Arc::new(super::super::protocol::codec_config_fixture(90109))).await.expect("reopen");
        assert_eq!(restored.load_account(90109, 524288).await.expect("halted").state, GuardianAccountState::Halted);
        assert_halted_cursor(&mut restored, 90109, 1).await;
        assert_eq!(restored.load_deposit_tree_states(90109, 524288).await.expect("retained deposit tree state after reopen"), signed.deposit_tree_states);
        assert!(restored.contains_included_withdrawal_burn(90109, 524288, 10, 4, append(0, 10, 1).burn.nonce).await.expect("retained identity"));
        assert!(!restored.contains_included_withdrawal_burn(90109, 524288, 11, 4, append(1, 11, 2).burn.nonce).await.expect("uncommitted identity absent"));
        assert!(!restored.contains_withdrawal_nonce(90109, 524288, 0, append(1, 11, 2).burn.nonce).await.expect("uncommitted nonce absent"));
        assert!(restored.contains_withdrawal_nonce(90109, 524288, 0, append(0, 10, 1).burn.nonce).await.expect("retained nonce"));
    }


    #[tokio::test]
    async fn open_rejects_empty_missing_and_multiple_accounts_without_inserting() {
        let path = std::env::temp_dir().join(format!("guardian-empty-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        let file = OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&path).expect("empty");
        assert!(matches!(GuardianDb::open(file, KEY, approval()).await, Err(GuardianSignError::DatabaseUnavailable)));
        assert_eq!(std::fs::metadata(&path).expect("metadata").len(), 0);
        let _ = std::fs::remove_file(&path);

        for accounts in [0usize, 2] {
            let path = std::env::temp_dir().join(format!("guardian-accounts-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            let file = OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&path).expect("raw");
            let db = open_database(file).unwrap();
            let tx = db.begin_write().expect("raw write");
            {
                tx.open_table(GUARDIAN_SCHEMA).unwrap().insert((), SCHEMA_VERSION).unwrap();
                let mut signer = tx.open_table(GUARDIAN_SIGNER).expect("signer");
                signer.insert((), &KEY).expect("key");
                let mut table = tx.open_table(GUARDIAN_ACCOUNT).expect("accounts");
                for index in 0..accounts {
                    let account = active(90101 + index as u64, 0);
                    let bytes = encode(&account).expect("account");
                    table.insert((account.network_magic, account.user_id), bytes.as_slice()).expect("account row");
                }
                let _signed = tx.open_table(GUARDIAN_SIGNED).expect("signed");
                let _sessions = tx.open_table(GUARDIAN_SESSION).expect("sessions");
                let _deposit_tree_states = tx.open_table(DEPOSIT_TREE_STATES).expect("deposit tree states");
                let _included_withdrawal_burns = tx.open_table(INCLUDED_WITHDRAWAL_BURNS).expect("identities");
                let _nonces = tx.open_table(WITHDRAWAL_NONCE).expect("nonces");

            }
            tx.commit().expect("raw commit");
            drop(db);
            let reopened = OpenOptions::new().read(true).write(true).open(&path).expect("reopen raw");
            assert!(matches!(GuardianDb::open(reopened, KEY, approval()).await, Err(GuardianSignError::DatabaseUnavailable)));
            let db = Database::builder().create_file(OpenOptions::new().read(true).write(true).open(&path).expect("inspect")).expect("inspect");
            let tx = db.begin_read().expect("inspect read");
            let table = tx.open_table(GUARDIAN_ACCOUNT).expect("inspect accounts");
            assert_eq!(table.range::<(u64, u64)>(..).expect("range").count(), accounts);
            drop(table);
            drop(tx);
            drop(db);
            let _ = std::fs::remove_file(&path);
        }
    }

    #[tokio::test]
    async fn legacy_or_unknown_schema_is_rejected_without_rewriting_journal() {
        for version in [None, Some(RAW_SCHEMA_VERSION), Some(1), Some(4)] {
            let mut owned = TestDb::create(&active(90101, 0)).await;
            let tx = owned.db().db.begin_write().unwrap();
            match version {
                None => { tx.delete_table(GUARDIAN_SCHEMA).unwrap(); }
                Some(version) => { tx.open_table(GUARDIAN_SCHEMA).unwrap().insert((), version).unwrap(); }
            }
            tx.commit().unwrap();
            let file = owned.reopen();
            let before = std::fs::read(&owned.path).unwrap();
            let error = match GuardianDb::open(file, KEY, approval()).await {
                Err(error) => error,
                Ok(_) => panic!("legacy journal must require explicit migration"),
            };
            assert_eq!(error, GuardianSignError::LegacyJournalSchema);
            assert!(error.to_string().contains("explicit operator-controlled migration is required"));
            assert_eq!(std::fs::read(&owned.path).unwrap(), before);
        }
    }

    /// Old two-row decode and the exact page produce the same record bytes, cursor, and has_more.
    #[tokio::test]
    async fn exact_session_page_matches_old_response_bytes() {
        let network = 90101;
        let user = 524288u64;
        let mut owned = TestDb::create(&active(network, 0)).await;
        let config = Arc::clone(&owned.db().config);
        for nonce in [1u64, 2, 3] {
            owned.db().import_session(&history(network, nonce, vec![]), &[], nonce, Hash4::default()).await.expect("import");
        }
        let reader = owned.db().session_reader();
        for (after, limit) in [(0u64, 1u32), (0, 64), (1, 2), (3, 1), (u32::MAX as u64, 1), (u64::MAX, 1)] {
            let old = {
                let tx = owned.db().db.begin_read().unwrap();
                let sessions = tx.open_table(GUARDIAN_SESSION).unwrap();
                let mut decoded = Vec::new();
                for entry in sessions.range(nonce_bounds(network, user, after)).unwrap() {
                    if decoded.len() == 2 { break; }
                    let (key, value) = entry.unwrap();
                    let copied = value.value().to_vec();
                    let session = decode_session(key.value(), &copied).unwrap();
                    session.record.request_json.decode().unwrap().validate_authorization(&config).unwrap();
                    decoded.push(session);
                }
                let has_more = decoded.len() > 1;
                decoded.truncate(1.min(limit as usize));
                let next_after_nonce = decoded.last().map(|session| session.nonce).unwrap_or(after);
                super::super::protocol::GuardianSessionsResponse {
                    sessions: decoded.into_iter().map(|session| session.record).collect(), next_after_nonce, has_more,
                }.to_bytes().unwrap()
            };
            let (row, has_more) = reader.load_session_page(network, user, after).await.expect("page");
            let next_after_nonce = row.as_ref().map(|(nonce, _)| *nonce).unwrap_or(after);
            let page = super::super::protocol::GuardianSessionsResponse {
                sessions: row.into_iter().map(|(_, record)| record).take(usize::from(limit > 0)).collect(), next_after_nonce, has_more,
            };
            assert_eq!(page.to_bytes().unwrap(), old, "after={after} limit={limit}");
        }
        let (foreign, more) = reader.load_session_page(network + 1, user, 0).await.unwrap();
        assert!(foreign.is_none() && !more);
        drop(reader); let file = owned.reopen();
        let reopened = GuardianDb::open(file, KEY, Arc::new(super::super::protocol::codec_config_fixture(network))).await.expect("authorized rows reopen");
        let (row, has_more) = reopened.session_reader().load_session_page(network, user, 0).await.unwrap();
        assert!(row.is_some() && !has_more);
    }

    #[tokio::test]
    async fn open_rejects_unauthorized_and_noncanonical_sessions_without_rewriting() {
        let network = 90101;
        for unauthorized in [true, false] {
            let mut session = history(network, 1, vec![]);
            let mut owned = TestDb::create(&active(network, 0)).await;
            if unauthorized {
                let mut request = session.record.request_json.decode().unwrap();
                let mut trace = request.decode_trace().unwrap();
                trace.meta.public_key = Hash4::from_values(99, 0, 0, 0);
                let mut generated = request.trace_json.decode().unwrap();
                generated.pk_hash = trace.meta.public_key.to_string();
                generated.trace.payload = serde_json::to_string(&trace).unwrap();
                request.trace_json = JsonText::from_value(&generated).unwrap();
                session.record.request_json = JsonText::from_value(&request).unwrap();
            }
            {
                let tx = owned.db().db.begin_write().unwrap();
                if unauthorized {
                    insert_session(&tx, &session).unwrap();
                } else {
                    let mut sessions = tx.open_table(GUARDIAN_SESSION).unwrap();
                    let mut bytes = encode_record(&encode(&session).unwrap(), MAX_SESSION_RECORD_BYTES).unwrap();
                    bytes.push(1);
                    sessions.insert((session.network_magic, session.user_id, session.nonce), bytes.as_slice()).unwrap();
                }
                tx.commit().unwrap();
            }
            let rows = |file: File| {
                let db = Database::builder().create_file(file).unwrap();
                let tx = db.begin_read().unwrap();
                let mut rows = Vec::new();
                let accounts = tx.open_table(GUARDIAN_ACCOUNT).unwrap();
                for row in accounts.iter().unwrap() { let (key, value) = row.unwrap(); rows.push((format!("{:?}", key.value()), value.value().to_vec())); }
                let signed = tx.open_table(GUARDIAN_SIGNED).unwrap();
                for row in signed.iter().unwrap() { let (key, value) = row.unwrap(); rows.push((format!("{:?}", key.value()), value.value().to_vec())); }
                let sessions = tx.open_table(GUARDIAN_SESSION).unwrap();
                for row in sessions.iter().unwrap() { let (key, value) = row.unwrap(); rows.push((format!("{:?}", key.value()), value.value().to_vec())); }
                let deposits = tx.open_table(DEPOSIT_TREE_STATES).unwrap();
                for row in deposits.iter().unwrap() { let (key, value) = row.unwrap(); rows.push((format!("{:?}", key.value()), value.value().to_vec())); }
                let burns = tx.open_table(INCLUDED_WITHDRAWAL_BURNS).unwrap();
                for row in burns.iter().unwrap() { let (key, value) = row.unwrap(); rows.push((format!("{:?}", key.value()), value.value().to_le_bytes().to_vec())); }
                let nonces = tx.open_table(WITHDRAWAL_NONCE).unwrap();
                for row in nonces.iter().unwrap() { let (key, value) = row.unwrap(); rows.push((format!("{:?}", key.value()), value.value().to_le_bytes().to_vec())); }
                rows
            };
            let before = rows(owned.reopen());
            let error = GuardianDb::open(owned.reopen(), KEY, approval()).await.err().expect("open must reject the stored session");
            let expected = if unauthorized { GuardianSignError::AccountIdentityConflict } else { GuardianSignError::LegacyJournalSchema };
            assert_eq!(error, expected);
            let after = rows(OpenOptions::new().read(true).write(true).open(&owned.path).unwrap());
            assert_eq!(before.len(), after.len());
            assert_eq!(before.iter().map(|(key, value)| (key.clone(), value.len(), super::super::protocol::sha256(value))).collect::<Vec<_>>(), after.iter().map(|(key, value)| (key.clone(), value.len(), super::super::protocol::sha256(value))).collect::<Vec<_>>());
        }
    }
    #[tokio::test]
    async fn successful_import_prunes_only_older_signed_and_session_rows() {
        let network = 90111u64;
        let user = 524288u64;
        let mut owned = TestDb::create(&active(network, 0)).await;
        let burn = append(0, 10, 1);
        let first = history(network, 1, vec![burn.clone()]);
        let mut deposit = DepositTreeState::empty(0);
        deposit.root = super::super::protocol::append_merkle_leaf(&mut deposit.frontier, 0, Hash4::default());
        deposit.count = 1;
        deposit.occupied_partial_page_hashes = vec![Hash4::default()];
        let anchor = super::super::protocol::DepositAnchor { chain_index: 0, block_number: 4, block_hash: super::super::protocol::Hex([9; 32]), old_count: 0, new_count: 1 };
        let mut changed = deposit.clone();
        changed.anchor = anchor.clone();
        changed.previous_count = 0;
        changed.previous_root = DepositTreeState::empty(0).root;
        let mut request = first.record.request_json.decode().expect("request");
        request.operation = GuardianOperation::Bridge;
        request.deposit_anchors = vec![anchor];
        request.withdrawal_records = vec![burn.burn.clone()];
        let mut signed_one = reserved();
        signed_one.network_magic = network;
        signed_one.nonce = 1;
        signed_one.request_bytes = request.canonical_bytes().expect("bytes");
        signed_one.deposit_tree_states = vec![changed.clone()];
        owned.db().reserve_guardian_nonce(&signed_one).await.expect("reserve nonce 1");
        owned.db().save_guardian_signature(network, user, 1, &signed_one.request_bytes, [5; 64]).await.expect("sign nonce 1");
        let mut session_one = first;
        session_one.record.request_json = JsonText::from_value(&request).expect("request json");
        owned.db().import_session(&session_one, &[changed.clone()], 1, Hash4::default()).await.expect("import nonce 1");
        assert!(owned.db().contains_included_withdrawal_burn(network, user, burn.burn.sender_user_id, burn.burn.token_contract_id, burn.burn.nonce).await.expect("identity"));
        assert!(owned.db().contains_withdrawal_nonce(network, user, 0, burn.burn.nonce).await.expect("nonce index"));

        let second = history(network, 2, vec![]);
        let fourth = history(network, 4, vec![]);
        let mut pending = reserved();
        pending.network_magic = network;
        pending.nonce = 4;
        pending.request_bytes = fourth.record.request_json.decode().expect("session 4 request").canonical_bytes().expect("pending bytes");
        let mut signed_two = reserved();
        signed_two.network_magic = network;
        signed_two.nonce = 2;
        signed_two.request_bytes = second.record.request_json.decode().expect("session 2 request").canonical_bytes().expect("signed N bytes");
        {
            let tx = owned.db().db.begin_write().expect("pending write");
            insert_signed(&tx, &signed_two).expect("signed N row");
            insert_signed(&tx, &pending).expect("pending N+1 row");
            tx.commit().expect("pending commit");
        }
        owned.db().import_session(&second, &[], 2, Hash4::default()).await.expect("import nonce 2");
        assert!(owned.db().lookup_signed(network, user, 1).await.expect("pruned signed").is_none());
        assert!(owned.db().lookup_signed(network, user, 2).await.expect("signed N pruned").is_none());
        assert!(owned.db().load_sessions(network, user, None, 64).await.expect("sessions").iter().all(|session| session.nonce >= 2));
        assert_eq!(owned.db().load_sessions(network, user, None, 64).await.expect("retained session").len(), 1);
        let retained = owned.db().lookup_signed(network, user, 4).await.expect("pending lookup").expect("pending N+1");
        assert!(retained.signature.is_none());
        assert_eq!(retained.request_bytes, pending.request_bytes);
        assert_eq!(owned.db().load_deposit_tree_states(network, user).await.expect("deposits"), vec![changed.clone()]);
        assert!(owned.db().contains_included_withdrawal_burn(network, user, burn.burn.sender_user_id, burn.burn.token_contract_id, burn.burn.nonce).await.expect("identity kept"));
        assert!(owned.db().contains_withdrawal_nonce(network, user, 0, burn.burn.nonce).await.expect("nonce index kept"));
        let account = owned.db().load_account(network, user).await.expect("account");
        assert_eq!(account.imported_nonce, Some(2));
        assert_eq!(account.state, GuardianAccountState::Active);

        let third = history(network, 3, vec![]);
        let mut signed_four = reserved();
        signed_four.network_magic = network;
        signed_four.nonce = 4;
        signed_four.request_bytes = pending.request_bytes.clone();
        {
            let tx = owned.db().db.begin_write().expect("future signed");
            insert_signed(&tx, &signed_four).expect("signed N+1 before import N");
            tx.commit().expect("future signed commit");
        }
        owned.db().import_session(&third, &[], 3, Hash4::default()).await.expect("import nonce 3");
        let sessions = owned.db().load_sessions(network, user, None, 64).await.expect("after nonce 3");
        assert_eq!(sessions.iter().map(|session| session.nonce).collect::<Vec<_>>(), vec![3]);
        assert!(owned.db().lookup_signed(network, user, 2).await.expect("pruned signed two").is_none());
        assert!(owned.db().lookup_signed(network, user, 3).await.expect("no fabricated signed").is_none());
        let kept = owned.db().lookup_signed(network, user, 4).await.expect("pending after 3").expect("pending retained");
        assert_eq!(kept.request_bytes, pending.request_bytes);
        assert_eq!(owned.db().load_account(network, user).await.expect("cursor").imported_nonce, Some(3));
        assert_eq!(owned.db().load_deposit_tree_states(network, user).await.expect("deposits after 3"), vec![changed.clone()]);
        assert!(owned.db().contains_included_withdrawal_burn(network, user, burn.burn.sender_user_id, burn.burn.token_contract_id, burn.burn.nonce).await.expect("identity after 3"));
        assert!(owned.db().contains_withdrawal_nonce(network, user, 0, burn.burn.nonce).await.expect("nonce index after 3"));
        assert_eq!(owned.db().load_account(network, user).await.expect("still active").state, GuardianAccountState::Active);
        assert_eq!(owned.db().import_session(&session_one, &[changed.clone()], 1, Hash4::default()).await.expect_err("old exact"), GuardianSignError::NonceConflict);
        let mut modified = session_one.clone();
        modified.record.endcap_proof_hex = "0x02".to_owned();
        assert_eq!(owned.db().import_session(&modified, &[changed.clone()], 1, Hash4::default()).await.expect_err("old conflict"), GuardianSignError::NonceConflict);
        let unchanged = owned.db().load_account(network, user).await.expect("cursor unchanged");
        assert_eq!((unchanged.state, unchanged.imported_nonce), (GuardianAccountState::Active, Some(3)));
        assert_eq!(owned.db().load_sessions(network, user, None, 64).await.expect("latest remains").iter().map(|session| session.nonce).collect::<Vec<_>>(), vec![3]);
        assert_eq!(owned.db().load_deposit_tree_states(network, user).await.expect("deposits unchanged"), vec![changed.clone()]);
        assert!(owned.db().contains_included_withdrawal_burn(network, user, burn.burn.sender_user_id, burn.burn.token_contract_id, burn.burn.nonce).await.expect("identity unchanged"));
        assert!(owned.db().contains_withdrawal_nonce(network, user, 0, burn.burn.nonce).await.expect("nonce index unchanged"));
        owned.db().import_session(&third, &[], 3, Hash4::default()).await.expect("exact latest retry");
        let mut different = third.clone();
        different.record.endcap_proof_hex = "0x01".to_owned();
        assert_eq!(owned.db().import_session(&different, &[], 3, Hash4::default()).await.expect_err("latest conflict"), GuardianSignError::AccountHalted);
        assert_eq!(owned.db().load_account(network, user).await.expect("halted latest").imported_nonce, Some(3));
        assert_eq!(owned.db().load_sessions(network, user, None, 64).await.expect("latest row").len(), 1);

        let file = owned.reopen();
        let mut restored = GuardianDb::open(file, KEY, Arc::new(super::super::protocol::codec_config_fixture(network))).await.expect("reopen pruned");
        assert_eq!(restored.load_account(network, user).await.expect("restored").imported_nonce, Some(3));
        assert_eq!(restored.load_sessions(network, user, None, 64).await.expect("restored sessions").iter().map(|session| session.nonce).collect::<Vec<_>>(), vec![3]);
        assert!(restored.lookup_signed(network, user, 4).await.expect("pending retained").is_some());
        assert!(restored.lookup_signed(network, user, 3).await.expect("no fabricated").is_none());
        assert!(restored.contains_included_withdrawal_burn(network, user, burn.burn.sender_user_id, burn.burn.token_contract_id, burn.burn.nonce).await.expect("restored identity"));
        assert!(restored.contains_withdrawal_nonce(network, user, 0, burn.burn.nonce).await.expect("restored nonce index"));
    }

    fn raw_rows(db: &GuardianDb) -> Vec<(String, Vec<u8>)> {
        let tx = db.db.begin_read().unwrap();
        let mut rows = Vec::new();
        for row in tx.open_table(GUARDIAN_ACCOUNT).unwrap().iter().unwrap() {
            let (key, value) = row.unwrap();
            rows.push((format!("account:{:?}", key.value()), value.value().to_vec()));
        }
        for row in tx.open_table(GUARDIAN_SIGNED).unwrap().iter().unwrap() {
            let (key, value) = row.unwrap();
            rows.push((format!("signed:{:?}", key.value()), value.value().to_vec()));
        }
        for row in tx.open_table(GUARDIAN_SESSION).unwrap().iter().unwrap() {
            let (key, value) = row.unwrap();
            rows.push((format!("session:{:?}", key.value()), value.value().to_vec()));
        }
        for row in tx.open_table(DEPOSIT_TREE_STATES).unwrap().iter().unwrap() {
            let (key, value) = row.unwrap();
            rows.push((format!("deposit:{:?}", key.value()), value.value().to_vec()));
        }
        for row in tx.open_table(INCLUDED_WITHDRAWAL_BURNS).unwrap().iter().unwrap() {
            let (key, value) = row.unwrap();
            rows.push((format!("burn:{:?}", key.value()), value.value().to_le_bytes().to_vec()));
        }
        for row in tx.open_table(WITHDRAWAL_NONCE).unwrap().iter().unwrap() {
            let (key, value) = row.unwrap();
            rows.push((format!("nonce:{:?}", key.value()), value.value().to_le_bytes().to_vec()));
        }
        rows.push(("schema".to_owned(), tx.open_table(GUARDIAN_SCHEMA).unwrap().get(()).unwrap().unwrap().value().to_le_bytes().to_vec()));
        rows
    }

    #[tokio::test]
    async fn migration_keeps_pending_bytes_and_aborts_without_rewriting() {
        let network = 90112u64;
        let user = 524288u64;
        let mut owned = TestDb::create(&active(network, 0)).await;
        let config = Arc::new(super::super::protocol::codec_config_fixture(network));
        let current = history(network, 2, vec![]);
        let future = history(network, 4, vec![]);
        current.validate(&config).expect("full structural session validation");
        future.validate(&config).expect("full structural session validation");
        let mut pending = reserved();
        pending.network_magic = network;
        pending.nonce = 4;
        pending.request_bytes = future.record.request_json.decode().unwrap().canonical_bytes().unwrap();
        owned.db().import_session(&history(network, 1, vec![]), &[], 1, Hash4::default()).await.unwrap();
        owned.db().import_session(&current, &[], 2, Hash4::default()).await.unwrap();
        {
            let tx = owned.db().db.begin_write().unwrap();
            insert_signed(&tx, &pending).unwrap();
            tx.commit().unwrap();
        }
        let pending_id = super::super::protocol::GuardianSignRequest::from_canonical_bytes(&pending.request_bytes).unwrap().request_id().unwrap();
        let session_id = current.record.request_json.decode().unwrap().request_id().unwrap();
        let account_before = raw_rows(owned.db()).into_iter().find(|(key, _)| key.starts_with("account:")).unwrap().1;
        {
            let tx = owned.db().db.begin_write().unwrap();
            tx.open_table(GUARDIAN_SCHEMA).unwrap().insert((), RAW_SCHEMA_VERSION).unwrap();
            {
                let mut signed = tx.open_table(GUARDIAN_SIGNED).unwrap();
                for (key, bytes) in signed.iter().unwrap().map(|row| { let (key, value) = row.unwrap(); (key.value(), decode_record(value.value(), MAX_BODY_BYTES).unwrap()) }).collect::<Vec<_>>() {
                    signed.insert(key, bytes.as_slice()).unwrap();
                }
            }
            {
                let mut sessions = tx.open_table(GUARDIAN_SESSION).unwrap();
                for (key, bytes) in sessions.iter().unwrap().map(|row| { let (key, value) = row.unwrap(); (key.value(), decode_record(value.value(), MAX_SESSION_RECORD_BYTES).unwrap()) }).collect::<Vec<_>>() {
                    sessions.insert(key, bytes.as_slice()).unwrap();
                }
            }
            tx.commit().unwrap();
        }
        assert!(matches!(GuardianDb::open(owned.reopen(), KEY, Arc::clone(&config)).await, Err(GuardianSignError::LegacyJournalSchema)));
        let db = Database::builder().create_file(OpenOptions::new().read(true).write(true).open(&owned.path).unwrap()).unwrap();
        let snapshot = |database: &Database| {
            let tx = database.begin_read().unwrap();
            let mut rows = Vec::new();
            for row in tx.open_table(GUARDIAN_ACCOUNT).unwrap().iter().unwrap() { let (key, value) = row.unwrap(); rows.push((format!("account:{:?}", key.value()), value.value().to_vec())); }
            for row in tx.open_table(GUARDIAN_SIGNED).unwrap().iter().unwrap() { let (key, value) = row.unwrap(); rows.push((format!("signed:{:?}", key.value()), value.value().to_vec())); }
            for row in tx.open_table(GUARDIAN_SESSION).unwrap().iter().unwrap() { let (key, value) = row.unwrap(); rows.push((format!("session:{:?}", key.value()), value.value().to_vec())); }
            rows
        };
        let raw = snapshot(&db);
        assert!(matches!(migrate_guardian_journal(&db, [9; 33], &config), Err(GuardianSignError::AccountIdentityConflict)));
        assert_eq!(snapshot(&db), raw);
        {
            let tx = db.begin_write().unwrap();
            tx.open_table(GUARDIAN_SCHEMA).unwrap().insert((), SCHEMA_VERSION).unwrap();
            drop(tx);
        }
        assert_eq!(db.begin_read().unwrap().open_table(GUARDIAN_SCHEMA).unwrap().get(()).unwrap().unwrap().value(), RAW_SCHEMA_VERSION);
        let migrated = migrate_guardian_journal(&db, KEY, &config).unwrap();
        assert!(migrated.rewritten && migrated.signed == 1 && migrated.sessions == 1);
        let again = migrate_guardian_journal(&db, KEY, &config).unwrap();
        assert_eq!(again, GuardianJournalMigration { signed: 1, sessions: 1, rewritten: false });
        let stored = snapshot(&db);
        for (key, bytes) in &raw {
            let saved = stored.iter().find(|(name, _)| name == key).unwrap().1.as_slice();
            if key.starts_with("account:") { assert_eq!(saved, bytes.as_slice()); assert_eq!(saved, account_before.as_slice()); }
            if key.starts_with("signed:") { assert_eq!(decode_record(saved, MAX_BODY_BYTES).unwrap(), *bytes); }
            if key.starts_with("session:") { assert_eq!(decode_record(saved, MAX_SESSION_RECORD_BYTES).unwrap(), *bytes); }
        }
        drop(db);
        let mut restored = GuardianDb::open(OpenOptions::new().read(true).write(true).open(&owned.path).unwrap(), KEY, config).await.unwrap();
        let kept = restored.lookup_signed(network, user, 4).await.unwrap().unwrap();
        assert_eq!(kept.request_bytes, pending.request_bytes);
        assert_eq!(super::super::protocol::GuardianSignRequest::from_canonical_bytes(&kept.request_bytes).unwrap().request_id().unwrap(), pending_id);
        let sessions = restored.load_sessions(network, user, None, 64).await.unwrap();
        assert_eq!(sessions.iter().map(|session| session.nonce).collect::<Vec<_>>(), vec![2]);
        assert_eq!(sessions[0].record.request_json.decode().unwrap().request_id().unwrap(), session_id);
        assert!(restored.lookup_signed(network, user, 1).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn migration_rejects_outer_session_mismatch_without_rewriting() {
        let network = 90113u64;
        let mut owned = TestDb::create(&active(network, 0)).await;
        let config = Arc::new(super::super::protocol::codec_config_fixture(network));
        let mut session = history(network, 1, vec![]);
        owned.db().import_session(&session, &[], 1, Hash4::default()).await.unwrap();
        let mut request = session.record.request_json.decode().unwrap();
        request.session_nonce = 2;
        session.record.request_json = JsonText::from_value(&request).unwrap();
        session.nonce = 1;
        {
            let tx = owned.db().db.begin_write().unwrap();
            tx.open_table(GUARDIAN_SCHEMA).unwrap().insert((), RAW_SCHEMA_VERSION).unwrap();
            {
                let mut sessions = tx.open_table(GUARDIAN_SESSION).unwrap();
                sessions.insert((network, 524288, 1), encode(&session).unwrap().as_slice()).unwrap();
            }
            tx.commit().unwrap();
        }
        let db = Database::builder().create_file(owned.reopen()).unwrap();
        let before = {
            let tx = db.begin_read().unwrap();
            let mut rows = Vec::new();
            for row in tx.open_table(GUARDIAN_ACCOUNT).unwrap().iter().unwrap() { let (key, value) = row.unwrap(); rows.push((format!("account:{:?}", key.value()), super::super::protocol::sha256(value.value()))); }
            for row in tx.open_table(GUARDIAN_SIGNED).unwrap().iter().unwrap() { let (key, value) = row.unwrap(); rows.push((format!("signed:{:?}", key.value()), super::super::protocol::sha256(value.value()))); }
            for row in tx.open_table(GUARDIAN_SESSION).unwrap().iter().unwrap() { let (key, value) = row.unwrap(); rows.push((format!("session:{:?}", key.value()), super::super::protocol::sha256(value.value()))); }
            rows.push(("schema".to_owned(), super::super::protocol::sha256(&tx.open_table(GUARDIAN_SCHEMA).unwrap().get(()).unwrap().unwrap().value().to_le_bytes())));
            rows
        };
        assert_eq!(migrate_guardian_journal(&db, KEY, &config).unwrap_err(), GuardianSignError::LegacyJournalSchema);
        let after = {
            let tx = db.begin_read().unwrap();
            let mut rows = Vec::new();
            for row in tx.open_table(GUARDIAN_ACCOUNT).unwrap().iter().unwrap() { let (key, value) = row.unwrap(); rows.push((format!("account:{:?}", key.value()), super::super::protocol::sha256(value.value()))); }
            for row in tx.open_table(GUARDIAN_SIGNED).unwrap().iter().unwrap() { let (key, value) = row.unwrap(); rows.push((format!("signed:{:?}", key.value()), super::super::protocol::sha256(value.value()))); }
            for row in tx.open_table(GUARDIAN_SESSION).unwrap().iter().unwrap() { let (key, value) = row.unwrap(); rows.push((format!("session:{:?}", key.value()), super::super::protocol::sha256(value.value()))); }
            rows.push(("schema".to_owned(), super::super::protocol::sha256(&tx.open_table(GUARDIAN_SCHEMA).unwrap().get(()).unwrap().unwrap().value().to_le_bytes())));
            rows
        };
        assert_eq!(after, before);
        drop(db);
        assert!(matches!(GuardianDb::open(OpenOptions::new().read(true).write(true).open(&owned.path).unwrap(), KEY, config).await, Err(GuardianSignError::LegacyJournalSchema)));
    }



}
