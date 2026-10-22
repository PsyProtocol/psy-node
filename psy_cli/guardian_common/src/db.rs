//! One redb file belongs to exactly one guardian signing key.
//! The caller supplies the exclusive file descriptor; dropping this value releases it.
//! Schema 2 stores runtime identity only. Legacy journals require explicit operator-controlled migration.

use std::collections::BTreeSet;
use std::fs::File;
use std::ops::Bound;
use std::sync::Arc;

use bincode::Options;
use redb::{Database, Key, ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle, TypeName, Value};
use serde::de::DeserializeOwned;
use serde::Serialize;


use super::protocol::{advance_included_account, DepositTreeState, GuardianAccount, GuardianAccountState, GuardianConfig, GuardianSession, GuardianSignError, GuardianSigned, HaltReason};

type Result<T, E = GuardianSignError> = std::result::Result<T, E>;

const GUARDIAN_SIGNER: TableDefinition<(), [u8; 33]> = TableDefinition::new("guardian_signer");
const GUARDIAN_SCHEMA: TableDefinition<(), u32> = TableDefinition::new("guardian_schema");
const SCHEMA_VERSION: u32 = 2;
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
    let value: GuardianSigned = canonical_bytes(bytes)?;
    if (value.network_magic, value.user_id, value.nonce) != key { return Err(GuardianSignError::DatabaseUnavailable); }
    value.validate()?;
    Ok(value)
}

fn decode_session(key: (u64, u64, u64), bytes: &[u8]) -> Result<GuardianSession> {
    let value: GuardianSession = canonical_bytes(bytes)?;
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

pub struct GuardianDb { db: Database, public_key: [u8; 33], config: Arc<GuardianConfig> }

impl GuardianDb {
    /// Creates an uninitialized database from an exclusively created protected empty file.
    pub async fn create(file: File, public_key: [u8; 33], config: Arc<GuardianConfig>) -> Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata().map_err(unavailable)?;
        if metadata.len() != 0 || !metadata.is_file() || metadata.mode() & 0o7777 != 0o600
            || metadata.uid() != unsafe { libc::geteuid() } || metadata.nlink() != 1 { return Err(GuardianSignError::DatabaseUnavailable); }
        Ok(Self { db: open_database(file)?, public_key, config })
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

    /// Opens an existing valid redb with zero or exactly eight schema-2 runtime tables.
    /// Legacy, partial, and unknown schemas are rejected without migration or writes.
    pub async fn open(file: File, public_key: [u8; 33], config: Arc<GuardianConfig>) -> Result<Self> {
        if file.metadata().map_err(unavailable)?.len() == 0 { return Err(GuardianSignError::DatabaseUnavailable); }
        let db = open_database(file)?;
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
                value.record.request_json.decode().map_err(|_| GuardianSignError::LegacyJournalSchema)?.validate_authorization(&config)?;
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

    pub async fn load_sessions(&mut self, network: u64, user: u64, after_nonce: Option<u64>, limit: u32) -> Result<Vec<GuardianSession>> {
        validate_limit(limit)?;
        if !self.runtime_initialized()? { return Ok(Vec::new()); }
        let tx = self.db.begin_read().map_err(unavailable)?;
        let rows = {
            let sessions = tx.open_table(GUARDIAN_SESSION).map_err(unavailable)?;
            let mut rows = Vec::new();
            for entry in sessions.range(nonce_bounds(network, user, after_nonce.unwrap_or(0))).map_err(unavailable)? {
                if rows.len() == limit as usize { break; }
                let (key, value) = entry.map_err(unavailable)?;
                rows.push((key.value(), value.value().to_vec()));
            }
            rows
        };
        rows.into_iter().map(|(key, bytes)| {
            let session = decode_session(key, &bytes)?;
            session.record.request_json.decode()?.validate_authorization(&self.config)?;
            Ok(session)
        }).collect()
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
    /// One write commits the session, included deposit tree states, both nonce indexes, and the sole account checkpoint.
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
    let bytes = encode(value)?;
    signed.insert((value.network_magic, value.user_id, value.nonce), bytes.as_slice()).map_err(unavailable)?;
    Ok(())
}

fn insert_session(tx: &redb::WriteTransaction, value: &GuardianSession) -> Result<()> {
    let mut sessions = tx.open_table(GUARDIAN_SESSION).map_err(unavailable)?;
    let bytes = encode(value)?;
    sessions.insert((value.network_magic, value.user_id, value.nonce), bytes.as_slice()).map_err(unavailable)?;
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
                signatures_json: JsonText::parse("{\"member_indices\":[],\"signatures\":[]}".to_owned()).expect("signature container"),
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
        assert!(consumed.db().lookup_signed(90103, 524288, 1).await.expect("lookup").expect("reservation retained").signature.is_none());
        assert!(matches!(consumed.db().reserve_guardian_nonce(&own).await, Err(GuardianSignError::NonceConflict)));
        assert!(matches!(consumed.db().save_guardian_signature(90103, 524288, 1, &own.request_bytes, [3; 64]).await, Err(GuardianSignError::NonceConflict)));
        assert!(consumed.db().lookup_signed(90103, 524288, 1).await.expect("unsigned").expect("row").signature.is_none());
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
        for version in [None, Some(1), Some(3)] {
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
}
