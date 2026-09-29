//! One redb file belongs to exactly one guardian signing key.
//! The caller supplies the exclusive file descriptor; dropping this value releases it.
//! Chain authentication and the immutable local approval archive belong to the service.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::ops::Bound;

use bincode::Options;
use redb::{Database, ReadableTable, TableDefinition, TableHandle};
use serde::de::DeserializeOwned;
use serde::Serialize;

use super::protocol::{GuardianAccount, GuardianAccountState, GuardianSession, GuardianSignError, GuardianSigned, HaltReason};

type Result<T, E = GuardianSignError> = std::result::Result<T, E>;

const GUARDIAN_SIGNER: TableDefinition<(), [u8; 33]> = TableDefinition::new("guardian_signer");
const GUARDIAN_ACCOUNT: TableDefinition<(u64, u64), &[u8]> = TableDefinition::new("guardian_account");
const GUARDIAN_SIGNED: TableDefinition<(u64, u64, u64), &[u8]> = TableDefinition::new("guardian_signed");
const GUARDIAN_SESSION: TableDefinition<(u64, u64, u64), &[u8]> = TableDefinition::new("guardian_session");
const TABLE_NAMES: [&str; 4] = ["guardian_account", "guardian_session", "guardian_signed", "guardian_signer"];

fn unavailable(_: impl std::fmt::Display) -> GuardianSignError { GuardianSignError::JournalUnavailable }

fn codec() -> impl bincode::Options {
    bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes()
}

fn canonical_bytes<T: Serialize + DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let value: T = codec().deserialize(bytes).map_err(unavailable)?;
    let encoded = codec().serialize(&value).map_err(unavailable)?;
    if encoded.as_slice() != bytes { return Err(GuardianSignError::JournalUnavailable); }
    Ok(value)
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> { codec().serialize(value).map_err(unavailable) }

fn decode_account(key: (u64, u64), bytes: &[u8]) -> Result<GuardianAccount> {
    let value: GuardianAccount = canonical_bytes(bytes)?;
    if (value.network_magic, value.user_id) != key { return Err(GuardianSignError::JournalUnavailable); }
    value.validate()?;
    Ok(value)
}

fn decode_signed(key: (u64, u64, u64), bytes: &[u8]) -> Result<GuardianSigned> {
    let value: GuardianSigned = canonical_bytes(bytes)?;
    if (value.network_magic, value.user_id, value.nonce) != key { return Err(GuardianSignError::JournalUnavailable); }
    value.validate()?;
    Ok(value)
}

fn decode_session(key: (u64, u64, u64), bytes: &[u8]) -> Result<GuardianSession> {
    let value: GuardianSession = canonical_bytes(bytes)?;
    if (value.network_magic, value.user_id, value.nonce) != key { return Err(GuardianSignError::JournalUnavailable); }
    Ok(value)
}

fn open_database(file: File) -> Result<Database> {
    Database::builder().create_file(file).map_err(|error| match error {
        redb::DatabaseError::DatabaseAlreadyOpen => GuardianSignError::KeyUnavailable,
        _ => GuardianSignError::JournalUnavailable,
    })
}

fn nonce_bounds(network: u64, user: u64, after: u64) -> (Bound<(u64, u64, u64)>, Bound<(u64, u64, u64)>) {
    (Bound::Excluded((network, user, after)), Bound::Included((network, user, u64::MAX)))
}

pub struct GuardianDb { db: Database, public_key: [u8; 33] }

impl GuardianDb {
    /// Creates the four tables, signer, and initial account in one durable transaction.
    /// The supplied file must be empty and mode 0600; this does not replace an existing database.
    pub async fn create(file: File, public_key: [u8; 33], account: &GuardianAccount) -> Result<Self> {
        account.validate()?;
        if account.state != GuardianAccountState::Active || account.halt_reason.is_some() || account.imported_nonce.is_some()
            || account.authorization_version == 0 { return Err(GuardianSignError::StateMismatch); }
        let metadata = file.metadata().map_err(unavailable)?;
        if metadata.len() != 0 { return Err(GuardianSignError::JournalUnavailable); }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o777 != 0o600 { return Err(GuardianSignError::JournalUnavailable); }
        }
        let db = open_database(file)?;
        let tx = db.begin_write().map_err(unavailable)?;
        {
            let mut signer = tx.open_table(GUARDIAN_SIGNER).map_err(unavailable)?;
            signer.insert((), &public_key).map_err(unavailable)?;
            let mut accounts = tx.open_table(GUARDIAN_ACCOUNT).map_err(unavailable)?;
            let bytes = encode(account)?;
            accounts.insert((account.network_magic, account.user_id), bytes.as_slice()).map_err(unavailable)?;
            let _signed = tx.open_table(GUARDIAN_SIGNED).map_err(unavailable)?;
            let _sessions = tx.open_table(GUARDIAN_SESSION).map_err(unavailable)?;
        }
        tx.commit().map_err(unavailable)?;
        Ok(Self { db, public_key })
    }

    /// Opens an existing database. Engine recovery may sync before these checks.
    /// A failed check does not insert or rewrite signer, account, signed, or session rows.
    pub async fn open(file: File, public_key: [u8; 33]) -> Result<Self> {
        if file.metadata().map_err(unavailable)?.len() == 0 { return Err(GuardianSignError::JournalUnavailable); }
        let db = open_database(file)?;
        let tx = db.begin_read().map_err(unavailable)?;
        let names = tx.list_tables().map_err(unavailable)?.map(|table| table.name().to_owned()).collect::<BTreeSet<_>>();
        if names != TABLE_NAMES.into_iter().map(str::to_owned).collect::<BTreeSet<_>>()
            || tx.list_multimap_tables().map_err(unavailable)?.next().is_some() {
            return Err(GuardianSignError::JournalUnavailable);
        }
        {
            let signer = tx.open_table(GUARDIAN_SIGNER).map_err(unavailable)?;
            let retained = signer.get(()).map_err(unavailable)?.ok_or(GuardianSignError::JournalUnavailable)?;
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
        if rows.len() != 1 { return Err(GuardianSignError::JournalUnavailable); }
        decode_account(rows[0].0, &rows[0].1)?;
        drop(tx.open_table(GUARDIAN_SIGNED).map_err(unavailable)?);
        drop(tx.open_table(GUARDIAN_SESSION).map_err(unavailable)?);
        Ok(Self { db, public_key })
    }

    pub async fn load_account(&mut self, network: u64, user: u64) -> Result<GuardianAccount> {
        let tx = self.db.begin_read().map_err(unavailable)?;
        let bytes = {
            let accounts = tx.open_table(GUARDIAN_ACCOUNT).map_err(unavailable)?;
            accounts.get((network, user)).map_err(unavailable)?.ok_or(GuardianSignError::JournalUnavailable)?.value().to_vec()
        };
        decode_account((network, user), &bytes)
    }

    pub async fn load_sessions(&mut self, network: u64, user: u64, after_nonce: Option<u64>, limit: u32) -> Result<Vec<GuardianSession>> {
        validate_limit(limit)?;
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
        rows.into_iter().map(|(key, bytes)| decode_session(key, &bytes)).collect()
    }

    pub async fn load_signed(&mut self, network: u64, user: u64, after_nonce: Option<u64>, limit: u32) -> Result<Vec<GuardianSigned>> {
        validate_limit(limit)?;
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
        rows.into_iter().map(|(key, bytes)| decode_signed(key, &bytes)).collect()
    }

    pub async fn reserve_guardian_nonce(&mut self, value: &GuardianSigned) -> Result<GuardianSigned> {
        value.validate()?;
        if value.signature.is_some() { return Err(GuardianSignError::StateMismatch); }
        let tx = self.db.begin_write().map_err(unavailable)?;
        ensure_signer(&tx, self.public_key)?;
        let account = account_in(&tx, value.network_magic, value.user_id)?;
        ensure_active(&account)?;
        if let Some(existing) = signed_in(&tx, value.network_magic, value.user_id, value.nonce)? {
            if !same_reservation(&existing, value) { return Err(GuardianSignError::NonceConflict); }
            if existing.signature.is_none() && account.imported_nonce.is_some_and(|nonce| nonce >= value.nonce) {
                return Err(GuardianSignError::NonceConflict);
            }
            tx.commit().map_err(unavailable)?;
            return Ok(existing);
        }
        if value.nonce != account.imported_nonce.unwrap_or(0).checked_add(1).ok_or(GuardianSignError::NonceConflict)? {
            return Err(GuardianSignError::HistoryUnavailable);
        }
        insert_signed(&tx, value)?;
        tx.commit().map_err(unavailable)?;
        Ok(value.clone())
    }

    pub async fn save_guardian_signature(&mut self, network: u64, user: u64, nonce: u64, request_bytes: &[u8], signature: [u8; 64]) -> Result<GuardianSigned> {
        let tx = self.db.begin_write().map_err(unavailable)?;
        ensure_signer(&tx, self.public_key)?;
        let account = account_in(&tx, network, user)?;
        ensure_active(&account)?;
        let mut value = signed_in(&tx, network, user, nonce)?.ok_or(GuardianSignError::NonceConflict)?;
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
    where F: FnOnce(&GuardianSigned) -> Result<T> {
        let tx = self.db.begin_write().map_err(unavailable)?;
        ensure_signer(&tx, self.public_key)?;
        ensure_active(&account_in(&tx, network, user)?)?;
        let value = signed_in(&tx, network, user, nonce)?.ok_or(GuardianSignError::NonceConflict)?;
        if value.request_bytes != request_bytes || value.signature.is_none() { return Err(GuardianSignError::NonceConflict); }
        let response = serialize(&value)?;
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
            || value.last_checkpoint_id < old.last_checkpoint_id || value.authorization_version == 0 {
            return Err(GuardianSignError::StateMismatch);
        }
        if value.last_checkpoint_id == old.last_checkpoint_id && value.last_checkpoint_hash != old.last_checkpoint_hash {
            write_halt(&tx, &old, HaltReason::CheckpointConflict)?;
            tx.commit().map_err(unavailable)?;
            return Err(GuardianSignError::AccountHalted);
        }
        if value.authorization_version != old.authorization_version && unresolved_signed(&tx, value.network_magic, value.user_id)? {
            return Err(GuardianSignError::AuthorizationMismatch);
        }
        insert_account(&tx, value)?;
        tx.commit().map_err(unavailable)
    }

    /// The service must authenticate the record and derive its deltas before calling.
    /// This transaction checks durable continuity; it does not assert provider trust.
    pub async fn import_session(&mut self, value: &GuardianSession) -> Result<GuardianSession> {
        let request = value.record.request_json.decode()?;
        if (request.network_magic, request.user_id, request.session_nonce) != (value.network_magic, value.user_id, value.nonce) {
            return Err(GuardianSignError::StateMismatch);
        }
        if value.withdrawal_appends.len() != request.withdrawal_records.len()
            || value.withdrawal_appends.iter().zip(&request.withdrawal_records).any(|(append, burn)| &append.burn != burn) {
            return Err(GuardianSignError::StateMismatch);
        }
        let request_bytes = request.canonical_bytes()?;
        let tx = self.db.begin_write().map_err(unavailable)?;
        ensure_signer(&tx, self.public_key)?;
        let account = account_in(&tx, value.network_magic, value.user_id)?;
        ensure_active(&account)?;
        if let Some(existing) = session_in(&tx, value.network_magic, value.user_id, value.nonce)? {
            if serde_json::to_string(&existing).map_err(unavailable)? != serde_json::to_string(value).map_err(unavailable)? {
                write_halt(&tx, &account, HaltReason::NonceConsumedDifferently)?;
                tx.commit().map_err(unavailable)?;
                return Err(GuardianSignError::AccountHalted);
            }
            tx.commit().map_err(unavailable)?;
            return Ok(existing);
        }
        if value.nonce != account.imported_nonce.unwrap_or(0).checked_add(1).ok_or(GuardianSignError::StateMismatch)? {
            return Err(GuardianSignError::HistoryUnavailable);
        }
        if let Some(nonce) = account.imported_nonce {
            let previous = session_in(&tx, value.network_magic, value.user_id, nonce)?.ok_or(GuardianSignError::JournalUnavailable)?;
            if previous.ending_leaf_hash != value.starting_leaf_hash {
                write_halt(&tx, &account, HaltReason::IncludedTransitionMissing)?;
                tx.commit().map_err(unavailable)?;
                return Err(GuardianSignError::AccountHalted);
            }
        }
        if let Some(own) = signed_in(&tx, value.network_magic, value.user_id, value.nonce)? {
            if own.request_bytes != request_bytes || own.starting_leaf_hash != value.starting_leaf_hash || own.ending_leaf_hash != value.ending_leaf_hash {
                write_halt(&tx, &account, HaltReason::NonceConsumedDifferently)?;
                tx.commit().map_err(unavailable)?;
                return Err(GuardianSignError::AccountHalted);
            }
        }
        if let Err(error) = verify_append_history(&tx, value) {
            if matches!(error, GuardianSignError::WithdrawalNonceConflict | GuardianSignError::StateMismatch) {
                write_halt(&tx, &account, HaltReason::AppendHistoryMismatch)?;
                tx.commit().map_err(unavailable)?;
                return Err(GuardianSignError::AccountHalted);
            }
            return Err(error);
        }
        insert_session(&tx, value)?;
        let mut advanced = account;
        advanced.imported_nonce = Some(value.nonce);
        insert_account(&tx, &advanced)?;
        tx.commit().map_err(unavailable)?;
        Ok(value.clone())
    }

    pub async fn lookup_signed(&mut self, network: u64, user: u64, nonce: u64) -> Result<Option<GuardianSigned>> {
        let tx = self.db.begin_read().map_err(unavailable)?;
        let bytes = {
            let signed = tx.open_table(GUARDIAN_SIGNED).map_err(unavailable)?;
            signed.get((network, user, nonce)).map_err(unavailable)?.map(|row| row.value().to_vec())
        };
        bytes.as_deref().map(|bytes| decode_signed((network, user, nonce), bytes)).transpose()
    }
}

fn ensure_signer(tx: &redb::WriteTransaction, public_key: [u8; 33]) -> Result<()> {
    let retained = {
        let signer = tx.open_table(GUARDIAN_SIGNER).map_err(unavailable)?;
        let row = signer.get(()).map_err(unavailable)?.ok_or(GuardianSignError::JournalUnavailable)?;
        row.value()
    };
    if retained != public_key { return Err(GuardianSignError::JournalUnavailable); }
    Ok(())
}

fn account_in(tx: &redb::WriteTransaction, network: u64, user: u64) -> Result<GuardianAccount> {
    let bytes = {
        let accounts = tx.open_table(GUARDIAN_ACCOUNT).map_err(unavailable)?;
        let row = accounts.get((network, user)).map_err(unavailable)?.ok_or(GuardianSignError::JournalUnavailable)?;
        row.value().to_vec()
    };
    decode_account((network, user), &bytes)
}

fn signed_in(tx: &redb::WriteTransaction, network: u64, user: u64, nonce: u64) -> Result<Option<GuardianSigned>> {
    let bytes = {
        let signed = tx.open_table(GUARDIAN_SIGNED).map_err(unavailable)?;
        let row = signed.get((network, user, nonce)).map_err(unavailable)?;
        row.map(|guard| guard.value().to_vec())
    };
    bytes.as_deref().map(|bytes| decode_signed((network, user, nonce), bytes)).transpose()
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

fn unresolved_signed(tx: &redb::WriteTransaction, network: u64, user: u64) -> Result<bool> {
    let mut nonces = Vec::new();
    {
        let signed = tx.open_table(GUARDIAN_SIGNED).map_err(unavailable)?;
        for entry in signed.range(nonce_bounds(network, user, 0)).map_err(unavailable)? {
            nonces.push(entry.map_err(unavailable)?.0.value().2);
        }
    }
    let sessions = tx.open_table(GUARDIAN_SESSION).map_err(unavailable)?;
    for nonce in nonces {
        if sessions.get((network, user, nonce)).map_err(unavailable)?.is_none() { return Ok(true); }
    }
    Ok(false)
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
        && a.request_bytes == b.request_bytes && a.authorization_bytes == b.authorization_bytes
        && a.starting_leaf_hash == b.starting_leaf_hash && a.ending_leaf_hash == b.ending_leaf_hash
        && a.message == b.message
}

fn verify_append_history(tx: &redb::WriteTransaction, value: &GuardianSession) -> Result<()> {
    if value.withdrawal_appends.is_empty() { return Ok(()); }
    let mut identities = BTreeSet::new();
    let mut nonces = BTreeSet::new();
    let mut next = BTreeMap::<u8, u64>::new();
    for append in &value.withdrawal_appends {
        if append.chain_index != append.burn.destination_chain_index
            || !identities.insert((append.burn.sender_user_id, append.burn.token_contract_id, append.burn.nonce))
            || !nonces.insert((append.chain_index, append.burn.nonce)) {
            return Err(GuardianSignError::WithdrawalNonceConflict);
        }
        next.entry(append.chain_index).or_insert(0);
    }
    let prior = {
        let sessions = tx.open_table(GUARDIAN_SESSION).map_err(unavailable)?;
        let mut prior = Vec::new();
        for entry in sessions.range(nonce_bounds(value.network_magic, value.user_id, 0)).map_err(unavailable)? {
            let (key, row) = entry.map_err(unavailable)?;
            prior.push((key.value(), row.value().to_vec()));
        }
        prior
    };
    for (key, bytes) in prior {
        let previous = decode_session(key, &bytes)?;
        for append in previous.withdrawal_appends {
            if identities.contains(&(append.burn.sender_user_id, append.burn.token_contract_id, append.burn.nonce))
                || nonces.contains(&(append.chain_index, append.burn.nonce)) {
                return Err(GuardianSignError::WithdrawalNonceConflict);
            }
            if let Some(index) = next.get_mut(&append.chain_index) {
                if u64::from(append.append_index) != *index { return Err(GuardianSignError::HistoryUnavailable); }
                *index += 1;
            }
        }
    }
    for append in &value.withdrawal_appends {
        let index = next.get_mut(&append.chain_index).ok_or(GuardianSignError::StateMismatch)?;
        if u64::from(append.append_index) != *index { return Err(GuardianSignError::StateMismatch); }
        *index += 1;
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
            let db = GuardianDb::create(file, KEY, account).await.expect("create");
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

    fn active(network: u64, checkpoint: u64) -> GuardianAccount {
        GuardianAccount {
            network_magic: network, user_id: 524288, state: GuardianAccountState::Active,
            last_checkpoint_id: checkpoint, last_checkpoint_hash: Hash4::default(), imported_nonce: None,
            authorization_version: 1, halt_reason: None,
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
            request_bytes: request.canonical_bytes().expect("canonical request"), authorization_bytes: vec![2],
            starting_leaf_hash: Hash4::default(), ending_leaf_hash: Hash4::default(), message: [3; 32], signature: None,
        }
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
        retry.authorization_bytes.push(9);
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
        assert!(matches!(GuardianDb::open(contender, KEY).await, Err(GuardianSignError::KeyUnavailable)));
        owned.db().reserve_guardian_nonce(&value).await.expect("reserve");
        let mut different = value.clone();
        different.authorization_bytes.push(7);
        assert!(matches!(owned.db().reserve_guardian_nonce(&different).await, Err(GuardianSignError::NonceConflict)));
        let file = owned.reopen();
        assert!(matches!(GuardianDb::open(file, [3; 33]).await, Err(GuardianSignError::AccountIdentityConflict)));
        let mut db = GuardianDb::open(owned.reopen(), KEY).await.expect("reopen");
        let saved = db.reserve_guardian_nonce(&value).await.expect("durable retry");
        assert!(saved.signature.is_none());
        assert_eq!(db.load_account(value.network_magic, value.user_id).await.expect("load").last_checkpoint_id, u64::MAX);
        let signed = db.save_guardian_signature(value.network_magic, value.user_id, value.nonce, &value.request_bytes, [3; 64]).await.expect("save");
        assert_eq!(signed.signature, Some([3; 64]));
        assert!(matches!(db.save_guardian_signature(value.network_magic, value.user_id, value.nonce, &value.request_bytes, [4; 64]).await, Err(GuardianSignError::NonceConflict)));
        assert_eq!(db.lookup_signed(value.network_magic, value.user_id, value.nonce).await.expect("unchanged").expect("decision").signature, Some([3; 64]));
        db.halt_account(value.network_magic, value.user_id, HaltReason::SigningAuthorizationInvalid).await.expect("halt");
        assert!(matches!(db.authorize_response(value.network_magic, value.user_id, value.nonce, &value.request_bytes, |_| Ok(())).await, Err(GuardianSignError::AccountHalted)));
        assert!(matches!(db.save_account(&active(value.network_magic, u64::MAX)).await, Err(GuardianSignError::AccountHalted)));
        assert_eq!(db.load_account(value.network_magic, value.user_id).await.expect("load halted").state, GuardianAccountState::Halted);
        drop(db);
        let mut restored = GuardianDb::open(OpenOptions::new().read(true).write(true).open(&owned.path).expect("restored"), KEY).await.expect("halt reopened");
        assert_eq!(restored.load_account(value.network_magic, value.user_id).await.expect("retained halt").state, GuardianAccountState::Halted);
    }

    #[tokio::test]
    async fn import_conflicts_halt_without_advancing_cursor() {
        let mut first = TestDb::create(&active(90102, 0)).await;
        let initial = history(90102, 1, vec![]);
        first.db().import_session(&initial).await.expect("offline import");
        first.db().import_session(&initial).await.expect("idempotent import");
        assert!(first.db().lookup_signed(90102, 524288, 1).await.expect("no fabricated decision").is_none());
        assert_eq!(first.db().load_sessions(90102, 524288, None, 64).await.expect("history").len(), 1);
        assert!(matches!(first.db().import_session(&history(90102, 3, vec![])).await, Err(GuardianSignError::HistoryUnavailable)));
        assert_eq!(first.db().load_account(90102, 524288).await.expect("rollback").imported_nonce, Some(1));
        first.db().import_session(&history(90102, 2, vec![])).await.expect("contiguous import");
        let mut wrong_root = history(90102, 3, vec![]);
        wrong_root.starting_leaf_hash = Hash4::try_from(&[1, 0, 0, 0]).expect("hash");
        assert!(matches!(first.db().import_session(&wrong_root).await, Err(GuardianSignError::AccountHalted)));
        assert_halted_cursor(first.db(), 90102, 2).await;

        let mut consumed = TestDb::create(&active(90103, 0)).await;
        let consumed_history = history(90103, 1, vec![]);
        let mut own = reserved();
        own.network_magic = 90103;
        own.request_bytes = consumed_history.record.request_json.decode().expect("request").canonical_bytes().expect("bytes");
        consumed.db().reserve_guardian_nonce(&own).await.expect("reserve before other quorum");
        consumed.db().import_session(&consumed_history).await.expect("other quorum consumed reservation");
        assert!(consumed.db().lookup_signed(90103, 524288, 1).await.expect("lookup").expect("reservation retained").signature.is_none());
        assert!(matches!(consumed.db().reserve_guardian_nonce(&own).await, Err(GuardianSignError::NonceConflict)));
        assert!(matches!(consumed.db().save_guardian_signature(90103, 524288, 1, &own.request_bytes, [3; 64]).await, Err(GuardianSignError::NonceConflict)));
        assert!(consumed.db().lookup_signed(90103, 524288, 1).await.expect("unsigned").expect("row").signature.is_none());
        let mut different = consumed_history.clone();
        different.record.endcap_proof_hex = "0x01".to_owned();
        assert!(matches!(consumed.db().import_session(&different).await, Err(GuardianSignError::AccountHalted)));
        assert_halted_cursor(consumed.db(), 90103, 1).await;

        let mut repeated_identity = append(0, 10, 1);
        repeated_identity.chain_index = 1;
        repeated_identity.burn.destination_chain_index = 1;
        for (network, conflicting) in [(90104, append(3, 10, 2)), (90105, repeated_identity), (90106, append(1, 11, 1))] {
            let mut owned = TestDb::create(&active(network, 0)).await;
            owned.db().import_session(&history(network, 1, vec![append(0, 10, 1)])).await.expect("first append");
            assert!(matches!(owned.db().import_session(&history(network, 2, vec![conflicting])).await, Err(GuardianSignError::AccountHalted)));
            assert_halted_cursor(owned.db(), network, 1).await;
        }

        let mut advanced = TestDb::create(&active(90107, 0)).await;
        advanced.db().import_session(&history(90107, 1, vec![append(0, 10, 1)])).await.expect("initial append");
        advanced.db().import_session(&history(90107, 2, vec![append(1, 10, 2)])).await.expect("next append");
        let saved = advanced.db().load_sessions(90107, 524288, Some(1), 1).await.expect("append history");
        assert_eq!(saved[0].withdrawal_appends, vec![append(1, 10, 2)]);
        let mut account = advanced.db().load_account(90107, 524288).await.expect("active observation");
        account.last_checkpoint_id = 7;
        account.last_checkpoint_hash = Hash4::try_from(&[7, 0, 0, 0]).expect("checkpoint hash");
        advanced.db().save_account(&account).await.expect("legal checkpoint advancement");
        let saved = advanced.db().load_account(90107, 524288).await.expect("advanced observation");
        assert_eq!((saved.last_checkpoint_id, saved.last_checkpoint_hash, saved.imported_nonce, saved.state), (7, account.last_checkpoint_hash, Some(2), GuardianAccountState::Active));

        let mut conflict = TestDb::create(&active(90108, 0)).await;
        let mut conflicting = history(90108, 1, vec![]);
        let mut own = reserved();
        own.network_magic = 90108;
        let mut request = conflicting.record.request_json.decode().expect("original request");
        own.request_bytes = request.canonical_bytes().expect("original bytes");
        conflict.db().reserve_guardian_nonce(&own).await.expect("unconsumed reservation");
        request.trace_json = JsonText::parse(format!(" {} ", request.trace_json.as_str())).expect("distinct exact request");
        conflicting.record.request_json = JsonText::from_value(&request).expect("conflicting request JSON");
        assert!(matches!(conflict.db().import_session(&conflicting).await, Err(GuardianSignError::AccountHalted)));
        let saved = conflict.db().load_account(90108, 524288).await.expect("conflict observation");
        assert_eq!(saved.state, GuardianAccountState::Halted);
        assert_eq!(saved.halt_reason, Some(HaltReason::NonceConsumedDifferently));
        assert_eq!(saved.imported_nonce, None);
        assert!(conflict.db().load_sessions(90108, 524288, None, 1).await.expect("no import").is_empty());
        let retained = conflict.db().lookup_signed(90108, 524288, 1).await.expect("retained decision").expect("reservation");
        assert!(same_reservation(&own, &retained));
        assert!(retained.signature.is_none());
    }

    #[tokio::test]
    async fn open_rejects_empty_missing_and_multiple_accounts_without_inserting() {
        let path = std::env::temp_dir().join(format!("guardian-empty-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        let file = OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&path).expect("empty");
        assert!(matches!(GuardianDb::open(file, KEY).await, Err(GuardianSignError::JournalUnavailable)));
        assert_eq!(std::fs::metadata(&path).expect("metadata").len(), 0);
        let _ = std::fs::remove_file(&path);

        for accounts in [0usize, 2] {
            let path = std::env::temp_dir().join(format!("guardian-accounts-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            let file = OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&path).expect("raw");
            let db = Database::builder().create_file(file).expect("raw database");
            let tx = db.begin_write().expect("raw write");
            {
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
            }
            tx.commit().expect("raw commit");
            drop(db);
            let reopened = OpenOptions::new().read(true).write(true).open(&path).expect("reopen raw");
            assert!(matches!(GuardianDb::open(reopened, KEY).await, Err(GuardianSignError::JournalUnavailable)));
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
}
