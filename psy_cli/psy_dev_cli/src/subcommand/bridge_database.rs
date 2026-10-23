//! Shared bridge-journal file handling for `fresh-devnet-state` and
//! `restore-bridge-state`.
//!
//! The four databases (`guardian-1/2/3.redb`, `relayer.redb`) are opened under
//! real redb `FileBackend` locks, in that fixed order, before any engine opens.
//! Guardian and relayer journals carry the same logical snapshot but **not**
//! interchangeable redb key types: every key type here is named exactly like
//! the runtime type that wrote it.

use std::{
    collections::BTreeSet,
    ffi::{CStr, CString, OsStr, OsString},
    fs::File,
    io::{self, ErrorKind},
    os::{fd::FromRawFd, unix::{ffi::{OsStrExt, OsStringExt}, fs::MetadataExt, io::AsRawFd}},
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, ensure};
use redb::{
    Key, ReadableTableMetadata, TableDefinition, TableHandle, TypeName, Value,
    backends::FileBackend, Database,
};

pub const DATABASES: [&str; 4] = ["guardian-1.redb", "guardian-2.redb", "guardian-3.redb", "relayer.redb"];
pub const GUARDIAN_TABLES: [&str; 8] = [
    "deposit_tree_states", "guardian_account", "guardian_schema", "guardian_session",
    "guardian_signed", "guardian_signer", "guardian_withdrawal_nonce", "included_withdrawal_burns",
];
pub const RELAYER_TABLES: [&str; 8] = [
    "chain_claims", "deposit_tree_states", "finalization_batch", "guardian_account",
    "guardian_withdrawal_nonce", "included_withdrawal_burns", "journal_schema", "relayer_request",
];
const GUARDIAN_TABLES_WITHOUT_SCHEMA: [&str; 7] = [
    "deposit_tree_states", "guardian_account", "guardian_session", "guardian_signed",
    "guardian_signer", "guardian_withdrawal_nonce", "included_withdrawal_burns",
];
pub const RELAYER_TABLES_WITHOUT_SCHEMA: [&str; 7] = [
    "chain_claims", "deposit_tree_states", "finalization_batch", "guardian_account",
    "guardian_withdrawal_nonce", "included_withdrawal_burns", "relayer_request",
];
pub const GUARDIAN_SCHEMA: TableDefinition<(), u32> = TableDefinition::new("guardian_schema");
pub const JOURNAL_SCHEMA: TableDefinition<(), u64> = TableDefinition::new("journal_schema");
pub const GUARDIAN_SCHEMA_VERSION: u32 = 3;
pub const JOURNAL_SCHEMA_VERSION: u64 = 3;
pub const LEGACY_JOURNAL: &str = "incompatible legacy journal schema; explicit operator-controlled migration is required";

pub const GUARDIAN_SIGNER: TableDefinition<(), [u8; 33]> = TableDefinition::new("guardian_signer");
pub const GUARDIAN_ACCOUNT: TableDefinition<(u64, u64), &[u8]> = TableDefinition::new("guardian_account");
pub const GUARDIAN_SIGNED: TableDefinition<(u64, u64, u64), &[u8]> = TableDefinition::new("guardian_signed");
pub const GUARDIAN_SESSION: TableDefinition<(u64, u64, u64), &[u8]> = TableDefinition::new("guardian_session");
pub const RELAYER_REQUEST: TableDefinition<u64, &[u8]> = TableDefinition::new("relayer_request");
pub const CHAIN_CLAIMS: TableDefinition<u8, &[u8]> = TableDefinition::new("chain_claims");
pub const FINALIZATION_BATCH: TableDefinition<(), &[u8]> = TableDefinition::new("finalization_batch");

pub struct HeldDatabase {
    pub name: &'static str,
    pub file: Option<File>,
    pub database: Option<Database>,
}

#[derive(Debug)]
pub struct GuardianDepositTreeKey(pub [u8; 17]);
#[derive(Debug)]
pub struct GuardianWithdrawalBurnKey(pub [u8; 56]);
#[derive(Debug)]
pub struct GuardianWithdrawalNonceKey(pub [u8; 49]);
#[derive(Debug)]
pub struct RelayerDepositTreeKey(pub [u8; 17]);
#[derive(Debug)]
pub struct RelayerWithdrawalBurnKey(pub [u8; 56]);
#[derive(Debug)]
pub struct RelayerWithdrawalNonceKey(pub [u8; 49]);

macro_rules! runtime_key {
    ($ty:ident, $width:expr, $name:literal) => {
        impl Value for $ty {
            type SelfType<'a> = Self;
            type AsBytes<'a> = [u8; $width];
            fn fixed_width() -> Option<usize> { Some($width) }
            fn from_bytes<'a>(data: &'a [u8]) -> Self where Self: 'a { Self(data.try_into().unwrap()) }
            fn as_bytes<'a, 'b: 'a>(value: &'a Self) -> [u8; $width] where Self: 'a, Self: 'b { value.0 }
            fn type_name() -> TypeName { TypeName::new($name) }
        }
        impl Key for $ty {
            fn compare(a: &[u8], b: &[u8]) -> std::cmp::Ordering { a.cmp(b) }
        }
    };
}
runtime_key!(GuardianDepositTreeKey, 17, "guardian_common::DepositTreeKey");
runtime_key!(GuardianWithdrawalBurnKey, 56, "guardian_common::WithdrawalBurnKey");
runtime_key!(GuardianWithdrawalNonceKey, 49, "guardian_common::NonceKey");
runtime_key!(RelayerDepositTreeKey, 17, "psy_relayer_cli::DepositTreeKey");
runtime_key!(RelayerWithdrawalBurnKey, 56, "psy_relayer_cli::WithdrawalBurnKey");
runtime_key!(RelayerWithdrawalNonceKey, 49, "psy_relayer_cli::NonceKey");

pub const GUARDIAN_DEPOSIT_TREE_STATES: TableDefinition<GuardianDepositTreeKey, &[u8]> = TableDefinition::new("deposit_tree_states");
pub const GUARDIAN_INCLUDED_WITHDRAWAL_BURNS: TableDefinition<GuardianWithdrawalBurnKey, u64> = TableDefinition::new("included_withdrawal_burns");
pub const GUARDIAN_WITHDRAWAL_NONCE: TableDefinition<GuardianWithdrawalNonceKey, u64> = TableDefinition::new("guardian_withdrawal_nonce");
pub const RELAYER_DEPOSIT_TREE_STATES: TableDefinition<RelayerDepositTreeKey, &[u8]> = TableDefinition::new("deposit_tree_states");
pub const RELAYER_INCLUDED_WITHDRAWAL_BURNS: TableDefinition<RelayerWithdrawalBurnKey, u64> = TableDefinition::new("included_withdrawal_burns");
pub const RELAYER_WITHDRAWAL_NONCE: TableDefinition<RelayerWithdrawalNonceKey, u64> = TableDefinition::new("guardian_withdrawal_nonce");

/// Key bytes in the runtime layout: little-endian scalars, then raw words.
pub fn deposit_tree_key_bytes(network: u64, user: u64, chain: u8) -> [u8; 17] {
    let mut bytes = [0; 17];
    bytes[..8].copy_from_slice(&network.to_le_bytes());
    bytes[8..16].copy_from_slice(&user.to_le_bytes());
    bytes[16] = chain;
    bytes
}

pub fn withdrawal_burn_key_bytes(network: u64, user: u64, sender: u32, token_contract: u32, nonce: &[u32; 8]) -> [u8; 56] {
    let mut bytes = [0; 56];
    bytes[..8].copy_from_slice(&network.to_le_bytes());
    bytes[8..16].copy_from_slice(&user.to_le_bytes());
    bytes[16..20].copy_from_slice(&sender.to_le_bytes());
    bytes[20..24].copy_from_slice(&token_contract.to_le_bytes());
    for (index, word) in nonce.iter().enumerate() {
        bytes[24 + index * 4..28 + index * 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

pub fn nonce_key_bytes(network: u64, user: u64, chain: u8, nonce: &[u32; 8]) -> [u8; 49] {
    let mut bytes = [0; 49];
    bytes[..8].copy_from_slice(&network.to_le_bytes());
    bytes[8..16].copy_from_slice(&user.to_le_bytes());
    bytes[16] = chain;
    for (index, word) in nonce.iter().enumerate() {
        bytes[17 + index * 4..21 + index * 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

pub fn is_relayer(name: &str) -> bool { name == "relayer.redb" }

pub fn absolute_path(path: &Path) -> anyhow::Result<PathBuf> {
    let path = if path.is_absolute() { path.to_owned() } else { std::env::current_dir()?.join(path) };
    ensure!(path.components().all(|part| matches!(part, Component::RootDir | Component::Normal(_))), "path must not contain dot or parent components");
    Ok(path)
}

pub fn open_at(parent: &File, name: &OsStr, flags: i32) -> anyhow::Result<Option<File>> {
    ensure!(!name.as_bytes().is_empty() && !name.as_bytes().contains(&b'/') && name != "." && name != "..", "invalid relative path component");
    let name = CString::new(name.as_bytes())?;
    let descriptor = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK, 0o600 as libc::mode_t) };
    if descriptor < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == ErrorKind::NotFound { return Ok(None); }
        return Err(error).context("opening protected path component");
    }
    Ok(Some(unsafe { File::from_raw_fd(descriptor) }))
}

pub fn validate_directory(directory: &File, private: bool) -> anyhow::Result<()> {
    let metadata = directory.metadata()?;
    ensure!(metadata.is_dir() && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.mode() & (if private { 0o077 } else { 0o022 }) == 0, "directory is not trusted and owner-controlled");
    Ok(())
}

pub fn open_absolute_directory(path: &Path) -> anyhow::Result<File> {
    let mut directory = File::open("/")?;
    for part in path.components() {
        let Component::Normal(name) = part else { continue };
        directory = open_at(&directory, name, libc::O_RDONLY | libc::O_DIRECTORY)?.context("directory is missing")?;
        let metadata = directory.metadata()?;
        ensure!([0, unsafe { libc::geteuid() }].contains(&metadata.uid()) && metadata.mode() & 0o022 == 0, "untrusted repo ancestor");
    }
    validate_directory(&directory, false)?;
    Ok(directory)
}

pub fn open_directory_path(parent: &File, path: &Path) -> anyhow::Result<Option<File>> {
    let mut directory = parent.try_clone()?;
    for part in path.components() {
        let Component::Normal(name) = part else { anyhow::bail!("invalid relative directory") };
        let Some(opened) = open_at(&directory, name, libc::O_RDONLY | libc::O_DIRECTORY)? else { return Ok(None) };
        validate_directory(&opened, false)?;
        ensure!(opened.metadata()?.dev() == parent.metadata()?.dev(), "directory path crosses filesystem boundary");
        directory = opened;
    }
    Ok(Some(directory))
}

pub fn directory_names(directory: &File) -> anyhow::Result<Vec<OsString>> {
    let dot = CString::new(".")?;
    let descriptor = unsafe { libc::openat(directory.as_raw_fd(), dot.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    let stream = unsafe { libc::fdopendir(descriptor) };
    if stream.is_null() {
        unsafe { libc::close(descriptor) };
        return Err(io::Error::last_os_error()).context("opening directory stream");
    }
    let mut names = Vec::new();
    let result = loop {
        unsafe { *libc::__errno_location() = 0 };
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            break if error.raw_os_error() == Some(0) { Ok(()) } else { Err(error) };
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." { names.push(OsString::from_vec(name.to_vec())); }
    };
    unsafe { libc::closedir(stream) };
    result?;
    Ok(names)
}

pub fn validate_database_file(file: &File, existing: bool) -> anyhow::Result<()> {
    let metadata = file.metadata()?;
    ensure!(metadata.is_file() && metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o7777 == 0o600
        && metadata.nlink() == 1 && (!existing || metadata.len() > 0), "database must be a nonempty protected single-link regular file");
    Ok(())
}

pub fn same_file(left: &File, right: &File) -> anyhow::Result<bool> {
    let left = left.metadata()?;
    let right = right.metadata()?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

/// Locks and opens every present database. Missing files stay `None`; callers
/// that require a complete set must reject them afterwards.
pub fn open_databases(directory: &File) -> anyhow::Result<Vec<HeldDatabase>> {
    // Acquire all real redb backend locks before opening any engine. No surrogate
    // lock file, fake magic-header check, or unlink/recreate of existing files.
    let mut backends = Vec::with_capacity(DATABASES.len());
    for name in DATABASES {
        let opened = match open_at(directory, OsStr::new(name), libc::O_RDWR)? {
            Some(file) => {
                validate_database_file(&file, true)?;
                let retained = file.try_clone()?;
                let backend = FileBackend::new(file).with_context(|| format!("exclusive database ownership refused: {name}"))?;
                Some((retained, backend))
            }
            None => None,
        };
        backends.push((name, opened));
    }
    let mut databases = Vec::with_capacity(DATABASES.len());
    for (name, opened) in backends {
        let (file, database) = match opened {
            Some((file, backend)) => {
                // An interrupted helper may leave a valid database needing redb's
                // standard crash recovery. All backend locks are already held;
                // recovery is not permission to clear business tables.
                let database = Database::builder().create_with_backend(backend)
                    .with_context(|| format!("opening existing redb database: {name}"))?;
                validate_database(&database, is_relayer(name)).with_context(|| format!("validating database: {name}"))?;
                (Some(file), Some(database))
            }
            None => (None, None),
        };
        databases.push(HeldDatabase { name, file, database });
    }
    Ok(databases)
}

/// Shape and schema check. An empty database (no tables) is accepted; a
/// populated one must be exactly the schema-3 runtime set with the right
/// marker and key types. Legacy seven-table journals fail closed.
pub fn validate_database(database: &Database, relayer: bool) -> anyhow::Result<()> {
    let transaction = database.begin_read()?;
    ensure!(transaction.list_multimap_tables()?.next().is_none(), "unexpected multimap tables");
    let names: BTreeSet<_> = transaction.list_tables()?.map(|table| table.name().to_owned()).collect();
    let runtime_names: &[&str] = if relayer { &RELAYER_TABLES } else { &GUARDIAN_TABLES };
    let runtime: BTreeSet<_> = runtime_names.iter().map(|name| (*name).to_owned()).collect();
    let legacy_names: &[&str] = if relayer { &RELAYER_TABLES_WITHOUT_SCHEMA } else { &GUARDIAN_TABLES_WITHOUT_SCHEMA };
    let legacy: BTreeSet<_> = legacy_names.iter().map(|name| (*name).to_owned()).collect();
    ensure!(names != legacy, "{LEGACY_JOURNAL}");
    ensure!(names.is_empty() || names == runtime, "unexpected database table shape");
    if names == runtime {
        if relayer {
            let schema = transaction.open_table(JOURNAL_SCHEMA)?;
            ensure!(schema.len()? == 1 && schema.get(())?.is_some_and(|row| row.value() == JOURNAL_SCHEMA_VERSION), "{LEGACY_JOURNAL}");
            drop(schema);
            drop(transaction.open_table(RELAYER_REQUEST)?);
            drop(transaction.open_table(CHAIN_CLAIMS)?);
            drop(transaction.open_table(FINALIZATION_BATCH)?);
            drop(transaction.open_table(GUARDIAN_ACCOUNT)?);
            drop(transaction.open_table(RELAYER_DEPOSIT_TREE_STATES)?);
            drop(transaction.open_table(RELAYER_INCLUDED_WITHDRAWAL_BURNS)?);
            drop(transaction.open_table(RELAYER_WITHDRAWAL_NONCE)?);
        } else {
            let schema = transaction.open_table(GUARDIAN_SCHEMA)?;
            ensure!(schema.len()? == 1 && schema.get(())?.is_some_and(|row| row.value() == GUARDIAN_SCHEMA_VERSION), "{LEGACY_JOURNAL}");
            drop(schema);
            drop(transaction.open_table(GUARDIAN_SIGNER)?);
            drop(transaction.open_table(GUARDIAN_ACCOUNT)?);
            drop(transaction.open_table(GUARDIAN_SIGNED)?);
            drop(transaction.open_table(GUARDIAN_SESSION)?);
            drop(transaction.open_table(GUARDIAN_DEPOSIT_TREE_STATES)?);
            drop(transaction.open_table(GUARDIAN_INCLUDED_WITHDRAWAL_BURNS)?);
            drop(transaction.open_table(GUARDIAN_WITHDRAWAL_NONCE)?);
        }
    }
    Ok(())
}

/// The path still names the inode this process locked.
pub fn check_database_bindings(directory: &File, databases: &[HeldDatabase], require_all: bool) -> anyhow::Result<()> {
    for held in databases {
        ensure!(!require_all || held.database.is_some(), "database handle missing: {}", held.name);
        match (&held.file, open_at(directory, OsStr::new(held.name), libc::O_RDONLY)?) {
            (Some(retained), Some(current)) => {
                validate_database_file(&current, true)?;
                ensure!(same_file(retained, &current)?, "database path changed: {}", held.name);
            }
            (None, None) if !require_all => (),
            _ => anyhow::bail!("database path changed: {}", held.name),
        }
    }
    Ok(())
}

/// Deletes every table, schema and signer included, in its own transaction.
/// `fresh-devnet-state` only; the bridge reset must not use it.
pub fn clear_database(database: &Database) -> anyhow::Result<()> {
    let transaction = database.begin_write()?;
    let tables: Vec<_> = transaction.list_tables()?.collect();
    for table in tables { transaction.delete_table(table)?; }
    transaction.commit()?;
    Ok(())
}
