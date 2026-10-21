//! Foreground fresh-devnet reset handshake. Database files are never unlinked.
//! Existing `guardians-root/db` must be owner-only. Preflight changes no business
//! rows or cleanup entries; redb may update headers and recovery metadata during
//! normal open/drop housekeeping or crash recovery under exclusive backend locks.
//! Missing databases are created only after `reset`; namespace binding stays put.
//! Reset commits each database separately. Any failure stops immediately;
//! earlier commits/removals remain, with no rollback or subsequent cleanup.
//! Authorization is published only in the selected network's canonical config;
//! runtime databases hold no authorization body or historical version store.
use std::{
    collections::BTreeSet,
    ffi::{CStr, CString, OsStr, OsString},
    fs::File,
    io::{self, BufRead, Write},
    os::{fd::{AsRawFd, FromRawFd}, unix::{ffi::{OsStrExt, OsStringExt}, fs::MetadataExt}},
    path::{Component, Path, PathBuf},
};

use anyhow::{ensure, Context};
use redb::{backends::FileBackend, Database, Key, TableDefinition, TableHandle, TypeName, Value};

use super::generate_genesis::{build_fresh_devnet_authorization, preflight_fresh_devnet_inputs, publish_guardian_authorization_unchanged, CanonicalPolicyPin};

const DATABASES: [&str; 4] = ["guardian-1.redb", "guardian-2.redb", "guardian-3.redb", "relayer.redb"];
/// Frozen runtime table sets: a populated database must match exactly; partial
/// or old sets fail closed and are never migrated by engine crash recovery.
const GUARDIAN_TABLES: [&str; 7] = ["deposit_tree_states", "guardian_account", "guardian_session", "guardian_signed", "guardian_signer", "guardian_withdrawal_nonce", "included_withdrawal_burns"];
const RELAYER_TABLES: [&str; 7] = ["chain_claims", "deposit_tree_states", "finalization_batch", "guardian_account", "guardian_withdrawal_nonce", "included_withdrawal_burns", "relayer_request"];
const TARGETS: [&str; 6] = [
    "db/anvil", "local_checkpoints", "genesis.json",
    "psy-contracts/deployments/localhost", "psy-contracts/deployments/localhostBsc",
    "psy-contracts/deployments/localhostBase",
];

struct HeldDatabase {
    name: &'static str,
    file: Option<File>,
    database: Option<Database>,
}

/// Every unsafe operation below is a POSIX descriptor operation: names are NUL-free,
/// relative single components; opened descriptors are owned exactly once. Directory
/// traversal never follows symlinks and refuses foreign owners or writable parents.
pub async fn run(repo_root: PathBuf, guardians_root: PathBuf) -> anyhow::Result<()> {
    ensure!(psy_config::CURRENT_NETWORK == "localhost",
        "fresh-devnet-state requires compiled CURRENT_NETWORK=localhost; selected {}", psy_config::CURRENT_NETWORK);
    let repo_root = absolute_path(&repo_root)?;
    let guardians_root = absolute_path(&guardians_root)?;
    let relative = guardians_root.strip_prefix(&repo_root).context("guardian root must be inside repo-root")?;
    ensure!(!relative.as_os_str().is_empty(), "guardian root must not equal repo-root");
    for target in TARGETS {
        ensure!(!relative.starts_with(target) && !Path::new(target).starts_with(relative), "guardian root overlaps cleanup target {target}");
    }
    let repo = open_absolute_directory(&repo_root)?;
    let guardian = open_directory_path(&repo, relative)?.context("guardian root is missing")?;
    let db_directory = open_at(&guardian, OsStr::new("db"), libc::O_RDONLY | libc::O_DIRECTORY)?
        .context("guardian db directory must already exist")?;
    validate_directory(&db_directory, true)?;
    validate_targets(&repo)?;
    // Secret-output metadata lives in this preflight. Keep it before database
    // open and `prepared`: mode 0664, a symlink, or a hardlink must fail with
    // no business-table change and no cleanup.
    preflight_fresh_devnet_inputs(&repo_root)?;
    let policy_pin = CanonicalPolicyPin::pin(&repo_root)?;
    let mut databases = open_databases(&db_directory)?;
    phase("prepared")?;
    let stdin = io::stdin();
    let mut input = stdin.lock();
    command(&mut input, "reset")?;
    // Revalidate the entire cleanup set and database bindings before the first reset write.
    validate_targets(&repo)?;
    policy_pin.validate(&repo_root)?;
    check_database_bindings(&db_directory, &databases, false)?;
    for held in &mut databases {
        if held.database.is_none() {
            let file = open_at(&db_directory, OsStr::new(held.name), libc::O_RDWR | libc::O_CREAT | libc::O_EXCL)?
                .context("exclusive database creation failed")?;
            validate_database_file(&file, false)?;
            held.file = Some(file.try_clone()?);
            held.database = Some(Database::builder().create_file(file).context("creating fresh redb database")?);
        }
    }
    db_directory.sync_all()?;
    check_database_bindings(&db_directory, &databases, true)?;
    for held in &databases {
        clear_database(held.database.as_ref().context("database handle missing")?)
            .with_context(|| format!("reset failed at {}; earlier database commits remain; cleanup not started", held.name))?;
    }
    for target in TARGETS { remove_target(&repo, Path::new(target))?; }
    phase("reset")?;
    command(&mut input, "authorize")?;
    check_database_bindings(&db_directory, &databases, true)?;
    policy_pin.validate(&repo_root)?;
    let (authorization, policy_pin, repo_root) = tokio::task::spawn_blocking(move || {
        let authorization = build_fresh_devnet_authorization(&repo_root, policy_pin.policy_bytes())?;
        Ok::<_, anyhow::Error>((authorization, policy_pin, repo_root))
    }).await.context("authorization builder worker failed")??;
    policy_pin.validate(&repo_root)?;
    let current_guardian = open_absolute_directory(&guardians_root)?;
    ensure!(same_file(&guardian, &current_guardian)?, "guardian root changed during authorization");
    check_database_bindings(&db_directory, &databases, true)?;
    publish_guardian_authorization_unchanged(&repo_root, &policy_pin, &authorization)?;
    phase("authorized")?;
    drop(databases);
    Ok(())
}

fn phase(value: &str) -> anyhow::Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{{\"phase\":\"{value}\"}}")?;
    stdout.flush()?;
    Ok(())
}

fn command(input: &mut impl BufRead, expected: &str) -> anyhow::Result<()> {
    let mut bytes = [0u8; 10];
    let count = expected.len() + 1;
    input.read_exact(&mut bytes[..count]).context("fresh-state protocol aborted before command")?;
    ensure!(&bytes[..expected.len()] == expected.as_bytes() && bytes[expected.len()] == b'\n', "unexpected fresh-state protocol command");
    Ok(())
}

fn absolute_path(path: &Path) -> anyhow::Result<PathBuf> {
    let path = if path.is_absolute() { path.to_owned() } else { std::env::current_dir()?.join(path) };
    ensure!(path.components().all(|part| matches!(part, Component::RootDir | Component::Normal(_))), "path must not contain dot or parent components");
    Ok(path)
}

fn open_at(parent: &File, name: &OsStr, flags: i32) -> anyhow::Result<Option<File>> {
    ensure!(!name.as_bytes().is_empty() && !name.as_bytes().contains(&b'/') && name != "." && name != "..", "invalid relative path component");
    let name = CString::new(name.as_bytes())?;
    let descriptor = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK, 0o600 as libc::mode_t) };
    if descriptor < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound { return Ok(None); }
        return Err(error).context("opening protected path component");
    }
    Ok(Some(unsafe { File::from_raw_fd(descriptor) }))
}

fn validate_directory(directory: &File, private: bool) -> anyhow::Result<()> {
    let metadata = directory.metadata()?;
    ensure!(metadata.is_dir() && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.mode() & (if private { 0o077 } else { 0o022 }) == 0, "directory is not trusted and owner-controlled");
    Ok(())
}

fn open_absolute_directory(path: &Path) -> anyhow::Result<File> {
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

fn open_directory_path(parent: &File, path: &Path) -> anyhow::Result<Option<File>> {
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

fn directory_names(directory: &File) -> anyhow::Result<Vec<OsString>> {
    // A separate open description avoids sharing readdir offsets with retained FDs.
    let dot = CString::new(".")?;
    let descriptor = unsafe { libc::openat(directory.as_raw_fd(), dot.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    ensure!(descriptor >= 0, "opening directory enumeration failed");
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

fn validate_entry(file: &File) -> anyhow::Result<()> {
    let metadata = file.metadata()?;
    ensure!(metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o022 == 0, "cleanup entry is not owner-controlled");
    ensure!(metadata.is_dir() || (metadata.is_file() && metadata.nlink() == 1), "cleanup entry must be a directory or unlinked regular file");
    Ok(())
}

fn validate_tree(file: &File, device: u64) -> anyhow::Result<()> {
    validate_entry(file)?;
    ensure!(file.metadata()?.dev() == device, "cleanup crosses filesystem boundary");
    if file.metadata()?.is_dir() {
        for name in directory_names(file)? {
            let child = open_at(file, &name, libc::O_RDONLY)?.context("cleanup entry disappeared during preflight")?;
            validate_tree(&child, device)?;
        }
    }
    Ok(())
}

fn validate_targets(repo: &File) -> anyhow::Result<()> {
    for target in TARGETS {
        let path = Path::new(target);
        let Some(parent) = open_directory_path(repo, path.parent().context("cleanup parent missing")?)? else { continue };
        if let Some(file) = open_at(&parent, path.file_name().context("cleanup name missing")?, libc::O_RDONLY)? {
            validate_tree(&file, repo.metadata()?.dev()).with_context(|| format!("preflighting {target}"))?;
            ensure!(file.metadata()?.is_dir() == (target != "genesis.json"), "wrong cleanup target type: {target}");
            if target == "local_checkpoints" {
                if let Some(binding) = open_at(&file, OsStr::new("devnet-namespace"), libc::O_RDONLY)? {
                    ensure!(binding.metadata()?.is_file(), "namespace binding must be a regular file");
                }
            }
        }
    }
    Ok(())
}

fn remove_target(repo: &File, path: &Path) -> anyhow::Result<()> {
    let Some(parent) = open_directory_path(repo, path.parent().context("cleanup parent missing")?)? else { return Ok(()) };
    ensure!(parent.metadata()?.dev() == repo.metadata()?.dev(), "cleanup parent crosses filesystem boundary");
    remove_entry(&parent, path.file_name().context("cleanup name missing")?, path == Path::new("local_checkpoints"))
}

fn remove_entry(parent: &File, name: &OsStr, retain_namespace: bool) -> anyhow::Result<()> {
    let Some(file) = open_at(parent, name, libc::O_RDONLY)? else { return Ok(()) };
    validate_entry(&file)?;
    ensure!(file.metadata()?.dev() == parent.metadata()?.dev(), "cleanup crosses filesystem boundary");
    let directory = file.metadata()?.is_dir();
    if directory {
        for child in directory_names(&file)? {
            if retain_namespace && child == "devnet-namespace" { continue; }
            remove_entry(&file, &child, false)?;
        }
        if retain_namespace { return Ok(()); }
    }
    let unlink_name = CString::new(name.as_bytes())?;
    let current = open_at(parent, name, libc::O_RDONLY)?.context("cleanup entry disappeared")?;
    ensure!(same_file(&file, &current)?, "cleanup entry changed during reset");
    let result = unsafe { libc::unlinkat(parent.as_raw_fd(), unlink_name.as_ptr(), if directory { libc::AT_REMOVEDIR } else { 0 }) };
    if result != 0 { return Err(io::Error::last_os_error()).context("removing fixed cleanup entry"); }
    Ok(())
}

fn validate_database_file(file: &File, existing: bool) -> anyhow::Result<()> {
    let metadata = file.metadata()?;
    ensure!(metadata.is_file() && metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o7777 == 0o600
        && metadata.nlink() == 1 && (!existing || metadata.len() > 0), "database must be a nonempty protected single-link regular file");
    Ok(())
}

fn same_file(left: &File, right: &File) -> anyhow::Result<bool> {
    let left = left.metadata()?;
    let right = right.metadata()?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

fn open_databases(directory: &File) -> anyhow::Result<Vec<HeldDatabase>> {
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
                // recovery is not permission to clear business tables before reset.
                let database = Database::builder().create_with_backend(backend)
                    .with_context(|| format!("opening existing redb database: {name}"))?;
                validate_database(&database, name == "relayer.redb").with_context(|| format!("validating database: {name}"))?;
                (Some(file), Some(database))
            }
            None => (None, None),
        };
        databases.push(HeldDatabase { name, file, database });
    }
    Ok(databases)
}

#[derive(Debug)]
struct GuardianDepositTreeKey([u8; 17]);
#[derive(Debug)]
struct GuardianWithdrawalBurnKey([u8; 56]);
#[derive(Debug)]
struct GuardianNonce([u8; 49]);
#[derive(Debug)]
struct RelayerDepositTreeKey([u8; 17]);
#[derive(Debug)]
struct RelayerWithdrawalBurnKey([u8; 56]);
#[derive(Debug)]
struct RelayerNonce([u8; 49]);

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
runtime_key!(GuardianNonce, 49, "guardian_common::NonceKey");
runtime_key!(RelayerDepositTreeKey, 17, "psy_relayer_cli::DepositTreeKey");
runtime_key!(RelayerWithdrawalBurnKey, 56, "psy_relayer_cli::WithdrawalBurnKey");
runtime_key!(RelayerNonce, 49, "psy_relayer_cli::NonceKey");

fn validate_database(database: &Database, relayer: bool) -> anyhow::Result<()> {
    let transaction = database.begin_read()?;
    ensure!(transaction.list_multimap_tables()?.next().is_none(), "unexpected multimap tables");
    let names: BTreeSet<_> = transaction.list_tables()?.map(|table| table.name().to_owned()).collect();
    let runtime_names: &[&str] = if relayer { &RELAYER_TABLES } else { &GUARDIAN_TABLES };
    let runtime: BTreeSet<_> = runtime_names.iter().map(|name| (*name).to_owned()).collect();
    ensure!(names.is_empty() || names == runtime, "unexpected database table shape");
    if names == runtime {
        if relayer {
            drop(transaction.open_table(TableDefinition::<u64, &[u8]>::new("relayer_request"))?);
            drop(transaction.open_table(TableDefinition::<u8, &[u8]>::new("chain_claims"))?);
            drop(transaction.open_table(TableDefinition::<(), &[u8]>::new("finalization_batch"))?);
            drop(transaction.open_table(TableDefinition::<(u64, u64), &[u8]>::new("guardian_account"))?);
            drop(transaction.open_table(TableDefinition::<RelayerDepositTreeKey, &[u8]>::new("deposit_tree_states"))?);
            drop(transaction.open_table(TableDefinition::<RelayerWithdrawalBurnKey, u64>::new("included_withdrawal_burns"))?);
            drop(transaction.open_table(TableDefinition::<RelayerNonce, u64>::new("guardian_withdrawal_nonce"))?);
        } else {
            drop(transaction.open_table(TableDefinition::<(), [u8; 33]>::new("guardian_signer"))?);
            drop(transaction.open_table(TableDefinition::<(u64, u64), &[u8]>::new("guardian_account"))?);
            drop(transaction.open_table(TableDefinition::<(u64, u64, u64), &[u8]>::new("guardian_signed"))?);
            drop(transaction.open_table(TableDefinition::<(u64, u64, u64), &[u8]>::new("guardian_session"))?);
            drop(transaction.open_table(TableDefinition::<GuardianDepositTreeKey, &[u8]>::new("deposit_tree_states"))?);
            drop(transaction.open_table(TableDefinition::<GuardianWithdrawalBurnKey, u64>::new("included_withdrawal_burns"))?);
            drop(transaction.open_table(TableDefinition::<GuardianNonce, u64>::new("guardian_withdrawal_nonce"))?);
        }
    }
    Ok(())
}


fn check_database_bindings(directory: &File, databases: &[HeldDatabase], require_all: bool) -> anyhow::Result<()> {
    for held in databases {
        ensure!(!require_all || held.database.is_some(), "database handle missing after reset: {}", held.name);
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

fn clear_database(database: &Database) -> anyhow::Result<()> {
    let transaction = database.begin_write()?;
    let tables: Vec<_> = transaction.list_tables()?.collect();
    for table in tables { transaction.delete_table(table)?; }
    transaction.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs::{self, OpenOptions}, os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink}, time::{SystemTime, UNIX_EPOCH}};
    use redb::ReadableTable;

    struct TestDirectory(PathBuf);
    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("fresh-devnet-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
        fn open(&self) -> File { File::open(&self.0).unwrap() }
        fn database_file(&self, name: &str) -> File {
            OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(self.0.join(name)).unwrap()
        }
        // create_dir and File::create request 0777/0666, then the process umask.
        // chmod the fixture; never umask(2), which is process-global and races parallel tests.
        fn dir(&self, relative: &str) -> PathBuf {
            let path = self.0.join(relative);
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            path
        }
        fn file(&self, relative: &str, body: &[u8]) {
            let mut created = OpenOptions::new().write(true).create_new(true).mode(0o600).open(self.0.join(relative)).unwrap();
            created.write_all(body).unwrap();
            created.set_permissions(fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    impl Drop for TestDirectory {
        fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); }
    }

    #[test]
    fn protocol_rejects_eof_and_unknown_commands() {
        assert!(command(&mut io::Cursor::new(b""), "reset").is_err());
        assert!(command(&mut io::Cursor::new(b"reset"), "reset").is_err());
        assert!(command(&mut io::Cursor::new(b"other\n"), "reset").is_err());
        let mut input = io::Cursor::new(b"reset\nauthorize\n");
        command(&mut input, "reset").unwrap();
        command(&mut input, "authorize").unwrap();
    }

    #[test]
    fn cleanup_preflight_rejects_symlinks_without_partial_removal() {
        let directory = TestDirectory::new();
        fs::write(directory.0.join("genesis.json"), b"retained").unwrap();
        fs::create_dir(directory.0.join("db")).unwrap();
        symlink("/", directory.0.join("db/anvil")).unwrap();
        assert!(validate_targets(&directory.open()).is_err());
        assert_eq!(fs::read(directory.0.join("genesis.json")).unwrap(), b"retained");
        assert!(open_directory_path(&directory.open(), Path::new("db/anvil/outside")).is_err());
        assert!(absolute_path(Path::new("../outside")).is_err());
    }

    #[test]
    fn reset_retains_namespace_binding_in_place() {
        let directory = TestDirectory::new();
        let checkpoints = directory.dir("local_checkpoints");
        directory.file("local_checkpoints/devnet-namespace", b"binding");
        directory.dir("local_checkpoints/checkpoint-1");
        directory.file("local_checkpoints/checkpoint-1/state", b"state");
        let inode = fs::metadata(checkpoints.join("devnet-namespace")).unwrap().ino();
        validate_targets(&directory.open()).unwrap();
        remove_target(&directory.open(), Path::new("local_checkpoints")).unwrap();
        assert_eq!(fs::read(checkpoints.join("devnet-namespace")).unwrap(), b"binding");
        assert_eq!(fs::metadata(checkpoints.join("devnet-namespace")).unwrap().ino(), inode);
        assert!(!checkpoints.join("checkpoint-1").exists());
    }

    #[test]
    fn actual_redb_owner_is_rejected_before_any_business_table_changes() {
        let directory = TestDirectory::new();
        let database = Database::builder().create_file(directory.database_file(DATABASES[0])).unwrap();
        assert!(open_databases(&directory.open()).is_err());
        assert!(database.begin_read().unwrap().list_tables().unwrap().next().is_none());
        assert!(!directory.0.join(DATABASES[1]).exists());
        drop(database);
    }

    #[test]
    fn malformed_later_database_does_not_clear_earlier_database() {
        let directory = TestDirectory::new();
        let database = Database::builder().create_file(directory.database_file(DATABASES[0])).unwrap();
        let marker = TableDefinition::<u64, u64>::new("marker");
        let transaction = database.begin_write().unwrap();
        transaction.open_table(marker).unwrap().insert(1, 7).unwrap();
        transaction.commit().unwrap();
        drop(database);
        let _malformed = directory.database_file(DATABASES[1]);
        assert!(open_databases(&directory.open()).is_err());
        let database = Database::open(directory.0.join(DATABASES[0])).unwrap();
        assert_eq!(database.begin_read().unwrap().open_table(marker).unwrap().get(1).unwrap().unwrap().value(), 7);
        assert!(fs::read(directory.0.join(DATABASES[1])).unwrap().is_empty());
        drop(database);
    }

    #[test]
    fn repeated_in_place_reset_retains_inode_and_exclusivity() {
        let directory = TestDirectory::new();
        let database = Database::builder().create_file(directory.database_file(DATABASES[0])).unwrap();
        let inode = fs::metadata(directory.0.join(DATABASES[0])).unwrap().ino();
        for _ in 0..2 {
            let transaction = database.begin_write().unwrap();
            transaction.open_table(TableDefinition::<u64, u64>::new("marker")).unwrap().insert(1, 7).unwrap();
            transaction.commit().unwrap();
            clear_database(&database).unwrap();
            assert!(database.begin_read().unwrap().list_tables().unwrap().next().is_none());
            assert!(Database::open(directory.0.join(DATABASES[0])).is_err());
            assert_eq!(fs::metadata(directory.0.join(DATABASES[0])).unwrap().ino(), inode);
        }
        drop(database);
    }

    #[test]
    fn cleanup_rejects_a_different_device_before_removal() {
        let directory = TestDirectory::new();
        fs::write(directory.0.join("retained"), b"retained").unwrap();
        let root = directory.open();
        assert!(validate_tree(&root, root.metadata().unwrap().dev().wrapping_add(1)).is_err());
        assert_eq!(fs::read(directory.0.join("retained")).unwrap(), b"retained");
    }

    #[test]
    fn post_reset_requires_every_database_handle() {
        let directory = TestDirectory::new();
        let missing = [HeldDatabase { name: DATABASES[0], file: None, database: None }];
        assert!(check_database_bindings(&directory.open(), &missing, false).is_ok());
        assert!(check_database_bindings(&directory.open(), &missing, true).is_err());
    }


    #[test]
    fn reset_commit_remains_when_later_cleanup_is_rejected() {
        let directory = TestDirectory::new();
        let database = Database::builder().create_file(directory.database_file(DATABASES[0])).unwrap();
        let transaction = database.begin_write().unwrap();
        transaction.open_table(TableDefinition::<u64, u64>::new("marker")).unwrap().insert(1, 7).unwrap();
        transaction.commit().unwrap();
        clear_database(&database).unwrap();
        symlink("/", directory.0.join("genesis.json")).unwrap();
        assert!(remove_target(&directory.open(), Path::new("genesis.json")).is_err());
        assert!(database.begin_read().unwrap().list_tables().unwrap().next().is_none());
        drop(database);
    }

    fn open_complete(database: &Database, relayer: bool) {
        let transaction = database.begin_write().unwrap();
        if relayer {
            transaction.open_table(TableDefinition::<u64, &[u8]>::new("relayer_request")).unwrap();
            transaction.open_table(TableDefinition::<u8, &[u8]>::new("chain_claims")).unwrap().insert(9, br#"{"claim_retry":{},"pending_claim_withdrawals":{},"retired_claim_withdrawals":{}}"#.as_slice()).unwrap();
            transaction.open_table(TableDefinition::<(), &[u8]>::new("finalization_batch")).unwrap().insert((), br#"{"finalized_chains":[],"pending_finalization_range":null}"#.as_slice()).unwrap();
            transaction.open_table(TableDefinition::<(u64, u64), &[u8]>::new("guardian_account")).unwrap();
            transaction.open_table(TableDefinition::<RelayerDepositTreeKey, &[u8]>::new("deposit_tree_states")).unwrap();
            transaction.open_table(TableDefinition::<RelayerWithdrawalBurnKey, u64>::new("included_withdrawal_burns")).unwrap();
            transaction.open_table(TableDefinition::<RelayerNonce, u64>::new("guardian_withdrawal_nonce")).unwrap();
        } else {
            transaction.open_table(TableDefinition::<(), [u8; 33]>::new("guardian_signer")).unwrap().insert((), &[2u8; 33]).unwrap();
            transaction.open_table(TableDefinition::<(u64, u64), &[u8]>::new("guardian_account")).unwrap();
            transaction.open_table(TableDefinition::<(u64, u64, u64), &[u8]>::new("guardian_signed")).unwrap();
            transaction.open_table(TableDefinition::<(u64, u64, u64), &[u8]>::new("guardian_session")).unwrap();
            transaction.open_table(TableDefinition::<GuardianDepositTreeKey, &[u8]>::new("deposit_tree_states")).unwrap();
            transaction.open_table(TableDefinition::<GuardianWithdrawalBurnKey, u64>::new("included_withdrawal_burns")).unwrap();
            transaction.open_table(TableDefinition::<GuardianNonce, u64>::new("guardian_withdrawal_nonce")).unwrap();
        }
        transaction.commit().unwrap();
    }

    #[test]
    fn nonmagic_later_database_preserves_valid_runtime_rows() {
        let directory = TestDirectory::new();
        let database = Database::builder().create_file(directory.database_file(DATABASES[0])).unwrap();
        open_complete(&database, false);
        drop(database);
        let mut malformed = directory.database_file(DATABASES[1]);
        malformed.write_all(b"nonmagic retained bytes").unwrap();
        assert!(open_databases(&directory.open()).is_err());
        assert_eq!(fs::read(directory.0.join(DATABASES[1])).unwrap(), b"nonmagic retained bytes");
        let database = Database::open(directory.0.join(DATABASES[0])).unwrap();
        assert_eq!(database.begin_read().unwrap().open_table(TableDefinition::<(), [u8; 33]>::new("guardian_signer")).unwrap().get(()).unwrap().unwrap().value(), [2u8; 33]);
        drop(database);
    }

    #[test]
    fn complete_zero_or_exact_sets_pass_and_old_sets_fail() {
        let directory = TestDirectory::new();
        let guardian = Database::builder().create_file(directory.database_file("guardian.redb")).unwrap();
        let relayer = Database::builder().create_file(directory.database_file("relayer.redb")).unwrap();
        validate_database(&guardian, false).unwrap();
        validate_database(&relayer, true).unwrap();
        open_complete(&guardian, false);
        open_complete(&relayer, true);
        validate_database(&guardian, false).unwrap();
        validate_database(&relayer, true).unwrap();
        assert!(validate_database(&guardian, true).is_err());
        let old = Database::builder().create_file(directory.database_file("old.redb")).unwrap();
        let transaction = old.begin_write().unwrap();
        transaction.open_table(TableDefinition::<(), [u8; 33]>::new("guardian_signer")).unwrap();
        transaction.open_table(TableDefinition::<(u64, u64), &[u8]>::new("guardian_account")).unwrap();
        transaction.open_table(TableDefinition::<(u64, u64, u64), &[u8]>::new("guardian_signed")).unwrap();
        transaction.open_table(TableDefinition::<(u64, u64, u64), &[u8]>::new("guardian_session")).unwrap();
        transaction.commit().unwrap();
        assert!(validate_database(&old, false).is_err());
        let transaction = old.begin_write().unwrap();
        for table in transaction.list_tables().unwrap() { transaction.delete_table(table).unwrap(); }
        transaction.open_table(TableDefinition::<(), [u8; 33]>::new("guardian_signer")).unwrap();
        transaction.open_table(TableDefinition::<(u64, u64), &[u8]>::new("guardian_account")).unwrap();
        transaction.open_table(TableDefinition::<(u64, u64, u64), &[u8]>::new("guardian_signed")).unwrap();
        transaction.open_table(TableDefinition::<(u64, u64, u64), &[u8]>::new("guardian_session")).unwrap();
        transaction.open_table(TableDefinition::<[u8; 17], &[u8]>::new("deposit_tree_states")).unwrap();
        transaction.open_table(TableDefinition::<[u8; 56], u64>::new("included_withdrawal_burns")).unwrap();
        transaction.open_table(TableDefinition::<[u8; 49], u64>::new("guardian_withdrawal_nonce")).unwrap();
        transaction.commit().unwrap();
        assert!(validate_database(&old, false).is_err());
        let transaction = old.begin_write().unwrap();
        transaction.delete_table(transaction.list_tables().unwrap().next().unwrap()).unwrap();
        transaction.commit().unwrap();
        clear_database(&old).unwrap();
        assert!(old.begin_read().unwrap().list_tables().unwrap().next().is_none());
        drop((guardian, relayer, old));
    }

    #[test]
    fn open_databases_verifies_complete_sets_and_rejects_old_shape_before_mutation() {
        let directory = TestDirectory::new();
        let guardian_1 = Database::builder().create_file(directory.database_file(DATABASES[0])).unwrap();
        open_complete(&guardian_1, false);
        drop(guardian_1);
        let guardian_2 = Database::builder().create_file(directory.database_file(DATABASES[1])).unwrap();
        open_complete(&guardian_2, false);
        drop(guardian_2);
        let guardian_3 = Database::builder().create_file(directory.database_file(DATABASES[2])).unwrap();
        open_complete(&guardian_3, false);
        drop(guardian_3);
        let relayer = Database::builder().create_file(directory.database_file(DATABASES[3])).unwrap();
        open_complete(&relayer, true);
        drop(relayer);
        let held = open_databases(&directory.open()).unwrap();
        assert_eq!(held.len(), 4);
        drop(held);
        let held = open_databases(&directory.open()).unwrap();
        assert_eq!(held.len(), 4);
        drop(held);
        std::fs::remove_file(directory.0.join(DATABASES[2])).unwrap();
        let old = Database::builder().create_file(directory.database_file(DATABASES[2])).unwrap();
        let transaction = old.begin_write().unwrap();
        transaction.open_table(TableDefinition::<(), [u8; 33]>::new("guardian_signer")).unwrap().insert((), &[5u8; 33]).unwrap();
        transaction.open_table(TableDefinition::<(u64, u64), &[u8]>::new("guardian_account")).unwrap();
        transaction.open_table(TableDefinition::<(u64, u64, u64), &[u8]>::new("guardian_signed")).unwrap();
        transaction.open_table(TableDefinition::<(u64, u64, u64), &[u8]>::new("guardian_session")).unwrap();
        transaction.commit().unwrap();
        drop(old);
        assert!(open_databases(&directory.open()).is_err());
        let old = Database::open(directory.0.join(DATABASES[2])).unwrap();
        let read = old.begin_read().unwrap();
        assert_eq!(read.list_tables().unwrap().count(), 4);
        assert_eq!(read.open_table(TableDefinition::<(), [u8; 33]>::new("guardian_signer")).unwrap().get(()).unwrap().unwrap().value(), [5u8; 33]);
        drop(read);
        drop(old);
    }

    #[test]
    fn unclean_exit_recovers_zero_and_runtime_tables_without_reset() {
        const FIXTURE_DIRECTORY: &str = "PSY_FRESH_STATE_CRASH_FIXTURE_DIRECTORY";
        const UNCLEAN_EXIT: i32 = 73;
        if let Some(path) = std::env::var_os(FIXTURE_DIRECTORY) {
            let directory = TestDirectory(PathBuf::from(path));
            let mut databases = Vec::new();
            for (index, name) in DATABASES.iter().enumerate() {
                let database = Database::builder().create_file(directory.database_file(name)).unwrap();
                if index != 0 {
                    open_complete(&database, index == 3);
                    seed_runtime_row(&database, index == 3, index as u8 + 1);
                }
                databases.push(database);
            }
            // Exit with live engines: no Database::drop, just as with a helper
            // terminated before its reset/authorize handshake finishes. The OS
            // releases locks; the parent owns fixture cleanup. No header spoofing.
            std::process::exit(UNCLEAN_EXIT);
        }

        let directory = TestDirectory::new();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", std::thread::current().name().unwrap()])
            .env(FIXTURE_DIRECTORY, &directory.0)
            .status().unwrap();
        assert_eq!(status.code(), Some(UNCLEAN_EXIT));
        // Prove this fixture requires actual engine recovery, rather than merely
        // reopening a clean database and claiming crash-recovery coverage.
        let mut builder = Database::builder();
        builder.set_repair_callback(|repair| repair.abort());
        assert!(matches!(builder.open(directory.0.join(DATABASES[0])), Err(redb::DatabaseError::RepairAborted)));

        let inodes: Vec<_> = DATABASES.iter().map(|name| fs::metadata(directory.0.join(name)).unwrap().ino()).collect();
        let held = open_databases(&directory.open()).unwrap();
        for (index, item) in held.iter().enumerate() {
            let database = item.database.as_ref().unwrap();
            assert_eq!(database.begin_read().unwrap().list_tables().unwrap().count(), match index { 0 => 0, _ => 7 });
            if index != 0 {
                assert_eq!(runtime_row(database, index == 3), if index == 3 { vec![4] } else { vec![index as u8 + 1; 33] });
            }
            assert_eq!(fs::metadata(directory.0.join(item.name)).unwrap().ino(), inodes[index]);
            assert!(Database::open(directory.0.join(item.name)).is_err());
        }
        drop(held);
        // Recovery leaves a database that can also be reopened normally.
        drop(open_databases(&directory.open()).unwrap());
    }

    fn seed_runtime_row(database: &Database, relayer: bool, marker: u8) {
        let transaction = database.begin_write().unwrap();
        if relayer {
            transaction.open_table(TableDefinition::<u64, &[u8]>::new("relayer_request")).unwrap().insert(1, &[marker][..]).unwrap();
        } else {
            transaction.open_table(TableDefinition::<(), [u8; 33]>::new("guardian_signer")).unwrap().insert((), &[marker; 33]).unwrap();
        }
        transaction.commit().unwrap();
    }

    fn runtime_row(database: &Database, relayer: bool) -> Vec<u8> {
        let read = database.begin_read().unwrap();
        if relayer {
            read.open_table(TableDefinition::<u64, &[u8]>::new("relayer_request")).unwrap().get(1).unwrap().unwrap().value().to_vec()
        } else {
            read.open_table(TableDefinition::<(), [u8; 33]>::new("guardian_signer")).unwrap().get(()).unwrap().unwrap().value().to_vec()
        }
    }

    fn open_old_shape(file: File, relayer: bool) {
        let database = Database::builder().create_file(file).unwrap();
        let transaction = database.begin_write().unwrap();
        if relayer {
            transaction.open_table(TableDefinition::<u64, &[u8]>::new("relayer_request")).unwrap().insert(1, &[9u8][..]).unwrap();
            transaction.open_table(TableDefinition::<(u64, u64), &[u8]>::new("guardian_account")).unwrap().insert((9, 9), &[9u8][..]).unwrap();
            transaction.open_table(TableDefinition::<RelayerDepositTreeKey, &[u8]>::new("deposit_tree_states")).unwrap().insert(RelayerDepositTreeKey([9; 17]), &[9u8][..]).unwrap();
            transaction.open_table(TableDefinition::<RelayerWithdrawalBurnKey, u64>::new("included_withdrawal_burns")).unwrap().insert(RelayerWithdrawalBurnKey([9; 56]), 9).unwrap();
            transaction.open_table(TableDefinition::<RelayerNonce, u64>::new("guardian_withdrawal_nonce")).unwrap().insert(RelayerNonce([9; 49]), 9).unwrap();
        } else {
            transaction.open_table(TableDefinition::<(), [u8; 33]>::new("guardian_signer")).unwrap().insert((), &[9u8; 33]).unwrap();
            transaction.open_table(TableDefinition::<(u64, u64), &[u8]>::new("guardian_account")).unwrap();
            transaction.open_table(TableDefinition::<(u64, u64, u64), &[u8]>::new("guardian_signed")).unwrap();
            transaction.open_table(TableDefinition::<(u64, u64, u64), &[u8]>::new("guardian_session")).unwrap();
            transaction.open_table(TableDefinition::<[u8; 17], &[u8]>::new("deposit_tree_states")).unwrap();
            transaction.open_table(TableDefinition::<[u8; 56], u64>::new("included_withdrawal_burns")).unwrap();
            transaction.open_table(TableDefinition::<[u8; 49], u64>::new("guardian_withdrawal_nonce")).unwrap();
        }
        transaction.commit().unwrap();
    }

    /// Four real redb files, held exclusively: a second open fails, a failed later
    /// file leaves every earlier business row untouched, and EOF never reaches clear.
    #[test]
    fn four_real_databases_fail_closed_without_clearing_rows() {
        let directory = TestDirectory::new();
        let mut opened = Vec::new();
        for (index, name) in DATABASES.iter().enumerate() {
            let database = Database::builder().create_file(directory.database_file(name)).unwrap();
            open_complete(&database, index == 3);
            seed_runtime_row(&database, index == 3, index as u8 + 1);
            opened.push(database);
        }
        drop(opened);
        let unrelated = directory.0.join("unrelated.txt");
        fs::write(&unrelated, b"kept").unwrap();
        let checkpoints = directory.0.join("local_checkpoints");
        fs::create_dir(&checkpoints).unwrap();
        fs::write(checkpoints.join("devnet-namespace"), b"binding").unwrap();
        let binding_inode = fs::metadata(checkpoints.join("devnet-namespace")).unwrap().ino();

        let held = open_databases(&directory.open()).unwrap();
        assert!(DATABASES.iter().all(|name| Database::open(directory.0.join(name)).is_err()));
        assert!(command(&mut io::Cursor::new(b""), "reset").is_err());
        for (index, name) in DATABASES.iter().enumerate() {
            let database = held.iter().find(|item| item.name == *name).unwrap().database.as_ref().unwrap();
            assert_eq!(runtime_row(database, index == 3), if index == 3 { vec![4] } else { vec![index as u8 + 1; 33] });
            assert_eq!(database.begin_read().unwrap().list_tables().unwrap().count(), 7);
        }
        drop(held);

        fs::remove_file(directory.0.join(DATABASES[2])).unwrap();
        open_old_shape(directory.database_file(DATABASES[2]), false);
        assert!(open_databases(&directory.open()).is_err());
        for index in [0, 1, 3] {
            let database = Database::open(directory.0.join(DATABASES[index])).unwrap();
            assert_eq!(runtime_row(&database, index == 3), if index == 3 { vec![4] } else { vec![index as u8 + 1; 33] });
            assert_eq!(database.begin_read().unwrap().list_tables().unwrap().count(), 7);
        }
        let old = Database::open(directory.0.join(DATABASES[2])).unwrap();
        assert_eq!(runtime_row(&old, false), vec![9; 33]);
        assert_eq!(old.begin_read().unwrap().list_tables().unwrap().count(), 7);
        drop(old);
        fs::remove_file(directory.0.join(DATABASES[2])).unwrap();
        let guardian = Database::builder().create_file(directory.database_file(DATABASES[2])).unwrap();
        open_complete(&guardian, false);
        seed_runtime_row(&guardian, false, 3);
        drop(guardian);

        fs::remove_file(directory.0.join(DATABASES[3])).unwrap();
        open_old_shape(directory.database_file(DATABASES[3]), true);
        assert!(open_databases(&directory.open()).is_err());
        for index in 0..3 {
            let database = Database::open(directory.0.join(DATABASES[index])).unwrap();
            assert_eq!(runtime_row(&database, false), vec![index as u8 + 1; 33]);
            assert_eq!(database.begin_read().unwrap().list_tables().unwrap().count(), 7);
        }
        let relayer = Database::open(directory.0.join(DATABASES[3])).unwrap();
        assert_eq!(runtime_row(&relayer, true), vec![9]);
        assert_eq!(relayer.begin_read().unwrap().list_tables().unwrap().count(), 5);
        drop(relayer);

        fs::remove_file(directory.0.join(DATABASES[3])).unwrap();
        let relayer = Database::builder().create_file(directory.database_file(DATABASES[3])).unwrap();
        open_complete(&relayer, true);
        seed_runtime_row(&relayer, true, 4);
        drop(relayer);
        // All four files are now the valid runtime shape: capture the inodes that the
        // repeated in-place reset below must preserve (the tampered files above had
        // their own, now-stale identities).
        let inodes: Vec<_> = DATABASES.iter().map(|name| fs::metadata(directory.0.join(name)).unwrap().ino()).collect();
        let mut held = open_databases(&directory.open()).unwrap();
        for _ in 0..2 {
            for held_database in &held { clear_database(held_database.database.as_ref().unwrap()).unwrap(); }
            for (index, name) in DATABASES.iter().enumerate() {
                assert!(held[index].database.as_ref().unwrap().begin_read().unwrap().list_tables().unwrap().next().is_none());
                assert_eq!(fs::metadata(directory.0.join(name)).unwrap().ino(), inodes[index]);
                assert!(Database::open(directory.0.join(name)).is_err());
            }
            assert_eq!(fs::read(&unrelated).unwrap(), b"kept");
            assert_eq!(fs::metadata(checkpoints.join("devnet-namespace")).unwrap().ino(), binding_inode);
        }
        for database in &mut held { database.database = None; }
        assert!(check_database_bindings(&directory.open(), &held, true).is_err());
        for name in DATABASES {
            let database = Database::open(directory.0.join(name)).unwrap();
            assert!(database.begin_read().unwrap().list_tables().unwrap().next().is_none());
        }
    }

}
