//! Read-only, hash-pinned import of private keys and public Genesis accounts.

use std::{
    collections::HashSet,
    ffi::CString,
    fs::{File, Metadata},
    io::Read,
    os::unix::{ffi::OsStrExt, fs::MetadataExt, io::{AsRawFd, FromRawFd}},
    path::{Component, Path},
    str::FromStr,
};

use anyhow::{anyhow, ensure, Context, Result};
use parth_core::pgoldilocks::QHashOut;
use plonky2::field::{goldilocks_field::GoldilocksField, types::Field64};
use psy_data::{
    genesis::genesis_block_setup::GenesisValidator,
    user::complete_user_record::PsyCompactUserDefinition,
};
use sha2::{Digest, Sha256};

use super::Hash;

#[derive(Clone, Copy)]
enum AccountInput {
    PrivateKeys,
    GenesisAccounts,
}

/// Reads only the public identity inputs; contracts and all other fields are
/// skipped by serde, not decoded through the current Genesis contract schema.
/// The caller owns registration, validator membership and identity comparison.
pub(super) fn read_genesis_accounts(
    path: &Path,
    expected_sha256: &str,
) -> Result<(Vec<PsyCompactUserDefinition<Hash>>, Vec<GenesisValidator>)> {
    #[derive(serde::Deserialize)]
    struct GenesisAccounts {
        users: Vec<PsyCompactUserDefinition<Hash>>,
        validators: Vec<GenesisValidator>,
    }
    let bytes = read_pinned_bytes(path, expected_sha256, AccountInput::GenesisAccounts)?;
    let accounts: GenesisAccounts = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow!("Genesis accounts JSON is invalid"))?;
    Ok((accounts.users, accounts.validators))
}

/// Imports existing keys without generating keys or writing any file. The hash
/// pins the exact JSON bytes, including whitespace. Only the selected multisig
/// registration may be null. All errors deliberately omit input values.
pub(super) fn read_private_keys(
    path: &Path,
    expected_sha256: &str,
    registration_count: usize,
    multisig_registration: usize,
) -> Result<Vec<Option<QHashOut<GoldilocksField>>>> {
    ensure!(registration_count > 0 && multisig_registration < registration_count,
        "private keys registration bounds are invalid");
    let bytes = read_pinned_bytes(path, expected_sha256, AccountInput::PrivateKeys)?;
    let entries: Vec<Option<String>> = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow!("private keys JSON is invalid"))?;
    ensure!(entries.len() == registration_count, "private keys registration count mismatch");
    let mut seen = HashSet::with_capacity(entries.len());
    entries.into_iter().enumerate().map(|(registration, entry)| {
        if registration == multisig_registration {
            ensure!(entry.is_none(), "private keys multisig registration must be null");
            return Ok(None);
        }
        let encoded = entry.context("private keys non-multisig registration must contain a key")?;
        let key = read_private_key(&encoded)?;
        ensure!(key != QHashOut::ZERO, "private keys must be nonzero");
        ensure!(seen.insert(key), "private keys must be distinct");
        Ok(Some(key))
    }).collect()
}

fn read_pinned_bytes(path: &Path, expected_sha256: &str, input: AccountInput) -> Result<Vec<u8>> {
    ensure!(expected_sha256.len() == 64 && expected_sha256.bytes().all(|byte| {
        byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
    }), "account input SHA-256 must be 64 lowercase hexadecimal characters");
    let directory = open_accounts_parent(path, input)?;
    let name = CString::new(path.file_name().context("account input path has no name")?.as_bytes())
        .map_err(|_| anyhow!("account input filename is invalid"))?;
    let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
    // SAFETY: the directory descriptor and NUL-terminated name remain valid;
    // openat never creates or writes. NONBLOCK avoids blocking on a FIFO.
    let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, 0) };
    ensure!(fd >= 0, "account input file cannot be opened read-only without following links");
    // SAFETY: openat returned a new owned descriptor, transferred exactly once.
    let mut file = unsafe { File::from_raw_fd(fd) };
    // SAFETY: geteuid has no arguments, side effects, or failure mode.
    let uid = unsafe { libc::geteuid() };
    let before = verify_accounts_file(&file, uid, input)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|_| anyhow!("account input file read failed"))?;
    let after = verify_accounts_file(&file, uid, input)?;
    ensure!(before.len() == after.len() && after.len() == bytes.len() as u64
        && before.mtime() == after.mtime() && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime() && before.ctime_nsec() == after.ctime_nsec(),
        "account input file changed while reading");
    ensure!(hex::encode(Sha256::digest(&bytes)) == expected_sha256,
        "account input SHA-256 mismatch");
    Ok(bytes)
}

fn read_private_key(encoded: &str) -> Result<QHashOut<GoldilocksField>> {
    ensure!(encoded.len() == 64, "private key must encode exactly 32 bytes");
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(encoded, &mut bytes)
        .map_err(|_| anyhow!("private key hexadecimal encoding is invalid"))?;
    // QHashOut JSON reverses the full little-endian byte array. Check each
    // big-endian limb before its decoder can reduce or assert on field values.
    for limb in bytes.chunks_exact(8) {
        let limb = u64::from_be_bytes(limb.try_into().map_err(|_| anyhow!("private key limb length is invalid"))?);
        ensure!(limb < GoldilocksField::ORDER, "private key field element is not canonical");
    }
    QHashOut::from_str(encoded).map_err(|_| anyhow!("private key encoding is invalid"))
}

fn verify_accounts_file(file: &File, uid: u32, input: AccountInput) -> Result<Metadata> {
    let metadata = file.metadata().map_err(|_| anyhow!("account input file metadata is unavailable"))?;
    ensure!(metadata.is_file() && metadata.nlink() == 1 && metadata.uid() == uid,
        "account input file must be a single-link effective-uid regular file");
    let mode = metadata.mode() & 0o7777;
    match input {
        AccountInput::PrivateKeys => ensure!(mode == 0o600, "private keys file must be mode 0600"),
        AccountInput::GenesisAccounts => ensure!(mode == 0o600 || mode == 0o644,
            "public Genesis accounts file must be mode 0600 or 0644"),
    }
    Ok(metadata)
}

fn verify_accounts_directory(directory: &File, uid: u32, immediate: bool, input: AccountInput) -> Result<()> {
    let metadata = directory.metadata()
        .map_err(|_| anyhow!("account input directory metadata is unavailable"))?;
    ensure!(metadata.is_dir() && [0, uid].contains(&metadata.uid()) && metadata.mode() & 0o022 == 0,
        "account input ancestor must be root or effective-uid owned and not group/world writable");
    if immediate {
        ensure!(metadata.uid() == uid, "account input parent must be effective-uid owned");
        if let AccountInput::PrivateKeys = input {
            ensure!(metadata.mode() & 0o7777 == 0o700, "private keys parent must be mode 0700");
        }
    }
    Ok(())
}

fn open_accounts_parent(path: &Path, input: AccountInput) -> Result<File> {
    ensure!(path.file_name().is_some(), "account input path has no name");
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_err(|_| anyhow!("account input working directory is unavailable"))?.join(path)
    };
    let parent = absolute.parent().context("account input path has no parent")?;
    // SAFETY: geteuid has no arguments, side effects, or failure mode.
    let uid = unsafe { libc::geteuid() };
    let mut directory = File::open(Path::new("/")).context("opening account input filesystem root")?;
    verify_accounts_directory(&directory, uid, false, input)?;
    for component in parent.components() {
        let name = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => name,
            _ => anyhow::bail!("account input path must not contain parent traversal"),
        };
        directory = super::open_nofollow_directory_at(&directory, name)
            .map_err(|_| anyhow!("account input ancestor cannot be opened without following links"))?
            .context("account input ancestor does not exist")?;
        verify_accounts_directory(&directory, uid, false, input)?;
    }
    verify_accounts_directory(&directory, uid, true, input)?;
    Ok(directory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::{self, DirBuilder, OpenOptions},
        io::Write,
        os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt, symlink},
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        directory: PathBuf,
        path: PathBuf,
        bytes: Vec<u8>,
        digest: String,
    }

    impl Fixture {
        fn new(bytes: Vec<u8>) -> Self {
            let directory = std::env::current_dir().unwrap().join(format!(
                ".accounts-test-{}-{}", std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            DirBuilder::new().mode(0o700).create(&directory).unwrap();
            let path = directory.join("private_keys.json");
            let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600)
                .open(&path).unwrap();
            file.write_all(&bytes).unwrap();
            let digest = hex::encode(Sha256::digest(&bytes));
            Self { directory, path, bytes, digest }
        }

        fn valid() -> Self {
            Self::new(serde_json::to_vec(&keys()).unwrap())
        }

        fn read(&self) -> Result<Vec<Option<QHashOut<GoldilocksField>>>> {
            read_private_keys(&self.path, &self.digest, 5, 2)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    fn keys() -> Vec<Option<QHashOut<GoldilocksField>>> {
        (0..5).map(|slot| {
            (slot != 2).then(|| QHashOut::from_values(slot + 1, 2, 3, 4))
        }).collect()
    }

    #[test]
    fn imports_existing_json_without_changing_bytes_or_metadata() {
        let fixture = Fixture::valid();
        let before = fs::metadata(&fixture.path).unwrap();
        assert!(fixture.read().unwrap() == keys());
        assert!(fixture.read().unwrap() == keys());
        assert!(fs::read(&fixture.path).unwrap() == fixture.bytes);
        let after = fs::metadata(&fixture.path).unwrap();
        assert_eq!((before.ino(), before.mode(), before.uid(), before.len()),
            (after.ino(), after.mode(), after.uid(), after.len()));
        assert_eq!((before.mtime(), before.mtime_nsec()), (after.mtime(), after.mtime_nsec()));
    }

    #[test]
    fn accepts_parameterized_multisig_registration() {
        let entries = vec![None, Some(QHashOut::<GoldilocksField>::from_values(1, 2, 3, 4))];
        let fixture = Fixture::new(serde_json::to_vec(&entries).unwrap());
        assert!(read_private_keys(&fixture.path, &fixture.digest, 2, 0).unwrap() == entries);
    }

    #[test]
    fn rejects_wrong_or_noncanonical_digest() {
        let fixture = Fixture::valid();
        for digest in ["0".repeat(64), "a".repeat(63), "g".repeat(64), "A".repeat(64)] {
            assert!(read_private_keys(&fixture.path, &digest, 5, 2).is_err());
        }
    }

    #[test]
    fn rejects_changed_bytes_before_json_decode() {
        let fixture = Fixture::valid();
        fs::write(&fixture.path, b"not json").unwrap();
        assert_eq!(fixture.read().unwrap_err().to_string(), "account input SHA-256 mismatch");
    }

    #[test]
    fn rejects_wrong_count_or_multisig_index() {
        let fixture = Fixture::valid();
        for (count, multisig) in [(0, 0), (4, 2), (6, 2), (5, 5), (5, 1)] {
            assert!(read_private_keys(&fixture.path, &fixture.digest, count, multisig).is_err());
        }
    }

    #[test]
    fn rejects_missing_keys_and_a_key_in_multisig_slot() {
        for slot in [0, 1, 3, 4] {
            let mut entries = keys();
            entries[slot] = None;
            assert!(Fixture::new(serde_json::to_vec(&entries).unwrap()).read().is_err());
        }
        let mut entries = keys();
        entries[2] = Some(QHashOut::from_values(90, 0, 0, 0));
        assert!(Fixture::new(serde_json::to_vec(&entries).unwrap()).read().is_err());
    }

    #[test]
    fn rejects_zero_and_duplicate_keys() {
        for replacement in [QHashOut::ZERO, keys()[0].unwrap()] {
            let mut entries = keys();
            entries[1] = Some(replacement);
            assert!(Fixture::new(serde_json::to_vec(&entries).unwrap()).read().is_err());
        }
    }

    #[test]
    fn rejects_invalid_encoding_and_noncanonical_limbs_without_panicking() {
        let mut invalid = vec![String::new(), "ab".repeat(31), "ab".repeat(33), "z".repeat(64)];
        for limb in 0..4 {
            let mut bytes = [0u8; 32];
            bytes[limb * 8..limb * 8 + 8].copy_from_slice(&GoldilocksField::ORDER.to_be_bytes());
            invalid.push(hex::encode(bytes));
        }
        for encoded in invalid {
            let mut entries = serde_json::to_value(keys()).unwrap();
            entries[0] = serde_json::Value::String(encoded);
            assert!(Fixture::new(serde_json::to_vec(&entries).unwrap()).read().is_err());
        }
    }

    #[test]
    fn json_errors_do_not_retain_input_or_serde_error_chain() {
        for bytes in [
            br#"["synthetic-secret-sentinel", 42]"#.to_vec(),
            br#"{"synthetic-secret-sentinel":true}"#.to_vec(),
            br#"["synthetic-secret-sentinel""#.to_vec(),
        ] {
            let error = Fixture::new(bytes).read().unwrap_err();
            assert_eq!(format!("{error:#}"), "private keys JSON is invalid");
            assert!(!format!("{error:?}").contains("synthetic-secret-sentinel"));
            assert_eq!(error.chain().count(), 1);
        }
    }

    #[test]
    fn rejects_file_permissions_hardlinks_and_symlinks() {
        let fixture = Fixture::valid();
        for mode in [0o400, 0o640, 0o644, 0o1600] {
            fs::set_permissions(&fixture.path, fs::Permissions::from_mode(mode)).unwrap();
            assert!(fixture.read().is_err());
        }
        fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o600)).unwrap();
        let other = fixture.directory.join("other.json");
        fs::hard_link(&fixture.path, &other).unwrap();
        assert!(fixture.read().is_err());
        fs::remove_file(&other).unwrap();
        symlink(&fixture.path, &other).unwrap();
        assert!(read_private_keys(&other, &fixture.digest, 5, 2).is_err());
    }

    #[test]
    fn rejects_directory_fifo_and_missing_file() {
        let fixture = Fixture::valid();
        let directory = fixture.directory.join("directory.json");
        DirBuilder::new().mode(0o700).create(&directory).unwrap();
        assert!(read_private_keys(&directory, &fixture.digest, 5, 2).is_err());
        let fifo = fixture.directory.join("fifo.json");
        let name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: the NUL-terminated path points inside this synthetic fixture.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(read_private_keys(&fifo, &fixture.digest, 5, 2).is_err());
        assert!(read_private_keys(&fixture.directory.join("missing.json"), &fixture.digest, 5, 2).is_err());
    }

    #[test]
    fn rejects_unsafe_parent_modes_and_symlinked_parent() {
        let fixture = Fixture::valid();
        for mode in [0o755, 0o770, 0o777, 0o1700] {
            fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(mode)).unwrap();
            assert!(fixture.read().is_err());
        }
        fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o700)).unwrap();
        let alias = fixture.directory.join("alias");
        symlink(&fixture.directory, &alias).unwrap();
        assert!(read_private_keys(&alias.join("private_keys.json"), &fixture.digest, 5, 2).is_err());
    }

    #[test]
    fn rejects_unsafe_ancestor_and_parent_traversal() {
        let fixture = Fixture::valid();
        let parent = fixture.directory.join("protected");
        DirBuilder::new().mode(0o700).create(&parent).unwrap();
        let path = parent.join("private_keys.json");
        fs::rename(&fixture.path, &path).unwrap();
        fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(read_private_keys(&path, &fixture.digest, 5, 2).is_err());
        fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(read_private_keys(&parent.join("../protected/private_keys.json"), &fixture.digest, 5, 2).is_err());
    }

    #[test]
    fn rejects_wrong_file_and_parent_owner_without_chown() {
        let fixture = Fixture::valid();
        let file = File::open(&fixture.path).unwrap();
        let wrong_uid = file.metadata().unwrap().uid() ^ 1;
        let directory = File::open(&fixture.directory).unwrap();
        for input in [AccountInput::PrivateKeys, AccountInput::GenesisAccounts] {
            assert!(verify_accounts_file(&file, wrong_uid, input).is_err());
            assert!(verify_accounts_directory(&directory, wrong_uid, true, input).is_err());
        }
    }

    fn genesis_accounts_json() -> serde_json::Value {
        let users: Vec<_> = keys().into_iter().flatten().map(|key| {
            super::super::compact_user(QHashOut::from_values(21, 22, 23, 24), key, 100)
        }).collect();
        serde_json::json!({
            "users": users,
            "validators": [{
                "realm_id": 1, "validator_user_id": 1048576,
                "node_id": "11".repeat(38), "bls_public_key": "22".repeat(48)
            }],
            "contracts": [{
                "deployer": 0, "code_root": QHashOut::<GoldilocksField>::ZERO,
                "code_definition": {"state_tree_height": 32, "functions": []},
                "function_whitelist": []
            }]
        })
    }

    #[test]
    fn reads_accounts_from_genesis_without_contract_layout_metadata() {
        let document = genesis_accounts_json();
        let fixture = Fixture::new(serde_json::to_vec(&document).unwrap());
        let (users, validators) = read_genesis_accounts(&fixture.path, &fixture.digest).unwrap();
        assert!(serde_json::to_value(&users).unwrap() == document["users"]);
        assert!(serde_json::to_value(&validators).unwrap() == document["validators"]);
        assert!(fs::read(&fixture.path).unwrap() == fixture.bytes);
    }

    #[test]
    fn ignores_contract_schema_and_unrelated_genesis_fields() {
        let mut document = genesis_accounts_json();
        for contracts in [serde_json::json!(null), serde_json::json!({"arbitrary": [1, {"nested": true}]}), serde_json::json!("not a contract array")] {
            document["contracts"] = contracts;
            document["checkpoint_stats"] = serde_json::json!({"ignored": true});
            let fixture = Fixture::new(serde_json::to_vec(&document).unwrap());
            let (users, validators) = read_genesis_accounts(&fixture.path, &fixture.digest).unwrap();
            assert_eq!(users.len(), 4);
            assert_eq!(validators.len(), 1);
        }
    }

    #[test]
    fn public_genesis_accepts_0600_or_0644_but_private_keys_stay_0600() {
        let fixture = Fixture::new(serde_json::to_vec(&genesis_accounts_json()).unwrap());
        fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o755)).unwrap();
        for mode in [0o600, 0o644] {
            fs::set_permissions(&fixture.path, fs::Permissions::from_mode(mode)).unwrap();
            assert!(read_genesis_accounts(&fixture.path, &fixture.digest).is_ok());
        }
        for mode in [0o400, 0o640, 0o660, 0o666, 0o755, 0o1644] {
            fs::set_permissions(&fixture.path, fs::Permissions::from_mode(mode)).unwrap();
            assert!(read_genesis_accounts(&fixture.path, &fixture.digest).is_err());
        }
        let secret = Fixture::valid();
        fs::set_permissions(&secret.path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(secret.read().is_err());
    }

    #[test]
    fn public_genesis_rejects_wrong_hash_before_parsing() {
        let fixture = Fixture::new(b"not json".to_vec());
        let error = read_genesis_accounts(&fixture.path, &"0".repeat(64)).unwrap_err();
        assert_eq!(error.to_string(), "account input SHA-256 mismatch");
        assert!(read_genesis_accounts(&fixture.path, &"A".repeat(64)).is_err());
    }

    #[test]
    fn public_genesis_requires_both_arrays_and_redacts_decode_errors() {
        for field in ["users", "validators"] {
            for replacement in [None, Some(serde_json::json!(null)), Some(serde_json::json!("synthetic-secret-sentinel"))] {
                let mut document = genesis_accounts_json();
                if let Some(value) = replacement {
                    document[field] = value;
                } else {
                    document.as_object_mut().unwrap().remove(field);
                }
                let fixture = Fixture::new(serde_json::to_vec(&document).unwrap());
                let error = read_genesis_accounts(&fixture.path, &fixture.digest).unwrap_err();
                assert_eq!(format!("{error:#}"), "Genesis accounts JSON is invalid");
                assert!(!format!("{error:?}").contains("synthetic-secret-sentinel"));
                assert_eq!(error.chain().count(), 1);
            }
        }
    }

    #[test]
    fn public_genesis_rejects_duplicate_account_fields_and_trailing_data() {
        for bytes in [
            br#"{"users":[],"users":[],"validators":[]}"#.to_vec(),
            br#"{"users":[],"validators":[],"validators":[]}"#.to_vec(),
            br#"{"users":[],"validators":[]} {}"#.to_vec(),
        ] {
            let fixture = Fixture::new(bytes);
            assert!(read_genesis_accounts(&fixture.path, &fixture.digest).is_err());
        }
    }

    #[test]
    fn public_genesis_rejects_links_and_writable_parent() {
        let fixture = Fixture::new(serde_json::to_vec(&genesis_accounts_json()).unwrap());
        let link = fixture.directory.join("link.json");
        symlink(&fixture.path, &link).unwrap();
        assert!(read_genesis_accounts(&link, &fixture.digest).is_err());
        fs::remove_file(&link).unwrap();
        fs::hard_link(&fixture.path, &link).unwrap();
        assert!(read_genesis_accounts(&fixture.path, &fixture.digest).is_err());
        fs::remove_file(&link).unwrap();
        fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(read_genesis_accounts(&fixture.path, &fixture.digest).is_err());
        fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o700)).unwrap();
        let alias = fixture.directory.join("alias");
        symlink(&fixture.directory, &alias).unwrap();
        assert!(read_genesis_accounts(&alias.join("private_keys.json"), &fixture.digest).is_err());
    }
}
