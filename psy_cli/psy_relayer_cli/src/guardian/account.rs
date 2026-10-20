use std::{fs, io::Write, os::unix::{fs::{DirBuilderExt, PermissionsExt}, io::AsRawFd}, path::{Path, PathBuf}};

use anyhow::{Context, ensure};
use guardian_common::runtime::{create_db_file, open_db_file, read_protected_file};
use plonky2::{field::goldilocks_field::GoldilocksField, hash::poseidon::PoseidonPermutation};
use psy_client_common::data::{qhashout::QHashOut, secp256k1::CompressedPublicKey};
use psy_crypto::signature::secp256k1::wallet::hash_no_pad_compressed_public_key;
use psy_provider::wallet::secp_wallet::Wallet;
use psy_vm::ups::multisig::{MultisigAccount, MultisigPolicy, MULTISIG_POLICY_CONTRACT_ID};
use rand::RngCore;
use zeroize::Zeroizing;

pub fn run(output: &Path) -> anyhow::Result<()> {
    let directory = home::home_dir().context("home directory unavailable")?.join(".psy/keystore");
    prepare(&directory, output)?;
    println!("Guardian public account ready: {} (three signers, threshold two)", output.display());
    Ok(())
}

fn prepare(directory: &Path, output: &Path) -> anyhow::Result<()> {
    let output = if output.is_absolute() { output.to_path_buf() } else { std::env::current_dir()?.join(output) };
    let parent = output.parent().context("account output must have a parent directory")?;
    fs::DirBuilder::new().recursive(true).mode(0o700).create(directory)?;
    fs::DirBuilder::new().recursive(true).mode(0o700).create(parent)?;
    // Refuse partial custody before creating any additional signing keys.
    for id in 1..=3 {
        let key = directory.join(format!("guardian-{id}.keystore.json"));
        let password = directory.join(format!("guardian-{id}.password"));
        ensure!(!key.try_exists()? || password.try_exists()?, "guardian {id} key exists without its password; recover custody before continuing");
        ensure!(!output.try_exists()? || (key.try_exists()? && password.try_exists()?), "existing account requires all three existing signing keys; refusing to create replacement identities");
    }
    let mut member_hashes = [QHashOut::<GoldilocksField>::ZERO; 8];
    for id in 1..=3 {
        let key_name = PathBuf::from(format!("guardian-{id}.keystore.json"));
        let password_name = PathBuf::from(format!("guardian-{id}.password"));
        if !directory.join(&password_name).try_exists()? {
            let mut random = Zeroizing::new([0u8; 32]);
            rand::rngs::OsRng.fill_bytes(&mut *random);
            let password = Zeroizing::new(hex::encode(*random));
            let (mut file, parent) = create_db_file(directory, &password_name)?;
            file.write_all(password.as_bytes())?;
            file.sync_all()?;
            parent.sync_all()?;
        }
        let password = read_protected_file(directory, &password_name, 4096)?;
        let password = std::str::from_utf8(&password).context("password is not UTF-8")?;
        ensure!(!password.is_empty() && !password.contains(['\0', '\r', '\n']), "guardian {id} password must be a single nonempty line without a trailing newline");
        if !directory.join(&key_name).try_exists()? {
            let mut random = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut random);
            let stage = directory.join(format!(".guardian-{id}-{}", hex::encode(random)));
            fs::DirBuilder::new().mode(0o700).create(&stage)?;
            let staged_key = stage.join("key.json");
            Wallet::new()?.save(&staged_key, Some(password))?;
            fs::set_permissions(&staged_key, fs::Permissions::from_mode(0o600))?;
            fs::File::open(&staged_key)?.sync_all()?;
            // Hard-link installation fails if another process has created the key.
            fs::hard_link(&staged_key, directory.join(&key_name))?;
            fs::File::open(directory)?.sync_all()?;
            fs::remove_file(&staged_key)?;
            fs::remove_dir(&stage)?;
        }
        let key_file = open_db_file(directory, &key_name)?;
        let descriptor = PathBuf::from(format!("{}/{}", if cfg!(target_os = "macos") { "/dev/fd" } else { "/proc/self/fd" }, key_file.as_raw_fd()));
        let wallet = Wallet::load_encrypted_keystore(&descriptor, password).with_context(|| format!("guardian {id} encrypted key"))?;
        member_hashes[(id - 1) as usize] = hash_no_pad_compressed_public_key::<GoldilocksField, PoseidonPermutation<GoldilocksField>>(
            CompressedPublicKey::new_from_slice(&wallet.compressed_public_key()),
        );
    }
    let account = MultisigAccount { contract_id: MULTISIG_POLICY_CONTRACT_ID, initial_policy: MultisigPolicy {
        version: 1, threshold: 2, member_count: 3, member_hashes,
    }};
    account.public_key_param()?;
    let bytes = serde_json::to_vec(&account)?;
    let name = Path::new(output.file_name().context("account output filename")?);
    if output.try_exists()? {
        let existing = read_protected_file(parent, name, 65536)?;
        let existing: serde_json::Value = serde_json::from_slice(&existing)?;
        ensure!(existing == serde_json::to_value(&account)?, "existing public account differs from the signing keys; refusing to replace it");
    } else {
        let (mut file, parent) = create_db_file(parent, name)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        parent.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepares_missing_account_and_reuses_custody_without_replacing_files() {
        let mut random = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let root = std::env::current_dir().unwrap().join(format!(".guardian-account-test-{}", hex::encode(random)));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let directory = root.join("keystore");
        let output = root.join("account.json");
        prepare(&directory, &output).unwrap();
        let files: Vec<_> = (1..=3).flat_map(|id| [directory.join(format!("guardian-{id}.password")), directory.join(format!("guardian-{id}.keystore.json"))]).chain([output.clone()]).collect();
        let before: Vec<_> = files.iter().map(|path| fs::read(path).unwrap()).collect();
        for path in &files {
            assert_eq!(fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let account: MultisigAccount = serde_json::from_slice(&before[6]).unwrap();
        account.public_key_param().unwrap();
        assert_eq!(account.initial_policy.member_count, 3);
        assert_eq!(account.initial_policy.threshold, 2);
        prepare(&directory, &output).unwrap();
        let after: Vec<_> = files.iter().map(|path| fs::read(path).unwrap()).collect();
        assert_eq!(before, after);
        fs::write(&output, b"{}").unwrap();
        assert!(prepare(&directory, &output).unwrap_err().to_string().contains("refusing to replace"));
        assert_eq!(fs::read(&output).unwrap(), b"{}");
        fs::remove_file(&output).unwrap();
        fs::remove_file(directory.join("guardian-1.password")).unwrap();
        assert!(prepare(&directory, &output).unwrap_err().to_string().contains("recover custody"));
        assert!(!output.exists());
        fs::remove_dir_all(root).unwrap();
    }
}
