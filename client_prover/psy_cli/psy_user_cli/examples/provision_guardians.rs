use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::PrimeField64},
    hash::poseidon::PoseidonPermutation,
};
use psy_client_common::data::{
    qhashout::QHashOut,
    secp256k1::CompressedPublicKey,
};
use psy_crypto::signature::secp256k1::wallet::hash_no_pad_compressed_public_key;
use psy_provider::wallet::secp_wallet::Wallet;
use psy_vm::ups::multisig::{MultisigAccount, MultisigPolicy, MULTISIG_POLICY_CONTRACT_ID};
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;

const PROVISIONED_GUARDIANS: usize = 3;
const PASSWORD_BYTES: usize = 32;

fn main() {
    if let Err(message) = provision() {
        let _ = writeln!(io::stderr(), "guardian provisioning failed: {message}");
        std::process::exit(1);
    }
    println!("provisioned three localhost guardians");
}

fn provision() -> Result<(), &'static str> {
    let root = protected_root()?;
    let output = create_output(root)?;
    let mut members = Vec::with_capacity(PROVISIONED_GUARDIANS);
    for index in 1..=PROVISIONED_GUARDIANS {
        members.push(provision_guardian(&output.secrets, index)?);
    }
    members.sort_by_key(|member| canonical_limbs(member.commitment));
    let account = multisig_account(&members)?;
    let public_key_param = account.public_key_param().map_err(|_| "multisig account validation failed")?;
    save_public(&output.public, &account, public_key_param, &members)
}

fn protected_root() -> Result<PathBuf, &'static str> {
    let mut args = std::env::args_os().skip(1);
    let root = args.next().ok_or("protected parent directory is required")?;
    if args.next().is_some() {
        return Err("exactly one protected parent directory is required");
    }
    let root = PathBuf::from(root);
    if !root.is_absolute() || root.components().any(|part| matches!(part, Component::ParentDir | Component::CurDir)) {
        return Err("protected parent must be an absolute path without . or ..");
    }
    let uid = current_uid()?;
    let mut ancestor = PathBuf::new();
    for part in root.components() {
        ancestor.push(part);
        if matches!(part, Component::RootDir) {
            continue;
        }
        let metadata = fs::symlink_metadata(&ancestor).map_err(|_| "reading protected ancestor failed")?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("protected ancestor must be a real directory");
        }
        if ![0, uid].contains(&metadata.uid()) || metadata.mode() & 0o022 != 0 {
            return Err("protected ancestor owner or mode is unsuitable");
        }
    }
    Ok(root)
}

fn current_uid() -> Result<u32, &'static str> {
    let status = fs::read_to_string("/proc/self/status").map_err(|_| "reading process status failed")?;
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("Uid:") {
            let uid = value.split_whitespace().next().ok_or("process uid missing")?.parse::<u32>().map_err(|_| "process uid invalid")?;
            return Ok(uid);
        }
    }
    Err("process uid missing")
}

struct OutputDirs {
    secrets: PathBuf,
    public: PathBuf,
}

fn create_output(root: PathBuf) -> Result<OutputDirs, &'static str> {
    let output = root.join("localhost-guardians");
    let secrets = output.join("secrets");
    let public = output.join("public");
    for directory in [&output, &secrets, &public] {
        fs::DirBuilder::new().recursive(false).mode(0o700).create(directory).map_err(|_| "creating guardian directory failed")?;
        let metadata = fs::symlink_metadata(directory).map_err(|_| "reading guardian directory failed")?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() || metadata.mode() & 0o777 != 0o700 {
            return Err("new directory mode or type is unsuitable");
        }
    }
    Ok(OutputDirs { secrets, public })
}

struct GuardianMember {
    provision_index: usize,
    commitment: QHashOut<GoldilocksField>,
    compressed_public_key: [u8; 33],
}

fn provision_guardian(secrets: &Path, index: usize) -> Result<GuardianMember, &'static str> {
    let keystore = secrets.join(format!("guardian-{index}.keystore.json"));
    let password_path = secrets.join(format!("guardian-{index}.password"));
    let mut password_file = reserve_private(&password_path)?;
    let mut keystore_file = reserve_private(&keystore)?;
    let password = random_password()?;
    password_file.write_all(password.as_bytes()).map_err(|_| "saving guardian password failed")?;
    password_file.sync_all().map_err(|_| "syncing guardian password failed")?;
    drop(password_file);
    let wallet = Wallet::new().map_err(|_| "creating guardian wallet failed")?;
    keystore_file.sync_all().map_err(|_| "syncing reserved keystore failed")?;
    drop(keystore_file);
    wallet.save(&keystore, Some(password.as_str())).map_err(|_| "saving guardian keystore failed")?;
    sync_file(&keystore)?;
    let loaded = Wallet::load_encrypted_keystore(&keystore, password.as_str()).map_err(|_| "reloading guardian keystore failed")?;
    if loaded.public_key_hash() != wallet.public_key_hash() || loaded.compressed_public_key() != wallet.compressed_public_key() {
        return Err("reloaded guardian public key mismatch");
    }
    let compressed = loaded.compressed_public_key();
    let commitment = hash_no_pad_compressed_public_key::<GoldilocksField, PoseidonPermutation<GoldilocksField>>(CompressedPublicKey(compressed));
    if commitment != loaded.public_key_hash() {
        return Err("guardian member commitment mismatch");
    }
    Ok(GuardianMember { provision_index: index, commitment, compressed_public_key: compressed })
}

fn reserve_private(path: &Path) -> Result<File, &'static str> {
    if fs::symlink_metadata(path).is_ok() {
        return Err("output file already exists");
    }
    let file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).map_err(|_| "reserving private output file failed")?;
    let metadata = file.metadata().map_err(|_| "reading reserved file failed")?;
    if !metadata.is_file() || metadata.mode() & 0o777 != 0o600 {
        return Err("reserved file mode is unsuitable");
    }
    Ok(file)
}

fn random_password() -> Result<String, &'static str> {
    let mut bytes = [0u8; PASSWORD_BYTES];
    OsRng.fill_bytes(&mut bytes);
    Ok(hex::encode(bytes))
}

fn canonical_limbs(commitment: QHashOut<GoldilocksField>) -> [u64; 4] {
    commitment.0.elements.map(|limb| limb.to_canonical_u64())
}

/// Consumer wire form of `Hex<N>` (`guardian/protocol.rs`): `0x` plus lowercase hex.
fn compressed_key_hex(key: [u8; 33]) -> String {
    format!("0x{}", hex::encode(key))
}

fn multisig_account(members: &[GuardianMember]) -> Result<MultisigAccount, &'static str> {
    if members.len() != PROVISIONED_GUARDIANS {
        return Err("localhost guardians require exactly three members");
    }
    let mut member_hashes = [QHashOut::ZERO; 8];
    for (slot, member) in members.iter().enumerate() {
        member_hashes[slot] = member.commitment;
    }
    Ok(MultisigAccount {
        contract_id: MULTISIG_POLICY_CONTRACT_ID,
        initial_policy: MultisigPolicy { version: 1, threshold: 2, member_count: 3, member_hashes },
    })
}

fn save_public(
    public: &Path,
    account: &MultisigAccount,
    public_key_param: QHashOut<GoldilocksField>,
    members: &[GuardianMember],
) -> Result<(), &'static str> {
    let account_path = public.join("multisig-account.json");
    let members_path = public.join("members.json");
    let account_json = serde_json::to_vec(account).map_err(|_| "serializing multisig account failed")?;
    save_private_json(&account_path, &account_json)?;
    let rows = members.iter().enumerate().map(|(sorted_slot, member)| MemberRow {
        public_key_param,
        provision_index: member.provision_index,
        sorted_slot,
        compressed_public_key: compressed_key_hex(member.compressed_public_key),
        member_commitment: member.commitment,
    }).collect::<Vec<_>>();
    let members_json = serde_json::to_vec(&rows).map_err(|_| "serializing guardian members failed")?;
    save_private_json(&members_path, &members_json)
}

fn save_private_json(path: &Path, body: &[u8]) -> Result<(), &'static str> {
    let mut file = reserve_private(path)?;
    file.write_all(body).and_then(|_| file.write_all(b"\n")).map_err(|_| "saving public json failed")?;
    file.sync_all().map_err(|_| "syncing public json failed")
}

fn sync_file(path: &Path) -> Result<(), &'static str> {
    OpenOptions::new().write(true).open(path).map_err(|_| "reopening guardian keystore failed")?.sync_all().map_err(|_| "syncing guardian keystore failed")?;
    Ok(())
}

#[derive(Serialize)]
struct MemberRow {
    public_key_param: QHashOut<GoldilocksField>,
    provision_index: usize,
    sorted_slot: usize,
    compressed_public_key: String,
    member_commitment: QHashOut<GoldilocksField>,
}
