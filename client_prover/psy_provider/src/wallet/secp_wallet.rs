#![cfg(not(target_arch = "wasm32"))]

use std::{fmt, fs, path::Path};

use alloy_primitives::{Address, B256};
use alloy_signer::SignerSync;
use alloy_signer_local::{
    coins_bip39::{English, Mnemonic},
    MnemonicBuilder, PrivateKeySigner,
};
use anyhow::{bail, Context, Result};
use k256::{
    ecdsa::SigningKey,
    sha2::{Digest, Sha256},
};
use plonky2::{field::goldilocks_field::GoldilocksField, hash::poseidon::PoseidonPermutation};
use psy_client_common::data::{qhashout::QHashOut, secp256k1::CompressedPublicKey};
use psy_config::PSY_NETWORK_MAGIC;

use crate::wallet::secp_sign::SignedRequest;

pub struct WalletConfig {
    pub default_keystore_dir: Option<String>,
    pub default_password: Option<String>,
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            default_keystore_dir: dirs::home_dir().map(|h| h.join(".psy/keystore").to_string_lossy().into_owned()),
            default_password: None,
        }
    }
}
#[derive(Clone)]
pub struct Wallet {
    inner: PrivateKeySigner,
    public_key_hash: QHashOut<GoldilocksField>,
}

impl Wallet {
    pub fn new() -> Result<Self> {
        Self::random()
    }

    pub fn random() -> Result<Self> {
        let mut rng = rand::thread_rng();
        let inner = PrivateKeySigner::random_with(&mut rng);
        Self::from_signer(inner)
    }

    pub fn from_bytes(key: &[u8]) -> Result<Self> {
        ensure_key_length(key)?;

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(key);

        let signing_key = SigningKey::from_bytes(&key_array.into()).context("Invalid private key")?;

        Self::from_signer(PrivateKeySigner::from_signing_key(signing_key))
    }

    pub fn from_hex(hex: &str) -> Result<Self> {
        let bytes = parse_hex(hex)?;
        Self::from_bytes(&bytes)
    }

    pub fn from_mnemonic(phrase: &str, index: u32) -> Result<Self> {
        let derivation_path = format!("m/44'/60'/0'/0/{}", index);

        let wallet = MnemonicBuilder::<English>::default()
            .phrase(phrase)
            .derivation_path(derivation_path)?
            .build()?;

        Self::from_signer(wallet)
    }

    fn from_signer(inner: PrivateKeySigner) -> Result<Self> {
        let compressed = compress_public_key(&inner.public_key().as_slice())?;
        let wallet_id = compute_wallet_id(compressed);

        Ok(Self {
            inner,
            public_key_hash: wallet_id,
        })
    }

    pub fn generate_mnemonic(word_count: usize) -> Result<String> {
        validate_word_count(word_count)?;

        let mut rng = rand::thread_rng();
        let mnemonic = Mnemonic::<English>::new_with_count(&mut rng, word_count).context("Failed to generate mnemonic")?;

        Ok(mnemonic.to_phrase())
    }

    pub fn vanity(prefix: Option<&str>, suffix: Option<&str>) -> Result<Self> {
        use rayon::prelude::*;

        let matcher = create_vanity_matcher(prefix, suffix);

        let wallet = (0..u64::MAX)
            .into_par_iter()
            .map(|_| {
                let mut rng = rand::thread_rng();
                PrivateKeySigner::random_with(&mut rng)
            })
            .find_any(|w| matcher(&w.address()))
            .ok_or_else(|| anyhow::anyhow!("Vanity address generation failed"))?;

        Self::from_signer(wallet)
    }

    pub fn public_key_hash(&self) -> QHashOut<GoldilocksField> {
        self.public_key_hash
    }

    pub fn address(&self) -> String {
        self.inner.address().to_checksum(None)
    }

    pub fn address_raw(&self) -> Address {
        self.inner.address()
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.inner.public_key().to_vec()
    }

    pub fn private_key(&self) -> Vec<u8> {
        self.inner.credential().to_bytes().to_vec()
    }

    pub fn private_key_hex(&self) -> String {
        format!("0x{}", hex::encode(self.private_key()))
    }

    pub fn address_from_public_key(public_key: &[u8]) -> Result<Address> {
        use alloy_primitives::keccak256;
        use anyhow::anyhow;

        // Validate public key length
        if public_key.len() != 64 && public_key.len() != 65 {
            return Err(anyhow!("Invalid public key length: expected 64 or 65 bytes, got {}", public_key.len()));
        }

        // Handle both compressed and uncompressed formats
        let key_bytes = if public_key.len() == 65 {
            if public_key[0] != 0x04 {
                return Err(anyhow!(
                    "Invalid uncompressed public key prefix: expected 0x04, got 0x{:02x}",
                    public_key[0]
                ));
            }
            &public_key[1..] // Skip the 0x04 prefix
        } else {
            public_key
        };

        let hash = keccak256(key_bytes);

        let mut address_bytes = [0u8; 20];
        address_bytes.copy_from_slice(&hash[12..32]);

        Ok(Address::from(address_bytes))
    }

    pub fn sign_eip712<T: crate::wallet::secp_sign::Eip712Signable>(&self, data: T) -> Result<SignedRequest<T>> {
        SignedRequest::new(self, data)
    }

    pub fn sign_eip712_with_params<T: crate::wallet::secp_sign::Eip712Signable>(
        &self,
        data: T,
        timestamp: u64,
        chain_id: Option<u64>,
    ) -> Result<SignedRequest<T>> {
        let chain_id = chain_id.unwrap_or(PSY_NETWORK_MAGIC);
        SignedRequest::new_with_timestamp_and_chain(self, data, timestamp, chain_id)
    }

    pub fn verify_signature(message: &[u8], signature: &[u8], address: Address) -> Result<bool> {
        use alloy_primitives::Signature;

        let sig = Signature::try_from(signature)?;
        let recovered = sig.recover_address_from_msg(message)?;

        Ok(recovered == address)
    }

    pub fn save(&self, path: &Path, password: Option<&str>) -> Result<()> {
        ensure_parent_dir(path)?;

        let password = password.unwrap_or("");

        let mut rng = rand::thread_rng();
        let private_key = self.inner.credential().to_bytes();

        let (dir, name) = split_path(path);

        let (_, uuid) = PrivateKeySigner::encrypt_keystore(dir.clone(), &mut rng, private_key, password, name.as_deref())
            .context("Failed to encrypt keystore")?;

        let final_path = build_keystore_path(&dir, name.as_deref(), &uuid);

        tracing::info!("Wallet saved to: {}", final_path.display());
        Ok(())
    }

    pub fn load(private_key: Option<&str>, keystore_path: Option<&Path>, password: Option<&str>) -> Result<Self> {
        if let Some(pk) = private_key {
            return Self::from_hex(pk);
        }

        if let Some(path) = keystore_path {
            let password = match password {
                Some(p) => p.to_string(),
                None => {
                    use std::io::{self, Write};
                    print!("Enter password for keystore: ");
                    io::stdout().flush()?;
                    rpassword::read_password()?
                }
            };
            let inner = PrivateKeySigner::decrypt_keystore(path, &password)?;
            return Self::from_signer(inner);
        }

        let default_keystore_dir = dirs::home_dir()
            .map(|h| h.join(".psy/keystore"))
            .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;

        if default_keystore_dir.exists() {
            let accounts = Self::list_accounts(Some(&default_keystore_dir))?;
            if !accounts.is_empty() {
                let wallet_file = default_keystore_dir.join(&accounts[0]);
                let password = match password {
                    Some(p) => p.to_string(),
                    None => {
                        use std::io::{self, Write};
                        print!("Enter password for keystore: ");
                        io::stdout().flush()?;
                        rpassword::read_password()?
                    }
                };
                let inner = PrivateKeySigner::decrypt_keystore(&wallet_file, &password)?;
                return Self::from_signer(inner);
            }
        }
        bail!(
            "❌ No wallet found in default keystore directory: {}.\n\
             Hints:\n\
               • Ensure the directory exists and contains a valid keystore JSON file (UTC--...json).\n\
               • Or specify a private key explicitly with `--private-key <hex>`.\n\
               • Or specify a keystore file with `--keystore-path <path-to-keystore.json>`.\n\
             Note: The default keystore directory is typically created by `cast wallet new <DIR>` or other Ethereum wallet tools.",
            default_keystore_dir.to_string_lossy()
        );
    }

    pub fn new_keystore(dir: &Path, password: &str, name: Option<&str>) -> Result<(Self, String)> {
        let mut rng = rand::thread_rng();
        let (inner, uuid) = PrivateKeySigner::new_keystore(dir, &mut rng, password, name)?;

        let wallet = Self::from_signer(inner)?;
        Ok((wallet, uuid))
    }

    pub fn to_json(&self, password: Option<&str>) -> Result<String> {
        let temp_dir = tempfile::tempdir()?;
        let temp_path = temp_dir.path().join("keystore");

        self.save(&temp_path, password)?;
        fs::read_to_string(&temp_path).context("Failed to read keystore JSON")
    }

    pub fn from_json(json: &str, password: Option<&str>) -> Result<Self> {
        let temp_dir = tempfile::tempdir()?;
        let temp_path = temp_dir.path().join("keystore");

        fs::write(&temp_path, json)?;
        Self::load(None, Some(&temp_path), password)
    }

    pub fn list_accounts(dir: Option<&Path>) -> Result<Vec<String>> {
        let keystore_dir = resolve_keystore_dir(dir)?;

        if !keystore_dir.exists() {
            return Ok(Vec::new());
        }

        let accounts = fs::read_dir(keystore_dir)?
            .filter_map(Result::ok)
            .filter(|e| e.path().is_file())
            .filter_map(|e| e.path().file_name().and_then(|n| n.to_str()).map(String::from))
            .collect();

        Ok(accounts)
    }

    pub fn signer(&self) -> &PrivateKeySigner {
        &self.inner
    }

    pub fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.inner
            .sign_message_sync(message)
            .map(|sig| sig.as_bytes().to_vec())
            .context("Failed to sign message")
    }

    pub fn sign_raw(&self, data: &[u8]) -> Result<Vec<u8>> {
        let hash = Sha256::digest(data);

        self.inner
            .sign_hash_sync(&B256::from(hash.as_ref()))
            .map(|sig| sig.as_bytes().to_vec())
            .context("Failed to sign hash")
    }
}

impl fmt::Display for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Wallet Information:")?;
        writeln!(f, "  Address: {}", self.address())?;
        writeln!(f, "  Public Key: {}", hex::encode(self.public_key()))?;
        Ok(())
    }
}

impl fmt::Debug for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Wallet")
            .field("public_key_hash", &self.public_key_hash())
            .field("address", &self.address())
            .finish()
    }
}

fn ensure_key_length(key: &[u8]) -> Result<()> {
    if key.len() != 32 {
        bail!("Private key must be exactly 32 bytes, got {}", key.len());
    }
    Ok(())
}

fn parse_hex(hex: &str) -> Result<Vec<u8>> {
    let clean = hex.strip_prefix("0x").unwrap_or(hex);
    hex::decode(clean).context("Invalid hex string")
}

fn validate_word_count(count: usize) -> Result<()> {
    const VALID_COUNTS: &[usize] = &[12, 15, 18, 21, 24];
    if !VALID_COUNTS.contains(&count) {
        bail!("Invalid word count. Must be one of: {:?}", VALID_COUNTS);
    }
    Ok(())
}

fn compress_public_key(public_key: &[u8]) -> Result<CompressedPublicKey> {
    match public_key.len() {
        65 => {
            let mut compressed = [0u8; 33];
            compressed[0] = if public_key[64] & 1 == 0 { 0x02 } else { 0x03 };
            compressed[1..].copy_from_slice(&public_key[1..33]);
            Ok(CompressedPublicKey(compressed))
        }
        64 => {
            let mut compressed = [0u8; 33];
            compressed[0] = if public_key[63] & 1 == 0 { 0x02 } else { 0x03 };
            compressed[1..].copy_from_slice(&public_key[0..32]);
            Ok(CompressedPublicKey(compressed))
        }
        _ => bail!("Invalid public key length: {}", public_key.len()),
    }
}

fn compute_wallet_id(compressed: CompressedPublicKey) -> QHashOut<GoldilocksField> {
    psy_crypto::signature::secp256k1::wallet::hash_no_pad_compressed_public_key::<GoldilocksField, PoseidonPermutation<GoldilocksField>>(compressed)
}

fn create_vanity_matcher(prefix: Option<&str>, suffix: Option<&str>) -> impl Fn(&Address) -> bool {
    let prefix = prefix.map(String::from);
    let suffix = suffix.map(String::from);

    move |addr: &Address| {
        let hex = hex::encode(addr.as_slice());
        prefix.as_ref().map_or(true, |p| hex.starts_with(p)) && suffix.as_ref().map_or(true, |s| hex.ends_with(s))
    }
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn split_path(path: &Path) -> (std::path::PathBuf, Option<String>) {
    if path.is_dir() {
        (path.to_path_buf(), None)
    } else {
        (
            path.parent().unwrap_or(Path::new(".")).to_path_buf(),
            path.file_name().and_then(|n| n.to_str()).map(String::from),
        )
    }
}

fn build_keystore_path(dir: &Path, name: Option<&str>, uuid: &str) -> std::path::PathBuf {
    name.map_or_else(|| dir.join(uuid), |n| dir.join(n))
}

fn resolve_keystore_dir(dir: Option<&Path>) -> Result<std::path::PathBuf> {
    dir.map(|p| p.to_path_buf())
        .or_else(|| dirs::home_dir().map(|h| h.join(".psy/keystore")))
        .ok_or_else(|| anyhow::anyhow!("Could not determine keystore directory"))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn test_wallet_creation() {
        let wallet = Wallet::new().unwrap();
        assert!(!wallet.address().is_empty());
        assert_eq!(wallet.private_key().len(), 32);
    }

    #[test]
    fn test_wallet_from_hex() {
        let hex_key = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
        let wallet1 = Wallet::from_hex(hex_key).unwrap();
        let wallet2 = Wallet::from_hex(hex_key).unwrap();

        assert_eq!(wallet1.address(), wallet2.address());
        assert_eq!(wallet1.public_key_hash(), wallet2.public_key_hash());
    }

    #[test]
    fn test_wallet_from_bytes() {
        let key_bytes = [1u8; 32];
        let wallet1 = Wallet::from_bytes(&key_bytes).unwrap();
        let wallet2 = Wallet::from_bytes(&key_bytes).unwrap();

        assert_eq!(wallet1.address(), wallet2.address());
        assert_eq!(wallet1.private_key(), wallet2.private_key());
    }

    #[test]
    fn test_wallet_sign_and_verify() {
        let wallet = Wallet::new().unwrap();
        let message = b"test message";

        let signature = wallet.sign_message(message).unwrap();
        let is_valid = Wallet::verify_signature(message, &signature, wallet.address_raw()).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_wallet_sign_raw() {
        let wallet = Wallet::new().unwrap();
        let data = b"test data";

        let signature = wallet.sign_raw(data).unwrap();
        assert_eq!(signature.len(), 65); // ECDSA signature length
    }

    #[test]
    fn test_wallet_save_load() {
        let temp_dir = tempdir().unwrap();
        let wallet_path = temp_dir.path().join("test_wallet");
        let password = "test_password";

        let original_wallet = Wallet::new().unwrap();
        original_wallet.save(&wallet_path, Some(password)).unwrap();

        let loaded_wallet = Wallet::load(None, Some(&wallet_path), Some(password)).unwrap();

        assert_eq!(original_wallet.address(), loaded_wallet.address());
        assert_eq!(original_wallet.private_key(), loaded_wallet.private_key());
    }

    #[test]
    fn test_wallet_json_export_import() {
        let original_wallet = Wallet::new().unwrap();
        let password = "test_password";

        let json = original_wallet.to_json(Some(password)).unwrap();
        let imported_wallet = Wallet::from_json(&json, Some(password)).unwrap();

        assert_eq!(original_wallet.address(), imported_wallet.address());
        assert_eq!(original_wallet.private_key(), imported_wallet.private_key());
    }

    #[test]
    fn test_mnemonic_generation() {
        let mnemonic = Wallet::generate_mnemonic(12).unwrap();
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 12);

        let wallet = Wallet::from_mnemonic(&mnemonic, 0).unwrap();
        assert!(!wallet.address().is_empty());
    }

    #[test]
    fn test_keystore_directory_consistency() {
        let config = WalletConfig::default();
        let resolve_dir = resolve_keystore_dir(None).unwrap();

        if let Some(config_dir) = config.default_keystore_dir {
            let config_path = PathBuf::from(config_dir);
            assert_eq!(
                resolve_dir, config_path,
                "WalletConfig default and resolve_keystore_dir should use the same path"
            );
        }
    }

    #[test]
    fn test_keystore_uses_psy_directory() {
        let resolve_dir = resolve_keystore_dir(None).unwrap();
        let dir_string = resolve_dir.to_string_lossy();

        assert!(
            dir_string.contains(".psy/keystore"),
            "Should use .psy/keystore, not foundry directory. Got: {}",
            dir_string
        );
        assert!(
            !dir_string.contains("foundry"),
            "Should not contain 'foundry' in path. Got: {}",
            dir_string
        );
    }

    #[test]
    fn test_display_format() {
        let wallet = Wallet::new().unwrap();
        let display_output = format!("{}", wallet);

        assert!(display_output.contains("Wallet Information:"));
        assert!(display_output.contains("Address:"));
        assert!(display_output.contains("Public Key:"));
    }

    #[test]
    fn test_hex_parsing() {
        assert!(parse_hex("0x1234").is_ok());
        assert!(parse_hex("1234").is_ok());
        assert!(parse_hex("invalid").is_err());
    }

    #[test]
    fn test_key_length_validation() {
        assert!(ensure_key_length(&[0u8; 32]).is_ok());
        assert!(ensure_key_length(&[0u8; 31]).is_err());
        assert!(ensure_key_length(&[0u8; 33]).is_err());
    }

    #[test]
    fn test_word_count_validation() {
        assert!(validate_word_count(12).is_ok());
        assert!(validate_word_count(24).is_ok());
        assert!(validate_word_count(13).is_err());
        assert!(validate_word_count(25).is_err());
    }

    #[test]
    fn test_wallet_load_with_priority() {
        let temp_dir = tempdir().unwrap();
        let wallet_path = temp_dir.path().join("test_wallet");
        let password = "test_password";

        // Create a wallet first
        let original_wallet = Wallet::new().unwrap();
        original_wallet.save(&wallet_path, Some(password)).unwrap();

        // Test loading with private key (priority 1)
        let private_key = original_wallet.private_key_hex();
        let loaded_from_key = Wallet::load(Some(&private_key), None, None).unwrap();
        assert_eq!(original_wallet.address(), loaded_from_key.address());

        // Test loading with keystore path (priority 2)
        let loaded_from_keystore = Wallet::load(None, Some(&wallet_path), Some(password)).unwrap();
        assert_eq!(original_wallet.address(), loaded_from_keystore.address());
    }

    #[test]
    fn test_wallet_load_errors() {
        // Should fail when no wallet found
        let result = Wallet::load(None, None, None);
        assert!(result.is_err());

        // Should fail with non-existent keystore path
        let non_existent = Path::new("/non/existent/path");
        let result = Wallet::load(None, Some(non_existent), None);
        assert!(result.is_err());

        // Should fail with invalid private key
        let result = Wallet::load(Some("invalid_key"), None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_wallet_id_consistency() {
        let wallet = Wallet::new().unwrap();

        // ID hash should be consistent
        let id1 = wallet.public_key_hash();
        let id2 = wallet.public_key_hash();
        assert_eq!(id1, id2);

        // Same private key should produce same ID
        let private_key = wallet.private_key_hex();
        let wallet2 = Wallet::from_hex(&private_key).unwrap();
        assert_eq!(wallet.public_key_hash(), wallet2.public_key_hash());
        assert_eq!(wallet.address(), wallet2.address());
    }

    #[test]
    fn test_sign_message_and_raw() {
        let wallet = Wallet::new().unwrap();
        let message = b"test message";
        let data = b"test data";

        // Test sign_message
        let sig1 = wallet.sign_message(message).unwrap();
        assert_eq!(sig1.len(), 65); // ECDSA signature length

        // Test sign_raw
        let sig2 = wallet.sign_raw(data).unwrap();
        assert_eq!(sig2.len(), 65);

        // Different data should produce different signatures
        assert_ne!(sig1, sig2);

        // Verify message signature
        assert!(Wallet::verify_signature(message, &sig1, wallet.address_raw()).unwrap());

        // For sign_raw, the signature is over the SHA256 hash,
        // but verify_signature expects the original message
        // So we can't directly verify sign_raw output with verify_signature
        // We can only test that the signature length is correct
    }

    #[test]
    fn test_vanity_address_generation() {
        // This test might take a while, so we use a simple prefix
        let wallet = Wallet::vanity(Some("a"), None).unwrap();
        let address_hex = format!("{:x}", wallet.address_raw());
        assert!(address_hex.starts_with("a"));
    }

    #[test]
    fn test_mnemonic_deterministic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        // Same mnemonic and index should produce same wallet
        let wallet1 = Wallet::from_mnemonic(mnemonic, 0).unwrap();
        let wallet2 = Wallet::from_mnemonic(mnemonic, 0).unwrap();

        assert_eq!(wallet1.address(), wallet2.address());
        assert_eq!(wallet1.private_key(), wallet2.private_key());
        assert_eq!(wallet1.public_key_hash(), wallet2.public_key_hash());

        // Different indices should produce different wallets
        let wallet3 = Wallet::from_mnemonic(mnemonic, 1).unwrap();
        assert_ne!(wallet1.address(), wallet3.address());
        assert_ne!(wallet1.public_key_hash(), wallet3.public_key_hash());
    }

    #[test]
    fn test_json_export_import_roundtrip() {
        let original_wallet = Wallet::new().unwrap();
        let password = "test_password";

        // Export to JSON
        let json = original_wallet.to_json(Some(password)).unwrap();

        // Import from JSON
        let imported_wallet = Wallet::from_json(&json, Some(password)).unwrap();

        // Should be identical
        assert_eq!(original_wallet.address(), imported_wallet.address());
        assert_eq!(original_wallet.private_key(), imported_wallet.private_key());
        assert_eq!(original_wallet.public_key_hash(), imported_wallet.public_key_hash());
    }

    #[test]
    fn test_new_keystore() {
        let temp_dir = tempdir().unwrap();
        let password = "test_password";
        let name = Some("test_wallet");

        let (wallet, uuid) = Wallet::new_keystore(temp_dir.path(), password, name).unwrap();

        // Check that wallet is valid
        assert!(!wallet.address().is_empty());
        assert!(!uuid.is_empty());

        // Check that file was created
        let expected_path = temp_dir.path().join("test_wallet");
        assert!(expected_path.exists());

        // Should be able to load the wallet back
        let loaded = Wallet::load(None, Some(&expected_path), Some(password)).unwrap();
        assert_eq!(wallet.address(), loaded.address());
    }

    #[test]
    fn test_list_accounts() {
        let temp_dir = tempdir().unwrap();

        // Should be empty initially
        let accounts = Wallet::list_accounts(Some(temp_dir.path())).unwrap();
        assert!(accounts.is_empty());

        // Create some wallets
        let (_wallet1, _uuid1) = Wallet::new_keystore(temp_dir.path(), "pass", Some("wallet1")).unwrap();
        let (_wallet2, _uuid2) = Wallet::new_keystore(temp_dir.path(), "pass", Some("wallet2")).unwrap();

        // Should list the created wallets
        let accounts = Wallet::list_accounts(Some(temp_dir.path())).unwrap();
        assert_eq!(accounts.len(), 2);
        assert!(accounts.contains(&"wallet1".to_string()));
        assert!(accounts.contains(&"wallet2".to_string()));
    }
}
