#![cfg(not(target_arch = "wasm32"))]

use std::{
    fmt,
    fmt::Display,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy_primitives::{keccak256, Address, B256, U256};
use anyhow::{Context, Result};
use plonky2::field::goldilocks_field::GoldilocksField;
use psy_client_common::data::qhashout::QHashOut;
use psy_config::PSY_NETWORK_MAGIC;
use serde::{Deserialize, Serialize};

use crate::wallet::secp_wallet::Wallet;

const DEFAULT_SIGNATURE_EXPIRY: Duration = Duration::from_secs(300);

pub const PSY_DOMAIN_NAME: &str = "Psy Protocol";
pub const PSY_DOMAIN_VERSION: &str = "1";

pub trait Eip712Signable: Serialize {
    fn type_hash() -> B256;

    fn domain_name() -> &'static str {
        PSY_DOMAIN_NAME
    }

    fn domain_version() -> &'static str {
        PSY_DOMAIN_VERSION
    }

    fn encode_for_signing(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).context("Failed to serialize data for signing")
    }
}

#[allow(dead_code)]
fn default_signed_request_typehash() -> B256 {
    keccak256(b"SignedRequest(address signer,uint256 timestamp,bytes32 dataHash)")
}

impl Eip712Signable for String {
    fn type_hash() -> B256 {
        keccak256(b"StringMessage(string value)")
    }
}

impl Eip712Signable for QHashOut<GoldilocksField> {
    fn type_hash() -> B256 {
        keccak256(b"QHashOut(bytes32 elements)")
    }

    fn encode_for_signing(&self) -> Result<Vec<u8>> {
        Ok(self.to_le_bytes().to_vec())
    }
}

pub trait TimestampProvider: Send + Sync {
    fn now(&self) -> u64;
}

#[derive(Clone, Debug)]
pub struct SystemTimeProvider;

impl TimestampProvider for SystemTimeProvider {
    fn now(&self) -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignedRequest<T: Eip712Signable> {
    pub data: T,
    pub address: Address,
    pub worker_public_key: String,
    pub signature: String,
    pub timestamp: u64,
    pub chain_id: u64,
}

fn create_eip712_hash<T: Eip712Signable>(data: &T, address: Address, timestamp: u64, chain_id: u64) -> Result<B256> {
    let domain_separator = psy_domain_separator_for_type::<T>(chain_id);

    let data_bytes = data.encode_for_signing()?;
    let data_hash = keccak256(&data_bytes);

    let typehash = T::type_hash();
    let mut encoded = Vec::new();
    encoded.extend_from_slice(typehash.as_slice());
    encoded.extend_from_slice(address.as_slice());
    encoded.extend_from_slice(&U256::from(timestamp).to_be_bytes::<32>());
    encoded.extend_from_slice(data_hash.as_slice());

    let struct_hash = keccak256(&encoded);

    let mut final_hash_data = Vec::new();
    final_hash_data.push(0x19);
    final_hash_data.push(0x01);
    final_hash_data.extend_from_slice(domain_separator.as_slice());
    final_hash_data.extend_from_slice(struct_hash.as_slice());

    Ok(keccak256(&final_hash_data))
}

fn psy_domain_separator_for_type<T: Eip712Signable>(chain_id: u64) -> B256 {
    let domain_typehash = keccak256(b"EIP712Domain(string name,string version,uint256 chainId)");
    let name_hash = keccak256(T::domain_name().as_bytes());
    let version_hash = keccak256(T::domain_version().as_bytes());

    let mut encoded = Vec::new();
    encoded.extend_from_slice(domain_typehash.as_slice());
    encoded.extend_from_slice(name_hash.as_slice());
    encoded.extend_from_slice(version_hash.as_slice());
    encoded.extend_from_slice(&U256::from(chain_id).to_be_bytes::<32>());

    keccak256(&encoded)
}

impl<T: Eip712Signable> SignedRequest<T> {
    pub fn new(wallet: &Wallet, data: T) -> Result<Self> {
        Self::new_with_timestamp_and_chain(wallet, data, SystemTimeProvider.now(), PSY_NETWORK_MAGIC)
    }

    pub fn new_with_timestamp(wallet: &Wallet, data: T, timestamp: u64) -> Result<Self> {
        Self::new_with_timestamp_and_chain(wallet, data, timestamp, PSY_NETWORK_MAGIC)
    }

    pub fn new_with_timestamp_and_chain(wallet: &Wallet, data: T, timestamp: u64, chain_id: u64) -> Result<Self> {
        let address = wallet.address_raw();
        let eip712_hash = create_eip712_hash(&data, address, timestamp, chain_id)?;
        let dummy_worker_public_key = "0x".to_string(); // Placeholder for worker public key
                                                        // Sign the EIP-712 hash
        let signature_bytes = wallet.sign_message(eip712_hash.as_slice()).context("Failed to sign EIP-712 hash")?;
        let signature = hex::encode(&signature_bytes);

        Ok(Self {
            data,
            address,
            worker_public_key: dummy_worker_public_key,
            signature,
            timestamp,
            chain_id,
        })
    }

    pub fn verify(&self, expiry_duration: Option<Duration>) -> Result<bool> {
        if let Some(duration) = expiry_duration {
            if self.is_expired_with_duration(duration) {
                return Ok(false);
            }
        }

        let chain_id = self.chain_id;
        let eip712_hash = create_eip712_hash(&self.data, self.address, self.timestamp, chain_id)?;
        let signature_bytes = hex::decode(&self.signature).context("Failed to decode signature")?;

        Wallet::verify_signature(eip712_hash.as_slice(), &signature_bytes, self.address)
    }

    pub fn is_expired(&self) -> bool {
        self.is_expired_with_duration(DEFAULT_SIGNATURE_EXPIRY)
    }

    pub fn is_expired_with_duration(&self, duration: Duration) -> bool {
        let now = SystemTimeProvider.now();
        now > self.timestamp + duration.as_secs()
    }

    pub fn age(&self) -> u64 {
        SystemTimeProvider.now().saturating_sub(self.timestamp)
    }
}

impl SignedRequest<QHashOut<GoldilocksField>> {
    pub fn sign_hashable<T: serde::Serialize>(wallet: &Wallet, data: &T) -> Result<SignedRequest<QHashOut<GoldilocksField>>> {
        use alloy_primitives::keccak256;

        let data_bytes = bincode::serialize(data).context("Failed to serialize data")?;
        let hash = keccak256(&data_bytes);
        let qhash = QHashOut::from_hash256_le(psy_client_common::data::base_types::hash256::Hash256(hash.0));

        SignedRequest::new(wallet, qhash)
    }

    pub fn verify_hashable<T: Serialize>(&self, original_data: &T, expected_address: Address, expiry_duration: Option<Duration>) -> Result<bool> {
        use alloy_primitives::keccak256;

        let data_bytes = bincode::serialize(original_data).context("Failed to serialize original data")?;
        let expected_hash = keccak256(&data_bytes);
        let expected_qhash = QHashOut::from_hash256_le(psy_client_common::data::base_types::hash256::Hash256(expected_hash.0));

        if self.data != expected_qhash {
            return Ok(false);
        }

        if self.address != expected_address {
            return Ok(false);
        }

        self.verify(expiry_duration)
    }
}

impl<T: Display + Eip712Signable> Display for SignedRequest<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SignedRequest[address={}, age={}s]", &format!("{:#x}", self.address)[..10], self.age())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eip712_signature_creation_and_verification() {
        let wallet = Wallet::new().unwrap();
        let test_data = "test_message".to_string();
        let timestamp = 1234567890u64;
        let chain_id = PSY_NETWORK_MAGIC;

        // Create signed request using the generic method
        let signed_request = wallet.sign_eip712_with_params(test_data, timestamp, Some(chain_id)).unwrap();

        // Verify signature
        assert!(signed_request.verify(None).unwrap());
        assert_eq!(signed_request.address, wallet.address_raw());
        assert_eq!(signed_request.timestamp, timestamp);
        assert_eq!(signed_request.chain_id, chain_id);
    }

    #[test]
    fn test_eip712_signature_with_different_data() {
        let wallet = Wallet::new().unwrap();
        let test_data1 = "message1".to_string();
        let test_data2 = "message2".to_string();
        let timestamp = 1234567890u64;
        let chain_id = PSY_NETWORK_MAGIC;

        let signed_request1 = wallet.sign_eip712_with_params(test_data1, timestamp, Some(chain_id)).unwrap();

        let signed_request2 = wallet.sign_eip712_with_params(test_data2, timestamp, Some(chain_id)).unwrap();

        // Different data should produce different signatures
        assert_ne!(signed_request1.signature, signed_request2.signature);

        // Both should verify correctly
        assert!(signed_request1.verify(None).unwrap());
        assert!(signed_request2.verify(None).unwrap());
    }

    #[test]
    fn test_eip712_domain_separation() {
        let wallet = Wallet::new().unwrap();
        let test_data = "same_message".to_string();
        let timestamp = 1234567890u64;

        let signed_request_chain1 = wallet.sign_eip712_with_params(test_data.clone(), timestamp, Some(1)).unwrap();

        let signed_request_chain2 = wallet.sign_eip712_with_params(test_data, timestamp, Some(2)).unwrap();

        // Same data on different chains should produce different signatures
        assert_ne!(signed_request_chain1.signature, signed_request_chain2.signature);

        // Both should verify correctly
        assert!(signed_request_chain1.verify(None).unwrap());
        assert!(signed_request_chain2.verify(None).unwrap());
    }

    #[test]
    fn test_generic_eip712_signing() {
        let wallet = Wallet::new().unwrap();
        let message = "hello world".to_string();

        // Test the generic signing method
        let signed_request = wallet.sign_eip712(message.clone()).unwrap();

        assert_eq!(signed_request.data, message);
        assert!(signed_request.verify(None).unwrap());
    }

    #[test]
    fn test_qhashout_eip712_signing() {
        let wallet = Wallet::new().unwrap();
        let hash = QHashOut::<GoldilocksField>::from_values(1, 2, 3, 4);
        let timestamp = 1234567890u64;
        let chain_id = PSY_NETWORK_MAGIC;

        // Create signed request for QHashOut
        let signed_request = wallet.sign_eip712_with_params(hash, timestamp, Some(chain_id)).unwrap();

        // Verify signature
        assert!(signed_request.verify(None).unwrap());
        assert_eq!(signed_request.address, wallet.address_raw());
        assert_eq!(signed_request.timestamp, timestamp);
        assert_eq!(signed_request.chain_id, chain_id);
        assert_eq!(signed_request.data, hash);
    }

    #[test]
    fn test_hashable_signing_and_verification() {
        let wallet = Wallet::new().unwrap();
        let test_data = "test message for hashing".to_string();

        // Sign the data
        let signed = SignedRequest::<QHashOut<GoldilocksField>>::sign_hashable(&wallet, &test_data).unwrap();

        // Verify with correct data
        assert!(signed.verify_hashable(&test_data, wallet.address_raw(), None).unwrap());

        // Verify should fail with different data
        let wrong_data = "different message";
        assert!(!signed.verify_hashable(&wrong_data, wallet.address_raw(), None).unwrap());
    }

    #[test]
    fn test_hashable_signing_with_complex_data() {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct TestStruct {
            id: u64,
            name: String,
            values: Vec<u32>,
        }

        impl Eip712Signable for TestStruct {
            fn type_hash() -> B256 {
                keccak256(b"TestStruct(uint64 id,string name,uint32[] values)")
            }
        }

        let wallet = Wallet::new().unwrap();
        let test_data = TestStruct {
            id: 12345,
            name: "test".to_string(),
            values: vec![1, 2, 3, 4, 5],
        };

        let signed = SignedRequest::<QHashOut<GoldilocksField>>::sign_hashable(&wallet, &test_data).unwrap();

        // Should verify with exact same data
        assert!(signed.verify_hashable(&test_data, wallet.address_raw(), None).unwrap());

        // Should fail with modified data
        let modified_data = TestStruct {
            id: 12346, // Different ID
            name: "test".to_string(),
            values: vec![1, 2, 3, 4, 5],
        };
        assert!(!signed.verify_hashable(&modified_data, wallet.address_raw(), None).unwrap());
    }

    #[test]
    fn test_hashable_expiry() {
        let wallet = Wallet::new().unwrap();
        let test_data = "test message";

        // Create an old signed request
        let old_timestamp = SystemTimeProvider.now() - 100; // 100 seconds ago
        let hash = {
            use alloy_primitives::keccak256;
            let data_bytes = bincode::serialize(&test_data).unwrap();
            let hash = keccak256(&data_bytes);
            QHashOut::from_hash256_le(psy_client_common::data::base_types::hash256::Hash256(hash.0))
        };

        let old_signed = SignedRequest::new_with_timestamp(&wallet, hash, old_timestamp).unwrap();

        // Should pass without expiry check
        assert!(old_signed.verify_hashable(&test_data, wallet.address_raw(), None).unwrap());

        // Should fail with 30 second expiry
        assert!(!old_signed
            .verify_hashable(&test_data, wallet.address_raw(), Some(Duration::from_secs(30)))
            .unwrap());

        // Should pass with 200 second expiry
        assert!(old_signed
            .verify_hashable(&test_data, wallet.address_raw(), Some(Duration::from_secs(200)))
            .unwrap());
    }

    #[test]
    fn test_different_wallets_different_signatures() {
        let wallet1 = Wallet::new().unwrap();
        let wallet2 = Wallet::new().unwrap();
        let test_data = "same message";

        let signed1 = SignedRequest::<QHashOut<GoldilocksField>>::sign_hashable(&wallet1, &test_data).unwrap();
        let signed2 = SignedRequest::<QHashOut<GoldilocksField>>::sign_hashable(&wallet2, &test_data).unwrap();

        // Different wallets should produce different signatures
        assert_ne!(signed1.signature, signed2.signature);
        assert_ne!(signed1.address, signed2.address);

        // Each should verify with their own data
        assert!(signed1.verify_hashable(&test_data, wallet1.address_raw(), None).unwrap());
        assert!(signed2.verify_hashable(&test_data, wallet2.address_raw(), None).unwrap());
    }
}
