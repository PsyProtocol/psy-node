//! Shared types for SP1 Plonky2 Adapter

use serde::{Deserialize, Serialize};

pub const PUBLIC_VALUES_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Groth16PublicValues {
    pub digest_hi: u128,
    pub digest_lo: u128,
    pub num_public_inputs: u32,
    pub schema_version: u32,
}

impl Groth16PublicValues {
    pub fn new(digest_hi: u128, digest_lo: u128, num_public_inputs: usize) -> Self {
        Self {
            digest_hi,
            digest_lo,
            num_public_inputs: num_public_inputs as u32,
            schema_version: PUBLIC_VALUES_SCHEMA_VERSION,
        }
    }

    pub fn abi_encode(&self) -> Vec<u8> {
        // Canonical ABI-like fixed layout: 4 x 32-byte words (big-endian).
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(&u128_to_u256_word_be(self.digest_hi));
        out.extend_from_slice(&u128_to_u256_word_be(self.digest_lo));
        out.extend_from_slice(&u32_to_u256_word_be(self.num_public_inputs));
        out.extend_from_slice(&u32_to_u256_word_be(self.schema_version));
        out
    }

    pub fn abi_decode(data: &[u8]) -> Result<Self, String> {
        if data.len() != 128 {
            return Err(format!("invalid public values length: expected 128, got {}", data.len()));
        }
        let digest_hi = u256_word_be_to_u128(&data[0..32])?;
        let digest_lo = u256_word_be_to_u128(&data[32..64])?;
        let num_public_inputs = u256_word_be_to_u32(&data[64..96])?;
        let schema_version = u256_word_be_to_u32(&data[96..128])?;
        Ok(Self {
            digest_hi,
            digest_lo,
            num_public_inputs,
            schema_version,
        })
    }
}

fn u128_to_u256_word_be(value: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..32].copy_from_slice(&value.to_be_bytes());
    out
}

fn u32_to_u256_word_be(value: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[28..32].copy_from_slice(&value.to_be_bytes());
    out
}

fn u256_word_be_to_u128(word: &[u8]) -> Result<u128, String> {
    if word.len() != 32 {
        return Err("word size must be 32 bytes".to_string());
    }
    if word[..16].iter().any(|b| *b != 0) {
        return Err("u256 value does not fit in u128".to_string());
    }
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&word[16..32]);
    Ok(u128::from_be_bytes(bytes))
}

fn u256_word_be_to_u32(word: &[u8]) -> Result<u32, String> {
    if word.len() != 32 {
        return Err("word size must be 32 bytes".to_string());
    }
    if word[..28].iter().any(|b| *b != 0) {
        return Err("u256 value does not fit in u32".to_string());
    }
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&word[28..32]);
    Ok(u32::from_be_bytes(bytes))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterContext {
    pub domain_tag: String,
    pub chain_id: u64,
    pub app_version: u32,
}

impl AdapterContext {
    pub fn encode_bytes(&self) -> Vec<u8> {
        let domain = self.domain_tag.as_bytes();
        let mut out = Vec::with_capacity(14 + domain.len());
        out.push(1u8);
        out.extend_from_slice(&self.chain_id.to_be_bytes());
        out.extend_from_slice(&self.app_version.to_be_bytes());
        out.push(domain.len() as u8);
        out.extend_from_slice(domain);
        out
    }

    pub fn decode_bytes(data: &[u8]) -> anyhow::Result<Self> {
        if !data.is_empty() && data[0] == 1u8 {
            if data.len() < 14 {
                anyhow::bail!("binary context too short");
            }
            let mut chain_id_bytes = [0u8; 8];
            chain_id_bytes.copy_from_slice(&data[1..9]);
            let mut app_version_bytes = [0u8; 4];
            app_version_bytes.copy_from_slice(&data[9..13]);
            let domain_len = data[13] as usize;
            let expected_len = 14 + domain_len;
            if data.len() != expected_len {
                anyhow::bail!(
                    "binary context length mismatch: expected {}, got {}",
                    expected_len,
                    data.len()
                );
            }
            let domain_tag = std::str::from_utf8(&data[14..])
                .map_err(|e| anyhow::anyhow!("binary domain utf8 error: {e}"))?
                .to_string();
            return Ok(Self {
                domain_tag,
                chain_id: u64::from_be_bytes(chain_id_bytes),
                app_version: u32::from_be_bytes(app_version_bytes),
            });
        }
        Ok(serde_json::from_slice(data)?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlonkProofFixture {
    pub proof_bytes: Vec<u8>,
    pub verifier_only_bytes: Vec<u8>,
    pub common_data_bytes: Vec<u8>,
    pub context_bytes: Vec<u8>,
}

impl PlonkProofFixture {
    pub fn from_json(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let fixture = serde_json::from_str(&content)?;
        Ok(fixture)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.proof_bytes.is_empty() {
            anyhow::bail!("proof_bytes must not be empty");
        }
        if self.verifier_only_bytes.is_empty() {
            anyhow::bail!("verifier_only_bytes must not be empty");
        }
        if self.common_data_bytes.is_empty() {
            anyhow::bail!("common_data_bytes must not be empty");
        }
        if self.context_bytes.is_empty() {
            anyhow::bail!("context_bytes must not be empty");
        }

        let context = AdapterContext::decode_bytes(&self.context_bytes)?;
        if context.domain_tag != "psy-plonky2-groth16-v1" {
            anyhow::bail!("invalid domain_tag: {}", context.domain_tag);
        }
        if context.chain_id == 0 {
            anyhow::bail!("chain_id must be non-zero");
        }
        if context.app_version == 0 {
            anyhow::bail!("app_version must be non-zero");
        }
        Ok(())
    }
}

pub fn create_dummy_fixture() -> PlonkProofFixture {
    let context = AdapterContext {
        domain_tag: "psy-plonky2-groth16-v1".to_string(),
        chain_id: 1,
        app_version: 1,
    };
    PlonkProofFixture {
        proof_bytes: vec![0u8; 1],
        verifier_only_bytes: vec![0u8; 1],
        common_data_bytes: vec![0u8; 1],
        context_bytes: context.encode_bytes(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_groth16_public_values_new() {
        let pv = Groth16PublicValues::new(123, 456, 52);

        assert_eq!(pv.digest_hi, 123);
        assert_eq!(pv.digest_lo, 456);
        assert_eq!(pv.num_public_inputs, 52);
        assert_eq!(pv.schema_version, PUBLIC_VALUES_SCHEMA_VERSION);
    }

    #[test]
    fn test_abi_encode() {
        let pv = Groth16PublicValues::new(0x1234, 0x5678, 52);
        let encoded = pv.abi_encode();

        // Four uint256 fields.
        assert_eq!(encoded.len(), 128);
    }

    #[test]
    fn test_abi_decode() {
        let pv = Groth16PublicValues::new(0x1234, 0x5678, 52);
        let decoded = Groth16PublicValues::abi_decode(&pv.abi_encode()).unwrap();

        assert_eq!(decoded.digest_hi, 0x1234);
        assert_eq!(decoded.digest_lo, 0x5678);
        assert_eq!(decoded.num_public_inputs, 52);
        assert_eq!(decoded.schema_version, PUBLIC_VALUES_SCHEMA_VERSION);
    }

    #[test]
    fn test_dummy_fixture() {
        let fixture = create_dummy_fixture();
        assert!(!fixture.proof_bytes.is_empty());
        assert!(!fixture.common_data_bytes.is_empty());
    }
}
