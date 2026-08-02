use std::fmt::{Display, Formatter};

use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::PrimeField64},
    plonk::{
        circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
        config::PoseidonGoldilocksConfig,
        proof::ProofWithPublicInputs,
        verifier_helper::verify_proof_borrowed,
    },
    util::serialization::DefaultGateSerializer,
};
use serde::{Deserialize, Serialize};

const EXPECTED_NUM_PUBLIC_INPUTS: usize = 52;
const D: usize = 2;
type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProgramContext {
    pub domain_tag: String,
    pub chain_id: u64,
    pub app_version: u32,
}

#[derive(Debug)]
pub enum ProgramError {
    Deserialize(String),
    InvalidContext(String),
    Verify(String),
}

impl Display for ProgramError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ProgramError::Deserialize(msg) => write!(f, "deserialize error: {msg}"),
            ProgramError::InvalidContext(msg) => write!(f, "invalid context: {msg}"),
            ProgramError::Verify(msg) => write!(f, "verify error: {msg}"),
        }
    }
}

impl std::error::Error for ProgramError {}

pub fn verify_plonky2_artifacts(
    proof_bytes: Vec<u8>,
    verifier_only_bytes: Vec<u8>,
    common_data_bytes: Vec<u8>,
    context_bytes: &[u8],
) -> Result<Vec<u64>, ProgramError> {
    let context = parse_context(context_bytes)?;
    validate_context(&context)?;

    if proof_bytes.is_empty() {
        return Err(ProgramError::Verify("proof_bytes must not be empty".to_string()));
    }
    if verifier_only_bytes.is_empty() {
        return Err(ProgramError::Verify("verifier_only_bytes must not be empty".to_string()));
    }
    if common_data_bytes.is_empty() {
        return Err(ProgramError::Verify("common_data_bytes must not be empty".to_string()));
    }

    // Use DefaultGateSerializer directly without storing
    let gate_serializer = DefaultGateSerializer;

    let common_data = CommonCircuitData::<F, D>::from_bytes(common_data_bytes, &gate_serializer)
        .map_err(|e| ProgramError::Deserialize(format!("common_data decode failed: {e}")))?;
    let verifier_only = VerifierOnlyCircuitData::<C, D>::from_bytes(verifier_only_bytes)
        .map_err(|e| ProgramError::Deserialize(format!("verifier_only decode failed: {e}")))?;
    let proof = ProofWithPublicInputs::<F, C, D>::from_bytes(proof_bytes, &common_data)
        .map_err(|e| ProgramError::Deserialize(format!("proof decode failed: {e}")))?;

    verify_proof_borrowed(&proof, &verifier_only, &common_data)
        .map_err(|e| ProgramError::Verify(format!("proof verification failed: {e}")))?;

    if proof.public_inputs.len() != EXPECTED_NUM_PUBLIC_INPUTS {
        return Err(ProgramError::Verify(format!(
            "unexpected public input length: got {}, expected {}",
            proof.public_inputs.len(),
            EXPECTED_NUM_PUBLIC_INPUTS
        )));
    }

    Ok(proof.public_inputs.iter().map(|x| x.to_canonical_u64()).collect())
}

fn parse_context(context_bytes: &[u8]) -> Result<ProgramContext, ProgramError> {
    // Binary format (versioned):
    // [1 byte version=1][8 bytes chain_id][4 bytes app_version][1 byte domain_len][domain bytes]
    if !context_bytes.is_empty() && context_bytes[0] == 1u8 {
        if context_bytes.len() < 14 {
            return Err(ProgramError::Deserialize("binary context too short".to_string()));
        }
        let mut chain_id_bytes = [0u8; 8];
        chain_id_bytes.copy_from_slice(&context_bytes[1..9]);
        let mut app_version_bytes = [0u8; 4];
        app_version_bytes.copy_from_slice(&context_bytes[9..13]);
        let domain_len = context_bytes[13] as usize;
        let expected_len = 14 + domain_len;
        if context_bytes.len() != expected_len {
            return Err(ProgramError::Deserialize(format!(
                "binary context length mismatch: expected {}, got {}",
                expected_len,
                context_bytes.len()
            )));
        }
        let domain = std::str::from_utf8(&context_bytes[14..])
            .map_err(|e| ProgramError::Deserialize(format!("binary domain utf8 error: {e}")))?;
        return Ok(ProgramContext {
            domain_tag: domain.to_string(),
            chain_id: u64::from_be_bytes(chain_id_bytes),
            app_version: u32::from_be_bytes(app_version_bytes),
        });
    }

    serde_json::from_slice(context_bytes).map_err(|e| ProgramError::Deserialize(format!("context decode failed: {e}")))
}

fn validate_context(context: &ProgramContext) -> Result<(), ProgramError> {
    if context.domain_tag.trim().is_empty() {
        return Err(ProgramError::InvalidContext("domain_tag cannot be empty".to_string()));
    }
    if context.domain_tag != "psy-plonky2-groth16-v1" {
        return Err(ProgramError::InvalidContext(format!(
            "unexpected domain_tag: {}",
            context.domain_tag
        )));
    }
    if context.chain_id == 0 {
        return Err(ProgramError::InvalidContext("chain_id must be non-zero".to_string()));
    }
    if context.app_version == 0 {
        return Err(ProgramError::InvalidContext("app_version must be non-zero".to_string()));
    }
    Ok(())
}

/// Compute public inputs hash using SP1 Keccak256 precompile
/// Format: keccak256(domain_tag || len(public_inputs) || public_inputs...)
pub fn compute_public_inputs_hash(public_inputs: &[u64]) -> [u8; 32] {
    // Build input buffer
    // Layout: domain_tag (32 bytes) || len (8 bytes) || public_inputs (52 * 8 bytes)
    // Total: 32 + 8 + 416 = 456 bytes
    let total_len = 32 + 8 + public_inputs.len() * 8;
    let mut buf = Vec::with_capacity(total_len);

    // Domain tag as bytes: "psy/plonky2/public-inputs/v1" (27 bytes) padded to 32
    let domain_bytes: [u8; 32] = *b"psy/plonky2/public-inputs/v1\0\0\0\0";
    buf.extend_from_slice(&domain_bytes);

    // Length as u64 in big-endian
    buf.extend_from_slice(&(public_inputs.len() as u64).to_be_bytes());

    // Public inputs as big-endian u64 values
    for &value in public_inputs {
        buf.extend_from_slice(&value.to_be_bytes());
    }

    // Use SP1 keccak256 precompile via Keccak256
    keccak256(&buf)
}

/// Compute Keccak256 hash using tiny_keccak (SP1 patch optimizes this)
#[inline]
fn keccak256(data: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

pub fn split_hash_to_bn254(hash: &[u8; 32]) -> (u128, u128) {
    let mut hi_bytes = [0u8; 16];
    let mut lo_bytes = [0u8; 16];
    hi_bytes.copy_from_slice(&hash[0..16]);
    lo_bytes.copy_from_slice(&hash[16..32]);
    (u128::from_be_bytes(hi_bytes), u128::from_be_bytes(lo_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_public_inputs_hash() {
        let public_inputs = vec![0u64; 52];
        let hash = compute_public_inputs_hash(&public_inputs);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_split_hash_to_bn254() {
        let hash: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
            0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        ];
        let (hi, lo) = split_hash_to_bn254(&hash);
        assert_eq!(hi, 0x0102030405060708090A0B0C0D0E0F10u128);
        assert_eq!(lo, 0x1112131415161718191A1B1C1D1E1F20u128);
    }

    #[test]
    fn test_parse_context_valid_json() {
        // Valid context in JSON format
        let context_bytes = br#"{"domain_tag":"psy-plonky2-groth16-v1","chain_id":1,"app_version":1}"#.to_vec();
        let ctx = parse_context(&context_bytes).expect("json context should parse");
        assert_eq!(ctx.domain_tag, "psy-plonky2-groth16-v1");
    }

    #[test]
    fn test_validate_context_wrong_domain() {
        let context_bytes = br#"{"domain_tag":"wrong-domain","chain_id":1,"app_version":1}"#.to_vec();
        let ctx = parse_context(&context_bytes).expect("context should parse");
        assert!(validate_context(&ctx).is_err());
    }

    #[test]
    fn test_validate_context_zero_chain_id() {
        let context_bytes = br#"{"domain_tag":"psy-plonky2-groth16-v1","chain_id":0,"app_version":1}"#.to_vec();
        let ctx = parse_context(&context_bytes).expect("context should parse");
        assert!(validate_context(&ctx).is_err());
    }

    #[test]
    fn test_validate_context_zero_app_version() {
        let context_bytes = br#"{"domain_tag":"psy-plonky2-groth16-v1","chain_id":1,"app_version":0}"#.to_vec();
        let ctx = parse_context(&context_bytes).expect("context should parse");
        assert!(validate_context(&ctx).is_err());
    }

    #[test]
    fn test_parse_context_valid_binary() {
        let domain = b"psy-plonky2-groth16-v1";
        let mut bytes = Vec::new();
        bytes.push(1u8);
        bytes.extend_from_slice(&1u64.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.push(domain.len() as u8);
        bytes.extend_from_slice(domain);
        let ctx = parse_context(&bytes).expect("binary context should parse");
        assert_eq!(ctx.domain_tag, "psy-plonky2-groth16-v1");
        assert_eq!(ctx.chain_id, 1);
        assert_eq!(ctx.app_version, 1);
    }

    #[test]
    fn test_verify_plonky2_artifacts_empty_proof() {
        let context_bytes = br#"{"domain_tag":"psy-plonky2-groth16-v1","chain_id":1,"app_version":1}"#.to_vec();

        let result = verify_plonky2_artifacts(
            vec![],  // empty proof
            vec![1],
            vec![1],
            &context_bytes,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_program_error_display() {
        let err = ProgramError::Deserialize("test error".to_string());
        assert_eq!(format!("{}", err), "deserialize error: test error");

        let err = ProgramError::InvalidContext("context error".to_string());
        assert_eq!(format!("{}", err), "invalid context: context error");

        let err = ProgramError::Verify("verify error".to_string());
        assert_eq!(format!("{}", err), "verify error: verify error");
    }

    #[test]
    fn test_keccak256_output() {
        // Verify keccak256 produces consistent output
        let data = b"test data";
        let hash1 = keccak256(data);
        let hash2 = keccak256(data);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }
}

