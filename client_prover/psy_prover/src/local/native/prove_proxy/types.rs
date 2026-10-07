use parth_core::pgoldilocks::QHashOut as ParthQHashOut;
use plonky2::{
    field::types::{Field, PrimeField64},
    hash::hash_types::HashOut,
};
use psy_plonky2_circuits::bridge::circuits::bridge_wrap::UncompressedGroth16ProofData;

use super::F;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BridgeWithdrawalWitnessInput {
    pub withdrawal_root: String,
    pub sender_user_id: u32,
    pub recipient: [u32; 8],
    pub token: [u32; 8],
    pub amount: [u32; 8],
    pub nonce: [u32; 8],
    pub destination_chain_index: u32,
    pub leaf_index: u32,
    pub bridge_user_id: u32,
    pub siblings: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BridgeWithdrawalBatchWitnessInput {
    pub bridge_user_id: u32,
    pub withdrawals: Vec<BridgeWithdrawalWitnessInput>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BridgeWithdrawalBatchGroth16Proof {
    pub solidity_proof: [String; 8],
    pub public_inputs: Vec<u64>,
    pub slot_data: Vec<u64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BridgeDepositLeafInput {
    pub shield_address: [u32; 8],
    pub token: [u32; 8],
    pub l2_token_contract_id: [u32; 8],
    pub amount: [u32; 8],
    pub chain_index: u32,
    pub note_commitment: [u32; 8],
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BridgeDepositBatchWitnessInput {
    pub from_index: u32,
    pub bridge_user_id: u32,
    pub old_frontier: Vec<String>,
    pub deposits: Vec<BridgeDepositLeafInput>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BridgeDepositBatchGroth16Proof {
    pub solidity_proof: [String; 8],
    pub public_inputs: Vec<u64>,
}

pub fn parse_hex_qhashout(hex: &str) -> anyhow::Result<ParthQHashOut<F>> {
    let hex = hex.trim_start_matches("0x");
    anyhow::ensure!(hex.len() == 64, "expected 64 hex chars, got {}", hex.len());
    let bytes = hex::decode(hex)?;
    let mut elems = [0u64; 4];
    for i in 0..4 {
        let reverse_i = 3 - i;
        let hi = u32::from_be_bytes(bytes[reverse_i * 8..reverse_i * 8 + 4].try_into()?);
        let lo = u32::from_be_bytes(bytes[reverse_i * 8 + 4..reverse_i * 8 + 8].try_into()?);
        elems[i] = ((hi as u64) << 32) | (lo as u64);
    }
    Ok(ParthQHashOut(HashOut {
        elements: elems.map(F::from_canonical_u64),
    }))
}

pub fn g16_proof_to_solidity_words(groth16: &UncompressedGroth16ProofData) -> [String; 8] {
    let with_0x = |s: &str| -> String {
        if s.starts_with("0x") {
            s.to_string()
        } else {
            format!("0x{}", s)
        }
    };
    [
        with_0x(&groth16.pi_a[0]),
        with_0x(&groth16.pi_a[1]),
        with_0x(&groth16.pi_b[0][1]),
        with_0x(&groth16.pi_b[0][0]),
        with_0x(&groth16.pi_b[1][1]),
        with_0x(&groth16.pi_b[1][0]),
        with_0x(&groth16.pi_c[0]),
        with_0x(&groth16.pi_c[1]),
    ]
}

pub fn parse_hex_qhashout_to_qhash(h: &str) -> anyhow::Result<parth_core::pgoldilocks::QHashOut<F>> {
    let pq = parse_hex_qhashout(h)?;
    Ok(parth_core::pgoldilocks::QHashOut(pq.0))
}

pub fn felt4_to_bytes32_hex(felts: &[F]) -> String {
    let mut out = [0u8; 32];
    for i in 0..4 {
        let v = felts[3 - i].to_canonical_u64();
        out[i * 8..(i + 1) * 8].copy_from_slice(&v.to_be_bytes());
    }
    format!("0x{}", hex::encode(out))
}

pub fn u32x8_to_bytes32_hex(felts: &[F]) -> String {
    let mut out = [0u8; 32];
    for i in 0..8 {
        let v = felts[i].to_canonical_u64() as u32;
        out[i * 4..(i + 1) * 4].copy_from_slice(&v.to_be_bytes());
    }
    format!("0x{}", hex::encode(out))
}

/// Parses the internal u32x8 word encoding (eight big-endian u32 words per
/// 32-byte hash, little-endian limb pairs within each u64 felt).
pub fn parse_internal_u32x8_qhashout(hex_str: &str) -> anyhow::Result<ParthQHashOut<F>> {
    let hex_str = hex_str.trim_start_matches("0x");
    anyhow::ensure!(hex_str.len() == 64, "expected 64 hex chars, got {}", hex_str.len());
    let bytes = hex::decode(hex_str)?;
    let mut words = [0u32; 8];
    for i in 0..8 {
        words[i] = u32::from_be_bytes(bytes[i * 4..i * 4 + 4].try_into()?);
    }
    let elems = [
        ((words[1] as u64) << 32) | words[0] as u64,
        ((words[3] as u64) << 32) | words[2] as u64,
        ((words[5] as u64) << 32) | words[4] as u64,
        ((words[7] as u64) << 32) | words[6] as u64,
    ];
    Ok(ParthQHashOut(HashOut {
        elements: elems.map(F::from_canonical_u64),
    }))
}

pub fn qhashout_from_felts(elems: &[F]) -> parth_core::pgoldilocks::QHashOut<F> {
    parth_core::pgoldilocks::QHashOut(HashOut {
        elements: [elems[0], elems[1], elems[2], elems[3]],
    })
}
