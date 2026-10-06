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

// ── Bridge Aggregation Types ─────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BridgeAggCheckpointLeaf {
    pub global_chain_root: String,
    pub stats_hash: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BridgeAggGlobalStateRoots {
    pub contract_tree_root: String,
    pub deposit_tree_root: String,
    pub user_tree_root: String,
    pub withdrawal_tree_root: String,
    pub user_registration_tree_root: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BridgeAggSlotWitness {
    pub owner_user_id: u64,
    pub contract_id: u64,
    pub user_leaf_public_key: String,
    pub user_leaf_user_state_tree_root: String,
    pub user_leaf_balance: u64,
    pub user_leaf_nonce: u64,
    pub user_leaf_last_checkpoint_id: u64,
    pub user_leaf_event_index: u64,
    pub user_leaf_user_id: u64,
    pub slot0_root: String,
    pub slot0_value: String,
    pub slot0_index: u64,
    pub slot0_siblings: Vec<String>,
    pub slot1_root: String,
    pub slot1_value: String,
    pub slot1_index: u64,
    pub slot1_siblings: Vec<String>,
    pub contract_root: String,
    pub contract_value: String,
    pub contract_index: u64,
    pub contract_siblings: Vec<String>,
    pub user_tree_root: String,
    pub user_tree_value: String,
    pub user_tree_index: u64,
    pub user_tree_siblings: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BridgeAggDeltaProof {
    pub index: u64,
    pub new_value: String,
    pub siblings: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BridgeAggWitnessInput {
    pub from_checkpoint: u64,
    pub to_checkpoint: u64,
    /// Bincode-serialized ProofWithPublicInputs for the final (to_checkpoint)
    /// checkpoint state transition proof, hex-encoded.
    pub final_checkpoint_proof_hex: String,
    pub delta_merkle_proofs: Vec<BridgeAggDeltaProof>,
    pub pre_delta_merkle_proofs: Vec<BridgeAggDeltaProof>,
    /// Chain hash immediately before the aggregated range (chain hash of
    /// checkpoint `from_checkpoint - 1`; for `from_checkpoint <= 1` this is the
    /// genesis checkpoint state transition hash).
    pub chain_start: String,
    /// Checkpoint state transition circuit fingerprint (hex).
    /// Must match the fingerprint the coordinator used when generating
    /// checkpoint proofs.
    pub checkpoint_fp: String,
    pub final_checkpoint_leaf: BridgeAggCheckpointLeaf,
    pub final_checkpoint_global_state_roots: BridgeAggGlobalStateRoots,
    pub deposit_witness: BridgeAggSlotWitness,
    pub withdrawal_witness: BridgeAggSlotWitness,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BridgeAggGroth16Output {
    pub from_checkpoint: u64,
    pub to_checkpoint: u64,
    pub num_checkpoints_aggregated: u64,
    pub bridge_agg_public_inputs_count: usize,
    pub bridge_agg_public_inputs: Vec<String>,
    pub groth16_proof: UncompressedGroth16ProofData,
    pub solidity_proof: [String; 8],
    pub solidity_public_inputs: [String; 2],
    pub checkpoint_roots: Vec<String>,
    pub deposit_tree_root: String,
    pub withdrawal_tree_root: String,
    pub end_checkpoint_index: u64,
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
