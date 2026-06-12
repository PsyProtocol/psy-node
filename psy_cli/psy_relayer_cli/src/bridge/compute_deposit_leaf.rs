use alloy_primitives::{Address, B256, U256};
use clap::Args;
use parth_core::{felt::ToU64Value, pgoldilocks::QHashOut};
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::{Field, PrimeField64}},
    hash::poseidon::PoseidonHash,
    plonk::config::Hasher,
};
use serde::Serialize;

const WORDS_PER_BYTES32: usize = 8;

#[derive(Debug, Clone, Args)]
pub struct ComputeDepositLeafArgs {
    #[arg(long)]
    pub shield_address: B256,
    #[arg(long)]
    pub token: Address,
    #[arg(long)]
    pub l2_token_contract_id: B256,
    #[arg(long)]
    pub amount: U256,
    #[arg(long)]
    pub chain_index: u32,
    #[arg(long)]
    pub note_secret_hash: B256,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComputeDepositLeafResult {
    pub leaf_hex: String,
    pub leaf_words: [u32; WORDS_PER_BYTES32],
    pub append_inputs: Vec<u32>,
}

pub fn run(args: ComputeDepositLeafArgs) -> anyhow::Result<()> {
    let result = compute(args);
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

pub fn compute(args: ComputeDepositLeafArgs) -> ComputeDepositLeafResult {
    let shield_address = bytes32_to_u32x8(args.shield_address);
    let token = address_to_u32x8(args.token);
    let l2_token_contract_id = bytes32_to_u32x8(args.l2_token_contract_id);
    let amount = u256_to_u32x8(args.amount);
    let note_secret_hash = bytes32_to_u32x8(args.note_secret_hash);

    let words = [
        shield_address.as_slice(),
        token.as_slice(),
        l2_token_contract_id.as_slice(),
        amount.as_slice(),
    ]
    .into_iter()
    .flatten()
    .copied()
    .chain([args.chain_index])
    .chain(note_secret_hash)
    .collect::<Vec<_>>();

    let leaf = poseidon_hash_u32_words(words.iter().map(|v| *v as u64));
    let leaf_words = qhashout_to_u32x8_internal(leaf);
    let append_inputs = std::iter::once(args.chain_index)
        .chain(leaf_words)
        .collect::<Vec<_>>();

    ComputeDepositLeafResult {
        leaf_hex: u32x8_be_to_hex(leaf_words),
        leaf_words,
        append_inputs,
    }
}

fn poseidon_hash_u32_words(words: impl IntoIterator<Item = u64>) -> QHashOut<GoldilocksField> {
    let felts = words
        .into_iter()
        .map(GoldilocksField::from_canonical_u64)
        .collect::<Vec<_>>();
    QHashOut(PoseidonHash::hash_no_pad(&felts))
}

fn qhashout_to_u32x8_internal(hash: QHashOut<GoldilocksField>) -> [u32; WORDS_PER_BYTES32] {
    let elems = hash.0.elements;
    [
        (elems[0].to_u64_value() & 0xffff_ffff) as u32,
        (elems[0].to_u64_value() >> 32) as u32,
        (elems[1].to_u64_value() & 0xffff_ffff) as u32,
        (elems[1].to_u64_value() >> 32) as u32,
        (elems[2].to_u64_value() & 0xffff_ffff) as u32,
        (elems[2].to_u64_value() >> 32) as u32,
        (elems[3].to_u64_value() & 0xffff_ffff) as u32,
        (elems[3].to_u64_value() >> 32) as u32,
    ]
}

fn u32x8_be_to_hex(words: [u32; WORDS_PER_BYTES32]) -> String {
    let mut bytes = [0u8; 32];
    for (i, &w) in words.iter().enumerate() {
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&w.to_be_bytes());
    }
    format!("0x{}", hex::encode(bytes))
}

fn bytes32_to_u32x8(bytes32: B256) -> [u32; WORDS_PER_BYTES32] {
    let bytes = bytes32.as_slice();
    std::array::from_fn(|i| {
        let start = i * 4;
        u32::from_be_bytes(bytes[start..start + 4].try_into().unwrap())
    })
}

fn u256_to_u32x8(value: U256) -> [u32; WORDS_PER_BYTES32] {
    let bytes = value.to_be_bytes::<32>();
    std::array::from_fn(|i| {
        let start = i * 4;
        u32::from_be_bytes(bytes[start..start + 4].try_into().unwrap())
    })
}

fn address_to_u32x8(address: Address) -> [u32; WORDS_PER_BYTES32] {
    let mut bytes = [0u8; 32];
    bytes[12..].copy_from_slice(address.as_slice());
    bytes32_to_u32x8(B256::from(bytes))
}
