use plonky2::field::{
    goldilocks_field::GoldilocksField,
    types::{Field, PrimeField64},
};
use psy_client_common::data::qhashout::QHashOut;

use crate::hash::traits::hasher::{FieldQHasher, PoseidonHasher};

pub const SHIELD_ADDRESS_DOMAIN: u64 = 1337;

pub fn derive_shield_address(user_id: u64, r0: u64, r1: u64) -> QHashOut<GoldilocksField> {
    PoseidonHasher::q_hash_many(&[
        GoldilocksField::from_canonical_u64(user_id),
        GoldilocksField::from_canonical_u64(SHIELD_ADDRESS_DOMAIN),
        GoldilocksField::from_canonical_u64(r0),
        GoldilocksField::from_canonical_u64(r1),
    ])
}

pub fn derive_nullifier_hash(nullifier_secret: [u64; 4]) -> QHashOut<GoldilocksField> {
    PoseidonHasher::q_hash_many(&[
        GoldilocksField::from_canonical_u64(nullifier_secret[0]),
        GoldilocksField::from_canonical_u64(nullifier_secret[1]),
        GoldilocksField::from_canonical_u64(nullifier_secret[2]),
        GoldilocksField::from_canonical_u64(nullifier_secret[3]),
    ])
}

pub fn derive_note_commitment(nullifier_secret: [u64; 4], note_secret: [u64; 4]) -> QHashOut<GoldilocksField> {
    PoseidonHasher::q_hash_many(&[
        GoldilocksField::from_canonical_u64(nullifier_secret[0]),
        GoldilocksField::from_canonical_u64(nullifier_secret[1]),
        GoldilocksField::from_canonical_u64(nullifier_secret[2]),
        GoldilocksField::from_canonical_u64(nullifier_secret[3]),
        GoldilocksField::from_canonical_u64(note_secret[0]),
        GoldilocksField::from_canonical_u64(note_secret[1]),
        GoldilocksField::from_canonical_u64(note_secret[2]),
        GoldilocksField::from_canonical_u64(note_secret[3]),
    ])
}

pub fn derive_deposit_commitment(
    shield_address: QHashOut<GoldilocksField>,
    token: [u32; 8],
    l2_token_contract_id: [u32; 8],
    amount: [u32; 8],
    source_chain_index: u32,
    note_commitment: [u64; 4],
) -> QHashOut<GoldilocksField> {
    let shield_words = qhashout_to_u32x8_be(shield_address);
    let mut inputs = Vec::with_capacity(41);
    inputs.extend(shield_words.into_iter().map(|x| GoldilocksField::from_canonical_u64(x as u64)));
    inputs.extend(token.into_iter().map(|x| GoldilocksField::from_canonical_u64(x as u64)));
    inputs.extend(l2_token_contract_id.into_iter().map(|x| GoldilocksField::from_canonical_u64(x as u64)));
    inputs.extend(amount.into_iter().map(|x| GoldilocksField::from_canonical_u64(x as u64)));
    inputs.push(GoldilocksField::from_canonical_u64(source_chain_index as u64));
    for limb in note_commitment {
        inputs.push(GoldilocksField::from_canonical_u64((limb >> 32) as u32 as u64));
        inputs.push(GoldilocksField::from_canonical_u64((limb & 0xffff_ffff) as u32 as u64));
    }
    PoseidonHasher::q_hash_many(&inputs)
}

pub fn qhashout_to_u32x8_be(hash: QHashOut<GoldilocksField>) -> [u32; 8] {
    [
        (hash.0.elements[0].to_canonical_u64() >> 32) as u32,
        (hash.0.elements[0].to_canonical_u64() & 0xffff_ffff) as u32,
        (hash.0.elements[1].to_canonical_u64() >> 32) as u32,
        (hash.0.elements[1].to_canonical_u64() & 0xffff_ffff) as u32,
        (hash.0.elements[2].to_canonical_u64() >> 32) as u32,
        (hash.0.elements[2].to_canonical_u64() & 0xffff_ffff) as u32,
        (hash.0.elements[3].to_canonical_u64() >> 32) as u32,
        (hash.0.elements[3].to_canonical_u64() & 0xffff_ffff) as u32,
    ]
}

pub fn qhashout_to_bytes32_be(hash: QHashOut<GoldilocksField>) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, element) in hash.0.elements.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&element.to_canonical_u64().to_be_bytes());
    }
    out
}

pub fn shield_address_to_bytes32(addr: QHashOut<GoldilocksField>) -> [u8; 32] {
    qhashout_to_bytes32_be(addr)
}

pub fn shield_address_from_bytes32(bytes: [u8; 32]) -> QHashOut<GoldilocksField> {
    let words: [u64; 4] = std::array::from_fn(|i| {
        let start = i * 8;
        u64::from_be_bytes(bytes[start..start + 8].try_into().unwrap())
    });
    QHashOut::from_values(words[0], words[1], words[2], words[3])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn note_commitment_binds_nullifier_and_note_secret() {
        let note_secret = [10, 20, 30, 40];
        let nullifier_a = [1, 2, 3, 4];
        let nullifier_b = [5, 2, 3, 4];

        let first = derive_note_commitment(nullifier_a, note_secret);
        assert_eq!(first, derive_note_commitment(nullifier_a, note_secret));
        assert_ne!(first, derive_note_commitment(nullifier_b, note_secret));
        assert_ne!(first, derive_note_commitment(nullifier_a, [10, 20, 30, 41]));
    }
}
