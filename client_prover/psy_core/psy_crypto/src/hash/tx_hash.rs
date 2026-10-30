use kvq::traits::KVQSerializable;
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64},
    },
    hash::poseidon::PoseidonHash,
};
use psy_client_common::{data::qhashout::QHashOut, traits::to_qfelts::ToQFelts};

use crate::hash::traits::hasher::FieldQHasher;

type F = GoldilocksField;
type Hash = QHashOut<F>;

pub fn compute_deploy_contract_content_hash(deployer: u64, function_tree_root: &[u8; 32], state_tree_height: u64) -> [u8; 32] {
    let function_root_felts = bytes32_to_felts(function_tree_root);

    let hash = PoseidonHash::q_hash_many(&[
        u64_to_felt(deployer),
        function_root_felts[0],
        function_root_felts[1],
        function_root_felts[2],
        function_root_felts[3],
        u64_to_felt(state_tree_height),
    ]);

    hash_to_bytes(&hash)
}

pub fn compute_update_contract_content_hash(
    contract_id: u64,
    deployer: u64,
    function_tree_root: &[u8; 32],
    state_tree_height: u64,
) -> [u8; 32] {
    let function_root_felts = bytes32_to_felts(function_tree_root);

    let hash = PoseidonHash::q_hash_many(&[
        u64_to_felt(contract_id),
        u64_to_felt(deployer),
        function_root_felts[0],
        function_root_felts[1],
        function_root_felts[2],
        function_root_felts[3],
        u64_to_felt(state_tree_height),
    ]);

    hash_to_bytes(&hash)
}

/// Domain separator binding a contract update authorization to this protocol.
const UPDATE_CONTRACT_AUTH_DOMAIN: &[u8; 27] = b"PSY_UPDATE_CONTRACT_AUTH_V1";

/// Binds an update authorization to the exact update it approves:
/// poseidon(update_content, old_leaf, code_root, code_definition, layout_proof),
/// two-to-one with poseidon(domain, network_magic).
pub fn compute_update_contract_auth_hash(
    network_magic: u64,
    update_content_hash: &[u8; 32],
    old_leaf_hash: &[u8; 32],
    code_root: &[u8; 32],
    code_definition_hash: &[u8; 32],
    canonical_layout_proof_hash: &[u8; 32],
) -> [u8; 32] {
    let domain_bytes = {
        let mut bytes = [0u8; 32];
        bytes[..UPDATE_CONTRACT_AUTH_DOMAIN.len()].copy_from_slice(UPDATE_CONTRACT_AUTH_DOMAIN);
        bytes
    };
    let domain_felts = bytes32_to_felts(&domain_bytes);
    let domain_hash = PoseidonHash::q_hash_many(&[
        domain_felts[0],
        domain_felts[1],
        domain_felts[2],
        domain_felts[3],
        u64_to_felt(network_magic),
    ]);

    let update_felts = bytes32_to_felts(update_content_hash);
    let old_leaf_felts = bytes32_to_felts(old_leaf_hash);
    let code_root_felts = bytes32_to_felts(code_root);
    let code_definition_felts = bytes32_to_felts(code_definition_hash);
    let layout_proof_felts = bytes32_to_felts(canonical_layout_proof_hash);

    let content_hash = PoseidonHash::q_hash_many(&[
        update_felts[0],
        update_felts[1],
        update_felts[2],
        update_felts[3],
        old_leaf_felts[0],
        old_leaf_felts[1],
        old_leaf_felts[2],
        old_leaf_felts[3],
        code_root_felts[0],
        code_root_felts[1],
        code_root_felts[2],
        code_root_felts[3],
        code_definition_felts[0],
        code_definition_felts[1],
        code_definition_felts[2],
        code_definition_felts[3],
        layout_proof_felts[0],
        layout_proof_felts[1],
        layout_proof_felts[2],
        layout_proof_felts[3],
    ]);

    hash_to_bytes(&PoseidonHash::q_two_to_one(domain_hash, content_hash))
}

pub fn compute_register_user_content_hash(fingerprint: &[u8; 32], param: &[u8; 32]) -> anyhow::Result<[u8; 32]> {
    // Convert bytes to Hash type and use MerkleHasher::two_to_one
    // This matches the gatherer's hash_two_from_slice function
    let fingerprint_hash = Hash::from_bytes(&*fingerprint)?;
    let param_hash = Hash::from_bytes(&*param)?;

    let hash = PoseidonHash::q_two_to_one(fingerprint_hash, param_hash);

    Ok(hash_to_bytes(&hash))
}

pub fn compute_user_end_cap_content_hash(
    user_id: u64,
    start_user_leaf_hash: &[u8; 32],
    end_user_leaf_hash: &[u8; 32],
    checkpoint_tree_root_hash: &[u8; 32],
    global_user_tree_height: u8,
) -> anyhow::Result<[u8; 32]> {
    let start_felts = bytes32_to_felts(start_user_leaf_hash);
    let end_felts = bytes32_to_felts(end_user_leaf_hash);

    // Compute: poseidon(user_id, start_hash[4], end_hash[4], height)
    let user_leaf_combo = PoseidonHash::q_hash_many(&[
        u64_to_felt(user_id),
        start_felts[0],
        start_felts[1],
        start_felts[2],
        start_felts[3],
        end_felts[0],
        end_felts[1],
        end_felts[2],
        end_felts[3],
        F::from_canonical_u64(global_user_tree_height as u64),
    ]);

    // Compute: two_to_one(checkpoint_tree_root, user_leaf_combo)
    let checkpoint_root = Hash::from_bytes(&*checkpoint_tree_root_hash)?;
    let end_cap_hash = PoseidonHash::q_two_to_one(checkpoint_root, user_leaf_combo);

    Ok(hash_to_bytes(&end_cap_hash))
}

#[inline]
fn u64_to_felt(value: u64) -> F {
    F::from_canonical_u64(value)
}

#[inline]
pub fn bytes32_to_felts(bytes: &[u8; 32]) -> [F; 4] {
    [
        F::from_canonical_u64(u64::from_le_bytes(bytes[0..8].try_into().unwrap())),
        F::from_canonical_u64(u64::from_le_bytes(bytes[8..16].try_into().unwrap())),
        F::from_canonical_u64(u64::from_le_bytes(bytes[16..24].try_into().unwrap())),
        F::from_canonical_u64(u64::from_le_bytes(bytes[24..32].try_into().unwrap())),
    ]
}

#[inline]
pub fn hash_to_bytes(hash: &Hash) -> [u8; 32] {
    let felts = hash.to_qfelts();
    let mut bytes = [0u8; 32];
    bytes[0..8].copy_from_slice(&felts[0].to_canonical_u64().to_le_bytes());
    bytes[8..16].copy_from_slice(&felts[1].to_canonical_u64().to_le_bytes());
    bytes[16..24].copy_from_slice(&felts[2].to_canonical_u64().to_le_bytes());
    bytes[24..32].copy_from_slice(&felts[3].to_canonical_u64().to_le_bytes());
    bytes
}

#[inline]
pub fn hash_to_hex(hash: &[u8; 32]) -> String {
    hex::encode(hash)
}

pub fn hash_from_hex(hex_str: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the update authorization digest: client and coordinator share this
    /// function, so any change here must regenerate the pinned vector below.
    #[test]
    fn update_contract_auth_hash_matches_the_pinned_vector() {
        let digest = compute_update_contract_auth_hash(
            1,
            &[1u8; 32],
            &[2u8; 32],
            &[3u8; 32],
            &[4u8; 32],
            &[5u8; 32],
        );
        assert_eq!(
            hash_to_hex(&digest),
            "deed3e83c73005ca480fb8ab646ecfb06ee6996e4b668dba4d7eb62181448593",
            "the digest construction changed; regenerate the vector and resync every producer"
        );
    }
}
