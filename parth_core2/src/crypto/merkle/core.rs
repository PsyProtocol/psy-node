use crate::common::{data::core::merkle::merkle_proof::{DeltaMerkleProofCore, MerkleProofCore}, traits::merkle::{MerkleHasher, MerkleZeroHasher}};


pub fn compute_partial_merkle_root_from_leaves<
    Hash: PartialEq + Copy,
    Hasher: MerkleHasher<Hash>,
>(
    leaves: &[Hash],
) -> Hash {
    let mut current = leaves.to_vec();
    while current.len() > 1 {
        let mut next = vec![];
        for i in 0..current.len() / 2 {
            next.push(Hasher::two_to_one(&current[2 * i], &current[2 * i + 1]));
        }
        if current.len() % 2 == 1 {
            next.push(current[current.len() - 1]);
        }
        current = next;
    }
    current[0]
}

pub fn compute_root_merkle_proof_generic<Hash: PartialEq + Copy, H: MerkleHasher<Hash>>(
    value: Hash,
    index: u64,
    siblings: &[Hash]
) -> Hash {
    let mut current = value;
    for (i, sibling) in siblings.iter().enumerate() {
        if index & (1 << i) == 0 {
            current = H::two_to_one(&current, sibling);
        } else {
            current = H::two_to_one(sibling, &current);
        }
    }
    current
}


pub fn verify_merkle_proof_core<Hash: PartialEq + Copy, Hasher: MerkleHasher<Hash>>(
    proof: &MerkleProofCore<Hash>,
) -> bool {
    let mut current = proof.value;
    for (i, sibling) in proof.siblings.iter().enumerate() {
        if proof.index & (1 << i) == 0 {
            current = Hasher::two_to_one(&current, sibling);
        } else {
            current = Hasher::two_to_one(sibling, &current);
        }
    }
    current == proof.root
}


pub fn compute_historical_and_current_merkle_roots_core<Hash: PartialEq + Copy, Hasher: MerkleZeroHasher<Hash>>(
    proof: &MerkleProofCore<Hash>,
) -> (Hash, Hash) {
    let mut current = proof.value;
    let mut historical = Hasher::get_zero_hash(0);
    for (i, sibling) in proof.siblings.iter().enumerate() {
        if proof.index & (1 << i) == 0 {
            current = Hasher::two_to_one(&current, sibling);
            historical = Hasher::two_to_one(&historical, &Hasher::get_zero_hash(i));
        } else {
            current = Hasher::two_to_one(sibling, &current);
            historical = Hasher::two_to_one(sibling, &historical);
        }
    }
    (historical, current)
}


pub fn verify_delta_merkle_proof_core<Hash: PartialEq + Copy, Hasher: MerkleHasher<Hash>>(
    proof: &DeltaMerkleProofCore<Hash>,
) -> bool {
    let mut current = proof.old_value;
    for (i, sibling) in proof.siblings.iter().enumerate() {
        if proof.index & (1 << i) == 0 {
            current = Hasher::two_to_one(&current, sibling);
        } else {
            current = Hasher::two_to_one(sibling, &current);
        }
    }
    if current != proof.old_root {
        return false;
    }
    current = proof.new_value;
    for (i, sibling) in proof.siblings.iter().enumerate() {
        if proof.index & (1 << i) == 0 {
            current = Hasher::two_to_one(&current, sibling);
        } else {
            current = Hasher::two_to_one(sibling, &current);
        }
    }
    current == proof.new_root
}


pub fn calc_merkle_root_from_leaves<Hash: PartialEq + Copy, Hasher: MerkleHasher<Hash>>(
    leaves: &[Hash],
) -> Hash {
    let mut current_leaves: Vec<Hash> = leaves
        .chunks_exact(2)
        .map(|chunk| Hasher::two_to_one(&chunk[0], &chunk[1]))
        .collect();
    let height = (current_leaves.len() as f64).log2().ceil() as usize;
    for _ in 1..height {
        let next_leaves = current_leaves
            .chunks_exact(2)
            .map(|chunk| Hasher::two_to_one(&chunk[0], &chunk[1]))
            .collect();
        current_leaves = next_leaves;
    }
    current_leaves[0]
}
