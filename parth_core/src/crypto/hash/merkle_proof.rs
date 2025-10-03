use pser::{QBytesSerialize, QBytesDeserialize};
use serde::{Deserialize, Serialize};

use crate::{crypto::hash::traits::{CodeSerializableHash, MerkleHasher, MerkleZeroHasher, ZeroableHash}, data::serializable::QPDSerializable};




pub const ZERO_HASH_CACHE_SIZE: usize = 128;
pub trait MerkleZeroHasherWithCache<Hash: PartialEq + Copy>: MerkleHasher<Hash> {
    const CACHED_ZERO_HASHES: [Hash; ZERO_HASH_CACHE_SIZE];
}



pub fn iterate_merkle_hasher<Hash: PartialEq, Hasher: MerkleHasher<Hash>>(
    mut current: Hash,
    reverse_level: usize,
) -> Hash {
    for _ in 0..reverse_level {
        current = Hasher::two_to_one(&current, &current);
    }
    current
}
pub fn generate_zero_hashes<Hash: PartialEq + Copy + ZeroableHash, Hasher: MerkleHasher<Hash>>() -> [Hash; ZERO_HASH_CACHE_SIZE] {
    let mut zero_hashes = [Hash::get_zero_value(); ZERO_HASH_CACHE_SIZE];
    zero_hashes[0] = Hash::get_zero_value();
    for i in 1..ZERO_HASH_CACHE_SIZE {
        zero_hashes[i] = Hasher::two_to_one(&zero_hashes[i - 1], &zero_hashes[i - 1]);
    }
    zero_hashes
}
pub fn generate_zero_hashes_code<Hash: PartialEq + CodeSerializableHash + ZeroableHash, Hasher: MerkleHasher<Hash>>() -> String {
    let zero_hashes = generate_zero_hashes::<Hash, Hasher>();
    let mut code_lines = vec![
        format!("pub const CACHED_ZERO_HASHES: [<{}>; {}] = [", Hash::get_type_name(), ZERO_HASH_CACHE_SIZE)
    ];
    for (_, zh) in zero_hashes.iter().enumerate() {
        code_lines.push(format!("    {},", zh.to_constant_code()));
    }
    code_lines.push("];".to_string());
    code_lines.join("\n")
}
impl<Hash: PartialEq + Copy, T: MerkleZeroHasherWithCache<Hash>> MerkleZeroHasher<Hash> for T {
    fn get_zero_hash(reverse_level: usize) -> Hash {
        if reverse_level < ZERO_HASH_CACHE_SIZE {
            T::CACHED_ZERO_HASHES[reverse_level]
        } else {
            let current = T::CACHED_ZERO_HASHES[ZERO_HASH_CACHE_SIZE - 1];
            iterate_merkle_hasher::<Hash, Self>(current, reverse_level - ZERO_HASH_CACHE_SIZE + 1)
        }
    }
}


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
    if proof.siblings.len() > 64 {
        return false;
    }
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
    if proof.siblings.len() > 64 {
        return false;
    }
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


// Start Merkle Proof
#[pderive::serialize_clone]
#[derive(ts_rs::TS)]
#[ts(export)]
pub struct MerkleProofCore<Hash: PartialEq + Copy> {
    pub root: Hash,
    pub value: Hash,

    pub index: u64,
    pub siblings: Vec<Hash>,
}

impl<Hash: PartialEq + Copy + Default> Default for MerkleProofCore<Hash> {
    fn default() -> Self {
        Self {
            root: Default::default(),
            value: Default::default(),
            index: Default::default(),
            siblings: Default::default(),
        }
    }
}
impl<Hash: PartialEq + Copy> MerkleProofCore<Hash> {
    pub fn new_from_params<Hasher: MerkleHasher<Hash>>(index: u64, value: Hash, siblings: Vec<Hash>) -> Self {
        let root =compute_root_merkle_proof_generic::<Hash, Hasher>(value, index, &siblings);
        Self {
            root,
            value,
            index,
            siblings,
        }
    }
    pub fn verify<Hasher: MerkleHasher<Hash>>(&self) -> bool {
        if self.siblings.len() > 64 {
            return false;
        }
        verify_merkle_proof_core::<Hash, Hasher>(self)
    }
    pub fn to_delta_merkle_proof_template_inplace(self) -> DeltaMerkleProofCore<Hash> {
        DeltaMerkleProofCore {
            old_root: self.root,
            new_root: self.root,
            old_value: self.value,
            new_value: self.value,
            index: self.index,
            siblings: self.siblings
        }
    }
    pub fn to_delta_merkle_proof_template(&self) -> DeltaMerkleProofCore<Hash> {
        DeltaMerkleProofCore {
            old_root: self.root,
            new_root: self.root,
            old_value: self.value,
            new_value: self.value,
            index: self.index,
            siblings: self.siblings.clone()
        }
    }
}

impl<Hash> QPDSerializable for MerkleProofCore<Hash>
where
    Hash: PartialEq + Copy + Serialize,
    for<'de2> Hash: Deserialize<'de2>,
{
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        self.to_qbytes()
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        Self::from_qbytes(bytes)
    }
}


// Start Delta Merkle Proof

#[pderive::serialize_clone]
#[derive(ts_rs::TS)]
#[ts(export)]
pub struct DeltaMerkleProofCore<Hash: PartialEq + Copy> {
    pub old_root: Hash,
    pub old_value: Hash,

    pub new_root: Hash,
    pub new_value: Hash,

    pub index: u64,
    pub siblings: Vec<Hash>,
}

impl<Hash: PartialEq + Copy> DeltaMerkleProofCore<Hash> {
    pub fn from_params<H: MerkleHasher<Hash>>(index: u64, old_value: Hash, new_value: Hash, siblings: Vec<Hash>) -> Self {
        let old_root = compute_root_merkle_proof_generic::<Hash, H>(old_value, index, &siblings);
        let new_root = compute_root_merkle_proof_generic::<Hash, H>(new_value, index, &siblings);

        Self {
            old_root,
            old_value,
            new_root,
            new_value,
            index,
            siblings,
        }
    }

    pub fn verify<Hasher: MerkleHasher<Hash>>(&self) -> bool {
        if self.siblings.len() > 64 {
            return false;
        }
        verify_delta_merkle_proof_core::<Hash, Hasher>(self)
    }

    pub fn single_value(index: u64, old_value: Hash, new_value: Hash) -> Self {
        Self {
            old_root: old_value,
            old_value,
            new_root: new_value,
            new_value,
            index,
            siblings: Vec::new(),
        }
    }

    pub fn with_shortened_height_from_bottom<H: MerkleHasher<Hash>>(&self, new_height: usize) -> Self {
        assert!(new_height <= self.siblings.len(), "cannot shorten tree to a height taller than the current proof");
        if new_height == self.siblings.len() {
            self.clone()
        }else{
            let height_diff = self.siblings.len()-new_height;
            let low_index = self.index&((1u64<<(height_diff as u64))-1u64);
            let new_index = self.index >> (height_diff as u64);
            let old_value = compute_root_merkle_proof_generic::<Hash, H>(self.old_value, low_index, &self.siblings[0..height_diff]);
            let new_value = compute_root_merkle_proof_generic::<Hash, H>(self.new_value, low_index, &self.siblings[0..height_diff]);

            Self::from_params::<H>(
                new_index,
                old_value,
                new_value,
                self.siblings[height_diff..].to_vec(),
            )
        }
    }

    pub fn shorten_height<H: MerkleHasher<Hash>>(&self, new_height: usize) -> Self {
        assert!(new_height <= self.siblings.len(), "cannot shorten tree to a height taller than the current proof");
        if new_height == self.siblings.len() {
            self.clone()
        }else{
            Self::from_params::<H>(
                self.index,
                self.old_value,
                self.new_value,
                self.siblings[0..new_height].to_vec(),
            )
        }
    }
}
impl<Hash: PartialEq + Copy> From<MerkleProofCore<Hash>> for DeltaMerkleProofCore<Hash> {
    fn from(value: MerkleProofCore<Hash>) -> Self {
        Self {
            old_root: value.root,
            old_value: value.value,
            new_root: value.root,
            new_value: value.value,
            index: value.index,
            siblings: value.siblings,
        }
    }
}
impl<Hash: PartialEq + Copy> From<&MerkleProofCore<Hash>> for DeltaMerkleProofCore<Hash> {
    fn from(value: &MerkleProofCore<Hash>) -> Self {
        Self {
            old_root: value.root,
            old_value: value.value,
            new_root: value.root,
            new_value: value.value,
            index: value.index,
            siblings: value.siblings.clone(),
        }
    }
}
impl<Hash: PartialEq + Copy + Default> Default for DeltaMerkleProofCore<Hash> {
    fn default() -> Self {
        Self {
            old_root: Default::default(),
            old_value: Default::default(),
            new_root: Default::default(),
            new_value: Default::default(),
            index: Default::default(),
            siblings: Default::default(),
        }
    }
}
impl<Hash> QPDSerializable for DeltaMerkleProofCore<Hash>
where
    Hash: PartialEq + Copy + Serialize,
    for<'de2> Hash: Deserialize<'de2>,
{
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        self.to_qbytes()
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        Self::from_qbytes(bytes)
    }
}

#[pderive::serialize_clone]
#[derive(ts_rs::TS)]
#[ts(export)]
pub struct DeltaMerkleProofCorePartial<Hash: PartialEq + Copy> {
    pub old_value: Hash,
    pub new_value: Hash,

    pub index: u64,
    pub siblings: Vec<Hash>,
}
