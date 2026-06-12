use std::fmt::Display;

use kvq::traits::KVQSerializable;
use plonky2::{
    hash::hash_types::{HashOut, RichField},
    plonk::config::AlgebraicHasher,
};
use psy_client_common::data::qhashout::QHashOut;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::hash::traits::hasher::{MerkleHasher, MerkleHasherWithMarkedLeaf, MerkleZeroHasher, QHasher};

pub fn compute_partial_merkle_root_from_leaves_algebraic<F: RichField, H: AlgebraicHasher<F>>(leaves: &[HashOut<F>]) -> HashOut<F> {
    let mut current = leaves.to_vec();
    while current.len() > 1 {
        let mut next = vec![];
        for i in 0..current.len() / 2 {
            next.push(H::two_to_one(current[2 * i], current[2 * i + 1]));
        }
        if current.len() % 2 == 1 {
            next.push(current[current.len() - 1]);
        }
        current = next;
    }
    current[0]
}
pub fn compute_partial_merkle_root_from_leaves<Hash: PartialEq + Copy, Hasher: MerkleHasher<Hash>>(leaves: &[Hash]) -> Hash {
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

pub fn compute_root_merkle_proof_generic<Hash: PartialEq + Copy, H: MerkleHasher<Hash>>(value: Hash, index: u64, siblings: &[Hash]) -> Hash {
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
pub fn compute_root_merkle_proof<H: QHasher<F>, F: RichField>(value: QHashOut<F>, index: F, siblings: &[QHashOut<F>]) -> QHashOut<F> {
    let mut current = value;
    let index = index.to_canonical_u64();
    for (i, sibling) in siblings.iter().enumerate() {
        if index & (1 << i) == 0 {
            current = H::q_two_to_one(current, *sibling);
        } else {
            current = H::q_two_to_one(*sibling, current);
        }
    }
    current
}
pub fn verify_merkle_proof<H: QHasher<F>, F: RichField>(proof: &MerkleProof<F>) -> bool {
    if proof.siblings.len() > 64 {
        return false;
    }
    compute_root_merkle_proof::<H, F>(proof.value, proof.index, &proof.siblings) == proof.root
}
pub fn verify_delta_merkle_proof<H: QHasher<F>, F: RichField>(proof: &DeltaMerkleProof<F>) -> bool {
    if proof.siblings.len() > 64 {
        return false;
    }
    compute_root_merkle_proof::<H, F>(proof.old_value, proof.index, &proof.siblings) == proof.old_root
        && compute_root_merkle_proof::<H, F>(proof.new_value, proof.index, &proof.siblings) == proof.new_root
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct MerkleProofBase<F: RichField> {
    pub value: QHashOut<F>,
    pub index: F,
    pub siblings: Vec<QHashOut<F>>,
}
impl<F: RichField> MerkleProofBase<F> {
    pub fn compute_root<H: QHasher<F>>(&self) -> QHashOut<F> {
        compute_root_merkle_proof::<H, F>(self.value, self.index, &self.siblings)
    }
    pub fn to_merkle_proof<H: QHasher<F>>(&self) -> MerkleProof<F> {
        MerkleProof {
            root: self.compute_root::<H>(),
            value: self.value,
            index: self.index,
            siblings: self.siblings.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct MerkleProof<F: RichField> {
    pub root: QHashOut<F>,
    pub value: QHashOut<F>,
    pub index: F,
    pub siblings: Vec<QHashOut<F>>,
}

impl<F: RichField> MerkleProof<F> {
    pub fn verify<H: QHasher<F>>(&self) -> bool {
        if self.siblings.len() > 64 {
            return false;
        }
        verify_merkle_proof::<H, F>(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct DeltaMerkleProofBase<F: RichField> {
    pub old_value: QHashOut<F>,
    pub new_value: QHashOut<F>,
    pub index: F,
    pub siblings: Vec<QHashOut<F>>,
}
impl<F: RichField> DeltaMerkleProofBase<F> {
    pub fn compute_old_root<H: QHasher<F>>(&self) -> QHashOut<F> {
        compute_root_merkle_proof::<H, F>(self.old_value, self.index, &self.siblings)
    }
    pub fn compute_new_root<H: QHasher<F>>(&self) -> QHashOut<F> {
        compute_root_merkle_proof::<H, F>(self.new_value, self.index, &self.siblings)
    }
    pub fn to_delta_merkle_proof<H: QHasher<F>>(&self) -> DeltaMerkleProof<F> {
        DeltaMerkleProof {
            old_root: self.compute_old_root::<H>(),
            old_value: self.old_value,
            new_root: self.compute_new_root::<H>(),
            new_value: self.new_value,
            index: self.index,
            siblings: self.siblings.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct DeltaMerkleProof<F: RichField> {
    pub old_root: QHashOut<F>,
    pub old_value: QHashOut<F>,
    pub new_root: QHashOut<F>,
    pub new_value: QHashOut<F>,
    pub index: F,
    pub siblings: Vec<QHashOut<F>>,
}

impl<F: RichField> DeltaMerkleProof<F> {
    pub fn verify<H: QHasher<F>>(&self) -> bool {
        if self.siblings.len() > 64 {
            return false;
        }
        verify_delta_merkle_proof::<H, F>(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
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
        let root = compute_root_merkle_proof_generic::<Hash, Hasher>(value, index, &siblings);
        Self {
            root,
            value,
            index,
            siblings,
        }
    }
    pub fn verify<Hasher: MerkleHasher<Hash>>(&self) -> bool
    where
        Hash: Display,
    {
        if self.siblings.len() > 64 {
            return false;
        }
        verify_merkle_proof_core::<Hash, Hasher>(self)
    }
    pub fn verify_marked<Hasher: MerkleHasherWithMarkedLeaf<Hash>>(&self) -> bool {
        if self.siblings.len() > 64 {
            return false;
        }
        verify_merkle_proof_marked_leaves_core::<Hash, Hasher>(self)
    }
    pub fn to_delta_merkle_proof_inplace(self) -> DeltaMerkleProofCore<Hash> {
        DeltaMerkleProofCore {
            old_root: self.root,
            new_root: self.root,
            old_value: self.value,
            new_value: self.value,
            index: self.index,
            siblings: self.siblings,
        }
    }
    pub fn to_delta_merkle_proof(&self) -> DeltaMerkleProofCore<Hash> {
        DeltaMerkleProofCore {
            old_root: self.root,
            new_root: self.root,
            old_value: self.value,
            new_value: self.value,
            index: self.index,
            siblings: self.siblings.clone(),
        }
    }
}
impl<F: RichField> From<MerkleProofCore<HashOut<F>>> for MerkleProofCore<QHashOut<F>> {
    fn from(value: MerkleProofCore<HashOut<F>>) -> Self {
        Self {
            root: QHashOut(value.root),
            value: QHashOut(value.value),
            index: value.index,
            siblings: value.siblings.into_iter().map(|s| QHashOut(s)).collect::<Vec<_>>(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeltaMerkleProofCorePartial<Hash: PartialEq + Copy> {
    pub old_value: Hash,
    pub new_value: Hash,

    pub index: u64,
    pub siblings: Vec<Hash>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[ts(export, concrete(Hash = u64))]
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
        assert!(
            new_height <= self.siblings.len(),
            "cannot shorten tree to a height taller than the current proof"
        );
        if new_height == self.siblings.len() {
            self.clone()
        } else {
            let height_diff = self.siblings.len() - new_height;
            let low_index = self.index & ((1u64 << (height_diff as u64)) - 1u64);
            let new_index = self.index >> (height_diff as u64);
            let old_value = compute_root_merkle_proof_generic::<Hash, H>(self.old_value, low_index, &self.siblings[0..height_diff]);
            let new_value = compute_root_merkle_proof_generic::<Hash, H>(self.new_value, low_index, &self.siblings[0..height_diff]);

            Self::from_params::<H>(new_index, old_value, new_value, self.siblings[height_diff..].to_vec())
        }
    }
    pub fn shorten_height<H: MerkleHasher<Hash>>(&self, new_height: usize) -> Self {
        assert!(
            new_height <= self.siblings.len(),
            "cannot shorten tree to a height taller than the current proof"
        );
        if new_height == self.siblings.len() {
            self.clone()
        } else {
            Self::from_params::<H>(self.index, self.old_value, self.new_value, self.siblings[0..new_height].to_vec())
        }
    }
}
impl<F: RichField> From<MerkleProofCore<QHashOut<F>>> for DeltaMerkleProofCore<QHashOut<F>> {
    fn from(value: MerkleProofCore<QHashOut<F>>) -> Self {
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
impl<F: RichField> From<&MerkleProofCore<QHashOut<F>>> for DeltaMerkleProofCore<QHashOut<F>> {
    fn from(value: &MerkleProofCore<QHashOut<F>>) -> Self {
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

impl<F: RichField> From<DeltaMerkleProofCore<HashOut<F>>> for DeltaMerkleProofCore<QHashOut<F>> {
    fn from(value: DeltaMerkleProofCore<HashOut<F>>) -> Self {
        Self {
            old_root: QHashOut(value.old_root),
            old_value: QHashOut(value.old_value),
            new_root: QHashOut(value.new_root),
            new_value: QHashOut(value.new_value),
            index: value.index,
            siblings: value.siblings.into_iter().map(|s| QHashOut(s)).collect::<Vec<_>>(),
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
impl<Hash: PartialEq + Copy> DeltaMerkleProofCore<Hash> {
    pub fn verify<Hasher: MerkleHasher<Hash>>(&self) -> bool {
        if self.siblings.len() > 64 {
            return false;
        }
        verify_delta_merkle_proof_core::<Hash, Hasher>(self)
    }
    pub fn verify_marked<Hasher: MerkleHasherWithMarkedLeaf<Hash>>(&self) -> bool {
        if self.siblings.len() > 64 {
            return false;
        }
        verify_delta_merkle_proof_marked_leaves_core::<Hash, Hasher>(self)
    }
}
pub fn verify_merkle_proof_core<Hash: PartialEq + Copy + Display, Hasher: MerkleHasher<Hash>>(proof: &MerkleProofCore<Hash>) -> bool {
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

pub fn compute_historical_and_current_merkle_roots_core_qho<F: RichField, Hasher: MerkleZeroHasher<HashOut<F>>>(
    proof: &MerkleProofCore<QHashOut<F>>,
) -> (QHashOut<F>, QHashOut<F>) {
    let mut current = proof.value.0;
    let mut historical = Hasher::get_zero_hash(0);
    for (i, sibling) in proof.siblings.iter().enumerate() {
        if proof.index & (1 << i) == 0 {
            current = Hasher::two_to_one(&current, &sibling.0);
            historical = Hasher::two_to_one(&historical, &Hasher::get_zero_hash(i));
        } else {
            current = Hasher::two_to_one(&sibling.0, &current);
            historical = Hasher::two_to_one(&sibling.0, &historical);
        }
    }
    (QHashOut(historical), QHashOut(current))
}

pub fn compute_historical_and_current_merkle_roots_core_gt<Hash: PartialEq + Copy, Hasher: MerkleZeroHasher<Hash>>(
    proof: &MerkleProofCore<Hash>,
) -> (Hash, Hash) {
    let mut current = proof.value;
    let mut historical = current.clone();
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

pub fn compute_historical_and_current_merkle_roots_core_gt_qho<F: RichField, Hasher: MerkleZeroHasher<HashOut<F>>>(
    proof: &MerkleProofCore<QHashOut<F>>,
) -> (QHashOut<F>, QHashOut<F>) {
    let mut current = proof.value.0;
    let mut historical = current.clone();
    for (i, sibling) in proof.siblings.iter().enumerate() {
        if proof.index & (1 << i) == 0 {
            current = Hasher::two_to_one(&current, &sibling.0);
            historical = Hasher::two_to_one(&historical, &Hasher::get_zero_hash(i));
        } else {
            current = Hasher::two_to_one(&sibling.0, &current);
            historical = Hasher::two_to_one(&sibling.0, &historical);
        }
    }
    (QHashOut(historical), QHashOut(current))
}

pub fn verify_delta_merkle_proof_core<Hash: PartialEq + Copy, Hasher: MerkleHasher<Hash>>(proof: &DeltaMerkleProofCore<Hash>) -> bool {
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

pub fn verify_merkle_proof_marked_leaves_core<Hash: PartialEq + Copy, Hasher: MerkleHasher<Hash>>(proof: &MerkleProofCore<Hash>) -> bool {
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
pub fn verify_delta_merkle_proof_marked_leaves_core<Hash: PartialEq + Copy, Hasher: MerkleHasherWithMarkedLeaf<Hash>>(
    proof: &DeltaMerkleProofCore<Hash>,
) -> bool {
    if proof.siblings.len() > 64 {
        return false;
    }
    let mut current = proof.old_value;
    for (i, sibling) in proof.siblings.iter().enumerate() {
        if i == 0 {
            if proof.index & (1 << i) == 0 {
                current = Hasher::two_to_one_marked_leaf(&current, sibling);
            } else {
                current = Hasher::two_to_one_marked_leaf(sibling, &current);
            }
        } else {
            // for non leaves, we hash like normal
            if proof.index & (1 << i) == 0 {
                current = Hasher::two_to_one(&current, sibling);
            } else {
                current = Hasher::two_to_one(sibling, &current);
            }
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

pub fn calc_merkle_root_from_leaves<Hash: PartialEq + Copy, Hasher: MerkleHasher<Hash>>(leaves: Vec<Hash>) -> Hash {
    let mut current_leaves: Vec<Hash> = leaves.chunks_exact(2).map(|chunk| Hasher::two_to_one(&chunk[0], &chunk[1])).collect();
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

impl<Hash> KVQSerializable for MerkleProofCore<Hash>
where
    Hash: PartialEq + Copy + Serialize,
    for<'de2> Hash: Deserialize<'de2>,
{
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }
}

impl<Hash> KVQSerializable for DeltaMerkleProofCore<Hash>
where
    Hash: PartialEq + Copy + Serialize,
    for<'de2> Hash: Deserialize<'de2>,
{
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }
}
