use serde::{Deserialize, Serialize};
use crate::{common::traits::{merkle::MerkleHasher, serializable::QPDSerializable}, crypto::merkle::core::{compute_root_merkle_proof_generic, verify_delta_merkle_proof_core, verify_merkle_proof_core}};

// Start Merkle Proof
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Ord, PartialOrd)]
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
        Ok(serde_json::to_vec(self)?)
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }
}


// Start Delta Merkle Proof

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
        Ok(serde_json::to_vec(self)?)
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeltaMerkleProofCorePartial<Hash: PartialEq + Copy> {
    pub old_value: Hash,
    pub new_value: Hash,

    pub index: u64,
    pub siblings: Vec<Hash>,
}
