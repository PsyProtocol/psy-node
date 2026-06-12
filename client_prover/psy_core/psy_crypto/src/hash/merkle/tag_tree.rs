use serde::{Deserialize, Serialize};

use crate::hash::traits::hasher::{MerkleHasher, ZeroableHash};

pub const PSY_OBJECT_FFS_SIZE_TAG_TREE_STORAGE_NODE: usize = 64;
pub const PSY_OBJECT_FFS_SIZE_TAG_TREE_PROOF_NODE: usize = 64;

#[inline]
pub fn hash_tag_tree_node<Hash: PartialEq, Hasher: MerkleHasher<Hash>>(left: &Hash, right: &Hash, tag: &Hash) -> Hash {
    Hasher::two_to_one(&Hasher::two_to_one(left, right), tag)
}
#[inline]
pub fn hash_tag_tree_node_single<Hash: PartialEq + ZeroableHash, Hasher: MerkleHasher<Hash>>(left: &Hash, tag: &Hash) -> Hash {
    Hasher::two_to_one(&Hasher::two_to_one(left, &Hash::get_zero_value()), tag)
}

#[inline]
pub fn hash_tag_tree_node_three<Hash: PartialEq + ZeroableHash, Hasher: MerkleHasher<Hash>>(
    first_tag_tree_value: &Hash,
    second_tag_tree_value: &Hash,
    third_tag_tree_value: &Hash,
    tag: &Hash,
) -> Hash {
    let last_two = hash_tag_tree_node::<Hash, Hasher>(second_tag_tree_value, third_tag_tree_value, tag);
    hash_tag_tree_node::<Hash, Hasher>(first_tag_tree_value, &last_two, tag)
}

#[inline]
pub fn hash_tag_tree_node_owned<Hash: PartialEq, Hasher: MerkleHasher<Hash>>(left: Hash, right: Hash, tag: Hash) -> Hash {
    Hasher::two_to_one(&Hasher::two_to_one(&left, &right), &tag)
}

pub fn compute_tag_tree_root_for_proof<Hash: Copy + PartialEq, Hasher: MerkleHasher<Hash>>(
    index: u64,
    leaf: &TagTreeNodePreimage<Hash>,
    siblings: &[TagTreeProofNode<Hash>],
) -> Hash {
    let mut current_value = leaf.get_node_hash::<Hasher>();

    if siblings.len() == 0 {
        return current_value;
    }
    for (i, sibling) in siblings.iter().enumerate() {
        let is_right = (index & (1 << i)) != 0;
        current_value = if is_right {
            Hasher::two_to_one(&sibling.sibling, &current_value)
        } else {
            Hasher::two_to_one(&current_value, &sibling.sibling)
        };
        current_value = Hasher::two_to_one(&current_value, &sibling.parent_tag);
    }
    current_value
}

pub fn verify_tag_tree_proof<Hash: PartialEq + Copy, Hasher: MerkleHasher<Hash>>(
    index: u64,
    leaf: &TagTreeNodePreimage<Hash>,
    siblings: &[TagTreeProofNode<Hash>],
    known_root: Hash,
) -> bool {
    if siblings.len() > 64 {
        return false;
    }
    let computed_root = compute_tag_tree_root_for_proof::<Hash, Hasher>(index, leaf, siblings);
    computed_root == known_root
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Eq, Hash, PartialOrd, Ord)]
pub struct TagTreeStorageNode<Hash> {
    pub value: Hash,
    pub tag: Hash,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Eq, Hash, PartialOrd, Ord)]
pub struct TagTreeNodePreimage<Hash> {
    pub left: Hash,
    pub right: Hash,
    pub tag: Hash,
}

impl<Hash: Default> Default for TagTreeNodePreimage<Hash> {
    fn default() -> Self {
        Self {
            left: Default::default(),
            right: Default::default(),
            tag: Default::default(),
        }
    }
}

impl<Hash: PartialEq> TagTreeNodePreimage<Hash> {
    pub fn get_node_hash<Hasher: MerkleHasher<Hash>>(&self) -> Hash {
        hash_tag_tree_node::<Hash, Hasher>(&self.left, &self.right, &self.tag)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct TagTreeProofNode<Hash> {
    pub sibling: Hash,
    pub parent_tag: Hash,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Eq, Hash, PartialOrd, Ord)]
pub struct TagTreeMerkleProofPartial<Hash> {
    pub index: u64,
    pub leaf: TagTreeNodePreimage<Hash>,
    pub siblings: Vec<TagTreeProofNode<Hash>>,
}

impl<Hash: PartialEq + Copy> TagTreeMerkleProofPartial<Hash> {
    pub fn new_from_params(index: u64, leaf: TagTreeNodePreimage<Hash>, siblings: Vec<TagTreeProofNode<Hash>>) -> Self {
        Self { index, leaf, siblings }
    }
}

impl<Hash: PartialEq + Copy> TagTreeMerkleProofPartial<Hash> {
    pub fn get_root<Hasher: MerkleHasher<Hash>>(&self) -> Hash {
        compute_tag_tree_root_for_proof::<Hash, Hasher>(self.index, &self.leaf, &self.siblings)
    }
    pub fn to_proof<Hasher: MerkleHasher<Hash>>(&self) -> TagTreeMerkleProof<Hash> {
        let root = self.get_root::<Hasher>();
        TagTreeMerkleProof {
            index: self.index,
            leaf: self.leaf.clone(),
            root,
            siblings: self.siblings.clone(),
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Eq, Hash, PartialOrd, Ord)]
pub struct TagTreeMerkleProof<Hash> {
    pub root: Hash,
    pub leaf: TagTreeNodePreimage<Hash>,
    pub index: u64,
    pub siblings: Vec<TagTreeProofNode<Hash>>,
}

impl<Hash: Copy + ZeroableHash + PartialEq> TagTreeMerkleProof<Hash> {
    pub fn new_empty() -> Self {
        Self {
            root: Hash::get_zero_value(),
            leaf: TagTreeNodePreimage {
                left: Hash::get_zero_value(),
                right: Hash::get_zero_value(),
                tag: Hash::get_zero_value(),
            },
            index: 0,
            siblings: Vec::new(),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.siblings.len() == 0
            && self.index == 0
            && self.leaf.left == Hash::get_zero_value()
            && self.leaf.right == Hash::get_zero_value()
            && self.leaf.tag == Hash::get_zero_value()
            && self.root == Hash::get_zero_value()
    }

    pub fn pad_to_height(mut self, max_height: usize) -> Self {
        let proof_height = self.siblings.len();
        assert!(
            proof_height <= max_height,
            "Proof height {} exceeds max height {}",
            proof_height,
            max_height
        );
        while self.siblings.len() < max_height {
            self.siblings.push(TagTreeProofNode {
                sibling: Hash::get_zero_value(),
                parent_tag: Hash::get_zero_value(),
            });
        }
        self
    }
}

impl<Hash: PartialEq + Copy> TagTreeMerkleProof<Hash> {
    pub fn new_from_params<Hasher: MerkleHasher<Hash>>(index: u64, leaf: TagTreeNodePreimage<Hash>, siblings: Vec<TagTreeProofNode<Hash>>) -> Self {
        let root = compute_tag_tree_root_for_proof::<Hash, Hasher>(index, &leaf, &siblings);

        Self { index, leaf, root, siblings }
    }
    pub fn verify<Hasher: MerkleHasher<Hash>>(&self) -> bool {
        if self.siblings.len() > 64 {
            return false;
        }
        verify_tag_tree_proof::<Hash, Hasher>(self.index, &self.leaf, &self.siblings, self.root)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Eq, Hash, PartialOrd, Ord)]
pub struct TagTreeMerkleProofWithRewardPreimage<Hash> {
    pub inner: TagTreeMerkleProof<Hash>,
    pub reward_tree_tag_preimage: Hash,
    pub proof_height: u64,
}

impl<Hash> TagTreeMerkleProofWithRewardPreimage<Hash> {
    pub fn new(proof: TagTreeMerkleProof<Hash>, reward_tree_tag_preimage: Hash) -> Self {
        Self {
            proof_height: proof.siblings.len() as u64,
            reward_tree_tag_preimage,
            inner: proof,
        }
    }
}

impl<Hash: PartialEq + Copy + ZeroableHash> TagTreeMerkleProofWithRewardPreimage<Hash> {
    pub fn pad_to_height(mut self, max_height: usize) -> Self {
        self.proof_height = self.inner.siblings.len() as u64;
        self.inner = self.inner.pad_to_height(max_height);
        self
    }
}
