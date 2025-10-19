use pser::{QBytesSerialize, QBytesDeserialize};
use serde::{Deserialize, Serialize};

use crate::{crypto::hash::traits::MerkleHasher, data::serializable::{QPDSerializable, QPDSerializableFixed}};
/*

Level[0][0] = hash(hash(0,0),Tag[0][0])
Level[0][1] = hash(hash(0,1),Tag[0][1])
Level[0][2] = hash(hash(0,2),Tag[0][2])
Level[0][3] = hash(hash(0,3),Tag[0][3])

Level[1][0] = hash(hash(Level[0][0], Level[0][1]), Tag[1][0])
Level[1][1] = hash(hash(Level[0][2], Level[0][3]), Tag[1][1])
Level[2][0] = hash(hash(Level[1][0], Level[1][1]), Tag[2][0])

Level[n][i] = hash(hash(Level[n-1][2*i], Level[n-1][2*i+1]), Tag[n][i])
*/
#[inline]
pub fn hash_tag_tree_node<Hash, Hasher: MerkleHasher<Hash>>(left: &Hash, right: &Hash, tag: &Hash) -> Hash {
    Hasher::two_to_one(&Hasher::two_to_one(left, right), tag)
}

#[inline]
pub fn hash_tag_tree_node_owned<Hash, Hasher: MerkleHasher<Hash>>(left: Hash, right: Hash, tag: Hash) -> Hash {
    Hasher::two_to_one(&Hasher::two_to_one(&left, &right), &tag)
}

pub fn compute_tag_tree_root_for_proof<Hash: Copy, Hasher: MerkleHasher<Hash>>(
    index: u64,
    leaf: &TagTreeNodePreimage<Hash>,
    siblings: &[TagTreeProofNode<Hash>],
) -> Hash {
    let mut current_value = leaf.get_node_hash::<Hasher>();

    if siblings.len() == 0 {
        return current_value
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



#[pderive::serialize_copy_ts_export]
pub struct TagTreeStorageNode<Hash> {
    pub value: Hash,
    pub tag: Hash,
}

impl<Hash: Default> Default for TagTreeStorageNode<Hash> {
    fn default() -> Self {
        Self {
            value: Default::default(),
            tag: Default::default(),
        }
    }
}
impl<Hash: QPDSerializableFixed + Copy> QPDSerializable for TagTreeStorageNode<Hash> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut result = Vec::with_capacity(Hash::get_fixed_size() * 2);
        result.extend_from_slice(self.value.to_bytes()?.as_slice());
        result.extend_from_slice(self.tag.to_bytes()?.as_slice());
        Ok(result)
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != Hash::get_fixed_size() * 2 {
            anyhow::bail!("TagTreeStorageNode: expected {} bytes, got {}", Hash::get_fixed_size() * 2, bytes.len());
        }
        let value = Hash::from_bytes(&bytes[0..Hash::get_fixed_size()])?;
        let tag = Hash::from_bytes(&bytes[Hash::get_fixed_size()..Hash::get_fixed_size() * 2])?;
        Ok(Self { value, tag })
    }
}

#[pderive::serialize_copy_ts_export]
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

impl<Hash> TagTreeNodePreimage<Hash> {
    pub fn get_node_hash<Hasher: MerkleHasher<Hash>>(&self) -> Hash {
        hash_tag_tree_node::<Hash, Hasher>(&self.left, &self.right, &self.tag)
    }
}


#[pderive::serialize_copy_ts_export]
pub struct TagTreeProofNode<Hash> {
    pub sibling: Hash,
    pub parent_tag: Hash,
}





#[pderive::serialize_clone_ts_export]
pub struct TagTreeMerkleProofPartial<Hash> {
    pub index: u64,
    pub leaf: TagTreeNodePreimage<Hash>,
    pub siblings: Vec<TagTreeProofNode<Hash>>,
}
impl<Hash: PartialEq + Copy> TagTreeMerkleProofPartial<Hash> {
    pub fn new_from_params(index: u64, leaf: TagTreeNodePreimage<Hash>, siblings: Vec<TagTreeProofNode<Hash>>) -> Self {
        Self {
            index,
            leaf,
            siblings,
        }
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
            leaf: self.leaf,
            root,
            siblings: self.siblings.clone(),
        }
    }
}
#[pderive::serialize_clone_ts_export]
pub struct TagTreeMerkleProof<Hash> {
    pub index: u64,
    pub leaf: TagTreeNodePreimage<Hash>,
    pub root: Hash,
    pub siblings: Vec<TagTreeProofNode<Hash>>,
}



impl<Hash: PartialEq + Copy> TagTreeMerkleProof<Hash> {
    pub fn new_from_params<Hasher: MerkleHasher<Hash>>(index: u64, leaf: TagTreeNodePreimage<Hash>, siblings: Vec<TagTreeProofNode<Hash>>) -> Self {
        let root = compute_tag_tree_root_for_proof::<Hash, Hasher>(index, &leaf, &siblings);

        Self {
            index,
            leaf,
            root,
            siblings,
        }
    }
    pub fn verify<Hasher: MerkleHasher<Hash>>(&self) -> bool {
        if self.siblings.len() > 64 {
            return false;
        }
        verify_tag_tree_proof::<Hash, Hasher>(self.index, &self.leaf, &self.siblings, self.root)
    }
}

impl<Hash> QPDSerializable for TagTreeMerkleProof<Hash>
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