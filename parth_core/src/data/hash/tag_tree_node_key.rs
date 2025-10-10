use crate::data::hash::merkle_node_key::SimpleMerkleNodeKey;


#[pderive::serialize_copy_default]
pub struct TagTreeNodeWithKey<Hash: PartialEq + Copy> {
    pub key: SimpleMerkleNodeKey,
    pub value: Hash,
    pub tag: Hash,
}
