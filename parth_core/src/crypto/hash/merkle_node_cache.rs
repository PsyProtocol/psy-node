use crate::data::hash::merkle_node_key::SimpleMerkleNodeKey;

pub trait QMerkleNodeCacheReader<Hash: PartialEq + Copy> {
    fn contains(&self, key: &SimpleMerkleNodeKey) -> bool;
    fn get_ref(&self, key: &SimpleMerkleNodeKey) -> Option<&Hash>;
    fn get(&self, key: &SimpleMerkleNodeKey) -> Option<Hash>;
}

pub trait QMerkleNodeCacheWriterMut<Hash: PartialEq + Copy> {
    fn insert(&mut self, key: SimpleMerkleNodeKey, value: Hash);
    fn remove(&mut self, key: &SimpleMerkleNodeKey) -> Option<Hash>;
}

pub trait QMerkleNodeCache<Hash: PartialEq + Copy>: QMerkleNodeCacheReader<Hash> + QMerkleNodeCacheWriterMut<Hash> {}
impl<T: QMerkleNodeCacheReader<Hash> + QMerkleNodeCacheWriterMut<Hash>, Hash: PartialEq + Copy> QMerkleNodeCache<Hash> for T {}

