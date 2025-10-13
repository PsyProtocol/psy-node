use auto_impl::auto_impl;

use crate::data::hash::merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey};

#[auto_impl(&, &mut, Arc, Box, Rc)]
pub trait QMerkleStoreReaderBase<Hash: PartialEq + Copy> {
    type OHash;
    fn get_root(&self) -> Hash;
    fn get_root_ref(&self) -> &Hash;

    fn get_node_value(&self, node_key: &SimpleMerkleNodeKey) -> Hash;
    fn get_node_value_ref(&self, node_key: &SimpleMerkleNodeKey) -> &Hash;

    fn get_node_value_by_owned_key(&self, node_key: SimpleMerkleNodeKey) -> Hash;
    fn get_node_value_ref_by_owned_key(&self, node_key: SimpleMerkleNodeKey) -> &Hash;

    fn get_node_values(&self, node_keys: &[SimpleMerkleNodeKey]) -> Vec<Hash>;
}
pub trait QMerkleStoreWriterMutBase<Hash: PartialEq + Copy> {
    fn set_node_split(&mut self, node_key: SimpleMerkleNodeKey, value: Hash);
    fn set_node(&mut self, node: SimpleMerkleNode<Hash>);
    fn set_nodes(&mut self, nodes: &[SimpleMerkleNode<Hash>]);
}

pub trait QMerkleStoreMutBase<Hash: PartialEq + Copy>: QMerkleStoreReaderBase<Hash> + QMerkleStoreWriterMutBase<Hash> {}
impl<T: QMerkleStoreReaderBase<Hash> + QMerkleStoreWriterMutBase<Hash>, Hash: PartialEq + Copy> QMerkleStoreMutBase<Hash> for T {}

