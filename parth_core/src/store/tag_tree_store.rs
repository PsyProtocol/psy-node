use async_trait::async_trait;

use crate::{crypto::hash::tag_tree::TagTreeStorageNode, data::hash::merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}, protocol::core_types::QHashBase};

#[async_trait]
pub trait GenericTagTreeStoreReader<Hash: QHashBase> {
    async fn get_node_at_checkpoint_p(&self, tree_id: u32, checkpoint_id: u64, level: u8, index: u64) -> anyhow::Result<TagTreeStorageNode<Hash>>;
    async fn get_nodes_at_checkpoint_p(&self, tree_id: u32, checkpoint_id: u64, nodes: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<TagTreeStorageNode<Hash>>>;
    async fn get_root_at_checkpoint(&self, tree_id: u32, checkpoint_id: u64) -> anyhow::Result<Hash>;
}


#[async_trait]
pub trait GenericTagTreeStoreWriterCore<Hash: QHashBase> {
    async fn put_nodes_for_checkpoint(&self, tree_id: u32, checkpoint_id: u64, nodes: &[SimpleMerkleNode<TagTreeStorageNode<Hash>>]) -> anyhow::Result<()>;
}



#[async_trait]
pub trait GenericTagTreeTempStoreReader<Hash: QHashBase> {
    async fn get_node_at_unique_checkpoint_temp(&self, tree_id: u32, unique_checkpoint_id: u128, level: u8, index: u64) -> anyhow::Result<TagTreeStorageNode<Hash>>;
    async fn get_nodes_at_unique_checkpoint_temp(&self, tree_id: u32, unique_checkpoint_id: u128, nodes: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<TagTreeStorageNode<Hash>>>;

}


#[async_trait]
pub trait GenericTagTreeTempStoreWriter<Hash: QHashBase> {
    async fn put_nodes_for_checkpoint(&self, tree_id: u32, unique_checkpoint_id: u128, nodes: &[SimpleMerkleNode<TagTreeStorageNode<Hash>>]) -> anyhow::Result<()>;
    async fn push_node_to_unique_checkpoint_temp(&self, tree_id: u32, unique_checkpoint_id: u128, partition: u32, node: &SimpleMerkleNode<TagTreeStorageNode<Hash>>) -> anyhow::Result<()>;
}




#[async_trait]
pub trait GenericTagTreeTempStoreDumper<Hash: QHashBase> {
    async fn dump_nodes_for_unique_checkpoint_tmp(&self, tree_id: u32, unique_checkpoint_id: u128, partition: u32) -> anyhow::Result<Vec<SimpleMerkleNode<TagTreeStorageNode<Hash>>>>;
}


pub trait GenericTagTreeTempStore<Hash: QHashBase>: GenericTagTreeTempStoreReader<Hash> + GenericTagTreeTempStoreWriter<Hash> + GenericTagTreeTempStoreDumper<Hash> {}
impl<Hash: QHashBase, T: GenericTagTreeTempStoreReader<Hash> + GenericTagTreeTempStoreWriter<Hash> + GenericTagTreeTempStoreDumper<Hash>> GenericTagTreeTempStore<Hash> for T {}


