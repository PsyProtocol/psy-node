use parth_core::data::hash::merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey};

pub trait QParthStats: Sized {
    fn combine_with(&self, other: &Self) -> Self;
}

pub trait QGUTAParthNodeBase<Hash: PartialEq + Copy> {
    fn get_parth_node_key(&self) -> SimpleMerkleNodeKey;
    fn get_parth_node(&self) -> SimpleMerkleNode<Hash>;
    fn get_parth_node_value(&self) -> Hash;
}

pub trait QGUTAParthNodePublicInputsLike<Hash: PartialEq + Copy, Stats: QParthStats>: QGUTAParthNodeBase<Hash> {
    fn get_stats(&self) -> Stats;
}

