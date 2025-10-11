use crate::{
    crypto::hash::traits::MerkleHasher,
    data::hash::merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey},
};

pub trait QMerkleUpdaterWriterSyncMut<Hash: PartialEq + Copy> {
    fn mark_updated(&mut self, key: SimpleMerkleNodeKey, value: Hash);
    fn mark_updates_from_siblings<Hasher: MerkleHasher<Hash>>(
        &mut self,
        key: SimpleMerkleNodeKey,
        new_value: Hash,
        siblings: &[Hash],
        mark_root: bool,
    ) -> Hash {
        if siblings.len() == 0 {
            if mark_root {
                self.mark_updated(key, new_value);
            }
            return new_value;
        }

        let mut current_hash = new_value;
        let mut current_key = key;
        for sibling_hash in siblings.iter() {
            self.mark_updated(key, new_value);
            let swap = (current_key.index & 1) == 1;
            current_hash = Hasher::two_to_one_swap(swap, &current_hash, sibling_hash);
            current_key = current_key.parent();
        }
        if mark_root {
            self.mark_updated(current_key, current_hash);
        }
        current_hash
    }
}
pub trait QMerkleUpdaterReaderSync<Hash: PartialEq + Copy> {
    fn drain_updates(self) -> Vec<SimpleMerkleNode<Hash>>;
}

pub trait QMerkleUpdaterSyncMut<Hash: PartialEq + Copy>: QMerkleUpdaterWriterSyncMut<Hash> + QMerkleUpdaterReaderSync<Hash> {}
impl<T, Hash: PartialEq + Copy> QMerkleUpdaterSyncMut<Hash> for T where T: QMerkleUpdaterWriterSyncMut<Hash> + QMerkleUpdaterReaderSync<Hash> {}

#[derive(Clone, Debug)]
pub struct SimpleMemoryMerkleUpdater<Hash: PartialEq + Copy + Clone> {
    pub updates: Vec<SimpleMerkleNode<Hash>>,
}
impl<Hash: PartialEq + Copy + Clone> SimpleMemoryMerkleUpdater<Hash> {
    pub fn new() -> Self {
        Self { updates: vec![] }
    }
    pub fn add_update(&mut self, key: SimpleMerkleNodeKey, new_value: Hash) {
        self.updates.push(SimpleMerkleNode { key: key, value: new_value });
    }
    pub fn finalize(self) -> Vec<SimpleMerkleNode<Hash>> {
        self.updates
    }
}

impl<Hash: PartialEq + Copy + Clone> QMerkleUpdaterWriterSyncMut<Hash> for SimpleMemoryMerkleUpdater<Hash> {
    fn mark_updated(&mut self, key: SimpleMerkleNodeKey, value: Hash) {
        self.add_update(key, value);
    }
}
impl<Hash: PartialEq + Copy + Clone> QMerkleUpdaterReaderSync<Hash> for SimpleMemoryMerkleUpdater<Hash> {
    fn drain_updates(self) -> Vec<SimpleMerkleNode<Hash>> {
        self.finalize()
    }
}
