use crate::{
    crypto::hash::{merkle_node_cache::QMerkleNodeCacheReader, traits::MerkleHasher},
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
            self.mark_updated(current_key, current_hash);
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
    fn get_total_node_count(&self) -> usize;
    fn drain_updates(self) -> Vec<SimpleMerkleNode<Hash>>;
    fn new_clean() -> Self where Self: Sized;
}

pub trait QMerkleUpdaterSyncMut<Hash: PartialEq + Copy>: QMerkleUpdaterWriterSyncMut<Hash> + QMerkleUpdaterReaderSync<Hash> {}
impl<T, Hash: PartialEq + Copy> QMerkleUpdaterSyncMut<Hash> for T where T: QMerkleUpdaterWriterSyncMut<Hash> + QMerkleUpdaterReaderSync<Hash> {}

#[derive(Clone, Debug)]
pub struct SimpleMemoryMerkleUpdater<Hash: PartialEq + Copy + Clone> {
    pub updates: Vec<SimpleMerkleNode<Hash>>,
    pub count: usize,
}
impl<Hash: PartialEq + Copy + Clone> SimpleMemoryMerkleUpdater<Hash> {
    pub fn new() -> Self {
        Self { updates: vec![], count: 0 }
    }
    pub fn add_update(&mut self, key: SimpleMerkleNodeKey, new_value: Hash) {
        self.updates.push(SimpleMerkleNode { key: key, value: new_value });
        self.count += 1;
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
    fn get_total_node_count(&self) -> usize{
        self.count
    }
    fn drain_updates(self) -> Vec<SimpleMerkleNode<Hash>> {
        self.finalize()
    }
    
    fn new_clean() -> Self {
        Self::new()
    }
}



#[derive(Clone, Debug)]
pub struct SimpleMemoryMerkleUpdaterUnique<Hash: PartialEq + Copy + Clone> {
    pub key_to_update: std::collections::HashMap<SimpleMerkleNodeKey, Hash>,
    pub count: usize,
}
impl<Hash: PartialEq + Copy + Clone> SimpleMemoryMerkleUpdaterUnique<Hash> {
    pub fn new() -> Self {
        Self { key_to_update: std::collections::HashMap::new(), count: 0 }
    }
    pub fn add_update(&mut self, key: SimpleMerkleNodeKey, new_value: Hash) {
        self.key_to_update.insert(key, new_value);
        self.count += 1;
    }
    pub fn finalize(self) -> Vec<SimpleMerkleNode<Hash>> {
        self.key_to_update.into_iter().map(|(k, v)| SimpleMerkleNode { key: k, value: v }).collect()
    }
}

impl<Hash: PartialEq + Copy + Clone> QMerkleUpdaterWriterSyncMut<Hash> for SimpleMemoryMerkleUpdaterUnique<Hash> {
    fn mark_updated(&mut self, key: SimpleMerkleNodeKey, value: Hash) {
        self.add_update(key, value);
    }
}
impl<Hash: PartialEq + Copy + Clone> QMerkleUpdaterReaderSync<Hash> for SimpleMemoryMerkleUpdaterUnique<Hash> {
    fn drain_updates(self) -> Vec<SimpleMerkleNode<Hash>> {
        self.finalize()
    }
    
    fn get_total_node_count(&self) -> usize {
        self.count
    }
    
    fn new_clean() -> Self where Self: Sized {
        Self::new()
    }
}


impl<Hash: PartialEq + Copy + Clone> QMerkleNodeCacheReader<Hash> for SimpleMemoryMerkleUpdaterUnique<Hash> {
    fn contains(&self, key: &SimpleMerkleNodeKey) -> bool {
        self.key_to_update.contains_key(key)
    }
    fn get_ref(&self, key: &SimpleMerkleNodeKey) -> Option<&Hash> {
        self.key_to_update.get(key)
    }
    fn get(&self, key: &SimpleMerkleNodeKey) -> Option<Hash> {
        self.key_to_update.get(key).copied()
    }
}