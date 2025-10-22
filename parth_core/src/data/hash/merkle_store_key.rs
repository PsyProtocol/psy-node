use std::hash::Hash;

use psy_serialize::{AutoDatabaseSerializationUseFastFixedSerialize, FastFixedSerializable, PsyCanonicalSerializeMetadata};

use crate::{
    data::{
        hash::merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey},
        serializable::{QPDSerializable, QPDSerializableFixed},
    },
    protocol::core_types::Q256BitHash,
    utils::QPGenRandom,
};

pub type QMerkleStoreZeroIdKey = SimpleMerkleNodeKey;
pub type QMerkleStoreZeroIdNode<Hash> = SimpleMerkleNode<Hash>;

#[pderive::serialize_copy_default]
pub struct QMerkleStoreSingleIdKey {
    pub tree_id: u64, // 8
    pub level: u8,    // 9
    pub index: u64,   // 17
}

impl QMerkleStoreSingleIdKey {
    pub fn at_root(&self) -> Self {
        Self {
            tree_id: self.tree_id,
            level: 0,
            index: 0,
        }
    }
    pub fn sibling(&self) -> Self {
        if self.level == 0 {
            self.clone()
        } else if (self.index & 1) == 0 {
            Self {
                tree_id: self.tree_id,
                level: self.level,
                index: self.index + 1,
            }
        } else {
            Self {
                tree_id: self.tree_id,
                level: self.level,
                index: self.index - 1,
            }
        }
    }
    pub fn parent(&self) -> Self {
        if self.level == 0 {
            self.clone()
        } else {
            Self {
                tree_id: self.tree_id,
                level: self.level - 1,
                index: self.index / 2,
            }
        }
    }

    pub fn siblings(&self) -> Vec<Self> {
        let mut result = Vec::with_capacity(self.level as usize);
        let mut current = *self;
        for _ in 0..self.level {
            result.push(current.sibling());
            current = current.parent();
        }
        result
    }

    // if self or other are on the same merkle path
    pub fn is_direct_path_related(&self, other: &Self) -> bool {
        if other.level == self.level {
            self.index == other.index
        } else if other.level < self.level {
            // opt?: (self.index>>(self.level-other.level)) == other.index
            self.parent_at_level(other.level).index == other.index
        } else {
            other.parent_at_level(self.level).index == self.index
        }
    }
    pub fn first_leaf_child(&self, tree_height: u8) -> Self {
        if self.level >= tree_height {
            return self.clone();
        }
        Self {
            tree_id: self.tree_id,
            level: tree_height,
            index: self.index << (tree_height - self.level),
        }
    }
    pub fn left_child(&self) -> Self {
        Self {
            tree_id: self.tree_id,
            level: self.level + 1,
            index: self.index << 1,
        }
    }
    pub fn right_child(&self) -> Self {
        Self {
            tree_id: self.tree_id,
            level: self.level + 1,
            index: (self.index << 1) + 1,
        }
    }
    pub fn is_on_the_right_of(&self, other: &Self) -> bool {
        if other.level == self.level {
            self.index > other.index
        } else if other.level < self.level {
            self.parent_at_level(other.level).index > other.index
        } else {
            self.index > other.parent_at_level(self.level).index
        }
    }
    pub fn is_to_the_left_of(&self, other: &Self) -> bool {
        if other.level == self.level {
            self.index < other.index
        } else if other.level < self.level {
            self.parent_at_level(other.level).index < other.index
        } else {
            self.index < other.parent_at_level(self.level).index
        }
    }

    pub fn parent_at_level(&self, level: u8) -> Self {
        if level > self.level {
            panic!("given level is not above this node")
        }
        self.n_th_ancestor(self.level - level)
    }
    pub fn n_th_ancestor(&self, levels_above: u8) -> Self {
        if levels_above >= self.level {
            self.at_root()
        } else {
            Self {
                tree_id: self.tree_id,
                level: self.level - levels_above,
                index: self.index >> levels_above,
            }
        }
    }
    pub fn is_left_sibling(&self) -> bool {
        self.index % 2 == 0
    }
    pub fn is_right_sibling(&self) -> bool {
        self.index % 2 == 1
    }
    pub fn find_nearest_common_ancestor(&self, other: &Self) -> Self {
        let start_level = u8::min(other.level, self.level);
        let mut self_current = self.parent_at_level(start_level);
        let mut other_current = other.parent_at_level(start_level);
        while !other_current.eq(&self_current) {
            self_current = self_current.parent();
            other_current = other_current.parent();
        }
        self_current
    }
    pub fn get_siblings_keys_to_height(&self, to_level: u8) -> Vec<Self> {
        if to_level > self.level {
            vec![]
        } else {
            let mut my_node = self.clone();
            let mut siblings = Vec::with_capacity((self.level - to_level) as usize);
            while my_node.level != to_level {
                siblings.push(my_node.sibling());
                my_node = my_node.parent();
            }

            siblings
        }
    }
    pub fn get_above_path_to_height(&self, to_level: u8, include_root: bool) -> Vec<Self> {
        if to_level >= self.level {
            vec![]
        } else {
            let mut my_node = self.parent();
            let mut path_node_keys = Vec::with_capacity((self.level - to_level - if include_root { 0 } else { 1 }) as usize);
            while my_node.level != to_level {
                path_node_keys.push(my_node.clone());
                my_node = my_node.parent();
            }
            if include_root {
                path_node_keys.push(my_node);
            }

            path_node_keys
        }
    }
    pub fn get_above_path_without_root(&self) -> Vec<Self> {
        self.get_above_path_to_height(0, false)
    }
    pub fn get_above_path_including_root(&self) -> Vec<Self> {
        self.get_above_path_to_height(0, true)
    }

    pub fn get_path_above_self_to_level(&self, sub_root_level: u8, include_sub_root: bool) -> Vec<Self> {
        if sub_root_level >= self.level {
            return vec![];
        }

        // Determine the level at which we should stop.
        // If we don't include the sub-root, we stop at the level *above* it.
        let stop_level = if include_sub_root {
            sub_root_level
        } else {
            // Use saturating_add to prevent overflow if sub_root_level is 255.
            sub_root_level.saturating_add(1)
        };

        // If the stop level is already at or above our current level, there's no path.
        if stop_level > self.level {
            return vec![];
        }

        let mut path_node_keys = Vec::with_capacity((self.level - sub_root_level) as usize);
        let mut my_node = *self;
        while my_node.level > stop_level {
            my_node = my_node.parent();
            path_node_keys.push(my_node);
        }

        path_node_keys
    }
}
impl FastFixedSerializable<17> for QMerkleStoreSingleIdKey {
    fn ffs_from_owned_bytes(data: [u8; 17]) -> Self {
        Self {
            tree_id: u64::from_le_bytes(data[0..8].try_into().unwrap()),
            level: data[8],
            index: u64::from_le_bytes(data[9..17].try_into().unwrap()),
        }
    }

    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        Self {
            tree_id: u64::from_le_bytes(data[0..8].try_into().unwrap()),
            level: data[8],
            index: u64::from_le_bytes(data[9..17].try_into().unwrap()),
        }
    }

    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != 17 {
            anyhow::bail!("invalid length for QMerkleStoreSingleIdKey, expected 17 bytes, got {}", data.len());
        }
        Ok(Self {
            tree_id: u64::from_le_bytes(data[0..8].try_into().unwrap()),
            level: data[8],
            index: u64::from_le_bytes(data[9..17].try_into().unwrap()),
        })
    }

    fn ffs_to_bytes(&self) -> [u8; 17] {
        let mut data: [u8; 17] = [0u8; 17];
        data[0..8].copy_from_slice(&self.tree_id.to_le_bytes());
        data[8] = self.level;

        data[9..17].copy_from_slice(&self.index.to_le_bytes());
        data
    }

    fn ffs_into_bytes(self) -> [u8; 17] {
        let mut data: [u8; 17] = [0u8; 17];
        data[0..8].copy_from_slice(&self.tree_id.to_le_bytes());
        data[8] = self.level;

        data[9..17].copy_from_slice(&self.index.to_le_bytes());
        data
    }
}
impl PsyCanonicalSerializeMetadata for QMerkleStoreSingleIdKey {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 17;
}
impl AutoDatabaseSerializationUseFastFixedSerialize<17> for QMerkleStoreSingleIdKey {}
psy_serialize::impl_psy_canonical_serialize_for_fixed_type!(QMerkleStoreSingleIdKey, 17);

impl QPDSerializable for QMerkleStoreSingleIdKey {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut data: [u8; 17] = [0u8; 17];
        data[0..8].copy_from_slice(&self.tree_id.to_le_bytes());
        data[8] = self.level;

        data[9..17].copy_from_slice(&self.index.to_le_bytes());
        Ok(data.to_vec())
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 17 {
            anyhow::bail!("invalid length for QMerkleStoreSingleIdKey, expected 17 bytes, got {}", bytes.len());
        }
        Ok(Self {
            tree_id: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            level: bytes[8],
            index: u64::from_le_bytes(bytes[9..17].try_into().unwrap()),
        })
    }
}

impl QPDSerializableFixed for QMerkleStoreSingleIdKey {
    fn get_fixed_size() -> usize {
        17
    }
}

impl QPGenRandom for QMerkleStoreSingleIdKey {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            tree_id: QPGenRandom::qp_rand_gen(),
            level: QPGenRandom::qp_rand_gen(),
            index: QPGenRandom::qp_rand_gen(),
        }
    }
}

#[pderive::serialize_copy_default]
pub struct QMerkleStoreSingleIdNode<Hash> {
    pub key: QMerkleStoreSingleIdKey,
    pub value: Hash,
}
impl<Hash: QPGenRandom> QPGenRandom for QMerkleStoreSingleIdNode<Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            key: QMerkleStoreSingleIdKey::qp_rand_gen(),
            value: QPGenRandom::qp_rand_gen(),
        }
    }
}
impl<Hash: Q256BitHash> FastFixedSerializable<49> for QMerkleStoreSingleIdNode<Hash> {
    fn ffs_from_owned_bytes(data: [u8; 49]) -> Self {
        Self {
            key: QMerkleStoreSingleIdKey::ffs_from_owned_bytes(data[0..17].try_into().unwrap()),
            value: Hash::from_ref_32bytes(data[17..49].try_into().unwrap()),
        }
    }

    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        Self {
            key: QMerkleStoreSingleIdKey::ffs_from_slice_or_panic(&data[0..17]),
            value: Hash::from_ref_32bytes(data[17..49].try_into().unwrap()),
        }
    }

    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != 49 {
            anyhow::bail!("invalid length for QMerkleStoreSingleIdNode, expected 49 bytes, got {}", data.len());
        }
        Ok(Self {
            key: QMerkleStoreSingleIdKey::ffs_try_from_slice(&data[0..17])?,
            value: Hash::from_slice_32bytes(&data[17..49])?,
        })
    }

    fn ffs_to_bytes(&self) -> [u8; 49] {
        let mut data: [u8; 49] = [0u8; 49];
        data[0..17].copy_from_slice(&self.key.ffs_to_bytes());
        data[17..49].copy_from_slice(&self.value.into_owned_32bytes());
        data
    }

    fn ffs_into_bytes(self) -> [u8; 49] {
        let mut data: [u8; 49] = [0u8; 49];
        data[0..17].copy_from_slice(&self.key.ffs_into_bytes());
        data[17..49].copy_from_slice(&self.value.into_owned_32bytes());
        data
    }
}

impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for QMerkleStoreSingleIdNode<Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 49;
}
impl<Hash: Q256BitHash> AutoDatabaseSerializationUseFastFixedSerialize<49> for QMerkleStoreSingleIdNode<Hash> {}
psy_serialize::impl_psy_canonical_serialize_for_fixed_type!(
    QMerkleStoreSingleIdNode,
    {Hash: Q256BitHash} => {Hash},
    49
);

#[pderive::serialize_copy_default]
pub struct QMerkleStoreDoubleIdKey {
    pub tree_id: u64,     // 8
    pub tree_sub_id: u64, // 16
    pub level: u8,        // 17
    pub index: u64,       // 25
}

impl QMerkleStoreDoubleIdKey {
    pub fn at_root(&self) -> Self {
        Self {
            tree_id: self.tree_id,
            tree_sub_id: self.tree_sub_id,
            level: 0,
            index: 0,
        }
    }
    pub fn sibling(&self) -> Self {
        if self.level == 0 {
            self.clone()
        } else if (self.index & 1) == 0 {
            Self {
                tree_id: self.tree_id,
                tree_sub_id: self.tree_sub_id,
                level: self.level,
                index: self.index + 1,
            }
        } else {
            Self {
                tree_id: self.tree_id,
                tree_sub_id: self.tree_sub_id,
                level: self.level,
                index: self.index - 1,
            }
        }
    }
    pub fn parent(&self) -> Self {
        if self.level == 0 {
            self.clone()
        } else {
            Self {
                tree_id: self.tree_id,
                tree_sub_id: self.tree_sub_id,
                level: self.level - 1,
                index: self.index / 2,
            }
        }
    }

    pub fn siblings(&self) -> Vec<Self> {
        let mut result = Vec::with_capacity(self.level as usize);
        let mut current = *self;
        for _ in 0..self.level {
            result.push(current.sibling());
            current = current.parent();
        }
        result
    }

    // if self or other are on the same merkle path
    pub fn is_direct_path_related(&self, other: &Self) -> bool {
        if other.level == self.level {
            self.index == other.index
        } else if other.level < self.level {
            // opt?: (self.index>>(self.level-other.level)) == other.index
            self.parent_at_level(other.level).index == other.index
        } else {
            other.parent_at_level(self.level).index == self.index
        }
    }
    pub fn first_leaf_child(&self, tree_height: u8) -> Self {
        if self.level >= tree_height {
            return self.clone();
        }
        Self {
            tree_id: self.tree_id,
            tree_sub_id: self.tree_sub_id,
            level: tree_height,
            index: self.index << (tree_height - self.level),
        }
    }
    pub fn left_child(&self) -> Self {
        Self {
            tree_id: self.tree_id,
            tree_sub_id: self.tree_sub_id,
            level: self.level + 1,
            index: self.index << 1,
        }
    }
    pub fn right_child(&self) -> Self {
        Self {
            tree_id: self.tree_id,
            tree_sub_id: self.tree_sub_id,
            level: self.level + 1,
            index: (self.index << 1) + 1,
        }
    }
    pub fn is_on_the_right_of(&self, other: &Self) -> bool {
        if other.level == self.level {
            self.index > other.index
        } else if other.level < self.level {
            self.parent_at_level(other.level).index > other.index
        } else {
            self.index > other.parent_at_level(self.level).index
        }
    }
    pub fn is_to_the_left_of(&self, other: &Self) -> bool {
        if other.level == self.level {
            self.index < other.index
        } else if other.level < self.level {
            self.parent_at_level(other.level).index < other.index
        } else {
            self.index < other.parent_at_level(self.level).index
        }
    }

    pub fn parent_at_level(&self, level: u8) -> Self {
        if level > self.level {
            panic!("given level is not above this node")
        }
        self.n_th_ancestor(self.level - level)
    }
    pub fn n_th_ancestor(&self, levels_above: u8) -> Self {
        if levels_above >= self.level {
            self.at_root()
        } else {
            Self {
                tree_id: self.tree_id,
                tree_sub_id: self.tree_sub_id,
                level: self.level - levels_above,
                index: self.index >> levels_above,
            }
        }
    }
    pub fn is_left_sibling(&self) -> bool {
        self.index % 2 == 0
    }
    pub fn is_right_sibling(&self) -> bool {
        self.index % 2 == 1
    }
    pub fn find_nearest_common_ancestor(&self, other: &Self) -> Self {
        let start_level = u8::min(other.level, self.level);
        let mut self_current = self.parent_at_level(start_level);
        let mut other_current = other.parent_at_level(start_level);
        while !other_current.eq(&self_current) {
            self_current = self_current.parent();
            other_current = other_current.parent();
        }
        self_current
    }
    pub fn get_siblings_keys_to_height(&self, to_level: u8) -> Vec<Self> {
        if to_level > self.level {
            vec![]
        } else {
            let mut my_node = self.clone();
            let mut siblings = Vec::with_capacity((self.level - to_level) as usize);
            while my_node.level != to_level {
                siblings.push(my_node.sibling());
                my_node = my_node.parent();
            }

            siblings
        }
    }
    pub fn get_above_path_to_height(&self, to_level: u8, include_root: bool) -> Vec<Self> {
        if to_level >= self.level {
            vec![]
        } else {
            let mut my_node = self.parent();
            let mut path_node_keys = Vec::with_capacity((self.level - to_level - if include_root { 0 } else { 1 }) as usize);
            while my_node.level != to_level {
                path_node_keys.push(my_node.clone());
                my_node = my_node.parent();
            }
            if include_root {
                path_node_keys.push(my_node);
            }

            path_node_keys
        }
    }
    pub fn get_above_path_without_root(&self) -> Vec<Self> {
        self.get_above_path_to_height(0, false)
    }
    pub fn get_above_path_including_root(&self) -> Vec<Self> {
        self.get_above_path_to_height(0, true)
    }

    pub fn get_path_above_self_to_level(&self, sub_root_level: u8, include_sub_root: bool) -> Vec<Self> {
        if sub_root_level >= self.level {
            return vec![];
        }

        // Determine the level at which we should stop.
        // If we don't include the sub-root, we stop at the level *above* it.
        let stop_level = if include_sub_root {
            sub_root_level
        } else {
            // Use saturating_add to prevent overflow if sub_root_level is 255.
            sub_root_level.saturating_add(1)
        };

        // If the stop level is already at or above our current level, there's no path.
        if stop_level > self.level {
            return vec![];
        }

        let mut path_node_keys = Vec::with_capacity((self.level - sub_root_level) as usize);
        let mut my_node = *self;
        while my_node.level > stop_level {
            my_node = my_node.parent();
            path_node_keys.push(my_node);
        }

        path_node_keys
    }
}
impl FastFixedSerializable<25> for QMerkleStoreDoubleIdKey {
    fn ffs_from_owned_bytes(data: [u8; 25]) -> Self {
        Self {
            tree_id: u64::from_le_bytes(data[0..8].try_into().unwrap()),
            tree_sub_id: u64::from_le_bytes(data[8..16].try_into().unwrap()),
            level: data[16],
            index: u64::from_le_bytes(data[17..25].try_into().unwrap()),
        }
    }

    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        Self {
            tree_id: u64::from_le_bytes(data[0..8].try_into().unwrap()),
            tree_sub_id: u64::from_le_bytes(data[8..16].try_into().unwrap()),
            level: data[16],
            index: u64::from_le_bytes(data[17..25].try_into().unwrap()),
        }
    }

    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != 25 {
            anyhow::bail!("invalid length for QMerkleStoreDoubleIdKey, expected 25 bytes, got {}", data.len());
        }
        Ok(Self {
            tree_id: u64::from_le_bytes(data[0..8].try_into().unwrap()),
            tree_sub_id: u64::from_le_bytes(data[8..16].try_into().unwrap()),
            level: data[16],
            index: u64::from_le_bytes(data[17..25].try_into().unwrap()),
        })
    }

    fn ffs_to_bytes(&self) -> [u8; 25] {
        let mut data: [u8; 25] = [0u8; 25];
        data[0..8].copy_from_slice(&self.tree_id.to_le_bytes());
        data[8..16].copy_from_slice(&self.tree_sub_id.to_le_bytes());
        data[16] = self.level;

        data[17..25].copy_from_slice(&self.index.to_le_bytes());
        data
    }

    fn ffs_into_bytes(self) -> [u8; 25] {
        let mut data: [u8; 25] = [0u8; 25];
        data[0..8].copy_from_slice(&self.tree_id.to_le_bytes());
        data[8..16].copy_from_slice(&self.tree_sub_id.to_le_bytes());
        data[16] = self.level;

        data[17..25].copy_from_slice(&self.index.to_le_bytes());
        data
    }
}
impl PsyCanonicalSerializeMetadata for QMerkleStoreDoubleIdKey {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 25;
}
impl AutoDatabaseSerializationUseFastFixedSerialize<25> for QMerkleStoreDoubleIdKey {}
psy_serialize::impl_psy_canonical_serialize_for_fixed_type!(QMerkleStoreDoubleIdKey, 25);
impl QPGenRandom for QMerkleStoreDoubleIdKey {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            tree_id: QPGenRandom::qp_rand_gen(),
            tree_sub_id: QPGenRandom::qp_rand_gen(),
            level: QPGenRandom::qp_rand_gen(),
            index: QPGenRandom::qp_rand_gen(),
        }
    }
}
impl QPDSerializable for QMerkleStoreDoubleIdKey {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut data: [u8; 25] = [0u8; 25];
        data[0..8].copy_from_slice(&self.tree_id.to_le_bytes());
        data[8..16].copy_from_slice(&self.tree_sub_id.to_le_bytes());
        data[16] = self.level;

        data[17..25].copy_from_slice(&self.index.to_le_bytes());
        Ok(data.to_vec())
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 25 {
            anyhow::bail!("invalid length for QMerkleStoreDoubleIdKey, expected 25 bytes, got {}", bytes.len());
        }
        Ok(Self {
            tree_id: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            tree_sub_id: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            level: bytes[16],
            index: u64::from_le_bytes(bytes[17..25].try_into().unwrap()),
        })
    }
}

impl QPDSerializableFixed for QMerkleStoreDoubleIdKey {
    fn get_fixed_size() -> usize {
        25
    }
}

#[pderive::serialize_copy_default]
pub struct QMerkleStoreDoubleIdNode<Hash> {
    pub key: QMerkleStoreDoubleIdKey,
    pub value: Hash,
}
impl<Hash: Copy> QMerkleStoreDoubleIdNode<Hash> {
    pub fn from_simple_merkle_nodes_for_tree_clone(tree_id: u64, tree_sub_id: u64, nodes: &[SimpleMerkleNode<Hash>]) -> Vec<Self> {
        let mut result = Vec::with_capacity(nodes.len());
        for node in nodes {
            result.push(Self {
                key: QMerkleStoreDoubleIdKey {
                    tree_id,
                    tree_sub_id,
                    level: node.key.level,
                    index: node.key.index,
                },
                value: node.value,
            });
        }
        result
    }
    pub fn from_simple_merkle_nodes_for_tree_owned(tree_id: u64, tree_sub_id: u64, nodes: Vec<SimpleMerkleNode<Hash>>) -> Vec<Self> {
        let mut result = Vec::with_capacity(nodes.len());
        for node in nodes {
            result.push(Self {
                key: QMerkleStoreDoubleIdKey {
                    tree_id,
                    tree_sub_id,
                    level: node.key.level,
                    index: node.key.index,
                },
                value: node.value,
            });
        }
        result
    }
}

impl<Hash: QPGenRandom> QPGenRandom for QMerkleStoreDoubleIdNode<Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            key: QMerkleStoreDoubleIdKey::qp_rand_gen(),
            value: QPGenRandom::qp_rand_gen(),
        }
    }
}
impl<Hash: Q256BitHash> FastFixedSerializable<57> for QMerkleStoreDoubleIdNode<Hash> {
    fn ffs_from_owned_bytes(data: [u8; 57]) -> Self {
        Self {
            key: QMerkleStoreDoubleIdKey::ffs_from_owned_bytes(data[0..25].try_into().unwrap()),
            value: Hash::from_ref_32bytes(data[25..57].try_into().unwrap()),
        }
    }

    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        Self {
            key: QMerkleStoreDoubleIdKey::ffs_from_slice_or_panic(&data[0..25]),
            value: Hash::from_ref_32bytes(data[25..57].try_into().unwrap()),
        }
    }

    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != 57 {
            anyhow::bail!("invalid length for QMerkleStoreDoubleIdNode, expected 57 bytes, got {}", data.len());
        }
        Ok(Self {
            key: QMerkleStoreDoubleIdKey::ffs_try_from_slice(&data[0..25])?,
            value: Hash::from_slice_32bytes(&data[25..57])?,
        })
    }

    fn ffs_to_bytes(&self) -> [u8; 57] {
        let mut data: [u8; 57] = [0u8; 57];
        data[0..25].copy_from_slice(&self.key.ffs_to_bytes());
        data[25..57].copy_from_slice(&self.value.into_owned_32bytes());
        data
    }

    fn ffs_into_bytes(self) -> [u8; 57] {
        let mut data: [u8; 57] = [0u8; 57];
        data[0..25].copy_from_slice(&self.key.ffs_into_bytes());
        data[25..57].copy_from_slice(&self.value.into_owned_32bytes());
        data
    }
}

impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for QMerkleStoreDoubleIdNode<Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 57;
}
impl<Hash: Q256BitHash> AutoDatabaseSerializationUseFastFixedSerialize<57> for QMerkleStoreDoubleIdNode<Hash> {}
psy_serialize::impl_psy_canonical_serialize_for_fixed_type!(
    QMerkleStoreDoubleIdNode,
    {Hash: Q256BitHash} => {Hash},
    57
);

pub fn convert_ffs_array_to_vec<const N: usize, T: FastFixedSerializable<N>>(data: &[T]) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::with_capacity(data.len() * N);
    for item in data {
        result.extend_from_slice(&item.ffs_to_bytes());
    }
    result
}
