use kvq::traits::{KVQSerializable, ScyllaKey};
use plonky2::field::types::PrimeField64;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KVQTreeNodePosition {
    pub level: u8,
    pub index: u64,
}

impl KVQTreeNodePosition {
    pub fn new(level: u8, index: u64) -> Self {
        Self { level, index }
    }
    pub fn new_u8_f<F: PrimeField64>(level: u8, index: F) -> Self {
        Self {
            level: level,
            index: index.to_canonical_u64(),
        }
    }
    pub fn new_ff<F: PrimeField64>(level: F, index: F) -> Self {
        Self {
            level: level.to_canonical_u64() as u8,
            index: index.to_canonical_u64(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KVQTreeIdentifier {
    pub tree_id: u8,
    pub primary_id: u64,
    pub secondary_id: u32,
}
impl KVQTreeIdentifier {
    pub fn new_simple_id(tree_id: u8) -> Self {
        Self {
            tree_id,
            primary_id: 0,
            secondary_id: 0,
        }
    }
    pub fn new(tree_id: u8, primary_id: u64, secondary_id: u32) -> Self {
        Self {
            tree_id,
            primary_id,
            secondary_id,
        }
    }
    pub fn new_ff<F: PrimeField64>(tree_id: u8, primary_id: F, secondary_id: F) -> Self {
        Self {
            tree_id,
            primary_id: primary_id.to_canonical_u64(),
            secondary_id: secondary_id.to_canonical_u64() as u32,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KVQMerkleNodeKey<const TABLE_TYPE: u16> {
    pub tree_id: u8,
    pub primary_id: u64,
    pub secondary_id: u32,
    pub level: u8,
    pub index: u64,
    pub checkpoint_id: u64,
}
impl<const TABLE_TYPE: u16> KVQMerkleNodeKey<TABLE_TYPE> {
    pub fn node_list_in_same_tree(list: &[Self]) -> bool {
        if list.len() == 0 {
            false
        } else if list.len() == 1 {
            true
        } else {
            let first = list[0];
            for key in list.iter() {
                if !first.belongs_to_same_tree(key) {
                    return false;
                }
            }
            true
        }
    }
    pub fn new_simple(tree_id: u8, level: u8, index: u64, checkpoint: u64) -> Self {
        Self {
            tree_id,
            primary_id: 0,
            secondary_id: 0,
            level,
            index,
            checkpoint_id: checkpoint,
        }
    }
    pub fn is_same_node_location(&self, other: &Self) -> bool {
        self.tree_id == other.tree_id
            && self.primary_id == other.primary_id
            && self.secondary_id == other.secondary_id
            && self.level == other.level
            && self.index == other.index
    }
    pub fn belongs_to_same_tree(&self, other: &Self) -> bool {
        self.tree_id == other.tree_id && self.primary_id == other.primary_id && self.secondary_id == other.secondary_id
    }
    pub fn is_sibling_for(&self, other: &Self) -> bool {
        self.level == other.level &&
        self.index ^ 1 == other.index &&
        //inlined self.belongs_to_same_tree(other)
        self.tree_id == other.tree_id &&
        self.primary_id == other.primary_id &&
        self.secondary_id == other.secondary_id
    }
    pub fn sibling(&self) -> Self {
        Self {
            tree_id: self.tree_id,
            primary_id: self.primary_id,
            secondary_id: self.secondary_id,
            level: self.level,
            index: self.index ^ 1,
            checkpoint_id: self.checkpoint_id,
        }
    }
    pub fn at_checkpoint(&self, checkpoint_id: u64) -> Self {
        Self {
            tree_id: self.tree_id,
            primary_id: self.primary_id,
            secondary_id: self.secondary_id,
            level: self.level,
            index: self.index,
            checkpoint_id,
        }
    }
    pub fn siblings(&self) -> Vec<KVQMerkleNodeKey<TABLE_TYPE>> {
        let mut result: Vec<KVQMerkleNodeKey<TABLE_TYPE>> = Vec::with_capacity(self.level as usize);
        let mut current = *self;
        for _ in 0..self.level {
            result.push(current.sibling());
            current = current.parent();
        }
        result
    }
    pub fn siblings_to_level(&self, top_level: u8) -> Vec<KVQMerkleNodeKey<TABLE_TYPE>> {
        if top_level >= self.level {
            Vec::new()
        } else {
            let sibling_count = (self.level - top_level) as usize;
            let mut result: Vec<KVQMerkleNodeKey<TABLE_TYPE>> = Vec::with_capacity(sibling_count);
            let mut current = *self;
            for _ in 0..sibling_count {
                result.push(current.sibling());
                current = current.parent();
            }
            result
        }
    }
    pub fn siblings_above(&self, num_levels: usize) -> Vec<KVQMerkleNodeKey<TABLE_TYPE>> {
        let mut result: Vec<KVQMerkleNodeKey<TABLE_TYPE>> = Vec::with_capacity(num_levels);
        let mut current = *self;
        for _ in 0..num_levels {
            result.push(current.sibling());
            current = current.parent();
        }
        result
    }
    pub fn parent(&self) -> Self {
        if self.level == 0 {
            return *self;
        }
        Self {
            tree_id: self.tree_id,
            primary_id: self.primary_id,
            secondary_id: self.secondary_id,
            level: self.level - 1,
            index: self.index >> 1,
            checkpoint_id: self.checkpoint_id,
        }
    }
    pub fn root(&self) -> Self {
        if self.level == 0 {
            return *self;
        }
        Self {
            tree_id: self.tree_id,
            primary_id: self.primary_id,
            secondary_id: self.secondary_id,
            level: 0,
            index: 0,
            checkpoint_id: self.checkpoint_id,
        }
    }
    pub fn at_index(&self, index: u64) -> Self {
        Self {
            tree_id: self.tree_id,
            primary_id: self.primary_id,
            secondary_id: self.secondary_id,
            level: self.level,
            index,
            checkpoint_id: self.checkpoint_id,
        }
    }
    pub fn at_position(&self, level: u8, index: u64) -> Self {
        Self {
            tree_id: self.tree_id,
            primary_id: self.primary_id,
            secondary_id: self.secondary_id,
            level,
            index,
            checkpoint_id: self.checkpoint_id,
        }
    }
    pub fn first_leaf_child(&self, tree_height: u8) -> Self {
        if self.level >= tree_height {
            let leaf_index = if self.level > tree_height {
                self.index >> (self.level - tree_height)
            } else {
                self.index
            };
            return Self {
                level: tree_height,
                index: leaf_index,
                tree_id: self.tree_id,
                primary_id: self.primary_id,
                secondary_id: self.secondary_id,
                checkpoint_id: self.checkpoint_id,
            };
        }
        Self {
            level: tree_height,
            index: self.index << (tree_height - self.level),
            tree_id: self.tree_id,
            primary_id: self.primary_id,
            secondary_id: self.secondary_id,
            checkpoint_id: self.checkpoint_id,
        }
    }
    pub fn left_child(&self) -> Self {
        Self {
            level: self.level + 1,
            index: self.index << 1,
            tree_id: self.tree_id,
            primary_id: self.primary_id,
            secondary_id: self.secondary_id,
            checkpoint_id: self.checkpoint_id,
        }
    }
    pub fn right_child(&self) -> Self {
        Self {
            level: self.level + 1,
            index: (self.index << 1) + 1,
            tree_id: self.tree_id,
            primary_id: self.primary_id,
            secondary_id: self.secondary_id,
            checkpoint_id: self.checkpoint_id,
        }
    }

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
    pub fn is_on_the_right_of(&self, other: &Self) -> bool {
        if other.level == self.level {
            self.index > other.index
        } else if other.level < self.level {
            self.parent_at_level(other.level).index > other.index
        } else {
            self.index > other.parent_at_level(self.level).index
        }
    }
    pub fn is_left_child(&self) -> bool {
        self.index & 1 == 0
    }
    pub fn is_right_child(&self) -> bool {
        self.index & 1 == 1
    }
    pub fn is_to_the_left_of(&self, other: &Self) -> bool {
        // Add validation to ensure nodes are from the same tree
        if self.tree_id != other.tree_id || self.primary_id != other.primary_id || self.secondary_id != other.secondary_id {
            panic!(
                "Cannot compare nodes from different trees: self({}, {}, {}) vs other({}, {}, {})",
                self.tree_id, self.primary_id, self.secondary_id, other.tree_id, other.primary_id, other.secondary_id
            );
        }
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
            // panic!("given level is not above this node")
            panic!(
                "Invalid level request: trying to get ancestor at level {} for node at level {} (index: {}). \
                Level {} is further from root than current level {}.",
                level, self.level, self.index, level, self.level
            );
        }
        self.n_th_ancestor(self.level - level)
    }
    pub fn n_th_ancestor(&self, levels_above: u8) -> Self {
        if levels_above >= self.level {
            self.root()
        } else {
            self.at_position(self.level - levels_above, self.index >> (levels_above as u64))
        }
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
}

impl<const TABLE_TYPE: u16> PartialOrd for KVQMerkleNodeKey<TABLE_TYPE> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match self.tree_id.partial_cmp(&other.tree_id) {
            Some(core::cmp::Ordering::Equal) => {}
            ord => return ord,
        }
        match self.primary_id.partial_cmp(&other.primary_id) {
            Some(core::cmp::Ordering::Equal) => {}
            ord => return ord,
        }
        match self.secondary_id.partial_cmp(&other.secondary_id) {
            Some(core::cmp::Ordering::Equal) => {}
            ord => return ord,
        }

        if self.level < other.level {
            let other_index = other.index >> (other.level - self.level);
            if other_index != self.index {
                return self.index.partial_cmp(&other_index);
            } else {
                return self.checkpoint_id.partial_cmp(&other.checkpoint_id);
            }
        } else if self.level > other.level {
            let self_index = self.index >> (self.level - other.level);
            if self_index != other.index {
                return self_index.partial_cmp(&other.index);
            } else {
                return self.checkpoint_id.partial_cmp(&other.checkpoint_id);
            }
        }
        match self.index.partial_cmp(&other.index) {
            Some(core::cmp::Ordering::Equal) => {}
            ord => return ord,
        }
        self.checkpoint_id.partial_cmp(&other.checkpoint_id)
    }
}
impl<const TABLE_TYPE: u16> Ord for KVQMerkleNodeKey<TABLE_TYPE> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.tree_id.cmp(&other.tree_id) {
            core::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        match self.primary_id.cmp(&other.primary_id) {
            core::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        match self.secondary_id.cmp(&other.secondary_id) {
            core::cmp::Ordering::Equal => {}
            ord => return ord,
        }

        if self.level < other.level {
            let other_index = other.index >> (other.level - self.level);
            if other_index != self.index {
                return self.index.cmp(&other_index);
            } else {
                return self.checkpoint_id.cmp(&other.checkpoint_id);
            }
        } else if self.level > other.level {
            let self_index = self.index >> (self.level - other.level);
            if self_index != other.index {
                return self_index.cmp(&other.index);
            } else {
                return self.checkpoint_id.cmp(&other.checkpoint_id);
            }
        }
        match self.index.cmp(&other.index) {
            core::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        self.checkpoint_id.cmp(&other.checkpoint_id)
    }
}
impl<const TABLE_TYPE: u16> KVQSerializable for KVQMerkleNodeKey<TABLE_TYPE> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut result: Vec<u8> = Vec::with_capacity(32);
        result.push(((TABLE_TYPE & 0xFF00) >> 8) as u8); // 1
        result.push((TABLE_TYPE & 0xFF) as u8); // 2
        result.push(self.tree_id); // 3
        result.extend_from_slice(&self.primary_id.to_be_bytes()); // 11
        result.extend_from_slice(&self.secondary_id.to_be_bytes()); // 15
        result.push(self.level); // 16
        result.extend_from_slice(&self.index.to_be_bytes()); // 24
        result.extend_from_slice(&self.checkpoint_id.to_be_bytes()); // 32
        Ok(result)
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(Self {
            tree_id: bytes[2],
            primary_id: u64::from_be_bytes(bytes[3..11].try_into().unwrap()),
            secondary_id: u32::from_be_bytes(bytes[11..15].try_into().unwrap()),
            level: bytes[15],
            index: u64::from_be_bytes(bytes[16..24].try_into().unwrap()),
            checkpoint_id: u64::from_be_bytes(bytes[24..32].try_into().unwrap()),
        })
    }
}
impl<const TABLE_TYPE: u16> KVQMerkleNodeKey<TABLE_TYPE> {
    pub fn new(tree_id: u8, primary_id: u64, secondary_id: u32, level: u8, index: u64, checkpoint_id: u64) -> Self {
        Self {
            tree_id,
            primary_id,
            secondary_id,
            level,
            index,
            checkpoint_id,
        }
    }
    pub fn from_position(tree_id: u8, primary_id: u64, secondary_id: u32, checkpoint_id: u64, position: KVQTreeNodePosition) -> Self {
        Self::from_position_ptr(tree_id, primary_id, secondary_id, checkpoint_id, &position)
    }
    pub fn from_position_ptr(tree_id: u8, primary_id: u64, secondary_id: u32, checkpoint_id: u64, position: &KVQTreeNodePosition) -> Self {
        Self {
            tree_id,
            primary_id,
            secondary_id,
            level: position.level,
            index: position.index,
            checkpoint_id,
        }
    }
    pub fn from_identifier_position_ptr(identifier: &KVQTreeIdentifier, checkpoint_id: u64, position: &KVQTreeNodePosition) -> Self {
        Self {
            tree_id: identifier.tree_id,
            primary_id: identifier.primary_id,
            secondary_id: identifier.secondary_id,
            level: position.level,
            index: position.index,
            checkpoint_id,
        }
    }
    pub fn from_identifier_position(identifier: &KVQTreeIdentifier, checkpoint_id: u64, position: KVQTreeNodePosition) -> Self {
        Self {
            tree_id: identifier.tree_id,
            primary_id: identifier.primary_id,
            secondary_id: identifier.secondary_id,
            level: position.level,
            index: position.index,
            checkpoint_id,
        }
    }
}

impl<const TABLE_TYPE: u16> ScyllaKey for KVQMerkleNodeKey<TABLE_TYPE> {
    fn get_partition_key(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(22);
        result.push(self.tree_id);
        result.extend_from_slice(&self.primary_id.to_be_bytes());
        result.extend_from_slice(&self.secondary_id.to_be_bytes());
        result.push(self.level);
        result.extend_from_slice(&self.index.to_be_bytes());
        result
    }

    fn get_clustering_key(&self) -> Option<Vec<u8>> {
        // Only checkpoint_id as clustering key for proper sorting
        Some(self.checkpoint_id.to_be_bytes().to_vec())
    }

    fn get_table_type(&self) -> u16 {
        TABLE_TYPE
    }
}
