use crate::data::{hash::merkle_node_key::SimpleMerkleNodeKey, serializable::{QPDSerializable, QPDSerializableFixed}};

#[pderive::serialize_copy_default]
pub struct TagTreeNodeKey {
    pub tag_tree_id: u32,
    pub key: SimpleMerkleNodeKey,
}

impl TagTreeNodeKey {
    pub fn new(tag_tree_id: u32, level: u8, index: u64) -> Self {
        Self {
            tag_tree_id,
            key: SimpleMerkleNodeKey { level, index },
        }
    }
    pub fn sibling(&self) -> Self {
        Self {
            tag_tree_id: self.tag_tree_id,
            key: self.key.sibling(),
        }
    }
    pub fn parent(&self) -> Self {
        let parent_key = self.key.parent();
        Self {
            tag_tree_id: self.tag_tree_id,
            key: parent_key,
        }
    }
    pub fn siblings(&self) -> Vec<Self> {
        let siblings = self.key.siblings();
        siblings
            .into_iter()
            .map(|s| Self {
                tag_tree_id: self.tag_tree_id,
                key: s,
            })
            .collect()
    }
    pub fn is_direct_path_related(&self, other: &TagTreeNodeKey) -> bool {
        if self.tag_tree_id != other.tag_tree_id {
            return false;
        }
        self.key.is_direct_path_related(&other.key)
    }
    pub fn parent_at_level(&self, level: u8) -> Self {
        let parent_key = self.key.parent_at_level(level);
        Self {
            tag_tree_id: self.tag_tree_id,
            key: parent_key,
        }
    }
    pub fn n_th_ancestor(&self, levels_above: u8) -> Self {
        let ancestor_key = self.key.n_th_ancestor(levels_above);
        Self {
            tag_tree_id: self.tag_tree_id,
            key: ancestor_key,
        }
    }
    pub fn is_left_sibling(&self) -> bool {
        self.key.is_left_sibling()
    }
    pub fn is_right_sibling(&self) -> bool {
        self.key.is_right_sibling()
    }

}

impl QPDSerializable for TagTreeNodeKey {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let tag_tree_id_bytes = u32::to_le_bytes(self.tag_tree_id);
        let index_bytes = u64::to_be_bytes(self.key.index);
        Ok(vec![
            tag_tree_id_bytes[0],
            tag_tree_id_bytes[1],
            tag_tree_id_bytes[2],
            tag_tree_id_bytes[3],
            self.key.level,
            index_bytes[0],
            index_bytes[1],
            index_bytes[2],
            index_bytes[3],
            index_bytes[4],
            index_bytes[5],
            index_bytes[6],
            index_bytes[7],
        ])
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() == 13 {
            Ok(Self {
                tag_tree_id: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
                key: SimpleMerkleNodeKey {
                    level: bytes[4],
                    index: u64::from_be_bytes(bytes[5..13].try_into().unwrap()),
                }
            })
        } else {
            anyhow::bail!(
                "error deserializing TagTreeNodeKey, expected 13 bytes, got {}",
                bytes.len()
            );
        }
    }
}
impl QPDSerializableFixed for TagTreeNodeKey {
    fn get_fixed_size() -> usize {
        13
    }
}


#[pderive::serialize_copy]
pub struct TagTreeNodeKeyWithCheckpoint {
    pub tt_node_key: TagTreeNodeKey,
    pub checkpoint_id: u64,
}

impl TagTreeNodeKeyWithCheckpoint {
    pub fn new(tt_node_key: TagTreeNodeKey, checkpoint_id: u64) -> Self {
        Self { tt_node_key, checkpoint_id }
    }
}


impl QPDSerializable for TagTreeNodeKeyWithCheckpoint {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let tag_tree_id_bytes = u32::to_le_bytes(self.tt_node_key.tag_tree_id);
        let checkpoint_id_bytes = u64::to_be_bytes(self.checkpoint_id);
        let index_bytes = u64::to_be_bytes(self.tt_node_key.key.index);
        Ok(vec![
            tag_tree_id_bytes[0],
            tag_tree_id_bytes[1],
            tag_tree_id_bytes[2],
            tag_tree_id_bytes[3],
            checkpoint_id_bytes[0],
            checkpoint_id_bytes[1],
            checkpoint_id_bytes[2],
            checkpoint_id_bytes[3],
            checkpoint_id_bytes[4],
            checkpoint_id_bytes[5],
            checkpoint_id_bytes[6],
            checkpoint_id_bytes[7],
            self.tt_node_key.key.level,
            index_bytes[0],
            index_bytes[1],
            index_bytes[2],
            index_bytes[3],
            index_bytes[4],
            index_bytes[5],
            index_bytes[6],
            index_bytes[7],
        ])
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() == 21 {
            Ok(Self {
                tt_node_key: TagTreeNodeKey {
                    tag_tree_id: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
                    key: SimpleMerkleNodeKey {
                        level: bytes[4],
                        index: u64::from_be_bytes(bytes[5..13].try_into().unwrap()),
                    },
                },
                checkpoint_id: u64::from_be_bytes(bytes[13..21].try_into().unwrap()),
            })
        } else {
            anyhow::bail!(
                "error deserializing TagTreeNodeKeyWithCheckpoint, expected 21 bytes, got {}",
                bytes.len()
            );
        }
    }
}
impl QPDSerializableFixed for TagTreeNodeKeyWithCheckpoint {
    fn get_fixed_size() -> usize {
        21
    }
}