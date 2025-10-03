use serde::{Deserialize, Serialize};

use crate::{data::hash::{merkle_node_key::SimpleMerkleNodeKey, merkle_store_key::QMerkleStoreKey}, store::merkle_store::SerializableMerkleTableKey};


pub trait DoubleTreeSerializableMerkleTableKey: SerializableMerkleTableKey {
    fn get_primary_id(&self) -> u64;
    fn new_with_primary_id(primary_id: u64) -> Self;
}
pub trait TripleTreeSerializableMerkleTableKey: SerializableMerkleTableKey {
    fn get_primary_id(&self) -> u64;
    fn get_secondary_id(&self) -> u64;
    fn new_with_ids(primary_id: u64, secondary_id: u64) -> Self;
}

pub struct SingleTreeMerkleTableKey<const SINGLE_MERKLE_MAGIC: u16, const TREE_TABLE_ID: u16, const TREE_HEIGHT: u8> {

}
impl <const SINGLE_MERKLE_MAGIC: u16, const TREE_TABLE_ID: u16, const TREE_HEIGHT: u8>  SingleTreeMerkleTableKey<SINGLE_MERKLE_MAGIC, TREE_TABLE_ID, TREE_HEIGHT> {
    pub fn new() -> Self {
        Self {

        }
    }
}
impl <const SINGLE_MERKLE_MAGIC: u16, const TREE_TABLE_ID: u16, const TREE_HEIGHT: u8>  SerializableMerkleTableKey for SingleTreeMerkleTableKey<SINGLE_MERKLE_MAGIC, TREE_TABLE_ID, TREE_HEIGHT> {
    const TREE_HEIGHT: u8 = TREE_HEIGHT;

    fn get_merkle_key_bytes(&self, node: &SimpleMerkleNodeKey, checkpoint_id: u64) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2 + 2 + 1 + 8 + 8);
        bytes.extend(&SINGLE_MERKLE_MAGIC.to_be_bytes());
        bytes.extend(&TREE_TABLE_ID.to_be_bytes());
        bytes.push(node.level);
        bytes.extend(&node.index.to_be_bytes());
        bytes.extend(&checkpoint_id.to_be_bytes());
        bytes
    }
    
    fn decode_merkle_key_bytes(&self, bytes: &[u8]) -> anyhow::Result<QMerkleStoreKey> {
        if bytes.len() != 2 + 2 + 1 + 8 + 8 {
            return Err(anyhow::anyhow!("bytes length incorrect"));
        }
        let magic = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        if magic != SINGLE_MERKLE_MAGIC {
            return Err(anyhow::anyhow!("magic number incorrect"));
        }
        let tree_type = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
        if tree_type != TREE_TABLE_ID {
            return Err(anyhow::anyhow!("tree type incorrect"));
        }
        let level = bytes[4];
        let index = u64::from_be_bytes(bytes[5..13].try_into().unwrap());
        let checkpoint_id = u64::from_be_bytes(bytes[13..21].try_into().unwrap());
        let tree_id = 0;
        Ok(QMerkleStoreKey { tree_type, tree_id, level, index, checkpoint_id })
    }
    
    /*
    fn get_full_merkle_key(&self, node: &SimpleMerkleNodeKey, checkpoint_id: u64) -> QMerkleStoreKey {
        QMerkleStoreKey { tree_type: TREE_TABLE_ID, tree_id: 0, level: node.level, index: node.index, checkpoint_id }
    }

    fn get_merkle_key_bytes(&self, node: &SimpleMerkleNodeKey, checkpoint_id: u64) -> Vec<u8> {
        let bytes = [0u8; ]
    }
    */
}


#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Copy)]
pub struct DoubleTreeMerkleTableKey<const DOUBLE_MERKLE_MAGIC: u16, const TREE_TABLE_ID: u16, const TREE_HEIGHT: u8> {
    pub primary_id: u64,
}
impl <const DOUBLE_MERKLE_MAGIC: u16, const TREE_TABLE_ID: u16, const TREE_HEIGHT: u8>  DoubleTreeMerkleTableKey<DOUBLE_MERKLE_MAGIC, TREE_TABLE_ID, TREE_HEIGHT> {
    pub fn new(primary_id: u64) -> Self {
        Self {
            primary_id,

        }
    }
}
impl <const DOUBLE_MERKLE_MAGIC: u16, const TREE_TABLE_ID: u16, const TREE_HEIGHT: u8>  SerializableMerkleTableKey for DoubleTreeMerkleTableKey<DOUBLE_MERKLE_MAGIC, TREE_TABLE_ID, TREE_HEIGHT> {
    const TREE_HEIGHT: u8 = TREE_HEIGHT;

    fn get_merkle_key_bytes(&self, node: &SimpleMerkleNodeKey, checkpoint_id: u64) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2 + 2 + 1 + 8 + 8 + 8);
        bytes.extend(&DOUBLE_MERKLE_MAGIC.to_be_bytes());
        bytes.extend(&TREE_TABLE_ID.to_be_bytes());
        bytes.extend(&self.primary_id.to_be_bytes());
        bytes.push(node.level);
        bytes.extend(&node.index.to_be_bytes());
        bytes.extend(&checkpoint_id.to_be_bytes());
        bytes
    }
    
    fn decode_merkle_key_bytes(&self, bytes: &[u8]) -> anyhow::Result<QMerkleStoreKey> {
        if bytes.len() != 2 + 2 + 1 + 8 + 8 + 8 {
            return Err(anyhow::anyhow!("bytes length incorrect"));
        }
        let magic = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        if magic != DOUBLE_MERKLE_MAGIC {
            return Err(anyhow::anyhow!("magic number incorrect"));
        }
        let tree_type = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
        if tree_type != TREE_TABLE_ID {
            return Err(anyhow::anyhow!("tree type incorrect"));
        }
        let primary_id = u64::from_be_bytes(bytes[4..12].try_into().unwrap());
        if primary_id != self.primary_id {
            return Err(anyhow::anyhow!("primary id incorrect"));
        }
        let level = bytes[12];
        let index = u64::from_be_bytes(bytes[13..21].try_into().unwrap());
        let checkpoint_id = u64::from_be_bytes(bytes[21..29].try_into().unwrap());
        Ok(QMerkleStoreKey { tree_type, tree_id: primary_id, level, index, checkpoint_id })
    }
    
    /*
    fn get_full_merkle_key(&self, node: &SimpleMerkleNodeKey, checkpoint_id: u64) -> QMerkleStoreKey {
        QMerkleStoreKey { tree_type: TREE_TABLE_ID, tree_id: 0, level: node.level, index: node.index, checkpoint_id }
    }

    fn get_merkle_key_bytes(&self, node: &SimpleMerkleNodeKey, checkpoint_id: u64) -> Vec<u8> {
        let bytes = [0u8; ]
    }
    */
}

impl<const DOUBLE_MERKLE_MAGIC: u16, const TREE_TABLE_ID: u16, const TREE_HEIGHT: u8> DoubleTreeSerializableMerkleTableKey for DoubleTreeMerkleTableKey<DOUBLE_MERKLE_MAGIC, TREE_TABLE_ID, TREE_HEIGHT> {
    fn get_primary_id(&self) -> u64 {
        self.primary_id
    }
    fn new_with_primary_id(primary_id: u64) -> Self {
        Self::new(primary_id)
    }
}


#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Copy)]
pub struct TripleTreeMerkleTableKey<const TRIPLE_MERKLE_MAGIC: u16, const TREE_TABLE_ID: u16, const TREE_HEIGHT: u8> {
    pub primary_id: u64,
    pub secondary_id: u64,
}
impl <const TRIPLE_MERKLE_MAGIC: u16, const TREE_TABLE_ID: u16, const TREE_HEIGHT: u8>  TripleTreeMerkleTableKey<TRIPLE_MERKLE_MAGIC, TREE_TABLE_ID, TREE_HEIGHT> {
    pub fn new(primary_id: u64, secondary_id: u64) -> Self {
        Self {
            primary_id,
            secondary_id,
        }
    }
}
impl <const TRIPLE_MERKLE_MAGIC: u16, const TREE_TABLE_ID: u16, const TREE_HEIGHT: u8>  SerializableMerkleTableKey for TripleTreeMerkleTableKey<TRIPLE_MERKLE_MAGIC, TREE_TABLE_ID, TREE_HEIGHT> {
    const TREE_HEIGHT: u8 = TREE_HEIGHT;

    fn get_merkle_key_bytes(&self, node: &SimpleMerkleNodeKey, checkpoint_id: u64) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2 + 2 + 1 + 8 + 8 + 8 + 8);
        bytes.extend(&TRIPLE_MERKLE_MAGIC.to_be_bytes());
        bytes.extend(&TREE_TABLE_ID.to_be_bytes());
        bytes.extend(&self.primary_id.to_be_bytes());
        bytes.extend(&self.secondary_id.to_be_bytes());
        bytes.push(node.level);
        bytes.extend(&node.index.to_be_bytes());
        bytes.extend(&checkpoint_id.to_be_bytes());
        bytes
    }
    
    fn decode_merkle_key_bytes(&self, bytes: &[u8]) -> anyhow::Result<QMerkleStoreKey> {
        if bytes.len() != 2 + 2 + 1 + 8 + 8 + 8 + 8 {
            return Err(anyhow::anyhow!("bytes length incorrect"));
        }
        let magic = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        if magic != TRIPLE_MERKLE_MAGIC {
            return Err(anyhow::anyhow!("magic number incorrect"));
        }
        let tree_type = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
        if tree_type != TREE_TABLE_ID {
            return Err(anyhow::anyhow!("tree type incorrect"));
        }
        let primary_id = u64::from_be_bytes(bytes[4..12].try_into().unwrap());
        if primary_id != self.primary_id {
            return Err(anyhow::anyhow!("primary id incorrect"));
        }
        let secondary_id = u64::from_be_bytes(bytes[12..20].try_into().unwrap());
        if secondary_id != self.secondary_id {
            return Err(anyhow::anyhow!("secondary id incorrect"));
        }
        let level = bytes[20];
        let index = u64::from_be_bytes(bytes[21..29].try_into().unwrap());
        let checkpoint_id = u64::from_be_bytes(bytes[29..37].try_into().unwrap());
        Ok(QMerkleStoreKey { tree_type, tree_id: primary_id, level, index, checkpoint_id })
    }
    
    /*
    fn get_full_merkle_key(&self, node: &SimpleMerkleNodeKey, checkpoint_id: u64) -> QMerkleStoreKey {
        QMerkleStoreKey { tree_type: TREE_TABLE_ID, tree_id: 0, level: node.level, index: node.index, checkpoint_id }
    }

    fn get_merkle_key_bytes(&self, node: &SimpleMerkleNodeKey, checkpoint_id: u64) -> Vec<u8> {
        let bytes = [0u8; ]
    }
    */
}


impl<const TRIPLE_MERKLE_MAGIC: u16, const TREE_TABLE_ID: u16, const TREE_HEIGHT: u8> TripleTreeSerializableMerkleTableKey for TripleTreeMerkleTableKey<TRIPLE_MERKLE_MAGIC, TREE_TABLE_ID, TREE_HEIGHT> {
    fn get_primary_id(&self) -> u64 {
        self.primary_id
    }
    fn get_secondary_id(&self) -> u64 {
        self.secondary_id
    }
    fn new_with_ids(primary_id: u64, secondary_id: u64) -> Self {
        Self::new(primary_id, secondary_id)
    }
}