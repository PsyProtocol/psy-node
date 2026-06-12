use std::{
    collections::HashMap,
    fmt,
    fmt::{Debug, Display},
};

use kvq::traits::{KVQPair, KVQSerializable};
use psy_crypto::hash::{
    merkle::{
        core::DeltaMerkleProofCore,
        utils::common::{SimpleMerkleNode, SimpleMerkleNodeKey},
    },
    traits::hasher::MerkleHasher,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(bound = "for<'de2> Hash: Deserialize<'de2>")]
pub struct CSTUserUpdate<Hash: PartialEq + Copy + Serialize> {
    pub checkpoint_id: u64,
    pub user_id: u64,
    pub uct_updates: Vec<SimpleMerkleNode<Hash>>,
    pub updates: Vec<CSTDeltaNode<Hash>>,
}

impl<Hash: PartialEq + Copy + Serialize> Debug for CSTUserUpdate<Hash> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let uct_updates_len = self.uct_updates.len();
        let updates_len = self.updates.len();
        f.debug_struct("CSTUserUpdate")
            .field("checkpoint_id", &self.checkpoint_id)
            .field("user_id", &self.user_id)
            .field("uct_updates len", &uct_updates_len)
            .field("update len", &updates_len)
            .finish()
    }
}

// impl<Hash: PartialEq + Copy + Serialize> DrainQueueMetadataTagged for
// CSTUserUpdate<Hash> {     fn get_dq_metadata(&self) -> DrainQueueMetadata {
//         DrainQueueMetadata {
//             channel_id: CST_USER_UPDATE_CHANNEL_ID,
//             checkpoint_id: self.checkpoint_id,
//             item_id: self.user_id,
//         }
//     }
// }
impl<Hash: PartialEq + Copy + Serialize + DeserializeOwned> KVQSerializable for CSTUserUpdate<Hash> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct CSTDeltaNodeKey {
    pub contract_id: u32,
    pub level: u8,
    pub index: u64,
}
impl KVQSerializable for CSTDeltaNodeKey {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

impl CSTDeltaNodeKey {
    pub fn new(contract_id: u32, level: u8, index: u64) -> Self {
        Self { contract_id, level, index }
    }
    pub fn root(&self) -> Self {
        Self {
            contract_id: self.contract_id,
            level: 0,
            index: 0,
        }
    }
    pub fn parent(&self) -> Self {
        if self.level != 0 {
            Self {
                contract_id: self.contract_id,
                level: self.level - 1,
                index: self.index >> 1u64,
            }
        } else {
            Self {
                contract_id: self.contract_id,
                level: 0,
                index: 0,
            }
        }
    }
}
pub type CSTDeltaNode<Hash> = KVQPair<CSTDeltaNodeKey, Hash>;

#[derive(Clone, PartialEq)]
pub struct CSTUserUpdateStore<Hash: PartialEq + Serialize + Copy> {
    pub node_map: HashMap<CSTDeltaNodeKey, Hash>,
    pub uct_node_map: HashMap<SimpleMerkleNodeKey, Hash>,
}
impl<Hash: PartialEq + Serialize + Copy + Display + std::fmt::Debug> CSTUserUpdateStore<Hash> {
    pub fn new() -> Self {
        Self {
            node_map: HashMap::new(),
            uct_node_map: HashMap::new(),
        }
    }
    pub fn verify_injest_uct_delta_merkle_proof<Hasher: MerkleHasher<Hash>>(&mut self, proof: &DeltaMerkleProofCore<Hash>) -> anyhow::Result<()> {
        tracing::debug!("UCT merkle proof: {}", serde_json::to_string_pretty(&proof).unwrap());
        let mut current = proof.old_value;
        for (i, sibling) in proof.siblings.iter().enumerate() {
            current = Hasher::two_to_one_swap(proof.index & (1 << i) != 0, &current, sibling);
        }
        if current != proof.old_root {
            tracing::debug!("UCT verification failed - current: {}, old_root: {}", current, proof.old_root);
            anyhow::bail!("invalid old root");
        }
        current = proof.new_value;
        let mut key = SimpleMerkleNodeKey::new(proof.siblings.len() as u8, proof.index);

        self.uct_node_map.insert(key, current);

        for (i, sibling) in proof.siblings.iter().enumerate() {
            key = key.parent();
            current = Hasher::two_to_one_swap(proof.index & (1 << i) != 0, &current, sibling);
            self.uct_node_map.insert(key, current);
        }
        if current != proof.new_root {
            tracing::debug!("UCT new root verification failed - current: {}, new_root: {}", current, proof.new_root);
            anyhow::bail!("invalid new root!");
        }

        Ok(())
    }
    pub fn verify_injest_delta_merkle_proof<Hasher: MerkleHasher<Hash>>(
        &mut self,
        contract_id: u32,
        proof: &DeltaMerkleProofCore<Hash>,
    ) -> anyhow::Result<()> {
        tracing::debug!("UCT delta merkle proof: {}", serde_json::to_string_pretty(&proof).unwrap());
        let mut current = proof.old_value;
        for (i, sibling) in proof.siblings.iter().enumerate() {
            tracing::debug!("UCT proof step {} - before: current={}, sibling={}", i, current, sibling);
            current = Hasher::two_to_one_swap(proof.index & (1 << i) != 0, &current, sibling);
            tracing::debug!("UCT proof step {} - after: current={}, sibling={}", i, current, sibling);
        }
        if current != proof.old_root {
            tracing::debug!("UCT old root verification failed - current: {}, old_root: {}", current, proof.old_root);
            anyhow::bail!("invalid old root");
        }
        current = proof.new_value;
        let mut key = CSTDeltaNodeKey::new(contract_id, proof.siblings.len() as u8, proof.index);

        self.node_map.insert(key, current);

        for (i, sibling) in proof.siblings.iter().enumerate() {
            key = key.parent();
            current = Hasher::two_to_one_swap(proof.index & (1 << i) != 0, &current, sibling);
            self.node_map.insert(key, current);
        }
        if current != proof.new_root {
            tracing::debug!("UCT new root verification failed - current: {}, new_root: {}", current, proof.new_root);
            anyhow::bail!("invalid new root!");
        }

        Ok(())
    }
    pub fn into_updates(self, checkpoint_id: u64, user_id: u64) -> CSTUserUpdate<Hash> {
        CSTUserUpdate {
            user_id,
            checkpoint_id,
            uct_updates: self
                .uct_node_map
                .into_iter()
                .map(|(k, v)| SimpleMerkleNode { key: k, value: v })
                .collect(),
            updates: self.node_map.into_iter().map(|(k, v)| CSTDeltaNode { key: k, value: v }).collect(),
        }
    }
    pub fn to_updates(self, checkpoint_id: u64, user_id: u64) -> CSTUserUpdate<Hash> {
        CSTUserUpdate {
            user_id,
            checkpoint_id,
            uct_updates: self.uct_node_map.iter().map(|(k, v)| SimpleMerkleNode { key: *k, value: *v }).collect(),
            updates: self.node_map.iter().map(|(k, v)| CSTDeltaNode { key: *k, value: *v }).collect(),
        }
    }
}
