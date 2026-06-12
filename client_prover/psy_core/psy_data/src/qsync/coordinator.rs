use kvq::traits::KVQSerializable;
use plonky2::hash::hash_types::RichField;
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::{
    hash::{
        merkle::{
            core::{DeltaMerkleProofCore, MerkleProofCore},
            utils::append_only_merkle_tree::get_merkle_proofs_for_compact,
        },
        traits::{
            hasher::{FieldQHasher, MerkleZeroHasherWithMarkedLeaf},
            qhashable::QFieldHashable,
        },
    },
    signature::zk::data::ZKPublicKeyInfo,
};
use serde::{Deserialize, Serialize};

use crate::qdata::checkpoint::{PsyBlockState, PsyCheckpointGlobalStateRoots, PsyCheckpointLeaf, PsyCheckpointLeafStats};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct PsyCheckpointSyncInfoCompact<F: RichField> {
    pub block_state: PsyBlockState,
    pub stats: PsyCheckpointLeafStats<F>,
    pub state_roots: PsyCheckpointGlobalStateRoots<F>,
    pub checkpoint_tree_update_siblings: Vec<QHashOut<F>>,
    pub regsitered_users_start_pivot_siblings: Vec<QHashOut<F>>,
    pub registered_users: Vec<ZKPublicKeyInfo<F>>,
    pub old_checkpoint_leaf_hash: QHashOut<F>,
    pub slot: u64,
}

impl<F: RichField> PsyCheckpointSyncInfoCompact<F> {
    pub fn get_registered_user_merkle_proofs<H: MerkleZeroHasherWithMarkedLeaf<QHashOut<F>> + FieldQHasher<F>>(
        &self,
    ) -> Vec<MerkleProofCore<QHashOut<F>>> {
        get_merkle_proofs_for_compact::<H, QHashOut<F>>(
            self.block_state.next_user_id - (self.registered_users.len() as u64),
            &self.regsitered_users_start_pivot_siblings,
            &self.registered_users.iter().map(|x| x.qfhash::<H>()).collect::<Vec<_>>(),
        )
    }
}
// impl<F: RichField> DrainQueueMetadataTagged for
// PsyCheckpointSyncInfoCompact<F> {     fn get_dq_metadata(&self) ->
// DrainQueueMetadata {         DrainQueueMetadata {
//             channel_id: PSY_CHECKPOINT_SYNC_INFO_COMPACT_DRAIN_QUEUE_CHANNEL,
//             checkpoint_id: self.block_state.checkpoint_id,
//             item_id: self.block_state.checkpoint_id,
//         }
//     }
// }

// impl<F: RichField> HistoryQueueMetadataTagged for
// PsyCheckpointSyncInfoCompact<F> {     fn get_hq_metadata(&self) ->
// HistoryQueueMetadata {         HistoryQueueMetadata {
//             channel_id: PSY_CHECKPOINT_SYNC_INFO_COMPACT_DRAIN_QUEUE_CHANNEL,
//             checkpoint_id: self.block_state.checkpoint_id,
//             item_id: self.block_state.checkpoint_id,
//         }
//     }
// }

impl<F: RichField> PsyCheckpointSyncInfoCompact<F> {
    pub fn to_sync_info<H: FieldQHasher<F>>(self) -> PsyCheckpointSyncInfo<F> {
        let global_chain_root = self.state_roots.qfhash::<H>();
        let checkpoint_leaf = PsyCheckpointLeaf {
            global_chain_root,
            stats: self.stats,
        };
        let checkpoint_leaf_hash = checkpoint_leaf.qfhash::<H>();

        let checkpoint_tree_update_proof = DeltaMerkleProofCore::from_params::<H>(
            self.block_state.checkpoint_id,
            self.old_checkpoint_leaf_hash,
            checkpoint_leaf_hash,
            self.checkpoint_tree_update_siblings,
        );
        let core = PsyCheckpointCoreSyncInfo {
            checkpoint_tree_root: checkpoint_tree_update_proof.new_root,
            checkpoint_leaf_hash,
            block_state: self.block_state,
            checkpoint_leaf,
            state_roots: self.state_roots,
        };
        PsyCheckpointSyncInfo {
            core,
            checkpoint_tree_update_proof,
            regsitered_users_start_pivot_siblings: self.regsitered_users_start_pivot_siblings,
            registered_users: self.registered_users,
            slot: self.slot,
        }
    }
}

impl<F: RichField> From<PsyCheckpointSyncInfo<F>> for PsyCheckpointSyncInfoCompact<F> {
    fn from(value: PsyCheckpointSyncInfo<F>) -> Self {
        Self {
            block_state: value.core.block_state,
            stats: value.core.checkpoint_leaf.stats,
            state_roots: value.core.state_roots,
            checkpoint_tree_update_siblings: value.checkpoint_tree_update_proof.siblings,
            regsitered_users_start_pivot_siblings: value.regsitered_users_start_pivot_siblings,
            registered_users: value.registered_users,
            old_checkpoint_leaf_hash: value.checkpoint_tree_update_proof.old_value,
            slot: value.slot,
        }
    }
}
impl<F: RichField> From<&PsyCheckpointSyncInfo<F>> for PsyCheckpointSyncInfoCompact<F> {
    fn from(value: &PsyCheckpointSyncInfo<F>) -> Self {
        Self {
            block_state: value.core.block_state,
            stats: value.core.checkpoint_leaf.stats,
            state_roots: value.core.state_roots,
            checkpoint_tree_update_siblings: value.checkpoint_tree_update_proof.siblings.clone(),
            regsitered_users_start_pivot_siblings: value.regsitered_users_start_pivot_siblings.clone(),
            registered_users: value.registered_users.clone(),
            old_checkpoint_leaf_hash: value.checkpoint_tree_update_proof.old_value,
            slot: value.slot,
        }
    }
}

impl<F: RichField> KVQSerializable for PsyCheckpointSyncInfoCompact<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Copy, Default)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct PsyCheckpointCoreSyncInfo<F: RichField> {
    pub checkpoint_tree_root: QHashOut<F>,
    pub checkpoint_leaf_hash: QHashOut<F>,
    pub block_state: PsyBlockState,
    pub checkpoint_leaf: PsyCheckpointLeaf<F>,
    pub state_roots: PsyCheckpointGlobalStateRoots<F>,
}

impl<F: RichField> KVQSerializable for PsyCheckpointCoreSyncInfo<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct PsyCheckpointSyncInfo<F: RichField> {
    pub core: PsyCheckpointCoreSyncInfo<F>,
    pub checkpoint_tree_update_proof: DeltaMerkleProofCore<QHashOut<F>>,
    pub regsitered_users_start_pivot_siblings: Vec<QHashOut<F>>,
    pub registered_users: Vec<ZKPublicKeyInfo<F>>,
    pub slot: u64,
}
impl<F: RichField> PsyCheckpointSyncInfo<F> {
    pub fn get_registered_user_merkle_proofs<H: MerkleZeroHasherWithMarkedLeaf<QHashOut<F>> + FieldQHasher<F>>(
        &self,
    ) -> Vec<MerkleProofCore<QHashOut<F>>> {
        get_merkle_proofs_for_compact::<H, QHashOut<F>>(
            self.core.block_state.next_user_id - (self.registered_users.len() as u64),
            &self.regsitered_users_start_pivot_siblings,
            &self.registered_users.iter().map(|x| x.qfhash::<H>()).collect::<Vec<_>>(),
        )
    }
}
impl<F: RichField> KVQSerializable for PsyCheckpointSyncInfo<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}
