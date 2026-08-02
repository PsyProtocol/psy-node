use kvq::traits::KVQSerializable;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::hash_types::{HashOut, RichField},
};
use psy_client_common::{
    data::qhashout::QHashOut,
    traits::to_qfelts::{QFeltSized, ToQFelts},
};
use psy_config::network_constants::DA_CHALLENGE_WINDOW;
use psy_crypto::hash::traits::{hasher::FieldQHasher, qhashable::QFieldHashable};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::{pm_jobs_completed_stats::PMJobsCompletedStats, pm_reward_commitment::PMRewardCommitment};
use crate::qsync::coordinator::PsyCheckpointSyncInfoCompact;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Copy, Default, TS)]
#[ts(export, concrete(F = GoldilocksField))]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct PsyCheckpointLeafStats<F: RichField> {
    pub guta_fees_collected: F,
    pub da_fees_collected: F,

    pub user_ops_processed: F,
    pub total_transactions: F,

    pub slots_modified: F,
    pub pm_jobs_completed: PMJobsCompletedStats<F>,

    pub block_time: F,

    pub random_seed: QHashOut<F>,
    pub pm_rewards_commitment: PMRewardCommitment<F>,

    // data availability miner proofs successfully completed for the previous 16 blocks
    pub da_challenges_claimed: [F; DA_CHALLENGE_WINDOW],
}

impl<F: RichField> PsyCheckpointLeafStats<F> {
    pub fn new_empty() -> Self {
        Self {
            guta_fees_collected: F::ZERO,
            da_fees_collected: F::ZERO,
            user_ops_processed: F::ZERO,
            total_transactions: F::ZERO,
            slots_modified: F::ZERO,
            pm_jobs_completed: PMJobsCompletedStats::new_empty(),
            block_time: F::ZERO,
            random_seed: QHashOut::ZERO,
            pm_rewards_commitment: PMRewardCommitment::default(),
            da_challenges_claimed: [F::ZERO; DA_CHALLENGE_WINDOW],
        }
    }
    pub fn get_genesis_value() -> Self {
        Self {
            guta_fees_collected: F::ZERO,
            da_fees_collected: F::ZERO,
            user_ops_processed: F::ZERO,
            total_transactions: F::ZERO,
            slots_modified: F::ZERO,
            pm_jobs_completed: PMJobsCompletedStats::new_empty(),
            block_time: F::ZERO,
            random_seed: QHashOut::ZERO,
            pm_rewards_commitment: PMRewardCommitment::default(),
            da_challenges_claimed: [F::ZERO; DA_CHALLENGE_WINDOW],
        }
    }
}
impl<F: RichField> ToQFelts<F> for PsyCheckpointLeafStats<F> {
    fn to_qfelts(&self) -> Vec<F> {
        let mut result = vec![
            self.guta_fees_collected,
            self.da_fees_collected,
            self.user_ops_processed,
            self.total_transactions,
            self.slots_modified,
        ];
        result.extend_from_slice(&self.pm_jobs_completed.to_qfelts());
        result.extend_from_slice(&[
            self.block_time,
            self.random_seed.0.elements[0],
            self.random_seed.0.elements[1],
            self.random_seed.0.elements[2],
            self.random_seed.0.elements[3],
        ]);
        result.extend_from_slice(&self.pm_rewards_commitment.to_qfelts());
        result.extend_from_slice(&self.da_challenges_claimed);
        result
    }

    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != Self::q_felt_size() {
            panic!(
                "Invalid number of elements for PsyCheckpointLeafStats, expected {} got {}",
                Self::q_felt_size(),
                felts.len()
            );
        }

        let pm_jobs_start = 5;
        let pm_jobs_end = pm_jobs_start + PMJobsCompletedStats::<F>::q_felt_size();
        let block_time_index = pm_jobs_end;
        let random_seed_start = block_time_index + 1;
        let random_seed_end = random_seed_start + 4;
        let pm_rewards_start = random_seed_end;
        let pm_rewards_end = pm_rewards_start + PMRewardCommitment::<F>::q_felt_size();
        let da_challenges_start = pm_rewards_end;

        Self {
            guta_fees_collected: felts[0],
            da_fees_collected: felts[1],
            user_ops_processed: felts[2],
            total_transactions: felts[3],
            slots_modified: felts[4],
            pm_jobs_completed: PMJobsCompletedStats::from_qfelts(&felts[pm_jobs_start..pm_jobs_end]),
            block_time: felts[block_time_index],
            random_seed: QHashOut::from_felt_slice(&felts[random_seed_start..random_seed_end]),
            pm_rewards_commitment: PMRewardCommitment::from_qfelts(&felts[pm_rewards_start..pm_rewards_end]),
            da_challenges_claimed: felts[da_challenges_start..].try_into().unwrap(),
        }
    }
}
impl<F: RichField> KVQSerializable for PsyCheckpointLeafStats<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

impl<F: RichField> QFeltSized for PsyCheckpointLeafStats<F> {
    fn q_felt_size() -> usize {
        5 + PMJobsCompletedStats::<F>::q_felt_size() + 5 + PMRewardCommitment::<F>::q_felt_size() + DA_CHALLENGE_WINDOW
    }
}
impl<F: RichField> QFieldHashable<F> for PsyCheckpointLeafStats<F> {
    fn qfhash<H: FieldQHasher<F>>(&self) -> QHashOut<F> {
        let felts = self.to_qfelts();
        H::q_hash_many(&felts)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Copy, Default, TS)]
#[ts(export, concrete(F = GoldilocksField))]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct PsyCheckpointGlobalStateRoots<F: RichField> {
    pub contract_tree_root: QHashOut<F>,
    pub deposit_tree_root: QHashOut<F>,
    pub user_tree_root: QHashOut<F>,
    pub withdrawal_tree_root: QHashOut<F>,
    pub user_registration_tree_root: QHashOut<F>,
}

impl<F: RichField> KVQSerializable for PsyCheckpointGlobalStateRoots<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

impl<F: RichField> QFeltSized for PsyCheckpointGlobalStateRoots<F> {
    fn q_felt_size() -> usize {
        20
    }
}
impl<F: RichField> ToQFelts<F> for PsyCheckpointGlobalStateRoots<F> {
    fn to_qfelts(&self) -> Vec<F> {
        let mut result = Vec::with_capacity(Self::q_felt_size());
        result.extend_from_slice(&self.contract_tree_root.0.elements);
        result.extend_from_slice(&self.deposit_tree_root.0.elements);
        result.extend_from_slice(&self.user_tree_root.0.elements);
        result.extend_from_slice(&self.withdrawal_tree_root.0.elements);
        result.extend_from_slice(&self.user_registration_tree_root.0.elements);

        result
    }

    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != Self::q_felt_size() {
            panic!("Invalid number of elements for PsyCheckpointGlobalStateRoots");
        }
        let contract_tree_root = QHashOut(HashOut {
            elements: [felts[0], felts[1], felts[2], felts[3]],
        });
        let deposit_tree_root = QHashOut(HashOut {
            elements: [felts[4], felts[5], felts[6], felts[7]],
        });
        let user_tree_root = QHashOut(HashOut {
            elements: [felts[8], felts[9], felts[10], felts[11]],
        });
        let withdrawal_tree_root = QHashOut(HashOut {
            elements: [felts[12], felts[13], felts[14], felts[15]],
        });
        let user_registration_tree_root = QHashOut(HashOut {
            elements: [felts[16], felts[17], felts[18], felts[19]],
        });
        PsyCheckpointGlobalStateRoots {
            contract_tree_root,
            deposit_tree_root,
            user_tree_root,
            withdrawal_tree_root,
            user_registration_tree_root,
        }
    }
}

impl<F: RichField> QFieldHashable<F> for PsyCheckpointGlobalStateRoots<F> {
    fn qfhash<H: FieldQHasher<F>>(&self) -> QHashOut<F> {
        let contract_and_deposit = H::q_two_to_one(self.contract_tree_root, self.deposit_tree_root);

        let user_and_withdrawal = H::q_two_to_one(self.user_tree_root, self.withdrawal_tree_root);

        let base_combo = H::q_two_to_one(contract_and_deposit, user_and_withdrawal);

        H::q_two_to_one(base_combo, self.user_registration_tree_root)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Copy, Default, TS)]
#[ts(export, concrete(F = GoldilocksField))]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct PsyCheckpointLeaf<F: RichField> {
    pub global_chain_root: QHashOut<F>,
    pub stats: PsyCheckpointLeafStats<F>,
}

impl<F: RichField> PsyCheckpointLeaf<F> {
    pub fn to_compact<H: FieldQHasher<F>>(&self) -> PsyCheckpointLeafCompact<F> {
        let stats_hash = self.stats.qfhash::<H>();
        PsyCheckpointLeafCompact {
            global_chain_root: self.global_chain_root,
            stats_hash,
        }
    }
}

impl<F: RichField> KVQSerializable for PsyCheckpointLeaf<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

impl<F: RichField> QFeltSized for PsyCheckpointLeaf<F> {
    fn q_felt_size() -> usize {
        4 + PsyCheckpointLeafStats::<F>::q_felt_size()
    }
}
impl<F: RichField> ToQFelts<F> for PsyCheckpointLeaf<F> {
    fn to_qfelts(&self) -> Vec<F> {
        let mut result = Vec::with_capacity(Self::q_felt_size());
        result.extend_from_slice(&self.global_chain_root.0.elements);
        result.extend_from_slice(&self.stats.to_qfelts());
        result
    }

    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != Self::q_felt_size() {
            panic!("Invalid number of elements for PsyCheckpointLeaf");
        }
        let global_chain_root = QHashOut(HashOut {
            elements: [felts[0], felts[1], felts[2], felts[3]],
        });
        let stats = PsyCheckpointLeafStats::from_qfelts(&felts[4..]);
        PsyCheckpointLeaf { global_chain_root, stats }
    }
}

impl<F: RichField> QFieldHashable<F> for PsyCheckpointLeaf<F> {
    fn qfhash<H: FieldQHasher<F>>(&self) -> QHashOut<F> {
        let stats_hash = self.stats.qfhash::<H>();
        H::q_two_to_one(self.global_chain_root, stats_hash)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Copy, Default, TS)]
#[ts(export, concrete(F = GoldilocksField))]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct PsyCheckpointLeafCompact<F: RichField> {
    pub global_chain_root: QHashOut<F>,
    pub stats_hash: QHashOut<F>,
}

impl<F: RichField> KVQSerializable for PsyCheckpointLeafCompact<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

impl<F: RichField> QFeltSized for PsyCheckpointLeafCompact<F> {
    fn q_felt_size() -> usize {
        8
    }
}
impl<F: RichField> ToQFelts<F> for PsyCheckpointLeafCompact<F> {
    fn to_qfelts(&self) -> Vec<F> {
        let mut result = Vec::with_capacity(Self::q_felt_size());
        result.extend_from_slice(&self.global_chain_root.0.elements);
        result.extend_from_slice(&self.stats_hash.0.elements);
        result
    }

    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != Self::q_felt_size() {
            panic!("Invalid number of elements for PsyCheckpointLeafCompact");
        }
        let global_chain_root = QHashOut(HashOut {
            elements: [felts[0], felts[1], felts[2], felts[3]],
        });
        let stats_hash = QHashOut(HashOut {
            elements: [felts[4], felts[5], felts[6], felts[7]],
        });
        PsyCheckpointLeafCompact {
            global_chain_root,
            stats_hash,
        }
    }
}

impl<F: RichField> QFieldHashable<F> for PsyCheckpointLeafCompact<F> {
    fn qfhash<H: FieldQHasher<F>>(&self) -> QHashOut<F> {
        H::q_two_to_one(self.global_chain_root, self.stats_hash)
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, Copy, Hash, Eq, PartialEq, TS)]
#[ts(export)]
pub struct PsyBlockState {
    pub checkpoint_id: u64,

    pub next_add_withdrawal_id: u64,
    pub next_process_withdrawal_id: u64,

    pub next_deposit_id: u64,
    pub total_deposits_claimed_epoch: u64,

    pub next_user_id: u64,

    pub end_balance: u64,

    pub next_contract_id: u32,
}
impl PsyBlockState {
    pub fn get_genesis_value() -> Self {
        Self {
            checkpoint_id: 0,
            next_add_withdrawal_id: 0,
            next_process_withdrawal_id: 0,
            next_deposit_id: 0,
            total_deposits_claimed_epoch: 0,
            next_user_id: 0,
            end_balance: 0,
            next_contract_id: 0,
        }
    }
}
impl KVQSerializable for PsyBlockState {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        // 7 * 8 + 4 = 60 bytes
        let mut result = Vec::with_capacity(60);
        result.extend(self.checkpoint_id.to_be_bytes());
        result.extend(self.next_add_withdrawal_id.to_le_bytes());
        result.extend(self.next_process_withdrawal_id.to_le_bytes());
        result.extend(self.next_deposit_id.to_le_bytes());
        result.extend(self.total_deposits_claimed_epoch.to_le_bytes());
        result.extend(self.next_user_id.to_le_bytes());
        result.extend(self.end_balance.to_le_bytes());
        result.extend(self.next_contract_id.to_le_bytes());
        Ok(result)
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 60 {
            anyhow::bail!("expected 60 bytes for deserializing PsyBlockState, got {} bytes", bytes.len());
        }
        let checkpoint_id = u64::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]);
        let next_add_withdrawal_id = u64::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]]);
        let next_process_withdrawal_id = u64::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23]]);
        let next_deposit_id = u64::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31]]);
        let total_deposits_claimed_epoch =
            u64::from_le_bytes([bytes[32], bytes[33], bytes[34], bytes[35], bytes[36], bytes[37], bytes[38], bytes[39]]);
        let next_user_id = u64::from_le_bytes([bytes[40], bytes[41], bytes[42], bytes[43], bytes[44], bytes[45], bytes[46], bytes[47]]);
        let end_balance = u64::from_le_bytes([bytes[48], bytes[49], bytes[50], bytes[51], bytes[52], bytes[53], bytes[54], bytes[55]]);
        let next_contract_id = u32::from_le_bytes([bytes[56], bytes[57], bytes[58], bytes[59]]);
        Ok(Self {
            checkpoint_id,
            next_add_withdrawal_id,
            next_process_withdrawal_id,
            next_deposit_id,
            total_deposits_claimed_epoch,
            next_user_id,
            end_balance,
            next_contract_id,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Copy, Default, TS)]
#[ts(export, concrete(F = GoldilocksField))]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct PsyCheckpointLeafCompactWithStateRoots<F: RichField> {
    pub checkpoint_leaf: PsyCheckpointLeafCompact<F>,
    pub global_state_roots: PsyCheckpointGlobalStateRoots<F>,
}

impl<F: RichField> KVQSerializable for PsyCheckpointLeafCompactWithStateRoots<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

impl<F: RichField> QFeltSized for PsyCheckpointLeafCompactWithStateRoots<F> {
    fn q_felt_size() -> usize {
        PsyCheckpointLeafCompact::<F>::q_felt_size() + PsyCheckpointGlobalStateRoots::<F>::q_felt_size()
    }
}
impl<F: RichField> ToQFelts<F> for PsyCheckpointLeafCompactWithStateRoots<F> {
    fn to_qfelts(&self) -> Vec<F> {
        let mut result = Vec::with_capacity(Self::q_felt_size());
        result.extend_from_slice(&self.checkpoint_leaf.to_qfelts());
        result.extend_from_slice(&self.global_state_roots.to_qfelts());
        result
    }

    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != Self::q_felt_size() {
            panic!("Invalid number of elements for PsyCheckpointLeafCompactWithStateRoots");
        }
        let checkpoint_part_size = PsyCheckpointLeafCompact::<F>::q_felt_size();
        let checkpoint_leaf = PsyCheckpointLeafCompact::from_qfelts(&felts[0..checkpoint_part_size]);
        let global_state_roots = PsyCheckpointGlobalStateRoots::from_qfelts(&felts[checkpoint_part_size..]);
        PsyCheckpointLeafCompactWithStateRoots {
            checkpoint_leaf,
            global_state_roots,
        }
    }
}

impl<F: RichField> QFieldHashable<F> for PsyCheckpointLeafCompactWithStateRoots<F> {
    fn qfhash<H: FieldQHasher<F>>(&self) -> QHashOut<F> {
        self.checkpoint_leaf.qfhash::<H>()
    }
}

/// push the latest checkpoint sync info
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct CheckpointSyncInfo<F: RichField> {
    pub latest_checkpoint_id: u64, // latest checkpoint id
    pub description: Option<String>,
    pub source_coordinator_edge_id: Option<String>,
    pub sync_timestamp: u64, // sync timestamp
    pub compact: PsyCheckpointSyncInfoCompact<F>,
    pub realm_root: QHashOut<F>,
}

impl<F: RichField + Serialize + for<'de> Deserialize<'de>> KVQSerializable for CheckpointSyncInfo<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

// impl<F: RichField>
// psy_client_common::job::history_queue::HistoryQueueMetadataTagged
// for CheckpointSyncInfo<F> {     fn get_hq_metadata(&self) ->
// psy_client_common::job::history_queue::HistoryQueueMetadata {         // Use
// the same channel as the compact version for consistency
//         psy_client_common::job::history_queue::HistoryQueueMetadata {
//             channel_id:
// psy_config::network_constants::PSY_CHECKPOINT_SYNC_INFO_COMPACT_DRAIN_QUEUE_CHANNEL,
//             checkpoint_id: self.compact.block_state.checkpoint_id,
//             item_id: self.compact.block_state.checkpoint_id,
//         }
//     }
// }
