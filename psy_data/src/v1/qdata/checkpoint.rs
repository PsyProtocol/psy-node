use parth_core::{
    crypto::hash::traits::{FieldQHasher, QFieldHashable},
    data::serializable::QPDSerializable,
    felt::{QFelt, QFelt64, QFeltSized, ToQFelts},
    impl_qpd_serialize_params, impl_qpq_serialize_bincode,
    protocol::core_types::{QFHashBase, QHashBase},
};
use pser::{QBytesDeserialize, QBytesSerialize};
use psy_core::constants::protocol::DA_CHALLENGE_WINDOW;
use ts_rs::TS;

use crate::v1::qdata::{checkpoint_sync::PQEDCheckpointSyncInfoCompact, pm_jobs_completed_stats::PPMJobsCompletedStats, pm_rewards_commitment::PPMRewardCommitment};

#[pderive::serialize_copy_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash), rename = "QEDCheckpointLeafStats")]
pub struct PQEDCheckpointLeafStats<F: QFelt, Hash: QHashBase> {
    pub fees_collected: F,
    pub user_ops_processed: F,
    pub total_transactions: F,
    pub slots_modified: F,
    pub pm_jobs_completed: PPMJobsCompletedStats<F>,
    pub block_time: F,
    pub random_seed: Hash,
    pub pm_rewards_commitment: PPMRewardCommitment<Hash>,
    pub da_challenges_claimed: [F; DA_CHALLENGE_WINDOW],
}
impl_qpd_serialize_params!(
    PQEDCheckpointLeafStats,
    { F: QFelt, Hash: QHashBase } => { F, Hash }
);

impl<F: QFelt, Hash: QHashBase> PQEDCheckpointLeafStats<F, Hash> {
    pub fn new_empty() -> Self {
        Self {
            fees_collected: F::ZERO_VALUE,
            user_ops_processed: F::ZERO_VALUE,
            total_transactions: F::ZERO_VALUE,
            slots_modified: F::ZERO_VALUE,
            pm_jobs_completed: PPMJobsCompletedStats::new_empty(),
            block_time: F::ZERO_VALUE,
            random_seed: Hash::get_zero_value(),
            pm_rewards_commitment: PPMRewardCommitment::default(),
            da_challenges_claimed: [F::ZERO_VALUE; DA_CHALLENGE_WINDOW],
        }
    }

    pub fn get_genesis_value() -> Self {
        Self::new_empty()
    }
}

impl<F: QFelt, Hash: QHashBase> QFeltSized for PQEDCheckpointLeafStats<F, Hash> {
    fn q_felt_size() -> usize {
        4 + PPMJobsCompletedStats::<F>::q_felt_size() + 1 + 4
            + PPMRewardCommitment::<Hash>::q_felt_size()
            + DA_CHALLENGE_WINDOW
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> ToQFelts<F> for PQEDCheckpointLeafStats<F, Hash> {
    fn to_qfelts(&self) -> Vec<F> {
        let mut result = vec![
            self.fees_collected,
            self.user_ops_processed,
            self.total_transactions,
            self.slots_modified,
        ];
        result.extend_from_slice(&self.pm_jobs_completed.to_qfelts());
        result.push(self.block_time);
        result.extend_from_slice(&self.random_seed.to_4_felts());
        result.extend_from_slice(&self.pm_rewards_commitment.to_qfelts());
        result.extend_from_slice(&self.da_challenges_claimed);
        result
    }

    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != Self::q_felt_size() {
            panic!(
                "Invalid number of elements for QEDCheckpointLeafStats, expected {} got {}",
                Self::q_felt_size(),
                felts.len()
            );
        }

        let pm_jobs_start = 4;
        let pm_jobs_end = pm_jobs_start + PPMJobsCompletedStats::<F>::q_felt_size();
        let block_time_index = pm_jobs_end;
        let random_seed_start = block_time_index + 1;
        let random_seed_end = random_seed_start + 4;
        let pm_rewards_start = random_seed_end;
        let pm_rewards_end = pm_rewards_start + PPMRewardCommitment::<Hash>::q_felt_size();
        let da_challenges_start = pm_rewards_end;

        Self {
            fees_collected: felts[0],
            user_ops_processed: felts[1],
            total_transactions: felts[2],
            slots_modified: felts[3],
            pm_jobs_completed: PPMJobsCompletedStats::from_qfelts(&felts[pm_jobs_start..pm_jobs_end]),
            block_time: felts[block_time_index],
            random_seed: Hash::from_4_felts_slice(&felts[random_seed_start..random_seed_end]),
            pm_rewards_commitment: PPMRewardCommitment::from_qfelts(
                &felts[pm_rewards_start..pm_rewards_end],
            ),
            da_challenges_claimed: felts[da_challenges_start..].try_into().unwrap(),
        }
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> QFieldHashable<F, Hash>
    for PQEDCheckpointLeafStats<F, Hash>
{
    fn qfhash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        H::q_hash_many(&self.to_qfelts())
    }
}

#[pderive::serialize_copy_hash_ts]
#[ts(export, concrete(Hash = parth_core::PHash), rename = "QEDCheckpointGlobalStateRoots")]
pub struct PQEDCheckpointGlobalStateRoots<Hash: QHashBase> {
    pub contract_tree_root: Hash,
    pub deposit_tree_root: Hash,
    pub user_tree_root: Hash,
    pub withdrawal_tree_root: Hash,
    pub user_registration_tree_root: Hash,
}
impl_qpd_serialize_params!(
    PQEDCheckpointGlobalStateRoots,
    { Hash: QHashBase } => { Hash }
);

impl<Hash: QHashBase> QFeltSized for PQEDCheckpointGlobalStateRoots<Hash> {
    fn q_felt_size() -> usize {
        20
    }
}
impl<F: QFelt64, Hash: QFHashBase<F>> ToQFelts<F> for PQEDCheckpointGlobalStateRoots<Hash> {
    fn to_qfelts(&self) -> Vec<F> {
        let mut result = Vec::with_capacity(Self::q_felt_size());
        result.extend_from_slice(&self.contract_tree_root.to_4_felts());
        result.extend_from_slice(&self.deposit_tree_root.to_4_felts());
        result.extend_from_slice(&self.user_tree_root.to_4_felts());
        result.extend_from_slice(&self.withdrawal_tree_root.to_4_felts());
        result.extend_from_slice(&self.user_registration_tree_root.to_4_felts());
        result
    }

    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != Self::q_felt_size() {
            panic!("Invalid number of elements for QEDCheckpointGlobalStateRoots");
        }
        Self {
            contract_tree_root: Hash::from_4_felts_slice(&felts[0..4]),
            deposit_tree_root: Hash::from_4_felts_slice(&felts[4..8]),
            user_tree_root: Hash::from_4_felts_slice(&felts[8..12]),
            withdrawal_tree_root: Hash::from_4_felts_slice(&felts[12..16]),
            user_registration_tree_root: Hash::from_4_felts_slice(&felts[16..20]),
        }
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> QFieldHashable<F, Hash>
    for PQEDCheckpointGlobalStateRoots<Hash>
{
    fn qfhash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        let contract_and_deposit = H::q_two_to_one(self.contract_tree_root, self.deposit_tree_root);
        let user_and_withdrawal = H::q_two_to_one(self.user_tree_root, self.withdrawal_tree_root);
        let base_combo = H::q_two_to_one(contract_and_deposit, user_and_withdrawal);
        H::q_two_to_one(base_combo, self.user_registration_tree_root)
    }
}

#[pderive::serialize_copy_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash), rename = "QEDCheckpointLeaf")]
pub struct PQEDCheckpointLeaf<F: QFelt, Hash: QHashBase> {
    pub global_chain_root: Hash,
    pub stats: PQEDCheckpointLeafStats<F, Hash>,
}
impl_qpd_serialize_params!(
    PQEDCheckpointLeaf,
    { F: QFelt, Hash: QHashBase } => { F, Hash }
);

impl<F: QFelt64, Hash: QFHashBase<F>> PQEDCheckpointLeaf<F, Hash> {
    pub fn to_compact<H: FieldQHasher<F, Hash>>(&self) -> PQEDCheckpointLeafCompact<Hash> {
        PQEDCheckpointLeafCompact {
            global_chain_root: self.global_chain_root,
            stats_hash: self.stats.qfhash::<H>(),
        }
    }
}

impl<F: QFelt, Hash: QHashBase> QFeltSized for PQEDCheckpointLeaf<F, Hash> {
    fn q_felt_size() -> usize {
        4 + PQEDCheckpointLeafStats::<F, Hash>::q_felt_size()
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> ToQFelts<F> for PQEDCheckpointLeaf<F, Hash> {
    fn to_qfelts(&self) -> Vec<F> {
        let mut result = Vec::with_capacity(Self::q_felt_size());
        result.extend_from_slice(&self.global_chain_root.to_4_felts());
        result.extend_from_slice(&self.stats.to_qfelts());
        result
    }

    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != Self::q_felt_size() {
            panic!("Invalid number of elements for QEDCheckpointLeaf");
        }
        Self {
            global_chain_root: Hash::from_4_felts_slice(&felts[0..4]),
            stats: PQEDCheckpointLeafStats::from_qfelts(&felts[4..]),
        }
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> QFieldHashable<F, Hash> for PQEDCheckpointLeaf<F, Hash> {
    fn qfhash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        let stats_hash = self.stats.qfhash::<H>();
        let root_felts = self.global_chain_root.to_4_felts();
        let stats_felts = stats_hash.to_4_felts();

        H::q_hash_many(&[
            root_felts[0],
            root_felts[1],
            root_felts[2],
            root_felts[3],
            stats_felts[0],
            stats_felts[1],
            stats_felts[2],
            stats_felts[3],
        ])
    }
}

#[pderive::serialize_copy_hash_ts]
#[ts(export, concrete(Hash = parth_core::PHash), rename = "QEDCheckpointLeafCompact")]
pub struct PQEDCheckpointLeafCompact<Hash: QHashBase> {
    pub global_chain_root: Hash,
    pub stats_hash: Hash,
}
impl_qpd_serialize_params!(
    PQEDCheckpointLeafCompact,
    { Hash: QHashBase } => { Hash }
);

impl<Hash: QHashBase> QFeltSized for PQEDCheckpointLeafCompact<Hash> {
    fn q_felt_size() -> usize {
        8
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> ToQFelts<F> for PQEDCheckpointLeafCompact<Hash> {
    fn to_qfelts(&self) -> Vec<F> {
        let mut result = Vec::with_capacity(Self::q_felt_size());
        result.extend_from_slice(&self.global_chain_root.to_4_felts());
        result.extend_from_slice(&self.stats_hash.to_4_felts());
        result
    }

    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != Self::q_felt_size() {
            panic!("Invalid number of elements for QEDCheckpointLeafCompact");
        }
        Self {
            global_chain_root: Hash::from_4_felts_slice(&felts[0..4]),
            stats_hash: Hash::from_4_felts_slice(&felts[4..8]),
        }
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> QFieldHashable<F, Hash>
    for PQEDCheckpointLeafCompact<Hash>
{
    fn qfhash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        H::q_two_to_one(self.global_chain_root, self.stats_hash)
    }
}

#[pderive::serialize_copy]
#[derive(TS)]
#[ts(export)]
pub struct QEDL2BlockState {
    pub checkpoint_id: u64,
    pub next_add_withdrawal_id: u64,
    pub next_process_withdrawal_id: u64,
    pub next_deposit_id: u64,
    pub total_deposits_claimed_epoch: u64,
    pub next_user_id: u64,
    pub end_balance: u64,
    pub next_contract_id: u32,
}
impl_qpq_serialize_bincode!(QEDL2BlockState);

impl QEDL2BlockState {
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

#[pderive::serialize_copy_hash_ts]
#[ts(export, concrete(Hash = parth_core::PHash), rename = "QEDCheckpointLeafCompactWithStateRoots")]
pub struct PQEDCheckpointLeafCompactWithStateRoots<Hash: QHashBase> {
    pub checkpoint_leaf: PQEDCheckpointLeafCompact<Hash>,
    pub global_state_roots: PQEDCheckpointGlobalStateRoots<Hash>,
}
impl_qpd_serialize_params!(
    PQEDCheckpointLeafCompactWithStateRoots,
    { Hash: QHashBase } => { Hash }
);

impl<Hash: QHashBase> QFeltSized for PQEDCheckpointLeafCompactWithStateRoots<Hash> {
    fn q_felt_size() -> usize {
        PQEDCheckpointLeafCompact::<Hash>::q_felt_size()
            + PQEDCheckpointGlobalStateRoots::<Hash>::q_felt_size()
    }
}
impl<F: QFelt64, Hash: QFHashBase<F>> ToQFelts<F> for PQEDCheckpointLeafCompactWithStateRoots<Hash> {
    fn to_qfelts(&self) -> Vec<F> {
        let mut result = Vec::with_capacity(Self::q_felt_size());
        result.extend_from_slice(&self.checkpoint_leaf.to_qfelts());
        result.extend_from_slice(&self.global_state_roots.to_qfelts());
        result
    }

    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != Self::q_felt_size() {
            panic!("Invalid number of elements for QEDCheckpointLeafCompactWithStateRoots");
        }
        let checkpoint_part_size = PQEDCheckpointLeafCompact::<Hash>::q_felt_size();
        Self {
            checkpoint_leaf: PQEDCheckpointLeafCompact::from_qfelts(&felts[0..checkpoint_part_size]),
            global_state_roots: PQEDCheckpointGlobalStateRoots::from_qfelts(
                &felts[checkpoint_part_size..],
            ),
        }
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> QFieldHashable<F, Hash>
    for PQEDCheckpointLeafCompactWithStateRoots<Hash>
{
    fn qfhash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        self.checkpoint_leaf.qfhash::<H>()
    }
}

/// push the latest checkpoint sync info
#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash), rename = "CheckpointSyncInfo")]
pub struct PCheckpointSyncInfo<F: QFelt, Hash: QHashBase> {
    pub latest_checkpoint_id: u64,
    pub description: Option<String>,
    pub source_coordinator_edge_id: Option<String>,
    pub sync_timestamp: u64,
    pub compact: PQEDCheckpointSyncInfoCompact<F, Hash>,
    pub realm_root: Hash,
}
impl_qpd_serialize_params!(
    PCheckpointSyncInfo,
    { F: QFelt, Hash: QHashBase } => { F, Hash }
);
