use parth_core::{
    crypto::hash::traits::{FieldQHasher, QFieldHashable},
    data::serializable::QPDSerializable,
    felt::{QFelt, QFelt64, QFeltSized, ToQFelts},
    impl_qpd_serialize_params, impl_qpq_serialize_bincode,
    protocol::core_types::{Q256BitHash, QFHashBase, QHashBase}, utils::QPGenRandom,
};
use pser::{QBytesDeserialize, QBytesSerialize};
use psy_core::constants::protocol::DA_CHALLENGE_WINDOW;
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};
use ts_rs::TS;

use psy_serialize::{AutoDatabaseSerializationUseFastFixedSerialize, FastFixedSerializable};

use crate::v1::qdata::{checkpoint_sync::PQEDCheckpointSyncInfoCompact, ffs_sizes::PSY_OBJECT_FFS_SIZE_GLOBAL_STATE_ROOTS, pm_jobs_completed_stats::PPMJobsCompletedStats, pm_rewards_commitment::PPMRewardCommitment};

#[pderive::serialize_copy_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash), rename = "QEDCheckpointLeafStats")]
pub struct PQEDCheckpointLeafStats<F, Hash> {
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


impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for PQEDCheckpointLeafStats<F, Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            fees_collected: F::qp_rand_gen(),
            user_ops_processed: F::qp_rand_gen(),
            total_transactions: F::qp_rand_gen(),
            slots_modified: F::qp_rand_gen(),
            pm_jobs_completed: PPMJobsCompletedStats::qp_rand_gen(),
            block_time: F::qp_rand_gen(),
            random_seed: Hash::qp_rand_gen(),
            pm_rewards_commitment: PPMRewardCommitment::qp_rand_gen(),
            da_challenges_claimed: F::qp_rand_gen_vec(DA_CHALLENGE_WINDOW).try_into().map_err(|_| anyhow::anyhow!("failed to alloc fixed length value")).unwrap(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for PQEDCheckpointLeafStats<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0; // 3 * 8 bytes for F = QFelt64
}
impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for PQEDCheckpointLeafStats<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        4*8 + self.pm_jobs_completed.pio_serialized_size() + 8 + 32 + self.pm_rewards_commitment.pio_serialized_size() + (DA_CHALLENGE_WINDOW * 8)
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_u64(self.fees_collected.to_u64_value())?;
        writer.psy_write_u64(self.user_ops_processed.to_u64_value())?;
        writer.psy_write_u64(self.total_transactions.to_u64_value())?;
        writer.psy_write_u64(self.slots_modified.to_u64_value())?;
        self.pm_jobs_completed.pio_write_to_io(writer)?;
        writer.psy_write_u64(self.block_time.to_u64_value())?;
        writer.psy_write_bytes_fixed(&self.random_seed.into_owned_32bytes())?;
        self.pm_rewards_commitment.pio_write_to_io(writer)?;
        for challenge in &self.da_challenges_claimed {
            writer.psy_write_u64(challenge.to_u64_value())?;
        }


        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        
        let fees_collected = F::from_u64_value(reader.psy_read_u64()?);
        let user_ops_processed = F::from_u64_value(reader.psy_read_u64()?);
        let total_transactions = F::from_u64_value(reader.psy_read_u64()?);
        let slots_modified = F::from_u64_value(reader.psy_read_u64()?);
        let pm_jobs_completed = PPMJobsCompletedStats::<F>::pio_read_from_io(reader)?;
        let block_time = F::from_u64_value(reader.psy_read_u64()?);
        let random_seed = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let pm_rewards_commitment = PPMRewardCommitment::<Hash>::pio_read_from_io(reader)?;
        let mut da_challenges_claimed = [F::ZERO_VALUE; DA_CHALLENGE_WINDOW];
        for challenge in &mut da_challenges_claimed {
            *challenge = F::from_u64_value(reader.psy_read_u64()?);
        }

        Ok(Self {
            fees_collected,
            user_ops_processed,
            total_transactions,
            slots_modified,
            pm_jobs_completed,
            block_time,
            random_seed,
            pm_rewards_commitment,
            da_challenges_claimed,
        })
    }

}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    PQEDCheckpointLeafStats,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for PQEDCheckpointLeafStats<F> {}


pser::impl_psy_ser_basic_tests_fallback!(
    PPMJobsCompletedStats,
    { parth_core::PF },
    test_ser_ppm_jobs_completed_stats
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
#[repr(C)]
pub struct PQEDCheckpointGlobalStateRoots<Hash> {
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



impl<Hash: QPGenRandom> QPGenRandom for PQEDCheckpointGlobalStateRoots<Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        PQEDCheckpointGlobalStateRoots {
            contract_tree_root: Hash::qp_rand_gen(),
            deposit_tree_root: Hash::qp_rand_gen(),
            user_tree_root: Hash::qp_rand_gen(),
            withdrawal_tree_root: Hash::qp_rand_gen(),
            user_registration_tree_root: Hash::qp_rand_gen(),
        }
    }
}
pser::impl_bytemuck_pod_and_zeroable!(PQEDCheckpointGlobalStateRoots, Hash);
pser::impl_bytemuck_ffs!(
    PQEDCheckpointGlobalStateRoots,
    { Hash: Q256BitHash },
    160
);

pser::impl_bytemuck_ffs_tests!(
    PQEDCheckpointGlobalStateRoots,
    // Note the use of concrete types here
    { parth_core::PHash },
    160
);


impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for PQEDCheckpointGlobalStateRoots<Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 160;
}
impl<Hash: Q256BitHash> AutoDatabaseSerializationUseFastFixedSerialize<160> for PQEDCheckpointGlobalStateRoots<Hash> {}
psy_serialize::impl_psy_canonical_serialize_for_fixed_type!(
    PQEDCheckpointGlobalStateRoots,
    { Hash: Q256BitHash } => { Hash },
    160
);
// This function is never called, it is just to ensure at compile time
//  PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF matches the FFS implementation
fn _ensure_compile_time_size_match() {
    let _bytes_h256: [u8; PSY_OBJECT_FFS_SIZE_GLOBAL_STATE_ROOTS] = PQEDCheckpointGlobalStateRoots::<parth_core::data::hash::hash256::Hash256>::qp_rand_gen().ffs_into_bytes();
    let _bytes_phash: [u8; PSY_OBJECT_FFS_SIZE_GLOBAL_STATE_ROOTS] = PQEDCheckpointGlobalStateRoots::<parth_core::PHash>::qp_rand_gen().ffs_into_bytes();
}

// fallback for big endian platforms, not zero copy
#[cfg(not(all(target_endian = "little", feature = "serialize_bytemuck")))]
impl<F: QFelt64, Hash: Q256BitHash> FastFixedSerializable<72> for PQEDContractLeaf<F, Hash> {
    fn ffs_from_owned_bytes(data: [u8; PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF]) -> Self {
        let deployer = Hash::from_ref_32bytes(&data[0..32].try_into().unwrap());
        let function_tree_root = Hash::from_ref_32bytes(&data[32..64].try_into().unwrap());
        let state_tree_height = F::from_u64_value(u64::from_le_bytes(data[64..72].try_into().unwrap()));
        PQEDContractLeaf {
            deployer,
            function_tree_root,
            state_tree_height,
        }
    }

    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        if data.len() != PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF {
            panic!("Invalid number of bytes for PQEDContractLeaf");
        }
        let deployer = Hash::from_ref_32bytes(&data[0..32].try_into().unwrap());
        let function_tree_root = Hash::from_ref_32bytes(&data[32..64].try_into().unwrap());
        let state_tree_height = F::from_u64_value(u64::from_le_bytes(data[64..72].try_into().unwrap()));
        PQEDContractLeaf {
            deployer,
            function_tree_root,
            state_tree_height,
        }
    }

    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF {
            anyhow::bail!("Invalid number of bytes for PQEDContractLeaf");
        }
        let deployer = Hash::from_ref_32bytes(&data[0..32].try_into().unwrap());
        let function_tree_root = Hash::from_ref_32bytes(&data[32..64].try_into().unwrap());
        let state_tree_height = F::from_u64_value(u64::from_le_bytes(data[64..72].try_into().unwrap()));
        Ok(PQEDContractLeaf {
            deployer,
            function_tree_root,
            state_tree_height,
        })
    }

    fn ffs_to_bytes(&self) -> [u8; PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF] {
        let mut bytes = [0u8; PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF];
        bytes[0..32].copy_from_slice(&self.deployer.into_owned_32bytes());
        bytes[32..64].copy_from_slice(&self.function_tree_root.into_owned_32bytes());
        bytes[64..72].copy_from_slice(&self.state_tree_height.to_u64_value().to_le_bytes());
        bytes
    }

    fn ffs_into_bytes(self) -> [u8; PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF] {
        let mut bytes = [0u8; PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF];
        bytes[0..32].copy_from_slice(&self.deployer.into_owned_32bytes());
        bytes[32..64].copy_from_slice(&self.function_tree_root.into_owned_32bytes());
        bytes[64..72].copy_from_slice(&self.state_tree_height.to_u64_value().to_le_bytes());
        bytes
    }
}

pser::impl_psy_ser_basic_tests!(
    PQEDCheckpointGlobalStateRoots,
    // Note the use of concrete types here
    {  parth_core::PHash },
    qed_global_state_roots_tests
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
pub struct PQEDCheckpointLeaf<F, Hash> {
    pub global_chain_root: Hash,
    pub stats: PQEDCheckpointLeafStats<F, Hash>,
}
impl_qpd_serialize_params!(
    PQEDCheckpointLeaf,
    { F: QFelt, Hash: QHashBase } => { F, Hash }
);


impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for PQEDCheckpointLeaf<F, Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            global_chain_root: Hash::qp_rand_gen(),
            stats: PQEDCheckpointLeafStats::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for PQEDCheckpointLeaf<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}
impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for PQEDCheckpointLeaf<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        32 + self.stats.pio_serialized_size()
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.global_chain_root.into_owned_32bytes())?;
        self.stats.pio_write_to_io(writer)
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let global_chain_root = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let stats = PQEDCheckpointLeafStats::<F, Hash>::pio_read_from_io(reader)?;
        Ok(Self {
            global_chain_root,
            stats,
        })
    }

}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    PQEDCheckpointLeaf,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for PQEDCheckpointLeaf<F, Hash> {}


pser::impl_psy_ser_basic_tests_fallback!(
    PQEDCheckpointLeaf,
    { parth_core::PF, parth_core::PHash },
    qed_checkpoint_leaf
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
pub struct PQEDCheckpointLeafCompact<Hash> {
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

// TODO: PERF: optimize serialization by 8-byte alignment and using bytemuck
// for now I don't want to change anything to preserve compaitbility
// this could be done by making next_contract_id a u64 instead of u32
#[pderive::serialize_copy]
#[derive(TS)]
#[ts(export)]
#[repr(C)]
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
impl QPGenRandom for QEDL2BlockState {
    fn qp_rand_gen() -> Self {
        Self {
            checkpoint_id: QPGenRandom::qp_rand_gen(),
            next_add_withdrawal_id: QPGenRandom::qp_rand_gen(),
            next_process_withdrawal_id: QPGenRandom::qp_rand_gen(),
            next_deposit_id: QPGenRandom::qp_rand_gen(),
            total_deposits_claimed_epoch: QPGenRandom::qp_rand_gen(),
            next_user_id: QPGenRandom::qp_rand_gen(),
            end_balance: QPGenRandom::qp_rand_gen(),
            next_contract_id: QPGenRandom::qp_rand_gen(),
        }
    }
}
impl_qpq_serialize_bincode!(QEDL2BlockState);

impl FallbackPsySerializeCanonical for QEDL2BlockState {
    fn fallback_pio_serialized_size(&self) -> usize {
        60
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_u64(self.checkpoint_id)?;
        writer.psy_write_u64(self.next_add_withdrawal_id)?;
        writer.psy_write_u64(self.next_process_withdrawal_id)?;
        writer.psy_write_u64(self.next_deposit_id)?;
        writer.psy_write_u64(self.total_deposits_claimed_epoch)?;
        writer.psy_write_u64(self.next_user_id)?;
        writer.psy_write_u64(self.end_balance)?;
        writer.psy_write_u32(self.next_contract_id)?;

        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {

        let checkpoint_id = reader.psy_read_u64()?;
        let next_add_withdrawal_id = reader.psy_read_u64()?;
        let next_process_withdrawal_id = reader.psy_read_u64()?;
        let next_deposit_id = reader.psy_read_u64()?;
        let total_deposits_claimed_epoch = reader.psy_read_u64()?;
        let next_user_id = reader.psy_read_u64()?;
        let end_balance = reader.psy_read_u64()?;
        let next_contract_id = reader.psy_read_u32()?;

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
impl PsyCanonicalSerializeMetadata for QEDL2BlockState {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
    const MAX_VEC_LENGTH: usize = 16_777_216; // max ~16 million block headers in one sync message
    
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(QEDL2BlockState);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl AutoImplementFallbackPsySerializeCanonical for QEDL2BlockState {}




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
pub struct PQEDCheckpointLeafCompactWithStateRoots<Hash> {
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
pub struct PCheckpointSyncInfo<F, Hash> {
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
