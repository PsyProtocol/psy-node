use serde::{de::DeserializeOwned, Serialize};

use crate::data::{maybe_serialization::MaybeSpeedy, queue::queue_key::PCoreQueueItemBase, serializable::QPDSerializableFixed};

pub const QJOB_ID_SERIALIZED_SIZE: usize = 24;
pub const QJOB_ID_WITH_REALM_PREFIX_SERIALIZED_SIZE: usize = 32;

pub const QJOB_ID_WITH_REWARD_PATH_SERIALIZED_SIZE: usize = 32;
pub const QJOB_ID_WITH_UNIQUE_PENDING_ID_SERIALIZED_SIZE: usize = 32;
pub const QJOB_ID_WITH_UNIQUE_PENDING_ID_AND_REALM_PREFIX_SERIALIZED_SIZE: usize = 40;

pub type QJobIdSerialized = [u8; QJOB_ID_SERIALIZED_SIZE];
pub type QJobIdWithRewardPathSerialized = [u8; QJOB_ID_WITH_REWARD_PATH_SERIALIZED_SIZE];

pub trait JobIDSerializable: Sized + Copy + Send + Sync + Clone + PartialEq + Eq{
    fn to_job_id_bytes(&self) -> QJobIdSerialized;
    fn from_job_id_bytes(bytes: &QJobIdSerialized) -> anyhow::Result<Self>;
    fn rand_job_id() -> Self;
}
pub trait JobIDWithRewardPathSerializable: Sized + Copy + Send + Sync + Clone + PartialEq + Eq  {
    fn to_job_id_with_reward_path_bytes(&self) -> QJobIdWithRewardPathSerialized;
    fn from_job_id_with_reward_path_bytes(bytes: &QJobIdWithRewardPathSerialized) -> anyhow::Result<Self>;
    fn rand_job_id_with_reward_path() -> Self;
    fn get_job_id_serialized(&self) -> QJobIdSerialized;
    fn get_reward_path_info(&self) -> u64;
}

pub trait QJobIdBase: Copy + Send + Sync + Serialize + DeserializeOwned + Clone + PartialEq + Eq + std::fmt::Debug + QPDSerializableFixed + Sized + Into<QJobIdSerialized> + TryFrom<QJobIdSerialized> + PCoreQueueItemBase + MaybeSpeedy  {
    
    fn to_bytes_fixed(&self) -> QJobIdSerialized;
    fn from_bytes_fixed(bytes: &QJobIdSerialized) -> anyhow::Result<Self>;
    fn circuit_type_u32(&self) -> u32;
    fn input_witness_id(&self) -> Self;
    fn output_proof_id(&self) -> Self;
    fn group_counter_id(&self) -> Self;
    fn get_synced_checkpoint_id(&self) -> u64;
    fn is_guta_proof_circuit_type(&self) -> bool;
    fn is_end_cap_proof_circuit_type(&self) -> bool;
    fn get_parth_index(&self) -> u64;
    fn get_reverse_parth_level(&self) -> u8;
    fn new_invalid_job_id() -> Self;
    fn is_valid(&self) -> bool;
}

pub trait QJobIdCreatable: QJobIdBase {
    fn new_standard_user_end_cap_proof_id(at_checkpoint_id: u64, user_id: u64, global_user_tree_height: u8) -> Self;
    fn new_alt_user_end_cap_proof_id(at_checkpoint_id: u64, user_id: u64, global_user_tree_height: u8, circuit_type: u32) -> Self;
    fn new_two_to_one_proof_id_or_invalid(target_checkpoint_id: u64, left_proof_id: &Self, right_proof_id: &Self, parth_index: u64, parth_level: u8, reverse_aggregation_level: u8) -> Self;
    fn new_two_to_one_proof_id(target_checkpoint_id: u64, left_proof_id: &Self, right_proof_id: &Self, parth_index: u64, parth_level: u8, reverse_aggregation_level: u8) -> anyhow::Result<Self>;
}


#[pderive::serialize_copy_ts_export]
pub struct QProvingJobDataIDWithRewardPath<T> {
    pub job_data_id: T,
    pub reward_path_info: u64,
}
impl<T: QJobIdBase> QProvingJobDataIDWithRewardPath<T> {
    pub fn new(job_data_id: T, reward_path_info: u64) -> Self {
        Self { job_data_id, reward_path_info }
    }
}

impl<T: QJobIdBase> PCoreQueueItemBase for QProvingJobDataIDWithRewardPath<T> {
    fn is_queue_item(data: &[u8]) -> bool {
        data.len() == QJOB_ID_WITH_REWARD_PATH_SERIALIZED_SIZE && T::is_queue_item(&data[0..QJOB_ID_SERIALIZED_SIZE])
    }

    fn decode_queue_item_ref(data: &[u8]) -> anyhow::Result<Self> {
        let job_data_id = T::from_bytes_fixed(&data[0..QJOB_ID_SERIALIZED_SIZE].try_into()? )?;
        let reward_path_info = u64::from_be_bytes(data[QJOB_ID_SERIALIZED_SIZE..QJOB_ID_WITH_REWARD_PATH_SERIALIZED_SIZE].try_into()?);
        Ok(Self { job_data_id, reward_path_info })
    }

    fn encode_queue_item_vec(&self) -> anyhow::Result<Vec<u8>> {
        let mut v = Vec::with_capacity(QJOB_ID_WITH_REWARD_PATH_SERIALIZED_SIZE);
        v.extend_from_slice(&self.job_data_id.to_bytes_fixed());
        v.extend_from_slice(&self.reward_path_info.to_be_bytes());
        Ok(v)
    }

    fn get_restorable_job_id(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(QJOB_ID_WITH_REWARD_PATH_SERIALIZED_SIZE);
        v.extend_from_slice(&self.job_data_id.to_bytes_fixed());
        v.extend_from_slice(&self.reward_path_info.to_be_bytes());
        v
    }

    fn get_size_hint() -> usize {
        QJOB_ID_SERIALIZED_SIZE + 8
    }

    fn has_fixed_size() -> bool {
        true
    }
}
