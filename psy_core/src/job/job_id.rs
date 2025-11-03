// fix new_two_to_one_proof_id to implement all the proof types and also use a more elegant syntax... there must be something better than those aweful match if else...
use hex::FromHexError;
use parth_core::{data::{hash::merkle_node_key::{SimpleMerkleNodeKey, JOB_ID_EMPTY_REWARD_PATH_INFO}, queue::queue_key::PCoreQueueItemBase, serializable::{QPDSerializable, QPDSerializableFixed}}, utils::QPGenRandom, QJobIdBase, QJobIdCreatable, QJobIdSerialized, QProvingJobDataIDWithRewardPath};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use ts_rs::TS;
#[derive(TS)]
#[ts(export)]
#[pderive::serialize_enum_repr_strum]
#[repr(u32)]
pub enum QWorkerMode {
    All = 0,
    NoGroth16 = 1,
    OnlyGroth16 = 2,
}
impl QWorkerMode {
    pub fn to_u32(&self) -> u32 {
        *self as u32
    }
    pub fn is_groth16_enabled(&self) -> bool {
        match self {
            QWorkerMode::All => true,
            QWorkerMode::NoGroth16 => false,
            QWorkerMode::OnlyGroth16 => true,
        }
    }
}
impl From<QWorkerMode> for u32 {
    fn from(value: QWorkerMode) -> u32 {
        value as u32
    }
}
impl TryFrom<u32> for QWorkerMode {
    type Error = anyhow::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(QWorkerMode::All),
            1 => Ok(QWorkerMode::NoGroth16),
            2 => Ok(QWorkerMode::OnlyGroth16),
            _ => Err(anyhow::format_err!("Invalid QWorkerMode value: {}", value)),
        }
    }

}
/* 
#[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum QCircuitCommonGatesType {
    A = 0,
    B = 1,
    C = 2,
    D = 3,
    E = 4,
    F = 5,
}
    */
#[derive(TS)]
#[ts(export)]
#[pderive::serialize_enum_repr_strum]
#[repr(u8)]
pub enum QJobTopic {
    GenerateStandardProof = 0,
    GenerateGroth16Proof = 1,
    BlockUserSignatureProof = 2,
    NotifyCoordinatorComplete = 3,
    NotifyRealmComplete = 4,
    AggregateJobs = 5,

    Invalid = 254,
    Unknown = 255,
}
impl QJobTopic {
    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
}
impl From<QJobTopic> for u8 {
    fn from(value: QJobTopic) -> u8 {
        value as u8
    }
}
impl TryFrom<u8> for QJobTopic {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(QJobTopic::GenerateStandardProof),
            1 => Ok(QJobTopic::GenerateGroth16Proof),
            2 => Ok(QJobTopic::BlockUserSignatureProof),
            3 => Ok(QJobTopic::NotifyCoordinatorComplete),
            4 => Ok(QJobTopic::NotifyRealmComplete),
            5 => Ok(QJobTopic::AggregateJobs),
            254 => Ok(QJobTopic::Invalid),
            255 => Ok(QJobTopic::Unknown),
            _ => Err(anyhow::format_err!("Invalid QJobTopic value: {}", value)),
        }
    }
}
#[derive(TS)]
#[ts(export)]
#[pderive::serialize_enum_repr_strum]
#[repr(u8)]
pub enum ProvingJobDataType {
    InputWitness = 0,
    BaseInputProof = 1,
    OutputProof = 8,
    Counter = 16,
}
impl ProvingJobDataType {
    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
}
impl TryFrom<u8> for ProvingJobDataType {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ProvingJobDataType::InputWitness),
            1 => Ok(ProvingJobDataType::BaseInputProof),
            8 => Ok(ProvingJobDataType::OutputProof),
            16 => Ok(ProvingJobDataType::Counter),
            _ => Err(anyhow::format_err!("Invalid ProvingJobDataType value: {}", value)),
        }
    }
}
impl From<ProvingJobDataType> for u8 {
    fn from(value: ProvingJobDataType) -> u8 {
        value as u8
    }
}
#[derive(TS)]
#[ts(export)]
#[pderive::serialize_enum_repr_strum]
#[repr(u8)]
pub enum ProvingJobCircuitType {
    AppendUserRegistrationTree = 0,
    AppendUserRegistrationTreeAggregate = 1,

    AddL1Deposit = 2,
    AddL1DepositAggregate = 3,

    ClaimL1Deposit = 4,
    ClaimL1DepositAggregate = 5,

    UserEndCap = 6,
    GUTATwoEndCap = 7,
    GUTATwoGUTA = 8,
    GUTALeftEndCapRightGUTA = 9,
    GUTALeftGUTARightEndCap = 10,
    GUTASingleEndCap = 11,
    GUTARegisterUsers = 12,
    GUTAVerifyToCap = 13,
    GUTAOnlyRegisterUsers = 14,
    GUTANoChange = 15,

    AddL1Withdrawal = 16,
    AddL1WithdrawalAggregate = 17,

    BatchDeployContracts = 18,
    BatchDeployContractsAggregate = 19,

    ProcessL1Withdrawal = 20,
    ProcessL1WithdrawalAggregate = 21,

    GenerateRollupStateTransitionProof = 32,
    GenerateSigHashIntrospectionProof = 33,
    GenerateFinalSigHashProof = 34,
    GenerateFinalSigHashProofGroth16 = 35,
    WrapFinalSigHashProofBLS12381 = 36,

    AggUserRegisterDeployContractsGUTA = 40,
    AggAddProcessL1WithdrawalAddL1Deposit = 41,

    DummyAppendUserRegistrationTreeAggregate = 48,
    DummyAddL1DepositAggregate = 49,
    DummyClaimL1DepositAggregate = 50,
    DummyGUTA = 51,
    DummyAddL1WithdrawalAggregate = 52,
    DummyProcessL1WithdrawalAggregate = 53,
    DummyBatchDeployContractsAggregate = 54,

    // ADDED NEW - For Historical Upgrades
    GUTATwoGUTAWithCheckpointUpgrade = 55,
    GUTAVerifyToCapWithCheckpointUpgrade = 56,

    WrappedSignatureProof = 64,
    Secp256K1SignatureProof = 65,

    NotifyRealmComplete = 192,

    TypeA = 224,
    TypeB = 225,
    TypeC = 226,
    TypeD = 227,
    TypeE = 228,
    TypeF = 229,
    Invalid = 254,
    Unknown = 255,
}

impl ProvingJobCircuitType {
    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
    pub fn to_circuit_group_id(&self) -> u32 {
        (self.to_u8() as u32) + 0xCF00u32
    }
    pub fn get_agg_leaf_circuit_type_or_err(&self) -> anyhow::Result<Self> {
        let leaf_type = match self {
            ProvingJobCircuitType::AppendUserRegistrationTree => ProvingJobCircuitType::AppendUserRegistrationTree,
            ProvingJobCircuitType::AppendUserRegistrationTreeAggregate => ProvingJobCircuitType::AppendUserRegistrationTree,
            ProvingJobCircuitType::AddL1Deposit => ProvingJobCircuitType::AddL1Deposit,
            ProvingJobCircuitType::AddL1DepositAggregate => ProvingJobCircuitType::AddL1Deposit,
            ProvingJobCircuitType::ClaimL1Deposit => ProvingJobCircuitType::ClaimL1Deposit,
            ProvingJobCircuitType::ClaimL1DepositAggregate => ProvingJobCircuitType::ClaimL1Deposit,
            ProvingJobCircuitType::AddL1Withdrawal => ProvingJobCircuitType::AddL1Withdrawal,
            ProvingJobCircuitType::AddL1WithdrawalAggregate => ProvingJobCircuitType::AddL1Withdrawal,
            ProvingJobCircuitType::BatchDeployContracts => ProvingJobCircuitType::BatchDeployContracts,
            ProvingJobCircuitType::BatchDeployContractsAggregate => ProvingJobCircuitType::BatchDeployContracts,
            ProvingJobCircuitType::ProcessL1Withdrawal => ProvingJobCircuitType::ProcessL1Withdrawal,
            ProvingJobCircuitType::ProcessL1WithdrawalAggregate => ProvingJobCircuitType::ProcessL1Withdrawal,
            _ => anyhow::bail!("circuit type {:?} does not have a leaf type", self),
        };
        Ok(leaf_type)
    }

    pub fn get_agg_circuit_type_or_err(&self) -> anyhow::Result<Self> {
        let leaf_type = match self {
            ProvingJobCircuitType::AppendUserRegistrationTree => ProvingJobCircuitType::AppendUserRegistrationTreeAggregate,
            ProvingJobCircuitType::AppendUserRegistrationTreeAggregate => ProvingJobCircuitType::AppendUserRegistrationTreeAggregate,
            ProvingJobCircuitType::AddL1Deposit => ProvingJobCircuitType::AddL1DepositAggregate,
            ProvingJobCircuitType::AddL1DepositAggregate => ProvingJobCircuitType::AddL1DepositAggregate,
            ProvingJobCircuitType::ClaimL1Deposit => ProvingJobCircuitType::ClaimL1DepositAggregate,
            ProvingJobCircuitType::ClaimL1DepositAggregate => ProvingJobCircuitType::ClaimL1DepositAggregate,
            ProvingJobCircuitType::AddL1Withdrawal => ProvingJobCircuitType::AddL1WithdrawalAggregate,
            ProvingJobCircuitType::AddL1WithdrawalAggregate => ProvingJobCircuitType::AddL1WithdrawalAggregate,
            ProvingJobCircuitType::BatchDeployContracts => ProvingJobCircuitType::BatchDeployContractsAggregate,
            ProvingJobCircuitType::BatchDeployContractsAggregate => ProvingJobCircuitType::BatchDeployContractsAggregate,
            ProvingJobCircuitType::ProcessL1Withdrawal => ProvingJobCircuitType::ProcessL1WithdrawalAggregate,
            ProvingJobCircuitType::ProcessL1WithdrawalAggregate => ProvingJobCircuitType::ProcessL1WithdrawalAggregate,
            _ => anyhow::bail!("circuit type {:?} does not have a aggregated circuit type", self),
        };
        Ok(leaf_type)
    }

    pub fn get_agg_dummy_circuit_type_or_err(&self) -> anyhow::Result<Self> {
        let leaf_type = match self {
            ProvingJobCircuitType::AppendUserRegistrationTree => ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate,
            ProvingJobCircuitType::AppendUserRegistrationTreeAggregate => ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate,
            ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate => ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate,
            ProvingJobCircuitType::AddL1Deposit => ProvingJobCircuitType::DummyAddL1DepositAggregate,
            ProvingJobCircuitType::AddL1DepositAggregate => ProvingJobCircuitType::DummyAddL1DepositAggregate,
            ProvingJobCircuitType::DummyAddL1DepositAggregate => ProvingJobCircuitType::DummyAddL1DepositAggregate,
            ProvingJobCircuitType::ClaimL1Deposit => ProvingJobCircuitType::DummyClaimL1DepositAggregate,
            ProvingJobCircuitType::ClaimL1DepositAggregate => ProvingJobCircuitType::DummyClaimL1DepositAggregate,
            ProvingJobCircuitType::DummyClaimL1DepositAggregate => ProvingJobCircuitType::DummyClaimL1DepositAggregate,
            ProvingJobCircuitType::AddL1Withdrawal => ProvingJobCircuitType::DummyAddL1WithdrawalAggregate,
            ProvingJobCircuitType::AddL1WithdrawalAggregate => ProvingJobCircuitType::DummyAddL1WithdrawalAggregate,
            ProvingJobCircuitType::DummyAddL1WithdrawalAggregate => ProvingJobCircuitType::DummyAddL1WithdrawalAggregate,
            ProvingJobCircuitType::BatchDeployContracts => ProvingJobCircuitType::DummyBatchDeployContractsAggregate,
            ProvingJobCircuitType::BatchDeployContractsAggregate => ProvingJobCircuitType::DummyBatchDeployContractsAggregate,
            ProvingJobCircuitType::DummyBatchDeployContractsAggregate => ProvingJobCircuitType::DummyBatchDeployContractsAggregate,
            ProvingJobCircuitType::ProcessL1Withdrawal => ProvingJobCircuitType::DummyProcessL1WithdrawalAggregate,
            ProvingJobCircuitType::ProcessL1WithdrawalAggregate => ProvingJobCircuitType::DummyProcessL1WithdrawalAggregate,
            ProvingJobCircuitType::DummyProcessL1WithdrawalAggregate => ProvingJobCircuitType::DummyProcessL1WithdrawalAggregate,
            _ => anyhow::bail!("circuit type {:?} does not have a aggregated dummy circuit type", self),
        };
        Ok(leaf_type)
    }
    pub fn try_from_u32(circuit_type_u32: u32) -> anyhow::Result<Self> {
        if circuit_type_u32 > u8::MAX as u32 {
            anyhow::bail!("invalid circuit type {}", circuit_type_u32);
        }
        let circuit_type = ProvingJobCircuitType::try_from(circuit_type_u32 as u8)?;
        Ok(circuit_type)
    }
}

impl TryFrom<u8> for ProvingJobCircuitType {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ProvingJobCircuitType::AppendUserRegistrationTree),
            1 => Ok(ProvingJobCircuitType::AppendUserRegistrationTreeAggregate),
            2 => Ok(ProvingJobCircuitType::AddL1Deposit),
            3 => Ok(ProvingJobCircuitType::AddL1DepositAggregate),
            4 => Ok(ProvingJobCircuitType::ClaimL1Deposit),
            5 => Ok(ProvingJobCircuitType::ClaimL1DepositAggregate),
            6 => Ok(ProvingJobCircuitType::UserEndCap),
            7 => Ok(ProvingJobCircuitType::GUTATwoEndCap),
            8 => Ok(ProvingJobCircuitType::GUTATwoGUTA),
            9 => Ok(ProvingJobCircuitType::GUTALeftEndCapRightGUTA),
            10 => Ok(ProvingJobCircuitType::GUTALeftGUTARightEndCap),
            11 => Ok(ProvingJobCircuitType::GUTASingleEndCap),
            12 => Ok(ProvingJobCircuitType::GUTARegisterUsers),
            13 => Ok(ProvingJobCircuitType::GUTAVerifyToCap),
            14 => Ok(ProvingJobCircuitType::GUTAOnlyRegisterUsers),
            15 => Ok(ProvingJobCircuitType::GUTANoChange),
            16 => Ok(ProvingJobCircuitType::AddL1Withdrawal),
            17 => Ok(ProvingJobCircuitType::AddL1WithdrawalAggregate),
            18 => Ok(ProvingJobCircuitType::BatchDeployContracts),
            19 => Ok(ProvingJobCircuitType::BatchDeployContractsAggregate),
            20 => Ok(ProvingJobCircuitType::ProcessL1Withdrawal),
            21 => Ok(ProvingJobCircuitType::ProcessL1WithdrawalAggregate),
            32 => Ok(ProvingJobCircuitType::GenerateRollupStateTransitionProof),
            33 => Ok(ProvingJobCircuitType::GenerateSigHashIntrospectionProof),
            34 => Ok(ProvingJobCircuitType::GenerateFinalSigHashProof),
            35 => Ok(ProvingJobCircuitType::GenerateFinalSigHashProofGroth16),
            36 => Ok(ProvingJobCircuitType::WrapFinalSigHashProofBLS12381),
            40 => Ok(ProvingJobCircuitType::AggUserRegisterDeployContractsGUTA),
            41 => Ok(ProvingJobCircuitType::AggAddProcessL1WithdrawalAddL1Deposit),
            48 => Ok(ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate),
            49 => Ok(ProvingJobCircuitType::DummyAddL1DepositAggregate),
            50 => Ok(ProvingJobCircuitType::DummyClaimL1DepositAggregate),
            51 => Ok(ProvingJobCircuitType::DummyGUTA),
            52 => Ok(ProvingJobCircuitType::DummyAddL1WithdrawalAggregate),
            53 => Ok(ProvingJobCircuitType::DummyProcessL1WithdrawalAggregate),
            54 => Ok(ProvingJobCircuitType::DummyBatchDeployContractsAggregate),
            55 => Ok(ProvingJobCircuitType::GUTATwoGUTAWithCheckpointUpgrade),
            56 => Ok(ProvingJobCircuitType::GUTAVerifyToCapWithCheckpointUpgrade),

            64 => Ok(ProvingJobCircuitType::WrappedSignatureProof),
            65 => Ok(ProvingJobCircuitType::Secp256K1SignatureProof),
            192 => Ok(ProvingJobCircuitType::NotifyRealmComplete),

            224 => Ok(ProvingJobCircuitType::TypeA),
            225 => Ok(ProvingJobCircuitType::TypeB),
            226 => Ok(ProvingJobCircuitType::TypeC),
            227 => Ok(ProvingJobCircuitType::TypeD),
            228 => Ok(ProvingJobCircuitType::TypeE),
            229 => Ok(ProvingJobCircuitType::TypeF),
            254 => Ok(ProvingJobCircuitType::Invalid),
            255 => Ok(ProvingJobCircuitType::Unknown),
            _ => Err(anyhow::format_err!("Invalid ProvingJobCircuitType value: {}", value)),
        }
    }
}

impl From<ProvingJobCircuitType> for u8 {
    fn from(value: ProvingJobCircuitType) -> Self {
        value as u8
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Copy, Eq, Hash, Clone, Debug)]
pub struct QProvingJobDataIDSerializedWrapped(#[serde_as(as = "serde_with::hex::Hex")] pub QJobIdSerialized);

impl QProvingJobDataIDSerializedWrapped {
    pub fn from_hex_string(s: &str) -> Result<Self, FromHexError> {
        let bytes = hex::decode(s)?;
        assert_eq!(bytes.len(), 24);
        let mut array = [0u8; 24];
        array.copy_from_slice(&bytes);
        Ok(Self(array))
    }
}

#[pderive::serialize_copy_ts_export_job_id]
#[repr(C)]
pub struct QProvingJobDataID {
    pub topic: QJobTopic,
    pub goal_id: u64,
    pub circuit_type: ProvingJobCircuitType,
    pub group_id: u32,
    pub sub_group_id: u32,
    pub task_index: u32,
    pub data_type: ProvingJobDataType,
    pub data_index: u8,
}
impl QPGenRandom for QProvingJobDataID {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            topic: QJobTopic::GenerateStandardProof,
            goal_id: QPGenRandom::qp_rand_gen(),
            circuit_type: ProvingJobCircuitType::BatchDeployContractsAggregate,
            group_id: QPGenRandom::qp_rand_gen(),
            sub_group_id: QPGenRandom::qp_rand_gen(),
            task_index: QPGenRandom::qp_rand_gen(),
            data_type: ProvingJobDataType::InputWitness,
            data_index: QPGenRandom::qp_rand_gen(),
        }
    }
}

impl QProvingJobDataID {
    pub fn try_get_coordinator_edge_proof_store_output_proof_id_for_realm_submit(realm_id: u32, realm_level: u8, unique_pending_id: u64, circuit_type: ProvingJobCircuitType) -> anyhow::Result<Self> {
        match circuit_type {
            ProvingJobCircuitType::GUTATwoEndCap |
            ProvingJobCircuitType::GUTATwoGUTA |
            ProvingJobCircuitType::GUTALeftEndCapRightGUTA |
            ProvingJobCircuitType::GUTALeftGUTARightEndCap |
            ProvingJobCircuitType::GUTASingleEndCap |
            ProvingJobCircuitType::GUTARegisterUsers |
            ProvingJobCircuitType::GUTAVerifyToCap |
            ProvingJobCircuitType::GUTAOnlyRegisterUsers |
            ProvingJobCircuitType::GUTANoChange |
            ProvingJobCircuitType::GUTATwoGUTAWithCheckpointUpgrade |
            ProvingJobCircuitType::GUTAVerifyToCapWithCheckpointUpgrade => {},
            _ => anyhow::bail!("circuit type {:?} is not a GUTA circuit type", circuit_type),
        };


        let job_data_id = QProvingJobDataID {
            topic: QJobTopic::GenerateStandardProof,
            goal_id: unique_pending_id,
            circuit_type,
            group_id: realm_level as u32,
            sub_group_id: 0,
            task_index: realm_id,
            data_type: ProvingJobDataType::OutputProof,
            data_index: 0,
        };
        Ok(job_data_id)
    }


    pub fn try_get_realm_edge_proof_store_output_proof_id_for_end_cap(user_id: u64, global_user_tree_height: u8, unique_pending_id: u64) -> anyhow::Result<Self> {

        if user_id > u32::MAX as u64 {
            anyhow::bail!("user id {} is too large to fit in u32", user_id);
        }

        let job_data_id = QProvingJobDataID {
            topic: QJobTopic::GenerateStandardProof,
            goal_id: unique_pending_id,
            circuit_type: ProvingJobCircuitType::UserEndCap,
            group_id: global_user_tree_height as u32,
            sub_group_id: 0,
            task_index: user_id as u32,
            data_type: ProvingJobDataType::OutputProof,
            data_index: 0,
        };
        Ok(job_data_id)
    }
}
impl QProvingJobDataID {
    pub fn with_empty_reward_path(&self) -> QProvingJobDataIDWithRewardPath<Self> {
        QProvingJobDataIDWithRewardPath { job_data_id: *self, reward_path_info: JOB_ID_EMPTY_REWARD_PATH_INFO }
    }
    pub fn into_with_empty_reward_path(self) -> QProvingJobDataIDWithRewardPath<Self> {
        QProvingJobDataIDWithRewardPath { job_data_id: self, reward_path_info: JOB_ID_EMPTY_REWARD_PATH_INFO }
    }
    pub fn with_reward_path_info(&self, reward_path_info: u64) -> QProvingJobDataIDWithRewardPath<Self> {
        QProvingJobDataIDWithRewardPath { job_data_id: *self, reward_path_info }
    }
    pub fn into_with_reward_path_info(self, reward_path_info: u64) -> QProvingJobDataIDWithRewardPath<Self> {
        QProvingJobDataIDWithRewardPath { job_data_id: self, reward_path_info }
    }
    pub fn with_reward_path_merkle_key(&self, reward_path_key: &SimpleMerkleNodeKey) -> QProvingJobDataIDWithRewardPath<Self> {
        QProvingJobDataIDWithRewardPath { job_data_id: *self, reward_path_info: reward_path_key.to_reward_path_info() }
    }
    pub fn into_with_reward_path_merkle_key(self, reward_path_key: &SimpleMerkleNodeKey) -> QProvingJobDataIDWithRewardPath<Self> {
        QProvingJobDataIDWithRewardPath { job_data_id: self, reward_path_info: reward_path_key.to_reward_path_info() }
    }

    pub fn notify_realm_complete(checkpoint_id: u64, realm_id: u32) -> Self {
        Self {
            topic: QJobTopic::NotifyRealmComplete,
            goal_id: checkpoint_id,
            group_id: realm_id,
            circuit_type: ProvingJobCircuitType::Unknown,
            sub_group_id: 0,
            task_index: 0,
            data_type: ProvingJobDataType::InputWitness,
            data_index: 0,
        }
    }
    pub fn notify_block_complete(checkpoint_id: u64, coordinator_id: u32) -> Self {
        Self {
            topic: QJobTopic::NotifyCoordinatorComplete,
            goal_id: checkpoint_id,
            group_id: coordinator_id,
            circuit_type: ProvingJobCircuitType::Unknown,
            sub_group_id: 0,
            task_index: 0,
            data_type: ProvingJobDataType::InputWitness,
            data_index: 0,
        }
    }
    pub fn with_ps_prefix(&self, prefix: [u8; 4]) -> [u8; 28] {
        let mut result = [0u8; 28];
        result[0..3].copy_from_slice(&prefix);
        result[4] = self.topic.to_u8();
        result[5..13].copy_from_slice(&self.goal_id.to_le_bytes());
        result[13] = self.circuit_type.to_u8();
        result[14..18].copy_from_slice(&self.group_id.to_le_bytes());
        result[18..22].copy_from_slice(&self.sub_group_id.to_le_bytes());
        result[22..26].copy_from_slice(&self.task_index.to_le_bytes());
        result[26] = self.data_type.to_u8();
        result[27] = self.data_index;
        result
    }

    pub fn try_from_byte_vec(value: &[u8]) -> anyhow::Result<Self> {
        if value.len() != 24 {
            anyhow::bail!("invalid byte length for proving job data id");
        }
        let topic: QJobTopic = value[0].try_into()?;
        let goal_id = u64::from_le_bytes(value[1..9].try_into()?);
        let circuit_type = ProvingJobCircuitType::try_from(value[9])?;
        let group_id = u32::from_le_bytes(value[10..14].try_into()?);
        let sub_group_id = u32::from_le_bytes(value[14..18].try_into()?);
        let task_index = u32::from_le_bytes(value[18..22].try_into()?);
        let data_type = ProvingJobDataType::try_from(value[22])?;
        let data_index = value[23];
        Ok(QProvingJobDataID {
            topic,
            goal_id,
            circuit_type,
            group_id,
            sub_group_id,
            task_index,
            data_type,
            data_index,
        })
    }
}


impl std::fmt::Display for QProvingJobDataID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            return write!(f, "{}", self.to_hex_string());
        }

        write!(
            f,
            "QJob[topic={:?}(0x{:02X}), goal={} (0x{:016X}), circuit={:?}(0x{:02X}, gid=0x{:08X}), \
group=0x{:08X}, subgroup=0x{:08X}, task=0x{:08X}, dtype={:?}(0x{:02X}), didx=0x{:02X}]",
            self.topic,                       self.topic.to_u8(),
            self.goal_id,                     self.goal_id,
            self.circuit_type,                self.circuit_type.to_u8(), self.circuit_type.to_circuit_group_id(),
            self.group_id,
            self.sub_group_id,
            self.task_index,
            self.data_type,                   self.data_type.to_u8(),
            self.data_index
        )
    }
}
impl From<&QProvingJobDataID> for [u8; 24] {
    fn from(value: &QProvingJobDataID) -> Self {
        let mut result = [0u8; 24];
        result[0] = value.topic.to_u8();
        result[1..9].copy_from_slice(&value.goal_id.to_le_bytes());
        result[9] = value.circuit_type.to_u8();
        result[10..14].copy_from_slice(&value.group_id.to_le_bytes());
        result[14..18].copy_from_slice(&value.sub_group_id.to_le_bytes());
        result[18..22].copy_from_slice(&value.task_index.to_le_bytes());
        result[22] = value.data_type.to_u8();
        result[23] = value.data_index;
        result
    }
}
impl TryFrom<[u8; 24]> for QProvingJobDataID {
    type Error = anyhow::Error;
    fn try_from(value: [u8; 24]) -> Result<Self, Self::Error> {
        let topic: QJobTopic = value[0].try_into()?;
        let goal_id = u64::from_le_bytes(value[1..9].try_into()?);
        let circuit_type = ProvingJobCircuitType::try_from(value[9])?;
        let group_id = u32::from_le_bytes(value[10..14].try_into()?);
        let sub_group_id = u32::from_le_bytes(value[14..18].try_into()?);
        let task_index = u32::from_le_bytes(value[18..22].try_into()?);
        let data_type = ProvingJobDataType::try_from(value[22])?;
        let data_index = value[23];
        Ok(QProvingJobDataID {
            topic,
            goal_id,
            circuit_type,
            group_id,
            sub_group_id,
            task_index,
            data_type,
            data_index,
        })
    }
}

impl QProvingJobDataID {
    pub fn new(
        topic: QJobTopic,
        goal_id: u64,
        group_id: u32,
        sub_group_id: u32,
        task_index: u32,
        circuit_type: ProvingJobCircuitType,
        data_type: ProvingJobDataType,
        data_index: u8,
    ) -> Self {
        Self {
            topic,
            goal_id,
            circuit_type,
            group_id,
            sub_group_id,
            task_index,
            data_type,
            data_index,
        }
    }
    pub fn guta_two_end_cap_witness(checkpoint_id: u64, group_id: u32, sub_group_id: u32, task_index: u32) -> Self {
        Self::new(
            QJobTopic::GenerateStandardProof,
            checkpoint_id,
            group_id,
            sub_group_id,
            task_index,
            ProvingJobCircuitType::GUTATwoEndCap,
            ProvingJobDataType::InputWitness,
            0,
        )
    }
    pub fn guta_two_agg_witness(checkpoint_id: u64, group_id: u32, sub_group_id: u32, task_index: u32) -> Self {
        Self::new(
            QJobTopic::GenerateStandardProof,
            checkpoint_id,
            group_id,
            sub_group_id,
            task_index,
            ProvingJobCircuitType::GUTATwoGUTA,
            ProvingJobDataType::InputWitness,
            0,
        )
    }
    pub fn guta_two_agg_witness_with_checkpoint_upgrade(checkpoint_id: u64, group_id: u32, sub_group_id: u32, task_index: u32) -> Self {
        Self::new(
            QJobTopic::GenerateStandardProof,
            checkpoint_id,
            group_id,
            sub_group_id,
            task_index,
            ProvingJobCircuitType::GUTATwoGUTAWithCheckpointUpgrade,
            ProvingJobDataType::InputWitness,
            0,
        )
    }
    pub fn guta_left_end_cap_right_guta_witness(checkpoint_id: u64, group_id: u32, sub_group_id: u32, task_index: u32) -> Self {
        Self::new(
            QJobTopic::GenerateStandardProof,
            checkpoint_id,
            group_id,
            sub_group_id,
            task_index,
            ProvingJobCircuitType::GUTALeftEndCapRightGUTA,
            ProvingJobDataType::InputWitness,
            0,
        )
    }
    pub fn guta_left_guta_right_end_cap_witness(checkpoint_id: u64, group_id: u32, sub_group_id: u32, task_index: u32) -> Self {
        Self::new(
            QJobTopic::GenerateStandardProof,
            checkpoint_id,
            group_id,
            sub_group_id,
            task_index,
            ProvingJobCircuitType::GUTALeftGUTARightEndCap,
            ProvingJobDataType::InputWitness,
            0,
        )
    }
    pub fn guta_single_end_cap_witness(checkpoint_id: u64, group_id: u32, sub_group_id: u32, task_index: u32) -> Self {
        Self::new(
            QJobTopic::GenerateStandardProof,
            checkpoint_id,
            group_id,
            sub_group_id,
            task_index,
            ProvingJobCircuitType::GUTASingleEndCap,
            ProvingJobDataType::InputWitness,
            0,
        )
    }
    pub fn core_op_witness(checkpoint_id: u64, group_id: u32, circuit_type: ProvingJobCircuitType, sub_group_id: u32, task_index: u32) -> Self {
        Self::new(
            QJobTopic::GenerateStandardProof,
            checkpoint_id,
            group_id,
            sub_group_id,
            task_index,
            circuit_type,
            ProvingJobDataType::InputWitness,
            0,
        )
    }
    pub fn transfer_signature_proof(checkpoint_id: u64, group_id: u32, transfer_id: u32) -> Self {
        Self {
            topic: QJobTopic::BlockUserSignatureProof,
            goal_id: checkpoint_id,
            group_id,
            circuit_type: ProvingJobCircuitType::WrappedSignatureProof,
            sub_group_id: 0,
            task_index: transfer_id,
            data_type: ProvingJobDataType::BaseInputProof,
            data_index: 0,
        }
    }
    pub fn end_cap_proof(checkpoint_id: u64, group_id: u32, user_id: u32) -> Self {
        Self {
            topic: QJobTopic::BlockUserSignatureProof,
            goal_id: checkpoint_id,
            group_id,
            circuit_type: ProvingJobCircuitType::UserEndCap,
            sub_group_id: 1,
            task_index: user_id,
            data_type: ProvingJobDataType::BaseInputProof,
            data_index: 0,
        }
    }
    pub fn withdrawal_signature_proof(checkpoint_id: u64, group_id: u32, withdrawal_id: u32) -> Self {
        Self {
            topic: QJobTopic::BlockUserSignatureProof,
            goal_id: checkpoint_id,
            group_id,
            circuit_type: ProvingJobCircuitType::WrappedSignatureProof,
            sub_group_id: 2,
            task_index: withdrawal_id,
            data_type: ProvingJobDataType::BaseInputProof,
            data_index: 0,
        }
    }
    pub fn claim_deposit_l1_signature_proof(checkpoint_id: u64, group_id: u32, deposit_id: u32) -> Self {
        Self {
            topic: QJobTopic::BlockUserSignatureProof,
            goal_id: checkpoint_id,
            group_id,
            circuit_type: ProvingJobCircuitType::Secp256K1SignatureProof,
            sub_group_id: 3,
            task_index: deposit_id,
            data_type: ProvingJobDataType::BaseInputProof,
            data_index: 0,
        }
    }
    pub fn new_proof_job_id(goal_id: u64, group_id: u32, circuit_type: ProvingJobCircuitType, sub_group_id: u32, task_index: u32) -> Self {
        Self {
            topic: QJobTopic::GenerateStandardProof,
            goal_id,
            group_id,
            circuit_type,
            sub_group_id,
            task_index,
            data_type: ProvingJobDataType::InputWitness,
            data_index: 0,
        }
    }
    pub fn new_groth16_proof_job_id(goal_id: u64, group_id: u32, circuit_type: ProvingJobCircuitType, sub_group_id: u32, task_index: u32) -> Self {
        Self {
            topic: QJobTopic::GenerateGroth16Proof,
            goal_id,
            circuit_type,
            group_id,
            sub_group_id,
            task_index,
            data_type: ProvingJobDataType::InputWitness,
            data_index: 0,
        }
    }
    pub fn get_block_aggregate_jobs_group(checkpoint_id: u64, group_id: u32, task_index: u32) -> Self {
        Self {
            topic: QJobTopic::AggregateJobs,
            goal_id: checkpoint_id,
            group_id,
            circuit_type: ProvingJobCircuitType::Unknown,
            sub_group_id: 0,
            task_index,
            data_type: ProvingJobDataType::InputWitness,
            data_index: 0,
        }
    }
    pub fn block_agg_state_part_1_input_witness(checkpoint_id: u64, group_id: u32) -> Self {
        Self {
            topic: QJobTopic::GenerateStandardProof,
            goal_id: checkpoint_id,
            group_id,
            circuit_type: ProvingJobCircuitType::AggUserRegisterDeployContractsGUTA,
            sub_group_id: 0,
            task_index: 0,
            data_type: ProvingJobDataType::InputWitness,
            data_index: 0,
        }
    }
    pub fn block_agg_state_part_2_input_witness(checkpoint_id: u64, group_id: u32) -> Self {
        Self {
            topic: QJobTopic::GenerateStandardProof,
            goal_id: checkpoint_id,
            group_id,
            circuit_type: ProvingJobCircuitType::AggAddProcessL1WithdrawalAddL1Deposit,
            sub_group_id: 0,
            task_index: 0,
            data_type: ProvingJobDataType::InputWitness,
            data_index: 0,
        }
    }
    pub fn block_state_transition_input_witness(checkpoint_id: u64, group_id: u32) -> Self {
        Self {
            topic: QJobTopic::GenerateStandardProof,
            goal_id: checkpoint_id,
            group_id,
            circuit_type: ProvingJobCircuitType::GenerateRollupStateTransitionProof,
            sub_group_id: 0,
            task_index: 0,
            data_type: ProvingJobDataType::InputWitness,
            data_index: 0,
        }
    }
    pub fn sighash_introspection_input_witness(checkpoint_id: u64, group_id: u32, input_id: usize) -> Self {
        Self {
            topic: QJobTopic::GenerateStandardProof,
            goal_id: checkpoint_id,
            group_id,
            circuit_type: ProvingJobCircuitType::GenerateSigHashIntrospectionProof,
            sub_group_id: 0,
            task_index: input_id as u32,
            data_type: ProvingJobDataType::InputWitness,
            data_index: 0,
        }
    }
    pub fn sighash_final_input_witness(checkpoint_id: u64, group_id: u32, input_id: usize) -> Self {
        Self {
            topic: QJobTopic::GenerateStandardProof,
            goal_id: checkpoint_id,
            group_id,
            circuit_type: ProvingJobCircuitType::GenerateFinalSigHashProof,
            sub_group_id: input_id as u32,
            task_index: input_id as u32,
            data_type: ProvingJobDataType::InputWitness,
            data_index: 0,
        }
    }
    pub fn wrap_sighash_final_bls3812_input_witness(checkpoint_id: u64, group_id: u32, input_id: usize) -> Self {
        Self {
            topic: QJobTopic::GenerateStandardProof,
            goal_id: checkpoint_id,
            group_id,
            circuit_type: ProvingJobCircuitType::WrapFinalSigHashProofBLS12381,
            sub_group_id: input_id as u32,
            task_index: input_id as u32,
            data_type: ProvingJobDataType::InputWitness,
            data_index: 0,
        }
    }
    pub fn get_input_proof_id(&self, data_index: u8) -> Self {
        Self {
            data_type: ProvingJobDataType::BaseInputProof,
            data_index,
            ..*self
        }
    }

    pub fn is_notify_coordinator_complete(&self) -> bool {
        self.topic == QJobTopic::NotifyCoordinatorComplete
    }

    pub fn is_notify_realm_complete(&self) -> bool {
        self.topic == QJobTopic::NotifyRealmComplete
    }

    pub fn is_notify_complete(&self) -> bool {
        self.is_notify_coordinator_complete() || self.is_notify_realm_complete()
    }

    pub fn is_provable(&self) -> bool {
        self.topic == QJobTopic::GenerateStandardProof && !self.is_notify_complete()
    }

    pub fn get_tree_parent_proof_input_id(&self) -> Self {
        let parent_type = match self.circuit_type {
            ProvingJobCircuitType::AppendUserRegistrationTree => ProvingJobCircuitType::AppendUserRegistrationTreeAggregate,
            ProvingJobCircuitType::AppendUserRegistrationTreeAggregate => ProvingJobCircuitType::AppendUserRegistrationTreeAggregate,
            ProvingJobCircuitType::BatchDeployContracts => ProvingJobCircuitType::BatchDeployContractsAggregate,
            ProvingJobCircuitType::BatchDeployContractsAggregate => ProvingJobCircuitType::BatchDeployContractsAggregate,
            ProvingJobCircuitType::AddL1Deposit => ProvingJobCircuitType::AddL1DepositAggregate,
            ProvingJobCircuitType::AddL1DepositAggregate => ProvingJobCircuitType::AddL1DepositAggregate,
            ProvingJobCircuitType::ClaimL1Deposit => ProvingJobCircuitType::ClaimL1DepositAggregate,
            ProvingJobCircuitType::ClaimL1DepositAggregate => ProvingJobCircuitType::ClaimL1DepositAggregate,
            ProvingJobCircuitType::AddL1Withdrawal => ProvingJobCircuitType::AddL1WithdrawalAggregate,
            ProvingJobCircuitType::AddL1WithdrawalAggregate => ProvingJobCircuitType::AddL1WithdrawalAggregate,
            ProvingJobCircuitType::ProcessL1Withdrawal => ProvingJobCircuitType::ProcessL1WithdrawalAggregate,
            ProvingJobCircuitType::ProcessL1WithdrawalAggregate => ProvingJobCircuitType::ProcessL1WithdrawalAggregate,
            ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate => ProvingJobCircuitType::AppendUserRegistrationTreeAggregate,
            ProvingJobCircuitType::DummyAddL1DepositAggregate => ProvingJobCircuitType::AddL1DepositAggregate,
            ProvingJobCircuitType::DummyClaimL1DepositAggregate => ProvingJobCircuitType::ClaimL1DepositAggregate,
            ProvingJobCircuitType::DummyAddL1WithdrawalAggregate => ProvingJobCircuitType::AddL1WithdrawalAggregate,
            ProvingJobCircuitType::DummyProcessL1WithdrawalAggregate => ProvingJobCircuitType::ProcessL1WithdrawalAggregate,
            _ => self.circuit_type,
        };
        Self {
            data_type: ProvingJobDataType::InputWitness,
            data_index: 0,
            circuit_type: parent_type,
            sub_group_id: self.sub_group_id + 1,
            task_index: self.task_index >> 1u32,
            ..*self
        }
    }
    pub fn get_output_id(&self) -> Self {
        Self {
            data_type: ProvingJobDataType::OutputProof,
            data_index: 0,
            ..*self
        }
    }
    pub fn get_input_witness_id(&self) -> Self {
        Self {
            data_type: ProvingJobDataType::InputWitness,
            data_index: 0,
            ..*self
        }
    }
    pub fn get_sub_group_counter_id(&self) -> Self {
        Self {
            data_type: ProvingJobDataType::Counter,
            task_index: 0,
            data_index: 0,
            ..*self
        }
    }
    pub fn get_sub_group_counter_goal_id(&self) -> Self {
        Self {
            data_type: ProvingJobDataType::Counter,
            task_index: 0,
            data_index: 1,
            ..*self
        }
    }
    pub fn get_sub_group_counter_goal_next_jobs_id(&self) -> Self {
        Self {
            data_type: ProvingJobDataType::Counter,
            task_index: 0,
            data_index: 2,
            ..*self
        }
    }
    pub fn to_fixed_bytes(&self) -> QJobIdSerialized {
        self.into()
    }
    pub fn with_task_index(&self, task_index: u32) -> Self {
        Self { task_index, ..*self }
    }
    pub fn to_hex_string(&self) -> String {
        hex::encode(&self.to_fixed_bytes())
    }
}


impl QProvingJobDataID {

    pub fn is_user_guta_proof_circuit_type_or_end_cap(&self) -> bool {
        matches!(
            self.circuit_type,
            ProvingJobCircuitType::GUTATwoEndCap
                | ProvingJobCircuitType::GUTATwoGUTA
                | ProvingJobCircuitType::GUTALeftEndCapRightGUTA
                | ProvingJobCircuitType::GUTALeftGUTARightEndCap
                | ProvingJobCircuitType::GUTASingleEndCap
                | ProvingJobCircuitType::GUTARegisterUsers
                | ProvingJobCircuitType::GUTAVerifyToCap
                | ProvingJobCircuitType::GUTAOnlyRegisterUsers
                | ProvingJobCircuitType::GUTANoChange
                | ProvingJobCircuitType::GUTATwoGUTAWithCheckpointUpgrade
                | ProvingJobCircuitType::GUTAVerifyToCapWithCheckpointUpgrade
                | ProvingJobCircuitType::UserEndCap
        )
    }
}
pub trait QWorkerModeFilter {
    fn can_process_job(&self, job_id: QProvingJobDataID) -> bool;
}
impl QWorkerModeFilter for QWorkerMode {
    fn can_process_job(&self, job_id: QProvingJobDataID) -> bool {
        match *self {
            QWorkerMode::All => true,
            QWorkerMode::NoGroth16 => job_id.circuit_type != ProvingJobCircuitType::WrapFinalSigHashProofBLS12381,
            QWorkerMode::OnlyGroth16 => job_id.circuit_type == ProvingJobCircuitType::WrapFinalSigHashProofBLS12381,
        }
    }
}

impl QPDSerializable for QProvingJobDataID {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.to_fixed_bytes().to_vec())
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        QProvingJobDataID::try_from_byte_vec(bytes)
    }
}
impl PCoreQueueItemBase for QProvingJobDataID {
    fn is_queue_item(data: &[u8]) -> bool {
        if data.len() != 24 {
            return false;
        }
        let topic: Result<QJobTopic, _> = data[0].try_into();
        let circuit_type: Result<ProvingJobCircuitType, _> = data[9].try_into();
        let data_type: Result<ProvingJobDataType, _> = data[22].try_into();
        topic.is_ok() && circuit_type.is_ok() && data_type.is_ok()
    }
    
    fn decode_queue_item_ref(data: &[u8]) -> anyhow::Result<Self> {
        QProvingJobDataID::try_from_byte_vec(data)
    }
    
    fn encode_queue_item_vec(&self) -> anyhow::Result<Vec<u8>> {
        self.to_bytes()
    }
    
    fn get_restorable_job_id(&self) -> Vec<u8> {
        self.to_fixed_bytes().to_vec()
    }
    
    fn get_size_hint() -> usize {
        24
    }
    
    fn has_fixed_size() -> bool {
        true
    }
}
impl QPDSerializableFixed for QProvingJobDataID {
    
    fn get_fixed_size() -> usize {
        24
    }
}
impl From<QProvingJobDataID> for QJobIdSerialized {
    fn from(value: QProvingJobDataID) -> Self {
        value.to_fixed_bytes()
    }
}

impl QJobIdBase for QProvingJobDataID{
    fn to_bytes_fixed(&self) -> QJobIdSerialized {
        self.to_fixed_bytes()
    }

    fn from_bytes_fixed(bytes: &QJobIdSerialized) -> anyhow::Result<Self> {
        QProvingJobDataID::try_from(*bytes)
    }

    fn circuit_type_u32(&self) -> u32 {
        self.circuit_type as u32
    }

    fn input_witness_id(&self) -> Self {
        self.get_input_witness_id()
    }

    fn output_proof_id(&self) -> Self {
        self.get_output_id()
    }

    fn group_counter_id(&self) -> Self {
        self.get_sub_group_counter_id()
    }


    fn is_end_cap_proof_circuit_type(&self) -> bool {
        self.circuit_type == ProvingJobCircuitType::UserEndCap
    }

    fn get_parth_index(&self) -> u64 {
        self.task_index as u64
    }

    fn get_reverse_parth_level(&self) -> u8 {
        self.sub_group_id as u8
    }
    
    fn new_invalid_job_id() -> Self {
        Self {
            topic: QJobTopic::Invalid,
            goal_id: 0,
            circuit_type: ProvingJobCircuitType::Invalid,
            group_id: 0,
            sub_group_id: 0,
            task_index: 0,
            data_type: ProvingJobDataType::BaseInputProof,
            data_index: 0,
        }
    }
    
    fn is_valid(&self) -> bool {
        !(self.circuit_type == ProvingJobCircuitType::Invalid || self.topic == QJobTopic::Invalid)
    }
    
    fn get_synced_checkpoint_id(&self) -> u64 {
        self.goal_id
    }
    
    fn is_guta_proof_circuit_type(&self) -> bool {
        matches!(
            self.circuit_type,
            ProvingJobCircuitType::GUTATwoEndCap
                | ProvingJobCircuitType::GUTATwoGUTA
                | ProvingJobCircuitType::GUTALeftEndCapRightGUTA
                | ProvingJobCircuitType::GUTALeftGUTARightEndCap
                | ProvingJobCircuitType::GUTASingleEndCap
                | ProvingJobCircuitType::GUTARegisterUsers
                | ProvingJobCircuitType::GUTAVerifyToCap
                | ProvingJobCircuitType::GUTAOnlyRegisterUsers
                | ProvingJobCircuitType::GUTANoChange
                | ProvingJobCircuitType::GUTATwoGUTAWithCheckpointUpgrade
                | ProvingJobCircuitType::GUTAVerifyToCapWithCheckpointUpgrade
        )
    }
}


impl QJobIdCreatable for QProvingJobDataID {
    fn new_standard_user_end_cap_proof_id(at_checkpoint_id: u64, user_id: u64, global_user_tree_height: u8) -> Self {
        Self {
            topic: QJobTopic::GenerateStandardProof,
            goal_id: at_checkpoint_id,
            group_id: 0,
            circuit_type: ProvingJobCircuitType::UserEndCap,
            sub_group_id: global_user_tree_height as u32,
            task_index: user_id as u32,
            data_type: ProvingJobDataType::BaseInputProof,
            data_index: 0,
        }
    }

    fn new_alt_user_end_cap_proof_id(at_checkpoint_id: u64, user_id: u64, global_user_tree_height: u8, circuit_type: u32) -> Self {
        if circuit_type > u8::MAX as u32 || circuit_type != ProvingJobCircuitType::UserEndCap as u32 {
            Self::new_invalid_job_id().get_input_proof_id(0)
        }else{
            Self {
                topic: QJobTopic::GenerateStandardProof,
                goal_id: at_checkpoint_id,
                group_id: 0,
                circuit_type: ProvingJobCircuitType::UserEndCap,
                sub_group_id: global_user_tree_height as u32,
                task_index: user_id as u32,
                data_type: ProvingJobDataType::BaseInputProof,
                data_index: 0,
            }
        }
    }
    
    
    fn new_two_to_one_proof_id_or_invalid(target_checkpoint_id: u64, left_proof_id: &Self, right_proof_id: &Self, parth_index: u64, parth_level: u8, reverse_aggregation_level: u8) -> Self {
        Self::new_two_to_one_proof_id(target_checkpoint_id, left_proof_id, right_proof_id, parth_index, parth_level, reverse_aggregation_level)
            .unwrap_or_else(|_| Self::new_invalid_job_id().get_output_id()) // Return invalid proof with OutputProof type for consistency
    }
    
    // TODO: should we use parth level and encode it in the job id?
    fn new_two_to_one_proof_id(target_checkpoint_id: u64, left_proof_id: &Self, right_proof_id: &Self, parth_index: u64, _parth_level: u8, reverse_aggregation_level: u8) -> anyhow::Result<Self> {
        if !left_proof_id.is_valid() || !right_proof_id.is_valid() {
            anyhow::bail!("invalid left or right proof id");
        }

        let left_circuit = left_proof_id.circuit_type;
        let right_circuit = right_proof_id.circuit_type;

        // Determine the resulting circuit type from the aggregation
        let circuit_type = {
            // First, handle the special case for GUTA and EndCap proofs
            let left_is_guta = left_proof_id.is_guta_proof_circuit_type();
            let left_is_end_cap = left_proof_id.is_end_cap_proof_circuit_type();
            let right_is_guta = right_proof_id.is_guta_proof_circuit_type();
            let right_is_end_cap = right_proof_id.is_end_cap_proof_circuit_type();

            if (left_is_guta || left_is_end_cap) && (right_is_guta || right_is_end_cap) {
                match (left_is_end_cap, right_is_end_cap) {
                    (true, true) => ProvingJobCircuitType::GUTATwoEndCap,
                    (true, false) => ProvingJobCircuitType::GUTALeftEndCapRightGUTA,
                    (false, true) => ProvingJobCircuitType::GUTALeftGUTARightEndCap,
                    (false, false) => {
                        // If both are GUTA, check if a checkpoint upgrade is needed
                        if left_proof_id.get_synced_checkpoint_id() == target_checkpoint_id
                            && right_proof_id.get_synced_checkpoint_id() == target_checkpoint_id
                        {
                            ProvingJobCircuitType::GUTATwoGUTA
                        } else {
                            ProvingJobCircuitType::GUTATwoGUTAWithCheckpointUpgrade
                        }
                    }
                }
            } else {
                // Handle all other standard aggregatable proof types generically
                let left_leaf = left_circuit.get_agg_leaf_circuit_type_or_err();
                let right_leaf = right_circuit.get_agg_leaf_circuit_type_or_err();

                match (left_leaf, right_leaf) {
                    (Ok(ll), Ok(rl)) if ll == rl => {
                        // If both proofs belong to the same aggregatable "family" (i.e., they normalize
                        // to the same leaf type), the result is the aggregate circuit for that family.
                        ll.get_agg_circuit_type_or_err()?
                    }
                    _ => {
                        // If they don't have a leaf type, or the leaf types don't match,
                        // they cannot be aggregated this way.
                        unreachable!("cannot aggregate proofs of different or non-aggregatable types: left={:?}, right={:?}", left_circuit, right_circuit);
                    }
                }
            }
        };

        // Construct the new job ID for the aggregation proof
        Ok(Self {
            topic: QJobTopic::GenerateStandardProof,
            goal_id: target_checkpoint_id,
            group_id: left_proof_id.group_id, // Assume group_id is consistent
            circuit_type,
            sub_group_id: reverse_aggregation_level as u32,
            task_index: parth_index as u32,
            data_type: ProvingJobDataType::BaseInputProof, // The result of aggregation is a proof
            data_index: 0,
        })
    }
}



#[cfg(feature = "serialize_speedy")]
impl<'a, C: speedy::Context> speedy::Readable<'a, C> for QProvingJobDataID {
    fn read_from<R: speedy::Reader<'a, C>>(reader: &mut R) -> Result<Self, C::Error> {
        let topic = reader.read_u8()?;
        let goal_id = reader.read_u64()?;
        let circuit_type = reader.read_u8()?;
        let group_id = reader.read_u32()?;
        let sub_group_id = reader.read_u32()?;
        let task_index = reader.read_u32()?;
        let data_type = reader.read_u8()?;
        let data_index = reader.read_u8()?;

        Ok(QProvingJobDataID {
            topic: QJobTopic::try_from(topic).map_err(speedy::Error::custom)?,
            goal_id,
            circuit_type: ProvingJobCircuitType::try_from(circuit_type).map_err(speedy::Error::custom)?,
            group_id,
            sub_group_id,
            task_index,
            data_type: ProvingJobDataType::try_from(data_type).map_err(speedy::Error::custom)?,
            data_index,
        })
    }
}

#[cfg(feature = "serialize_speedy")]
impl<C: speedy::Context> speedy::Writable<C> for QProvingJobDataID {
    fn write_to<T: ?Sized + speedy::Writer<C>>(&self, writer: &mut T) -> Result<(), C::Error> {
        writer.write_u8(self.topic.to_u8())?;
        writer.write_u64(self.goal_id)?;
        writer.write_u8(self.circuit_type.to_u8())?;
        writer.write_u32(self.group_id)?;
        writer.write_u32(self.sub_group_id)?;
        writer.write_u32(self.task_index)?;
        writer.write_u8(self.data_type.to_u8())?;
        writer.write_u8(self.data_index)?;
        Ok(())
    }
}
