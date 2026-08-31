use std::fmt;

use anyhow::Result;
use hex::FromHexError;
use kvq::traits::KVQSerializable;
use plonky2::{field::goldilocks_field::GoldilocksField, hash::hash_types::HashOut, plonk::config::PoseidonGoldilocksConfig};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use serde_with::serde_as;
use strum_macros::{AsRefStr, Display};

use super::traits::QProofStoreAsyncImm;

#[async_trait::async_trait]
pub trait QJobRewardDataProvider {
    async fn get_job_commitment(&self, job_id: QProvingJobDataID) -> anyhow::Result<QHashOut<F>>;
    async fn get_job_worker_public_key(&self, job_id: QProvingJobDataID) -> anyhow::Result<QHashOut<F>>;
}

#[async_trait::async_trait]
impl<T: QProofStoreAsyncImm> QJobRewardDataProvider for T {
    async fn get_job_commitment(&self, job_id: QProvingJobDataID) -> anyhow::Result<QHashOut<F>> {
        let public_inputs = self.get_public_input_by_id::<PoseidonGoldilocksConfig, 2>(job_id.get_output_id()).await?;
        Ok(QHashOut(HashOut {
            elements: [public_inputs[0], public_inputs[1], public_inputs[2], public_inputs[3]],
        }))
    }

    async fn get_job_worker_public_key(&self, job_id: QProvingJobDataID) -> anyhow::Result<QHashOut<F>> {
        let public_inputs = self.get_public_input_by_id::<PoseidonGoldilocksConfig, 2>(job_id.get_output_id()).await?;
        Ok(QHashOut(HashOut {
            elements: [public_inputs[4], public_inputs[5], public_inputs[6], public_inputs[7]],
        }))
    }
}

use crate::data::qhashout::QHashOut;

type F = GoldilocksField;

pub const GUTA_REWARDS_TREE_MAX_HEIGHT: usize = 12;
pub const GUTA_REWARDS_TREE_V2_MAX_HEIGHT: usize = 21;
pub const CONTRACT_DEPLOYMENT_REWARDS_MAX_HEIGHT: usize = 20;
pub const USER_REGISTRATION_REWARDS_MAX_HEIGHT: usize = 20;

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
#[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum QJobTopic {
    GenerateStandardProof = 0,
    GenerateGroth16Proof = 1,
    BlockUserSignatureProof = 2,
    NotifyCoordinatorComplete = 3,
    NotifyRealmComplete = 4,
    AggregateJobs = 5,
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
            _ => Err(anyhow::format_err!("Invalid QJobTopic value: {}", value)),
        }
    }
}

#[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
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

#[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord, Display, AsRefStr)]
#[repr(u8)]
pub enum ProvingJobCircuitType {
    AppendUserRegistrationTree = 0,
    AppendUserRegistrationTreeAggregate = 1,

    AddDeposit = 2,
    AddDepositAggregate = 3,

    ClaimDeposit = 4,
    ClaimDepositAggregate = 5,

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

    AddWithdrawal = 16,
    AddWithdrawalAggregate = 17,

    BatchDeployContracts = 18,
    BatchDeployContractsAggregate = 19,

    ProcessWithdrawal = 20,
    ProcessWithdrawalAggregate = 21,

    GenerateRollupStateTransitionProof = 32,
    GenerateSigHashIntrospectionProof = 33,
    GenerateFinalSigHashProof = 34,
    GenerateFinalSigHashProofGroth16 = 35,
    WrapFinalSigHashProofBLS12381 = 36,

    AggUserRegisterDeployContractsGUTA = 40,
    AggAddProcessWithdrawalAddDeposit = 41,

    DummyAppendUserRegistrationTreeAggregate = 48,
    DummyAddDepositAggregate = 49,
    DummyClaimDepositAggregate = 50,
    DummyGUTA = 51,
    DummyAddWithdrawalAggregate = 52,
    DummyProcessWithdrawalAggregate = 53,
    DummyBatchDeployContractsAggregate = 54,

    // ADDED NEW - For Historical Upgrades
    GUTATwoGUTAWithCheckpointUpgrade = 55,
    GUTAVerifyToCapWithCheckpointUpgrade = 56,

    RealmFinalizeGUTA = 63,

    WrappedSignatureProof = 64,
    Secp256K1SignatureProof = 65,

    NotifyRealmComplete = 192,

    TypeA = 224,
    TypeB = 225,
    TypeC = 226,
    TypeD = 227,
    TypeE = 228,
    TypeF = 229,
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
            ProvingJobCircuitType::AddDeposit => ProvingJobCircuitType::AddDeposit,
            ProvingJobCircuitType::AddDepositAggregate => ProvingJobCircuitType::AddDeposit,
            ProvingJobCircuitType::ClaimDeposit => ProvingJobCircuitType::ClaimDeposit,
            ProvingJobCircuitType::ClaimDepositAggregate => ProvingJobCircuitType::ClaimDeposit,
            ProvingJobCircuitType::AddWithdrawal => ProvingJobCircuitType::AddWithdrawal,
            ProvingJobCircuitType::AddWithdrawalAggregate => ProvingJobCircuitType::AddWithdrawal,
            ProvingJobCircuitType::BatchDeployContracts => ProvingJobCircuitType::BatchDeployContracts,
            ProvingJobCircuitType::BatchDeployContractsAggregate => ProvingJobCircuitType::BatchDeployContracts,
            ProvingJobCircuitType::ProcessWithdrawal => ProvingJobCircuitType::ProcessWithdrawal,
            ProvingJobCircuitType::ProcessWithdrawalAggregate => ProvingJobCircuitType::ProcessWithdrawal,
            _ => anyhow::bail!("circuit type {:?} does not have a leaf type", self),
        };
        Ok(leaf_type)
    }

    pub fn is_deploy_contracts_job(&self) -> bool {
        matches!(
            self,
            ProvingJobCircuitType::BatchDeployContracts
                | ProvingJobCircuitType::BatchDeployContractsAggregate
                | ProvingJobCircuitType::DummyBatchDeployContractsAggregate
        )
    }

    pub fn is_user_registration_job(&self) -> bool {
        matches!(
            self,
            ProvingJobCircuitType::AppendUserRegistrationTree
                | ProvingJobCircuitType::AppendUserRegistrationTreeAggregate
                | ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate
        )
    }

    pub fn is_guta_job(&self) -> bool {
        matches!(
            self,
            ProvingJobCircuitType::GUTAOnlyRegisterUsers
                | ProvingJobCircuitType::GUTARegisterUsers
                | ProvingJobCircuitType::GUTATwoEndCap
                | ProvingJobCircuitType::GUTATwoGUTA
                | ProvingJobCircuitType::GUTALeftEndCapRightGUTA
                | ProvingJobCircuitType::GUTALeftGUTARightEndCap
                | ProvingJobCircuitType::GUTASingleEndCap
                | ProvingJobCircuitType::GUTAVerifyToCap
                | ProvingJobCircuitType::GUTATwoGUTAWithCheckpointUpgrade
                | ProvingJobCircuitType::GUTAVerifyToCapWithCheckpointUpgrade
                | ProvingJobCircuitType::GUTANoChange
        )
    }

    pub fn get_agg_circuit_type_or_err(&self) -> anyhow::Result<Self> {
        let leaf_type = match self {
            ProvingJobCircuitType::AppendUserRegistrationTree => ProvingJobCircuitType::AppendUserRegistrationTreeAggregate,
            ProvingJobCircuitType::AppendUserRegistrationTreeAggregate => ProvingJobCircuitType::AppendUserRegistrationTreeAggregate,
            ProvingJobCircuitType::AddDeposit => ProvingJobCircuitType::AddDepositAggregate,
            ProvingJobCircuitType::AddDepositAggregate => ProvingJobCircuitType::AddDepositAggregate,
            ProvingJobCircuitType::ClaimDeposit => ProvingJobCircuitType::ClaimDepositAggregate,
            ProvingJobCircuitType::ClaimDepositAggregate => ProvingJobCircuitType::ClaimDepositAggregate,
            ProvingJobCircuitType::AddWithdrawal => ProvingJobCircuitType::AddWithdrawalAggregate,
            ProvingJobCircuitType::AddWithdrawalAggregate => ProvingJobCircuitType::AddWithdrawalAggregate,
            ProvingJobCircuitType::BatchDeployContracts => ProvingJobCircuitType::BatchDeployContractsAggregate,
            ProvingJobCircuitType::BatchDeployContractsAggregate => ProvingJobCircuitType::BatchDeployContractsAggregate,
            ProvingJobCircuitType::ProcessWithdrawal => ProvingJobCircuitType::ProcessWithdrawalAggregate,
            ProvingJobCircuitType::ProcessWithdrawalAggregate => ProvingJobCircuitType::ProcessWithdrawalAggregate,
            _ => anyhow::bail!("circuit type {:?} does not have a aggregated circuit type", self),
        };
        Ok(leaf_type)
    }

    pub fn get_agg_dummy_circuit_type_or_err(&self) -> anyhow::Result<Self> {
        let leaf_type = match self {
            ProvingJobCircuitType::AppendUserRegistrationTree => ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate,
            ProvingJobCircuitType::AppendUserRegistrationTreeAggregate => ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate,
            ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate => ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate,
            ProvingJobCircuitType::AddDeposit => ProvingJobCircuitType::DummyAddDepositAggregate,
            ProvingJobCircuitType::AddDepositAggregate => ProvingJobCircuitType::DummyAddDepositAggregate,
            ProvingJobCircuitType::DummyAddDepositAggregate => ProvingJobCircuitType::DummyAddDepositAggregate,
            ProvingJobCircuitType::ClaimDeposit => ProvingJobCircuitType::DummyClaimDepositAggregate,
            ProvingJobCircuitType::ClaimDepositAggregate => ProvingJobCircuitType::DummyClaimDepositAggregate,
            ProvingJobCircuitType::DummyClaimDepositAggregate => ProvingJobCircuitType::DummyClaimDepositAggregate,
            ProvingJobCircuitType::AddWithdrawal => ProvingJobCircuitType::DummyAddWithdrawalAggregate,
            ProvingJobCircuitType::AddWithdrawalAggregate => ProvingJobCircuitType::DummyAddWithdrawalAggregate,
            ProvingJobCircuitType::DummyAddWithdrawalAggregate => ProvingJobCircuitType::DummyAddWithdrawalAggregate,
            ProvingJobCircuitType::BatchDeployContracts => ProvingJobCircuitType::DummyBatchDeployContractsAggregate,
            ProvingJobCircuitType::BatchDeployContractsAggregate => ProvingJobCircuitType::DummyBatchDeployContractsAggregate,
            ProvingJobCircuitType::DummyBatchDeployContractsAggregate => ProvingJobCircuitType::DummyBatchDeployContractsAggregate,
            ProvingJobCircuitType::ProcessWithdrawal => ProvingJobCircuitType::DummyProcessWithdrawalAggregate,
            ProvingJobCircuitType::ProcessWithdrawalAggregate => ProvingJobCircuitType::DummyProcessWithdrawalAggregate,
            ProvingJobCircuitType::DummyProcessWithdrawalAggregate => ProvingJobCircuitType::DummyProcessWithdrawalAggregate,
            _ => anyhow::bail!("circuit type {:?} does not have a aggregated dummy circuit type", self),
        };
        Ok(leaf_type)
    }
}

impl TryFrom<u8> for ProvingJobCircuitType {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ProvingJobCircuitType::AppendUserRegistrationTree),
            1 => Ok(ProvingJobCircuitType::AppendUserRegistrationTreeAggregate),
            2 => Ok(ProvingJobCircuitType::AddDeposit),
            3 => Ok(ProvingJobCircuitType::AddDepositAggregate),
            4 => Ok(ProvingJobCircuitType::ClaimDeposit),
            5 => Ok(ProvingJobCircuitType::ClaimDepositAggregate),
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
            16 => Ok(ProvingJobCircuitType::AddWithdrawal),
            17 => Ok(ProvingJobCircuitType::AddWithdrawalAggregate),
            18 => Ok(ProvingJobCircuitType::BatchDeployContracts),
            19 => Ok(ProvingJobCircuitType::BatchDeployContractsAggregate),
            20 => Ok(ProvingJobCircuitType::ProcessWithdrawal),
            21 => Ok(ProvingJobCircuitType::ProcessWithdrawalAggregate),
            32 => Ok(ProvingJobCircuitType::GenerateRollupStateTransitionProof),
            33 => Ok(ProvingJobCircuitType::GenerateSigHashIntrospectionProof),
            34 => Ok(ProvingJobCircuitType::GenerateFinalSigHashProof),
            35 => Ok(ProvingJobCircuitType::GenerateFinalSigHashProofGroth16),
            36 => Ok(ProvingJobCircuitType::WrapFinalSigHashProofBLS12381),
            40 => Ok(ProvingJobCircuitType::AggUserRegisterDeployContractsGUTA),
            41 => Ok(ProvingJobCircuitType::AggAddProcessWithdrawalAddDeposit),
            48 => Ok(ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate),
            49 => Ok(ProvingJobCircuitType::DummyAddDepositAggregate),
            50 => Ok(ProvingJobCircuitType::DummyClaimDepositAggregate),
            51 => Ok(ProvingJobCircuitType::DummyGUTA),
            52 => Ok(ProvingJobCircuitType::DummyAddWithdrawalAggregate),
            53 => Ok(ProvingJobCircuitType::DummyProcessWithdrawalAggregate),
            54 => Ok(ProvingJobCircuitType::DummyBatchDeployContractsAggregate),
            55 => Ok(ProvingJobCircuitType::GUTATwoGUTAWithCheckpointUpgrade),

            63 => Ok(ProvingJobCircuitType::RealmFinalizeGUTA),

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

pub type QProvingJobDataIDSerialized = [u8; 32];

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Copy, Eq, Hash, Clone, Debug)]
pub struct QProvingJobDataIDSerializedWrapped(#[serde_as(as = "serde_with::hex::Hex")] pub QProvingJobDataIDSerialized);

impl QProvingJobDataIDSerializedWrapped {
    pub fn from_hex_string(s: &str) -> Result<Self, FromHexError> {
        let bytes = hex::decode(s)?;
        assert_eq!(bytes.len(), 32);
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(Self(array))
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct QProvingJobDataID {
    pub topic: QJobTopic,
    pub goal_id: u64,
    #[serde(skip)]
    pub slot_id: u64,
    pub circuit_type: ProvingJobCircuitType,
    pub group_id: u32,
    pub sub_group_id: u32,
    pub task_index: u32,
    pub data_type: ProvingJobDataType,
    pub data_index: u8,
}
impl QProvingJobDataID {
    pub fn notify_realm_complete(checkpoint_id: u64, slot_id: u64, realm_id: u32) -> Self {
        Self {
            topic: QJobTopic::NotifyRealmComplete,
            goal_id: checkpoint_id,
            slot_id,
            group_id: realm_id,
            circuit_type: ProvingJobCircuitType::Unknown,
            sub_group_id: 0,
            task_index: 0,
            data_type: ProvingJobDataType::InputWitness,
            data_index: 0,
        }
    }
    pub fn notify_block_complete(checkpoint_id: u64, slot_id: u64, coordinator_id: u32) -> Self {
        Self {
            topic: QJobTopic::NotifyCoordinatorComplete,
            goal_id: checkpoint_id,
            slot_id,
            group_id: coordinator_id,
            circuit_type: ProvingJobCircuitType::Unknown,
            sub_group_id: 0,
            task_index: 0,
            data_type: ProvingJobDataType::InputWitness,
            data_index: 0,
        }
    }

    pub fn try_from_byte_vec(value: &[u8]) -> anyhow::Result<Self> {
        if value.len() != 32 {
            anyhow::bail!("invalid byte length for proving job data id");
        }
        let topic: QJobTopic = value[0].try_into()?;
        let goal_id = u64::from_le_bytes(value[1..9].try_into()?);
        let slot_id = u64::from_le_bytes(value[9..17].try_into()?);
        let circuit_type = ProvingJobCircuitType::try_from(value[17])?;
        let group_id = u32::from_le_bytes(value[18..22].try_into()?);
        let sub_group_id = u32::from_le_bytes(value[22..26].try_into()?);
        let task_index = u32::from_le_bytes(value[26..30].try_into()?);
        let data_type = ProvingJobDataType::try_from(value[30])?;
        let data_index = value[31];
        Ok(QProvingJobDataID {
            topic,
            goal_id,
            slot_id,
            circuit_type,
            group_id,
            sub_group_id,
            task_index,
            data_type,
            data_index,
        })
    }

    /// Parse from 24-byte format (parth-generic-v1 format, without slot_id)
    /// Format: [0]: topic, [1..9]: goal_id, [9]: circuit_type, [10..14]:
    /// group_id, [14..18]: sub_group_id, [18..22]: task_index, [22]: data_type,
    /// [23]: data_index
    pub fn try_from_byte_vec_without_slot_id(value: &[u8]) -> anyhow::Result<Self> {
        if value.len() != 24 {
            anyhow::bail!("invalid byte length for proving job data id (expected 24 bytes without slot_id)");
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
            slot_id: 0, // 24-byte format has no slot_id, default to 0
            circuit_type,
            group_id,
            sub_group_id,
            task_index,
            data_type,
            data_index,
        })
    }

    /// Serialize to 24-byte format (parth-generic-v1 format, without slot_id)
    /// Format: [0]: topic, [1..9]: goal_id, [9]: circuit_type, [10..14]:
    /// group_id, [14..18]: sub_group_id, [18..22]: task_index, [22]: data_type,
    /// [23]: data_index
    pub fn to_bytes_without_slot_id(&self) -> [u8; 24] {
        let mut result = [0u8; 24];
        result[0] = self.topic.to_u8();
        result[1..9].copy_from_slice(&self.goal_id.to_le_bytes());
        result[9] = self.circuit_type.to_u8();
        result[10..14].copy_from_slice(&self.group_id.to_le_bytes());
        result[14..18].copy_from_slice(&self.sub_group_id.to_le_bytes());
        result[18..22].copy_from_slice(&self.task_index.to_le_bytes());
        result[22] = self.data_type.to_u8();
        result[23] = self.data_index;
        result
    }
}

impl fmt::Display for QProvingJobDataID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            return write!(f, "{}", self.to_hex_string());
        }

        write!(
            f,
            "QJob[topic={:?}(0x{:02X}), goal={} (0x{:016X}), slot={} (0x{:016X}), circuit={:?}(0x{:02X}, gid=0x{:08X}), \
group=0x{:08X}, subgroup=0x{:08X}, task=0x{:08X}, dtype={:?}(0x{:02X}), didx=0x{:02X}]",
            self.topic,
            self.topic.to_u8(),
            self.goal_id,
            self.goal_id,
            self.slot_id,
            self.slot_id,
            self.circuit_type,
            self.circuit_type.to_u8(),
            self.circuit_type.to_circuit_group_id(),
            self.group_id,
            self.sub_group_id,
            self.task_index,
            self.data_type,
            self.data_type.to_u8(),
            self.data_index
        )
    }
}
impl From<&QProvingJobDataID> for [u8; 32] {
    fn from(value: &QProvingJobDataID) -> Self {
        let mut result = [0u8; 32];
        result[0] = value.topic.to_u8();
        result[1..9].copy_from_slice(&value.goal_id.to_le_bytes());
        result[9..17].copy_from_slice(&value.slot_id.to_le_bytes());
        result[17] = value.circuit_type.to_u8();
        result[18..22].copy_from_slice(&value.group_id.to_le_bytes());
        result[22..26].copy_from_slice(&value.sub_group_id.to_le_bytes());
        result[26..30].copy_from_slice(&value.task_index.to_le_bytes());
        result[30] = value.data_type.to_u8();
        result[31] = value.data_index;
        result
    }
}
impl TryFrom<[u8; 32]> for QProvingJobDataID {
    type Error = anyhow::Error;
    fn try_from(value: [u8; 32]) -> Result<Self, Self::Error> {
        let topic: QJobTopic = value[0].try_into()?;
        let goal_id = u64::from_le_bytes(value[1..9].try_into()?);
        let slot_id = u64::from_le_bytes(value[9..17].try_into()?);
        let circuit_type = ProvingJobCircuitType::try_from(value[17])?;
        let group_id = u32::from_le_bytes(value[18..22].try_into()?);
        let sub_group_id = u32::from_le_bytes(value[22..26].try_into()?);
        let task_index = u32::from_le_bytes(value[26..30].try_into()?);
        let data_type = ProvingJobDataType::try_from(value[30])?;
        let data_index = value[31];
        Ok(QProvingJobDataID {
            topic,
            goal_id,
            slot_id,
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
        slot_id: u64,
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
            slot_id,
            circuit_type,
            group_id,
            sub_group_id,
            task_index,
            data_type,
            data_index,
        }
    }
    pub fn guta_two_end_cap_witness(checkpoint_id: u64, slot_id: u64, group_id: u32, sub_group_id: u32, task_index: u32) -> Self {
        Self::new(
            QJobTopic::GenerateStandardProof,
            checkpoint_id,
            slot_id,
            group_id,
            sub_group_id,
            task_index,
            ProvingJobCircuitType::GUTATwoEndCap,
            ProvingJobDataType::InputWitness,
            0,
        )
    }
    pub fn guta_two_agg_witness(checkpoint_id: u64, slot_id: u64, group_id: u32, sub_group_id: u32, task_index: u32) -> Self {
        Self::new(
            QJobTopic::GenerateStandardProof,
            checkpoint_id,
            slot_id,
            group_id,
            sub_group_id,
            task_index,
            ProvingJobCircuitType::GUTATwoGUTA,
            ProvingJobDataType::InputWitness,
            0,
        )
    }
    pub fn guta_two_agg_witness_with_checkpoint_upgrade(checkpoint_id: u64, slot_id: u64, group_id: u32, sub_group_id: u32, task_index: u32) -> Self {
        Self::new(
            QJobTopic::GenerateStandardProof,
            checkpoint_id,
            slot_id,
            group_id,
            sub_group_id,
            task_index,
            ProvingJobCircuitType::GUTATwoGUTAWithCheckpointUpgrade,
            ProvingJobDataType::InputWitness,
            0,
        )
    }
    pub fn guta_left_end_cap_right_guta_witness(checkpoint_id: u64, slot_id: u64, group_id: u32, sub_group_id: u32, task_index: u32) -> Self {
        Self::new(
            QJobTopic::GenerateStandardProof,
            checkpoint_id,
            slot_id,
            group_id,
            sub_group_id,
            task_index,
            ProvingJobCircuitType::GUTALeftEndCapRightGUTA,
            ProvingJobDataType::InputWitness,
            0,
        )
    }
    pub fn guta_left_guta_right_end_cap_witness(checkpoint_id: u64, slot_id: u64, group_id: u32, sub_group_id: u32, task_index: u32) -> Self {
        Self::new(
            QJobTopic::GenerateStandardProof,
            checkpoint_id,
            slot_id,
            group_id,
            sub_group_id,
            task_index,
            ProvingJobCircuitType::GUTALeftGUTARightEndCap,
            ProvingJobDataType::InputWitness,
            0,
        )
    }
    pub fn guta_single_end_cap_witness(checkpoint_id: u64, slot_id: u64, group_id: u32, sub_group_id: u32, task_index: u32) -> Self {
        Self::new(
            QJobTopic::GenerateStandardProof,
            checkpoint_id,
            slot_id,
            group_id,
            sub_group_id,
            task_index,
            ProvingJobCircuitType::GUTASingleEndCap,
            ProvingJobDataType::InputWitness,
            0,
        )
    }
    pub fn core_op_witness(
        checkpoint_id: u64,
        slot_id: u64,
        group_id: u32,
        circuit_type: ProvingJobCircuitType,
        sub_group_id: u32,
        task_index: u32,
    ) -> Self {
        Self::new(
            QJobTopic::GenerateStandardProof,
            checkpoint_id,
            slot_id,
            group_id,
            sub_group_id,
            task_index,
            circuit_type,
            ProvingJobDataType::InputWitness,
            0,
        )
    }
    pub fn transfer_signature_proof(checkpoint_id: u64, slot_id: u64, group_id: u32, transfer_id: u32) -> Self {
        Self {
            topic: QJobTopic::BlockUserSignatureProof,
            goal_id: checkpoint_id,
            slot_id,
            group_id,
            circuit_type: ProvingJobCircuitType::WrappedSignatureProof,
            sub_group_id: 0,
            task_index: transfer_id,
            data_type: ProvingJobDataType::BaseInputProof,
            data_index: 0,
        }
    }
    pub fn end_cap_proof(checkpoint_id: u64, slot_id: u64, group_id: u32, user_id: u32) -> Self {
        Self {
            topic: QJobTopic::BlockUserSignatureProof,
            goal_id: checkpoint_id,
            slot_id,
            group_id,
            circuit_type: ProvingJobCircuitType::UserEndCap,
            sub_group_id: 1,
            task_index: user_id,
            data_type: ProvingJobDataType::BaseInputProof,
            data_index: 0,
        }
    }
    pub fn withdrawal_signature_proof(checkpoint_id: u64, slot_id: u64, group_id: u32, withdrawal_id: u32) -> Self {
        Self {
            topic: QJobTopic::BlockUserSignatureProof,
            goal_id: checkpoint_id,
            slot_id,
            group_id,
            circuit_type: ProvingJobCircuitType::WrappedSignatureProof,
            sub_group_id: 2,
            task_index: withdrawal_id,
            data_type: ProvingJobDataType::BaseInputProof,
            data_index: 0,
        }
    }
    pub fn claim_deposit_signature_proof(checkpoint_id: u64, slot_id: u64, group_id: u32, deposit_id: u32) -> Self {
        Self {
            topic: QJobTopic::BlockUserSignatureProof,
            goal_id: checkpoint_id,
            slot_id,
            group_id,
            circuit_type: ProvingJobCircuitType::Secp256K1SignatureProof,
            sub_group_id: 3,
            task_index: deposit_id,
            data_type: ProvingJobDataType::BaseInputProof,
            data_index: 0,
        }
    }
    pub fn new_proof_job_id(
        goal_id: u64,
        slot_id: u64,
        group_id: u32,
        circuit_type: ProvingJobCircuitType,
        sub_group_id: u32,
        task_index: u32,
    ) -> Self {
        Self {
            topic: QJobTopic::GenerateStandardProof,
            goal_id,
            slot_id,
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
            slot_id: 0,
            circuit_type,
            group_id,
            sub_group_id,
            task_index,
            data_type: ProvingJobDataType::InputWitness,
            data_index: 0,
        }
    }
    pub fn get_block_aggregate_jobs_group(checkpoint_id: u64, slot_id: u64, group_id: u32, task_index: u32) -> Self {
        Self {
            topic: QJobTopic::AggregateJobs,
            goal_id: checkpoint_id,
            slot_id,
            group_id,
            circuit_type: ProvingJobCircuitType::Unknown,
            sub_group_id: 0,
            task_index,
            data_type: ProvingJobDataType::InputWitness,
            data_index: 0,
        }
    }
    pub fn block_agg_state_part_1_input_witness(checkpoint_id: u64, slot_id: u64, group_id: u32) -> Self {
        Self {
            topic: QJobTopic::GenerateStandardProof,
            goal_id: checkpoint_id,
            slot_id,
            group_id,
            circuit_type: ProvingJobCircuitType::AggUserRegisterDeployContractsGUTA,
            sub_group_id: 0,
            task_index: 0,
            data_type: ProvingJobDataType::InputWitness,
            data_index: 0,
        }
    }
    pub fn block_agg_state_part_2_input_witness(checkpoint_id: u64, slot_id: u64, group_id: u32) -> Self {
        Self {
            topic: QJobTopic::GenerateStandardProof,
            goal_id: checkpoint_id,
            slot_id,
            group_id,
            circuit_type: ProvingJobCircuitType::AggAddProcessWithdrawalAddDeposit,
            sub_group_id: 0,
            task_index: 0,
            data_type: ProvingJobDataType::InputWitness,
            data_index: 0,
        }
    }
    pub fn block_state_transition_input_witness(checkpoint_id: u64, slot_id: u64, group_id: u32) -> Self {
        Self {
            topic: QJobTopic::GenerateStandardProof,
            goal_id: checkpoint_id,
            slot_id,
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
            slot_id: 0,
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
            slot_id: 0,
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
            slot_id: 0,
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
            ProvingJobCircuitType::AddDeposit => ProvingJobCircuitType::AddDepositAggregate,
            ProvingJobCircuitType::AddDepositAggregate => ProvingJobCircuitType::AddDepositAggregate,
            ProvingJobCircuitType::ClaimDeposit => ProvingJobCircuitType::ClaimDepositAggregate,
            ProvingJobCircuitType::ClaimDepositAggregate => ProvingJobCircuitType::ClaimDepositAggregate,
            ProvingJobCircuitType::AddWithdrawal => ProvingJobCircuitType::AddWithdrawalAggregate,
            ProvingJobCircuitType::AddWithdrawalAggregate => ProvingJobCircuitType::AddWithdrawalAggregate,
            ProvingJobCircuitType::ProcessWithdrawal => ProvingJobCircuitType::ProcessWithdrawalAggregate,
            ProvingJobCircuitType::ProcessWithdrawalAggregate => ProvingJobCircuitType::ProcessWithdrawalAggregate,
            ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate => ProvingJobCircuitType::AppendUserRegistrationTreeAggregate,
            ProvingJobCircuitType::DummyAddDepositAggregate => ProvingJobCircuitType::AddDepositAggregate,
            ProvingJobCircuitType::DummyClaimDepositAggregate => ProvingJobCircuitType::ClaimDepositAggregate,
            ProvingJobCircuitType::DummyAddWithdrawalAggregate => ProvingJobCircuitType::AddWithdrawalAggregate,
            ProvingJobCircuitType::DummyProcessWithdrawalAggregate => ProvingJobCircuitType::ProcessWithdrawalAggregate,
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
    pub fn to_fixed_bytes(&self) -> QProvingJobDataIDSerialized {
        self.into()
    }
    pub fn with_task_index(&self, task_index: u32) -> Self {
        Self { task_index, ..*self }
    }
    pub fn to_hex_string(&self) -> String {
        hex::encode(&self.to_fixed_bytes())
    }
}

// impl HistoryQueueMetadataTagged for QProvingJobDataID {
//     fn get_hq_metadata(&self) -> HistoryQueueMetadata {
//         HistoryQueueMetadata {
//             channel_id: REALM_PROCESSOR_TO_EDGE_CHANNEL,
//             checkpoint_id: self.goal_id,
//             item_id: self.task_index as u64, // Use task_index as item_id
//         }
//     }
// }

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct QProvingJobDataIDWithRewardPath {
    pub job_data_id: QProvingJobDataID,
    pub reward_path_info: u64,
}

impl QProvingJobDataIDWithRewardPath {
    pub fn new(job_data_id: QProvingJobDataID, reward_path_info: u64) -> Self {
        Self {
            job_data_id,
            reward_path_info,
        }
    }
}

impl Default for QProvingJobDataIDWithRewardPath {
    fn default() -> Self {
        let default_job_id = QProvingJobDataID::new(
            QJobTopic::GenerateStandardProof,
            0,
            0,
            0,
            0,
            0,
            ProvingJobCircuitType::AppendUserRegistrationTree,
            ProvingJobDataType::InputWitness,
            0,
        );
        Self::new(default_job_id, 0)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Eq, Hash)]
pub struct QClaimRewardJobs {
    pub realm_jobs: Vec<QProvingJobDataIDWithRewardPreimage>,
    pub coordinator_jobs: Vec<QProvingJobDataIDWithRewardPreimage>,
}

impl QClaimRewardJobs {
    pub fn new(realm_jobs: Vec<QProvingJobDataIDWithRewardPreimage>, coordinator_jobs: Vec<QProvingJobDataIDWithRewardPreimage>) -> Self {
        Self {
            realm_jobs,
            coordinator_jobs,
        }
    }

    pub fn new_empty() -> Self {
        Self::new(vec![], vec![])
    }

    pub fn jobs_len(&self) -> usize {
        self.realm_jobs.len() + self.coordinator_jobs.len()
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Eq, Hash)]
pub struct QProvingJobDataIDWithRewardPreimage {
    pub inner: QProvingJobDataIDWithRewardPath,
    pub reward_tree_tag_preimage: QHashOut<GoldilocksField>,
}

impl QProvingJobDataIDWithRewardPreimage {
    pub fn new(job_id: QProvingJobDataID, reward_path_info: u64, reward_tree_tag_preimage: QHashOut<GoldilocksField>) -> Self {
        Self {
            inner: QProvingJobDataIDWithRewardPath::new(job_id, reward_path_info),
            reward_tree_tag_preimage,
        }
    }
}

impl KVQSerializable for QProvingJobDataID {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.to_fixed_bytes().to_vec())
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        QProvingJobDataID::try_from_byte_vec(bytes)
    }
}
