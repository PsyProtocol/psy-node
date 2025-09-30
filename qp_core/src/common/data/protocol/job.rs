use std::fmt;

use hex::FromHexError;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use serde_with::serde_as;

use crate::common::traits::serializable::QPDSerializable;

#[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum QJobTopic {
    CompressGzip = 0,
    ComputeCombinedRealmRootUpdateMerkleRoot = 1,
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
            0 => Ok(QJobTopic::CompressGzip),
            1 => Ok(QJobTopic::ComputeCombinedRealmRootUpdateMerkleRoot),
            _ => Err(anyhow::format_err!("Invalid QJobTopic value: {}", value)),
        }
    }
}

#[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum ProvingJobDataType {
    RawUserData = 0,
    CompressedUserData = 1,
    RealmRootHashes = 8,
    CombinedRealmRootUpdateMerkleRoot = 16,
    Counter = 32,
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
            0 => Ok(ProvingJobDataType::RawUserData),
            1 => Ok(ProvingJobDataType::CompressedUserData),
            8 => Ok(ProvingJobDataType::RealmRootHashes),
            16 => Ok(ProvingJobDataType::CombinedRealmRootUpdateMerkleRoot),
            32 => Ok(ProvingJobDataType::Counter),
            _ => Err(anyhow::format_err!("Invalid ProvingJobDataType value: {}", value)),
        }
    }
}
impl From<ProvingJobDataType> for u8 {
    fn from(value: ProvingJobDataType) -> u8 {
        value as u8
    }
}

#[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum ProvingJobCircuitType {
    KeepThisForNowIWillUseLaterWhenWeAddZKPs = 0,
    Unknown = 255,
}

impl ProvingJobCircuitType {
    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
    pub fn to_circuit_group_id(&self) -> u32 {
        (self.to_u8() as u32) + 0xCF00u32
    }
}

impl TryFrom<u8> for ProvingJobCircuitType {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ProvingJobCircuitType::KeepThisForNowIWillUseLaterWhenWeAddZKPs),
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

pub type QPWorkerJobDataIDSerialized = [u8; 24];

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Copy, Eq, Hash, Clone, Debug)]
pub struct QPWorkerJobDataIDSerializedWrapped(#[serde_as(as = "serde_with::hex::Hex")] pub QPWorkerJobDataIDSerialized);

impl QPWorkerJobDataIDSerializedWrapped {
    pub fn from_hex_string(s: &str) -> Result<Self, FromHexError> {
        let bytes = hex::decode(s)?;
        assert_eq!(bytes.len(), 24);
        let mut array = [0u8; 24];
        array.copy_from_slice(&bytes);
        Ok(Self(array))
    }
}


#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct QPWorkerJobDataID {
    pub topic: QJobTopic,
    pub goal_id: u64,
    pub circuit_type: ProvingJobCircuitType,
    pub group_id: u32,
    pub sub_group_id: u32,
    pub task_index: u32,
    pub data_type: ProvingJobDataType,
    pub data_index: u8,
}
impl QPWorkerJobDataID {
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
        Ok(QPWorkerJobDataID {
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

    pub fn to_key_string(&self) -> String {
        format!(
            "topic:{:02X}:goal:{:016X}:circuit:{:02X}:group:{:08X}:subgroup:{:08X}:task:{:08X}:dtype:{:02X}:didx:{:02X}",
            self.topic.to_u8(),
            self.goal_id,
            self.circuit_type.to_u8(),
            self.group_id,
            self.sub_group_id,
            self.task_index,
            self.data_type.to_u8(),
            self.data_index,
        )
    }
    pub fn from_key_string(s: &str) -> anyhow::Result<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 18 {
            anyhow::bail!("invalid key string: {}", s);
        }

        // Parts index correspondence:
        // 0="topic" 1=val 2="goal" 3=val 4="circuit" 5=val
        // 6="group" 7=val 8="subgroup" 9=val 10="task" 11=val
        // 12="dtype" 13=val 14="didx" 15=val
        // (Note that the length after split is 16, not 18; there is no extra ":")

        let topic: QJobTopic = u8::from_str_radix(parts[1], 16)?.try_into()?;
        let goal_id = u64::from_str_radix(parts[3], 16)?;
        let circuit_type = ProvingJobCircuitType::try_from(u8::from_str_radix(parts[5], 16)?)?;
        let group_id = u32::from_str_radix(parts[7], 16)?;
        let sub_group_id = u32::from_str_radix(parts[9], 16)?;
        let task_index = u32::from_str_radix(parts[11], 16)?;
        let data_type = ProvingJobDataType::try_from(u8::from_str_radix(parts[13], 16)?)?;
        let data_index = u8::from_str_radix(parts[15], 16)?;

        Ok(Self {
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


impl fmt::Display for QPWorkerJobDataID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
impl From<&QPWorkerJobDataID> for [u8; 24] {
    fn from(value: &QPWorkerJobDataID) -> Self {
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
impl TryFrom<[u8; 24]> for QPWorkerJobDataID {
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
        Ok(QPWorkerJobDataID {
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

impl QPWorkerJobDataID {
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
    pub fn compress_gzip_job_input(checkpoint_id: u64, group_id: u32, sub_group_id: u32, task_index: u32) -> Self {
        Self::new(
            QJobTopic::CompressGzip,
            checkpoint_id,
            group_id,
            sub_group_id,
            task_index,
            ProvingJobCircuitType::KeepThisForNowIWillUseLaterWhenWeAddZKPs,
            ProvingJobDataType::RawUserData,
            0,
        )
    }
    pub fn compute_combined_realm_root_update_merkle_root(checkpoint_id: u64, group_id: u32, sub_group_id: u32, task_index: u32) -> Self {
        Self::new(
            QJobTopic::ComputeCombinedRealmRootUpdateMerkleRoot,
            checkpoint_id,
            group_id,
            sub_group_id,
            task_index,
            ProvingJobCircuitType::KeepThisForNowIWillUseLaterWhenWeAddZKPs,
            ProvingJobDataType::CombinedRealmRootUpdateMerkleRoot,
            0,
        )
    }
    pub fn get_input_data(&self, data_index: u8) -> Self {
        Self {
            data_type: match self.topic {
                QJobTopic::CompressGzip => ProvingJobDataType::RawUserData,
                QJobTopic::ComputeCombinedRealmRootUpdateMerkleRoot => ProvingJobDataType::CombinedRealmRootUpdateMerkleRoot,
            },
            data_index,
            ..*self
        }
    }

    pub fn get_output_id(&self) -> Self {
        Self {
            data_type: match self.topic {
                QJobTopic::CompressGzip => ProvingJobDataType::CompressedUserData,
                QJobTopic::ComputeCombinedRealmRootUpdateMerkleRoot => ProvingJobDataType::CombinedRealmRootUpdateMerkleRoot,
            },
            data_index: 0,
            ..*self
        }
    }
    pub fn get_input_witness_id(&self) -> Self {
        Self {
            data_type: match self.topic {
                QJobTopic::CompressGzip => ProvingJobDataType::RealmRootHashes,
                QJobTopic::ComputeCombinedRealmRootUpdateMerkleRoot => ProvingJobDataType::RealmRootHashes,
            },
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
    pub fn to_fixed_bytes(&self) -> QPWorkerJobDataIDSerialized {
        self.into()
    }
    pub fn with_task_index(&self, task_index: u32) -> Self {
        Self { task_index, ..*self }
    }
    pub fn to_hex_string(&self) -> String {
        hex::encode(&self.to_fixed_bytes())
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct ProvingJobDataId {
    pub checkpoint_id: u64,
    pub job_id: QPWorkerJobDataID,
}

impl ProvingJobDataId {
    pub fn new(checkpoint_id: u64, job_id: QPWorkerJobDataID) -> Self {
        Self { checkpoint_id, job_id }
    }
}


impl QPDSerializable for QPWorkerJobDataID {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.to_fixed_bytes().to_vec())
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        QPWorkerJobDataID::try_from_byte_vec(bytes)
    }
}
