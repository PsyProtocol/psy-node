use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use strum_macros::{Display, FromRepr};

use crate::{data::{hash::merkle_node_key::SimpleMerkleNodeKey, serializable::{QPDSerializable, QPDSerializableFixed}}, protocol::core_types::QJobIdBase};


#[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord, FromRepr, Display)]
#[repr(u8)]
pub enum QJobTopic {
    GenerateStandardProof = 0,
    Counter = 1,
    // more to be added later
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
       Self::from_repr(value).ok_or_else(|| anyhow::format_err!("Invalid QJobTopic value: {}", value))
    }
}

#[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord, Display, FromRepr)]
#[repr(u8)]
pub enum ProvingJobDataType {
    InputWitness = 0,
    InputProof = 1,
    OutputProof = 2,
}
impl ProvingJobDataType {
    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
}
impl From<ProvingJobDataType> for u8 {
    fn from(value: ProvingJobDataType) -> u8 {
        value as u8
    }
}

impl TryFrom<u8> for ProvingJobDataType {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::from_repr(value).ok_or_else(|| anyhow::format_err!("Invalid ProvingJobDataType value: {}", value))
    }
}

#[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord, Display, FromRepr)]
#[repr(u8)]
pub enum ProvingJobCircuitType {
    UserEndCap = 6, // a user end cap proof, proves a user leaf node has updated from its old value to its new value
    GUTATwoEndCap = 7, // verifies two user end cap proofs to a higher node in the user state tree
    GUTATwoGUTA = 8, // verifies two GUTA proofs to a higher node in the user state tree
    GUTALeftEndCapRightGUTA = 9, // verifes a left user end cap proof and a right GUTA proof to a higher node in the user state tree
    GUTALeftGUTARightEndCap = 10, // verfifes a left GUTA proof and a right user end cap proof to a higher node in the user state tree
    GUTASingleEndCap = 11,// verfifes a single user end cap proof to a higher node in the user state tree
    GUTAVerifyToNode = 12, // verfies a single GUTA proof to a higher node in the user state tree
    GUTAOnlyRegisterUsers = 14,
    GUTANoChange = 15,

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


impl From<ProvingJobCircuitType> for u8 {
    fn from(value: ProvingJobCircuitType) -> Self {
        value as u8
    }
}
impl TryFrom<u8> for ProvingJobCircuitType {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::from_repr(value).ok_or_else(|| anyhow::format_err!("Invalid ProvingJobCircuitType value: {}", value))
    }
}
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct QProvingJobDataID {
    pub topic: QJobTopic, // for now, this is always GenerateStandardProof
    pub goal_id: u64, // usually the checkpoint id, not necessarily the canonical checkpoint id, just one more than the last finalized checkpoint id
    pub circuit_type: ProvingJobCircuitType, // the type of proof circuit for this job, used to determine which zkp verifier data to use for recursion
    pub group_id: u32, // for end cap proofs it is unique the realm edge api id that intakes the user end cap proof, for guta proofs it is the realm id
    pub sub_group_id: u32, // usually the level in the tree for guta proofs, 
    pub task_index: u32, // for guta proofs it is the index of the proof in the global user tree casted to a u32 for now since we only have less than 4 billion users
    pub data_type: ProvingJobDataType, // the type of data stored, can be input witness, input proof, output proof
    pub data_index: u8, // make this 0 for now 
}
impl QProvingJobDataID {
    pub fn try_from_bytes(value: &[u8]) -> anyhow::Result<Self> {
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
    pub fn end_cap_proof(checkpoint_id: u64, group_id: u32, user_id: u32) -> Self {
        Self {
            topic: QJobTopic::GenerateStandardProof,
            goal_id: checkpoint_id,
            group_id,
            circuit_type: ProvingJobCircuitType::UserEndCap,
            sub_group_id: 1,
            task_index: user_id,
            data_type: ProvingJobDataType::InputProof,
            data_index: 0,
        }
    }
    pub fn get_input_proof_id(&self, data_index: u8) -> Self {
        Self {
            data_type: ProvingJobDataType::InputProof,
            data_index,
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
    pub fn to_fixed_bytes(&self) -> [u8; 24] {
        self.into()
    }
    pub fn with_task_index(&self, task_index: u32) -> Self {
        Self { task_index, ..*self }
    }
    pub fn to_hex_string(&self) -> String {
        hex::encode(&self.to_fixed_bytes())
    }
}


impl QPDSerializable for QProvingJobDataID {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.to_fixed_bytes().to_vec())
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        Self::try_from_bytes(bytes)
    }
}


impl QPDSerializableFixed for QProvingJobDataID {
    fn get_fixed_size() -> usize {
        24
    }
}

impl QJobIdBase for QProvingJobDataID {
    fn to_bytes_24(&self) -> [u8; 24] {
        self.to_fixed_bytes()
    }
    fn from_bytes_24(bytes: &[u8; 24]) -> anyhow::Result<Self> {
        Self::try_from(*bytes)
    }
    
    fn circuit_type_u32(&self) -> u32 {
        self.circuit_type.to_u8() as u32
    }
    
    fn input_witness_id(&self) -> Self {
        self.get_input_witness_id()
    }
    
    fn output_proof_id(&self) -> Self {
        self.get_output_id()
    }
    
    fn group_counter_id(&self) -> Self {
        todo!()
    }
    
    fn get_checkpoint_id(&self) -> u64 {
        self.goal_id
    }
    
    fn is_user_guta_proof_circuit_type(&self) -> bool {
        self.circuit_type == ProvingJobCircuitType::UserEndCap || self.circuit_type == ProvingJobCircuitType::GUTATwoEndCap || self.circuit_type == ProvingJobCircuitType::GUTATwoGUTA || self.circuit_type == ProvingJobCircuitType::GUTALeftEndCapRightGUTA || self.circuit_type == ProvingJobCircuitType::GUTALeftGUTARightEndCap || self.circuit_type == ProvingJobCircuitType::GUTASingleEndCap
    }
    
    fn is_end_cap_proof_circuit_type(&self) -> bool {
        self.circuit_type == ProvingJobCircuitType::UserEndCap
    }
    
    fn get_parth_merkle_node_key(&self) -> SimpleMerkleNodeKey {
        SimpleMerkleNodeKey { level: self.sub_group_id as u8, index: self.task_index as u64 }
    }
    
    fn get_parth_index(&self) -> u64 {
        self.task_index as u64
    }
    
    fn get_parth_level(&self) -> u8 {
        self.sub_group_id as u8
    }
}