use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct QSRCmdGetUserLeafData {
    pub checkpoint_id: u64,
    pub user_id: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct QSRCmdGetContractLeafData {
    pub contract_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct QSRCmdGetContractCodeDefinition {
    pub contract_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct QSRCmdGetCheckpointLeafData {
    pub checkpoint_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct QSRCmdGetBlockState {
    pub checkpoint_id: u64,
}

// start tree hash cmds

#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct QSRHashCmdGetUserContractStateTreeRoot {
    pub checkpoint_id: u64,
    pub user_id: u64,
    pub contract_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct QSRHashCmdGetUserContractStateTreeLeafHash {
    pub checkpoint_id: u64,
    pub user_id: u64,
    pub contract_id: u32,
    pub height: u8,
    pub leaf_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct QSRHashCmdGetUserContractTreeRoot {
    pub checkpoint_id: u64,
    pub user_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct QSRHashCmdGetUserContractTreeLeafHash {
    pub checkpoint_id: u64,
    pub user_id: u64,
    pub contract_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct QSRHashCmdGetUserTreeRoot {
    pub checkpoint_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct QSRHashCmdGetUserTreeLeafHash {
    pub checkpoint_id: u64,
    pub user_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct QSRHashCmdGetContractFunctionTreeRoot {
    pub checkpoint_id: u64,
    pub contract_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct QSRHashCmdGetContractFunctionTreeLeafHash {
    pub checkpoint_id: u64,
    pub contract_id: u32,
    pub function_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct QSRHashCmdGetContractTreeRoot {
    pub checkpoint_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct QSRHashCmdGetContractTreeLeafHash {
    pub checkpoint_id: u64,
    pub contract_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct QSRHashCmdGetUserRegistrationTreeRoot {
    pub checkpoint_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct QSRHashCmdGetUserRegistrationTreeLeafHash {
    pub checkpoint_id: u64,
    pub leaf_index: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct QSRHashCmdGetWithdrawalTreeRoot {
    pub checkpoint_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct QSRHashCmdGetCheckpointTreeRoot {
    pub checkpoint_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct QSRHashCmdGetCheckpointTreeLeafHash {
    pub checkpoint_id: u64,
    pub leaf_checkpoint_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum QSRHashCmd {
    GetUserContractStateTreeRoot(QSRHashCmdGetUserContractStateTreeRoot),
    GetUserContractStateTreeLeafHash(QSRHashCmdGetUserContractStateTreeLeafHash),
    GetUserContractTreeRoot(QSRHashCmdGetUserContractTreeRoot),
    GetUserContractTreeLeafHash(QSRHashCmdGetUserContractTreeLeafHash),
    GetUserTreeRoot(QSRHashCmdGetUserTreeRoot),
    GetUserTreeLeafHash(QSRHashCmdGetUserTreeLeafHash),
    GetContractFunctionTreeRoot(QSRHashCmdGetContractFunctionTreeRoot),
    GetContractFunctionTreeLeafHash(QSRHashCmdGetContractFunctionTreeLeafHash),
    GetContractTreeRoot(QSRHashCmdGetContractTreeRoot),
    GetContractTreeLeafHash(QSRHashCmdGetContractTreeLeafHash),
    GetWithdrawalTreeRoot(QSRHashCmdGetWithdrawalTreeRoot),
    GetCheckpointTreeRoot(QSRHashCmdGetCheckpointTreeRoot),
    GetCheckpointTreeLeafHash(QSRHashCmdGetCheckpointTreeLeafHash),
    GetUserRegistrationTreeRoot(QSRHashCmdGetUserRegistrationTreeRoot),
    GetUserRegistrationTreeLeafHash(QSRHashCmdGetUserRegistrationTreeLeafHash),
}
// end tree hash cmds
impl QSRHashCmd {
    pub fn user_id(&self) -> Option<u64> {
        match self {
            QSRHashCmd::GetUserContractStateTreeRoot(c) => Some(c.user_id),
            QSRHashCmd::GetUserContractStateTreeLeafHash(c) => Some(c.user_id),
            QSRHashCmd::GetUserContractTreeRoot(c) => Some(c.user_id),
            QSRHashCmd::GetUserContractTreeLeafHash(c) => Some(c.user_id),
            QSRHashCmd::GetUserTreeLeafHash(c) => Some(c.user_id),
            _ => None,
        }
    }

    pub fn is_realm_cmd(&self) -> bool {
        match self {
            QSRHashCmd::GetUserContractStateTreeRoot(_)
            | QSRHashCmd::GetUserContractStateTreeLeafHash(_)
            | QSRHashCmd::GetUserContractTreeRoot(_)
            | QSRHashCmd::GetUserContractTreeLeafHash(_)
            | QSRHashCmd::GetUserTreeRoot(_)
            | QSRHashCmd::GetUserTreeLeafHash(_) => true,
            QSRHashCmd::GetContractFunctionTreeRoot(_)
            | QSRHashCmd::GetContractFunctionTreeLeafHash(_)
            | QSRHashCmd::GetContractTreeRoot(_)
            | QSRHashCmd::GetContractTreeLeafHash(_)
            | QSRHashCmd::GetWithdrawalTreeRoot(_)
            | QSRHashCmd::GetCheckpointTreeRoot(_)
            | QSRHashCmd::GetCheckpointTreeLeafHash(_)
            | QSRHashCmd::GetUserRegistrationTreeRoot(_)
            | QSRHashCmd::GetUserRegistrationTreeLeafHash(_) => false,
        }
    }
}

// start tree merkle proof cmds

#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct QSRMerkleCmdGetUserContractStateTreeMerkleProof {
    pub checkpoint_id: u64,
    pub user_id: u64,
    pub contract_id: u32,
    pub height: u8,
    pub leaf_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct QSRMerkleCmdGetUserContractTreeMerkleProof {
    pub checkpoint_id: u64,
    pub user_id: u64,
    pub contract_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct QSRMerkleCmdGetUserTreeMerkleProof {
    pub checkpoint_id: u64,
    pub user_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct QSRMerkleCmdGetContractFunctionTreeMerkleProof {
    pub checkpoint_id: u64,
    pub contract_id: u32,
    pub function_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct QSRMerkleCmdGetContractTreeMerkleProof {
    pub checkpoint_id: u64,
    pub contract_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct QSRMerkleCmdGetUserRegistrationTreeMerkleProof {
    pub checkpoint_id: u64,
    pub leaf_index: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct QSRMerkleCmdGetCheckpointTreeMerkleProof {
    pub checkpoint_id: u64,
    pub leaf_checkpoint_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum QSRMerkleCmd {
    GetUserContractStateTreeMerkleProof(QSRMerkleCmdGetUserContractStateTreeMerkleProof),
    GetUserContractTreeMerkleProof(QSRMerkleCmdGetUserContractTreeMerkleProof),
    GetUserTreeMerkleProof(QSRMerkleCmdGetUserTreeMerkleProof),
    GetContractFunctionTreeMerkleProof(QSRMerkleCmdGetContractFunctionTreeMerkleProof),
    GetContractTreeMerkleProof(QSRMerkleCmdGetContractTreeMerkleProof),
    GetCheckpointTreeMerkleProof(QSRMerkleCmdGetCheckpointTreeMerkleProof),
    GetUserRegistrationTreeMerkleProof(QSRMerkleCmdGetUserRegistrationTreeMerkleProof),
}
// end tree merkle proof cmds

impl QSRMerkleCmd {
    pub fn user_id(&self) -> Option<u64> {
        match self {
            QSRMerkleCmd::GetUserContractStateTreeMerkleProof(c) => Some(c.user_id),
            QSRMerkleCmd::GetUserContractTreeMerkleProof(c) => Some(c.user_id),
            QSRMerkleCmd::GetUserTreeMerkleProof(c) => Some(c.user_id),
            QSRMerkleCmd::GetContractFunctionTreeMerkleProof(_c) => None,
            QSRMerkleCmd::GetContractTreeMerkleProof(_c) => None,

            QSRMerkleCmd::GetCheckpointTreeMerkleProof(_c) => None,
            QSRMerkleCmd::GetUserRegistrationTreeMerkleProof(_c) => None,
        }
    }
    pub fn is_realm_cmd(&self) -> bool {
        match self {
            QSRMerkleCmd::GetUserContractStateTreeMerkleProof(_) => true,
            QSRMerkleCmd::GetUserContractTreeMerkleProof(_) => true,
            QSRMerkleCmd::GetUserTreeMerkleProof(_) => true,
            QSRMerkleCmd::GetContractFunctionTreeMerkleProof(_) => false,
            QSRMerkleCmd::GetContractTreeMerkleProof(_) => false,

            QSRMerkleCmd::GetCheckpointTreeMerkleProof(_) => false,
            QSRMerkleCmd::GetUserRegistrationTreeMerkleProof(_) => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct QSRIMTCmdGetLeafPreimage {
    pub checkpoint_id: u64,
    pub user_id: u64,
    pub contract_id: u32,
    pub leaf_index: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct QSRIMTCmdGetLeafIndexForKey {
    pub checkpoint_id: u64,
    pub user_id: u64,
    pub contract_id: u32,
    pub state_slot_base: u64,
    pub capacity: u64,
    pub key: [u64; 4],
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct QSRIMTCmdFindPredecessor {
    pub checkpoint_id: u64,
    pub user_id: u64,
    pub contract_id: u32,
    pub state_slot_base: u64,
    pub capacity: u64,
    pub key: [u64; 4],
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct QSRIMTCmdGetNextAppendIndex {
    pub user_id: u64,
    pub contract_id: u32,
    pub state_slot_base: u64,
    pub capacity: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum QSRIMTCmd {
    GetLeafPreimage(QSRIMTCmdGetLeafPreimage),
    GetLeafIndexForKey(QSRIMTCmdGetLeafIndexForKey),
    FindPredecessor(QSRIMTCmdFindPredecessor),
    GetNextAppendIndex(QSRIMTCmdGetNextAppendIndex),
}
