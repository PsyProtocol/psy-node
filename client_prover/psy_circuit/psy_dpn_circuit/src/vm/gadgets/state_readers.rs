use std::collections::HashMap;

use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{
        target::{BoolTarget, Target},
        witness::Witness,
    },
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_client_common::data::{base_types::hash256::Hash256, qhashout::QHashOut};
use psy_common_circuit::{
    builder::{
        comparison::CircuitBuilderComparison, connect::CircuitBuilderConnectHelpers, hash::core::CircuitBuilderHashCore,
        math::core::CircuitBuilderCoreMathHelpers, select::CircuitBuilderSelectHelpers,
    },
    hash::merkle::gadgets::{
        delta_merkle_proof::DeltaMerkleProofGadget,
        historical_root_merkle_proof::HistoricalRootMerkleProofGadget,
        imt_contract_state_update::{is_qhashout_lt, IMTLeafTargets},
        merkle_array_gen::enforce_merkle_array_values_2_bit,
        merkle_proof::MerkleProofGadget,
        sub_slot_delta_merkle_proof_batch::SubSlotDeltaMerkleProofBatchGadget,
        sub_slot_merkle_proof_batch::SubSlotMerkleProofBatchGadget,
        variable_height_merkle_proof::VariableHeightMerkleProofGadget,
    },
    traits::{CreatableTarget, ToTargets},
};
use psy_config::network_constants::{CHECKPOINT_TREE_HEIGHT, DEFERRED_TRANSACTION_TREE_HEIGHT, GLOBAL_CONTRACT_TREE_HEIGHT, GLOBAL_USER_TREE_HEIGHT};
use psy_crypto::hash::core::sha256;
use psy_crypto::hash::traits::hasher::MerkleZeroHasher;
use psy_network_circuit::gadgets::qdata::{
    checkpoint_state_roots::PsyCheckpointGlobalStateRootsGadget, checkpoint_stats::PsyCheckpointLeafStatsGadget, contract::PsyContractLeafGadget,
    contract_function_call::DPNProvingSessionSimpleMethodCallGadget, user::PsyUserLeafGadget,
};
use psy_vm::dpn::ops::state_cmd::data::DPNStateCmd;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::vm::ops::SimpleDPNBuilder;

#[derive(Clone, Debug)]
pub struct ClearEntireTreeGadget {
    pub state_tree_height: Target,
    pub zero_hash: HashOutTarget,
}

impl ClearEntireTreeGadget {
    pub fn create_virtual<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            state_tree_height: builder.add_virtual_target(),
            zero_hash: builder.add_virtual_hash(),
        }
    }

    pub fn set_witness<W: Witness<F>, F: RichField>(&self, witness: &mut W, state_tree_height: u64, zero_hash: QHashOut<F>) -> anyhow::Result<()> {
        witness.set_target(self.state_tree_height, F::from_canonical_u64(state_tree_height))?;
        witness.set_hash_target(self.zero_hash, zero_hash.into())?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct IMTSetGadget {
    pub is_insert: BoolTarget,
    pub insert_has_predecessor: BoolTarget,
    pub update_old_leaf: IMTLeafTargets,
    pub update_new_leaf: IMTLeafTargets,
    pub update_delta_proof: DeltaMerkleProofGadget,
    pub insert_predecessor_old_leaf: IMTLeafTargets,
    pub insert_predecessor_new_leaf: IMTLeafTargets,
    pub insert_new_leaf: IMTLeafTargets,
    pub insert_predecessor_delta_proof: DeltaMerkleProofGadget,
    pub insert_new_leaf_delta_proof: DeltaMerkleProofGadget,
}

#[derive(Clone, Debug)]
pub struct IMTReadGadget {
    pub merkle_proof: MerkleProofGadget,
    pub leaf: IMTLeafTargets,
}

#[derive(Clone, Debug)]
pub struct IMTExternalReadGadget {
    pub contract_tree_proof: MerkleProofGadget,
    pub state_slot_proof: VariableHeightMerkleProofGadget,
    pub leaf: IMTLeafTargets,
}

#[derive(Clone, Debug)]
pub struct IMTOtherUserReadGadget {
    pub state_slot_proof: VariableHeightMerkleProofGadget,
    pub leaf: IMTLeafTargets,
}

#[derive(Clone, Debug)]
pub struct IMTContainsOtherUserGadget {
    pub state_slot_proof: VariableHeightMerkleProofGadget,
    pub leaf: IMTLeafTargets,
    pub exists: Target,
}

#[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum StateReaderReferenceKeyType {
    MerkleProof = 0,
    DeltaMerkleProof = 1,
    UserLeaf = 2,
    CheckpointStats = 3,
    CheckpointStateRoots = 4,
    HistoricalProof = 5,
    ClearEntireTree = 6,
    ContractLeaf = 7,
    IMTContains = 8,
    IMTSet = 9,
    IMTRead = 10,
    IMTExternalRead = 11,
    IMTOtherUserRead = 12,
    IMTContainsOtherUser = 13,
    VariableHeightMerkleProof = 14,
}
impl StateReaderReferenceKeyType {
    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
}
impl From<StateReaderReferenceKeyType> for u8 {
    fn from(value: StateReaderReferenceKeyType) -> u8 {
        value as u8
    }
}
impl TryFrom<u8> for StateReaderReferenceKeyType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(StateReaderReferenceKeyType::MerkleProof),
            1 => Ok(StateReaderReferenceKeyType::DeltaMerkleProof),
            2 => Ok(StateReaderReferenceKeyType::UserLeaf),
            3 => Ok(StateReaderReferenceKeyType::CheckpointStats),
            4 => Ok(StateReaderReferenceKeyType::CheckpointStateRoots),
            5 => Ok(StateReaderReferenceKeyType::HistoricalProof),
            6 => Ok(StateReaderReferenceKeyType::ClearEntireTree),
            7 => Ok(StateReaderReferenceKeyType::ContractLeaf),
            8 => Ok(StateReaderReferenceKeyType::IMTContains),
            9 => Ok(StateReaderReferenceKeyType::IMTSet),
            10 => Ok(StateReaderReferenceKeyType::IMTRead),
            11 => Ok(StateReaderReferenceKeyType::IMTExternalRead),
            12 => Ok(StateReaderReferenceKeyType::IMTOtherUserRead),
            13 => Ok(StateReaderReferenceKeyType::IMTContainsOtherUser),
            14 => Ok(StateReaderReferenceKeyType::VariableHeightMerkleProof),
            _ => Err(anyhow::format_err!("Invalid StateReaderReferenceKeyType value: {}", value)),
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct StateReaderReferenceKey {
    pub gadget_type: StateReaderReferenceKeyType,
    pub gadget_index: usize,
}
impl StateReaderReferenceKey {
    pub fn new_merkle_proof_key(index: usize) -> Self {
        Self {
            gadget_type: StateReaderReferenceKeyType::MerkleProof,
            gadget_index: index,
        }
    }
    pub fn new_delta_merkle_proof_key(index: usize) -> Self {
        Self {
            gadget_type: StateReaderReferenceKeyType::DeltaMerkleProof,
            gadget_index: index,
        }
    }
    pub fn new_variable_height_merkle_proof_key(index: usize) -> Self {
        Self {
            gadget_type: StateReaderReferenceKeyType::VariableHeightMerkleProof,
            gadget_index: index,
        }
    }
    pub fn new_user_leaf_key(index: usize) -> Self {
        Self {
            gadget_type: StateReaderReferenceKeyType::UserLeaf,
            gadget_index: index,
        }
    }
    pub fn new_checkpoint_stats_key(index: usize) -> Self {
        Self {
            gadget_type: StateReaderReferenceKeyType::CheckpointStats,
            gadget_index: index,
        }
    }
    pub fn new_clear_entire_tree_key(index: usize) -> Self {
        Self {
            gadget_type: StateReaderReferenceKeyType::ClearEntireTree,
            gadget_index: index,
        }
    }
    pub fn new_contract_leaf_key(index: usize) -> Self {
        Self {
            gadget_type: StateReaderReferenceKeyType::ContractLeaf,
            gadget_index: index,
        }
    }
    pub fn new_imt_contains_key(index: usize) -> Self {
        Self {
            gadget_type: StateReaderReferenceKeyType::IMTContains,
            gadget_index: index,
        }
    }
    pub fn new_imt_set_key(index: usize) -> Self {
        Self {
            gadget_type: StateReaderReferenceKeyType::IMTSet,
            gadget_index: index,
        }
    }
    pub fn new_imt_read_key(index: usize) -> Self {
        Self {
            gadget_type: StateReaderReferenceKeyType::IMTRead,
            gadget_index: index,
        }
    }
    pub fn new_imt_external_read_key(index: usize) -> Self {
        Self {
            gadget_type: StateReaderReferenceKeyType::IMTExternalRead,
            gadget_index: index,
        }
    }
    pub fn new_imt_other_user_read_key(index: usize) -> Self {
        Self {
            gadget_type: StateReaderReferenceKeyType::IMTOtherUserRead,
            gadget_index: index,
        }
    }
    pub fn new_imt_contains_other_user_key(index: usize) -> Self {
        Self {
            gadget_type: StateReaderReferenceKeyType::IMTContainsOtherUser,
            gadget_index: index,
        }
    }
    pub fn to_u64(&self) -> u64 {
        ((self.gadget_type.to_u8() as u64) << 56u64) | (self.gadget_index as u64)
    }
}
impl From<StateReaderReferenceKey> for u64 {
    fn from(value: StateReaderReferenceKey) -> u64 {
        value.to_u64()
    }
}
impl TryFrom<u64> for StateReaderReferenceKey {
    type Error = anyhow::Error;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        let gadget_type = StateReaderReferenceKeyType::try_from((value >> 56u64) as u8)?;
        let gadget_index = (value & 0x00ffffffffffffffu64) as usize;

        Ok(Self { gadget_type, gadget_index })
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct CKInvokeDeferredMethodCall {
    pub condition_target_id: u64,
    pub contract_target_id: u64,
    pub method_target_id: u64,
    pub deferred_tx_counter: u32,
    pub input_target_ids_hash: Hash256,
}
impl CKInvokeDeferredMethodCall {
    pub fn new(condition_target_id: u64, contract_target_id: u64, method_target_id: u64, deferred_tx_counter: u32, input_target_ids: &[u64]) -> Self {
        Self {
            condition_target_id,
            contract_target_id,
            method_target_id,
            deferred_tx_counter,
            input_target_ids_hash: sha256::CoreSha256Hasher::hash_u64s(input_target_ids),
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct CKReadCurrentContractSlot {
    pub slot_target_id: u64,
    pub write_epoch: u32,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct CKReadCurrentContractSingle {
    pub sub_slot_target_id: u64,
    pub write_epoch: u32,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct CKReadCurrentContractRange {
    pub sub_slot_target_id: u64,
    pub length: u32,
    pub slot_offset_index: u64,
    pub write_epoch: u32,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct CKWriteCurrentContractSlot {
    pub slot_target_id: u64,
    pub condition_target_id: u64,
    pub write_epoch: u32,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct CKWriteCurrentContractSingle {
    pub sub_slot_target_id: u64,
    pub condition_target_id: u64,
    pub write_epoch: u32,
}
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct CKWriteCurrentContractRange {
    pub sub_slot_target_id: u64,
    pub condition_target_id: u64,
    pub length: u32,
    pub slot_offset_index: u64,
    pub write_epoch: u32,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct CKReadSelfUserExternalContractRoot {
    pub contract_target_id: u64,
    pub contract_call_epoch: u32,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct CKReadSelfUserExternalContractSlot {
    pub contract_target_id: u64,
    pub slot_target_id: u64,
    pub contract_call_epoch: u32,
}
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct CKReadSelfUserExternalContractSingle {
    pub contract_target_id: u64,
    pub sub_slot_target_id: u64,
    pub contract_call_epoch: u32,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct CKReadSelfUserExternalContractRange {
    pub contract_target_id: u64,
    pub sub_slot_target_id: u64,
    pub length: u32,
    pub contract_call_epoch: u32,
    pub slot_offset_index: u64,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct CKReadOtherUserLeafHash {
    pub user_target_id: u64,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct CKReadOtherUserLeaf {
    pub user_target_id: u64,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct CKReadOtherUserContractContractRoot {
    pub user_target_id: u64,
    pub contract_target_id: u64,
}
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct CKReadOtherUserContractContractSlot {
    pub user_target_id: u64,
    pub contract_target_id: u64,
    pub slot_target_id: u64,
}
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct CKReadOtherUserContractContractRange {
    pub user_target_id: u64,
    pub contract_target_id: u64,
    pub sub_slot_target_id: u64,
    pub length: u32,
    pub slot_offset_index: u64,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct CKReadOtherUserContractContractSingle {
    pub user_target_id: u64,
    pub contract_target_id: u64,
    pub sub_slot_target_id: u64,
    pub write_epoch: u32,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct CKGetContractLeaf {
    pub contract_target_id: u64,
}

// IMT cache key structs

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct CKWriteIMTCurrentContract {
    pub condition_target_id: u64,
    pub proof_index: u64,
    pub write_epoch: u32,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct CKReadIMTCurrentContract {
    pub key_targets: [u64; 4],
    pub base_offset: u64,
    pub capacity: u64,
    pub write_epoch: u32,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct CKReadIMTContainsCurrentContract {
    pub key_targets: [u64; 4],
    pub base_offset: u64,
    pub capacity: u64,
    pub write_epoch: u32,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct CKReadIMTSelfUserExternalContract {
    pub contract_target_id: u64,
    pub key_targets: [u64; 4],
    pub contract_state_tree_height: u64,
    pub base_offset: u64,
    pub capacity: u64,
    pub contract_call_epoch: u32,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct CKReadIMTOtherUserContract {
    pub user_target_id: u64,
    pub contract_target_id: u64,
    pub key_targets: [u64; 4],
    pub contract_state_tree_height: u64,
    pub base_offset: u64,
    pub capacity: u64,
    pub write_epoch: u32,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct CKReadIMTContainsOtherUserContract {
    pub user_target_id: u64,
    pub contract_target_id: u64,
    pub key_targets: [u64; 4],
    pub contract_state_tree_height: u64,
    pub base_offset: u64,
    pub capacity: u64,
    pub write_epoch: u32,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub enum StateCommandCacheKey {
    InvokeDeferredMethodCall(CKInvokeDeferredMethodCall),
    ReadCurrentContractSlot(CKReadCurrentContractSlot),
    ReadCurrentContractSingle(CKReadCurrentContractSingle),
    ReadCurrentContractRange(CKReadCurrentContractRange),
    WriteCurrentContractSlot(CKWriteCurrentContractSlot),
    WriteCurrentContractSingle(CKWriteCurrentContractSingle),
    WriteCurrentContractRange(CKWriteCurrentContractRange),
    ReadSelfUserExternalContractRoot(CKReadSelfUserExternalContractRoot),
    ReadSelfUserExternalContractSlot(CKReadSelfUserExternalContractSlot),
    ReadSelfUserExternalContractSingle(CKReadSelfUserExternalContractSingle),
    ReadSelfUserExternalContractRange(CKReadSelfUserExternalContractRange),
    ReadOtherUserLeafHash(CKReadOtherUserLeafHash),
    ReadOtherUserLeaf(CKReadOtherUserLeaf),
    ReadOtherUserContractContractRoot(CKReadOtherUserContractContractRoot),
    ReadOtherUserContractContractSlot(CKReadOtherUserContractContractSlot),
    ReadOtherUserContractContractRange(CKReadOtherUserContractContractRange),
    ReadOtherUserContractContractSingle(CKReadOtherUserContractContractSingle),
    GetCheckpointStats(CKGetCheckpointStats),
    ClearEntireTree(CKClearEntireTree),
    GetContractLeaf(CKGetContractLeaf),

    // IMT cache keys
    WriteIMTCurrentContract(CKWriteIMTCurrentContract),
    ReadIMTCurrentContract(CKReadIMTCurrentContract),
    ReadIMTContainsCurrentContract(CKReadIMTContainsCurrentContract),
    ReadIMTSelfUserExternalContract(CKReadIMTSelfUserExternalContract),
    ReadIMTOtherUserContract(CKReadIMTOtherUserContract),
    ReadIMTContainsOtherUserContract(CKReadIMTContainsOtherUserContract),
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct CKGetCheckpointStats {
    pub checkpoint_id: u64,
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct CKClearEntireTree {
    pub condition: u64,
    pub write_epoch: u32,
}
impl StateCommandCacheKey {
    pub fn new_read_current_contract_slot(slot_target_id: u64, write_epoch: u32) -> Self {
        Self::ReadCurrentContractSlot(CKReadCurrentContractSlot { slot_target_id, write_epoch })
    }
    pub fn new_read_current_contract_single(sub_slot_target_id: u64, write_epoch: u32) -> Self {
        Self::ReadCurrentContractSingle(CKReadCurrentContractSingle {
            sub_slot_target_id,
            write_epoch,
        })
    }
    pub fn new_read_current_contract_range(sub_slot_target_id: u64, length: u32, slot_offset_index: u64, write_epoch: u32) -> Self {
        Self::ReadCurrentContractRange(CKReadCurrentContractRange {
            sub_slot_target_id,
            length,
            slot_offset_index,
            write_epoch,
        })
    }
    pub fn new_write_current_contract_slot(slot_target_id: u64, condition_target_id: u64, write_epoch: u32) -> Self {
        Self::WriteCurrentContractSlot(CKWriteCurrentContractSlot {
            slot_target_id,
            condition_target_id,
            write_epoch,
        })
    }
    pub fn new_write_current_contract_single(sub_slot_target_id: u64, condition_target_id: u64, write_epoch: u32) -> Self {
        Self::WriteCurrentContractSingle(CKWriteCurrentContractSingle {
            sub_slot_target_id,
            condition_target_id,
            write_epoch,
        })
    }
    pub fn new_write_current_contract_range(
        sub_slot_target_id: u64,
        condition_target_id: u64,
        length: u32,
        slot_offset_index: u64,
        write_epoch: u32,
    ) -> Self {
        Self::WriteCurrentContractRange(CKWriteCurrentContractRange {
            sub_slot_target_id,
            condition_target_id,
            length,
            slot_offset_index,
            write_epoch,
        })
    }
    pub fn new_read_self_user_external_contract_root(contract_target_id: u64, contract_call_epoch: u32) -> Self {
        Self::ReadSelfUserExternalContractRoot(CKReadSelfUserExternalContractRoot {
            contract_target_id,
            contract_call_epoch,
        })
    }
    pub fn new_read_self_user_external_contract_slot(contract_target_id: u64, slot_target_id: u64, contract_call_epoch: u32) -> Self {
        Self::ReadSelfUserExternalContractSlot(CKReadSelfUserExternalContractSlot {
            contract_target_id,
            slot_target_id,
            contract_call_epoch,
        })
    }
    pub fn new_read_self_user_external_contract_single(contract_target_id: u64, sub_slot_target_id: u64, contract_call_epoch: u32) -> Self {
        Self::ReadSelfUserExternalContractSingle(CKReadSelfUserExternalContractSingle {
            contract_target_id,
            sub_slot_target_id,
            contract_call_epoch,
        })
    }
    pub fn new_read_self_user_external_contract_range(
        contract_target_id: u64,
        sub_slot_target_id: u64,
        contract_call_epoch: u32,
        length: u32,
        slot_offset_index: u64,
    ) -> Self {
        Self::ReadSelfUserExternalContractRange(CKReadSelfUserExternalContractRange {
            contract_target_id,
            sub_slot_target_id,
            contract_call_epoch,
            length,
            slot_offset_index,
        })
    }
    pub fn new_read_other_user_leaf_hash(user_target_id: u64) -> Self {
        Self::ReadOtherUserLeafHash(CKReadOtherUserLeafHash { user_target_id })
    }
    pub fn new_read_other_user_leaf(user_target_id: u64) -> Self {
        Self::ReadOtherUserLeaf(CKReadOtherUserLeaf { user_target_id })
    }
    pub fn new_read_other_user_contract_root(user_target_id: u64, contract_target_id: u64) -> Self {
        Self::ReadOtherUserContractContractRoot(CKReadOtherUserContractContractRoot {
            user_target_id,
            contract_target_id,
        })
    }
    pub fn new_read_other_user_contract_slot(user_target_id: u64, contract_target_id: u64, slot_target_id: u64) -> Self {
        Self::ReadOtherUserContractContractSlot(CKReadOtherUserContractContractSlot {
            user_target_id,
            contract_target_id,
            slot_target_id,
        })
    }
    pub fn new_read_other_user_contract_range(
        user_target_id: u64,
        contract_target_id: u64,
        sub_slot_target_id: u64,
        length: u32,
        slot_offset_index: u64,
    ) -> Self {
        Self::ReadOtherUserContractContractRange(CKReadOtherUserContractContractRange {
            user_target_id,
            contract_target_id,
            sub_slot_target_id,
            length,
            slot_offset_index,
        })
    }
    pub fn new_read_other_user_contract_single(user_id: u64, contract_id: u64, sub_slot_target_id: u64, write_epoch: u32) -> Self {
        Self::ReadOtherUserContractContractSingle(CKReadOtherUserContractContractSingle {
            user_target_id: user_id,
            contract_target_id: contract_id,
            sub_slot_target_id,
            write_epoch,
        })
    }
    pub fn new_get_checkpoint_stats(checkpoint_id: u64) -> Self {
        Self::GetCheckpointStats(CKGetCheckpointStats { checkpoint_id })
    }
    pub fn new_clear_entire_tree_with_condition(condition: u64, write_epoch: u32) -> Self {
        Self::ClearEntireTree(CKClearEntireTree { condition, write_epoch })
    }
    pub fn new_get_contract_leaf(contract_target_id: u64) -> Self {
        Self::GetContractLeaf(CKGetContractLeaf { contract_target_id })
    }

    // IMT cache key constructors
    pub fn new_write_imt_current_contract(condition_target_id: u64, proof_index: u64, write_epoch: u32) -> Self {
        Self::WriteIMTCurrentContract(CKWriteIMTCurrentContract {
            condition_target_id,
            proof_index,
            write_epoch,
        })
    }
    pub fn new_read_imt_current_contract(key_targets: [u64; 4], base_offset: u64, capacity: u64, write_epoch: u32) -> Self {
        Self::ReadIMTCurrentContract(CKReadIMTCurrentContract { key_targets, base_offset, capacity, write_epoch })
    }
    pub fn new_read_imt_contains_current_contract(key_targets: [u64; 4], base_offset: u64, capacity: u64, write_epoch: u32) -> Self {
        Self::ReadIMTContainsCurrentContract(CKReadIMTContainsCurrentContract { key_targets, base_offset, capacity, write_epoch })
    }
    pub fn new_read_imt_self_user_external_contract(contract_target_id: u64, key_targets: [u64; 4], contract_state_tree_height: u64, base_offset: u64, capacity: u64, contract_call_epoch: u32) -> Self {
        Self::ReadIMTSelfUserExternalContract(CKReadIMTSelfUserExternalContract {
            contract_target_id,
            key_targets,
            contract_state_tree_height,
            base_offset,
            capacity,
            contract_call_epoch,
        })
    }
    pub fn new_read_imt_other_user_contract(user_target_id: u64, contract_target_id: u64, key_targets: [u64; 4], contract_state_tree_height: u64, base_offset: u64, capacity: u64, write_epoch: u32) -> Self {
        Self::ReadIMTOtherUserContract(CKReadIMTOtherUserContract {
            user_target_id,
            contract_target_id,
            key_targets,
            contract_state_tree_height,
            base_offset,
            capacity,
            write_epoch,
        })
    }
    pub fn new_imt_contains_other_user_contract(user_target_id: u64, contract_target_id: u64, key_targets: [u64; 4], contract_state_tree_height: u64, base_offset: u64, capacity: u64, write_epoch: u32) -> Self {
        Self::ReadIMTContainsOtherUserContract(CKReadIMTContainsOtherUserContract {
            user_target_id,
            contract_target_id,
            key_targets,
            contract_state_tree_height,
            base_offset,
            capacity,
            write_epoch,
        })
    }
}

#[derive(Clone, Debug)]
pub struct StateReaderGadget {
    pub merkle_proofs: Vec<MerkleProofGadget>,
    pub variable_height_merkle_proofs: Vec<VariableHeightMerkleProofGadget>,
    pub delta_merkle_proofs: Vec<DeltaMerkleProofGadget>,
    pub user_leaves: Vec<PsyUserLeafGadget>,
    pub checkpoint_stats_requests: Vec<PsyCheckpointLeafStatsGadget>,
    pub checkpoint_state_roots_requests: Vec<PsyCheckpointGlobalStateRootsGadget>,
    pub historical_proofs: Vec<HistoricalRootMerkleProofGadget>,
    pub clear_entire_tree_requests: Vec<ClearEntireTreeGadget>,
    pub contract_leaf_requests: Vec<PsyContractLeafGadget>,
    pub contract_leaf_proofs: Vec<MerkleProofGadget>,
    pub imt_contains_proofs: Vec<MerkleProofGadget>,
    pub imt_contains_leaf_requests: Vec<IMTLeafTargets>,
    pub imt_contains_exists_targets: Vec<Target>,
    pub imt_set_requests: Vec<IMTSetGadget>,
    pub imt_read_requests: Vec<IMTReadGadget>,
    pub imt_external_read_requests: Vec<IMTExternalReadGadget>,
    pub imt_other_user_read_requests: Vec<IMTOtherUserReadGadget>,
    pub imt_contains_other_user_requests: Vec<IMTContainsOtherUserGadget>,
    pub start_contract_state_root: HashOutTarget,
    pub end_contract_state_root: HashOutTarget,
    pub current_contract_proof: Option<MerkleProofGadget>,
    pub user_contract_tree_state_root: HashOutTarget,
    pub chain_state_roots: PsyCheckpointGlobalStateRootsGadget,
    pub checkpoint_stats: PsyCheckpointLeafStatsGadget,
    pub checkpoint_tree_root: HashOutTarget,

    pub start_deferred_tx_tree_root: HashOutTarget,
    pub end_deferred_tx_tree_root: HashOutTarget,

    pub session_proof_tree_root: HashOutTarget,

    pub state_cmd_results: Vec<Vec<Target>>,

    pub gadget_map: HashMap<StateCommandCacheKey, StateReaderReferenceKey>,
    pub result_map: HashMap<StateCommandCacheKey, Vec<Target>>,

    pub contract_call_epoch: u32,
    pub deferred_tx_count: u32,
    pub write_epoch: u32,

    pub contract_state_tree_height: usize,
    pub session_proof_tree_height: usize,
    pub force_four_align: bool,
}

impl StateReaderGadget {
    /// Pins a leaf index to one IMT map's slot range; also guards write indices,
    /// so the name covers more than reads.
    fn constrain_imt_read_index<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>, index: Target, base_offset: Target, capacity: Target) {
        builder.range_check(index, 32);
        builder.range_check(base_offset, 34);
        builder.range_check(capacity, 32);
        let offset = builder.mul_const(F::from_canonical_u64(4), index);
        let capacity_offset = builder.mul_const(F::from_canonical_u64(4), capacity);
        let last_offset = builder.add(base_offset, capacity_offset);
        let above_base = builder.is_less_than_or_equal(36, base_offset, offset);
        let below_end = builder.is_less_than_or_equal(36, offset, last_offset);
        let in_range = builder.and(above_base, below_end);
        builder.assert_one(in_range.target);
    }

    pub fn new(
        chain_state_roots: PsyCheckpointGlobalStateRootsGadget,
        user_contract_tree_state_root: HashOutTarget,
        deferred_tx_tree_root: HashOutTarget,
        contract_state_root: HashOutTarget,
        contract_state_tree_height: usize,
        session_proof_tree_root: HashOutTarget,
        session_proof_tree_height: usize,
        force_four_align: bool,
        checkpoint_stats: PsyCheckpointLeafStatsGadget,
        checkpoint_tree_root: HashOutTarget,
    ) -> Self {
        Self {
            merkle_proofs: vec![],
            variable_height_merkle_proofs: vec![],
            delta_merkle_proofs: vec![],
            user_leaves: vec![],
            checkpoint_stats_requests: vec![],
            checkpoint_state_roots_requests: vec![],
            historical_proofs: vec![],
            clear_entire_tree_requests: vec![],
            contract_leaf_requests: vec![],
            contract_leaf_proofs: vec![],
            imt_contains_proofs: vec![],
            imt_contains_leaf_requests: vec![],
            imt_contains_exists_targets: vec![],
            imt_set_requests: vec![],
            imt_read_requests: vec![],
            imt_external_read_requests: vec![],
            imt_other_user_read_requests: vec![],
            imt_contains_other_user_requests: vec![],
            start_deferred_tx_tree_root: deferred_tx_tree_root,
            end_deferred_tx_tree_root: deferred_tx_tree_root,
            start_contract_state_root: contract_state_root,
            end_contract_state_root: contract_state_root,
            current_contract_proof: None,
            chain_state_roots,
            checkpoint_stats,
            checkpoint_tree_root,
            state_cmd_results: vec![],
            gadget_map: HashMap::new(),
            result_map: HashMap::new(),
            contract_call_epoch: 0,
            write_epoch: 0,
            contract_state_tree_height,
            user_contract_tree_state_root,
            deferred_tx_count: 0,

            session_proof_tree_root,
            session_proof_tree_height,
            force_four_align,
        }
    }

    // resolvers

    pub fn resolve_merkle_proof_gadget(&self, key: &StateCommandCacheKey) -> Option<&MerkleProofGadget> {
        if self.gadget_map.contains_key(key) {
            let value = self.gadget_map[key];
            if value.gadget_type == StateReaderReferenceKeyType::MerkleProof {
                return Some(&self.merkle_proofs[value.gadget_index]);
            }
        }
        None
    }
    pub fn insert_merkle_proof_gadget(&mut self, key: StateCommandCacheKey, gadget: MerkleProofGadget) -> StateReaderReferenceKey {
        let ref_key = StateReaderReferenceKey::new_merkle_proof_key(self.merkle_proofs.len());
        self.merkle_proofs.push(gadget);
        self.gadget_map.insert(key, ref_key);
        ref_key
    }

    pub fn resolve_or_insert_merkle_proof_gadget<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        key: StateCommandCacheKey,
        height: usize,
    ) -> (bool, &MerkleProofGadget) {
        if self.gadget_map.contains_key(&key) {
            let value = self.gadget_map[&key];
            if value.gadget_type == StateReaderReferenceKeyType::MerkleProof {
                return (false, &self.merkle_proofs[value.gadget_index]);
            }
        }
        let g = MerkleProofGadget::add_virtual_to::<H, F, D>(builder, height);
        self.insert_merkle_proof_gadget(key, g);
        (true, self.merkle_proofs.last().unwrap())
    }

    pub fn resolve_or_insert_variable_height_merkle_proof_gadget<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        key: StateCommandCacheKey,
        height: Target,
    ) -> (bool, &VariableHeightMerkleProofGadget) {
        if self.gadget_map.contains_key(&key) {
            let value = self.gadget_map[&key];
            if value.gadget_type == StateReaderReferenceKeyType::VariableHeightMerkleProof {
                return (false, &self.variable_height_merkle_proofs[value.gadget_index]);
            }
        }
        let gadget = VariableHeightMerkleProofGadget::add_virtual_to_full::<H, F, D>(builder, 32, Some(height));
        let ref_key = StateReaderReferenceKey::new_variable_height_merkle_proof_key(self.variable_height_merkle_proofs.len());
        self.variable_height_merkle_proofs.push(gadget);
        self.gadget_map.insert(key, ref_key);
        (true, self.variable_height_merkle_proofs.last().unwrap())
    }

    fn add_variable_height_merkle_proof_batch<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        height: Target,
        sub_slot_index: Target,
        length: usize,
        force_four_align: bool,
    ) -> (Vec<Target>, Vec<VariableHeightMerkleProofGadget>) {
        let (start_slot_index, sub_slot_index_mod_4) = builder.div_rem4(sub_slot_index);
        let proof_count = (length + 6) / 4;
        let mut proofs: Vec<VariableHeightMerkleProofGadget> = Vec::with_capacity(proof_count);
        let one = builder.one();
        for proof_index in 0..proof_count {
            let proof = VariableHeightMerkleProofGadget::add_virtual_to_full::<H, F, D>(builder, 32, Some(height));
            // The generic variable-height proof constrains the index to the
            // maximum height. A range must also fit the selected tree height.
            let index_bits = builder.split_le(proof.index, 32);
            let zero = builder.zero();
            let mut remaining = height;
            let mut exhausted = builder.is_zero(remaining);
            for bit in index_bits {
                builder.connect_if_true(exhausted, bit.target, zero);
                remaining = builder.sub(remaining, one);
                let is_zero = builder.is_zero(remaining);
                exhausted = builder.or(exhausted, is_zero);
            }
            let expected_index = if proof_index == 0 {
                start_slot_index
            } else if proof_index == proof_count - 1 {
                let mut last_proof_used = builder._false();
                for offset in 0..4 {
                    if length + offset > 4 * proof_index {
                        let offset_target = builder.constant(F::from_canonical_usize(offset));
                        let matches = builder.is_equal(sub_slot_index_mod_4, offset_target);
                        last_proof_used = builder.or(last_proof_used, matches);
                    }
                }
                let previous_index = proofs[proof_index - 1].index;
                let next_index = builder.add(previous_index, one);
                let sequential = builder.is_equal(proof.index, next_index);
                let repeated = builder.is_equal(proof.index, previous_index);
                let unused = builder.not(last_proof_used);
                let unused_repeated = builder.and(unused, repeated);
                let valid_index = builder.or(sequential, unused_repeated);
                builder.assert_one(valid_index.target);
                proof.index
            } else {
                builder.add(proofs[proof_index - 1].index, one)
            };
            builder.connect(proof.index, expected_index);
            if proof_index > 0 {
                builder.connect_hashes(proof.root, proofs[0].root);
            }
            proofs.push(proof);
        }

        let proof_values = proofs.iter().map(|proof| proof.value).collect::<Vec<_>>();
        let values = if force_four_align {
            builder.assert_zero(sub_slot_index_mod_4);
            proof_values
                .iter()
                .flat_map(|value| value.elements)
                .take(length)
                .collect()
        } else {
            enforce_merkle_array_values_2_bit(builder, sub_slot_index_mod_4, length, &proof_values)
        };
        (values, proofs)
    }

    pub fn resolve_delta_merkle_proof_gadget(&self, key: &StateCommandCacheKey) -> Option<&DeltaMerkleProofGadget> {
        if self.gadget_map.contains_key(key) {
            let value = self.gadget_map[key];
            if value.gadget_type == StateReaderReferenceKeyType::DeltaMerkleProof {
                return Some(&self.delta_merkle_proofs[value.gadget_index]);
            }
        }
        None
    }
    pub fn insert_delta_merkle_proof_gadget(&mut self, key: StateCommandCacheKey, gadget: DeltaMerkleProofGadget) -> StateReaderReferenceKey {
        let ref_key = StateReaderReferenceKey::new_delta_merkle_proof_key(self.delta_merkle_proofs.len());
        self.delta_merkle_proofs.push(gadget);
        self.gadget_map.insert(key, ref_key);
        ref_key
    }
    pub fn resolve_or_insert_delta_merkle_proof_gadget<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        key: StateCommandCacheKey,
        height: usize,
    ) -> &DeltaMerkleProofGadget {
        if self.gadget_map.contains_key(&key) {
            let value = self.gadget_map[&key];
            if value.gadget_type == StateReaderReferenceKeyType::DeltaMerkleProof {
                return &self.delta_merkle_proofs[value.gadget_index];
            }
        }
        let g = DeltaMerkleProofGadget::add_virtual_to::<H, F, D>(builder, height);
        self.insert_delta_merkle_proof_gadget(key, g);
        self.delta_merkle_proofs.last().unwrap()
    }

    pub fn resolve_user_leaf_gadget(&self, key: &StateCommandCacheKey) -> Option<&PsyUserLeafGadget> {
        if self.gadget_map.contains_key(key) {
            let value = self.gadget_map[key];
            if value.gadget_type == StateReaderReferenceKeyType::UserLeaf {
                return Some(&self.user_leaves[value.gadget_index]);
            }
        }
        None
    }
    pub fn insert_user_leaf_gadget(&mut self, key: StateCommandCacheKey, gadget: PsyUserLeafGadget) -> StateReaderReferenceKey {
        let ref_key = StateReaderReferenceKey::new_user_leaf_key(self.user_leaves.len());
        self.user_leaves.push(gadget);
        self.gadget_map.insert(key, ref_key);
        ref_key
    }
    pub fn insert_contract_leaf_gadget(
        &mut self,
        key: StateCommandCacheKey,
        contract_leaf_gadget: PsyContractLeafGadget,
        contract_tree_proof: MerkleProofGadget,
    ) -> StateReaderReferenceKey {
        let ref_key = StateReaderReferenceKey::new_contract_leaf_key(self.contract_leaf_requests.len());
        self.contract_leaf_requests.push(contract_leaf_gadget);
        self.contract_leaf_proofs.push(contract_tree_proof);
        self.gadget_map.insert(key, ref_key);
        ref_key
    }

    pub fn insert_checkpoint_stats_gadget(
        &mut self,
        key: StateCommandCacheKey,
        stats_gadget: PsyCheckpointLeafStatsGadget,
        state_roots_gadget: PsyCheckpointGlobalStateRootsGadget,
        historical_proof: HistoricalRootMerkleProofGadget,
    ) -> StateReaderReferenceKey {
        let index = self.checkpoint_stats_requests.len();
        self.checkpoint_stats_requests.push(stats_gadget);
        self.checkpoint_state_roots_requests.push(state_roots_gadget);
        self.historical_proofs.push(historical_proof);
        let ref_key = StateReaderReferenceKey::new_checkpoint_stats_key(index);
        self.gadget_map.insert(key, ref_key);
        ref_key
    }
    pub fn insert_imt_set_gadget(&mut self, key: StateCommandCacheKey, gadget: IMTSetGadget) -> StateReaderReferenceKey {
        let ref_key = StateReaderReferenceKey::new_imt_set_key(self.imt_set_requests.len());
        self.imt_set_requests.push(gadget);
        self.gadget_map.insert(key, ref_key);
        ref_key
    }
    pub fn insert_imt_contains_gadget(
        &mut self,
        key: StateCommandCacheKey,
        proof: MerkleProofGadget,
        leaf: IMTLeafTargets,
        exists_target: Target,
    ) -> StateReaderReferenceKey {
        let ref_key = StateReaderReferenceKey::new_imt_contains_key(self.imt_contains_leaf_requests.len());
        self.imt_contains_proofs.push(proof);
        self.imt_contains_leaf_requests.push(leaf);
        self.imt_contains_exists_targets.push(exists_target);
        self.gadget_map.insert(key, ref_key);
        ref_key
    }
    pub fn insert_imt_read_gadget(&mut self, key: StateCommandCacheKey, gadget: IMTReadGadget) -> StateReaderReferenceKey {
        let ref_key = StateReaderReferenceKey::new_imt_read_key(self.imt_read_requests.len());
        self.imt_read_requests.push(gadget);
        self.gadget_map.insert(key, ref_key);
        ref_key
    }
    pub fn insert_imt_external_read_gadget(&mut self, key: StateCommandCacheKey, gadget: IMTExternalReadGadget) -> StateReaderReferenceKey {
        let ref_key = StateReaderReferenceKey::new_imt_external_read_key(self.imt_external_read_requests.len());
        self.imt_external_read_requests.push(gadget);
        self.gadget_map.insert(key, ref_key);
        ref_key
    }
    pub fn insert_imt_other_user_read_gadget(&mut self, key: StateCommandCacheKey, gadget: IMTOtherUserReadGadget) -> StateReaderReferenceKey {
        let ref_key = StateReaderReferenceKey::new_imt_other_user_read_key(self.imt_other_user_read_requests.len());
        self.imt_other_user_read_requests.push(gadget);
        self.gadget_map.insert(key, ref_key);
        ref_key
    }
    pub fn insert_imt_contains_other_user_gadget(
        &mut self,
        key: StateCommandCacheKey,
        gadget: IMTContainsOtherUserGadget,
    ) -> StateReaderReferenceKey {
        let ref_key = StateReaderReferenceKey::new_imt_contains_other_user_key(self.imt_contains_other_user_requests.len());
        self.imt_contains_other_user_requests.push(gadget);
        self.gadget_map.insert(key, ref_key);
        ref_key
    }
    pub fn resolve_or_insert_user_leaf_gadget<F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        key: StateCommandCacheKey,
    ) -> (bool, &PsyUserLeafGadget) {
        if self.gadget_map.contains_key(&key) {
            let value = self.gadget_map[&key];
            if value.gadget_type == StateReaderReferenceKeyType::UserLeaf {
                return (false, &self.user_leaves[value.gadget_index]);
            }
        }

        let g = PsyUserLeafGadget::create_virtual(builder);
        self.insert_user_leaf_gadget(key, g);
        (true, self.user_leaves.last().unwrap())
    }
    pub fn resolve_or_insert_contract_leaf_gadget<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        key: StateCommandCacheKey,
    ) -> (bool, usize) {
        if let Some(ref_key) = self.gadget_map.get(&key) {
            if ref_key.gadget_type == StateReaderReferenceKeyType::ContractLeaf {
                let index = ref_key.gadget_index;
                return (false, index);
            }
        }

        let contract_leaf_gadget = PsyContractLeafGadget::create_virtual::<F, D>(builder);
        let contract_tree_proof = MerkleProofGadget::add_virtual_to::<H, F, D>(builder, GLOBAL_CONTRACT_TREE_HEIGHT as usize);
        self.insert_contract_leaf_gadget(key, contract_leaf_gadget, contract_tree_proof);
        let index = self.contract_leaf_requests.len() - 1;
        (true, index)
    }

    // end resolvers

    pub fn get_self_user_external_contract_root<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        dpn: &SimpleDPNBuilder<F, D>,
        contract_target_id: u64,
    ) -> HashOutTarget {
        let read_root_ck = StateCommandCacheKey::new_read_self_user_external_contract_root(contract_target_id, self.contract_call_epoch);
        let uct_root = self.user_contract_tree_state_root;
        let expected_contract_state_tree_root = {
            let (is_new_uct, mp_uct) =
                self.resolve_or_insert_merkle_proof_gadget::<H, F, D>(builder, read_root_ck, GLOBAL_CONTRACT_TREE_HEIGHT as usize);
            let expected_contract_state_tree_root = mp_uct.value.clone();
            if is_new_uct {
                builder.connect_hashes(mp_uct.root, uct_root);

                let contract_id_target = dpn.resolve_target(contract_target_id);

                builder.connect(mp_uct.index, contract_id_target);
                let mp_uct: Vec<Target> = mp_uct.value.elements.to_vec();
                self.result_map.insert(read_root_ck, mp_uct);
            }
            expected_contract_state_tree_root
        };
        expected_contract_state_tree_root
    }

    pub fn get_self_user_external_contract_slot_hash<H: AlgebraicHasher<F> + MerkleZeroHasher<HashOut<F>>, F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        dpn: &SimpleDPNBuilder<F, D>,
        contract_target_id: u64,
        slot_target_id: u64,
        contract_state_tree_height: Target,
    ) -> HashOutTarget {
        let expected_contract_state_tree_root = self.get_self_user_external_contract_root::<H, F, D>(builder, dpn, contract_target_id);
        let contract_state_tree_ck =
            StateCommandCacheKey::new_read_self_user_external_contract_slot(contract_target_id, slot_target_id, self.contract_call_epoch);
        let (is_new_contract_state_tree, mp_cst_value, mp_cst_root, mp_cst_index) = {
            let (is_new_contract_state_tree, mp_cst) =
                self.resolve_or_insert_variable_height_merkle_proof_gadget::<H, F, D>(builder, contract_state_tree_ck, contract_state_tree_height);
            (is_new_contract_state_tree, mp_cst.value, mp_cst.root, mp_cst.index)
        };

        let slot_value = mp_cst_value;
        let is_uninitialized = Self::connect_external_contract_state_root_if_initialized::<H, F, D>(
            builder, expected_contract_state_tree_root, mp_cst_root, contract_state_tree_height,
        );
        if is_new_contract_state_tree {
            let slot_index = dpn.resolve_target(slot_target_id);
            builder.connect(slot_index, mp_cst_index);
            self.result_map.insert(contract_state_tree_ck, slot_value.elements.to_vec());
        }
        let zero_hash = builder.constant_hash(HashOut::ZERO);
        builder.select_hash(is_uninitialized, zero_hash, slot_value)
    }

    pub fn get_other_user_leaf_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        dpn: &SimpleDPNBuilder<F, D>,
        user_target_id: u64,
    ) -> HashOutTarget {
        let user_tree_ck = StateCommandCacheKey::new_read_other_user_leaf_hash(user_target_id);
        let (is_new, mp_user_tree_root, mp_user_tree_value, mp_user_tree_index) = {
            let (is_new, mp_user_tree) =
                self.resolve_or_insert_merkle_proof_gadget::<H, F, D>(builder, user_tree_ck, GLOBAL_USER_TREE_HEIGHT as usize);
            (is_new, mp_user_tree.root, mp_user_tree.value, mp_user_tree.index)
        };

        if is_new {
            builder.connect_hashes(mp_user_tree_root, self.chain_state_roots.user_tree_root);
            let user_id_target = dpn.resolve_target(user_target_id);
            builder.connect(mp_user_tree_index, user_id_target);
        }
        mp_user_tree_value
    }

    pub fn get_other_user_leaf<H: AlgebraicHasher<F> + MerkleZeroHasher<HashOut<F>>, F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        dpn: &SimpleDPNBuilder<F, D>,
        user_target_id: u64,
    ) -> &PsyUserLeafGadget {
        let expected_leaf_hash = { self.get_other_user_leaf_hash::<H, F, D>(builder, dpn, user_target_id) };
        let user_leaf_ck = StateCommandCacheKey::new_read_other_user_leaf(user_target_id);

        let (is_new, leaf) = self.resolve_or_insert_user_leaf_gadget::<F, D>(builder, user_leaf_ck);

        if is_new {
            let requested_user_id = dpn.resolve_target(user_target_id);
            Self::connect_authenticated_other_user_leaf::<H, F, D>(builder, expected_leaf_hash, leaf, requested_user_id);
        }
        leaf
    }

    fn connect_authenticated_other_user_leaf<
        H: AlgebraicHasher<F> + MerkleZeroHasher<HashOut<F>>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        expected_leaf_hash: HashOutTarget,
        leaf: &PsyUserLeafGadget,
        requested_user_id: Target,
    ) {
        let actual_leaf_hash = leaf.to_hash::<H, F, D>(builder);
        let is_absent = builder.is_zero_hash(expected_leaf_hash);
        builder.connect_hashes_if_false(is_absent, expected_leaf_hash, actual_leaf_hash);
        // An unregistered user has a zero user-tree leaf. The RPC supplies a
        // synthetic leaf with the default contract-tree root for reads.
        let zero_hash = builder.constant_hash(HashOut::ZERO);
        let empty_contract_root = builder.constant_hash(H::get_zero_hash(GLOBAL_CONTRACT_TREE_HEIGHT as usize));
        let zero = builder.zero();
        builder.connect_if_true(is_absent, leaf.user_id, requested_user_id);
        builder.connect_hashes_if_true(is_absent, leaf.public_key, zero_hash);
        builder.connect_hashes_if_true(is_absent, leaf.user_state_tree_root, empty_contract_root);
        for field in [leaf.balance, leaf.nonce, leaf.last_checkpoint_id, leaf.event_index] {
            builder.connect_if_true(is_absent, field, zero);
        }
    }

    pub fn get_other_user_contract_state_root<H: AlgebraicHasher<F> + MerkleZeroHasher<HashOut<F>>, F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        dpn: &SimpleDPNBuilder<F, D>,
        user_target_id: u64,
        contract_target_id: u64,
    ) -> HashOutTarget {
        let expected_user_contract_tree_root = { self.get_other_user_leaf::<H, F, D>(builder, dpn, user_target_id).user_state_tree_root };
        let uct_ck = StateCommandCacheKey::new_read_other_user_contract_root(user_target_id, contract_target_id);

        let (is_new, mp_uct) = self.resolve_or_insert_merkle_proof_gadget::<H, F, D>(builder, uct_ck, GLOBAL_CONTRACT_TREE_HEIGHT as usize);

        if is_new {
            let expected_contract_id = dpn.resolve_target(contract_target_id);

            builder.connect(expected_contract_id, mp_uct.index);

            builder.connect_hashes(expected_user_contract_tree_root, mp_uct.root);
        }
        mp_uct.value
    }

    fn connect_external_contract_state_root_if_initialized<
        H: AlgebraicHasher<F> + MerkleZeroHasher<HashOut<F>>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        contract_state_root: HashOutTarget,
        state_proof_root: HashOutTarget,
        state_tree_height: Target,
    ) -> BoolTarget {
        let is_uninitialized = builder.is_zero_hash(contract_state_root);
        builder.connect_hashes_if_false(is_uninitialized, state_proof_root, contract_state_root);
        let mut empty_root = builder.constant_hash(H::get_zero_hash(1));
        for height in 2..=32 {
            let height_target = builder.constant(F::from_canonical_usize(height));
            let at_height = builder.is_equal(state_tree_height, height_target);
            let root_at_height = builder.constant_hash(H::get_zero_hash(height));
            empty_root = builder.select_hash(at_height, root_at_height, empty_root);
        }
        builder.connect_hashes_if_true(is_uninitialized, state_proof_root, empty_root);
        is_uninitialized
    }

    fn imt_sentinel_slot<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        dpn: &SimpleDPNBuilder<F, D>,
        base_offset_id: u64,
    ) -> Target {
        // base_offset_id is an encoded DPN operand, not the bytecode's
        // literal offset. Resolve its runtime value before computing ceil(/4).
        let base_offset = dpn.resolve_target(base_offset_id);
        let three = builder.constant(F::from_canonical_u64(3));
        let rounded = builder.add(base_offset, three);
        builder.div_rem4(rounded).0
    }

    fn connect_external_imt_get_leaf<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        leaf: &IMTLeafTargets,
        proof_value: HashOutTarget,
        proof_index: Target,
        query_key: HashOutTarget,
        is_uninitialized: BoolTarget,
        state_slot_base: Target,
    ) -> Vec<Target> {
        let leaf_hash = leaf.hash::<H, F, D>(builder);
        let key_zero = builder.is_zero_hash(leaf.key);
        let value_zero = builder.is_zero_hash(leaf.value);
        let next_key_zero = builder.is_zero_hash(leaf.next_key);
        let next_index_zero = builder.is_zero(leaf.next_index);
        let key_value_zero = builder.and(key_zero, value_zero);
        let next_zero = builder.and(next_key_zero, next_index_zero);
        let leaf_is_empty = builder.and(key_value_zero, next_zero);
        let leaf_is_nonempty = builder.not(leaf_is_empty);

        builder.connect_hashes_if_true(leaf_is_nonempty, leaf_hash, proof_value);
        let zero_hash = builder.constant_hash(HashOut::ZERO);
        builder.connect_hashes_if_true(leaf_is_empty, proof_value, zero_hash);
        builder.connect_if_true(leaf_is_empty, proof_index, state_slot_base);

        let key_eq = builder.is_equal_hash(leaf.key, query_key);
        let initialized = builder.not(is_uninitialized);
        let nonempty_match = builder.and(leaf_is_nonempty, key_eq);
        let is_member = builder.and(initialized, nonempty_match);
        let is_missing = builder.not(is_member);
        let nonempty_missing = builder.and(is_missing, leaf_is_nonempty);
        let pred_lt_query = is_qhashout_lt::<F, D>(builder, leaf.key, query_key);
        let next_key_zero = builder.is_zero_hash(leaf.next_key);
        let query_lt_next = is_qhashout_lt::<F, D>(builder, query_key, leaf.next_key);
        let next_ok = builder.or(next_key_zero, query_lt_next);
        let non_member = builder.and(pred_lt_query, next_ok);
        let one = builder._true();
        builder.connect_if_true(nonempty_missing, non_member.target, one.target);

        let zero = builder.zero();
        leaf.value.elements.iter().map(|value| builder.select(is_member, *value, zero)).collect()
    }

    pub fn get_other_user_contract_state_slot_hash<H: AlgebraicHasher<F> + MerkleZeroHasher<HashOut<F>>, F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        dpn: &SimpleDPNBuilder<F, D>,
        user_target_id: u64,
        contract_target_id: u64,
        slot_target_id: u64,
        contract_state_tree_height: Target,
    ) -> HashOutTarget {
        let expected_contract_state_tree_root =
            { self.get_other_user_contract_state_root::<H, F, D>(builder, dpn, user_target_id, contract_target_id) };

        let cst_ck = StateCommandCacheKey::new_read_other_user_contract_slot(user_target_id, contract_target_id, slot_target_id);

        let (is_new, mp_cst) =
            self.resolve_or_insert_variable_height_merkle_proof_gadget::<H, F, D>(builder, cst_ck, contract_state_tree_height);

        let is_uninitialized = Self::connect_external_contract_state_root_if_initialized::<H, F, D>(
            builder, expected_contract_state_tree_root, mp_cst.root, contract_state_tree_height,
        );
        if is_new {
            let expected_contract_id = dpn.resolve_target(slot_target_id);

            builder.connect(expected_contract_id, mp_cst.index);
        }
        let zero_hash = builder.constant_hash(HashOut::ZERO);
        builder.select_hash(is_uninitialized, zero_hash, mp_cst.value)
    }

    pub fn get_other_user_contract_state_slot_range<H: AlgebraicHasher<F> + MerkleZeroHasher<HashOut<F>>, F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        dpn: &SimpleDPNBuilder<F, D>,
        user_target_id: u64,
        contract_target_id: u64,
        sub_slot_target_id: u64,
        contract_state_tree_height: Target,
        length: usize,
    ) -> Vec<Target> {
        let expected_contract_state_tree_root =
            { self.get_other_user_contract_state_root::<H, F, D>(builder, dpn, user_target_id, contract_target_id) };

        let r_ck = StateCommandCacheKey::new_read_other_user_contract_range(user_target_id, contract_target_id, sub_slot_target_id, length as u32, 0);

        let values = if self.result_map.contains_key(&r_ck) {
            self.result_map.get(&r_ck).unwrap().to_owned()
        } else {
            let sub_slot_index = dpn.resolve_target(sub_slot_target_id);
            let (values, mps) = Self::add_variable_height_merkle_proof_batch::<H, F, D>(
                builder,
                contract_state_tree_height,
                sub_slot_index,
                length,
                self.force_four_align,
            );
            Self::connect_external_contract_state_root_if_initialized::<H, F, D>(
                builder, expected_contract_state_tree_root, mps[0].root, contract_state_tree_height,
            );
            for (i, mp) in mps.into_iter().enumerate() {
                let ck = StateCommandCacheKey::new_read_other_user_contract_range(
                    user_target_id,
                    contract_target_id,
                    sub_slot_target_id,
                    length as u32,
                    i as u64,
                );
                let ref_key = StateReaderReferenceKey::new_variable_height_merkle_proof_key(self.variable_height_merkle_proofs.len());
                self.variable_height_merkle_proofs.push(mp);
                self.gadget_map.insert(ck, ref_key);
            }
            self.result_map.insert(r_ck, values.clone());
            values
        };
        let is_uninitialized = builder.is_zero_hash(expected_contract_state_tree_root);
        let zero = builder.zero();
        values.into_iter().map(|value| builder.select(is_uninitialized, zero, value)).collect()
    }

    pub fn get_self_user_external_contract_state_slot_single<H: AlgebraicHasher<F> + MerkleZeroHasher<HashOut<F>>, F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        dpn: &SimpleDPNBuilder<F, D>,
        contract_target_id: u64,
        sub_slot_target_id: u64,
        contract_state_tree_height: Target,
    ) -> Target {
        let ck = StateCommandCacheKey::new_read_self_user_external_contract_single(contract_target_id, sub_slot_target_id, self.contract_call_epoch);

        let expected_contract_state_tree_root = self.get_self_user_external_contract_root::<H, F, D>(builder, dpn, contract_target_id);

        let (is_new, mp_cst) =
            self.resolve_or_insert_variable_height_merkle_proof_gadget::<H, F, D>(builder, ck, contract_state_tree_height);
        let is_uninitialized = Self::connect_external_contract_state_root_if_initialized::<H, F, D>(
            builder, expected_contract_state_tree_root, mp_cst.root, contract_state_tree_height,
        );

        if is_new {
            let sub_slot_index = dpn.resolve_target(sub_slot_target_id);
            let (slot_index, inner_index) = builder.div_rem4(sub_slot_index);
            let raw_value = builder.select_in_hash(mp_cst.value, inner_index);
            let zero = builder.zero();
            let single_value = builder.select(is_uninitialized, zero, raw_value);
            builder.connect(slot_index, mp_cst.index);
            self.result_map.insert(ck, vec![single_value]);
            single_value
        } else {
            let zero = builder.zero();
            builder.select(is_uninitialized, zero, self.result_map[&ck][0])
        }
    }

    pub fn get_self_user_external_contract_state_slot_range<H: AlgebraicHasher<F> + MerkleZeroHasher<HashOut<F>>, F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        dpn: &SimpleDPNBuilder<F, D>,
        contract_target_id: u64,
        sub_slot_target_id: u64,
        contract_state_tree_height: Target,
        length: usize,
    ) -> Vec<Target> {
        let expected_contract_state_tree_root = self.get_self_user_external_contract_root::<H, F, D>(builder, dpn, contract_target_id);
        let r_ck = StateCommandCacheKey::new_read_self_user_external_contract_range(
            contract_target_id,
            sub_slot_target_id,
            length as u32,
            self.contract_call_epoch,
            0,
        );

        let values = if self.result_map.contains_key(&r_ck) {
            self.result_map.get(&r_ck).unwrap().to_owned()
        } else {
            let sub_slot_index = dpn.resolve_target(sub_slot_target_id);
            let (values, mps) = Self::add_variable_height_merkle_proof_batch::<H, F, D>(
                builder,
                contract_state_tree_height,
                sub_slot_index,
                length,
                self.force_four_align,
            );

            Self::connect_external_contract_state_root_if_initialized::<H, F, D>(
                builder, expected_contract_state_tree_root, mps[0].root, contract_state_tree_height,
            );
            for (i, mp) in mps.into_iter().enumerate() {
                let ck = StateCommandCacheKey::new_read_self_user_external_contract_range(
                    contract_target_id,
                    sub_slot_target_id,
                    length as u32,
                    self.contract_call_epoch,
                    i as u64,
                );
                let ref_key = StateReaderReferenceKey::new_variable_height_merkle_proof_key(self.variable_height_merkle_proofs.len());
                self.variable_height_merkle_proofs.push(mp);
                self.gadget_map.insert(ck, ref_key);
            }

            self.result_map.insert(r_ck, values.clone());
            values
        };
        let is_uninitialized = builder.is_zero_hash(expected_contract_state_tree_root);
        let zero = builder.zero();
        values.into_iter().map(|value| builder.select(is_uninitialized, zero, value)).collect()
    }

    pub fn injest_symbolic_state_command<
        H: AlgebraicHasher<F> + psy_crypto::hash::traits::hasher::MerkleZeroHasher<HashOut<F>>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        dpn: &SimpleDPNBuilder<F, D>,
        cmd: &DPNStateCmd<u64>,
    ) -> Vec<Target> {
        let value = match cmd {
            DPNStateCmd::SetContractStateSlotHash(c) => {
                let dmp = DeltaMerkleProofGadget::add_virtual_to::<H, F, D>(builder, self.contract_state_tree_height);

                let value = HashOutTarget {
                    elements: dpn.resolve_targets_sized::<4>(&c.value),
                };
                let condition = dpn.resolve_bool(builder, c.condition);
                let slot_index = dpn.resolve_target(c.slot_index);

                builder.connect_hashes_if_true(condition, dmp.old_root, self.end_contract_state_root);
                builder.connect_hashes_if_true(condition, dmp.new_value, value);
                builder.connect_if_true(condition, dmp.index, slot_index);

                let new_end_state_root = builder.select_hash(condition, dmp.new_root, self.end_contract_state_root);
                self.end_contract_state_root = new_end_state_root;

                let ck = StateCommandCacheKey::new_write_current_contract_slot(c.slot_index, c.condition, self.write_epoch);
                self.write_epoch += 1;

                let _ref_key = self.insert_delta_merkle_proof_gadget(ck, dmp);

                value.elements.to_vec()
            }
            DPNStateCmd::SetContractStateSlotSingle(c) => {
                let dmp = DeltaMerkleProofGadget::add_virtual_to::<H, F, D>(builder, self.contract_state_tree_height);

                let condition = dpn.resolve_bool(builder, c.condition);
                let sub_slot_index = dpn.resolve_target(c.sub_slot_index);
                let value = dpn.resolve_target(c.value);
                let (slot_index, inner_index) = builder.div_rem4(sub_slot_index);
                // modify a single element in the hash (ie. set hash.elements[inner_index] =
                // value)
                let modded_hash = builder.set_target_in_hash(dmp.old_value, inner_index, value);

                builder.connect_hashes_if_true(condition, dmp.old_root, self.end_contract_state_root);
                builder.connect_hashes_if_true(condition, dmp.new_value, modded_hash);
                builder.connect_if_true(condition, dmp.index, slot_index);

                let new_end_state_root = builder.select_hash(condition, dmp.new_root, self.end_contract_state_root);
                self.end_contract_state_root = new_end_state_root;

                let ck = StateCommandCacheKey::new_write_current_contract_single(c.sub_slot_index, c.condition, self.write_epoch);

                self.write_epoch += 1;
                let _ref_key = self.insert_delta_merkle_proof_gadget(ck, dmp);

                vec![value]
            }
            DPNStateCmd::SetContractStateSlotRange(c) => {
                let condition = dpn.resolve_bool(builder, c.condition);
                let sub_slot_index = dpn.resolve_target(c.sub_slot_index);
                let values = dpn.resolve_targets(&c.value);

                let (values, dmps) = {
                    let gadget = SubSlotDeltaMerkleProofBatchGadget::add_virtual_to::<H, F, D>(
                        builder,
                        self.contract_state_tree_height,
                        sub_slot_index,
                        values,
                        self.force_four_align,
                        Some(condition),
                    );
                    (gadget.values, gadget.delta_merkle_proof_gadgets)
                };
                builder.connect_hashes_if_true(condition, dmps[0].old_root, self.end_contract_state_root);

                let new_end_state_root = builder.select_hash(condition, dmps.last().unwrap().new_root, self.end_contract_state_root);
                self.end_contract_state_root = new_end_state_root;
                let values_len = values.len() as u32;
                for (i, dmp) in dmps.into_iter().enumerate() {
                    let ck =
                        StateCommandCacheKey::new_write_current_contract_range(c.sub_slot_index, c.condition, values_len, i as u64, self.write_epoch);
                    let _ref_key = self.insert_delta_merkle_proof_gadget(ck, dmp);
                }

                self.write_epoch += 1;
                values
            }
            DPNStateCmd::InvokeExternalContractFunctionSync(_c) => todo!(),
            DPNStateCmd::GetSelfUserCurrentContractStateSlotHash(c) => {
                let ck = StateCommandCacheKey::new_read_current_contract_slot(c.slot_index, self.write_epoch);

                let end_contract_state_root = self.end_contract_state_root;
                let (is_new, mp) = self.resolve_or_insert_merkle_proof_gadget::<H, F, D>(builder, ck, self.contract_state_tree_height);
                let mp_value = mp.value.elements.to_vec();

                if is_new {
                    let slot_index = dpn.resolve_target(c.slot_index);

                    builder.connect(mp.index, slot_index);
                    builder.connect_hashes(mp.root, end_contract_state_root);
                    self.result_map.insert(ck, mp_value.clone());
                    mp_value
                } else {
                    mp_value
                }
            }
            DPNStateCmd::GetSelfUserCurrentContractStateSlotSingle(c) => {
                let ck = StateCommandCacheKey::new_read_current_contract_single(c.sub_slot_index, self.write_epoch);

                let end_contract_state_root = self.end_contract_state_root;
                let (is_new, mp) = self.resolve_or_insert_merkle_proof_gadget::<H, F, D>(builder, ck, self.contract_state_tree_height);

                if is_new {
                    let sub_slot_index = dpn.resolve_target(c.sub_slot_index);
                    let (slot_index, inner_index) = builder.div_rem4(sub_slot_index);
                    let single_value = builder.select_in_hash(mp.value, inner_index);
                    builder.connect(mp.index, slot_index);
                    builder.connect_hashes(mp.root, end_contract_state_root);
                    self.result_map.insert(ck, vec![single_value]);

                    vec![single_value]
                } else {
                    self.result_map[&ck].to_vec()
                }
            }
            DPNStateCmd::GetSelfUserCurrentContractStateSlotRange(c) => {
                let r_ck = StateCommandCacheKey::new_read_current_contract_range(c.sub_slot_index, c.length, 0, self.write_epoch);
                if self.result_map.contains_key(&r_ck) {
                    self.result_map.get(&r_ck).unwrap().to_owned()
                } else {
                    let sub_slot_index = dpn.resolve_target(c.sub_slot_index);
                    let (values, mps) = {
                        let gadget = SubSlotMerkleProofBatchGadget::add_virtual_to::<H, F, D>(
                            builder,
                            self.contract_state_tree_height,
                            c.length as usize,
                            sub_slot_index,
                            self.force_four_align,
                        );
                        (gadget.values, gadget.merkle_proof_gadgets)
                    };
                    builder.connect_hashes(mps[0].root, self.end_contract_state_root);
                    for (i, mp) in mps.into_iter().enumerate() {
                        let ck = StateCommandCacheKey::new_read_current_contract_range(c.sub_slot_index, c.length, i as u64, self.write_epoch);
                        let _ref_key = self.insert_merkle_proof_gadget(ck, mp);
                    }
                    self.result_map.insert(r_ck, values.clone());
                    values
                }
            }
            DPNStateCmd::GetSelfUserExternalContractStateSlotHash(c) => {
                self.get_self_user_external_contract_slot_hash::<H, F, D>(
                    builder,
                    dpn,
                    c.contract_id,
                    c.slot_index,
                    dpn.resolve_target(c.contract_state_tree_height),
                )
                .elements
                .to_vec()
            }

            DPNStateCmd::GetSelfUserExternalContractStateSlotSingle(c) => {
                let single_value = self.get_self_user_external_contract_state_slot_single::<H, F, D>(
                    builder,
                    dpn,
                    c.contract_id,
                    c.sub_slot_index,
                    dpn.resolve_target(c.contract_state_tree_height),
                );
                vec![single_value]
            }
            DPNStateCmd::GetSelfUserExternalContractStateSlotRange(c) => self.get_self_user_external_contract_state_slot_range::<H, F, D>(
                builder,
                dpn,
                c.contract_id,
                c.sub_slot_index,
                dpn.resolve_target(c.contract_state_tree_height),
                c.length as usize,
            ),
            DPNStateCmd::GetOtherUserContractStateSlotSingle(c) => {
                let ck = StateCommandCacheKey::new_read_other_user_contract_single(c.user_id, c.contract_id, c.sub_slot_index, self.write_epoch);

                let expected_contract_state_tree_root = self.get_other_user_contract_state_root::<H, F, D>(builder, dpn, c.user_id, c.contract_id);

                let contract_state_tree_height = dpn.resolve_target(c.contract_state_tree_height);
                let (is_new, mp_cst) =
                    self.resolve_or_insert_variable_height_merkle_proof_gadget::<H, F, D>(builder, ck, contract_state_tree_height);

                let is_uninitialized = Self::connect_external_contract_state_root_if_initialized::<H, F, D>(
                    builder, expected_contract_state_tree_root, mp_cst.root, contract_state_tree_height,
                );
                if is_new {
                    let sub_slot_index = dpn.resolve_target(c.sub_slot_index);
                    let (slot_index, inner_index) = builder.div_rem4(sub_slot_index);
                    let raw_value = builder.select_in_hash(mp_cst.value, inner_index);
                    let zero = builder.zero();
                    let single_value = builder.select(is_uninitialized, zero, raw_value);
                    builder.connect(slot_index, mp_cst.index);
                    self.result_map.insert(ck, vec![single_value]);
                    vec![single_value]
                } else {
                    let zero = builder.zero();
                    self.result_map[&ck].iter().map(|value| builder.select(is_uninitialized, zero, *value)).collect()
                }
            }
            DPNStateCmd::GetOtherUserContractStateSlotRange(c) => self.get_other_user_contract_state_slot_range::<H, F, D>(
                builder,
                dpn,
                c.user_id,
                c.contract_id,
                c.sub_slot_index,
                dpn.resolve_target(c.contract_state_tree_height),
                c.length as usize,
            ),
            DPNStateCmd::GetOtherUserContractStateSlotHash(c) => self
                .get_other_user_contract_state_slot_hash::<H, F, D>(
                    builder,
                    dpn,
                    c.user_id,
                    c.contract_id,
                    c.slot_index,
                    dpn.resolve_target(c.contract_state_tree_height),
                )
                .elements
                .to_vec(),
            DPNStateCmd::InvokeExternalContractFunctionDeferred(c) => {
                let ck = StateCommandCacheKey::InvokeDeferredMethodCall(CKInvokeDeferredMethodCall::new(
                    c.condition,
                    c.contract_id,
                    c.method_id,
                    self.deferred_tx_count,
                    &c.input_args,
                ));
                let condition_target = dpn.resolve_bool(builder, c.condition);
                let contract_id_target = dpn.resolve_target(c.contract_id);
                let method_id_target = dpn.resolve_target(c.method_id);
                let input_targets = dpn.resolve_targets(&c.input_args);
                let deferred_method_call_gadget = DPNProvingSessionSimpleMethodCallGadget {
                    caller_contract_id: dpn.contract_id,
                    contract_id: contract_id_target,
                    method_id: method_id_target,
                    inputs: input_targets,
                };

                let tx_hash = deferred_method_call_gadget.to_hash::<H, F, D>(builder);
                let dmp = DeltaMerkleProofGadget::add_virtual_to::<H, F, D>(builder, DEFERRED_TRANSACTION_TREE_HEIGHT as usize);
                builder.connect_hashes_if_true(condition_target, dmp.old_root, self.end_deferred_tx_tree_root);
                let new_root = builder.select_hash(condition_target, dmp.new_root, self.end_deferred_tx_tree_root);
                self.end_deferred_tx_tree_root = new_root;
                builder.connect_hashes_if_true(condition_target, dmp.new_value, tx_hash);
                let zero_hash = builder.constant_hash(HashOut::ZERO);
                builder.connect_hashes_if_true(condition_target, dmp.old_value, zero_hash);

                let _ref_key = self.insert_delta_merkle_proof_gadget(ck, dmp);
                self.deferred_tx_count += 1;
                tx_hash.elements.to_vec()
            }
            DPNStateCmd::GetContractLeaf(c) => {
                let ck = StateCommandCacheKey::new_get_contract_leaf(c.contract_id);

                if let Some(existing_result) = self.result_map.get(&ck) {
                    existing_result.clone()
                } else {
                    let contract_id_target = dpn.resolve_target(c.contract_id);

                    let (is_new, index) = self.resolve_or_insert_contract_leaf_gadget::<H, F, D>(builder, ck.clone());

                    if is_new {
                        {
                            let contract_tree_proof = &self.contract_leaf_proofs[index];
                            builder.connect_hashes(contract_tree_proof.root, self.chain_state_roots.contract_tree_root);
                            builder.connect(contract_tree_proof.index, contract_id_target);

                            let contract_leaf_hash = {
                                let contract_leaf_gadget = &self.contract_leaf_requests[index];
                                contract_leaf_gadget.to_hash::<H, F, D>(builder)
                            };
                            builder.connect_hashes(contract_tree_proof.value, contract_leaf_hash);
                        }

                        let targets = {
                            let contract_leaf_gadget = &self.contract_leaf_requests[index];
                            contract_leaf_gadget.to_targets()
                        };
                        self.result_map.insert(ck.clone(), targets);
                    }

                    self.result_map[&ck].clone()
                }
            }
            DPNStateCmd::GetCheckpointLeafStats(c) => {
                let ck = StateCommandCacheKey::new_get_checkpoint_stats(c.checkpoint_id);

                if let Some(existing_result) = self.result_map.get(&ck) {
                    existing_result.clone()
                } else {
                    let requested_checkpoint_id = dpn.resolve_target(c.checkpoint_id);

                    let requested_checkpoint_stats = PsyCheckpointLeafStatsGadget::create_virtual(builder);

                    let historical_proof =
                        HistoricalRootMerkleProofGadget::add_virtual_to_zero_gt::<H, F, D>(builder, CHECKPOINT_TREE_HEIGHT as usize);

                    builder.connect(historical_proof.index, requested_checkpoint_id);

                    builder.connect_hashes(historical_proof.current_root, self.checkpoint_tree_root);

                    let checkpoint_stats_hash = requested_checkpoint_stats.to_hash::<H, F, D>(builder);

                    let requested_checkpoint_state_roots = PsyCheckpointGlobalStateRootsGadget::create_virtual(builder);
                    let state_roots_hash = requested_checkpoint_state_roots.to_hash::<H, F, D>(builder);

                    let checkpoint_leaf_hash = builder.hash_two_to_one::<H>(state_roots_hash, checkpoint_stats_hash);

                    builder.connect_hashes(historical_proof.current_value, checkpoint_leaf_hash);

                    self.insert_checkpoint_stats_gadget(
                        ck.clone(),
                        requested_checkpoint_stats.clone(),
                        requested_checkpoint_state_roots,
                        historical_proof,
                    );

                    let mut result = Vec::new();

                    result.push(requested_checkpoint_stats.guta_fees_collected);
                    result.push(requested_checkpoint_stats.da_fees_collected);
                    result.push(requested_checkpoint_stats.user_ops_processed);
                    result.push(requested_checkpoint_stats.total_transactions);
                    result.push(requested_checkpoint_stats.slots_modified);
                    result.extend_from_slice(&requested_checkpoint_stats.pm_jobs_completed.to_targets());
                    result.push(requested_checkpoint_stats.block_time);

                    result.extend_from_slice(&requested_checkpoint_stats.random_seed.elements);

                    let pm_rewards = &requested_checkpoint_stats.pm_rewards_commitment;
                    result.extend_from_slice(&pm_rewards.register_users_root.elements);
                    result.extend_from_slice(&pm_rewards.gutas_root.elements);
                    result.extend_from_slice(&pm_rewards.deploy_contracts_root.elements);

                    result.extend_from_slice(&requested_checkpoint_stats.da_challenges_claimed);

                    self.result_map.insert(ck, result.clone());

                    result
                }
            }
            DPNStateCmd::GetGlobalStateRoots(c) => {
                let ck = StateCommandCacheKey::new_get_checkpoint_stats(c.checkpoint_id);

                if let Some(ref_key) = self.gadget_map.get(&ck) {
                    self.checkpoint_state_roots_requests[ref_key.gadget_index].to_targets()
                } else {
                    let requested_checkpoint_id = dpn.resolve_target(c.checkpoint_id);

                    let requested_checkpoint_stats = PsyCheckpointLeafStatsGadget::create_virtual(builder);

                    let historical_proof =
                        HistoricalRootMerkleProofGadget::add_virtual_to_zero_gt::<H, F, D>(builder, CHECKPOINT_TREE_HEIGHT as usize);

                    builder.connect(historical_proof.index, requested_checkpoint_id);
                    builder.connect_hashes(historical_proof.current_root, self.checkpoint_tree_root);

                    let checkpoint_stats_hash = requested_checkpoint_stats.to_hash::<H, F, D>(builder);
                    let requested_checkpoint_state_roots = PsyCheckpointGlobalStateRootsGadget::create_virtual(builder);
                    let state_roots_hash = requested_checkpoint_state_roots.to_hash::<H, F, D>(builder);
                    let checkpoint_leaf_hash = builder.hash_two_to_one::<H>(state_roots_hash, checkpoint_stats_hash);
                    builder.connect_hashes(historical_proof.current_value, checkpoint_leaf_hash);

                    self.insert_checkpoint_stats_gadget(
                        ck.clone(),
                        requested_checkpoint_stats.clone(),
                        requested_checkpoint_state_roots.clone(),
                        historical_proof,
                    );
                    requested_checkpoint_state_roots.to_targets()
                }
            }
            DPNStateCmd::ClearEntireTree(c) => {
                let ck = StateCommandCacheKey::new_clear_entire_tree_with_condition(c.condition, self.write_epoch);

                let result = if let Some(existing_result) = self.result_map.get(&ck) {
                    existing_result.clone()
                } else {
                    let condition = dpn.resolve_bool(builder, c.condition);
                    let zero_hash_constant = builder.constant_hash(H::get_zero_hash(self.contract_state_tree_height));

                    let new_end_state_root = builder.select_hash(condition, zero_hash_constant, self.end_contract_state_root);
                    self.end_contract_state_root = new_end_state_root;

                    let clear_tree_gadget = ClearEntireTreeGadget::create_virtual(builder);
                    let height_constant = builder.constant(F::from_canonical_usize(self.contract_state_tree_height));

                    builder.connect_hashes(clear_tree_gadget.zero_hash, zero_hash_constant);
                    builder.connect(clear_tree_gadget.state_tree_height, height_constant);

                    let index = self.clear_entire_tree_requests.len();
                    self.clear_entire_tree_requests.push(clear_tree_gadget.clone());
                    let ref_key = StateReaderReferenceKey::new_clear_entire_tree_key(index);
                    self.gadget_map.insert(ck.clone(), ref_key);

                    let result_hash = new_end_state_root;
                    let result = result_hash.elements.to_vec();
                    self.result_map.insert(ck, result.clone());
                    result
                };

                self.write_epoch += 1;
                result
            }
            DPNStateCmd::SetIMTContractStateValue(c) => {
                // ================================================================
                // SetIMTContractStateValue — Insert or Update a leaf in an
                // Indexed Merkle Tree (sorted linked-list over a Merkle tree).
                //
                // # IMT Leaf Structure
                //
                //   Each leaf is a struct with 13 field elements hashed by Poseidon:
                //
                //     IMTLeaf { key, value, next_key, next_index }
                //              (4)   (4)     (4)        (1)
                //
                //   Leaves form a sorted singly-linked list ordered by key.
                //   next_key/next_index point to the successor; zero = end of list.
                //
                // # Slot Layout
                //
                //     slot index:  [ base ] [ base+1 ] [ base+2 ] ...
                //     contents:    sentinel   leaf 1     leaf 2   ...
                //
                //   slot[base] = sentinel (key=0, value=0), always present.
                //   slot[base+N] = tree leaf N.
                //   Empty (never-written) slots store ZERO in the Merkle tree.
                //
                // # Operation Modes (mutually exclusive via witness booleans)
                //
                //   condition=0 ............ NOOP (all constraints gated off)
                //   condition=1, is_insert=0 UPDATE (change value, keep linked-list pointers)
                //   condition=1, is_insert=1 INSERT (add new leaf, splice into sorted list)
                //
                // ## UPDATE
                //
                //   Key already exists at some slot. Only the value changes:
                //
                //     Before:  ... -> [key=K, val=V_old, next=...] -> ...
                //     After:   ... -> [key=K, val=V_new, next=...] -> ...
                //
                //   One DMP:  slot[i]: hash(old_leaf) -> hash(new_leaf)
                //   Constraints: key, next_key, next_index unchanged.
                //
                // ## INSERT (two sub-cases)
                //
                //   Key does not exist. We must splice a new leaf into the sorted list.
                //   This always requires TWO DMPs executed in sequence:
                //
                //     DMP 1: update the predecessor slot (change its next pointer)
                //     DMP 2: write the new leaf into an empty slot
                //
                //   The state root chains:
                //
                //     end_state_root
                //         |
                //         v
                //     pred_dmp.old_root == end_state_root
                //         | (update predecessor's next pointer)
                //         v
                //     pred_dmp.new_root == new_leaf_dmp.old_root
                //         | (write new leaf into empty slot)
                //         v
                //     new_leaf_dmp.new_root  ==>  new end_state_root
                //
                //   ### INSERT with predecessor (insert_has_predecessor = true)
                //
                //     Predecessor is a real leaf with key < new_key.
                //     Splice new leaf between predecessor and its successor:
                //
                //     Before: ... -> [pred: key=A, next=(C,idx_C)] -> [C] -> ...
                //     After:  ... -> [pred: key=A, next=(B,idx_B)] -> [new: key=B,
                // next=(C,idx_C)] -> [C] -> ...
                //
                //     Ordering enforced: A < B < C  (or C==0 if pred was tail)
                //
                //   ### INSERT without predecessor (insert_has_predecessor = false)
                //
                //     New key is smaller than all existing keys.
                //     Predecessor is the sentinel (key=0, value=0).
                //
                //     First insert (empty IMT):
                //
                //       Before: [sentinel: next=(0,0)]              (virgin, slot=ZERO in tree)
                //       After:  [sentinel: next=(B,idx_B)] -> [new: key=B, next=(0,0)]
                //
                //       pred_dmp: ZERO -> hash(sentinel_new)
                //       leaf_dmp: ZERO -> hash(new_leaf)
                //
                //     Subsequent insert (new key is the new minimum):
                //
                //       Before: [sentinel: next=(A,idx_A)] -> [A] -> ...
                //       After:  [sentinel: next=(B,idx_B)] -> [new: key=B, next=(A,idx_A)] ->
                // [A] -> ...
                //
                //       Ordering enforced: B < A  (or A==0 if list was empty)
                //
                // ================================================================

                let condition = dpn.resolve_bool(builder, c.condition);
                let is_insert = builder.add_virtual_bool_target_safe();
                let is_update = builder.not(is_insert);
                let insert_has_predecessor = builder.add_virtual_bool_target_safe();
                let insert_empty_predecessor = builder.not(insert_has_predecessor);
                let condition_and_insert = builder.and(condition, is_insert);
                let condition_and_update = builder.and(condition, is_update);
                let condition_and_insert_with_predecessor = builder.and(condition_and_insert, insert_has_predecessor);
                let condition_and_insert_without_predecessor = builder.and(condition_and_insert, insert_empty_predecessor);
                let key_target = HashOutTarget {
                    elements: [
                        dpn.resolve_target(c.key[0]),
                        dpn.resolve_target(c.key[1]),
                        dpn.resolve_target(c.key[2]),
                        dpn.resolve_target(c.key[3]),
                    ],
                };
                let value_target = HashOutTarget {
                    elements: [
                        dpn.resolve_target(c.value[0]),
                        dpn.resolve_target(c.value[1]),
                        dpn.resolve_target(c.value[2]),
                        dpn.resolve_target(c.value[3]),
                    ],
                };

                let update_old_leaf = IMTLeafTargets::add_virtual_to(builder);
                let update_new_leaf = IMTLeafTargets::add_virtual_to(builder);
                let update_delta_proof = DeltaMerkleProofGadget::add_virtual_to::<H, F, D>(builder, self.contract_state_tree_height);

                let update_old_leaf_hash = update_old_leaf.hash::<H, F, D>(builder);
                let update_new_leaf_hash = update_new_leaf.hash::<H, F, D>(builder);
                // UPDATE path constraints (only enforced when condition_and_update = 1):

                // The leaf stored in the Merkle tree is the hash of the leaf struct.
                // Bind old/new leaf hashes to the delta proof's old/new slot values,
                // proving the delta proof covers exactly these two leaves.
                builder.connect_hashes_if_true(condition_and_update, update_old_leaf_hash, update_delta_proof.old_value);
                builder.connect_hashes_if_true(condition_and_update, update_new_leaf_hash, update_delta_proof.new_value);

                // An UPDATE must not move the leaf to a different position in the linked list:
                // key, next_key, and next_index must stay the same across the update.
                builder.connect_hashes_if_true(condition_and_update, update_old_leaf.key, update_new_leaf.key);
                builder.connect_hashes_if_true(condition_and_update, update_old_leaf.next_key, update_new_leaf.next_key);
                builder.connect_if_true(condition_and_update, update_old_leaf.next_index, update_new_leaf.next_index);

                // The delta proof's old_root must equal the current accumulated state root,
                // chaining this write onto the previous state transition.
                builder.connect_hashes_if_true(condition_and_update, update_delta_proof.old_root, self.end_contract_state_root);

                // The leaf being updated must be the one whose key matches the requested key,
                // and the new value must match the requested value.
                builder.connect_hashes_if_true(condition_and_update, update_old_leaf.key, key_target);
                builder.connect_hashes_if_true(condition_and_update, update_new_leaf.key, key_target);
                builder.connect_hashes_if_true(condition_and_update, update_new_leaf.value, value_target);

                let insert_predecessor_old_leaf = IMTLeafTargets::add_virtual_to(builder);
                let insert_predecessor_new_leaf = IMTLeafTargets::add_virtual_to(builder);
                let insert_new_leaf = IMTLeafTargets::add_virtual_to(builder);
                let insert_predecessor_delta_proof = DeltaMerkleProofGadget::add_virtual_to::<H, F, D>(builder, self.contract_state_tree_height);
                let insert_new_leaf_delta_proof = DeltaMerkleProofGadget::add_virtual_to::<H, F, D>(builder, self.contract_state_tree_height);

                let insert_pred_old_hash = insert_predecessor_old_leaf.hash::<H, F, D>(builder);
                let insert_pred_new_hash = insert_predecessor_new_leaf.hash::<H, F, D>(builder);
                let insert_new_leaf_hash = insert_new_leaf.hash::<H, F, D>(builder);
                let one = builder._true();
                let zero_hash = builder.constant_hash(HashOut::ZERO);

                // Predecessor DMP old_value consistency.
                //
                //   pred_dmp.old_value is what the Merkle tree currently stores at the
                //   predecessor's slot.  Two cases:
                //
                //     Case A — slot was previously written (normal):
                //       old_value = hash(pred_old_leaf)   =>  verify hash match
                //
                //     Case B — virgin sentinel (first insert into this IMT):
                //       old_value = ZERO  (slot never written)
                //       hash(default_leaf) = poseidon(0..0) != ZERO
                //       =>  cannot do hash match; instead verify pred_old is all-zeros
                //
                let pred_dmp_old_is_zero = builder.is_zero_hash(insert_predecessor_delta_proof.old_value);
                let pred_dmp_old_not_zero = builder.not(pred_dmp_old_is_zero);
                let sentinel_next_zero = builder.is_zero_hash(insert_predecessor_old_leaf.next_key);
                let new_lt_sentinel_next = is_qhashout_lt::<F, D>(builder, insert_new_leaf.key, insert_predecessor_old_leaf.next_key);
                let sentinel_ordering_ok = builder.or(sentinel_next_zero, new_lt_sentinel_next);
                let base_offset = dpn.resolve_target(c.base_offset);
                let capacity = dpn.resolve_target(c.capacity);
                let zero = builder.zero();
                let update_index = builder.select(condition_and_update, update_delta_proof.index, zero);
                let update_base = builder.select(condition_and_update, base_offset, zero);
                let update_capacity = builder.select(condition_and_update, capacity, zero);
                // admits the sentinel slot because the zero-key guard below
                // makes it unreachable as an update target
                Self::constrain_imt_read_index(builder, update_index, update_base, update_capacity);
                let key_is_zero = builder.is_zero_hash(key_target);
                builder.connect_if_true(condition, key_is_zero.target, zero);
                let active_base_offset = builder.select(condition_and_insert, base_offset, zero);
                let active_capacity = builder.select(condition_and_insert, capacity, zero);
                builder.range_check(active_base_offset, 34);
                builder.range_check(active_capacity, 32);
                let capacity_offset = builder.mul_const(F::from_canonical_u64(4), active_capacity);
                let last_leaf_offset = builder.add(active_base_offset, capacity_offset);
                let first_leaf_offset = builder.add_const(active_base_offset, F::from_canonical_u64(4));
                builder.range_check(insert_predecessor_delta_proof.index, self.contract_state_tree_height);
                builder.range_check(insert_new_leaf_delta_proof.index, self.contract_state_tree_height);
                let predecessor_offset = builder.mul_const(F::from_canonical_u64(4), insert_predecessor_delta_proof.index);
                let new_leaf_offset = builder.mul_const(F::from_canonical_u64(4), insert_new_leaf_delta_proof.index);
                let virgin_predecessor = builder.and(condition_and_insert, pred_dmp_old_is_zero);
                // Only this map's sentinel can supply a virgin predecessor.
                builder.connect_if_true(virgin_predecessor, predecessor_offset, active_base_offset);
                builder.connect_if_true(condition_and_insert_without_predecessor, predecessor_offset, active_base_offset);
                let predecessor_above_base = builder.is_less_than_or_equal(36, active_base_offset, predecessor_offset);
                let predecessor_below_end = builder.is_less_than_or_equal(36, predecessor_offset, last_leaf_offset);
                let predecessor_in_range = builder.and(predecessor_above_base, predecessor_below_end);
                builder.connect_if_true(condition_and_insert_with_predecessor, predecessor_in_range.target, one.target);
                let new_leaf_above_base = builder.is_less_than_or_equal(36, first_leaf_offset, new_leaf_offset);
                let new_leaf_below_end = builder.is_less_than_or_equal(36, new_leaf_offset, last_leaf_offset);
                let new_leaf_in_range = builder.and(new_leaf_above_base, new_leaf_below_end);
                builder.connect_if_true(condition_and_insert, new_leaf_in_range.target, one.target);
                // When old_value != 0: verify hash(pred_old) == old_value
                let cond_hash_check = builder.and(condition_and_insert, pred_dmp_old_not_zero);
                builder.connect_hashes_if_true(cond_hash_check, insert_pred_old_hash, insert_predecessor_delta_proof.old_value);
                // When old_value == 0 (virgin slot): pred_old must be entirely zero
                let cond_virgin = builder.and(condition_and_insert, pred_dmp_old_is_zero);
                for i in 0..4 {
                    builder.connect_zero_if_true(cond_virgin, insert_predecessor_old_leaf.key.elements[i]);
                    builder.connect_zero_if_true(cond_virgin, insert_predecessor_old_leaf.value.elements[i]);
                    builder.connect_zero_if_true(cond_virgin, insert_predecessor_old_leaf.next_key.elements[i]);
                }
                builder.connect_zero_if_true(cond_virgin, insert_predecessor_old_leaf.next_index);
                builder.connect_hashes_if_true(condition_and_insert, insert_pred_new_hash, insert_predecessor_delta_proof.new_value);
                builder.connect_hashes_if_true(condition_and_insert, insert_new_leaf_hash, insert_new_leaf_delta_proof.new_value);
                builder.connect_hashes_if_true(condition_and_insert, insert_new_leaf.key, key_target);
                builder.connect_hashes_if_true(condition_and_insert, insert_new_leaf.value, value_target);
                builder.connect_hashes_if_true(
                    condition_and_insert,
                    insert_predecessor_delta_proof.new_root,
                    insert_new_leaf_delta_proof.old_root,
                );
                builder.connect_hashes_if_true(
                    condition_and_insert,
                    insert_predecessor_delta_proof.old_root,
                    self.end_contract_state_root,
                );
                // The new leaf must be written into a never-used slot (old_value == ZERO).
                // The new leaf must be written into a never-used slot (old_value == ZERO).
                for i in 0..4 {
                    builder.connect_zero_if_true(condition_and_insert, insert_new_leaf_delta_proof.old_value.elements[i]);
                }

                // INSERT with predecessor:
                //
                //   ... -> [pred_old: key=A, val=V, next=(C, idx_C)] -> [C] -> ...
                //                          |
                //                          v  (splice)
                //   ... -> [pred_new: key=A, val=V, next=(B, idx_B)] -> [new: key=B, next=(C,
                // idx_C)] -> [C] -> ...
                //
                //   Pointer rewiring:
                //     new_leaf.next      = pred_old.next       (inherit successor)
                //     pred_new.next_key  = new_leaf.key        (predecessor -> new leaf)
                //     pred_new.next_index = new_leaf_dmp.index
                //     pred key/value unchanged
                //
                //   Ordering: A < B AND (B < C OR C == 0)
                //
                {
                    builder.connect_hashes_if_true(
                        condition_and_insert_with_predecessor,
                        insert_predecessor_old_leaf.key,
                        insert_predecessor_new_leaf.key,
                    );
                    builder.connect_hashes_if_true(
                        condition_and_insert_with_predecessor,
                        insert_predecessor_old_leaf.value,
                        insert_predecessor_new_leaf.value,
                    );
                    builder.connect_hashes_if_true(
                        condition_and_insert_with_predecessor,
                        insert_new_leaf.next_key,
                        insert_predecessor_old_leaf.next_key,
                    );
                    builder.connect_if_true(
                        condition_and_insert_with_predecessor,
                        insert_new_leaf.next_index,
                        insert_predecessor_old_leaf.next_index,
                    );
                    builder.connect_hashes_if_true(
                        condition_and_insert_with_predecessor,
                        insert_predecessor_new_leaf.next_key,
                        insert_new_leaf.key,
                    );
                    // pred_new.next_index = new_leaf_dmp.index
                    builder.connect_if_true(
                        condition_and_insert_with_predecessor,
                        insert_predecessor_new_leaf.next_index,
                        insert_new_leaf_delta_proof.index,
                    );

                    let pred_lt_new = is_qhashout_lt::<F, D>(builder, insert_predecessor_old_leaf.key, insert_new_leaf.key);
                    let next_key_is_zero = builder.is_zero_hash(insert_predecessor_old_leaf.next_key);
                    let new_lt_next = is_qhashout_lt::<F, D>(builder, insert_new_leaf.key, insert_predecessor_old_leaf.next_key);
                    let next_index_is_zero = builder.is_zero(insert_predecessor_old_leaf.next_index);
                    let is_last = builder.and(next_key_is_zero, next_index_is_zero);
                    let ordering_ok = builder.or(is_last, new_lt_next);
                    builder.connect_if_true(condition_and_insert_with_predecessor, pred_lt_new.target, one.target);
                    builder.connect_if_true(condition_and_insert_with_predecessor, ordering_ok.target, one.target);
                }

                // INSERT without predecessor (sentinel is the predecessor):
                //
                //   First insert (virgin sentinel):
                //
                //     [sentinel: key=0, val=0, next=(0,0)]    (slot = ZERO in tree)
                //                      |
                //                      v
                //     [sentinel: key=0, val=0, next=(B,idx)] -> [new: key=B, next=(0,0)]
                //
                //   Subsequent insert (new key B is new minimum, old minimum was A):
                //
                //     [sentinel: next=(A, idx_A)] -> [A] -> ...
                //                      |
                //                      v
                //     [sentinel: next=(B, idx_B)] -> [new: key=B, next=(A, idx_A)] -> [A] ->
                // ...
                //
                //   Same splice logic as with_predecessor, plus:
                //     - sentinel key and value are always zero
                //     - no need to check sentinel.key < new.key (0 < any nonzero key)
                //     - ordering: B < A  (or A == 0 if list was empty)
                //
                {
                    // Sentinel key and value are always zero.
                    for i in 0..4 {
                        builder.connect_zero_if_true(condition_and_insert_without_predecessor, insert_predecessor_old_leaf.key.elements[i]);
                        builder.connect_zero_if_true(condition_and_insert_without_predecessor, insert_predecessor_old_leaf.value.elements[i]);
                        builder.connect_zero_if_true(condition_and_insert_without_predecessor, insert_predecessor_new_leaf.key.elements[i]);
                        builder.connect_zero_if_true(condition_and_insert_without_predecessor, insert_predecessor_new_leaf.value.elements[i]);
                    }
                    // 1. new_leaf.next = sentinel_old.next (inherit successor)
                    builder.connect_hashes_if_true(
                        condition_and_insert_without_predecessor,
                        insert_new_leaf.next_key,
                        insert_predecessor_old_leaf.next_key,
                    );
                    builder.connect_if_true(
                        condition_and_insert_without_predecessor,
                        insert_new_leaf.next_index,
                        insert_predecessor_old_leaf.next_index,
                    );
                    // 2. sentinel_new.next_key = new_leaf.key (sentinel points to new leaf)
                    builder.connect_hashes_if_true(
                        condition_and_insert_without_predecessor,
                        insert_predecessor_new_leaf.next_key,
                        insert_new_leaf.key,
                    );
                    // sentinel_new.next_index = new_leaf_dmp.index
                    builder.connect_if_true(
                        condition_and_insert_without_predecessor,
                        insert_predecessor_new_leaf.next_index,
                        insert_new_leaf_delta_proof.index,
                    );
                    // A sentinel insertion must precede the current minimum unless the map is empty.
                    builder.connect_if_true(condition_and_insert_without_predecessor, sentinel_ordering_ok.target, one.target);
                }

                // State root multiplexing:
                //
                //   is_insert=1: new_root comes from the INSERT chain (new_leaf_dmp.new_root)
                //   is_insert=0: new_root comes from the UPDATE DMP (update_dmp.new_root)
                //   condition=0: root unchanged (NOOP)
                //
                //   condition=0:  end_state_root (unchanged)
                //   condition=1:  is_insert ? new_leaf_dmp.new_root : update_dmp.new_root
                //
                let write_new_root = builder.select_hash(is_insert, insert_new_leaf_delta_proof.new_root, update_delta_proof.new_root);
                let new_end_state_root = builder.select_hash(condition, write_new_root, self.end_contract_state_root);
                self.end_contract_state_root = new_end_state_root;

                // Result returned to DPN bytecode: [old_value, new_value] of the operated leaf.
                let result_old_value = builder.select_hash(is_insert, zero_hash, update_old_leaf.value);
                let result_new_value = builder.select_hash(is_insert, insert_new_leaf.value, update_new_leaf.value);
                let mut result = result_old_value.elements.to_vec();
                result.extend_from_slice(&result_new_value.elements);

                let ck = StateCommandCacheKey::new_write_imt_current_contract(c.condition, 0, self.write_epoch);
                self.insert_imt_set_gadget(
                    ck,
                    IMTSetGadget {
                        is_insert,
                        insert_has_predecessor,
                        update_old_leaf,
                        update_new_leaf,
                        update_delta_proof,
                        insert_predecessor_old_leaf,
                        insert_predecessor_new_leaf,
                        insert_new_leaf,
                        insert_predecessor_delta_proof,
                        insert_new_leaf_delta_proof,
                    },
                );

                self.write_epoch += 1;

                result
            }
            DPNStateCmd::GetSelfUserCurrentIMTContractStateValue(c) => {
                let ck = StateCommandCacheKey::new_read_imt_current_contract(c.key, c.base_offset, c.capacity, self.write_epoch);
                if let Some(existing_result) = self.result_map.get(&ck) {
                    existing_result.clone()
                } else {
                    let merkle_proof = MerkleProofGadget::add_virtual_to::<H, F, D>(builder, self.contract_state_tree_height);
                    Self::constrain_imt_read_index(builder, merkle_proof.index, dpn.resolve_target(c.base_offset), dpn.resolve_target(c.capacity));
                    let leaf = IMTLeafTargets::add_virtual_to(builder);
                    let query_key = HashOutTarget {
                        elements: [
                            dpn.resolve_target(c.key[0]),
                            dpn.resolve_target(c.key[1]),
                            dpn.resolve_target(c.key[2]),
                            dpn.resolve_target(c.key[3]),
                        ],
                    };
                    let leaf_hash = leaf.hash::<H, F, D>(builder);
                    let leaf_key_zero = builder.is_zero_hash(leaf.key);
                    let leaf_value_zero = builder.is_zero_hash(leaf.value);
                    let leaf_next_key_zero = builder.is_zero_hash(leaf.next_key);
                    let leaf_next_index_zero = builder.is_zero(leaf.next_index);
                    let leaf_key_and_value_zero = builder.and(leaf_key_zero, leaf_value_zero);
                    let leaf_next_zero = builder.and(leaf_next_key_zero, leaf_next_index_zero);
                    let leaf_is_empty = builder.and(leaf_key_and_value_zero, leaf_next_zero);
                    let leaf_is_nonempty = builder.not(leaf_is_empty);
                    let key_eq = builder.is_equal_hash(leaf.key, query_key);
                    let is_member = builder.and(leaf_is_nonempty, key_eq);
                    let is_missing = builder.not(is_member);
                    let nonempty_missing = builder.and(is_missing, leaf_is_nonempty);
                    let pred_lt_query = is_qhashout_lt::<F, D>(builder, leaf.key, query_key);
                    let next_key_zero = builder.is_zero_hash(leaf.next_key);
                    let query_lt_next = is_qhashout_lt::<F, D>(builder, query_key, leaf.next_key);
                    let next_ok = builder.or(next_key_zero, query_lt_next);
                    let non_member = builder.and(pred_lt_query, next_ok);
                    let one = builder._true();
                    // A missing key must be bracketed by an authenticated
                    // predecessor. An empty map uses its zero sentinel slot.
                    builder.connect_if_true(nonempty_missing, non_member.target, one.target);
                    builder.connect_hashes(merkle_proof.root, self.end_contract_state_root);
                    builder.connect_hashes_if_true(leaf_is_nonempty, leaf_hash, merkle_proof.value);
                    let zero_hash = builder.constant_hash(HashOut::ZERO);
                    builder.connect_hashes_if_true(leaf_is_empty, merkle_proof.value, zero_hash);
                    let state_slot_base = Self::imt_sentinel_slot(builder, dpn, c.base_offset);
                    builder.connect_if_true(leaf_is_empty, merkle_proof.index, state_slot_base);
                    self.insert_imt_read_gadget(
                        ck,
                        IMTReadGadget {
                            merkle_proof,
                            leaf: leaf.clone(),
                        },
                    );
                    let zero = builder.zero();
                    let result = leaf.value.elements.iter().map(|value| builder.select(is_member, *value, zero)).collect::<Vec<_>>();
                    self.result_map.insert(ck, result.clone());
                    result
                }
            }
            DPNStateCmd::ContainsSelfUserCurrentIMTContractStateValue(c) => {
                let ck = StateCommandCacheKey::new_read_imt_contains_current_contract(c.key, c.base_offset, c.capacity, self.write_epoch);
                if let Some(existing_result) = self.result_map.get(&ck) {
                    existing_result.clone()
                } else {
                    let end_contract_state_root = self.end_contract_state_root;
                    let mp = MerkleProofGadget::add_virtual_to::<H, F, D>(builder, self.contract_state_tree_height);
                    Self::constrain_imt_read_index(builder, mp.index, dpn.resolve_target(c.base_offset), dpn.resolve_target(c.capacity));

                    // Witnessed IMT leaf preimage and existence selector.
                    let leaf = IMTLeafTargets::add_virtual_to(builder);
                    let exists = builder.add_virtual_bool_target_safe();

                    let leaf_hash = leaf.hash::<H, F, D>(builder);
                    let zero_hash = builder.constant_hash(HashOut::ZERO);
                    let leaf_key_zero = builder.is_zero_hash(leaf.key);
                    let leaf_value_zero = builder.is_zero_hash(leaf.value);
                    let leaf_next_key_zero = builder.is_zero_hash(leaf.next_key);
                    let leaf_next_index_zero = builder.is_zero(leaf.next_index);
                    let leaf_key_and_value_zero = builder.and(leaf_key_zero, leaf_value_zero);
                    let leaf_next_zero = builder.and(leaf_next_key_zero, leaf_next_index_zero);
                    let leaf_is_empty = builder.and(leaf_key_and_value_zero, leaf_next_zero);

                    // key targets from command input
                    let query_key = HashOutTarget {
                        elements: [
                            dpn.resolve_target(c.key[0]),
                            dpn.resolve_target(c.key[1]),
                            dpn.resolve_target(c.key[2]),
                            dpn.resolve_target(c.key[3]),
                        ],
                    };

                    // Membership branch: leaf.key == query_key
                    let key_eq = builder.is_equal_hash(leaf.key, query_key);

                    // The zero key is reserved for the sentinel and is never a
                    // member; its absence is witnessed by the sentinel leaf itself.
                    let query_key_zero = builder.is_zero_hash(query_key);
                    let zero_key_membership = builder.and(exists, query_key_zero);
                    builder.assert_zero(zero_key_membership.target);

                    // Non-membership requires a bracketing predecessor or a fully terminated tail.
                    let pred_lt_query = is_qhashout_lt::<F, D>(builder, leaf.key, query_key);
                    let next_key_zero = builder.is_zero_hash(leaf.next_key);
                    let query_lt_next = is_qhashout_lt::<F, D>(builder, query_key, leaf.next_key);
                    let is_last = builder.and(next_key_zero, leaf_next_index_zero);
                    let next_ok = builder.or(is_last, query_lt_next);
                    let sentinel_absence = builder.and(leaf_key_zero, query_key_zero);
                    let predecessor_ok = builder.or(pred_lt_query, sentinel_absence);
                    let non_member = builder.and(predecessor_ok, next_ok);

                    let one = builder._true();
                    let not_exists = builder.not(exists);
                    let empty_non_member = builder.and(not_exists, leaf_is_empty);
                    let non_empty_case = builder.not(empty_non_member);
                    builder.connect_hashes_if_true(non_empty_case, leaf_hash, mp.value);
                    builder.connect_hashes_if_true(empty_non_member, mp.value, zero_hash);
                    let slot_offset = builder.mul_const(F::from_canonical_u64(4), mp.index);
                    builder.connect_if_true(empty_non_member, slot_offset, dpn.resolve_target(c.base_offset));
                    builder.connect_if_true(exists, key_eq.target, one.target);
                    let non_empty_non_member = builder.and(not_exists, non_empty_case);
                    builder.connect_if_true(non_empty_non_member, non_member.target, one.target);

                    builder.connect_hashes(mp.root, end_contract_state_root);
                    self.insert_imt_contains_gadget(ck, mp, leaf, exists.target);

                    let result = vec![exists.target];
                    self.result_map.insert(ck, result.clone());
                    result
                }
            }
            DPNStateCmd::GetSelfUserExternalIMTContractStateValue(c) => {
                // Two proofs: UCT lookup (contract root in user's contract tree) + IMT leaf
                // lookup
                let read_root_ck = StateCommandCacheKey::new_read_self_user_external_contract_root(c.contract_id, self.contract_call_epoch);
                let uct_root = self.user_contract_tree_state_root;
                let call_epoch = self.contract_call_epoch;
                let expected_contract_state_tree_root = {
                    let (is_new_uct, mp_uct) =
                        self.resolve_or_insert_merkle_proof_gadget::<H, F, D>(builder, read_root_ck, GLOBAL_CONTRACT_TREE_HEIGHT as usize);
                    let expected_contract_state_tree_root = mp_uct.value.clone();
                    if is_new_uct {
                        builder.connect_hashes(mp_uct.root, uct_root);
                        let contract_id_target = dpn.resolve_target(c.contract_id);
                        builder.connect(mp_uct.index, contract_id_target);
                        let mp_uct: Vec<Target> = mp_uct.value.elements.to_vec();
                        self.result_map.insert(read_root_ck, mp_uct);
                    }
                    expected_contract_state_tree_root
                };
                let is_uninitialized = builder.is_zero_hash(expected_contract_state_tree_root);

                let imt_ck = StateCommandCacheKey::new_read_imt_self_user_external_contract(c.contract_id, c.key, c.contract_state_tree_height, c.base_offset, c.capacity, call_epoch);
                if let Some(existing_result) = self.result_map.get(&imt_ck) {
                    let zero = builder.zero();
                    existing_result.iter().map(|value| builder.select(is_uninitialized, zero, *value)).collect()
                } else {
                    let height = dpn.resolve_target(c.contract_state_tree_height);
                    let state_slot_proof = VariableHeightMerkleProofGadget::add_virtual_to_full::<H, F, D>(builder, 32, Some(height));
                    Self::constrain_imt_read_index(builder, state_slot_proof.index, dpn.resolve_target(c.base_offset), dpn.resolve_target(c.capacity));
                    let leaf = IMTLeafTargets::add_virtual_to(builder);
                    let query_key = HashOutTarget {
                        elements: [
                            dpn.resolve_target(c.key[0]),
                            dpn.resolve_target(c.key[1]),
                            dpn.resolve_target(c.key[2]),
                            dpn.resolve_target(c.key[3]),
                        ],
                    };
                    Self::connect_external_contract_state_root_if_initialized::<H, F, D>(
                        builder, expected_contract_state_tree_root, state_slot_proof.root, height,
                    );
                    let sentinel_slot = Self::imt_sentinel_slot(builder, dpn, c.base_offset);
                    let result = Self::connect_external_imt_get_leaf::<H, F, D>(
                        builder, &leaf, state_slot_proof.value, state_slot_proof.index, query_key, is_uninitialized,
                        sentinel_slot,
                    );
                    self.insert_imt_external_read_gadget(
                        imt_ck,
                        IMTExternalReadGadget {
                            contract_tree_proof: self.merkle_proofs[self.gadget_map[&read_root_ck].gadget_index].clone(),
                            state_slot_proof,
                            leaf: leaf.clone(),
                        },
                    );
                    self.result_map.insert(imt_ck, result.clone());
                    result
                }
            }
            DPNStateCmd::GetOtherUserIMTContractStateValue(c) => {
                // Full chain: user tree -> user leaf -> UCT -> IMT leaf
                let expected_contract_state_tree_root =
                    { self.get_other_user_contract_state_root::<H, F, D>(builder, dpn, c.user_id, c.contract_id) };
                let is_uninitialized = builder.is_zero_hash(expected_contract_state_tree_root);

                let imt_ck = StateCommandCacheKey::new_read_imt_other_user_contract(c.user_id, c.contract_id, c.key, c.contract_state_tree_height, c.base_offset, c.capacity, self.write_epoch);
                if let Some(existing_result) = self.result_map.get(&imt_ck) {
                    let zero = builder.zero();
                    existing_result.iter().map(|value| builder.select(is_uninitialized, zero, *value)).collect()
                } else {
                    let height = dpn.resolve_target(c.contract_state_tree_height);
                    let state_slot_proof = VariableHeightMerkleProofGadget::add_virtual_to_full::<H, F, D>(builder, 32, Some(height));
                    Self::constrain_imt_read_index(builder, state_slot_proof.index, dpn.resolve_target(c.base_offset), dpn.resolve_target(c.capacity));
                    let leaf = IMTLeafTargets::add_virtual_to(builder);
                    let query_key = HashOutTarget {
                        elements: [
                            dpn.resolve_target(c.key[0]),
                            dpn.resolve_target(c.key[1]),
                            dpn.resolve_target(c.key[2]),
                            dpn.resolve_target(c.key[3]),
                        ],
                    };
                    Self::connect_external_contract_state_root_if_initialized::<H, F, D>(
                        builder, expected_contract_state_tree_root, state_slot_proof.root, height,
                    );
                    let sentinel_slot = Self::imt_sentinel_slot(builder, dpn, c.base_offset);
                    let result = Self::connect_external_imt_get_leaf::<H, F, D>(
                        builder, &leaf, state_slot_proof.value, state_slot_proof.index, query_key, is_uninitialized,
                        sentinel_slot,
                    );
                    self.insert_imt_other_user_read_gadget(
                        imt_ck,
                        IMTOtherUserReadGadget {
                            state_slot_proof,
                            leaf: leaf.clone(),
                        },
                    );
                    self.result_map.insert(imt_ck, result.clone());
                    result
                }
            }
            DPNStateCmd::ContainsOtherUserIMTContractStateValue(c) => {
                // Resolve external root chain: user tree -> user leaf -> UCT -> contract IMT
                // root.
                let expected_contract_state_tree_root =
                    { self.get_other_user_contract_state_root::<H, F, D>(builder, dpn, c.user_id, c.contract_id) };
                let is_uninitialized = builder.is_zero_hash(expected_contract_state_tree_root);

                let imt_ck = StateCommandCacheKey::new_imt_contains_other_user_contract(c.user_id, c.contract_id, c.key, c.contract_state_tree_height, c.base_offset, c.capacity, self.write_epoch);
                if let Some(existing_result) = self.result_map.get(&imt_ck) {
                    let zero = builder.zero();
                    existing_result.iter().map(|value| builder.select(is_uninitialized, zero, *value)).collect()
                } else {
                    let height = dpn.resolve_target(c.contract_state_tree_height);
                    let state_slot_proof = VariableHeightMerkleProofGadget::add_virtual_to_full::<H, F, D>(builder, 32, Some(height));
                    Self::constrain_imt_read_index(builder, state_slot_proof.index, dpn.resolve_target(c.base_offset), dpn.resolve_target(c.capacity));
                    let leaf = IMTLeafTargets::add_virtual_to(builder);
                    let exists = builder.add_virtual_bool_target_safe();

                    let leaf_hash = leaf.hash::<H, F, D>(builder);
                    let zero_hash = builder.constant_hash(HashOut::ZERO);

                    // Detect a fully-empty leaf preimage (empty IMT non-membership predecessor).
                    let leaf_key_zero = builder.is_zero_hash(leaf.key);
                    let leaf_value_zero = builder.is_zero_hash(leaf.value);
                    let leaf_next_key_zero = builder.is_zero_hash(leaf.next_key);
                    let leaf_next_index_zero = builder.is_zero(leaf.next_index);
                    let leaf_key_and_value_zero = builder.and(leaf_key_zero, leaf_value_zero);
                    let leaf_next_zero = builder.and(leaf_next_key_zero, leaf_next_index_zero);
                    let leaf_is_empty = builder.and(leaf_key_and_value_zero, leaf_next_zero);

                    let query_key = HashOutTarget {
                        elements: [
                            dpn.resolve_target(c.key[0]),
                            dpn.resolve_target(c.key[1]),
                            dpn.resolve_target(c.key[2]),
                            dpn.resolve_target(c.key[3]),
                        ],
                    };

                    // Membership branch: leaf.key == query_key
                    let key_eq = builder.is_equal_hash(leaf.key, query_key);

                    // The zero key is reserved for the sentinel and is never a
                    // member; its absence is witnessed by the sentinel leaf itself.
                    let query_key_zero = builder.is_zero_hash(query_key);
                    let zero_key_membership = builder.and(exists, query_key_zero);
                    builder.assert_zero(zero_key_membership.target);

                    // Non-membership requires a bracketing predecessor or a fully terminated tail.
                    let pred_lt_query = is_qhashout_lt::<F, D>(builder, leaf.key, query_key);
                    let next_key_zero = builder.is_zero_hash(leaf.next_key);
                    let query_lt_next = is_qhashout_lt::<F, D>(builder, query_key, leaf.next_key);
                    let is_last = builder.and(next_key_zero, leaf_next_index_zero);
                    let next_ok = builder.or(is_last, query_lt_next);
                    let sentinel_absence = builder.and(leaf_key_zero, query_key_zero);
                    let predecessor_ok = builder.or(pred_lt_query, sentinel_absence);
                    let non_member = builder.and(predecessor_ok, next_ok);

                    let one = builder._true();
                    let not_exists = builder.not(exists);
                    let empty_non_member = builder.and(not_exists, leaf_is_empty);
                    let non_empty_case = builder.not(empty_non_member);
                    // Mirror ContainsSelf: leaf must hash to mp.value unless this is the
                    // empty-tree non-membership case, in which case the state slot is the
                    // zero hash.
                    builder.connect_hashes_if_true(non_empty_case, leaf_hash, state_slot_proof.value);
                    builder.connect_hashes_if_true(empty_non_member, state_slot_proof.value, zero_hash);
                    let slot_offset = builder.mul_const(F::from_canonical_u64(4), state_slot_proof.index);
                    builder.connect_if_true(empty_non_member, slot_offset, dpn.resolve_target(c.base_offset));
                    // exists => leaf.key == query_key
                    builder.connect_if_true(exists, key_eq.target, one.target);
                    // (!exists && !leaf_is_empty) => predecessor bracketing holds
                    let non_empty_non_member = builder.and(not_exists, non_empty_case);
                    builder.connect_if_true(non_empty_non_member, non_member.target, one.target);

                    Self::connect_external_contract_state_root_if_initialized::<H, F, D>(
                        builder, expected_contract_state_tree_root, state_slot_proof.root, height,
                    );
                    let false_target = builder._false().target;
                    builder.connect_if_true(is_uninitialized, exists.target, false_target);

                    self.insert_imt_contains_other_user_gadget(
                        imt_ck,
                        IMTContainsOtherUserGadget {
                            state_slot_proof,
                            leaf,
                            exists: exists.target,
                        },
                    );

                    let zero = builder.zero();
                    let result = vec![builder.select(is_uninitialized, zero, exists.target)];
                    self.result_map.insert(imt_ck, result.clone());
                    result
                }
            }
            DPNStateCmd::BurnStakedBalance(_) => Vec::new(),
        };
        value
    }
}

#[cfg(test)]
mod tests {
    use kvq::memory::simple::KVQSimpleMemoryBackingStore;
    use plonky2::{
        field::types::Field,
        hash::poseidon::PoseidonHash,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use psy_client_common::data::qhashout::QHashOut;
    use psy_client_data::qdata::{imt_contract_state::IMTContractStateLeaf, imt_proof::IMTContractStateUpdate};
    use psy_common_circuit::traits::CreatableTarget;
    use psy_crypto::hash::traits::{hasher::{FieldQHasher, PoseidonHasher}, qhashable::QFieldHashable};
    use psy_vm::dpn::ops::{
        op_types::{encode_indexed_op_id, DPNBuiltInDataType, DPNIndexedVarDef, DPNOpType},
        state_cmd::data::{DPNStateCmd, DPNStateCmdSetIMTContractStateValue},
    };

    use psy_client_data::models::user::contract_state_tree::UserContractStateTreeId;
    use psy_crypto::hash::merkle::core::MerkleProofCore;
    use psy_vm::dpn::ops::state_cmd::data::DPNStateCmdContainsSelfUserCurrentIMTContractStateValue;
    use plonky2::{iop::generator::{CopyGenerator, SimpleGenerator, WitnessGeneratorRef}, util::serialization::{Buffer, Read, Write}};
    use super::*;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type Store = KVQSimpleMemoryBackingStore;
    type IMT = psy_client_data::models::imt::IndexedMerkleTree<Store, F, PoseidonHash>;
    const TEST_TREE_HEIGHT: usize = 8;

    #[test]
    fn variable_height_range_accepts_unused_tail_and_rejects_index_alias() {
        use psy_crypto::hash::merkle::utils::simple_merkle_tree::SimpleMerkleTree;
        let tree = SimpleMerkleTree::<PoseidonHasher, QHashOut<F>>::new(4);
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let height = builder.constant(F::from_canonical_u64(4));
        let start = builder.zero();
        let (values, proofs) = StateReaderGadget::add_variable_height_merkle_proof_batch::<PoseidonHash, F, D>(
            &mut builder, height, start, 64, true,
        );
        builder.register_public_inputs(&values);
        let data = builder.build::<C>();
        for alias in [false, true] {
            let mut pw = PartialWitness::new();
            for (i, proof) in proofs.iter().enumerate() {
                let index = if alias && i == 16 { 16 } else { i.min(15) };
                let leaf = tree.get_leaf(if index == 16 { 0 } else { index as u64 });
                proof.set_witness_generic(&mut pw, F::from_canonical_usize(index), leaf.value, &leaf.siblings).unwrap();
            }
            if alias {
                assert!(data.prove(pw).is_err(), "index above the selected height must not alias a valid leaf");
            } else {
                let proof = data.prove(pw).unwrap();
                data.verify(proof).unwrap();
            }
        }
    }

    fn dummy_hash(builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        HashOutTarget {
            elements: [
                builder.add_virtual_target(),
                builder.add_virtual_target(),
                builder.add_virtual_target(),
                builder.add_virtual_target(),
            ],
        }
    }

    fn new_test_dpn(builder: &mut CircuitBuilder<F, D>) -> SimpleDPNBuilder<F, D> {
        let mut dpn = SimpleDPNBuilder::new_with_contract_ctx(
            Vec::new(),
            builder.zero(),
            builder.zero(),
            builder.zero(),
            builder.zero(),
            builder.zero(),
            dummy_hash(builder),
            dummy_hash(builder),
        );
        let base_offset = builder.zero();
        let capacity = builder.constant(F::from_canonical_u64(3));
        dpn.push_external_target(1000, base_offset);
        dpn.push_external_target(1001, capacity);
        dpn
    }
    fn prove_imt_absence(query: QHashOut<F>, leaf: IMTContractStateLeaf<F>, mp: MerkleProofCore<QHashOut<F>>, base_slot: u64) -> anyhow::Result<()> {
        prove_imt_read(query, leaf, mp, base_slot, false, false)
    }

    fn prove_imt_read(query: QHashOut<F>, leaf: IMTContractStateLeaf<F>, mp: MerkleProofCore<QHashOut<F>>, base_slot: u64, get: bool, alias: bool) -> anyhow::Result<()> {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let mut dpn = new_test_dpn(&mut builder);
        let base_offset = builder.constant(F::from_canonical_u64(base_slot * 4));
        dpn.push_external_target(0, base_offset);
        let query_targets: [Target; 4] = core::array::from_fn(|_| builder.add_virtual_target());
        for (i, target) in query_targets.into_iter().enumerate() {
            dpn.push_external_target(i + 1, target);
        }
        let root = builder.constant_hash(mp.root.0);
        let zero_hash = builder.constant_hash(HashOut::ZERO);
        let stats = PsyCheckpointLeafStatsGadget::create_virtual(&mut builder);
        let roots = PsyCheckpointGlobalStateRootsGadget::create_virtual(&mut builder);
        let mut reader = StateReaderGadget::new(roots, zero_hash, zero_hash, root, TEST_TREE_HEIGHT, zero_hash, TEST_TREE_HEIGHT, false, stats, zero_hash);
        let cmd = DPNStateCmd::ContainsSelfUserCurrentIMTContractStateValue(DPNStateCmdContainsSelfUserCurrentIMTContractStateValue {
            base_offset: encode_indexed_op_id(DPNBuiltInDataType::Target, 0),
            capacity: encode_indexed_op_id(DPNBuiltInDataType::Target, 1001),
            key: core::array::from_fn(|i| encode_indexed_op_id(DPNBuiltInDataType::Target, i + 1)),
        });
        let cmd = if get {
            DPNStateCmd::GetSelfUserCurrentIMTContractStateValue(psy_vm::dpn::ops::state_cmd::data::DPNStateCmdGetSelfUserCurrentIMTContractStateValue {
                base_offset: encode_indexed_op_id(DPNBuiltInDataType::Target, 0),
                capacity: encode_indexed_op_id(DPNBuiltInDataType::Target, 1001),
                key: core::array::from_fn(|i| encode_indexed_op_id(DPNBuiltInDataType::Target, i + 1)),
            })
        } else { cmd };
        reader.injest_symbolic_state_command::<PoseidonHash, F, D>(&mut builder, &dpn, &cmd);
        let mut data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        for (target, value) in query_targets.into_iter().zip(query.0.elements) {
            pw.set_target(target, value)?;
        }
        if alias {
            let mut replacements = 0;
            for generator in &mut data.prover_only.generators {
                if generator.0.id() != "LowHighGenerator" { continue; }
                let mut bytes = Vec::new();
                generator.0.serialize(&mut bytes, &data.common).unwrap();
                let mut buffer = Buffer::new(&bytes);
                let integer = buffer.read_target().unwrap();
                let bits = buffer.read_usize().unwrap();
                let low = buffer.read_target().unwrap();
                let high = buffer.read_target().unwrap();
                if integer != query_targets[0] || bits != 32 { continue; }
                pw.set_target(low, query.0.elements[0] + F::ONE)?;
                pw.set_target(high, F::from_canonical_u64(u32::MAX as u64))?;
                let mut copy = Vec::new();
                copy.write_target(low).unwrap();
                copy.write_target(low).unwrap();
                let replacement = <CopyGenerator as SimpleGenerator<F, D>>::deserialize(&mut Buffer::new(&copy), &data.common).unwrap();
                *generator = WitnessGeneratorRef::new(replacement.adapter());
                replacements += 1;
            }
            assert!(replacements > 0);
        }
        if get {
            reader.imt_read_requests[0].leaf.set_witness(&mut pw, &leaf)?;
            reader.imt_read_requests[0].merkle_proof.set_witness_core_proof_q(&mut pw, &mp)?;
        } else {
            pw.set_target(reader.imt_contains_exists_targets[0], F::ZERO)?;
            reader.imt_contains_leaf_requests[0].set_witness(&mut pw, &leaf)?;
            reader.imt_contains_proofs[0].set_witness_core_proof_q(&mut pw, &mp)?;
        }
        data.verify(data.prove(pw)?)
    }

    #[test]
    fn absent_other_user_requires_canonical_synthetic_leaf() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let expected_hash = builder.add_virtual_hash();
        let requested_user_id = builder.add_virtual_target();
        let leaf = PsyUserLeafGadget {
            public_key: builder.add_virtual_hash(),
            user_state_tree_root: builder.add_virtual_hash(),
            balance: builder.add_virtual_target(),
            nonce: builder.add_virtual_target(),
            last_checkpoint_id: builder.add_virtual_target(),
            event_index: builder.add_virtual_target(),
            user_id: builder.add_virtual_target(),
        };
        StateReaderGadget::connect_authenticated_other_user_leaf::<PoseidonHash, F, D>(
            &mut builder, expected_hash, &leaf, requested_user_id,
        );
        let circuit = builder.build::<C>();

        let witness = |public_key: HashOut<F>, state_root: HashOut<F>| {
            let mut pw = PartialWitness::new();
            pw.set_hash_target(expected_hash, HashOut::ZERO).unwrap();
            pw.set_target(requested_user_id, F::from_canonical_u64(3)).unwrap();
            pw.set_hash_target(leaf.public_key, public_key).unwrap();
            pw.set_hash_target(leaf.user_state_tree_root, state_root).unwrap();
            for field in [leaf.balance, leaf.nonce, leaf.last_checkpoint_id, leaf.event_index] {
                pw.set_target(field, F::ZERO).unwrap();
            }
            pw.set_target(leaf.user_id, F::from_canonical_u64(3)).unwrap();
            pw
        };
        let empty_root = PoseidonHash::get_zero_hash(GLOBAL_CONTRACT_TREE_HEIGHT as usize);
        circuit.verify(circuit.prove(witness(HashOut::ZERO, empty_root)).unwrap()).unwrap();
        assert!(circuit.prove(witness(HashOut::ZERO, HashOut::ZERO)).is_err(), "forged contract root must fail");
        assert!(circuit.prove(witness(HashOut { elements: [F::ONE, F::ZERO, F::ZERO, F::ZERO] }, empty_root)).is_err(),
            "forged public key must fail");
    }

    #[test]
    fn imt_sentinel_slot_uses_resolved_base_offset() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let base_offset = builder.add_virtual_target();
        let mut dpn = new_test_dpn(&mut builder);
        // The compiled token method stores operand ID 15 here; the VM
        // resolves it to the contract layout's absolute felt offset.
        dpn.push_external_target(15, base_offset);
        let slot = StateReaderGadget::imt_sentinel_slot(&mut builder, &dpn, 15);
        builder.register_public_input(slot);
        let circuit = builder.build::<C>();
        let mut witness = PartialWitness::new();
        witness.set_target(base_offset, F::from_canonical_u64(8_589_934_680)).unwrap();
        let proof = circuit.prove(witness).unwrap();
        assert_eq!(proof.public_inputs, vec![F::from_canonical_u64(2_147_483_670)]);
        circuit.verify(proof).unwrap();
    }

    #[test]
    fn external_empty_state_root_requires_canonical_height() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let contract_root = builder.add_virtual_hash();
        let proof_root = builder.add_virtual_hash();
        let height = builder.add_virtual_target();
        StateReaderGadget::connect_external_contract_state_root_if_initialized::<PoseidonHash, F, D>(
            &mut builder, contract_root, proof_root, height,
        );
        let data = builder.build::<C>();
        let empty_height_two = PoseidonHash::get_zero_hash(2);

        let mut valid_empty = PartialWitness::new();
        valid_empty.set_hash_target(contract_root, HashOut::ZERO).unwrap();
        valid_empty.set_hash_target(proof_root, empty_height_two).unwrap();
        valid_empty.set_target(height, F::from_canonical_u64(2)).unwrap();
        data.verify(data.prove(valid_empty).expect("canonical empty root must prove"))
            .expect("canonical empty root must verify");

        let mut wrong_height = PartialWitness::new();
        wrong_height.set_hash_target(contract_root, HashOut::ZERO).unwrap();
        wrong_height.set_hash_target(proof_root, empty_height_two).unwrap();
        wrong_height.set_target(height, F::from_canonical_u64(3)).unwrap();
        assert!(data.prove(wrong_height).is_err(), "empty root at the wrong height must fail");

        let mut forged_absence = PartialWitness::new();
        forged_absence.set_hash_target(contract_root, HashOut::ZERO).unwrap();
        forged_absence.set_hash_target(proof_root, HashOut::ZERO).unwrap();
        forged_absence.set_target(height, F::from_canonical_u64(2)).unwrap();
        assert!(data.prove(forged_absence).is_err(), "zero outer leaf cannot bypass the inner root check");

        let mut initialized = PartialWitness::new();
        initialized.set_hash_target(contract_root, empty_height_two).unwrap();
        initialized.set_hash_target(proof_root, empty_height_two).unwrap();
        initialized.set_target(height, F::from_canonical_u64(2)).unwrap();
        data.verify(data.prove(initialized).expect("initialized matching root must prove"))
            .expect("initialized matching root must verify");

        let mut wrong_initialized_path = PartialWitness::new();
        wrong_initialized_path.set_hash_target(contract_root, empty_height_two).unwrap();
        wrong_initialized_path.set_hash_target(proof_root, PoseidonHash::get_zero_hash(3)).unwrap();
        wrong_initialized_path.set_target(height, F::from_canonical_u64(2)).unwrap();
        assert!(data.prove(wrong_initialized_path).is_err(), "initialized contract must reject a mismatched state proof root");
    }

    #[test]
    fn external_imt_missing_key_requires_authenticated_predecessor() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let leaf_targets = IMTLeafTargets::add_virtual_to(&mut builder);
        let proof_value = builder.add_virtual_hash();
        let proof_index = builder.add_virtual_target();
        let query_key = builder.add_virtual_hash();
        let uninitialized = builder.add_virtual_bool_target_safe();
        let sentinel_slot = builder.zero();
        let result = StateReaderGadget::connect_external_imt_get_leaf::<PoseidonHash, F, D>(
            &mut builder, &leaf_targets, proof_value, proof_index, query_key, uninitialized, sentinel_slot,
        );
        builder.register_public_inputs(&result);
        let data = builder.build::<C>();
        let predecessor = IMTContractStateLeaf::new(
            QHashOut::from_values(3, 0, 0, 0),
            QHashOut::from_values(9, 0, 0, 0),
            QHashOut::ZERO,
            F::ZERO,
        );

        let witness = |leaf: &IMTContractStateLeaf<F>, value: HashOut<F>, index: u64, key: u64| {
            let mut pw = PartialWitness::new();
            leaf_targets.set_witness(&mut pw, leaf).unwrap();
            pw.set_hash_target(proof_value, value).unwrap();
            pw.set_target(proof_index, F::from_canonical_u64(index)).unwrap();
            pw.set_hash_target(query_key, QHashOut::from_values(key, 0, 0, 0).0).unwrap();
            pw.set_target(uninitialized.target, F::ZERO).unwrap();
            pw
        };

        let missing = witness(&predecessor, predecessor.qfhash::<PoseidonHasher>().0, 1, 4);
        let proof = data.prove(missing).expect("authenticated predecessor must prove missing key");
        assert_eq!(proof.public_inputs, vec![F::ZERO; 4]);
        data.verify(proof).expect("missing-key proof must verify");

        let wrong_order = witness(&predecessor, predecessor.qfhash::<PoseidonHasher>().0, 1, 2);
        assert!(data.prove(wrong_order).is_err(), "predecessor after query key must fail");

        let wrong_leaf_hash = witness(&predecessor, HashOut::ZERO, 1, 4);
        assert!(data.prove(wrong_leaf_hash).is_err(), "forged predecessor leaf hash must fail");

        let empty = IMTContractStateLeaf::<F>::default();
        let wrong_empty_index = witness(&empty, HashOut::ZERO, 1, 4);
        assert!(data.prove(wrong_empty_index).is_err(), "empty-map sentinel must be at its base slot");
    }

    #[test]
    fn state_reader_imt_contains_aliased_query_rejected() {
        let store = Store::new();
        let mut imt = IMT::new(&store, 1, 1, TEST_TREE_HEIGHT as u8, 100).unwrap();
        for key in [10, 20] {
            let key = QHashOut::from_values(key, 0, 0, 0);
            imt.insert(&store, key, key).unwrap();
        }
        let tail = imt.get_membership_proof(&store, &QHashOut::from_values(20, 0, 0, 0)).unwrap();
        assert!(prove_imt_read(QHashOut::from_values(10, 0, 0, 0), tail.leaf, tail.merkle_proof, 0, false, true).is_err());
    }

    #[test]
    fn state_reader_imt_foreign_map_reads_rejected() {
        let store = Store::new();
        let tree = UserContractStateTreeId::<Store, F, PoseidonHash>::new(1, 1, TEST_TREE_HEIGHT as u8);
        let key = QHashOut::from_values(10, 0, 0, 0);
        let leaf = IMTContractStateLeaf::new(key, key, QHashOut::ZERO, F::ZERO);
        tree.set_leaf_ucs(&store, 100, 5, leaf.qfhash::<PoseidonHash>()).unwrap();
        let mp = tree.get_leaf_ucs(&store, 100, 5).unwrap();
        let get_rejected = prove_imt_read(key, leaf, mp.clone(), 0, true, false).is_err();
        let contains_rejected = prove_imt_absence(QHashOut::from_values(20, 0, 0, 0), leaf, mp, 0).is_err();
        assert!(get_rejected && contains_rejected, "get_rejected={get_rejected}, contains_rejected={contains_rejected}");
    }

    #[test]
    fn state_reader_imt_two_maps_same_key_prove() {
        let store = Store::new();
        let tree = UserContractStateTreeId::<Store, F, PoseidonHash>::new(1, 1, TEST_TREE_HEIGHT as u8);
        let key = QHashOut::from_values(10, 0, 0, 0);
        let leaves = [11, 22].map(|value| IMTContractStateLeaf::new(key, QHashOut::from_values(value, 0, 0, 0), QHashOut::ZERO, F::ZERO));
        for (index, leaf) in [1, 5].into_iter().zip(leaves) {
            tree.set_leaf_ucs(&store, 100, index, leaf.qfhash::<PoseidonHash>()).unwrap();
        }
        let proofs = [1, 5].map(|index| tree.get_leaf_ucs(&store, 100, index).unwrap());
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let mut dpn = new_test_dpn(&mut builder);
        for (i, value) in key.0.elements.into_iter().enumerate() {
            let target = builder.constant(value);
            dpn.push_external_target(i, target);
        }
        let second_base = builder.constant(F::from_canonical_u64(16));
        dpn.push_external_target(1002, second_base);
        let root = builder.constant_hash(proofs[0].root.0);
        let zero = builder.constant_hash(HashOut::ZERO);
        let stats = PsyCheckpointLeafStatsGadget::create_virtual(&mut builder);
        let roots = PsyCheckpointGlobalStateRootsGadget::create_virtual(&mut builder);
        let mut reader = StateReaderGadget::new(roots, zero, zero, root, TEST_TREE_HEIGHT, zero, TEST_TREE_HEIGHT, false, stats, zero);
        for base in [1000, 1002] {
            let key = core::array::from_fn(|i| encode_indexed_op_id(DPNBuiltInDataType::Target, i));
            let base_offset = encode_indexed_op_id(DPNBuiltInDataType::Target, base);
            let capacity = encode_indexed_op_id(DPNBuiltInDataType::Target, 1001);
            let cmd = DPNStateCmd::GetSelfUserCurrentIMTContractStateValue(psy_vm::dpn::ops::state_cmd::data::DPNStateCmdGetSelfUserCurrentIMTContractStateValue { base_offset, capacity, key });
            let value = reader.injest_symbolic_state_command::<PoseidonHash, F, D>(&mut builder, &dpn, &cmd);
            builder.register_public_inputs(&value);
            let cmd = DPNStateCmd::ContainsSelfUserCurrentIMTContractStateValue(DPNStateCmdContainsSelfUserCurrentIMTContractStateValue { base_offset, capacity, key });
            reader.injest_symbolic_state_command::<PoseidonHash, F, D>(&mut builder, &dpn, &cmd);
        }
        assert_eq!(reader.imt_read_requests.len(), 2);
        assert_eq!(reader.imt_contains_proofs.len(), 2);
        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        for i in 0..2 {
            reader.imt_read_requests[i].leaf.set_witness(&mut pw, &leaves[i]).unwrap();
            reader.imt_read_requests[i].merkle_proof.set_witness_core_proof_q(&mut pw, &proofs[i]).unwrap();
            reader.imt_contains_leaf_requests[i].set_witness(&mut pw, &leaves[i]).unwrap();
            reader.imt_contains_proofs[i].set_witness_core_proof_q(&mut pw, &proofs[i]).unwrap();
            pw.set_target(reader.imt_contains_exists_targets[i], F::ONE).unwrap();
        }
        let proof = data.prove(pw).unwrap();
        assert_eq!(proof.public_inputs[0], F::from_canonical_u64(11));
        assert_eq!(proof.public_inputs[4], F::from_canonical_u64(22));
        data.verify(proof).unwrap();
    }

    #[test]
    fn state_reader_other_user_imt_two_maps_same_key_use_separate_gadgets() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let mut dpn = new_test_dpn(&mut builder);
        for index in 0..6 {
            let target = builder.constant(F::from_canonical_usize(index + 1));
            dpn.push_external_target(index, target);
        }
        let second_base = builder.constant(F::from_canonical_u64(16));
        dpn.push_external_target(1002, second_base);
        let zero = builder.constant_hash(HashOut::ZERO);
        let stats = PsyCheckpointLeafStatsGadget::create_virtual(&mut builder);
        let roots = PsyCheckpointGlobalStateRootsGadget::create_virtual(&mut builder);
        let mut reader = StateReaderGadget::new(roots, zero, zero, zero, TEST_TREE_HEIGHT, zero, TEST_TREE_HEIGHT, false, stats, zero);
        let target = |index| encode_indexed_op_id(DPNBuiltInDataType::Target, index);
        let key = [target(2), target(3), target(4), target(5)];
        for base in [1000, 1002] {
            let get = DPNStateCmd::get_other_user_imt_contract_state_value(target(0), target(1), target(1001), target(base), target(1001), key);
            let contains = DPNStateCmd::contains_other_user_imt_contract_state_value(target(0), target(1), target(1001), target(base), target(1001), key);
            let external = DPNStateCmd::get_self_user_external_imt_contract_state_value(target(1), target(1001), target(base), target(1001), key);
            reader.injest_symbolic_state_command::<PoseidonHash, F, D>(&mut builder, &dpn, &get);
            reader.injest_symbolic_state_command::<PoseidonHash, F, D>(&mut builder, &dpn, &contains);
            reader.injest_symbolic_state_command::<PoseidonHash, F, D>(&mut builder, &dpn, &external);
        }
        assert_eq!((reader.imt_other_user_read_requests.len(), reader.imt_contains_other_user_requests.len()), (2, 2));
        assert_eq!(reader.imt_external_read_requests.len(), 2);
    }

    #[test]
    fn state_reader_imt_contains_zero_key_sentinel_membership_rejected() {
        let store = Store::new();
        let mut imt = IMT::new(&store, 1, 1, TEST_TREE_HEIGHT as u8, 100).unwrap();
        let key = QHashOut::from_values(10, 0, 0, 0);
        imt.insert(&store, key, key).unwrap();
        let sentinel = imt.get_membership_proof(&store, &QHashOut::ZERO).unwrap();
        assert_eq!(sentinel.merkle_proof.index, 0);
        assert_eq!(sentinel.leaf.key, QHashOut::ZERO);

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let mut dpn = new_test_dpn(&mut builder);
        for i in 0..4 {
            let zero = builder.zero();
            dpn.push_external_target(i, zero);
        }
        let root = builder.constant_hash(sentinel.merkle_proof.root.0);
        let zero = builder.constant_hash(HashOut::ZERO);
        let stats = PsyCheckpointLeafStatsGadget::create_virtual(&mut builder);
        let roots = PsyCheckpointGlobalStateRootsGadget::create_virtual(&mut builder);
        let mut reader = StateReaderGadget::new(roots, zero, zero, root, TEST_TREE_HEIGHT, zero, TEST_TREE_HEIGHT, false, stats, zero);
        let cmd = DPNStateCmd::ContainsSelfUserCurrentIMTContractStateValue(DPNStateCmdContainsSelfUserCurrentIMTContractStateValue {
            base_offset: encode_indexed_op_id(DPNBuiltInDataType::Target, 1000),
            capacity: encode_indexed_op_id(DPNBuiltInDataType::Target, 1001),
            key: core::array::from_fn(|i| encode_indexed_op_id(DPNBuiltInDataType::Target, i)),
        });
        let result = reader.injest_symbolic_state_command::<PoseidonHash, F, D>(&mut builder, &dpn, &cmd);
        builder.register_public_inputs(&result);
        let data = builder.build::<C>();

        let witness = |exists: F| {
            let mut pw = PartialWitness::new();
            reader.imt_contains_leaf_requests[0].set_witness(&mut pw, &sentinel.leaf).unwrap();
            reader.imt_contains_proofs[0].set_witness_core_proof_q(&mut pw, &sentinel.merkle_proof).unwrap();
            pw.set_target(reader.imt_contains_exists_targets[0], exists).unwrap();
            pw
        };

        // The reserved zero key must never prove as a member via the sentinel leaf.
        assert!(data.prove(witness(F::ONE)).is_err());

        // Its absence is witnessed by the sentinel leaf itself.
        let proof = data.prove(witness(F::ZERO)).unwrap();
        assert_eq!(proof.public_inputs, vec![F::ZERO]);
        data.verify(proof).unwrap();
    }

    #[test]
    fn state_reader_other_user_imt_contains_zero_key_sentinel_membership_rejected() {
        use psy_client_data::qdata::user::PsyUserLeaf;
        use psy_crypto::hash::merkle::utils::simple_merkle_tree::SimpleMerkleTree;

        let store = Store::new();
        let mut imt = IMT::new(&store, 1, 1, TEST_TREE_HEIGHT as u8, 100).unwrap();
        let key = QHashOut::from_values(10, 0, 0, 0);
        imt.insert(&store, key, key).unwrap();
        let sentinel = imt.get_membership_proof(&store, &QHashOut::ZERO).unwrap();
        assert_eq!(sentinel.merkle_proof.index, 0);
        assert_eq!(sentinel.leaf.key, QHashOut::ZERO);

        let contract_state_root = sentinel.merkle_proof.root;
        let mut uct = SimpleMerkleTree::<PoseidonHasher, QHashOut<F>>::new(GLOBAL_CONTRACT_TREE_HEIGHT);
        uct.set_leaf(1, contract_state_root);
        let uct_proof = uct.get_leaf(1);

        let user_leaf = PsyUserLeaf::new_user_default(F::from_canonical_u64(1), QHashOut::from_values(7, 0, 0, 0), uct.get_root());
        let mut user_tree = SimpleMerkleTree::<PoseidonHasher, QHashOut<F>>::new(GLOBAL_USER_TREE_HEIGHT);
        user_tree.set_leaf(1, user_leaf.qfhash::<PoseidonHasher>());
        let user_proof = user_tree.get_leaf(1);

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let mut dpn = new_test_dpn(&mut builder);
        dpn.push_external_target(0, builder.constant(F::from_canonical_u64(1)));
        dpn.push_external_target(1, builder.constant(F::from_canonical_u64(1)));
        dpn.push_external_target(2, builder.constant(F::from_canonical_u64(TEST_TREE_HEIGHT as u64)));
        for i in 3..7 {
            let zero = builder.zero();
            dpn.push_external_target(i, zero);
        }
        let zero = builder.constant_hash(HashOut::ZERO);
        let stats = PsyCheckpointLeafStatsGadget::create_virtual(&mut builder);
        let roots = PsyCheckpointGlobalStateRootsGadget::create_virtual(&mut builder);
        let mut reader = StateReaderGadget::new(roots, zero, zero, zero, TEST_TREE_HEIGHT, zero, TEST_TREE_HEIGHT, false, stats, zero);
        let target = |index| encode_indexed_op_id(DPNBuiltInDataType::Target, index);
        let key = [target(3), target(4), target(5), target(6)];
        let cmd = DPNStateCmd::contains_other_user_imt_contract_state_value(target(0), target(1), target(2), target(1000), target(1001), key);
        let result = reader.injest_symbolic_state_command::<PoseidonHash, F, D>(&mut builder, &dpn, &cmd);
        builder.register_public_inputs(&result);
        let data = builder.build::<C>();

        let witness = |exists: F| {
            let mut pw = PartialWitness::new();
            pw.set_hash_target(reader.chain_state_roots.user_tree_root, user_proof.root.0).unwrap();
            reader.merkle_proofs[0].set_witness_core_proof_q(&mut pw, &user_proof).unwrap();
            reader.merkle_proofs[1].set_witness_core_proof_q(&mut pw, &uct_proof).unwrap();
            reader.user_leaves[0].set_witness(&mut pw, &user_leaf).unwrap();
            let gadget = &reader.imt_contains_other_user_requests[0];
            gadget.state_slot_proof.set_witness_core_proof_q(&mut pw, &sentinel.merkle_proof).unwrap();
            gadget.leaf.set_witness(&mut pw, &sentinel.leaf).unwrap();
            pw.set_target(gadget.exists, exists).unwrap();
            pw
        };

        // The reserved zero key must never prove as a member via the sentinel leaf.
        assert!(data.prove(witness(F::ONE)).is_err());

        // Its absence is witnessed by the sentinel leaf itself.
        let proof = data.prove(witness(F::ZERO)).unwrap();
        assert_eq!(proof.public_inputs, vec![F::ZERO]);
        data.verify(proof).unwrap();
    }

    #[test]
    fn state_reader_imt_contains_membership_cannot_claim_absence() {
        let store = Store::new();
        let mut imt = IMT::new(&store, 1, 1, TEST_TREE_HEIGHT as u8, 100).unwrap();
        let key = QHashOut::from_values(10, 0, 0, 0);
        imt.insert(&store, key, key).unwrap();
        let proof = imt.get_membership_proof(&store, &key).unwrap();
        assert!(prove_imt_absence(key, proof.leaf, proof.merkle_proof, 0).is_err());
    }

    #[test]
    fn state_reader_imt_contains_bracketing_absence_proves() {
        let store = Store::new();
        let mut imt = IMT::new(&store, 1, 1, TEST_TREE_HEIGHT as u8, 100).unwrap();
        for key in [10, 30] {
            let key = QHashOut::from_values(key, 0, 0, 0);
            imt.insert(&store, key, key).unwrap();
        }
        let key = QHashOut::from_values(20, 0, 0, 0);
        let (index, leaf) = imt.find_predecessor(&key).unwrap();
        let tree = UserContractStateTreeId::<Store, F, PoseidonHash>::new(1, 1, TEST_TREE_HEIGHT as u8);
        prove_imt_absence(key, leaf, tree.get_leaf_ucs(&store, 100, index).unwrap(), 0).unwrap();
    }

    #[test]
    fn state_reader_imt_contains_wrong_empty_slot_rejected() {
        let store = Store::new();
        let mut imt = IMT::new(&store, 1, 1, TEST_TREE_HEIGHT as u8, 100).unwrap();
        let key = QHashOut::from_values(10, 0, 0, 0);
        imt.insert(&store, key, key).unwrap();
        let tree = UserContractStateTreeId::<Store, F, PoseidonHash>::new(1, 1, TEST_TREE_HEIGHT as u8);
        let mp = tree.get_leaf_ucs(&store, 100, 2).unwrap();
        assert_eq!(mp.value, QHashOut::ZERO);
        assert!(prove_imt_absence(key, IMTContractStateLeaf::default(), mp, 0).is_err());
    }

    #[test]
    fn state_reader_imt_contains_virgin_base_slot_proves() {
        let store = Store::new();
        let tree = UserContractStateTreeId::<Store, F, PoseidonHash>::new(1, 1, TEST_TREE_HEIGHT as u8);
        for key in [0, 10] {
            let mp = tree.get_leaf_ucs(&store, 100, 3).unwrap();
            assert_eq!(mp.value, QHashOut::ZERO);
            prove_imt_absence(QHashOut::from_values(key, 0, 0, 0), IMTContractStateLeaf::default(), mp, 3).unwrap();
        }
    }

    fn prove_imt_sentinel_insert(next_key: u64, has_predecessor: bool, predecessor_index: u64, new_index: u64, virgin: bool) -> anyhow::Result<()> {
        prove_imt_insert_key(QHashOut::from_values(10, 0, 0, 0), next_key, has_predecessor, predecessor_index, new_index, virgin)
    }

    fn prove_imt_insert_key(key: QHashOut<F>, next_key: u64, has_predecessor: bool, predecessor_index: u64, new_index: u64, virgin: bool) -> anyhow::Result<()> {
        prove_imt_write_key(key, next_key, has_predecessor, predecessor_index, new_index, virgin, false)
    }

    fn prove_imt_write_key(key: QHashOut<F>, next_key: u64, has_predecessor: bool, predecessor_index: u64, new_index: u64, virgin: bool, update: bool) -> anyhow::Result<()> {
        prove_imt_write_predecessor(key, next_key, has_predecessor, predecessor_index, new_index, virgin, update, false)
    }

    fn prove_imt_write_predecessor(key: QHashOut<F>, next_key: u64, has_predecessor: bool, predecessor_index: u64, new_index: u64, virgin: bool, update: bool, malformed_tail: bool) -> anyhow::Result<()> {
        let store = Store::new();
        let tree = UserContractStateTreeId::<Store, F, PoseidonHash>::new(1, 1, TEST_TREE_HEIGHT as u8);
        let value = QHashOut::from_values(100, 200, 300, 400);
        let mut predecessor_old_leaf = IMTContractStateLeaf::default();
        if next_key != 0 {
            predecessor_old_leaf.next_key = QHashOut::from_values(next_key, 0, 0, 0);
            predecessor_old_leaf.next_index = F::ONE;
            let old_minimum = IMTContractStateLeaf::new(predecessor_old_leaf.next_key, value, QHashOut::ZERO, F::ZERO);
            tree.set_leaf_ucs(&store, 100, 1, old_minimum.qfhash::<PoseidonHash>()).unwrap();
            tree.set_leaf_ucs(&store, 100, predecessor_index, predecessor_old_leaf.qfhash::<PoseidonHash>()).unwrap();
        }
        if malformed_tail {
            predecessor_old_leaf.next_index = F::ONE;
            tree.set_leaf_ucs(&store, 100, predecessor_index, predecessor_old_leaf.qfhash::<PoseidonHash>()).unwrap();
        }
        if virgin {
            let sentinel = IMTContractStateLeaf::new(QHashOut::ZERO, QHashOut::ZERO, key, F::ONE);
            tree.set_leaf_ucs(&store, 100, 0, sentinel.qfhash::<PoseidonHash>()).unwrap();
            let existing = IMTContractStateLeaf::new(key, value, QHashOut::ZERO, F::ZERO);
            tree.set_leaf_ucs(&store, 100, 1, existing.qfhash::<PoseidonHash>()).unwrap();
            predecessor_old_leaf = IMTContractStateLeaf::default();
        }
        let new_leaf = IMTContractStateLeaf::new(key, value, predecessor_old_leaf.next_key, predecessor_old_leaf.next_index);
        let predecessor_new_leaf = IMTContractStateLeaf::new(QHashOut::ZERO, QHashOut::ZERO, key, F::from_canonical_u64(new_index));
        let predecessor_delta_proof = tree.set_leaf_ucs(&store, 100, predecessor_index, predecessor_new_leaf.qfhash::<PoseidonHash>()).unwrap();
        let new_leaf_delta_proof = tree.set_leaf_ucs(&store, 100, new_index, new_leaf.qfhash::<PoseidonHash>()).unwrap();
        let update_old_leaf = IMTContractStateLeaf::new(key, QHashOut::ZERO, QHashOut::ZERO, F::ZERO);
        let update_new_leaf = IMTContractStateLeaf::new(key, value, QHashOut::ZERO, F::ZERO);
        tree.set_leaf_ucs(&store, 101, predecessor_index, update_old_leaf.qfhash::<PoseidonHash>()).unwrap();
        let update_proof = tree.set_leaf_ucs(&store, 101, predecessor_index, update_new_leaf.qfhash::<PoseidonHash>()).unwrap();

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let mut dpn = new_test_dpn(&mut builder);

        let condition_target = builder.add_virtual_target();
        let key_targets: [Target; 4] = core::array::from_fn(|_| builder.add_virtual_target());
        let value_targets: [Target; 4] = core::array::from_fn(|_| builder.add_virtual_target());
        dpn.push_external_target(0, condition_target);
        for (i, target) in key_targets.iter().copied().enumerate() {
            dpn.push_external_target(i + 1, target);
        }
        for (i, target) in value_targets.iter().copied().enumerate() {
            dpn.push_external_target(i + 5, target);
        }

        let start_root = builder.constant_hash(if update { update_proof.old_root.0 } else { predecessor_delta_proof.old_root.0 });
        let zero_hash = builder.constant_hash(HashOut::ZERO);
        let checkpoint_stats = PsyCheckpointLeafStatsGadget::create_virtual(&mut builder);
        let checkpoint_roots = PsyCheckpointGlobalStateRootsGadget::create_virtual(&mut builder);
        let checkpoint_tree_root = zero_hash;

        let mut state_reader = StateReaderGadget::new(
            checkpoint_roots,
            zero_hash,
            zero_hash,
            start_root,
            TEST_TREE_HEIGHT,
            zero_hash,
            TEST_TREE_HEIGHT,
            false,
            checkpoint_stats,
            checkpoint_tree_root,
        );

        let cmd = DPNStateCmd::SetIMTContractStateValue(DPNStateCmdSetIMTContractStateValue {
            condition: encode_indexed_op_id(DPNBuiltInDataType::Target, 0),
            base_offset: encode_indexed_op_id(DPNBuiltInDataType::Target, 1000),
            capacity: encode_indexed_op_id(DPNBuiltInDataType::Target, 1001),
            key: [
                encode_indexed_op_id(DPNBuiltInDataType::Target, 1),
                encode_indexed_op_id(DPNBuiltInDataType::Target, 2),
                encode_indexed_op_id(DPNBuiltInDataType::Target, 3),
                encode_indexed_op_id(DPNBuiltInDataType::Target, 4),
            ],
            value: [
                encode_indexed_op_id(DPNBuiltInDataType::Target, 5),
                encode_indexed_op_id(DPNBuiltInDataType::Target, 6),
                encode_indexed_op_id(DPNBuiltInDataType::Target, 7),
                encode_indexed_op_id(DPNBuiltInDataType::Target, 8),
            ],
        });

        let result = state_reader.injest_symbolic_state_command::<PoseidonHash, F, D>(&mut builder, &dpn, &cmd);
        builder.register_public_inputs(&state_reader.end_contract_state_root.elements);
        builder.register_public_inputs(&result);

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        pw.set_target(condition_target, F::ONE).unwrap();
        for (target, value) in key_targets.iter().copied().zip(key.0.elements.into_iter()) {
            pw.set_target(target, value).unwrap();
        }
        for (target, value) in value_targets.iter().copied().zip(value.0.elements.into_iter()) {
            pw.set_target(target, value).unwrap();
        }

        let gadget = &state_reader.imt_set_requests[0];
        pw.set_bool_target(gadget.is_insert, !update).unwrap();
        pw.set_bool_target(gadget.insert_has_predecessor, has_predecessor).unwrap();
        gadget.update_old_leaf.set_witness(&mut pw, &if update { update_old_leaf } else { IMTContractStateLeaf::default() }).unwrap();
        gadget.update_new_leaf.set_witness(&mut pw, &if update { update_new_leaf } else { new_leaf }).unwrap();
        gadget
            .update_delta_proof
            .set_witness_core_proof_q(&mut pw, if update { &update_proof } else { &predecessor_delta_proof })
            .unwrap();
        gadget.insert_predecessor_old_leaf.set_witness(&mut pw, &predecessor_old_leaf).unwrap();
        gadget.insert_predecessor_new_leaf.set_witness(&mut pw, &predecessor_new_leaf).unwrap();
        gadget.insert_new_leaf.set_witness(&mut pw, &new_leaf).unwrap();
        gadget
            .insert_predecessor_delta_proof
            .set_witness_core_proof_q(&mut pw, &predecessor_delta_proof)
            .unwrap();
        gadget
            .insert_new_leaf_delta_proof
            .set_witness_core_proof_q(&mut pw, &new_leaf_delta_proof)
            .unwrap();

        let proof = data.prove(pw)?;
        assert_eq!(proof.public_inputs[0], if update { update_proof.new_root.0.elements[0] } else { new_leaf_delta_proof.new_root.0.elements[0] });
        assert_eq!(proof.public_inputs[4], F::ZERO);
        assert_eq!(proof.public_inputs[8], new_leaf.value.0.elements[0]);
        data.verify(proof)
    }

    #[test]
    fn state_reader_imt_zero_key_update_rejected() {
        assert!(prove_imt_write_key(QHashOut::ZERO, 0, false, 0, 2, false, true).is_err());
        prove_imt_write_key(QHashOut::from_values(10, 0, 0, 0), 0, false, 0, 2, false, true).unwrap();
    }

    #[test]
    fn state_reader_imt_malformed_insert_tail_rejected() {
        assert!(prove_imt_write_predecessor(QHashOut::from_values(10, 0, 0, 0), 0, true, 0, 2, false, false, true).is_err());
        prove_imt_write_predecessor(QHashOut::from_values(10, 0, 0, 0), 0, true, 0, 2, false, false, false).unwrap();
    }

    #[test]
    fn state_reader_imt_foreign_map_update_rejected() {
        let key = QHashOut::from_values(10, 0, 0, 0);
        assert!(prove_imt_write_key(key, 0, false, 5, 2, false, true).is_err());
        prove_imt_write_key(key, 0, false, 3, 2, false, true).unwrap();
    }

    #[test]
    fn state_reader_imt_set_first_insert_proves() {
        prove_imt_sentinel_insert(0, false, 0, 2, false).unwrap();
    }

    #[test]
    fn state_reader_imt_set_new_minimum_proves() {
        prove_imt_sentinel_insert(20, false, 0, 2, false).unwrap();
    }

    #[test]
    fn state_reader_imt_set_unordered_sentinel_insert_rejected() {
        assert!(prove_imt_sentinel_insert(5, false, 0, 2, false).is_err());
    }

    #[test]
    fn state_reader_imt_delta_index_alias_rejected() {
        let store = Store::new();
        let tree = UserContractStateTreeId::<Store, F, PoseidonHash>::new(1, 1, TEST_TREE_HEIGHT as u8);
        let mut mp = tree.set_leaf_ucs(&store, 100, 2, QHashOut::ZERO).unwrap();
        mp.index = 0xbfffffff40000003;
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let gadget = DeltaMerkleProofGadget::add_virtual_to::<PoseidonHash, F, D>(&mut builder, TEST_TREE_HEIGHT);
        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        gadget.set_witness_core_proof_q(&mut pw, &mp).unwrap();
        assert!(data.prove(pw).is_err());
    }

    #[test]
    fn state_reader_imt_set_zero_key_rejected() {
        assert!(prove_imt_insert_key(QHashOut::ZERO, 0, false, 0, 2, false).is_err());
    }

    #[test]
    fn state_reader_imt_contains_malformed_tail_rejected() {
        let store = Store::new();
        let tree = UserContractStateTreeId::<Store, F, PoseidonHash>::new(1, 1, TEST_TREE_HEIGHT as u8);
        let leaf = IMTContractStateLeaf::new(QHashOut::ZERO, QHashOut::ZERO, QHashOut::ZERO, F::ONE);
        tree.set_leaf_ucs(&store, 100, 0, leaf.qfhash::<PoseidonHash>()).unwrap();
        let mp = tree.get_leaf_ucs(&store, 100, 0).unwrap();
        assert!(prove_imt_absence(QHashOut::from_values(10, 0, 0, 0), leaf, mp, 0).is_err());
    }

    #[test]
    fn state_reader_imt_set_virgin_decoy_rejected() {
        assert!(prove_imt_sentinel_insert(0, false, 2, 3, true).is_err());
        assert!(prove_imt_sentinel_insert(0, true, 2, 3, true).is_err());
    }

    #[test]
    fn state_reader_imt_set_wrong_written_sentinel_rejected() {
        assert!(prove_imt_sentinel_insert(20, false, 2, 3, false).is_err());
    }

    #[test]
    fn state_reader_imt_set_out_of_range_predecessor_rejected() {
        assert!(prove_imt_sentinel_insert(20, true, 4, 2, false).is_err());
    }

    #[test]
    fn state_reader_imt_set_out_of_range_new_leaf_rejected() {
        assert!(prove_imt_sentinel_insert(20, true, 0, 4, false).is_err());
        assert!(prove_imt_sentinel_insert(0, false, 0, 4, false).is_err());
    }

    #[test]
    fn state_reader_imt_set_written_sentinel_predecessor_proves() {
        prove_imt_sentinel_insert(20, true, 0, 3, false).unwrap();
    }

    #[test]
    fn state_reader_imt_set_from_hash_outputs_proves() {
        let sender_user_id = F::from_canonical_u64(11);
        let recipient = [
            F::from_canonical_u64(21),
            F::from_canonical_u64(22),
            F::from_canonical_u64(23),
            F::from_canonical_u64(24),
            F::from_canonical_u64(25),
            F::from_canonical_u64(26),
            F::from_canonical_u64(27),
            F::from_canonical_u64(28),
        ];
        let token = [
            F::from_canonical_u64(31),
            F::from_canonical_u64(32),
            F::from_canonical_u64(33),
            F::from_canonical_u64(34),
            F::from_canonical_u64(35),
            F::from_canonical_u64(36),
            F::from_canonical_u64(37),
            F::from_canonical_u64(38),
        ];
        let amount = [
            F::from_canonical_u64(41),
            F::from_canonical_u64(42),
            F::from_canonical_u64(43),
            F::from_canonical_u64(44),
            F::from_canonical_u64(45),
            F::from_canonical_u64(46),
            F::from_canonical_u64(47),
            F::from_canonical_u64(48),
        ];
        let nonce = [
            F::from_canonical_u64(51),
            F::from_canonical_u64(52),
            F::from_canonical_u64(53),
            F::from_canonical_u64(54),
            F::from_canonical_u64(55),
            F::from_canonical_u64(56),
            F::from_canonical_u64(57),
            F::from_canonical_u64(58),
        ];
        let destination_chain = F::from_canonical_u64(61);

        let leaf_hash = PoseidonHasher::q_hash_many(
            &core::iter::once(sender_user_id)
                .chain(recipient)
                .chain(token)
                .chain(amount)
                .chain(nonce)
                .chain(core::iter::once(destination_chain))
                .collect::<Vec<_>>(),
        );
        let record_key = PoseidonHasher::q_hash_many(&nonce);

        let store = Store::new();
        let mut imt = IMT::new(&store, 1, 1, TEST_TREE_HEIGHT as u8, 100).unwrap();
        let update = imt.insert(&store, record_key, leaf_hash).unwrap();
        let (predecessor_old_leaf, predecessor_new_leaf, new_leaf, predecessor_delta_proof, new_leaf_delta_proof) = match update {
            IMTContractStateUpdate::Insert {
                predecessor_old_preimage,
                predecessor_new_preimage,
                new_leaf_preimage,
                predecessor_delta_proof,
                new_leaf_delta_proof,
            } => (
                predecessor_old_preimage,
                predecessor_new_preimage,
                new_leaf_preimage,
                predecessor_delta_proof,
                new_leaf_delta_proof,
            ),
            _ => panic!("expected insert"),
        };

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let mut dpn = new_test_dpn(&mut builder);

        let mut external_targets = Vec::new();
        for index in 0..35usize {
            let target = builder.add_virtual_target();
            dpn.push_external_target(index, target);
            external_targets.push(target);
        }

        let leaf_hash_op = DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::HashOut,
            index: 0,
            op_type: DPNOpType::HashNoPad,
            inputs: (0..34).map(|i| encode_indexed_op_id(DPNBuiltInDataType::Target, i)).collect(),
        };
        let record_key_op = DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::HashOut,
            index: 1,
            op_type: DPNOpType::HashNoPad,
            inputs: (25..33).map(|i| encode_indexed_op_id(DPNBuiltInDataType::Target, i)).collect(),
        };
        dpn.process_var_def(&mut builder, &leaf_hash_op);
        dpn.process_var_def(&mut builder, &record_key_op);

        for limb in 0..4usize {
            let const_op = DPNIndexedVarDef {
                data_type: DPNBuiltInDataType::Target,
                index: 100 + limb,
                op_type: DPNOpType::Constant,
                inputs: vec![limb as u64],
            };
            dpn.process_var_def(&mut builder, &const_op);

            let key_limb_op = DPNIndexedVarDef {
                data_type: DPNBuiltInDataType::Target,
                index: 200 + limb,
                op_type: DPNOpType::TargetAt,
                inputs: vec![
                    encode_indexed_op_id(DPNBuiltInDataType::HashOut, 1),
                    encode_indexed_op_id(DPNBuiltInDataType::Target, 100 + limb),
                ],
            };
            dpn.process_var_def(&mut builder, &key_limb_op);

            let value_limb_op = DPNIndexedVarDef {
                data_type: DPNBuiltInDataType::Target,
                index: 204 + limb,
                op_type: DPNOpType::TargetAt,
                inputs: vec![
                    encode_indexed_op_id(DPNBuiltInDataType::HashOut, 0),
                    encode_indexed_op_id(DPNBuiltInDataType::Target, 100 + limb),
                ],
            };
            dpn.process_var_def(&mut builder, &value_limb_op);
        }

        let start_root = builder.constant_hash(predecessor_delta_proof.old_root.0);
        let zero_hash = builder.constant_hash(HashOut::ZERO);
        let checkpoint_stats = PsyCheckpointLeafStatsGadget::create_virtual(&mut builder);
        let checkpoint_roots = PsyCheckpointGlobalStateRootsGadget::create_virtual(&mut builder);
        let mut state_reader = StateReaderGadget::new(
            checkpoint_roots,
            zero_hash,
            zero_hash,
            start_root,
            TEST_TREE_HEIGHT,
            zero_hash,
            TEST_TREE_HEIGHT,
            false,
            checkpoint_stats,
            zero_hash,
        );

        let cmd = DPNStateCmd::SetIMTContractStateValue(DPNStateCmdSetIMTContractStateValue {
            condition: encode_indexed_op_id(DPNBuiltInDataType::Target, 34),
            base_offset: encode_indexed_op_id(DPNBuiltInDataType::Target, 1000),
            capacity: encode_indexed_op_id(DPNBuiltInDataType::Target, 1001),
            key: [
                encode_indexed_op_id(DPNBuiltInDataType::Target, 200),
                encode_indexed_op_id(DPNBuiltInDataType::Target, 201),
                encode_indexed_op_id(DPNBuiltInDataType::Target, 202),
                encode_indexed_op_id(DPNBuiltInDataType::Target, 203),
            ],
            value: [
                encode_indexed_op_id(DPNBuiltInDataType::Target, 204),
                encode_indexed_op_id(DPNBuiltInDataType::Target, 205),
                encode_indexed_op_id(DPNBuiltInDataType::Target, 206),
                encode_indexed_op_id(DPNBuiltInDataType::Target, 207),
            ],
        });
        state_reader.injest_symbolic_state_command::<PoseidonHash, F, D>(&mut builder, &dpn, &cmd);
        builder.register_public_inputs(&state_reader.end_contract_state_root.elements);

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        let external_values = core::iter::once(sender_user_id)
            .chain(recipient)
            .chain(token)
            .chain(amount)
            .chain(nonce)
            .chain([destination_chain, F::ONE])
            .collect::<Vec<_>>();
        for (target, value) in external_targets.into_iter().zip(external_values.into_iter()) {
            pw.set_target(target, value).unwrap();
        }

        let gadget = &state_reader.imt_set_requests[0];
        pw.set_target(gadget.is_insert.target, F::ONE).unwrap();
        pw.set_target(gadget.insert_has_predecessor.target, F::ZERO).unwrap();
        gadget.update_old_leaf.set_witness(&mut pw, &IMTContractStateLeaf::default()).unwrap();
        gadget.update_new_leaf.set_witness(&mut pw, &new_leaf).unwrap();
        gadget
            .update_delta_proof
            .set_witness_core_proof_q(&mut pw, &predecessor_delta_proof)
            .unwrap();
        gadget.insert_predecessor_old_leaf.set_witness(&mut pw, &predecessor_old_leaf).unwrap();
        gadget.insert_predecessor_new_leaf.set_witness(&mut pw, &predecessor_new_leaf).unwrap();
        gadget.insert_new_leaf.set_witness(&mut pw, &new_leaf).unwrap();
        gadget
            .insert_predecessor_delta_proof
            .set_witness_core_proof_q(&mut pw, &predecessor_delta_proof)
            .unwrap();
        gadget
            .insert_new_leaf_delta_proof
            .set_witness_core_proof_q(&mut pw, &new_leaf_delta_proof)
            .unwrap();

        let proof = data.prove(pw).expect("hash outputs feeding IMT set should prove");
        assert_eq!(proof.public_inputs[0], new_leaf_delta_proof.new_root.0.elements[0]);
        data.verify(proof).expect("hash outputs feeding IMT set should verify");
    }

    #[test]
    fn state_reader_imt_set_with_namespaced_hash_key_proves() {
        let sender_user_id = F::from_canonical_u64(11);
        let recipient = [
            F::from_canonical_u64(21),
            F::from_canonical_u64(22),
            F::from_canonical_u64(23),
            F::from_canonical_u64(24),
            F::from_canonical_u64(25),
            F::from_canonical_u64(26),
            F::from_canonical_u64(27),
            F::from_canonical_u64(28),
        ];
        let token = [
            F::from_canonical_u64(31),
            F::from_canonical_u64(32),
            F::from_canonical_u64(33),
            F::from_canonical_u64(34),
            F::from_canonical_u64(35),
            F::from_canonical_u64(36),
            F::from_canonical_u64(37),
            F::from_canonical_u64(38),
        ];
        let amount = [
            F::from_canonical_u64(41),
            F::from_canonical_u64(42),
            F::from_canonical_u64(43),
            F::from_canonical_u64(44),
            F::from_canonical_u64(45),
            F::from_canonical_u64(46),
            F::from_canonical_u64(47),
            F::from_canonical_u64(48),
        ];
        let nonce = [
            F::from_canonical_u64(51),
            F::from_canonical_u64(52),
            F::from_canonical_u64(53),
            F::from_canonical_u64(54),
            F::from_canonical_u64(55),
            F::from_canonical_u64(56),
            F::from_canonical_u64(57),
            F::from_canonical_u64(58),
        ];
        let destination_chain = F::from_canonical_u64(61);
        let namespace = F::from_canonical_u64(6);

        let record_key = PoseidonHasher::q_hash_many(&nonce);
        let namespaced_key = PoseidonHasher::q_hash_many(&core::iter::once(namespace).chain(record_key.0.elements).collect::<Vec<_>>());
        let leaf_hash = PoseidonHasher::q_hash_many(
            &core::iter::once(sender_user_id)
                .chain(recipient)
                .chain(token)
                .chain(amount)
                .chain(nonce)
                .chain(core::iter::once(destination_chain))
                .collect::<Vec<_>>(),
        );

        let store = Store::new();
        let mut imt = IMT::new(&store, 1, 1, TEST_TREE_HEIGHT as u8, 100).unwrap();
        let update = imt.insert(&store, namespaced_key, leaf_hash).unwrap();
        let (predecessor_old_leaf, predecessor_new_leaf, new_leaf, predecessor_delta_proof, new_leaf_delta_proof) = match update {
            IMTContractStateUpdate::Insert {
                predecessor_old_preimage,
                predecessor_new_preimage,
                new_leaf_preimage,
                predecessor_delta_proof,
                new_leaf_delta_proof,
            } => (
                predecessor_old_preimage,
                predecessor_new_preimage,
                new_leaf_preimage,
                predecessor_delta_proof,
                new_leaf_delta_proof,
            ),
            _ => panic!("expected insert"),
        };

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let mut dpn = new_test_dpn(&mut builder);

        let mut external_targets = Vec::new();
        for index in 0..35usize {
            let target = builder.add_virtual_target();
            dpn.push_external_target(index, target);
            external_targets.push(target);
        }

        let record_key_op = DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::HashOut,
            index: 0,
            op_type: DPNOpType::HashNoPad,
            inputs: (25..33).map(|i| encode_indexed_op_id(DPNBuiltInDataType::Target, i)).collect(),
        };
        dpn.process_var_def(&mut builder, &record_key_op);

        for limb in 0..4usize {
            let const_op = DPNIndexedVarDef {
                data_type: DPNBuiltInDataType::Target,
                index: 100 + limb,
                op_type: DPNOpType::Constant,
                inputs: vec![limb as u64],
            };
            dpn.process_var_def(&mut builder, &const_op);

            let record_key_limb_op = DPNIndexedVarDef {
                data_type: DPNBuiltInDataType::Target,
                index: 200 + limb,
                op_type: DPNOpType::TargetAt,
                inputs: vec![
                    encode_indexed_op_id(DPNBuiltInDataType::HashOut, 0),
                    encode_indexed_op_id(DPNBuiltInDataType::Target, 100 + limb),
                ],
            };
            dpn.process_var_def(&mut builder, &record_key_limb_op);
        }

        let namespace_op = DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::Target,
            index: 300,
            op_type: DPNOpType::Constant,
            inputs: vec![6],
        };
        dpn.process_var_def(&mut builder, &namespace_op);

        let namespaced_key_op = DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::HashOut,
            index: 1,
            op_type: DPNOpType::HashNoPad,
            inputs: core::iter::once(encode_indexed_op_id(DPNBuiltInDataType::Target, 300))
                .chain((0..4).map(|limb| encode_indexed_op_id(DPNBuiltInDataType::Target, 200 + limb)))
                .collect(),
        };
        dpn.process_var_def(&mut builder, &namespaced_key_op);

        for limb in 0..4usize {
            let namespaced_key_limb_op = DPNIndexedVarDef {
                data_type: DPNBuiltInDataType::Target,
                index: 220 + limb,
                op_type: DPNOpType::TargetAt,
                inputs: vec![
                    encode_indexed_op_id(DPNBuiltInDataType::HashOut, 1),
                    encode_indexed_op_id(DPNBuiltInDataType::Target, 100 + limb),
                ],
            };
            dpn.process_var_def(&mut builder, &namespaced_key_limb_op);
        }

        let leaf_hash_op = DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::HashOut,
            index: 2,
            op_type: DPNOpType::HashNoPad,
            inputs: (0..34).map(|i| encode_indexed_op_id(DPNBuiltInDataType::Target, i)).collect(),
        };
        dpn.process_var_def(&mut builder, &leaf_hash_op);

        for limb in 0..4usize {
            let value_limb_op = DPNIndexedVarDef {
                data_type: DPNBuiltInDataType::Target,
                index: 240 + limb,
                op_type: DPNOpType::TargetAt,
                inputs: vec![
                    encode_indexed_op_id(DPNBuiltInDataType::HashOut, 2),
                    encode_indexed_op_id(DPNBuiltInDataType::Target, 100 + limb),
                ],
            };
            dpn.process_var_def(&mut builder, &value_limb_op);
        }

        let start_root = builder.constant_hash(predecessor_delta_proof.old_root.0);
        let zero_hash = builder.constant_hash(HashOut::ZERO);
        let checkpoint_stats = PsyCheckpointLeafStatsGadget::create_virtual(&mut builder);
        let checkpoint_roots = PsyCheckpointGlobalStateRootsGadget::create_virtual(&mut builder);
        let mut state_reader = StateReaderGadget::new(
            checkpoint_roots,
            zero_hash,
            zero_hash,
            start_root,
            TEST_TREE_HEIGHT,
            zero_hash,
            TEST_TREE_HEIGHT,
            false,
            checkpoint_stats,
            zero_hash,
        );

        let cmd = DPNStateCmd::SetIMTContractStateValue(DPNStateCmdSetIMTContractStateValue {
            condition: encode_indexed_op_id(DPNBuiltInDataType::Target, 34),
            base_offset: encode_indexed_op_id(DPNBuiltInDataType::Target, 1000),
            capacity: encode_indexed_op_id(DPNBuiltInDataType::Target, 1001),
            key: [
                encode_indexed_op_id(DPNBuiltInDataType::Target, 220),
                encode_indexed_op_id(DPNBuiltInDataType::Target, 221),
                encode_indexed_op_id(DPNBuiltInDataType::Target, 222),
                encode_indexed_op_id(DPNBuiltInDataType::Target, 223),
            ],
            value: [
                encode_indexed_op_id(DPNBuiltInDataType::Target, 240),
                encode_indexed_op_id(DPNBuiltInDataType::Target, 241),
                encode_indexed_op_id(DPNBuiltInDataType::Target, 242),
                encode_indexed_op_id(DPNBuiltInDataType::Target, 243),
            ],
        });
        state_reader.injest_symbolic_state_command::<PoseidonHash, F, D>(&mut builder, &dpn, &cmd);
        builder.register_public_inputs(&state_reader.end_contract_state_root.elements);

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        let external_values = core::iter::once(sender_user_id)
            .chain(recipient)
            .chain(token)
            .chain(amount)
            .chain(nonce)
            .chain([destination_chain, F::ONE])
            .collect::<Vec<_>>();
        for (target, value) in external_targets.into_iter().zip(external_values.into_iter()) {
            pw.set_target(target, value).unwrap();
        }

        let gadget = &state_reader.imt_set_requests[0];
        pw.set_target(gadget.is_insert.target, F::ONE).unwrap();
        pw.set_target(gadget.insert_has_predecessor.target, F::ONE).unwrap();
        gadget.update_old_leaf.set_witness(&mut pw, &IMTContractStateLeaf::default()).unwrap();
        gadget.update_new_leaf.set_witness(&mut pw, &new_leaf).unwrap();
        gadget
            .update_delta_proof
            .set_witness_core_proof_q(&mut pw, &predecessor_delta_proof)
            .unwrap();
        gadget.insert_predecessor_old_leaf.set_witness(&mut pw, &predecessor_old_leaf).unwrap();
        gadget.insert_predecessor_new_leaf.set_witness(&mut pw, &predecessor_new_leaf).unwrap();
        gadget.insert_new_leaf.set_witness(&mut pw, &new_leaf).unwrap();
        gadget
            .insert_predecessor_delta_proof
            .set_witness_core_proof_q(&mut pw, &predecessor_delta_proof)
            .unwrap();
        gadget
            .insert_new_leaf_delta_proof
            .set_witness_core_proof_q(&mut pw, &new_leaf_delta_proof)
            .unwrap();

        let proof = data.prove(pw).expect("namespaced hash key feeding IMT set should prove");
        assert_eq!(proof.public_inputs[0], new_leaf_delta_proof.new_root.0.elements[0]);
        data.verify(proof).expect("namespaced hash key feeding IMT set should verify");
    }
}
