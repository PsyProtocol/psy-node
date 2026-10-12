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

/// Shared IMT write. `condition` selects the live transition; disabled sets
/// keep every raw witness zero while the delta gadgets still compute roots.
#[derive(Clone, Debug)]
pub struct IMTSetGadget {
    pub is_insert: BoolTarget,
    pub update_old_leaf: IMTLeafTargets,
    pub update_new_leaf: IMTLeafTargets,
    pub update_delta_proof: DeltaMerkleProofGadget,
    pub insert_predecessor_old_leaf: IMTLeafTargets,
    pub insert_predecessor_new_leaf: IMTLeafTargets,
    pub insert_new_leaf: IMTLeafTargets,
    pub insert_predecessor_delta_proof: DeltaMerkleProofGadget,
    pub insert_new_leaf_delta_proof: DeltaMerkleProofGadget,
    pub sentinel_preimage: IMTLeafTargets,
    pub sentinel_merkle_proof: MerkleProofGadget,
    pub sentinel_old_leaf: IMTLeafTargets,
    pub sentinel_new_leaf: IMTLeafTargets,
    pub insert_sentinel_delta_proof: DeltaMerkleProofGadget,
}

#[derive(Clone, Debug)]
pub struct IMTReadGadget {
    pub merkle_proof: MerkleProofGadget,
    pub leaf: IMTLeafTargets,
    pub sentinel_preimage: IMTLeafTargets,
    pub sentinel_merkle_proof: MerkleProofGadget,
}

#[derive(Clone, Debug)]
pub struct IMTExternalReadGadget {
    pub contract_tree_proof: MerkleProofGadget,
    pub state_slot_proof: VariableHeightMerkleProofGadget,
    pub leaf: IMTLeafTargets,
    pub sentinel_preimage: IMTLeafTargets,
    pub sentinel_merkle_proof: VariableHeightMerkleProofGadget,
}

#[derive(Clone, Debug)]
pub struct IMTOtherUserReadGadget {
    pub state_slot_proof: VariableHeightMerkleProofGadget,
    pub leaf: IMTLeafTargets,
    pub sentinel_preimage: IMTLeafTargets,
    pub sentinel_merkle_proof: VariableHeightMerkleProofGadget,
}

#[derive(Clone, Debug)]
pub struct IMTContainsOtherUserGadget {
    pub state_slot_proof: VariableHeightMerkleProofGadget,
    pub leaf: IMTLeafTargets,
    pub exists: Target,
    pub sentinel_preimage: IMTLeafTargets,
    pub sentinel_merkle_proof: VariableHeightMerkleProofGadget,
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
    pub base_offset_target_id: u64,
    pub capacity_target_id: u64,
    pub key_targets: [u64; 4],
    pub write_epoch: u32,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct CKReadIMTCurrentContract {
    pub base_offset_target_id: u64,
    pub capacity_target_id: u64,
    pub key_targets: [u64; 4],
    pub write_epoch: u32,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct CKReadIMTContainsCurrentContract {
    pub base_offset_target_id: u64,
    pub capacity_target_id: u64,
    pub key_targets: [u64; 4],
    pub write_epoch: u32,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct CKReadIMTSelfUserExternalContract {
    pub contract_target_id: u64,
    pub base_offset_target_id: u64,
    pub capacity_target_id: u64,
    pub height_target_id: u64,
    pub key_targets: [u64; 4],
    pub contract_call_epoch: u32,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct CKReadIMTOtherUserContract {
    pub user_target_id: u64,
    pub contract_target_id: u64,
    pub base_offset_target_id: u64,
    pub capacity_target_id: u64,
    pub height_target_id: u64,
    pub key_targets: [u64; 4],
    pub write_epoch: u32,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct CKReadIMTContainsOtherUserContract {
    pub user_target_id: u64,
    pub contract_target_id: u64,
    pub base_offset_target_id: u64,
    pub capacity_target_id: u64,
    pub height_target_id: u64,
    pub key_targets: [u64; 4],
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
    pub fn new_write_imt_current_contract(
        condition_target_id: u64,
        base_offset_target_id: u64,
        capacity_target_id: u64,
        key_targets: [u64; 4],
        write_epoch: u32,
    ) -> Self {
        Self::WriteIMTCurrentContract(CKWriteIMTCurrentContract {
            condition_target_id,
            base_offset_target_id,
            capacity_target_id,
            key_targets,
            write_epoch,
        })
    }
    pub fn new_read_imt_current_contract(base_offset_target_id: u64, capacity_target_id: u64, key_targets: [u64; 4], write_epoch: u32) -> Self {
        Self::ReadIMTCurrentContract(CKReadIMTCurrentContract {
            base_offset_target_id,
            capacity_target_id,
            key_targets,
            write_epoch,
        })
    }
    pub fn new_read_imt_contains_current_contract(
        base_offset_target_id: u64,
        capacity_target_id: u64,
        key_targets: [u64; 4],
        write_epoch: u32,
    ) -> Self {
        Self::ReadIMTContainsCurrentContract(CKReadIMTContainsCurrentContract {
            base_offset_target_id,
            capacity_target_id,
            key_targets,
            write_epoch,
        })
    }
    pub fn new_read_imt_self_user_external_contract(
        contract_target_id: u64,
        base_offset_target_id: u64,
        capacity_target_id: u64,
        height_target_id: u64,
        key_targets: [u64; 4],
        contract_call_epoch: u32,
    ) -> Self {
        Self::ReadIMTSelfUserExternalContract(CKReadIMTSelfUserExternalContract {
            contract_target_id,
            base_offset_target_id,
            capacity_target_id,
            height_target_id,
            key_targets,
            contract_call_epoch,
        })
    }
    pub fn new_read_imt_other_user_contract(
        user_target_id: u64,
        contract_target_id: u64,
        base_offset_target_id: u64,
        capacity_target_id: u64,
        height_target_id: u64,
        key_targets: [u64; 4],
        write_epoch: u32,
    ) -> Self {
        Self::ReadIMTOtherUserContract(CKReadIMTOtherUserContract {
            user_target_id,
            contract_target_id,
            base_offset_target_id,
            capacity_target_id,
            height_target_id,
            key_targets,
            write_epoch,
        })
    }
    pub fn new_imt_contains_other_user_contract(
        user_target_id: u64,
        contract_target_id: u64,
        base_offset_target_id: u64,
        capacity_target_id: u64,
        height_target_id: u64,
        key_targets: [u64; 4],
        write_epoch: u32,
    ) -> Self {
        Self::ReadIMTContainsOtherUserContract(CKReadIMTContainsOtherUserContract {
            user_target_id,
            contract_target_id,
            base_offset_target_id,
            capacity_target_id,
            height_target_id,
            key_targets,
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
    pub imt_contains_sentinel_proofs: Vec<MerkleProofGadget>,
    pub imt_contains_leaf_requests: Vec<IMTLeafTargets>,
    pub imt_contains_sentinel_requests: Vec<IMTLeafTargets>,
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
            imt_contains_sentinel_proofs: vec![],
            imt_contains_leaf_requests: vec![],
            imt_contains_sentinel_requests: vec![],
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
            let expected_index = if proof_index == 0 {
                start_slot_index
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
        sentinel: IMTLeafTargets,
        sentinel_proof: MerkleProofGadget,
    ) -> StateReaderReferenceKey {
        let ref_key = StateReaderReferenceKey::new_imt_contains_key(self.imt_contains_leaf_requests.len());
        self.imt_contains_proofs.push(proof);
        self.imt_contains_sentinel_proofs.push(sentinel_proof);
        self.imt_contains_leaf_requests.push(leaf);
        self.imt_contains_sentinel_requests.push(sentinel);
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

    pub fn get_self_user_external_contract_slot_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        dpn: &SimpleDPNBuilder<F, D>,
        contract_target_id: u64,
        slot_target_id: u64,
        contract_state_tree_height: Target,
    ) -> HashOutTarget {
        let contract_state_tree_ck =
            StateCommandCacheKey::new_read_self_user_external_contract_slot(contract_target_id, slot_target_id, self.contract_call_epoch);
        let (is_new_contract_state_tree, mp_cst_value, mp_cst_root, mp_cst_index) = {
            let (is_new_contract_state_tree, mp_cst) =
                self.resolve_or_insert_variable_height_merkle_proof_gadget::<H, F, D>(builder, contract_state_tree_ck, contract_state_tree_height);
            (is_new_contract_state_tree, mp_cst.value, mp_cst.root, mp_cst.index)
        };

        let slot_value = mp_cst_value;
        if is_new_contract_state_tree {
            let expected_contract_state_tree_root = self.get_self_user_external_contract_root::<H, F, D>(builder, dpn, contract_target_id);
            builder.connect_hashes(mp_cst_root, expected_contract_state_tree_root);

            let slot_index = dpn.resolve_target(slot_target_id);
            builder.connect(slot_index, mp_cst_index);
            self.result_map.insert(contract_state_tree_ck, slot_value.elements.to_vec());
        }
        slot_value
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

    pub fn get_other_user_leaf<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        dpn: &SimpleDPNBuilder<F, D>,
        user_target_id: u64,
    ) -> &PsyUserLeafGadget {
        let expected_leaf_hash = { self.get_other_user_leaf_hash::<H, F, D>(builder, dpn, user_target_id) };
        let user_leaf_ck = StateCommandCacheKey::new_read_other_user_leaf(user_target_id);

        let (is_new, leaf) = self.resolve_or_insert_user_leaf_gadget::<F, D>(builder, user_leaf_ck);

        if is_new {
            let actual_leaf_hash = leaf.to_hash::<H, F, D>(builder);

            builder.connect_hashes(expected_leaf_hash, actual_leaf_hash);
        }
        leaf
    }

    pub fn get_other_user_contract_state_root<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
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
    pub fn get_other_user_contract_state_slot_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
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

        if is_new {
            let expected_contract_id = dpn.resolve_target(slot_target_id);

            builder.connect(expected_contract_id, mp_cst.index);

            builder.connect_hashes(expected_contract_state_tree_root, mp_cst.root);
        }
        mp_cst.value
    }

    pub fn get_other_user_contract_state_slot_range<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
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

        if self.result_map.contains_key(&r_ck) {
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
            builder.connect_hashes(mps[0].root, expected_contract_state_tree_root);
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
        }
    }

    pub fn get_self_user_external_contract_state_slot_single<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
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

        if is_new {
            let sub_slot_index = dpn.resolve_target(sub_slot_target_id);
            let (slot_index, inner_index) = builder.div_rem4(sub_slot_index);
            let single_value = builder.select_in_hash(mp_cst.value, inner_index);
            builder.connect_hashes(mp_cst.root, expected_contract_state_tree_root);
            builder.connect(slot_index, mp_cst.index);
            self.result_map.insert(ck, vec![single_value]);
            single_value
        } else {
            self.result_map[&ck][0]
        }
    }

    pub fn get_self_user_external_contract_state_slot_range<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        dpn: &SimpleDPNBuilder<F, D>,
        contract_target_id: u64,
        sub_slot_target_id: u64,
        contract_state_tree_height: Target,
        length: usize,
    ) -> Vec<Target> {
        let r_ck = StateCommandCacheKey::new_read_self_user_external_contract_range(
            contract_target_id,
            sub_slot_target_id,
            length as u32,
            self.contract_call_epoch,
            0,
        );

        if self.result_map.contains_key(&r_ck) {
            self.result_map.get(&r_ck).unwrap().to_owned()
        } else {
            let expected_contract_state_tree_root = self.get_self_user_external_contract_root::<H, F, D>(builder, dpn, contract_target_id);

            let sub_slot_index = dpn.resolve_target(sub_slot_target_id);
            let (values, mps) = Self::add_variable_height_merkle_proof_batch::<H, F, D>(
                builder,
                contract_state_tree_height,
                sub_slot_index,
                length,
                self.force_four_align,
            );

            builder.connect_hashes(mps[0].root, expected_contract_state_tree_root);
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
        }
    }
    fn checked_state_height<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>, height: Target) -> Target {
        builder.range_check(height, 6);
        let mut selected = builder.zero();
        let mut matched = builder._false();
        for bits in 1..=32usize {
            let candidate = builder.constant(F::from_canonical_usize(bits));
            let is_candidate = builder.is_equal(height, candidate);
            selected = builder.select(is_candidate, candidate, selected);
            matched = builder.or(matched, is_candidate);
        }
        builder.connect(matched.target, builder.one());
        selected
    }

    /// `verify_imt_map_bounds`: `b=4*q+r`, `0<=r<4`, `B=q+(r!=0)`, positive `C`,
    /// and `B+C<2^h`.
    fn verify_imt_map_bounds<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        base_offset: Target,
        capacity: Target,
        height_bits: Target,
    ) -> (Target, Target) {
        let (quotient, remainder) = builder.div_rem4(base_offset);
        let remainder_nonzero = builder.is_not_zero(remainder);
        let physical_base = builder.add(quotient, remainder_nonzero.target);
        builder.range_check(physical_base, 32);
        builder.range_check(capacity, 32);
        let one = builder.one();
        let capacity_positive = builder.is_less_than(32, builder.zero(), capacity);
        builder.connect(capacity_positive.target, one);
        let occupied = builder.add(physical_base, capacity);
        let mut tree_size = builder.one();
        for bits in 1..=32usize {
            tree_size = builder.add(tree_size, tree_size);
            let is_height = builder.is_equal(height_bits, builder.constant(F::from_canonical_usize(bits)));
            let within_tree = builder.is_less_than(33, occupied, tree_size);
            let accepted = builder.select(is_height, within_tree.target, one);
            builder.connect(accepted, one);
        }
        (physical_base, capacity)
    }

    fn connect_leaf_zero_if_true<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        condition: BoolTarget,
        leaf: &IMTLeafTargets,
    ) {
        for limb in 0..4 {
            builder.connect_zero_if_true(condition, leaf.key.elements[limb]);
            builder.connect_zero_if_true(condition, leaf.value.elements[limb]);
            builder.connect_zero_if_true(condition, leaf.next_key.elements[limb]);
        }
        builder.connect_zero_if_true(condition, leaf.next_index);
    }

    fn connect_index_in_open_interval<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        condition: BoolTarget,
        index: Target,
        physical_base: Target,
        count: Target,
    ) {
        let one = builder.one();
        let first_member = builder.add(physical_base, one);
        let last_member = builder.add(physical_base, count);
        let at_or_above_first = builder.is_less_than_or_equal(33, first_member, index);
        let at_or_below_last = builder.is_less_than_or_equal(33, index, last_member);
        let in_interval = builder.and(at_or_above_first, at_or_below_last);
        builder.connect_if_true(condition, in_interval.target, builder._true().target);
    }

    /// Authenticate the sentinel at `B` and expose its allocated count.
    /// Stable initialized sentinels have positive `n` and a successor in `[B+1,B+n]`;
    /// stable virgin state is the physical zero slot with an all-zero preimage.
    fn constrain_authenticated_sentinel<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        active: BoolTarget,
        root: HashOutTarget,
        physical_base: Target,
        capacity: Target,
        sentinel: &IMTLeafTargets,
        proof_root: HashOutTarget,
        proof_value: HashOutTarget,
        proof_index: Target,
    ) -> (BoolTarget, Target) {
        let sentinel_hash = sentinel.hash::<H, F, D>(builder);
        let one = builder.one();
        let zero_hash = builder.constant_hash(HashOut::ZERO);
        let slot_is_zero = builder.is_zero_hash(proof_value);
        let count = sentinel.value.elements[0];

        builder.connect_hashes_if_true(active, proof_root, root);
        builder.connect_if_true(active, proof_index, physical_base);
        for limb in 0..4 {
            builder.connect_zero_if_true(active, sentinel.key.elements[limb]);
            if limb != 0 {
                builder.connect_zero_if_true(active, sentinel.value.elements[limb]);
            }
        }
        builder.range_check(count, 32);
        let count_within_capacity = builder.is_less_than_or_equal(32, count, capacity);
        builder.connect_if_true(active, count_within_capacity.target, builder._true().target);

        let initialized = builder.and(active, builder.not(slot_is_zero));
        let virgin = builder.and(active, slot_is_zero);
        builder.connect_hashes_if_true(initialized, sentinel_hash, proof_value);
        Self::connect_leaf_zero_if_true(builder, virgin, sentinel);

        let count_positive = builder.is_less_than(32, builder.zero(), count);
        builder.connect_if_true(initialized, count_positive.target, one);
        let successor_present = builder.not(builder.is_zero_hash(sentinel.next_key));
        let successor_index_present = builder.is_not_zero(sentinel.next_index);
        let successor_linked = builder.and(successor_present, successor_index_present);
        builder.connect_if_true(initialized, successor_linked.target, one);
        Self::connect_index_in_open_interval(builder, initialized, sentinel.next_index, physical_base, count);
        let next_key_zero = builder.is_zero_hash(sentinel.next_key);
        let next_index_zero = builder.is_zero(sentinel.next_index);
        let virgin_successor_absent = builder.and(next_key_zero, next_index_zero);
        builder.connect_if_true(virgin, virgin_successor_absent.target, one);
        builder.connect_hashes_if_true(virgin, proof_value, zero_hash);
        (slot_is_zero, count)
    }

    fn connect_query_nonzero<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        active: BoolTarget,
        query_key: HashOutTarget,
    ) {
        let query_nonzero = builder.not(builder.is_zero_hash(query_key));
        builder.connect_if_true(active, query_nonzero.target, builder._true().target);
    }


    fn connect_predecessor_role<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        active: BoolTarget,
        predecessor: &IMTLeafTargets,
        predecessor_index: Target,
        physical_base: Target,
        count: Target,
    ) {
        let one = builder._true();
        let at_sentinel = builder.is_equal(predecessor_index, physical_base);
        let sentinel_role = builder.and(active, at_sentinel);
        for limb in 0..4 {
            builder.connect_zero_if_true(sentinel_role, predecessor.key.elements[limb]);
        }
        let member_role = builder.and(active, builder.not(at_sentinel));
        Self::connect_index_in_open_interval(builder, member_role, predecessor_index, physical_base, count);
        let member_key_nonzero = builder.not(builder.is_zero_hash(predecessor.key));
        builder.connect_if_true(member_role, member_key_nonzero.target, one.target);
        Self::connect_successor_pair(builder, active, predecessor.next_key, predecessor.next_index, physical_base, count);
    }

    fn connect_successor_pair<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        active: BoolTarget,
        next_key: HashOutTarget,
        next_index: Target,
        physical_base: Target,
        count: Target,
    ) {
        let key_absent = builder.is_zero_hash(next_key);
        let index_absent = builder.is_zero(next_index);
        let both_absent = builder.and(key_absent, index_absent);
        let key_present = builder.not(key_absent);
        let index_present = builder.not(index_absent);
        let both_present = builder.and(key_present, index_present);
        let paired = builder.or(both_absent, both_present);
        builder.connect_if_true(active, paired.target, builder._true().target);
        let present = builder.and(active, both_present);
        Self::connect_index_in_open_interval(builder, present, next_index, physical_base, count);
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

                let contract_state_tree_ck = StateCommandCacheKey::new_read_self_user_external_contract_slot(c.contract_id, c.slot_index, call_epoch);

                let contract_state_tree_height = dpn.resolve_target(c.contract_state_tree_height);
                let (is_new_contract_state_tree, mp_cst) =
                    self.resolve_or_insert_variable_height_merkle_proof_gadget::<H, F, D>(
                        builder,
                        contract_state_tree_ck,
                        contract_state_tree_height,
                    );

                let slot_value = mp_cst.value.elements.to_vec();
                if is_new_contract_state_tree {
                    builder.connect_hashes(mp_cst.root, expected_contract_state_tree_root);
                    let slot_index = dpn.resolve_target(c.slot_index);
                    builder.connect(slot_index, mp_cst.index);
                    self.result_map.insert(contract_state_tree_ck, slot_value.clone());
                }
                slot_value
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

                if is_new {
                    let sub_slot_index = dpn.resolve_target(c.sub_slot_index);
                    let (slot_index, inner_index) = builder.div_rem4(sub_slot_index);
                    let single_value = builder.select_in_hash(mp_cst.value, inner_index);
                    builder.connect_hashes(mp_cst.root, expected_contract_state_tree_root);
                    builder.connect(slot_index, mp_cst.index);
                    self.result_map.insert(ck, vec![single_value]);
                    vec![single_value]
                } else {
                    self.result_map[&ck].to_vec()
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
                let condition = dpn.resolve_bool(builder, c.condition);
                let is_insert = builder.add_virtual_bool_target_safe();
                let is_update = builder.not(is_insert);
                let condition_and_insert = builder.and(condition, is_insert);
                let condition_and_update = builder.and(condition, is_update);
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
                let base_offset = dpn.resolve_target(c.base_offset);
                let capacity = dpn.resolve_target(c.capacity);
                let state_height = builder.constant(F::from_canonical_usize(self.contract_state_tree_height));
                let (physical_base, map_capacity) = Self::verify_imt_map_bounds(builder, base_offset, capacity, state_height);
                let one = builder.one();
                let true_target = builder._true();
                let zero_hash = builder.constant_hash(HashOut::ZERO);

                let sentinel = IMTLeafTargets::add_virtual_to(builder);
                let sentinel_proof = MerkleProofGadget::add_virtual_to::<H, F, D>(builder, self.contract_state_tree_height);
                let (sentinel_virgin, starting_count) = Self::constrain_authenticated_sentinel::<H, F, D>(
                    builder,
                    condition,
                    self.end_contract_state_root,
                    physical_base,
                    map_capacity,
                    &sentinel,
                    sentinel_proof.root,
                    sentinel_proof.value,
                    sentinel_proof.index,
                );
                let update_old_leaf = IMTLeafTargets::add_virtual_to(builder);
                let update_new_leaf = IMTLeafTargets::add_virtual_to(builder);
                let update_delta_proof = DeltaMerkleProofGadget::add_virtual_to::<H, F, D>(builder, self.contract_state_tree_height);
                let update_old_hash = update_old_leaf.hash::<H, F, D>(builder);
                let update_new_hash = update_new_leaf.hash::<H, F, D>(builder);
                builder.connect_hashes_if_true(condition_and_update, update_delta_proof.old_root, self.end_contract_state_root);
                builder.connect_hashes_if_true(condition_and_update, update_old_hash, update_delta_proof.old_value);
                builder.connect_hashes_if_true(condition_and_update, update_new_hash, update_delta_proof.new_value);
                builder.connect_hashes_if_true(condition_and_update, update_old_leaf.key, key_target);
                builder.connect_hashes_if_true(condition_and_update, update_new_leaf.key, key_target);
                builder.connect_hashes_if_true(condition_and_update, update_new_leaf.value, value_target);
                builder.connect_hashes_if_true(condition_and_update, update_old_leaf.key, update_new_leaf.key);
                builder.connect_hashes_if_true(condition_and_update, update_old_leaf.next_key, update_new_leaf.next_key);
                builder.connect_if_true(condition_and_update, update_old_leaf.next_index, update_new_leaf.next_index);
                Self::connect_index_in_open_interval(builder, condition_and_update, update_delta_proof.index, physical_base, starting_count);
                Self::connect_successor_pair(builder, condition_and_update, update_old_leaf.next_key, update_old_leaf.next_index, physical_base, starting_count);
                Self::connect_query_nonzero(builder, condition, key_target);

                let predecessor_old = IMTLeafTargets::add_virtual_to(builder);
                let predecessor_new = IMTLeafTargets::add_virtual_to(builder);
                let inserted_leaf = IMTLeafTargets::add_virtual_to(builder);
                let predecessor_delta = DeltaMerkleProofGadget::add_virtual_to::<H, F, D>(builder, self.contract_state_tree_height);
                let member_delta = DeltaMerkleProofGadget::add_virtual_to::<H, F, D>(builder, self.contract_state_tree_height);
                let sentinel_delta = DeltaMerkleProofGadget::add_virtual_to::<H, F, D>(builder, self.contract_state_tree_height);
                let sentinel_old = IMTLeafTargets::add_virtual_to(builder);
                let sentinel_new = IMTLeafTargets::add_virtual_to(builder);
                let predecessor_old_hash = predecessor_old.hash::<H, F, D>(builder);
                let predecessor_new_hash = predecessor_new.hash::<H, F, D>(builder);
                let inserted_hash = inserted_leaf.hash::<H, F, D>(builder);
                let room_for_insert = builder.is_less_than(32, starting_count, map_capacity);
                builder.connect_if_true(condition_and_insert, room_for_insert.target, true_target.target);
                let allocated_index = builder.add(builder.add(physical_base, starting_count), one);
                builder.connect_hashes_if_true(condition_and_insert, predecessor_delta.old_root, self.end_contract_state_root);
                builder.connect_hashes_if_true(condition_and_insert, predecessor_delta.new_root, member_delta.old_root);
                builder.connect_hashes_if_true(condition_and_insert, member_delta.new_root, sentinel_delta.old_root);
                builder.connect_hashes_if_true(condition_and_insert, predecessor_new_hash, predecessor_delta.new_value);
                builder.connect_hashes_if_true(condition_and_insert, inserted_hash, member_delta.new_value);
                for limb in 0..4 {
                    builder.connect_zero_if_true(condition_and_insert, member_delta.old_value.elements[limb]);
                }
                builder.connect_if_true(condition_and_insert, member_delta.index, allocated_index);
                builder.connect_if_true(condition_and_insert, sentinel_delta.index, physical_base);
                let predecessor_differs = builder.is_not_equal(predecessor_delta.index, allocated_index);
                builder.connect_if_true(condition_and_insert, predecessor_differs.target, true_target.target);
                builder.connect_hashes_if_true(condition_and_insert, inserted_leaf.key, key_target);
                builder.connect_hashes_if_true(condition_and_insert, inserted_leaf.value, value_target);

                let predecessor_is_sentinel = builder.is_equal(predecessor_delta.index, physical_base);
                let sentinel_predecessor = builder.and(condition_and_insert, predecessor_is_sentinel);
                let member_predecessor = builder.and(condition_and_insert, builder.not(predecessor_is_sentinel));
                let initialized_insert = builder.and(condition_and_insert, builder.not(sentinel_virgin));
                let initialized_member_predecessor = builder.and(initialized_insert, member_predecessor);
                builder.connect_hashes_if_true(initialized_member_predecessor, predecessor_old_hash, predecessor_delta.old_value);
                builder.connect_hashes_if_true(sentinel_predecessor, predecessor_old.key, sentinel.key);
                builder.connect_hashes_if_true(sentinel_predecessor, predecessor_old.value, sentinel.value);
                builder.connect_hashes_if_true(sentinel_predecessor, predecessor_old.next_key, sentinel.next_key);
                builder.connect_if_true(sentinel_predecessor, predecessor_old.next_index, sentinel.next_index);
                let virgin_insert = builder.and(condition_and_insert, sentinel_virgin);
                builder.connect_hashes_if_true(virgin_insert, predecessor_delta.old_value, zero_hash);
                Self::connect_leaf_zero_if_true(builder, virgin_insert, &predecessor_old);
                builder.connect_if_true(virgin_insert, predecessor_is_sentinel.target, true_target.target);
                Self::connect_predecessor_role(
                    builder,
                    condition_and_insert,
                    &predecessor_old,
                    predecessor_delta.index,
                    physical_base,
                    starting_count,
                );
                let predecessor_before_query = is_qhashout_lt::<F, D>(builder, predecessor_old.key, key_target);
                let inherited_successor_absent = builder.is_zero_hash(predecessor_old.next_key);
                let query_before_successor = is_qhashout_lt::<F, D>(builder, key_target, predecessor_old.next_key);
                let successor_gap = builder.or(inherited_successor_absent, query_before_successor);
                let strict_absence = builder.and(predecessor_before_query, successor_gap);
                builder.connect_if_true(condition_and_insert, strict_absence.target, true_target.target);
                builder.connect_hashes_if_true(member_predecessor, predecessor_old.key, predecessor_new.key);
                builder.connect_hashes_if_true(member_predecessor, predecessor_old.value, predecessor_new.value);
                builder.connect_hashes_if_true(sentinel_predecessor, predecessor_new.key, sentinel.key);
                for limb in 1..4 {
                    builder.connect_if_true(sentinel_predecessor, predecessor_new.value.elements[limb], sentinel.value.elements[limb]);
                }
                builder.connect_if_true(sentinel_predecessor, predecessor_new.value.elements[0], starting_count);
                builder.connect_hashes_if_true(condition_and_insert, inserted_leaf.next_key, predecessor_old.next_key);
                builder.connect_if_true(condition_and_insert, inserted_leaf.next_index, predecessor_old.next_index);
                builder.connect_hashes_if_true(condition_and_insert, predecessor_new.next_key, inserted_leaf.key);
                builder.connect_if_true(condition_and_insert, predecessor_new.next_index, allocated_index);
                Self::connect_successor_pair(
                    builder,
                    condition_and_insert,
                    inserted_leaf.next_key,
                    inserted_leaf.next_index,
                    physical_base,
                    starting_count,
                );

                let sentinel_old_hash = sentinel_old.hash::<H, F, D>(builder);
                let sentinel_new_hash = sentinel_new.hash::<H, F, D>(builder);
                let next_count = builder.add(starting_count, one);
                builder.connect_hashes_if_true(initialized_insert, sentinel_old_hash, sentinel_delta.old_value);
                builder.connect_hashes_if_true(virgin_insert, sentinel_delta.old_value, predecessor_new_hash);
                builder.connect_hashes_if_true(condition_and_insert, sentinel_new_hash, sentinel_delta.new_value);
                builder.connect_hashes_if_true(condition_and_insert, sentinel_old.key, sentinel.key);
                builder.connect_hashes_if_true(condition_and_insert, sentinel_new.key, sentinel.key);
                for limb in 1..4 {
                    builder.connect_if_true(condition_and_insert, sentinel_old.value.elements[limb], sentinel.value.elements[limb]);
                    builder.connect_if_true(condition_and_insert, sentinel_new.value.elements[limb], sentinel.value.elements[limb]);
                }
                builder.connect_if_true(condition_and_insert, sentinel_old.value.elements[0], starting_count);
                builder.connect_if_true(condition_and_insert, sentinel_new.value.elements[0], next_count);
                builder.connect_hashes_if_true(member_predecessor, sentinel_old.next_key, sentinel.next_key);
                builder.connect_if_true(member_predecessor, sentinel_old.next_index, sentinel.next_index);
                builder.connect_hashes_if_true(sentinel_predecessor, sentinel_old.next_key, inserted_leaf.key);
                builder.connect_if_true(sentinel_predecessor, sentinel_old.next_index, allocated_index);
                builder.connect_hashes_if_true(condition_and_insert, sentinel_new.next_key, sentinel_old.next_key);
                builder.connect_if_true(condition_and_insert, sentinel_new.next_index, sentinel_old.next_index);
                Self::connect_index_in_open_interval(builder, condition_and_insert, sentinel_new.next_index, physical_base, next_count);

                let not_condition = builder.not(condition);
                Self::connect_leaf_zero_if_true(builder, not_condition, &update_old_leaf);
                Self::connect_leaf_zero_if_true(builder, not_condition, &update_new_leaf);
                Self::connect_leaf_zero_if_true(builder, not_condition, &predecessor_old);
                Self::connect_leaf_zero_if_true(builder, not_condition, &predecessor_new);
                Self::connect_leaf_zero_if_true(builder, not_condition, &inserted_leaf);
                Self::connect_leaf_zero_if_true(builder, not_condition, &sentinel);
                Self::connect_leaf_zero_if_true(builder, not_condition, &sentinel_old);
                Self::connect_leaf_zero_if_true(builder, not_condition, &sentinel_new);
                builder.connect_if_true(not_condition, is_insert.target, builder.zero());
                Self::connect_leaf_zero_if_true(builder, condition_and_update, &predecessor_old);
                Self::connect_leaf_zero_if_true(builder, condition_and_update, &predecessor_new);
                Self::connect_leaf_zero_if_true(builder, condition_and_update, &inserted_leaf);
                Self::connect_leaf_zero_if_true(builder, condition_and_update, &sentinel_old);
                Self::connect_leaf_zero_if_true(builder, condition_and_update, &sentinel_new);
                Self::connect_leaf_zero_if_true(builder, condition_and_insert, &update_old_leaf);
                Self::connect_leaf_zero_if_true(builder, condition_and_insert, &update_new_leaf);

                let write_new_root = builder.select_hash(is_insert, sentinel_delta.new_root, update_delta_proof.new_root);
                let new_end_state_root = builder.select_hash(condition, write_new_root, self.end_contract_state_root);
                self.end_contract_state_root = new_end_state_root;
                let result_old_value = builder.select_hash(condition_and_update, update_old_leaf.value, zero_hash);
                let result_new_value = builder.select_hash(condition, value_target, zero_hash);
                let mut result = result_old_value.elements.to_vec();
                result.extend_from_slice(&result_new_value.elements);
                let ck = StateCommandCacheKey::new_write_imt_current_contract(c.condition, c.base_offset, c.capacity, c.key, self.write_epoch);
                self.insert_imt_set_gadget(
                    ck,
                    IMTSetGadget {
                        is_insert,
                        update_old_leaf,
                        update_new_leaf,
                        update_delta_proof,
                        insert_predecessor_old_leaf: predecessor_old,
                        insert_predecessor_new_leaf: predecessor_new,
                        insert_new_leaf: inserted_leaf,
                        insert_predecessor_delta_proof: predecessor_delta,
                        insert_new_leaf_delta_proof: member_delta,
                        sentinel_preimage: sentinel,
                        sentinel_merkle_proof: sentinel_proof,
                        sentinel_old_leaf: sentinel_old,
                        sentinel_new_leaf: sentinel_new,
                        insert_sentinel_delta_proof: sentinel_delta,
                    },
                );
                self.write_epoch += 1;
                result
            }
            DPNStateCmd::GetSelfUserCurrentIMTContractStateValue(c) => {
                let ck = StateCommandCacheKey::new_read_imt_current_contract(c.base_offset, c.capacity, c.key, self.write_epoch);
                if let Some(existing_result) = self.result_map.get(&ck) {
                    existing_result.clone()
                } else {
                    let merkle_proof = MerkleProofGadget::add_virtual_to::<H, F, D>(builder, self.contract_state_tree_height);
                    let leaf = IMTLeafTargets::add_virtual_to(builder);
                    let sentinel = IMTLeafTargets::add_virtual_to(builder);
                    let sentinel_proof = MerkleProofGadget::add_virtual_to::<H, F, D>(builder, self.contract_state_tree_height);
                    let query_key = HashOutTarget {
                        elements: [
                            dpn.resolve_target(c.key[0]),
                            dpn.resolve_target(c.key[1]),
                            dpn.resolve_target(c.key[2]),
                            dpn.resolve_target(c.key[3]),
                        ],
                    };
                    let (physical_base, map_capacity) = Self::verify_imt_map_bounds(
                        builder,
                        dpn.resolve_target(c.base_offset),
                        dpn.resolve_target(c.capacity),
                        builder.constant(F::from_canonical_usize(self.contract_state_tree_height)),
                    );
                    let active = builder._true();
                    let (_virgin, count) = Self::constrain_authenticated_sentinel::<H, F, D>(
                        builder,
                        active,
                        self.end_contract_state_root,
                        physical_base,
                        map_capacity,
                        &sentinel,
                        sentinel_proof.root,
                        sentinel_proof.value,
                        sentinel_proof.index,
                    );
                    let leaf_hash = leaf.hash::<H, F, D>(builder);
                    builder.connect_hashes(merkle_proof.root, self.end_contract_state_root);
                    builder.connect_hashes(leaf_hash, merkle_proof.value);
                    builder.connect_hashes(leaf.key, query_key);
                    Self::connect_query_nonzero(builder, active, query_key);
                    Self::connect_index_in_open_interval(
                        builder,
                        active,
                        merkle_proof.index,
                        physical_base,
                        count,
                    );
                    Self::connect_successor_pair(
                        builder,
                        active,
                        leaf.next_key,
                        leaf.next_index,
                        physical_base,
                        count,
                    );
                    self.insert_imt_read_gadget(
                        ck,
                        IMTReadGadget {
                            merkle_proof,
                            leaf: leaf.clone(),
                            sentinel_preimage: sentinel,
                            sentinel_merkle_proof: sentinel_proof,
                        },
                    );
                    let result = leaf.value.elements.to_vec();
                    self.result_map.insert(ck, result.clone());
                    result
                }
            }
            DPNStateCmd::ContainsSelfUserCurrentIMTContractStateValue(c) => {
                let ck = StateCommandCacheKey::new_read_imt_contains_current_contract(c.base_offset, c.capacity, c.key, self.write_epoch);
                if let Some(existing_result) = self.result_map.get(&ck) {
                    existing_result.clone()
                } else {
                    let end_contract_state_root = self.end_contract_state_root;
                    let mp = MerkleProofGadget::add_virtual_to::<H, F, D>(builder, self.contract_state_tree_height);
                    let leaf = IMTLeafTargets::add_virtual_to(builder);
                    let sentinel = IMTLeafTargets::add_virtual_to(builder);
                    let sentinel_proof = MerkleProofGadget::add_virtual_to::<H, F, D>(builder, self.contract_state_tree_height);
                    let exists = builder.add_virtual_bool_target_safe();
                    let query_key = HashOutTarget {
                        elements: [
                            dpn.resolve_target(c.key[0]),
                            dpn.resolve_target(c.key[1]),
                            dpn.resolve_target(c.key[2]),
                            dpn.resolve_target(c.key[3]),
                        ],
                    };
                    let (physical_base, map_capacity) = Self::verify_imt_map_bounds(
                        builder,
                        dpn.resolve_target(c.base_offset),
                        dpn.resolve_target(c.capacity),
                        builder.constant(F::from_canonical_usize(self.contract_state_tree_height)),
                    );
                    let active = builder._true();
                    let (virgin, count) = Self::constrain_authenticated_sentinel::<H, F, D>(
                        builder,
                        active,
                        end_contract_state_root,
                        physical_base,
                        map_capacity,
                        &sentinel,
                        sentinel_proof.root,
                        sentinel_proof.value,
                        sentinel_proof.index,
                    );
                    let leaf_hash = leaf.hash::<H, F, D>(builder);
                    let key_eq = builder.is_equal_hash(leaf.key, query_key);
                    let not_exists = builder.not(exists);
                    let membership = exists;
                    let initialized = builder.not(virgin);
                    let initialized_absence = builder.and(not_exists, initialized);
                    let virgin_absence = builder.and(not_exists, virgin);
                    builder.connect_hashes(mp.root, end_contract_state_root);
                    builder.connect_hashes_if_true(membership, leaf_hash, mp.value);
                    builder.connect_hashes_if_true(initialized_absence, leaf_hash, mp.value);
                    builder.connect_hashes_if_true(virgin_absence, mp.value, builder.constant_hash(HashOut::ZERO));
                    builder.connect_if_true(membership, key_eq.target, builder._true().target);
                    builder.connect_if_true(virgin_absence, mp.index, physical_base);
                    Self::connect_query_nonzero(builder, active, query_key);
                    Self::connect_index_in_open_interval(
                        builder,
                        membership,
                        mp.index,
                        physical_base,
                        count,
                    );
                    Self::connect_successor_pair(
                        builder,
                        membership,
                        leaf.next_key,
                        leaf.next_index,
                        physical_base,
                        count,
                    );
                    Self::connect_predecessor_role(
                        builder,
                        initialized_absence,
                        &leaf,
                        mp.index,
                        physical_base,
                        count,
                    );
                    let predecessor_before_query = is_qhashout_lt::<F, D>(builder, leaf.key, query_key);
                    let successor_absent = builder.is_zero_hash(leaf.next_key);
                    let query_before_successor = is_qhashout_lt::<F, D>(builder, query_key, leaf.next_key);
                    let successor_gap = builder.or(successor_absent, query_before_successor);
                    let strict_absence = builder.and(predecessor_before_query, successor_gap);
                    builder.connect_if_true(initialized_absence, strict_absence.target, builder._true().target);
                    builder.connect_if_true(virgin, exists.target, builder.zero());
                    self.insert_imt_contains_gadget(ck, mp, leaf, exists.target, sentinel, sentinel_proof);
                    let result = vec![exists.target];
                    self.result_map.insert(ck, result.clone());
                    result
                }
            }
            DPNStateCmd::GetSelfUserExternalIMTContractStateValue(c) => {
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
                        self.result_map.insert(read_root_ck, mp_uct.value.elements.to_vec());
                    }
                    expected_contract_state_tree_root
                };
                let imt_ck = StateCommandCacheKey::new_read_imt_self_user_external_contract(
                    c.contract_id,
                    c.base_offset,
                    c.capacity,
                    c.contract_state_tree_height,
                    c.key,
                    call_epoch,
                );
                if let Some(existing_result) = self.result_map.get(&imt_ck) {
                    existing_result.clone()
                } else {
                    let height = dpn.resolve_target(c.contract_state_tree_height);
                    let checked_height = Self::checked_state_height(builder, height);
                    let state_slot_proof = VariableHeightMerkleProofGadget::add_virtual_to_full::<H, F, D>(builder, 32, Some(height));
                    let sentinel_proof = VariableHeightMerkleProofGadget::add_virtual_to_full::<H, F, D>(builder, 32, Some(height));
                    let leaf = IMTLeafTargets::add_virtual_to(builder);
                    let sentinel = IMTLeafTargets::add_virtual_to(builder);
                    let query_key = HashOutTarget { elements: dpn.resolve_targets_sized::<4>(&c.key) };
                    let (physical_base, map_capacity) = Self::verify_imt_map_bounds(
                        builder,
                        dpn.resolve_target(c.base_offset),
                        dpn.resolve_target(c.capacity),
                        checked_height,
                    );
                    let active = builder._true();
                    let (_virgin, count) = Self::constrain_authenticated_sentinel::<H, F, D>(
                        builder,
                        active,
                        expected_contract_state_tree_root,
                        physical_base,
                        map_capacity,
                        &sentinel,
                        sentinel_proof.root,
                        sentinel_proof.value,
                        sentinel_proof.index,
                    );
                    let leaf_hash = leaf.hash::<H, F, D>(builder);
                    builder.connect_hashes(state_slot_proof.root, expected_contract_state_tree_root);
                    builder.connect_hashes(leaf_hash, state_slot_proof.value);
                    builder.connect_hashes(leaf.key, query_key);
                    Self::connect_query_nonzero(builder, active, query_key);
                    Self::connect_index_in_open_interval(builder, active, state_slot_proof.index, physical_base, count);
                    Self::connect_successor_pair(builder, active, leaf.next_key, leaf.next_index, physical_base, count);
                    self.insert_imt_external_read_gadget(
                        imt_ck,
                        IMTExternalReadGadget {
                            contract_tree_proof: self.merkle_proofs[self.gadget_map[&read_root_ck].gadget_index].clone(),
                            state_slot_proof,
                            leaf: leaf.clone(),
                            sentinel_preimage: sentinel,
                            sentinel_merkle_proof: sentinel_proof,
                        },
                    );
                    let result = leaf.value.elements.to_vec();
                    self.result_map.insert(imt_ck, result.clone());
                    result
                }
            }
            DPNStateCmd::GetOtherUserIMTContractStateValue(c) => {
                let expected_contract_state_tree_root =
                    self.get_other_user_contract_state_root::<H, F, D>(builder, dpn, c.user_id, c.contract_id);
                let imt_ck = StateCommandCacheKey::new_read_imt_other_user_contract(
                    c.user_id,
                    c.contract_id,
                    c.base_offset,
                    c.capacity,
                    c.contract_state_tree_height,
                    c.key,
                    self.write_epoch,
                );
                if let Some(existing_result) = self.result_map.get(&imt_ck) {
                    existing_result.clone()
                } else {
                    let height = dpn.resolve_target(c.contract_state_tree_height);
                    let checked_height = Self::checked_state_height(builder, height);
                    let state_slot_proof = VariableHeightMerkleProofGadget::add_virtual_to_full::<H, F, D>(builder, 32, Some(height));
                    let sentinel_proof = VariableHeightMerkleProofGadget::add_virtual_to_full::<H, F, D>(builder, 32, Some(height));
                    let leaf = IMTLeafTargets::add_virtual_to(builder);
                    let sentinel = IMTLeafTargets::add_virtual_to(builder);
                    let query_key = HashOutTarget { elements: dpn.resolve_targets_sized::<4>(&c.key) };
                    let (physical_base, map_capacity) = Self::verify_imt_map_bounds(
                        builder,
                        dpn.resolve_target(c.base_offset),
                        dpn.resolve_target(c.capacity),
                        checked_height,
                    );
                    let active = builder._true();
                    let (_virgin, count) = Self::constrain_authenticated_sentinel::<H, F, D>(
                        builder,
                        active,
                        expected_contract_state_tree_root,
                        physical_base,
                        map_capacity,
                        &sentinel,
                        sentinel_proof.root,
                        sentinel_proof.value,
                        sentinel_proof.index,
                    );
                    let leaf_hash = leaf.hash::<H, F, D>(builder);
                    builder.connect_hashes(state_slot_proof.root, expected_contract_state_tree_root);
                    builder.connect_hashes(leaf_hash, state_slot_proof.value);
                    builder.connect_hashes(leaf.key, query_key);
                    Self::connect_query_nonzero(builder, active, query_key);
                    Self::connect_index_in_open_interval(builder, active, state_slot_proof.index, physical_base, count);
                    Self::connect_successor_pair(builder, active, leaf.next_key, leaf.next_index, physical_base, count);
                    self.insert_imt_other_user_read_gadget(
                        imt_ck,
                        IMTOtherUserReadGadget {
                            state_slot_proof,
                            leaf: leaf.clone(),
                            sentinel_preimage: sentinel,
                            sentinel_merkle_proof: sentinel_proof,
                        },
                    );
                    let result = leaf.value.elements.to_vec();
                    self.result_map.insert(imt_ck, result.clone());
                    result
                }
            }
            DPNStateCmd::ContainsOtherUserIMTContractStateValue(c) => {
                let expected_contract_state_tree_root =
                    self.get_other_user_contract_state_root::<H, F, D>(builder, dpn, c.user_id, c.contract_id);
                let imt_ck = StateCommandCacheKey::new_imt_contains_other_user_contract(
                    c.user_id,
                    c.contract_id,
                    c.base_offset,
                    c.capacity,
                    c.contract_state_tree_height,
                    c.key,
                    self.write_epoch,
                );
                if let Some(existing_result) = self.result_map.get(&imt_ck) {
                    existing_result.clone()
                } else {
                    let height = dpn.resolve_target(c.contract_state_tree_height);
                    let checked_height = Self::checked_state_height(builder, height);
                    let state_slot_proof = VariableHeightMerkleProofGadget::add_virtual_to_full::<H, F, D>(builder, 32, Some(height));
                    let sentinel_proof = VariableHeightMerkleProofGadget::add_virtual_to_full::<H, F, D>(builder, 32, Some(height));
                    let leaf = IMTLeafTargets::add_virtual_to(builder);
                    let sentinel = IMTLeafTargets::add_virtual_to(builder);
                    let exists = builder.add_virtual_bool_target_safe();
                    let query_key = HashOutTarget { elements: dpn.resolve_targets_sized::<4>(&c.key) };
                    let (physical_base, map_capacity) = Self::verify_imt_map_bounds(
                        builder,
                        dpn.resolve_target(c.base_offset),
                        dpn.resolve_target(c.capacity),
                        checked_height,
                    );
                    let active = builder._true();
                    let (virgin, count) = Self::constrain_authenticated_sentinel::<H, F, D>(
                        builder,
                        active,
                        expected_contract_state_tree_root,
                        physical_base,
                        map_capacity,
                        &sentinel,
                        sentinel_proof.root,
                        sentinel_proof.value,
                        sentinel_proof.index,
                    );
                    let leaf_hash = leaf.hash::<H, F, D>(builder);
                    let key_eq = builder.is_equal_hash(leaf.key, query_key);
                    let not_exists = builder.not(exists);
                    let initialized = builder.not(virgin);
                    let initialized_absence = builder.and(not_exists, initialized);
                    let virgin_absence = builder.and(not_exists, virgin);
                    builder.connect_hashes(state_slot_proof.root, expected_contract_state_tree_root);
                    builder.connect_hashes_if_true(exists, leaf_hash, state_slot_proof.value);
                    builder.connect_hashes_if_true(initialized_absence, leaf_hash, state_slot_proof.value);
                    builder.connect_hashes_if_true(virgin_absence, state_slot_proof.value, builder.constant_hash(HashOut::ZERO));
                    builder.connect_if_true(exists, key_eq.target, builder._true().target);
                    builder.connect_if_true(virgin_absence, state_slot_proof.index, physical_base);
                    Self::connect_query_nonzero(builder, active, query_key);
                    Self::connect_index_in_open_interval(builder, exists, state_slot_proof.index, physical_base, count);
                    Self::connect_successor_pair(builder, exists, leaf.next_key, leaf.next_index, physical_base, count);
                    Self::connect_predecessor_role(
                        builder,
                        initialized_absence,
                        &leaf,
                        state_slot_proof.index,
                        physical_base,
                        count,
                    );
                    let predecessor_before_query = is_qhashout_lt::<F, D>(builder, leaf.key, query_key);
                    let successor_absent = builder.is_zero_hash(leaf.next_key);
                    let query_before_successor = is_qhashout_lt::<F, D>(builder, query_key, leaf.next_key);
                    let successor_gap = builder.or(successor_absent, query_before_successor);
                    let strict_absence = builder.and(predecessor_before_query, successor_gap);
                    builder.connect_if_true(initialized_absence, strict_absence.target, builder._true().target);
                    builder.connect_if_true(virgin, exists.target, builder.zero());
                    self.insert_imt_contains_other_user_gadget(
                        imt_ck,
                        IMTContainsOtherUserGadget {
                            state_slot_proof,
                            leaf,
                            exists: exists.target,
                            sentinel_preimage: sentinel,
                            sentinel_merkle_proof: sentinel_proof,
                        },
                    );
                    let result = vec![exists.target];
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
    use psy_client_data::qdata::imt_contract_state::IMTContractStateLeaf;
    use psy_common_circuit::traits::CreatableTarget;
    use psy_crypto::hash::{
        merkle::{core::{DeltaMerkleProofCore, MerkleProofCore}, utils::simple_merkle_tree::SimpleMerkleTree},
        traits::hasher::{FieldQHasher, PoseidonHasher},
    };
    use psy_vm::dpn::ops::{
        op_types::{encode_indexed_op_id, DPNBuiltInDataType, DPNIndexedVarDef, DPNOpType},
        state_cmd::data::{DPNStateCmd, DPNStateCmdSetIMTContractStateValue},
    };

    use super::*;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type Tree = SimpleMerkleTree<PoseidonHash, QHashOut<F>>;
    const HEIGHT: usize = 8;
    const CAPACITY: u64 = 4;

    struct ThreeWrite {
        predecessor_old: IMTContractStateLeaf<F>,
        predecessor_new: IMTContractStateLeaf<F>,
        member: IMTContractStateLeaf<F>,
        sentinel_r0: IMTContractStateLeaf<F>,
        sentinel_r2: IMTContractStateLeaf<F>,
        sentinel_r3: IMTContractStateLeaf<F>,
        predecessor_delta: DeltaMerkleProofCore<QHashOut<F>>,
        member_delta: DeltaMerkleProofCore<QHashOut<F>>,
        sentinel_delta: DeltaMerkleProofCore<QHashOut<F>>,
        sentinel_proof: MerkleProofCore<QHashOut<F>>,
    }

    fn hashed(leaf: &IMTContractStateLeaf<F>) -> QHashOut<F> {
        leaf.qfhash::<PoseidonHasher>()
    }

    fn zero_delta() -> DeltaMerkleProofCore<QHashOut<F>> {
        DeltaMerkleProofCore {
            old_root: QHashOut::ZERO,
            old_value: QHashOut::ZERO,
            new_root: QHashOut::ZERO,
            new_value: QHashOut::ZERO,
            index: 0,
            siblings: vec![QHashOut::ZERO; HEIGHT],
        }
    }

    fn virgin_insert(base: u64, key: QHashOut<F>, value: QHashOut<F>) -> ThreeWrite {
        let mut tree = Tree::new(HEIGHT as u8);
        let sentinel_proof = tree.get_leaf(base);
        let member_index = base + 1;
        let member = IMTContractStateLeaf::new(key, value, QHashOut::ZERO, F::ZERO);
        let predecessor_new = IMTContractStateLeaf::new(QHashOut::ZERO, QHashOut::ZERO, key, F::from_canonical_u64(member_index));
        let predecessor_delta = tree.set_leaf(base, hashed(&predecessor_new));
        let member_delta = tree.set_leaf(member_index, hashed(&member));
        let sentinel_r3 = IMTContractStateLeaf::new(QHashOut::ZERO, QHashOut::from_values(1, 0, 0, 0), key, F::from_canonical_u64(member_index));
        let sentinel_delta = tree.set_leaf(base, hashed(&sentinel_r3));
        ThreeWrite {
            predecessor_old: IMTContractStateLeaf::default(),
            predecessor_new,
            member,
            sentinel_r0: IMTContractStateLeaf::default(),
            sentinel_r2: predecessor_new,
            sentinel_r3,
            predecessor_delta,
            member_delta,
            sentinel_delta,
            sentinel_proof,
        }
    }

    fn member_predecessor_insert(base: u64, first: QHashOut<F>, second: QHashOut<F>, value: QHashOut<F>) -> ThreeWrite {
        let mut tree = Tree::new(HEIGHT as u8);
        let first_member = IMTContractStateLeaf::new(first, QHashOut::from_values(1, 0, 0, 0), QHashOut::ZERO, F::ZERO);
        let first_sentinel = IMTContractStateLeaf::new(QHashOut::ZERO, QHashOut::from_values(1, 0, 0, 0), first, F::from_canonical_u64(base + 1));
        tree.set_leaf(base, hashed(&first_sentinel));
        tree.set_leaf(base + 1, hashed(&first_member));
        let sentinel_proof = tree.get_leaf(base);
        let predecessor_new = first_member.with_new_next(second, F::from_canonical_u64(base + 2));
        let member = IMTContractStateLeaf::new(second, value, QHashOut::ZERO, F::ZERO);
        let predecessor_delta = tree.set_leaf(base + 1, hashed(&predecessor_new));
        let member_delta = tree.set_leaf(base + 2, hashed(&member));
        let sentinel_r3 = IMTContractStateLeaf::new(QHashOut::ZERO, QHashOut::from_values(2, 0, 0, 0), first, F::from_canonical_u64(base + 1));
        let sentinel_delta = tree.set_leaf(base, hashed(&sentinel_r3));
        ThreeWrite {
            predecessor_old: first_member,
            predecessor_new,
            member,
            sentinel_r0: first_sentinel,
            sentinel_r2: first_sentinel,
            sentinel_r3,
            predecessor_delta,
            member_delta,
            sentinel_delta,
            sentinel_proof,
        }
    }

    fn reader(builder: &mut CircuitBuilder<F, D>, root: HashOut<F>) -> (SimpleDPNBuilder<F, D>, StateReaderGadget) {
        let zero = builder.constant_hash(HashOut::ZERO);
        let dpn = SimpleDPNBuilder::new_with_contract_ctx(Vec::new(), builder.zero(), builder.zero(), builder.zero(), builder.zero(), builder.zero(), HashOutTarget { elements: core::array::from_fn(|_| builder.add_virtual_target()) }, HashOutTarget { elements: core::array::from_fn(|_| builder.add_virtual_target()) });
        let reader = StateReaderGadget::new(PsyCheckpointGlobalStateRootsGadget::create_virtual(builder), zero, zero, builder.constant_hash(root), HEIGHT, zero, HEIGHT, false, PsyCheckpointLeafStatsGadget::create_virtual(builder), zero);
        (dpn, reader)
    }

    fn command(base: u64, capacity: u64) -> DPNStateCmd<u64> {
        DPNStateCmd::SetIMTContractStateValue(DPNStateCmdSetIMTContractStateValue {
            condition: encode_indexed_op_id(DPNBuiltInDataType::Target, 0),
            base_offset: base,
            capacity,
            key: core::array::from_fn(|i| encode_indexed_op_id(DPNBuiltInDataType::Target, (i + 1) as u64)),
            value: core::array::from_fn(|i| encode_indexed_op_id(DPNBuiltInDataType::Target, (i + 5) as u64)),
        })
    }

    fn push_inputs(builder: &mut CircuitBuilder<F, D>, dpn: &mut SimpleDPNBuilder<F, D>) -> Vec<Target> {
        (0..9).map(|index| {
            let target = builder.add_virtual_target();
            dpn.push_external_target(index, target);
            target
        }).collect()
    }

    fn assign_inputs(pw: &mut PartialWitness<F>, targets: &[Target], key: QHashOut<F>, value: QHashOut<F>, condition: F) {
        pw.set_target(targets[0], condition).unwrap();
        for (target, limb) in targets[1..5].iter().copied().zip(key.0.elements) {
            pw.set_target(target, limb).unwrap();
        }
        for (target, limb) in targets[5..9].iter().copied().zip(value.0.elements) {
            pw.set_target(target, limb).unwrap();
        }
    }

    fn assign_insert(pw: &mut PartialWitness<F>, gadget: &IMTSetGadget, write: &ThreeWrite) {
        pw.set_bool_target(gadget.is_insert, true).unwrap();
        gadget.update_old_leaf.set_witness(pw, &IMTContractStateLeaf::default()).unwrap();
        gadget.update_new_leaf.set_witness(pw, &IMTContractStateLeaf::default()).unwrap();
        gadget.update_delta_proof.set_witness_core_proof_q(pw, &zero_delta()).unwrap();
        gadget.insert_predecessor_old_leaf.set_witness(pw, &write.predecessor_old).unwrap();
        gadget.insert_predecessor_new_leaf.set_witness(pw, &write.predecessor_new).unwrap();
        gadget.insert_new_leaf.set_witness(pw, &write.member).unwrap();
        gadget.insert_predecessor_delta_proof.set_witness_core_proof_q(pw, &write.predecessor_delta).unwrap();
        gadget.insert_new_leaf_delta_proof.set_witness_core_proof_q(pw, &write.member_delta).unwrap();
        gadget.insert_sentinel_delta_proof.set_witness_core_proof_q(pw, &write.sentinel_delta).unwrap();
        gadget.sentinel_preimage.set_witness(pw, &write.sentinel_r0).unwrap();
        gadget.sentinel_merkle_proof.set_witness_generic(pw, F::from_canonical_u64(write.sentinel_proof.index), write.sentinel_proof.value, &write.sentinel_proof.siblings).unwrap();
        gadget.sentinel_old_leaf.set_witness(pw, &write.sentinel_r2).unwrap();
        gadget.sentinel_new_leaf.set_witness(pw, &write.sentinel_r3).unwrap();
    }

    fn prove_insert(base: u64, key: QHashOut<F>, value: QHashOut<F>, write: &ThreeWrite) {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let (mut dpn, mut state_reader) = reader(&mut builder, write.predecessor_delta.old_root.0);
        let targets = push_inputs(&mut builder, &mut dpn);
        let mut cmd = command(encode_indexed_op_id(DPNBuiltInDataType::Target, 100), encode_indexed_op_id(DPNBuiltInDataType::Target, 101));
        dpn.process_var_def(&mut builder, &DPNIndexedVarDef { data_type: DPNBuiltInDataType::Target, index: 100, op_type: DPNOpType::Constant, inputs: vec![base] });
        dpn.process_var_def(&mut builder, &DPNIndexedVarDef { data_type: DPNBuiltInDataType::Target, index: 101, op_type: DPNOpType::Constant, inputs: vec![CAPACITY] });
        if let DPNStateCmd::SetIMTContractStateValue(set) = &mut cmd {
            set.base_offset = encode_indexed_op_id(DPNBuiltInDataType::Target, 100);
            set.capacity = encode_indexed_op_id(DPNBuiltInDataType::Target, 101);
        }
        state_reader.injest_symbolic_state_command::<PoseidonHash, F, D>(&mut builder, &dpn, &cmd);
        builder.register_public_inputs(&state_reader.end_contract_state_root.elements);
        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        assign_inputs(&mut pw, &targets, key, value, F::ONE);
        assign_insert(&mut pw, &state_reader.imt_set_requests[0], write);
        let proof = data.prove(pw).expect("three-write IMT insertion should prove");
        assert_eq!(proof.public_inputs[0], write.sentinel_delta.new_root.0.elements[0]);
        data.verify(proof).expect("three-write IMT insertion should verify");
    }

    #[test]
    fn state_reader_imt_virgin_and_member_predecessor_insertions_prove() {
        let first = QHashOut::from_values(10, 0, 0, 0);
        let value = QHashOut::from_values(100, 200, 300, 400);
        prove_insert(1, first, value, &virgin_insert(1, first, value));
        let second = QHashOut::from_values(30, 0, 0, 0);
        prove_insert(1, second, value, &member_predecessor_insert(1, first, second, value));
    }

    #[test]
    fn state_reader_imt_update_preserves_sentinel_count() {
        let mut tree = Tree::new(HEIGHT as u8);
        let key = QHashOut::from_values(10, 0, 0, 0);
        let old = IMTContractStateLeaf::new(key, QHashOut::from_values(1, 0, 0, 0), QHashOut::ZERO, F::ZERO);
        let sentinel = IMTContractStateLeaf::new(QHashOut::ZERO, QHashOut::from_values(1, 0, 0, 0), key, F::ONE);
        tree.set_leaf(0, hashed(&sentinel));
        tree.set_leaf(1, hashed(&old));
        let updated = old.with_new_value(QHashOut::from_values(9, 0, 0, 0));
        let update_delta = tree.set_leaf(1, hashed(&updated));
        let sentinel_proof = tree.get_leaf(0);
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let (mut dpn, mut state_reader) = reader(&mut builder, update_delta.old_root.0);
        let targets = push_inputs(&mut builder, &mut dpn);
        dpn.process_var_def(&mut builder, &DPNIndexedVarDef { data_type: DPNBuiltInDataType::Target, index: 101, op_type: DPNOpType::Constant, inputs: vec![CAPACITY] });
        state_reader.injest_symbolic_state_command::<PoseidonHash, F, D>(&mut builder, &dpn, &command(0, encode_indexed_op_id(DPNBuiltInDataType::Target, 101)));
        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        assign_inputs(&mut pw, &targets, key, updated.value, F::ONE);
        let gadget = &state_reader.imt_set_requests[0];
        pw.set_bool_target(gadget.is_insert, false).unwrap();
        gadget.update_old_leaf.set_witness(&mut pw, &old).unwrap();
        gadget.update_new_leaf.set_witness(&mut pw, &updated).unwrap();
        gadget.update_delta_proof.set_witness_core_proof_q(&mut pw, &update_delta).unwrap();
        gadget.sentinel_preimage.set_witness(&mut pw, &sentinel).unwrap();
        gadget.sentinel_merkle_proof.set_witness_generic(&mut pw, F::ZERO, sentinel_proof.value, &sentinel_proof.siblings).unwrap();
        for leaf in [&gadget.insert_predecessor_old_leaf, &gadget.insert_predecessor_new_leaf, &gadget.insert_new_leaf, &gadget.sentinel_old_leaf, &gadget.sentinel_new_leaf] {
            leaf.set_witness(&mut pw, &IMTContractStateLeaf::default()).unwrap();
        }
        for delta in [&gadget.insert_predecessor_delta_proof, &gadget.insert_new_leaf_delta_proof, &gadget.insert_sentinel_delta_proof] {
            delta.set_witness_core_proof_q(&mut pw, &zero_delta()).unwrap();
        }
        let proof = data.prove(pw).expect("ordinary IMT update should prove");
        data.verify(proof).expect("ordinary IMT update should verify");
    }

    #[test]
    fn state_reader_imt_disabled_set_keeps_root_and_returns_zeros() {
        let start = HashOut { elements: [F::from_canonical_u64(7), F::ZERO, F::ZERO, F::ZERO] };
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let (mut dpn, mut state_reader) = reader(&mut builder, start);
        let targets = push_inputs(&mut builder, &mut dpn);
        dpn.process_var_def(&mut builder, &DPNIndexedVarDef { data_type: DPNBuiltInDataType::Target, index: 101, op_type: DPNOpType::Constant, inputs: vec![CAPACITY] });
        let result = state_reader.injest_symbolic_state_command::<PoseidonHash, F, D>(&mut builder, &dpn, &command(0, encode_indexed_op_id(DPNBuiltInDataType::Target, 101)));
        builder.register_public_inputs(&state_reader.end_contract_state_root.elements);
        builder.register_public_inputs(&result);
        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        assign_inputs(&mut pw, &targets, QHashOut::from_values(3, 0, 0, 0), QHashOut::from_values(4, 0, 0, 0), F::ZERO);
        let gadget = &state_reader.imt_set_requests[0];
        pw.set_bool_target(gadget.is_insert, false).unwrap();
        for leaf in [&gadget.update_old_leaf, &gadget.update_new_leaf, &gadget.insert_predecessor_old_leaf, &gadget.insert_predecessor_new_leaf, &gadget.insert_new_leaf, &gadget.sentinel_preimage, &gadget.sentinel_old_leaf, &gadget.sentinel_new_leaf] {
            leaf.set_witness(&mut pw, &IMTContractStateLeaf::default()).unwrap();
        }
        let opening = zero_delta();
        gadget.sentinel_merkle_proof.set_witness_generic(&mut pw, F::ZERO, QHashOut::ZERO, &opening.siblings).unwrap();
        for delta in [&gadget.update_delta_proof, &gadget.insert_predecessor_delta_proof, &gadget.insert_new_leaf_delta_proof, &gadget.insert_sentinel_delta_proof] {
            delta.set_witness_core_proof_q(&mut pw, &opening).unwrap();
        }
        let proof = data.prove(pw).expect("disabled IMT set should prove");
        assert_eq!(&proof.public_inputs[..4], &start.elements);
        assert!(proof.public_inputs[4..].iter().all(|limb| *limb == F::ZERO));
        data.verify(proof).expect("disabled IMT set should verify");
    }
}
