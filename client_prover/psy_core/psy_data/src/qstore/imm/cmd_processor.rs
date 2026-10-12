use plonky2::{field::goldilocks_field::GoldilocksField, hash::hash_types::RichField};
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::hash::merkle::core::{DeltaMerkleProofCore, MerkleProofCore};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::cmd::{
    QSRCmdGetBlockState, QSRCmdGetCheckpointLeafData, QSRCmdGetContractCodeDefinition, QSRCmdGetContractLeafData, QSRCmdGetUserLeafData, QSRHashCmd,
    QSRMerkleCmd,
};
use crate::{
    dpn::proving_session::DPNProvingSessionSimpleMethodCall,
    qdata::{
        checkpoint::{PsyBlockState, PsyCheckpointGlobalStateRoots, PsyCheckpointLeaf, PsyCheckpointLeafStats},
        contract::{ContractCodeDefinition, PsyContractLeaf},
        imt_contract_state::IMTContractStateLeaf,
        user::PsyUserLeaf,
    },
};

pub trait QUserIdManager {
    fn get_user_id(&self) -> u64;
    fn set_user_id(&mut self, user_id: u64);
}

impl QUserIdManager for kvq::memory::simple::KVQSimpleMemoryBackingStore {
    fn get_user_id(&self) -> u64 {
        0
    }

    fn set_user_id(&mut self, _user_id: u64) {
        // No-op for memory store
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PsyReadCommandBatchInput {
    pub get_user_leaf: Vec<QSRCmdGetUserLeafData>,
    pub get_contract_leaf: Vec<QSRCmdGetContractLeafData>,
    pub get_contract_code: Vec<QSRCmdGetContractCodeDefinition>,
    pub get_checkpoint_leaf: Vec<QSRCmdGetCheckpointLeafData>,
    pub get_block_state: Vec<QSRCmdGetBlockState>,
    pub get_merkle_proof: Vec<QSRMerkleCmd>,
    pub get_hash: Vec<QSRHashCmd>,
}
impl PsyReadCommandBatchInput {
    pub fn new() -> Self {
        Self {
            get_user_leaf: Vec::new(),
            get_contract_leaf: Vec::new(),
            get_contract_code: Vec::new(),
            get_checkpoint_leaf: Vec::new(),
            get_block_state: Vec::new(),
            get_merkle_proof: Vec::new(),
            get_hash: Vec::new(),
        }
    }
    pub fn push_get_user_leaf(&mut self, checkpoint_id: u64, user_id: u64) -> usize {
        let id = self.get_user_leaf.len();
        self.get_user_leaf.push(QSRCmdGetUserLeafData { checkpoint_id, user_id });
        id
    }
    pub fn push_get_contract_leaf(&mut self, contract_id: u64) -> usize {
        let id = self.get_contract_leaf.len();
        self.get_contract_leaf.push(QSRCmdGetContractLeafData { contract_id });
        id
    }
    pub fn push_get_contract_code(&mut self, contract_id: u64) -> usize {
        let id = self.get_contract_code.len();
        self.get_contract_code.push(QSRCmdGetContractCodeDefinition { contract_id });
        id
    }
    pub fn push_get_checkpoint_leaf(&mut self, checkpoint_id: u64) -> usize {
        let id = self.get_checkpoint_leaf.len();
        self.get_checkpoint_leaf.push(QSRCmdGetCheckpointLeafData { checkpoint_id });
        id
    }
    pub fn push_get_block_state(&mut self, checkpoint_id: u64) -> usize {
        let id = self.get_block_state.len();
        self.get_block_state.push(QSRCmdGetBlockState { checkpoint_id });
        id
    }
    pub fn push_get_merkle_proof(&mut self, cmd: QSRMerkleCmd) -> usize {
        let id = self.get_merkle_proof.len();
        self.get_merkle_proof.push(cmd);
        id
    }
    pub fn push_get_hash(&mut self, cmd: QSRHashCmd) -> usize {
        let id = self.get_hash.len();
        self.get_hash.push(cmd);
        id
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct PsyReadCommandBatchOutput<F: RichField> {
    pub get_user_leaf: Vec<PsyUserLeaf<F>>,
    pub get_contract_leaf: Vec<PsyContractLeaf<F>>,
    pub get_contract_code: Vec<ContractCodeDefinition>,
    pub get_checkpoint_leaf: Vec<PsyCheckpointLeaf<F>>,
    pub get_block_state: Vec<PsyBlockState>,
    pub get_merkle_proof: Vec<MerkleProofCore<QHashOut<F>>>,
    pub get_hash: Vec<QHashOut<F>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct DPNReadOtherUserLeafMerkleProof<F: RichField> {
    pub user_tree_proof: MerkleProofCore<QHashOut<F>>,
    pub user_leaf: PsyUserLeaf<F>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct DPNReadOtherUserContractStateLeafMerkleProof<F: RichField> {
    pub user_leaf_witness: DPNReadOtherUserLeafMerkleProof<F>,
    pub contract_state_proof: MerkleProofCore<QHashOut<F>>,
    pub state_slot_proofs: Vec<MerkleProofCore<QHashOut<F>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct DPNInvokeDeferredMethodCallWitness<F: RichField> {
    pub call_data: DPNProvingSessionSimpleMethodCall<F>,
    pub insertion_proof: DeltaMerkleProofCore<QHashOut<F>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct DPNCheckpointLeafStatsWitness<F: RichField> {
    pub checkpoint_leaf_stats: PsyCheckpointLeafStats<F>,
    pub checkpoint_state_roots: PsyCheckpointGlobalStateRoots<F>,
    pub checkpoint_historical_proof: MerkleProofCore<QHashOut<F>>, // Proves this checkpoint existed historically
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct DPNClearEntireTreeWitness<F: RichField> {
    pub state_tree_height: u64,
    pub zero_hash: QHashOut<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct DPNContractLeafWitness<F: RichField> {
    pub contract_leaf: PsyContractLeaf<F>,
    pub contract_tree_proof: MerkleProofCore<QHashOut<F>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct DPNCheckpointGlobalStateRootsWitness<F: RichField> {
    pub checkpoint_state_roots: PsyCheckpointGlobalStateRoots<F>,
    pub checkpoint_leaf_stats: PsyCheckpointLeafStats<F>,
    pub checkpoint_historical_proof: MerkleProofCore<QHashOut<F>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct DPNIMTContainsWitness<F: RichField> {
    pub exists: bool,
    pub leaf_preimage: IMTContractStateLeaf<F>,
    pub merkle_proof: MerkleProofCore<QHashOut<F>>,
    /// Starting sentinel at the operation's starting CSTATE root.
    pub sentinel_preimage: IMTContractStateLeaf<F>,
    /// Membership path of `sentinel_preimage` under that same root.
    pub sentinel_merkle_proof: MerkleProofCore<QHashOut<F>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct DPNIMTContainsOtherUserWitness<F: RichField> {
    pub exists: bool,
    pub user_leaf_witness: DPNReadOtherUserLeafMerkleProof<F>,
    pub contract_state_proof: MerkleProofCore<QHashOut<F>>,
    pub state_slot_proof: MerkleProofCore<QHashOut<F>>,
    pub leaf_preimage: IMTContractStateLeaf<F>,
    /// Starting sentinel at the operation's starting CSTATE root.
    pub sentinel_preimage: IMTContractStateLeaf<F>,
    /// Membership path of `sentinel_preimage` under that same root.
    pub sentinel_merkle_proof: MerkleProofCore<QHashOut<F>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct DPNIMTReadWitness<F: RichField> {
    pub leaf_preimage: IMTContractStateLeaf<F>,
    pub merkle_proof: MerkleProofCore<QHashOut<F>>,
    /// Starting sentinel at the operation's starting CSTATE root.
    pub sentinel_preimage: IMTContractStateLeaf<F>,
    /// Membership path of `sentinel_preimage` under that same root.
    pub sentinel_merkle_proof: MerkleProofCore<QHashOut<F>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct DPNIMTSelfUserExternalReadWitness<F: RichField> {
    pub contract_tree_proof: MerkleProofCore<QHashOut<F>>,
    pub state_slot_proof: MerkleProofCore<QHashOut<F>>,
    pub leaf_preimage: IMTContractStateLeaf<F>,
    /// Starting sentinel at the operation's starting CSTATE root.
    pub sentinel_preimage: IMTContractStateLeaf<F>,
    /// Membership path of `sentinel_preimage` under that same root.
    pub sentinel_merkle_proof: MerkleProofCore<QHashOut<F>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct DPNIMTOtherUserReadWitness<F: RichField> {
    pub user_leaf_witness: DPNReadOtherUserLeafMerkleProof<F>,
    pub contract_state_proof: MerkleProofCore<QHashOut<F>>,
    pub state_slot_proof: MerkleProofCore<QHashOut<F>>,
    pub leaf_preimage: IMTContractStateLeaf<F>,
    /// Starting sentinel at the operation's starting CSTATE root.
    pub sentinel_preimage: IMTContractStateLeaf<F>,
    /// Membership path of `sentinel_preimage` under that same root.
    pub sentinel_merkle_proof: MerkleProofCore<QHashOut<F>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct DPNIMTSetWitness<F: RichField> {
    pub delta_merkle_proofs: Vec<DeltaMerkleProofCore<QHashOut<F>>>,
    pub is_insert: bool,
    pub old_leaf: IMTContractStateLeaf<F>,
    pub new_leaf: IMTContractStateLeaf<F>,
    pub predecessor_old_leaf: IMTContractStateLeaf<F>,
    pub predecessor_new_leaf: IMTContractStateLeaf<F>,
    /// Starting sentinel authenticated at R0.
    pub sentinel_preimage: IMTContractStateLeaf<F>,
    /// Membership path of `sentinel_preimage` under the starting CSTATE root.
    pub sentinel_merkle_proof: MerkleProofCore<QHashOut<F>>,
    /// Sentinel immediately before the final count write, at R2. Zero for an ordinary update.
    pub sentinel_old_leaf: IMTContractStateLeaf<F>,
    /// Sentinel immediately after the final count write, at R3. Zero for an ordinary update.
    pub sentinel_new_leaf: IMTContractStateLeaf<F>,
}

/// Delta-vector lengths selected by a set command before any proof is indexed.
pub const IMT_SET_DISABLED_DELTA_LEN: usize = 0;
pub const IMT_SET_UPDATE_DELTA_LEN: usize = 1;
pub const IMT_SET_INSERT_DELTA_LEN: usize = 3;

impl<F: RichField> DPNIMTSetWitness<F> {
    /// Return the delta vector only after its mode length is exact.
    ///
    /// A disabled conditional set has length 0, an ordinary update has length 1,
    /// and an insertion has length 3 in the order predecessor, member, sentinel.
    /// Callers index only the returned slice.
    pub fn delta_proofs(&self) -> anyhow::Result<&[DeltaMerkleProofCore<QHashOut<F>>]> {
        match (self.is_insert, self.delta_merkle_proofs.len()) {
            (_, IMT_SET_DISABLED_DELTA_LEN) | (false, IMT_SET_UPDATE_DELTA_LEN) | (true, IMT_SET_INSERT_DELTA_LEN) => {
                Ok(&self.delta_merkle_proofs)
            }
            (_, actual) => anyhow::bail!(
                "IMT set delta length {actual} does not match disabled 0, update 1, or insert 3"
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub enum DPNStateCmdWitness<F: RichField> {
    MerkleProof(MerkleProofCore<QHashOut<F>>),
    DeltaMerkleProof(DeltaMerkleProofCore<QHashOut<F>>),
    MerkleProofArray(Vec<MerkleProofCore<QHashOut<F>>>),
    DeltaMerkleProofArray(Vec<DeltaMerkleProofCore<QHashOut<F>>>),
    ReadOtherUserContractState(DPNReadOtherUserContractStateLeafMerkleProof<F>),
    InvokeExternalContractFunctionDeferred(DPNInvokeDeferredMethodCallWitness<F>),
    CheckpointLeafStats(DPNCheckpointLeafStatsWitness<F>),
    CheckpointGlobalStateRoots(DPNCheckpointGlobalStateRootsWitness<F>),
    ClearEntireTree(DPNClearEntireTreeWitness<F>),
    ContractLeaf(DPNContractLeafWitness<F>),
    IMTSet(DPNIMTSetWitness<F>),
    IMTContains(DPNIMTContainsWitness<F>),
    IMTContainsOtherUser(DPNIMTContainsOtherUserWitness<F>),
    IMTRead(DPNIMTReadWitness<F>),
    IMTSelfUserExternalRead(DPNIMTSelfUserExternalReadWitness<F>),
    IMTOtherUserRead(DPNIMTOtherUserReadWitness<F>),
    TargetArray(Vec<F>),
    TargetArray2D(Vec<Vec<F>>),
}

impl<F: RichField> DPNStateCmdWitness<F> {
    pub fn get_merkle_proof_ref(&self) -> &MerkleProofCore<QHashOut<F>> {
        match &self {
            DPNStateCmdWitness::MerkleProof(merkle_proof) => merkle_proof,
            _ => panic!("get_merkle_proof_ref expects witnesss type to be MerkleProof, but got {:?}", &self),
        }
    }
    pub fn get_delta_merkle_proof_ref(&self) -> &DeltaMerkleProofCore<QHashOut<F>> {
        match &self {
            DPNStateCmdWitness::DeltaMerkleProof(delta_merkle_proof) => delta_merkle_proof,
            _ => panic!(
                "get_delta_merkle_proof_ref expects witnesss type to be DeltaMerkleProof, but got {:?}",
                &self
            ),
        }
    }
    pub fn get_merkle_proof_array_ref(&self) -> &Vec<MerkleProofCore<QHashOut<F>>> {
        match &self {
            DPNStateCmdWitness::MerkleProofArray(merkle_proofs) => merkle_proofs,
            _ => panic!(
                "get_merkle_proof_array_ref expects witnesss type to be MerkleProofArray, but got {:?}",
                &self
            ),
        }
    }
    pub fn get_delta_merkle_proof_array_ref(&self) -> &Vec<DeltaMerkleProofCore<QHashOut<F>>> {
        match &self {
            DPNStateCmdWitness::DeltaMerkleProofArray(delta_merkle_proofs) => delta_merkle_proofs,
            _ => panic!(
                "get_delta_merkle_proof_array_ref expects witnesss type to be DeltaMerkleProofArray, but got {:?}",
                &self
            ),
        }
    }

    pub fn get_read_other_contract_state_ref(&self) -> &DPNReadOtherUserContractStateLeafMerkleProof<F> {
        match &self {
            DPNStateCmdWitness::ReadOtherUserContractState(w) => w,
            _ => panic!(
                "get_read_other_contract_state_ref expects witnesss type to be ReadOtherUserContractState, but got {:?}",
                &self
            ),
        }
    }

    pub fn get_invoke_external_function_deferred_ref(&self) -> &DPNInvokeDeferredMethodCallWitness<F> {
        match &self {
            DPNStateCmdWitness::InvokeExternalContractFunctionDeferred(w) => w,
            _ => panic!(
                "get_invoke_external_function_deferred_ref expects witnesss type to be InvokeExternalContractFunctionDeferred, but got {:?}",
                &self
            ),
        }
    }
    pub fn get_target_array_ref(&self) -> &Vec<F> {
        match &self {
            DPNStateCmdWitness::TargetArray(w) => w,
            _ => panic!("get_target_array_ref expects witnesss type to be TargetArray, but got {:?}", &self),
        }
    }
    pub fn get_target_array_2d_ref(&self) -> &Vec<Vec<F>> {
        match &self {
            DPNStateCmdWitness::TargetArray2D(w) => w,
            _ => panic!("get_target_array_2d_ref expects witnesss type to be TargetArray2D, but got {:?}", &self),
        }
    }
    pub fn get_checkpoint_leaf_stats_ref(&self) -> &DPNCheckpointLeafStatsWitness<F> {
        match &self {
            DPNStateCmdWitness::CheckpointLeafStats(stats) => stats,
            _ => panic!(
                "get_checkpoint_leaf_stats_ref expects witness type to be CheckpointLeafStats, but got {:?}",
                &self
            ),
        }
    }
    pub fn get_checkpoint_global_state_roots_ref(&self) -> &DPNCheckpointGlobalStateRootsWitness<F> {
        match &self {
            DPNStateCmdWitness::CheckpointGlobalStateRoots(witness) => witness,
            _ => panic!(
                "get_checkpoint_global_state_roots_ref expects witness type to be CheckpointGlobalStateRoots, but got {:?}",
                &self
            ),
        }
    }
    pub fn get_clear_entire_tree_ref(&self) -> &DPNClearEntireTreeWitness<F> {
        match &self {
            DPNStateCmdWitness::ClearEntireTree(witness) => witness,
            _ => panic!(
                "get_clear_entire_tree_ref expects witness type to be ClearEntireTree, but got {:?}",
                &self
            ),
        }
    }
    pub fn get_contract_leaf_ref(&self) -> &DPNContractLeafWitness<F> {
        match &self {
            DPNStateCmdWitness::ContractLeaf(witness) => witness,
            _ => panic!("get_contract_leaf_ref expects witness type to be ContractLeaf, but got {:?}", &self),
        }
    }
    pub fn get_imt_contains_ref(&self) -> &DPNIMTContainsWitness<F> {
        match &self {
            DPNStateCmdWitness::IMTContains(w) => w,
            _ => panic!("get_imt_contains_ref expects IMTContains, but got {:?}", &self),
        }
    }
    pub fn get_imt_contains_other_user_ref(&self) -> &DPNIMTContainsOtherUserWitness<F> {
        match &self {
            DPNStateCmdWitness::IMTContainsOtherUser(w) => w,
            _ => panic!("get_imt_contains_other_user_ref expects IMTContainsOtherUser, but got {:?}", &self),
        }
    }
    pub fn get_imt_set_ref(&self) -> &DPNIMTSetWitness<F> {
        match &self {
            DPNStateCmdWitness::IMTSet(w) => w,
            _ => panic!("get_imt_set_ref expects IMTSet, but got {:?}", &self),
        }
    }
    pub fn get_imt_read_ref(&self) -> &DPNIMTReadWitness<F> {
        match &self {
            DPNStateCmdWitness::IMTRead(w) => w,
            _ => panic!("get_imt_read_ref expects IMTRead, but got {:?}", &self),
        }
    }
    pub fn get_imt_self_user_external_read_ref(&self) -> &DPNIMTSelfUserExternalReadWitness<F> {
        match &self {
            DPNStateCmdWitness::IMTSelfUserExternalRead(w) => w,
            _ => panic!("get_imt_self_user_external_read_ref expects IMTSelfUserExternalRead, but got {:?}", &self),
        }
    }
    pub fn get_imt_other_user_read_ref(&self) -> &DPNIMTOtherUserReadWitness<F> {
        match &self {
            DPNStateCmdWitness::IMTOtherUserRead(w) => w,
            _ => panic!("get_imt_other_user_read_ref expects IMTOtherUserRead, but got {:?}", &self),
        }
    }
    pub fn get_merkle_proof(self) -> MerkleProofCore<QHashOut<F>> {
        match self {
            DPNStateCmdWitness::MerkleProof(merkle_proof) => merkle_proof,
            _ => panic!("get_merkle_proof expects witnesss type to be MerkleProof, but got {:?}", &self),
        }
    }
    pub fn get_delta_merkle_proof(self) -> DeltaMerkleProofCore<QHashOut<F>> {
        match self {
            DPNStateCmdWitness::DeltaMerkleProof(delta_merkle_proof) => delta_merkle_proof,
            _ => panic!("get_delta_merkle_proof expects witnesss type to be DeltaMerkleProof, but got {:?}", &self),
        }
    }
    pub fn get_merkle_proof_array(self) -> Vec<MerkleProofCore<QHashOut<F>>> {
        match self {
            DPNStateCmdWitness::MerkleProofArray(merkle_proofs) => merkle_proofs,
            _ => panic!("get_merkle_proof_array expects witnesss type to be MerkleProofArray, but got {:?}", &self),
        }
    }
    pub fn get_delta_merkle_proof_array(self) -> Vec<DeltaMerkleProofCore<QHashOut<F>>> {
        match self {
            DPNStateCmdWitness::DeltaMerkleProofArray(delta_merkle_proofs) => delta_merkle_proofs,
            _ => panic!(
                "get_delta_merkle_proof_array expects witnesss type to be DeltaMerkleProofArray, but got {:?}",
                &self
            ),
        }
    }

    pub fn get_read_other_contract_state(self) -> DPNReadOtherUserContractStateLeafMerkleProof<F> {
        match self {
            DPNStateCmdWitness::ReadOtherUserContractState(w) => w,
            _ => panic!(
                "get_read_other_contract_state expects witnesss type to be ReadOtherUserContractState, but got {:?}",
                &self
            ),
        }
    }

    pub fn get_invoke_external_function_deferred(self) -> DPNInvokeDeferredMethodCallWitness<F> {
        match self {
            DPNStateCmdWitness::InvokeExternalContractFunctionDeferred(w) => w,
            _ => panic!(
                "get_invoke_external_function_deferred expects witnesss type to be InvokeExternalContractFunctionDeferred, but got {:?}",
                &self
            ),
        }
    }
    pub fn get_target_array(self) -> Vec<F> {
        match self {
            DPNStateCmdWitness::TargetArray(w) => w,
            _ => panic!("get_target_array expects witnesss type to be TargetArray, but got {:?}", &self),
        }
    }
    pub fn get_target_array_2d(self) -> Vec<Vec<F>> {
        match self {
            DPNStateCmdWitness::TargetArray2D(w) => w,
            _ => panic!("get_target_array_2d expects witnesss type to be TargetArray2D, but got {:?}", &self),
        }
    }
    pub fn get_clear_entire_tree(self) -> DPNClearEntireTreeWitness<F> {
        match self {
            DPNStateCmdWitness::ClearEntireTree(witness) => witness,
            _ => panic!("get_clear_entire_tree expects witness type to be ClearEntireTree, but got {:?}", &self),
        }
    }
}
impl<F: RichField> PsyReadCommandBatchOutput<F> {
    pub fn new() -> Self {
        Self {
            get_user_leaf: Vec::new(),
            get_contract_leaf: Vec::new(),
            get_contract_code: Vec::new(),
            get_checkpoint_leaf: Vec::new(),
            get_block_state: Vec::new(),
            get_merkle_proof: Vec::new(),
            get_hash: Vec::new(),
        }
    }
    pub fn append(&mut self, other: Self) {
        self.get_user_leaf.extend(other.get_user_leaf);
        self.get_contract_leaf.extend(other.get_contract_leaf);
        self.get_contract_code.extend(other.get_contract_code);
        self.get_checkpoint_leaf.extend(other.get_checkpoint_leaf);
        self.get_block_state.extend(other.get_block_state);
        self.get_merkle_proof.extend(other.get_merkle_proof);
        self.get_hash.extend(other.get_hash);
    }
    pub fn concat(&self, other: &Self) -> Self {
        let mut b = self.clone();
        b.append(other.clone());
        b
    }
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
pub trait PsyReadCommandProcessorSync<F: RichField> {
    async fn resolve_batch(&self, input: &PsyReadCommandBatchInput) -> anyhow::Result<PsyReadCommandBatchOutput<F>>;
    async fn resolve_get_hash(&self, input: &QSRHashCmd) -> anyhow::Result<QHashOut<F>>;
    async fn resolve_get_merkle_proof(&self, input: &QSRMerkleCmd) -> anyhow::Result<MerkleProofCore<QHashOut<F>>>;
    async fn resolve_get_user_leaf(&self, input: &QSRCmdGetUserLeafData) -> anyhow::Result<PsyUserLeaf<F>>;
    async fn resolve_get_contract_leaf(&self, input: &QSRCmdGetContractLeafData) -> anyhow::Result<PsyContractLeaf<F>>;
    async fn resolve_get_contract_code(&self, input: &QSRCmdGetContractCodeDefinition) -> anyhow::Result<ContractCodeDefinition>;
    async fn resolve_get_checkpoint_leaf(&self, input: &QSRCmdGetCheckpointLeafData) -> anyhow::Result<PsyCheckpointLeaf<F>>;
    async fn resolve_get_block_state(&self, input: &QSRCmdGetBlockState) -> anyhow::Result<PsyBlockState>;
    async fn resolve_get_latest_block_state(&self) -> anyhow::Result<PsyBlockState>;

    async fn resolve_contract_state_imt_get_leaf_preimage(
        &self,
        input: &crate::qstore::imm::cmd::QSRIMTCmdGetLeafPreimage,
    ) -> anyhow::Result<crate::qdata::imt_contract_state::IMTContractStateLeaf<F>>;

    async fn resolve_contract_state_imt_get_leaf_index_for_key(
        &self,
        input: &crate::qstore::imm::cmd::QSRIMTCmdGetLeafIndexForKey,
    ) -> anyhow::Result<u64>;

    async fn resolve_contract_state_imt_find_predecessor(
        &self,
        input: &crate::qstore::imm::cmd::QSRIMTCmdFindPredecessor,
    ) -> anyhow::Result<Option<(u64, crate::qdata::imt_contract_state::IMTContractStateLeaf<F>)>>;

    async fn resolve_contract_state_imt_get_next_append_index(
        &self,
        input: &crate::qstore::imm::cmd::QSRIMTCmdGetNextAppendIndex,
    ) -> anyhow::Result<u64>;
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
pub trait PsyReadCommandProcessorSyncMut<F: RichField> {
    async fn resolve_batch_mut(&mut self, input: &PsyReadCommandBatchInput) -> anyhow::Result<PsyReadCommandBatchOutput<F>>;
    async fn resolve_get_hash_mut(&mut self, input: &QSRHashCmd) -> anyhow::Result<QHashOut<F>>;
    async fn resolve_get_merkle_proof_mut(&mut self, input: &QSRMerkleCmd) -> anyhow::Result<MerkleProofCore<QHashOut<F>>>;
    async fn resolve_get_user_leaf_mut(&mut self, input: &QSRCmdGetUserLeafData) -> anyhow::Result<PsyUserLeaf<F>>;
    async fn resolve_get_contract_leaf_mut(&mut self, input: &QSRCmdGetContractLeafData) -> anyhow::Result<PsyContractLeaf<F>>;
    async fn resolve_get_contract_code_mut(&mut self, input: &QSRCmdGetContractCodeDefinition) -> anyhow::Result<ContractCodeDefinition>;
    async fn resolve_get_checkpoint_leaf_mut(&mut self, input: &QSRCmdGetCheckpointLeafData) -> anyhow::Result<PsyCheckpointLeaf<F>>;
    async fn resolve_get_block_state_mut(&mut self, input: &QSRCmdGetBlockState) -> anyhow::Result<PsyBlockState>;
    async fn resolve_get_latest_block_state_mut(&mut self) -> anyhow::Result<PsyBlockState>;

    async fn resolve_contract_state_imt_get_leaf_preimage_mut(
        &mut self,
        input: &crate::qstore::imm::cmd::QSRIMTCmdGetLeafPreimage,
    ) -> anyhow::Result<crate::qdata::imt_contract_state::IMTContractStateLeaf<F>>;

    async fn resolve_contract_state_imt_get_leaf_index_for_key_mut(
        &mut self,
        input: &crate::qstore::imm::cmd::QSRIMTCmdGetLeafIndexForKey,
    ) -> anyhow::Result<u64>;

    async fn resolve_contract_state_imt_find_predecessor_mut(
        &mut self,
        input: &crate::qstore::imm::cmd::QSRIMTCmdFindPredecessor,
    ) -> anyhow::Result<Option<(u64, crate::qdata::imt_contract_state::IMTContractStateLeaf<F>)>>;

    async fn resolve_contract_state_imt_get_next_append_index_mut(
        &mut self,
        input: &crate::qstore::imm::cmd::QSRIMTCmdGetNextAppendIndex,
    ) -> anyhow::Result<u64>;
}
/*
 */

#[cfg(test)]
mod tests {
    use plonky2::field::goldilocks_field::GoldilocksField;

    use super::*;

    type F = GoldilocksField;

    fn delta(index: u64) -> DeltaMerkleProofCore<QHashOut<F>> {
        DeltaMerkleProofCore {
            old_root: QHashOut::from_values(index, 0, 0, 0),
            old_value: QHashOut::ZERO,
            new_root: QHashOut::from_values(index + 1, 0, 0, 0),
            new_value: QHashOut::ZERO,
            index,
            siblings: vec![QHashOut::ZERO],
        }
    }

    fn set_witness(is_insert: bool, count: usize) -> DPNIMTSetWitness<F> {
        let leaf = IMTContractStateLeaf::default();
        DPNIMTSetWitness {
            delta_merkle_proofs: (0..count as u64).map(delta).collect(),
            is_insert,
            old_leaf: leaf,
            new_leaf: leaf,
            predecessor_old_leaf: leaf,
            predecessor_new_leaf: leaf,
            sentinel_preimage: leaf,
            sentinel_merkle_proof: MerkleProofCore::default(),
            sentinel_old_leaf: leaf,
            sentinel_new_leaf: leaf,
        }
    }

    #[test]
    fn delta_lengths_are_checked_before_indexing() {
        assert_eq!(set_witness(false, 0).delta_proofs().unwrap().len(), 0);
        assert_eq!(set_witness(true, 0).delta_proofs().unwrap().len(), 0);
        assert_eq!(set_witness(false, 1).delta_proofs().unwrap()[0].index, 0);
        let inserted = set_witness(true, 3).delta_proofs().unwrap();
        assert_eq!(inserted.iter().map(|proof| proof.index).collect::<Vec<_>>(), vec![0, 1, 2]);

        assert!(set_witness(true, 1).delta_proofs().is_err());
        assert!(set_witness(true, 2).delta_proofs().is_err());
        assert!(set_witness(false, 3).delta_proofs().is_err());
    }

    #[test]
    fn read_contains_and_set_witnesses_round_trip_with_sentinels() {
        let leaf = IMTContractStateLeaf::<F>::default();
        let sentinel_proof = MerkleProofCore {
            root: QHashOut::from_values(8, 0, 0, 0),
            value: QHashOut::ZERO,
            index: 4,
            siblings: vec![QHashOut::from_values(9, 0, 0, 0)],
        };
        let read = DPNStateCmdWitness::IMTRead(DPNIMTReadWitness {
            leaf_preimage: leaf,
            merkle_proof: MerkleProofCore::default(),
            sentinel_preimage: leaf,
            sentinel_merkle_proof: sentinel_proof.clone(),
        });
        let contains = DPNStateCmdWitness::IMTContains(DPNIMTContainsWitness {
            exists: false,
            leaf_preimage: leaf,
            merkle_proof: MerkleProofCore::default(),
            sentinel_preimage: leaf,
            sentinel_merkle_proof: sentinel_proof.clone(),
        });
        let external = DPNStateCmdWitness::IMTSelfUserExternalRead(DPNIMTSelfUserExternalReadWitness {
            contract_tree_proof: MerkleProofCore::default(),
            state_slot_proof: MerkleProofCore::default(),
            leaf_preimage: leaf,
            sentinel_preimage: leaf,
            sentinel_merkle_proof: sentinel_proof.clone(),
        });
        let other_user = DPNReadOtherUserLeafMerkleProof {
            user_tree_proof: MerkleProofCore::default(),
            user_leaf: PsyUserLeaf::default(),
        };
        let other_read = DPNStateCmdWitness::IMTOtherUserRead(DPNIMTOtherUserReadWitness {
            user_leaf_witness: other_user.clone(),
            contract_state_proof: MerkleProofCore::default(),
            state_slot_proof: MerkleProofCore::default(),
            leaf_preimage: leaf,
            sentinel_preimage: leaf,
            sentinel_merkle_proof: sentinel_proof.clone(),
        });
        let other_contains = DPNStateCmdWitness::IMTContainsOtherUser(DPNIMTContainsOtherUserWitness {
            exists: true,
            user_leaf_witness: other_user,
            contract_state_proof: MerkleProofCore::default(),
            state_slot_proof: MerkleProofCore::default(),
            leaf_preimage: leaf,
            sentinel_preimage: leaf,
            sentinel_merkle_proof: sentinel_proof,
        });
        let set = DPNStateCmdWitness::IMTSet(set_witness(true, 3));

        for witness in [read, contains, external, other_read, other_contains, set] {
            let bytes = bincode::serialize(&witness).unwrap();
            let restored: DPNStateCmdWitness<F> = bincode::deserialize(&bytes).unwrap();
            assert_eq!(restored, witness);
            assert!(bincode::deserialize::<DPNStateCmdWitness<F>>(&bytes[..bytes.len() / 2]).is_err());
        }
    }
}
