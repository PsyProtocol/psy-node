use parth_core::{QCoreProcCheckpointUniqueId, crypto::hash::traits::{FieldQHasher, QFieldHashable}, felt::{QFelt, QFelt64}, generic_traits::psy_debug_printable::PsyDebugPrintable, node::realm_identifier::QRealmIdentifier, protocol::core_types::{QFHashBase, QHashBase}};

use crate::{protocol::checkpoint_transition_hash::CheckpointStateHashTransition, v1::qdata::{checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, PQEDCheckpointLeafStats, QEDL2BlockState}, populated_checkpoint::PsyCheckpointLeafPopulated}};

#[pderive::serialize_copy_f_hash]
pub struct CoordinatorProcessorLastCommittedState<F, Hash> {
    pub l2_state: QEDL2BlockState,
    pub checkpoint_leaf_stats: PQEDCheckpointLeafStats<F, Hash>,
    pub checkpoint_leaf: PQEDCheckpointLeaf<F, Hash>,
    pub checkpoint_state_roots: PQEDCheckpointGlobalStateRoots<Hash>,
    pub checkpoint_state_transition: CheckpointStateHashTransition<Hash>,
    pub checkpoint_root: Hash,
    pub checkpoint_leaf_hash: Hash,
    pub last_chain_hash: Hash,
}


impl<F: QFelt, Hash: QHashBase> PsyDebugPrintable for CoordinatorProcessorLastCommittedState<F, Hash> {
    fn psy_debug_print(&self) -> String {
        format!("{:#?}", self)
        
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> CoordinatorProcessorLastCommittedState<F, Hash> {
    pub fn update_for_block<Hasher: FieldQHasher<F, Hash>>(
        &mut self,
        l2_state: QEDL2BlockState,
        populated_leaf: PsyCheckpointLeafPopulated<F, Hash>,
        checkpoint_state_transition: CheckpointStateHashTransition<Hash>,
    ) -> anyhow::Result<()> {
        let expected_leaf_hash = populated_leaf.qfhash::<Hasher>();
        if expected_leaf_hash != checkpoint_state_transition.new_checkpoint_leaf_hash {
            return Err(anyhow::anyhow!(
                "Populated checkpoint leaf hash does not match expected hash. Expected: {:?}, Actual: {:?}",
                checkpoint_state_transition.new_checkpoint_leaf_hash,
                expected_leaf_hash
            ));
        }
        self.l2_state = l2_state;
        self.checkpoint_leaf_stats = populated_leaf.stats;
        self.checkpoint_leaf = populated_leaf.to_checkpoint_leaf::<Hasher>();
        self.checkpoint_state_roots = populated_leaf.global_state_roots;
        self.checkpoint_state_transition = checkpoint_state_transition;
        self.checkpoint_root = checkpoint_state_transition.new_checkpoint_tree_root;
        self.checkpoint_leaf_hash = expected_leaf_hash;
        Ok(())
    }
    pub fn new_from_minimal<Hasher: FieldQHasher<F, Hash>>(
        l2_state: QEDL2BlockState,
        populated_leaf: PsyCheckpointLeafPopulated<F, Hash>,
        checkpoint_state_transition: CheckpointStateHashTransition<Hash>,
        last_chain_hash: Hash,
    ) -> anyhow::Result<Self> {
        let expected_leaf_hash = populated_leaf.qfhash::<Hasher>();
        if expected_leaf_hash != checkpoint_state_transition.new_checkpoint_leaf_hash {
            return Err(anyhow::anyhow!(
                "Populated checkpoint leaf hash does not match expected hash. Expected: {:?}, Actual: {:?}",
                checkpoint_state_transition.new_checkpoint_leaf_hash,
                expected_leaf_hash
            ));
        }
        Ok(Self {
            l2_state,
            checkpoint_leaf_stats: populated_leaf.stats,
            checkpoint_leaf: populated_leaf.to_checkpoint_leaf::<Hasher>(),
            checkpoint_state_roots: populated_leaf.global_state_roots,
            checkpoint_state_transition,
            checkpoint_root: checkpoint_state_transition.new_checkpoint_tree_root,
            checkpoint_leaf_hash: expected_leaf_hash,
            last_chain_hash,
        })
    }
}

impl<F: Copy, Hash: Copy> CoordinatorProcessorLastCommittedState<F, Hash> {
    pub fn get_last_committed_populated_checkpoint(&self) -> PsyCheckpointLeafPopulated<F, Hash> {
        PsyCheckpointLeafPopulated {
            global_state_roots: self.checkpoint_state_roots,
            stats: self.checkpoint_leaf_stats,
        }
    }
}


#[pderive::serialize_copy]
pub struct CoordinatorProcessorIdState {
    pub realm_identifier: QRealmIdentifier,
    pub realm_id_u64: u64,
    pub realm_sub_id_u64: u64,


    pub checkpoint_id: u64,
    pub next_checkpoint_id: u64,
    
    pub unique_pending_id: u64,
    pub proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId,

    pub gathering_unique_pending_id: u64,
    pub gathering_proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId,
}
