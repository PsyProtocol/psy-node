use parth_core::{
    crypto::hash::traits::{FieldQHasher, QFieldHashable},
    felt::QFelt64,
    protocol::core_types::QFHashBase,
};

use crate::guta::{stats::GUTAStats, sub_tree_transition::SubTreeNodeStateTransition};

#[pderive::serialize_copy_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct GlobalUserTreeAggregatorHeader<F, Hash > {
    pub guta_circuit_whitelist: Hash,
    pub checkpoint_tree_root: Hash,
    pub state_transition: SubTreeNodeStateTransition<F, Hash>,
    pub stats: GUTAStats<F>,
}



impl<F: QFelt64, Hash: QFHashBase<F>> QFieldHashable<F, Hash> for GlobalUserTreeAggregatorHeader<F, Hash> {
    fn qfhash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        let state_transition_hash = self.state_transition.qfhash::<H>();
        let stats_hash = self.stats.qfhash::<H>();



        let state_transition_and_stats_hash = H::q_two_to_one(
            state_transition_hash,
            stats_hash,
        );

        let state_stats_checkpoint_hash = H::q_two_to_one(
            self.checkpoint_tree_root,
            state_transition_and_stats_hash,
        );

        H::q_two_to_one(
            self.guta_circuit_whitelist,
            state_stats_checkpoint_hash,
        )
    }
}

