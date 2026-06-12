use kvq::traits::KVQSerializable;
use plonky2::hash::hash_types::RichField;
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::hash::{
    merkle::treeprover::subtree::SubTreeNodeStateTransition,
    traits::{hasher::FieldQHasher, qhashable::QFieldHashable},
};
use serde::{Deserialize, Serialize};

use super::stats::GUTAStats;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Copy, Default)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct GlobalUserTreeAggregatorHeader<F: RichField> {
    pub guta_circuit_whitelist: QHashOut<F>,
    pub checkpoint_tree_root: QHashOut<F>,
    pub state_transition: SubTreeNodeStateTransition<F>,
    pub stats: GUTAStats<F>,
}

impl<F: RichField> KVQSerializable for GlobalUserTreeAggregatorHeader<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

impl<F: RichField> QFieldHashable<F> for GlobalUserTreeAggregatorHeader<F> {
    fn qfhash<H: FieldQHasher<F>>(&self) -> QHashOut<F> {
        let state_transition_hash = self.state_transition.qfhash::<H>();
        let stats_hash = self.stats.qfhash::<H>();

        let state_transition_and_stats_hash = H::q_two_to_one(state_transition_hash, stats_hash);

        let state_stats_checkpoint_hash = H::q_two_to_one(self.checkpoint_tree_root, state_transition_and_stats_hash);

        H::q_two_to_one(self.guta_circuit_whitelist, state_stats_checkpoint_hash)
    }
}
