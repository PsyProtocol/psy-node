use kvq::traits::KVQSerializable;
use plonky2::hash::hash_types::RichField;
use psy_client_common::data::qhashout::QHashOut;
use serde::{Deserialize, Serialize};

use crate::hash::traits::{hasher::FieldQHasher, qhashable::QFieldHashable};

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Hash, Default)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct SubTreeNodeStateTransition<F: RichField> {
    pub old_node_value: QHashOut<F>,
    pub new_node_value: QHashOut<F>,
    pub node_index: F,
    pub node_level: F,
}

impl<F: RichField> QFieldHashable<F> for SubTreeNodeStateTransition<F> {
    fn qfhash<H: FieldQHasher<F>>(&self) -> QHashOut<F> {
        let node_change_combo = H::q_hash_many(&[
            self.node_index,
            self.old_node_value.0.elements[0],
            self.old_node_value.0.elements[1],
            self.old_node_value.0.elements[2],
            self.old_node_value.0.elements[3],
            self.new_node_value.0.elements[0],
            self.new_node_value.0.elements[1],
            self.new_node_value.0.elements[2],
            self.new_node_value.0.elements[3],
            self.node_level,
        ]);
        node_change_combo
    }
}

impl<F: RichField> KVQSerializable for SubTreeNodeStateTransition<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}
