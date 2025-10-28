/*use crate::{crypto::hash::traits::{FieldQHasher, QFieldHashable, ToU64x4}, felt::QFelt64, protocol::core_types::{QFHashBase, QHashBase}};


pub struct SubTreeNodeStateTransition<Hash> {
    pub old_node_value: Hash,
    pub new_node_value: Hash,
    pub node_index: u64,
    pub node_level: u8,
}

impl<F: QFelt64, Hash: QFHashBase<F> + QHashBase> QFieldHashable<F, Hash> for SubTreeNodeStateTransition<F> {
    fn qfhash<Hasher: FieldQHasher<F, Hash>>(&self) -> Hash {
        let old_node_value = self.old_node_value.to_4_felts();
        let new_node_value = self.new_node_value.to_4_felts();
        

        let node_change_combo = Hasher::q_hash_many(&[
            F::from_owned_u64(self.node_index),

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
}*/

