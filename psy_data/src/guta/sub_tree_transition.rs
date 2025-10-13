use parth_core::{crypto::hash::traits::{FieldQHasher, QFieldHashable}, felt::QFelt64, protocol::core_types::QFHashBase};


#[pderive::serialize_copy_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct SubTreeNodeStateTransition<F, Hash> {
    pub old_node_value: Hash,
    pub new_node_value: Hash,
    pub node_index: F,
    pub node_level: F,
}

impl<F: QFelt64, Hash: QFHashBase<F>> QFieldHashable<F, Hash> for SubTreeNodeStateTransition<F, Hash> {
    fn qfhash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        let old_node_value = self.old_node_value.to_4_felts();
        let new_node_value = self.new_node_value.to_4_felts();
        let node_change_combo = H::q_hash_many(&[
            self.node_index,
            old_node_value[0],
            old_node_value[1],
            old_node_value[2],
            old_node_value[3],
            new_node_value[0],
            new_node_value[1],
            new_node_value[2],
            new_node_value[3],
            self.node_level,
        ]);
        node_change_combo
    }
}
