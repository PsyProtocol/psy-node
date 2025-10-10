use parth_core::{crypto::hash::traits::FieldQHasher, data::serializable::QPDSerializable, felt::{QFelt, QFelt64, QFeltSized}, protocol::core_types::{QFHashBase, QHashBase}};


#[pderive::serialize_copy_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash), rename = "UPSEndCapResultCompact")]
pub struct PUPSEndCapResultCompact<F: QFelt, Hash: QHashBase> {
    pub start_user_leaf_hash: Hash,
    pub end_user_leaf_hash: Hash,
    pub checkpoint_tree_root_hash: Hash,
    pub user_id: F,
}


impl<F: QFelt, Hash: QHashBase> QPDSerializable for PUPSEndCapResultCompact<F, Hash> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

impl<F: QFelt, Hash: QHashBase> QFeltSized for PUPSEndCapResultCompact<F, Hash> {
    fn q_felt_size() -> usize {
        13
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> PUPSEndCapResultCompact<F, Hash> {
    pub fn qfhash_with_guta_height<H: FieldQHasher<F, Hash>>(&self, global_user_tree_height: u8) -> Hash {
        let start_user_leaf_hash = self.start_user_leaf_hash.to_4_felts();
        let end_user_leaf_hash = self.end_user_leaf_hash.to_4_felts();

        let user_leaf_change_combo_with_user_id = H::q_hash_many(&[
            self.user_id,

            start_user_leaf_hash[0],
            start_user_leaf_hash[1],
            start_user_leaf_hash[2],
            start_user_leaf_hash[3],

            end_user_leaf_hash[0],
            end_user_leaf_hash[1],
            end_user_leaf_hash[2],
            end_user_leaf_hash[3],

            F::from_u8_value(global_user_tree_height),
        ]);

        let end_cap_result_hash = H::q_two_to_one(
            self.checkpoint_tree_root_hash,
            user_leaf_change_combo_with_user_id,
        );
        end_cap_result_hash
    }
}


