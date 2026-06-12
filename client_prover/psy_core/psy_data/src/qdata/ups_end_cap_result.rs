use kvq::traits::KVQSerializable;
use plonky2::{field::goldilocks_field::GoldilocksField, hash::hash_types::RichField};
use psy_client_common::{data::qhashout::QHashOut, traits::to_qfelts::QFeltSized};
use psy_config::network_constants::GLOBAL_USER_TREE_HEIGHT;
use psy_crypto::hash::traits::{hasher::FieldQHasher, qhashable::QFieldHashable};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Copy, Default, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct UPSEndCapResultCompact<F: RichField> {
    pub start_user_leaf_hash: QHashOut<F>,
    pub end_user_leaf_hash: QHashOut<F>,
    pub checkpoint_tree_root_hash: QHashOut<F>,
    pub user_id: F,
}

impl<F: RichField> KVQSerializable for UPSEndCapResultCompact<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

impl<F: RichField> QFeltSized for UPSEndCapResultCompact<F> {
    fn q_felt_size() -> usize {
        13
    }
}

impl<F: RichField> QFieldHashable<F> for UPSEndCapResultCompact<F> {
    fn qfhash<H: FieldQHasher<F>>(&self) -> QHashOut<F> {
        let user_leaf_change_combo_with_user_id = H::q_hash_many(&[
            self.user_id,
            self.start_user_leaf_hash.0.elements[0],
            self.start_user_leaf_hash.0.elements[1],
            self.start_user_leaf_hash.0.elements[2],
            self.start_user_leaf_hash.0.elements[3],
            self.end_user_leaf_hash.0.elements[0],
            self.end_user_leaf_hash.0.elements[1],
            self.end_user_leaf_hash.0.elements[2],
            self.end_user_leaf_hash.0.elements[3],
            F::from_canonical_u8(GLOBAL_USER_TREE_HEIGHT),
        ]);

        let end_cap_result_hash = H::q_two_to_one(self.checkpoint_tree_root_hash, user_leaf_change_combo_with_user_id);
        end_cap_result_hash
    }
}
