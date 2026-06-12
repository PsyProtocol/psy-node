use kvq::traits::KVQSerializable;
use plonky2::hash::hash_types::RichField;
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::hash::traits::{hasher::FieldQHasher, qhashable::QFieldHashable};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Copy, Default)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct DapenContractFunctionContextHeader<F: RichField> {
    pub user_contract_tree_root: QHashOut<F>,
    pub start_contract_state_root: QHashOut<F>,

    pub contract_id: F,
    pub method_id: F,
    pub balance: F,
    pub event_index: F,
}

impl<F: RichField> KVQSerializable for DapenContractFunctionContextHeader<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

impl<F: RichField> QFieldHashable<F> for DapenContractFunctionContextHeader<F> {
    fn qfhash<H: FieldQHasher<F>>(&self) -> QHashOut<F> {
        let state_combo = H::hash_many(&[
            self.user_contract_tree_root.0.elements[0],
            self.user_contract_tree_root.0.elements[1],
            self.user_contract_tree_root.0.elements[2],
            self.user_contract_tree_root.0.elements[3],
            self.start_contract_state_root.0.elements[0],
            self.start_contract_state_root.0.elements[1],
            self.start_contract_state_root.0.elements[2],
            self.start_contract_state_root.0.elements[3],
        ]);

        let final_hash = H::q_hash_many(&[
            state_combo.elements[0],
            state_combo.elements[1],
            state_combo.elements[2],
            state_combo.elements[3],
            self.contract_id,
            self.method_id,
            self.balance,
            self.event_index,
        ]);

        final_hash
    }
}
