use kvq::traits::KVQSerializable;
use plonky2::hash::hash_types::RichField;
use psy_client_common::data::qhashout::QHashOut;
use serde::{Deserialize, Serialize};

use crate::qdata::user::PsyUserLeaf;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Copy)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct QBCUserContractStateUpdateKVPair<F: RichField> {
    pub state_slot_id: u64,
    pub value: QHashOut<F>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct QBCUserContractStateUpdateKVPairs<F: RichField> {
    pub contract_id: u32,
    pub updates: Vec<QBCUserContractStateUpdateKVPair<F>>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct QBCUpdateUser<F: RichField> {
    pub updated_leaf: PsyUserLeaf<F>,
    pub contract_state_updates: Vec<QBCUserContractStateUpdateKVPairs<F>>,
}

impl<F: RichField> QBCUpdateUser<F> {
    pub fn new(updated_leaf: PsyUserLeaf<F>, contract_state_updates: Vec<QBCUserContractStateUpdateKVPairs<F>>) -> Self {
        Self {
            updated_leaf,
            contract_state_updates,
        }
    }
}

impl<F: RichField> KVQSerializable for QBCUpdateUser<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}
