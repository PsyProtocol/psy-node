use kvq::traits::KVQSerializable;
use plonky2::{field::goldilocks_field::GoldilocksField, hash::hash_types::RichField};
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::hash::traits::{hasher::FieldQHasher, qhashable::QFieldHashable};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::qdata::user::PsyUserLeaf;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Copy, Default)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct UserProvingSessionHeaderCompact<F: RichField> {
    pub ups_step_circuit_whitelist_root: QHashOut<F>,
    pub session_start_context_hash: QHashOut<F>,
    pub current_state: UserProvingSessionCurrentState<F>,
}

impl<F: RichField> QFieldHashable<F> for UserProvingSessionHeaderCompact<F> {
    fn qfhash<H: FieldQHasher<F>>(&self) -> QHashOut<F> {
        let current_state_hash = self.current_state.qfhash::<H>();

        let start_current_combo = H::q_two_to_one(self.session_start_context_hash, current_state_hash);

        H::q_two_to_one(self.ups_step_circuit_whitelist_root, start_current_combo)
    }
}

impl<F: RichField> KVQSerializable for UserProvingSessionHeaderCompact<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Copy, Default, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct UserProvingSessionHeader<F: RichField> {
    pub ups_step_circuit_whitelist_root: QHashOut<F>,
    pub session_start_context: UserProvingSessionStartContext<F>,
    pub current_state: UserProvingSessionCurrentState<F>,
}

impl<F: RichField> UserProvingSessionHeader<F> {
    pub fn to_compact<H: FieldQHasher<F>>(&self) -> UserProvingSessionHeaderCompact<F> {
        let session_start_context_hash = self.session_start_context.qfhash::<H>();

        UserProvingSessionHeaderCompact {
            ups_step_circuit_whitelist_root: self.ups_step_circuit_whitelist_root,
            session_start_context_hash,
            current_state: self.current_state,
        }
    }
}

impl<F: RichField> QFieldHashable<F> for UserProvingSessionHeader<F> {
    fn qfhash<H: FieldQHasher<F>>(&self) -> QHashOut<F> {
        let session_start_context_hash = self.session_start_context.qfhash::<H>();
        let current_state_hash = self.current_state.qfhash::<H>();

        let start_current_combo = H::q_two_to_one(session_start_context_hash, current_state_hash);

        H::q_two_to_one(self.ups_step_circuit_whitelist_root, start_current_combo)
    }
}

impl<F: RichField> KVQSerializable for UserProvingSessionHeader<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Copy, Default, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct UserProvingSessionStartContext<F: RichField> {
    pub checkpoint_id: F,
    pub checkpoint_tree_root: QHashOut<F>,
    pub checkpoint_leaf_hash: QHashOut<F>,
    pub start_session_user_leaf: PsyUserLeaf<F>,
}

impl<F: RichField> QFieldHashable<F> for UserProvingSessionStartContext<F> {
    fn qfhash<H: FieldQHasher<F>>(&self) -> QHashOut<F> {
        let checkpoint_combo = H::q_two_to_one(self.checkpoint_tree_root, self.checkpoint_leaf_hash);
        let user_leaf_hash = self.start_session_user_leaf.qfhash::<H>();

        let checkpoint_user_combo = H::q_two_to_one(checkpoint_combo, user_leaf_hash);
        H::q_hash_many(&[
            self.checkpoint_id,
            checkpoint_user_combo.0.elements[0],
            checkpoint_user_combo.0.elements[1],
            checkpoint_user_combo.0.elements[2],
            checkpoint_user_combo.0.elements[3],
        ])
    }
}

impl<F: RichField> KVQSerializable for UserProvingSessionStartContext<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Copy, Default, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct UserProvingSessionCurrentState<F: RichField> {
    pub user_leaf: PsyUserLeaf<F>,

    pub deferred_tx_debt_tree_root: QHashOut<F>,
    pub inline_tx_debt_tree_root: QHashOut<F>,

    pub tx_hash_stack: QHashOut<F>,
    pub tx_count: F,
}

impl<F: RichField> QFieldHashable<F> for UserProvingSessionCurrentState<F> {
    fn qfhash<H: FieldQHasher<F>>(&self) -> QHashOut<F> {
        let user_leaf_hash = self.user_leaf.qfhash::<H>();

        let debt_combo = H::q_two_to_one(self.deferred_tx_debt_tree_root, self.inline_tx_debt_tree_root);
        let tx_combo = H::q_hash_many(&[
            self.tx_hash_stack.0.elements[0],
            self.tx_hash_stack.0.elements[1],
            self.tx_hash_stack.0.elements[2],
            self.tx_hash_stack.0.elements[3],
            self.tx_count,
        ]);

        let debt_tx_combo = H::q_two_to_one(debt_combo, tx_combo);
        let result = H::q_two_to_one(user_leaf_hash, debt_tx_combo);

        result
    }
}

impl<F: RichField> KVQSerializable for UserProvingSessionCurrentState<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}
