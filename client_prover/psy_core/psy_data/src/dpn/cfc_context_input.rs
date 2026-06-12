use kvq::traits::KVQSerializable;
use plonky2::{field::goldilocks_field::GoldilocksField, hash::hash_types::RichField};
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::hash::traits::{hasher::FieldQHasher, qhashable::QFieldHashable};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::proving_session::DPNProvingSessionCompactMethodCall;
use crate::qdata::{
    checkpoint::{PsyCheckpointGlobalStateRoots, PsyCheckpointLeaf},
    user::PsyUserLeaf,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Copy, Default, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct DapenCFCProvingSessionStartContext<F: RichField> {
    pub checkpoint_id: F,
    pub checkpoint_tree_root: QHashOut<F>,
    pub checkpoint_leaf: PsyCheckpointLeaf<F>,
    pub state_roots: PsyCheckpointGlobalStateRoots<F>,
    pub start_session_user_leaf: PsyUserLeaf<F>,
}

impl<F: RichField> QFieldHashable<F> for DapenCFCProvingSessionStartContext<F> {
    fn qfhash<H: FieldQHasher<F>>(&self) -> QHashOut<F> {
        let checkpoint_leaf_hash = self.checkpoint_leaf.qfhash::<H>();
        let checkpoint_combo = H::q_two_to_one(self.checkpoint_tree_root, checkpoint_leaf_hash);
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

impl<F: RichField> KVQSerializable for DapenCFCProvingSessionStartContext<F> {
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
pub struct DapenCFCUserTransactionCallStartContext<F: RichField> {
    pub start_user_contract_tree_root: QHashOut<F>,
    pub start_contract_state_tree_root: QHashOut<F>,

    pub call_data: DPNProvingSessionCompactMethodCall<F>,

    pub start_deferred_tx_debt_tree_root: QHashOut<F>,

    // user info
    pub start_user_balance: F,
    pub start_user_event_index: F,
}

impl<F: RichField> QFieldHashable<F> for DapenCFCUserTransactionCallStartContext<F> {
    fn qfhash<H: FieldQHasher<F>>(&self) -> QHashOut<F> {
        let uct_cst_combo = H::q_two_to_one(self.start_user_contract_tree_root, self.start_contract_state_tree_root);

        let debt_combo = self.start_deferred_tx_debt_tree_root;
        let call_data_hash = self.call_data.qfhash::<H>();

        let call_data_debt_combo = H::q_two_to_one(call_data_hash, debt_combo);

        let state_call_combo = H::q_two_to_one(uct_cst_combo, call_data_debt_combo);

        H::q_hash_many(&[
            state_call_combo.0.elements[0],
            state_call_combo.0.elements[1],
            state_call_combo.0.elements[2],
            state_call_combo.0.elements[3],
            self.start_user_balance,
            self.start_user_event_index,
        ])
    }
}

impl<F: RichField> KVQSerializable for DapenCFCUserTransactionCallStartContext<F> {
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
pub struct DapenCFCUserTransactionEndContext<F: RichField> {
    pub end_contract_state_tree_root: QHashOut<F>,
    pub end_deferred_tx_debt_tree_root: QHashOut<F>,

    pub outputs_hash: QHashOut<F>,
    pub outputs_length: F,
    pub total_events_emitted: F,
    pub total_balance_spent: F,
}

impl<F: RichField> QFieldHashable<F> for DapenCFCUserTransactionEndContext<F> {
    fn qfhash<H: FieldQHasher<F>>(&self) -> QHashOut<F> {
        let debt_combo = self.end_deferred_tx_debt_tree_root;

        let state_debt_combo = H::q_two_to_one(self.end_contract_state_tree_root, debt_combo);

        let output_info_hash = H::q_hash_many(&[
            self.outputs_hash.0.elements[0],
            self.outputs_hash.0.elements[1],
            self.outputs_hash.0.elements[2],
            self.outputs_hash.0.elements[3],
            self.outputs_length,
            self.total_events_emitted,
            self.total_balance_spent,
        ]);

        H::q_two_to_one(state_debt_combo, output_info_hash)
    }
}

impl<F: RichField> KVQSerializable for DapenCFCUserTransactionEndContext<F> {
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
pub struct DapenCFCUserTransactionInputContext<F: RichField> {
    pub proving_session_start_ctx: DapenCFCProvingSessionStartContext<F>,
    pub transaction_call_start_ctx: DapenCFCUserTransactionCallStartContext<F>,
    pub transaction_end_ctx: DapenCFCUserTransactionEndContext<F>,
}

impl<F: RichField> QFieldHashable<F> for DapenCFCUserTransactionInputContext<F> {
    fn qfhash<H: FieldQHasher<F>>(&self) -> QHashOut<F> {
        let proving_session_start_ctx_hash = self.proving_session_start_ctx.qfhash::<H>();

        let transaction_call_start_ctx_hash = self.transaction_call_start_ctx.qfhash::<H>();
        let transaction_end_ctx_hash = self.transaction_end_ctx.qfhash::<H>();
        let tx_start_end_combo = H::q_two_to_one(transaction_call_start_ctx_hash, transaction_end_ctx_hash);

        let session_start_tx_combo = H::q_two_to_one(proving_session_start_ctx_hash, tx_start_end_combo);

        session_start_tx_combo
    }
}

impl<F: RichField> KVQSerializable for DapenCFCUserTransactionInputContext<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}
