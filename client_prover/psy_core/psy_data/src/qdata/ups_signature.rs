use kvq::traits::KVQSerializable;
use plonky2::hash::hash_types::RichField;
use psy_client_common::{
    data::qhashout::QHashOut,
    traits::to_qfelts::{QFeltSized, ToQFelts},
};
use psy_config::network_constants::PSY_SIG_ACTION_SIGN_UPS_END_CAP;
use psy_crypto::{
    hash::traits::{hasher::FieldQHasher, qhashable::QFieldHashable},
    signature::zk::wallet::PsySigAction,
};
use serde::{Deserialize, Serialize};

use crate::qdata::user_contract_state::SignContext;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Copy, Default)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct PsyUserProvingSessionSignatureDataCompact<F: RichField> {
    pub start_user_leaf_hash: QHashOut<F>,
    pub end_user_leaf_hash: QHashOut<F>,
    pub checkpoint_leaf_hash: QHashOut<F>,
    pub tx_stack_hash: QHashOut<F>,
    pub tx_count: F,
}

impl<F: RichField> PsyUserProvingSessionSignatureDataCompact<F> {
    pub fn get_sig_action_for_user<H: FieldQHasher<F>>(
        &self,
        network_magic: u64,
        user_id: F,
        nonce: F,
        sign_context: SignContext<F>,
    ) -> PsySigAction<F> {
        let network_magic_f = F::from_noncanonical_u64(network_magic);
        let sig_action = F::from_noncanonical_u64(PSY_SIG_ACTION_SIGN_UPS_END_CAP);
        let ups_end_data_hash = self.qfhash::<H>();

        // ups_end_data_hash || checkpoint_tree_root || sign_inputs
        let mut action_arguments = ups_end_data_hash.0.elements.to_vec();
        action_arguments.extend_from_slice(&sign_context.to_qfelts());

        PsySigAction {
            network_magic: network_magic_f,
            user: user_id,
            sig_action,
            nonce,
            action_arguments,
        }
    }
}

impl<F: RichField> KVQSerializable for PsyUserProvingSessionSignatureDataCompact<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

impl<F: RichField> QFeltSized for PsyUserProvingSessionSignatureDataCompact<F> {
    fn q_felt_size() -> usize {
        17
    }
}

impl<F: RichField> QFieldHashable<F> for PsyUserProvingSessionSignatureDataCompact<F> {
    fn qfhash<H: FieldQHasher<F>>(&self) -> QHashOut<F> {
        let user_leaf_change_combo = H::q_two_to_one(self.start_user_leaf_hash, self.end_user_leaf_hash);
        let tx_sized_hash = H::q_hash_many(&[
            self.tx_count,
            self.tx_stack_hash.0.elements[0],
            self.tx_stack_hash.0.elements[1],
            self.tx_stack_hash.0.elements[2],
            self.tx_stack_hash.0.elements[3],
        ]);

        let state_context_combo = H::q_two_to_one(self.checkpoint_leaf_hash, user_leaf_change_combo);

        H::q_two_to_one(state_context_combo, tx_sized_hash)
    }
}
