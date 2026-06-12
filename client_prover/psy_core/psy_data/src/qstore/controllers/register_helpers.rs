use plonky2::hash::hash_types::RichField;
use psy_client_common::data::qhashout::QHashOut;
use psy_config::DEFAULT_USER_STATE_TREE_ROOT_U64;

use crate::qdata::user::PsyUserLeaf;
pub fn get_default_user_contract_tree_root<F: RichField>() -> QHashOut<F> {
    QHashOut::from_values(
        DEFAULT_USER_STATE_TREE_ROOT_U64[0],
        DEFAULT_USER_STATE_TREE_ROOT_U64[1],
        DEFAULT_USER_STATE_TREE_ROOT_U64[2],
        DEFAULT_USER_STATE_TREE_ROOT_U64[3],
    )
}
pub fn get_new_empty_user_leaf<F: RichField>(user_id: F, public_key: QHashOut<F>) -> PsyUserLeaf<F> {
    PsyUserLeaf {
        user_id,
        user_state_tree_root: get_default_user_contract_tree_root(),
        public_key,
        balance: F::ZERO,
        nonce: F::ZERO,
        last_checkpoint_id: F::ZERO,
        event_index: F::ZERO,
    }
}
