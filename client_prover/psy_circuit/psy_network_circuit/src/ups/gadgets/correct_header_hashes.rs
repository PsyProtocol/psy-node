use plonky2::hash::hash_types::HashOutTarget;

use crate::gadgets::qdata::ups_context_input::UserProvingSessionHeaderGadget;

#[derive(Debug, Clone, Copy)]
pub struct CorrectUPSHeaderHashesGadget {
    pub previous_step_deferred_tx_debt_tree_root: HashOutTarget,
    pub previous_step_inline_tx_debt_tree_root: HashOutTarget,
}

impl CorrectUPSHeaderHashesGadget {
    pub fn from_previous_step(previous_step: &UserProvingSessionHeaderGadget) -> Self {
        let previous_step_deferred_tx_debt_tree_root = previous_step.current_state.deferred_tx_debt_tree_root;
        let previous_step_inline_tx_debt_tree_root = previous_step.current_state.inline_tx_debt_tree_root;
        CorrectUPSHeaderHashesGadget {
            previous_step_deferred_tx_debt_tree_root,
            previous_step_inline_tx_debt_tree_root,
        }
    }
}
