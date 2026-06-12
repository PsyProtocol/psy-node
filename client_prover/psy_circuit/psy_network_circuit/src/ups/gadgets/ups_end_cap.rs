use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::target::Target,
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_common_circuit::builder::{comparison::CircuitBuilderComparison, core::CircuitBuilderHelpersCore, hash::core::CircuitBuilderHashCore};
use psy_config::{
    network_constants::{CHECKPOINT_TREE_HEIGHT, DEFAULT_CALLER_CONTRACT_ID_U64, GUTA_FEE, TOKEN_CONTRACT_ID, TOKEN_SIMPLE_BURN_METHOD_ID},
    DA_FEE,
};

use super::{ups_end_cap_result::UPSEndCapResultCompactGadget, ups_signature_data::PsyUserProvingSessionSignatureDataCompactGadget};
use crate::{
    gadgets::qdata::{
        contract_function_call::DPNProvingSessionSimpleMethodCallGadget, ups_context_input::UserProvingSessionHeaderGadget,
        user_contract_state::SignContextGadget,
    },
    guta::gadgets::guta_stats::GUTAStatsGadget,
};

#[derive(Clone, Debug)]
pub struct UPSEndCapCoreGadget {
    // start require witness

    // start computed
    pub sig_data_compact_gadget: PsyUserProvingSessionSignatureDataCompactGadget,
    pub end_cap_result_gadget: UPSEndCapResultCompactGadget,
    pub guta_stats: GUTAStatsGadget,
}
const MAX_NONCE_BITS: u8 = 32;

impl UPSEndCapCoreGadget {
    pub fn enforce_signature_constraints<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        last_header_gadget: &UserProvingSessionHeaderGadget,
        sig_proof_public_inputs_hash: HashOutTarget,
        sig_proof_fingerprint: HashOutTarget,
        sig_proof_param_hash: HashOutTarget,
        nonce: Target,
        slots_modified: Target,
        network_magic: u64,
        empty_deferred_tx_debt_tree_root: HashOutTarget,
        empty_inline_tx_debt_tree_root: HashOutTarget,
        second_to_last_tx_hash_stack: HashOutTarget,
    ) -> Self {
        tracing::debug!(
            "🏁 EndCap Constraint 1 - nonce equality: current={:?}, start={:?}",
            last_header_gadget.current_state.user_leaf.nonce,
            last_header_gadget.session_start_context.start_session_user_leaf.nonce
        );
        builder.connect(
            last_header_gadget.current_state.user_leaf.nonce,
            last_header_gadget.session_start_context.start_session_user_leaf.nonce,
        );

        tracing::debug!(
            "🏁 EndCap Constraint 2 - nonce greater than: new_nonce={:?}, current_nonce={:?}",
            nonce,
            last_header_gadget.current_state.user_leaf.nonce
        );
        builder.ensure_is_greater_than(MAX_NONCE_BITS as usize, nonce, last_header_gadget.current_state.user_leaf.nonce);

        let mut real_end_user_leaf = last_header_gadget.current_state.user_leaf.clone();
        real_end_user_leaf.nonce = nonce;

        let end_user_leaf_hash = real_end_user_leaf.to_hash::<H, F, D>(builder);

        let expected_public_key = builder.hash_two_to_one::<H>(sig_proof_fingerprint, sig_proof_param_hash);
        tracing::debug!(
            "🏁 EndCap Public Key - fingerprint={:?}, param_hash={:?}, expected={:?}",
            sig_proof_fingerprint,
            sig_proof_param_hash,
            expected_public_key
        );

        tracing::debug!(
            "🏁 EndCap Constraint 3 - public key equality: start={:?}, end={:?}",
            last_header_gadget.session_start_context.start_session_user_leaf.public_key,
            real_end_user_leaf.public_key
        );
        builder.connect_hashes(
            last_header_gadget.session_start_context.start_session_user_leaf.public_key,
            real_end_user_leaf.public_key,
        );
        tracing::debug!(
            "🏁 EndCap Constraint 4 - public key vs expected: start={:?}, expected={:?}",
            last_header_gadget.session_start_context.start_session_user_leaf.public_key,
            expected_public_key
        );
        builder.connect_hashes(
            last_header_gadget.session_start_context.start_session_user_leaf.public_key,
            expected_public_key,
        );

        tracing::debug!(
            "🏁 EndCap Constraint 5 - user_id equality: end={:?}, start={:?}",
            real_end_user_leaf.user_id,
            last_header_gadget.session_start_context.start_session_user_leaf.user_id
        );
        builder.connect(
            real_end_user_leaf.user_id,
            last_header_gadget.session_start_context.start_session_user_leaf.user_id,
        );

        let start_user_leaf_hash = last_header_gadget.session_start_context.start_session_user_leaf_hash;

        let sig_data_compact_gadget = PsyUserProvingSessionSignatureDataCompactGadget {
            start_user_leaf_hash,
            end_user_leaf_hash,
            checkpoint_leaf_hash: last_header_gadget.session_start_context.checkpoint_leaf_hash,
            tx_stack_hash: last_header_gadget.current_state.tx_hash_stack,
            tx_count: last_header_gadget.current_state.tx_count,
        };

        let sign_context = SignContextGadget {
            checkpoint_tree_root: last_header_gadget.session_start_context.checkpoint_tree_root,
            user_leaf: last_header_gadget.current_state.user_leaf,
        };

        let ups_end_cap_sighash = sig_data_compact_gadget
            .get_sig_action_with_user_info::<H, F, D>(
                builder,
                network_magic,
                last_header_gadget.session_start_context.start_session_user_leaf.user_id,
                nonce,
                &sign_context,
            )
            .sig_action_hash;

        let expected_public_inputs_hash = builder.hash_two_to_one::<H>(ups_end_cap_sighash, sig_proof_param_hash);

        tracing::debug!(
            "🏁 EndCap Constraint 6 - public inputs hash: expected={:?}, actual={:?}",
            expected_public_inputs_hash,
            sig_proof_public_inputs_hash
        );
        tracing::debug!(
            "🏁 EndCap Signature Data - sighash={:?}, param_hash={:?}",
            ups_end_cap_sighash,
            sig_proof_param_hash
        );
        builder.connect_hashes(expected_public_inputs_hash, sig_proof_public_inputs_hash);

        let end_cap_result_gadget = UPSEndCapResultCompactGadget {
            start_user_leaf_hash,
            end_user_leaf_hash,
            checkpoint_tree_root_hash: last_header_gadget.session_start_context.checkpoint_tree_root,
            user_id: last_header_gadget.session_start_context.start_session_user_leaf.user_id,
        };

        tracing::debug!(
            "🏁 EndCap Constraint 7 - checkpoint_id equality: session={:?}, user_leaf={:?}",
            last_header_gadget.session_start_context.checkpoint_id,
            real_end_user_leaf.last_checkpoint_id
        );
        builder.connect(
            last_header_gadget.session_start_context.checkpoint_id,
            real_end_user_leaf.last_checkpoint_id,
        );

        tracing::debug!(
            "🏁 EndCap Constraint 8 - checkpoint greater than: end={:?}, start={:?}",
            real_end_user_leaf.last_checkpoint_id,
            last_header_gadget.session_start_context.start_session_user_leaf.last_checkpoint_id
        );

        let is_greater_than = builder.is_greater_than(
            CHECKPOINT_TREE_HEIGHT as usize,
            real_end_user_leaf.last_checkpoint_id,
            last_header_gadget.session_start_context.start_session_user_leaf.last_checkpoint_id,
        );
        let is_equal = builder.is_equal(
            real_end_user_leaf.last_checkpoint_id,
            last_header_gadget.session_start_context.start_session_user_leaf.last_checkpoint_id,
        );
        let is_zero = builder.is_zero(real_end_user_leaf.last_checkpoint_id);

        let zero_and_equal = builder.and(is_zero, is_equal);
        let valid_checkpoint = builder.or(zero_and_equal, is_greater_than);

        tracing::debug!(
            "🏁 EndCap Checkpoint Logic - is_zero={:?}, is_equal={:?}, is_greater={:?}, valid={:?}",
            is_zero,
            is_equal,
            is_greater_than,
            valid_checkpoint
        );

        builder.assert_one(valid_checkpoint.target);

        // ensure the deferred tx debt tree is empty
        tracing::debug!(
            "🏁 EndCap Constraint 9 - deferred debt tree empty: current={:?}, expected_empty={:?}",
            last_header_gadget.current_state.deferred_tx_debt_tree_root,
            empty_deferred_tx_debt_tree_root
        );
        builder.connect_hashes(
            last_header_gadget.current_state.deferred_tx_debt_tree_root,
            empty_deferred_tx_debt_tree_root,
        );

        // ensure the inline tx debt tree is empty
        tracing::debug!(
            "🏁 EndCap Constraint 10 - inline debt tree empty: current={:?}, expected_empty={:?}",
            last_header_gadget.current_state.inline_tx_debt_tree_root,
            empty_inline_tx_debt_tree_root
        );
        builder.connect_hashes(last_header_gadget.current_state.inline_tx_debt_tree_root, empty_inline_tx_debt_tree_root);

        let one_target = builder.one();

        let tx_count = last_header_gadget.current_state.tx_count;
        tracing::debug!("🏁 EndCap Constraint 11 - tx_count greater than one: tx_count={:?}", tx_count);
        builder.ensure_is_greater_than(MAX_NONCE_BITS as usize, tx_count, one_target);

        let burn_contract_id = builder.constant_u64(TOKEN_CONTRACT_ID as u64);
        let burn_method_id = builder.constant_u64(TOKEN_SIMPLE_BURN_METHOD_ID as u64);
        let guta_fee = builder.constant_u64(GUTA_FEE);
        let da_fee_per_slot = builder.constant_u64(DA_FEE);
        let da_fee = builder.mul(da_fee_per_slot, slots_modified);
        let burn_amount = builder.add(guta_fee, da_fee);

        let expected_burn_transaction = DPNProvingSessionSimpleMethodCallGadget {
            caller_contract_id: builder.constant_u64(DEFAULT_CALLER_CONTRACT_ID_U64),
            contract_id: burn_contract_id,
            method_id: burn_method_id,
            inputs: vec![burn_amount],
        };

        let current_tx_stack = last_header_gadget.current_state.tx_hash_stack;
        let expected_burn_tx_hash = expected_burn_transaction.to_hash::<H, F, D>(builder);

        let reconstructed_current_stack = builder.hash_two_to_one::<H>(second_to_last_tx_hash_stack, expected_burn_tx_hash);
        tracing::debug!(
            "🏁 EndCap Constraint 12 - tx_stack reconstruction: reconstructed={:?}, current={:?}",
            reconstructed_current_stack,
            current_tx_stack
        );
        tracing::debug!(
            "🏁 EndCap Gas Fee Transaction - contract_id={:?}, method_id={:?}, amount={:?}, hash={:?}",
            burn_contract_id,
            burn_method_id,
            burn_amount,
            expected_burn_tx_hash
        );
        builder.connect_hashes(reconstructed_current_stack, current_tx_stack);

        let guta_stats = GUTAStatsGadget {
            guta_fees_collected: guta_fee,
            da_fees_collected: da_fee,
            user_ops_processed: one_target,
            total_transactions: tx_count,
            slots_modified: slots_modified,
        };

        Self {
            sig_data_compact_gadget,
            end_cap_result_gadget,
            guta_stats,
        }
    }
}
