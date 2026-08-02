use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_client_data::ups::ups_standard_cfc_input::UPSCFCStandardStateDeltaInput;
use psy_common_circuit::{
    builder::{comparison::CircuitBuilderComparison, connect::CircuitBuilderConnectHelpers, select::CircuitBuilderSelectHelpers},
    hash::{
        hash_stack::simple::SimpleHashStackGadget,
        merkle::gadgets::{delta_merkle_proof::DeltaMerkleProofGadget, historical_root_merkle_proof::HistoricalRootMerkleProofGadget},
    },
    traits::WitnessValueFor,
};
use psy_config::network_constants::{
    DEFERRED_TRANSACTION_TREE_HEIGHT, GLOBAL_CONTRACT_TREE_HEIGHT, INLINE_TRANSACTION_TREE_HEIGHT, MAX_CONTRACT_STATE_TREE_HEIGHT,
};
use psy_crypto::hash::traits::hasher::MerkleZeroHasher;

use super::correct_header_hashes::CorrectUPSHeaderHashesGadget;
use crate::gadgets::{
    qdata::{
        cfc_context_input::UPSInspectDapenCFCUserTransactionInputContextGadget,
        ups_context_input::{UserProvingSessionCurrentStateGadget, UserProvingSessionHeaderGadget},
        user::PsyUserLeafGadget,
    },
    stack_items::transaction_log::TransactionLogStackItemGadget,
};

#[derive(Clone, Debug)]
pub struct UPSCFCStandardStateDeltaGadget {
    // start require witness
    pub cfc_transaction_input_context: UPSInspectDapenCFCUserTransactionInputContextGadget,
    pub user_contract_tree_update_proof: DeltaMerkleProofGadget,
    pub deferred_tx_debt_pivot_proof: HistoricalRootMerkleProofGadget,
    pub inline_tx_debt_pivot_proof: HistoricalRootMerkleProofGadget,

    // start computed

    // start computed assumptions
    pub cfc_inner_public_inputs_hash: HashOutTarget,
    pub cfc_contract_id: Target,
    pub cfc_method_id: Target,
    pub cfc_num_inputs: Target,
    pub cfc_num_outputs: Target,
    // key proven results
}
impl UPSCFCStandardStateDeltaGadget {
    pub fn get_default_zero_hashes<H: AlgebraicHasher<F> + MerkleZeroHasher<HashOut<F>>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<HashOutTarget> {
        (0..(MAX_CONTRACT_STATE_TREE_HEIGHT + 1))
            .map(|i| builder.constant_hash(H::get_zero_hash(i as usize)))
            .collect::<Vec<_>>()
    }
    pub fn add_virtual_to<H: AlgebraicHasher<F> + MerkleZeroHasher<HashOut<F>>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        previous_step_header_gadget: &UserProvingSessionHeaderGadget,
        corrections: &CorrectUPSHeaderHashesGadget,
        contract_state_tree_height: Target,
    ) -> (Self, UserProvingSessionHeaderGadget) {
        tracing::debug!(
            "📊 UPS CFC Standard State Delta - start context: {:?}, contract_state_tree_height: {:?}",
            previous_step_header_gadget.session_start_context,
            contract_state_tree_height
        );
        let proving_session_start_ctx_hash = previous_step_header_gadget.session_start_context_hash;

        // -- start require witness

        // get the witness/preimage so we can compute the expected
        // inner_public_inputs_hash for the cfc proof
        let cfc_transaction_input_context =
            UPSInspectDapenCFCUserTransactionInputContextGadget::add_virtual_to::<H, F, D>(builder, proving_session_start_ctx_hash);

        // update the contract state tree root (aka. the leaf in the user contract tree)
        // for the contract being modified by the transaction
        let user_contract_tree_update_proof = DeltaMerkleProofGadget::add_virtual_to::<H, F, D>(builder, GLOBAL_CONTRACT_TREE_HEIGHT as usize);
        let deferred_tx_debt_pivot_proof =
            HistoricalRootMerkleProofGadget::add_virtual_to_zero_gte::<H, F, D>(builder, DEFERRED_TRANSACTION_TREE_HEIGHT as usize);
        let inline_tx_debt_pivot_proof =
            HistoricalRootMerkleProofGadget::add_virtual_to_zero_gte::<H, F, D>(builder, INLINE_TRANSACTION_TREE_HEIGHT as usize);

        // -- end require_witnesss

        // -- start list assumptions from cfc_transaction_input_context
        let cfc_inner_public_inputs_hash = cfc_transaction_input_context.to_hash::<H, F, D>(builder);

        let cfc_method_id = cfc_transaction_input_context.transaction_call_start_ctx.call_data.method_id;
        let cfc_num_inputs = cfc_transaction_input_context.transaction_call_start_ctx.call_data.inputs_length;
        let cfc_num_outputs = cfc_transaction_input_context.transaction_end_ctx.outputs_length;
        tracing::debug!(
            "📊 CFC Transaction Context - method_id: {:?}, num_inputs: {:?}, num_outputs: {:?}, inner_hash: {:?}",
            cfc_method_id,
            cfc_num_inputs,
            cfc_num_outputs,
            cfc_inner_public_inputs_hash
        );
        // -- end list assumptions from cfc_transaction_input_context

        // -- start get useful info from the previous step
        // the previous values for EVERYTHING we want to modify in the new session state
        // must be here
        let previous_step_user_state_tree_root = previous_step_header_gadget.current_state.user_leaf.user_state_tree_root;

        // CORRECTIONS POSSIBLE: Get deferred_tx_debt_tree_root from corrections instead
        // to support deferred/inline payback without tree stack fragmentation
        // let previous_step_deferred_tx_debt_tree_root =
        // previous_step_header_gadget.current_state.deferred_tx_debt_tree_root;
        let previous_step_deferred_tx_debt_tree_root = corrections.previous_step_deferred_tx_debt_tree_root;

        // CORRECTIONS POSSIBLE: Get deferred_tx_debt_tree_root from corrections instead
        // to support deferred/inline payback without tree stack fragmentation
        // let previous_step_inline_tx_debt_tree_root =
        // previous_step_header_gadget.current_state.inline_tx_debt_tree_root;
        let previous_step_inline_tx_debt_tree_root = corrections.previous_step_inline_tx_debt_tree_root;

        let previous_step_tx_count = previous_step_header_gadget.current_state.tx_count;
        let previous_step_tx_hash_stack = previous_step_header_gadget.current_state.tx_hash_stack;
        let previous_step_user_balance = previous_step_header_gadget.current_state.user_leaf.balance;
        let previous_step_user_event_index = previous_step_header_gadget.current_state.user_leaf.event_index;
        tracing::debug!(
            "📊 Previous Step State - user_tree_root: {:?}, tx_count: {:?}, user_balance: {:?}, event_index: {:?}",
            previous_step_user_state_tree_root,
            previous_step_tx_count,
            previous_step_user_balance,
            previous_step_user_event_index
        );
        tracing::debug!(
            "📊 Previous Step Debt Trees - deferred: {:?}, inline: {:?}",
            previous_step_deferred_tx_debt_tree_root,
            previous_step_inline_tx_debt_tree_root
        );
        // -- end get useful info from the previous step

        // -- start list all the info we are going to check in the cfc_transaction_input
        let tx_in_start_user_contract_tree_root = cfc_transaction_input_context.transaction_call_start_ctx.start_user_contract_tree_root;

        let tx_in_start_contract_state_tree_root = cfc_transaction_input_context.transaction_call_start_ctx.start_contract_state_tree_root;
        let tx_in_start_deferred_tx_debt_tree_root = cfc_transaction_input_context.transaction_call_start_ctx.start_deferred_tx_debt_tree_root;
        let tx_in_start_user_balance = cfc_transaction_input_context.transaction_call_start_ctx.start_user_balance;
        let tx_in_start_event_index = cfc_transaction_input_context.transaction_call_start_ctx.start_user_event_index;

        let tx_in_contract_id = cfc_transaction_input_context.transaction_call_start_ctx.call_data.contract_id;

        let tx_in_end_contract_state_tree_root = cfc_transaction_input_context.transaction_end_ctx.end_contract_state_tree_root;
        let tx_in_end_deferred_tx_debt_tree_root = cfc_transaction_input_context.transaction_end_ctx.end_deferred_tx_debt_tree_root;
        let tx_in_total_balance_spent = cfc_transaction_input_context.transaction_end_ctx.total_balance_spent;
        let tx_in_total_events_emitted = cfc_transaction_input_context.transaction_end_ctx.total_events_emitted;
        tracing::debug!(
            "📊 Transaction Input Start State - contract_id: {:?}, user_contract_tree: {:?}, contract_state_tree: {:?}",
            tx_in_contract_id,
            tx_in_start_user_contract_tree_root,
            tx_in_start_contract_state_tree_root
        );
        tracing::debug!(
            "📊 Transaction Input Start Values - user_balance: {:?}, event_index: {:?}, deferred_debt: {:?}",
            tx_in_start_user_balance,
            tx_in_start_event_index,
            tx_in_start_deferred_tx_debt_tree_root
        );
        tracing::debug!(
            "📊 Transaction Input End State - contract_state_tree: {:?}, deferred_debt: {:?}, balance_spent: {:?}, events_emitted: {:?}",
            tx_in_end_contract_state_tree_root,
            tx_in_end_deferred_tx_debt_tree_root,
            tx_in_total_balance_spent,
            tx_in_total_events_emitted
        );

        // TODO: support inline tx debt, for now just use the merkle proof start value
        let tx_in_start_inline_tx_debt_tree_root = inline_tx_debt_pivot_proof.historical_root;
        let tx_in_end_inline_tx_debt_tree_root = inline_tx_debt_pivot_proof.historical_root;

        // -- start list all the info we are going to check in the cfc_transaction_input

        // ensure that the user contract tree update proof's old root matches the
        // previous session state
        builder.connect_hashes(user_contract_tree_update_proof.old_root, previous_step_user_state_tree_root);

        // ensure that the start user contract state tree root in the tx info matches
        // our previous session state
        builder.connect_hashes(tx_in_start_user_contract_tree_root, previous_step_user_state_tree_root);

        // ensure that the index of the leaf we are updating in the user contract tree
        // matches our contract id
        builder.connect(user_contract_tree_update_proof.index, tx_in_contract_id);

        // ensure that the update to the user contract tree reflects the change in the
        // transaction info

        /*

        instead of the following:
        builder.connect_hashes(
            tx_in_start_contract_state_tree_root,
            user_contract_tree_update_proof.old_value,
        );
        we need to check to see if the old_value in the user contract tree is a zero hash (the default value for every leaf)
        and if so we need to ensure the start state root for the contract is the default state root given its height, not the old_value
        */
        let default_zero_hashes = Self::get_default_zero_hashes::<H, F, D>(builder);
        let default_contract_state_root = builder.select_in_hash_array(&default_zero_hashes, contract_state_tree_height);

        let is_first_cst_update = builder.is_zero_hash(user_contract_tree_update_proof.old_value);
        tracing::debug!(
            "📊 Contract State Tree Update - height: {:?}, old_value: {:?}, new_value: {:?}, is_first_update: {:?}",
            contract_state_tree_height,
            user_contract_tree_update_proof.old_value,
            user_contract_tree_update_proof.new_value,
            is_first_cst_update
        );
        tracing::debug!(
            "📊 Contract State Tree Update - default_root: {:?}, index: {:?}",
            default_contract_state_root,
            user_contract_tree_update_proof.index
        );

        // if the user_contract_tree_update_proof.old_value is zero, ensure
        // tx_in_start_contract_state_tree_root is the contract's default state root
        // if the user_contract_tree_update_proof.old_value is NOT zero, ensure
        // tx_in_start_contract_state_tree_root is the previous value of the user
        // contract tree leaf
        builder.connect_hashes_switch(
            is_first_cst_update,
            tx_in_start_contract_state_tree_root,
            default_contract_state_root,
            user_contract_tree_update_proof.old_value,
        );

        builder.connect_hashes(tx_in_end_contract_state_tree_root, user_contract_tree_update_proof.new_value);
        let new_step_user_state_tree_root = user_contract_tree_update_proof.new_root;

        // ensure the user starting balance matches the user leaf in the previous step
        builder.connect(tx_in_start_user_balance, previous_step_user_balance);

        // ensure the user starting event index matches the user leaf in the previous
        // step
        builder.connect(tx_in_start_event_index, previous_step_user_event_index);

        // User leaf balance is not mutated by current token slot operations.
        // Keep the old protocol behavior until a dedicated native-balance delta is
        // specified.
        let zero_target = builder.zero();
        builder.connect(tx_in_total_balance_spent, zero_target);
        let new_step_user_balance = tx_in_start_user_balance;
        let new_step_event_index = builder.add(tx_in_start_event_index, tx_in_total_events_emitted);

        // ensure that the transaction inputs and previous step agree on the previous
        // tx_debt_tree_root
        builder.connect_hashes(tx_in_start_deferred_tx_debt_tree_root, previous_step_deferred_tx_debt_tree_root);

        // ensure that the transaction inputs and update merkle proof agree on the
        // previous tx_debt_tree_root
        builder.connect_hashes(tx_in_start_deferred_tx_debt_tree_root, deferred_tx_debt_pivot_proof.historical_root);

        // ensure that the transaction inputs and update merkle proof agree on the new
        // tx_debt_tree_root
        builder.connect_hashes(tx_in_end_deferred_tx_debt_tree_root, deferred_tx_debt_pivot_proof.current_root);

        // ensure that the transaction inputs and previous step agree on the previous
        // inline tx debt root
        builder.connect_hashes(previous_step_inline_tx_debt_tree_root, inline_tx_debt_pivot_proof.historical_root);

        builder.connect_hashes(previous_step_inline_tx_debt_tree_root, tx_in_start_inline_tx_debt_tree_root);

        builder.connect_hashes(tx_in_end_inline_tx_debt_tree_root, inline_tx_debt_pivot_proof.current_root);

        // TODO: add suppport for inline transaction debt, for now just disable it
        builder.connect_hashes(inline_tx_debt_pivot_proof.historical_root, inline_tx_debt_pivot_proof.current_root);

        /*
        // TODO: support deferred txs
        builder.connect_hashes(
            tx_in_start_deferred_tx_debt_tree_root,
            tx_in_end_deferred_tx_debt_tree_root,
        );
        */

        let new_step_deferred_tx_debt_tree_root = tx_in_end_deferred_tx_debt_tree_root;
        // TODO: add support for inline tx debt
        let new_step_inline_tx_debt_tree_root = tx_in_end_inline_tx_debt_tree_root;

        let one_target = builder.one();

        // ensure that the transaction count is updated properly
        let new_step_tx_count = builder.add(previous_step_tx_count, one_target);
        tracing::debug!(
            "📊 Transaction Count Update - previous: {:?}, new: {:?}",
            previous_step_tx_count,
            new_step_tx_count
        );

        // generate the tx stack item hash for the tx
        let tx_stack_item = TransactionLogStackItemGadget {
            call_data: cfc_transaction_input_context.transaction_call_start_ctx.call_data,
        };

        let mut tx_hash_stack = SimpleHashStackGadget::new(previous_step_tx_hash_stack);
        tx_hash_stack.push_hashable::<H, F, D, _>(builder, tx_stack_item);

        let new_step_tx_hash_stack = tx_hash_stack.get_tip();
        tracing::debug!(
            "📊 Transaction Hash Stack - previous: {:?}, new: {:?}",
            previous_step_tx_hash_stack,
            new_step_tx_hash_stack
        );

        let new_step_user_leaf = PsyUserLeafGadget {
            public_key: previous_step_header_gadget.current_state.user_leaf.public_key,
            user_state_tree_root: new_step_user_state_tree_root,
            balance: new_step_user_balance,
            nonce: previous_step_header_gadget.current_state.user_leaf.nonce,
            last_checkpoint_id: previous_step_header_gadget.current_state.user_leaf.last_checkpoint_id,
            event_index: new_step_event_index,
            user_id: previous_step_header_gadget.current_state.user_leaf.user_id,
        };

        let new_step_current_state = UserProvingSessionCurrentStateGadget {
            user_leaf: new_step_user_leaf,
            deferred_tx_debt_tree_root: new_step_deferred_tx_debt_tree_root,
            inline_tx_debt_tree_root: new_step_inline_tx_debt_tree_root,
            tx_hash_stack: new_step_tx_hash_stack,
            tx_count: new_step_tx_count,
        };
        tracing::debug!(
            "📊 New Step State - user_tree_root: {:?}, tx_count: {:?}, user_balance: {:?}",
            new_step_user_state_tree_root,
            new_step_tx_count,
            new_step_user_balance
        );
        tracing::debug!(
            "📊 New Step Debt Trees - deferred: {:?}, inline: {:?}",
            new_step_deferred_tx_debt_tree_root,
            new_step_inline_tx_debt_tree_root
        );

        let new_header_gadget = UserProvingSessionHeaderGadget::new_from_existing_ups_context::<H, F, D>(
            builder,
            previous_step_header_gadget.ups_step_circuit_whitelist_root,
            previous_step_header_gadget.session_start_context,
            new_step_current_state,
        );

        // -- end constraining cfc_inclusion_proof_gadget

        let cfc_contract_id = tx_in_contract_id;
        // -- end list key proven results
        tracing::debug!(
            "📊 Final Gadget State - contract_id: {:?}, method_id: {:?}, num_inputs: {:?}, num_outputs: {:?}",
            cfc_contract_id,
            cfc_method_id,
            cfc_num_inputs,
            cfc_num_outputs
        );

        let gadget = Self {
            cfc_transaction_input_context,
            user_contract_tree_update_proof,
            deferred_tx_debt_pivot_proof,
            inline_tx_debt_pivot_proof,
            cfc_inner_public_inputs_hash,
            cfc_contract_id,
            cfc_method_id,
            cfc_num_inputs,
            cfc_num_outputs,
        };

        (gadget, new_header_gadget)
    }
    pub fn set_witness<F: RichField>(&self, witness: &mut impl Witness<F>, input: &UPSCFCStandardStateDeltaInput<F>) -> anyhow::Result<()> {
        tracing::debug!(
            "📊 UPS CFC Standard State Delta set_witness - contract_id: {}, start_contract_root: {}, end_contract_root: {}",
            serde_json::to_string_pretty(&input.cfc_transaction_input_context.transaction_call_start_ctx.call_data.contract_id).unwrap(),
            serde_json::to_string_pretty(
                &input
                    .cfc_transaction_input_context
                    .transaction_call_start_ctx
                    .start_contract_state_tree_root
            )
            .unwrap(),
            serde_json::to_string_pretty(&input.cfc_transaction_input_context.transaction_end_ctx.end_contract_state_tree_root).unwrap()
        );

        self.cfc_transaction_input_context.set_witness_params(
            witness,
            &input.cfc_transaction_input_context.transaction_call_start_ctx,
            &input.cfc_transaction_input_context.transaction_end_ctx,
        )?;
        self.user_contract_tree_update_proof
            .set_witness_core_proof_q(witness, &input.user_contract_tree_update_proof)?;
        self.deferred_tx_debt_pivot_proof
            .set_witness_proof_core(witness, &input.deferred_tx_debt_pivot_proof)?;
        self.inline_tx_debt_pivot_proof
            .set_witness_proof_core(witness, &input.inline_tx_debt_pivot_proof)
    }
}

impl<F: RichField> WitnessValueFor<UPSCFCStandardStateDeltaGadget, F, true> for UPSCFCStandardStateDeltaInput<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &UPSCFCStandardStateDeltaGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<UPSCFCStandardStateDeltaGadget, F, false> for UPSCFCStandardStateDeltaInput<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &UPSCFCStandardStateDeltaGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}
