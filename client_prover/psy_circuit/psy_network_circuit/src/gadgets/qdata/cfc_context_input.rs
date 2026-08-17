use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_client_data::dpn::cfc_context_input::{
    DapenCFCProvingSessionStartContext, DapenCFCUserTransactionCallStartContext, DapenCFCUserTransactionEndContext,
    DapenCFCUserTransactionInputContext,
};
use psy_common_circuit::{
    builder::hash::core::CircuitBuilderHashCore,
    traits::{AlgebraicHashableTarget, CreatableTarget, CreatableWithHasherTarget, FromTargets, ToTargets, WitnessValueFor},
};

use super::{
    checkpoint::PsyCheckpointLeafGadget, checkpoint_state_roots::PsyCheckpointGlobalStateRootsGadget,
    contract_function_call::DPNProvingSessionCompactMethodCallGadget, ups_context_input::UserProvingSessionStartContextGadget,
    user::PsyUserLeafGadget,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DapenCFCProvingSessionStartContextGadget {
    pub checkpoint_id: Target,
    pub checkpoint_tree_root: HashOutTarget,
    pub checkpoint_leaf: PsyCheckpointLeafGadget,
    pub state_roots: PsyCheckpointGlobalStateRootsGadget,
    pub start_session_user_leaf: PsyUserLeafGadget,
}

impl DapenCFCProvingSessionStartContextGadget {
    fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        let checkpoint_id = builder.add_virtual_target();
        let checkpoint_tree_root = builder.add_virtual_hash();
        let checkpoint_leaf = PsyCheckpointLeafGadget::create_virtual(builder);
        let state_roots = PsyCheckpointGlobalStateRootsGadget::create_virtual(builder);
        let start_session_user_leaf = PsyUserLeafGadget::create_virtual(builder);

        let expected_global_chain_root = checkpoint_leaf.global_chain_root;
        let computed_global_chain_root = state_roots.to_hash::<H, F, D>(builder);

        builder.connect_hashes(expected_global_chain_root, computed_global_chain_root);

        Self {
            checkpoint_id,
            checkpoint_tree_root,
            checkpoint_leaf,
            state_roots,
            start_session_user_leaf,
        }
    }
    pub fn to_user_proving_session_start_context<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> UserProvingSessionStartContextGadget {
        let start_session_user_leaf_hash = self.start_session_user_leaf.to_hash::<H, F, D>(builder);
        let checkpoint_leaf_hash = self.checkpoint_leaf.to_hash::<H, F, D>(builder);
        // we need to ensure that these are interchangable and most importantly have
        // interchangable hashes with UserProvingSessionStartContextGadget

        UserProvingSessionStartContextGadget {
            checkpoint_id: self.checkpoint_id,
            checkpoint_tree_root: self.checkpoint_tree_root,
            checkpoint_leaf_hash,
            start_session_user_leaf: self.start_session_user_leaf,
            start_session_user_leaf_hash,
        }
    }

    /*
    pub fn ensure_self_consistent<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) {

        let expected_global_chain_root = self.checkpoint_leaf.global_chain_root;
        let computed_global_chain_root = self.state_roots.to_hash::<H, F, D>(builder);

        builder.connect_hashes(expected_global_chain_root, computed_global_chain_root);
    }
    */
    pub fn set_witness<F: RichField>(&self, witness: &mut impl Witness<F>, target: &DapenCFCProvingSessionStartContext<F>) -> anyhow::Result<()> {
        witness.set_target(self.checkpoint_id, target.checkpoint_id)?;
        witness.set_hash_target(self.checkpoint_tree_root, target.checkpoint_tree_root.0)?;
        self.checkpoint_leaf.set_witness(witness, &target.checkpoint_leaf)?;
        self.state_roots.set_witness(witness, &target.state_roots)?;
        self.start_session_user_leaf.set_witness(witness, &target.start_session_user_leaf)
    }
    pub fn to_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        // IMPORTANT: Must be the same hash result/algo as
        // UserProvingSessionStartContextGadget
        let checkpoint_leaf_hash = self.checkpoint_leaf.to_hash_target::<H, F, D>(builder);

        let checkpoint_combo = builder.hash_two_to_one::<H>(self.checkpoint_tree_root, checkpoint_leaf_hash);
        let user_leaf_hash = self.start_session_user_leaf.to_hash_target::<H, F, D>(builder);

        let checkpoint_user_combo = builder.hash_two_to_one::<H>(checkpoint_combo, user_leaf_hash);
        builder.hash_n_to_hash_no_pad::<H>(vec![
            self.checkpoint_id,
            checkpoint_user_combo.elements[0],
            checkpoint_user_combo.elements[1],
            checkpoint_user_combo.elements[2],
            checkpoint_user_combo.elements[3],
        ])
    }
}
impl CreatableWithHasherTarget for DapenCFCProvingSessionStartContextGadget {
    fn create_virtual_with_hasher<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self::add_virtual_to::<H, F, D>(builder)
    }
}
impl AlgebraicHashableTarget for DapenCFCProvingSessionStartContextGadget {
    fn to_hash_target<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        self.to_hash::<H, F, D>(builder)
    }
}
impl<F: RichField> WitnessValueFor<DapenCFCProvingSessionStartContextGadget, F, true> for DapenCFCProvingSessionStartContext<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &DapenCFCProvingSessionStartContextGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<DapenCFCProvingSessionStartContextGadget, F, false> for DapenCFCProvingSessionStartContext<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &DapenCFCProvingSessionStartContextGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DapenCFCUserTransactionCallStartContextGadget {
    pub start_user_contract_tree_root: HashOutTarget,
    pub start_contract_state_tree_root: HashOutTarget,

    pub call_data: DPNProvingSessionCompactMethodCallGadget,
    pub start_deferred_tx_debt_tree_root: HashOutTarget,
    pub previous_tx_stack_hash: HashOutTarget,
    pub previous_tx_count: Target,

    pub start_user_balance: Target,
    pub start_user_event_index: Target,
}

impl DapenCFCUserTransactionCallStartContextGadget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        let start_user_contract_tree_root = builder.add_virtual_hash();
        let start_contract_state_tree_root = builder.add_virtual_hash();

        let call_data = DPNProvingSessionCompactMethodCallGadget::create_virtual(builder);
        let start_deferred_tx_debt_tree_root = builder.add_virtual_hash();
        let previous_tx_stack_hash = builder.add_virtual_hash();
        let previous_tx_count = builder.add_virtual_target();

        let start_user_balance = builder.add_virtual_target();
        let start_user_event_index = builder.add_virtual_target();

        Self {
            start_user_contract_tree_root,
            start_contract_state_tree_root,
            call_data,
            start_deferred_tx_debt_tree_root,
            previous_tx_stack_hash,
            previous_tx_count,
            start_user_balance,
            start_user_event_index,
        }
    }
    pub fn set_witness<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        target: &DapenCFCUserTransactionCallStartContext<F>,
    ) -> anyhow::Result<()> {
        witness.set_hash_target(self.start_user_contract_tree_root, target.start_user_contract_tree_root.0)?;
        witness.set_hash_target(self.start_contract_state_tree_root, target.start_contract_state_tree_root.0)?;

        self.call_data.set_witness(witness, &target.call_data)?;
        witness.set_hash_target(self.start_deferred_tx_debt_tree_root, target.start_deferred_tx_debt_tree_root.0)?;
        witness.set_hash_target(self.previous_tx_stack_hash, target.previous_tx_stack_hash.0)?;
        witness.set_target(self.previous_tx_count, target.previous_tx_count)?;

        witness.set_target(self.start_user_balance, target.start_user_balance)?;
        witness.set_target(self.start_user_event_index, target.start_user_event_index)
    }
    pub fn to_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        let uct_cst_combo = builder.hash_two_to_one::<H>(self.start_user_contract_tree_root, self.start_contract_state_tree_root);

        let debt_combo = self.start_deferred_tx_debt_tree_root;
        let call_data_hash = self.call_data.to_hash::<H, F, D>(builder);

        let call_data_debt_combo = builder.hash_two_to_one::<H>(call_data_hash, debt_combo);
        let previous_tx_context_hash = builder.hash_n_to_hash_no_pad::<H>(vec![
            self.previous_tx_count,
            self.previous_tx_stack_hash.elements[0],
            self.previous_tx_stack_hash.elements[1],
            self.previous_tx_stack_hash.elements[2],
            self.previous_tx_stack_hash.elements[3],
        ]);

        let state_call_combo = builder.hash_two_to_one::<H>(uct_cst_combo, call_data_debt_combo);
        let state_call_tx_combo = builder.hash_two_to_one::<H>(state_call_combo, previous_tx_context_hash);

        builder.hash_n_to_hash_no_pad::<H>(vec![
            state_call_tx_combo.elements[0],
            state_call_tx_combo.elements[1],
            state_call_tx_combo.elements[2],
            state_call_tx_combo.elements[3],
            self.start_user_balance,
            self.start_user_event_index,
        ])
    }
}
impl CreatableTarget for DapenCFCUserTransactionCallStartContextGadget {
    fn create_virtual<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self::add_virtual_to(builder)
    }
}
impl AlgebraicHashableTarget for DapenCFCUserTransactionCallStartContextGadget {
    fn to_hash_target<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        self.to_hash::<H, F, D>(builder)
    }
}

impl<F: RichField> WitnessValueFor<DapenCFCUserTransactionCallStartContextGadget, F, true> for DapenCFCUserTransactionCallStartContext<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &DapenCFCUserTransactionCallStartContextGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<DapenCFCUserTransactionCallStartContextGadget, F, false> for DapenCFCUserTransactionCallStartContext<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &DapenCFCUserTransactionCallStartContextGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DapenCFCUserTransactionEndContextGadget {
    pub end_contract_state_tree_root: HashOutTarget,
    pub end_deferred_tx_debt_tree_root: HashOutTarget,

    pub outputs_hash: HashOutTarget,
    pub outputs_length: Target,
    pub total_events_emitted: Target,
    pub total_balance_spent: Target,
}

impl DapenCFCUserTransactionEndContextGadget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        let end_contract_state_tree_root = builder.add_virtual_hash();
        let end_deferred_tx_debt_tree_root = builder.add_virtual_hash();

        let outputs_hash = builder.add_virtual_hash();
        let outputs_length = builder.add_virtual_target();
        let total_events_emitted = builder.add_virtual_target();
        let total_balance_spent = builder.add_virtual_target();

        Self {
            end_contract_state_tree_root,
            end_deferred_tx_debt_tree_root,
            outputs_hash,
            outputs_length,
            total_events_emitted,
            total_balance_spent,
        }
    }
    pub fn set_witness<F: RichField>(&self, witness: &mut impl Witness<F>, target: &DapenCFCUserTransactionEndContext<F>) -> anyhow::Result<()> {
        witness.set_hash_target(self.end_contract_state_tree_root, target.end_contract_state_tree_root.0)?;
        witness.set_hash_target(self.end_deferred_tx_debt_tree_root, target.end_deferred_tx_debt_tree_root.0)?;

        witness.set_hash_target(self.outputs_hash, target.outputs_hash.0)?;
        witness.set_target(self.outputs_length, target.outputs_length)?;
        witness.set_target(self.total_events_emitted, target.total_events_emitted)?;
        witness.set_target(self.total_balance_spent, target.total_balance_spent)
    }
    pub fn to_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        let debt_combo = self.end_deferred_tx_debt_tree_root;

        let state_debt_combo = builder.hash_two_to_one::<H>(self.end_contract_state_tree_root, debt_combo);

        let output_info_hash = builder.hash_n_to_hash_no_pad::<H>(vec![
            self.outputs_hash.elements[0],
            self.outputs_hash.elements[1],
            self.outputs_hash.elements[2],
            self.outputs_hash.elements[3],
            self.outputs_length,
            self.total_events_emitted,
            self.total_balance_spent,
        ]);

        builder.hash_two_to_one::<H>(state_debt_combo, output_info_hash)
    }
}
impl CreatableTarget for DapenCFCUserTransactionEndContextGadget {
    fn create_virtual<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self::add_virtual_to(builder)
    }
}
impl AlgebraicHashableTarget for DapenCFCUserTransactionEndContextGadget {
    fn to_hash_target<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        self.to_hash::<H, F, D>(builder)
    }
}
impl ToTargets for DapenCFCUserTransactionEndContextGadget {
    fn to_targets(&self) -> Vec<Target> {
        vec![
            self.end_contract_state_tree_root.elements[0],
            self.end_contract_state_tree_root.elements[1],
            self.end_contract_state_tree_root.elements[2],
            self.end_contract_state_tree_root.elements[3],
            self.end_deferred_tx_debt_tree_root.elements[0],
            self.end_deferred_tx_debt_tree_root.elements[1],
            self.end_deferred_tx_debt_tree_root.elements[2],
            self.end_deferred_tx_debt_tree_root.elements[3],
            self.outputs_hash.elements[0],
            self.outputs_hash.elements[1],
            self.outputs_hash.elements[2],
            self.outputs_hash.elements[3],
            self.outputs_length,
            self.total_events_emitted,
            self.total_balance_spent,
        ]
    }
}
impl FromTargets for DapenCFCUserTransactionEndContextGadget {
    fn from_targets(targets: &[Target]) -> Self {
        if targets.len() != 15 {
            panic!(
                "Invalid number of elements for DapenCFCUserTransactionEndContextGadget, expected 15, got {}",
                targets.len()
            );
        }
        Self {
            end_contract_state_tree_root: HashOutTarget {
                elements: [targets[0], targets[1], targets[2], targets[3]],
            },

            end_deferred_tx_debt_tree_root: HashOutTarget {
                elements: [targets[4], targets[5], targets[6], targets[7]],
            },

            outputs_hash: HashOutTarget {
                elements: [targets[8], targets[9], targets[10], targets[11]],
            },

            outputs_length: targets[12],
            total_events_emitted: targets[13],
            total_balance_spent: targets[14],
        }
    }
}

impl<F: RichField> WitnessValueFor<DapenCFCUserTransactionEndContextGadget, F, true> for DapenCFCUserTransactionEndContext<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &DapenCFCUserTransactionEndContextGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<DapenCFCUserTransactionEndContextGadget, F, false> for DapenCFCUserTransactionEndContext<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &DapenCFCUserTransactionEndContextGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

pub fn hash_transaction_input_context<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    proving_session_start_ctx_hash: HashOutTarget,
    transaction_call_start_ctx: &DapenCFCUserTransactionCallStartContextGadget,
    transaction_end_ctx: &DapenCFCUserTransactionEndContextGadget,
) -> HashOutTarget {
    // shared by UPSInspectDapenCFCUserTransactionInputContextGadget and
    // UPSInspectDapenCFCUserTransactionInputContextGadget
    let transaction_call_start_ctx_hash = transaction_call_start_ctx.to_hash::<H, F, D>(builder);
    let transaction_end_ctx_hash = transaction_end_ctx.to_hash::<H, F, D>(builder);
    let tx_start_end_combo = builder.hash_two_to_one::<H>(transaction_call_start_ctx_hash, transaction_end_ctx_hash);

    let session_start_tx_combo = builder.hash_two_to_one::<H>(proving_session_start_ctx_hash, tx_start_end_combo);

    session_start_tx_combo
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DapenCFCUserTransactionInputContextGadget {
    pub proving_session_start_ctx: DapenCFCProvingSessionStartContextGadget,
    pub transaction_call_start_ctx: DapenCFCUserTransactionCallStartContextGadget,
    pub transaction_end_ctx: DapenCFCUserTransactionEndContextGadget,
}

impl DapenCFCUserTransactionInputContextGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        let proving_session_start_ctx = DapenCFCProvingSessionStartContextGadget::create_virtual_with_hasher::<H, F, D>(builder);
        let transaction_call_start_ctx = DapenCFCUserTransactionCallStartContextGadget::create_virtual(builder);
        let transaction_end_ctx = DapenCFCUserTransactionEndContextGadget::create_virtual(builder);

        Self {
            proving_session_start_ctx,
            transaction_call_start_ctx,
            transaction_end_ctx,
        }
    }
    pub fn set_witness<F: RichField>(&self, witness: &mut impl Witness<F>, target: &DapenCFCUserTransactionInputContext<F>) -> anyhow::Result<()> {
        self.proving_session_start_ctx.set_witness(witness, &target.proving_session_start_ctx)?;
        self.transaction_call_start_ctx.set_witness(witness, &target.transaction_call_start_ctx)?;
        self.transaction_end_ctx.set_witness(witness, &target.transaction_end_ctx)
    }
    pub fn to_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        let proving_session_start_ctx_hash = self.proving_session_start_ctx.to_hash::<H, F, D>(builder);

        hash_transaction_input_context::<H, F, D>(
            builder,
            proving_session_start_ctx_hash,
            &self.transaction_call_start_ctx,
            &self.transaction_end_ctx,
        )
    }
}
impl CreatableWithHasherTarget for DapenCFCUserTransactionInputContextGadget {
    fn create_virtual_with_hasher<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self::add_virtual_to::<H, F, D>(builder)
    }
}
impl AlgebraicHashableTarget for DapenCFCUserTransactionInputContextGadget {
    fn to_hash_target<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        self.to_hash::<H, F, D>(builder)
    }
}

impl<F: RichField> WitnessValueFor<DapenCFCUserTransactionInputContextGadget, F, true> for DapenCFCUserTransactionInputContext<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &DapenCFCUserTransactionInputContextGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<DapenCFCUserTransactionInputContextGadget, F, false> for DapenCFCUserTransactionInputContext<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &DapenCFCUserTransactionInputContextGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UPSInspectDapenCFCUserTransactionInputContextGadget {
    pub transaction_call_start_ctx: DapenCFCUserTransactionCallStartContextGadget,
    pub transaction_end_ctx: DapenCFCUserTransactionEndContextGadget,

    // start computed
    pub proving_session_start_ctx_hash: HashOutTarget,
}

impl UPSInspectDapenCFCUserTransactionInputContextGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        proving_session_start_ctx_hash: HashOutTarget,
    ) -> Self {
        let transaction_call_start_ctx = DapenCFCUserTransactionCallStartContextGadget::create_virtual(builder);
        let transaction_end_ctx = DapenCFCUserTransactionEndContextGadget::create_virtual(builder);

        Self {
            proving_session_start_ctx_hash,
            transaction_call_start_ctx,
            transaction_end_ctx,
        }
    }
    pub fn set_witness_params<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        transaction_call_start_ctx: &DapenCFCUserTransactionCallStartContext<F>,
        transaction_end_ctx: &DapenCFCUserTransactionEndContext<F>,
    ) -> anyhow::Result<()> {
        self.transaction_call_start_ctx.set_witness(witness, &transaction_call_start_ctx)?;
        self.transaction_end_ctx.set_witness(witness, &transaction_end_ctx)
    }
    pub fn to_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        hash_transaction_input_context::<H, F, D>(
            builder,
            self.proving_session_start_ctx_hash,
            &self.transaction_call_start_ctx,
            &self.transaction_end_ctx,
        )
    }
}
impl AlgebraicHashableTarget for UPSInspectDapenCFCUserTransactionInputContextGadget {
    fn to_hash_target<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        self.to_hash::<H, F, D>(builder)
    }
}

impl<F: RichField> WitnessValueFor<UPSInspectDapenCFCUserTransactionInputContextGadget, F, true> for DapenCFCUserTransactionInputContext<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &UPSInspectDapenCFCUserTransactionInputContextGadget) -> anyhow::Result<()> {
        target.set_witness_params(witness, &self.transaction_call_start_ctx, &self.transaction_end_ctx)
    }
}

impl<F: RichField> WitnessValueFor<UPSInspectDapenCFCUserTransactionInputContextGadget, F, false> for DapenCFCUserTransactionInputContext<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &UPSInspectDapenCFCUserTransactionInputContextGadget) -> anyhow::Result<()> {
        target.set_witness_params(witness, &self.transaction_call_start_ctx, &self.transaction_end_ctx)
    }
}
