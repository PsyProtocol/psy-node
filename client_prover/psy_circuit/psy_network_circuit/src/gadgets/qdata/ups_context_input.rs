use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::ups::ups_context_input::{UserProvingSessionCurrentState, UserProvingSessionHeader, UserProvingSessionStartContext};
use psy_common_circuit::{
    builder::{comparison::CircuitBuilderComparison, hash::core::CircuitBuilderHashCore, select::CircuitBuilderSelectHelpers},
    traits::{AlgebraicHashableTarget, CreatableTarget, CreatableWithHasherTarget, WitnessValueFor},
};
use psy_config::get_default_user_state_tree_root;

use super::user::PsyUserLeafGadget;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserProvingSessionStartContextGadget {
    pub checkpoint_id: Target,
    pub checkpoint_tree_root: HashOutTarget,
    pub checkpoint_leaf_hash: HashOutTarget,

    // this is the user leaf as it was at the start of the proving session, not to be confused with start_user_leaf
    pub start_session_user_leaf: PsyUserLeafGadget,

    // computed
    pub start_session_user_leaf_hash: HashOutTarget,
}

impl UserProvingSessionStartContextGadget {
    fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        let checkpoint_id = builder.add_virtual_target();
        let checkpoint_tree_root = builder.add_virtual_hash();
        let checkpoint_leaf_hash = builder.add_virtual_hash();
        let start_session_user_leaf = PsyUserLeafGadget::create_virtual(builder);
        let start_session_user_leaf_hash = start_session_user_leaf.to_hash::<H, F, D>(builder);

        Self {
            checkpoint_id,
            checkpoint_tree_root,
            checkpoint_leaf_hash,
            start_session_user_leaf,
            start_session_user_leaf_hash,
        }
    }
    pub fn get_end_cap_start_session_user_leaf_hash_with_potential_register_user<
        H: AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        // if the start session user leaf has the default state tree root, it is a new
        // user being registered, so the transition should start from the zero hash
        // otherwise, use the start session user leaf hash
        let default_user_state_tree_root = builder.constant_qhash(get_default_user_state_tree_root::<F>());
        let is_state_root_default = builder.is_equal_hash(self.start_session_user_leaf.user_state_tree_root, default_user_state_tree_root);
        let zero_hash = builder.constant_qhash(QHashOut::ZERO);
        builder.select_hash(is_state_root_default, zero_hash, self.start_session_user_leaf_hash)
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
    pub fn set_witness<F: RichField>(&self, witness: &mut impl Witness<F>, target: &UserProvingSessionStartContext<F>) -> anyhow::Result<()> {
        witness.set_target(self.checkpoint_id, target.checkpoint_id)?;
        witness.set_hash_target(self.checkpoint_tree_root, target.checkpoint_tree_root.0)?;
        witness.set_hash_target(self.checkpoint_leaf_hash, target.checkpoint_leaf_hash.0)?;
        self.start_session_user_leaf.set_witness(witness, &target.start_session_user_leaf)
    }
    pub fn to_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        // IMPORTANT: Must be the same hash result/algo as
        // DapenCFCProvingSessionStartContextGadget
        let checkpoint_combo = builder.hash_two_to_one::<H>(self.checkpoint_tree_root, self.checkpoint_leaf_hash);
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
impl CreatableWithHasherTarget for UserProvingSessionStartContextGadget {
    fn create_virtual_with_hasher<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self::add_virtual_to::<H, F, D>(builder)
    }
}
impl AlgebraicHashableTarget for UserProvingSessionStartContextGadget {
    fn to_hash_target<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        self.to_hash::<H, F, D>(builder)
    }
}
impl<F: RichField> WitnessValueFor<UserProvingSessionStartContextGadget, F, true> for UserProvingSessionStartContext<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &UserProvingSessionStartContextGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<UserProvingSessionStartContextGadget, F, false> for UserProvingSessionStartContext<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &UserProvingSessionStartContextGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserProvingSessionCurrentStateGadget {
    pub user_leaf: PsyUserLeafGadget,

    pub deferred_tx_debt_tree_root: HashOutTarget,
    pub inline_tx_debt_tree_root: HashOutTarget,

    pub tx_hash_stack: HashOutTarget,
    pub tx_count: Target,
}

impl UserProvingSessionCurrentStateGadget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        let user_leaf = PsyUserLeafGadget::create_virtual::<F, D>(builder);

        let deferred_tx_debt_tree_root = builder.add_virtual_hash();
        let inline_tx_debt_tree_root = builder.add_virtual_hash();

        let tx_hash_stack = builder.add_virtual_hash();
        let tx_count = builder.add_virtual_target();

        Self {
            user_leaf,
            deferred_tx_debt_tree_root,
            inline_tx_debt_tree_root,
            tx_hash_stack,
            tx_count,
        }
    }
    pub fn set_witness<F: RichField>(&self, witness: &mut impl Witness<F>, target: &UserProvingSessionCurrentState<F>) -> anyhow::Result<()> {
        self.user_leaf.set_witness(witness, &target.user_leaf)?;
        witness.set_hash_target(self.deferred_tx_debt_tree_root, target.deferred_tx_debt_tree_root.0)?;
        witness.set_hash_target(self.inline_tx_debt_tree_root, target.inline_tx_debt_tree_root.0)?;
        witness.set_hash_target(self.tx_hash_stack, target.tx_hash_stack.0)?;
        witness.set_target(self.tx_count, target.tx_count)
    }
    pub fn to_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        let user_leaf_hash = self.user_leaf.to_hash::<H, F, D>(builder);
        let debt_combo = builder.hash_two_to_one::<H>(self.deferred_tx_debt_tree_root, self.inline_tx_debt_tree_root);
        let tx_combo = builder.hash_n_to_hash_no_pad::<H>(vec![
            self.tx_hash_stack.elements[0],
            self.tx_hash_stack.elements[1],
            self.tx_hash_stack.elements[2],
            self.tx_hash_stack.elements[3],
            self.tx_count,
        ]);

        let debt_tx_combo = builder.hash_two_to_one::<H>(debt_combo, tx_combo);
        let result = builder.hash_two_to_one::<H>(user_leaf_hash, debt_tx_combo);

        result
    }
}
impl CreatableTarget for UserProvingSessionCurrentStateGadget {
    fn create_virtual<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self::add_virtual_to(builder)
    }
}
impl AlgebraicHashableTarget for UserProvingSessionCurrentStateGadget {
    fn to_hash_target<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        self.to_hash::<H, F, D>(builder)
    }
}
impl<F: RichField> WitnessValueFor<UserProvingSessionCurrentStateGadget, F, true> for UserProvingSessionCurrentState<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &UserProvingSessionCurrentStateGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<UserProvingSessionCurrentStateGadget, F, false> for UserProvingSessionCurrentState<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &UserProvingSessionCurrentStateGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserProvingSessionHeaderGadget {
    pub ups_step_circuit_whitelist_root: HashOutTarget,
    pub session_start_context: UserProvingSessionStartContextGadget,
    pub current_state: UserProvingSessionCurrentStateGadget,

    // computed
    pub session_start_context_hash: HashOutTarget,
    pub current_state_hash: HashOutTarget,
}

impl UserProvingSessionHeaderGadget {
    pub fn new_from_existing_ups_context<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        ups_step_circuit_whitelist_root: HashOutTarget,
        session_start_context: UserProvingSessionStartContextGadget,
        current_state: UserProvingSessionCurrentStateGadget,
    ) -> Self {
        // sanity check: make sure we are on the same user as we started with
        builder.connect(session_start_context.start_session_user_leaf.user_id, current_state.user_leaf.user_id);
        builder.connect_hashes(
            session_start_context.start_session_user_leaf.public_key,
            current_state.user_leaf.public_key,
        );

        let session_start_context_hash = session_start_context.to_hash::<H, F, D>(builder);
        let current_state_hash = current_state.to_hash::<H, F, D>(builder);

        Self {
            ups_step_circuit_whitelist_root,
            session_start_context,
            current_state,

            session_start_context_hash,
            current_state_hash,
        }
    }
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        let ups_step_circuit_whitelist_root = builder.add_virtual_hash();
        let session_start_context = UserProvingSessionStartContextGadget::add_virtual_to::<H, F, D>(builder);
        let current_state = UserProvingSessionCurrentStateGadget::add_virtual_to::<F, D>(builder);

        // sanity check: make sure we are on the same user as we started with
        builder.connect(session_start_context.start_session_user_leaf.user_id, current_state.user_leaf.user_id);
        builder.connect_hashes(
            session_start_context.start_session_user_leaf.public_key,
            current_state.user_leaf.public_key,
        );

        let session_start_context_hash = session_start_context.to_hash::<H, F, D>(builder);
        let current_state_hash = current_state.to_hash::<H, F, D>(builder);

        Self {
            ups_step_circuit_whitelist_root,
            session_start_context,
            current_state,

            session_start_context_hash,
            current_state_hash,
        }
    }
    pub fn set_witness<F: RichField>(&self, witness: &mut impl Witness<F>, target: &UserProvingSessionHeader<F>) -> anyhow::Result<()> {
        witness.set_hash_target(self.ups_step_circuit_whitelist_root, target.ups_step_circuit_whitelist_root.0)?;
        self.session_start_context.set_witness(witness, &target.session_start_context)?;
        self.current_state.set_witness(witness, &target.current_state)
    }
    pub fn to_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        let start_current_combo = builder.hash_two_to_one::<H>(self.session_start_context_hash, self.current_state_hash);

        builder.hash_two_to_one::<H>(self.ups_step_circuit_whitelist_root, start_current_combo)
    }
}
impl CreatableWithHasherTarget for UserProvingSessionHeaderGadget {
    fn create_virtual_with_hasher<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self::add_virtual_to::<H, F, D>(builder)
    }
}
impl AlgebraicHashableTarget for UserProvingSessionHeaderGadget {
    fn to_hash_target<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        self.to_hash::<H, F, D>(builder)
    }
}
impl<F: RichField> WitnessValueFor<UserProvingSessionHeaderGadget, F, true> for UserProvingSessionHeader<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &UserProvingSessionHeaderGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<UserProvingSessionHeaderGadget, F, false> for UserProvingSessionHeader<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &UserProvingSessionHeaderGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}
