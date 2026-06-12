use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::qdata::user::PsyUserLeaf;
use psy_common_circuit::{
    builder::hash::core::CircuitBuilderHashCore,
    traits::{AlgebraicHashableTarget, CreatableTarget, FromTargets, ToTargets, WitnessValueFor},
};

#[derive(Clone, Debug, PartialEq, Eq, Copy)]
pub struct PsyUserLeafGadget {
    pub public_key: HashOutTarget,
    pub user_state_tree_root: HashOutTarget,

    pub balance: Target,
    pub nonce: Target,
    pub last_checkpoint_id: Target,
    pub event_index: Target,
    pub user_id: Target,
}

impl PsyUserLeafGadget {
    pub fn create_new_user_default<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        user_id: Target,
        public_key: HashOutTarget,
        default_user_state_tree_root: QHashOut<F>,
    ) -> Self {
        let zero = builder.zero();
        Self {
            public_key,
            user_state_tree_root: builder.constant_qhash(default_user_state_tree_root),
            balance: zero,
            nonce: zero,
            last_checkpoint_id: zero,
            event_index: zero,
            user_id,
        }
    }

    pub fn set_witness<F: RichField>(&self, witness: &mut impl Witness<F>, target: &PsyUserLeaf<F>) -> anyhow::Result<()> {
        witness.set_hash_target(self.public_key, target.public_key.0)?;
        witness.set_hash_target(self.user_state_tree_root, target.user_state_tree_root.0)?;

        witness.set_target(self.balance, target.balance)?;
        witness.set_target(self.nonce, target.nonce)?;
        witness.set_target(self.last_checkpoint_id, target.last_checkpoint_id)?;
        witness.set_target(self.event_index, target.event_index)?;
        witness.set_target(self.user_id, target.user_id)
    }
    pub fn to_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        builder.hash_n_to_hash_no_pad::<H>(self.to_targets())
    }
    pub fn connect_to_other<F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>, other: PsyUserLeafGadget) {
        builder.connect_hashes(self.public_key, other.public_key);

        builder.connect_hashes(self.user_state_tree_root, other.user_state_tree_root);

        builder.connect(self.balance, other.balance);

        builder.connect(self.nonce, other.nonce);

        builder.connect(self.last_checkpoint_id, other.last_checkpoint_id);

        builder.connect(self.event_index, other.event_index);

        builder.connect(self.user_id, other.user_id);
    }

    pub fn connect_to_all_except_state_balance_event_index<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: PsyUserLeafGadget,
    ) {
        builder.connect_hashes(self.public_key, other.public_key);

        /*
        // allow update to state root, hence this is commented out
        builder.connect_hashes(
            self.user_state_tree_root,
            other.user_state_tree_root,
        );
        */

        /*
        // allow update to balance, hence this is commented out
        builder.connect(
            self.balance,
            other.balance,
        );
        */

        builder.connect(self.nonce, other.nonce);

        builder.connect(self.last_checkpoint_id, other.last_checkpoint_id);

        /*
        // allow update to event index, hence this is commented out
        builder.connect(
            self.event_index,
            other.event_index,
        );
        */

        builder.connect(self.user_id, other.user_id);
    }
}
impl AlgebraicHashableTarget for PsyUserLeafGadget {
    fn to_hash_target<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        self.to_hash::<H, F, D>(builder)
    }
}
impl CreatableTarget for PsyUserLeafGadget {
    fn create_virtual<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        let public_key = builder.add_virtual_hash();
        let user_state_tree_root = builder.add_virtual_hash();

        let balance = builder.add_virtual_target();
        let nonce = builder.add_virtual_target();
        let last_checkpoint_id = builder.add_virtual_target();
        let event_index = builder.add_virtual_target();
        let user_id = builder.add_virtual_target();

        Self {
            public_key,
            user_state_tree_root,
            balance,
            nonce,
            last_checkpoint_id,
            event_index,
            user_id,
        }
    }
}
impl ToTargets for PsyUserLeafGadget {
    fn to_targets(&self) -> Vec<Target> {
        vec![
            self.public_key.elements[0],
            self.public_key.elements[1],
            self.public_key.elements[2],
            self.public_key.elements[3],
            self.user_state_tree_root.elements[0],
            self.user_state_tree_root.elements[1],
            self.user_state_tree_root.elements[2],
            self.user_state_tree_root.elements[3],
            self.balance,
            self.nonce,
            self.last_checkpoint_id,
            self.event_index,
            self.user_id,
        ]
    }
}
impl FromTargets for PsyUserLeafGadget {
    fn from_targets(targets: &[Target]) -> Self {
        if targets.len() != 13 {
            panic!(
                "tried to create PsyUserLeafGadget from an array of {} targets, but expected an array of 13 targets",
                targets.len()
            );
        }
        let public_key = HashOutTarget {
            elements: [targets[0], targets[1], targets[2], targets[3]],
        };
        let user_state_tree_root = HashOutTarget {
            elements: [targets[4], targets[5], targets[6], targets[7]],
        };
        let balance = targets[8];
        let nonce = targets[9];
        let last_checkpoint_id = targets[10];
        let event_index = targets[11];
        let user_id = targets[12];
        Self {
            public_key,
            user_state_tree_root,
            balance,
            nonce,
            last_checkpoint_id,
            event_index,
            user_id,
        }
    }
}

impl<F: RichField> WitnessValueFor<PsyUserLeafGadget, F, true> for PsyUserLeaf<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &PsyUserLeafGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<PsyUserLeafGadget, F, false> for PsyUserLeaf<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &PsyUserLeafGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}
