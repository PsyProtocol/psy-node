use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::circuit_builder::CircuitBuilder,
};
use psy_client_data::qdata::user_contract_state::UserContractState;
use psy_common_circuit::traits::CreatableTarget;

use super::user::PsyUserLeafGadget;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserContractStateGadget {
    pub checkpoint_tree_root: HashOutTarget,
    pub user_leaf: PsyUserLeafGadget,
    pub start_contract_state_root: HashOutTarget,
    pub contract_id: Target,
    pub checkpoint_id: Target,
}

impl UserContractStateGadget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        let checkpoint_tree_root = builder.add_virtual_hash();
        let user_leaf = PsyUserLeafGadget::create_virtual(builder);
        let start_contract_state_root = builder.add_virtual_hash();
        let contract_id = builder.add_virtual_target();
        let checkpoint_id = builder.add_virtual_target();

        Self {
            // checkpoint_id: builder.add_virtual_target(),
            checkpoint_tree_root,
            // checkpoint_leaf_hash: builder.add_virtual_hash(),
            user_leaf,
            start_contract_state_root,
            contract_id,
            checkpoint_id,
        }
    }

    pub fn set_witness<F: RichField>(&self, witness: &mut impl Witness<F>, target: &UserContractState<F>) -> anyhow::Result<()> {
        witness.set_hash_target(self.checkpoint_tree_root, target.checkpoint_tree_root.0)?;
        self.user_leaf.set_witness(witness, &target.user_leaf)?;
        witness.set_hash_target(self.start_contract_state_root, target.start_contract_state_root.0)?;
        witness.set_target(self.contract_id, target.contract_id)?;
        witness.set_target(self.checkpoint_id, target.checkpoint_id)
    }

    pub fn to_targets(&self) -> Vec<Target> {
        vec![
            self.checkpoint_tree_root.elements[0],
            self.checkpoint_tree_root.elements[1],
            self.checkpoint_tree_root.elements[2],
            self.checkpoint_tree_root.elements[3],
            self.user_leaf.public_key.elements[0],
            self.user_leaf.public_key.elements[1],
            self.user_leaf.public_key.elements[2],
            self.user_leaf.public_key.elements[3],
            self.user_leaf.user_state_tree_root.elements[0],
            self.user_leaf.user_state_tree_root.elements[1],
            self.user_leaf.user_state_tree_root.elements[2],
            self.user_leaf.user_state_tree_root.elements[3],
            self.user_leaf.balance,
            self.user_leaf.nonce,
            self.user_leaf.last_checkpoint_id,
            self.user_leaf.event_index,
            self.user_leaf.user_id,
            self.start_contract_state_root.elements[0],
            self.start_contract_state_root.elements[1],
            self.start_contract_state_root.elements[2],
            self.start_contract_state_root.elements[3],
            self.contract_id,
            self.checkpoint_id,
        ]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignContextGadget {
    pub checkpoint_tree_root: HashOutTarget,
    pub user_leaf: PsyUserLeafGadget,
}

impl SignContextGadget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        let checkpoint_tree_root = builder.add_virtual_hash();
        let user_leaf = PsyUserLeafGadget::create_virtual(builder);

        Self {
            checkpoint_tree_root,
            user_leaf,
        }
    }

    pub fn set_witness<F: RichField>(&self, witness: &mut impl Witness<F>, target: &UserContractState<F>) -> anyhow::Result<()> {
        witness.set_hash_target(self.checkpoint_tree_root, target.checkpoint_tree_root.0)?;
        self.user_leaf.set_witness(witness, &target.user_leaf)?;
        Ok(())
    }

    pub fn to_targets(&self) -> Vec<Target> {
        vec![
            self.checkpoint_tree_root.elements[0],
            self.checkpoint_tree_root.elements[1],
            self.checkpoint_tree_root.elements[2],
            self.checkpoint_tree_root.elements[3],
            self.user_leaf.public_key.elements[0],
            self.user_leaf.public_key.elements[1],
            self.user_leaf.public_key.elements[2],
            self.user_leaf.public_key.elements[3],
            self.user_leaf.user_state_tree_root.elements[0],
            self.user_leaf.user_state_tree_root.elements[1],
            self.user_leaf.user_state_tree_root.elements[2],
            self.user_leaf.user_state_tree_root.elements[3],
            self.user_leaf.balance,
            self.user_leaf.nonce,
            self.user_leaf.last_checkpoint_id,
            self.user_leaf.event_index,
            self.user_leaf.user_id,
        ]
    }
}
