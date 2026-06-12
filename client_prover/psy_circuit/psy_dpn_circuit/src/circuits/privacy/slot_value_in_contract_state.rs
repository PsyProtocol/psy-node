use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::qdata::user::PsyUserLeaf;
use psy_common_circuit::{
    hash::merkle::gadgets::merkle_proof::{MerkleProofGadget, OptionalMerkleProofGadget},
    traits::CreatableTarget,
};
use psy_crypto::hash::merkle::core::MerkleProofCore;
use psy_network_circuit::gadgets::qdata::user::PsyUserLeafGadget;

#[derive(Clone, Debug)]
pub struct SlotValueInContractStateWitnessInput<F: RichField> {
    pub sender_user_id: u64,
    pub contract_id: u64,
    pub slot_index: u64,
    pub user_leaf: PsyUserLeaf<F>,
    pub slot_proof: MerkleProofCore<QHashOut<F>>,
    pub contract_proof: MerkleProofCore<QHashOut<F>>,
    pub user_tree_proof: MerkleProofCore<QHashOut<F>>,
}

#[derive(Debug)]
pub struct SlotValueInContractStateGadget {
    pub sender_user_id: Target,
    pub contract_id: Target,
    pub slot_index: Target,
    pub user_leaf: PsyUserLeafGadget,
    pub slot_proof: MerkleProofGadget,
    pub contract_proof: MerkleProofGadget,
    pub user_tree_proof: MerkleProofGadget,
    pub user_tree_root: HashOutTarget,
}

impl SlotValueInContractStateGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        global_user_tree_height: usize,
        global_contract_tree_height: usize,
        contract_state_tree_height: usize,
        slot_value: HashOutTarget,
    ) -> Self {
        let sender_user_id = builder.add_virtual_target();
        let contract_id = builder.add_virtual_target();
        let slot_index = builder.add_virtual_target();
        let user_leaf = PsyUserLeafGadget::create_virtual(builder);

        let slot_proof = MerkleProofGadget::add_virtual_to_with_options::<H, F, D>(
            builder,
            contract_state_tree_height,
            OptionalMerkleProofGadget {
                root: None,
                value: Some(slot_value),
                index: Some(slot_index),
                siblings: None,
            },
        );
        let contract_state_root = slot_proof.root;

        let contract_proof = MerkleProofGadget::add_virtual_to_with_options::<H, F, D>(
            builder,
            global_contract_tree_height,
            OptionalMerkleProofGadget {
                root: Some(user_leaf.user_state_tree_root),
                value: Some(contract_state_root),
                index: Some(contract_id),
                siblings: None,
            },
        );

        let user_leaf_hash = user_leaf.to_hash::<H, F, D>(builder);
        let user_tree_proof = MerkleProofGadget::add_virtual_to_with_options::<H, F, D>(
            builder,
            global_user_tree_height,
            OptionalMerkleProofGadget {
                root: None,
                value: Some(user_leaf_hash),
                index: Some(sender_user_id),
                siblings: None,
            },
        );
        let user_tree_root = user_tree_proof.root;

        Self {
            sender_user_id,
            contract_id,
            slot_index,
            user_leaf,
            slot_proof,
            contract_proof,
            user_tree_proof,
            user_tree_root,
        }
    }

    pub fn set_witness<F: RichField>(&self, pw: &mut PartialWitness<F>, input: &SlotValueInContractStateWitnessInput<F>) -> anyhow::Result<()> {
        pw.set_target(self.sender_user_id, F::from_canonical_u64(input.sender_user_id))?;
        pw.set_target(self.contract_id, F::from_canonical_u64(input.contract_id))?;
        pw.set_target(self.slot_index, F::from_canonical_u64(input.slot_index))?;
        self.user_leaf.set_witness(pw, &input.user_leaf)?;
        self.slot_proof.set_witness_core_proof_q(pw, &input.slot_proof)?;
        self.contract_proof.set_witness_core_proof_q(pw, &input.contract_proof)?;
        self.user_tree_proof.set_witness_core_proof_q(pw, &input.user_tree_proof)?;
        Ok(())
    }
}
