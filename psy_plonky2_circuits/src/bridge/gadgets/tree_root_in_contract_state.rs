use parth_core::{
    crypto::hash::{merkle_proof::MerkleProofCore, traits::MerkleZeroHasher},
    pgoldilocks::QHashOut,
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::witness::Witness,
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_data::v1::qdata::user::PQEDUserLeaf;
use serde::Serialize;

use super::slot_value_in_contract_state::{SlotValueInContractStateGadget, SlotValueInContractStateWitnessInput};

#[derive(Debug, Serialize)]
pub struct TreeRootInContractStateWitnessInput<F: RichField> {
    pub owner_user_id: u64,
    pub contract_id: u64,
    pub user_leaf: PQEDUserLeaf<F, QHashOut<F>>,
    pub slot0_proof: MerkleProofCore<QHashOut<F>>,
    pub slot1_proof: MerkleProofCore<QHashOut<F>>,
    pub contract_proof: MerkleProofCore<QHashOut<F>>,
    pub user_tree_proof: MerkleProofCore<QHashOut<F>>,
}

impl<F: RichField> TreeRootInContractStateWitnessInput<F> {
    pub fn to_slot_witnesses(&self) -> [SlotValueInContractStateWitnessInput<F>; 2] {
        [
            SlotValueInContractStateWitnessInput {
                sender_user_id: self.owner_user_id,
                contract_id: self.contract_id,
                slot_index: 0,
                user_leaf: self.user_leaf.clone(),
                slot_proof: self.slot0_proof.clone(),
                contract_proof: self.contract_proof.clone(),
                user_tree_proof: self.user_tree_proof.clone(),
            },
            SlotValueInContractStateWitnessInput {
                sender_user_id: self.owner_user_id,
                contract_id: self.contract_id,
                slot_index: 1,
                user_leaf: self.user_leaf.clone(),
                slot_proof: self.slot1_proof.clone(),
                contract_proof: self.contract_proof.clone(),
                user_tree_proof: self.user_tree_proof.clone(),
            },
        ]
    }
}

#[derive(Debug)]
pub struct TreeRootInContractStateGadget {
    pub slot0: SlotValueInContractStateGadget,
    pub slot1: SlotValueInContractStateGadget,
    pub user_tree_root: HashOutTarget,
    pub tree_root: [HashOutTarget; 2],
}

impl TreeRootInContractStateGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F> + MerkleZeroHasher<HashOut<F>>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        global_user_tree_height: usize,
        global_contract_tree_height: usize,
        contract_state_tree_height: usize,
    ) -> Self {
        let slot0 = SlotValueInContractStateGadget::add_virtual_to::<H, F, D>(
            builder,
            global_user_tree_height,
            global_contract_tree_height,
            contract_state_tree_height,
        );
        let slot1 = SlotValueInContractStateGadget::add_virtual_to::<H, F, D>(
            builder,
            global_user_tree_height,
            global_contract_tree_height,
            contract_state_tree_height,
        );

        builder.connect_hashes(slot0.slot_proof.root, slot1.slot_proof.root);
        builder.connect_hashes(slot0.user_tree_root, slot1.user_tree_root);

        let zero = builder.zero();
        let one = builder.one();
        builder.connect(slot0.slot_index, zero);
        builder.connect(slot1.slot_index, one);

        // Storage layout for deposit/withdrawal tree contracts:
        // slot0 = [root[0], root[1], root[2], root[3]]
        // slot1 = [root[4], root[5], root[6], root[7]]
        let tree_root = [
            HashOutTarget {
                elements: [
                    slot0.slot_proof.value.elements[0],
                    slot0.slot_proof.value.elements[1],
                    slot0.slot_proof.value.elements[2],
                    slot0.slot_proof.value.elements[3],
                ],
            },
            HashOutTarget {
                elements: [
                    slot1.slot_proof.value.elements[0],
                    slot1.slot_proof.value.elements[1],
                    slot1.slot_proof.value.elements[2],
                    slot1.slot_proof.value.elements[3],
                ],
            },
        ];

        // Range-check each element to u32 (8 elements total across 2 slots)
        for slot_hash in &tree_root {
            for &elem in &slot_hash.elements {
                builder.range_check(elem, 32);
            }
        }

        let user_tree_root = slot0.user_tree_root;

        Self {
            slot0,
            slot1,
            user_tree_root,
            tree_root,
        }
    }

    pub fn set_witness<F: RichField>(&self, pw: &mut impl Witness<F>, input: &TreeRootInContractStateWitnessInput<F>) -> anyhow::Result<()> {
        let slot_witnesses = input.to_slot_witnesses();
        self.slot0.set_witness(pw, &slot_witnesses[0])?;
        self.slot1.set_witness(pw, &slot_witnesses[1])?;
        Ok(())
    }
}
