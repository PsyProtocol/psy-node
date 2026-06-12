use parth_core::{
    crypto::hash::{merkle_proof::MerkleProofCore, traits::MerkleZeroHasher},
    pgoldilocks::QHashOut,
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_data::v1::qdata::user::PQEDUserLeaf;
use psy_plonky2_basic_helpers::builder::{comparison::CircuitBuilderComparison, select::CircuitBuilderSelectHelpers};
use psy_plonky2_common_circuits::{
    hash::merkle::gadgets::merkle_proof::{MerkleProofGadget, OptionalMerkleProofGadget},
    traits::CreatableTarget,
};

use crate::gadgets::qdata::user::QEDUserLeafGadget;

#[derive(Clone, Debug)]
pub struct SlotValueInContractStateWitnessInput<F: RichField> {
    pub sender_user_id: u64,
    pub contract_id: u64,
    pub slot_index: u64,
    pub user_leaf: PQEDUserLeaf<F, QHashOut<F>>,
    pub slot_proof: MerkleProofCore<QHashOut<F>>,
    pub contract_proof: MerkleProofCore<QHashOut<F>>,
    pub user_tree_proof: MerkleProofCore<QHashOut<F>>,
}

#[derive(Debug)]
pub struct SlotValueInContractStateGadget {
    pub sender_user_id: Target,
    pub contract_id: Target,
    pub slot_index: Target,
    pub user_leaf: QEDUserLeafGadget,
    pub slot_proof: MerkleProofGadget,
    pub contract_proof: MerkleProofGadget,
    pub user_tree_proof: MerkleProofGadget,
    pub user_tree_root: HashOutTarget,
}

impl SlotValueInContractStateGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F> + MerkleZeroHasher<HashOut<F>>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        global_user_tree_height: usize,
        global_contract_tree_height: usize,
        contract_state_tree_height: usize,
    ) -> Self {
        let sender_user_id = builder.add_virtual_target();
        let contract_id = builder.add_virtual_target();
        let slot_index = builder.add_virtual_target();
        let user_leaf = QEDUserLeafGadget::create_virtual(builder);

        let slot_proof = MerkleProofGadget::add_virtual_to_with_options::<H, F, D>(
            builder,
            contract_state_tree_height,
            OptionalMerkleProofGadget {
                root: None,
                value: None,
                index: None,
                siblings: None,
            },
        );
        builder.connect(slot_proof.index, slot_index);

        let zero_root = builder.constant_hash(HashOut::ZERO);
        let default_contract_state_root = builder.constant_hash(H::get_zero_hash(contract_state_tree_height));
        let is_contract_state_tree_empty = builder.is_equal_hash(slot_proof.root, default_contract_state_root);

        let contract_proof_value = builder.select_hash(is_contract_state_tree_empty, zero_root, slot_proof.root);
        let contract_proof = MerkleProofGadget::add_virtual_to_with_options::<H, F, D>(
            builder,
            global_contract_tree_height,
            OptionalMerkleProofGadget {
                root: None,
                value: None,
                index: None,
                siblings: None,
            },
        );
        builder.connect_hashes(contract_proof.value, contract_proof_value);
        builder.connect(contract_proof.index, contract_id);

        // 🛡 Key constraint: the contract tree proof must authenticate against
        // the user_state_tree_root stored in the user leaf. This locks the
        // slot_proof's root (which becomes contract_proof.value) into the user
        // leaf, preventing a free-witness attack on contract state roots.
        builder.connect_hashes(contract_proof.root, user_leaf.user_state_tree_root);

        let user_leaf_hash = user_leaf.to_hash::<H, F, D>(builder);

        let default_user_state_tree_root = builder.constant_hash(H::get_zero_hash(global_contract_tree_height));
        let is_state_root_default = builder.is_equal_hash(user_leaf.user_state_tree_root, default_user_state_tree_root);
        let is_balance_default = builder.is_zero(user_leaf.balance);
        let is_new_user = builder.and(is_state_root_default, is_balance_default);

        let user_tree_proof_value = builder.select_hash(is_new_user, zero_root, user_leaf_hash);

        let user_tree_proof = MerkleProofGadget::add_virtual_to_with_options::<H, F, D>(
            builder,
            global_user_tree_height,
            OptionalMerkleProofGadget {
                root: None,
                value: None,
                index: None,
                siblings: None,
            },
        );
        builder.connect_hashes(user_tree_proof.value, user_tree_proof_value);
        builder.connect(user_tree_proof.index, sender_user_id);

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

    pub fn set_witness<F: RichField>(&self, pw: &mut impl Witness<F>, input: &SlotValueInContractStateWitnessInput<F>) -> anyhow::Result<()> {
        pw.set_target(self.sender_user_id, F::from_canonical_u64(input.sender_user_id))?;
        pw.set_target(self.contract_id, F::from_canonical_u64(input.contract_id))?;
        pw.set_target(self.slot_index, F::from_canonical_u64(input.slot_index))?;
        self.user_leaf.set_witness(pw, &input.user_leaf)?;
        self.slot_proof.set_witness_core_proof_q_generic(pw, &input.slot_proof)?;
        self.contract_proof.set_witness_core_proof_q_generic(pw, &input.contract_proof)?;
        self.user_tree_proof.set_witness_core_proof_q_generic(pw, &input.user_tree_proof)?;
        Ok(())
    }
}
