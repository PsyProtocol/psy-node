use std::fmt::Debug;

use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::PrimeField64},
    hash::{
        hash_types::{HashOut, HashOutTarget, RichField},
        poseidon::PoseidonHash,
    },
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use psy_common_circuit::builder::{
    comparison::CircuitBuilderComparison, connect::CircuitBuilderConnectHelpers, hash::core::CircuitBuilderHashCore,
};
use psy_common_circuit::hash::merkle::gadgets::merkle_proof::MerkleProofGadget;
use psy_common_circuit::traits::CreatableTarget;
use psy_config::network_constants::{GLOBAL_CONTRACT_TREE_HEIGHT, GLOBAL_USER_TREE_HEIGHT};
use psy_crypto::hash::traits::hasher::MerkleZeroHasher;
use psy_network_circuit::gadgets::qdata::{user::PsyUserLeafGadget, user_contract_state::UserContractStateGadget};
use psy_network_circuit::gadgets::qdata::{checkpoint::PsyCheckpointLeafGadget, checkpoint_state_roots::PsyCheckpointGlobalStateRootsGadget};
use psy_vm::dpn::ops::state_cmd::data::{
    DPNStateCmd, DPNStateCmdGetOtherUserContractStateSlotHash, DPNStateCmdGetSelfUserCurrentContractStateSlotHash,
    DPNStateCmdGetSelfUserExternalContractStateSlotHash,
};

#[derive(Debug)]
pub struct StateReaderGadget<F: RichField + Extendable<D>, const D: usize> {
    pub state: UserContractStateGadget,
    /// Checkpoint-authenticated global user tree root (witness).
    pub user_tree_root: HashOutTarget,
    pub checkpoint_leaf_hash: HashOutTarget,
    pub checkpoint: Option<(PsyCheckpointLeafGadget, PsyCheckpointGlobalStateRootsGadget)>,
    pub contract_state_tree_height: u8,
    pub merkel_proofs: Vec<MerkleProofGadget>,
    pub aux_user_leaves: Vec<PsyUserLeafGadget>,
    pub state_cmds: Vec<DPNStateCmd<F>>,
}

impl<F: RichField + Extendable<D>, const D: usize> StateReaderGadget<F, D> {
    pub fn new(builder: &mut CircuitBuilder<F, D>, contract_state_tree_height: u8) -> Self {
        let state = UserContractStateGadget::add_virtual_to(builder);
        let user_tree_root = builder.add_virtual_hash();
        let checkpoint_leaf_hash = builder.add_virtual_hash();
        Self {
            state,
            user_tree_root,
            checkpoint_leaf_hash,
            checkpoint: None,
            contract_state_tree_height,
            merkel_proofs: Vec::new(),
            aux_user_leaves: Vec::new(),
            state_cmds: Vec::new(),
        }
    }

    pub fn set_witness(&self, pw: &mut PartialWitness<F>, results: &psy_vm::ups::state_reader::StateReaderResults<F>) -> anyhow::Result<()> {
        self.state.set_witness(pw, &results.state)?;
        pw.set_hash_target(self.user_tree_root, results.user_tree_root.0)?;
        if let Some((leaf, roots)) = &self.checkpoint {
            let (leaf_value, roots_value) = results.checkpoint.as_ref().ok_or_else(|| anyhow::anyhow!("missing checkpoint authentication witness"))?;
            leaf.set_witness(pw, leaf_value)?;
            roots.set_witness(pw, roots_value)?;
        }

        self.state_cmds
            .iter()
            .zip(results.state_cmds.iter())
            .for_each(|(state_cmd, state_cmd_reader)| {
                assert_eq!(state_cmd, state_cmd_reader);
            });

        anyhow::ensure!(
            self.aux_user_leaves.len() == results.aux_user_leaves.len(),
            "aux user leaf count mismatch: circuit {} vs witness {}",
            self.aux_user_leaves.len(),
            results.aux_user_leaves.len()
        );
        for (gadget, leaf) in self.aux_user_leaves.iter().zip(results.aux_user_leaves.iter()) {
            gadget.set_witness(pw, leaf)?;
        }

        anyhow::ensure!(
            self.merkel_proofs.len() == results.merkel_proofs.len(),
            "merkle proof count mismatch: circuit {} vs witness {}",
            self.merkel_proofs.len(),
            results.merkel_proofs.len()
        );
        self.merkel_proofs
            .iter()
            .zip(results.merkel_proofs.iter())
            .try_for_each(|(merkle_proof_gadget, merkle_proof)| merkle_proof_gadget.set_witness_core_proof_q_generic(pw, merkle_proof))?;
        Ok(())
    }

    pub fn get_self_user_current_contract_state_slot_hash(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        slot_index: F,
    ) -> anyhow::Result<HashOutTarget> {
        let contract_proof = MerkleProofGadget::add_virtual_to::<PoseidonHash, F, D>(builder, GLOBAL_CONTRACT_TREE_HEIGHT as usize);
        builder.connect_hashes(contract_proof.root, self.state.user_leaf.user_state_tree_root);
        builder.connect(contract_proof.index, self.state.contract_id);
        // Uninitialized UCON leaf (ZERO): start root is empty-tree root at CST height, not the leaf.
        let default_zh =
            <PoseidonHash as MerkleZeroHasher<HashOut<GoldilocksField>>>::get_zero_hash(self.contract_state_tree_height as usize);
        let default_contract_state_root = builder.constant_hash(HashOut {
            elements: [
                F::from_canonical_u64(default_zh.elements[0].to_canonical_u64()),
                F::from_canonical_u64(default_zh.elements[1].to_canonical_u64()),
                F::from_canonical_u64(default_zh.elements[2].to_canonical_u64()),
                F::from_canonical_u64(default_zh.elements[3].to_canonical_u64()),
            ],
        });
        let is_first_cst_update = builder.is_zero_hash(contract_proof.value);
        builder.connect_hashes_switch(
            is_first_cst_update,
            self.state.start_contract_state_root,
            default_contract_state_root,
            contract_proof.value,
        );
        self.merkel_proofs.push(contract_proof);
        let merkle_proof_gadget = MerkleProofGadget::add_virtual_to::<PoseidonHash, F, D>(builder, self.contract_state_tree_height as usize);
        builder.connect_hashes(merkle_proof_gadget.root, self.state.start_contract_state_root);
        let expected_slot_index_target = builder.constant(slot_index);
        builder.connect(merkle_proof_gadget.index, expected_slot_index_target);

        let value = merkle_proof_gadget.value.clone();

        self.merkel_proofs.push(merkle_proof_gadget);
        self.state_cmds.push(DPNStateCmd::GetSelfUserCurrentContractStateSlotHash(
            DPNStateCmdGetSelfUserCurrentContractStateSlotHash { slot_index },
        ));

        Ok(value)
    }

    pub fn get_self_user_current_contract_state_slot_single(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        sub_slot_index: F,
    ) -> anyhow::Result<Target> {
        let sub_slot_index = sub_slot_index.to_noncanonical_u64();
        let slot_index = F::from_canonical_u64(sub_slot_index / 4u64);
        let slot_offset = sub_slot_index % 4u64;
        let value = self.get_self_user_current_contract_state_slot_hash(builder, slot_index)?;
        Ok(value.elements[slot_offset as usize])
    }

    pub fn get_self_user_current_contract_state_slot_range(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        sub_slot_index: F,
        length: u32,
    ) -> anyhow::Result<Vec<Target>> {
        let sub_slot_index = sub_slot_index.to_noncanonical_u64();
        let slot_index = F::from_canonical_u64(sub_slot_index / 4u64);
        let n = (sub_slot_index & 0b11) as usize;
        if length == 1 {
            let cur = self.get_self_user_current_contract_state_slot_hash(builder, slot_index)?;
            Ok(vec![cur.elements[n]])
        } else if length < 6 {
            let value_0 = self.get_self_user_current_contract_state_slot_hash(builder, slot_index)?;
            let value_1 = self.get_self_user_current_contract_state_slot_hash(builder, slot_index + F::ONE)?;

            let elements = [value_0.elements, value_1.elements].concat();

            Ok(elements[n..(n + length as usize)].to_vec())
        } else {
            let n_proofs = ((length + 6) / 4) as u64;
            let sub_slot_index_mod_4 = sub_slot_index % 4;
            let start_slot = sub_slot_index / 4;
            let mut result = Vec::<Target>::with_capacity(length as usize);

            let len_minus_2_mod_4 = (length - 2) % 4;

            for i in 0..n_proofs {
                let mp_value = self.get_self_user_current_contract_state_slot_hash(builder, F::from_canonical_u64(start_slot + i))?;
                if i == 0 {
                    if sub_slot_index_mod_4 == 0 {
                        result.push(mp_value.elements[0]);
                        result.push(mp_value.elements[1]);
                        result.push(mp_value.elements[2]);
                        result.push(mp_value.elements[3]);
                    } else if sub_slot_index_mod_4 == 1 {
                        result.push(mp_value.elements[1]);
                        result.push(mp_value.elements[2]);
                        result.push(mp_value.elements[3]);
                    } else if sub_slot_index_mod_4 == 2 {
                        result.push(mp_value.elements[2]);
                        result.push(mp_value.elements[3]);
                    } else if sub_slot_index_mod_4 == 3 {
                        result.push(mp_value.elements[3]);
                    }
                } else if i == (n_proofs - 1) {
                    let slot_mask_type = (len_minus_2_mod_4 as usize) + sub_slot_index_mod_4 as usize;
                    if slot_mask_type >= 3 {
                        result.push(mp_value.elements[0]);
                    }
                    if slot_mask_type >= 4 {
                        result.push(mp_value.elements[1]);
                    }
                    if slot_mask_type >= 5 {
                        result.push(mp_value.elements[2]);
                    }
                    if slot_mask_type >= 6 {
                        result.push(mp_value.elements[3]);
                    }
                } else {
                    result.extend_from_slice(&mp_value.elements);
                }
            }
            Ok(result)
        }
    }

    /// Read a slot under another of the session user's contracts.
    ///
    /// Binds `contract_id` through the user-contract tree under
    /// `user_leaf.user_state_tree_root`, then proves the slot against that
    /// derived contract-state root (not an unbound witness root).
    pub fn get_self_user_external_contract_state_slot_hash(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        contract_id: F,
        slot_index: F,
        contract_state_tree_height: u8,
    ) -> anyhow::Result<HashOutTarget> {
        let uct_proof = MerkleProofGadget::add_virtual_to::<PoseidonHash, F, D>(builder, GLOBAL_CONTRACT_TREE_HEIGHT as usize);
        builder.connect_hashes(uct_proof.root, self.state.user_leaf.user_state_tree_root);
        let expected_contract_id = builder.constant(contract_id);
        builder.connect(uct_proof.index, expected_contract_id);

        let slot_proof = MerkleProofGadget::add_virtual_to::<PoseidonHash, F, D>(builder, contract_state_tree_height as usize);
        // Uninitialized UCON leaf (ZERO): CST proofs root at empty-tree hash, not the leaf.
        let default_zh =
            <PoseidonHash as MerkleZeroHasher<HashOut<GoldilocksField>>>::get_zero_hash(contract_state_tree_height as usize);
        let default_contract_state_root = builder.constant_hash(HashOut {
            elements: [
                F::from_canonical_u64(default_zh.elements[0].to_canonical_u64()),
                F::from_canonical_u64(default_zh.elements[1].to_canonical_u64()),
                F::from_canonical_u64(default_zh.elements[2].to_canonical_u64()),
                F::from_canonical_u64(default_zh.elements[3].to_canonical_u64()),
            ],
        });
        let is_first_cst_update = builder.is_zero_hash(uct_proof.value);
        builder.connect_hashes_switch(
            is_first_cst_update,
            slot_proof.root,
            default_contract_state_root,
            uct_proof.value,
        );
        let expected_slot_index = builder.constant(slot_index);
        builder.connect(slot_proof.index, expected_slot_index);

        let value = slot_proof.value.clone();
        self.merkel_proofs.push(uct_proof);
        self.merkel_proofs.push(slot_proof);
        self.state_cmds.push(DPNStateCmd::GetSelfUserExternalContractStateSlotHash(
            DPNStateCmdGetSelfUserExternalContractStateSlotHash {
                contract_id,
                slot_index,
                contract_state_tree_height: F::from_canonical_u8(contract_state_tree_height),
            },
        ));

        Ok(value)
    }

    pub fn get_self_user_external_contract_state_slot_single(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        contract_id: F,
        sub_slot_index: F,
        contract_state_tree_height: u8,
    ) -> anyhow::Result<Target> {
        let sub_slot_index = sub_slot_index.to_canonical_u64();
        let slot_index = F::from_canonical_u64(sub_slot_index / 4u64);
        let slot_offset = sub_slot_index % 4u64;
        let value = self.get_self_user_external_contract_state_slot_hash(builder, contract_id, slot_index, contract_state_tree_height)?;
        Ok(value.elements[slot_offset as usize])
    }

    pub fn get_self_user_external_contract_state_slot_range(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        contract_id: F,
        sub_slot_index: F,
        length: u32,
        contract_state_tree_height: u8,
    ) -> anyhow::Result<Vec<Target>> {
        let sub_slot_index = sub_slot_index.to_noncanonical_u64();
        let slot_index = F::from_canonical_u64(sub_slot_index / 4u64);
        let n = (sub_slot_index & 0b11) as usize;
        if length == 1 {
            let cur = self.get_self_user_external_contract_state_slot_hash(builder, contract_id, slot_index, contract_state_tree_height)?;
            Ok(vec![cur.elements[n]])
        } else if length < 6 {
            let value_0 = self.get_self_user_external_contract_state_slot_hash(builder, contract_id, slot_index, contract_state_tree_height)?;
            let value_1 =
                self.get_self_user_external_contract_state_slot_hash(builder, contract_id, slot_index + F::ONE, contract_state_tree_height)?;

            let elements = [value_0.elements, value_1.elements].concat();

            Ok(elements[n..(n + length as usize)].to_vec())
        } else {
            let n_proofs = ((length + 6) / 4) as u64;
            let sub_slot_index_mod_4 = sub_slot_index % 4;
            let start_slot = sub_slot_index / 4;
            let mut result = Vec::<Target>::with_capacity(length as usize);

            let len_minus_2_mod_4 = (length - 2) % 4;

            for i in 0..n_proofs {
                let mp_value = self.get_self_user_external_contract_state_slot_hash(
                    builder,
                    contract_id,
                    F::from_canonical_u64(start_slot + i),
                    contract_state_tree_height,
                )?;
                if i == 0 {
                    if sub_slot_index_mod_4 == 0 {
                        result.push(mp_value.elements[0]);
                        result.push(mp_value.elements[1]);
                        result.push(mp_value.elements[2]);
                        result.push(mp_value.elements[3]);
                    } else if sub_slot_index_mod_4 == 1 {
                        result.push(mp_value.elements[1]);
                        result.push(mp_value.elements[2]);
                        result.push(mp_value.elements[3]);
                    } else if sub_slot_index_mod_4 == 2 {
                        result.push(mp_value.elements[2]);
                        result.push(mp_value.elements[3]);
                    } else if sub_slot_index_mod_4 == 3 {
                        result.push(mp_value.elements[3]);
                    }
                } else if i == (n_proofs - 1) {
                    let slot_mask_type = (len_minus_2_mod_4 as usize) + sub_slot_index_mod_4 as usize;
                    if slot_mask_type >= 3 {
                        result.push(mp_value.elements[0]);
                    }
                    if slot_mask_type >= 4 {
                        result.push(mp_value.elements[1]);
                    }
                    if slot_mask_type >= 5 {
                        result.push(mp_value.elements[2]);
                    }
                    if slot_mask_type >= 6 {
                        result.push(mp_value.elements[3]);
                    }
                } else {
                    result.extend_from_slice(&mp_value.elements);
                }
            }
            Ok(result)
        }
    }

    /// Read a slot under `(user_id, contract_id)`.
    ///
    /// Proves the full inclusion path:
    /// global user tree → user leaf → user-contract tree → contract-state slot.
    /// Requested identities are constrained as Merkle indices; command metadata is not evidence.
    pub fn get_other_user_contract_state_slot_hash(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        user_id: F,
        contract_id: F,
        slot_index: F,
        contract_state_tree_height: u8,
    ) -> anyhow::Result<HashOutTarget> {
        if self.checkpoint.is_none() {
            let leaf = PsyCheckpointLeafGadget::create_virtual(builder);
            let roots = PsyCheckpointGlobalStateRootsGadget::create_virtual(builder);
            let roots_hash = roots.to_hash::<PoseidonHash, F, D>(builder);
            let leaf_hash = leaf.to_hash::<PoseidonHash, F, D>(builder);
            builder.connect_hashes(roots_hash, leaf.global_chain_root);
            builder.connect_hashes(leaf_hash, self.checkpoint_leaf_hash);
            builder.connect_hashes(roots.user_tree_root, self.user_tree_root);
            self.checkpoint = Some((leaf, roots));
        }
        let expected_user_id = builder.constant(user_id);
        let expected_contract_id = builder.constant(contract_id);
        let expected_slot_index = builder.constant(slot_index);

        let other_user_leaf = PsyUserLeafGadget::create_virtual(builder);
        builder.connect(other_user_leaf.user_id, expected_user_id);
        let other_user_leaf_hash = other_user_leaf.to_hash::<PoseidonHash, F, D>(builder);

        let user_tree_proof = MerkleProofGadget::add_virtual_to::<PoseidonHash, F, D>(builder, GLOBAL_USER_TREE_HEIGHT as usize);
        builder.connect_hashes(user_tree_proof.root, self.user_tree_root);
        builder.connect(user_tree_proof.index, expected_user_id);
        builder.connect_hashes(user_tree_proof.value, other_user_leaf_hash);

        let uct_proof = MerkleProofGadget::add_virtual_to::<PoseidonHash, F, D>(builder, GLOBAL_CONTRACT_TREE_HEIGHT as usize);
        builder.connect_hashes(uct_proof.root, other_user_leaf.user_state_tree_root);
        builder.connect(uct_proof.index, expected_contract_id);

        let slot_proof = MerkleProofGadget::add_virtual_to::<PoseidonHash, F, D>(builder, contract_state_tree_height as usize);
        // Uninitialized UCON leaf (ZERO): CST proofs root at empty-tree hash, not the leaf.
        let default_zh =
            <PoseidonHash as MerkleZeroHasher<HashOut<GoldilocksField>>>::get_zero_hash(contract_state_tree_height as usize);
        let default_contract_state_root = builder.constant_hash(HashOut {
            elements: [
                F::from_canonical_u64(default_zh.elements[0].to_canonical_u64()),
                F::from_canonical_u64(default_zh.elements[1].to_canonical_u64()),
                F::from_canonical_u64(default_zh.elements[2].to_canonical_u64()),
                F::from_canonical_u64(default_zh.elements[3].to_canonical_u64()),
            ],
        });
        let is_first_cst_update = builder.is_zero_hash(uct_proof.value);
        builder.connect_hashes_switch(
            is_first_cst_update,
            slot_proof.root,
            default_contract_state_root,
            uct_proof.value,
        );
        builder.connect(slot_proof.index, expected_slot_index);

        let value = slot_proof.value.clone();
        self.aux_user_leaves.push(other_user_leaf);
        self.merkel_proofs.push(user_tree_proof);
        self.merkel_proofs.push(uct_proof);
        self.merkel_proofs.push(slot_proof);
        self.state_cmds.push(DPNStateCmd::GetOtherUserContractStateSlotHash(
            DPNStateCmdGetOtherUserContractStateSlotHash {
                user_id,
                contract_id,
                slot_index,
                contract_state_tree_height: F::from_canonical_u8(contract_state_tree_height),
            },
        ));

        Ok(value)
    }

    pub fn get_other_user_contract_state_slot_single(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        user_id: F,
        contract_id: F,
        sub_slot_index: F,
        contract_state_tree_height: u8,
    ) -> anyhow::Result<Target> {
        let sub_slot_index = sub_slot_index.to_canonical_u64();
        let slot_index = F::from_canonical_u64(sub_slot_index / 4u64);
        let slot_offset = sub_slot_index % 4u64;
        let value = self.get_other_user_contract_state_slot_hash(builder, user_id, contract_id, slot_index, contract_state_tree_height)?;

        Ok(value.elements[slot_offset as usize])
    }

    pub fn get_other_user_contract_state_slot_range(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        user_id: F,
        contract_id: F,
        sub_slot_index: F,
        length: u32,
        contract_state_tree_height: u8,
    ) -> anyhow::Result<Vec<Target>> {
        let sub_slot_index = sub_slot_index.to_noncanonical_u64();
        let slot_index = F::from_canonical_u64(sub_slot_index / 4u64);
        let n = (sub_slot_index & 0b11) as usize;
        if length == 1 {
            let cur = self.get_other_user_contract_state_slot_hash(builder, user_id, contract_id, slot_index, contract_state_tree_height)?;
            Ok(vec![cur.elements[n]])
        } else if length < 6 {
            let value_0 = self.get_other_user_contract_state_slot_hash(builder, user_id, contract_id, slot_index, contract_state_tree_height)?;
            let value_1 =
                self.get_other_user_contract_state_slot_hash(builder, user_id, contract_id, slot_index + F::ONE, contract_state_tree_height)?;

            let elements = [value_0.elements, value_1.elements].concat();

            Ok(elements[n..(n + length as usize)].to_vec())
        } else {
            let n_proofs = ((length + 6) / 4) as u64;
            let sub_slot_index_mod_4 = sub_slot_index % 4;
            let start_slot = sub_slot_index / 4;
            let mut result = Vec::<Target>::with_capacity(length as usize);

            let len_minus_2_mod_4 = (length - 2) % 4;

            for i in 0..n_proofs {
                let mp_value = self.get_other_user_contract_state_slot_hash(
                    builder,
                    user_id,
                    contract_id,
                    F::from_canonical_u64(start_slot + i),
                    contract_state_tree_height,
                )?;
                if i == 0 {
                    if sub_slot_index_mod_4 == 0 {
                        result.push(mp_value.elements[0]);
                        result.push(mp_value.elements[1]);
                        result.push(mp_value.elements[2]);
                        result.push(mp_value.elements[3]);
                    } else if sub_slot_index_mod_4 == 1 {
                        result.push(mp_value.elements[1]);
                        result.push(mp_value.elements[2]);
                        result.push(mp_value.elements[3]);
                    } else if sub_slot_index_mod_4 == 2 {
                        result.push(mp_value.elements[2]);
                        result.push(mp_value.elements[3]);
                    } else if sub_slot_index_mod_4 == 3 {
                        result.push(mp_value.elements[3]);
                    }
                } else if i == (n_proofs - 1) {
                    let slot_mask_type = (len_minus_2_mod_4 as usize) + sub_slot_index_mod_4 as usize;
                    if slot_mask_type >= 3 {
                        result.push(mp_value.elements[0]);
                    }
                    if slot_mask_type >= 4 {
                        result.push(mp_value.elements[1]);
                    }
                    if slot_mask_type >= 5 {
                        result.push(mp_value.elements[2]);
                    }
                    if slot_mask_type >= 6 {
                        result.push(mp_value.elements[3]);
                    }
                } else {
                    result.extend_from_slice(&mp_value.elements);
                }
            }
            Ok(result)
        }
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig},
    };

    use super::StateReaderGadget;

    type F = GoldilocksField;
    const D: usize = 2;

    #[test]
    fn external_contract_read_binds_contract_via_user_contract_tree() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let mut reader = StateReaderGadget::new(&mut builder, 1);
        reader
            .get_self_user_external_contract_state_slot_hash(&mut builder, F::from_canonical_u64(7), F::from_canonical_u64(3), 1)
            .expect("external read");
        assert_eq!(reader.merkel_proofs.len(), 2, "UCT proof + slot proof");
        assert!(reader.aux_user_leaves.is_empty());
        assert_eq!(reader.state_cmds.len(), 1);
    }

    #[test]
    fn other_user_read_binds_user_and_contract_via_inclusion_path() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let mut reader = StateReaderGadget::new(&mut builder, 1);
        reader
            .get_other_user_contract_state_slot_hash(
                &mut builder,
                F::from_canonical_u64(10),
                F::from_canonical_u64(20),
                F::from_canonical_u64(0),
                1,
            )
            .expect("other-user read");
        assert_eq!(reader.merkel_proofs.len(), 3, "user-tree + UCT + slot proofs");
        assert_eq!(reader.aux_user_leaves.len(), 1, "other-user leaf gadget");
        assert_eq!(reader.state_cmds.len(), 1);
    }
}
