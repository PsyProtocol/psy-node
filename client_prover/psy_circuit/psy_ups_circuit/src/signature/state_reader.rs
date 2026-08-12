use std::fmt::Debug;

use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOutTarget, RichField},
        poseidon::PoseidonHash,
    },
    iop::{target::Target, witness::PartialWitness},
    plonk::circuit_builder::CircuitBuilder,
};
use psy_common_circuit::hash::merkle::gadgets::merkle_proof::MerkleProofGadget;
use psy_network_circuit::gadgets::qdata::user_contract_state::UserContractStateGadget;
use psy_vm::dpn::ops::state_cmd::data::{
    DPNStateCmd, DPNStateCmdGetOtherUserContractStateSlotHash, DPNStateCmdGetSelfUserCurrentContractStateSlotHash,
    DPNStateCmdGetSelfUserExternalContractStateSlotHash,
};

#[derive(Debug)]
pub struct StateReaderGadget<F: RichField + Extendable<D>, const D: usize> {
    pub state: UserContractStateGadget,
    pub contract_state_tree_height: u8,
    pub merkel_proofs: Vec<MerkleProofGadget>,
    pub state_cmds: Vec<DPNStateCmd<F>>,
    // pub current_state_cmd_index: usize,
}

impl<F: RichField + Extendable<D>, const D: usize> StateReaderGadget<F, D> {
    pub fn new(builder: &mut CircuitBuilder<F, D>, contract_state_tree_height: u8) -> Self {
        let state = UserContractStateGadget::add_virtual_to(builder);
        Self {
            state,
            contract_state_tree_height,
            merkel_proofs: Vec::new(),
            state_cmds: Vec::new(),
            // current_state_cmd_index: 0,
        }
    }
    pub fn set_witness(&self, pw: &mut PartialWitness<F>, results: &psy_vm::ups::state_reader::StateReaderResults<F>) -> anyhow::Result<()> {
        self.state.set_witness(pw, &results.state)?;

        self.state_cmds
            .iter()
            .zip(results.state_cmds.iter())
            .for_each(|(state_cmd, state_cmd_reader)| {
                assert_eq!(state_cmd, state_cmd_reader);
            });

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
            // one merkle proof
            let cur = self.get_self_user_current_contract_state_slot_hash(builder, slot_index)?;
            Ok(vec![cur.elements[n]])
        } else if length < 6 {
            // two merkle proofs
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

    pub fn get_self_user_external_contract_state_slot_hash(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        contract_id: F,
        slot_index: F,
        contract_state_tree_height: u8,
    ) -> anyhow::Result<HashOutTarget> {
        let merkle_proof_gadget = MerkleProofGadget::add_virtual_to::<PoseidonHash, F, D>(builder, contract_state_tree_height as usize);

        builder.connect_hashes(merkle_proof_gadget.root, self.state.start_contract_state_root);
        tracing::info!("merkle_proof_gadget.root: {:?}", merkle_proof_gadget.root);
        tracing::info!("self.state.start_contract_state_root: {:?}", self.state.start_contract_state_root);
        let expected_slot_index_target = builder.constant(slot_index);
        builder.connect(merkle_proof_gadget.index, expected_slot_index_target);

        let value = merkle_proof_gadget.value.clone();

        self.merkel_proofs.push(merkle_proof_gadget);
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
            // one merkle proof
            let cur = self.get_self_user_external_contract_state_slot_hash(builder, contract_id, slot_index, contract_state_tree_height)?;
            Ok(vec![cur.elements[n]])
        } else if length < 6 {
            // two merkle proofs
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

    pub fn get_other_user_contract_state_slot_hash(
        &mut self,
        builder: &mut CircuitBuilder<F, D>,
        user_id: F,
        contract_id: F,
        slot_index: F,
        contract_state_tree_height: u8,
    ) -> anyhow::Result<HashOutTarget> {
        let merkle_proof_gadget = MerkleProofGadget::add_virtual_to::<PoseidonHash, F, D>(builder, contract_state_tree_height as usize);
        builder.connect_hashes(merkle_proof_gadget.root, self.state.start_contract_state_root);
        let expected_slot_index = builder.constant(slot_index);
        builder.connect(merkle_proof_gadget.index, expected_slot_index);

        let value = merkle_proof_gadget.value.clone();

        self.merkel_proofs.push(merkle_proof_gadget);
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
            // one merkle proof
            let cur = self.get_other_user_contract_state_slot_hash(builder, user_id, contract_id, slot_index, contract_state_tree_height)?;
            Ok(vec![cur.elements[n]])
        } else if length < 6 {
            // two merkle proofs
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
