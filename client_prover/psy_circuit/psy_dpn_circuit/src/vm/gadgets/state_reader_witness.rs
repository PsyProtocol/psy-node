use plonky2::{hash::hash_types::RichField, iop::witness::Witness};
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::qdata::user::PsyUserLeaf;
use psy_crypto::hash::merkle::core::{DeltaMerkleProofCore, MerkleProofCore};
use psy_vm::{
    dpn::{ops::state_cmd::data::DPNStateCmd, vm::def::DPNFunctionCircuitDefinition},
    vm::{cfc_input::DapenContractFunctionCircuitInput, exec::PsyCmdWithInputAndWitness},
};

use super::state_readers::{CKInvokeDeferredMethodCall, StateCommandCacheKey, StateReaderGadget, StateReaderReferenceKeyType};

/*
fn some_or_error<T>(v: Option<T>) -> anyhow::Result<T> {
    match v {
        Some(x) => Ok(x),
        None => anyhow::bail!("unwrapped None value"),
    }
}
*/

#[derive(Clone, Debug, Copy, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct StateReaderGadgetWitnessBuilderState {
    pub contract_call_epoch: u32,
    pub deferred_tx_count: u32,
    pub write_epoch: u32,
}
impl StateReaderGadgetWitnessBuilderState {
    pub fn new() -> Self {
        Self {
            contract_call_epoch: 0,
            deferred_tx_count: 0,
            write_epoch: 0,
        }
    }
    pub fn inc_contract_call_epoch(&mut self) -> u32 {
        self.contract_call_epoch += 1;
        self.contract_call_epoch
    }
    pub fn inc_deferred_tx_count(&mut self) -> u32 {
        self.deferred_tx_count += 1;
        self.deferred_tx_count
    }
    pub fn inc_write_epoch(&mut self) -> u32 {
        self.write_epoch += 1;
        self.write_epoch
    }
}
// witness handlers
impl StateReaderGadget {
    fn dynamic_contract_state_tree_height<F: RichField>(cmd_witness: &PsyCmdWithInputAndWitness<F>) -> anyhow::Result<usize> {
        let height = match &cmd_witness.state_cmd {
            DPNStateCmd::GetSelfUserExternalContractStateSlotHash(c) => c.contract_state_tree_height,
            DPNStateCmd::GetSelfUserExternalContractStateSlotSingle(c) => c.contract_state_tree_height,
            DPNStateCmd::GetSelfUserExternalContractStateSlotRange(c) => c.contract_state_tree_height,
            DPNStateCmd::GetOtherUserContractStateSlotHash(c) => c.contract_state_tree_height,
            DPNStateCmd::GetOtherUserContractStateSlotSingle(c) => c.contract_state_tree_height,
            DPNStateCmd::GetOtherUserContractStateSlotRange(c) => c.contract_state_tree_height,
            DPNStateCmd::GetSelfUserExternalIMTContractStateValue(c) => c.contract_state_tree_height,
            DPNStateCmd::GetOtherUserIMTContractStateValue(c) => c.contract_state_tree_height,
            DPNStateCmd::ContainsOtherUserIMTContractStateValue(c) => c.contract_state_tree_height,
            command => anyhow::bail!("state command does not carry a dynamic contract state tree height: {:?}", command),
        } as usize;
        if !(1..=32).contains(&height) {
            anyhow::bail!("contract state tree height {} is outside supported range 1..=32", height);
        }
        Ok(height)
    }

    fn validate_dynamic_merkle_proof_height<F: RichField>(
        cmd_witness: &PsyCmdWithInputAndWitness<F>,
        proof: &MerkleProofCore<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        let expected_height = Self::dynamic_contract_state_tree_height(cmd_witness)?;
        if proof.siblings.len() != expected_height {
            anyhow::bail!(
                "contract state proof height mismatch: expected_height={} rpc_siblings_len={}",
                expected_height,
                proof.siblings.len()
            );
        }
        Ok(())
    }

    fn set_witness_for_key_dmp<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        ck: &StateCommandCacheKey,
        witness_value: &DeltaMerkleProofCore<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        let Some(reader_ref_key) = self.gadget_map.get(ck).copied() else {
            anyhow::bail!("missing state reader key for dmp witness: {:?}", ck);
        };
        match reader_ref_key.gadget_type {
            StateReaderReferenceKeyType::DeltaMerkleProof => {
                self.delta_merkle_proofs[reader_ref_key.gadget_index].set_witness::<W, F>(
                    witness,
                    F::from_noncanonical_u64(witness_value.index),
                    witness_value.old_value,
                    witness_value.new_value,
                    &witness_value.siblings,
                )?;
            }
            v => anyhow::bail!(
                "set_witness_for_key_dmp expects to set the witness for a DeltaMerkleMerkleProof gadget, but got {:?}",
                v
            ),
        }
        Ok(())
    }
    fn set_witness_for_key_mp<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        ck: &StateCommandCacheKey,
        witness_value: &MerkleProofCore<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        let Some(reader_ref_key) = self.gadget_map.get(ck).copied() else {
            anyhow::bail!("missing state reader key for mp witness: {:?}", ck);
        };
        match reader_ref_key.gadget_type {
            StateReaderReferenceKeyType::MerkleProof => {
                self.merkle_proofs[reader_ref_key.gadget_index].set_witness_generic::<W, F>(
                    witness,
                    F::from_noncanonical_u64(witness_value.index),
                    witness_value.value,
                    &witness_value.siblings,
                )?;
            }
            StateReaderReferenceKeyType::VariableHeightMerkleProof => {
                self.variable_height_merkle_proofs[reader_ref_key.gadget_index].set_witness_generic::<W, F>(
                    witness,
                    F::from_noncanonical_u64(witness_value.index),
                    witness_value.value,
                    &witness_value.siblings,
                )?;
            }
            v => anyhow::bail!(
                "set_witness_for_key_dmp expects to set the witness for a DeltaMerkleMerkleProof gadget, but got {:?}",
                v
            ),
        }
        Ok(())
    }
    fn set_witness_for_key_imt_contains_mp<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        ck: &StateCommandCacheKey,
        witness_value: &MerkleProofCore<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        let Some(reader_ref_key) = self.gadget_map.get(ck).copied() else {
            anyhow::bail!("missing state reader key for imt contains witness: {:?}", ck);
        };
        match reader_ref_key.gadget_type {
            StateReaderReferenceKeyType::IMTContains => {
                self.imt_contains_proofs[reader_ref_key.gadget_index].set_witness_generic::<W, F>(
                    witness,
                    F::from_noncanonical_u64(witness_value.index),
                    witness_value.value,
                    &witness_value.siblings,
                )?;
            }
            v => anyhow::bail!("set_witness_for_key_imt_contains_mp expects IMTContains gadget, but got {:?}", v),
        }
        Ok(())
    }
    fn set_witness_for_key_user_leaf<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        ck: &StateCommandCacheKey,
        witness_value: &PsyUserLeaf<F>,
    ) -> anyhow::Result<()> {
        let reader_ref_key = self.gadget_map.get(ck);
        if reader_ref_key.is_some() {
            let reader_ref_key = reader_ref_key.unwrap().to_owned();
            match reader_ref_key.gadget_type {
                StateReaderReferenceKeyType::UserLeaf => {
                    self.user_leaves[reader_ref_key.gadget_index].set_witness(witness, witness_value)?;
                }
                v => anyhow::bail!(
                    "set_witness_for_key_user_leaf expects to set the witness for a UserLeaf gadget, but got {:?}",
                    v
                ),
            }
        }
        Ok(())
    }
    fn set_witness_single<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        def_cmd: &DPNStateCmd<u64>,
        cmd_witness: &PsyCmdWithInputAndWitness<F>,
        wb_state: &mut StateReaderGadgetWitnessBuilderState,
    ) -> anyhow::Result<()> {
        match &def_cmd {
            DPNStateCmd::SetContractStateSlotHash(c) => {
                let ck = StateCommandCacheKey::new_write_current_contract_slot(c.slot_index, c.condition, wb_state.write_epoch);
                self.set_witness_for_key_dmp(witness, &ck, cmd_witness.witness.get_delta_merkle_proof_ref())?;
                wb_state.inc_write_epoch();
            }
            DPNStateCmd::SetContractStateSlotSingle(c) => {
                let ck = StateCommandCacheKey::new_write_current_contract_single(c.sub_slot_index, c.condition, wb_state.write_epoch);
                self.set_witness_for_key_dmp(witness, &ck, cmd_witness.witness.get_delta_merkle_proof_ref())?;
                wb_state.inc_write_epoch();
            }
            DPNStateCmd::SetContractStateSlotRange(c) => {
                let dmps = cmd_witness.witness.get_delta_merkle_proof_array_ref();
                for (i, p) in dmps.iter().enumerate() {
                    let ck = StateCommandCacheKey::new_write_current_contract_range(
                        c.sub_slot_index,
                        c.condition,
                        c.value.len() as u32,
                        i as u64,
                        wb_state.write_epoch,
                    );
                    self.set_witness_for_key_dmp(witness, &ck, p)?;
                }
                wb_state.inc_write_epoch();
            }
            DPNStateCmd::InvokeExternalContractFunctionSync(_c) => todo!(),
            DPNStateCmd::InvokeExternalContractFunctionDeferred(c) => {
                let ck = StateCommandCacheKey::InvokeDeferredMethodCall(CKInvokeDeferredMethodCall::new(
                    c.condition,
                    c.contract_id,
                    c.method_id,
                    wb_state.deferred_tx_count,
                    &c.input_args,
                ));
                self.set_witness_for_key_dmp(
                    witness,
                    &ck,
                    &cmd_witness.witness.get_invoke_external_function_deferred_ref().insertion_proof,
                )?;
                wb_state.inc_deferred_tx_count();
            }
            DPNStateCmd::GetContractLeaf(c) => {
                let ck = StateCommandCacheKey::new_get_contract_leaf(c.contract_id);

                if let Some(ref_key) = self.gadget_map.get(&ck) {
                    match ref_key.gadget_type {
                        StateReaderReferenceKeyType::ContractLeaf => {
                            let index = ref_key.gadget_index;
                            let contract_leaf_witness = cmd_witness.witness.get_contract_leaf_ref();

                            self.contract_leaf_requests[index].set_witness(witness, &contract_leaf_witness.contract_leaf)?;

                            self.contract_leaf_proofs[index].set_witness_generic::<W, F>(
                                witness,
                                F::from_noncanonical_u64(contract_leaf_witness.contract_tree_proof.index),
                                contract_leaf_witness.contract_tree_proof.value,
                                &contract_leaf_witness.contract_tree_proof.siblings,
                            )?;
                        }
                        v => anyhow::bail!("GetContractLeaf expects ContractLeaf reference key type, but got {:?}", v),
                    }
                }
            }
            DPNStateCmd::GetSelfUserCurrentContractStateSlotHash(c) => {
                let ck = StateCommandCacheKey::new_read_current_contract_slot(c.slot_index, wb_state.write_epoch);
                self.set_witness_for_key_mp(witness, &ck, cmd_witness.witness.get_merkle_proof_ref())?;
            }
            DPNStateCmd::GetSelfUserCurrentContractStateSlotSingle(c) => {
                let ck = StateCommandCacheKey::new_read_current_contract_single(c.sub_slot_index, wb_state.write_epoch);
                self.set_witness_for_key_mp(witness, &ck, cmd_witness.witness.get_merkle_proof_ref())?;
            }
            DPNStateCmd::GetSelfUserCurrentContractStateSlotRange(c) => {
                let mps = cmd_witness.witness.get_merkle_proof_array_ref();
                for (i, p) in mps.iter().enumerate() {
                    let ck = StateCommandCacheKey::new_read_current_contract_range(c.sub_slot_index, c.length, i as u64, wb_state.write_epoch);
                    self.set_witness_for_key_mp(witness, &ck, p)?;
                }
            }
            DPNStateCmd::GetSelfUserExternalContractStateSlotHash(c) => {
                let read_root_ck = StateCommandCacheKey::new_read_self_user_external_contract_root(c.contract_id, wb_state.contract_call_epoch);

                let proofs = cmd_witness.witness.get_merkle_proof_array_ref();
                self.set_witness_for_key_mp(witness, &read_root_ck, &proofs[0])?;

                let contract_state_tree_ck =
                    StateCommandCacheKey::new_read_self_user_external_contract_slot(c.contract_id, c.slot_index, wb_state.contract_call_epoch);

                Self::validate_dynamic_merkle_proof_height(cmd_witness, &proofs[1])?;
                self.set_witness_for_key_mp(witness, &contract_state_tree_ck, &proofs[1])?;
            }
            DPNStateCmd::GetSelfUserExternalContractStateSlotSingle(c) => {
                let read_root_ck = StateCommandCacheKey::new_read_self_user_external_contract_root(c.contract_id, wb_state.contract_call_epoch);

                let contract_state_tree_ck =
                    StateCommandCacheKey::new_read_self_user_external_contract_single(c.contract_id, c.sub_slot_index, wb_state.contract_call_epoch);

                let proofs = cmd_witness.witness.get_merkle_proof_array_ref();

                self.set_witness_for_key_mp(witness, &read_root_ck, &proofs[0])?;

                Self::validate_dynamic_merkle_proof_height(cmd_witness, &proofs[1])?;
                self.set_witness_for_key_mp(witness, &contract_state_tree_ck, &proofs[1])?;
            }
            DPNStateCmd::GetSelfUserExternalContractStateSlotRange(c) => {
                let read_root_ck = StateCommandCacheKey::new_read_self_user_external_contract_root(c.contract_id, wb_state.contract_call_epoch);

                let proofs = cmd_witness.witness.get_merkle_proof_array_ref();
                self.set_witness_for_key_mp(witness, &read_root_ck, &proofs[0])?;

                for (i, p) in proofs.iter().skip(1).enumerate() {
                    let contract_state_tree_ck = StateCommandCacheKey::new_read_self_user_external_contract_range(
                        c.contract_id,
                        c.sub_slot_index,
                        wb_state.contract_call_epoch,
                        c.length,
                        i as u64,
                    );

                    Self::validate_dynamic_merkle_proof_height(cmd_witness, p)?;
                    self.set_witness_for_key_mp(witness, &contract_state_tree_ck, p)?;
                }
            }
            DPNStateCmd::GetOtherUserContractStateSlotHash(c) => {
                /*
                let user_tree_ck =
                StateCommandCacheKey::new_read_other_user_leaf_hash(
                    user_target_id
                );
                let user_leaf_ck =
                    StateCommandCacheKey::new_read_other_user_leaf(
                        user_target_id
                    );*/
                let user_target_id = c.user_id;
                let contract_target_id = c.contract_id;
                let slot_target_id = c.slot_index;

                let user_tree_ck = StateCommandCacheKey::new_read_other_user_leaf_hash(user_target_id);

                let user_leaf_ck = StateCommandCacheKey::new_read_other_user_leaf(user_target_id);

                let uct_ck = StateCommandCacheKey::new_read_other_user_contract_root(user_target_id, contract_target_id);

                let cst_ck = StateCommandCacheKey::new_read_other_user_contract_slot(user_target_id, contract_target_id, slot_target_id);
                let read_witness = cmd_witness.witness.get_read_other_contract_state_ref();

                self.set_witness_for_key_mp(witness, &user_tree_ck, &read_witness.user_leaf_witness.user_tree_proof)?;
                self.set_witness_for_key_user_leaf(witness, &user_leaf_ck, &read_witness.user_leaf_witness.user_leaf)?;
                self.set_witness_for_key_mp(witness, &uct_ck, &read_witness.contract_state_proof)?;
                Self::validate_dynamic_merkle_proof_height(cmd_witness, &read_witness.state_slot_proofs[0])?;
                self.set_witness_for_key_mp(witness, &cst_ck, &read_witness.state_slot_proofs[0])?;
            }
            DPNStateCmd::GetOtherUserContractStateSlotSingle(c) => {
                let user_target_id = c.user_id;
                let contract_target_id = c.contract_id;
                let sub_slot_target_id = c.sub_slot_index;

                let user_tree_ck = StateCommandCacheKey::new_read_other_user_leaf_hash(user_target_id);
                let user_leaf_ck = StateCommandCacheKey::new_read_other_user_leaf(user_target_id);
                let uct_ck = StateCommandCacheKey::new_read_other_user_contract_root(user_target_id, contract_target_id);
                let cst_ck = StateCommandCacheKey::new_read_other_user_contract_single(
                    user_target_id,
                    contract_target_id,
                    sub_slot_target_id,
                    wb_state.write_epoch,
                );

                let read_witness = cmd_witness.witness.get_read_other_contract_state_ref();

                self.set_witness_for_key_mp(witness, &user_tree_ck, &read_witness.user_leaf_witness.user_tree_proof)?;
                self.set_witness_for_key_user_leaf(witness, &user_leaf_ck, &read_witness.user_leaf_witness.user_leaf)?;
                self.set_witness_for_key_mp(witness, &uct_ck, &read_witness.contract_state_proof)?;
                Self::validate_dynamic_merkle_proof_height(cmd_witness, &read_witness.state_slot_proofs[0])?;
                self.set_witness_for_key_mp(witness, &cst_ck, &read_witness.state_slot_proofs[0])?;
            }
            DPNStateCmd::GetOtherUserContractStateSlotRange(c) => {
                let user_target_id = c.user_id;
                let contract_target_id = c.contract_id;

                let user_tree_ck = StateCommandCacheKey::new_read_other_user_leaf_hash(user_target_id);

                let user_leaf_ck = StateCommandCacheKey::new_read_other_user_leaf(user_target_id);

                let uct_ck = StateCommandCacheKey::new_read_other_user_contract_root(user_target_id, contract_target_id);
                let read_witness = cmd_witness.witness.get_read_other_contract_state_ref();

                self.set_witness_for_key_mp(witness, &user_tree_ck, &read_witness.user_leaf_witness.user_tree_proof)?;
                self.set_witness_for_key_user_leaf(witness, &user_leaf_ck, &read_witness.user_leaf_witness.user_leaf)?;
                self.set_witness_for_key_mp(witness, &uct_ck, &read_witness.contract_state_proof)?;

                for (i, mp) in read_witness.state_slot_proofs.iter().enumerate() {
                    let cst_ck = StateCommandCacheKey::new_read_other_user_contract_range(
                        user_target_id,
                        contract_target_id,
                        c.sub_slot_index,
                        c.length,
                        i as u64,
                    );

                    Self::validate_dynamic_merkle_proof_height(cmd_witness, mp)?;
                    self.set_witness_for_key_mp(witness, &cst_ck, mp)?;
                }
            }
            DPNStateCmd::GetCheckpointLeafStats(c) => {
                let ck = StateCommandCacheKey::new_get_checkpoint_stats(c.checkpoint_id);

                if let Some(ref_key) = self.gadget_map.get(&ck) {
                    match ref_key.gadget_type {
                        StateReaderReferenceKeyType::CheckpointStats => {
                            let index = ref_key.gadget_index;

                            let checkpoint_witness = cmd_witness.witness.get_checkpoint_leaf_stats_ref();

                            self.checkpoint_stats_requests[index].set_witness(witness, &checkpoint_witness.checkpoint_leaf_stats)?;

                            self.checkpoint_state_roots_requests[index].set_witness(witness, &checkpoint_witness.checkpoint_state_roots)?;

                            self.historical_proofs[index].set_witness_generic::<W, F>(
                                witness,
                                F::from_noncanonical_u64(checkpoint_witness.checkpoint_historical_proof.index),
                                checkpoint_witness.checkpoint_historical_proof.value,
                                &checkpoint_witness.checkpoint_historical_proof.siblings,
                            )?;
                        }
                        v => anyhow::bail!("GetCheckpointLeafStats expects CheckpointStats reference key type, but got {:?}", v),
                    }
                }
            }
            DPNStateCmd::GetGlobalStateRoots(c) => {
                let ck = StateCommandCacheKey::new_get_checkpoint_stats(c.checkpoint_id);

                let Some(ref_key) = self.gadget_map.get(&ck).copied() else {
                    anyhow::bail!("missing state reader key for GetGlobalStateRoots witness: {:?}", ck);
                };
                match ref_key.gadget_type {
                    StateReaderReferenceKeyType::CheckpointStats => {
                        let index = ref_key.gadget_index;

                        let global_roots_witness = cmd_witness.witness.get_checkpoint_global_state_roots_ref();

                        self.checkpoint_stats_requests[index].set_witness(witness, &global_roots_witness.checkpoint_leaf_stats)?;
                        self.checkpoint_state_roots_requests[index].set_witness(witness, &global_roots_witness.checkpoint_state_roots)?;

                        self.historical_proofs[index].set_witness_generic::<W, F>(
                            witness,
                            F::from_noncanonical_u64(global_roots_witness.checkpoint_historical_proof.index),
                            global_roots_witness.checkpoint_historical_proof.value,
                            &global_roots_witness.checkpoint_historical_proof.siblings,
                        )?;
                    }
                    v => anyhow::bail!("GetGlobalStateRoots expects CheckpointStats reference key type, but got {:?}", v),
                }
            }
            DPNStateCmd::ClearEntireTree(c) => {
                let clear_tree_witness = cmd_witness.witness.get_clear_entire_tree_ref();

                if let Some(reader_ref_key) = self.gadget_map.get(&StateCommandCacheKey::new_clear_entire_tree_with_condition(
                    c.condition,
                    wb_state.write_epoch,
                )) {
                    match reader_ref_key.gadget_type {
                        StateReaderReferenceKeyType::ClearEntireTree => {
                            let index = reader_ref_key.gadget_index;
                            self.clear_entire_tree_requests[index].set_witness(
                                witness,
                                clear_tree_witness.state_tree_height,
                                clear_tree_witness.zero_hash,
                            )?;
                        }
                        v => anyhow::bail!("ClearEntireTree expects ClearEntireTree reference key type, but got {:?}", v),
                    }
                }

                wb_state.inc_write_epoch();
            }
            DPNStateCmd::SetIMTContractStateValue(c) => {
                let ck = StateCommandCacheKey::new_write_imt_current_contract(c.condition, 0, wb_state.write_epoch);
                let imt_set_witness = cmd_witness.witness.get_imt_set_ref();

                let Some(reader_ref_key) = self.gadget_map.get(&ck).copied() else {
                    anyhow::bail!("missing state reader key for imt set witness: {:?}", ck);
                };
                match reader_ref_key.gadget_type {
                    StateReaderReferenceKeyType::IMTSet => {
                        let index = reader_ref_key.gadget_index;
                        let gadget = &self.imt_set_requests[index];

                        witness.set_target(gadget.is_insert.target, if imt_set_witness.is_insert { F::ONE } else { F::ZERO })?;
                        witness.set_target(
                            gadget.insert_has_predecessor.target,
                            if imt_set_witness.insert_has_predecessor { F::ONE } else { F::ZERO },
                        )?;

                        gadget.update_old_leaf.set_witness(witness, &imt_set_witness.old_leaf)?;
                        gadget.update_new_leaf.set_witness(witness, &imt_set_witness.new_leaf)?;
                        gadget
                            .update_delta_proof
                            .set_witness_core_proof_q(witness, &imt_set_witness.delta_merkle_proofs[0])?;

                        if imt_set_witness.delta_merkle_proofs.len() < 2 {
                            anyhow::bail!(
                                "IMT set witness expects at least 2 delta merkle proofs, got {}",
                                imt_set_witness.delta_merkle_proofs.len()
                            );
                        }
                        let predecessor_proof = &imt_set_witness.delta_merkle_proofs[0];
                        let new_leaf_proof = &imt_set_witness.delta_merkle_proofs[1];

                        gadget
                            .insert_predecessor_old_leaf
                            .set_witness(witness, &imt_set_witness.predecessor_old_leaf)?;
                        gadget
                            .insert_predecessor_new_leaf
                            .set_witness(witness, &imt_set_witness.predecessor_new_leaf)?;
                        gadget.insert_new_leaf.set_witness(witness, &imt_set_witness.new_leaf)?;
                        gadget
                            .insert_predecessor_delta_proof
                            .set_witness_core_proof_q(witness, predecessor_proof)?;
                        gadget.insert_new_leaf_delta_proof.set_witness_core_proof_q(witness, new_leaf_proof)?;
                    }
                    v => anyhow::bail!("SetIMTContractStateValue expects IMTSet reference key type, but got {:?}", v),
                }
                wb_state.inc_write_epoch();
            }
            DPNStateCmd::GetSelfUserCurrentIMTContractStateValue(c) => {
                let ck = StateCommandCacheKey::new_read_imt_current_contract(c.key, wb_state.write_epoch);
                let read_witness = cmd_witness.witness.get_imt_read_ref();
                let Some(reader_ref_key) = self.gadget_map.get(&ck).copied() else {
                    anyhow::bail!("missing state reader key for imt current read witness: {:?}", ck);
                };
                match reader_ref_key.gadget_type {
                    StateReaderReferenceKeyType::IMTRead => {
                        let gadget = &self.imt_read_requests[reader_ref_key.gadget_index];
                        gadget.merkle_proof.set_witness_generic::<W, F>(
                            witness,
                            F::from_noncanonical_u64(read_witness.merkle_proof.index),
                            read_witness.merkle_proof.value,
                            &read_witness.merkle_proof.siblings,
                        )?;
                        gadget.leaf.set_witness(witness, &read_witness.leaf_preimage)?;
                    }
                    v => anyhow::bail!("IMT current read expects IMTRead key type, but got {:?}", v),
                }
            }
            DPNStateCmd::ContainsSelfUserCurrentIMTContractStateValue(c) => {
                let ck = StateCommandCacheKey::new_read_imt_contains_current_contract(c.key, wb_state.write_epoch);
                let contains_witness = cmd_witness.witness.get_imt_contains_ref();
                self.set_witness_for_key_imt_contains_mp(witness, &ck, &contains_witness.merkle_proof)?;
                let Some(reader_ref_key) = self.gadget_map.get(&ck).copied() else {
                    anyhow::bail!("missing state reader key for imt contains witness: {:?}", ck);
                };
                match reader_ref_key.gadget_type {
                    StateReaderReferenceKeyType::IMTContains => {
                        let index = reader_ref_key.gadget_index;
                        self.imt_contains_leaf_requests[index].set_witness(witness, &contains_witness.leaf_preimage)?;
                        witness.set_target(
                            self.imt_contains_exists_targets[index],
                            if contains_witness.exists { F::ONE } else { F::ZERO },
                        )?;
                    }
                    v => anyhow::bail!("IMT contains expects IMTContains key type, but got {:?}", v),
                }
            }
            DPNStateCmd::GetSelfUserExternalIMTContractStateValue(c) => {
                let read_witness = cmd_witness.witness.get_imt_self_user_external_read_ref();
                let uct_ck = StateCommandCacheKey::new_read_self_user_external_contract_root(c.contract_id, wb_state.contract_call_epoch);
                self.set_witness_for_key_mp(witness, &uct_ck, &read_witness.contract_tree_proof)?;
                let imt_ck = StateCommandCacheKey::new_read_imt_self_user_external_contract(c.contract_id, c.key, wb_state.contract_call_epoch);
                let Some(reader_ref_key) = self.gadget_map.get(&imt_ck).copied() else {
                    anyhow::bail!("missing state reader key for imt external read witness: {:?}", imt_ck);
                };
                match reader_ref_key.gadget_type {
                    StateReaderReferenceKeyType::IMTExternalRead => {
                        let gadget = &self.imt_external_read_requests[reader_ref_key.gadget_index];
                        gadget.contract_tree_proof.set_witness_generic::<W, F>(
                            witness,
                            F::from_noncanonical_u64(read_witness.contract_tree_proof.index),
                            read_witness.contract_tree_proof.value,
                            &read_witness.contract_tree_proof.siblings,
                        )?;
                        Self::validate_dynamic_merkle_proof_height(cmd_witness, &read_witness.state_slot_proof)?;
                        gadget.state_slot_proof.set_witness_generic::<W, F>(
                            witness,
                            F::from_noncanonical_u64(read_witness.state_slot_proof.index),
                            read_witness.state_slot_proof.value,
                            &read_witness.state_slot_proof.siblings,
                        )?;
                        gadget.leaf.set_witness(witness, &read_witness.leaf_preimage)?;
                    }
                    v => anyhow::bail!("IMT external read expects IMTExternalRead key type, but got {:?}", v),
                }
            }
            DPNStateCmd::GetOtherUserIMTContractStateValue(c) => {
                let read_witness = cmd_witness.witness.get_imt_other_user_read_ref();

                let user_tree_ck = StateCommandCacheKey::new_read_other_user_leaf_hash(c.user_id);
                let user_leaf_ck = StateCommandCacheKey::new_read_other_user_leaf(c.user_id);
                let uct_ck = StateCommandCacheKey::new_read_other_user_contract_root(c.user_id, c.contract_id);
                let imt_ck = StateCommandCacheKey::new_read_imt_other_user_contract(c.user_id, c.contract_id, c.key, wb_state.write_epoch);

                self.set_witness_for_key_mp(witness, &user_tree_ck, &read_witness.user_leaf_witness.user_tree_proof)?;
                self.set_witness_for_key_user_leaf(witness, &user_leaf_ck, &read_witness.user_leaf_witness.user_leaf)?;
                self.set_witness_for_key_mp(witness, &uct_ck, &read_witness.contract_state_proof)?;
                let Some(reader_ref_key) = self.gadget_map.get(&imt_ck).copied() else {
                    anyhow::bail!("missing state reader key for imt other-user read witness: {:?}", imt_ck);
                };
                match reader_ref_key.gadget_type {
                    StateReaderReferenceKeyType::IMTOtherUserRead => {
                        let gadget = &self.imt_other_user_read_requests[reader_ref_key.gadget_index];
                        Self::validate_dynamic_merkle_proof_height(cmd_witness, &read_witness.state_slot_proof)?;
                        gadget.state_slot_proof.set_witness_generic::<W, F>(
                            witness,
                            F::from_noncanonical_u64(read_witness.state_slot_proof.index),
                            read_witness.state_slot_proof.value,
                            &read_witness.state_slot_proof.siblings,
                        )?;
                        gadget.leaf.set_witness(witness, &read_witness.leaf_preimage)?;
                    }
                    v => anyhow::bail!("IMT other-user read expects IMTOtherUserRead key type, but got {:?}", v),
                }
            }
            DPNStateCmd::ContainsOtherUserIMTContractStateValue(c) => {
                let read_witness = cmd_witness.witness.get_imt_contains_other_user_ref();

                let user_tree_ck = StateCommandCacheKey::new_read_other_user_leaf_hash(c.user_id);
                let user_leaf_ck = StateCommandCacheKey::new_read_other_user_leaf(c.user_id);
                let uct_ck = StateCommandCacheKey::new_read_other_user_contract_root(c.user_id, c.contract_id);
                let imt_ck = StateCommandCacheKey::new_imt_contains_other_user_contract(c.user_id, c.contract_id, c.key, wb_state.write_epoch);

                self.set_witness_for_key_mp(witness, &user_tree_ck, &read_witness.user_leaf_witness.user_tree_proof)?;
                self.set_witness_for_key_user_leaf(witness, &user_leaf_ck, &read_witness.user_leaf_witness.user_leaf)?;
                self.set_witness_for_key_mp(witness, &uct_ck, &read_witness.contract_state_proof)?;
                let Some(reader_ref_key) = self.gadget_map.get(&imt_ck).copied() else {
                    anyhow::bail!("missing state reader key for imt contains other-user witness: {:?}", imt_ck);
                };
                match reader_ref_key.gadget_type {
                    StateReaderReferenceKeyType::IMTContainsOtherUser => {
                        let gadget = &self.imt_contains_other_user_requests[reader_ref_key.gadget_index];
                        Self::validate_dynamic_merkle_proof_height(cmd_witness, &read_witness.state_slot_proof)?;
                        gadget.state_slot_proof.set_witness_generic::<W, F>(
                            witness,
                            F::from_noncanonical_u64(read_witness.state_slot_proof.index),
                            read_witness.state_slot_proof.value,
                            &read_witness.state_slot_proof.siblings,
                        )?;
                        gadget.leaf.set_witness(witness, &read_witness.leaf_preimage)?;
                        witness.set_target(gadget.exists, if read_witness.exists { F::ONE } else { F::ZERO })?;
                    }
                    v => anyhow::bail!("IMT contains other-user expects IMTContainsOtherUser key type, but got {:?}", v),
                }
            }
        };
        Ok(())
    }
    pub fn set_command_witnesses<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        cmd_witnesses: &[PsyCmdWithInputAndWitness<F>],
        fn_def: &DPNFunctionCircuitDefinition,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            fn_def.state_commands.len() == cmd_witnesses.len(),
            "state command/witness count mismatch: commands={} witnesses={}",
            fn_def.state_commands.len(),
            cmd_witnesses.len()
        );
        let mut wb = StateReaderGadgetWitnessBuilderState::new();

        for (command_index, (dsc, ciw)) in fn_def.state_commands.iter().zip(cmd_witnesses.iter()).enumerate() {
            tracing::debug!(
                target: "state_reader_witness_dump",
                "set_witness dsc: {}, ciw: {}",
                serde_json::to_string_pretty(dsc).unwrap(),
                serde_json::to_string_pretty(ciw).unwrap()
            );
            self.set_witness_single(witness, dsc, ciw, &mut wb).map_err(|err| {
                anyhow::anyhow!(
                    "failed to set state command witness at index {}: command={} error={:#}",
                    command_index,
                    serde_json::to_string(dsc).unwrap_or_else(|_| format!("{:?}", dsc)),
                    err
                )
            })?;
        }
        Ok(())
    }

    pub fn set_witness<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        input: &DapenContractFunctionCircuitInput<F>,
        fn_def: &DPNFunctionCircuitDefinition,
    ) -> anyhow::Result<()> {
        self.set_command_witnesses(witness, &input.cmd_witnesses, fn_def)
    }
}
