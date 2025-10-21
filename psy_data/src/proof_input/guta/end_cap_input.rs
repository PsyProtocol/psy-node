use parth_core::{
    crypto::hash::
        traits::{FieldQHasher, QFieldHashable}
    ,
    felt::QFelt64,
    protocol::core_types::QFHashBase,
};

use crate::{
    proof_input::guta::SubmitUserEndCapNonProofCoreInput,
    v1::qdata::contract::{QEDContractStateUpdateHistory, PSimpleContractHeightCache},
};

#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct SubmitUserEndCapNonProofInput<F, Hash> {
    pub core: SubmitUserEndCapNonProofCoreInput<F, Hash>,
    pub contract_state_updates: Vec<QEDContractStateUpdateHistory<Hash>>,
}

impl<F: QFelt64, Hash: QFHashBase<F> + std::fmt::Debug> SubmitUserEndCapNonProofInput<F, Hash> {
    pub fn ensure_simple_self_consistent<Hasher: FieldQHasher<F, Hash>, C: PSimpleContractHeightCache<Hash>>(
        &self,
        proof_public_inputs_hash: Hash,
        contract_helper: &C,
        global_user_tree_height: u8,
    ) -> anyhow::Result<()> {
        if self.core.checkpoint_id != self.core.new_user_leaf.last_checkpoint_id {
            anyhow::bail!(
                "invalid checkpoint id, left: {}, right: {}",
                self.core.checkpoint_id,
                self.core.new_user_leaf.last_checkpoint_id
            );
        }
        if self.core.new_user_leaf.user_id != self.core.state_transition.user_id {
            anyhow::bail!(
                "inconsistent user id, left: {}, right: {}",
                self.core.new_user_leaf.user_id,
                self.core.state_transition.user_id
            );
        }

        let expected_proof_public_inputs_hash = self.core.get_proof_public_inputs_hash::<Hasher>(global_user_tree_height);
        if proof_public_inputs_hash != expected_proof_public_inputs_hash {
            anyhow::bail!(
                "invalid public inputs/state transition, left: {:?}, right: {:?}",
                proof_public_inputs_hash,
                expected_proof_public_inputs_hash
            );
        }

        let computed_leaf_hash = self.core.new_user_leaf.qfhash::<Hasher>();
        if computed_leaf_hash != self.core.state_transition.end_user_leaf_hash {
            anyhow::bail!("invalid new_user_leaf");
        }
        if self.contract_state_updates.len() == 0 {
            anyhow::bail!("contract_state_updates cannot be empty");
        }

        if self
            .contract_state_updates
            .last()
            .as_ref()
            .unwrap()
            .user_contract_tree_update_proof
            .new_root
            != self.core.new_user_leaf.user_state_tree_root
        {
            anyhow::bail!(
                "user_state_tree_root does not match the last new root, left: {:?}, right: {:?}",
                self.contract_state_updates
                    .last()
                    .as_ref()
                    .unwrap()
                    .user_contract_tree_update_proof
                    .new_root,
                self.core.new_user_leaf.user_state_tree_root
            );
        }

        for csu in self.contract_state_updates.iter() {
            csu.ensure_basic_consistency(contract_helper)?;
        }

        Ok(())
    }
    pub fn get_needed_contract_zero_hashes(&self) -> Vec<(u64, usize)> {
        self.contract_state_updates
            .iter()
            .filter_map(|x| {
                if x.user_contract_tree_update_proof.old_value == Hash::get_zero_value() && x.contract_state_tree_updates.len() != 0 {
                    Some((x.user_contract_tree_update_proof.index, x.contract_state_tree_updates[0].siblings.len()))
                } else {
                    None
                }
            })
            .collect()
    }
    /*
    pub fn verify_and_generate_cst_updates<H: FieldQHasher<F, Hash>>(&self, checkpoint_id: u64, old_user_state_tree_root: Hash) -> anyhow::Result<CSTUserUpdate<Hash>> {

        if self.contract_state_updates.len() == 0 {
            anyhow::bail!("contract_state_updates cannot be empty");
        }


        if self.contract_state_updates[0].user_contract_tree_update_proof.old_root != old_user_state_tree_root {

            anyhow::bail!("old_user_state_tree_root does not match the first old root ({:?}, {:?})",self.contract_state_updates[0].user_contract_tree_update_proof.old_root,old_user_state_tree_root);
        }
        let mut injestor = CSTUserUpdateStore::<Hash>::new();

        for csu in self.contract_state_updates.iter() {
            csu.verify_generate_cst_delta::<H>(&mut injestor)?;
        }

        let upd = injestor.into_updates(checkpoint_id, self.core.state_transition.user_id.to_canonical_u64());



        Ok(upd)
    }
    */
}
