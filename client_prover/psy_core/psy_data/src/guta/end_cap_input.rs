use kvq::traits::KVQSerializable;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::PrimeField64},
    hash::hash_types::RichField,
};
use psy_client_common::data::qhashout::QHashOut;
use psy_config::GLOBAL_USER_TREE_HEIGHT;
use psy_crypto::hash::{
    traits::{hasher::FieldQHasher, qhashable::QFieldHashable},
    tx_hash::{bytes32_to_felts, compute_user_end_cap_content_hash, hash_to_bytes},
};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::api::{ContractStateUpdate, PsyContractStateUpdateHistory, SimpleContractHeightCache, SubmitUserEndCapNonProofCoreInput};
use crate::{
    dpn::event::PsyUserEventRecord,
    qblock::cmds::deploy_contract::PsyContractSlotUpdates,
    qstore::uct_merkle_nodes::{CSTUserUpdate, CSTUserUpdateStore},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Default, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct SubmitUserEndCapNonProofInput<F: RichField> {
    pub core: SubmitUserEndCapNonProofCoreInput<F>,
    pub contract_state_updates: Vec<PsyContractStateUpdateHistory<F>>,
    #[serde(default)]
    pub events: Vec<PsyUserEventRecord<F>>,
}
impl<F: RichField> SubmitUserEndCapNonProofInput<F> {
    pub fn ensure_simple_self_consistent<H: FieldQHasher<F>>(
        &self,
        proof_public_inputs_hash: QHashOut<F>,
        contract_helper: &SimpleContractHeightCache<F>,
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

        let expected_proof_public_inputs_hash = self.core.get_proof_public_inputs_hash::<H>();
        if proof_public_inputs_hash != expected_proof_public_inputs_hash {
            anyhow::bail!(
                "invalid public inputs/state transition, left: {:?}, right: {:?}",
                proof_public_inputs_hash,
                expected_proof_public_inputs_hash
            );
        }

        let computed_leaf_hash = self.core.new_user_leaf.qfhash::<H>();
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
                "user_state_tree_root does not match the last new root, left: {}, right: {}",
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
                if x.user_contract_tree_update_proof.old_value != QHashOut::ZERO || x.contract_state_tree_updates.is_empty() {
                    return None;
                }
                match &x.contract_state_tree_updates[0] {
                    ContractStateUpdate::Positional { delta_proof } => Some((x.user_contract_tree_update_proof.index, delta_proof.siblings.len())),
                    ContractStateUpdate::IMT { update } => match update {
                        crate::qdata::imt_proof::IMTContractStateUpdate::Update { delta_proof, .. } => {
                            Some((x.user_contract_tree_update_proof.index, delta_proof.siblings.len()))
                        }
                        crate::qdata::imt_proof::IMTContractStateUpdate::Insert { predecessor_delta_proof, .. } => {
                            Some((x.user_contract_tree_update_proof.index, predecessor_delta_proof.siblings.len()))
                        }
                    },
                }
            })
            .collect()
    }
    pub fn verify_and_generate_cst_updates<H: FieldQHasher<F>>(
        &self,
        checkpoint_id: u64,
        old_user_state_tree_root: QHashOut<F>,
    ) -> anyhow::Result<CSTUserUpdate<QHashOut<F>>> {
        if self.contract_state_updates.len() == 0 {
            anyhow::bail!("contract_state_updates cannot be empty");
        }

        if self.contract_state_updates[0].user_contract_tree_update_proof.old_root != old_user_state_tree_root {
            anyhow::bail!(
                "old_user_state_tree_root does not match the first old root ({:?}, {:?})",
                self.contract_state_updates[0].user_contract_tree_update_proof.old_root,
                old_user_state_tree_root
            );
        }
        let mut injestor = CSTUserUpdateStore::<QHashOut<F>>::new();

        for csu in self.contract_state_updates.iter() {
            csu.verify_generate_cst_delta::<H>(&mut injestor)?;
        }

        let upd = injestor.into_updates(checkpoint_id, self.core.state_transition.user_id.to_canonical_u64());

        Ok(upd)
    }

    pub fn get_slot_updates(&self) -> anyhow::Result<Vec<PsyContractSlotUpdates<F>>> {
        let contract_updates = self
            .contract_state_updates
            .iter()
            .map(|x| x.get_slot_updates())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(contract_updates)
    }
}

impl<F: RichField> KVQSerializable for SubmitUserEndCapNonProofInput<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

impl SubmitUserEndCapNonProofInput<GoldilocksField> {
    pub fn get_tx_hash(&self) -> anyhow::Result<QHashOut<GoldilocksField>> {
        let user_id = self.core.new_user_leaf.user_id.to_canonical_u64();
        let start_user_leaf_hash: [u8; 32] = hash_to_bytes(&self.core.state_transition.start_user_leaf_hash);
        let end_user_leaf_hash = hash_to_bytes(&self.core.state_transition.end_user_leaf_hash);
        let checkpoint_tree_root_hash = hash_to_bytes(&self.core.state_transition.checkpoint_tree_root_hash);
        let global_user_tree_height = GLOBAL_USER_TREE_HEIGHT;
        let hash_bytes = compute_user_end_cap_content_hash(
            user_id,
            &start_user_leaf_hash,
            &end_user_leaf_hash,
            &checkpoint_tree_root_hash,
            global_user_tree_height,
        )?;
        let tx_hash = QHashOut::from_felt_slice(&bytes32_to_felts(&hash_bytes));
        Ok(tx_hash)
    }
}
