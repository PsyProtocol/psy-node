use std::fmt::Debug;

use kvq::memory::simple::KVQSimpleMemoryBackingStore;
use maybe_async::maybe_async;
use plonky2::{field::extension::Extendable, hash::hash_types::RichField};
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::{
    models::user::contract_state_tree::UserContractStateTreeId,
    qdata::user_contract_state::UserContractState,
    qstore::imm::{
        cache::PsyCmdStoreWithCache,
        cmd::{QSRCmdGetContractLeafData, QSRMerkleCmd, QSRMerkleCmdGetUserContractStateTreeMerkleProof},
        cmd_processor::{PsyReadCommandProcessorSync, PsyReadCommandProcessorSyncMut},
    },
    traits::qdatastore::qmetadata::QMetaDataStoreReaderSync,
};
use psy_crypto::hash::merkle::core::MerkleProofCore;
use serde::{Deserialize, Serialize};

use crate::dpn::ops::state_cmd::data::{
    DPNStateCmd, DPNStateCmdGetOtherUserContractStateSlotHash, DPNStateCmdGetSelfUserCurrentContractStateSlotHash,
    DPNStateCmdGetSelfUserExternalContractStateSlotHash,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "F: Serialize + serde::de::DeserializeOwned")]
pub struct StateReaderResults<F: RichField> {
    pub state: UserContractState<F>,
    pub state_cmds: Vec<DPNStateCmd<F>>,
    pub merkel_proofs: Vec<MerkleProofCore<QHashOut<F>>>,
}

#[derive(Debug)]
pub struct StateReader<
    F: RichField + Extendable<D>,
    const D: usize,
    R: PsyReadCommandProcessorSync<F> + psy_client_data::qstore::imm::cmd_processor::QUserIdManager + QMetaDataStoreReaderSync<F> + Send + Sync,
> {
    pub state: UserContractState<F>,
    pub cmd_store: PsyCmdStoreWithCache<F, R>,
    pub state_tree_store: KVQSimpleMemoryBackingStore,
    pub merkel_proofs: Vec<MerkleProofCore<QHashOut<F>>>,
    pub state_cmds: Vec<DPNStateCmd<F>>,
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async(?Send))]
impl<
        F: RichField + Extendable<D>,
        const D: usize,
        R: PsyReadCommandProcessorSync<F> + psy_client_data::qstore::imm::cmd_processor::QUserIdManager + QMetaDataStoreReaderSync<F> + Send + Sync,
    > StateReader<F, D, R>
{
    pub async fn new(state: UserContractState<F>, cmd_store: PsyCmdStoreWithCache<F, R>, state_tree_store: KVQSimpleMemoryBackingStore) -> Self {
        Self {
            state,
            cmd_store,
            state_tree_store,
            merkel_proofs: Vec::new(),
            state_cmds: Vec::new(),
        }
    }

    pub fn to_results(&self) -> StateReaderResults<F> {
        StateReaderResults {
            state: self.state.clone(),
            state_cmds: self.state_cmds.clone(),
            merkel_proofs: self.merkel_proofs.clone(),
        }
    }

    async fn get_user_contract_state_tree_merkle_proof(
        &mut self,
        checkpoint_id: F,
        user_id: F,
        contract_id: F,
        slot_index: F,
    ) -> anyhow::Result<MerkleProofCore<QHashOut<F>>> {
        let checkpoint_id = checkpoint_id.to_canonical_u64();
        let user_id = user_id.to_canonical_u64();
        let contract_id = contract_id.to_canonical_u64();
        let slot_index = slot_index.to_canonical_u64();

        let state_tree_height = self
            .cmd_store
            .resolve_get_contract_leaf_mut(&QSRCmdGetContractLeafData { contract_id })
            .await?
            .state_tree_height
            .to_canonical_u64() as u8;
        let id = UserContractStateTreeId::<KVQSimpleMemoryBackingStore>::new(user_id, contract_id as u32, state_tree_height);
        let base_mp = self
            .cmd_store
            .resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetUserContractStateTreeMerkleProof(
                QSRMerkleCmdGetUserContractStateTreeMerkleProof {
                    checkpoint_id,
                    user_id,
                    contract_id: contract_id as u32,
                    height: state_tree_height,
                    leaf_id: slot_index,
                },
            ))
            .await?;
        let base_mp_gf =
            serde_json::from_str::<MerkleProofCore<QHashOut<plonky2::field::goldilocks_field::GoldilocksField>>>(&serde_json::to_string(&base_mp)?)?;
        id.injest_merkle_proof_ucs(&mut self.state_tree_store, checkpoint_id, &base_mp_gf)?;
        let merkel_proof = id.get_leaf_ucs(&self.state_tree_store, checkpoint_id, slot_index)?;
        let merkel_proof_f = serde_json::from_str::<MerkleProofCore<QHashOut<F>>>(&serde_json::to_string(&merkel_proof)?)?;
        Ok(merkel_proof_f)
    }
    pub async fn get_self_user_current_contract_state_slot_hash(&mut self, slot_index: F) -> anyhow::Result<QHashOut<F>> {
        let merkle_proof = self
            .get_user_contract_state_tree_merkle_proof(self.state.checkpoint_id, self.state.user_leaf.user_id, self.state.contract_id, slot_index)
            .await?;
        tracing::info!("merkle_proof: {}", serde_json::to_string_pretty(&merkle_proof)?);

        let value = merkle_proof.value.clone();

        self.merkel_proofs.push(merkle_proof);
        self.state_cmds.push(DPNStateCmd::GetSelfUserCurrentContractStateSlotHash(
            DPNStateCmdGetSelfUserCurrentContractStateSlotHash { slot_index },
        ));

        Ok(value)
    }

    pub async fn get_self_user_current_contract_state_slot_single(&mut self, sub_slot_index: F) -> anyhow::Result<F> {
        let sub_slot_index = sub_slot_index.to_noncanonical_u64();
        let slot_index = F::from_canonical_u64(sub_slot_index / 4u64);
        let slot_offset = sub_slot_index % 4u64;
        let value = self.get_self_user_current_contract_state_slot_hash(slot_index).await?;
        Ok(value.0.elements[slot_offset as usize])
    }

    pub async fn get_self_user_current_contract_state_slot_range(&mut self, sub_slot_index: F, length: u32) -> anyhow::Result<Vec<F>> {
        let sub_slot_index = sub_slot_index.to_noncanonical_u64();
        let slot_index = F::from_canonical_u64(sub_slot_index / 4u64);
        let n = (sub_slot_index & 0b11) as usize;
        if length == 1 {
            // one merkle proof
            let cur = self.get_self_user_current_contract_state_slot_hash(slot_index).await?;
            Ok(vec![cur.0.elements[n]])
        } else if length < 6 {
            // two merkle proofs
            let value_0 = self.get_self_user_current_contract_state_slot_hash(slot_index).await?;
            let value_1 = self.get_self_user_current_contract_state_slot_hash(slot_index + F::ONE).await?;

            let elements = [value_0.0.elements, value_1.0.elements].concat();

            Ok(elements[n..(n + length as usize)].to_vec())
        } else {
            let n_proofs = ((length + 6) / 4) as u64;
            let sub_slot_index_mod_4 = sub_slot_index % 4;
            let start_slot = sub_slot_index / 4;
            let mut result = Vec::<F>::with_capacity(length as usize);

            let len_minus_2_mod_4 = (length - 2) % 4;

            for i in 0..n_proofs {
                let mp_value = self
                    .get_self_user_current_contract_state_slot_hash(F::from_canonical_u64(start_slot + i))
                    .await?;
                if i == 0 {
                    if sub_slot_index_mod_4 == 0 {
                        result.push(mp_value.0.elements[0]);
                        result.push(mp_value.0.elements[1]);
                        result.push(mp_value.0.elements[2]);
                        result.push(mp_value.0.elements[3]);
                    } else if sub_slot_index_mod_4 == 1 {
                        result.push(mp_value.0.elements[1]);
                        result.push(mp_value.0.elements[2]);
                        result.push(mp_value.0.elements[3]);
                    } else if sub_slot_index_mod_4 == 2 {
                        result.push(mp_value.0.elements[2]);
                        result.push(mp_value.0.elements[3]);
                    } else if sub_slot_index_mod_4 == 3 {
                        result.push(mp_value.0.elements[3]);
                    }
                } else if i == (n_proofs - 1) {
                    let slot_mask_type = (len_minus_2_mod_4 as usize) + sub_slot_index_mod_4 as usize;
                    if slot_mask_type >= 3 {
                        result.push(mp_value.0.elements[0]);
                    }
                    if slot_mask_type >= 4 {
                        result.push(mp_value.0.elements[1]);
                    }
                    if slot_mask_type >= 5 {
                        result.push(mp_value.0.elements[2]);
                    }
                    if slot_mask_type >= 6 {
                        result.push(mp_value.0.elements[3]);
                    }
                } else {
                    result.extend_from_slice(&mp_value.0.elements);
                }
            }
            Ok(result)
        }
    }

    pub async fn get_self_user_external_contract_state_slot_hash(&mut self, contract_id: F, slot_index: F) -> anyhow::Result<QHashOut<F>> {
        let merkle_proof = self
            .get_user_contract_state_tree_merkle_proof(self.state.checkpoint_id, self.state.user_leaf.user_id, contract_id, slot_index)
            .await?;

        let value = merkle_proof.value.clone();

        let state_tree_height = merkle_proof.siblings.len() as u8;

        self.merkel_proofs.push(merkle_proof);
        self.state_cmds.push(DPNStateCmd::GetSelfUserExternalContractStateSlotHash(
            DPNStateCmdGetSelfUserExternalContractStateSlotHash {
                contract_id,
                slot_index,
                contract_state_tree_height: F::from_canonical_u8(state_tree_height),
            },
        ));

        Ok(value)
    }

    pub async fn get_self_user_external_contract_state_slot_single(&mut self, contract_id: F, sub_slot_index: F) -> anyhow::Result<F> {
        let sub_slot_index = sub_slot_index.to_canonical_u64();
        let slot_index = F::from_canonical_u64(sub_slot_index / 4u64);
        let slot_offset = sub_slot_index % 4u64;
        let value = self.get_self_user_external_contract_state_slot_hash(contract_id, slot_index).await?;
        Ok(value.0.elements[slot_offset as usize])
    }

    pub async fn get_self_user_external_contract_state_slot_range(
        &mut self,
        contract_id: F,
        sub_slot_index: F,
        length: u32,
    ) -> anyhow::Result<Vec<F>> {
        let sub_slot_index = sub_slot_index.to_noncanonical_u64();
        let slot_index = F::from_canonical_u64(sub_slot_index / 4u64);
        let n = (sub_slot_index & 0b11) as usize;
        if length == 1 {
            // one merkle proof
            let cur = self.get_self_user_external_contract_state_slot_hash(contract_id, slot_index).await?;
            Ok(vec![cur.0.elements[n]])
        } else if length < 6 {
            // two merkle proofs
            let value_0 = self.get_self_user_external_contract_state_slot_hash(contract_id, slot_index).await?;
            let value_1 = self
                .get_self_user_external_contract_state_slot_hash(contract_id, slot_index + F::ONE)
                .await?;

            let elements = [value_0.0.elements, value_1.0.elements].concat();

            Ok(elements[n..(n + length as usize)].to_vec())
        } else {
            let n_proofs = ((length + 6) / 4) as u64;
            let sub_slot_index_mod_4 = sub_slot_index % 4;
            let start_slot = sub_slot_index / 4;
            let mut result = Vec::<F>::with_capacity(length as usize);

            let len_minus_2_mod_4 = (length - 2) % 4;

            for i in 0..n_proofs {
                let mp_value = self
                    .get_self_user_external_contract_state_slot_hash(contract_id, F::from_canonical_u64(start_slot + i))
                    .await?;
                if i == 0 {
                    if sub_slot_index_mod_4 == 0 {
                        result.push(mp_value.0.elements[0]);
                        result.push(mp_value.0.elements[1]);
                        result.push(mp_value.0.elements[2]);
                        result.push(mp_value.0.elements[3]);
                    } else if sub_slot_index_mod_4 == 1 {
                        result.push(mp_value.0.elements[1]);
                        result.push(mp_value.0.elements[2]);
                        result.push(mp_value.0.elements[3]);
                    } else if sub_slot_index_mod_4 == 2 {
                        result.push(mp_value.0.elements[2]);
                        result.push(mp_value.0.elements[3]);
                    } else if sub_slot_index_mod_4 == 3 {
                        result.push(mp_value.0.elements[3]);
                    }
                } else if i == (n_proofs - 1) {
                    let slot_mask_type = (len_minus_2_mod_4 as usize) + sub_slot_index_mod_4 as usize;
                    if slot_mask_type >= 3 {
                        result.push(mp_value.0.elements[0]);
                    }
                    if slot_mask_type >= 4 {
                        result.push(mp_value.0.elements[1]);
                    }
                    if slot_mask_type >= 5 {
                        result.push(mp_value.0.elements[2]);
                    }
                    if slot_mask_type >= 6 {
                        result.push(mp_value.0.elements[3]);
                    }
                } else {
                    result.extend_from_slice(&mp_value.0.elements);
                }
            }
            Ok(result)
        }
    }

    pub async fn get_other_user_contract_state_slot_hash(&mut self, user_id: F, contract_id: F, slot_index: F) -> anyhow::Result<QHashOut<F>> {
        let merkle_proof = self
            .get_user_contract_state_tree_merkle_proof(self.state.checkpoint_id, user_id, contract_id, slot_index)
            .await?;
        let state_tree_height = merkle_proof.siblings.len() as u8;

        let value = merkle_proof.value.clone();

        self.merkel_proofs.push(merkle_proof);
        self.state_cmds.push(DPNStateCmd::GetOtherUserContractStateSlotHash(
            DPNStateCmdGetOtherUserContractStateSlotHash {
                user_id,
                contract_id,
                slot_index,
                contract_state_tree_height: F::from_canonical_u8(state_tree_height),
            },
        ));

        Ok(value)
    }

    pub async fn get_other_user_contract_state_slot_single(&mut self, user_id: F, contract_id: F, sub_slot_index: F) -> anyhow::Result<F> {
        let sub_slot_index = sub_slot_index.to_canonical_u64();
        let slot_index = F::from_canonical_u64(sub_slot_index / 4u64);
        let slot_offset = sub_slot_index % 4u64;
        let value = self.get_other_user_contract_state_slot_hash(user_id, contract_id, slot_index).await?;

        Ok(value.0.elements[slot_offset as usize])
    }

    pub async fn get_other_user_contract_state_slot_range(
        &mut self,
        user_id: F,
        contract_id: F,
        sub_slot_index: F,
        length: u32,
    ) -> anyhow::Result<Vec<F>> {
        let sub_slot_index = sub_slot_index.to_noncanonical_u64();
        let slot_index = F::from_canonical_u64(sub_slot_index / 4u64);
        let n = (sub_slot_index & 0b11) as usize;
        if length == 1 {
            // one merkle proof
            let cur = self.get_other_user_contract_state_slot_hash(user_id, contract_id, slot_index).await?;
            Ok(vec![cur.0.elements[n]])
        } else if length < 6 {
            // two merkle proofs
            let value_0 = self.get_other_user_contract_state_slot_hash(user_id, contract_id, slot_index).await?;
            let value_1 = self
                .get_other_user_contract_state_slot_hash(user_id, contract_id, slot_index + F::ONE)
                .await?;

            let elements = [value_0.0.elements, value_1.0.elements].concat();

            Ok(elements[n..(n + length as usize)].to_vec())
        } else {
            let n_proofs = ((length + 6) / 4) as u64;
            let sub_slot_index_mod_4 = sub_slot_index % 4;
            let start_slot = sub_slot_index / 4;
            let mut result = Vec::<F>::with_capacity(length as usize);

            let len_minus_2_mod_4 = (length - 2) % 4;

            for i in 0..n_proofs {
                let mp_value = self
                    .get_other_user_contract_state_slot_hash(user_id, contract_id, F::from_canonical_u64(start_slot + i))
                    .await?;
                if i == 0 {
                    if sub_slot_index_mod_4 == 0 {
                        result.push(mp_value.0.elements[0]);
                        result.push(mp_value.0.elements[1]);
                        result.push(mp_value.0.elements[2]);
                        result.push(mp_value.0.elements[3]);
                    } else if sub_slot_index_mod_4 == 1 {
                        result.push(mp_value.0.elements[1]);
                        result.push(mp_value.0.elements[2]);
                        result.push(mp_value.0.elements[3]);
                    } else if sub_slot_index_mod_4 == 2 {
                        result.push(mp_value.0.elements[2]);
                        result.push(mp_value.0.elements[3]);
                    } else if sub_slot_index_mod_4 == 3 {
                        result.push(mp_value.0.elements[3]);
                    }
                } else if i == (n_proofs - 1) {
                    let slot_mask_type = (len_minus_2_mod_4 as usize) + sub_slot_index_mod_4 as usize;
                    if slot_mask_type >= 3 {
                        result.push(mp_value.0.elements[0]);
                    }
                    if slot_mask_type >= 4 {
                        result.push(mp_value.0.elements[1]);
                    }
                    if slot_mask_type >= 5 {
                        result.push(mp_value.0.elements[2]);
                    }
                    if slot_mask_type >= 6 {
                        result.push(mp_value.0.elements[3]);
                    }
                } else {
                    result.extend_from_slice(&mp_value.0.elements);
                }
            }
            Ok(result)
        }
    }
}
