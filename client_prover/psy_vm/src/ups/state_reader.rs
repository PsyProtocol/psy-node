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
        if length == 0 {
            return Ok(Vec::new());
        }
        let n = (sub_slot_index & 0b11) as usize;
        let start_slot = sub_slot_index / 4;
        let mut result = Vec::<F>::with_capacity(length as usize);
        let n_proofs = (n + length as usize).div_ceil(4) as u64;
        for i in 0..n_proofs {
            let value = self
                .get_self_user_current_contract_state_slot_hash(F::from_canonical_u64(start_slot + i))
                .await?;
            let offset = if i == 0 { n } else { 0 };
            let count = (length as usize - result.len()).min(4 - offset);
            result.extend_from_slice(&value.0.elements[offset..offset + count]);
        }
        Ok(result)
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
        if length == 0 {
            return Ok(Vec::new());
        }
        let n = (sub_slot_index & 0b11) as usize;
        let start_slot = sub_slot_index / 4;
        let mut result = Vec::<F>::with_capacity(length as usize);
        let n_proofs = (n + length as usize).div_ceil(4) as u64;
        for i in 0..n_proofs {
            let value = self
                .get_self_user_external_contract_state_slot_hash(contract_id, F::from_canonical_u64(start_slot + i))
                .await?;
            let offset = if i == 0 { n } else { 0 };
            let count = (length as usize - result.len()).min(4 - offset);
            result.extend_from_slice(&value.0.elements[offset..offset + count]);
        }
        Ok(result)
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
        if length == 0 {
            return Ok(Vec::new());
        }
        let n = (sub_slot_index & 0b11) as usize;
        let start_slot = sub_slot_index / 4;
        let mut result = Vec::<F>::with_capacity(length as usize);
        let n_proofs = (n + length as usize).div_ceil(4) as u64;
        for i in 0..n_proofs {
            let value = self
                .get_other_user_contract_state_slot_hash(user_id, contract_id, F::from_canonical_u64(start_slot + i))
                .await?;
            let offset = if i == 0 { n } else { 0 };
            let count = (length as usize - result.len()).min(4 - offset);
            result.extend_from_slice(&value.0.elements[offset..offset + count]);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::types::{Field, PrimeField64};
    use plonky2::field::goldilocks_field::GoldilocksField;

    async fn reader_with_distinct_current_slots() -> StateReader<GoldilocksField, 2, KVQSimpleMemoryBackingStore> {
        type F = GoldilocksField;
        let mut state = UserContractState::<F>::default();
        state.checkpoint_id = F::from_canonical_u64(2);
        state.user_leaf.user_id = F::from_canonical_u64(3);
        state.contract_id = F::from_canonical_u64(7);
        let mut cmd_store = PsyCmdStoreWithCache::new(2, KVQSimpleMemoryBackingStore::new());
        cmd_store.cache.contract_leaf_cache.insert(
            7,
            psy_client_data::qdata::contract::PsyContractLeaf {
                state_tree_height: F::from_canonical_u64(2),
                ..Default::default()
            },
        );
        for leaf_id in 0..3 {
            let base = leaf_id * 4;
            cmd_store.cache.merkle_cmd_cache.insert(
                QSRMerkleCmd::GetUserContractStateTreeMerkleProof(QSRMerkleCmdGetUserContractStateTreeMerkleProof {
                    checkpoint_id: 2,
                    user_id: 3,
                    contract_id: 7,
                    height: 2,
                    leaf_id,
                }),
                MerkleProofCore {
                    root: QHashOut::default(),
                    value: QHashOut::from_values(base, base + 1, base + 2, base + 3),
                    index: leaf_id,
                    siblings: vec![QHashOut::default(); 2],
                },
            );
        }
        StateReader::new(state, cmd_store, KVQSimpleMemoryBackingStore::new()).await
    }

    #[tokio::test]
    async fn range_reads_return_exact_values_and_only_the_minimum_proofs() {
        let cases = [
            (0, 4, vec![0, 1, 2, 3], 1),
            (1, 2, vec![1, 2], 1),
            (2, 3, vec![2, 3, 4], 2),
            (3, 6, vec![3, 4, 5, 6, 7, 8], 3),
        ];
        for (offset, length, expected, expected_proofs) in cases {
            let mut reader = reader_with_distinct_current_slots().await;
            let values = reader
                .get_self_user_current_contract_state_slot_range(GoldilocksField::from_canonical_u64(offset), length)
                .await
                .unwrap();
            assert_eq!(values.iter().map(|value| value.to_canonical_u64()).collect::<Vec<_>>(), expected);
            let results = reader.to_results();
            assert_eq!(results.merkel_proofs.len(), expected_proofs);
            assert_eq!(results.state_cmds.len(), expected_proofs);
        }
    }

    #[tokio::test]
    async fn new_reader_preserves_empty_accumulators_in_results() {
        type F = GoldilocksField;

        let state = UserContractState::<F>::default();
        let cmd_store = PsyCmdStoreWithCache::new(17, KVQSimpleMemoryBackingStore::new());
        let reader: StateReader<F, 2, KVQSimpleMemoryBackingStore> =
            StateReader::new(state, cmd_store, KVQSimpleMemoryBackingStore::new()).await;

        let results = reader.to_results();
        assert_eq!(results.state, state);
        assert!(results.state_cmds.is_empty());
        assert!(results.merkel_proofs.is_empty());
    }

    #[tokio::test]
    async fn missing_cached_contract_or_proof_is_reported_without_recording_side_effects() {
        type F = GoldilocksField;

        let mut state = UserContractState::<F>::default();
        state.checkpoint_id = F::from_canonical_u64(9);
        state.user_leaf.user_id = F::from_canonical_u64(10);
        state.contract_id = F::from_canonical_u64(11);
        let cmd_store = PsyCmdStoreWithCache::new(2, KVQSimpleMemoryBackingStore::new());
        let mut reader: StateReader<F, 2, KVQSimpleMemoryBackingStore> =
            StateReader::new(state, cmd_store, KVQSimpleMemoryBackingStore::new()).await;

        assert!(reader.get_self_user_current_contract_state_slot_hash(F::ZERO).await.is_err());
        assert!(reader
            .get_self_user_external_contract_state_slot_hash(F::from_canonical_u64(12), F::ZERO)
            .await
            .is_err());
        assert!(reader
            .get_other_user_contract_state_slot_hash(F::from_canonical_u64(13), F::from_canonical_u64(14), F::ZERO)
            .await
            .is_err());
        let results = reader.to_results();
        assert!(results.state_cmds.is_empty());
        assert!(results.merkel_proofs.is_empty());
    }

    #[tokio::test]
    async fn zero_length_ranges_are_empty_for_every_contract_scope() {
        type F = GoldilocksField;
        let state = UserContractState::<F>::default();
        let cmd_store = PsyCmdStoreWithCache::new(2, KVQSimpleMemoryBackingStore::new());
        let mut reader: StateReader<F, 2, KVQSimpleMemoryBackingStore> =
            StateReader::new(state, cmd_store, KVQSimpleMemoryBackingStore::new()).await;

        assert!(reader.get_self_user_current_contract_state_slot_range(F::ZERO, 0).await.unwrap().is_empty());
        assert!(reader
            .get_self_user_external_contract_state_slot_range(F::ZERO, F::ZERO, 0)
            .await
            .unwrap()
            .is_empty());
        assert!(reader
            .get_other_user_contract_state_slot_range(F::ZERO, F::ZERO, F::ZERO, 0)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn reads_current_contract_slot_from_cached_merkle_proof_and_records_command() {
        type F = GoldilocksField;

        let mut state = UserContractState::<F>::default();
        state.checkpoint_id = F::from_canonical_u64(2);
        state.user_leaf.user_id = F::from_canonical_u64(3);
        state.contract_id = F::from_canonical_u64(7);

        let mut cmd_store = PsyCmdStoreWithCache::new(2, KVQSimpleMemoryBackingStore::new());
        cmd_store.cache.contract_leaf_cache.insert(
            7,
            psy_client_data::qdata::contract::PsyContractLeaf {
                state_tree_height: F::from_canonical_u64(2),
                ..Default::default()
            },
        );
        cmd_store.cache.contract_leaf_cache.insert(
            8,
            psy_client_data::qdata::contract::PsyContractLeaf {
                state_tree_height: F::from_canonical_u64(2),
                ..Default::default()
            },
        );
        let proof = MerkleProofCore {
            root: QHashOut::default(),
            value: QHashOut::default(),
            index: 0,
            siblings: vec![QHashOut::default(); 2],
        };
        cmd_store.cache.merkle_cmd_cache.insert(
            QSRMerkleCmd::GetUserContractStateTreeMerkleProof(QSRMerkleCmdGetUserContractStateTreeMerkleProof {
                checkpoint_id: 2,
                user_id: 3,
                contract_id: 7,
                height: 2,
                leaf_id: 0,
            }),
            proof,
        );
        cmd_store.cache.merkle_cmd_cache.insert(
            QSRMerkleCmd::GetUserContractStateTreeMerkleProof(QSRMerkleCmdGetUserContractStateTreeMerkleProof {
                checkpoint_id: 2,
                user_id: 3,
                contract_id: 7,
                height: 2,
                leaf_id: 1,
            }),
            MerkleProofCore {
                root: QHashOut::default(),
                value: QHashOut::default(),
                index: 1,
                siblings: vec![QHashOut::default(); 2],
            },
        );
        cmd_store.cache.merkle_cmd_cache.insert(
            QSRMerkleCmd::GetUserContractStateTreeMerkleProof(QSRMerkleCmdGetUserContractStateTreeMerkleProof {
                checkpoint_id: 2,
                user_id: 3,
                contract_id: 7,
                height: 2,
                leaf_id: 2,
            }),
            MerkleProofCore {
                root: QHashOut::default(),
                value: QHashOut::default(),
                index: 2,
                siblings: vec![QHashOut::default(); 2],
            },
        );
        for user_id in [3, 4] {
            for leaf_id in [0, 1] {
                cmd_store.cache.merkle_cmd_cache.insert(
                    QSRMerkleCmd::GetUserContractStateTreeMerkleProof(QSRMerkleCmdGetUserContractStateTreeMerkleProof {
                        checkpoint_id: 2,
                        user_id,
                        contract_id: 8,
                        height: 2,
                        leaf_id,
                    }),
                    MerkleProofCore {
                        root: QHashOut::default(),
                        value: QHashOut::default(),
                        index: leaf_id,
                        siblings: vec![QHashOut::default(); 2],
                    },
                );
            }
        }
        let mut reader: StateReader<F, 2, KVQSimpleMemoryBackingStore> =
            StateReader::new(state, cmd_store, KVQSimpleMemoryBackingStore::new()).await;
        assert_eq!(reader.get_self_user_current_contract_state_slot_single(F::ZERO).await.unwrap(), F::ZERO);
        assert_eq!(reader.get_self_user_current_contract_state_slot_range(F::ZERO, 4).await.unwrap(), vec![F::ZERO; 4]);
        assert!(reader.get_self_user_current_contract_state_slot_range(F::ZERO, 0).await.unwrap().is_empty());
        assert_eq!(reader.get_self_user_current_contract_state_slot_range(F::ONE, 4).await.unwrap(), vec![F::ZERO; 4]);
        assert_eq!(reader.get_self_user_current_contract_state_slot_range(F::ONE, 6).await.unwrap(), vec![F::ZERO; 6]);
        assert_eq!(
            reader
                .get_self_user_external_contract_state_slot_single(F::from_canonical_u64(8), F::ZERO)
                .await
                .unwrap(),
            F::ZERO
        );
        assert_eq!(
            reader
                .get_self_user_external_contract_state_slot_range(F::from_canonical_u64(8), F::ONE, 6)
                .await
                .unwrap(),
            vec![F::ZERO; 6]
        );
        assert_eq!(
            reader
                .get_self_user_external_contract_state_slot_range(F::from_canonical_u64(8), F::ZERO, 4)
                .await
                .unwrap(),
            vec![F::ZERO; 4]
        );
        assert_eq!(
            reader
                .get_other_user_contract_state_slot_single(F::from_canonical_u64(4), F::from_canonical_u64(8), F::ZERO)
                .await
                .unwrap(),
            F::ZERO
        );
        assert_eq!(
            reader
                .get_other_user_contract_state_slot_range(F::from_canonical_u64(4), F::from_canonical_u64(8), F::ONE, 6)
                .await
                .unwrap(),
            vec![F::ZERO; 6]
        );
        assert_eq!(
            reader
                .get_other_user_contract_state_slot_range(F::from_canonical_u64(4), F::from_canonical_u64(8), F::ZERO, 4)
                .await
                .unwrap(),
            vec![F::ZERO; 4]
        );

        let results = reader.to_results();
        assert!(results.merkel_proofs.len() >= 11);
        assert_eq!(results.state_cmds.len(), results.merkel_proofs.len());
        assert!(matches!(
            results.state_cmds[0],
            DPNStateCmd::GetSelfUserCurrentContractStateSlotHash(DPNStateCmdGetSelfUserCurrentContractStateSlotHash { slot_index })
                if slot_index == F::ZERO
        ));
    }
}
