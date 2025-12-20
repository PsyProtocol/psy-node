use std::{collections::HashMap, sync::Arc};

use parth_common::{memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore, tree_sync::traits::sync_local_tree_from_remote};
use parth_core::{
    crypto::hash::traits::{FieldQHasher, QFieldHashable}, felt::QFelt64, protocol::core_types::{Q256BitHash, QFHashBase}
};
use psy_data::{
    guta::stats::GUTAStats,
    proof_input::guta::{end_cap_input::SubmitUserEndCapNonProofInput, SubmitUserEndCapNonProofCoreInput},
    v1::qdata::{
        contract::{DashMapContractHeightCache, PSimpleContractHeightCache, QEDContractStateUpdateHistory},
        user::PQEDUserLeaf,
        user_end_cap_result::PUPSEndCapResultCompact,
    },
};

use crate::api::data_fetcher::{PsyContractStateTreeDataSyncHelper, PsyUserContractDataFetcher, PsyUserContractTreeDataSyncHelper};

#[derive(Clone)]
pub struct DPContractUpdate<Hash> {
    pub contract_id: u32,
    pub leaves: Vec<(u64, Hash)>,
}

#[derive(Clone)]
pub struct DPLocalUser<Hasher, Hash: Copy + PartialEq + Default + std::fmt::Debug, F> {
    pub user_id: u64,
    pub uct: SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
    pub contract_trees: HashMap<u32, SimpleMemoryMerkleRecorderStore<Hasher, Hash>>,
    pub user_leaf: PQEDUserLeaf<F, Hash>,
}

impl<Hasher: FieldQHasher<F, Hash>, Hash: Q256BitHash + QFHashBase<F> + std::fmt::Debug, F: QFelt64> DPLocalUser<Hasher, Hash, F> {
    pub fn new(global_contract_tree_height: u8, user_leaf: PQEDUserLeaf<F, Hash>) -> Self {
        Self {
            user_id: user_leaf.user_id.to_u64_value(),
            uct: SimpleMemoryMerkleRecorderStore::new(global_contract_tree_height),
            contract_trees: HashMap::new(),
            user_leaf,
        }
    }
    pub fn new_empty(user_id: u64, global_contract_tree_height: u8) -> Self {
        Self {
            user_id,
            uct: SimpleMemoryMerkleRecorderStore::new(global_contract_tree_height),
            contract_trees: HashMap::new(),
            user_leaf: PQEDUserLeaf {
                public_key: Hash::get_zero_value(),
                user_state_tree_root: Hasher::get_zero_hash(global_contract_tree_height as usize),
                balance: F::ZERO_VALUE,
                nonce: F::ZERO_VALUE,
                last_checkpoint_id: F::ZERO_VALUE,
                event_index: F::ZERO_VALUE,
                user_id: F::from_u64_value(user_id),
            },
        }
    }
    async fn ensure_contract_heights_in_cache_or_fetch<DF: PsyUserContractDataFetcher<F, Hash> + Send + Sync + 'static>(
        data_fetcher: Arc<DF>,
        contract_height_cache: &DashMapContractHeightCache<Hash>,
        contract_ids: &[u32],
    ) -> anyhow::Result<()> {
        let missing_heights = contract_ids
            .iter()
            .filter_map(|c| if contract_height_cache.contains_key(*c) { None } else { Some(*c) })
            .collect::<Vec<u32>>();
        if !missing_heights.is_empty() {
            let fetched_heights: Vec<u8> = data_fetcher
                .df_get_contract_state_heights(u64::MAX, missing_heights.iter().map(|x| *x as u64).collect())
                .await?;
            //println!("Fetched missing contract heights for contracts: {:?} heights: {:?}", missing_heights, fetched_heights);
            for (contract_id, height) in missing_heights.iter().zip(fetched_heights.iter()) {
                contract_height_cache.add_contract(*contract_id, *height, Hasher::get_zero_hash(*height as usize));
            }
        }
        Ok(())
    }
    pub async fn sync_to_latest<DF: PsyUserContractDataFetcher<F, Hash> + Send + Sync + 'static>(
        &mut self,
        data_fetcher: Arc<DF>,
        contract_height_cache: &DashMapContractHeightCache<Hash>,
        checkpoint_id: u64,
        user_leaf: PQEDUserLeaf<F, Hash>,
    ) -> anyhow::Result<()> {
        if user_leaf.user_id.to_u64_value() != self.user_id {
            return Err(anyhow::anyhow!(
                "Mismatched user ids in sync: expected {}, got {}",
                self.user_id,
                user_leaf.user_id.to_u64_value()
            ));
        }
        if self.user_leaf.qfhash::<Hasher>() == user_leaf.qfhash::<Hasher>() {
            //println!("User leaf hash matches, no sync needed");
            return Ok(());
        }
        let needs_state_sync = user_leaf.user_state_tree_root != self.uct.get_root();
        self.user_leaf = user_leaf;
        if !needs_state_sync {
            //println!("User state tree root matches, no state sync needed");
            return Ok(());
        }
        self.uct.commit_changes();
        let remote_tree = PsyUserContractTreeDataSyncHelper {
            user_id: self.user_id,
            checkpoint_id,
            fetcher: data_fetcher.clone(),
            _phantom_f: std::marker::PhantomData,
            _phantom_hash: std::marker::PhantomData,
        };
        sync_local_tree_from_remote(&mut self.uct, &remote_tree).await?;
        /* 

        self.uct_commit_changes();
        let modified_contract_ids = self
            .uct
            .get_leaves_slow_all()
            .iter().filter_map(|(index, root)|  {
                let index_u32 = *index as u32;
                let tree = self.contract_trees.get(&index_u32);
                if tree.is_none() {
                    Some(index_u32)
                }else if tree.unwrap().get_root() != *root {
                    println!("Contract tree root mismatch for contract id {}, local: {:?}, remote: {:?}, syncing to remote...", index_u32, tree.unwrap().get_root(), *root);
                    Some(index_u32)
                } else {
                    None
                }
            })
            .collect::<Vec<u32>>();
        */
        let modified_contract_ids = self.uct.get_changed_leaves().iter().map(|(ind, _)| *ind as u32).collect::<Vec<u32>>();
        self.uct.commit_changes();

        Self::ensure_contract_heights_in_cache_or_fetch::<DF>(data_fetcher.clone(), contract_height_cache, &modified_contract_ids).await?;
        for contract_id in modified_contract_ids {
            if let Some(contract_tree) = self.contract_trees.get_mut(&contract_id) {
                sync_local_tree_from_remote(
                    contract_tree,
                    &PsyContractStateTreeDataSyncHelper {
                        user_id: self.user_id,
                        contract_id: contract_id as u64,
                        state_tree_height: contract_height_cache.get_contract_height(contract_id)?,
                        checkpoint_id,
                        fetcher: data_fetcher.clone(),
                        _phantom_f: std::marker::PhantomData,
                        _phantom_hash: std::marker::PhantomData,
                    },
                )
                .await?;
                contract_tree.commit_changes();
                self.uct.set_leaf(contract_id as u64, contract_tree.get_root());
            } else {
                let height = contract_height_cache.get_contract_height(contract_id)?;
                let mut new_contract_tree = SimpleMemoryMerkleRecorderStore::new(height);
                sync_local_tree_from_remote(
                    &mut new_contract_tree,
                    &PsyContractStateTreeDataSyncHelper {
                        user_id: self.user_id,
                        contract_id: contract_id as u64,
                        state_tree_height: height,
                        checkpoint_id,
                        fetcher: data_fetcher.clone(),
                        _phantom_f: std::marker::PhantomData,
                        _phantom_hash: std::marker::PhantomData,
                    },
                )
                .await?;
                new_contract_tree.commit_changes();
                self.uct.set_leaf(contract_id as u64, new_contract_tree.get_root());
                self.contract_trees.insert(contract_id, new_contract_tree);
            }
        }
        self.user_leaf.user_state_tree_root = self.uct.get_root();
        self.uct.commit_changes();

        Ok(())
    }
    pub fn _ensure_user_leaf_synced(&mut self) {
        let uct_root = self.uct.get_root();
        self.user_leaf.user_state_tree_root = uct_root;
    }

    pub fn run_ups(
        &mut self,
        contract_height_cache: &DashMapContractHeightCache<Hash>,
        latest_checkpoint_id: u64,
        latest_checkpoint_tree_root: Hash,
        txs: &[DPContractUpdate<Hash>],
    ) -> anyhow::Result<SubmitUserEndCapNonProofInput<F, Hash>> {
        let start_leaf_hash = if self.user_leaf.last_checkpoint_id == F::ZERO_VALUE && self.user_leaf.nonce == F::ZERO_VALUE {
            Hash::get_zero_value()
        } else {
            self.user_leaf.qfhash::<Hasher>()
        };
        let mut state_history = Vec::with_capacity(txs.len());
        let mut total_slots_modified = 0;
        for tx in txs {
            if !self.contract_trees.contains_key(&tx.contract_id) {
                self.contract_trees.insert(
                    tx.contract_id,
                    SimpleMemoryMerkleRecorderStore::new(contract_height_cache.get_contract_height(tx.contract_id)?),
                );
            }
            let contract_tree = self.contract_trees.get_mut(&tx.contract_id).unwrap();
            let mut contract_state_tree_updates = Vec::with_capacity(txs.len());
            for (leaf_index, leaf_hash) in tx.leaves.iter() {
                let proof = contract_tree.set_leaf(*leaf_index, *leaf_hash);
                contract_state_tree_updates.push(proof);
                total_slots_modified += 1;
            }
            state_history.push(QEDContractStateUpdateHistory {
                contract_state_tree_updates,
                user_contract_tree_update_proof: self.uct.set_leaf(tx.contract_id as u64, contract_tree.get_root()),
            });
            contract_tree.commit_changes();
        }
        self.uct.commit_changes();
        let new_user_state_root = self.uct.get_root();
        self.user_leaf.user_state_tree_root = new_user_state_root;
        self.user_leaf.nonce += F::from_u8_value(1);
        self.user_leaf.last_checkpoint_id = F::from_u64_value(latest_checkpoint_id);
        let end_leaf_hash = self.user_leaf.qfhash::<Hasher>();
        let core_input = SubmitUserEndCapNonProofCoreInput {
            checkpoint_id: F::from_u64_value(latest_checkpoint_id),
            stats: GUTAStats {
                fees_collected: F::from_u64_value(1000 * total_slots_modified + 1000),
                user_ops_processed: F::from_u8_value(1),
                total_transactions: F::from_u64_value(txs.len() as u64),
                slots_modified: F::from_u64_value(total_slots_modified as u64),
            },
            state_transition: PUPSEndCapResultCompact {
                start_user_leaf_hash: start_leaf_hash,
                end_user_leaf_hash: end_leaf_hash,
                checkpoint_tree_root_hash: latest_checkpoint_tree_root,
                user_id: F::from_u64_value(self.user_id),
            },
            new_user_leaf: self.user_leaf.clone(),
        };

        Ok(SubmitUserEndCapNonProofInput {
            core: core_input,
            contract_state_updates: state_history,
        })
    }
}
