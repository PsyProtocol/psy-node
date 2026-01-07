use std::{collections::HashMap, sync::Arc};

use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
use parth_core::{
    crypto::hash::{
        merkle_proof::{compute_root_merkle_proof_generic, DeltaMerkleProofCore, MerkleProofCore},
        traits::{FieldQHasher, QFieldHashable},
    },
    data::hash::{merkle_node_key::SimpleMerkleNodeKey, merkle_store_key::QMerkleStoreSingleIdKey},
    felt::QFelt64,
    protocol::core_types::{QDBHashBase, QFHashBase},
};
use psy_data::{
    guta::stats::GUTAStats,
    proof_input::guta::{end_cap_input::SubmitUserEndCapNonProofInput, SubmitUserEndCapNonProofCoreInput},
    v1::qdata::{
        contract::QEDContractStateUpdateHistory, public_key::PZKPublicKeyInfo, user::PQEDUserLeaf, user_end_cap_result::PUPSEndCapResultCompact,
    },
};

use crate::api::combo_dummy_fetcher::PsyDummyProverComboFetcher;
#[derive(Clone)]
pub struct DummyUPSStateBuilder<
    F: QFelt64,
    Hash: QDBHashBase + QFHashBase<F>,
    Fetcher: PsyDummyProverComboFetcher<F, Hash>,
    Hasher: FieldQHasher<F, Hash>,
> {
    pub user_contract_tree: SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
    pub data_fetcher: Arc<Fetcher>,
    pub user_id: u64,
    pub checkpoint_id: u64,
    pub checkpoint_root_hash: Hash,
    pub contract_state_trees: HashMap<u32, SimpleMemoryMerkleRecorderStore<Hasher, Hash>>,
    pub contract_state_tree_heights: HashMap<u32, u8>,
    pub contract_state_dmps: HashMap<u32, Vec<DeltaMerkleProofCore<Hash>>>,
    pub start_user_leaf: PQEDUserLeaf<F, Hash>,
    pub public_key: PZKPublicKeyInfo<Hash>,
    pub slots_modified: u64,
    pub pending_writes: Vec<(u32, u64, Hash)>,
    pub is_first_tx: bool,
}

impl<F: QFelt64, Hash: QDBHashBase + QFHashBase<F>, Fetcher: PsyDummyProverComboFetcher<F, Hash>, Hasher: FieldQHasher<F, Hash>>
    DummyUPSStateBuilder<F, Hash, Fetcher, Hasher>
{
    pub async fn new_init(data_fetcher: Arc<Fetcher>, user_contract_tree_height: u8, user_id: u64, checkpoint_id: u64) -> anyhow::Result<Self> {
        let global_user_tree_proof: MerkleProofCore<Hash> = data_fetcher.df_get_global_user_tree_proof(u64::MAX - 0xffff, user_id).await?;

        let is_first_tx = global_user_tree_proof.value == Hash::get_zero_value();
        println!("is_first_tx: {}", is_first_tx);

        let public_key: PZKPublicKeyInfo<Hash> = data_fetcher.cf_get_user_public_key(user_id).await.unwrap_or(PZKPublicKeyInfo {
            fingerprint: Hash::get_zero_value(),
            public_key_param: Hash::get_zero_value()
        });

        println!("public_key: {:?}", public_key);

        let checkpoint_proof: MerkleProofCore<Hash> = data_fetcher
            .cf_get_checkpoint_tree_merkle_proof(checkpoint_id)
            .await?;
        //println!("first checkpoint proof (valid={}): {:?}", checkpoint_proof.verify::<Hasher>(), checkpoint_proof);
        let checkpoint_proof = checkpoint_proof
            .to_append_proof::<Hasher>();
        //println!("append proof (valid= {}): {:#?}", checkpoint_proof.verify::<Hasher>(), checkpoint_proof);
        //println!("verify checkpoint proof: {:?}", checkpoint_proof.verify::<Hasher>());
        //println!("append root: {:?}", checkpoint_proof.get_append_root::<Hasher>());

        let checkpoint_root = checkpoint_proof.get_append_root::<Hasher>();

        let start_user_leaf = data_fetcher.df_get_user_leaf(checkpoint_id, user_id).await?;

        Ok(Self {
            user_contract_tree: SimpleMemoryMerkleRecorderStore::new(user_contract_tree_height),
            data_fetcher,
            user_id,
            checkpoint_id,
            checkpoint_root_hash: checkpoint_root,
            contract_state_trees: HashMap::new(),
            start_user_leaf,
            slots_modified: 0,
            pending_writes: vec![],
            contract_state_dmps: HashMap::new(),
            contract_state_tree_heights: HashMap::new(),
            public_key,
            is_first_tx,
        })
    }
    pub async fn populate_user_contract_tree(&mut self) -> anyhow::Result<()> {
        for contract_id in self.contract_state_tree_heights.keys() {
            let leaf_key = SimpleMerkleNodeKey {
                level: self.user_contract_tree.get_height(),
                index: *contract_id as u64,
            };
            let mut siblings_keys = leaf_key.get_siblings_keys_to_height(0);
            siblings_keys.push(leaf_key);
            let keys = siblings_keys
                .iter()
                .map(|x| QMerkleStoreSingleIdKey {
                    tree_id: self.user_id,
                    level: x.level,
                    index: x.index,
                })
                .collect::<Vec<_>>();
            let mut siblings = self.data_fetcher.df_get_user_contract_tree_nodes(self.checkpoint_id, keys).await?;
            let leaf = siblings.pop().ok_or_else(|| anyhow::anyhow!("No leaf found in merkle proof"))?;
            let root = compute_root_merkle_proof_generic::<Hash, Hasher>(leaf, *contract_id as u64, &siblings);
            let mp = MerkleProofCore {
                siblings,
                value: leaf,
                root: root,
                index: *contract_id as u64,
            };
            //println!("Injesting user contract tree merkle proof for contract_id {}: {:?}", contract_id, mp);
            self.user_contract_tree.injest_merkle_proof_into_nodes(&mp)?;
        }
        Ok(())
    }
    pub async fn get_state_tree_height(&mut self, contract_id: u32) -> anyhow::Result<u8> {
        if self.contract_state_tree_heights.contains_key(&contract_id) {
            let height = *self
                .contract_state_tree_heights
                .get(&contract_id)
                .ok_or_else(|| anyhow::anyhow!("No height found for contract"))?;
            return Ok(height);
        }
        let height = self
            .data_fetcher
            .df_get_contract_state_heights(u64::MAX - 0xff, vec![contract_id as u64])
            .await?
            .pop()
            .ok_or_else(|| anyhow::anyhow!("No height returned for contract"))?;
        self.contract_state_tree_heights.insert(contract_id, height);
        self.contract_state_dmps.insert(contract_id, Vec::new());
        let tree = SimpleMemoryMerkleRecorderStore::new(height);
        /*println!(
            "initialized tree with root {:?} and height {} for contract {}",
            tree.get_root(),
            height,
            contract_id
        );
        */
        self.contract_state_trees.insert(contract_id, tree);
        Ok(height)
    }
    pub async fn get_merkle_proof_for_contract_from_fetcher(&mut self, contract_id: u32, slot_id: u64) -> anyhow::Result<MerkleProofCore<Hash>> {
        let height = self.get_state_tree_height(contract_id).await?;

        let mp: MerkleProofCore<Hash> = self
            .data_fetcher
            .df_get_contract_state_tree_merkle_proof(self.checkpoint_id, self.user_id, contract_id as u64, height, slot_id)
            .await?;
        //println!("mp: {:?}, height: {}", mp, height);
        self.contract_state_trees
            .get_mut(&contract_id)
            .ok_or_else(|| anyhow::anyhow!("Contract tree not found"))?
            .injest_merkle_proof_into_nodes(&mp)?;
        Ok(mp)
    }
    pub async fn write_to_contract(&mut self, contract_id: u32, slot_id: u64, value_hash: Hash) -> anyhow::Result<()> {
        let state_height = self.get_state_tree_height(contract_id).await?;
        //println!("state_height for contract {}: {}", contract_id, state_height);
        if slot_id >= (1u64 << state_height) {
            return Err(anyhow::anyhow!(
                "Slot ID {} is out of bounds for contract {} with state tree height {}",
                slot_id,
                contract_id,
                state_height
            ));
        }

        self.get_merkle_proof_for_contract_from_fetcher(contract_id, slot_id).await?;

        let dmp = self
            .contract_state_trees
            .get_mut(&contract_id)
            .ok_or_else(|| anyhow::anyhow!("Contract tree not found"))?
            .set_leaf(slot_id, value_hash);
        //println!("old root for contract {}: {:?}", contract_id, dmp.old_root);
        let rt = self
            .contract_state_trees
            .get_mut(&contract_id)
            .ok_or_else(|| anyhow::anyhow!("Contract tree not found"))?
            .get_root();

        if rt != dmp.new_root {
            println!("Computed root: {:?}, DMP new root: {:?}", rt, dmp.new_root);
            return Err(anyhow::anyhow!("Computed new root does not match DMP new root"));
        } else {
            //println!("Roots match: {:?}", rt);
        }

        //println!("dmp for contract {} slot {}: {:?}", contract_id, slot_id, dmp);
        self.contract_state_dmps
            .get_mut(&contract_id)
            .ok_or_else(|| anyhow::anyhow!("No DMPs found for contract"))?
            .push(dmp);
        for _ in self
            .contract_state_dmps
            .get(&contract_id)
            .ok_or_else(|| anyhow::anyhow!("No DMPs found for contract"))?
            .iter()
        {
            //println!("Current DMP for contract {}: {:#?}", contract_id, i);
        }

        self.slots_modified += 1;
        Ok(())
    }

    pub async fn read_from_contract(&mut self, contract_id: u32, slot_id: u64) -> anyhow::Result<Hash> {
        let state_height = self.get_state_tree_height(contract_id).await?;
        if slot_id >= (1u64 << state_height) {
            return Err(anyhow::anyhow!(
                "Slot ID {} is out of bounds for contract {} with state tree height {}",
                slot_id,
                contract_id,
                state_height
            ));
        }

        self.get_merkle_proof_for_contract_from_fetcher(contract_id, slot_id).await?;
        Ok(self
            .contract_state_trees
            .get(&contract_id)
            .ok_or_else(|| anyhow::anyhow!("Contract tree not found"))?
            .get_leaf_value(slot_id))
    }

    pub async fn finalize_and_build(mut self) -> anyhow::Result<SubmitUserEndCapNonProofInput<F, Hash>> {
        self.populate_user_contract_tree().await?;
        let mut contract_state_updates: Vec<QEDContractStateUpdateHistory<Hash>> = Vec::new();
        for (contract_id, dmps) in self.contract_state_dmps.into_iter() {
            let contract_update = QEDContractStateUpdateHistory {
                user_contract_tree_update_proof: self.user_contract_tree.set_leaf(
                    contract_id as u64,
                    dmps.last().ok_or_else(|| anyhow::anyhow!("No DMPs found for contract"))?.new_root,
                ),
                contract_state_tree_updates: dmps.clone(),
            };
            contract_state_updates.push(contract_update);
        }

        let new_user_leaf = PQEDUserLeaf {
            user_id: self.start_user_leaf.user_id,
            balance: self.start_user_leaf.balance,
            nonce: self.start_user_leaf.nonce + F::from_u64_value(1),
            public_key: self.public_key.qfhash::<Hasher>(),
            user_state_tree_root: self.user_contract_tree.get_root(),
            last_checkpoint_id: F::from_u64_value(self.checkpoint_id),
            event_index: self.start_user_leaf.event_index,
        };

        let ups_end = PUPSEndCapResultCompact {
            start_user_leaf_hash: if self.is_first_tx {
                Hash::get_zero_value()
            } else {
                self.start_user_leaf.qfhash::<Hasher>()
            },
            end_user_leaf_hash: new_user_leaf.qfhash::<Hasher>(),
            checkpoint_tree_root_hash: self.checkpoint_root_hash,
            user_id: self.start_user_leaf.user_id,
        };
        let stats = GUTAStats {
            guta_fees_collected: F::from_u64_value(1000),
            da_fees_collected: F::from_u64_value(1000 * self.slots_modified),
            user_ops_processed: F::from_u64_value(1),
            total_transactions: F::from_u64_value(1),
            slots_modified: F::from_u64_value(self.slots_modified),
        };

        Ok(SubmitUserEndCapNonProofInput {
            core: SubmitUserEndCapNonProofCoreInput {
                checkpoint_id: F::from_u64_value(self.checkpoint_id),
                stats: stats,
                state_transition: ups_end,
                new_user_leaf,
            },
            contract_state_updates,
        })
    }
}
