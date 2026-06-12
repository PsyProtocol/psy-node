use std::marker::PhantomData;

use kvq::{adapters::standard::KVQStandardAdapter, traits::KVQStoreAdapter};
use plonky2::hash::hash_types::RichField;
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::hash::{
    merkle::core::{DeltaMerkleProofCore, MerkleProofCore},
    traits::hasher::MerkleZeroHasherWithMarkedLeaf,
};
use serde::{Deserialize, Serialize};

use crate::{
    config::store_config::{BaseContractStateTreeStore, PsyFelt, PsyHasher, CONTRACT_STATE_TREE_ID, USER_CONTRACT_STATE_TREE_TABLE_TYPE},
    models::kvq_merkle::{
        key::KVQMerkleNodeKey,
        model::{KVQMerkleTreeModelCore, KVQMerkleTreeModelReaderCore},
    },
};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserContractStateTreeId<
    S,
    F: RichField = PsyFelt,
    H: MerkleZeroHasherWithMarkedLeaf<QHashOut<F>> = PsyHasher,
    IDKVA = KVQStandardAdapter<S, KVQMerkleNodeKey<USER_CONTRACT_STATE_TREE_TABLE_TYPE>, QHashOut<F>>,
> {
    pub user_id: u64,
    pub contract_id: u32,
    pub height: u8,
    #[serde(skip)]
    _adapter: PhantomData<(S, F, H, IDKVA)>,
}

impl<
        S,
        F: RichField,
        H: MerkleZeroHasherWithMarkedLeaf<QHashOut<F>>,
        IDKVA: KVQStoreAdapter<S, KVQMerkleNodeKey<USER_CONTRACT_STATE_TREE_TABLE_TYPE>, QHashOut<F>>,
    > UserContractStateTreeId<S, F, H, IDKVA>
{
    pub fn new(user_id: u64, contract_id: u32, height: u8) -> Self {
        Self {
            user_id,
            contract_id,
            height,
            _adapter: PhantomData,
        }
    }
    pub fn get_leaf_key(&self, checkpoint_id: u64, index: u64) -> KVQMerkleNodeKey<USER_CONTRACT_STATE_TREE_TABLE_TYPE> {
        KVQMerkleNodeKey {
            tree_id: CONTRACT_STATE_TREE_ID,
            primary_id: self.user_id,
            secondary_id: self.contract_id,
            level: self.height,
            index,
            checkpoint_id,
        }
    }
    pub fn get_leaf_ucs(&self, store: &S, checkpoint_id: u64, index: u64) -> anyhow::Result<MerkleProofCore<QHashOut<F>>> {
        BaseContractStateTreeStore::<S, F, H, IDKVA>::get_leaf(store, &self.get_leaf_key(checkpoint_id, index))
    }
    pub fn get_leaf_value_ucs(&self, store: &S, checkpoint_id: u64, index: u64) -> anyhow::Result<QHashOut<F>> {
        BaseContractStateTreeStore::<S, F, H, IDKVA>::get_node(store, self.height.into(), &self.get_leaf_key(checkpoint_id, index))
    }
    pub fn set_leaf_ucs(&self, store: &S, checkpoint_id: u64, index: u64, value: QHashOut<F>) -> anyhow::Result<DeltaMerkleProofCore<QHashOut<F>>> {
        BaseContractStateTreeStore::<S, F, H, IDKVA>::set_leaf(store, &self.get_leaf_key(checkpoint_id, index), value)
    }
    pub fn injest_merkle_proof_ucs(&self, store: &S, checkpoint_id: u64, merkle_proof: &MerkleProofCore<QHashOut<F>>) -> anyhow::Result<()> {
        BaseContractStateTreeStore::<S, F, H, IDKVA>::injest_merkle_proof(
            store,
            CONTRACT_STATE_TREE_ID,
            self.user_id,
            self.contract_id,
            checkpoint_id,
            merkle_proof,
        )
    }
    pub fn get_root(&self, store: &S, checkpoint_id: u64) -> anyhow::Result<QHashOut<F>> {
        BaseContractStateTreeStore::<S, F, H, IDKVA>::get_node(
            store,
            self.height.into(),
            &KVQMerkleNodeKey {
                tree_id: CONTRACT_STATE_TREE_ID,
                primary_id: self.user_id,
                secondary_id: self.contract_id,
                level: 0,
                index: 0,
                checkpoint_id,
            },
        )
    }
}
