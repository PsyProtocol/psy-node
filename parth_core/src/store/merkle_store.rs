use std::u64;

use async_trait::async_trait;
use crate::{crypto::hash::{merkle_proof::MerkleProofCore, traits::{QHasher}}, data::{hash::{merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}, merkle_store_key::QMerkleStoreKey}, serializable::QPDPair}, protocol::core_types::QHashBase, store::qpd_store::{QPDBinaryStoreReaderAsync, QPDBinaryStoreWriterAsync}};


pub trait SerializableMerkleTableKey {
    const TREE_HEIGHT: u8;

    //fn get_full_merkle_key(&self, node: &SimpleMerkleNodeKey, checkpoint_id: u64) -> QMerkleStoreKey;
    fn get_merkle_key_bytes(&self, node: &SimpleMerkleNodeKey, checkpoint_id: u64) -> Vec<u8>;
    fn decode_merkle_key_bytes(&self, bytes: &[u8]) -> anyhow::Result<QMerkleStoreKey>;
}


#[async_trait]
pub trait QSimpleMerkleNodeStoreReader<Hash: QHashBase, Hasher: QHasher<Hash>, S: QPDBinaryStoreReaderAsync + Sync>: SerializableMerkleTableKey {
    async fn get_nodes_at_checkpoint(&self, store: &S, max_checkpoint_id: u64, nodes: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<Hash>> {
        let n_keys: Vec<_> = nodes.iter().map(|n| self.get_merkle_key_bytes(n, max_checkpoint_id)).collect();
        let result: Vec<Hash> = store.get_many_leq_kv_async(&n_keys, 8).await?.into_iter().zip(nodes.iter()).map(|(p, n)|{
            if p.is_some(){
                let d = p.unwrap().value;
                if d.len() == Hash::get_fixed_size() {
                    Hash::from_bytes(&d)
                }else{
            Ok(Hasher::get_zero_hash((Self::TREE_HEIGHT - n.level) as usize))

                }
            }else{

            Ok(Hasher::get_zero_hash((Self::TREE_HEIGHT - n.level) as usize))
            }


        }).collect::<anyhow::Result<Vec<Hash>>>()?;
        Ok(result)
    }
    async fn get_node_at_checkpoint(&self, store: &S, max_checkpoint_id: u64, node: &SimpleMerkleNodeKey) -> anyhow::Result<Hash> {

        let n_key = self.get_merkle_key_bytes(&node, max_checkpoint_id);
        
        let result = store.get_leq_kv_async(&n_key, 8).await?;
        let v = if result.is_some() {
            let d = result.unwrap().value;
                if d.len() == Hash::get_fixed_size() {
                    Hash::from_bytes(&d)?
                }else{
            Hasher::get_zero_hash((Self::TREE_HEIGHT - node.level) as usize)

                }
        }else{

            Hasher::get_zero_hash((Self::TREE_HEIGHT - node.level) as usize)
        };
        Ok(v)
    }
    async fn get_node_latest(&self, store: &S, node: &SimpleMerkleNodeKey) -> anyhow::Result<Hash> {
        self.get_node_at_checkpoint(store, u64::MAX, node).await
    }


    async fn get_root_at_checkpoint(&self, store: &S, max_checkpoint_id: u64) -> anyhow::Result<Hash> {
        self.get_node_at_checkpoint(store, max_checkpoint_id, &SimpleMerkleNodeKey { level: 0, index: 0 }).await
    }
    async fn get_root_latest(&self, store: &S) -> anyhow::Result<Hash> {
        self.get_node_latest(store, &SimpleMerkleNodeKey { level: 0, index: 0 }).await
    }

    async fn get_nodes_latest(&self, store: &S, nodes: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<Hash>> {
        self.get_nodes_at_checkpoint(store, u64::MAX, nodes).await
    }

    async fn get_merkle_proof_from_to_at_checkpoint(&self, store: &S, max_checkpoint_id: u64, value_node: SimpleMerkleNodeKey, root_level: u8) -> anyhow::Result<MerkleProofCore<Hash>> {
        if root_level > value_node.level {
            anyhow::bail!("root level greater than value level in get_merkle_proof_from_to");
        }

        let mut keys = value_node.get_siblings_keys_to_height(root_level);
        keys.push(SimpleMerkleNodeKey::new_root());
        keys.push(value_node);
        let mut vt = self.get_nodes_at_checkpoint(store, max_checkpoint_id, &keys).await?;

        let value = vt.pop().unwrap();
        let root = vt.pop().unwrap();


        Ok(
            MerkleProofCore { root, value, index: value_node.index, siblings: vt }
        )


    }
    async fn get_merkle_proof_from_to_latest(&self, store: &S, value_node: SimpleMerkleNodeKey, root_level: u8) -> anyhow::Result<MerkleProofCore<Hash>> {
       self.get_merkle_proof_from_to_at_checkpoint(store, u64::MAX, value_node, root_level).await

    }

    async fn get_merkle_proof_at_checkpoint(&self, store: &S, max_checkpoint_id: u64, value_node: SimpleMerkleNodeKey) -> anyhow::Result<MerkleProofCore<Hash>> {
        self.get_merkle_proof_from_to_at_checkpoint(store, max_checkpoint_id, value_node, 0).await
    }
    async fn get_merkle_proof_latest(&self, store: &S, value_node: SimpleMerkleNodeKey) -> anyhow::Result<MerkleProofCore<Hash>> {
        self.get_merkle_proof_from_to_latest(store, value_node, 0).await
    }

} 


#[async_trait]
pub trait QSimpleMerkleNodeStoreWriter<Hash: QHashBase, Hasher: QHasher<Hash>, S: QPDBinaryStoreWriterAsync + Sync>: SerializableMerkleTableKey {
    async fn put_nodes_at_checkpoint(&self, store: &S, checkpoint_id: u64, nodes: &[SimpleMerkleNode<Hash>]) -> anyhow::Result<()> {
        let kvs: Vec<_> = nodes.iter().map(|n| {
            let key = self.get_merkle_key_bytes(&n.key, checkpoint_id);
            let value = n.value.to_bytes().unwrap();
            QPDPair {
                key,
                value,
            }
        }).collect();
        store.set_many_vec_async(kvs).await
    }
}

#[async_trait]
pub trait QSimpleMerkleNodeStore<Hash: QHashBase, Hasher: QHasher<Hash>, S: QPDBinaryStoreReaderAsync + QPDBinaryStoreWriterAsync + Sync>: QSimpleMerkleNodeStoreReader<Hash, Hasher, S> + QSimpleMerkleNodeStoreWriter<Hash, Hasher, S> {
    async fn put_node_hash_up_to_level_at_checkpoint(&self, store: &S, checkpoint_id: u64, node: &SimpleMerkleNode<Hash>, up_to_level: u8) -> anyhow::Result<()> {
        if up_to_level > node.key.level {
            anyhow::bail!("up to level greater than node level in put_node_hash_up_to_level");
        }

        let mut nodes_to_write = Vec::new();
        let siblings = node.key.siblings();
        let sibling_hashes = self.get_nodes_at_checkpoint(store, checkpoint_id, &siblings).await?;

        let mut current_node = node.to_owned();

        for i in 0..(node.key.level - up_to_level) as usize {
            nodes_to_write.push(current_node.clone());
            let sibling_hash = &sibling_hashes[i];
            let parent_key = current_node.key.parent();
            let parent_hash = if current_node.key.is_left_sibling() {
                Hasher::two_to_one(&current_node.value, sibling_hash)
            } else {
                Hasher::two_to_one(sibling_hash, &current_node.value)
            };
            current_node = SimpleMerkleNode {
                key: parent_key,
                value: parent_hash,
            };
        }


        
        self.put_nodes_at_checkpoint(store, checkpoint_id, &nodes_to_write).await
    }

}
 


pub trait SerializableMerkleTableKeyAuto: SerializableMerkleTableKey {

}

impl<T: SerializableMerkleTableKeyAuto, Hash: QHashBase, Hasher: QHasher<Hash>, S: QPDBinaryStoreReaderAsync + Sync> QSimpleMerkleNodeStoreReader<Hash, Hasher, S> for T {

}

impl<T: SerializableMerkleTableKeyAuto, Hash: QHashBase, Hasher: QHasher<Hash>, S: QPDBinaryStoreWriterAsync + Sync> QSimpleMerkleNodeStoreWriter<Hash, Hasher, S> for T {

}

impl<T: SerializableMerkleTableKeyAuto, Hash: QHashBase, Hasher: QHasher<Hash>, S: QPDBinaryStoreReaderAsync + QPDBinaryStoreWriterAsync + Sync> QSimpleMerkleNodeStore<Hash, Hasher, S> for T {

}



