use parth_core::{
    crypto::hash::traits::MerkleZeroHasher,
    data::hash::merkle_node_key::SimpleMerkleNodeKey,
    protocol::core_types::Q256BitHash,
};
use psy_data::{
    guta::realm_finalize::VALIDATOR_TREE_HEIGHT,
    p2p::{
        authenticate_validator_preimage, realm_validator_indexes, require_realm_validator_count,
        BlsPublicKey, ValidatorLeaf, ValidatorLeafPreimage,
    },
};

use crate::psy_core_db::traits::full::{
    PsyNodeValidatorTreeDatabaseReader, PsyNodeValidatorTreeDatabaseWriter,
};

pub async fn load_realm_validators_from_tree<Hasher, Hash, Store>(
    store: &Store,
    chain_id: u64,
    checkpoint_id: u64,
    realm_id: u32,
    expected_root: &Hash,
) -> anyhow::Result<(
    Vec<u16>,
    Vec<(u16, BlsPublicKey)>,
    Vec<(u16, u64)>,
    Vec<(u16, ValidatorLeaf)>,
)>
where
    Hasher: MerkleZeroHasher<Hash>,
    Hash: Copy + PartialEq + Q256BitHash,
    Store: PsyNodeValidatorTreeDatabaseReader<Hash> + Sync,
{
    let tree_root = store.validator_tree_get_root_hash(checkpoint_id).await?;
    anyhow::ensure!(
        &tree_root == expected_root,
        "validator tree root mismatch at checkpoint {checkpoint_id}"
    );

    let empty_leaf = Hasher::get_zero_hash(0);
    let slots: Vec<(u16, u64)> = realm_validator_indexes(realm_id).collect();
    let leaf_keys: Vec<SimpleMerkleNodeKey> = slots
        .iter()
        .map(|(_, leaf_index)| SimpleMerkleNodeKey::new(VALIDATOR_TREE_HEIGHT as u8, *leaf_index))
        .collect();
    let leaf_hashes = store.validator_tree_get_nodes(checkpoint_id, &leaf_keys).await?;
    anyhow::ensure!(
        leaf_hashes.len() == slots.len(),
        "validator tree leaf batch returned {} hashes for {} realm {realm_id} slots",
        leaf_hashes.len(),
        slots.len()
    );

    let occupied: Vec<(u16, u64, Hash)> = slots
        .iter()
        .zip(leaf_hashes.iter())
        .filter(|(_, leaf_hash)| **leaf_hash != empty_leaf)
        .map(|((sub_id, leaf_index), leaf_hash)| (*sub_id, *leaf_index, *leaf_hash))
        .collect();
    let preimage_indexes: Vec<u64> = occupied.iter().map(|(_, leaf_index, _)| *leaf_index).collect();
    let preimages = if preimage_indexes.is_empty() {
        Vec::new()
    } else {
        store
            .validator_tree_get_leaf_preimages(checkpoint_id, &preimage_indexes)
            .await?
    };
    anyhow::ensure!(
        preimages.len() == occupied.len(),
        "validator tree preimage batch returned {} values for {} occupied realm {realm_id} slots",
        preimages.len(),
        occupied.len()
    );

    let mut validator_sub_ids = Vec::with_capacity(occupied.len());
    let mut keys = Vec::with_capacity(occupied.len());
    let mut user_ids = Vec::with_capacity(occupied.len());
    let mut leaves = Vec::with_capacity(occupied.len());
    for ((sub_id, _leaf_index, leaf_hash), preimage) in occupied.iter().zip(preimages) {
        let preimage = preimage.ok_or_else(|| {
            anyhow::anyhow!(
                "validator leaf preimage missing at realm {realm_id} sub {sub_id} checkpoint {checkpoint_id}"
            )
        })?;
        anyhow::ensure!(
            preimage.chain_id == chain_id,
            "validator preimage chain_id {} does not match configured chain {chain_id} at realm {realm_id} sub {sub_id}",
            preimage.chain_id
        );
        anyhow::ensure!(
            preimage.realm_id == realm_id && preimage.realm_sub_id == *sub_id,
            "validator preimage slot mismatch at realm {realm_id} sub {sub_id}"
        );
        let leaf = authenticate_validator_preimage(&preimage, leaf_hash)?;
        validator_sub_ids.push(*sub_id);
        keys.push((*sub_id, leaf.bls_public_key));
        user_ids.push((*sub_id, preimage.validator_user_id));
        leaves.push((*sub_id, leaf));
    }
    require_realm_validator_count(realm_id, validator_sub_ids.len())?;
    Ok((validator_sub_ids, keys, user_ids, leaves))
}

pub fn validator_nodes_from_leaves(leaves: &[(u16, ValidatorLeaf)]) -> Vec<(u16, psy_data::p2p::NodeId)> {
    leaves
        .iter()
        .map(|(sub_id, leaf)| (*sub_id, leaf.node_id))
        .collect()
}

pub async fn write_validator_tree_genesis<Hash, Store>(
    store: &Store,
    nodes_ffs: &[u8],
    preimages: &[ValidatorLeafPreimage],
) -> anyhow::Result<()>
where
    Store: PsyNodeValidatorTreeDatabaseWriter<Hash> + Sync,
{
    if !nodes_ffs.is_empty() {
        store.validator_tree_set_nodes_ffs(0, nodes_ffs).await?;
    }
    for preimage in preimages {
        store
            .validator_tree_set_leaf_preimage(0, preimage.tree_index()?, preimage)
            .await?;
    }
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashMap, sync::atomic::{AtomicUsize, Ordering}};
    use async_trait::async_trait;
    use parth_core::{crypto::hash::merkle_proof::MerkleProofCore, pgoldilocks::PoseidonHasher, PHash};
    use psy_core::constants::chain_id::PSY_CHAIN_ID_LOCAL_DEVNET;
    use psy_data::p2p::{BlsSecretKey, NodeId, NODE_ID_RAW_LEN};

    const CHAIN: u64 = PSY_CHAIN_ID_LOCAL_DEVNET;
    const REALM: u32 = 1;
    const CP: u64 = 7;

    fn sample(sub: u16, user: u64, seed: u8) -> ValidatorLeafPreimage {
        for i in 0u8..=32 {
            let mut raw = [0u8; NODE_ID_RAW_LEN];
            raw[..6].copy_from_slice(&[0x00, 0x24, 0x08, 0x01, 0x12, 0x20]);
            raw[6..].fill(seed.wrapping_add(i));
            let p = ValidatorLeafPreimage {
                chain_id: CHAIN, realm_id: REALM, realm_sub_id: sub, validator_user_id: user,
                node_id: *NodeId::from_raw(raw).unwrap().as_raw(),
                bls_public_key: BlsSecretKey::key_gen(&[seed.wrapping_add(i); 32]).unwrap().public_key().to_bytes(),
            };
            if p.leaf_hash().is_ok() { return p; }
        }
        panic!("no canonical preimage");
    }
    fn h(p: &ValidatorLeafPreimage) -> PHash { PHash::from_owned_32bytes(p.leaf_hash().unwrap()) }
    fn idx(sub: u16) -> u64 { ((REALM as u64) << 8) | sub as u64 }

    struct Tree {
        roots: HashMap<u64, PHash>,
        leaves: HashMap<(u64, u64), PHash>,
        preimages: HashMap<(u64, u64), ValidatorLeafPreimage>,
        leaf_q: AtomicUsize, pre_q: AtomicUsize, leaf_b: AtomicUsize, pre_b: AtomicUsize,
        short_leaves: bool, short_preimages: bool,
    }
    impl Tree {
        fn with(checkpoint: u64, root: PHash, occupied: &[ValidatorLeafPreimage]) -> Self {
            let mut t = Self {
                roots: HashMap::from([(checkpoint, root)]),
                leaves: HashMap::new(), preimages: HashMap::new(),
                leaf_q: AtomicUsize::new(0), pre_q: AtomicUsize::new(0),
                leaf_b: AtomicUsize::new(0), pre_b: AtomicUsize::new(0),
                short_leaves: false, short_preimages: false,
            };
            for p in occupied {
                t.occupy(checkpoint, p.clone());
            }
            t
        }
        fn occupy(&mut self, checkpoint: u64, p: ValidatorLeafPreimage) {
            let i = idx(p.realm_sub_id);
            self.leaves.insert((checkpoint, i), h(&p));
            self.preimages.insert((checkpoint, i), p);
        }
        fn occupy_leaf(&mut self, checkpoint: u64, sub: u16, hash: PHash) {
            self.leaves.insert((checkpoint, idx(sub)), hash);
        }
        fn latest_leaf(&self, checkpoint: u64, i: u64) -> PHash {
            self.leaves.iter()
                .filter(|((c, idx), _)| *idx == i && *c <= checkpoint)
                .max_by_key(|((c, _), _)| *c)
                .map(|(_, hash)| *hash)
                .unwrap_or_else(|| PoseidonHasher::get_zero_hash(0))
        }
        fn latest_preimage(&self, checkpoint: u64, i: u64) -> Option<ValidatorLeafPreimage> {
            self.preimages.iter()
                .filter(|((c, idx), _)| *idx == i && *c <= checkpoint)
                .max_by_key(|((c, _), _)| *c)
                .map(|(_, p)| p.clone())
        }
        fn latest_root(&self, checkpoint: u64) -> PHash {
            self.roots.iter()
                .filter(|(c, _)| **c <= checkpoint)
                .max_by_key(|(c, _)| **c)
                .map(|(_, root)| *root)
                .unwrap_or(self.roots[&CP])
        }
    }
    #[async_trait]
    impl PsyNodeValidatorTreeDatabaseReader<PHash> for Tree {
        async fn validator_tree_get_leaf_hash(&self, c: u64, i: u64) -> anyhow::Result<PHash> {
            self.leaf_q.fetch_add(1, Ordering::SeqCst);
            Ok(self.latest_leaf(c, i))
        }
        async fn validator_tree_get_root_hash(&self, c: u64) -> anyhow::Result<PHash> { Ok(self.latest_root(c)) }
        async fn validator_tree_get_merkle_proof(&self, _c: u64, _i: u64) -> anyhow::Result<MerkleProofCore<PHash>> { unreachable!() }
        async fn validator_tree_get_nodes(&self, c: u64, keys: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<PHash>> {
            self.leaf_b.fetch_add(1, Ordering::SeqCst);
            self.leaf_q.fetch_add(keys.len(), Ordering::SeqCst);
            let mut out: Vec<_> = keys.iter().map(|k| self.latest_leaf(c, k.index)).collect();
            if self.short_leaves { out.pop(); }
            Ok(out)
        }
        async fn validator_tree_get_node(&self, _c: u64, _k: SimpleMerkleNodeKey) -> anyhow::Result<PHash> { unreachable!() }
        async fn validator_tree_get_leaf_preimage(&self, c: u64, i: u64) -> anyhow::Result<Option<ValidatorLeafPreimage>> {
            self.pre_q.fetch_add(1, Ordering::SeqCst);
            Ok(self.latest_preimage(c, i))
        }
        async fn validator_tree_get_leaf_preimages(&self, c: u64, idxs: &[u64]) -> anyhow::Result<Vec<Option<ValidatorLeafPreimage>>> {
            self.pre_b.fetch_add(1, Ordering::SeqCst);
            self.pre_q.fetch_add(idxs.len(), Ordering::SeqCst);
            let mut out: Vec<_> = idxs.iter().map(|i| self.latest_preimage(c, *i)).collect();
            if self.short_preimages { out.pop(); }
            Ok(out)
        }
    }
    async fn load_at(t: &Tree, checkpoint: u64, root: &PHash) -> anyhow::Result<(Vec<u16>, Vec<(u16, BlsPublicKey)>, Vec<(u16, u64)>, Vec<(u16, ValidatorLeaf)>)> {
        load_realm_validators_from_tree::<PoseidonHasher, _, _>(t, CHAIN, checkpoint, REALM, root).await
    }
    async fn load(t: &Tree, root: &PHash) -> anyhow::Result<(Vec<u16>, Vec<(u16, BlsPublicKey)>, Vec<(u16, u64)>, Vec<(u16, ValidatorLeaf)>)> {
        load_at(t, CP, root).await
    }
    fn rejects(err: anyhow::Error, needle: &str) {
        let text = err.to_string();
        assert!(text.contains(needle), "expected {needle:?} in {text:?}");
    }

    #[tokio::test]
    async fn two_validators_authenticate_query_count_and_empty_slots() {
        let a = sample(1, 11, 11); let b = sample(5, 15, 15); let root = h(&a);
        let t = Tree::with(CP, root, &[a.clone(), b.clone()]);
        let empty = PoseidonHasher::get_zero_hash(0);
        for (_, i) in realm_validator_indexes(REALM) {
            if t.validator_tree_get_leaf_hash(CP, i).await.unwrap() != empty {
                t.validator_tree_get_leaf_preimage(CP, i).await.unwrap();
            }
        }
        assert_eq!((t.leaf_q.load(Ordering::SeqCst), t.pre_q.load(Ordering::SeqCst)), (256, 2));
        t.leaf_q.store(0, Ordering::SeqCst); t.pre_q.store(0, Ordering::SeqCst);
        let (subs, keys, users, leaves) = load(&t, &root).await.unwrap();
        assert_eq!(subs, vec![1, 5]);
        assert_eq!(users, vec![(1, 11), (5, 15)]);
        assert_eq!(keys[0].1, a.to_leaf().unwrap().bls_public_key);
        assert_eq!(leaves[1].1, b.to_leaf().unwrap());
        assert_eq!((t.leaf_b.load(Ordering::SeqCst), t.pre_b.load(Ordering::SeqCst)), (1, 1));
        assert_eq!((t.leaf_q.load(Ordering::SeqCst), t.pre_q.load(Ordering::SeqCst)), (256, 2));
    }

    #[tokio::test]
    async fn missing_occupied_preimage_rejects() {
        let a = sample(1, 11, 11); let root = h(&a);
        let mut t = Tree::with(CP, root, &[]);
        t.occupy_leaf(CP, 1, root);
        rejects(load(&t, &root).await.unwrap_err(), "preimage missing");
    }

    #[tokio::test]
    async fn corrupted_preimage_rejects() {
        let a = sample(1, 11, 11); let root = h(&a);
        let mut t = Tree::with(CP, root, &[a]);
        t.occupy_leaf(CP, 1, h(&sample(5, 15, 15)));
        rejects(load(&t, &root).await.unwrap_err(), "hash mismatch");
    }

    #[tokio::test]
    async fn historical_checkpoint_uses_old_leaf_and_preimage() {
        let old = sample(1, 11, 11); let new = sample(1, 99, 21);
        let old_root = h(&old); let new_root = h(&new);
        let mut t = Tree::with(3, old_root, &[old]);
        t.roots.insert(CP, new_root);
        t.occupy(CP, new);
        let users = load_at(&t, 3, &old_root).await.unwrap().2;
        assert_eq!(users, vec![(1, 11)]);
        let users = load_at(&t, CP, &new_root).await.unwrap().2;
        assert_eq!(users, vec![(1, 99)]);
    }

    #[tokio::test]
    async fn empty_realm_hits_count_gate_without_preimage_batch() {
        let empty_root = PoseidonHasher::get_zero_hash(VALIDATOR_TREE_HEIGHT);
        let empty = Tree::with(CP, empty_root, &[]);
        rejects(load(&empty, &empty_root).await.unwrap_err(), "validator count 0");
        assert_eq!(empty.pre_b.load(Ordering::SeqCst), 0);
        assert_eq!(empty.pre_q.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn short_batches_reject() {
        let a = sample(1, 11, 11); let b = sample(5, 15, 15); let root = h(&a);
        let mut t = Tree::with(CP, root, &[a.clone(), b]);
        t.short_leaves = true;
        rejects(load(&t, &root).await.unwrap_err(), "leaf batch returned");
        t.short_leaves = false; t.short_preimages = true;
        rejects(load(&t, &root).await.unwrap_err(), "preimage batch returned");
    }

    #[tokio::test]
    async fn invalid_bls_rejects() {
        let a = sample(1, 11, 11);
        let mut bad = a; bad.bls_public_key = [0u8; 48];
        let dummy = PHash::from_owned_32bytes([1u8; 32]);
        let mut t = Tree::with(CP, dummy, &[]);
        t.occupy_leaf(CP, 1, dummy);
        t.preimages.insert((CP, idx(1)), bad);
        rejects(load(&t, &dummy).await.unwrap_err(), "invalid stored validator BLS key");
    }
}
