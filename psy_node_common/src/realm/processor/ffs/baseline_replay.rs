//! Coverage checks, tree replay, and previous-checkpoint contract heights.

use std::collections::{HashMap, HashSet};

use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
use parth_common::memory_stores::traits::PsyMemoryMerkleStoreImm;
use parth_core::{
    crypto::hash::traits::{FieldQHasher, MerkleZeroHasher, QFieldHashable},
    data::hash::fast_node_serializer::QMerkleStoreFastZeroNodeSerializer,
    felt::{FromPrimitiveValuesFelt, ToU64Value},
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use psy_data::{
    prepared_block::realm::PsyPreparedRealmBlockStateUpdates,
    v1::qdata::{
        ffs_sizes::PSY_OBJECT_FFS_SIZE_USER_LEAF,
        user::PQEDUserLeaf,
    },
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use super::{gut_local_key, require_imt_leaf_ffs_consistency};
use crate::realm::processor::db::require_state_update_record_coverage;

pub(crate) fn replay_state_updates_into_tree<F, Hash, H>(
    tree: &mut SimpleMemoryMerkleRecorderStore<H, Hash>,
    updates: &PsyPreparedRealmBlockStateUpdates<Hash>,
    coordinator_height: u8,
    realm_user_tree_height: u8,
    realm_id: u64,
    checkpoint_id: u64,
    changed_leaves_on_imt_indexed_trees: &HashSet<(u64, u64, u64)>,
) -> anyhow::Result<()>
where
    F: parth_core::felt::QFelt64 + FromPrimitiveValuesFelt,
    Hash: Q256BitHash + QFHashBase<F> + Copy + PartialEq + Default + std::fmt::Debug,
    H: MerkleZeroHasher<Hash> + FieldQHasher<F, Hash>,
{
    require_state_update_record_coverage(updates, checkpoint_id, changed_leaves_on_imt_indexed_trees)?;
    anyhow::ensure!(
        tree.get_root() == updates.old_realm_root,
        "MissingAuthenticatedState: tree root {:?} is not old_realm_root {:?}",
        tree.get_root(),
        updates.old_realm_root
    );

    let gut_nodes = if updates.update_global_user_tree_nodes_ffs.is_empty() {
        Vec::new()
    } else {
        QMerkleStoreFastZeroNodeSerializer::deserialize_zero_id_nodes_from_slice::<Hash>(
            &updates.update_global_user_tree_nodes_ffs,
        )
    };
    let min_user_id = realm_id << realm_user_tree_height;
    let mut last_user: HashMap<u64, PQEDUserLeaf<F, Hash>> = HashMap::new();
    for bytes in updates
        .update_user_leaves_ffs
        .chunks_exact(PSY_OBJECT_FFS_SIZE_USER_LEAF)
    {
        let leaf = PQEDUserLeaf::<F, Hash>::psy_ser_from_slice(bytes)?;
        last_user.insert(leaf.user_id.to_u64_value(), leaf);
    }
    let mut last_leaf: HashMap<u64, Hash> = HashMap::new();
    for node in &gut_nodes {
        let local = gut_local_key(node.key, coordinator_height, realm_id)?;
        if local.level == realm_user_tree_height {
            last_leaf.insert(local.index, node.value);
        }
    }
    for (index, value) in &last_leaf {
        let previous_leaf = tree.get_leaf_value(*index);
        if previous_leaf == *value {
            continue;
        }
        let user_id = min_user_id + *index;
        let leaf = last_user.get(&user_id).ok_or_else(|| {
            anyhow::anyhow!("InvalidStateUpdates: GUT leaf {index} changed without preimage")
        })?;
        anyhow::ensure!(
            leaf.qfhash::<H>() == *value,
            "InvalidStateUpdates: user {user_id} preimage does not bind the GUT leaf"
        );
    }
    for (index, value) in last_leaf {
        tree.set_leaf(index, value);
    }

    for node in &gut_nodes {
        let local = gut_local_key(node.key, coordinator_height, realm_id)?;
        anyhow::ensure!(
            tree.get_node_value(&local) == node.value,
            "InvalidStateUpdates: declared GUT node {:?}={:?} does not match recomputed {:?}",
            local,
            node.value,
            tree.get_node_value(&local)
        );
    }

    for (user_id, leaf) in &last_user {
        anyhow::ensure!(
            *user_id >= min_user_id,
            "InvalidStateUpdates: user_id {user_id} is outside realm {realm_id}"
        );
        let local_index = user_id - min_user_id;
        let expected = leaf.qfhash::<H>();
        anyhow::ensure!(
            tree.get_leaf_value(local_index) == expected,
            "InvalidStateUpdates: user {user_id} preimage does not bind the recomputed GUT leaf"
        );
    }

    require_imt_leaf_ffs_consistency::<F, Hash, H>(&updates.update_contract_state_imt_leaves_ffs)?;

    anyhow::ensure!(
        tree.get_root() == updates.new_realm_root,
        "InvalidStateUpdates: recomputed root {:?} is not new_realm_root {:?}",
        tree.get_root(),
        updates.new_realm_root
    );
    Ok(())
}

pub(super) async fn load_previous_contract_heights<S, F, Hash>(
    db: &S,
    previous_checkpoint_id: u64,
    contract_ids: impl IntoIterator<Item = u64>,
) -> anyhow::Result<HashMap<u64, u8>>
where
    S: psy_node_core::psy_core_db::traits::full::PsyNodeCoreDatabaseBasicContractInfoStoreReader<F, Hash> + Sync,
    F: Send + Sync,
    Hash: Send + Sync,
{
    let mut unique = Vec::new();
    let mut seen = HashSet::new();
    for contract_id in contract_ids {
        if seen.insert(contract_id) {
            unique.push(contract_id);
        }
    }
    if unique.is_empty() {
        return Ok(HashMap::new());
    }
    let fetched = db
        .get_contract_tree_heights(previous_checkpoint_id, &unique)
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "MissingAuthenticatedState: contract heights unavailable at previous checkpoint {previous_checkpoint_id}: {error}"
            )
        })?;
    let mut heights = HashMap::with_capacity(unique.len());
    for (i, contract_id) in unique.into_iter().enumerate() {
        heights.insert(contract_id, fetched.get(i).copied().unwrap_or(0));
    }
    Ok(heights)
}

pub(super) fn require_previous_contract_height(heights: &HashMap<u64, u8>, contract_id: u64) -> anyhow::Result<u8> {
    let height = heights.get(&contract_id).copied().unwrap_or(0);
    anyhow::ensure!(
        height > 0,
        "MissingAuthenticatedState: contract {contract_id} height is zero"
    );
    Ok(height)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
    use parth_core::{
        crypto::hash::traits::{MerkleZeroHasher, QFieldHashable},
        data::hash::{
            fast_node_serializer::{
                QMerkleStoreFastSingleNodeSerializer, QMerkleStoreFastZeroNodeSerializer,
                QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE,
            },
            merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey},
        },
        pgoldilocks::{PGoldilocksFelt, PGoldilocksHash, PoseidonHasher},
        protocol::core_types::Q256BitHash,
    };
    use psy_data::{
        prepared_block::realm::PsyPreparedRealmBlockStateUpdates,
        v1::qdata::ffs_sizes::PSY_OBJECT_FFS_SIZE_USER_LEAF,
    };
    use crate::realm::processor::ffs::layout::{
        replay_double_id_nodes_from_leaves, require_width,
    };
    use std::collections::{HashMap, HashSet};

    fn verify_double_id_node_ffs_bytes<H, Hash>(
        bytes: &[u8],
        width: usize,
        parse: impl Fn(&[u8]) -> (u64, u64, u8, u64, Hash),
    ) -> anyhow::Result<()>
    where
        H: MerkleZeroHasher<Hash>,
        Hash: Q256BitHash + Copy + PartialEq + Default + std::fmt::Debug,
    {
        require_width(bytes, width, "tree node FFS")?;
        let mut grouped: HashMap<(u64, u64), Vec<(u8, u64, Hash)>> = HashMap::new();
        for chunk in bytes.chunks_exact(width) {
            let (tree_id, tree_sub_id, level, index, value) = parse(chunk);
            grouped.entry((tree_id, tree_sub_id)).or_default().push((level, index, value));
        }
        for nodes in grouped.values() {
            let height = nodes.iter().map(|(level, _, _)| *level).max().unwrap_or(0);
            let mut tree = SimpleMemoryMerkleRecorderStore::<H, Hash>::new(height.max(1));
            replay_double_id_nodes_from_leaves(&mut tree, nodes)?;
        }
        Ok(())
    }

    fn empty_updates(old: PGoldilocksHash, new: PGoldilocksHash) -> PsyPreparedRealmBlockStateUpdates<PGoldilocksHash> {
        PsyPreparedRealmBlockStateUpdates {
            realm_id: 0,
            realm_sub_id: 0,
            unique_pending_id: 0,
            proc_checkpoint_unique_id: Default::default(),
            old_realm_root: old,
            new_realm_root: new,
            update_global_user_tree_nodes_ffs: vec![],
            update_user_contract_tree_nodes_ffs: vec![],
            update_contract_state_tree_nodes_ffs: vec![],
            update_user_leaves_ffs: vec![],
            update_contract_state_imt_leaves_ffs: vec![],
        }
    }

    #[test]
    fn history_bad_ffs() {
        let mut tree = SimpleMemoryMerkleRecorderStore::<PoseidonHasher, PGoldilocksHash>::new(8);
        let old = tree.get_root();
        let mut updates = empty_updates(old, old);
        let poison = SimpleMerkleNode {
            key: SimpleMerkleNodeKey { level: 8, index: 0 },
            value: PGoldilocksHash::from_owned_32bytes([0x11; 32]),
        };
        updates.update_global_user_tree_nodes_ffs =
            QMerkleStoreFastZeroNodeSerializer::serialize_zero_id_node_to_vec(&poison);
        let error = replay_state_updates_into_tree::<PGoldilocksFelt, PGoldilocksHash, PoseidonHasher>(
            &mut tree, &updates, 8, 8, 0, 1, &HashSet::new(),
        )
            .expect_err("poisoned GUT node must fail baseline replay");
        assert!(
            error.to_string().contains("InvalidStateUpdates"),
            "{error}"
        );
        let contract_leaf = parth_core::data::hash::merkle_store_key::QMerkleStoreSingleIdNode {
            key: parth_core::data::hash::merkle_store_key::QMerkleStoreSingleIdKey {
                tree_id: 1,
                level: 8,
                index: 0,
            },
            value: PGoldilocksHash::from_owned_32bytes([0x01; 32]),
        };
        let poison_contract = parth_core::data::hash::merkle_store_key::QMerkleStoreSingleIdNode {
            key: parth_core::data::hash::merkle_store_key::QMerkleStoreSingleIdKey {
                tree_id: 1,
                level: 4,
                index: 0,
            },
            value: PGoldilocksHash::from_owned_32bytes([0x44; 32]),
        };
        let mut contract_ffs =
            QMerkleStoreFastSingleNodeSerializer::serialize_single_id_node_to_vec(&contract_leaf);
        contract_ffs.extend_from_slice(
            &QMerkleStoreFastSingleNodeSerializer::serialize_single_id_node_to_vec(&poison_contract),
        );
        let leaf_poison = SimpleMerkleNode {
            key: SimpleMerkleNodeKey { level: 16, index: 0 },
            value: PGoldilocksHash::from_owned_32bytes([0x22; 32]),
        };
        let mut leaf_updates = empty_updates(old, old);
        leaf_updates.update_global_user_tree_nodes_ffs =
            QMerkleStoreFastZeroNodeSerializer::serialize_zero_id_node_to_vec(&leaf_poison);
        let preimage_error = replay_state_updates_into_tree::<PGoldilocksFelt, PGoldilocksHash, PoseidonHasher>(
            &mut SimpleMemoryMerkleRecorderStore::<PoseidonHasher, PGoldilocksHash>::new(8),
            &leaf_updates,
            8,
            8,
            0,
            1,
            &HashSet::new(),
        )
        .expect_err("changed GUT leaf without preimage must fail");
        assert!(
            preimage_error.to_string().contains("InvalidStateUpdates"),
            "{preimage_error}"
        );
        let contract_error = verify_double_id_node_ffs_bytes::<PoseidonHasher, PGoldilocksHash>(
            &contract_ffs,
            QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE,
            |chunk| {
                let node = QMerkleStoreFastSingleNodeSerializer::deserialize_single_id_node_from_slice::<PGoldilocksHash>(
                    chunk,
                );
                (node.key.tree_id, 0, node.key.level, node.key.index, node.value)
            },
        )
        .expect_err("poisoned contract node must fail baseline replay");
        assert!(
            contract_error.to_string().contains("InvalidStateUpdates"),
            "{contract_error}"
        );
    }

    #[test]
    fn history_poison_included_transition() {
        let mut tree = SimpleMemoryMerkleRecorderStore::<PoseidonHasher, PGoldilocksHash>::new(8);
        let old = tree.get_root();
        let mut updates = empty_updates(old, old);
        updates.update_user_leaves_ffs = vec![0u8; PSY_OBJECT_FFS_SIZE_USER_LEAF + 1];
        let error = replay_state_updates_into_tree::<PGoldilocksFelt, PGoldilocksHash, PoseidonHasher>(
            &mut tree, &updates, 8, 8, 0, 1, &HashSet::new(),
        )
            .expect_err("poisoned user-leaf width must fail");
        assert!(error.to_string().contains("InvalidStateUpdates"), "{error}");
        assert!(!error.to_string().contains("auto"));
    }

    struct CountingHeightStore {
        heights: HashMap<(u64, u64), u8>,
        calls: std::sync::atomic::AtomicUsize,
        batches: std::sync::Mutex<Vec<(u64, Vec<u64>)>>,
        fail: bool,
    }

    impl CountingHeightStore {
        fn new(heights: HashMap<(u64, u64), u8>) -> Self {
            Self {
                heights,
                calls: std::sync::atomic::AtomicUsize::new(0),
                batches: std::sync::Mutex::new(Vec::new()),
                fail: false,
            }
        }
    }

    #[async_trait::async_trait]
    impl psy_node_core::psy_core_db::traits::full::PsyNodeCoreDatabaseBasicContractInfoStoreReader<
        PGoldilocksFelt,
        PGoldilocksHash,
    > for CountingHeightStore
    {
        async fn get_contract_tree_heights(
            &self,
            checkpoint_id: u64,
            contract_ids: &[u64],
        ) -> anyhow::Result<Vec<u8>> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.batches
                .lock()
                .expect("height batch log")
                .push((checkpoint_id, contract_ids.to_vec()));
            if self.fail {
                anyhow::bail!("injected height store failure");
            }
            Ok(contract_ids
                .iter()
                .map(|contract_id| self.heights.get(&(checkpoint_id, *contract_id)).copied().unwrap_or(0))
                .collect())
        }
    }


    // Same C+I union the verify path feeds the loader: CST groups (1,7),(2,7),(1,8)
    // then IMT finals (1,7,0),(1,9,0) with a duplicate (1,7,0) that or_insert keeps first.
    const C_AND_I_IDS: [u64; 5] = [7, 7, 8, 7, 9];


    #[tokio::test]
    async fn previous_heights_batch_unique_c_and_i_at_historical_checkpoint() {
        let previous = 10u64;
        let store = CountingHeightStore::new(HashMap::from([
            ((previous, 7), 8),
            ((previous, 8), 16),
            ((previous, 9), 24),
            ((previous + 1, 7), 32),
        ]));
        let heights = load_previous_contract_heights::<_, PGoldilocksFelt, PGoldilocksHash>(
            &store,
            previous,
            C_AND_I_IDS,
        )
        .await
        .expect("batch heights");
        assert_eq!(store.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        let batches = store.batches.lock().expect("height batch log");
        assert_eq!(batches.as_slice(), &[(previous, vec![7, 8, 9])]);
        drop(batches);
        assert_eq!(require_previous_contract_height(&heights, 7).unwrap(), 8);
        assert_eq!(require_previous_contract_height(&heights, 8).unwrap(), 16);
        assert_eq!(require_previous_contract_height(&heights, 9).unwrap(), 24);
        let later = load_previous_contract_heights::<_, PGoldilocksFelt, PGoldilocksHash>(&store, previous + 1, [7])
            .await
            .expect("later checkpoint is a different key");
        assert_eq!(require_previous_contract_height(&later, 7).unwrap(), 32);
    }

    #[tokio::test]
    async fn previous_heights_reject_zero_missing_and_injected_db_error() {
        let previous = 10u64;
        let store = CountingHeightStore::new(HashMap::from([((previous, 7), 0)]));
        let heights = load_previous_contract_heights::<_, PGoldilocksFelt, PGoldilocksHash>(&store, previous, [7, 8])
            .await
            .expect("missing maps to zero without a store error");
        let zero = require_previous_contract_height(&heights, 7).expect_err("zero height must reject");
        assert!(zero.to_string().contains("height is zero"), "{zero}");
        let missing = require_previous_contract_height(&heights, 8).expect_err("absent height must reject");
        assert!(missing.to_string().contains("height is zero"), "{missing}");
        let failing = CountingHeightStore {
            fail: true,
            ..CountingHeightStore::new(HashMap::new())
        };
        let error = load_previous_contract_heights::<_, PGoldilocksFelt, PGoldilocksHash>(&failing, previous, [7])
            .await
            .expect_err("store failure must reject");
        assert!(error.to_string().contains("MissingAuthenticatedState"), "{error}");
        assert!(error.to_string().contains("injected height store failure"), "{error}");
        assert_eq!(failing.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
