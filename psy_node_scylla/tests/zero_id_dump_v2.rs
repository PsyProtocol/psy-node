use cf_utils::timer::DebugTimer;
use rand::{thread_rng, Rng, RngCore};
use std::{collections::HashMap, hash::Hash, sync::{Arc, RwLock}};

use dashmap::DashMap;
use parth_core::{crypto::hash::traits::MerkleZeroHasher, data::{db::table::QDatabaseTableRoutingKey, hash::{hash256::Hash256, merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}}, serializable::QPDPair}, protocol::core_types::{QDBHashBase}};
use parth_crypto::hash::sha256::CoreSha256Hasher;
use parth_node_scylla::{core::ScyllaCoreStore, tables::merkle::ScyllaMerkleNodesZeroPreparedStatements};
use psy_node_core::store::traits::{core_db::{CoreDatabaseZeroIdMerkleDumpReader, CoreDatabaseZeroIdMerkleReader, CoreDatabaseZeroIdMerkleStore}, helpers::db_helper_zero_id_merkle_node_simple_set_leaves};

use serde::Serialize;


/*
// A function to create a 32-byte seed from any hashable input (like a string)
fn get_seed_for_rng(s: &str) -> [u8; 32] {
    CoreSha256Hasher::hash_bytes(s.as_bytes()).0
}

*/
fn rand_leaf_node_in_tree<R: RngCore + Rng, Hash: QDBHashBase>(rng: &mut R, tree_height: usize) -> SimpleMerkleNode<Hash> {
    let level: u8 = tree_height as u8;
    // [FIXED] The original code `(1u64 << (tree_height as u8 - level))` always resulted in `1u64 << 0`,
    // so the index was always 0. The correct range for indices at the leaf level is up to 2^level.
    let index: u64 = rng.gen_range(0..(1u64 << level));
    let key = SimpleMerkleNodeKey { level, index };
    let value: [u8; 32] = [
        rng.next_u64().to_le_bytes(),
        rng.next_u64().to_le_bytes(),
        rng.next_u64().to_le_bytes(),
        rng.next_u64().to_le_bytes(),
    ].concat().try_into().unwrap();

    let value = Hash::from_owned_32bytes(value);
    SimpleMerkleNode { key, value }
}
fn random_leaves_in_tree<R: RngCore, Hash: QDBHashBase>(count: usize, rng: &mut R, tree_height: usize) -> Vec<SimpleMerkleNode<Hash>> {
    let mut nodes = Vec::with_capacity(count);
    for _ in 0..count {
        nodes.push(rand_leaf_node_in_tree(rng, tree_height));
    }
    nodes
}


pub trait THStandardTableIdentifier: Clone + Send + Sync {
    fn get_table_unique_identifier(&self) -> String;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InsertedNodeBatch<T> {
    pub checkpoint_id: u64,
    pub nodes: Vec<T>,
}
#[derive(Debug, Clone)]
pub struct NodeCheckpointRecorder<K: Hash+ Clone + Eq, V: Clone + Eq> {
    pub recorded_checkpoints: DashMap<u64, DashMap<K, V>>,
    pub inserted_checkpoints: Arc<RwLock<Vec<u64>>>,

}
impl <K: Hash + Clone + Eq, V: Clone + Eq> NodeCheckpointRecorder<K, V> {
    pub fn new() -> Self {
        Self {
            recorded_checkpoints: DashMap::new(),
            inserted_checkpoints: Arc::new(RwLock::new(Vec::new())),
        }
    }
    pub fn contains_checkpoint(&self, checkpoint_id: u64) -> bool {
        self.recorded_checkpoints.contains_key(&checkpoint_id)
    }
    pub fn insert_checkpoint_if_not_exists(&self, new_checkpoint_id: u64) {
        if !self.contains_checkpoint(new_checkpoint_id) {
            let mut inserted_checkpoints = self.inserted_checkpoints.write().unwrap();
            if !inserted_checkpoints.contains(&new_checkpoint_id) {
                inserted_checkpoints.push(new_checkpoint_id);
            }
        }
    }
    pub fn record_node(&self, checkpoint_id: u64, key: K, value: V) {
        self.insert_checkpoint_if_not_exists(checkpoint_id);
        if !self.recorded_checkpoints.contains_key(&checkpoint_id) {
            self.recorded_checkpoints.insert(checkpoint_id, DashMap::new());
        }
        let checkpoint_map = self.recorded_checkpoints.entry(checkpoint_id).or_insert_with(|| DashMap::new());
        checkpoint_map.insert(key, value);
    }
    pub fn record_nodes(&self, checkpoint_id: u64, key: &[QPDPair<K, V>]) {
        self.insert_checkpoint_if_not_exists(checkpoint_id);
        if !self.recorded_checkpoints.contains_key(&checkpoint_id) {
            self.recorded_checkpoints.insert(checkpoint_id, DashMap::new());
        }
        let checkpoint_map = self.recorded_checkpoints.entry(checkpoint_id).or_insert_with(|| DashMap::new());
        for pair in key {
            checkpoint_map.insert(pair.key.clone(), pair.value.clone());
        }
    }pub fn get_all_nodes_as_of_checkpoint(&self, checkpoint_id: u64) -> Vec<QPDPair<K, V>> {
        let mut accumulated_ids = self.inserted_checkpoints.read().unwrap().clone().into_iter().filter(|x| *x <= checkpoint_id).collect::<Vec<u64>>();
        // FIX: Ensure checkpoints are processed in chronological order.
        accumulated_ids.sort_unstable(); 
        
        let mut all_nodes = HashMap::<K, V>::new();
        for chk_id in accumulated_ids {
            if let Some(checkpoint_map) = self.recorded_checkpoints.get(&chk_id) {
                for entry in checkpoint_map.iter() {
                    all_nodes.insert(entry.key().clone(), entry.value().clone());
                }
            }
        }
        all_nodes.into_iter().map(|(key, value)| {
            QPDPair { key, value }
        }).collect()
    }

}

pub trait THHasher<Hash: QDBHashBase>: MerkleZeroHasher<Hash> + Send + Sync + Sized + 'static {}
impl<T: MerkleZeroHasher<Hash> + Send + Sync + Sized + 'static, Hash: QDBHashBase> THHasher<Hash> for T {}
#[derive(Clone)]
pub struct QZeroIdStore<
    const ZERO_ID_TREE_A_HEIGHT: usize,
    const ZERO_ID_TREE_B_HEIGHT: usize,
    Hash: QDBHashBase,
    Hasher: THHasher<Hash>,
    ZeroIdMerkleTableIdentifier: THStandardTableIdentifier,
    S: CoreDatabaseZeroIdMerkleStore< Hash, Hasher, ZeroIdMerkleTableIdentifier > 
        + CoreDatabaseZeroIdMerkleStore<Hash, Hasher, ZeroIdMerkleTableIdentifier> 
        + CoreDatabaseZeroIdMerkleDumpReader<Hash, Hasher, ZeroIdMerkleTableIdentifier>
        + Send
        + Sync,
> {
    pub store: Arc<S>,
    pub recorded_map: DashMap<String, NodeCheckpointRecorder<SimpleMerkleNodeKey, Hash>>,

    // start objects
    // start trees
    pub merkle_node_zero_id_table_a: Arc<ZeroIdMerkleTableIdentifier>,
    pub merkle_node_zero_id_table_b: Arc<ZeroIdMerkleTableIdentifier>,



    // start phantom core
    _phantom_hash: std::marker::PhantomData<Hash>,
    _phantom_hasher: std::marker::PhantomData<Hasher>,

}

//#[async_trait]
impl<
    const ZERO_ID_TREE_A_HEIGHT: usize,
    const ZERO_ID_TREE_B_HEIGHT: usize,
    Hash: QDBHashBase,
    Hasher: THHasher<Hash>,
    ZeroIdMerkleTableIdentifier: THStandardTableIdentifier,
    S: CoreDatabaseZeroIdMerkleStore< Hash, Hasher, ZeroIdMerkleTableIdentifier > 
        + CoreDatabaseZeroIdMerkleStore<Hash, Hasher, ZeroIdMerkleTableIdentifier> 
        + CoreDatabaseZeroIdMerkleDumpReader<Hash, Hasher, ZeroIdMerkleTableIdentifier>
        + Send
        + Sync,
    >
    QZeroIdStore<
        ZERO_ID_TREE_A_HEIGHT,
        ZERO_ID_TREE_B_HEIGHT,
        Hash,
        Hasher,
        ZeroIdMerkleTableIdentifier,
        S,
    >
{
    pub fn new(
        store: Arc<S>,

        // start objects
        merkle_node_zero_id_table_a: Arc<ZeroIdMerkleTableIdentifier>,
        merkle_node_zero_id_table_b: Arc<ZeroIdMerkleTableIdentifier>,
    ) -> Self {
        Self {
                    recorded_map: DashMap::new(),

            store,
            merkle_node_zero_id_table_a,
            merkle_node_zero_id_table_b,
            _phantom_hash: std::marker::PhantomData,
            _phantom_hasher: std::marker::PhantomData,
        }
    }

}

// START: TH Helpers
//#[async_trait]
impl<
    const ZERO_ID_TREE_A_HEIGHT: usize,
    const ZERO_ID_TREE_B_HEIGHT: usize,
    Hash: QDBHashBase,
    Hasher: THHasher<Hash>,
    ZeroIdMerkleTableIdentifier: THStandardTableIdentifier,
    S: CoreDatabaseZeroIdMerkleStore< Hash, Hasher, ZeroIdMerkleTableIdentifier > 
        + CoreDatabaseZeroIdMerkleStore<Hash, Hasher, ZeroIdMerkleTableIdentifier> 
        + CoreDatabaseZeroIdMerkleDumpReader<Hash, Hasher, ZeroIdMerkleTableIdentifier>
        + Send
        + Sync,
    >
    QZeroIdStore<
        ZERO_ID_TREE_A_HEIGHT,
        ZERO_ID_TREE_B_HEIGHT,
        Hash,
        Hasher,
        ZeroIdMerkleTableIdentifier,
        S,
    >
{
    pub async fn set_zero_id_merkle_nodes_for_checkpoint(&self, table: &ZeroIdMerkleTableIdentifier, checkpoint_id: u64, nodes: &[SimpleMerkleNode<Hash>]) -> anyhow::Result<()> {
        self.store
            .db_set_zero_id_merkle_nodes_batch(
                table,
                checkpoint_id,
                &nodes,
            )
            .await?;
        db_helper_zero_id_merkle_node_simple_set_leaves(&self.store, table, checkpoint_id, 0, 512, nodes).await?;
        let tbl_map = self.recorded_map.entry(table.get_table_unique_identifier()).or_insert_with(|| NodeCheckpointRecorder::new());
        tbl_map.record_nodes(checkpoint_id, &nodes.iter().map(|x| {
            QPDPair {
                key: x.key,
                value: x.value
            }
        }).collect::<Vec<_>>());
        Ok(())
    }
    
}

const EX_ZERO_ID_TREE_A_HEIGHT: usize = 24;
const EX_ZERO_ID_TREE_B_HEIGHT: usize = 22;
// Unused type aliases removed
type ExHash = Hash256;
type ExHasher = CoreSha256Hasher;


impl THStandardTableIdentifier for ScyllaMerkleNodesZeroPreparedStatements {
    fn get_table_unique_identifier(&self) -> String {
        self.table_name.clone()
    }
}
pub struct SimpleStoreEx {
    pub store: QZeroIdStore<
        EX_ZERO_ID_TREE_A_HEIGHT,
        EX_ZERO_ID_TREE_B_HEIGHT,
        ExHash,
        ExHasher,
        ScyllaMerkleNodesZeroPreparedStatements,
        ScyllaCoreStore<ExHash, ExHasher>,
    >,
}

fn get_rk(table_id: u64) -> QDatabaseTableRoutingKey {
    QDatabaseTableRoutingKey::new_with_connection_empty_secondary_routing_key(table_id, 0)
}

fn unique_parent_merkle_keys(level: &[SimpleMerkleNodeKey]) -> Vec<SimpleMerkleNodeKey> {
    let mut parent_keys = level.iter().map(|x| x.parent()).collect::<Vec<SimpleMerkleNodeKey>>();
    parent_keys.sort_unstable();
    parent_keys.dedup();
    parent_keys
}

impl SimpleStoreEx {
    pub async fn setup(store: Arc<ScyllaCoreStore<ExHash, ExHasher>>) -> anyhow::Result<Self> {
        let merkle_node_zero_id_table_a = store
            .init_zero_id_merkle_table("merkle_node_zero_id_table_a", get_rk(13), EX_ZERO_ID_TREE_A_HEIGHT as u8)
            .await?;
        let merkle_node_zero_id_table_b = store
            .init_zero_id_merkle_table("merkle_node_zero_id_table_b", get_rk(14), EX_ZERO_ID_TREE_B_HEIGHT as u8)
            .await?;

        let simple_store = QZeroIdStore::new(
            store,
            Arc::new(merkle_node_zero_id_table_a),
            Arc::new(merkle_node_zero_id_table_b),
        );
        Ok(Self {
            store: simple_store,
        })
    }

    async fn overwrite_test(&self, _seed: &str, tree_height: usize) -> anyhow::Result<()> {
        let mut rng = thread_rng();//ChaCha12Rng::from_seed(get_seed_for_rng(seed));
        rng.next_u64();
        
        let mut current_checkpoint = 0u64;
        let mut timer = DebugTimer::new("merkle_dumper");
        let mut total_leaves_inserted = 0usize;
        for i in 0..100 {
            let count =(rng.next_u32() % 5000) + 1;
            total_leaves_inserted += count as usize;
            let leaves = random_leaves_in_tree::<_, ExHash>(count as usize, &mut rng, tree_height);
            self.store
                .set_zero_id_merkle_nodes_for_checkpoint(
                    &self.store.merkle_node_zero_id_table_a,
                    current_checkpoint,
                    &leaves,
                )
                .await?;
            current_checkpoint += rng.next_u32() as u64 % 50 + 1;
            println!("inserted batch {} with {} leaves up to checkpoint {}", i, count, current_checkpoint);
            
        }
        timer.event(format!("inserted {} leaves", total_leaves_inserted));
        println!("done inserting nodes {} up to checkpoint {}", total_leaves_inserted, current_checkpoint);
        
        let recorded = self.store.recorded_map.get(&self.store.merkle_node_zero_id_table_a.get_table_unique_identifier()).unwrap();
        // [FIXED] The original code used `current_checkpoint - 1`, which excluded the last batch of writes from the verification.
        let recorded_nodes = recorded.get_all_nodes_as_of_checkpoint(current_checkpoint);
        let expected_map = HashMap::<SimpleMerkleNodeKey, ExHash>::from_iter(
            recorded_nodes.iter().map(|x| (x.key.clone(), x.value.clone()))
        );
        timer.event(format!("got {} leaves from the recording", recorded_nodes.len()));

        let keys = recorded_nodes.iter().map(|x| x.key).collect::<Vec<SimpleMerkleNodeKey>>();
        let root_key = SimpleMerkleNodeKey {
            level: 0,
            index: 0,
        };
        let mut level = unique_parent_merkle_keys(&keys);
        let mut ctr = 1;
        while level.len() > 1 {
            let zero_hash = ExHasher::get_zero_hash(ctr);
            
            level = unique_parent_merkle_keys(&level);
            let mut values = self.store.store.db_select_many_zero_id_merkle_nodes_max_checkpoint(&self.store.merkle_node_zero_id_table_a, current_checkpoint, &level).await?;
            for v in values.iter() {
                if *v == zero_hash {
                    return Err(anyhow::anyhow!("found zero hash at level {} during verification", ctr));
                }
            }
            values.sort_unstable();
            values.dedup();
            println!("{} unique nodes at level {}", values.len(), ctr);
            ctr += 1;
        }
        
        let root = self.store.store.db_select_zero_id_merkle_node_max_checkpoint(&self.store.merkle_node_zero_id_table_a, current_checkpoint, &root_key).await?;
        assert!(root != ExHasher::get_zero_hash(tree_height as usize));
        println!("recorded nodes count: {}", recorded_nodes.len());
        let fetched_nodes = self.store.store.db_select_many_zero_id_merkle_nodes_max_checkpoint(
            &self.store.merkle_node_zero_id_table_a,
            current_checkpoint,
            &keys,
        ).await?;
        timer.event(format!("fetched {} leaves from the database", fetched_nodes.len()));
        
        // This check is now valid because both recorded and fetched values are up-to-date.
        for (fetched_value, key) in fetched_nodes.iter().zip(keys.iter()) {
            if fetched_value != expected_map.get(key).unwrap() {
                return Err(anyhow::anyhow!("mismatched node value for key {:?}: recorded {:?} vs fetched {:?}", key, expected_map.get(key).unwrap(), fetched_value));
            }
        }
        timer.lap("verified all fetched nodes match recorded nodes");


        let dump_map = Arc::new(DashMap::<SimpleMerkleNodeKey, ExHash>::new());
        let level_u8 = EX_ZERO_ID_TREE_A_HEIGHT as u8;
/*
        self.store.store.dump_all_zero_id_merkle_node_leaves_chunked(
            &self.store.merkle_node_zero_id_table_a,
            current_checkpoint,
            |chunk| {
                let dump_map_clone = dump_map.clone();
                async move {
                    for (key, value) in chunk {
                        // Correctly use the index from the chunk 'key'
                        dump_map_clone.insert(SimpleMerkleNodeKey { level: level_u8, index: key }, value);
                    }
                    Ok(())
                }
            },
        ).await?;
*/

        let dumped_map = self.store.store.db_dump_all_zero_id_merkle_node_leaves_chunked(
            &self.store.merkle_node_zero_id_table_a,
            current_checkpoint,
        ).await?;
        for (key, value) in dumped_map.into_iter() {
            dump_map.insert(SimpleMerkleNodeKey { level: level_u8, index: key }, value);
        }
        timer.event(format!("dumped {} leaves", dump_map.len()));

        if recorded_nodes.len() != dump_map.len() {
            return Err(anyhow::anyhow!("mismatched node counts: recorded {} vs dumped {}", recorded_nodes.len(), dump_map.len()));
        }
        for node in recorded_nodes.iter() {
            if !dump_map.contains_key(&node.key) {
                return Err(anyhow::anyhow!("missing node in dump: key {:?}", node.key));
            }
            let dumped_value = dump_map.get(&node.key).unwrap();
            if *dumped_value != node.value {
                return Err(anyhow::anyhow!("mismatched node value for key {:?}: recorded {:?} vs dumped {:?}", node.key, node.value, dumped_value));
            }
        }
        timer.lap("verified all dumped nodes match recorded nodes");
        Ok(())


    }

    pub async fn basic_test_1(&self) -> anyhow::Result<()> {
        
        self.overwrite_test("aoiwefjowfej12", EX_ZERO_ID_TREE_A_HEIGHT as usize).await?;
        Ok(())
    }
}


#[tokio::test]
#[ignore = "database slow"]
async fn simple_store_basic_test_1() -> anyhow::Result<()> {
    let key_space = format!("psy_node_zero_id_dump_test_v1_{}", rand::random::<u64>());
    let scylla_db = ScyllaCoreStore::<ExHash, ExHasher>::new(0, 0, key_space, &[
        "127.0.0.1:9042".to_string()
    ]).await?;
    let simple_store = SimpleStoreEx::setup(Arc::new(scylla_db)).await?;
    println!("setup simple store");
    simple_store.basic_test_1().await?;
    Ok(())
}