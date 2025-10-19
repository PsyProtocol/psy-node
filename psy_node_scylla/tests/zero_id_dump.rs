use cf_utils::timer::DebugTimer;
use parth_common::memory_stores::mem_tree_v3::SimpleMemoryMerkleStoreV3;
use rand::{SeedableRng, RngCore, Rng};
use rand_chacha::ChaCha12Rng;
use std::{collections::HashMap, hash::Hash, sync::{Arc, RwLock}};

use bincode::de;
use dashmap::DashMap;
use parth_core::{crypto::hash::traits::MerkleZeroHasher, data::{db::table::QDatabaseTableRoutingKey, hash::{hash256::Hash256, merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}}, serializable::QPDPair}, protocol::core_types::{Q256BitHash, QDBHashBase}, utils::QPGenRandom};
use parth_crypto::hash::sha256::CoreSha256Hasher;
use parth_node_scylla::{core::ScyllaCoreStore, tables::merkle::ScyllaMerkleNodesZeroPreparedStatements};
use psy_data::v1::qdata::user::PQEDUserLeaf;
use psy_node_core::store::traits::core_db::{CoreDatabaseStore, CoreDatabaseZeroIdMerkleDumpReader, CoreDatabaseZeroIdMerkleReader, CoreDatabaseZeroIdMerkleStore};

use serde::Serialize;



// A function to create a 32-byte seed from any hashable input (like a string)
fn get_seed_for_rng(s: &str) -> [u8; 32] {
    CoreSha256Hasher::hash_bytes(s.as_bytes()).0
}
fn rand_leaf_node_in_tree<R: RngCore + Rng, Hash: Q256BitHash>(rng: &mut R, tree_height: usize) -> SimpleMerkleNode<Hash> {
    let level: u8 = tree_height as u8;
    let index: u64 = rng.gen_range(0..(1u64 << (tree_height as u8 - level)));
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
fn random_leaves_in_tree<R: RngCore, Hash: Q256BitHash>(count: usize, rng: &mut R, tree_height: usize) -> Vec<SimpleMerkleNode<Hash>> {
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
        /* 
        if let Some(checkpoint) = self.inserted_checkpoints.read().unwrap().last(){
            if *checkpoint == new_checkpoint_id {
                return;
            }else if *checkpoint < new_checkpoint_id {
                let mut inserted_checkpoints = self.inserted_checkpoints.write().unwrap();
                inserted_checkpoints.push(new_checkpoint_id);
                return;
            }else{
                // greater than our current, we need to insert and sort
                // we will sort after insert
                let mut inserted_checkpoints = self.inserted_checkpoints.write().unwrap();
                if !inserted_checkpoints.contains(&new_checkpoint_id) {
                    inserted_checkpoints.push(new_checkpoint_id);
                    inserted_checkpoints.sort_unstable();
                }
            }
        }else{
            let mut inserted_checkpoints = self.inserted_checkpoints.write().unwrap();
            inserted_checkpoints.push(new_checkpoint_id);
        }
        */
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
    }
    pub fn get_all_nodes_as_of_checkpoint(&self, checkpoint_id: u64) -> Vec<QPDPair<K, V>> {
        let accumulated_ids = self.inserted_checkpoints.read().unwrap().clone().into_iter().filter(|x| *x <= checkpoint_id).collect::<Vec<u64>>();
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

const EX_ZERO_ID_TREE_A_HEIGHT: usize = 32;
const EX_ZERO_ID_TREE_B_HEIGHT: usize = 22;
type ExBidirectionalMappingTableAK1 = u64;
type ExBidirectionalMappingTableAK2 = Hash256;
type ExBidirectionalMappingTableBK1 = Hash256;
type ExBidirectionalMappingTableBK2 = Hash256;
type ExKivTableAValue = PQEDUserLeaf<u64, Hash256>;
type ExKivTableBValue = PQEDUserLeaf<u64, Hash256>;
type ExObjSingleIdTableAValue = PQEDUserLeaf<u64, Hash256>;
type ExObjDoubleIdTableBValue = PQEDUserLeaf<u64, Hash256>;
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

impl SimpleStoreEx {
    pub async fn setup(store: Arc<ScyllaCoreStore<ExHash, ExHasher>>) -> anyhow::Result<Self> {
        let merkle_node_zero_id_table_a = store
            .init_zero_id_merkle_table("merkle_node_zero_id_table_a", get_rk(13), EX_ZERO_ID_TREE_A_HEIGHT as u8)
            .await?;
        let merkle_node_zero_id_table_b = store
            .init_zero_id_merkle_table("merkle_node_zero_id_table_b", get_rk(14), EX_ZERO_ID_TREE_B_HEIGHT as u8)
            .await?;
        //QSimpleStore::new(store, kiv_table_a, kiv_table_b,
        // bidirectional_mapping_table_a, bidirectional_mapping_table_b,
        // obj_single_id_table_a, obj_single_id_table_b, obj_double_id_table_a,
        // obj_double_id_table_b, u64_table_a, u64_table_b,
        // u64_u128_bi_directional_mapping_table_a,
        // u64_u128_bi_directional_mapping_table_b, merkle_node_zero_id_table_a,
        // merkle_node_zero_id_table_b, merkle_node_single_id_table_a,
        // merkle_node_single_id_table_b, merkle_node_double_id_table_a,
        // merkle_node_double_id_table_b, tag_tree_table_a, tag_tree_table_b)

        let simple_store = QZeroIdStore::new(
            store,
            Arc::new(merkle_node_zero_id_table_a),
            Arc::new(merkle_node_zero_id_table_b),
        );
        Ok(Self {
            store: simple_store,
        })
    }

    async fn overwrite_test(&self, seed: &str, tree_height: usize) -> anyhow::Result<()> {
        let mut rng = ChaCha12Rng::from_seed(get_seed_for_rng(seed));
        rng.next_u64();
        
        let mut current_checkpoint = 0u64;
        let mut timer = DebugTimer::new("merkle_dumper");
        let mut total_leaves_inserted = 0usize;
        for i in 0..100 {
            let count = rng.next_u32() % 100;
            total_leaves_inserted += count as usize;
            let leaves = random_leaves_in_tree::<ChaCha12Rng, ExHash>(count as usize, &mut rng, tree_height);
            self.store
                .set_zero_id_merkle_nodes_for_checkpoint(
                    &self.store.merkle_node_zero_id_table_a,
                    current_checkpoint,
                    &leaves,
                )
                .await?;
            if i != 99 {
                current_checkpoint += rng.next_u32() as u64 % 50 + 1;
            }
        }
        timer.event(format!("inserted {} leaves", total_leaves_inserted));
        println!("done inserting nodes {} up to checkpoint {}", total_leaves_inserted, current_checkpoint);
        
        //let hash_map_injestor = SimpleMemoryMerkleStoreV3::<ExHasher, ExHash>::new(EX_ZERO_ID_TREE_A_HEIGHT as u8);
        
        //let mut dumped_nodes = Vec::new();

        let recorded = self.store.recorded_map.get(&self.store.merkle_node_zero_id_table_a.get_table_unique_identifier()).unwrap();
        let recorded_nodes = recorded.get_all_nodes_as_of_checkpoint(current_checkpoint - 1);
        let expected_map = HashMap::<SimpleMerkleNodeKey, ExHash>::from_iter(
            recorded_nodes.iter().map(|x| (x.key.clone(), x.value.clone()))
        );
        timer.event(format!("got {} leaves from the recording", recorded_nodes.len()));

        let keys = recorded_nodes.iter().map(|x| x.key).collect::<Vec<SimpleMerkleNodeKey>>();
        println!("recorded nodes count: {}", recorded_nodes.len());
        let fetched_nodes = self.store.store.db_select_many_zero_id_merkle_nodes_max_checkpoint(
            &self.store.merkle_node_zero_id_table_a,
            current_checkpoint,
            &keys,
        ).await?;
        timer.event(format!("fetched {} leaves from the database", fetched_nodes.len()));
        for (fetched_value, key) in fetched_nodes.iter().zip(keys.iter()) {
            if fetched_value != expected_map.get(key).unwrap() {
                return Err(anyhow::anyhow!("mismatched node value for key {:?}: recorded {:?} vs fetched {:?}", key, expected_map.get(key).unwrap(), fetched_value));
            }
        }
        timer.lap("verified all fetched nodes match recorded nodes");


        let dump_map = Arc::new(DashMap::<SimpleMerkleNodeKey, ExHash>::new());
        let level_u8 = EX_ZERO_ID_TREE_A_HEIGHT as u8;

        self.store.store.dump_all_zero_id_merkle_node_leaves_chunked(
            &self.store.merkle_node_zero_id_table_a,
            current_checkpoint,
            |chunk| {
                // Clone the Arc *outside* the async block.
                // This `dump_map_clone` is what the async block will capture and move.
                let dump_map_clone = dump_map.clone();

                async move {
                    // I noticed in your new code you were constructing a new key,
                    // but the chunk now provides the full SimpleMerkleNodeKey.
                    // This is a small correction to align with the latest `dump` function.
                    for (key, value) in chunk {
                        println!("got leaf at index: {}", key);
                        dump_map_clone.insert(SimpleMerkleNodeKey { level: level_u8, index: key }, value);
                    }
                    Ok(())
                }
            },
        ).await?;

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
        
        self.overwrite_test("test123", EX_ZERO_ID_TREE_A_HEIGHT as usize).await?;
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
