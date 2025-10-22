use std::sync::Arc;

use parth_core::
    data::
        hash::
            hash256::Hash256
        
    
;
use parth_crypto::hash::sha256::CoreSha256Hasher;

use psy_node_store_memory::cbs_store::{InMemoryCoreStore, InMemoryTableIdentifier};
use psy_data::v1::qdata::user::PQEDUserLeaf;
use psy_node_core::test_helpers::jumbo_store::QJumboStore;
// ================================================================================================
// REPLACEMENT FOR TEST HARNESS SETUP
// ================================================================================================

// --- Test Type Definitions & Setup ---
const EX_ZERO_ID_TREE_A_HEIGHT: usize = 32;
const EX_ZERO_ID_TREE_B_HEIGHT: usize = 22;
const EX_SINGLE_ID_TREE_A_HEIGHT: usize = 32;
const EX_SINGLE_ID_TREE_B_HEIGHT: usize = 24;
const EX_DOUBLE_ID_TREE_A_HEIGHT: usize = 48;
const EX_DOUBLE_ID_TREE_B_HEIGHT: usize = 60;
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

type InMemoryTestStore = InMemoryCoreStore<ExHash, ExHasher>;

pub struct SimpleStoreEx {
    pub store: QJumboStore<
        EX_ZERO_ID_TREE_A_HEIGHT,
        EX_ZERO_ID_TREE_B_HEIGHT,
        EX_SINGLE_ID_TREE_A_HEIGHT,
        EX_SINGLE_ID_TREE_B_HEIGHT,
        EX_DOUBLE_ID_TREE_A_HEIGHT,
        EX_DOUBLE_ID_TREE_B_HEIGHT,
        ExBidirectionalMappingTableAK1,
        ExBidirectionalMappingTableAK2,
        ExBidirectionalMappingTableBK1,
        ExBidirectionalMappingTableBK2,
        ExKivTableAValue,
        ExKivTableBValue,
        ExObjSingleIdTableAValue,
        ExObjDoubleIdTableBValue,
        ExHash,
        ExHasher,
        InMemoryTableIdentifier,
        InMemoryTableIdentifier,
        InMemoryTableIdentifier,
        InMemoryTableIdentifier,
        InMemoryTableIdentifier,
        InMemoryTableIdentifier,
        InMemoryTableIdentifier,
        InMemoryTableIdentifier,
        InMemoryTableIdentifier,
        InMemoryTableIdentifier,
        InMemoryTableIdentifier,
        InMemoryTestStore,
    >,
}

impl SimpleStoreEx {
    pub async fn setup(store: Arc<InMemoryTestStore>) -> anyhow::Result<Self> {
        let keyspace = format!("in_memory_test_ex1_{}", rand::random::<u64>());
        let simple_store = QJumboStore::new(
            store,
            Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "KivTableA")),
            Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "KivTableB")),
            Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "BidirectionalMappingTableA")),
            Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "BidirectionalMappingTableB")),
            Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "ObjSingleIdTableA")),
            Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "ObjSingleIdTableB")),
            Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "ObjDoubleIdTableA")),
            Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "ObjDoubleIdTableB")),
            Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "U64TableA")),
            Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "U64TableB")),
            Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "U64U128BiDirectionalMappingTableA")),
            Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "U64U128BiDirectionalMappingTableB")),
            Arc::new(InMemoryTableIdentifier::new_treee_with_keyspace(&keyspace, "MerkleNodeZeroIdTableA", EX_ZERO_ID_TREE_A_HEIGHT as u8)),
            Arc::new(InMemoryTableIdentifier::new_treee_with_keyspace(&keyspace, "MerkleNodeZeroIdTableB", EX_ZERO_ID_TREE_B_HEIGHT as u8)),
            Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "MerkleNodeSingleIdTableA")),
            Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "MerkleNodeSingleIdTableB")),
            Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "MerkleNodeDoubleIdTableA")),
            Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "MerkleNodeDoubleIdTableB")),
            Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "TagTreeTableA")),
            Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "TagTreeTableB")),
            Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "HashIdToValueU64TableA")),
        );
        Ok(Self { store: simple_store })
    }

    pub async fn basic_test_1(&self) -> anyhow::Result<()> {
        println!("starting basic_test_1");
        self.store.th_test_tag_tree_medium(&self.store.tag_tree_table_a, 54321).await?;
        self.store.th_test_tag_tree_v2(&self.store.tag_tree_table_a, 12345).await?;
        self.store.th_test_tag_tree_tiny(&self.store.tag_tree_table_a, 123).await?;
        println!("finished th_test_tag_tree_v2");
        self.store.th_test_tag_tree_small(&self.store.tag_tree_table_a, 888).await?;
        //self.store.th_test_tag_tree_basic(&self.store.tag_tree_table_a, 999).await?;
        //println!("finished small tag tree test");
        //println!("finished basic tag tree test");

        // u128 <-> u64 bi-directional mapping tests
        self.store.th_test_u128_u64_pairs_table_1(&self.store.u64_u128_bi_directional_mapping_table_a).await?;

        // u64 value table tests
        self.store.th_test_u64_table_1(&self.store.u64_table_a).await?;

        // single checkpointed object id tests
        self.store.th_test_single_checkpointed_object_1_full_history_1::<ExObjSingleIdTableAValue>(&self.store.obj_single_id_table_a).await?;
        // ensure that we can have multiple different objects in the same table and they do not interfere
        self.store.th_test_single_checkpointed_object_1_full_history_1::<ExObjSingleIdTableAValue>(&self.store.obj_single_id_table_a).await?;
        self.store.th_test_single_checkpointed_object_1_full_history_1::<ExObjSingleIdTableAValue>(&self.store.obj_single_id_table_b).await?;


        self.store.th_test_single_checkpointed_object_1_full_history_2::<ExObjSingleIdTableAValue>(&self.store.obj_single_id_table_a).await?;
        self.store.th_test_single_checkpointed_object_1_full_history_3::<ExObjSingleIdTableAValue>(&self.store.obj_single_id_table_a).await?;
        self.store.th_test_single_checkpointed_object_1_full_history_2::<ExObjSingleIdTableAValue>(&self.store.obj_single_id_table_b).await?;
        self.store.th_test_single_checkpointed_object_1_full_history_3::<ExObjSingleIdTableAValue>(&self.store.obj_single_id_table_b).await?;
        self.store.th_test_single_id_merkle_nodes_basic(&self.store.merkle_node_single_id_table_a, 1337, EX_SINGLE_ID_TREE_A_HEIGHT as u8).await?;
        self.store.th_test_double_checkpointed_object_1_full_history_1::<ExObjDoubleIdTableBValue>(&self.store.obj_double_id_table_b).await?;
        self.store.th_test_double_checkpointed_object_1_full_history_2::<ExObjDoubleIdTableBValue>(&self.store.obj_double_id_table_b).await?;
        self.store.th_test_double_checkpointed_object_1_full_history_3::<ExObjDoubleIdTableBValue>(&self.store.obj_double_id_table_b).await?;
        self.store.th_test_double_id_merkle_nodes_basic(&self.store.merkle_node_double_id_table_b, 7331, 1337, EX_DOUBLE_ID_TREE_B_HEIGHT as u8).await?;
        self.store.th_test_double_id_merkle_nodes_basic(&self.store.merkle_node_double_id_table_a, 7331, 1339, EX_DOUBLE_ID_TREE_A_HEIGHT as u8).await?;
        self.store.th_test_zero_id_merkle_nodes_basic(&self.store.merkle_node_zero_id_table_a, EX_ZERO_ID_TREE_A_HEIGHT as u8).await?;
        self.store.th_test_zero_id_merkle_nodes_basic(&self.store.merkle_node_zero_id_table_b, EX_ZERO_ID_TREE_B_HEIGHT as u8).await?;
        self.store.th_test_hash_to_u64s_basic(&self.store.hash_id_to_u64s_table_a).await?;
        
        Ok(())
    }
}

#[tokio::test]
async fn simple_store_basic_test_1() -> anyhow::Result<()> {
    let db = Arc::new(InMemoryTestStore::new());
    let simple_store = SimpleStoreEx::setup(db).await?;
    println!("setup simple store");
    simple_store.basic_test_1().await?;
    Ok(())
}