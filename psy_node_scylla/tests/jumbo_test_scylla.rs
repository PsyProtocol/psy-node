use std::sync::Arc;

use parth_core::
    data::{
        db::
            table::QDatabaseTableRoutingKey
        ,
        hash::
            hash256::Hash256
        ,
    }
;
use parth_crypto::hash::sha256::CoreSha256Hasher;
use parth_node_scylla::{
    core::ScyllaCoreStore,
    tables::{
        blob::ScyllaBiDirectionalBlobToBlobTablePreparedStatements, hash_to_many_ids::ScyllaHashToManyIdsTablePreparedStatements, merkle::{ScyllaDoubleMerkleNodesPreparedStatements, ScyllaMerkleNodesPreparedStatements, ScyllaMerkleNodesZeroPreparedStatements}, object::{
            ScyllaGenericKeyIdValueTablePreparedStatements, ScyllaGenericObjectDoubleIdTablePreparedStatements,
            ScyllaGenericObjectSingleIdTablePreparedStatements,
        }, tag_tree::ScyllaTagTreeNodesPreparedStatements, u64_tbl::{ScyllaBidirectionalU64U128MappingPreparedStatements, ScyllaU64ToU64TablePreparedStatements}
    },
};
use psy_data::v1::qdata::user::PQEDUserLeaf;
use psy_node_core::test_helpers::jumbo_store::QJumboStore;


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
        ScyllaBiDirectionalBlobToBlobTablePreparedStatements,
        ScyllaBidirectionalU64U128MappingPreparedStatements,
        ScyllaU64ToU64TablePreparedStatements,
        ScyllaGenericObjectSingleIdTablePreparedStatements,
        ScyllaGenericObjectDoubleIdTablePreparedStatements,
        ScyllaGenericKeyIdValueTablePreparedStatements,
        ScyllaMerkleNodesPreparedStatements,
        ScyllaDoubleMerkleNodesPreparedStatements,
        ScyllaMerkleNodesZeroPreparedStatements,
        ScyllaTagTreeNodesPreparedStatements,
        ScyllaHashToManyIdsTablePreparedStatements,
        ScyllaCoreStore<ExHash, ExHasher>,
    >,
}

fn get_rk(table_id: u64) -> QDatabaseTableRoutingKey {
    QDatabaseTableRoutingKey::new_with_connection_empty_secondary_routing_key(table_id, 0)
}

impl SimpleStoreEx {
    pub async fn setup(store: Arc<ScyllaCoreStore<ExHash, ExHasher>>) -> anyhow::Result<Self> {
        let kiv_table_a = store
            .init_std_table::<ScyllaGenericKeyIdValueTablePreparedStatements>("kiv_table_a", get_rk(1))
            .await?;
        let kiv_table_b = store
            .init_std_table::<ScyllaGenericKeyIdValueTablePreparedStatements>("kiv_table_b", get_rk(2))
            .await?;
        let bidirectional_mapping_table_a = store
            .init_std_table::<ScyllaBiDirectionalBlobToBlobTablePreparedStatements>("bidirectional_mapping_table_a", get_rk(3))
            .await?;
        let bidirectional_mapping_table_b = store
            .init_std_table::<ScyllaBiDirectionalBlobToBlobTablePreparedStatements>("bidirectional_mapping_table_b", get_rk(4))
            .await?;
        let obj_single_id_table_a = store
            .init_std_table::<ScyllaGenericObjectSingleIdTablePreparedStatements>("obj_single_id_table_a", get_rk(5))
            .await?;
        let obj_single_id_table_b = store
            .init_std_table::<ScyllaGenericObjectSingleIdTablePreparedStatements>("obj_single_id_table_b", get_rk(6))
            .await?;
        let obj_double_id_table_a = store
            .init_std_table::<ScyllaGenericObjectDoubleIdTablePreparedStatements>("obj_double_id_table_a", get_rk(7))
            .await?;
        let obj_double_id_table_b = store
            .init_std_table::<ScyllaGenericObjectDoubleIdTablePreparedStatements>("obj_double_id_table_b", get_rk(8))
            .await?;
        let u64_table_a = store
            .init_std_table::<ScyllaU64ToU64TablePreparedStatements>("u64_table_a", get_rk(9))
            .await?;
        let u64_table_b = store
            .init_std_table::<ScyllaU64ToU64TablePreparedStatements>("u64_table_b", get_rk(10))
            .await?;
        let u64_u128_bi_directional_mapping_table_a = store
            .init_std_table::<ScyllaBidirectionalU64U128MappingPreparedStatements>("u64_u128_bi_directional_mapping_table_a", get_rk(11))
            .await?;
        let u64_u128_bi_directional_mapping_table_b = store
            .init_std_table::<ScyllaBidirectionalU64U128MappingPreparedStatements>("u64_u128_bi_directional_mapping_table_b", get_rk(12))
            .await?;
        let merkle_node_zero_id_table_a = store
            .init_zero_id_merkle_table("merkle_node_zero_id_table_a", get_rk(13), EX_ZERO_ID_TREE_A_HEIGHT as u8)
            .await?;
        let merkle_node_zero_id_table_b = store
            .init_zero_id_merkle_table("merkle_node_zero_id_table_b", get_rk(14), EX_ZERO_ID_TREE_B_HEIGHT as u8)
            .await?;
        let merkle_node_single_id_table_a = store
            .init_std_table::<ScyllaMerkleNodesPreparedStatements>("merkle_node_single_id_table_a", get_rk(15))
            .await?;
        let merkle_node_single_id_table_b = store
            .init_std_table::<ScyllaMerkleNodesPreparedStatements>("merkle_node_single_id_table_b", get_rk(16))
            .await?;
        let merkle_node_double_id_table_a = store
            .init_std_table::<ScyllaDoubleMerkleNodesPreparedStatements>("merkle_node_double_id_table_a", get_rk(17))
            .await?;
        let merkle_node_double_id_table_b = store
            .init_std_table::<ScyllaDoubleMerkleNodesPreparedStatements>("merkle_node_double_id_table_b", get_rk(18))
            .await?;
        let tag_tree_table_a = store
            .init_std_table::<ScyllaTagTreeNodesPreparedStatements>("tag_tree_table_a", get_rk(19))
            .await?;
        let tag_tree_table_b = store
            .init_std_table::<ScyllaTagTreeNodesPreparedStatements>("tag_tree_table_b", get_rk(20))
            .await?;

        let hash_ids_to_many_ids_table_a = store.init_std_table::<ScyllaHashToManyIdsTablePreparedStatements>("hash_ids_to_many_ids_table_a", get_rk(21))
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

        let simple_store = QJumboStore::new(
            store,
            Arc::new(kiv_table_a),
            Arc::new(kiv_table_b),
            Arc::new(bidirectional_mapping_table_a),
            Arc::new(bidirectional_mapping_table_b),
            Arc::new(obj_single_id_table_a),
            Arc::new(obj_single_id_table_b),
            Arc::new(obj_double_id_table_a),
            Arc::new(obj_double_id_table_b),
            Arc::new(u64_table_a),
            Arc::new(u64_table_b),
            Arc::new(u64_u128_bi_directional_mapping_table_a),
            Arc::new(u64_u128_bi_directional_mapping_table_b),
            Arc::new(merkle_node_zero_id_table_a),
            Arc::new(merkle_node_zero_id_table_b),
            Arc::new(merkle_node_single_id_table_a),
            Arc::new(merkle_node_single_id_table_b),
            Arc::new(merkle_node_double_id_table_a),
            Arc::new(merkle_node_double_id_table_b),
            Arc::new(tag_tree_table_a),
            Arc::new(tag_tree_table_b),
            Arc::new(hash_ids_to_many_ids_table_a),
        );
        Ok(Self {
            store: simple_store,
        })
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
#[ignore = "database slow"]
async fn simple_store_basic_test_1() -> anyhow::Result<()> {
    let key_space = format!("psy_node_jumbo_scylla_test_ex1_{}", rand::random::<u64>());
    let scylla_db = ScyllaCoreStore::<ExHash, ExHasher>::new(0, 0, key_space, &[
        "127.0.0.1:9042".to_string()
    ]).await?;
    let simple_store = SimpleStoreEx::setup(Arc::new(scylla_db)).await?;
    println!("setup jumbo store");
    simple_store.basic_test_1().await?;
    Ok(())
}
