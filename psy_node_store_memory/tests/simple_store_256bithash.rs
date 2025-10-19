use std::{collections::{HashMap, HashSet}, sync::Arc};

use parth_common::memory_stores::simple_memory_tag_tree_store::SimpleMemoryTagTreeStore;
use parth_core::{
    constants::chain_id::PSY_CHAIN_ID_LOCAL_DEVNET, crypto::hash::{
        merkle_proof::DeltaMerkleProofCore, tag_tree::{compute_tag_tree_root_for_proof, hash_tag_tree_node, TagTreeMerkleProof, TagTreeNodePreimage, TagTreeStorageNode}, traits::MerkleZeroHasher
    }, data::{
        db::{
            data_types::{BiDirectionalMappingRow, QDatabasePrimitiveKey},
            row::{QDatabaseDoubleIdTableRow, QDatabaseDoubleIdTableRowNoCheckpointId, QDatabaseDoubleIdTableRowNoCheckpointIdLike, QDatabaseKeyIdValueTableRowLike, QDatabaseSingleIdTableRow, QDatabaseSingleIdTableRowNoCheckpointId, QDatabaseSingleIdTableRowNoCheckpointIdLike, QDoubleIdKey},
            table::QDatabaseTableRoutingKey,
        },
        hash::{
            hash256::Hash256,
            merkle_node_key::{generate_nca_tree_groups_efficient, SimpleMerkleNode, SimpleMerkleNodeKey}, merkle_store_key::QMerkleStoreDoubleIdNode,
        },
        serializable::{QPDPair, QPDSerializable},
    }, felt::QFelt, impl_qpd_serialize_params, protocol::core_types::{Q256BitHash, QHashBase, QDBHashBase}, utils::QPGenRandom
};
use parth_crypto::hash::sha256::CoreSha256Hasher;

use pser::{QBytesDeserialize, QBytesSerialize};
use psy_node_store_memory::cbs_store::{InMemoryCoreStore, InMemoryTableIdentifier};
use psy_serialize::PsySerializeCanonicalAsyncSafe;
use psy_data::v1::qdata::user::PQEDUserLeaf;
use psy_node_core::{qblob::{data_views::double_merkle_node_batch::QBlobDoubleMerkleNodeBatchDataView, structs::common::{blob_metadata_header::QBlobWriterContextMetadataHeader, tree_node_batch_header::QBLOB_TREE_NODE_BATCH_HEADER_SIZE}}, store::traits::{core_db::{CoreDatabaseSingleIdMerkleReader, CoreDatabaseStore, CoreDatabaseTagTreeStore}, helpers::{db_helper_double_id_merkle_node_simple_set_leaves, db_helper_double_id_merkle_node_simple_set_leaves_fast_serialize, db_helper_select_double_id_merkle_proof_max_checkpoint, db_helper_select_single_id_merkle_proof_max_checkpoint, db_helper_select_zero_id_merkle_proof_max_checkpoint, db_helper_single_id_merkle_node_simple_set_leaves, db_helper_single_id_merkle_node_simple_set_leaves_fast_serialize, db_helper_zero_id_merkle_node_simple_set_leaves, db_helper_zero_id_merkle_node_simple_set_leaves_fast_serialize}}};
trait PsyDBSer:  PsySerializeCanonicalAsyncSafe + PartialEq + Clone {

}
impl<T: PsySerializeCanonicalAsyncSafe + PartialEq + Clone> PsyDBSer for T {}
pub trait CreateRandomTestDataItem: Sized {
    fn create_random_test_data_item() -> Self;
}
const MAX_REAL_U64_ID_VALUE: u64 = 0x0000_FFFF_FFFF_FFFF;
const DEFINITELY_MISSING_U64_VALUE: u64 = MAX_REAL_U64_ID_VALUE + 1;

const MAX_REAL_CHECKPOINT_ID: u64 = 0x0000_FFFF_FFFF_FFFF;
//const DEFINITELY_MISSING_CHECKPOINT_ID: u64 = MAX_REAL_CHECKPOINT_ID + 1;

const MAX_REAL_U128_ID_VALUE: u128 = 0x0000_00FF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFFu128;
const DEFINITELY_MISSING_U128_ID_VALUE: u128 = MAX_REAL_U128_ID_VALUE + 1;


const MAX_GET_UNIQUE_ID_RETRY_ATTEMPTS: usize = 64;

fn get_unique_node_set(node_set: Vec<SimpleMerkleNodeKey>) -> Vec<SimpleMerkleNodeKey> {
    let hset = HashSet::<SimpleMerkleNodeKey>::from_iter(node_set.into_iter());
    hset.into_iter().collect::<Vec<_>>()
}

fn random_nodes_in_tree(height: u8, count: usize) -> Vec<SimpleMerkleNodeKey>{

    let max_node_id = 1u64 << (height as u64);

    let mut result = Vec::with_capacity(count);
    for _ in 0..count {
        result.push(SimpleMerkleNodeKey {
            level: height,
            index: rand::random::<u64>()%max_node_id,
        });
    }

    get_unique_node_set(result)
    
}

fn rand_real_u64_id() -> u64 {
    rand::random::<u64>() % MAX_REAL_U64_ID_VALUE
}
/* 
fn rand_real_checkpoint_id() -> u64 {
    // add some padding for addon checks
    (rand::random::<u64>() % MAX_REAL_CHECKPOINT_ID) - 0xFFFF
}
    */
fn rand_real_u128_id() -> u128 {
    rand::random::<u128>() % MAX_REAL_U128_ID_VALUE
}

fn rand_child(key: &SimpleMerkleNodeKey) -> SimpleMerkleNodeKey {
    let bit: bool = rand::random::<bool>();
    if bit {
        key.left_child()
    } else {
        key.right_child()
    }
}
fn rand_children_to_height(sub_root_key: &SimpleMerkleNodeKey, height: u8) -> Vec<SimpleMerkleNodeKey> {
    assert!(height > sub_root_key.level, "Height must be greater than sub root level");

    let mut keys = Vec::with_capacity(height as usize - sub_root_key.level as usize);
    let mut key = sub_root_key.clone();
    while key.level < height {
        key = rand_child(&key);
        keys.push(key.clone());
    }
    keys
}
fn fisher_yates_shuffle_array<T: Copy>(arr: &mut [T]) {
    let len = arr.len();
    for i in (1..len).rev() {
        let j = rand::random::<usize>() % (i + 1);
        arr.swap(i, j);
    }
}
fn unique_u64s_in_range(count: usize, min_inclusive: u64, max_exclusive: u64) -> Vec<u64> {
    assert!(max_exclusive > min_inclusive, "Max must be greater than min");
    let span = max_exclusive - min_inclusive;
    assert!(span >= (count as u64), "Range must be at least as large as count");
    let span_usize = span as usize;
    
    if count == span_usize {
        let mut arr: Vec<u64> = (min_inclusive..max_exclusive).collect();
        fisher_yates_shuffle_array(&mut arr);
        return arr;
    }

    // The heuristic for choosing the algorithm.
    // A threshold of 25% or even 10% is often a good trade-off.
    // We only create the full vector if the number of items we need is a significant
    // fraction of the total range.
    if count > span_usize / 4 { // Using 25% as a reasonable threshold
        let mut all: Vec<u64> = (min_inclusive..max_exclusive).collect();
        fisher_yates_shuffle_array(&mut all);
        return all.into_iter().take(count).collect();
    }

    // This is the correct path for your case: low count, large span.
    let mut set = std::collections::HashSet::with_capacity(count);
    while set.len() < count {
        let value = min_inclusive + (rand::random::<u64>() % span);
        set.insert(value);
    }
    set.into_iter().collect()
}
fn rand_leaves_for_subtree<Hash: PartialEq + Copy + QPGenRandom>(sub_root_key: &SimpleMerkleNodeKey, tree_height: u8, count: usize) -> Vec<SimpleMerkleNode<Hash>> {
    assert!(tree_height > sub_root_key.level, "Tree height must be greater than sub root level");
    let num_leaves_in_span_u64: u64 = 1u64 << (tree_height - sub_root_key.level - 1);
    let num_leaves_in_span: usize = num_leaves_in_span_u64 as usize;
    let start_leaf_offset = sub_root_key.index * num_leaves_in_span_u64;
    assert!(count <= num_leaves_in_span, "Count must be less than or equal to number of leaves in span");

    let leaf_indexes = unique_u64s_in_range(count, start_leaf_offset, start_leaf_offset + num_leaves_in_span_u64);

    leaf_indexes.into_iter()
        .map(|index| {
            SimpleMerkleNode {
                value: Hash::qp_rand_gen(),
                key: SimpleMerkleNodeKey::new(tree_height, index),
            }
        })
        .collect::<Vec<SimpleMerkleNode<Hash>>>()


}

pub trait THStandardTableIdentifier: Clone + Send + Sync {}
impl<T: Clone + Send + Sync> THStandardTableIdentifier for T {}

pub trait THHasher<Hash: QDBHashBase>: MerkleZeroHasher<Hash> + Send + Sync + Sized + 'static {}
impl<T: MerkleZeroHasher<Hash> + Send + Sync + Sized + 'static, Hash: QDBHashBase> THHasher<Hash> for T {}

#[derive(Clone)]
pub struct QSimpleStore<
    const ZERO_ID_TREE_A_HEIGHT: usize,
    const ZERO_ID_TREE_B_HEIGHT: usize,
    const SINGLE_ID_TREE_A_HEIGHT: usize,
    const SINGLE_ID_TREE_B_HEIGHT: usize,
    const DOUBLE_ID_TREE_A_HEIGHT: usize,
    const DOUBLE_ID_TREE_B_HEIGHT: usize,
    BidirectionalMappingTableAK1: QDatabasePrimitiveKey,
    BidirectionalMappingTableAK2: QDatabasePrimitiveKey,
    BidirectionalMappingTableBK1: QDatabasePrimitiveKey,
    BidirectionalMappingTableBK2: QDatabasePrimitiveKey,
    KivTableAValue: PsyDBSer,
    KivTableBValue: PsyDBSer,
    ObjSingleIdTableAValue: PsyDBSer,
    ObjDoubleIdTableBValue: PsyDBSer,
    Hash: QDBHashBase,
    Hasher: THHasher<Hash>,
    BiDirectionalMappingTableIdentifier: THStandardTableIdentifier,
    BiDirectionalU64U128MappingTableIdentifier: THStandardTableIdentifier,
    U64TableIdentifier: THStandardTableIdentifier,
    SingleIdTableIdentifier: THStandardTableIdentifier,
    DoubleIdTableIdentifier: THStandardTableIdentifier,
    KivTableIdentifier: THStandardTableIdentifier,
    SingleIdMerkleTableIdentifier: THStandardTableIdentifier,
    DoubleIdMerkleTableIdentifier: THStandardTableIdentifier,
    ZeroIdMerkleTableIdentifier: THStandardTableIdentifier,
    RewardTreeTableIdentifier: THStandardTableIdentifier,
    S: CoreDatabaseStore<
            Hash,
            Hasher,
            BiDirectionalMappingTableIdentifier,
            BiDirectionalU64U128MappingTableIdentifier,
            U64TableIdentifier,
            SingleIdTableIdentifier,
            DoubleIdTableIdentifier,
            KivTableIdentifier,
            SingleIdMerkleTableIdentifier,
            DoubleIdMerkleTableIdentifier,
            ZeroIdMerkleTableIdentifier,
        > + CoreDatabaseTagTreeStore<Hash, Hasher, RewardTreeTableIdentifier> + CoreDatabaseSingleIdMerkleReader<
            Hash,
            Hasher,
            SingleIdMerkleTableIdentifier,
            >
        + Send
        + Sync,
> {
    pub store: Arc<S>,
    // start objects
    pub kiv_table_a: Arc<KivTableIdentifier>,
    pub kiv_table_b: Arc<KivTableIdentifier>,
    pub bidirectional_mapping_table_a: Arc<BiDirectionalMappingTableIdentifier>,
    pub bidirectional_mapping_table_b: Arc<BiDirectionalMappingTableIdentifier>,
    pub obj_single_id_table_a: Arc<SingleIdTableIdentifier>,
    pub obj_single_id_table_b: Arc<SingleIdTableIdentifier>,
    pub obj_double_id_table_a: Arc<DoubleIdTableIdentifier>,
    pub obj_double_id_table_b: Arc<DoubleIdTableIdentifier>,

    pub u64_table_a: Arc<U64TableIdentifier>,
    pub u64_table_b: Arc<U64TableIdentifier>,
    pub u64_u128_bi_directional_mapping_table_a: Arc<BiDirectionalU64U128MappingTableIdentifier>,
    pub u64_u128_bi_directional_mapping_table_b: Arc<BiDirectionalU64U128MappingTableIdentifier>,
    // start trees
    pub merkle_node_zero_id_table_a: Arc<ZeroIdMerkleTableIdentifier>,
    pub merkle_node_zero_id_table_b: Arc<ZeroIdMerkleTableIdentifier>,
    pub merkle_node_single_id_table_a: Arc<SingleIdMerkleTableIdentifier>,
    pub merkle_node_single_id_table_b: Arc<SingleIdMerkleTableIdentifier>,
    pub merkle_node_double_id_table_a: Arc<DoubleIdMerkleTableIdentifier>,
    pub merkle_node_double_id_table_b: Arc<DoubleIdMerkleTableIdentifier>,

    // start tag tree
    pub tag_tree_table_a: Arc<RewardTreeTableIdentifier>,
    pub tag_tree_table_b: Arc<RewardTreeTableIdentifier>,

    // start phantom core
    _phantom_hash: std::marker::PhantomData<Hash>,
    _phantom_hasher: std::marker::PhantomData<Hasher>,

    // start phantom key/value types
    _phantom_kiv_table_a_value: std::marker::PhantomData<KivTableAValue>,
    _phantom_kiv_table_b_value: std::marker::PhantomData<KivTableBValue>,
    _phantom_bidirectional_mapping_table_a_key1: std::marker::PhantomData<BidirectionalMappingTableAK1>,
    _phantom_bidirectional_mapping_table_a_key2: std::marker::PhantomData<BidirectionalMappingTableAK2>,
    _phantom_bidirectional_mapping_table_b_key1: std::marker::PhantomData<BidirectionalMappingTableBK1>,
    _phantom_bidirectional_mapping_table_b_key2: std::marker::PhantomData<BidirectionalMappingTableBK2>,
    _phantom_obj_single_id_table_a_value: std::marker::PhantomData<ObjSingleIdTableAValue>,
    _phantom_obj_single_id_table_b_value: std::marker::PhantomData<ObjSingleIdTableAValue>,
    _phantom_obj_double_id_table_a_value: std::marker::PhantomData<ObjDoubleIdTableBValue>,
    _phantom_obj_double_id_table_b_value: std::marker::PhantomData<ObjDoubleIdTableBValue>,
}

//#[async_trait]
impl<
        const ZERO_ID_TREE_A_HEIGHT: usize,
        const ZERO_ID_TREE_B_HEIGHT: usize,
        const SINGLE_ID_TREE_A_HEIGHT: usize,
        const SINGLE_ID_TREE_B_HEIGHT: usize,
        const DOUBLE_ID_TREE_A_HEIGHT: usize,
        const DOUBLE_ID_TREE_B_HEIGHT: usize,
        BidirectionalMappingTableAK1: QDatabasePrimitiveKey,
        BidirectionalMappingTableAK2: QDatabasePrimitiveKey,
        BidirectionalMappingTableBK1: QDatabasePrimitiveKey,
        BidirectionalMappingTableBK2: QDatabasePrimitiveKey,
        KivTableAValue: PsyDBSer,
        KivTableBValue: PsyDBSer,
        ObjSingleIdTableAValue: PsyDBSer,
        ObjDoubleIdTableBValue: PsyDBSer,
        Hash: QDBHashBase,
        Hasher: THHasher<Hash>,
        BiDirectionalMappingTableIdentifier: THStandardTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier: THStandardTableIdentifier,
        U64TableIdentifier: THStandardTableIdentifier,
        SingleIdTableIdentifier: THStandardTableIdentifier,
        DoubleIdTableIdentifier: THStandardTableIdentifier,
        KivTableIdentifier: THStandardTableIdentifier,
        SingleIdMerkleTableIdentifier: THStandardTableIdentifier,
        DoubleIdMerkleTableIdentifier: THStandardTableIdentifier,
        ZeroIdMerkleTableIdentifier: THStandardTableIdentifier,
        RewardTreeTableIdentifier: THStandardTableIdentifier,
        S: CoreDatabaseStore<
                Hash,
                Hasher,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
            > + CoreDatabaseTagTreeStore<Hash, Hasher, RewardTreeTableIdentifier>
            + Send
            + Sync,
    >
    QSimpleStore<
        ZERO_ID_TREE_A_HEIGHT,
        ZERO_ID_TREE_B_HEIGHT,
        SINGLE_ID_TREE_A_HEIGHT,
        SINGLE_ID_TREE_B_HEIGHT,
        DOUBLE_ID_TREE_A_HEIGHT,
        DOUBLE_ID_TREE_B_HEIGHT,
        BidirectionalMappingTableAK1,
        BidirectionalMappingTableAK2,
        BidirectionalMappingTableBK1,
        BidirectionalMappingTableBK2,
        KivTableAValue,
        KivTableBValue,
        ObjSingleIdTableAValue,
        ObjDoubleIdTableBValue,
        Hash,
        Hasher,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        RewardTreeTableIdentifier,
        S,
    >
{
    pub fn new(
        store: Arc<S>,
        // start objects
        kiv_table_a: Arc<KivTableIdentifier>,
        kiv_table_b: Arc<KivTableIdentifier>,
        bidirectional_mapping_table_a: Arc<BiDirectionalMappingTableIdentifier>,
        bidirectional_mapping_table_b: Arc<BiDirectionalMappingTableIdentifier>,
        obj_single_id_table_a: Arc<SingleIdTableIdentifier>,
        obj_single_id_table_b: Arc<SingleIdTableIdentifier>,
        obj_double_id_table_a: Arc<DoubleIdTableIdentifier>,
        obj_double_id_table_b: Arc<DoubleIdTableIdentifier>,

        u64_table_a: Arc<U64TableIdentifier>,
        u64_table_b: Arc<U64TableIdentifier>,
        u64_u128_bi_directional_mapping_table_a: Arc<BiDirectionalU64U128MappingTableIdentifier>,
        u64_u128_bi_directional_mapping_table_b: Arc<BiDirectionalU64U128MappingTableIdentifier>,
        // start trees
        merkle_node_zero_id_table_a: Arc<ZeroIdMerkleTableIdentifier>,
        merkle_node_zero_id_table_b: Arc<ZeroIdMerkleTableIdentifier>,
        merkle_node_single_id_table_a: Arc<SingleIdMerkleTableIdentifier>,
        merkle_node_single_id_table_b: Arc<SingleIdMerkleTableIdentifier>,
        merkle_node_double_id_table_a: Arc<DoubleIdMerkleTableIdentifier>,
        merkle_node_double_id_table_b: Arc<DoubleIdMerkleTableIdentifier>,

        // start tag tree
        tag_tree_table_a: Arc<RewardTreeTableIdentifier>,
        tag_tree_table_b: Arc<RewardTreeTableIdentifier>,
    ) -> Self {
        Self {
            store,
            kiv_table_a,
            kiv_table_b,
            bidirectional_mapping_table_a,
            bidirectional_mapping_table_b,
            obj_single_id_table_a,
            obj_single_id_table_b,
            obj_double_id_table_a,
            obj_double_id_table_b,
            u64_table_a,
            u64_table_b,
            u64_u128_bi_directional_mapping_table_a,
            u64_u128_bi_directional_mapping_table_b,
            merkle_node_zero_id_table_a,
            merkle_node_zero_id_table_b,
            merkle_node_single_id_table_a,
            merkle_node_single_id_table_b,
            merkle_node_double_id_table_a,
            merkle_node_double_id_table_b,
            tag_tree_table_a,
            tag_tree_table_b,
            _phantom_hash: std::marker::PhantomData,
            _phantom_hasher: std::marker::PhantomData,
            _phantom_kiv_table_a_value: std::marker::PhantomData,
            _phantom_kiv_table_b_value: std::marker::PhantomData,
            _phantom_bidirectional_mapping_table_a_key1: std::marker::PhantomData,
            _phantom_bidirectional_mapping_table_a_key2: std::marker::PhantomData,
            _phantom_bidirectional_mapping_table_b_key1: std::marker::PhantomData,
            _phantom_bidirectional_mapping_table_b_key2: std::marker::PhantomData,
            _phantom_obj_single_id_table_a_value: std::marker::PhantomData,
            _phantom_obj_single_id_table_b_value: std::marker::PhantomData,
            _phantom_obj_double_id_table_a_value: std::marker::PhantomData,
            _phantom_obj_double_id_table_b_value: std::marker::PhantomData,
        }
    }

}

// START: TH Helpers
//#[async_trait]
impl<
        const ZERO_ID_TREE_A_HEIGHT: usize,
        const ZERO_ID_TREE_B_HEIGHT: usize,
        const SINGLE_ID_TREE_A_HEIGHT: usize,
        const SINGLE_ID_TREE_B_HEIGHT: usize,
        const DOUBLE_ID_TREE_A_HEIGHT: usize,
        const DOUBLE_ID_TREE_B_HEIGHT: usize,
        BidirectionalMappingTableAK1: QDatabasePrimitiveKey,
        BidirectionalMappingTableAK2: QDatabasePrimitiveKey,
        BidirectionalMappingTableBK1: QDatabasePrimitiveKey,
        BidirectionalMappingTableBK2: QDatabasePrimitiveKey,
        KivTableAValue: PsyDBSer,
        KivTableBValue: PsyDBSer,
        ObjSingleIdTableAValue: PsyDBSer,
        ObjDoubleIdTableBValue: PsyDBSer,
        Hash: QDBHashBase,
        Hasher: THHasher<Hash>,
        BiDirectionalMappingTableIdentifier: THStandardTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier: THStandardTableIdentifier,
        U64TableIdentifier: THStandardTableIdentifier,
        SingleIdTableIdentifier: THStandardTableIdentifier,
        DoubleIdTableIdentifier: THStandardTableIdentifier,
        KivTableIdentifier: THStandardTableIdentifier,
        SingleIdMerkleTableIdentifier: THStandardTableIdentifier,
        DoubleIdMerkleTableIdentifier: THStandardTableIdentifier,
        ZeroIdMerkleTableIdentifier: THStandardTableIdentifier,
        RewardTreeTableIdentifier: THStandardTableIdentifier,
        S: CoreDatabaseStore<
                Hash,
                Hasher,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
            > + CoreDatabaseTagTreeStore<Hash, Hasher, RewardTreeTableIdentifier>
            + Send
            + Sync,
    >
    QSimpleStore<
        ZERO_ID_TREE_A_HEIGHT,
        ZERO_ID_TREE_B_HEIGHT,
        SINGLE_ID_TREE_A_HEIGHT,
        SINGLE_ID_TREE_B_HEIGHT,
        DOUBLE_ID_TREE_A_HEIGHT,
        DOUBLE_ID_TREE_B_HEIGHT,
        BidirectionalMappingTableAK1,
        BidirectionalMappingTableAK2,
        BidirectionalMappingTableBK1,
        BidirectionalMappingTableBK2,
        KivTableAValue,
        KivTableBValue,
        ObjSingleIdTableAValue,
        ObjDoubleIdTableBValue,
        Hash,
        Hasher,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        RewardTreeTableIdentifier,
        S,
    >
{
    pub async fn th_util_insert_one_kiv<V: PsyDBSer>(
        &self,
        table: &KivTableIdentifier,
        obj_id: u64,
        value: &V,
    ) -> anyhow::Result<()> {
        self.store.db_insert_one_kiv(table, obj_id, value).await?;
        let result = self.store.db_select_one_kiv_value::<V>(table, obj_id).await?;
        assert!(result.is_some(), "Value not found after insert");
        let result_value = result.unwrap();
        assert!(result_value == value.clone(), "Inserted value does not match retrieved value");
        Ok(())
    }

    async fn th_util_insert_many_kivs_t<V: PsyDBSer, R: QDatabaseKeyIdValueTableRowLike<V> + Send + Sync>(
        &self,
        table: &KivTableIdentifier,
        rows: &[R],
    ) -> anyhow::Result<()> {
        self.store.db_insert_many_kivs_t(table, rows).await?;
        let keys: Vec<u64> = rows.iter().map(|r| r.get_row_obj_id()).collect();
        let results = self.store.db_select_many_kiv_values::<V>(table, &keys).await?;
        assert!(
            results.len() == rows.len(),
            "Number of retrieved values does not match number of inserted values"
        );
        for (i, row) in rows.iter().enumerate() {
            let result_value = results[i].as_ref().ok_or_else(|| anyhow::anyhow!("Value not found after insert"))?;
            assert!(result_value == row.get_row_value_ref(), "Inserted value does not match retrieved value");
        }
        Ok(())
    }

    async fn th_util_insert_one_bidirectional_mapping<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &BiDirectionalMappingTableIdentifier,
        key1: &K1,
        key2: &K2,
    ) -> anyhow::Result<()> {
        self.store.db_insert_pair_ref(table, key1, key2).await?;

        let result_key2 = self.store.db_select_one_by_k1::<K1, K2>(table, key1).await?;
        assert!(result_key2.is_some(), "Key2 not found after insert");
        let result_key2_value = result_key2.unwrap();
        assert!(result_key2_value == key2.clone(), "Inserted key2 does not match retrieved key2");
        let result_key1 = self.store.db_select_one_by_k2::<K1, K2>(table, key2).await?;
        assert!(result_key1.is_some(), "Key1 not found after insert");
        let result_key1_value = result_key1.unwrap();
        assert!(result_key1_value == key1.clone(), "Inserted key1 does not match retrieved key1");

        // test many as well
        let result_key2_multi = self.store.db_select_many_by_k1::<K1, K2>(table, &[key1.clone()]).await?;
        assert!(
            result_key2_multi.len() == 1,
            "Number of retrieved key2 values does not match number of inserted values"
        );
        let result_key2_multi_value = result_key2_multi[0]
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Key2 not found after insert in multi"))?;
        assert!(
            *result_key2_multi_value == key2.clone(),
            "Inserted key2 does not match retrieved key2 in multi"
        );
        let result_key1_multi = self.store.db_select_many_by_k2::<K1, K2>(table, &[key2.clone()]).await?;
        assert!(
            result_key1_multi.len() == 1,
            "Number of retrieved key1 values does not match number of inserted values"
        );
        let result_key1_multi_value = result_key1_multi[0]
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Key1 not found after insert in multi"))?;
        assert!(
            *result_key1_multi_value == key1.clone(),
            "Inserted key1 does not match retrieved key1 in multi"
        );

        Ok(())
    }

    async fn th_util_insert_many_bidirectional_mappings<
        K1: QDatabasePrimitiveKey,
        K2: QDatabasePrimitiveKey,
        R: QDatabaseKeyIdValueTableRowLike<K2> + Send + Sync,
    >(
        &self,
        table: &BiDirectionalMappingTableIdentifier,
        rows: &[BiDirectionalMappingRow<K1, K2>],
    ) -> anyhow::Result<()> {
        let expected_k1s = rows.iter().map(|r| r.k1.clone()).collect::<Vec<K1>>();
        let expected_k2s = rows.iter().map(|r| r.k2.clone()).collect::<Vec<K2>>();

        self.store.db_insert_pairs(table, rows).await?;

        // ensure multi select works

        let actual_rows = self.store.db_select_many_pairs_by_k1::<K1, K2>(table, &expected_k1s).await?;
        assert!(
            actual_rows.len() == rows.len(),
            "Number of retrieved rows does not match number of inserted rows"
        );
        for row in rows.iter() {
            let actual_row = actual_rows
                .iter()
                .find(|r| r.k1 == row.k1)
                .ok_or_else(|| anyhow::anyhow!("Row not found after insert"))?;
            assert!(actual_row.k2 == row.k2, "Inserted row does not match retrieved row");
        }
        assert!(&actual_rows == rows, "Inserted rows order do not match retrieved rows order");
        let actual_k2s = self
            .store
            .db_select_many_by_k1::<K1, K2>(table, &expected_k1s)
            .await?
            .into_iter()
            .map(|r| r.unwrap())
            .collect::<Vec<K2>>();
        assert!(
            actual_k2s.len() == rows.len(),
            "Number of retrieved key2 values does not match number of inserted values"
        );
        assert!(&actual_k2s == &expected_k2s, "Inserted key2 values do not match retrieved key2 values");
        let actual_k1s = self
            .store
            .db_select_many_by_k2::<K1, K2>(table, &expected_k2s)
            .await?
            .into_iter()
            .map(|r| r.unwrap())
            .collect::<Vec<K1>>();
        assert!(
            actual_k1s.len() == rows.len(),
            "Number of retrieved key1 values does not match number of inserted values"
        );
        assert!(&actual_k1s == &expected_k1s, "Inserted key1 values do not match retrieved key1 values");

        // ensure single select works
        for (i, k1) in expected_k1s.iter().enumerate() {
            let actual_k2 = self.store.db_select_one_by_k1::<K1, K2>(table, k1).await?;
            assert!(actual_k2.is_some(), "Key2 not found after insert");
            let actual_k2_value = actual_k2.unwrap();
            assert!(actual_k2_value == expected_k2s[i], "Inserted key2 does not match retrieved key2");
        }

        for (i, k2) in expected_k2s.iter().enumerate() {
            let actual_k1 = self.store.db_select_one_by_k2::<K1, K2>(table, k2).await?;
            assert!(actual_k1.is_some(), "Key1 not found after insert");
            let actual_k1_value = actual_k1.unwrap();
            assert!(actual_k1_value == expected_k1s[i], "Inserted key1 does not match retrieved key1");
        }

        let actual_rows_by_k2 = self.store.db_select_many_pairs_by_k2::<K1, K2>(table, &expected_k2s).await?;
        assert!(
            actual_rows_by_k2.len() == rows.len(),
            "Number of retrieved rows does not match number of inserted rows"
        );
        assert!(&actual_rows_by_k2 == rows, "Inserted rows order do not match retrieved rows order");
        Ok(())
    }
}

// END: TH Helpers

impl<
        const ZERO_ID_TREE_A_HEIGHT: usize,
        const ZERO_ID_TREE_B_HEIGHT: usize,
        const SINGLE_ID_TREE_A_HEIGHT: usize,
        const SINGLE_ID_TREE_B_HEIGHT: usize,
        const DOUBLE_ID_TREE_A_HEIGHT: usize,
        const DOUBLE_ID_TREE_B_HEIGHT: usize,
        BidirectionalMappingTableAK1: QDatabasePrimitiveKey,
        BidirectionalMappingTableAK2: QDatabasePrimitiveKey,
        BidirectionalMappingTableBK1: QDatabasePrimitiveKey,
        BidirectionalMappingTableBK2: QDatabasePrimitiveKey,
        KivTableAValue: PsyDBSer,
        KivTableBValue: PsyDBSer,
        ObjSingleIdTableAValue: PsyDBSer,
        ObjDoubleIdTableBValue: PsyDBSer,
        Hash: QDBHashBase,
        Hasher: THHasher<Hash>,
        BiDirectionalMappingTableIdentifier: THStandardTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier: THStandardTableIdentifier,
        U64TableIdentifier: THStandardTableIdentifier,
        SingleIdTableIdentifier: THStandardTableIdentifier,
        DoubleIdTableIdentifier: THStandardTableIdentifier,
        KivTableIdentifier: THStandardTableIdentifier,
        SingleIdMerkleTableIdentifier: THStandardTableIdentifier,
        DoubleIdMerkleTableIdentifier: THStandardTableIdentifier,
        ZeroIdMerkleTableIdentifier: THStandardTableIdentifier,
        RewardTreeTableIdentifier: THStandardTableIdentifier,
        S: CoreDatabaseStore<
                Hash,
                Hasher,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
            > + CoreDatabaseTagTreeStore<Hash, Hasher, RewardTreeTableIdentifier>
            + Send
            + Sync,
    >
    QSimpleStore<
        ZERO_ID_TREE_A_HEIGHT,
        ZERO_ID_TREE_B_HEIGHT,
        SINGLE_ID_TREE_A_HEIGHT,
        SINGLE_ID_TREE_B_HEIGHT,
        DOUBLE_ID_TREE_A_HEIGHT,
        DOUBLE_ID_TREE_B_HEIGHT,
        BidirectionalMappingTableAK1,
        BidirectionalMappingTableAK2,
        BidirectionalMappingTableBK1,
        BidirectionalMappingTableBK2,
        KivTableAValue,
        KivTableBValue,
        ObjSingleIdTableAValue,
        ObjDoubleIdTableBValue,
        Hash,
        Hasher,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        RewardTreeTableIdentifier,
        S,
    >
{
    pub async fn th_util_select_u64_value(&self, table: &U64TableIdentifier, obj_id: u64) -> anyhow::Result<Option<u64>> {
        let result = self.store.db_select_u64_value(table, obj_id).await?;
        let multi_result = self
            .store
            .db_select_u64_values(table, &[obj_id, DEFINITELY_MISSING_U64_VALUE, obj_id])
            .await?;
        assert!(multi_result.len() == 3, "Multi select did not return correct number of results");
        assert!(multi_result[0] == result, "Multi select first result does not match single select result");
        assert!(multi_result[1].is_none(), "Multi select second result should be None");
        assert!(multi_result[2] == result, "Multi select third result does not match single select result");

        Ok(result)
    }
    pub async fn th_util_set_u64_value(&self, table: &U64TableIdentifier, obj_id: u64, value: u64) -> anyhow::Result<()> {
        self.store.db_set_u64_value(table, obj_id, value).await?;
        let result = self.th_util_select_u64_value(table, obj_id).await?;
        assert!(result.is_some(), "Value not found after insert");
        let result_value = result.unwrap();
        assert!(result_value == value, "Inserted value does not match retrieved value");
        Ok(())
    }
    pub async fn th_util_set_many_u64_values(&self, table: &U64TableIdentifier, rows: &[QPDPair<u64, u64>]) -> anyhow::Result<()> {
        self.store.db_set_many_u64_values(table, rows).await?;
        let keys: Vec<u64> = rows.iter().map(|r| r.key).collect();
        let results = self.store.db_select_u64_values(table, &keys).await?;
        assert!(
            results.len() == rows.len(),
            "Number of retrieved values does not match number of inserted values"
        );
        for (i, row) in rows.iter().enumerate() {
            let result_value = results[i].as_ref().ok_or_else(|| anyhow::anyhow!("Value not found after insert"))?;
            assert!(*result_value == row.value, "Inserted value does not match retrieved value");
            let result_single_value = self.th_util_select_u64_value(table, row.key).await?;
            assert!(result_single_value.is_some(), "Value not found after insert in single select");
            let result_single_value_unwrapped = result_single_value.unwrap();
            assert!(
                result_single_value_unwrapped == row.value,
                "Inserted value does not match retrieved value in single select"
            );
        }

        Ok(())
    }

    pub async fn th_util_inc_counter(&self, table: &U64TableIdentifier, obj_id: u64, inc_amount: i64) -> anyhow::Result<u64> {
        let before = self.th_util_select_u64_value(table, obj_id).await?;
        let result = self.store.db_inc_counter(table, obj_id, inc_amount).await?;
        let after = self.th_util_select_u64_value(table, obj_id).await?;
        if before.is_none() {
            assert!(result == inc_amount as u64, "Increment result does not match expected value");
            assert!(after.is_some(), "Value not found after increment");
            let after_unwrapped = after.unwrap();
            assert!(
                after_unwrapped == inc_amount as u64,
                "Value after increment does not match expected value"
            );
        } else {
            let before_unwrapped = before.unwrap();
            let expected = if inc_amount.is_negative() {
                before_unwrapped.saturating_sub(inc_amount.wrapping_abs() as u64)
            } else {
                before_unwrapped.saturating_add(inc_amount as u64)
            };
            assert!(result == expected, "Increment result does not match expected value");
            assert!(after.is_some(), "Value not found after increment");
            let after_unwrapped = after.unwrap();
            assert!(after_unwrapped == expected, "Value after increment does not match expected value");
        }
        Ok(result)
    }
    pub async fn th_util_select_u64_u128_bi_directional_mapping(
        &self,
        table: &BiDirectionalU64U128MappingTableIdentifier,
        key: u64,
    ) -> anyhow::Result<Option<u128>> {
        let result = self.store.db_select_one_u128_value_by_u64(table, key).await?;
        let result_multi = self
            .store
            .db_select_many_u128_values_by_u64s(table, &[key, DEFINITELY_MISSING_U64_VALUE, key])
            .await?;
        assert!(result_multi.len() == 3, "Multi select did not return correct number of results");
        assert!(result_multi[0] == result, "Multi select first result does not match single select result");
        assert!(result_multi[1].is_none(), "Multi select second result should be None");
        assert!(result_multi[2] == result, "Multi select third result does not match single select result");

        // check the reverse

        if result.is_some() {
            let r_result = result.unwrap();
            let reverse_lookup = self.store.db_select_one_u64_key_by_u128(table, r_result).await?;
            assert!(reverse_lookup.is_some(), "Reverse lookup failed, value not found");
            let reverse_lookup_unwrapped = reverse_lookup.unwrap();
            assert!(reverse_lookup_unwrapped == key, "Reverse lookup failed, value does not match");

            let reverse_lookup_multi = self
                .store
                .db_select_many_u64_keys_by_u128s(table, &[r_result, (DEFINITELY_MISSING_U128_ID_VALUE), r_result])
                .await?;
            assert!(
                reverse_lookup_multi.len() == 3,
                "Reverse lookup multi did not return correct number of results"
            );
            assert!(reverse_lookup_multi[0].is_some(), "Reverse lookup multi first result should be Some");
            assert!(
                reverse_lookup_multi[0].unwrap() == key,
                "Reverse lookup multi first result does not match key"
            );
            assert!(reverse_lookup_multi[1].is_none(), "Reverse lookup multi second result should be None");
            assert!(reverse_lookup_multi[2].is_some(), "Reverse lookup multi third result should be Some");
            assert!(
                reverse_lookup_multi[2].unwrap() == key,
                "Reverse lookup multi third result does not match key"
            );
        }
        Ok(result)
    }

    pub async fn th_util_select_many_u128_values_by_u64s(
        &self,
        table: &BiDirectionalU64U128MappingTableIdentifier,
        keys: &[u64],
    ) -> anyhow::Result<Vec<Option<u128>>> {
        let result = self.store.db_select_many_u128_values_by_u64s(table, keys).await?;
        assert!(
            result.len() == keys.len(),
            "Number of retrieved values does not match number of requested values"
        );
        for (i, key) in keys.iter().enumerate() {
            let single_result = self.th_util_select_u64_u128_bi_directional_mapping(table, *key).await?;
            assert!(result[i] == single_result, "Multi select result does not match single select result");
        }
        Ok(result)
    }

    pub async fn th_util_select_u64_u128_bi_directional_mapping_by_u128(
        &self,
        table: &BiDirectionalU64U128MappingTableIdentifier,
        key: u128,
    ) -> anyhow::Result<Option<u64>> {
        let result = self.store.db_select_one_u64_key_by_u128(table, key).await?;
        let result_multi = self
            .store
            .db_select_many_u64_keys_by_u128s(table, &[key, DEFINITELY_MISSING_U128_ID_VALUE, key])
            .await?;
        assert!(result_multi.len() == 3, "Multi select did not return correct number of results");
        assert!(result_multi[0] == result, "Multi select first result does not match single select result");
        assert!(result_multi[1].is_none(), "Multi select second result should be None");
        assert!(result_multi[2] == result, "Multi select third result does not match single select result");

        // check the reverse

        if result.is_some() {
            let r_result = result.unwrap();
            let reverse_lookup = self.store.db_select_one_u128_value_by_u64(table, r_result).await?;
            assert!(reverse_lookup.is_some(), "Reverse lookup failed, value not found");
            let reverse_lookup_unwrapped = reverse_lookup.unwrap();
            assert!(reverse_lookup_unwrapped == key, "Reverse lookup failed, value does not match");

            let reverse_lookup_multi = self
                .store
                .db_select_many_u128_values_by_u64s(table, &[r_result, DEFINITELY_MISSING_U64_VALUE, r_result])
                .await?;
            assert!(
                reverse_lookup_multi.len() == 3,
                "Reverse lookup multi did not return correct number of results"
            );
            assert!(reverse_lookup_multi[0].is_some(), "Reverse lookup multi first result should be Some");
            assert!(
                reverse_lookup_multi[0].unwrap() == key,
                "Reverse lookup multi first result does not match key"
            );
            assert!(reverse_lookup_multi[1].is_none(), "Reverse lookup multi second result should be None");
            assert!(reverse_lookup_multi[2].is_some(), "Reverse lookup multi third result should be Some");
            assert!(
                reverse_lookup_multi[2].unwrap() == key,
                "Reverse lookup multi third result does not match key"
            );
        }
        Ok(result)
    }

    pub async fn th_util_select_many_u64_keys_by_u128s(
        &self,
        table: &BiDirectionalU64U128MappingTableIdentifier,
        keys: &[u128],
    ) -> anyhow::Result<Vec<Option<u64>>> {
        let result = self.store.db_select_many_u64_keys_by_u128s(table, keys).await?;
        assert!(
            result.len() == keys.len(),
            "Number of retrieved values does not match number of requested values"
        );
        for (i, key) in keys.iter().enumerate() {
            let single_result = self.th_util_select_u64_u128_bi_directional_mapping_by_u128(table, *key).await?;
            assert!(result[i] == single_result, "Multi select result does not match single select result");
        }
        Ok(result)
    }
    pub async fn th_util_insert_u64_u128_mapping_pair(
        &self,
        table: &BiDirectionalU64U128MappingTableIdentifier,
        key: u64,
        value: u128,
    ) -> anyhow::Result<()> {
        self.store.db_insert_u64_u128_mapping_pair(table, key, value).await?;
        let result = self.th_util_select_u64_u128_bi_directional_mapping(table, key).await?;
        assert!(result.is_some(), "Value not found after insert");
        let result_value = result.unwrap();
        assert!(result_value == value, "Inserted value does not match retrieved value");

        let reverse_result = self.th_util_select_u64_u128_bi_directional_mapping_by_u128(table, value).await?;
        assert!(reverse_result.is_some(), "Reverse value not found after insert");
        let reverse_result_value = reverse_result.unwrap();
        assert!(
            reverse_result_value == key,
            "Inserted reverse value does not match retrieved reverse value"
        );
        Ok(())
    }
    pub async fn th_util_insert_u64_u128_mapping_pairs(
        &self,
        table: &BiDirectionalU64U128MappingTableIdentifier,
        rows: &[BiDirectionalMappingRow<u64, u128>],
    ) -> anyhow::Result<()> {
        let expected_k1s = rows.iter().map(|r| r.k1).collect::<Vec<u64>>();
        let expected_k2s = rows.iter().map(|r| r.k2).collect::<Vec<u128>>();

        self.store.db_insert_u64_u128_mapping_pairs(table, &rows).await?;

        // ensure multi select works

        let actual_k1s = self
            .th_util_select_many_u64_keys_by_u128s(table, &expected_k2s)
            .await?
            .iter()
            .map(|r| r.unwrap())
            .collect::<Vec<u64>>();
        assert!(
            actual_k1s.len() == rows.len(),
            "Number of retrieved key1 values does not match number of inserted values"
        );
        assert!(&actual_k1s == &expected_k1s, "Inserted key1 values do not match retrieved key1 values");

        let actual_k2s = self
            .th_util_select_many_u128_values_by_u64s(table, &expected_k1s)
            .await?
            .iter()
            .map(|r| r.unwrap())
            .collect::<Vec<u128>>();
        assert!(
            actual_k2s.len() == rows.len(),
            "Number of retrieved key2 values does not match number of inserted values"
        );
        assert!(&actual_k2s == &expected_k2s, "Inserted key2 values do not match retrieved key2 values");
        Ok(())
    }

    pub async fn th_util_select_one_single_checkpointed_object_value<V: PsyDBSer>(
        &self,
        table: &SingleIdTableIdentifier,
        obj_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<V>> {
        let result = self
            .store
            .db_select_one_single_checkpointed_object_value::<V>(table, obj_id, max_checkpoint_id)
            .await?;
        let result_with_ids = self
            .store
            .db_select_one_single_checkpointed_object_value_and_ids::<V>(table, obj_id, max_checkpoint_id)
            .await?;
        if result.is_some() {
            let r = result.clone().unwrap();
            let row = result_with_ids.ok_or_else(|| anyhow::anyhow!("Value with ids not found after select"))?;
            assert!(row.obj_id == obj_id, "Object id does not match");
            assert!(row.checkpoint_id <= max_checkpoint_id, "Checkpoint id is greater than max_checkpoint_id");
            assert!(row.value == r, "Value with ids does not match value without ids");

            let above_checkpoint_id = row.checkpoint_id + 1;
            let result_above = self
                .store
                .db_select_one_single_checkpointed_object_value_and_ids::<V>(table, obj_id, above_checkpoint_id)
                .await?;
            assert!(
                result_above.is_some(),
                "Value not found when selecting with checkpoint_id above the one returned in value with ids"
            );
            let result_above_unwrapped = result_above.unwrap();
            assert!(
                result_above_unwrapped.obj_id == obj_id,
                "Object id does not match when selecting with checkpoint_id above the one returned in value with ids"
            );
            if result_above_unwrapped.checkpoint_id != row.checkpoint_id {
                assert!(result_above_unwrapped.checkpoint_id > row.checkpoint_id, "Checkpoint id is not greater than the one returned in value with ids when selecting with checkpoint_id above the one returned in value with ids");
            }
            if row.checkpoint_id > 0 {
                let result_below = self
                    .store
                    .db_select_one_single_checkpointed_object_value_and_ids::<V>(table, obj_id, row.checkpoint_id - 1)
                    .await?;
                if result_below.is_some() {
                    let result_below_unwrapped = result_below.unwrap();
                    assert!(
                        result_below_unwrapped.obj_id == obj_id,
                        "Object id does not match when selecting with checkpoint_id equal to the one returned in value with ids"
                    );
                    assert!(result_below_unwrapped.checkpoint_id < row.checkpoint_id);
                }
            }
        } else {
            assert!(result_with_ids.is_none(), "Value with ids should be None when value without ids is None");
        }
        let multi_result = self
            .store
            .db_select_many_single_checkpointed_object_values::<V>(table, &[obj_id, DEFINITELY_MISSING_U64_VALUE, obj_id], max_checkpoint_id)
            .await?;
        assert!(multi_result.len() == 3, "Multi select did not return correct number of results");
        assert!(multi_result[0] == result, "Multi select first result does not match single select result");
        assert!(multi_result[1].is_none(), "Multi select second result should be None");
        assert!(multi_result[2] == result, "Multi select third result does not match single select result");

        Ok(result)
    }

    pub async fn th_util_select_many_single_checkpointed_object_values<V: PsyDBSer>(
        &self,
        table: &SingleIdTableIdentifier,
        obj_id: &[u64],
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Vec<Option<V>>> {
        let result = self
            .store
            .db_select_many_single_checkpointed_object_values::<V>(table, obj_id, max_checkpoint_id)
            .await?;
        assert!(
            result.len() == obj_id.len(),
            "Number of retrieved values does not match number of requested values"
        );
        for (i, id) in obj_id.iter().enumerate() {
            let single_result = self
                .th_util_select_one_single_checkpointed_object_value::<V>(table, *id, max_checkpoint_id)
                .await?;
            assert!(result[i] == single_result, "Multi select result does not match single select result");
        }
        Ok(result)
    }
    pub async fn th_util_insert_single_checkpointed_object<V: PsyDBSer>(
        &self,
        table: &SingleIdTableIdentifier,
        obj_id: u64,
        checkpoint_id: u64,
        value: &V,
    ) -> anyhow::Result<()> {
        let prev_lower = if checkpoint_id > 0 {
            self.th_util_select_one_single_checkpointed_object_value::<V>(table, obj_id, checkpoint_id - 1)
                .await?
        } else {
            None
        };

        let higher = self
            .th_util_select_one_single_checkpointed_object_value::<V>(table, obj_id, checkpoint_id + 1)
            .await?;

        self.store
            .db_insert_one_single_checkpointed_object(table, obj_id, checkpoint_id, value)
            .await?;

        let after = self
            .th_util_select_one_single_checkpointed_object_value::<V>(table, obj_id, checkpoint_id)
            .await?;

        assert!(after.is_some(), "Value not found after insert");
        let after_unwrapped = after.clone().unwrap();
        assert!(after_unwrapped == *value, "Inserted value does not match retrieved value after insert");
        if higher.is_none() {
            let higher_new = self
                .th_util_select_one_single_checkpointed_object_value::<V>(table, obj_id, checkpoint_id + 1)
                .await?;
            assert!(higher_new.is_some(), "Higher value should be found after insert");
            let higher_new_unwrapped = higher_new.unwrap();
            assert!(higher_new_unwrapped == after_unwrapped, "Higher value should match inserted value");
        }

        if prev_lower.is_some() {
            let prev_lower_unwrapped = prev_lower.unwrap();
            let prev_lower_again = self
                .th_util_select_one_single_checkpointed_object_value::<V>(table, obj_id, checkpoint_id - 1)
                .await?;
            assert!(prev_lower_again.is_some(), "Previous lower value should still be found after insert");
            let prev_lower_again_unwrapped = prev_lower_again.unwrap();
            assert!(
                prev_lower_again_unwrapped == prev_lower_unwrapped,
                "Previous lower value should not change after insert"
            );
        }

        // check multi
        let multi_result = self
            .store
            .db_select_many_single_checkpointed_object_values::<V>(table, &[obj_id, DEFINITELY_MISSING_U64_VALUE, obj_id], checkpoint_id)
            .await?;
        assert!(multi_result.len() == 3, "Multi select did not return correct number of results");
        assert!(multi_result[0] == after, "Multi select first result does not match single select result");
        assert!(multi_result[1].is_none(), "Multi select second result should be None");
        assert!(multi_result[2] == after, "Multi select third result does not match single select result");

        Ok(())
    }

    pub async fn th_util_insert_many_single_checkpointed_objects<
        V: PsyDBSer,
        R: QDatabaseSingleIdTableRowNoCheckpointIdLike<V> + Send + Sync,
    >(
        &self,
        table: &SingleIdTableIdentifier,
        rows: &[R],
        checkpoint_id: u64,
    ) -> anyhow::Result<()> {
        let mut prev_lowers = Vec::with_capacity(rows.len());
        let mut highers = Vec::with_capacity(rows.len());
        for row in rows.iter() {
            let prev_lower = if checkpoint_id > 0 {
                self.th_util_select_one_single_checkpointed_object_value::<V>(table, row.get_row_obj_id(), checkpoint_id - 1)
                    .await?
            } else {
                None
            };
            prev_lowers.push(prev_lower);
            let higher = self
                .th_util_select_one_single_checkpointed_object_value::<V>(table, row.get_row_obj_id(), checkpoint_id + 1)
                .await?;
            highers.push(higher);
        }

        self.store
            .db_insert_many_single_checkpointed_objects_at_checkpoint_t::<V, R>(table, checkpoint_id, rows)
            .await?;

        for (i, row) in rows.iter().enumerate() {
            let after = self
                .th_util_select_one_single_checkpointed_object_value::<V>(table, row.get_row_obj_id(), checkpoint_id)
                .await?;
            assert!(after.is_some(), "Value not found after insert");
            let after_unwrapped = after.clone().unwrap();
            assert!(
                after_unwrapped == *row.get_row_value_ref(),
                "Inserted value does not match retrieved value after insert"
            );

            if highers[i].is_none() {
                let higher_new = self
                    .th_util_select_one_single_checkpointed_object_value::<V>(table, row.get_row_obj_id(), checkpoint_id + 1)
                    .await?;
                assert!(higher_new.is_some(), "Higher value should be found after insert");
                let higher_new_unwrapped = higher_new.unwrap();
                assert!(higher_new_unwrapped == after_unwrapped, "Higher value should match inserted value");
            }

            if prev_lowers[i].is_some() {
                let prev_lower_unwrapped = prev_lowers[i].as_ref().unwrap();
                let prev_lower_again = self
                    .th_util_select_one_single_checkpointed_object_value::<V>(table, row.get_row_obj_id(), checkpoint_id - 1)
                    .await?;
                assert!(prev_lower_again.is_some(), "Previous lower value should still be found after insert");
                let prev_lower_again_unwrapped = prev_lower_again.unwrap();
                assert!(
                    prev_lower_again_unwrapped == *prev_lower_unwrapped,
                    "Previous lower value should not change after insert"
                );
            }
        }
        // check multi
        let keys: Vec<u64> = rows.iter().map(|r| r.get_row_obj_id()).collect();
        let multi_result = self
            .store
            .db_select_many_single_checkpointed_object_values::<V>(table, &keys, checkpoint_id)
            .await?;
        assert!(multi_result.len() == rows.len(), "Multi select did not return correct number of results");
        for (i, row) in rows.iter().enumerate() {
            let after = self
                .th_util_select_one_single_checkpointed_object_value::<V>(table, row.get_row_obj_id(), checkpoint_id)
                .await?;
            assert!(multi_result[i] == after, "Multi select result does not match single select result");
        }
        Ok(())
    }

    pub async fn th_util_select_single_id_merkle_node_max_checkpoint(
        &self,
        table: &SingleIdMerkleTableIdentifier,
        tree_height: u8,
        max_checkpoint_id: u64,
        tree_id: u64,
        key: SimpleMerkleNodeKey,
    ) -> anyhow::Result<Hash> {
        let result = self
            .store
            .db_select_single_id_merkle_node_max_checkpoint(table, max_checkpoint_id, tree_id, tree_height, key)
            .await?;
        let zero_hash_at_level = Hasher::get_zero_hash((tree_height - key.level) as usize);
        if result == zero_hash_at_level {
            if max_checkpoint_id > 0 {
                // if it is a zero hash, then checking at another lower checkpoint should also
                // return the same zero hash
                let lower_checkpoint = max_checkpoint_id - 1;
                let lower_result = self
                    .store
                    .db_select_single_id_merkle_node_max_checkpoint(table, lower_checkpoint, tree_id, tree_height, key)
                    .await?;
                assert!(lower_result == result, "Lower checkpoint result does not match when result is zero hash");
            }
        }

        let multi_result = self
            .store
            .db_select_many_single_id_merkle_nodes_max_checkpoint(table, max_checkpoint_id, tree_id, tree_height, &[key, key])
            .await?;

        assert!(multi_result.len() == 2, "Multi select did not return correct number of results");
        assert!(multi_result[0] == result, "Multi select first result does not match single select result");
        assert!(
            multi_result[1] == result,
            "Multi select second result does not match single select result"
        );

        Ok(result)
    }
    pub async fn th_util_select_many_single_id_merkle_nodes_max_checkpoint(
        &self,
        table: &SingleIdMerkleTableIdentifier,
        tree_height: u8,
        max_checkpoint_id: u64,
        tree_id: u64,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Hash>> {
        let result = self
            .store
            .db_select_many_single_id_merkle_nodes_max_checkpoint(table, max_checkpoint_id, tree_id, tree_height, keys)
            .await?;
        assert!(
            result.len() == keys.len(),
            "Number of retrieved values does not match number of requested values"
        );
        for (i, key) in keys.iter().enumerate() {
            let single_result = self
                .th_util_select_single_id_merkle_node_max_checkpoint(table, tree_height, max_checkpoint_id, tree_id, *key)
                .await?;
            assert!(result[i] == single_result, "Multi select result does not match single select result");
        }
        Ok(result)
    }
    pub async fn th_util_insert_single_id_merkle_node_max_checkpoint(
        &self,
        table: &SingleIdMerkleTableIdentifier,
        tree_height: u8,
        checkpoint_id: u64,
        tree_id: u64,
        key: SimpleMerkleNodeKey,
        hash: &Hash,
    ) -> anyhow::Result<()> {
        let prev_lower = if checkpoint_id > 0 {
            self.th_util_select_single_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id - 1, tree_id, key)
                .await?
        } else {
            Hasher::get_zero_hash((tree_height - key.level) as usize)
        };

        let higher = self
            .th_util_select_single_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id + 1, tree_id, key)
            .await?;

        self.store
            .db_insert_single_id_merkle_node(table, checkpoint_id, tree_id, key, hash)
            .await?;

        let after = self
            .th_util_select_single_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id, tree_id, key)
            .await?;

        assert!(after == *hash, "Inserted hash does not match retrieved hash after insert");
        if higher == Hasher::get_zero_hash((tree_height - key.level) as usize) {
            let higher_new = self
                .th_util_select_single_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id + 1, tree_id, key)
                .await?;
            assert!(higher_new == after, "Higher hash should match inserted hash");
        }

        if prev_lower != Hasher::get_zero_hash((tree_height - key.level) as usize) {
            let prev_lower_again = self
                .th_util_select_single_id_merkle_node_max_checkpoint(
                    table,
                    tree_height,
                    if checkpoint_id > 0 { checkpoint_id - 1 } else { 0 },
                    tree_id,
                    key,
                )
                .await?;
            assert!(prev_lower_again == prev_lower, "Previous lower hash should not change after insert");
        }

        // check multi
        let multi_result = self
            .store
            .db_select_many_single_id_merkle_nodes_max_checkpoint(table, checkpoint_id, tree_id, tree_height, &[key, key])
            .await?;
        assert!(multi_result.len() == 2, "Multi select did not return correct number of results");
        assert!(multi_result[0] == after, "Multi select first result does not match single select result");
        assert!(multi_result[1] == after, "Multi select second result does not match single select result");

        Ok(())
    }

    pub async fn th_util_insert_many_single_id_merkle_node_max_checkpoint(
        &self,
        table: &SingleIdMerkleTableIdentifier,
        tree_height: u8,
        checkpoint_id: u64,
        tree_id: u64,
        nodes: &[SimpleMerkleNode<Hash>],
    ) -> anyhow::Result<()> {
        let keys = nodes.iter().map(|n| n.key).collect::<Vec<SimpleMerkleNodeKey>>();
        let mut prev_lowers = Vec::with_capacity(nodes.len());
        let mut highers = Vec::with_capacity(nodes.len());
        for key in keys.iter() {
            let prev_lower = if checkpoint_id > 0 {
                self.th_util_select_single_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id - 1, tree_id, *key)
                    .await?
            } else {
                Hasher::get_zero_hash((tree_height - key.level) as usize)
            };
            prev_lowers.push(prev_lower);
            let higher = self
                .th_util_select_single_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id + 1, tree_id, *key)
                .await?;
            highers.push(higher);
        }

        self.store
            .db_set_single_id_merkle_nodes_batch(table, checkpoint_id, tree_id, nodes)
            .await?;
        for (i, node) in nodes.iter().enumerate() {
            let after = self
                .th_util_select_single_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id, tree_id, node.key)
                .await?;
            assert!(after == node.value, "Inserted hash does not match retrieved hash after insert");

            if highers[i] == Hasher::get_zero_hash((tree_height - node.key.level) as usize) {
                let higher_new = self
                    .th_util_select_single_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id + 1, tree_id, node.key)
                    .await?;
                assert!(higher_new == after, "Higher hash should match inserted hash");
            }

            if prev_lowers[i] != Hasher::get_zero_hash((tree_height - node.key.level) as usize) {
                let prev_lower_again = self
                    .th_util_select_single_id_merkle_node_max_checkpoint(
                        table,
                        tree_height,
                        if checkpoint_id > 0 { checkpoint_id - 1 } else { 0 },
                        tree_id,
                        node.key,
                    )
                    .await?;
                assert!(prev_lower_again == prev_lowers[i], "Previous lower hash should not change after insert");
            }
        }
        // check multi
        let multi_result = self
            .store
            .db_select_many_single_id_merkle_nodes_max_checkpoint(table, checkpoint_id, tree_id, tree_height, &keys)
            .await?;
        assert!(multi_result.len() == nodes.len(), "Multi select did not return correct number of results");
        for (i, node) in nodes.iter().enumerate() {
            let after = self
                .th_util_select_single_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id, tree_id, node.key)
                .await?;
            assert!(multi_result[i] == after, "Multi select result does not match single select result");
        }
        Ok(())
    }
}

impl<
        const ZERO_ID_TREE_A_HEIGHT: usize,
        const ZERO_ID_TREE_B_HEIGHT: usize,
        const SINGLE_ID_TREE_A_HEIGHT: usize,
        const SINGLE_ID_TREE_B_HEIGHT: usize,
        const DOUBLE_ID_TREE_A_HEIGHT: usize,
        const DOUBLE_ID_TREE_B_HEIGHT: usize,
        BidirectionalMappingTableAK1: QDatabasePrimitiveKey + QPGenRandom,
        BidirectionalMappingTableAK2: QDatabasePrimitiveKey + QPGenRandom,
        BidirectionalMappingTableBK1: QDatabasePrimitiveKey + QPGenRandom,
        BidirectionalMappingTableBK2: QDatabasePrimitiveKey + QPGenRandom,
        KivTableAValue: PsyDBSer + QPGenRandom,
        KivTableBValue: PsyDBSer + QPGenRandom,
        ObjSingleIdTableAValue: PsyDBSer + QPGenRandom,
        ObjDoubleIdTableBValue: PsyDBSer + QPGenRandom,
        Hash: QDBHashBase + QPGenRandom,
        Hasher: THHasher<Hash>,
        BiDirectionalMappingTableIdentifier: THStandardTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier: THStandardTableIdentifier,
        U64TableIdentifier: THStandardTableIdentifier,
        SingleIdTableIdentifier: THStandardTableIdentifier,
        DoubleIdTableIdentifier: THStandardTableIdentifier,
        KivTableIdentifier: THStandardTableIdentifier,
        SingleIdMerkleTableIdentifier: THStandardTableIdentifier,
        DoubleIdMerkleTableIdentifier: THStandardTableIdentifier,
        ZeroIdMerkleTableIdentifier: THStandardTableIdentifier,
        RewardTreeTableIdentifier: THStandardTableIdentifier,
        S: CoreDatabaseStore<
                Hash,
                Hasher,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
            > + CoreDatabaseTagTreeStore<Hash, Hasher, RewardTreeTableIdentifier>
            + Send
            + Sync,
    >
    QSimpleStore<
        ZERO_ID_TREE_A_HEIGHT,
        ZERO_ID_TREE_B_HEIGHT,
        SINGLE_ID_TREE_A_HEIGHT,
        SINGLE_ID_TREE_B_HEIGHT,
        DOUBLE_ID_TREE_A_HEIGHT,
        DOUBLE_ID_TREE_B_HEIGHT,
        BidirectionalMappingTableAK1,
        BidirectionalMappingTableAK2,
        BidirectionalMappingTableBK1,
        BidirectionalMappingTableBK2,
        KivTableAValue,
        KivTableBValue,
        ObjSingleIdTableAValue,
        ObjDoubleIdTableBValue,
        Hash,
        Hasher,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        RewardTreeTableIdentifier,
        S,
    >
{
    pub async fn th_test_u128_u64_pairs_table_1(&self, table: &BiDirectionalU64U128MappingTableIdentifier) -> anyhow::Result<()> {
        let test_rows = vec![
            BiDirectionalMappingRow { k1: 1u64, k2: 100u128 },
            BiDirectionalMappingRow { k1: 2u64, k2: 200u128 },
            BiDirectionalMappingRow { k1: 3u64, k2: 300u128 },
            BiDirectionalMappingRow { k1: 4u64, k2: 400u128 },
            BiDirectionalMappingRow { k1: 5u64, k2: 500u128 },
        ];
        self.th_util_insert_u64_u128_mapping_pairs(table, &test_rows).await?;

        for row in test_rows.iter() {
            let selected = self.th_util_select_u64_u128_bi_directional_mapping(table, row.k1).await?;
            assert!(selected.is_some(), "Value not found after insert");
            let selected_unwrapped = selected.unwrap();
            assert!(selected_unwrapped == row.k2, "Inserted value does not match retrieved value");

            let reverse_selected = self.th_util_select_u64_u128_bi_directional_mapping_by_u128(table, row.k2).await?;
            assert!(reverse_selected.is_some(), "Reverse value not found after insert");
            let reverse_selected_unwrapped = reverse_selected.unwrap();
            assert!(
                reverse_selected_unwrapped == row.k1,
                "Inserted reverse value does not match retrieved reverse value"
            );
        }

        let random_pairs = (0..100)
            .map(|_| BiDirectionalMappingRow {
                k1: rand_real_u64_id(),
                k2: rand_real_u128_id(),
            })
            .collect::<Vec<_>>();
        self.th_util_insert_u64_u128_mapping_pairs(table, &random_pairs).await?;

        let random_pairs = (0..100)
            .map(|_| BiDirectionalMappingRow {
                k1: rand_real_u64_id(),
                k2: rand_real_u128_id(),
            })
            .collect::<Vec<_>>();

        for rp in random_pairs.into_iter() {
            self.th_util_insert_u64_u128_mapping_pair(table, rp.k1, rp.k2).await?;
        }

        Ok(())
    }

    pub async fn th_test_u64_table_1(&self, table: &U64TableIdentifier) -> anyhow::Result<()> {
        let test_ids = vec![1u64, 2u64, 3u64, 4u64, 5u64];
        for id in test_ids.iter() {
            let selected = self.th_util_select_u64_value(table, *id).await?;
            assert!(selected.is_none(), "Value should not be found before insert");
        }

        for id in test_ids.iter() {
            self.th_util_set_u64_value(table, *id, *id as u64 * 10).await?;
            let selected_value = self.th_util_select_u64_value(table, *id).await?;
            assert!(selected_value.is_some(), "Value not found after insert");
            let selected_value_unwrapped = selected_value.unwrap();
            assert!(
                selected_value_unwrapped == *id as u64 * 10,
                "Inserted value does not match retrieved value"
            );
        }

        for id in test_ids.iter() {
            let selected = self.th_util_select_u64_value(table, *id).await?;
            assert!(selected.is_some(), "Value not found after insert");
            let selected_unwrapped = selected.unwrap();
            assert!(selected_unwrapped == *id as u64 * 10, "Inserted value does not match retrieved value");
        }

        for id in test_ids.iter() {
            let incremented_value = self.th_util_inc_counter(table, *id, 5).await?;
            assert!(
                incremented_value == (*id as u64 * 10) + 5,
                "Incremented value does not match expected value"
            );
            let selected = self.th_util_select_u64_value(table, *id).await?;
            assert!(selected.is_some(), "Value not found after increment");
            let selected_unwrapped = selected.unwrap();
            assert!(
                selected_unwrapped == incremented_value,
                "Incremented value does not match retrieved value"
            );
        }

        for id in test_ids.iter() {
            let current_value = self.store.db_select_u64_value(table, *id).await?;
            if current_value.is_none() || current_value.unwrap() < 3 {
                continue;
            }
            let incremented_value = self.th_util_inc_counter(table, *id, -3).await?;
            assert!(
                incremented_value == ((*id as u64 * 10) + 5).saturating_sub(3),
                "Decremented value does not match expected value"
            );
            let selected = self.th_util_select_u64_value(table, *id).await?;
            assert!(selected.is_some(), "Value not found after decrement");
            let selected_unwrapped = selected.unwrap();
            assert!(
                selected_unwrapped == incremented_value,
                "Decremented value does not match retrieved value"
            );
        }

        // test incrementing a non-existing value
        let non_existing_id = 999u64;
        let incremented_value = self.th_util_inc_counter(table, non_existing_id, 7).await?;
        assert!(
            incremented_value == 7,
            "Incremented value of non-existing id does not match expected value"
        );
        let selected = self.th_util_select_u64_value(table, non_existing_id).await?;
        assert!(selected.is_some(), "Value not found after incrementing non-existing id");
        let selected_unwrapped = selected.unwrap();
        assert!(
            selected_unwrapped == incremented_value,
            "Incremented value of non-existing id does not match retrieved value"
        );

        // test batches
        let batch_ids = vec![10u64, 20u64, 30u64, 40u64, 50u64];
        let batch_values = vec![100u64, 200u64, 300u64, 400u64, 500u64];
        let batch_rows = batch_ids
            .iter()
            .zip(batch_values.iter())
            .map(|(&id, &value)| QPDPair { key: id, value })
            .collect::<Vec<_>>();
        self.th_util_set_many_u64_values(table, &batch_rows).await?;
        Ok(())
    }

    pub async fn get_many_non_existent_ids_in_single_object_single_try<V: PsyDBSer>(&self, table: &SingleIdTableIdentifier, max_count: usize) -> anyhow::Result<Vec<u64>> {
        let ids = (0..(max_count+16)).map(|_| rand_real_u64_id()).collect::<Vec<u64>>();
        let results = self.store.db_select_many_single_checkpointed_object_values::<V>(table, &ids, MAX_REAL_CHECKPOINT_ID).await?;
        let non_existent_ids = ids.iter().zip(results.iter()).filter_map(|(&id, res)| if res.is_none() { Some(id) } else { None }).collect::<Vec<u64>>();
        
        if non_existent_ids.len() > max_count {
            Ok(non_existent_ids.into_iter().take(max_count).collect())
        } else {
            Ok(non_existent_ids)
        }
       }
        pub async fn get_many_non_existent_ids_in_single_object<V: PsyDBSer>(&self, table: &SingleIdTableIdentifier, count: usize) -> anyhow::Result<Vec<u64>> {
        let mut non_existent_ids = self.get_many_non_existent_ids_in_single_object_single_try::<V>(table, count).await?;
        let mut retry_counter = 0;
        while non_existent_ids.len() < count {
            if retry_counter > MAX_GET_UNIQUE_ID_RETRY_ATTEMPTS {
                return Err(anyhow::anyhow!("Too many retries to find non-existent ids"));
            }
            let needed = count - non_existent_ids.len();
            let mut new_ids = self.get_many_non_existent_ids_in_single_object_single_try::<V>(table, needed).await?;
            non_existent_ids.append(&mut new_ids);
            retry_counter += 1;
        }
        Ok(non_existent_ids.into_iter().take(count).collect())
    }

    pub async fn get_non_existent_id_in_single_object<V: PsyDBSer>(&self, table: &SingleIdTableIdentifier) -> anyhow::Result<u64> {
        let mut id = rand_real_u64_id();
        let mut result = self.store.db_select_one_single_checkpointed_object_value::<V>(table, id, MAX_REAL_CHECKPOINT_ID).await?;
        let mut retry_counter = 0;
        while result.is_some() {
            if retry_counter > MAX_GET_UNIQUE_ID_RETRY_ATTEMPTS {
                return Err(anyhow::anyhow!("Too many retries to find a non-existent id"));
            }
            id = rand_real_u64_id();
            result = self.store.db_select_one_single_checkpointed_object_value::<V>(table, id, MAX_REAL_CHECKPOINT_ID).await?;
            retry_counter += 1;
        }
        Ok(id)
    }
    pub async fn get_non_existent_id_in_double_object<V: PsyDBSer>(&self, table: &DoubleIdTableIdentifier) -> anyhow::Result<(u64, u64)> {
        let mut id = rand_real_u64_id();
        let mut secondary_id = rand_real_u64_id();
        let mut result = self.store.db_select_one_double_checkpointed_object_value::<V>(table, id, secondary_id, MAX_REAL_CHECKPOINT_ID).await?;
        let mut retry_counter = 0;

        while result.is_some() {
            if retry_counter > MAX_GET_UNIQUE_ID_RETRY_ATTEMPTS {
                return Err(anyhow::anyhow!("Too many retries to find a non-existent id"));
            }
            id = rand_real_u64_id();
            secondary_id = rand_real_u64_id();
            result = self.store.db_select_one_double_checkpointed_object_value::<V>(table, id, secondary_id, MAX_REAL_CHECKPOINT_ID).await?;
            retry_counter += 1;
        }
        Ok((id, secondary_id))
    }


    pub async fn th_test_single_checkpointed_object_1_full_history_1<V: PsyDBSer + QPGenRandom>(&self, table: &SingleIdTableIdentifier) -> anyhow::Result<()>{

        let obj_id = self.get_non_existent_id_in_single_object::<V>(table).await?;
        // ensure the id is really non-existent
        let check = self.store.db_select_one_single_checkpointed_object_value::<V>(table, obj_id, MAX_REAL_CHECKPOINT_ID).await?;
        assert!(check.is_none(), "Expected non-existent id to not be found");

        




        let value_c_1337 = V::qp_rand_gen();
        let start_checkpoint_id = 1337u64;
        self.store.db_insert_one_single_checkpointed_object(table, obj_id, start_checkpoint_id, &value_c_1337).await?;

        let result = self.th_util_select_one_single_checkpointed_object_value::<V>(table, obj_id, start_checkpoint_id).await?;
        assert!(result.is_some(), "Value not found after insert at checkpoint 1337");
        let result_unwrapped = result.unwrap();
        assert!(result_unwrapped == value_c_1337, "Inserted value does not match");
        let result_with_ids = self.store.db_select_one_single_checkpointed_object_value_and_ids::<V>(table, obj_id, start_checkpoint_id).await?;
        assert!(result_with_ids.is_some(), "Value with ids not found after insert at checkpoint 1337");
        let result_with_ids_unwrapped = result_with_ids.unwrap();
        assert!(result_with_ids_unwrapped.obj_id == obj_id, "Object id does not match");
        assert!(result_with_ids_unwrapped.checkpoint_id == start_checkpoint_id, "Checkpoint id does not match");
        assert!(result_with_ids_unwrapped.value == value_c_1337, "Value does not match");
        // checking at a higher checkpoint should return the same value
        let result_higher = self.th_util_select_one_single_checkpointed_object_value::<V>(table, obj_id, start_checkpoint_id + 100).await?;
        assert!(result_higher.is_some(), "Value not found at higher checkpoint after insert at checkpoint 1337");
        let result_higher_unwrapped = result_higher.unwrap();
        assert!(result_higher_unwrapped == value_c_1337, "Value does not match at higher checkpoint");
        let result_higher_with_ids = self.store.db_select_one_single_checkpointed_object_value_and_ids::<V>(table, obj_id, start_checkpoint_id + 100).await?;
        assert!(result_higher_with_ids.is_some(), "Value with ids not found at higher checkpoint after insert at checkpoint 1337");
        let result_higher_with_ids_unwrapped = result_higher_with_ids.unwrap();
        assert!(result_higher_with_ids_unwrapped.obj_id == obj_id, "Object id does not match at higher checkpoint");
        assert_eq!(result_higher_with_ids_unwrapped.checkpoint_id, start_checkpoint_id, "Checkpoint id does not match at higher checkpoint");
        assert!(result_higher_with_ids_unwrapped.value == value_c_1337, "Value does not match at higher checkpoint");

        // checking at a lower checkpoint should return None
        let result_lower = self.store.db_select_one_single_checkpointed_object_value::<V>(table, obj_id, start_checkpoint_id - 1).await?;
        assert!(result_lower.is_none(), "Value should not be found at lower checkpoint after insert at checkpoint 1337");
        let result_lower_with_ids = self.store.db_select_one_single_checkpointed_object_value_and_ids::<V>(table, obj_id, start_checkpoint_id - 1).await?;
        assert!(result_lower_with_ids.is_none(), "Value with ids should not be found at lower checkpoint after insert at checkpoint 1337");
        // inserting at a lower checkpoint should work
        let value_c_1000 = V::qp_rand_gen();
        let lower_checkpoint_id = 1000u64;
        self.store.db_insert_one_single_checkpointed_object(table, obj_id, lower_checkpoint_id, &value_c_1000).await?;
        let result_after_lower_insert = self.th_util_select_one_single_checkpointed_object_value::<V>(table, obj_id, lower_checkpoint_id).await?;
        assert!(result_after_lower_insert.is_some(), "Value not found after insert at lower checkpoint 1000");
        let result_after_lower_insert_unwrapped = result_after_lower_insert.unwrap();
        assert!(result_after_lower_insert_unwrapped == value_c_1000, "Inserted value at lower checkpoint does not match");
        let result_after_lower_insert_with_ids = self.store.db_select_one_single_checkpointed_object_value_and_ids::<V>(table, obj_id, lower_checkpoint_id).await?;
        assert!(result_after_lower_insert_with_ids.is_some(), "Value with ids not found after insert at lower checkpoint 1000");
        let result_after_lower_insert_with_ids_unwrapped = result_after_lower_insert_with_ids.unwrap();
        assert!(result_after_lower_insert_with_ids_unwrapped.obj_id == obj_id, "Object id does not match after lower checkpoint insert");
        assert!(result_after_lower_insert_with_ids_unwrapped.checkpoint_id == lower_checkpoint_id, "Checkpoint id does not match after lower checkpoint insert");
        assert!(result_after_lower_insert_with_ids_unwrapped.value == value_c_1000, "Value does not match after lower checkpoint insert");
        // checking at a higher checkpoint should still return the original value
        let result_higher_after_lower_insert = self.th_util_select_one_single_checkpointed_object_value::<V>(table, obj_id, start_checkpoint_id).await?;
        assert!(result_higher_after_lower_insert.is_some(), "Value not found at original checkpoint after lower checkpoint insert");
        let result_higher_after_lower_insert_unwrapped = result_higher_after_lower_insert.unwrap();
        assert!(result_higher_after_lower_insert_unwrapped == value_c_1337, "Value at original checkpoint does not match after lower checkpoint insert");
        let result_higher_after_lower_insert_with_ids = self.store.db_select_one_single_checkpointed_object_value_and_ids::<V>(table, obj_id, start_checkpoint_id).await?;
        assert!(result_higher_after_lower_insert_with_ids.is_some(), "Value with ids not found at original checkpoint after lower checkpoint insert");
        let result_higher_after_lower_insert_with_ids_unwrapped = result_higher_after_lower_insert_with_ids.unwrap();
        assert!(result_higher_after_lower_insert_with_ids_unwrapped.obj_id == obj_id, "Object id does not match at original checkpoint after lower checkpoint insert");
        assert!(result_higher_after_lower_insert_with_ids_unwrapped.checkpoint_id == start_checkpoint_id, "Checkpoint id does not match at original checkpoint after lower checkpoint insert");
        assert!(result_higher_after_lower_insert_with_ids_unwrapped.value == value_c_1337, "Value does not match at original checkpoint after lower checkpoint insert");

        // 0-100 full history test
        let first_100_checkpoints = (0..100u64).map(|i| V::qp_rand_gen()).collect::<Vec<_>>();
        
        let should_be_empty_pre_insert_0 = self.store.db_select_one_single_checkpointed_object_value::<V>(table, obj_id, 0).await?;
        assert!(should_be_empty_pre_insert_0.is_none(), "Value should not be found at checkpoint 0 before insert");
        let should_be_empty_pre_insert_50 = self.store.db_select_one_single_checkpointed_object_value::<V>(table, obj_id, 50).await?;
        assert!(should_be_empty_pre_insert_50.is_none(), "Value should not be found at checkpoint 50 before insert");
        let should_be_empty_pre_insert_99 = self.store.db_select_one_single_checkpointed_object_value::<V>(table, obj_id, 99).await?;
        assert!(should_be_empty_pre_insert_99.is_none(), "Value should not be found at checkpoint 99 before insert");



        


        for (checkpoint_id, value) in first_100_checkpoints.iter().enumerate() {
            self.store.db_insert_one_single_checkpointed_object(table, obj_id, checkpoint_id as u64, value).await?;
            let should_be_value_post_insert = self.store.db_select_one_single_checkpointed_object_value::<V>(table, obj_id, checkpoint_id as u64).await?;
            assert!(should_be_value_post_insert.is_some(), "Value should be found at checkpoint {} after insert", checkpoint_id);
            let should_be_value_post_insert_unwrapped = should_be_value_post_insert.unwrap();
            assert!(should_be_value_post_insert_unwrapped == *value, "Value at checkpoint {} does not match inserted value", checkpoint_id);
            // check all future checkpoints to 100 are also the same as this value
            for future_checkpoint in (checkpoint_id + 1)..100 {
                let should_be_value_future = self.store.db_select_one_single_checkpointed_object_value::<V>(table, obj_id, future_checkpoint as u64).await?;
                assert!(should_be_value_future.is_some(), "Value should be found at future checkpoint {} after insert at checkpoint {}", future_checkpoint, checkpoint_id);
                let should_be_value_future_unwrapped = should_be_value_future.unwrap();
                assert!(should_be_value_future_unwrapped == *value, "Value at future checkpoint {} does not match value at checkpoint {} after insert", future_checkpoint, checkpoint_id);
            }
        }


        // 5000-5600 full history test with batches
        let checkpoints_5000_5600 = (5000..5600u64).map(|i| QDatabaseSingleIdTableRow::new(obj_id, i, V::qp_rand_gen())).collect::<Vec<_>>();

        // insert the first 300 in a batch
        self.store.db_insert_many_single_checkpointed_object_rows_t(table, &checkpoints_5000_5600[0..300]).await?;
        
            
        for chk in checkpoints_5000_5600[0..300].iter() {
            let actual_value = self.th_util_select_one_single_checkpointed_object_value::<V>(table, obj_id, chk.checkpoint_id).await?;
            assert!(actual_value.is_some(), "Value should be found at checkpoint {} after batch insert", chk.checkpoint_id);
            let actual_value_unwrapped = actual_value.unwrap();
            assert!(actual_value_unwrapped == chk.value, "Value at checkpoint {} does not match inserted value after batch insert", chk.checkpoint_id);
        }
        let actual_value_max_real = self.store.db_select_one_single_checkpointed_object_value::<V>(table, obj_id, MAX_REAL_CHECKPOINT_ID).await?;
        assert!(actual_value_max_real.is_some(), "Value should be found at MAX_REAL_CHECKPOINT_ID after batch insert");
        let actual_value_max_real_unwrapped = actual_value_max_real.unwrap();
        assert!(actual_value_max_real_unwrapped == checkpoints_5000_5600[299].value, "Value at MAX_REAL_CHECKPOINT_ID does not match last inserted value after batch insert");

        let actual_value_u64_max = self.store.db_select_one_single_checkpointed_object_value::<V>(table, obj_id, u64::MAX).await?;
        assert!(actual_value_u64_max.is_some(), "Value should be found at u64::MAX after batch insert");
        let actual_value_u64_max_unwrapped = actual_value_u64_max.unwrap();
        assert!(actual_value_u64_max_unwrapped == checkpoints_5000_5600[299].value, "Value at u64::MAX does not match last inserted value after batch insert");
        assert!(actual_value_u64_max_unwrapped == actual_value_max_real_unwrapped, "Value at u64::MAX does not match value at MAX_REAL_CHECKPOINT_ID after batch insert");

        // insert the next 300 in a batch
        self.store.db_insert_many_single_checkpointed_object_rows_t(table, &checkpoints_5000_5600[300..600]).await?;
        for chk in checkpoints_5000_5600[0..600].iter() {
            let actual_value = self.th_util_select_one_single_checkpointed_object_value::<V>(table, obj_id, chk.checkpoint_id).await?;
            assert!(actual_value.is_some(), "Value should be found at checkpoint {} after second batch insert", chk.checkpoint_id);
            let actual_value_unwrapped = actual_value.unwrap();
            assert!(actual_value_unwrapped == chk.value, "Value at checkpoint {} does not match inserted value after second batch insert", chk.checkpoint_id);
        }
        let actual_value_max_real = self.store.db_select_one_single_checkpointed_object_value::<V>(table, obj_id, MAX_REAL_CHECKPOINT_ID).await?;
        assert!(actual_value_max_real.is_some(), "Value should be found at MAX_REAL_CHECKPOINT_ID after second batch insert");
        let actual_value_max_real_unwrapped = actual_value_max_real.unwrap();
        assert!(actual_value_max_real_unwrapped == checkpoints_5000_5600[599].value, "Value at MAX_REAL_CHECKPOINT_ID does not match last inserted value after second batch insert");
        let actual_value_u64_max = self.store.db_select_one_single_checkpointed_object_value::<V>(table, obj_id, u64::MAX).await?;
        assert!(actual_value_u64_max.is_some(), "Value should be found at u64::MAX after second batch insert"); 
        
        let actual_value_u64_max_unwrapped = actual_value_u64_max.unwrap();
        assert!(actual_value_u64_max_unwrapped == checkpoints_5000_5600[599].value, "Value at u64::MAX does not match last inserted value after second batch insert");
        assert!(actual_value_u64_max_unwrapped == actual_value_max_real_unwrapped, "Value at u64::MAX does not match value at MAX_REAL_CHECKPOINT_ID after second batch insert");
        Ok(())


    }

    pub async fn th_test_single_checkpointed_object_1_full_history_2<V: PsyDBSer + QPGenRandom>(&self, table: &SingleIdTableIdentifier) -> anyhow::Result<()>{
        // ensure the id is really non-existent
        let obj_id = self.get_non_existent_id_in_single_object::<V>(table).await?;
        let check = self.store.db_select_one_single_checkpointed_object_value::<V>(table, obj_id, MAX_REAL_CHECKPOINT_ID).await?;
        assert!(check.is_none(), "Expected non-existent id to not be found");

        




        let value_c_1337 = V::qp_rand_gen();
        let start_checkpoint_id = 1337u64;
        self.store.db_insert_one_single_checkpointed_object(table, obj_id, start_checkpoint_id, &value_c_1337).await?;

        let result = self.th_util_select_one_single_checkpointed_object_value::<V>(table, obj_id, start_checkpoint_id).await?;
        assert!(result.is_some(), "Value not found after insert at checkpoint 1337");
        let result_unwrapped = result.unwrap();
        assert!(result_unwrapped == value_c_1337, "Inserted value does not match");
        let result_with_ids = self.store.db_select_one_single_checkpointed_object_value_and_ids::<V>(table, obj_id, start_checkpoint_id).await?;
        assert!(result_with_ids.is_some(), "Value with ids not found after insert at checkpoint 1337");
        let result_with_ids_unwrapped = result_with_ids.unwrap();
        assert!(result_with_ids_unwrapped.obj_id == obj_id, "Object id does not match");
        assert!(result_with_ids_unwrapped.checkpoint_id == start_checkpoint_id, "Checkpoint id does not match");
        assert!(result_with_ids_unwrapped.value == value_c_1337, "Value does not match");
        // checking at a higher checkpoint should return the same value
        let result_higher = self.th_util_select_one_single_checkpointed_object_value::<V>(table, obj_id, start_checkpoint_id + 100).await?;
        assert!(result_higher.is_some(), "Value not found at higher checkpoint after insert at checkpoint 1337");
        let result_higher_unwrapped = result_higher.unwrap();
        assert!(result_higher_unwrapped == value_c_1337, "Value does not match at higher checkpoint");
        let result_higher_with_ids = self.store.db_select_one_single_checkpointed_object_value_and_ids::<V>(table, obj_id, start_checkpoint_id + 100).await?;
        assert!(result_higher_with_ids.is_some(), "Value with ids not found at higher checkpoint after insert at checkpoint 1337");
        let result_higher_with_ids_unwrapped = result_higher_with_ids.unwrap();
        assert!(result_higher_with_ids_unwrapped.obj_id == obj_id, "Object id does not match at higher checkpoint");
        assert!(result_higher_with_ids_unwrapped.checkpoint_id == start_checkpoint_id, "Checkpoint id does not match at higher checkpoint");
        assert!(result_higher_with_ids_unwrapped.value == value_c_1337, "Value does not match at higher checkpoint");

        // checking at a lower checkpoint should return None
        let result_lower = self.store.db_select_one_single_checkpointed_object_value::<V>(table, obj_id, start_checkpoint_id - 1).await?;
        assert!(result_lower.is_none(), "Value should not be found at lower checkpoint after insert at checkpoint 1337");
        let result_lower_with_ids = self.store.db_select_one_single_checkpointed_object_value_and_ids::<V>(table, obj_id, start_checkpoint_id - 1).await?;
        assert!(result_lower_with_ids.is_none(), "Value with ids should not be found at lower checkpoint after insert at checkpoint 1337");
        // inserting at a lower checkpoint should work
        let value_c_1000 = V::qp_rand_gen();
        let lower_checkpoint_id = 1000u64;
        self.store.db_insert_one_single_checkpointed_object(table, obj_id, lower_checkpoint_id, &value_c_1000).await?;
        let result_after_lower_insert = self.th_util_select_one_single_checkpointed_object_value::<V>(table, obj_id, lower_checkpoint_id).await?;
        assert!(result_after_lower_insert.is_some(), "Value not found after insert at lower checkpoint 1000");
        let result_after_lower_insert_unwrapped = result_after_lower_insert.unwrap();
        assert!(result_after_lower_insert_unwrapped == value_c_1000, "Inserted value at lower checkpoint does not match");
        let result_after_lower_insert_with_ids = self.store.db_select_one_single_checkpointed_object_value_and_ids::<V>(table, obj_id, lower_checkpoint_id).await?;
        assert!(result_after_lower_insert_with_ids.is_some(), "Value with ids not found after insert at lower checkpoint 1000");
        let result_after_lower_insert_with_ids_unwrapped = result_after_lower_insert_with_ids.unwrap();
        assert!(result_after_lower_insert_with_ids_unwrapped.obj_id == obj_id, "Object id does not match after lower checkpoint insert");
        assert!(result_after_lower_insert_with_ids_unwrapped.checkpoint_id == lower_checkpoint_id, "Checkpoint id does not match after lower checkpoint insert");
        assert!(result_after_lower_insert_with_ids_unwrapped.value == value_c_1000, "Value does not match after lower checkpoint insert");
        // checking at a higher checkpoint should still return the original value
        let result_higher_after_lower_insert = self.th_util_select_one_single_checkpointed_object_value::<V>(table, obj_id, start_checkpoint_id).await?;
        assert!(result_higher_after_lower_insert.is_some(), "Value not found at original checkpoint after lower checkpoint insert");
        let result_higher_after_lower_insert_unwrapped = result_higher_after_lower_insert.unwrap();
        assert!(result_higher_after_lower_insert_unwrapped == value_c_1337, "Value at original checkpoint does not match after lower checkpoint insert");
        let result_higher_after_lower_insert_with_ids = self.store.db_select_one_single_checkpointed_object_value_and_ids::<V>(table, obj_id, start_checkpoint_id).await?;
        assert!(result_higher_after_lower_insert_with_ids.is_some(), "Value with ids not found at original checkpoint after lower checkpoint insert");
        let result_higher_after_lower_insert_with_ids_unwrapped = result_higher_after_lower_insert_with_ids.unwrap();
        assert!(result_higher_after_lower_insert_with_ids_unwrapped.obj_id == obj_id, "Object id does not match at original checkpoint after lower checkpoint insert");
        assert!(result_higher_after_lower_insert_with_ids_unwrapped.checkpoint_id == start_checkpoint_id, "Checkpoint id does not match at original checkpoint after lower checkpoint insert");
        assert!(result_higher_after_lower_insert_with_ids_unwrapped.value == value_c_1337, "Value does not match at original checkpoint after lower checkpoint insert");

        // 0-10 full history test
        let first_10_checkpoints = (0..10u64).map(|_| V::qp_rand_gen()).collect::<Vec<_>>();
        
        let should_be_empty_pre_insert_0 = self.store.db_select_one_single_checkpointed_object_value::<V>(table, obj_id, 0).await?;
        assert!(should_be_empty_pre_insert_0.is_none(), "Value should not be found at checkpoint 0 before insert");
        let should_be_empty_pre_insert_5 = self.store.db_select_one_single_checkpointed_object_value::<V>(table, obj_id, 5).await?;
        assert!(should_be_empty_pre_insert_5.is_none(), "Value should not be found at checkpoint 5 before insert");
        let should_be_empty_pre_insert_9 = self.store.db_select_one_single_checkpointed_object_value::<V>(table, obj_id, 9).await?;
        assert!(should_be_empty_pre_insert_9.is_none(), "Value should not be found at checkpoint 9 before insert");



        


        for (checkpoint_id, value) in first_10_checkpoints.iter().enumerate() {
            self.store.db_insert_one_single_checkpointed_object(table, obj_id, checkpoint_id as u64, value).await?;
            let should_be_value_post_insert = self.store.db_select_one_single_checkpointed_object_value::<V>(table, obj_id, checkpoint_id as u64).await?;
            assert!(should_be_value_post_insert.is_some(), "Value should be found at checkpoint {} after insert", checkpoint_id);
            let should_be_value_post_insert_unwrapped = should_be_value_post_insert.unwrap();
            assert!(should_be_value_post_insert_unwrapped == *value, "Value at checkpoint {} does not match inserted value", checkpoint_id);
            // check all future checkpoints to 10 are also the same as this value
            for future_checkpoint in (checkpoint_id + 1)..10 {
                let should_be_value_future = self.store.db_select_one_single_checkpointed_object_value::<V>(table, obj_id, future_checkpoint as u64).await?;
                assert!(should_be_value_future.is_some(), "Value should be found at future checkpoint {} after insert at checkpoint {}", future_checkpoint, checkpoint_id);
                let should_be_value_future_unwrapped = should_be_value_future.unwrap();
                assert!(should_be_value_future_unwrapped == *value, "Value at future checkpoint {} does not match value at checkpoint {} after insert", future_checkpoint, checkpoint_id);
            }
        }

        // test if we can get many non-existent ids and this id

        let non_existent_obj_id_a = self.get_non_existent_id_in_single_object::<V>(table).await?;
        
        let non_existent_obj_id_b = self.get_non_existent_id_in_single_object::<V>(table).await?;


        let result = self.store.db_select_many_single_checkpointed_object_values::<V>(table, &[non_existent_obj_id_a, obj_id, non_existent_obj_id_b], MAX_REAL_CHECKPOINT_ID).await?;
        assert!(result.len() == 3, "Expected 3 results from multi-select");
        assert!(result[0].is_none(), "Expected first result to be None for non-existent id");
        assert!(result[1].is_some(), "Expected second result to be Some for existing id");
        assert!(result[1].as_ref().unwrap() == &value_c_1337, "Expected second result to match inserted value");
        assert!(result[2].is_none(), "Expected third result to be None for non-existent id");


        // check an intermediate checkpoint id 1336
        let result = self.store.db_select_many_single_checkpointed_object_values::<V>(table, &[non_existent_obj_id_a, obj_id, non_existent_obj_id_b], 500).await?;
        assert!(result.len() == 3, "Expected 3 results from multi-select at intermediate checkpoint");
        assert!(result[0].is_none(), "Expected first result to be None for non-existent id at intermediate checkpoint");
        assert!(result[1].is_some(), "Expected second result to be Some for existing id at intermediate checkpoint");
        assert!(result[1].as_ref().unwrap() == &first_10_checkpoints[9], "Expected second result to match inserted value at intermediate first_10_checkpoints[9]");
        assert!(result[2].is_none(), "Expected third result to be None for non-existent id at intermediate checkpoint");
        

        // test multiple occurrences of the same id
        let result = self.store.db_select_many_single_checkpointed_object_values::<V>(table, &[obj_id, non_existent_obj_id_a, obj_id, non_existent_obj_id_b, obj_id], MAX_REAL_CHECKPOINT_ID).await?;
        assert!(result.len() == 5, "Expected 5 results from multi-select with duplicates");
        assert!(result[0].is_some(), "Expected first result to be Some for existing id");
        assert!(result[0].as_ref().unwrap() == &value_c_1337, "Expected first result to match inserted value");
        assert!(result[1].is_none(), "Expected second result to be None for non-existent id");
        assert!(result[2].is_some(), "Expected third result to be Some for existing id");
        assert!(result[2].as_ref().unwrap() == &value_c_1337, "Expected third result to match inserted value");
        assert!(result[3].is_none(), "Expected fourth result to be None for non-existent id");
        assert!(result[4].is_some(), "Expected fifth result to be Some for existing id");
        assert!(result[4].as_ref().unwrap() == &value_c_1337, "Expected fifth result to match inserted value");


        Ok(())


    }

        pub async fn th_test_single_checkpointed_object_1_full_history_3<V: PsyDBSer + QPGenRandom>(&self, table: &SingleIdTableIdentifier) -> anyhow::Result<()>{

            let first_checkpoint = 0u64;
            let second_checkpoint = 1u64;
            let last_checkpoint = 100_000u64;
            
            let obj_ids_batch_a = self.get_many_non_existent_ids_in_single_object::<V>(table, 2000).await?;
            assert!(obj_ids_batch_a.len() == 2000, "Expected to get 2000 non-existent ids");
            
            let obj_rows_batch_a = obj_ids_batch_a.iter().map(|&id| QDatabaseSingleIdTableRowNoCheckpointId::new(id, V::qp_rand_gen())).collect::<Vec<_>>();
            
            self.store.db_insert_many_single_checkpointed_objects_at_checkpoint(table,  first_checkpoint, &obj_rows_batch_a).await?;
            let objs_a_at_first = self.store.db_select_many_single_checkpointed_object_values::<V>(table, &obj_ids_batch_a, first_checkpoint).await?;
            let objs_a_at_first = objs_a_at_first.into_iter().collect::<Option<Vec<V>>>().ok_or_else(|| anyhow::anyhow!("Expected all objects to be found at first checkpoint"))?;
            assert!(objs_a_at_first.len() == obj_ids_batch_a.len(), "Expected all objects to be found at first checkpoint");
            for (i, obj) in objs_a_at_first.iter().enumerate() {
                assert!(obj == &obj_rows_batch_a[i].value, "Expected object value to match at first checkpoint");
            }
            let objs_a_at_second = self.store.db_select_many_single_checkpointed_object_values::<V>(table, &obj_ids_batch_a, second_checkpoint).await?;
            let objs_a_at_second = objs_a_at_second.into_iter().collect::<Option<Vec<V>>>().ok_or_else(|| anyhow::anyhow!("Expected all objects to be found at second checkpoint"))?;
            assert!(objs_a_at_second.len() == obj_ids_batch_a.len(), "Expected all objects to be found at second checkpoint");
            for (i, obj) in objs_a_at_second.iter().enumerate() {
                assert!(obj == &obj_rows_batch_a[i].value, "Expected object value to match at second checkpoint");
            }
            let objs_a_at_high = self.store.db_select_many_single_checkpointed_object_keys_and_values::<V, QDatabaseSingleIdTableRow<V>>(table, &obj_ids_batch_a, 12312732).await?;
            for (i, row) in objs_a_at_high.iter().enumerate() {
                assert!(row.obj_id == obj_ids_batch_a[i], "Expected object id to match at high checkpoint");
                assert!(row.checkpoint_id == first_checkpoint, "Expected checkpoint id to match at high checkpoint");
                assert!(row.value == obj_rows_batch_a[i].value, "Expected object value to match at high checkpoint");
            }

            // insert at second_checkpoint
            let obj_rows_batch_a_second = obj_ids_batch_a.iter().map(|&id| QDatabaseSingleIdTableRowNoCheckpointId::new(id, V::qp_rand_gen())).collect::<Vec<_>>();
            let obj_ids_batch_b = self.get_many_non_existent_ids_in_single_object::<V>(table, 1500).await?;
            assert!(obj_ids_batch_b.len() == 1500, "Expected to get 1500 non-existent ids for batch b");
            let obj_rows_batch_b = obj_ids_batch_b.iter().map(|&id| QDatabaseSingleIdTableRowNoCheckpointId::new(id, V::qp_rand_gen())).collect::<Vec<_>>();
            let combined_rows: Vec<QDatabaseSingleIdTableRowNoCheckpointId<V>> = obj_rows_batch_a_second.iter().chain(obj_rows_batch_b.iter()).cloned().collect();
            self.store.db_insert_many_single_checkpointed_objects_at_checkpoint(table,  second_checkpoint, &combined_rows).await?;

            let combined_ids = obj_ids_batch_a.iter().chain(obj_ids_batch_b.iter()).cloned().collect::<Vec<_>>();
            let objs_combined_at_second = self.store.db_select_many_single_checkpointed_object_values::<V>(table, &combined_ids, second_checkpoint).await?;
            let objs_combined_at_second = objs_combined_at_second.into_iter().collect::<Option<Vec<V>>>().ok_or_else(|| anyhow::anyhow!("Expected all objects to be found at second checkpoint after second insert"))?;
            assert!(objs_combined_at_second.len() == combined_ids.len(), "Expected all objects to be found at second checkpoint after second insert");
            for i in 0..obj_ids_batch_a.len() {
                assert!(objs_combined_at_second[i] == obj_rows_batch_a_second[i].value, "Expected object value to match for batch a at second checkpoint after second insert");
            }
            for i in 0..obj_ids_batch_b.len() {
                assert!(objs_combined_at_second[i + obj_ids_batch_a.len()] == obj_rows_batch_b[i].value, "Expected object value to match for batch b at second checkpoint after second insert");
            }
            // check that batch a ids at first checkpoint are still the same, and batch b ids are not found
            let objs_a_at_first_post_second = self.store.db_select_many_single_checkpointed_object_values::<V>(table, &combined_ids, first_checkpoint).await?;
            let objs_a_at_first_post_second = objs_a_at_first_post_second[0..obj_ids_batch_a.len()].to_vec().into_iter().collect::<Option<Vec<V>>>().ok_or_else(|| anyhow::anyhow!("Expected all batch a objects to be found at first checkpoint after second insert"))?;
            assert!(objs_a_at_first_post_second.len() == obj_ids_batch_a.len(), "Expected all batch a objects to be found at first checkpoint after second insert");
            for (i, obj) in objs_a_at_first_post_second.iter().enumerate() {
                assert!(obj == &obj_rows_batch_a[i].value, "Expected batch a object value to match at first checkpoint after second insert");
            }
            let objs_b_at_first_post_second = self.store.db_select_many_single_checkpointed_object_values::<V>(table, &obj_ids_batch_b, first_checkpoint).await?;
            for obj in objs_b_at_first_post_second.iter() {
                assert!(obj.is_none(), "Expected batch b object to not be found at first checkpoint after second insert");
            }
            // insert at last_checkpoint
            let obj_rows_batch_a_last = obj_ids_batch_a.iter().map(|&id| QDatabaseSingleIdTableRowNoCheckpointId::new(id, V::qp_rand_gen())).collect::<Vec<_>>();
            let obj_rows_batch_b_last = obj_ids_batch_b.iter().map(|&id| QDatabaseSingleIdTableRowNoCheckpointId::new(id, V::qp_rand_gen())).collect::<Vec<_>>();
            self.store.db_insert_many_single_checkpointed_objects_at_checkpoint(table,  last_checkpoint, &obj_rows_batch_a_last).await?;
            self.store.db_insert_many_single_checkpointed_objects_at_checkpoint_t(table,  last_checkpoint, &obj_rows_batch_b_last).await?;
            let combined_ids = obj_ids_batch_a.iter().chain(obj_ids_batch_b.iter()).cloned().collect::<Vec<_>>();
            let objs_combined_at_last = self.store.db_select_many_single_checkpointed_object_values::<V>(table, &combined_ids, last_checkpoint).await?;
            let objs_combined_at_last = objs_combined_at_last.into_iter().collect::<Option<Vec<V>>>().ok_or_else(|| anyhow::anyhow!("Expected all objects to be found at last checkpoint after last insert"))?;
            assert!(objs_combined_at_last.len() == combined_ids.len(), "Expected all objects to be found at last checkpoint after last insert");
            for i in 0..obj_ids_batch_a.len() {
                assert!(objs_combined_at_last[i] == obj_rows_batch_a_last[i].value, "Expected object value to match for batch a at last checkpoint after last insert");
            }
            for i in 0..obj_ids_batch_b.len() {
                assert!(objs_combined_at_last[i + obj_ids_batch_a.len()] == obj_rows_batch_b_last[i].value, "Expected object value to match for batch b at last checkpoint after last insert");
            }
            // check that batch a ids at second checkpoint are still the same, and batch b ids are not found
            let objs_a_at_second_post_last = self.store.db_select_many_single_checkpointed_object_values::<V>(table, &combined_ids, second_checkpoint).await?;
            let objs_a_at_second_post_last = objs_a_at_second_post_last[0..obj_ids_batch_a.len()].to_vec().into_iter().collect::<Option<Vec<V>>>().ok_or_else(|| anyhow::anyhow!("Expected all batch a objects to be found at second checkpoint after last insert"))?;
            assert!(objs_a_at_second_post_last.len() == obj_ids_batch_a.len(), "Expected all batch a objects to be found at second checkpoint after last insert");
            for (i, obj) in objs_a_at_second_post_last.iter().enumerate() {
                assert!(obj == &obj_rows_batch_a_second[i].value, "Expected batch a object value to match at second checkpoint after last insert");
            }
            let objs_b_at_second_post_last = self.store.db_select_many_single_checkpointed_object_values::<V>(table, &obj_ids_batch_b, second_checkpoint).await?;
            for obj in objs_b_at_second_post_last.iter() {
                assert!(obj.is_some(), "Expected batch b object to be found at second checkpoint after last insert");
                assert!(obj.as_ref().unwrap() == &obj_rows_batch_b[objs_b_at_second_post_last.iter().position(|x| x == obj).unwrap()].value, "Expected batch b object value to match at second checkpoint after last insert");
            }
            // check that batch a ids at first checkpoint are still the same, and batch b ids are not found
            let objs_a_at_first_post_last = self.store.db_select_many_single_checkpointed_object_values::<V>(table, &combined_ids, first_checkpoint).await?;
            let objs_a_at_first_post_last = objs_a_at_first_post_last[0..obj_ids_batch_a.len()].to_vec().into_iter().collect::<Option<Vec<V>>>().ok_or_else(|| anyhow::anyhow!("Expected all batch a objects to be found at first checkpoint after last insert"))?;
            assert!(objs_a_at_first_post_last.len() == obj_ids_batch_a.len(), "Expected all batch a objects to be found at first checkpoint after last insert");
            for (i, obj) in objs_a_at_first_post_last.iter().enumerate() {
                assert!(obj == &obj_rows_batch_a[i].value, "Expected batch a object value to match at first checkpoint after last insert");
            }
            let objs_b_at_first_post_last = self.store.db_select_many_single_checkpointed_object_values::<V>(table, &obj_ids_batch_b, first_checkpoint).await?;
            for obj in objs_b_at_first_post_last.iter() {
                assert!(obj.is_none(), "Expected batch b object to not be found at first checkpoint after last insert");
            }



            // batch set obj_ids_batch_a to first_checkpoint


            Ok(())





        }
        
        async fn th_ensure_single_id_merkle_zero_hashes_at_checkpoint_for_sub_tree_a(&self, table: &SingleIdMerkleTableIdentifier, tree_id: u64, checkpoint_id: u64, tree_height: u8, root: SimpleMerkleNodeKey) -> anyhow::Result<()> {
            assert!(tree_height >= root.level, "Tree height must be greater than or equal to root level");
            let root_value = self.store.db_select_single_id_merkle_node_max_checkpoint(table, checkpoint_id, tree_id, tree_height, root).await?;
            assert!(root_value == Hasher::get_zero_hash((tree_height-root.level) as usize), "Root value must be zero hash at root level");
            if root.level == tree_height {
                return Ok(());
            }

            let child_keys = rand_children_to_height(&root, tree_height);
            let node_values = self.store.db_select_many_single_id_merkle_nodes_max_checkpoint(table, checkpoint_id, tree_id, tree_height, &child_keys).await?;
            let expected_values = child_keys.iter().map(|key| Hasher::get_zero_hash((tree_height - key.level) as usize)).collect::<Vec<_>>();
            assert!(node_values.len() == expected_values.len(), "Node values and expected values lengths must match");
            for (i, value) in node_values.iter().enumerate() {
                assert!(value == &expected_values[i], "Node value must match expected zero hash");
            }

            Ok(())
        }
        pub async fn th_test_insert_single_id_merkle_leaves_sub_tree_dmp(&self, table: &SingleIdMerkleTableIdentifier, checkpoint_id: u64, tree_id: u64, tree_height: u8, sub_root_key: &SimpleMerkleNodeKey, leaves: &[SimpleMerkleNode<Hash>]) -> anyhow::Result<Vec<DeltaMerkleProofCore<Hash>>> {
            if leaves.is_empty() {
                return Ok(vec![]);
            }
            assert!(sub_root_key.level <= tree_height, "Sub root level must be at or below the tree height level");
            
            let first_leaf_level = leaves[0].key.level;
            assert!(first_leaf_level <= tree_height, "Leaf keys must be at or below the tree height level");
            assert!(first_leaf_level >= sub_root_key.level, "Leaf keys must be at or below the sub root level");

            for leaf in leaves.iter() {
                assert!(leaf.key.level == first_leaf_level, "All leaf keys must be at the same level");
            }
            let leaf_values = leaves.iter().map(|node| node.value).collect::<Vec<_>>();
            let leaf_keys = leaves.iter().map(|node| node.key).collect::<Vec<_>>();
            let dmps = db_helper_single_id_merkle_node_simple_set_leaves_fast_serialize::<Hash, Hasher, SingleIdMerkleTableIdentifier,_>(&self.store, table, checkpoint_id, tree_id, tree_height, 0, 9999, leaves).await?;
            assert!(dmps.len() == leaves.len(), "Number of DeltaMerkleProofs must match number of inserted leaves");
            let selected_leaf_values = self.store.db_select_many_single_id_merkle_nodes_max_checkpoint(table, checkpoint_id, tree_id, tree_height, &leaf_keys).await?;
            assert!(selected_leaf_values.len() == leaf_values.len(), "Selected leaf values length must match inserted leaf values length");
            for (i, value) in selected_leaf_values.iter().enumerate() {
                assert!(value == &leaf_values[i], "Selected leaf value must match inserted leaf value");
            }
            for dmp in dmps.iter() {

                assert!(dmp.verify::<Hasher>(), "DeltaMerkleProof must verify correctly");
            }

            for i in 1..dmps.len() {
                assert!(dmps[i-1].new_root == dmps[i].old_root, "Consecutive DeltaMerkleProofs must be connected back to back, ie. new_root of previous must equal old_root of next"); 
            }
            

            Ok(dmps)

        }
        pub async fn th_test_single_id_merkle_nodes_basic(&self, table: &SingleIdMerkleTableIdentifier, tree_id: u64, tree_height: u8) -> anyhow::Result<()> {

            let first_checkpoint_id = 1u64;
            let second_checkpoint_id = 2u64;
            let third_checkpoint_id = 3u64;
            let fourth_checkpoint_id = 999u64;
            let last_checkpoint_id = 12874892u64;
            self.th_ensure_single_id_merkle_zero_hashes_at_checkpoint_for_sub_tree_a(table, tree_id, first_checkpoint_id, tree_height, SimpleMerkleNodeKey::new_root()).await?;
            self.th_ensure_single_id_merkle_zero_hashes_at_checkpoint_for_sub_tree_a(table, tree_id, second_checkpoint_id, tree_height, SimpleMerkleNodeKey::new_root()).await?;
            self.th_ensure_single_id_merkle_zero_hashes_at_checkpoint_for_sub_tree_a(table, tree_id, third_checkpoint_id, tree_height, SimpleMerkleNodeKey::new_root()).await?;
            self.th_ensure_single_id_merkle_zero_hashes_at_checkpoint_for_sub_tree_a(table, tree_id, fourth_checkpoint_id, tree_height, SimpleMerkleNodeKey::new_root()).await?;
            self.th_ensure_single_id_merkle_zero_hashes_at_checkpoint_for_sub_tree_a(table, tree_id, last_checkpoint_id, tree_height, SimpleMerkleNodeKey::new_root()).await?;

            let max_leaves_in_tree = 1u64 << tree_height;
            let num_leaves_to_insert = 16u64.min(max_leaves_in_tree);
            let num_leaves_to_insert_usize = num_leaves_to_insert as usize;
            let root_key = SimpleMerkleNodeKey::new_root();
            let first_batch = rand_leaves_for_subtree::<Hash>(&root_key, tree_height, num_leaves_to_insert_usize);

            let dmps_0 = self.th_test_insert_single_id_merkle_leaves_sub_tree_dmp(table, first_checkpoint_id, tree_id, tree_height, &SimpleMerkleNodeKey::new_root(), &first_batch).await?;
            assert!(dmps_0.len() == first_batch.len(), "Number of DeltaMerkleProofs must match number of inserted leaves at first checkpoint");

            self.th_ensure_single_id_merkle_zero_hashes_at_checkpoint_for_sub_tree_a(table, tree_id, 0, tree_height, SimpleMerkleNodeKey::new_root()).await?;
            let second_batch = rand_leaves_for_subtree::<Hash>(&root_key, tree_height, num_leaves_to_insert_usize);
            let dmps_1 = self.th_test_insert_single_id_merkle_leaves_sub_tree_dmp(table, second_checkpoint_id, tree_id, tree_height, &SimpleMerkleNodeKey::new_root(), &second_batch).await?;
            assert!(dmps_1.len() == second_batch.len(), "Number of DeltaMerkleProofs must match number of inserted leaves at second checkpoint");
            

            let first_second_batch_combined_halves = [
                first_batch[0..(num_leaves_to_insert_usize/2)].to_vec(),
                second_batch[(num_leaves_to_insert_usize/2)..num_leaves_to_insert_usize].to_vec()
            ].concat();
            let third_batch_unmodified = [
                first_batch[(num_leaves_to_insert_usize/2)..num_leaves_to_insert_usize].to_vec(),
                second_batch[0..(num_leaves_to_insert_usize/2)].to_vec()
            ].concat();
            let third_batch_new_leaves = rand_leaves_for_subtree::<Hash>(&root_key, tree_height, num_leaves_to_insert_usize);
            let first_second_batch_leaves_at_third_checkpoint = first_second_batch_combined_halves.iter().map(|x|{
                SimpleMerkleNode {
                    key: x.key,
                    value: Hash::qp_rand_gen(),
                }
            }).collect::<Vec<_>>();
            let third_batch = [first_second_batch_leaves_at_third_checkpoint, third_batch_new_leaves.clone()].concat();
            let dmps_2 = self.th_test_insert_single_id_merkle_leaves_sub_tree_dmp(table, third_checkpoint_id, tree_id, tree_height, &SimpleMerkleNodeKey::new_root(), &third_batch).await?;
            assert!(dmps_2.len() == third_batch.len(), "Number of DeltaMerkleProofs must match number of inserted leaves at third checkpoint");
            // ensure that the unmodified leaves are still the same at third checkpoint
            let b12_unmodified_keys = third_batch_unmodified.iter().map(|x| x.key).collect::<Vec<_>>();
            let b12_unmodified_values = third_batch_unmodified.iter().map(|x| x.value).collect::<Vec<_>>();
            let selected_unmodified_values = self.store.db_select_many_single_id_merkle_nodes_max_checkpoint(table, third_checkpoint_id, tree_id, tree_height, &b12_unmodified_keys).await?;
            assert!(selected_unmodified_values.len() == b12_unmodified_values.len(), "Selected unmodified values length must match unmodified values length at third checkpoint");
            for (i, value) in selected_unmodified_values.iter().enumerate() {
                assert!(value == &b12_unmodified_values[i], "Selected unmodified value must match unmodified value at third checkpoint");
            }
            // ensure that the modified leaves are different at third checkpoint
            let b3_modified_keys = third_batch_new_leaves.iter().map(|x| x.key).collect::<Vec<_>>();
            let b3_modified_values = third_batch_new_leaves.iter().map(|x| x.value).collect::<Vec<_>>();
            let selected_modified_values = self.store.db_select_many_single_id_merkle_nodes_max_checkpoint(table, third_checkpoint_id, tree_id, tree_height, &b3_modified_keys).await?;
            assert!(selected_modified_values.len() == b3_modified_values.len(), "Selected modified values length must match modified values length at third checkpoint");
            for (i, value) in selected_modified_values.iter().enumerate() {
                assert!(value == &b3_modified_values[i], "Selected modified value must match modified value at third checkpoint");
            }

            let fourth_batch = rand_leaves_for_subtree::<Hash>(&root_key, tree_height, num_leaves_to_insert_usize);
            let dmps_3 = self.th_test_insert_single_id_merkle_leaves_sub_tree_dmp(table, fourth_checkpoint_id, tree_id, tree_height, &SimpleMerkleNodeKey::new_root(), &fourth_batch).await?;
            assert!(dmps_3.len() == fourth_batch.len(), "Number of DeltaMerkleProofs must match number of inserted leaves at fourth checkpoint");

            let last_batch = rand_leaves_for_subtree::<Hash>(&root_key, tree_height, num_leaves_to_insert_usize);
            let dmps_4 = self.th_test_insert_single_id_merkle_leaves_sub_tree_dmp(table, last_checkpoint_id, tree_id, tree_height, &SimpleMerkleNodeKey::new_root(), &last_batch).await?;
            assert!(dmps_4.len() == last_batch.len(), "Number of DeltaMerkleProofs must match number of inserted leaves at last checkpoint");

            let keys_to_check: Vec<_> = first_batch.iter().chain(second_batch.iter()).chain(third_batch.iter()).chain(fourth_batch.iter()).chain(last_batch.iter()).map(|x| x.key)
                .into_iter()
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();

            for k in keys_to_check {
                let mp = db_helper_select_single_id_merkle_proof_max_checkpoint::<Hash, Hasher, _, _>(&self.store, table, first_checkpoint_id+1, tree_id, tree_height, k). await?;
                assert!(mp.verify::<Hasher>(), "MerkleProof must verify correctly for key {:?}", k);
                let mp = db_helper_select_single_id_merkle_proof_max_checkpoint::<Hash, Hasher, _, _>(&self.store, table, second_checkpoint_id, tree_id, tree_height, k). await?;
                assert!(mp.verify::<Hasher>(), "MerkleProof must verify correctly for key {:?}", k);
                let mp = db_helper_select_single_id_merkle_proof_max_checkpoint::<Hash, Hasher, _, _>(&self.store, table, third_checkpoint_id, tree_id, tree_height, k). await?;
                assert!(mp.verify::<Hasher>(), "MerkleProof must verify correctly for key {:?}", k);
                let mp = db_helper_select_single_id_merkle_proof_max_checkpoint::<Hash, Hasher, _, _>(&self.store, table, fourth_checkpoint_id, tree_id, tree_height, k). await?;
                assert!(mp.verify::<Hasher>(), "MerkleProof must verify correctly for key {:?}", k);
                let mp = db_helper_select_single_id_merkle_proof_max_checkpoint::<Hash, Hasher, _, _>(&self.store, table, last_checkpoint_id, tree_id, tree_height, k). await?;
                assert!(mp.verify::<Hasher>(), "MerkleProof must verify correctly for key {:?}", k);
                let mp = db_helper_select_single_id_merkle_proof_max_checkpoint::<Hash, Hasher, _, _>(&self.store, table, last_checkpoint_id+100, tree_id, tree_height, k). await?;
                assert!(mp.verify::<Hasher>(), "MerkleProof must verify correctly for key {:?}", k);
            }
            Ok(())
        }


    
}

impl<
        const ZERO_ID_TREE_A_HEIGHT: usize,
        const ZERO_ID_TREE_B_HEIGHT: usize,
        const SINGLE_ID_TREE_A_HEIGHT: usize,
        const SINGLE_ID_TREE_B_HEIGHT: usize,
        const DOUBLE_ID_TREE_A_HEIGHT: usize,
        const DOUBLE_ID_TREE_B_HEIGHT: usize,
        BidirectionalMappingTableAK1: QDatabasePrimitiveKey + QPGenRandom,
        BidirectionalMappingTableAK2: QDatabasePrimitiveKey + QPGenRandom,
        BidirectionalMappingTableBK1: QDatabasePrimitiveKey + QPGenRandom,
        BidirectionalMappingTableBK2: QDatabasePrimitiveKey + QPGenRandom,
        KivTableAValue: PsyDBSer + QPGenRandom,
        KivTableBValue: PsyDBSer + QPGenRandom,
        ObjSingleIdTableAValue: PsyDBSer + QPGenRandom,
        ObjDoubleIdTableBValue: PsyDBSer + QPGenRandom,
        Hash: QDBHashBase + QPGenRandom,
        Hasher: THHasher<Hash>,
        BiDirectionalMappingTableIdentifier: THStandardTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier: THStandardTableIdentifier,
        U64TableIdentifier: THStandardTableIdentifier,
        SingleIdTableIdentifier: THStandardTableIdentifier,
        DoubleIdTableIdentifier: THStandardTableIdentifier,
        KivTableIdentifier: THStandardTableIdentifier,
        SingleIdMerkleTableIdentifier: THStandardTableIdentifier,
        DoubleIdMerkleTableIdentifier: THStandardTableIdentifier,
        ZeroIdMerkleTableIdentifier: THStandardTableIdentifier,
        RewardTreeTableIdentifier: THStandardTableIdentifier,
        S: CoreDatabaseStore<
                Hash,
                Hasher,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
            > + CoreDatabaseTagTreeStore<Hash, Hasher, RewardTreeTableIdentifier>
            + Send
            + Sync,
    >
    QSimpleStore<
        ZERO_ID_TREE_A_HEIGHT,
        ZERO_ID_TREE_B_HEIGHT,
        SINGLE_ID_TREE_A_HEIGHT,
        SINGLE_ID_TREE_B_HEIGHT,
        DOUBLE_ID_TREE_A_HEIGHT,
        DOUBLE_ID_TREE_B_HEIGHT,
        BidirectionalMappingTableAK1,
        BidirectionalMappingTableAK2,
        BidirectionalMappingTableBK1,
        BidirectionalMappingTableBK2,
        KivTableAValue,
        KivTableBValue,
        ObjSingleIdTableAValue,
        ObjDoubleIdTableBValue,
        Hash,
        Hasher,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        RewardTreeTableIdentifier,
        S,
    >
{
    pub async fn th_util_select_one_double_checkpointed_object_value<V: PsyDBSer>(
        &self,
        table: &DoubleIdTableIdentifier,
        obj_id: u64,
        secondary_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<V>> {
        let result = self
            .store
            .db_select_one_double_checkpointed_object_value::<V>(table, obj_id, secondary_id, max_checkpoint_id)
            .await?;
        let result_with_ids = self
            .store
            .db_select_one_double_checkpointed_object_value_and_ids::<V>(table, obj_id, secondary_id, max_checkpoint_id)
            .await?;
        if result.is_some() {
            let r = result.clone().unwrap();
            let row = result_with_ids.ok_or_else(|| anyhow::anyhow!("Value with ids not found after select"))?;
            assert!(row.obj_id == obj_id, "Object id does not match");
            assert!(row.secondary_id == secondary_id, "Secondary id does not match");
            assert!(row.checkpoint_id <= max_checkpoint_id, "Checkpoint id is greater than max_checkpoint_id");
            assert!(row.value == r, "Value with ids does not match value without ids");

            let above_checkpoint_id = row.checkpoint_id + 1;
            let result_above = self
                .store
                .db_select_one_double_checkpointed_object_value_and_ids::<V>(table, obj_id, secondary_id, above_checkpoint_id)
                .await?;
            assert!(
                result_above.is_some(),
                "Value not found when selecting with checkpoint_id above the one returned in value with ids"
            );
            let result_above_unwrapped = result_above.unwrap();
            assert!(
                result_above_unwrapped.obj_id == obj_id,
                "Object id does not match when selecting with checkpoint_id above the one returned in value with ids"
            );
            assert!(
                result_above_unwrapped.secondary_id == secondary_id,
                "Secondary id does not match when selecting with checkpoint_id above the one returned in value with ids"
            );
            if result_above_unwrapped.checkpoint_id != row.checkpoint_id {
                assert!(result_above_unwrapped.checkpoint_id > row.checkpoint_id, "Checkpoint id is not greater than the one returned in value with ids when selecting with checkpoint_id above the one returned in value with ids");
            }
            if row.checkpoint_id > 0 {
                let result_below = self
                    .store
                    .db_select_one_double_checkpointed_object_value_and_ids::<V>(table, obj_id, secondary_id, row.checkpoint_id - 1)
                    .await?;
                if result_below.is_some() {
                    let result_below_unwrapped = result_below.unwrap();
                    assert!(
                        result_below_unwrapped.obj_id == obj_id,
                        "Object id does not match when selecting with checkpoint_id equal to the one returned in value with ids"
                    );
                    assert!(
                        result_below_unwrapped.secondary_id == secondary_id,
                        "Secondary id does not match when selecting with checkpoint_id equal to the one returned in value with ids"
                    );
                    assert!(result_below_unwrapped.checkpoint_id < row.checkpoint_id);
                }
            }
        } else {
            assert!(result_with_ids.is_none(), "Value with ids should be None when value without ids is None");
        }
        let multi_result = self
            .store
            .db_select_many_double_checkpointed_object_values::<V>(table, &[QDoubleIdKey::from((obj_id, secondary_id)), QDoubleIdKey::from((DEFINITELY_MISSING_U64_VALUE, DEFINITELY_MISSING_U64_VALUE)), QDoubleIdKey::from((obj_id, secondary_id))], max_checkpoint_id)
            .await?;
        assert!(multi_result.len() == 3, "Multi select did not return correct number of results");
        assert!(multi_result[0] == result, "Multi select first result does not match single select result");
        assert!(multi_result[1].is_none(), "Multi select second result should be None");
        assert!(multi_result[2] == result, "Multi select third result does not match single select result");

        Ok(result)
    }

    pub async fn th_util_select_many_double_checkpointed_object_values<V: PsyDBSer>(
        &self,
        table: &DoubleIdTableIdentifier,
        obj_keys: &[QDoubleIdKey],
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Vec<Option<V>>> {
        let result = self
            .store
            .db_select_many_double_checkpointed_object_values::<V>(table, obj_keys, max_checkpoint_id)
            .await?;
        assert!(
            result.len() == obj_keys.len(),
            "Number of retrieved values does not match number of requested values"
        );
        for (i, key) in obj_keys.iter().enumerate() {
            let single_result = self
                .th_util_select_one_double_checkpointed_object_value::<V>(table, key.obj_id, key.secondary_id, max_checkpoint_id)
                .await?;
            assert!(result[i] == single_result, "Multi select result does not match single select result");
        }
        Ok(result)
    }

    pub async fn th_util_insert_double_checkpointed_object<V: PsyDBSer>(
        &self,
        table: &DoubleIdTableIdentifier,
        obj_id: u64,
        secondary_id: u64,
        checkpoint_id: u64,
        value: &V,
    ) -> anyhow::Result<()> {
        let prev_lower = if checkpoint_id > 0 {
            self.th_util_select_one_double_checkpointed_object_value::<V>(table, obj_id, secondary_id, checkpoint_id - 1)
                .await?
        } else {
            None
        };

        let higher = self
            .th_util_select_one_double_checkpointed_object_value::<V>(table, obj_id, secondary_id, checkpoint_id + 1)
            .await?;

        self.store
            .db_insert_one_double_checkpointed_object(table, obj_id, secondary_id, checkpoint_id, value)
            .await?;

        let after = self
            .th_util_select_one_double_checkpointed_object_value::<V>(table, obj_id, secondary_id, checkpoint_id)
            .await?;

        assert!(after.is_some(), "Value not found after insert");
        let after_unwrapped = after.clone().unwrap();
        assert!(after_unwrapped == *value, "Inserted value does not match retrieved value after insert");
        if higher.is_none() {
            let higher_new = self
                .th_util_select_one_double_checkpointed_object_value::<V>(table, obj_id, secondary_id, checkpoint_id + 1)
                .await?;
            assert!(higher_new.is_some(), "Higher value should be found after insert");
            let higher_new_unwrapped = higher_new.unwrap();
            assert!(higher_new_unwrapped == after_unwrapped, "Higher value should match inserted value");
        }

        if prev_lower.is_some() {
            let prev_lower_unwrapped = prev_lower.unwrap();
            let prev_lower_again = self
                .th_util_select_one_double_checkpointed_object_value::<V>(table, obj_id, secondary_id, checkpoint_id - 1)
                .await?;
            assert!(prev_lower_again.is_some(), "Previous lower value should still be found after insert");
            let prev_lower_again_unwrapped = prev_lower_again.unwrap();
            assert!(
                prev_lower_again_unwrapped == prev_lower_unwrapped,
                "Previous lower value should not change after insert"
            );
        }

        // check multi
        let multi_result = self
            .store
            .db_select_many_double_checkpointed_object_values::<V>(table, &[QDoubleIdKey::from((obj_id, secondary_id)), QDoubleIdKey::from((DEFINITELY_MISSING_U64_VALUE, DEFINITELY_MISSING_U64_VALUE)), QDoubleIdKey::from((obj_id, secondary_id))], checkpoint_id)
            .await?;
        assert!(multi_result.len() == 3, "Multi select did not return correct number of results");
        assert!(multi_result[0] == after, "Multi select first result does not match single select result");
        assert!(multi_result[1].is_none(), "Multi select second result should be None");
        assert!(multi_result[2] == after, "Multi select third result does not match single select result");

        Ok(())
    }

    pub async fn th_util_insert_many_double_checkpointed_objects<
        V: PsyDBSer,
        R: QDatabaseDoubleIdTableRowNoCheckpointIdLike<V> + Send + Sync,
    >(
        &self,
        table: &DoubleIdTableIdentifier,
        rows: &[R],
        checkpoint_id: u64,
    ) -> anyhow::Result<()> {
        let mut prev_lowers = Vec::with_capacity(rows.len());
        let mut highers = Vec::with_capacity(rows.len());
        for row in rows.iter() {
            let prev_lower = if checkpoint_id > 0 {
                self.th_util_select_one_double_checkpointed_object_value::<V>(table, row.get_row_obj_id(), row.get_row_secondary_id(), checkpoint_id - 1)
                    .await?
            } else {
                None
            };
            prev_lowers.push(prev_lower);
            let higher = self
                .th_util_select_one_double_checkpointed_object_value::<V>(table, row.get_row_obj_id(), row.get_row_secondary_id(), checkpoint_id + 1)
                .await?;
            highers.push(higher);
        }

        self.store
            .db_insert_many_double_checkpointed_objects_at_checkpoint_t::<V, R>(table, checkpoint_id, rows)
            .await?;

        for (i, row) in rows.iter().enumerate() {
            let after = self
                .th_util_select_one_double_checkpointed_object_value::<V>(table, row.get_row_obj_id(), row.get_row_secondary_id(), checkpoint_id)
                .await?;
            assert!(after.is_some(), "Value not found after insert");
            let after_unwrapped = after.clone().unwrap();
            assert!(
                after_unwrapped == *row.get_row_value_ref(),
                "Inserted value does not match retrieved value after insert"
            );

            if highers[i].is_none() {
                let higher_new = self
                    .th_util_select_one_double_checkpointed_object_value::<V>(table, row.get_row_obj_id(), row.get_row_secondary_id(), checkpoint_id + 1)
                    .await?;
                assert!(higher_new.is_some(), "Higher value should be found after insert");
                let higher_new_unwrapped = higher_new.unwrap();
                assert!(higher_new_unwrapped == after_unwrapped, "Higher value should match inserted value");
            }

            if prev_lowers[i].is_some() {
                let prev_lower_unwrapped = prev_lowers[i].as_ref().unwrap();
                let prev_lower_again = self
                    .th_util_select_one_double_checkpointed_object_value::<V>(table, row.get_row_obj_id(), row.get_row_secondary_id(), checkpoint_id - 1)
                    .await?;
                assert!(prev_lower_again.is_some(), "Previous lower value should still be found after insert");
                let prev_lower_again_unwrapped = prev_lower_again.unwrap();
                assert!(
                    prev_lower_again_unwrapped == *prev_lower_unwrapped,
                    "Previous lower value should not change after insert"
                );
            }
        }
        // check multi
        let keys: Vec<QDoubleIdKey> = rows.iter().map(|r| QDoubleIdKey::from((r.get_row_obj_id(), r.get_row_secondary_id()))).collect();
        let multi_result = self
            .store
            .db_select_many_double_checkpointed_object_values::<V>(table, &keys, checkpoint_id)
            .await?;
        assert!(multi_result.len() == rows.len(), "Multi select did not return correct number of results");
        for (i, row) in rows.iter().enumerate() {
            let after = self
                .th_util_select_one_double_checkpointed_object_value::<V>(table, row.get_row_obj_id(), row.get_row_secondary_id(), checkpoint_id)
                .await?;
            assert!(multi_result[i] == after, "Multi select result does not match single select result");
        }
        Ok(())
    }

    pub async fn get_many_non_existent_double_ids_in_double_object_single_try<V: PsyDBSer>(&self, table: &DoubleIdTableIdentifier, max_count: usize) -> anyhow::Result<Vec<(u64, u64)>> {
        let ids = (0..(max_count+16)).map(|_| (rand_real_u64_id(), rand_real_u64_id())).collect::<Vec<_>>();
        let keys = ids.iter().map(|&(obj_id, sec_id)| QDoubleIdKey::from((obj_id, sec_id))).collect::<Vec<_>>();
        let results = self.store.db_select_many_double_checkpointed_object_values::<V>(table, &keys, MAX_REAL_CHECKPOINT_ID).await?;
        let non_existent_ids = ids.iter().zip(results.iter()).filter_map(|(&id, res)| if res.is_none() { Some(id) } else { None }).collect::<Vec<(u64, u64)>>();
        
        if non_existent_ids.len() > max_count {
            Ok(non_existent_ids.into_iter().take(max_count).collect())
        } else {
            Ok(non_existent_ids)
        }
    }

    pub async fn get_many_non_existent_double_ids_in_double_object<V: PsyDBSer>(&self, table: &DoubleIdTableIdentifier, count: usize) -> anyhow::Result<Vec<(u64, u64)>> {
        let mut non_existent_ids = self.get_many_non_existent_double_ids_in_double_object_single_try::<V>(table, count).await?;
        let mut retry_counter = 0;
        while non_existent_ids.len() < count {
            if retry_counter > MAX_GET_UNIQUE_ID_RETRY_ATTEMPTS {
                return Err(anyhow::anyhow!("Too many retries to find non-existent double ids"));
            }
            let needed = count - non_existent_ids.len();
            let mut new_ids = self.get_many_non_existent_double_ids_in_double_object_single_try::<V>(table, needed).await?;
            non_existent_ids.append(&mut new_ids);
            retry_counter += 1;
        }
        Ok(non_existent_ids.into_iter().take(count).collect())
    }

    pub async fn th_test_double_checkpointed_object_1_full_history_1<V: PsyDBSer + QPGenRandom>(&self, table: &DoubleIdTableIdentifier) -> anyhow::Result<()> {

        let (obj_id, secondary_id) = self.get_non_existent_id_in_double_object::<V>(table).await?;
        let check = self.store.db_select_one_double_checkpointed_object_value::<V>(table, obj_id, secondary_id, MAX_REAL_CHECKPOINT_ID).await?;
        assert!(check.is_none(), "Expected non-existent pair to not be found");

        let value_c_1337 = V::qp_rand_gen();
        let start_checkpoint_id = 1337u64;
        self.store.db_insert_one_double_checkpointed_object(table, obj_id, secondary_id, start_checkpoint_id, &value_c_1337).await?;

        let result = self.th_util_select_one_double_checkpointed_object_value::<V>(table, obj_id, secondary_id, start_checkpoint_id).await?;
        assert!(result.is_some(), "Value not found after insert at checkpoint 1337");
        let result_unwrapped = result.unwrap();
        assert!(result_unwrapped == value_c_1337, "Inserted value does not match");
        let result_with_ids = self.store.db_select_one_double_checkpointed_object_value_and_ids::<V>(table, obj_id, secondary_id, start_checkpoint_id).await?;
        assert!(result_with_ids.is_some(), "Value with ids not found after insert at checkpoint 1337");
        let result_with_ids_unwrapped = result_with_ids.unwrap();
        assert!(result_with_ids_unwrapped.obj_id == obj_id, "Object id does not match");
        assert!(result_with_ids_unwrapped.secondary_id == secondary_id, "Secondary id does not match");
        assert!(result_with_ids_unwrapped.checkpoint_id == start_checkpoint_id, "Checkpoint id does not match");
        assert!(result_with_ids_unwrapped.value == value_c_1337, "Value does not match");

        let result_higher = self.th_util_select_one_double_checkpointed_object_value::<V>(table, obj_id, secondary_id, start_checkpoint_id + 100).await?;
        assert!(result_higher.is_some(), "Value not found at higher checkpoint after insert at checkpoint 1337");
        let result_higher_unwrapped = result_higher.unwrap();
        assert!(result_higher_unwrapped == value_c_1337, "Value does not match at higher checkpoint");
        let result_higher_with_ids = self.store.db_select_one_double_checkpointed_object_value_and_ids::<V>(table, obj_id, secondary_id, start_checkpoint_id + 100).await?;
        assert!(result_higher_with_ids.is_some(), "Value with ids not found at higher checkpoint after insert at checkpoint 1337");
        let result_higher_with_ids_unwrapped = result_higher_with_ids.unwrap();
        assert!(result_higher_with_ids_unwrapped.obj_id == obj_id, "Object id does not match at higher checkpoint");
        assert!(result_higher_with_ids_unwrapped.secondary_id == secondary_id, "Secondary id does not match at higher checkpoint");
        assert!(result_higher_with_ids_unwrapped.checkpoint_id == start_checkpoint_id, "Checkpoint id does not match at higher checkpoint");
        assert!(result_higher_with_ids_unwrapped.value == value_c_1337, "Value does not match at higher checkpoint");

        let result_lower = self.store.db_select_one_double_checkpointed_object_value::<V>(table, obj_id, secondary_id, start_checkpoint_id - 1).await?;
        assert!(result_lower.is_none(), "Value should not be found at lower checkpoint after insert at checkpoint 1337");
        let result_lower_with_ids = self.store.db_select_one_double_checkpointed_object_value_and_ids::<V>(table, obj_id, secondary_id, start_checkpoint_id - 1).await?;
        assert!(result_lower_with_ids.is_none(), "Value with ids should not be found at lower checkpoint after insert at checkpoint 1337");

        let value_c_1000 = V::qp_rand_gen();
        let lower_checkpoint_id = 1000u64;
        self.store.db_insert_one_double_checkpointed_object(table, obj_id, secondary_id, lower_checkpoint_id, &value_c_1000).await?;
        let result_after_lower_insert = self.th_util_select_one_double_checkpointed_object_value::<V>(table, obj_id, secondary_id, lower_checkpoint_id).await?;
        assert!(result_after_lower_insert.is_some(), "Value not found after insert at lower checkpoint 1000");
        let result_after_lower_insert_unwrapped = result_after_lower_insert.unwrap();
        assert!(result_after_lower_insert_unwrapped == value_c_1000, "Inserted value at lower checkpoint does not match");
        let result_after_lower_insert_with_ids = self.store.db_select_one_double_checkpointed_object_value_and_ids::<V>(table, obj_id, secondary_id, lower_checkpoint_id).await?;
        assert!(result_after_lower_insert_with_ids.is_some(), "Value with ids not found after insert at lower checkpoint 1000");
        let result_after_lower_insert_with_ids_unwrapped = result_after_lower_insert_with_ids.unwrap();
        assert!(result_after_lower_insert_with_ids_unwrapped.obj_id == obj_id, "Object id does not match after lower checkpoint insert");
        assert!(result_after_lower_insert_with_ids_unwrapped.secondary_id == secondary_id, "Secondary id does not match after lower checkpoint insert");
        assert!(result_after_lower_insert_with_ids_unwrapped.checkpoint_id == lower_checkpoint_id, "Checkpoint id does not match after lower checkpoint insert");
        assert!(result_after_lower_insert_with_ids_unwrapped.value == value_c_1000, "Value does not match after lower checkpoint insert");

        let result_higher_after_lower_insert = self.th_util_select_one_double_checkpointed_object_value::<V>(table, obj_id, secondary_id, start_checkpoint_id).await?;
        assert!(result_higher_after_lower_insert.is_some(), "Value not found at original checkpoint after lower checkpoint insert");
        let result_higher_after_lower_insert_unwrapped = result_higher_after_lower_insert.unwrap();
        assert!(result_higher_after_lower_insert_unwrapped == value_c_1337, "Value at original checkpoint does not match after lower checkpoint insert");
        let result_higher_after_lower_insert_with_ids = self.store.db_select_one_double_checkpointed_object_value_and_ids::<V>(table, obj_id, secondary_id, start_checkpoint_id).await?;
        assert!(result_higher_after_lower_insert_with_ids.is_some(), "Value with ids not found at original checkpoint after lower checkpoint insert");
        let result_higher_after_lower_insert_with_ids_unwrapped = result_higher_after_lower_insert_with_ids.unwrap();
        assert!(result_higher_after_lower_insert_with_ids_unwrapped.obj_id == obj_id, "Object id does not match at original checkpoint after lower checkpoint insert");
        assert!(result_higher_after_lower_insert_with_ids_unwrapped.secondary_id == secondary_id, "Secondary id does not match at original checkpoint after lower checkpoint insert");
        assert!(result_higher_after_lower_insert_with_ids_unwrapped.checkpoint_id == start_checkpoint_id, "Checkpoint id does not match at original checkpoint after lower checkpoint insert");
        assert!(result_higher_after_lower_insert_with_ids_unwrapped.value == value_c_1337, "Value does not match at original checkpoint after lower checkpoint insert");

        let first_100_checkpoints = (0..100u64).map(|i| V::qp_rand_gen()).collect::<Vec<_>>();

        let should_be_empty_pre_insert_0 = self.store.db_select_one_double_checkpointed_object_value::<V>(table, obj_id, secondary_id, 0).await?;
        assert!(should_be_empty_pre_insert_0.is_none(), "Value should not be found at checkpoint 0 before insert");
        let should_be_empty_pre_insert_50 = self.store.db_select_one_double_checkpointed_object_value::<V>(table, obj_id, secondary_id, 50).await?;
        assert!(should_be_empty_pre_insert_50.is_none(), "Value should not be found at checkpoint 50 before insert");
        let should_be_empty_pre_insert_99 = self.store.db_select_one_double_checkpointed_object_value::<V>(table, obj_id, secondary_id, 99).await?;
        assert!(should_be_empty_pre_insert_99.is_none(), "Value should not be found at checkpoint 99 before insert");

        for (checkpoint_id, value) in first_100_checkpoints.iter().enumerate() {
            self.store.db_insert_one_double_checkpointed_object(table, obj_id, secondary_id, checkpoint_id as u64, value).await?;
            let should_be_value_post_insert = self.store.db_select_one_double_checkpointed_object_value::<V>(table, obj_id, secondary_id, checkpoint_id as u64).await?;
            assert!(should_be_value_post_insert.is_some(), "Value should be found at checkpoint {} after insert", checkpoint_id);
            let should_be_value_post_insert_unwrapped = should_be_value_post_insert.unwrap();
            assert!(should_be_value_post_insert_unwrapped == *value, "Value at checkpoint {} does not match inserted value", checkpoint_id);
            for future_checkpoint in (checkpoint_id + 1)..100 {
                let should_be_value_future = self.store.db_select_one_double_checkpointed_object_value::<V>(table, obj_id, secondary_id, future_checkpoint as u64).await?;
                assert!(should_be_value_future.is_some(), "Value should be found at future checkpoint {} after insert at checkpoint {}", future_checkpoint, checkpoint_id);
                let should_be_value_future_unwrapped = should_be_value_future.unwrap();
                assert!(should_be_value_future_unwrapped == *value, "Value at future checkpoint {} does not match value at checkpoint {} after insert", future_checkpoint, checkpoint_id);
            }
        }

        let checkpoints_5000_5600 = (5000..5600u64).map(|i| QDatabaseDoubleIdTableRow::new(obj_id, secondary_id, i, V::qp_rand_gen())).collect::<Vec<_>>();

        self.store.db_insert_many_double_checkpointed_object_rows_t(table, &checkpoints_5000_5600[0..300]).await?;
        
        for chk in checkpoints_5000_5600[0..300].iter() {
            let actual_value = self.th_util_select_one_double_checkpointed_object_value::<V>(table, obj_id, secondary_id, chk.checkpoint_id).await?;
            assert!(actual_value.is_some(), "Value should be found at checkpoint {} after batch insert", chk.checkpoint_id);
            let actual_value_unwrapped = actual_value.unwrap();
            assert!(actual_value_unwrapped == chk.value, "Value at checkpoint {} does not match inserted value after batch insert", chk.checkpoint_id);
        }
        let actual_value_max_real = self.store.db_select_one_double_checkpointed_object_value::<V>(table, obj_id, secondary_id, MAX_REAL_CHECKPOINT_ID).await?;
        assert!(actual_value_max_real.is_some(), "Value should be found at MAX_REAL_CHECKPOINT_ID after batch insert");
        let actual_value_max_real_unwrapped = actual_value_max_real.unwrap();
        assert!(actual_value_max_real_unwrapped == checkpoints_5000_5600[299].value, "Value at MAX_REAL_CHECKPOINT_ID does not match last inserted value after batch insert");

        let actual_value_u64_max = self.store.db_select_one_double_checkpointed_object_value::<V>(table, obj_id, secondary_id, u64::MAX).await?;
        assert!(actual_value_u64_max.is_some(), "Value should be found at u64::MAX after batch insert");
        let actual_value_u64_max_unwrapped = actual_value_u64_max.unwrap();
        assert!(actual_value_u64_max_unwrapped == checkpoints_5000_5600[299].value, "Value at u64::MAX does not match last inserted value after batch insert");
        assert!(actual_value_u64_max_unwrapped == actual_value_max_real_unwrapped, "Value at u64::MAX does not match value at MAX_REAL_CHECKPOINT_ID after batch insert");

        self.store.db_insert_many_double_checkpointed_object_rows_t(table, &checkpoints_5000_5600[300..600]).await?;
        for chk in checkpoints_5000_5600[0..600].iter() {
            let actual_value = self.th_util_select_one_double_checkpointed_object_value::<V>(table, obj_id, secondary_id, chk.checkpoint_id).await?;
            assert!(actual_value.is_some(), "Value should be found at checkpoint {} after second batch insert", chk.checkpoint_id);
            let actual_value_unwrapped = actual_value.unwrap();
            assert!(actual_value_unwrapped == chk.value, "Value at checkpoint {} does not match inserted value after second batch insert", chk.checkpoint_id);
        }
        let actual_value_max_real = self.store.db_select_one_double_checkpointed_object_value::<V>(table, obj_id, secondary_id, MAX_REAL_CHECKPOINT_ID).await?;
        assert!(actual_value_max_real.is_some(), "Value should be found at MAX_REAL_CHECKPOINT_ID after second batch insert");
        let actual_value_max_real_unwrapped = actual_value_max_real.unwrap();
        assert!(actual_value_max_real_unwrapped == checkpoints_5000_5600[599].value, "Value at MAX_REAL_CHECKPOINT_ID does not match last inserted value after second batch insert");
        let actual_value_u64_max = self.store.db_select_one_double_checkpointed_object_value::<V>(table, obj_id, secondary_id, u64::MAX).await?;
        assert!(actual_value_u64_max.is_some(), "Value should be found at u64::MAX after second batch insert"); 
        
        let actual_value_u64_max_unwrapped = actual_value_u64_max.unwrap();
        assert!(actual_value_u64_max_unwrapped == checkpoints_5000_5600[599].value, "Value at u64::MAX does not match last inserted value after second batch insert");
        assert!(actual_value_u64_max_unwrapped == actual_value_max_real_unwrapped, "Value at u64::MAX does not match value at MAX_REAL_CHECKPOINT_ID after second batch insert");
        Ok(())
    }

    pub async fn th_test_double_checkpointed_object_1_full_history_2<V: PsyDBSer + QPGenRandom>(&self, table: &DoubleIdTableIdentifier) -> anyhow::Result<()>{
        let (obj_id, secondary_id) = self.get_non_existent_id_in_double_object::<V>(table).await?;
        let check = self.store.db_select_one_double_checkpointed_object_value::<V>(table, obj_id, secondary_id, MAX_REAL_CHECKPOINT_ID).await?;
        assert!(check.is_none(), "Expected non-existent pair to not be found");

        let value_c_1337 = V::qp_rand_gen();
        let start_checkpoint_id = 1337u64;
        self.store.db_insert_one_double_checkpointed_object(table, obj_id, secondary_id, start_checkpoint_id, &value_c_1337).await?;

        let result = self.th_util_select_one_double_checkpointed_object_value::<V>(table, obj_id, secondary_id, start_checkpoint_id).await?;
        assert!(result.is_some(), "Value not found after insert at checkpoint 1337");
        let result_unwrapped = result.unwrap();
        assert!(result_unwrapped == value_c_1337, "Inserted value does not match");
        let result_with_ids = self.store.db_select_one_double_checkpointed_object_value_and_ids::<V>(table, obj_id, secondary_id, start_checkpoint_id).await?;
        assert!(result_with_ids.is_some(), "Value with ids not found after insert at checkpoint 1337");
        let result_with_ids_unwrapped = result_with_ids.unwrap();
        assert!(result_with_ids_unwrapped.obj_id == obj_id, "Object id does not match");
        assert!(result_with_ids_unwrapped.secondary_id == secondary_id, "Secondary id does not match");
        assert!(result_with_ids_unwrapped.checkpoint_id == start_checkpoint_id, "Checkpoint id does not match");
        assert!(result_with_ids_unwrapped.value == value_c_1337, "Value does not match");

        let result_higher = self.th_util_select_one_double_checkpointed_object_value::<V>(table, obj_id, secondary_id, start_checkpoint_id + 100).await?;
        assert!(result_higher.is_some(), "Value not found at higher checkpoint after insert at checkpoint 1337");
        let result_higher_unwrapped = result_higher.unwrap();
        assert!(result_higher_unwrapped == value_c_1337, "Value does not match at higher checkpoint");
        let result_higher_with_ids = self.store.db_select_one_double_checkpointed_object_value_and_ids::<V>(table, obj_id, secondary_id, start_checkpoint_id + 100).await?;
        assert!(result_higher_with_ids.is_some(), "Value with ids not found at higher checkpoint after insert at checkpoint 1337");
        let result_higher_with_ids_unwrapped = result_higher_with_ids.unwrap();
        assert!(result_higher_with_ids_unwrapped.obj_id == obj_id, "Object id does not match at higher checkpoint");
        assert!(result_higher_with_ids_unwrapped.secondary_id == secondary_id, "Secondary id does not match at higher checkpoint");
        assert!(result_higher_with_ids_unwrapped.checkpoint_id == start_checkpoint_id, "Checkpoint id does not match at higher checkpoint");
        assert!(result_higher_with_ids_unwrapped.value == value_c_1337, "Value does not match at higher checkpoint");

        let result_lower = self.store.db_select_one_double_checkpointed_object_value::<V>(table, obj_id, secondary_id, start_checkpoint_id - 1).await?;
        assert!(result_lower.is_none(), "Value should not be found at lower checkpoint after insert at checkpoint 1337");
        let result_lower_with_ids = self.store.db_select_one_double_checkpointed_object_value_and_ids::<V>(table, obj_id, secondary_id, start_checkpoint_id - 1).await?;
        assert!(result_lower_with_ids.is_none(), "Value with ids should not be found at lower checkpoint after insert at checkpoint 1337");

        let value_c_1000 = V::qp_rand_gen();
        let lower_checkpoint_id = 1000u64;
        self.store.db_insert_one_double_checkpointed_object(table, obj_id, secondary_id, lower_checkpoint_id, &value_c_1000).await?;
        let result_after_lower_insert = self.th_util_select_one_double_checkpointed_object_value::<V>(table, obj_id, secondary_id, lower_checkpoint_id).await?;
        assert!(result_after_lower_insert.is_some(), "Value not found after insert at lower checkpoint 1000");
        let result_after_lower_insert_unwrapped = result_after_lower_insert.unwrap();
        assert!(result_after_lower_insert_unwrapped == value_c_1000, "Inserted value at lower checkpoint does not match");
        let result_after_lower_insert_with_ids = self.store.db_select_one_double_checkpointed_object_value_and_ids::<V>(table, obj_id, secondary_id, lower_checkpoint_id).await?;
        assert!(result_after_lower_insert_with_ids.is_some(), "Value with ids not found after insert at lower checkpoint 1000");
        let result_after_lower_insert_with_ids_unwrapped = result_after_lower_insert_with_ids.unwrap();
        assert!(result_after_lower_insert_with_ids_unwrapped.obj_id == obj_id, "Object id does not match after lower checkpoint insert");
        assert!(result_after_lower_insert_with_ids_unwrapped.secondary_id == secondary_id, "Secondary id does not match after lower checkpoint insert");
        assert!(result_after_lower_insert_with_ids_unwrapped.checkpoint_id == lower_checkpoint_id, "Checkpoint id does not match after lower checkpoint insert");
        assert!(result_after_lower_insert_with_ids_unwrapped.value == value_c_1000, "Value does not match after lower checkpoint insert");

        let result_higher_after_lower_insert = self.th_util_select_one_double_checkpointed_object_value::<V>(table, obj_id, secondary_id, start_checkpoint_id).await?;
        assert!(result_higher_after_lower_insert.is_some(), "Value not found at original checkpoint after lower checkpoint insert");
        let result_higher_after_lower_insert_unwrapped = result_higher_after_lower_insert.unwrap();
        assert!(result_higher_after_lower_insert_unwrapped == value_c_1337, "Value at original checkpoint does not match after lower checkpoint insert");
        let result_higher_after_lower_insert_with_ids = self.store.db_select_one_double_checkpointed_object_value_and_ids::<V>(table, obj_id, secondary_id, start_checkpoint_id).await?;
        assert!(result_higher_after_lower_insert_with_ids.is_some(), "Value with ids not found at original checkpoint after lower checkpoint insert");
        let result_higher_after_lower_insert_with_ids_unwrapped = result_higher_after_lower_insert_with_ids.unwrap();
        assert!(result_higher_after_lower_insert_with_ids_unwrapped.obj_id == obj_id, "Object id does not match at original checkpoint after lower checkpoint insert");
        assert!(result_higher_after_lower_insert_with_ids_unwrapped.secondary_id == secondary_id, "Secondary id does not match at original checkpoint after lower checkpoint insert");
        assert!(result_higher_after_lower_insert_with_ids_unwrapped.checkpoint_id == start_checkpoint_id, "Checkpoint id does not match at original checkpoint after lower checkpoint insert");
        assert!(result_higher_after_lower_insert_with_ids_unwrapped.value == value_c_1337, "Value does not match at original checkpoint after lower checkpoint insert");

        let first_10_checkpoints = (0..10u64).map(|i| V::qp_rand_gen()).collect::<Vec<_>>();

        let should_be_empty_pre_insert_0 = self.store.db_select_one_double_checkpointed_object_value::<V>(table, obj_id, secondary_id, 0).await?;
        assert!(should_be_empty_pre_insert_0.is_none(), "Value should not be found at checkpoint 0 before insert");
        let should_be_empty_pre_insert_5 = self.store.db_select_one_double_checkpointed_object_value::<V>(table, obj_id, secondary_id, 5).await?;
        assert!(should_be_empty_pre_insert_5.is_none(), "Value should not be found at checkpoint 5 before insert");
        let should_be_empty_pre_insert_9 = self.store.db_select_one_double_checkpointed_object_value::<V>(table, obj_id, secondary_id, 9).await?;
        assert!(should_be_empty_pre_insert_9.is_none(), "Value should not be found at checkpoint 9 before insert");

        for (checkpoint_id, value) in first_10_checkpoints.iter().enumerate() {
            self.store.db_insert_one_double_checkpointed_object(table, obj_id, secondary_id, checkpoint_id as u64, value).await?;
            let should_be_value_post_insert = self.store.db_select_one_double_checkpointed_object_value::<V>(table, obj_id, secondary_id, checkpoint_id as u64).await?;
            assert!(should_be_value_post_insert.is_some(), "Value should be found at checkpoint {} after insert", checkpoint_id);
            let should_be_value_post_insert_unwrapped = should_be_value_post_insert.unwrap();
            assert!(should_be_value_post_insert_unwrapped == *value, "Value at checkpoint {} does not match inserted value", checkpoint_id);
            for future_checkpoint in (checkpoint_id + 1)..10 {
                let should_be_value_future = self.store.db_select_one_double_checkpointed_object_value::<V>(table, obj_id, secondary_id, future_checkpoint as u64).await?;
                assert!(should_be_value_future.is_some(), "Value should be found at future checkpoint {} after insert at checkpoint {}", future_checkpoint, checkpoint_id);
                let should_be_value_future_unwrapped = should_be_value_future.unwrap();
                assert!(should_be_value_future_unwrapped == *value, "Value at future checkpoint {} does not match value at checkpoint {} after insert", future_checkpoint, checkpoint_id);
            }
        }

        let (non_existent_obj_id_a, non_existent_sec_id_a) = self.get_non_existent_id_in_double_object::<V>(table).await?;

        let (non_existent_obj_id_b, non_existent_sec_id_b) = self.get_non_existent_id_in_double_object::<V>(table).await?;


        let result = self.store.db_select_many_double_checkpointed_object_values::<V>(table, &[QDoubleIdKey::from((non_existent_obj_id_a, non_existent_sec_id_a)), QDoubleIdKey::from((obj_id, secondary_id)), QDoubleIdKey::from((non_existent_obj_id_b, non_existent_sec_id_b))], MAX_REAL_CHECKPOINT_ID).await?;
        assert!(result.len() == 3, "Expected 3 results from multi-select");
        assert!(result[0].is_none(), "Expected first result to be None for non-existent pair");
        assert!(result[1].is_some(), "Expected second result to be Some for existing pair");
        assert!(result[1].as_ref().unwrap() == &value_c_1337, "Expected second result to match inserted value");
        assert!(result[2].is_none(), "Expected third result to be None for non-existent pair");


        let result = self.store.db_select_many_double_checkpointed_object_values::<V>(table, &[QDoubleIdKey::from((non_existent_obj_id_a, non_existent_sec_id_a)), QDoubleIdKey::from((obj_id, secondary_id)), QDoubleIdKey::from((non_existent_obj_id_b, non_existent_sec_id_b))], 500).await?;
        assert!(result.len() == 3, "Expected 3 results from multi-select at intermediate checkpoint");
        assert!(result[0].is_none(), "Expected first result to be None for non-existent pair at intermediate checkpoint");
        assert!(result[1].is_some(), "Expected second result to be Some for existing pair at intermediate checkpoint");
        assert!(result[1].as_ref().unwrap() == &first_10_checkpoints[9], "Expected second result to match inserted value at intermediate first_10_checkpoints[9]");
        assert!(result[2].is_none(), "Expected third result to be None for non-existent pair at intermediate checkpoint");

        let result = self.store.db_select_many_double_checkpointed_object_values::<V>(table, &[QDoubleIdKey::from((obj_id, secondary_id)), QDoubleIdKey::from((non_existent_obj_id_a, non_existent_sec_id_a)), QDoubleIdKey::from((obj_id, secondary_id)), QDoubleIdKey::from((non_existent_obj_id_b, non_existent_sec_id_b)), QDoubleIdKey::from((obj_id, secondary_id))], MAX_REAL_CHECKPOINT_ID).await?;
        assert!(result.len() == 5, "Expected 5 results from multi-select with duplicates");
        assert!(result[0].is_some(), "Expected first result to be Some for existing pair");
        assert!(result[0].as_ref().unwrap() == &value_c_1337, "Expected first result to match inserted value");
        assert!(result[1].is_none(), "Expected second result to be None for non-existent pair");
        assert!(result[2].is_some(), "Expected third result to be Some for existing pair");
        assert!(result[2].as_ref().unwrap() == &value_c_1337, "Expected third result to match inserted value");
        assert!(result[3].is_none(), "Expected fourth result to be None for non-existent pair");
        assert!(result[4].is_some(), "Expected fifth result to be Some for existing pair");
        assert!(result[4].as_ref().unwrap() == &value_c_1337, "Expected fifth result to match inserted value");


        Ok(())
    }

    pub async fn th_test_double_checkpointed_object_1_full_history_3<V: PsyDBSer + QPGenRandom>(&self, table: &DoubleIdTableIdentifier) -> anyhow::Result<()>{
        let first_checkpoint = 0u64;
        let second_checkpoint = 1u64;
        let last_checkpoint = 100_000u64;

        let double_ids_batch_a = self.get_many_non_existent_double_ids_in_double_object::<V>(table, 2000).await?;
        assert!(double_ids_batch_a.len() == 2000, "Expected to get 2000 non-existent double ids");

        let obj_rows_batch_a = double_ids_batch_a.iter().map(|&(id, sec_id)| QDatabaseDoubleIdTableRowNoCheckpointId::new(id, sec_id, V::qp_rand_gen())).collect::<Vec<_>>();

        self.store.db_insert_many_double_checkpointed_objects_at_checkpoint(table, first_checkpoint, &obj_rows_batch_a).await?;
        let keys_a = double_ids_batch_a.iter().map(|&(id, sec_id)| QDoubleIdKey::from((id, sec_id))).collect::<Vec<_>>();
        let objs_a_at_first = self.store.db_select_many_double_checkpointed_object_values::<V>(table, &keys_a, first_checkpoint).await?;
        let objs_a_at_first = objs_a_at_first.into_iter().collect::<Option<Vec<V>>>().ok_or_else(|| anyhow::anyhow!("Expected all objects to be found at first checkpoint"))?;
        assert!(objs_a_at_first.len() == double_ids_batch_a.len(), "Expected all objects to be found at first checkpoint");
        for (i, obj) in objs_a_at_first.iter().enumerate() {
            assert!(obj == &obj_rows_batch_a[i].value, "Expected object value to match at first checkpoint");
        }
        let objs_a_at_second = self.store.db_select_many_double_checkpointed_object_values::<V>(table, &keys_a, second_checkpoint).await?;
        let objs_a_at_second = objs_a_at_second.into_iter().collect::<Option<Vec<V>>>().ok_or_else(|| anyhow::anyhow!("Expected all objects to be found at second checkpoint"))?;
        assert!(objs_a_at_second.len() == double_ids_batch_a.len(), "Expected all objects to be found at second checkpoint");
        for (i, obj) in objs_a_at_second.iter().enumerate() {
            assert!(obj == &obj_rows_batch_a[i].value, "Expected object value to match at second checkpoint");
        }
        let objs_a_at_high = self.store.db_select_many_double_checkpointed_object_keys_and_values::<V, QDatabaseDoubleIdTableRow<V>>(table, &keys_a, 12312732).await?;
        for (i, row) in objs_a_at_high.iter().enumerate() {
            assert!(row.obj_id == double_ids_batch_a[i].0, "Expected object id to match at high checkpoint");
            assert!(row.secondary_id == double_ids_batch_a[i].1, "Expected secondary id to match at high checkpoint");
            assert!(row.checkpoint_id == first_checkpoint, "Expected checkpoint id to match at high checkpoint");
            assert!(row.value == obj_rows_batch_a[i].value, "Expected object value to match at high checkpoint");
        }

        let obj_rows_batch_a_second = double_ids_batch_a.iter().map(|&(id, sec_id)| QDatabaseDoubleIdTableRowNoCheckpointId::new(id, sec_id, V::qp_rand_gen())).collect::<Vec<_>>();
        let double_ids_batch_b = self.get_many_non_existent_double_ids_in_double_object::<V>(table, 1500).await?;
        assert!(double_ids_batch_b.len() == 1500, "Expected to get 1500 non-existent double ids for batch b");
        let obj_rows_batch_b = double_ids_batch_b.iter().map(|&(id, sec_id)| QDatabaseDoubleIdTableRowNoCheckpointId::new(id, sec_id, V::qp_rand_gen())).collect::<Vec<_>>();
        let combined_rows: Vec<QDatabaseDoubleIdTableRowNoCheckpointId<V>> = obj_rows_batch_a_second.iter().chain(obj_rows_batch_b.iter()).cloned().collect();
        self.store.db_insert_many_double_checkpointed_objects_at_checkpoint(table, second_checkpoint, &combined_rows).await?;

        let combined_double_ids = double_ids_batch_a.iter().chain(double_ids_batch_b.iter()).cloned().collect::<Vec<_>>();
        let combined_keys = combined_double_ids.iter().map(|&(id, sec_id)| QDoubleIdKey::from((id, sec_id))).collect::<Vec<_>>();
        let objs_combined_at_second = self.store.db_select_many_double_checkpointed_object_values::<V>(table, &combined_keys, second_checkpoint).await?;
        let objs_combined_at_second = objs_combined_at_second.into_iter().collect::<Option<Vec<V>>>().ok_or_else(|| anyhow::anyhow!("Expected all objects to be found at second checkpoint after second insert"))?;
        assert!(objs_combined_at_second.len() == combined_double_ids.len(), "Expected all objects to be found at second checkpoint after second insert");
        for i in 0..double_ids_batch_a.len() {
            assert!(objs_combined_at_second[i] == obj_rows_batch_a_second[i].value, "Expected object value to match for batch a at second checkpoint after second insert");
        }
        for i in 0..double_ids_batch_b.len() {
            assert!(objs_combined_at_second[i + double_ids_batch_a.len()] == obj_rows_batch_b[i].value, "Expected object value to match for batch b at second checkpoint after second insert");
        }
        let objs_a_at_first_post_second = self.store.db_select_many_double_checkpointed_object_values::<V>(table, &combined_keys, first_checkpoint).await?;
        let objs_a_at_first_post_second = objs_a_at_first_post_second[0..double_ids_batch_a.len()].to_vec().into_iter().collect::<Option<Vec<V>>>().ok_or_else(|| anyhow::anyhow!("Expected all batch a objects to be found at first checkpoint after second insert"))?;
        assert!(objs_a_at_first_post_second.len() == double_ids_batch_a.len(), "Expected all batch a objects to be found at first checkpoint after second insert");
        for (i, obj) in objs_a_at_first_post_second.iter().enumerate() {
            assert!(obj == &obj_rows_batch_a[i].value, "Expected batch a object value to match at first checkpoint after second insert");
        }
        let keys_b = double_ids_batch_b.iter().map(|&(id, sec_id)| QDoubleIdKey::from((id, sec_id))).collect::<Vec<_>>();
        let objs_b_at_first_post_second = self.store.db_select_many_double_checkpointed_object_values::<V>(table, &keys_b, first_checkpoint).await?;
        for obj in objs_b_at_first_post_second.iter() {
            assert!(obj.is_none(), "Expected batch b object to not be found at first checkpoint after second insert");
        }

        let obj_rows_batch_a_last = double_ids_batch_a.iter().map(|&(id, sec_id)| QDatabaseDoubleIdTableRowNoCheckpointId::new(id, sec_id, V::qp_rand_gen())).collect::<Vec<_>>();
        let obj_rows_batch_b_last = double_ids_batch_b.iter().map(|&(id, sec_id)| QDatabaseDoubleIdTableRowNoCheckpointId::new(id, sec_id, V::qp_rand_gen())).collect::<Vec<_>>();
        self.store.db_insert_many_double_checkpointed_objects_at_checkpoint(table, last_checkpoint, &obj_rows_batch_a_last).await?;
        self.store.db_insert_many_double_checkpointed_objects_at_checkpoint_t(table, last_checkpoint, &obj_rows_batch_b_last).await?;
        let objs_combined_at_last = self.store.db_select_many_double_checkpointed_object_values::<V>(table, &combined_keys, last_checkpoint).await?;
        let objs_combined_at_last = objs_combined_at_last.into_iter().collect::<Option<Vec<V>>>().ok_or_else(|| anyhow::anyhow!("Expected all objects to be found at last checkpoint after last insert"))?;
        assert!(objs_combined_at_last.len() == combined_double_ids.len(), "Expected all objects to be found at last checkpoint after last insert");
        for i in 0..double_ids_batch_a.len() {
            assert!(objs_combined_at_last[i] == obj_rows_batch_a_last[i].value, "Expected object value to match for batch a at last checkpoint after last insert");
        }
        for i in 0..double_ids_batch_b.len() {
            assert!(objs_combined_at_last[i + double_ids_batch_a.len()] == obj_rows_batch_b_last[i].value, "Expected object value to match for batch b at last checkpoint after last insert");
        }
        let objs_a_at_second_post_last = self.store.db_select_many_double_checkpointed_object_values::<V>(table, &combined_keys, second_checkpoint).await?;
        let objs_a_at_second_post_last = objs_a_at_second_post_last[0..double_ids_batch_a.len()].to_vec().into_iter().collect::<Option<Vec<V>>>().ok_or_else(|| anyhow::anyhow!("Expected all batch a objects to be found at second checkpoint after last insert"))?;
        assert!(objs_a_at_second_post_last.len() == double_ids_batch_a.len(), "Expected all batch a objects to be found at second checkpoint after last insert");
        for (i, obj) in objs_a_at_second_post_last.iter().enumerate() {
            assert!(obj == &obj_rows_batch_a_second[i].value, "Expected batch a object value to match at second checkpoint after last insert");
        }
        let objs_b_at_second_post_last = self.store.db_select_many_double_checkpointed_object_values::<V>(table, &keys_b, second_checkpoint).await?;
        let objs_b_at_second_post_last = objs_b_at_second_post_last.into_iter().collect::<Option<Vec<V>>>().ok_or_else(|| anyhow::anyhow!("Expected all batch b objects to be found at second checkpoint after last insert"))?;
        for (i, obj) in objs_b_at_second_post_last.iter().enumerate() {
            assert!(obj == &obj_rows_batch_b[i].value, "Expected batch b object value to match at second checkpoint after last insert");
        }
        let objs_a_at_first_post_last = self.store.db_select_many_double_checkpointed_object_values::<V>(table, &combined_keys, first_checkpoint).await?;
        let objs_a_at_first_post_last = objs_a_at_first_post_last[0..double_ids_batch_a.len()].to_vec().into_iter().collect::<Option<Vec<V>>>().ok_or_else(|| anyhow::anyhow!("Expected all batch a objects to be found at first checkpoint after last insert"))?;
        assert!(objs_a_at_first_post_last.len() == double_ids_batch_a.len(), "Expected all batch a objects to be found at first checkpoint after last insert");
        for (i, obj) in objs_a_at_first_post_last.iter().enumerate() {
            assert!(obj == &obj_rows_batch_a[i].value, "Expected batch a object value to match at first checkpoint after last insert");
        }
        let objs_b_at_first_post_last = self.store.db_select_many_double_checkpointed_object_values::<V>(table, &keys_b, first_checkpoint).await?;
        for obj in objs_b_at_first_post_last.iter() {
            assert!(obj.is_none(), "Expected batch b object to not be found at first checkpoint after last insert");
        }

        Ok(())
    }

    pub async fn th_util_select_double_id_merkle_node_max_checkpoint(
        &self,
        table: &DoubleIdMerkleTableIdentifier,
        tree_height: u8,
        max_checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        key: SimpleMerkleNodeKey,
    ) -> anyhow::Result<Hash> {
        let result = self
            .store
            .db_select_double_id_merkle_node_max_checkpoint(table, max_checkpoint_id, tree_id, tree_sub_id, tree_height, key)
            .await?;
        let zero_hash_at_level = Hasher::get_zero_hash((tree_height - key.level) as usize);
        if result == zero_hash_at_level {
            if max_checkpoint_id > 0 {
                let lower_checkpoint = max_checkpoint_id - 1;
                let lower_result = self
                    .store
                    .db_select_double_id_merkle_node_max_checkpoint(table, lower_checkpoint, tree_id, tree_sub_id, tree_height, key)
                    .await?;
                assert!(lower_result == result, "Lower checkpoint result does not match when result is zero hash");
            }
        }

        let multi_result = self
            .store
            .db_select_many_double_id_merkle_nodes_max_checkpoint(table, max_checkpoint_id, tree_id, tree_sub_id, tree_height, &[key, key])
            .await?;

        assert!(multi_result.len() == 2, "Multi select did not return correct number of results");
        assert!(multi_result[0] == result, "Multi select first result does not match single select result");
        assert!(
            multi_result[1] == result,
            "Multi select second result does not match single select result"
        );

        Ok(result)
    }

    pub async fn th_util_select_many_double_id_merkle_nodes_max_checkpoint(
        &self,
        table: &DoubleIdMerkleTableIdentifier,
        tree_height: u8,
        max_checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Hash>> {
        let result = self
            .store
            .db_select_many_double_id_merkle_nodes_max_checkpoint(table, max_checkpoint_id, tree_id, tree_sub_id, tree_height, keys)
            .await?;
        assert!(
            result.len() == keys.len(),
            "Number of retrieved values does not match number of requested values"
        );
        for (i, key) in keys.iter().enumerate() {
            let single_result = self
                .th_util_select_double_id_merkle_node_max_checkpoint(table, tree_height, max_checkpoint_id, tree_id, tree_sub_id, *key)
                .await?;
            assert!(result[i] == single_result, "Multi select result does not match single select result");
        }
        Ok(result)
    }

    pub async fn th_util_insert_double_id_merkle_node_max_checkpoint(
        &self,
        table: &DoubleIdMerkleTableIdentifier,
        tree_height: u8,
        checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        key: SimpleMerkleNodeKey,
        hash: &Hash,
    ) -> anyhow::Result<()> {
        let prev_lower = if checkpoint_id > 0 {
            self.th_util_select_double_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id - 1, tree_id, tree_sub_id, key)
                .await?
        } else {
            Hasher::get_zero_hash((tree_height - key.level) as usize)
        };

        let higher = self
            .th_util_select_double_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id + 1, tree_id, tree_sub_id, key)
            .await?;

        self.store
            .db_insert_double_id_merkle_node(table, checkpoint_id, tree_id, tree_sub_id, key, hash)
            .await?;

        let after = self
            .th_util_select_double_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id, tree_id, tree_sub_id, key)
            .await?;

        assert!(after == *hash, "Inserted hash does not match retrieved hash after insert");
        if higher == Hasher::get_zero_hash((tree_height - key.level) as usize) {
            let higher_new = self
                .th_util_select_double_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id + 1, tree_id, tree_sub_id, key)
                .await?;
            assert!(higher_new == after, "Higher hash should match inserted hash");
        }

        if prev_lower != Hasher::get_zero_hash((tree_height - key.level) as usize) {
            let prev_lower_again = self
                .th_util_select_double_id_merkle_node_max_checkpoint(
                    table,
                    tree_height,
                    if checkpoint_id > 0 { checkpoint_id - 1 } else { 0 },
                    tree_id,
                    tree_sub_id,
                    key,
                )
                .await?;
            assert!(prev_lower_again == prev_lower, "Previous lower hash should not change after insert");
        }

        let multi_result = self
            .store
            .db_select_many_double_id_merkle_nodes_max_checkpoint(table, checkpoint_id, tree_id, tree_sub_id, tree_height, &[key, key])
            .await?;
        assert!(multi_result.len() == 2, "Multi select did not return correct number of results");
        assert!(multi_result[0] == after, "Multi select first result does not match single select result");
        assert!(multi_result[1] == after, "Multi select second result does not match single select result");

        Ok(())
    }
    pub async fn th_util_insert_many_double_id_merkle_node_max_checkpoint(
        &self,
        table: &DoubleIdMerkleTableIdentifier,
        tree_height: u8,
        checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        nodes: &[SimpleMerkleNode<Hash>],
    ) -> anyhow::Result<()> {
        let keys = nodes.iter().map(|n| n.key).collect::<Vec<SimpleMerkleNodeKey>>();
        let mut prev_lowers = Vec::with_capacity(nodes.len());
        let mut highers = Vec::with_capacity(nodes.len());
        for key in keys.iter() {
            let prev_lower = if checkpoint_id > 0 {
                self.th_util_select_double_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id - 1, tree_id, tree_sub_id, *key)
                    .await?
            } else {
                Hasher::get_zero_hash((tree_height - key.level) as usize)
            };
            prev_lowers.push(prev_lower);
            let higher = self
                .th_util_select_double_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id + 1, tree_id, tree_sub_id, *key)
                .await?;
            highers.push(higher);
        }

        self.store
            .db_set_double_id_merkle_nodes_batch(table, checkpoint_id, tree_id, tree_sub_id, nodes)
            .await?;
        for (i, node) in nodes.iter().enumerate() {
            let after = self
                .th_util_select_double_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id, tree_id, tree_sub_id, node.key)
                .await?;
            assert!(after == node.value, "Inserted hash does not match retrieved hash after insert");

            if highers[i] == Hasher::get_zero_hash((tree_height - node.key.level) as usize) {
                let higher_new = self
                    .th_util_select_double_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id + 1, tree_id, tree_sub_id, node.key)
                    .await?;
                assert!(higher_new == after, "Higher hash should match inserted hash");
            }

            if prev_lowers[i] != Hasher::get_zero_hash((tree_height - node.key.level) as usize) {
                let prev_lower_again = self
                    .th_util_select_double_id_merkle_node_max_checkpoint(
                        table,
                        tree_height,
                        if checkpoint_id > 0 { checkpoint_id - 1 } else { 0 },
                        tree_id,
                        tree_sub_id,
                        node.key,
                    )
                    .await?;
                assert!(prev_lower_again == prev_lowers[i], "Previous lower hash should not change after insert");
            }
        }
        let multi_result = self
            .store
            .db_select_many_double_id_merkle_nodes_max_checkpoint(table, checkpoint_id, tree_id, tree_sub_id, tree_height, &keys)
            .await?;
        assert!(multi_result.len() == nodes.len(), "Multi select did not return correct number of results");
        for (i, node) in nodes.iter().enumerate() {
            let after = self
                .th_util_select_double_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id, tree_id, tree_sub_id, node.key)
                .await?;
            assert!(multi_result[i] == after, "Multi select result does not match single select result");
        }
        Ok(())
    }


    async fn th_ensure_double_id_merkle_zero_hashes_at_checkpoint_for_sub_tree_a(&self, table: &DoubleIdMerkleTableIdentifier, tree_id: u64, tree_sub_id: u64, checkpoint_id: u64, tree_height: u8, root: SimpleMerkleNodeKey) -> anyhow::Result<()> {
        assert!(tree_height >= root.level, "Tree height must be greater than or equal to root level");
        let root_value = self.store.db_select_double_id_merkle_node_max_checkpoint(table, checkpoint_id, tree_id, tree_sub_id, tree_height, root).await?;
        assert!(root_value == Hasher::get_zero_hash((tree_height-root.level) as usize), "Root value must be zero hash at root level");
        if root.level == tree_height {
            return Ok(());
        }

        let child_keys = rand_children_to_height(&root, tree_height);
        let node_values = self.store.db_select_many_double_id_merkle_nodes_max_checkpoint(table, checkpoint_id, tree_id, tree_sub_id, tree_height, &child_keys).await?;
        let expected_values = child_keys.iter().map(|key| Hasher::get_zero_hash((tree_height - key.level) as usize)).collect::<Vec<_>>();
        assert!(node_values.len() == expected_values.len(), "Node values and expected values lengths must match");
        for (i, value) in node_values.iter().enumerate() {
            assert!(value == &expected_values[i], "Node value must match expected zero hash");
        }

        Ok(())
    }

    pub async fn th_test_insert_double_id_merkle_leaves_sub_tree_dmp(&self, table: &DoubleIdMerkleTableIdentifier, checkpoint_id: u64, tree_id: u64, tree_sub_id: u64, tree_height: u8, sub_root_key: &SimpleMerkleNodeKey, leaves: &[SimpleMerkleNode<Hash>]) -> anyhow::Result<Vec<DeltaMerkleProofCore<Hash>>> {
        if leaves.is_empty() {
            return Ok(vec![]);
        }
        assert!(sub_root_key.level <= tree_height, "Sub root level must be at or below the tree height level");
        
        let first_leaf_level = leaves[0].key.level;
        assert!(first_leaf_level <= tree_height, "Leaf keys must be at or below the tree height level");
        assert!(first_leaf_level >= sub_root_key.level, "Leaf keys must be at or below the sub root level");

        for leaf in leaves.iter() {
            assert!(leaf.key.level == first_leaf_level, "All leaf keys must be at the same level");
        }
        let leaf_values = leaves.iter().map(|node| node.value).collect::<Vec<_>>();
        let leaf_keys = leaves.iter().map(|node: &SimpleMerkleNode<Hash>| node.key).collect::<Vec<_>>();
        let dmps = db_helper_double_id_merkle_node_simple_set_leaves_fast_serialize::<Hash, Hasher, DoubleIdMerkleTableIdentifier,_>(&self.store, table, checkpoint_id, tree_id, tree_sub_id, tree_height, 0, 9999, leaves).await?;
        assert!(dmps.len() == leaves.len(), "Number of DeltaMerkleProofs must match number of inserted leaves");
        let selected_leaf_values = self.store.db_select_many_double_id_merkle_nodes_max_checkpoint(table, checkpoint_id, tree_id, tree_sub_id, tree_height, &leaf_keys).await?;
        assert!(selected_leaf_values.len() == leaf_values.len(), "Selected leaf values length must match inserted leaf values length");
        for (i, value) in selected_leaf_values.iter().enumerate() {
            assert!(value == &leaf_values[i], "Selected leaf value must match inserted leaf value");
        }
        for dmp in dmps.iter() {

            assert!(dmp.verify::<Hasher>(), "DeltaMerkleProof must verify correctly");
        }

        for i in 1..dmps.len() {
            assert!(dmps[i-1].new_root == dmps[i].old_root, "Consecutive DeltaMerkleProofs must be connected back to back, ie. new_root of previous must equal old_root of next"); 
        }
        

        Ok(dmps)

    }

    pub async fn th_test_double_id_merkle_nodes_basic(&self, table: &DoubleIdMerkleTableIdentifier, tree_id: u64, tree_sub_id: u64, tree_height: u8) -> anyhow::Result<()> {

        let first_checkpoint_id = 1u64;
        let second_checkpoint_id = 2u64;
        let third_checkpoint_id = 3u64;
        let fourth_checkpoint_id = 999u64;
        let last_checkpoint_id = 12874892u64;
        self.th_ensure_double_id_merkle_zero_hashes_at_checkpoint_for_sub_tree_a(table, tree_id, tree_sub_id, first_checkpoint_id, tree_height, SimpleMerkleNodeKey::new_root()).await?;
        self.th_ensure_double_id_merkle_zero_hashes_at_checkpoint_for_sub_tree_a(table, tree_id, tree_sub_id, second_checkpoint_id, tree_height, SimpleMerkleNodeKey::new_root()).await?;
        self.th_ensure_double_id_merkle_zero_hashes_at_checkpoint_for_sub_tree_a(table, tree_id, tree_sub_id, third_checkpoint_id, tree_height, SimpleMerkleNodeKey::new_root()).await?;
        self.th_ensure_double_id_merkle_zero_hashes_at_checkpoint_for_sub_tree_a(table, tree_id, tree_sub_id, fourth_checkpoint_id, tree_height, SimpleMerkleNodeKey::new_root()).await?;
        self.th_ensure_double_id_merkle_zero_hashes_at_checkpoint_for_sub_tree_a(table, tree_id, tree_sub_id, last_checkpoint_id, tree_height, SimpleMerkleNodeKey::new_root()).await?;

        let max_leaves_in_tree = 1u64 << tree_height;
        let num_leaves_to_insert = 16u64.min(max_leaves_in_tree);
        let num_leaves_to_insert_usize = num_leaves_to_insert as usize;
        let root_key = SimpleMerkleNodeKey::new_root();
        let first_batch = rand_leaves_for_subtree::<Hash>(&root_key, tree_height, num_leaves_to_insert_usize);

        let dmps_0 = self.th_test_insert_double_id_merkle_leaves_sub_tree_dmp(table, first_checkpoint_id, tree_id, tree_sub_id, tree_height, &SimpleMerkleNodeKey::new_root(), &first_batch).await?;
        assert!(dmps_0.len() == first_batch.len(), "Number of DeltaMerkleProofs must match number of inserted leaves at first checkpoint");

        self.th_ensure_double_id_merkle_zero_hashes_at_checkpoint_for_sub_tree_a(table, tree_id, tree_sub_id, 0, tree_height, SimpleMerkleNodeKey::new_root()).await?;
        let second_batch = rand_leaves_for_subtree::<Hash>(&root_key, tree_height, num_leaves_to_insert_usize);
        let dmps_1 = self.th_test_insert_double_id_merkle_leaves_sub_tree_dmp(table, second_checkpoint_id, tree_id, tree_sub_id, tree_height, &SimpleMerkleNodeKey::new_root(), &second_batch).await?;
        assert!(dmps_1.len() == second_batch.len(), "Number of DeltaMerkleProofs must match number of inserted leaves at second checkpoint");
        

        let first_second_batch_combined_halves = [
            first_batch[0..(num_leaves_to_insert_usize/2)].to_vec(),
            second_batch[(num_leaves_to_insert_usize/2)..num_leaves_to_insert_usize].to_vec()
        ].concat();
        let third_batch_unmodified = [
            first_batch[(num_leaves_to_insert_usize/2)..num_leaves_to_insert_usize].to_vec(),
            second_batch[0..(num_leaves_to_insert_usize/2)].to_vec()
        ].concat();
        let third_batch_new_leaves = rand_leaves_for_subtree::<Hash>(&root_key, tree_height, num_leaves_to_insert_usize);
        let first_second_batch_leaves_at_third_checkpoint = first_second_batch_combined_halves.iter().map(|x|{
            SimpleMerkleNode {
                key: x.key,
                value: Hash::qp_rand_gen(),
            }
        }).collect::<Vec<_>>();
        let third_batch = [first_second_batch_leaves_at_third_checkpoint, third_batch_new_leaves.clone()].concat();
        let dmps_2 = self.th_test_insert_double_id_merkle_leaves_sub_tree_dmp(table, third_checkpoint_id, tree_id, tree_sub_id, tree_height, &SimpleMerkleNodeKey::new_root(), &third_batch).await?;
        assert!(dmps_2.len() == third_batch.len(), "Number of DeltaMerkleProofs must match number of inserted leaves at third checkpoint");
        let b12_unmodified_keys = third_batch_unmodified.iter().map(|x| x.key).collect::<Vec<_>>();
        let b12_unmodified_values = third_batch_unmodified.iter().map(|x| x.value).collect::<Vec<_>>();
        let selected_unmodified_values = self.store.db_select_many_double_id_merkle_nodes_max_checkpoint(table, third_checkpoint_id, tree_id, tree_sub_id, tree_height, &b12_unmodified_keys).await?;
        assert!(selected_unmodified_values.len() == b12_unmodified_values.len(), "Selected unmodified values length must match unmodified values length at third checkpoint");
        for (i, value) in selected_unmodified_values.iter().enumerate() {
            assert!(value == &b12_unmodified_values[i], "Selected unmodified value must match unmodified value at third checkpoint");
        }
        let b3_modified_keys = third_batch_new_leaves.iter().map(|x| x.key).collect::<Vec<_>>();
        let b3_modified_values = third_batch_new_leaves.iter().map(|x| x.value).collect::<Vec<_>>();
        let selected_modified_values = self.store.db_select_many_double_id_merkle_nodes_max_checkpoint(table, third_checkpoint_id, tree_id, tree_sub_id, tree_height, &b3_modified_keys).await?;
        assert!(selected_modified_values.len() == b3_modified_values.len(), "Selected modified values length must match modified values length at third checkpoint");
        for (i, value) in selected_modified_values.iter().enumerate() {
            assert!(value == &b3_modified_values[i], "Selected modified value must match modified value at third checkpoint");
        }

        let fourth_batch = rand_leaves_for_subtree::<Hash>(&root_key, tree_height, num_leaves_to_insert_usize);
        let dmps_3 = self.th_test_insert_double_id_merkle_leaves_sub_tree_dmp(table, fourth_checkpoint_id, tree_id, tree_sub_id, tree_height, &SimpleMerkleNodeKey::new_root(), &fourth_batch).await?;
        assert!(dmps_3.len() == fourth_batch.len(), "Number of DeltaMerkleProofs must match number of inserted leaves at fourth checkpoint");

        let last_batch = rand_leaves_for_subtree::<Hash>(&root_key, tree_height, num_leaves_to_insert_usize);
        let dmps_4 = self.th_test_insert_double_id_merkle_leaves_sub_tree_dmp(table, last_checkpoint_id, tree_id, tree_sub_id, tree_height, &SimpleMerkleNodeKey::new_root(), &last_batch).await?;
        assert!(dmps_4.len() == last_batch.len(), "Number of DeltaMerkleProofs must match number of inserted leaves at last checkpoint");

        let keys_to_check: Vec<_> = first_batch.iter().chain(second_batch.iter()).chain(third_batch.iter()).chain(fourth_batch.iter()).chain(last_batch.iter()).map(|x| x.key)
            .into_iter()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        for k in keys_to_check {
            let mp = db_helper_select_double_id_merkle_proof_max_checkpoint::<Hash, Hasher, _, _>(&self.store, table, first_checkpoint_id+1, tree_id, tree_sub_id, tree_height, &k). await?;
            assert!(mp.verify::<Hasher>(), "MerkleProof must verify correctly for key {:?}", k);
            let mp = db_helper_select_double_id_merkle_proof_max_checkpoint::<Hash, Hasher, _, _>(&self.store, table, second_checkpoint_id, tree_id, tree_sub_id, tree_height, &k). await?;
            assert!(mp.verify::<Hasher>(), "MerkleProof must verify correctly for key {:?}", k);
            let mp = db_helper_select_double_id_merkle_proof_max_checkpoint::<Hash, Hasher, _, _>(&self.store, table, third_checkpoint_id, tree_id, tree_sub_id, tree_height, &k). await?;
            assert!(mp.verify::<Hasher>(), "MerkleProof must verify correctly for key {:?}", k);
            let mp = db_helper_select_double_id_merkle_proof_max_checkpoint::<Hash, Hasher, _, _>(&self.store, table, fourth_checkpoint_id, tree_id, tree_sub_id, tree_height, &k). await?;
            assert!(mp.verify::<Hasher>(), "MerkleProof must verify correctly for key {:?}", k);
            let mp = db_helper_select_double_id_merkle_proof_max_checkpoint::<Hash, Hasher, _, _>(&self.store, table, last_checkpoint_id, tree_id, tree_sub_id, tree_height, &k). await?;
            assert!(mp.verify::<Hasher>(), "MerkleProof must verify correctly for key {:?}", k);
            let mp = db_helper_select_double_id_merkle_proof_max_checkpoint::<Hash, Hasher, _, _>(&self.store, table, last_checkpoint_id+100, tree_id, tree_sub_id, tree_height, &k). await?;
            assert!(mp.verify::<Hasher>(), "MerkleProof must verify correctly for key {:?}", k);
        }
        Ok(())
    }

    pub async fn th_util_select_zero_id_merkle_node_max_checkpoint(
        &self,
        table: &ZeroIdMerkleTableIdentifier,
        tree_height: u8,
        max_checkpoint_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<Hash> {
        let result = self
            .store
            .db_select_zero_id_merkle_node_max_checkpoint(table, max_checkpoint_id, key)
            .await?;
        let zero_hash_at_level = Hasher::get_zero_hash((tree_height - key.level) as usize);
        if result == zero_hash_at_level {
            if max_checkpoint_id > 0 {
                let lower_checkpoint = max_checkpoint_id - 1;
                let lower_result = self
                    .store
                    .db_select_zero_id_merkle_node_max_checkpoint(table, lower_checkpoint, key)
                    .await?;
                assert!(lower_result == result, "Lower checkpoint result does not match when result is zero hash");
            }
        }

        let multi_result = self
            .store
            .db_select_many_zero_id_merkle_nodes_max_checkpoint(table, max_checkpoint_id, &[key.clone(), key.clone()])
            .await?;

        assert!(multi_result.len() == 2, "Multi select did not return correct number of results");
        assert!(multi_result[0] == result, "Multi select first result does not match single select result");
        assert!(
            multi_result[1] == result,
            "Multi select second result does not match single select result"
        );

        Ok(result)
    }

    pub async fn th_util_select_many_zero_id_merkle_nodes_max_checkpoint(
        &self,
        table: &ZeroIdMerkleTableIdentifier,
        tree_height: u8,
        max_checkpoint_id: u64,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Hash>> {
        let result = self
            .store
            .db_select_many_zero_id_merkle_nodes_max_checkpoint(table, max_checkpoint_id, keys)
            .await?;
        assert!(
            result.len() == keys.len(),
            "Number of retrieved values does not match number of requested values"
        );
        for (i, key) in keys.iter().enumerate() {
            let single_result = self
                .th_util_select_zero_id_merkle_node_max_checkpoint(table, tree_height, max_checkpoint_id, key)
                .await?;
            assert!(result[i] == single_result, "Multi select result does not match single select result");
        }
        Ok(result)
    }

    pub async fn th_util_insert_zero_id_merkle_node_max_checkpoint(
        &self,
        table: &ZeroIdMerkleTableIdentifier,
        tree_height: u8,
        checkpoint_id: u64,
        key: &SimpleMerkleNodeKey,
        hash: &Hash,
    ) -> anyhow::Result<()> {
        let prev_lower = if checkpoint_id > 0 {
            self.th_util_select_zero_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id - 1, key)
                .await?
        } else {
            Hasher::get_zero_hash((tree_height - key.level) as usize)
        };

        let higher = self
            .th_util_select_zero_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id + 1, key)
            .await?;

        self.store
            .db_insert_zero_id_merkle_node(table, checkpoint_id, key, hash)
            .await?;

        let after = self
            .th_util_select_zero_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id, key)
            .await?;

        assert!(after == *hash, "Inserted hash does not match retrieved hash after insert");
        if higher == Hasher::get_zero_hash((tree_height - key.level) as usize) {
            let higher_new = self
                .th_util_select_zero_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id + 1, key)
                .await?;
            assert!(higher_new == after, "Higher hash should match inserted hash");
        }

        if prev_lower != Hasher::get_zero_hash((tree_height - key.level) as usize) {
            let prev_lower_again = self
                .th_util_select_zero_id_merkle_node_max_checkpoint(
                    table,
                    tree_height,
                    if checkpoint_id > 0 { checkpoint_id - 1 } else { 0 },
                    key,
                )
                .await?;
            assert!(prev_lower_again == prev_lower, "Previous lower hash should not change after insert");
        }

        let multi_result = self
            .store
            .db_select_many_zero_id_merkle_nodes_max_checkpoint(table, checkpoint_id, &[key.clone(), key.clone()])
            .await?;
        assert!(multi_result.len() == 2, "Multi select did not return correct number of results");
        assert!(multi_result[0] == after, "Multi select first result does not match single select result");
        assert!(multi_result[1] == after, "Multi select second result does not match single select result");

        Ok(())
    }

    pub async fn th_util_insert_many_zero_id_merkle_node_max_checkpoint(
        &self,
        table: &ZeroIdMerkleTableIdentifier,
        tree_height: u8,
        checkpoint_id: u64,
        nodes: &[SimpleMerkleNode<Hash>],
    ) -> anyhow::Result<()> {
        let keys = nodes.iter().map(|n| n.key.clone()).collect::<Vec<SimpleMerkleNodeKey>>();
        let mut prev_lowers = Vec::with_capacity(nodes.len());
        let mut highers = Vec::with_capacity(nodes.len());
        for key in keys.iter() {
            let prev_lower = if checkpoint_id > 0 {
                self.th_util_select_zero_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id - 1, key)
                    .await?
            } else {
                Hasher::get_zero_hash((tree_height - key.level) as usize)
            };
            prev_lowers.push(prev_lower);
            let higher = self
                .th_util_select_zero_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id + 1, key)
                .await?;
            highers.push(higher);
        }

        self.store
            .db_set_zero_id_merkle_nodes_batch(table, checkpoint_id, nodes)
            .await?;
        for (i, node) in nodes.iter().enumerate() {
            let after = self
                .th_util_select_zero_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id, &node.key)
                .await?;
            assert!(after == node.value, "Inserted hash does not match retrieved hash after insert");

            if highers[i] == Hasher::get_zero_hash((tree_height - node.key.level) as usize) {
                let higher_new = self
                    .th_util_select_zero_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id + 1, &node.key)
                    .await?;
                assert!(higher_new == after, "Higher hash should match inserted hash");
            }

            if prev_lowers[i] != Hasher::get_zero_hash((tree_height - node.key.level) as usize) {
                let prev_lower_again = self
                    .th_util_select_zero_id_merkle_node_max_checkpoint(
                        table,
                        tree_height,
                        if checkpoint_id > 0 { checkpoint_id - 1 } else { 0 },
                        &node.key,
                    )
                    .await?;
                assert!(prev_lower_again == prev_lowers[i], "Previous lower hash should not change after insert");
            }
        }
        let multi_result = self
            .store
            .db_select_many_zero_id_merkle_nodes_max_checkpoint(table, checkpoint_id, &keys)
            .await?;
        assert!(multi_result.len() == nodes.len(), "Multi select did not return correct number of results");
        for (i, node) in nodes.iter().enumerate() {
            let after = self
                .th_util_select_zero_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id, &node.key)
                .await?;
            assert!(multi_result[i] == after, "Multi select result does not match single select result");
        }
        Ok(())
    }

    async fn th_ensure_zero_id_merkle_zero_hashes_at_checkpoint_for_sub_tree_a(&self, table: &ZeroIdMerkleTableIdentifier, checkpoint_id: u64, tree_height: u8, root: SimpleMerkleNodeKey) -> anyhow::Result<()> {
        assert!(tree_height >= root.level, "Tree height must be greater than or equal to root level");
        let root_value = self.store.db_select_zero_id_merkle_node_max_checkpoint(table, checkpoint_id, &root).await?;
        assert!(root_value == Hasher::get_zero_hash((tree_height-root.level) as usize), "Root value must be zero hash at root level");
        if root.level == tree_height {
            return Ok(());
        }

        let child_keys = rand_children_to_height(&root, tree_height);
        let node_values = self.store.db_select_many_zero_id_merkle_nodes_max_checkpoint(table, checkpoint_id, &child_keys).await?;
        let expected_values = child_keys.iter().map(|key| Hasher::get_zero_hash((tree_height - key.level) as usize)).collect::<Vec<_>>();
        assert!(node_values.len() == expected_values.len(), "Node values and expected values lengths must match");
        for (i, value) in node_values.iter().enumerate() {
            assert!(value == &expected_values[i], "Node value must match expected zero hash");
        }

        Ok(())
    }

    pub async fn th_test_insert_zero_id_merkle_leaves_sub_tree_dmp(&self, table: &ZeroIdMerkleTableIdentifier, checkpoint_id: u64, tree_height: u8, sub_root_key: &SimpleMerkleNodeKey, leaves: &[SimpleMerkleNode<Hash>]) -> anyhow::Result<Vec<DeltaMerkleProofCore<Hash>>> {
        if leaves.is_empty() {
            return Ok(vec![]);
        }
        assert!(sub_root_key.level <= tree_height, "Sub root level must be at or below the tree height level");
        
        let first_leaf_level = leaves[0].key.level;
        assert!(first_leaf_level <= tree_height, "Leaf keys must be at or below the tree height level");
        assert!(first_leaf_level >= sub_root_key.level, "Leaf keys must be at or below the sub root level");

        for leaf in leaves.iter() {
            assert!(leaf.key.level == first_leaf_level, "All leaf keys must be at the same level");
        }
        let leaf_values = leaves.iter().map(|node| node.value).collect::<Vec<_>>();
        let leaf_keys = leaves.iter().map(|node| node.key.clone()).collect::<Vec<_>>();
        let dmps = db_helper_zero_id_merkle_node_simple_set_leaves_fast_serialize::<Hash, Hasher, ZeroIdMerkleTableIdentifier,_>(&self.store, table, checkpoint_id, 0, 9999, leaves).await?;
        assert!(dmps.len() == leaves.len(), "Number of DeltaMerkleProofs must match number of inserted leaves");
        let selected_leaf_values = self.store.db_select_many_zero_id_merkle_nodes_max_checkpoint(table, checkpoint_id, &leaf_keys).await?;
        assert!(selected_leaf_values.len() == leaf_values.len(), "Selected leaf values length must match inserted leaf values length");
        for (i, value) in selected_leaf_values.iter().enumerate() {
            assert!(value == &leaf_values[i], "Selected leaf value must match inserted leaf value");
        }
        for dmp in dmps.iter() {

            assert!(dmp.verify::<Hasher>(), "DeltaMerkleProof must verify correctly");
        }

        for i in 1..dmps.len() {
            assert!(dmps[i-1].new_root == dmps[i].old_root, "Consecutive DeltaMerkleProofs must be connected back to back, ie. new_root of previous must equal old_root of next"); 
        }
        

        Ok(dmps)

    }

    pub async fn th_test_zero_id_merkle_nodes_basic(&self, table: &ZeroIdMerkleTableIdentifier, tree_height: u8) -> anyhow::Result<()> {

        let first_checkpoint_id = 1u64;
        let second_checkpoint_id = 2u64;
        let third_checkpoint_id = 3u64;
        let fourth_checkpoint_id = 999u64;
        let last_checkpoint_id = 12874892u64;
        self.th_ensure_zero_id_merkle_zero_hashes_at_checkpoint_for_sub_tree_a(table, first_checkpoint_id, tree_height, SimpleMerkleNodeKey::new_root()).await?;
        self.th_ensure_zero_id_merkle_zero_hashes_at_checkpoint_for_sub_tree_a(table, second_checkpoint_id, tree_height, SimpleMerkleNodeKey::new_root()).await?;
        self.th_ensure_zero_id_merkle_zero_hashes_at_checkpoint_for_sub_tree_a(table, third_checkpoint_id, tree_height, SimpleMerkleNodeKey::new_root()).await?;
        self.th_ensure_zero_id_merkle_zero_hashes_at_checkpoint_for_sub_tree_a(table, fourth_checkpoint_id, tree_height, SimpleMerkleNodeKey::new_root()).await?;
        self.th_ensure_zero_id_merkle_zero_hashes_at_checkpoint_for_sub_tree_a(table, last_checkpoint_id, tree_height, SimpleMerkleNodeKey::new_root()).await?;

        let max_leaves_in_tree = 1u64 << tree_height;
        let num_leaves_to_insert = 16u64.min(max_leaves_in_tree);
        let num_leaves_to_insert_usize = num_leaves_to_insert as usize;
        let root_key = SimpleMerkleNodeKey::new_root();
        let first_batch = rand_leaves_for_subtree::<Hash>(&root_key, tree_height, num_leaves_to_insert_usize);

        let dmps_0 = self.th_test_insert_zero_id_merkle_leaves_sub_tree_dmp(table, first_checkpoint_id, tree_height, &SimpleMerkleNodeKey::new_root(), &first_batch).await?;
        assert!(dmps_0.len() == first_batch.len(), "Number of DeltaMerkleProofs must match number of inserted leaves at first checkpoint");

        self.th_ensure_zero_id_merkle_zero_hashes_at_checkpoint_for_sub_tree_a(table, 0, tree_height, SimpleMerkleNodeKey::new_root()).await?;
        let second_batch = rand_leaves_for_subtree::<Hash>(&root_key, tree_height, num_leaves_to_insert_usize);
        let dmps_1 = self.th_test_insert_zero_id_merkle_leaves_sub_tree_dmp(table, second_checkpoint_id, tree_height, &SimpleMerkleNodeKey::new_root(), &second_batch).await?;
        assert!(dmps_1.len() == second_batch.len(), "Number of DeltaMerkleProofs must match number of inserted leaves at second checkpoint");
        

        let first_second_batch_combined_halves = [
            first_batch[0..(num_leaves_to_insert_usize/2)].to_vec(),
            second_batch[(num_leaves_to_insert_usize/2)..num_leaves_to_insert_usize].to_vec()
        ].concat();
        let third_batch_unmodified = [
            first_batch[(num_leaves_to_insert_usize/2)..num_leaves_to_insert_usize].to_vec(),
            second_batch[0..(num_leaves_to_insert_usize/2)].to_vec()
        ].concat();
        let third_batch_new_leaves = rand_leaves_for_subtree::<Hash>(&root_key, tree_height, num_leaves_to_insert_usize);
        let first_second_batch_leaves_at_third_checkpoint = first_second_batch_combined_halves.iter().map(|x|{
            SimpleMerkleNode {
                key: x.key,
                value: Hash::qp_rand_gen(),
            }
        }).collect::<Vec<_>>();
        let third_batch = [first_second_batch_leaves_at_third_checkpoint, third_batch_new_leaves.clone()].concat();
        let dmps_2 = self.th_test_insert_zero_id_merkle_leaves_sub_tree_dmp(table, third_checkpoint_id, tree_height, &SimpleMerkleNodeKey::new_root(), &third_batch).await?;
        assert!(dmps_2.len() == third_batch.len(), "Number of DeltaMerkleProofs must match number of inserted leaves at third checkpoint");
        let b12_unmodified_keys = third_batch_unmodified.iter().map(|x| x.key.clone()).collect::<Vec<_>>();
        let b12_unmodified_values = third_batch_unmodified.iter().map(|x| x.value).collect::<Vec<_>>();
        let selected_unmodified_values = self.store.db_select_many_zero_id_merkle_nodes_max_checkpoint(table, third_checkpoint_id, &b12_unmodified_keys).await?;
        assert!(selected_unmodified_values.len() == b12_unmodified_values.len(), "Selected unmodified values length must match unmodified values length at third checkpoint");
        for (i, value) in selected_unmodified_values.iter().enumerate() {
            assert!(value == &b12_unmodified_values[i], "Selected unmodified value must match unmodified value at third checkpoint");
        }
        let b3_modified_keys = third_batch_new_leaves.iter().map(|x| x.key.clone()).collect::<Vec<_>>();
        let b3_modified_values = third_batch_new_leaves.iter().map(|x| x.value).collect::<Vec<_>>();
        let selected_modified_values = self.store.db_select_many_zero_id_merkle_nodes_max_checkpoint(table, third_checkpoint_id, &b3_modified_keys).await?;
        assert!(selected_modified_values.len() == b3_modified_values.len(), "Selected modified values length must match modified values length at third checkpoint");
        for (i, value) in selected_modified_values.iter().enumerate() {
            assert!(value == &b3_modified_values[i], "Selected modified value must match modified value at third checkpoint");
        }

        let fourth_batch = rand_leaves_for_subtree::<Hash>(&root_key, tree_height, num_leaves_to_insert_usize);
        let dmps_3 = self.th_test_insert_zero_id_merkle_leaves_sub_tree_dmp(table, fourth_checkpoint_id, tree_height, &SimpleMerkleNodeKey::new_root(), &fourth_batch).await?;
        assert!(dmps_3.len() == fourth_batch.len(), "Number of DeltaMerkleProofs must match number of inserted leaves at fourth checkpoint");

        let last_batch = rand_leaves_for_subtree::<Hash>(&root_key, tree_height, num_leaves_to_insert_usize);
        let dmps_4 = self.th_test_insert_zero_id_merkle_leaves_sub_tree_dmp(table, last_checkpoint_id, tree_height, &SimpleMerkleNodeKey::new_root(), &last_batch).await?;
        assert!(dmps_4.len() == last_batch.len(), "Number of DeltaMerkleProofs must match number of inserted leaves at last checkpoint");

        let keys_to_check: Vec<_> = first_batch.iter().chain(second_batch.iter()).chain(third_batch.iter()).chain(fourth_batch.iter()).chain(last_batch.iter()).map(|x| x.key.clone())
            .into_iter()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        for k in keys_to_check {
            let mp = db_helper_select_zero_id_merkle_proof_max_checkpoint::<Hash, Hasher, _, _>(&self.store, table, first_checkpoint_id+1, &k). await?;
            assert!(mp.verify::<Hasher>(), "MerkleProof must verify correctly for key {:?}", k);
            let mp = db_helper_select_zero_id_merkle_proof_max_checkpoint::<Hash, Hasher, _, _>(&self.store, table, second_checkpoint_id, &k). await?;
            assert!(mp.verify::<Hasher>(), "MerkleProof must verify correctly for key {:?}", k);
            let mp = db_helper_select_zero_id_merkle_proof_max_checkpoint::<Hash, Hasher, _, _>(&self.store, table, third_checkpoint_id, &k). await?;
            assert!(mp.verify::<Hasher>(), "MerkleProof must verify correctly for key {:?}", k);
            let mp = db_helper_select_zero_id_merkle_proof_max_checkpoint::<Hash, Hasher, _, _>(&self.store, table, fourth_checkpoint_id, &k). await?;
            assert!(mp.verify::<Hasher>(), "MerkleProof must verify correctly for key {:?}", k);
            let mp = db_helper_select_zero_id_merkle_proof_max_checkpoint::<Hash, Hasher, _, _>(&self.store, table, last_checkpoint_id, &k). await?;
            assert!(mp.verify::<Hasher>(), "MerkleProof must verify correctly for key {:?}", k);
            let mp = db_helper_select_zero_id_merkle_proof_max_checkpoint::<Hash, Hasher, _, _>(&self.store, table, last_checkpoint_id+100, &k). await?;
            assert!(mp.verify::<Hasher>(), "MerkleProof must verify correctly for key {:?}", k);
        }
        Ok(())
    }
}


impl<
        const ZERO_ID_TREE_A_HEIGHT: usize,
        const ZERO_ID_TREE_B_HEIGHT: usize,
        const SINGLE_ID_TREE_A_HEIGHT: usize,
        const SINGLE_ID_TREE_B_HEIGHT: usize,
        const DOUBLE_ID_TREE_A_HEIGHT: usize,
        const DOUBLE_ID_TREE_B_HEIGHT: usize,
        BidirectionalMappingTableAK1: QDatabasePrimitiveKey + QPGenRandom,
        BidirectionalMappingTableAK2: QDatabasePrimitiveKey + QPGenRandom,
        BidirectionalMappingTableBK1: QDatabasePrimitiveKey + QPGenRandom,
        BidirectionalMappingTableBK2: QDatabasePrimitiveKey + QPGenRandom,
        KivTableAValue: PsyDBSer + QPGenRandom,
        KivTableBValue: PsyDBSer + QPGenRandom,
        ObjSingleIdTableAValue: PsyDBSer + QPGenRandom,
        ObjDoubleIdTableBValue: PsyDBSer + QPGenRandom,
        Hash: QDBHashBase + QPGenRandom + Q256BitHash,
        Hasher: THHasher<Hash>,
        BiDirectionalMappingTableIdentifier: THStandardTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier: THStandardTableIdentifier,
        U64TableIdentifier: THStandardTableIdentifier,
        SingleIdTableIdentifier: THStandardTableIdentifier,
        DoubleIdTableIdentifier: THStandardTableIdentifier,
        KivTableIdentifier: THStandardTableIdentifier,
        SingleIdMerkleTableIdentifier: THStandardTableIdentifier,
        DoubleIdMerkleTableIdentifier: THStandardTableIdentifier,
        ZeroIdMerkleTableIdentifier: THStandardTableIdentifier,
        RewardTreeTableIdentifier: THStandardTableIdentifier,
        S: CoreDatabaseStore<
                Hash,
                Hasher,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
            > + CoreDatabaseTagTreeStore<Hash, Hasher, RewardTreeTableIdentifier>
            + Send
            + Sync,
    >
    QSimpleStore<
        ZERO_ID_TREE_A_HEIGHT,
        ZERO_ID_TREE_B_HEIGHT,
        SINGLE_ID_TREE_A_HEIGHT,
        SINGLE_ID_TREE_B_HEIGHT,
        DOUBLE_ID_TREE_A_HEIGHT,
        DOUBLE_ID_TREE_B_HEIGHT,
        BidirectionalMappingTableAK1,
        BidirectionalMappingTableAK2,
        BidirectionalMappingTableBK1,
        BidirectionalMappingTableBK2,
        KivTableAValue,
        KivTableBValue,
        ObjSingleIdTableAValue,
        ObjDoubleIdTableBValue,
        Hash,
        Hasher,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        RewardTreeTableIdentifier,
        S,
    >
{

    pub async fn th_util_insert_many_double_id_merkle_node_max_checkpoint_fast_serialized_single_tree(
        &self,
        table: &DoubleIdMerkleTableIdentifier,
        tree_height: u8,
        checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        nodes: &[SimpleMerkleNode<Hash>],
    ) -> anyhow::Result<()> {
        let keys = nodes.iter().map(|n| n.key).collect::<Vec<SimpleMerkleNodeKey>>();
        let mut prev_lowers = Vec::with_capacity(nodes.len());
        let mut highers = Vec::with_capacity(nodes.len());
        for key in keys.iter() {
            let prev_lower = if checkpoint_id > 0 {
                self.th_util_select_double_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id - 1, tree_id, tree_sub_id, *key)
                    .await?
            } else {
                Hasher::get_zero_hash((tree_height - key.level) as usize)
            };
            prev_lowers.push(prev_lower);
            let higher = self
                .th_util_select_double_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id + 1, tree_id, tree_sub_id, *key)
                .await?;
            highers.push(higher);
        }
        let context = QBlobWriterContextMetadataHeader::new_at_now(PSY_CHAIN_ID_LOCAL_DEVNET, 0,0,0, 1, checkpoint_id, tree_id);
        let double_nodes = QMerkleStoreDoubleIdNode::from_simple_merkle_nodes_for_tree_clone(tree_id, tree_sub_id, nodes);

         let fast_serialized_merkle_nodes = QBlobDoubleMerkleNodeBatchDataView::generate_double_merkle_node_batch_blob_data_from_ref(context, &double_nodes);

        self.store
            .db_set_double_id_merkle_nodes_from_fast_serialized(table, checkpoint_id, &fast_serialized_merkle_nodes[QBLOB_TREE_NODE_BATCH_HEADER_SIZE..])
            .await?;
        for (i, node) in nodes.iter().enumerate() {
            let after = self
                .th_util_select_double_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id, tree_id, tree_sub_id, node.key)
                .await?;
            assert!(after == node.value, "Inserted hash does not match retrieved hash after insert");

            if highers[i] == Hasher::get_zero_hash((tree_height - node.key.level) as usize) {
                let higher_new = self
                    .th_util_select_double_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id + 1, tree_id, tree_sub_id, node.key)
                    .await?;
                assert!(higher_new == after, "Higher hash should match inserted hash");
            }

            if prev_lowers[i] != Hasher::get_zero_hash((tree_height - node.key.level) as usize) {
                let prev_lower_again = self
                    .th_util_select_double_id_merkle_node_max_checkpoint(
                        table,
                        tree_height,
                        if checkpoint_id > 0 { checkpoint_id - 1 } else { 0 },
                        tree_id,
                        tree_sub_id,
                        node.key,
                    )
                    .await?;
                assert!(prev_lower_again == prev_lowers[i], "Previous lower hash should not change after insert");
            }
        }
        let multi_result = self
            .store
            .db_select_many_double_id_merkle_nodes_max_checkpoint(table, checkpoint_id, tree_id, tree_sub_id, tree_height, &keys)
            .await?;
        assert!(multi_result.len() == nodes.len(), "Multi select did not return correct number of results");
        for (i, node) in nodes.iter().enumerate() {
            let after = self
                .th_util_select_double_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id, tree_id, tree_sub_id, node.key)
                .await?;
            assert!(multi_result[i] == after, "Multi select result does not match single select result");
        }
        Ok(())
    }


}
/*
impl<
        const ZERO_ID_TREE_A_HEIGHT: usize,
        const ZERO_ID_TREE_B_HEIGHT: usize,
        const SINGLE_ID_TREE_A_HEIGHT: usize,
        const SINGLE_ID_TREE_B_HEIGHT: usize,
        const DOUBLE_ID_TREE_A_HEIGHT: usize,
        const DOUBLE_ID_TREE_B_HEIGHT: usize,
        BidirectionalMappingTableAK1: QDatabasePrimitiveKey,
        BidirectionalMappingTableAK2: QDatabasePrimitiveKey,
        BidirectionalMappingTableBK1: QDatabasePrimitiveKey,
        BidirectionalMappingTableBK2: QDatabasePrimitiveKey,
        KivTableAValue: PsyDBSer,
        KivTableBValue: PsyDBSer,
        ObjSingleIdTableAValue: PsyDBSer,
        ObjDoubleIdTableBValue: PsyDBSer,
        Hash: QDBHashBase + QPGenRandom + std::fmt::Debug + Default + Clone + Send + Sync,
        Hasher: THHasher<Hash>,
        BiDirectionalMappingTableIdentifier: THStandardTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier: THStandardTableIdentifier,
        U64TableIdentifier: THStandardTableIdentifier,
        SingleIdTableIdentifier: THStandardTableIdentifier,
        DoubleIdTableIdentifier: THStandardTableIdentifier,
        KivTableIdentifier: THStandardTableIdentifier,
        SingleIdMerkleTableIdentifier: THStandardTableIdentifier,
        DoubleIdMerkleTableIdentifier: THStandardTableIdentifier,
        ZeroIdMerkleTableIdentifier: THStandardTableIdentifier,
        RewardTreeTableIdentifier: THStandardTableIdentifier,
        S: CoreDatabaseStore<
                Hash,
                Hasher,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
            > + CoreDatabaseTagTreeStore<Hash, Hasher, RewardTreeTableIdentifier>
            + Send
            + Sync,
    >
    QSimpleStore<
        ZERO_ID_TREE_A_HEIGHT,
        ZERO_ID_TREE_B_HEIGHT,
        SINGLE_ID_TREE_A_HEIGHT,
        SINGLE_ID_TREE_B_HEIGHT,
        DOUBLE_ID_TREE_A_HEIGHT,
        DOUBLE_ID_TREE_B_HEIGHT,
        BidirectionalMappingTableAK1,
        BidirectionalMappingTableAK2,
        BidirectionalMappingTableBK1,
        BidirectionalMappingTableBK2,
        KivTableAValue,
        KivTableBValue,
        ObjSingleIdTableAValue,
        ObjDoubleIdTableBValue,
        Hash,
        Hasher,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        RewardTreeTableIdentifier,
        S,
    >
{
    pub async fn th_util_get_tag_tree_node_value(
        &self,
        table: &RewardTreeTableIdentifier,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<Option<Hash>> {
        let result = self.store.db_get_tag_tree_node_value(table, unique_pending_id, key).await?;
        let multi_result = self.store.db_get_tag_tree_node_values(table, unique_pending_id, &[key.clone(), key.clone()]).await?;
        assert!(multi_result.len() == 2, "Multi get did not return correct number of results");
        assert!(multi_result[0] == result, "Multi get first result does not match single get result");
        assert!(multi_result[1] == result, "Multi get second result does not match single get result");
        Ok(result)
    }

    pub async fn th_util_get_many_tag_tree_node_values(
        &self,
        table: &RewardTreeTableIdentifier,
        unique_pending_id: u64,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Option<Hash>>> {
        let result = self.store.db_get_tag_tree_node_values(table, unique_pending_id, keys).await?;
        assert!(
            result.len() == keys.len(),
            "Number of retrieved values does not match number of requested keys"
        );
        for (i, key) in keys.iter().enumerate() {
            let single_result = self.th_util_get_tag_tree_node_value(table, unique_pending_id, key).await?;
            assert!(result[i] == single_result, "Multi get result does not match single get result");
        }
        Ok(result)
    }
pub async fn th_util_get_tag_tree_node_tag(
        &self,
        table: &RewardTreeTableIdentifier,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<Option<Hash>> {
        let result = self.store.db_get_tag_tree_node_tag(table, unique_pending_id, key).await?;
        let value = self.th_util_get_tag_tree_node_value(table, unique_pending_id, key).await?;
        if let Some(v) = value {
            let storage = TagTreeStorageNode { value: v, tag: result.unwrap_or_default() };
            let left = self.th_util_get_tag_tree_node_value(table, unique_pending_id, &key.left_child()).await?.unwrap_or_default();
            let right = self.th_util_get_tag_tree_node_value(table, unique_pending_id, &key.right_child()).await?.unwrap_or_default();
            let preimage = TagTreeNodePreimage { left, right, tag: storage.tag };
            assert_eq!(preimage.get_node_hash::<Hasher>(), storage.value, "Computed node value from preimage does not match stored value");
        }
        Ok(result)
    }

    pub async fn th_util_get_tag_tree_root(&self, table: &RewardTreeTableIdentifier, unique_pending_id: u64) -> anyhow::Result<Option<Hash>> {
        let result = self.store.db_get_tag_tree_root(table, unique_pending_id).await?;
        let root_key = SimpleMerkleNodeKey::new_root();
        let value_from_node = self.th_util_get_tag_tree_node_value(table, unique_pending_id, &root_key).await?;
        assert!(result == value_from_node, "Root from get_root does not match get_node_value for root key");
        Ok(result)
    }

    pub async fn th_util_get_tag_tree_merkle_proof(
        &self,
        table: &RewardTreeTableIdentifier,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<TagTreeMerkleProof<Hash>> {
        let result = self.store.db_get_tag_tree_merkle_proof(table, unique_pending_id, key).await?;
        assert!(result.verify::<Hasher>(), "Retrieved proof does not verify");
        let computed_root = compute_tag_tree_root_for_proof::<Hash, Hasher>(result.index, &result.leaf, &result.siblings);
        assert_eq!(computed_root, result.root, "Computed root does not match proof root");
        let stored_root = self.th_util_get_tag_tree_root(table, unique_pending_id).await?.unwrap_or_default();
        assert_eq!(result.root, stored_root, "Proof root does not match stored root");
        Ok(result)
    }

    pub async fn th_util_set_tag_tree_tag_value(
        &self,
        table: &RewardTreeTableIdentifier,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
        tag: &Hash,
        value: &Hash,
    ) -> anyhow::Result<()> {
        self.store.set_tag_tree_tag_value(table, unique_pending_id, key, tag, value).await?;
        let retrieved_value = self.th_util_get_tag_tree_node_value(table, unique_pending_id, key).await?;
        assert_eq!(retrieved_value, Some(*value), "Retrieved value does not match set value");
        let retrieved_tag = self.th_util_get_tag_tree_node_tag(table, unique_pending_id, key).await?;
        assert_eq!(retrieved_tag, Some(*tag), "Retrieved tag does not match set tag");
        Ok(())
    }

    pub async fn th_util_set_tag_tree_tag(
        &self,
        table: &RewardTreeTableIdentifier,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
        tag: &Hash,
    ) -> anyhow::Result<()> {
        let left = self.th_util_get_tag_tree_node_value(table, unique_pending_id, &key.left_child()).await?.unwrap_or_default();
        let right = self.th_util_get_tag_tree_node_value(table, unique_pending_id, &key.right_child()).await?.unwrap_or_default();
        let expected_value = hash_tag_tree_node::<Hash, Hasher>(&left, &right, tag);
        self.store.set_tag_tree_tag(table, unique_pending_id, key, tag).await?;
        let retrieved_value = self.th_util_get_tag_tree_node_value(table, unique_pending_id, key).await?;
        assert_eq!(retrieved_value, Some(expected_value), "Retrieved value does not match computed value");
        let retrieved_tag = self.th_util_get_tag_tree_node_tag(table, unique_pending_id, key).await?;
        assert_eq!(retrieved_tag, Some(*tag), "Retrieved tag does not match set tag");
        Ok(())
    }
pub async fn th_test_tag_tree_basic(&self, table: &RewardTreeTableIdentifier, unique_pending_id: u64) -> anyhow::Result<()> {
        let height = 32u8;
        let leaves = random_nodes_in_tree(height, 1337);
        let group_levels = generate_nca_tree_groups_efficient(&leaves, height);

        let tree_height = (group_levels.len() - 1) as u8;

        let mut hash_map_dat = HashMap::<SimpleMerkleNodeKey, (Hash, Hash)>::new();

        for (level, gl) in group_levels.iter().enumerate() {
            for (index, g) in gl.iter().enumerate() {
                let tag = Hash::qp_rand_gen();
                let key = SimpleMerkleNodeKey::new(tree_height - level as u8, index as u64);
                let left_key = key.left_child();
                let right_key = key.right_child();
                let left_value = hash_map_dat.get(&left_key).map(|&(_, v)| v).unwrap_or_default();
                let right_value = hash_map_dat.get(&right_key).map(|&(_, v)| v).unwrap_or_default();
                let value = hash_tag_tree_node::<Hash, Hasher>(&left_value, &right_value, &tag);
                hash_map_dat.insert(key, (tag, value));
                self.th_util_set_tag_tree_tag_value(table, unique_pending_id, &key, &tag, &value).await?;
            }
        }

        for (key, &(tag, value)) in hash_map_dat.iter() {
            let retrieved_tag = self.th_util_get_tag_tree_node_tag(table, unique_pending_id, key).await?;
            assert_eq!(retrieved_tag, Some(tag), "Retrieved tag does not match");
            let retrieved_value = self.th_util_get_tag_tree_node_value(table, unique_pending_id, key).await?;
            assert_eq!(retrieved_value, Some(value), "Retrieved value does not match");
        }

        let all_keys = hash_map_dat.keys().cloned().collect::<Vec<_>>();
        let multi_values = self.th_util_get_many_tag_tree_node_values(table, unique_pending_id, &all_keys).await?;
        for (i, key) in all_keys.iter().enumerate() {
            assert_eq!(multi_values[i], Some(hash_map_dat[key].1), "Multi retrieved value does not match");
        }

        let root_key = SimpleMerkleNodeKey::new_root();
        let root = self.th_util_get_tag_tree_root(table, unique_pending_id).await?;
        assert_eq!(root, Some(hash_map_dat[&root_key].1), "Retrieved root does not match");

        for g in group_levels.iter().flatten() {
            let key = g.nca.clone();
            let proof = self.th_util_get_tag_tree_merkle_proof(table, unique_pending_id, &key).await?;
            assert_eq!(proof.root, root.unwrap(), "Proof root does not match tree root");
        }

        let missing_key = SimpleMerkleNodeKey::random_simple_merkle_node_in_tree(tree_height);
        if !hash_map_dat.contains_key(&missing_key) {
            let missing_value = self.th_util_get_tag_tree_node_value(table, unique_pending_id, &missing_key).await?;
            assert!(missing_value.is_none(), "Missing value should be None");
            let missing_tag = self.th_util_get_tag_tree_node_tag(table, unique_pending_id, &missing_key).await?;
            assert!(missing_tag.is_none(), "Missing tag should be None");
            let proof_missing = self.th_util_get_tag_tree_merkle_proof(table, unique_pending_id, &missing_key).await?;
            assert_eq!(proof_missing.leaf.left, Hash::default());
            assert_eq!(proof_missing.leaf.right, Hash::default());
            assert_eq!(proof_missing.leaf.tag, Hash::default());
            assert_eq!(proof_missing.root, root.unwrap_or_default());
        }

        let different_pending_id = unique_pending_id + 1;
        let root_diff = self.th_util_get_tag_tree_root(table, different_pending_id).await?;
        assert!(root_diff.is_none(), "Different pending id root should be None");
        let value_diff = self.th_util_get_tag_tree_node_value(table, different_pending_id, &root_key).await?;
        assert!(value_diff.is_none(), "Different pending id value should be None");

        let override_key = SimpleMerkleNodeKey::random_simple_merkle_node_in_tree(tree_height);
        if hash_map_dat.contains_key(&override_key) {
            let old_tag = hash_map_dat[&override_key].0;
            let new_tag = Hash::qp_rand_gen();
            self.th_util_set_tag_tree_tag(table, unique_pending_id, &override_key, &new_tag).await?;
            let retrieved_new_tag = self.th_util_get_tag_tree_node_tag(table, unique_pending_id, &override_key).await?;
            assert_eq!(retrieved_new_tag, Some(new_tag), "Overridden tag does not match");
            let left = self.th_util_get_tag_tree_node_value(table, unique_pending_id, &override_key.left_child()).await?.unwrap_or_default();
            let right = self.th_util_get_tag_tree_node_value(table, unique_pending_id, &override_key.right_child()).await?.unwrap_or_default();
            let new_value = hash_tag_tree_node::<Hash, Hasher>(&left, &right, &new_tag);
            let retrieved_new_value = self.th_util_get_tag_tree_node_value(table, unique_pending_id, &override_key).await?;
            assert_eq!(retrieved_new_value, Some(new_value), "Overridden value does not match computed value");
            let proof_after_override = self.th_util_get_tag_tree_merkle_proof(table, unique_pending_id, &override_key).await?;
            assert!(proof_after_override.verify::<Hasher>(), "Proof after override does not verify");
        }

        Ok(())
    }
}

*/

impl<
        const ZERO_ID_TREE_A_HEIGHT: usize,
        const ZERO_ID_TREE_B_HEIGHT: usize,
        const SINGLE_ID_TREE_A_HEIGHT: usize,
        const SINGLE_ID_TREE_B_HEIGHT: usize,
        const DOUBLE_ID_TREE_A_HEIGHT: usize,
        const DOUBLE_ID_TREE_B_HEIGHT: usize,
        BidirectionalMappingTableAK1: QDatabasePrimitiveKey,
        BidirectionalMappingTableAK2: QDatabasePrimitiveKey,
        BidirectionalMappingTableBK1: QDatabasePrimitiveKey,
        BidirectionalMappingTableBK2: QDatabasePrimitiveKey,
        KivTableAValue: PsyDBSer,
        KivTableBValue: PsyDBSer,
        ObjSingleIdTableAValue: PsyDBSer,
        ObjDoubleIdTableBValue: PsyDBSer,
        Hash: QDBHashBase + QPGenRandom + std::fmt::Debug + Default + Clone + Send + Sync,
        Hasher: THHasher<Hash>,
        BiDirectionalMappingTableIdentifier: THStandardTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier: THStandardTableIdentifier,
        U64TableIdentifier: THStandardTableIdentifier,
        SingleIdTableIdentifier: THStandardTableIdentifier,
        DoubleIdTableIdentifier: THStandardTableIdentifier,
        KivTableIdentifier: THStandardTableIdentifier,
        SingleIdMerkleTableIdentifier: THStandardTableIdentifier,
        DoubleIdMerkleTableIdentifier: THStandardTableIdentifier,
        ZeroIdMerkleTableIdentifier: THStandardTableIdentifier,
        RewardTreeTableIdentifier: THStandardTableIdentifier,
        S: CoreDatabaseStore<
                Hash,
                Hasher,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
            > + CoreDatabaseTagTreeStore<Hash, Hasher, RewardTreeTableIdentifier>
            + Send
            + Sync,
    >
    QSimpleStore<
        ZERO_ID_TREE_A_HEIGHT,
        ZERO_ID_TREE_B_HEIGHT,
        SINGLE_ID_TREE_A_HEIGHT,
        SINGLE_ID_TREE_B_HEIGHT,
        DOUBLE_ID_TREE_A_HEIGHT,
        DOUBLE_ID_TREE_B_HEIGHT,
        BidirectionalMappingTableAK1,
        BidirectionalMappingTableAK2,
        BidirectionalMappingTableBK1,
        BidirectionalMappingTableBK2,
        KivTableAValue,
        KivTableBValue,
        ObjSingleIdTableAValue,
        ObjDoubleIdTableBValue,
        Hash,
        Hasher,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        RewardTreeTableIdentifier,
        S,
    >
{
    pub async fn th_util_get_tag_tree_merkle_proof(
        &self,
        table: &RewardTreeTableIdentifier,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<TagTreeMerkleProof<Hash>> {
        let result = self.store.db_get_tag_tree_merkle_proof(table, unique_pending_id, key).await?;
        assert!(result.verify::<Hasher>(), "Retrieved proof does not verify");
        let computed_root = compute_tag_tree_root_for_proof::<Hash, Hasher>(result.index, &result.leaf, &result.siblings);
        assert_eq!(computed_root, result.root, "Computed root does not match proof root");
        let stored_root = self.th_util_get_tag_tree_root(table, unique_pending_id).await?.unwrap_or_default();
        assert_eq!(result.root, stored_root, "Proof root does not match stored root");
        Ok(result)
    }
    
    pub async fn th_util_get_tag_tree_node_value(
        &self,
        table: &RewardTreeTableIdentifier,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<Option<Hash>> {
        let result = self.store.db_get_tag_tree_node_value(table, unique_pending_id, key).await?;
        let multi_result = self.store.db_get_tag_tree_node_values(table, unique_pending_id, &[key.clone(), key.clone()]).await?;
        assert!(multi_result.len() == 2, "Multi get did not return correct number of results");
        assert!(multi_result[0] == result, "Multi get first result does not match single get result");
        assert!(multi_result[1] == result, "Multi get second result does not match single get result");
        Ok(result)
    }

    pub async fn th_util_get_many_tag_tree_node_values(
        &self,
        table: &RewardTreeTableIdentifier,
        unique_pending_id: u64,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Option<Hash>>> {
        let result = self.store.db_get_tag_tree_node_values(table, unique_pending_id, keys).await?;
        assert!(
            result.len() == keys.len(),
            "Number of retrieved values does not match number of requested keys"
        );
        for (i, key) in keys.iter().enumerate() {
            let single_result = self.th_util_get_tag_tree_node_value(table, unique_pending_id, key).await?;
            assert!(result[i] == single_result, "Multi get result does not match single get result");
        }
        Ok(result)
    }

    pub async fn th_util_get_tag_tree_node_tag(
        &self,
        table: &RewardTreeTableIdentifier,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<Option<Hash>> {
        let result = self.store.db_get_tag_tree_node_tag(table, unique_pending_id, key).await?;
        Ok(result)
    }

    pub async fn th_util_get_tag_tree_root(&self, table: &RewardTreeTableIdentifier, unique_pending_id: u64) -> anyhow::Result<Option<Hash>> {
        let result = self.store.db_get_tag_tree_root(table, unique_pending_id).await?;
        let root_key = SimpleMerkleNodeKey::new_root();
        let value_from_node = self.th_util_get_tag_tree_node_value(table, unique_pending_id, &root_key).await?;
        assert_eq!(result, value_from_node, "Root from get_root does not match get_node_value for root key");
        Ok(result)
    }


    pub async fn th_util_set_tag_tree_tag_value(
        &self,
        table: &RewardTreeTableIdentifier,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
        tag: &Hash,
        value: &Hash,
    ) -> anyhow::Result<()> {
        self.store.set_tag_tree_tag_value(table, unique_pending_id, key, tag, value).await?;
        let retrieved_value = self.th_util_get_tag_tree_node_value(table, unique_pending_id, key).await?;
        assert_eq!(retrieved_value, Some(*value), "Retrieved value does not match set value");
        let retrieved_tag = self.th_util_get_tag_tree_node_tag(table, unique_pending_id, key).await?;
        assert_eq!(retrieved_tag, Some(*tag), "Retrieved tag does not match set tag");
        Ok(())
    }

    pub async fn th_util_set_tag_tree_tag(
        &self,
        table: &RewardTreeTableIdentifier,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
        tag: &Hash,
    ) -> anyhow::Result<()> {
        self.store.set_tag_tree_tag(table, unique_pending_id, key, tag).await?;
        let retrieved_tag = self.th_util_get_tag_tree_node_tag(table, unique_pending_id, key).await?;
        assert_eq!(retrieved_tag, Some(*tag), "Retrieved tag does not match set tag");
        Ok(())
    }
    pub async fn th_test_tag_tree_v2(&self, table: &RewardTreeTableIdentifier, unique_pending_id: u64) -> anyhow::Result<()> {

        let guta_height = 3u8;
        let leaf_1 = SimpleMerkleNodeKey::new(guta_height, 0);
        let leaf_2 = SimpleMerkleNodeKey::new(guta_height, 1);
        let leaf_3 = SimpleMerkleNodeKey::new(guta_height, 2);
        let leaf_5 = SimpleMerkleNodeKey::new(guta_height, 5);
        let leaf_6 = SimpleMerkleNodeKey::new(guta_height, 6);
        let leaves = vec![leaf_1, leaf_2, leaf_3, leaf_5, leaf_6];
        let group_levels = generate_nca_tree_groups_efficient(&leaves, guta_height);
        let tree_height = group_levels.len()-1;
        assert_eq!(group_levels.len(), 3);
        let mut simple_tree = SimpleMemoryTagTreeStore::<Hasher, Hash>::new(tree_height as u8);
        let mut hash_map_dat = HashMap::<SimpleMerkleNodeKey, SimpleMerkleNodeKey>::new();
        for (level, gl) in group_levels.iter().enumerate() {    
            for (index, g) in gl.iter().enumerate() {
                let hash = Hash::qp_rand_gen();
                let key = SimpleMerkleNodeKey::new((tree_height-level) as u8, index as u64);
                hash_map_dat.insert(g.nca, key);
                self.store.set_tag_tree_tag_known_height(table, unique_pending_id, tree_height as u8, &key, &hash).await?;
                simple_tree.set_tag(key, hash);
                let retrieved_tag = self.store.db_get_tag_tree_node_tag(table, unique_pending_id, &key).await?;
                assert_eq!(retrieved_tag, Some(hash), "Retrieved tag does not match");
                let ret_combo = self.store.db_get_tag_tree_node_value(table, unique_pending_id, &key).await?;
                assert!(ret_combo.is_some(), "Retrieved value should be Some");
                let left = self.store.db_get_tag_tree_node_value(table, unique_pending_id, &key.left_child()).await?.unwrap_or_default();
                let right = self.store.db_get_tag_tree_node_value(table, unique_pending_id, &key.right_child()).await?.unwrap_or_default();
                let expected_value = hash_tag_tree_node::<Hash, Hasher>(&left, &right, &hash);
                assert_eq!(ret_combo.unwrap(), expected_value, "Retrieved value does not match expected value");
            }
        }
        for g in group_levels.iter().flatten() {
            let key = hash_map_dat[&g.nca];
            let proof = simple_tree.get_proof_full(key);
            let proof_2 = self.store.db_get_tag_tree_merkle_proof(table, unique_pending_id, &key).await?;
            assert_eq!(proof, proof_2, "Proofs do not match");
            assert!(proof.verify::<Hasher>(), "proof verification failed"); 
        }
        Ok(())
    }
    pub async fn th_test_tag_tree_small(&self, table: &RewardTreeTableIdentifier, unique_pending_id: u64) -> anyhow::Result<()> {
        let guta_height = 3u8;
        let leaf_1 = SimpleMerkleNodeKey::new(guta_height, 0);
        let leaf_2 = SimpleMerkleNodeKey::new(guta_height, 1);
        let leaf_3 = SimpleMerkleNodeKey::new(guta_height, 2);
        let leaf_5 = SimpleMerkleNodeKey::new(guta_height, 5);
        let leaf_6 = SimpleMerkleNodeKey::new(guta_height, 6);
        let leaves = vec![leaf_1, leaf_2, leaf_3, leaf_5, leaf_6];
        let group_levels = generate_nca_tree_groups_efficient(&leaves, guta_height);

        let tree_height = (group_levels.len() - 1) as u8;

        let mut tags = HashMap::new();

        for (level, gl) in group_levels.iter().enumerate() {
            for (index, g) in gl.iter().enumerate() {
                let tag = Hash::qp_rand_gen();
                let key = SimpleMerkleNodeKey::new(tree_height - level as u8, index as u64);
                tags.insert(key, tag);
                self.th_util_set_tag_tree_tag(table, unique_pending_id, &key, &tag).await?;
            }
        }

        for (key, tag) in tags.iter() {
            let retrieved_tag = self.th_util_get_tag_tree_node_tag(table, unique_pending_id, key).await?;
            assert_eq!(retrieved_tag, Some(*tag), "Retrieved tag does not match");
        }

        for g in group_levels.iter().flatten() {
            let key = g.nca.clone();
            let proof = self.th_util_get_tag_tree_merkle_proof(table, unique_pending_id, &key).await?;
            assert!(proof.verify::<Hasher>(), "Proof verification failed");
        }

        Ok(())
    }

    pub async fn th_test_tag_tree_medium(&self, table: &RewardTreeTableIdentifier, unique_pending_id: u64) -> anyhow::Result<()> {

        let guta_height: u8 = 32;
        let leaves = random_nodes_in_tree(guta_height, 1337);
        let group_levels = generate_nca_tree_groups_efficient(&leaves, guta_height);

        let tree_height = group_levels.len() - 1;
        let mut simple_tree = SimpleMemoryTagTreeStore::<Hasher, Hash>::new(tree_height as u8);

        let mut hash_map_dat = HashMap::<SimpleMerkleNodeKey, SimpleMerkleNodeKey>::new();

        for (level, gl) in group_levels.iter().enumerate() {

            for (index, g) in gl.iter().enumerate() {
                let hash = Hash::qp_rand_gen();
                let tag_tree_key = SimpleMerkleNodeKey::new((tree_height-level) as u8, index as u64);
                hash_map_dat.insert(g.nca, tag_tree_key);
                simple_tree.set_tag(tag_tree_key, hash);
                self.store.set_tag_tree_tag_known_height(table, unique_pending_id, tree_height as u8, &tag_tree_key, &hash).await?;
                let retrieved_tag = self.store.db_get_tag_tree_node_tag(table, unique_pending_id, &tag_tree_key).await?;
                assert_eq!(retrieved_tag, Some(hash), "Retrieved tag does not match");
                let ret_combo = self.store.db_get_tag_tree_node_value(table, unique_pending_id, &tag_tree_key).await?;
                assert!(ret_combo.is_some(), "Retrieved value should be Some");
                let left = self.store.db_get_tag_tree_node_value(table, unique_pending_id, &tag_tree_key.left_child()).await?.unwrap_or_default();
                let right = self.store.db_get_tag_tree_node_value(table, unique_pending_id, &tag_tree_key.right_child()).await?.unwrap_or_default();
                let expected_value = hash_tag_tree_node::<Hash, Hasher>(&left, &right, &hash);
                assert_eq!(ret_combo.unwrap(), expected_value, "Retrieved value does not match expected value");
                assert_eq!(simple_tree.get_node_value(&tag_tree_key), expected_value, "In-memory tree value does not match expected value");
            }
        }
        for g in group_levels.iter().flatten() {
            let key = hash_map_dat[&g.nca];
            let proof = simple_tree.get_proof_full(key);
            assert!(proof.verify::<Hasher>(), "proof verification failed for in-memory tree");
            let proof_2 = self.store.db_get_tag_tree_merkle_proof(table, unique_pending_id, &key).await?;
            assert_eq!(proof, proof_2, "proof from store does not match in-memory proof");
            assert!(proof_2.verify::<Hasher>(), "store proof verification failed");
            let th_proof = self.th_util_get_tag_tree_merkle_proof(table, unique_pending_id, &key).await?;
            assert!(th_proof.verify::<Hasher>(), "th_util proof verification failed");
        }
        Ok(())
    }

    pub async fn th_test_tag_tree_tiny(&self, table: &RewardTreeTableIdentifier, unique_pending_id: u64) -> anyhow::Result<()> {
        let guta_height = 1u8;
        let leaf_1 = SimpleMerkleNodeKey::new(guta_height, 0);
        let leaf_2 = SimpleMerkleNodeKey::new(guta_height, 1);
        let tag_1 = Hash::qp_rand_gen();
        let tag_2 = Hash::qp_rand_gen();
        let tag_root = Hash::qp_rand_gen();
        self.th_util_set_tag_tree_tag(table, unique_pending_id, &leaf_1, &tag_1).await?;
        self.th_util_set_tag_tree_tag(table, unique_pending_id, &leaf_2, &tag_2).await?;
        self.th_util_set_tag_tree_tag(table, unique_pending_id, &SimpleMerkleNodeKey::new_root(), &tag_root).await?;

        let expected_left_value = hash_tag_tree_node::<Hash, Hasher>(&Hash::default(), &Hash::default(), &tag_1);
        let expected_right_value = hash_tag_tree_node::<Hash, Hasher>(&Hash::default(), &Hash::default(), &tag_2);
        assert_eq!(self.th_util_get_tag_tree_node_tag(table, unique_pending_id, &leaf_1).await?, Some(tag_1));
        assert_eq!(self.th_util_get_tag_tree_node_tag(table, unique_pending_id, &leaf_2).await?, Some(tag_2));
        assert_eq!(self.th_util_get_tag_tree_node_tag(table, unique_pending_id, &SimpleMerkleNodeKey::new_root()).await?, Some(tag_root));

        assert_eq!(self.th_util_get_tag_tree_node_value(table, unique_pending_id, &leaf_1).await?, Some(expected_left_value));
        assert_eq!(self.th_util_get_tag_tree_node_value(table, unique_pending_id, &leaf_2).await?, Some(expected_right_value));

        let expected_root_value = hash_tag_tree_node::<Hash, Hasher>(&expected_left_value, &expected_right_value, &tag_root);

        let root = self.th_util_get_tag_tree_root(table, unique_pending_id).await?;
        assert_eq!(root, Some(expected_root_value));
        let proof_1 = self.th_util_get_tag_tree_merkle_proof(table, unique_pending_id, &leaf_1).await?;
        let proof_2 = self.th_util_get_tag_tree_merkle_proof(table, unique_pending_id, &leaf_2).await?;
        assert!(proof_1.verify::<Hasher>(), "proof 1 verification failed");
        assert!(proof_2.verify::<Hasher>(), "proof 2 verification failed");

        Ok(())
    }
}


/*pub struct SimpleStoreEx {
    pub store: QSimpleStore<
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

        //QSimpleStore::new(store, kiv_table_a, kiv_table_b,
        // bidirectional_mapping_table_a, bidirectional_mapping_table_b,
        // obj_single_id_table_a, obj_single_id_table_b, obj_double_id_table_a,
        // obj_double_id_table_b, u64_table_a, u64_table_b,
        // u64_u128_bi_directional_mapping_table_a,
        // u64_u128_bi_directional_mapping_table_b, merkle_node_zero_id_table_a,
        // merkle_node_zero_id_table_b, merkle_node_single_id_table_a,
        // merkle_node_single_id_table_b, merkle_node_double_id_table_a,
        // merkle_node_double_id_table_b, tag_tree_table_a, tag_tree_table_b)

        let simple_store = QSimpleStore::new(
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
        

        Ok(())
    }
}


#[tokio::test]
#[ignore = "database slow"]
async fn simple_store_basic_test_1() -> anyhow::Result<()> {
    let key_space = format!("psy_node_scylla_test_ex1_{}", rand::random::<u64>());
    let scylla_db = ScyllaCoreStore::<ExHash, ExHasher>::new(0, 0, key_space, &[
        "127.0.0.1:9042".to_string()
    ]).await?;
    let simple_store = SimpleStoreEx::setup(Arc::new(scylla_db)).await?;
    println!("setup simple store");
    simple_store.basic_test_1().await?;
    Ok(())
}
*/

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
    pub store: QSimpleStore<
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
        InMemoryTestStore,
    >,
}

impl SimpleStoreEx {
    pub async fn setup(store: Arc<InMemoryTestStore>) -> anyhow::Result<Self> {
        let keyspace = format!("in_memory_test_ex1_{}", rand::random::<u64>());
        let simple_store = QSimpleStore::new(
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
            Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "MerkleNodeZeroIdTableA")),
            Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "MerkleNodeZeroIdTableB")),
            Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "MerkleNodeSingleIdTableA")),
            Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "MerkleNodeSingleIdTableB")),
            Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "MerkleNodeDoubleIdTableA")),
            Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "MerkleNodeDoubleIdTableB")),
            Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "TagTreeTableA")),
            Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "TagTreeTableB")),
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