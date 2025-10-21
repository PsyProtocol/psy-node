use std::sync::Arc;

use parth_core::{
    data::
        db::
            data_types::QDatabasePrimitiveKey
        
    , protocol::core_types::QDBHashBase
};

use crate::store::traits::core_db::CoreDatabaseStore;
use super::utils::{PsyDBSer, THStandardTableIdentifier, THHasher};
#[derive(Clone)]
pub struct QJumboStore<
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
    HashToManyIdsTableIdentifier: THStandardTableIdentifier,
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
            RewardTreeTableIdentifier,
            HashToManyIdsTableIdentifier,
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

    pub hash_id_to_u64s_table_a: Arc<HashToManyIdsTableIdentifier>,

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
        HashToManyIdsTableIdentifier: THStandardTableIdentifier,
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
                RewardTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
            >
            + Send
            + Sync,
    >
    QJumboStore<
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
        HashToManyIdsTableIdentifier,
        
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
        hash_id_to_u64s_table_a: Arc<HashToManyIdsTableIdentifier>,
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
            hash_id_to_u64s_table_a,

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