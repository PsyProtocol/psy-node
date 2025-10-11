use std::sync::Arc;

use parth_core::{
    crypto::hash::{
        merkle_proof::MerkleProofCore,
        traits::{MerkleZeroHasher, QHasher},
    },
    data::{
        db::{
            data_types::{BiDirectionalMappingRow, CoreDatabaseValueDeserialize, QDatabasePrimitiveKey},
            row::{QDatabaseKeyIdValueTableRowLike, QDatabaseSingleIdTableRowNoCheckpointIdLike},
            table::QDatabaseTableRoutingKey,
        },
        hash::{
            hash256::Hash256,
            merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey},
        },
        serializable::{QPDPair, QPDSerializable},
    },
    felt::QFelt,
    impl_qpd_serialize_params,
    protocol::core_types::{QHashBase, QHasherBase},
    utils::QPGenRandom,
};
use parth_crypto::hash::sha256::CoreSha256Hasher;
use parth_node_scylla::{
    core::ScyllaCoreStore,
    tables::{
        blob::ScyllaBiDirectionalBlobToBlobTablePreparedStatements,
        merkle::{ScyllaDoubleMerkleNodesPreparedStatements, ScyllaMerkleNodesPreparedStatements, ScyllaMerkleNodesZeroPreparedStatements},
        object::{
            ScyllaGenericKeyIdValueTablePreparedStatements, ScyllaGenericObjectDoubleIdTablePreparedStatements,
            ScyllaGenericObjectSingleIdTablePreparedStatements,
        },
        tag_tree::ScyllaTagTreeNodesPreparedStatements,
        traits::ScyllaStandardPreparedTableStatements,
        u64_tbl::{ScyllaBidirectionalU64U128MappingPreparedStatements, ScyllaU64ToU64TablePreparedStatements},
    },
};
use pser::{QBytesDeserialize, QBytesSerialize};
use psy_node_core::store::traits::core_db::{CoreDatabaseStore, CoreDatabaseTagTreeStore};
use scylla::client::session::Session;

pub trait CreateRandomTestDataItem: Sized {
    fn create_random_test_data_item() -> Self;
}
const MAX_REAL_U64_ID_VALUE: u64 = 0x0000_FFFF_FFFF_FFFF;
const DEFINITELY_MISSING_U64_VALUE: u64 = MAX_REAL_U64_ID_VALUE + 1;

const MAX_REAL_CHECKPOINT_ID: u64 = 0x0000_FFFF_FFFF_FFFF;
const DEFINITELY_MISSING_CHECKPOINT_ID: u64 = MAX_REAL_CHECKPOINT_ID + 1;

const MAX_REAL_U128_ID_VALUE: u128 = 0x0000_00FF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFFu128;
const DEFINITELY_MISSING_U128_ID_VALUE: u128 = MAX_REAL_U128_ID_VALUE + 1;

fn rand_real_u64_id() -> u64 {
    rand::random::<u64>() % MAX_REAL_U64_ID_VALUE
}
fn rand_real_checkpoint_id() -> u64 {
    // add some padding for addon checks
    (rand::random::<u64>() % MAX_REAL_CHECKPOINT_ID) - 0xFFFF
}
fn rand_real_u128_id() -> u128 {
    rand::random::<u128>() % MAX_REAL_U128_ID_VALUE
}

pub trait THStandardTableIdentifier: Clone + Send + Sync {}
impl<T: Clone + Send + Sync> THStandardTableIdentifier for T {}

pub trait THHasher<Hash: QHashBase>: MerkleZeroHasher<Hash> + Send + Sync + Sized + 'static {}
impl<T: MerkleZeroHasher<Hash> + Send + Sync + Sized + 'static, Hash: QHashBase> THHasher<Hash> for T {}

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
    KivTableAValue: CoreDatabaseValueDeserialize,
    KivTableBValue: CoreDatabaseValueDeserialize,
    ObjSingleIdTableAValue: CoreDatabaseValueDeserialize,
    ObjDoubleIdTableBValue: CoreDatabaseValueDeserialize,
    Hash: QHashBase,
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
        KivTableAValue: CoreDatabaseValueDeserialize,
        KivTableBValue: CoreDatabaseValueDeserialize,
        ObjSingleIdTableAValue: CoreDatabaseValueDeserialize,
        ObjDoubleIdTableBValue: CoreDatabaseValueDeserialize,
        Hash: QHashBase,
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
    // start merkle helpers

    async fn db_select_double_id_merkle_proof_max_checkpoint(
        &self,
        table: &DoubleIdMerkleTableIdentifier,
        max_checkpoint_id: u64,
        tree_id: u64,
        tree_sub_id: u64,
        tree_height: u8,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<MerkleProofCore<Hash>> {
        let mut lookup = key.siblings();
        lookup.push(key.clone());
        lookup.push(SimpleMerkleNodeKey::new_root());
        let mut results = self
            .store
            .db_select_many_double_id_merkle_nodes_max_checkpoint(table, max_checkpoint_id, tree_id, tree_sub_id, tree_height, &lookup)
            .await?;
        let root = results.pop().ok_or_else(|| anyhow::anyhow!("No root found in merkle proof"))?;
        let value = results.pop().ok_or_else(|| anyhow::anyhow!("No node found in merkle proof"))?;
        Ok(MerkleProofCore {
            root,
            value,
            index: key.index,
            siblings: results,
        })
    }

    async fn db_select_single_id_merkle_proof_max_checkpoint(
        &self,
        table: &SingleIdMerkleTableIdentifier,
        checkpoint_id: u64,
        tree_id: u64,
        tree_height: u8,
        key: SimpleMerkleNodeKey,
    ) -> anyhow::Result<MerkleProofCore<Hash>> {
        let mut lookup = key.siblings();
        lookup.push(key.clone());
        lookup.push(SimpleMerkleNodeKey::new_root());
        let mut results = self
            .store
            .db_select_many_single_id_merkle_nodes_max_checkpoint(table, checkpoint_id, tree_id, tree_height, &lookup)
            .await?;
        let root = results.pop().ok_or_else(|| anyhow::anyhow!("No root found in merkle proof"))?;
        let value = results.pop().ok_or_else(|| anyhow::anyhow!("No node value found in merkle proof"))?;
        Ok(MerkleProofCore {
            root,
            value,
            siblings: results,
            index: key.index,
        })
    }
    async fn db_select_zero_id_merkle_proof_max_checkpoint(
        &self,
        table: &ZeroIdMerkleTableIdentifier,
        max_checkpoint_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<MerkleProofCore<Hash>> {
        let mut lookup = key.siblings();
        lookup.push(key.clone());
        lookup.push(SimpleMerkleNodeKey::new_root());
        let mut results = self
            .store
            .db_select_many_zero_id_merkle_nodes_max_checkpoint(table, max_checkpoint_id, &lookup)
            .await?;
        let root = results.pop().ok_or_else(|| anyhow::anyhow!("No root found in merkle proof"))?;
        let value = results.pop().ok_or_else(|| anyhow::anyhow!("No node found in merkle proof"))?;
        Ok(MerkleProofCore {
            root,
            value,
            index: key.index,
            siblings: results,
        })
    }
    async fn db_select_zero_id_merkle_proof_max_checkpoint_to_root_level(
        &self,
        table: &ZeroIdMerkleTableIdentifier,
        max_checkpoint_id: u64,
        root_level: u8,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<MerkleProofCore<Hash>> {
        let mut lookup = key.siblings();
        lookup.push(key.clone());
        lookup.push(key.parent_at_level(root_level));
        let mut results = self
            .store
            .db_select_many_zero_id_merkle_nodes_max_checkpoint(table, max_checkpoint_id, &lookup)
            .await?;
        let root = results.pop().ok_or_else(|| anyhow::anyhow!("No root found in merkle proof"))?;
        let value = results.pop().ok_or_else(|| anyhow::anyhow!("No node found in merkle proof"))?;
        Ok(MerkleProofCore {
            root,
            value,
            index: key.index,
            siblings: results,
        })
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
        KivTableAValue: CoreDatabaseValueDeserialize,
        KivTableBValue: CoreDatabaseValueDeserialize,
        ObjSingleIdTableAValue: CoreDatabaseValueDeserialize,
        ObjDoubleIdTableBValue: CoreDatabaseValueDeserialize,
        Hash: QHashBase,
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
    pub async fn th_util_insert_one_kiv<V: CoreDatabaseValueDeserialize>(
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

    async fn th_util_insert_many_kivs_t<V: CoreDatabaseValueDeserialize, R: QDatabaseKeyIdValueTableRowLike<V> + Send + Sync>(
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
        for (i, row) in rows.iter().enumerate() {
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
        KivTableAValue: CoreDatabaseValueDeserialize,
        KivTableBValue: CoreDatabaseValueDeserialize,
        ObjSingleIdTableAValue: CoreDatabaseValueDeserialize,
        ObjDoubleIdTableBValue: CoreDatabaseValueDeserialize,
        Hash: QHashBase,
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

    pub async fn th_util_select_one_single_checkpointed_object_value<V: CoreDatabaseValueDeserialize>(
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

    pub async fn th_util_select_many_single_checkpointed_object_values<V: CoreDatabaseValueDeserialize>(
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
    pub async fn th_util_insert_single_checkpointed_object<V: CoreDatabaseValueDeserialize>(
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
        V: CoreDatabaseValueDeserialize,
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
        KivTableAValue: CoreDatabaseValueDeserialize + QPGenRandom,
        KivTableBValue: CoreDatabaseValueDeserialize + QPGenRandom,
        ObjSingleIdTableAValue: CoreDatabaseValueDeserialize + QPGenRandom,
        ObjDoubleIdTableBValue: CoreDatabaseValueDeserialize + QPGenRandom,
        Hash: QHashBase + QPGenRandom,
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
    pub async fn th_test_u128_u64_pairs_table(&self, table: &BiDirectionalU64U128MappingTableIdentifier) -> anyhow::Result<()> {
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

    pub async fn th_test_u64_table(&self, table: &U64TableIdentifier) -> anyhow::Result<()> {
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
}

#[pderive::serialize_copy_f_hash]
pub struct PQEDUserLeaf<F: QFelt, Hash: QHashBase> {
    pub public_key: Hash,
    pub user_state_tree_root: Hash,
    pub balance: F,
    pub nonce: F,
    pub last_checkpoint_id: F,
    pub event_index: F,
    pub user_id: F,
}

impl_qpd_serialize_params!(
    PQEDUserLeaf,
    { F: QFelt, Hash: QHashBase } => { F, Hash }
);

impl<F: QFelt, Hash: QHashBase> QPGenRandom for PQEDUserLeaf<F, Hash> {
    fn qp_rand_gen() -> Self{
        Self {
            public_key: Hash::rand_hash(),
            user_state_tree_root: Hash::rand_hash(),
            balance: F::get_simple_rand(),
            nonce: F::get_simple_rand(),
            last_checkpoint_id: F::get_simple_rand(),
            event_index: F::get_simple_rand(),
            user_id: F::get_simple_rand(),
        }
    }
}

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

    pub async fn basic_test(&self) -> anyhow::Result<()> {
        self.store.th_test_u128_u64_pairs_table(&self.store.u64_u128_bi_directional_mapping_table_a).await?;
        self.store.th_test_u64_table(&self.store.u64_table_a).await?;
        Ok(())
    }
}


#[tokio::test]
async fn simple_store_basic_test() -> anyhow::Result<()> {
    let key_space = format!("psy_node_scylla_test_ex1_{}", rand::random::<u64>());
    let scylla_db = ScyllaCoreStore::<ExHash, ExHasher>::new(0, 0, key_space, &[
        "127.0.0.1:9042".to_string()
    ]).await?;
    let simple_store = SimpleStoreEx::setup(Arc::new(scylla_db)).await?;
    simple_store.basic_test().await?;
    Ok(())
}
