use std::sync::Arc;

use parth_core::{
    data::{
        hash::hash256::Hash256,
    },
    protocol::core_types::{QNetworkHashTypes, QNetworkTreeConstants},
};
use parth_crypto::hash::sha256::CoreSha256Hasher;
use psy_node_scylla::{
    core::ScyllaCoreStore,
    tables::{
        blob::ScyllaBiDirectionalBlobToBlobTablePreparedStatements, counter::u64_counter::ScyllaU64ToU64CounterTablePreparedStatements, hash_to_many_ids::ScyllaHashToManyIdsTablePreparedStatements, imt::{ScyllaIMTKeyIndexPreparedStatements, ScyllaIMTLeafPreparedStatements, ScyllaIMTNextAppendIndexPreparedStatements}, merkle::{
            ScyllaDoubleMerkleNodesPreparedStatements, ScyllaMerkleNodesPreparedStatements, ScyllaMerkleNodesZeroPreparedStatements,
        }, object::{
            ScyllaGenericKeyIdValueTablePreparedStatements, ScyllaGenericObjectDoubleIdTablePreparedStatements,
            ScyllaGenericObjectSingleIdTablePreparedStatements,
        }, tag_tree::ScyllaTagTreeNodesPreparedStatements, u64_table::{ScyllaBidirectionalU64U128MappingPreparedStatements, ScyllaU64ToU64TablePreparedStatements}
    },
};
use psy_node_core::{
    psy_core_db::v3_implementation::{test_helper::ExPsyUnifiedStoreTestHelper},
};

// ================================================================================================
// REPLACEMENT FOR TEST HARNESS SETUP
// ================================================================================================

// --- Test Type Definitions & Setup ---
type ExHash = Hash256;
type ExHasher = CoreSha256Hasher;

type ExBiDirectionalMappingTableIdentifier = ScyllaBiDirectionalBlobToBlobTablePreparedStatements;
type ExBiDirectionalU64U128MappingTableIdentifier = ScyllaBidirectionalU64U128MappingPreparedStatements;
type ExU64TableIdentifier = ScyllaU64ToU64TablePreparedStatements;
type ExU64CounterTableIdentifier = ScyllaU64ToU64CounterTablePreparedStatements;
type ExSingleIdTableIdentifier = ScyllaGenericObjectSingleIdTablePreparedStatements;
type ExDoubleIdTableIdentifier = ScyllaGenericObjectDoubleIdTablePreparedStatements;
type ExKivTableIdentifier = ScyllaGenericKeyIdValueTablePreparedStatements;
type ExSingleIdMerkleTableIdentifier = ScyllaMerkleNodesPreparedStatements;
type ExDoubleIdMerkleTableIdentifier = ScyllaDoubleMerkleNodesPreparedStatements;
type ExZeroIdMerkleTableIdentifier = ScyllaMerkleNodesZeroPreparedStatements;
type ExTagTreeTableIdentifier = ScyllaTagTreeNodesPreparedStatements;
type ExHashToManyIdsTableIdentifier = ScyllaHashToManyIdsTablePreparedStatements;
type ExIMTLeafTableIdentifier = ScyllaIMTLeafPreparedStatements;
type ExIMTKeyIndexTableIdentifier = ScyllaIMTKeyIndexPreparedStatements;
type ExIMTNextAppendIndexTableIdentifier = ScyllaIMTNextAppendIndexPreparedStatements;

type ScyllaTestStore = ScyllaCoreStore<ExHash, ExHasher>;

#[derive(Copy, Clone)]
pub struct SimpleTestNetworkConfig {}
impl QNetworkTreeConstants for SimpleTestNetworkConfig {
    const CHECKPOINT_TREE_HEIGHT_USIZE: usize = 32;
    const CHECKPOINT_TREE_HEIGHT: u8 = Self::CHECKPOINT_TREE_HEIGHT_USIZE as u8;

    const GLOBAL_USER_TREE_HEIGHT_USIZE: usize = 32;
    const GLOBAL_USER_TREE_HEIGHT: u8 = Self::GLOBAL_USER_TREE_HEIGHT_USIZE as u8;

    const GLOBAL_CONTRACT_TREE_HEIGHT_USIZE: usize = 24;
    const GLOBAL_CONTRACT_TREE_HEIGHT: u8 = Self::GLOBAL_CONTRACT_TREE_HEIGHT_USIZE as u8;

    const CONTRACT_FUNCTION_TREE_HEIGHT_USIZE: usize = 16;
    const CONTRACT_FUNCTION_TREE_HEIGHT: u8 = Self::CONTRACT_FUNCTION_TREE_HEIGHT_USIZE as u8;

    const COORDINATOR_GLOBAL_USER_TREE_HEIGHT_USIZE: usize = 10;
    const COORDINATOR_GLOBAL_USER_TREE_HEIGHT: u8 = Self::COORDINATOR_GLOBAL_USER_TREE_HEIGHT_USIZE as u8;

    const REALM_GLOBAL_USER_TREE_HEIGHT_USIZE: usize = 22;
    const REALM_GLOBAL_USER_TREE_HEIGHT: u8 = Self::REALM_GLOBAL_USER_TREE_HEIGHT_USIZE as u8;

    const MAX_CONTRACT_STATE_TREE_HEIGHT_USIZE: usize = 32;
    const MAX_CONTRACT_STATE_TREE_HEIGHT: u8 = Self::MAX_CONTRACT_STATE_TREE_HEIGHT_USIZE as u8;

    const GROUP_REALM_HEIGHT: u8 = 3;

    const MAX_USERS: u64 = 1 << Self::GLOBAL_USER_TREE_HEIGHT;

    const MAX_REALMS: u32 = 1 << Self::COORDINATOR_GLOBAL_USER_TREE_HEIGHT;

    const MAX_USERS_PER_REALM: u32 = 1 << Self::REALM_GLOBAL_USER_TREE_HEIGHT;
}

impl QNetworkHashTypes for SimpleTestNetworkConfig {
    type QHash = ExHash;
    type HasherBase = CoreSha256Hasher;
    type F = u64;
}
pub struct SimpleStoreEx {
    pub store: ExPsyUnifiedStoreTestHelper<
        SimpleTestNetworkConfig,
        ExBiDirectionalMappingTableIdentifier,
        ExBiDirectionalU64U128MappingTableIdentifier,
        ExU64TableIdentifier,
        ExU64CounterTableIdentifier,
        ExSingleIdTableIdentifier,
        ExDoubleIdTableIdentifier,
        ExKivTableIdentifier,
        ExSingleIdMerkleTableIdentifier,
        ExDoubleIdMerkleTableIdentifier,
        ExZeroIdMerkleTableIdentifier,
        ExTagTreeTableIdentifier,
        ExHashToManyIdsTableIdentifier,
        ExIMTLeafTableIdentifier,
        ExIMTKeyIndexTableIdentifier,
        ExIMTNextAppendIndexTableIdentifier,
        ScyllaTestStore,
    >,
}


impl SimpleStoreEx {
    pub async fn setup(store: Arc<ScyllaCoreStore<ExHash, ExHasher>>) -> anyhow::Result<Self> {
        let psy_db = psy_node_scylla::psy_setup::setup_psy_scylla_database_store::<SimpleTestNetworkConfig>(store.clone()).await?;
        // Edge preparation must work on an existing schema without creating it.
        let prepared = psy_node_scylla::psy_setup::prepare_psy_scylla_database_store::<SimpleTestNetworkConfig>(store).await?;
        assert_eq!(prepared.store.keyspace, psy_db.store.keyspace);
        let simple_store = ExPsyUnifiedStoreTestHelper::new(psy_db, 0, 0);
        Ok(Self { store: simple_store })
    }

    pub async fn basic_test_1(&self) -> anyhow::Result<()> {
        println!("starting basic_test_1");
        self.store.run_all_tests().await?;
        Ok(())
    }
}

#[tokio::test]
#[ignore = "database slow"]
async fn simple_store_basic_test_1() -> anyhow::Result<()> {
    let key_space = format!("psy_node_v3_scylla_test_ex1_{}", rand::random::<u64>());
    let scylla_db = ScyllaTestStore::new(0, 0, key_space, &[std::env::var("PSY_TEST_SCYLLA").expect("PSY_TEST_SCYLLA must identify an isolated test database")]).await?;
    let simple_store = SimpleStoreEx::setup(Arc::new(scylla_db)).await?;
    println!("setup simple store");
    simple_store.basic_test_1().await?;
    Ok(())
}
