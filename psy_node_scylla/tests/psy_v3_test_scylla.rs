use std::sync::Arc;

use parth_core::{
    data::{
        db::table::QDatabaseTableRoutingKey,
        hash::hash256::Hash256,
    },
    protocol::core_types::{QNetworkHashTypes, QNetworkTreeConstants},
};
use parth_crypto::hash::sha256::CoreSha256Hasher;
use parth_node_scylla::{
    core::ScyllaCoreStore,
    tables::{
        blob::ScyllaBiDirectionalBlobToBlobTablePreparedStatements,
        hash_to_many_ids::ScyllaHashToManyIdsTablePreparedStatements,
        merkle::{
            ScyllaDoubleMerkleNodesPreparedStatements, ScyllaMerkleNodesPreparedStatements, ScyllaMerkleNodesZeroPreparedStatements,
        },
        object::{
            ScyllaGenericKeyIdValueTablePreparedStatements, ScyllaGenericObjectDoubleIdTablePreparedStatements,
            ScyllaGenericObjectSingleIdTablePreparedStatements,
        },
        tag_tree::ScyllaTagTreeNodesPreparedStatements,
        u64_tbl::{ScyllaBidirectionalU64U128MappingPreparedStatements, ScyllaU64ToU64TablePreparedStatements},
    },
};
use psy_node_core::{
    psy_core_db::v3_implementation::{full::PsyUnifiedCoreDatabaseStore, test_helper::ExPsyUnifiedStoreTestHelper},
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
type ExSingleIdTableIdentifier = ScyllaGenericObjectSingleIdTablePreparedStatements;
type ExDoubleIdTableIdentifier = ScyllaGenericObjectDoubleIdTablePreparedStatements;
type ExKivTableIdentifier = ScyllaGenericKeyIdValueTablePreparedStatements;
type ExSingleIdMerkleTableIdentifier = ScyllaMerkleNodesPreparedStatements;
type ExDoubleIdMerkleTableIdentifier = ScyllaDoubleMerkleNodesPreparedStatements;
type ExZeroIdMerkleTableIdentifier = ScyllaMerkleNodesZeroPreparedStatements;
type ExTagTreeTableIdentifier = ScyllaTagTreeNodesPreparedStatements;
type ExHashToManyIdsTableIdentifier = ScyllaHashToManyIdsTablePreparedStatements;

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
        ExSingleIdTableIdentifier,
        ExDoubleIdTableIdentifier,
        ExKivTableIdentifier,
        ExSingleIdMerkleTableIdentifier,
        ExDoubleIdMerkleTableIdentifier,
        ExZeroIdMerkleTableIdentifier,
        ExTagTreeTableIdentifier,
        ExHashToManyIdsTableIdentifier,
        ScyllaTestStore,
    >,
}

fn get_rk(table_id: u64) -> QDatabaseTableRoutingKey {
    QDatabaseTableRoutingKey::new_with_connection_empty_secondary_routing_key(table_id, 0)
}

impl SimpleStoreEx {
    pub async fn setup(store: Arc<ScyllaTestStore>) -> anyhow::Result<Self> {
        let checkpoint_leaf_table = store.init_std_table::<ExKivTableIdentifier>("checkpoint_leaf_table", get_rk(1)).await?;
        let checkpoint_root_to_checkpoint_id_table = store
            .init_std_table::<ExBiDirectionalMappingTableIdentifier>("checkpoint_root_to_checkpoint_id_table", get_rk(2))
            .await?;
        let checkpoint_leaf_to_checkpoint_id_table = store
            .init_std_table::<ExBiDirectionalMappingTableIdentifier>("checkpoint_leaf_to_checkpoint_id_table", get_rk(3))
            .await?;
        let l2_block_state_table = store.init_std_table::<ExKivTableIdentifier>("l2_block_state_table", get_rk(4)).await?;
        let checkpoint_id_to_realm_root_table =
            store.init_std_table::<ExKivTableIdentifier>("checkpoint_id_to_realm_root_table", get_rk(5)).await?;
        let latest_info_table = store.init_std_table::<ExKivTableIdentifier>("latest_info_table", get_rk(6)).await?;
        let checkpointed_object_table = store.init_std_table::<ExSingleIdTableIdentifier>("checkpointed_object_table", get_rk(7)).await?;
        let checkpoint_state_roots_table = store.init_std_table::<ExKivTableIdentifier>("checkpoint_state_roots_table", get_rk(8)).await?;
        let user_leaf_table = store.init_std_table::<ExSingleIdTableIdentifier>("user_leaf_table", get_rk(9)).await?;
        let user_public_key_table = store.init_std_table::<ExSingleIdTableIdentifier>("user_public_key_table", get_rk(10)).await?;
        let u64_singleton_table = store.init_std_table::<ExU64TableIdentifier>("u64_singleton_table", get_rk(11)).await?;
        let contract_state_tree_height_table =
            store.init_std_table::<ExSingleIdTableIdentifier>("contract_state_tree_height_table", get_rk(12)).await?;
        let checkpoint_id_to_pending_id_table =
            store.init_std_table::<ExU64TableIdentifier>("checkpoint_id_to_pending_id_table", get_rk(13)).await?;
        let pending_id_to_checkpoint_id_table =
            store.init_std_table::<ExU64TableIdentifier>("pending_id_to_checkpoint_id_table", get_rk(14)).await?;
        let pending_id_to_pending_proc_id_table = store
            .init_std_table::<ExBiDirectionalU64U128MappingTableIdentifier>("pending_id_to_pending_proc_id_table", get_rk(15))
            .await?;
        let realm_rewards_tree_node_key_table = store
            .init_std_table::<ExSingleIdTableIdentifier>("realm_rewards_tree_node_key_table", get_rk(27))
            .await?;
        // mappings
        let public_key_hash_to_user_ids_table =
            store.init_std_table::<ExHashToManyIdsTableIdentifier>("public_key_hash_to_user_ids_table", get_rk(16)).await?;
        // start trees
        let global_user_tree_table = store
            .init_zero_id_merkle_table(
                "global_user_tree_table",
                get_rk(17),
                SimpleTestNetworkConfig::GLOBAL_USER_TREE_HEIGHT,
            )
            .await?;
        let user_contract_tree_table = store.init_std_table::<ExSingleIdMerkleTableIdentifier>("user_contract_tree_table", get_rk(18)).await?;
        let contract_state_tree_table =
            store.init_std_table::<ExDoubleIdMerkleTableIdentifier>("contract_state_tree_table", get_rk(19)).await?;
        let global_checkpoint_tree_table = store
            .init_zero_id_merkle_table(
                "global_checkpoint_tree_table",
                get_rk(20),
                SimpleTestNetworkConfig::CHECKPOINT_TREE_HEIGHT,
            )
            .await?;
        // start reward tree table
        let guta_reward_tag_tree_table = store.init_std_table::<ExTagTreeTableIdentifier>("guta_reward_tag_tree_table", get_rk(21)).await?;
        // added tables for completeness
        let user_registration_tree_table = store
            .init_zero_id_merkle_table(
                "user_registration_tree_table",
                get_rk(22),
                SimpleTestNetworkConfig::GLOBAL_USER_TREE_HEIGHT,
            )
            .await?;
        let global_contract_tree_table = store
            .init_zero_id_merkle_table(
                "global_contract_tree_table",
                get_rk(23),
                SimpleTestNetworkConfig::GLOBAL_CONTRACT_TREE_HEIGHT,
            )
            .await?;
        let contract_function_tree_table =
            store.init_std_table::<ExSingleIdMerkleTableIdentifier>("contract_function_tree_table", get_rk(24)).await?;
        let contract_leaf_table = store.init_std_table::<ExSingleIdTableIdentifier>("contract_leaf_table", get_rk(25)).await?;
        let contract_code_definition_table =
            store.init_std_table::<ExSingleIdTableIdentifier>("contract_code_definition_table", get_rk(26)).await?;

        let psy_db = PsyUnifiedCoreDatabaseStore::new(
            store.clone(),
            Arc::new(checkpoint_leaf_table),
            Arc::new(checkpoint_root_to_checkpoint_id_table),
            Arc::new(checkpoint_leaf_to_checkpoint_id_table),
            Arc::new(l2_block_state_table),
            Arc::new(checkpoint_id_to_realm_root_table),
            Arc::new(latest_info_table),
            Arc::new(checkpointed_object_table),
            Arc::new(checkpoint_state_roots_table),
            Arc::new(user_leaf_table),
            Arc::new(user_public_key_table),
            Arc::new(u64_singleton_table),
            Arc::new(contract_state_tree_height_table),
            Arc::new(checkpoint_id_to_pending_id_table),
            Arc::new(pending_id_to_checkpoint_id_table),
            Arc::new(pending_id_to_pending_proc_id_table),
            Arc::new(realm_rewards_tree_node_key_table),
            // mappings
            Arc::new(public_key_hash_to_user_ids_table),
            // start trees
            Arc::new(global_user_tree_table),
            Arc::new(user_contract_tree_table),
            Arc::new(contract_state_tree_table),
            Arc::new(global_checkpoint_tree_table),
            // start reward tree table
            Arc::new(guta_reward_tag_tree_table),
            // added tables for completeness
            Arc::new(user_registration_tree_table),
            Arc::new(global_contract_tree_table),
            Arc::new(contract_function_tree_table),
            Arc::new(contract_leaf_table),
            Arc::new(contract_code_definition_table),
        );
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
    let scylla_db = ScyllaTestStore::new(0, 0, key_space, &["127.0.0.1:9042".to_string()]).await?;
    let simple_store = SimpleStoreEx::setup(Arc::new(scylla_db)).await?;
    println!("setup simple store");
    simple_store.basic_test_1().await?;
    Ok(())
}