use std::sync::Arc;

use parth_core::{
    data::hash::hash256::Hash256,
    protocol::core_types::{QNetworkHashTypes, QNetworkTreeConstants},
};
use parth_crypto::hash::sha256::CoreSha256Hasher;
use psy_node_core::
    psy_core_db::v3_implementation::{full::PsyUnifiedCoreDatabaseStore, test_helper::ExPsyUnifiedStoreTestHelper}
;
use psy_node_store_memory::cbs_store::{InMemoryCoreStore, InMemoryTableIdentifier};
// ================================================================================================
// REPLACEMENT FOR TEST HARNESS SETUP
// ================================================================================================

// --- Test Type Definitions & Setup ---
type ExHash = Hash256;
type ExHasher = CoreSha256Hasher;

/*
BiDirectionalMappingTableIdentifier: Clone + Send + Sync,
BiDirectionalU64U128MappingTableIdentifier: Clone + Send + Sync,
U64TableIdentifier: Clone + Send + Sync,
SingleIdTableIdentifier: Clone + Send + Sync,
DoubleIdTableIdentifier: Clone + Send + Sync,
KivTableIdentifier: Clone + Send + Sync,
SingleIdMerkleTableIdentifier: Clone + Send + Sync,
DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
TagTreeTableIdentifier: Clone + Send + Sync,
HashToManyIdsTableIdentifier: Clone + Send + Sync,

 */

type ExBiDirectionalMappingTableIdentifier = InMemoryTableIdentifier;
type ExBiDirectionalU64U128MappingTableIdentifier = InMemoryTableIdentifier;
type ExU64TableIdentifier = InMemoryTableIdentifier;
type ExSingleIdTableIdentifier = InMemoryTableIdentifier;
type ExDoubleIdTableIdentifier = InMemoryTableIdentifier;
type ExKivTableIdentifier = InMemoryTableIdentifier;
type ExSingleIdMerkleTableIdentifier = InMemoryTableIdentifier;
type ExDoubleIdMerkleTableIdentifier = InMemoryTableIdentifier;
type ExZeroIdMerkleTableIdentifier = InMemoryTableIdentifier;
type ExTagTreeTableIdentifier = InMemoryTableIdentifier;
type ExHashToManyIdsTableIdentifier = InMemoryTableIdentifier;

type InMemoryTestStore = InMemoryCoreStore<ExHash, ExHasher>;
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
        InMemoryTestStore,
    >,
}

impl SimpleStoreEx {
    pub async fn setup(store: Arc<InMemoryTestStore>) -> anyhow::Result<Self> {
        let keyspace = format!("psy_v3_mem_test_ex1_{}", rand::random::<u64>());
        let checkpoint_leaf_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "checkpoint_leaf_table"));
        let checkpoint_root_to_checkpoint_id_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(
            &keyspace,
            "checkpoint_root_to_checkpoint_id_table",
        ));
        let checkpoint_leaf_to_checkpoint_id_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(
            &keyspace,
            "checkpoint_leaf_to_checkpoint_id_table",
        ));
        let l2_block_state_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "l2_block_state_table"));
        let checkpoint_id_to_realm_root_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "checkpoint_id_to_realm_root_table"));
        let latest_info_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "latest_info_table"));
        let checkpointed_object_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "checkpointed_object_table"));
        let checkpoint_state_roots_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "checkpoint_state_roots_table"));
        let user_leaf_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "user_leaf_table"));
        let user_public_key_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "user_public_key_table"));
        let u64_singleton_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "u64_singleton_table"));
        let contract_state_tree_height_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "contract_state_tree_height_table"));
        let checkpoint_id_to_pending_id_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "checkpoint_id_to_pending_id_table"));
        let pending_id_to_checkpoint_id_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "pending_id_to_checkpoint_id_table"));
        let pending_id_to_pending_proc_id_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(
            &keyspace,
            "pending_id_to_pending_proc_id_table",
        ));
        let realm_rewards_tree_node_key_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "realm_rewards_tree_node_key_table"));
        // mappings
        let public_key_hash_to_user_ids_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "public_key_hash_to_user_ids_table"));
        // start trees
        let global_user_tree_table = Arc::new(InMemoryTableIdentifier::new_treee_with_keyspace(&keyspace, "global_user_tree_table", SimpleTestNetworkConfig::GLOBAL_USER_TREE_HEIGHT));
        let user_contract_tree_table = Arc::new(InMemoryTableIdentifier::new_treee_with_keyspace(&keyspace, "user_contract_tree_table", SimpleTestNetworkConfig::GLOBAL_CONTRACT_TREE_HEIGHT));
        let contract_state_tree_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "contract_state_tree_table"));
        let global_checkpoint_tree_table = Arc::new(InMemoryTableIdentifier::new_treee_with_keyspace(&keyspace, "global_checkpoint_tree_table", SimpleTestNetworkConfig::CHECKPOINT_TREE_HEIGHT));
        // start reward tree table
        let guta_reward_tag_tree_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "guta_reward_tag_tree_table"));
        // added tables for completeness
        let user_registration_tree_table = Arc::new(InMemoryTableIdentifier::new_treee_with_keyspace(&keyspace, "user_registration_tree_table", SimpleTestNetworkConfig::GLOBAL_USER_TREE_HEIGHT));
        let global_contract_tree_table = Arc::new(InMemoryTableIdentifier::new_treee_with_keyspace(&keyspace, "global_contract_tree_table", SimpleTestNetworkConfig::GLOBAL_CONTRACT_TREE_HEIGHT));
        let contract_function_tree_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "contract_function_tree_table"));
        let contract_leaf_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "contract_leaf_table"));
        let contract_code_definition_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "contract_code_definition_table"));
        let psy_db = PsyUnifiedCoreDatabaseStore::new(
            store.clone(),
            checkpoint_leaf_table,
            checkpoint_root_to_checkpoint_id_table,
            checkpoint_leaf_to_checkpoint_id_table,
            l2_block_state_table,
            checkpoint_id_to_realm_root_table,
            latest_info_table,
            checkpointed_object_table,
            checkpoint_state_roots_table,
            user_leaf_table,
            user_public_key_table,
            u64_singleton_table,
            contract_state_tree_height_table,
            checkpoint_id_to_pending_id_table,
            pending_id_to_checkpoint_id_table,
            pending_id_to_pending_proc_id_table,
            realm_rewards_tree_node_key_table,
            // mappings
            public_key_hash_to_user_ids_table,
            // start trees
            global_user_tree_table,
            user_contract_tree_table,
            contract_state_tree_table,
            global_checkpoint_tree_table,
            // start reward tree table
            guta_reward_tag_tree_table,
            // added tables for completeness
            user_registration_tree_table,
            global_contract_tree_table,
            contract_function_tree_table,
            contract_leaf_table,
            contract_code_definition_table,
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
async fn simple_store_basic_test_1() -> anyhow::Result<()> {
    let db = Arc::new(InMemoryTestStore::new());
    let simple_store = SimpleStoreEx::setup(db).await?;
    println!("setup simple store");
    simple_store.basic_test_1().await?;
    Ok(())
}
