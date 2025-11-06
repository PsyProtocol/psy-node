use std::sync::Arc;

use parth_core::{
    pgoldilocks::{PoseidonHasher, QHashOut}, protocol::core_types::{QNetworkDatabaseTypes, QNetworkHashTypes, QNetworkTreeCircuitConstants, QNetworkTreeConstants}, PHash, PF
};
use plonky2::{field::goldilocks_field::GoldilocksField, hash::hash_types::HashOut};
use psy_node_core::
    psy_core_db::v3_implementation::full::PsyUnifiedCoreDatabaseStore
;
use psy_node_store_memory::cbs_store::{InMemoryCoreStore, InMemoryTableIdentifier};
// ================================================================================================
// REPLACEMENT FOR TEST HARNESS SETUP
// ================================================================================================

// --- Test Type Definitions & Setup ---
type ExHash = PHash;
type ExHasher = PoseidonHasher;

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

#[derive(Debug, Copy, Clone)]
pub struct SimpleTestNetworkConfig;
impl QNetworkTreeCircuitConstants for SimpleTestNetworkConfig {
    const GUTA_CIRCUIT_WHITELIST_TREE_HEIGHT: u8 = 4;
    const MAX_USERS_TO_REGISTER_PER_PROOF: usize = 32;
    const ONLY_REGISTER_USERS_MAX_USERS_PER_PROOF: usize = 64;
    const BATCH_USER_REGISTRATION_SUB_TREE_HEIGHT: usize = 8; 
    const BATCH_USER_REGISTRATION_MAX_SUB_TREES: usize = 4; 
    const BATCH_DEPLOY_CONTRACT_SUB_TREE_HEIGHT: usize = 8;
    const CHAIN_ID: u32 = 0;
}

impl QNetworkTreeConstants for SimpleTestNetworkConfig {
    const CHECKPOINT_TREE_HEIGHT_USIZE: usize = 32;
    const CHECKPOINT_TREE_HEIGHT: u8 = Self::CHECKPOINT_TREE_HEIGHT_USIZE as u8;

    const GLOBAL_USER_TREE_HEIGHT_USIZE: usize = 24;
    const GLOBAL_USER_TREE_HEIGHT: u8 = Self::GLOBAL_USER_TREE_HEIGHT_USIZE as u8;

    const GLOBAL_CONTRACT_TREE_HEIGHT_USIZE: usize = 24;
    const GLOBAL_CONTRACT_TREE_HEIGHT: u8 = Self::GLOBAL_CONTRACT_TREE_HEIGHT_USIZE as u8;

    const CONTRACT_FUNCTION_TREE_HEIGHT_USIZE: usize = 16;
    const CONTRACT_FUNCTION_TREE_HEIGHT: u8 = Self::CONTRACT_FUNCTION_TREE_HEIGHT_USIZE as u8;

    const COORDINATOR_GLOBAL_USER_TREE_HEIGHT_USIZE: usize = 4;
    const COORDINATOR_GLOBAL_USER_TREE_HEIGHT: u8 = Self::COORDINATOR_GLOBAL_USER_TREE_HEIGHT_USIZE as u8;

    const REALM_GLOBAL_USER_TREE_HEIGHT_USIZE: usize = 20;
    const REALM_GLOBAL_USER_TREE_HEIGHT: u8 = Self::REALM_GLOBAL_USER_TREE_HEIGHT_USIZE as u8;

    const MAX_CONTRACT_STATE_TREE_HEIGHT_USIZE: usize = 32;
    const MAX_CONTRACT_STATE_TREE_HEIGHT: u8 = Self::MAX_CONTRACT_STATE_TREE_HEIGHT_USIZE as u8;

    const GROUP_REALM_HEIGHT: u8 = 1;

    const MAX_USERS: u64 = 1 << Self::GLOBAL_USER_TREE_HEIGHT;

    const MAX_REALMS: u32 = 1 << Self::COORDINATOR_GLOBAL_USER_TREE_HEIGHT;

    const MAX_USERS_PER_REALM: u32 = 1 << Self::REALM_GLOBAL_USER_TREE_HEIGHT;

}

pub const SIMPLE_TESTNET_DEFAULT_USER_STATE_TREE_ROOT: QHashOut<GoldilocksField> = QHashOut::<GoldilocksField>(
    HashOut {
        elements: [
            GoldilocksField(3896366420105793420),
            GoldilocksField(17410332186442776169),
            GoldilocksField(7329967984378645716),
            GoldilocksField(6310665049578686403),
        ],
    }
);
impl QNetworkHashTypes for SimpleTestNetworkConfig {
    type QHash = ExHash;
    type HasherBase = ExHasher;
    type F = PF;
}


pub struct P2TestbedChainStateStore<N: QNetworkDatabaseTypes> {
    pub db: PsyUnifiedCoreDatabaseStore<
        N,
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
        InMemoryCoreStore<N::QHash, N::HasherBase>,
    >,
}

impl<N: QNetworkDatabaseTypes> P2TestbedChainStateStore<N> {
    pub async fn setup(store: Arc<InMemoryCoreStore<N::QHash, N::HasherBase>>) -> anyhow::Result<Self> {
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
        Ok(Self { db: psy_db })
    }

}

#[tokio::test]
async fn simple_store_basic_test_1() -> anyhow::Result<()> {
    let db = Arc::new(InMemoryTestStore::new());
    let simple_store = P2TestbedChainStateStore::<SimpleTestNetworkConfig>::setup(db).await?;
    println!("setup simple store");
    Ok(())
}
