use std::sync::Arc;

use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
use parth_core::pgoldilocks::PoseidonHasher;

use parth_core::protocol::core_types::{QNetworkHashTypes, QNetworkTreeCircuitSpecificConstants, QNetworkTreeConstants};
use psy_node_core::psy_core_db::v3_implementation::full::PsyUnifiedCoreDatabaseStore;
use psy_node_store_memory::cbs_store::{InMemoryCoreStore, InMemoryTableIdentifier};
use psy_node_store_memory::temp_store::InMemoryTempStore;

pub type Hasher = PoseidonHasher;
pub type Hash = parth_core::PHash;
pub type F = parth_core::PF;
pub type RecTree = SimpleMemoryMerkleRecorderStore<Hasher, Hash>;

#[derive(Debug, Clone, Copy)]
pub struct PsyRGPNetworkConfig {}

impl QNetworkTreeCircuitSpecificConstants for PsyRGPNetworkConfig {
    const GUTA_CIRCUIT_WHITELIST_TREE_HEIGHT: u8 = 4;
    const MAX_USERS_TO_REGISTER_PER_PROOF: usize = 32;
    const ONLY_REGISTER_USERS_MAX_USERS_PER_PROOF: usize = 64;
    const BATCH_USER_REGISTRATION_SUB_TREE_HEIGHT: usize = 8;
    const BATCH_USER_REGISTRATION_MAX_SUB_TREES: usize = 4;
    const BATCH_DEPLOY_CONTRACT_SUB_TREE_HEIGHT: usize = 8;

    const DEFAULT_USER_STATE_TREE_ROOT_HASH_U64_X4: [u64; 4] = [3896366420105793420, 17410332186442776169, 7329967984378645716, 6310665049578686403];

    const END_CAP_CIRCUIT_FINGERPRINT_HASH_U64_X4: [u64; 4] = [1412692327731855940, 17963365021580141687, 10532510199226356508, 3943799806037696098];
}

impl QNetworkTreeConstants for PsyRGPNetworkConfig {
    const CHECKPOINT_TREE_HEIGHT_USIZE: usize = 32;
    const CHECKPOINT_TREE_HEIGHT: u8 = Self::CHECKPOINT_TREE_HEIGHT_USIZE as u8;

    const GLOBAL_USER_TREE_HEIGHT_USIZE: usize = 32;
    const GLOBAL_USER_TREE_HEIGHT: u8 = Self::GLOBAL_USER_TREE_HEIGHT_USIZE as u8;

    const GLOBAL_CONTRACT_TREE_HEIGHT_USIZE: usize = 24;
    const GLOBAL_CONTRACT_TREE_HEIGHT: u8 = Self::GLOBAL_CONTRACT_TREE_HEIGHT_USIZE as u8;

    const CONTRACT_FUNCTION_TREE_HEIGHT_USIZE: usize = 16;
    const CONTRACT_FUNCTION_TREE_HEIGHT: u8 = Self::CONTRACT_FUNCTION_TREE_HEIGHT_USIZE as u8;

    const COORDINATOR_GLOBAL_USER_TREE_HEIGHT_USIZE: usize = 12;
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

type InMemoryTestStore = InMemoryCoreStore<Hash, Hasher>;

impl QNetworkHashTypes for PsyRGPNetworkConfig {
    type QHash = Hash;

    type HasherBase = Hasher;

    type F = F;
}
pub type TempStore = InMemoryTempStore;

pub type PsyRGPTestDatabase = PsyUnifiedCoreDatabaseStore<
    PsyRGPNetworkConfig,
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
    InMemoryTableIdentifier,
    InMemoryTableIdentifier,
    InMemoryTableIdentifier,
    InMemoryTableIdentifier,
    InMemoryCoreStore<Hash, Hasher>,
>;

pub async fn create_rgp_test_db() -> anyhow::Result<PsyRGPTestDatabase> {
    let store = Arc::new(InMemoryTestStore::new());
    setup_rgp_test_db(store).await
}
pub async fn setup_rgp_test_db(store: Arc<InMemoryTestStore>) -> anyhow::Result<PsyRGPTestDatabase> {
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
    let u64_counter_singleton_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "u64_counter_singleton_table"));
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
    let global_user_tree_table = Arc::new(InMemoryTableIdentifier::new_treee_with_keyspace(
        &keyspace,
        "global_user_tree_table",
        PsyRGPNetworkConfig::GLOBAL_USER_TREE_HEIGHT,
    ));
    let user_contract_tree_table = Arc::new(InMemoryTableIdentifier::new_treee_with_keyspace(
        &keyspace,
        "user_contract_tree_table",
        PsyRGPNetworkConfig::GLOBAL_CONTRACT_TREE_HEIGHT,
    ));
    let contract_state_tree_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "contract_state_tree_table"));
    let global_checkpoint_tree_table = Arc::new(InMemoryTableIdentifier::new_treee_with_keyspace(
        &keyspace,
        "global_checkpoint_tree_table",
        PsyRGPNetworkConfig::CHECKPOINT_TREE_HEIGHT,
    ));
    // start reward tree table
    let guta_reward_tag_tree_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "guta_reward_tag_tree_table"));
    // added tables for completeness
    let user_registration_tree_table = Arc::new(InMemoryTableIdentifier::new_treee_with_keyspace(
        &keyspace,
        "user_registration_tree_table",
        PsyRGPNetworkConfig::GLOBAL_USER_TREE_HEIGHT,
    ));
    let validator_tree_table = Arc::new(InMemoryTableIdentifier::new_treee_with_keyspace(
        &keyspace,
        "validator_tree_table",
        psy_data::guta::realm_finalize::VALIDATOR_TREE_HEIGHT as u8,
    ));
    let global_contract_tree_table = Arc::new(InMemoryTableIdentifier::new_treee_with_keyspace(
        &keyspace,
        "global_contract_tree_table",
        PsyRGPNetworkConfig::GLOBAL_CONTRACT_TREE_HEIGHT,
    ));
    let contract_function_tree_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "contract_function_tree_table"));
    let contract_leaf_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "contract_leaf_table"));
    let contract_code_definition_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "contract_code_definition_table"));
    let checkpoint_zk_proof_and_transition_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(
        &keyspace,
        "checkpoint_zk_proof_and_transition_table",
    ));

    let imt_leaf_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "imt_leaf_table"));
    let imt_key_index_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "imt_key_index_table"));
    let imt_next_append_index_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "imt_next_append_index_table"));

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
        u64_counter_singleton_table,
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
        validator_tree_table,
        global_contract_tree_table,
        contract_function_tree_table,
        contract_leaf_table,
        contract_code_definition_table,
        checkpoint_zk_proof_and_transition_table,
        imt_leaf_table,
        imt_key_index_table,
        imt_next_append_index_table,
    );
    Ok(psy_db)
}
