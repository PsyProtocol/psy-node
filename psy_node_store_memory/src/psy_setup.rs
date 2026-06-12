use std::sync::Arc;

use parth_core::{data::db::table::QDatabaseTableRoutingKey, protocol::core_types::QNetworkDatabaseTypes};
use psy_node_core::psy_core_db::v3_implementation::full::PsyUnifiedCoreDatabaseStore;

use crate::v2::cbs_store::{InMemoryCoreStore, InMemoryTableIdentifier};

// Type aliases for table identifiers (all use InMemoryTableIdentifier)
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
type ExU64CounterTableIdentifier = InMemoryTableIdentifier;
type ExIMTLeafTableIdentifier = InMemoryTableIdentifier;
type ExIMTKeyIndexTableIdentifier = InMemoryTableIdentifier;
type ExIMTNextAppendIndexTableIdentifier = InMemoryTableIdentifier;

/// Unified Psy Store using InMemoryCoreStore (compatible with ScyllaUnifiedPsyStore interface)
pub type MemoryUnifiedPsyStore<N, Hash, Hasher> = PsyUnifiedCoreDatabaseStore<
    N,
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

fn get_rk(table_id: u64) -> QDatabaseTableRoutingKey {
    QDatabaseTableRoutingKey::new_with_connection_empty_secondary_routing_key(table_id, 0)
}

/// Setup function for in-memory database store (compatible with setup_psy_scylla_database_store).
/// This function creates all required tables and returns a unified store that can be used
/// as a drop-in replacement for ScyllaDB.
pub async fn setup_psy_memory_database_store<N: QNetworkDatabaseTypes>(
    store: Arc<InMemoryCoreStore<N::QHash, N::HasherBase>>,
) -> anyhow::Result<MemoryUnifiedPsyStore<N, N::QHash, N::HasherBase>> {
    // Initialize all tables (same order and names as ScyllaDB setup)
    let checkpoint_leaf_table = store.init_std_table::<ExKivTableIdentifier>("checkpoint_leaf_table", get_rk(1)).await?;
    let checkpoint_root_to_checkpoint_id_table = store.init_std_table::<ExBiDirectionalMappingTableIdentifier>("checkpoint_root_to_checkpoint_id_table", get_rk(2)).await?;
    let checkpoint_leaf_to_checkpoint_id_table = store.init_std_table::<ExBiDirectionalMappingTableIdentifier>("checkpoint_leaf_to_checkpoint_id_table", get_rk(3)).await?;
    let l2_block_state_table = store.init_std_table::<ExKivTableIdentifier>("l2_block_state_table", get_rk(4)).await?;
    let checkpoint_id_to_realm_root_table = store.init_std_table::<ExKivTableIdentifier>("checkpoint_id_to_realm_root_table", get_rk(5)).await?;
    let latest_info_table = store.init_std_table::<ExKivTableIdentifier>("latest_info_table", get_rk(6)).await?;
    let checkpointed_object_table = store.init_std_table::<ExSingleIdTableIdentifier>("checkpointed_object_table", get_rk(7)).await?;
    let checkpoint_state_roots_table = store.init_std_table::<ExKivTableIdentifier>("checkpoint_state_roots_table", get_rk(8)).await?;
    let user_leaf_table = store.init_std_table::<ExSingleIdTableIdentifier>("user_leaf_table", get_rk(9)).await?;
    let user_public_key_table = store.init_std_table::<ExSingleIdTableIdentifier>("user_public_key_table", get_rk(10)).await?;
    let u64_singleton_table = store.init_std_table::<ExU64TableIdentifier>("u64_singleton_table", get_rk(11)).await?;
    let u64_counter_singleton_table = store.init_no_tablet_table::<ExU64CounterTableIdentifier>("u64_counter_singleton_table", get_rk(12)).await?;
    let contract_state_tree_height_table = store.init_std_table::<ExSingleIdTableIdentifier>("contract_state_tree_height_table", get_rk(13)).await?;
    let checkpoint_id_to_pending_id_table = store.init_std_table::<ExU64TableIdentifier>("checkpoint_id_to_pending_id_table", get_rk(14)).await?;
    let pending_id_to_checkpoint_id_table = store.init_std_table::<ExU64TableIdentifier>("pending_id_to_checkpoint_id_table", get_rk(15)).await?;
    let pending_id_to_pending_proc_id_table = store.init_std_table::<ExBiDirectionalU64U128MappingTableIdentifier>("pending_id_to_pending_proc_id_table", get_rk(16)).await?;
    let realm_rewards_tree_node_key_table = store.init_std_table::<ExSingleIdTableIdentifier>("realm_rewards_tree_node_key_table", get_rk(17)).await?;
    // mappings
    let public_key_hash_to_user_ids_table = store.init_std_table::<ExHashToManyIdsTableIdentifier>("public_key_hash_to_user_ids_table", get_rk(18)).await?;
    // start trees
    let global_user_tree_table = store.init_zero_id_merkle_table::<ExZeroIdMerkleTableIdentifier>("global_user_tree_table", get_rk(19), N::GLOBAL_USER_TREE_HEIGHT).await?;
    let user_contract_tree_table = store.init_std_table::<ExSingleIdMerkleTableIdentifier>("user_contract_tree_table", get_rk(20)).await?;
    let contract_state_tree_table = store.init_std_table::<ExDoubleIdMerkleTableIdentifier>("contract_state_tree_table", get_rk(21)).await?;
    let global_checkpoint_tree_table = store.init_zero_id_merkle_table::<ExZeroIdMerkleTableIdentifier>("global_checkpoint_tree_table", get_rk(22), N::CHECKPOINT_TREE_HEIGHT).await?;
    // start reward tree table
    let guta_reward_tag_tree_table = store.init_std_table::<ExTagTreeTableIdentifier>("guta_reward_tag_tree_table", get_rk(23)).await?;
    // added tables for completeness
    let user_registration_tree_table = store.init_zero_id_merkle_table::<ExZeroIdMerkleTableIdentifier>("user_registration_tree_table", get_rk(24), N::GLOBAL_USER_TREE_HEIGHT).await?;
    let global_contract_tree_table = store.init_zero_id_merkle_table::<ExZeroIdMerkleTableIdentifier>("global_contract_tree_table", get_rk(25), N::GLOBAL_CONTRACT_TREE_HEIGHT).await?;
    let contract_function_tree_table = store.init_std_table::<ExSingleIdMerkleTableIdentifier>("contract_function_tree_table", get_rk(26)).await?;
    let contract_leaf_table = store.init_std_table::<ExSingleIdTableIdentifier>("contract_leaf_table", get_rk(27)).await?;
    let contract_code_definition_table = store.init_std_table::<ExSingleIdTableIdentifier>("contract_code_definition_table", get_rk(28)).await?;
    let checkpoint_zk_proof_and_transition_table = store.init_std_table::<ExKivTableIdentifier>("checkpoint_zk_proof_and_transition_table", get_rk(29)).await?;

    let imt_leaf_table = store.init_std_table::<ExIMTLeafTableIdentifier>("imt_leaf_table", get_rk(30)).await?;
    let imt_key_index_table = store
        .init_std_table::<ExIMTKeyIndexTableIdentifier>("imt_key_index_table", get_rk(31))
        .await?;
    let imt_next_append_index_table = store
        .init_std_table::<ExIMTNextAppendIndexTableIdentifier>("imt_next_append_index_table", get_rk(32))
        .await?;

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
        Arc::new(u64_counter_singleton_table),
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
        Arc::new(checkpoint_zk_proof_and_transition_table),
        // IMT tables
        Arc::new(imt_leaf_table),
        Arc::new(imt_key_index_table),
        Arc::new(imt_next_append_index_table),
    );
    Ok(psy_db)
}

pub async fn setup_psy_memory_database_store_from_keyspace<N: QNetworkDatabaseTypes>(
    keyspace: &str,
) -> anyhow::Result<MemoryUnifiedPsyStore<N, N::QHash, N::HasherBase>> {
    let memory_db = InMemoryCoreStore::new_with_keyspace(0, 0, keyspace.to_string());
    setup_psy_memory_database_store::<N>(Arc::new(memory_db)).await
}

