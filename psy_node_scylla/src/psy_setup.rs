use std::sync::Arc;

use parth_core::{data::db::table::QDatabaseTableRoutingKey, protocol::core_types::QNetworkDatabaseTypes};
use psy_node_core::psy_core_db::v3_implementation::full::PsyUnifiedCoreDatabaseStore;

use crate::{
    core::ScyllaCoreStore,
    tables::{
        blob::ScyllaBiDirectionalBlobToBlobTablePreparedStatements, bridge::{deposit_leaf::ScyllaBridgeDepositLeafPreparedStatements, next_index::ScyllaBridgeDepositNextIndexPreparedStatements}, counter::u64_counter::ScyllaU64ToU64CounterTablePreparedStatements, hash_to_many_ids::ScyllaHashToManyIdsTablePreparedStatements, imt::{imt_key_index::ScyllaIMTKeyIndexPreparedStatements, imt_leaf::ScyllaIMTLeafPreparedStatements, imt_next_append_index::ScyllaIMTNextAppendIndexPreparedStatements}, merkle::{ScyllaDoubleMerkleNodesPreparedStatements, ScyllaMerkleNodesPreparedStatements, ScyllaMerkleNodesZeroPreparedStatements}, object::{
            ScyllaGenericKeyIdValueTablePreparedStatements, ScyllaGenericObjectDoubleIdTablePreparedStatements,
            ScyllaGenericObjectSingleIdTablePreparedStatements,
        }, tag_tree::ScyllaTagTreeNodesPreparedStatements, u64_table::{ScyllaBidirectionalU64U128MappingPreparedStatements, ScyllaU64ToU64TablePreparedStatements}
    },
};

type ExBiDirectionalMappingTableIdentifier = ScyllaBiDirectionalBlobToBlobTablePreparedStatements;
type ExBiDirectionalU64U128MappingTableIdentifier = ScyllaBidirectionalU64U128MappingPreparedStatements;
type ExU64TableIdentifier = ScyllaU64ToU64TablePreparedStatements;
type ExSingleIdTableIdentifier = ScyllaGenericObjectSingleIdTablePreparedStatements;
type ExKivTableIdentifier = ScyllaGenericKeyIdValueTablePreparedStatements;
type ExSingleIdMerkleTableIdentifier = ScyllaMerkleNodesPreparedStatements;
type ExDoubleIdMerkleTableIdentifier = ScyllaDoubleMerkleNodesPreparedStatements;
type ExTagTreeTableIdentifier = ScyllaTagTreeNodesPreparedStatements;
type ExHashToManyIdsTableIdentifier = ScyllaHashToManyIdsTablePreparedStatements;
type ExU64CounterTableIdentifier = ScyllaU64ToU64CounterTablePreparedStatements;
type ExIMTLeafTableIdentifier = ScyllaIMTLeafPreparedStatements;
type ExIMTKeyIndexTableIdentifier = ScyllaIMTKeyIndexPreparedStatements;
type ExIMTNextAppendIndexTableIdentifier = ScyllaIMTNextAppendIndexPreparedStatements;
type ExBridgeDepositLeafTableIdentifier = ScyllaBridgeDepositLeafPreparedStatements;
type ExBridgeDepositNextIndexTableIdentifier = ScyllaBridgeDepositNextIndexPreparedStatements;
pub type ScyllaUnifiedPsyStore<N, Hash, Hasher> = PsyUnifiedCoreDatabaseStore<
    N,
    ScyllaBiDirectionalBlobToBlobTablePreparedStatements,
    ScyllaBidirectionalU64U128MappingPreparedStatements,
    ScyllaU64ToU64TablePreparedStatements,
    ScyllaU64ToU64CounterTablePreparedStatements,
    ScyllaGenericObjectSingleIdTablePreparedStatements,
    ScyllaGenericObjectDoubleIdTablePreparedStatements,
    ScyllaGenericKeyIdValueTablePreparedStatements,
    ScyllaMerkleNodesPreparedStatements,
    ScyllaDoubleMerkleNodesPreparedStatements,
    ScyllaMerkleNodesZeroPreparedStatements,
    ScyllaTagTreeNodesPreparedStatements,
    ScyllaHashToManyIdsTablePreparedStatements,
    ScyllaIMTLeafPreparedStatements,
    ScyllaIMTKeyIndexPreparedStatements,
    ScyllaIMTNextAppendIndexPreparedStatements,
    ScyllaCoreStore<Hash, Hasher>,
>;

fn get_rk(table_id: u64) -> QDatabaseTableRoutingKey {
    QDatabaseTableRoutingKey::new_with_connection_empty_secondary_routing_key(table_id, 0)
}
pub async fn setup_psy_scylla_database_store<N: QNetworkDatabaseTypes>(
    store: Arc<ScyllaCoreStore<N::QHash, N::HasherBase>>,
) -> anyhow::Result<ScyllaUnifiedPsyStore<N, N::QHash, N::HasherBase>> {
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
    let global_user_tree_table = store.init_zero_id_merkle_table("global_user_tree_table", get_rk(19), N::GLOBAL_USER_TREE_HEIGHT).await?;
    let user_contract_tree_table = store.init_std_table::<ExSingleIdMerkleTableIdentifier>("user_contract_tree_table", get_rk(20)).await?;
    let contract_state_tree_table = store.init_std_table::<ExDoubleIdMerkleTableIdentifier>("contract_state_tree_table", get_rk(21)).await?;
    let global_checkpoint_tree_table = store.init_zero_id_merkle_table("global_checkpoint_tree_table", get_rk(22), N::CHECKPOINT_TREE_HEIGHT).await?;
    // start reward tree table
    let guta_reward_tag_tree_table = store.init_std_table::<ExTagTreeTableIdentifier>("guta_reward_tag_tree_table", get_rk(23)).await?;
    // added tables for completeness
    let user_registration_tree_table = store.init_zero_id_merkle_table("user_registration_tree_table", get_rk(24), N::GLOBAL_USER_TREE_HEIGHT).await?;
    let validator_tree_table = store.init_zero_id_merkle_table("validator_tree_table", get_rk(33), 20u8).await?;
    let global_contract_tree_table = store.init_zero_id_merkle_table("global_contract_tree_table", get_rk(25), N::GLOBAL_CONTRACT_TREE_HEIGHT).await?;
    let contract_function_tree_table = store.init_std_table::<ExSingleIdMerkleTableIdentifier>("contract_function_tree_table", get_rk(26)).await?;
    let contract_leaf_table = store.init_std_table::<ExSingleIdTableIdentifier>("contract_leaf_table", get_rk(27)).await?;
    let contract_code_definition_table = store.init_std_table::<ExSingleIdTableIdentifier>("contract_code_definition_table", get_rk(28)).await?;
    let checkpoint_zk_proof_and_transition_table = store.init_std_table::<ExKivTableIdentifier>("checkpoint_zk_proof_and_transition_table", get_rk(29)).await?;

    let imt_leaf_table = store.init_std_table::<ExIMTLeafTableIdentifier>("imt_leaf_table", get_rk(30)).await?;
    let imt_key_index_table = store.init_std_table::<ExIMTKeyIndexTableIdentifier>("imt_key_index_table", get_rk(31)).await?;
    let imt_next_append_index_table = store.init_std_table::<ExIMTNextAppendIndexTableIdentifier>("imt_next_append_index_table", get_rk(32)).await?;

    /**
    let (
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
        public_key_hash_to_user_ids_table,
        global_user_tree_table,
        user_contract_tree_table,
        contract_state_tree_table,
        global_checkpoint_tree_table,
        guta_reward_tag_tree_table,
        user_registration_tree_table,
        validator_tree_table,
        global_contract_tree_table,
        contract_function_tree_table,
        contract_leaf_table,
        contract_code_definition_table,
        checkpoint_zk_proof_and_transition_table,
    ) = tokio::try_join!(
        store.init_std_table::<ExKivTableIdentifier>("checkpoint_leaf_table", get_rk(1)),
        store.init_std_table::<ExBiDirectionalMappingTableIdentifier>("checkpoint_root_to_checkpoint_id_table", get_rk(2)),
        store.init_std_table::<ExBiDirectionalMappingTableIdentifier>("checkpoint_leaf_to_checkpoint_id_table", get_rk(3)),
        store.init_std_table::<ExKivTableIdentifier>("l2_block_state_table", get_rk(4)),
        store.init_std_table::<ExKivTableIdentifier>("checkpoint_id_to_realm_root_table", get_rk(5)),
        store.init_std_table::<ExKivTableIdentifier>("latest_info_table", get_rk(6)),
        store.init_std_table::<ExSingleIdTableIdentifier>("checkpointed_object_table", get_rk(7)),
        store.init_std_table::<ExKivTableIdentifier>("checkpoint_state_roots_table", get_rk(8)),
        store.init_std_table::<ExSingleIdTableIdentifier>("user_leaf_table", get_rk(9)),
        store.init_std_table::<ExSingleIdTableIdentifier>("user_public_key_table", get_rk(10)),
        store.init_std_table::<ExU64TableIdentifier>("u64_singleton_table", get_rk(11)),
        store.init_no_tablet_table::<ExU64CounterTableIdentifier>("u64_counter_singleton_table", get_rk(12)),
        store.init_std_table::<ExSingleIdTableIdentifier>("contract_state_tree_height_table", get_rk(13)),
        store.init_std_table::<ExU64TableIdentifier>("checkpoint_id_to_pending_id_table", get_rk(14)),
        store.init_std_table::<ExU64TableIdentifier>("pending_id_to_checkpoint_id_table", get_rk(15)),
        store.init_std_table::<ExBiDirectionalU64U128MappingTableIdentifier>("pending_id_to_pending_proc_id_table", get_rk(16)),
        store.init_std_table::<ExSingleIdTableIdentifier>("realm_rewards_tree_node_key_table", get_rk(17)),
        // mappings
        store.init_std_table::<ExHashToManyIdsTableIdentifier>("public_key_hash_to_user_ids_table", get_rk(18)),
        // start trees
        store.init_zero_id_merkle_table("global_user_tree_table", get_rk(19), N::GLOBAL_USER_TREE_HEIGHT),
        store.init_std_table::<ExSingleIdMerkleTableIdentifier>("user_contract_tree_table", get_rk(20)),
        store.init_std_table::<ExDoubleIdMerkleTableIdentifier>("contract_state_tree_table", get_rk(21)),
        store.init_zero_id_merkle_table("global_checkpoint_tree_table", get_rk(22), N::CHECKPOINT_TREE_HEIGHT),
        // start reward tree table
        store.init_std_table::<ExTagTreeTableIdentifier>("guta_reward_tag_tree_table", get_rk(23)),
        // added tables for completeness
        store.init_zero_id_merkle_table("user_registration_tree_table", get_rk(24), N::GLOBAL_USER_TREE_HEIGHT),
        store.init_zero_id_merkle_table("validator_tree_table", get_rk(33), psy_data::guta::realm_finalize::VALIDATOR_TREE_HEIGHT as u8),
        store.init_zero_id_merkle_table("global_contract_tree_table", get_rk(25), N::GLOBAL_CONTRACT_TREE_HEIGHT),
        store.init_std_table::<ExSingleIdMerkleTableIdentifier>("contract_function_tree_table", get_rk(26)),
        store.init_std_table::<ExSingleIdTableIdentifier>("contract_leaf_table", get_rk(27)),
        store.init_std_table::<ExSingleIdTableIdentifier>("contract_code_definition_table", get_rk(28)),
        store.init_std_table::<ExKivTableIdentifier>("checkpoint_zk_proof_and_transition_table", get_rk(29))
    )?;
     */
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
        Arc::new(validator_tree_table),
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

// Edge nodes version - only prepare statements, don't create tables
pub async fn prepare_psy_scylla_database_store<N: QNetworkDatabaseTypes>(
    store: Arc<ScyllaCoreStore<N::QHash, N::HasherBase>>,
) -> anyhow::Result<ScyllaUnifiedPsyStore<N, N::QHash, N::HasherBase>> {
    let checkpoint_leaf_table = store.init_std_table_prepare_only::<ExKivTableIdentifier>("checkpoint_leaf_table", get_rk(1)).await?;
    let checkpoint_root_to_checkpoint_id_table = store.init_std_table_prepare_only::<ExBiDirectionalMappingTableIdentifier>("checkpoint_root_to_checkpoint_id_table", get_rk(2)).await?;
    let checkpoint_leaf_to_checkpoint_id_table = store.init_std_table_prepare_only::<ExBiDirectionalMappingTableIdentifier>("checkpoint_leaf_to_checkpoint_id_table", get_rk(3)).await?;
    let l2_block_state_table = store.init_std_table_prepare_only::<ExKivTableIdentifier>("l2_block_state_table", get_rk(4)).await?;
    let checkpoint_id_to_realm_root_table = store.init_std_table_prepare_only::<ExKivTableIdentifier>("checkpoint_id_to_realm_root_table", get_rk(5)).await?;
    let latest_info_table = store.init_std_table_prepare_only::<ExKivTableIdentifier>("latest_info_table", get_rk(6)).await?;
    let checkpointed_object_table = store.init_std_table_prepare_only::<ExSingleIdTableIdentifier>("checkpointed_object_table", get_rk(7)).await?;
    let checkpoint_state_roots_table = store.init_std_table_prepare_only::<ExKivTableIdentifier>("checkpoint_state_roots_table", get_rk(8)).await?;
    let user_leaf_table = store.init_std_table_prepare_only::<ExSingleIdTableIdentifier>("user_leaf_table", get_rk(9)).await?;
    let user_public_key_table = store.init_std_table_prepare_only::<ExSingleIdTableIdentifier>("user_public_key_table", get_rk(10)).await?;
    let u64_singleton_table = store.init_std_table_prepare_only::<ExU64TableIdentifier>("u64_singleton_table", get_rk(11)).await?;
    let u64_counter_singleton_table = store.init_no_tablet_table_prepare_only::<ExU64CounterTableIdentifier>("u64_counter_singleton_table", get_rk(12)).await?;
    let contract_state_tree_height_table = store.init_std_table_prepare_only::<ExSingleIdTableIdentifier>("contract_state_tree_height_table", get_rk(13)).await?;
    let checkpoint_id_to_pending_id_table = store.init_std_table_prepare_only::<ExU64TableIdentifier>("checkpoint_id_to_pending_id_table", get_rk(14)).await?;
    let pending_id_to_checkpoint_id_table = store.init_std_table_prepare_only::<ExU64TableIdentifier>("pending_id_to_checkpoint_id_table", get_rk(15)).await?;
    let pending_id_to_pending_proc_id_table = store.init_std_table_prepare_only::<ExBiDirectionalU64U128MappingTableIdentifier>("pending_id_to_pending_proc_id_table", get_rk(16)).await?;
    let realm_rewards_tree_node_key_table = store.init_std_table_prepare_only::<ExSingleIdTableIdentifier>("realm_rewards_tree_node_key_table", get_rk(17)).await?;
    // mappings
    let public_key_hash_to_user_ids_table = store.init_std_table_prepare_only::<ExHashToManyIdsTableIdentifier>("public_key_hash_to_user_ids_table", get_rk(18)).await?;
    // start trees
    let global_user_tree_table = store.init_zero_id_merkle_table_prepare_only("global_user_tree_table", get_rk(19), N::GLOBAL_USER_TREE_HEIGHT).await?;
    let user_contract_tree_table = store.init_std_table_prepare_only::<ExSingleIdMerkleTableIdentifier>("user_contract_tree_table", get_rk(20)).await?;
    let contract_state_tree_table = store.init_std_table_prepare_only::<ExDoubleIdMerkleTableIdentifier>("contract_state_tree_table", get_rk(21)).await?;
    let global_checkpoint_tree_table = store.init_zero_id_merkle_table_prepare_only("global_checkpoint_tree_table", get_rk(22), N::CHECKPOINT_TREE_HEIGHT).await?;
    // start reward tree table
    let guta_reward_tag_tree_table = store.init_std_table_prepare_only::<ExTagTreeTableIdentifier>("guta_reward_tag_tree_table", get_rk(23)).await?;
    // added tables for completeness
    let user_registration_tree_table = store.init_zero_id_merkle_table_prepare_only("user_registration_tree_table", get_rk(24), N::GLOBAL_USER_TREE_HEIGHT).await?;
    let validator_tree_table = store.init_zero_id_merkle_table_prepare_only("validator_tree_table", get_rk(33), 20u8).await?;
    let global_contract_tree_table = store.init_zero_id_merkle_table_prepare_only("global_contract_tree_table", get_rk(25), N::GLOBAL_CONTRACT_TREE_HEIGHT).await?;
    let contract_function_tree_table = store.init_std_table_prepare_only::<ExSingleIdMerkleTableIdentifier>("contract_function_tree_table", get_rk(26)).await?;
    let contract_leaf_table = store.init_std_table_prepare_only::<ExSingleIdTableIdentifier>("contract_leaf_table", get_rk(27)).await?;
    let contract_code_definition_table = store.init_std_table_prepare_only::<ExSingleIdTableIdentifier>("contract_code_definition_table", get_rk(28)).await?;
    let checkpoint_zk_proof_and_transition_table = store.init_std_table_prepare_only::<ExKivTableIdentifier>("checkpoint_zk_proof_and_transition_table", get_rk(29)).await?;
    // IMT tables
    let imt_leaf_table = store.init_std_table_prepare_only::<ExIMTLeafTableIdentifier>("imt_leaf_table", get_rk(30)).await?;
    let imt_key_index_table = store.init_std_table_prepare_only::<ExIMTKeyIndexTableIdentifier>("imt_key_index_table", get_rk(31)).await?;
    let imt_next_append_index_table = store.init_std_table_prepare_only::<ExIMTNextAppendIndexTableIdentifier>("imt_next_append_index_table", get_rk(32)).await?;

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
        Arc::new(validator_tree_table),
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

pub async fn setup_psy_scylla_database_store_from_connection_string<N: QNetworkDatabaseTypes>(
    keyspace: &str,
    connection_string: &str,
    create_tables: bool,
) -> anyhow::Result<ScyllaUnifiedPsyStore<N, N::QHash, N::HasherBase>> {
    if connection_string.is_empty() {
        anyhow::bail!("Scylla Connection string is empty");
    }
    let addresses = connection_string.split(",").map(|s| s.to_string()).collect::<Vec<String>>();

    let scylla_db = ScyllaCoreStore::new(0, 0, keyspace.to_string(), &addresses).await?;

    if create_tables {
        // Processor nodes: create tables then prepare statements
        setup_psy_scylla_database_store::<N>(Arc::new(scylla_db)).await
    } else {
        // Edge nodes: only prepare statements, assume tables exist
        prepare_psy_scylla_database_store::<N>(Arc::new(scylla_db)).await
    }
}
