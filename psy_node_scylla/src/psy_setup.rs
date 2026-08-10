use std::sync::Arc;

use parth_core::{
    data::db::table::QDatabaseTableRoutingKey,
    protocol::core_types::{Q256BitHash, QNetworkDatabaseTypes},
};
use psy_node_core::{
    psy_core_db::v3_implementation::full::PsyUnifiedCoreDatabaseStore,
    store::{
        branch_exact_schema::AuthorityScope,
        realm_processor_startup::{
            authorize_realm_processor_startup, RealmProcessorFreshRunPermit,
            RealmProcessorStartupAuthorization, RealmProcessorStartupError,
            RealmProcessorStartupLineage, RealmProcessorStartupMode,
            RealmProcessorStartupPreflightProvider,
        },
        realm_processor_branch_exact_runtime::RealmBranchExactCommitRuntimeInstaller,
    },
};
use rand::{rngs::OsRng, RngCore};

use crate::{
    core::ScyllaCoreStore,
    rollback::{
        BranchExactDeploymentNoTabletKeyspace, BranchExactSchemaSetupMode,
        BranchExactSchemaSetupRequest, BranchExactWriterAuthorityKey,
        BranchExactWriterReadState, PendingQueueSidecarSetupMode,
        ScyllaBranchExactWriterLifecycleStore,
    },
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

/// Coordinator processor/edge composition root. The canonical-head control
/// table is deliberately initialized here instead of in the generic 32-table
/// setup, so Realm databases and Realm Edge processes do not acquire
/// Coordinator authority state. With `create_tables=false`, Coordinator Edge
/// only prepares access to a schema already created by the processor rollout.
pub async fn setup_coordinator_psy_scylla_database_store_from_connection_string<
    N: QNetworkDatabaseTypes,
>(
    keyspace: &str,
    connection_string: &str,
    create_tables: bool,
) -> anyhow::Result<ScyllaUnifiedPsyStore<N, N::QHash, N::HasherBase>> {
    setup_coordinator_psy_scylla_database_store_with_branch_exact_schema::<N>(
        keyspace,
        connection_string,
        create_tables,
        BranchExactSchemaSetupMode::Disabled,
    )
    .await
}

/// Explicit Coordinator composition root for the default-off branch-exact
/// setup gate. The branch schema is never created here; a requested mode must
/// already have a durable BACKFILL_VERIFIED lifecycle and exact live schema.
pub async fn setup_coordinator_psy_scylla_database_store_with_branch_exact_schema<
    N: QNetworkDatabaseTypes,
>(
    keyspace: &str,
    connection_string: &str,
    create_tables: bool,
    branch_exact_mode: BranchExactSchemaSetupMode,
) -> anyhow::Result<ScyllaUnifiedPsyStore<N, N::QHash, N::HasherBase>> {
    let db = setup_psy_scylla_database_store_from_connection_string::<N>(
        keyspace,
        connection_string,
        create_tables,
    )
    .await?;
    db.store
        .initialize_coordinator_canonical_head(create_tables)
        .await?;
    db.store
        .initialize_coordinator_rollback_admission(create_tables)
        .await?;
    db.store
        .initialize_branch_exact_schema_setup(
            AuthorityScope::Coordinator,
            branch_exact_mode,
        )
        .await?;
    Ok(db)
}

/// Explicit Realm composition root for branch-exact setup preparation. The
/// generic setup cannot infer Realm identity and therefore cannot enable this
/// path. Existing callers remain default-off.
pub async fn setup_realm_psy_scylla_database_store_with_branch_exact_schema<
    N: QNetworkDatabaseTypes,
>(
    keyspace: &str,
    connection_string: &str,
    create_tables: bool,
    realm_id: u32,
    realm_sub_id: u16,
    branch_exact_mode: BranchExactSchemaSetupMode,
) -> anyhow::Result<ScyllaUnifiedPsyStore<N, N::QHash, N::HasherBase>> {
    if connection_string.is_empty() {
        anyhow::bail!("Scylla Connection string is empty");
    }
    let addresses = connection_string
        .split(',')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let store = Arc::new(
        ScyllaCoreStore::new(
            u64::from(realm_id),
            u64::from(realm_sub_id),
            keyspace.to_owned(),
            &addresses,
        )
        .await?,
    );
    let db = if create_tables {
        setup_psy_scylla_database_store::<N>(store).await?
    } else {
        prepare_psy_scylla_database_store::<N>(store).await?
    };
    db.store
        .initialize_branch_exact_schema_setup(
            AuthorityScope::Realm {
                realm_id,
                realm_sub_id,
            },
            branch_exact_mode,
        )
        .await?;
    db.store
        .initialize_pending_queue_sidecar_setup(
            AuthorityScope::Realm {
                realm_id,
                realm_sub_id,
            },
            PendingQueueSidecarSetupMode::Disabled,
        )
        .await?;
    Ok(db)
}

#[derive(Debug)]
enum ScyllaRealmEdgeStartupAuthorization {
    Disabled,
    BranchExact(RealmProcessorFreshRunPermit),
}

/// DB and its startup authorization remain one value until the caller reaches
/// the real handler composition boundary. Enabled mode cannot be silently
/// downgraded to the legacy handler.
pub struct ScyllaRealmEdgeStartupComposition<N: QNetworkDatabaseTypes> {
    db: ScyllaUnifiedPsyStore<N, N::QHash, N::HasherBase>,
    authorization: ScyllaRealmEdgeStartupAuthorization,
}

impl<N: QNetworkDatabaseTypes> ScyllaRealmEdgeStartupComposition<N> {
    /// Extract the legacy DB only when branch-exact is disabled. The enabled
    /// permit intentionally cannot be separated from this composition and
    /// ignored by a caller that would then construct the legacy handler.
    pub fn into_legacy_db(
        self,
    ) -> anyhow::Result<ScyllaUnifiedPsyStore<N, N::QHash, N::HasherBase>> {
        match self.authorization {
            ScyllaRealmEdgeStartupAuthorization::Disabled => Ok(self.db),
            ScyllaRealmEdgeStartupAuthorization::BranchExact(permit) => anyhow::bail!(
                "REALM_EDGE_BRANCH_EXACT_HANDLER_NOT_INTEGRATED: durable storage preflight passed (permit {}) but the handler route is not installed",
                hex::encode(permit.digest().as_bytes())
            ),
        }
    }
}

/// Default-off Realm Edge storage composition. Enabled mode performs a fresh,
/// read-only full-composite preflight after live schema/backfill and queue
/// sidecar authorization. It deliberately stops before constructing a handler
/// or NATS publisher; h23c4c2b4 must consume the opaque token at that boundary.
pub async fn setup_realm_edge_scylla_startup_composition<
    N: QNetworkDatabaseTypes,
>(
    keyspace: &str,
    connection_string: &str,
    create_tables: bool,
    realm_id: u32,
    realm_sub_id: u16,
    lineage: Option<RealmProcessorStartupLineage>,
) -> anyhow::Result<ScyllaRealmEdgeStartupComposition<N>>
where
    N::QHash: Q256BitHash + Send + Sync + 'static,
    N::HasherBase: Send + Sync + 'static,
{
    let db = setup_realm_psy_scylla_database_store_with_branch_exact_schema::<N>(
        keyspace,
        connection_string,
        create_tables,
        realm_id,
        realm_sub_id,
        BranchExactSchemaSetupMode::Disabled,
    )
    .await?;
    let Some(lineage) = lineage else {
        return Ok(ScyllaRealmEdgeStartupComposition {
            db,
            authorization: ScyllaRealmEdgeStartupAuthorization::Disabled,
        });
    };
    if lineage.realm_id() != realm_id || lineage.realm_sub_id() != realm_sub_id {
        return Err(RealmProcessorStartupError::AuthorityMismatch.into());
    }

    let authority = AuthorityScope::Realm {
        realm_id,
        realm_sub_id,
    };
    let control_keyspace = BranchExactDeploymentNoTabletKeyspace::try_new(
        db.store.no_tablet_keyspace.clone(),
    )?;
    let writer_store = ScyllaBranchExactWriterLifecycleStore::prepare(
        db.store.session.clone(),
        control_keyspace,
    )
    .await?;
    let writer = match writer_store
        .read::<N::QHash>(BranchExactWriterAuthorityKey::new(
            lineage.network(),
            authority,
        ))
        .await?
    {
        BranchExactWriterReadState::Current(writer) => writer,
        BranchExactWriterReadState::Uninitialized => {
            return Err(RealmProcessorStartupError::DurableEvidenceNotVerified(
                "branch-exact writer lifecycle is uninitialized".to_owned(),
            )
            .into())
        }
    };
    if writer.plan().digest().as_bytes()
        != lineage.expected_writer_activation_digest().as_bytes()
    {
        return Err(RealmProcessorStartupError::WriterActivationMismatch.into());
    }
    db.store
        .initialize_branch_exact_schema_setup(
            authority,
            BranchExactSchemaSetupMode::RequireVerified(
                BranchExactSchemaSetupRequest::new(
                    writer.plan().backfill_receipt().clone(),
                ),
            ),
        )
        .await?;
    db.store
        .initialize_pending_queue_sidecar_setup(
            authority,
            PendingQueueSidecarSetupMode::RequireVerified,
        )
        .await?;

    let expectation = lineage.seal_attempt(fresh_startup_nonce())?;
    let provider = db
        .store
        .prepare_realm_processor_startup_preflight(expectation)
        .await?;
    let authorization = authorize_realm_processor_startup(
        RealmProcessorStartupMode::RequireBranchExact(expectation),
        Some(provider.as_ref()),
    )
    .await?;
    let RealmProcessorStartupAuthorization::BranchExact(permit) = authorization
    else {
        return Err(RealmProcessorStartupError::StartupProviderMissing.into());
    };
    Ok(ScyllaRealmEdgeStartupComposition {
        db,
        authorization: ScyllaRealmEdgeStartupAuthorization::BranchExact(permit),
    })
}

/// One indivisible Realm startup composition. Keeping DB, mode and provider
/// together prevents a caller from pairing a provider prepared for one
/// session/Realm with a different authority store.
pub struct ScyllaRealmProcessorStartupComposition<N: QNetworkDatabaseTypes> {
    db: ScyllaUnifiedPsyStore<N, N::QHash, N::HasherBase>,
    startup_mode: RealmProcessorStartupMode,
    startup_preflight: Option<Arc<dyn RealmProcessorStartupPreflightProvider>>,
    commit_runtime_installer:
        Option<Arc<dyn RealmBranchExactCommitRuntimeInstaller<N::QHash>>>,
}

impl<N: QNetworkDatabaseTypes> ScyllaRealmProcessorStartupComposition<N> {
    pub fn into_parts(
        self,
    ) -> (
        ScyllaUnifiedPsyStore<N, N::QHash, N::HasherBase>,
        RealmProcessorStartupMode,
        Option<Arc<dyn RealmProcessorStartupPreflightProvider>>,
        Option<Arc<dyn RealmBranchExactCommitRuntimeInstaller<N::QHash>>>,
    ) {
        (
            self.db,
            self.startup_mode,
            self.startup_preflight,
            self.commit_runtime_installer,
        )
    }
}

/// Default-off Realm Processor composition root. Enabled mode discovers the
/// complete h20 receipt from the operator-pinned durable writer plan, reruns
/// live schema authorization, mints a process-local nonce and returns the
/// provider bound to this exact DB instance.
pub async fn setup_realm_processor_scylla_startup_composition<
    N: QNetworkDatabaseTypes,
>(
    keyspace: &str,
    connection_string: &str,
    create_tables: bool,
    realm_id: u32,
    realm_sub_id: u16,
    lineage: Option<RealmProcessorStartupLineage>,
) -> anyhow::Result<ScyllaRealmProcessorStartupComposition<N>>
where
    N::QHash: Q256BitHash + Send + Sync + 'static,
    N::HasherBase: Send + Sync + 'static,
{
    let db = setup_realm_psy_scylla_database_store_with_branch_exact_schema::<N>(
        keyspace,
        connection_string,
        create_tables,
        realm_id,
        realm_sub_id,
        BranchExactSchemaSetupMode::Disabled,
    )
    .await?;
    let Some(lineage) = lineage else {
        return Ok(ScyllaRealmProcessorStartupComposition {
            db,
            startup_mode: RealmProcessorStartupMode::Disabled,
            startup_preflight: None,
            commit_runtime_installer: None,
        });
    };
    if lineage.realm_id() != realm_id || lineage.realm_sub_id() != realm_sub_id {
        return Err(RealmProcessorStartupError::AuthorityMismatch.into());
    }

    let authority = AuthorityScope::Realm {
        realm_id,
        realm_sub_id,
    };
    let control_keyspace = BranchExactDeploymentNoTabletKeyspace::try_new(
        db.store.no_tablet_keyspace.clone(),
    )?;
    let writer_store = ScyllaBranchExactWriterLifecycleStore::prepare(
        db.store.session.clone(),
        control_keyspace,
    )
    .await?;
    let writer = match writer_store
        .read::<N::QHash>(BranchExactWriterAuthorityKey::new(
            lineage.network(),
            authority,
        ))
        .await?
    {
        BranchExactWriterReadState::Current(writer) => writer,
        BranchExactWriterReadState::Uninitialized => {
            return Err(RealmProcessorStartupError::DurableEvidenceNotVerified(
                "branch-exact writer lifecycle is uninitialized".to_owned(),
            )
            .into())
        }
    };
    if writer.plan().digest().as_bytes()
        != lineage.expected_writer_activation_digest().as_bytes()
    {
        return Err(RealmProcessorStartupError::WriterActivationMismatch.into());
    }
    db.store
        .initialize_branch_exact_schema_setup(
            authority,
            BranchExactSchemaSetupMode::RequireVerified(
                BranchExactSchemaSetupRequest::new(
                    writer.plan().backfill_receipt().clone(),
                ),
            ),
        )
        .await?;
    db.store
        .initialize_pending_queue_sidecar_setup(
            authority,
            PendingQueueSidecarSetupMode::RequireVerified,
        )
        .await?;

    let recovery_expectation = lineage.seal_attempt(fresh_startup_nonce())?;
    db.store
        .recover_realm_processor_startup(recovery_expectation)
        .await?;
    // Recovery admission is never serving authority. A distinct, freshly
    // sampled nonce seals the full post-recovery preflight/run attempt.
    let expectation = lineage.seal_attempt(fresh_startup_nonce_excluding(
        recovery_expectation.startup_nonce(),
    ))?;
    let provider = Arc::new(db
        .store
        .prepare_realm_processor_startup_provider(expectation)
        .await?);
    let startup_preflight: Arc<dyn RealmProcessorStartupPreflightProvider> =
        provider.clone();
    let commit_runtime_installer:
        Arc<dyn RealmBranchExactCommitRuntimeInstaller<N::QHash>> = provider;
    Ok(ScyllaRealmProcessorStartupComposition {
        db,
        startup_mode: RealmProcessorStartupMode::RequireBranchExact(
            expectation,
        ),
        startup_preflight: Some(startup_preflight),
        commit_runtime_installer: Some(commit_runtime_installer),
    })
}

fn fresh_startup_nonce() -> [u8; 32] {
    loop {
        let mut nonce = [0; 32];
        OsRng.fill_bytes(&mut nonce);
        if nonce != [0; 32] {
            return nonce;
        }
    }
}

fn fresh_startup_nonce_excluding(excluded: [u8; 32]) -> [u8; 32] {
    loop {
        let nonce = fresh_startup_nonce();
        if nonce != excluded {
            return nonce;
        }
    }
}

#[cfg(test)]
mod realm_startup_composition_tests {
    use super::*;

    #[test]
    fn edge_composition_is_default_off_full_preflight_and_non_serving() {
        let source = include_str!("psy_setup.rs");
        let composition = source
            .split("pub struct ScyllaRealmEdgeStartupComposition")
            .nth(1)
            .unwrap()
            .split("/// Default-off Realm Edge storage composition")
            .next()
            .unwrap();
        assert!(composition.contains("db:"));
        assert!(composition.contains("authorization:"));
        assert!(!composition.contains("pub db:"));
        assert!(!composition.contains("into_parts"));
        assert!(composition.contains("into_legacy_db"));
        assert!(composition
            .contains("ScyllaRealmEdgeStartupAuthorization::Disabled => Ok(self.db)"));
        assert!(composition
            .contains("ScyllaRealmEdgeStartupAuthorization::BranchExact(permit)"));

        let factory = source
            .split("pub async fn setup_realm_edge_scylla_startup_composition")
            .nth(1)
            .unwrap()
            .split("/// One indivisible Realm startup composition")
            .next()
            .unwrap();
        let disabled = factory.find("let Some(lineage) = lineage else").unwrap();
        let writer = factory
            .find("ScyllaBranchExactWriterLifecycleStore::prepare")
            .unwrap();
        assert!(disabled < writer);
        assert!(factory.contains("ScyllaRealmEdgeStartupAuthorization::Disabled"));
        assert!(factory.contains("expected_writer_activation_digest"));
        assert!(factory.contains("BranchExactSchemaSetupMode::RequireVerified"));
        assert!(factory.contains("PendingQueueSidecarSetupMode::RequireVerified"));
        assert!(factory.contains("prepare_realm_processor_startup_preflight"));
        assert!(factory.contains("authorize_realm_processor_startup"));
        for forbidden in [
            "recover_realm_processor_startup",
            "prepare_realm_edge_durable_publisher",
            "ScyllaRealmUserUpdateDurableRouter::prepare",
            "RealmEdgeHandler",
            "start_realm_edge_rpc_server",
        ] {
            assert!(
                !factory.contains(forbidden),
                "storage admission gained serving capability {forbidden}"
            );
        }
        let public_authorization = [
            "pub enum ScyllaRealmEdge",
            "StartupAuthorization",
        ]
        .concat();
        assert!(!source.contains(&public_authorization));
    }

    #[test]
    fn composition_is_default_off_indivisible_and_receipt_is_discovered() {
        let source = include_str!("psy_setup.rs");
        let composition = source
            .split("pub struct ScyllaRealmProcessorStartupComposition")
            .nth(1)
            .unwrap()
            .split("/// Default-off Realm Processor composition root")
            .next()
            .unwrap();
        assert!(composition.contains("db:"));
        assert!(composition.contains("startup_mode:"));
        assert!(composition.contains("startup_preflight:"));
        assert!(composition.contains("commit_runtime_installer:"));
        assert!(!composition.contains("pub db:"));

        let factory = source
            .split("pub async fn setup_realm_processor_scylla_startup_composition")
            .nth(1)
            .unwrap()
            .split("fn fresh_startup_nonce")
            .next()
            .unwrap();
        let disabled = factory.find("let Some(lineage) = lineage else").unwrap();
        let writer_prepare = factory
            .find("ScyllaBranchExactWriterLifecycleStore::prepare")
            .unwrap();
        assert!(disabled < writer_prepare);
        assert!(factory.contains("RealmProcessorStartupMode::Disabled"));
        assert!(factory.contains("BranchExactWriterReadState::Uninitialized"));
        assert!(
            factory.find("expected_writer_activation_digest").unwrap()
                < factory.find("backfill_receipt().clone()").unwrap()
        );
        assert!(factory.contains("fresh_startup_nonce()"));
        let recovery = factory
            .find("recover_realm_processor_startup(recovery_expectation)")
            .unwrap();
        let queue_ready = factory
            .find("PendingQueueSidecarSetupMode::RequireVerified")
            .unwrap();
        let fresh_run = factory
            .find("fresh_startup_nonce_excluding")
            .unwrap();
        let final_preflight = factory
            .find("prepare_realm_processor_startup_provider(expectation)")
            .unwrap();
        assert!(queue_ready < recovery);
        assert!(recovery < fresh_run && fresh_run < final_preflight);
        assert!(source.contains("PendingQueueSidecarSetupMode::Disabled"));
        assert!(!factory.contains("PendingQueueSidecarDeploymentExecutor::deploy"));
        assert!(factory.contains("RealmBranchExactCommitRuntimeInstaller"));
        assert!(!factory.contains("startup_nonce:"));
    }

    #[test]
    fn production_nonce_is_nonzero_and_fresh_per_attempt() {
        let first = fresh_startup_nonce();
        let second = fresh_startup_nonce();
        assert_ne!(first, [0; 32]);
        assert_ne!(second, [0; 32]);
        assert_ne!(first, second);
        let third = fresh_startup_nonce_excluding(first);
        assert_ne!(third, [0; 32]);
        assert_ne!(third, first);
    }
}
