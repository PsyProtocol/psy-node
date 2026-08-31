use std::sync::Arc;

use parth_core::{
    data::hash::{hash256::Hash256, merkle_node_key::SimpleMerkleNodeKey},
    protocol::core_types::{QNetworkHashTypes, QNetworkTreeConstants},
};
use parth_crypto::hash::sha256::CoreSha256Hasher;
use psy_node_core::store::traits::core_db::{
    CoreDatabaseBidirectionalMappingReader, CoreDatabaseBidirectionalMappingWriter,
    CoreDatabaseBidirectionalU64U128MappingReader, CoreDatabaseBidirectionalU64U128MappingWriter,
    CoreDatabaseBlobPairDeleter, CoreDatabaseBlobPairVerifier, CoreDatabaseDoubleIdMerkleWriter,
    CoreDatabaseHashToManyIdsWriter, CoreDatabaseHashUserPairDeleter, CoreDatabaseHashUserPairVerifier,
    CoreDatabaseIMTKeyIndexWriter, CoreDatabaseIMTLeafWriter, CoreDatabaseIMTNextAppendIndexWriter,
    CoreDatabaseImtKeyDeleter, CoreDatabaseImtKeyVerifier, CoreDatabaseImtLeafDeleter,
    CoreDatabaseImtLeafVerifier, CoreDatabaseImtNextAppendIndexDeleter, CoreDatabaseImtNextAppendIndexVerifier,
    CoreDatabaseKivWriter, CoreDatabaseMerkleDeleter, CoreDatabaseMerkleVerifier,
    CoreDatabaseObjectCheckpointDeleter, CoreDatabaseObjectCheckpointVerifier, CoreDatabaseObjectIdDeleter,
    CoreDatabaseObjectIdVerifier, CoreDatabasePendingIdPartitionDeleter, CoreDatabasePendingIdPartitionVerifier,
    CoreDatabaseSingleIdCheckpointedWriter, CoreDatabaseSingleIdMerkleWriter, CoreDatabaseTagTreeReader,
    CoreDatabaseTagTreeWriter, CoreDatabaseTreeMerkleDeleter, CoreDatabaseTreeMerkleVerifier,
    CoreDatabaseTreeSubtreeMerkleDeleter, CoreDatabaseTreeSubtreeMerkleVerifier, CoreDatabaseU64U128PairDeleter,
    CoreDatabaseU64U128PairVerifier, CoreDatabaseU64Writer, CoreDatabaseZeroIdMerkleWriter,
};
use psy_node_scylla::{
    core::ScyllaCoreStore,
    psy_setup::{setup_psy_scylla_database_store, ScyllaUnifiedPsyStore},
};
use scylla::client::{session::Session, session_builder::SessionBuilder};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

type ExHash = Hash256;
type ExHasher = CoreSha256Hasher;
type ScyllaTestStore = ScyllaCoreStore<ExHash, ExHasher>;
type ScyllaUnifiedStore = ScyllaUnifiedPsyStore<SimpleTestNetworkConfig, ExHash, ExHasher>;

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

const SCYLLA_NODE: &str = "127.0.0.1:9042";

async fn drop_keyspaces(session: &Session, keyspace: &str) -> anyhow::Result<()> {
    session.query_unpaged(format!("DROP KEYSPACE IF EXISTS {keyspace}"), &[]).await?;
    session.await_schema_agreement().await?;
    session.query_unpaged(format!("DROP KEYSPACE IF EXISTS {keyspace}_no_tablet"), &[]).await?;
    session.await_schema_agreement().await?;
    Ok(())
}

async fn setup_store(keyspace: &str) -> anyhow::Result<ScyllaUnifiedStore> {
    let session = SessionBuilder::new().known_nodes([SCYLLA_NODE]).build().await?;
    drop_keyspaces(&session, keyspace).await?;
    let scylla_db = ScyllaTestStore::new(0, 0, keyspace.to_string(), &[SCYLLA_NODE.to_string()]).await?;
    setup_psy_scylla_database_store::<SimpleTestNetworkConfig>(Arc::new(scylla_db)).await
}

async fn cleanup_store(db: &ScyllaUnifiedStore) -> anyhow::Result<()> {
    drop_keyspaces(&db.store.session, &db.store.keyspace).await
}

#[tokio::test]
#[ignore = "database slow"]
async fn delete_apis_accept_empty_and_missing_keys() -> anyhow::Result<()> {
    let db = setup_store("psy_del_empty_missing").await?;
    let backend = db.store.as_ref();

    backend.db_delete_many_object_ids(db.checkpoint_leaf_table.as_ref(), &[]).await?;
    backend.db_delete_many_object_checkpoint(db.checkpointed_object_table.as_ref(), &[]).await?;
    backend.db_delete_many_merkle_nodes(db.global_checkpoint_tree_table.as_ref(), &[]).await?;
    backend.db_delete_many_tree_merkle_nodes(db.user_contract_tree_table.as_ref(), &[]).await?;
    backend.db_delete_many_tree_subtree_merkle_nodes(db.contract_state_tree_table.as_ref(), &[]).await?;
    backend.db_delete_many_imt_leaves(db.imt_leaf_table.as_ref(), &[]).await?;
    backend.db_delete_many_imt_keys(db.imt_key_index_table.as_ref(), &[]).await?;
    backend.db_delete_many_imt_next_append_indexes(db.imt_next_append_index_table.as_ref(), &[]).await?;
    backend.db_delete_many_hash_user_pairs(db.public_key_hash_to_user_ids_table.as_ref(), &[]).await?;
    backend.db_delete_many_blob_pairs(db.checkpoint_root_to_checkpoint_id_table.as_ref(), &[]).await?;
    backend.db_delete_many_u64_u128_pairs(db.pending_id_to_pending_proc_id_table.as_ref(), &[]).await?;
    backend.db_delete_many_pending_id_partitions(db.guta_reward_tag_tree_table.as_ref(), &[]).await?;

    backend.db_delete_many_object_ids(db.checkpoint_leaf_table.as_ref(), &[1]).await?;
    backend.db_delete_many_object_checkpoint(db.checkpointed_object_table.as_ref(), &[(1, 2)]).await?;
    backend.db_delete_many_merkle_nodes(db.global_checkpoint_tree_table.as_ref(), &[(1, 2, 3)]).await?;
    backend.db_delete_many_tree_merkle_nodes(db.user_contract_tree_table.as_ref(), &[(1, 2, 3, 4)]).await?;
    backend.db_delete_many_tree_subtree_merkle_nodes(db.contract_state_tree_table.as_ref(), &[(1, 2, 3, 4, 5)]).await?;
    backend.db_delete_many_imt_leaves(db.imt_leaf_table.as_ref(), &[(1, 2, 3, 4)]).await?;
    backend.db_delete_many_imt_keys(db.imt_key_index_table.as_ref(), &[(1, 2, 3, vec![4])]).await?;
    backend.db_delete_many_imt_next_append_indexes(db.imt_next_append_index_table.as_ref(), &[(1, 2)]).await?;
    backend.db_delete_many_hash_user_pairs(db.public_key_hash_to_user_ids_table.as_ref(), &[(Hash256::default(), 1)]).await?;
    backend.db_delete_many_blob_pairs(db.checkpoint_root_to_checkpoint_id_table.as_ref(), &[(vec![1], vec![2])]).await?;
    backend.db_delete_many_u64_u128_pairs(db.pending_id_to_pending_proc_id_table.as_ref(), &[(1, 2)]).await?;
    backend.db_delete_many_pending_id_partitions(db.guta_reward_tag_tree_table.as_ref(), &[1]).await?;

    assert!(backend.db_get_existing_object_ids(db.checkpoint_leaf_table.as_ref(), &[1]).await?.is_empty());
    assert!(backend.db_get_existing_object_checkpoints(db.checkpointed_object_table.as_ref(), &[(1, 2)]).await?.is_empty());
    assert!(backend.db_get_existing_merkle_nodes(db.global_checkpoint_tree_table.as_ref(), &[(1, 2, 3)]).await?.is_empty());
    assert!(backend.db_get_existing_tree_merkle_nodes(db.user_contract_tree_table.as_ref(), &[(1, 2, 3, 4)]).await?.is_empty());
    assert!(backend.db_get_existing_tree_subtree_merkle_nodes(db.contract_state_tree_table.as_ref(), &[(1, 2, 3, 4, 5)]).await?.is_empty());
    assert!(backend.db_get_existing_imt_leaves(db.imt_leaf_table.as_ref(), &[(1, 2, 3, 4)]).await?.is_empty());
    assert!(backend.db_get_existing_imt_keys(db.imt_key_index_table.as_ref(), &[(1, 2, 3, vec![4])]).await?.is_empty());
    assert!(backend.db_get_existing_imt_next_append_indexes(db.imt_next_append_index_table.as_ref(), &[(1, 2)]).await?.is_empty());
    assert!(backend.db_get_existing_hash_user_pairs(db.public_key_hash_to_user_ids_table.as_ref(), &[(Hash256::default(), 1)]).await?.is_empty());
    assert!(backend.db_get_blob_pair_presence(db.checkpoint_root_to_checkpoint_id_table.as_ref(), &[(vec![1], vec![2])]).await?.is_empty());
    assert!(backend.db_get_u64_u128_pair_presence(db.pending_id_to_pending_proc_id_table.as_ref(), &[(1, 2)]).await?.is_empty());
    assert!(backend.db_get_existing_pending_id_partitions(db.guta_reward_tag_tree_table.as_ref(), &[1]).await?.is_empty());

    cleanup_store(&db).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "database slow"]
async fn object_ids_delete_removes_only_selected_ids() -> anyhow::Result<()> {
    let db = setup_store("psy_del_object_ids").await?;
    let backend = db.store.as_ref();

    backend.db_insert_one_kiv(db.checkpoint_leaf_table.as_ref(), 7, &11_u64).await?;
    backend.db_insert_one_kiv(db.checkpoint_leaf_table.as_ref(), 8, &12_u64).await?;
    backend.db_set_u64_value(db.checkpoint_id_to_pending_id_table.as_ref(), 7, 11).await?;
    backend.db_set_u64_value(db.checkpoint_id_to_pending_id_table.as_ref(), 8, 12).await?;

    assert_eq!(backend.db_get_existing_object_ids(db.checkpoint_leaf_table.as_ref(), &[7, 8]).await?, vec![7, 8]);
    assert_eq!(backend.db_get_existing_object_ids(db.checkpoint_id_to_pending_id_table.as_ref(), &[7, 8]).await?, vec![7, 8]);

    for _ in 0..2 {
        backend.db_delete_many_object_ids(db.checkpoint_leaf_table.as_ref(), &[7, 7, 999]).await?;
        backend.db_delete_many_object_ids(db.checkpoint_id_to_pending_id_table.as_ref(), &[7, 7, 999]).await?;
    }

    assert!(backend.db_get_existing_object_ids(db.checkpoint_leaf_table.as_ref(), &[7, 999]).await?.is_empty());
    assert_eq!(backend.db_get_existing_object_ids(db.checkpoint_leaf_table.as_ref(), &[8]).await?, vec![8]);
    assert!(backend.db_get_existing_object_ids(db.checkpoint_id_to_pending_id_table.as_ref(), &[7, 999]).await?.is_empty());
    assert_eq!(backend.db_get_existing_object_ids(db.checkpoint_id_to_pending_id_table.as_ref(), &[8]).await?, vec![8]);

    cleanup_store(&db).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "database slow"]
async fn object_checkpoint_delete_removes_only_exact_checkpoint() -> anyhow::Result<()> {
    let db = setup_store("psy_del_object_checkpoint").await?;
    let backend = db.store.as_ref();

    backend.db_insert_one_single_checkpointed_object(db.checkpointed_object_table.as_ref(), 5, 13, &17_u64).await?;
    backend.db_insert_one_single_checkpointed_object(db.checkpointed_object_table.as_ref(), 5, 14, &18_u64).await?;
    backend.db_insert_one_single_checkpointed_object(db.checkpointed_object_table.as_ref(), 6, 13, &19_u64).await?;

    assert_eq!(
        backend.db_get_existing_object_checkpoints(db.checkpointed_object_table.as_ref(), &[(5, 13), (5, 14), (6, 13)]).await?,
        vec![(5, 13), (5, 14), (6, 13)]
    );

    for _ in 0..2 {
        backend.db_delete_many_object_checkpoint(db.checkpointed_object_table.as_ref(), &[(5, 13), (5, 13), (5, 14)]).await?;
    }

    assert!(backend.db_get_existing_object_checkpoints(db.checkpointed_object_table.as_ref(), &[(5, 13), (5, 14)]).await?.is_empty());
    assert_eq!(backend.db_get_existing_object_checkpoints(db.checkpointed_object_table.as_ref(), &[(6, 13)]).await?, vec![(6, 13)]);

    cleanup_store(&db).await?;
    Ok(())
}


#[tokio::test]
#[ignore = "database slow"]
async fn object_id_preserves_u64_max_identity_through_delete() -> anyhow::Result<()> {
    let db = setup_store("psy_del_object_id_u64_max").await?;
    let backend = db.store.as_ref();
    let adjacent_id = u64::MAX - 1;

    backend.db_insert_one_kiv(db.checkpoint_leaf_table.as_ref(), u64::MAX, &1_u64).await?;
    backend.db_insert_one_kiv(db.checkpoint_leaf_table.as_ref(), adjacent_id, &2_u64).await?;
    assert_eq!(
        backend.db_get_existing_object_ids(db.checkpoint_leaf_table.as_ref(), &[u64::MAX, adjacent_id]).await?,
        vec![u64::MAX, adjacent_id]
    );

    backend.db_delete_many_object_ids(db.checkpoint_leaf_table.as_ref(), &[u64::MAX]).await?;

    assert!(backend.db_get_existing_object_ids(db.checkpoint_leaf_table.as_ref(), &[u64::MAX]).await?.is_empty());
    assert_eq!(backend.db_get_existing_object_ids(db.checkpoint_leaf_table.as_ref(), &[adjacent_id]).await?, vec![adjacent_id]);

    cleanup_store(&db).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "database slow"]
async fn pending_id_preserves_u64_max_identity_through_delete() -> anyhow::Result<()> {
    let db = setup_store("psy_del_pending_id_u64_max").await?;
    let backend = db.store.as_ref();
    let adjacent_id = u64::MAX - 1;

    backend.db_set_u64_value(db.checkpoint_id_to_pending_id_table.as_ref(), u64::MAX, 11).await?;
    backend.db_set_u64_value(db.checkpoint_id_to_pending_id_table.as_ref(), adjacent_id, 12).await?;
    assert_eq!(
        backend
            .db_get_existing_object_ids(db.checkpoint_id_to_pending_id_table.as_ref(), &[u64::MAX, adjacent_id])
            .await?,
        vec![u64::MAX, adjacent_id]
    );

    backend.db_delete_many_object_ids(db.checkpoint_id_to_pending_id_table.as_ref(), &[u64::MAX]).await?;

    assert!(backend
        .db_get_existing_object_ids(db.checkpoint_id_to_pending_id_table.as_ref(), &[u64::MAX])
        .await?
        .is_empty());
    assert_eq!(
        backend.db_get_existing_object_ids(db.checkpoint_id_to_pending_id_table.as_ref(), &[adjacent_id]).await?,
        vec![adjacent_id]
    );

    cleanup_store(&db).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "database slow"]
async fn merkle_zero_single_double_delete_removes_exact_scope() -> anyhow::Result<()> {
    let db = setup_store("psy_del_merkle_scope").await?;
    let backend = db.store.as_ref();
    let node = SimpleMerkleNodeKey { level: 3, index: 9 };
    let hash = Hash256::default();

    backend.db_insert_zero_id_merkle_node(db.global_checkpoint_tree_table.as_ref(), 13, &node, &hash).await?;
    backend.db_insert_zero_id_merkle_node(db.global_checkpoint_tree_table.as_ref(), 14, &node, &hash).await?;
    backend.db_insert_single_id_merkle_node(db.user_contract_tree_table.as_ref(), 13, 2, node, &hash).await?;
    backend.db_insert_single_id_merkle_node(db.user_contract_tree_table.as_ref(), 14, 2, node, &hash).await?;
    backend.db_insert_double_id_merkle_node(db.contract_state_tree_table.as_ref(), 13, 2, 4, node, &hash).await?;
    backend.db_insert_double_id_merkle_node(db.contract_state_tree_table.as_ref(), 14, 2, 4, node, &hash).await?;

    assert_eq!(
        backend.db_get_existing_merkle_nodes(db.global_checkpoint_tree_table.as_ref(), &[(3, 9, 13), (3, 9, 14)]).await?,
        vec![(3, 9, 13), (3, 9, 14)]
    );
    assert_eq!(
        backend.db_get_existing_tree_merkle_nodes(db.user_contract_tree_table.as_ref(), &[(2, 3, 9, 13), (2, 3, 9, 14)]).await?,
        vec![(2, 3, 9, 13), (2, 3, 9, 14)]
    );
    assert_eq!(
        backend.db_get_existing_tree_subtree_merkle_nodes(db.contract_state_tree_table.as_ref(), &[(2, 4, 3, 9, 13), (2, 4, 3, 9, 14)]).await?,
        vec![(2, 4, 3, 9, 13), (2, 4, 3, 9, 14)]
    );

    backend.db_delete_many_merkle_nodes(db.global_checkpoint_tree_table.as_ref(), &[(3, 9, 13)]).await?;
    backend.db_delete_many_tree_merkle_nodes(db.user_contract_tree_table.as_ref(), &[(2, 3, 9, 13)]).await?;
    backend.db_delete_many_tree_subtree_merkle_nodes(db.contract_state_tree_table.as_ref(), &[(2, 4, 3, 9, 13)]).await?;

    assert_eq!(
        backend.db_get_existing_merkle_nodes(db.global_checkpoint_tree_table.as_ref(), &[(3, 9, 13), (3, 9, 14)]).await?,
        vec![(3, 9, 14)]
    );
    assert_eq!(
        backend.db_get_existing_tree_merkle_nodes(db.user_contract_tree_table.as_ref(), &[(2, 3, 9, 13), (2, 3, 9, 14)]).await?,
        vec![(2, 3, 9, 14)]
    );
    assert_eq!(
        backend.db_get_existing_tree_subtree_merkle_nodes(db.contract_state_tree_table.as_ref(), &[(2, 4, 3, 9, 13), (2, 4, 3, 9, 14)]).await?,
        vec![(2, 4, 3, 9, 14)]
    );

    cleanup_store(&db).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "database slow"]
async fn imt_leaf_key_index_next_index_delete_removes_exact_scope() -> anyhow::Result<()> {
    let db = setup_store("psy_del_imt_scope").await?;
    let backend = db.store.as_ref();

    backend.db_insert_imt_leaf(db.imt_leaf_table.as_ref(), 1, 2, 3, 13, &[0; 32], &[1; 32], &[2; 32], &[3; 32], 4).await?;
    backend.db_insert_imt_leaf(db.imt_leaf_table.as_ref(), 1, 2, 4, 13, &[0; 32], &[1; 32], &[2; 32], &[3; 32], 4).await?;
    backend.db_insert_imt_key_index(db.imt_key_index_table.as_ref(), 1, 2, 3, &[4; 32], &[5; 32], 13, 6).await?;
    backend.db_insert_imt_key_index(db.imt_key_index_table.as_ref(), 1, 2, 3, &[6; 32], &[7; 32], 13, 6).await?;
    backend.db_insert_imt_next_append_index(db.imt_next_append_index_table.as_ref(), 1, 2, 7).await?;
    backend.db_insert_imt_next_append_index(db.imt_next_append_index_table.as_ref(), 1, 3, 8).await?;

    assert_eq!(
        backend.db_get_existing_imt_leaves(db.imt_leaf_table.as_ref(), &[(1, 2, 3, 13), (1, 2, 4, 13)]).await?,
        vec![(1, 2, 3, 13), (1, 2, 4, 13)]
    );
    assert_eq!(
        backend.db_get_existing_imt_keys(db.imt_key_index_table.as_ref(), &[(1, 2, 3, vec![4; 32]), (1, 2, 3, vec![6; 32])]).await?,
        vec![(1, 2, 3, vec![4; 32]), (1, 2, 3, vec![6; 32])]
    );
    assert_eq!(
        backend.db_get_existing_imt_next_append_indexes(db.imt_next_append_index_table.as_ref(), &[(1, 2), (1, 3)]).await?,
        vec![(1, 2), (1, 3)]
    );

    backend.db_delete_many_imt_leaves(db.imt_leaf_table.as_ref(), &[(1, 2, 3, 13)]).await?;
    backend.db_delete_many_imt_keys(db.imt_key_index_table.as_ref(), &[(1, 2, 3, vec![4; 32])]).await?;
    backend.db_delete_many_imt_next_append_indexes(db.imt_next_append_index_table.as_ref(), &[(1, 2)]).await?;

    assert_eq!(
        backend.db_get_existing_imt_leaves(db.imt_leaf_table.as_ref(), &[(1, 2, 3, 13), (1, 2, 4, 13)]).await?,
        vec![(1, 2, 4, 13)]
    );
    assert_eq!(
        backend.db_get_existing_imt_keys(db.imt_key_index_table.as_ref(), &[(1, 2, 3, vec![4; 32]), (1, 2, 3, vec![6; 32])]).await?,
        vec![(1, 2, 3, vec![6; 32])]
    );
    assert_eq!(
        backend.db_get_existing_imt_next_append_indexes(db.imt_next_append_index_table.as_ref(), &[(1, 2), (1, 3)]).await?,
        vec![(1, 3)]
    );

    cleanup_store(&db).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "database slow"]
async fn hash_user_pair_delete_removes_only_selected_pair() -> anyhow::Result<()> {
    let db = setup_store("psy_del_hash_user_pair").await?;
    let backend = db.store.as_ref();
    let hash = Hash256::default();

    backend.db_insert_one_hash_to_u64(db.public_key_hash_to_user_ids_table.as_ref(), hash, 23).await?;
    backend.db_insert_one_hash_to_u64(db.public_key_hash_to_user_ids_table.as_ref(), hash, 24).await?;

    assert_eq!(
        backend.db_get_existing_hash_user_pairs(db.public_key_hash_to_user_ids_table.as_ref(), &[(hash, 23), (hash, 24)]).await?,
        vec![(hash, 23), (hash, 24)]
    );

    for _ in 0..2 {
        backend.db_delete_many_hash_user_pairs(db.public_key_hash_to_user_ids_table.as_ref(), &[(hash, 23), (hash, 23), (hash, 99)]).await?;
    }

    assert!(backend.db_get_existing_hash_user_pairs(db.public_key_hash_to_user_ids_table.as_ref(), &[(hash, 23), (hash, 99)]).await?.is_empty());
    assert_eq!(backend.db_get_existing_hash_user_pairs(db.public_key_hash_to_user_ids_table.as_ref(), &[(hash, 24)]).await?, vec![(hash, 24)]);

    cleanup_store(&db).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "database slow"]
async fn blob_pair_delete_removes_both_physical_directions() -> anyhow::Result<()> {
    let db = setup_store("psy_del_blob_pair").await?;
    let backend = db.store.as_ref();
    let blob_pair = (17_u64, Hash256::default());
    let blob_keys = (blob_pair.0.psy_ser_to_bytes_vec()?, blob_pair.1.psy_ser_to_bytes_vec()?);

    backend.db_insert_pair(db.checkpoint_root_to_checkpoint_id_table.as_ref(), blob_pair.0, blob_pair.1).await?;

    let presence = backend.db_get_blob_pair_presence(db.checkpoint_root_to_checkpoint_id_table.as_ref(), &[blob_keys.clone()]).await?;
    assert_eq!((presence[0].forward_present, presence[0].reverse_present), (true, true));
    assert_eq!(
        backend.db_select_one_by_k1::<u64, Hash256>(db.checkpoint_root_to_checkpoint_id_table.as_ref(), &blob_pair.0).await?,
        Some(blob_pair.1)
    );
    assert_eq!(
        backend.db_select_one_by_k2::<u64, Hash256>(db.checkpoint_root_to_checkpoint_id_table.as_ref(), &blob_pair.1).await?,
        Some(blob_pair.0)
    );

    backend.db_delete_many_blob_pairs(db.checkpoint_root_to_checkpoint_id_table.as_ref(), &[blob_keys.clone()]).await?;

    assert!(backend.db_get_blob_pair_presence(db.checkpoint_root_to_checkpoint_id_table.as_ref(), &[blob_keys]).await?.is_empty());
    assert_eq!(
        backend.db_select_one_by_k1::<u64, Hash256>(db.checkpoint_root_to_checkpoint_id_table.as_ref(), &blob_pair.0).await?,
        None
    );
    assert_eq!(
        backend.db_select_one_by_k2::<u64, Hash256>(db.checkpoint_root_to_checkpoint_id_table.as_ref(), &blob_pair.1).await?,
        None
    );

    cleanup_store(&db).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "database slow"]
async fn u64_u128_pair_delete_removes_both_physical_directions() -> anyhow::Result<()> {
    let db = setup_store("psy_del_u64_u128_pair").await?;
    let backend = db.store.as_ref();
    let pending_pair = (17_u64, 29_u128);

    backend.db_insert_u64_u128_mapping_pair(db.pending_id_to_pending_proc_id_table.as_ref(), pending_pair.0, pending_pair.1).await?;

    let presence = backend.db_get_u64_u128_pair_presence(db.pending_id_to_pending_proc_id_table.as_ref(), &[pending_pair]).await?;
    assert_eq!((presence[0].forward_present, presence[0].reverse_present), (true, true));
    assert_eq!(
        backend.db_select_one_u128_value_by_u64(db.pending_id_to_pending_proc_id_table.as_ref(), pending_pair.0).await?,
        Some(pending_pair.1)
    );
    assert_eq!(
        backend.db_select_one_u64_key_by_u128(db.pending_id_to_pending_proc_id_table.as_ref(), pending_pair.1).await?,
        Some(pending_pair.0)
    );

    backend.db_delete_many_u64_u128_pairs(db.pending_id_to_pending_proc_id_table.as_ref(), &[pending_pair]).await?;

    assert!(backend.db_get_u64_u128_pair_presence(db.pending_id_to_pending_proc_id_table.as_ref(), &[pending_pair]).await?.is_empty());
    assert_eq!(
        backend.db_select_one_u128_value_by_u64(db.pending_id_to_pending_proc_id_table.as_ref(), pending_pair.0).await?,
        None
    );
    assert_eq!(
        backend.db_select_one_u64_key_by_u128(db.pending_id_to_pending_proc_id_table.as_ref(), pending_pair.1).await?,
        None
    );

    cleanup_store(&db).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "database slow"]
async fn tag_tree_partition_delete_removes_only_selected_partition() -> anyhow::Result<()> {
    let db = setup_store("psy_del_tag_partition").await?;
    let backend = db.store.as_ref();
    let root = SimpleMerkleNodeKey::new_root();
    let child = SimpleMerkleNodeKey { level: 1, index: 1 };
    let tag = Hash256::default();
    let value = Hash256::default();

    backend.db_set_tag_tree_tag_value(db.guta_reward_tag_tree_table.as_ref(), 41, &root, &tag, &value).await?;
    backend.db_set_tag_tree_tag_value(db.guta_reward_tag_tree_table.as_ref(), 41, &child, &tag, &value).await?;
    backend.db_set_tag_tree_tag_value(db.guta_reward_tag_tree_table.as_ref(), 42, &root, &tag, &value).await?;

    assert_eq!(
        backend.db_get_existing_pending_id_partitions(db.guta_reward_tag_tree_table.as_ref(), &[41, 42]).await?,
        vec![41, 42]
    );
    assert!(backend.db_get_tag_tree_node_value(db.guta_reward_tag_tree_table.as_ref(), 41, &root).await?.is_some());

    backend.db_delete_many_pending_id_partitions(db.guta_reward_tag_tree_table.as_ref(), &[41]).await?;

    assert_eq!(
        backend.db_get_existing_pending_id_partitions(db.guta_reward_tag_tree_table.as_ref(), &[41, 42]).await?,
        vec![42]
    );
    assert_eq!(backend.db_get_tag_tree_node_value(db.guta_reward_tag_tree_table.as_ref(), 41, &root).await?, None);
    assert_eq!(backend.db_get_tag_tree_node_value(db.guta_reward_tag_tree_table.as_ref(), 41, &child).await?, None);
    assert!(backend.db_get_tag_tree_node_value(db.guta_reward_tag_tree_table.as_ref(), 42, &root).await?.is_some());

    cleanup_store(&db).await?;
    Ok(())
}
