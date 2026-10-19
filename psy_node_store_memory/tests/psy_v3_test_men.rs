use std::sync::Arc;

use parth_core::{
    data::hash::hash256::Hash256,
    protocol::core_types::{Q256BitHash, QNetworkHashTypes, QNetworkTreeConstants},
};
use parth_crypto::hash::sha256::CoreSha256Hasher;
use psy_node_core::psy_core_db::v3_implementation::{full::PsyUnifiedCoreDatabaseStore, test_helper::ExPsyUnifiedStoreTestHelper};
use psy_node_core::{
    psy_core_db::traits::full::PsyNodeContractStateIMTDatabaseWriter,
    store::traits::core_db::{CoreDatabaseIMTKeyIndexReader, CoreDatabaseIMTKeyIndexWriter, CoreDatabaseIMTLeafWriter},
};
use psy_data::v1::qdata::contract::{encode_imt_key_for_sorting, imt_key_bucket_to_i16, serialize_imt_leaf_ffs_entry_v2};
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
type ExU64CounterTableIdentifier = InMemoryTableIdentifier;
type ExSingleIdTableIdentifier = InMemoryTableIdentifier;
type ExDoubleIdTableIdentifier = InMemoryTableIdentifier;
type ExKivTableIdentifier = InMemoryTableIdentifier;
type ExSingleIdMerkleTableIdentifier = InMemoryTableIdentifier;
type ExDoubleIdMerkleTableIdentifier = InMemoryTableIdentifier;
type ExZeroIdMerkleTableIdentifier = InMemoryTableIdentifier;
type ExTagTreeTableIdentifier = InMemoryTableIdentifier;
type ExHashToManyIdsTableIdentifier = InMemoryTableIdentifier;
type ExImtLeafTableIdentifier = InMemoryTableIdentifier;
type ExImtKeyIndexTableIdentifier = InMemoryTableIdentifier;
type ExImtNextAppendIndexTableIdentifier = InMemoryTableIdentifier;

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
        ExU64CounterTableIdentifier,
        ExSingleIdTableIdentifier,
        ExDoubleIdTableIdentifier,
        ExKivTableIdentifier,
        ExSingleIdMerkleTableIdentifier,
        ExDoubleIdMerkleTableIdentifier,
        ExZeroIdMerkleTableIdentifier,
        ExTagTreeTableIdentifier,
        ExHashToManyIdsTableIdentifier,
        ExImtLeafTableIdentifier,
        ExImtKeyIndexTableIdentifier,
        ExImtNextAppendIndexTableIdentifier,
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
        let global_user_tree_table = Arc::new(InMemoryTableIdentifier::new_treee_with_keyspace(&keyspace, "global_user_tree_table", SimpleTestNetworkConfig::GLOBAL_USER_TREE_HEIGHT));
        let user_contract_tree_table = Arc::new(InMemoryTableIdentifier::new_treee_with_keyspace(&keyspace, "user_contract_tree_table", SimpleTestNetworkConfig::GLOBAL_CONTRACT_TREE_HEIGHT));
        let contract_state_tree_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "contract_state_tree_table"));
        let global_checkpoint_tree_table = Arc::new(InMemoryTableIdentifier::new_treee_with_keyspace(&keyspace, "global_checkpoint_tree_table", SimpleTestNetworkConfig::CHECKPOINT_TREE_HEIGHT));
        // start reward tree table
        let guta_reward_tag_tree_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "guta_reward_tag_tree_table"));
        // added tables for completeness
        let user_registration_tree_table = Arc::new(InMemoryTableIdentifier::new_treee_with_keyspace(&keyspace, "user_registration_tree_table", SimpleTestNetworkConfig::GLOBAL_USER_TREE_HEIGHT));
        let validator_tree_table = Arc::new(InMemoryTableIdentifier::new_treee_with_keyspace(&keyspace, "validator_tree_table", psy_data::guta::realm_finalize::VALIDATOR_TREE_HEIGHT as u8));
        let global_contract_tree_table = Arc::new(InMemoryTableIdentifier::new_treee_with_keyspace(&keyspace, "global_contract_tree_table", SimpleTestNetworkConfig::GLOBAL_CONTRACT_TREE_HEIGHT));
        let contract_function_tree_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "contract_function_tree_table"));
        let contract_leaf_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "contract_leaf_table"));
        let contract_code_definition_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "contract_code_definition_table"));
        let checkpoint_zk_proof_and_transition_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "checkpoint_zk_proof_and_transition_table"));

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

#[tokio::test]
async fn torn_pending_allocation_falls_back_then_skips_abandoned_id() -> anyhow::Result<()> {
    let db = Arc::new(InMemoryTestStore::new());
    let simple_store = SimpleStoreEx::setup(db).await?;
    simple_store.store.test_pending_ids().await
}

#[tokio::test]
async fn exact_vintage_rewards_and_completeness_regressions() -> anyhow::Result<()> {
    let db = Arc::new(InMemoryTestStore::new());
    let simple_store = SimpleStoreEx::setup(db).await?;
    simple_store.store.test_realm_specific_proofs().await?;
    simple_store.store.test_exact_global_user_proof_completeness().await?;
    Ok(())
}

fn imt_entry(tree_id: u64, tree_sub_id: u64, leaf_index: u64, leaf_key: [u8; 32], leaf_value: [u8; 32], is_new_key: bool) -> [u8; 161] {
    serialize_imt_leaf_ffs_entry_v2::<Hash256>(
        tree_id,
        tree_sub_id,
        leaf_index,
        &Hash256::from_owned_32bytes([1; 32]),
        &Hash256::from_owned_32bytes(leaf_key),
        &Hash256::from_owned_32bytes(leaf_value),
        &Hash256::from_owned_32bytes([2; 32]),
        0,
        is_new_key,
    )
}

fn sentinel_index_key(leaf_key: &[u8; 32]) -> (i16, [u8; 32]) {
    let encoded_key = encode_imt_key_for_sorting::<u64, Hash256>(&Hash256::from_owned_32bytes(*leaf_key));
    let key_bucket = imt_key_bucket_to_i16(u16::from_be_bytes([encoded_key[0], encoded_key[1]]));
    (key_bucket, encoded_key)
}

#[tokio::test]
async fn sentinel_key_index_preserves_birth_and_recovers_missing_row() -> anyhow::Result<()> {
    let db = Arc::new(InMemoryTestStore::new());
    let simple_store = SimpleStoreEx::setup(db).await?;
    let unified = &simple_store.store.db;
    let tree_id = 7_i64;
    let tree_sub_id = 9_i64;
    let sentinel_key = [0u8; 32];
    let (key_bucket, encoded_key) = sentinel_index_key(&sentinel_key);

    unified
        .contract_state_imt_set_leaves_ffs(3, &imt_entry(7, 9, 10, sentinel_key, [0; 32], false))
        .await?;
    unified
        .contract_state_imt_set_leaves_ffs(11, &imt_entry(7, 9, 10, sentinel_key, [0; 32], false))
        .await?;
    assert_eq!(
        unified
            .store
            .db_select_imt_key_index_exact(unified.imt_key_index_table.as_ref(), tree_id, tree_sub_id, key_bucket, &encoded_key)
            .await?,
        Some((10, 3))
    );

    let new_key = [5u8; 32];
    unified
        .contract_state_imt_set_leaves_ffs(11, &imt_entry(7, 9, 12, new_key, [6; 32], true))
        .await?;
    let (new_bucket, new_encoded_key) = sentinel_index_key(&new_key);
    assert_eq!(
        unified
            .store
            .db_select_imt_key_index_exact(unified.imt_key_index_table.as_ref(), tree_id, tree_sub_id, new_bucket, &new_encoded_key)
            .await?,
        Some((12, 11))
    );

    let recovered_tree_id = 8_i64;
    let recovered_tree_sub_id = 10_i64;
    let (recovered_bucket, recovered_encoded_key) = sentinel_index_key(&sentinel_key);
    assert_eq!(
        unified
            .store
            .db_select_imt_key_index_exact(
                unified.imt_key_index_table.as_ref(),
                recovered_tree_id,
                recovered_tree_sub_id,
                recovered_bucket,
                &recovered_encoded_key,
            )
            .await?,
        None
    );
    unified
        .store
        .db_insert_imt_leaf(unified.imt_leaf_table.as_ref(), recovered_tree_id, recovered_tree_sub_id, 14, 4, &[1; 32], &sentinel_key, &[0; 32], &[2; 32], 0)
        .await?;
    unified
        .store
        .db_insert_imt_leaf(unified.imt_leaf_table.as_ref(), recovered_tree_id, recovered_tree_sub_id, 14, 9, &[3; 32], &sentinel_key, &[0; 32], &[2; 32], 0)
        .await?;
    unified
        .contract_state_imt_set_leaves_ffs(9, &imt_entry(8, 10, 14, sentinel_key, [0; 32], false))
        .await?;
    assert_eq!(
        unified
            .store
            .db_select_imt_key_index_exact(
                unified.imt_key_index_table.as_ref(),
                recovered_tree_id,
                recovered_tree_sub_id,
                recovered_bucket,
                &recovered_encoded_key,
            )
            .await?,
        Some((14, 4))
    );

    unified
        .store
        .db_insert_imt_key_index(unified.imt_key_index_table.as_ref(), tree_id, tree_sub_id, key_bucket, &encoded_key, &sentinel_key, 4, 99)
        .await?;
    let conflict = unified
        .contract_state_imt_set_leaves_ffs(11, &imt_entry(7, 9, 10, sentinel_key, [0; 32], false))
        .await;
    assert!(conflict.is_err());
    Ok(())
}
