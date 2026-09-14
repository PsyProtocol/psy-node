//! Shared in-memory test infrastructure for psy_node_common integration tests.
//!
//! Everything here is `#[cfg(test)]`-gated at the module declaration site, so
//! none of it ships in production builds. It wires together the real in-memory
//! database stack (`InMemoryCoreStore` + `PsyUnifiedCoreDatabaseStore` +
//! `InMemoryTempStore`), the mock memory file system, and lightweight fake
//! queues, so processor-level integration tests can run fully offline against
//! the same code paths production uses.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use parth_core::{
    data::queue::queue_key::{PCoreQueueItemBase, PCoreStandardQueueKeyForRealm},
    pgoldilocks::PoseidonHasher,
    protocol::core_types::{
        QNetworkHashTypes, QNetworkTreeCircuitSpecificConstants, QNetworkTreeConstants, QNetworkTypesConfig, QNetworkZKTypes,
        QZKProofPublicInputsHasherReader, QZKProofVerifier,
    },
    crypto::hash::traits::MerkleZeroHasher,
    QCoreProcCheckpointUniqueId,
};
use psy_core::job::job_id::QProvingJobDataID;
use psy_node_core::queue::{
    infrastructure::QStandardQueueBase,
    worker_queue::{QStandardWorkerQueue, QStandardWorkerQueuePublisher, QStandardWorkerQueueSubscriber},
};
use psy_node_store_memory::cbs_store::{InMemoryCoreStore, InMemoryTableIdentifier};

/// Full network config for coordinator-side integration tests: real tree
/// constants, Poseidon hashing and a trivially-accepting ZK verifier whose
/// public-input hash is the zero hash at depth 1.
#[derive(Debug, Clone, Copy)]
pub struct TestNetworkConfig {}

impl QNetworkTreeCircuitSpecificConstants for TestNetworkConfig {
    const GUTA_CIRCUIT_WHITELIST_TREE_HEIGHT: u8 = 4;
    const MAX_USERS_TO_REGISTER_PER_PROOF: usize = 32;
    const ONLY_REGISTER_USERS_MAX_USERS_PER_PROOF: usize = 64;
    const BATCH_USER_REGISTRATION_SUB_TREE_HEIGHT: usize = 8;
    const BATCH_USER_REGISTRATION_MAX_SUB_TREES: usize = 4;
    const BATCH_DEPLOY_CONTRACT_SUB_TREE_HEIGHT: usize = 8;

    const DEFAULT_USER_STATE_TREE_ROOT_HASH_U64_X4: [u64; 4] =
        [3896366420105793420, 17410332186442776169, 7329967984378645716, 6310665049578686403];

    const END_CAP_CIRCUIT_FINGERPRINT_HASH_U64_X4: [u64; 4] =
        [1412692327731855940, 17963365021580141687, 10532510199226356508, 3943799806037696098];
}

impl QNetworkTreeConstants for TestNetworkConfig {
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

impl QNetworkHashTypes for TestNetworkConfig {
    type QHash = parth_core::PHash;
    type HasherBase = PoseidonHasher;
    type F = parth_core::PF;
}

/// ZK "verifier" that accepts everything: proofs are `()`, public-input hash
/// is the zero hash. The tests that care about chain-hash arithmetic compute
/// the expected values explicitly.
pub struct TestZKVerifier {}

impl QZKProofPublicInputsHasherReader<parth_core::PHash, ()> for TestZKVerifier {
    fn get_proof_public_inputs_hash(_proof: &()) -> anyhow::Result<parth_core::PHash> {
        Ok(PoseidonHasher::get_zero_hash(1))
    }
    fn try_proof_from_slice(_bytes: &[u8]) -> anyhow::Result<()> {
        Ok(())
    }
}

impl QZKProofVerifier<parth_core::PHash, ()> for TestZKVerifier {
    fn verify_zk_proof(&self, _circuit_type: u32, _proof: &()) -> anyhow::Result<parth_core::PHash> {
        Ok(PoseidonHasher::get_zero_hash(1))
    }
    fn verify_zk_proof_from_slice_check_public_inputs_hash(
        &self,
        _circuit_type: u32,
        _proof_bytes: &[u8],
        _expected_public_inputs_hash: parth_core::PHash,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

impl QNetworkZKTypes for TestNetworkConfig {
    type ZKProof = ();
    type ZKVerifier = TestZKVerifier;
}

impl QNetworkTypesConfig for TestNetworkConfig {
    type JobId = QProvingJobDataID;
}

pub type TestInMemoryCoreStore = InMemoryCoreStore<parth_core::PHash, PoseidonHasher>;

/// Full unified database store over the in-memory core store, wired with the
/// same table layout production uses. Mirrors the construction in
/// `guta_planner::realm_guta_planner_tests::core::setup_rgp_test_db`.
pub type TestUnifiedDatabaseStore =
    psy_node_core::psy_core_db::v3_implementation::full::PsyUnifiedCoreDatabaseStore<
        TestNetworkConfig,
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
        TestInMemoryCoreStore,
    >;

pub async fn create_test_unified_db() -> anyhow::Result<TestUnifiedDatabaseStore> {
    let store = Arc::new(TestInMemoryCoreStore::new());
    setup_test_unified_db(store).await
}

pub async fn setup_test_unified_db(store: Arc<TestInMemoryCoreStore>) -> anyhow::Result<TestUnifiedDatabaseStore> {
    use psy_node_core::psy_core_db::v3_implementation::full::PsyUnifiedCoreDatabaseStore;

    let keyspace = format!("psy_node_common_test_{}", rand::random::<u64>());
    let table = |name: &str| Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, name));
    let tree_table = |name: &str, height: u8| {
        Arc::new(InMemoryTableIdentifier::new_treee_with_keyspace(&keyspace, name, height))
    };

    let psy_db = PsyUnifiedCoreDatabaseStore::new(
        store,
        table("checkpoint_leaf_table"),
        table("checkpoint_root_to_checkpoint_id_table"),
        table("checkpoint_leaf_to_checkpoint_id_table"),
        table("l2_block_state_table"),
        table("checkpoint_id_to_realm_root_table"),
        table("latest_info_table"),
        table("checkpointed_object_table"),
        table("checkpoint_state_roots_table"),
        table("user_leaf_table"),
        table("user_public_key_table"),
        table("u64_singleton_table"),
        table("u64_counter_singleton_table"),
        table("contract_state_tree_height_table"),
        table("checkpoint_id_to_pending_id_table"),
        table("pending_id_to_checkpoint_id_table"),
        table("pending_id_to_pending_proc_id_table"),
        table("realm_rewards_tree_node_key_table"),
        table("public_key_hash_to_user_ids_table"),
        tree_table("global_user_tree_table", TestNetworkConfig::GLOBAL_USER_TREE_HEIGHT),
        tree_table("user_contract_tree_table", TestNetworkConfig::GLOBAL_CONTRACT_TREE_HEIGHT),
        table("contract_state_tree_table"),
        tree_table("global_checkpoint_tree_table", TestNetworkConfig::CHECKPOINT_TREE_HEIGHT),
        table("guta_reward_tag_tree_table"),
        tree_table("user_registration_tree_table", TestNetworkConfig::GLOBAL_USER_TREE_HEIGHT),
        tree_table("global_contract_tree_table", TestNetworkConfig::GLOBAL_CONTRACT_TREE_HEIGHT),
        table("contract_function_tree_table"),
        table("contract_leaf_table"),
        table("contract_code_definition_table"),
        table("checkpoint_zk_proof_and_transition_table"),
        table("imt_leaf_table"),
        table("imt_key_index_table"),
        table("imt_next_append_index_table"),
    );
    Ok(psy_db)
}

/// In-memory fake for ephemeral queue subscribers: per-unique_id FIFOs plus
/// logs of consumer lifecycle calls so tests can assert queue orchestration.
#[derive(Default)]
pub struct FakeEphemeralQueueSubscriber {
    queues: Mutex<HashMap<u128, VecDeque<Vec<u8>>>>,
    pub ensured_consumers: Mutex<Vec<(u128, u32)>>,
    pub deleted_consumers: Mutex<Vec<u128>>,
}

impl FakeEphemeralQueueSubscriber {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add_items(&self, unique_id: u128, items: Vec<Vec<u8>>) {
        self.queues
            .lock()
            .unwrap()
            .entry(unique_id)
            .or_default()
            .extend(items);
    }
    pub fn ensured_consumer_count(&self) -> usize {
        self.ensured_consumers.lock().unwrap().len()
    }
}

#[async_trait]
impl QStandardQueueBase for FakeEphemeralQueueSubscriber {
    async fn ensure_stream(&self) -> anyhow::Result<()> {
        Ok(())
    }
    async fn ensure_consumer<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        _queue_key: &QK,
        _realm_id: u64,
        _realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
    ) -> anyhow::Result<()> {
        self.ensured_consumers.lock().unwrap().push((unique_id, task_group));
        Ok(())
    }
}

#[async_trait]
impl psy_node_core::queue::ephemeral::QStandardEphemeralQueueSubscriber for FakeEphemeralQueueSubscriber {
    async fn wait_for_ephemeral_queue_item_bytes<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        _queue_key: &QK,
        _realm_id: u64,
        _realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        _task_group: u32,
        _timeout_ms: u64,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self.queues.lock().unwrap().get_mut(&unique_id).and_then(|q| q.pop_front()))
    }
    async fn wait_for_ephemeral_queue_item<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        _queue_key: &QK,
        _realm_id: u64,
        _realm_sub_id: u64,
        _unique_id: QCoreProcCheckpointUniqueId,
        _task_group: u32,
        _timeout_ms: u64,
    ) -> anyhow::Result<Option<QK::QueueItem>> {
        unreachable!("not used by the coordinator database processor paths under test")
    }
    async fn dump_entire_ephemeral_queue_bytes<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        _queue_key: &QK,
        _realm_id: u64,
        _realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        _task_group: u32,
        max_items: usize,
    ) -> anyhow::Result<Vec<Vec<u8>>> {
        Ok(self
            .queues
            .lock()
            .unwrap()
            .get_mut(&unique_id)
            .map(|q| {
                let mut out = Vec::new();
                while out.len() < max_items {
                    let Some(item) = q.pop_front() else { break };
                    out.push(item);
                }
                out
            })
            .unwrap_or_default())
    }
    async fn dump_entire_ephemeral_queue<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        _queue_key: &QK,
        _realm_id: u64,
        _realm_sub_id: u64,
        _unique_id: QCoreProcCheckpointUniqueId,
        _task_group: u32,
        _max_items: usize,
    ) -> anyhow::Result<Vec<QK::QueueItem>> {
        unreachable!("not used by the coordinator database processor paths under test")
    }
    async fn consume_ephemeral_queue_item_or_none_bytes<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        _queue_key: &QK,
        _realm_id: u64,
        _realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        _task_group: u32,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self.queues.lock().unwrap().get_mut(&unique_id).and_then(|q| q.pop_front()))
    }
    async fn consume_ephemeral_queue_item_or_none<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        _queue_key: &QK,
        _realm_id: u64,
        _realm_sub_id: u64,
        _unique_id: QCoreProcCheckpointUniqueId,
        _task_group: u32,
    ) -> anyhow::Result<Option<QK::QueueItem>> {
        unreachable!("not used by the coordinator database processor paths under test")
    }
    async fn delete_ephemeral_queue_consumer<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        _queue_key: &QK,
        _realm_id: u64,
        _realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        _task_group: u32,
    ) -> anyhow::Result<()> {
        self.deleted_consumers.lock().unwrap().push(unique_id);
        Ok(())
    }
}

/// In-memory fake for the worker-queue publisher used to dispatch proving
/// jobs: records every published item and ensured consumer for assertions.
#[derive(Default)]
pub struct FakeWorkerQueuePublisher {
    pub published_items: Mutex<Vec<Vec<u8>>>,
    pub ensured_consumers: Mutex<Vec<u128>>,
}

impl FakeWorkerQueuePublisher {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn ensured_consumer_count(&self) -> usize {
        self.ensured_consumers.lock().unwrap().len()
    }
}

#[async_trait]
impl QStandardQueueBase for FakeWorkerQueuePublisher {
    async fn ensure_stream(&self) -> anyhow::Result<()> {
        Ok(())
    }
    async fn ensure_consumer<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        _queue_key: &QK,
        _realm_id: u64,
        _realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        _task_group: u32,
    ) -> anyhow::Result<()> {
        self.ensured_consumers.lock().unwrap().push(unique_id);
        Ok(())
    }
}

impl QStandardWorkerQueue for FakeWorkerQueuePublisher {
    type PublishBarrier = ();
}

#[async_trait]
impl QStandardWorkerQueuePublisher for FakeWorkerQueuePublisher {
    async fn publish_worker_queue_item_ref<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        _queue_key: &QK,
        _realm_id: u64,
        _realm_sub_id: u64,
        _unique_id: QCoreProcCheckpointUniqueId,
        _task_group: u32,
        item: &QK::QueueItem,
    ) -> anyhow::Result<Self::PublishBarrier> {
        self.published_items
            .lock()
            .unwrap()
            .push(item.encode_queue_item_vec()?);
        Ok(())
    }
    async fn publish_many_worker_queue_items_ref<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        _queue_key: &QK,
        _realm_id: u64,
        _realm_sub_id: u64,
        _unique_id: QCoreProcCheckpointUniqueId,
        _task_group: u32,
        items: &[&QK::QueueItem],
    ) -> anyhow::Result<Self::PublishBarrier> {
        for item in items {
            self.published_items
                .lock()
                .unwrap()
                .push(item.encode_queue_item_vec()?);
        }
        Ok(())
    }
    async fn publish_worker_queue_item_owned<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        _queue_key: &QK,
        _realm_id: u64,
        _realm_sub_id: u64,
        _unique_id: QCoreProcCheckpointUniqueId,
        _task_group: u32,
        item: QK::QueueItem,
    ) -> anyhow::Result<Self::PublishBarrier> {
        self.publish_worker_queue_item_ref::<QK>(_queue_key, _realm_id, _realm_sub_id, _unique_id, _task_group, &item)
            .await
    }
    async fn publish_many_worker_queue_items_owned<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        _queue_key: &QK,
        _realm_id: u64,
        _realm_sub_id: u64,
        _unique_id: QCoreProcCheckpointUniqueId,
        _task_group: u32,
        items: Vec<QK::QueueItem>,
    ) -> anyhow::Result<Self::PublishBarrier> {
        for item in &items {
            self.published_items
                .lock()
                .unwrap()
                .push(item.encode_queue_item_vec()?);
        }
        Ok(())
    }
    async fn publish_many_worker_queue_items<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        _queue_key: &QK,
        _realm_id: u64,
        _realm_sub_id: u64,
        _unique_id: QCoreProcCheckpointUniqueId,
        _task_group: u32,
        items: &[QK::QueueItem],
    ) -> anyhow::Result<Self::PublishBarrier> {
        for item in items {
            self.published_items
                .lock()
                .unwrap()
                .push(item.encode_queue_item_vec()?);
        }
        Ok(())
    }
}



/// In-memory fake for ephemeral queue publishers: records every published
/// (unique_id, bytes) pair so tests can assert queue dispatch behavior.
#[derive(Default)]
pub struct FakeEphemeralQueuePublisher {
    pub published: Mutex<Vec<(u128, Vec<u8>)>>,
}

impl FakeEphemeralQueuePublisher {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn published_count(&self) -> usize {
        self.published.lock().unwrap().len()
    }
    pub fn published_bytes_for(&self, unique_id: u128) -> Vec<Vec<u8>> {
        self.published
            .lock()
            .unwrap()
            .iter()
            .filter(|(uid, _)| *uid == unique_id)
            .map(|(_, bytes)| bytes.clone())
            .collect()
    }
    pub fn published_items_for_unique_id_count(&self, unique_id: u128) -> usize {
        self.published_bytes_for(unique_id).len()
    }
}

#[async_trait]
impl QStandardQueueBase for FakeEphemeralQueuePublisher {
    async fn ensure_stream(&self) -> anyhow::Result<()> {
        Ok(())
    }
    async fn ensure_consumer<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        _queue_key: &QK,
        _realm_id: u64,
        _realm_sub_id: u64,
        _unique_id: QCoreProcCheckpointUniqueId,
        _task_group: u32,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

#[async_trait]
impl psy_node_core::queue::ephemeral::QStandardEphemeralQueuePublisher for FakeEphemeralQueuePublisher {
    async fn publish_ephemeral_queue_item_bytes_ref<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        _queue_key: &QK,
        _realm_id: u64,
        _realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        _task_group: u32,
        item_bytes: &[u8],
    ) -> anyhow::Result<()> {
        self.published.lock().unwrap().push((unique_id, item_bytes.to_vec()));
        Ok(())
    }
    async fn publish_many_ephemeral_queue_items_bytes_ref<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        items_bytes: &[&[u8]],
    ) -> anyhow::Result<()> {
        for bytes in items_bytes {
            self.publish_ephemeral_queue_item_bytes_ref::<QK>(queue_key, realm_id, realm_sub_id, unique_id, task_group, bytes)
                .await?;
        }
        Ok(())
    }
    async fn publish_ephemeral_queue_item_owned_bytes<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        item_bytes: Vec<u8>,
    ) -> anyhow::Result<()> {
        self.publish_ephemeral_queue_item_bytes_ref::<QK>(queue_key, realm_id, realm_sub_id, unique_id, task_group, &item_bytes)
            .await
    }
    async fn publish_many_ephemeral_queue_items_owned_bytes<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        items_bytes: Vec<Vec<u8>>,
    ) -> anyhow::Result<()> {
        for bytes in &items_bytes {
            self.publish_ephemeral_queue_item_bytes_ref::<QK>(queue_key, realm_id, realm_sub_id, unique_id, task_group, bytes)
                .await?;
        }
        Ok(())
    }
    async fn publish_ephemeral_queue_item_ref<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        item: &QK::QueueItem,
    ) -> anyhow::Result<()> {
        let bytes = item.encode_queue_item_vec()?;
        self.publish_ephemeral_queue_item_owned_bytes::<QK>(queue_key, realm_id, realm_sub_id, unique_id, task_group, bytes)
            .await
    }
    async fn publish_many_ephemeral_queue_items_ref<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        items: &[&QK::QueueItem],
    ) -> anyhow::Result<()> {
        for item in items {
            self.publish_ephemeral_queue_item_ref::<QK>(queue_key, realm_id, realm_sub_id, unique_id, task_group, item)
                .await?;
        }
        Ok(())
    }
    async fn publish_ephemeral_queue_item_owned<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        item: QK::QueueItem,
    ) -> anyhow::Result<()> {
        self.publish_ephemeral_queue_item_ref::<QK>(queue_key, realm_id, realm_sub_id, unique_id, task_group, &item)
            .await
    }
    async fn publish_many_ephemeral_queue_items_owned<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        items: Vec<QK::QueueItem>,
    ) -> anyhow::Result<()> {
        for item in &items {
            self.publish_ephemeral_queue_item_ref::<QK>(queue_key, realm_id, realm_sub_id, unique_id, task_group, item)
                .await?;
        }
        Ok(())
    }
    async fn publish_many_ephemeral_queue_items<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        items: &[QK::QueueItem],
    ) -> anyhow::Result<()> {
        for item in items {
            self.publish_ephemeral_queue_item_ref::<QK>(queue_key, realm_id, realm_sub_id, unique_id, task_group, item)
                .await?;
        }
        Ok(())
    }
}

/// In-memory fake for worker queue subscribers: tests can pre-load items which
/// the fake hands out one at a time, and consumer lifecycle calls are logged.
#[derive(Default)]
pub struct FakeWorkerQueueSubscriber {
    items: Mutex<VecDeque<Vec<u8>>>,
    pub deleted_consumers: Mutex<Vec<u128>>,
}

impl FakeWorkerQueueSubscriber {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add_items(&self, items: Vec<Vec<u8>>) {
        self.items.lock().unwrap().extend(items);
    }
}

#[async_trait]
impl QStandardQueueBase for FakeWorkerQueueSubscriber {
    async fn ensure_stream(&self) -> anyhow::Result<()> {
        Ok(())
    }
    async fn ensure_consumer<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        _queue_key: &QK,
        _realm_id: u64,
        _realm_sub_id: u64,
        _unique_id: QCoreProcCheckpointUniqueId,
        _task_group: u32,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

impl QStandardWorkerQueue for FakeWorkerQueueSubscriber {
    type PublishBarrier = ();
}

#[async_trait]
impl QStandardWorkerQueueSubscriber for FakeWorkerQueueSubscriber {
    async fn wait_for_worker_queue_item<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        _queue_key: &QK,
        _realm_id: u64,
        _realm_sub_id: u64,
        _unique_id: QCoreProcCheckpointUniqueId,
        _task_group: u32,
        timeout_ms: u64,
    ) -> anyhow::Result<Option<QK::QueueItem>> {
        // only wait as long as needed for a pre-loaded item to appear
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms.min(2_000));
        loop {
            if let Some(bytes) = self.items.lock().unwrap().pop_front() {
                return Ok(Some(QK::QueueItem::decode_queue_item_ref(&bytes)?));
            }
            if std::time::Instant::now() >= deadline {
                return Ok(None);
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }
    async fn dump_entire_worker_queue<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        _queue_key: &QK,
        _realm_id: u64,
        _realm_sub_id: u64,
        _unique_id: QCoreProcCheckpointUniqueId,
        _task_group: u32,
        max_items: usize,
    ) -> anyhow::Result<Vec<QK::QueueItem>> {
        let mut queue = self.items.lock().unwrap();
        let take = max_items.min(queue.len());
        let drained: Vec<Vec<u8>> = queue.drain(..take).collect();
        drop(queue);
        drained.iter().map(|b| QK::QueueItem::decode_queue_item_ref(b)).collect()
    }
    async fn get_next_worker_queue_item_or_none<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        _queue_key: &QK,
        _realm_id: u64,
        _realm_sub_id: u64,
        _unique_id: QCoreProcCheckpointUniqueId,
        _task_group: u32,
    ) -> anyhow::Result<Option<QK::QueueItem>> {
        Ok(match self.items.lock().unwrap().pop_front() {
            Some(bytes) => Some(QK::QueueItem::decode_queue_item_ref(&bytes)?),
            None => None,
        })
    }
    async fn wait_until_all_jobs_complete_or_timeout_worker<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        _queue_key: &QK,
        _realm_id: u64,
        _realm_sub_id: u64,
        _unique_topic: u128,
        _task_group: u32,
        _barrier: &Self::PublishBarrier,
        _timeout_ms: u64,
    ) -> anyhow::Result<()> {
        Ok(())
    }
    async fn worker_queue_report_job_completed<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        _queue_key: &QK,
        _realm_id: u64,
        _realm_sub_id: u64,
        _unique_topic: u128,
        _task_group: u32,
        _item: &QK::QueueItem,
    ) -> anyhow::Result<bool> {
        Ok(true)
    }
    async fn delete_worker_queue_consumer<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        _queue_key: &QK,
        _realm_id: u64,
        _realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        _task_group: u32,
    ) -> anyhow::Result<()> {
        self.deleted_consumers.lock().unwrap().push(unique_id);
        Ok(())
    }
}

/// Combined worker-queue fake: implements BOTH the publisher and subscriber
/// sides over one FIFO, so items published by the processor are immediately
/// observable by consumers in the same test. Used where a component requires
/// `QStandardWorkerQueuePublisher + QStandardWorkerQueueSubscriber` (realm
/// processors).
#[derive(Default)]
pub struct FakeWorkerQueue {
    items: Mutex<VecDeque<Vec<u8>>>,
    pub published_count: Mutex<usize>,
    pub ensured_consumers: Mutex<Vec<u128>>,
    pub deleted_consumers: Mutex<Vec<u128>>,
}

impl FakeWorkerQueue {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add_items(&self, items: Vec<Vec<u8>>) {
        self.items.lock().unwrap().extend(items);
    }
    pub fn pending_len(&self) -> usize {
        self.items.lock().unwrap().len()
    }
}

#[async_trait]
impl QStandardQueueBase for FakeWorkerQueue {
    async fn ensure_stream(&self) -> anyhow::Result<()> {
        Ok(())
    }
    async fn ensure_consumer<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        _queue_key: &QK,
        _realm_id: u64,
        _realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        _task_group: u32,
    ) -> anyhow::Result<()> {
        self.ensured_consumers.lock().unwrap().push(unique_id);
        Ok(())
    }
}

impl QStandardWorkerQueue for FakeWorkerQueue {
    type PublishBarrier = ();
}

#[async_trait]
impl QStandardWorkerQueuePublisher for FakeWorkerQueue {
    async fn publish_worker_queue_item_ref<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        _queue_key: &QK,
        _realm_id: u64,
        _realm_sub_id: u64,
        _unique_id: QCoreProcCheckpointUniqueId,
        _task_group: u32,
        item: &QK::QueueItem,
    ) -> anyhow::Result<Self::PublishBarrier> {
        *self.published_count.lock().unwrap() += 1;
        self.items.lock().unwrap().push_back(item.encode_queue_item_vec()?);
        Ok(())
    }
    async fn publish_many_worker_queue_items_ref<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        items: &[&QK::QueueItem],
    ) -> anyhow::Result<Self::PublishBarrier> {
        for item in items {
            self.publish_worker_queue_item_ref::<QK>(queue_key, realm_id, realm_sub_id, unique_id, task_group, item)
                .await?;
        }
        Ok(())
    }
    async fn publish_worker_queue_item_owned<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        item: QK::QueueItem,
    ) -> anyhow::Result<Self::PublishBarrier> {
        self.publish_worker_queue_item_ref::<QK>(queue_key, realm_id, realm_sub_id, unique_id, task_group, &item)
            .await
    }
    async fn publish_many_worker_queue_items_owned<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        items: Vec<QK::QueueItem>,
    ) -> anyhow::Result<Self::PublishBarrier> {
        for item in &items {
            self.publish_worker_queue_item_ref::<QK>(queue_key, realm_id, realm_sub_id, unique_id, task_group, item)
                .await?;
        }
        Ok(())
    }
    async fn publish_many_worker_queue_items<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        items: &[QK::QueueItem],
    ) -> anyhow::Result<Self::PublishBarrier> {
        for item in items {
            self.publish_worker_queue_item_ref::<QK>(queue_key, realm_id, realm_sub_id, unique_id, task_group, item)
                .await?;
        }
        Ok(())
    }
}

#[async_trait]
impl psy_node_core::queue::worker_queue::QStandardWorkerQueueSubscriber for FakeWorkerQueue {
    async fn wait_for_worker_queue_item<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        _queue_key: &QK,
        _realm_id: u64,
        _realm_sub_id: u64,
        _unique_id: QCoreProcCheckpointUniqueId,
        _task_group: u32,
        timeout_ms: u64,
    ) -> anyhow::Result<Option<QK::QueueItem>> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms.min(2_000));
        loop {
            if let Some(bytes) = self.items.lock().unwrap().pop_front() {
                return Ok(Some(QK::QueueItem::decode_queue_item_ref(&bytes)?));
            }
            if std::time::Instant::now() >= deadline {
                return Ok(None);
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }
    async fn dump_entire_worker_queue<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        _queue_key: &QK,
        _realm_id: u64,
        _realm_sub_id: u64,
        _unique_id: QCoreProcCheckpointUniqueId,
        _task_group: u32,
        max_items: usize,
    ) -> anyhow::Result<Vec<QK::QueueItem>> {
        let mut queue = self.items.lock().unwrap();
        let take = max_items.min(queue.len());
        let drained: Vec<Vec<u8>> = queue.drain(..take).collect();
        drop(queue);
        drained.iter().map(|b| QK::QueueItem::decode_queue_item_ref(b)).collect()
    }
    async fn get_next_worker_queue_item_or_none<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        _queue_key: &QK,
        _realm_id: u64,
        _realm_sub_id: u64,
        _unique_id: QCoreProcCheckpointUniqueId,
        _task_group: u32,
    ) -> anyhow::Result<Option<QK::QueueItem>> {
        Ok(match self.items.lock().unwrap().pop_front() {
            Some(bytes) => Some(QK::QueueItem::decode_queue_item_ref(&bytes)?),
            None => None,
        })
    }
    async fn wait_until_all_jobs_complete_or_timeout_worker<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        _queue_key: &QK,
        _realm_id: u64,
        _realm_sub_id: u64,
        _unique_topic: u128,
        _task_group: u32,
        _barrier: &Self::PublishBarrier,
        _timeout_ms: u64,
    ) -> anyhow::Result<()> {
        Ok(())
    }
    async fn worker_queue_report_job_completed<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        _queue_key: &QK,
        _realm_id: u64,
        _realm_sub_id: u64,
        _unique_topic: u128,
        _task_group: u32,
        _item: &QK::QueueItem,
    ) -> anyhow::Result<bool> {
        Ok(true)
    }
    async fn delete_worker_queue_consumer<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        _queue_key: &QK,
        _realm_id: u64,
        _realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        _task_group: u32,
    ) -> anyhow::Result<()> {
        self.deleted_consumers.lock().unwrap().push(unique_id);
        Ok(())
    }
}

