use std::sync::Arc;

use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
use parth_core::protocol::core_types::QNetworkTypesConfig;
use psy_core::job::job_id::QProvingJobDataID;
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    psy_core_db::traits::full::PsyNodeCoreDatabaseContractObjectStoreReader, psy_temp_db::StandardProcessorTempDBStoreBase, queue::ephemeral::QStandardEphemeralQueueSubscriber,
};
use tokio::sync::{mpsc, oneshot};

use crate::{
    constants::queue::{PQ_COORDINATOR_DEPLOY_CONTRACT_QUEUE_TOPIC_ID, PQ_COORDINATOR_UPDATE_CONTRACT_QUEUE_TOPIC_ID},
    coordinator::{
        processor::gatherers::{
            deploy_contract_gatherer::{DeployContractGatherer, DeployContractGathererConfig, DeployContractGathererOutput},
            update_contract_gatherer::{UpdateContractGatherer, UpdateContractGathererConfig, UpdateContractGathererOutput},
        },
        queue_key::{CoordinatorDeployContractQueueKey, CoordinatorUpdateContractQueueKey},
    },
    queue::gatherer::QueueKeyStatusManager,
};

/// Combined output of the contract gatherer (deploys + code updates) for one
/// block.
#[derive(Debug)]
pub struct ContractGathererOutput<Hash, JobId> {
    pub deploy: DeployContractGathererOutput<Hash, JobId>,
    pub update: UpdateContractGathererOutput<Hash, JobId>,
}

/// Config for the combined contract gatherer.
pub struct ContractGathererConfig<
    N: QNetworkTypesConfig,
    S: PsyNodeCoreDatabaseContractObjectStoreReader<N::F, N::QHash>,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
    FileSystem: TokioLikeFileSystem,
> {
    pub deploy: DeployContractGathererConfig<N, TempDatabase, FileSystem>,
    pub update: UpdateContractGathererConfig<N, S, TempDatabase, FileSystem>,
}
impl<N: QNetworkTypesConfig, S: PsyNodeCoreDatabaseContractObjectStoreReader<N::F, N::QHash>, TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>, FileSystem: TokioLikeFileSystem> Clone
    for ContractGathererConfig<N, S, TempDatabase, FileSystem>
{
    fn clone(&self) -> Self {
        Self {
            deploy: self.deploy.clone(),
            update: self.update.clone(),
        }
    }
}

/// Combined contract gatherer: drives the deploy gatherer and the update
/// gatherer on a SINGLE shared in-memory global contract tree.
///
/// Ordering decision: queue items of both queues can be applied in any order
/// during the gathering phase (deploys append at fresh indices, updates only
/// touch already-committed contracts, and a same-block deploy->update is
/// impossible because the deploy contract id is only assigned at gather time).
/// At finalize time the deploy gatherer ALWAYS finalizes first (append
/// proofs), then the update gatherer finalizes on the post-deploy tree
/// (overwrite proofs), so the update output's end root is the final
/// deploy-then-update contract tree root and its
/// `update_global_contract_tree_nodes_ffs` is a superset of the deploy
/// gatherer's change set.
pub struct ContractGatherer<
    N: QNetworkTypesConfig,
    S: PsyNodeCoreDatabaseContractObjectStoreReader<N::F, N::QHash>,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
    FileSystem: TokioLikeFileSystem,
> {
    pub deploy: DeployContractGatherer<N, TempDatabase, FileSystem>,
    pub update: UpdateContractGatherer<N, S, TempDatabase, FileSystem>,
}

impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        S: PsyNodeCoreDatabaseContractObjectStoreReader<N::F, N::QHash> + Send + Sync + 'static,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
        FileSystem: TokioLikeFileSystem,
    > ContractGatherer<N, S, TempDatabase, FileSystem>
{
    pub async fn create_new_with_tree(
        tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        unique_id: parth_core::QCoreProcCheckpointUniqueId,
        config: ContractGathererConfig<N, S, TempDatabase, FileSystem>,
    ) -> anyhow::Result<Self> {
        use crate::queue::gatherer_builder::QueueGathererItemBuilderWithTree;

        let deploy = DeployContractGatherer::create_new_with_tree(tree, unique_id, config.deploy).await?;
        let update = UpdateContractGatherer::create_new_with_tree(tree, unique_id, config.update).await?;
        Ok(Self { deploy, update })
    }

    pub async fn update_from_deploy_queue_items_with_tree(
        &mut self,
        tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        items: Vec<Vec<u8>>,
    ) -> anyhow::Result<()> {
        use crate::queue::gatherer_builder::QueueGathererItemBuilderWithTree;

        self.deploy.update_from_many_queue_items_with_tree(tree, items).await
    }

    pub async fn update_from_update_queue_items_with_tree(
        &mut self,
        tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        items: Vec<Vec<u8>>,
    ) -> anyhow::Result<()> {
        use crate::queue::gatherer_builder::QueueGathererItemBuilderWithTree;

        self.update.update_from_many_queue_items_with_tree(tree, items).await
    }

    pub async fn finalize_with_tree(
        self,
        tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
    ) -> anyhow::Result<ContractGathererOutput<N::QHash, N::JobId>> {
        use crate::queue::gatherer_builder::QueueGathererItemBuilderWithTree;

        // deploy always finalizes first so the update gatherer sees the
        // post-deploy tree state
        let deploy_output = self.deploy.finalize_with_tree(tree).await?;
        let update_output = self.update.finalize_with_tree(tree).await?;
        Ok(ContractGathererOutput {
            deploy: deploy_output,
            update: update_output,
        })
    }
}

/// Processor-side handle for the combined contract gatherer (mirrors the
/// `EphemeralQueueGathererWithTree` API but manages both the deploy and the
/// update queue keys).
pub struct ContractQueueGatherer<N: QNetworkTypesConfig> {
    qk_deploy: QueueKeyStatusManager<PQ_COORDINATOR_DEPLOY_CONTRACT_QUEUE_TOPIC_ID, psy_data::v1::qdata::contract::PsyDeployContractQueueItemV2<N::F, N::QHash>>,
    qk_update: QueueKeyStatusManager<PQ_COORDINATOR_UPDATE_CONTRACT_QUEUE_TOPIC_ID, psy_data::v1::qdata::contract::PsyUpdateContractQueueItem<N::F, N::QHash>>,
    trigger_tx: mpsc::Sender<oneshot::Sender<anyhow::Result<ContractGathererOutput<N::QHash, N::JobId>>>>,
}

impl<N: QNetworkTypesConfig<JobId = QProvingJobDataID> + 'static> Clone for ContractQueueGatherer<N> {
    fn clone(&self) -> Self {
        Self {
            qk_deploy: self.qk_deploy.clone(),
            qk_update: self.qk_update.clone(),
            trigger_tx: self.trigger_tx.clone(),
        }
    }
}

impl<N: QNetworkTypesConfig<JobId = QProvingJobDataID> + 'static> ContractQueueGatherer<N> {
    pub fn new_with_status<
        Sub: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
        S: PsyNodeCoreDatabaseContractObjectStoreReader<N::F, N::QHash> + Send + Sync + 'static,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
        FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
    >(
        stream: Arc<Sub>,
        create_builder_config: ContractGathererConfig<N, S, TempDatabase, FileSystem>,
        deploy_queue_key: CoordinatorDeployContractQueueKey<N::F, N::QHash>,
        update_queue_key: CoordinatorUpdateContractQueueKey<N::F, N::QHash>,
        tree: SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        status: crate::utils::processor_status::ProcessorStatus,
    ) -> (Self, tokio::task::JoinHandle<Result<(), anyhow::Error>>)
    where
        N: 'static,
        N::HasherBase: Send + Sync,
        N::QHash: Send + Sync,
    {
        let qk_deploy = QueueKeyStatusManager::new_with_status(deploy_queue_key.clone(), status.clone());
        let qk_update = QueueKeyStatusManager::new_with_status(update_queue_key.clone(), status);
        let (trigger_tx, trigger_rx) = mpsc::channel::<oneshot::Sender<anyhow::Result<ContractGathererOutput<N::QHash, N::JobId>>>>(1);

        let jh: tokio::task::JoinHandle<Result<(), anyhow::Error>> = tokio::spawn(contract_gatherer_runner::<N, Sub, S, TempDatabase, FileSystem>(
            stream,
            create_builder_config,
            deploy_queue_key,
            update_queue_key,
            tree,
            qk_deploy.clone(),
            qk_update.clone(),
            trigger_rx,
        ));

        (Self { qk_deploy, qk_update, trigger_tx }, jh)
    }

    pub async fn stop_gracefully(&mut self) -> anyhow::Result<()> {
        self.qk_deploy.begin_shutdown()?;
        self.qk_update.begin_shutdown()?;
        let (response_tx, response_rx) = oneshot::channel();
        self.trigger_tx.send(response_tx).await?;
        let _result = response_rx.await?;
        Ok(())
    }

    pub async fn finalize_gathering_and_update_queue_key(
        &mut self,
        unique_id: u128,
    ) -> anyhow::Result<ContractGathererOutput<N::QHash, N::JobId>> {
        self.qk_deploy.set_unique_id(unique_id)?;
        self.qk_update.set_unique_id(unique_id)?;
        let (response_tx, response_rx) = oneshot::channel();
        if response_rx.is_terminated() {
            anyhow::bail!("CONTRACT_GATHERER: Response channel was terminated before sending.");
        } else if response_tx.is_closed() {
            anyhow::bail!("CONTRACT_GATHERER: Response channel was closed before sending.");
        }
        tracing::info!("start finish finalize_gathering_and_update_queue_key for CONTRACT_GATHERER");
        self.trigger_tx.send(response_tx).await?;
        // Preserve the gatherer's real error instead of turning a dropped
        // responder into the unhelpful `channel closed` error.
        let result = response_rx.await??;
        tracing::info!("end finish finalize_gathering_and_update_queue_key for CONTRACT_GATHERER");
        Ok(result)
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn contract_gatherer_runner<
    N: QNetworkTypesConfig<JobId = QProvingJobDataID> + 'static,
    Sub: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    S: PsyNodeCoreDatabaseContractObjectStoreReader<N::F, N::QHash> + Send + Sync + 'static,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
    FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
>(
    stream: Arc<Sub>,
    create_builder_config: ContractGathererConfig<N, S, TempDatabase, FileSystem>,
    mut deploy_queue_key: CoordinatorDeployContractQueueKey<N::F, N::QHash>,
    mut update_queue_key: CoordinatorUpdateContractQueueKey<N::F, N::QHash>,
    mut tree: SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
    deploy_queue_key_helper: QueueKeyStatusManager<PQ_COORDINATOR_DEPLOY_CONTRACT_QUEUE_TOPIC_ID, psy_data::v1::qdata::contract::PsyDeployContractQueueItemV2<N::F, N::QHash>>,
    update_queue_key_helper: QueueKeyStatusManager<PQ_COORDINATOR_UPDATE_CONTRACT_QUEUE_TOPIC_ID, psy_data::v1::qdata::contract::PsyUpdateContractQueueItem<N::F, N::QHash>>,
    mut trigger_rx: mpsc::Receiver<oneshot::Sender<anyhow::Result<ContractGathererOutput<N::QHash, N::JobId>>>>,
) -> anyhow::Result<()> {
    loop {
        let mut builder = match ContractGatherer::create_new_with_tree(&mut tree, deploy_queue_key.unique_id, create_builder_config.clone()).await {
            Ok(builder) => builder,
            Err(err) => {
                tracing::error!("CONTRACT_GATHERER: Error creating new builder: {:?}, retrying in 5s", err);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
        };
        tracing::info!(
            "CONTRACT_GATHERER: Starting new gathering phase with unique_id: {}, realm_id: {}, realm_sub_id: {}",
            deploy_queue_key.unique_id, deploy_queue_key.realm_id, deploy_queue_key.realm_sub_id
        );
        if let Err(e) = stream
            .ensure_consumer(&deploy_queue_key, deploy_queue_key.realm_id, deploy_queue_key.realm_sub_id, deploy_queue_key.unique_id, deploy_queue_key.task_group as u32)
            .await
        {
            tracing::warn!("CONTRACT_GATHERER: ensure_consumer (deploy) for unique_id {} failed: {}; proceeding with existing consumer state", deploy_queue_key.unique_id, e);
        }
        if let Err(e) = stream
            .ensure_consumer(&update_queue_key, update_queue_key.realm_id, update_queue_key.realm_sub_id, update_queue_key.unique_id, update_queue_key.task_group as u32)
            .await
        {
            tracing::warn!("CONTRACT_GATHERER: ensure_consumer (update) for unique_id {} failed: {}; proceeding with existing consumer state", update_queue_key.unique_id, e);
        }
        if trigger_rx.is_closed() {
            tracing::info!("CONTRACT_GATHERER: Trigger channel closed before gathering started, stopping gatherer.");
            return Ok(());
        }
        'gathering: loop {
            if trigger_rx.is_closed() {
                tracing::info!("CONTRACT_GATHERER: Trigger channel closed, shutting down gatherer.");
                return Ok(());
            }
            tokio::select! {
                // Biased ensures we check for a processor trigger first for better responsiveness.
                biased;

                // A trigger from the Processor was received.
                Some(responder) = trigger_rx.recv() => {
                    let old_unique_id = deploy_queue_key.unique_id;
                    let old_deploy_queue_key = deploy_queue_key.clone();
                    let old_update_queue_key = update_queue_key.clone();
                    tracing::info!("CONTRACT_GATHERER: Interrupted by Processor. Preparing to hand over");
                    deploy_queue_key = deploy_queue_key_helper.get_queue_key()?;
                    update_queue_key = update_queue_key_helper.get_queue_key()?;
                    // Keep the historical control-flow meaning of this
                    // variable: despite its name, it represents whether the
                    // shared processor is still active. The runner below
                    // uses `!is_stopped` to decide whether to exit.
                    let is_stopped = deploy_queue_key_helper.should_run();
                    let mut trigger_ok = true;

                    // drain the remaining deploy items, then the remaining
                    // update items for the old unique id
                    let remaining_deploy_items = match stream
                        .dump_entire_ephemeral_queue_bytes(
                            &old_deploy_queue_key,
                            old_deploy_queue_key.realm_id,
                            old_deploy_queue_key.realm_sub_id,
                            old_unique_id,
                            old_deploy_queue_key.task_group as u32,
                            usize::MAX,
                        )
                        .await
                    {
                        Ok(items) => items,
                        Err(err) => {
                            tracing::warn!("CONTRACT_GATHERER: Error draining deploy queue for old unique_id {}; continuing with empty queue so processor can retry: {}", old_unique_id, err);
                            trigger_ok = false;
                            Vec::new()
                        }
                    };
                    if !remaining_deploy_items.is_empty() {
                        if let Err(err) = builder.update_from_deploy_queue_items_with_tree(&mut tree, remaining_deploy_items).await {
                            tracing::error!("CONTRACT_GATHERER: Error updating from remaining deploy items: {:?}; processor will retry", err);
                            trigger_ok = false;
                        }
                    }
                    let remaining_update_items = match stream
                        .dump_entire_ephemeral_queue_bytes(
                            &old_update_queue_key,
                            old_update_queue_key.realm_id,
                            old_update_queue_key.realm_sub_id,
                            old_unique_id,
                            old_update_queue_key.task_group as u32,
                            usize::MAX,
                        )
                        .await
                    {
                        Ok(items) => items,
                        Err(err) => {
                            let err_string = err.to_string();
                            if err_string.contains("consumer not found") {
                                tracing::warn!("CONTRACT_GATHERER: Missing update consumer while draining old unique_id {}; treating as empty queue: {}", old_unique_id, err_string);
                            } else {
                                tracing::warn!("CONTRACT_GATHERER: Error draining update queue for old unique_id {}; continuing with empty queue so processor can retry: {}", old_unique_id, err_string);
                                trigger_ok = false;
                            }
                            Vec::new()
                        }
                    };
                    if !remaining_update_items.is_empty() {
                        if let Err(err) = builder.update_from_update_queue_items_with_tree(&mut tree, remaining_update_items).await {
                            tracing::error!("CONTRACT_GATHERER: Error updating from remaining update items: {:?}; processor will retry", err);
                            trigger_ok = false;
                        }
                    }

                    if trigger_ok {
                        match builder.finalize_with_tree(&mut tree).await {
                            Ok(finalized_output) => {
                                tracing::info!("CONTRACT_GATHERER: Finalized output prepared, sending to processor.");
                                if responder.send(Ok(finalized_output)).is_err() {
                                    tracing::error!("CONTRACT_GATHERER: Failed to send data to processor. The receiver was dropped.");
                                } else {
                                    tracing::info!("CONTRACT_GATHERER: Successfully handed over data to processor.");
                                }
                            }
                            Err(err) => {
                                tracing::error!("CONTRACT_GATHERER: Error during finalize: {:?}; processor will retry", err);
                                if responder.send(Err(err)).is_err() {
                                    tracing::error!("CONTRACT_GATHERER: Failed to send finalize error to processor. The receiver was dropped.");
                                }
                            }
                        }
                    } else {
                        tracing::error!("CONTRACT_GATHERER: Skipped finalize after update error; processor will retry.");
                        if responder
                            .send(Err(anyhow::anyhow!(
                                "CONTRACT_GATHERER: failed to drain or apply queued contract items"
                            )))
                            .is_err()
                        {
                            tracing::error!("CONTRACT_GATHERER: Failed to send queue update error to processor. The receiver was dropped.");
                        }
                    }

                    if !is_stopped {
                        tracing::info!("CONTRACT_GATHERER: Stopping as requested.");
                        return Ok(());
                    }
                    if trigger_rx.is_closed() {
                        tracing::info!("CONTRACT_GATHERER: Trigger channel closed after handing over, stopping gatherer.");
                        return Ok(());
                    }

                    break 'gathering; // Break inner loop to start a new cycle.
                },

                // New messages from the deploy queue.
                deploy_msgs = stream.dump_entire_ephemeral_queue_bytes(&deploy_queue_key, deploy_queue_key.realm_id, deploy_queue_key.realm_sub_id, deploy_queue_key.unique_id, deploy_queue_key.task_group as u32, 50000) => {
                    match deploy_msgs {
                        Ok(d) => {
                            if !d.is_empty() {
                                tracing::info!("CONTRACT_GATHERER: Received {} deploy items from queue.", d.len());
                                if let Err(err) = builder.update_from_deploy_queue_items_with_tree(&mut tree, d).await {
                                    tracing::error!("CONTRACT_GATHERER: Error updating from deploy queue items: {:?}; restarting gather cycle", err);
                                    break 'gathering;
                                }
                            }
                        },
                        Err(err) => {
                            tracing::error!("CONTRACT_GATHERER: Error receiving deploy message: {}", err);
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        },
                    }
                    // drain the update queue right after the deploy queue
                    match stream.dump_entire_ephemeral_queue_bytes(&update_queue_key, update_queue_key.realm_id, update_queue_key.realm_sub_id, update_queue_key.unique_id, update_queue_key.task_group as u32, 50000).await {
                        Ok(d) => {
                            if !d.is_empty() {
                                tracing::info!("CONTRACT_GATHERER: Received {} update items from queue.", d.len());
                                if let Err(err) = builder.update_from_update_queue_items_with_tree(&mut tree, d).await {
                                    tracing::error!("CONTRACT_GATHERER: Error updating from update queue items: {:?}; restarting gather cycle", err);
                                    break 'gathering;
                                }
                            }
                        },
                        Err(err) => {
                            let err_string = err.to_string();
                            if !err_string.contains("consumer not found") {
                                tracing::error!("CONTRACT_GATHERER: Error receiving update message: {}", err);
                                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                            }
                        },
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                },
            }
        }
        tracing::info!("CONTRACT_GATHERER: Handoff complete. Cycle restarting.");
    }
}

#[cfg(test)]
mod tests {
    use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
    use parth_core::{crypto::hash::traits::{FieldQHasher, MerkleHasher, MerkleZeroHasher, QFieldHashable}, felt::FromPrimitiveValuesFelt, pgoldilocks::PoseidonHasher, protocol::core_types::Q256BitHash, utils::QPGenRandom, PHash, PF};
    use psy_data::v1::qdata::contract::PQEDContractLeaf;

    type Hash = PHash;
    type F = PF;
    type Hasher = PoseidonHasher;

    fn rand_contract_leaf(deployer: Hash, state_tree_height: u64) -> PQEDContractLeaf<F, Hash> {
        PQEDContractLeaf {
            deployer,
            function_tree_root: Hash::qp_rand_gen(),
            code_root: Hash::qp_rand_gen(),
            state_tree_height: F::from_u64_value(state_tree_height),
        }
    }

    // Simulates the combined finalize ordering (deploy first, then update) on
    // a single shared tree and verifies the composed root and change sets.
    #[test]
    fn test_deploy_then_update_composition_on_single_tree() -> anyhow::Result<()> {
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(8);
        let deployer = Hash::qp_rand_gen();

        // two pre-existing committed contracts
        let committed_leaf_a = rand_contract_leaf(deployer, 10);
        let committed_leaf_b = rand_contract_leaf(deployer, 12);
        tree.set_leaf(0, committed_leaf_a.qfhash::<Hasher>());
        tree.set_leaf(1, committed_leaf_b.qfhash::<Hasher>());
        tree.commit_changes();
        let committed_root = tree.get_root();

        // ---- block start: deploy gatherer appends two new contracts
        let new_leaf_c = rand_contract_leaf(deployer, 10);
        let new_leaf_d = rand_contract_leaf(deployer, 11);
        let append_hashes = vec![new_leaf_c.qfhash::<Hasher>(), new_leaf_d.qfhash::<Hasher>()];
        let deploy_proofs = tree.append_leaves_spider_man(2, &append_hashes)?;
        assert_eq!(deploy_proofs.len(), 1);
        let deploy_end_root = tree.get_root();
        let deploy_change_count = tree.get_changes().len();

        // ---- update gatherer overwrites committed contract 1 (same tree,
        // after deploy, exactly like the combined finalize)
        let mut updated_leaf_b = committed_leaf_b;
        updated_leaf_b.code_root = Hash::qp_rand_gen();
        updated_leaf_b.function_tree_root = Hash::qp_rand_gen();
        let updated_hash_b = updated_leaf_b.qfhash::<Hasher>();
        let update_proofs = tree.update_leaves_spider_man(2, &[1], &[updated_hash_b])?;
        assert_eq!(update_proofs.len(), 1);
        // the update proof must see the pre-update value of the window
        assert_eq!(update_proofs[0].web_proof_old_leaves[1], committed_leaf_b.qfhash::<Hasher>());
        assert_eq!(update_proofs[0].web_proof_new_leaves[1], updated_hash_b);
        let final_root = tree.get_root();
        assert_ne!(final_root, deploy_end_root);

        // the change set after both finalizes is the union (superset of the
        // deploy-only changes) — this is what gets written to the db
        assert!(tree.get_changes().len() > deploy_change_count);

        // independently recompute the expected final root on a fresh tree
        let mut expected_tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(8);
        expected_tree.set_leaf(0, committed_leaf_a.qfhash::<Hasher>());
        expected_tree.set_leaf(1, updated_leaf_b.qfhash::<Hasher>());
        expected_tree.set_leaf(2, new_leaf_c.qfhash::<Hasher>());
        expected_tree.set_leaf(3, new_leaf_d.qfhash::<Hasher>());
        assert_eq!(final_root, expected_tree.get_root());

        // sanity: the deploy-only end root also matches the fresh tree without
        // the update applied
        let mut deploy_only_tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(8);
        deploy_only_tree.set_leaf(0, committed_leaf_a.qfhash::<Hasher>());
        deploy_only_tree.set_leaf(1, committed_leaf_b.qfhash::<Hasher>());
        deploy_only_tree.set_leaf(2, new_leaf_c.qfhash::<Hasher>());
        deploy_only_tree.set_leaf(3, new_leaf_d.qfhash::<Hasher>());
        assert_eq!(deploy_end_root, deploy_only_tree.get_root());
        assert_ne!(committed_root, deploy_end_root);
        Ok(())
    }
}

/// Tests for the combined `ContractGatherer` builder and the
/// `ContractQueueGatherer`/`contract_gatherer_runner` orchestration, running
/// fully offline against the in-memory db stack, temp store, mock file system
/// and a topic-aware fake subscriber.
#[cfg(test)]
mod gatherer_tests {
    use std::collections::{HashMap, VecDeque};
    use std::sync::{Arc, Mutex, RwLock};

    use async_trait::async_trait;
    use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
    use parth_core::{
        crypto::hash::traits::{MerkleZeroHasher, QFieldHashable},
        data::queue::queue_key::{PCoreStandardQueueKeyForRealm, PCoreSubjectQueueBase, QPBaseQueueType},
        felt::FromPrimitiveValuesFelt,
        node::realm_identifier::QRealmIdentifier,
        pgoldilocks::PoseidonHasher,
        protocol::core_types::QNetworkTreeConstants,
        utils::QPGenRandom,
        PHash, PF,
    };
    use psy_data::v1::qdata::{
        checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, QEDL2BlockState},
        contract::{ContractCodeDefinition, PQEDContractLeafV2, PsyDeployContractQueueItemV2, PsyUpdateContractQueueItem},
    };
    use psy_node_core::{
        file::memory_fs::SimpleMockMemoryFileSystem,
        psy_core_db::traits::full::PsyNodeCoreDatabaseContractObjectStoreWriter,
        psy_temp_db::QTempDBDeployContractDataWriter,
        queue::{ephemeral::QStandardEphemeralQueueSubscriber, infrastructure::QStandardQueueBase},
    };
    use psy_node_core::qblob::data_views::single_merkle_node_batch::generate_single_merkle_node_blob_from_leaves_with_tree_height;
    use psy_node_store_memory::temp_store::InMemoryTempStore;
    use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

    use crate::{
        coordinator::processor::processor_shared_status::PsyCoordinatorProcessorSharedStatus,
        test_common::{create_test_unified_db, TestNetworkConfig, TestUnifiedDatabaseStore},
    };

    use super::*;

    type N = TestNetworkConfig;
    type Hash = PHash;
    type F = PF;
    type Hasher = PoseidonHasher;
    type Db = TestUnifiedDatabaseStore;
    type TempDb = InMemoryTempStore;
    type Fs = SimpleMockMemoryFileSystem;

    type DeployKey = CoordinatorDeployContractQueueKey<F, Hash>;
    type UpdateKey = CoordinatorUpdateContractQueueKey<F, Hash>;

    const REALM_ID: u64 = 1;
    const REALM_SUB_ID: u64 = 2;
    const UNIQUE_PENDING_ID: u64 = 500;
    const TASK_GROUP: u64 = 3;

    fn zh(level: usize) -> Hash {
        PoseidonHasher::get_zero_hash(level)
    }

    /// `unwrap_err` needs the Ok type to be Debug; the combined output is, but
    /// keep the same helper style as the other gatherer test modules.
    fn err_str<T>(result: anyhow::Result<T>) -> String {
        match result {
            Ok(_) => panic!("expected the call to fail, but it succeeded"),
            Err(e) => e.to_string(),
        }
    }

    fn rand_contract_leaf(deployer: Hash, state_tree_height: u16) -> PQEDContractLeafV2<F, Hash> {
        PQEDContractLeafV2 {
            deployer,
            function_tree_root: Hash::qp_rand_gen(),
            code_root: Hash::qp_rand_gen(),
            state_tree_height: F::from_u16_value(state_tree_height),
            state_layout_root: Hash::default(),
            state_layout_field_count: F::default(),
            state_layout_slot_count: F::default(),
        }
    }

    fn function_leaves() -> Vec<Hash> {
        vec![Hash::qp_rand_gen(), Hash::qp_rand_gen()]
    }

    fn fn_tree_root_full_height(contract_id: u64, leaves: &[Hash]) -> Hash {
        generate_single_merkle_node_blob_from_leaves_with_tree_height::<Hash, Hasher>(contract_id, leaves, N::CONTRACT_FUNCTION_TREE_HEIGHT).0
    }

    fn block_state(next_contract_id: u32) -> QEDL2BlockState {
        QEDL2BlockState {
            checkpoint_id: 0,
            next_add_withdrawal_id: 0,
            next_process_withdrawal_id: 0,
            next_deposit_id: 0,
            total_deposits_claimed_epoch: 0,
            next_user_id: 0,
            end_balance: 0,
            next_contract_id,
        }
    }

    fn shared_status(contract_tree_root: Hash) -> Arc<RwLock<PsyCoordinatorProcessorSharedStatus<F, Hash>>> {
        Arc::new(RwLock::new(PsyCoordinatorProcessorSharedStatus {
            last_committed_checkpoint_id: 0,
            unique_pending_id: UNIQUE_PENDING_ID,
            last_committed_checkpoint_leaf: PQEDCheckpointLeaf::qp_rand_gen(),
            last_committed_checkpoint_state_roots: PQEDCheckpointGlobalStateRoots {
                contract_tree_root,
                deposit_tree_root: zh(2),
                user_tree_root: zh(3),
                withdrawal_tree_root: zh(2),
                user_registration_tree_root: zh(3),
            },
            should_revert_last_changes: false,
            block_state: block_state(1),
        }))
    }

    fn contract_config(
        db: Arc<Db>,
        temp_db: Arc<TempDb>,
        fs: Arc<Fs>,
        status: Arc<RwLock<PsyCoordinatorProcessorSharedStatus<F, Hash>>>,
        last_job_next_contract_id: u64,
    ) -> ContractGathererConfig<N, Db, TempDb, Fs> {
        ContractGathererConfig {
            deploy: DeployContractGathererConfig {
                realm_id_u64: REALM_ID,
                realm_sub_id_u64: REALM_SUB_ID,
                shared_status: Arc::clone(&status),
                temp_db: Arc::clone(&temp_db),
                backup_file_directory: "gatherer_backups".to_string(),
                deploy_contract_circuit_whitelist: zh(23),
                last_job_next_contract_id: Arc::new(RwLock::new(last_job_next_contract_id)),
                file_system: Arc::clone(&fs),
                _phantom_n: std::marker::PhantomData,
            },
            update: UpdateContractGathererConfig {
                realm_id_u64: REALM_ID,
                realm_sub_id_u64: REALM_SUB_ID,
                shared_status: status,
                temp_db,
                contract_leaf_reader: db,
                backup_file_directory: "gatherer_backups".to_string(),
                update_contract_circuit_whitelist: zh(24),
                file_system: fs,
                _phantom_n: std::marker::PhantomData,
            },
        }
    }

    /// Deploys and commits one pre-existing contract at id 1 (update contract
    /// ids must be non-zero) in the tree, the core db and the temp db (code
    /// definition keyed for update items).
    async fn seed_existing_contract_1(
        tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
        db: &Db,
        temp_db: &TempDb,
        old_leaf: &PQEDContractLeafV2<F, Hash>,
    ) -> anyhow::Result<()> {
        tree.set_leaf(1, old_leaf.qfhash::<Hasher>());
        tree.commit_changes();
        db.set_contract_leaf(0, 1, old_leaf).await?;
        temp_db
            .set_deploy_contract_code_definition_raw(
                &QRealmIdentifier { realm_id: REALM_ID as u32, realm_sub_id: REALM_SUB_ID as u16 },
                UNIQUE_PENDING_ID,
                &[8u8; 16],
                ContractCodeDefinition { state_tree_height: 10, functions: vec![] }.psy_ser_to_bytes_vec()?,
            )
            .await?;
        Ok(())
    }

    async fn seed_deploy_code_definition(temp_db: &TempDb, rand_key_id: &[u8; 16]) -> anyhow::Result<()> {
        temp_db
            .set_deploy_contract_code_definition_raw(
                &QRealmIdentifier { realm_id: REALM_ID as u32, realm_sub_id: REALM_SUB_ID as u16 },
                UNIQUE_PENDING_ID,
                rand_key_id,
                ContractCodeDefinition { state_tree_height: 12, functions: vec![] }.psy_ser_to_bytes_vec()?,
            )
            .await?;
        Ok(())
    }

    fn deploy_item_bytes(contract_leaf: PQEDContractLeafV2<F, Hash>, leaves: Vec<Hash>) -> anyhow::Result<Vec<u8>> {
        let item = PsyDeployContractQueueItemV2::<F, Hash> {
            rand_key_id: [3u8; 16],
            contract_leaf,
            function_leaves: leaves,
            layout_protocol_version: 1,
            canonical_layout_verifier_fingerprint: Hash::default(),
            canonical_layout_proof: vec![1, 2, 3, 4],
        };
        item.psy_ser_to_bytes_vec()
    }

    fn update_item_bytes(contract_id: u64, contract_leaf: PQEDContractLeafV2<F, Hash>, leaves: Vec<Hash>) -> anyhow::Result<Vec<u8>> {
        let item = PsyUpdateContractQueueItem::<F, Hash> {
            rand_key_id: [8u8; 16],
            contract_id,
            contract_leaf,
            function_leaves: leaves,
            layout_protocol_version: 1,
            canonical_layout_verifier_fingerprint: Hash::default(),
            canonical_layout_proof: vec![1, 2, 3, 4],
        };
        item.psy_ser_to_bytes_vec()
    }

    fn queue_keys(unique_id: u128) -> (DeployKey, UpdateKey) {
        (
            DeployKey {
                realm_id: REALM_ID,
                realm_sub_id: REALM_SUB_ID,
                unique_id,
                task_group: TASK_GROUP,
                queue_type: QPBaseQueueType::StandardEphemeral,
                _phantom_queue_item: std::marker::PhantomData,
            },
            UpdateKey {
                realm_id: REALM_ID,
                realm_sub_id: REALM_SUB_ID,
                unique_id,
                task_group: TASK_GROUP,
                queue_type: QPBaseQueueType::StandardEphemeral,
                _phantom_queue_item: std::marker::PhantomData,
            },
        )
    }

    fn running_status() -> crate::utils::processor_status::ProcessorStatus {
        let status = crate::utils::processor_status::ProcessorStatus::new();
        status.mark_running();
        status
    }

    #[tokio::test]
    async fn combined_builder_gathers_deploy_then_update_on_shared_tree() -> anyhow::Result<()> {
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(24);
        let old_leaf = rand_contract_leaf(Hash::qp_rand_gen(), 10);

        let db = Arc::new(create_test_unified_db().await?);
        let temp_db = Arc::new(InMemoryTempStore::new("contract_gatherer_test".to_string(), 1, 2));
        let fs = Arc::new(SimpleMockMemoryFileSystem::new());
        seed_existing_contract_1(&mut tree, &db, &temp_db, &old_leaf).await?;
        seed_deploy_code_definition(&temp_db, &[3u8; 16]).await?;
        let committed_root = tree.get_root();

        let config = contract_config(Arc::clone(&db), Arc::clone(&temp_db), Arc::clone(&fs), shared_status(committed_root), 2);
        let mut gatherer = ContractGatherer::create_new_with_tree(&mut tree, 66, config).await?;

        // deploy item -> assigned contract id 2 (next free id after the cursor)
        let deploy_leaves = function_leaves();
        let mut deploy_leaf = rand_contract_leaf(Hash::qp_rand_gen(), 12);
        deploy_leaf.function_tree_root = fn_tree_root_full_height(2, &deploy_leaves);
        let deploy_item = deploy_item_bytes(deploy_leaf.clone(), deploy_leaves)?;
        // update item -> overwrite committed contract 1
        let update_leaves = function_leaves();
        let mut updated_leaf = old_leaf;
        updated_leaf.code_root = Hash::qp_rand_gen();
        updated_leaf.function_tree_root = fn_tree_root_full_height(1, &update_leaves);
        let update_item = update_item_bytes(1, updated_leaf.clone(), update_leaves)?;

        gatherer.update_from_deploy_queue_items_with_tree(&mut tree, vec![deploy_item]).await?;
        gatherer.update_from_update_queue_items_with_tree(&mut tree, vec![update_item]).await?;
        assert_eq!(gatherer.deploy.next_contract_id, 3);
        assert_eq!(gatherer.update.updated_contract_ids, vec![1u64]);

        let output = ContractGatherer::finalize_with_tree(gatherer, &mut tree).await?;
        assert_eq!(output.deploy.db_output.start_next_contract_id, 2);
        assert_eq!(output.deploy.db_output.next_contract_id, 3);
        assert_eq!(output.deploy.db_output.start_global_contract_tree_root, committed_root);
        assert_eq!(output.update.db_output.updated_contract_ids, vec![1u64]);
        // the update gatherer captures its start root when ITS finalize begins,
        // i.e. on the post-deploy tree
        assert_eq!(output.update.db_output.start_global_contract_tree_root, output.deploy.db_output.end_global_contract_tree_root);
        // the update output's end root is the FINAL deploy-then-update root
        assert_eq!(output.update.db_output.end_global_contract_tree_root, tree.get_root());
        assert_ne!(output.update.db_output.end_global_contract_tree_root, output.deploy.db_output.end_global_contract_tree_root);
        assert_eq!(tree.get_leaf_value(1), updated_leaf.qfhash::<Hasher>());
        assert_eq!(tree.get_leaf_value(2), deploy_leaf.qfhash::<Hasher>());

        // independently recompute the expected final root
        let mut expected_tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(24);
        expected_tree.set_leaf(1, updated_leaf.qfhash::<Hasher>());
        expected_tree.set_leaf(2, deploy_leaf.qfhash::<Hasher>());
        assert_eq!(tree.get_root(), expected_tree.get_root());
        // both backup files were written under the shared pending id
        assert!(fs
            .files
            .get(&super::super::deploy_contract_gatherer::get_new_deploy_contract_gatherer_backup_file_path("gatherer_backups", 1, 2, 500))
            .is_some());
        assert!(fs
            .files
            .get(&super::super::update_contract_gatherer::get_new_update_contract_gatherer_backup_file_path("gatherer_backups", 1, 2, 500))
            .is_some());

        // Recovery replays deploy first, then applies the update backup from
        // the post-deploy root recorded when the update phase finalized.
        let mut recovery_tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(24);
        recovery_tree.set_leaf(1, old_leaf.qfhash::<Hasher>());
        recovery_tree.commit_changes();
        assert_eq!(recovery_tree.get_root(), committed_root);

        let deploy_backup_path = super::super::deploy_contract_gatherer::get_new_deploy_contract_gatherer_backup_file_path(
            "gatherer_backups",
            REALM_ID,
            REALM_SUB_ID,
            UNIQUE_PENDING_ID,
        );
        let deploy_backup_output = super::super::deploy_contract_gatherer::read_deploy_contract_gatherer_backup_file_path::<Hasher, Hash, F, Fs>(
            fs.as_ref(),
            &deploy_backup_path,
            1 << N::CONTRACT_FUNCTION_TREE_HEIGHT,
            &mut recovery_tree,
        )
        .await?;
        assert_eq!(recovery_tree.get_root(), deploy_backup_output.end_global_contract_tree_root);

        let update_backup_path = super::super::update_contract_gatherer::get_new_update_contract_gatherer_backup_file_path(
            "gatherer_backups",
            REALM_ID,
            REALM_SUB_ID,
            UNIQUE_PENDING_ID,
        );
        let update_backup_output = super::super::update_contract_gatherer::read_update_contract_gatherer_backup_file_path::<Hasher, Hash, F, Fs>(
            fs.as_ref(),
            &update_backup_path,
            1 << N::CONTRACT_FUNCTION_TREE_HEIGHT,
            &mut recovery_tree,
        )
        .await?;
        assert_eq!(update_backup_output.start_global_contract_tree_root, deploy_backup_output.end_global_contract_tree_root);
        assert_eq!(update_backup_output.end_global_contract_tree_root, output.update.db_output.end_global_contract_tree_root);
        assert_eq!(recovery_tree.get_root(), tree.get_root());
        assert_eq!(recovery_tree.get_leaf_value(1), updated_leaf.qfhash::<Hasher>());
        assert_eq!(recovery_tree.get_leaf_value(2), deploy_leaf.qfhash::<Hasher>());
        Ok(())
    }

    #[tokio::test]
    async fn combined_create_fails_when_deploy_cursor_is_invalid() -> anyhow::Result<()> {
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(24);
        let db = Arc::new(create_test_unified_db().await?);
        let temp_db = Arc::new(InMemoryTempStore::new("contract_gatherer_test".to_string(), 1, 2));
        let fs = Arc::new(SimpleMockMemoryFileSystem::new());
        // cursor at 3 on an empty tree: the leaf before the cursor is missing
        let config = contract_config(db, temp_db, fs, shared_status(tree.get_root()), 3);
        let err = err_str(ContractGatherer::create_new_with_tree(&mut tree, 66, config).await);
        assert!(err.contains("minus one does not exist in tree"), "got: {err}");
        Ok(())
    }

    /// Topic-aware fake subscriber: per-subject FIFOs so the deploy and update
    /// queues stay separate, plus the pending-on-empty behaviour the gatherer
    /// runner tests rely on (a buffered processor trigger wins the biased
    /// select over the steady-state poll).
    #[derive(Default)]
    struct TopicFakeSubscriber {
        queues: Mutex<HashMap<String, VecDeque<Vec<u8>>>>,
        /// subjects whose FULL drain (max_items == usize::MAX, used by the
        /// trigger handover branch) fails with the stored message
        full_drain_failures: Mutex<HashMap<String, String>>,
    }

    impl TopicFakeSubscriber {
        fn subject_for<QK: PCoreSubjectQueueBase>(queue_key: &QK, unique_id: u128) -> String {
            queue_key.get_queue_subject("", REALM_ID, REALM_SUB_ID, unique_id, TASK_GROUP as u32)
        }
        fn add_items<QK: PCoreSubjectQueueBase>(&self, queue_key: &QK, unique_id: u128, items: Vec<Vec<u8>>) {
            let subject = Self::subject_for(queue_key, unique_id);
            self.queues.lock().unwrap().entry(subject).or_default().extend(items);
        }
        fn fail_full_drain<QK: PCoreSubjectQueueBase>(&self, queue_key: &QK, unique_id: u128, message: &str) {
            let subject = Self::subject_for(queue_key, unique_id);
            self.full_drain_failures.lock().unwrap().insert(subject, message.to_string());
        }
    }

    #[async_trait]
    impl QStandardQueueBase for TopicFakeSubscriber {
        async fn ensure_stream(&self) -> anyhow::Result<()> {
            Ok(())
        }
        async fn ensure_consumer<QK: PCoreStandardQueueKeyForRealm>(
            &self,
            _queue_key: &QK,
            _realm_id: u64,
            _realm_sub_id: u64,
            _unique_id: parth_core::QCoreProcCheckpointUniqueId,
            _task_group: u32,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl QStandardEphemeralQueueSubscriber for TopicFakeSubscriber {
        async fn wait_for_ephemeral_queue_item_bytes<QK: PCoreStandardQueueKeyForRealm>(
            &self,
            _queue_key: &QK,
            _realm_id: u64,
            _realm_sub_id: u64,
            _unique_id: parth_core::QCoreProcCheckpointUniqueId,
            _task_group: u32,
            _timeout_ms: u64,
        ) -> anyhow::Result<Option<Vec<u8>>> {
            unreachable!("not used by the contract gatherer runner paths under test")
        }
        async fn wait_for_ephemeral_queue_item<QK: PCoreStandardQueueKeyForRealm>(
            &self,
            _queue_key: &QK,
            _realm_id: u64,
            _realm_sub_id: u64,
            _unique_id: parth_core::QCoreProcCheckpointUniqueId,
            _task_group: u32,
            _timeout_ms: u64,
        ) -> anyhow::Result<Option<QK::QueueItem>> {
            unreachable!("not used by the contract gatherer runner paths under test")
        }
        async fn dump_entire_ephemeral_queue_bytes<QK: PCoreStandardQueueKeyForRealm>(
            &self,
            queue_key: &QK,
            realm_id: u64,
            realm_sub_id: u64,
            unique_id: parth_core::QCoreProcCheckpointUniqueId,
            task_group: u32,
            max_items: usize,
        ) -> anyhow::Result<Vec<Vec<u8>>> {
            let subject = queue_key.get_queue_subject("", realm_id, realm_sub_id, unique_id, task_group);
            if max_items == usize::MAX {
                if let Some(message) = self.full_drain_failures.lock().unwrap().get(&subject) {
                    return Err(anyhow::anyhow!("{}", message));
                }
            }
            let drained = self
                .queues
                .lock()
                .unwrap()
                .get_mut(&subject)
                .map(|q| {
                    let mut out = Vec::new();
                    while out.len() < max_items {
                        let Some(item) = q.pop_front() else { break };
                        out.push(item);
                    }
                    out
                })
                .unwrap_or_default();
            if drained.is_empty() {
                // mimic a real subscriber waiting on the network so a buffered
                // processor trigger (checked first, biased) wins the select
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Ok(drained)
        }
        async fn dump_entire_ephemeral_queue<QK: PCoreStandardQueueKeyForRealm>(
            &self,
            _queue_key: &QK,
            _realm_id: u64,
            _realm_sub_id: u64,
            _unique_id: parth_core::QCoreProcCheckpointUniqueId,
            _task_group: u32,
            _max_items: usize,
        ) -> anyhow::Result<Vec<QK::QueueItem>> {
            unreachable!("not used by the contract gatherer runner paths under test")
        }
        async fn consume_ephemeral_queue_item_or_none_bytes<QK: PCoreStandardQueueKeyForRealm>(
            &self,
            _queue_key: &QK,
            _realm_id: u64,
            _realm_sub_id: u64,
            _unique_id: parth_core::QCoreProcCheckpointUniqueId,
            _task_group: u32,
        ) -> anyhow::Result<Option<Vec<u8>>> {
            unreachable!("not used by the contract gatherer runner paths under test")
        }
        async fn consume_ephemeral_queue_item_or_none<QK: PCoreStandardQueueKeyForRealm>(
            &self,
            _queue_key: &QK,
            _realm_id: u64,
            _realm_sub_id: u64,
            _unique_id: parth_core::QCoreProcCheckpointUniqueId,
            _task_group: u32,
        ) -> anyhow::Result<Option<QK::QueueItem>> {
            unreachable!("not used by the contract gatherer runner paths under test")
        }
    }

    #[tokio::test]
    async fn runner_drains_both_queues_and_hands_over_output() -> anyhow::Result<()> {
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(24);
        let old_leaf = rand_contract_leaf(Hash::qp_rand_gen(), 10);

        let db = Arc::new(create_test_unified_db().await?);
        let temp_db = Arc::new(InMemoryTempStore::new("contract_gatherer_test".to_string(), 1, 2));
        let fs = Arc::new(SimpleMockMemoryFileSystem::new());
        seed_existing_contract_1(&mut tree, &db, &temp_db, &old_leaf).await?;
        seed_deploy_code_definition(&temp_db, &[3u8; 16]).await?;
        let committed_root = tree.get_root();

        let subscriber = Arc::new(TopicFakeSubscriber::default());
        let (deploy_key, update_key) = queue_keys(11);
        let deploy_leaves = function_leaves();
        let mut deploy_leaf = rand_contract_leaf(Hash::qp_rand_gen(), 12);
        deploy_leaf.function_tree_root = fn_tree_root_full_height(2, &deploy_leaves);
        let update_leaves = function_leaves();
        let mut updated_leaf = old_leaf;
        updated_leaf.code_root = Hash::qp_rand_gen();
        updated_leaf.function_tree_root = fn_tree_root_full_height(1, &update_leaves);
        subscriber.add_items(&deploy_key, 11, vec![deploy_item_bytes(deploy_leaf.clone(), deploy_leaves)?]);
        subscriber.add_items(&update_key, 11, vec![update_item_bytes(1, updated_leaf.clone(), update_leaves)?]);

        let config = contract_config(Arc::clone(&db), Arc::clone(&temp_db), Arc::clone(&fs), shared_status(committed_root), 2);
        let (mut gatherer, join_handle) = ContractQueueGatherer::<N>::new_with_status::<TopicFakeSubscriber, Db, TempDb, Fs>(
            Arc::clone(&subscriber),
            config,
            deploy_key,
            update_key,
            tree,
            running_status(),
        );

        // whether the items were consumed by the steady-state poll or by the
        // handover drain, the finalized output must combine both queues
        let output = gatherer.finalize_gathering_and_update_queue_key(12).await?;
        assert_eq!(output.deploy.db_output.next_contract_id, 3);
        assert_eq!(output.deploy.db_output.start_next_contract_id, 2);
        assert_eq!(output.update.db_output.updated_contract_ids, vec![1u64]);
        assert_ne!(output.update.db_output.end_global_contract_tree_root, output.deploy.db_output.end_global_contract_tree_root);
        assert!(fs
            .files
            .get(&super::super::deploy_contract_gatherer::get_new_deploy_contract_gatherer_backup_file_path("gatherer_backups", 1, 2, 500))
            .is_some());

        gatherer.stop_gracefully().await?;
        join_handle.await??;
        Ok(())
    }

    #[tokio::test]
    async fn runner_reports_error_when_the_handover_drain_fails() -> anyhow::Result<()> {
        let tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(24);
        let db = Arc::new(create_test_unified_db().await?);
        let temp_db = Arc::new(InMemoryTempStore::new("contract_gatherer_test".to_string(), 1, 2));
        let fs = Arc::new(SimpleMockMemoryFileSystem::new());

        let subscriber = Arc::new(TopicFakeSubscriber::default());
        let (deploy_key, update_key) = queue_keys(21);
        subscriber.fail_full_drain(&deploy_key, 21, "injected drain failure");

        let config = contract_config(Arc::clone(&db), Arc::clone(&temp_db), Arc::clone(&fs), shared_status(tree.get_root()), 0);
        let (mut gatherer, join_handle) = ContractQueueGatherer::<N>::new_with_status::<TopicFakeSubscriber, Db, TempDb, Fs>(
            Arc::clone(&subscriber),
            config,
            deploy_key,
            update_key,
            tree,
            running_status(),
        );

        let err = err_str(gatherer.finalize_gathering_and_update_queue_key(22).await);
        assert!(err.contains("failed to drain or apply queued contract items"), "got: {err}");

        gatherer.stop_gracefully().await?;
        join_handle.await??;
        Ok(())
    }

    #[tokio::test]
    async fn runner_propagates_finalize_error_to_the_processor() -> anyhow::Result<()> {
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(24);
        let old_leaf = rand_contract_leaf(Hash::qp_rand_gen(), 10);

        let db = Arc::new(create_test_unified_db().await?);
        let temp_db = Arc::new(InMemoryTempStore::new("contract_gatherer_test".to_string(), 1, 2));
        let fs = Arc::new(SimpleMockMemoryFileSystem::new());
        seed_existing_contract_1(&mut tree, &db, &temp_db, &old_leaf).await?;
        let committed_root = tree.get_root();

        let subscriber = Arc::new(TopicFakeSubscriber::default());
        let (deploy_key, update_key) = queue_keys(31);
        let update_leaves = function_leaves();
        let mut updated_leaf = old_leaf;
        updated_leaf.code_root = Hash::qp_rand_gen();
        updated_leaf.function_tree_root = fn_tree_root_full_height(1, &update_leaves);
        subscriber.add_items(&update_key, 31, vec![update_item_bytes(1, updated_leaf, update_leaves)?]);

        // flip the block into revert mode while claiming a mismatching
        // committed contract root BEFORE the runner starts, so the create-time
        // status snapshot is deterministic; the revert path also resets the
        // shared cursor to block_state.next_contract_id, so point it at the
        // next free contract id (2) to keep the runner's follow-up gather
        // cycle creatable for the shutdown handshake
        let status = shared_status(committed_root);
        {
            let mut status = status.write().unwrap();
            status.should_revert_last_changes = true;
            status.last_committed_checkpoint_state_roots.contract_tree_root = Hash::qp_rand_gen();
            status.block_state = block_state(2);
        }
        let config = contract_config(Arc::clone(&db), Arc::clone(&temp_db), Arc::clone(&fs), status, 0);
        let (mut gatherer, join_handle) = ContractQueueGatherer::<N>::new_with_status::<TopicFakeSubscriber, Db, TempDb, Fs>(
            Arc::clone(&subscriber),
            config,
            deploy_key,
            update_key,
            tree,
            running_status(),
        );

        // the finalize must fail and the real error must reach the processor
        // (not a channel-closed error)
        let err = err_str(gatherer.finalize_gathering_and_update_queue_key(32).await);
        assert!(err.contains("tree root mismatch"), "got: {err}");

        gatherer.stop_gracefully().await?;
        join_handle.await??;
        Ok(())
    }
}
