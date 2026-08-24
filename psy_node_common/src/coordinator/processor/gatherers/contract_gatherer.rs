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
