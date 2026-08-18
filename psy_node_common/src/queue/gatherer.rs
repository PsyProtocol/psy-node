use std::{
    sync::{Arc, RwLock},
    time::Duration,
};

use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
use parth_core::{crypto::hash::traits::MerkleZeroHasher, data::queue::queue_key::{PCoreQueueItemBase, QPStandardUniqueIdQueueKey}, protocol::core_types::QHashBase};
use psy_node_core::queue::ephemeral::QStandardEphemeralQueueSubscriber;
use tokio::sync::{mpsc, oneshot};

use crate::{
    queue::gatherer_builder::{QueueGathererItemBuilder, QueueGathererItemBuilderWithTree},
    utils::processor_status::ProcessorStatus,
};


#[derive(Clone)]
pub struct GathererValue<T> {
    value: Arc<RwLock<T>>,
}
impl<T: Clone> GathererValue<T> {
    pub fn new_from_inner(value: T) -> Self {
        Self {
            value: Arc::new(RwLock::new(value))
        }
    }
    pub fn new_from_arc(value: Arc<RwLock<T>>) -> Self {
        Self {
            value
        }
    }
    pub fn set_value(&self, value: T) {
        let mut v = self.value.write().unwrap();
        *v = value;
    }
    pub fn get_value(&self) -> T {
        self.value.read().unwrap().clone()
    }
}

#[derive(Clone)]
pub struct QueueKeyStatusManager<const QUEUE_TOPIC_ID: u32, QueueItem: PCoreQueueItemBase> {
    queue_key: Arc<RwLock<QPStandardUniqueIdQueueKey<QUEUE_TOPIC_ID, QueueItem>>>,
    status: ProcessorStatus,
}

impl<const QUEUE_TOPIC_ID: u32, QueueItem: PCoreQueueItemBase> QueueKeyStatusManager<QUEUE_TOPIC_ID, QueueItem> {
    pub fn new(base_queue_key: QPStandardUniqueIdQueueKey<QUEUE_TOPIC_ID, QueueItem>) -> Self {
        let status = ProcessorStatus::new();
        status.mark_running();
        Self::new_with_status(base_queue_key, status)
    }
    pub fn new_with_status(base_queue_key: QPStandardUniqueIdQueueKey<QUEUE_TOPIC_ID, QueueItem>, status: ProcessorStatus) -> Self {
        let queue_key = Arc::new(RwLock::new(base_queue_key));

        Self { queue_key, status }
    }
    pub fn get_queue_key(&self) -> anyhow::Result<QPStandardUniqueIdQueueKey<QUEUE_TOPIC_ID, QueueItem>> {
        let key = self.queue_key.read().unwrap();
        Ok(key.clone())
    }
    pub fn should_run(&self) -> bool {
        self.status.should_run()
    }
    pub fn begin_shutdown(&self) -> anyhow::Result<()> {
        self.status.begin_shutdown();
        Ok(())
    }
    pub fn set_unique_id(&self, unique_id: u128) -> anyhow::Result<()> {
        let mut key = self.queue_key.write().unwrap();
        key.unique_id = unique_id;
        Ok(())
    }
}

#[derive(Clone)]
pub struct EphemeralQueueGatherer<const QUEUE_TOPIC_ID: u32, QueueItem: PCoreQueueItemBase, Output: Sized + Send + Sync + 'static>
{
    qk: QueueKeyStatusManager<QUEUE_TOPIC_ID, QueueItem>,
    trigger_tx: mpsc::Sender<oneshot::Sender<Output>>,
}

impl<const QUEUE_TOPIC_ID: u32, QueueItem: PCoreQueueItemBase + 'static, Output: Send + Sync>
    EphemeralQueueGatherer<QUEUE_TOPIC_ID, QueueItem, Output>
{
    pub fn new<Sub: QStandardEphemeralQueueSubscriber + Send + Sync + 'static, C: Clone + Send + Sync + 'static, Builder: QueueGathererItemBuilder<C, Output = Output> + Send + Sync + 'static>(
        stream: Arc<Sub>,
        create_builder_config: C,
        base_queue_key: QPStandardUniqueIdQueueKey<QUEUE_TOPIC_ID, QueueItem>,
    ) -> (Self, tokio::task::JoinHandle<Result<(), anyhow::Error>>) {
        let qk = QueueKeyStatusManager::new(base_queue_key.clone());
        let (trigger_tx, trigger_rx) = mpsc::channel::<oneshot::Sender<Output>>(1);

        let jh: tokio::task::JoinHandle<Result<(), anyhow::Error>> = tokio::spawn(gatherer_runner::<
            QUEUE_TOPIC_ID,
            QueueItem,
            Sub,
            Builder,
            C,
        >(
            stream,
            create_builder_config,
            base_queue_key.clone(),
            qk.clone(),
            trigger_rx,
        ));

        (Self { qk, trigger_tx }, jh)
    }

    pub async fn stop_gracefully(&mut self) -> anyhow::Result<()> {
        self.qk.begin_shutdown()?;
        let (response_tx, response_rx) = oneshot::channel();
        self.trigger_tx.send(response_tx).await?;
        let _result = response_rx.await?;
        Ok(())
    }
    pub async fn finalize_gathering_and_update_queue_key(&mut self, unique_id: u128) -> anyhow::Result<Output> {
        self.qk.set_unique_id(unique_id)?;
        let (response_tx, response_rx) = oneshot::channel();
        self.trigger_tx.send(response_tx).await?;
        let result = response_rx.await?;
        Ok(result)
    }
}

#[derive(Clone)]
pub struct EphemeralQueueGathererWithTree<
    const QUEUE_TOPIC_ID: u32,
    QueueItem: PCoreQueueItemBase,
    Output: Sized + Send + Sync + 'static,
> {
    qk: QueueKeyStatusManager<QUEUE_TOPIC_ID, QueueItem>,
    trigger_tx: mpsc::Sender<oneshot::Sender<Output>>,
}

impl<const QUEUE_TOPIC_ID: u32, QueueItem: PCoreQueueItemBase + 'static, Output: Send + Sync>
    EphemeralQueueGathererWithTree<QUEUE_TOPIC_ID, QueueItem, Output>
{
    pub fn new<
        Sub: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
        C: Clone + Send + Sync + 'static,
        Hash: QHashBase + Send + Sync + 'static,
        Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static,
        Builder: QueueGathererItemBuilderWithTree<C, SimpleMemoryMerkleRecorderStore<Hasher, Hash>, Output = Output>
            + Send
            + Sync
            + 'static,
    >(
        stream: Arc<Sub>,
        create_builder_config: C,
        base_queue_key: QPStandardUniqueIdQueueKey<QUEUE_TOPIC_ID, QueueItem>,
        tree: SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
    ) -> (Self, tokio::task::JoinHandle<Result<(), anyhow::Error>>) {
        Self::new_with_status::<Sub, C, Hash, Hasher, Builder>(stream, create_builder_config, base_queue_key, tree, {
            let status = ProcessorStatus::new();
            status.mark_running();
            status
        })
    }
    pub fn new_with_status<
        Sub: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
        C: Clone + Send + Sync + 'static,
        Hash: QHashBase + Send + Sync + 'static,
        Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static,
        Builder: QueueGathererItemBuilderWithTree<C, SimpleMemoryMerkleRecorderStore<Hasher, Hash>, Output = Output>
            + Send
            + Sync
            + 'static,
    >(
        stream: Arc<Sub>,
        create_builder_config: C,
        base_queue_key: QPStandardUniqueIdQueueKey<QUEUE_TOPIC_ID, QueueItem>,
        tree: SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
        status: ProcessorStatus,
    ) -> (Self, tokio::task::JoinHandle<Result<(), anyhow::Error>>) {
        Self::new_with_status_shared::<Sub, C, Hash, Hasher, Builder>(
            stream,
            create_builder_config,
            base_queue_key,
            Arc::new(tokio::sync::RwLock::new(tree)),
            status,
        )
    }
    pub fn new_with_status_shared<
        Sub: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
        C: Clone + Send + Sync + 'static,
        Hash: QHashBase + Send + Sync + 'static,
        Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static,
        Builder: QueueGathererItemBuilderWithTree<C, SimpleMemoryMerkleRecorderStore<Hasher, Hash>, Output = Output>
            + Send
            + Sync
            + 'static,
    >(
        stream: Arc<Sub>,
        create_builder_config: C,
        base_queue_key: QPStandardUniqueIdQueueKey<QUEUE_TOPIC_ID, QueueItem>,
        tree: Arc<tokio::sync::RwLock<SimpleMemoryMerkleRecorderStore<Hasher, Hash>>>,
        status: ProcessorStatus,
    ) -> (Self, tokio::task::JoinHandle<Result<(), anyhow::Error>>) {
        let qk = QueueKeyStatusManager::new_with_status(base_queue_key.clone(), status);
        let (trigger_tx, trigger_rx) = mpsc::channel::<oneshot::Sender<Output>>(1);

        let jh: tokio::task::JoinHandle<Result<(), anyhow::Error>> =
            tokio::spawn(gatherer_runner_for_tree::<
                QUEUE_TOPIC_ID,
                QueueItem,
                Sub,
                Builder,
                C,
                Hash,
                Hasher,
            >(
                stream,
                create_builder_config,
                base_queue_key.clone(),
                tree,
                qk.clone(),
                trigger_rx,
            ));

        (Self { qk, trigger_tx }, jh)
    }

    pub async fn stop_gracefully(&mut self) -> anyhow::Result<()> {
        self.qk.begin_shutdown()?;
        let (response_tx, response_rx) = oneshot::channel();
        self.trigger_tx.send(response_tx).await?;
        let _result = response_rx.await?;
        Ok(())
    }

    pub async fn finalize_gathering_and_update_queue_key(
        &mut self,
        unique_id: u128,
    ) -> anyhow::Result<Output> {
        self.qk.set_unique_id(unique_id)?;
        let (response_tx, response_rx) = oneshot::channel();
        if response_rx.is_terminated() {
            anyhow::bail!("GATHERER_{QUEUE_TOPIC_ID}: Response channel was terminated before sending.");
        }else if response_tx.is_closed() {
            anyhow::bail!("GATHERER_{QUEUE_TOPIC_ID}: Response channel was closed before sending.");
        }
        tracing::info!("start finish finalize_gathering_and_update_queue_key for GATHERER_{QUEUE_TOPIC_ID}");
        self.trigger_tx.send(response_tx).await?;
        let result = response_rx.await?;
        tracing::info!("end finish finalize_gathering_and_update_queue_key for GATHERER_{QUEUE_TOPIC_ID}");
        Ok(result)
    }
}
pub async fn gatherer_runner<
    const QUEUE_TOPIC_ID: u32,
    QueueItem: PCoreQueueItemBase,
    Sub: QStandardEphemeralQueueSubscriber + Send + Sync,
    Builder: QueueGathererItemBuilder<C> + Send + Sync,
    C: Clone + Send + Sync + 'static,
>(
    stream: Arc<Sub>,
    create_builder_config: C,
    mut queue_key: QPStandardUniqueIdQueueKey<QUEUE_TOPIC_ID, QueueItem>,
    queue_key_helper: QueueKeyStatusManager<QUEUE_TOPIC_ID, QueueItem>,
    mut trigger_rx: mpsc::Receiver<oneshot::Sender<Builder::Output>>,
) -> anyhow::Result<()> {
    loop {
        if !queue_key_helper.should_run() {
            tracing::error!("GATHERER_{QUEUE_TOPIC_ID}: Processor entered {:?}; stopping gatherer", queue_key_helper.status.state());
            return Ok(());
        }
        let mut builder = match Builder::create_new(queue_key.unique_id, create_builder_config.clone()).await {
            Ok(builder) => builder,
            Err(err) => {
                tracing::error!(
                    "GATHERER: Error creating new builder for queue topic ID {QUEUE_TOPIC_ID}: {:?}, retrying in 5s",
                    err
                );
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };
        tracing::info!("GATHERER: Starting new gathering phase with unique_id: {}, realm_id: {}, realm_sub_id: {}",
                      queue_key.unique_id, queue_key.realm_id, queue_key.realm_sub_id);
        if let Err(e) = stream
            .ensure_consumer(&queue_key, queue_key.realm_id, queue_key.realm_sub_id, queue_key.unique_id, queue_key.task_group as u32)
            .await
        {
            tracing::warn!("GATHERER_{QUEUE_TOPIC_ID}: ensure_consumer for unique_id {} failed: {}; proceeding with existing consumer state",
                queue_key.unique_id, e);
        }
        if trigger_rx.is_closed() {
            tracing::info!("GATHERER_{QUEUE_TOPIC_ID}: Trigger channel closed before gathering started, stopping gatherer.");
            return Ok(());
        }
        'gathering: loop {
            if !queue_key_helper.should_run() {
                tracing::error!("GATHERER_{QUEUE_TOPIC_ID}: Processor entered {:?}; stopping gatherer", queue_key_helper.status.state());
                return Ok(());
            }
            if trigger_rx.is_closed() {
                tracing::info!("GATHERER_{QUEUE_TOPIC_ID}: Trigger channel closed, shutting down gatherer.");
                return Ok(());
            }
            //tracing::info!("GATHERER_{QUEUE_TOPIC_ID}: Waiting for messages or trigger...");
            tokio::select! {
                // Biased ensures we check for a processor trigger first for better responsiveness.
                biased;

                // A trigger from the Processor was received.
                Some(responder) = trigger_rx.recv() => {
                    tracing::info!("GATHERER: Interrupted by Processor. Preparing to hand over");
                    queue_key = queue_key_helper.get_queue_key()?;
                    let should_run = queue_key_helper.should_run();
                    tracing::info!("GATHERER: Current unique ID: {}, should_run: {}", queue_key.unique_id, should_run);

                    match builder.finalize().await {
                        Ok(finalized_output) => {
                            tracing::info!("GATHERER: Finalized output prepared, sending to processor.");
                            if responder.send(finalized_output).is_err() {
                                tracing::error!("GATHERER: Failed to send data to processor. The receiver was dropped.");
                            }else{
                                tracing::info!("GATHERER: Successfully handed over data to processor.");
                            }
                        }
                        Err(err) => {
                            tracing::error!(
                                "GATHERER: Error during finalize for queue topic ID {QUEUE_TOPIC_ID}: {:?}; processor will retry",
                                err
                            );
                        }
                    }
                    if !should_run {
                        return Ok(());
                    }
                    if trigger_rx.is_closed() {
                        tracing::info!("GATHERER_{QUEUE_TOPIC_ID}: Trigger channel closed after handing over, stopping gatherer.");
                        return Ok(());
                    }

                    break 'gathering; // Break inner loop to start a new cycle.
                },

                // A new message from NATS stream.
                msgs =     stream.dump_entire_ephemeral_queue_bytes(&queue_key, queue_key.realm_id, queue_key.realm_sub_id, queue_key.unique_id, queue_key.task_group as u32, 50000) => {
                    match msgs {
                        Ok(d) => {
                            if d.len() != 0 {
                                tracing::info!("GATHERER: Received {} items from queue.", d.len());
                                if let Err(err) = builder.update_from_many_queue_items(d).await {
                                    tracing::error!(
                                        "GATHERER: Error updating from queue items for topic {QUEUE_TOPIC_ID}: {:?}; restarting gather cycle",
                                        err
                                    );
                                    break 'gathering;
                                }
                            }
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            //builder.update_from_queue_item(d).await?;
                        },
                        Err(err) => {
                            tracing::error!("GATHERER: Error receiving message: {}", err);
                            // Potentially break or sleep before retrying
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        },
                    }
                }
            }
        }
        tracing::info!("GATHERER: Handoff complete. Cycle restarting.");
    }
}

pub async fn gatherer_runner_for_tree<
    const QUEUE_TOPIC_ID: u32,
    QueueItem: PCoreQueueItemBase,
    Sub: QStandardEphemeralQueueSubscriber + Send + Sync,
    Builder: QueueGathererItemBuilderWithTree<C, SimpleMemoryMerkleRecorderStore<Hasher, Hash>> + Send + Sync,
    C: Clone + Send + Sync + 'static,
    Hash: QHashBase + Send + Sync + 'static,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static,
>(
    stream: Arc<Sub>,
    create_builder_config: C,
    mut queue_key: QPStandardUniqueIdQueueKey<QUEUE_TOPIC_ID, QueueItem>,
    tree: Arc<tokio::sync::RwLock<SimpleMemoryMerkleRecorderStore<Hasher, Hash>>>,
    queue_key_helper: QueueKeyStatusManager<QUEUE_TOPIC_ID, QueueItem>,
    mut trigger_rx: mpsc::Receiver<oneshot::Sender<Builder::Output>>,
) -> anyhow::Result<()> {
    loop {
        if !queue_key_helper.should_run() {
            tracing::error!("GATHERER_{QUEUE_TOPIC_ID}: Processor entered {:?}; stopping gatherer", queue_key_helper.status.state());
            return Ok(());
        }
        let mut builder = match {
            let mut tree = tree.write().await;
            Builder::create_new_with_tree(&mut *tree, queue_key.unique_id, create_builder_config.clone()).await
        } {
            Ok(builder) => builder,
            Err(err) => {
                tracing::error!(
                    "GATHERER_{QUEUE_TOPIC_ID}: Error creating new builder: {:?}, retrying in 5s",
                    err
                );
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };
        tracing::info!("GATHERER_{QUEUE_TOPIC_ID}: Starting new gathering phase with unique_id: {}, realm_id: {}, realm_sub_id: {}",
                      queue_key.unique_id, queue_key.realm_id, queue_key.realm_sub_id);
        if let Err(e) = stream
            .ensure_consumer(&queue_key, queue_key.realm_id, queue_key.realm_sub_id, queue_key.unique_id, queue_key.task_group as u32)
            .await
        {
            tracing::warn!("GATHERER_{QUEUE_TOPIC_ID}: ensure_consumer for unique_id {} failed: {}; proceeding with existing consumer state",
                queue_key.unique_id, e);
        }
        if trigger_rx.is_closed() {
            tracing::info!("GATHERER_{QUEUE_TOPIC_ID}: Trigger channel closed before gathering started, stopping gatherer.");
            return Ok(());
        }
        'gathering: loop {
            if !queue_key_helper.should_run() {
                tracing::error!("GATHERER_{QUEUE_TOPIC_ID}: Processor entered {:?}; stopping gatherer", queue_key_helper.status.state());
                return Ok(());
            }
            /*
            if trigger_rx.is_closed() {
                tracing::info!("GATHERER_{QUEUE_TOPIC_ID}: Trigger channel closed, stopping gatherer.");
                return Ok(());
            }
            */
            //tracing::info!("GATHERER_{QUEUE_TOPIC_ID}: Waiting for messages or trigger...");

            tokio::select! {
                // Biased ensures we check for a processor trigger first for better responsiveness.
                biased;

                // A trigger from the Processor was received.
                Some(responder) = trigger_rx.recv() => {
                    let old_unique_id = queue_key.unique_id;
                    let old_queue_key = queue_key.clone();
                    tracing::info!("GATHERER_{QUEUE_TOPIC_ID}: Interrupted by Processor. Preparing to hand over");
                    queue_key = queue_key_helper.get_queue_key()?;
                    let new_unique_id = queue_key.unique_id;
                    tracing::info!("GATHERER_{QUEUE_TOPIC_ID}: Switching from old unique_id {} to new unique_id {}", old_unique_id, new_unique_id);
                    let should_run = queue_key_helper.should_run();
                    let mut trigger_ok = true;
                    let remaining_items_bytes = match stream
                        .dump_entire_ephemeral_queue_bytes(
                            &old_queue_key,
                            old_queue_key.realm_id,
                            old_queue_key.realm_sub_id,
                            old_unique_id,
                            old_queue_key.task_group as u32,
                            usize::MAX,
                        )
                        .await
                    {
                        Ok(items) => items,
                        Err(err) => {
                            let err_string = err.to_string();
                            if err_string.contains("consumer not found") {
                                tracing::warn!(
                                    "GATHERER_{QUEUE_TOPIC_ID}: Missing consumer while draining old unique_id {}; treating as empty queue: {}",
                                    old_unique_id,
                                    err_string
                                );
                                Vec::new()
                            } else {
                                tracing::warn!(
                                    "GATHERER_{QUEUE_TOPIC_ID}: Error draining old unique_id {}; continuing with empty queue so processor can retry: {}",
                                    old_unique_id,
                                    err_string
                                );
                                trigger_ok = false;
                                Vec::new()
                            }
                        }
                    };
                    tracing::info!("GATHERER_{QUEUE_TOPIC_ID}: Processing {} remaining items from old unique_id {} before finalize", remaining_items_bytes.len(), old_unique_id);
                    if !remaining_items_bytes.is_empty() {
                        if let Err(err) = {
                            let mut tree = tree.write().await;
                            builder.update_from_many_queue_items_with_tree(&mut *tree, remaining_items_bytes).await
                        } {
                            tracing::error!(
                                "GATHERER_{QUEUE_TOPIC_ID}: Error updating from remaining items: {:?}; processor will retry",
                                err
                            );
                            trigger_ok = false;
                        }
                    }
                    if trigger_ok {
                        // Pre-finalize drain: one more drain right before finalize
                        // to capture endcaps that arrived during the initial drain +
                        // update_from_many_queue_items_with_tree above.
                        let pre_final_items = match stream
                            .dump_entire_ephemeral_queue_bytes(
                                &old_queue_key,
                                old_queue_key.realm_id,
                                old_queue_key.realm_sub_id,
                                old_unique_id,
                                old_queue_key.task_group as u32,
                                usize::MAX,
                            )
                            .await
                        {
                            Ok(items) => items,
                            Err(_) => Vec::new(),
                        };
                        if !pre_final_items.is_empty() {
                            tracing::info!(
                                "GATHERER_{QUEUE_TOPIC_ID}: Captured {} pre-finalize items for old unique_id {}",
                                pre_final_items.len(), old_unique_id
                            );
                            if let Err(err) = {
                                let mut tree = tree.write().await;
                                builder.update_from_many_queue_items_with_tree(&mut *tree, pre_final_items).await
                            } {
                                tracing::error!(
                                    "GATHERER_{QUEUE_TOPIC_ID}: Error updating from pre-finalize items: {:?}; processor will retry",
                                    err
                                );
                                trigger_ok = false;
                            }
                        }
                    }

                    if trigger_ok {
                        match {
                            let mut tree = tree.write().await;
                            builder.finalize_with_tree(&mut *tree).await
                        } {
                            Ok(finalized_output) => {
                                tracing::info!("GATHERER_{QUEUE_TOPIC_ID}: Finalized output prepared, sending to processor.");
                                if responder.send(finalized_output).is_err() {
                                    tracing::error!("GATHERER_{QUEUE_TOPIC_ID}: Failed to send data to processor. The receiver was dropped.");
                                }else{
                                    tracing::info!("GATHERER_{QUEUE_TOPIC_ID}: Successfully handed over data to processor.");
                                }
                            }
                            Err(err) => {
                                tracing::error!(
                                    "GATHERER_{QUEUE_TOPIC_ID}: Error during finalize: {:?}; processor will retry",
                                    err
                                );
                            }
                        }
                    } else {
                        tracing::error!("GATHERER_{QUEUE_TOPIC_ID}: Skipped finalize after update error; processor will retry.");
                    }

                    // Post-finalize drain: capture any items that arrived during finalize.
                    // If found, they need to be processed — but the builder is already
                    // finalized/consumed. Since we use ensure_consumer (not recreate),
                    // the consumer still exists and these messages will be replayed
                    // via DeliverPolicy::All on the next dump_entire_ephemeral_queue_bytes
                    // call for this unique_id. The next gatherer cycle won't drain this
                    // old unique_id, so we must NOT delete the consumer here. The processor
                    // will eventually re-process this checkpoint and pick up the messages.
                    let late_items = match stream
                        .dump_entire_ephemeral_queue_bytes(
                            &old_queue_key,
                            old_queue_key.realm_id,
                            old_queue_key.realm_sub_id,
                            old_unique_id,
                            old_queue_key.task_group as u32,
                            usize::MAX,
                        )
                        .await
                    {
                        Ok(items) => items,
                        Err(_) => Vec::new(),
                    };
                    if !late_items.is_empty() {
                        tracing::warn!(
                            "GATHERER_{QUEUE_TOPIC_ID}: {} late items arrived during finalize for old unique_id {} — NOT deleting consumer; messages will be replayed on next drain",
                            late_items.len(), old_unique_id
                        );
                    } else {
                        if let Err(err) = stream
                            .delete_ephemeral_queue_consumer(
                                &old_queue_key,
                                old_queue_key.realm_id,
                                old_queue_key.realm_sub_id,
                                old_unique_id,
                                old_queue_key.task_group as u32,
                            )
                            .await
                        {
                            tracing::warn!(
                                "GATHERER_{QUEUE_TOPIC_ID}: Failed to delete old consumer for unique_id {} after handoff: {}",
                                old_unique_id,
                                err
                            );
                        }
                    }
                    if !should_run {
                        return Ok(());
                    }

                    break 'gathering; // Break inner loop to start a new cycle.
                },

                // A new message from NATS stream.
                msgs =     stream.dump_entire_ephemeral_queue_bytes(&queue_key, queue_key.realm_id, queue_key.realm_sub_id, queue_key.unique_id, queue_key.task_group as u32, 50000) => {
                    match msgs {
                        Ok(d) => {
                            if d.len() != 0 {
                                tracing::info!("GATHERER_{QUEUE_TOPIC_ID}: Received {} items from queue.", d.len());
                                if let Err(err) = {
                                    let mut tree = tree.write().await;
                                    builder.update_from_many_queue_items_with_tree(&mut *tree, d).await
                                } {
                                    tracing::error!(
                                        "GATHERER_{QUEUE_TOPIC_ID}: Error updating from queue items: {:?}; restarting gather cycle",
                                        err
                                    );
                                    break 'gathering;
                                }

                            }
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            //builder.update_from_queue_item(d).await?;
                        },
                        Err(err) => {
                            tracing::error!("GATHERER_{QUEUE_TOPIC_ID}: Error receiving message: {}", err);
                            // Potentially break or sleep before retrying
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        },
                    }
                }
            }
        }
        tracing::info!("GATHERER_{QUEUE_TOPIC_ID}: Handoff complete. Cycle restarting.");
    }
}
