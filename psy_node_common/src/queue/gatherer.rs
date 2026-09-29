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
    mut tree: SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
    queue_key_helper: QueueKeyStatusManager<QUEUE_TOPIC_ID, QueueItem>,
    mut trigger_rx: mpsc::Receiver<oneshot::Sender<Builder::Output>>,
) -> anyhow::Result<()> {
    loop {
        if !queue_key_helper.should_run() {
            tracing::error!("GATHERER_{QUEUE_TOPIC_ID}: Processor entered {:?}; stopping gatherer", queue_key_helper.status.state());
            return Ok(());
        }
        let mut builder = match Builder::create_new_with_tree(&mut tree, queue_key.unique_id, create_builder_config.clone()).await {
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
                        if let Err(err) = builder.update_from_many_queue_items_with_tree(&mut tree, remaining_items_bytes).await {
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
                            if let Err(err) = builder.update_from_many_queue_items_with_tree(&mut tree, pre_final_items).await {
                                tracing::error!(
                                    "GATHERER_{QUEUE_TOPIC_ID}: Error updating from pre-finalize items: {:?}; processor will retry",
                                    err
                                );
                                trigger_ok = false;
                            }
                        }
                    }

                    if trigger_ok {
                        match builder.finalize_with_tree(&mut tree).await {
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
                                if let Err(err) = builder.update_from_many_queue_items_with_tree(&mut tree, d).await {
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

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, VecDeque};
    use std::sync::Mutex;

    use async_trait::async_trait;
    use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
    use parth_core::{
        data::queue::queue_key::{PCoreQueueItemBase, QPBaseQueueType, QPStandardUniqueIdQueueKey},
        pgoldilocks::PoseidonHasher,
        utils::QPGenRandom,
        PHash,
    };
    use psy_data::v1::qdata::public_key::PZKPublicKeyInfo;
    use psy_node_core::queue::{
        infrastructure::QStandardQueueBase,
    };

    use super::{GathererValue, QueueKeyStatusManager};

    type QueueItem = PZKPublicKeyInfo<PHash>;
    type TestQueueKey = QPStandardUniqueIdQueueKey<7, QueueItem>;

    fn base_queue_key(unique_id: u128) -> TestQueueKey {
        QPStandardUniqueIdQueueKey {
            realm_id: 1,
            realm_sub_id: 2,
            unique_id,
            task_group: 3,
            queue_type: QPBaseQueueType::StandardEphemeral,
            _phantom_queue_item: std::marker::PhantomData,
        }
    }

    #[test]
    fn gatherer_value_set_get_and_shared_clones() {
        let value = GathererValue::new_from_inner(10u64);
        assert_eq!(value.get_value(), 10);

        let clone = value.clone();
        clone.set_value(20);
        // clones share the inner RwLock, so the write is visible everywhere
        assert_eq!(value.get_value(), 20);

        let from_arc = GathererValue::new_from_arc(std::sync::Arc::new(std::sync::RwLock::new(30u64)));
        assert_eq!(from_arc.get_value(), 30);
    }

    #[test]
    fn queue_key_status_manager_tracks_unique_id_and_lifecycle() -> anyhow::Result<()> {
        let manager = QueueKeyStatusManager::<7, QueueItem>::new(base_queue_key(11));

        // `new` marks the processor running, so the gatherer should run
        assert!(manager.should_run());
        let key = manager.get_queue_key()?;
        assert_eq!(key.unique_id, 11);
        assert_eq!(key.realm_id, 1);
        assert_eq!(key.realm_sub_id, 2);
        assert_eq!(key.task_group, 3);

        manager.set_unique_id(22)?;
        assert_eq!(manager.get_queue_key()?.unique_id, 22);

        // after begin_shutdown the manager must stop the gatherer loop
        manager.begin_shutdown()?;
        assert!(!manager.should_run());
        Ok(())
    }

    /// Minimal in-memory stand-in for the ephemeral queue: a per-unique_id FIFO
    /// plus a log of deleted consumers, enough to drive `gatherer_runner(_for_tree)`
    /// through their drain/finalize/delete cycles without real messaging infra.
    #[derive(Default)]
    struct FakeEphemeralSubscriber {
        queues: Mutex<HashMap<u128, VecDeque<Vec<u8>>>>,
        deleted_consumers: Mutex<Vec<u128>>,
    }

    impl FakeEphemeralSubscriber {
        fn with_items(unique_id: u128, items: Vec<Vec<u8>>) -> Self {
            let mut queues = HashMap::new();
            queues.insert(unique_id, VecDeque::from(items));
            Self {
                queues: Mutex::new(queues),
                deleted_consumers: Mutex::new(Vec::new()),
            }
        }

        fn add_items(&self, unique_id: u128, items: Vec<Vec<u8>>) {
            self.queues
                .lock()
                .unwrap()
                .entry(unique_id)
                .or_default()
                .extend(items);
        }

        /// The runner deletes the old consumer only AFTER handing the
        /// finalized output to the processor, so tests must wait for it.
        async fn wait_for_deleted_consumers(&self, expected: Vec<u128>) {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while *self.deleted_consumers.lock().unwrap() != expected {
                assert!(
                    std::time::Instant::now() < deadline,
                    "timed out waiting for deleted consumers {expected:?}, got {:?}",
                    self.deleted_consumers.lock().unwrap()
                );
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        }
    }

    #[async_trait]
    impl QStandardQueueBase for FakeEphemeralSubscriber {
        async fn ensure_stream(&self) -> anyhow::Result<()> {
            Ok(())
        }
        async fn ensure_consumer<QK: parth_core::data::queue::queue_key::PCoreStandardQueueKeyForRealm>(
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
    impl psy_node_core::queue::ephemeral::QStandardEphemeralQueueSubscriber for FakeEphemeralSubscriber {
        async fn wait_for_ephemeral_queue_item_bytes<QK: parth_core::data::queue::queue_key::PCoreStandardQueueKeyForRealm>(
            &self,
            _queue_key: &QK,
            _realm_id: u64,
            _realm_sub_id: u64,
            unique_id: parth_core::QCoreProcCheckpointUniqueId,
            _task_group: u32,
            _timeout_ms: u64,
        ) -> anyhow::Result<Option<Vec<u8>>> {
            Ok(self.queues.lock().unwrap().get_mut(&unique_id).and_then(|q| q.pop_front()))
        }
        async fn wait_for_ephemeral_queue_item<QK: parth_core::data::queue::queue_key::PCoreStandardQueueKeyForRealm>(
            &self,
            _queue_key: &QK,
            _realm_id: u64,
            _realm_sub_id: u64,
            _unique_id: parth_core::QCoreProcCheckpointUniqueId,
            _task_group: u32,
            _timeout_ms: u64,
        ) -> anyhow::Result<Option<QK::QueueItem>> {
            unreachable!("not used by the gatherer runner paths under test")
        }
        async fn dump_entire_ephemeral_queue_bytes<QK: parth_core::data::queue::queue_key::PCoreStandardQueueKeyForRealm>(
            &self,
            _queue_key: &QK,
            _realm_id: u64,
            _realm_sub_id: u64,
            unique_id: parth_core::QCoreProcCheckpointUniqueId,
            _task_group: u32,
            max_items: usize,
        ) -> anyhow::Result<Vec<Vec<u8>>> {
            let drained = self
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
                .unwrap_or_default();
            if drained.is_empty() {
                // mimic a real subscriber waiting on the network: stay pending
                // for a while so the runner parks inside tokio::select! and a
                // buffered processor trigger (checked first, biased) wins over
                // the loop-top shutdown check on the next poll
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Ok(drained)
        }
        async fn dump_entire_ephemeral_queue<QK: parth_core::data::queue::queue_key::PCoreStandardQueueKeyForRealm>(
            &self,
            _queue_key: &QK,
            _realm_id: u64,
            _realm_sub_id: u64,
            _unique_id: parth_core::QCoreProcCheckpointUniqueId,
            _task_group: u32,
            _max_items: usize,
        ) -> anyhow::Result<Vec<QK::QueueItem>> {
            unreachable!("not used by the gatherer runner paths under test")
        }
        async fn consume_ephemeral_queue_item_or_none_bytes<QK: parth_core::data::queue::queue_key::PCoreStandardQueueKeyForRealm>(
            &self,
            _queue_key: &QK,
            _realm_id: u64,
            _realm_sub_id: u64,
            _unique_id: parth_core::QCoreProcCheckpointUniqueId,
            _task_group: u32,
        ) -> anyhow::Result<Option<Vec<u8>>> {
            unreachable!("not used by the gatherer runner paths under test")
        }
        async fn consume_ephemeral_queue_item_or_none<QK: parth_core::data::queue::queue_key::PCoreStandardQueueKeyForRealm>(
            &self,
            _queue_key: &QK,
            _realm_id: u64,
            _realm_sub_id: u64,
            _unique_id: parth_core::QCoreProcCheckpointUniqueId,
            _task_group: u32,
        ) -> anyhow::Result<Option<QK::QueueItem>> {
            unreachable!("not used by the gatherer runner paths under test")
        }
        async fn delete_ephemeral_queue_consumer<QK: parth_core::data::queue::queue_key::PCoreStandardQueueKeyForRealm>(
            &self,
            _queue_key: &QK,
            _realm_id: u64,
            _realm_sub_id: u64,
            unique_id: parth_core::QCoreProcCheckpointUniqueId,
            _task_group: u32,
        ) -> anyhow::Result<()> {
            self.deleted_consumers.lock().unwrap().push(unique_id);
            Ok(())
        }
    }

    /// Shared observability for the recording builders below: every accepted
    /// queue item is appended to `items_log`, and every builder creation bumps
    /// `creations`. Tests use these to synchronize with the runner's async
    /// cycles instead of sleeping on faith.
    #[derive(Default)]
    struct BuilderSignals {
        items_log: Mutex<Vec<Vec<u8>>>,
        creations: std::sync::atomic::AtomicU32,
    }

    impl BuilderSignals {
        fn log_len(&self) -> usize {
            self.items_log.lock().unwrap().len()
        }
        fn log_items(&self) -> Vec<Vec<u8>> {
            self.items_log.lock().unwrap().clone()
        }
        async fn wait_for_log_len(&self, expected: usize) -> anyhow::Result<()> {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while self.log_len() < expected {
                anyhow::ensure!(std::time::Instant::now() < deadline, "timed out waiting for {expected} queued items");
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            Ok(())
        }
        async fn wait_for_creations(&self, expected: u32) -> anyhow::Result<()> {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while self.creations.load(std::sync::atomic::Ordering::SeqCst) < expected {
                anyhow::ensure!(std::time::Instant::now() < deadline, "timed out waiting for {expected} builder creations");
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            Ok(())
        }
    }

    /// Builder for the tree-less runner: records accepted items into the shared
    /// log and reports them to the processor on finalize.
    struct RecordingBuilder {
        created_with_unique_id: u128,
        signals: std::sync::Arc<BuilderSignals>,
    }

    #[async_trait]
    impl super::QueueGathererItemBuilder<std::sync::Arc<BuilderSignals>> for RecordingBuilder {
        type Output = (u128, Vec<Vec<u8>>);

        async fn create_new(unique_id: u128, signals: std::sync::Arc<BuilderSignals>) -> anyhow::Result<Self> {
            signals.creations.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Self { created_with_unique_id: unique_id, signals })
        }
        async fn update_from_queue_item(&mut self, item: Vec<u8>) -> anyhow::Result<()> {
            self.signals.items_log.lock().unwrap().push(item);
            Ok(())
        }
        async fn finalize(self) -> anyhow::Result<Self::Output> {
            Ok((self.created_with_unique_id, self.signals.log_items()))
        }
    }

    #[tokio::test]
    async fn gatherer_runner_collects_items_and_restarts_cycles() -> anyhow::Result<()> {
        let signals = std::sync::Arc::new(BuilderSignals::default());
        let subscriber = std::sync::Arc::new(FakeEphemeralSubscriber::with_items(
            11,
            vec![vec![1, 1], vec![1, 2]],
        ));
        let (mut gatherer, join_handle) = super::EphemeralQueueGatherer::<7, QueueItem, (u128, Vec<Vec<u8>>)>::new::<
            FakeEphemeralSubscriber,
            std::sync::Arc<BuilderSignals>,
            RecordingBuilder,
        >(std::sync::Arc::clone(&subscriber), std::sync::Arc::clone(&signals), base_queue_key(11));

        // wait until the runner has actually consumed both items before
        // triggering finalize: the tree-less runner does not drain on trigger
        signals.wait_for_log_len(2).await?;
        let (created_with, items) = gatherer.finalize_gathering_and_update_queue_key(12).await?;
        assert_eq!(created_with, 11);
        assert_eq!(items, vec![vec![1, 1], vec![1, 2]]);

        // a second cycle must be served by a fresh builder on the new unique_id
        subscriber.add_items(12, vec![vec![2, 1]]);
        signals.wait_for_log_len(3).await?;
        let (created_with, items) = gatherer.finalize_gathering_and_update_queue_key(13).await?;
        assert_eq!(created_with, 12);
        assert_eq!(items.last(), Some(&vec![2, 1]));

        gatherer.stop_gracefully().await?;
        join_handle.await??;
        Ok(())
    }

    /// Builder for the tree runner: rejects the poison marker item so the
    /// restart-cycle branch is exercised.
    struct RecordingTreeBuilder {
        created_with_unique_id: u128,
        signals: std::sync::Arc<BuilderSignals>,
    }

    #[async_trait]
    impl super::QueueGathererItemBuilderWithTree<std::sync::Arc<BuilderSignals>, SimpleMemoryMerkleRecorderStore<PoseidonHasher, PHash>>
        for RecordingTreeBuilder
    {
        type Output = (u128, Vec<Vec<u8>>);

        async fn create_new_with_tree(
            _tree: &mut SimpleMemoryMerkleRecorderStore<PoseidonHasher, PHash>,
            unique_id: u128,
            signals: std::sync::Arc<BuilderSignals>,
        ) -> anyhow::Result<Self> {
            signals.creations.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Self { created_with_unique_id: unique_id, signals })
        }
        async fn update_from_queue_item_with_tree(
            &mut self,
            _tree: &mut SimpleMemoryMerkleRecorderStore<PoseidonHasher, PHash>,
            item: Vec<u8>,
        ) -> anyhow::Result<()> {
            anyhow::ensure!(!item.contains(&0xFF), "poison item rejected by test builder");
            self.signals.items_log.lock().unwrap().push(item);
            Ok(())
        }
        async fn update_from_many_queue_items_with_tree(
            &mut self,
            tree: &mut SimpleMemoryMerkleRecorderStore<PoseidonHasher, PHash>,
            items: Vec<Vec<u8>>,
        ) -> anyhow::Result<()> {
            for item in items {
                self.update_from_queue_item_with_tree(tree, item).await?;
            }
            Ok(())
        }
        async fn finalize_with_tree(
            self,
            _tree: &mut SimpleMemoryMerkleRecorderStore<PoseidonHasher, PHash>,
        ) -> anyhow::Result<Self::Output> {
            Ok((self.created_with_unique_id, self.signals.log_items()))
        }
    }

    #[tokio::test]
    async fn tree_gatherer_runner_drains_and_deletes_old_consumer() -> anyhow::Result<()> {
        let signals = std::sync::Arc::new(BuilderSignals::default());
        let subscriber = std::sync::Arc::new(FakeEphemeralSubscriber::with_items(
            21,
            vec![vec![1], vec![2], vec![3]],
        ));
        let tree = SimpleMemoryMerkleRecorderStore::<PoseidonHasher, PHash>::new(32);
        let (mut gatherer, join_handle) =
            super::EphemeralQueueGathererWithTree::<7, QueueItem, (u128, Vec<Vec<u8>>)>::new::<
                FakeEphemeralSubscriber,
                std::sync::Arc<BuilderSignals>,
                PHash,
                PoseidonHasher,
                RecordingTreeBuilder,
            >(std::sync::Arc::clone(&subscriber), std::sync::Arc::clone(&signals), base_queue_key(21), tree);

        let (created_with, items) = gatherer.finalize_gathering_and_update_queue_key(22).await?;
        assert_eq!(created_with, 21);
        assert_eq!(items, vec![vec![1], vec![2], vec![3]]);
        // the consumer for the finalized unique_id must be cleaned up (this
        // happens after the handover, so wait for it)
        subscriber.wait_for_deleted_consumers(vec![21]).await;

        gatherer.stop_gracefully().await?;
        join_handle.await??;
        Ok(())
    }

    #[tokio::test]
    async fn tree_gatherer_runner_restarts_cycle_after_update_error() -> anyhow::Result<()> {
        // the poison item makes the first update fail; the runner must drop the
        // cycle, rebuild, and still answer the next trigger
        let signals = std::sync::Arc::new(BuilderSignals::default());
        let subscriber = std::sync::Arc::new(FakeEphemeralSubscriber::with_items(
            31,
            vec![vec![9], vec![0xFF], vec![8]],
        ));
        let tree = SimpleMemoryMerkleRecorderStore::<PoseidonHasher, PHash>::new(32);
        let (mut gatherer, join_handle) =
            super::EphemeralQueueGathererWithTree::<7, QueueItem, (u128, Vec<Vec<u8>>)>::new::<
                FakeEphemeralSubscriber,
                std::sync::Arc<BuilderSignals>,
                PHash,
                PoseidonHasher,
                RecordingTreeBuilder,
            >(std::sync::Arc::clone(&subscriber), std::sync::Arc::clone(&signals), base_queue_key(31), tree);

        // wait for the poisoned cycle to crash and the replacement builder to
        // spin up before triggering, so the outcome does not depend on which
        // select branch wins the race
        signals.wait_for_creations(2).await?;
        let (created_with, items) = gatherer.finalize_gathering_and_update_queue_key(32).await?;
        assert_eq!(created_with, 31);
        // [9] was accepted before the poison item killed the cycle; the poison
        // itself and the trailing [8] were dropped with the failed batch
        assert_eq!(items, vec![vec![9]]);

        // wait until the runner has finished the post-handover cleanup of the
        // poisoned unique_id before requesting the stop, so the shutdown flag
        // cannot land mid-branch and skip the stop trigger
        subscriber.wait_for_deleted_consumers(vec![31]).await;

        gatherer.stop_gracefully().await?;
        join_handle.await??;
        Ok(())
    }

    #[test]
    fn pzk_public_key_info_queue_item_codec_roundtrip() -> anyhow::Result<()> {
        // sanity-check the queue item type used by the fake subscriber keys
        let item = PZKPublicKeyInfo::<PHash>::qp_rand_gen();
        let encoded = item.encode_queue_item_vec()?;
        assert!(PZKPublicKeyInfo::<PHash>::is_queue_item(&encoded));
        let decoded = PZKPublicKeyInfo::<PHash>::decode_queue_item_ref(&encoded)?;
        assert_eq!(decoded.get_restorable_job_id(), item.get_restorable_job_id());
        assert_eq!(PZKPublicKeyInfo::<PHash>::get_size_hint(), 64);
        assert!(PZKPublicKeyInfo::<PHash>::has_fixed_size());
        Ok(())
    }
}
