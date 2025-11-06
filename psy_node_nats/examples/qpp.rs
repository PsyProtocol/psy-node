use std::{
    any,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use async_nats::{
    jetstream::{
        self,
        consumer::{pull::Config as PullConfig, PullConsumer},
        kv::Store,
    },
    Subject, ToServerAddrs,
};
use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use futures::{future::try_join_all, stream::StreamExt};
use parth_core::{
    data::queue::queue_key::{PCoreQueueItemBase, PCoreStandardQueueKeyForRealm, QPBaseQueueType, QPStandardUniqueIdQueueKey},
    QCoreProcCheckpointUniqueId,
};
use parth_node_nats::queue::NatsJetStreamClient;
use psy_core::job::job_id::QProvingJobDataID;
use psy_node_core::queue::{
    ephemeral::{QStandardEphemeralQueuePublisher, QStandardEphemeralQueueSubscriber},
    worker_queue::{QStandardWorkerQueuePublisher, QStandardWorkerQueueSubscriber},
};
use rand::RngCore;
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

#[async_trait::async_trait]
pub trait QueueGathererItemBuilder: Sized {
    type Output: Sized + Send + Sync;
    async fn create_new(unique_id: u128) -> anyhow::Result<Self>;
    async fn update_from_queue_item(&mut self, item: Vec<u8>) -> anyhow::Result<()>;
    async fn finalize(self) -> anyhow::Result<Self::Output>;
}

#[async_trait::async_trait]
pub trait QueueGathererV2<Output: Sized + Send + Sync> {
    async fn stop_gracefully(&self) -> anyhow::Result<()>;
    async fn finalize_gathering_and_update_queue_key(&self, unique_id: u128) -> anyhow::Result<Output>;
}

// Type alias for the signal from Processor to Gatherer
const USER_INFO_TEST_QUEUE_TOPIC_ID: u32 = 13337;
type QueueKey = QPStandardUniqueIdQueueKey<USER_INFO_TEST_QUEUE_TOPIC_ID, QProvingJobDataID>;

pub struct QueueKeyHelper<const QUEUE_TOPIC_ID: u32, QueueItem: PCoreQueueItemBase> {
    base_queue_key: QPStandardUniqueIdQueueKey<QUEUE_TOPIC_ID, QueueItem>,
    queue_key: Arc<RwLock<QPStandardUniqueIdQueueKey<QUEUE_TOPIC_ID, QueueItem>>>,
}
impl<const QUEUE_TOPIC_ID: u32, QueueItem: PCoreQueueItemBase> QueueKeyHelper<QUEUE_TOPIC_ID, QueueItem> {
    pub fn set_queue_key_unique_id(&self, unique_id: u128) {
        let mut new_queue_key = self.base_queue_key.clone();
        new_queue_key.unique_id = unique_id;
        *self.queue_key.write().unwrap() = new_queue_key;
    }
    pub fn set_queue_key_random(&self) -> QPStandardUniqueIdQueueKey<QUEUE_TOPIC_ID, QueueItem> {
        let rand_u128 = rand::random::<u128>();
        let mut new_queue_key = self.base_queue_key.clone();
        new_queue_key.unique_id = rand_u128;
        *self.queue_key.write().unwrap() = new_queue_key.clone();
        new_queue_key
    }
    pub fn get_queue_key(&self) -> anyhow::Result<QPStandardUniqueIdQueueKey<QUEUE_TOPIC_ID, QueueItem>> {
        Ok(self.queue_key.read().unwrap().clone())  
        
    }
    pub fn new(base_queue_key: QPStandardUniqueIdQueueKey<QUEUE_TOPIC_ID, QueueItem>) -> Self {
        let queue_key = Arc::new(RwLock::new(base_queue_key.clone()));
        Self {
            base_queue_key,
            queue_key,
        }
    }
}

pub struct QueueGatherer<
    const QUEUE_TOPIC_ID: u32,
    QueueItem: PCoreQueueItemBase,
    Builder: QueueGathererItemBuilder + Send + Sync,
    Sub: QStandardEphemeralQueueSubscriber + Send + Sync,
> {
    queue_key_helper: Arc<QueueKeyHelper<QUEUE_TOPIC_ID, QueueItem>>,
    stream: Arc<Sub>,
    _phantom: std::marker::PhantomData<Builder>,
}

impl<
        const QUEUE_TOPIC_ID: u32,
        QueueItem: PCoreQueueItemBase,
        Builder: QueueGathererItemBuilder + Send + Sync,
        Sub: QStandardEphemeralQueueSubscriber + Send + Sync,
    > QueueGatherer<QUEUE_TOPIC_ID, QueueItem, Builder, Sub>
{
    pub fn new(queue_key_helper: Arc<QueueKeyHelper<QUEUE_TOPIC_ID, QueueItem>>, sub: Arc<Sub>) -> Self {
        Self {
            queue_key_helper,
            stream: sub,
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn set_new_queue_id_and_dump(&self, unique_id: u128) {
        self.queue_key_helper.set_queue_key_unique_id(unique_id);
    }
}

/// The Gatherer's main function.
/// It runs in a continuous loop, handling the "gathering -> handoff" cycle.
async fn gatherer<
    const QUEUE_TOPIC_ID: u32,
    QueueItem: PCoreQueueItemBase,
    Sub: QStandardEphemeralQueueSubscriber,
    Builder: QueueGathererItemBuilder + Send + Sync,
>(
    stream: Arc<Sub>,
    mut queue_key: QPStandardUniqueIdQueueKey<QUEUE_TOPIC_ID, QueueItem>,
    queue_key_helper: Arc<QueueKeyHelper<QUEUE_TOPIC_ID, QueueItem>>,
    mut trigger_rx: mpsc::Receiver<oneshot::Sender<Builder::Output>>,
) -> anyhow::Result<()> {
    // Create a durable consumer. A pull-based consumer gives us fine-grained
    // control. **FIX:** The `expires` field is the modern equivalent of
    // `max_wait` for a pull. It tells the NATS server to close the pull request
    // after this period of inactivity.

    // The main cycle loop
    loop {
        let mut builder = Builder::create_new(queue_key.unique_id).await?;
        info!("GATHERER: Starting new gathering phase.");

        // **FIX:** Get a message stream. This stream will yield messages until it times
        // out based on the `expires` config above, or until it's dropped.

        // This is the inner loop where we actually consume from NATS.
        'gathering: loop {
            tokio::select! {
                // Biased ensures we check for a processor trigger first for better responsiveness.
                biased;

                // A trigger from the Processor was received.
                Some(responder) = trigger_rx.recv() => {
                    info!("GATHERER: Interrupted by Processor. Preparing to hand over");
                    queue_key = queue_key_helper.get_queue_key()?;


                    if responder.send(builder.finalize().await?).is_err() {
                        error!("GATHERER: Failed to send data to processor. The receiver was dropped.");
                    }
                    break 'gathering; // Break inner loop to start a new cycle.
                },

                // A new message from NATS stream.
                msgs =     stream.dump_entire_ephemeral_queue_bytes(&queue_key, queue_key.realm_id, queue_key.realm_sub_id, queue_key.unique_id, queue_key.task_group as u32, 50000) => {
                    match msgs {
                        Ok(d) => {
                            if d.len() != 0 {
                                info!("GATHERER: Received {} items from queue.", d.len());
                                for item in d {
                                    builder.update_from_queue_item(item).await?;
                                }
                            }
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            //builder.update_from_queue_item(d).await?;
                        },
                        Err(err) => {
                            error!("GATHERER: Error receiving message: {}", err);
                            // Potentially break or sleep before retrying
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        },
                    }
                }
            }
        }
        info!("GATHERER: Handoff complete. Cycle restarting.");
    }
}

/// The Processor's main function.
async fn processor<const QUEUE_TOPIC_ID: u32, QueueItem: PCoreQueueItemBase, Builder: QueueGathererItemBuilder + Send + Sync>(
    trigger_tx: mpsc::Sender<oneshot::Sender<Builder>>,
    queue_key_helper: Arc<QueueKeyHelper<QUEUE_TOPIC_ID, QueueItem>>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        interval.tick().await;
        info!("PROCESSOR: Triggering gatherer to collect data...");
        queue_key_helper.set_queue_key_random();

        let (response_tx, response_rx) = oneshot::channel();

        if trigger_tx.send(response_tx).await.is_err() {
            error!("PROCESSOR: Failed to send trigger. Gatherer has likely panicked.");
            break;
        }

        match response_rx.await {
            Ok(builder_result) => {
                info!("PROCESSOR: Received items. Starting heavy computation...");
                // --- Heavy Computation Step ---
                info!("PROCESSOR: Heavy computation finished.");

                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(_) => {
                error!("PROCESSOR: Gatherer dropped the response channel before sending data.");
            }
        }
    }
}
fn rand_queue_item() -> Vec<u8> {
    let mut bytes = [0u8; 300];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.to_vec()
}
/// The Processor's main function.
async fn fake_api(
    client: Arc<NatsJetStreamClient>,
    queue_key_helper: Arc<QueueKeyHelper<USER_INFO_TEST_QUEUE_TOPIC_ID, QProvingJobDataID>>,
) -> anyhow::Result<()> {
    let thousand_items = (0..10000).map(|_| rand_queue_item()).collect::<Vec<Vec<u8>>>();
    let thousand_refs = thousand_items.iter().map(|item| item.as_slice()).collect::<Vec<&[u8]>>();

    loop {
        info!("FAKE API: Sending data...");
        tokio::time::sleep(Duration::from_millis(100)).await;
        for _ in 0..50 {
            let queue_key = queue_key_helper.get_queue_key()?;
            client
                .publish_many_ephemeral_queue_items_bytes_ref(
                    &queue_key,
                    queue_key.realm_id,
                    queue_key.realm_sub_id,
                    queue_key.unique_id,
                    queue_key.task_group as u32,
                    &thousand_refs,
                )
                .await?;
        }
        println!("sent 100k items");
        /*
        for item in &thousand_items {
            client
                .publish_ephemeral_queue_item_bytes_ref(
                    &queue_key,
                    queue_key.realm_id,
                    queue_key.realm_sub_id,
                    queue_key.unique_id,
                    queue_key.task_group as u32,
                    item,
                )
                .await?;
            */
    }
}

pub struct SimpleDataBuilder {
    data: Vec<u8>,
    count: usize,
}

#[async_trait::async_trait]
impl QueueGathererItemBuilder for SimpleDataBuilder {
    type Output = Self;
    async fn create_new(_unique_id: u128) -> anyhow::Result<Self> {
        Ok(Self { data: Vec::new(), count: 0 })
    }

    async fn update_from_queue_item(&mut self, item: Vec<u8>) -> anyhow::Result<()> {
        self.data.extend_from_slice(&item);
        self.count += 1;
        Ok(())
    }
    async fn finalize(self) -> anyhow::Result<Self::Output> {
        info!("BUILDER: Finalized with {} bytes of data and {} items.", self.data.len(), self.count);
        Ok(self)
    }
}

// **FIX:** main now returns anyhow::Result
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let subscriber = FmtSubscriber::builder().with_max_level(Level::INFO).finish();
    tracing::subscriber::set_global_default(subscriber)?;
    let base_namespace = "EX_JOB_STREAM".to_string();
    let realm_id = 1u64;
    let realm_sub_id = 1u64;
    let ex_queue_type = 1337u32;
    let task_group = 1u64;

    let timeout_ms = 5000u64;
    let standard_ephemeral_queue_pull_config: PullConfig = PullConfig {
        ack_policy: jetstream::consumer::AckPolicy::All,
        ack_wait: Duration::from_millis(timeout_ms),
        max_deliver: 1,
        replay_policy: jetstream::consumer::ReplayPolicy::Instant,
        deliver_policy: jetstream::consumer::DeliverPolicy::All,
        max_ack_pending: 100000,
        ..Default::default()
    };
    let worker_queue_pull_config = PullConfig {
        ack_policy: jetstream::consumer::AckPolicy::Explicit,
        max_deliver: 20,
        replay_policy: jetstream::consumer::ReplayPolicy::Instant,
        deliver_policy: jetstream::consumer::DeliverPolicy::All,
        max_ack_pending: 100000,
        ..Default::default()
    };
    let standard_jet_stream_config = jetstream::stream::Config { ..Default::default() };
    let client = NatsJetStreamClient::new_connection(
        base_namespace,
        "localhost:4222".to_string(),
        standard_ephemeral_queue_pull_config,
        worker_queue_pull_config,
        standard_jet_stream_config,
        timeout_ms,
    )
    .await?;

    let (trigger_tx, trigger_rx) = mpsc::channel::<oneshot::Sender<SimpleDataBuilder>>(1);

    // Spawn the tasks
    let queue_key = QueueKey {
        realm_id,
        realm_sub_id,
        unique_id: 0u128,
        task_group,
        queue_type: QPBaseQueueType::StandardEphemeral,
        _phantom_queue_item: std::marker::PhantomData,
    };

    let queue_key_helper = Arc::new(QueueKeyHelper::new(queue_key));

    let stream = Arc::new(client);
    let gatherer_handle = tokio::spawn(gatherer::<USER_INFO_TEST_QUEUE_TOPIC_ID, QProvingJobDataID, _, SimpleDataBuilder>(
        stream.clone(),
        queue_key,
        queue_key_helper.clone(),
        trigger_rx,
    ));
    let processor_handle = tokio::spawn(processor::<USER_INFO_TEST_QUEUE_TOPIC_ID, QProvingJobDataID, SimpleDataBuilder>(
        trigger_tx,
        queue_key_helper.clone(),
    ));
    let fake_api_handle = tokio::spawn(fake_api(stream.clone(), queue_key_helper.clone()));

    tokio::select! {
        res = gatherer_handle => {
            error!("Gatherer task exited unexpectedly!");
            res??; // Propagate the error from the task
        },
        res = processor_handle => {
            warn!("Processor task exited.");
            res?;
        },
        res = fake_api_handle => {
            warn!("fake api task exited.");
            let _ = res?;
        },
    }

    Ok(())
}
