use std::{
    sync::{Arc, RwLock},
    time::Duration,
};

use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
use parth_core::{crypto::hash::traits::MerkleZeroHasher, data::queue::queue_key::{PCoreQueueItemBase, QPStandardUniqueIdQueueKey}, protocol::core_types::QHashBase};
use psy_node_core::{
    queue::{
        ephemeral::QStandardEphemeralQueueSubscriber,
        realm_processor_deferred_actor_input::{
            RealmProcessorDeferredActorInput,
            RealmProcessorDeferredActorInputDigest,
        },
        realm_processor_durable_capture::{
            RealmProcessorDurableCapturedGeneration,
            RealmProcessorDurableGenerationDigest,
        },
        recoverable_ephemeral::{
            PendingQueueBoundaryDigest, PendingQueueCaptureContext,
            PendingQueueCaptureContextDigest,
        },
    },
    store::realm_processor_quiescence::RealmProcessorDrainRequest,
};
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

pub struct EphemeralQueueGathererWithTree<
    const QUEUE_TOPIC_ID: u32,
    QueueItem: PCoreQueueItemBase,
    Output: Sized + Send + Sync + 'static,
> {
    qk: QueueKeyStatusManager<QUEUE_TOPIC_ID, QueueItem>,
    trigger_tx: mpsc::Sender<TreeGathererCommand<Output>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GathererActorRevision(u64);

impl GathererActorRevision {
    pub fn try_new(value: u64) -> Result<Self, GathererPauseError> {
        if value > i64::MAX as u64 {
            return Err(GathererPauseError::RevisionOutOfRange(value));
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    fn checked_next(self) -> Result<Self, GathererPauseError> {
        let next = self
            .0
            .checked_add(1)
            .ok_or(GathererPauseError::RevisionOverflow)?;
        if next > i64::MAX as u64 {
            return Err(GathererPauseError::RevisionOverflow);
        }
        Ok(Self(next))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GathererPauseRequest {
    drain_request: RealmProcessorDrainRequest,
    expected_revision: GathererActorRevision,
    expected_unique_id: u128,
}

impl GathererPauseRequest {
    pub const fn new(
        drain_request: RealmProcessorDrainRequest,
        expected_revision: GathererActorRevision,
        expected_unique_id: u128,
    ) -> Self {
        Self {
            drain_request,
            expected_revision,
            expected_unique_id,
        }
    }

    pub const fn drain_request(self) -> RealmProcessorDrainRequest {
        self.drain_request
    }

    pub const fn expected_revision(self) -> GathererActorRevision {
        self.expected_revision
    }

    pub const fn expected_unique_id(self) -> u128 {
        self.expected_unique_id
    }
}

#[derive(Debug)]
struct GathererActorIdentity;

#[derive(Debug)]
pub struct GathererPauseReceipt {
    actor_identity: Arc<GathererActorIdentity>,
    request: GathererPauseRequest,
    revision: GathererActorRevision,
    queue_topic_id: u32,
    realm_id: u64,
    realm_sub_id: u64,
    unique_id: u128,
}

impl GathererPauseReceipt {
    pub const fn request(&self) -> GathererPauseRequest {
        self.request
    }

    pub const fn revision(&self) -> GathererActorRevision {
        self.revision
    }

    pub const fn queue_topic_id(&self) -> u32 {
        self.queue_topic_id
    }

    pub const fn realm_id(&self) -> u64 {
        self.realm_id
    }

    pub const fn realm_sub_id(&self) -> u64 {
        self.realm_sub_id
    }

    pub const fn unique_id(&self) -> u128 {
        self.unique_id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GathererBoundaryPhase {
    Running,
    Paused,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GathererBoundaryStatus {
    revision: GathererActorRevision,
    phase: GathererBoundaryPhase,
    request: Option<GathererPauseRequest>,
    unique_id: u128,
}

impl GathererBoundaryStatus {
    pub const fn revision(self) -> GathererActorRevision {
        self.revision
    }

    pub const fn phase(self) -> GathererBoundaryPhase {
        self.phase
    }

    pub const fn request(self) -> Option<GathererPauseRequest> {
        self.request
    }

    pub const fn unique_id(self) -> u128 {
        self.unique_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GathererPauseError {
    RevisionOutOfRange(u64),
    RevisionOverflow,
    RealmIdentityMismatch,
    UniqueIdMismatch { current: u128, expected: u128 },
    RevisionMismatch {
        current: GathererActorRevision,
        expected: GathererActorRevision,
    },
    AlreadyPausedAtDifferentRequest,
    NotPaused,
    ReceiptFromDifferentActor,
    StaleReceipt,
    FinalizeWhilePaused,
    DurableGenerationOnLegacyActor,
    LegacyFinalizeOnDurableActor,
    DurableGenerationIdentityMismatch,
    DurableGenerationApplyFailed,
    SemanticHandoffNotIntegrated,
    CallbackBoundaryFailed,
    ControlChannelClosed,
    ResponseChannelClosed,
}

impl std::fmt::Display for GathererPauseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for GathererPauseError {}

enum TreeGathererCommand<Output> {
    Finalize {
        next_unique_id: Option<u128>,
        responder: oneshot::Sender<anyhow::Result<Output>>,
    },
    Pause {
        request: GathererPauseRequest,
        responder: oneshot::Sender<Result<GathererPauseReceipt, GathererPauseError>>,
    },
    Resume {
        receipt: GathererPauseReceipt,
        responder: oneshot::Sender<Result<GathererBoundaryStatus, GathererPauseError>>,
    },
    Status(oneshot::Sender<GathererBoundaryStatus>),
    ApplyDurableGeneration {
        generation: RealmProcessorDurableCapturedGeneration,
        deferred_input: RealmProcessorDeferredActorInput,
        responder: oneshot::Sender<
            Result<DurableTreeGathererApplyReceipt, GathererPauseError>,
        >,
    },
    FinalizeDurableGeneration {
        receipt: DurableTreeGathererApplyReceipt,
        responder: oneshot::Sender<
            Result<DurableTreeGathererFinalizeReceipt<Output>, GathererPauseError>,
        >,
    },
}

/// A builder config used by the command-only branch-exact actor must bind its
/// mutable legacy status to the exact processing generation carried by the
/// exhaustive artifact replay.
pub trait DurableTreeGathererConfig: Clone + Send + Sync + 'static {
    fn bind_complete_generation(
        &self,
        context: PendingQueueCaptureContext,
        deferred_input: RealmProcessorDeferredActorInput,
    ) -> anyhow::Result<Self>;
}

#[derive(Debug)]
pub struct DurableTreeGathererApplyReceipt {
    actor_identity: Arc<GathererActorIdentity>,
    actor_revision: GathererActorRevision,
    context_digest: PendingQueueCaptureContextDigest,
    generation_digest: RealmProcessorDurableGenerationDigest,
    boundary_digest: PendingQueueBoundaryDigest,
    item_count: u64,
    actor_input_digest: RealmProcessorDeferredActorInputDigest,
}

/// In-process proof that the command-only actor finalized exactly the builder
/// selected by one durable apply receipt.
///
/// This is deliberately not durable storage authority.  c4a2 must persist and
/// exactly read back the semantic output before advancing the pipeline.  The
/// `Arc` only makes response-loss retry idempotent inside the same actor.
pub struct DurableTreeGathererFinalizeReceipt<Output> {
    _actor_identity: Arc<GathererActorIdentity>,
    actor_revision: GathererActorRevision,
    context_digest: PendingQueueCaptureContextDigest,
    generation_digest: RealmProcessorDurableGenerationDigest,
    boundary_digest: PendingQueueBoundaryDigest,
    item_count: u64,
    actor_input_digest: RealmProcessorDeferredActorInputDigest,
    output: Arc<Output>,
}

impl<Output> DurableTreeGathererFinalizeReceipt<Output> {
    pub const fn actor_revision(&self) -> GathererActorRevision {
        self.actor_revision
    }

    pub const fn context_digest(&self) -> PendingQueueCaptureContextDigest {
        self.context_digest
    }

    pub const fn generation_digest(&self) -> RealmProcessorDurableGenerationDigest {
        self.generation_digest
    }

    pub const fn boundary_digest(&self) -> PendingQueueBoundaryDigest {
        self.boundary_digest
    }

    pub const fn item_count(&self) -> u64 {
        self.item_count
    }

    pub const fn actor_input_digest(&self) -> RealmProcessorDeferredActorInputDigest {
        self.actor_input_digest
    }

    pub fn output(&self) -> &Output {
        self.output.as_ref()
    }
}

impl DurableTreeGathererApplyReceipt {
    pub const fn actor_revision(&self) -> GathererActorRevision {
        self.actor_revision
    }

    pub const fn context_digest(&self) -> PendingQueueCaptureContextDigest {
        self.context_digest
    }

    pub const fn generation_digest(&self) -> RealmProcessorDurableGenerationDigest {
        self.generation_digest
    }

    pub const fn boundary_digest(&self) -> PendingQueueBoundaryDigest {
        self.boundary_digest
    }

    pub const fn item_count(&self) -> u64 {
        self.item_count
    }

    pub const fn actor_input_digest(&self) -> RealmProcessorDeferredActorInputDigest {
        self.actor_input_digest
    }
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
        let (trigger_tx, trigger_rx) = mpsc::channel::<TreeGathererCommand<Output>>(1);

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

    /// Spawn the branch-exact command-only gatherer.
    ///
    /// This actor deliberately owns no queue subscriber.  Its only data-plane
    /// input is a complete generation reconstructed from durable artifacts by
    /// the affine Processor capture owner, so the legacy dump/ACK/delete path
    /// is structurally unreachable.
    pub fn new_durable_with_status<
        C: DurableTreeGathererConfig,
        Hash: QHashBase + Send + Sync + 'static,
        Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static,
        Builder: QueueGathererItemBuilderWithTree<
                C,
                SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
                Output = Output,
            > + Send
            + Sync
            + 'static,
    >(
        create_builder_config: C,
        base_queue_key: QPStandardUniqueIdQueueKey<QUEUE_TOPIC_ID, QueueItem>,
        tree: SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
        status: ProcessorStatus,
    ) -> (Self, tokio::task::JoinHandle<Result<(), anyhow::Error>>) {
        let qk = QueueKeyStatusManager::new_with_status(base_queue_key.clone(), status);
        let (trigger_tx, trigger_rx) = mpsc::channel::<TreeGathererCommand<Output>>(1);
        let jh = tokio::spawn(durable_gatherer_runner_for_tree::<
            QUEUE_TOPIC_ID,
            QueueItem,
            Builder,
            C,
            Hash,
            Hasher,
        >(
            create_builder_config,
            base_queue_key,
            tree,
            trigger_rx,
        ));
        (Self { qk, trigger_tx }, jh)
    }

    /// Apply one complete, exhaustive durable generation to the tentative
    /// WithTree builder.  This remains crate-private so a checked data value is
    /// not itself mutation authority; only the real Processor route can call
    /// it.
    pub(crate) async fn apply_durable_generation(
        &self,
        generation: RealmProcessorDurableCapturedGeneration,
        deferred_input: RealmProcessorDeferredActorInput,
    ) -> Result<DurableTreeGathererApplyReceipt, GathererPauseError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.trigger_tx
            .send(TreeGathererCommand::ApplyDurableGeneration {
                generation,
                deferred_input,
                responder: response_tx,
            })
            .await
            .map_err(|_| GathererPauseError::ControlChannelClosed)?;
        response_rx
            .await
            .map_err(|_| GathererPauseError::ResponseChannelClosed)?
    }

    /// RF=3 qualification-only entry into the exact command used by the real
    /// Processor. It is absent from ordinary builds and deliberately exposes
    /// neither a receipt constructor nor storage authority.
    #[cfg(feature = "rf3-test-support")]
    pub async fn qualification_apply_durable_generation(
        &self,
        generation: RealmProcessorDurableCapturedGeneration,
        deferred_input: RealmProcessorDeferredActorInput,
    ) -> Result<DurableTreeGathererApplyReceipt, GathererPauseError> {
        self.apply_durable_generation(generation, deferred_input).await
    }

    /// Finalize exactly the tentative builder selected by `receipt`.
    ///
    /// The actor caches the result, so a response-loss retry with a freshly
    /// replayed, identical apply receipt returns the same output without
    /// running builder finalization twice.  This method remains crate-private;
    /// a caller still needs c4a2's storage-owned archive receipt before it can
    /// hand work to the durable pipeline.
    pub(crate) async fn finalize_durable_generation(
        &self,
        receipt: DurableTreeGathererApplyReceipt,
    ) -> Result<DurableTreeGathererFinalizeReceipt<Output>, GathererPauseError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.trigger_tx
            .send(TreeGathererCommand::FinalizeDurableGeneration {
                receipt,
                responder: response_tx,
            })
            .await
            .map_err(|_| GathererPauseError::ControlChannelClosed)?;
        response_rx
            .await
            .map_err(|_| GathererPauseError::ResponseChannelClosed)?
    }

    /// RF=3 qualification-only entry into the same cached finalize command
    /// used by the real Processor. The returned value remains an inert
    /// in-process receipt and cannot advance durable storage.
    #[cfg(feature = "rf3-test-support")]
    pub async fn qualification_finalize_durable_generation(
        &self,
        receipt: DurableTreeGathererApplyReceipt,
    ) -> Result<DurableTreeGathererFinalizeReceipt<Output>, GathererPauseError> {
        self.finalize_durable_generation(receipt).await
    }

    pub async fn stop_gracefully(&mut self) -> anyhow::Result<()> {
        self.qk.begin_shutdown()?;
        let (response_tx, response_rx) = oneshot::channel();
        self.trigger_tx
            .send(TreeGathererCommand::Finalize {
                next_unique_id: None,
                responder: response_tx,
            })
            .await
            .map_err(|_| GathererPauseError::ControlChannelClosed)?;
        let _result = response_rx
            .await
            .map_err(|_| GathererPauseError::ResponseChannelClosed)??;
        Ok(())
    }

    pub async fn finalize_gathering_and_update_queue_key(
        &mut self,
        unique_id: u128,
    ) -> anyhow::Result<Output> {
        let (response_tx, response_rx) = oneshot::channel();
        if response_rx.is_terminated() {
            anyhow::bail!("GATHERER_{QUEUE_TOPIC_ID}: Response channel was terminated before sending.");
        }else if response_tx.is_closed() {
            anyhow::bail!("GATHERER_{QUEUE_TOPIC_ID}: Response channel was closed before sending.");
        }
        tracing::info!("start finish finalize_gathering_and_update_queue_key for GATHERER_{QUEUE_TOPIC_ID}");
        self.trigger_tx
            .send(TreeGathererCommand::Finalize {
                next_unique_id: Some(unique_id),
                responder: response_tx,
            })
            .await
            .map_err(|_| GathererPauseError::ControlChannelClosed)?;
        let result = response_rx
            .await
            .map_err(|_| GathererPauseError::ResponseChannelClosed)??;
        tracing::info!("end finish finalize_gathering_and_update_queue_key for GATHERER_{QUEUE_TOPIC_ID}");
        Ok(result)
    }

    /// Park the current builder/tree without finalizing, rotating the queue
    /// key, acknowledging another message batch, or deleting a consumer.
    pub async fn pause(
        &self,
        request: GathererPauseRequest,
    ) -> Result<GathererPauseReceipt, GathererPauseError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.trigger_tx
            .send(TreeGathererCommand::Pause {
                request,
                responder: response_tx,
            })
            .await
            .map_err(|_| GathererPauseError::ControlChannelClosed)?;
        response_rx
            .await
            .map_err(|_| GathererPauseError::ResponseChannelClosed)?
    }

    pub async fn resume(
        &self,
        receipt: GathererPauseReceipt,
    ) -> Result<GathererBoundaryStatus, GathererPauseError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.trigger_tx
            .send(TreeGathererCommand::Resume {
                receipt,
                responder: response_tx,
            })
            .await
            .map_err(|_| GathererPauseError::ControlChannelClosed)?;
        response_rx
            .await
            .map_err(|_| GathererPauseError::ResponseChannelClosed)?
    }

    /// Linearized actor status. A returned status proves that no earlier
    /// command or backend callback remains in flight, but is not authority to
    /// change a storage route.
    pub async fn status(&self) -> Result<GathererBoundaryStatus, GathererPauseError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.trigger_tx
            .send(TreeGathererCommand::Status(response_tx))
            .await
            .map_err(|_| GathererPauseError::ControlChannelClosed)?;
        response_rx
            .await
            .map_err(|_| GathererPauseError::ResponseChannelClosed)
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

async fn apply_tree_gatherer_poll<Builder, C, Hash, Hasher>(
    builder: &mut Builder,
    tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
    messages: anyhow::Result<Vec<Vec<u8>>>,
) -> anyhow::Result<usize>
where
    Builder: QueueGathererItemBuilderWithTree<
            C,
            SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
        > + Send
        + Sync,
    C: Clone + Send + Sync + 'static,
    Hash: QHashBase + Send + Sync + 'static,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static,
{
    let messages = messages?;
    let count = messages.len();
    if count != 0 {
        builder
            .update_from_many_queue_items_with_tree(tree, messages)
            .await?;
    }
    Ok(count)
}

fn reject_tree_command_at_callback_boundary<Output>(
    command: TreeGathererCommand<Output>,
    reason: &str,
) {
    match command {
        TreeGathererCommand::Finalize { responder, .. } => {
            let _ = responder.send(Err(anyhow::anyhow!(reason.to_owned())));
        }
        TreeGathererCommand::Pause { responder, .. } => {
            let _ = responder.send(Err(GathererPauseError::CallbackBoundaryFailed));
        }
        TreeGathererCommand::Resume { responder, .. } => {
            let _ = responder.send(Err(GathererPauseError::CallbackBoundaryFailed));
        }
        TreeGathererCommand::Status(responder) => {
            drop(responder);
        }
        TreeGathererCommand::ApplyDurableGeneration { responder, .. } => {
            let _ = responder.send(Err(GathererPauseError::DurableGenerationOnLegacyActor));
        }
        TreeGathererCommand::FinalizeDurableGeneration { responder, .. } => {
            let _ = responder.send(Err(GathererPauseError::DurableGenerationOnLegacyActor));
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn durable_gatherer_runner_for_tree<
    const QUEUE_TOPIC_ID: u32,
    QueueItem: PCoreQueueItemBase,
    Builder: QueueGathererItemBuilderWithTree<C, SimpleMemoryMerkleRecorderStore<Hasher, Hash>>
        + Send
        + Sync,
    C: DurableTreeGathererConfig,
    Hash: QHashBase + Send + Sync + 'static,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static,
>(
    base_config: C,
    queue_key: QPStandardUniqueIdQueueKey<QUEUE_TOPIC_ID, QueueItem>,
    mut tree: SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
    mut trigger_rx: mpsc::Receiver<TreeGathererCommand<Builder::Output>>,
) -> anyhow::Result<()> {
    let actor_identity = Arc::new(GathererActorIdentity);
    let mut actor_revision = GathererActorRevision(0);
    let mut applied: Option<DurableTreeGathererApplyReceipt> = None;
    let mut tentative_builder: Option<Builder> = None;
    let mut finalized_output: Option<Arc<Builder::Output>> = None;
    let mut finalized_revision: Option<GathererActorRevision> = None;

    while let Some(command) = trigger_rx.recv().await {
        match command {
            TreeGathererCommand::ApplyDurableGeneration {
                generation,
                deferred_input,
                responder,
            } => {
                let context = generation.context();
                let boundary_digest = generation.boundary().digest();
                let generation_digest = generation.digest();
                let item_count = generation.item_count();
                let actor_input_digest = deferred_input.digest();

                if context.key().authority()
                    != (psy_data::protocol::chain_context::AuthorityScope::Realm {
                        realm_id: queue_key.realm_id as u32,
                        realm_sub_id: queue_key.realm_sub_id as u16,
                    })
                    || context.processing().proc_checkpoint_id().as_u128()
                        != queue_key.unique_id
                    || deferred_input.successor() != context.processing()
                {
                    let _ = responder.send(Err(
                        GathererPauseError::DurableGenerationIdentityMismatch,
                    ));
                    continue;
                }

                if let Some(current) = applied.as_ref() {
                    let outcome = if current.context_digest() == context.digest()
                        && current.generation_digest() == generation_digest
                        && current.boundary_digest() == boundary_digest
                        && current.item_count() == item_count
                        && current.actor_input_digest() == actor_input_digest
                    {
                        Ok(DurableTreeGathererApplyReceipt {
                            actor_identity: current.actor_identity.clone(),
                            actor_revision: current.actor_revision,
                            context_digest: current.context_digest,
                            generation_digest: current.generation_digest,
                            boundary_digest: current.boundary_digest,
                            item_count: current.item_count,
                            actor_input_digest: current.actor_input_digest,
                        })
                    } else {
                        Err(GathererPauseError::DurableGenerationIdentityMismatch)
                    };
                    let _ = responder.send(outcome);
                    continue;
                }

                let bound_config = match base_config
                    .bind_complete_generation(context, deferred_input)
                {
                    Ok(config) => config,
                    Err(err) => {
                        tracing::error!(
                            "GATHERER_{QUEUE_TOPIC_ID}: cannot bind durable generation: {err:?}"
                        );
                        let _ = responder.send(Err(
                            GathererPauseError::DurableGenerationIdentityMismatch,
                        ));
                        return Err(err);
                    }
                };
                let mut builder = match Builder::create_new_with_tree(
                    &mut tree,
                    queue_key.unique_id,
                    bound_config,
                )
                .await
                {
                    Ok(builder) => builder,
                    Err(err) => {
                        let _ = responder
                            .send(Err(GathererPauseError::DurableGenerationApplyFailed));
                        return Err(err);
                    }
                };
                let items = generation.into_business_items();
                if let Err(err) = builder
                    .update_from_many_queue_items_with_tree(&mut tree, items)
                    .await
                {
                    let _ = responder
                        .send(Err(GathererPauseError::DurableGenerationApplyFailed));
                    return Err(err);
                }
                actor_revision = actor_revision.checked_next()?;
                let receipt = DurableTreeGathererApplyReceipt {
                    actor_identity: actor_identity.clone(),
                    actor_revision,
                    context_digest: context.digest(),
                    generation_digest,
                    boundary_digest,
                    item_count,
                    actor_input_digest,
                };
                let response = DurableTreeGathererApplyReceipt {
                    actor_identity: receipt.actor_identity.clone(),
                    actor_revision: receipt.actor_revision,
                    context_digest: receipt.context_digest,
                    generation_digest: receipt.generation_digest,
                    boundary_digest: receipt.boundary_digest,
                    item_count: receipt.item_count,
                    actor_input_digest: receipt.actor_input_digest,
                };
                tentative_builder = Some(builder);
                applied = Some(receipt);
                let _ = responder.send(Ok(response));
            }
            TreeGathererCommand::FinalizeDurableGeneration { receipt, responder } => {
                let Some(current) = applied.as_ref() else {
                    let _ = responder.send(Err(GathererPauseError::DurableGenerationIdentityMismatch));
                    continue;
                };
                if !Arc::ptr_eq(&receipt.actor_identity, &current.actor_identity)
                    || receipt.actor_revision != current.actor_revision
                    || receipt.context_digest != current.context_digest
                    || receipt.generation_digest != current.generation_digest
                    || receipt.boundary_digest != current.boundary_digest
                    || receipt.item_count != current.item_count
                    || receipt.actor_input_digest != current.actor_input_digest
                {
                    let _ = responder.send(Err(GathererPauseError::DurableGenerationIdentityMismatch));
                    continue;
                }
                if let Some(output) = finalized_output.as_ref() {
                    let finalized_revision = finalized_revision.ok_or_else(|| {
                        anyhow::anyhow!("finalized output is missing its stable actor revision")
                    })?;
                    let _ = responder.send(Ok(DurableTreeGathererFinalizeReceipt {
                        _actor_identity: current.actor_identity.clone(),
                        actor_revision: finalized_revision,
                        context_digest: current.context_digest,
                        generation_digest: current.generation_digest,
                        boundary_digest: current.boundary_digest,
                        item_count: current.item_count,
                        actor_input_digest: current.actor_input_digest,
                        output: output.clone(),
                    }));
                    continue;
                }
                let Some(builder) = tentative_builder.take() else {
                    let _ = responder.send(Err(GathererPauseError::DurableGenerationApplyFailed));
                    return Err(anyhow::anyhow!("durable builder missing before finalize"));
                };
                let output = match builder.finalize_with_tree(&mut tree).await {
                    Ok(output) => Arc::new(output),
                    Err(error) => {
                        let _ = responder.send(Err(GathererPauseError::DurableGenerationApplyFailed));
                        return Err(error);
                    }
                };
                actor_revision = actor_revision.checked_next()?;
                finalized_revision = Some(actor_revision);
                finalized_output = Some(output.clone());
                let _ = responder.send(Ok(DurableTreeGathererFinalizeReceipt {
                    _actor_identity: current.actor_identity.clone(),
                    actor_revision,
                    context_digest: current.context_digest,
                    generation_digest: current.generation_digest,
                    boundary_digest: current.boundary_digest,
                    item_count: current.item_count,
                    actor_input_digest: current.actor_input_digest,
                    output,
                }));
            }
            TreeGathererCommand::Pause { request, responder } => {
                if request.drain_request().realm_id() as u64 != queue_key.realm_id
                    || request.drain_request().realm_sub_id() as u64 != queue_key.realm_sub_id
                {
                    let _ = responder.send(Err(GathererPauseError::RealmIdentityMismatch));
                    continue;
                }
                if request.expected_unique_id() != queue_key.unique_id {
                    let _ = responder.send(Err(GathererPauseError::UniqueIdMismatch {
                        current: queue_key.unique_id,
                        expected: request.expected_unique_id(),
                    }));
                    continue;
                }
                if request.expected_revision() != actor_revision {
                    let _ = responder.send(Err(GathererPauseError::RevisionMismatch {
                        current: actor_revision,
                        expected: request.expected_revision(),
                    }));
                    continue;
                }
                actor_revision = actor_revision.checked_next()?;
                let make_receipt = || GathererPauseReceipt {
                    actor_identity: actor_identity.clone(),
                    request,
                    revision: actor_revision,
                    queue_topic_id: QUEUE_TOPIC_ID,
                    realm_id: queue_key.realm_id,
                    realm_sub_id: queue_key.realm_sub_id,
                    unique_id: queue_key.unique_id,
                };
                let _ = responder.send(Ok(make_receipt()));

                loop {
                    let Some(paused_command) = trigger_rx.recv().await else {
                        return Ok(());
                    };
                    match paused_command {
                        TreeGathererCommand::Pause {
                            request: retry,
                            responder,
                        } => {
                            let result = if retry == request {
                                Ok(make_receipt())
                            } else {
                                Err(GathererPauseError::AlreadyPausedAtDifferentRequest)
                            };
                            let _ = responder.send(result);
                        }
                        TreeGathererCommand::Resume { receipt, responder } => {
                            if !Arc::ptr_eq(&actor_identity, &receipt.actor_identity)
                                || receipt.request != request
                                || receipt.revision != actor_revision
                                || receipt.unique_id != queue_key.unique_id
                            {
                                let _ = responder.send(Err(GathererPauseError::StaleReceipt));
                                continue;
                            }
                            actor_revision = actor_revision.checked_next()?;
                            let _ = responder.send(Ok(GathererBoundaryStatus {
                                revision: actor_revision,
                                phase: GathererBoundaryPhase::Running,
                                request: None,
                                unique_id: queue_key.unique_id,
                            }));
                            break;
                        }
                        TreeGathererCommand::Status(responder) => {
                            let _ = responder.send(GathererBoundaryStatus {
                                revision: actor_revision,
                                phase: GathererBoundaryPhase::Paused,
                                request: Some(request),
                                unique_id: queue_key.unique_id,
                            });
                        }
                        TreeGathererCommand::Finalize { responder, .. } => {
                            let _ = responder.send(Err(
                                GathererPauseError::LegacyFinalizeOnDurableActor.into(),
                            ));
                        }
                        TreeGathererCommand::ApplyDurableGeneration { responder, .. } => {
                            let _ = responder.send(Err(
                                GathererPauseError::AlreadyPausedAtDifferentRequest,
                            ));
                        }
                        TreeGathererCommand::FinalizeDurableGeneration { responder, .. } => {
                            let _ = responder.send(Err(
                                GathererPauseError::AlreadyPausedAtDifferentRequest,
                            ));
                        }
                    }
                }
            }
            TreeGathererCommand::Resume { responder, .. } => {
                let _ = responder.send(Err(GathererPauseError::NotPaused));
            }
            TreeGathererCommand::Status(responder) => {
                let _ = responder.send(GathererBoundaryStatus {
                    revision: actor_revision,
                    phase: GathererBoundaryPhase::Running,
                    request: None,
                    unique_id: queue_key.unique_id,
                });
            }
            TreeGathererCommand::Finalize { responder, .. } => {
                let _ = responder.send(Err(
                    GathererPauseError::SemanticHandoffNotIntegrated.into(),
                ));
            }
        }
    }
    Ok(())
}

async fn gatherer_runner_for_tree<
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
    mut trigger_rx: mpsc::Receiver<TreeGathererCommand<Builder::Output>>,
) -> anyhow::Result<()> {
    let actor_identity = Arc::new(GathererActorIdentity);
    let mut actor_revision = GathererActorRevision(0);
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
            if trigger_rx.is_closed() {
                tracing::info!(
                    "GATHERER_{QUEUE_TOPIC_ID}: Trigger channel closed, stopping gatherer."
                );
                return Ok(());
            }
            //tracing::info!("GATHERER_{QUEUE_TOPIC_ID}: Waiting for messages or trigger...");
            // The backend callback may ACK/drain incrementally. Never put the
            // callback expression directly in `select!`: dropping the losing
            // future could acknowledge data which never reaches the builder.
            // A control command must wait for this exact callback and its
            // builder update before it may observe a linearized boundary.
            let poll = stream.dump_entire_ephemeral_queue_bytes(
                &queue_key,
                queue_key.realm_id,
                queue_key.realm_sub_id,
                queue_key.unique_id,
                queue_key.task_group as u32,
                50000,
            );
            tokio::pin!(poll);

            tokio::select! {
                // Biased ensures we check for a processor trigger first for better responsiveness.
                biased;

                // A trigger from the Processor was received.
                Some(command) = trigger_rx.recv() => {
                    let poll_result = (&mut poll).await;
                    drop(poll);
                    match apply_tree_gatherer_poll::<Builder, C, Hash, Hasher>(
                        &mut builder,
                        &mut tree,
                        poll_result,
                    )
                    .await
                    {
                        Ok(count) => {
                            if count != 0 {
                                tracing::info!(
                                    "GATHERER_{QUEUE_TOPIC_ID}: Applied {count} items before control boundary"
                                );
                            }
                        }
                        Err(err) => {
                            tracing::error!(
                                "GATHERER_{QUEUE_TOPIC_ID}: Cannot establish callback boundary: {err:?}"
                            );
                            reject_tree_command_at_callback_boundary(command, &err.to_string());
                            break 'gathering;
                        }
                    }

                    let (next_unique_id, responder) = match command {
                        TreeGathererCommand::Pause { request, responder } => {
                            if request.drain_request().realm_id() as u64 != queue_key.realm_id
                                || request.drain_request().realm_sub_id() as u64 != queue_key.realm_sub_id
                            {
                                let _ = responder.send(Err(GathererPauseError::RealmIdentityMismatch));
                                continue 'gathering;
                            }
                            if request.expected_unique_id() != queue_key.unique_id {
                                let _ = responder.send(Err(GathererPauseError::UniqueIdMismatch {
                                    current: queue_key.unique_id,
                                    expected: request.expected_unique_id(),
                                }));
                                continue 'gathering;
                            }
                            if request.expected_revision() != actor_revision {
                                let _ = responder.send(Err(GathererPauseError::RevisionMismatch {
                                    current: actor_revision,
                                    expected: request.expected_revision(),
                                }));
                                continue 'gathering;
                            }
                            actor_revision = match actor_revision.checked_next() {
                                Ok(next) => next,
                                Err(err) => {
                                    let _ = responder.send(Err(err));
                                    continue 'gathering;
                                }
                            };
                            let make_receipt = || GathererPauseReceipt {
                                actor_identity: actor_identity.clone(),
                                request,
                                revision: actor_revision,
                                queue_topic_id: QUEUE_TOPIC_ID,
                                realm_id: queue_key.realm_id,
                                realm_sub_id: queue_key.realm_sub_id,
                                unique_id: queue_key.unique_id,
                            };
                            let _ = responder.send(Ok(make_receipt()));
                                'paused: loop {
                                    let Some(command) = trigger_rx.recv().await else {
                                        return Ok(());
                                    };
                                    match command {
                                        TreeGathererCommand::Pause { request: retry, responder } => {
                                            let outcome = if retry == request {
                                                Ok(make_receipt())
                                            } else {
                                                Err(GathererPauseError::AlreadyPausedAtDifferentRequest)
                                            };
                                            let _ = responder.send(outcome);
                                        }
                                        TreeGathererCommand::Resume { receipt, responder } => {
                                            if !Arc::ptr_eq(&actor_identity, &receipt.actor_identity) {
                                                let _ = responder.send(Err(GathererPauseError::ReceiptFromDifferentActor));
                                                continue;
                                            }
                                            if receipt.request != request
                                                || receipt.revision != actor_revision
                                                || receipt.unique_id != queue_key.unique_id
                                            {
                                                let _ = responder.send(Err(GathererPauseError::StaleReceipt));
                                                continue;
                                            }
                                            actor_revision = match actor_revision.checked_next() {
                                                Ok(next) => next,
                                                Err(err) => {
                                                    let _ = responder.send(Err(err));
                                                    continue;
                                                }
                                            };
                                            let _ = responder.send(Ok(GathererBoundaryStatus {
                                                revision: actor_revision,
                                                phase: GathererBoundaryPhase::Running,
                                                request: None,
                                                unique_id: queue_key.unique_id,
                                            }));
                                            break 'paused;
                                        }
                                        TreeGathererCommand::Status(responder) => {
                                            let _ = responder.send(GathererBoundaryStatus {
                                                revision: actor_revision,
                                                phase: GathererBoundaryPhase::Paused,
                                                request: Some(request),
                                                unique_id: queue_key.unique_id,
                                            });
                                        }
                                        TreeGathererCommand::Finalize { next_unique_id, responder } => {
                                            if queue_key_helper.should_run() || next_unique_id.is_some() {
                                                let _ = responder.send(Err(GathererPauseError::FinalizeWhilePaused.into()));
                                                continue;
                                            }
                                            let result = builder
                                                .finalize_with_tree(&mut tree)
                                                .await
                                                .map_err(anyhow::Error::from);
                                            let _ = responder.send(result);
                                            return Ok(());
                                        }
                                        TreeGathererCommand::ApplyDurableGeneration { responder, .. } => {
                                            let _ = responder.send(Err(
                                                GathererPauseError::DurableGenerationOnLegacyActor,
                                            ));
                                        }
                                        TreeGathererCommand::FinalizeDurableGeneration { responder, .. } => {
                                            let _ = responder.send(Err(
                                                GathererPauseError::DurableGenerationOnLegacyActor,
                                            ));
                                        }
                                    }
                                }
                                continue 'gathering;
                        }
                        TreeGathererCommand::Resume { responder, .. } => {
                                let _ = responder.send(Err(GathererPauseError::NotPaused));
                                continue 'gathering;
                        }
                        TreeGathererCommand::Status(responder) => {
                            let _ = responder.send(GathererBoundaryStatus {
                                revision: actor_revision,
                                phase: GathererBoundaryPhase::Running,
                                request: None,
                                unique_id: queue_key.unique_id,
                            });
                            continue 'gathering;
                        }
                        TreeGathererCommand::Finalize { next_unique_id, responder } => {
                            (next_unique_id, responder)
                        }
                        TreeGathererCommand::ApplyDurableGeneration { responder, .. } => {
                            let _ = responder.send(Err(
                                GathererPauseError::DurableGenerationOnLegacyActor,
                            ));
                            continue 'gathering;
                        }
                        TreeGathererCommand::FinalizeDurableGeneration { responder, .. } => {
                            let _ = responder.send(Err(
                                GathererPauseError::DurableGenerationOnLegacyActor,
                            ));
                            continue 'gathering;
                        }
                    };
                    let mut responder = Some(responder);
                    let old_unique_id = queue_key.unique_id;
                    let old_queue_key = queue_key.clone();
                    tracing::info!("GATHERER_{QUEUE_TOPIC_ID}: Interrupted by Processor. Preparing to hand over");
                    if let Some(next_unique_id) = next_unique_id {
                        queue_key_helper.set_unique_id(next_unique_id)?;
                    }
                    let next_queue_key = queue_key_helper.get_queue_key()?;
                    let new_unique_id = next_queue_key.unique_id;
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

                    let finalized_output = if trigger_ok {
                        match builder.finalize_with_tree(&mut tree).await {
                            Ok(finalized_output) => {
                                tracing::info!(
                                    "GATHERER_{QUEUE_TOPIC_ID}: Finalized output prepared; completing terminal queue cleanup before replying"
                                );
                                Some(finalized_output)
                            }
                            Err(err) => {
                                tracing::error!(
                                    "GATHERER_{QUEUE_TOPIC_ID}: Error during finalize: {:?}; processor will retry",
                                    err
                                );
                                let _ = responder
                                    .take()
                                    .expect("finalize responder is consumed once")
                                    .send(Err(anyhow::Error::from(err)));
                                None
                            }
                        }
                    } else {
                        let message =
                            "gatherer skipped finalize after a drain/update error; processor must retry";
                        tracing::error!("GATHERER_{QUEUE_TOPIC_ID}: {message}");
                        let _ = responder
                            .take()
                            .expect("finalize responder is consumed once")
                            .send(Err(anyhow::anyhow!(message)));
                        None
                    };

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
                    if let Some(finalized_output) = finalized_output {
                        if responder
                            .take()
                            .expect("successful finalize retains its responder")
                            .send(Ok(finalized_output))
                            .is_err()
                        {
                            tracing::error!(
                                "GATHERER_{QUEUE_TOPIC_ID}: Failed to send data to processor after terminal cleanup; receiver dropped"
                            );
                        } else {
                            tracing::info!(
                                "GATHERER_{QUEUE_TOPIC_ID}: Successfully handed over data after terminal cleanup"
                            );
                        }
                    }
                    if !should_run {
                        return Ok(());
                    }

                    break 'gathering; // Break inner loop to start a new cycle.
                },

                // A completed backend callback may now safely be applied. The
                // control branch above awaits this same pinned future.
                msgs = &mut poll => {
                    drop(poll);
                    match apply_tree_gatherer_poll::<Builder, C, Hash, Hasher>(
                        &mut builder,
                        &mut tree,
                        msgs,
                    )
                    .await
                    {
                        Ok(count) => {
                            if count != 0 {
                                tracing::info!("GATHERER_{QUEUE_TOPIC_ID}: Received {count} items from queue.");
                            }
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                        Err(err) => {
                            tracing::error!(
                                "GATHERER_{QUEUE_TOPIC_ID}: Error applying queue callback: {err:?}; restarting gather cycle"
                            );
                            break 'gathering;
                        }
                    }
                }
            }
        }
        queue_key = queue_key_helper.get_queue_key()?;
        tracing::info!("GATHERER_{QUEUE_TOPIC_ID}: Handoff complete. Cycle restarting.");
    }
}

#[cfg(test)]
mod h23b1_tests {
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    };

    use async_trait::async_trait;
    use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
    use parth_core::{
        data::queue::queue_key::{
            PCoreQueueItemBase, PCoreStandardQueueKeyForRealm, QPBaseQueueType,
            QPStandardUniqueIdQueueKey,
        },
        pgoldilocks::PoseidonHasher,
        PHash,
    };
    use psy_core::constants::chain_id::PsyChainNetworkType;
    use psy_data::protocol::{
        canonical_chain::NetworkId, chain_context::AuthorityScope,
    };
    use psy_node_core::{
        queue::{
            ephemeral::QStandardEphemeralQueueSubscriber,
            infrastructure::QStandardQueueBase,
            realm_processor_durable_capture::{
                RealmProcessorDurableCapturedBatch,
                RealmProcessorDurableCapturedGeneration,
                RealmProcessorDurableCapturedItem,
            },
            realm_processor_generation_terminal::RealmProcessorDeferredCarryover,
            recoverable_ephemeral::{
                PendingQueueBoundaryObservation, PendingQueueCaptureCandidate,
                PendingQueueCaptureContext, PendingQueueGenerationBoundary,
                PendingQueueSourceCursor, PendingQueueSourceIdentity,
            },
        },
        store::{
            pending_generation_identity::{
                PendingGenerationActivationDigest, PendingGenerationBootstrapReason,
                PendingGenerationContext,
                PendingGenerationLedgerKey,
            },
            pending_generation_pipeline::PendingQueueCloseIntentDigest,
        },
    };
    use tokio::sync::Notify;

    use super::*;

    const TEST_TOPIC: u32 = 0x23_b1;

    #[derive(Clone)]
    struct TestQueueItem(Vec<u8>);

    impl PCoreQueueItemBase for TestQueueItem {
        fn is_queue_item(_data: &[u8]) -> bool {
            true
        }

        fn decode_queue_item_ref(data: &[u8]) -> anyhow::Result<Self> {
            Ok(Self(data.to_vec()))
        }

        fn encode_queue_item_vec(&self) -> anyhow::Result<Vec<u8>> {
            Ok(self.0.clone())
        }

        fn get_restorable_job_id(&self) -> Vec<u8> {
            Vec::new()
        }

        fn get_size_hint() -> usize {
            1
        }

        fn has_fixed_size() -> bool {
            false
        }
    }

    #[derive(Default)]
    struct TestGathererState {
        dump_calls: AtomicUsize,
        update_calls: AtomicUsize,
        ensure_calls: AtomicUsize,
        delete_calls: AtomicUsize,
        finalize_calls: AtomicUsize,
        fail_update: AtomicBool,
        fail_finalize: AtomicBool,
        subsequent_dump_empty: AtomicBool,
        block_delete: AtomicBool,
        dump_started: Notify,
        release_dump: Notify,
        update_started: Notify,
        release_update: Notify,
        delete_started: Notify,
        release_delete: Notify,
    }

    struct TestSubscriber {
        state: Arc<TestGathererState>,
    }

    #[async_trait]
    impl QStandardQueueBase for TestSubscriber {
        async fn ensure_stream(&self) -> anyhow::Result<()> {
            Ok(())
        }

        async fn ensure_consumer<QK: PCoreStandardQueueKeyForRealm>(
            &self,
            _queue_key: &QK,
            _realm_id: u64,
            _realm_sub_id: u64,
            _unique_id: u128,
            _task_group: u32,
        ) -> anyhow::Result<()> {
            self.state.ensure_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[async_trait]
    impl QStandardEphemeralQueueSubscriber for TestSubscriber {
        async fn wait_for_ephemeral_queue_item_bytes<QK: PCoreStandardQueueKeyForRealm>(
            &self,
            _queue_key: &QK,
            _realm_id: u64,
            _realm_sub_id: u64,
            _unique_id: u128,
            _task_group: u32,
            _timeout_ms: u64,
        ) -> anyhow::Result<Option<Vec<u8>>> {
            unreachable!("test gatherer uses dump only")
        }

        async fn wait_for_ephemeral_queue_item<QK: PCoreStandardQueueKeyForRealm>(
            &self,
            _queue_key: &QK,
            _realm_id: u64,
            _realm_sub_id: u64,
            _unique_id: u128,
            _task_group: u32,
            _timeout_ms: u64,
        ) -> anyhow::Result<Option<QK::QueueItem>> {
            unreachable!("test gatherer uses dump only")
        }

        async fn dump_entire_ephemeral_queue_bytes<QK: PCoreStandardQueueKeyForRealm>(
            &self,
            _queue_key: &QK,
            _realm_id: u64,
            _realm_sub_id: u64,
            _unique_id: u128,
            _task_group: u32,
            _max_items: usize,
        ) -> anyhow::Result<Vec<Vec<u8>>> {
            let call = self.state.dump_calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                self.state.dump_started.notify_one();
                self.state.release_dump.notified().await;
                Ok(vec![vec![7]])
            } else if self.state.subsequent_dump_empty.load(Ordering::SeqCst) {
                Ok(Vec::new())
            } else {
                std::future::pending().await
            }
        }

        async fn dump_entire_ephemeral_queue<QK: PCoreStandardQueueKeyForRealm>(
            &self,
            _queue_key: &QK,
            _realm_id: u64,
            _realm_sub_id: u64,
            _unique_id: u128,
            _task_group: u32,
            _max_items: usize,
        ) -> anyhow::Result<Vec<QK::QueueItem>> {
            unreachable!("test gatherer uses byte dump only")
        }

        async fn consume_ephemeral_queue_item_or_none_bytes<
            QK: PCoreStandardQueueKeyForRealm,
        >(
            &self,
            _queue_key: &QK,
            _realm_id: u64,
            _realm_sub_id: u64,
            _unique_id: u128,
            _task_group: u32,
        ) -> anyhow::Result<Option<Vec<u8>>> {
            unreachable!("test gatherer uses dump only")
        }

        async fn consume_ephemeral_queue_item_or_none<
            QK: PCoreStandardQueueKeyForRealm,
        >(
            &self,
            _queue_key: &QK,
            _realm_id: u64,
            _realm_sub_id: u64,
            _unique_id: u128,
            _task_group: u32,
        ) -> anyhow::Result<Option<QK::QueueItem>> {
            unreachable!("test gatherer uses dump only")
        }

        async fn delete_ephemeral_queue_consumer<QK: PCoreStandardQueueKeyForRealm>(
            &self,
            _queue_key: &QK,
            _realm_id: u64,
            _realm_sub_id: u64,
            _unique_id: u128,
            _task_group: u32,
        ) -> anyhow::Result<()> {
            self.state.delete_calls.fetch_add(1, Ordering::SeqCst);
            self.state.delete_started.notify_one();
            if self.state.block_delete.load(Ordering::SeqCst) {
                self.state.release_delete.notified().await;
            }
            Ok(())
        }
    }

    struct TestBuilder {
        state: Arc<TestGathererState>,
    }

    impl DurableTreeGathererConfig for Arc<TestGathererState> {
        fn bind_complete_generation(
            &self,
            _context: PendingQueueCaptureContext,
            _deferred_input: RealmProcessorDeferredActorInput,
        ) -> anyhow::Result<Self> {
            Ok(self.clone())
        }
    }

    #[async_trait]
    impl QueueGathererItemBuilderWithTree<
            Arc<TestGathererState>,
            SimpleMemoryMerkleRecorderStore<PoseidonHasher, PHash>,
        > for TestBuilder
    {
        type Output = usize;

        async fn create_new_with_tree(
            _tree: &mut SimpleMemoryMerkleRecorderStore<PoseidonHasher, PHash>,
            _unique_id: u128,
            state: Arc<TestGathererState>,
        ) -> anyhow::Result<Self> {
            Ok(Self { state })
        }

        async fn update_from_queue_item_with_tree(
            &mut self,
            _tree: &mut SimpleMemoryMerkleRecorderStore<PoseidonHasher, PHash>,
            _item: Vec<u8>,
        ) -> anyhow::Result<()> {
            unreachable!("runner uses batch update")
        }

        async fn update_from_many_queue_items_with_tree(
            &mut self,
            _tree: &mut SimpleMemoryMerkleRecorderStore<PoseidonHasher, PHash>,
            _items: Vec<Vec<u8>>,
        ) -> anyhow::Result<()> {
            self.state.update_calls.fetch_add(1, Ordering::SeqCst);
            self.state.update_started.notify_one();
            self.state.release_update.notified().await;
            if self.state.fail_update.load(Ordering::SeqCst) {
                anyhow::bail!("injected builder failure")
            }
            Ok(())
        }

        async fn finalize_with_tree(
            self,
            _tree: &mut SimpleMemoryMerkleRecorderStore<PoseidonHasher, PHash>,
        ) -> anyhow::Result<Self::Output> {
            self.state.finalize_calls.fetch_add(1, Ordering::SeqCst);
            if self.state.fail_finalize.load(Ordering::SeqCst) {
                anyhow::bail!("injected finalize failure")
            }
            Ok(self.state.update_calls.load(Ordering::SeqCst))
        }
    }

    fn drain_request(nonce: u8) -> RealmProcessorDrainRequest {
        RealmProcessorDrainRequest::try_new(
            NetworkId::from_network_type(PsyChainNetworkType::LocalDevnet),
            7,
            3,
            11,
            19,
            [21; 32],
            [nonce; 32],
        )
        .unwrap()
    }

    fn queue_key() -> QPStandardUniqueIdQueueKey<TEST_TOPIC, TestQueueItem> {
        QPStandardUniqueIdQueueKey {
            realm_id: 7,
            realm_sub_id: 3,
            unique_id: 41,
            task_group: 0,
            queue_type: QPBaseQueueType::StandardEphemeral,
            _phantom_queue_item: std::marker::PhantomData,
        }
    }

    fn start_test_gatherer(
        state: Arc<TestGathererState>,
    ) -> (
        EphemeralQueueGathererWithTree<TEST_TOPIC, TestQueueItem, usize>,
        tokio::task::JoinHandle<anyhow::Result<()>>,
    ) {
        EphemeralQueueGathererWithTree::new::<
            TestSubscriber,
            Arc<TestGathererState>,
            PHash,
            PoseidonHasher,
            TestBuilder,
        >(
            Arc::new(TestSubscriber {
                state: state.clone(),
            }),
            state,
            queue_key(),
            SimpleMemoryMerkleRecorderStore::new(4),
        )
    }

    fn durable_context() -> PendingQueueCaptureContext {
        PendingQueueCaptureContext::try_new(
            PendingGenerationLedgerKey::new(
                NetworkId::from_network_type(PsyChainNetworkType::LocalDevnet),
                AuthorityScope::Realm {
                    realm_id: 7,
                    realm_sub_id: 3,
                },
            ),
            PendingGenerationActivationDigest::try_new([3; 32]).unwrap(),
            PendingGenerationContext::try_from_legacy(101, 41).unwrap(),
        )
        .unwrap()
    }

    fn durable_generation(marker: u8) -> RealmProcessorDurableCapturedGeneration {
        let context = durable_context();
        let source = PendingQueueSourceIdentity::nats_jetstream(
            "psy",
            "realm-updates-r7-s3",
            "psy.realm-updates.r7.s3.processing",
        )
        .unwrap();
        let candidate = PendingQueueCaptureCandidate::try_new(
            context,
            source.clone(),
            PendingQueueSourceCursor::nats_jetstream([4; 32], &[10, 11]).unwrap(),
            vec![vec![marker, 1], vec![marker, 2]],
        )
        .unwrap();
        let batch = RealmProcessorDurableCapturedBatch::try_from_verified_envelopes(
            candidate,
            vec![
                RealmProcessorDurableCapturedItem::try_new(
                    10,
                    [marker.max(1); 32],
                    vec![marker, 11],
                )
                .unwrap(),
                RealmProcessorDurableCapturedItem::try_new(
                    11,
                    [marker.saturating_add(1).max(1); 32],
                    vec![marker, 12],
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let boundary = PendingQueueGenerationBoundary::try_from_backend_observation(
            context,
            PendingQueueCloseIntentDigest::try_new([7; 32]).unwrap(),
            source,
            PendingQueueBoundaryObservation::NatsJetStream {
                seal_marker_stream_sequence: 12,
                last_data_stream_sequence: 11,
                seal_marker_digest: [8; 32],
            },
        )
        .unwrap();
        RealmProcessorDurableCapturedGeneration::try_from_exhaustive_readback(
            context,
            vec![batch],
            boundary,
        )
        .unwrap()
    }

    fn durable_input(
        reason: PendingGenerationBootstrapReason,
    ) -> RealmProcessorDeferredActorInput {
        let context = durable_context();
        let carryover = RealmProcessorDeferredCarryover::try_bootstrap_empty(
            context.key(),
            context.activation(),
            context.processing(),
            reason,
        )
        .unwrap();
        RealmProcessorDeferredActorInput::try_from_storage(
            context.processing(),
            reason,
            carryover,
            None,
        )
        .unwrap()
    }

    fn start_durable_test_gatherer(
        state: Arc<TestGathererState>,
    ) -> (
        EphemeralQueueGathererWithTree<TEST_TOPIC, TestQueueItem, usize>,
        tokio::task::JoinHandle<anyhow::Result<()>>,
    ) {
        let status = ProcessorStatus::new();
        status.mark_running();
        EphemeralQueueGathererWithTree::new_durable_with_status::<
            Arc<TestGathererState>,
            PHash,
            PoseidonHasher,
            TestBuilder,
        >(
            state,
            queue_key(),
            SimpleMemoryMerkleRecorderStore::new(4),
            status,
        )
    }

    #[test]
    fn actor_revision_is_bounded_for_cql_and_request_is_exact() {
        assert_eq!(GathererActorRevision::try_new(i64::MAX as u64).unwrap().get(), i64::MAX as u64);
        assert_eq!(
            GathererActorRevision::try_new(i64::MAX as u64 + 1),
            Err(GathererPauseError::RevisionOutOfRange(i64::MAX as u64 + 1))
        );
        assert_eq!(
            GathererActorRevision(i64::MAX as u64).checked_next(),
            Err(GathererPauseError::RevisionOverflow)
        );
        let request = GathererPauseRequest::new(
            drain_request(1),
            GathererActorRevision::try_new(0).unwrap(),
            41,
        );
        assert_eq!(request.drain_request(), drain_request(1));
        assert_eq!(request.expected_unique_id(), 41);
    }

    #[tokio::test]
    async fn pause_waits_for_non_cancelled_dump_and_builder_update_then_parks() {
        let state = Arc::new(TestGathererState::default());
        let (mut gatherer, join) = start_test_gatherer(state.clone());
        state.dump_started.notified().await;

        let request = GathererPauseRequest::new(
            drain_request(1),
            GathererActorRevision::try_new(0).unwrap(),
            41,
        );
        let receipt = {
            let pause = gatherer.pause(request);
            tokio::pin!(pause);
            assert!(tokio::time::timeout(Duration::from_millis(20), &mut pause)
                .await
                .is_err());

            state.release_dump.notify_one();
            state.update_started.notified().await;
            assert!(tokio::time::timeout(Duration::from_millis(20), &mut pause)
                .await
                .is_err());
            state.release_update.notify_one();
            tokio::time::timeout(Duration::from_secs(1), &mut pause)
                .await
                .unwrap()
                .unwrap()
        };

        assert_eq!(receipt.revision().get(), 1);
        assert_eq!(receipt.request(), request);
        assert_eq!(receipt.unique_id(), 41);
        assert_eq!(state.dump_calls.load(Ordering::SeqCst), 1);
        assert_eq!(state.update_calls.load(Ordering::SeqCst), 1);
        assert_eq!(state.finalize_calls.load(Ordering::SeqCst), 0);
        assert_eq!(state.delete_calls.load(Ordering::SeqCst), 0);

        let status = gatherer.status().await.unwrap();
        assert_eq!(status.phase(), GathererBoundaryPhase::Paused);
        assert_eq!(status.revision().get(), 1);
        assert_eq!(status.request(), Some(request));
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(state.dump_calls.load(Ordering::SeqCst), 1);
        assert_eq!(state.update_calls.load(Ordering::SeqCst), 1);

        let retry_receipt = gatherer.pause(request).await.unwrap();
        assert_eq!(retry_receipt.revision().get(), 1);
        let conflict = GathererPauseRequest::new(
            drain_request(2),
            GathererActorRevision::try_new(0).unwrap(),
            41,
        );
        assert_eq!(
            gatherer.pause(conflict).await.unwrap_err(),
            GathererPauseError::AlreadyPausedAtDifferentRequest
        );
        assert!(gatherer
            .finalize_gathering_and_update_queue_key(42)
            .await
            .unwrap_err()
            .to_string()
            .contains("FinalizeWhilePaused"));
        assert_eq!(gatherer.status().await.unwrap().unique_id(), 41);

        let resumed = gatherer.resume(receipt).await.unwrap();
        assert_eq!(resumed.phase(), GathererBoundaryPhase::Running);
        assert_eq!(resumed.revision().get(), 2);
        join.abort();
        assert!(join.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn callback_error_never_mints_a_clean_pause_receipt() {
        let state = Arc::new(TestGathererState::default());
        state.fail_update.store(true, Ordering::SeqCst);
        let (gatherer, join) = start_test_gatherer(state.clone());
        state.dump_started.notified().await;
        let request = GathererPauseRequest::new(
            drain_request(3),
            GathererActorRevision::try_new(0).unwrap(),
            41,
        );
        let pause = gatherer.pause(request);
        tokio::pin!(pause);
        assert!(tokio::time::timeout(Duration::from_millis(20), &mut pause)
            .await
            .is_err());
        state.release_dump.notify_one();
        state.update_started.notified().await;
        state.release_update.notify_one();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), &mut pause)
                .await
                .unwrap()
                .unwrap_err(),
            GathererPauseError::CallbackBoundaryFailed
        );
        join.abort();
        assert!(join.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn finalize_rotates_inside_actor_and_replies_after_terminal_cleanup() {
        let state = Arc::new(TestGathererState::default());
        state.subsequent_dump_empty.store(true, Ordering::SeqCst);
        state.block_delete.store(true, Ordering::SeqCst);
        let (mut gatherer, join) = start_test_gatherer(state.clone());
        state.dump_started.notified().await;

        let output = {
            let finalize = gatherer.finalize_gathering_and_update_queue_key(42);
            tokio::pin!(finalize);
            assert!(tokio::time::timeout(Duration::from_millis(20), &mut finalize)
                .await
                .is_err());
            state.release_dump.notify_one();
            state.update_started.notified().await;
            state.release_update.notify_one();
            state.delete_started.notified().await;
            assert_eq!(state.finalize_calls.load(Ordering::SeqCst), 1);
            assert!(tokio::time::timeout(Duration::from_millis(20), &mut finalize)
                .await
                .is_err());
            state.release_delete.notify_one();
            tokio::time::timeout(Duration::from_secs(1), &mut finalize)
                .await
                .unwrap()
                .unwrap()
        };

        assert_eq!(output, 1);
        assert_eq!(state.delete_calls.load(Ordering::SeqCst), 1);
        assert_eq!(gatherer.status().await.unwrap().unique_id(), 42);
        join.abort();
        assert!(join.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn durable_actor_applies_exhaustive_generation_once_without_queue_io() {
        let state = Arc::new(TestGathererState::default());
        let (mut gatherer, join) = start_durable_test_gatherer(state.clone());
        state.release_update.notify_one();
        let receipt = gatherer
            .apply_durable_generation(
                durable_generation(1),
                durable_input(PendingGenerationBootstrapReason::LegacyActivation),
            )
            .await
            .unwrap();
        assert_eq!(receipt.item_count(), 2);
        assert_eq!(receipt.actor_revision().get(), 1);
        let expected_input_digest = receipt.actor_input_digest();
        assert_eq!(state.update_calls.load(Ordering::SeqCst), 1);

        let retry = gatherer
            .apply_durable_generation(
                durable_generation(1),
                durable_input(PendingGenerationBootstrapReason::LegacyActivation),
            )
            .await
            .unwrap();
        assert_eq!(retry.generation_digest(), receipt.generation_digest());
        assert_eq!(retry.actor_input_digest(), receipt.actor_input_digest());
        assert_eq!(retry.actor_revision(), receipt.actor_revision());
        assert_eq!(state.update_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            gatherer
                .apply_durable_generation(
                    durable_generation(1),
                    durable_input(PendingGenerationBootstrapReason::Genesis),
                )
                .await
                .unwrap_err(),
            GathererPauseError::DurableGenerationIdentityMismatch
        );
        assert_eq!(state.update_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            gatherer
                .apply_durable_generation(
                    durable_generation(2),
                    durable_input(PendingGenerationBootstrapReason::LegacyActivation),
                )
                .await
                .unwrap_err(),
            GathererPauseError::DurableGenerationIdentityMismatch
        );

        let foreign_state = Arc::new(TestGathererState::default());
        let (foreign_gatherer, foreign_join) =
            start_durable_test_gatherer(foreign_state.clone());
        foreign_state.release_update.notify_one();
        let foreign_receipt = foreign_gatherer
            .apply_durable_generation(
                durable_generation(1),
                durable_input(PendingGenerationBootstrapReason::LegacyActivation),
            )
            .await
            .unwrap();
        assert_eq!(
            gatherer
                .finalize_durable_generation(foreign_receipt)
                .await
                .err()
                .unwrap(),
            GathererPauseError::DurableGenerationIdentityMismatch
        );
        drop(foreign_gatherer);
        foreign_join.await.unwrap().unwrap();

        let finalized = gatherer
            .finalize_durable_generation(receipt)
            .await
            .unwrap();
        assert_eq!(finalized.actor_revision().get(), 2);
        assert_eq!(finalized.item_count(), 2);
        assert_eq!(finalized.actor_input_digest(), expected_input_digest);
        assert_eq!(*finalized.output(), 1);
        assert_eq!(state.finalize_calls.load(Ordering::SeqCst), 1);

        let retry_apply = gatherer
            .apply_durable_generation(
                durable_generation(1),
                durable_input(PendingGenerationBootstrapReason::LegacyActivation),
            )
            .await
            .unwrap();
        let retry_finalize = gatherer
            .finalize_durable_generation(retry_apply)
            .await
            .unwrap();
        assert_eq!(retry_finalize.actor_revision(), finalized.actor_revision());
        assert_eq!(retry_finalize.generation_digest(), finalized.generation_digest());
        assert_eq!(*retry_finalize.output(), 1);
        assert_eq!(state.finalize_calls.load(Ordering::SeqCst), 1);

        let pause_receipt = gatherer
            .pause(GathererPauseRequest::new(
                drain_request(10),
                GathererActorRevision::try_new(2).unwrap(),
                41,
            ))
            .await
            .unwrap();
        assert_eq!(pause_receipt.revision().get(), 3);
        assert_eq!(gatherer.resume(pause_receipt).await.unwrap().revision().get(), 4);
        let post_resume_apply = gatherer
            .apply_durable_generation(
                durable_generation(1),
                durable_input(PendingGenerationBootstrapReason::LegacyActivation),
            )
            .await
            .unwrap();
        let post_resume_finalize = gatherer
            .finalize_durable_generation(post_resume_apply)
            .await
            .unwrap();
        assert_eq!(post_resume_finalize.actor_revision(), finalized.actor_revision());
        assert_eq!(post_resume_finalize.generation_digest(), finalized.generation_digest());
        assert_eq!(state.finalize_calls.load(Ordering::SeqCst), 1);

        assert!(gatherer
            .finalize_gathering_and_update_queue_key(42)
            .await
            .unwrap_err()
            .to_string()
            .contains("SemanticHandoffNotIntegrated"));
        assert_eq!(state.dump_calls.load(Ordering::SeqCst), 0);
        assert_eq!(state.ensure_calls.load(Ordering::SeqCst), 0);
        assert_eq!(state.delete_calls.load(Ordering::SeqCst), 0);
        assert_eq!(state.finalize_calls.load(Ordering::SeqCst), 1);
        drop(gatherer);
        join.await.unwrap().unwrap();
    }

    #[test]
    fn realm_durable_actor_binds_deferred_lineage_before_external_data() {
        let actor = include_str!("gatherer.rs")
            .split("async fn durable_gatherer_runner_for_tree")
            .nth(1)
            .unwrap()
            .split("\nasync fn gatherer_runner_for_tree")
            .next()
            .unwrap();
        let bind = actor.find("bind_complete_generation").unwrap();
        let create = actor.find("Builder::create_new_with_tree").unwrap();
        let external = actor
            .find("update_from_many_queue_items_with_tree")
            .unwrap();
        assert!(bind < create);
        assert!(create < external);

        let realm = include_str!(
            "../realm/processor/gatherers/realm_end_cap_gatherer.rs"
        );
        let create = realm
            .split("async fn create_new_with_tree")
            .nth(1)
            .unwrap()
            .split("async fn update_from_queue_item_with_tree")
            .next()
            .unwrap();
        let isolate = create.find("future_pending_end_cap_jobs").unwrap();
        let inject = create.find("add_future_end_cap_jobs").unwrap();
        assert!(isolate < inject);
    }

    #[tokio::test]
    async fn durable_pause_waits_for_apply_and_failed_actor_replays_from_clean_builder() {
        let state = Arc::new(TestGathererState::default());
        let (gatherer, join) = start_durable_test_gatherer(state.clone());
        let pause_receipt = {
            let apply = gatherer.apply_durable_generation(
                durable_generation(3),
                durable_input(PendingGenerationBootstrapReason::LegacyActivation),
            );
            tokio::pin!(apply);
            assert!(tokio::time::timeout(Duration::from_millis(20), &mut apply)
                .await
                .is_err());
            assert_eq!(state.update_calls.load(Ordering::SeqCst), 1);
            let pause = gatherer.pause(GathererPauseRequest::new(
                drain_request(9),
                GathererActorRevision::try_new(1).unwrap(),
                41,
            ));
            tokio::pin!(pause);
            assert!(tokio::time::timeout(Duration::from_millis(20), &mut pause)
                .await
                .is_err());
            state.release_update.notify_one();
            apply.as_mut().await.unwrap();
            pause.as_mut().await.unwrap()
        };
        assert_eq!(pause_receipt.revision().get(), 2);
        drop(gatherer);
        join.await.unwrap().unwrap();

        let failed = Arc::new(TestGathererState::default());
        failed.fail_update.store(true, Ordering::SeqCst);
        let (failed_gatherer, failed_join) = start_durable_test_gatherer(failed.clone());
        failed.release_update.notify_one();
        assert_eq!(
            failed_gatherer
                .apply_durable_generation(
                    durable_generation(4),
                    durable_input(PendingGenerationBootstrapReason::LegacyActivation),
                )
                .await
                .unwrap_err(),
            GathererPauseError::DurableGenerationApplyFailed
        );
        assert!(failed_join.await.unwrap().is_err());

        let recovered = Arc::new(TestGathererState::default());
        let (recovered_gatherer, recovered_join) =
            start_durable_test_gatherer(recovered.clone());
        recovered.release_update.notify_one();
        recovered_gatherer
            .apply_durable_generation(
                durable_generation(4),
                durable_input(PendingGenerationBootstrapReason::LegacyActivation),
            )
            .await
            .unwrap();
        assert_eq!(recovered.update_calls.load(Ordering::SeqCst), 1);
        drop(recovered_gatherer);
        recovered_join.await.unwrap().unwrap();

        let finalize_failed = Arc::new(TestGathererState::default());
        finalize_failed.fail_finalize.store(true, Ordering::SeqCst);
        let (finalize_failed_gatherer, finalize_failed_join) =
            start_durable_test_gatherer(finalize_failed.clone());
        finalize_failed.release_update.notify_one();
        let failed_receipt = finalize_failed_gatherer
            .apply_durable_generation(
                durable_generation(5),
                durable_input(PendingGenerationBootstrapReason::LegacyActivation),
            )
            .await
            .unwrap();
        assert_eq!(
            finalize_failed_gatherer
                .finalize_durable_generation(failed_receipt)
                .await
                .err()
                .unwrap(),
            GathererPauseError::DurableGenerationApplyFailed
        );
        assert!(finalize_failed_join.await.unwrap().is_err());

        let finalize_recovered = Arc::new(TestGathererState::default());
        let (finalize_recovered_gatherer, finalize_recovered_join) =
            start_durable_test_gatherer(finalize_recovered.clone());
        finalize_recovered.release_update.notify_one();
        let recovered_receipt = finalize_recovered_gatherer
            .apply_durable_generation(
                durable_generation(5),
                durable_input(PendingGenerationBootstrapReason::LegacyActivation),
            )
            .await
            .unwrap();
        let recovered_output = finalize_recovered_gatherer
            .finalize_durable_generation(recovered_receipt)
            .await
            .unwrap();
        assert_eq!(*recovered_output.output(), 1);
        drop(finalize_recovered_gatherer);
        finalize_recovered_join.await.unwrap().unwrap();
    }
}
