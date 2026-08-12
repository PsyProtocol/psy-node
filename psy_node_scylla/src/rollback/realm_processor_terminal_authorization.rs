//! Storage-private signer for one Realm terminal or no-work retirement
//! evidence envelope.
//!
//! It reads the terminal pipeline, Active writer, authority-local head, and
//! successor dependency projection from their durable stores, validates the
//! complete relationship, then repeats every read. The result is still only
//! an input to the storage-owned terminal/retirement owner; it cannot persist
//! a terminal or apply a pipeline transition by itself.

#![allow(dead_code)]

use std::{error::Error, fmt, sync::Arc};

use async_trait::async_trait;
use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::NetworkId,
    chain_context::{AuthorityObservation, AuthorityScope},
};
use psy_node_core::{
    queue::realm_processor_terminal_authorization::{
        RealmProcessorTerminalAuthorizationEnvelope,
        RealmProcessorTerminalAuthorizationError,
    },
    queue::{
        realm_user_update_publish::GlobalUserTreeHeight,
        realm_user_update_consumer::RealmUserUpdateDurableConsumerError,
        recoverable_ephemeral::PendingQueueCaptureContext,
    },
    store::{
        authority_commit::AuthorityTimestampKey,
        authority_local_head::{
            AuthorityLocalHeadReadState, StoredAuthorityLocalHead,
        },
        pending_generation_pipeline::{
            PendingPipelineReadState, StoredPendingPipeline,
        },
    },
};
use psy_node_nats::recoverable_assignment::PendingQueueSegmentLedgerKey;
use scylla::client::session::Session;

use super::{
    branch_exact_pending_orchestration::{
        validate_branch_exact_application_no_work_pair,
        validate_branch_exact_deferred_only_pair,
        validate_branch_exact_queue_terminal_pair,
        BranchExactPendingOrchestrationError,
    },
    realm_processor_external_dependency_projection::{
        PersistedRealmProcessorExternalDependencyProjection,
        RealmProcessorExternalDependencyProjectionError,
        ScyllaRealmProcessorExternalDependencyProjector,
    },
    pending_queue_segment_ledger::{
        PendingQueueSegmentAssignmentRouteReceipt,
        PendingQueueSegmentLedgerStoreError, ScyllaPendingQueueSegmentLedgerStore,
    },
    BranchExactWriterAuthorityKey, BranchExactWriterReadState, ScyllaAuthorityLocalHeadStore,
    ScyllaBranchExactWriterLifecycleStore, ScyllaPendingPipelineStore,
    StoredBranchExactWriterLifecycle, PendingQueueSidecarReady,
};

pub(super) struct PersistedRealmProcessorTerminalAuthorization<Hash> {
    mode: RealmProcessorTerminalAuthorizationMode,
    envelope: RealmProcessorTerminalAuthorizationEnvelope,
    route: PendingQueueSegmentAssignmentRouteReceipt,
    dependency: PersistedRealmProcessorExternalDependencyProjection,
    pipeline: StoredPendingPipeline<Hash>,
    writer: StoredBranchExactWriterLifecycle<Hash>,
    head: StoredAuthorityLocalHead<Hash>,
}

impl<Hash: Q256BitHash> PersistedRealmProcessorTerminalAuthorization<Hash> {
    pub(super) const fn envelope(&self) -> &RealmProcessorTerminalAuthorizationEnvelope {
        &self.envelope
    }

    pub(super) const fn pipeline(&self) -> &StoredPendingPipeline<Hash> {
        &self.pipeline
    }

    pub(super) const fn writer(&self) -> &StoredBranchExactWriterLifecycle<Hash> {
        &self.writer
    }

    pub(super) fn head_observation(
        &self,
    ) -> Result<AuthorityObservation<Hash>, RealmProcessorTerminalAuthorizationStoreError> {
        authority_observation(&self.head)
    }

    pub(super) const fn allocation_timestamp(
        &self,
    ) -> psy_node_core::store::timestamp::CommitWriteTimestampUs {
        self.head.commit_write_timestamp()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RealmProcessorTerminalAuthorizationMode {
    Terminal,
    RetireNoWork,
    RetireDeferredOnly,
}

#[async_trait]
pub(super) trait RealmProcessorTerminalAuthorizationProvider<Hash>: Send + Sync {
    async fn authorize_current(
        &self,
    ) -> Result<
        PersistedRealmProcessorTerminalAuthorization<Hash>,
        RealmProcessorTerminalAuthorizationStoreError,
    >;

    async fn revalidate_exact(
        &self,
        receipt: &PersistedRealmProcessorTerminalAuthorization<Hash>,
    ) -> Result<(), RealmProcessorTerminalAuthorizationStoreError>;

    async fn authorize_no_work_current(
        &self,
    ) -> Result<
        PersistedRealmProcessorTerminalAuthorization<Hash>,
        RealmProcessorTerminalAuthorizationStoreError,
    >;

    async fn authorize_deferred_only_current(
        &self,
    ) -> Result<
        PersistedRealmProcessorTerminalAuthorization<Hash>,
        RealmProcessorTerminalAuthorizationStoreError,
    >;
}

pub(super) struct ScyllaRealmProcessorTerminalAuthorizer<F, Hash> {
    session: Arc<Session>,
    network: NetworkId,
    authority: AuthorityScope,
    global_user_tree_height: GlobalUserTreeHeight,
    ready: Arc<PendingQueueSidecarReady>,
    ledger_key: PendingQueueSegmentLedgerKey,
    ledger: Arc<ScyllaPendingQueueSegmentLedgerStore>,
    pipeline: Arc<ScyllaPendingPipelineStore>,
    writer: Arc<ScyllaBranchExactWriterLifecycleStore>,
    head: Arc<ScyllaAuthorityLocalHeadStore>,
    _types: std::marker::PhantomData<(F, Hash)>,
}

impl<F, Hash> ScyllaRealmProcessorTerminalAuthorizer<F, Hash>
where
    F: parth_core::felt::QFelt64 + Send + Sync,
    Hash: Q256BitHash + parth_core::protocol::core_types::QFHashBase<F> + Send + Sync,
{
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        session: Arc<Session>,
        network: NetworkId,
        authority: AuthorityScope,
        global_user_tree_height: GlobalUserTreeHeight,
        ready: Arc<PendingQueueSidecarReady>,
        base_namespace: &str,
        ledger: Arc<ScyllaPendingQueueSegmentLedgerStore>,
        pipeline: Arc<ScyllaPendingPipelineStore>,
        writer: Arc<ScyllaBranchExactWriterLifecycleStore>,
        head: Arc<ScyllaAuthorityLocalHeadStore>,
    ) -> Result<Self, RealmProcessorTerminalAuthorizationStoreError> {
        if !matches!(authority, AuthorityScope::Realm { .. })
            || ready.view().authority() != authority
            || base_namespace.is_empty()
        {
            return Err(RealmProcessorTerminalAuthorizationStoreError::IdentityMismatch);
        }
        let ledger_key = PendingQueueSegmentLedgerKey::try_new(
            psy_node_core::store::pending_generation_identity::PendingGenerationLedgerKey::new(
                network,
                authority,
            ),
            base_namespace,
        )
        .map_err(backend)?;
        Ok(Self {
            session,
            network,
            authority,
            global_user_tree_height,
            ready,
            ledger_key,
            ledger,
            pipeline,
            writer,
            head,
            _types: std::marker::PhantomData,
        })
    }

    async fn authorize_selected(
        &self,
        mode: RealmProcessorTerminalAuthorizationMode,
    ) -> Result<
        PersistedRealmProcessorTerminalAuthorization<Hash>,
        RealmProcessorTerminalAuthorizationStoreError,
    > {
        let (pipeline, writer, head) = self.read_terminal_sources().await?;
        let context = PendingQueueCaptureContext::try_new(
            pipeline.key(),
            pipeline.activation_digest(),
            pipeline.gathering(),
        )
        .map_err(backend)?;
        let route = self
            .ledger
            .read_assignment_route_exact(&self.ledger_key, context)
            .await
            .map_err(RealmProcessorTerminalAuthorizationStoreError::Assignment)?;
        self.ledger
            .revalidate_assignment_route(&route)
            .await
            .map_err(RealmProcessorTerminalAuthorizationStoreError::Assignment)?;
        let projector = ScyllaRealmProcessorExternalDependencyProjector::<F, Hash>::prepare(
            self.session.clone(),
            self.network,
            self.authority,
            self.global_user_tree_height,
            self.ready.clone(),
            route.segment().clone(),
        )
        .await?;
        let dependency = projector
            .read_gathering_selected_exact(
                context,
                *route.assignment().assignment().digest().as_bytes(),
            )
            .await?;
        projector.revalidate_exact(&dependency).await?;
        self.validate_relationship(mode, &pipeline, &writer, &head, &dependency)?;
        let envelope = RealmProcessorTerminalAuthorizationEnvelope::try_new(
            dependency.commitment(),
            *writer.slot().as_bytes(),
            writer.revision().get(),
            writer.to_canonical_bytes(),
            head.revision().get(),
            head.encode_canonical().to_vec(),
        )?;

        self.ledger
            .revalidate_assignment_route(&route)
            .await
            .map_err(RealmProcessorTerminalAuthorizationStoreError::Assignment)?;
        projector.revalidate_exact(&dependency).await?;
        let (second_pipeline, second_writer, second_head) =
            self.read_terminal_sources().await?;
        self.validate_relationship(
            mode,
            &second_pipeline,
            &second_writer,
            &second_head,
            &dependency,
        )?;
        if pipeline != second_pipeline || writer != second_writer || head != second_head {
            return Err(RealmProcessorTerminalAuthorizationStoreError::ConcurrentMutation);
        }
        Ok(PersistedRealmProcessorTerminalAuthorization {
            mode,
            envelope,
            route,
            dependency,
            pipeline: second_pipeline,
            writer: second_writer,
            head: second_head,
        })
    }

    async fn revalidate_selected(
        &self,
        receipt: &PersistedRealmProcessorTerminalAuthorization<Hash>,
    ) -> Result<(), RealmProcessorTerminalAuthorizationStoreError> {
        self.ledger
            .revalidate_assignment_route(&receipt.route)
            .await
            .map_err(RealmProcessorTerminalAuthorizationStoreError::Assignment)?;
        let projector = ScyllaRealmProcessorExternalDependencyProjector::<F, Hash>::prepare(
            self.session.clone(),
            self.network,
            self.authority,
            self.global_user_tree_height,
            self.ready.clone(),
            receipt.route.segment().clone(),
        )
        .await?;
        projector.revalidate_exact(&receipt.dependency).await?;
        if receipt.dependency.commitment() != receipt.envelope.external_dependency() {
            return Err(RealmProcessorTerminalAuthorizationStoreError::ConcurrentMutation);
        }
        let (pipeline, writer, head) = self.read_terminal_sources().await?;
        if pipeline != receipt.pipeline || writer != receipt.writer || head != receipt.head {
            return Err(RealmProcessorTerminalAuthorizationStoreError::ConcurrentMutation);
        }
        self.validate_relationship(
            receipt.mode,
            &pipeline,
            &writer,
            &head,
            &receipt.dependency,
        )?;
        let envelope = RealmProcessorTerminalAuthorizationEnvelope::try_new(
            receipt.envelope.external_dependency(),
            *writer.slot().as_bytes(),
            writer.revision().get(),
            writer.to_canonical_bytes(),
            head.revision().get(),
            head.encode_canonical().to_vec(),
        )?;
        if envelope != receipt.envelope {
            return Err(RealmProcessorTerminalAuthorizationStoreError::ConcurrentMutation);
        }
        Ok(())
    }

    async fn read_terminal_sources(
        &self,
    ) -> Result<
        (
            StoredPendingPipeline<Hash>,
            StoredBranchExactWriterLifecycle<Hash>,
            StoredAuthorityLocalHead<Hash>,
        ),
        RealmProcessorTerminalAuthorizationStoreError,
    > {
        let key = psy_node_core::store::pending_generation_identity::PendingGenerationLedgerKey::new(
            self.network,
            self.authority,
        );
        let PendingPipelineReadState::Current(pipeline) = self
            .pipeline
            .read::<Hash>(key)
            .await
            .map_err(backend)?
        else {
            return Err(RealmProcessorTerminalAuthorizationStoreError::MissingPipeline);
        };
        let BranchExactWriterReadState::Current(writer) = self
            .writer
            .read::<Hash>(BranchExactWriterAuthorityKey::new(
                self.network,
                self.authority,
            ))
            .await
            .map_err(backend)?
        else {
            return Err(RealmProcessorTerminalAuthorizationStoreError::MissingWriter);
        };
        let AuthorityLocalHeadReadState::Current(head) = self
            .head
            .read::<Hash>(AuthorityTimestampKey::new(
                self.network,
                self.authority,
            ))
            .await
            .map_err(backend)?
        else {
            return Err(RealmProcessorTerminalAuthorizationStoreError::MissingHead);
        };
        Ok((pipeline, writer, head))
    }

    fn validate_relationship(
        &self,
        mode: RealmProcessorTerminalAuthorizationMode,
        pipeline: &StoredPendingPipeline<Hash>,
        writer: &StoredBranchExactWriterLifecycle<Hash>,
        head: &StoredAuthorityLocalHead<Hash>,
        dependency: &PersistedRealmProcessorExternalDependencyProjection,
    ) -> Result<(), RealmProcessorTerminalAuthorizationStoreError> {
        if pipeline.key().network() != self.network
            || pipeline.key().authority() != self.authority
            || pipeline.blocked_reason().is_some()
        {
            return Err(RealmProcessorTerminalAuthorizationStoreError::IdentityMismatch);
        }
        match mode {
            RealmProcessorTerminalAuthorizationMode::Terminal => {
                validate_branch_exact_queue_terminal_pair(pipeline, writer)?
            }
            RealmProcessorTerminalAuthorizationMode::RetireNoWork => {
                validate_branch_exact_application_no_work_pair(pipeline, writer)?
            }
            RealmProcessorTerminalAuthorizationMode::RetireDeferredOnly => {
                validate_branch_exact_deferred_only_pair(pipeline, writer)?
            }
        }
        let view = head.head();
        let observed = authority_observation(head)?;
        if observed != *pipeline.frontier()
            || view.key().network() != self.network
            || view.key().authority() != self.authority
        {
            return Err(RealmProcessorTerminalAuthorizationStoreError::HeadMismatch);
        }
        let context = dependency.commitment().context();
        if context.key() != pipeline.key()
            || context.activation() != pipeline.activation_digest()
            || context.processing() != pipeline.gathering()
        {
            return Err(RealmProcessorTerminalAuthorizationStoreError::DependencyGenerationMismatch);
        }
        Ok(())
    }
}

#[async_trait]
impl<F, Hash> RealmProcessorTerminalAuthorizationProvider<Hash>
    for ScyllaRealmProcessorTerminalAuthorizer<F, Hash>
where
    F: parth_core::felt::QFelt64 + Send + Sync,
    Hash: Q256BitHash + parth_core::protocol::core_types::QFHashBase<F> + Send + Sync,
{
    async fn authorize_current(
        &self,
    ) -> Result<
        PersistedRealmProcessorTerminalAuthorization<Hash>,
        RealmProcessorTerminalAuthorizationStoreError,
    > {
        self.authorize_selected(RealmProcessorTerminalAuthorizationMode::Terminal)
            .await
    }

    async fn revalidate_exact(
        &self,
        receipt: &PersistedRealmProcessorTerminalAuthorization<Hash>,
    ) -> Result<(), RealmProcessorTerminalAuthorizationStoreError> {
        self.revalidate_selected(receipt).await
    }

    async fn authorize_no_work_current(
        &self,
    ) -> Result<
        PersistedRealmProcessorTerminalAuthorization<Hash>,
        RealmProcessorTerminalAuthorizationStoreError,
    > {
        self.authorize_selected(RealmProcessorTerminalAuthorizationMode::RetireNoWork)
            .await
    }

    async fn authorize_deferred_only_current(
        &self,
    ) -> Result<
        PersistedRealmProcessorTerminalAuthorization<Hash>,
        RealmProcessorTerminalAuthorizationStoreError,
    > {
        self.authorize_selected(
            RealmProcessorTerminalAuthorizationMode::RetireDeferredOnly,
        )
        .await
    }
}

fn authority_observation<Hash: Q256BitHash>(
    head: &StoredAuthorityLocalHead<Hash>,
) -> Result<AuthorityObservation<Hash>, RealmProcessorTerminalAuthorizationStoreError> {
    let view = head.head();
    AuthorityObservation::try_new(
        *view.chain(),
        view.key().authority(),
        view.state_checkpoint(),
        *view.state_root(),
    )
    .map_err(backend)
}

fn backend(error: impl fmt::Display) -> RealmProcessorTerminalAuthorizationStoreError {
    RealmProcessorTerminalAuthorizationStoreError::Backend(error.to_string())
}

#[derive(Debug)]
pub(super) enum RealmProcessorTerminalAuthorizationStoreError {
    IdentityMismatch,
    MissingPipeline,
    MissingWriter,
    MissingHead,
    HeadMismatch,
    DependencyGenerationMismatch,
    ConcurrentMutation,
    Assignment(PendingQueueSegmentLedgerStoreError),
    Pending(BranchExactPendingOrchestrationError),
    Dependency(RealmProcessorExternalDependencyProjectionError),
    Envelope(RealmProcessorTerminalAuthorizationError),
    Backend(String),
}

impl RealmProcessorTerminalAuthorizationStoreError {
    /// The successor generation may legitimately still be gathering. Only
    /// these exact absence/not-yet-qualified states are retryable waits;
    /// corruption, backend loss and identity drift remain hard failures.
    pub(super) const fn successor_dependency_pending(&self) -> bool {
        match self {
            Self::Assignment(PendingQueueSegmentLedgerStoreError::AssignmentMissing) => true,
            Self::Dependency(
                RealmProcessorExternalDependencyProjectionError::Consumer(error),
            ) => matches!(
                error,
                RealmUserUpdateDurableConsumerError::GenerationUninitialized
                    | RealmUserUpdateDurableConsumerError::GenerationNotQualified
                    | RealmUserUpdateDurableConsumerError::AwaitExactRequestReplay
                    | RealmUserUpdateDurableConsumerError::AwaitExactArtifactReplay
                    | RealmUserUpdateDurableConsumerError::AwaitProofRecovery
                    | RealmUserUpdateDurableConsumerError::AwaitPublication
                    | RealmUserUpdateDurableConsumerError::AwaitClaimPublication
                    | RealmUserUpdateDurableConsumerError::TerminalSourceMissing
            ),
            _ => false,
        }
    }
}

impl From<BranchExactPendingOrchestrationError>
    for RealmProcessorTerminalAuthorizationStoreError
{
    fn from(value: BranchExactPendingOrchestrationError) -> Self {
        Self::Pending(value)
    }
}

impl From<RealmProcessorExternalDependencyProjectionError>
    for RealmProcessorTerminalAuthorizationStoreError
{
    fn from(value: RealmProcessorExternalDependencyProjectionError) -> Self {
        Self::Dependency(value)
    }
}

impl From<RealmProcessorTerminalAuthorizationError>
    for RealmProcessorTerminalAuthorizationStoreError
{
    fn from(value: RealmProcessorTerminalAuthorizationError) -> Self {
        Self::Envelope(value)
    }
}

impl fmt::Display for RealmProcessorTerminalAuthorizationStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RealmProcessorTerminalAuthorizationStoreError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorizer_is_storage_selected_and_cannot_persist_or_rotate() {
        let source = include_str!("realm_processor_terminal_authorization.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("read_terminal_sources"));
        assert!(production.contains("revalidate_exact"));
        assert!(production.contains("validate_branch_exact_queue_terminal_pair"));
        assert!(production.contains("validate_branch_exact_application_no_work_pair"));
        assert!(production.contains("authorize_no_work_current"));
        assert!(!production.contains("qualification_persist"));
        assert!(!production.contains("seal_rotation"));
        assert!(!production.contains("pipeline.apply"));
        assert!(!production.contains("publish_authority_head"));
    }

    #[test]
    fn only_exact_successor_absence_states_are_retryable_waits() {
        assert!(RealmProcessorTerminalAuthorizationStoreError::Assignment(
            PendingQueueSegmentLedgerStoreError::AssignmentMissing,
        )
        .successor_dependency_pending());
        assert!(RealmProcessorTerminalAuthorizationStoreError::Dependency(
            RealmProcessorExternalDependencyProjectionError::Consumer(
                RealmUserUpdateDurableConsumerError::AwaitPublication,
            ),
        )
        .successor_dependency_pending());
        assert!(RealmProcessorTerminalAuthorizationStoreError::Dependency(
            RealmProcessorExternalDependencyProjectionError::Consumer(
                RealmUserUpdateDurableConsumerError::TerminalSourceMissing,
            ),
        )
        .successor_dependency_pending());

        for error in [
            RealmUserUpdateDurableConsumerError::DurableDependencyLoss,
            RealmUserUpdateDurableConsumerError::DependencyCorruption("tampered".to_owned()),
            RealmUserUpdateDurableConsumerError::ConcurrentChange,
        ] {
            assert!(
                !RealmProcessorTerminalAuthorizationStoreError::Dependency(
                    RealmProcessorExternalDependencyProjectionError::Consumer(error),
                )
                .successor_dependency_pending()
            );
        }
        assert!(!RealmProcessorTerminalAuthorizationStoreError::Assignment(
            PendingQueueSegmentLedgerStoreError::AssignmentMismatch,
        )
        .successor_dependency_pending());
        assert!(!RealmProcessorTerminalAuthorizationStoreError::ConcurrentMutation
            .successor_dependency_pending());
    }
}
