//! Storage-private signer for one Realm terminal evidence envelope.
//!
//! It reads the terminal pipeline, Active writer, authority-local head, and
//! successor dependency projection from their durable stores, validates the
//! complete relationship, then repeats every read. The result is still only
//! an input to the future terminal owner; it cannot persist a terminal or
//! apply a pipeline transition.

#![allow(dead_code)]

use std::{error::Error, fmt, sync::Arc};

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

use super::{
    branch_exact_pending_orchestration::{
        validate_branch_exact_queue_terminal_pair, BranchExactPendingOrchestrationError,
    },
    realm_processor_external_dependency_projection::{
        PersistedRealmProcessorExternalDependencyProjection,
        RealmProcessorExternalDependencyProjectionError,
        ScyllaRealmProcessorExternalDependencyProjector,
    },
    BranchExactWriterAuthorityKey, BranchExactWriterReadState, ScyllaAuthorityLocalHeadStore,
    ScyllaBranchExactWriterLifecycleStore, ScyllaPendingPipelineStore,
    StoredBranchExactWriterLifecycle,
};

pub(super) struct PersistedRealmProcessorTerminalAuthorization<Hash> {
    envelope: RealmProcessorTerminalAuthorizationEnvelope,
    dependency: PersistedRealmProcessorExternalDependencyProjection,
    pipeline: StoredPendingPipeline<Hash>,
    writer: StoredBranchExactWriterLifecycle<Hash>,
    head: StoredAuthorityLocalHead<Hash>,
}

impl<Hash> PersistedRealmProcessorTerminalAuthorization<Hash> {
    pub(super) const fn envelope(&self) -> &RealmProcessorTerminalAuthorizationEnvelope {
        &self.envelope
    }

    pub(super) const fn pipeline(&self) -> &StoredPendingPipeline<Hash> {
        &self.pipeline
    }
}

pub(super) struct ScyllaRealmProcessorTerminalAuthorizer<F, Hash> {
    network: NetworkId,
    authority: AuthorityScope,
    pipeline: Arc<ScyllaPendingPipelineStore>,
    writer: Arc<ScyllaBranchExactWriterLifecycleStore>,
    head: Arc<ScyllaAuthorityLocalHeadStore>,
    dependency: Arc<ScyllaRealmProcessorExternalDependencyProjector<F, Hash>>,
}

impl<F, Hash> ScyllaRealmProcessorTerminalAuthorizer<F, Hash>
where
    F: parth_core::felt::QFelt64 + Send + Sync,
    Hash: Q256BitHash + parth_core::protocol::core_types::QFHashBase<F> + Send + Sync,
{
    pub(super) fn new(
        network: NetworkId,
        authority: AuthorityScope,
        pipeline: Arc<ScyllaPendingPipelineStore>,
        writer: Arc<ScyllaBranchExactWriterLifecycleStore>,
        head: Arc<ScyllaAuthorityLocalHeadStore>,
        dependency: Arc<ScyllaRealmProcessorExternalDependencyProjector<F, Hash>>,
    ) -> Result<Self, RealmProcessorTerminalAuthorizationStoreError> {
        if !matches!(authority, AuthorityScope::Realm { .. }) {
            return Err(RealmProcessorTerminalAuthorizationStoreError::IdentityMismatch);
        }
        Ok(Self {
            network,
            authority,
            pipeline,
            writer,
            head,
            dependency,
        })
    }

    pub(super) async fn authorize(
        &self,
        dependency: PersistedRealmProcessorExternalDependencyProjection,
    ) -> Result<
        PersistedRealmProcessorTerminalAuthorization<Hash>,
        RealmProcessorTerminalAuthorizationStoreError,
    > {
        self.dependency.revalidate_exact(&dependency).await?;
        let (pipeline, writer, head) = self.read_terminal_sources().await?;
        self.validate_relationship(&pipeline, &writer, &head, &dependency)?;
        let envelope = RealmProcessorTerminalAuthorizationEnvelope::try_new(
            dependency.commitment(),
            *writer.slot().as_bytes(),
            writer.revision().get(),
            writer.to_canonical_bytes(),
            head.revision().get(),
            head.encode_canonical().to_vec(),
        )?;

        self.dependency.revalidate_exact(&dependency).await?;
        let (second_pipeline, second_writer, second_head) =
            self.read_terminal_sources().await?;
        self.validate_relationship(
            &second_pipeline,
            &second_writer,
            &second_head,
            &dependency,
        )?;
        if pipeline != second_pipeline || writer != second_writer || head != second_head {
            return Err(RealmProcessorTerminalAuthorizationStoreError::ConcurrentMutation);
        }
        Ok(PersistedRealmProcessorTerminalAuthorization {
            envelope,
            dependency,
            pipeline: second_pipeline,
            writer: second_writer,
            head: second_head,
        })
    }

    pub(super) async fn revalidate_exact(
        &self,
        receipt: &PersistedRealmProcessorTerminalAuthorization<Hash>,
    ) -> Result<(), RealmProcessorTerminalAuthorizationStoreError> {
        self.dependency.revalidate_exact(&receipt.dependency).await?;
        if receipt.dependency.commitment() != receipt.envelope.external_dependency() {
            return Err(RealmProcessorTerminalAuthorizationStoreError::ConcurrentMutation);
        }
        let (pipeline, writer, head) = self.read_terminal_sources().await?;
        if pipeline != receipt.pipeline || writer != receipt.writer || head != receipt.head {
            return Err(RealmProcessorTerminalAuthorizationStoreError::ConcurrentMutation);
        }
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
        validate_branch_exact_queue_terminal_pair(pipeline, writer)?;
        let view = head.head();
        let observed = AuthorityObservation::try_new(
            *view.chain(),
            self.authority,
            view.state_checkpoint(),
            *view.state_root(),
        )
        .map_err(backend)?;
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
    Pending(BranchExactPendingOrchestrationError),
    Dependency(RealmProcessorExternalDependencyProjectionError),
    Envelope(RealmProcessorTerminalAuthorizationError),
    Backend(String),
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
    #[test]
    fn authorizer_is_storage_selected_and_cannot_persist_or_rotate() {
        let source = include_str!("realm_processor_terminal_authorization.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("read_terminal_sources"));
        assert!(production.contains("revalidate_exact"));
        assert!(production.contains("validate_branch_exact_queue_terminal_pair"));
        assert!(!production.contains("qualification_persist"));
        assert!(!production.contains("seal_rotation"));
        assert!(!production.contains("pipeline.apply"));
        assert!(!production.contains("publish_authority_head"));
    }
}
