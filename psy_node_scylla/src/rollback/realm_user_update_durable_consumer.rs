//! Direct, read-only Scylla consumer for one qualified Realm user generation.
//!
//! This component owns no NATS, Redis, proof-store or temp-DB handle. It
//! rebuilds projection inputs exclusively from the durable admission, claim,
//! dependency, ledger and publication rows.

use std::{marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use parth_core::{
    felt::QFelt64,
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use psy_data::protocol::{
    canonical_chain::NetworkId,
    chain_context::AuthorityScope,
};
use psy_node_core::{
    queue::{
        realm_user_update_admission::{
            RealmUserUpdateAdmissionCloseIntent, RealmUserUpdateAdmissionKey,
        },
        realm_user_update_claim::RealmUserUpdateClaimPhase,
        realm_user_update_consumer::{
            RealmUserUpdateDurableConsumerError,
            RealmUserUpdateDurableConsumerPort,
            RealmUserUpdateDurableGeneration, RealmUserUpdateDurableItem,
        },
        realm_user_update_dependency::RealmUserUpdateDependencyError,
        realm_user_update_publish::{
            GlobalUserTreeHeight, RealmUserUpdatePublishReceipt,
            RealmUserUpdatePublishRequest,
        },
    },
    store::{
        pending_generation_identity::PendingGenerationLedgerKey,
        pending_generation_pipeline::PendingPipelineReadState,
    },
};
use psy_node_nats::{
    recoverable_assignment::PendingQueueSegmentLedgerKey,
    recoverable_publish::{
        PendingQueuePublishIntentId, PendingQueuePublisherKind,
    },
    recoverable_segment::RecoverableNatsStreamSegment,
};
use scylla::client::session::Session;

use super::{
    BranchExactDeploymentNoTabletKeyspace, PendingQueueArtifactDataKeyspace,
    PendingQueuePublishDataKeyspace, PendingQueuePublishKeyspaces,
    PendingQueuePublishStoreError, PendingQueueSidecarReady,
    RealmUserUpdateAdmissionGuardError,
    RealmUserUpdateDependencyStoreError, ScyllaPendingPipelineStore,
    ScyllaPendingQueuePublishDurableReader,
    ScyllaPendingQueueSegmentLedgerStore,
    ScyllaRealmUserUpdateAdmissionGuard,
    ScyllaRealmUserUpdateAdmissionStore, ScyllaRealmUserUpdateClaimStore,
    ScyllaRealmUserUpdateDependencyStore,
};

pub(crate) struct ScyllaRealmUserUpdateDurableConsumer<F, Hash> {
    network: NetworkId,
    authority: AuthorityScope,
    global_user_tree_height: GlobalUserTreeHeight,
    admission: ScyllaRealmUserUpdateAdmissionGuard,
    dependencies: ScyllaRealmUserUpdateDependencyStore,
    pipeline: ScyllaPendingPipelineStore,
    ledger: ScyllaPendingQueueSegmentLedgerStore,
    ledger_key: PendingQueueSegmentLedgerKey,
    publication: ScyllaPendingQueuePublishDurableReader,
    segment: RecoverableNatsStreamSegment,
    _types: PhantomData<(F, Hash)>,
}

impl<F, Hash> ScyllaRealmUserUpdateDurableConsumer<F, Hash>
where
    F: QFelt64 + Send + Sync,
    Hash: Q256BitHash + QFHashBase<F> + Send + Sync,
{
    pub(crate) async fn prepare(
        session: Arc<Session>,
        network: NetworkId,
        authority: AuthorityScope,
        global_user_tree_height: GlobalUserTreeHeight,
        ready: Arc<PendingQueueSidecarReady>,
        segment: RecoverableNatsStreamSegment,
    ) -> Result<Self, RealmUserUpdateDurableConsumerError> {
        if !matches!(authority, AuthorityScope::Realm { .. })
            || ready.view().authority() != authority
        {
            return Err(RealmUserUpdateDurableConsumerError::ScopeMismatch);
        }
        let generation_key = PendingGenerationLedgerKey::new(network, authority);
        if segment.generation_key() != generation_key {
            return Err(RealmUserUpdateDurableConsumerError::ScopeMismatch);
        }
        let keyspaces = ready
            .view()
            .verified()
            .stored()
            .keyspaces()
            .clone();
        let control = BranchExactDeploymentNoTabletKeyspace::try_new(
            keyspaces.control().as_str().to_owned(),
        )
        .map_err(backend)?;
        let data = PendingQueueArtifactDataKeyspace::try_new(
            keyspaces.data().as_str().to_owned(),
        )
        .map_err(backend)?;
        let publish_keyspaces = PendingQueuePublishKeyspaces::new(
            control.clone(),
            PendingQueuePublishDataKeyspace::try_new(
                keyspaces.data().as_str().to_owned(),
            )
            .map_err(backend)?,
        );
        let claims = Arc::new(
            ScyllaRealmUserUpdateClaimStore::prepare(
                session.clone(),
                control.clone(),
            )
            .await
            .map_err(backend)?,
        );
        let gates = Arc::new(
            ScyllaRealmUserUpdateAdmissionStore::prepare(
                session.clone(),
                control.clone(),
            )
            .await
            .map_err(backend)?,
        );
        let admission = ScyllaRealmUserUpdateAdmissionGuard::new(gates, claims);
        let dependencies = ScyllaRealmUserUpdateDependencyStore::prepare(
            session.clone(),
            data,
        )
        .await
        .map_err(backend)?;
        let pipeline = ScyllaPendingPipelineStore::prepare(
            session.clone(),
            control.clone(),
        )
        .await
        .map_err(backend)?;
        let ledger = ScyllaPendingQueueSegmentLedgerStore::prepare(
            session.clone(),
            control,
        )
        .await
        .map_err(backend)?;
        let ledger_key = PendingQueueSegmentLedgerKey::try_new(
            generation_key,
            segment.base_namespace().to_owned(),
        )
        .map_err(backend)?;
        let publication = ScyllaPendingQueuePublishDurableReader::prepare(
            session,
            segment.clone(),
            publish_keyspaces,
        )
        .await
        .map_err(backend)?;
        Ok(Self {
            network,
            authority,
            global_user_tree_height,
            admission,
            dependencies,
            pipeline,
            ledger,
            ledger_key,
            publication,
            segment,
            _types: PhantomData,
        })
    }

    async fn read_exact(
        &self,
        key: RealmUserUpdateAdmissionKey,
        close: RealmUserUpdateAdmissionCloseIntent,
    ) -> Result<RealmUserUpdateDurableGeneration<F, Hash>, RealmUserUpdateDurableConsumerError>
    {
        if key.capture().key().network() != self.network
            || key.capture().key().authority() != self.authority
        {
            return Err(RealmUserUpdateDurableConsumerError::ScopeMismatch);
        }
        let sampled = self
            .admission
            .qualified_generation::<Hash>(key, close)
            .await
            .map_err(admission)?;
        let qualification = *sampled
            .header()
            .generation_qualification()
            .ok_or(RealmUserUpdateDurableConsumerError::GenerationNotQualified)?;
        let PendingPipelineReadState::Current(pipeline) = self
            .pipeline
            .read::<Hash>(key.capture().key())
            .await
            .map_err(backend)?
        else {
            return Err(RealmUserUpdateDurableConsumerError::PipelineFenceMismatch);
        };
        if !qualification.fence().matches_pipeline(key, &pipeline) {
            return Err(RealmUserUpdateDurableConsumerError::PipelineFenceMismatch);
        }

        let assignment = self
            .ledger
            .read_assignment_exact(&self.ledger_key, key.capture())
            .await
            .map_err(backend)?;
        if assignment.assignment().segment_id() != self.segment.segment_id()
            || assignment.assignment().contract_digest() != self.segment.digest()
        {
            return Err(RealmUserUpdateDurableConsumerError::ScopeMismatch);
        }
        let mut items = Vec::with_capacity(sampled.claims().len());
        for claim in sampled.claims() {
            match claim.phase() {
                RealmUserUpdateClaimPhase::Claimed => {
                    return Err(RealmUserUpdateDurableConsumerError::AwaitExactRequestReplay)
                }
                RealmUserUpdateClaimPhase::DependenciesPlanned => {
                    return Err(RealmUserUpdateDurableConsumerError::AwaitProofRecovery)
                }
                RealmUserUpdateClaimPhase::DependenciesReady => {
                    return Err(RealmUserUpdateDurableConsumerError::AwaitClaimPublication)
                }
                RealmUserUpdateClaimPhase::Published => {}
            }
            let dependency_digest = claim
                .dependency_digest()
                .ok_or(RealmUserUpdateDurableConsumerError::DurableDependencyLoss)?;
            let bundle = self
                .dependencies
                .read_bundle(
                    claim.slot(),
                    *claim.request_digest().as_bytes(),
                    claim.stable_status(),
                    claim.created_at().get(),
                    dependency_digest,
                )
                .await
                .map_err(dependency)?;
            let request = RealmUserUpdatePublishRequest::<F, Hash>::try_from_persisted_dependencies(
                claim,
                &bundle,
                self.global_user_tree_height,
            )
            .map_err(|error| {
                RealmUserUpdateDurableConsumerError::DependencyCorruption(
                    error.to_string(),
                )
            })?;
            let intent_id = PendingQueuePublishIntentId::try_new(
                *request.intent_id().as_bytes(),
            )
            .map_err(backend)?;
            let committed = self
                .publication
                .observe_committed_data(
                    &assignment,
                    PendingQueuePublisherKind::RealmUserUpdate,
                    intent_id,
                    request.payload(),
                )
                .await
                .map_err(publication)?
                .ok_or(RealmUserUpdateDurableConsumerError::TerminalSourceMissing)?;
            let receipt = RealmUserUpdatePublishReceipt::durable(
                request.intent_id(),
                *assignment.assignment().digest().as_bytes(),
                committed.subject_sequence(),
                *committed.envelope_digest(),
                true,
            )
            .map_err(|_| {
                RealmUserUpdateDurableConsumerError::TerminalEvidenceMismatch
            })?;
            items.push(RealmUserUpdateDurableItem::try_from_observed(
                key,
                qualification.fence(),
                claim.clone(),
                bundle,
                self.global_user_tree_height,
                receipt,
            )?);
        }

        // The long dependency/source scan cannot return a mixed generation.
        // Re-scan all bucket partitions, not just the known point rows, so a
        // concurrent extra claim cannot hide behind the old qualification.
        let fresh = self
            .admission
            .qualified_generation::<Hash>(key, close)
            .await
            .map_err(admission)?;
        if fresh.header() != sampled.header() || fresh.claims() != sampled.claims() {
            return Err(RealmUserUpdateDurableConsumerError::ConcurrentChange);
        }
        let PendingPipelineReadState::Current(fresh_pipeline) = self
            .pipeline
            .read::<Hash>(key.capture().key())
            .await
            .map_err(backend)?
        else {
            return Err(RealmUserUpdateDurableConsumerError::PipelineFenceMismatch);
        };
        if !qualification.fence().matches_pipeline(key, &fresh_pipeline) {
            return Err(RealmUserUpdateDurableConsumerError::PipelineFenceMismatch);
        }
        RealmUserUpdateDurableGeneration::try_new(
            key,
            close,
            qualification,
            items,
        )
    }
}

#[async_trait]
impl<F, Hash> RealmUserUpdateDurableConsumerPort<F, Hash>
    for ScyllaRealmUserUpdateDurableConsumer<F, Hash>
where
    F: QFelt64 + Send + Sync,
    Hash: Q256BitHash + QFHashBase<F> + Send + Sync,
{
    async fn read_qualified_generation(
        &self,
        key: RealmUserUpdateAdmissionKey,
        close: RealmUserUpdateAdmissionCloseIntent,
    ) -> Result<RealmUserUpdateDurableGeneration<F, Hash>, RealmUserUpdateDurableConsumerError>
    {
        self.read_exact(key, close).await
    }
}

fn admission(
    error: RealmUserUpdateAdmissionGuardError,
) -> RealmUserUpdateDurableConsumerError {
    match error {
        RealmUserUpdateAdmissionGuardError::GenerationUninitialized => {
            RealmUserUpdateDurableConsumerError::GenerationUninitialized
        }
        RealmUserUpdateAdmissionGuardError::MembershipMismatch => {
            RealmUserUpdateDurableConsumerError::MembershipMismatch
        }
        RealmUserUpdateAdmissionGuardError::AdmissionRace => {
            RealmUserUpdateDurableConsumerError::ConcurrentChange
        }
        RealmUserUpdateAdmissionGuardError::GenerationConflict => {
            RealmUserUpdateDurableConsumerError::GenerationNotQualified
        }
        other => RealmUserUpdateDurableConsumerError::BackendUnavailable(
            other.to_string(),
        ),
    }
}

fn dependency(
    error: RealmUserUpdateDependencyStoreError,
) -> RealmUserUpdateDurableConsumerError {
    match error {
        RealmUserUpdateDependencyStoreError::Dependency(
            RealmUserUpdateDependencyError::MissingFragment
            | RealmUserUpdateDependencyError::EmptyComponent(_),
        ) => RealmUserUpdateDurableConsumerError::DurableDependencyLoss,
        RealmUserUpdateDependencyStoreError::Cql(error)
        | RealmUserUpdateDependencyStoreError::IndeterminateWrite(error) => {
            RealmUserUpdateDurableConsumerError::DependencyUnavailable(error)
        }
        other => RealmUserUpdateDurableConsumerError::DependencyCorruption(
            other.to_string(),
        ),
    }
}

fn publication(
    error: PendingQueuePublishStoreError,
) -> RealmUserUpdateDurableConsumerError {
    match error {
        PendingQueuePublishStoreError::SourceUninitialized
        | PendingQueuePublishStoreError::IntentUninitialized
        | PendingQueuePublishStoreError::FragmentMissing => {
            RealmUserUpdateDurableConsumerError::TerminalSourceMissing
        }
        PendingQueuePublishStoreError::Cql(error)
        | PendingQueuePublishStoreError::Indeterminate(error)
        | PendingQueuePublishStoreError::IndeterminateFragment(error) => {
            RealmUserUpdateDurableConsumerError::BackendUnavailable(error)
        }
        _other => RealmUserUpdateDurableConsumerError::TerminalEvidenceMismatch,
    }
}

fn backend(error: impl std::fmt::Display) -> RealmUserUpdateDurableConsumerError {
    RealmUserUpdateDurableConsumerError::BackendUnavailable(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_has_no_projection_or_transport_authority() {
        let source = include_str!("realm_user_update_durable_consumer.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(!source.contains("RecoverablePendingQueueNatsPublisher"));
        assert!(!source.contains("redis"));
        assert!(!source.contains("temp_db"));
        assert!(!source.contains("proof_store"));
        assert!(!source.contains("publish_and_commit"));
        assert!(!source.contains("observe_authorized"));
    }

    #[test]
    fn missing_and_corrupt_dependencies_are_not_collapsed() {
        assert_eq!(
            dependency(RealmUserUpdateDependencyStoreError::Dependency(
                RealmUserUpdateDependencyError::MissingFragment,
            )),
            RealmUserUpdateDurableConsumerError::DurableDependencyLoss,
        );
        assert!(matches!(
            dependency(RealmUserUpdateDependencyStoreError::Dependency(
                RealmUserUpdateDependencyError::DigestMismatch,
            )),
            RealmUserUpdateDurableConsumerError::DependencyCorruption(_),
        ));
    }
}
