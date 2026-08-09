//! Read-only Scylla composition for Realm Processor startup preflight.
//!
//! Every enabled request performs two complete composite samples. A route-only
//! bracket is insufficient because writer, timestamp, head, shadow, or pending
//! rows can change without a cutover CAS. This module never creates, bootstraps,
//! repairs, or updates a row and is not wired into production setup yet.

use std::{marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::NetworkId,
    chain_context::AuthorityScope,
};
use psy_node_core::store::{
    authority_commit::{
        AuthorityTimestampKey, AuthorityTimestampPhase,
        ObservedAuthorityTimestampState,
    },
    authority_local_head::{
        AuthorityLocalHeadReadState, StoredAuthorityLocalHead,
    },
    pending_generation_identity::PendingGenerationLedgerKey,
    pending_generation_pipeline::{
        PendingPipelineReadState, StoredPendingPipeline,
    },
    realm_processor_startup::{
        RealmProcessorStartupError, RealmProcessorStartupEvidence,
        RealmProcessorStartupExpectation,
        RealmProcessorStartupPreflightProvider,
        RealmProcessorStartupRouteObservation,
        RealmProcessorStartupRoutePhase,
    },
};
use scylla::client::session::Session;
use sha2::{Digest, Sha256};

use super::{
    AuthorityLocalHeadNoTabletKeyspace, AuthorityTimestampNoTabletKeyspace,
    BranchExactCutoverAuthorityKey, BranchExactCutoverPhase,
    BranchExactCutoverReadState, BranchExactDeploymentNoTabletKeyspace,
    BranchExactSchemaReadyView, BranchExactSchemaSetupRequest,
    BranchExactShadowAuditReadState, BranchExactShadowAuditState,
    BranchExactWriterAuthorityKey, BranchExactWriterReadState,
    BranchExactWriterState, ScyllaAuthorityLocalHeadStore,
    ScyllaAuthorityTimestampStore, ScyllaBranchExactCutoverStore,
    ScyllaBranchExactSchemaSetupGate, ScyllaBranchExactShadowAuditStore,
    ScyllaBranchExactWriterLifecycleStore, ScyllaPendingPipelineStore,
    StoredBranchExactCutover, StoredBranchExactShadowAudit,
    StoredBranchExactWriterLifecycle,
};
use super::branch_exact_pending_orchestration::{
    classify_branch_exact_pending_startup, BranchExactPendingStartupRecovery,
    BranchExactPreparedWriterRecovery,
};

const READINESS_DOMAIN: &[u8] =
    b"psy/rollback/realm-startup-scylla-readiness/v1";
const WATERMARK_DOMAIN: &[u8] =
    b"psy/rollback/realm-startup-cutover-watermark/v1";
const RECOVERY_ADMISSION_DOMAIN: &[u8] =
    b"psy/rollback/realm-startup-recovery-admission/v1";
const COMPOSITE_PARTS: usize = 7;

/// Private schema reader. The provider does not expose or return the raw
/// session used for live h20 authorization.
struct ScyllaStartupSchemaReader {
    session: Arc<Session>,
    standard_keyspace: String,
    no_tablet_keyspace: String,
    authority: AuthorityScope,
}

impl ScyllaStartupSchemaReader {
    async fn fresh<Hash: Q256BitHash>(
        &self,
        writer: &StoredBranchExactWriterLifecycle<Hash>,
    ) -> Result<BranchExactSchemaReadyView, RealmProcessorStartupError> {
        let request = BranchExactSchemaSetupRequest::new(
            writer.plan().backfill_receipt().clone(),
        );
        ScyllaBranchExactSchemaSetupGate::authorize(
            self.session.clone(),
            &self.standard_keyspace,
            &self.no_tablet_keyspace,
            self.authority,
            &request,
        )
        .await
        .map(|ready| ready.view().clone())
        .map_err(|error| not_verified("schema/backfill", error))
    }
}

/// Complete read-only provider. Construction only prepares statements; all
/// readiness decisions are based on fresh reads made by `fresh_read`.
pub(crate) struct ScyllaRealmProcessorStartupPreflightProvider<Hash> {
    network: NetworkId,
    authority: AuthorityScope,
    route_key: BranchExactCutoverAuthorityKey,
    writer_key: BranchExactWriterAuthorityKey,
    authority_key: AuthorityTimestampKey,
    pending_key: PendingGenerationLedgerKey,
    route: ScyllaBranchExactCutoverStore,
    writer: ScyllaBranchExactWriterLifecycleStore,
    shadow: ScyllaBranchExactShadowAuditStore,
    timestamp: ScyllaAuthorityTimestampStore,
    head: ScyllaAuthorityLocalHeadStore,
    pending: ScyllaPendingPipelineStore,
    schema: ScyllaStartupSchemaReader,
    setup_ready: BranchExactSchemaReadyView,
    _hash: PhantomData<Hash>,
}

impl<Hash: Q256BitHash> ScyllaRealmProcessorStartupPreflightProvider<Hash> {
    /// Prepare-only factory. No schema or data mutation is executed here.
    pub(crate) async fn prepare(
        session: Arc<Session>,
        standard_keyspace: &str,
        no_tablet_keyspace: &str,
        network: NetworkId,
        authority: AuthorityScope,
        setup_ready: BranchExactSchemaReadyView,
    ) -> Result<Self, RealmProcessorStartupError> {
        let AuthorityScope::Realm { .. } = authority else {
            return Err(RealmProcessorStartupError::AuthorityMismatch);
        };
        if setup_ready.authority() != authority {
            return Err(RealmProcessorStartupError::AuthorityMismatch);
        }
        let control_keyspace = BranchExactDeploymentNoTabletKeyspace::try_new(
            no_tablet_keyspace.to_owned(),
        )
        .map_err(|error| storage("control keyspace", error))?;
        let timestamp_keyspace = AuthorityTimestampNoTabletKeyspace::try_new(
            no_tablet_keyspace.to_owned(),
        )
        .map_err(|error| storage("timestamp keyspace", error))?;
        let head_keyspace = AuthorityLocalHeadNoTabletKeyspace::try_new(
            no_tablet_keyspace.to_owned(),
        )
        .map_err(|error| storage("head keyspace", error))?;
        let route_key = BranchExactCutoverAuthorityKey::try_new(network, authority)
            .map_err(|error| storage("route key", error))?;
        let writer_key = BranchExactWriterAuthorityKey::new(network, authority);
        let authority_key = AuthorityTimestampKey::new(network, authority);
        let pending_key = PendingGenerationLedgerKey::new(network, authority);

        let route = ScyllaBranchExactCutoverStore::prepare(
            session.clone(),
            control_keyspace.clone(),
        )
        .await
        .map_err(|error| storage("route prepare", error))?;
        let writer = ScyllaBranchExactWriterLifecycleStore::prepare(
            session.clone(),
            control_keyspace.clone(),
        )
        .await
        .map_err(|error| storage("writer prepare", error))?;
        let shadow = ScyllaBranchExactShadowAuditStore::prepare(
            session.clone(),
            control_keyspace.clone(),
        )
        .await
        .map_err(|error| storage("shadow prepare", error))?;
        let pending = ScyllaPendingPipelineStore::prepare(
            session.clone(),
            control_keyspace,
        )
        .await
        .map_err(|error| storage("pending prepare", error))?;
        let timestamp = ScyllaAuthorityTimestampStore::prepare(
            session.clone(),
            timestamp_keyspace,
        )
        .await
        .map_err(|error| storage("timestamp prepare", error))?;
        let head = ScyllaAuthorityLocalHeadStore::prepare(
            session.clone(),
            head_keyspace,
        )
        .await
        .map_err(|error| storage("head prepare", error))?;

        Ok(Self {
            network,
            authority,
            route_key,
            writer_key,
            authority_key,
            pending_key,
            route,
            writer,
            shadow,
            timestamp,
            head,
            pending,
            schema: ScyllaStartupSchemaReader {
                session,
                standard_keyspace: standard_keyspace.to_owned(),
                no_tablet_keyspace: no_tablet_keyspace.to_owned(),
                authority,
            },
            setup_ready,
            _hash: PhantomData,
        })
    }

    async fn read_composite(
        &self,
    ) -> Result<ScyllaStartupComposite<Hash>, RealmProcessorStartupError> {
        let route = match self
            .route
            .read::<Hash>(self.route_key)
            .await
            .map_err(|error| storage("route read", error))?
        {
            BranchExactCutoverReadState::Current(current) => current,
            BranchExactCutoverReadState::Uninitialized => {
                return Err(not_verified_message("route row is uninitialized"))
            }
        };
        let writer = match self
            .writer
            .read::<Hash>(self.writer_key)
            .await
            .map_err(|error| storage("writer read", error))?
        {
            BranchExactWriterReadState::Current(current) => current,
            BranchExactWriterReadState::Uninitialized => {
                return Err(not_verified_message("writer row is uninitialized"))
            }
        };
        let schema = self.schema.fresh(&writer).await?;
        let shadow = match self
            .shadow
            .read(writer.plan().shadow_audit_slot())
            .await
            .map_err(|error| storage("shadow read", error))?
        {
            BranchExactShadowAuditReadState::Current(current) => current,
            BranchExactShadowAuditReadState::Uninitialized => {
                return Err(not_verified_message("shadow row is uninitialized"))
            }
        };
        let timestamp = self
            .timestamp
            .read_observed(self.authority_key)
            .await
            .map_err(|error| storage("timestamp read", error))?
            .ok_or_else(|| not_verified_message("timestamp row is uninitialized"))?;
        let head = match self
            .head
            .read::<Hash>(self.authority_key)
            .await
            .map_err(|error| storage("authority head read", error))?
        {
            AuthorityLocalHeadReadState::Current(current) => current,
            AuthorityLocalHeadReadState::Uninitialized => {
                return Err(not_verified_message("authority head is uninitialized"))
            }
        };
        let pending = match self
            .pending
            .read::<Hash>(self.pending_key)
            .await
            .map_err(|error| storage("pending pipeline read", error))?
        {
            PendingPipelineReadState::Current(current) => current,
            PendingPipelineReadState::Uninitialized => {
                return Err(not_verified_message("pending pipeline is uninitialized"))
            }
        };
        Ok(ScyllaStartupComposite {
            route,
            schema,
            writer,
            shadow,
            timestamp,
            head,
            pending,
        })
    }

    fn validate_composite(
        &self,
        expectation: RealmProcessorStartupExpectation,
        sample: &ScyllaStartupComposite<Hash>,
    ) -> Result<ValidatedScyllaStartup, RealmProcessorStartupError> {
        if expectation.network() != self.network {
            return Err(RealmProcessorStartupError::AuthorityMismatch);
        }
        let AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } = self.authority
        else {
            return Err(RealmProcessorStartupError::AuthorityMismatch);
        };
        if expectation.realm_id() != realm_id
            || expectation.realm_sub_id() != realm_sub_id
        {
            return Err(RealmProcessorStartupError::AuthorityMismatch);
        }

        let binding = sample.route.binding();
        if binding.network() != self.network || binding.authority() != self.authority {
            return Err(RealmProcessorStartupError::AuthorityMismatch);
        }
        if binding.generation().get() != expectation.expected_generation()
            || binding.digest().as_bytes()
                != expectation.expected_binding_digest().as_bytes()
        {
            return Err(RealmProcessorStartupError::RouteMismatch);
        }
        let phase = route_phase(sample.route.phase())?;
        let plan = sample.writer.plan();
        if plan.authority() != self.authority
            || plan.baseline().canonical_chain().network_id() != self.network
        {
            return Err(RealmProcessorStartupError::AuthorityMismatch);
        }
        if plan.digest().as_bytes()
            != expectation.expected_writer_activation_digest().as_bytes()
            || binding.writer_activation_digest_bytes() != plan.digest().as_bytes()
        {
            return Err(RealmProcessorStartupError::WriterActivationMismatch);
        }
        if binding.schema_digest_bytes() != sample.schema.digest().as_bytes()
            || sample.schema != self.setup_ready
            || sample.schema.digest() != plan.schema_ready_digest()
            || binding.backfill_digest_bytes()
                != plan.backfill_receipt().digest().as_bytes()
        {
            return Err(not_verified_message(
                "route/schema/backfill evidence does not close",
            ));
        }
        let BranchExactShadowAuditState::Consumed(consumed) = sample.shadow.state()
        else {
            return Err(not_verified_message("shadow audit is not Consumed"));
        };
        if consumed.writer_activation_digest() != plan.digest()
            || consumed.verified().digest() != plan.shadow_verified_digest()
            || consumed.verified().plan().slot() != plan.shadow_audit_slot()
            || binding.shadow_consumed_digest_bytes() != consumed.digest().as_bytes()
        {
            return Err(not_verified_message(
                "route/shadow/writer evidence does not close",
            ));
        }
        if sample.pending.activation_digest().as_bytes() != plan.digest().as_bytes()
            || sample.pending.blocked_reason().is_some()
        {
            return Err(not_verified_message(
                "pending pipeline activation is not ready",
            ));
        }

        let recovery = classify_branch_exact_pending_startup(
            &sample.pending,
            &sample.writer,
            sample.timestamp,
        )
        .map_err(|error| not_verified("pending/writer/timestamp", error))?;
        let recovery_tag = require_clean_run_boundary(&recovery)?;
        let BranchExactWriterState::Active(active) = sample.writer.state() else {
            return Err(RealmProcessorStartupError::DurableRecoveryRequired(
                "writer/pending crash recovery must complete before Realm startup"
                    .to_owned(),
            ));
        };
        if !matches!(sample.timestamp.state().phase(), AuthorityTimestampPhase::Idle { .. })
            || sample.timestamp.state() != active.timestamp_state()
        {
            return Err(not_verified_message(
                "active writer and timestamp allocator disagree",
            ));
        }
        if sample.head.head().key().network() != self.network
            || sample.head.head().key().authority() != self.authority
            || sample.head.head().chain() != active.watermark().canonical_chain()
        {
            return Err(not_verified_message(
                "authority head and active writer watermark disagree",
            ));
        }
        require_not_behind_cutover(binding.watermark(), active.watermark())?;

        let route = RealmProcessorStartupRouteObservation::try_new(
            binding.generation().get(),
            sample.route.revision().get(),
            *binding.digest().as_bytes(),
            *sample.route.state_digest().as_bytes(),
            phase,
        )?;
        let watermark_digest = cutover_watermark_digest(binding.watermark());
        let fingerprint = sample.fingerprint();
        let readiness_digest = readiness_digest(&fingerprint, recovery_tag);
        Ok(ValidatedScyllaStartup {
            route,
            writer_activation_digest: *plan.digest().as_bytes(),
            watermark_digest,
            readiness_digest,
        })
    }
}

#[async_trait]
impl<Hash> RealmProcessorStartupPreflightProvider
    for ScyllaRealmProcessorStartupPreflightProvider<Hash>
where
    Hash: Q256BitHash + Send + Sync + 'static,
{
    async fn fresh_read(
        &self,
        expectation: RealmProcessorStartupExpectation,
    ) -> Result<RealmProcessorStartupEvidence, RealmProcessorStartupError> {
        let before = self.read_composite().await?;
        let after = self.read_composite().await?;
        let before_fingerprint = before.fingerprint();
        let after_fingerprint = after.fingerprint();
        if before_fingerprint != after_fingerprint {
            return Err(RealmProcessorStartupError::ConcurrentMutation);
        }
        let validated_before = self.validate_composite(expectation, &before)?;
        let validated_after = self.validate_composite(expectation, &after)?;
        if validated_before != validated_after {
            return Err(RealmProcessorStartupError::ConcurrentMutation);
        }
        RealmProcessorStartupEvidence::try_new(
            self.network,
            expectation.realm_id(),
            expectation.realm_sub_id(),
            validated_before.route,
            validated_after.route,
            validated_after.writer_activation_digest,
            validated_after.watermark_digest,
            validated_after.readiness_digest,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ScyllaStartupComposite<Hash> {
    route: StoredBranchExactCutover<Hash>,
    schema: BranchExactSchemaReadyView,
    writer: StoredBranchExactWriterLifecycle<Hash>,
    shadow: StoredBranchExactShadowAudit,
    timestamp: ObservedAuthorityTimestampState,
    head: StoredAuthorityLocalHead<Hash>,
    pending: StoredPendingPipeline<Hash>,
}

impl<Hash: Q256BitHash> ScyllaStartupComposite<Hash> {
    fn fingerprint(&self) -> ScyllaStartupCompositeFingerprint {
        let mut route = self.route.revision().get().to_be_bytes().to_vec();
        route.extend_from_slice(&self.route.to_canonical_bytes());

        let mut schema = self.schema.lifecycle_revision().get().to_be_bytes().to_vec();
        schema.extend_from_slice(self.schema.digest().as_bytes());

        let mut writer = self.writer.revision().get().to_be_bytes().to_vec();
        writer.extend_from_slice(&self.writer.to_canonical_bytes());

        let mut shadow = self.shadow.revision().to_be_bytes().to_vec();
        shadow.extend_from_slice(&self.shadow.encode_state());

        let mut timestamp = authority_key_bytes(self.timestamp.key());
        timestamp.extend_from_slice(
            &self.timestamp.state().revision().get().to_be_bytes(),
        );
        timestamp.extend_from_slice(&self.timestamp.state().encode_canonical());

        let mut head = self.head.revision().get().to_be_bytes().to_vec();
        head.extend_from_slice(&self.head.encode_canonical());

        let mut pending = self.pending.revision().get().to_be_bytes().to_vec();
        pending.extend_from_slice(&self.pending.canonical_payload());

        ScyllaStartupCompositeFingerprint::try_new(vec![
            route, schema, writer, shadow, timestamp, head, pending,
        ])
        .expect("all canonical durable rows are non-empty")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ScyllaStartupCompositeFingerprint {
    parts: Vec<Vec<u8>>,
}

impl ScyllaStartupCompositeFingerprint {
    fn try_new(parts: Vec<Vec<u8>>) -> Result<Self, RealmProcessorStartupError> {
        if parts.len() != COMPOSITE_PARTS || parts.iter().any(Vec::is_empty) {
            return Err(RealmProcessorStartupError::DurableStorageIndeterminate(
                "startup composite fingerprint is incomplete".to_owned(),
            ));
        }
        Ok(Self { parts })
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.parts.len() as u64).to_be_bytes());
        for part in &self.parts {
            out.extend_from_slice(&(part.len() as u64).to_be_bytes());
            out.extend_from_slice(part);
        }
        out
    }

    fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum ScyllaStartupRecoveryActionKind {
    ApplyPendingTransition = 1,
    ResumeWriterVerification = 2,
    FinishWriterAfterTrustedMarker = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScyllaStartupAwaitExternalReason {
    PrimeOrRotate,
    ResumeQueueSeal,
    RecoverCapturedWork,
    PublishTrustedMarker,
    PublishNoWork,
    RotateTerminal,
}

enum ScyllaStartupRecoveryAction<Hash> {
    ApplyPendingTransition(
        psy_node_core::store::pending_generation_pipeline::SealedPendingPipelineTransition<Hash>,
    ),
    ResumeWriterVerification(BranchExactPreparedWriterRecovery),
    FinishWriterAfterTrustedMarker,
}

/// One full-composite-bound action. It is intentionally non-Clone and has no
/// public constructor or codec. h23c3c must fresh-read the seven-component
/// fingerprint before consuming it and execute exactly this one action.
struct SealedScyllaStartupRecoveryAdmission<Hash> {
    source_fingerprint: [u8; 32],
    action_digest: [u8; 32],
    action: ScyllaStartupRecoveryAction<Hash>,
}

impl<Hash> SealedScyllaStartupRecoveryAdmission<Hash> {
    fn source_fingerprint(&self) -> &[u8; 32] {
        &self.source_fingerprint
    }

    fn action_digest(&self) -> &[u8; 32] {
        &self.action_digest
    }

    fn matches_source(&self, current: &ScyllaStartupCompositeFingerprint) -> bool {
        self.source_fingerprint == current.digest()
    }
}

enum ScyllaStartupRecoveryDecision<Hash> {
    Clean,
    Recover(SealedScyllaStartupRecoveryAdmission<Hash>),
    AwaitExternal(ScyllaStartupAwaitExternalReason),
}

fn seal_recovery_decision<Hash>(
    source: &ScyllaStartupCompositeFingerprint,
    recovery: BranchExactPendingStartupRecovery<Hash>,
) -> ScyllaStartupRecoveryDecision<Hash> {
    let source_fingerprint = source.digest();
    let action = match recovery {
        BranchExactPendingStartupRecovery::ReadyForQueueClose => {
            return ScyllaStartupRecoveryDecision::Clean
        }
        BranchExactPendingStartupRecovery::ApplyPipeline { pipeline, .. } => {
            ScyllaStartupRecoveryAction::ApplyPendingTransition(pipeline)
        }
        BranchExactPendingStartupRecovery::ResumeWriterVerification(recovery) => {
            ScyllaStartupRecoveryAction::ResumeWriterVerification(recovery)
        }
        BranchExactPendingStartupRecovery::FinishWriterAfterTrustedMarker => {
            ScyllaStartupRecoveryAction::FinishWriterAfterTrustedMarker
        }
        BranchExactPendingStartupRecovery::AwaitPrimeOrRotate => {
            return ScyllaStartupRecoveryDecision::AwaitExternal(
                ScyllaStartupAwaitExternalReason::PrimeOrRotate,
            )
        }
        BranchExactPendingStartupRecovery::ResumeQueueSeal(_) => {
            return ScyllaStartupRecoveryDecision::AwaitExternal(
                ScyllaStartupAwaitExternalReason::ResumeQueueSeal,
            )
        }
        BranchExactPendingStartupRecovery::AwaitRecoverableWork(_) => {
            return ScyllaStartupRecoveryDecision::AwaitExternal(
                ScyllaStartupAwaitExternalReason::RecoverCapturedWork,
            )
        }
        BranchExactPendingStartupRecovery::AwaitTrustedMarker => {
            return ScyllaStartupRecoveryDecision::AwaitExternal(
                ScyllaStartupAwaitExternalReason::PublishTrustedMarker,
            )
        }
        BranchExactPendingStartupRecovery::ResumeNoWorkPublication(_) => {
            return ScyllaStartupRecoveryDecision::AwaitExternal(
                ScyllaStartupAwaitExternalReason::PublishNoWork,
            )
        }
        BranchExactPendingStartupRecovery::CompleteNoWorkAfterTrustedMarker
        | BranchExactPendingStartupRecovery::CompleteAfterTrustedMarker => {
            return ScyllaStartupRecoveryDecision::AwaitExternal(
                ScyllaStartupAwaitExternalReason::RotateTerminal,
            )
        }
    };
    let action_kind = match &action {
        ScyllaStartupRecoveryAction::ApplyPendingTransition(_) => {
            ScyllaStartupRecoveryActionKind::ApplyPendingTransition
        }
        ScyllaStartupRecoveryAction::ResumeWriterVerification(_) => {
            ScyllaStartupRecoveryActionKind::ResumeWriterVerification
        }
        ScyllaStartupRecoveryAction::FinishWriterAfterTrustedMarker => {
            ScyllaStartupRecoveryActionKind::FinishWriterAfterTrustedMarker
        }
    };
    let mut hasher = Sha256::new();
    hasher.update(RECOVERY_ADMISSION_DOMAIN);
    hasher.update(source_fingerprint);
    hasher.update([action_kind as u8]);
    let action_digest = hasher.finalize().into();
    ScyllaStartupRecoveryDecision::Recover(
        SealedScyllaStartupRecoveryAdmission {
            source_fingerprint,
            action_digest,
            action,
        },
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ValidatedScyllaStartup {
    route: RealmProcessorStartupRouteObservation,
    writer_activation_digest: [u8; 32],
    watermark_digest: [u8; 32],
    readiness_digest: [u8; 32],
}

fn route_phase(
    phase: BranchExactCutoverPhase,
) -> Result<RealmProcessorStartupRoutePhase, RealmProcessorStartupError> {
    match phase {
        BranchExactCutoverPhase::LegacyPrimaryDualWrite => {
            Ok(RealmProcessorStartupRoutePhase::LegacyPrimaryDualWrite)
        }
        BranchExactCutoverPhase::TargetPrimaryDualWrite => {
            Ok(RealmProcessorStartupRoutePhase::TargetPrimaryDualWrite)
        }
        BranchExactCutoverPhase::QuiescingToTarget => {
            Err(RealmProcessorStartupError::RouteQuiescing)
        }
        BranchExactCutoverPhase::QuiescingToLegacy => {
            Err(RealmProcessorStartupError::RouteQuiescing)
        }
    }
}

/// A durable state may be internally consistent without being safe for a new
/// Processor/gatherer. Only the clean Ready boundary authorizes a run; every
/// crash-intermediate or terminal-but-unrotated state belongs to the isolated
/// recovery runner.
fn require_clean_run_boundary<Hash>(
    recovery: &BranchExactPendingStartupRecovery<Hash>,
) -> Result<u8, RealmProcessorStartupError> {
    match recovery {
        BranchExactPendingStartupRecovery::ReadyForQueueClose => Ok(2),
        BranchExactPendingStartupRecovery::AwaitPrimeOrRotate
        | BranchExactPendingStartupRecovery::ResumeQueueSeal(_)
        | BranchExactPendingStartupRecovery::AwaitRecoverableWork(_)
        | BranchExactPendingStartupRecovery::ApplyPipeline { .. }
        | BranchExactPendingStartupRecovery::ResumeWriterVerification(_)
        | BranchExactPendingStartupRecovery::AwaitTrustedMarker
        | BranchExactPendingStartupRecovery::ResumeNoWorkPublication(_)
        | BranchExactPendingStartupRecovery::CompleteNoWorkAfterTrustedMarker
        | BranchExactPendingStartupRecovery::FinishWriterAfterTrustedMarker
        | BranchExactPendingStartupRecovery::CompleteAfterTrustedMarker => {
            Err(RealmProcessorStartupError::DurableRecoveryRequired(
                "pending pipeline is not at the clean Ready run boundary"
                    .to_owned(),
            ))
        }
    }
}

fn require_not_behind_cutover<Hash: Q256BitHash>(
    baseline: &psy_node_core::store::branch_pending_mapping::BranchPendingMapping<Hash>,
    current: &psy_node_core::store::branch_pending_mapping::BranchPendingMapping<Hash>,
) -> Result<(), RealmProcessorStartupError> {
    let baseline_chain = baseline.canonical_chain();
    let current_chain = current.canonical_chain();
    let baseline_height = baseline_chain.checkpoint().checkpoint_id().get();
    let current_height = current_chain.checkpoint().checkpoint_id().get();
    if baseline_chain.network_id() != current_chain.network_id()
        || baseline_chain.chain_epoch() != current_chain.chain_epoch()
        || baseline_height > current_height
        || baseline.pending_id() > current.pending_id()
        || (baseline_height == current_height && baseline_chain != current_chain)
        || (baseline.pending_id() == current.pending_id() && baseline_chain != current_chain)
    {
        return Err(RealmProcessorStartupError::DurableEvidenceNotVerified(
            "live writer watermark is not a descendant of cutover baseline"
                .to_owned(),
        ));
    }
    Ok(())
}

fn authority_key_bytes(key: AuthorityTimestampKey) -> Vec<u8> {
    let mut bytes = key.network().chain_id().to_be_bytes().to_vec();
    match key.authority() {
        AuthorityScope::Coordinator => bytes.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0]),
        AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } => {
            bytes.push(2);
            bytes.extend_from_slice(&realm_id.to_be_bytes());
            bytes.extend_from_slice(&realm_sub_id.to_be_bytes());
        }
    }
    bytes
}

fn cutover_watermark_digest<Hash: Q256BitHash>(
    watermark: &psy_node_core::store::branch_pending_mapping::BranchPendingMapping<Hash>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(WATERMARK_DOMAIN);
    hasher.update(watermark.canonical_chain_bytes());
    hasher.update(watermark.pending_id().get().to_be_bytes());
    hasher.finalize().into()
}

fn readiness_digest(
    fingerprint: &ScyllaStartupCompositeFingerprint,
    recovery_tag: u8,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(READINESS_DOMAIN);
    hasher.update(fingerprint.canonical_bytes());
    hasher.update([recovery_tag]);
    hasher.finalize().into()
}

fn not_verified(
    component: &'static str,
    error: impl std::fmt::Display,
) -> RealmProcessorStartupError {
    RealmProcessorStartupError::DurableEvidenceNotVerified(format!(
        "{component}: {error}"
    ))
}

fn not_verified_message(message: &'static str) -> RealmProcessorStartupError {
    RealmProcessorStartupError::DurableEvidenceNotVerified(message.to_owned())
}

fn storage(
    component: &'static str,
    error: impl std::fmt::Display,
) -> RealmProcessorStartupError {
    RealmProcessorStartupError::DurableStorageIndeterminate(format!(
        "{component}: {error}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fingerprint() -> ScyllaStartupCompositeFingerprint {
        ScyllaStartupCompositeFingerprint::try_new(
            (1..=COMPOSITE_PARTS)
                .map(|value| vec![value as u8; value])
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn complete_fingerprint_is_deterministic_and_length_delimited() {
        let first = fingerprint();
        let second = fingerprint();
        assert_eq!(first, second);
        assert_eq!(first.canonical_bytes(), second.canonical_bytes());
        assert_eq!(
            readiness_digest(&first, 2),
            readiness_digest(&second, 2)
        );
        assert_ne!(
            readiness_digest(&first, 2),
            readiness_digest(&second, 3)
        );
    }

    #[test]
    fn every_composite_part_participates_in_stability_and_digest() {
        let baseline = fingerprint();
        for index in 0..COMPOSITE_PARTS {
            let mut changed = baseline.clone();
            changed.parts[index].push(0xff);
            assert_ne!(baseline, changed, "part {index} must be stable");
            assert_ne!(
                readiness_digest(&baseline, 1),
                readiness_digest(&changed, 1),
                "part {index} must be committed"
            );
        }
    }

    #[test]
    fn incomplete_composite_fails_closed() {
        assert!(matches!(
            ScyllaStartupCompositeFingerprint::try_new(vec![vec![1]]),
            Err(RealmProcessorStartupError::DurableStorageIndeterminate(_))
        ));
        let mut parts = vec![vec![1]; COMPOSITE_PARTS];
        parts[4].clear();
        assert!(matches!(
            ScyllaStartupCompositeFingerprint::try_new(parts),
            Err(RealmProcessorStartupError::DurableStorageIndeterminate(_))
        ));
    }

    #[test]
    fn recovery_decision_is_exhaustive_and_bound_to_the_full_composite() {
        let source = fingerprint();
        assert!(matches!(
            seal_recovery_decision::<parth_core::PHash>(
                &source,
                BranchExactPendingStartupRecovery::ReadyForQueueClose,
            ),
            ScyllaStartupRecoveryDecision::Clean
        ));
        for (recovery, expected) in [
            (
                BranchExactPendingStartupRecovery::<parth_core::PHash>::AwaitPrimeOrRotate,
                ScyllaStartupAwaitExternalReason::PrimeOrRotate,
            ),
            (
                BranchExactPendingStartupRecovery::AwaitTrustedMarker,
                ScyllaStartupAwaitExternalReason::PublishTrustedMarker,
            ),
            (
                BranchExactPendingStartupRecovery::CompleteAfterTrustedMarker,
                ScyllaStartupAwaitExternalReason::RotateTerminal,
            ),
        ] {
            assert!(matches!(
                seal_recovery_decision(&source, recovery),
                ScyllaStartupRecoveryDecision::AwaitExternal(reason)
                    if reason == expected
            ));
        }

        let ScyllaStartupRecoveryDecision::Recover(admission) =
            seal_recovery_decision::<parth_core::PHash>(
                &source,
                BranchExactPendingStartupRecovery::FinishWriterAfterTrustedMarker,
            )
        else {
            panic!("finish-writer must produce one sealed recovery action")
        };
        assert_eq!(admission.source_fingerprint(), &source.digest());
        assert_ne!(admission.action_digest(), &[0; 32]);
        assert!(admission.matches_source(&source));
        let mut changed = source.clone();
        changed.parts[6].push(0xff);
        assert!(!admission.matches_source(&changed));
        assert!(matches!(
            admission.action,
            ScyllaStartupRecoveryAction::FinishWriterAfterTrustedMarker
        ));
    }

    #[test]
    fn recovery_admission_is_private_nonclone_and_has_no_codec() {
        let source = include_str!("branch_exact_startup_preflight.rs");
        let declaration = source
            .split("struct SealedScyllaStartupRecoveryAdmission")
            .next()
            .unwrap()
            .lines()
            .rev()
            .take(2)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!declaration.contains("pub struct"));
        assert!(!declaration.contains("Clone"));
        assert!(!declaration.contains("Serialize"));
        let public_constructor = ["pub fn ", "seal_recovery_decision"].concat();
        assert!(!source.contains(&public_constructor));
        let decision = source
            .split("fn seal_recovery_decision")
            .nth(1)
            .unwrap()
            .split("#[derive(Clone, Copy, Debug, Eq, PartialEq)]\nstruct ValidatedScyllaStartup")
            .next()
            .unwrap();
        assert!(!decision.contains("_ =>"));
    }

    #[test]
    fn only_clean_ready_pending_boundary_can_authorize_a_run() {
        assert_eq!(
            require_clean_run_boundary::<parth_core::PHash>(
                &BranchExactPendingStartupRecovery::ReadyForQueueClose,
            ),
            Ok(2),
        );
        for recovery in [
            BranchExactPendingStartupRecovery::<parth_core::PHash>::AwaitPrimeOrRotate,
            BranchExactPendingStartupRecovery::AwaitTrustedMarker,
            BranchExactPendingStartupRecovery::CompleteNoWorkAfterTrustedMarker,
            BranchExactPendingStartupRecovery::FinishWriterAfterTrustedMarker,
            BranchExactPendingStartupRecovery::CompleteAfterTrustedMarker,
        ] {
            assert!(matches!(
                require_clean_run_boundary(&recovery),
                Err(RealmProcessorStartupError::DurableRecoveryRequired(_))
            ));
        }

        let source = include_str!("branch_exact_startup_preflight.rs");
        let boundary = source
            .split("fn require_clean_run_boundary")
            .nth(1)
            .unwrap()
            .split("fn require_not_behind_cutover")
            .next()
            .unwrap();
        assert_eq!(boundary.matches("=> Ok(").count(), 1);
        assert!(boundary.contains("ReadyForQueueClose => Ok(2)"));
    }

    #[test]
    fn provider_is_read_only_default_off_and_full_double_sampled() {
        let source = include_str!("branch_exact_startup_preflight.rs");
        let fresh = source
            .split("async fn fresh_read(")
            .nth(1)
            .expect("provider trait implementation must exist")
            .split("#[derive(Clone, Debug, Eq, PartialEq)]")
            .next()
            .unwrap();
        assert_eq!(fresh.matches("self.read_composite().await?").count(), 2);
        assert!(fresh.contains("before_fingerprint != after_fingerprint"));
        assert!(!fresh.contains("create_schema"));
        assert!(!fresh.contains("bootstrap("));
        assert!(!fresh.contains("compare_and_set"));

        let setup = include_str!("../psy_setup.rs");
        let common = include_str!(
            "../../../psy_node_common/src/realm/processor/create.rs"
        );
        assert!(!setup.contains("ScyllaRealmProcessorStartupPreflightProvider"));
        assert!(!common.contains("ScyllaRealmProcessorStartupPreflightProvider"));
    }

    #[test]
    fn static_expectation_does_not_pin_dynamic_writer_watermark() {
        let core = include_str!(
            "../../../psy_node_core/src/store/realm_processor_startup.rs"
        );
        let expectation = core
            .split("pub struct RealmProcessorStartupExpectation")
            .nth(1)
            .unwrap()
            .split("pub struct RealmProcessorStartupRouteObservation")
            .next()
            .unwrap();
        assert!(!expectation.contains("expected_watermark"));
        assert!(core.contains("hasher.update(evidence.watermark_digest.as_bytes())"));
    }
}
