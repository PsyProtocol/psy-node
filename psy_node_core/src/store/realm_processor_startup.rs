//! Driver-independent preflight boundary for an enabled Realm Processor.
//!
//! A provider may inspect durable storage and return a stable evidence view,
//! but only this module can seal the non-Clone permit. Providers decide which
//! exact durable phases have an installed runtime recovery owner; the permit
//! commits that complete evidence without turning the observation itself into
//! mutation authority.

use std::{error::Error, fmt};

use async_trait::async_trait;
use psy_data::protocol::canonical_chain::NetworkId;
use sha2::{Digest, Sha256};

const REQUEST_DOMAIN: &[u8] = b"psy/rollback/realm-startup-request/v1";
const PERMIT_DOMAIN: &[u8] = b"psy/rollback/realm-startup-permit/v1";

macro_rules! digest_type {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub struct $name([u8; 32]);

        impl $name {
            pub fn try_new(bytes: [u8; 32]) -> Result<Self, RealmProcessorStartupError> {
                if bytes == [0; 32] {
                    return Err(RealmProcessorStartupError::ZeroDigest);
                }
                Ok(Self(bytes))
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}

digest_type!(RealmProcessorStartupBindingDigest);
digest_type!(RealmProcessorStartupRouteStateDigest);
digest_type!(RealmProcessorStartupWriterActivationDigest);
digest_type!(RealmProcessorStartupWatermarkDigest);
digest_type!(RealmProcessorStartupReadinessDigest);
digest_type!(RealmProcessorStartupRequestDigest);
digest_type!(RealmProcessorStartupPermitDigest);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RealmProcessorStartupRoutePhase {
    LegacyPrimaryDualWrite = 1,
    QuiescingToTarget = 2,
    TargetPrimaryDualWrite = 3,
    QuiescingToLegacy = 4,
}

impl RealmProcessorStartupRoutePhase {
    pub const fn is_stable(self) -> bool {
        matches!(
            self,
            Self::LegacyPrimaryDualWrite | Self::TargetPrimaryDualWrite
        )
    }
}

/// Operator-selected exact lineage. Revision and state digest are deliberately
/// sampled by the provider so a restart does not require editing config after
/// every legal route CAS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmProcessorStartupExpectation {
    network: NetworkId,
    realm_id: u32,
    realm_sub_id: u16,
    expected_generation: u64,
    expected_binding_digest: RealmProcessorStartupBindingDigest,
    expected_writer_activation_digest: RealmProcessorStartupWriterActivationDigest,
    startup_nonce: [u8; 32],
    digest: RealmProcessorStartupRequestDigest,
}

/// Stable operator-selected lineage. It deliberately excludes route revision,
/// live writer watermark, readiness state, and the per-attempt nonce.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmProcessorStartupLineage {
    network: NetworkId,
    realm_id: u32,
    realm_sub_id: u16,
    expected_generation: u64,
    expected_binding_digest: RealmProcessorStartupBindingDigest,
    expected_writer_activation_digest: RealmProcessorStartupWriterActivationDigest,
}

impl RealmProcessorStartupLineage {
    pub fn try_new(
        network: NetworkId,
        realm_id: u32,
        realm_sub_id: u16,
        expected_generation: u64,
        expected_binding_digest: [u8; 32],
        expected_writer_activation_digest: [u8; 32],
    ) -> Result<Self, RealmProcessorStartupError> {
        if expected_generation > i64::MAX as u64 {
            return Err(RealmProcessorStartupError::GenerationOutOfRange);
        }
        Ok(Self {
            network,
            realm_id,
            realm_sub_id,
            expected_generation,
            expected_binding_digest: RealmProcessorStartupBindingDigest::try_new(
                expected_binding_digest,
            )?,
            expected_writer_activation_digest:
                RealmProcessorStartupWriterActivationDigest::try_new(
                    expected_writer_activation_digest,
                )?,
        })
    }

    pub const fn network(self) -> NetworkId {
        self.network
    }

    pub const fn realm_id(self) -> u32 {
        self.realm_id
    }

    pub const fn realm_sub_id(self) -> u16 {
        self.realm_sub_id
    }

    pub const fn expected_generation(self) -> u64 {
        self.expected_generation
    }

    pub const fn expected_binding_digest(self) -> RealmProcessorStartupBindingDigest {
        self.expected_binding_digest
    }

    pub const fn expected_writer_activation_digest(
        self,
    ) -> RealmProcessorStartupWriterActivationDigest {
        self.expected_writer_activation_digest
    }

    /// Seal one process-local startup attempt. Production composition must
    /// supply a freshly minted nonce rather than deserialize one from config.
    pub fn seal_attempt(
        self,
        startup_nonce: [u8; 32],
    ) -> Result<RealmProcessorStartupExpectation, RealmProcessorStartupError> {
        RealmProcessorStartupExpectation::try_new(
            self.network,
            self.realm_id,
            self.realm_sub_id,
            self.expected_generation,
            *self.expected_binding_digest.as_bytes(),
            *self.expected_writer_activation_digest.as_bytes(),
            startup_nonce,
        )
    }
}

impl RealmProcessorStartupExpectation {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        network: NetworkId,
        realm_id: u32,
        realm_sub_id: u16,
        expected_generation: u64,
        expected_binding_digest: [u8; 32],
        expected_writer_activation_digest: [u8; 32],
        startup_nonce: [u8; 32],
    ) -> Result<Self, RealmProcessorStartupError> {
        if expected_generation > i64::MAX as u64 {
            return Err(RealmProcessorStartupError::GenerationOutOfRange);
        }
        if startup_nonce == [0; 32] {
            return Err(RealmProcessorStartupError::ZeroStartupNonce);
        }
        let expected_binding_digest =
            RealmProcessorStartupBindingDigest::try_new(expected_binding_digest)?;
        let expected_writer_activation_digest =
            RealmProcessorStartupWriterActivationDigest::try_new(
                expected_writer_activation_digest,
            )?;
        let digest = request_digest(
            network,
            realm_id,
            realm_sub_id,
            expected_generation,
            expected_binding_digest,
            expected_writer_activation_digest,
            startup_nonce,
        )?;
        Ok(Self {
            network,
            realm_id,
            realm_sub_id,
            expected_generation,
            expected_binding_digest,
            expected_writer_activation_digest,
            startup_nonce,
            digest,
        })
    }

    pub const fn network(self) -> NetworkId {
        self.network
    }

    pub const fn realm_id(self) -> u32 {
        self.realm_id
    }

    pub const fn realm_sub_id(self) -> u16 {
        self.realm_sub_id
    }

    pub const fn expected_generation(self) -> u64 {
        self.expected_generation
    }

    pub const fn expected_binding_digest(self) -> RealmProcessorStartupBindingDigest {
        self.expected_binding_digest
    }

    pub const fn expected_writer_activation_digest(
        self,
    ) -> RealmProcessorStartupWriterActivationDigest {
        self.expected_writer_activation_digest
    }

    pub const fn startup_nonce(self) -> [u8; 32] {
        self.startup_nonce
    }

    pub const fn digest(self) -> RealmProcessorStartupRequestDigest {
        self.digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmProcessorStartupRouteObservation {
    generation: u64,
    revision: u64,
    binding_digest: RealmProcessorStartupBindingDigest,
    state_digest: RealmProcessorStartupRouteStateDigest,
    phase: RealmProcessorStartupRoutePhase,
}

impl RealmProcessorStartupRouteObservation {
    pub fn try_new(
        generation: u64,
        revision: u64,
        binding_digest: [u8; 32],
        state_digest: [u8; 32],
        phase: RealmProcessorStartupRoutePhase,
    ) -> Result<Self, RealmProcessorStartupError> {
        if generation > i64::MAX as u64 {
            return Err(RealmProcessorStartupError::GenerationOutOfRange);
        }
        if revision > i64::MAX as u64 {
            return Err(RealmProcessorStartupError::RevisionOutOfRange);
        }
        Ok(Self {
            generation,
            revision,
            binding_digest: RealmProcessorStartupBindingDigest::try_new(binding_digest)?,
            state_digest: RealmProcessorStartupRouteStateDigest::try_new(state_digest)?,
            phase,
        })
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub const fn revision(self) -> u64 {
        self.revision
    }

    pub const fn binding_digest(self) -> RealmProcessorStartupBindingDigest {
        self.binding_digest
    }

    pub const fn state_digest(self) -> RealmProcessorStartupRouteStateDigest {
        self.state_digest
    }

    pub const fn phase(self) -> RealmProcessorStartupRoutePhase {
        self.phase
    }
}

/// Provider-owned result of `route A -> subordinate readiness -> route B`.
/// It is a view, not authorization; callers cannot turn it into a permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmProcessorStartupEvidence {
    network: NetworkId,
    realm_id: u32,
    realm_sub_id: u16,
    route_before: RealmProcessorStartupRouteObservation,
    route_after: RealmProcessorStartupRouteObservation,
    writer_activation_digest: RealmProcessorStartupWriterActivationDigest,
    watermark_digest: RealmProcessorStartupWatermarkDigest,
    readiness_digest: RealmProcessorStartupReadinessDigest,
}

impl RealmProcessorStartupEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        network: NetworkId,
        realm_id: u32,
        realm_sub_id: u16,
        route_before: RealmProcessorStartupRouteObservation,
        route_after: RealmProcessorStartupRouteObservation,
        writer_activation_digest: [u8; 32],
        watermark_digest: [u8; 32],
        readiness_digest: [u8; 32],
    ) -> Result<Self, RealmProcessorStartupError> {
        Ok(Self {
            network,
            realm_id,
            realm_sub_id,
            route_before,
            route_after,
            writer_activation_digest:
                RealmProcessorStartupWriterActivationDigest::try_new(
                    writer_activation_digest,
                )?,
            watermark_digest: RealmProcessorStartupWatermarkDigest::try_new(
                watermark_digest,
            )?,
            readiness_digest: RealmProcessorStartupReadinessDigest::try_new(
                readiness_digest,
            )?,
        })
    }

    pub const fn route(self) -> RealmProcessorStartupRouteObservation {
        self.route_after
    }

    pub const fn readiness_digest(self) -> RealmProcessorStartupReadinessDigest {
        self.readiness_digest
    }
}

#[async_trait]
pub trait RealmProcessorStartupPreflightProvider: Send + Sync {
    /// Must perform a fresh, read-only durable sample. Missing/malformed rows
    /// are errors; providers must not bootstrap, repair, or cache readiness.
    async fn fresh_read(
        &self,
        expectation: RealmProcessorStartupExpectation,
    ) -> Result<RealmProcessorStartupEvidence, RealmProcessorStartupError>;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RealmProcessorStartupMode {
    #[default]
    Disabled,
    RequireBranchExact(RealmProcessorStartupExpectation),
}

#[derive(Debug)]
struct RealmProcessorStartupPermit {
    expectation: RealmProcessorStartupExpectation,
    evidence: RealmProcessorStartupEvidence,
    digest: RealmProcessorStartupPermitDigest,
}

impl RealmProcessorStartupPermit {
    pub const fn expectation(&self) -> RealmProcessorStartupExpectation {
        self.expectation
    }

    pub const fn evidence(&self) -> RealmProcessorStartupEvidence {
        self.evidence
    }

    pub const fn digest(&self) -> RealmProcessorStartupPermitDigest {
        self.digest
    }
}

/// The only branch-exact authorization that may cross from startup admission
/// into a Processor composition. It is minted from one fresh, fully
/// runtime-resumable preflight and is deliberately non-Clone and
/// non-serializable.
#[derive(Debug)]
pub struct RealmProcessorFreshRunPermit {
    startup: RealmProcessorStartupPermit,
}

impl RealmProcessorFreshRunPermit {
    pub const fn expectation(&self) -> RealmProcessorStartupExpectation {
        self.startup.expectation()
    }

    pub const fn evidence(&self) -> RealmProcessorStartupEvidence {
        self.startup.evidence()
    }

    pub const fn digest(&self) -> RealmProcessorStartupPermitDigest {
        self.startup.digest()
    }
}

#[derive(Debug)]
pub enum RealmProcessorStartupAuthorization {
    Disabled,
    BranchExact(RealmProcessorFreshRunPermit),
}

pub async fn authorize_realm_processor_startup(
    mode: RealmProcessorStartupMode,
    provider: Option<&dyn RealmProcessorStartupPreflightProvider>,
) -> Result<RealmProcessorStartupAuthorization, RealmProcessorStartupError> {
    match mode {
        RealmProcessorStartupMode::Disabled => {
            if provider.is_some() {
                return Err(RealmProcessorStartupError::UnexpectedProviderWhileDisabled);
            }
            Ok(RealmProcessorStartupAuthorization::Disabled)
        }
        RealmProcessorStartupMode::RequireBranchExact(expectation) => {
            let provider = provider.ok_or(RealmProcessorStartupError::StartupProviderMissing)?;
            let evidence = provider.fresh_read(expectation).await?;
            validate_evidence(expectation, evidence)?;
            let digest = permit_digest(expectation, evidence)?;
            Ok(RealmProcessorStartupAuthorization::BranchExact(
                RealmProcessorFreshRunPermit {
                    startup: RealmProcessorStartupPermit {
                        expectation,
                        evidence,
                        digest,
                    },
                },
            ))
        }
    }
}

fn validate_evidence(
    expectation: RealmProcessorStartupExpectation,
    evidence: RealmProcessorStartupEvidence,
) -> Result<(), RealmProcessorStartupError> {
    if evidence.network != expectation.network
        || evidence.realm_id != expectation.realm_id
        || evidence.realm_sub_id != expectation.realm_sub_id
    {
        return Err(RealmProcessorStartupError::AuthorityMismatch);
    }
    if evidence.route_before != evidence.route_after {
        return Err(RealmProcessorStartupError::ConcurrentMutation);
    }
    let route = evidence.route_after;
    if !route.phase.is_stable() {
        return Err(RealmProcessorStartupError::RouteQuiescing);
    }
    if route.generation != expectation.expected_generation
        || route.binding_digest != expectation.expected_binding_digest
    {
        return Err(RealmProcessorStartupError::RouteMismatch);
    }
    if evidence.writer_activation_digest != expectation.expected_writer_activation_digest {
        return Err(RealmProcessorStartupError::WriterActivationMismatch);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn request_digest(
    network: NetworkId,
    realm_id: u32,
    realm_sub_id: u16,
    generation: u64,
    binding: RealmProcessorStartupBindingDigest,
    writer: RealmProcessorStartupWriterActivationDigest,
    nonce: [u8; 32],
) -> Result<RealmProcessorStartupRequestDigest, RealmProcessorStartupError> {
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_DOMAIN);
    hasher.update(network.chain_id().to_be_bytes());
    hasher.update(realm_id.to_be_bytes());
    hasher.update(realm_sub_id.to_be_bytes());
    hasher.update(generation.to_be_bytes());
    hasher.update(binding.as_bytes());
    hasher.update(writer.as_bytes());
    hasher.update(nonce);
    RealmProcessorStartupRequestDigest::try_new(hasher.finalize().into())
}

fn permit_digest(
    expectation: RealmProcessorStartupExpectation,
    evidence: RealmProcessorStartupEvidence,
) -> Result<RealmProcessorStartupPermitDigest, RealmProcessorStartupError> {
    let route = evidence.route_after;
    let mut hasher = Sha256::new();
    hasher.update(PERMIT_DOMAIN);
    hasher.update(expectation.digest.as_bytes());
    hasher.update(route.generation.to_be_bytes());
    hasher.update(route.revision.to_be_bytes());
    hasher.update(route.binding_digest.as_bytes());
    hasher.update(route.state_digest.as_bytes());
    hasher.update([route.phase as u8]);
    hasher.update(evidence.writer_activation_digest.as_bytes());
    hasher.update(evidence.watermark_digest.as_bytes());
    hasher.update(evidence.readiness_digest.as_bytes());
    RealmProcessorStartupPermitDigest::try_new(hasher.finalize().into())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealmProcessorStartupError {
    StartupProviderMissing,
    CommitRuntimeInstallerMissing,
    ProofVerifierMissing,
    CommitRuntimeIdentityMismatch,
    UnexpectedProviderWhileDisabled,
    UnexpectedCommitRuntimeInstallerWhileDisabled,
    UnexpectedProofVerifierWhileDisabled,
    ProviderRejected(String),
    DurableEvidenceNotVerified(String),
    DurableRecoveryRequired(String),
    DurableStorageIndeterminate(String),
    GenerationOutOfRange,
    RevisionOutOfRange,
    ZeroDigest,
    ZeroStartupNonce,
    AuthorityMismatch,
    ConcurrentMutation,
    RouteQuiescing,
    RouteMismatch,
    WriterActivationMismatch,
}

impl fmt::Display for RealmProcessorStartupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RealmProcessorStartupError {}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use psy_core::constants::chain_id::PsyChainNetworkType;

    use super::*;

    fn network() -> NetworkId {
        NetworkId::from_network_type(PsyChainNetworkType::LocalDevnet)
    }

    fn other_network() -> NetworkId {
        NetworkId::from_network_type(PsyChainNetworkType::InternalDevnet)
    }

    fn expectation() -> RealmProcessorStartupExpectation {
        RealmProcessorStartupExpectation::try_new(
            network(), 7, 3, 11, [1; 32], [2; 32], [4; 32],
        )
        .unwrap()
    }

    fn lineage() -> RealmProcessorStartupLineage {
        RealmProcessorStartupLineage::try_new(
            network(), 7, 3, 11, [1; 32], [2; 32],
        )
        .unwrap()
    }

    #[test]
    fn stable_lineage_excludes_nonce_and_seals_fresh_attempts() {
        let lineage = lineage();
        let first = lineage.seal_attempt([3; 32]).unwrap();
        let second = lineage.seal_attempt([4; 32]).unwrap();
        assert_eq!(first.network(), lineage.network());
        assert_eq!(first.realm_id(), lineage.realm_id());
        assert_eq!(first.realm_sub_id(), lineage.realm_sub_id());
        assert_eq!(first.expected_generation(), lineage.expected_generation());
        assert_ne!(first.startup_nonce(), second.startup_nonce());
        assert_ne!(first.digest(), second.digest());

        let source = include_str!("realm_processor_startup.rs");
        let fields = source
            .split("pub struct RealmProcessorStartupLineage")
            .nth(1)
            .unwrap()
            .split("impl RealmProcessorStartupLineage")
            .next()
            .unwrap();
        assert!(!fields.contains("nonce"));
    }

    fn route(revision: u64, phase: RealmProcessorStartupRoutePhase) -> RealmProcessorStartupRouteObservation {
        RealmProcessorStartupRouteObservation::try_new(
            11,
            revision,
            [1; 32],
            [5; 32],
            phase,
        )
        .unwrap()
    }

    fn evidence() -> RealmProcessorStartupEvidence {
        RealmProcessorStartupEvidence::try_new(
            network(),
            7,
            3,
            route(13, RealmProcessorStartupRoutePhase::LegacyPrimaryDualWrite),
            route(13, RealmProcessorStartupRoutePhase::LegacyPrimaryDualWrite),
            [2; 32],
            [3; 32],
            [6; 32],
        )
        .unwrap()
    }

    struct FakeProvider {
        calls: Arc<AtomicUsize>,
        result: Result<RealmProcessorStartupEvidence, RealmProcessorStartupError>,
    }

    #[async_trait]
    impl RealmProcessorStartupPreflightProvider for FakeProvider {
        async fn fresh_read(
            &self,
            _expectation: RealmProcessorStartupExpectation,
        ) -> Result<RealmProcessorStartupEvidence, RealmProcessorStartupError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.result.clone()
        }
    }

    #[tokio::test]
    async fn disabled_is_no_io_and_provider_is_rejected() {
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = FakeProvider {
            calls: calls.clone(),
            result: Ok(evidence()),
        };
        assert!(matches!(
            authorize_realm_processor_startup(RealmProcessorStartupMode::Disabled, None)
                .await
                .unwrap(),
            RealmProcessorStartupAuthorization::Disabled
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            authorize_realm_processor_startup(
                RealmProcessorStartupMode::Disabled,
                Some(&provider),
            )
            .await
            .unwrap_err(),
            RealmProcessorStartupError::UnexpectedProviderWhileDisabled
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn missing_enabled_composition_fails_before_any_read() {
        assert_eq!(
            authorize_realm_processor_startup(
                RealmProcessorStartupMode::RequireBranchExact(expectation()),
                None,
            )
            .await
            .unwrap_err(),
            RealmProcessorStartupError::StartupProviderMissing
        );
    }

    #[tokio::test]
    async fn exact_stable_sample_seals_deterministic_nonclone_permit() {
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = FakeProvider {
            calls: calls.clone(),
            result: Ok(evidence()),
        };
        let first = authorize_realm_processor_startup(
            RealmProcessorStartupMode::RequireBranchExact(expectation()),
            Some(&provider),
        )
        .await
        .unwrap();
        let second = authorize_realm_processor_startup(
            RealmProcessorStartupMode::RequireBranchExact(expectation()),
            Some(&provider),
        )
        .await
        .unwrap();
        let RealmProcessorStartupAuthorization::BranchExact(first) = first else {
            panic!("expected permit")
        };
        let RealmProcessorStartupAuthorization::BranchExact(second) = second else {
            panic!("expected permit")
        };
        assert_eq!(first.digest(), second.digest());
        assert_eq!(first.evidence().route().revision(), 13);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn route_change_and_quiescing_phase_fail_closed() {
        let changed = RealmProcessorStartupEvidence::try_new(
            network(),
            7,
            3,
            route(13, RealmProcessorStartupRoutePhase::LegacyPrimaryDualWrite),
            route(14, RealmProcessorStartupRoutePhase::LegacyPrimaryDualWrite),
            [2; 32],
            [3; 32],
            [6; 32],
        )
        .unwrap();
        for (sample, expected) in [
            (changed, RealmProcessorStartupError::ConcurrentMutation),
            (
                RealmProcessorStartupEvidence::try_new(
                    network(),
                    7,
                    3,
                    route(13, RealmProcessorStartupRoutePhase::QuiescingToTarget),
                    route(13, RealmProcessorStartupRoutePhase::QuiescingToTarget),
                    [2; 32],
                    [3; 32],
                    [6; 32],
                )
                .unwrap(),
                RealmProcessorStartupError::RouteQuiescing,
            ),
        ] {
            let provider = FakeProvider {
                calls: Arc::new(AtomicUsize::new(0)),
                result: Ok(sample),
            };
            assert_eq!(
                authorize_realm_processor_startup(
                    RealmProcessorStartupMode::RequireBranchExact(expectation()),
                    Some(&provider),
                )
                .await
                .unwrap_err(),
                expected
            );
        }
    }

    #[tokio::test]
    async fn every_external_identity_axis_is_checked() {
        let fixtures = [
            RealmProcessorStartupEvidence::try_new(
                other_network(),
                7,
                3,
                evidence().route(),
                evidence().route(),
                [2; 32],
                [3; 32],
                [6; 32],
            )
            .unwrap(),
            RealmProcessorStartupEvidence::try_new(
                network(), 8, 3, evidence().route(), evidence().route(), [2; 32], [3; 32], [6; 32],
            ).unwrap(),
            RealmProcessorStartupEvidence::try_new(
                network(), 7, 4, evidence().route(), evidence().route(), [2; 32], [3; 32], [6; 32],
            ).unwrap(),
            RealmProcessorStartupEvidence::try_new(
                network(), 7, 3, evidence().route(), evidence().route(), [9; 32], [3; 32], [6; 32],
            ).unwrap(),
        ];
        let expected_errors = [
            RealmProcessorStartupError::AuthorityMismatch,
            RealmProcessorStartupError::AuthorityMismatch,
            RealmProcessorStartupError::AuthorityMismatch,
            RealmProcessorStartupError::WriterActivationMismatch,
        ];
        for (sample, expected) in fixtures.into_iter().zip(expected_errors) {
            let provider = FakeProvider {
                calls: Arc::new(AtomicUsize::new(0)),
                result: Ok(sample),
            };
            assert_eq!(
                authorize_realm_processor_startup(
                    RealmProcessorStartupMode::RequireBranchExact(expectation()),
                    Some(&provider),
                )
                .await
                .unwrap_err(),
                expected
            );
        }
    }

    #[test]
    fn request_rejects_zero_and_cql_out_of_range_values() {
        assert_eq!(
            RealmProcessorStartupExpectation::try_new(
                network(), 7, 3, i64::MAX as u64 + 1, [1; 32], [2; 32], [4; 32],
            )
            .unwrap_err(),
            RealmProcessorStartupError::GenerationOutOfRange
        );
        assert_eq!(
            RealmProcessorStartupExpectation::try_new(
                network(), 7, 3, 1, [0; 32], [2; 32], [4; 32],
            )
            .unwrap_err(),
            RealmProcessorStartupError::ZeroDigest
        );
        assert_eq!(
            RealmProcessorStartupExpectation::try_new(
                network(), 7, 3, 1, [1; 32], [2; 32], [0; 32],
            )
            .unwrap_err(),
            RealmProcessorStartupError::ZeroStartupNonce
        );
    }

    #[test]
    fn fresh_run_permit_has_no_clone_default_codec_or_public_constructor() {
        let source = include_str!("realm_processor_startup.rs");
        let permit = source
            .split("pub struct RealmProcessorFreshRunPermit")
            .nth(1)
            .unwrap();
        let permit_header = source
            .split("pub struct RealmProcessorFreshRunPermit")
            .next()
            .unwrap()
            .lines()
            .rev()
            .take(1)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!permit_header.contains("Clone"));
        assert!(!permit_header.contains("Default"));
        assert!(!permit_header.contains("Serialize"));
        assert!(!permit_header.contains("Deserialize"));
        assert!(!permit.contains("pub fn new("));
        assert!(!permit.contains("pub fn try_new("));
        let clone_impl = ["impl Clone for RealmProcessor", "FreshRunPermit"].concat();
        assert!(!source.contains(&clone_impl));
    }
}
