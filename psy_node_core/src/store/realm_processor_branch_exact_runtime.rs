//! Opaque installation boundary between Realm startup admission and the
//! branch-exact commit composition.
//!
//! A fresh-run permit is deliberately insufficient on its own.  The exact
//! storage-backed runtime must consume that permit, revalidate its identity,
//! and return this module's non-Clone installed capability.  No live commit
//! operation is exposed yet: h23c4a only closes the ownership hand-off while
//! the production commit path remains fail closed.

use std::sync::Arc;

use async_trait::async_trait;
use psy_data::protocol::canonical_chain::NetworkId;

use super::realm_processor_startup::{
    RealmProcessorFreshRunPermit, RealmProcessorStartupError,
    RealmProcessorStartupPermitDigest,
};

/// Exact, deliberately narrow scope of the runtime being installed.  It does
/// not claim full 22-domain normal-commit coverage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmBranchExactRuntimeScope {
    MappingAndRewardProofDualWrite,
}

/// Driver-independent identity exposed by a storage-owned runtime.
///
/// The trait intentionally has no mutation method in h23c4a.  Adding live
/// commit operations is a later, independently reviewed slice.
pub trait RealmBranchExactCommitRuntime<Hash>: Send + Sync {
    fn network(&self) -> NetworkId;
    fn realm_id(&self) -> u32;
    fn realm_sub_id(&self) -> u16;
    fn writer_activation_digest(&self) -> [u8; 32];
    fn scope(&self) -> RealmBranchExactRuntimeScope;
}

/// Non-Clone capability proving that one exact fresh-run permit has been
/// consumed by an identity-matching runtime.
pub struct InstalledRealmBranchExactCommitRuntime<Hash> {
    startup_permit: RealmProcessorFreshRunPermit,
    runtime: Arc<dyn RealmBranchExactCommitRuntime<Hash>>,
}

impl<Hash> InstalledRealmBranchExactCommitRuntime<Hash> {
    /// The only constructor.  It consumes the non-Clone permit and rejects a
    /// runtime prepared for another network, Realm, or writer activation.
    pub fn seal(
        startup_permit: RealmProcessorFreshRunPermit,
        runtime: Arc<dyn RealmBranchExactCommitRuntime<Hash>>,
    ) -> Result<Self, RealmProcessorStartupError> {
        let expectation = startup_permit.expectation();
        if runtime.network() != expectation.network()
            || runtime.realm_id() != expectation.realm_id()
            || runtime.realm_sub_id() != expectation.realm_sub_id()
            || runtime.writer_activation_digest()
                != *expectation.expected_writer_activation_digest().as_bytes()
            || runtime.scope()
                != RealmBranchExactRuntimeScope::MappingAndRewardProofDualWrite
        {
            return Err(RealmProcessorStartupError::CommitRuntimeIdentityMismatch);
        }
        Ok(Self {
            startup_permit,
            runtime,
        })
    }

    pub const fn startup_permit_digest(&self) -> RealmProcessorStartupPermitDigest {
        self.startup_permit.digest()
    }

    pub fn runtime(&self) -> &dyn RealmBranchExactCommitRuntime<Hash> {
        self.runtime.as_ref()
    }
}

/// Storage-owned installer.  Implementations must fresh-read their durable
/// composite after startup authorization and before calling `seal`.
#[async_trait]
pub trait RealmBranchExactCommitRuntimeInstaller<Hash>: Send + Sync {
    async fn install(
        self: Arc<Self>,
        startup_permit: RealmProcessorFreshRunPermit,
    ) -> Result<InstalledRealmBranchExactCommitRuntime<Hash>, RealmProcessorStartupError>;
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use parth_core::PHash;
    use psy_core::constants::chain_id::PsyChainNetworkType;

    use super::*;
    use crate::store::realm_processor_startup::{
        authorize_realm_processor_startup, RealmProcessorStartupAuthorization,
        RealmProcessorStartupEvidence, RealmProcessorStartupExpectation,
        RealmProcessorStartupMode, RealmProcessorStartupPreflightProvider,
        RealmProcessorStartupRouteObservation,
        RealmProcessorStartupRoutePhase,
    };

    fn network() -> NetworkId {
        NetworkId::from_network_type(PsyChainNetworkType::LocalDevnet)
    }

    fn expectation() -> RealmProcessorStartupExpectation {
        RealmProcessorStartupExpectation::try_new(
            network(), 7, 3, 11, [1; 32], [2; 32], [4; 32],
        )
        .unwrap()
    }

    fn evidence() -> RealmProcessorStartupEvidence {
        let route = RealmProcessorStartupRouteObservation::try_new(
            11,
            13,
            [1; 32],
            [5; 32],
            RealmProcessorStartupRoutePhase::LegacyPrimaryDualWrite,
        )
        .unwrap();
        RealmProcessorStartupEvidence::try_new(
            network(), network_realm(), 3, route, route, [2; 32], [3; 32], [6; 32],
        )
        .unwrap()
    }

    const fn network_realm() -> u32 {
        7
    }

    struct Provider;

    #[async_trait]
    impl RealmProcessorStartupPreflightProvider for Provider {
        async fn fresh_read(
            &self,
            _expectation: RealmProcessorStartupExpectation,
        ) -> Result<RealmProcessorStartupEvidence, RealmProcessorStartupError> {
            Ok(evidence())
        }
    }

    async fn permit() -> RealmProcessorFreshRunPermit {
        let RealmProcessorStartupAuthorization::BranchExact(permit) =
            authorize_realm_processor_startup(
                RealmProcessorStartupMode::RequireBranchExact(expectation()),
                Some(&Provider),
            )
            .await
            .unwrap()
        else {
            panic!("expected branch-exact permit")
        };
        permit
    }

    struct Runtime {
        network: NetworkId,
        realm_id: u32,
        realm_sub_id: u16,
        activation: [u8; 32],
        drops: Arc<AtomicUsize>,
    }

    impl RealmBranchExactCommitRuntime<PHash> for Runtime {
        fn network(&self) -> NetworkId {
            self.network
        }

        fn realm_id(&self) -> u32 {
            self.realm_id
        }

        fn realm_sub_id(&self) -> u16 {
            self.realm_sub_id
        }

        fn writer_activation_digest(&self) -> [u8; 32] {
            self.activation
        }

        fn scope(&self) -> RealmBranchExactRuntimeScope {
            RealmBranchExactRuntimeScope::MappingAndRewardProofDualWrite
        }
    }

    impl Drop for Runtime {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn runtime(
        network: NetworkId,
        realm_id: u32,
        realm_sub_id: u16,
        activation: [u8; 32],
        drops: Arc<AtomicUsize>,
    ) -> Arc<dyn RealmBranchExactCommitRuntime<PHash>> {
        Arc::new(Runtime {
            network,
            realm_id,
            realm_sub_id,
            activation,
            drops,
        })
    }

    #[tokio::test]
    async fn exact_runtime_consumes_permit_into_nonclone_capability() {
        let permit = permit().await;
        let expected_digest = permit.digest();
        let drops = Arc::new(AtomicUsize::new(0));
        let installed = InstalledRealmBranchExactCommitRuntime::seal(
            permit,
            runtime(network(), 7, 3, [2; 32], drops.clone()),
        )
        .unwrap();
        assert_eq!(installed.startup_permit_digest(), expected_digest);
        assert_eq!(installed.runtime().realm_id(), 7);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(installed);
        assert_eq!(drops.load(Ordering::SeqCst), 1);

        let source = include_str!("realm_processor_branch_exact_runtime.rs");
        let installed = source
            .split("pub struct InstalledRealmBranchExactCommitRuntime")
            .nth(1)
            .unwrap()
            .split("impl<Hash> InstalledRealmBranchExactCommitRuntime")
            .next()
            .unwrap();
        assert!(!installed.contains("derive(Clone"));
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(!production.contains("impl Clone for InstalledRealmBranchExactCommitRuntime"));
    }

    #[tokio::test]
    async fn network_realm_sub_or_activation_mismatch_fails_closed() {
        for (candidate_network, realm_id, realm_sub_id, activation) in [
            (NetworkId::try_from_chain_id(1).unwrap(), 7, 3, [2; 32]),
            (network(), 8, 3, [2; 32]),
            (network(), 7, 4, [2; 32]),
            (network(), 7, 3, [9; 32]),
        ] {
            let result = InstalledRealmBranchExactCommitRuntime::seal(
                permit().await,
                runtime(
                    candidate_network,
                    realm_id,
                    realm_sub_id,
                    activation,
                    Arc::new(AtomicUsize::new(0)),
                ),
            );
            let Err(error) = result else {
                panic!("mismatched runtime must not install")
            };
            assert_eq!(
                error,
                RealmProcessorStartupError::CommitRuntimeIdentityMismatch
            );
        }
    }

    #[test]
    fn h23c4a_runtime_has_no_live_mutation_api() {
        let source = include_str!("realm_processor_branch_exact_runtime.rs");
        let runtime_trait = source
            .split("pub trait RealmBranchExactCommitRuntime")
            .nth(1)
            .unwrap()
            .split("pub struct InstalledRealmBranchExactCommitRuntime")
            .next()
            .unwrap();
        assert!(!runtime_trait.contains("async fn"));
        assert!(!runtime_trait.contains("prepare_and_verify"));
        assert!(!runtime_trait.contains("finish_published"));
    }
}
