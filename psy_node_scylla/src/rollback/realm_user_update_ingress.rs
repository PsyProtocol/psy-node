//! Storage-owned high-level Realm user-update ingress.
//!
//! The façade is crate-private and default-off. It is the only object intended
//! for a production Edge composition; neither the raw durable router nor the
//! low-level publisher crosses this boundary.

use std::sync::Arc;

use async_trait::async_trait;
use parth_core::{
    crypto::hash::traits::FieldQHasher,
    felt::QFelt64,
    protocol::core_types::{Q256BitHash, QFHashBase, QZKProofVerifier},
};
use psy_data::proof_input::guta::end_cap_input::SubmitUserEndCapNonProofInput;
use psy_node_core::queue::{
    realm_user_update_ingress::{
        RealmUserUpdateArtifactFactory, RealmUserUpdateIngressError,
        RealmUserUpdateIngressPort, RealmUserUpdateIngressReceipt,
        RealmUserUpdateStateFence,
    },
    realm_user_update_publish::RealmUserUpdatePublishAdmission,
};

use super::ScyllaRealmUserUpdateDurableRouter;

pub(crate) struct ScyllaRealmUserUpdateIngress<
    F,
    Hash,
    Hasher,
    Proof,
    Verifier,
> {
    router: ScyllaRealmUserUpdateDurableRouter<F, Hash, Hasher, Proof, Verifier>,
    artifact_factory: Arc<dyn RealmUserUpdateArtifactFactory<F, Hash>>,
}

impl<F, Hash, Hasher, Proof, Verifier>
    ScyllaRealmUserUpdateIngress<F, Hash, Hasher, Proof, Verifier>
{
    pub(crate) fn new(
        router: ScyllaRealmUserUpdateDurableRouter<
            F,
            Hash,
            Hasher,
            Proof,
            Verifier,
        >,
        artifact_factory: Arc<dyn RealmUserUpdateArtifactFactory<F, Hash>>,
    ) -> Self {
        Self {
            router,
            artifact_factory,
        }
    }
}

#[async_trait]
impl<F, Hash, Hasher, Proof, Verifier> RealmUserUpdateIngressPort<F, Hash>
    for ScyllaRealmUserUpdateIngress<F, Hash, Hasher, Proof, Verifier>
where
    F: QFelt64 + Send + Sync + 'static,
    Hash: Q256BitHash + QFHashBase<F> + Send + Sync + 'static,
    Hasher: FieldQHasher<F, Hash> + Send + Sync + 'static,
    Proof: 'static,
    Verifier: QZKProofVerifier<Hash, Proof> + Send + Sync + 'static,
{
    async fn admit(
        &self,
    ) -> Result<RealmUserUpdatePublishAdmission<Hash>, RealmUserUpdateIngressError>
    {
        self.router
            .admit()
            .await
            .map_err(|error| RealmUserUpdateIngressError::Admission(error.to_string()))
    }

    async fn submit_after_state_validation(
        &self,
        fence: RealmUserUpdateStateFence<Hash>,
        input: SubmitUserEndCapNonProofInput<F, Hash>,
        proof: Vec<u8>,
    ) -> Result<RealmUserUpdateIngressReceipt<Hash>, RealmUserUpdateIngressError>
    {
        self.router
            .submit_after_state_validation(
                fence,
                input,
                proof,
                Arc::clone(&self.artifact_factory),
            )
            .await
            .map_err(|error| match error {
                super::RealmUserUpdateRouterError::ProofTaskFailed(_)
                | super::RealmUserUpdateRouterError::ProofRecoveryFailed(_) => {
                    RealmUserUpdateIngressError::Proof(error.to_string())
                }
                super::RealmUserUpdateRouterError::AuthorityObservationChanged => {
                    RealmUserUpdateIngressError::AuthorityObservationChanged
                }
                super::RealmUserUpdateRouterError::ArtifactTaskFailed(_)
                | super::RealmUserUpdateRouterError::ArtifactBuildFailed(_) => {
                    RealmUserUpdateIngressError::Artifact(error.to_string())
                }
                super::RealmUserUpdateRouterError::ClaimConflict { .. } => {
                    RealmUserUpdateIngressError::Claim(error.to_string())
                }
                _ => RealmUserUpdateIngressError::Publication(error.to_string()),
            })
    }
}

#[cfg(test)]
mod tests {
    fn production_source() -> &'static str {
        include_str!("realm_user_update_ingress.rs")
            .split("#[cfg(test)]\nmod tests")
            .next()
            .unwrap()
    }

    #[test]
    fn facade_is_high_level_default_off_and_hides_router() {
        let source = production_source();
        assert!(source.contains("RealmUserUpdateIngressPort<F, Hash>"));
        assert!(source.contains("submit_after_state_validation"));
        assert!(source.contains("Arc<dyn RealmUserUpdateArtifactFactory<F, Hash>>"));
        assert!(!source.contains("pub struct ScyllaRealmUserUpdateIngress"));
        for forbidden in [
            "pub fn router",
            "pub fn publisher",
            "RealmUserUpdatePublishPort",
            "Session",
            "legacy",
        ] {
            assert!(
                !source.contains(forbidden),
                "ingress façade exposed forbidden capability {forbidden}"
            );
        }
    }
}
