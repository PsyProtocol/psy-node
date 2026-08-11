//! Storage-selected loader for the exact external dependencies committed by
//! a predecessor Realm terminal.
//!
//! The loader resolves the committed generation through the durable segment
//! ledger, rebuilds the qualified dependency projection from immutable rows,
//! and joins it to the exact closed NATS generation. It is read-only and does
//! not expose raw receipts, dependency payload injection, or mutation APIs.

use std::{fmt, marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use parth_core::{
    felt::QFelt64,
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use psy_data::protocol::{
    canonical_chain::NetworkId,
    chain_context::AuthorityScope,
};
use psy_node_core::queue::{
    realm_processor_durable_capture::{
        RealmProcessorDurableCapturedGeneration,
        RealmProcessorDurableCaptureError,
        RealmProcessorExternalDependencyLoader,
    },
    realm_processor_external_dependency_input::{
        RealmProcessorExternalDependencyCommitment,
        RealmProcessorQualifiedExternalActorInput,
    },
    realm_user_update_publish::GlobalUserTreeHeight,
};
use psy_node_nats::recoverable_assignment::PendingQueueSegmentLedgerKey;
use scylla::client::session::Session;

use super::{
    PendingQueueSidecarReady, ScyllaPendingQueueSegmentLedgerStore,
};
use super::realm_processor_external_dependency_projection::ScyllaRealmProcessorExternalDependencyProjector;

pub(super) struct ScyllaRealmProcessorExternalDependencyLoader<F, Hash> {
    session: Arc<Session>,
    network: NetworkId,
    authority: AuthorityScope,
    global_user_tree_height: GlobalUserTreeHeight,
    ready: Arc<PendingQueueSidecarReady>,
    base_namespace: String,
    ledger: Arc<ScyllaPendingQueueSegmentLedgerStore>,
    _types: PhantomData<(F, Hash)>,
}

impl<F, Hash> ScyllaRealmProcessorExternalDependencyLoader<F, Hash>
where
    F: QFelt64 + Send + Sync + 'static,
    Hash: Q256BitHash + QFHashBase<F> + Send + Sync + 'static,
{
    pub(super) async fn prepare(
        session: Arc<Session>,
        network: NetworkId,
        authority: AuthorityScope,
        global_user_tree_height: GlobalUserTreeHeight,
        ready: Arc<PendingQueueSidecarReady>,
        base_namespace: String,
    ) -> Result<Self, RealmProcessorDurableCaptureError> {
        if !matches!(authority, AuthorityScope::Realm { .. })
            || ready.view().authority() != authority
            || base_namespace.is_empty()
        {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        }
        let control = ready
            .view()
            .verified()
            .stored()
            .keyspaces()
            .control()
            .clone();
        let ledger = Arc::new(
            ScyllaPendingQueueSegmentLedgerStore::prepare(session.clone(), control)
                .await
                .map_err(backend)?,
        );
        Ok(Self {
            session,
            network,
            authority,
            global_user_tree_height,
            ready,
            base_namespace,
            ledger,
            _types: PhantomData,
        })
    }

    async fn load(
        &self,
        generation: RealmProcessorDurableCapturedGeneration,
        expected: RealmProcessorExternalDependencyCommitment,
    ) -> Result<RealmProcessorQualifiedExternalActorInput, RealmProcessorDurableCaptureError> {
        let context = expected.context();
        if context.key().network() != self.network
            || context.key().authority() != self.authority
            || generation.context() != context
        {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        }
        let ledger_key = PendingQueueSegmentLedgerKey::try_new(
            context.key(),
            &self.base_namespace,
        )
        .map_err(backend)?;
        let route = self
            .ledger
            .read_assignment_route_exact(&ledger_key, context)
            .await
            .map_err(backend)?;
        self.ledger
            .revalidate_assignment_route(&route)
            .await
            .map_err(backend)?;
        if route.assignment().assignment().digest().as_bytes()
            != expected.assignment_digest()
        {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        }

        let projector = ScyllaRealmProcessorExternalDependencyProjector::<F, Hash>::prepare(
            self.session.clone(),
            self.network,
            self.authority,
            self.global_user_tree_height,
            self.ready.clone(),
            route.segment().clone(),
        )
        .await
        .map_err(backend)?;
        let projection = projector
            .read_committed_exact(expected)
            .await
            .map_err(backend)?;
        projector
            .revalidate_exact(&projection)
            .await
            .map_err(backend)?;
        self.ledger
            .revalidate_assignment_route(&route)
            .await
            .map_err(backend)?;

        RealmProcessorQualifiedExternalActorInput::try_from_exact_sources(
            generation,
            projection.into_projection(),
        )
        .map_err(backend)
    }

    async fn load_current(
        &self,
        generation: RealmProcessorDurableCapturedGeneration,
    ) -> Result<RealmProcessorQualifiedExternalActorInput, RealmProcessorDurableCaptureError> {
        let context = generation.context();
        if context.key().network() != self.network
            || context.key().authority() != self.authority
        {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        }
        let ledger_key = PendingQueueSegmentLedgerKey::try_new(
            context.key(),
            &self.base_namespace,
        )
        .map_err(backend)?;
        let route = self
            .ledger
            .read_assignment_route_exact(&ledger_key, context)
            .await
            .map_err(backend)?;
        self.ledger
            .revalidate_assignment_route(&route)
            .await
            .map_err(backend)?;
        let assignment_digest = *route.assignment().assignment().digest().as_bytes();
        let projector = ScyllaRealmProcessorExternalDependencyProjector::<F, Hash>::prepare(
            self.session.clone(),
            self.network,
            self.authority,
            self.global_user_tree_height,
            self.ready.clone(),
            route.segment().clone(),
        )
        .await
        .map_err(backend)?;
        let projection = projector
            .read_current_selected_exact(context, assignment_digest)
            .await
            .map_err(backend)?;
        projector
            .revalidate_exact(&projection)
            .await
            .map_err(backend)?;
        self.ledger
            .revalidate_assignment_route(&route)
            .await
            .map_err(backend)?;
        RealmProcessorQualifiedExternalActorInput::try_from_exact_sources(
            generation,
            projection.into_projection(),
        )
        .map_err(backend)
    }
}

#[async_trait]
impl<F, Hash> RealmProcessorExternalDependencyLoader
    for ScyllaRealmProcessorExternalDependencyLoader<F, Hash>
where
    F: QFelt64 + Send + Sync + 'static,
    Hash: Q256BitHash + QFHashBase<F> + Send + Sync + 'static,
{
    async fn load_current_exact(
        &self,
        generation: RealmProcessorDurableCapturedGeneration,
    ) -> Result<RealmProcessorQualifiedExternalActorInput, RealmProcessorDurableCaptureError> {
        self.load_current(generation).await
    }

    async fn load_committed_exact(
        &self,
        generation: RealmProcessorDurableCapturedGeneration,
        expected: RealmProcessorExternalDependencyCommitment,
    ) -> Result<RealmProcessorQualifiedExternalActorInput, RealmProcessorDurableCaptureError> {
        self.load(generation, expected).await
    }
}

fn backend(error: impl fmt::Display) -> RealmProcessorDurableCaptureError {
    RealmProcessorDurableCaptureError::Backend(error.to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn loader_is_storage_selected_and_read_only() {
        let source = include_str!("realm_processor_external_dependency_loader.rs");
        let load = source
            .split("async fn load(")
            .nth(1)
            .unwrap()
            .split("#[async_trait]")
            .next()
            .unwrap();
        assert!(load.contains("read_assignment_route_exact"));
        assert!(load.contains("read_committed_exact(expected)"));
        assert!(load.contains("revalidate_exact(&projection)"));
        assert!(load.contains("try_from_exact_sources"));
        assert!(!load.contains("persist"));
        assert!(!load.contains("apply("));
        assert!(!load.contains("seal_rotation"));

        let load_current = source
            .split("async fn load_current(")
            .nth(1)
            .unwrap()
            .split("#[async_trait]")
            .next()
            .unwrap();
        assert!(load_current.contains("read_assignment_route_exact"));
        assert!(load_current.contains("read_current_selected_exact"));
        assert!(load_current.contains("revalidate_exact(&projection)"));
        assert!(load_current.contains("revalidate_assignment_route"));
        assert!(load_current.contains("try_from_exact_sources"));
        assert!(!load_current.contains("persist"));
        assert!(!load_current.contains("apply("));
    }
}
