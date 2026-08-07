//! Default-off composition of the pending-pipeline and branch-exact writer.
//!
//! Disabled selection has no `Session`-accepting operation.  The enabled
//! preparation owns both durable adapters and only exposes read-only startup
//! classification until a queue backend can provide an opaque persist-before-
//! ack seal and the authority marker can provide a trusted publish receipt.

#![allow(dead_code)]

use std::{error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_node_core::store::{
    pending_generation_identity::PendingGenerationLedgerKey,
    pending_generation_pipeline::{PendingPipelineReadState, StoredPendingPipeline},
};
use scylla::client::session::Session;

use super::{
    BranchExactDeploymentNoTabletKeyspace, BranchExactSchemaReady,
    BranchExactWriterRecoverySample, BranchExactWriterRuntimeError,
    BranchExactWriterRuntimeRequest, ScyllaBranchExactWriterRuntime,
    ScyllaPendingPipelineStore,
};
use super::branch_exact_pending_orchestration::{
    classify_branch_exact_pending_startup, BranchExactPendingOrchestrationError,
    BranchExactPendingStartupRecovery,
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum BranchExactPendingRuntimeMode<Hash> {
    #[default]
    Disabled,
    RequireRecoverable(BranchExactPendingRuntimeRequest<Hash>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactPendingRuntimeRequest<Hash> {
    writer: BranchExactWriterRuntimeRequest<Hash>,
}

impl<Hash> BranchExactPendingRuntimeRequest<Hash> {
    pub const fn new(writer: BranchExactWriterRuntimeRequest<Hash>) -> Self {
        Self { writer }
    }

    pub const fn writer(&self) -> &BranchExactWriterRuntimeRequest<Hash> {
        &self.writer
    }
}

/// The disabled branch contains no session or adapter.  Only the enabled
/// preparation accepts a Session, making "disabled performs no CQL" a type
/// boundary rather than a convention inside a large setup function.
pub(crate) enum BranchExactPendingRuntimeSelection<Hash> {
    Disabled,
    RequireRecoverable(BranchExactPendingRuntimePreparation<Hash>),
}

pub(crate) struct BranchExactPendingRuntimePreparation<Hash> {
    request: BranchExactPendingRuntimeRequest<Hash>,
}

pub(crate) struct ScyllaBranchExactPendingRuntime<Hash> {
    pipeline: ScyllaPendingPipelineStore,
    writer: ScyllaBranchExactWriterRuntime<Hash>,
    key: PendingGenerationLedgerKey,
    expected_activation: [u8; 32],
}

impl<Hash> ScyllaBranchExactPendingRuntime<Hash> {
    pub(crate) fn select(
        mode: BranchExactPendingRuntimeMode<Hash>,
    ) -> BranchExactPendingRuntimeSelection<Hash> {
        match mode {
            BranchExactPendingRuntimeMode::Disabled => {
                BranchExactPendingRuntimeSelection::Disabled
            }
            BranchExactPendingRuntimeMode::RequireRecoverable(request) => {
                BranchExactPendingRuntimeSelection::RequireRecoverable(
                    BranchExactPendingRuntimePreparation { request },
                )
            }
        }
    }
}

impl<Hash: Q256BitHash> BranchExactPendingRuntimePreparation<Hash> {
    /// Prepare-only factory. It never creates or bootstraps either durable row.
    /// Missing, blocked, wrong-activation or impossible cross-row state fails
    /// before a runtime can be returned.
    pub(crate) async fn prepare(
        self,
        session: Arc<Session>,
        no_tablet_keyspace: &str,
        ready: &BranchExactSchemaReady,
    ) -> Result<ScyllaBranchExactPendingRuntime<Hash>, BranchExactPendingRuntimeError> {
        let network = self.request.writer.network();
        let authority = self.request.writer.authority();
        let expected_activation = *self.request.writer.expected_activation_digest().as_bytes();
        let key = PendingGenerationLedgerKey::new(network, authority);
        let control_keyspace = BranchExactDeploymentNoTabletKeyspace::try_new(
            no_tablet_keyspace.to_owned(),
        )
        .map_err(|error| BranchExactPendingRuntimeError::Setup(error.to_string()))?;
        let pipeline = ScyllaPendingPipelineStore::prepare(
            session.clone(),
            control_keyspace,
        )
        .await
        .map_err(pipeline_store)?;
        let writer = ScyllaBranchExactWriterRuntime::prepare_from_ready(
            session,
            no_tablet_keyspace,
            self.request.writer,
            ready,
        )
        .await
        .map_err(writer_runtime)?;
        let runtime = ScyllaBranchExactPendingRuntime {
            pipeline,
            writer,
            key,
            expected_activation,
        };
        runtime.inspect_startup().await?;
        Ok(runtime)
    }
}

impl<Hash: Q256BitHash> ScyllaBranchExactPendingRuntime<Hash> {
    /// Re-read all three rows for every startup/retry decision. No cached state can
    /// authorize queue consumption or marker publication.
    pub(crate) async fn inspect_startup(
        &self,
    ) -> Result<BranchExactPendingStartupRecovery<Hash>, BranchExactPendingRuntimeError> {
        const MAX_STABLE_READ_ATTEMPTS: usize = 3;
        for _ in 0..MAX_STABLE_READ_ATTEMPTS {
            let first = self.read_sample().await?;
            let second = self.read_sample().await?;
            if let Some(first) = select_stable_sample(first, second) {
                return classify_branch_exact_pending_startup(
                    &first.pipeline,
                    first.writer.writer(),
                    first.writer.timestamp(),
                )
                .map_err(orchestration);
            }
        }
        Err(BranchExactPendingRuntimeError::ConcurrentMutation)
    }

    async fn read_sample(
        &self,
    ) -> Result<BranchExactPendingRuntimeSample<Hash>, BranchExactPendingRuntimeError> {
        let pipeline = require_pipeline(
            self.pipeline.read(self.key).await.map_err(pipeline_store)?,
            self.expected_activation,
        )?;
        let writer = self
            .writer
            .read_recovery_sample()
            .await
            .map_err(writer_runtime)?;
        Ok(BranchExactPendingRuntimeSample { pipeline, writer })
    }
}

fn select_stable_sample<T: PartialEq>(first: T, second: T) -> Option<T> {
    (first == second).then_some(first)
}

#[derive(Clone, Debug, PartialEq)]
struct BranchExactPendingRuntimeSample<Hash> {
    pipeline: StoredPendingPipeline<Hash>,
    writer: BranchExactWriterRecoverySample<Hash>,
}

fn require_pipeline<Hash>(
    state: PendingPipelineReadState<Hash>,
    expected_activation: [u8; 32],
) -> Result<StoredPendingPipeline<Hash>, BranchExactPendingRuntimeError> {
    let PendingPipelineReadState::Current(current) = state else {
        return Err(BranchExactPendingRuntimeError::PipelineUninitialized);
    };
    if current.activation_digest().as_bytes() != &expected_activation {
        return Err(BranchExactPendingRuntimeError::ActivationMismatch);
    }
    if current.blocked_reason().is_some() {
        return Err(BranchExactPendingRuntimeError::PipelineBlocked);
    }
    Ok(current)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactPendingRuntimeError {
    Setup(String),
    PipelineStore(String),
    WriterRuntime(String),
    Orchestration(String),
    PipelineUninitialized,
    PipelineBlocked,
    ActivationMismatch,
    ConcurrentMutation,
}

impl fmt::Display for BranchExactPendingRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for BranchExactPendingRuntimeError {}

fn pipeline_store(error: impl fmt::Display) -> BranchExactPendingRuntimeError {
    BranchExactPendingRuntimeError::PipelineStore(error.to_string())
}

fn writer_runtime(error: BranchExactWriterRuntimeError) -> BranchExactPendingRuntimeError {
    BranchExactPendingRuntimeError::WriterRuntime(error.to_string())
}

fn orchestration(error: BranchExactPendingOrchestrationError) -> BranchExactPendingRuntimeError {
    BranchExactPendingRuntimeError::Orchestration(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use parth_core::PHash;
    use psy_data::protocol::{
        canonical_chain::{NetworkId},
        chain_context::AuthorityScope,
    };
    use crate::rollback::BranchExactWriterActivationDigest;

    fn request() -> BranchExactPendingRuntimeRequest<PHash> {
        BranchExactPendingRuntimeRequest::new(BranchExactWriterRuntimeRequest::new(
            NetworkId::try_from_chain_id(1337).unwrap(),
            AuthorityScope::Coordinator,
            BranchExactWriterActivationDigest::try_from_hex(
                &hex::encode([0x5a; 32]),
            )
            .unwrap(),
        ))
    }

    #[test]
    fn default_disabled_selection_has_no_session_accepting_operation() {
        assert_eq!(
            BranchExactPendingRuntimeMode::<PHash>::default(),
            BranchExactPendingRuntimeMode::Disabled,
        );
        assert!(matches!(
            ScyllaBranchExactPendingRuntime::<PHash>::select(
                BranchExactPendingRuntimeMode::Disabled,
            ),
            BranchExactPendingRuntimeSelection::Disabled,
        ));
    }

    #[test]
    fn enabled_selection_preserves_exact_writer_authority() {
        let expected = request();
        let BranchExactPendingRuntimeSelection::RequireRecoverable(preparation) =
            ScyllaBranchExactPendingRuntime::<PHash>::select(
                BranchExactPendingRuntimeMode::RequireRecoverable(expected.clone()),
            )
        else {
            panic!("enabled mode must produce a preparation")
        };
        assert_eq!(preparation.request, expected);
    }

    #[test]
    fn stable_sampling_rejects_any_pipeline_writer_or_timestamp_change() {
        assert_eq!(select_stable_sample((1, 2, 3), (1, 2, 3)), Some((1, 2, 3)));
        assert_eq!(select_stable_sample((1, 2, 3), (2, 2, 3)), None);
        assert_eq!(select_stable_sample((1, 2, 3), (1, 3, 3)), None);
        assert_eq!(select_stable_sample((1, 2, 3), (1, 2, 4)), None);
    }

    #[test]
    fn runtime_is_private_and_not_wired_into_setup_or_processor() {
        let module = include_str!("mod.rs");
        assert!(module.contains("mod branch_exact_pending_runtime;"));
        assert!(!module.contains("pub use branch_exact_pending_runtime"));

        let setup = include_str!("../psy_setup.rs");
        assert!(!setup.contains("BranchExactPendingRuntimeMode"));
        assert!(!setup.contains("ScyllaBranchExactPendingRuntime"));

        let common = include_str!(
            "../../../psy_node_common/src/coordinator/processor/db.rs"
        );
        assert!(!common.contains("ScyllaBranchExactPendingRuntime"));
    }

    #[test]
    fn prepare_only_path_never_creates_or_bootstraps_pipeline() {
        let source = include_str!("branch_exact_pending_runtime.rs");
        let prepare = source
            .split("pub(crate) async fn prepare(")
            .nth(1)
            .unwrap()
            .split("impl<Hash: Q256BitHash> ScyllaBranchExactPendingRuntime")
            .next()
            .unwrap();
        assert!(!prepare.contains("create_schema"));
        assert!(!prepare.contains(".bootstrap("));
        assert!(!prepare.contains(".apply("));
        assert!(prepare.contains("ScyllaBranchExactWriterRuntime::prepare_from_ready"));
        assert!(!prepare.contains("ScyllaBranchExactWriterRuntime::prepare("));
        assert!(prepare.contains("runtime.inspect_startup()"));
        let inspect = source
            .split("pub(crate) async fn inspect_startup(")
            .nth(1)
            .unwrap()
            .split("fn require_pipeline")
            .next()
            .unwrap();
        assert!(!inspect.contains("create_schema"));
        assert!(!inspect.contains(".bootstrap("));
        assert!(!inspect.contains(".apply("));
        assert!(inspect.contains("classify_branch_exact_pending_startup"));
    }

    #[test]
    fn queue_seal_is_opaque_outside_the_private_orchestration_module() {
        let source = include_str!("branch_exact_pending_orchestration.rs");
        assert!(source.contains("pub struct VerifiedPendingQueueSeal"));
        assert!(!source.contains("pub enum VerifiedPendingQueueSeal"));
        assert!(source.contains("enum VerifiedPendingQueueSealKind"));
        assert!(source.contains("#[cfg(test)]\n    pub(crate) fn model_work"));
        assert!(source.contains(
            "#[cfg(test)]\n    pub(crate) fn model_stable_empty",
        ));
        assert!(source.contains(
            "#[cfg(test)]\n    pub(crate) fn model<Hash: Q256BitHash>",
        ));
    }
}
