//! G0-04b confinement boundary for representative rollback-aware writes.
//!
//! The production writers are intentionally unchanged. This prototype proves
//! the desired ownership direction: the Scylla session and prepared adapter
//! stay behind the store, while callers can submit only registry-resolved,
//! timestamp-sealed mutations.
//!
//! A business/helper crate cannot obtain the raw driver capability:
//!
//! ```compile_fail
//! use psy_node_scylla::rollback::RollbackableStorePrototype;
//! let store = RollbackableStorePrototype::recording();
//! let _raw = store.raw_session();
//! ```
//!
//! Nor can it use the store as an untyped CQL executor:
//!
//! ```compile_fail
//! use psy_node_scylla::rollback::RollbackableStorePrototype;
//! let store = RollbackableStorePrototype::recording();
//! # async fn misuse(store: RollbackableStorePrototype) {
//! store.query_unpaged("TRUNCATE rollback_authority", &[]).await;
//! # }
//! ```
//!
//! The backend is private and cannot be forged outside this module:
//!
//! ```compile_fail
//! use psy_node_scylla::rollback::RollbackableStorePrototype;
//! let _store = RollbackableStorePrototype { backend: todo!() };
//! ```

use std::{error::Error, fmt, sync::{Arc, Mutex}};

use scylla::{client::session::Session, statement::Consistency};

use super::{
    CheckpointLeafPutBinding, CqlKeyspaceName, GlobalUserMerklePutBinding, PrototypeBindValue,
    MutableSingletonAdapter, MutableSingletonPlanError, MutableSingletonQueryKind,
    ScyllaPhysicalTableId, SealedTimestampedPut, TimestampPrototypeAdapter,
    TimestampPrototypePlanError, TimestampPrototypeQueryId,
    U64SingletonBeforeImage, U64SingletonTransitionPlan,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfinedWriteQueryId {
    TimestampPrototype(TimestampPrototypeQueryId),
    MutableSingleton(MutableSingletonQueryKind),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfinedWriteReceipt {
    physical_table: ScyllaPhysicalTableId,
    query_id: ConfinedWriteQueryId,
    bind_values: Vec<PrototypeBindValue>,
    canonical_mutation: Vec<u8>,
}

impl ConfinedWriteReceipt {
    pub const fn physical_table(&self) -> ScyllaPhysicalTableId {
        self.physical_table
    }

    pub const fn query_id(&self) -> ConfinedWriteQueryId {
        self.query_id
    }

    pub fn bind_values(&self) -> &[PrototypeBindValue] {
        &self.bind_values
    }

    pub fn canonical_mutation(&self) -> &[u8] {
        &self.canonical_mutation
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RollbackableStorePrototypeError {
    TypedPlan(TimestampPrototypePlanError),
    MutableSingletonPlan(MutableSingletonPlanError),
    Driver(String),
    RecordingLockPoisoned,
    NotARecordingStore,
    ExactReadRequiresScylla,
    CheckpointOutOfRange(u64),
}

impl fmt::Display for RollbackableStorePrototypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TypedPlan(error) => error.fmt(f),
            Self::MutableSingletonPlan(error) => error.fmt(f),
            Self::Driver(error) => write!(f, "Scylla prototype adapter failed: {error}"),
            Self::RecordingLockPoisoned => write!(f, "recording prototype lock is poisoned"),
            Self::NotARecordingStore => write!(f, "prepared Scylla stores do not expose an in-memory recording"),
            Self::ExactReadRequiresScylla => write!(f, "exact physical read requires the confined Scylla backend"),
            Self::CheckpointOutOfRange(value) => write!(f, "singleton checkpoint {value} is outside the typed CQL range"),
        }
    }
}

impl Error for RollbackableStorePrototypeError {}

impl From<TimestampPrototypePlanError> for RollbackableStorePrototypeError {
    fn from(value: TimestampPrototypePlanError) -> Self {
        Self::TypedPlan(value)
    }
}

impl From<MutableSingletonPlanError> for RollbackableStorePrototypeError {
    fn from(value: MutableSingletonPlanError) -> Self {
        Self::MutableSingletonPlan(value)
    }
}

struct PrivateScyllaBackend {
    session: Arc<Session>,
    adapter: TimestampPrototypeAdapter,
    mutable_singleton: MutableSingletonAdapter,
}

enum PrivateStoreBackend {
    Recording(Mutex<Vec<ConfinedWriteReceipt>>),
    Scylla(PrivateScyllaBackend),
}

/// Representative rollback-aware store boundary.
///
/// Only the crate-local composition root can inject a raw [`Session`]. Public
/// callers see semantic methods accepting [`SealedTimestampedPut`] and never
/// receive or pass a driver session or a CQL string.
pub struct RollbackableStorePrototype {
    backend: PrivateStoreBackend,
}

impl RollbackableStorePrototype {
    /// Offline backend used by contract tests. It exercises the same typed
    /// bindings as the prepared adapter without requiring a database.
    pub fn recording() -> Self {
        Self { backend: PrivateStoreBackend::Recording(Mutex::new(Vec::new())) }
    }

    /// Future composition-root hook. It is deliberately crate-private and is
    /// not called by production setup in G0-04b.
    #[allow(dead_code)]
    pub(crate) async fn prepare_scylla(
        session: Arc<Session>,
        keyspace: CqlKeyspaceName,
        consistency: Consistency,
    ) -> Result<Self, RollbackableStorePrototypeError> {
        let adapter = TimestampPrototypeAdapter::prepare_with_consistency(&session, keyspace.clone(), consistency)
            .await
            .map_err(|error| RollbackableStorePrototypeError::Driver(error.to_string()))?;
        let mutable_singleton = MutableSingletonAdapter::prepare_with_consistency(&session, keyspace, consistency)
            .await
            .map_err(|error| RollbackableStorePrototypeError::Driver(error.to_string()))?;
        Ok(Self { backend: PrivateStoreBackend::Scylla(PrivateScyllaBackend { session, adapter, mutable_singleton }) })
    }

    pub async fn put_checkpoint_leaf(
        &self,
        sealed: &SealedTimestampedPut,
    ) -> Result<ConfinedWriteReceipt, RollbackableStorePrototypeError> {
        let binding = CheckpointLeafPutBinding::try_from_sealed(sealed)?;
        let receipt = ConfinedWriteReceipt {
            physical_table: ScyllaPhysicalTableId::CheckpointLeaf,
            query_id: ConfinedWriteQueryId::TimestampPrototype(TimestampPrototypeQueryId::CheckpointLeafPut),
            bind_values: binding.bind_values(),
            canonical_mutation: sealed.canonical_bytes().to_vec(),
        };
        match &self.backend {
            PrivateStoreBackend::Recording(_) => self.record(receipt),
            PrivateStoreBackend::Scylla(backend) => {
                backend
                    .adapter
                    .put_checkpoint_leaf(&backend.session, sealed)
                    .await
                    .map_err(|error| RollbackableStorePrototypeError::Driver(error.to_string()))?;
                Ok(receipt)
            }
        }
    }

    pub async fn put_global_user_merkle(
        &self,
        sealed: &SealedTimestampedPut,
    ) -> Result<ConfinedWriteReceipt, RollbackableStorePrototypeError> {
        let binding = GlobalUserMerklePutBinding::try_from_sealed(sealed)?;
        let receipt = ConfinedWriteReceipt {
            physical_table: ScyllaPhysicalTableId::GlobalUserTree,
            query_id: ConfinedWriteQueryId::TimestampPrototype(TimestampPrototypeQueryId::GlobalUserMerklePut),
            bind_values: binding.bind_values(),
            canonical_mutation: sealed.canonical_bytes().to_vec(),
        };
        match &self.backend {
            PrivateStoreBackend::Recording(_) => self.record(receipt),
            PrivateStoreBackend::Scylla(backend) => {
                backend
                    .adapter
                    .put_global_user_merkle(&backend.session, sealed)
                    .await
                    .map_err(|error| RollbackableStorePrototypeError::Driver(error.to_string()))?;
                Ok(receipt)
            }
        }
    }

    /// Exact physical read used by the representative normal-commit verifier.
    /// It intentionally remains behind the same confined backend as writes.
    pub async fn read_global_user_merkle_exact(
        &self,
        sealed: &SealedTimestampedPut,
    ) -> Result<Option<Vec<u8>>, RollbackableStorePrototypeError> {
        GlobalUserMerklePutBinding::try_from_sealed(sealed)?;
        match &self.backend {
            PrivateStoreBackend::Recording(_) => {
                Err(RollbackableStorePrototypeError::ExactReadRequiresScylla)
            }
            PrivateStoreBackend::Scylla(backend) => backend
                .adapter
                .read_global_user_merkle_exact(&backend.session, sealed)
                .await
                .map_err(|error| {
                    RollbackableStorePrototypeError::Driver(error.to_string())
                }),
        }
    }

    pub async fn put_latest_checkpoint(
        &self,
        sealed: &SealedTimestampedPut,
    ) -> Result<ConfinedWriteReceipt, RollbackableStorePrototypeError> {
        let mutation = sealed.resolved().mutation();
        let checkpoint = match (mutation.key(), mutation.operation()) {
            (
                psy_node_core::store::typed::TypedTableKey::U64Singleton(_),
                psy_node_core::store::typed::MutationOperation::Put(
                    psy_node_core::store::typed::MutationValue::CqlU64(value),
                ),
            ) => psy_node_core::store::typed::CheckpointId::try_new(*value)
                .map_err(|_| RollbackableStorePrototypeError::CheckpointOutOfRange(*value))?,
            _ => return Err(MutableSingletonPlanError::WrongTypedKey.into()),
        };
        let before = match &self.backend {
            PrivateStoreBackend::Recording(_) => U64SingletonBeforeImage::Absent,
            PrivateStoreBackend::Scylla(backend) => backend
                .mutable_singleton
                .read_latest_checkpoint(&backend.session)
                .await
                .map_err(|error| RollbackableStorePrototypeError::Driver(error.to_string()))?
                .map_or(U64SingletonBeforeImage::Absent, |value| U64SingletonBeforeImage::Present(value.get())),
        };
        let plan = U64SingletonTransitionPlan::try_for_commit(sealed, checkpoint, before)?;
        let receipt = ConfinedWriteReceipt {
            physical_table: ScyllaPhysicalTableId::U64Singleton,
            query_id: ConfinedWriteQueryId::MutableSingleton(MutableSingletonQueryKind::LatestCheckpointPut),
            bind_values: plan.put().bind_values(),
            canonical_mutation: sealed.canonical_bytes().to_vec(),
        };
        match &self.backend {
            PrivateStoreBackend::Recording(_) => self.record(receipt),
            PrivateStoreBackend::Scylla(backend) => {
                backend
                    .mutable_singleton
                    .put_latest_checkpoint(&backend.session, &plan)
                    .await
                    .map_err(|error| RollbackableStorePrototypeError::Driver(error.to_string()))?;
                Ok(receipt)
            }
        }
    }

    pub async fn read_latest_checkpoint_exact(
        &self,
        sealed: &SealedTimestampedPut,
    ) -> Result<Option<u64>, RollbackableStorePrototypeError> {
        let mutation = sealed.resolved().mutation();
        if !matches!(
            (mutation.physical_table(), mutation.key(), mutation.operation()),
            (
                ScyllaPhysicalTableId::U64Singleton,
                psy_node_core::store::typed::TypedTableKey::U64Singleton(_),
                psy_node_core::store::typed::MutationOperation::Put(
                    psy_node_core::store::typed::MutationValue::CqlU64(_)
                )
            )
        ) {
            return Err(MutableSingletonPlanError::WrongTypedKey.into());
        }
        match &self.backend {
            PrivateStoreBackend::Recording(_) => Err(RollbackableStorePrototypeError::ExactReadRequiresScylla),
            PrivateStoreBackend::Scylla(backend) => backend
                .mutable_singleton
                .read_latest_checkpoint(&backend.session)
                .await
                .map(|value| value.map(|checkpoint| checkpoint.get()))
                .map_err(|error| RollbackableStorePrototypeError::Driver(error.to_string())),
        }
    }

    pub fn recorded_calls(&self) -> Result<Vec<ConfinedWriteReceipt>, RollbackableStorePrototypeError> {
        match &self.backend {
            PrivateStoreBackend::Recording(calls) => calls
                .lock()
                .map(|calls| calls.clone())
                .map_err(|_| RollbackableStorePrototypeError::RecordingLockPoisoned),
            PrivateStoreBackend::Scylla(_) => Err(RollbackableStorePrototypeError::NotARecordingStore),
        }
    }

    fn record(&self, receipt: ConfinedWriteReceipt) -> Result<ConfinedWriteReceipt, RollbackableStorePrototypeError> {
        let PrivateStoreBackend::Recording(calls) = &self.backend else {
            return Err(RollbackableStorePrototypeError::NotARecordingStore);
        };
        calls
            .lock()
            .map_err(|_| RollbackableStorePrototypeError::RecordingLockPoisoned)?
            .push(receipt.clone());
        Ok(receipt)
    }
}
