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
    ScyllaPhysicalTableId, SealedTimestampedPut, TimestampPrototypeAdapter,
    TimestampPrototypePlanError, TimestampPrototypeQueryId,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfinedWriteReceipt {
    physical_table: ScyllaPhysicalTableId,
    query_id: TimestampPrototypeQueryId,
    bind_values: Vec<PrototypeBindValue>,
    canonical_mutation: Vec<u8>,
}

impl ConfinedWriteReceipt {
    pub const fn physical_table(&self) -> ScyllaPhysicalTableId {
        self.physical_table
    }

    pub const fn query_id(&self) -> TimestampPrototypeQueryId {
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
    Driver(String),
    RecordingLockPoisoned,
    NotARecordingStore,
}

impl fmt::Display for RollbackableStorePrototypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TypedPlan(error) => error.fmt(f),
            Self::Driver(error) => write!(f, "Scylla prototype adapter failed: {error}"),
            Self::RecordingLockPoisoned => write!(f, "recording prototype lock is poisoned"),
            Self::NotARecordingStore => write!(f, "prepared Scylla stores do not expose an in-memory recording"),
        }
    }
}

impl Error for RollbackableStorePrototypeError {}

impl From<TimestampPrototypePlanError> for RollbackableStorePrototypeError {
    fn from(value: TimestampPrototypePlanError) -> Self {
        Self::TypedPlan(value)
    }
}

struct PrivateScyllaBackend {
    session: Arc<Session>,
    adapter: TimestampPrototypeAdapter,
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
        let adapter = TimestampPrototypeAdapter::prepare_with_consistency(&session, keyspace, consistency)
            .await
            .map_err(|error| RollbackableStorePrototypeError::Driver(error.to_string()))?;
        Ok(Self { backend: PrivateStoreBackend::Scylla(PrivateScyllaBackend { session, adapter }) })
    }

    pub async fn put_checkpoint_leaf(
        &self,
        sealed: &SealedTimestampedPut,
    ) -> Result<ConfinedWriteReceipt, RollbackableStorePrototypeError> {
        let binding = CheckpointLeafPutBinding::try_from_sealed(sealed)?;
        let receipt = ConfinedWriteReceipt {
            physical_table: ScyllaPhysicalTableId::CheckpointLeaf,
            query_id: TimestampPrototypeQueryId::CheckpointLeafPut,
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
            query_id: TimestampPrototypeQueryId::GlobalUserMerklePut,
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
