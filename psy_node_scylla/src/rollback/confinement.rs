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
    CheckpointLeafPutBinding, CheckpointRootPairAdapter,
    CheckpointRootPairPlanError, CheckpointRootPairPutPlan,
    CheckpointRootPairQueryKind, CqlKeyspaceName, GlobalUserMerklePutBinding,
    PrototypeBindValue,
    ImtCursorPutBinding, ImtFamilyAdapter, ImtIndexPutBinding,
    ImtLeafPutBinding, ImtPlanError, ImtQueryKind, MutableSingletonAdapter,
    MutableSingletonPlanError, MutableSingletonQueryKind,
    ScyllaPhysicalTableId, SealedTimestampedPut, SealedTimestampedPutBatch,
    TimestampPrototypeAdapter,
    TimestampPrototypePlanError, TimestampPrototypeQueryId,
    U64SingletonBeforeImage, U64SingletonTransitionPlan,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfinedWriteQueryId {
    TimestampPrototype(TimestampPrototypeQueryId),
    MutableSingleton(MutableSingletonQueryKind),
    CheckpointRootPair(CheckpointRootPairQueryKind),
    Imt(ImtQueryKind),
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
    CheckpointRootPairPlan(CheckpointRootPairPlanError),
    ImtPlan(ImtPlanError),
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
            Self::CheckpointRootPairPlan(error) => error.fmt(f),
            Self::ImtPlan(error) => error.fmt(f),
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

impl From<CheckpointRootPairPlanError> for RollbackableStorePrototypeError {
    fn from(value: CheckpointRootPairPlanError) -> Self {
        Self::CheckpointRootPairPlan(value)
    }
}

impl From<ImtPlanError> for RollbackableStorePrototypeError {
    fn from(value: ImtPlanError) -> Self {
        Self::ImtPlan(value)
    }
}

struct PrivateScyllaBackend {
    session: Arc<Session>,
    adapter: TimestampPrototypeAdapter,
    mutable_singleton: MutableSingletonAdapter,
    checkpoint_root_pair: CheckpointRootPairAdapter,
    imt: ImtFamilyAdapter,
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
        let mutable_singleton = MutableSingletonAdapter::prepare_with_consistency(
            &session,
            keyspace.clone(),
            consistency,
        )
            .await
            .map_err(|error| RollbackableStorePrototypeError::Driver(error.to_string()))?;
        let checkpoint_root_pair = CheckpointRootPairAdapter::prepare_with_consistency(
            &session,
            keyspace.clone(),
            consistency,
        )
        .await
        .map_err(|error| RollbackableStorePrototypeError::Driver(error.to_string()))?;
        let imt = ImtFamilyAdapter::prepare_with_consistency(
            &session,
            keyspace,
            consistency,
        )
        .await
        .map_err(|error| RollbackableStorePrototypeError::Driver(error.to_string()))?;
        Ok(Self { backend: PrivateStoreBackend::Scylla(PrivateScyllaBackend {
            session,
            adapter,
            mutable_singleton,
            checkpoint_root_pair,
            imt,
        }) })
    }

    pub async fn put_imt_leaf(
        &self,
        sealed: &SealedTimestampedPut,
        binding: &ImtLeafPutBinding,
    ) -> Result<ConfinedWriteReceipt, RollbackableStorePrototypeError> {
        if &ImtLeafPutBinding::try_from_sealed(sealed)? != binding {
            return Err(ImtPlanError::DerivedMutationMismatch.into());
        }
        let receipt = ConfinedWriteReceipt {
            physical_table: ScyllaPhysicalTableId::ImtLeaf,
            query_id: ConfinedWriteQueryId::Imt(ImtQueryKind::LeafPut),
            bind_values: binding.bind_values(),
            canonical_mutation: sealed.canonical_bytes().to_vec(),
        };
        match &self.backend {
            PrivateStoreBackend::Recording(_) => self.record(receipt),
            PrivateStoreBackend::Scylla(backend) => {
                backend.imt.put_leaf(&backend.session, binding).await
                    .map_err(|error| RollbackableStorePrototypeError::Driver(error.to_string()))?;
                Ok(receipt)
            }
        }
    }

    pub async fn put_imt_index(
        &self,
        sealed: &SealedTimestampedPut,
        binding: &ImtIndexPutBinding,
    ) -> Result<ConfinedWriteReceipt, RollbackableStorePrototypeError> {
        validate_imt_derived_sealed(sealed, binding.durable_supplement(), binding.write_timestamp_us())?;
        let receipt = ConfinedWriteReceipt {
            physical_table: ScyllaPhysicalTableId::ImtKeyIndex,
            query_id: ConfinedWriteQueryId::Imt(ImtQueryKind::IndexPut),
            bind_values: binding.bind_values(),
            canonical_mutation: sealed.canonical_bytes().to_vec(),
        };
        match &self.backend {
            PrivateStoreBackend::Recording(_) => self.record(receipt),
            PrivateStoreBackend::Scylla(backend) => {
                backend.imt.put_index(&backend.session, binding).await
                    .map_err(|error| RollbackableStorePrototypeError::Driver(error.to_string()))?;
                Ok(receipt)
            }
        }
    }

    pub async fn put_imt_cursor(
        &self,
        sealed: &SealedTimestampedPut,
        binding: &ImtCursorPutBinding,
    ) -> Result<ConfinedWriteReceipt, RollbackableStorePrototypeError> {
        validate_imt_derived_sealed(sealed, binding.durable_supplement(), binding.write_timestamp_us())?;
        let receipt = ConfinedWriteReceipt {
            physical_table: ScyllaPhysicalTableId::ImtNextAppendIndex,
            query_id: ConfinedWriteQueryId::Imt(ImtQueryKind::CursorPut),
            bind_values: binding.bind_values(),
            canonical_mutation: sealed.canonical_bytes().to_vec(),
        };
        match &self.backend {
            PrivateStoreBackend::Recording(_) => self.record(receipt),
            PrivateStoreBackend::Scylla(backend) => {
                backend.imt.put_cursor(&backend.session, binding).await
                    .map_err(|error| RollbackableStorePrototypeError::Driver(error.to_string()))?;
                Ok(receipt)
            }
        }
    }

    pub async fn read_imt_leaf_exact(
        &self,
        binding: &ImtLeafPutBinding,
    ) -> Result<Option<Vec<u8>>, RollbackableStorePrototypeError> {
        match &self.backend {
            PrivateStoreBackend::Recording(_) => Err(RollbackableStorePrototypeError::ExactReadRequiresScylla),
            PrivateStoreBackend::Scylla(backend) => backend.imt.read_leaf_exact(&backend.session, binding).await
                .map_err(|error| RollbackableStorePrototypeError::Driver(error.to_string())),
        }
    }

    pub async fn read_imt_index_exact(
        &self,
        binding: &ImtIndexPutBinding,
    ) -> Result<Option<Vec<u8>>, RollbackableStorePrototypeError> {
        match &self.backend {
            PrivateStoreBackend::Recording(_) => Err(RollbackableStorePrototypeError::ExactReadRequiresScylla),
            PrivateStoreBackend::Scylla(backend) => backend.imt.read_index_exact(&backend.session, binding).await
                .map_err(|error| RollbackableStorePrototypeError::Driver(error.to_string())),
        }
    }

    pub async fn read_imt_cursor_exact(
        &self,
        binding: &ImtCursorPutBinding,
    ) -> Result<Option<Vec<u8>>, RollbackableStorePrototypeError> {
        match &self.backend {
            PrivateStoreBackend::Recording(_) => Err(RollbackableStorePrototypeError::ExactReadRequiresScylla),
            PrivateStoreBackend::Scylla(backend) => backend.imt.read_cursor_exact(&backend.session, binding).await
                .map_err(|error| RollbackableStorePrototypeError::Driver(error.to_string())),
        }
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

    pub async fn put_checkpoint_root_pair(
        &self,
        sealed: &SealedTimestampedPutBatch,
    ) -> Result<Vec<ConfinedWriteReceipt>, RollbackableStorePrototypeError> {
        let plan = CheckpointRootPairPutPlan::try_from_sealed(sealed)?;
        let receipts = vec![
            ConfinedWriteReceipt {
                physical_table: ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK1,
                query_id: ConfinedWriteQueryId::CheckpointRootPair(
                    CheckpointRootPairQueryKind::Put,
                ),
                bind_values: plan.k1_bind_values(),
                canonical_mutation: sealed.members()[0].canonical_bytes().to_vec(),
            },
            ConfinedWriteReceipt {
                physical_table: ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK2,
                query_id: ConfinedWriteQueryId::CheckpointRootPair(
                    CheckpointRootPairQueryKind::Put,
                ),
                bind_values: plan.k2_bind_values(),
                canonical_mutation: sealed.members()[1].canonical_bytes().to_vec(),
            },
        ];
        match &self.backend {
            PrivateStoreBackend::Recording(_) => self.record_many(receipts),
            PrivateStoreBackend::Scylla(backend) => {
                backend
                    .checkpoint_root_pair
                    .put_pair(&backend.session, &plan)
                    .await
                    .map_err(|error| RollbackableStorePrototypeError::Driver(error.to_string()))?;
                Ok(receipts)
            }
        }
    }

    pub async fn read_checkpoint_root_pair_exact(
        &self,
        sealed: &SealedTimestampedPutBatch,
    ) -> Result<[Option<Vec<u8>>; 2], RollbackableStorePrototypeError> {
        let plan = CheckpointRootPairPutPlan::try_from_sealed(sealed)?;
        match &self.backend {
            PrivateStoreBackend::Recording(_) => {
                Err(RollbackableStorePrototypeError::ExactReadRequiresScylla)
            }
            PrivateStoreBackend::Scylla(backend) => backend
                .checkpoint_root_pair
                .read_pair_exact(&backend.session, &plan)
                .await
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

    fn record_many(
        &self,
        receipts: Vec<ConfinedWriteReceipt>,
    ) -> Result<Vec<ConfinedWriteReceipt>, RollbackableStorePrototypeError> {
        let PrivateStoreBackend::Recording(calls) = &self.backend else {
            return Err(RollbackableStorePrototypeError::NotARecordingStore);
        };
        calls
            .lock()
            .map_err(|_| RollbackableStorePrototypeError::RecordingLockPoisoned)?
            .extend(receipts.iter().cloned());
        Ok(receipts)
    }
}

fn validate_imt_derived_sealed(
    sealed: &SealedTimestampedPut,
    mutation: psy_node_core::store::typed::LogicalMutation,
    write_timestamp_us: i64,
) -> Result<(), RollbackableStorePrototypeError> {
    let resolved = super::expand_logical_mutation(mutation).map_err(ImtPlanError::from)?;
    if resolved.len() != 1
        || &resolved[0] != sealed.resolved()
        || sealed.timestamp().as_i64() != write_timestamp_us
    {
        return Err(ImtPlanError::DerivedMutationMismatch.into());
    }
    Ok(())
}
