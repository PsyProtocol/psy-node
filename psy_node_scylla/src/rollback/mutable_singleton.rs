//! D-02T7 timestamped before/after plans for mutable singleton tables.
//!
//! The latest-info KIV and latest-checkpoint U64 row are restored by writing
//! the target value after the delete fence. They never expose a DELETE plan.
//! The executable adapter remains private until D-04 owns publication order.
//!
//! ```compile_fail
//! use psy_node_scylla::rollback::MutableSingletonAdapter;
//! ```

use std::{error::Error, fmt};

use psy_node_core::store::typed::{
    CheckpointId, LatestInfoSlot, MutationOperation, MutationValue, TypedTableKey,
    U64SingletonSlot,
};
use scylla::{
    client::session::Session,
    statement::{prepared::PreparedStatement, Consistency},
};
use sha2::{Digest, Sha256};

use crate::utils::{i64_to_u64_exact, u64_to_i64_exact};

use super::{
    physical_descriptor, CqlKeyspaceName, PrototypeBindValue,
    ScyllaPhysicalTableId, SealedTimestampedPut, TimestampedWriteKind,
};

const L2_BLOCK_STATE_CANONICAL_LEN: usize = 60;
const AUTHORITY_OBSERVATION_CANONICAL_LEN: usize = 122;
const AUTHORITY_OBSERVATION_MAGIC: &[u8; 8] = b"PSYAUTHO";
const CANONICAL_CHAIN_REF_MAGIC: &[u8; 8] = b"PSYCCREF";
const CODEC_VERSION_V1: u16 = 1;
const CHECKPOINT_HASH_KIND_LAST_CHAIN_HASH: u8 = 1;
const CHECKPOINT_HASH_LEN: u16 = 32;
const AUTHORITY_KIND_REALM: u8 = 2;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum SingletonTransitionKind {
    AuthorityCommit = 1,
    TargetRestore = 2,
    NewBranchCommit = 3,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum MutableSingletonQueryKind {
    LatestInfoPut = 1,
    LatestCheckpointPut = 2,
    LatestCheckpointRead = 3,
    LatestInfoRead = 4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutableSingletonQuery {
    kind: MutableSingletonQueryKind,
    cql: String,
    bind_shape: &'static [&'static str],
}

impl MutableSingletonQuery {
    pub const fn kind(&self) -> MutableSingletonQueryKind { self.kind }
    pub fn cql(&self) -> &str { &self.cql }
    pub const fn bind_shape(&self) -> &'static [&'static str] { self.bind_shape }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutableSingletonQueries {
    latest_info_put: MutableSingletonQuery,
    latest_checkpoint_put: MutableSingletonQuery,
    latest_checkpoint_read: MutableSingletonQuery,
    latest_info_read: MutableSingletonQuery,
}

impl MutableSingletonQueries {
    pub fn new(keyspace: &CqlKeyspaceName) -> Self {
        let latest_info = physical_descriptor(ScyllaPhysicalTableId::LatestInfo).physical_name;
        let latest_checkpoint = physical_descriptor(ScyllaPhysicalTableId::U64Singleton).physical_name;
        Self {
            latest_info_put: MutableSingletonQuery {
                kind: MutableSingletonQueryKind::LatestInfoPut,
                cql: format!("INSERT INTO {}.{latest_info} (obj_id, value) VALUES (?, ?) USING TIMESTAMP ?", keyspace.as_str()),
                bind_shape: &["obj_id:BIGINT", "value:BLOB", "write_timestamp_us:BIGINT"],
            },
            latest_checkpoint_put: MutableSingletonQuery {
                kind: MutableSingletonQueryKind::LatestCheckpointPut,
                cql: format!("INSERT INTO {}.{latest_checkpoint} (obj_id, value) VALUES (?, ?) USING TIMESTAMP ?", keyspace.as_str()),
                bind_shape: &["obj_id:BIGINT", "value:BIGINT", "write_timestamp_us:BIGINT"],
            },
            latest_checkpoint_read: MutableSingletonQuery {
                kind: MutableSingletonQueryKind::LatestCheckpointRead,
                cql: format!("SELECT value, writetime(value) FROM {}.{latest_checkpoint} WHERE obj_id = ?", keyspace.as_str()),
                bind_shape: &["obj_id:BIGINT"],
            },
            latest_info_read: MutableSingletonQuery {
                kind: MutableSingletonQueryKind::LatestInfoRead,
                cql: format!("SELECT value, writetime(value) FROM {}.{latest_info} WHERE obj_id = ?", keyspace.as_str()),
                bind_shape: &["obj_id:BIGINT"],
            },
        }
    }

    pub const fn latest_info_put(&self) -> &MutableSingletonQuery { &self.latest_info_put }
    pub const fn latest_checkpoint_put(&self) -> &MutableSingletonQuery { &self.latest_checkpoint_put }
    pub const fn latest_checkpoint_read(&self) -> &MutableSingletonQuery { &self.latest_checkpoint_read }
    pub const fn latest_info_read(&self) -> &MutableSingletonQuery { &self.latest_info_read }

    pub fn render_golden(&self) -> String {
        let mut output = String::new();
        for query in [self.latest_info_put(), self.latest_checkpoint_put(), self.latest_checkpoint_read(), self.latest_info_read()] {
            output.push_str(&format!("{:?}\n{}\n{}\n", query.kind(), query.cql(), query.bind_shape().join(",")));
        }
        output
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SingletonTransitionDigest([u8; 32]);

impl SingletonTransitionDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LatestInfoBeforeImage {
    Absent,
    Present(Vec<u8>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum U64SingletonBeforeImage {
    Absent,
    Present(u64),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LatestInfoPutBinding {
    slot: LatestInfoSlot,
    checkpoint: CheckpointId,
    canonical_value: Vec<u8>,
    stored_value: Vec<u8>,
    write_timestamp_us: i64,
}

impl LatestInfoPutBinding {
    pub const fn slot(&self) -> LatestInfoSlot { self.slot }
    pub const fn checkpoint(&self) -> CheckpointId { self.checkpoint }
    pub fn canonical_value(&self) -> &[u8] { &self.canonical_value }
    pub fn stored_value(&self) -> &[u8] { &self.stored_value }
    pub const fn write_timestamp_us(&self) -> i64 { self.write_timestamp_us }

    pub fn bind_values(&self) -> Vec<PrototypeBindValue> {
        vec![
            PrototypeBindValue::BigInt(u64_to_i64_exact(self.slot as u8 as u64)),
            PrototypeBindValue::Blob(self.stored_value.clone()),
            PrototypeBindValue::BigInt(self.write_timestamp_us),
        ]
    }

    fn driver_values(&self) -> (i64, &Vec<u8>, i64) {
        (u64_to_i64_exact(self.slot as u8 as u64), &self.stored_value, self.write_timestamp_us)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LatestInfoTransitionPlan {
    kind: SingletonTransitionKind,
    checkpoint: CheckpointId,
    before: LatestInfoBeforeImage,
    put: LatestInfoPutBinding,
    digest: SingletonTransitionDigest,
}

impl LatestInfoTransitionPlan {
    pub fn try_for_commit(
        sealed: &SealedTimestampedPut,
        checkpoint: CheckpointId,
        before: LatestInfoBeforeImage,
    ) -> Result<Self, MutableSingletonPlanError> {
        Self::try_build(sealed, checkpoint, before, SingletonTransitionKind::AuthorityCommit)
    }

    pub fn try_for_restore(
        sealed: &SealedTimestampedPut,
        target: CheckpointId,
        current: Vec<u8>,
    ) -> Result<Self, MutableSingletonPlanError> {
        Self::try_build(
            sealed,
            target,
            LatestInfoBeforeImage::Present(current),
            SingletonTransitionKind::TargetRestore,
        )
    }

    /// Commit a new canonical checkpoint after a rollback fence. This keeps
    /// ordinary monotonic-before-image checks while requiring the
    /// `NewBranchAfterFence` timestamp kind; it is not a target restore.
    pub fn try_for_new_branch_commit(
        sealed: &SealedTimestampedPut,
        checkpoint: CheckpointId,
        before: LatestInfoBeforeImage,
    ) -> Result<Self, MutableSingletonPlanError> {
        Self::try_build(
            sealed,
            checkpoint,
            before,
            SingletonTransitionKind::NewBranchCommit,
        )
    }

    fn try_build(
        sealed: &SealedTimestampedPut,
        checkpoint: CheckpointId,
        before: LatestInfoBeforeImage,
        kind: SingletonTransitionKind,
    ) -> Result<Self, MutableSingletonPlanError> {
        require_write_kind(sealed, kind)?;
        let mutation = sealed.resolved().mutation();
        if mutation.physical_table() != ScyllaPhysicalTableId::LatestInfo {
            return Err(MutableSingletonPlanError::WrongPhysicalTable(mutation.physical_table()));
        }
        let slot = match mutation.key() {
            TypedTableKey::LatestInfo(slot) => *slot,
            _ => return Err(MutableSingletonPlanError::WrongTypedKey),
        };
        if matches!(kind, SingletonTransitionKind::AuthorityCommit | SingletonTransitionKind::NewBranchCommit)
            && slot == LatestInfoSlot::LatestCheckpointTreeRoot
        {
            return Err(MutableSingletonPlanError::ReaderOnlySlotRequiresRestore);
        }
        let canonical_value = match mutation.operation() {
            MutationOperation::Put(MutationValue::PsyCanonicalBytes(value)) => value,
            _ => return Err(MutableSingletonPlanError::ExpectedPsyCanonicalBytes),
        };
        require_after_checkpoint(validate_latest_info_value(slot, canonical_value)?, checkpoint)?;
        match &before {
            LatestInfoBeforeImage::Absent => {
                if kind == SingletonTransitionKind::TargetRestore {
                    return Err(MutableSingletonPlanError::RestoreRequiresBeforeImage);
                }
            }
            LatestInfoBeforeImage::Present(value) => {
                let before_checkpoint = validate_latest_info_value(slot, value)?;
                if matches!(kind, SingletonTransitionKind::AuthorityCommit | SingletonTransitionKind::NewBranchCommit) {
                    require_prior_not_ahead(before_checkpoint, checkpoint)?;
                }
            }
        }
        let stored_value = crate::compression::compress(canonical_value)
            .map_err(|error| MutableSingletonPlanError::ValueCodec(error.to_string()))?;
        let put = LatestInfoPutBinding {
            slot,
            checkpoint,
            canonical_value: canonical_value.clone(),
            stored_value,
            write_timestamp_us: sealed.timestamp().as_i64(),
        };
        let digest = transition_digest(
            ScyllaPhysicalTableId::LatestInfo,
            slot as u8 as u64,
            checkpoint,
            kind,
            before_bytes(&before),
            sealed.canonical_bytes(),
        );
        Ok(Self { kind, checkpoint, before, put, digest })
    }

    pub const fn kind(&self) -> SingletonTransitionKind { self.kind }
    pub const fn checkpoint(&self) -> CheckpointId { self.checkpoint }
    pub const fn before(&self) -> &LatestInfoBeforeImage { &self.before }
    pub const fn put(&self) -> &LatestInfoPutBinding { &self.put }
    pub const fn digest(&self) -> SingletonTransitionDigest { self.digest }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct U64SingletonPutBinding {
    slot: U64SingletonSlot,
    checkpoint: CheckpointId,
    value: u64,
    write_timestamp_us: i64,
}

impl U64SingletonPutBinding {
    pub const fn slot(&self) -> U64SingletonSlot { self.slot }
    pub const fn checkpoint(&self) -> CheckpointId { self.checkpoint }
    pub const fn value(&self) -> u64 { self.value }
    pub const fn write_timestamp_us(&self) -> i64 { self.write_timestamp_us }

    pub fn bind_values(&self) -> Vec<PrototypeBindValue> {
        vec![
            PrototypeBindValue::BigInt(u64_to_i64_exact(self.slot as u8 as u64)),
            PrototypeBindValue::BigInt(u64_to_i64_exact(self.value)),
            PrototypeBindValue::BigInt(self.write_timestamp_us),
        ]
    }

    fn driver_values(&self) -> (i64, i64, i64) {
        (
            u64_to_i64_exact(self.slot as u8 as u64),
            u64_to_i64_exact(self.value),
            self.write_timestamp_us,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct U64SingletonTransitionPlan {
    kind: SingletonTransitionKind,
    checkpoint: CheckpointId,
    before: U64SingletonBeforeImage,
    put: U64SingletonPutBinding,
    digest: SingletonTransitionDigest,
}

impl U64SingletonTransitionPlan {
    pub fn try_for_commit(
        sealed: &SealedTimestampedPut,
        checkpoint: CheckpointId,
        before: U64SingletonBeforeImage,
    ) -> Result<Self, MutableSingletonPlanError> {
        Self::try_build(sealed, checkpoint, before, SingletonTransitionKind::AuthorityCommit)
    }

    pub fn try_for_restore(
        sealed: &SealedTimestampedPut,
        target: CheckpointId,
        current: u64,
    ) -> Result<Self, MutableSingletonPlanError> {
        Self::try_build(
            sealed,
            target,
            U64SingletonBeforeImage::Present(current),
            SingletonTransitionKind::TargetRestore,
        )
    }

    /// Commit a new canonical checkpoint after a rollback fence without
    /// weakening the ordinary monotonic before-image rule.
    pub fn try_for_new_branch_commit(
        sealed: &SealedTimestampedPut,
        checkpoint: CheckpointId,
        before: U64SingletonBeforeImage,
    ) -> Result<Self, MutableSingletonPlanError> {
        Self::try_build(
            sealed,
            checkpoint,
            before,
            SingletonTransitionKind::NewBranchCommit,
        )
    }

    fn try_build(
        sealed: &SealedTimestampedPut,
        checkpoint: CheckpointId,
        before: U64SingletonBeforeImage,
        kind: SingletonTransitionKind,
    ) -> Result<Self, MutableSingletonPlanError> {
        require_write_kind(sealed, kind)?;
        let mutation = sealed.resolved().mutation();
        if mutation.physical_table() != ScyllaPhysicalTableId::U64Singleton {
            return Err(MutableSingletonPlanError::WrongPhysicalTable(mutation.physical_table()));
        }
        let slot = match mutation.key() {
            TypedTableKey::U64Singleton(slot) => *slot,
            _ => return Err(MutableSingletonPlanError::WrongTypedKey),
        };
        let value = match mutation.operation() {
            MutationOperation::Put(MutationValue::CqlU64(value)) => *value,
            _ => return Err(MutableSingletonPlanError::ExpectedCqlU64),
        };
        if value != checkpoint.get() {
            return Err(MutableSingletonPlanError::TargetCheckpointMismatch { expected: checkpoint.get(), actual: value });
        }
        match before {
            U64SingletonBeforeImage::Absent => {
                if kind == SingletonTransitionKind::TargetRestore {
                    return Err(MutableSingletonPlanError::RestoreRequiresBeforeImage);
                }
            }
            U64SingletonBeforeImage::Present(prior) => {
                if matches!(kind, SingletonTransitionKind::AuthorityCommit | SingletonTransitionKind::NewBranchCommit)
                    && prior > checkpoint.get()
                {
                    return Err(MutableSingletonPlanError::PriorCheckpointAhead { prior, candidate: checkpoint.get() });
                }
            }
        }
        let put = U64SingletonPutBinding { slot, checkpoint, value, write_timestamp_us: sealed.timestamp().as_i64() };
        let before_storage;
        let before_bytes = match before {
            U64SingletonBeforeImage::Absent => &[][..],
            U64SingletonBeforeImage::Present(value) => {
                before_storage = value.to_be_bytes();
                &before_storage
            }
        };
        let digest = transition_digest(
            ScyllaPhysicalTableId::U64Singleton,
            slot as u8 as u64,
            checkpoint,
            kind,
            before_bytes,
            sealed.canonical_bytes(),
        );
        Ok(Self { kind, checkpoint, before, put, digest })
    }

    pub const fn kind(&self) -> SingletonTransitionKind { self.kind }
    pub const fn checkpoint(&self) -> CheckpointId { self.checkpoint }
    pub const fn before(&self) -> U64SingletonBeforeImage { self.before }
    pub const fn put(&self) -> &U64SingletonPutBinding { &self.put }
    pub const fn digest(&self) -> SingletonTransitionDigest { self.digest }
}

fn validate_latest_info_value(
    slot: LatestInfoSlot,
    canonical: &[u8],
) -> Result<Option<u64>, MutableSingletonPlanError> {
    match slot {
        LatestInfoSlot::LatestL2BlockState => {
            if canonical.len() != L2_BLOCK_STATE_CANONICAL_LEN {
                return Err(MutableSingletonPlanError::InvalidL2BlockStateLength {
                    actual: canonical.len(),
                });
            }
            Ok(Some(u64::from_le_bytes(
                canonical[0..8].try_into().expect("fixed slice"),
            )))
        }
        LatestInfoSlot::LatestCheckpointTreeRoot => {
            if canonical.len() != 32 {
                return Err(MutableSingletonPlanError::InvalidCheckpointRootLength { actual: canonical.len() });
            }
            Ok(None)
        }
        LatestInfoSlot::RealmAuthorityObservation => {
            validate_realm_observation(canonical).map(Some)
        }
    }
}

fn validate_realm_observation(
    canonical: &[u8],
) -> Result<u64, MutableSingletonPlanError> {
    if canonical.len() != AUTHORITY_OBSERVATION_CANONICAL_LEN {
        return Err(MutableSingletonPlanError::InvalidAuthorityObservationLength {
            actual: canonical.len(),
        });
    }
    if &canonical[0..8] != AUTHORITY_OBSERVATION_MAGIC
        || u16::from_le_bytes(canonical[8..10].try_into().expect("fixed slice"))
            != CODEC_VERSION_V1
        || &canonical[10..18] != CANONICAL_CHAIN_REF_MAGIC
        || u16::from_le_bytes(canonical[18..20].try_into().expect("fixed slice"))
            != CODEC_VERSION_V1
        || canonical[40] != CHECKPOINT_HASH_KIND_LAST_CHAIN_HASH
        || u16::from_le_bytes(canonical[41..43].try_into().expect("fixed slice"))
            != CHECKPOINT_HASH_LEN
    {
        return Err(MutableSingletonPlanError::InvalidAuthorityObservationHeader);
    }
    if canonical[75] != AUTHORITY_KIND_REALM {
        return Err(MutableSingletonPlanError::ExpectedRealmObservation);
    }
    let chain_checkpoint = u64::from_le_bytes(
        canonical[32..40].try_into().expect("fixed slice"),
    );
    let state_checkpoint = u64::from_le_bytes(
        canonical[82..90].try_into().expect("fixed slice"),
    );
    if state_checkpoint > chain_checkpoint {
        return Err(MutableSingletonPlanError::ObservationStateAhead {
            state_checkpoint,
            chain_checkpoint,
        });
    }
    Ok(chain_checkpoint)
}

fn require_after_checkpoint(
    embedded: Option<u64>,
    expected: CheckpointId,
) -> Result<(), MutableSingletonPlanError> {
    if let Some(actual) = embedded {
        if actual != expected.get() {
            return Err(MutableSingletonPlanError::TargetCheckpointMismatch { expected: expected.get(), actual });
        }
    }
    Ok(())
}

fn require_prior_not_ahead(
    embedded: Option<u64>,
    candidate: CheckpointId,
) -> Result<(), MutableSingletonPlanError> {
    if let Some(prior) = embedded {
        if prior > candidate.get() {
            return Err(MutableSingletonPlanError::PriorCheckpointAhead { prior, candidate: candidate.get() });
        }
    }
    Ok(())
}

fn require_write_kind(
    sealed: &SealedTimestampedPut,
    kind: SingletonTransitionKind,
) -> Result<(), MutableSingletonPlanError> {
    let expected = match kind {
        SingletonTransitionKind::AuthorityCommit => TimestampedWriteKind::AuthorityCommit,
        SingletonTransitionKind::TargetRestore => TimestampedWriteKind::NewBranchAfterFence,
        SingletonTransitionKind::NewBranchCommit => TimestampedWriteKind::NewBranchAfterFence,
    };
    if sealed.write_kind() != expected {
        return Err(MutableSingletonPlanError::WrongWriteKind { expected, actual: sealed.write_kind() });
    }
    Ok(())
}

fn before_bytes(before: &LatestInfoBeforeImage) -> &[u8] {
    match before {
        LatestInfoBeforeImage::Absent => &[],
        LatestInfoBeforeImage::Present(value) => value,
    }
}

fn transition_digest(
    table: ScyllaPhysicalTableId,
    slot: u64,
    checkpoint: CheckpointId,
    kind: SingletonTransitionKind,
    before: &[u8],
    sealed: &[u8],
) -> SingletonTransitionDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"psy/mutable-singleton-transition/v1");
    hasher.update([table as u8, kind as u8]);
    hasher.update(slot.to_be_bytes());
    hasher.update(checkpoint.get().to_be_bytes());
    hasher.update((before.len() as u32).to_be_bytes());
    hasher.update(before);
    hasher.update((sealed.len() as u32).to_be_bytes());
    hasher.update(sealed);
    SingletonTransitionDigest(hasher.finalize().into())
}

struct PreparedMutableSingleton {
    latest_info_put: PreparedStatement,
    latest_checkpoint_put: PreparedStatement,
    latest_checkpoint_read: PreparedStatement,
    latest_info_read: PreparedStatement,
}

#[allow(dead_code)]
pub(crate) struct MutableSingletonAdapter {
    queries: MutableSingletonQueries,
    prepared: PreparedMutableSingleton,
}

#[allow(dead_code)]
impl MutableSingletonAdapter {
    pub(crate) async fn prepare_with_consistency(
        session: &Session,
        keyspace: CqlKeyspaceName,
        consistency: Consistency,
    ) -> anyhow::Result<Self> {
        let queries = MutableSingletonQueries::new(&keyspace);
        let prepared = PreparedMutableSingleton {
            latest_info_put: prepare(session, queries.latest_info_put().cql(), consistency).await?,
            latest_checkpoint_put: prepare(session, queries.latest_checkpoint_put().cql(), consistency).await?,
            latest_checkpoint_read: prepare(session, queries.latest_checkpoint_read().cql(), consistency).await?,
            latest_info_read: prepare(session, queries.latest_info_read().cql(), consistency).await?,
        };
        Ok(Self { queries, prepared })
    }

    pub(crate) const fn queries(&self) -> &MutableSingletonQueries { &self.queries }

    pub(crate) async fn put_latest_info(
        &self,
        session: &Session,
        plan: &LatestInfoTransitionPlan,
    ) -> anyhow::Result<()> {
        session.execute_unpaged(&self.prepared.latest_info_put, plan.put.driver_values()).await?;
        Ok(())
    }

    pub(crate) async fn put_latest_checkpoint(
        &self,
        session: &Session,
        plan: &U64SingletonTransitionPlan,
    ) -> anyhow::Result<()> {
        session.execute_unpaged(&self.prepared.latest_checkpoint_put, plan.put.driver_values()).await?;
        Ok(())
    }

    pub(crate) async fn read_latest_checkpoint(
        &self,
        session: &Session,
    ) -> anyhow::Result<Option<CheckpointId>> {
        let result = session
            .execute_unpaged(
                &self.prepared.latest_checkpoint_read,
                (u64_to_i64_exact(U64SingletonSlot::LatestCheckpoint as u8 as u64),),
            )
            .await?;
        let rows = result.into_rows_result()?;
        rows.maybe_first_row::<(i64, Option<i64>)>()?
            .map(|(value, _)| {
                CheckpointId::try_new(i64_to_u64_exact(value))
                    .map_err(anyhow::Error::from)
            })
            .transpose()
    }

    pub(crate) async fn read_latest_checkpoint_exact(
        &self,
        session: &Session,
    ) -> anyhow::Result<Option<(Vec<u8>, i64)>> {
        let result = session
            .execute_unpaged(
                &self.prepared.latest_checkpoint_read,
                (u64_to_i64_exact(U64SingletonSlot::LatestCheckpoint as u8 as u64),),
            )
            .await?;
        let Some((value, writetime)) = result
            .into_rows_result()?
            .maybe_first_row::<(Option<i64>, Option<i64>)>()?
        else {
            return Ok(None);
        };
        let value = value.ok_or_else(|| anyhow::anyhow!("latest checkpoint value is null"))?;
        let writetime = writetime
            .ok_or_else(|| anyhow::anyhow!("latest checkpoint writetime is null"))?;
        Ok(Some((i64_to_u64_exact(value).to_be_bytes().to_vec(), writetime)))
    }

    pub(crate) async fn read_latest_info_exact(
        &self,
        session: &Session,
        slot: LatestInfoSlot,
    ) -> anyhow::Result<Option<(Vec<u8>, i64)>> {
        let result = session
            .execute_unpaged(
                &self.prepared.latest_info_read,
                (u64_to_i64_exact(slot as u8 as u64),),
            )
            .await?;
        let Some((stored, writetime)) = result
            .into_rows_result()?
            .maybe_first_row::<(Option<Vec<u8>>, Option<i64>)>()?
        else {
            return Ok(None);
        };
        let stored = stored.ok_or_else(|| anyhow::anyhow!("latest info value is null"))?;
        let writetime = writetime
            .ok_or_else(|| anyhow::anyhow!("latest info writetime is null"))?;
        Ok(Some((crate::compression::decompress(&stored)?, writetime)))
    }

    pub(crate) async fn read_exact(
        &self,
        session: &Session,
        sealed: &SealedTimestampedPut,
    ) -> anyhow::Result<Option<(Vec<u8>, i64)>> {
        match (
            sealed.resolved().mutation().physical_table(),
            sealed.resolved().mutation().key(),
        ) {
            (
                ScyllaPhysicalTableId::U64Singleton,
                TypedTableKey::U64Singleton(U64SingletonSlot::LatestCheckpoint),
            ) => self.read_latest_checkpoint_exact(session).await,
            (
                ScyllaPhysicalTableId::LatestInfo,
                TypedTableKey::LatestInfo(slot),
            ) => self.read_latest_info_exact(session, *slot).await,
            _ => anyhow::bail!("sealed mutation is not a supported mutable singleton"),
        }
    }

    pub(crate) async fn read_exact_physical(
        &self,
        session: &Session,
        sealed: &SealedTimestampedPut,
    ) -> anyhow::Result<Option<(Vec<u8>, i64)>> {
        match (
            sealed.resolved().mutation().physical_table(),
            sealed.resolved().mutation().key(),
        ) {
            (
                ScyllaPhysicalTableId::U64Singleton,
                TypedTableKey::U64Singleton(U64SingletonSlot::LatestCheckpoint),
            ) => self.read_latest_checkpoint_exact(session).await,
            (
                ScyllaPhysicalTableId::LatestInfo,
                TypedTableKey::LatestInfo(slot),
            ) => {
                let result = session
                    .execute_unpaged(
                        &self.prepared.latest_info_read,
                        (u64_to_i64_exact(*slot as u8 as u64),),
                    )
                    .await?;
                let Some((stored, writetime)) = result
                    .into_rows_result()?
                    .maybe_first_row::<(Option<Vec<u8>>, Option<i64>)>()?
                else {
                    return Ok(None);
                };
                Ok(Some((
                    stored.ok_or_else(|| anyhow::anyhow!("latest info value is null"))?,
                    writetime.ok_or_else(|| anyhow::anyhow!("latest info writetime is null"))?,
                )))
            }
            _ => anyhow::bail!("sealed mutation is not a supported mutable singleton"),
        }
    }
}

async fn prepare(
    session: &Session,
    cql: &str,
    consistency: Consistency,
) -> anyhow::Result<PreparedStatement> {
    let mut statement = session.prepare(cql).await?;
    statement.set_consistency(consistency);
    statement.set_is_idempotent(true);
    Ok(statement)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MutableSingletonPlanError {
    WrongPhysicalTable(ScyllaPhysicalTableId),
    WrongTypedKey,
    ExpectedPsyCanonicalBytes,
    ExpectedCqlU64,
    WrongWriteKind { expected: TimestampedWriteKind, actual: TimestampedWriteKind },
    ReaderOnlySlotRequiresRestore,
    RestoreRequiresBeforeImage,
    InvalidL2BlockStateLength { actual: usize },
    InvalidCheckpointRootLength { actual: usize },
    InvalidAuthorityObservationLength { actual: usize },
    InvalidAuthorityObservationHeader,
    TargetCheckpointMismatch { expected: u64, actual: u64 },
    PriorCheckpointAhead { prior: u64, candidate: u64 },
    ExpectedRealmObservation,
    ObservationStateAhead { state_checkpoint: u64, chain_checkpoint: u64 },
    ValueCodec(String),
}

impl fmt::Display for MutableSingletonPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "mutable singleton plan rejected: {self:?}")
    }
}

impl Error for MutableSingletonPlanError {}
