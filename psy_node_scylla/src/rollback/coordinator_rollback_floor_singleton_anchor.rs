//! Immutable values required to restore a non-genesis Coordinator rollback floor.
//!
//! A floor row commits only chain identity. This companion row captures the
//! exact latest-L2 bytes and latest-checkpoint value while the canonical head
//! is still the activation floor. It is append-only evidence: there is no
//! hot-state write, delete, barrier, or canonical-head mutation API here.

use std::{error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::{
    protocol::canonical_chain::NetworkId,
    v1::qdata::checkpoint::QEDL2BlockState,
};
use psy_node_core::store::{
    canonical_head::StoredCanonicalHead,
    coordinator_commit_source::CoordinatorRollbackFloor,
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
use scylla::{
    client::session::Session,
    statement::{prepared::PreparedStatement, Consistency, SerialConsistency},
};
use sha2::{Digest, Sha256};

use super::{
    CanonicalHeadNoTabletKeyspace, CoordinatorCommitPhysicalSourceCell,
    CqlKeyspaceName,
};

pub(crate) const COORDINATOR_ROLLBACK_FLOOR_SINGLETON_ANCHOR_TABLE: &str =
    "coordinator_rollback_floor_singleton_anchor_v1";
const MAGIC: &[u8; 8] = b"PSYCRFA1";
const VERSION: u16 = 1;
const ROW_REVISION: i64 = 1;
const DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.coordinator-floor-singleton-anchor.v1\0";
const MAX_ANCHOR_BYTES: usize = 32 * 1024;
const MAX_L2_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CoordinatorRollbackFloorSingletonAnchor<Hash> {
    floor: CoordinatorRollbackFloor<Hash>,
    latest_l2_stored_value: Vec<u8>,
    latest_l2_writetime_us: i64,
    target_l2_writetime_us: i64,
    latest_checkpoint: u64,
    latest_checkpoint_writetime_us: i64,
    digest: [u8; 32],
    canonical_bytes: Vec<u8>,
}

impl<Hash: Q256BitHash> CoordinatorRollbackFloorSingletonAnchor<Hash> {
    pub(crate) fn try_new(
        floor: CoordinatorRollbackFloor<Hash>,
        latest_l2: &CoordinatorCommitPhysicalSourceCell,
        target_l2: &CoordinatorCommitPhysicalSourceCell,
        latest_checkpoint: &CoordinatorCommitPhysicalSourceCell,
    ) -> Result<Self, CoordinatorRollbackFloorSingletonAnchorError> {
        if latest_l2.bytes() != target_l2.bytes() {
            return Err(
                CoordinatorRollbackFloorSingletonAnchorError::LatestL2TargetMismatch,
            );
        }
        let l2 = decode_l2(latest_l2.bytes())?;
        let checkpoint = decode_checkpoint(latest_checkpoint.bytes())?;
        let floor_checkpoint = floor.floor().checkpoint().checkpoint_id().get();
        if l2.checkpoint_id != floor_checkpoint || checkpoint != floor_checkpoint {
            return Err(
                CoordinatorRollbackFloorSingletonAnchorError::CheckpointMismatch,
            );
        }
        let mut anchor = Self {
            floor,
            latest_l2_stored_value: latest_l2.bytes().to_vec(),
            latest_l2_writetime_us: latest_l2.writetime_us(),
            target_l2_writetime_us: target_l2.writetime_us(),
            latest_checkpoint: checkpoint,
            latest_checkpoint_writetime_us: latest_checkpoint.writetime_us(),
            digest: [0; 32],
            canonical_bytes: Vec::new(),
        };
        let commitment = anchor.encode_without_digest()?;
        anchor.digest = anchor_digest(&commitment);
        anchor.canonical_bytes = commitment;
        anchor.canonical_bytes.extend_from_slice(&anchor.digest);
        if anchor.canonical_bytes.len() > MAX_ANCHOR_BYTES {
            return Err(CoordinatorRollbackFloorSingletonAnchorError::PayloadTooLarge);
        }
        Ok(anchor)
    }

    pub(crate) fn decode_persisted(
        network: NetworkId,
        chain_epoch: u64,
        row_revision: i64,
        bytes: &[u8],
    ) -> Result<Self, CoordinatorRollbackFloorSingletonAnchorError> {
        if row_revision != ROW_REVISION {
            return Err(
                CoordinatorRollbackFloorSingletonAnchorError::InvalidRowRevision(
                    row_revision,
                ),
            );
        }
        if bytes.len() > MAX_ANCHOR_BYTES {
            return Err(CoordinatorRollbackFloorSingletonAnchorError::PayloadTooLarge);
        }
        let mut cursor = AnchorCursor::new(bytes);
        if cursor.take(8)? != MAGIC {
            return Err(CoordinatorRollbackFloorSingletonAnchorError::InvalidMagic);
        }
        let version = cursor.u16()?;
        if version != VERSION {
            return Err(
                CoordinatorRollbackFloorSingletonAnchorError::UnknownVersion(version),
            );
        }
        let floor_bytes = cursor.bytes()?.to_vec();
        let floor = CoordinatorRollbackFloor::decode_persisted(
            network,
            chain_epoch,
            ROW_REVISION,
            &floor_bytes,
        )
        .map_err(|error| {
            CoordinatorRollbackFloorSingletonAnchorError::Floor(error.to_string())
        })?;
        let latest_l2_stored_value = cursor.bytes()?.to_vec();
        let latest_l2_writetime_us = cursor.i64()?;
        let target_l2_writetime_us = cursor.i64()?;
        let latest_checkpoint = cursor.u64()?;
        let latest_checkpoint_writetime_us = cursor.i64()?;
        let digest = cursor.array_32()?;
        if !cursor.is_empty() {
            return Err(CoordinatorRollbackFloorSingletonAnchorError::TrailingBytes);
        }
        if digest == [0; 32]
            || decode_l2(&latest_l2_stored_value)?.checkpoint_id
                != latest_checkpoint
            || floor.floor().checkpoint().checkpoint_id().get()
                != latest_checkpoint
        {
            return Err(CoordinatorRollbackFloorSingletonAnchorError::CheckpointMismatch);
        }
        if bytes.len() < 32 || anchor_digest(&bytes[..bytes.len() - 32]) != digest {
            return Err(CoordinatorRollbackFloorSingletonAnchorError::DigestMismatch);
        }
        let decoded = Self {
            floor,
            latest_l2_stored_value,
            latest_l2_writetime_us,
            target_l2_writetime_us,
            latest_checkpoint,
            latest_checkpoint_writetime_us,
            digest,
            canonical_bytes: bytes.to_vec(),
        };
        if decoded.encode_without_digest()? != bytes[..bytes.len() - 32] {
            return Err(
                CoordinatorRollbackFloorSingletonAnchorError::NonCanonicalEncoding,
            );
        }
        Ok(decoded)
    }

    pub(crate) fn validate_floor(
        &self,
        floor: &CoordinatorRollbackFloor<Hash>,
    ) -> Result<(), CoordinatorRollbackFloorSingletonAnchorError> {
        if &self.floor != floor {
            return Err(CoordinatorRollbackFloorSingletonAnchorError::FloorMismatch);
        }
        Ok(())
    }

    pub(crate) fn validate_target_l2(
        &self,
        target_l2: &CoordinatorCommitPhysicalSourceCell,
    ) -> Result<(), CoordinatorRollbackFloorSingletonAnchorError> {
        if target_l2.bytes() != self.latest_l2_stored_value
            || target_l2.writetime_us() != self.target_l2_writetime_us
        {
            return Err(
                CoordinatorRollbackFloorSingletonAnchorError::TargetL2Changed,
            );
        }
        Ok(())
    }

    pub(crate) const fn floor(&self) -> &CoordinatorRollbackFloor<Hash> {
        &self.floor
    }

    pub(crate) fn latest_l2_stored_value(&self) -> &[u8] {
        &self.latest_l2_stored_value
    }

    pub(crate) const fn target_l2_writetime_us(&self) -> i64 {
        self.target_l2_writetime_us
    }

    pub(crate) const fn latest_checkpoint(&self) -> u64 {
        self.latest_checkpoint
    }

    pub(crate) const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    fn encode_without_digest(
        &self,
    ) -> Result<Vec<u8>, CoordinatorRollbackFloorSingletonAnchorError> {
        if self.latest_l2_stored_value.is_empty()
            || self.latest_l2_stored_value.len() > MAX_L2_BYTES
        {
            return Err(CoordinatorRollbackFloorSingletonAnchorError::InvalidL2);
        }
        let floor_bytes = self.floor.encode_canonical();
        let mut bytes = Vec::with_capacity(
            96 + floor_bytes.len() + self.latest_l2_stored_value.len(),
        );
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        encode_bytes(&mut bytes, &floor_bytes)?;
        encode_bytes(&mut bytes, &self.latest_l2_stored_value)?;
        bytes.extend_from_slice(&self.latest_l2_writetime_us.to_be_bytes());
        bytes.extend_from_slice(&self.target_l2_writetime_us.to_be_bytes());
        bytes.extend_from_slice(&self.latest_checkpoint.to_be_bytes());
        bytes.extend_from_slice(&self.latest_checkpoint_writetime_us.to_be_bytes());
        Ok(bytes)
    }

    fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CoordinatorRollbackFloorSingletonAnchorQueries {
    create_anchor: String,
    read_anchor: String,
    insert_anchor: String,
    read_latest_l2: String,
    read_target_l2: String,
    read_latest_checkpoint: String,
}

impl CoordinatorRollbackFloorSingletonAnchorQueries {
    pub(crate) fn new(
        control: &CanonicalHeadNoTabletKeyspace,
        state: &CqlKeyspaceName,
    ) -> Self {
        let anchor = format!(
            "{}.{}",
            control.as_str(),
            COORDINATOR_ROLLBACK_FLOOR_SINGLETON_ANCHOR_TABLE
        );
        Self {
            create_anchor: format!(
                "CREATE TABLE IF NOT EXISTS {anchor} (network_chain_id bigint, chain_epoch bigint, revision bigint, anchor blob, PRIMARY KEY ((network_chain_id, chain_epoch)))"
            ),
            read_anchor: format!(
                "SELECT revision, anchor FROM {anchor} WHERE network_chain_id = ? AND chain_epoch = ?"
            ),
            insert_anchor: format!(
                "INSERT INTO {anchor} (network_chain_id, chain_epoch, revision, anchor) VALUES (?, ?, ?, ?) IF NOT EXISTS"
            ),
            read_latest_l2: format!(
                "SELECT value, WRITETIME(value) FROM {}.latest_info_table WHERE obj_id = ?",
                state.as_str()
            ),
            read_target_l2: format!(
                "SELECT value, WRITETIME(value) FROM {}.l2_block_state_table WHERE obj_id = ?",
                state.as_str()
            ),
            read_latest_checkpoint: format!(
                "SELECT value, WRITETIME(value) FROM {}.u64_singleton_table WHERE obj_id = ?",
                state.as_str()
            ),
        }
    }
}

pub(crate) struct ScyllaCoordinatorRollbackFloorSingletonAnchorStore {
    session: Arc<Session>,
    read_anchor: PreparedStatement,
    insert_anchor: PreparedStatement,
    read_latest_l2: PreparedStatement,
    read_target_l2: PreparedStatement,
    read_latest_checkpoint: PreparedStatement,
}

impl ScyllaCoordinatorRollbackFloorSingletonAnchorStore {
    pub(crate) async fn create_schema(
        session: &Session,
        control: &CanonicalHeadNoTabletKeyspace,
        state: &CqlKeyspaceName,
    ) -> Result<(), CoordinatorRollbackFloorSingletonAnchorStoreError> {
        let queries = CoordinatorRollbackFloorSingletonAnchorQueries::new(control, state);
        session
            .query_unpaged(queries.create_anchor, &[])
            .await
            .map_err(driver)?;
        session.await_schema_agreement().await.map_err(driver)?;
        Ok(())
    }

    pub(crate) async fn prepare(
        session: Arc<Session>,
        control: CanonicalHeadNoTabletKeyspace,
        state: CqlKeyspaceName,
    ) -> Result<Self, CoordinatorRollbackFloorSingletonAnchorStoreError> {
        let queries = CoordinatorRollbackFloorSingletonAnchorQueries::new(&control, &state);
        Ok(Self {
            read_anchor: prepare_regular(&session, &queries.read_anchor).await?,
            insert_anchor: prepare_lwt(&session, &queries.insert_anchor).await?,
            read_latest_l2: prepare_regular(&session, &queries.read_latest_l2).await?,
            read_target_l2: prepare_regular(&session, &queries.read_target_l2).await?,
            read_latest_checkpoint: prepare_regular(
                &session,
                &queries.read_latest_checkpoint,
            )
            .await?,
            session,
        })
    }

    pub(crate) async fn ensure<Hash: Q256BitHash>(
        &self,
        current: &StoredCanonicalHead<Hash>,
        floor: &CoordinatorRollbackFloor<Hash>,
    ) -> Result<CoordinatorRollbackFloorSingletonAnchor<Hash>, CoordinatorRollbackFloorSingletonAnchorStoreError>
    {
        floor
            .validate_current_head(current)
            .map_err(|error| {
                CoordinatorRollbackFloorSingletonAnchorStoreError::Floor(
                    error.to_string(),
                )
            })?;
        if let Some(anchor) = self
            .read(floor.floor().network_id(), floor.floor().chain_epoch().get())
            .await?
        {
            anchor.validate_floor(floor)?;
            let target = self.read_target_l2(floor).await?;
            anchor.validate_target_l2(&target)?;
            return Ok(anchor);
        }
        if !current.rollback_control().is_idle()
            || current.canonical_ref() != floor.floor()
            || current.revision().get() != floor.activation_head_revision()
        {
            return Err(
                CoordinatorRollbackFloorSingletonAnchorStoreError::MissingAfterHeadAdvanced,
            );
        }
        let source_before = self.read_activation_sources(floor).await?;
        let expected = CoordinatorRollbackFloorSingletonAnchor::try_new(
            *floor,
            &source_before.latest_l2,
            &source_before.target_l2,
            &source_before.latest_checkpoint,
        )?;
        let key = floor_key(floor)?;
        let execution = self
            .session
            .execute_unpaged(
                &self.insert_anchor,
                (
                    key.0,
                    key.1,
                    ROW_REVISION,
                    expected.canonical_bytes(),
                ),
            )
            .await;
        if let Err(error) = execution {
            match self
                .read(floor.floor().network_id(), floor.floor().chain_epoch().get())
                .await
            {
                Ok(Some(current)) if current == expected => {}
                Ok(Some(_)) => {
                    return Err(
                        CoordinatorRollbackFloorSingletonAnchorStoreError::Conflict,
                    );
                }
                Ok(None) => {
                    return Err(
                        CoordinatorRollbackFloorSingletonAnchorStoreError::IndeterminateWrite(
                            error.to_string(),
                        ),
                    );
                }
                Err(read) => {
                    return Err(
                        CoordinatorRollbackFloorSingletonAnchorStoreError::IndeterminateWrite(
                            format!("execute={error}; read={read}"),
                        ),
                    );
                }
            }
        }
        let persisted = self
            .read(floor.floor().network_id(), floor.floor().chain_epoch().get())
            .await?
            .ok_or(
                CoordinatorRollbackFloorSingletonAnchorStoreError::MissingAfterWrite,
            )?;
        if persisted != expected {
            return Err(CoordinatorRollbackFloorSingletonAnchorStoreError::Conflict);
        }
        let source_after = self.read_activation_sources(floor).await?;
        let rebuilt = CoordinatorRollbackFloorSingletonAnchor::try_new(
            *floor,
            &source_after.latest_l2,
            &source_after.target_l2,
            &source_after.latest_checkpoint,
        )?;
        if rebuilt != expected {
            return Err(
                CoordinatorRollbackFloorSingletonAnchorStoreError::SourceChanged,
            );
        }
        Ok(persisted)
    }

    pub(crate) async fn read<Hash: Q256BitHash>(
        &self,
        network: NetworkId,
        chain_epoch: u64,
    ) -> Result<Option<CoordinatorRollbackFloorSingletonAnchor<Hash>>, CoordinatorRollbackFloorSingletonAnchorStoreError>
    {
        let row = self
            .session
            .execute_unpaged(
                &self.read_anchor,
                (i64::from(network.chain_id()), to_i64(chain_epoch)?),
            )
            .await
            .map_err(driver)?
            .into_rows_result()
            .map_err(driver)?
            .maybe_first_row::<(i64, Vec<u8>)>()
            .map_err(driver)?;
        row.map(|(revision, bytes)| {
            CoordinatorRollbackFloorSingletonAnchor::decode_persisted(
                network,
                chain_epoch,
                revision,
                &bytes,
            )
            .map_err(Into::into)
        })
        .transpose()
    }

    async fn read_activation_sources<Hash: Q256BitHash>(
        &self,
        floor: &CoordinatorRollbackFloor<Hash>,
    ) -> Result<FloorSingletonSourceObservation, CoordinatorRollbackFloorSingletonAnchorStoreError>
    {
        Ok(FloorSingletonSourceObservation {
            latest_l2: read_blob(&self.session, &self.read_latest_l2, 1).await?,
            target_l2: self.read_target_l2(floor).await?,
            latest_checkpoint: read_bigint(
                &self.session,
                &self.read_latest_checkpoint,
                1,
            )
            .await?,
        })
    }

    async fn read_target_l2<Hash: Q256BitHash>(
        &self,
        floor: &CoordinatorRollbackFloor<Hash>,
    ) -> Result<CoordinatorCommitPhysicalSourceCell, CoordinatorRollbackFloorSingletonAnchorStoreError>
    {
        let checkpoint = to_i64(floor.floor().checkpoint().checkpoint_id().get())?;
        read_blob(&self.session, &self.read_target_l2, checkpoint).await
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FloorSingletonSourceObservation {
    latest_l2: CoordinatorCommitPhysicalSourceCell,
    target_l2: CoordinatorCommitPhysicalSourceCell,
    latest_checkpoint: CoordinatorCommitPhysicalSourceCell,
}

fn decode_l2(
    stored: &[u8],
) -> Result<QEDL2BlockState, CoordinatorRollbackFloorSingletonAnchorError> {
    if stored.is_empty() || stored.len() > MAX_L2_BYTES {
        return Err(CoordinatorRollbackFloorSingletonAnchorError::InvalidL2);
    }
    let canonical = crate::compression::decompress(stored).map_err(|error| {
        CoordinatorRollbackFloorSingletonAnchorError::L2(error.to_string())
    })?;
    let decoded = QEDL2BlockState::psy_ser_from_owned_bytes_vec(canonical.clone())
        .map_err(|error| {
            CoordinatorRollbackFloorSingletonAnchorError::L2(error.to_string())
        })?;
    if decoded.psy_ser_to_bytes_vec().map_err(|error| {
        CoordinatorRollbackFloorSingletonAnchorError::L2(error.to_string())
    })? != canonical
    {
        return Err(
            CoordinatorRollbackFloorSingletonAnchorError::NonCanonicalL2,
        );
    }
    Ok(decoded)
}

fn decode_checkpoint(
    bytes: &[u8],
) -> Result<u64, CoordinatorRollbackFloorSingletonAnchorError> {
    let encoded: [u8; 8] = bytes.try_into().map_err(|_| {
        CoordinatorRollbackFloorSingletonAnchorError::InvalidCheckpoint
    })?;
    let value = i64::from_be_bytes(encoded);
    u64::try_from(value).map_err(|_| {
        CoordinatorRollbackFloorSingletonAnchorError::InvalidCheckpoint
    })
}

async fn read_blob(
    session: &Session,
    statement: &PreparedStatement,
    key: i64,
) -> Result<CoordinatorCommitPhysicalSourceCell, CoordinatorRollbackFloorSingletonAnchorStoreError>
{
    let row = session
        .execute_unpaged(statement, (key,))
        .await
        .map_err(driver)?
        .into_rows_result()
        .map_err(driver)?
        .maybe_first_row::<(Option<Vec<u8>>, Option<i64>)>()
        .map_err(driver)?
        .ok_or(CoordinatorRollbackFloorSingletonAnchorStoreError::MissingSource)?;
    Ok(CoordinatorCommitPhysicalSourceCell::value(
        row.0
            .ok_or(CoordinatorRollbackFloorSingletonAnchorStoreError::MissingSource)?,
        row.1
            .ok_or(CoordinatorRollbackFloorSingletonAnchorStoreError::MissingSource)?,
    ))
}

async fn read_bigint(
    session: &Session,
    statement: &PreparedStatement,
    key: i64,
) -> Result<CoordinatorCommitPhysicalSourceCell, CoordinatorRollbackFloorSingletonAnchorStoreError>
{
    let row = session
        .execute_unpaged(statement, (key,))
        .await
        .map_err(driver)?
        .into_rows_result()
        .map_err(driver)?
        .maybe_first_row::<(Option<i64>, Option<i64>)>()
        .map_err(driver)?
        .ok_or(CoordinatorRollbackFloorSingletonAnchorStoreError::MissingSource)?;
    Ok(CoordinatorCommitPhysicalSourceCell::value(
        row.0
            .ok_or(CoordinatorRollbackFloorSingletonAnchorStoreError::MissingSource)?
            .to_be_bytes()
            .to_vec(),
        row.1
            .ok_or(CoordinatorRollbackFloorSingletonAnchorStoreError::MissingSource)?,
    ))
}

fn floor_key<Hash: Q256BitHash>(
    floor: &CoordinatorRollbackFloor<Hash>,
) -> Result<(i64, i64), CoordinatorRollbackFloorSingletonAnchorStoreError> {
    Ok((
        i64::from(floor.floor().network_id().chain_id()),
        to_i64(floor.floor().chain_epoch().get())?,
    ))
}

fn to_i64(value: u64) -> Result<i64, CoordinatorRollbackFloorSingletonAnchorStoreError> {
    i64::try_from(value).map_err(|_| {
        CoordinatorRollbackFloorSingletonAnchorStoreError::IntegerOutOfRange
    })
}

fn encode_bytes(
    output: &mut Vec<u8>,
    bytes: &[u8],
) -> Result<(), CoordinatorRollbackFloorSingletonAnchorError> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| CoordinatorRollbackFloorSingletonAnchorError::PayloadTooLarge)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn anchor_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update(bytes);
    hasher.finalize().into()
}

async fn prepare_regular(
    session: &Session,
    query: &str,
) -> Result<PreparedStatement, CoordinatorRollbackFloorSingletonAnchorStoreError> {
    let mut statement = session.prepare(query).await.map_err(driver)?;
    statement.set_consistency(Consistency::Quorum);
    Ok(statement)
}

async fn prepare_lwt(
    session: &Session,
    query: &str,
) -> Result<PreparedStatement, CoordinatorRollbackFloorSingletonAnchorStoreError> {
    let mut statement = prepare_regular(session, query).await?;
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    Ok(statement)
}

fn driver(error: impl ToString) -> CoordinatorRollbackFloorSingletonAnchorStoreError {
    CoordinatorRollbackFloorSingletonAnchorStoreError::Driver(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CoordinatorRollbackFloorSingletonAnchorError {
    InvalidRowRevision(i64),
    InvalidMagic,
    UnknownVersion(u16),
    PayloadTooLarge,
    InvalidL2,
    L2(String),
    NonCanonicalL2,
    InvalidCheckpoint,
    LatestL2TargetMismatch,
    CheckpointMismatch,
    Floor(String),
    FloorMismatch,
    TargetL2Changed,
    DigestMismatch,
    NonCanonicalEncoding,
    Truncated,
    TrailingBytes,
}

impl fmt::Display for CoordinatorRollbackFloorSingletonAnchorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Coordinator rollback floor singleton anchor error: {self:?}")
    }
}

impl Error for CoordinatorRollbackFloorSingletonAnchorError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CoordinatorRollbackFloorSingletonAnchorStoreError {
    Driver(String),
    Anchor(CoordinatorRollbackFloorSingletonAnchorError),
    Floor(String),
    IntegerOutOfRange,
    MissingSource,
    MissingAfterHeadAdvanced,
    MissingAfterWrite,
    Conflict,
    SourceChanged,
    IndeterminateWrite(String),
}

impl From<CoordinatorRollbackFloorSingletonAnchorError>
    for CoordinatorRollbackFloorSingletonAnchorStoreError
{
    fn from(error: CoordinatorRollbackFloorSingletonAnchorError) -> Self {
        Self::Anchor(error)
    }
}

impl fmt::Display for CoordinatorRollbackFloorSingletonAnchorStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Coordinator rollback floor singleton anchor store error: {self:?}")
    }
}

impl Error for CoordinatorRollbackFloorSingletonAnchorStoreError {}

struct AnchorCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> AnchorCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], CoordinatorRollbackFloorSingletonAnchorError> {
        let end = self.offset.checked_add(length).ok_or(
            CoordinatorRollbackFloorSingletonAnchorError::Truncated,
        )?;
        let value = self.bytes.get(self.offset..end).ok_or(
            CoordinatorRollbackFloorSingletonAnchorError::Truncated,
        )?;
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, CoordinatorRollbackFloorSingletonAnchorError> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("fixed length"),
        ))
    }

    fn u32(&mut self) -> Result<u32, CoordinatorRollbackFloorSingletonAnchorError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("fixed length"),
        ))
    }

    fn u64(&mut self) -> Result<u64, CoordinatorRollbackFloorSingletonAnchorError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("fixed length"),
        ))
    }

    fn i64(&mut self) -> Result<i64, CoordinatorRollbackFloorSingletonAnchorError> {
        Ok(i64::from_be_bytes(
            self.take(8)?.try_into().expect("fixed length"),
        ))
    }

    fn bytes(&mut self) -> Result<&'a [u8], CoordinatorRollbackFloorSingletonAnchorError> {
        let length = self.u32()? as usize;
        self.take(length)
    }

    fn array_32(&mut self) -> Result<[u8; 32], CoordinatorRollbackFloorSingletonAnchorError> {
        Ok(self.take(32)?.try_into().expect("fixed length"))
    }

    const fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use parth_core::PHash;
    use psy_data::{
        protocol::canonical_chain::{
            CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
            CheckpointRef, NetworkId,
        },
        v1::qdata::checkpoint::QEDL2BlockState,
    };
    use psy_node_core::store::{
        canonical_head::StoredCanonicalHead,
        coordinator_commit_source::CoordinatorRollbackFloor,
        rollback_control::RollbackControlState,
    };
    use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

    use super::*;

    fn canonical(checkpoint: u64) -> CanonicalChainRef<PHash> {
        CanonicalChainRef::new(
            NetworkId::try_from_chain_id(1337).unwrap(),
            ChainEpoch::new(6),
            CheckpointRef::new(
                CheckpointId::new(checkpoint),
                CheckpointHash::from_last_chain_hash(PHash::from_owned_32bytes([7; 32])),
            ),
        )
    }

    fn head(checkpoint: u64) -> StoredCanonicalHead<PHash> {
        let canonical = canonical(checkpoint);
        StoredCanonicalHead::decode_persisted(
            canonical.network_id(),
            11,
            &canonical.to_canonical_bytes(),
            &RollbackControlState::<PHash>::Idle.to_canonical_bytes(),
        )
        .unwrap()
    }

    fn state(checkpoint: u64, next_contract_id: u32) -> QEDL2BlockState {
        QEDL2BlockState {
            checkpoint_id: checkpoint,
            next_add_withdrawal_id: 11,
            next_process_withdrawal_id: 12,
            next_deposit_id: 13,
            total_deposits_claimed_epoch: 14,
            next_user_id: 15,
            end_balance: 16,
            next_contract_id,
        }
    }

    fn l2_cell(checkpoint: u64, next_contract_id: u32, writetime: i64) -> CoordinatorCommitPhysicalSourceCell {
        CoordinatorCommitPhysicalSourceCell::value(
            crate::compression::compress(
                &state(checkpoint, next_contract_id)
                    .psy_ser_to_bytes_vec()
                    .unwrap(),
            )
            .unwrap(),
            writetime,
        )
    }

    fn checkpoint_cell(checkpoint: u64, writetime: i64) -> CoordinatorCommitPhysicalSourceCell {
        CoordinatorCommitPhysicalSourceCell::value(
            i64::try_from(checkpoint).unwrap().to_be_bytes().to_vec(),
            writetime,
        )
    }

    #[test]
    fn floor_anchor_roundtrips_and_binds_exact_sources() {
        let floor = CoordinatorRollbackFloor::try_new(head(7)).unwrap();
        let anchor = CoordinatorRollbackFloorSingletonAnchor::try_new(
            floor,
            &l2_cell(7, 41, 1_001),
            &l2_cell(7, 41, 901),
            &checkpoint_cell(7, 1_002),
        )
        .unwrap();
        assert_eq!(
            CoordinatorRollbackFloorSingletonAnchor::decode_persisted(
                floor.floor().network_id(),
                floor.floor().chain_epoch().get(),
                ROW_REVISION,
                anchor.canonical_bytes(),
            ),
            Ok(anchor.clone()),
        );
        assert_eq!(anchor.latest_checkpoint(), 7);
        assert_ne!(anchor.digest(), &[0; 32]);
        assert_eq!(
            anchor.validate_target_l2(&l2_cell(7, 41, 902)),
            Err(CoordinatorRollbackFloorSingletonAnchorError::TargetL2Changed),
        );
    }

    #[test]
    fn floor_anchor_rejects_current_target_or_checkpoint_drift() {
        let floor = CoordinatorRollbackFloor::try_new(head(7)).unwrap();
        assert_eq!(
            CoordinatorRollbackFloorSingletonAnchor::try_new(
                floor,
                &l2_cell(7, 42, 1_001),
                &l2_cell(7, 41, 901),
                &checkpoint_cell(7, 1_002),
            ),
            Err(CoordinatorRollbackFloorSingletonAnchorError::LatestL2TargetMismatch),
        );
        assert_eq!(
            CoordinatorRollbackFloorSingletonAnchor::try_new(
                floor,
                &l2_cell(7, 41, 1_001),
                &l2_cell(7, 41, 901),
                &checkpoint_cell(8, 1_002),
            ),
            Err(CoordinatorRollbackFloorSingletonAnchorError::CheckpointMismatch),
        );
    }

    #[test]
    fn anchor_queries_are_append_only_and_exact() {
        let control = CanonicalHeadNoTabletKeyspace::try_new(
            "psy_floor_anchor_no_tablet".to_owned(),
        )
        .unwrap();
        let state = CqlKeyspaceName::try_new("psy_floor_anchor".to_owned()).unwrap();
        let queries = CoordinatorRollbackFloorSingletonAnchorQueries::new(
            &control,
            &state,
        );
        assert!(queries.insert_anchor.contains("IF NOT EXISTS"));
        for query in [
            queries.create_anchor,
            queries.read_anchor,
            queries.insert_anchor,
            queries.read_latest_l2,
            queries.read_target_l2,
            queries.read_latest_checkpoint,
        ] {
            assert!(!query.contains("DELETE"));
            assert!(!query.contains("UPDATE"));
            assert!(!query.contains("USING TIMESTAMP"));
        }
    }
}
