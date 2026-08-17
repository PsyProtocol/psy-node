//! Durable Scylla adapter for the rollback floor and its singleton anchor.
//!
//! The floor is the lower bound of source-backed rollback in one chain epoch:
//! below it there are no manifests, so `NOT_FEASIBLE` is the only honest answer
//! (design-r1 §2.2, §13 Q1).  It is established lazily, on the first commit of
//! an epoch, and never moves.
//!
//! The anchor is the part that is easy to get wrong.  Restoring the target needs
//! the mutable singleton values as they were at the floor, and those tables are
//! overwritten in place (design-r1 §2.2.1), so the values are observable only
//! while the head still stands at the floor activation point.  A missing anchor
//! must therefore fail closed once the head has advanced rather than record
//! whatever the singletons happen to hold now, which would be a later commit's
//! state wearing the floor's name.

use std::{error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::canonical_chain::NetworkId;
use psy_node_core::{
    psy_core_db::core_implementation::constants::{
        LATEST_INFO_TABLE_OBJ_ID_LATEST_CHECKPOINT_TREE_ROOT,
        LATEST_INFO_TABLE_OBJ_ID_LATEST_L2_BLOCK_STATE, U64_SINGLETON_TABLE_OBJ_ID_CHECKPOINT_ID,
    },
    store::{
        canonical_head::StoredCanonicalHead,
        coordinator_commit_source::{CoordinatorRollbackFloor, CoordinatorRollbackFloorStore},
    },
};
use scylla::{
    client::session::Session,
    statement::{Consistency, SerialConsistency, prepared::PreparedStatement},
};
use sha2::{Digest, Sha256};

use super::{CqlKeyspaceName, InvalidCqlKeyspaceName};

pub const COORDINATOR_ROLLBACK_FLOOR_TABLE: &str = "coordinator_rollback_floor";
pub const COORDINATOR_ROLLBACK_FLOOR_ANCHOR_TABLE: &str = "coordinator_rollback_floor_anchor";

pub const COORDINATOR_SINGLETON_ANCHOR_MAGIC: [u8; 8] = *b"PSYFANC1";
pub const COORDINATOR_SINGLETON_ANCHOR_CODEC_VERSION: u16 = 1;

const ANCHOR_DIGEST_DOMAIN: &[u8] = b"psy.rollback.coordinator-floor-anchor.v1\0";
const FLOOR_ROW_REVISION: i64 = 1;

/// Explicit trust boundary for a keyspace provisioned with tablets disabled.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RollbackFloorNoTabletKeyspace(CqlKeyspaceName);

impl RollbackFloorNoTabletKeyspace {
    pub fn try_new(name: impl Into<String>) -> Result<Self, RollbackFloorStoreError> {
        let name = name.into();
        if !name.ends_with("_no_tablet") {
            return Err(RollbackFloorStoreError::KeyspaceIsNotNoTablet(name));
        }
        Ok(Self(CqlKeyspaceName::try_new(name)?))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RollbackFloorStoreError {
    KeyspaceIsNotNoTablet(String),
    InvalidKeyspace(InvalidCqlKeyspaceName),
    Conflict {
        table: &'static str,
        stored_len: usize,
        offered_len: usize,
    },
    MissingAfterWrite {
        table: &'static str,
    },
    UnexpectedRowRevision {
        table: &'static str,
        revision: i64,
    },
    /// The anchor is absent and the head has already moved past the floor
    /// activation point, so the floor-time singleton values no longer exist
    /// anywhere.  Recording current values under the floor's name would be a
    /// silent lie; refusing keeps the floor honest.
    AnchorUnobservable {
        activation_head_revision: u64,
        current_head_revision: u64,
    },
    /// A stored anchor belongs to a different floor activation.
    AnchorFloorMismatch {
        stored_activation_revision: u64,
        floor_activation_revision: u64,
    },
    /// `latest_info` slot 1 is the Coordinator's L2 block state and is written
    /// by every commit.  Its absence at a live head means the state keyspace is
    /// not what the floor claims.
    MissingRequiredSingleton {
        what: &'static str,
    },
    InvalidAnchorMagic,
    UnknownAnchorVersion(u16),
    TruncatedAnchor,
    TrailingAnchorBytes,
    AnchorDigestMismatch,
}

impl From<InvalidCqlKeyspaceName> for RollbackFloorStoreError {
    fn from(error: InvalidCqlKeyspaceName) -> Self {
        Self::InvalidKeyspace(error)
    }
}

impl fmt::Display for RollbackFloorStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for RollbackFloorStoreError {}

/// The mutable singleton values as observed at the floor activation head.
///
/// Only the two Coordinator-owned cells are here.  `imt_next_append_index` is
/// Realm authority (inventory §5 row 35) and belongs to slice B's anchor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinatorSingletonAnchor {
    activation_head_revision: u64,
    latest_l2_block_state: Vec<u8>,
    latest_checkpoint_tree_root: Option<Vec<u8>>,
    latest_checkpoint_id: u64,
}

impl CoordinatorSingletonAnchor {
    pub fn new(
        activation_head_revision: u64,
        latest_l2_block_state: Vec<u8>,
        latest_checkpoint_tree_root: Option<Vec<u8>>,
        latest_checkpoint_id: u64,
    ) -> Self {
        Self {
            activation_head_revision,
            latest_l2_block_state,
            latest_checkpoint_tree_root,
            latest_checkpoint_id,
        }
    }

    pub const fn activation_head_revision(&self) -> u64 {
        self.activation_head_revision
    }

    pub fn latest_l2_block_state(&self) -> &[u8] {
        &self.latest_l2_block_state
    }

    pub fn latest_checkpoint_tree_root(&self) -> Option<&[u8]> {
        self.latest_checkpoint_tree_root.as_deref()
    }

    pub const fn latest_checkpoint_id(&self) -> u64 {
        self.latest_checkpoint_id
    }

    fn payload(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&COORDINATOR_SINGLETON_ANCHOR_MAGIC);
        out.extend_from_slice(&COORDINATOR_SINGLETON_ANCHOR_CODEC_VERSION.to_be_bytes());
        out.extend_from_slice(&self.activation_head_revision.to_be_bytes());
        out.extend_from_slice(&self.latest_checkpoint_id.to_be_bytes());
        out.extend_from_slice(&(self.latest_l2_block_state.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.latest_l2_block_state);
        // Slot 2's absence is encoded explicitly.  A legacy deployment may never
        // have written it, and "absent" must restore as absent rather than as an
        // empty value.
        match &self.latest_checkpoint_tree_root {
            Some(root) => {
                out.push(1);
                out.extend_from_slice(&(root.len() as u32).to_be_bytes());
                out.extend_from_slice(root);
            }
            None => out.push(0),
        }
        out
    }

    pub fn encode_canonical(&self) -> Vec<u8> {
        let payload = self.payload();
        let mut hasher = Sha256::new();
        hasher.update(ANCHOR_DIGEST_DOMAIN);
        hasher.update((payload.len() as u64).to_be_bytes());
        hasher.update(&payload);
        let digest: [u8; 32] = hasher.finalize().into();
        let mut out = payload;
        out.extend_from_slice(&digest);
        out
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, RollbackFloorStoreError> {
        const FIXED: usize = 8 + 2 + 8 + 8 + 4;
        if bytes.len() < FIXED + 32 {
            return Err(RollbackFloorStoreError::TruncatedAnchor);
        }
        if bytes[..8] != COORDINATOR_SINGLETON_ANCHOR_MAGIC {
            return Err(RollbackFloorStoreError::InvalidAnchorMagic);
        }
        let version = u16::from_be_bytes([bytes[8], bytes[9]]);
        if version != COORDINATOR_SINGLETON_ANCHOR_CODEC_VERSION {
            return Err(RollbackFloorStoreError::UnknownAnchorVersion(version));
        }
        let activation_head_revision = u64::from_be_bytes(
            bytes[10..18].try_into().expect("checked length"),
        );
        let latest_checkpoint_id =
            u64::from_be_bytes(bytes[18..26].try_into().expect("checked length"));
        let state_len =
            u32::from_be_bytes(bytes[26..30].try_into().expect("checked length")) as usize;
        let mut cursor = FIXED;
        let state_end = cursor
            .checked_add(state_len)
            .ok_or(RollbackFloorStoreError::TruncatedAnchor)?;
        if bytes.len() < state_end + 1 + 32 {
            return Err(RollbackFloorStoreError::TruncatedAnchor);
        }
        let latest_l2_block_state = bytes[cursor..state_end].to_vec();
        cursor = state_end;
        let latest_checkpoint_tree_root = match bytes[cursor] {
            0 => {
                cursor += 1;
                None
            }
            1 => {
                cursor += 1;
                if bytes.len() < cursor + 4 {
                    return Err(RollbackFloorStoreError::TruncatedAnchor);
                }
                let root_len = u32::from_be_bytes(
                    bytes[cursor..cursor + 4].try_into().expect("checked length"),
                ) as usize;
                cursor += 4;
                let root_end = cursor
                    .checked_add(root_len)
                    .ok_or(RollbackFloorStoreError::TruncatedAnchor)?;
                if bytes.len() < root_end + 32 {
                    return Err(RollbackFloorStoreError::TruncatedAnchor);
                }
                let root = bytes[cursor..root_end].to_vec();
                cursor = root_end;
                Some(root)
            }
            _ => return Err(RollbackFloorStoreError::TruncatedAnchor),
        };
        if bytes.len() != cursor + 32 {
            return Err(RollbackFloorStoreError::TrailingAnchorBytes);
        }
        let anchor = Self {
            activation_head_revision,
            latest_l2_block_state,
            latest_checkpoint_tree_root,
            latest_checkpoint_id,
        };
        if anchor.encode_canonical() != bytes {
            return Err(RollbackFloorStoreError::AnchorDigestMismatch);
        }
        Ok(anchor)
    }
}

pub struct RollbackFloorQueries {
    pub create_floor: String,
    pub create_anchor: String,
    pub insert_floor: String,
    pub read_floor: String,
    pub insert_anchor: String,
    pub read_anchor: String,
    pub read_latest_info_slot: String,
    pub read_u64_singleton: String,
}

impl RollbackFloorQueries {
    pub fn new(
        control_keyspace: &RollbackFloorNoTabletKeyspace,
        state_keyspace: &CqlKeyspaceName,
    ) -> Self {
        let floor = format!("{}.{COORDINATOR_ROLLBACK_FLOOR_TABLE}", control_keyspace.as_str());
        let anchor = format!(
            "{}.{COORDINATOR_ROLLBACK_FLOOR_ANCHOR_TABLE}",
            control_keyspace.as_str()
        );
        let state = state_keyspace.as_str();
        Self {
            create_floor: format!(
                "CREATE TABLE IF NOT EXISTS {floor} (network_chain_id bigint, chain_epoch bigint, \
                 revision bigint, floor blob, PRIMARY KEY ((network_chain_id, chain_epoch)))"
            ),
            create_anchor: format!(
                "CREATE TABLE IF NOT EXISTS {anchor} (network_chain_id bigint, chain_epoch bigint, \
                 revision bigint, anchor blob, PRIMARY KEY ((network_chain_id, chain_epoch)))"
            ),
            insert_floor: format!(
                "INSERT INTO {floor} (network_chain_id, chain_epoch, revision, floor) \
                 VALUES (?, ?, ?, ?) IF NOT EXISTS"
            ),
            read_floor: format!(
                "SELECT revision, floor FROM {floor} \
                 WHERE network_chain_id = ? AND chain_epoch = ?"
            ),
            insert_anchor: format!(
                "INSERT INTO {anchor} (network_chain_id, chain_epoch, revision, anchor) \
                 VALUES (?, ?, ?, ?) IF NOT EXISTS"
            ),
            read_anchor: format!(
                "SELECT revision, anchor FROM {anchor} \
                 WHERE network_chain_id = ? AND chain_epoch = ?"
            ),
            // The two mutable Coordinator singletons, read exactly the way the
            // production adapters read them.
            read_latest_info_slot: format!(
                "SELECT value FROM {state}.latest_info_table WHERE obj_id = ? LIMIT 1"
            ),
            read_u64_singleton: format!(
                "SELECT value FROM {state}.u64_singleton_table WHERE obj_id = ? LIMIT 1"
            ),
        }
    }
}

pub struct ScyllaCoordinatorRollbackFloorStore {
    session: Arc<Session>,
    insert_floor: PreparedStatement,
    read_floor: PreparedStatement,
    insert_anchor: PreparedStatement,
    read_anchor: PreparedStatement,
    read_latest_info_slot: PreparedStatement,
    read_u64_singleton: PreparedStatement,
}

impl ScyllaCoordinatorRollbackFloorStore {
    pub async fn create_tables(
        session: &Session,
        control_keyspace: &RollbackFloorNoTabletKeyspace,
        state_keyspace: &CqlKeyspaceName,
    ) -> anyhow::Result<()> {
        let queries = RollbackFloorQueries::new(control_keyspace, state_keyspace);
        session.query_unpaged(queries.create_floor, &[]).await?;
        session.query_unpaged(queries.create_anchor, &[]).await?;
        session.await_schema_agreement().await?;
        Ok(())
    }

    pub async fn prepare(
        session: Arc<Session>,
        control_keyspace: &RollbackFloorNoTabletKeyspace,
        state_keyspace: &CqlKeyspaceName,
    ) -> anyhow::Result<Self> {
        let queries = RollbackFloorQueries::new(control_keyspace, state_keyspace);
        let mut insert_floor = session.prepare(queries.insert_floor).await?;
        insert_floor.set_consistency(Consistency::Quorum);
        insert_floor.set_serial_consistency(Some(SerialConsistency::LocalSerial));
        let mut insert_anchor = session.prepare(queries.insert_anchor).await?;
        insert_anchor.set_consistency(Consistency::Quorum);
        insert_anchor.set_serial_consistency(Some(SerialConsistency::LocalSerial));
        let mut read_floor = session.prepare(queries.read_floor).await?;
        read_floor.set_consistency(Consistency::Quorum);
        let mut read_anchor = session.prepare(queries.read_anchor).await?;
        read_anchor.set_consistency(Consistency::Quorum);
        let mut read_latest_info_slot = session.prepare(queries.read_latest_info_slot).await?;
        read_latest_info_slot.set_consistency(Consistency::Quorum);
        let mut read_u64_singleton = session.prepare(queries.read_u64_singleton).await?;
        read_u64_singleton.set_consistency(Consistency::Quorum);
        Ok(Self {
            session,
            insert_floor,
            read_floor,
            insert_anchor,
            read_anchor,
            read_latest_info_slot,
            read_u64_singleton,
        })
    }

    async fn read_blob_row(
        &self,
        statement: &PreparedStatement,
        network: i64,
        chain_epoch: i64,
        table: &'static str,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let rows = self
            .session
            .execute_unpaged(statement, (network, chain_epoch))
            .await?
            .into_rows_result()?;
        let Some(row) = rows.rows::<(i64, Vec<u8>)>()?.next().transpose()? else {
            return Ok(None);
        };
        let (revision, payload) = row;
        if revision != FLOOR_ROW_REVISION {
            return Err(RollbackFloorStoreError::UnexpectedRowRevision { table, revision }.into());
        }
        Ok(Some(payload))
    }

    async fn observe_singletons(
        &self,
        activation_head_revision: u64,
    ) -> anyhow::Result<CoordinatorSingletonAnchor> {
        let latest_l2_block_state = self
            .read_latest_info_blob(LATEST_INFO_TABLE_OBJ_ID_LATEST_L2_BLOCK_STATE)
            .await?
            .ok_or(RollbackFloorStoreError::MissingRequiredSingleton {
                what: "latest_info slot 1 (latest L2 block state)",
            })?;
        let latest_checkpoint_tree_root = self
            .read_latest_info_blob(LATEST_INFO_TABLE_OBJ_ID_LATEST_CHECKPOINT_TREE_ROOT)
            .await?;
        let latest_checkpoint_id = self
            .read_u64_singleton_value(U64_SINGLETON_TABLE_OBJ_ID_CHECKPOINT_ID)
            .await?
            .ok_or(RollbackFloorStoreError::MissingRequiredSingleton {
                what: "u64_singleton latest checkpoint id",
            })?;
        Ok(CoordinatorSingletonAnchor::new(
            activation_head_revision,
            latest_l2_block_state,
            latest_checkpoint_tree_root,
            latest_checkpoint_id,
        ))
    }

    async fn read_latest_info_blob(&self, obj_id: u64) -> anyhow::Result<Option<Vec<u8>>> {
        let rows = self
            .session
            .execute_unpaged(&self.read_latest_info_slot, (obj_id as i64,))
            .await?
            .into_rows_result()?;
        Ok(rows.rows::<(Vec<u8>,)>()?.next().transpose()?.map(|(v,)| v))
    }

    async fn read_u64_singleton_value(&self, obj_id: u64) -> anyhow::Result<Option<u64>> {
        let rows = self
            .session
            .execute_unpaged(&self.read_u64_singleton, (obj_id as i64,))
            .await?
            .into_rows_result()?;
        Ok(rows
            .rows::<(i64,)>()?
            .next()
            .transpose()?
            .map(|(v,)| v as u64))
    }
}

#[async_trait::async_trait]
impl<Hash: Q256BitHash> CoordinatorRollbackFloorStore<Hash>
    for ScyllaCoordinatorRollbackFloorStore
{
    async fn persist_coordinator_rollback_floor(
        &self,
        floor: &CoordinatorRollbackFloor<Hash>,
    ) -> anyhow::Result<()> {
        let network = i64::from(floor.floor().network_id().chain_id());
        let chain_epoch = floor.floor().chain_epoch().get() as i64;
        let payload = floor.encode_canonical();
        self.session
            .execute_unpaged(
                &self.insert_floor,
                (network, chain_epoch, FLOOR_ROW_REVISION, payload.clone()),
            )
            .await?;
        match self
            .read_blob_row(
                &self.read_floor,
                network,
                chain_epoch,
                COORDINATOR_ROLLBACK_FLOOR_TABLE,
            )
            .await?
        {
            Some(stored) if stored == payload => Ok(()),
            Some(stored) => Err(RollbackFloorStoreError::Conflict {
                table: COORDINATOR_ROLLBACK_FLOOR_TABLE,
                stored_len: stored.len(),
                offered_len: payload.len(),
            }
            .into()),
            None => Err(RollbackFloorStoreError::MissingAfterWrite {
                table: COORDINATOR_ROLLBACK_FLOOR_TABLE,
            }
            .into()),
        }
    }

    async fn read_coordinator_rollback_floor(
        &self,
        network: NetworkId,
        chain_epoch: u64,
    ) -> anyhow::Result<Option<CoordinatorRollbackFloor<Hash>>> {
        let network_chain_id = i64::from(network.chain_id());
        let Some(payload) = self
            .read_blob_row(
                &self.read_floor,
                network_chain_id,
                chain_epoch as i64,
                COORDINATOR_ROLLBACK_FLOOR_TABLE,
            )
            .await?
        else {
            return Ok(None);
        };
        Ok(Some(CoordinatorRollbackFloor::decode_persisted(
            network,
            chain_epoch,
            FLOOR_ROW_REVISION,
            &payload,
        )?))
    }

    async fn ensure_coordinator_rollback_floor_singleton_anchor(
        &self,
        current: &StoredCanonicalHead<Hash>,
        floor: &CoordinatorRollbackFloor<Hash>,
    ) -> anyhow::Result<()> {
        let network = i64::from(floor.floor().network_id().chain_id());
        let chain_epoch = floor.floor().chain_epoch().get() as i64;
        if let Some(stored) = self
            .read_blob_row(
                &self.read_anchor,
                network,
                chain_epoch,
                COORDINATOR_ROLLBACK_FLOOR_ANCHOR_TABLE,
            )
            .await?
        {
            let anchor = CoordinatorSingletonAnchor::decode_canonical(&stored)?;
            if anchor.activation_head_revision() != floor.activation_head_revision() {
                return Err(RollbackFloorStoreError::AnchorFloorMismatch {
                    stored_activation_revision: anchor.activation_head_revision(),
                    floor_activation_revision: floor.activation_head_revision(),
                }
                .into());
            }
            return Ok(());
        }

        // No anchor yet.  Minting one is only honest while the head still stands
        // where the floor was activated; past that the singletons have been
        // overwritten and their floor-time values exist nowhere.
        if current.revision().get() != floor.activation_head_revision() {
            return Err(RollbackFloorStoreError::AnchorUnobservable {
                activation_head_revision: floor.activation_head_revision(),
                current_head_revision: current.revision().get(),
            }
            .into());
        }

        let anchor = self
            .observe_singletons(floor.activation_head_revision())
            .await?;
        let payload = anchor.encode_canonical();
        self.session
            .execute_unpaged(
                &self.insert_anchor,
                (network, chain_epoch, FLOOR_ROW_REVISION, payload.clone()),
            )
            .await?;
        match self
            .read_blob_row(
                &self.read_anchor,
                network,
                chain_epoch,
                COORDINATOR_ROLLBACK_FLOOR_ANCHOR_TABLE,
            )
            .await?
        {
            Some(stored) if stored == payload => Ok(()),
            Some(stored) => Err(RollbackFloorStoreError::Conflict {
                table: COORDINATOR_ROLLBACK_FLOOR_ANCHOR_TABLE,
                stored_len: stored.len(),
                offered_len: payload.len(),
            }
            .into()),
            None => Err(RollbackFloorStoreError::MissingAfterWrite {
                table: COORDINATOR_ROLLBACK_FLOOR_ANCHOR_TABLE,
            }
            .into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn control() -> RollbackFloorNoTabletKeyspace {
        RollbackFloorNoTabletKeyspace::try_new("psy_no_tablet").unwrap()
    }

    fn state() -> CqlKeyspaceName {
        CqlKeyspaceName::try_new("psy").unwrap()
    }

    fn anchor(root: Option<Vec<u8>>) -> CoordinatorSingletonAnchor {
        CoordinatorSingletonAnchor::new(7, vec![1, 2, 3, 4, 5], root, 4242)
    }

    #[test]
    fn floor_tables_require_a_no_tablet_keyspace() {
        assert!(RollbackFloorNoTabletKeyspace::try_new("psy").is_err());
        assert!(RollbackFloorNoTabletKeyspace::try_new("psy_no_tablet").is_ok());
    }

    #[test]
    fn anchor_round_trips_with_and_without_the_optional_slot() {
        for root in [None, Some(vec![9u8; 32])] {
            let original = anchor(root);
            let encoded = original.encode_canonical();
            assert_eq!(
                CoordinatorSingletonAnchor::decode_canonical(&encoded),
                Ok(original)
            );
        }
    }

    #[test]
    fn an_absent_optional_slot_stays_absent_rather_than_becoming_empty() {
        // Slot 2 may never have been written on a legacy deployment, and
        // restoring "absent" as an empty value would write a cell that never
        // existed at the floor.
        let absent = anchor(None);
        let empty = anchor(Some(Vec::new()));
        assert_ne!(absent.encode_canonical(), empty.encode_canonical());
        assert_eq!(
            CoordinatorSingletonAnchor::decode_canonical(&absent.encode_canonical())
                .unwrap()
                .latest_checkpoint_tree_root(),
            None
        );
        assert_eq!(
            CoordinatorSingletonAnchor::decode_canonical(&empty.encode_canonical())
                .unwrap()
                .latest_checkpoint_tree_root(),
            Some(&[][..])
        );
    }

    #[test]
    fn a_corrupted_anchor_fails_closed() {
        let encoded = anchor(Some(vec![3u8; 32])).encode_canonical();
        for cut in 0..encoded.len() {
            assert!(
                CoordinatorSingletonAnchor::decode_canonical(&encoded[..cut]).is_err(),
                "prefix of {cut} bytes must not decode"
            );
        }
        let mut extended = encoded.clone();
        extended.push(0);
        assert!(CoordinatorSingletonAnchor::decode_canonical(&extended).is_err());
        let mut flipped = encoded.clone();
        // Flip a payload byte and leave the digest alone.
        flipped[20] ^= 0xff;
        assert_eq!(
            CoordinatorSingletonAnchor::decode_canonical(&flipped),
            Err(RollbackFloorStoreError::AnchorDigestMismatch)
        );
        let mut wrong_magic = encoded;
        wrong_magic[0] ^= 0xff;
        assert_eq!(
            CoordinatorSingletonAnchor::decode_canonical(&wrong_magic),
            Err(RollbackFloorStoreError::InvalidAnchorMagic)
        );
    }

    #[test]
    fn control_rows_are_append_only_and_singleton_reads_match_production() {
        let queries = RollbackFloorQueries::new(&control(), &state());
        for statement in [&queries.insert_floor, &queries.insert_anchor] {
            assert!(statement.starts_with("INSERT INTO"));
            assert!(statement.ends_with("IF NOT EXISTS"));
        }
        for statement in [
            &queries.create_floor,
            &queries.create_anchor,
            &queries.insert_floor,
            &queries.read_floor,
            &queries.insert_anchor,
            &queries.read_anchor,
            &queries.read_latest_info_slot,
            &queries.read_u64_singleton,
        ] {
            for forbidden in ["UPDATE ", "DELETE ", " USING TTL", " USING TIMESTAMP"] {
                assert!(
                    !statement.contains(forbidden),
                    "{forbidden:?} must not appear in {statement}"
                );
            }
        }
        // The singleton reads must hit the state keyspace, not the control one,
        // and must be the same shape the production adapters use.
        assert_eq!(
            queries.read_latest_info_slot,
            "SELECT value FROM psy.latest_info_table WHERE obj_id = ? LIMIT 1"
        );
        assert_eq!(
            queries.read_u64_singleton,
            "SELECT value FROM psy.u64_singleton_table WHERE obj_id = ? LIMIT 1"
        );
    }

    #[test]
    fn the_anchor_covers_exactly_the_coordinator_owned_mutable_cells() {
        // design-r1 §2.2.1 lists three tables needing a before image; the third,
        // imt_next_append_index, is Realm authority and belongs to slice B.
        assert_eq!(LATEST_INFO_TABLE_OBJ_ID_LATEST_L2_BLOCK_STATE, 1);
        assert_eq!(LATEST_INFO_TABLE_OBJ_ID_LATEST_CHECKPOINT_TREE_ROOT, 2);
        assert_eq!(U64_SINGLETON_TABLE_OBJ_ID_CHECKPOINT_ID, 1);
    }
}
