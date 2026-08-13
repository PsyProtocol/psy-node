//! Durable all-participant archive barrier for one explicit global rollback.
//!
//! The barrier is selected only from the exact Coordinator readiness object
//! and every exact Realm participant completion in the durable participant
//! plan.  It is written to a stable immutable slot, then the whole participant
//! set is selected again.  This module deliberately has no hot-row delete,
//! restore, or canonical/local-head mutation API.

#![allow(dead_code)]

use std::{error::Error, fmt, sync::Arc};

use parth_core::{
    crypto::hash::traits::{FieldQHasher, MerkleHasher},
    felt::QFelt64,
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use psy_data::protocol::{
    canonical_chain::{CANONICAL_CHAIN_REF_V1_LEN, CanonicalChainRef, NetworkId},
    chain_context::AuthorityScope,
};
use psy_node_core::store::{
    canonical_head::{
        CanonicalHeadReadState, CanonicalHeadTransition, StoredCanonicalHead,
    },
    rollback_control::ROLLBACK_CONTROL_V1_LEN,
    rollback_participant_plan::{
        RollbackParticipantPlan, RollbackRealmParticipant,
    },
};
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{prepared::PreparedStatement, Consistency, SerialConsistency},
    value::{CqlValue, Row},
};
use sha2::{Digest, Sha256};

use super::{
    CqlKeyspaceName, ScyllaCanonicalHeadStore,
    ScyllaCoordinatorCommitSourceStore, ScyllaRollbackParticipantPlanStore,
    coordinator_commit_physical_archive_store::{
        CoordinatorCommitPhysicalArchiveOwnerError,
        CoordinatorCommitPreBarrierReadinessReceipt,
        ScyllaCoordinatorCommitPhysicalArchiveOwner,
    },
    coordinator_rollback_archive_store::COORDINATOR_ROLLBACK_SUFFIX_ARCHIVE_TABLE,
    realm_rollback_participant_completion::RealmRollbackParticipantCompletion,
    realm_rollback_physical_archive_owner::{
        RealmRollbackPhysicalArchiveOwnerError,
        ScyllaRealmRollbackPhysicalArchiveOwner,
    },
};

const MAGIC: &[u8; 8] = b"PSYRBGAB";
const VERSION: u16 = 1;
const ARCHIVE_REVISION: i64 = 1;
const BARRIER_KEY_DOMAIN: i16 = -3;
const MAX_FRAGMENT_BYTES: usize = 4 * 1024 * 1024;
const MAX_FRAGMENTS: usize = 16;
const MAX_BARRIER_BYTES: usize = 64 * 1024;
const SLOT_DOMAIN: &[u8] = b"psy.rollback.global-archive-barrier-slot.v1\0";
const DIGEST_DOMAIN: &[u8] = b"psy.rollback.global-archive-barrier.v1\0";
const PARTICIPANT_SET_DOMAIN: &[u8] =
    b"psy.rollback.global-archive-barrier-participant-set.v1\0";
const FRAGMENT_DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.global-archive-barrier-fragment.v1\0";
const STORE_FINGERPRINT_DOMAIN: &[u8] =
    b"psy.rollback.global-archive-barrier-store.v1\0";

const INSERT_TEMPLATE: &str = "INSERT INTO {table} (network_chain_id, chain_epoch, participant_plan_digest, key_domain, row_slot, fragment_index, revision, fragment_count, row_bytes, fragment_payload, fragment_digest, row_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) IF NOT EXISTS";
const READ_ROW_TEMPLATE: &str = "SELECT fragment_index, revision, fragment_count, row_bytes, fragment_payload, fragment_digest, row_digest FROM {table} WHERE network_chain_id = ? AND chain_epoch = ? AND participant_plan_digest = ? AND key_domain = ? AND row_slot = ?";
const READ_FRAGMENT_TEMPLATE: &str = "SELECT revision, fragment_count, row_bytes, fragment_payload, fragment_digest, row_digest FROM {table} WHERE network_chain_id = ? AND chain_epoch = ? AND participant_plan_digest = ? AND key_domain = ? AND row_slot = ? AND fragment_index = ?";

/// Fixed-size canonical record selecting the exact all-participant completion
/// set.  The participants themselves remain in their immutable completion
/// rows; this record commits their plan-ordered slot/digest stream so a large
/// topology does not create one giant barrier row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RollbackGlobalArchiveBarrier<Hash> {
    network: NetworkId,
    old_chain_epoch: u64,
    archiving_head: StoredCanonicalHead<Hash>,
    target: CanonicalChainRef<Hash>,
    participant_plan_digest: [u8; 32],
    topology_revision: u64,
    topology_digest: [u8; 32],
    coordinator_completion_slot: [u8; 32],
    coordinator_completion_digest: [u8; 32],
    coordinator_target_restore_slot: [u8; 32],
    coordinator_target_restore_digest: [u8; 32],
    coordinator_readiness_digest: [u8; 32],
    participant_count: u64,
    total_entry_count: u64,
    participant_set_digest: [u8; 32],
    store_fingerprint: [u8; 32],
    slot: [u8; 32],
    digest: [u8; 32],
    canonical_bytes: Vec<u8>,
}

impl<Hash: Q256BitHash> RollbackGlobalArchiveBarrier<Hash> {
    fn decode_canonical(bytes: &[u8]) -> Result<Self, RollbackGlobalArchiveBarrierError> {
        if bytes.len() > MAX_BARRIER_BYTES || bytes.len() < 32 {
            return Err(RollbackGlobalArchiveBarrierError::InvalidLength);
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take(8)? != MAGIC {
            return Err(RollbackGlobalArchiveBarrierError::InvalidMagic);
        }
        let version = cursor.u16()?;
        if version != VERSION {
            return Err(RollbackGlobalArchiveBarrierError::UnknownVersion(version));
        }
        let network = NetworkId::try_from_chain_id(cursor.u32()?)
            .map_err(|error| RollbackGlobalArchiveBarrierError::Canonical(error.to_string()))?;
        let old_chain_epoch = cursor.u64()?;
        let archiving_revision = cursor.i64()?;
        let archiving_head = StoredCanonicalHead::decode_persisted(
            network,
            archiving_revision,
            cursor.take(CANONICAL_CHAIN_REF_V1_LEN)?,
            cursor.take(ROLLBACK_CONTROL_V1_LEN)?,
        )
        .map_err(|error| RollbackGlobalArchiveBarrierError::Canonical(error.to_string()))?;
        let target = CanonicalChainRef::from_canonical_bytes(
            cursor.take(CANONICAL_CHAIN_REF_V1_LEN)?,
        )
        .map_err(|error| RollbackGlobalArchiveBarrierError::Canonical(error.to_string()))?;
        let participant_plan_digest = cursor.array_32()?;
        let topology_revision = cursor.u64()?;
        let topology_digest = cursor.array_32()?;
        let coordinator_completion_slot = cursor.array_32()?;
        let coordinator_completion_digest = cursor.array_32()?;
        let coordinator_target_restore_slot = cursor.array_32()?;
        let coordinator_target_restore_digest = cursor.array_32()?;
        let coordinator_readiness_digest = cursor.array_32()?;
        let participant_count = cursor.u64()?;
        let total_entry_count = cursor.u64()?;
        let participant_set_digest = cursor.array_32()?;
        let store_fingerprint = cursor.array_32()?;
        let slot = cursor.array_32()?;
        let digest = cursor.array_32()?;
        if !cursor.is_empty() {
            return Err(RollbackGlobalArchiveBarrierError::TrailingBytes);
        }
        let decoded = Self::try_from_fields(
            network,
            old_chain_epoch,
            archiving_head,
            target,
            participant_plan_digest,
            topology_revision,
            topology_digest,
            coordinator_completion_slot,
            coordinator_completion_digest,
            coordinator_target_restore_slot,
            coordinator_target_restore_digest,
            coordinator_readiness_digest,
            participant_count,
            total_entry_count,
            participant_set_digest,
            store_fingerprint,
        )?;
        if decoded.slot != slot
            || decoded.digest != digest
            || decoded.canonical_bytes != bytes
        {
            return Err(RollbackGlobalArchiveBarrierError::NonCanonicalEncoding);
        }
        Ok(decoded)
    }

    #[allow(clippy::too_many_arguments)]
    fn try_from_fields(
        network: NetworkId,
        old_chain_epoch: u64,
        archiving_head: StoredCanonicalHead<Hash>,
        target: CanonicalChainRef<Hash>,
        participant_plan_digest: [u8; 32],
        topology_revision: u64,
        topology_digest: [u8; 32],
        coordinator_completion_slot: [u8; 32],
        coordinator_completion_digest: [u8; 32],
        coordinator_target_restore_slot: [u8; 32],
        coordinator_target_restore_digest: [u8; 32],
        coordinator_readiness_digest: [u8; 32],
        participant_count: u64,
        total_entry_count: u64,
        participant_set_digest: [u8; 32],
        store_fingerprint: [u8; 32],
    ) -> Result<Self, RollbackGlobalArchiveBarrierError> {
        let request = archiving_head
            .rollback_control()
            .requested()
            .ok_or(RollbackGlobalArchiveBarrierError::NotArchiving)?;
        let active_epoch = archiving_head.canonical_ref().chain_epoch().get();
        if !archiving_head.rollback_control().is_archiving()
            || archiving_head.canonical_ref().network_id() != network
            || active_epoch.checked_sub(1) != Some(old_chain_epoch)
            || target.network_id() != network
            || target.chain_epoch().get() != old_chain_epoch
            || target.checkpoint() != request.target()
            || request.plan_digest().as_bytes() != &participant_plan_digest
            || participant_count < 2
            || [
                participant_plan_digest,
                topology_digest,
                coordinator_completion_slot,
                coordinator_completion_digest,
                coordinator_target_restore_slot,
                coordinator_target_restore_digest,
                coordinator_readiness_digest,
                participant_set_digest,
                store_fingerprint,
            ]
            .contains(&[0; 32])
        {
            return Err(RollbackGlobalArchiveBarrierError::BindingMismatch);
        }
        let slot = barrier_slot(
            network,
            old_chain_epoch,
            &archiving_head,
            &target,
            &participant_plan_digest,
            topology_revision,
            &topology_digest,
            &store_fingerprint,
        );
        let mut selected = Self {
            network,
            old_chain_epoch,
            archiving_head,
            target,
            participant_plan_digest,
            topology_revision,
            topology_digest,
            coordinator_completion_slot,
            coordinator_completion_digest,
            coordinator_target_restore_slot,
            coordinator_target_restore_digest,
            coordinator_readiness_digest,
            participant_count,
            total_entry_count,
            participant_set_digest,
            store_fingerprint,
            slot,
            digest: [0; 32],
            canonical_bytes: Vec::new(),
        };
        let body = selected.encode_without_digest();
        selected.digest = barrier_digest(&body);
        selected.canonical_bytes = body;
        selected.canonical_bytes.extend_from_slice(&selected.digest);
        if selected.canonical_bytes.len() > MAX_BARRIER_BYTES {
            return Err(RollbackGlobalArchiveBarrierError::InvalidLength);
        }
        Ok(selected)
    }

    fn encode_without_digest(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1024);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.network.chain_id().to_be_bytes());
        bytes.extend_from_slice(&self.old_chain_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.archiving_head.revision().as_i64().to_be_bytes());
        bytes.extend_from_slice(&self.archiving_head.canonical_ref_bytes());
        bytes.extend_from_slice(&self.archiving_head.rollback_control_bytes());
        bytes.extend_from_slice(&self.target.to_canonical_bytes());
        bytes.extend_from_slice(&self.participant_plan_digest);
        bytes.extend_from_slice(&self.topology_revision.to_be_bytes());
        bytes.extend_from_slice(&self.topology_digest);
        bytes.extend_from_slice(&self.coordinator_completion_slot);
        bytes.extend_from_slice(&self.coordinator_completion_digest);
        bytes.extend_from_slice(&self.coordinator_target_restore_slot);
        bytes.extend_from_slice(&self.coordinator_target_restore_digest);
        bytes.extend_from_slice(&self.coordinator_readiness_digest);
        bytes.extend_from_slice(&self.participant_count.to_be_bytes());
        bytes.extend_from_slice(&self.total_entry_count.to_be_bytes());
        bytes.extend_from_slice(&self.participant_set_digest);
        bytes.extend_from_slice(&self.store_fingerprint);
        bytes.extend_from_slice(&self.slot);
        bytes
    }

    pub(super) const fn archiving_head(&self) -> &StoredCanonicalHead<Hash> {
        &self.archiving_head
    }

    pub(super) const fn participant_plan_digest(&self) -> &[u8; 32] {
        &self.participant_plan_digest
    }

    pub(super) const fn participant_count(&self) -> u64 {
        self.participant_count
    }

    pub(super) const fn total_entry_count(&self) -> u64 {
        self.total_entry_count
    }

    pub(super) const fn participant_set_digest(&self) -> &[u8; 32] {
        &self.participant_set_digest
    }

    pub(super) const fn slot(&self) -> &[u8; 32] {
        &self.slot
    }

    pub(super) const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub(super) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

/// Streaming builder.  It consumes completions in the exact participant-plan
/// order and retains only a digest plus counters, not the Realm dataset.
struct RollbackGlobalArchiveBarrierBuilder<'a, Hash> {
    plan: &'a RollbackParticipantPlan<Hash>,
    readiness: &'a CoordinatorCommitPreBarrierReadinessReceipt<Hash>,
    store_fingerprint: [u8; 32],
    next_realm: usize,
    total_entry_count: u64,
    participant_set: Sha256,
}

impl<'a, Hash: Q256BitHash> RollbackGlobalArchiveBarrierBuilder<'a, Hash> {
    fn try_new(
        plan: &'a RollbackParticipantPlan<Hash>,
        readiness: &'a CoordinatorCommitPreBarrierReadinessReceipt<Hash>,
        store_fingerprint: [u8; 32],
    ) -> Result<Self, RollbackGlobalArchiveBarrierError> {
        let expected_requested = CanonicalHeadTransition::start_rollback(
            *plan.expected_head(),
            plan.rollback_request()
                .map_err(|error| RollbackGlobalArchiveBarrierError::Plan(error.to_string()))?,
        )
        .map_err(|error| RollbackGlobalArchiveBarrierError::Canonical(error.to_string()))?;
        let expected_archiving = CanonicalHeadTransition::begin_rollback_archive(
            *expected_requested.candidate(),
        )
        .map_err(|error| RollbackGlobalArchiveBarrierError::Canonical(error.to_string()))?;
        if readiness.archiving_head() != expected_archiving.candidate()
            || readiness.target() != plan.target()
            || store_fingerprint == [0; 32]
        {
            return Err(RollbackGlobalArchiveBarrierError::BindingMismatch);
        }
        let participant_count = u64::try_from(plan.participant_count())
            .map_err(|_| RollbackGlobalArchiveBarrierError::LengthOverflow)?;
        let mut participant_set = Sha256::new();
        participant_set.update(PARTICIPANT_SET_DOMAIN);
        participant_set.update(plan.digest());
        participant_set.update(participant_count.to_be_bytes());
        participant_set.update([0]); // Coordinator is participant zero.
        participant_set.update(readiness.participant_completion_slot());
        participant_set.update(readiness.participant_completion_digest());
        participant_set.update(readiness.target_restore_slot());
        participant_set.update(readiness.target_restore_digest());
        participant_set.update(readiness.digest());
        Ok(Self {
            plan,
            readiness,
            store_fingerprint,
            next_realm: 0,
            total_entry_count: readiness.entry_count(),
            participant_set,
        })
    }

    fn push_realm(
        &mut self,
        completion: &RealmRollbackParticipantCompletion<Hash>,
    ) -> Result<(), RollbackGlobalArchiveBarrierError> {
        let expected = self
            .plan
            .realms()
            .get(self.next_realm)
            .ok_or(RollbackGlobalArchiveBarrierError::UnexpectedParticipant)?;
        let AuthorityScope::Realm { realm_id, realm_sub_id } = completion.authority() else {
            return Err(RollbackGlobalArchiveBarrierError::UnexpectedParticipant);
        };
        let actual = RollbackRealmParticipant::new(realm_id, realm_sub_id);
        if &actual != expected
            || completion.network() != self.plan.target().network_id()
            || completion.old_chain_epoch() != self.plan.target().chain_epoch().get()
            || completion.participant_plan_digest() != self.plan.digest()
            || completion.target().network_id() != self.plan.target().network_id()
            || completion.target().chain_epoch() != self.plan.target().chain_epoch()
            || completion.target().checkpoint().checkpoint_id()
                != self.plan.target().checkpoint().checkpoint_id()
        {
            return Err(RollbackGlobalArchiveBarrierError::UnexpectedParticipant);
        }
        self.participant_set.update([1]);
        self.participant_set.update(realm_id.to_be_bytes());
        self.participant_set.update(realm_sub_id.to_be_bytes());
        self.participant_set.update(completion.slot());
        self.participant_set.update(completion.digest());
        self.total_entry_count = self
            .total_entry_count
            .checked_add(completion.entry_count())
            .ok_or(RollbackGlobalArchiveBarrierError::CountOverflow)?;
        self.next_realm += 1;
        Ok(())
    }

    fn finish(self) -> Result<RollbackGlobalArchiveBarrier<Hash>, RollbackGlobalArchiveBarrierError> {
        if self.next_realm != self.plan.realms().len() {
            return Err(RollbackGlobalArchiveBarrierError::ParticipantMissing);
        }
        RollbackGlobalArchiveBarrier::try_from_fields(
            self.plan.target().network_id(),
            self.plan.target().chain_epoch().get(),
            *self.readiness.archiving_head(),
            *self.plan.target(),
            *self.plan.digest(),
            self.plan.topology_revision(),
            *self.plan.topology_digest(),
            *self.readiness.participant_completion_slot(),
            *self.readiness.participant_completion_digest(),
            *self.readiness.target_restore_slot(),
            *self.readiness.target_restore_digest(),
            *self.readiness.digest(),
            u64::try_from(self.plan.participant_count())
                .map_err(|_| RollbackGlobalArchiveBarrierError::LengthOverflow)?,
            self.total_entry_count,
            self.participant_set.finalize().into(),
            self.store_fingerprint,
        )
    }
}

/// Non-Clone storage receipt.  Later PONR code must revalidate this exact
/// object; the public barrier model alone is never accepted as write authority.
#[derive(Debug)]
pub(super) struct PersistedRollbackGlobalArchiveBarrier<Hash> {
    store_fingerprint: [u8; 32],
    barrier: RollbackGlobalArchiveBarrier<Hash>,
}

impl<Hash> PersistedRollbackGlobalArchiveBarrier<Hash> {
    pub(super) const fn barrier(&self) -> &RollbackGlobalArchiveBarrier<Hash> {
        &self.barrier
    }
}

struct ScyllaRollbackGlobalArchiveBarrierStore {
    session: Arc<Session>,
    fingerprint: [u8; 32],
    insert: PreparedStatement,
    read_row: PreparedStatement,
    read_fragment: PreparedStatement,
}

impl ScyllaRollbackGlobalArchiveBarrierStore {
    async fn prepare(
        session: Arc<Session>,
        keyspace: &CqlKeyspaceName,
    ) -> Result<Self, RollbackGlobalArchiveBarrierError> {
        let table = format!(
            "{}.{}",
            keyspace.as_str(),
            COORDINATOR_ROLLBACK_SUFFIX_ARCHIVE_TABLE,
        );
        let insert = INSERT_TEMPLATE.replace("{table}", &table);
        let read_row = READ_ROW_TEMPLATE.replace("{table}", &table);
        let read_fragment = READ_FRAGMENT_TEMPLATE.replace("{table}", &table);
        let mut hasher = Sha256::new();
        hasher.update(STORE_FINGERPRINT_DOMAIN);
        hasher.update(keyspace.as_str().as_bytes());
        hasher.update(insert.as_bytes());
        hasher.update(read_row.as_bytes());
        hasher.update(read_fragment.as_bytes());
        Ok(Self {
            insert: prepare_lwt(&session, &insert).await?,
            read_row: prepare_read(&session, &read_row).await?,
            read_fragment: prepare_read(&session, &read_fragment).await?,
            fingerprint: hasher.finalize().into(),
            session,
        })
    }

    const fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    async fn persist_and_readback<Hash: Q256BitHash>(
        &self,
        barrier: RollbackGlobalArchiveBarrier<Hash>,
    ) -> Result<PersistedRollbackGlobalArchiveBarrier<Hash>, RollbackGlobalArchiveBarrierError> {
        let coordinates = ArchiveCoordinates::try_from_barrier(&barrier)?;
        for fragment in archive_fragments(barrier.canonical_bytes(), barrier.digest())? {
            let execution = self.session.execute_unpaged(
                &self.insert,
                (
                    coordinates.network,
                    coordinates.chain_epoch,
                    coordinates.participant_plan_digest.as_slice(),
                    BARRIER_KEY_DOMAIN,
                    coordinates.row_slot.as_slice(),
                    fragment.index,
                    ARCHIVE_REVISION,
                    fragment.count,
                    fragment.row_bytes,
                    fragment.payload.as_slice(),
                    fragment.digest.as_slice(),
                    fragment.row_digest.as_slice(),
                ),
            ).await;
            match execution {
                Ok(result) => {
                    if !decode_applied(result)?
                        && self.read_fragment(&coordinates, fragment.index).await?.as_ref()
                            != Some(&fragment)
                    {
                        return Err(RollbackGlobalArchiveBarrierError::Conflict);
                    }
                }
                Err(error) => match self.read_fragment(&coordinates, fragment.index).await {
                    Ok(Some(current)) if current == fragment => {}
                    Ok(_) => return Err(RollbackGlobalArchiveBarrierError::Indeterminate(error.to_string())),
                    Err(read) => return Err(RollbackGlobalArchiveBarrierError::Indeterminate(
                        format!("execute={error}; read={read}"),
                    )),
                },
            }
        }
        let current = self.read_exact::<Hash>(&barrier).await?
            .ok_or(RollbackGlobalArchiveBarrierError::MissingAfterPersist)?;
        if current != barrier {
            return Err(RollbackGlobalArchiveBarrierError::Conflict);
        }
        Ok(PersistedRollbackGlobalArchiveBarrier {
            store_fingerprint: self.fingerprint,
            barrier: current,
        })
    }

    async fn read_exact<Hash: Q256BitHash>(
        &self,
        expected: &RollbackGlobalArchiveBarrier<Hash>,
    ) -> Result<Option<RollbackGlobalArchiveBarrier<Hash>>, RollbackGlobalArchiveBarrierError> {
        let coordinates = ArchiveCoordinates::try_from_barrier(expected)?;
        let rows = self.session.execute_unpaged(
            &self.read_row,
            (
                coordinates.network,
                coordinates.chain_epoch,
                coordinates.participant_plan_digest.as_slice(),
                BARRIER_KEY_DOMAIN,
                coordinates.row_slot.as_slice(),
            ),
        ).await.map_err(cql)?.into_rows_result().map_err(cql)?
            .rows::<(
                Option<i32>, Option<i64>, Option<i32>, Option<i64>,
                Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>,
            )>().map_err(cql)?.collect::<Result<Vec<_>, _>>().map_err(cql)?;
        if rows.is_empty() {
            return Ok(None);
        }
        let mut fragments = Vec::with_capacity(rows.len());
        for (index, revision, count, row_bytes, payload, digest, row_digest) in rows {
            fragments.push(decode_fragment(
                index, revision, count, row_bytes, payload, digest, row_digest,
            )?);
        }
        let row_digest = fragments[0].row_digest;
        let bytes = reconstruct_fragments(fragments, &row_digest)?;
        let current = RollbackGlobalArchiveBarrier::decode_canonical(&bytes)?;
        if current.slot() != expected.slot()
            || current.digest() != &row_digest
            || current.participant_plan_digest() != expected.participant_plan_digest()
        {
            return Err(RollbackGlobalArchiveBarrierError::Conflict);
        }
        Ok(Some(current))
    }

    async fn revalidate<Hash: Q256BitHash>(
        &self,
        receipt: &PersistedRollbackGlobalArchiveBarrier<Hash>,
    ) -> Result<(), RollbackGlobalArchiveBarrierError> {
        if receipt.store_fingerprint != self.fingerprint {
            return Err(RollbackGlobalArchiveBarrierError::StoreFingerprintMismatch);
        }
        match self.read_exact(&receipt.barrier).await? {
            Some(current) if current == receipt.barrier => Ok(()),
            Some(_) => Err(RollbackGlobalArchiveBarrierError::Conflict),
            None => Err(RollbackGlobalArchiveBarrierError::MissingAfterPersist),
        }
    }

    async fn read_fragment(
        &self,
        coordinates: &ArchiveCoordinates,
        index: i32,
    ) -> Result<Option<ArchiveFragment>, RollbackGlobalArchiveBarrierError> {
        self.session.execute_unpaged(
            &self.read_fragment,
            (
                coordinates.network,
                coordinates.chain_epoch,
                coordinates.participant_plan_digest.as_slice(),
                BARRIER_KEY_DOMAIN,
                coordinates.row_slot.as_slice(),
                index,
            ),
        ).await.map_err(cql)?.into_rows_result().map_err(cql)?
            .maybe_first_row::<(
                Option<i64>, Option<i32>, Option<i64>, Option<Vec<u8>>,
                Option<Vec<u8>>, Option<Vec<u8>>,
            )>().map_err(cql)?
            .map(|(revision, count, row_bytes, payload, digest, row_digest)| {
                decode_fragment(Some(index), revision, count, row_bytes, payload, digest, row_digest)
            }).transpose()
    }
}

/// Storage-owned composition over the Coordinator and all planned Realms.
/// It only persists/reconstructs the barrier; crossing to PONR is a later
/// separately gated operation.
pub(super) struct ScyllaRollbackGlobalArchiveBarrierOwner {
    session: Arc<Session>,
    canonical_head: Arc<ScyllaCanonicalHeadStore>,
    commit_sources: Arc<ScyllaCoordinatorCommitSourceStore>,
    participant_plans: Arc<ScyllaRollbackParticipantPlanStore>,
    realm: ScyllaRealmRollbackPhysicalArchiveOwner,
    coordinator_archive_keyspace: CqlKeyspaceName,
    coordinator_source_keyspace: CqlKeyspaceName,
    checkpoint_tree_height: u8,
}

impl ScyllaRollbackGlobalArchiveBarrierOwner {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        session: Arc<Session>,
        canonical_head: Arc<ScyllaCanonicalHeadStore>,
        commit_sources: Arc<ScyllaCoordinatorCommitSourceStore>,
        participant_plans: Arc<ScyllaRollbackParticipantPlanStore>,
        realm: ScyllaRealmRollbackPhysicalArchiveOwner,
        coordinator_archive_keyspace: CqlKeyspaceName,
        coordinator_source_keyspace: CqlKeyspaceName,
        checkpoint_tree_height: u8,
    ) -> Self {
        Self {
            session,
            canonical_head,
            commit_sources,
            participant_plans,
            realm,
            coordinator_archive_keyspace,
            coordinator_source_keyspace,
            checkpoint_tree_height,
        }
    }

    pub(super) async fn persist_or_recover<F, Hash, Hasher>(
        &mut self,
        network: NetworkId,
    ) -> Result<PersistedRollbackGlobalArchiveBarrier<Hash>, RollbackGlobalArchiveBarrierError>
    where
        F: QFelt64,
        Hash: Q256BitHash + QFHashBase<F>,
        Hasher: MerkleHasher<Hash> + FieldQHasher<F, Hash>,
    {
        let store = ScyllaRollbackGlobalArchiveBarrierStore::prepare(
            self.session.clone(),
            &self.coordinator_archive_keyspace,
        ).await?;
        let first = self.select_current::<F, Hash, Hasher>(network, store.fingerprint()).await?;
        let receipt = match store.read_exact(&first).await? {
            Some(current) if current == first => PersistedRollbackGlobalArchiveBarrier {
                store_fingerprint: store.fingerprint(),
                barrier: current,
            },
            Some(_) => return Err(RollbackGlobalArchiveBarrierError::Conflict),
            None => store.persist_and_readback(first.clone()).await?,
        };
        let second = self.select_current::<F, Hash, Hasher>(network, store.fingerprint()).await?;
        if second != first || receipt.barrier != second {
            return Err(RollbackGlobalArchiveBarrierError::ParticipantSetChanged);
        }
        store.revalidate(&receipt).await?;
        Ok(receipt)
    }

    async fn select_current<F, Hash, Hasher>(
        &mut self,
        network: NetworkId,
        store_fingerprint: [u8; 32],
    ) -> Result<RollbackGlobalArchiveBarrier<Hash>, RollbackGlobalArchiveBarrierError>
    where
        F: QFelt64,
        Hash: Q256BitHash + QFHashBase<F>,
        Hasher: MerkleHasher<Hash> + FieldQHasher<F, Hash>,
    {
        let head: StoredCanonicalHead<Hash> = match self
            .canonical_head
            .read(network)
            .await
            .map_err(backend)?
        {
            CanonicalHeadReadState::Current(head) => head,
            CanonicalHeadReadState::Uninitialized => {
                return Err(RollbackGlobalArchiveBarrierError::HeadMissing);
            }
        };
        let request = head.rollback_control().requested()
            .ok_or(RollbackGlobalArchiveBarrierError::NotArchiving)?;
        if !head.rollback_control().is_archiving() {
            return Err(RollbackGlobalArchiveBarrierError::NotArchiving);
        }
        let plan = self.participant_plans
            .read_participant_plan(network, request.plan_digest().as_bytes())
            .await.map_err(backend)?;
        let topology = self.participant_plans.read_current_topology(network).await
            .map_err(backend)?
            .ok_or(RollbackGlobalArchiveBarrierError::TopologyMissing)?;
        if !topology.snapshot().validates_plan(&plan) {
            return Err(RollbackGlobalArchiveBarrierError::TopologyChanged);
        }
        let mut coordinator = ScyllaCoordinatorCommitPhysicalArchiveOwner::new(
            self.session.clone(),
            self.canonical_head.clone(),
            self.commit_sources.clone(),
            self.coordinator_archive_keyspace.clone(),
            self.coordinator_source_keyspace.clone(),
            self.checkpoint_tree_height,
        );
        let readiness = coordinator
            .recover_pre_barrier_readiness::<F, Hash, Hasher>(network)
            .await?;
        let mut builder = RollbackGlobalArchiveBarrierBuilder::try_new(
            &plan,
            &readiness,
            store_fingerprint,
        )?;
        for participant in plan.realms() {
            let authority = AuthorityScope::Realm {
                realm_id: participant.realm_id(),
                realm_sub_id: participant.realm_sub_id(),
            };
            let completion = self.realm
                .recover_participant_completion(network, authority, &plan)
                .await?;
            builder.push_realm(completion.completion())?;
        }
        let barrier = builder.finish()?;
        let topology_after = self.participant_plans.read_current_topology(network).await
            .map_err(backend)?
            .ok_or(RollbackGlobalArchiveBarrierError::TopologyMissing)?;
        let plan_after = self.participant_plans
            .read_participant_plan(network, plan.digest())
            .await.map_err(backend)?;
        let head_after: StoredCanonicalHead<Hash> = match self
            .canonical_head
            .read(network)
            .await
            .map_err(backend)?
        {
            CanonicalHeadReadState::Current(head) => head,
            CanonicalHeadReadState::Uninitialized => {
                return Err(RollbackGlobalArchiveBarrierError::HeadMissing);
            }
        };
        if head_after != head
            || plan_after != plan
            || topology_after.snapshot() != topology.snapshot()
        {
            return Err(RollbackGlobalArchiveBarrierError::ParticipantSetChanged);
        }
        Ok(barrier)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ArchiveCoordinates {
    network: i64,
    chain_epoch: i64,
    participant_plan_digest: [u8; 32],
    row_slot: [u8; 32],
}

impl ArchiveCoordinates {
    fn try_from_barrier<Hash: Q256BitHash>(
        barrier: &RollbackGlobalArchiveBarrier<Hash>,
    ) -> Result<Self, RollbackGlobalArchiveBarrierError> {
        Ok(Self {
            network: i64::from(barrier.network.chain_id()),
            chain_epoch: i64::try_from(barrier.old_chain_epoch)
                .map_err(|_| RollbackGlobalArchiveBarrierError::IntegerOutOfCqlRange)?,
            participant_plan_digest: barrier.participant_plan_digest,
            row_slot: barrier.slot,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ArchiveFragment {
    index: i32,
    count: i32,
    row_bytes: i64,
    payload: Vec<u8>,
    digest: [u8; 32],
    row_digest: [u8; 32],
}

fn archive_fragments(
    bytes: &[u8],
    row_digest: &[u8; 32],
) -> Result<Vec<ArchiveFragment>, RollbackGlobalArchiveBarrierError> {
    let count = bytes.len().div_ceil(MAX_FRAGMENT_BYTES);
    if count == 0 || count > MAX_FRAGMENTS {
        return Err(RollbackGlobalArchiveBarrierError::InvalidFragmentSet);
    }
    let count = i32::try_from(count)
        .map_err(|_| RollbackGlobalArchiveBarrierError::LengthOverflow)?;
    let row_bytes = i64::try_from(bytes.len())
        .map_err(|_| RollbackGlobalArchiveBarrierError::LengthOverflow)?;
    Ok(bytes.chunks(MAX_FRAGMENT_BYTES).enumerate().map(|(index, payload)| {
        let index = i32::try_from(index).expect("at most sixteen fragments");
        ArchiveFragment {
            index,
            count,
            row_bytes,
            payload: payload.to_vec(),
            digest: fragment_digest(row_digest, index, count, row_bytes, payload),
            row_digest: *row_digest,
        }
    }).collect())
}

fn decode_fragment(
    index: Option<i32>,
    revision: Option<i64>,
    count: Option<i32>,
    row_bytes: Option<i64>,
    payload: Option<Vec<u8>>,
    digest: Option<Vec<u8>>,
    row_digest: Option<Vec<u8>>,
) -> Result<ArchiveFragment, RollbackGlobalArchiveBarrierError> {
    let index = index.ok_or(RollbackGlobalArchiveBarrierError::MalformedRow)?;
    let count = count.ok_or(RollbackGlobalArchiveBarrierError::MalformedRow)?;
    let row_bytes = row_bytes.ok_or(RollbackGlobalArchiveBarrierError::MalformedRow)?;
    let payload = payload.ok_or(RollbackGlobalArchiveBarrierError::MalformedRow)?;
    let digest: [u8; 32] = digest
        .ok_or(RollbackGlobalArchiveBarrierError::MalformedRow)?
        .try_into().map_err(|_| RollbackGlobalArchiveBarrierError::MalformedRow)?;
    let row_digest: [u8; 32] = row_digest
        .ok_or(RollbackGlobalArchiveBarrierError::MalformedRow)?
        .try_into().map_err(|_| RollbackGlobalArchiveBarrierError::MalformedRow)?;
    if revision != Some(ARCHIVE_REVISION)
        || index < 0
        || count <= 0
        || count as usize > MAX_FRAGMENTS
        || index >= count
        || row_bytes <= 0
        || payload.is_empty()
        || payload.len() > MAX_FRAGMENT_BYTES
        || fragment_digest(&row_digest, index, count, row_bytes, &payload) != digest
    {
        return Err(RollbackGlobalArchiveBarrierError::MalformedRow);
    }
    Ok(ArchiveFragment { index, count, row_bytes, payload, digest, row_digest })
}

fn reconstruct_fragments(
    mut fragments: Vec<ArchiveFragment>,
    row_digest: &[u8; 32],
) -> Result<Vec<u8>, RollbackGlobalArchiveBarrierError> {
    fragments.sort_unstable_by_key(|fragment| fragment.index);
    let first = fragments
        .first()
        .ok_or(RollbackGlobalArchiveBarrierError::InvalidFragmentSet)?;
    let first_count = first.count;
    let first_row_bytes = first.row_bytes;
    if first_count as usize != fragments.len() || &first.row_digest != row_digest {
        return Err(RollbackGlobalArchiveBarrierError::InvalidFragmentSet);
    }
    let expected_bytes = usize::try_from(first_row_bytes)
        .map_err(|_| RollbackGlobalArchiveBarrierError::InvalidFragmentSet)?;
    let mut bytes = Vec::with_capacity(expected_bytes);
    for (position, fragment) in fragments.into_iter().enumerate() {
        if fragment.index as usize != position
            || fragment.count != first_count
            || fragment.row_bytes != first_row_bytes
            || fragment.row_digest != *row_digest
        {
            return Err(RollbackGlobalArchiveBarrierError::InvalidFragmentSet);
        }
        bytes.extend_from_slice(&fragment.payload);
    }
    if bytes.len() != expected_bytes || barrier_digest(&bytes[..bytes.len().saturating_sub(32)]) != *row_digest {
        return Err(RollbackGlobalArchiveBarrierError::InvalidFragmentSet);
    }
    Ok(bytes)
}

fn barrier_slot<Hash: Q256BitHash>(
    network: NetworkId,
    old_chain_epoch: u64,
    archiving_head: &StoredCanonicalHead<Hash>,
    target: &CanonicalChainRef<Hash>,
    participant_plan_digest: &[u8; 32],
    topology_revision: u64,
    topology_digest: &[u8; 32],
    store_fingerprint: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SLOT_DOMAIN);
    hasher.update(network.chain_id().to_be_bytes());
    hasher.update(old_chain_epoch.to_be_bytes());
    hasher.update(archiving_head.revision().as_i64().to_be_bytes());
    hasher.update(archiving_head.canonical_ref_bytes());
    hasher.update(archiving_head.rollback_control_bytes());
    hasher.update(target.to_canonical_bytes());
    hasher.update(participant_plan_digest);
    hasher.update(topology_revision.to_be_bytes());
    hasher.update(topology_digest);
    hasher.update(store_fingerprint);
    hasher.finalize().into()
}

fn barrier_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn fragment_digest(
    row_digest: &[u8; 32],
    index: i32,
    count: i32,
    row_bytes: i64,
    payload: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(FRAGMENT_DIGEST_DOMAIN);
    hasher.update(row_digest);
    hasher.update(index.to_be_bytes());
    hasher.update(count.to_be_bytes());
    hasher.update(row_bytes.to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

struct Cursor<'a> { bytes: &'a [u8], offset: usize }
impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self { Self { bytes, offset: 0 } }
    fn take(&mut self, length: usize) -> Result<&'a [u8], RollbackGlobalArchiveBarrierError> {
        let end = self.offset.checked_add(length)
            .ok_or(RollbackGlobalArchiveBarrierError::InvalidLength)?;
        let value = self.bytes.get(self.offset..end)
            .ok_or(RollbackGlobalArchiveBarrierError::Truncated)?;
        self.offset = end;
        Ok(value)
    }
    fn u16(&mut self) -> Result<u16, RollbackGlobalArchiveBarrierError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, RollbackGlobalArchiveBarrierError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, RollbackGlobalArchiveBarrierError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn i64(&mut self) -> Result<i64, RollbackGlobalArchiveBarrierError> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn array_32(&mut self) -> Result<[u8; 32], RollbackGlobalArchiveBarrierError> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    fn is_empty(&self) -> bool { self.offset == self.bytes.len() }
}

async fn prepare_read(
    session: &Session,
    cql_text: &str,
) -> Result<PreparedStatement, RollbackGlobalArchiveBarrierError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_lwt(
    session: &Session,
    cql_text: &str,
) -> Result<PreparedStatement, RollbackGlobalArchiveBarrierError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_applied(result: QueryResult) -> Result<bool, RollbackGlobalArchiveBarrierError> {
    let rows = result.into_rows_result().map_err(cql)?;
    let column = rows.column_specs().get_by_name("[applied]")
        .ok_or(RollbackGlobalArchiveBarrierError::MalformedRow)?;
    let row = rows.single_row::<Row>().map_err(cql)?;
    match row.columns.get(column.0) {
        Some(Some(CqlValue::Boolean(applied))) => Ok(*applied),
        _ => Err(RollbackGlobalArchiveBarrierError::MalformedRow),
    }
}

fn cql(error: impl fmt::Display) -> RollbackGlobalArchiveBarrierError {
    RollbackGlobalArchiveBarrierError::Backend(error.to_string())
}

fn backend(error: impl fmt::Display) -> RollbackGlobalArchiveBarrierError {
    RollbackGlobalArchiveBarrierError::Backend(error.to_string())
}

#[derive(Debug)]
pub(super) enum RollbackGlobalArchiveBarrierError {
    Backend(String),
    Canonical(String),
    Plan(String),
    HeadMissing,
    TopologyMissing,
    TopologyChanged,
    NotArchiving,
    BindingMismatch,
    UnexpectedParticipant,
    ParticipantMissing,
    ParticipantSetChanged,
    CountOverflow,
    LengthOverflow,
    IntegerOutOfCqlRange,
    InvalidLength,
    InvalidMagic,
    UnknownVersion(u16),
    Truncated,
    TrailingBytes,
    NonCanonicalEncoding,
    InvalidFragmentSet,
    MalformedRow,
    Conflict,
    Indeterminate(String),
    MissingAfterPersist,
    StoreFingerprintMismatch,
    Coordinator(CoordinatorCommitPhysicalArchiveOwnerError),
    Realm(RealmRollbackPhysicalArchiveOwnerError),
}

impl From<CoordinatorCommitPhysicalArchiveOwnerError> for RollbackGlobalArchiveBarrierError {
    fn from(value: CoordinatorCommitPhysicalArchiveOwnerError) -> Self { Self::Coordinator(value) }
}
impl From<RealmRollbackPhysicalArchiveOwnerError> for RollbackGlobalArchiveBarrierError {
    fn from(value: RealmRollbackPhysicalArchiveOwnerError) -> Self { Self::Realm(value) }
}
impl fmt::Display for RollbackGlobalArchiveBarrierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "global rollback archive barrier error: {self:?}")
    }
}
impl Error for RollbackGlobalArchiveBarrierError {}

#[cfg(test)]
mod tests {
    use parth_core::PHash;
    use psy_core::constants::chain_id::PsyChainNetworkType;
    use psy_data::protocol::canonical_chain::{
        ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef,
    };
    use psy_node_core::store::{
        rollback_control::RollbackControlState,
        timestamp::{CommitWriteTimestampUs, TimestampFenceWindow},
    };

    use super::*;

    fn chain(epoch: u64, height: u64, seed: u64) -> CanonicalChainRef<PHash> {
        CanonicalChainRef::new(
            NetworkId::from_network_type(PsyChainNetworkType::LocalDevnet),
            ChainEpoch::new(epoch),
            CheckpointRef::new(
                CheckpointId::new(height),
                CheckpointHash::from_last_chain_hash(PHash::from_values(
                    seed,
                    seed + 1,
                    seed + 2,
                    seed + 3,
                )),
            ),
        )
    }

    fn barrier(participant_set_digest: [u8; 32]) -> RollbackGlobalArchiveBarrier<PHash> {
        let expected_ref = chain(4, 10, 20);
        let expected = StoredCanonicalHead::decode_persisted(
            expected_ref.network_id(),
            7,
            &expected_ref.to_canonical_bytes(),
            &RollbackControlState::<PHash>::Idle.to_canonical_bytes(),
        )
        .unwrap();
        let target = chain(4, 7, 30);
        let plan = RollbackParticipantPlan::try_new(
            expected,
            target,
            TimestampFenceWindow::try_new(
                CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
                1_001,
                1_002,
            )
            .unwrap(),
            9,
            [1; 32],
            vec![RollbackRealmParticipant::new(3, 4)],
        )
        .unwrap();
        let requested = CanonicalHeadTransition::start_rollback(
            *plan.expected_head(),
            plan.rollback_request().unwrap(),
        )
        .unwrap();
        let archiving = CanonicalHeadTransition::begin_rollback_archive(
            *requested.candidate(),
        )
        .unwrap();
        RollbackGlobalArchiveBarrier::try_from_fields(
            target.network_id(),
            target.chain_epoch().get(),
            *archiving.candidate(),
            target,
            *plan.digest(),
            plan.topology_revision(),
            *plan.topology_digest(),
            [2; 32],
            [3; 32],
            [4; 32],
            [5; 32],
            [6; 32],
            2,
            11,
            participant_set_digest,
            [8; 32],
        )
        .unwrap()
    }

    #[test]
    fn barrier_codec_is_strict_and_content_conflicts_at_one_slot() {
        let first = barrier([7; 32]);
        let different = barrier([9; 32]);
        assert_eq!(first.slot(), different.slot());
        assert_ne!(first.digest(), different.digest());
        assert_eq!(
            RollbackGlobalArchiveBarrier::decode_canonical(first.canonical_bytes()).unwrap(),
            first,
        );

        let mut corrupt = first.canonical_bytes().to_vec();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(matches!(
            RollbackGlobalArchiveBarrier::<PHash>::decode_canonical(&corrupt),
            Err(RollbackGlobalArchiveBarrierError::NonCanonicalEncoding),
        ));
        let mut trailing = first.canonical_bytes().to_vec();
        trailing.push(0);
        assert!(matches!(
            RollbackGlobalArchiveBarrier::<PHash>::decode_canonical(&trailing),
            Err(RollbackGlobalArchiveBarrierError::TrailingBytes),
        ));
    }

    #[test]
    fn barrier_fragment_reconstruction_rejects_missing_extra_and_tamper() {
        let barrier = barrier([7; 32]);
        let fragments = archive_fragments(barrier.canonical_bytes(), barrier.digest()).unwrap();
        assert_eq!(
            reconstruct_fragments(fragments.clone(), barrier.digest()).unwrap(),
            barrier.canonical_bytes(),
        );
        assert!(reconstruct_fragments(Vec::new(), barrier.digest()).is_err());
        let mut extra = fragments.clone();
        extra.push(fragments[0].clone());
        assert!(reconstruct_fragments(extra, barrier.digest()).is_err());
        let mut tampered = fragments;
        tampered[0].payload[0] ^= 1;
        assert!(reconstruct_fragments(tampered, barrier.digest()).is_err());
    }

    #[test]
    fn participant_set_is_streamed_and_barrier_is_fixed_size() {
        assert_eq!(BARRIER_KEY_DOMAIN, -3);
        assert!(MAX_BARRIER_BYTES < MAX_FRAGMENT_BYTES);
        let source = include_str!("rollback_global_archive_barrier.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("for participant in plan.realms()"));
        assert!(!production.contains("Vec<RealmRollbackParticipantCompletion"));
    }

    #[test]
    fn barrier_owner_has_no_delete_restore_or_head_transition() {
        let source = include_str!("rollback_global_archive_barrier.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in [
            "delete_hot_suffix(",
            "execute_delete",
            "restore_target(",
            "begin_rollback_delete(",
            "complete_rollback(",
            "compare_and_set(",
        ] {
            assert!(!production.contains(forbidden), "forbidden {forbidden}");
        }
        assert!(production.contains("recover_pre_barrier_readiness"));
        assert!(production.contains("recover_participant_completion"));
        assert!(production.contains("persist_and_readback"));
    }
}
