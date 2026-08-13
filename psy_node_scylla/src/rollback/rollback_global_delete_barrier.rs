//! Durable all-participant delete-completion barrier.
//!
//! This is the second global rollback barrier.  It is written only after the
//! Coordinator and every plan-ordered Realm have immutable, exact post-delete
//! completion rows.  The barrier is still inert: target-head publication is a
//! separate operation that must freshly revalidate this row and all selected
//! participant completions.

#![allow(dead_code)]

use std::{collections::BTreeSet, error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::canonical_chain::{
    CanonicalChainRef, NetworkId, CANONICAL_CHAIN_REF_V1_LEN,
};
use psy_node_core::store::{
    canonical_head::StoredCanonicalHead,
    rollback_control::RollbackControlState,
    timestamp::NewBranchWriteTimestampUs,
};
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{prepared::PreparedStatement, Consistency, SerialConsistency},
    value::{CqlValue, Row},
};
use sha2::{Digest, Sha256};

use super::{
    coordinator_rollback_archive_store::COORDINATOR_ROLLBACK_SUFFIX_ARCHIVE_TABLE,
    coordinator_rollback_delete_completion_store::{
        CoordinatorRollbackDeleteCompletion,
        PersistedCoordinatorRollbackDeleteCompletion,
    },
    realm_rollback_delete_completion::RealmRollbackDeleteCompletion,
    realm_rollback_physical_archive_store::PersistedRealmRollbackDeleteCompletion,
    rollback_global_archive_barrier::DeletingRollbackGlobalArchiveBarrier,
    CqlKeyspaceName,
};

const KEY_DOMAIN: i16 = -7;
const REVISION: i64 = 1;
const MAGIC: &[u8; 8] = b"PSYRGDB1";
const VERSION: u16 = 1;
const MAX_BYTES: usize = 64 * 1024;
const SLOT_DOMAIN: &[u8] = b"psy.rollback.global-delete-barrier-slot.v1\0";
const DIGEST_DOMAIN: &[u8] = b"psy.rollback.global-delete-barrier.v1\0";
const PARTICIPANT_SET_DOMAIN: &[u8] =
    b"psy.rollback.global-delete-barrier-participants.v1\0";
const FRAGMENT_DOMAIN: &[u8] =
    b"psy.rollback.global-delete-barrier-fragment.v1\0";
const STORE_DOMAIN: &[u8] = b"psy.rollback.global-delete-barrier-store.v1\0";

const INSERT_TEMPLATE: &str = "INSERT INTO {table} (network_chain_id, chain_epoch, participant_plan_digest, key_domain, row_slot, fragment_index, revision, fragment_count, row_bytes, fragment_payload, fragment_digest, row_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) IF NOT EXISTS";
const READ_TEMPLATE: &str = "SELECT fragment_index, revision, fragment_count, row_bytes, fragment_payload, fragment_digest, row_digest FROM {table} WHERE network_chain_id = ? AND chain_epoch = ? AND participant_plan_digest = ? AND key_domain = ? AND row_slot = ?";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RollbackGlobalDeleteBarrier<Hash> {
    deleting_head: StoredCanonicalHead<Hash>,
    target: CanonicalChainRef<Hash>,
    participant_plan_digest: [u8; 32],
    archive_barrier_store_fingerprint: [u8; 32],
    archive_barrier_slot: [u8; 32],
    archive_barrier_digest: [u8; 32],
    topology_revision: u64,
    topology_digest: [u8; 32],
    coordinator_completion_slot: [u8; 32],
    coordinator_completion_digest: [u8; 32],
    coordinator_post_state_digest: [u8; 32],
    realm_count: u64,
    participant_count: u64,
    total_physical_delete_count: u64,
    total_restored_row_count: u64,
    participant_set_digest: [u8; 32],
    store_fingerprint: [u8; 32],
    slot: [u8; 32],
    digest: [u8; 32],
    canonical_bytes: Vec<u8>,
}

impl<Hash: Q256BitHash> RollbackGlobalDeleteBarrier<Hash> {
    fn try_from_receipts(
        authority: &DeletingRollbackGlobalArchiveBarrier<Hash>,
        coordinator: &PersistedCoordinatorRollbackDeleteCompletion<Hash>,
        realms: &[PersistedRealmRollbackDeleteCompletion<Hash>],
        store_fingerprint: [u8; 32],
    ) -> Result<Self, RollbackGlobalDeleteBarrierError> {
        let plan = authority.participant_plan();
        let archive = authority.barrier();
        let coordinator = coordinator.completion();
        if coordinator.deleting_head() != authority.deleting_head()
            || coordinator.target() != archive.target()
            || coordinator.participant_plan_digest() != archive.participant_plan_digest()
            || coordinator.barrier_digest() != archive.digest()
            || realms.len() != plan.realms().len()
        {
            return Err(RollbackGlobalDeleteBarrierError::BindingMismatch);
        }
        let mut seen = BTreeSet::new();
        let mut total_physical_delete_count = coordinator.physical_delete_count();
        let mut total_restored_row_count = coordinator.restored_singleton_count();
        for (planned, receipt) in plan.realms().iter().zip(realms) {
            let completion = receipt.completion();
            if completion.authority()
                != (psy_data::protocol::chain_context::AuthorityScope::Realm {
                    realm_id: planned.realm_id(),
                    realm_sub_id: planned.realm_sub_id(),
                })
                || completion.target() != archive.target()
                || completion.participant_plan_digest() != archive.participant_plan_digest()
                || completion.barrier_digest() != archive.digest()
                || !seen.insert((*completion.slot(), *completion.digest()))
            {
                return Err(RollbackGlobalDeleteBarrierError::BindingMismatch);
            }
            total_physical_delete_count = total_physical_delete_count
                .checked_add(completion.physical_delete_count())
                .ok_or(RollbackGlobalDeleteBarrierError::CountOverflow)?;
            total_restored_row_count = total_restored_row_count
                .checked_add(completion.restored_row_count())
                .ok_or(RollbackGlobalDeleteBarrierError::CountOverflow)?;
        }
        let realm_count = u64::try_from(realms.len())
            .map_err(|_| RollbackGlobalDeleteBarrierError::CountOverflow)?;
        let participant_count = realm_count
            .checked_add(1)
            .ok_or(RollbackGlobalDeleteBarrierError::CountOverflow)?;
        if participant_count != archive.participant_count() {
            return Err(RollbackGlobalDeleteBarrierError::BindingMismatch);
        }
        let participant_set_digest = participant_set_digest(coordinator, realms);
        Self::try_from_fields(
            *authority.deleting_head(),
            *archive.target(),
            *archive.participant_plan_digest(),
            *archive.store_fingerprint(),
            *archive.slot(),
            *archive.digest(),
            archive.topology_revision(),
            *archive.topology_digest(),
            *coordinator.slot(),
            *coordinator.digest(),
            *coordinator.post_state_digest(),
            realm_count,
            participant_count,
            total_physical_delete_count,
            total_restored_row_count,
            participant_set_digest,
            store_fingerprint,
        )
    }

    pub(super) fn reconstruct_exact(
        authority: &DeletingRollbackGlobalArchiveBarrier<Hash>,
        coordinator: &PersistedCoordinatorRollbackDeleteCompletion<Hash>,
        realms: &[PersistedRealmRollbackDeleteCompletion<Hash>],
        store_fingerprint: [u8; 32],
    ) -> Result<Self, RollbackGlobalDeleteBarrierError> {
        Self::try_from_receipts(authority, coordinator, realms, store_fingerprint)
    }

    #[allow(clippy::too_many_arguments)]
    fn try_from_fields(
        deleting_head: StoredCanonicalHead<Hash>,
        target: CanonicalChainRef<Hash>,
        participant_plan_digest: [u8; 32],
        archive_barrier_store_fingerprint: [u8; 32],
        archive_barrier_slot: [u8; 32],
        archive_barrier_digest: [u8; 32],
        topology_revision: u64,
        topology_digest: [u8; 32],
        coordinator_completion_slot: [u8; 32],
        coordinator_completion_digest: [u8; 32],
        coordinator_post_state_digest: [u8; 32],
        realm_count: u64,
        participant_count: u64,
        total_physical_delete_count: u64,
        total_restored_row_count: u64,
        participant_set_digest: [u8; 32],
        store_fingerprint: [u8; 32],
    ) -> Result<Self, RollbackGlobalDeleteBarrierError> {
        let request = deleting_head.rollback_control().requested()
            .ok_or(RollbackGlobalDeleteBarrierError::BindingMismatch)?;
        if !matches!(deleting_head.rollback_control(), RollbackControlState::Deleting(_))
            || deleting_head.canonical_ref().network_id() != target.network_id()
            || deleting_head.canonical_ref().chain_epoch().get().checked_sub(1)
                != Some(target.chain_epoch().get())
            || request.target() != target.checkpoint()
            || request.plan_digest().as_bytes() != &participant_plan_digest
            || participant_count != realm_count.checked_add(1)
                .ok_or(RollbackGlobalDeleteBarrierError::CountOverflow)?
            || total_physical_delete_count == 0
            || total_restored_row_count > total_physical_delete_count
            || [
                participant_plan_digest,
                archive_barrier_store_fingerprint,
                archive_barrier_slot,
                archive_barrier_digest,
                topology_digest,
                coordinator_completion_slot,
                coordinator_completion_digest,
                coordinator_post_state_digest,
                participant_set_digest,
                store_fingerprint,
            ].contains(&[0; 32])
        {
            return Err(RollbackGlobalDeleteBarrierError::BindingMismatch);
        }
        let slot = barrier_slot(
            &deleting_head,
            &target,
            &participant_plan_digest,
            &archive_barrier_slot,
            &archive_barrier_digest,
            &store_fingerprint,
        );
        let mut barrier = Self {
            deleting_head,
            target,
            participant_plan_digest,
            archive_barrier_store_fingerprint,
            archive_barrier_slot,
            archive_barrier_digest,
            topology_revision,
            topology_digest,
            coordinator_completion_slot,
            coordinator_completion_digest,
            coordinator_post_state_digest,
            realm_count,
            participant_count,
            total_physical_delete_count,
            total_restored_row_count,
            participant_set_digest,
            store_fingerprint,
            slot,
            digest: [0; 32],
            canonical_bytes: Vec::new(),
        };
        let body = barrier.encode_body()?;
        barrier.digest = row_digest(&body);
        barrier.canonical_bytes = body;
        barrier.canonical_bytes.extend_from_slice(&barrier.digest);
        if barrier.canonical_bytes.len() > MAX_BYTES {
            return Err(RollbackGlobalDeleteBarrierError::RowTooLarge);
        }
        Ok(barrier)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, RollbackGlobalDeleteBarrierError> {
        if bytes.len() > MAX_BYTES || bytes.len() < 32 {
            return Err(RollbackGlobalDeleteBarrierError::MalformedRow);
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take(8)? != MAGIC {
            return Err(RollbackGlobalDeleteBarrierError::InvalidMagic);
        }
        let version = cursor.u16()?;
        if version != VERSION {
            return Err(RollbackGlobalDeleteBarrierError::UnknownVersion(version));
        }
        let network = NetworkId::try_from_chain_id(cursor.u32()?)
            .map_err(|error| RollbackGlobalDeleteBarrierError::Model(error.to_string()))?;
        let old_chain_epoch = cursor.u64()?;
        let head_revision = cursor.i64()?;
        let deleting_head = StoredCanonicalHead::decode_persisted(
            network,
            head_revision,
            cursor.bytes()?,
            cursor.bytes()?,
        ).map_err(|error| RollbackGlobalDeleteBarrierError::Model(error.to_string()))?;
        let target = CanonicalChainRef::from_canonical_bytes(
            cursor.take(CANONICAL_CHAIN_REF_V1_LEN)?,
        ).map_err(|error| RollbackGlobalDeleteBarrierError::Model(error.to_string()))?;
        if target.chain_epoch().get() != old_chain_epoch {
            return Err(RollbackGlobalDeleteBarrierError::BindingMismatch);
        }
        let participant_plan_digest = cursor.array_32()?;
        let archive_barrier_store_fingerprint = cursor.array_32()?;
        let archive_barrier_slot = cursor.array_32()?;
        let archive_barrier_digest = cursor.array_32()?;
        let topology_revision = cursor.u64()?;
        let topology_digest = cursor.array_32()?;
        let coordinator_completion_slot = cursor.array_32()?;
        let coordinator_completion_digest = cursor.array_32()?;
        let coordinator_post_state_digest = cursor.array_32()?;
        let realm_count = cursor.u64()?;
        let participant_count = cursor.u64()?;
        let total_physical_delete_count = cursor.u64()?;
        let total_restored_row_count = cursor.u64()?;
        let participant_set_digest = cursor.array_32()?;
        let store_fingerprint = cursor.array_32()?;
        let slot = cursor.array_32()?;
        let digest = cursor.array_32()?;
        if !cursor.is_empty() {
            return Err(RollbackGlobalDeleteBarrierError::TrailingBytes);
        }
        let decoded = Self::try_from_fields(
            deleting_head,
            target,
            participant_plan_digest,
            archive_barrier_store_fingerprint,
            archive_barrier_slot,
            archive_barrier_digest,
            topology_revision,
            topology_digest,
            coordinator_completion_slot,
            coordinator_completion_digest,
            coordinator_post_state_digest,
            realm_count,
            participant_count,
            total_physical_delete_count,
            total_restored_row_count,
            participant_set_digest,
            store_fingerprint,
        )?;
        if decoded.slot != slot || decoded.digest != digest || decoded.canonical_bytes != bytes {
            return Err(RollbackGlobalDeleteBarrierError::NonCanonicalEncoding);
        }
        Ok(decoded)
    }

    fn encode_body(&self) -> Result<Vec<u8>, RollbackGlobalDeleteBarrierError> {
        let mut bytes = Vec::with_capacity(1024);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.target.network_id().chain_id().to_be_bytes());
        bytes.extend_from_slice(&self.target.chain_epoch().get().to_be_bytes());
        bytes.extend_from_slice(&self.deleting_head.revision().as_i64().to_be_bytes());
        push_bytes(&mut bytes, &self.deleting_head.canonical_ref_bytes())?;
        push_bytes(&mut bytes, &self.deleting_head.rollback_control_bytes())?;
        bytes.extend_from_slice(&self.target.to_canonical_bytes());
        bytes.extend_from_slice(&self.participant_plan_digest);
        bytes.extend_from_slice(&self.archive_barrier_store_fingerprint);
        bytes.extend_from_slice(&self.archive_barrier_slot);
        bytes.extend_from_slice(&self.archive_barrier_digest);
        bytes.extend_from_slice(&self.topology_revision.to_be_bytes());
        bytes.extend_from_slice(&self.topology_digest);
        bytes.extend_from_slice(&self.coordinator_completion_slot);
        bytes.extend_from_slice(&self.coordinator_completion_digest);
        bytes.extend_from_slice(&self.coordinator_post_state_digest);
        bytes.extend_from_slice(&self.realm_count.to_be_bytes());
        bytes.extend_from_slice(&self.participant_count.to_be_bytes());
        bytes.extend_from_slice(&self.total_physical_delete_count.to_be_bytes());
        bytes.extend_from_slice(&self.total_restored_row_count.to_be_bytes());
        bytes.extend_from_slice(&self.participant_set_digest);
        bytes.extend_from_slice(&self.store_fingerprint);
        bytes.extend_from_slice(&self.slot);
        Ok(bytes)
    }

    pub(super) const fn deleting_head(&self) -> &StoredCanonicalHead<Hash> { &self.deleting_head }
    pub(super) const fn target(&self) -> &CanonicalChainRef<Hash> { &self.target }
    pub(super) const fn participant_plan_digest(&self) -> &[u8; 32] { &self.participant_plan_digest }
    pub(super) const fn archive_barrier_slot(&self) -> &[u8; 32] { &self.archive_barrier_slot }
    pub(super) const fn archive_barrier_digest(&self) -> &[u8; 32] { &self.archive_barrier_digest }
    pub(super) const fn coordinator_completion_slot(&self) -> &[u8; 32] { &self.coordinator_completion_slot }
    pub(super) const fn coordinator_completion_digest(&self) -> &[u8; 32] { &self.coordinator_completion_digest }
    pub(super) const fn participant_set_digest(&self) -> &[u8; 32] { &self.participant_set_digest }
    pub(super) const fn participant_count(&self) -> u64 { self.participant_count }
    pub(super) const fn slot(&self) -> &[u8; 32] { &self.slot }
    pub(super) const fn digest(&self) -> &[u8; 32] { &self.digest }
}

#[derive(Debug)]
pub(super) struct PersistedRollbackGlobalDeleteBarrier<Hash> {
    store_fingerprint: [u8; 32],
    barrier: RollbackGlobalDeleteBarrier<Hash>,
}

impl<Hash> PersistedRollbackGlobalDeleteBarrier<Hash> {
    pub(super) const fn barrier(&self) -> &RollbackGlobalDeleteBarrier<Hash> { &self.barrier }

    pub(super) const fn store_fingerprint(&self) -> &[u8; 32] {
        &self.store_fingerprint
    }
}

/// Non-Clone proof that one Realm completion was selected from the exact
/// plan-ordered set which produced the persisted global delete barrier.
/// Individual completion rows are not sufficient to authorize restoration.
#[derive(Debug)]
pub(super) struct SelectedRealmRollbackDeleteCompletion<Hash> {
    barrier_store_fingerprint: [u8; 32],
    barrier: RollbackGlobalDeleteBarrier<Hash>,
    completion: RealmRollbackDeleteCompletion<Hash>,
    new_branch_write: NewBranchWriteTimestampUs,
}

impl<Hash> SelectedRealmRollbackDeleteCompletion<Hash> {
    pub(super) const fn barrier(&self) -> &RollbackGlobalDeleteBarrier<Hash> {
        &self.barrier
    }

    pub(super) const fn completion(&self) -> &RealmRollbackDeleteCompletion<Hash> {
        &self.completion
    }

    /// Exact timestamp fence selected from the same persisted Coordinator
    /// delete plan which authorized the global archive/delete barriers.
    pub(super) const fn new_branch_write(&self) -> NewBranchWriteTimestampUs {
        self.new_branch_write
    }
}

pub(super) struct ScyllaRollbackGlobalDeleteBarrierStore {
    session: Arc<Session>,
    fingerprint: [u8; 32],
    insert: PreparedStatement,
    read: PreparedStatement,
}

impl ScyllaRollbackGlobalDeleteBarrierStore {
    pub(super) async fn prepare(
        session: Arc<Session>,
        keyspace: &CqlKeyspaceName,
    ) -> Result<Self, RollbackGlobalDeleteBarrierError> {
        let table = format!("{}.{}", keyspace.as_str(), COORDINATOR_ROLLBACK_SUFFIX_ARCHIVE_TABLE);
        let insert = INSERT_TEMPLATE.replace("{table}", &table);
        let read = READ_TEMPLATE.replace("{table}", &table);
        let mut hasher = Sha256::new();
        hasher.update(STORE_DOMAIN);
        hasher.update(keyspace.as_str().as_bytes());
        hasher.update(insert.as_bytes());
        hasher.update(read.as_bytes());
        Ok(Self {
            insert: prepare_lwt(&session, &insert).await?,
            read: prepare_read(&session, &read).await?,
            fingerprint: hasher.finalize().into(),
            session,
        })
    }

    pub(super) async fn persist_or_recover<Hash: Q256BitHash>(
        &self,
        authority: &DeletingRollbackGlobalArchiveBarrier<Hash>,
        coordinator: &PersistedCoordinatorRollbackDeleteCompletion<Hash>,
        realms: &[PersistedRealmRollbackDeleteCompletion<Hash>],
    ) -> Result<PersistedRollbackGlobalDeleteBarrier<Hash>, RollbackGlobalDeleteBarrierError> {
        let barrier = RollbackGlobalDeleteBarrier::try_from_receipts(
            authority, coordinator, realms, self.fingerprint,
        )?;
        if let Some(current) = self.read_exact(&barrier).await? {
            if current != barrier { return Err(RollbackGlobalDeleteBarrierError::Conflict); }
            return Ok(PersistedRollbackGlobalDeleteBarrier {
                store_fingerprint: self.fingerprint,
                barrier: current,
            });
        }
        let row_bytes = i64::try_from(barrier.canonical_bytes.len())
            .map_err(|_| RollbackGlobalDeleteBarrierError::LengthOverflow)?;
        let fragment = fragment_digest(barrier.digest(), row_bytes, &barrier.canonical_bytes);
        let execution = self.session.execute_unpaged(
            &self.insert,
            (
                i64::from(barrier.target.network_id().chain_id()),
                i64::try_from(barrier.target.chain_epoch().get())
                    .map_err(|_| RollbackGlobalDeleteBarrierError::IntegerOutOfCqlRange)?,
                barrier.participant_plan_digest.as_slice(),
                KEY_DOMAIN,
                barrier.slot.as_slice(),
                0_i32,
                REVISION,
                1_i32,
                row_bytes,
                barrier.canonical_bytes.as_slice(),
                fragment.as_slice(),
                barrier.digest.as_slice(),
            ),
        ).await;
        match execution {
            Ok(result) => {
                if !decode_applied(result)? {
                    match self.read_exact(&barrier).await? {
                        Some(current) if current == barrier => {}
                        _ => return Err(RollbackGlobalDeleteBarrierError::Conflict),
                    }
                }
            }
            Err(error) => match self.read_exact(&barrier).await {
                Ok(Some(current)) if current == barrier => {}
                Ok(_) => return Err(RollbackGlobalDeleteBarrierError::Indeterminate(error.to_string())),
                Err(read) => return Err(RollbackGlobalDeleteBarrierError::Indeterminate(
                    format!("execute={error}; read={read}"),
                )),
            },
        }
        let current = self.read_exact(&barrier).await?
            .ok_or(RollbackGlobalDeleteBarrierError::MissingAfterPersist)?;
        if current != barrier { return Err(RollbackGlobalDeleteBarrierError::Conflict); }
        Ok(PersistedRollbackGlobalDeleteBarrier {
            store_fingerprint: self.fingerprint,
            barrier: current,
        })
    }

    pub(super) async fn revalidate<Hash: Q256BitHash>(
        &self,
        receipt: &PersistedRollbackGlobalDeleteBarrier<Hash>,
    ) -> Result<(), RollbackGlobalDeleteBarrierError> {
        if receipt.store_fingerprint != self.fingerprint {
            return Err(RollbackGlobalDeleteBarrierError::StoreFingerprintMismatch);
        }
        match self.read_exact(&receipt.barrier).await? {
            Some(current) if current == receipt.barrier => Ok(()),
            Some(_) => Err(RollbackGlobalDeleteBarrierError::Conflict),
            None => Err(RollbackGlobalDeleteBarrierError::MissingAfterPersist),
        }
    }

    /// Select one Realm only after reconstructing the complete barrier from
    /// the same Coordinator completion and plan-ordered Realm completion set.
    /// This closes the gap where an individually valid but non-member Realm
    /// completion could otherwise be presented to a target restore executor.
    pub(super) async fn select_realm<Hash: Q256BitHash>(
        &self,
        receipt: &PersistedRollbackGlobalDeleteBarrier<Hash>,
        authority: &DeletingRollbackGlobalArchiveBarrier<Hash>,
        coordinator: &PersistedCoordinatorRollbackDeleteCompletion<Hash>,
        realms: &[PersistedRealmRollbackDeleteCompletion<Hash>],
        index: usize,
    ) -> Result<SelectedRealmRollbackDeleteCompletion<Hash>, RollbackGlobalDeleteBarrierError> {
        self.revalidate(receipt).await?;
        let reconstructed = RollbackGlobalDeleteBarrier::try_from_receipts(
            authority,
            coordinator,
            realms,
            self.fingerprint,
        )?;
        if reconstructed != receipt.barrier {
            return Err(RollbackGlobalDeleteBarrierError::BindingMismatch);
        }
        let selected = realms
            .get(index)
            .ok_or(RollbackGlobalDeleteBarrierError::BindingMismatch)?;
        let planned = authority
            .participant_plan()
            .realms()
            .get(index)
            .ok_or(RollbackGlobalDeleteBarrierError::BindingMismatch)?;
        let completion = selected.completion();
        if completion.authority()
            != (psy_data::protocol::chain_context::AuthorityScope::Realm {
                realm_id: planned.realm_id(),
                realm_sub_id: planned.realm_sub_id(),
            })
        {
            return Err(RollbackGlobalDeleteBarrierError::BindingMismatch);
        }
        Ok(SelectedRealmRollbackDeleteCompletion {
            barrier_store_fingerprint: self.fingerprint,
            barrier: reconstructed,
            completion: completion.clone(),
            new_branch_write: authority
                .delete_plan()
                .plan()
                .fence_window()
                .new_branch_write(),
        })
    }

    pub(super) async fn revalidate_selected_realm<Hash: Q256BitHash>(
        &self,
        selected: &SelectedRealmRollbackDeleteCompletion<Hash>,
    ) -> Result<(), RollbackGlobalDeleteBarrierError> {
        if selected.barrier_store_fingerprint != self.fingerprint {
            return Err(RollbackGlobalDeleteBarrierError::StoreFingerprintMismatch);
        }
        let expected = PersistedRollbackGlobalDeleteBarrier {
            store_fingerprint: selected.barrier_store_fingerprint,
            barrier: selected.barrier.clone(),
        };
        self.revalidate(&expected).await?;
        if selected.completion.target() != selected.barrier.target()
            || selected.completion.participant_plan_digest()
                != selected.barrier.participant_plan_digest()
            || selected.completion.barrier_digest()
                != selected.barrier.archive_barrier_digest()
            || selected.new_branch_write
                != selected
                    .barrier
                    .deleting_head()
                    .rollback_control()
                    .requested()
                    .ok_or(RollbackGlobalDeleteBarrierError::BindingMismatch)?
                    .fence_window()
                    .new_branch_write()
        {
            return Err(RollbackGlobalDeleteBarrierError::BindingMismatch);
        }
        Ok(())
    }

    async fn read_exact<Hash: Q256BitHash>(
        &self,
        expected: &RollbackGlobalDeleteBarrier<Hash>,
    ) -> Result<Option<RollbackGlobalDeleteBarrier<Hash>>, RollbackGlobalDeleteBarrierError> {
        let rows = self.session.execute_unpaged(
            &self.read,
            (
                i64::from(expected.target.network_id().chain_id()),
                i64::try_from(expected.target.chain_epoch().get())
                    .map_err(|_| RollbackGlobalDeleteBarrierError::IntegerOutOfCqlRange)?,
                expected.participant_plan_digest.as_slice(),
                KEY_DOMAIN,
                expected.slot.as_slice(),
            ),
        ).await.map_err(cql)?.into_rows_result().map_err(cql)?
            .rows::<(
                Option<i32>, Option<i64>, Option<i32>, Option<i64>,
                Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>,
            )>().map_err(cql)?.collect::<Result<Vec<_>, _>>().map_err(cql)?;
        if rows.is_empty() { return Ok(None); }
        if rows.len() != 1 { return Err(RollbackGlobalDeleteBarrierError::MalformedRow); }
        let (index, revision, count, row_bytes, payload, fragment, row_digest) =
            rows.into_iter().next().expect("one row");
        let payload = payload.ok_or(RollbackGlobalDeleteBarrierError::MalformedRow)?;
        let row_bytes = row_bytes.ok_or(RollbackGlobalDeleteBarrierError::MalformedRow)?;
        let fragment: [u8; 32] = fragment
            .ok_or(RollbackGlobalDeleteBarrierError::MalformedRow)?
            .try_into().map_err(|_| RollbackGlobalDeleteBarrierError::MalformedRow)?;
        let row_digest: [u8; 32] = row_digest
            .ok_or(RollbackGlobalDeleteBarrierError::MalformedRow)?
            .try_into().map_err(|_| RollbackGlobalDeleteBarrierError::MalformedRow)?;
        if index != Some(0)
            || revision != Some(REVISION)
            || count != Some(1)
            || row_bytes <= 0
            || usize::try_from(row_bytes).ok() != Some(payload.len())
            || fragment_digest(&row_digest, row_bytes, &payload) != fragment
        {
            return Err(RollbackGlobalDeleteBarrierError::MalformedRow);
        }
        let barrier = RollbackGlobalDeleteBarrier::decode_canonical(&payload)?;
        if barrier.digest != row_digest
            || barrier.participant_plan_digest != expected.participant_plan_digest
            || barrier.slot != expected.slot
        {
            return Err(RollbackGlobalDeleteBarrierError::Conflict);
        }
        Ok(Some(barrier))
    }
}

fn participant_set_digest<Hash: Q256BitHash>(
    coordinator: &CoordinatorRollbackDeleteCompletion<Hash>,
    realms: &[PersistedRealmRollbackDeleteCompletion<Hash>],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PARTICIPANT_SET_DOMAIN);
    hasher.update((realms.len() as u64 + 1).to_be_bytes());
    hasher.update(coordinator.slot());
    hasher.update(coordinator.digest());
    hasher.update(coordinator.post_state_digest());
    for realm in realms {
        let completion: &RealmRollbackDeleteCompletion<Hash> = realm.completion();
        let psy_data::protocol::chain_context::AuthorityScope::Realm {
            realm_id, realm_sub_id,
        } = completion.authority() else { unreachable!() };
        hasher.update(realm_id.to_be_bytes());
        hasher.update(realm_sub_id.to_be_bytes());
        hasher.update(completion.slot());
        hasher.update(completion.digest());
        hasher.update(completion.post_state_digest());
    }
    hasher.finalize().into()
}

fn barrier_slot<Hash: Q256BitHash>(
    deleting_head: &StoredCanonicalHead<Hash>,
    target: &CanonicalChainRef<Hash>,
    participant_plan_digest: &[u8; 32],
    archive_barrier_slot: &[u8; 32],
    archive_barrier_digest: &[u8; 32],
    store_fingerprint: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SLOT_DOMAIN);
    hasher.update(target.network_id().chain_id().to_be_bytes());
    hasher.update(target.chain_epoch().get().to_be_bytes());
    hasher.update(participant_plan_digest);
    hasher.update(deleting_head.revision().as_i64().to_be_bytes());
    hasher.update(deleting_head.canonical_ref_bytes());
    hasher.update(deleting_head.rollback_control_bytes());
    hasher.update(archive_barrier_slot);
    hasher.update(archive_barrier_digest);
    hasher.update(store_fingerprint);
    hasher.finalize().into()
}

fn row_digest(body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update(body);
    hasher.finalize().into()
}

fn fragment_digest(row_digest: &[u8; 32], row_bytes: i64, payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(FRAGMENT_DOMAIN);
    hasher.update(row_digest);
    hasher.update(0_i32.to_be_bytes());
    hasher.update(1_i32.to_be_bytes());
    hasher.update(row_bytes.to_be_bytes());
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

fn push_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), RollbackGlobalDeleteBarrierError> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| RollbackGlobalDeleteBarrierError::LengthOverflow)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

async fn prepare_read(session: &Session, query: &str) -> Result<PreparedStatement, RollbackGlobalDeleteBarrierError> {
    let mut statement = session.prepare(query).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}
async fn prepare_lwt(session: &Session, query: &str) -> Result<PreparedStatement, RollbackGlobalDeleteBarrierError> {
    let mut statement = session.prepare(query).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    statement.set_is_idempotent(true);
    Ok(statement)
}
fn decode_applied(result: QueryResult) -> Result<bool, RollbackGlobalDeleteBarrierError> {
    let rows = result.into_rows_result().map_err(cql)?;
    let column = rows.column_specs().get_by_name("[applied]")
        .ok_or(RollbackGlobalDeleteBarrierError::MalformedRow)?;
    let row = rows.single_row::<Row>().map_err(cql)?;
    match row.columns.get(column.0) {
        Some(Some(CqlValue::Boolean(applied))) => Ok(*applied),
        _ => Err(RollbackGlobalDeleteBarrierError::MalformedRow),
    }
}
fn cql(error: impl fmt::Display) -> RollbackGlobalDeleteBarrierError {
    RollbackGlobalDeleteBarrierError::Backend(error.to_string())
}

struct Cursor<'a> { bytes: &'a [u8], offset: usize }
impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self { Self { bytes, offset: 0 } }
    fn take(&mut self, length: usize) -> Result<&'a [u8], RollbackGlobalDeleteBarrierError> {
        let end = self.offset.checked_add(length)
            .ok_or(RollbackGlobalDeleteBarrierError::LengthOverflow)?;
        let value = self.bytes.get(self.offset..end)
            .ok_or(RollbackGlobalDeleteBarrierError::Truncated)?;
        self.offset = end;
        Ok(value)
    }
    fn u16(&mut self) -> Result<u16, RollbackGlobalDeleteBarrierError> { Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap())) }
    fn u32(&mut self) -> Result<u32, RollbackGlobalDeleteBarrierError> { Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap())) }
    fn u64(&mut self) -> Result<u64, RollbackGlobalDeleteBarrierError> { Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap())) }
    fn i64(&mut self) -> Result<i64, RollbackGlobalDeleteBarrierError> { Ok(i64::from_be_bytes(self.take(8)?.try_into().unwrap())) }
    fn array_32(&mut self) -> Result<[u8; 32], RollbackGlobalDeleteBarrierError> { Ok(self.take(32)?.try_into().unwrap()) }
    fn bytes(&mut self) -> Result<&'a [u8], RollbackGlobalDeleteBarrierError> {
        let length = usize::try_from(self.u32()?)
            .map_err(|_| RollbackGlobalDeleteBarrierError::LengthOverflow)?;
        self.take(length)
    }
    fn is_empty(&self) -> bool { self.offset == self.bytes.len() }
}

#[derive(Debug)]
pub(super) enum RollbackGlobalDeleteBarrierError {
    Backend(String),
    Model(String),
    BindingMismatch,
    CountOverflow,
    IntegerOutOfCqlRange,
    LengthOverflow,
    RowTooLarge,
    InvalidMagic,
    UnknownVersion(u16),
    MalformedRow,
    Truncated,
    TrailingBytes,
    NonCanonicalEncoding,
    Conflict,
    Indeterminate(String),
    MissingAfterPersist,
    StoreFingerprintMismatch,
}
impl fmt::Display for RollbackGlobalDeleteBarrierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "global rollback delete barrier error: {self:?}")
    }
}
impl Error for RollbackGlobalDeleteBarrierError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn barrier_store_is_append_only_and_has_no_head_publish_api() {
        let source = include_str!("rollback_global_delete_barrier.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains(" IF NOT EXISTS"));
        assert!(production.contains("participant_set_digest"));
        for forbidden in ["DELETE FROM", "UPDATE ", "complete_rollback(", "publish_head"] {
            assert!(!production.contains(forbidden), "forbidden {forbidden}");
        }
    }

    #[test]
    fn fragment_digest_commits_payload_and_row_identity() {
        assert_ne!(fragment_digest(&[1; 32], 3, b"abc"), fragment_digest(&[1; 32], 3, b"abd"));
        assert_ne!(fragment_digest(&[1; 32], 3, b"abc"), fragment_digest(&[2; 32], 3, b"abc"));
    }
}
