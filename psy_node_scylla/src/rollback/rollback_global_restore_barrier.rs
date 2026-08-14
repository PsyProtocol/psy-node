//! Durable all-Realm target-restore barrier.
//!
//! The delete barrier proves that every participant crossed the destructive
//! boundary. This later barrier proves that every plan-selected Realm reached
//! its exact post-delete control-row candidate. It is immutable evidence only:
//! publishing the Coordinator canonical target remains a separate, freshly
//! fenced operation.

#![allow(dead_code)]

use std::{collections::BTreeSet, error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::{CanonicalChainRef, NetworkId, CANONICAL_CHAIN_REF_V1_LEN},
    chain_context::AuthorityScope,
};
use psy_node_core::store::{
    canonical_head::{CanonicalHeadTransition, StoredCanonicalHead},
    rollback_runtime_rebuild::RollbackRuntimeRebuildDirective,
};
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{prepared::PreparedStatement, Consistency, SerialConsistency},
    value::{CqlValue, Row},
};
use sha2::{Digest, Sha256};

use super::{
    CqlKeyspaceName,
    coordinator_rollback_archive_store::COORDINATOR_ROLLBACK_SUFFIX_ARCHIVE_TABLE,
    coordinator_rollback_delete_completion_store::PersistedCoordinatorRollbackDeleteCompletion,
    realm_rollback_physical_archive_store::{
        PersistedRealmRollbackDeleteCompletion,
        PersistedRealmRollbackTargetRestoreCompletion,
    },
    rollback_global_archive_barrier::DeletingRollbackGlobalArchiveBarrier,
    rollback_global_delete_barrier::{
        PersistedRollbackGlobalDeleteBarrier, RollbackGlobalDeleteBarrier,
    },
};

const KEY_DOMAIN: i16 = -10;
const REVISION: i64 = 1;
const MAGIC: &[u8; 8] = b"PSYRGRB1";
const VERSION: u16 = 1;
const MAX_BYTES: usize = 16 * 1024;
const SLOT_DOMAIN: &[u8] = b"psy.rollback.global-restore-barrier-slot.v1\0";
const DIGEST_DOMAIN: &[u8] = b"psy.rollback.global-restore-barrier.v1\0";
const REALM_SET_DOMAIN: &[u8] = b"psy.rollback.global-restore-barrier-realms.v1\0";
const FRAGMENT_DOMAIN: &[u8] = b"psy.rollback.global-restore-barrier-fragment.v1\0";
const STORE_DOMAIN: &[u8] = b"psy.rollback.global-restore-barrier-store.v1\0";

const INSERT_TEMPLATE: &str = "INSERT INTO {table} (network_chain_id, chain_epoch, participant_plan_digest, key_domain, row_slot, fragment_index, revision, fragment_count, row_bytes, fragment_payload, fragment_digest, row_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) IF NOT EXISTS";
const READ_TEMPLATE: &str = "SELECT fragment_index, revision, fragment_count, row_bytes, fragment_payload, fragment_digest, row_digest FROM {table} WHERE network_chain_id = ? AND chain_epoch = ? AND participant_plan_digest = ? AND key_domain = ? AND row_slot = ?";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RollbackGlobalRestoreBarrier<Hash> {
    deleting_head: StoredCanonicalHead<Hash>,
    target: CanonicalChainRef<Hash>,
    participant_plan_digest: [u8; 32],
    delete_barrier_store_fingerprint: [u8; 32],
    delete_barrier_slot: [u8; 32],
    delete_barrier_digest: [u8; 32],
    coordinator_completion_slot: [u8; 32],
    coordinator_completion_digest: [u8; 32],
    coordinator_post_state_digest: [u8; 32],
    realm_archive_store_fingerprint: [u8; 32],
    realm_count: u64,
    realm_restore_set_digest: [u8; 32],
    store_fingerprint: [u8; 32],
    slot: [u8; 32],
    digest: [u8; 32],
    canonical_bytes: Vec<u8>,
}

impl<Hash: Q256BitHash> RollbackGlobalRestoreBarrier<Hash> {
    #[allow(clippy::too_many_arguments)]
    fn try_from_receipts(
        authority: &DeletingRollbackGlobalArchiveBarrier<Hash>,
        delete_barrier: &PersistedRollbackGlobalDeleteBarrier<Hash>,
        coordinator: &PersistedCoordinatorRollbackDeleteCompletion<Hash>,
        realm_deletes: &[PersistedRealmRollbackDeleteCompletion<Hash>],
        realm_restores: &[PersistedRealmRollbackTargetRestoreCompletion<Hash>],
        realm_archive_store_fingerprint: [u8; 32],
        store_fingerprint: [u8; 32],
    ) -> Result<Self, RollbackGlobalRestoreBarrierError> {
        let reconstructed = RollbackGlobalDeleteBarrier::reconstruct_exact(
            authority,
            coordinator,
            realm_deletes,
            *delete_barrier.store_fingerprint(),
        )?;
        if &reconstructed != delete_barrier.barrier()
            || realm_deletes.len() != authority.participant_plan().realms().len()
            || realm_restores.len() != realm_deletes.len()
            || coordinator.completion().slot() != reconstructed.coordinator_completion_slot()
            || coordinator.completion().digest() != reconstructed.coordinator_completion_digest()
        {
            return Err(RollbackGlobalRestoreBarrierError::BindingMismatch);
        }
        let mut seen = BTreeSet::new();
        let mut set = Sha256::new();
        set.update(REALM_SET_DOMAIN);
        set.update((realm_restores.len() as u64).to_be_bytes());
        for ((planned, deleted), restored) in authority
            .participant_plan()
            .realms()
            .iter()
            .zip(realm_deletes)
            .zip(realm_restores)
        {
            let expected_authority = AuthorityScope::Realm {
                realm_id: planned.realm_id(),
                realm_sub_id: planned.realm_sub_id(),
            };
            let deleted = deleted.completion();
            let restored = restored.completion();
            if deleted.authority() != expected_authority
                || restored.authority() != expected_authority
                || restored.global_target() != reconstructed.target()
                || restored.participant_plan_digest() != reconstructed.participant_plan_digest()
                || restored.global_barrier_slot() != reconstructed.slot()
                || restored.global_barrier_digest() != reconstructed.digest()
                || restored.delete_completion_slot() != deleted.slot()
                || restored.delete_completion_digest() != deleted.digest()
                || restored.archive_store_fingerprint() != &realm_archive_store_fingerprint
                || restored.restored_target().network_id() != reconstructed.target().network_id()
                || restored.restored_target().chain_epoch()
                    != reconstructed.deleting_head().canonical_ref().chain_epoch()
                || restored.restored_target().checkpoint().checkpoint_id()
                    != reconstructed.target().checkpoint().checkpoint_id()
                || !seen.insert((*restored.slot(), *restored.digest()))
            {
                return Err(RollbackGlobalRestoreBarrierError::BindingMismatch);
            }
            set.update(encode_authority(expected_authority));
            set.update(deleted.slot());
            set.update(deleted.digest());
            set.update(restored.slot());
            set.update(restored.digest());
            set.update(restored.restored_target().to_canonical_bytes());
            set.update(restored.final_rows_digest());
        }
        let realm_count = u64::try_from(realm_restores.len())
            .map_err(|_| RollbackGlobalRestoreBarrierError::CountOverflow)?;
        if realm_count.checked_add(1) != Some(reconstructed.participant_count()) {
            return Err(RollbackGlobalRestoreBarrierError::BindingMismatch);
        }
        Self::try_from_fields(
            *reconstructed.deleting_head(),
            *reconstructed.target(),
            *reconstructed.participant_plan_digest(),
            *delete_barrier.store_fingerprint(),
            *reconstructed.slot(),
            *reconstructed.digest(),
            *coordinator.completion().slot(),
            *coordinator.completion().digest(),
            *coordinator.completion().post_state_digest(),
            realm_archive_store_fingerprint,
            realm_count,
            set.finalize().into(),
            store_fingerprint,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn try_from_fields(
        deleting_head: StoredCanonicalHead<Hash>,
        target: CanonicalChainRef<Hash>,
        participant_plan_digest: [u8; 32],
        delete_barrier_store_fingerprint: [u8; 32],
        delete_barrier_slot: [u8; 32],
        delete_barrier_digest: [u8; 32],
        coordinator_completion_slot: [u8; 32],
        coordinator_completion_digest: [u8; 32],
        coordinator_post_state_digest: [u8; 32],
        realm_archive_store_fingerprint: [u8; 32],
        realm_count: u64,
        realm_restore_set_digest: [u8; 32],
        store_fingerprint: [u8; 32],
    ) -> Result<Self, RollbackGlobalRestoreBarrierError> {
        let request = deleting_head
            .rollback_control()
            .requested()
            .ok_or(RollbackGlobalRestoreBarrierError::BindingMismatch)?;
        if !matches!(
            deleting_head.rollback_control(),
            psy_node_core::store::rollback_control::RollbackControlState::Deleting(_)
        ) || deleting_head.canonical_ref().network_id() != target.network_id()
            || deleting_head.canonical_ref().chain_epoch().get().checked_sub(1)
                != Some(target.chain_epoch().get())
            || request.target() != target.checkpoint()
            || request.plan_digest().as_bytes() != &participant_plan_digest
            || realm_count == 0
            || [
                participant_plan_digest,
                delete_barrier_store_fingerprint,
                delete_barrier_slot,
                delete_barrier_digest,
                coordinator_completion_slot,
                coordinator_completion_digest,
                coordinator_post_state_digest,
                realm_archive_store_fingerprint,
                realm_restore_set_digest,
                store_fingerprint,
            ]
            .contains(&[0; 32])
        {
            return Err(RollbackGlobalRestoreBarrierError::BindingMismatch);
        }
        let slot = barrier_slot(
            &deleting_head,
            &target,
            &participant_plan_digest,
            &delete_barrier_slot,
            &delete_barrier_digest,
            &store_fingerprint,
        );
        let mut barrier = Self {
            deleting_head,
            target,
            participant_plan_digest,
            delete_barrier_store_fingerprint,
            delete_barrier_slot,
            delete_barrier_digest,
            coordinator_completion_slot,
            coordinator_completion_digest,
            coordinator_post_state_digest,
            realm_archive_store_fingerprint,
            realm_count,
            realm_restore_set_digest,
            store_fingerprint,
            slot,
            digest: [0; 32],
            canonical_bytes: Vec::new(),
        };
        let body = barrier.encode_body()?;
        barrier.digest = barrier_digest(&body);
        barrier.canonical_bytes = body;
        barrier.canonical_bytes.extend_from_slice(&barrier.digest);
        if barrier.canonical_bytes.len() > MAX_BYTES {
            return Err(RollbackGlobalRestoreBarrierError::RowTooLarge);
        }
        Ok(barrier)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, RollbackGlobalRestoreBarrierError> {
        if bytes.len() < 32 || bytes.len() > MAX_BYTES {
            return Err(RollbackGlobalRestoreBarrierError::MalformedRow);
        }
        let body_len = bytes.len() - 32;
        if barrier_digest(&bytes[..body_len]) != bytes[body_len..] {
            return Err(RollbackGlobalRestoreBarrierError::DigestMismatch);
        }
        let mut cursor = Cursor::new(&bytes[..body_len]);
        if cursor.take(8)? != MAGIC {
            return Err(RollbackGlobalRestoreBarrierError::MalformedRow);
        }
        let version = cursor.u16()?;
        if version != VERSION {
            return Err(RollbackGlobalRestoreBarrierError::UnknownVersion(version));
        }
        let network = NetworkId::try_from_chain_id(cursor.u32()?).map_err(model)?;
        let revision = cursor.i64()?;
        let head = StoredCanonicalHead::decode_persisted(
            network,
            revision,
            cursor.bytes()?,
            cursor.bytes()?,
        )
        .map_err(model)?;
        let target = CanonicalChainRef::from_canonical_bytes(
            cursor.take(CANONICAL_CHAIN_REF_V1_LEN)?,
        )
        .map_err(model)?;
        let decoded = Self::try_from_fields(
            head,
            target,
            cursor.array32()?,
            cursor.array32()?,
            cursor.array32()?,
            cursor.array32()?,
            cursor.array32()?,
            cursor.array32()?,
            cursor.array32()?,
            cursor.array32()?,
            cursor.u64()?,
            cursor.array32()?,
            cursor.array32()?,
        )?;
        let encoded_slot = cursor.array32()?;
        if !cursor.is_empty() || decoded.slot != encoded_slot || decoded.canonical_bytes != bytes {
            return Err(RollbackGlobalRestoreBarrierError::NonCanonicalEncoding);
        }
        Ok(decoded)
    }

    fn encode_body(&self) -> Result<Vec<u8>, RollbackGlobalRestoreBarrierError> {
        let mut out = Vec::with_capacity(1024);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_be_bytes());
        out.extend_from_slice(&self.target.network_id().chain_id().to_be_bytes());
        out.extend_from_slice(&self.deleting_head.revision().as_i64().to_be_bytes());
        push_bytes(&mut out, &self.deleting_head.canonical_ref_bytes())?;
        push_bytes(&mut out, &self.deleting_head.rollback_control_bytes())?;
        out.extend_from_slice(&self.target.to_canonical_bytes());
        for field in [
            &self.participant_plan_digest,
            &self.delete_barrier_store_fingerprint,
            &self.delete_barrier_slot,
            &self.delete_barrier_digest,
            &self.coordinator_completion_slot,
            &self.coordinator_completion_digest,
            &self.coordinator_post_state_digest,
            &self.realm_archive_store_fingerprint,
        ] {
            out.extend_from_slice(field);
        }
        out.extend_from_slice(&self.realm_count.to_be_bytes());
        out.extend_from_slice(&self.realm_restore_set_digest);
        out.extend_from_slice(&self.store_fingerprint);
        out.extend_from_slice(&self.slot);
        Ok(out)
    }

    pub(super) const fn deleting_head(&self) -> &StoredCanonicalHead<Hash> { &self.deleting_head }
    pub(super) const fn target(&self) -> &CanonicalChainRef<Hash> { &self.target }
    pub(super) const fn participant_plan_digest(&self) -> &[u8; 32] { &self.participant_plan_digest }
    pub(super) const fn delete_barrier_slot(&self) -> &[u8; 32] { &self.delete_barrier_slot }
    pub(super) const fn delete_barrier_digest(&self) -> &[u8; 32] { &self.delete_barrier_digest }
    pub(super) const fn coordinator_completion_slot(&self) -> &[u8; 32] { &self.coordinator_completion_slot }
    pub(super) const fn coordinator_completion_digest(&self) -> &[u8; 32] { &self.coordinator_completion_digest }
    pub(super) const fn realm_count(&self) -> u64 { self.realm_count }
    pub(super) const fn realm_restore_set_digest(&self) -> &[u8; 32] { &self.realm_restore_set_digest }
    pub(super) const fn slot(&self) -> &[u8; 32] { &self.slot }
    pub(super) const fn digest(&self) -> &[u8; 32] { &self.digest }
}

#[derive(Debug)]
pub(super) struct PersistedRollbackGlobalRestoreBarrier<Hash> {
    store_fingerprint: [u8; 32],
    barrier: RollbackGlobalRestoreBarrier<Hash>,
}

impl<Hash> PersistedRollbackGlobalRestoreBarrier<Hash> {
    pub(super) const fn barrier(&self) -> &RollbackGlobalRestoreBarrier<Hash> { &self.barrier }
    pub(super) const fn store_fingerprint(&self) -> &[u8; 32] { &self.store_fingerprint }
}

pub(super) struct ScyllaRollbackGlobalRestoreBarrierStore {
    session: Arc<Session>,
    fingerprint: [u8; 32],
    insert: PreparedStatement,
    read: PreparedStatement,
}

impl ScyllaRollbackGlobalRestoreBarrierStore {
    pub(super) async fn prepare(
        session: Arc<Session>,
        keyspace: &CqlKeyspaceName,
    ) -> Result<Self, RollbackGlobalRestoreBarrierError> {
        let table = format!(
            "{}.{}",
            keyspace.as_str(),
            COORDINATOR_ROLLBACK_SUFFIX_ARCHIVE_TABLE
        );
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

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn persist_or_recover<Hash: Q256BitHash>(
        &self,
        authority: &DeletingRollbackGlobalArchiveBarrier<Hash>,
        delete_barrier: &PersistedRollbackGlobalDeleteBarrier<Hash>,
        coordinator: &PersistedCoordinatorRollbackDeleteCompletion<Hash>,
        realm_deletes: &[PersistedRealmRollbackDeleteCompletion<Hash>],
        realm_restores: &[PersistedRealmRollbackTargetRestoreCompletion<Hash>],
        realm_archive_store_fingerprint: [u8; 32],
    ) -> Result<PersistedRollbackGlobalRestoreBarrier<Hash>, RollbackGlobalRestoreBarrierError> {
        let barrier = RollbackGlobalRestoreBarrier::try_from_receipts(
            authority,
            delete_barrier,
            coordinator,
            realm_deletes,
            realm_restores,
            realm_archive_store_fingerprint,
            self.fingerprint,
        )?;
        if let Some(current) = self.read_exact(&barrier).await? {
            if current != barrier {
                return Err(RollbackGlobalRestoreBarrierError::Conflict);
            }
            return Ok(PersistedRollbackGlobalRestoreBarrier {
                store_fingerprint: self.fingerprint,
                barrier: current,
            });
        }
        let row_bytes = i64::try_from(barrier.canonical_bytes.len())
            .map_err(|_| RollbackGlobalRestoreBarrierError::LengthOverflow)?;
        let fragment = fragment_digest(barrier.digest(), row_bytes, &barrier.canonical_bytes);
        let execution = self.session.execute_unpaged(
            &self.insert,
            (
                i64::from(barrier.target.network_id().chain_id()),
                i64::try_from(barrier.target.chain_epoch().get())
                    .map_err(|_| RollbackGlobalRestoreBarrierError::IntegerOutOfCqlRange)?,
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
                        _ => return Err(RollbackGlobalRestoreBarrierError::Conflict),
                    }
                }
            }
            Err(error) => match self.read_exact(&barrier).await {
                Ok(Some(current)) if current == barrier => {}
                Ok(_) => return Err(RollbackGlobalRestoreBarrierError::Indeterminate(error.to_string())),
                Err(read) => return Err(RollbackGlobalRestoreBarrierError::Indeterminate(
                    format!("execute={error}; read={read}"),
                )),
            },
        }
        let current = self.read_exact(&barrier).await?
            .ok_or(RollbackGlobalRestoreBarrierError::MissingAfterPersist)?;
        if current != barrier {
            return Err(RollbackGlobalRestoreBarrierError::Conflict);
        }
        Ok(PersistedRollbackGlobalRestoreBarrier {
            store_fingerprint: self.fingerprint,
            barrier: current,
        })
    }

    pub(super) async fn revalidate<Hash: Q256BitHash>(
        &self,
        receipt: &PersistedRollbackGlobalRestoreBarrier<Hash>,
    ) -> Result<(), RollbackGlobalRestoreBarrierError> {
        if receipt.store_fingerprint != self.fingerprint {
            return Err(RollbackGlobalRestoreBarrierError::StoreFingerprintMismatch);
        }
        match self.read_exact(&receipt.barrier).await? {
            Some(current) if current == receipt.barrier => Ok(()),
            Some(_) => Err(RollbackGlobalRestoreBarrierError::Conflict),
            None => Err(RollbackGlobalRestoreBarrierError::MissingAfterPersist),
        }
    }

    /// Recover the immutable restore barrier selected by the Coordinator's
    /// storage-authored runtime directive. The caller supplies no barrier
    /// payload and therefore cannot substitute a different participant set.
    pub(super) async fn read_selected_for_runtime<Hash: Q256BitHash>(
        &self,
        verifying_head: StoredCanonicalHead<Hash>,
        directive: RollbackRuntimeRebuildDirective<Hash>,
    ) -> Result<PersistedRollbackGlobalRestoreBarrier<Hash>, RollbackGlobalRestoreBarrierError> {
        if directive.authority() != AuthorityScope::Coordinator
            || directive.target().network_id()
                != verifying_head.canonical_ref().network_id()
            || directive.target().chain_epoch()
                != verifying_head.canonical_ref().chain_epoch()
        {
            return Err(RollbackGlobalRestoreBarrierError::BindingMismatch);
        }
        let barrier = self
            .read_coordinates(
                directive.target().network_id(),
                directive.target().chain_epoch().get(),
                directive.participant_plan_digest(),
                directive.global_restore_barrier_slot(),
            )
            .await?
            .ok_or(RollbackGlobalRestoreBarrierError::MissingAfterPersist)?;
        let restoring = CanonicalHeadTransition::begin_rollback_restore(
            *barrier.deleting_head(),
        )
        .map_err(model)?;
        let expected_verifying = CanonicalHeadTransition::begin_rollback_verify(
            *restoring.candidate(),
        )
        .map_err(model)?;
        if expected_verifying.candidate() != &verifying_head
            || barrier.store_fingerprint != self.fingerprint
            || barrier.slot() != directive.global_restore_barrier_slot()
            || barrier.digest() != directive.global_restore_barrier_digest()
            || barrier.participant_plan_digest() != directive.participant_plan_digest()
            || barrier.target().network_id() != directive.target().network_id()
            || barrier.target().chain_epoch() != directive.target().chain_epoch()
            || barrier.target().checkpoint() != directive.target().checkpoint()
        {
            return Err(RollbackGlobalRestoreBarrierError::BindingMismatch);
        }
        let receipt = PersistedRollbackGlobalRestoreBarrier {
            store_fingerprint: self.fingerprint,
            barrier,
        };
        self.revalidate(&receipt).await?;
        Ok(receipt)
    }

    async fn read_exact<Hash: Q256BitHash>(
        &self,
        expected: &RollbackGlobalRestoreBarrier<Hash>,
    ) -> Result<Option<RollbackGlobalRestoreBarrier<Hash>>, RollbackGlobalRestoreBarrierError> {
        let barrier = self
            .read_coordinates(
                expected.target.network_id(),
                expected.target.chain_epoch().get(),
                &expected.participant_plan_digest,
                &expected.slot,
            )
            .await?;
        if barrier.as_ref().is_some_and(|barrier| {
            barrier.slot != expected.slot
                || barrier.participant_plan_digest != expected.participant_plan_digest
        }) {
            return Err(RollbackGlobalRestoreBarrierError::Conflict);
        }
        Ok(barrier)
    }

    async fn read_coordinates<Hash: Q256BitHash>(
        &self,
        network: NetworkId,
        chain_epoch: u64,
        participant_plan_digest: &[u8; 32],
        slot: &[u8; 32],
    ) -> Result<Option<RollbackGlobalRestoreBarrier<Hash>>, RollbackGlobalRestoreBarrierError> {
        let rows = self.session.execute_unpaged(
            &self.read,
            (
                i64::from(network.chain_id()),
                i64::try_from(chain_epoch)
                    .map_err(|_| RollbackGlobalRestoreBarrierError::IntegerOutOfCqlRange)?,
                participant_plan_digest.as_slice(),
                KEY_DOMAIN,
                slot.as_slice(),
            ),
        ).await.map_err(cql)?.into_rows_result().map_err(cql)?
            .rows::<(
                Option<i32>, Option<i64>, Option<i32>, Option<i64>,
                Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>,
            )>().map_err(cql)?.collect::<Result<Vec<_>, _>>().map_err(cql)?;
        if rows.is_empty() { return Ok(None); }
        if rows.len() != 1 { return Err(RollbackGlobalRestoreBarrierError::MalformedRow); }
        let (index, revision, count, row_bytes, payload, fragment, row_digest) =
            rows.into_iter().next().expect("one row");
        let payload = payload.ok_or(RollbackGlobalRestoreBarrierError::MalformedRow)?;
        let row_bytes = row_bytes.ok_or(RollbackGlobalRestoreBarrierError::MalformedRow)?;
        let fragment: [u8; 32] = fragment
            .ok_or(RollbackGlobalRestoreBarrierError::MalformedRow)?
            .try_into().map_err(|_| RollbackGlobalRestoreBarrierError::MalformedRow)?;
        let row_digest: [u8; 32] = row_digest
            .ok_or(RollbackGlobalRestoreBarrierError::MalformedRow)?
            .try_into().map_err(|_| RollbackGlobalRestoreBarrierError::MalformedRow)?;
        if index != Some(0)
            || revision != Some(REVISION)
            || count != Some(1)
            || row_bytes <= 0
            || usize::try_from(row_bytes).ok() != Some(payload.len())
            || fragment_digest(&row_digest, row_bytes, &payload) != fragment
        {
            return Err(RollbackGlobalRestoreBarrierError::MalformedRow);
        }
        let barrier = RollbackGlobalRestoreBarrier::decode_canonical(&payload)?;
        if barrier.digest != row_digest
            || barrier.slot.as_slice() != slot.as_slice()
            || &barrier.participant_plan_digest != participant_plan_digest
        {
            return Err(RollbackGlobalRestoreBarrierError::Conflict);
        }
        Ok(Some(barrier))
    }
}

fn barrier_slot<Hash: Q256BitHash>(
    deleting_head: &StoredCanonicalHead<Hash>,
    target: &CanonicalChainRef<Hash>,
    participant_plan_digest: &[u8; 32],
    delete_barrier_slot: &[u8; 32],
    delete_barrier_digest: &[u8; 32],
    store_fingerprint: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SLOT_DOMAIN);
    hasher.update(deleting_head.canonical_ref().network_id().chain_id().to_be_bytes());
    hasher.update(deleting_head.canonical_ref().chain_epoch().get().to_be_bytes());
    hasher.update(target.to_canonical_bytes());
    hasher.update(participant_plan_digest);
    hasher.update(delete_barrier_slot);
    hasher.update(delete_barrier_digest);
    hasher.update(store_fingerprint);
    hasher.finalize().into()
}

fn barrier_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn fragment_digest(row_digest: &[u8; 32], row_bytes: i64, payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(FRAGMENT_DOMAIN);
    hasher.update(row_digest);
    hasher.update(row_bytes.to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

fn encode_authority(authority: AuthorityScope) -> [u8; 7] {
    let mut out = [0_u8; 7];
    match authority {
        AuthorityScope::Coordinator => out[0] = 1,
        AuthorityScope::Realm { realm_id, realm_sub_id } => {
            out[0] = 2;
            out[1..5].copy_from_slice(&realm_id.to_be_bytes());
            out[5..7].copy_from_slice(&realm_sub_id.to_be_bytes());
        }
    }
    out
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), RollbackGlobalRestoreBarrierError> {
    let len = u32::try_from(bytes.len()).map_err(|_| RollbackGlobalRestoreBarrierError::LengthOverflow)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn decode_applied(result: QueryResult) -> Result<bool, RollbackGlobalRestoreBarrierError> {
    let rows = result.into_rows_result().map_err(cql)?;
    let column = rows
        .column_specs()
        .get_by_name("[applied]")
        .ok_or(RollbackGlobalRestoreBarrierError::MalformedLwtResponse)?;
    let row = rows.single_row::<Row>().map_err(cql)?;
    match row.columns.get(column.0) {
        Some(Some(CqlValue::Boolean(applied))) => Ok(*applied),
        _ => Err(RollbackGlobalRestoreBarrierError::MalformedLwtResponse),
    }
}

async fn prepare_lwt(session: &Session, cql_text: &str) -> Result<PreparedStatement, RollbackGlobalRestoreBarrierError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_read(session: &Session, cql_text: &str) -> Result<PreparedStatement, RollbackGlobalRestoreBarrierError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn cql(error: impl fmt::Display) -> RollbackGlobalRestoreBarrierError {
    RollbackGlobalRestoreBarrierError::Cql(error.to_string())
}

fn model(error: impl fmt::Display) -> RollbackGlobalRestoreBarrierError {
    RollbackGlobalRestoreBarrierError::Model(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RollbackGlobalRestoreBarrierError {
    BindingMismatch,
    CountOverflow,
    RowTooLarge,
    LengthOverflow,
    IntegerOutOfCqlRange,
    MalformedRow,
    MalformedLwtResponse,
    DigestMismatch,
    UnknownVersion(u16),
    TrailingBytes,
    NonCanonicalEncoding,
    StoreFingerprintMismatch,
    MissingAfterPersist,
    Conflict,
    Indeterminate(String),
    Model(String),
    Cql(String),
}

impl From<super::rollback_global_delete_barrier::RollbackGlobalDeleteBarrierError>
    for RollbackGlobalRestoreBarrierError
{
    fn from(error: super::rollback_global_delete_barrier::RollbackGlobalDeleteBarrierError) -> Self {
        Self::Model(error.to_string())
    }
}

impl fmt::Display for RollbackGlobalRestoreBarrierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "global restore barrier error: {self:?}")
    }
}

impl Error for RollbackGlobalRestoreBarrierError {}

struct Cursor<'a> { bytes: &'a [u8], offset: usize }

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self { Self { bytes, offset: 0 } }
    fn take(&mut self, len: usize) -> Result<&'a [u8], RollbackGlobalRestoreBarrierError> {
        let end = self.offset.checked_add(len).ok_or(RollbackGlobalRestoreBarrierError::MalformedRow)?;
        let value = self.bytes.get(self.offset..end).ok_or(RollbackGlobalRestoreBarrierError::MalformedRow)?;
        self.offset = end;
        Ok(value)
    }
    fn u16(&mut self) -> Result<u16, RollbackGlobalRestoreBarrierError> { Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("2"))) }
    fn u32(&mut self) -> Result<u32, RollbackGlobalRestoreBarrierError> { Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("4"))) }
    fn u64(&mut self) -> Result<u64, RollbackGlobalRestoreBarrierError> { Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("8"))) }
    fn i64(&mut self) -> Result<i64, RollbackGlobalRestoreBarrierError> { Ok(i64::from_be_bytes(self.take(8)?.try_into().expect("8"))) }
    fn array32(&mut self) -> Result<[u8; 32], RollbackGlobalRestoreBarrierError> { Ok(self.take(32)?.try_into().expect("32")) }
    fn bytes(&mut self) -> Result<&'a [u8], RollbackGlobalRestoreBarrierError> {
        let len = usize::try_from(self.u32()?).map_err(|_| RollbackGlobalRestoreBarrierError::LengthOverflow)?;
        self.take(len)
    }
    fn is_empty(&self) -> bool { self.offset == self.bytes.len() }
}

#[cfg(test)]
mod tests {
    #[test]
    fn store_is_append_only_and_barrier_has_no_head_publish_api() {
        let source = include_str!("rollback_global_restore_barrier.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source");
        assert!(source.contains("IF NOT EXISTS"));
        assert!(source.contains("Consistency::Quorum"));
        assert!(source.contains("SerialConsistency::LocalSerial"));
        assert!(!source.contains("CanonicalHeadTransition::complete_rollback"));
        assert!(!source.contains("compare_and_set("));
        assert!(!source.contains("DELETE FROM"));
    }
}
