//! Durable per-participant runtime-rebuild directives and acknowledgements.
//!
//! The global restore owner writes every directive before entering VERIFYING.
//! A processor may then rebuild its local checkpoint/tree state and append one
//! exact report.  Neither row can publish the target canonical head.

#![allow(dead_code)]

use std::{collections::HashSet, error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::{CanonicalChainRef, NetworkId, CANONICAL_CHAIN_REF_V1_LEN},
    chain_context::AuthorityScope,
};
use psy_node_core::store::{
    canonical_head::{CanonicalHeadTransition, StoredCanonicalHead},
    pending_generation::ProcNamespacePrefix,
    pending_generation_identity::PendingGenerationContext,
    rollback_control::RollbackControlState,
    rollback_runtime_rebuild::{
        RollbackRuntimeRebuildDirective, RollbackRuntimeRebuildReport, restored_target,
    },
    timestamp::{
        CommitWriteTimestampUs, DeleteFenceTimestampUs, NewBranchWriteTimestampUs,
    },
    typed::UniquePendingId,
};
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{Consistency, SerialConsistency, prepared::PreparedStatement},
    value::{CqlValue, Row},
};
use sha2::{Digest, Sha256};

use super::{
    CqlKeyspaceName,
    coordinator_rollback_archive_store::COORDINATOR_ROLLBACK_SUFFIX_ARCHIVE_TABLE,
    coordinator_rollback_delete_completion_store::PersistedCoordinatorRollbackDeleteCompletion,
    pending_counter::{
        PendingCounterAdapter, PendingCounterAllocationOutcome, PendingCounterExpected,
        PendingCounterReadState, SealedPendingCounterAllocation,
    },
    realm_rollback_physical_archive_store::PersistedRealmRollbackTargetRestoreCompletion,
    rollback_global_restore_barrier::{
        PersistedRollbackGlobalRestoreBarrier, RollbackGlobalRestoreBarrier,
    },
};

const DIRECTIVE_KEY_DOMAIN: i16 = -11;
const REPORT_KEY_DOMAIN: i16 = -12;
const RUNTIME_READY_KEY_DOMAIN: i16 = -13;
const REVISION: i64 = 1;
const DIRECTIVE_MAGIC: &[u8; 8] = b"PSYRRBD2";
const REPORT_MAGIC: &[u8; 8] = b"PSYRRBR2";
const RUNTIME_READY_MAGIC: &[u8; 8] = b"PSYRRDY2";
const VERSION: u16 = 2;
const MAX_BYTES: usize = 16 * 1024;
const DIRECTIVE_SLOT_DOMAIN: &[u8] = b"psy.rollback.runtime-directive-slot.v2\0";
const REPORT_SLOT_DOMAIN: &[u8] = b"psy.rollback.runtime-report-slot.v2\0";
const ROW_DIGEST_DOMAIN: &[u8] = b"psy.rollback.runtime-row.v2\0";
const FRAGMENT_DOMAIN: &[u8] = b"psy.rollback.runtime-fragment.v2\0";
const STORE_DOMAIN: &[u8] = b"psy.rollback.runtime-rebuild-store.v2\0";
const RUNTIME_READY_SLOT_DOMAIN: &[u8] = b"psy.rollback.runtime-ready-slot.v2\0";
const RUNTIME_READY_REALM_SET_DOMAIN: &[u8] = b"psy.rollback.runtime-ready-realms.v2\0";

const INSERT_TEMPLATE: &str = "INSERT INTO {table} (network_chain_id, chain_epoch, participant_plan_digest, key_domain, row_slot, fragment_index, revision, fragment_count, row_bytes, fragment_payload, fragment_digest, row_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) IF NOT EXISTS";
const READ_TEMPLATE: &str = "SELECT fragment_index, revision, fragment_count, row_bytes, fragment_payload, fragment_digest, row_digest FROM {table} WHERE network_chain_id = ? AND chain_epoch = ? AND participant_plan_digest = ? AND key_domain = ? AND row_slot = ?";

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredRuntimeDirective<Hash> {
    directive: RollbackRuntimeRebuildDirective<Hash>,
    slot: [u8; 32],
    canonical_bytes: Vec<u8>,
    row_digest: [u8; 32],
}

impl<Hash: Q256BitHash> StoredRuntimeDirective<Hash> {
    fn from_directive(
        directive: RollbackRuntimeRebuildDirective<Hash>,
        fingerprint: [u8; 32],
    ) -> Result<Self, RollbackRuntimeRebuildStoreError> {
        let slot = directive_slot(&directive, &fingerprint);
        let mut bytes = Vec::with_capacity(512);
        bytes.extend_from_slice(DIRECTIVE_MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&encode_authority(directive.authority()));
        bytes.extend_from_slice(&directive.target().to_canonical_bytes());
        for field in [
            directive.participant_plan_digest(),
            directive.global_restore_barrier_slot(),
            directive.global_restore_barrier_digest(),
            directive.participant_restore_slot(),
            directive.participant_restore_digest(),
        ] {
            bytes.extend_from_slice(field);
        }
        encode_new_branch_write(&mut bytes, directive.new_branch_write());
        for field in [
            directive.digest(),
            &fingerprint,
            &slot,
        ] {
            bytes.extend_from_slice(field);
        }
        encode_context(&mut bytes, directive.processing());
        encode_context(&mut bytes, directive.gathering());
        let row_digest = row_digest(&bytes);
        bytes.extend_from_slice(&row_digest);
        if bytes.len() > MAX_BYTES {
            return Err(RollbackRuntimeRebuildStoreError::RowTooLarge);
        }
        Ok(Self {
            directive,
            slot,
            canonical_bytes: bytes,
            row_digest,
        })
    }

    fn decode(bytes: &[u8]) -> Result<Self, RollbackRuntimeRebuildStoreError> {
        if bytes.len() < 32 || bytes.len() > MAX_BYTES {
            return Err(RollbackRuntimeRebuildStoreError::MalformedRow);
        }
        let body_len = bytes.len() - 32;
        let expected_row_digest: [u8; 32] = bytes[body_len..].try_into().expect("32");
        if row_digest(&bytes[..body_len]) != expected_row_digest {
            return Err(RollbackRuntimeRebuildStoreError::DigestMismatch);
        }
        let mut cursor = Cursor::new(&bytes[..body_len]);
        if cursor.take(8)? != DIRECTIVE_MAGIC || cursor.u16()? != VERSION {
            return Err(RollbackRuntimeRebuildStoreError::MalformedRow);
        }
        let authority = decode_authority(cursor.take(7)?)?;
        let target = CanonicalChainRef::from_canonical_bytes(
            cursor.take(CANONICAL_CHAIN_REF_V1_LEN)?,
        )
        .map_err(model)?;
        let participant_plan_digest = cursor.array32()?;
        let barrier_slot = cursor.array32()?;
        let barrier_digest = cursor.array32()?;
        let participant_slot = cursor.array32()?;
        let participant_digest = cursor.array32()?;
        let new_branch_write = decode_new_branch_write(&mut cursor)?;
        let encoded_directive_digest = cursor.array32()?;
        let fingerprint = cursor.array32()?;
        let encoded_slot = cursor.array32()?;
        let processing = decode_context(&mut cursor)?;
        let gathering = decode_context(&mut cursor)?;
        if !cursor.is_empty() {
            return Err(RollbackRuntimeRebuildStoreError::TrailingBytes);
        }
        let directive = RollbackRuntimeRebuildDirective::try_from_storage(
            authority,
            target,
            participant_plan_digest,
            barrier_slot,
            barrier_digest,
            participant_slot,
            participant_digest,
            new_branch_write,
            processing,
            gathering,
        )
        .map_err(model)?;
        let decoded = Self::from_directive(directive, fingerprint)?;
        if directive.digest() != &encoded_directive_digest
            || decoded.slot != encoded_slot
            || decoded.row_digest != expected_row_digest
            || decoded.canonical_bytes != bytes
        {
            return Err(RollbackRuntimeRebuildStoreError::NonCanonicalEncoding);
        }
        Ok(decoded)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredRuntimeReport<Hash> {
    directive: RollbackRuntimeRebuildDirective<Hash>,
    report: RollbackRuntimeRebuildReport<Hash>,
    slot: [u8; 32],
    canonical_bytes: Vec<u8>,
    row_digest: [u8; 32],
}

impl<Hash: Q256BitHash> StoredRuntimeReport<Hash> {
    fn from_report(
        directive: RollbackRuntimeRebuildDirective<Hash>,
        report: RollbackRuntimeRebuildReport<Hash>,
        fingerprint: [u8; 32],
    ) -> Result<Self, RollbackRuntimeRebuildStoreError> {
        if report.directive_digest() != directive.digest()
            || report.authority() != directive.authority()
            || report.target() != directive.target()
            || report.new_branch_write() != directive.new_branch_write()
        {
            return Err(RollbackRuntimeRebuildStoreError::BindingMismatch);
        }
        let slot = report_slot(&directive, &fingerprint);
        let mut bytes = Vec::with_capacity(768);
        bytes.extend_from_slice(REPORT_MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&encode_authority(report.authority()));
        bytes.extend_from_slice(&report.target().to_canonical_bytes());
        for field in [
            directive.participant_plan_digest(),
            directive.digest(),
            report.digest(),
            &fingerprint,
            &slot,
        ] {
            bytes.extend_from_slice(field);
        }
        encode_new_branch_write(&mut bytes, report.new_branch_write());
        bytes.extend_from_slice(&report.backup_min_checkpoint().to_be_bytes());
        bytes.extend_from_slice(&report.backup_next_checkpoint().to_be_bytes());
        bytes.extend_from_slice(&report.backup_root().into_owned_32bytes());
        bytes.extend_from_slice(&report.processor_checkpoint().to_be_bytes());
        bytes.extend_from_slice(&report.authority_state_checkpoint().to_be_bytes());
        bytes.extend_from_slice(&report.authority_state_root().into_owned_32bytes());
        encode_context(&mut bytes, report.processing());
        encode_context(&mut bytes, report.gathering());
        let row_digest = row_digest(&bytes);
        bytes.extend_from_slice(&row_digest);
        if bytes.len() > MAX_BYTES {
            return Err(RollbackRuntimeRebuildStoreError::RowTooLarge);
        }
        Ok(Self {
            directive,
            report,
            slot,
            canonical_bytes: bytes,
            row_digest,
        })
    }

    fn decode(
        bytes: &[u8],
        directive: RollbackRuntimeRebuildDirective<Hash>,
    ) -> Result<Self, RollbackRuntimeRebuildStoreError> {
        if bytes.len() < 32 || bytes.len() > MAX_BYTES {
            return Err(RollbackRuntimeRebuildStoreError::MalformedRow);
        }
        let body_len = bytes.len() - 32;
        let expected_row_digest: [u8; 32] = bytes[body_len..].try_into().expect("32");
        if row_digest(&bytes[..body_len]) != expected_row_digest {
            return Err(RollbackRuntimeRebuildStoreError::DigestMismatch);
        }
        let mut cursor = Cursor::new(&bytes[..body_len]);
        if cursor.take(8)? != REPORT_MAGIC || cursor.u16()? != VERSION {
            return Err(RollbackRuntimeRebuildStoreError::MalformedRow);
        }
        let authority = decode_authority(cursor.take(7)?)?;
        let target = CanonicalChainRef::from_canonical_bytes(
            cursor.take(CANONICAL_CHAIN_REF_V1_LEN)?,
        )
        .map_err(model)?;
        let participant_plan_digest = cursor.array32()?;
        let directive_digest = cursor.array32()?;
        let encoded_report_digest = cursor.array32()?;
        let fingerprint = cursor.array32()?;
        let encoded_slot = cursor.array32()?;
        let new_branch_write = decode_new_branch_write(&mut cursor)?;
        let backup_min = cursor.u64()?;
        let backup_next = cursor.u64()?;
        let backup_root = Hash::from_owned_32bytes(cursor.array32()?);
        let processor_checkpoint = cursor.u64()?;
        let state_checkpoint = cursor.u64()?;
        let state_root = Hash::from_owned_32bytes(cursor.array32()?);
        let processing = decode_context(&mut cursor)?;
        let gathering = decode_context(&mut cursor)?;
        if !cursor.is_empty()
            || authority != directive.authority()
            || target != *directive.target()
            || participant_plan_digest != *directive.participant_plan_digest()
            || directive_digest != *directive.digest()
            || new_branch_write != directive.new_branch_write()
        {
            return Err(RollbackRuntimeRebuildStoreError::BindingMismatch);
        }
        let report = RollbackRuntimeRebuildReport::try_after_exact_rebuild(
            &directive,
            backup_min,
            backup_next,
            backup_root,
            processor_checkpoint,
            state_checkpoint,
            state_root,
            processing,
            gathering,
        )
        .map_err(model)?;
        let decoded = Self::from_report(directive, report, fingerprint)?;
        if report.digest() != &encoded_report_digest
            || decoded.slot != encoded_slot
            || decoded.row_digest != expected_row_digest
            || decoded.canonical_bytes != bytes
        {
            return Err(RollbackRuntimeRebuildStoreError::NonCanonicalEncoding);
        }
        Ok(decoded)
    }
}

#[derive(Debug)]
pub(super) struct PersistedRollbackRuntimeRebuildReport<Hash> {
    store_fingerprint: [u8; 32],
    stored: StoredRuntimeReport<Hash>,
}

impl<Hash> PersistedRollbackRuntimeRebuildReport<Hash> {
    pub(super) const fn directive(&self) -> &RollbackRuntimeRebuildDirective<Hash> {
        &self.stored.directive
    }

    pub(super) const fn report(&self) -> &RollbackRuntimeRebuildReport<Hash> {
        &self.stored.report
    }

    pub(super) const fn slot(&self) -> &[u8; 32] {
        &self.stored.slot
    }

    pub(super) const fn row_digest(&self) -> &[u8; 32] {
        &self.stored.row_digest
    }

    pub(super) const fn store_fingerprint(&self) -> &[u8; 32] {
        &self.store_fingerprint
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredRuntimeReadyBarrier<Hash> {
    verifying_head: StoredCanonicalHead<Hash>,
    target: CanonicalChainRef<Hash>,
    participant_plan_digest: [u8; 32],
    restore_barrier_store_fingerprint: [u8; 32],
    restore_barrier_slot: [u8; 32],
    restore_barrier_digest: [u8; 32],
    runtime_store_fingerprint: [u8; 32],
    coordinator_report_slot: [u8; 32],
    coordinator_report_row_digest: [u8; 32],
    coordinator_report_digest: [u8; 32],
    realm_count: u64,
    realm_report_set_digest: [u8; 32],
    slot: [u8; 32],
    canonical_bytes: Vec<u8>,
    row_digest: [u8; 32],
}

impl<Hash: Q256BitHash> StoredRuntimeReadyBarrier<Hash> {
    fn try_from_reports(
        verifying_head: StoredCanonicalHead<Hash>,
        restore: &PersistedRollbackGlobalRestoreBarrier<Hash>,
        coordinator: &PersistedRollbackRuntimeRebuildReport<Hash>,
        realms: &[PersistedRollbackRuntimeRebuildReport<Hash>],
        store_fingerprint: [u8; 32],
    ) -> Result<Self, RollbackRuntimeRebuildStoreError> {
        let restore_barrier = restore.barrier();
        let restoring = CanonicalHeadTransition::begin_rollback_restore(
            *restore_barrier.deleting_head(),
        )
        .map_err(model)?;
        let expected_verifying = CanonicalHeadTransition::begin_rollback_verify(
            *restoring.candidate(),
        )
        .map_err(model)?;
        let target = restored_target(*restore_barrier.target()).map_err(model)?;
        if verifying_head != *expected_verifying.candidate()
            || coordinator.store_fingerprint() != &store_fingerprint
            || realms.len() != usize::try_from(restore_barrier.realm_count()).unwrap_or(usize::MAX)
        {
            return Err(RollbackRuntimeRebuildStoreError::BindingMismatch);
        }
        require_ready_report(
            coordinator,
            AuthorityScope::Coordinator,
            &target,
            restore_barrier,
            &store_fingerprint,
        )?;

        let mut set = Sha256::new();
        set.update(RUNTIME_READY_REALM_SET_DOMAIN);
        set.update(restore_barrier.realm_count().to_be_bytes());
        let mut previous = None;
        for receipt in realms {
            let authority = receipt.report().authority();
            let AuthorityScope::Realm {
                realm_id,
                realm_sub_id,
            } = authority
            else {
                return Err(RollbackRuntimeRebuildStoreError::BindingMismatch);
            };
            let identity = (realm_id, realm_sub_id);
            if previous.is_some_and(|previous| previous >= identity) {
                return Err(RollbackRuntimeRebuildStoreError::BindingMismatch);
            }
            previous = Some(identity);
            require_ready_report(
                receipt,
                authority,
                &target,
                restore_barrier,
                &store_fingerprint,
            )?;
            set.update(encode_authority(authority));
            set.update(receipt.directive().digest());
            set.update(receipt.slot());
            set.update(receipt.row_digest());
            set.update(receipt.report().digest());
        }
        Self::try_from_fields(
            verifying_head,
            target,
            *restore_barrier.participant_plan_digest(),
            *restore.store_fingerprint(),
            *restore_barrier.slot(),
            *restore_barrier.digest(),
            store_fingerprint,
            *coordinator.slot(),
            *coordinator.row_digest(),
            *coordinator.report().digest(),
            restore_barrier.realm_count(),
            set.finalize().into(),
            store_fingerprint,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn try_from_fields(
        verifying_head: StoredCanonicalHead<Hash>,
        target: CanonicalChainRef<Hash>,
        participant_plan_digest: [u8; 32],
        restore_barrier_store_fingerprint: [u8; 32],
        restore_barrier_slot: [u8; 32],
        restore_barrier_digest: [u8; 32],
        runtime_store_fingerprint: [u8; 32],
        coordinator_report_slot: [u8; 32],
        coordinator_report_row_digest: [u8; 32],
        coordinator_report_digest: [u8; 32],
        realm_count: u64,
        realm_report_set_digest: [u8; 32],
        store_fingerprint: [u8; 32],
    ) -> Result<Self, RollbackRuntimeRebuildStoreError> {
        let request = match verifying_head.rollback_control() {
            RollbackControlState::Verifying(request) => request,
            _ => return Err(RollbackRuntimeRebuildStoreError::NotVerifying),
        };
        if verifying_head.canonical_ref().network_id() != target.network_id()
            || verifying_head.canonical_ref().chain_epoch() != target.chain_epoch()
            || request.target() != target.checkpoint()
            || request.plan_digest().as_bytes() != &participant_plan_digest
            || runtime_store_fingerprint != store_fingerprint
            || realm_count == 0
            || [
                participant_plan_digest,
                restore_barrier_store_fingerprint,
                restore_barrier_slot,
                restore_barrier_digest,
                runtime_store_fingerprint,
                coordinator_report_slot,
                coordinator_report_row_digest,
                coordinator_report_digest,
                realm_report_set_digest,
                store_fingerprint,
            ]
            .contains(&[0; 32])
        {
            return Err(RollbackRuntimeRebuildStoreError::BindingMismatch);
        }
        let slot = runtime_ready_slot(
            &target,
            &participant_plan_digest,
            &restore_barrier_slot,
            &restore_barrier_digest,
            &store_fingerprint,
        );
        let mut stored = Self {
            verifying_head,
            target,
            participant_plan_digest,
            restore_barrier_store_fingerprint,
            restore_barrier_slot,
            restore_barrier_digest,
            runtime_store_fingerprint,
            coordinator_report_slot,
            coordinator_report_row_digest,
            coordinator_report_digest,
            realm_count,
            realm_report_set_digest,
            slot,
            canonical_bytes: Vec::new(),
            row_digest: [0; 32],
        };
        let mut bytes = Vec::with_capacity(1024);
        bytes.extend_from_slice(RUNTIME_READY_MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&stored.target.network_id().chain_id().to_be_bytes());
        bytes.extend_from_slice(&stored.verifying_head.revision().as_i64().to_be_bytes());
        push_bytes(&mut bytes, &stored.verifying_head.canonical_ref_bytes())?;
        push_bytes(&mut bytes, &stored.verifying_head.rollback_control_bytes())?;
        bytes.extend_from_slice(&stored.target.to_canonical_bytes());
        for field in [
            &stored.participant_plan_digest,
            &stored.restore_barrier_store_fingerprint,
            &stored.restore_barrier_slot,
            &stored.restore_barrier_digest,
            &stored.runtime_store_fingerprint,
            &stored.coordinator_report_slot,
            &stored.coordinator_report_row_digest,
            &stored.coordinator_report_digest,
        ] {
            bytes.extend_from_slice(field);
        }
        bytes.extend_from_slice(&stored.realm_count.to_be_bytes());
        bytes.extend_from_slice(&stored.realm_report_set_digest);
        bytes.extend_from_slice(&store_fingerprint);
        bytes.extend_from_slice(&stored.slot);
        stored.row_digest = row_digest(&bytes);
        bytes.extend_from_slice(&stored.row_digest);
        if bytes.len() > MAX_BYTES {
            return Err(RollbackRuntimeRebuildStoreError::RowTooLarge);
        }
        stored.canonical_bytes = bytes;
        Ok(stored)
    }

    fn decode(bytes: &[u8]) -> Result<Self, RollbackRuntimeRebuildStoreError> {
        if bytes.len() < 32 || bytes.len() > MAX_BYTES {
            return Err(RollbackRuntimeRebuildStoreError::MalformedRow);
        }
        let body_len = bytes.len() - 32;
        let expected_digest: [u8; 32] = bytes[body_len..]
            .try_into()
            .expect("32-byte row digest");
        if row_digest(&bytes[..body_len]) != expected_digest {
            return Err(RollbackRuntimeRebuildStoreError::DigestMismatch);
        }
        let mut cursor = Cursor::new(&bytes[..body_len]);
        if cursor.take(8)? != RUNTIME_READY_MAGIC || cursor.u16()? != VERSION {
            return Err(RollbackRuntimeRebuildStoreError::MalformedRow);
        }
        let network = NetworkId::try_from_chain_id(cursor.u32()?).map_err(model)?;
        let revision = cursor.i64()?;
        let verifying_head = StoredCanonicalHead::decode_persisted(
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
            verifying_head,
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
        if !cursor.is_empty()
            || decoded.slot != encoded_slot
            || decoded.row_digest != expected_digest
            || decoded.canonical_bytes != bytes
        {
            return Err(RollbackRuntimeRebuildStoreError::NonCanonicalEncoding);
        }
        Ok(decoded)
    }
}

#[derive(Debug)]
pub(super) struct PersistedRollbackGlobalRuntimeReadyBarrier<Hash> {
    store_fingerprint: [u8; 32],
    stored: StoredRuntimeReadyBarrier<Hash>,
}

impl<Hash> PersistedRollbackGlobalRuntimeReadyBarrier<Hash> {
    pub(super) const fn verifying_head(&self) -> &StoredCanonicalHead<Hash> {
        &self.stored.verifying_head
    }

    pub(super) const fn target(&self) -> &CanonicalChainRef<Hash> {
        &self.stored.target
    }

    pub(super) const fn slot(&self) -> &[u8; 32] {
        &self.stored.slot
    }

    pub(super) const fn row_digest(&self) -> &[u8; 32] {
        &self.stored.row_digest
    }
}

pub(crate) struct ScyllaRollbackRuntimeRebuildStore {
    session: Arc<Session>,
    fingerprint: [u8; 32],
    insert: PreparedStatement,
    read: PreparedStatement,
}

impl ScyllaRollbackRuntimeRebuildStore {
    pub(crate) async fn prepare(
        session: Arc<Session>,
        keyspace: &CqlKeyspaceName,
    ) -> Result<Self, RollbackRuntimeRebuildStoreError> {
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
            session: session.clone(),
            fingerprint: hasher.finalize().into(),
            insert: prepare_lwt(&session, &insert).await?,
            read: prepare_read(&session, &read).await?,
        })
    }

    pub(super) async fn persist_or_recover_coordinator_directive<Hash: Q256BitHash>(
        &self,
        counter: &PendingCounterAdapter,
        barrier: &PersistedRollbackGlobalRestoreBarrier<Hash>,
        coordinator: &PersistedCoordinatorRollbackDeleteCompletion<Hash>,
    ) -> Result<RollbackRuntimeRebuildDirective<Hash>, RollbackRuntimeRebuildStoreError> {
        let binding = barrier.barrier();
        if binding.coordinator_completion_slot() != coordinator.completion().slot()
            || binding.coordinator_completion_digest() != coordinator.completion().digest()
            || binding.target() != coordinator.completion().target()
        {
            return Err(RollbackRuntimeRebuildStoreError::BindingMismatch);
        }
        let target = restored_target(*binding.target()).map_err(model)?;
        let authority = AuthorityScope::Coordinator;
        let slot = directive_slot_for(
            &target,
            binding.participant_plan_digest(),
            authority,
            &self.fingerprint,
        );
        let selected = self
            .read_row(
                target.network_id(),
                target.chain_epoch().get(),
                binding.participant_plan_digest(),
                DIRECTIVE_KEY_DOMAIN,
                &slot,
            )
            .await?
            .map(|bytes| StoredRuntimeDirective::decode(&bytes))
            .transpose()?;
        let request = binding
            .deleting_head()
            .rollback_control()
            .requested()
            .ok_or(RollbackRuntimeRebuildStoreError::BindingMismatch)?;

        // The immutable directive is selected before observing the global
        // counter on retry. Once either allocation succeeds, a fresh counter
        // observation must not choose a different namespace.
        let directive = match selected {
            Some(stored) if stored.slot == slot => stored.directive,
            Some(_) => return Err(RollbackRuntimeRebuildStoreError::Conflict),
            None => {
                let current = counter.observe_counter().await.map_err(backend)?;
                let (processing, gathering) = coordinator_contexts(target.network_id(), current)?;
                let candidate = RollbackRuntimeRebuildDirective::try_from_storage(
                    authority,
                    target,
                    *binding.participant_plan_digest(),
                    *binding.slot(),
                    *binding.digest(),
                    *coordinator.completion().slot(),
                    *coordinator.completion().digest(),
                    request.fence_window().new_branch_write(),
                    Some(processing),
                    Some(gathering),
                )
                .map_err(model)?;
                self.persist_directive(candidate).await?
            }
        };
        require_coordinator_binding(&directive, binding, coordinator)?;

        let processing = directive
            .processing()
            .ok_or(RollbackRuntimeRebuildStoreError::BindingMismatch)?;
        let gathering = directive
            .gathering()
            .ok_or(RollbackRuntimeRebuildStoreError::BindingMismatch)?;
        let processing_expected = pending_predecessor(processing.pending_id())?;
        let processing_allocation = SealedPendingCounterAllocation::try_for_rollback(
            processing_expected,
            processing.proc_checkpoint_id(),
            request.fence_window().new_branch_write(),
        )
        .map_err(model)?;
        let gathering_allocation = SealedPendingCounterAllocation::try_for_rollback(
            PendingCounterExpected::Present(processing.pending_id()),
            gathering.proc_checkpoint_id(),
            request.fence_window().new_branch_write(),
        )
        .map_err(model)?;
        if processing_allocation.candidate() != processing.pending_id()
            || gathering_allocation.candidate() != gathering.pending_id()
        {
            return Err(RollbackRuntimeRebuildStoreError::BindingMismatch);
        }
        for allocation in [&processing_allocation, &gathering_allocation] {
            let PendingCounterAllocationOutcome::Owned(owned) =
                counter.allocate(allocation).await.map_err(backend)?
            else {
                return Err(RollbackRuntimeRebuildStoreError::CounterConflict);
            };
            if owned.pending() != allocation.candidate()
                || owned.proc_id() != allocation.proc_id()
                || owned.plan_digest() != allocation.digest()
                || owned.write_timestamp_us() != allocation.write_timestamp_us()
                || owned.write_kind() != allocation.write_kind()
            {
                return Err(RollbackRuntimeRebuildStoreError::BindingMismatch);
            }
        }
        if counter.observe_counter().await.map_err(backend)?
            != PendingCounterReadState::Current(gathering.pending_id())
        {
            return Err(RollbackRuntimeRebuildStoreError::CounterConflict);
        }
        self.revalidate_directive(&directive).await?;
        Ok(directive)
    }

    pub(super) fn realm_directives<Hash: Q256BitHash>(
        &self,
        barrier: &PersistedRollbackGlobalRestoreBarrier<Hash>,
        realms: &[PersistedRealmRollbackTargetRestoreCompletion<Hash>],
    ) -> Result<Vec<RollbackRuntimeRebuildDirective<Hash>>, RollbackRuntimeRebuildStoreError> {
        let barrier = barrier.barrier();
        if usize::try_from(barrier.realm_count()).ok() != Some(realms.len()) {
            return Err(RollbackRuntimeRebuildStoreError::BindingMismatch);
        }
        let mut seen = HashSet::new();
        realms
            .iter()
            .map(|persisted| {
                let completion = persisted.completion();
                if completion.global_target() != barrier.target()
                    || completion.participant_plan_digest() != barrier.participant_plan_digest()
                    || !seen.insert(completion.authority())
                {
                    return Err(RollbackRuntimeRebuildStoreError::BindingMismatch);
                }
                RollbackRuntimeRebuildDirective::try_from_storage(
                    completion.authority(),
                    *completion.restored_target(),
                    *barrier.participant_plan_digest(),
                    *barrier.slot(),
                    *barrier.digest(),
                    *completion.slot(),
                    *completion.digest(),
                    completion.new_branch_write(),
                    Some(completion.processing()),
                    Some(completion.gathering()),
                )
                .map_err(model)
            })
            .collect()
    }

    pub(super) async fn persist_directive<Hash: Q256BitHash>(
        &self,
        directive: RollbackRuntimeRebuildDirective<Hash>,
    ) -> Result<RollbackRuntimeRebuildDirective<Hash>, RollbackRuntimeRebuildStoreError> {
        let expected = StoredRuntimeDirective::from_directive(directive, self.fingerprint)?;
        let execute_error = self.persist_row(&expected, DIRECTIVE_KEY_DOMAIN).await?;
        let current = self.finish_directive_readback(&directive, execute_error).await?;
        if current != expected {
            return Err(RollbackRuntimeRebuildStoreError::Conflict);
        }
        Ok(current.directive)
    }

    /// Select the storage-authored directive from the exact VERIFYING or
    /// ALL_REALMS_READY head. The directive is immutable; accepting the
    /// latter phase lets a restarted participant recover after its report was
    /// already included in the global ready barrier.
    /// The caller supplies only its authority identity; target, epoch, and plan
    /// are selected from the durable Coordinator row.
    pub(crate) async fn read_selected_directive<Hash: Q256BitHash>(
        &self,
        verifying_head: StoredCanonicalHead<Hash>,
        authority: AuthorityScope,
    ) -> Result<Option<RollbackRuntimeRebuildDirective<Hash>>, RollbackRuntimeRebuildStoreError> {
        let request = match verifying_head.rollback_control() {
            RollbackControlState::Verifying(request)
            | RollbackControlState::AllRealmsReady(request) => request,
            _ => return Err(RollbackRuntimeRebuildStoreError::NotVerifying),
        };
        let target = CanonicalChainRef::new(
            verifying_head.canonical_ref().network_id(),
            verifying_head.canonical_ref().chain_epoch(),
            *request.target(),
        );
        let plan_digest = request.plan_digest();
        let slot = directive_slot_for(
            &target,
            plan_digest.as_bytes(),
            authority,
            &self.fingerprint,
        );
        self.read_row(
            target.network_id(),
            target.chain_epoch().get(),
            plan_digest.as_bytes(),
            DIRECTIVE_KEY_DOMAIN,
            &slot,
        )
        .await?
        .map(|bytes| {
            let decoded = StoredRuntimeDirective::decode(&bytes)?;
            if decoded.slot != slot
                || decoded.directive.target() != &target
                || decoded.directive.participant_plan_digest() != plan_digest.as_bytes()
                || decoded.directive.authority() != authority
            {
                return Err(RollbackRuntimeRebuildStoreError::Conflict);
            }
            Ok(decoded.directive)
        })
        .transpose()
    }

    async fn read_directive_exact<Hash: Q256BitHash>(
        &self,
        directive: &RollbackRuntimeRebuildDirective<Hash>,
    ) -> Result<Option<StoredRuntimeDirective<Hash>>, RollbackRuntimeRebuildStoreError> {
        let slot = directive_slot(directive, &self.fingerprint);
        self.read_row(
            directive.target().network_id(),
            directive.target().chain_epoch().get(),
            directive.participant_plan_digest(),
            DIRECTIVE_KEY_DOMAIN,
            &slot,
        )
        .await?
        .map(|bytes| {
            let decoded = StoredRuntimeDirective::decode(&bytes)?;
            if decoded.directive != *directive || decoded.slot != slot {
                return Err(RollbackRuntimeRebuildStoreError::Conflict);
            }
            Ok(decoded)
        })
        .transpose()
    }

    pub(super) async fn revalidate_directive<Hash: Q256BitHash>(
        &self,
        directive: &RollbackRuntimeRebuildDirective<Hash>,
    ) -> Result<(), RollbackRuntimeRebuildStoreError> {
        match self.read_directive_exact(directive).await? {
            Some(current) if current.directive == *directive => Ok(()),
            Some(_) => Err(RollbackRuntimeRebuildStoreError::Conflict),
            None => Err(RollbackRuntimeRebuildStoreError::MissingDirective),
        }
    }

    pub(super) async fn persist_report<Hash: Q256BitHash>(
        &self,
        directive: RollbackRuntimeRebuildDirective<Hash>,
        report: RollbackRuntimeRebuildReport<Hash>,
    ) -> Result<PersistedRollbackRuntimeRebuildReport<Hash>, RollbackRuntimeRebuildStoreError> {
        let selected = self
            .read_directive_exact(&directive)
            .await?
            .ok_or(RollbackRuntimeRebuildStoreError::MissingDirective)?;
        if selected.directive != directive {
            return Err(RollbackRuntimeRebuildStoreError::Conflict);
        }
        let expected = StoredRuntimeReport::from_report(directive, report, self.fingerprint)?;
        let execute_error = self.persist_row(&expected, REPORT_KEY_DOMAIN).await?;
        let current = self.finish_report_readback(directive, execute_error).await?;
        if current != expected {
            return Err(RollbackRuntimeRebuildStoreError::Conflict);
        }
        Ok(PersistedRollbackRuntimeRebuildReport {
            store_fingerprint: self.fingerprint,
            stored: current,
        })
    }

    pub(crate) async fn persist_and_revalidate_report<Hash: Q256BitHash>(
        &self,
        directive: RollbackRuntimeRebuildDirective<Hash>,
        report: RollbackRuntimeRebuildReport<Hash>,
    ) -> Result<(), RollbackRuntimeRebuildStoreError> {
        let receipt = self.persist_report(directive, report).await?;
        self.revalidate_report(&receipt).await
    }

    pub(super) async fn revalidate_report<Hash: Q256BitHash>(
        &self,
        receipt: &PersistedRollbackRuntimeRebuildReport<Hash>,
    ) -> Result<(), RollbackRuntimeRebuildStoreError> {
        if receipt.store_fingerprint != self.fingerprint {
            return Err(RollbackRuntimeRebuildStoreError::StoreFingerprintMismatch);
        }
        match self.read_report_exact(receipt.stored.directive).await? {
            Some(current) if current == receipt.stored => Ok(()),
            Some(_) => Err(RollbackRuntimeRebuildStoreError::Conflict),
            None => Err(RollbackRuntimeRebuildStoreError::MissingAfterPersist),
        }
    }

    pub(super) async fn read_report_for_directive<Hash: Q256BitHash>(
        &self,
        directive: RollbackRuntimeRebuildDirective<Hash>,
    ) -> Result<Option<PersistedRollbackRuntimeRebuildReport<Hash>>, RollbackRuntimeRebuildStoreError>
    {
        self.read_report_exact(directive).await.map(|stored| {
            stored.map(|stored| PersistedRollbackRuntimeRebuildReport {
                store_fingerprint: self.fingerprint,
                stored,
            })
        })
    }

    pub(super) async fn persist_runtime_ready_barrier<Hash: Q256BitHash>(
        &self,
        verifying_head: StoredCanonicalHead<Hash>,
        restore: &PersistedRollbackGlobalRestoreBarrier<Hash>,
        coordinator: &PersistedRollbackRuntimeRebuildReport<Hash>,
        realms: &[PersistedRollbackRuntimeRebuildReport<Hash>],
    ) -> Result<PersistedRollbackGlobalRuntimeReadyBarrier<Hash>, RollbackRuntimeRebuildStoreError>
    {
        let expected = StoredRuntimeReadyBarrier::try_from_reports(
            verifying_head,
            restore,
            coordinator,
            realms,
            self.fingerprint,
        )?;
        let execute_error = self
            .persist_row(&expected, RUNTIME_READY_KEY_DOMAIN)
            .await?;
        let current = match self.read_runtime_ready_exact(&expected).await {
            Ok(Some(current)) => current,
            Ok(None) => {
                return Err(execute_error.map_or(
                    RollbackRuntimeRebuildStoreError::MissingAfterPersist,
                    RollbackRuntimeRebuildStoreError::Indeterminate,
                ));
            }
            Err(read_error) => {
                return Err(indeterminate_or_read_error(execute_error, read_error));
            }
        };
        if current != expected {
            return Err(RollbackRuntimeRebuildStoreError::Conflict);
        }
        Ok(PersistedRollbackGlobalRuntimeReadyBarrier {
            store_fingerprint: self.fingerprint,
            stored: current,
        })
    }

    pub(super) async fn revalidate_runtime_ready_barrier<Hash: Q256BitHash>(
        &self,
        receipt: &PersistedRollbackGlobalRuntimeReadyBarrier<Hash>,
    ) -> Result<(), RollbackRuntimeRebuildStoreError> {
        if receipt.store_fingerprint != self.fingerprint {
            return Err(RollbackRuntimeRebuildStoreError::StoreFingerprintMismatch);
        }
        match self.read_runtime_ready_exact(&receipt.stored).await? {
            Some(current) if current == receipt.stored => Ok(()),
            Some(_) => Err(RollbackRuntimeRebuildStoreError::Conflict),
            None => Err(RollbackRuntimeRebuildStoreError::MissingAfterPersist),
        }
    }

    async fn finish_directive_readback<Hash: Q256BitHash>(
        &self,
        directive: &RollbackRuntimeRebuildDirective<Hash>,
        execute_error: Option<String>,
    ) -> Result<StoredRuntimeDirective<Hash>, RollbackRuntimeRebuildStoreError> {
        match self.read_directive_exact(directive).await {
            Ok(Some(current)) => Ok(current),
            Ok(None) => Err(execute_error.map_or(
                RollbackRuntimeRebuildStoreError::MissingAfterPersist,
                RollbackRuntimeRebuildStoreError::Indeterminate,
            )),
            Err(read_error) => Err(indeterminate_or_read_error(execute_error, read_error)),
        }
    }

    async fn finish_report_readback<Hash: Q256BitHash>(
        &self,
        directive: RollbackRuntimeRebuildDirective<Hash>,
        execute_error: Option<String>,
    ) -> Result<StoredRuntimeReport<Hash>, RollbackRuntimeRebuildStoreError> {
        match self.read_report_exact(directive).await {
            Ok(Some(current)) => Ok(current),
            Ok(None) => Err(execute_error.map_or(
                RollbackRuntimeRebuildStoreError::MissingAfterPersist,
                RollbackRuntimeRebuildStoreError::Indeterminate,
            )),
            Err(read_error) => Err(indeterminate_or_read_error(execute_error, read_error)),
        }
    }

    async fn read_report_exact<Hash: Q256BitHash>(
        &self,
        directive: RollbackRuntimeRebuildDirective<Hash>,
    ) -> Result<Option<StoredRuntimeReport<Hash>>, RollbackRuntimeRebuildStoreError> {
        let slot = report_slot(&directive, &self.fingerprint);
        self.read_row(
            directive.target().network_id(),
            directive.target().chain_epoch().get(),
            directive.participant_plan_digest(),
            REPORT_KEY_DOMAIN,
            &slot,
        )
        .await?
        .map(|bytes| {
            let decoded = StoredRuntimeReport::decode(&bytes, directive)?;
            if decoded.slot != slot {
                return Err(RollbackRuntimeRebuildStoreError::Conflict);
            }
            Ok(decoded)
        })
        .transpose()
    }

    async fn read_runtime_ready_exact<Hash: Q256BitHash>(
        &self,
        expected: &StoredRuntimeReadyBarrier<Hash>,
    ) -> Result<Option<StoredRuntimeReadyBarrier<Hash>>, RollbackRuntimeRebuildStoreError> {
        self.read_row(
            expected.target.network_id(),
            expected.target.chain_epoch().get(),
            &expected.participant_plan_digest,
            RUNTIME_READY_KEY_DOMAIN,
            &expected.slot,
        )
        .await?
        .map(|bytes| {
            let decoded = StoredRuntimeReadyBarrier::decode(&bytes)?;
            if decoded.slot != expected.slot {
                return Err(RollbackRuntimeRebuildStoreError::Conflict);
            }
            Ok(decoded)
        })
        .transpose()
    }

    async fn persist_row<Hash: Q256BitHash, T: RuntimeRow<Hash>>(
        &self,
        row: &T,
        key_domain: i16,
    ) -> Result<Option<String>, RollbackRuntimeRebuildStoreError> {
        let bytes = row.bytes();
        let row_bytes = i64::try_from(bytes.len())
            .map_err(|_| RollbackRuntimeRebuildStoreError::LengthOverflow)?;
        let fragment = fragment_digest(row.row_digest(), row_bytes, bytes);
        let execution = self
            .session
            .execute_unpaged(
                &self.insert,
                (
                    i64::from(row.target().network_id().chain_id()),
                    i64::try_from(row.target().chain_epoch().get())
                        .map_err(|_| RollbackRuntimeRebuildStoreError::IntegerOutOfCqlRange)?,
                    row.plan_digest().as_slice(),
                    key_domain,
                    row.slot().as_slice(),
                    0_i32,
                    REVISION,
                    1_i32,
                    row_bytes,
                    bytes,
                    fragment.as_slice(),
                    row.row_digest().as_slice(),
                ),
            )
            .await;
        match execution {
            Ok(result) => {
                let _ = decode_applied(result)?;
                Ok(None)
            }
            // An execute error may have happened after the LWT was applied.
            // Preserve the transport error, then let the caller point-read the
            // immutable row and accept only the exact canonical candidate.
            Err(error) => Ok(Some(error.to_string())),
        }
    }

    async fn read_row(
        &self,
        network: NetworkId,
        epoch: u64,
        plan_digest: &[u8; 32],
        key_domain: i16,
        slot: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, RollbackRuntimeRebuildStoreError> {
        let rows = self
            .session
            .execute_unpaged(
                &self.read,
                (
                    i64::from(network.chain_id()),
                    i64::try_from(epoch)
                        .map_err(|_| RollbackRuntimeRebuildStoreError::IntegerOutOfCqlRange)?,
                    plan_digest.as_slice(),
                    key_domain,
                    slot.as_slice(),
                ),
            )
            .await
            .map_err(cql)?
            .into_rows_result()
            .map_err(cql)?
            .rows::<(
                Option<i32>,
                Option<i64>,
                Option<i32>,
                Option<i64>,
                Option<Vec<u8>>,
                Option<Vec<u8>>,
                Option<Vec<u8>>,
            )>()
            .map_err(cql)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(cql)?;
        if rows.is_empty() {
            return Ok(None);
        }
        if rows.len() != 1 {
            return Err(RollbackRuntimeRebuildStoreError::MalformedRow);
        }
        let (index, revision, count, row_bytes, payload, fragment, digest) =
            rows.into_iter().next().expect("one row");
        let payload = payload.ok_or(RollbackRuntimeRebuildStoreError::MalformedRow)?;
        let row_bytes = row_bytes.ok_or(RollbackRuntimeRebuildStoreError::MalformedRow)?;
        let fragment: [u8; 32] = fragment
            .ok_or(RollbackRuntimeRebuildStoreError::MalformedRow)?
            .try_into()
            .map_err(|_| RollbackRuntimeRebuildStoreError::MalformedRow)?;
        let digest: [u8; 32] = digest
            .ok_or(RollbackRuntimeRebuildStoreError::MalformedRow)?
            .try_into()
            .map_err(|_| RollbackRuntimeRebuildStoreError::MalformedRow)?;
        if index != Some(0)
            || revision != Some(REVISION)
            || count != Some(1)
            || row_bytes <= 0
            || payload.len() < 32
            || usize::try_from(row_bytes).ok() != Some(payload.len())
            || fragment_digest(&digest, row_bytes, &payload) != fragment
            || row_digest(&payload[..payload.len() - 32]) != digest
        {
            return Err(RollbackRuntimeRebuildStoreError::MalformedRow);
        }
        Ok(Some(payload))
    }
}

trait RuntimeRow<Hash> {
    fn target(&self) -> &CanonicalChainRef<Hash>;
    fn plan_digest(&self) -> &[u8; 32];
    fn slot(&self) -> &[u8; 32];
    fn bytes(&self) -> &[u8];
    fn row_digest(&self) -> &[u8; 32];
}

impl<Hash: Q256BitHash> RuntimeRow<Hash> for StoredRuntimeDirective<Hash> {
    fn target(&self) -> &CanonicalChainRef<Hash> { self.directive.target() }
    fn plan_digest(&self) -> &[u8; 32] { self.directive.participant_plan_digest() }
    fn slot(&self) -> &[u8; 32] { &self.slot }
    fn bytes(&self) -> &[u8] { &self.canonical_bytes }
    fn row_digest(&self) -> &[u8; 32] { &self.row_digest }
}

impl<Hash: Q256BitHash> RuntimeRow<Hash> for StoredRuntimeReport<Hash> {
    fn target(&self) -> &CanonicalChainRef<Hash> { self.directive.target() }
    fn plan_digest(&self) -> &[u8; 32] { self.directive.participant_plan_digest() }
    fn slot(&self) -> &[u8; 32] { &self.slot }
    fn bytes(&self) -> &[u8] { &self.canonical_bytes }
    fn row_digest(&self) -> &[u8; 32] { &self.row_digest }
}

impl<Hash: Q256BitHash> RuntimeRow<Hash> for StoredRuntimeReadyBarrier<Hash> {
    fn target(&self) -> &CanonicalChainRef<Hash> { &self.target }
    fn plan_digest(&self) -> &[u8; 32] { &self.participant_plan_digest }
    fn slot(&self) -> &[u8; 32] { &self.slot }
    fn bytes(&self) -> &[u8] { &self.canonical_bytes }
    fn row_digest(&self) -> &[u8; 32] { &self.row_digest }
}

fn directive_slot<Hash: Q256BitHash>(
    directive: &RollbackRuntimeRebuildDirective<Hash>,
    fingerprint: &[u8; 32],
) -> [u8; 32] {
    directive_slot_for(
        directive.target(),
        directive.participant_plan_digest(),
        directive.authority(),
        fingerprint,
    )
}

fn directive_slot_for<Hash: Q256BitHash>(
    target: &CanonicalChainRef<Hash>,
    participant_plan_digest: &[u8; 32],
    authority: AuthorityScope,
    fingerprint: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DIRECTIVE_SLOT_DOMAIN);
    hasher.update(target.to_canonical_bytes());
    hasher.update(participant_plan_digest);
    hasher.update(encode_authority(authority));
    hasher.update(fingerprint);
    hasher.finalize().into()
}

fn report_slot<Hash: Q256BitHash>(
    directive: &RollbackRuntimeRebuildDirective<Hash>,
    fingerprint: &[u8; 32],
) -> [u8; 32] {
    slot_digest(REPORT_SLOT_DOMAIN, directive, fingerprint)
}

fn runtime_ready_slot<Hash: Q256BitHash>(
    target: &CanonicalChainRef<Hash>,
    participant_plan_digest: &[u8; 32],
    restore_barrier_slot: &[u8; 32],
    restore_barrier_digest: &[u8; 32],
    fingerprint: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RUNTIME_READY_SLOT_DOMAIN);
    hasher.update(target.to_canonical_bytes());
    hasher.update(participant_plan_digest);
    hasher.update(restore_barrier_slot);
    hasher.update(restore_barrier_digest);
    hasher.update(fingerprint);
    hasher.finalize().into()
}

fn slot_digest<Hash: Q256BitHash>(
    domain: &[u8],
    directive: &RollbackRuntimeRebuildDirective<Hash>,
    fingerprint: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(directive.target().to_canonical_bytes());
    hasher.update(directive.participant_plan_digest());
    hasher.update(encode_authority(directive.authority()));
    hasher.update(fingerprint);
    hasher.finalize().into()
}

fn row_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ROW_DIGEST_DOMAIN);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn fragment_digest(digest: &[u8; 32], row_bytes: i64, payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(FRAGMENT_DOMAIN);
    hasher.update(digest);
    hasher.update(row_bytes.to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

fn encode_authority(authority: AuthorityScope) -> [u8; 7] {
    let mut out = [0; 7];
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

fn decode_authority(bytes: &[u8]) -> Result<AuthorityScope, RollbackRuntimeRebuildStoreError> {
    match bytes {
        [1, 0, 0, 0, 0, 0, 0] => Ok(AuthorityScope::Coordinator),
        [2, a, b, c, d, e, f] => Ok(AuthorityScope::Realm {
            realm_id: u32::from_be_bytes([*a, *b, *c, *d]),
            realm_sub_id: u16::from_be_bytes([*e, *f]),
        }),
        _ => Err(RollbackRuntimeRebuildStoreError::MalformedRow),
    }
}

fn encode_context(out: &mut Vec<u8>, context: Option<PendingGenerationContext>) {
    match context {
        None => out.push(0),
        Some(context) => {
            out.push(1);
            out.extend_from_slice(&context.pending_id().get().to_be_bytes());
            out.extend_from_slice(&context.proc_checkpoint_id().as_u128().to_be_bytes());
        }
    }
}

fn decode_context(
    cursor: &mut Cursor<'_>,
) -> Result<Option<PendingGenerationContext>, RollbackRuntimeRebuildStoreError> {
    match cursor.u8()? {
        0 => Ok(None),
        1 => PendingGenerationContext::try_from_legacy(cursor.u64()?, cursor.u128()?)
            .map(Some)
            .map_err(model),
        _ => Err(RollbackRuntimeRebuildStoreError::MalformedRow),
    }
}

fn coordinator_contexts(
    network: NetworkId,
    counter: PendingCounterReadState,
) -> Result<(PendingGenerationContext, PendingGenerationContext), RollbackRuntimeRebuildStoreError> {
    let processing_pending = match counter {
        PendingCounterReadState::Uninitialized => UniquePendingId::try_new(1).map_err(model)?,
        PendingCounterReadState::Current(current) => UniquePendingId::try_new(
            current
                .get()
                .checked_add(1)
                .ok_or(RollbackRuntimeRebuildStoreError::PendingOverflow)?,
        )
        .map_err(model)?,
    };
    let gathering_pending = UniquePendingId::try_new(
        processing_pending
            .get()
            .checked_add(1)
            .ok_or(RollbackRuntimeRebuildStoreError::PendingOverflow)?,
    )
    .map_err(model)?;
    let prefix = ProcNamespacePrefix::for_authority(network, AuthorityScope::Coordinator);
    Ok((
        PendingGenerationContext::try_from_legacy(
            processing_pending.get(),
            prefix.derive_proc_id(processing_pending).as_u128(),
        )
        .map_err(model)?,
        PendingGenerationContext::try_from_legacy(
            gathering_pending.get(),
            prefix.derive_proc_id(gathering_pending).as_u128(),
        )
        .map_err(model)?,
    ))
}

fn pending_predecessor(
    processing: UniquePendingId,
) -> Result<PendingCounterExpected, RollbackRuntimeRebuildStoreError> {
    match processing.get() {
        1 => Ok(PendingCounterExpected::Absent),
        value => UniquePendingId::try_new(value - 1)
            .map(PendingCounterExpected::Present)
            .map_err(model),
    }
}

fn require_coordinator_binding<Hash: Q256BitHash>(
    directive: &RollbackRuntimeRebuildDirective<Hash>,
    barrier: &RollbackGlobalRestoreBarrier<Hash>,
    coordinator: &PersistedCoordinatorRollbackDeleteCompletion<Hash>,
) -> Result<(), RollbackRuntimeRebuildStoreError> {
    let request = barrier
        .deleting_head()
        .rollback_control()
        .requested()
        .ok_or(RollbackRuntimeRebuildStoreError::BindingMismatch)?;
    if directive.authority() != AuthorityScope::Coordinator
        || directive.target() != &restored_target(*barrier.target()).map_err(model)?
        || directive.participant_plan_digest() != barrier.participant_plan_digest()
        || directive.global_restore_barrier_slot() != barrier.slot()
        || directive.global_restore_barrier_digest() != barrier.digest()
        || directive.participant_restore_slot() != coordinator.completion().slot()
        || directive.participant_restore_digest() != coordinator.completion().digest()
        || directive.new_branch_write() != request.fence_window().new_branch_write()
        || directive.processing().is_none()
        || directive.gathering().is_none()
    {
        return Err(RollbackRuntimeRebuildStoreError::BindingMismatch);
    }
    Ok(())
}

fn require_ready_report<Hash: Q256BitHash>(
    receipt: &PersistedRollbackRuntimeRebuildReport<Hash>,
    expected_authority: AuthorityScope,
    target: &CanonicalChainRef<Hash>,
    restore: &RollbackGlobalRestoreBarrier<Hash>,
    runtime_store_fingerprint: &[u8; 32],
) -> Result<(), RollbackRuntimeRebuildStoreError> {
    let directive = receipt.directive();
    let report = receipt.report();
    let target_checkpoint = target.checkpoint().checkpoint_id().get();
    let request = restore
        .deleting_head()
        .rollback_control()
        .requested()
        .ok_or(RollbackRuntimeRebuildStoreError::BindingMismatch)?;
    if receipt.store_fingerprint() != runtime_store_fingerprint
        || directive.authority() != expected_authority
        || report.authority() != expected_authority
        || directive.target() != target
        || report.target() != target
        || directive.participant_plan_digest() != restore.participant_plan_digest()
        || directive.global_restore_barrier_slot() != restore.slot()
        || directive.global_restore_barrier_digest() != restore.digest()
        || directive.new_branch_write() != request.fence_window().new_branch_write()
        || report.directive_digest() != directive.digest()
        || report.new_branch_write() != directive.new_branch_write()
        || report.processor_checkpoint() != target_checkpoint
        || report.authority_state_checkpoint() != target_checkpoint
        || report.processing() != directive.processing()
        || report.gathering() != directive.gathering()
    {
        return Err(RollbackRuntimeRebuildStoreError::BindingMismatch);
    }
    Ok(())
}

fn encode_new_branch_write(output: &mut Vec<u8>, timestamp: NewBranchWriteTimestampUs) {
    output.extend_from_slice(
        &timestamp
            .delete_fence()
            .orphan_write_max()
            .as_i64()
            .to_be_bytes(),
    );
    output.extend_from_slice(&timestamp.delete_fence().as_i64().to_be_bytes());
    output.extend_from_slice(&timestamp.as_commit_timestamp().as_i64().to_be_bytes());
}

fn decode_new_branch_write(
    cursor: &mut Cursor<'_>,
) -> Result<NewBranchWriteTimestampUs, RollbackRuntimeRebuildStoreError> {
    let orphan_write_max = CommitWriteTimestampUs::try_from_i128(i128::from(cursor.i64()?))
        .map_err(model)?;
    let delete_fence =
        DeleteFenceTimestampUs::try_after(orphan_write_max, i128::from(cursor.i64()?))
            .map_err(model)?;
    NewBranchWriteTimestampUs::try_after(delete_fence, i128::from(cursor.i64()?)).map_err(model)
}

fn push_bytes(
    output: &mut Vec<u8>,
    bytes: &[u8],
) -> Result<(), RollbackRuntimeRebuildStoreError> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| RollbackRuntimeRebuildStoreError::LengthOverflow)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn decode_applied(result: QueryResult) -> Result<bool, RollbackRuntimeRebuildStoreError> {
    let rows = result
        .into_rows_result()
        .map_err(cql)?;
    let column = rows
        .column_specs()
        .get_by_name("[applied]")
        .ok_or(RollbackRuntimeRebuildStoreError::MalformedLwtResponse)?;
    let row = rows.single_row::<Row>().map_err(cql)?;
    match row.columns.get(column.0) {
        Some(Some(CqlValue::Boolean(applied))) => Ok(*applied),
        _ => Err(RollbackRuntimeRebuildStoreError::MalformedLwtResponse),
    }
}

async fn prepare_lwt(
    session: &Session,
    cql_text: &str,
) -> Result<PreparedStatement, RollbackRuntimeRebuildStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_read(
    session: &Session,
    cql_text: &str,
) -> Result<PreparedStatement, RollbackRuntimeRebuildStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn cql(error: impl fmt::Display) -> RollbackRuntimeRebuildStoreError {
    RollbackRuntimeRebuildStoreError::Cql(error.to_string())
}

fn model(error: impl fmt::Display) -> RollbackRuntimeRebuildStoreError {
    RollbackRuntimeRebuildStoreError::Model(error.to_string())
}

fn backend(error: impl fmt::Display) -> RollbackRuntimeRebuildStoreError {
    RollbackRuntimeRebuildStoreError::Backend(error.to_string())
}

fn indeterminate_or_read_error(
    execute_error: Option<String>,
    read_error: RollbackRuntimeRebuildStoreError,
) -> RollbackRuntimeRebuildStoreError {
    match execute_error {
        Some(execute_error) => RollbackRuntimeRebuildStoreError::Indeterminate(format!(
            "execute error: {execute_error}; exact readback error: {read_error}"
        )),
        None => read_error,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RollbackRuntimeRebuildStoreError {
    BindingMismatch,
    RowTooLarge,
    LengthOverflow,
    IntegerOutOfCqlRange,
    MalformedRow,
    MalformedLwtResponse,
    DigestMismatch,
    TrailingBytes,
    NonCanonicalEncoding,
    MissingDirective,
    MissingAfterPersist,
    PendingOverflow,
    CounterConflict,
    NotVerifying,
    StoreFingerprintMismatch,
    Conflict,
    Indeterminate(String),
    Model(String),
    Backend(String),
    Cql(String),
}

impl fmt::Display for RollbackRuntimeRebuildStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "rollback runtime rebuild store error: {self:?}")
    }
}

impl Error for RollbackRuntimeRebuildStoreError {}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self { Self { bytes, offset: 0 } }
    fn take(&mut self, len: usize) -> Result<&'a [u8], RollbackRuntimeRebuildStoreError> {
        let end = self.offset.checked_add(len).ok_or(RollbackRuntimeRebuildStoreError::MalformedRow)?;
        let value = self.bytes.get(self.offset..end).ok_or(RollbackRuntimeRebuildStoreError::MalformedRow)?;
        self.offset = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8, RollbackRuntimeRebuildStoreError> { Ok(self.take(1)?[0]) }
    fn u16(&mut self) -> Result<u16, RollbackRuntimeRebuildStoreError> { Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("2"))) }
    fn u32(&mut self) -> Result<u32, RollbackRuntimeRebuildStoreError> { Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("4"))) }
    fn i64(&mut self) -> Result<i64, RollbackRuntimeRebuildStoreError> { Ok(i64::from_be_bytes(self.take(8)?.try_into().expect("8"))) }
    fn u64(&mut self) -> Result<u64, RollbackRuntimeRebuildStoreError> { Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("8"))) }
    fn u128(&mut self) -> Result<u128, RollbackRuntimeRebuildStoreError> { Ok(u128::from_be_bytes(self.take(16)?.try_into().expect("16"))) }
    fn bytes(&mut self) -> Result<&'a [u8], RollbackRuntimeRebuildStoreError> {
        let length = usize::try_from(self.u32()?)
            .map_err(|_| RollbackRuntimeRebuildStoreError::MalformedRow)?;
        self.take(length)
    }
    fn array32(&mut self) -> Result<[u8; 32], RollbackRuntimeRebuildStoreError> { Ok(self.take(32)?.try_into().expect("32")) }
    fn is_empty(&self) -> bool { self.offset == self.bytes.len() }
}

#[cfg(test)]
mod tests {
    use parth_core::PHash;
    use psy_core::constants::chain_id::PsyChainNetworkType;
    use psy_data::protocol::canonical_chain::{
        CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef, NetworkId,
    };
    use psy_node_core::store::{
        canonical_head::StoredCanonicalHead,
        rollback_control::{RollbackExecutionMode, RollbackPlanDigest, RollbackRequest},
        timestamp::{CommitWriteTimestampUs, TimestampFenceWindow},
        typed::UniquePendingId,
    };

    use super::*;

    fn runtime_target() -> CanonicalChainRef<PHash> {
        CanonicalChainRef::new(
            NetworkId::try_from_chain_id(1337).unwrap(),
            ChainEpoch::new(8),
            checkpoint(40, 400),
        )
    }

    fn runtime_new_branch_write() -> NewBranchWriteTimestampUs {
        TimestampFenceWindow::try_new(
            CommitWriteTimestampUs::try_from_i128(100).unwrap(),
            101,
            102,
        )
        .unwrap()
        .new_branch_write()
    }

    fn runtime_directive() -> RollbackRuntimeRebuildDirective<PHash> {
        let target = runtime_target();
        let (processing, gathering) = coordinator_contexts(
            target.network_id(),
            PendingCounterReadState::Uninitialized,
        )
        .unwrap();
        RollbackRuntimeRebuildDirective::try_from_storage(
            AuthorityScope::Coordinator,
            target,
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
            [5; 32],
            runtime_new_branch_write(),
            Some(processing),
            Some(gathering),
        )
        .unwrap()
    }

    #[test]
    fn runtime_rows_roundtrip_the_complete_new_branch_fence_window() {
        let directive = runtime_directive();
        let stored = StoredRuntimeDirective::from_directive(directive, [9; 32]).unwrap();
        let decoded = StoredRuntimeDirective::decode(&stored.canonical_bytes).unwrap();
        assert_eq!(decoded, stored);
        assert_eq!(
            decoded.directive.new_branch_write(),
            runtime_new_branch_write()
        );

        let report = RollbackRuntimeRebuildReport::try_after_exact_rebuild(
            &directive,
            0,
            41,
            PHash::from_owned_32bytes([6; 32]),
            40,
            40,
            PHash::from_owned_32bytes([7; 32]),
            directive.processing(),
            directive.gathering(),
        )
        .unwrap();
        let stored_report = StoredRuntimeReport::from_report(directive, report, [9; 32]).unwrap();
        assert_eq!(
            StoredRuntimeReport::decode(&stored_report.canonical_bytes, directive).unwrap(),
            stored_report
        );
    }

    #[test]
    fn runtime_directive_rejects_a_rehashed_invalid_fence_window() {
        let stored = StoredRuntimeDirective::from_directive(runtime_directive(), [9; 32]).unwrap();
        let mut forged = stored.canonical_bytes.clone();
        let timestamp_offset = 8 + 2 + 7 + CANONICAL_CHAIN_REF_V1_LEN + 5 * 32;
        let orphan = forged[timestamp_offset..timestamp_offset + 8].to_vec();
        forged[timestamp_offset + 8..timestamp_offset + 16].copy_from_slice(&orphan);
        let body_len = forged.len() - 32;
        let forged_digest = row_digest(&forged[..body_len]);
        forged[body_len..].copy_from_slice(&forged_digest);
        assert!(matches!(
            StoredRuntimeDirective::<PHash>::decode(&forged),
            Err(RollbackRuntimeRebuildStoreError::Model(_))
        ));
    }

    #[test]
    fn runtime_rows_are_append_only_and_cannot_publish_the_head() {
        let source = include_str!("rollback_runtime_rebuild_store.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(source.contains("IF NOT EXISTS"));
        assert!(source.contains("Consistency::Quorum"));
        assert!(source.contains("SerialConsistency::LocalSerial"));
        assert!(!source.contains("CanonicalHeadTransition::complete_rollback"));
        assert!(!source.contains("hard_reset_and_truncate"));
        assert!(!source.contains("DELETE FROM"));
    }

    #[test]
    fn coordinator_contexts_are_fresh_adjacent_and_authority_namespaced() {
        let network = NetworkId::try_from_chain_id(1337).unwrap();
        let current = UniquePendingId::try_new(40).unwrap();
        let (processing, gathering) = coordinator_contexts(
            network,
            PendingCounterReadState::Current(current),
        )
        .unwrap();
        let prefix = ProcNamespacePrefix::for_authority(network, AuthorityScope::Coordinator);
        assert_eq!(processing.pending_id().get(), 41);
        assert_eq!(gathering.pending_id().get(), 42);
        assert_eq!(
            processing.proc_checkpoint_id(),
            prefix.derive_proc_id(processing.pending_id())
        );
        assert_eq!(
            gathering.proc_checkpoint_id(),
            prefix.derive_proc_id(gathering.pending_id())
        );
        assert_eq!(
            pending_predecessor(processing.pending_id()).unwrap(),
            PendingCounterExpected::Present(current)
        );

        let (first, second) = coordinator_contexts(
            network,
            PendingCounterReadState::Uninitialized,
        )
        .unwrap();
        assert_eq!(first.pending_id().get(), 1);
        assert_eq!(second.pending_id().get(), 2);
        assert_eq!(
            pending_predecessor(first.pending_id()).unwrap(),
            PendingCounterExpected::Absent
        );
    }

    #[test]
    fn coordinator_directive_is_durable_before_counter_allocation() {
        let source = include_str!("rollback_runtime_rebuild_store.rs")
            .split("pub(super) fn realm_directives")
            .next()
            .expect("Coordinator slice");
        let persist = source.find("self.persist_directive(candidate)").unwrap();
        let allocate = source.find("counter.allocate(allocation)").unwrap();
        assert!(persist < allocate);
        assert!(source.contains("Some(stored) if stored.slot == slot"));
        assert!(source.contains("self.revalidate_directive(&directive)"));
    }

    #[test]
    fn runtime_ready_barrier_roundtrips_and_binds_verifying_head() {
        let network = NetworkId::from(PsyChainNetworkType::PsyMainnet);
        let requested_checkpoint = checkpoint(10, 100);
        let target_checkpoint = checkpoint(5, 50);
        let current_ref = CanonicalChainRef::new(
            network,
            ChainEpoch::new(0),
            requested_checkpoint,
        );
        let current = StoredCanonicalHead::decode_persisted(
            network,
            0,
            &current_ref.to_canonical_bytes(),
            &RollbackControlState::<PHash>::Idle.to_canonical_bytes(),
        )
        .unwrap();
        let request = RollbackRequest::try_new(
            requested_checkpoint,
            target_checkpoint,
            TimestampFenceWindow::try_new(
                CommitWriteTimestampUs::try_from_i128(100).unwrap(),
                101,
                102,
            )
            .unwrap(),
            RollbackExecutionMode::InPlace,
            RollbackPlanDigest::try_new([7; 32]).unwrap(),
        )
        .unwrap();
        let requested = CanonicalHeadTransition::start_rollback(current, request)
            .unwrap()
            .candidate()
            .to_owned();
        let archiving = *CanonicalHeadTransition::begin_rollback_archive(requested)
            .unwrap()
            .candidate();
        let archive_ready = *CanonicalHeadTransition::complete_rollback_archive_barrier(archiving)
            .unwrap()
            .candidate();
        let deleting = *CanonicalHeadTransition::begin_rollback_delete(archive_ready)
            .unwrap()
            .candidate();
        let restoring = *CanonicalHeadTransition::begin_rollback_restore(deleting)
            .unwrap()
            .candidate();
        let verifying = *CanonicalHeadTransition::begin_rollback_verify(restoring)
            .unwrap()
            .candidate();
        let restored = CanonicalChainRef::new(
            network,
            ChainEpoch::new(1),
            target_checkpoint,
        );
        let stored = StoredRuntimeReadyBarrier::try_from_fields(
            verifying,
            restored,
            [7; 32],
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
            [5; 32],
            [6; 32],
            [8; 32],
            1,
            [9; 32],
            [4; 32],
        )
        .unwrap();
        assert_eq!(
            StoredRuntimeReadyBarrier::decode(&stored.canonical_bytes).unwrap(),
            stored
        );

        let mut tampered = stored.canonical_bytes.clone();
        tampered[20] ^= 1;
        assert_eq!(
            StoredRuntimeReadyBarrier::<PHash>::decode(&tampered),
            Err(RollbackRuntimeRebuildStoreError::DigestMismatch)
        );
        assert!(StoredRuntimeReadyBarrier::try_from_fields(
            verifying,
            restored,
            [6; 32],
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
            [5; 32],
            [6; 32],
            [8; 32],
            1,
            [9; 32],
            [4; 32],
        )
        .is_err());
    }

    fn checkpoint(id: u64, hash: u64) -> CheckpointRef<PHash> {
        CheckpointRef::new(
            CheckpointId::new(id),
            CheckpointHash::from_last_chain_hash(PHash::from_values(
                hash,
                hash + 1,
                hash + 2,
                hash + 3,
            )),
        )
    }
}
