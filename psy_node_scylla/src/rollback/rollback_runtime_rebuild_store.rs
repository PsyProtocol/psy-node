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
    canonical_head::StoredCanonicalHead,
    pending_generation_identity::PendingGenerationContext,
    rollback_control::RollbackControlState,
    rollback_runtime_rebuild::{
        RollbackRuntimeRebuildDirective, RollbackRuntimeRebuildReport, restored_target,
    },
};
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{Consistency, SerialConsistency, prepared::PreparedStatement},
};
use sha2::{Digest, Sha256};

use super::{
    CqlKeyspaceName,
    coordinator_rollback_archive_store::COORDINATOR_ROLLBACK_SUFFIX_ARCHIVE_TABLE,
    coordinator_rollback_delete_completion_store::PersistedCoordinatorRollbackDeleteCompletion,
    realm_rollback_physical_archive_store::PersistedRealmRollbackTargetRestoreCompletion,
    rollback_global_restore_barrier::PersistedRollbackGlobalRestoreBarrier,
};

const DIRECTIVE_KEY_DOMAIN: i16 = -11;
const REPORT_KEY_DOMAIN: i16 = -12;
const REVISION: i64 = 1;
const DIRECTIVE_MAGIC: &[u8; 8] = b"PSYRRBD1";
const REPORT_MAGIC: &[u8; 8] = b"PSYRRBR1";
const VERSION: u16 = 1;
const MAX_BYTES: usize = 16 * 1024;
const DIRECTIVE_SLOT_DOMAIN: &[u8] = b"psy.rollback.runtime-directive-slot.v1\0";
const REPORT_SLOT_DOMAIN: &[u8] = b"psy.rollback.runtime-report-slot.v1\0";
const ROW_DIGEST_DOMAIN: &[u8] = b"psy.rollback.runtime-row.v1\0";
const FRAGMENT_DOMAIN: &[u8] = b"psy.rollback.runtime-fragment.v1\0";
const STORE_DOMAIN: &[u8] = b"psy.rollback.runtime-rebuild-store.v1\0";

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
    pub(super) const fn report(&self) -> &RollbackRuntimeRebuildReport<Hash> {
        &self.stored.report
    }

    pub(super) const fn slot(&self) -> &[u8; 32] {
        &self.stored.slot
    }

    pub(super) const fn row_digest(&self) -> &[u8; 32] {
        &self.stored.row_digest
    }
}

pub(super) struct ScyllaRollbackRuntimeRebuildStore {
    session: Arc<Session>,
    fingerprint: [u8; 32],
    insert: PreparedStatement,
    read: PreparedStatement,
}

impl ScyllaRollbackRuntimeRebuildStore {
    pub(super) async fn prepare(
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

    pub(super) fn coordinator_directive<Hash: Q256BitHash>(
        &self,
        barrier: &PersistedRollbackGlobalRestoreBarrier<Hash>,
        coordinator: &PersistedCoordinatorRollbackDeleteCompletion<Hash>,
    ) -> Result<RollbackRuntimeRebuildDirective<Hash>, RollbackRuntimeRebuildStoreError> {
        let barrier = barrier.barrier();
        if barrier.coordinator_completion_slot() != coordinator.completion().slot()
            || barrier.coordinator_completion_digest() != coordinator.completion().digest()
            || barrier.target() != coordinator.completion().target()
        {
            return Err(RollbackRuntimeRebuildStoreError::BindingMismatch);
        }
        RollbackRuntimeRebuildDirective::try_from_storage(
            AuthorityScope::Coordinator,
            restored_target(*barrier.target()).map_err(model)?,
            *barrier.participant_plan_digest(),
            *barrier.slot(),
            *barrier.digest(),
            *coordinator.completion().slot(),
            *coordinator.completion().digest(),
            None,
            None,
        )
        .map_err(model)
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

    /// Select the storage-authored directive from the exact VERIFYING head.
    /// The caller supplies only its authority identity; target, epoch, and plan
    /// are selected from the durable Coordinator row.
    pub(super) async fn read_selected_directive<Hash: Q256BitHash>(
        &self,
        verifying_head: StoredCanonicalHead<Hash>,
        authority: AuthorityScope,
    ) -> Result<Option<RollbackRuntimeRebuildDirective<Hash>>, RollbackRuntimeRebuildStoreError> {
        let request = match verifying_head.rollback_control() {
            RollbackControlState::Verifying(request) => request,
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

fn decode_applied(result: QueryResult) -> Result<bool, RollbackRuntimeRebuildStoreError> {
    let rows = result
        .into_rows_result()
        .map_err(cql)?
        .rows::<(Option<bool>,)>()
        .map_err(cql)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(cql)?;
    match rows.as_slice() {
        [(Some(applied),)] => Ok(*applied),
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
pub(super) enum RollbackRuntimeRebuildStoreError {
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
    NotVerifying,
    StoreFingerprintMismatch,
    Conflict,
    Indeterminate(String),
    Model(String),
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
    fn u64(&mut self) -> Result<u64, RollbackRuntimeRebuildStoreError> { Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("8"))) }
    fn u128(&mut self) -> Result<u128, RollbackRuntimeRebuildStoreError> { Ok(u128::from_be_bytes(self.take(16)?.try_into().expect("16"))) }
    fn array32(&mut self) -> Result<[u8; 32], RollbackRuntimeRebuildStoreError> { Ok(self.take(32)?.try_into().expect("32")) }
    fn is_empty(&self) -> bool { self.offset == self.bytes.len() }
}

#[cfg(test)]
mod tests {
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
}
