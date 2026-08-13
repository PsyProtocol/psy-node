//! Immutable proof that one Realm's post-delete control rows reached the exact
//! deterministic restore-plan candidates.

#![allow(dead_code)]

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::{CanonicalChainRef, CANONICAL_CHAIN_REF_V1_LEN},
    chain_context::AuthorityScope,
};
use psy_node_core::store::{
    pending_generation_identity::PendingGenerationContext,
    timestamp::NewBranchWriteTimestampUs,
};
use sha2::{Digest, Sha256};

use super::{
    realm_rollback_target_restore_executor::ExecutedRealmRollbackTargetRestore,
    rollback_global_delete_barrier::SelectedRealmRollbackDeleteCompletion,
};

pub(super) const REALM_TARGET_RESTORE_COMPLETION_KEY_DOMAIN: i16 = -9;
const MAGIC: &[u8; 8] = b"PSYRTRC1";
const VERSION: u16 = 1;
const MAX_BYTES: usize = 16 * 1024;
const SLOT_DOMAIN: &[u8] = b"psy.rollback.realm-target-restore-completion-slot.v1\0";
const DIGEST_DOMAIN: &[u8] = b"psy.rollback.realm-target-restore-completion.v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RealmRollbackTargetRestoreCompletion<Hash> {
    authority: AuthorityScope,
    global_target: CanonicalChainRef<Hash>,
    restored_target: CanonicalChainRef<Hash>,
    participant_plan_digest: [u8; 32],
    global_barrier_slot: [u8; 32],
    global_barrier_digest: [u8; 32],
    delete_completion_slot: [u8; 32],
    delete_completion_digest: [u8; 32],
    restore_plan_slot: [u8; 32],
    restore_plan_digest: [u8; 32],
    processing: PendingGenerationContext,
    gathering: PendingGenerationContext,
    new_branch_write: NewBranchWriteTimestampUs,
    final_rows_digest: [u8; 32],
    archive_store_fingerprint: [u8; 32],
    slot: [u8; 32],
    digest: [u8; 32],
    canonical_bytes: Vec<u8>,
}

impl<Hash: Q256BitHash> RealmRollbackTargetRestoreCompletion<Hash> {
    pub(super) fn try_from_executed(
        executed: &ExecutedRealmRollbackTargetRestore<Hash>,
    ) -> Result<Self, RealmRollbackTargetRestoreCompletionError> {
        let plan = executed.plan().plan();
        let restored_target = *plan.restored_observation().map_err(model)?.chain();
        Self::try_from_fields(
            plan.authority(),
            *plan.global_target(),
            restored_target,
            *plan.participant_plan_digest(),
            *plan.global_delete_barrier_slot(),
            *plan.global_delete_barrier_digest(),
            *plan.realm_delete_completion_slot(),
            *plan.realm_delete_completion_digest(),
            *plan.slot(),
            *plan.digest(),
            plan.processing(),
            plan.gathering(),
            plan.new_branch_write(),
            *executed.final_rows_digest(),
            *plan.archive_store_fingerprint(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn try_from_fields(
        authority: AuthorityScope,
        global_target: CanonicalChainRef<Hash>,
        restored_target: CanonicalChainRef<Hash>,
        participant_plan_digest: [u8; 32],
        global_barrier_slot: [u8; 32],
        global_barrier_digest: [u8; 32],
        delete_completion_slot: [u8; 32],
        delete_completion_digest: [u8; 32],
        restore_plan_slot: [u8; 32],
        restore_plan_digest: [u8; 32],
        processing: PendingGenerationContext,
        gathering: PendingGenerationContext,
        new_branch_write: NewBranchWriteTimestampUs,
        final_rows_digest: [u8; 32],
        archive_store_fingerprint: [u8; 32],
    ) -> Result<Self, RealmRollbackTargetRestoreCompletionError> {
        let AuthorityScope::Realm { .. } = authority else {
            return Err(RealmRollbackTargetRestoreCompletionError::RealmRequired);
        };
        if [
            participant_plan_digest,
            global_barrier_slot,
            global_barrier_digest,
            delete_completion_slot,
            delete_completion_digest,
            restore_plan_slot,
            restore_plan_digest,
            final_rows_digest,
            archive_store_fingerprint,
        ]
        .contains(&[0; 32])
            || restored_target.network_id() != global_target.network_id()
            || restored_target.chain_epoch().get()
                != global_target.chain_epoch().get().checked_add(1)
                    .ok_or(RealmRollbackTargetRestoreCompletionError::BindingMismatch)?
            || restored_target.checkpoint().checkpoint_id()
                != global_target.checkpoint().checkpoint_id()
            || gathering.pending_id().get()
                != processing.pending_id().get().checked_add(1)
                    .ok_or(RealmRollbackTargetRestoreCompletionError::BindingMismatch)?
        {
            return Err(RealmRollbackTargetRestoreCompletionError::BindingMismatch);
        }
        let slot = completion_slot(
            global_target.network_id().chain_id(),
            authority,
            global_target.chain_epoch().get(),
            &participant_plan_digest,
            &global_barrier_slot,
            &global_barrier_digest,
            &archive_store_fingerprint,
        );
        let mut completion = Self {
            authority,
            global_target,
            restored_target,
            participant_plan_digest,
            global_barrier_slot,
            global_barrier_digest,
            delete_completion_slot,
            delete_completion_digest,
            restore_plan_slot,
            restore_plan_digest,
            processing,
            gathering,
            new_branch_write,
            final_rows_digest,
            archive_store_fingerprint,
            slot,
            digest: [0; 32],
            canonical_bytes: Vec::new(),
        };
        let body = completion.encode_body();
        completion.digest = completion_digest(&body);
        completion.canonical_bytes = body;
        completion.canonical_bytes.extend_from_slice(&completion.digest);
        Ok(completion)
    }

    pub(super) fn decode_canonical(
        bytes: &[u8],
    ) -> Result<Self, RealmRollbackTargetRestoreCompletionError> {
        if bytes.len() < 32 || bytes.len() > MAX_BYTES {
            return Err(RealmRollbackTargetRestoreCompletionError::MalformedRow);
        }
        let body_len = bytes.len() - 32;
        if completion_digest(&bytes[..body_len]) != bytes[body_len..] {
            return Err(RealmRollbackTargetRestoreCompletionError::DigestMismatch);
        }
        let mut cursor = Cursor::new(&bytes[..body_len]);
        if cursor.take(8)? != MAGIC {
            return Err(RealmRollbackTargetRestoreCompletionError::MalformedRow);
        }
        let version = cursor.u16()?;
        if version != VERSION {
            return Err(RealmRollbackTargetRestoreCompletionError::UnknownVersion(version));
        }
        let authority = decode_authority(cursor.take(7)?)?;
        let global_target = CanonicalChainRef::from_canonical_bytes(
            cursor.take(CANONICAL_CHAIN_REF_V1_LEN)?,
        ).map_err(model)?;
        let restored_target = CanonicalChainRef::from_canonical_bytes(
            cursor.take(CANONICAL_CHAIN_REF_V1_LEN)?,
        ).map_err(model)?;
        let participant_plan_digest = cursor.array32()?;
        let global_barrier_slot = cursor.array32()?;
        let global_barrier_digest = cursor.array32()?;
        let delete_completion_slot = cursor.array32()?;
        let delete_completion_digest = cursor.array32()?;
        let restore_plan_slot = cursor.array32()?;
        let restore_plan_digest = cursor.array32()?;
        let processing = context(cursor.u64()?, cursor.u128()?)?;
        let gathering = context(cursor.u64()?, cursor.u128()?)?;
        let orphan_max = psy_node_core::store::timestamp::CommitWriteTimestampUs::try_from_i128(
            i128::from(cursor.i64()?),
        ).map_err(model)?;
        let fence = psy_node_core::store::timestamp::DeleteFenceTimestampUs::try_after(
            orphan_max,
            i128::from(cursor.i64()?),
        ).map_err(model)?;
        let new_branch_write = NewBranchWriteTimestampUs::try_after(
            fence,
            i128::from(cursor.i64()?),
        ).map_err(model)?;
        let final_rows_digest = cursor.array32()?;
        let archive_store_fingerprint = cursor.array32()?;
        let slot = cursor.array32()?;
        if !cursor.is_empty() {
            return Err(RealmRollbackTargetRestoreCompletionError::TrailingBytes);
        }
        let decoded = Self::try_from_fields(
            authority,
            global_target,
            restored_target,
            participant_plan_digest,
            global_barrier_slot,
            global_barrier_digest,
            delete_completion_slot,
            delete_completion_digest,
            restore_plan_slot,
            restore_plan_digest,
            processing,
            gathering,
            new_branch_write,
            final_rows_digest,
            archive_store_fingerprint,
        )?;
        if decoded.slot != slot || decoded.canonical_bytes != bytes {
            return Err(RealmRollbackTargetRestoreCompletionError::NonCanonicalEncoding);
        }
        Ok(decoded)
    }

    fn encode_body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1024);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_be_bytes());
        out.extend_from_slice(&encode_authority(self.authority));
        out.extend_from_slice(&self.global_target.to_canonical_bytes());
        out.extend_from_slice(&self.restored_target.to_canonical_bytes());
        for bytes in [
            &self.participant_plan_digest,
            &self.global_barrier_slot,
            &self.global_barrier_digest,
            &self.delete_completion_slot,
            &self.delete_completion_digest,
            &self.restore_plan_slot,
            &self.restore_plan_digest,
        ] {
            out.extend_from_slice(bytes);
        }
        push_context(&mut out, self.processing);
        push_context(&mut out, self.gathering);
        out.extend_from_slice(&self.new_branch_write.delete_fence().orphan_write_max().as_i64().to_be_bytes());
        out.extend_from_slice(&self.new_branch_write.delete_fence().as_i64().to_be_bytes());
        out.extend_from_slice(&self.new_branch_write.as_commit_timestamp().as_i64().to_be_bytes());
        out.extend_from_slice(&self.final_rows_digest);
        out.extend_from_slice(&self.archive_store_fingerprint);
        out.extend_from_slice(&self.slot);
        out
    }

    pub(super) fn slot_for_selected(
        selected: &SelectedRealmRollbackDeleteCompletion<Hash>,
        archive_store_fingerprint: [u8; 32],
    ) -> [u8; 32] {
        completion_slot(
            selected.barrier().target().network_id().chain_id(),
            selected.completion().authority(),
            selected.barrier().target().chain_epoch().get(),
            selected.barrier().participant_plan_digest(),
            selected.barrier().slot(),
            selected.barrier().digest(),
            &archive_store_fingerprint,
        )
    }

    pub(super) const fn authority(&self) -> AuthorityScope { self.authority }
    pub(super) const fn global_target(&self) -> &CanonicalChainRef<Hash> { &self.global_target }
    pub(super) const fn restored_target(&self) -> &CanonicalChainRef<Hash> { &self.restored_target }
    pub(super) const fn participant_plan_digest(&self) -> &[u8; 32] { &self.participant_plan_digest }
    pub(super) const fn global_barrier_slot(&self) -> &[u8; 32] { &self.global_barrier_slot }
    pub(super) const fn global_barrier_digest(&self) -> &[u8; 32] { &self.global_barrier_digest }
    pub(super) const fn delete_completion_slot(&self) -> &[u8; 32] { &self.delete_completion_slot }
    pub(super) const fn delete_completion_digest(&self) -> &[u8; 32] { &self.delete_completion_digest }
    pub(super) const fn restore_plan_slot(&self) -> &[u8; 32] { &self.restore_plan_slot }
    pub(super) const fn restore_plan_digest(&self) -> &[u8; 32] { &self.restore_plan_digest }
    pub(super) const fn processing(&self) -> PendingGenerationContext { self.processing }
    pub(super) const fn gathering(&self) -> PendingGenerationContext { self.gathering }
    pub(super) const fn new_branch_write(&self) -> NewBranchWriteTimestampUs { self.new_branch_write }
    pub(super) const fn final_rows_digest(&self) -> &[u8; 32] { &self.final_rows_digest }
    pub(super) const fn archive_store_fingerprint(&self) -> &[u8; 32] { &self.archive_store_fingerprint }
    pub(super) const fn slot(&self) -> &[u8; 32] { &self.slot }
    pub(super) const fn digest(&self) -> &[u8; 32] { &self.digest }
    pub(super) fn canonical_bytes(&self) -> &[u8] { &self.canonical_bytes }
}

fn context(pending: u64, proc_id: u128) -> Result<PendingGenerationContext, RealmRollbackTargetRestoreCompletionError> {
    PendingGenerationContext::try_from_legacy(pending, proc_id).map_err(model)
}

fn push_context(out: &mut Vec<u8>, context: PendingGenerationContext) {
    out.extend_from_slice(&context.pending_id().get().to_be_bytes());
    out.extend_from_slice(&context.proc_checkpoint_id().as_u128().to_be_bytes());
}

fn completion_slot(
    network: u32,
    authority: AuthorityScope,
    old_epoch: u64,
    plan_digest: &[u8; 32],
    barrier_slot: &[u8; 32],
    barrier_digest: &[u8; 32],
    store_fingerprint: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SLOT_DOMAIN);
    hasher.update(network.to_be_bytes());
    hasher.update(encode_authority(authority));
    hasher.update(old_epoch.to_be_bytes());
    hasher.update(plan_digest);
    hasher.update(barrier_slot);
    hasher.update(barrier_digest);
    hasher.update(store_fingerprint);
    hasher.finalize().into()
}

fn completion_digest(body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update(body);
    hasher.finalize().into()
}

fn encode_authority(authority: AuthorityScope) -> [u8; 7] {
    let mut bytes = [0_u8; 7];
    match authority {
        AuthorityScope::Coordinator => bytes[0] = 1,
        AuthorityScope::Realm { realm_id, realm_sub_id } => {
            bytes[0] = 2;
            bytes[1..5].copy_from_slice(&realm_id.to_be_bytes());
            bytes[5..7].copy_from_slice(&realm_sub_id.to_be_bytes());
        }
    }
    bytes
}

fn decode_authority(bytes: &[u8]) -> Result<AuthorityScope, RealmRollbackTargetRestoreCompletionError> {
    match bytes {
        [1, 0, 0, 0, 0, 0, 0] => Ok(AuthorityScope::Coordinator),
        [2, a, b, c, d, e, f] => Ok(AuthorityScope::Realm {
            realm_id: u32::from_be_bytes([*a, *b, *c, *d]),
            realm_sub_id: u16::from_be_bytes([*e, *f]),
        }),
        _ => Err(RealmRollbackTargetRestoreCompletionError::MalformedRow),
    }
}

fn model(error: impl fmt::Display) -> RealmRollbackTargetRestoreCompletionError {
    RealmRollbackTargetRestoreCompletionError::Model(error.to_string())
}

struct Cursor<'a> { bytes: &'a [u8], offset: usize }
impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self { Self { bytes, offset: 0 } }
    fn take(&mut self, len: usize) -> Result<&'a [u8], RealmRollbackTargetRestoreCompletionError> {
        let end = self.offset.checked_add(len).ok_or(RealmRollbackTargetRestoreCompletionError::MalformedRow)?;
        let value = self.bytes.get(self.offset..end).ok_or(RealmRollbackTargetRestoreCompletionError::MalformedRow)?;
        self.offset = end;
        Ok(value)
    }
    fn u16(&mut self) -> Result<u16, RealmRollbackTargetRestoreCompletionError> { Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap())) }
    fn u64(&mut self) -> Result<u64, RealmRollbackTargetRestoreCompletionError> { Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap())) }
    fn i64(&mut self) -> Result<i64, RealmRollbackTargetRestoreCompletionError> { Ok(i64::from_be_bytes(self.take(8)?.try_into().unwrap())) }
    fn u128(&mut self) -> Result<u128, RealmRollbackTargetRestoreCompletionError> { Ok(u128::from_be_bytes(self.take(16)?.try_into().unwrap())) }
    fn array32(&mut self) -> Result<[u8; 32], RealmRollbackTargetRestoreCompletionError> { Ok(self.take(32)?.try_into().unwrap()) }
    fn is_empty(&self) -> bool { self.offset == self.bytes.len() }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RealmRollbackTargetRestoreCompletionError {
    RealmRequired,
    BindingMismatch,
    MalformedRow,
    UnknownVersion(u16),
    DigestMismatch,
    TrailingBytes,
    NonCanonicalEncoding,
    Model(String),
}

impl fmt::Display for RealmRollbackTargetRestoreCompletionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Realm target restore completion error: {self:?}")
    }
}
impl Error for RealmRollbackTargetRestoreCompletionError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_domains_are_stable_and_decode_fails_closed() {
        assert_eq!(REALM_TARGET_RESTORE_COMPLETION_KEY_DOMAIN, -9);
        assert_ne!(SLOT_DOMAIN, DIGEST_DOMAIN);
        assert_eq!(RealmRollbackTargetRestoreCompletion::<parth_core::PHash>::decode_canonical(&[]), Err(RealmRollbackTargetRestoreCompletionError::MalformedRow));
    }
}
