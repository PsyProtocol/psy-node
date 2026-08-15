//! Canonical physical inventory for one committed Realm generation.
//!
//! The existing full-commit manifest proves exact writes but intentionally
//! stores only digests and counts. Rollback additionally needs the complete
//! physical mutation identities so it never guesses which hot rows belong to
//! a discarded suffix. This object retains the exact narrow intent plus every
//! registry-resolved non-narrow PUT. It is inert data: persistence, COMMITTED
//! selection, archive, delete, and restore authority are separate layers.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::CanonicalChainRef,
    chain_context::{AuthorityObservation, AUTHORITY_OBSERVATION_V1_LEN},
};
use psy_node_core::store::{
    branch_exact_dual_write::BranchExactDualWriteIntent,
    branch_exact_schema::AuthorityScope,
    branch_pending_mapping::BranchPendingMapping,
    timestamp::CommitWriteTimestampUs,
};
use sha2::{Digest, Sha256};

use super::{
    BranchExactWriterPrepared, SealedTimestampedPut, TimestampedWriteKind,
    TimestampedMutationError,
    realm_full_commit_execution::RealmFullCommitExecutionSchedule,
    realm_full_commit_plan::RealmFullCommitPhysicalPlan,
};

const MAGIC: &[u8; 8] = b"PSYRRINV";
const VERSION_FULL_COMMIT: u16 = 1;
const VERSION_WITH_LINEAGE: u16 = 2;
const SLOT_DOMAIN: &[u8] = b"psy.rollback.realm-commit-inventory-slot.v1\0";
const DIGEST_DOMAIN: &[u8] = b"psy.rollback.realm-commit-inventory.v1\0";
const MAX_ROWS: usize = 1_048_576;
const MAX_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct RealmRollbackCommitInventorySlot([u8; 32]);

impl RealmRollbackCommitInventorySlot {
    pub(crate) const fn as_bytes(&self) -> &[u8; 32] { &self.0 }

    pub(crate) fn for_candidate<Hash: Q256BitHash>(
        authority: AuthorityScope,
        candidate: &BranchPendingMapping<Hash>,
    ) -> Self {
        inventory_slot(authority, candidate.canonical_chain())
    }

    pub(crate) fn for_chain<Hash: Q256BitHash>(
        authority: AuthorityScope,
        chain: &CanonicalChainRef<Hash>,
    ) -> Self {
        inventory_slot(authority, chain)
    }

    pub(crate) const fn from_persisted(bytes: [u8; 32]) -> Self { Self(bytes) }
}

#[derive(Debug, Eq, PartialEq)]
enum RealmRollbackCommitInventoryLineage<Hash> {
    FullCommit {
        candidate: BranchPendingMapping<Hash>,
        narrow_intent: BranchExactDualWriteIntent<Hash>,
    },
    RealmSync {
        observation: AuthorityObservation<Hash>,
    },
}

/// Non-Clone complete inventory. A later store may persist it, but this model
/// itself cannot mark a generation committed or authorize any mutation.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct RealmRollbackCommitInventory<Hash> {
    slot: RealmRollbackCommitInventorySlot,
    authority: AuthorityScope,
    chain: CanonicalChainRef<Hash>,
    timestamp: CommitWriteTimestampUs,
    coverage_digest: [u8; 32],
    total_mutation_count: u64,
    lineage: RealmRollbackCommitInventoryLineage<Hash>,
    typed_puts: Vec<SealedTimestampedPut>,
    canonical_bytes: Vec<u8>,
    digest: [u8; 32],
}

impl<Hash: Q256BitHash> RealmRollbackCommitInventory<Hash> {
    pub(crate) fn try_from_schedule(
        narrow: &BranchExactWriterPrepared<Hash>,
        plan: &RealmFullCommitPhysicalPlan,
        schedule: &RealmFullCommitExecutionSchedule,
    ) -> Result<Self, RealmRollbackCommitInventoryError> {
        if plan.narrow_prepared_digest() != narrow.digest()
            || plan.narrow_intent_digest()
                != narrow.intent().intent_digest().as_bytes()
            || schedule.narrow_prepared_digest() != narrow.digest()
            || schedule.coverage_digest() != plan.coverage().digest()
        {
            return Err(RealmRollbackCommitInventoryError::SourceMismatch);
        }
        let mut typed_puts = schedule
            .rows()
            .iter()
            .map(|row| row.sealed().clone())
            .collect::<Vec<_>>();
        typed_puts.sort_by(|left, right| {
            (
                left.resolved().mutation().physical_table().stable_id(),
                left.resolved().locator_bytes(),
            )
                .cmp(&(
                    right.resolved().mutation().physical_table().stable_id(),
                    right.resolved().locator_bytes(),
                ))
        });
        Self::try_from_lineage_parts(
            RealmRollbackCommitInventoryLineage::FullCommit {
                candidate: *narrow.intent().candidate(),
                narrow_intent: narrow.intent().clone(),
            },
            narrow.timestamp(),
            *plan.coverage().digest(),
            plan.coverage().total_mutation_count(),
            typed_puts,
        )
    }

    pub(crate) fn decode_canonical(
        bytes: &[u8],
    ) -> Result<Self, RealmRollbackCommitInventoryError> {
        if bytes.len() > MAX_BYTES {
            return Err(RealmRollbackCommitInventoryError::PayloadTooLarge);
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take(8)? != MAGIC {
            return Err(RealmRollbackCommitInventoryError::InvalidMagic);
        }
        let version = cursor.u16()?;
        if version != VERSION_FULL_COMMIT && version != VERSION_WITH_LINEAGE {
            return Err(RealmRollbackCommitInventoryError::UnknownVersion(version));
        }
        let lineage_tag = if version == VERSION_FULL_COMMIT { 1 } else { cursor.u8()? };
        let timestamp = CommitWriteTimestampUs::try_from_i128(i128::from(cursor.i64()?))
            .map_err(|_| RealmRollbackCommitInventoryError::InvalidTimestamp)?;
        let coverage_digest = cursor.array_32()?;
        let total_mutation_count = cursor.u64()?;
        let lineage_bytes = cursor.bytes()?;
        let lineage = match lineage_tag {
            1 => {
                let narrow_intent =
                    BranchExactDualWriteIntent::<Hash>::decode_persisted(lineage_bytes)
                        .map_err(|_| RealmRollbackCommitInventoryError::InvalidNarrowIntent)?;
                RealmRollbackCommitInventoryLineage::FullCommit {
                    candidate: *narrow_intent.candidate(),
                    narrow_intent,
                }
            }
            2 if lineage_bytes.len() == AUTHORITY_OBSERVATION_V1_LEN => {
                RealmRollbackCommitInventoryLineage::RealmSync {
                    observation: AuthorityObservation::from_canonical_bytes(lineage_bytes)
                        .map_err(|_| RealmRollbackCommitInventoryError::InvalidSyncObservation)?,
                }
            }
            2 => return Err(RealmRollbackCommitInventoryError::InvalidSyncObservation),
            other => return Err(RealmRollbackCommitInventoryError::UnknownLineage(other)),
        };
        let row_count = cursor.u32()? as usize;
        if row_count > MAX_ROWS {
            return Err(RealmRollbackCommitInventoryError::TooManyRows(row_count));
        }
        let mut typed_puts = Vec::with_capacity(row_count);
        for _ in 0..row_count {
            typed_puts.push(
                SealedTimestampedPut::decode_realm_commit_inventory_canonical(cursor.bytes()?)
                    .map_err(RealmRollbackCommitInventoryError::InvalidTypedPut)?,
            );
        }
        let digest = cursor.array_32()?;
        if !cursor.is_empty() {
            return Err(RealmRollbackCommitInventoryError::TrailingBytes);
        }
        if bytes.len() < 32
            || inventory_digest(&bytes[..bytes.len() - 32]) != digest
        {
            return Err(RealmRollbackCommitInventoryError::DigestMismatch);
        }
        let decoded = Self::try_from_lineage_parts(
            lineage,
            timestamp,
            coverage_digest,
            total_mutation_count,
            typed_puts,
        )?;
        if decoded.canonical_bytes != bytes || decoded.digest != digest {
            return Err(RealmRollbackCommitInventoryError::NonCanonicalEncoding);
        }
        Ok(decoded)
    }

    pub(crate) fn try_from_realm_sync(
        observation: AuthorityObservation<Hash>,
        timestamp: CommitWriteTimestampUs,
        mut typed_puts: Vec<SealedTimestampedPut>,
    ) -> Result<Self, RealmRollbackCommitInventoryError> {
        typed_puts.sort_by(|left, right| {
            (
                left.resolved().mutation().physical_table().stable_id(),
                left.resolved().locator_bytes(),
            )
                .cmp(&(
                    right.resolved().mutation().physical_table().stable_id(),
                    right.resolved().locator_bytes(),
                ))
        });
        let mut hasher = Sha256::new();
        hasher.update(b"psy.rollback.realm-sync-inventory-coverage.v1\0");
        hasher.update(observation.to_canonical_bytes());
        for put in &typed_puts {
            hasher.update(put.mutation_digest().as_bytes());
        }
        let total_mutation_count = u64::try_from(typed_puts.len())
            .map_err(|_| RealmRollbackCommitInventoryError::CountOutOfRange)?;
        Self::try_from_lineage_parts(
            RealmRollbackCommitInventoryLineage::RealmSync { observation },
            timestamp,
            hasher.finalize().into(),
            total_mutation_count,
            typed_puts,
        )
    }

    /// Qualification-only constructor for exercising the production archive
    /// owner with a small canonical narrow-write history. It does not create
    /// a COMMITTED marker and is unavailable outside test builds.
    #[cfg(test)]
    pub(crate) fn qualification_from_narrow(
        narrow_intent: BranchExactDualWriteIntent<Hash>,
        timestamp: CommitWriteTimestampUs,
    ) -> Result<Self, RealmRollbackCommitInventoryError> {
        let mut hasher = Sha256::new();
        hasher.update(b"psy.rollback.qualification-narrow-inventory.v1\0");
        hasher.update(narrow_intent.intent_digest().as_bytes());
        let coverage_digest = hasher.finalize().into();
        let total_mutation_count = u64::try_from(narrow_intent.mutations().len())
            .map_err(|_| RealmRollbackCommitInventoryError::CountOutOfRange)?;
        let candidate = *narrow_intent.candidate();
        Self::try_from_lineage_parts(
            RealmRollbackCommitInventoryLineage::FullCommit { candidate, narrow_intent },
            timestamp,
            coverage_digest,
            total_mutation_count,
            Vec::new(),
        )
    }

    fn try_from_lineage_parts(
        lineage: RealmRollbackCommitInventoryLineage<Hash>,
        timestamp: CommitWriteTimestampUs,
        coverage_digest: [u8; 32],
        total_mutation_count: u64,
        typed_puts: Vec<SealedTimestampedPut>,
    ) -> Result<Self, RealmRollbackCommitInventoryError> {
        let (authority, chain, narrow_count) = match &lineage {
            RealmRollbackCommitInventoryLineage::FullCommit { candidate, narrow_intent } => {
                if candidate != narrow_intent.candidate() {
                    return Err(RealmRollbackCommitInventoryError::SourceMismatch);
                }
                (narrow_intent.authority(), *candidate.canonical_chain(), narrow_intent.mutations().len())
            }
            RealmRollbackCommitInventoryLineage::RealmSync { observation } => {
                (observation.authority(), *observation.chain(), 0)
            }
        };
        let AuthorityScope::Realm { .. } = authority else {
            return Err(RealmRollbackCommitInventoryError::RealmRequired);
        };
        if coverage_digest == [0; 32] {
            return Err(RealmRollbackCommitInventoryError::ZeroCoverageDigest);
        }
        if typed_puts.len() > MAX_ROWS {
            return Err(RealmRollbackCommitInventoryError::TooManyRows(
                typed_puts.len(),
            ));
        }
        let observed_total = narrow_count
            .checked_add(typed_puts.len())
            .and_then(|count| u64::try_from(count).ok())
            .ok_or(RealmRollbackCommitInventoryError::CountOutOfRange)?;
        if observed_total != total_mutation_count {
            return Err(RealmRollbackCommitInventoryError::MutationCountMismatch);
        }
        for put in &typed_puts {
            if put.write_kind() != TimestampedWriteKind::AuthorityCommit {
                return Err(RealmRollbackCommitInventoryError::TimestampOrKindMismatch);
            }
            if matches!(&lineage, RealmRollbackCommitInventoryLineage::FullCommit { .. })
                && put.timestamp() != timestamp
            {
                return Err(RealmRollbackCommitInventoryError::TimestampOrKindMismatch);
            }
        }
        if typed_puts.windows(2).any(|pair| {
            let left = (
                pair[0].resolved().mutation().physical_table().stable_id(),
                pair[0].resolved().locator_bytes(),
            );
            let right = (
                pair[1].resolved().mutation().physical_table().stable_id(),
                pair[1].resolved().locator_bytes(),
            );
            left >= right
        }) {
            return Err(RealmRollbackCommitInventoryError::RowsNotCanonical);
        }

        let slot = inventory_slot(authority, &chain);
        let mut inventory = Self {
            slot,
            authority,
            chain,
            timestamp,
            coverage_digest,
            total_mutation_count,
            lineage,
            typed_puts,
            canonical_bytes: Vec::new(),
            digest: [0; 32],
        };
        let body = encode_without_digest(&inventory)?;
        inventory.digest = inventory_digest(&body);
        inventory.canonical_bytes = body;
        inventory.canonical_bytes.extend_from_slice(&inventory.digest);
        if inventory.canonical_bytes.len() > MAX_BYTES {
            return Err(RealmRollbackCommitInventoryError::PayloadTooLarge);
        }
        Ok(inventory)
    }

    pub(crate) const fn slot(&self) -> RealmRollbackCommitInventorySlot { self.slot }
    pub(crate) const fn authority(&self) -> AuthorityScope { self.authority }
    pub(crate) const fn chain(&self) -> &CanonicalChainRef<Hash> { &self.chain }
    pub(crate) const fn full_candidate(&self) -> Option<&BranchPendingMapping<Hash>> {
        match &self.lineage {
            RealmRollbackCommitInventoryLineage::FullCommit { candidate, .. } => Some(candidate),
            RealmRollbackCommitInventoryLineage::RealmSync { .. } => None,
        }
    }
    pub(crate) const fn sync_observation(&self) -> Option<&AuthorityObservation<Hash>> {
        match &self.lineage {
            RealmRollbackCommitInventoryLineage::RealmSync { observation } => Some(observation),
            RealmRollbackCommitInventoryLineage::FullCommit { .. } => None,
        }
    }
    pub(crate) const fn timestamp(&self) -> CommitWriteTimestampUs { self.timestamp }
    pub(crate) const fn coverage_digest(&self) -> &[u8; 32] { &self.coverage_digest }
    pub(crate) const fn total_mutation_count(&self) -> u64 { self.total_mutation_count }
    pub(crate) const fn narrow_intent(&self) -> Option<&BranchExactDualWriteIntent<Hash>> {
        match &self.lineage {
            RealmRollbackCommitInventoryLineage::FullCommit { narrow_intent, .. } => Some(narrow_intent),
            RealmRollbackCommitInventoryLineage::RealmSync { .. } => None,
        }
    }
    pub(crate) fn typed_puts(&self) -> &[SealedTimestampedPut] { &self.typed_puts }
    pub(crate) fn canonical_bytes(&self) -> &[u8] { &self.canonical_bytes }
    pub(crate) const fn digest(&self) -> &[u8; 32] { &self.digest }
}

fn inventory_slot<Hash: Q256BitHash>(
    authority: AuthorityScope,
    chain: &CanonicalChainRef<Hash>,
) -> RealmRollbackCommitInventorySlot {
    let AuthorityScope::Realm { realm_id, realm_sub_id } = authority else {
        unreachable!("inventory validates Realm authority")
    };
    let mut hasher = Sha256::new();
    hasher.update(SLOT_DOMAIN);
    hasher.update(chain.network_id().chain_id().to_be_bytes());
    hasher.update(realm_id.to_be_bytes());
    hasher.update(realm_sub_id.to_be_bytes());
    hasher.update(chain.chain_epoch().get().to_be_bytes());
    hasher.update(
        chain
            .checkpoint()
            .checkpoint_id()
            .get()
            .to_be_bytes(),
    );
    RealmRollbackCommitInventorySlot(hasher.finalize().into())
}

fn encode_without_digest<Hash: Q256BitHash>(
    inventory: &RealmRollbackCommitInventory<Hash>,
) -> Result<Vec<u8>, RealmRollbackCommitInventoryError> {
    let (lineage_tag, lineage) = match &inventory.lineage {
        RealmRollbackCommitInventoryLineage::FullCommit { narrow_intent, .. } => {
            (1_u8, narrow_intent.to_canonical_bytes().to_vec())
        }
        RealmRollbackCommitInventoryLineage::RealmSync { observation } => {
            (2_u8, observation.to_canonical_bytes().to_vec())
        }
    };
    let mut out = Vec::with_capacity(
        128 + lineage.len()
            + inventory
                .typed_puts
                .iter()
                .map(|put| put.canonical_bytes().len() + 4)
                .sum::<usize>(),
    );
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION_WITH_LINEAGE.to_be_bytes());
    out.push(lineage_tag);
    out.extend_from_slice(&inventory.timestamp.as_i64().to_be_bytes());
    out.extend_from_slice(&inventory.coverage_digest);
    out.extend_from_slice(&inventory.total_mutation_count.to_be_bytes());
    encode_bytes(&lineage, &mut out)?;
    out.extend_from_slice(
        &u32::try_from(inventory.typed_puts.len())
            .map_err(|_| RealmRollbackCommitInventoryError::CountOutOfRange)?
            .to_be_bytes(),
    );
    for put in &inventory.typed_puts {
        encode_bytes(put.canonical_bytes(), &mut out)?;
    }
    Ok(out)
}

fn encode_bytes(
    bytes: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), RealmRollbackCommitInventoryError> {
    out.extend_from_slice(
        &u32::try_from(bytes.len())
            .map_err(|_| RealmRollbackCommitInventoryError::PayloadTooLarge)?
            .to_be_bytes(),
    );
    out.extend_from_slice(bytes);
    Ok(())
}

fn inventory_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update(bytes);
    hasher.finalize().into()
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self { Self { bytes, offset: 0 } }
    fn take(&mut self, len: usize) -> Result<&'a [u8], RealmRollbackCommitInventoryError> {
        let end = self.offset.checked_add(len).ok_or(RealmRollbackCommitInventoryError::Truncated)?;
        let value = self.bytes.get(self.offset..end).ok_or(RealmRollbackCommitInventoryError::Truncated)?;
        self.offset = end;
        Ok(value)
    }
    fn u16(&mut self) -> Result<u16, RealmRollbackCommitInventoryError> { Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap())) }
    fn u8(&mut self) -> Result<u8, RealmRollbackCommitInventoryError> { Ok(self.take(1)?[0]) }
    fn u32(&mut self) -> Result<u32, RealmRollbackCommitInventoryError> { Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap())) }
    fn u64(&mut self) -> Result<u64, RealmRollbackCommitInventoryError> { Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap())) }
    fn i64(&mut self) -> Result<i64, RealmRollbackCommitInventoryError> { Ok(i64::from_be_bytes(self.take(8)?.try_into().unwrap())) }
    fn array_32(&mut self) -> Result<[u8; 32], RealmRollbackCommitInventoryError> { Ok(self.take(32)?.try_into().unwrap()) }
    fn bytes(&mut self) -> Result<&'a [u8], RealmRollbackCommitInventoryError> { let len = self.u32()? as usize; self.take(len) }
    fn is_empty(&self) -> bool { self.offset == self.bytes.len() }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RealmRollbackCommitInventoryError {
    RealmRequired,
    SourceMismatch,
    ZeroCoverageDigest,
    TooManyRows(usize),
    CountOutOfRange,
    MutationCountMismatch,
    TimestampOrKindMismatch,
    RowsNotCanonical,
    PayloadTooLarge,
    InvalidMagic,
    UnknownVersion(u16),
    InvalidTimestamp,
    InvalidNarrowIntent,
    InvalidSyncObservation,
    UnknownLineage(u8),
    InvalidTypedPut(TimestampedMutationError),
    Truncated,
    TrailingBytes,
    DigestMismatch,
    NonCanonicalEncoding,
}

impl fmt::Display for RealmRollbackCommitInventoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid Realm rollback commit inventory: {self:?}")
    }
}

impl Error for RealmRollbackCommitInventoryError {}

#[cfg(test)]
mod tests {
    use parth_core::PHash;
    use psy_data::protocol::chain_context::{
        AuthorityStateCheckpointId, AuthorityStateRoot,
    };
    use psy_node_core::store::timestamp::CommitWriteTimestampUs;

    use super::*;

    fn inventory() -> RealmRollbackCommitInventory<PHash> {
        let timestamp = CommitWriteTimestampUs::try_from_i128(10_000).unwrap();
        let prepared = crate::rollback::realm_full_commit_plan::tests::qualification_prepared(timestamp);
        let plan = crate::rollback::realm_full_commit_plan::tests::qualification_no_state_full_plan(&prepared);
        let schedule = RealmFullCommitExecutionSchedule::try_from_plan(&plan, &prepared).unwrap();
        RealmRollbackCommitInventory::try_from_schedule(&prepared, &plan, &schedule).unwrap()
    }

    #[test]
    fn complete_inventory_roundtrips_and_binds_stable_checkpoint_slot() {
        let inventory = inventory();
        let decoded = RealmRollbackCommitInventory::<PHash>::decode_canonical(
            inventory.canonical_bytes(),
        )
        .unwrap();
        assert_eq!(decoded, inventory);
        assert_eq!(decoded.narrow_intent().unwrap().mutations().len(), 8);
        assert_eq!(
            decoded.total_mutation_count(),
            decoded.narrow_intent().unwrap().mutations().len() as u64
                + decoded.typed_puts().len() as u64,
        );
        assert_ne!(decoded.slot().as_bytes(), &[0; 32]);
    }

    #[test]
    fn outer_digest_and_inner_put_frames_are_both_strict() {
        let inventory = inventory();
        let mut forged = inventory.canonical_bytes().to_vec();
        let typed_marker = forged
            .windows(4)
            .position(|window| window == b"PSTP")
            .expect("fixture has typed rows");
        forged[typed_marker + 6] = 9;
        let body_len = forged.len() - 32;
        let digest = inventory_digest(&forged[..body_len]);
        forged[body_len..].copy_from_slice(&digest);
        assert_eq!(
            RealmRollbackCommitInventory::<PHash>::decode_canonical(&forged),
            Err(RealmRollbackCommitInventoryError::InvalidTypedPut(
                TimestampedMutationError::InvalidEncoding("unknown write kind"),
            )),
        );
    }

    #[test]
    fn realm_sync_inventory_roundtrips_with_observed_row_timestamps() {
        let full = inventory();
        let observation = AuthorityObservation::try_new(
            *full.chain(),
            full.authority(),
            AuthorityStateCheckpointId::new(
                full.chain().checkpoint().checkpoint_id().get(),
            ),
            AuthorityStateRoot::from_local_state_root(PHash::from_values(5, 6, 7, 8)),
        )
        .unwrap();
        let first = super::super::timestamped::reseal_observed_authority_put(
            &full.typed_puts()[0],
            CommitWriteTimestampUs::try_from_i128(20_001).unwrap(),
        )
        .unwrap();
        let second = super::super::timestamped::reseal_observed_authority_put(
            &full.typed_puts()[1],
            CommitWriteTimestampUs::try_from_i128(20_002).unwrap(),
        )
        .unwrap();
        let sync = RealmRollbackCommitInventory::try_from_realm_sync(
            observation,
            CommitWriteTimestampUs::try_from_i128(20_003).unwrap(),
            vec![second, first],
        )
        .unwrap();
        let decoded = RealmRollbackCommitInventory::<PHash>::decode_canonical(
            sync.canonical_bytes(),
        )
        .unwrap();
        assert_eq!(decoded, sync);
        assert_eq!(decoded.sync_observation(), Some(&observation));
        assert!(decoded.full_candidate().is_none());
        assert!(decoded.narrow_intent().is_none());
        assert_ne!(decoded.typed_puts()[0].timestamp(), decoded.typed_puts()[1].timestamp());
    }

    #[test]
    fn model_is_not_commit_archive_or_delete_authority() {
        let source = include_str!("realm_rollback_commit_inventory.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in [
            "mark_committed",
            "archive_suffix",
            "delete_suffix",
            "restore_target",
            "enter_archive_barrier",
        ] {
            assert!(!production.contains(forbidden));
        }
        assert!(!production.contains("impl Clone for RealmRollbackCommitInventory"));
    }
}
