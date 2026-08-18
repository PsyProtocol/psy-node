//! What a rollback to `T` would have to undo.
//!
//! The plan is read entirely from manifests: for every checkpoint in
//! `(T, old_head]`, the keys that commit wrote.  Nothing here scans a hot table.
//! That is design-r1 §2.2's rule and not an optimisation -- a scan would find the
//! rows that happen to exist, while a rollback has to undo the rows that were
//! written, and those differ exactly where it matters.  A checkpoint whose
//! manifest or commit source is missing therefore makes the plan infeasible
//! rather than triggering a scan.

use std::collections::BTreeMap;

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::canonical_chain::CanonicalChainRef;

use super::manifest_record::{
    AuthorityManifestIdentity, AuthorityManifestStatus, PreparedAuthorityManifestRecord,
};
use super::manifest_store::{CoordinatorCommitRecording, ManifestArtifactKind};

/// Why a range cannot be rolled back.
///
/// Every variant is a refusal to guess.  design-r1 §2.2: history with no source
/// or no marker returns `NOT_FEASIBLE` and must not fall back to scanning the
/// hot tables for an inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RollbackInfeasible {
    /// The target is at or above the head, so there is nothing to undo.
    EmptyRange { target: u64, head: u64 },
    /// A height in the range has no COMMITTED manifest.  Either it predates the
    /// rollback floor or its commit never finished.
    MissingManifest { checkpoint: u64 },
    /// The range has a hole: rolling back to `T` requires undoing every height
    /// above it, and a gap means some height's writes are unknown.
    MissingCheckpoint { checkpoint: u64 },
    /// The manifest is there but its artifact chunks are not, so the keys it
    /// wrote cannot be enumerated.
    MissingArtifact { checkpoint: u64, expected: u32, found: usize },
}

impl std::fmt::Display for RollbackInfeasible {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyRange { target, head } => write!(
                f,
                "rollback target {target} is not below the head {head}, so there is nothing \
                 to undo"
            ),
            Self::MissingManifest { checkpoint } => write!(
                f,
                "checkpoint {checkpoint} has no committed manifest, so what it wrote is \
                 unknown; scanning the hot tables to guess is forbidden"
            ),
            Self::MissingCheckpoint { checkpoint } => write!(
                f,
                "checkpoint {checkpoint} is missing from the discarded range, which must be \
                 contiguous"
            ),
            Self::MissingArtifact { checkpoint, expected, found } => write!(
                f,
                "checkpoint {checkpoint} committed to {expected} locator chunks but {found} \
                 are readable"
            ),
        }
    }
}

impl std::error::Error for RollbackInfeasible {}

/// One checkpoint's contribution to the discarded suffix.
pub struct PlannedCheckpoint<Hash: Q256BitHash> {
    pub chain: CanonicalChainRef<Hash>,
    /// Every physical row this checkpoint wrote, as `(physical_table, locator)`.
    pub rows: Vec<(u16, Vec<u8>)>,
}

impl<Hash: Q256BitHash> PlannedCheckpoint<Hash> {
    pub fn checkpoint_id(&self) -> u64 {
        self.chain.checkpoint().checkpoint_id().get()
    }
}

/// The full set of writes a rollback to `target` must undo.
pub struct RollbackPlan<Hash: Q256BitHash> {
    pub target: u64,
    pub head: u64,
    /// Ascending by checkpoint.  Archive walks it forwards; delete walks it
    /// backwards, so the newest version of a key goes first and no read ever
    /// sees a height whose successor still exists.
    pub checkpoints: Vec<PlannedCheckpoint<Hash>>,
}

impl<Hash: Q256BitHash> RollbackPlan<Hash> {
    pub fn row_count(&self) -> usize {
        self.checkpoints.iter().map(|c| c.rows.len()).sum()
    }

    /// Every distinct key the range touched, and the lowest checkpoint that
    /// touched it.
    ///
    /// That checkpoint is `c(K)` in the journal assertion: the first write to `K`
    /// above the target, so the state just before it is the state a rollback has
    /// to restore.
    pub fn first_touch_by_key(&self) -> BTreeMap<Vec<u8>, u64> {
        let mut first: BTreeMap<Vec<u8>, u64> = BTreeMap::new();
        for checkpoint in &self.checkpoints {
            let height = checkpoint.checkpoint_id();
            for (_, locator) in &checkpoint.rows {
                first.entry(locator.clone()).or_insert(height);
            }
        }
        first
    }
}

/// Read the manifests for `(target, head]` and enumerate what they wrote.
pub async fn build_rollback_plan<Hash: Q256BitHash>(
    recording: &CoordinatorCommitRecording<Hash>,
    head: &CanonicalChainRef<Hash>,
    target: u64,
    decode_locators: &dyn Fn(&[Vec<u8>]) -> anyhow::Result<Vec<(u16, Vec<u8>)>>,
) -> anyhow::Result<RollbackPlan<Hash>> {
    let head_height = head.checkpoint().checkpoint_id().get();
    if target >= head_height {
        anyhow::bail!(RollbackInfeasible::EmptyRange {
            target,
            head: head_height
        });
    }
    let identity = AuthorityManifestIdentity::try_new(
        super::authority_commit::AuthorityTimestampKey::new(
            head.network_id(),
            psy_data::protocol::chain_context::AuthorityScope::Coordinator,
        ),
        *head,
    )?;

    let rows = recording
        .manifest()
        .read_manifest_suffix(&identity, target, head_height)
        .await?;

    // Only COMMITTED rows describe a commit whose state writes finished.  A
    // PREPARED row with no COMMITTED sibling is a commit that died in flight;
    // its keys may or may not have landed, so the range is not plannable.
    let mut committed: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    let mut digests: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    let mut prepared: BTreeMap<u64, (Vec<u8>, Vec<u8>)> = BTreeMap::new();
    for row in rows {
        match row.status {
            AuthorityManifestStatus::Committed => {
                committed.insert(row.checkpoint_id, row.payload);
                digests.insert(row.checkpoint_id, row.digest);
            }
            AuthorityManifestStatus::Prepared => {
                prepared.insert(row.checkpoint_id, (row.payload, row.digest));
            }
            _ => {}
        }
    }

    let mut checkpoints = Vec::new();
    for height in (target + 1)..=head_height {
        if !committed.contains_key(&height) {
            anyhow::bail!(RollbackInfeasible::MissingManifest { checkpoint: height });
        }
        // The PREPARED row carries the intent and the artifact commitment; the
        // COMMITTED row only marks that the commit finished.
        let (payload, digest) = prepared
            .get(&height)
            .ok_or(RollbackInfeasible::MissingManifest { checkpoint: height })?;
        let intent = PreparedAuthorityManifestRecord::<Hash>::peek_intent(payload, digest)?;
        let chain = *intent.candidate_chain();
        let chunk_count = intent.artifacts().locator_chunk_count();

        let per_checkpoint_identity = AuthorityManifestIdentity::try_new(
            super::authority_commit::AuthorityTimestampKey::new(
                chain.network_id(),
                psy_data::protocol::chain_context::AuthorityScope::Coordinator,
            ),
            chain,
        )?;
        let chunks = recording
            .manifest_artifact()
            .read_artifact_chunks(
                &per_checkpoint_identity,
                ManifestArtifactKind::Locator,
                chunk_count,
            )
            .await?;
        if chunks.len() as u32 != chunk_count {
            anyhow::bail!(RollbackInfeasible::MissingArtifact {
                checkpoint: height,
                expected: chunk_count,
                found: chunks.len(),
            });
        }
        checkpoints.push(PlannedCheckpoint {
            chain,
            rows: decode_locators(&chunks)?,
        });
    }

    Ok(RollbackPlan {
        target,
        head: head_height,
        checkpoints,
    })
}
