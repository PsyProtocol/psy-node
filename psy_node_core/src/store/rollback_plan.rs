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
use super::manifest_store::{
    AuthorityManifestStore, CoordinatorCommitRecording, ManifestArtifactKind,
    ManifestArtifactStore,
};

/// Why a range cannot be rolled back.
///
/// Every variant is a refusal to guess.  design-r1 §2.2: history with no source
/// or no marker returns `NOT_FEASIBLE` and must not fall back to scanning the
/// hot tables for an inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RollbackInfeasible {
    /// The target is at or above the head, so there is nothing to undo.
    EmptyRange { target: u64, head: u64 },
    /// A height in the range has no COMMITTED manifest under this chain epoch.
    ///
    /// Three causes, and the epoch one is easy to mistake for the others.
    /// Manifests are partitioned by `chain_epoch` because heights are reused: a
    /// checkpoint 25 in epoch 0 and a checkpoint 25 in epoch 1 are different
    /// commits and must not share a row.  A rollback bumps the epoch, so the
    /// manifests of everything committed before it are in another partition and
    /// a later rollback cannot reach below where this epoch's commits begin.
    /// The other two are the ordinary ones: the height predates the rollback
    /// floor, or its commit never finished.
    MissingManifest { checkpoint: u64, chain_epoch: u64 },
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
            Self::MissingManifest { checkpoint, chain_epoch } => write!(
                f,
                "checkpoint {checkpoint} has no committed manifest in chain epoch \
                 {chain_epoch}, so what it wrote is unknown and scanning the hot tables to \
                 guess is forbidden.  If this epoch began above that height, its predecessors \
                 were committed under an earlier epoch and live in a different partition: a \
                 rollback cannot reach below the point where the current epoch starts"
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
/// Which manifest state means "this commit finished".
///
/// The two authorities answer differently, and the difference is §6 rather than
/// a convention.  A Coordinator commit ends at COMMITTED, which asserts that the
/// head was published.  A Realm never publishes a head, so its manifest ends at
/// SEALED -- which already asserts what a Realm can claim: its writes landed and
/// they match what it recorded.  Demanding COMMITTED of a Realm would find none
/// and call every one of its commits unfinished.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestCompletionMarker {
    Committed,
    Sealed,
}

impl ManifestCompletionMarker {
    /// Whether every height in the discarded range must carry a commit.
    ///
    /// The Coordinator commits at every checkpoint, so a gap there means a
    /// commit is missing and its writes are unknown.  A Realm commits only when
    /// it has transactions of its own -- §6.3's sparse semantics -- so a height
    /// it skipped wrote nothing through its manifest, and demanding one would
    /// call every quiet stretch a corrupt range.  What a Realm does write at
    /// those heights comes from `sync`, and that is undone by re-fetching rather
    /// than from a manifest.
    const fn requires_every_height(self) -> bool {
        match self {
            Self::Committed => true,
            Self::Sealed => false,
        }
    }

    fn matches(self, status: AuthorityManifestStatus) -> bool {
        match self {
            Self::Committed => status == AuthorityManifestStatus::Committed,
            Self::Sealed => status == AuthorityManifestStatus::Sealed,
        }
    }
}

/// Read the manifests for `(target, head]` and enumerate what they wrote.
///
/// Takes the two stores rather than an authority's capability bundle, because
/// the read is the same on both sides: manifests are partitioned by
/// `authority_scope`, so the scope is what selects whose commits are being
/// planned.  Sharing the code means a Realm plan cannot drift from a
/// Coordinator plan in how it decodes an artifact.
pub async fn build_rollback_plan_for<Hash: Q256BitHash>(
    manifest: &dyn AuthorityManifestStore<Hash>,
    manifest_artifact: &dyn ManifestArtifactStore<Hash>,
    authority: psy_data::protocol::chain_context::AuthorityScope,
    marker: ManifestCompletionMarker,
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
        super::authority_commit::AuthorityTimestampKey::new(head.network_id(), authority),
        *head,
    )?;

    let rows = manifest
        .read_manifest_suffix(&identity, target, head_height)
        .await?;

    // Only COMMITTED rows describe a commit whose state writes finished.  A
    // PREPARED row with no COMMITTED sibling is a commit that died in flight;
    // its keys may or may not have landed, so the range is not plannable.
    let mut committed: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    let mut prepared: BTreeMap<u64, (Vec<u8>, Vec<u8>)> = BTreeMap::new();
    for row in rows {
        if marker.matches(row.status) {
            committed.insert(row.checkpoint_id, row.payload.clone());
        }
        if row.status == AuthorityManifestStatus::Prepared {
            prepared.insert(row.checkpoint_id, (row.payload, row.digest));
        }
    }

    let mut checkpoints = Vec::new();
    for height in (target + 1)..=head_height {
        if !committed.contains_key(&height) {
            if !marker.requires_every_height() {
                // This authority did not commit here, so its manifest names
                // nothing to undo at this height.
                continue;
            }
            anyhow::bail!(RollbackInfeasible::MissingManifest {
                checkpoint: height,
                chain_epoch: head.chain_epoch().get(),
            });
        }
        // The PREPARED row carries the intent and the artifact commitment; the
        // COMMITTED row only marks that the commit finished.
        let (payload, digest) = prepared
            .get(&height)
            .ok_or(RollbackInfeasible::MissingManifest {
                checkpoint: height,
                chain_epoch: head.chain_epoch().get(),
            })?;
        let intent = PreparedAuthorityManifestRecord::<Hash>::peek_intent(payload, digest)?;
        let chain = *intent.candidate_chain();
        let chunk_count = intent.artifacts().locator_chunk_count();

        let per_checkpoint_identity = AuthorityManifestIdentity::try_new(
            super::authority_commit::AuthorityTimestampKey::new(chain.network_id(), authority),
            chain,
        )?;
        let chunks = manifest_artifact
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

/// The Coordinator's plan: its manifests, and COMMITTED as the completion mark.
pub async fn build_rollback_plan<Hash: Q256BitHash>(
    recording: &CoordinatorCommitRecording<Hash>,
    head: &CanonicalChainRef<Hash>,
    target: u64,
    decode_locators: &dyn Fn(&[Vec<u8>]) -> anyhow::Result<Vec<(u16, Vec<u8>)>>,
) -> anyhow::Result<RollbackPlan<Hash>> {
    build_rollback_plan_for(
        recording.manifest(),
        recording.manifest_artifact(),
        psy_data::protocol::chain_context::AuthorityScope::Coordinator,
        ManifestCompletionMarker::Committed,
        head,
        target,
        decode_locators,
    )
    .await
}
