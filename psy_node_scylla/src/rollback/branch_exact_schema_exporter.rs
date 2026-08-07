//! Deterministic exporter from the frozen epoch-zero legacy schema into the
//! h17 branch-exact canonical artifact.
//!
//! This is deployment tooling, not an online snapshot algorithm.  Scylla does
//! not provide a cross-partition snapshot for the legacy tables, so callers
//! must first stop and drain every authority Processor.  The typed permit
//! records that operational assertion; this adapter then adds two complete
//! source scans and exact durable-head observations.  Neither check is a
//! substitute for the stop/drain boundary.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    sync::Arc,
};

use async_trait::async_trait;
use parth_core::{
    crypto::hash::{
        tag_tree::TagTreeMerkleProof,
        traits::{FieldQHasher, QFieldHashable},
    },
    felt::QFelt64,
    protocol::core_types::{
        Q256BitHash, QFHashBase, QZKProofPublicInputsHasherReader,
    },
};
use psy_data::protocol::{
    canonical_chain::{
        checkpoint_hash_from_saved_proof_bytes, genesis_checkpoint_hash,
        CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
        CheckpointRef,
    },
    verifiable_checkpoint_transition::PsyVerifiableCheckpointTransitionWithProof,
};
use psy_node_core::store::{
    branch_exact_schema::AuthorityScope,
    branch_pending_mapping::BranchPendingMapping,
    canonical_head::{
        CanonicalHeadBootstrapProfile, CanonicalHeadReadState,
        CoordinatorCanonicalHeadReader, StoredCanonicalHead,
    },
    typed::UniquePendingId,
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
use scylla::{
    client::session::Session,
    statement::{prepared::PreparedStatement, Consistency},
};
use sha2::{Digest, Sha256};

use crate::utils::{i64_to_u64_exact, u64_to_i64_exact};

use super::{
    BranchExactBackfillArtifact, BranchExactBackfillArtifactRow,
    BranchExactBackfillDatasetDigest,
    BranchExactSchemaMaterializationRequest, CqlKeyspaceName,
};

const LEGACY_FORWARD_TABLE: &str = "checkpoint_id_to_pending_id_table";
const LEGACY_REVERSE_TABLE: &str = "pending_id_to_checkpoint_id_table";
const LEGACY_CHECKPOINT_TRANSITION_TABLE: &str =
    "checkpoint_zk_proof_and_transition_table";
const LEGACY_CHECKPOINTED_OBJECT_TABLE: &str = "checkpointed_object_table";
const REALM_REWARD_PROOF_OBJ_ID: u64 = 2;
const SOURCE_CHUNK_ROWS: usize = 256;

const PERMIT_DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/branch-exact-legacy-export-permit/v1";
const CATALOG_DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/branch-exact-canonical-catalog/v1";
const SOURCE_DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/branch-exact-legacy-source/v1";
const SOURCE_CHUNK_DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/branch-exact-source-chunk/v1";

/// The only legacy profile that can recover epoch from the current schema.
///
/// Once an authority has entered epoch > 0, a height-only row no longer says
/// which historical occurrence it belongs to.  Such data needs a VERIFIED
/// baseline snapshot/catalog adapter, which is deliberately not fabricated by
/// this module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BranchExactLegacyExportProfile {
    OfflineStoppedPostGenesisEpochZero,
}

/// Explicit operator assertion required before opening the legacy scanner.
///
/// This is intentionally verbose.  It prevents a future caller from treating
/// an unchanged head read as proof that the Processor was quiescent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BranchExactLegacyFreezeReason {
    AllAuthorityProcessorsStoppedAndDrained,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BranchExactLegacyExportPermitDigest([u8; 32]);

impl BranchExactLegacyExportPermitDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Sealed source identity for one offline export.
///
/// The materialization request contributes the authority, target keyspace,
/// profile and baseline evidence digest; `source_head` contributes the exact
/// revision and 65-byte canonical identity.  No public constructor accepts a
/// bare height or epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactFrozenLegacyExportPermit<Hash> {
    request: BranchExactSchemaMaterializationRequest,
    source_head: StoredCanonicalHead<Hash>,
    profile: BranchExactLegacyExportProfile,
    freeze_reason: BranchExactLegacyFreezeReason,
    digest: BranchExactLegacyExportPermitDigest,
}

impl<Hash: Q256BitHash> BranchExactFrozenLegacyExportPermit<Hash> {
    pub fn try_new(
        request: BranchExactSchemaMaterializationRequest,
        source_head: StoredCanonicalHead<Hash>,
        freeze_reason: BranchExactLegacyFreezeReason,
    ) -> Result<Self, BranchExactLegacyExportError> {
        if request.plan().profile()
            != CanonicalHeadBootstrapProfile::PostGenesisFloor
        {
            return Err(BranchExactLegacyExportError::UnsupportedSourceProfile);
        }
        if request.plan().floor_evidence().is_none() {
            return Err(BranchExactLegacyExportError::MissingBaselineEvidence);
        }
        if source_head.canonical_ref().chain_epoch().get() != 0 {
            return Err(BranchExactLegacyExportError::LegacyEpochAmbiguous(
                source_head.canonical_ref().chain_epoch().get(),
            ));
        }
        if !source_head.rollback_control().is_idle() {
            return Err(BranchExactLegacyExportError::RollbackControlNotIdle);
        }
        if request.plan().anchor_payload()
            != &source_head.canonical_ref_bytes()
        {
            return Err(BranchExactLegacyExportError::SourceHeadAnchorMismatch);
        }
        let profile =
            BranchExactLegacyExportProfile::OfflineStoppedPostGenesisEpochZero;
        let digest = permit_digest(
            &request,
            &source_head,
            profile,
            freeze_reason,
        );
        Ok(Self {
            request,
            source_head,
            profile,
            freeze_reason,
            digest,
        })
    }

    pub const fn request(&self) -> &BranchExactSchemaMaterializationRequest {
        &self.request
    }

    pub const fn source_head(&self) -> &StoredCanonicalHead<Hash> {
        &self.source_head
    }

    pub const fn profile(&self) -> BranchExactLegacyExportProfile {
        self.profile
    }

    pub const fn freeze_reason(&self) -> BranchExactLegacyFreezeReason {
        self.freeze_reason
    }

    pub const fn digest(&self) -> BranchExactLegacyExportPermitDigest {
        self.digest
    }
}

fn permit_digest<Hash: Q256BitHash>(
    request: &BranchExactSchemaMaterializationRequest,
    source_head: &StoredCanonicalHead<Hash>,
    profile: BranchExactLegacyExportProfile,
    reason: BranchExactLegacyFreezeReason,
) -> BranchExactLegacyExportPermitDigest {
    let mut hasher = Sha256::new();
    hasher.update(PERMIT_DIGEST_DOMAIN);
    hasher.update(request.plan().digest().as_bytes());
    hasher.update((request.keyspace().as_str().len() as u32).to_be_bytes());
    hasher.update(request.keyspace().as_str().as_bytes());
    hasher.update(source_head.revision().get().to_be_bytes());
    hasher.update(source_head.canonical_ref_bytes());
    hasher.update(source_head.rollback_control_bytes());
    hasher.update([match profile {
        BranchExactLegacyExportProfile::OfflineStoppedPostGenesisEpochZero => 1,
    }]);
    hasher.update([match reason {
        BranchExactLegacyFreezeReason::AllAuthorityProcessorsStoppedAndDrained => 1,
    }]);
    BranchExactLegacyExportPermitDigest(hasher.finalize().into())
}

/// Exact fingerprints needed to recompute the chain-mode checkpoint hash.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BranchExactCheckpointChainConfig<Hash> {
    genesis_checkpoint_state_transition_fingerprint: Hash,
    genesis_checkpoint_state_transition_hash: Hash,
    checkpoint_state_transition_circuit_fingerprint: Hash,
}

impl<Hash> BranchExactCheckpointChainConfig<Hash> {
    pub const fn new(
        genesis_checkpoint_state_transition_fingerprint: Hash,
        genesis_checkpoint_state_transition_hash: Hash,
        checkpoint_state_transition_circuit_fingerprint: Hash,
    ) -> Self {
        Self {
            genesis_checkpoint_state_transition_fingerprint,
            genesis_checkpoint_state_transition_hash,
            checkpoint_state_transition_circuit_fingerprint,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BranchExactCanonicalCatalogDigest([u8; 32]);

impl BranchExactCanonicalCatalogDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Full epoch-zero canonical index produced from the Coordinator's stored
/// checkpoint transition/proof KIV rows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactCanonicalCatalog<Hash> {
    source_head: StoredCanonicalHead<Hash>,
    by_checkpoint: BTreeMap<u64, CanonicalChainRef<Hash>>,
    digest: BranchExactCanonicalCatalogDigest,
}

impl<Hash> BranchExactCanonicalCatalog<Hash> {
    pub const fn source_head(&self) -> &StoredCanonicalHead<Hash> {
        &self.source_head
    }

    pub fn get(&self, checkpoint_id: u64) -> Option<&CanonicalChainRef<Hash>> {
        self.by_checkpoint.get(&checkpoint_id)
    }

    pub fn rows(&self) -> impl Iterator<Item = (&u64, &CanonicalChainRef<Hash>)> {
        self.by_checkpoint.iter()
    }

    pub const fn digest(&self) -> BranchExactCanonicalCatalogDigest {
        self.digest
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BranchExactLegacySourceDigest([u8; 32]);

impl BranchExactLegacySourceDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BranchExactSourceChunkDigest([u8; 32]);

impl BranchExactSourceChunkDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Source-bound evidence returned with the existing h17 artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactLegacyExportReceipt {
    permit_digest: BranchExactLegacyExportPermitDigest,
    catalog_digest: BranchExactCanonicalCatalogDigest,
    source_digest: BranchExactLegacySourceDigest,
    dataset_digest: BranchExactBackfillDatasetDigest,
    source_chunk_digests: Vec<BranchExactSourceChunkDigest>,
    pair_rows: u64,
    proof_rows: u64,
}

impl BranchExactLegacyExportReceipt {
    pub const fn permit_digest(&self) -> BranchExactLegacyExportPermitDigest {
        self.permit_digest
    }

    pub const fn catalog_digest(&self) -> BranchExactCanonicalCatalogDigest {
        self.catalog_digest
    }

    pub const fn source_digest(&self) -> BranchExactLegacySourceDigest {
        self.source_digest
    }

    pub const fn dataset_digest(&self) -> BranchExactBackfillDatasetDigest {
        self.dataset_digest
    }

    pub fn source_chunk_digests(&self) -> &[BranchExactSourceChunkDigest] {
        &self.source_chunk_digests
    }

    pub const fn pair_rows(&self) -> u64 {
        self.pair_rows
    }

    pub const fn proof_rows(&self) -> u64 {
        self.proof_rows
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactLegacyExport<Hash> {
    artifact: BranchExactBackfillArtifact<Hash>,
    receipt: BranchExactLegacyExportReceipt,
}

impl<Hash> BranchExactLegacyExport<Hash> {
    pub const fn artifact(&self) -> &BranchExactBackfillArtifact<Hash> {
        &self.artifact
    }

    pub const fn receipt(&self) -> &BranchExactLegacyExportReceipt {
        &self.receipt
    }

    pub fn into_artifact(self) -> BranchExactBackfillArtifact<Hash> {
        self.artifact
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LegacyU64PairRow {
    key: u64,
    value: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LegacyBlobRow {
    key: u64,
    value: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LegacySourceSnapshot {
    forward: Vec<LegacyU64PairRow>,
    reverse: Vec<LegacyU64PairRow>,
    reward_proofs: Vec<LegacyBlobRow>,
    digest: BranchExactLegacySourceDigest,
}

impl LegacySourceSnapshot {
    fn try_new(
        authority: AuthorityScope,
        mut forward: Vec<LegacyU64PairRow>,
        mut reverse: Vec<LegacyU64PairRow>,
        mut reward_proofs: Vec<LegacyBlobRow>,
    ) -> Result<Self, BranchExactLegacyExportError> {
        forward.sort_unstable_by_key(|row| (row.key, row.value));
        reverse.sort_unstable_by_key(|row| (row.key, row.value));
        reward_proofs.sort_unstable_by(|left, right| {
            left.key
                .cmp(&right.key)
                .then_with(|| left.value.cmp(&right.value))
        });
        reject_duplicate_keys(&forward, LegacyDirection::Forward)?;
        reject_duplicate_keys(&reverse, LegacyDirection::Reverse)?;
        reject_duplicate_blob_keys(&reward_proofs)?;
        match authority {
            AuthorityScope::Coordinator if !reward_proofs.is_empty() => {
                return Err(
                    BranchExactLegacyExportError::UnexpectedCoordinatorProof,
                )
            }
            AuthorityScope::Coordinator | AuthorityScope::Realm { .. } => {}
        }
        let digest = source_digest(
            authority,
            &forward,
            &reverse,
            &reward_proofs,
        );
        Ok(Self {
            forward,
            reverse,
            reward_proofs,
            digest,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LegacyDirection {
    Forward,
    Reverse,
}

fn reject_duplicate_keys(
    rows: &[LegacyU64PairRow],
    direction: LegacyDirection,
) -> Result<(), BranchExactLegacyExportError> {
    if let Some(pair) = rows.windows(2).find(|pair| pair[0].key == pair[1].key)
    {
        return Err(match direction {
            LegacyDirection::Forward => {
                BranchExactLegacyExportError::DuplicateForwardCheckpoint(
                    pair[0].key,
                )
            }
            LegacyDirection::Reverse => {
                BranchExactLegacyExportError::DuplicateReversePending(
                    pair[0].key,
                )
            }
        });
    }
    Ok(())
}

fn reject_duplicate_blob_keys(
    rows: &[LegacyBlobRow],
) -> Result<(), BranchExactLegacyExportError> {
    if let Some(pair) = rows.windows(2).find(|pair| pair[0].key == pair[1].key)
    {
        return Err(BranchExactLegacyExportError::DuplicateRealmProof(
            pair[0].key,
        ));
    }
    Ok(())
}

fn source_digest(
    authority: AuthorityScope,
    forward: &[LegacyU64PairRow],
    reverse: &[LegacyU64PairRow],
    proofs: &[LegacyBlobRow],
) -> BranchExactLegacySourceDigest {
    let mut hasher = Sha256::new();
    hasher.update(SOURCE_DIGEST_DOMAIN);
    update_authority(&mut hasher, authority);
    hasher.update((forward.len() as u64).to_be_bytes());
    for row in forward {
        hasher.update(row.key.to_be_bytes());
        hasher.update(row.value.to_be_bytes());
    }
    hasher.update((reverse.len() as u64).to_be_bytes());
    for row in reverse {
        hasher.update(row.key.to_be_bytes());
        hasher.update(row.value.to_be_bytes());
    }
    hasher.update((proofs.len() as u64).to_be_bytes());
    for row in proofs {
        hasher.update(row.key.to_be_bytes());
        hasher.update((row.value.len() as u64).to_be_bytes());
        hasher.update(&row.value);
    }
    BranchExactLegacySourceDigest(hasher.finalize().into())
}

fn update_authority(hasher: &mut Sha256, authority: AuthorityScope) {
    match authority {
        AuthorityScope::Coordinator => hasher.update([1, 0, 0, 0, 0, 0, 0]),
        AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } => {
            hasher.update([2]);
            hasher.update(realm_id.to_be_bytes());
            hasher.update(realm_sub_id.to_be_bytes());
        }
    }
}

struct LegacyPreparedQueries {
    forward: PreparedStatement,
    reverse: PreparedStatement,
    checkpoint_transitions: PreparedStatement,
    reward_proofs: Option<PreparedStatement>,
}

/// Confined, fixed-query legacy source reader.
///
/// It is absent from `psy_setup.rs` and Processor composition.  Raw sessions
/// are retained privately and no method accepts a table name or CQL string.
pub struct ScyllaBranchExactLegacyExporter<Hash> {
    authority_session: Arc<Session>,
    canonical_session: Arc<Session>,
    authority: AuthorityScope,
    target_keyspace: CqlKeyspaceName,
    canonical_source_keyspace: CqlKeyspaceName,
    consistency: Consistency,
    queries: LegacyPreparedQueries,
    head_reader: Arc<dyn CoordinatorCanonicalHeadReader<Hash>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BranchExactLegacyExportBoundary {
    HeadBeforeScan,
    FirstCatalogComplete,
    FirstLegacySourceComplete,
    SecondCatalogComplete,
    SecondLegacySourceComplete,
    HeadAfterScan,
}

#[async_trait]
pub trait BranchExactLegacyExportObserver: Send + Sync {
    async fn observe(
        &self,
        boundary: BranchExactLegacyExportBoundary,
    ) -> anyhow::Result<()>;
}

struct NoopLegacyExportObserver;

#[async_trait]
impl BranchExactLegacyExportObserver for NoopLegacyExportObserver {
    async fn observe(
        &self,
        _boundary: BranchExactLegacyExportBoundary,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

impl<Hash: Q256BitHash> ScyllaBranchExactLegacyExporter<Hash> {
    /// Deployment-tooling composition hook.  Sessions remain confined after
    /// construction; all table names are fixed constants.
    pub async fn prepare(
        authority_session: Arc<Session>,
        canonical_session: Arc<Session>,
        authority: AuthorityScope,
        target_keyspace: CqlKeyspaceName,
        canonical_source_keyspace: CqlKeyspaceName,
        head_reader: Arc<dyn CoordinatorCanonicalHeadReader<Hash>>,
    ) -> Result<Self, BranchExactLegacyExportError> {
        let consistency = Consistency::Quorum;
        let mut forward = authority_session
            .prepare(format!(
                "SELECT obj_id, value FROM {}.{LEGACY_FORWARD_TABLE}",
                target_keyspace.as_str()
            ))
            .await
            .map_err(driver)?;
        forward.set_consistency(consistency);
        let mut reverse = authority_session
            .prepare(format!(
                "SELECT obj_id, value FROM {}.{LEGACY_REVERSE_TABLE}",
                target_keyspace.as_str()
            ))
            .await
            .map_err(driver)?;
        reverse.set_consistency(consistency);
        let mut checkpoint_transitions = canonical_session
            .prepare(format!(
                "SELECT obj_id, value FROM {}.{LEGACY_CHECKPOINT_TRANSITION_TABLE}",
                canonical_source_keyspace.as_str()
            ))
            .await
            .map_err(driver)?;
        checkpoint_transitions.set_consistency(consistency);
        let reward_proofs = match authority {
            AuthorityScope::Coordinator => None,
            AuthorityScope::Realm { .. } => {
                let mut prepared = authority_session
                    .prepare(format!(
                        "SELECT checkpoint_id, value FROM {}.{LEGACY_CHECKPOINTED_OBJECT_TABLE} WHERE obj_id = ?",
                        target_keyspace.as_str()
                    ))
                    .await
                    .map_err(driver)?;
                prepared.set_consistency(consistency);
                Some(prepared)
            }
        };
        Ok(Self {
            authority_session,
            canonical_session,
            authority,
            target_keyspace,
            canonical_source_keyspace,
            consistency,
            queries: LegacyPreparedQueries {
                forward,
                reverse,
                checkpoint_transitions,
                reward_proofs,
            },
            head_reader,
        })
    }

    pub const fn authority(&self) -> AuthorityScope {
        self.authority
    }

    pub const fn consistency(&self) -> Consistency {
        self.consistency
    }

    pub fn target_keyspace(&self) -> &CqlKeyspaceName {
        &self.target_keyspace
    }

    pub fn canonical_source_keyspace(&self) -> &CqlKeyspaceName {
        &self.canonical_source_keyspace
    }

    /// Perform two complete scans around exact durable-head observations and
    /// export only if every byte is stable.
    pub async fn export<F, Hasher, Proof, Verifier>(
        &self,
        permit: &BranchExactFrozenLegacyExportPermit<Hash>,
        chain_config: BranchExactCheckpointChainConfig<Hash>,
    ) -> Result<BranchExactLegacyExport<Hash>, BranchExactLegacyExportError>
    where
        F: QFelt64,
        Hash: QFHashBase<F>,
        Hasher: FieldQHasher<F, Hash>,
        Verifier: QZKProofPublicInputsHasherReader<Hash, Proof>,
        PsyVerifiableCheckpointTransitionWithProof<F, Hash>:
            PsyCanonicalDatabaseSerializeBaseSingle,
    {
        self.export_observed::<F, Hasher, Proof, Verifier>(
            permit,
            chain_config,
            &NoopLegacyExportObserver,
        )
        .await
    }

    /// Same immutable export path with observable boundaries for crash and
    /// source-mutation qualification.  The observer cannot replace any row,
    /// digest, permit, chain config or returned artifact.
    pub async fn export_observed<F, Hasher, Proof, Verifier>(
        &self,
        permit: &BranchExactFrozenLegacyExportPermit<Hash>,
        chain_config: BranchExactCheckpointChainConfig<Hash>,
        observer: &dyn BranchExactLegacyExportObserver,
    ) -> Result<BranchExactLegacyExport<Hash>, BranchExactLegacyExportError>
    where
        F: QFelt64,
        Hash: QFHashBase<F>,
        Hasher: FieldQHasher<F, Hash>,
        Verifier: QZKProofPublicInputsHasherReader<Hash, Proof>,
        PsyVerifiableCheckpointTransitionWithProof<F, Hash>:
            PsyCanonicalDatabaseSerializeBaseSingle,
    {
        self.require_permit(permit)?;
        observe(observer, BranchExactLegacyExportBoundary::HeadBeforeScan).await?;
        self.require_exact_head(permit).await?;

        let transitions_a = self.scan_checkpoint_transitions().await?;
        let catalog_a = build_catalog::<F, Hash, Hasher, Proof, Verifier>(
            permit.source_head,
            chain_config,
            transitions_a,
        )?;
        observe(
            observer,
            BranchExactLegacyExportBoundary::FirstCatalogComplete,
        )
        .await?;
        let source_a = self.scan_legacy_source().await?;
        observe(
            observer,
            BranchExactLegacyExportBoundary::FirstLegacySourceComplete,
        )
        .await?;

        let transitions_b = self.scan_checkpoint_transitions().await?;
        let catalog_b = build_catalog::<F, Hash, Hasher, Proof, Verifier>(
            permit.source_head,
            chain_config,
            transitions_b,
        )?;
        observe(
            observer,
            BranchExactLegacyExportBoundary::SecondCatalogComplete,
        )
        .await?;
        let source_b = self.scan_legacy_source().await?;
        observe(
            observer,
            BranchExactLegacyExportBoundary::SecondLegacySourceComplete,
        )
        .await?;
        observe(observer, BranchExactLegacyExportBoundary::HeadAfterScan).await?;
        self.require_exact_head(permit).await?;

        if catalog_a != catalog_b {
            return Err(BranchExactLegacyExportError::CanonicalSourceChanged);
        }
        if source_a != source_b {
            return Err(BranchExactLegacyExportError::LegacySourceChanged);
        }

        export_snapshot(permit, &catalog_a, source_a)
    }

    fn require_permit(
        &self,
        permit: &BranchExactFrozenLegacyExportPermit<Hash>,
    ) -> Result<(), BranchExactLegacyExportError> {
        if permit.request.plan().authority() != self.authority {
            return Err(BranchExactLegacyExportError::AuthorityMismatch);
        }
        if permit.request.keyspace() != &self.target_keyspace {
            return Err(BranchExactLegacyExportError::TargetKeyspaceMismatch);
        }
        Ok(())
    }

    async fn require_exact_head(
        &self,
        permit: &BranchExactFrozenLegacyExportPermit<Hash>,
    ) -> Result<(), BranchExactLegacyExportError> {
        let observed = self
            .head_reader
            .read_canonical_head(
                permit.source_head.canonical_ref().network_id(),
            )
            .await
            .map_err(|error| {
                BranchExactLegacyExportError::HeadRead(error.to_string())
            })?;
        match observed {
            CanonicalHeadReadState::Uninitialized => {
                Err(BranchExactLegacyExportError::HeadUninitialized)
            }
            CanonicalHeadReadState::Current(current)
                if current == permit.source_head =>
            {
                Ok(())
            }
            CanonicalHeadReadState::Current(_) => {
                Err(BranchExactLegacyExportError::SourceHeadChanged)
            }
        }
    }

    async fn scan_checkpoint_transitions(
        &self,
    ) -> Result<Vec<LegacyBlobRow>, BranchExactLegacyExportError> {
        let mut rows = self
            .canonical_session
            .execute_iter(self.queries.checkpoint_transitions.clone(), ())
            .await
            .map_err(driver)?
            .rows_stream::<(i64, Vec<u8>)>()
            .map_err(driver)?;
        let mut output = Vec::new();
        use futures::TryStreamExt;
        while let Some((key, value)) = rows.try_next().await.map_err(driver)? {
            output.push(LegacyBlobRow {
                key: i64_to_u64_exact(key),
                value: crate::compression::decompress(&value)
                    .map_err(|error| {
                        BranchExactLegacyExportError::MalformedCheckpointTransition {
                            checkpoint_id: i64_to_u64_exact(key),
                            reason: error.to_string(),
                        }
                    })?,
            });
        }
        output.sort_unstable_by(|left, right| {
            left.key
                .cmp(&right.key)
                .then_with(|| left.value.cmp(&right.value))
        });
        if let Some(pair) =
            output.windows(2).find(|pair| pair[0].key == pair[1].key)
        {
            return Err(BranchExactLegacyExportError::DuplicateCheckpointTransition(
                pair[0].key,
            ));
        }
        Ok(output)
    }

    async fn scan_legacy_source(
        &self,
    ) -> Result<LegacySourceSnapshot, BranchExactLegacyExportError> {
        let forward = scan_u64_pairs(
            &self.authority_session,
            &self.queries.forward,
        )
        .await?;
        let reverse = scan_u64_pairs(
            &self.authority_session,
            &self.queries.reverse,
        )
        .await?;
        let reward_proofs = match &self.queries.reward_proofs {
            None => Vec::new(),
            Some(query) => {
                scan_blob_partition(
                    &self.authority_session,
                    query,
                    REALM_REWARD_PROOF_OBJ_ID,
                )
                .await?
            }
        };
        LegacySourceSnapshot::try_new(
            self.authority,
            forward,
            reverse,
            reward_proofs,
        )
    }
}

async fn observe(
    observer: &dyn BranchExactLegacyExportObserver,
    boundary: BranchExactLegacyExportBoundary,
) -> Result<(), BranchExactLegacyExportError> {
    observer
        .observe(boundary)
        .await
        .map_err(|error| BranchExactLegacyExportError::Observer(error.to_string()))
}

async fn scan_u64_pairs(
    session: &Session,
    query: &PreparedStatement,
) -> Result<Vec<LegacyU64PairRow>, BranchExactLegacyExportError> {
    use futures::TryStreamExt;
    let mut rows = session
        .execute_iter(query.clone(), ())
        .await
        .map_err(driver)?
        .rows_stream::<(i64, i64)>()
        .map_err(driver)?;
    let mut output = Vec::new();
    while let Some((key, value)) = rows.try_next().await.map_err(driver)? {
        output.push(LegacyU64PairRow {
            key: i64_to_u64_exact(key),
            value: i64_to_u64_exact(value),
        });
    }
    Ok(output)
}

async fn scan_blob_partition(
    session: &Session,
    query: &PreparedStatement,
    obj_id: u64,
) -> Result<Vec<LegacyBlobRow>, BranchExactLegacyExportError> {
    use futures::TryStreamExt;
    let mut rows = session
        .execute_iter(query.clone(), (u64_to_i64_exact(obj_id),))
        .await
        .map_err(driver)?
        .rows_stream::<(i64, Vec<u8>)>()
        .map_err(driver)?;
    let mut output = Vec::new();
    while let Some((key, value)) = rows.try_next().await.map_err(driver)? {
        output.push(LegacyBlobRow {
            key: i64_to_u64_exact(key),
            value: crate::compression::decompress(&value).map_err(|error| {
                BranchExactLegacyExportError::MalformedRealmProof {
                    pending_id: i64_to_u64_exact(key),
                    reason: error.to_string(),
                }
            })?,
        });
    }
    Ok(output)
}

fn driver(error: impl ToString) -> BranchExactLegacyExportError {
    BranchExactLegacyExportError::Driver(error.to_string())
}

fn build_catalog<F, Hash, Hasher, Proof, Verifier>(
    source_head: StoredCanonicalHead<Hash>,
    config: BranchExactCheckpointChainConfig<Hash>,
    rows: Vec<LegacyBlobRow>,
) -> Result<BranchExactCanonicalCatalog<Hash>, BranchExactLegacyExportError>
where
    F: QFelt64,
    Hash: QFHashBase<F> + Q256BitHash,
    Hasher: FieldQHasher<F, Hash>,
    Verifier: QZKProofPublicInputsHasherReader<Hash, Proof>,
    PsyVerifiableCheckpointTransitionWithProof<F, Hash>:
        PsyCanonicalDatabaseSerializeBaseSingle,
{
    if source_head.canonical_ref().chain_epoch() != ChainEpoch::new(0) {
        return Err(BranchExactLegacyExportError::LegacyEpochAmbiguous(
            source_head.canonical_ref().chain_epoch().get(),
        ));
    }
    let head_id = source_head
        .canonical_ref()
        .checkpoint()
        .checkpoint_id()
        .get();
    let expected_len = head_id
        .checked_add(1)
        .ok_or(BranchExactLegacyExportError::CheckpointRangeOverflow)?;
    if rows.len() as u64 != expected_len {
        return Err(BranchExactLegacyExportError::CheckpointTransitionCount {
            expected: expected_len,
            actual: rows.len() as u64,
        });
    }

    let mut by_checkpoint = BTreeMap::new();
    let mut previous_hash = None;
    let mut previous_root_leaf = None;
    for (expected_checkpoint, row) in (0_u64..=head_id).zip(rows) {
        if row.key != expected_checkpoint {
            return Err(BranchExactLegacyExportError::CheckpointTransitionGap {
                expected: expected_checkpoint,
                actual: row.key,
            });
        }
        let transition = PsyVerifiableCheckpointTransitionWithProof::<F, Hash>::
            psy_ser_from_owned_bytes_vec(row.value.clone())
            .map_err(|error| {
                BranchExactLegacyExportError::MalformedCheckpointTransition {
                    checkpoint_id: row.key,
                    reason: error.to_string(),
                }
            })?;
        let canonical = transition
            .psy_ser_to_bytes_vec()
            .map_err(|error| {
                BranchExactLegacyExportError::MalformedCheckpointTransition {
                    checkpoint_id: row.key,
                    reason: error.to_string(),
                }
            })?;
        if canonical != row.value {
            return Err(
                BranchExactLegacyExportError::NonCanonicalCheckpointTransition(
                    row.key,
                ),
            );
        }
        if transition
            .info
            .state_transition
            .genesis_checkpoint_state_transition_hash
            != config.genesis_checkpoint_state_transition_hash
        {
            return Err(
                BranchExactLegacyExportError::GenesisTransitionHashMismatch(
                    row.key,
                ),
            );
        }
        if transition
            .info
            .state_transition
            .checkpoint_state_transition_circuit_fingerprint
            != config.checkpoint_state_transition_circuit_fingerprint
        {
            return Err(BranchExactLegacyExportError::CircuitFingerprintMismatch(
                row.key,
            ));
        }
        let transition_state =
            &transition.info.state_transition.checkpoint_transition;
        if transition
            .info
            .checkpoint_leaf
            .qfhash::<Hasher>()
            != transition_state.new_checkpoint_leaf_hash
        {
            return Err(
                BranchExactLegacyExportError::CheckpointLeafHashMismatch(
                    row.key,
                ),
            );
        }
        if row.key == 0 {
            if transition_state.old_checkpoint_tree_root
                != transition_state.new_checkpoint_tree_root
                || transition_state.old_checkpoint_leaf_hash
                    != transition_state.new_checkpoint_leaf_hash
            {
                return Err(
                    BranchExactLegacyExportError::GenesisTransitionNotSelf,
                );
            }
        } else if previous_root_leaf
            != Some((
                transition_state.old_checkpoint_tree_root,
                transition_state.old_checkpoint_leaf_hash,
            ))
        {
            return Err(
                BranchExactLegacyExportError::TransitionPredecessorMismatch(
                    row.key,
                ),
            );
        }

        let checkpoint_hash = if row.key == 0 {
            if !transition.zk_proof.is_empty() {
                return Err(
                    BranchExactLegacyExportError::UnexpectedGenesisProof,
                );
            }
            genesis_checkpoint_hash::<_, Hasher>(
                transition
                    .info
                    .state_transition
                    .checkpoint_transition
                    .new_checkpoint_tree_root,
                transition
                    .info
                    .state_transition
                    .checkpoint_transition
                    .new_checkpoint_leaf_hash,
                config.genesis_checkpoint_state_transition_fingerprint,
            )
        } else {
            if transition.zk_proof.is_empty() {
                return Err(BranchExactLegacyExportError::MissingCheckpointProof(
                    row.key,
                ));
            }
            let extracted = checkpoint_hash_from_saved_proof_bytes::<
                Hash,
                Proof,
                Verifier,
            >(&transition.zk_proof)
            .map_err(|error| {
                BranchExactLegacyExportError::MalformedCheckpointProof {
                    checkpoint_id: row.key,
                    reason: error.to_string(),
                }
            })?;
            let expected = CheckpointHash::from_last_chain_hash(
                transition
                    .info
                    .state_transition
                    .get_chain_hash_from_previous::<Hasher>(
                        previous_hash
                            .as_ref()
                            .expect("checkpoint 0 establishes previous hash"),
                    ),
            );
            if extracted != expected {
                return Err(
                    BranchExactLegacyExportError::CheckpointChainMismatch(
                        row.key,
                    ),
                );
            }
            extracted
        };
        previous_hash = Some(*checkpoint_hash.as_inner());
        previous_root_leaf = Some((
            transition_state.new_checkpoint_tree_root,
            transition_state.new_checkpoint_leaf_hash,
        ));
        by_checkpoint.insert(
            row.key,
            CanonicalChainRef::new(
                source_head.canonical_ref().network_id(),
                ChainEpoch::new(0),
                CheckpointRef::new(CheckpointId::new(row.key), checkpoint_hash),
            ),
        );
    }

    let recovered_head = by_checkpoint
        .get(&head_id)
        .expect("non-empty continuous catalog contains head");
    if recovered_head != source_head.canonical_ref() {
        return Err(BranchExactLegacyExportError::RecoveredHeadMismatch);
    }
    let digest = catalog_digest(&source_head, &by_checkpoint);
    Ok(BranchExactCanonicalCatalog {
        source_head,
        by_checkpoint,
        digest,
    })
}

fn catalog_digest<Hash: Q256BitHash>(
    source_head: &StoredCanonicalHead<Hash>,
    rows: &BTreeMap<u64, CanonicalChainRef<Hash>>,
) -> BranchExactCanonicalCatalogDigest {
    let mut hasher = Sha256::new();
    hasher.update(CATALOG_DIGEST_DOMAIN);
    hasher.update(source_head.revision().get().to_be_bytes());
    hasher.update(source_head.canonical_ref_bytes());
    hasher.update((rows.len() as u64).to_be_bytes());
    for (checkpoint_id, canonical_ref) in rows {
        hasher.update(checkpoint_id.to_be_bytes());
        hasher.update(canonical_ref.to_canonical_bytes());
    }
    BranchExactCanonicalCatalogDigest(hasher.finalize().into())
}

fn export_snapshot<Hash: Q256BitHash>(
    permit: &BranchExactFrozenLegacyExportPermit<Hash>,
    catalog: &BranchExactCanonicalCatalog<Hash>,
    source: LegacySourceSnapshot,
) -> Result<BranchExactLegacyExport<Hash>, BranchExactLegacyExportError> {
    let mut reverse = BTreeMap::new();
    for row in &source.reverse {
        let pending_id = UniquePendingId::try_new(row.key).map_err(|_| {
            BranchExactLegacyExportError::PendingOutOfTargetRange(row.key)
        })?;
        if reverse.insert(pending_id, row.value).is_some() {
            return Err(BranchExactLegacyExportError::DuplicateReversePending(
                row.key,
            ));
        }
    }

    let mut mappings = Vec::with_capacity(source.forward.len());
    let mut seen_pending = BTreeSet::new();
    for row in &source.forward {
        let pending_id = UniquePendingId::try_new(row.value).map_err(|_| {
            BranchExactLegacyExportError::PendingOutOfTargetRange(row.value)
        })?;
        if !seen_pending.insert(pending_id) {
            return Err(BranchExactLegacyExportError::PendingMappedTwice(
                row.value,
            ));
        }
        match reverse.remove(&pending_id) {
            None => {
                return Err(BranchExactLegacyExportError::MissingReverse {
                    checkpoint_id: row.key,
                    pending_id: row.value,
                })
            }
            Some(checkpoint_id) if checkpoint_id != row.key => {
                return Err(BranchExactLegacyExportError::NonMutualPair {
                    checkpoint_id: row.key,
                    pending_id: row.value,
                    reverse_checkpoint_id: checkpoint_id,
                })
            }
            Some(_) => {}
        }
        let canonical_ref = catalog.get(row.key).copied().ok_or(
            BranchExactLegacyExportError::MissingCanonicalRef(row.key),
        )?;
        mappings.push(BranchPendingMapping::new(canonical_ref, pending_id));
    }
    if let Some((pending_id, checkpoint_id)) = reverse.first_key_value() {
        return Err(BranchExactLegacyExportError::OrphanReverse {
            pending_id: pending_id.get(),
            checkpoint_id: *checkpoint_id,
        });
    }
    if mappings.is_empty() {
        return Err(BranchExactLegacyExportError::EmptyLegacyMapping);
    }

    let proof_by_pending = decode_exact_proofs::<Hash>(
        permit.request.plan().authority(),
        source.reward_proofs,
        &seen_pending,
    )?;
    let mut rows = Vec::with_capacity(mappings.len());
    for mapping in mappings {
        let proof = match permit.request.plan().authority() {
            AuthorityScope::Coordinator => None,
            AuthorityScope::Realm { .. } => Some(
                proof_by_pending.get(&mapping.pending_id()).ok_or(
                    BranchExactLegacyExportError::MissingRealmProof(
                        mapping.pending_id().get(),
                    ),
                )?,
            ),
        };
        rows.push(
            BranchExactBackfillArtifactRow::try_new(mapping, proof)
                .map_err(|error| {
                    BranchExactLegacyExportError::Artifact(error.to_string())
                })?,
        );
    }
    let artifact = BranchExactBackfillArtifact::try_new(
        permit.request.plan().authority(),
        rows,
    )
    .map_err(|error| BranchExactLegacyExportError::Artifact(error.to_string()))?;
    let source_chunk_digests = source_chunk_digests(permit, &artifact);
    let receipt = BranchExactLegacyExportReceipt {
        permit_digest: permit.digest,
        catalog_digest: catalog.digest,
        source_digest: source.digest,
        dataset_digest: artifact.dataset_digest(),
        source_chunk_digests,
        pair_rows: artifact.pair_rows_per_direction(),
        proof_rows: artifact.proof_rows(),
    };
    Ok(BranchExactLegacyExport { artifact, receipt })
}

fn decode_exact_proofs<Hash: Q256BitHash>(
    authority: AuthorityScope,
    proofs: Vec<LegacyBlobRow>,
    expected_pending: &BTreeSet<UniquePendingId>,
) -> Result<BTreeMap<UniquePendingId, TagTreeMerkleProof<Hash>>, BranchExactLegacyExportError>
{
    if authority == AuthorityScope::Coordinator {
        if proofs.is_empty() {
            return Ok(BTreeMap::new());
        }
        return Err(BranchExactLegacyExportError::UnexpectedCoordinatorProof);
    }
    let mut decoded = BTreeMap::new();
    for row in proofs {
        let pending_id = UniquePendingId::try_new(row.key).map_err(|_| {
            BranchExactLegacyExportError::PendingOutOfTargetRange(row.key)
        })?;
        if !expected_pending.contains(&pending_id) {
            return Err(BranchExactLegacyExportError::OrphanRealmProof(row.key));
        }
        let proof = TagTreeMerkleProof::<Hash>::psy_ser_from_owned_bytes_vec(
            row.value.clone(),
        )
        .map_err(|error| BranchExactLegacyExportError::MalformedRealmProof {
            pending_id: row.key,
            reason: error.to_string(),
        })?;
        let canonical = proof.psy_ser_to_bytes_vec().map_err(|error| {
            BranchExactLegacyExportError::MalformedRealmProof {
                pending_id: row.key,
                reason: error.to_string(),
            }
        })?;
        if canonical != row.value {
            return Err(BranchExactLegacyExportError::NonCanonicalRealmProof(
                row.key,
            ));
        }
        if decoded.insert(pending_id, proof).is_some() {
            return Err(BranchExactLegacyExportError::DuplicateRealmProof(
                row.key,
            ));
        }
    }
    if let Some(missing) = expected_pending
        .iter()
        .find(|pending_id| !decoded.contains_key(pending_id))
    {
        return Err(BranchExactLegacyExportError::MissingRealmProof(
            missing.get(),
        ));
    }
    Ok(decoded)
}

fn source_chunk_digests<Hash: Q256BitHash>(
    permit: &BranchExactFrozenLegacyExportPermit<Hash>,
    artifact: &BranchExactBackfillArtifact<Hash>,
) -> Vec<BranchExactSourceChunkDigest> {
    artifact
        .rows()
        .chunks(SOURCE_CHUNK_ROWS)
        .enumerate()
        .map(|(index, rows)| {
            let mut hasher = Sha256::new();
            hasher.update(SOURCE_CHUNK_DIGEST_DOMAIN);
            hasher.update(permit.digest.as_bytes());
            hasher.update((index as u32).to_be_bytes());
            hasher.update((rows.len() as u32).to_be_bytes());
            for row in rows {
                hasher.update(row.mapping().canonical_chain_bytes());
                hasher.update(row.mapping().pending_id().get().to_be_bytes());
                match row.reward_proof_canonical() {
                    None => hasher.update([0]),
                    Some(proof) => {
                        hasher.update([1]);
                        hasher.update((proof.len() as u64).to_be_bytes());
                        hasher.update(proof);
                    }
                }
            }
            BranchExactSourceChunkDigest(hasher.finalize().into())
        })
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactLegacyExportError {
    UnsupportedSourceProfile,
    MissingBaselineEvidence,
    LegacyEpochAmbiguous(u64),
    RollbackControlNotIdle,
    SourceHeadAnchorMismatch,
    AuthorityMismatch,
    TargetKeyspaceMismatch,
    HeadRead(String),
    HeadUninitialized,
    SourceHeadChanged,
    CanonicalSourceChanged,
    LegacySourceChanged,
    Driver(String),
    Observer(String),
    CheckpointRangeOverflow,
    CheckpointTransitionCount { expected: u64, actual: u64 },
    CheckpointTransitionGap { expected: u64, actual: u64 },
    DuplicateCheckpointTransition(u64),
    MalformedCheckpointTransition { checkpoint_id: u64, reason: String },
    NonCanonicalCheckpointTransition(u64),
    GenesisTransitionHashMismatch(u64),
    CircuitFingerprintMismatch(u64),
    CheckpointLeafHashMismatch(u64),
    GenesisTransitionNotSelf,
    TransitionPredecessorMismatch(u64),
    UnexpectedGenesisProof,
    MissingCheckpointProof(u64),
    MalformedCheckpointProof { checkpoint_id: u64, reason: String },
    CheckpointChainMismatch(u64),
    RecoveredHeadMismatch,
    DuplicateForwardCheckpoint(u64),
    DuplicateReversePending(u64),
    PendingOutOfTargetRange(u64),
    PendingMappedTwice(u64),
    MissingReverse { checkpoint_id: u64, pending_id: u64 },
    NonMutualPair {
        checkpoint_id: u64,
        pending_id: u64,
        reverse_checkpoint_id: u64,
    },
    OrphanReverse { pending_id: u64, checkpoint_id: u64 },
    MissingCanonicalRef(u64),
    EmptyLegacyMapping,
    UnexpectedCoordinatorProof,
    DuplicateRealmProof(u64),
    MissingRealmProof(u64),
    OrphanRealmProof(u64),
    MalformedRealmProof { pending_id: u64, reason: String },
    NonCanonicalRealmProof(u64),
    Artifact(String),
}

impl fmt::Display for BranchExactLegacyExportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for BranchExactLegacyExportError {}

#[cfg(test)]
mod tests {
    use parth_core::{
        crypto::hash::traits::{QFieldHashable, ZeroableHash},
        pgoldilocks::PoseidonHasher,
        protocol::core_types::{Q256BitHash, QZKProofPublicInputsHasherReader},
        PHash, PF,
    };
    use psy_data::{
        protocol::{
            canonical_chain::{
                checkpoint_hash_from_previous, CanonicalChainRef, ChainEpoch,
                CheckpointHash, CheckpointId, CheckpointRef, NetworkId,
            },
            checkpoint_transition_hash::{
                CheckpointStateHashTransition,
                CheckpointStateTransitionPublicInputs,
            },
            verifiable_checkpoint_transition::{
                PsyVerifiableCheckpointTransition,
                PsyVerifiableCheckpointTransitionWithProof,
            },
        },
        v1::qdata::{
            checkpoint::{
                PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeafStats,
            },
            populated_checkpoint::PsyCheckpointLeafPopulated,
        },
    };
    use psy_node_core::store::{
        branch_exact_schema::{
            BaselineSnapshotArtifactDigest,
            BranchExactPostGenesisFloorEvidence,
            BranchExactSchemaMaterializationPlan,
        },
        canonical_head::{
            CanonicalHeadBootstrap, CanonicalHeadBootstrapProfile,
            StoredCanonicalHead,
        },
        manifest_record::AuthorityManifestDigest,
        rollback_control::RollbackControlState,
    };

    use super::*;

    #[derive(Clone, Copy, Debug)]
    struct HashProofVerifier;

    impl QZKProofPublicInputsHasherReader<PHash, PHash> for HashProofVerifier {
        fn get_proof_public_inputs_hash(proof: &PHash) -> anyhow::Result<PHash> {
            Ok(*proof)
        }

        fn try_proof_from_slice(bytes: &[u8]) -> anyhow::Result<PHash> {
            Ok(PHash::from_owned_32bytes(bytes.try_into()?))
        }
    }

    fn network() -> NetworkId {
        NetworkId::try_from_chain_id(0x6979_7350).unwrap()
    }

    fn hash(seed: u64) -> PHash {
        PHash::from_values(seed, seed + 1, seed + 2, seed + 3)
    }

    fn empty_checkpoint_leaf() -> PsyCheckpointLeafPopulated<PF, PHash> {
        PsyCheckpointLeafPopulated {
            global_state_roots: PQEDCheckpointGlobalStateRoots {
                contract_tree_root: PHash::get_zero_value(),
                deposit_tree_root: PHash::get_zero_value(),
                user_tree_root: PHash::get_zero_value(),
                withdrawal_tree_root: PHash::get_zero_value(),
                user_registration_tree_root: PHash::get_zero_value(),
            },
            stats: PQEDCheckpointLeafStats::get_empty_stats(),
        }
    }

    fn transition_rows(
        head: u64,
    ) -> (
        Vec<LegacyBlobRow>,
        BranchExactCheckpointChainConfig<PHash>,
        Vec<CanonicalChainRef<PHash>>,
    ) {
        let genesis_fingerprint = hash(100);
        let genesis_transition_hash = hash(200);
        let checkpoint_fingerprint = hash(300);
        let config = BranchExactCheckpointChainConfig::new(
            genesis_fingerprint,
            genesis_transition_hash,
            checkpoint_fingerprint,
        );
        let checkpoint_leaf = empty_checkpoint_leaf();
        let leaf_hash = checkpoint_leaf.qfhash::<PoseidonHasher>();
        let mut previous_root = hash(400);
        let mut previous_leaf = leaf_hash;
        let mut previous_chain = None;
        let mut rows = Vec::new();
        let mut refs = Vec::new();
        for checkpoint_id in 0..=head {
            let new_root = hash(500 + checkpoint_id * 10);
            let state = CheckpointStateHashTransition {
                old_checkpoint_tree_root: if checkpoint_id == 0 {
                    new_root
                } else {
                    previous_root
                },
                new_checkpoint_tree_root: new_root,
                old_checkpoint_leaf_hash: if checkpoint_id == 0 {
                    leaf_hash
                } else {
                    previous_leaf
                },
                new_checkpoint_leaf_hash: leaf_hash,
            };
            let chain_hash = if checkpoint_id == 0 {
                genesis_checkpoint_hash::<_, PoseidonHasher>(
                    new_root,
                    leaf_hash,
                    genesis_fingerprint,
                )
            } else {
                checkpoint_hash_from_previous::<_, PoseidonHasher>(
                    CheckpointHash::from_last_chain_hash(
                        previous_chain.expect("genesis chain"),
                    ),
                    new_root,
                    leaf_hash,
                    checkpoint_fingerprint,
                )
            };
            let proof = if checkpoint_id == 0 {
                Vec::new()
            } else {
                chain_hash.as_inner().into_owned_32bytes().to_vec()
            };
            let transition = PsyVerifiableCheckpointTransitionWithProof {
                info: PsyVerifiableCheckpointTransition {
                    state_transition: CheckpointStateTransitionPublicInputs {
                        checkpoint_transition: state,
                        genesis_checkpoint_state_transition_hash:
                            genesis_transition_hash,
                        checkpoint_state_transition_circuit_fingerprint:
                            checkpoint_fingerprint,
                    },
                    checkpoint_leaf,
                },
                circuit_type: 7,
                zk_proof: proof,
            };
            rows.push(LegacyBlobRow {
                key: checkpoint_id,
                value: transition.psy_ser_to_bytes_vec().unwrap(),
            });
            refs.push(CanonicalChainRef::new(
                network(),
                ChainEpoch::new(0),
                CheckpointRef::new(CheckpointId::new(checkpoint_id), chain_hash),
            ));
            previous_root = new_root;
            previous_leaf = leaf_hash;
            previous_chain = Some(*chain_hash.as_inner());
        }
        (rows, config, refs)
    }

    fn authority() -> AuthorityScope {
        AuthorityScope::Realm {
            realm_id: 7,
            realm_sub_id: 2,
        }
    }

    fn bootstrap(
        head: CanonicalChainRef<PHash>,
    ) -> CanonicalHeadBootstrap<PHash> {
        CanonicalHeadBootstrap::try_new(
            CanonicalHeadBootstrapProfile::PostGenesisFloor,
            head,
        )
        .unwrap()
    }

    fn permit(
        authority: AuthorityScope,
        head: CanonicalChainRef<PHash>,
    ) -> BranchExactFrozenLegacyExportPermit<PHash> {
        let bootstrap = bootstrap(head);
        let plan = BranchExactSchemaMaterializationPlan::try_new(
            &bootstrap,
            authority,
            Some(BranchExactPostGenesisFloorEvidence::new(
                authority,
                BaselineSnapshotArtifactDigest::try_new([7; 32]).unwrap(),
                AuthorityManifestDigest::from_persisted([8; 32]),
            )),
        )
        .unwrap();
        let request = BranchExactSchemaMaterializationRequest::try_new(
            CqlKeyspaceName::try_new("legacy_ks").unwrap(),
            plan,
        )
        .unwrap();
        BranchExactFrozenLegacyExportPermit::try_new(
            request,
            *bootstrap.candidate(),
            BranchExactLegacyFreezeReason::AllAuthorityProcessorsStoppedAndDrained,
        )
        .unwrap()
    }

    fn catalog(
        refs: &[CanonicalChainRef<PHash>],
    ) -> BranchExactCanonicalCatalog<PHash> {
        let head = *refs.last().unwrap();
        let stored = *bootstrap(head).candidate();
        let by_checkpoint = refs
            .iter()
            .map(|reference| {
                (
                    reference.checkpoint().checkpoint_id().get(),
                    *reference,
                )
            })
            .collect::<BTreeMap<_, _>>();
        BranchExactCanonicalCatalog {
            source_head: stored,
            digest: catalog_digest(&stored, &by_checkpoint),
            by_checkpoint,
        }
    }

    fn proof_bytes() -> Vec<u8> {
        TagTreeMerkleProof::<PHash>::new_empty()
            .psy_ser_to_bytes_vec()
            .unwrap()
    }

    #[test]
    fn proof_chain_builds_full_catalog_and_binds_exact_head() {
        let (rows, config, refs) = transition_rows(3);
        let head = *bootstrap(*refs.last().unwrap()).candidate();
        let actual = build_catalog::<PF, PHash, PoseidonHasher, PHash, HashProofVerifier>(
            head, config, rows,
        )
        .unwrap();
        assert_eq!(actual.rows().count(), 4);
        assert_eq!(actual.get(2), Some(&refs[2]));
        assert_eq!(actual.source_head(), &head);
        assert_ne!(actual.digest().as_bytes(), &[0; 32]);
    }

    #[test]
    fn catalog_rejects_gap_bad_chain_and_noncanonical_transition() {
        let (rows, config, refs) = transition_rows(2);
        let head = *bootstrap(*refs.last().unwrap()).candidate();

        let mut missing = rows.clone();
        missing.remove(1);
        assert!(matches!(
            build_catalog::<PF, PHash, PoseidonHasher, PHash, HashProofVerifier>(
                head, config, missing
            ),
            Err(BranchExactLegacyExportError::CheckpointTransitionCount { .. })
        ));

        let mut bad_chain = rows.clone();
        let mut decoded = PsyVerifiableCheckpointTransitionWithProof::<PF, PHash>::
            psy_ser_from_owned_bytes_vec(bad_chain[2].value.clone())
            .unwrap();
        decoded.zk_proof = hash(999).into_owned_32bytes().to_vec();
        bad_chain[2].value = decoded.psy_ser_to_bytes_vec().unwrap();
        assert_eq!(
            build_catalog::<PF, PHash, PoseidonHasher, PHash, HashProofVerifier>(
                head, config, bad_chain
            )
            .unwrap_err(),
            BranchExactLegacyExportError::CheckpointChainMismatch(2)
        );

        let mut trailing = rows;
        trailing[1].value.push(0);
        assert!(matches!(
            build_catalog::<PF, PHash, PoseidonHasher, PHash, HashProofVerifier>(
                head, config, trailing
            ),
            Err(BranchExactLegacyExportError::NonCanonicalCheckpointTransition(1))
                | Err(BranchExactLegacyExportError::MalformedCheckpointTransition { checkpoint_id: 1, .. })
        ));
    }

    #[test]
    fn realm_export_is_deterministic_across_source_order() {
        let (_, _, refs) = transition_rows(3);
        let catalog = catalog(&refs);
        let permit = permit(authority(), refs[3]);
        let forward_a = vec![
            LegacyU64PairRow { key: 3, value: 13 },
            LegacyU64PairRow { key: 0, value: 10 },
            LegacyU64PairRow { key: 2, value: 12 },
        ];
        let reverse_a = vec![
            LegacyU64PairRow { key: 12, value: 2 },
            LegacyU64PairRow { key: 10, value: 0 },
            LegacyU64PairRow { key: 13, value: 3 },
        ];
        let proofs_a = vec![10, 12, 13]
            .into_iter()
            .rev()
            .map(|key| LegacyBlobRow {
                key,
                value: proof_bytes(),
            })
            .collect::<Vec<_>>();
        let first = export_snapshot(
            &permit,
            &catalog,
            LegacySourceSnapshot::try_new(
                authority(),
                forward_a.clone(),
                reverse_a.clone(),
                proofs_a.clone(),
            )
            .unwrap(),
        )
        .unwrap();
        let second = export_snapshot(
            &permit,
            &catalog,
            LegacySourceSnapshot::try_new(
                authority(),
                forward_a.into_iter().rev().collect(),
                reverse_a.into_iter().rev().collect(),
                proofs_a.into_iter().rev().collect(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            first.artifact().to_canonical_bytes(),
            second.artifact().to_canonical_bytes()
        );
        assert_eq!(first.receipt(), second.receipt());
        assert_eq!(first.receipt().pair_rows(), 3);
        assert_eq!(first.receipt().proof_rows(), 3);
        assert_eq!(first.receipt().source_chunk_digests().len(), 1);
    }

    #[test]
    fn coordinator_export_contains_no_reward_proofs() {
        let (_, _, refs) = transition_rows(1);
        let catalog = catalog(&refs);
        let permit = permit(AuthorityScope::Coordinator, refs[1]);
        let source = LegacySourceSnapshot::try_new(
            AuthorityScope::Coordinator,
            vec![LegacyU64PairRow { key: 1, value: 9 }],
            vec![LegacyU64PairRow { key: 9, value: 1 }],
            vec![],
        )
        .unwrap();
        let exported = export_snapshot(&permit, &catalog, source).unwrap();
        assert_eq!(exported.receipt().proof_rows(), 0);
        assert!(exported.artifact().rows()[0]
            .reward_proof_canonical()
            .is_none());
    }

    #[test]
    fn mapping_pair_anomalies_fail_closed() {
        let (_, _, refs) = transition_rows(2);
        let catalog = catalog(&refs);
        let permit = permit(AuthorityScope::Coordinator, refs[2]);
        let source = |forward, reverse| {
            LegacySourceSnapshot::try_new(
                AuthorityScope::Coordinator,
                forward,
                reverse,
                vec![],
            )
            .unwrap()
        };
        assert!(matches!(
            export_snapshot(
                &permit,
                &catalog,
                source(vec![LegacyU64PairRow { key: 2, value: 20 }], vec![])
            ),
            Err(BranchExactLegacyExportError::MissingReverse { .. })
        ));
        assert!(matches!(
            export_snapshot(
                &permit,
                &catalog,
                source(
                    vec![LegacyU64PairRow { key: 2, value: 20 }],
                    vec![LegacyU64PairRow { key: 20, value: 1 }]
                )
            ),
            Err(BranchExactLegacyExportError::NonMutualPair { .. })
        ));
        assert!(matches!(
            export_snapshot(
                &permit,
                &catalog,
                source(
                    vec![LegacyU64PairRow { key: 2, value: 20 }],
                    vec![
                        LegacyU64PairRow { key: 20, value: 2 },
                        LegacyU64PairRow { key: 21, value: 1 }
                    ]
                )
            ),
            Err(BranchExactLegacyExportError::OrphanReverse { .. })
        ));
        assert_eq!(
            export_snapshot(
                &permit,
                &catalog,
                source(
                    vec![LegacyU64PairRow {
                        key: 2,
                        value: i64::MAX as u64 + 1,
                    }],
                    vec![LegacyU64PairRow {
                        key: i64::MAX as u64 + 1,
                        value: 2,
                    }]
                )
            )
            .unwrap_err(),
            BranchExactLegacyExportError::PendingOutOfTargetRange(
                i64::MAX as u64 + 1
            )
        );
    }

    #[test]
    fn realm_proof_set_is_exact_and_strictly_canonical() {
        let (_, _, refs) = transition_rows(1);
        let catalog = catalog(&refs);
        let permit = permit(authority(), refs[1]);
        let source = |proofs| {
            LegacySourceSnapshot::try_new(
                authority(),
                vec![LegacyU64PairRow { key: 1, value: 11 }],
                vec![LegacyU64PairRow { key: 11, value: 1 }],
                proofs,
            )
            .unwrap()
        };
        assert_eq!(
            export_snapshot(&permit, &catalog, source(vec![])).unwrap_err(),
            BranchExactLegacyExportError::MissingRealmProof(11)
        );
        assert_eq!(
            export_snapshot(
                &permit,
                &catalog,
                source(vec![LegacyBlobRow {
                    key: 12,
                    value: proof_bytes(),
                }])
            )
            .unwrap_err(),
            BranchExactLegacyExportError::OrphanRealmProof(12)
        );
        let mut trailing = proof_bytes();
        trailing.push(0);
        assert!(matches!(
            export_snapshot(
                &permit,
                &catalog,
                source(vec![LegacyBlobRow {
                    key: 11,
                    value: trailing,
                }])
            ),
            Err(BranchExactLegacyExportError::NonCanonicalRealmProof(11))
                | Err(BranchExactLegacyExportError::MalformedRealmProof { pending_id: 11, .. })
        ));
    }

    #[test]
    fn permit_refuses_epoch_recovery_from_height_only_legacy_rows() {
        let (_, _, refs) = transition_rows(1);
        let epoch_one = CanonicalChainRef::new(
            network(),
            ChainEpoch::new(1),
            *refs[1].checkpoint(),
        );
        let idle = RollbackControlState::<PHash>::Idle.to_canonical_bytes();
        let stored: StoredCanonicalHead<PHash> =
            StoredCanonicalHead::decode_persisted(
            network(),
            1,
            &epoch_one.to_canonical_bytes(),
            &idle,
        )
        .unwrap();
        let bootstrap = bootstrap(refs[1]);
        let plan = BranchExactSchemaMaterializationPlan::try_new(
            &bootstrap,
            AuthorityScope::Coordinator,
            Some(BranchExactPostGenesisFloorEvidence::new(
                AuthorityScope::Coordinator,
                BaselineSnapshotArtifactDigest::try_new([7; 32]).unwrap(),
                AuthorityManifestDigest::from_persisted([8; 32]),
            )),
        )
        .unwrap();
        let request = BranchExactSchemaMaterializationRequest::try_new(
            CqlKeyspaceName::try_new("legacy_ks").unwrap(),
            plan,
        )
        .unwrap();
        assert_eq!(
            BranchExactFrozenLegacyExportPermit::try_new(
                request,
                stored,
                BranchExactLegacyFreezeReason::AllAuthorityProcessorsStoppedAndDrained,
            )
            .unwrap_err(),
            BranchExactLegacyExportError::LegacyEpochAmbiguous(1)
        );
    }
}
