//! Canonical artifact reader and production-shaped branch-exact backfill I/O.
//!
//! The executor writes only the isolated branch-exact target schema. It does
//! not publish a reader/writer cutover capability and is absent from node
//! startup/setup paths.

use std::{collections::BTreeSet, error::Error, fmt, sync::Arc};

use parth_core::{
    crypto::hash::tag_tree::TagTreeMerkleProof,
    protocol::core_types::Q256BitHash,
};
use psy_node_core::store::{
    branch_exact_schema::AuthorityScope,
    branch_pending_mapping::{
        BranchPendingMapping, BRANCH_PENDING_CANONICAL_REF_LEN,
    },
    typed::UniquePendingId,
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
use scylla::{client::session::Session, statement::Consistency};
use sha2::{Digest, Sha256};

use super::{
    BranchExactBackfillChunkDigest, BranchExactBackfillChunkReceipt,
    BranchExactBackfillDatasetDigest, BranchExactBackfillMode,
    BranchExactBackfillPlan, BranchExactBackfillReadbackObservation,
    BranchExactSchemaMigrationAdapter, BranchPendingPairPutPlan,
    PendingRewardProofPutPlan,
};

const ARTIFACT_MAGIC: [u8; 8] = *b"PSYBEXBF";
const ARTIFACT_CODEC_VERSION: u16 = 1;
const ARTIFACT_DATASET_DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/branch-exact-backfill-artifact/v1";
const ARTIFACT_CHUNK_DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/branch-exact-backfill-chunk/v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactBackfillArtifactRow<Hash> {
    mapping: BranchPendingMapping<Hash>,
    reward_proof_canonical: Option<Vec<u8>>,
}

impl<Hash: Q256BitHash> BranchExactBackfillArtifactRow<Hash> {
    pub fn try_new(
        mapping: BranchPendingMapping<Hash>,
        reward_proof: Option<&TagTreeMerkleProof<Hash>>,
    ) -> Result<Self, BranchExactBackfillArtifactError> {
        let reward_proof_canonical = reward_proof
            .map(|proof| {
                proof
                    .psy_ser_to_bytes_vec()
                    .map_err(|error| {
                        BranchExactBackfillArtifactError::ProofCodec(
                            error.to_string(),
                        )
                    })
            })
            .transpose()?;
        if let Some(proof) = &reward_proof_canonical {
            if proof.len() > u32::MAX as usize {
                return Err(BranchExactBackfillArtifactError::ProofTooLarge(
                    proof.len(),
                ));
            }
        }
        Ok(Self {
            mapping,
            reward_proof_canonical,
        })
    }

    pub const fn mapping(&self) -> &BranchPendingMapping<Hash> {
        &self.mapping
    }

    pub fn reward_proof_canonical(&self) -> Option<&[u8]> {
        self.reward_proof_canonical.as_deref()
    }

    fn canonical_ref_bytes(&self) -> [u8; BRANCH_PENDING_CANONICAL_REF_LEN] {
        self.mapping.canonical_chain_bytes()
    }

    fn decode_reward_proof(
        &self,
    ) -> Result<Option<TagTreeMerkleProof<Hash>>, BranchExactBackfillArtifactError>
    {
        self.reward_proof_canonical
            .as_ref()
            .map(|bytes| {
                TagTreeMerkleProof::<Hash>::psy_ser_from_owned_bytes_vec(
                    bytes.clone(),
                )
                .map_err(|error| {
                    BranchExactBackfillArtifactError::ProofCodec(
                        error.to_string(),
                    )
                })
            })
            .transpose()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactBackfillArtifact<Hash> {
    authority: AuthorityScope,
    rows: Vec<BranchExactBackfillArtifactRow<Hash>>,
    proof_rows: u64,
    dataset_digest: BranchExactBackfillDatasetDigest,
    canonical_bytes: Vec<u8>,
}

impl<Hash: Q256BitHash> BranchExactBackfillArtifact<Hash> {
    pub fn try_new(
        authority: AuthorityScope,
        mut rows: Vec<BranchExactBackfillArtifactRow<Hash>>,
    ) -> Result<Self, BranchExactBackfillArtifactError> {
        if rows.is_empty() {
            return Err(BranchExactBackfillArtifactError::EmptyArtifact);
        }
        if rows.len() > u32::MAX as usize {
            return Err(BranchExactBackfillArtifactError::TooManyRows(
                rows.len(),
            ));
        }
        rows.sort_unstable_by(|left, right| {
            left.canonical_ref_bytes()
                .cmp(&right.canonical_ref_bytes())
                .then_with(|| {
                    left.mapping
                        .pending_id()
                        .cmp(&right.mapping.pending_id())
                })
        });

        let mut canonical_refs = BTreeSet::new();
        let mut pending_ids = BTreeSet::new();
        let mut proof_rows = 0_u64;
        for row in &rows {
            if !canonical_refs.insert(row.canonical_ref_bytes()) {
                return Err(
                    BranchExactBackfillArtifactError::DuplicateCanonicalRef,
                );
            }
            if !pending_ids.insert(row.mapping.pending_id()) {
                return Err(
                    BranchExactBackfillArtifactError::DuplicatePendingId(
                        row.mapping.pending_id().get(),
                    ),
                );
            }
            if row.reward_proof_canonical.is_some() {
                if authority == AuthorityScope::Coordinator {
                    return Err(
                        BranchExactBackfillArtifactError::CoordinatorProofRow,
                    );
                }
                row.decode_reward_proof()?;
                proof_rows = proof_rows
                    .checked_add(1)
                    .ok_or(BranchExactBackfillArtifactError::RowCountOverflow)?;
            }
        }

        let without_digest = encode_artifact_without_digest(authority, &rows);
        let dataset_digest = calculate_dataset_digest(&without_digest)?;
        let mut canonical_bytes = without_digest;
        canonical_bytes.extend_from_slice(dataset_digest.as_bytes());
        Ok(Self {
            authority,
            rows,
            proof_rows,
            dataset_digest,
            canonical_bytes,
        })
    }

    pub const fn authority(&self) -> AuthorityScope {
        self.authority
    }

    pub fn rows(&self) -> &[BranchExactBackfillArtifactRow<Hash>] {
        &self.rows
    }

    pub fn pair_rows_per_direction(&self) -> u64 {
        self.rows.len() as u64
    }

    pub const fn proof_rows(&self) -> u64 {
        self.proof_rows
    }

    pub const fn dataset_digest(&self) -> BranchExactBackfillDatasetDigest {
        self.dataset_digest
    }

    pub fn to_canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn decode_persisted(
        bytes: &[u8],
    ) -> Result<Self, BranchExactBackfillArtifactError> {
        let mut decoder = ArtifactDecoder::new(bytes);
        if decoder.take(ARTIFACT_MAGIC.len())? != ARTIFACT_MAGIC {
            return Err(BranchExactBackfillArtifactError::InvalidMagic);
        }
        let version = decoder.u16()?;
        if version != ARTIFACT_CODEC_VERSION {
            return Err(
                BranchExactBackfillArtifactError::UnknownCodecVersion(version),
            );
        }
        let authority = decoder.authority()?;
        let row_count = decoder.u32()? as usize;
        if row_count == 0 {
            return Err(BranchExactBackfillArtifactError::EmptyArtifact);
        }
        let mut rows = Vec::with_capacity(row_count);
        for _ in 0..row_count {
            let canonical_ref = decoder
                .take(BRANCH_PENDING_CANONICAL_REF_LEN)?
                .to_vec();
            let pending_id = UniquePendingId::try_new(decoder.u64()?)?;
            let reward_proof_canonical = match decoder.u8()? {
                0 => None,
                1 => {
                    let length = decoder.u32()? as usize;
                    Some(decoder.take(length)?.to_vec())
                }
                value => {
                    return Err(
                        BranchExactBackfillArtifactError::InvalidProofPresence(
                            value,
                        ),
                    )
                }
            };
            rows.push(BranchExactBackfillArtifactRow {
                mapping: BranchPendingMapping::from_canonical_chain_bytes(
                    &canonical_ref,
                    pending_id,
                )
                .map_err(|error| {
                    BranchExactBackfillArtifactError::CanonicalRefCodec(
                        error.to_string(),
                    )
                })?,
                reward_proof_canonical,
            });
        }
        let persisted_digest = decoder.array32()?;
        decoder.finish()?;
        let artifact = Self::try_new(authority, rows)?;
        if artifact.dataset_digest.as_bytes() != &persisted_digest
            || artifact.canonical_bytes != bytes
        {
            return Err(
                BranchExactBackfillArtifactError::DatasetDigestMismatch,
            );
        }
        Ok(artifact)
    }

    pub fn validate_plan(
        &self,
        plan: &BranchExactBackfillPlan,
    ) -> Result<(), BranchExactBackfillArtifactError> {
        if plan.mode() != BranchExactBackfillMode::PostGenesisArtifact {
            return Err(BranchExactBackfillArtifactError::PlanModeMismatch);
        }
        if plan.deployment().intent().authority() != self.authority {
            return Err(BranchExactBackfillArtifactError::PlanAuthorityMismatch);
        }
        if plan.dataset_digest() != self.dataset_digest {
            return Err(BranchExactBackfillArtifactError::PlanDatasetMismatch);
        }
        if plan.pair_rows_per_direction() != self.pair_rows_per_direction()
            || plan.proof_rows() != self.proof_rows
        {
            return Err(BranchExactBackfillArtifactError::PlanCountMismatch);
        }
        if plan.write_timestamp().is_none() {
            return Err(
                BranchExactBackfillArtifactError::MissingWriteTimestamp,
            );
        }
        if plan.total_chunks() == 0
            || usize::try_from(plan.total_chunks()).unwrap_or(usize::MAX)
                > self.rows.len()
        {
            return Err(BranchExactBackfillArtifactError::InvalidChunkCount);
        }
        Ok(())
    }

    fn chunk(
        &self,
        plan: &BranchExactBackfillPlan,
        chunk_index: u32,
    ) -> Result<ArtifactChunk<'_, Hash>, BranchExactBackfillArtifactError> {
        self.validate_plan(plan)?;
        if chunk_index >= plan.total_chunks() {
            return Err(
                BranchExactBackfillArtifactError::ChunkIndexOutOfRange {
                    chunk_index,
                    total_chunks: plan.total_chunks(),
                },
            );
        }
        let total_chunks = plan.total_chunks() as usize;
        let chunk_index_usize = chunk_index as usize;
        let base = self.rows.len() / total_chunks;
        let remainder = self.rows.len() % total_chunks;
        let start = chunk_index_usize * base
            + chunk_index_usize.min(remainder);
        let length = base + usize::from(chunk_index_usize < remainder);
        let rows = &self.rows[start..start + length];
        let mut hasher = Sha256::new();
        hasher.update(ARTIFACT_CHUNK_DIGEST_DOMAIN);
        hasher.update(plan.digest().as_bytes());
        hasher.update(chunk_index.to_be_bytes());
        hasher.update(
            plan.write_timestamp()
                .expect("validated post-genesis plan has timestamp")
                .as_i64()
                .to_be_bytes(),
        );
        hasher.update((rows.len() as u64).to_be_bytes());
        let mut proof_rows = 0_u64;
        for row in rows {
            update_row_digest(&mut hasher, row);
            proof_rows += u64::from(row.reward_proof_canonical.is_some());
        }
        Ok(ArtifactChunk {
            rows,
            digest: BranchExactBackfillChunkDigest::try_new(
                hasher.finalize().into(),
            )?,
            proof_rows,
        })
    }
}

fn encode_artifact_without_digest<Hash: Q256BitHash>(
    authority: AuthorityScope,
    rows: &[BranchExactBackfillArtifactRow<Hash>],
) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(&ARTIFACT_MAGIC);
    output.extend_from_slice(&ARTIFACT_CODEC_VERSION.to_be_bytes());
    encode_authority(&mut output, authority);
    output.extend_from_slice(&(rows.len() as u32).to_be_bytes());
    for row in rows {
        output.extend_from_slice(&row.canonical_ref_bytes());
        output.extend_from_slice(&row.mapping.pending_id().get().to_be_bytes());
        match &row.reward_proof_canonical {
            None => output.push(0),
            Some(proof) => {
                output.push(1);
                output.extend_from_slice(&(proof.len() as u32).to_be_bytes());
                output.extend_from_slice(proof);
            }
        }
    }
    output
}

fn encode_authority(output: &mut Vec<u8>, authority: AuthorityScope) {
    match authority {
        AuthorityScope::Coordinator => {
            output.push(1);
            output.extend_from_slice(&[0; 6]);
        }
        AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } => {
            output.push(2);
            output.extend_from_slice(&realm_id.to_be_bytes());
            output.extend_from_slice(&realm_sub_id.to_be_bytes());
        }
    }
}

fn calculate_dataset_digest(
    canonical_without_digest: &[u8],
) -> Result<BranchExactBackfillDatasetDigest, BranchExactBackfillArtifactError>
{
    let mut hasher = Sha256::new();
    hasher.update(ARTIFACT_DATASET_DIGEST_DOMAIN);
    hasher.update((canonical_without_digest.len() as u64).to_be_bytes());
    hasher.update(canonical_without_digest);
    Ok(BranchExactBackfillDatasetDigest::try_new(
        hasher.finalize().into(),
    )?)
}

fn update_row_digest<Hash: Q256BitHash>(
    hasher: &mut Sha256,
    row: &BranchExactBackfillArtifactRow<Hash>,
) {
    hasher.update(row.canonical_ref_bytes());
    hasher.update(row.mapping.pending_id().get().to_be_bytes());
    match &row.reward_proof_canonical {
        None => hasher.update([0]),
        Some(proof) => {
            hasher.update([1]);
            hasher.update((proof.len() as u64).to_be_bytes());
            hasher.update(proof);
        }
    }
}

struct ArtifactChunk<'a, Hash> {
    rows: &'a [BranchExactBackfillArtifactRow<Hash>],
    digest: BranchExactBackfillChunkDigest,
    proof_rows: u64,
}

/// Isolated target-table writer and complete target-namespace read-back
/// scanner.
///
/// `prepare` is bound to the keyspace and authority from a durable plan. There
/// is no overload accepting a dynamic table name or a bare keyspace.
pub struct ScyllaBranchExactBackfillExecutor {
    session: Arc<Session>,
    adapter: BranchExactSchemaMigrationAdapter,
    authority: AuthorityScope,
    plan_digest: super::BranchExactBackfillPlanDigest,
}

/// Observable durable-work boundaries inside one idempotent backfill chunk.
///
/// The deployment runner uses these boundaries to inject process-loss errors
/// and prove that retrying the same timestamp-bound plan is safe.  They do not
/// grant access to the underlying session or allow callers to alter a
/// mutation.  Returning an error from the observer stops before a chunk
/// receipt is issued, so the durable lifecycle cannot advance past work that
/// was not completely read back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BranchExactBackfillExecutionBoundary {
    ChunkStarted,
    MappingPairWritten { row_offset: u32 },
    RewardProofWritten { row_offset: u32 },
    PointReadbackComplete { row_offset: u32 },
}

impl ScyllaBranchExactBackfillExecutor {
    pub async fn prepare(
        session: Arc<Session>,
        plan: &BranchExactBackfillPlan,
    ) -> anyhow::Result<Self> {
        if plan.mode() != BranchExactBackfillMode::PostGenesisArtifact
            || plan.write_timestamp().is_none()
        {
            anyhow::bail!(
                "Scylla backfill executor requires a timestamp-bound post-genesis plan"
            );
        }
        let intent = plan.deployment().intent();
        let adapter =
            BranchExactSchemaMigrationAdapter::prepare_with_consistency(
                &session,
                intent.keyspace().clone(),
                intent.authority(),
                Consistency::Quorum,
            )
            .await?;
        Ok(Self {
            session,
            adapter,
            authority: intent.authority(),
            plan_digest: plan.digest(),
        })
    }

    pub async fn execute_chunk<Hash: Q256BitHash>(
        &self,
        plan: &BranchExactBackfillPlan,
        artifact: &BranchExactBackfillArtifact<Hash>,
        chunk_index: u32,
    ) -> anyhow::Result<BranchExactBackfillChunkReceipt> {
        self.execute_chunk_observed(
            plan,
            artifact,
            chunk_index,
            |_| Ok(()),
        )
        .await
    }

    /// Executes the same production-shaped path as [`Self::execute_chunk`]
    /// while reporting immutable crash-test boundaries.
    ///
    /// This remains a prototype/deployment-tooling API.  The observer cannot
    /// change the sealed plan, timestamp, branch identity, payload, or query.
    pub async fn execute_chunk_observed<Hash, Observe>(
        &self,
        plan: &BranchExactBackfillPlan,
        artifact: &BranchExactBackfillArtifact<Hash>,
        chunk_index: u32,
        mut observe: Observe,
    ) -> anyhow::Result<BranchExactBackfillChunkReceipt>
    where
        Hash: Q256BitHash,
        Observe: FnMut(BranchExactBackfillExecutionBoundary) -> anyhow::Result<()>,
    {
        self.validate_bound_plan(plan, artifact)?;
        let chunk = artifact.chunk(plan, chunk_index)?;
        observe(BranchExactBackfillExecutionBoundary::ChunkStarted)?;
        for (row_offset, row) in chunk.rows.iter().enumerate() {
            self.write_row(plan, row, row_offset as u32, &mut observe)
                .await?;
        }
        for (row_offset, row) in chunk.rows.iter().enumerate() {
            self.verify_row(plan, row).await?;
            observe(
                BranchExactBackfillExecutionBoundary::PointReadbackComplete {
                    row_offset: row_offset as u32,
                },
            )?;
        }
        Ok(BranchExactBackfillChunkReceipt::try_new(
            plan.digest(),
            chunk_index,
            chunk.rows.len() as u64,
            chunk.proof_rows,
            chunk.digest,
        )?)
    }

    pub async fn verify_artifact_readback<Hash: Q256BitHash>(
        &self,
        plan: &BranchExactBackfillPlan,
        artifact: &BranchExactBackfillArtifact<Hash>,
    ) -> anyhow::Result<BranchExactBackfillReadbackObservation> {
        self.validate_bound_plan(plan, artifact)?;
        let forward = self
            .adapter
            .scan_branch_to_pending(&self.session)
            .await?;
        let reverse = self
            .adapter
            .scan_pending_to_branch(&self.session)
            .await?;
        let proofs = if matches!(self.authority, AuthorityScope::Realm { .. }) {
            self.adapter
                .scan_pending_reward_proofs(&self.session)
                .await?
        } else {
            Vec::new()
        };
        verify_complete_target_scan(plan, artifact, forward, reverse, proofs)
    }

    fn validate_bound_plan<Hash: Q256BitHash>(
        &self,
        plan: &BranchExactBackfillPlan,
        artifact: &BranchExactBackfillArtifact<Hash>,
    ) -> anyhow::Result<()> {
        artifact.validate_plan(plan)?;
        if plan.digest() != self.plan_digest
            || plan.deployment().intent().authority() != self.authority
        {
            anyhow::bail!("backfill executor plan/authority binding mismatch");
        }
        Ok(())
    }

    async fn write_row<Hash, Observe>(
        &self,
        plan: &BranchExactBackfillPlan,
        row: &BranchExactBackfillArtifactRow<Hash>,
        row_offset: u32,
        observe: &mut Observe,
    ) -> anyhow::Result<()>
    where
        Hash: Q256BitHash,
        Observe: FnMut(BranchExactBackfillExecutionBoundary) -> anyhow::Result<()>,
    {
        let timestamp = plan
            .write_timestamp()
            .ok_or_else(|| anyhow::anyhow!("durable plan omitted write timestamp"))?;
        let pair = BranchPendingPairPutPlan::new(*row.mapping(), timestamp);
        self.adapter.put_pair(&self.session, &pair).await?;
        observe(
            BranchExactBackfillExecutionBoundary::MappingPairWritten {
                row_offset,
            },
        )?;
        if let Some(proof) = row.decode_reward_proof()? {
            let proof_plan = PendingRewardProofPutPlan::try_new(
                row.mapping().pending_id(),
                &proof,
                timestamp,
            )?;
            self.adapter
                .put_pending_reward_proof(&self.session, &proof_plan)
                .await?;
            observe(
                BranchExactBackfillExecutionBoundary::RewardProofWritten {
                    row_offset,
                },
            )?;
        }
        Ok(())
    }

    async fn verify_row<Hash: Q256BitHash>(
        &self,
        plan: &BranchExactBackfillPlan,
        row: &BranchExactBackfillArtifactRow<Hash>,
    ) -> anyhow::Result<()> {
        let pair = BranchPendingPairPutPlan::new(
            *row.mapping(),
            plan.write_timestamp()
                .ok_or_else(|| anyhow::anyhow!("durable plan omitted write timestamp"))?,
        );
        self.adapter.verify_pair(&self.session, &pair).await?;
        if matches!(self.authority, AuthorityScope::Realm { .. }) {
            let observed = self
                .adapter
                .read_pending_reward_proof::<Hash>(
                    &self.session,
                    row.mapping().pending_id(),
                )
                .await?
                .map(|proof| proof.psy_ser_to_bytes_vec())
                .transpose()?;
            if observed.as_deref() != row.reward_proof_canonical() {
                anyhow::bail!(
                    "pending reward proof read-back mismatch for pending {}",
                    row.mapping().pending_id().get()
                );
            }
        }
        Ok(())
    }
}

fn verify_complete_target_scan<Hash: Q256BitHash>(
    plan: &BranchExactBackfillPlan,
    artifact: &BranchExactBackfillArtifact<Hash>,
    forward_rows: Vec<(Vec<u8>, i64, Vec<u8>)>,
    reverse_rows: Vec<(i64, Vec<u8>, Vec<u8>)>,
    proof_rows: Vec<(i64, Vec<u8>)>,
) -> anyhow::Result<BranchExactBackfillReadbackObservation> {
    artifact.validate_plan(plan)?;

    let expected_forward = artifact
        .rows()
        .iter()
        .map(|row| {
            (
                row.mapping().canonical_chain_bytes().to_vec(),
                row.mapping().pending_id().get(),
            )
        })
        .collect::<BTreeSet<_>>();
    let expected_reverse = expected_forward
        .iter()
        .map(|(canonical, pending)| (*pending, canonical.clone()))
        .collect::<BTreeSet<_>>();
    let expected_proofs = artifact
        .rows()
        .iter()
        .filter_map(|row| {
            row.reward_proof_canonical().map(|proof| {
                (row.mapping().pending_id().get(), proof.to_vec())
            })
        })
        .collect::<BTreeSet<_>>();

    let mut observed_forward = BTreeSet::new();
    for (canonical, pending, mapping_digest) in forward_rows {
        let pending_id = pending_from_cql(pending)?;
        let mapping = BranchPendingMapping::<Hash>::from_canonical_chain_bytes(
            &canonical,
            pending_id,
        )
        .map_err(|error| {
            anyhow::anyhow!("malformed forward canonical ref: {error}")
        })?;
        if mapping_digest.as_slice() != mapping.digest().as_bytes() {
            anyhow::bail!("forward mapping digest mismatch in target scan");
        }
        if !observed_forward.insert((canonical, pending_id.get())) {
            anyhow::bail!("duplicate forward row in target scan");
        }
    }

    let mut observed_reverse = BTreeSet::new();
    for (pending, canonical, mapping_digest) in reverse_rows {
        let pending_id = pending_from_cql(pending)?;
        let mapping = BranchPendingMapping::<Hash>::from_canonical_chain_bytes(
            &canonical,
            pending_id,
        )
        .map_err(|error| {
            anyhow::anyhow!("malformed reverse canonical ref: {error}")
        })?;
        if mapping_digest.as_slice() != mapping.digest().as_bytes() {
            anyhow::bail!("reverse mapping digest mismatch in target scan");
        }
        if !observed_reverse.insert((pending_id.get(), canonical)) {
            anyhow::bail!("duplicate reverse row in target scan");
        }
    }

    let mut observed_proofs = BTreeSet::new();
    for (pending, stored_value) in proof_rows {
        let pending_id = pending_from_cql(pending)?;
        let proof = TagTreeMerkleProof::<Hash>::psy_ser_from_owned_bytes_vec(
            crate::compression::decompress(&stored_value)?,
        )?;
        let canonical = proof.psy_ser_to_bytes_vec()?;
        if !observed_proofs.insert((pending_id.get(), canonical)) {
            anyhow::bail!("duplicate pending reward proof in target scan");
        }
    }

    require_exact_scan_set("forward mapping", &expected_forward, &observed_forward)?;
    require_exact_scan_set("reverse mapping", &expected_reverse, &observed_reverse)?;
    require_exact_scan_set("reward proof", &expected_proofs, &observed_proofs)?;

    Ok(BranchExactBackfillReadbackObservation::new(
        plan.digest(),
        artifact.dataset_digest(),
        observed_forward.len() as u64,
        observed_reverse.len() as u64,
        observed_proofs.len() as u64,
    ))
}

fn pending_from_cql(value: i64) -> anyhow::Result<UniquePendingId> {
    let value = u64::try_from(value)
        .map_err(|_| anyhow::anyhow!("negative pending id in target scan"))?;
    Ok(UniquePendingId::try_new(value)?)
}

fn require_exact_scan_set<T: Ord>(
    label: &str,
    expected: &BTreeSet<T>,
    observed: &BTreeSet<T>,
) -> anyhow::Result<()> {
    if expected != observed {
        anyhow::bail!(
            "{label} target scan mismatch: expected {} rows, observed {}; missing {}, unexpected {}",
            expected.len(),
            observed.len(),
            expected.difference(observed).count(),
            observed.difference(expected).count(),
        );
    }
    Ok(())
}

struct ArtifactDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ArtifactDecoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(
        &mut self,
        length: usize,
    ) -> Result<&'a [u8], BranchExactBackfillArtifactError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(BranchExactBackfillArtifactError::TruncatedPayload)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(BranchExactBackfillArtifactError::TruncatedPayload)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, BranchExactBackfillArtifactError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, BranchExactBackfillArtifactError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, BranchExactBackfillArtifactError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, BranchExactBackfillArtifactError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn array32(&mut self) -> Result<[u8; 32], BranchExactBackfillArtifactError> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    fn authority(
        &mut self,
    ) -> Result<AuthorityScope, BranchExactBackfillArtifactError> {
        let bytes = self.take(7)?;
        match bytes[0] {
            1 if bytes[1..].iter().all(|byte| *byte == 0) => {
                Ok(AuthorityScope::Coordinator)
            }
            1 => Err(
                BranchExactBackfillArtifactError::NonCanonicalCoordinator,
            ),
            2 => Ok(AuthorityScope::Realm {
                realm_id: u32::from_be_bytes(bytes[1..5].try_into().unwrap()),
                realm_sub_id: u16::from_be_bytes(
                    bytes[5..7].try_into().unwrap(),
                ),
            }),
            value => Err(BranchExactBackfillArtifactError::UnknownAuthority(
                value,
            )),
        }
    }

    fn finish(self) -> Result<(), BranchExactBackfillArtifactError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(BranchExactBackfillArtifactError::TrailingBytes)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactBackfillArtifactError {
    EmptyArtifact,
    TooManyRows(usize),
    RowCountOverflow,
    DuplicateCanonicalRef,
    DuplicatePendingId(u64),
    CoordinatorProofRow,
    ProofTooLarge(usize),
    ProofCodec(String),
    CanonicalRefCodec(String),
    PendingIdOutOfRange(u64),
    InvalidMagic,
    UnknownCodecVersion(u16),
    UnknownAuthority(u8),
    NonCanonicalCoordinator,
    InvalidProofPresence(u8),
    TruncatedPayload,
    TrailingBytes,
    DatasetDigestMismatch,
    DatasetDigest(super::BranchExactBackfillError),
    PlanModeMismatch,
    PlanAuthorityMismatch,
    PlanDatasetMismatch,
    PlanCountMismatch,
    MissingWriteTimestamp,
    InvalidChunkCount,
    ChunkIndexOutOfRange {
        chunk_index: u32,
        total_chunks: u32,
    },
}

impl From<psy_node_core::store::typed::UniquePendingIdOutOfRange>
    for BranchExactBackfillArtifactError
{
    fn from(
        value: psy_node_core::store::typed::UniquePendingIdOutOfRange,
    ) -> Self {
        Self::PendingIdOutOfRange(value.0)
    }
}

impl From<super::BranchExactBackfillError>
    for BranchExactBackfillArtifactError
{
    fn from(value: super::BranchExactBackfillError) -> Self {
        Self::DatasetDigest(value)
    }
}

impl fmt::Display for BranchExactBackfillArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for BranchExactBackfillArtifactError {}

#[cfg(test)]
mod tests {
    use parth_core::PHash;
    use psy_data::protocol::canonical_chain::{
        CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
        CheckpointRef, NetworkId,
    };
    use psy_node_core::store::{
        branch_exact_schema::{
            BaselineSnapshotArtifactDigest,
            BranchExactPostGenesisFloorEvidence,
            BranchExactSchemaMaterializationPlan,
        },
        canonical_head::{
            CanonicalHeadBootstrap, CanonicalHeadBootstrapProfile,
        },
        manifest_record::AuthorityManifestDigest,
        timestamp::CommitWriteTimestampUs,
    };

    use super::*;
    use crate::rollback::{
        branch_exact_schema_fingerprint, BranchExactDeploymentIntent,
        BranchExactExpectedTopology, BranchExactNodeSchemaPostflight,
        BranchExactSchemaInspection, BranchExactSchemaMaterializationRequest,
        BranchExactSchemaOnlyReceipt, BranchExactScyllaNodeId,
        BranchExactScyllaSchemaVersion, BranchExactTopologyAttestation,
        BranchExactVerifiedDeploymentReceipt, CqlKeyspaceName,
    };

    fn authority() -> AuthorityScope {
        AuthorityScope::Realm {
            realm_id: 7,
            realm_sub_id: 2,
        }
    }

    fn mapping(
        epoch: u64,
        height: u64,
        pending: u64,
        byte: u8,
    ) -> BranchPendingMapping<PHash> {
        BranchPendingMapping::new(
            CanonicalChainRef::new(
                NetworkId::try_from_chain_id(1337).unwrap(),
                ChainEpoch::new(epoch),
                CheckpointRef::new(
                    CheckpointId::new(height),
                    CheckpointHash::from_last_chain_hash(
                        PHash::from_owned_32bytes([byte; 32]),
                    ),
                ),
            ),
            UniquePendingId::try_new(pending).unwrap(),
        )
    }

    fn row(
        epoch: u64,
        height: u64,
        pending: u64,
        byte: u8,
    ) -> BranchExactBackfillArtifactRow<PHash> {
        BranchExactBackfillArtifactRow::try_new(
            mapping(epoch, height, pending, byte),
            None,
        )
        .unwrap()
    }

    fn request(
        keyspace: &str,
        authority: AuthorityScope,
    ) -> BranchExactSchemaMaterializationRequest {
        let bootstrap = CanonicalHeadBootstrap::try_new(
            CanonicalHeadBootstrapProfile::PostGenesisFloor,
            CanonicalChainRef::new(
                NetworkId::try_from_chain_id(1337).unwrap(),
                ChainEpoch::new(0),
                CheckpointRef::new(
                    CheckpointId::new(100),
                    CheckpointHash::from_last_chain_hash(
                        PHash::from_owned_32bytes([9; 32]),
                    ),
                ),
            ),
        )
        .unwrap();
        let floor = BranchExactPostGenesisFloorEvidence::new(
            authority,
            BaselineSnapshotArtifactDigest::try_new([7; 32]).unwrap(),
            AuthorityManifestDigest::from_persisted([8; 32]),
        );
        let plan = BranchExactSchemaMaterializationPlan::try_new(
            &bootstrap,
            authority,
            Some(floor),
        )
        .unwrap();
        BranchExactSchemaMaterializationRequest::try_new(
            CqlKeyspaceName::try_new(keyspace).unwrap(),
            plan,
        )
        .unwrap()
    }

    fn topology() -> BranchExactExpectedTopology {
        BranchExactExpectedTopology::try_new(
            [1_u8, 2, 3]
                .map(|byte| {
                    BranchExactScyllaNodeId::try_new([byte; 16]).unwrap()
                })
                .to_vec(),
        )
        .unwrap()
    }

    fn verified(
        request: &BranchExactSchemaMaterializationRequest,
    ) -> BranchExactVerifiedDeploymentReceipt {
        let fingerprint =
            branch_exact_schema_fingerprint(request.plan().authority());
        let schema = BranchExactSchemaOnlyReceipt::from_verified_parts_for_deployment(
            request,
            fingerprint,
        );
        let topology = topology();
        let observations = topology
            .nodes()
            .iter()
            .copied()
            .map(|node| {
                BranchExactNodeSchemaPostflight::try_new(
                    node,
                    BranchExactScyllaSchemaVersion::try_new([9; 16]).unwrap(),
                    BranchExactSchemaInspection::Exact { fingerprint },
                )
                .unwrap()
            })
            .collect();
        let attestation = BranchExactTopologyAttestation::try_new(
            &schema,
            topology.clone(),
            observations,
        )
        .unwrap();
        BranchExactVerifiedDeploymentReceipt::try_new(
            BranchExactDeploymentIntent::new(request, topology),
            attestation,
        )
        .unwrap()
    }

    fn artifact_with_proof() -> BranchExactBackfillArtifact<PHash> {
        let proof = TagTreeMerkleProof::<PHash>::new_empty();
        BranchExactBackfillArtifact::try_new(
            authority(),
            vec![
                row(0, 1, 11, 1),
                BranchExactBackfillArtifactRow::try_new(
                    mapping(0, 2, 12, 2),
                    Some(&proof),
                )
                .unwrap(),
                row(0, 3, 13, 3),
            ],
        )
        .unwrap()
    }

    fn backfill_plan(
        artifact: &BranchExactBackfillArtifact<PHash>,
        total_chunks: u32,
    ) -> BranchExactBackfillPlan {
        let request = request("psy_h17_realm", authority());
        BranchExactBackfillPlan::post_genesis_artifact(
            &request,
            verified(&request),
            artifact.dataset_digest(),
            CommitWriteTimestampUs::try_from_i128(
                1_700_000_000_000_000_i128,
            )
            .unwrap(),
            total_chunks,
            artifact.pair_rows_per_direction(),
            artifact.proof_rows(),
        )
        .unwrap()
    }

    type ScanRows = (
        Vec<(Vec<u8>, i64, Vec<u8>)>,
        Vec<(i64, Vec<u8>, Vec<u8>)>,
        Vec<(i64, Vec<u8>)>,
    );

    fn exact_scan_rows(
        artifact: &BranchExactBackfillArtifact<PHash>,
    ) -> ScanRows {
        let forward = artifact
            .rows()
            .iter()
            .map(|row| {
                (
                    row.mapping().canonical_chain_bytes().to_vec(),
                    row.mapping().pending_id().get() as i64,
                    row.mapping().digest().as_bytes().to_vec(),
                )
            })
            .collect();
        let reverse = artifact
            .rows()
            .iter()
            .map(|row| {
                (
                    row.mapping().pending_id().get() as i64,
                    row.mapping().canonical_chain_bytes().to_vec(),
                    row.mapping().digest().as_bytes().to_vec(),
                )
            })
            .collect();
        let proofs = artifact
            .rows()
            .iter()
            .filter_map(|row| {
                row.reward_proof_canonical().map(|proof| {
                    (
                        row.mapping().pending_id().get() as i64,
                        crate::compression::compress(proof).unwrap(),
                    )
                })
            })
            .collect();
        (forward, reverse, proofs)
    }

    #[test]
    fn artifact_sort_codec_and_digest_are_deterministic() {
        let artifact = artifact_with_proof();
        assert_eq!(artifact.rows()[0].mapping().pending_id().get(), 11);
        assert_eq!(artifact.proof_rows(), 1);
        let decoded = BranchExactBackfillArtifact::<PHash>::decode_persisted(
            artifact.to_canonical_bytes(),
        )
        .unwrap();
        assert_eq!(decoded, artifact);
        assert_eq!(decoded.dataset_digest(), artifact.dataset_digest());
    }

    #[test]
    fn one_to_one_mapping_and_authority_fail_closed() {
        let duplicate_pending = BranchExactBackfillArtifact::try_new(
            authority(),
            vec![row(0, 1, 11, 1), row(0, 2, 11, 2)],
        );
        assert_eq!(
            duplicate_pending,
            Err(BranchExactBackfillArtifactError::DuplicatePendingId(11))
        );
        let same = row(0, 1, 11, 1);
        assert_eq!(
            BranchExactBackfillArtifact::try_new(
                authority(),
                vec![same.clone(), same],
            ),
            Err(BranchExactBackfillArtifactError::DuplicateCanonicalRef)
        );

        let proof = TagTreeMerkleProof::<PHash>::new_empty();
        let proof_row = BranchExactBackfillArtifactRow::try_new(
            mapping(0, 1, 11, 1),
            Some(&proof),
        )
        .unwrap();
        assert_eq!(
            BranchExactBackfillArtifact::try_new(
                AuthorityScope::Coordinator,
                vec![proof_row],
            ),
            Err(BranchExactBackfillArtifactError::CoordinatorProofRow)
        );
    }

    #[test]
    fn malformed_artifact_never_rehydrates() {
        let artifact = BranchExactBackfillArtifact::try_new(
            authority(),
            vec![row(0, 1, 11, 1)],
        )
        .unwrap();
        let mut tampered = artifact.to_canonical_bytes().to_vec();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(
            BranchExactBackfillArtifact::<PHash>::decode_persisted(&tampered),
            Err(BranchExactBackfillArtifactError::DatasetDigestMismatch)
        );
        let mut trailing = artifact.to_canonical_bytes().to_vec();
        trailing.push(0);
        assert_eq!(
            BranchExactBackfillArtifact::<PHash>::decode_persisted(&trailing),
            Err(BranchExactBackfillArtifactError::TrailingBytes)
        );
    }

    #[test]
    fn durable_plan_binds_artifact_timestamp_and_exact_counts() {
        let artifact = artifact_with_proof();
        let plan = backfill_plan(&artifact, 2);
        artifact.validate_plan(&plan).unwrap();
        assert_eq!(plan.dataset_digest(), artifact.dataset_digest());
        assert_eq!(plan.pair_rows_per_direction(), 3);
        assert_eq!(plan.proof_rows(), 1);
        assert_eq!(plan.total_chunks(), 2);
        assert_eq!(
            plan.write_timestamp().unwrap().as_i64(),
            1_700_000_000_000_000
        );

        let other = BranchExactBackfillArtifact::try_new(
            authority(),
            vec![row(0, 9, 19, 9)],
        )
        .unwrap();
        assert_eq!(
            other.validate_plan(&plan),
            Err(BranchExactBackfillArtifactError::PlanDatasetMismatch)
        );
    }

    #[test]
    fn chunk_partition_and_digest_are_deterministic() {
        let artifact = artifact_with_proof();
        let plan = backfill_plan(&artifact, 2);
        let first = artifact.chunk(&plan, 0).unwrap();
        let retry = artifact.chunk(&plan, 0).unwrap();
        let second = artifact.chunk(&plan, 1).unwrap();
        assert_eq!(first.rows.len(), 2);
        assert_eq!(second.rows.len(), 1);
        assert_eq!(first.proof_rows + second.proof_rows, 1);
        assert_eq!(first.digest, retry.digest);
        assert_ne!(first.digest, second.digest);
        assert_eq!(
            artifact.chunk(&plan, 2).map(|_| ()),
            Err(BranchExactBackfillArtifactError::ChunkIndexOutOfRange {
                chunk_index: 2,
                total_chunks: 2,
            })
        );
    }

    #[test]
    fn chunk_count_cannot_create_empty_or_ambiguous_work() {
        let artifact = artifact_with_proof();
        let request = request("psy_h17_bad_chunks", authority());
        assert_eq!(
            BranchExactBackfillPlan::post_genesis_artifact(
                &request,
                verified(&request),
                artifact.dataset_digest(),
                CommitWriteTimestampUs::try_from_i128(10).unwrap(),
                4,
                artifact.pair_rows_per_direction(),
                artifact.proof_rows(),
            ),
            Err(super::super::BranchExactBackfillError::TooManyChunksForRows)
        );
    }

    #[test]
    fn complete_scan_requires_exact_forward_reverse_and_proof_sets() {
        let artifact = artifact_with_proof();
        let plan = backfill_plan(&artifact, 2);
        let (forward, reverse, proofs) = exact_scan_rows(&artifact);
        assert_eq!(
            verify_complete_target_scan(
                &plan,
                &artifact,
                forward.clone(),
                reverse.clone(),
                proofs.clone(),
            )
            .unwrap(),
            BranchExactBackfillReadbackObservation::new(
                plan.digest(),
                artifact.dataset_digest(),
                3,
                3,
                1,
            )
        );

        let mut unexpected_forward = forward.clone();
        unexpected_forward.push((
            mapping(9, 99, 999, 9).canonical_chain_bytes().to_vec(),
            999,
            mapping(9, 99, 999, 9).digest().as_bytes().to_vec(),
        ));
        assert!(verify_complete_target_scan(
            &plan,
            &artifact,
            unexpected_forward,
            reverse.clone(),
            proofs.clone(),
        )
        .unwrap_err()
        .to_string()
        .contains("unexpected 1"));

        assert!(verify_complete_target_scan(
            &plan,
            &artifact,
            forward.clone(),
            reverse[1..].to_vec(),
            proofs.clone(),
        )
        .unwrap_err()
        .to_string()
        .contains("missing 1"));

        let mut unexpected_proof = proofs;
        unexpected_proof.push((
            999,
            crate::compression::compress(
                &TagTreeMerkleProof::<PHash>::new_empty()
                    .psy_ser_to_bytes_vec()
                    .unwrap(),
            )
            .unwrap(),
        ));
        assert!(verify_complete_target_scan(
            &plan,
            &artifact,
            forward,
            reverse,
            unexpected_proof,
        )
        .unwrap_err()
        .to_string()
        .contains("unexpected 1"));
    }

    #[test]
    fn complete_scan_rejects_malformed_identity_and_pending_domain() {
        let artifact = artifact_with_proof();
        let plan = backfill_plan(&artifact, 2);
        let (mut forward, reverse, proofs) = exact_scan_rows(&artifact);
        forward[0].0 = vec![0; BRANCH_PENDING_CANONICAL_REF_LEN];
        assert!(verify_complete_target_scan(
            &plan,
            &artifact,
            forward,
            reverse.clone(),
            proofs.clone(),
        )
        .unwrap_err()
        .to_string()
        .contains("malformed forward"));

        let (forward, mut reverse, _) = exact_scan_rows(&artifact);
        reverse[0].0 = -1;
        assert!(verify_complete_target_scan(
            &plan, &artifact, forward, reverse, proofs,
        )
        .unwrap_err()
        .to_string()
        .contains("negative pending"));
    }

    #[test]
    fn executor_remains_absent_from_production_setup() {
        let setup = include_str!("../psy_setup.rs");
        assert!(!setup.contains("ScyllaBranchExactBackfillExecutor"));
        assert!(!setup.contains("BranchExactBackfillArtifact"));
    }
}
