//! Fail-closed legacy-serving shadow reads for the branch-exact schema.
//!
//! The old height/pending tables remain the serving authority in h21.  A
//! successful call proves that the legacy result, both branch-exact mapping
//! directions and (for Realm) the exact reward proof agree with one sealed
//! h17 artifact row.  A mismatch is an error; there is no silent fallback.
//! The adapter is opened only from the opaque h20 setup capability and is not
//! installed by `psy_setup.rs` or any Processor/Edge path.

use std::{collections::BTreeSet, error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_node_core::store::{
    branch_exact_schema::AuthorityScope,
    branch_pending_mapping::BranchPendingMapping,
    typed::UniquePendingId,
};
use scylla::{
    client::session::Session,
    statement::{prepared::PreparedStatement, Consistency},
};
use sha2::{Digest, Sha256};

use crate::utils::{i64_to_u64_exact, u64_to_i64_exact};

use super::{
    BranchExactBackfillArtifact, BranchExactBackfillArtifactRow,
    BranchExactBackfillDatasetDigest, BranchExactBackfillVerifiedReceipt,
    BranchExactSchemaReady, BranchExactSchemaReadyDigest,
    BranchExactSchemaReadyView,
    BranchExactQueries, BranchExactQueryId,
};

const LEGACY_FORWARD_TABLE: &str = "checkpoint_id_to_pending_id_table";
const LEGACY_REVERSE_TABLE: &str = "pending_id_to_checkpoint_id_table";
const LEGACY_CHECKPOINTED_OBJECT_TABLE: &str = "checkpointed_object_table";
const REALM_REWARD_PROOF_OBJ_ID: i64 = 2;
const SHADOW_COMPARISON_DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/branch-exact-shadow-comparison/v1";
const SHADOW_AUDIT_DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/branch-exact-shadow-audit/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BranchExactShadowComparisonDigest([u8; 32]);

impl BranchExactShadowComparisonDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BranchExactShadowAuditDigest([u8; 32]);

impl BranchExactShadowAuditDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) const fn from_persisted(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Value returned to the caller after exact comparison.  `served_pending_id`
/// is deliberately the legacy observation, not the target observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BranchExactLegacyServedMapping {
    served_pending_id: UniquePendingId,
    comparison_digest: BranchExactShadowComparisonDigest,
}

impl BranchExactLegacyServedMapping {
    pub const fn served_pending_id(self) -> UniquePendingId {
        self.served_pending_id
    }

    pub const fn comparison_digest(self) -> BranchExactShadowComparisonDigest {
        self.comparison_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactLegacyServedProof {
    canonical_proof: Vec<u8>,
    comparison_digest: BranchExactShadowComparisonDigest,
}

impl BranchExactLegacyServedProof {
    pub fn canonical_proof(&self) -> &[u8] {
        &self.canonical_proof
    }

    pub const fn comparison_digest(&self) -> BranchExactShadowComparisonDigest {
        self.comparison_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactShadowAuditObservation {
    schema_ready_digest: BranchExactSchemaReadyDigest,
    dataset_digest: BranchExactBackfillDatasetDigest,
    mapping_rows: u64,
    proof_rows: u64,
    digest: BranchExactShadowAuditDigest,
}

impl BranchExactShadowAuditObservation {
    pub const fn schema_ready_digest(&self) -> BranchExactSchemaReadyDigest {
        self.schema_ready_digest
    }

    pub const fn dataset_digest(&self) -> BranchExactBackfillDatasetDigest {
        self.dataset_digest
    }

    pub const fn mapping_rows(&self) -> u64 {
        self.mapping_rows
    }

    pub const fn proof_rows(&self) -> u64 {
        self.proof_rows
    }

    pub const fn digest(&self) -> BranchExactShadowAuditDigest {
        self.digest
    }

    #[cfg(test)]
    pub(crate) fn test_fixture(
        schema_ready_digest: BranchExactSchemaReadyDigest,
        dataset_digest: BranchExactBackfillDatasetDigest,
        mapping_rows: u64,
        proof_rows: u64,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(SHADOW_AUDIT_DIGEST_DOMAIN);
        hasher.update(schema_ready_digest.as_bytes());
        hasher.update(dataset_digest.as_bytes());
        hasher.update(mapping_rows.to_be_bytes());
        hasher.update(proof_rows.to_be_bytes());
        Self {
            schema_ready_digest,
            dataset_digest,
            mapping_rows,
            proof_rows,
            digest: BranchExactShadowAuditDigest(hasher.finalize().into()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BranchExactShadowDirection {
    LegacyForward,
    LegacyReverse,
    TargetForward,
    TargetReverse,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactShadowReadError {
    AuthorityMismatch,
    DatasetMismatch,
    BackfillPlanMismatch,
    CoordinatorProofRequest,
    TargetProofUnavailable,
    MissingMapping(BranchExactShadowDirection),
    ConflictingMapping {
        direction: BranchExactShadowDirection,
        expected: String,
        actual: String,
    },
    TargetCardinality {
        direction: BranchExactShadowDirection,
        actual: usize,
    },
    TargetMappingProvenanceMismatch(BranchExactShadowDirection),
    MissingLegacyProof(u64),
    MissingTargetProof(u64),
    LegacyReadThrough {
        requested_pending_id: u64,
        returned_pending_id: u64,
    },
    ProofMismatch {
        pending_id: u64,
    },
    MalformedTargetCanonicalRef(String),
    MalformedLegacyValue(i64),
    Driver(String),
    Codec(String),
    RowCountOverflow,
}

impl fmt::Display for BranchExactShadowReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for BranchExactShadowReadError {}

#[derive(Clone)]
struct PreparedShadowReads {
    target_forward: PreparedStatement,
    target_reverse: PreparedStatement,
    target_proof: Option<PreparedStatement>,
    target_forward_scan: PreparedStatement,
    target_reverse_scan: PreparedStatement,
    target_proof_scan: Option<PreparedStatement>,
    legacy_forward: PreparedStatement,
    legacy_reverse: PreparedStatement,
    legacy_serving_proof: Option<PreparedStatement>,
    legacy_forward_scan: PreparedStatement,
    legacy_reverse_scan: PreparedStatement,
    legacy_proof_scan: Option<PreparedStatement>,
}

/// Production-shaped but not production-installed h21 adapter.
pub struct ScyllaBranchExactShadowReader<Hash> {
    session: Arc<Session>,
    authority: AuthorityScope,
    setup_view: BranchExactSchemaReadyView,
    expected_receipt: BranchExactBackfillVerifiedReceipt,
    prepared: PreparedShadowReads,
    _hash: std::marker::PhantomData<Hash>,
}

impl<Hash: Q256BitHash> ScyllaBranchExactShadowReader<Hash> {
    pub(crate) async fn prepare_from_ready(
        session: Arc<Session>,
        legacy_keyspace: &str,
        ready: &BranchExactSchemaReady,
    ) -> Result<Self, BranchExactShadowReadError> {
        let authority = ready.view().authority();
        let (target_forward, target_reverse, target_proof) =
            ready.prepared_reads();
        let queries = BranchExactQueries::new(ready.view().keyspace());
        let target_forward_scan = prepare_read(
            &session,
            queries
                .get(BranchExactQueryId::ScanBranchToPending)
                .cql()
                .to_owned(),
        )
        .await?;
        let target_reverse_scan = prepare_read(
            &session,
            queries
                .get(BranchExactQueryId::ScanPendingToBranch)
                .cql()
                .to_owned(),
        )
        .await?;
        let target_proof_scan = match authority {
            AuthorityScope::Coordinator => None,
            AuthorityScope::Realm { .. } => Some(
                prepare_read(
                    &session,
                    queries
                        .get(BranchExactQueryId::ScanPendingRewardProof)
                        .cql()
                        .to_owned(),
                )
                .await?,
            ),
        };
        let legacy_forward = prepare_read(
            &session,
            format!(
                "SELECT value FROM {legacy_keyspace}.{LEGACY_FORWARD_TABLE} WHERE obj_id = ?"
            ),
        )
        .await?;
        let legacy_reverse = prepare_read(
            &session,
            format!(
                "SELECT value FROM {legacy_keyspace}.{LEGACY_REVERSE_TABLE} WHERE obj_id = ?"
            ),
        )
        .await?;
        let legacy_serving_proof = match authority {
            AuthorityScope::Coordinator => None,
            AuthorityScope::Realm { .. } => Some(
                prepare_read(
                    &session,
                    format!(
                        "SELECT checkpoint_id, value FROM {legacy_keyspace}.{LEGACY_CHECKPOINTED_OBJECT_TABLE} WHERE obj_id = ? AND checkpoint_id <= ? ORDER BY checkpoint_id DESC LIMIT 1"
                    ),
                )
                .await?,
            ),
        };
        let legacy_forward_scan = prepare_read(
            &session,
            format!(
                "SELECT obj_id, value FROM {legacy_keyspace}.{LEGACY_FORWARD_TABLE}"
            ),
        )
        .await?;
        let legacy_reverse_scan = prepare_read(
            &session,
            format!(
                "SELECT obj_id, value FROM {legacy_keyspace}.{LEGACY_REVERSE_TABLE}"
            ),
        )
        .await?;
        let legacy_proof_scan = match authority {
            AuthorityScope::Coordinator => None,
            AuthorityScope::Realm { .. } => Some(
                prepare_read(
                    &session,
                    format!(
                        "SELECT checkpoint_id, value FROM {legacy_keyspace}.{LEGACY_CHECKPOINTED_OBJECT_TABLE} WHERE obj_id = ?"
                    ),
                )
                .await?,
            ),
        };
        Ok(Self {
            session,
            authority,
            setup_view: ready.view().clone(),
            expected_receipt: ready.expected_receipt().clone(),
            prepared: PreparedShadowReads {
                target_forward: target_forward.clone(),
                target_reverse: target_reverse.clone(),
                target_proof: target_proof.cloned(),
                target_forward_scan,
                target_reverse_scan,
                target_proof_scan,
                legacy_forward,
                legacy_reverse,
                legacy_serving_proof,
                legacy_forward_scan,
                legacy_reverse_scan,
                legacy_proof_scan,
            },
            _hash: std::marker::PhantomData,
        })
    }

    pub const fn setup_view(&self) -> &BranchExactSchemaReadyView {
        &self.setup_view
    }

    pub const fn authority(&self) -> AuthorityScope {
        self.authority
    }

    /// Compare both mapping directions and return the old-path result only on
    /// exact agreement.  The expected full branch identity comes from the
    /// sealed artifact; it is never reconstructed from a bare height.
    pub async fn compare_and_serve_mapping(
        &self,
        expected: &BranchPendingMapping<Hash>,
    ) -> Result<BranchExactLegacyServedMapping, BranchExactShadowReadError> {
        let checkpoint_id = expected
            .canonical_chain()
            .checkpoint()
            .checkpoint_id()
            .get();
        let pending_id = expected.pending_id();

        let legacy_forward = self
            .read_legacy_u64(&self.prepared.legacy_forward, checkpoint_id)
            .await?
            .ok_or(BranchExactShadowReadError::MissingMapping(
                BranchExactShadowDirection::LegacyForward,
            ))?;
        if legacy_forward != pending_id.get() {
            return Err(BranchExactShadowReadError::ConflictingMapping {
                direction: BranchExactShadowDirection::LegacyForward,
                expected: pending_id.get().to_string(),
                actual: legacy_forward.to_string(),
            });
        }

        let target_forward = self.read_target_forward(expected).await?;
        if target_forward != pending_id {
            return Err(BranchExactShadowReadError::ConflictingMapping {
                direction: BranchExactShadowDirection::TargetForward,
                expected: pending_id.get().to_string(),
                actual: target_forward.get().to_string(),
            });
        }

        let legacy_reverse = self
            .read_legacy_u64(&self.prepared.legacy_reverse, pending_id.get())
            .await?
            .ok_or(BranchExactShadowReadError::MissingMapping(
                BranchExactShadowDirection::LegacyReverse,
            ))?;
        if legacy_reverse != checkpoint_id {
            return Err(BranchExactShadowReadError::ConflictingMapping {
                direction: BranchExactShadowDirection::LegacyReverse,
                expected: checkpoint_id.to_string(),
                actual: legacy_reverse.to_string(),
            });
        }

        let target_reverse = self.read_target_reverse(expected).await?;
        if &target_reverse != expected {
            return Err(BranchExactShadowReadError::ConflictingMapping {
                direction: BranchExactShadowDirection::TargetReverse,
                expected: hex::encode(expected.canonical_chain_bytes()),
                actual: hex::encode(target_reverse.canonical_chain_bytes()),
            });
        }

        let digest = comparison_digest(
            b"mapping",
            expected,
            &pending_id.get().to_be_bytes(),
        );
        Ok(BranchExactLegacyServedMapping {
            served_pending_id: UniquePendingId::try_new(legacy_forward)
                .map_err(|error| BranchExactShadowReadError::Codec(error.to_string()))?,
            comparison_digest: digest,
        })
    }

    pub async fn compare_and_serve_reward_proof(
        &self,
        expected: &BranchExactBackfillArtifactRow<Hash>,
    ) -> Result<BranchExactLegacyServedProof, BranchExactShadowReadError> {
        if matches!(self.authority, AuthorityScope::Coordinator) {
            return Err(BranchExactShadowReadError::CoordinatorProofRequest);
        }
        let expected_proof = expected.reward_proof_canonical().ok_or(
            BranchExactShadowReadError::MissingLegacyProof(
                expected.mapping().pending_id().get(),
            ),
        )?;
        let pending_id = expected.mapping().pending_id();
        let legacy = self.read_legacy_serving_proof(pending_id).await?.ok_or(
            BranchExactShadowReadError::MissingLegacyProof(pending_id.get()),
        )?;
        let target = self.read_target_proof(pending_id).await?.ok_or(
            BranchExactShadowReadError::MissingTargetProof(pending_id.get()),
        )?;
        if legacy.as_slice() != expected_proof || target.as_slice() != expected_proof
        {
            return Err(BranchExactShadowReadError::ProofMismatch {
                pending_id: pending_id.get(),
            });
        }
        Ok(BranchExactLegacyServedProof {
            canonical_proof: legacy,
            comparison_digest: comparison_digest(
                b"proof",
                expected.mapping(),
                expected_proof,
            ),
        })
    }

    /// Full point-by-point baseline audit.  Exact target-set completeness is
    /// already bound by the h17 receipt retained in the h20 capability; this
    /// method adds fresh old/new equivalence reads for every artifact row.
    pub async fn audit_artifact(
        &self,
        artifact: &BranchExactBackfillArtifact<Hash>,
    ) -> Result<BranchExactShadowAuditObservation, BranchExactShadowReadError> {
        if artifact.authority() != self.authority {
            return Err(BranchExactShadowReadError::AuthorityMismatch);
        }
        if artifact.dataset_digest() != self.setup_view.dataset_digest() {
            return Err(BranchExactShadowReadError::DatasetMismatch);
        }
        artifact
            .validate_plan(self.expected_receipt.plan())
            .map_err(|_| BranchExactShadowReadError::BackfillPlanMismatch)?;
        // The target and legacy inventories are both checked as exact sets.
        // Legacy is checked again after all point reads so an authority that
        // violates the required stopped/drained contract fails closed.
        self.verify_complete_target_set(artifact).await?;
        self.verify_complete_legacy_set(artifact).await?;

        let mut proof_rows = 0_u64;
        let mut aggregate = Sha256::new();
        aggregate.update(SHADOW_AUDIT_DIGEST_DOMAIN);
        aggregate.update(self.setup_view.digest().as_bytes());
        aggregate.update(artifact.dataset_digest().as_bytes());
        for row in artifact.rows() {
            let mapping = self.compare_and_serve_mapping(row.mapping()).await?;
            aggregate.update(mapping.comparison_digest().as_bytes());
            if row.reward_proof_canonical().is_some() {
                let proof = self.compare_and_serve_reward_proof(row).await?;
                aggregate.update(proof.comparison_digest().as_bytes());
                proof_rows = proof_rows
                    .checked_add(1)
                    .ok_or(BranchExactShadowReadError::RowCountOverflow)?;
            }
        }
        let mapping_rows = u64::try_from(artifact.rows().len())
            .map_err(|_| BranchExactShadowReadError::RowCountOverflow)?;
        aggregate.update(mapping_rows.to_be_bytes());
        aggregate.update(proof_rows.to_be_bytes());
        self.verify_complete_legacy_set(artifact).await?;
        Ok(BranchExactShadowAuditObservation {
            schema_ready_digest: self.setup_view.digest(),
            dataset_digest: artifact.dataset_digest(),
            mapping_rows,
            proof_rows,
            digest: BranchExactShadowAuditDigest(aggregate.finalize().into()),
        })
    }

    async fn verify_complete_legacy_set(
        &self,
        artifact: &BranchExactBackfillArtifact<Hash>,
    ) -> Result<(), BranchExactShadowReadError> {
        use futures::TryStreamExt;

        let expected_forward = artifact
            .rows()
            .iter()
            .map(|row| {
                (
                    row.mapping()
                        .canonical_chain()
                        .checkpoint()
                        .checkpoint_id()
                        .get(),
                    row.mapping().pending_id().get(),
                )
            })
            .collect::<BTreeSet<_>>();
        let expected_reverse = expected_forward
            .iter()
            .map(|(checkpoint, pending)| (*pending, *checkpoint))
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

        let forward = self
            .session
            .execute_iter(self.prepared.legacy_forward_scan.clone(), ())
            .await
            .map_err(driver)?
            .rows_stream::<(i64, i64)>()
            .map_err(driver)?
            .try_collect::<Vec<_>>()
            .await
            .map_err(driver)?;
        let observed_forward = legacy_u64_pairs(forward)?;

        let reverse = self
            .session
            .execute_iter(self.prepared.legacy_reverse_scan.clone(), ())
            .await
            .map_err(driver)?
            .rows_stream::<(i64, i64)>()
            .map_err(driver)?
            .try_collect::<Vec<_>>()
            .await
            .map_err(driver)?;
        let observed_reverse = legacy_u64_pairs(reverse)?;

        let observed_proofs = match &self.prepared.legacy_proof_scan {
            None => BTreeSet::new(),
            Some(query) => {
                let rows = self
                    .session
                    .execute_iter(
                        query.clone(),
                        (REALM_REWARD_PROOF_OBJ_ID,),
                    )
                    .await
                    .map_err(driver)?
                    .rows_stream::<(i64, Vec<u8>)>()
                    .map_err(driver)?
                    .try_collect::<Vec<_>>()
                    .await
                    .map_err(driver)?;
                rows.into_iter()
                    .map(|(pending, stored)| {
                        let pending = u64::try_from(pending).map_err(|_| {
                            BranchExactShadowReadError::MalformedLegacyValue(pending)
                        })?;
                        let canonical = crate::compression::decompress(&stored)
                            .map_err(|error| {
                                BranchExactShadowReadError::Codec(error.to_string())
                            })?;
                        Ok((pending, canonical))
                    })
                    .collect::<Result<BTreeSet<_>, BranchExactShadowReadError>>()?
            }
        };

        require_exact_set("legacy forward", &expected_forward, &observed_forward)?;
        require_exact_set("legacy reverse", &expected_reverse, &observed_reverse)?;
        require_exact_set("legacy proof", &expected_proofs, &observed_proofs)?;
        Ok(())
    }

    async fn verify_complete_target_set(
        &self,
        artifact: &BranchExactBackfillArtifact<Hash>,
    ) -> Result<(), BranchExactShadowReadError> {
        use futures::TryStreamExt;

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

        let forward = self
            .session
            .execute_iter(self.prepared.target_forward_scan.clone(), ())
            .await
            .map_err(driver)?
            .rows_stream::<(Vec<u8>, i64, Vec<u8>)>()
            .map_err(driver)?
            .map_ok(|(canonical, pending, digest)| {
                (canonical, u64::try_from(pending).ok(), digest)
            })
            .try_collect::<Vec<_>>()
            .await
            .map_err(driver)?;
        let observed_forward = forward
            .into_iter()
            .map(|(canonical, pending, digest)| {
                let pending = pending.ok_or(
                    BranchExactShadowReadError::MalformedLegacyValue(-1),
                )?;
                let pending_id = UniquePendingId::try_new(pending)
                    .map_err(|error| BranchExactShadowReadError::Codec(error.to_string()))?;
                let mapping = BranchPendingMapping::<Hash>::from_canonical_chain_bytes(
                    &canonical,
                    pending_id,
                )
                .map_err(|error| {
                    BranchExactShadowReadError::MalformedTargetCanonicalRef(
                        error.to_string(),
                    )
                })?;
                if digest.as_slice() != mapping.digest().as_bytes() {
                    return Err(
                        BranchExactShadowReadError::TargetMappingProvenanceMismatch(
                            BranchExactShadowDirection::TargetForward,
                        ),
                    );
                }
                Ok((canonical, pending))
            })
            .collect::<Result<BTreeSet<_>, BranchExactShadowReadError>>()?;

        let reverse = self
            .session
            .execute_iter(self.prepared.target_reverse_scan.clone(), ())
            .await
            .map_err(driver)?
            .rows_stream::<(i64, Vec<u8>, Vec<u8>)>()
            .map_err(driver)?
            .try_collect::<Vec<_>>()
            .await
            .map_err(driver)?;
        let observed_reverse = reverse
            .into_iter()
            .map(|(pending, canonical, digest)| {
                let pending = u64::try_from(pending).map_err(|_| {
                    BranchExactShadowReadError::MalformedLegacyValue(pending)
                })?;
                let pending_id = UniquePendingId::try_new(pending)
                    .map_err(|error| BranchExactShadowReadError::Codec(error.to_string()))?;
                let mapping = BranchPendingMapping::<Hash>::from_canonical_chain_bytes(
                    &canonical,
                    pending_id,
                )
                .map_err(|error| {
                    BranchExactShadowReadError::MalformedTargetCanonicalRef(
                        error.to_string(),
                    )
                })?;
                if digest.as_slice() != mapping.digest().as_bytes() {
                    return Err(
                        BranchExactShadowReadError::TargetMappingProvenanceMismatch(
                            BranchExactShadowDirection::TargetReverse,
                        ),
                    );
                }
                Ok((pending, canonical))
            })
            .collect::<Result<BTreeSet<_>, BranchExactShadowReadError>>()?;

        let observed_proofs = match &self.prepared.target_proof_scan {
            None => BTreeSet::new(),
            Some(query) => {
                let rows = self
                    .session
                    .execute_iter(query.clone(), ())
                    .await
                    .map_err(driver)?
                    .rows_stream::<(i64, Vec<u8>)>()
                    .map_err(driver)?
                    .try_collect::<Vec<_>>()
                    .await
                    .map_err(driver)?;
                rows.into_iter()
                    .map(|(pending, stored)| {
                        let pending = u64::try_from(pending).map_err(|_| {
                            BranchExactShadowReadError::MalformedLegacyValue(pending)
                        })?;
                        let canonical = crate::compression::decompress(&stored)
                            .map_err(|error| {
                                BranchExactShadowReadError::Codec(error.to_string())
                            })?;
                        Ok((pending, canonical))
                    })
                    .collect::<Result<BTreeSet<_>, BranchExactShadowReadError>>()?
            }
        };

        require_exact_set("target forward", &expected_forward, &observed_forward)?;
        require_exact_set("target reverse", &expected_reverse, &observed_reverse)?;
        require_exact_set("target proof", &expected_proofs, &observed_proofs)?;
        Ok(())
    }

    async fn read_legacy_u64(
        &self,
        statement: &PreparedStatement,
        key: u64,
    ) -> Result<Option<u64>, BranchExactShadowReadError> {
        let row = self
            .session
            .execute_unpaged(statement, (u64_to_i64_exact(key),))
            .await
            .map_err(driver)?
            .into_rows_result()
            .map_err(driver)?
            .maybe_first_row::<(i64,)>()
            .map_err(driver)?;
        row.map(|(value,)| {
            u64::try_from(value)
                .map_err(|_| BranchExactShadowReadError::MalformedLegacyValue(value))
        })
        .transpose()
    }

    async fn read_target_forward(
        &self,
        expected: &BranchPendingMapping<Hash>,
    ) -> Result<UniquePendingId, BranchExactShadowReadError> {
        let rows = self
            .session
            .execute_unpaged(
                &self.prepared.target_forward,
                (expected.canonical_chain_bytes().as_slice(),),
            )
            .await
            .map_err(driver)?
            .into_rows_result()
            .map_err(driver)?;
        let mut values = rows
            .rows::<(i64, Vec<u8>, i64)>()
            .map_err(driver)?
            .map(|row| row.map_err(driver))
            .collect::<Result<Vec<_>, _>>()?;
        if values.len() != 1 {
            return Err(BranchExactShadowReadError::TargetCardinality {
                direction: BranchExactShadowDirection::TargetForward,
                actual: values.len(),
            });
        }
        let (value, digest, write_timestamp) = values.pop().expect("one value");
        let expected_timestamp = self
            .expected_receipt
            .plan()
            .write_timestamp()
            .ok_or(BranchExactShadowReadError::BackfillPlanMismatch)?
            .as_i64();
        if digest.as_slice() != expected.digest().as_bytes()
            || write_timestamp != expected_timestamp
        {
            return Err(
                BranchExactShadowReadError::TargetMappingProvenanceMismatch(
                    BranchExactShadowDirection::TargetForward,
                ),
            );
        }
        let value = u64::try_from(value)
            .map_err(|_| BranchExactShadowReadError::MalformedLegacyValue(value))?;
        UniquePendingId::try_new(value)
            .map_err(|error| BranchExactShadowReadError::Codec(error.to_string()))
    }

    async fn read_target_reverse(
        &self,
        expected: &BranchPendingMapping<Hash>,
    ) -> Result<BranchPendingMapping<Hash>, BranchExactShadowReadError> {
        let pending_id = expected.pending_id();
        let rows = self
            .session
            .execute_unpaged(
                &self.prepared.target_reverse,
                (u64_to_i64_exact(pending_id.get()),),
            )
            .await
            .map_err(driver)?
            .into_rows_result()
            .map_err(driver)?;
        let mut values = rows
            .rows::<(Vec<u8>, Vec<u8>, i64)>()
            .map_err(driver)?
            .map(|row| row.map_err(driver))
            .collect::<Result<Vec<_>, _>>()?;
        if values.len() != 1 {
            return Err(BranchExactShadowReadError::TargetCardinality {
                direction: BranchExactShadowDirection::TargetReverse,
                actual: values.len(),
            });
        }
        let (canonical, digest, write_timestamp) = values.pop().expect("one value");
        let expected_timestamp = self
            .expected_receipt
            .plan()
            .write_timestamp()
            .ok_or(BranchExactShadowReadError::BackfillPlanMismatch)?
            .as_i64();
        if digest.as_slice() != expected.digest().as_bytes()
            || write_timestamp != expected_timestamp
        {
            return Err(
                BranchExactShadowReadError::TargetMappingProvenanceMismatch(
                    BranchExactShadowDirection::TargetReverse,
                ),
            );
        }
        BranchPendingMapping::from_canonical_chain_bytes(
            &canonical,
            pending_id,
        )
        .map_err(|error| {
            BranchExactShadowReadError::MalformedTargetCanonicalRef(
                error.to_string(),
            )
        })
    }

    async fn read_legacy_serving_proof(
        &self,
        pending_id: UniquePendingId,
    ) -> Result<Option<Vec<u8>>, BranchExactShadowReadError> {
        let query = self.prepared.legacy_serving_proof.as_ref().ok_or(
            BranchExactShadowReadError::CoordinatorProofRequest,
        )?;
        let row = self
            .session
            .execute_unpaged(
                query,
                (REALM_REWARD_PROOF_OBJ_ID, u64_to_i64_exact(pending_id.get())),
            )
            .await
            .map_err(driver)?
            .into_rows_result()
            .map_err(driver)?
            .maybe_first_row::<(i64, Vec<u8>)>()
            .map_err(driver)?;
        row.map(|(observed_pending, stored)| {
            let observed_pending = i64_to_u64_exact(observed_pending);
            if observed_pending != pending_id.get() {
                return Err(BranchExactShadowReadError::LegacyReadThrough {
                    requested_pending_id: pending_id.get(),
                    returned_pending_id: observed_pending,
                });
            }
            crate::compression::decompress(&stored)
                .map_err(|error| BranchExactShadowReadError::Codec(error.to_string()))
        })
        .transpose()
    }

    async fn read_target_proof(
        &self,
        pending_id: UniquePendingId,
    ) -> Result<Option<Vec<u8>>, BranchExactShadowReadError> {
        let query = self.prepared.target_proof.as_ref().ok_or(
            BranchExactShadowReadError::TargetProofUnavailable,
        )?;
        let row = self
            .session
            .execute_unpaged(query, (u64_to_i64_exact(pending_id.get()),))
            .await
            .map_err(driver)?
            .into_rows_result()
            .map_err(driver)?
            .maybe_first_row::<(Vec<u8>,)>()
            .map_err(driver)?;
        row.map(|(stored,)| {
            crate::compression::decompress(&stored)
                .map_err(|error| BranchExactShadowReadError::Codec(error.to_string()))
        })
        .transpose()
    }
}

fn legacy_u64_pairs(
    rows: Vec<(i64, i64)>,
) -> Result<BTreeSet<(u64, u64)>, BranchExactShadowReadError> {
    rows.into_iter()
        .map(|(key, value)| {
            let key = u64::try_from(key)
                .map_err(|_| BranchExactShadowReadError::MalformedLegacyValue(key))?;
            let value = u64::try_from(value)
                .map_err(|_| BranchExactShadowReadError::MalformedLegacyValue(value))?;
            Ok((key, value))
        })
        .collect()
}

async fn prepare_read(
    session: &Session,
    cql: String,
) -> Result<PreparedStatement, BranchExactShadowReadError> {
    let mut statement = session.prepare(cql).await.map_err(driver)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn comparison_digest<Hash: Q256BitHash>(
    kind: &[u8],
    mapping: &BranchPendingMapping<Hash>,
    value: &[u8],
) -> BranchExactShadowComparisonDigest {
    let mut hasher = Sha256::new();
    hasher.update(SHADOW_COMPARISON_DIGEST_DOMAIN);
    hasher.update((kind.len() as u64).to_be_bytes());
    hasher.update(kind);
    hasher.update(mapping.canonical_chain_bytes());
    hasher.update(mapping.pending_id().get().to_be_bytes());
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
    BranchExactShadowComparisonDigest(hasher.finalize().into())
}

fn driver(error: impl fmt::Display) -> BranchExactShadowReadError {
    BranchExactShadowReadError::Driver(error.to_string())
}

fn require_exact_set<T: Ord>(
    label: &str,
    expected: &BTreeSet<T>,
    actual: &BTreeSet<T>,
) -> Result<(), BranchExactShadowReadError> {
    if expected == actual {
        Ok(())
    } else {
        Err(BranchExactShadowReadError::Driver(format!(
            "{label} full-set mismatch: expected {}, actual {}, missing {}, extra {}",
            expected.len(),
            actual.len(),
            expected.difference(actual).count(),
            actual.difference(expected).count(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use parth_core::{PHash, crypto::hash::tag_tree::TagTreeMerkleProof};
    use psy_data::protocol::canonical_chain::{
        CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
        CheckpointRef, NetworkId,
    };

    use super::*;

    fn mapping(epoch: u64, height: u64, hash: u64, pending: u64) -> BranchPendingMapping<PHash> {
        BranchPendingMapping::new(
            CanonicalChainRef::new(
                NetworkId::try_from_chain_id(0).unwrap(),
                ChainEpoch::new(epoch),
                CheckpointRef::new(
                    CheckpointId::new(height),
                    CheckpointHash::from_last_chain_hash(
                        PHash::from_owned_32bytes([hash as u8; 32]),
                    ),
                ),
            ),
            UniquePendingId::try_new(pending).unwrap(),
        )
    }

    #[test]
    fn digest_distinguishes_same_height_hash_across_epochs() {
        let first = mapping(0, 100, 9, 12);
        let second = mapping(1, 100, 9, 12);
        assert_ne!(
            comparison_digest(b"mapping", &first, &[1]),
            comparison_digest(b"mapping", &second, &[1])
        );
    }

    #[test]
    fn digest_distinguishes_same_height_epoch_across_hashes() {
        let first = mapping(1, 100, 9, 12);
        let second = mapping(1, 100, 10, 12);
        assert_ne!(
            comparison_digest(b"mapping", &first, &[1]),
            comparison_digest(b"mapping", &second, &[1])
        );
    }

    #[test]
    fn artifact_rows_preserve_proof_canonical_bytes() {
        let proof = TagTreeMerkleProof::<PHash>::new_empty();
        let row = BranchExactBackfillArtifactRow::try_new(
            mapping(0, 0, 1, 2),
            Some(&proof),
        )
        .unwrap();
        assert!(row.reward_proof_canonical().is_some());
    }

    #[test]
    fn shadow_error_is_fail_closed_and_has_no_fallback_variant() {
        let error = BranchExactShadowReadError::MissingMapping(
            BranchExactShadowDirection::TargetForward,
        );
        assert!(format!("{error}").contains("MissingMapping"));
    }
}
