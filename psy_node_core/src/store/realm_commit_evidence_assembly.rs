//! Production-shaped assembly of one changed-Realm commit evidence bundle.
//!
//! Planning consumes the exact prepared update, submitted GUTA header, proof
//! bytes, verifier and Coordinator inclusion response. It verifies the proof
//! envelope and builds the mutation graph's complete predecessor read-set.
//! Completion then consumes exactly those predecessor rows and is the only
//! path from the plan to [`SealedRealmCommitEvidence`].

use std::{error::Error, fmt};

use parth_core::{
    crypto::hash::traits::{
        FieldQHasher, MerkleHasher, MerkleZeroHasher,
    },
    felt::QFelt64,
    protocol::core_types::{
        Q256BitHash, QFHashBase, QZKProofVerifier,
    },
};
use psy_data::{
    guta::header_extended::GlobalUserTreeAggregatorHeaderWithTagValueAndJobType,
    prepared_block::realm::{
        PsyPreparedRealmBlockStateUpdates, PsyRealmCoordinatorUpdate,
    },
    protocol::chain_context::{
        AuthorityScope, AuthorityStateCheckpointId,
    },
};

use super::{
    realm_commit_evidence::{
        RealmCommitEvidenceError, SealedRealmCommitEvidence,
    },
    realm_imt_mutation_graph::{
        RealmImtContractHeightReadPlan, RealmImtContractHeights,
        RealmImtMutationGraphConfig, RealmImtMutationGraphError,
        RealmImtMutationGraphPlan, RealmImtPredecessorReadPlan,
        RealmImtPredecessorReadRow,
    },
    realm_proof_binding::{
        RealmProofBindingError, SealedRealmProofBinding,
    },
};

/// Verified proof envelope plus the exact predecessor read-set required to
/// validate the same prepared update's complete Realm mutation graph,
/// including its IMT preimage layer when present.
///
/// The plan owns the live proof seal. Persisted proof evidence cannot recreate
/// it, and callers cannot replace either component during completion.
#[derive(Clone, Debug)]
pub struct RealmCommitEvidenceAssemblyPlan<Hash, Hasher> {
    proof: SealedRealmProofBinding<Hash>,
    graph: RealmImtMutationGraphPlan<Hash, Hasher>,
}

impl<Hash: Q256BitHash, Hasher: MerkleHasher<Hash>>
    RealmCommitEvidenceAssemblyPlan<Hash, Hasher>
{
    #[allow(clippy::too_many_arguments)]
    pub fn try_new<F, Proof, Verifier>(
        authority: AuthorityScope,
        predecessor_checkpoint: AuthorityStateCheckpointId,
        config: RealmImtMutationGraphConfig,
        contract_state_tree_heights: &RealmImtContractHeights,
        prepared: &PsyPreparedRealmBlockStateUpdates<Hash>,
        submission: &GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<
            F,
            Hash,
        >,
        proof_bytes: &[u8],
        proof_verifier: &Verifier,
        coordinator: &PsyRealmCoordinatorUpdate<F, Hash>,
    ) -> Result<Self, RealmCommitEvidenceAssemblyError>
    where
        F: QFelt64,
        Hash: QFHashBase<F>,
        Hasher: FieldQHasher<F, Hash>,
        Verifier: QZKProofVerifier<Hash, Proof>,
    {
        if contract_state_tree_heights.predecessor_checkpoint()
            != predecessor_checkpoint
        {
            return Err(
                RealmCommitEvidenceAssemblyError::ContractHeightCheckpointMismatch {
                    expected: predecessor_checkpoint,
                    actual: contract_state_tree_heights
                        .predecessor_checkpoint(),
                },
            );
        }
        let expected_height_plan =
            RealmImtContractHeightReadPlan::try_from_prepared(
                predecessor_checkpoint,
                prepared,
            )?;
        let actual_contract_ids = contract_state_tree_heights
            .contract_ids()
            .collect::<Vec<_>>();
        if expected_height_plan.contract_ids() != actual_contract_ids {
            return Err(
                RealmCommitEvidenceAssemblyError::ContractHeightDomainMismatch {
                    expected: expected_height_plan.contract_ids().to_vec(),
                    actual: actual_contract_ids,
                },
            );
        }
        let state_checkpoint = AuthorityStateCheckpointId::new(
            coordinator.checkpoint_sync_info.checkpoint_id,
        );

        // Reject malformed mutation graphs before invoking the comparatively
        // expensive proof verifier.
        let graph = RealmImtMutationGraphPlan::<Hash, Hasher>::try_from_prepared::<F>(
            authority,
            predecessor_checkpoint,
            state_checkpoint,
            config,
            contract_state_tree_heights.as_map(),
            prepared,
        )?;
        let proof = SealedRealmProofBinding::verify_and_seal::<
            F,
            Hasher,
            Proof,
            Verifier,
        >(
            authority,
            prepared,
            submission,
            proof_bytes,
            proof_verifier,
            coordinator,
            config.coordinator_tree_height(),
        )?;
        Ok(Self { proof, graph })
    }

    pub fn predecessor_read_plan(&self) -> RealmImtPredecessorReadPlan {
        self.graph.predecessor_read_plan()
    }

    pub const fn proof(&self) -> &SealedRealmProofBinding<Hash> {
        &self.proof
    }

    pub const fn graph(&self) -> &RealmImtMutationGraphPlan<Hash, Hasher> {
        &self.graph
    }

    /// Consume the exact predecessor response and bind both live seals into
    /// one commit evidence bundle. Missing, duplicated or additional rows fail
    /// before a bundle can exist.
    pub fn verify_predecessor_rows_and_seal(
        self,
        rows: &[RealmImtPredecessorReadRow<Hash>],
    ) -> Result<SealedRealmCommitEvidence<Hash, Hasher>, RealmCommitEvidenceAssemblyError>
    where
        Hasher: MerkleZeroHasher<Hash>,
    {
        let graph = self.graph.verify_predecessor_rows_and_seal(rows)?;
        Ok(SealedRealmCommitEvidence::try_bind(self.proof, graph)?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealmCommitEvidenceAssemblyError {
    ContractHeightCheckpointMismatch {
        expected: AuthorityStateCheckpointId,
        actual: AuthorityStateCheckpointId,
    },
    ContractHeightDomainMismatch {
        expected: Vec<u64>,
        actual: Vec<u64>,
    },
    Proof(RealmProofBindingError),
    Graph(RealmImtMutationGraphError),
    Bundle(RealmCommitEvidenceError),
}

impl From<RealmProofBindingError> for RealmCommitEvidenceAssemblyError {
    fn from(value: RealmProofBindingError) -> Self {
        Self::Proof(value)
    }
}

impl From<RealmImtMutationGraphError> for RealmCommitEvidenceAssemblyError {
    fn from(value: RealmImtMutationGraphError) -> Self {
        Self::Graph(value)
    }
}

impl From<RealmCommitEvidenceError> for RealmCommitEvidenceAssemblyError {
    fn from(value: RealmCommitEvidenceError) -> Self {
        Self::Bundle(value)
    }
}

impl fmt::Display for RealmCommitEvidenceAssemblyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RealmCommitEvidenceAssemblyError {}
