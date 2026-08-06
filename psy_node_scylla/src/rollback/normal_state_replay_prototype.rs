//! Representative D-04b2 state replay and verification boundary.
//!
//! This prototype deliberately supports only Realm `global_user_tree_table`
//! PUTs carried directly by the durable prepared payload. It proves the
//! important normal-commit property without pretending that all 35 physical
//! tables have replay adapters: every exact physical row is read back, the
//! committed root row is compared independently, and only then can an
//! [`AuthorityPostWriteObservation`] be produced for SEALED.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_node_core::store::{
    authority_commit::AuthorityScope,
    manifest_lifecycle::{
        AuthorityHeadPayloadDigest, AuthorityHeadView,
        AuthorityPostWriteObservation, AuthorityProofObservation,
    },
    manifest_record::PreparedAuthorityManifestRecord,
    typed::{LogicalMutation, MutationOperation, MutationValue, TypedTableKey},
};
use super::{
    seal_commit_put, CanonicalPhysicalMutationBatch, PreparedPayload,
    PreparedPayloadKind, ReplayPrototypeError, ReplayRecordKind,
    RollbackableStorePrototype, RollbackableStorePrototypeError,
    ScyllaPhysicalTableId, SealedTimestampedPut, TimestampedMutationError,
    VerifiedPersistedManifestArtifacts,
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExpectedMerkleRow {
    sealed: SealedTimestampedPut,
    value: Vec<u8>,
    is_root: bool,
}

/// A manifest-bound, timestamped replay plan for one representative Realm
/// state transition. Construction consumes only verified durable artifact
/// bytes and fails closed if any physical mutation is outside the supported
/// table or is not covered by the manifest digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepresentativeRealmStateReplayPlan<Hash> {
    prepared: PreparedAuthorityManifestRecord<Hash>,
    rows: Vec<ExpectedMerkleRow>,
    mutation_digest: [u8; 32],
}

impl<Hash: Q256BitHash> RepresentativeRealmStateReplayPlan<Hash> {
    pub fn try_from_verified_artifacts(
        prepared: &PreparedAuthorityManifestRecord<Hash>,
        artifacts: &VerifiedPersistedManifestArtifacts,
    ) -> Result<Self, RepresentativeStateReplayError> {
        Self::try_from_verified_parts(
            prepared,
            artifacts.plan().replay_record_kind(),
            *artifacts.plan().mutation_digest(),
            artifacts.durable_prepared_payload(),
        )
    }

    fn try_from_verified_parts(
        prepared: &PreparedAuthorityManifestRecord<Hash>,
        replay_kind: Option<ReplayRecordKind>,
        persisted_mutation_digest: [u8; 32],
        durable_prepared_payload: Option<&[u8]>,
    ) -> Result<Self, RepresentativeStateReplayError> {
        if !matches!(prepared.identity().authority(), AuthorityScope::Realm { .. }) {
            return Err(RepresentativeStateReplayError::RealmAuthorityRequired);
        }
        if !prepared.intent().state_transition().state_changed() {
            return Err(RepresentativeStateReplayError::ChangedStateRequired);
        }
        if replay_kind != Some(ReplayRecordKind::PreparedReferencePlusSupplement) {
            return Err(RepresentativeStateReplayError::CompactPreparedReplayRequired);
        }
        let durable_prepared_payload = durable_prepared_payload
            .ok_or(RepresentativeStateReplayError::DurablePreparedPayloadMissing)?;
        let payload = PreparedPayload::decode_canonical(durable_prepared_payload)?;
        if payload.kind() != PreparedPayloadKind::Realm {
            return Err(RepresentativeStateReplayError::RealmPreparedPayloadRequired);
        }
        let batch = CanonicalPhysicalMutationBatch::try_new(
            payload.expand_physical()?,
        )?;
        let mutation_digest = *batch.digest().as_bytes();
        let committed_digest = prepared.intent().artifacts().mutation_digest();
        if mutation_digest != persisted_mutation_digest
            || mutation_digest != committed_digest
        {
            return Err(
                RepresentativeStateReplayError::PreparedPayloadDoesNotCoverManifest,
            );
        }
        if batch.mutations().len() as u64
            != prepared.intent().artifacts().affected_row_count()
        {
            return Err(
                RepresentativeStateReplayError::PreparedPayloadDoesNotCoverManifest,
            );
        }

        let expected_checkpoint = prepared
            .intent()
            .state_transition()
            .state_checkpoint()
            .get();
        let expected_root = prepared
            .intent()
            .state_transition()
            .new_root()
            .as_inner()
            .to_vec_32bytes();
        let mut rows = Vec::with_capacity(batch.mutations().len());
        let mut root_count = 0_usize;

        for resolved in batch.mutations() {
            let mutation = resolved.mutation();
            if mutation.physical_table() != ScyllaPhysicalTableId::GlobalUserTree {
                return Err(RepresentativeStateReplayError::UnsupportedPhysicalTable(
                    mutation.physical_table(),
                ));
            }
            let (node, checkpoint) = match mutation.key() {
                TypedTableKey::GlobalUserMerkle { node, checkpoint } => {
                    (*node, *checkpoint)
                }
                _ => return Err(RepresentativeStateReplayError::WrongTypedKey),
            };
            if checkpoint.get() != expected_checkpoint {
                return Err(RepresentativeStateReplayError::StateCheckpointMismatch {
                    expected: expected_checkpoint,
                    actual: checkpoint.get(),
                });
            }
            let value = match mutation.operation() {
                MutationOperation::Put(MutationValue::PsyCanonicalBytes(value)) => {
                    value.clone()
                }
                MutationOperation::Put(_) => {
                    return Err(RepresentativeStateReplayError::WrongValueEncoding)
                }
                MutationOperation::Delete => {
                    return Err(RepresentativeStateReplayError::DeleteNotSupported)
                }
            };
            if value.len() != 32 {
                return Err(RepresentativeStateReplayError::InvalidMerkleValueLength(
                    value.len(),
                ));
            }
            let is_root = node.level() == 0 && node.index().get() == 0;
            if is_root {
                root_count += 1;
                if value != expected_root {
                    return Err(RepresentativeStateReplayError::ManifestRootMismatch);
                }
            }
            let sealed = seal_commit_put(
                LogicalMutation::Put {
                    key: mutation.key().clone(),
                    value: MutationValue::PsyCanonicalBytes(value.clone()),
                },
                prepared.commit_write_timestamp(),
            )?;
            rows.push(ExpectedMerkleRow {
                sealed,
                value,
                is_root,
            });
        }
        if root_count != 1 {
            return Err(RepresentativeStateReplayError::ExpectedExactlyOneRoot {
                actual: root_count,
            });
        }

        Ok(Self {
            prepared: prepared.clone(),
            rows,
            mutation_digest,
        })
    }

    pub fn puts(&self) -> impl ExactSizeIterator<Item = &SealedTimestampedPut> {
        self.rows.iter().map(|row| &row.sealed)
    }

    pub fn mutation_count(&self) -> usize {
        self.rows.len()
    }

    pub fn root_position(&self) -> usize {
        self.rows
            .iter()
            .position(|row| row.is_root)
            .expect("plan construction requires exactly one root")
    }

    pub const fn mutation_digest(&self) -> &[u8; 32] {
        &self.mutation_digest
    }

    pub const fn prepared(&self) -> &PreparedAuthorityManifestRecord<Hash> {
        &self.prepared
    }

    /// Convert exact physical read-back into lifecycle evidence. A root-only
    /// check is intentionally insufficient: every manifest row must exist and
    /// match before this constructor returns an observation.
    pub fn verify_observed_rows(
        &self,
        observed: &[Option<Vec<u8>>],
    ) -> Result<AuthorityPostWriteObservation<Hash>, RepresentativeStateReplayError> {
        if observed.len() != self.rows.len() {
            return Err(RepresentativeStateReplayError::ObservationCountMismatch {
                expected: self.rows.len(),
                actual: observed.len(),
            });
        }
        for (index, (expected, actual)) in
            self.rows.iter().zip(observed).enumerate()
        {
            match actual {
                None => {
                    return Err(RepresentativeStateReplayError::PhysicalRowMissing {
                        index,
                    })
                }
                Some(actual) if actual != &expected.value => {
                    return Err(if expected.is_root {
                        RepresentativeStateReplayError::ObservedRootMismatch
                    } else {
                        RepresentativeStateReplayError::PhysicalRowValueMismatch {
                            index,
                        }
                    })
                }
                Some(_) => {}
            }
        }

        Ok(AuthorityPostWriteObservation::new(
            AuthorityHeadView::candidate(&self.prepared),
            self.mutation_digest,
            AuthorityHeadPayloadDigest::from_verified_payload_bytes(
                self.prepared.intent().head_payload().as_bytes(),
            ),
            AuthorityProofObservation::NotApplicableForRealm,
        ))
    }
}

/// I/O facade kept outside production setup. It uses the real timestamped
/// table adapter for both writes and exact physical reads.
pub struct RepresentativeRealmStateReplayExecutor<'a> {
    store: &'a RollbackableStorePrototype,
}

impl<'a> RepresentativeRealmStateReplayExecutor<'a> {
    pub const fn new(store: &'a RollbackableStorePrototype) -> Self {
        Self { store }
    }

    pub async fn reapply_all<Hash: Q256BitHash>(
        &self,
        plan: &RepresentativeRealmStateReplayPlan<Hash>,
    ) -> Result<(), RepresentativeStateExecutionError> {
        self.reapply_prefix_for_gate(plan, plan.mutation_count()).await
    }

    /// Fault-injection hook for M16/M17. Production integration must only call
    /// `reapply_all`; this method exists so the RF=3 gate can crash after an
    /// exact prefix without inventing a second write path.
    pub async fn reapply_prefix_for_gate<Hash: Q256BitHash>(
        &self,
        plan: &RepresentativeRealmStateReplayPlan<Hash>,
        count: usize,
    ) -> Result<(), RepresentativeStateExecutionError> {
        if count > plan.mutation_count() {
            return Err(RepresentativeStateExecutionError::PrefixOutOfBounds {
                requested: count,
                available: plan.mutation_count(),
            });
        }
        for sealed in plan.puts().take(count) {
            self.store.put_global_user_merkle(sealed).await?;
        }
        Ok(())
    }

    pub async fn read_exact<Hash: Q256BitHash>(
        &self,
        plan: &RepresentativeRealmStateReplayPlan<Hash>,
    ) -> Result<Vec<Option<Vec<u8>>>, RepresentativeStateExecutionError> {
        let mut observed = Vec::with_capacity(plan.mutation_count());
        for sealed in plan.puts() {
            observed.push(self.store.read_global_user_merkle_exact(sealed).await?);
        }
        Ok(observed)
    }

    pub async fn verify_exact<Hash: Q256BitHash>(
        &self,
        plan: &RepresentativeRealmStateReplayPlan<Hash>,
    ) -> Result<AuthorityPostWriteObservation<Hash>, RepresentativeStateExecutionError> {
        let observed = self.read_exact(plan).await?;
        plan.verify_observed_rows(&observed).map_err(Into::into)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RepresentativeStateExecutionError {
    Store(RollbackableStorePrototypeError),
    Verification(RepresentativeStateReplayError),
    PrefixOutOfBounds { requested: usize, available: usize },
}

impl From<RollbackableStorePrototypeError>
    for RepresentativeStateExecutionError
{
    fn from(value: RollbackableStorePrototypeError) -> Self {
        Self::Store(value)
    }
}

impl From<RepresentativeStateReplayError> for RepresentativeStateExecutionError {
    fn from(value: RepresentativeStateReplayError) -> Self {
        Self::Verification(value)
    }
}

impl fmt::Display for RepresentativeStateExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RepresentativeStateExecutionError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RepresentativeStateReplayError {
    Replay(ReplayPrototypeError),
    Timestamped(TimestampedMutationError),
    RealmAuthorityRequired,
    ChangedStateRequired,
    CompactPreparedReplayRequired,
    DurablePreparedPayloadMissing,
    RealmPreparedPayloadRequired,
    PreparedPayloadDoesNotCoverManifest,
    UnsupportedPhysicalTable(ScyllaPhysicalTableId),
    WrongTypedKey,
    WrongValueEncoding,
    DeleteNotSupported,
    InvalidMerkleValueLength(usize),
    StateCheckpointMismatch { expected: u64, actual: u64 },
    ManifestRootMismatch,
    ExpectedExactlyOneRoot { actual: usize },
    ObservationCountMismatch { expected: usize, actual: usize },
    PhysicalRowMissing { index: usize },
    PhysicalRowValueMismatch { index: usize },
    ObservedRootMismatch,
}

impl From<ReplayPrototypeError> for RepresentativeStateReplayError {
    fn from(value: ReplayPrototypeError) -> Self {
        Self::Replay(value)
    }
}

impl From<TimestampedMutationError> for RepresentativeStateReplayError {
    fn from(value: TimestampedMutationError) -> Self {
        Self::Timestamped(value)
    }
}

impl fmt::Display for RepresentativeStateReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RepresentativeStateReplayError {}

#[cfg(test)]
mod tests {
    use parth_core::{protocol::core_types::Q256BitHash, PHash};
    use psy_data::protocol::{
        canonical_chain::{
            CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
            CheckpointRef, NetworkId,
        },
        chain_context::{
            AuthorityScope, AuthorityStateCheckpointId, AuthorityStateRoot,
        },
    };
    use psy_node_core::store::{
        authority_commit::{
            AuthorityClockSampleUs, AuthorityTimestampBootstrap,
            AuthorityTimestampBootstrapReason, AuthorityTimestampKey,
        },
        manifest_intent::{
            AuthorityHeadPayload, AuthorityStateTransition,
            SealedAuthorityCommitIntent,
        },
        manifest_lifecycle::SealedAuthorityManifest,
        timestamp::CommitWriteTimestampUs,
        typed::{
            CheckpointId as StorageCheckpointId, LogicalMutation, MerkleNode,
            MutationValue, NodeIndex, TypedTableKey,
        },
    };

    use super::*;
    use crate::rollback::{
        CanonicalManifestArtifacts, DerivedSupplementBatch,
        DurablePreparedPayloadReference, OperationalReplayAction,
        PreparedPayloadSource, PreparedReferencePlusSupplementRecord,
        PreparedSemanticMutation, ReplayAuthority, ReplayReceipt,
        VerifiedPreparedManifestPackage,
    };

    fn hash(seed: u8) -> PHash {
        PHash::from_owned_32bytes([seed; 32])
    }

    fn network() -> NetworkId {
        NetworkId::try_from_chain_id(1337).unwrap()
    }

    fn chain(checkpoint: u64, seed: u8) -> CanonicalChainRef<PHash> {
        CanonicalChainRef::new(
            network(),
            ChainEpoch::new(7),
            CheckpointRef::new(
                CheckpointId::new(checkpoint),
                CheckpointHash::from_last_chain_hash(hash(seed)),
            ),
        )
    }

    fn fixture() -> (
        VerifiedPreparedManifestPackage<PHash>,
        Vec<u8>,
    ) {
        let checkpoint = StorageCheckpointId::try_new(41).unwrap();
        let root = MerkleNode::new(0, NodeIndex::new(0));
        let child = MerkleNode::new(1, NodeIndex::new(0));
        let semantic = vec![
            PreparedSemanticMutation::GlobalUserMerkle {
                checkpoint,
                node: root,
                value: vec![4; 32],
            },
            PreparedSemanticMutation::GlobalUserMerkle {
                checkpoint,
                node: child,
                value: vec![5; 32],
            },
        ];
        let payload =
            PreparedPayload::try_v1(PreparedPayloadKind::Realm, semantic)
                .unwrap();
        let payload_bytes = payload.encode_canonical();
        let reference = DurablePreparedPayloadReference::try_from_source(
            payload.kind(),
            1,
            1,
            PreparedPayloadSource::ContentAddressedBytes(&payload_bytes),
        )
        .unwrap();
        let logical = vec![
            LogicalMutation::Put {
                key: TypedTableKey::GlobalUserMerkle {
                    checkpoint,
                    node: root,
                },
                value: MutationValue::PsyCanonicalBytes(vec![4; 32]),
            },
            LogicalMutation::Put {
                key: TypedTableKey::GlobalUserMerkle {
                    checkpoint,
                    node: child,
                },
                value: MutationValue::PsyCanonicalBytes(vec![5; 32]),
            },
        ];
        let full = CanonicalPhysicalMutationBatch::from_logical(logical).unwrap();
        let compact = PreparedReferencePlusSupplementRecord::try_v1(
            reference,
            DerivedSupplementBatch::from_logical(Vec::new()).unwrap(),
            ReplayReceipt::new(
                ReplayAuthority::Realm,
                checkpoint,
                2,
                0,
                vec![OperationalReplayAction::RotatePendingCheckpointNamespace],
            ),
            &payload_bytes,
            &full,
        )
        .unwrap();
        let artifacts =
            CanonicalManifestArtifacts::try_from_compact(&compact, &payload_bytes)
                .unwrap();
        let key = AuthorityTimestampKey::new(
            network(),
            AuthorityScope::Realm {
                realm_id: 3,
                realm_sub_id: 2,
            },
        );
        let intent = SealedAuthorityCommitIntent::seal_normal_advance(
            key,
            chain(40, 1),
            chain(41, 2),
            AuthorityStateTransition::Changed {
                previous_checkpoint: AuthorityStateCheckpointId::new(40),
                checkpoint: AuthorityStateCheckpointId::new(41),
                old_root: AuthorityStateRoot::from_local_state_root(hash(3)),
                new_root: AuthorityStateRoot::from_local_state_root(hash(4)),
            },
            AuthorityHeadPayload::try_new(vec![0x66; 16]).unwrap(),
            artifacts.commitment(),
        )
        .unwrap();
        let reservation = AuthorityTimestampBootstrap::new(
            key,
            CommitWriteTimestampUs::try_from_i128(500).unwrap(),
            AuthorityTimestampBootstrapReason::GenesisNative,
        )
        .candidate()
        .seal_reservation(
            key,
            intent.digest(),
            AuthorityClockSampleUs::try_from_i128(501).unwrap(),
        )
        .unwrap();
        let prepared = intent.attach_timestamp_lease(reservation.lease()).unwrap();
        (
            VerifiedPreparedManifestPackage::try_new(&prepared, artifacts)
                .unwrap(),
            payload_bytes,
        )
    }

    fn plan() -> RepresentativeRealmStateReplayPlan<PHash> {
        let (package, payload) = fixture();
        let set = package.artifacts().chunked().unwrap();
        RepresentativeRealmStateReplayPlan::try_from_verified_parts(
            package.record(),
            Some(set.replay_record_kind()),
            *set.mutation_digest(),
            Some(&payload),
        )
        .unwrap()
    }

    #[test]
    fn compact_payload_becomes_exact_timestamped_replay_and_seal_evidence() {
        let plan = plan();
        assert_eq!(plan.mutation_count(), 2);
        assert_eq!(
            plan.mutation_digest(),
            &plan.prepared().intent().artifacts().mutation_digest()
        );
        for put in plan.puts() {
            assert_eq!(put.timestamp(), plan.prepared().commit_write_timestamp());
        }

        let observed = plan
            .rows
            .iter()
            .map(|row| Some(row.value.clone()))
            .collect::<Vec<_>>();
        let observation = plan.verify_observed_rows(&observed).unwrap();
        SealedAuthorityManifest::verify_and_seal(
            plan.prepared().clone(),
            observation,
        )
        .unwrap();
    }

    #[test]
    fn root_without_every_manifest_row_cannot_become_sealed() {
        let plan = plan();
        let observed = plan
            .rows
            .iter()
            .map(|row| row.is_root.then(|| row.value.clone()))
            .collect::<Vec<_>>();
        assert!(observed.iter().any(Option::is_some));
        assert_eq!(
            plan.verify_observed_rows(&observed),
            Err(RepresentativeStateReplayError::PhysicalRowMissing {
                index: plan.rows.iter().position(|row| !row.is_root).unwrap(),
            })
        );
    }

    #[test]
    fn root_and_non_root_corruption_are_distinguished() {
        let plan = plan();
        let complete = plan
            .rows
            .iter()
            .map(|row| Some(row.value.clone()))
            .collect::<Vec<_>>();

        let root_index = plan.rows.iter().position(|row| row.is_root).unwrap();
        let mut wrong_root = complete.clone();
        wrong_root[root_index] = Some(vec![0xEE; 32]);
        assert_eq!(
            plan.verify_observed_rows(&wrong_root),
            Err(RepresentativeStateReplayError::ObservedRootMismatch)
        );

        let child_index = plan.rows.iter().position(|row| !row.is_root).unwrap();
        let mut wrong_child = complete;
        wrong_child[child_index] = Some(vec![0xDD; 32]);
        assert_eq!(
            plan.verify_observed_rows(&wrong_child),
            Err(RepresentativeStateReplayError::PhysicalRowValueMismatch {
                index: child_index,
            })
        );
    }

    #[test]
    fn payload_not_covering_manifest_fails_before_any_put_is_executable() {
        let (package, payload) = fixture();
        assert_eq!(
            RepresentativeRealmStateReplayPlan::try_from_verified_parts(
                package.record(),
                Some(ReplayRecordKind::PreparedReferencePlusSupplement),
                [0xAA; 32],
                Some(&payload),
            ),
            Err(
                RepresentativeStateReplayError::PreparedPayloadDoesNotCoverManifest
            )
        );
    }

    #[test]
    fn unsupported_replay_kind_and_missing_payload_fail_closed() {
        let (package, _) = fixture();
        let digest = package.record().intent().artifacts().mutation_digest();
        assert_eq!(
            RepresentativeRealmStateReplayPlan::try_from_verified_parts(
                package.record(),
                Some(ReplayRecordKind::FullPhysicalDelta),
                digest,
                None,
            ),
            Err(RepresentativeStateReplayError::CompactPreparedReplayRequired)
        );
        assert_eq!(
            RepresentativeRealmStateReplayPlan::try_from_verified_parts(
                package.record(),
                Some(ReplayRecordKind::PreparedReferencePlusSupplement),
                digest,
                None,
            ),
            Err(RepresentativeStateReplayError::DurablePreparedPayloadMissing)
        );
    }

    #[tokio::test]
    async fn fault_injection_prefix_is_bounded_before_any_write() {
        let plan = plan();
        let store = RollbackableStorePrototype::recording();
        let executor = RepresentativeRealmStateReplayExecutor::new(&store);
        assert_eq!(
            executor
                .reapply_prefix_for_gate(&plan, plan.mutation_count() + 1)
                .await,
            Err(RepresentativeStateExecutionError::PrefixOutOfBounds {
                requested: plan.mutation_count() + 1,
                available: plan.mutation_count(),
            })
        );
        assert!(store.recorded_calls().unwrap().is_empty());
    }
}
