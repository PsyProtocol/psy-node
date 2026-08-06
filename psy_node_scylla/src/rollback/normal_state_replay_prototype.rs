//! Representative D-04b2 state replay and verification boundary.
//!
//! This prototype supports Realm `global_user_tree_table` PUTs plus the
//! checkpoint-root bidirectional mapping and latest-checkpoint singleton
//! carried by durable supplements. It proves that root-covered state and
//! root-independent rows share one recovery boundary without pretending that
//! all 35 physical tables have replay adapters: every exact physical row is
//! read back, the committed state root is compared independently, and only
//! then can an [`AuthorityPostWriteObservation`] be produced for SEALED.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_node_core::store::{
    authority_commit::AuthorityScope,
    manifest_lifecycle::{
        AuthorityHeadPayloadDigest, AuthorityHeadView,
        AuthorityPostWriteObservation, AuthorityProofObservation,
    },
    manifest_record::PreparedAuthorityManifestRecord,
    typed::{
        CheckpointRootKey, LogicalMutation, MutationOperation, MutationValue,
        TypedTableKey,
    },
};
use super::{
    seal_commit_put, seal_commit_put_batch, CanonicalPhysicalMutationBatch,
    CheckpointRootPairPutPlan, PreparedPayload, PreparedPayloadKind,
    ReplayPrototypeError,
    RollbackableStorePrototype, RollbackableStorePrototypeError,
    ScyllaPhysicalTableId, SealedTimestampedPut, SealedTimestampedPutBatch,
    TimestampedMutationError,
    VerifiedPersistedManifestArtifacts,
};
#[cfg(test)]
use super::ReplayRecordKind;

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExpectedStateRow {
    sealed: SealedTimestampedPut,
    value: Vec<u8>,
    is_root: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExpectedCheckpointRootPair {
    start: usize,
    sealed: SealedTimestampedPutBatch,
}

/// A manifest-bound, timestamped replay plan for one representative Realm
/// state transition. Construction consumes only verified durable artifact
/// bytes and fails closed if any physical mutation is outside the supported
/// table or is not covered by the manifest digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepresentativeRealmStateReplayPlan<Hash> {
    prepared: PreparedAuthorityManifestRecord<Hash>,
    rows: Vec<ExpectedStateRow>,
    checkpoint_root_pair: ExpectedCheckpointRootPair,
    mutation_digest: [u8; 32],
}

impl<Hash: Q256BitHash> RepresentativeRealmStateReplayPlan<Hash> {
    pub fn try_from_verified_artifacts(
        prepared: &PreparedAuthorityManifestRecord<Hash>,
        artifacts: &VerifiedPersistedManifestArtifacts,
    ) -> Result<Self, RepresentativeStateReplayError> {
        let durable_prepared_payload = artifacts
            .durable_prepared_payload()
            .ok_or(RepresentativeStateReplayError::DurablePreparedPayloadMissing)?;
        let payload = PreparedPayload::decode_canonical(durable_prepared_payload)?;
        if payload.kind() != PreparedPayloadKind::Realm {
            return Err(RepresentativeStateReplayError::RealmPreparedPayloadRequired);
        }
        let batch = artifacts.decode_and_expand_compact_replay()?;
        Self::try_from_expanded_batch(
            prepared,
            *artifacts.plan().mutation_digest(),
            batch,
        )
    }

    #[cfg(test)]
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
        Self::try_from_expanded_batch(prepared, persisted_mutation_digest, batch)
    }

    fn try_from_expanded_batch(
        prepared: &PreparedAuthorityManifestRecord<Hash>,
        persisted_mutation_digest: [u8; 32],
        batch: CanonicalPhysicalMutationBatch,
    ) -> Result<Self, RepresentativeStateReplayError> {
        if !matches!(prepared.identity().authority(), AuthorityScope::Realm { .. }) {
            return Err(RepresentativeStateReplayError::RealmAuthorityRequired);
        }
        if !prepared.intent().state_transition().state_changed() {
            return Err(RepresentativeStateReplayError::ChangedStateRequired);
        }
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
        let mut checkpoint_root_k1 = None;
        let mut checkpoint_root_k2 = None;

        for resolved in batch.mutations() {
            let mutation = resolved.mutation();
            match mutation.physical_table() {
                ScyllaPhysicalTableId::GlobalUserTree => {
                    let (node, checkpoint) = match mutation.key() {
                        TypedTableKey::GlobalUserMerkle { node, checkpoint } => (*node, *checkpoint),
                        _ => return Err(RepresentativeStateReplayError::WrongTypedKey),
                    };
                    if checkpoint.get() != expected_checkpoint {
                        return Err(RepresentativeStateReplayError::StateCheckpointMismatch {
                            expected: expected_checkpoint,
                            actual: checkpoint.get(),
                        });
                    }
                    let value = match mutation.operation() {
                        MutationOperation::Put(MutationValue::PsyCanonicalBytes(value)) => value.clone(),
                        MutationOperation::Put(_) => return Err(RepresentativeStateReplayError::WrongValueEncoding),
                        MutationOperation::Delete => return Err(RepresentativeStateReplayError::DeleteNotSupported),
                    };
                    if value.len() != 32 {
                        return Err(RepresentativeStateReplayError::InvalidMerkleValueLength(value.len()));
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
                    rows.push(ExpectedStateRow { sealed, value, is_root });
                }
                ScyllaPhysicalTableId::U64Singleton => {
                    if !matches!(mutation.key(), TypedTableKey::U64Singleton(_)) {
                        return Err(RepresentativeStateReplayError::WrongTypedKey);
                    }
                    let value = match mutation.operation() {
                        MutationOperation::Put(MutationValue::CqlU64(value)) => *value,
                        MutationOperation::Put(_) => return Err(RepresentativeStateReplayError::WrongValueEncoding),
                        MutationOperation::Delete => return Err(RepresentativeStateReplayError::DeleteNotSupported),
                    };
                    if value != expected_checkpoint {
                        return Err(RepresentativeStateReplayError::StateCheckpointMismatch {
                            expected: expected_checkpoint,
                            actual: value,
                        });
                    }
                    let sealed = seal_commit_put(
                        LogicalMutation::Put {
                            key: mutation.key().clone(),
                            value: MutationValue::CqlU64(value),
                        },
                        prepared.commit_write_timestamp(),
                    )?;
                    rows.push(ExpectedStateRow { sealed, value: value.to_be_bytes().to_vec(), is_root: false });
                }
                ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK1 => {
                    if checkpoint_root_k1.replace(resolved.clone()).is_some() {
                        return Err(
                            RepresentativeStateReplayError::DuplicateCheckpointRootDirection,
                        );
                    }
                }
                ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK2 => {
                    if checkpoint_root_k2.replace(resolved.clone()).is_some() {
                        return Err(
                            RepresentativeStateReplayError::DuplicateCheckpointRootDirection,
                        );
                    }
                }
                other => return Err(RepresentativeStateReplayError::UnsupportedPhysicalTable(other)),
            }
        }
        if root_count != 1 {
            return Err(RepresentativeStateReplayError::ExpectedExactlyOneRoot {
                actual: root_count,
            });
        }

        let (checkpoint_root_k1, checkpoint_root_k2) = checkpoint_root_k1
            .zip(checkpoint_root_k2)
            .ok_or(RepresentativeStateReplayError::ExpectedCheckpointRootPair)?;
        let checkpoint_root = match checkpoint_root_k1.mutation().key() {
            TypedTableKey::CheckpointRootByHash(root) => root.clone(),
            _ => return Err(RepresentativeStateReplayError::WrongTypedKey),
        };
        let checkpoint = match checkpoint_root_k2.mutation().key() {
            TypedTableKey::CheckpointRootByCheckpoint(checkpoint) => *checkpoint,
            _ => return Err(RepresentativeStateReplayError::WrongTypedKey),
        };
        if checkpoint.get() != expected_checkpoint {
            return Err(RepresentativeStateReplayError::StateCheckpointMismatch {
                expected: expected_checkpoint,
                actual: checkpoint.get(),
            });
        }
        let sealed_checkpoint_root_pair = seal_commit_put_batch(
            LogicalMutation::CheckpointRootMapping {
                root: CheckpointRootKey::new(checkpoint_root.as_bytes().to_vec()),
                checkpoint,
            },
            prepared.commit_write_timestamp(),
        )?;
        for (sealed, persisted) in sealed_checkpoint_root_pair
            .members()
            .iter()
            .zip([&checkpoint_root_k1, &checkpoint_root_k2])
        {
            if sealed.resolved() != persisted {
                return Err(
                    RepresentativeStateReplayError::CheckpointRootPairMismatch,
                );
            }
        }
        let checkpoint_root_plan =
            CheckpointRootPairPutPlan::try_from_sealed(&sealed_checkpoint_root_pair)
                .map_err(|_| {
                    RepresentativeStateReplayError::CheckpointRootPairMismatch
                })?;
        for (sealed, value) in sealed_checkpoint_root_pair
            .members()
            .iter()
            .cloned()
            .zip(checkpoint_root_plan.expected_canonical_values())
        {
            rows.push(ExpectedStateRow {
                sealed,
                value,
                is_root: false,
            });
        }

        // Keep the pair contiguous behind root-covered state, then place the
        // mutable singleton last. The manifest digest remains over the
        // canonical physical batch; this is execution order only. The durable
        // authority head remains the actual final publish marker.
        rows.sort_by_key(|row| {
            match row.sealed.resolved().mutation().physical_table() {
                ScyllaPhysicalTableId::GlobalUserTree => 0,
                ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK1 => 1,
                ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK2 => 2,
                ScyllaPhysicalTableId::U64Singleton => 3,
                _ => 4,
            }
        });
        let checkpoint_root_pair_start = rows
            .iter()
            .position(|row| {
                row.sealed.resolved().mutation().physical_table()
                    == ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK1
            })
            .ok_or(RepresentativeStateReplayError::ExpectedCheckpointRootPair)?;
        if rows
            .get(checkpoint_root_pair_start + 1)
            .map(|row| row.sealed.resolved().mutation().physical_table())
            != Some(ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK2)
        {
            return Err(RepresentativeStateReplayError::CheckpointRootPairMismatch);
        }

        Ok(Self {
            prepared: prepared.clone(),
            rows,
            checkpoint_root_pair: ExpectedCheckpointRootPair {
                start: checkpoint_root_pair_start,
                sealed: sealed_checkpoint_root_pair,
            },
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
        if count == plan.checkpoint_root_pair.start + 1 {
            return Err(
                RepresentativeStateExecutionError::CheckpointRootPairPrefixSplit,
            );
        }
        let mut index = 0;
        while index < count {
            if index == plan.checkpoint_root_pair.start {
                self.store
                    .put_checkpoint_root_pair(&plan.checkpoint_root_pair.sealed)
                    .await?;
                index += 2;
                continue;
            }
            let sealed = &plan.rows[index].sealed;
            match sealed.resolved().mutation().physical_table() {
                ScyllaPhysicalTableId::GlobalUserTree => {
                    self.store.put_global_user_merkle(sealed).await?;
                }
                ScyllaPhysicalTableId::U64Singleton => {
                    self.store.put_latest_checkpoint(sealed).await?;
                }
                ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK1
                | ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK2 => {
                    return Err(
                        RepresentativeStateReplayError::CheckpointRootPairMismatch
                            .into(),
                    )
                }
                other => return Err(RepresentativeStateReplayError::UnsupportedPhysicalTable(other).into()),
            }
            index += 1;
        }
        Ok(())
    }

    pub async fn read_exact<Hash: Q256BitHash>(
        &self,
        plan: &RepresentativeRealmStateReplayPlan<Hash>,
    ) -> Result<Vec<Option<Vec<u8>>>, RepresentativeStateExecutionError> {
        let mut observed = Vec::with_capacity(plan.mutation_count());
        let mut index = 0;
        while index < plan.mutation_count() {
            if index == plan.checkpoint_root_pair.start {
                observed.extend(
                    self.store
                        .read_checkpoint_root_pair_exact(
                            &plan.checkpoint_root_pair.sealed,
                        )
                        .await?,
                );
                index += 2;
                continue;
            }
            let sealed = &plan.rows[index].sealed;
            let value = match sealed.resolved().mutation().physical_table() {
                ScyllaPhysicalTableId::GlobalUserTree => self.store.read_global_user_merkle_exact(sealed).await?,
                ScyllaPhysicalTableId::U64Singleton => self
                    .store
                    .read_latest_checkpoint_exact(sealed)
                    .await?
                    .map(|value| value.to_be_bytes().to_vec()),
                ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK1
                | ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK2 => {
                    return Err(
                        RepresentativeStateReplayError::CheckpointRootPairMismatch
                            .into(),
                    )
                }
                other => return Err(RepresentativeStateReplayError::UnsupportedPhysicalTable(other).into()),
            };
            observed.push(value);
            index += 1;
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
    CheckpointRootPairPrefixSplit,
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
    ExpectedCheckpointRootPair,
    DuplicateCheckpointRootDirection,
    CheckpointRootPairMismatch,
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
            CheckpointId as StorageCheckpointId, CheckpointRootKey,
            LogicalMutation, MerkleNode, MutationValue, NodeIndex,
            TypedTableKey, U64SingletonSlot,
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
        CanonicalPhysicalMutationBatch,
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
        let singleton = LogicalMutation::Put {
            key: TypedTableKey::U64Singleton(
                U64SingletonSlot::LatestCheckpoint,
            ),
            value: MutationValue::CqlU64(checkpoint.get()),
        };
        let checkpoint_root = LogicalMutation::CheckpointRootMapping {
            root: CheckpointRootKey::new(vec![0x44; 32]),
            checkpoint,
        };
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
            checkpoint_root.clone(),
            singleton.clone(),
        ];
        let full = CanonicalPhysicalMutationBatch::from_logical(logical).unwrap();
        let compact = PreparedReferencePlusSupplementRecord::try_v1(
            reference,
            DerivedSupplementBatch::from_logical(vec![
                checkpoint_root,
                singleton,
            ])
            .unwrap(),
            ReplayReceipt::new(
                ReplayAuthority::Realm,
                checkpoint,
                2,
                3,
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
            full,
        )
    }

    fn plan() -> RepresentativeRealmStateReplayPlan<PHash> {
        let (package, _, full) = fixture();
        let set = package.artifacts().chunked().unwrap();
        RepresentativeRealmStateReplayPlan::try_from_expanded_batch(
            package.record(),
            *set.mutation_digest(),
            full,
        )
        .unwrap()
    }

    #[test]
    fn compact_payload_becomes_exact_timestamped_replay_and_seal_evidence() {
        let plan = plan();
        assert_eq!(plan.mutation_count(), 5);
        assert_eq!(plan.checkpoint_root_pair.start, 2);
        assert_eq!(plan.checkpoint_root_pair.sealed.members().len(), 2);
        assert_eq!(
            plan.puts()
                .last()
                .unwrap()
                .resolved()
                .mutation()
                .physical_table(),
            ScyllaPhysicalTableId::U64Singleton
        );
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

        let child_index = plan
            .rows
            .iter()
            .position(|row| {
                !row.is_root
                    && row.sealed.resolved().mutation().physical_table()
                        == ScyllaPhysicalTableId::GlobalUserTree
            })
            .unwrap();
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
    fn singleton_supplement_is_required_even_when_every_merkle_row_matches() {
        let plan = plan();
        let singleton_index = plan
            .rows
            .iter()
            .position(|row| {
                row.sealed.resolved().mutation().physical_table()
                    == ScyllaPhysicalTableId::U64Singleton
            })
            .unwrap();
        let complete = plan
            .rows
            .iter()
            .map(|row| Some(row.value.clone()))
            .collect::<Vec<_>>();

        let mut missing = complete.clone();
        missing[singleton_index] = None;
        assert_eq!(
            plan.verify_observed_rows(&missing),
            Err(RepresentativeStateReplayError::PhysicalRowMissing {
                index: singleton_index,
            })
        );

        let mut wrong = complete;
        wrong[singleton_index] = Some(40_u64.to_be_bytes().to_vec());
        assert_eq!(
            plan.verify_observed_rows(&wrong),
            Err(RepresentativeStateReplayError::PhysicalRowValueMismatch {
                index: singleton_index,
            })
        );
    }

    #[test]
    fn both_checkpoint_root_directions_are_required() {
        let plan = plan();
        let complete = plan
            .rows
            .iter()
            .map(|row| Some(row.value.clone()))
            .collect::<Vec<_>>();
        for index in [
            plan.checkpoint_root_pair.start,
            plan.checkpoint_root_pair.start + 1,
        ] {
            let mut missing = complete.clone();
            missing[index] = None;
            assert_eq!(
                plan.verify_observed_rows(&missing),
                Err(RepresentativeStateReplayError::PhysicalRowMissing {
                    index,
                })
            );
        }
    }

    #[test]
    fn payload_not_covering_manifest_fails_before_any_put_is_executable() {
        let (package, payload, _) = fixture();
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
        let (package, _, _) = fixture();
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

        assert_eq!(
            executor
                .reapply_prefix_for_gate(
                    &plan,
                    plan.checkpoint_root_pair.start + 1,
                )
                .await,
            Err(
                RepresentativeStateExecutionError::CheckpointRootPairPrefixSplit
            )
        );
        assert!(store.recorded_calls().unwrap().is_empty());
    }
}
