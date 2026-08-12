//! Assemble the real Processor output into the checked, driver-independent
//! full-commit write set. No database mutation occurs in this module.

use std::collections::BTreeSet;

use parth_core::{
    crypto::hash::{
        merkle_proof::MerkleProofCore,
        traits::{FieldQHasher, MerkleHasher, MerkleZeroHasher},
    },
    data::hash::{
        merkle_node_key::SimpleMerkleNodeKey,
        merkle_store_key::{
            QMerkleStoreDoubleIdKeyWithHeight, QMerkleStoreSingleIdKey,
        },
    },
    protocol::core_types::{Q256BitHash, QFHashBase, QNetworkTypesConfig},
};
use parth_common::memory_stores::traits::PsyMemoryMerkleStoreImm;
use psy_data::{
    prepared_block::realm::{
        PsyPreparedRealmBlockStateUpdates, PsyRealmCoordinatorUpdate,
    },
    protocol::chain_context::{
        AuthorityObservation, AuthorityScope, AuthorityStateCheckpointId,
        AuthorityStateRoot,
    },
    v1::qdata::contract::{
        IMT_LEAF_FFS_ENTRY_SIZE_V2, deserialize_imt_leaf_ffs_entry_v2,
    },
};
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    p2p::traits::realm_coordinantor::RealmCoordinatorClient,
    psy_core_db::traits::full::{
        PsyNodeCoreRewardsTagTreeStoreReader,
        PsyNodeCoreRewardsTagTreeStoreWriter, PsyRealmProcessorStore,
    },
    psy_temp_db::StandardProcessorTempDBStoreBase,
    queue::{
        ephemeral::QStandardEphemeralQueueSubscriber,
        worker_queue::QStandardWorkerQueuePublisher,
    },
    store::{
        realm_full_commit_write_set::{
            RealmCommitLogicalDomainBatch, RealmFullCommitWriteSet,
            RealmImtCursorBeforeImage, RealmPreparedStateWriteSet,
        },
        realm_imt_mutation_graph::{
            RealmImtBaselineNodeKey, RealmImtContractHeightReadPlan,
            RealmImtMutationGraphConfig, RealmImtMutationGraphPlan,
        },
        realm_normal_commit_coverage::{
            RealmNormalCommitCoveragePlan, RealmNormalCommitWriteDomain,
        },
        traits::proof_store::QParthProofStore,
        typed::{
            CheckpointId, CheckpointRootKey, CheckpointedObjectKey,
            LatestInfoSlot, LogicalMutation, MerkleNode, MutationValue,
            NodeIndex, TreeId, TreeSubId, TypedTableKey, U64SingletonSlot,
        },
    },
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use super::PsyRealmDatabaseProcessor;

impl<
        N: QNetworkTypesConfig,
        S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash>
            + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash>
            + Send
            + Sync,
        GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync,
        ProofWorkQueue: QStandardWorkerQueuePublisher + Send + Sync,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
        ProofStore: QParthProofStore,
        FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
        CoordinatorClient: RealmCoordinatorClient<N::F, N::QHash> + Send + Sync,
    >
    PsyRealmDatabaseProcessor<
        N,
        S,
        STagTreeRewards,
        GUTAUpdateQueue,
        ProofWorkQueue,
        TempDatabase,
        ProofStore,
        FileSystem,
        CoordinatorClient,
    >
where
    N::HasherBase: FieldQHasher<N::F, N::QHash>
        + MerkleHasher<N::QHash>
        + MerkleZeroHasher<N::QHash>
        + 'static
        + Send
        + Sync,
    N::QHash: QFHashBase<N::F>,
{
    /// Read the exact predecessor state and construct every logical domain
    /// selected by the real Realm commit path. The returned value is data, not
    /// a storage authority; Scylla must still resolve it under the durable
    /// narrow-writer timestamp and identity.
    pub(in crate::realm::processor) async fn build_branch_exact_full_commit_write_set(
        &self,
        prepared: &PsyPreparedRealmBlockStateUpdates<N::QHash>,
        coordinator: &PsyRealmCoordinatorUpdate<N::F, N::QHash>,
    ) -> anyhow::Result<RealmFullCommitWriteSet> {
        self.validate_realm_sync_context(coordinator)?;
        let authority = AuthorityScope::Realm {
            realm_id: u32::try_from(self.state.realm_id_u64)?,
            realm_sub_id: u16::try_from(self.state.realm_sub_id_u64)?,
        };
        if prepared.realm_id != self.state.realm_id_u64
            || prepared.realm_sub_id != self.state.realm_sub_id_u64
            || coordinator.merkle_proof_to_realm_root.value
                != prepared.new_realm_root
        {
            anyhow::bail!("branch-exact full-commit source identity mismatch");
        }

        let coverage = RealmNormalCommitCoveragePlan::from_prepared(prepared);
        let prior = self.db.get_realm_authority_observation().await?;
        let prior = prior.ok_or_else(|| {
            anyhow::anyhow!("full Realm commit requires a predecessor authority observation")
        })?;
        if prior.authority() != authority
            || prior.state_root().as_inner() != &prepared.old_realm_root
        {
            anyhow::bail!("Realm predecessor authority observation mismatch");
        }
        let checkpoint = coordinator.checkpoint_sync_info.checkpoint_id;
        let state_checkpoint = if coverage.invokes_state_update_branch() {
            checkpoint
        } else {
            prior.state_checkpoint_id().get()
        };
        let prepared_state = if coverage.invokes_state_update_branch() {
            Some(
                self.build_prepared_state_write_set(
                    authority,
                    prior.state_checkpoint_id(),
                    AuthorityStateCheckpointId::new(checkpoint),
                    prepared,
                )
                .await?,
            )
        } else {
            None
        };

        let observation = AuthorityObservation::try_new(
            coordinator.canonical_chain_ref,
            authority,
            AuthorityStateCheckpointId::new(state_checkpoint),
            AuthorityStateRoot::from_local_state_root(prepared.new_realm_root),
        )?;
        let remaining = self.build_non_state_batches(coordinator, observation)?;
        Ok(RealmFullCommitWriteSet::try_new(
            prepared,
            remaining,
            prepared_state,
        )?)
    }

    async fn build_prepared_state_write_set(
        &self,
        authority: AuthorityScope,
        predecessor_checkpoint: AuthorityStateCheckpointId,
        state_checkpoint: AuthorityStateCheckpointId,
        prepared: &PsyPreparedRealmBlockStateUpdates<N::QHash>,
    ) -> anyhow::Result<RealmPreparedStateWriteSet> {
        let heights_plan = RealmImtContractHeightReadPlan::try_from_prepared(
            predecessor_checkpoint,
            prepared,
        )?;
        let heights = self
            .db
            .get_contract_tree_heights(
                predecessor_checkpoint.get(),
                heights_plan.contract_ids(),
            )
            .await?;
        let heights = heights_plan.bind_response(&heights)?;
        let graph = RealmImtMutationGraphPlan::<N::QHash, N::HasherBase>::try_from_bound_prepared::<N::F>(
            authority,
            predecessor_checkpoint,
            state_checkpoint,
            RealmImtMutationGraphConfig::try_new(
                N::GLOBAL_USER_TREE_HEIGHT,
                N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
                N::GLOBAL_CONTRACT_TREE_HEIGHT,
            )?,
            &heights,
            prepared,
        )?;

        let read_plan = graph.predecessor_read_plan();
        let mut observations = Vec::with_capacity(read_plan.requests().len());
        let mut global = Vec::new();
        let mut user_contract = Vec::new();
        let mut contract_state = Vec::new();
        for request in read_plan.requests().iter().copied() {
            match request.key() {
                RealmImtBaselineNodeKey::GlobalUser { level, index } => {
                    global.push((request, SimpleMerkleNodeKey { level, index }));
                }
                RealmImtBaselineNodeKey::UserContract {
                    user_id,
                    level,
                    index,
                } => user_contract.push((
                    request,
                    QMerkleStoreSingleIdKey {
                        tree_id: user_id,
                        level,
                        index,
                    },
                )),
                RealmImtBaselineNodeKey::ContractState {
                    user_id,
                    contract_id,
                    level,
                    index,
                } => contract_state.push((
                    request,
                    QMerkleStoreDoubleIdKeyWithHeight {
                        tree_id: user_id,
                        tree_sub_id: contract_id,
                        index,
                        level,
                        tree_height: request.tree_height(),
                    },
                )),
            }
        }
        let global_values = self
            .db
            .global_user_tree_get_nodes(
                predecessor_checkpoint.get(),
                &global.iter().map(|(_, key)| *key).collect::<Vec<_>>(),
            )
            .await?;
        bind_read_values(&mut observations, &global, &global_values)?;
        let user_contract_values = self
            .db
            .user_contract_tree_get_nodes(
                predecessor_checkpoint.get(),
                &user_contract.iter().map(|(_, key)| *key).collect::<Vec<_>>(),
            )
            .await?;
        bind_read_values(
            &mut observations,
            &user_contract,
            &user_contract_values,
        )?;
        let contract_state_values = self
            .db
            .contract_state_tree_get_nodes(
                predecessor_checkpoint.get(),
                &contract_state.iter().map(|(_, key)| *key).collect::<Vec<_>>(),
            )
            .await?;
        bind_read_values(
            &mut observations,
            &contract_state,
            &contract_state_values,
        )?;
        let sealed = graph.verify_and_seal(&observations)?;

        let mut cursor_pairs = BTreeSet::new();
        for chunk in prepared
            .update_contract_state_imt_leaves_ffs
            .chunks_exact(IMT_LEAF_FFS_ENTRY_SIZE_V2)
        {
            let (tree, tree_sub, ..) = deserialize_imt_leaf_ffs_entry_v2(chunk)?;
            cursor_pairs.insert((tree, tree_sub));
        }
        let mut cursors = Vec::with_capacity(cursor_pairs.len());
        for (tree, tree_sub) in cursor_pairs {
            cursors.push(RealmImtCursorBeforeImage::new(
                TreeId::new(tree),
                TreeSubId::new(tree_sub),
                self.db
                    .contract_state_imt_get_next_append_index(tree, tree_sub)
                    .await?,
            ));
        }
        Ok(RealmPreparedStateWriteSet::try_from_verified::<
            N::F,
            N::QHash,
            N::HasherBase,
        >(prepared, &sealed, cursors)?)
    }

    fn build_non_state_batches(
        &self,
        coordinator: &PsyRealmCoordinatorUpdate<N::F, N::QHash>,
        observation: AuthorityObservation<N::QHash>,
    ) -> anyhow::Result<Vec<RealmCommitLogicalDomainBatch>> {
        use RealmNormalCommitWriteDomain as D;

        let sync = &coordinator.checkpoint_sync_info;
        let checkpoint = CheckpointId::try_new(sync.checkpoint_id)?;
        let root = CheckpointRootKey::new(
            sync.checkpoint_tree_root.into_owned_32bytes().to_vec(),
        );
        let previous = self
            .checkpoint_tree_backup_manager
            .checkpoint_tree
            .get_leaf(sync.checkpoint_id)
            .to_append_proof::<N::HasherBase>();
        let checkpoint_proof = MerkleProofCore::new_from_params::<N::HasherBase>(
            sync.checkpoint_id,
            sync.checkpoint_leaf_hash,
            previous.siblings,
        );
        if checkpoint_proof.root != sync.checkpoint_tree_root {
            anyhow::bail!("Coordinator checkpoint root does not match local append proof");
        }
        let checkpoint_nodes = checkpoint_proof
            .get_all_merkle_nodes_and_verify::<N::HasherBase>()?
            .into_iter()
            .map(|node| LogicalMutation::Put {
                key: TypedTableKey::GlobalCheckpointMerkle {
                    node: MerkleNode::new(
                        node.key.level,
                        NodeIndex::new(node.key.index),
                    ),
                    checkpoint,
                },
                value: MutationValue::PsyCanonicalBytes(
                    node.value.into_owned_32bytes().to_vec(),
                ),
            })
            .collect::<Vec<_>>();
        let root_mapping = LogicalMutation::CheckpointRootMapping {
            root,
            checkpoint,
        };

        Ok(vec![
            batch(
                D::GlobalUserTopProofAtCheckpoint,
                LogicalMutation::Put {
                    key: TypedTableKey::CheckpointedObject(
                        CheckpointedObjectKey::GlobalUserProofAtCheckpoint(
                            checkpoint,
                        ),
                    ),
                    value: canonical(&coordinator.merkle_proof_to_realm_root)?,
                },
            ),
            batch(
                D::CheckpointStateRoots,
                LogicalMutation::Put {
                    key: TypedTableKey::CheckpointStateRoots(checkpoint),
                    value: canonical(&sync.state_roots)?,
                },
            ),
            batch(
                D::CheckpointLeaf,
                LogicalMutation::Put {
                    key: TypedTableKey::CheckpointLeaf(checkpoint),
                    value: canonical(&sync.checkpoint_leaf)?,
                },
            ),
            RealmCommitLogicalDomainBatch::new(
                D::GlobalCheckpointMerkle,
                checkpoint_nodes,
            ),
            batch(D::CheckpointRootByHash, root_mapping.clone()),
            batch(D::CheckpointRootByCheckpoint, root_mapping),
            batch(
                D::L2BlockState,
                LogicalMutation::Put {
                    key: TypedTableKey::L2BlockState(checkpoint),
                    value: canonical(&sync.block_state)?,
                },
            ),
            batch(
                D::LatestCheckpoint,
                LogicalMutation::Put {
                    key: TypedTableKey::U64Singleton(
                        U64SingletonSlot::LatestCheckpoint,
                    ),
                    value: MutationValue::CqlU64(checkpoint.get()),
                },
            ),
            batch(
                D::LatestL2BlockState,
                LogicalMutation::Put {
                    key: TypedTableKey::LatestInfo(
                        LatestInfoSlot::LatestL2BlockState,
                    ),
                    value: canonical(&sync.block_state)?,
                },
            ),
            batch(
                D::RealmAuthorityObservation,
                LogicalMutation::Put {
                    key: TypedTableKey::LatestInfo(
                        LatestInfoSlot::RealmAuthorityObservation,
                    ),
                    value: MutationValue::PsyCanonicalBytes(
                        observation.to_canonical_bytes().to_vec(),
                    ),
                },
            ),
        ])
    }
}

fn bind_read_values<Key, Hash: Copy>(
    output: &mut Vec<(RealmImtBaselineNodeKey, Hash)>,
    requests: &[(
        psy_node_core::store::realm_imt_mutation_graph::RealmImtPredecessorReadRequest,
        Key,
    )],
    values: &[Hash],
) -> anyhow::Result<()> {
    if requests.len() != values.len() {
        anyhow::bail!(
            "predecessor Merkle response count mismatch: expected {}, got {}",
            requests.len(),
            values.len(),
        );
    }
    output.extend(
        requests
            .iter()
            .zip(values)
            .map(|((request, _), value)| (request.key(), *value)),
    );
    Ok(())
}

fn batch(
    domain: RealmNormalCommitWriteDomain,
    mutation: LogicalMutation,
) -> RealmCommitLogicalDomainBatch {
    RealmCommitLogicalDomainBatch::new(domain, vec![mutation])
}

fn canonical<T: PsyCanonicalDatabaseSerializeBaseSingle>(
    value: &T,
) -> anyhow::Result<MutationValue> {
    Ok(MutationValue::PsyCanonicalBytes(
        value.psy_ser_to_bytes_vec()?,
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn real_processor_full_commit_builder_reads_predecessors_and_covers_non_state_domains() {
        let source = include_str!("full_commit.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        for required in [
            "get_realm_authority_observation",
            "get_contract_tree_heights",
            "global_user_tree_get_nodes",
            "user_contract_tree_get_nodes",
            "contract_state_tree_get_nodes",
            "contract_state_imt_get_next_append_index",
            "RealmImtMutationGraphPlan::<N::QHash, N::HasherBase>::try_from_bound_prepared",
            "RealmPreparedStateWriteSet::try_from_verified",
        ] {
            assert!(source.contains(required), "missing exact read/build step: {required}");
        }
        for domain in [
            "GlobalUserTopProofAtCheckpoint",
            "CheckpointStateRoots",
            "CheckpointLeaf",
            "GlobalCheckpointMerkle",
            "CheckpointRootByHash",
            "CheckpointRootByCheckpoint",
            "L2BlockState",
            "LatestCheckpoint",
            "LatestL2BlockState",
            "RealmAuthorityObservation",
        ] {
            assert!(source.contains(domain), "missing logical domain: {domain}");
        }
        for forbidden in [
            "commit_state(",
            "write_and_verify(",
            "publish_authority_head(",
            "seal_rotation(",
        ] {
            assert!(!source.contains(forbidden), "builder must remain read-only: {forbidden}");
        }
    }
}
