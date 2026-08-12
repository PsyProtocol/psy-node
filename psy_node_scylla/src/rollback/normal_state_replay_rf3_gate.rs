use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    process::Command,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, ensure, Context};
use futures::future::join_all;
use parth_core::{
    crypto::hash::{
        merkle_proof::MerkleProofCore,
        traits::{MerkleHasher, MerkleZeroHasher, QFieldHashable},
    },
    data::hash::{
        merkle_node_key::SimpleMerkleNode,
        merkle_store_key::{
            QMerkleStoreDoubleIdKey, QMerkleStoreDoubleIdNode,
            QMerkleStoreSingleIdKey, QMerkleStoreSingleIdNode,
        },
    },
    felt::{FromPrimitiveValuesFelt, ToU64Value, ZeroableFelt},
    pgoldilocks::PoseidonHasher,
    protocol::core_types::{
        Q256BitHash, QZKProofPublicInputsHasherReader, QZKProofVerifier,
    },
    PHash, PF, QCoreProcCheckpointUniqueId,
};
use psy_data::{
    guta::{
        header::GlobalUserTreeAggregatorHeader,
        header_extended::{
            GlobalUserTreeAggregatorHeaderWithTagValue,
            GlobalUserTreeAggregatorHeaderWithTagValueAndJobType,
        },
        stats::GUTAStats,
        sub_tree_transition::SubTreeNodeStateTransition,
    },
    prepared_block::realm::{
        PsyPreparedRealmBlockStateUpdates, PsyRealmCoordinatorUpdate,
    },
    protocol::{
        canonical_chain::{
            CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
            CheckpointRef, NetworkId,
        },
        chain_context::{
            AuthorityScope, AuthorityStateCheckpointId, AuthorityStateRoot,
        },
    },
    v1::qdata::{
        checkpoint::{
            PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf,
            PQEDCheckpointLeafStats, QEDL2BlockState,
        },
        checkpoint_sync::PQEDCheckpointSyncInfoCompact,
        contract::{serialize_imt_leaf_ffs_entry_v2, IMTContractStateLeaf},
        user::PQEDUserLeaf,
    },
};
use psy_node_core::store::{
    authority_commit::{
        AuthorityClockSampleUs, AuthorityTimestampBootstrap,
        AuthorityTimestampBootstrapReason, AuthorityTimestampKey,
        AuthorityTimestampWriteOutcome, ObservedAuthorityTimestampState,
        SealedAuthorityTimestampReservation,
    },
    authority_local_head::{
        AuthorityLocalHeadBootstrap, AuthorityLocalHeadBootstrapReason,
        AuthorityLocalHeadWriteOutcome, AuthorityStorageBindingGeneration,
        AuthorityStorageBindingRef, AuthorityStorageNamespaceId,
        StoredAuthorityLocalHead,
    },
    manifest_intent::{
        AuthorityHeadPayload, AuthorityStateTransition,
        SealedAuthorityCommitIntent,
    },
    manifest_lifecycle::{
        AuthorityHeadPayloadDigest, AuthorityHeadView,
        AuthorityPostWriteObservation, AuthorityProofObservation,
        ManifestLifecycleError, PersistedAuthorityManifest,
        SealedAuthorityManifest,
    },
    manifest_record::AuthorityManifestIdentity,
    normal_commit::{
        plan_normal_commit_recovery, NormalCommitOrchestrationError,
        NormalCommitRecoveryAction, NormalHeadPublishProgress,
        SealedNormalHeadPublish,
    },
    realm_commit_evidence::SealedRealmCommitEvidence,
    realm_commit_evidence_assembly::RealmCommitEvidenceAssemblyPlan,
    realm_imt_mutation_graph::{
        RealmImtBaselineNodeKey, RealmImtContractHeightReadPlan,
        RealmImtMutationGraphConfig, RealmImtPredecessorReadRow,
    },
    realm_manifest_evidence::SealedRealmManifestEvidence,
    timestamp::CommitWriteTimestampUs,
    typed::{
        CheckpointId as StorageCheckpointId, CheckpointRootKey,
        ImtEncodedKey, ImtKeyIndexRow, LeafIndex, LogicalMutation, MerkleNode,
        MutationValue, NodeIndex, StructuredValueSchema,
        TreeId, TreeSubId, TypedTableKey, U64SingletonSlot,
    },
};
use psy_serialize::FastFixedSerializable;
use scylla::{
    client::{
        execution_profile::ExecutionProfile, session::Session,
        session_builder::SessionBuilder,
    },
    policies::load_balancing::{
        NodeIdentifier, SingleTargetLoadBalancingPolicy,
    },
    statement::Consistency,
};
use serde::Serialize;
use tokio::time::sleep;

use super::*;
use super::realm_full_commit_scylla::{
    RealmFullCommitScyllaExecutor, validate_schedule_write_plan,
};
use crate::utils::{
    convert_checkpoint_id_to_i64, i64_to_u64_exact, u64_to_i64_exact,
    u8_to_i8_exact,
};

const CONTROL_KEYSPACE: &str = "psy_d04b2c_rf3_nt";
const ARTIFACT_KEYSPACE: &str = "psy_d04b2c_rf3_artifacts";
const STATE_KEYSPACE: &str = "psy_d04b2c_rf3_state";
const BASELINE: &str = "133b412755e0241c83b496ff023eff07180f120d";
const IMAGE: &str = "scylladb/scylla@sha256:17496f2dd6e72056d0b0d7e2bd18bd62638872d1d80a5dd9db96ba017fd426fc";
const NODE_IPS: [Ipv4Addr; 3] = [
    Ipv4Addr::new(172, 29, 86, 11),
    Ipv4Addr::new(172, 29, 86, 12),
    Ipv4Addr::new(172, 29, 86, 13),
];
const NODE_CONTAINERS: [&str; 3] = [
    "psy-g0-02-rf3-scylla1-1",
    "psy-g0-02-rf3-scylla2-1",
    "psy-g0-02-rf3-scylla3-1",
];
const EVIDENCE_GLOBAL_HEIGHT: u8 = 4;
const EVIDENCE_COORDINATOR_HEIGHT: u8 = 2;
const EVIDENCE_UCT_HEIGHT: u8 = 3;
const EVIDENCE_CST_HEIGHT: u8 = 3;
const EVIDENCE_REALM_SUB_ID: u64 = 2;
const EVIDENCE_CONTRACT_ID: u64 = 2;
const EVIDENCE_IMT_INDEX: u64 = 3;
const EVIDENCE_PREDECESSOR: u64 = 40;
const EVIDENCE_STATE: u64 = 41;

fn hash(seed: u8) -> PHash {
    PHash::from_owned_32bytes([seed; 32])
}

fn network() -> NetworkId {
    NetworkId::try_from_chain_id(1337).expect("RF=3 network is configured")
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

fn evidence_levels(mut leaves: Vec<PHash>, height: u8) -> Vec<Vec<PHash>> {
    assert_eq!(leaves.len(), 1usize << height);
    let mut result = vec![Vec::new(); usize::from(height) + 1];
    result[usize::from(height)] = std::mem::take(&mut leaves);
    for level in (0..usize::from(height)).rev() {
        result[level] = result[level + 1]
            .chunks_exact(2)
            .map(|pair| PoseidonHasher::two_to_one(&pair[0], &pair[1]))
            .collect();
    }
    result
}

fn evidence_simple_path(
    tree: &[Vec<PHash>],
    height: u8,
    index: u64,
    min_level: u8,
) -> Vec<SimpleMerkleNode<PHash>> {
    (min_level..=height)
        .rev()
        .map(|level| {
            let at_level = index >> (height - level);
            SimpleMerkleNode::new(
                level,
                at_level,
                tree[usize::from(level)][at_level as usize],
            )
        })
        .collect()
}

fn evidence_single_path(
    tree: &[Vec<PHash>],
    height: u8,
    tree_id: u64,
    index: u64,
) -> Vec<QMerkleStoreSingleIdNode<PHash>> {
    (0..=height)
        .rev()
        .map(|level| {
            let at_level = index >> (height - level);
            QMerkleStoreSingleIdNode {
                key: QMerkleStoreSingleIdKey {
                    tree_id,
                    level,
                    index: at_level,
                },
                value: tree[usize::from(level)][at_level as usize],
            }
        })
        .collect()
}

fn evidence_double_path(
    tree: &[Vec<PHash>],
    height: u8,
    tree_id: u64,
    tree_sub_id: u64,
    index: u64,
) -> Vec<QMerkleStoreDoubleIdNode<PHash>> {
    (0..=height)
        .rev()
        .map(|level| {
            let at_level = index >> (height - level);
            QMerkleStoreDoubleIdNode {
                key: QMerkleStoreDoubleIdKey {
                    tree_id,
                    tree_sub_id,
                    level,
                    index: at_level,
                },
                value: tree[usize::from(level)][at_level as usize],
            }
        })
        .collect()
}

fn evidence_encode_ffs<const N: usize, T: FastFixedSerializable<N>>(
    values: &[T],
) -> Vec<u8> {
    let mut result = Vec::with_capacity(values.len() * N);
    for value in values {
        result.extend_from_slice(&value.ffs_to_bytes());
    }
    result
}

fn evidence_inclusion_siblings(
    tree: &[Vec<PHash>],
    level: u8,
    mut index: u64,
) -> Vec<PHash> {
    let mut siblings = Vec::with_capacity(usize::from(level));
    for at_level in (1..=level).rev() {
        siblings.push(tree[usize::from(at_level)][(index ^ 1) as usize]);
        index >>= 1;
    }
    siblings
}

#[derive(Clone, Copy, Debug)]
struct DeterministicEvidenceProofVerifier;

impl QZKProofPublicInputsHasherReader<PHash, PHash>
    for DeterministicEvidenceProofVerifier
{
    fn get_proof_public_inputs_hash(proof: &PHash) -> anyhow::Result<PHash> {
        Ok(*proof)
    }

    fn try_proof_from_slice(bytes: &[u8]) -> anyhow::Result<PHash> {
        Ok(PHash::from_owned_32bytes(bytes.try_into()?))
    }
}

impl QZKProofVerifier<PHash, PHash> for DeterministicEvidenceProofVerifier {
    fn verify_zk_proof(
        &self,
        _circuit_type: u32,
        proof: &PHash,
    ) -> anyhow::Result<PHash> {
        Ok(*proof)
    }
}

struct RealmEvidenceFixture {
    authority: AuthorityScope,
    prepared: PsyPreparedRealmBlockStateUpdates<PHash>,
    submission: GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<PF, PHash>,
    proof_bytes: Vec<u8>,
    coordinator: PsyRealmCoordinatorUpdate<PF, PHash>,
    baseline: BTreeMap<RealmImtBaselineNodeKey, PHash>,
    with_imt_preimage: bool,
}

impl RealmEvidenceFixture {
    fn assembly_plan(
        &self,
    ) -> anyhow::Result<
        RealmCommitEvidenceAssemblyPlan<PHash, PoseidonHasher>,
    > {
        let height_plan = RealmImtContractHeightReadPlan::try_from_prepared(
            AuthorityStateCheckpointId::new(EVIDENCE_PREDECESSOR),
            &self.prepared,
        )?;
        let heights = height_plan.bind_response(
            &height_plan
                .contract_ids()
                .iter()
                .map(|contract_id| {
                    assert_eq!(*contract_id, EVIDENCE_CONTRACT_ID);
                    EVIDENCE_CST_HEIGHT
                })
                .collect::<Vec<_>>(),
        )?;
        Ok(RealmCommitEvidenceAssemblyPlan::try_new::<
            PF,
            PHash,
            DeterministicEvidenceProofVerifier,
        >(
            self.authority,
            AuthorityStateCheckpointId::new(EVIDENCE_PREDECESSOR),
            RealmImtMutationGraphConfig::try_new(
                EVIDENCE_GLOBAL_HEIGHT,
                EVIDENCE_COORDINATOR_HEIGHT,
                EVIDENCE_UCT_HEIGHT,
            )?,
            &heights,
            &self.prepared,
            &self.submission,
            &self.proof_bytes,
            &DeterministicEvidenceProofVerifier,
            &self.coordinator,
        )?)
    }
}

fn realm_evidence_fixture(
    realm_id: u64,
    user_id: u64,
    offset: u8,
    with_imt_preimage: bool,
) -> RealmEvidenceFixture {
    realm_evidence_fixture_from_offsets(
        realm_id,
        user_id,
        offset,
        offset,
        with_imt_preimage,
    )
}

/// Build one changed-Realm evidence graph while allowing two competing
/// candidates to share the exact predecessor state. `old_state_offset`
/// controls every predecessor leaf; `mutation_offset` controls the proposed
/// mutation, proof inputs and candidate checkpoint hash.
fn realm_evidence_fixture_from_offsets(
    realm_id: u64,
    user_id: u64,
    old_state_offset: u8,
    mutation_offset: u8,
    with_imt_preimage: bool,
) -> RealmEvidenceFixture {
    assert_eq!(
        user_id >> (EVIDENCE_GLOBAL_HEIGHT - EVIDENCE_COORDINATOR_HEIGHT),
        realm_id,
    );
    let old_seeded = |seed: u8| hash(seed.wrapping_add(old_state_offset));
    let mutation_seeded =
        |seed: u8| hash(seed.wrapping_add(mutation_offset));
    let imt_preimage = IMTContractStateLeaf::<PF, PHash> {
        key: mutation_seeded(1),
        value: mutation_seeded(2),
        next_key: mutation_seeded(3),
        next_index: PF::from_u64_value(1),
    };
    let imt_hash = imt_preimage.qfhash::<PoseidonHasher>();

    let mut cst_old_leaves = (0..(1u8 << EVIDENCE_CST_HEIGHT))
        .map(|i| old_seeded(20 + i))
        .collect::<Vec<_>>();
    cst_old_leaves[2] = PoseidonHasher::get_zero_hash(0);
    let cst_old = evidence_levels(cst_old_leaves.clone(), EVIDENCE_CST_HEIGHT);
    cst_old_leaves[EVIDENCE_IMT_INDEX as usize] = imt_hash;
    let cst_new = evidence_levels(cst_old_leaves, EVIDENCE_CST_HEIGHT);

    let mut uct_old_leaves = (0..(1u8 << EVIDENCE_UCT_HEIGHT))
        .map(|i| old_seeded(40 + i))
        .collect::<Vec<_>>();
    uct_old_leaves[EVIDENCE_CONTRACT_ID as usize] = cst_old[0][0];
    let uct_old = evidence_levels(uct_old_leaves.clone(), EVIDENCE_UCT_HEIGHT);
    uct_old_leaves[EVIDENCE_CONTRACT_ID as usize] = cst_new[0][0];
    let uct_new = evidence_levels(uct_old_leaves, EVIDENCE_UCT_HEIGHT);

    let old_user = PQEDUserLeaf::<PF, PHash> {
        public_key: old_seeded(60),
        user_state_tree_root: uct_old[0][0],
        balance: PF::from_u64_value(10),
        nonce: PF::ZERO_VALUE,
        last_checkpoint_id: PF::from_u64_value(EVIDENCE_PREDECESSOR),
        event_index: PF::ZERO_VALUE,
        user_id: PF::from_u64_value(user_id),
    };
    let new_user = PQEDUserLeaf::<PF, PHash> {
        user_state_tree_root: uct_new[0][0],
        nonce: PF::from_u64_value(1),
        last_checkpoint_id: PF::from_u64_value(EVIDENCE_STATE),
        ..old_user
    };
    let mut gut_old_leaves = (0..(1u8 << EVIDENCE_GLOBAL_HEIGHT))
        .map(|i| old_seeded(80 + i))
        .collect::<Vec<_>>();
    gut_old_leaves[user_id as usize] = old_user.qfhash::<PoseidonHasher>();
    let gut_old = evidence_levels(gut_old_leaves.clone(), EVIDENCE_GLOBAL_HEIGHT);
    gut_old_leaves[user_id as usize] = new_user.qfhash::<PoseidonHasher>();
    let gut_new = evidence_levels(gut_old_leaves, EVIDENCE_GLOBAL_HEIGHT);
    let old_realm_root = gut_old[usize::from(EVIDENCE_COORDINATOR_HEIGHT)]
        [realm_id as usize];
    let new_realm_root = gut_new[usize::from(EVIDENCE_COORDINATOR_HEIGHT)]
        [realm_id as usize];

    let mut prepared = PsyPreparedRealmBlockStateUpdates {
        realm_id,
        realm_sub_id: EVIDENCE_REALM_SUB_ID,
        unique_pending_id: 90 + realm_id,
        proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId::from(
            91u128 + u128::from(realm_id),
        ),
        old_realm_root,
        new_realm_root,
        update_global_user_tree_nodes_ffs: evidence_encode_ffs(
            &evidence_simple_path(
                &gut_new,
                EVIDENCE_GLOBAL_HEIGHT,
                user_id,
                EVIDENCE_COORDINATOR_HEIGHT,
            ),
        ),
        update_user_contract_tree_nodes_ffs: evidence_encode_ffs(
            &evidence_single_path(
                &uct_new,
                EVIDENCE_UCT_HEIGHT,
                user_id,
                EVIDENCE_CONTRACT_ID,
            ),
        ),
        update_contract_state_tree_nodes_ffs: evidence_encode_ffs(
            &evidence_double_path(
                &cst_new,
                EVIDENCE_CST_HEIGHT,
                user_id,
                EVIDENCE_CONTRACT_ID,
                EVIDENCE_IMT_INDEX,
            ),
        ),
        update_user_leaves_ffs: new_user.ffs_to_bytes().to_vec(),
        update_contract_state_imt_leaves_ffs:
            serialize_imt_leaf_ffs_entry_v2(
                user_id,
                EVIDENCE_CONTRACT_ID,
                EVIDENCE_IMT_INDEX,
                &imt_hash,
                &imt_preimage.key,
                &imt_preimage.value,
                &imt_preimage.next_key,
                imt_preimage.next_index.to_u64_value(),
                false,
            )
            .to_vec(),
    };
    if !with_imt_preimage {
        prepared.update_contract_state_imt_leaves_ffs.clear();
    }

    let submission = GlobalUserTreeAggregatorHeaderWithTagValueAndJobType {
        header: GlobalUserTreeAggregatorHeaderWithTagValue {
            header: GlobalUserTreeAggregatorHeader {
                guta_circuit_whitelist: mutation_seeded(120),
                checkpoint_tree_root: mutation_seeded(121),
                state_transition: SubTreeNodeStateTransition {
                    old_node_value: old_realm_root,
                    new_node_value: new_realm_root,
                    node_index: PF::from_u64_value(realm_id),
                    node_level: PF::from_u64_value(u64::from(
                        EVIDENCE_COORDINATOR_HEIGHT,
                    )),
                },
                stats: GUTAStats::get_zero_value(),
                total_aggregation_proofs_generated: PF::from_u64_value(5),
            },
            new_tag_tree_node_value: mutation_seeded(122),
        },
        // Stable wire discriminant for `ProvingJobCircuitType::GUTASingleEndCap`.
        job_type_u32: 11,
    };
    let proof_bytes = submission
        .qfhash::<PoseidonHasher>()
        .into_owned_32bytes()
        .to_vec();
    let inclusion = MerkleProofCore::new_from_params::<PoseidonHasher>(
        realm_id,
        new_realm_root,
        evidence_inclusion_siblings(
            &gut_new,
            EVIDENCE_COORDINATOR_HEIGHT,
            realm_id,
        ),
    );
    assert_eq!(inclusion.root, gut_new[0][0]);
    let state_roots = PQEDCheckpointGlobalStateRoots {
        contract_tree_root: mutation_seeded(130),
        deposit_tree_root: mutation_seeded(131),
        user_tree_root: inclusion.root,
        withdrawal_tree_root: mutation_seeded(132),
        user_registration_tree_root: mutation_seeded(133),
    };
    let checkpoint_leaf = PQEDCheckpointLeaf {
        global_chain_root: state_roots.qfhash::<PoseidonHasher>(),
        stats: PQEDCheckpointLeafStats::<PF, PHash>::get_empty_stats(),
    };
    let checkpoint_leaf_hash = checkpoint_leaf.qfhash::<PoseidonHasher>();
    let mut block_state = QEDL2BlockState::get_genesis_value();
    block_state.checkpoint_id = EVIDENCE_STATE;
    let coordinator = PsyRealmCoordinatorUpdate {
        canonical_chain_ref: CanonicalChainRef::new(
            network(),
            ChainEpoch::new(7),
            CheckpointRef::new(
                CheckpointId::new(EVIDENCE_STATE),
                CheckpointHash::from_proof_public_inputs_hash(
                    mutation_seeded(140),
                ),
            ),
        ),
        checkpoint_sync_info: PQEDCheckpointSyncInfoCompact {
            checkpoint_id: EVIDENCE_STATE,
            coordinator_id: 0,
            coordinator_sub_id: 0,
            coordinator_unique_pending_id: 80,
            block_state,
            state_roots,
            checkpoint_leaf,
            checkpoint_leaf_hash,
            checkpoint_tree_root: mutation_seeded(141),
        },
        merkle_proof_to_realm_root: inclusion,
        reward_tree_top_proof:
            parth_core::crypto::hash::tag_tree::TagTreeMerkleProof::new_empty(),
    };

    let mut baseline = BTreeMap::new();
    for level in 0..=EVIDENCE_GLOBAL_HEIGHT {
        for (index, value) in gut_old[usize::from(level)].iter().enumerate() {
            baseline.insert(
                RealmImtBaselineNodeKey::GlobalUser {
                    level,
                    index: index as u64,
                },
                *value,
            );
        }
    }
    for level in 0..=EVIDENCE_UCT_HEIGHT {
        for (index, value) in uct_old[usize::from(level)].iter().enumerate() {
            baseline.insert(
                RealmImtBaselineNodeKey::UserContract {
                    user_id,
                    level,
                    index: index as u64,
                },
                *value,
            );
        }
    }
    for level in 0..=EVIDENCE_CST_HEIGHT {
        for (index, value) in cst_old[usize::from(level)].iter().enumerate() {
            baseline.insert(
                RealmImtBaselineNodeKey::ContractState {
                    user_id,
                    contract_id: EVIDENCE_CONTRACT_ID,
                    level,
                    index: index as u64,
                },
                *value,
            );
        }
    }

    RealmEvidenceFixture {
        authority: AuthorityScope::Realm {
            realm_id: realm_id as u32,
            realm_sub_id: EVIDENCE_REALM_SUB_ID as u16,
        },
        prepared,
        submission,
        proof_bytes,
        coordinator,
        baseline,
        with_imt_preimage,
    }
}

fn imt_row(
    tree: u64,
    tree_sub: u64,
    leaf: u64,
    seed: u8,
    leaf_key: [u8; 32],
) -> Vec<u8> {
    let mut bytes = vec![0_u8; 161];
    bytes[0..8].copy_from_slice(&tree.to_le_bytes());
    bytes[8..16].copy_from_slice(&tree_sub.to_le_bytes());
    bytes[16..24].copy_from_slice(&leaf.to_le_bytes());
    bytes[24..56].copy_from_slice(&[seed; 32]);
    bytes[56..88].copy_from_slice(&leaf_key);
    bytes[88..120].copy_from_slice(&[seed.wrapping_add(1); 32]);
    bytes[120..152].copy_from_slice(&[seed.wrapping_add(2); 32]);
    bytes[152..160].copy_from_slice(&(leaf + 1).to_le_bytes());
    bytes[160] = 1;
    bytes
}

struct Fixture {
    timestamp_bootstrap: AuthorityTimestampBootstrap,
    reservation: SealedAuthorityTimestampReservation,
    head_bootstrap: AuthorityLocalHeadBootstrap<PHash>,
    package: VerifiedPreparedManifestPackage<PHash>,
}

impl Fixture {
    fn identity(&self) -> AuthorityManifestIdentity<PHash> {
        *self.package.record().identity()
    }
}

fn assemble_realm_evidence_from_fixture(
    fixture: &RealmEvidenceFixture,
) -> anyhow::Result<SealedRealmCommitEvidence<PHash, PoseidonHasher>> {
    let plan = fixture.assembly_plan()?;
    let zero_hashes = (0..64)
        .map(PoseidonHasher::get_zero_hash)
        .collect::<Vec<_>>();
    let rows = plan
        .predecessor_read_plan()
        .requests()
        .iter()
        .map(|request| {
            let expected = fixture.baseline[&request.key()];
            RealmImtPredecessorReadRow::new(
                *request,
                (!zero_hashes.contains(&expected)).then_some(expected),
            )
        })
        .collect::<Vec<_>>();
    Ok(plan.verify_predecessor_rows_and_seal(&rows)?)
}

fn seal_fixture_for_head_gate(
    fixture: &Fixture,
    bundle: SealedRealmCommitEvidence<PHash, PoseidonHasher>,
) -> anyhow::Result<SealedAuthorityManifest<PHash>> {
    let prepared = fixture.package.record().clone();
    let observation = AuthorityPostWriteObservation::new(
        AuthorityHeadView::candidate(&prepared),
        prepared.intent().artifacts().mutation_digest(),
        AuthorityHeadPayloadDigest::from_verified_payload_bytes(
            prepared.intent().head_payload().as_bytes(),
        ),
        AuthorityProofObservation::NotApplicableForRealm,
    );
    let supplement = SealedRealmManifestEvidence::try_bind(&prepared, bundle)?;
    Ok(SealedAuthorityManifest::verify_and_seal(
        prepared,
        observation.attach_changed_realm_evidence(supplement),
    )?)
}

fn publish_fixture_for_head_gate(
    fixture: &Fixture,
    sealed: &SealedAuthorityManifest<PHash>,
    expected: &StoredAuthorityLocalHead<PHash>,
) -> SealedNormalHeadPublish<PHash> {
    let allocator = ObservedAuthorityTimestampState::from_selected_row(
        fixture.package.record().identity().timestamp_key(),
        fixture.reservation.candidate(),
    );
    match plan_normal_commit_recovery(
        &PersistedAuthorityManifest::Sealed(sealed.clone()),
        expected,
        allocator,
    )
    .unwrap()
    {
        NormalCommitRecoveryAction::PublishExactHead { publish } => publish,
        other => panic!("unexpected conflict-gate plan: {other:?}"),
    }
}

fn fixture(
    realm_id: u32,
    checkpoint_id: u64,
    seed: u8,
    high_water: i64,
) -> Fixture {
    fixture_from_seeds(
        realm_id,
        checkpoint_id,
        seed,
        seed.wrapping_add(1),
        seed.wrapping_add(2),
        seed.wrapping_add(3),
        seed,
        high_water,
        seed.wrapping_add(6),
    )
}

#[allow(clippy::too_many_arguments)]
fn fixture_from_seeds(
    realm_id: u32,
    checkpoint_id: u64,
    expected_chain_seed: u8,
    candidate_chain_seed: u8,
    old_root_seed: u8,
    new_root_seed: u8,
    payload_seed: u8,
    high_water: i64,
    namespace_seed: u8,
) -> Fixture {
    fixture_from_commit_identity(
        AuthorityScope::Realm {
            realm_id,
            realm_sub_id: 2,
        },
        chain(checkpoint_id - 1, expected_chain_seed),
        chain(checkpoint_id, candidate_chain_seed),
        hash(old_root_seed),
        hash(new_root_seed),
        payload_seed,
        high_water,
        namespace_seed,
        true,
    )
}

fn fixture_for_realm_evidence(
    evidence: &RealmEvidenceFixture,
    payload_seed: u8,
    high_water: i64,
    namespace_seed: u8,
) -> Fixture {
    fixture_from_commit_identity(
        evidence.authority,
        CanonicalChainRef::new(
            network(),
            evidence.coordinator.canonical_chain_ref.chain_epoch(),
            CheckpointRef::new(
                CheckpointId::new(EVIDENCE_PREDECESSOR),
                CheckpointHash::from_last_chain_hash(hash(199)),
            ),
        ),
        evidence.coordinator.canonical_chain_ref,
        evidence.prepared.old_realm_root,
        evidence.prepared.new_realm_root,
        payload_seed,
        high_water,
        namespace_seed,
        evidence.with_imt_preimage,
    )
}

#[allow(clippy::too_many_arguments)]
fn fixture_from_commit_identity(
    authority: AuthorityScope,
    expected_chain: CanonicalChainRef<PHash>,
    candidate_chain: CanonicalChainRef<PHash>,
    old_root: PHash,
    new_root: PHash,
    payload_seed: u8,
    high_water: i64,
    namespace_seed: u8,
    include_imt: bool,
) -> Fixture {
    let checkpoint_id = candidate_chain.checkpoint().checkpoint_id().get();
    let checkpoint = StorageCheckpointId::try_new(checkpoint_id).unwrap();
    let semantic = [
        (
            MerkleNode::new(0, NodeIndex::new(0)),
            new_root.into_owned_32bytes().to_vec(),
        ),
        (
            MerkleNode::new(1, NodeIndex::new(0)),
            vec![payload_seed.wrapping_add(1); 32],
        ),
        (
            MerkleNode::new(1, NodeIndex::new(1)),
            vec![payload_seed.wrapping_add(2); 32],
        ),
    ];
    let realm_id = match authority {
        AuthorityScope::Realm { realm_id, .. } => realm_id,
        AuthorityScope::Coordinator => panic!("Realm fixture requires Realm authority"),
    };
    let imt_tree = TreeId::new(9);
    let imt_sub = TreeSubId::new(realm_id as u64);
    let imt_leaf = LeafIndex::new(3);
    let imt_leaf_key = [payload_seed.wrapping_add(30); 32];
    let imt_row = imt_row(
        imt_tree.get(),
        imt_sub.get(),
        imt_leaf.get(),
        payload_seed.wrapping_add(31),
        imt_leaf_key,
    );
    let mut prepared_semantic = semantic
        .iter()
        .map(|(node, value)| {
            PreparedSemanticMutation::GlobalUserMerkle {
                checkpoint,
                node: *node,
                value: value.clone(),
            }
        })
        .collect::<Vec<_>>();
    if include_imt {
        prepared_semantic.push(PreparedSemanticMutation::ImtLeaf {
            tree: imt_tree,
            tree_sub: imt_sub,
            leaf: imt_leaf,
            checkpoint,
            canonical_row: imt_row.clone(),
        });
    }
    let payload = PreparedPayload::try_v1(
        PreparedPayloadKind::Realm,
        prepared_semantic,
    )
    .unwrap();
    let payload_bytes = payload.encode_canonical();
    let reference = DurablePreparedPayloadReference::try_from_source(
        payload.kind(),
        1,
        1,
        PreparedPayloadSource::ContentAddressedBytes(&payload_bytes),
    )
    .unwrap();
    let mut logical = semantic
        .iter()
        .map(|(node, value)| LogicalMutation::Put {
            key: TypedTableKey::GlobalUserMerkle {
                node: *node,
                checkpoint,
            },
            value: MutationValue::PsyCanonicalBytes(value.clone()),
        })
        .collect::<Vec<_>>();
    if include_imt {
        logical.push(LogicalMutation::Put {
            key: TypedTableKey::ImtLeaf {
                tree: imt_tree,
                tree_sub: imt_sub,
                leaf: imt_leaf,
                checkpoint,
            },
            value: MutationValue::Structured {
                schema: StructuredValueSchema::ImtLeafRowV1,
                canonical_bytes: imt_row,
            },
        });
    }
    let latest_checkpoint = LogicalMutation::Put {
        key: TypedTableKey::U64Singleton(
            U64SingletonSlot::LatestCheckpoint,
        ),
        value: MutationValue::CqlU64(checkpoint.get()),
    };
    let checkpoint_root = LogicalMutation::CheckpointRootMapping {
        root: CheckpointRootKey::new(vec![payload_seed.wrapping_add(40); 32]),
        checkpoint,
    };
    let imt_supplements = if include_imt {
        imt_leaf_supplements(
            imt_tree,
            imt_sub,
            ImtEncodedKey::new(encode_raw_imt_key_for_sorting(imt_leaf_key)),
            imt_leaf_key,
            imt_leaf,
            checkpoint,
            3,
            4,
        )
        .unwrap()
    } else {
        Vec::new()
    };
    logical.extend(imt_supplements.clone());
    logical.push(checkpoint_root.clone());
    logical.push(latest_checkpoint.clone());
    let full = CanonicalPhysicalMutationBatch::from_logical(logical).unwrap();
    let (prepared_mutation_count, supplement_mutation_count) =
        if include_imt { (4, 5) } else { (3, 3) };
    let compact = PreparedReferencePlusSupplementRecord::try_v1(
        reference,
        DerivedSupplementBatch::from_logical(
            imt_supplements
                .into_iter()
                .chain([checkpoint_root, latest_checkpoint])
                .collect(),
        )
        .unwrap(),
        ReplayReceipt::new(
            ReplayAuthority::Realm,
            checkpoint,
            prepared_mutation_count,
            supplement_mutation_count,
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
        authority,
    );
    let intent = SealedAuthorityCommitIntent::seal_normal_advance(
        key,
        expected_chain,
        candidate_chain,
        AuthorityStateTransition::Changed {
            previous_checkpoint: AuthorityStateCheckpointId::new(
                checkpoint_id - 1,
            ),
            checkpoint: AuthorityStateCheckpointId::new(checkpoint_id),
            old_root: AuthorityStateRoot::from_local_state_root(old_root),
            new_root: AuthorityStateRoot::from_local_state_root(new_root),
        },
        AuthorityHeadPayload::try_new(vec![payload_seed; 16]).unwrap(),
        artifacts.commitment(),
    )
    .unwrap();
    let timestamp_bootstrap = AuthorityTimestampBootstrap::new(
        key,
        CommitWriteTimestampUs::try_from_i128(high_water as i128).unwrap(),
        AuthorityTimestampBootstrapReason::GenesisNative,
    );
    let reservation = timestamp_bootstrap
        .candidate()
        .seal_reservation(
            key,
            intent.digest(),
            AuthorityClockSampleUs::try_from_i128((high_water + 1) as i128)
                .unwrap(),
        )
        .unwrap();
    let prepared = intent.attach_timestamp_lease(reservation.lease()).unwrap();
    let package =
        VerifiedPreparedManifestPackage::try_new(&prepared, artifacts).unwrap();
    let head_bootstrap = AuthorityLocalHeadBootstrap::seal(
        AuthorityLocalHeadBootstrapReason::GenesisNative,
        AuthorityHeadView::expected(package.record()),
        CommitWriteTimestampUs::try_from_i128(high_water as i128).unwrap(),
        package.record().digest(),
        AuthorityStorageBindingRef::new(
            AuthorityStorageBindingGeneration::try_new(3).unwrap(),
            AuthorityStorageNamespaceId::from_verified_namespace_id([
                namespace_seed;
                32
            ]),
        ),
    );
    Fixture {
        timestamp_bootstrap,
        reservation,
        head_bootstrap,
        package,
    }
}

async fn connect(
    target: Option<Ipv4Addr>,
    consistency: Consistency,
) -> anyhow::Result<Session> {
    let mut profile = ExecutionProfile::builder()
        .consistency(consistency)
        .request_timeout(Some(Duration::from_secs(120)));
    if let Some(ip) = target {
        profile = profile.load_balancing_policy(
            SingleTargetLoadBalancingPolicy::new(
                NodeIdentifier::NodeAddress(SocketAddr::new(
                    IpAddr::V4(ip),
                    9042,
                )),
                None,
            ),
        );
    }
    SessionBuilder::new()
        .known_nodes_addr(
            NODE_IPS.map(|ip| SocketAddr::new(IpAddr::V4(ip), 9042)),
        )
        .default_execution_profile_handle(profile.build().into_handle())
        .connection_timeout(Duration::from_secs(120))
        .build()
        .await
        .context("connect to isolated D-04b2c RF=3 Scylla cluster")
}

fn keyspaces() -> anyhow::Result<ManifestPreparedKeyspaces> {
    Ok(ManifestPreparedKeyspaces::new(
        ManifestControlNoTabletKeyspace::try_new(CONTROL_KEYSPACE)?,
        ManifestArtifactKeyspace::try_new(ARTIFACT_KEYSPACE)?,
    ))
}

async fn create_schema(session: &Session) -> anyhow::Result<()> {
    session
        .query_unpaged(
            format!(
                "CREATE KEYSPACE IF NOT EXISTS {CONTROL_KEYSPACE} WITH replication = {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}} AND tablets = {{'enabled': false}}"
            ),
            &[],
        )
        .await?;
    for keyspace in [ARTIFACT_KEYSPACE, STATE_KEYSPACE] {
        session
            .query_unpaged(
                format!(
                    "CREATE KEYSPACE IF NOT EXISTS {keyspace} WITH replication = {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}}"
                ),
                &[],
            )
            .await?;
    }
    session
        .query_unpaged(
            format!(
                "CREATE TABLE IF NOT EXISTS {STATE_KEYSPACE}.imt_leaf_table (tree_id BIGINT, tree_sub_id BIGINT, leaf_index BIGINT, checkpoint_id BIGINT, leaf_hash BLOB, leaf_key BLOB, leaf_value BLOB, next_key BLOB, next_index BIGINT, PRIMARY KEY ((tree_id, tree_sub_id, leaf_index), checkpoint_id)) WITH CLUSTERING ORDER BY (checkpoint_id DESC)"
            ),
            &[],
        )
        .await?;
    session
        .query_unpaged(
            format!(
                "CREATE TABLE IF NOT EXISTS {STATE_KEYSPACE}.imt_key_index_table (tree_id BIGINT, tree_sub_id BIGINT, key_bucket SMALLINT, encoded_key BLOB, leaf_key BLOB, birth_checkpoint BIGINT, leaf_index BIGINT, PRIMARY KEY ((tree_id, tree_sub_id, key_bucket), encoded_key))"
            ),
            &[],
        )
        .await?;
    session
        .query_unpaged(
            format!(
                "CREATE TABLE IF NOT EXISTS {STATE_KEYSPACE}.imt_next_append_index_table (tree_id BIGINT, tree_sub_id BIGINT, next_append_index BIGINT, PRIMARY KEY ((tree_id, tree_sub_id)))"
            ),
            &[],
        )
        .await?;
    for suffix in ["k1", "k2"] {
        session
            .query_unpaged(
                format!(
                    "CREATE TABLE IF NOT EXISTS {STATE_KEYSPACE}.checkpoint_root_to_checkpoint_id_table_{suffix} (obj_id BLOB PRIMARY KEY, value BLOB)"
                ),
                &[],
            )
            .await?;
    }
    ScyllaPreparedManifestStore::create_schema(session, &keyspaces()?).await?;
    // `RollbackableStorePrototype` deliberately prepares the complete G0-06
    // representative query set. Keep the RF=3 fixture production-shaped by
    // creating the KIV representative table even though this gate executes
    // Merkle, checkpoint-root pair and latest-checkpoint rows.
    session
        .query_unpaged(
            format!(
                "CREATE TABLE IF NOT EXISTS {STATE_KEYSPACE}.checkpoint_leaf_table (obj_id BIGINT PRIMARY KEY, value BLOB)"
            ),
            &[],
        )
        .await?;
    session
        .query_unpaged(
            format!(
                "CREATE TABLE IF NOT EXISTS {STATE_KEYSPACE}.global_user_tree_table (level TINYINT, node_index BIGINT, checkpoint_id BIGINT, value BLOB, PRIMARY KEY ((level), node_index, checkpoint_id)) WITH CLUSTERING ORDER BY (node_index ASC, checkpoint_id DESC)"
            ),
            &[],
        )
        .await?;
    session
        .query_unpaged(
            format!(
                "CREATE TABLE IF NOT EXISTS {STATE_KEYSPACE}.user_contract_tree_table (tree_id BIGINT, level TINYINT, node_index BIGINT, checkpoint_id BIGINT, value BLOB, PRIMARY KEY ((tree_id), level, node_index, checkpoint_id)) WITH CLUSTERING ORDER BY (level ASC, node_index ASC, checkpoint_id DESC)"
            ),
            &[],
        )
        .await?;
    session
        .query_unpaged(
            format!(
                "CREATE TABLE IF NOT EXISTS {STATE_KEYSPACE}.contract_state_tree_table (tree_id BIGINT, tree_sub_id BIGINT, level TINYINT, node_index BIGINT, checkpoint_id BIGINT, value BLOB, PRIMARY KEY ((tree_id, tree_sub_id), level, node_index, checkpoint_id)) WITH CLUSTERING ORDER BY (level ASC, node_index ASC, checkpoint_id DESC)"
            ),
            &[],
        )
        .await?;
    session
        .query_unpaged(
            format!(
                "CREATE TABLE IF NOT EXISTS {STATE_KEYSPACE}.u64_singleton_table (obj_id BIGINT PRIMARY KEY, value BIGINT)"
            ),
            &[],
        )
        .await?;
    // The confined mutable-singleton adapter prepares its complete query
    // family. This table is not executed by this gate, but keeping the real
    // schema present proves preparation uses the production-shaped catalog.
    session
        .query_unpaged(
            format!(
                "CREATE TABLE IF NOT EXISTS {STATE_KEYSPACE}.latest_info_table (obj_id BIGINT PRIMARY KEY, value BLOB)"
            ),
            &[],
        )
        .await?;
    Ok(())
}

struct Stores {
    manifests: ScyllaPreparedManifestStore,
    state: RollbackableStorePrototype,
}

async fn open_stores() -> anyhow::Result<Stores> {
    let session = Arc::new(connect(None, Consistency::Quorum).await?);
    Ok(Stores {
        manifests: ScyllaPreparedManifestStore::prepare(
            Arc::clone(&session),
            keyspaces()?,
        )
        .await?,
        state: RollbackableStorePrototype::prepare_scylla(
            session,
            CqlKeyspaceName::try_new(STATE_KEYSPACE)?,
            Consistency::Quorum,
        )
        .await?,
    })
}

struct CombinedStores {
    session: Arc<Session>,
    manifests: ScyllaPreparedManifestStore,
    heads: ScyllaAuthorityLocalHeadStore,
    timestamps: ScyllaAuthorityTimestampStore,
    state: RollbackableStorePrototype,
    predecessor: RealmImtPredecessorAdapter<PHash>,
}

impl CombinedStores {
    fn executor(&self) -> ScyllaRepresentativeRealmNormalCommitExecutor<'_> {
        ScyllaRepresentativeRealmNormalCommitExecutor::new(
            &self.manifests,
            &self.heads,
            &self.timestamps,
            &self.state,
        )
    }

    async fn assemble_realm_evidence(
        &self,
        fixture: &RealmEvidenceFixture,
        seed_predecessor: bool,
    ) -> anyhow::Result<SealedRealmCommitEvidence<PHash, PoseidonHasher>> {
        let session = &self.session;
        if seed_predecessor {
            seed_realm_evidence_predecessor(session, fixture).await?;
        }
        let plan = fixture.assembly_plan()?;
        let rows = self
            .predecessor
            .read_plan(session, &plan.predecessor_read_plan())
            .await?;
        Ok(plan.verify_predecessor_rows_and_seal(&rows)?)
    }
}

async fn create_combined_schema(session: &Session) -> anyhow::Result<()> {
    create_schema(session).await?;
    ScyllaAuthorityTimestampStore::create_schema(
        session,
        &AuthorityTimestampNoTabletKeyspace::try_new(CONTROL_KEYSPACE)?,
    )
    .await?;
    ScyllaAuthorityLocalHeadStore::create_schema(
        session,
        &AuthorityLocalHeadNoTabletKeyspace::try_new(CONTROL_KEYSPACE)?,
    )
    .await?;
    Ok(())
}

async fn open_combined_stores() -> anyhow::Result<CombinedStores> {
    let session = Arc::new(connect(None, Consistency::Quorum).await?);
    let predecessor = RealmImtPredecessorAdapter::<PHash>::prepare_with_consistency(
        &session,
        CqlKeyspaceName::try_new(STATE_KEYSPACE)?,
        Consistency::Quorum,
    )
    .await?;
    Ok(CombinedStores {
        session: Arc::clone(&session),
        manifests: ScyllaPreparedManifestStore::prepare(
            Arc::clone(&session),
            keyspaces()?,
        )
        .await?,
        heads: ScyllaAuthorityLocalHeadStore::prepare(
            Arc::clone(&session),
            AuthorityLocalHeadNoTabletKeyspace::try_new(CONTROL_KEYSPACE)?,
        )
        .await?,
        timestamps: ScyllaAuthorityTimestampStore::prepare(
            Arc::clone(&session),
            AuthorityTimestampNoTabletKeyspace::try_new(CONTROL_KEYSPACE)?,
        )
        .await?,
        state: RollbackableStorePrototype::prepare_scylla(
            session,
            CqlKeyspaceName::try_new(STATE_KEYSPACE)?,
            Consistency::Quorum,
        )
        .await?,
        predecessor,
    })
}

async fn initialize_combined_fixture(
    stores: &CombinedStores,
    fixture: &Fixture,
) -> anyhow::Result<()> {
    ensure!(matches!(
        stores
            .timestamps
            .bootstrap(fixture.timestamp_bootstrap)
            .await?,
        AuthorityTimestampWriteOutcome::Applied(_)
    ));
    ensure!(matches!(
        stores.timestamps.reserve(fixture.reservation).await?,
        AuthorityTimestampWriteOutcome::Applied(_)
    ));
    ensure!(matches!(
        stores.heads.bootstrap(&fixture.head_bootstrap).await?,
        AuthorityLocalHeadWriteOutcome::Applied(_)
    ));
    ensure!(matches!(
        stores
            .manifests
            .persist_prepared(&fixture.package)
            .await?,
        psy_node_core::store::manifest_record::PreparedManifestWriteOutcome::Applied(_)
    ));
    Ok(())
}

async fn insert_predecessor_node(
    session: &Session,
    key: RealmImtBaselineNodeKey,
    checkpoint: u64,
    value: &[u8],
) -> anyhow::Result<()> {
    let checkpoint = i64::try_from(checkpoint)?;
    match key {
        RealmImtBaselineNodeKey::GlobalUser { level, index } => {
            session
                .query_unpaged(
                    format!(
                        "INSERT INTO {STATE_KEYSPACE}.global_user_tree_table (level, node_index, checkpoint_id, value) VALUES (?, ?, ?, ?)"
                    ),
                    (
                        u8_to_i8_exact(level),
                        u64_to_i64_exact(index),
                        checkpoint,
                        value,
                    ),
                )
                .await?;
        }
        RealmImtBaselineNodeKey::UserContract {
            user_id,
            level,
            index,
        } => {
            session
                .query_unpaged(
                    format!(
                        "INSERT INTO {STATE_KEYSPACE}.user_contract_tree_table (tree_id, level, node_index, checkpoint_id, value) VALUES (?, ?, ?, ?, ?)"
                    ),
                    (
                        u64_to_i64_exact(user_id),
                        u8_to_i8_exact(level),
                        u64_to_i64_exact(index),
                        checkpoint,
                        value,
                    ),
                )
                .await?;
        }
        RealmImtBaselineNodeKey::ContractState {
            user_id,
            contract_id,
            level,
            index,
        } => {
            session
                .query_unpaged(
                    format!(
                        "INSERT INTO {STATE_KEYSPACE}.contract_state_tree_table (tree_id, tree_sub_id, level, node_index, checkpoint_id, value) VALUES (?, ?, ?, ?, ?, ?)"
                    ),
                    (
                        u64_to_i64_exact(user_id),
                        u64_to_i64_exact(contract_id),
                        u8_to_i8_exact(level),
                        u64_to_i64_exact(index),
                        checkpoint,
                        value,
                    ),
                )
                .await?;
        }
    }
    Ok(())
}

async fn seed_realm_evidence_predecessor(
    session: &Session,
    fixture: &RealmEvidenceFixture,
) -> anyhow::Result<usize> {
    let plan = fixture.assembly_plan()?;
    let zero_hashes = (0..64)
        .map(PoseidonHasher::get_zero_hash)
        .collect::<Vec<_>>();
    let mut absent_count = 0;
    for request in plan.predecessor_read_plan().requests() {
        let key = request.key();
        let expected = fixture.baseline[&key];
        if zero_hashes.contains(&expected) {
            absent_count += 1;
        } else {
            insert_predecessor_node(
                session,
                key,
                EVIDENCE_PREDECESSOR,
                &expected.into_owned_32bytes(),
            )
            .await?;
        }
        insert_predecessor_node(
            session,
            key,
            EVIDENCE_STATE + 1,
            &[211; 32],
        )
        .await?;
    }
    ensure!(absent_count > 0, "fixture must exercise implicit zero rows");
    Ok(absent_count)
}

async fn load_plan(
    stores: &Stores,
    identity: AuthorityManifestIdentity<PHash>,
) -> anyhow::Result<RepresentativeRealmStateReplayPlan<PHash>> {
    load_plan_from(&stores.manifests, identity).await
}

async fn load_plan_from(
    manifests: &ScyllaPreparedManifestStore,
    identity: AuthorityManifestIdentity<PHash>,
) -> anyhow::Result<RepresentativeRealmStateReplayPlan<PHash>> {
    let prepared = match manifests
        .read_lifecycle(identity)
        .await?
        .context("durable PREPARED row is missing")?
    {
        PersistedAuthorityManifest::Prepared(prepared) => prepared,
        other => bail!("expected PREPARED lifecycle, got {other:?}"),
    };
    let artifacts = manifests.load_verified_artifacts(&prepared).await?;
    RepresentativeRealmStateReplayPlan::try_from_verified_artifacts(
        &prepared,
        &artifacts,
    )
    .map_err(Into::into)
}

fn run_command(
    mut command: Command,
    description: &str,
) -> anyhow::Result<String> {
    let output = command
        .output()
        .with_context(|| format!("start {description}"))?;
    if !output.status.success() {
        bail!(
            "{description} failed ({}): stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn docker_exec(
    container: &str,
    args: &[&str],
    description: &str,
) -> anyhow::Result<String> {
    let mut command = Command::new("docker");
    command.arg("exec").arg(container).args(args);
    run_command(command, description)
}

fn docker_container(action: &str, container: &str) -> anyhow::Result<()> {
    let mut command = Command::new("docker");
    command.arg(action).arg(container);
    run_command(command, &format!("docker {action} {container}"))?;
    Ok(())
}

async fn wait_for_three_up_normal() -> anyhow::Result<()> {
    for _ in 0..90 {
        let status = docker_exec(
            NODE_CONTAINERS[0],
            &["nodetool", "status"],
            "read D-04b2c RF=3 status",
        )?;
        if status.lines().filter(|line| line.starts_with("UN ")).count() == 3 {
            return Ok(());
        }
        sleep(Duration::from_secs(2)).await;
    }
    bail!("cluster did not return to three Up/Normal members")
}

fn repair_flush_compact() -> anyhow::Result<()> {
    // The control substrate is intentionally vnode/no-tablet because it uses
    // LWT.  The artifact and representative state keyspaces use Scylla's
    // default tablets.  These two storage modes have distinct repair APIs.
    for node in NODE_CONTAINERS {
        docker_exec(
            node,
            &["nodetool", "repair", "-pr", CONTROL_KEYSPACE],
            "repair D-04b2c no-tablet control keyspace",
        )?;
    }
    for keyspace in [ARTIFACT_KEYSPACE, STATE_KEYSPACE] {
        docker_exec(
            NODE_CONTAINERS[0],
            &["nodetool", "cluster", "repair", keyspace],
            "repair D-04b2c tablet keyspace",
        )?;
    }
    for node in NODE_CONTAINERS {
        for keyspace in [CONTROL_KEYSPACE, ARTIFACT_KEYSPACE, STATE_KEYSPACE] {
            docker_exec(
                node,
                &["nodetool", "flush", keyspace],
                "flush D-04b2c keyspace",
            )?;
            docker_exec(
                node,
                &["nodetool", "compact", keyspace],
                "compact D-04b2c keyspace",
            )?;
        }
    }
    Ok(())
}

async fn read_direct_rows(
    ip: Ipv4Addr,
    plan: &RepresentativeRealmStateReplayPlan<PHash>,
) -> anyhow::Result<Vec<Vec<u8>>> {
    let session = connect(Some(ip), Consistency::One).await?;
    let merkle_query = format!(
        "SELECT value FROM {STATE_KEYSPACE}.global_user_tree_table WHERE level = ? AND node_index = ? AND checkpoint_id = ?"
    );
    let singleton_query = format!(
        "SELECT value FROM {STATE_KEYSPACE}.u64_singleton_table WHERE obj_id = ?"
    );
    let checkpoint_root_k1_query = format!(
        "SELECT value FROM {STATE_KEYSPACE}.checkpoint_root_to_checkpoint_id_table_k1 WHERE obj_id = ?"
    );
    let checkpoint_root_k2_query = format!(
        "SELECT value FROM {STATE_KEYSPACE}.checkpoint_root_to_checkpoint_id_table_k2 WHERE obj_id = ?"
    );
    let imt_leaf_query = format!(
        "SELECT leaf_hash, leaf_key, leaf_value, next_key, next_index FROM {STATE_KEYSPACE}.imt_leaf_table WHERE tree_id = ? AND tree_sub_id = ? AND leaf_index = ? AND checkpoint_id = ?"
    );
    let imt_index_query = format!(
        "SELECT leaf_key, birth_checkpoint, leaf_index FROM {STATE_KEYSPACE}.imt_key_index_table WHERE tree_id = ? AND tree_sub_id = ? AND key_bucket = ? AND encoded_key = ?"
    );
    let imt_cursor_query = format!(
        "SELECT next_append_index FROM {STATE_KEYSPACE}.imt_next_append_index_table WHERE tree_id = ? AND tree_sub_id = ?"
    );
    let mut values = Vec::with_capacity(plan.mutation_count());
    for sealed in plan.puts() {
        let value = match sealed.resolved().mutation().key() {
            TypedTableKey::GlobalUserMerkle { node, checkpoint } => session
                .query_unpaged(
                    merkle_query.as_str(),
                    (
                        u8_to_i8_exact(node.level()),
                        u64_to_i64_exact(node.index().get()),
                        convert_checkpoint_id_to_i64(checkpoint.get()),
                    ),
                )
                .await?
                .into_rows_result()?
                .single_row::<(Vec<u8>,)>()?
                .0,
            TypedTableKey::U64Singleton(
                U64SingletonSlot::LatestCheckpoint,
            ) => i64_to_u64_exact(
                session
                    .query_unpaged(
                        singleton_query.as_str(),
                        (u64_to_i64_exact(
                            U64SingletonSlot::LatestCheckpoint as u8 as u64,
                        ),),
                    )
                    .await?
                    .into_rows_result()?
                    .single_row::<(i64,)>()?
                    .0,
            )
            .to_be_bytes()
            .to_vec(),
            TypedTableKey::CheckpointRootByHash(root) => {
                let stored = session
                    .query_unpaged(
                        checkpoint_root_k1_query.as_str(),
                        (root.as_bytes(),),
                    )
                    .await?
                    .into_rows_result()?
                    .single_row::<(Vec<u8>,)>()?
                    .0;
                crate::compression::decompress(&stored)?
            }
            TypedTableKey::CheckpointRootByCheckpoint(checkpoint) => {
                let stored = session
                    .query_unpaged(
                        checkpoint_root_k2_query.as_str(),
                        (checkpoint.get().to_le_bytes().as_slice(),),
                    )
                    .await?
                    .into_rows_result()?
                    .single_row::<(Vec<u8>,)>()?
                    .0;
                crate::compression::decompress(&stored)?
            }
            TypedTableKey::ImtLeaf {
                tree,
                tree_sub,
                leaf,
                checkpoint,
            } => {
                let (leaf_hash, leaf_key, leaf_value, next_key, next_index) = session
                    .query_unpaged(
                        imt_leaf_query.as_str(),
                        (
                            u64_to_i64_exact(tree.get()),
                            u64_to_i64_exact(tree_sub.get()),
                            u64_to_i64_exact(leaf.get()),
                            convert_checkpoint_id_to_i64(checkpoint.get()),
                        ),
                    )
                    .await?
                    .into_rows_result()?
                    .single_row::<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64)>()?;
                ensure!(
                    leaf_hash.len() == 32
                        && leaf_key.len() == 32
                        && leaf_value.len() == 32
                        && next_key.len() == 32
                );
                [leaf_hash, leaf_key, leaf_value, next_key]
                    .into_iter()
                    .flatten()
                    .chain(i64_to_u64_exact(next_index).to_be_bytes())
                    .collect()
            }
            TypedTableKey::ImtKeyIndex {
                tree,
                tree_sub,
                encoded_key,
            } => {
                let (leaf_key, birth_checkpoint, leaf_index) = session
                    .query_unpaged(
                        imt_index_query.as_str(),
                        (
                            u64_to_i64_exact(tree.get()),
                            u64_to_i64_exact(tree_sub.get()),
                            encoded_key.cql_bucket(),
                            encoded_key.as_bytes(),
                        ),
                    )
                    .await?
                    .into_rows_result()?
                    .single_row::<(Vec<u8>, i64, i64)>()?;
                ensure!(leaf_key.len() == 32 && birth_checkpoint >= 0);
                ImtKeyIndexRow::new(
                    leaf_key.as_slice().try_into().expect("validated length"),
                    StorageCheckpointId::try_new(birth_checkpoint as u64)?,
                    LeafIndex::new(i64_to_u64_exact(leaf_index)),
                )
                .encode_canonical()
                .to_vec()
            }
            TypedTableKey::ImtCursor { tree, tree_sub } => i64_to_u64_exact(
                session
                    .query_unpaged(
                        imt_cursor_query.as_str(),
                        (
                            u64_to_i64_exact(tree.get()),
                            u64_to_i64_exact(tree_sub.get()),
                        ),
                    )
                    .await?
                    .into_rows_result()?
                    .single_row::<(i64,)>()?
                    .0,
            )
            .to_be_bytes()
            .to_vec(),
            _ => bail!("representative plan exposed an unsupported typed key"),
        };
        values.push(value);
    }
    Ok(values)
}

fn expected_rows(
    plan: &RepresentativeRealmStateReplayPlan<PHash>,
) -> anyhow::Result<Vec<Vec<u8>>> {
    Ok(plan
        .expected_physical_values()
        .map(<[u8]>::to_vec)
        .collect())
}

#[derive(Serialize)]
struct D04b2cReport {
    baseline: &'static str,
    image: &'static str,
    scylla_release: String,
    replication_factor: u8,
    regular_consistency: &'static str,
    restart_count: u8,
    partial_root_present_before_replay: bool,
    missing_row_rejected_before_seal: bool,
    exact_replay_verified_manifest_evidence_required: bool,
    direct_one_replicas_equal: bool,
    scenarios_passed: Vec<&'static str>,
    finished_unix_ms: u64,
    qualification: &'static str,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the destructive local three-node Scylla RF=3 harness"]
async fn d04b2c_representative_state_replay_rf3_gate() -> anyhow::Result<()> {
    if std::env::var_os("PSY_D04B2C_RF3").is_none() {
        bail!("set PSY_D04B2C_RF3=1 through run-d04b2c.sh");
    }
    let initial_session = connect(None, Consistency::Quorum).await?;
    create_schema(&initial_session).await?;
    let release = docker_exec(
        NODE_CONTAINERS[0],
        &["scylla", "--version"],
        "read D-04b2c Scylla version",
    )?
    .trim()
    .to_owned();
    drop(initial_session);

    let fixture = fixture(3, 41, 1, 500);
    let identity = fixture.identity();
    let stores = open_stores().await?;
    ensure!(matches!(
        stores.manifests.persist_prepared(&fixture.package).await?,
        psy_node_core::store::manifest_record::PreparedManifestWriteOutcome::Applied(_)
    ));
    let plan = load_plan(&stores, identity).await?;
    ensure!(plan.root_position() == 0, "fixture root must sort first");
    let prefix = plan.root_position() + 1;
    ensure!(prefix < plan.mutation_count());
    RepresentativeRealmStateReplayExecutor::new(&stores.state)
        .reapply_prefix_for_gate(&plan, prefix)
        .await?;
    drop(stores);

    // Simulated process restart: all adapters and sessions are recreated from
    // the durable PREPARED row and immutable artifact chunks.
    let stores = open_stores().await?;
    let plan = load_plan(&stores, identity).await?;
    let executor = RepresentativeRealmStateReplayExecutor::new(&stores.state);
    let partial = executor.read_exact(&plan).await?;
    let root_present = partial[plan.root_position()].is_some();
    ensure!(root_present);
    ensure!(matches!(
        plan.verify_observed_rows(&partial),
        Err(RepresentativeStateReplayError::PhysicalRowMissing { .. })
    ));

    docker_container("stop", NODE_CONTAINERS[2])?;
    executor.reapply_all(&plan).await?;
    let observation = executor.verify_exact(&plan).await?;
    ensure!(
        SealedAuthorityManifest::verify_and_seal(
            plan.prepared().clone(),
            observation,
        )
        .unwrap_err()
            == ManifestLifecycleError::ChangedRealmEvidenceRequired
    );
    drop(stores);

    docker_container("start", NODE_CONTAINERS[2])?;
    wait_for_three_up_normal().await?;
    repair_flush_compact()?;
    let expected = expected_rows(&plan)?;
    let mut replicas = Vec::new();
    for ip in NODE_IPS {
        replicas.push(read_direct_rows(ip, &plan).await?);
    }
    ensure!(replicas.iter().all(|rows| rows == &expected));

    let report = D04b2cReport {
        baseline: BASELINE,
        image: IMAGE,
        scylla_release: release,
        replication_factor: 3,
        regular_consistency: "QUORUM",
        restart_count: 1,
        partial_root_present_before_replay: root_present,
        missing_row_rejected_before_seal: true,
        exact_replay_verified_manifest_evidence_required: true,
        direct_one_replicas_equal: true,
        scenarios_passed: vec![
            "M16_partial_state_write_restart_reapplies_exact_timestamped_rows",
            "M17_root_present_but_missing_non_root_row_cannot_seal",
            "IMT_leaf_index_cursor_exact_rows_are_all_required_before_realm_evidence",
            "one_replica_offline_quorum_replay_then_repair_flush_compact",
            "direct_one_all_replicas_equal_expected_rows",
        ],
        finished_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis() as u64,
        qualification: "representative Realm global-user Merkle, IMT leaf/key-index/cursor, checkpoint-root pair and latest-checkpoint singleton replay; verifies exact IMT physical durability, not upstream contract-state/root proof binding, production Processor integration, or full 35-table replay coverage",
    };
    let report_path = std::env::var("PSY_D04B2C_REPORT_PATH")
        .unwrap_or_else(|_| "target/d04b2c-state-replay-rf3-report.json".into());
    let report_path = Path::new(&report_path);
    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(report_path, serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}

async fn create_full_commit_schema(session: &Session) -> anyhow::Result<()> {
    create_schema(session).await?;

    for table in CHECKPOINT_KIV_TABLES {
        let name = physical_descriptor(table.physical_table()).physical_name;
        session
            .query_unpaged(
                format!(
                    "CREATE TABLE IF NOT EXISTS {STATE_KEYSPACE}.{name} (obj_id BIGINT PRIMARY KEY, value BLOB)"
                ),
                &[],
            )
            .await?;
    }
    for table in CHECKPOINT_OBJECT_SINGLE_TABLES {
        let name = physical_descriptor(table.physical_table()).physical_name;
        session
            .query_unpaged(
                format!(
                    "CREATE TABLE IF NOT EXISTS {STATE_KEYSPACE}.{name} (obj_id BIGINT, checkpoint_id BIGINT, value BLOB, PRIMARY KEY ((obj_id), checkpoint_id)) WITH CLUSTERING ORDER BY (checkpoint_id DESC)"
                ),
                &[],
            )
            .await?;
    }
    for table in CHECKPOINT_MERKLE_TABLES {
        let name = physical_descriptor(table.physical_table()).physical_name;
        let cql = match table.schema_family() {
            ScyllaSchemaFamily::MerkleZero => format!(
                "CREATE TABLE IF NOT EXISTS {STATE_KEYSPACE}.{name} (level TINYINT, node_index BIGINT, checkpoint_id BIGINT, value BLOB, PRIMARY KEY ((level), node_index, checkpoint_id)) WITH CLUSTERING ORDER BY (node_index ASC, checkpoint_id DESC)"
            ),
            ScyllaSchemaFamily::MerkleSingle => format!(
                "CREATE TABLE IF NOT EXISTS {STATE_KEYSPACE}.{name} (tree_id BIGINT, level TINYINT, node_index BIGINT, checkpoint_id BIGINT, value BLOB, PRIMARY KEY ((tree_id), level, node_index, checkpoint_id)) WITH CLUSTERING ORDER BY (level ASC, node_index ASC, checkpoint_id DESC)"
            ),
            ScyllaSchemaFamily::MerkleDouble => format!(
                "CREATE TABLE IF NOT EXISTS {STATE_KEYSPACE}.{name} (tree_id BIGINT, tree_sub_id BIGINT, level TINYINT, node_index BIGINT, checkpoint_id BIGINT, value BLOB, PRIMARY KEY ((tree_id, tree_sub_id), level, node_index, checkpoint_id)) WITH CLUSTERING ORDER BY (level ASC, node_index ASC, checkpoint_id DESC)"
            ),
            family => bail!("full-commit Merkle table exposed unexpected schema family {family:?}"),
        };
        session.query_unpaged(cql, &[]).await?;
    }
    let checkpointed_object =
        physical_descriptor(ScyllaPhysicalTableId::CheckpointedObject).physical_name;
    session
        .query_unpaged(
            format!(
                "CREATE TABLE IF NOT EXISTS {STATE_KEYSPACE}.{checkpointed_object} (obj_id BIGINT, checkpoint_id BIGINT, value BLOB, PRIMARY KEY ((obj_id), checkpoint_id)) WITH CLUSTERING ORDER BY (checkpoint_id DESC)"
            ),
            &[],
        )
        .await?;
    Ok(())
}

async fn open_full_commit_executor(
    target: Option<Ipv4Addr>,
    consistency: Consistency,
) -> anyhow::Result<(Session, RealmFullCommitScyllaExecutor)> {
    let session = connect(target, consistency).await?;
    let executor = RealmFullCommitScyllaExecutor::prepare_with_consistency(
        &session,
        CqlKeyspaceName::try_new(STATE_KEYSPACE)?,
        consistency,
    )
    .await?;
    Ok((session, executor))
}

#[derive(Serialize)]
struct H23c4e2c2b2bReport {
    baseline: &'static str,
    image: &'static str,
    scylla_release: String,
    replication_factor: u8,
    regular_consistency: &'static str,
    full_schedule_rows: usize,
    full_schedule_actions: usize,
    partial_prefix_actions: usize,
    partial_restart_recovered: bool,
    caller_discard_retry: bool,
    socket_response_loss_injected: bool,
    one_replica_offline: bool,
    exact_retry_digest_equal: bool,
    repair_ms: u64,
    direct_one_nodes: usize,
    direct_one_table_names: Vec<&'static str>,
    direct_one_table_count: usize,
    direct_one_row_count: usize,
    direct_one_dataset_digest: String,
    direct_one_equal: bool,
    h22_typed_composite_manifest: bool,
    manifest_persisted: bool,
    processor_writer_invocation: bool,
    production_writer_covered_domains: u8,
    authority_head_published: bool,
    production_serving: bool,
    h8_domains_closed: u8,
    finished_unix_ms: u64,
    qualification: &'static str,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the destructive local three-node Scylla RF=3 harness"]
async fn h23c4e2c2b2b_full_commit_executor_rf3_gate() -> anyhow::Result<()> {
    if std::env::var_os("PSY_D04B6H23C4E2C2B2B_RF3").is_none() {
        bail!("set PSY_D04B6H23C4E2C2B2B_RF3=1 through run-d04b6h23c4e2c2b2b.sh");
    }

    let initial_session = connect(None, Consistency::Quorum).await?;
    create_full_commit_schema(&initial_session).await?;
    let release = docker_exec(
        NODE_CONTAINERS[0],
        &["scylla", "--version"],
        "read h23c4e2c2b2b Scylla version",
    )?
    .trim()
    .to_owned();
    drop(initial_session);

    let first_timestamp = CommitWriteTimestampUs::try_from_i128(70_000)?;
    let first_schedule =
        realm_full_commit_plan::tests::qualification_full_schedule(first_timestamp);
    ensure!(first_schedule.rows().len() == 25);
    let all_missing = vec![None; first_schedule.rows().len()];
    let full_schedule_actions =
        validate_schedule_write_plan(&first_schedule, &all_missing)?;
    ensure!(full_schedule_actions == 24);

    let (first_session, first_executor) =
        open_full_commit_executor(None, Consistency::Quorum).await?;
    ensure!(first_executor
        .read_all(&first_session, &first_schedule)
        .await?
        .iter()
        .all(Option::is_none));
    let partial_prefix_actions = first_executor
        .qualification_write_prefix(&first_session, &first_schedule, 7)
        .await?;
    ensure!(partial_prefix_actions == 7);
    let partial = first_executor.read_all(&first_session, &first_schedule).await?;
    ensure!(partial.iter().any(Option::is_some));
    ensure!(partial.iter().any(Option::is_none));
    drop(first_executor);
    drop(first_session);

    let (restart_session, restart_executor) =
        open_full_commit_executor(None, Consistency::Quorum).await?;
    let restarted = restart_executor
        .write_and_verify(&restart_session, &first_schedule)
        .await?;
    ensure!(restarted.row_count() == 25);
    drop(restart_executor);
    drop(restart_session);

    docker_container("stop", NODE_CONTAINERS[2])?;
    let retry_timestamp = CommitWriteTimestampUs::try_from_i128(70_001)?;
    let retry_schedule =
        realm_full_commit_plan::tests::qualification_full_schedule(retry_timestamp);
    let (offline_session, offline_executor) =
        open_full_commit_executor(None, Consistency::Quorum).await?;
    let first_retry = offline_executor
        .write_and_verify(&offline_session, &retry_schedule)
        .await?;
    let first_retry_digest = *first_retry.digest();
    drop(offline_executor);
    drop(offline_session);

    // Model a caller/process losing the successful result: rebuild every
    // prepared statement while one replica remains offline, then retry the
    // same sealed schedule and require an identical typed observation.
    let (discard_session, discard_executor) =
        open_full_commit_executor(None, Consistency::Quorum).await?;
    let discarded_retry = discard_executor
        .write_and_verify(&discard_session, &retry_schedule)
        .await?;
    ensure!(discarded_retry.digest() == &first_retry_digest);
    drop(discard_executor);
    drop(discard_session);

    docker_container("start", NODE_CONTAINERS[2])?;
    wait_for_three_up_normal().await?;
    let repair_started = Instant::now();
    repair_flush_compact()?;
    let repair_ms = u64::try_from(repair_started.elapsed().as_millis())?;

    let mut replica_digests = Vec::new();
    for ip in NODE_IPS {
        let (session, executor) =
            open_full_commit_executor(Some(ip), Consistency::One).await?;
        let rows = executor.read_all(&session, &retry_schedule).await?;
        replica_digests.push(*retry_schedule.verify_after_write(&rows)?.digest());
    }
    let direct_one_equal = replica_digests
        .iter()
        .all(|digest| digest == &first_retry_digest);
    ensure!(direct_one_equal);

    let direct_one_table_names = retry_schedule
        .rows()
        .iter()
        .map(|row| physical_descriptor(row.physical_table()).physical_name)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let report = H23c4e2c2b2bReport {
        baseline: "236fd77f9d682af35a19bedcbfeda319e373d0dd",
        image: IMAGE,
        scylla_release: release,
        replication_factor: 3,
        regular_consistency: "QUORUM",
        full_schedule_rows: retry_schedule.rows().len(),
        full_schedule_actions,
        partial_prefix_actions,
        partial_restart_recovered: true,
        caller_discard_retry: true,
        socket_response_loss_injected: false,
        one_replica_offline: true,
        exact_retry_digest_equal: true,
        repair_ms,
        direct_one_nodes: NODE_IPS.len(),
        direct_one_table_count: direct_one_table_names.len(),
        direct_one_table_names,
        direct_one_row_count: retry_schedule.rows().len(),
        direct_one_dataset_digest: hex::encode(first_retry_digest),
        direct_one_equal,
        h22_typed_composite_manifest: false,
        manifest_persisted: false,
        processor_writer_invocation: false,
        production_writer_covered_domains: 0,
        authority_head_published: false,
        production_serving: false,
        h8_domains_closed: 0,
        finished_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis() as u64,
        qualification:
            "H23C4E2C2B2B_FULL_COMMIT_EXECUTOR_RF3_PASSED",
    };
    let report_path = std::env::var(
        "PSY_D04B6H23C4E2C2B2B_REPORT_PATH",
    )
    .unwrap_or_else(|_| {
        "target/d04b6h23c4e2c2b2b-full-commit-executor-rf3-report.json"
            .into()
    });
    let report_path = Path::new(&report_path);
    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(report_path, serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}

#[derive(Serialize)]
struct D04b2dReport {
    baseline: &'static str,
    image: &'static str,
    scylla_release: String,
    replication_factor: u8,
    regular_consistency: &'static str,
    serial_consistency: &'static str,
    restart_count: u8,
    with_imt_awaiting_evidence_survived_restart: bool,
    live_evidence_lost_then_reacquired: bool,
    with_imt_reached_sealed: bool,
    without_imt_reached_sealed: bool,
    implicit_zero_rows_observed_as_absent: usize,
    head_response_loss_recovered: bool,
    committed_response_loss_recovered: bool,
    timestamp_response_loss_recovered: bool,
    one_replica_offline_without_imt_reached_done: bool,
    direct_one_state_replicas_equal: bool,
    scenarios_passed: Vec<&'static str>,
    finished_unix_ms: u64,
    qualification: &'static str,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the destructive RF=3 harness and changed-Realm supplement orchestration"]
async fn d04b2d_combined_representative_normal_commit_rf3_gate(
) -> anyhow::Result<()> {
    if std::env::var_os("PSY_D04B2D_RF3").is_none() {
        bail!("set PSY_D04B2D_RF3=1 through run-d04b2d.sh");
    }
    let initial_session = connect(None, Consistency::Quorum).await?;
    create_combined_schema(&initial_session).await?;
    let release = docker_exec(
        NODE_CONTAINERS[0],
        &["scylla", "--version"],
        "read D-04b2d Scylla version",
    )?
    .trim()
    .to_owned();
    drop(initial_session);

    // Start from a real PREPARED row with only the physical prefix through the
    // root present. Exact physical replay may cross only into the explicit
    // AwaitingRealmEvidence state; the live proof/graph capability must be
    // reacquired after a simulated process crash before SEALED is legal.
    let with_imt_evidence = realm_evidence_fixture(0, 1, 0, true);
    let crash = fixture_for_realm_evidence(&with_imt_evidence, 11, 1_500, 17);
    let stores = open_combined_stores().await?;
    initialize_combined_fixture(&stores, &crash).await?;
    let with_imt_absent =
        seed_realm_evidence_predecessor(&stores.session, &with_imt_evidence)
            .await?;
    let crash_plan = load_plan_from(&stores.manifests, crash.identity()).await?;
    ensure!(crash_plan.root_position() == 0);
    let crash_prefix = crash_plan.root_position() + 1;
    ensure!(crash_prefix < crash_plan.mutation_count());
    RepresentativeRealmStateReplayExecutor::new(&stores.state)
        .reapply_prefix_for_gate(&crash_plan, crash_prefix)
        .await?;
    drop(stores);

    let stores = open_combined_stores().await?;
    let first_state = match stores.executor().step(crash.identity()).await? {
        RepresentativeNormalCommitStep::StateVerifiedAwaitingRealmEvidence {
            state,
        } => state,
        other => bail!("expected AwaitingRealmEvidence after replay, got {other:?}"),
    };
    ensure!(first_state.prepared().identity() == &crash.identity());
    drop(stores);

    // Awaiting is derived from PREPARED plus exact read-back, not a durable
    // phase bit. Re-reading after restart must reproduce it. Acquire a valid
    // live bundle and deliberately lose it with the process; persisted bytes
    // alone are not allowed to cross the seal boundary.
    let stores = open_combined_stores().await?;
    let state_before_evidence_loss =
        match stores.executor().step(crash.identity()).await? {
            RepresentativeNormalCommitStep::StateVerifiedAwaitingRealmEvidence {
                state,
            } => state,
            other => bail!("expected AwaitingRealmEvidence after restart, got {other:?}"),
        };
    ensure!(state_before_evidence_loss.prepared().identity() == &crash.identity());
    let lost_bundle = stores
        .assemble_realm_evidence(&with_imt_evidence, false)
        .await?;
    ensure!(lost_bundle.graph().counts().final_imt_leaves == 1);
    drop(lost_bundle);
    drop(stores);

    // Reconstruct both the exact physical observation and the live proof /
    // predecessor graph bundle, then persist SEALED. Its response is also
    // discarded so the following head publish is driven only by durable rows.
    let stores = open_combined_stores().await?;
    let recovered_state = match stores.executor().step(crash.identity()).await? {
        RepresentativeNormalCommitStep::StateVerifiedAwaitingRealmEvidence {
            state,
        } => state,
        other => bail!("expected re-derived AwaitingRealmEvidence, got {other:?}"),
    };
    let recovered_bundle =
        stores.assemble_realm_evidence(&with_imt_evidence, false).await?;
    ensure!(matches!(
        stores
            .executor()
            .seal_changed_realm_state_with_bundle(
                recovered_state,
                recovered_bundle,
            )
            .await?,
        RepresentativeNormalCommitStep::StateVerifiedAndSealed { .. }
    ));
    drop(stores);

    // Each following response is deliberately discarded with the adapters.
    // The next process is allowed to advance only from durable observations.
    let stores = open_combined_stores().await?;
    ensure!(matches!(
        stores.executor().step(crash.identity()).await?,
        RepresentativeNormalCommitStep::HeadPublishedAwaitingCommitted { .. }
    ));
    drop(stores);

    let stores = open_combined_stores().await?;
    ensure!(matches!(
        stores.executor().step(crash.identity()).await?,
        RepresentativeNormalCommitStep::CommittedPersisted { .. }
    ));
    drop(stores);

    let stores = open_combined_stores().await?;
    ensure!(matches!(
        stores.executor().step(crash.identity()).await?,
        RepresentativeNormalCommitStep::TimestampCompleted
    ));
    drop(stores);

    let stores = open_combined_stores().await?;
    ensure!(matches!(
        stores.executor().step(crash.identity()).await?,
        RepresentativeNormalCommitStep::Done { .. }
    ));
    drop(stores);

    // A second authority uses a positional contract-state update with no IMT
    // preimage payload. It still needs the complete CST -> UCT -> user -> GUT
    // predecessor graph and proof binding. Run the whole path with one replica
    // unavailable after all production-shaped adapters have been prepared.
    let without_imt_evidence = realm_evidence_fixture(1, 5, 10, false);
    let offline =
        fixture_for_realm_evidence(&without_imt_evidence, 21, 2_500, 27);
    let stores = open_combined_stores().await?;
    initialize_combined_fixture(&stores, &offline).await?;
    let without_imt_absent = seed_realm_evidence_predecessor(
        &stores.session,
        &without_imt_evidence,
    )
    .await?;
    let offline_plan =
        load_plan_from(&stores.manifests, offline.identity()).await?;
    ensure!(offline_plan.puts().all(|put| !matches!(
        put.resolved().mutation().key(),
        TypedTableKey::ImtLeaf { .. }
            | TypedTableKey::ImtKeyIndex { .. }
            | TypedTableKey::ImtCursor { .. }
    )));
    docker_container("stop", NODE_CONTAINERS[2])?;
    let offline_state = match stores.executor().step(offline.identity()).await? {
        RepresentativeNormalCommitStep::StateVerifiedAwaitingRealmEvidence {
            state,
        } => state,
        other => bail!("expected no-IMT AwaitingRealmEvidence, got {other:?}"),
    };
    let offline_bundle = stores
        .assemble_realm_evidence(&without_imt_evidence, false)
        .await?;
    ensure!(offline_bundle.graph().counts().final_imt_leaves == 0);
    ensure!(matches!(
        stores
            .executor()
            .seal_changed_realm_state_with_bundle(
                offline_state,
                offline_bundle,
            )
            .await?,
        RepresentativeNormalCommitStep::StateVerifiedAndSealed { .. }
    ));
    let committed = stores
        .executor()
        .drive_to_done(offline.identity(), 8)
        .await?;
    ensure!(
        committed.sealed().prepared().identity() == &offline.identity()
    );
    drop(stores);

    docker_container("start", NODE_CONTAINERS[2])?;
    wait_for_three_up_normal().await?;
    repair_flush_compact()?;

    let expected = expected_rows(&offline_plan)?;
    let mut replicas = Vec::new();
    for ip in NODE_IPS {
        replicas.push(read_direct_rows(ip, &offline_plan).await?);
    }
    let direct_one_state_replicas_equal =
        replicas.iter().all(|rows| rows == &expected);
    ensure!(direct_one_state_replicas_equal);

    let final_stores = open_combined_stores().await?;
    ensure!(matches!(
        final_stores.executor().step(crash.identity()).await?,
        RepresentativeNormalCommitStep::Done { .. }
    ));
    ensure!(matches!(
        final_stores.executor().step(offline.identity()).await?,
        RepresentativeNormalCommitStep::Done { .. }
    ));
    RepresentativeRealmStateReplayExecutor::new(&final_stores.state)
        .verify_exact(&offline_plan)
        .await?;

    let report = D04b2dReport {
        baseline: BASELINE,
        image: IMAGE,
        scylla_release: release,
        replication_factor: 3,
        regular_consistency: "QUORUM",
        serial_consistency: "LOCAL_SERIAL",
        restart_count: 8,
        with_imt_awaiting_evidence_survived_restart: true,
        live_evidence_lost_then_reacquired: true,
        with_imt_reached_sealed: true,
        without_imt_reached_sealed: true,
        implicit_zero_rows_observed_as_absent:
            with_imt_absent + without_imt_absent,
        head_response_loss_recovered: true,
        committed_response_loss_recovered: true,
        timestamp_response_loss_recovered: true,
        one_replica_offline_without_imt_reached_done: true,
        direct_one_state_replicas_equal,
        scenarios_passed: vec![
            "partial exact state restart stops at AwaitingRealmEvidence",
            "with-IMT proof plus predecessor graph assembles one live bundle",
            "live evidence lost before seal is reacquired from exact inputs",
            "with-IMT bundle is required before durable SEALED",
            "SEALED response loss resumes exact head publication",
            "head response loss recovers COMMITTED from durable state",
            "COMMITTED response loss recovers timestamp completion",
            "positional no-IMT update still validates CST-to-GUT graph",
            "one replica offline no-IMT combined drive reaches Done",
            "repair flush compact converges exact state rows on every replica",
        ],
        finished_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis() as u64,
        qualification: "representative changed-Realm lifecycle with real deterministic proof verification, Coordinator inclusion, exact predecessor Scylla reads, optional IMT preimage semantics, manifest/head/timestamp crash recovery and RF=3 degradation; not production Processor input capture or full 35-table coverage",
    };
    let report_path = std::env::var("PSY_D04B2D_REPORT_PATH")
        .unwrap_or_else(|_| "target/d04b2d-combined-normal-commit-rf3-report.json".into());
    let report_path = Path::new(&report_path);
    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(report_path, serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}

#[derive(Serialize)]
struct D04b2eReport {
    baseline: &'static str,
    image: &'static str,
    scylla_release: String,
    replication_factor: u8,
    regular_consistency: &'static str,
    serial_consistency: &'static str,
    conflicting_reservations_applied: u8,
    conflicting_reservations_rejected: u8,
    conflicting_live_evidence_distinct: bool,
    winner_live_bundle_read_from_rf3: bool,
    losing_publish_rejected_before_head_io: bool,
    winning_head_published: bool,
    exact_idempotent_publish_retries: usize,
    losing_manifest_absent: bool,
    winner_reached_done: bool,
    one_replica_offline: bool,
    direct_one_state_replicas_equal: bool,
    scenarios_passed: Vec<&'static str>,
    finished_unix_ms: u64,
    qualification: &'static str,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the destructive RF=3 harness and changed-Realm supplement orchestration"]
async fn d04b2e_conflicting_normal_commit_rf3_gate() -> anyhow::Result<()> {
    if std::env::var_os("PSY_D04B2E_RF3").is_none() {
        bail!("set PSY_D04B2E_RF3=1 through run-d04b2e.sh");
    }
    let initial_session = connect(None, Consistency::Quorum).await?;
    create_combined_schema(&initial_session).await?;
    let release = docker_exec(
        NODE_CONTAINERS[0],
        &["scylla", "--version"],
        "read D-04b2e Scylla version",
    )?
    .trim()
    .to_owned();
    drop(initial_session);

    // Both requests target the same authority and exact predecessor state,
    // but commit different prepared updates, proof inputs, mutation graphs,
    // checkpoint hashes, state roots, payloads and artifact digests. Their
    // independently sealed timestamp reservations therefore compete for the
    // same idle allocator revision.
    let left_evidence =
        realm_evidence_fixture_from_offsets(2, 9, 30, 31, true);
    let right_evidence =
        realm_evidence_fixture_from_offsets(2, 9, 30, 41, true);
    ensure!(left_evidence.prepared.old_realm_root == right_evidence.prepared.old_realm_root);
    ensure!(left_evidence.prepared.new_realm_root != right_evidence.prepared.new_realm_root);
    ensure!(left_evidence.coordinator.canonical_chain_ref != right_evidence.coordinator.canonical_chain_ref);
    ensure!(left_evidence.proof_bytes != right_evidence.proof_bytes);
    let left = fixture_for_realm_evidence(&left_evidence, 35, 4_000, 40);
    let right = fixture_for_realm_evidence(&right_evidence, 45, 4_000, 40);
    ensure!(
        AuthorityHeadView::expected(left.package.record())
            == AuthorityHeadView::expected(right.package.record())
    );
    ensure!(
        left.package.record().intent().artifacts().mutation_digest()
            != right.package.record().intent().artifacts().mutation_digest()
    );
    ensure!(
        left.package.record().intent().head_payload().as_bytes()
            != right.package.record().intent().head_payload().as_bytes()
    );
    ensure!(left.package.record().digest() != right.package.record().digest());
    ensure!(left.reservation.candidate() != right.reservation.candidate());
    ensure!(
        left.timestamp_bootstrap.candidate()
            == right.timestamp_bootstrap.candidate()
    );

    let common_head = left.head_bootstrap.candidate().clone();
    ensure!(
        *common_head.head() == AuthorityHeadView::expected(right.package.record())
    );
    let left_bundle = assemble_realm_evidence_from_fixture(&left_evidence)?;
    let right_bundle = assemble_realm_evidence_from_fixture(&right_evidence)?;
    ensure!(left_bundle.digest() != right_bundle.digest());
    let left_sealed = seal_fixture_for_head_gate(&left, left_bundle)?;
    let right_sealed = seal_fixture_for_head_gate(&right, right_bundle)?;
    let left_publish = publish_fixture_for_head_gate(
        &left,
        &left_sealed,
        &common_head,
    );
    let right_publish = publish_fixture_for_head_gate(
        &right,
        &right_sealed,
        &common_head,
    );
    ensure!(left_publish.head_cas().candidate() != right_publish.head_cas().candidate());

    let stores = open_combined_stores().await?;
    ensure!(matches!(
        stores
            .timestamps
            .bootstrap(left.timestamp_bootstrap)
            .await?,
        AuthorityTimestampWriteOutcome::Applied(_)
    ));
    ensure!(matches!(
        stores.heads.bootstrap(&left.head_bootstrap).await?,
        AuthorityLocalHeadWriteOutcome::Applied(_)
    ));

    // Exercise allocator ownership, state replay and the conflicting publish
    // attempts while one RF=3 member is unavailable.
    docker_container("stop", NODE_CONTAINERS[2])?;
    let (left_reservation, right_reservation) = tokio::join!(
        stores.timestamps.reserve(left.reservation),
        stores.timestamps.reserve(right.reservation),
    );
    let left_reservation = left_reservation?;
    let right_reservation = right_reservation?;
    let left_won = matches!(
        left_reservation,
        AuthorityTimestampWriteOutcome::Applied(_)
    );
    ensure!(
        (left_won
            && matches!(
                right_reservation,
                AuthorityTimestampWriteOutcome::Conflict(_)
            ))
            || (!left_won
                && matches!(
                    left_reservation,
                    AuthorityTimestampWriteOutcome::Conflict(_)
                )
                && matches!(
                    right_reservation,
                    AuthorityTimestampWriteOutcome::Applied(_)
                ))
    );

    let (
        winner,
        loser,
        winner_evidence,
        winner_publish,
        loser_publish,
        winner_sealed,
    ) =
        if left_won {
            (
                &left,
                &right,
                &left_evidence,
                left_publish,
                right_publish,
                left_sealed,
            )
        } else {
            (
                &right,
                &left,
                &right_evidence,
                right_publish,
                left_publish,
                right_sealed,
            )
        };

    ensure!(matches!(
        stores.manifests.persist_prepared(&winner.package).await?,
        psy_node_core::store::manifest_record::PreparedManifestWriteOutcome::Applied(_)
    ));
    let winner_plan = load_plan_from(&stores.manifests, winner.identity()).await?;
    let combined = stores.executor();
    let verified_state = match combined.step(winner.identity()).await? {
        RepresentativeNormalCommitStep::StateVerifiedAwaitingRealmEvidence {
            state,
        } => state,
        other => bail!("unexpected winner state step: {other:?}"),
    };
    let winner_bundle = stores
        .assemble_realm_evidence(winner_evidence, true)
        .await?;
    let durable_sealed = match combined
        .seal_changed_realm_state_with_bundle(verified_state, winner_bundle)
        .await?
    {
        RepresentativeNormalCommitStep::StateVerifiedAndSealed { sealed } => sealed,
        other => bail!("unexpected winner evidence seal: {other:?}"),
    };
    ensure!(durable_sealed == winner_sealed);

    let metadata = ScyllaNormalCommitMetadataExecutor::new(
        &stores.manifests,
        &stores.heads,
        &stores.timestamps,
    );
    let (winner_result, loser_result) = tokio::join!(
        metadata.publish_head(winner_publish.clone()),
        metadata.publish_head(loser_publish.clone()),
    );
    let committed = match winner_result? {
        NormalHeadPublishProgress::PersistCommitted { committed } => committed,
        other => bail!("unexpected winning publish result: {other:?}"),
    };
    ensure!(matches!(
        loser_result,
        Err(NormalCommitMetadataError::Orchestration(
            NormalCommitOrchestrationError::AllocatorOwnedByOtherIntent
        ))
    ));
    let current_head = match stores
        .heads
        .read(winner.identity().timestamp_key())
        .await?
    {
        psy_node_core::store::authority_local_head::AuthorityLocalHeadReadState::Current(head) => head,
        psy_node_core::store::authority_local_head::AuthorityLocalHeadReadState::Uninitialized => {
            bail!("authority head disappeared after winning publish")
        }
    };
    ensure!(current_head == *winner_publish.head_cas().candidate());

    // Exact duplicate requests remain safe: all observe the same candidate
    // and become idempotent COMMITTED capabilities rather than alternate
    // interpretations of the losing branch.
    let retry_results = join_all(
        (0..32).map(|_| metadata.publish_head(winner_publish.clone())),
    )
    .await;
    for result in retry_results {
        ensure!(matches!(
            result?,
            NormalHeadPublishProgress::PersistCommitted { .. }
        ));
    }

    metadata.persist_committed(&committed).await?;
    let completion = match metadata.plan(winner.identity()).await? {
        NormalCommitRecoveryAction::CompleteTimestampLease { completion } => completion,
        other => bail!("unexpected post-COMMITTED plan: {other:?}"),
    };
    metadata.complete_timestamp(completion).await?;
    ensure!(matches!(
        metadata.plan(winner.identity()).await?,
        NormalCommitRecoveryAction::Done { .. }
    ));
    ensure!(stores
        .manifests
        .read_lifecycle(loser.identity())
        .await?
        .is_none());
    ensure!(matches!(
        metadata.publish_head(loser_publish).await,
        Err(NormalCommitMetadataError::Orchestration(
            NormalCommitOrchestrationError::AllocatorDoesNotOwnIntent
        ))
    ));
    drop(metadata);
    drop(stores);

    docker_container("start", NODE_CONTAINERS[2])?;
    wait_for_three_up_normal().await?;
    repair_flush_compact()?;

    let expected = expected_rows(&winner_plan)?;
    let mut replicas = Vec::new();
    for ip in NODE_IPS {
        replicas.push(read_direct_rows(ip, &winner_plan).await?);
    }
    let direct_one_state_replicas_equal =
        replicas.iter().all(|rows| rows == &expected);
    ensure!(direct_one_state_replicas_equal);

    let final_stores = open_combined_stores().await?;
    ensure!(matches!(
        final_stores.executor().step(winner.identity()).await?,
        RepresentativeNormalCommitStep::Done { .. }
    ));
    ensure!(final_stores
        .manifests
        .read_lifecycle(loser.identity())
        .await?
        .is_none());

    let report = D04b2eReport {
        baseline: BASELINE,
        image: IMAGE,
        scylla_release: release,
        replication_factor: 3,
        regular_consistency: "QUORUM",
        serial_consistency: "LOCAL_SERIAL",
        conflicting_reservations_applied: 1,
        conflicting_reservations_rejected: 1,
        conflicting_live_evidence_distinct: true,
        winner_live_bundle_read_from_rf3: true,
        losing_publish_rejected_before_head_io: true,
        winning_head_published: true,
        exact_idempotent_publish_retries: 32,
        losing_manifest_absent: true,
        winner_reached_done: true,
        one_replica_offline: true,
        direct_one_state_replicas_equal,
        scenarios_passed: vec![
            "same predecessor state yields two distinct exact proof and mutation-graph bundles",
            "two live-evidence intent reservations have one durable owner",
            "winner reads exact predecessor rows from RF=3 before SEALED",
            "delayed losing live-evidence publish is rejected before head CAS",
            "winning replay includes exact IMT leaf/index/cursor physical rows",
            "winning publish is the only canonical head",
            "32 exact publish retries are idempotent",
            "loser cannot persist a manifest or complete a timestamp lease",
            "one replica offline flow converges after repair flush compact",
        ],
        finished_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis() as u64,
        qualification: "M20 requalified for two changed-Realm intents with one shared predecessor head and distinct exact prepared/GUTA/proof/Coordinator-inclusion/predecessor-graph bundles; winner uses RF=3 predecessor reads and representative Merkle/IMT/root-pair/singleton replay, but this is not production Processor integration or full table coverage",
    };
    let report_path = std::env::var("PSY_D04B2E_REPORT_PATH")
        .unwrap_or_else(|_| "target/d04b2e-normal-commit-conflict-rf3-report.json".into());
    let report_path = Path::new(&report_path);
    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(report_path, serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}
