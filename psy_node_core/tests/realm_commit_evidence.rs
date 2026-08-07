use std::collections::BTreeMap;

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
use psy_core::job::job_id::ProvingJobCircuitType;
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
    },
    manifest_intent::{
        AuthorityHeadPayload, AuthorityStateTransition,
        ManifestArtifactSetCommitment, SealedAuthorityCommitIntent,
    },
    manifest_lifecycle::{
        AuthorityHeadPayloadDigest, AuthorityHeadView,
        AuthorityPostWriteObservation, AuthorityProofObservation,
        ManifestLifecycleError, SealedAuthorityManifest,
    },
    manifest_record::PreparedAuthorityManifestRecord,
    realm_commit_evidence::{
        PersistedRealmCommitEvidence, RealmCommitEvidenceError,
        SealedRealmCommitEvidence, REALM_COMMIT_EVIDENCE_CODEC_VERSION,
        REALM_COMMIT_EVIDENCE_V1_LEN,
    },
    realm_manifest_evidence::{
        PersistedRealmManifestEvidence, RealmManifestEvidenceError,
        SealedRealmManifestEvidence, REALM_MANIFEST_EVIDENCE_CODEC_VERSION,
        REALM_MANIFEST_EVIDENCE_V1_LEN,
    },
    realm_imt_mutation_graph::{
        RealmImtBaselineNodeKey, RealmImtMutationGraphConfig,
        RealmImtMutationGraphPlan, SealedRealmImtMutationGraph,
    },
    realm_proof_binding::{RealmProofBindingError, SealedRealmProofBinding},
    timestamp::CommitWriteTimestampUs,
};
use psy_serialize::FastFixedSerializable;

const GLOBAL_HEIGHT: u8 = 4;
const COORDINATOR_HEIGHT: u8 = 2;
const UCT_HEIGHT: u8 = 3;
const CST_HEIGHT: u8 = 3;
const REALM_ID: u64 = 0;
const REALM_SUB_ID: u64 = 2;
const USER_ID: u64 = 1;
const CONTRACT_ID: u64 = 2;
const IMT_INDEX: u64 = 3;
const PREDECESSOR: u64 = 40;
const STATE: u64 = 41;

fn hash(seed: u8) -> PHash { PHash::from_owned_32bytes([seed; 32]) }

fn seeded(seed: u8, offset: u8) -> PHash { hash(seed.wrapping_add(offset)) }

fn levels(mut leaves: Vec<PHash>, height: u8) -> Vec<Vec<PHash>> {
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

fn simple_path(
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

fn single_path(
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

fn double_path(
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

fn encode_ffs<const N: usize, T: FastFixedSerializable<N>>(
    values: &[T],
) -> Vec<u8> {
    let mut result = Vec::with_capacity(values.len() * N);
    for value in values {
        result.extend_from_slice(&value.ffs_to_bytes());
    }
    result
}

fn inclusion_siblings(
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
struct DeterministicProofVerifier;

impl QZKProofPublicInputsHasherReader<PHash, PHash>
    for DeterministicProofVerifier
{
    fn get_proof_public_inputs_hash(proof: &PHash) -> anyhow::Result<PHash> {
        Ok(*proof)
    }

    fn try_proof_from_slice(bytes: &[u8]) -> anyhow::Result<PHash> {
        Ok(PHash::from_owned_32bytes(bytes.try_into()?))
    }
}

impl QZKProofVerifier<PHash, PHash> for DeterministicProofVerifier {
    fn verify_zk_proof(
        &self,
        _circuit_type: u32,
        proof: &PHash,
    ) -> anyhow::Result<PHash> {
        Ok(*proof)
    }
}

#[derive(Clone)]
struct Fixture {
    authority: AuthorityScope,
    coordinator_height: u8,
    prepared: PsyPreparedRealmBlockStateUpdates<PHash>,
    submission: GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<PF, PHash>,
    proof_bytes: Vec<u8>,
    coordinator: PsyRealmCoordinatorUpdate<PF, PHash>,
    heights: BTreeMap<u64, u8>,
    baseline: BTreeMap<RealmImtBaselineNodeKey, PHash>,
}

impl Fixture {
    fn proof_seal(
        &self,
    ) -> Result<SealedRealmProofBinding<PHash>, RealmProofBindingError> {
        SealedRealmProofBinding::verify_and_seal::<
            PF,
            PoseidonHasher,
            PHash,
            DeterministicProofVerifier,
        >(
            self.authority,
            &self.prepared,
            &self.submission,
            &self.proof_bytes,
            &DeterministicProofVerifier,
            &self.coordinator,
            self.coordinator_height,
        )
    }

    fn graph_seal(
        &self,
    ) -> anyhow::Result<SealedRealmImtMutationGraph<PHash, PoseidonHasher>> {
        self.graph_seal_with(
            self.authority,
            &self.prepared,
            PREDECESSOR,
            STATE,
        )
    }

    fn graph_seal_with(
        &self,
        authority: AuthorityScope,
        prepared: &PsyPreparedRealmBlockStateUpdates<PHash>,
        predecessor: u64,
        state: u64,
    ) -> anyhow::Result<SealedRealmImtMutationGraph<PHash, PoseidonHasher>> {
        let plan = RealmImtMutationGraphPlan::<PHash, PoseidonHasher>::try_from_prepared::<PF>(
            authority,
            AuthorityStateCheckpointId::new(predecessor),
            AuthorityStateCheckpointId::new(state),
            RealmImtMutationGraphConfig::try_new(
                GLOBAL_HEIGHT,
                self.coordinator_height,
                UCT_HEIGHT,
            )?,
            &self.heights,
            prepared,
        )?;
        let observations = plan
            .baseline_requests()
            .iter()
            .map(|key| (*key, self.baseline[key]))
            .collect::<Vec<_>>();
        Ok(plan.verify_and_seal(&observations)?)
    }
}

fn fixture(
    old_state_offset: u8,
    mutation_offset: u8,
    coordinator_height: u8,
) -> Fixture {
    let realm_id = USER_ID >> (GLOBAL_HEIGHT - coordinator_height);
    assert_eq!(realm_id, REALM_ID);
    let imt_preimage = IMTContractStateLeaf::<PF, PHash> {
        key: seeded(1, mutation_offset),
        value: seeded(2, mutation_offset),
        next_key: seeded(3, mutation_offset),
        next_index: PF::from_u64_value(1),
    };
    let imt_hash = imt_preimage.qfhash::<PoseidonHasher>();

    let mut cst_old_leaves = (0..(1u8 << CST_HEIGHT))
        .map(|i| seeded(20 + i, old_state_offset))
        .collect::<Vec<_>>();
    cst_old_leaves[2] = PoseidonHasher::get_zero_hash(0);
    let cst_old = levels(cst_old_leaves.clone(), CST_HEIGHT);
    cst_old_leaves[IMT_INDEX as usize] = imt_hash;
    let cst_new = levels(cst_old_leaves, CST_HEIGHT);

    let mut uct_old_leaves = (0..(1u8 << UCT_HEIGHT))
        .map(|i| seeded(40 + i, old_state_offset))
        .collect::<Vec<_>>();
    uct_old_leaves[CONTRACT_ID as usize] = cst_old[0][0];
    let uct_old = levels(uct_old_leaves.clone(), UCT_HEIGHT);
    uct_old_leaves[CONTRACT_ID as usize] = cst_new[0][0];
    let uct_new = levels(uct_old_leaves, UCT_HEIGHT);

    let old_user = PQEDUserLeaf::<PF, PHash> {
        public_key: seeded(60, old_state_offset),
        user_state_tree_root: uct_old[0][0],
        balance: PF::from_u64_value(10),
        nonce: PF::ZERO_VALUE,
        last_checkpoint_id: PF::from_u64_value(PREDECESSOR),
        event_index: PF::ZERO_VALUE,
        user_id: PF::from_u64_value(USER_ID),
    };
    let new_user = PQEDUserLeaf::<PF, PHash> {
        user_state_tree_root: uct_new[0][0],
        nonce: PF::from_u64_value(1),
        last_checkpoint_id: PF::from_u64_value(STATE),
        ..old_user
    };
    let mut gut_old_leaves = (0..(1u8 << GLOBAL_HEIGHT))
        .map(|i| seeded(80 + i, old_state_offset))
        .collect::<Vec<_>>();
    gut_old_leaves[USER_ID as usize] = old_user.qfhash::<PoseidonHasher>();
    let gut_old = levels(gut_old_leaves.clone(), GLOBAL_HEIGHT);
    gut_old_leaves[USER_ID as usize] = new_user.qfhash::<PoseidonHasher>();
    let gut_new = levels(gut_old_leaves, GLOBAL_HEIGHT);
    let old_realm_root =
        gut_old[usize::from(coordinator_height)][REALM_ID as usize];
    let new_realm_root =
        gut_new[usize::from(coordinator_height)][REALM_ID as usize];

    let prepared = PsyPreparedRealmBlockStateUpdates {
        realm_id: REALM_ID,
        realm_sub_id: REALM_SUB_ID,
        unique_pending_id: 90,
        proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId::from(91u128),
        old_realm_root,
        new_realm_root,
        update_global_user_tree_nodes_ffs: encode_ffs(&simple_path(
            &gut_new,
            GLOBAL_HEIGHT,
            USER_ID,
            coordinator_height,
        )),
        update_user_contract_tree_nodes_ffs: encode_ffs(&single_path(
            &uct_new,
            UCT_HEIGHT,
            USER_ID,
            CONTRACT_ID,
        )),
        update_contract_state_tree_nodes_ffs: encode_ffs(&double_path(
            &cst_new,
            CST_HEIGHT,
            USER_ID,
            CONTRACT_ID,
            IMT_INDEX,
        )),
        update_user_leaves_ffs: new_user.ffs_to_bytes().to_vec(),
        update_contract_state_imt_leaves_ffs:
            serialize_imt_leaf_ffs_entry_v2(
                USER_ID,
                CONTRACT_ID,
                IMT_INDEX,
                &imt_hash,
                &imt_preimage.key,
                &imt_preimage.value,
                &imt_preimage.next_key,
                imt_preimage.next_index.to_u64_value(),
                false,
            )
            .to_vec(),
    };

    let submission = GlobalUserTreeAggregatorHeaderWithTagValueAndJobType {
        header: GlobalUserTreeAggregatorHeaderWithTagValue {
            header: GlobalUserTreeAggregatorHeader {
                guta_circuit_whitelist: seeded(120, old_state_offset),
                checkpoint_tree_root: seeded(121, old_state_offset),
                state_transition: SubTreeNodeStateTransition {
                    old_node_value: old_realm_root,
                    new_node_value: new_realm_root,
                    node_index: PF::from_u64_value(REALM_ID),
                    node_level: PF::from_u64_value(u64::from(
                        coordinator_height,
                    )),
                },
                stats: GUTAStats::get_zero_value(),
                total_aggregation_proofs_generated: PF::from_u64_value(5),
            },
            new_tag_tree_node_value: seeded(122, old_state_offset),
        },
        job_type_u32: ProvingJobCircuitType::GUTASingleEndCap as u32,
    };
    let proof_bytes = submission
        .qfhash::<PoseidonHasher>()
        .into_owned_32bytes()
        .to_vec();
    let inclusion = MerkleProofCore::new_from_params::<PoseidonHasher>(
        REALM_ID,
        new_realm_root,
        inclusion_siblings(&gut_new, coordinator_height, REALM_ID),
    );
    assert_eq!(inclusion.root, gut_new[0][0]);
    let state_roots = PQEDCheckpointGlobalStateRoots {
        contract_tree_root: seeded(130, old_state_offset),
        deposit_tree_root: seeded(131, old_state_offset),
        user_tree_root: inclusion.root,
        withdrawal_tree_root: seeded(132, old_state_offset),
        user_registration_tree_root: seeded(133, old_state_offset),
    };
    let checkpoint_leaf = PQEDCheckpointLeaf {
        global_chain_root: state_roots.qfhash::<PoseidonHasher>(),
        stats: PQEDCheckpointLeafStats::<PF, PHash>::get_empty_stats(),
    };
    let checkpoint_leaf_hash = checkpoint_leaf.qfhash::<PoseidonHasher>();
    let mut block_state = QEDL2BlockState::get_genesis_value();
    block_state.checkpoint_id = STATE;
    let coordinator = PsyRealmCoordinatorUpdate {
        canonical_chain_ref: CanonicalChainRef::new(
            NetworkId::try_from_chain_id(1337).unwrap(),
            ChainEpoch::new(7),
            CheckpointRef::new(
                CheckpointId::new(STATE),
                CheckpointHash::from_proof_public_inputs_hash(seeded(
                    140,
                    old_state_offset,
                )),
            ),
        ),
        checkpoint_sync_info: PQEDCheckpointSyncInfoCompact {
            checkpoint_id: STATE,
            coordinator_id: 0,
            coordinator_sub_id: 0,
            coordinator_unique_pending_id: 80,
            block_state,
            state_roots,
            checkpoint_leaf,
            checkpoint_leaf_hash,
            checkpoint_tree_root: seeded(141, old_state_offset),
        },
        merkle_proof_to_realm_root: inclusion,
        reward_tree_top_proof:
            parth_core::crypto::hash::tag_tree::TagTreeMerkleProof::new_empty(),
    };

    let mut baseline = BTreeMap::new();
    for level in 0..=GLOBAL_HEIGHT {
        for (index, value) in
            gut_old[usize::from(level)].iter().enumerate()
        {
            baseline.insert(
                RealmImtBaselineNodeKey::GlobalUser {
                    level,
                    index: index as u64,
                },
                *value,
            );
        }
    }
    for level in 0..=UCT_HEIGHT {
        for (index, value) in
            uct_old[usize::from(level)].iter().enumerate()
        {
            baseline.insert(
                RealmImtBaselineNodeKey::UserContract {
                    user_id: USER_ID,
                    level,
                    index: index as u64,
                },
                *value,
            );
        }
    }
    for level in 0..=CST_HEIGHT {
        for (index, value) in
            cst_old[usize::from(level)].iter().enumerate()
        {
            baseline.insert(
                RealmImtBaselineNodeKey::ContractState {
                    user_id: USER_ID,
                    contract_id: CONTRACT_ID,
                    level,
                    index: index as u64,
                },
                *value,
            );
        }
    }

    Fixture {
        authority: AuthorityScope::Realm {
            realm_id: REALM_ID as u32,
            realm_sub_id: REALM_SUB_ID as u16,
        },
        coordinator_height,
        prepared,
        submission,
        proof_bytes,
        coordinator,
        heights: BTreeMap::from([(CONTRACT_ID, CST_HEIGHT)]),
        baseline,
    }
}

fn bundle(
    fixture: &Fixture,
) -> anyhow::Result<SealedRealmCommitEvidence<PHash, PoseidonHasher>> {
    Ok(SealedRealmCommitEvidence::try_bind(
        fixture.proof_seal()?,
        fixture.graph_seal()?,
    )?)
}

fn prepared_manifest(
    authority: AuthorityScope,
    candidate_chain: CanonicalChainRef<PHash>,
    predecessor: u64,
    old_root: PHash,
    new_root: PHash,
    changed: bool,
    seed: u8,
) -> PreparedAuthorityManifestRecord<PHash> {
    let key = AuthorityTimestampKey::new(candidate_chain.network_id(), authority);
    let expected_chain = CanonicalChainRef::new(
        candidate_chain.network_id(),
        candidate_chain.chain_epoch(),
        CheckpointRef::new(
            CheckpointId::new(STATE - 1),
            CheckpointHash::from_last_chain_hash(hash(200)),
        ),
    );
    let state_transition = if changed {
        AuthorityStateTransition::Changed {
            previous_checkpoint: AuthorityStateCheckpointId::new(predecessor),
            checkpoint: AuthorityStateCheckpointId::new(STATE),
            old_root: AuthorityStateRoot::from_local_state_root(old_root),
            new_root: AuthorityStateRoot::from_local_state_root(new_root),
        }
    } else {
        AuthorityStateTransition::Unchanged {
            checkpoint: AuthorityStateCheckpointId::new(predecessor),
            root: AuthorityStateRoot::from_local_state_root(old_root),
        }
    };
    let summary = vec![seed; 24];
    let artifacts = ManifestArtifactSetCommitment::from_verified_artifact_summary(
        &summary,
        [seed.wrapping_add(2); 32],
        1,
        1,
        1,
        8,
    )
    .unwrap();
    let intent = SealedAuthorityCommitIntent::seal_normal_advance(
        key,
        expected_chain,
        candidate_chain,
        state_transition,
        AuthorityHeadPayload::try_new(vec![seed.wrapping_add(3); 16]).unwrap(),
        artifacts,
    )
    .unwrap();
    let bootstrap = AuthorityTimestampBootstrap::new(
        key,
        CommitWriteTimestampUs::try_from_i128(2_000).unwrap(),
        AuthorityTimestampBootstrapReason::GenesisNative,
    );
    let reservation = bootstrap
        .candidate()
        .seal_reservation(
            key,
            intent.digest(),
            AuthorityClockSampleUs::try_from_i128(2_001).unwrap(),
        )
        .unwrap();
    let prepared = intent.attach_timestamp_lease(reservation.lease()).unwrap();
    PreparedAuthorityManifestRecord::seal(&prepared, summary).unwrap()
}

fn matching_manifest(
    fixture: &Fixture,
    seed: u8,
) -> PreparedAuthorityManifestRecord<PHash> {
    prepared_manifest(
        fixture.authority,
        fixture.coordinator.canonical_chain_ref,
        PREDECESSOR,
        fixture.prepared.old_realm_root,
        fixture.prepared.new_realm_root,
        true,
        seed,
    )
}

#[test]
fn real_proof_and_graph_seals_form_one_deterministic_bundle() {
    let fixture = fixture(0, 0, COORDINATOR_HEIGHT);
    let first = bundle(&fixture).unwrap();
    let second = bundle(&fixture).unwrap();
    assert_eq!(first.digest(), second.digest());
    assert_eq!(first.encode_canonical(), second.encode_canonical());
    assert_eq!(first.encode_canonical().len(), REALM_COMMIT_EVIDENCE_V1_LEN);
    assert_eq!(first.record().authority(), fixture.authority);
    assert_eq!(first.record().predecessor_checkpoint().get(), PREDECESSOR);
    assert_eq!(first.record().state_checkpoint().get(), STATE);
    assert_eq!(first.record().canonical_chain(), &fixture.coordinator.canonical_chain_ref);
    assert_eq!(first.record().old_realm_root(), &fixture.prepared.old_realm_root);
    assert_eq!(first.record().new_realm_root(), &fixture.prepared.new_realm_root);
    assert_eq!(first.record().proof_binding_digest(), first.proof().digest());
    assert_eq!(first.record().mutation_graph_digest(), first.graph().digest());
    assert_eq!(first.proof().prepared_payload_commitment(), first.graph().prepared_payload_commitment());

    let persisted = PersistedRealmCommitEvidence::<PHash>::decode_canonical(
        first.encode_canonical(),
    )
    .unwrap();
    assert_eq!(&persisted, first.record());
}

#[test]
fn authority_checkpoint_and_tree_height_must_match() {
    let base = fixture(0, 0, COORDINATOR_HEIGHT);

    let mut other_authority_prepared = base.prepared.clone();
    other_authority_prepared.realm_sub_id += 1;
    let other_authority = AuthorityScope::Realm {
        realm_id: REALM_ID as u32,
        realm_sub_id: (REALM_SUB_ID + 1) as u16,
    };
    assert_eq!(
        SealedRealmCommitEvidence::try_bind(
            base.proof_seal().unwrap(),
            base.graph_seal_with(
                other_authority,
                &other_authority_prepared,
                PREDECESSOR,
                STATE,
            )
            .unwrap(),
        )
        .unwrap_err(),
        RealmCommitEvidenceError::AuthorityMismatch,
    );

    assert_eq!(
        SealedRealmCommitEvidence::try_bind(
            base.proof_seal().unwrap(),
            base.graph_seal_with(
                base.authority,
                &base.prepared,
                PREDECESSOR,
                STATE + 1,
            )
            .unwrap(),
        )
        .unwrap_err(),
        RealmCommitEvidenceError::StateCheckpointMismatch {
            proof: AuthorityStateCheckpointId::new(STATE),
            graph: AuthorityStateCheckpointId::new(STATE + 1),
        },
    );

    let taller = fixture(0, 0, COORDINATOR_HEIGHT + 1);
    assert_eq!(
        SealedRealmCommitEvidence::try_bind(
            taller.proof_seal().unwrap(),
            base.graph_seal().unwrap(),
        )
        .unwrap_err(),
        RealmCommitEvidenceError::CoordinatorTreeHeightMismatch {
            proof: COORDINATOR_HEIGHT + 1,
            graph: COORDINATOR_HEIGHT,
        },
    );
}

#[test]
fn roots_and_exact_prepared_payload_must_match() {
    let base = fixture(0, 0, COORDINATOR_HEIGHT);
    let different_old_state = fixture(11, 0, COORDINATOR_HEIGHT);
    assert_eq!(
        SealedRealmCommitEvidence::try_bind(
            base.proof_seal().unwrap(),
            different_old_state.graph_seal().unwrap(),
        )
        .unwrap_err(),
        RealmCommitEvidenceError::OldRealmRootMismatch,
    );

    let different_transition = fixture(0, 50, COORDINATOR_HEIGHT);
    assert_eq!(
        SealedRealmCommitEvidence::try_bind(
            base.proof_seal().unwrap(),
            different_transition.graph_seal().unwrap(),
        )
        .unwrap_err(),
        RealmCommitEvidenceError::NewRealmRootMismatch,
    );

    let mut different_payload = base.prepared.clone();
    different_payload.unique_pending_id += 1;
    assert_eq!(
        SealedRealmCommitEvidence::try_bind(
            base.proof_seal().unwrap(),
            base.graph_seal_with(
                base.authority,
                &different_payload,
                PREDECESSOR,
                STATE,
            )
            .unwrap(),
        )
        .unwrap_err(),
        RealmCommitEvidenceError::PreparedPayloadMismatch,
    );
}

#[test]
fn persisted_codec_fails_closed_and_does_not_recreate_live_seals() {
    let bytes = bundle(&fixture(0, 0, COORDINATOR_HEIGHT))
        .unwrap()
        .encode_canonical()
        .to_vec();
    assert_eq!(
        PersistedRealmCommitEvidence::<PHash>::decode_canonical(
            &bytes[..bytes.len() - 1],
        ),
        Err(RealmCommitEvidenceError::InvalidCanonicalLength {
            expected: REALM_COMMIT_EVIDENCE_V1_LEN,
            actual: REALM_COMMIT_EVIDENCE_V1_LEN - 1,
        }),
    );

    let mut bad_magic = bytes.clone();
    bad_magic[0] ^= 1;
    assert_eq!(
        PersistedRealmCommitEvidence::<PHash>::decode_canonical(&bad_magic),
        Err(RealmCommitEvidenceError::InvalidMagic),
    );
    let mut bad_version = bytes.clone();
    bad_version[8..10].copy_from_slice(
        &(REALM_COMMIT_EVIDENCE_CODEC_VERSION + 1).to_le_bytes(),
    );
    assert_eq!(
        PersistedRealmCommitEvidence::<PHash>::decode_canonical(&bad_version),
        Err(RealmCommitEvidenceError::UnknownCodecVersion(2)),
    );
    let mut bad_payload = bytes.clone();
    bad_payload[100] ^= 1;
    assert_eq!(
        PersistedRealmCommitEvidence::<PHash>::decode_canonical(&bad_payload),
        Err(RealmCommitEvidenceError::BundleDigestMismatch),
    );
    let mut bad_digest = bytes;
    let last = bad_digest.len() - 1;
    bad_digest[last] ^= 1;
    assert_eq!(
        PersistedRealmCommitEvidence::<PHash>::decode_canonical(&bad_digest),
        Err(RealmCommitEvidenceError::BundleDigestMismatch),
    );
}

#[test]
fn bundle_digest_commits_to_both_live_component_seals() {
    let base = fixture(0, 0, COORDINATOR_HEIGHT);
    let baseline = bundle(&base).unwrap();
    let mut altered_proof_fixture = base.clone();
    altered_proof_fixture.coordinator.reward_tree_top_proof.root = hash(240);
    let altered = SealedRealmCommitEvidence::try_bind(
        altered_proof_fixture.proof_seal().unwrap(),
        base.graph_seal().unwrap(),
    )
    .unwrap();
    assert_ne!(baseline.proof().digest(), altered.proof().digest());
    assert_eq!(baseline.graph().digest(), altered.graph().digest());
    assert_ne!(baseline.digest(), altered.digest());
}

#[test]
fn live_bundle_binds_one_exact_prepared_manifest() {
    let fixture = fixture(0, 0, COORDINATOR_HEIGHT);
    let prepared = matching_manifest(&fixture, 31);
    let supplement = SealedRealmManifestEvidence::try_bind(
        &prepared,
        bundle(&fixture).unwrap(),
    )
    .unwrap();

    assert_eq!(
        supplement.encode_canonical().len(),
        REALM_MANIFEST_EVIDENCE_V1_LEN
    );
    assert_eq!(
        supplement.record().prepared_manifest_digest(),
        prepared.digest()
    );
    assert_eq!(
        supplement
            .record()
            .realm_commit_evidence()
            .canonical_chain(),
        prepared.intent().candidate_chain()
    );
    supplement.record().verify_for(&prepared).unwrap();

    let persisted = PersistedRealmManifestEvidence::<PHash>::decode_canonical(
        supplement.encode_canonical(),
    )
    .unwrap();
    assert_eq!(&persisted, supplement.record());
    assert_eq!(persisted.digest(), supplement.digest());
    persisted.verify_for(&prepared).unwrap();

    let same_identity_and_state_but_different_manifest =
        matching_manifest(&fixture, 32);
    assert_eq!(
        persisted
            .verify_for(&same_identity_and_state_but_different_manifest)
            .unwrap_err(),
        RealmManifestEvidenceError::PreparedManifestDigestMismatch
    );
}

#[test]
fn manifest_identity_state_and_roots_must_match_live_bundle() {
    let fixture = fixture(0, 0, COORDINATOR_HEIGHT);
    let different_authority = prepared_manifest(
        AuthorityScope::Realm {
            realm_id: REALM_ID as u32,
            realm_sub_id: (REALM_SUB_ID + 1) as u16,
        },
        fixture.coordinator.canonical_chain_ref,
        PREDECESSOR,
        fixture.prepared.old_realm_root,
        fixture.prepared.new_realm_root,
        true,
        40,
    );
    assert_eq!(
        SealedRealmManifestEvidence::try_bind(
            &different_authority,
            bundle(&fixture).unwrap(),
        )
        .unwrap_err(),
        RealmManifestEvidenceError::AuthorityMismatch
    );

    let different_chain = CanonicalChainRef::new(
        fixture.coordinator.canonical_chain_ref.network_id(),
        fixture.coordinator.canonical_chain_ref.chain_epoch(),
        CheckpointRef::new(
            CheckpointId::new(STATE),
            CheckpointHash::from_last_chain_hash(hash(241)),
        ),
    );
    let wrong_chain = prepared_manifest(
        fixture.authority,
        different_chain,
        PREDECESSOR,
        fixture.prepared.old_realm_root,
        fixture.prepared.new_realm_root,
        true,
        41,
    );
    assert_eq!(
        SealedRealmManifestEvidence::try_bind(
            &wrong_chain,
            bundle(&fixture).unwrap(),
        )
        .unwrap_err(),
        RealmManifestEvidenceError::CanonicalChainMismatch
    );

    let wrong_predecessor = prepared_manifest(
        fixture.authority,
        fixture.coordinator.canonical_chain_ref,
        PREDECESSOR - 1,
        fixture.prepared.old_realm_root,
        fixture.prepared.new_realm_root,
        true,
        42,
    );
    assert_eq!(
        SealedRealmManifestEvidence::try_bind(
            &wrong_predecessor,
            bundle(&fixture).unwrap(),
        )
        .unwrap_err(),
        RealmManifestEvidenceError::PredecessorCheckpointMismatch {
            manifest: AuthorityStateCheckpointId::new(PREDECESSOR - 1),
            bundle: AuthorityStateCheckpointId::new(PREDECESSOR),
        }
    );

    let wrong_old_root = prepared_manifest(
        fixture.authority,
        fixture.coordinator.canonical_chain_ref,
        PREDECESSOR,
        hash(242),
        fixture.prepared.new_realm_root,
        true,
        43,
    );
    assert_eq!(
        SealedRealmManifestEvidence::try_bind(
            &wrong_old_root,
            bundle(&fixture).unwrap(),
        )
        .unwrap_err(),
        RealmManifestEvidenceError::OldRealmRootMismatch
    );

    let wrong_new_root = prepared_manifest(
        fixture.authority,
        fixture.coordinator.canonical_chain_ref,
        PREDECESSOR,
        fixture.prepared.old_realm_root,
        hash(243),
        true,
        44,
    );
    assert_eq!(
        SealedRealmManifestEvidence::try_bind(
            &wrong_new_root,
            bundle(&fixture).unwrap(),
        )
        .unwrap_err(),
        RealmManifestEvidenceError::NewRealmRootMismatch
    );
}

#[test]
fn coordinator_or_unchanged_manifest_cannot_accept_realm_bundle() {
    let fixture = fixture(0, 0, COORDINATOR_HEIGHT);
    let coordinator = prepared_manifest(
        AuthorityScope::Coordinator,
        fixture.coordinator.canonical_chain_ref,
        PREDECESSOR,
        fixture.prepared.old_realm_root,
        fixture.prepared.new_realm_root,
        true,
        50,
    );
    assert_eq!(
        SealedRealmManifestEvidence::try_bind(
            &coordinator,
            bundle(&fixture).unwrap(),
        )
        .unwrap_err(),
        RealmManifestEvidenceError::RealmAuthorityRequired
    );

    let unchanged = prepared_manifest(
        fixture.authority,
        fixture.coordinator.canonical_chain_ref,
        PREDECESSOR,
        fixture.prepared.old_realm_root,
        fixture.prepared.old_realm_root,
        false,
        51,
    );
    assert_eq!(
        SealedRealmManifestEvidence::try_bind(
            &unchanged,
            bundle(&fixture).unwrap(),
        )
        .unwrap_err(),
        RealmManifestEvidenceError::ChangedRealmManifestRequired
    );
}

#[test]
fn manifest_supplement_codec_fails_closed_without_recreating_live_authority() {
    let fixture = fixture(0, 0, COORDINATOR_HEIGHT);
    let prepared = matching_manifest(&fixture, 60);
    let bytes = SealedRealmManifestEvidence::try_bind(
        &prepared,
        bundle(&fixture).unwrap(),
    )
    .unwrap()
    .encode_canonical()
    .to_vec();

    assert_eq!(
        PersistedRealmManifestEvidence::<PHash>::decode_canonical(
            &bytes[..bytes.len() - 1],
        ),
        Err(RealmManifestEvidenceError::InvalidCanonicalLength {
            expected: REALM_MANIFEST_EVIDENCE_V1_LEN,
            actual: REALM_MANIFEST_EVIDENCE_V1_LEN - 1,
        })
    );
    let mut bad_magic = bytes.clone();
    bad_magic[0] ^= 1;
    assert_eq!(
        PersistedRealmManifestEvidence::<PHash>::decode_canonical(&bad_magic),
        Err(RealmManifestEvidenceError::InvalidMagic)
    );
    let mut bad_version = bytes.clone();
    bad_version[8..10].copy_from_slice(
        &(REALM_MANIFEST_EVIDENCE_CODEC_VERSION + 1).to_le_bytes(),
    );
    assert_eq!(
        PersistedRealmManifestEvidence::<PHash>::decode_canonical(&bad_version),
        Err(RealmManifestEvidenceError::UnknownCodecVersion(2))
    );
    let mut bad_nested_bundle = bytes.clone();
    bad_nested_bundle[100] ^= 1;
    assert!(matches!(
        PersistedRealmManifestEvidence::<PHash>::decode_canonical(
            &bad_nested_bundle
        ),
        Err(RealmManifestEvidenceError::RealmCommitEvidence(
            RealmCommitEvidenceError::BundleDigestMismatch
        ))
    ));
    let mut bad_outer_digest = bytes;
    *bad_outer_digest.last_mut().unwrap() ^= 1;
    assert_eq!(
        PersistedRealmManifestEvidence::<PHash>::decode_canonical(
            &bad_outer_digest
        ),
        Err(RealmManifestEvidenceError::SupplementDigestMismatch)
    );
}

#[test]
fn changed_realm_lifecycle_consumes_and_persists_exact_supplement() {
    let fixture = fixture(0, 0, COORDINATOR_HEIGHT);
    let prepared = matching_manifest(&fixture, 70);
    let supplement = SealedRealmManifestEvidence::try_bind(
        &prepared,
        bundle(&fixture).unwrap(),
    )
    .unwrap();
    let expected_supplement = supplement.record().clone();
    let observation = AuthorityPostWriteObservation::new(
        AuthorityHeadView::candidate(&prepared),
        prepared.intent().artifacts().mutation_digest(),
        AuthorityHeadPayloadDigest::from_verified_payload_bytes(
            prepared.intent().head_payload().as_bytes(),
        ),
        AuthorityProofObservation::NotApplicableForRealm,
    )
    .attach_changed_realm_evidence(supplement);
    let sealed = SealedAuthorityManifest::verify_and_seal(
        prepared.clone(),
        observation,
    )
    .unwrap();
    assert_eq!(
        sealed.realm_manifest_evidence(),
        Some(&expected_supplement)
    );
    assert_eq!(
        sealed.encode_canonical()[sealed.encode_canonical().len()
            - REALM_MANIFEST_EVIDENCE_V1_LEN
            - 1],
        3
    );

    let decoded = SealedAuthorityManifest::<PHash>::decode_persisted(
        *prepared.identity(),
        sealed.revision().as_i64(),
        sealed.status() as i8,
        prepared.digest().as_bytes(),
        sealed.lifecycle_digest().as_bytes(),
        sealed.encode_canonical(),
    )
    .unwrap();
    assert_eq!(decoded, sealed);
    assert_eq!(
        decoded.realm_manifest_evidence(),
        Some(&expected_supplement)
    );
}

#[test]
fn unchanged_realm_lifecycle_rejects_a_changed_realm_supplement() {
    let fixture = fixture(0, 0, COORDINATOR_HEIGHT);
    let changed = matching_manifest(&fixture, 71);
    let supplement = SealedRealmManifestEvidence::try_bind(
        &changed,
        bundle(&fixture).unwrap(),
    )
    .unwrap();
    let unchanged = prepared_manifest(
        fixture.authority,
        fixture.coordinator.canonical_chain_ref,
        PREDECESSOR,
        fixture.prepared.old_realm_root,
        fixture.prepared.old_realm_root,
        false,
        72,
    );
    let observation = AuthorityPostWriteObservation::new(
        AuthorityHeadView::candidate(&unchanged),
        unchanged.intent().artifacts().mutation_digest(),
        AuthorityHeadPayloadDigest::from_verified_payload_bytes(
            unchanged.intent().head_payload().as_bytes(),
        ),
        AuthorityProofObservation::NotApplicableForRealm,
    )
    .attach_changed_realm_evidence(supplement);

    assert_eq!(
        SealedAuthorityManifest::verify_and_seal(unchanged, observation)
            .unwrap_err(),
        ManifestLifecycleError::UnchangedRealmEvidenceForbidden
    );
}

#[test]
fn changed_realm_lifecycle_rejects_supplement_for_another_prepared_record() {
    let fixture = fixture(0, 0, COORDINATOR_HEIGHT);
    let original = matching_manifest(&fixture, 73);
    let supplement = SealedRealmManifestEvidence::try_bind(
        &original,
        bundle(&fixture).unwrap(),
    )
    .unwrap();
    let other = matching_manifest(&fixture, 74);
    let observation = AuthorityPostWriteObservation::new(
        AuthorityHeadView::candidate(&other),
        other.intent().artifacts().mutation_digest(),
        AuthorityHeadPayloadDigest::from_verified_payload_bytes(
            other.intent().head_payload().as_bytes(),
        ),
        AuthorityProofObservation::NotApplicableForRealm,
    )
    .attach_changed_realm_evidence(supplement);

    assert_eq!(
        SealedAuthorityManifest::verify_and_seal(other, observation)
            .unwrap_err(),
        ManifestLifecycleError::RealmManifestEvidence(
            RealmManifestEvidenceError::PreparedManifestDigestMismatch
        )
    );
}
