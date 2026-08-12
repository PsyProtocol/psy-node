use std::collections::BTreeMap;

use parth_core::{
    PHash, PF, QCoreProcCheckpointUniqueId,
    crypto::hash::traits::{MerkleHasher, MerkleZeroHasher, QFieldHashable},
    data::hash::{
        merkle_node_key::SimpleMerkleNode,
        merkle_store_key::{
            QMerkleStoreDoubleIdKey, QMerkleStoreDoubleIdNode,
            QMerkleStoreSingleIdKey, QMerkleStoreSingleIdNode,
        },
    },
    felt::{FromPrimitiveValuesFelt, ToU64Value, ZeroableFelt},
    pgoldilocks::PoseidonHasher,
    protocol::core_types::Q256BitHash,
};
use psy_data::{
    prepared_block::realm::PsyPreparedRealmBlockStateUpdates,
    protocol::chain_context::{AuthorityScope, AuthorityStateCheckpointId},
    v1::qdata::{
        contract::{serialize_imt_leaf_ffs_entry_v2, IMTContractStateLeaf},
        user::PQEDUserLeaf,
    },
};
use psy_node_core::store::realm_imt_mutation_graph::{
    RealmImtBaselineNodeKey, RealmImtMutationGraphConfig,
    RealmImtMutationGraphError, RealmImtMutationGraphPlan,
    RealmImtPredecessorReadRow,
};
use psy_node_core::store::typed::{
    MutationValue, StructuredValueSchema, TypedTableKey,
};
use psy_serialize::FastFixedSerializable;

const GLOBAL_HEIGHT: u8 = 4;
const COORDINATOR_HEIGHT: u8 = 2;
const UCT_HEIGHT: u8 = 3;
const CST_HEIGHT: u8 = 3;
const REALM_ID: u64 = 1;
const REALM_SUB_ID: u64 = 2;
const USER_ID: u64 = 5;
const CONTRACT_ID: u64 = 2;
const IMT_INDEX: u64 = 3;

fn hash(seed: u8) -> PHash { PHash::from_owned_32bytes([seed; 32]) }

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

fn simple_path(tree: &[Vec<PHash>], height: u8, index: u64, min_level: u8) -> Vec<SimpleMerkleNode<PHash>> {
    (min_level..=height)
        .rev()
        .map(|level| {
            let at_level = index >> (height - level);
            SimpleMerkleNode::new(level, at_level, tree[usize::from(level)][at_level as usize])
        })
        .collect()
}

fn single_path(tree: &[Vec<PHash>], height: u8, tree_id: u64, index: u64) -> Vec<QMerkleStoreSingleIdNode<PHash>> {
    (0..=height)
        .rev()
        .map(|level| {
            let at_level = index >> (height - level);
            QMerkleStoreSingleIdNode {
                key: QMerkleStoreSingleIdKey { tree_id, level, index: at_level },
                value: tree[usize::from(level)][at_level as usize],
            }
        })
        .collect()
}

fn double_path(tree: &[Vec<PHash>], height: u8, tree_id: u64, tree_sub_id: u64, index: u64) -> Vec<QMerkleStoreDoubleIdNode<PHash>> {
    (0..=height)
        .rev()
        .map(|level| {
            let at_level = index >> (height - level);
            QMerkleStoreDoubleIdNode {
                key: QMerkleStoreDoubleIdKey { tree_id, tree_sub_id, level, index: at_level },
                value: tree[usize::from(level)][at_level as usize],
            }
        })
        .collect()
}

fn encode_ffs<const N: usize, T: FastFixedSerializable<N>>(values: &[T]) -> Vec<u8> {
    let mut result = Vec::with_capacity(values.len() * N);
    for value in values { result.extend_from_slice(&value.ffs_to_bytes()); }
    result
}

#[derive(Clone)]
struct Fixture {
    prepared: PsyPreparedRealmBlockStateUpdates<PHash>,
    heights: BTreeMap<u64, u8>,
    baseline: BTreeMap<RealmImtBaselineNodeKey, PHash>,
}

impl Fixture {
    fn config(&self) -> RealmImtMutationGraphConfig {
        RealmImtMutationGraphConfig::try_new(GLOBAL_HEIGHT, COORDINATOR_HEIGHT, UCT_HEIGHT).unwrap()
    }

    fn plan(&self) -> Result<RealmImtMutationGraphPlan<PHash, PoseidonHasher>, RealmImtMutationGraphError> {
        RealmImtMutationGraphPlan::<PHash, PoseidonHasher>::try_from_prepared::<PF>(
            AuthorityScope::Realm { realm_id: REALM_ID as u32, realm_sub_id: REALM_SUB_ID as u16 },
            AuthorityStateCheckpointId::new(40),
            AuthorityStateCheckpointId::new(41),
            self.config(),
            &self.heights,
            &self.prepared,
        )
    }

    fn observations(&self, plan: &RealmImtMutationGraphPlan<PHash, PoseidonHasher>) -> Vec<(RealmImtBaselineNodeKey, PHash)> {
        plan.baseline_requests().iter().map(|key| (*key, self.baseline[key])).collect()
    }
}

fn valid_fixture() -> Fixture {
    let imt_preimage = IMTContractStateLeaf::<PF, PHash> {
        key: hash(1),
        value: hash(2),
        next_key: hash(3),
        next_index: PF::from_u64_value(1),
    };
    let imt_hash = imt_preimage.qfhash::<PoseidonHasher>();

    let mut cst_old_leaves = (0..(1u8 << CST_HEIGHT)).map(|i| hash(20 + i)).collect::<Vec<_>>();
    cst_old_leaves[2] = PoseidonHasher::get_zero_hash(0);
    let cst_old = levels(cst_old_leaves.clone(), CST_HEIGHT);
    cst_old_leaves[IMT_INDEX as usize] = imt_hash;
    let cst_new = levels(cst_old_leaves, CST_HEIGHT);

    let mut uct_old_leaves = (0..(1u8 << UCT_HEIGHT)).map(|i| hash(40 + i)).collect::<Vec<_>>();
    uct_old_leaves[CONTRACT_ID as usize] = cst_old[0][0];
    let uct_old = levels(uct_old_leaves.clone(), UCT_HEIGHT);
    uct_old_leaves[CONTRACT_ID as usize] = cst_new[0][0];
    let uct_new = levels(uct_old_leaves, UCT_HEIGHT);

    let old_user = PQEDUserLeaf::<PF, PHash> {
        public_key: hash(60),
        user_state_tree_root: uct_old[0][0],
        balance: PF::from_u64_value(10),
        nonce: PF::ZERO_VALUE,
        last_checkpoint_id: PF::from_u64_value(40),
        event_index: PF::ZERO_VALUE,
        user_id: PF::from_u64_value(USER_ID),
    };
    let new_user = PQEDUserLeaf::<PF, PHash> {
        user_state_tree_root: uct_new[0][0],
        nonce: PF::from_u64_value(1),
        last_checkpoint_id: PF::from_u64_value(41),
        ..old_user
    };
    let mut gut_old_leaves = (0..(1u8 << GLOBAL_HEIGHT)).map(|i| hash(80 + i)).collect::<Vec<_>>();
    gut_old_leaves[USER_ID as usize] = old_user.qfhash::<PoseidonHasher>();
    let gut_old = levels(gut_old_leaves.clone(), GLOBAL_HEIGHT);
    gut_old_leaves[USER_ID as usize] = new_user.qfhash::<PoseidonHasher>();
    let gut_new = levels(gut_old_leaves, GLOBAL_HEIGHT);

    let prepared = PsyPreparedRealmBlockStateUpdates {
        realm_id: REALM_ID,
        realm_sub_id: REALM_SUB_ID,
        unique_pending_id: 90,
        proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId::from(91u128),
        old_realm_root: gut_old[COORDINATOR_HEIGHT as usize][REALM_ID as usize],
        new_realm_root: gut_new[COORDINATOR_HEIGHT as usize][REALM_ID as usize],
        update_global_user_tree_nodes_ffs: encode_ffs(&simple_path(&gut_new, GLOBAL_HEIGHT, USER_ID, COORDINATOR_HEIGHT)),
        update_user_contract_tree_nodes_ffs: encode_ffs(&single_path(&uct_new, UCT_HEIGHT, USER_ID, CONTRACT_ID)),
        update_contract_state_tree_nodes_ffs: encode_ffs(&double_path(&cst_new, CST_HEIGHT, USER_ID, CONTRACT_ID, IMT_INDEX)),
        update_user_leaves_ffs: new_user.ffs_to_bytes().to_vec(),
        update_contract_state_imt_leaves_ffs: serialize_imt_leaf_ffs_entry_v2(
            USER_ID,
            CONTRACT_ID,
            IMT_INDEX,
            &imt_hash,
            &imt_preimage.key,
            &imt_preimage.value,
            &imt_preimage.next_key,
            imt_preimage.next_index.to_u64_value(),
            false,
        ).to_vec(),
    };

    let mut baseline = BTreeMap::new();
    for level in 0..=GLOBAL_HEIGHT {
        for (index, value) in gut_old[level as usize].iter().enumerate() {
            baseline.insert(RealmImtBaselineNodeKey::GlobalUser { level, index: index as u64 }, *value);
        }
    }
    for level in 0..=UCT_HEIGHT {
        for (index, value) in uct_old[level as usize].iter().enumerate() {
            baseline.insert(RealmImtBaselineNodeKey::UserContract { user_id: USER_ID, level, index: index as u64 }, *value);
        }
    }
    for level in 0..=CST_HEIGHT {
        for (index, value) in cst_old[level as usize].iter().enumerate() {
            baseline.insert(RealmImtBaselineNodeKey::ContractState {
                user_id: USER_ID, contract_id: CONTRACT_ID, level, index: index as u64,
            }, *value);
        }
    }
    Fixture { prepared, heights: BTreeMap::from([(CONTRACT_ID, CST_HEIGHT)]), baseline }
}

#[test]
fn complete_real_ffs_graph_requires_baseline_and_seals_deterministically() {
    let fixture = valid_fixture();
    let plan = fixture.plan().unwrap();
    let observations = fixture.observations(&plan);
    let first = plan.verify_and_seal(&observations).unwrap();
    let second = plan.verify_and_seal(&observations).unwrap();
    assert_eq!(first.digest(), second.digest());
    assert_eq!(first.baseline_observation_digest(), second.baseline_observation_digest());
    assert_eq!(first.authority(), AuthorityScope::Realm { realm_id: 1, realm_sub_id: 2 });
    assert_eq!(first.predecessor_checkpoint().get(), 40);
    assert_eq!(first.state_checkpoint().get(), 41);
    assert_eq!(first.old_realm_root(), &fixture.prepared.old_realm_root);
    assert_eq!(first.new_realm_root(), &fixture.prepared.new_realm_root);
    assert_eq!(first.counts().global_nodes, 3);
    assert_eq!(first.counts().user_contract_nodes, 4);
    assert_eq!(first.counts().contract_state_nodes, 4);
    assert_eq!(first.counts().user_leaves, 1);
    assert_eq!(first.counts().final_imt_leaves, 1);
    assert!(!plan.baseline_requests().is_empty());
}

#[test]
fn sealed_graph_expands_only_its_exact_prepared_payload_into_typed_rows() {
    let fixture = valid_fixture();
    let plan = fixture.plan().unwrap();
    let sealed = plan
        .verify_and_seal(&fixture.observations(&plan))
        .unwrap();
    let rows = sealed
        .expand_exact_prepared_rows::<PF>(&fixture.prepared)
        .unwrap();

    assert_eq!(rows.global_user_merkle().len(), 3);
    assert_eq!(rows.user_contract_merkle().len(), 4);
    assert_eq!(rows.contract_state_merkle().len(), 4);
    assert_eq!(rows.user_leaves().len(), 1);
    assert_eq!(rows.imt_leaves().len(), 1);
    assert_eq!(
        rows.prepared_payload_commitment(),
        sealed.prepared_payload_commitment(),
    );
    assert!(matches!(
        &rows.user_leaves()[0],
        psy_node_core::store::typed::LogicalMutation::Put {
            key: TypedTableKey::UserLeaf { user, checkpoint },
            value: MutationValue::PsyCanonicalBytes(value),
        } if user.get() == USER_ID
            && checkpoint.get() == 41
            && value == &fixture.prepared.update_user_leaves_ffs
    ));
    assert!(matches!(
        &rows.imt_leaves()[0],
        psy_node_core::store::typed::LogicalMutation::Put {
            key: TypedTableKey::ImtLeaf { tree, tree_sub, leaf, checkpoint },
            value: MutationValue::Structured {
                schema: StructuredValueSchema::ImtLeafRowV1,
                canonical_bytes,
            },
        } if tree.get() == USER_ID
            && tree_sub.get() == CONTRACT_ID
            && leaf.get() == IMT_INDEX
            && checkpoint.get() == 41
            && canonical_bytes == &fixture.prepared.update_contract_state_imt_leaves_ffs
    ));

    let mut foreign = fixture.prepared.clone();
    foreign.unique_pending_id += 1;
    assert_eq!(
        sealed.expand_exact_prepared_rows::<PF>(&foreign),
        Err(RealmImtMutationGraphError::PreparedPayloadIdentityMismatch),
    );
}

#[test]
fn positional_cst_update_without_imt_preimages_still_seals_the_base_graph() {
    let mut fixture = valid_fixture();
    fixture.prepared.update_contract_state_imt_leaves_ffs.clear();

    let plan = fixture.plan().unwrap();
    let seal = plan
        .verify_and_seal(&fixture.observations(&plan))
        .unwrap();

    assert_eq!(seal.counts().final_imt_leaves, 0);
    assert_eq!(seal.counts().contract_state_nodes, 4);
    assert_eq!(seal.counts().user_contract_nodes, 4);
    assert_eq!(seal.counts().user_leaves, 1);
}

#[test]
fn imt_preimage_hash_and_canonical_flag_are_checked_before_graph_edges() {
    let mut fixture = valid_fixture();
    fixture.prepared.update_contract_state_imt_leaves_ffs.push(0);
    assert_eq!(
        fixture.plan().unwrap_err(),
        RealmImtMutationGraphError::MalformedImtLeaves
    );

    let mut fixture = valid_fixture();
    fixture.prepared.update_contract_state_imt_leaves_ffs[56] ^= 1;
    assert_eq!(fixture.plan().unwrap_err(), RealmImtMutationGraphError::ImtLeafHashMismatch {
        tree_id: USER_ID, contract_id: CONTRACT_ID, leaf_index: IMT_INDEX,
    });

    let mut fixture = valid_fixture();
    fixture.prepared.update_contract_state_imt_leaves_ffs[160] = 2;
    assert_eq!(fixture.plan().unwrap_err(), RealmImtMutationGraphError::NonCanonicalImtNewKeyFlag(2));
}

#[test]
fn every_cross_table_commitment_is_required() {
    let mut fixture = valid_fixture();
    fixture.prepared.update_contract_state_tree_nodes_ffs[25..57].copy_from_slice(&hash(200).into_owned_32bytes());
    assert_eq!(fixture.plan().unwrap_err(), RealmImtMutationGraphError::ImtToContractStateMismatch {
        tree_id: USER_ID, contract_id: CONTRACT_ID, leaf_index: IMT_INDEX,
    });

    let mut fixture = valid_fixture();
    fixture.prepared.update_user_contract_tree_nodes_ffs[17..49].copy_from_slice(&hash(201).into_owned_32bytes());
    assert_eq!(fixture.plan().unwrap_err(), RealmImtMutationGraphError::ContractStateToUserContractMismatch {
        user_id: USER_ID, contract_id: CONTRACT_ID,
    });

    let mut fixture = valid_fixture();
    fixture.prepared.update_user_leaves_ffs[32..64].copy_from_slice(&hash(202).into_owned_32bytes());
    assert_eq!(fixture.plan().unwrap_err(), RealmImtMutationGraphError::UserContractToUserLeafMismatch(USER_ID));

    let mut fixture = valid_fixture();
    fixture.prepared.update_global_user_tree_nodes_ffs[9..41].copy_from_slice(&hash(203).into_owned_32bytes());
    assert_eq!(fixture.plan().unwrap_err(), RealmImtMutationGraphError::UserLeafToGlobalTreeMismatch(USER_ID));
}

#[test]
fn malformed_duplicate_out_of_scope_and_missing_height_fail_closed() {
    let mut fixture = valid_fixture();
    fixture.prepared.update_global_user_tree_nodes_ffs.push(0);
    assert_eq!(fixture.plan().unwrap_err(), RealmImtMutationGraphError::MalformedGlobalNodes);

    let mut fixture = valid_fixture();
    let duplicate = fixture.prepared.update_contract_state_tree_nodes_ffs[0..57].to_vec();
    fixture.prepared.update_contract_state_tree_nodes_ffs.extend_from_slice(&duplicate);
    assert!(matches!(fixture.plan(), Err(RealmImtMutationGraphError::DuplicateMerkleMutation(_))));

    let mut fixture = valid_fixture();
    fixture.heights.clear();
    assert_eq!(fixture.plan().unwrap_err(), RealmImtMutationGraphError::ContractHeightMissing(CONTRACT_ID));

    let mut fixture = valid_fixture();
    fixture.prepared.realm_id = 2;
    assert_eq!(fixture.plan().unwrap_err(), RealmImtMutationGraphError::PreparedAuthorityMismatch);
}

#[test]
fn a_disconnected_written_node_is_rejected_even_when_roots_still_match() {
    let mut fixture = valid_fixture();
    let width = 49;
    fixture.prepared.update_user_contract_tree_nodes_ffs.drain(width..2 * width);
    assert!(matches!(fixture.plan(), Err(RealmImtMutationGraphError::MutationPathNotClosed(_))));
}

#[test]
fn baseline_observations_require_exact_typed_coverage() {
    let fixture = valid_fixture();
    let plan = fixture.plan().unwrap();
    let observations = fixture.observations(&plan);

    let missing_key = observations[0].0;
    assert_eq!(
        plan.verify_and_seal(&observations[1..]).unwrap_err(),
        RealmImtMutationGraphError::BaselineCoverageMismatch { missing: Some(missing_key), unexpected: None },
    );

    let mut extra = observations.clone();
    let extra_key = RealmImtBaselineNodeKey::GlobalUser { level: GLOBAL_HEIGHT, index: 15 };
    assert!(!plan.baseline_requests().contains(&extra_key));
    extra.push((extra_key, hash(220)));
    assert_eq!(
        plan.verify_and_seal(&extra).unwrap_err(),
        RealmImtMutationGraphError::BaselineCoverageMismatch { missing: None, unexpected: Some(extra_key) },
    );

    let mut duplicate = observations;
    duplicate.push(duplicate[0]);
    assert_eq!(
        plan.verify_and_seal(&duplicate).unwrap_err(),
        RealmImtMutationGraphError::DuplicateBaselineObservation(duplicate[0].0),
    );
}

#[test]
fn typed_predecessor_rows_bind_checkpoint_and_materialize_absent_zero_nodes() {
    let fixture = valid_fixture();
    let plan = fixture.plan().unwrap();
    let read_plan = plan.predecessor_read_plan();
    assert_eq!(read_plan.checkpoint(), AuthorityStateCheckpointId::new(40));
    assert_eq!(read_plan.requests().len(), plan.baseline_requests().len());

    let zero = PoseidonHasher::get_zero_hash(0);
    let rows = read_plan
        .requests()
        .iter()
        .copied()
        .map(|request| {
            let value = fixture.baseline[&request.key()];
            RealmImtPredecessorReadRow::new(request, (value != zero).then_some(value))
        })
        .collect::<Vec<_>>();
    assert!(rows.iter().any(|row| row.value().is_none()));

    let from_rows = plan.verify_predecessor_rows_and_seal(&rows).unwrap();
    let explicit = plan.verify_and_seal(&fixture.observations(&plan)).unwrap();
    assert_eq!(from_rows.digest(), explicit.digest());

    let missing = rows[0].request();
    assert_eq!(
        plan.verify_predecessor_rows_and_seal(&rows[1..]).unwrap_err(),
        RealmImtMutationGraphError::PredecessorReadCoverageMismatch {
            missing: Some(missing),
            unexpected: None,
        },
    );

    let mut duplicate = rows;
    duplicate.push(duplicate[0]);
    assert_eq!(
        plan.verify_predecessor_rows_and_seal(&duplicate).unwrap_err(),
        RealmImtMutationGraphError::DuplicatePredecessorReadRow(duplicate[0].request()),
    );
}

#[test]
fn predecessor_anchor_and_each_recomputed_parent_are_mandatory() {
    let fixture = valid_fixture();
    let plan = fixture.plan().unwrap();
    let mut observations = fixture.observations(&plan);
    let anchor = RealmImtBaselineNodeKey::GlobalUser { level: COORDINATOR_HEIGHT, index: REALM_ID };
    observations.iter_mut().find(|(key, _)| *key == anchor).unwrap().1 = hash(230);
    assert_eq!(plan.verify_and_seal(&observations).unwrap_err(), RealmImtMutationGraphError::PredecessorRealmRootMismatch);

    let mut observations = fixture.observations(&plan);
    let non_anchor = observations.iter_mut().find(|(key, _)| *key != anchor).unwrap();
    non_anchor.1 = hash(231);
    assert!(matches!(plan.verify_and_seal(&observations), Err(RealmImtMutationGraphError::MerkleParentMismatch(_))));
}

#[test]
fn checkpoint_and_config_boundaries_are_typed_and_fail_closed() {
    assert_eq!(RealmImtMutationGraphConfig::try_new(4, 4, 3), Err(RealmImtMutationGraphError::InvalidCoordinatorTreeHeight(4)));
    assert_eq!(RealmImtMutationGraphConfig::try_new(64, 2, 3), Err(RealmImtMutationGraphError::InvalidGlobalUserTreeHeight(64)));

    let fixture = valid_fixture();
    let result = RealmImtMutationGraphPlan::<PHash, PoseidonHasher>::try_from_prepared::<PF>(
        AuthorityScope::Realm { realm_id: 1, realm_sub_id: 2 },
        AuthorityStateCheckpointId::new(41),
        AuthorityStateCheckpointId::new(41),
        fixture.config(),
        &fixture.heights,
        &fixture.prepared,
    );
    assert_eq!(result.unwrap_err(), RealmImtMutationGraphError::InvalidCheckpointOrder);
}
