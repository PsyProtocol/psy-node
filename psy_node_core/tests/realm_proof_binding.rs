use parth_core::{
    PHash, PF, QCoreProcCheckpointUniqueId,
    crypto::hash::{
        merkle_proof::MerkleProofCore,
        traits::{QFieldHashable, ZeroableHash},
    },
    data::hash::merkle_node_key::SimpleMerkleNode,
    felt::{FromPrimitiveValuesFelt, ZeroableFelt},
    pgoldilocks::PoseidonHasher,
    protocol::core_types::{
        Q256BitHash, QZKProofPublicInputsHasherReader, QZKProofVerifier,
    },
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
        chain_context::AuthorityScope,
    },
    v1::qdata::{
        checkpoint::{
            PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf,
            PQEDCheckpointLeafStats, QEDL2BlockState,
        },
        checkpoint_sync::PQEDCheckpointSyncInfoCompact,
    },
};
use psy_node_core::store::realm_proof_binding::{
    PersistedRealmProofBinding, RealmProofBindingError,
    SealedRealmProofBinding, REALM_PROOF_BINDING_CODEC_VERSION,
    REALM_PROOF_BINDING_V1_LEN,
};
use psy_serialize::FastFixedSerializable;

const REALM_ID: u64 = 3;
const REALM_SUB_ID: u64 = 2;
const CHECKPOINT_ID: u64 = 42;
const TREE_HEIGHT: u8 = 4;

fn hash(seed: u8) -> PHash {
    PHash::from_owned_32bytes([seed; 32])
}

#[derive(Clone, Copy, Debug)]
struct DeterministicProofVerifier {
    reject: bool,
}

impl QZKProofPublicInputsHasherReader<PHash, PHash>
    for DeterministicProofVerifier
{
    fn get_proof_public_inputs_hash(proof: &PHash) -> anyhow::Result<PHash> {
        Ok(*proof)
    }

    fn try_proof_from_slice(bytes: &[u8]) -> anyhow::Result<PHash> {
        if bytes.len() != 32 {
            anyhow::bail!("fake proof must be exactly 32 bytes")
        }
        Ok(PHash::from_owned_32bytes(bytes.try_into().expect("fixed")))
    }
}

impl QZKProofVerifier<PHash, PHash> for DeterministicProofVerifier {
    fn verify_zk_proof(
        &self,
        _circuit_type: u32,
        proof: &PHash,
    ) -> anyhow::Result<PHash> {
        if self.reject {
            anyhow::bail!("injected verifier rejection")
        }
        Ok(*proof)
    }
}

#[derive(Clone)]
struct Fixture {
    authority: AuthorityScope,
    prepared: PsyPreparedRealmBlockStateUpdates<PHash>,
    submission: GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<PF, PHash>,
    proof_bytes: Vec<u8>,
    coordinator: PsyRealmCoordinatorUpdate<PF, PHash>,
}

impl Fixture {
    fn seal(
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
            &DeterministicProofVerifier { reject: false },
            &self.coordinator,
            TREE_HEIGHT,
        )
    }
}

fn valid_fixture() -> Fixture {
    let old_root = hash(1);
    let new_root = hash(2);
    let prepared = PsyPreparedRealmBlockStateUpdates {
        realm_id: REALM_ID,
        realm_sub_id: REALM_SUB_ID,
        unique_pending_id: 90,
        proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId::from(91u128),
        old_realm_root: old_root,
        new_realm_root: new_root,
        update_global_user_tree_nodes_ffs: SimpleMerkleNode::new(
            TREE_HEIGHT,
            REALM_ID,
            new_root,
        )
        .ffs_into_bytes()
        .to_vec(),
        update_user_contract_tree_nodes_ffs: vec![0x22; 64],
        update_contract_state_tree_nodes_ffs: vec![0x33; 64],
        update_user_leaves_ffs: vec![0x44; 64],
        update_contract_state_imt_leaves_ffs: vec![0x55; 161],
    };
    let submission = GlobalUserTreeAggregatorHeaderWithTagValueAndJobType {
        header: GlobalUserTreeAggregatorHeaderWithTagValue {
            header: GlobalUserTreeAggregatorHeader {
                guta_circuit_whitelist: hash(3),
                checkpoint_tree_root: hash(4),
                state_transition: SubTreeNodeStateTransition {
                    old_node_value: old_root,
                    new_node_value: new_root,
                    node_index: PF::from_u64_value(REALM_ID),
                    node_level: PF::from_u64_value(u64::from(TREE_HEIGHT)),
                },
                stats: GUTAStats::get_zero_value(),
                total_aggregation_proofs_generated: PF::from_u64_value(5),
            },
            new_tag_tree_node_value: hash(6),
        },
        job_type_u32: ProvingJobCircuitType::GUTASingleEndCap as u32,
    };
    let public_inputs = submission.qfhash::<PoseidonHasher>();
    let proof_bytes = public_inputs.into_owned_32bytes().to_vec();

    let siblings = (0..TREE_HEIGHT)
        .map(|index| hash(20 + index))
        .collect::<Vec<_>>();
    let inclusion = MerkleProofCore::new_from_params::<PoseidonHasher>(
        REALM_ID,
        new_root,
        siblings,
    );
    let state_roots = PQEDCheckpointGlobalStateRoots {
        contract_tree_root: hash(31),
        deposit_tree_root: hash(32),
        user_tree_root: inclusion.root,
        withdrawal_tree_root: hash(33),
        user_registration_tree_root: hash(34),
    };
    let checkpoint_leaf = PQEDCheckpointLeaf {
        global_chain_root: state_roots.qfhash::<PoseidonHasher>(),
        stats: PQEDCheckpointLeafStats::<PF, PHash>::get_empty_stats(),
    };
    let checkpoint_leaf_hash = checkpoint_leaf.qfhash::<PoseidonHasher>();
    let mut block_state = QEDL2BlockState::get_genesis_value();
    block_state.checkpoint_id = CHECKPOINT_ID;
    let canonical_chain_ref = CanonicalChainRef::new(
        NetworkId::try_from_chain_id(1337).unwrap(),
        ChainEpoch::new(7),
        CheckpointRef::new(
            CheckpointId::new(CHECKPOINT_ID),
            CheckpointHash::from_proof_public_inputs_hash(hash(35)),
        ),
    );
    let coordinator = PsyRealmCoordinatorUpdate {
        canonical_chain_ref,
        checkpoint_sync_info: PQEDCheckpointSyncInfoCompact {
            checkpoint_id: CHECKPOINT_ID,
            coordinator_id: 0,
            coordinator_sub_id: 0,
            coordinator_unique_pending_id: 80,
            block_state,
            state_roots,
            checkpoint_leaf,
            checkpoint_leaf_hash,
            checkpoint_tree_root: hash(36),
        },
        merkle_proof_to_realm_root: inclusion,
        reward_tree_top_proof: parth_core::crypto::hash::tag_tree::TagTreeMerkleProof::new_empty(),
    };

    Fixture {
        authority: AuthorityScope::Realm {
            realm_id: REALM_ID as u32,
            realm_sub_id: REALM_SUB_ID as u16,
        },
        prepared,
        submission,
        proof_bytes,
        coordinator,
    }
}

#[test]
fn real_types_seal_one_deterministic_binding_and_persisted_decode_is_not_sealed() {
    let fixture = valid_fixture();
    let first = fixture.seal().unwrap();
    let second = fixture.seal().unwrap();
    assert_eq!(first, second);
    assert_eq!(first.encode_canonical().len(), REALM_PROOF_BINDING_V1_LEN);

    let persisted = PersistedRealmProofBinding::<PHash>::decode_canonical(
        first.encode_canonical(),
    )
    .unwrap();
    assert_eq!(persisted, first.record().clone());
    assert_eq!(persisted.authority(), fixture.authority);
    assert_eq!(persisted.state_checkpoint().get(), CHECKPOINT_ID);
    assert_eq!(persisted.old_realm_root(), &fixture.prepared.old_realm_root);
    assert_eq!(persisted.new_realm_root(), &fixture.prepared.new_realm_root);
    assert_eq!(persisted.digest(), first.digest());
}

#[test]
fn prepared_authority_and_changed_imt_payload_are_mandatory() {
    let mut fixture = valid_fixture();
    fixture.authority = AuthorityScope::Coordinator;
    assert_eq!(fixture.seal(), Err(RealmProofBindingError::RealmAuthorityRequired));

    let mut fixture = valid_fixture();
    fixture.prepared.realm_sub_id += 1;
    assert_eq!(fixture.seal(), Err(RealmProofBindingError::PreparedAuthorityMismatch));

    let mut fixture = valid_fixture();
    fixture.prepared.new_realm_root = fixture.prepared.old_realm_root;
    assert_eq!(fixture.seal(), Err(RealmProofBindingError::ChangedRealmStateRequired));

    let mut fixture = valid_fixture();
    fixture.prepared.update_contract_state_imt_leaves_ffs.clear();
    assert_eq!(fixture.seal(), Err(RealmProofBindingError::ImtPreparedMutationRequired));

    let mut fixture = valid_fixture();
    fixture.prepared.update_global_user_tree_nodes_ffs.clear();
    assert_eq!(fixture.seal(), Err(RealmProofBindingError::RealmRootMutationRequired));

    let mut fixture = valid_fixture();
    fixture.prepared.update_global_user_tree_nodes_ffs.push(0);
    assert_eq!(fixture.seal(), Err(RealmProofBindingError::InvalidRealmRootMutationEncoding));

    let mut fixture = valid_fixture();
    fixture.prepared.update_global_user_tree_nodes_ffs =
        SimpleMerkleNode::new(TREE_HEIGHT, REALM_ID + 1, fixture.prepared.new_realm_root)
            .ffs_into_bytes()
            .to_vec();
    assert_eq!(fixture.seal(), Err(RealmProofBindingError::RealmRootMutationMissing));

    let mut fixture = valid_fixture();
    let duplicate = fixture.prepared.update_global_user_tree_nodes_ffs.clone();
    fixture
        .prepared
        .update_global_user_tree_nodes_ffs
        .extend_from_slice(&duplicate);
    assert_eq!(fixture.seal(), Err(RealmProofBindingError::DuplicateRealmRootMutation));

    let mut fixture = valid_fixture();
    fixture.prepared.update_global_user_tree_nodes_ffs =
        SimpleMerkleNode::new(TREE_HEIGHT, REALM_ID, hash(69))
            .ffs_into_bytes()
            .to_vec();
    assert_eq!(fixture.seal(), Err(RealmProofBindingError::RealmRootMutationValueMismatch));
}

#[test]
fn submission_must_bind_exact_realm_position_and_roots() {
    let mut fixture = valid_fixture();
    fixture.submission.header.header.state_transition.node_index = PF::from_u64_value(4);
    assert_eq!(fixture.seal(), Err(RealmProofBindingError::SubmissionRealmIndexMismatch));

    let mut fixture = valid_fixture();
    fixture.submission.header.header.state_transition.node_level = PF::from_u64_value(3);
    assert_eq!(fixture.seal(), Err(RealmProofBindingError::SubmissionRealmLevelMismatch));

    let mut fixture = valid_fixture();
    fixture.submission.header.header.state_transition.old_node_value = hash(70);
    assert_eq!(fixture.seal(), Err(RealmProofBindingError::SubmissionOldRootMismatch));

    let mut fixture = valid_fixture();
    fixture.submission.header.header.state_transition.new_node_value = hash(71);
    assert_eq!(fixture.seal(), Err(RealmProofBindingError::SubmissionNewRootMismatch));

    let mut fixture = valid_fixture();
    fixture.submission.job_type_u32 = ProvingJobCircuitType::AddL1Deposit as u32;
    assert_eq!(fixture.seal(), Err(RealmProofBindingError::NonGutaCircuit(2)));
}

#[test]
fn checkpoint_receipt_must_be_internally_consistent() {
    let mut fixture = valid_fixture();
    fixture.coordinator.checkpoint_sync_info.checkpoint_id += 1;
    assert_eq!(fixture.seal(), Err(RealmProofBindingError::CanonicalCheckpointMismatch));

    let mut fixture = valid_fixture();
    fixture.coordinator.checkpoint_sync_info.block_state.checkpoint_id += 1;
    assert_eq!(fixture.seal(), Err(RealmProofBindingError::L2CheckpointMismatch));

    let mut fixture = valid_fixture();
    fixture.coordinator.checkpoint_sync_info.state_roots.contract_tree_root = hash(80);
    assert_eq!(fixture.seal(), Err(RealmProofBindingError::CheckpointStateRootsMismatch));

    let mut fixture = valid_fixture();
    fixture.coordinator.checkpoint_sync_info.checkpoint_leaf_hash = hash(81);
    assert_eq!(fixture.seal(), Err(RealmProofBindingError::CheckpointLeafHashMismatch));
}

#[test]
fn coordinator_inclusion_checks_value_index_height_root_and_path() {
    let mut fixture = valid_fixture();
    fixture.coordinator.merkle_proof_to_realm_root.value = hash(90);
    assert_eq!(fixture.seal(), Err(RealmProofBindingError::InclusionValueMismatch));

    let mut fixture = valid_fixture();
    fixture.coordinator.merkle_proof_to_realm_root.index += 1;
    assert_eq!(fixture.seal(), Err(RealmProofBindingError::InclusionIndexMismatch));

    let mut fixture = valid_fixture();
    fixture.coordinator.merkle_proof_to_realm_root.siblings.pop();
    assert_eq!(fixture.seal(), Err(RealmProofBindingError::InclusionHeightMismatch { expected: TREE_HEIGHT, actual: 3 }));

    let mut fixture = valid_fixture();
    fixture.coordinator.merkle_proof_to_realm_root.root = hash(91);
    assert_eq!(fixture.seal(), Err(RealmProofBindingError::InclusionRootMismatch));

    let mut fixture = valid_fixture();
    fixture.coordinator.merkle_proof_to_realm_root.siblings[0] = hash(92);
    fixture.coordinator.merkle_proof_to_realm_root.root = fixture.coordinator.checkpoint_sync_info.state_roots.user_tree_root;
    assert_eq!(fixture.seal(), Err(RealmProofBindingError::InvalidInclusionProof));
}

#[test]
fn exact_proof_public_input_and_verifier_success_are_mandatory() {
    let mut fixture = valid_fixture();
    fixture.proof_bytes.clear();
    assert_eq!(fixture.seal(), Err(RealmProofBindingError::EmptyProofBytes));

    let mut fixture = valid_fixture();
    fixture.proof_bytes = hash(100).into_owned_32bytes().to_vec();
    assert_eq!(fixture.seal(), Err(RealmProofBindingError::ZkProofVerificationFailed));

    let fixture = valid_fixture();
    let result = SealedRealmProofBinding::verify_and_seal::<
        PF,
        PoseidonHasher,
        PHash,
        DeterministicProofVerifier,
    >(
        fixture.authority,
        &fixture.prepared,
        &fixture.submission,
        &fixture.proof_bytes,
        &DeterministicProofVerifier { reject: true },
        &fixture.coordinator,
        TREE_HEIGHT,
    );
    assert_eq!(result, Err(RealmProofBindingError::ZkProofVerificationFailed));
}

#[test]
fn tree_position_rejects_the_off_by_one_leaf_count_boundary() {
    let mut fixture = valid_fixture();
    fixture.prepared.realm_id = 1u64 << TREE_HEIGHT;
    fixture.authority = AuthorityScope::Realm {
        realm_id: fixture.prepared.realm_id as u32,
        realm_sub_id: REALM_SUB_ID as u16,
    };
    assert_eq!(fixture.seal(), Err(RealmProofBindingError::RealmIndexOutOfRange { realm_id: 16, coordinator_tree_height: TREE_HEIGHT }));
}

#[test]
fn persisted_codec_rejects_truncation_version_magic_and_digest_tampering() {
    let bytes = valid_fixture()
        .seal()
        .unwrap()
        .encode_canonical()
        .to_vec();
    assert_eq!(PersistedRealmProofBinding::<PHash>::decode_canonical(&bytes[..bytes.len() - 1]), Err(RealmProofBindingError::InvalidCanonicalLength { expected: REALM_PROOF_BINDING_V1_LEN, actual: REALM_PROOF_BINDING_V1_LEN - 1 }));

    let mut bad_magic = bytes.clone();
    bad_magic[0] ^= 1;
    assert_eq!(PersistedRealmProofBinding::<PHash>::decode_canonical(&bad_magic), Err(RealmProofBindingError::InvalidMagic));

    let mut bad_version = bytes.clone();
    bad_version[8..10].copy_from_slice(&(REALM_PROOF_BINDING_CODEC_VERSION + 1).to_le_bytes());
    assert_eq!(PersistedRealmProofBinding::<PHash>::decode_canonical(&bad_version), Err(RealmProofBindingError::UnknownCodecVersion(2)));

    let mut bad_payload = bytes.clone();
    bad_payload[100] ^= 1;
    assert_eq!(PersistedRealmProofBinding::<PHash>::decode_canonical(&bad_payload), Err(RealmProofBindingError::BindingDigestMismatch));

    let mut bad_digest = bytes;
    let last = bad_digest.len() - 1;
    bad_digest[last] ^= 1;
    assert_eq!(PersistedRealmProofBinding::<PHash>::decode_canonical(&bad_digest), Err(RealmProofBindingError::BindingDigestMismatch));
}

#[test]
fn every_bound_input_changes_the_binding_commitment() {
    let baseline = valid_fixture();
    let baseline_binding = baseline.seal().unwrap();

    let mut changed = baseline.clone();
    changed.prepared.update_contract_state_imt_leaves_ffs.push(1);
    assert_ne!(changed.seal().unwrap().digest(), baseline_binding.digest());

    let mut changed = baseline.clone();
    changed.submission.header.header.stats.total_transactions = PF::from_u64_value(1);
    let new_public_inputs = changed.submission.qfhash::<PoseidonHasher>();
    changed.proof_bytes = new_public_inputs.into_owned_32bytes().to_vec();
    assert_ne!(changed.seal().unwrap().digest(), baseline_binding.digest());

    let mut changed = baseline.clone();
    changed.proof_bytes = changed.submission.qfhash::<PoseidonHasher>().into_owned_32bytes().to_vec();
    changed.proof_bytes.extend_from_slice(&[0]);
    assert_eq!(changed.seal(), Err(RealmProofBindingError::ZkProofVerificationFailed));

    let mut changed = baseline;
    changed.coordinator.reward_tree_top_proof.root = hash(110);
    assert_ne!(changed.seal().unwrap().digest(), baseline_binding.digest());
}

#[test]
fn zero_hash_helpers_are_not_used_as_implicit_binding_defaults() {
    let fixture = valid_fixture();
    let sealed = fixture.seal().unwrap();
    assert_ne!(sealed.record().old_realm_root(), &PHash::get_zero_value());
    assert_ne!(sealed.record().new_realm_root(), &PHash::get_zero_value());
    assert_ne!(sealed.record().proof_public_inputs_hash().as_inner(), &PHash::get_zero_value());
    assert_ne!(PF::ZERO_VALUE, PF::from_u64_value(TREE_HEIGHT.into()));
}
