//! Test-only implementation of circuit 63. It validates the witness before
//! signing the same output/reward commitment used by the Plonky2 finalizer.
use anyhow::ensure;
use parth_common::{realm_rotation::RealmRotationConfig, secp256k1::MemorySecp256K1SinglePrivateKeyWallet};
use parth_core::{
    crypto::hash::{merkle_proof::MerkleProofCore, traits::{FieldQHasher, HashTo4Felts, QFieldHashable, ZeroableHash}},
    felt::{FromPrimitiveValuesFelt, ToU64Value},
    protocol::core_types::Q256BitHash,
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{
    guta::realm_finalize::{finalize_output_from_witness, finalize_public_input_hash, realm_validator_leaf_hash, validator_tree_index, RealmFinalizeGUTAInput},
    p2p::{validate_goldilocks_limb, MAX_VALIDATORS_PER_REALM},
    worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse,
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::{
    proof::{PsyTestJTMBProof, PsyTestJTMBProofVerifierData},
    proving::gadgets::{guta::verify_guta_proof::verify_guta_proof, merkle::{verify_delta_merkle_proof, verify_merkle_proof}},
    utils::{circuit_info_library::PsyJTMBCircuitInfoLibrary, jtmb_standard_circuit::{JTMBCircuitConfig, QJTMBProofCircuit, QJTMBProofCircuitBase}, proof_library::get_single_child_proof_for_api_response_with_inclusion_proof},
};

pub struct RealmFinalizeGUTACircuit<C: JTMBCircuitConfig> {
    private_key: MemorySecp256K1SinglePrivateKeyWallet,
    verifier_data: PsyTestJTMBProofVerifierData,
    fingerprint: C::Hash,
    global_user_tree_height: usize,
    realm_global_user_tree_height: usize,
    guta_whitelist_tree_height: u8,
    checkpoint_tree_height: usize,
    chain_domain: C::Hash,
    rotation: RealmRotationConfig,
}

impl<C: JTMBCircuitConfig> QJTMBProofCircuitBase<C::Hash> for RealmFinalizeGUTACircuit<C> {
    fn get_circuit_type(&self) -> ProvingJobCircuitType { ProvingJobCircuitType::RealmFinalizeGUTA }
    fn get_verifier_data(&self) -> &PsyTestJTMBProofVerifierData { &self.verifier_data }
    fn get_fingerprint(&self) -> C::Hash { self.fingerprint }
}

impl<C: JTMBCircuitConfig> RealmFinalizeGUTACircuit<C> {
    pub fn new(
        private_key: &MemorySecp256K1SinglePrivateKeyWallet,
        global_user_tree_height: usize,
        realm_global_user_tree_height: usize,
        guta_whitelist_tree_height: u8,
        checkpoint_tree_height: usize,
        chain_domain: C::Hash,
        rotation: RealmRotationConfig,
    ) -> Self {
        assert!(realm_global_user_tree_height <= global_user_tree_height && global_user_tree_height <= 63);
        assert!(global_user_tree_height - realm_global_user_tree_height <= 55);
        assert!((1..=63).contains(&checkpoint_tree_height));
        assert!(rotation.checkpoints_per_epoch > 0);
        assert!((1..=MAX_VALIDATORS_PER_REALM).contains(&rotation.validator_sub_ids.len()));
        assert!(rotation.validator_sub_ids.iter().all(|&id| id <= 255));
        assert!(rotation.validator_sub_ids.windows(2).all(|ids| ids[0] < ids[1]));
        let mut fields = chain_domain.to_4_felts().to_vec();
        fields.extend([global_user_tree_height as u64, realm_global_user_tree_height as u64,
            guta_whitelist_tree_height as u64, checkpoint_tree_height as u64,
            rotation.checkpoints_per_epoch, rotation.validator_sub_ids.len() as u64]
            .map(C::F::from_u64_value));
        fields.extend(rotation.validator_sub_ids.iter().map(|&id| C::F::from_u64_value(id as u64)));
        let config_hash = C::Hasher::q_hash_many(&fields);
        let verifier_data = PsyTestJTMBProofVerifierData::new_from_compressed_public_key(
            ProvingJobCircuitType::RealmFinalizeGUTA as u32, config_hash.into_owned_32bytes(), &private_key.get_public_key());
        let fingerprint = verifier_data.get_fingerprint::<C::Hash, C::Hasher, C::F>();
        Self { private_key: private_key.clone(), verifier_data, fingerprint, global_user_tree_height,
            realm_global_user_tree_height, guta_whitelist_tree_height, checkpoint_tree_height, chain_domain, rotation }
    }

    pub fn prove_base(
        &self,
        worker_reward_tag: C::Hash,
        input: &RealmFinalizeGUTAInput<C::F, C::Hash>,
        inclusion: &MerkleProofCore<C::Hash>,
        child_proof: &PsyTestJTMBProof<C::Hash>,
        child_verifier: &PsyTestJTMBProofVerifierData,
        child_rewards: C::Hash,
    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        verify_guta_proof::<C>(self.guta_whitelist_tree_height, inclusion, &input.root_guta_header,
            child_proof, child_verifier, child_rewards)?;
        let header = &input.root_guta_header;
        let realm_bits = self.global_user_tree_height - self.realm_global_user_tree_height;
        let realm_id = header.state_transition.node_index.to_u64_value();
        ensure!(realm_id < 1u64 << realm_bits && realm_id <= u32::MAX as u64, "finalizer realm out of range");
        ensure!(header.state_transition.node_level.to_u64_value() == realm_bits as u64, "finalizer realm level mismatch");
        let checkpoint_id = input.checkpoint_id.to_u64_value();
        let target = checkpoint_id.checked_add(1).ok_or_else(|| anyhow::anyhow!("checkpoint overflow"))?;
        ensure!(target < 1u64 << self.checkpoint_tree_height, "finalizer checkpoint out of range");
        let epoch = parth_common::realm_rotation::epoch(target, self.rotation.checkpoints_per_epoch);
        let anchor = parth_common::realm_rotation::anchor_checkpoint_id(epoch, self.rotation.checkpoints_per_epoch);
        verify_merkle_proof::<C::Hash, C::F, C::Hasher>(&input.anchor_checkpoint_tree_proof,
            header.checkpoint_tree_root, input.anchor_checkpoint_leaf.qfhash::<C::Hasher>(), anchor, self.checkpoint_tree_height)?;
        let seed = input.anchor_checkpoint_leaf.stats.random_seed.to_4_felts().map(|felt| felt.to_u64_value());
        ensure!(self.rotation.proposer_sub_id(realm_id as u32, target, seed)? == Some(input.realm_sub_id),
            "finalizer is not the scheduled proposer");
        let roots = &input.checkpoint_leaf.global_state_roots;
        ensure!(roots.qfhash::<C::Hasher>() == input.checkpoint_leaf.checkpoint_leaf.global_chain_root,
            "finalizer checkpoint state roots mismatch");
        verify_merkle_proof::<C::Hash, C::F, C::Hasher>(&input.checkpoint_tree_proof,
            header.checkpoint_tree_root, input.checkpoint_leaf.checkpoint_leaf.qfhash::<C::Hasher>(), checkpoint_id, self.checkpoint_tree_height)?;
        verify_merkle_proof::<C::Hash, C::F, C::Hasher>(&input.old_realm_root_proof,
            roots.user_tree_root, header.state_transition.old_node_value, realm_id, realm_bits)?;
        let user_id = input.validator_user_id.to_u64_value();
        ensure!(user_id < 1u64 << self.global_user_tree_height && user_id >> self.realm_global_user_tree_height == realm_id,
            "finalizer validator user is outside realm");
        for limb in input.validator_node_id_hash_limbs.iter().chain(input.validator_bls_hash_limbs.iter()) {
            validate_goldilocks_limb(*limb)?;
        }
        let validator_hash = realm_validator_leaf_hash::<C::F, C::Hash, C::Hasher>(
            user_id, input.validator_node_id_hash_limbs, input.validator_bls_hash_limbs);
        ensure!(validator_hash != C::Hash::get_zero_value(), "empty validator identity");
        verify_merkle_proof::<C::Hash, C::F, C::Hasher>(&input.validator_tree_proof,
            roots.validator_tree_root, validator_hash, validator_tree_index(realm_id as u32, input.realm_sub_id), realm_bits + 8)?;
        ensure!(input.validator_user_leaf.user_id == input.validator_user_id
            && input.current_validator_user_leaf.user_id == input.validator_user_id, "finalizer validator account mismatch");
        ensure!(input.validator_user_leaf.public_key != C::Hash::get_zero_value(), "empty validator account key");
        verify_merkle_proof::<C::Hash, C::F, C::Hasher>(&input.validator_user_tree_proof,
            roots.user_tree_root, input.validator_user_leaf.qfhash::<C::Hasher>(), user_id, self.global_user_tree_height)?;
        let local_index = user_id & ((1u64 << self.realm_global_user_tree_height) - 1);
        let current_hash = input.current_validator_user_leaf.qfhash::<C::Hasher>();
        verify_merkle_proof::<C::Hash, C::F, C::Hasher>(&input.current_validator_user_tree_proof,
            header.state_transition.new_node_value, current_hash, local_index, self.realm_global_user_tree_height)?;
        let balance = input.current_validator_user_leaf.balance.to_u64_value();
        let fee = header.stats.da_fees_collected.to_u64_value();
        let updated = balance.checked_add(fee).ok_or_else(|| anyhow::anyhow!("validator fee overflow"))?;
        ensure!(balance < 1u64 << 60 && fee < 1u64 << 60 && updated < 1u64 << 60, "validator balance exceeds 60 bits");
        let mut new_leaf = input.current_validator_user_leaf.clone();
        new_leaf.balance = C::F::from_u64_value(updated);
        if fee != 0 { new_leaf.last_checkpoint_id = input.checkpoint_id; }
        verify_delta_merkle_proof::<C::Hash, C::F, C::Hasher>(&input.validator_fee_delta_proof,
            header.state_transition.new_node_value, input.validator_fee_delta_proof.new_root,
            current_hash, new_leaf.qfhash::<C::Hasher>(), local_index, self.realm_global_user_tree_height)?;
        ensure!(header.total_aggregation_proofs_generated.to_u64_value().checked_add(1).is_some(), "finalizer proof count overflow");
        let output = finalize_output_from_witness::<C::F, C::Hash, C::Hasher>(input, self.chain_domain, child_rewards);
        let public_inputs = finalize_public_input_hash::<C::F, C::Hash, C::Hasher>(&output, &worker_reward_tag);
        self.verifier_data.generate_proof_with_signer::<C::Hasher, C::Hash, C::F, _>(public_inputs, &self.private_key)
    }
}

impl<L: PsyJTMBCircuitInfoLibrary<C::Hash>, C: JTMBCircuitConfig> QJTMBProofCircuit<C, L> for RealmFinalizeGUTACircuit<C> {
    fn jtmb_prove_with_raw_proofs_and_ref_library(
        &self,
        library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<C::Hash, QProvingJobDataID>,
        worker_reward_tag: C::Hash,
    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>> {
        input.ensure_expected_child_proof_count_with_tags(1)?;
        ensure!(input.base.job.job_id.circuit_type == ProvingJobCircuitType::RealmFinalizeGUTA, "expected finalizer job");
        let child = get_single_child_proof_for_api_response_with_inclusion_proof::<L, C::Hash, C::Hasher>(library, &input)?;
        let witness = RealmFinalizeGUTAInput::<C::F, C::Hash>::psy_ser_from_slice(&input.base.witness)?;
        self.prove_base(worker_reward_tag, &witness, &child.whitelist_inclusion_proof,
            &child.zk_proof, &child.verifier_data, child.reward_tag_tree_value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parth_common::memory_stores::simple_merkle_tree::SimpleMerkleTree;
    use parth_core::{
        crypto::hash::{merkle_proof::DeltaMerkleProofCore, traits::MerkleZeroHasher},
        pgoldilocks::PoseidonHasher,
        protocol::core_types::QZKProofVerifier,
    };
    use psy_core::worker::traits::QNextGenWorkerGenericInfo;
    use psy_data::{
        guta::{header::GlobalUserTreeAggregatorHeader, realm_finalize::finalize_reward_root63, stats::GUTAStats, sub_tree_transition::SubTreeNodeStateTransition},
        v1::qdata::{checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, PQEDCheckpointLeafStats, PQEDCheckpointLeafCompactWithStateRoots}, user::PQEDUserLeaf},
        worker::{api_response::{PsyWorkerGetProvingWorkAPIResponse, PROVING_JOB_NODE_TYPE_REALM}, metadata::PsyProvingJobMetadata, metadata_with_job_id::PsyProvingJobMetadataWithJobId},
    };
    use psy_worker_core::worker::prover_trait::PsyWorkerGenericLibraryProver;
    use crate::{
        protocol_types::JTMBPoseidonGoldilocksConfig,
        proving::guta_helper::QEDGUTACircuitManager,
        utils::{circuit_info_library::PsyJTMBCircuitInfoLibraryCore, proof_serialization::{serialize_jtmb_proof, deserialize_jtmb_proof}, simple_circuit_info_library::JTMBSimpleCircuitLibrary, generic_circuit_library::JTMBGenericCircuitVerifier},
        zk_verifier::PsyJTMBZKVerifier,
    };
    type C = JTMBPoseidonGoldilocksConfig;
    type F = parth_core::PF;
    type Hash = parth_core::PHash;
    type Hasher = PoseidonHasher;
    type Input = RealmFinalizeGUTAInput<F, Hash>;
    type Response = PsyWorkerGetProvingWorkWithChildProofsAPIResponse<Hash, QProvingJobDataID>;

    struct Fixture {
        manager: QEDGUTACircuitManager<C>,
        library: JTMBSimpleCircuitLibrary<C>,
        input: Input,
        child: PsyTestJTMBProof<Hash>,
        child_rewards: Hash,
        worker_tag: Hash,
    }

    impl Fixture {
        fn new(fee: u64, balance: u64, checkpoint: u64, count: u16) -> anyhow::Result<Self> {
            Self::new_for_realm(fee, balance, checkpoint, count, 0, 0, false)
        }

        fn new_for_realm(fee: u64, balance: u64, checkpoint: u64, count: u16,
            realm_id: u32, realm_bits: u8, changed_current: bool) -> anyhow::Result<Self> {
            let key = MemorySecp256K1SinglePrivateKeyWallet::new_from_private_key_bytes(&[7u8; 32])?;
            let rotation = RealmRotationConfig { checkpoints_per_epoch: 32, validator_sub_ids: (1..=count).collect() };
            let seed = [7, 11, 13, 17];
            let sub_id = rotation.proposer_sub_id(realm_id, checkpoint + 1, seed)?.unwrap();
            let manager = QEDGUTACircuitManager::<C>::new(&key, 4 + realm_bits as usize, 4, 4, 8, 4,
                Hash::from_values(1, 2, 3, 4), rotation);
            let mut library = JTMBSimpleCircuitLibrary::<C>::new();
            manager.register_library(&mut library);
            let zero = Hash::get_zero_value();
            let user = PQEDUserLeaf {
                user_id: F::from_u64_value(((realm_id as u64) << 4) | 1), public_key: Hash::from_values(1, 2, 3, 4),
                user_state_tree_root: zero, balance: F::from_u64_value(balance), nonce: F::from_u64_value(0),
                event_index: F::from_u64_value(0), last_checkpoint_id: F::from_u64_value(0),
            };
            let mut users = SimpleMerkleTree::<Hasher, Hash>::new(4);
            users.set_leaf(1, user.qfhash::<Hasher>());
            let user_proof = users.get_leaf(1);
            let mut top = SimpleMerkleTree::<Hasher, Hash>::new(realm_bits);
            top.set_leaf(realm_id as u64, user_proof.root);
            let old_realm_root_proof = top.get_leaf(realm_id as u64);
            let mut global_user_proof = user_proof.clone();
            global_user_proof.root = top.get_root();
            global_user_proof.index = user.user_id.to_u64_value();
            global_user_proof.siblings.extend_from_slice(&old_realm_root_proof.siblings);
            let mut current_user = user.clone();
            if changed_current {
                current_user.balance = F::from_u64_value(balance + 5);
                current_user.nonce = F::from_u64_value(1);
                current_user.public_key = Hash::from_values(41, 42, 43, 44);
                current_user.user_state_tree_root = Hash::from_values(51, 52, 53, 54);
            }
            users.set_leaf(1, current_user.qfhash::<Hasher>());
            let current_proof = users.get_leaf(1);
            let mut validators = SimpleMerkleTree::<Hasher, Hash>::new(realm_bits + 8);
            for id in 1..=count {
                let user_id = ((realm_id as u64) << 4) | if id == sub_id { 1 } else { id as u64 + 1 };
                validators.set_leaf(validator_tree_index(realm_id, id), realm_validator_leaf_hash::<F, Hash, Hasher>(
                    user_id, [id as u64, 2, 3, 4], [id as u64, 6, 7, 8]));
            }
            let validator_proof = validators.get_leaf(validator_tree_index(realm_id, sub_id));
            let validator_leaves = (((realm_id as u64) << 8)..(((realm_id as u64) + 1) << 8))
                .map(|index| validators.get_leaf(index).value).collect::<Vec<_>>();
            let roots = PQEDCheckpointGlobalStateRoots {
                contract_tree_root: zero, deposit_tree_root: zero, withdrawal_tree_root: zero,
                user_registration_tree_root: zero, user_tree_root: global_user_proof.root, validator_tree_root: validator_proof.root,
            };
            let mut stats = PQEDCheckpointLeafStats::get_empty_stats();
            stats.random_seed = Hash::from_values(seed[0], seed[1], seed[2], seed[3]);
            let leaf = PQEDCheckpointLeaf { global_chain_root: roots.qfhash::<Hasher>(), stats };
            let anchor = parth_common::realm_rotation::anchor_checkpoint_id(
                parth_common::realm_rotation::epoch(checkpoint + 1, 32), 32);
            let mut checkpoints = SimpleMerkleTree::<Hasher, Hash>::new(8);
            checkpoints.set_leaf(anchor, leaf.qfhash::<Hasher>());
            checkpoints.set_leaf(checkpoint, leaf.qfhash::<Hasher>());
            let checkpoint_proof = checkpoints.get_leaf(checkpoint);
            let header = GlobalUserTreeAggregatorHeader {
                guta_circuit_whitelist: manager.guta_circuit_whitelist_root,
                checkpoint_tree_root: checkpoint_proof.root,
                state_transition: SubTreeNodeStateTransition {
                    old_node_value: user_proof.root, new_node_value: current_proof.root,
                    node_index: F::from_u64_value(realm_id as u64), node_level: F::from_u64_value(realm_bits as u64),
                },
                stats: GUTAStats { da_fees_collected: F::from_u64_value(fee), ..GUTAStats::get_zero_value() },
                total_aggregation_proofs_generated: F::from_u64_value(1),
            };
            let child_rewards = Hash::from_values(21, 22, 23, 24);
            // A signed root fixture isolates finalizer validation from the child
            // aggregation algorithm; its signature and whitelist are still checked.
            let child = manager.verify_two_guta.get_verifier_data().generate_proof_with_signer::<Hasher, Hash, F, _>(
                Hasher::q_two_to_one(header.qfhash::<Hasher>(), child_rewards), &key)?;
            let mut new_user = current_user.clone();
            new_user.balance = F::from_u64_value(current_user.balance.to_u64_value().checked_add(fee).unwrap_or(0));
            if fee != 0 { new_user.last_checkpoint_id = F::from_u64_value(checkpoint); }
            users.set_leaf(1, new_user.qfhash::<Hasher>());
            let input = RealmFinalizeGUTAInput {
                root_guta_header: header,
                root_guta_whitelist_proof: manager.verify_two_guta_whitelist_proof.clone(),
                checkpoint_id: F::from_u64_value(checkpoint), realm_sub_id: sub_id,
                anchor_checkpoint_leaf: leaf.clone(), anchor_checkpoint_tree_proof: checkpoints.get_leaf(anchor),
                checkpoint_tree_proof: checkpoint_proof,
                checkpoint_leaf: PQEDCheckpointLeafCompactWithStateRoots {
                    checkpoint_leaf: leaf.to_compact::<Hasher>(), global_state_roots: roots,
                },
                old_realm_root_proof,
                validator_user_id: user.user_id, validator_node_id_hash_limbs: [sub_id as u64, 2, 3, 4],
                validator_bls_hash_limbs: [sub_id as u64, 6, 7, 8], validator_tree_proof: validator_proof,
                validator_leaves,
                validator_user_leaf: user.clone(), validator_user_tree_proof: global_user_proof,
                current_validator_user_leaf: current_user, current_validator_user_tree_proof: current_proof.clone(),
                validator_fee_delta_proof: DeltaMerkleProofCore {
                    old_value: current_proof.value, new_value: new_user.qfhash::<Hasher>(), old_root: current_proof.root,
                    new_root: users.get_root(), index: 1, siblings: current_proof.siblings,
                },
            };
            Ok(Self { manager, library, input, child, child_rewards, worker_tag: Hash::from_values(31, 32, 33, 34) })
        }

        fn response(&self, input: &Input) -> anyhow::Result<Response> {
            let output = finalize_output_from_witness::<F, Hash, Hasher>(input,
                Hash::from_values(1, 2, 3, 4), self.child_rewards);
            Ok(Response {
                base: PsyWorkerGetProvingWorkAPIResponse {
                    job: PsyProvingJobMetadataWithJobId {
                        job_id: QProvingJobDataID::realm_finalize_guta(input.checkpoint_id.to_u64_value(), input.root_guta_header.state_transition.node_index.to_u64_value() as u32),
                        metadata: PsyProvingJobMetadata {
                            expected_public_inputs_hash: output.final_guta_header.qfhash::<Hasher>(),
                            reward_tree_node_index: 0, reward_tree_node_level: 0,
                            reward_tree_hash_mode: psy_data::worker::metadata::PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD,
                            reward_tree_node_children: 2,
                            dependencies: vec![QProvingJobDataID::new_proof_job_id(0, 0, ProvingJobCircuitType::GUTATwoGUTA, 0, 0)],
                        },
                    },
                    child_proof_tag_values: vec![self.child_rewards], realm_id: input.root_guta_header.state_transition.node_index.to_u64_value(), realm_sub_id: input.realm_sub_id as u64,
                    unique_pending_id: 0, node_type: PROVING_JOB_NODE_TYPE_REALM, witness: input.psy_ser_to_bytes_vec()?,
                },
                input_proofs: vec![serialize_jtmb_proof(&self.child)?],
            })
        }

        fn prove(&self, input: &Input) -> anyhow::Result<Vec<u8>> {
            self.manager.prove_job_from_api(&self.library, self.response(input)?, self.worker_tag)
        }
    }

    #[test]
    fn finalizer_worker_dispatch_and_public_input_binding() -> anyhow::Result<()> {
        for checkpoint in [0, 30, 31, 32, 63] {
            for fee in [0, 9] {
                let fixture = Fixture::new(fee, 100, checkpoint, 3)?;
                let response = fixture.response(&fixture.input)?;
                assert!(fixture.manager.can_process_job(response.base.job.job_id));
                let bytes = fixture.prove(&fixture.input)?;
                let proof = deserialize_jtmb_proof::<Hash>(&bytes)?;
                let output = finalize_output_from_witness::<F, Hash, Hasher>(&fixture.input,
                    Hash::from_values(1, 2, 3, 4), fixture.child_rewards);
                let expected = finalize_public_input_hash::<F, Hash, Hasher>(&output, &fixture.worker_tag);
                let verifier = PsyJTMBZKVerifier::new(JTMBGenericCircuitVerifier { library: fixture.library });
                verifier.verify_zk_proof_from_slice_check_public_inputs_hash(63, &bytes, expected)?;
                assert_eq!(proof.public_inputs_hash, expected);
                let reward = finalize_reward_root63::<F, Hash, Hasher>(&output, &fixture.worker_tag);
                assert_eq!(reward, response.base.job.metadata.get_new_rewards_tag_tree_value::<Hasher>(
                    fixture.worker_tag, &[fixture.child_rewards, output.qfhash::<Hasher>()])?);
                assert!(verifier.verify_zk_proof_from_slice_check_public_inputs_hash(63, &bytes, Hash::get_zero_value()).is_err());
            }
        }
        Ok(())
    }

    #[test]
    fn finalizer_nonzero_realm_uses_current_account_for_fee() -> anyhow::Result<()> {
        for fee in [0, 9] {
            let fixture = Fixture::new_for_realm(fee, 100, 32, 3, 3, 2, true)?;
            assert_eq!(fixture.input.validator_user_id.to_u64_value(), 49);
            assert_eq!(fixture.input.validator_user_tree_proof.index, 49);
            assert_eq!(fixture.input.current_validator_user_tree_proof.index, 1);
            assert!(fixture.prove(&fixture.input).is_ok());
            let mut tampered = fixture.input.clone();
            // This is a valid Merkle delta, but incorrectly credits the older
            // checkpoint account instead of preserving the post-GUTA account.
            let mut wrong = tampered.validator_user_leaf.clone();
            wrong.balance = F::from_u64_value(100 + fee);
            if fee != 0 { wrong.last_checkpoint_id = tampered.checkpoint_id; }
            tampered.validator_fee_delta_proof.new_value = wrong.qfhash::<Hasher>();
            tampered.validator_fee_delta_proof.new_root = parth_core::crypto::hash::merkle_proof::compute_root_merkle_proof_generic::<Hash, Hasher>(
                tampered.validator_fee_delta_proof.new_value, 1, &tampered.validator_fee_delta_proof.siblings);
            assert!(tampered.validator_fee_delta_proof.verify::<Hasher>());
            assert!(fixture.prove(&tampered).is_err());
        }
        Ok(())
    }

    #[test]
    fn finalizer_coordinator_dispatch_and_parent_inclusion() -> anyhow::Result<()> {
        let fixture = Fixture::new(9, 100, 32, 3)?;
        let key = MemorySecp256K1SinglePrivateKeyWallet::new_from_private_key_bytes(&[7u8; 32])?;
        let coordinator = crate::proving::coordinator_helper::QEDCoordinatorCircuitManager::<C>::new(
            &key, 4, 4, 4, 8, 1, 32, 64, 1, 2, 8, 2, 4, Hash::from_values(1, 2, 3, 4),
            RealmRotationConfig { checkpoints_per_epoch: 32, validator_sub_ids: vec![1, 2, 3] });
        let mut library = JTMBSimpleCircuitLibrary::<C>::new();
        coordinator.register_library(&mut library);
        let response = fixture.response(&fixture.input)?;
        let finalizer_job = response.base.job.job_id;
        assert!(coordinator.can_process_job(finalizer_job));
        let bytes = coordinator.prove_job_from_api(&library, response, fixture.worker_tag)?;
        let proof = deserialize_jtmb_proof::<Hash>(&bytes)?;
        library.verify_proof_of_type(ProvingJobCircuitType::RealmFinalizeGUTA, &proof)?;
        for parent in [ProvingJobCircuitType::GUTATwoGUTA, ProvingJobCircuitType::GUTAVerifyToCap,
            ProvingJobCircuitType::GUTATwoGUTALinearUpgradeCheckpoint, ProvingJobCircuitType::RealmFinalizeGUTA] {
            let inclusion = library.get_group_inclusion_proof(parent, ProvingJobCircuitType::RealmFinalizeGUTA)?;
            assert_eq!(inclusion.value, coordinator.guta_circuits.realm_finalize_guta.get_fingerprint());
            assert_eq!(inclusion.root, coordinator.guta_circuits.guta_circuit_whitelist_root);
            assert!(inclusion.verify::<Hasher>());
        }
        let output = finalize_output_from_witness::<F, Hash, Hasher>(&fixture.input,
            Hash::from_values(1, 2, 3, 4), fixture.child_rewards);
        let reward = finalize_reward_root63::<F, Hash, Hasher>(&output, &fixture.worker_tag);
        let witness = psy_data::proof_input::guta::VerifyGUTAToCapCircuitInputSimple {
            guta_proof_header: output.final_guta_header, top_line_siblings: vec![],
        };
        let new_header = crate::proving::gadgets::guta::verify_to_cap::verify_guta_to_cap::<C>(
            &witness.guta_proof_header, &witness.top_line_siblings)?;
        let mut response = fixture.response(&fixture.input)?;
        response.base.job.job_id = QProvingJobDataID::new_proof_job_id(0, 0, ProvingJobCircuitType::GUTAVerifyToCap, 1, 0);
        response.base.job.metadata.dependencies = vec![finalizer_job];
        response.base.job.metadata.expected_public_inputs_hash = new_header.qfhash::<Hasher>();
        response.base.job.metadata.reward_tree_hash_mode = psy_data::worker::metadata::PROOF_REWARD_TREE_HASH_MODE_LIFT_CHILD;
        response.base.job.metadata.reward_tree_node_children = 1;
        response.base.child_proof_tag_values = vec![reward];
        response.base.witness = witness.psy_ser_to_bytes_vec()?;
        response.input_proofs = vec![bytes];
        let lifted = coordinator.prove_job_from_api(&library, response.clone(), fixture.worker_tag)?;
        let lifted = deserialize_jtmb_proof::<Hash>(&lifted)?;
        library.verify_proof_of_type(ProvingJobCircuitType::GUTAVerifyToCap, &lifted)?;
        let expected = crate::proving::gadgets::guta::guta_header::compute_guta_public_inputs_hash_two_children::<F, Hash, Hasher>(
            &new_header, reward, Hash::get_zero_value(), fixture.worker_tag);
        assert_eq!(lifted.public_inputs_hash, expected);
        response.base.child_proof_tag_values[0] = Hash::get_zero_value();
        assert!(coordinator.prove_job_from_api(&library, response, fixture.worker_tag).is_err());
        Ok(())
    }

    #[test]
    fn finalizer_rejects_tampered_witnesses() -> anyhow::Result<()> {
        let fixture = Fixture::new(9, 100, 32, 3)?;
        assert!(fixture.prove(&fixture.input).is_ok());
        let mutations: &[fn(&mut Input)] = &[
            |w| w.realm_sub_id = if w.realm_sub_id == 1 { 2 } else { 1 },
            |w| w.checkpoint_id = F::from_u64_value(33),
            |w| w.anchor_checkpoint_tree_proof.index = 30,
            |w| w.anchor_checkpoint_leaf.stats.random_seed = Hash::from_values(1, 1, 1, 1),
            |w| w.checkpoint_leaf.global_state_roots.validator_tree_root = Hash::get_zero_value(),
            |w| w.validator_node_id_hash_limbs[0] += 1,
            |w| w.validator_bls_hash_limbs[0] += 1,
            |w| w.validator_tree_proof.siblings[0] = Hash::from_values(8, 8, 8, 8),
            |w| w.validator_user_id = F::from_u64_value(2),
            |w| w.validator_user_tree_proof.index = 2,
            |w| w.current_validator_user_leaf.nonce = F::from_u64_value(1),
            |w| w.current_validator_user_tree_proof.index = 2,
            |w| w.validator_fee_delta_proof.new_value = Hash::get_zero_value(),
            |w| w.validator_fee_delta_proof.new_root = Hash::get_zero_value(),
            |w| w.validator_fee_delta_proof.index = 2,
            |w| { w.validator_tree_proof.siblings.pop(); },
        ];
        for (index, mutate) in mutations.iter().enumerate() {
            let mut input = fixture.input.clone();
            mutate(&mut input);
            assert!(fixture.prove(&input).is_err(), "accepted mutation {index}");
        }
        Ok(())
    }

    #[test]
    fn finalizer_rejects_bad_children_and_fee_overflow() -> anyhow::Result<()> {
        let fixture = Fixture::new(0, 100, 32, 3)?;
        let mut response = fixture.response(&fixture.input)?;
        response.input_proofs[0][0] ^= 1;
        assert!(fixture.manager.prove_job_from_api(&fixture.library, response, fixture.worker_tag).is_err());
        let mut response = fixture.response(&fixture.input)?;
        response.base.child_proof_tag_values.clear();
        assert!(fixture.manager.prove_job_from_api(&fixture.library, response, fixture.worker_tag).is_err());
        let mut response = fixture.response(&fixture.input)?;
        response.input_proofs.push(response.input_proofs[0].clone());
        assert!(fixture.manager.prove_job_from_api(&fixture.library, response, fixture.worker_tag).is_err());
        for (fee, balance) in [(1, (1u64 << 60) - 1), (1u64 << 60, 0), (0, 1u64 << 60)] {
            let fixture = Fixture::new(fee, balance, 32, 3)?;
            assert!(fixture.prove(&fixture.input).is_err());
        }
        Ok(())
    }

    #[test]
    fn finalizer_fingerprint_binds_network_and_rotation() -> anyhow::Result<()> {
        let fixture = Fixture::new(0, 100, 32, 3)?;
        let key = MemorySecp256K1SinglePrivateKeyWallet::new_from_private_key_bytes(&[7u8; 32])?;
        let bytes = fixture.prove(&fixture.input)?;
        let proof = deserialize_jtmb_proof::<Hash>(&bytes)?;
        for (domain, period, ids) in [(Hash::from_values(9, 2, 3, 4), 32, vec![1, 2, 3]),
            (Hash::from_values(1, 2, 3, 4), 16, vec![1, 2, 3]),
            (Hash::from_values(1, 2, 3, 4), 32, vec![1, 2])] {
            let other = RealmFinalizeGUTACircuit::<C>::new(&key, 4, 4, 4, 8, domain,
                RealmRotationConfig { checkpoints_per_epoch: period, validator_sub_ids: ids });
            assert_ne!(other.get_fingerprint(), fixture.manager.realm_finalize_guta.get_fingerprint());
            assert!(other.get_verifier_data().verify_proof::<Hasher, Hash, F>(&proof).is_err());
        }
        Ok(())
    }
}
