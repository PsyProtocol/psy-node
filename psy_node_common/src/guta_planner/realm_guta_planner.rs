use std::{collections::HashMap, sync::Arc};

use parth_common::memory_stores::{dash_tree_append_only::PsyDashMemoryAppendOnlyMerkleStore, mem_tree_recorder::SimpleMemoryMerkleRecorderStore};
use parth_core::{
    crypto::hash::{
        merkle_proof::{compute_root_merkle_proof_generic, DeltaMerkleProofCore, MerkleProofCore},
        traits::{FieldQHasher, QFieldHashable, ZeroableHash},
    },
    data::hash::merkle_node_key::SimpleMerkleNodeKey,
    felt::{FromPrimitiveValuesFelt, QFelt64, ToU64Value, ZeroableFelt},
    node::realm_identifier::QRealmIdentifier,
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use psy_client_common::data::{
    base_types::hash256::Hash256 as ClientHash256,
    qhashout::QHashOut as ClientQHashOut,
};
use psy_core::job::job_id::{ProvingJobCircuitType, ProvingJobDataType, QJobTopic, QProvingJobDataID};
use psy_crypto::common::witnesses::zk_signature::PsyZKSignatureCircuitInput;
use psy_data::{
    guta::{
        header::GlobalUserTreeAggregatorHeader,
        header_extended::GlobalUserTreeAggregatorHeaderWithJobId,
        realm_finalize::{
            realm_finalize_guta_chain_domain, RealmFinalizeGUTAAction, RealmFinalizeGUTAInput, RealmFinalizeGUTAPublicOutput, SIGNATURE_TYPE_ZK,
        },
    },
    proof_input::guta::{
        GUTAVerifyLeftGUTARightEndCapCircuitInputV2, GUTAVerifyTwoEndCapCircuitInputV2, GUTAVerifyTwoGUTALinearCircuitInput,
        VerifyEndCapSimpleStandardInput, VerifySingleEndCapInputV2,
    },
    queue_items::realm_user_update::PsyRealmUserUpdateQueueItem,
    v1::qdata::{
        checkpoint::{PQEDCheckpointLeaf, PQEDCheckpointLeafCompactWithStateRoots},
        user::PQEDUserLeaf,
    },
    worker::{
        metadata::{
            PsyProvingJobMetadata, PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD, PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN,
        },
        metadata_with_job_id::PsyProvingJobMetadataWithJobId,
    },
};
use psy_io::tokio::TokioFileLike;
use psy_node_core::{
    psy_temp_db::StandardProcessorTempDBStoreBase,
    qblob::{
        blob_type::{QBlobDataType, QBlobMerkleNodeTreeType},
        data_views::{
            double_merkle_node_batch::QBlobDoubleMerkleNodeBatchDataView, single_merkle_node_batch::QBlobSingleMerkleNodeBatchDataView,
            zero_merkle_node_batch::create_ffs_merkle_nodes_zero_id_from_hash_map_with_offset,
        },
        structs::common::tree_node_batch_header::QBlobMerkleTreeNodeBatchHeaderV1,
    },
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::realm::processor::gatherers::realm_end_cap_gatherer::{RealmGUTAEndCapGathererOutput, RealmGUTAEndCapGathererOutputDatabase};

const MAX_REALM_PROVING_LEVELS: usize = 32;

#[derive(Clone)]
pub struct PlannedFutureEndCapJob<F, Hash> {
    pub queue_item: PsyRealmUserUpdateQueueItem<F, Hash>,
    pub contract_updates: Vec<u8>,
}

/// Genesis validator identity + ZK signing + checkpoint/proof material needed
/// to wrap a realm's root GUTA with a RealmFinalizeGUTA job (circuit type 63).
///
/// Built by the processor from `validator_registry` (genesis.validators lookup
/// for this `(realm_id, realm_sub_id)`) plus the validator's ZK private key,
/// user leaf, and the anchor/checkpoint Merkle proofs. When absent, the planner
/// keeps today's GUTASingleEndCap / TwoGUTA root path so single-producer HTTP
/// flow still works.
pub struct RealmFinalizeGUTAIdentity<F, Hash> {
    pub validator_user_id: u64,
    pub validator_user_leaf: PQEDUserLeaf<F, Hash>,
    pub validator_zk_private_key: Hash,
    pub validator_public_key_param: Hash,
    pub anchor_checkpoint_leaf: PQEDCheckpointLeaf<F, Hash>,
    pub anchor_checkpoint_tree_proof: MerkleProofCore<Hash>,
    pub checkpoint_leaf: PQEDCheckpointLeafCompactWithStateRoots<Hash>,
    pub checkpoint_tree_proof: MerkleProofCore<Hash>,
    pub old_realm_root_proof: MerkleProofCore<Hash>,
    pub validator_tree_proof: MerkleProofCore<Hash>,
    pub validator_user_tree_proof: MerkleProofCore<Hash>,
}

pub struct RealmGUTAPlanner<F, Hash> {
    pub realm_id_u64: u64,
    pub realm_sub_id_u64: u64,
    pub chain_id: u32,
    pub unique_pending_id: u64,
    pub realm_identifier: QRealmIdentifier,
    pub job_level_map: HashMap<QProvingJobDataID, (usize, usize)>,
    pub future_pending_end_cap_jobs: Vec<PlannedFutureEndCapJob<F, Hash>>,
    pub planned_jobs: [Vec<PsyProvingJobMetadataWithJobId<Hash, QProvingJobDataID>>; MAX_REALM_PROVING_LEVELS],
    pub job_stragglers: [Option<GlobalUserTreeAggregatorHeaderWithJobId<F, Hash>>; MAX_REALM_PROVING_LEVELS],
    pub job_level_counts: [u64; MAX_REALM_PROVING_LEVELS],
    pub end_cap_straggler: Option<PsyRealmUserUpdateQueueItem<F, Hash>>,
    pub user_contract_tree_updates_ffs: Vec<u8>,
    pub contract_state_tree_updates_ffs: Vec<u8>,
    pub user_leaf_updates_ffs: Vec<u8>,
    /// IMT (Indexed Merkle Tree) leaf preimage data for contract state trees.
    /// Accumulated from end cap submissions.
    pub contract_state_imt_leaves_ffs: Vec<u8>,

    pub current_checkpoint_root: Hash,
    pub current_checkpoint_id: u64,
    pub has_committed_reward_ids: bool,
    pub start_realm_root: Hash,
    pub realm_root_key: SimpleMerkleNodeKey,
    pub realm_user_min_id: u64,
    pub realm_user_max_id: u64,
    pub realm_tree_height: u8,
    pub global_user_tree_height: u8,
    pub guta_circuit_whitelist: Hash,
    pub total_jobs: usize,
    pub total_end_caps_processed: usize,

    // --- RealmFinalizeGUTA material (circuit type 63) ---
    // All None by default: the single-producer HTTP path keeps today's
    // GUTASingleEndCap / TwoGUTA root. When the validator identity is Some
    // (see `with_realm_finalize_identity` / `realm_finalize_enabled`),
    // `finalize_with_reward_ids` wraps the root GUTA with a RealmFinalizeGUTA
    // job. `append_realm_finalize_guta` fail-closes if identity is configured
    // but any required ZK key / leaf / tree proof is missing.
    pub realm_finalize_validator_user_id: Option<u64>,
    pub realm_finalize_validator_user_leaf: Option<PQEDUserLeaf<F, Hash>>,
    pub realm_finalize_validator_zk_private_key: Option<Hash>,
    pub realm_finalize_validator_public_key_param: Option<Hash>,
    pub realm_finalize_anchor_checkpoint_leaf: Option<PQEDCheckpointLeaf<F, Hash>>,
    pub realm_finalize_anchor_checkpoint_tree_proof: Option<MerkleProofCore<Hash>>,
    pub realm_finalize_checkpoint_leaf: Option<PQEDCheckpointLeafCompactWithStateRoots<Hash>>,
    pub realm_finalize_checkpoint_tree_proof: Option<MerkleProofCore<Hash>>,
    pub realm_finalize_old_realm_root_proof: Option<MerkleProofCore<Hash>>,
    pub realm_finalize_validator_tree_proof: Option<MerkleProofCore<Hash>>,
    pub realm_finalize_validator_user_tree_proof: Option<MerkleProofCore<Hash>>,
    /// Cached finalizer public output once `append_realm_finalize_guta` runs.
    pub finalizer_public_output: Option<RealmFinalizeGUTAPublicOutput<F, Hash>>,
}

impl<F, Hash> RealmGUTAPlanner<F, Hash> {
    pub fn new(
        chain_id: u32,
        realm_identifier: QRealmIdentifier,
        current_checkpoint_root: Hash,
        current_checkpoint_id: u64,
        unique_pending_id: u64,
        start_realm_root: Hash,
        realm_tree_height: u8,
        global_user_tree_height: u8,
        guta_circuit_whitelist: Hash,
    ) -> Self {
        Self {
            chain_id,
            start_realm_root,
            realm_identifier,
            realm_id_u64: realm_identifier.realm_id as u64,
            realm_sub_id_u64: realm_identifier.realm_sub_id as u64,
            job_level_counts: [0u64; MAX_REALM_PROVING_LEVELS],
            job_level_map: HashMap::new(),
            future_pending_end_cap_jobs: Vec::new(),
            planned_jobs: Default::default(),
            job_stragglers: Default::default(),
            end_cap_straggler: None,
            user_contract_tree_updates_ffs: Vec::new(),
            contract_state_tree_updates_ffs: Vec::new(),
            user_leaf_updates_ffs: Vec::new(),
            contract_state_imt_leaves_ffs: Vec::new(),
            current_checkpoint_root,
            current_checkpoint_id,
            unique_pending_id,
            has_committed_reward_ids: false,
            realm_tree_height: realm_tree_height,
            global_user_tree_height: global_user_tree_height,
            realm_user_min_id: (realm_identifier.realm_id as u64) << realm_tree_height,
            realm_user_max_id: (((realm_identifier.realm_id as u64) + 1) << realm_tree_height) - 1,
            realm_root_key: SimpleMerkleNodeKey {
                index: realm_identifier.realm_id as u64,
                level: global_user_tree_height - realm_tree_height,
            },
            guta_circuit_whitelist,
            total_jobs: 0,
            total_end_caps_processed: 0,
            realm_finalize_validator_user_id: None,
            realm_finalize_validator_user_leaf: None,
            realm_finalize_validator_zk_private_key: None,
            realm_finalize_validator_public_key_param: None,
            realm_finalize_anchor_checkpoint_leaf: None,
            realm_finalize_anchor_checkpoint_tree_proof: None,
            realm_finalize_checkpoint_leaf: None,
            realm_finalize_checkpoint_tree_proof: None,
            realm_finalize_old_realm_root_proof: None,
            realm_finalize_validator_tree_proof: None,
            realm_finalize_validator_user_tree_proof: None,
            finalizer_public_output: None,
        }
    }

    /// Configure this planner with the genesis validator identity + ZK signing
    /// material for its realm. When set, `finalize_with_reward_ids` wraps the
    /// root GUTA with a RealmFinalizeGUTA job (circuit type 63). When unset
    /// (the default), the planner keeps today's GUTASingleEndCap / TwoGUTA root
    /// path so single-producer HTTP flow still works.
    pub fn with_realm_finalize_identity(mut self, identity: RealmFinalizeGUTAIdentity<F, Hash>) -> Self {
        self.realm_finalize_validator_user_id = Some(identity.validator_user_id);
        self.realm_finalize_validator_user_leaf = Some(identity.validator_user_leaf);
        self.realm_finalize_validator_zk_private_key = Some(identity.validator_zk_private_key);
        self.realm_finalize_validator_public_key_param = Some(identity.validator_public_key_param);
        self.realm_finalize_anchor_checkpoint_leaf = Some(identity.anchor_checkpoint_leaf);
        self.realm_finalize_anchor_checkpoint_tree_proof = Some(identity.anchor_checkpoint_tree_proof);
        self.realm_finalize_checkpoint_leaf = Some(identity.checkpoint_leaf);
        self.realm_finalize_checkpoint_tree_proof = Some(identity.checkpoint_tree_proof);
        self.realm_finalize_old_realm_root_proof = Some(identity.old_realm_root_proof);
        self.realm_finalize_validator_tree_proof = Some(identity.validator_tree_proof);
        self.realm_finalize_validator_user_tree_proof = Some(identity.validator_user_tree_proof);
        self
    }
}

impl<F: QFelt64, Hash: Q256BitHash + QFHashBase<F>> RealmGUTAPlanner<F, Hash> {
    pub async fn populate_future_end_cap_job<TempStore: StandardProcessorTempDBStoreBase<QProvingJobDataID, Hash>>(
        _chain_id: u32,
        realm_identifier: &QRealmIdentifier,
        unique_pending_id: u64,
        temp_store: Arc<TempStore>,
        queue_item: PsyRealmUserUpdateQueueItem<F, Hash>,
    ) -> anyhow::Result<Option<PlannedFutureEndCapJob<F, Hash>>> {
        let data: Option<Vec<u8>> = temp_store
            .get_contract_updates_for_user(realm_identifier, unique_pending_id, queue_item.new_user_leaf.user_id.to_u64_value())
            .await?;
        if data.is_none() {
            return Ok(None);
        }
        let data = data.unwrap();

        /* 

        let realm_id_u64 = realm_identifier.realm_id as u64;
        let realm_sub_id_u64 = realm_identifier.realm_sub_id as u64;

        let (single_header, single_payload, double_full) =
            QBlobSingleMerkleNodeBatchDataView::validate_single_tree_nodes_batch_header_for_realm_context_get_clipped_ref_no_exact_size_any_unique_pending_id(
                &data,
                chain_id,
                realm_id_u64,
                realm_sub_id_u64,
                QBlobMerkleNodeTreeType::UserContractTree,
            )?;
        let (_double_header, double_payload) =
            QBlobDoubleMerkleNodeBatchDataView::validate_cst_nodes_batch_header_for_realm_context_get_clipped_ref_any_unique_pending_id(
                &double_full,
                chain_id,
                realm_id_u64,
                realm_sub_id_u64,
            )?;
        if single_header.checkpoint_id != queue_item.expected_fake_checkpoint_id {
            tracing::info!("Skipping end-cap job population due to fake checkpoint ID mismatch: expected {}, found {}. Likely got overwritten due to a race condition. Gracefully skipping.",
                queue_item.expected_fake_checkpoint_id,
                single_header.checkpoint_id
            );
            return Ok(None);
        }*/

        Ok(Some(PlannedFutureEndCapJob {
            queue_item,
            contract_updates: data,
            //user_contract_tree_updates_ffs: single_payload.to_vec(),
            //contract_state_tree_updates_ffs: double_payload.to_vec(),
        }))
    }

    pub async fn insert_job_at_level<Hasher: FieldQHasher<F, Hash>, TempStore: StandardProcessorTempDBStoreBase<QProvingJobDataID, Hash>>(
        &mut self,
        guta_header: GlobalUserTreeAggregatorHeaderWithJobId<F, Hash>,
        temp_store: &TempStore,
        level: usize,
        metadata: PsyProvingJobMetadataWithJobId<Hash, QProvingJobDataID>,
    ) -> anyhow::Result<()> {
        if level >= MAX_REALM_PROVING_LEVELS {
            anyhow::bail!("Exceeded maximum realm proving levels.");
        }
        self.planned_jobs[level].push(metadata);
        self.total_jobs += 1;
        self.job_level_map
            .insert(guta_header.job_id.clone(), (level, self.job_level_counts[level] as usize));
        let mut current_header = guta_header;

        for current_level in level..MAX_REALM_PROVING_LEVELS {
            self.job_level_counts[current_level] += 1;
            if self.job_stragglers[current_level].is_some() {
                if current_level == MAX_REALM_PROVING_LEVELS - 1 {
                    anyhow::bail!("Exceeded maximum realm proving levels during aggregation.");
                }
                let straggler = self.job_stragglers[current_level].take().unwrap();
                let left_job_id = straggler.job_id;
                let right_job_id = current_header.job_id;
                let witness = GUTAVerifyTwoGUTALinearCircuitInput {
                    left_header: straggler.header,
                    right_header: current_header.header,
                };
                let (job, new_header) = witness.get_job_witness_and_new_guta::<Hasher>(
                    self.unique_pending_id,
                    (current_level + 1) as u8,
                    self.job_level_counts[current_level + 1],
                    left_job_id,
                    right_job_id,
                );
                temp_store
                    .set_tdb_proof_witnesses_tuple_owned_raw(
                        &self.realm_identifier,
                        self.unique_pending_id,
                        vec![(job.job_id, witness.psy_ser_into_bytes_vec()?)],
                    )
                    .await?;
                self.job_level_map
                    .insert(job.job_id.clone(), (current_level + 1, self.job_level_counts[current_level + 1] as usize));
                self.planned_jobs[current_level + 1].push(job);
                self.total_jobs += 1;
                current_header = new_header;
            } else {
                self.job_stragglers[current_level] = Some(current_header);
                break;
            }
        }

        Ok(())
    }
    pub async fn add_end_cap_job<
        Hasher: FieldQHasher<F, Hash>,
        TempStore: StandardProcessorTempDBStoreBase<QProvingJobDataID, Hash>,
        File: TokioFileLike,
    >(
        &mut self,
        checkpoint_tree: &PsyDashMemoryAppendOnlyMerkleStore<Hasher, Hash>,
        global_user_tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
        file: &mut File,
        temp_store: Arc<TempStore>,
        queue_item_bytes: &[u8],
        queue_item: PsyRealmUserUpdateQueueItem<F, Hash>,
    ) -> anyhow::Result<usize> {
        self.add_end_cap_job_internal::<Hasher, TempStore, File>(checkpoint_tree, global_user_tree, file, temp_store, queue_item_bytes, queue_item)
            .await
    }
    async fn add_end_cap_job_internal<
        Hasher: FieldQHasher<F, Hash>,
        TempStore: StandardProcessorTempDBStoreBase<QProvingJobDataID, Hash>,
        File: TokioFileLike,
    >(
        &mut self,
        checkpoint_tree: &PsyDashMemoryAppendOnlyMerkleStore<Hasher, Hash>,
        global_user_tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
        file: &mut File,
        temp_store: Arc<TempStore>,
        queue_item_bytes: &[u8],
        queue_item: PsyRealmUserUpdateQueueItem<F, Hash>,
    ) -> anyhow::Result<usize> {
        let user_last_checkpoint_id = queue_item.new_user_leaf.last_checkpoint_id.to_u64_value();
        let user_id = queue_item.new_user_leaf.user_id.to_u64_value();
        if user_id < self.realm_user_min_id || user_id > self.realm_user_max_id {
            //anyhow::bail!("User ID {} is out of bounds for realm ID {}.", user_id,
            // self.realm_identifier.realm_id);
            tracing::info!(
                "Skipping end-cap job population due to out-of-bounds user ID {} for realm ID {}.",
                user_id,
                self.realm_identifier.realm_id
            );
            return Ok(0);
        }
        let last_user_leaf_value = global_user_tree.get_leaf_value(user_id - self.realm_user_min_id);
        if last_user_leaf_value != queue_item.old_user_leaf_hash {
            if last_user_leaf_value == Hash::get_zero_value() {
                tracing::warn!(
                    "Initializing missing global user tree leaf for user ID {} from queue item old hash {:?}.",
                    user_id,
                    queue_item.old_user_leaf_hash
                );
                global_user_tree.set_leaf(user_id - self.realm_user_min_id, queue_item.old_user_leaf_hash);
            } else {
            tracing::info!(
                "Skipping end-cap job population due to user leaf hash mismatch for user ID {}. Expected last_user_leaf_value={:?}, found {:?}. Likely got overwritten due to a race condition. Gracefully skipping.",
                user_id,
                last_user_leaf_value,
                queue_item.old_user_leaf_hash
            );
            return Ok(0);
            }
        }
        if user_last_checkpoint_id > self.current_checkpoint_id {
            tracing::info!(
                "Skipping end-cap job population due to user last checkpoint ID {} being greater than current checkpoint ID {} for user ID {}.",
                user_last_checkpoint_id,
                self.current_checkpoint_id,
                user_id
            );
            let result = RealmGUTAPlanner::populate_future_end_cap_job(
                self.chain_id,
                &self.realm_identifier,
                self.unique_pending_id,
                temp_store.clone(),
                queue_item,
            )
            .await?;
            if result.is_none() {
                tracing::info!("Skipping end-cap job population due to missing contract updates for user ID {}.", user_id);
            } else {
                self.future_pending_end_cap_jobs.push(result.unwrap());
            }
            return Ok(0);
        }
        let data: Option<Vec<u8>> = temp_store
            .get_contract_updates_for_user(&self.realm_identifier, self.unique_pending_id, user_id)
            .await?;
        if data.is_none() {
            tracing::info!("Skipping end-cap job population due to missing contract updates for user ID {}.", user_id);
            return Ok(0);
        }
        tracing::info!("Populating end-cap job for user ID {} at checkpoint ID {}.", user_id, user_last_checkpoint_id);
        let data = data.unwrap();
        file.write_all(&queue_item_bytes).await?;
        file.write_all(&data).await?;
        self.total_end_caps_processed += 1;

        tracing::debug!("End-cap job populated data len {}.", data.len());

        let (single_header, single_payload, double_full) =
            QBlobSingleMerkleNodeBatchDataView::validate_single_tree_nodes_batch_header_for_realm_context_get_clipped_ref_no_exact_size_any_unique_pending_id(
                &data,
                self.chain_id,
                self.realm_id_u64,
                self.realm_sub_id_u64,
                QBlobMerkleNodeTreeType::UserContractTree,
            )?;

        tracing::debug!("Single header: {}", serde_json::to_string_pretty(&single_header)?);
        let (double_header, double_payload, imt_full) =
            QBlobDoubleMerkleNodeBatchDataView::validate_cst_nodes_batch_header_for_realm_context_get_clipped_ref_any_unique_pending_id_with_remaining(
                &double_full,
                self.chain_id,
                self.realm_id_u64,
                self.realm_sub_id_u64,
            )?;
        tracing::debug!("Double header: {}", serde_json::to_string_pretty(&double_header)?);
        
        if !imt_full.is_empty() {
            let (imt_header, imt_payload) = QBlobMerkleTreeNodeBatchHeaderV1::clip_header_get_payload_for_blob_type_and_tree_ref(
                imt_full,
                QBlobDataType::GenericIMTLeafBatch,
                QBlobMerkleNodeTreeType::IMTContractStateLeaf,
                true,
            )?;
            tracing::debug!("IMT header: {}", serde_json::to_string_pretty(&imt_header)?);
            // Store IMT leaf preimage data for FFS database
            self.contract_state_imt_leaves_ffs.extend_from_slice(imt_payload);
        }

        if single_header.checkpoint_id != queue_item.expected_fake_checkpoint_id {
            tracing::info!("Skipping end-cap job population due to fake checkpoint ID mismatch: expected {}, found {}. Likely got overwritten due to a race condition. Gracefully skipping.",
                queue_item.expected_fake_checkpoint_id,
                single_header.checkpoint_id
            );
            return Ok(0);
        }

        self.user_contract_tree_updates_ffs.extend_from_slice(&single_payload);
        self.contract_state_tree_updates_ffs.extend_from_slice(&double_payload);
        self.user_leaf_updates_ffs
            .extend_from_slice(&queue_item.new_user_leaf.psy_ser_to_bytes_vec()?);

        if self.end_cap_straggler.is_some() {
            let left = self.end_cap_straggler.take().unwrap();
            let right = queue_item;
            let left_effective_user_id = left.new_user_leaf.user_id.to_u64_value() - self.realm_user_min_id;
            let right_effective_user_id = right.new_user_leaf.user_id.to_u64_value() - self.realm_user_min_id;
            let left_checkpoint_id = left.new_user_leaf.last_checkpoint_id.to_u64_value();
            let right_checkpoint_id = right.new_user_leaf.last_checkpoint_id.to_u64_value();
            let left_checkpoint_merkle_proof =
                checkpoint_tree.get_historical_merkle_proof_at_historical_index(left_checkpoint_id, self.current_checkpoint_id);
            let right_checkpoint_merkle_proof =
                checkpoint_tree.get_historical_merkle_proof_at_historical_index(right_checkpoint_id, self.current_checkpoint_id);

                
            tracing::debug!("[{:?}] left_checkpoint_merkle_proof ({left_checkpoint_id} @ {}) (append_root: {:?}): {:?}", left.job_id, self.current_checkpoint_id, left_checkpoint_merkle_proof.get_append_root::<Hasher>(), left_checkpoint_merkle_proof);
            tracing::debug!("[{:?}] right_checkpoint_merkle_proof ({right_checkpoint_id} @ {}) (append_root: {:?}): {:?}", right.job_id, self.current_checkpoint_id, right_checkpoint_merkle_proof.get_append_root::<Hasher>(), right_checkpoint_merkle_proof);
            if !left_checkpoint_merkle_proof.verify::<Hasher>() {
                tracing::error!(
                    "Left checkpoint merkle proof verification failed for user ID {} at checkpoint ID {}.",
                    left.new_user_leaf.user_id.to_u64_value(),
                    left_checkpoint_id
                );
            }
            if !right_checkpoint_merkle_proof.verify::<Hasher>() {
                tracing::error!(
                    "Right checkpoint merkle proof verification failed for user ID {} at checkpoint ID {}.",
                    right.new_user_leaf.user_id.to_u64_value(),
                    right_checkpoint_id
                );
            }

            

            let mut left_global_user_tree_delta_merkle_proof = global_user_tree.set_leaf(left_effective_user_id, left.new_user_leaf_hash);
            let mut right_global_user_tree_delta_merkle_proof = global_user_tree.set_leaf(right_effective_user_id, right.new_user_leaf_hash);
            left_global_user_tree_delta_merkle_proof.index += self.realm_user_min_id;
            right_global_user_tree_delta_merkle_proof.index += self.realm_user_min_id;

            let parent_witness = GUTAVerifyTwoEndCapCircuitInputV2 {
                left_end_cap: VerifyEndCapSimpleStandardInput {
                    guta_stats: left.stats,
                    checkpoint_root: left_checkpoint_merkle_proof.get_append_root::<Hasher>(),
                    checkpoint_historical_merkle_proof: left_checkpoint_merkle_proof,
                },
                left_global_user_tree_delta_merkle_proof,
                right_end_cap: VerifyEndCapSimpleStandardInput {
                    guta_stats: right.stats,
                    checkpoint_root: right_checkpoint_merkle_proof.get_append_root::<Hasher>(),
                    checkpoint_historical_merkle_proof: right_checkpoint_merkle_proof,
                },
                right_global_user_tree_delta_merkle_proof,
            };

            let parent_witness_job_id = QProvingJobDataID::guta_two_end_cap_witness(self.unique_pending_id, 0, self.job_level_counts[0]);

            let expected_public_inputs_hash =
                parent_witness.get_public_inputs_hash_no_rewards_tag::<Hasher>(self.global_user_tree_height as usize, self.guta_circuit_whitelist);
            
            let parent_job = PsyProvingJobMetadataWithJobId {
                job_id: parent_witness_job_id,
                metadata: PsyProvingJobMetadata {
                    expected_public_inputs_hash,
                    reward_tree_node_index: 0,
                    reward_tree_node_level: 0,
                    reward_tree_hash_mode: PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN,
                    reward_tree_node_children: 0,
                    dependencies: vec![left.job_id, right.job_id],
                },
            };
            let parent_guta = GlobalUserTreeAggregatorHeaderWithJobId {
                header: parent_witness.get_new_guta_header(self.global_user_tree_height as usize, self.guta_circuit_whitelist),
                job_id: parent_witness_job_id,
            };
            temp_store
                .set_tdb_proof_witnesses_tuple_owned_raw(
                    &self.realm_identifier,
                    self.unique_pending_id,
                    vec![(parent_witness_job_id, parent_witness.psy_ser_into_bytes_vec()?)],
                )
                .await?;
            self.insert_job_at_level::<Hasher, TempStore>(parent_guta, &temp_store, 0, parent_job)
                .await?;
        }else{
            self.end_cap_straggler = Some(queue_item);
        }

        Ok(1)
    }


    pub async fn add_future_end_cap_jobs<
        Hasher: FieldQHasher<F, Hash>,
        TempStore: StandardProcessorTempDBStoreBase<QProvingJobDataID, Hash>,
        File: TokioFileLike,
    >(
        &mut self,
        checkpoint_tree: &PsyDashMemoryAppendOnlyMerkleStore<Hasher, Hash>,
        global_user_tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
        file: &mut File,
        temp_store: Arc<TempStore>,
        future_end_cap_jobs: Vec<PlannedFutureEndCapJob<F, Hash>>,
    ) -> anyhow::Result<usize> {
        let mut count = 0;
        for future_end_cap_job in future_end_cap_jobs {
            count += self.add_future_end_cap_job::<Hasher, TempStore, File>(
                checkpoint_tree,
                global_user_tree,
                file,
                temp_store.clone(),
                future_end_cap_job,
            )
            .await?;
        }
        Ok(count)
    }
    async fn add_future_end_cap_job<
        Hasher: FieldQHasher<F, Hash>,
        TempStore: StandardProcessorTempDBStoreBase<QProvingJobDataID, Hash>,
        File: TokioFileLike,
    >(
        &mut self,
        checkpoint_tree: &PsyDashMemoryAppendOnlyMerkleStore<Hasher, Hash>,
        global_user_tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
        file: &mut File,
        temp_store: Arc<TempStore>,
        future_end_cap_job: PlannedFutureEndCapJob<F, Hash>,
    ) -> anyhow::Result<usize> {
        let queue_item = future_end_cap_job.queue_item.clone();
        let user_last_checkpoint_id = queue_item.new_user_leaf.last_checkpoint_id.to_u64_value();
        let user_id = queue_item.new_user_leaf.user_id.to_u64_value();
        if user_id < self.realm_user_min_id || user_id > self.realm_user_max_id {
            //anyhow::bail!("User ID {} is out of bounds for realm ID {}.", user_id,
            // self.realm_identifier.realm_id);
            tracing::info!(
                "Skipping end-cap job population due to out-of-bounds user ID {} for realm ID {}.",
                user_id,
                self.realm_identifier.realm_id
            );
            return Ok(0);
        }
        if user_last_checkpoint_id > self.current_checkpoint_id {
            tracing::info!(
                "Deferring end-cap job population due to future checkpoint ID {} for user ID {}.",
                user_last_checkpoint_id,
                user_id
            );
            self.future_pending_end_cap_jobs.push(future_end_cap_job);
            return Ok(0);
        }

        tracing::info!(
            "Populating deferred end-cap job for user ID {} at checkpoint ID {}.",
            user_id,
            user_last_checkpoint_id
        );
        
        file.write_all(&queue_item.psy_ser_to_bytes_vec()?).await?;
        file.write_all(&future_end_cap_job.contract_updates).await?;
        self.total_end_caps_processed += 1;

        let (single_header, single_payload, double_full) =
            QBlobSingleMerkleNodeBatchDataView::validate_single_tree_nodes_batch_header_for_realm_context_get_clipped_ref_no_exact_size_any_unique_pending_id(
                &future_end_cap_job.contract_updates,
                self.chain_id,
                self.realm_id_u64,
                self.realm_sub_id_u64,
                QBlobMerkleNodeTreeType::UserContractTree,
            )?;
        tracing::debug!("Single header: {}", serde_json::to_string_pretty(&single_header)?);
        // For IMT: validate CST nodes and extract IMT leaf data (3 parts: single, double, imt)
        let (double_header, double_payload, imt_full) =
            QBlobDoubleMerkleNodeBatchDataView::validate_cst_nodes_batch_header_for_realm_context_get_clipped_ref_any_unique_pending_id_with_remaining(
                &double_full,
                self.chain_id,
                self.realm_id_u64,
                self.realm_sub_id_u64,
            )?;
        tracing::debug!("Double header: {}", serde_json::to_string_pretty(&double_header)?);
        if !imt_full.is_empty() {
            let (imt_header, imt_payload) = QBlobMerkleTreeNodeBatchHeaderV1::clip_header_get_payload_for_blob_type_and_tree_ref(
                imt_full,
                QBlobDataType::GenericIMTLeafBatch,
                QBlobMerkleNodeTreeType::IMTContractStateLeaf,
                true,
            )?;
            // Store IMT leaf preimage data for FFS database
            tracing::debug!("IMT header: {}", serde_json::to_string_pretty(&imt_header)?);
            self.contract_state_imt_leaves_ffs.extend_from_slice(imt_payload);
        }
        if single_header.checkpoint_id != queue_item.expected_fake_checkpoint_id {
            tracing::info!("Skipping end-cap job population due to fake checkpoint ID mismatch: expected {}, found {}. Likely got overwritten due to a race condition. Gracefully skipping.",
                queue_item.expected_fake_checkpoint_id,
                single_header.checkpoint_id
            );
            return Ok(0);
        }

        self.user_contract_tree_updates_ffs.extend_from_slice(&single_payload);
        self.contract_state_tree_updates_ffs.extend_from_slice(&double_payload);
        self.user_leaf_updates_ffs
            .extend_from_slice(&queue_item.new_user_leaf.psy_ser_to_bytes_vec()?);

        if self.end_cap_straggler.is_some() {
            let left = self.end_cap_straggler.take().unwrap();
            let right = queue_item;
            let left_effective_user_id = left.new_user_leaf.user_id.to_u64_value() - self.realm_user_min_id;
            let right_effective_user_id = right.new_user_leaf.user_id.to_u64_value() - self.realm_user_min_id;
            let left_checkpoint_id = left.new_user_leaf.last_checkpoint_id.to_u64_value();
            let right_checkpoint_id = right.new_user_leaf.last_checkpoint_id.to_u64_value();
            let left_checkpoint_merkle_proof =
                checkpoint_tree.get_historical_merkle_proof_at_historical_index(left_checkpoint_id, self.current_checkpoint_id);
            let right_checkpoint_merkle_proof =
                checkpoint_tree.get_historical_merkle_proof_at_historical_index(right_checkpoint_id, self.current_checkpoint_id);

            let mut left_global_user_tree_delta_merkle_proof = global_user_tree.set_leaf(left_effective_user_id, left.new_user_leaf_hash);
            let mut right_global_user_tree_delta_merkle_proof = global_user_tree.set_leaf(right_effective_user_id, right.new_user_leaf_hash);
            left_global_user_tree_delta_merkle_proof.index += self.realm_user_min_id;
            right_global_user_tree_delta_merkle_proof.index += self.realm_user_min_id;

            let parent_witness = GUTAVerifyTwoEndCapCircuitInputV2 {
                left_end_cap: VerifyEndCapSimpleStandardInput {
                    guta_stats: left.stats,
                    checkpoint_root: left_checkpoint_merkle_proof.get_append_root::<Hasher>(),
                    checkpoint_historical_merkle_proof: left_checkpoint_merkle_proof,
                },
                left_global_user_tree_delta_merkle_proof,
                right_end_cap: VerifyEndCapSimpleStandardInput {
                    guta_stats: right.stats,
                    checkpoint_root: right_checkpoint_merkle_proof.get_append_root::<Hasher>(),
                    checkpoint_historical_merkle_proof: right_checkpoint_merkle_proof,
                },
                right_global_user_tree_delta_merkle_proof,
            };

            let parent_witness_job_id = QProvingJobDataID::guta_two_end_cap_witness(self.unique_pending_id, 0, self.job_level_counts[0]);

            let expected_public_inputs_hash =
                parent_witness.get_public_inputs_hash_no_rewards_tag::<Hasher>(self.global_user_tree_height as usize, self.guta_circuit_whitelist);
            let parent_job = PsyProvingJobMetadataWithJobId {
                job_id: parent_witness_job_id,
                metadata: PsyProvingJobMetadata {
                    expected_public_inputs_hash,
                    reward_tree_node_index: 0,
                    reward_tree_node_level: 0,
                    reward_tree_hash_mode: PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN,
                    reward_tree_node_children: 0,
                    dependencies: vec![left.job_id, right.job_id],
                },
            };
            let parent_guta = GlobalUserTreeAggregatorHeaderWithJobId {
                header: parent_witness.get_new_guta_header(self.global_user_tree_height as usize, self.guta_circuit_whitelist),
                job_id: parent_witness_job_id,
            };
            temp_store
                .set_tdb_proof_witnesses_tuple_owned_raw(
                    &self.realm_identifier,
                    self.unique_pending_id,
                    vec![(parent_witness_job_id, parent_witness.psy_ser_into_bytes_vec()?)],
                )
                .await?;
            self.insert_job_at_level::<Hasher, TempStore>(parent_guta, &temp_store, 0, parent_job)
                .await?;
        }else{
            self.end_cap_straggler = Some(queue_item);
        }

        Ok(1)
    }
    fn update_reward_tree_config(&mut self, job_id: &QProvingJobDataID, level: u8, index: u64) -> anyhow::Result<()> {
        if job_id.circuit_type == ProvingJobCircuitType::UserEndCap {
            return Ok(());
        }
        let position = self
            .job_level_map
            .get(job_id)
            .ok_or_else(|| anyhow::anyhow!("Job ID {:?} not found in job level map.", job_id))?;
        let child_jobs = self.planned_jobs[position.0][position.1].update_level_and_index(level, index).to_vec();
        if child_jobs.len() > 0 && child_jobs[0].circuit_type != ProvingJobCircuitType::UserEndCap {
            self.update_reward_tree_config(&child_jobs[0], level + 1, index * 2)?;
        }
        if child_jobs.len() > 1  && child_jobs[1].circuit_type != ProvingJobCircuitType::UserEndCap {
            self.update_reward_tree_config(&child_jobs[1], level + 1, index * 2 + 1)?;
        }
        Ok(())
    }

    async fn finalize_promote_end_cap_stragglers<
        Hasher: FieldQHasher<F, Hash>,
        TempStore: StandardProcessorTempDBStoreBase<QProvingJobDataID, Hash>,
    >(
        &mut self,
        checkpoint_tree: &PsyDashMemoryAppendOnlyMerkleStore<Hasher, Hash>,
        global_user_tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
        temp_store: Arc<TempStore>,
    ) -> anyhow::Result<Option<PsyRealmUserUpdateQueueItem<F, Hash>>> {
        if self.end_cap_straggler.is_none() {
            return Ok(None);
        }
        let end_cap_straggler = self.end_cap_straggler.take().unwrap();

        for i in 0..MAX_REALM_PROVING_LEVELS {
            if self.job_stragglers[i].is_some() {
                let straggler = self.job_stragglers[i].take().unwrap();

                let left_job_id = straggler.job_id;
                let right_job_id = end_cap_straggler.job_id;
                let right_effective_user_id = end_cap_straggler.new_user_leaf.user_id.to_u64_value() - self.realm_user_min_id;
                let right_checkpoint_id = end_cap_straggler.new_user_leaf.last_checkpoint_id.to_u64_value();
                let right_checkpoint_merkle_proof =
                    checkpoint_tree.get_historical_merkle_proof_at_historical_index(right_checkpoint_id, self.current_checkpoint_id);
                let mut right_global_user_tree_delta_merkle_proof =
                    global_user_tree.set_leaf(right_effective_user_id, end_cap_straggler.new_user_leaf_hash);
                right_global_user_tree_delta_merkle_proof.index += self.realm_user_min_id;

                let witness = GUTAVerifyLeftGUTARightEndCapCircuitInputV2 {
                    left_header: straggler.header,
                    right_end_cap: VerifyEndCapSimpleStandardInput {
                        guta_stats: end_cap_straggler.stats,
                        checkpoint_root: right_checkpoint_merkle_proof.get_append_root::<Hasher>(),
                        checkpoint_historical_merkle_proof: right_checkpoint_merkle_proof,
                    },
                    right_global_user_tree_delta_merkle_proof,
                };
                let (job, new_header) = witness.get_job_witness_and_new_guta::<Hasher>(
                    self.unique_pending_id,
                    (i + 1) as u8,
                    self.job_level_counts[i + 1],
                    left_job_id,
                    right_job_id,
                );
                temp_store
                    .set_tdb_proof_witnesses_tuple_owned_raw(
                        &self.realm_identifier,
                        self.unique_pending_id,
                        vec![(job.job_id, witness.psy_ser_into_bytes_vec()?)],
                    )
                    .await?;
                self.insert_job_at_level::<Hasher, TempStore>(new_header, &temp_store, i + 1, job).await?;
                return Ok(None);
            }
        }

        Ok(Some(end_cap_straggler))
    }
    fn find_next_straggler_level(&self, start_level: usize) -> Option<usize> {
        if start_level >= MAX_REALM_PROVING_LEVELS {
            return None;
        }
        for i in start_level..MAX_REALM_PROVING_LEVELS {
            if self.job_stragglers[i].is_some() {
                return Some(i);
            }
        }
        None
    }
    async fn finalize_promote_guta_stragglers<Hasher: FieldQHasher<F, Hash>, TempStore: StandardProcessorTempDBStoreBase<QProvingJobDataID, Hash>>(
        &mut self,
        temp_store: Arc<TempStore>,
    ) -> anyhow::Result<Option<usize>> {
        loop {
            let first_straggler_level = match self.find_next_straggler_level(0) {
                Some(level) => level,
                None => return Ok(None),
            };
            let next_straggler_level = match self.find_next_straggler_level(first_straggler_level + 1) {
                Some(level) => level,
                None => return Ok(Some(first_straggler_level)),
            };

            // ---- START OF FIX ----

            // The straggler from the HIGHER level (next_straggler_level) represents an
            // earlier, larger, already-aggregated sub-tree. It must be the LEFT child.
            let left_straggler = self.job_stragglers[next_straggler_level].take().unwrap();

            // The straggler from the LOWER level (first_straggler_level) represents a
            // later, smaller sub-tree. It must be the RIGHT child.
            let right_straggler = self.job_stragglers[first_straggler_level].take().unwrap();
            
            // ---- END OF FIX ----

            // The original incorrect code was:
            // let left_straggler = self.job_stragglers[first_straggler_level].take().unwrap();
            // let right_straggler = self.job_stragglers[next_straggler_level].take().unwrap();

            let left_job_id = left_straggler.job_id;
            let right_job_id = right_straggler.job_id;
            let witness = GUTAVerifyTwoGUTALinearCircuitInput {
                left_header: left_straggler.header,
                right_header: right_straggler.header,
            };
            let (job, new_header) = witness.get_job_witness_and_new_guta::<Hasher>(
                self.unique_pending_id,
                (next_straggler_level + 1) as u8,
                self.job_level_counts[next_straggler_level + 1],
                left_job_id,
                right_job_id,
            );
            temp_store
                .set_tdb_proof_witnesses_tuple_owned_raw(
                    &self.realm_identifier,
                    self.unique_pending_id,
                    vec![(job.job_id, witness.psy_ser_into_bytes_vec()?)],
                )
                .await?;
            self.insert_job_at_level::<Hasher, TempStore>(new_header, &temp_store, next_straggler_level + 1, job)
                .await?;
        }
    }
    /// Returns true when this planner has been configured with a genesis validator
    /// identity for its realm, in which case `finalize_with_reward_ids` wraps
    /// the root GUTA with a RealmFinalizeGUTA job (circuit type 63).
    pub fn realm_finalize_enabled(&self) -> bool {
        self.realm_finalize_validator_user_id.is_some()
    }

    /// Wrap the realm's root GUTA header with a RealmFinalizeGUTA job.
    ///
    /// Mirrors the x5 `feat/realm-rotation` port: derives the validator fee
    /// delta (balance += root GUTA `da_fees_collected`), builds the
    /// `RealmFinalizeGUTAAction` + signed `WrappedSignatureProof` child, and
    /// publishes a `RealmFinalizeGUTA` finalizer job (circuit type 63) on a
    /// fresh level above the existing planned jobs. The signature and finalizer
    /// jobs depend on the root GUTA job (and each other) so level-by-level
    /// worker dispatch respects the dependency order.
    ///
    /// Fail-closed: identity is considered configured when
    /// `realm_finalize_validator_user_id` is `Some`; if any other required ZK
    /// key / leaf / tree proof material is `None` this returns an error rather
    /// than silently producing an invalid witness.
    pub(crate) async fn append_realm_finalize_guta<
        Hasher: FieldQHasher<F, Hash>,
        TempStore: StandardProcessorTempDBStoreBase<QProvingJobDataID, Hash>,
    >(
        &mut self,
        global_user_tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
        temp_store: Arc<TempStore>,
        root_header: GlobalUserTreeAggregatorHeaderWithJobId<F, Hash>,
    ) -> anyhow::Result<(GlobalUserTreeAggregatorHeaderWithJobId<F, Hash>, bool)> {
        let validator_user_id_u64 = self
            .realm_finalize_validator_user_id
            .ok_or_else(|| anyhow::anyhow!("realm_finalize_validator_user_id is required to append RealmFinalizeGUTA"))?;
        let private_key = self
            .realm_finalize_validator_zk_private_key
            .ok_or_else(|| anyhow::anyhow!("validator_zk_private_key is required to append RealmFinalizeGUTA"))?;
        let public_key_param = self
            .realm_finalize_validator_public_key_param
            .ok_or_else(|| anyhow::anyhow!("validator_public_key_param is required to append RealmFinalizeGUTA"))?;
        let validator_user_leaf = self
            .realm_finalize_validator_user_leaf
            .clone()
            .ok_or_else(|| anyhow::anyhow!("validator_user_leaf is required to append RealmFinalizeGUTA"))?;
        let anchor_checkpoint_leaf = self
            .realm_finalize_anchor_checkpoint_leaf
            .clone()
            .ok_or_else(|| anyhow::anyhow!("anchor_checkpoint_leaf is required to append RealmFinalizeGUTA"))?;
        let anchor_checkpoint_tree_proof = self
            .realm_finalize_anchor_checkpoint_tree_proof
            .clone()
            .ok_or_else(|| anyhow::anyhow!("anchor_checkpoint_tree_proof is required to append RealmFinalizeGUTA"))?;
        let checkpoint_leaf = self
            .realm_finalize_checkpoint_leaf
            .clone()
            .ok_or_else(|| anyhow::anyhow!("checkpoint_leaf is required to append RealmFinalizeGUTA"))?;
        let checkpoint_tree_proof = self
            .realm_finalize_checkpoint_tree_proof
            .clone()
            .ok_or_else(|| anyhow::anyhow!("checkpoint_tree_proof is required to append RealmFinalizeGUTA"))?;
        let old_realm_root_proof = self
            .realm_finalize_old_realm_root_proof
            .clone()
            .ok_or_else(|| anyhow::anyhow!("old_realm_root_proof is required to append RealmFinalizeGUTA"))?;
        let validator_tree_proof = self
            .realm_finalize_validator_tree_proof
            .clone()
            .ok_or_else(|| anyhow::anyhow!("validator_tree_proof is required to append RealmFinalizeGUTA"))?;
        let validator_user_tree_proof = self
            .realm_finalize_validator_user_tree_proof
            .clone()
            .ok_or_else(|| anyhow::anyhow!("validator_user_tree_proof is required to append RealmFinalizeGUTA"))?;

        if validator_user_leaf.user_id.to_u64_value() != validator_user_id_u64 {
            anyhow::bail!(
                "validator_user_leaf.user_id {} does not match validator_user_id {}",
                validator_user_leaf.user_id.to_u64_value(),
                validator_user_id_u64
            );
        }
        if validator_user_id_u64 < self.realm_user_min_id || validator_user_id_u64 > self.realm_user_max_id {
            anyhow::bail!(
                "validator_user_id {} is outside Realm {} range [{}..={}]",
                validator_user_id_u64,
                self.realm_identifier.realm_id,
                self.realm_user_min_id,
                self.realm_user_max_id
            );
        }

        let effective_validator_index = validator_user_id_u64 - self.realm_user_min_id;
        let old_leaf_proof = global_user_tree.get_leaf(effective_validator_index);
        let old_leaf_hash = validator_user_leaf.qfhash::<Hasher>();
        let current_tree_leaf = old_leaf_proof.value;
        let is_new_user_zero_leaf = current_tree_leaf == Hash::get_zero_value()
            && validator_user_leaf.balance == F::ZERO_VALUE
            && validator_user_leaf.nonce == F::ZERO_VALUE
            && validator_user_leaf.last_checkpoint_id == F::ZERO_VALUE
            && validator_user_leaf.event_index == F::ZERO_VALUE;
        if old_leaf_hash != current_tree_leaf && !is_new_user_zero_leaf {
            anyhow::bail!(
                "Cannot finalize fees for validator user {}: leaf hash {:?} does not match tree leaf {:?}.",
                validator_user_id_u64,
                old_leaf_hash,
                current_tree_leaf
            );
        }

        let da_fees_collected = root_header.header.stats.da_fees_collected;
        let old_balance = validator_user_leaf.balance.to_u64_value();
        let fee = da_fees_collected.to_u64_value();
        let new_balance = old_balance
            .checked_add(fee)
            .filter(|balance| *balance < (1u64 << 60))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "DA fee claim balance overflow for validator user {}: balance {} + fee {} (60-bit limit)",
                    validator_user_id_u64,
                    old_balance,
                    fee
                )
            })?;

        let new_last_checkpoint_id = if fee == 0 {
            validator_user_leaf.last_checkpoint_id
        } else {
            F::from_u64_value(self.current_checkpoint_id)
        };
        let new_user_leaf = PQEDUserLeaf {
            public_key: validator_user_leaf.public_key,
            user_state_tree_root: validator_user_leaf.user_state_tree_root,
            balance: F::from_u64_value(new_balance),
            nonce: validator_user_leaf.nonce,
            last_checkpoint_id: new_last_checkpoint_id,
            event_index: validator_user_leaf.event_index,
            user_id: validator_user_leaf.user_id,
        };

        let new_leaf_hash = new_user_leaf.qfhash::<Hasher>();
        let old_root = global_user_tree.get_root();
        let new_root = compute_root_merkle_proof_generic::<Hash, Hasher>(
            new_leaf_hash,
            effective_validator_index,
            &old_leaf_proof.siblings,
        );
        // Circuit expects the fee-delta index to be the local realm-tree index.
        let fee_delta_proof = DeltaMerkleProofCore {
            old_value: old_leaf_hash,
            new_value: new_leaf_hash,
            old_root,
            new_root,
            index: effective_validator_index,
            siblings: old_leaf_proof.siblings,
        };

        // Root header's new_node_value must match the fee-delta old_root (circuit binding).
        if root_header.header.state_transition.new_node_value != fee_delta_proof.old_root {
            anyhow::bail!("root GUTA new_node_value does not match validator fee-delta old_root");
        }

        let chain_domain = realm_finalize_guta_chain_domain::<F, Hash, Hasher>(self.chain_id);
        let root_guta_header_hash = root_header.header.qfhash::<Hasher>();
        let action = RealmFinalizeGUTAAction {
            chain_domain,
            checkpoint_id: F::from_u64_value(self.current_checkpoint_id),
            realm_id: F::from_u64_value(self.realm_id_u64),
            checkpoint_tree_root: root_header.header.checkpoint_tree_root,
            validator_tree_root: checkpoint_leaf.global_state_roots.validator_tree_root,
            root_guta_header_hash,
        };
        let action_hash = action.action_hash::<Hasher>();

        let signature_job_id = QProvingJobDataID::new(
            QJobTopic::GenerateStandardProof,
            self.unique_pending_id,
            self.realm_id_u64 as u32,
            0,
            0,
            ProvingJobCircuitType::WrappedSignatureProof,
            ProvingJobDataType::StandardProof,
            0,
        );
        // Worker deserializes client-side PsyZKSignatureCircuitInput via bincode.
        // Use concrete Goldilocks field (network field is Goldilocks) so planner F
        // need not be RichField. Bridge the generic planner Hash to the client
        // QHashOut via the 32-byte canonical encoding.
        let signature_input = PsyZKSignatureCircuitInput::<parth_core::PF> {
            private_key: ClientQHashOut::from_hash256_le(ClientHash256(private_key.into_owned_32bytes())),
            sig_hash: ClientQHashOut::from_hash256_le(ClientHash256(action_hash.into_owned_32bytes())),
        };
        let signature_expected_pi = Hasher::q_two_to_one(action_hash, public_key_param);
        let signature_job = PsyProvingJobMetadataWithJobId {
            job_id: signature_job_id,
            metadata: PsyProvingJobMetadata {
                expected_public_inputs_hash: signature_expected_pi,
                reward_tree_node_index: 0,
                reward_tree_node_level: 0,
                reward_tree_hash_mode: PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN,
                reward_tree_node_children: 0,
                dependencies: vec![],
            },
        };

        let mut final_guta_header = root_header.header;
        final_guta_header.state_transition.new_node_value = fee_delta_proof.new_root;
        final_guta_header.total_aggregation_proofs_generated =
            F::from_u64_value(final_guta_header.total_aggregation_proofs_generated.to_u64_value() + 1);

        // Placeholder reward tag. Worker prove path binds the real child tag;
        // metadata PI is rewritten in finalize_with_reward_ids after reward-tree
        // assignment, and process_block rebuilds the public output for
        // coordinator submission from the proved root child tag.
        let root_guta_reward_tag = Hash::get_zero_value();
        let public_output = RealmFinalizeGUTAPublicOutput {
            chain_domain,
            checkpoint_id: F::from_u64_value(self.current_checkpoint_id),
            realm_id: F::from_u64_value(self.realm_id_u64),
            realm_sub_id: self.realm_sub_id_u64 as u16,
            checkpoint_tree_root: root_header.header.checkpoint_tree_root,
            validator_tree_root: checkpoint_leaf.global_state_roots.validator_tree_root,
            validator_user_id: F::from_u64_value(validator_user_id_u64),
            root_guta_header_hash,
            root_guta_reward_tag,
            action_hash,
            final_guta_header: final_guta_header,
        };
        let finalizer_expected_pi = public_output.public_output_hash::<Hasher>();

        let finalizer_job_id = QProvingJobDataID::realm_finalize_guta(self.current_checkpoint_id, self.realm_id_u64 as u32);
        // root_guta_whitelist_proof is ignored by the circuit prove path (library fills it).
        // Keep a serializable empty proof for the witness shape.
        let finalizer_input = RealmFinalizeGUTAInput {
            root_guta_header: root_header.header,
            root_guta_whitelist_proof: MerkleProofCore {
                root: Hash::get_zero_value(),
                value: Hash::get_zero_value(),
                index: 0,
                siblings: vec![],
            },
            checkpoint_id: F::from_u64_value(self.current_checkpoint_id),
            realm_sub_id: self.realm_sub_id_u64 as u16,
            anchor_checkpoint_leaf,
            anchor_checkpoint_tree_proof,
            checkpoint_tree_proof,
            checkpoint_leaf,
            old_realm_root_proof,
            validator_user_id: F::from_u64_value(validator_user_id_u64),
            validator_tree_proof,
            validator_user_leaf,
            validator_user_tree_proof,
            validator_public_key_param: public_key_param,
            signature_proof_type: F::from_u64_value(SIGNATURE_TYPE_ZK as u64),
            validator_fee_delta_proof: fee_delta_proof,
        };

        let finalizer_job = PsyProvingJobMetadataWithJobId {
            job_id: finalizer_job_id,
            metadata: PsyProvingJobMetadata {
                expected_public_inputs_hash: finalizer_expected_pi,
                reward_tree_node_index: 0,
                reward_tree_node_level: 0,
                reward_tree_hash_mode: PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD,
                reward_tree_node_children: 2,
                dependencies: vec![root_header.job_id, signature_job_id],
            },
        };

        // Signature must complete before the finalizer claim. Publish signature
        // on base_level, finalizer on base_level+1 so level-by-level worker
        // dispatch respects deps.
        let base_level = self
            .planned_jobs
            .iter()
            .rposition(|jobs| !jobs.is_empty())
            .map(|level| level + 1)
            .unwrap_or(0);
        let signature_level = base_level;
        let finalizer_level = base_level + 1;
        if finalizer_level >= MAX_REALM_PROVING_LEVELS {
            anyhow::bail!(
                "Cannot append RealmFinalizeGUTA: level {} exceeds planner capacity.",
                finalizer_level
            );
        }

        let signature_bytes = bincode::serialize(&signature_input)
            .map_err(|e| anyhow::anyhow!("serialize signature witness: {e}"))?;
        let finalizer_bytes = finalizer_input.psy_ser_into_bytes_vec()?;
        let new_user_leaf_bytes = new_user_leaf.psy_ser_to_bytes_vec()?;
        let new_total_jobs = self
            .total_jobs
            .checked_add(2)
            .ok_or_else(|| anyhow::anyhow!("RealmFinalizeGUTA would overflow planner total_jobs"))?;

        temp_store
            .set_tdb_proof_witnesses_tuple_owned_raw(
                &self.realm_identifier,
                self.unique_pending_id,
                vec![
                    (signature_job_id, signature_bytes),
                    (finalizer_job_id, finalizer_bytes),
                ],
            )
            .await?;

        global_user_tree.set_leaf(effective_validator_index, new_leaf_hash);
        let signature_position = self.planned_jobs[signature_level].len();
        self.job_level_map
            .insert(signature_job_id, (signature_level, signature_position));
        self.planned_jobs[signature_level].push(signature_job);

        let finalizer_position = self.planned_jobs[finalizer_level].len();
        self.job_level_map
            .insert(finalizer_job_id, (finalizer_level, finalizer_position));
        self.planned_jobs[finalizer_level].push(finalizer_job);

        self.total_jobs = new_total_jobs;
        self.user_leaf_updates_ffs.extend_from_slice(&new_user_leaf_bytes);
        self.realm_finalize_validator_user_leaf = Some(new_user_leaf);
        self.finalizer_public_output = Some(public_output);

        let final_header = GlobalUserTreeAggregatorHeaderWithJobId {
            header: final_guta_header,
            job_id: finalizer_job_id,
        };
        Ok((final_header, true))
    }

    pub async fn finalize_with_reward_ids<Hasher: FieldQHasher<F, Hash>, TempStore: StandardProcessorTempDBStoreBase<QProvingJobDataID, Hash>>(
        mut self,
        checkpoint_tree: &PsyDashMemoryAppendOnlyMerkleStore<Hasher, Hash>,
        global_user_tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
        temp_store: Arc<TempStore>,
        reward_tree_root_level: u8,
        reward_tree_root_index: u64,
    ) -> anyhow::Result<Option<RealmGUTAEndCapGathererOutput<F, Hash, QProvingJobDataID>>> {
        if self.total_jobs == 0 && self.end_cap_straggler.is_none() {
            // No jobs were added.
            tracing::info!("No jobs were added during GUTA planning. Nothing to finalize.");
            return Ok(None);
        } else if self.end_cap_straggler.is_some() {
            let end_cap_straggler = self
                .finalize_promote_end_cap_stragglers(&checkpoint_tree, global_user_tree, temp_store.clone())
                .await?;
            if end_cap_straggler.is_some() {
                // single end-cap straggler remains, promote to GUTA root
                if self.total_jobs != 0 {
                    tracing::error!("End-cap straggler remains but other jobs exist. This should never happen.");
                    anyhow::bail!("End-cap straggler remains but other jobs exist. This should never happen.");
                }
                let end_cap_straggler = end_cap_straggler.unwrap();
                let effective_user_id = end_cap_straggler.new_user_leaf.user_id.to_u64_value() - self.realm_user_min_id;
                let checkpoint_id = end_cap_straggler.new_user_leaf.last_checkpoint_id.to_u64_value();
                let checkpoint_merkle_proof =
                    checkpoint_tree.get_historical_merkle_proof_at_historical_index(checkpoint_id, self.current_checkpoint_id);
                let mut global_user_tree_delta_merkle_proof = global_user_tree.set_leaf(effective_user_id, end_cap_straggler.new_user_leaf_hash);
                global_user_tree_delta_merkle_proof.index += self.realm_user_min_id;
                println!("global_user_tree_delta_merkle_proof: {:?}", global_user_tree_delta_merkle_proof);
                if checkpoint_merkle_proof.verify::<Hasher>() {
                    tracing::info!("Checkpoint merkle proof verified successfully.");
                } else {
                    tracing::error!("Checkpoint merkle proof verification failed: {:?}", checkpoint_merkle_proof);
                }

                let witness = VerifySingleEndCapInputV2 {
                    guta_circuit_whitelist: self.guta_circuit_whitelist,
                    core: VerifyEndCapSimpleStandardInput {
                        guta_stats: end_cap_straggler.stats,
                        checkpoint_root: checkpoint_merkle_proof.get_append_root::<Hasher>(),
                        checkpoint_historical_merkle_proof: checkpoint_merkle_proof,
                    },
                    global_user_tree_sub_root_transition: global_user_tree_delta_merkle_proof,
                    user_id: end_cap_straggler.new_user_leaf.user_id,
                };
                if witness.core.checkpoint_historical_merkle_proof.verify::<Hasher>() {
                    tracing::info!("witness.core.checkpoint_historical_merkle_proof verified successfully.");
                } else {
                    tracing::error!("witness.core.checkpoint_historical_merkle_proof merkle proof verification failed: {:?}", witness.core.checkpoint_historical_merkle_proof);
                }
                let job_id = QProvingJobDataID::guta_single_end_cap_witness(self.unique_pending_id, 0, 0, 0);
                let expected_public_inputs_hash = witness.get_public_inputs_hash_no_rewards_tag::<Hasher>(self.global_user_tree_height);
                let job = PsyProvingJobMetadataWithJobId {
                    job_id: job_id.clone(),
                    metadata: PsyProvingJobMetadata {
                        expected_public_inputs_hash,
                        reward_tree_node_index: reward_tree_root_index,
                        reward_tree_node_level: reward_tree_root_level,
                        reward_tree_hash_mode: PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN,
                        reward_tree_node_children: 0,
                        dependencies: vec![end_cap_straggler.job_id],
                    },
                };
                let new_guta_header = GlobalUserTreeAggregatorHeaderWithJobId {
                    header: witness.get_new_guta_header(self.global_user_tree_height),
                    job_id: job_id.clone(),
                };
                println!("new_guta_header: {:?}", new_guta_header);
                temp_store
                    .set_tdb_proof_witnesses_tuple_owned_raw(
                        &self.realm_identifier,
                        self.unique_pending_id,
                        vec![(job_id, witness.psy_ser_into_bytes_vec()?)],
                    )
                    .await?;
                self.total_jobs += 1;
                let mut root_header = new_guta_header;
                if self.realm_finalize_enabled() {
                    root_header = self
                        .append_realm_finalize_guta::<Hasher, TempStore>(global_user_tree, temp_store.clone(), root_header)
                        .await?
                        .0;
                    self.update_reward_tree_config(&root_header.job_id, reward_tree_root_level, reward_tree_root_index)?;
                }
                return Ok(Some(RealmGUTAEndCapGathererOutput {
                    db_output: RealmGUTAEndCapGathererOutputDatabase {
                        total_users_updated: self.total_end_caps_processed as u64,
                        total_proofs_generated: self.total_jobs as u64,
                        old_realm_root: self.start_realm_root,
                        new_realm_root: global_user_tree.get_root(),
                        update_global_user_tree_nodes_ffs: create_ffs_merkle_nodes_zero_id_from_hash_map_with_offset::<Hash>(
                            global_user_tree.get_changes(),
                            self.realm_root_key,
                        ),
                        update_user_contract_tree_nodes_ffs: self.user_contract_tree_updates_ffs,
                        update_contract_state_tree_nodes_ffs: self.contract_state_tree_updates_ffs,
                        update_contract_state_imt_leaves_ffs: self.contract_state_imt_leaves_ffs,
                        update_user_leaves_ffs: self.user_leaf_updates_ffs,
                        guta_header: root_header,
                    },
                    job_ids: vec![vec![job]],
                }));
            }
        }
        let result = self.finalize_promote_guta_stragglers::<Hasher, TempStore>(temp_store.clone()).await?;
        if let Some(level) = result {
            // this is the root
            let straggler = self.job_stragglers[level].take().unwrap();
            let mut root_header = straggler;
            if self.realm_finalize_enabled() {
                root_header = self
                    .append_realm_finalize_guta::<Hasher, TempStore>(global_user_tree, temp_store.clone(), root_header)
                    .await?
                    .0;
            }
            self.update_reward_tree_config(&root_header.job_id, reward_tree_root_level, reward_tree_root_index)?;

            Ok(Some(RealmGUTAEndCapGathererOutput {
                db_output: RealmGUTAEndCapGathererOutputDatabase {
                    total_users_updated: self.total_end_caps_processed as u64,
                    old_realm_root: self.start_realm_root,
                    new_realm_root: global_user_tree.get_root(),
                    update_global_user_tree_nodes_ffs: create_ffs_merkle_nodes_zero_id_from_hash_map_with_offset::<Hash>(
                        global_user_tree.get_changes(),
                        self.realm_root_key,
                    ),
                    total_proofs_generated: self.total_jobs as u64,
                    update_user_contract_tree_nodes_ffs: self.user_contract_tree_updates_ffs,
                    update_contract_state_tree_nodes_ffs: self.contract_state_tree_updates_ffs,
                    update_contract_state_imt_leaves_ffs: self.contract_state_imt_leaves_ffs,
                    update_user_leaves_ffs: self.user_leaf_updates_ffs,
                    guta_header: root_header,
                },
                job_ids: self.planned_jobs.into_iter().filter(|x| !x.is_empty()).collect(),
            }))
        } else {
            tracing::info!("No stragglers remain after finalization, but no root found. This should never happen.");
            anyhow::bail!("No stragglers remain after finalization, but no root found. This should never happen.");
        }
    }
}
