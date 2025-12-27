use std::{collections::HashMap, sync::Arc};

use parth_common::memory_stores::{dash_tree_append_only::PsyDashMemoryAppendOnlyMerkleStore, mem_tree_recorder::SimpleMemoryMerkleRecorderStore};
use parth_core::{
    crypto::hash::traits::FieldQHasher,
    data::hash::merkle_node_key::SimpleMerkleNodeKey,
    felt::QFelt64,
    node::realm_identifier::QRealmIdentifier,
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{
    guta::header_extended::GlobalUserTreeAggregatorHeaderWithJobId,
    proof_input::guta::{
        GUTAVerifyLeftGUTARightEndCapCircuitInputV2, GUTAVerifyTwoEndCapCircuitInputV2, GUTAVerifyTwoGUTALinearCircuitInput,
        VerifyEndCapSimpleStandardInput, VerifySingleEndCapInputV2,
    },
    queue_items::realm_user_update::PsyRealmUserUpdateQueueItem,
    worker::{
        metadata::{PsyProvingJobMetadata, PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN},
        metadata_with_job_id::PsyProvingJobMetadataWithJobId,
    },
};
use psy_io::tokio::TokioFileLike;
use psy_node_core::{
    psy_temp_db::StandardProcessorTempDBStoreBase,
    qblob::{
        blob_type::QBlobMerkleNodeTreeType,
        data_views::{
            double_merkle_node_batch::QBlobDoubleMerkleNodeBatchDataView, single_merkle_node_batch::QBlobSingleMerkleNodeBatchDataView,
            zero_merkle_node_batch::create_ffs_merkle_nodes_zero_id_from_hash_map_with_offset,
        },
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
        }
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
            tracing::info!(
                "Skipping end-cap job population due to user leaf hash mismatch for user ID {}. Expected last_user_leaf_value={:?}, found {:?}. Likely got overwritten due to a race condition. Gracefully skipping.",
                user_id,
                last_user_leaf_value,
                queue_item.old_user_leaf_hash
            );
            return Ok(0);
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
                tracing::info!(
                    "Skipping end-cap job population due to missing contract updates for user ID {}.",
                    queue_item.new_user_leaf.user_id.to_u64_value()
                );
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

        let (single_header, single_payload, double_full) =
            QBlobSingleMerkleNodeBatchDataView::validate_single_tree_nodes_batch_header_for_realm_context_get_clipped_ref_no_exact_size_any_unique_pending_id(
                &data,
                self.chain_id,
                self.realm_id_u64,
                self.realm_sub_id_u64,
                QBlobMerkleNodeTreeType::UserContractTree,
            )?;
        let (_double_header, double_payload) =
            QBlobDoubleMerkleNodeBatchDataView::validate_cst_nodes_batch_header_for_realm_context_get_clipped_ref_any_unique_pending_id(
                &double_full,
                self.chain_id,
                self.realm_id_u64,
                self.realm_sub_id_u64,
            )?;
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
        let queue_item = future_end_cap_job.queue_item;
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
        let (_double_header, double_payload) =
            QBlobDoubleMerkleNodeBatchDataView::validate_cst_nodes_batch_header_for_realm_context_get_clipped_ref_any_unique_pending_id(
                &double_full,
                self.chain_id,
                self.realm_id_u64,
                self.realm_sub_id_u64,
            )?;
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
                        update_user_leaves_ffs: self.user_leaf_updates_ffs,
                        guta_header: new_guta_header,
                    },
                    job_ids: vec![vec![job]],
                }));
            }
        }
        let result = self.finalize_promote_guta_stragglers::<Hasher, TempStore>(temp_store.clone()).await?;
        if let Some(level) = result {
            // this is the root
            let straggler = self.job_stragglers[level].take().unwrap();
            let root_job_id = straggler.job_id;
            self.update_reward_tree_config(&root_job_id, reward_tree_root_level, reward_tree_root_index)?;

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
                    update_user_leaves_ffs: self.user_leaf_updates_ffs,
                    guta_header: straggler,
                },
                job_ids: self.planned_jobs.into_iter().filter(|x| !x.is_empty()).collect(),
            }))
        } else {
            tracing::info!("No stragglers remain after finalization, but no root found. This should never happen.");
            anyhow::bail!("No stragglers remain after finalization, but no root found. This should never happen.");
        }
    }
}
