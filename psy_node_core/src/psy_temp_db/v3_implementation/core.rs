use async_trait::async_trait;
use parth_core::{
    QCoreProcCheckpointUniqueId, QJobIdBase, data::serializable::QProofWitnessSerializable, node::realm_identifier::QRealmIdentifier, protocol::core_types::Q256BitHash
};
use psy_data::{node::node_proving_state::PsyNodeProvingState, worker::metadata::PsyProvingJobMetadata};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

const DEPLOY_CONTRACT_ZSTD_PREFIX: &[u8; 4] = b"PSZ1";

use crate::{
    psy_temp_db::{
        tt_get_worker_reputation_key,
        CheckpointJobStats, QTempDBDeployContractDataReader, QTempDBDeployContractDataWriter, QTempDBJobClaimInfoReader, QTempDBJobClaimInfoWriter, QTempDBJobStatsStore, QTempDBNodeProvingStateReader, QTempDBNodeProvingStateWriter, QTempDBPendingIdReader, QTempDBPendingIdWriter, QTempDBProofWitnessReader, QTempDBProofWitnessWriter, QTempDBProvingJobMetadataReader, QTempDBProvingJobMetadataWriter, QTempDBRewardsTreeReader, QTempDBRewardsTreeWriter, QTempDBSubmitStatusReader, QTempDBSubmitStatusWriter, QTempDBUserContractUpdatesReader, QTempDBUserContractUpdatesWriter, QTempDBUserEndCapSlotUpdatesReader, QTempDBUserEndCapSlotUpdatesWriter, QTempDBWorkerReputationMutation, QTempDBWorkerReputationReader, QTempDBWorkerReputationWriter, tt_get_contract_updates_key, tt_get_deploy_contract_code_definition_key, tt_get_gathering_unique_pending_id_key, tt_get_job_claim_key_from_job, tt_get_job_stats_count_key, tt_get_job_stats_max_duration_key, tt_get_job_stats_min_duration_key, tt_get_job_stats_total_duration_key, tt_get_node_proving_state_key, tt_get_proof_claim_tag_key_from_job, tt_get_proof_witness_data_key_from_job, tt_get_proving_job_metadata_key_from_job, tt_get_rewards_tag_tree_value_key_from_job, tt_get_submit_status_key, tt_get_unique_pending_id_key, tt_get_user_end_cap_slot_updates_key,
    },
    store::traits::temp_db::{
        QTempDatabaseRawCounterReaderBase, QTempDatabaseRawCounterWriterBase, QTempDatabaseRawKVReaderBase, QTempDatabaseRawKVWriterBase,
        QTempDatabaseRawWorkerReputationMutationBase,
    },
};
use crate::psy_temp_db::WorkerJobClaim;
/*


let key = tt_get_unique_pending_id_key(rid.realm_id, rid.realm_sub_id);
let mut value = [u8; 24];
value[0..8].copy_from_slice(&unique_pending_id.to_le_bytes());
value[8..24].copy_from_slice(&proc_checkpoint_unique_id.to_le_bytes());
self.(&key, &value).await
*/

/* 
#[async_trait]
impl<T: QTempDatabaseRawKVReaderBase + Sync + Send, JobId: QJobIdBase + Sync + Send + 'static, Hash: QDBHashBase + Sync + Send>
    QTempDBExpectedPublicInputsReader<JobId, Hash> for T
{
    async fn get_expected_public_inputs_hash(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_id: JobId) -> anyhow::Result<Hash> {
        let key = tt_get_proving_job_metadata_key_from_job(rid.realm_id as u32, rid.realm_sub_id as u16, unique_pending_id, &job_id);
        let value_bytes = self.qtdb_raw_kv_get_value(&key).await?;
        if value_bytes.is_some() {
            let value_bytes = value_bytes.unwrap();
            if value_bytes.len() != 32 {
                return Err(anyhow::anyhow!("Invalid value length for expected public inputs hash"));
            }
            Ok(Hash::from_owned_32bytes(value_bytes.try_into().unwrap()))
        } else {
            anyhow::bail!("Expected public inputs hash not found");
        }
    }
}
#[async_trait]
impl<T: QTempDatabaseRawKVWriterBase + Sync + Send, JobId: QJobIdBase + Sync + Send + 'static, Hash: QDBHashBase + Sync + Send>
    QTempDBExpectedPublicInputsWriter<JobId, Hash> for T
{
    async fn set_expected_public_inputs_hash(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_id: JobId, hash: Hash) -> anyhow::Result<()> {
        let key = tt_get_proving_job_metadata_key_from_job(rid.realm_id as u32, rid.realm_sub_id as u16, unique_pending_id, &job_id);
        self.qtdb_raw_kv_put_value(&key, &hash.into_owned_32bytes()).await
    }
    async fn set_expected_public_inputs_hash_batch_fast_serialized(
        &self,
        rid: &QRealmIdentifier,
        unique_pending_id: u64,
        data: &[u8],
    ) -> anyhow::Result<()> {
        const ITEM_SIZE: usize = QJOB_ID_SERIALIZED_SIZE + TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_VALUE_SIZE;
        let data_len = data.len();
        if data_len % ITEM_SIZE != 0 {
            return Err(anyhow::anyhow!("Data length is not a multiple of combined key and value size"));
        }
        if data_len == 0 {
            return Ok(());
        }

        let num_entries = data_len / ITEM_SIZE;
        let mut entries = Vec::with_capacity(num_entries);
        for i in 0..num_entries {
            let idx = i * ITEM_SIZE;
            let job_id_bytes = &data[idx..(idx + QJOB_ID_SERIALIZED_SIZE)];
            let value_bytes = &data[(idx + QJOB_ID_SERIALIZED_SIZE)..(idx + ITEM_SIZE)];
            let key = tt_get_proving_job_metadata_key_from_job(rid.realm_id, rid.realm_sub_id, unique_pending_id, &job_id_bytes.try_into().unwrap());
            entries.push((key.to_vec(), value_bytes.to_vec()));
        }

        self.qtdb_raw_kv_put_many_values_tuple(&entries).await?;
        /*
        let num_entries = data_len / combined_size;
        let combined_size = TEMP_TABLE_WORKER_PROOF_METADATA_KEY_SIZE + TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_VALUE_SIZE;
        let data_len = data.len();
        if data_len % combined_size != 0 {
            return Err(anyhow::anyhow!("Data length is not a multiple of combined key and value size"));
        }
        if data_len == 0 {
            return Ok(());
        }
        let template = tt_get_expected_public_inputs_key(rid.realm_id, rid.realm_sub_id, unique_pending_id, &[0u8; QJOB_ID_SERIALIZED_SIZE]);

        const BATCH_SIZE: usize = 512;
        const BUFFER_SIZE: usize = BATCH_SIZE * TEMP_TABLE_WORKER_PROOF_METADATA_KEY_SIZE;
        const

        if num_entries < BATCH_SIZE {
            let mut keys = Vec::with_capacity(num_entries);
            let mut entries = Vec::with_capacity(num_entries);

            for i in 0..num_entries {

                let idx = i * (QJOB_ID_SERIALIZED_SIZE + TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_VALUE_SIZE);
                let job_id_bytes = &data[idx..(idx+TEMP_TABLE_WORKER_PROOF_METADATA_KEY_SIZE - 40 + QJOB_ID_SERIALIZED_SIZE)];
                let mut key = template;
                key[16..40].copy_from_slice(job_id_bytes);
                let value = &data[(idx+TEMP_TABLE_WORKER_PROOF_METADATA_KEY_SIZE)..(idx+TEMP_TABLE_WORKER_PROOF_METADATA_KEY_SIZE+TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_VALUE_SIZE)];
                entries.push(((key.as_ref(),value)));
            }
            self.qtdb_raw_kv_put_many_values_tuple_ref(&entries).await?;
            return Ok(());
        }
        let buffer = [0u8; BUFFER_SIZE];

        let num_entries = data_len / combined_size;
        let mut entries = Vec::with_capacity(num_entries);
        for i in 0..num_entries {
            let idx = i * (TEMP_TABLE_WORKER_PROOF_METADATA_KEY_SIZE + TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_VALUE_SIZE);
            let key = &data[idx..(idx+TEMP_TABLE_WORKER_PROOF_METADATA_KEY_SIZE)];
            let value = &data[(idx+TEMP_TABLE_WORKER_PROOF_METADATA_KEY_SIZE)..(idx+TEMP_TABLE_WORKER_PROOF_METADATA_KEY_SIZE+TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_VALUE_SIZE)];
            entries.push(((key,value)));
        }
        self.qtdb_raw_kv_put_many_values_tuple_ref(&entries).await?;
        */
        /*
        let combined_size = TEMP_TABLE_WORKER_PROOF_METADATA_KEY_SIZE + TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_VALUE_SIZE;
        let data_len = data.len();
        if data_len % combined_size != 0 {
            return Err(anyhow::anyhow!("Data length is not a multiple of combined key and value size"));
        }
        if data_len == 0 {
            return Ok(());
        }
        let num_entries = data_len / combined_size;
        let mut entries = Vec::with_capacity(num_entries);
        for i in 0..num_entries {
            let idx = i * (TEMP_TABLE_WORKER_PROOF_METADATA_KEY_SIZE + TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_VALUE_SIZE);
            let key = &data[idx..(idx+TEMP_TABLE_WORKER_PROOF_METADATA_KEY_SIZE)];
            let value = &data[(idx+TEMP_TABLE_WORKER_PROOF_METADATA_KEY_SIZE)..(idx+TEMP_TABLE_WORKER_PROOF_METADATA_KEY_SIZE+TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_VALUE_SIZE)];
            entries.push(((key,value)));
        }
        self.qtdb_raw_kv_put_many_values_tuple_ref(&entries).await?;
        Ok(())
        */

        Ok(())
    }
}
*/

#[async_trait]
impl<T> QTempDBJobStatsStore for T
where
    T: QTempDatabaseRawCounterReaderBase + QTempDatabaseRawCounterWriterBase + Send + Sync,
{
    async fn increment_job_stats(
        &self,
        rid: &QRealmIdentifier,
        unique_pending_id: u64,
        duration_ms: u64,
    ) -> anyhow::Result<()> {
        let duration_ms = i64::try_from(duration_ms)
            .map_err(|_| anyhow::anyhow!("job duration exceeds i64::MAX milliseconds"))?;
        let count_key = tt_get_job_stats_count_key(rid.realm_id, rid.realm_sub_id, unique_pending_id);
        let total_key = tt_get_job_stats_total_duration_key(rid.realm_id, rid.realm_sub_id, unique_pending_id);
        let min_key = tt_get_job_stats_min_duration_key(rid.realm_id, rid.realm_sub_id, unique_pending_id);
        let max_key = tt_get_job_stats_max_duration_key(rid.realm_id, rid.realm_sub_id, unique_pending_id);

        let completed = self.qtdb_raw_counter_increment_by(&count_key, 1).await?;
        self.qtdb_raw_counter_increment_by(&total_key, duration_ms).await?;

        if completed == 1 {
            self.qtdb_raw_counter_set_value(&min_key, duration_ms).await?;
            self.qtdb_raw_counter_set_value(&max_key, duration_ms).await?;
            return Ok(());
        }

        let current_min = self.qtdb_raw_counter_get_value(&min_key).await?;
        if duration_ms < current_min {
            self.qtdb_raw_counter_set_value(&min_key, duration_ms).await?;
        }

        let current_max = self.qtdb_raw_counter_get_value(&max_key).await?;
        if duration_ms > current_max {
            self.qtdb_raw_counter_set_value(&max_key, duration_ms).await?;
        }

        Ok(())
    }

    async fn get_job_stats(
        &self,
        rid: &QRealmIdentifier,
        unique_pending_id: u64,
    ) -> anyhow::Result<Option<CheckpointJobStats>> {
        let count_key = tt_get_job_stats_count_key(rid.realm_id, rid.realm_sub_id, unique_pending_id);
        let total_key = tt_get_job_stats_total_duration_key(rid.realm_id, rid.realm_sub_id, unique_pending_id);
        let min_key = tt_get_job_stats_min_duration_key(rid.realm_id, rid.realm_sub_id, unique_pending_id);
        let max_key = tt_get_job_stats_max_duration_key(rid.realm_id, rid.realm_sub_id, unique_pending_id);

        let completed = self.qtdb_raw_counter_get_value(&count_key).await?;
        if completed <= 0 {
            return Ok(None);
        }

        let total_duration_ms = self.qtdb_raw_counter_get_value(&total_key).await?;
        let min_duration_ms = self.qtdb_raw_counter_get_value(&min_key).await?;
        let max_duration_ms = self.qtdb_raw_counter_get_value(&max_key).await?;
        if total_duration_ms < 0 || min_duration_ms < 0 || max_duration_ms < 0 {
            anyhow::bail!("job stats counters contain a negative duration");
        }

        Ok(Some(CheckpointJobStats {
            total_completed: completed as u64,
            total_duration_ms: total_duration_ms as u64,
            min_duration_ms: Some(min_duration_ms as u64),
            max_duration_ms: Some(max_duration_ms as u64),
        }))
    }

    async fn clear_job_stats(&self, rid: &QRealmIdentifier, unique_pending_id: u64) -> anyhow::Result<()> {
        for key in [
            tt_get_job_stats_count_key(rid.realm_id, rid.realm_sub_id, unique_pending_id),
            tt_get_job_stats_total_duration_key(rid.realm_id, rid.realm_sub_id, unique_pending_id),
            tt_get_job_stats_min_duration_key(rid.realm_id, rid.realm_sub_id, unique_pending_id),
            tt_get_job_stats_max_duration_key(rid.realm_id, rid.realm_sub_id, unique_pending_id),
        ] {
            self.qtdb_raw_counter_set_value(&key, 0).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl<T: QTempDatabaseRawKVReaderBase + Sync> QTempDBPendingIdReader for T {
    async fn get_unique_pending_id(&self, rid: &QRealmIdentifier) -> anyhow::Result<u64> {
        let key = tt_get_unique_pending_id_key(rid.realm_id, rid.realm_sub_id);
        let value_bytes = self.qtdb_raw_kv_get_value(&key).await?;
        if value_bytes.is_some() {
            let value_bytes = value_bytes.unwrap();
            if value_bytes.len() != 24 {
                return Err(anyhow::anyhow!("Invalid value length for unique pending id"));
            }
            let unique_pending_id = u64::from_le_bytes(value_bytes[0..8].try_into().unwrap());
            Ok(unique_pending_id)
        } else {
            anyhow::bail!("Unique pending id not found");
        }
    }
    async fn get_proc_checkpoint_unique_id(&self, rid: &QRealmIdentifier) -> anyhow::Result<QCoreProcCheckpointUniqueId> {
        let key = tt_get_unique_pending_id_key(rid.realm_id, rid.realm_sub_id);
        let value_bytes = self.qtdb_raw_kv_get_value(&key).await?;
        if value_bytes.is_some() {
            let value_bytes = value_bytes.unwrap();
            if value_bytes.len() != 24 {
                return Err(anyhow::anyhow!("Invalid value length for proc checkpoint unique id"));
            }
            let proc_checkpoint_unique_id = QCoreProcCheckpointUniqueId::from_le_bytes(value_bytes[8..24].try_into().unwrap());
            Ok(proc_checkpoint_unique_id)
        } else {
            anyhow::bail!("Proc checkpoint unique id not found");
        }
    }
    async fn get_unique_pending_ids(&self, rid: &QRealmIdentifier) -> anyhow::Result<(u64, QCoreProcCheckpointUniqueId)> {
        let key = tt_get_unique_pending_id_key(rid.realm_id, rid.realm_sub_id);
        let value_bytes = self.qtdb_raw_kv_get_value(&key).await?;
        if value_bytes.is_some() {
            let value_bytes = value_bytes.unwrap();
            if value_bytes.len() != 24 {
                return Err(anyhow::anyhow!("Invalid value length for unique pending ids"));
            }
            let unique_pending_id = u64::from_le_bytes(value_bytes[0..8].try_into().unwrap());
            let proc_checkpoint_unique_id = QCoreProcCheckpointUniqueId::from_le_bytes(value_bytes[8..24].try_into().unwrap());
            Ok((unique_pending_id, proc_checkpoint_unique_id))
        } else {
            anyhow::bail!("Unique pending ids not found");
        }
    }
    async fn get_gathering_unique_pending_ids(&self, rid: &QRealmIdentifier) -> anyhow::Result<(u64, QCoreProcCheckpointUniqueId)> {
        let key = tt_get_gathering_unique_pending_id_key(rid.realm_id, rid.realm_sub_id);
        let value_bytes = self.qtdb_raw_kv_get_value(&key).await?;
        if value_bytes.is_some() {
            let value_bytes = value_bytes.unwrap();
            if value_bytes.len() != 24 {
                return Err(anyhow::anyhow!("Invalid value length for unique pending ids"));
            }
            let unique_pending_id = u64::from_le_bytes(value_bytes[0..8].try_into().unwrap());
            let proc_checkpoint_unique_id = QCoreProcCheckpointUniqueId::from_le_bytes(value_bytes[8..24].try_into().unwrap());
            Ok((unique_pending_id, proc_checkpoint_unique_id))
        } else {
            anyhow::bail!("Unique pending ids not found");
        }
    }
}

#[async_trait]
impl<T: QTempDatabaseRawKVWriterBase + Sync> QTempDBPendingIdWriter for T {
    async fn set_unique_pending_ids(
        &self,
        rid: &QRealmIdentifier,
        unique_pending_id: u64,
        proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId,
    ) -> anyhow::Result<()> {
        let key = tt_get_unique_pending_id_key(rid.realm_id, rid.realm_sub_id);
        let mut data = [0u8; 24];
        data[0..8].copy_from_slice(&unique_pending_id.to_le_bytes());
        data[8..24].copy_from_slice(&proc_checkpoint_unique_id.to_le_bytes());
        self.qtdb_raw_kv_put_value(&key, &data).await
    }
    async fn set_gathering_unique_pending_ids(&self, rid: &QRealmIdentifier, unique_pending_id: u64, proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId) -> anyhow::Result<()> {
        let key = tt_get_gathering_unique_pending_id_key(rid.realm_id, rid.realm_sub_id);
        let mut data = [0u8; 24];
        data[0..8].copy_from_slice(&unique_pending_id.to_le_bytes());
        data[8..24].copy_from_slice(&proc_checkpoint_unique_id.to_le_bytes());
        self.qtdb_raw_kv_put_value(&key, &data).await
    }
}





#[async_trait]
impl<T: QTempDatabaseRawKVReaderBase + Sync> QTempDBNodeProvingStateReader for T {
    async fn get_psy_node_proving_state(&self, rid: &QRealmIdentifier) -> anyhow::Result<PsyNodeProvingState>{
        let key = tt_get_node_proving_state_key(rid.realm_id, rid.realm_sub_id);
        let value_bytes = self.qtdb_raw_kv_get_value(&key).await?;
        if value_bytes.is_some() {
            let value_bytes = value_bytes.unwrap();
            Ok(PsyNodeProvingState::psy_ser_from_owned_bytes_vec(value_bytes)?)
        }else{
            Ok(PsyNodeProvingState { realm_id: 0, realm_sub_id: 0, node_type: 0, plan_variant: 0, current_proving_level: 0, has_remaining_proving_jobs: 0, unique_pending_id: 0, last_committed_checkpoint_id: 0, guta_input_proofs: 0, total_guta_jobs: 0, new_user_registrations: 0, total_user_registration_jobs: 0, new_contracts_deployed: 0, total_deploy_contract_jobs: 0 })
        }
        

    }
}

#[async_trait]
impl<T: QTempDatabaseRawKVWriterBase + Sync> QTempDBNodeProvingStateWriter for T {
    async fn set_psy_node_proving_state(&self, rid: &QRealmIdentifier, state: &PsyNodeProvingState) -> anyhow::Result<()>{
        let key = tt_get_node_proving_state_key(rid.realm_id, rid.realm_sub_id);
        let value_bytes = state.psy_ser_to_bytes_vec()?;
        self.qtdb_raw_kv_put_value(&key, &value_bytes).await
    }
}

#[async_trait]
impl<T: QTempDatabaseRawKVReaderBase + Sync> QTempDBSubmitStatusReader for T {
    async fn get_submitted_status_for_pending(&self, rid: &QRealmIdentifier, unique_pending_id: u64, user_or_realm_id: u64) -> anyhow::Result<u64> {
        let key = tt_get_submit_status_key(rid.realm_id, rid.realm_sub_id, unique_pending_id, user_or_realm_id);
        let value_bytes = self.qtdb_raw_kv_get_value(&key).await?;
        if value_bytes.is_some() {
            let value_bytes = value_bytes.unwrap();
            if value_bytes.len() != 8 {
                return Ok(0);
            }
            let submitted_status = u64::from_le_bytes(value_bytes[0..8].try_into().unwrap());
            Ok(submitted_status)
        } else {
            Ok(0)
            //anyhow::bail!("Submitted status not found");
        }
    }
}

/*


#[async_trait]
#[auto_impl(&, Arc)]
pub trait QTempDBProofWitnessReader<JobId: QJobIdBase> {
    async fn get_tdb_proof_witness<T: QProofWitnessSerializable>(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_id: JobId) -> anyhow::Result<T>;
    async fn get_tdb_proof_witness_bytes(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_id: JobId) -> anyhow::Result<Vec<u8>>;
    async fn get_tdb_proof_expected_public_inputs_hash_raw_and_dependencies(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_id: JobId) -> anyhow::Result<([u8; 32], Vec<JobId>)>;
}

#[async_trait]
#[auto_impl(&, Arc)]
pub trait QTempDBProofWitnessWriter<JobId: QJobIdBase> {
    async fn set_tdb_proof_witness<T: QProofWitnessSerializable>(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_id: JobId, witness: &T) -> anyhow::Result<()>;
    async fn set_tdb_proof_witnesses_tuple_owned<T: QProofWitnessSerializable>(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_witnesses: &[(JobId, T)]) -> anyhow::Result<()>;
    async fn set_tdb_proof_expected_public_inputs_hash_and_dependencies_raw(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_id: JobId, expected_public_inputs_hash: [u8; 32], dependencies: &[JobId]) -> anyhow::Result<()>;
    async fn set_tdb_proof_expected_public_inputs_many_tuple_owned_hash_raw(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_public_inputs: Vec<(JobId, ([u8; 32], Vec<JobId>))>) -> anyhow::Result<()>;

*/

#[async_trait]
impl<JobId: QJobIdBase + 'static, D: QTempDatabaseRawKVReaderBase + Sync> QTempDBProofWitnessReader<JobId> for D {

    async fn get_tdb_proof_witness<T: QProofWitnessSerializable>(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_id: JobId) -> anyhow::Result<T>{
        let key = tt_get_proof_witness_data_key_from_job(rid.realm_id, rid.realm_sub_id , unique_pending_id, &job_id);
        let value_bytes = self.qtdb_raw_kv_get_value(&key).await?;
        if value_bytes.is_some() {
            T::psy_ser_from_owned_bytes_vec(value_bytes.unwrap())
        }else{
            anyhow::bail!("Proof witness not found");
        }
    }
    async fn get_tdb_proof_witness_bytes(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_id: JobId) -> anyhow::Result<Vec<u8>>{
        let key = tt_get_proof_witness_data_key_from_job(rid.realm_id, rid.realm_sub_id , unique_pending_id, &job_id);
        let value_bytes = self.qtdb_raw_kv_get_value(&key).await?;
        if value_bytes.is_some() {
            Ok(value_bytes.unwrap())
        }else{
            anyhow::bail!("Proof witness not found");
        }
    }
}

#[async_trait]
impl<JobId: QJobIdBase + 'static, D: QTempDatabaseRawKVWriterBase + Sync> QTempDBProofWitnessWriter<JobId> for D {
    async fn set_tdb_proof_witness<T: QProofWitnessSerializable>(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_id: JobId, witness: &T) -> anyhow::Result<()>{
        let key = tt_get_proof_witness_data_key_from_job(rid.realm_id, rid.realm_sub_id , unique_pending_id, &job_id);
        let value_bytes = witness.psy_ser_to_bytes_vec()?;
        self.qtdb_raw_kv_put_value(&key, &value_bytes).await
    }
    async fn set_tdb_proof_witnesses_tuple_owned<T: QProofWitnessSerializable>(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_witnesses: &[(JobId, T)]) -> anyhow::Result<()>{
        let mut entries = Vec::with_capacity(job_witnesses.len());
        for (job_id, witness) in job_witnesses.iter() {
            let key = tt_get_proof_witness_data_key_from_job(rid.realm_id, rid.realm_sub_id , unique_pending_id, job_id);
            let value_bytes = witness.psy_ser_to_bytes_vec()?;
            entries.push((key.to_vec(), value_bytes));
        }
        self.qtdb_raw_kv_put_many_values_tuple(&entries).await?;
        Ok(())
    }
    async fn set_tdb_proof_witnesses_tuple_owned_raw(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_witnesses: Vec<(JobId, Vec<u8>)>) -> anyhow::Result<()> {
        let mut entries = Vec::with_capacity(job_witnesses.len());
        for (job_id, witness) in job_witnesses {
            let key = tt_get_proof_witness_data_key_from_job(rid.realm_id, rid.realm_sub_id, unique_pending_id, &job_id);
            entries.push((key.to_vec(), witness));
        }
        self.qtdb_raw_kv_put_many_values_tuple(&entries).await?;
        Ok(())
    }

}
#[async_trait]
impl<T: QTempDatabaseRawKVWriterBase + Sync> QTempDBSubmitStatusWriter for T {
    async fn set_submitted_status_for_pending(
        &self,
        rid: &QRealmIdentifier,
        unique_pending_id: u64,
        user_or_realm_id: u64,
        status: u64,
    ) -> anyhow::Result<()> {
        let key = tt_get_submit_status_key(rid.realm_id, rid.realm_sub_id, unique_pending_id, user_or_realm_id);
        let value = status.to_le_bytes();
        self.qtdb_raw_kv_put_value(&key, &value).await
    }
}

#[async_trait]
impl<T: QTempDatabaseRawKVReaderBase + Sync> QTempDBDeployContractDataReader for T {
    async fn get_deploy_contract_code_definition_raw(
        &self,
        rid: &QRealmIdentifier,
        unique_pending_id: u64,
        rand_key: &[u8; 16],
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let key = tt_get_deploy_contract_code_definition_key(rid.realm_id, rid.realm_sub_id, unique_pending_id, rand_key);
        let value_bytes = self.qtdb_raw_kv_get_value(&key).await?;
        if value_bytes.is_some() {
            let value_bytes = value_bytes.unwrap();
            if value_bytes.len() == 0 {
                return Ok(None);
            }
            if value_bytes.starts_with(DEPLOY_CONTRACT_ZSTD_PREFIX) {
                let compressed = &value_bytes[DEPLOY_CONTRACT_ZSTD_PREFIX.len()..];
                let decoded = zstd::stream::decode_all(compressed)
                    .map_err(|e| anyhow::anyhow!("failed to zstd-decompress deploy contract code definition: {}", e))?;
                Ok(Some(decoded))
            } else {
                Ok(Some(value_bytes))
            }
        } else {
            anyhow::bail!("deploy contract code definition not found (key: {})", hex::encode(&key));
        }
    }
}

#[async_trait]
impl<T: QTempDatabaseRawKVWriterBase + Sync> QTempDBDeployContractDataWriter for T {
    async fn set_deploy_contract_code_definition_raw(
        &self,
        rid: &QRealmIdentifier,
        unique_pending_id: u64,
        rand_key: &[u8; 16],
        data: Vec<u8>,
    ) -> anyhow::Result<()> {
        let key = tt_get_deploy_contract_code_definition_key(rid.realm_id, rid.realm_sub_id, unique_pending_id, &rand_key);
        let compressed = zstd::stream::encode_all(data.as_slice(), 3)
            .map_err(|e| anyhow::anyhow!("failed to zstd-compress deploy contract code definition: {}", e))?;
        let mut stored = Vec::with_capacity(DEPLOY_CONTRACT_ZSTD_PREFIX.len() + compressed.len());
        stored.extend_from_slice(DEPLOY_CONTRACT_ZSTD_PREFIX);
        stored.extend_from_slice(&compressed);
        self.qtdb_raw_kv_put_value(&key, &stored).await
    }
}





#[async_trait]
impl<Hash: Q256BitHash, JobId: QJobIdBase + 'static, D: QTempDatabaseRawKVReaderBase + Sync> QTempDBProvingJobMetadataReader<Hash, JobId> for D {
    async fn get_proving_job_metadata(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_id: JobId) -> anyhow::Result<PsyProvingJobMetadata<Hash, JobId>>{
        let value_bytes = self.qtdb_raw_kv_get_value(&tt_get_proving_job_metadata_key_from_job(rid.realm_id, rid.realm_sub_id, unique_pending_id, &job_id)).await?;
        if value_bytes.is_some() {
            PsyProvingJobMetadata::<Hash, JobId>::psy_ser_from_owned_bytes_vec(value_bytes.unwrap())
        }else{
            anyhow::bail!("Proving job metadata not found for job {:?} at unique_pending_id {}", job_id, unique_pending_id);
        }
    }
}

#[async_trait]
impl<Hash: Q256BitHash, JobId: QJobIdBase + 'static, D: QTempDatabaseRawKVWriterBase + Sync> QTempDBProvingJobMetadataWriter<Hash, JobId> for D {
    async fn set_proving_job_metadata(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_id: JobId, metadata: &PsyProvingJobMetadata<Hash, JobId>) -> anyhow::Result<()>{
        let key = tt_get_proving_job_metadata_key_from_job(rid.realm_id, rid.realm_sub_id, unique_pending_id, &job_id);
        let value_bytes = metadata.psy_ser_to_bytes_vec()?;
        self.qtdb_raw_kv_put_value(&key, &value_bytes).await
    }
    async fn set_proving_job_metadata_batch(&self, rid: &QRealmIdentifier, unique_pending_id: u64, data: &[(JobId, PsyProvingJobMetadata<Hash, JobId>)]) -> anyhow::Result<()>{
        let mut entries = Vec::with_capacity(data.len());
        for (job_id, metadata) in data.iter() {
            let key = tt_get_proving_job_metadata_key_from_job(rid.realm_id, rid.realm_sub_id, unique_pending_id, job_id);
            let value_bytes = metadata.psy_ser_to_bytes_vec()?;
            entries.push((key.to_vec(), value_bytes));
        }
        self.qtdb_raw_kv_put_many_values_tuple(&entries).await?;
        Ok(())
    }

}


#[async_trait]
impl<Hash: Q256BitHash, JobId: QJobIdBase + 'static, D: QTempDatabaseRawKVReaderBase + Sync> QTempDBRewardsTreeReader<Hash, JobId> for D {
    async fn get_proof_miner_rewards_tree_value(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_id: JobId) -> anyhow::Result<Hash> {
        let value_bytes: Option<Vec<u8>> = self.qtdb_raw_kv_get_value(&tt_get_rewards_tag_tree_value_key_from_job(rid.realm_id, rid.realm_sub_id, unique_pending_id, &job_id)).await?;
        if value_bytes.is_some() {
            Hash::from_slice_32bytes(&value_bytes.unwrap())
        }else{
            anyhow::bail!("get_proof_miner_rewards_tree_value not found for job {:?} at unique_pending_id {}", job_id, unique_pending_id);
        }
    }
    async fn get_proof_miner_rewards_tree_value_or_none(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_id: JobId) -> anyhow::Result<Option<Hash>>{
        let value_bytes: Option<Vec<u8>> = self.qtdb_raw_kv_get_value(&tt_get_rewards_tag_tree_value_key_from_job(rid.realm_id, rid.realm_sub_id, unique_pending_id, &job_id)).await?;
        if value_bytes.is_some() {
            let hash = Hash::from_slice_32bytes(&value_bytes.unwrap())?;
            Ok(Some(hash))
        }else{
            Ok(None)
        }
    }
    async fn get_proof_claim_tag(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_id: JobId) -> anyhow::Result<Hash> {
        let value_bytes: Option<Vec<u8>> = self.qtdb_raw_kv_get_value(&tt_get_proof_claim_tag_key_from_job(rid.realm_id, rid.realm_sub_id, unique_pending_id, &job_id)).await?;
        if let Some(v) = value_bytes {
            Hash::from_slice_32bytes(&v)
        } else {
            anyhow::bail!("get_proof_claim_tag not found for job {:?} at unique_pending_id {}", job_id, unique_pending_id);
        }
    }
    async fn get_proof_claim_tag_or_none(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_id: JobId) -> anyhow::Result<Option<Hash>> {
        let value_bytes: Option<Vec<u8>> = self.qtdb_raw_kv_get_value(&tt_get_proof_claim_tag_key_from_job(rid.realm_id, rid.realm_sub_id, unique_pending_id, &job_id)).await?;
        if let Some(v) = value_bytes {
            Ok(Some(Hash::from_slice_32bytes(&v)?))
        } else {
            Ok(None)
        }
    }
}

#[async_trait]
impl<Hash: Q256BitHash, JobId: QJobIdBase + 'static, D: QTempDatabaseRawKVWriterBase + Sync> QTempDBRewardsTreeWriter<Hash, JobId> for D {
    async fn set_proof_miner_rewards_tree_value(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_id: JobId, value: Hash) -> anyhow::Result<Hash>{
        let key = tt_get_rewards_tag_tree_value_key_from_job(rid.realm_id, rid.realm_sub_id, unique_pending_id, &job_id);
        self.qtdb_raw_kv_put_value(&key, &value.into_owned_32bytes()).await?;
        Ok(value)
    }
    async fn set_proof_claim_tag(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_id: JobId, tag: Hash) -> anyhow::Result<Hash> {
        let key = tt_get_proof_claim_tag_key_from_job(rid.realm_id, rid.realm_sub_id, unique_pending_id, &job_id);
        self.qtdb_raw_kv_put_value(&key, &tag.into_owned_32bytes()).await?;
        Ok(tag)
    }
}


/*


#[async_trait]
pub trait QTempDBUserContractUpdatesReader {
    async fn get_contract_updates_for_user(&self, rid: &QRealmIdentifier, unique_pending_id: u64, user_id: u64) -> anyhow::Result<Option<Vec<u8>>>;
}

#[async_trait]
pub trait QTempDBUserContractUpdatesWriter {
    async fn set_contract_updates_for_user(&self, rid: &QRealmIdentifier, unique_pending_id: u64, user_id: u64, data: Vec<u8>) -> anyhow::Result<()>;
    async fn set_contract_updates_for_user_ref(&self, rid: &QRealmIdentifier, unique_pending_id: u64, user_id: u64, data: &[u8]) -> anyhow::Result<()>;
}
    
    */


#[async_trait]
impl<T: QTempDatabaseRawKVReaderBase + Sync> QTempDBUserContractUpdatesReader for T {
        async fn get_contract_updates_for_user(&self, rid: &QRealmIdentifier, unique_pending_id: u64, user_id: u64) -> anyhow::Result<Option<Vec<u8>>>{
            let key = tt_get_contract_updates_key(rid.realm_id, rid.realm_sub_id, unique_pending_id, user_id);
            let value_bytes = self.qtdb_raw_kv_get_value(&key).await?;
            Ok(value_bytes)
        }
}

#[async_trait]
impl<T: QTempDatabaseRawKVWriterBase + Sync> QTempDBUserContractUpdatesWriter for T {

    async fn set_contract_updates_for_user(&self, rid: &QRealmIdentifier, unique_pending_id: u64, user_id: u64, data: Vec<u8>) -> anyhow::Result<()>{
        let key = tt_get_contract_updates_key(rid.realm_id, rid.realm_sub_id, unique_pending_id, user_id);
        self.qtdb_raw_kv_put_value(&key, &data).await
    }
    async fn set_contract_updates_for_user_ref(&self, rid: &QRealmIdentifier, unique_pending_id: u64, user_id: u64, data: &[u8]) -> anyhow::Result<()> {
        let key = tt_get_contract_updates_key(rid.realm_id, rid.realm_sub_id, unique_pending_id, user_id);
        self.qtdb_raw_kv_put_value(&key, data).await
    }
}

#[async_trait]
impl<T: QTempDatabaseRawKVReaderBase + Sync> QTempDBUserEndCapSlotUpdatesReader for T {
    async fn get_user_end_cap_slot_updates(
        &self,
        rid: &QRealmIdentifier,
        unique_pending_id: u64,
        user_id: u64,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let key = tt_get_user_end_cap_slot_updates_key(
            rid.realm_id,
            rid.realm_sub_id,
            unique_pending_id,
            user_id,
        );
        self.qtdb_raw_kv_get_value(&key).await
    }
}

#[async_trait]
impl<T: QTempDatabaseRawKVWriterBase + Sync> QTempDBUserEndCapSlotUpdatesWriter for T {
    async fn set_user_end_cap_slot_updates(
        &self,
        rid: &QRealmIdentifier,
        unique_pending_id: u64,
        user_id: u64,
        data: Vec<u8>,
    ) -> anyhow::Result<()> {
        let key = tt_get_user_end_cap_slot_updates_key(
            rid.realm_id,
            rid.realm_sub_id,
            unique_pending_id,
            user_id,
        );
        self.qtdb_raw_kv_put_value(&key, &data).await
    }

    async fn set_user_end_cap_slot_updates_ref(
        &self,
        rid: &QRealmIdentifier,
        unique_pending_id: u64,
        user_id: u64,
        data: &[u8],
    ) -> anyhow::Result<()> {
        let key = tt_get_user_end_cap_slot_updates_key(
            rid.realm_id,
            rid.realm_sub_id,
            unique_pending_id,
            user_id,
        );
        self.qtdb_raw_kv_put_value(&key, data).await
    }
}

#[async_trait]
impl<JobId: QJobIdBase + 'static, D: QTempDatabaseRawKVReaderBase + Sync> QTempDBJobClaimInfoReader<JobId> for D {
    async fn get_job_claim(
        &self,
        rid: &QRealmIdentifier,
        unique_pending_id: u64,
        job_id: JobId,
    ) -> anyhow::Result<Option<WorkerJobClaim>> {
        let key = tt_get_job_claim_key_from_job(rid.realm_id, rid.realm_sub_id, unique_pending_id, &job_id);
        let value_bytes = self.qtdb_raw_kv_get_value(&key).await?;
        match value_bytes {
            Some(value) if value.len() >= 66 => {
                let mut public_key = [0u8; 33];
                public_key.copy_from_slice(&value[0..33]);
                Ok(Some(WorkerJobClaim {
                    public_key,
                    claim_time_ms: u64::from_le_bytes(value[33..41].try_into().unwrap()),
                    proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId::from_le_bytes(value[41..57].try_into().unwrap()),
                    reputation_at_claim: u64::from_le_bytes(value[57..65].try_into().unwrap()),
                    is_finalized: value[65] != 0,
                    has_reputation_update: value.get(66).is_some_and(|flag| *flag != 0),
                }))
            }
            _ => Ok(None),
        }
    }
}

#[async_trait]
impl<JobId: QJobIdBase + 'static, D: QTempDatabaseRawKVWriterBase + Sync> QTempDBJobClaimInfoWriter<JobId> for D {
    async fn set_job_claim(
        &self,
        rid: &QRealmIdentifier,
        unique_pending_id: u64,
        job_id: JobId,
        claim: &WorkerJobClaim,
    ) -> anyhow::Result<()> {
        let key = tt_get_job_claim_key_from_job(rid.realm_id, rid.realm_sub_id, unique_pending_id, &job_id);
        let mut value = [0u8; 67];
        value[0..33].copy_from_slice(&claim.public_key);
        value[33..41].copy_from_slice(&claim.claim_time_ms.to_le_bytes());
        value[41..57].copy_from_slice(&claim.proc_checkpoint_unique_id.to_le_bytes());
        value[57..65].copy_from_slice(&claim.reputation_at_claim.to_le_bytes());
        value[65] = u8::from(claim.is_finalized);
        value[66] = u8::from(claim.has_reputation_update);
        self.qtdb_raw_kv_put_value(&key, &value).await
    }
}

/// Initial reputation for new workers (no prior record). Must be positive to allow claiming.
pub const INITIAL_WORKER_REPUTATION: u64 = 5;

#[async_trait]
impl<D: QTempDatabaseRawKVReaderBase + Sync> QTempDBWorkerReputationReader for D {
    async fn get_worker_reputation(&self, rid: &QRealmIdentifier, public_key: &[u8; 33]) -> anyhow::Result<u64> {
        let key = tt_get_worker_reputation_key(rid.realm_id, rid.realm_sub_id, public_key);
        let value_bytes = self.qtdb_raw_kv_get_value(&key).await?;
        match value_bytes {
            Some(v) if v.len() >= 8 => Ok(u64::from_le_bytes(v[0..8].try_into().unwrap())),
            _ => Ok(INITIAL_WORKER_REPUTATION),
        }
    }
}

#[async_trait]
impl<D: QTempDatabaseRawWorkerReputationMutationBase + Sync> QTempDBWorkerReputationMutation for D {
    async fn apply_worker_reputation_once(
        &self,
        rid: &QRealmIdentifier,
        public_key: &[u8; 33],
        unique_pending_id: u64,
        job_id: &[u8; 24],
        on_time: bool,
        reward: u64,
        slash: u64,
        maximum: u64,
    ) -> anyhow::Result<bool> {
        let claim_key = crate::psy_temp_db::tt_get_job_claim_key_from_bytes(
            rid.realm_id,
            rid.realm_sub_id,
            unique_pending_id,
            job_id,
        );
        let reputation_key = tt_get_worker_reputation_key(rid.realm_id, rid.realm_sub_id, public_key);
        self.qtdb_raw_apply_worker_reputation_once(
            &claim_key,
            &reputation_key,
            INITIAL_WORKER_REPUTATION,
            on_time,
            reward,
            slash,
            maximum,
        )
        .await
    }
}

#[async_trait]
impl<D: QTempDatabaseRawKVWriterBase + Sync> QTempDBWorkerReputationWriter for D {
    async fn set_worker_reputation(
        &self,
        rid: &QRealmIdentifier,
        public_key: &[u8; 33],
        reputation: u64,
    ) -> anyhow::Result<()> {
        let key = tt_get_worker_reputation_key(rid.realm_id, rid.realm_sub_id, public_key);
        self.qtdb_raw_kv_put_value(&key, &reputation.to_le_bytes()).await
    }
}


#[cfg(test)]
mod tests {
    use parth_core::{
        data::hash::hash256::Hash256,
        node::realm_identifier::QRealmIdentifier,
        protocol::core_types::Q256BitHash,
    };
    use psy_core::job::job_id::{
        QJobTopic, ProvingJobCircuitType, ProvingJobDataType, QProvingJobDataID,
    };
    use crate::{
        memory_stores::simple_memory_temp_store::SimpleMemoryTempStore,
        psy_temp_db::{
            tt_get_job_claim_key_from_job, QTempDBJobClaimInfoReader, QTempDBJobClaimInfoWriter,
            QTempDBRewardsTreeReader, QTempDBRewardsTreeWriter, WorkerJobClaim,
        },
        store::traits::temp_db::QTempDatabaseRawKVWriterBase,
    };

    // Defends the checkpoint-367 contract against the proof/reward namespace corruption:
    // for one realm/pending/job-id, a worker's proof claim-tag and the finalized
    // reward-tree value MUST live in distinct KV namespaces, and the blanket reward-trait
    // impls must route claim reads/writes to the claim-tag key and reward reads/writes to
    // the reward-tree key. If the namespaces alias (or a reader uses the wrong key), setting
    // the final reward would overwrite the claim tag and/or the claim getter would read back
    // the reward value. This exercises the real in-memory KV store through the real blanket
    // traits — not the key functions in isolation — so it reddens on any wrong-key routing.
    #[tokio::test]
    async fn proof_claim_tag_and_final_reward_do_not_alias_in_kv_store() {
        let store = SimpleMemoryTempStore::new();
        let rid = QRealmIdentifier::new(0x0a0b_0c0d, 0x0e0f);
        let unique_pending_id: u64 = 0x1122_3344_5566_7788;

        // Fixed, reproducible job id using a real QJobIdBase type (not raw bytes), so the
        // blanket reward-trait impls (which require JobId: QJobIdBase) are exercised exactly
        // as production calls them.
        let job_id = QProvingJobDataID {
            topic: QJobTopic::GenerateStandardProof,
            goal_id: 0x1122_3344_5566_7788,
            circuit_type: ProvingJobCircuitType::BatchDeployContractsAggregate,
            group_id: 0x1122_3344,
            sub_group_id: 0x5566_7788,
            task_index: 0x99aa_bbcc,
            data_type: ProvingJobDataType::StandardProof,
            data_index: 0x01,
        };

        // Distinct 32-byte values so a value collision can never mask a key alias.
        let claim_tag = Hash256([0x11u8; 32]);
        let final_reward = Hash256([0x22u8; 32]);
        assert_ne!(
            claim_tag.into_owned_32bytes(),
            final_reward.into_owned_32bytes()
        );

        // 1. Record the worker's claim tag.
        let written_tag = store
            .set_proof_claim_tag(&rid, unique_pending_id, job_id, claim_tag)
            .await
            .unwrap();
        assert_eq!(
            written_tag.into_owned_32bytes(),
            claim_tag.into_owned_32bytes()
        );

        // 2. Claim is readable; finalized reward is still absent. If the reward reader used
        //    the claim-tag key it would return Some(claim_tag) here instead of None.
        assert_eq!(
            store
                .get_proof_claim_tag_or_none(&rid, unique_pending_id, job_id)
                .await
                .unwrap()
                .map(|h: Hash256| h.into_owned_32bytes()),
            Some(claim_tag.into_owned_32bytes())
        );
        let reward_before_finalize: Option<Hash256> = store
            .get_proof_miner_rewards_tree_value_or_none(&rid, unique_pending_id, job_id)
            .await
            .unwrap();
        assert!(reward_before_finalize.is_none());

        // 3. Record the finalized reward.
        let written_reward = store
            .set_proof_miner_rewards_tree_value(&rid, unique_pending_id, job_id, final_reward)
            .await
            .unwrap();
        assert_eq!(
            written_reward.into_owned_32bytes(),
            final_reward.into_owned_32bytes()
        );

        // 4. Finalized reward is readable under the reward key.
        assert_eq!(
            store
                .get_proof_miner_rewards_tree_value_or_none(&rid, unique_pending_id, job_id)
                .await
                .unwrap()
                .map(|h: Hash256| h.into_owned_32bytes()),
            Some(final_reward.into_owned_32bytes())
        );

        // 5. The claim tag survives setting the reward (no namespace aliasing), and the
        //    strict claim getter still returns the claim rather than the reward value —
        //    proving claim reads never hit the reward key. If set_proof_miner_rewards_tree_value
        //    wrote the claim-tag key, the claim read here would yield final_reward instead.
        assert_eq!(
            store
                .get_proof_claim_tag_or_none(&rid, unique_pending_id, job_id)
                .await
                .unwrap()
                .map(|h: Hash256| h.into_owned_32bytes()),
            Some(claim_tag.into_owned_32bytes())
        );
        let claim_roundtrip: Hash256 = store
            .get_proof_claim_tag(&rid, unique_pending_id, job_id)
            .await
            .unwrap();
        assert_eq!(
            claim_roundtrip.into_owned_32bytes(),
            claim_tag.into_owned_32bytes()
        );
    }
    // Fixed, reproducible job id using a real QJobIdBase type (not raw bytes), so the
    // blanket reward-trait impls (which require JobId: QJobIdBase) are exercised exactly
    // as production calls them. Distinct from the inline construction in the aliasing test
    // above to keep that test self-contained.
    fn sample_job_id() -> QProvingJobDataID {
        QProvingJobDataID {
            topic: QJobTopic::GenerateStandardProof,
            goal_id: 0x1122_3344_5566_7788,
            circuit_type: ProvingJobCircuitType::BatchDeployContractsAggregate,
            group_id: 0x1122_3344,
            sub_group_id: 0x5566_7788,
            task_index: 0x99aa_bbcc,
            data_type: ProvingJobDataType::StandardProof,
            data_index: 0x01,
        }
    }

    // Claim tag survives an independent final-reward write to the same job. Defends the
    // forward direction of the checkpoint-367 contract: set_proof_miner_rewards_tree_value
    // must NOT write the claim-tag key. If it did (or the claim getter read the reward
    // key), the subsequent claim read would return the reward value instead of the claim.
    #[tokio::test]
    async fn claim_tag_survives_independent_final_reward_write() {
        let store = SimpleMemoryTempStore::new();
        let rid = QRealmIdentifier::new(0x0a0b_0c0d, 0x0e0f);
        let unique_pending_id: u64 = 0x1122_3344_5566_7788;
        let job_id = sample_job_id();

        let claim_tag = Hash256([0x11u8; 32]);
        let final_reward = Hash256([0x22u8; 32]);

        store
            .set_proof_claim_tag(&rid, unique_pending_id, job_id, claim_tag)
            .await
            .unwrap();
        store
            .set_proof_miner_rewards_tree_value(&rid, unique_pending_id, job_id, final_reward)
            .await
            .unwrap();

        // The claim must still read back as the original claim, not the reward. The _or_none
        // and strict getters both read the claim key; either would yield final_reward if the
        // reward write aliased the claim key.
        assert_eq!(
            store
                .get_proof_claim_tag_or_none(&rid, unique_pending_id, job_id)
                .await
                .unwrap()
                .map(|h: Hash256| h.into_owned_32bytes()),
            Some(claim_tag.into_owned_32bytes())
        );
        let claim_roundtrip: Hash256 = store
            .get_proof_claim_tag(&rid, unique_pending_id, job_id)
            .await
            .unwrap();
        assert_eq!(
            claim_roundtrip.into_owned_32bytes(),
            claim_tag.into_owned_32bytes()
        );
    }

    // Final reward survives an independent claim-tag write to the same job. Defends the
    // REVERSE direction: set_proof_claim_tag must NOT write the reward key. If it did (or
    // the reward getter read the claim key), the subsequent reward read would return the
    // claim value instead of the finalized reward.
    #[tokio::test]
    async fn final_reward_survives_independent_claim_tag_write() {
        let store = SimpleMemoryTempStore::new();
        let rid = QRealmIdentifier::new(0x0a0b_0c0d, 0x0e0f);
        let unique_pending_id: u64 = 0x1122_3344_5566_7788;
        let job_id = sample_job_id();

        let final_reward = Hash256([0x22u8; 32]);
        let claim_tag = Hash256([0x11u8; 32]);

        store
            .set_proof_miner_rewards_tree_value(&rid, unique_pending_id, job_id, final_reward)
            .await
            .unwrap();
        store
            .set_proof_claim_tag(&rid, unique_pending_id, job_id, claim_tag)
            .await
            .unwrap();

        // The reward must still read back as the finalized reward, not the claim.
        assert_eq!(
            store
                .get_proof_miner_rewards_tree_value_or_none(&rid, unique_pending_id, job_id)
                .await
                .unwrap()
                .map(|h: Hash256| h.into_owned_32bytes()),
            Some(final_reward.into_owned_32bytes())
        );
    }

    // get_proof_claim_tag_or_none reads the claim key, not the reward key. When only a
    // finalized reward is written (no claim recorded), the claim _or_none getter MUST
    // return None — not the reward value. If the claim getter used the reward key it would
    // return Some(final_reward) here, masking the missing claim as a present claim.
    #[tokio::test]
    async fn get_proof_claim_tag_or_none_is_none_when_only_final_reward_written() {
        let store = SimpleMemoryTempStore::new();
        let rid = QRealmIdentifier::new(0x0a0b_0c0d, 0x0e0f);
        let unique_pending_id: u64 = 0x1122_3344_5566_7788;
        let job_id = sample_job_id();

        let final_reward = Hash256([0x22u8; 32]);

        store
            .set_proof_miner_rewards_tree_value(&rid, unique_pending_id, job_id, final_reward)
            .await
            .unwrap();
        // Reward is present under the reward key...
        assert_eq!(
            store
                .get_proof_miner_rewards_tree_value_or_none(&rid, unique_pending_id, job_id)
                .await
                .unwrap()
                .map(|h: Hash256| h.into_owned_32bytes()),
            Some(final_reward.into_owned_32bytes())
        );
        // ...but the claim getter must read None from the (empty) claim namespace, NOT the
        // reward value.
        assert_eq!(
            store
                .get_proof_claim_tag_or_none(&rid, unique_pending_id, job_id)
                .await
                .unwrap()
                .map(|h: Hash256| h.into_owned_32bytes()),
            None
        );
    }

    #[tokio::test]
    async fn legacy_worker_job_claim_defaults_reputation_marker_to_false() {
        let store = SimpleMemoryTempStore::new();
        let rid = QRealmIdentifier::new(7, 11);
        let unique_pending_id = 13;
        let job_id = sample_job_id();
        let key = tt_get_job_claim_key_from_job(rid.realm_id, rid.realm_sub_id, unique_pending_id, &job_id);
        let mut value = [0u8; 66];
        value[0..33].copy_from_slice(&[2; 33]);
        value[33..41].copy_from_slice(&17u64.to_le_bytes());
        value[41..57].copy_from_slice(&19u128.to_le_bytes());
        value[57..65].copy_from_slice(&23u64.to_le_bytes());
        value[65] = 1;
        store.qtdb_raw_kv_put_value(&key, &value).await.unwrap();

        assert_eq!(
            store.get_job_claim(&rid, unique_pending_id, job_id).await.unwrap(),
            Some(WorkerJobClaim {
                public_key: [2; 33],
                claim_time_ms: 17,
                proc_checkpoint_unique_id: 19,
                reputation_at_claim: 23,
                is_finalized: true,
                has_reputation_update: false,
            })
        );
    }
    #[tokio::test]
    async fn worker_job_claim_roundtrip_preserves_queue_and_finalization_state() {
        let store = SimpleMemoryTempStore::new();
        let rid = QRealmIdentifier::new(7, 11);
        let unique_pending_id = 13;
        let job_id = sample_job_id();
        let claim = WorkerJobClaim {
            public_key: [2; 33],
            claim_time_ms: 17,
            proc_checkpoint_unique_id: 19,
            reputation_at_claim: 23,
            is_finalized: false,
            has_reputation_update: true,
        };

        store
            .set_job_claim(&rid, unique_pending_id, job_id, &claim)
            .await
            .unwrap();
        assert_eq!(
            store
                .get_job_claim(&rid, unique_pending_id, job_id)
                .await
                .unwrap(),
            Some(claim)
        );

        let finalized = WorkerJobClaim {
            is_finalized: true,
            ..claim
        };
        store
            .set_job_claim(&rid, unique_pending_id, job_id, &finalized)
            .await
            .unwrap();
        assert_eq!(
            store
                .get_job_claim(&rid, unique_pending_id, job_id)
                .await
                .unwrap(),
            Some(finalized)
        );
    }

}
