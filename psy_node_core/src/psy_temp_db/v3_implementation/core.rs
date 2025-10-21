use async_trait::async_trait;
use parth_core::{
    node::realm_identifier::QRealmIdentifier, protocol::core_types::QDBHashBase, QCoreProcCheckpointUniqueId, QJobIdBase, QJOB_ID_SERIALIZED_SIZE,
};

use crate::{
    psy_temp_db::{
        tt_get_expected_public_inputs_key, tt_get_expected_public_inputs_key_from_job, tt_get_submit_status_key, tt_get_unique_pending_id_key,
        QTempDBExpectedPublicInputsReader, QTempDBExpectedPublicInputsWriter, QTempDBPendingIdReader, QTempDBPendingIdWriter,
        QTempDBSubmitStatusReader, QTempDBSubmitStatusWriter, TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_KEY_SIZE,
        TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_VALUE_SIZE,
    },
    store::traits::temp_db::{QTempDatabaseRawKVReaderBase, QTempDatabaseRawKVWriterBase},
};
/*


let key = tt_get_unique_pending_id_key(rid.realm_id, rid.realm_sub_id);
let mut value = [u8; 24];
value[0..8].copy_from_slice(&unique_pending_id.to_le_bytes());
value[8..24].copy_from_slice(&proc_checkpoint_unique_id.to_le_bytes());
self.(&key, &value).await
*/
#[async_trait]
impl<T: QTempDatabaseRawKVReaderBase + Sync + Send, JobId: QJobIdBase + Sync + Send + 'static, Hash: QDBHashBase + Sync + Send>
    QTempDBExpectedPublicInputsReader<JobId, Hash> for T
{
    async fn get_expected_public_inputs_hash(&self, rid: &QRealmIdentifier, unique_pending_id: u64, job_id: JobId) -> anyhow::Result<Hash> {
        let key = tt_get_expected_public_inputs_key_from_job(rid.realm_id as u32, rid.realm_sub_id as u16, unique_pending_id, &job_id);
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
        let key = tt_get_expected_public_inputs_key_from_job(rid.realm_id as u32, rid.realm_sub_id as u16, unique_pending_id, &job_id);
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
            let key = tt_get_expected_public_inputs_key(rid.realm_id, rid.realm_sub_id, unique_pending_id, &job_id_bytes.try_into().unwrap());
            entries.push((key.to_vec(), value_bytes.to_vec()));
        }

        self.qtdb_raw_kv_put_many_values_tuple(&entries).await?;
        /*
        let num_entries = data_len / combined_size;
        let combined_size = TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_KEY_SIZE + TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_VALUE_SIZE;
        let data_len = data.len();
        if data_len % combined_size != 0 {
            return Err(anyhow::anyhow!("Data length is not a multiple of combined key and value size"));
        }
        if data_len == 0 {
            return Ok(());
        }
        let template = tt_get_expected_public_inputs_key(rid.realm_id, rid.realm_sub_id, unique_pending_id, &[0u8; QJOB_ID_SERIALIZED_SIZE]);

        const BATCH_SIZE: usize = 512;
        const BUFFER_SIZE: usize = BATCH_SIZE * TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_KEY_SIZE;
        const

        if num_entries < BATCH_SIZE {
            let mut keys = Vec::with_capacity(num_entries);
            let mut entries = Vec::with_capacity(num_entries);

            for i in 0..num_entries {

                let idx = i * (QJOB_ID_SERIALIZED_SIZE + TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_VALUE_SIZE);
                let job_id_bytes = &data[idx..(idx+TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_KEY_SIZE - 40 + QJOB_ID_SERIALIZED_SIZE)];
                let mut key = template;
                key[16..40].copy_from_slice(job_id_bytes);
                let value = &data[(idx+TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_KEY_SIZE)..(idx+TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_KEY_SIZE+TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_VALUE_SIZE)];
                entries.push(((key.as_ref(),value)));
            }
            self.qtdb_raw_kv_put_many_values_tuple_ref(&entries).await?;
            return Ok(());
        }
        let buffer = [0u8; BUFFER_SIZE];

        let num_entries = data_len / combined_size;
        let mut entries = Vec::with_capacity(num_entries);
        for i in 0..num_entries {
            let idx = i * (TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_KEY_SIZE + TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_VALUE_SIZE);
            let key = &data[idx..(idx+TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_KEY_SIZE)];
            let value = &data[(idx+TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_KEY_SIZE)..(idx+TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_KEY_SIZE+TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_VALUE_SIZE)];
            entries.push(((key,value)));
        }
        self.qtdb_raw_kv_put_many_values_tuple_ref(&entries).await?;
        */
        /*
        let combined_size = TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_KEY_SIZE + TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_VALUE_SIZE;
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
            let idx = i * (TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_KEY_SIZE + TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_VALUE_SIZE);
            let key = &data[idx..(idx+TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_KEY_SIZE)];
            let value = &data[(idx+TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_KEY_SIZE)..(idx+TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_KEY_SIZE+TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_VALUE_SIZE)];
            entries.push(((key,value)));
        }
        self.qtdb_raw_kv_put_many_values_tuple_ref(&entries).await?;
        Ok(())
        */

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
            anyhow::bail!("Submitted status not found");
        }
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
