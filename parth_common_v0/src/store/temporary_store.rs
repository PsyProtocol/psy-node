use async_trait::async_trait;

use crate::data::serializable::{QPDPair, QPDSerializable};
/*


#[async_trait]
pub trait QProofStoreReaderAsync {
    async fn get_proof_by_id<C: GenericConfig<D>, const D: usize>(
        &self,
        id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
    async fn get_bytes_by_id(&self, id: QProvingJobDataID) -> anyhow::Result<Vec<u8>>;
    async fn contains_id(&self, id: QProvingJobDataID) -> anyhow::Result<bool>;
    async fn get_obj_by_id<T: DeserializeOwned>(&self, id: QProvingJobDataID) -> anyhow::Result<T> {

        bincode::deserialize::<T>(&self.get_bytes_by_id(id).await?).map_err(|e| anyhow::anyhow!(e))

    }
    async fn get_goal_by_job_id(&self, id: QProvingJobDataID) -> anyhow::Result<u32> {
        let counter_id = id.get_sub_group_counter_id();
        let goal_id = counter_id.get_sub_group_counter_goal_id();
        //tracing::info!("goal_id: {:?}", goal_id);
        let goal = self.get_bytes_by_id(goal_id).await?;
        Ok(u32::from_le_bytes(goal.try_into().unwrap()))
    }
    async fn get_next_jobs_by_job_id(
        &self,
        id: QProvingJobDataID,
    ) -> anyhow::Result<Vec<QProvingJobDataID>> {
        let counter_id = id.get_sub_group_counter_id();
        let next_jobs_id = counter_id.get_sub_group_counter_goal_next_jobs_id();
        let next_jobs = self.get_bytes_by_id(next_jobs_id).await?;
        Ok(bincode::deserialize(&next_jobs)?)
    }

}

#[async_trait]
pub trait QProofStoreWriterAsyncImm: Send + Sync {


    async fn set_obj_by_id<T: Serialize + Send + Sync>(&self, id: QProvingJobDataID, obj: &T) -> anyhow::Result<()> {
        let bytes = bincode::serialize::<T>(&obj).map_err(|e| anyhow::anyhow!(e))?;
        self.set_bytes_by_id(id, &bytes).await?;
        Ok(())
    }

    async fn set_proof_by_id<C: GenericConfig<D>, const D: usize>(
        &self,
        id: QProvingJobDataID,
        proof: &ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<()>;
    async fn set_bytes_by_id(&self, id: QProvingJobDataID, data: &[u8]) -> anyhow::Result<()>;

    async fn set_bytes_by_id_batch(&self, kv_pairs: &[KVQPair<QProvingJobDataID, Vec<u8>>]) -> anyhow::Result<()>;
    async fn set_bytes_by_id_batch_core(&self, kv_pairs: &[KVQPair<QProvingJobDataID, Vec<u8>>]) -> anyhow::Result<()> {
        for kv in kv_pairs.iter() {
            self.set_bytes_by_id(kv.key, &kv.value).await?;
        }
        Ok(())
    }

    async fn inc_counter_by_id(&self, id: QProvingJobDataID) -> anyhow::Result<u32>;
    async fn write_next_jobs(
        &self,
        jobs: &[QProvingJobDataID],
        next_jobs: &[QProvingJobDataID],
    ) -> anyhow::Result<()>;
    async fn write_next_jobs_core(
        &self,
        jobs: &[QProvingJobDataID],
        next_jobs: &[QProvingJobDataID],
    ) -> anyhow::Result<()> {
        let counter_id = jobs[0].get_sub_group_counter_id();
        let goal_id = counter_id.get_sub_group_counter_goal_id();
        let next_jobs_id = counter_id.get_sub_group_counter_goal_next_jobs_id();
        self.set_bytes_by_id(counter_id, &u32::to_le_bytes(0)).await?;
        self.set_bytes_by_id(goal_id, &u32::to_le_bytes(jobs.len() as u32)).await?;
        self.set_bytes_by_id(next_jobs_id, &bincode::serialize(next_jobs)?).await?;
        Ok(())
    }

    async fn write_multidimensional_jobs(
        &self,
        jobs_levels: &[Vec<QProvingJobDataID>],
        next_jobs: &[QProvingJobDataID],
    ) -> anyhow::Result<()>;
    async fn write_multidimensional_jobs_core(
        &self,
        jobs_levels: &[Vec<QProvingJobDataID>],
        next_jobs: &[QProvingJobDataID],
    ) -> anyhow::Result<()> {
        let job_levels_count = jobs_levels.len();
        for i in 0..job_levels_count {
            let counter_id = jobs_levels[i][0].get_sub_group_counter_id();
            let goal_id = counter_id.get_sub_group_counter_goal_id();
            let next_jobs_id = counter_id.get_sub_group_counter_goal_next_jobs_id();
            self.set_bytes_by_id(counter_id, &u32::to_le_bytes(0)).await?;
            self.set_bytes_by_id(goal_id, &u32::to_le_bytes(jobs_levels[i].len() as u32)).await?;
            self.set_bytes_by_id(
                next_jobs_id,
                &bincode::serialize(if i == (job_levels_count - 1) {
                    next_jobs
                } else {
                    &jobs_levels[i + 1]
                })?,
            ).await?;
        }
        Ok(())
    }
}


pub trait QProofStoreAsyncImm: QProofStoreReaderAsync + QProofStoreWriterAsyncImm {

}

*/
#[async_trait]
pub trait QPTemporaryStoreReader {
    async fn contains_key(&self, key: &[u8]) -> anyhow::Result<bool>;
    async fn get_bytes(&self, key: &[u8]) -> anyhow::Result<Vec<u8>>;
    async fn get_bytes_batch(&self, keys: &[Vec<u8>]) -> anyhow::Result<Vec<Vec<u8>>>;
    async fn get_counter_by_key(&self, key: &[u8]) -> anyhow::Result<u64>;


    async fn get_bytes_by_qp_key<K: QPDSerializable + Sync + Send>(&self, key: K) -> anyhow::Result<Vec<u8>> {
        let key_bytes = key.to_bytes()?;
        self.get_bytes(&key_bytes).await
    }
    async fn get_obj_by_qp_key<K: QPDSerializable + Sync + Send, V: QPDSerializable + Sync + Send>(&self, key: K) -> anyhow::Result<V> {
        let key_bytes = key.to_bytes()?;
        let data = self.get_bytes(&key_bytes).await?;
        Ok(V::from_bytes(&data).map_err(|e| anyhow::anyhow!(e))?)
    }
    async fn get_counter_by_qp_key<K: QPDSerializable + Sync + Send>(&self, key: K) -> anyhow::Result<u64> {
        let key_bytes = key.to_bytes()?;
        self.get_counter_by_key(&key_bytes).await
    }
}


#[async_trait]
pub trait QPTemporaryStoreWriter {
    async fn delete_key(&self, key: &[u8]) -> anyhow::Result<()>;
    async fn set_bytes(&self, key: Vec<u8>, value: Vec<u8>) -> anyhow::Result<()>;
    async fn set_bytes_ref(&self, key: &[u8], value: &[u8]) -> anyhow::Result<()>;
    async fn set_bytes_batch(&self, items: Vec<QPDPair<Vec<u8>, Vec<u8>>>) -> anyhow::Result<()>;
    async fn set_counter_by_key(&self, key: &[u8], value: u64) -> anyhow::Result<()>;
    async fn inc_counter_by_key(&self, key: &[u8]) -> anyhow::Result<u64>;
}

pub trait QPTemporaryStore: QPTemporaryStoreReader + QPTemporaryStoreWriter {}
impl<T: QPTemporaryStoreReader + QPTemporaryStoreWriter> QPTemporaryStore for T {}