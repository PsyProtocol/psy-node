use async_trait::async_trait;
use parth_core::{data::serializable::QPDPair, pgoldilocks::QHashOut};
use plonky2::plonk::{circuit_data::{CommonCircuitData, VerifierOnlyCircuitData}, config::GenericConfig, proof::ProofWithPublicInputs};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use serde::{de::DeserializeOwned, Serialize};


pub trait QProofStoreReaderSync {
    fn get_proof_by_id<C: GenericConfig<D>, const D: usize>(
        &self,
        id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
    fn get_bytes_by_id(&self, id: QProvingJobDataID) -> anyhow::Result<Vec<u8>>;
    fn get_goal_by_job_id(&self, id: QProvingJobDataID) -> anyhow::Result<u32> {
        let counter_id = id.get_sub_group_counter_id();
        let goal_id = counter_id.get_sub_group_counter_goal_id();
        //tracing::info!("goal_id: {:?}", goal_id);
        let goal = self.get_bytes_by_id(goal_id)?;
        Ok(u32::from_le_bytes(goal.try_into().unwrap()))
    }
    fn get_next_jobs_by_job_id(
        &self,
        id: QProvingJobDataID,
    ) -> anyhow::Result<Vec<QProvingJobDataID>> {
        let counter_id = id.get_sub_group_counter_id();
        let next_jobs_id = counter_id.get_sub_group_counter_goal_next_jobs_id();
        let next_jobs = self.get_bytes_by_id(next_jobs_id)?;
        Ok(bincode::deserialize(&next_jobs)?)
    }
}

pub trait QProofStoreWriterSync {
    fn set_proof_by_id<C: GenericConfig<D>, const D: usize>(
        &mut self,
        id: QProvingJobDataID,
        proof: &ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<()>;
    fn set_bytes_by_id(&mut self, id: QProvingJobDataID, data: &[u8]) -> anyhow::Result<()>;

    fn inc_counter_by_id(&mut self, id: QProvingJobDataID) -> anyhow::Result<u32>;
    fn write_next_jobs(
        &mut self,
        jobs: &[QProvingJobDataID],
        next_jobs: &[QProvingJobDataID],
    ) -> anyhow::Result<()>;
    fn write_next_jobs_core(
        &mut self,
        jobs: &[QProvingJobDataID],
        next_jobs: &[QProvingJobDataID],
    ) -> anyhow::Result<()> {
        let counter_id = jobs[0].get_sub_group_counter_id();
        let goal_id = counter_id.get_sub_group_counter_goal_id();
        let next_jobs_id = counter_id.get_sub_group_counter_goal_next_jobs_id();
        self.set_bytes_by_id(counter_id, &u32::to_le_bytes(0))?;
        self.set_bytes_by_id(goal_id, &u32::to_le_bytes(jobs.len() as u32))?;
        self.set_bytes_by_id(next_jobs_id, &bincode::serialize(next_jobs)?)?;
        Ok(())
    }

    fn write_multidimensional_jobs(
        &mut self,
        jobs_levels: &[Vec<QProvingJobDataID>],
        next_jobs: &[QProvingJobDataID],
    ) -> anyhow::Result<()>;
    fn write_multidimensional_jobs_core(
        &mut self,
        jobs_levels: &[Vec<QProvingJobDataID>],
        next_jobs: &[QProvingJobDataID],
    ) -> anyhow::Result<()> {
        let job_levels_count = jobs_levels.len();
        for i in 0..job_levels_count {
            let counter_id = jobs_levels[i][0].get_sub_group_counter_id();
            let goal_id = counter_id.get_sub_group_counter_goal_id();
            let next_jobs_id = counter_id.get_sub_group_counter_goal_next_jobs_id();
            self.set_bytes_by_id(counter_id, &u32::to_le_bytes(0))?;
            self.set_bytes_by_id(goal_id, &u32::to_le_bytes(jobs_levels[i].len() as u32))?;
            self.set_bytes_by_id(
                next_jobs_id,
                &bincode::serialize(if i == (job_levels_count - 1) {
                    next_jobs
                } else {
                    &jobs_levels[i + 1]
                })?,
            )?;
        }
        Ok(())
    }
}

pub trait QProofStoreWriterSyncImm {
    fn set_proof_by_id_imm<C: GenericConfig<D>, const D: usize>(
        &self,
        id: QProvingJobDataID,
        proof: &ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<()>;
    fn set_bytes_by_id_imm(&self, id: QProvingJobDataID, data: &[u8]) -> anyhow::Result<()>;

    fn inc_counter_by_id_imm(&self, id: QProvingJobDataID) -> anyhow::Result<u32>;
    fn write_next_jobs_imm(
        &self,
        jobs: &[QProvingJobDataID],
        next_jobs: &[QProvingJobDataID],
    ) -> anyhow::Result<()>;
    fn write_next_jobs_core_imm(
        &self,
        jobs: &[QProvingJobDataID],
        next_jobs: &[QProvingJobDataID],
    ) -> anyhow::Result<()> {
        let counter_id = jobs[0].get_sub_group_counter_id();
        let goal_id = counter_id.get_sub_group_counter_goal_id();
        let next_jobs_id = counter_id.get_sub_group_counter_goal_next_jobs_id();
        self.set_bytes_by_id_imm(counter_id, &u32::to_le_bytes(0))?;
        self.set_bytes_by_id_imm(goal_id, &u32::to_le_bytes(jobs.len() as u32))?;
        self.set_bytes_by_id_imm(next_jobs_id, &bincode::serialize(next_jobs)?)?;
        Ok(())
    }

    fn write_multidimensional_jobs_imm(
        &self,
        jobs_levels: &[Vec<QProvingJobDataID>],
        next_jobs: &[QProvingJobDataID],
    ) -> anyhow::Result<()>;
    fn write_multidimensional_jobs_core_imm(
        &self,
        jobs_levels: &[Vec<QProvingJobDataID>],
        next_jobs: &[QProvingJobDataID],
    ) -> anyhow::Result<()> {
        let job_levels_count = jobs_levels.len();
        for i in 0..job_levels_count {
            let counter_id = jobs_levels[i][0].get_sub_group_counter_id();
            let goal_id = counter_id.get_sub_group_counter_goal_id();
            let next_jobs_id = counter_id.get_sub_group_counter_goal_next_jobs_id();
            self.set_bytes_by_id_imm(counter_id, &u32::to_le_bytes(0))?;
            self.set_bytes_by_id_imm(goal_id, &u32::to_le_bytes(jobs_levels[i].len() as u32))?;
            self.set_bytes_by_id_imm(
                next_jobs_id,
                &bincode::serialize(if i == (job_levels_count - 1) {
                    next_jobs
                } else {
                    &jobs_levels[i + 1]
                })?,
            )?;
        }
        Ok(())
    }
}



pub trait QProofStore: QProofStoreReaderSync + QProofStoreWriterSync {

}

impl<T: QProofStoreReaderSync + QProofStoreWriterSync> QProofStore for T {}

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

    async fn get_public_input_by_id<C: GenericConfig<D>, const D: usize>(
        &self,
        id: QProvingJobDataID,
    ) -> anyhow::Result<Vec<C::F>>;
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

    async fn set_bytes_by_id_batch(&self, kv_pairs: &[QPDPair<QProvingJobDataID, Vec<u8>>]) -> anyhow::Result<()>;
    async fn set_bytes_by_id_batch_core(&self, kv_pairs: &[QPDPair<QProvingJobDataID, Vec<u8>>]) -> anyhow::Result<()> {
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

    async fn cleanup_old_proofs(&self, current_height: u64, keep_blocks: u64) -> anyhow::Result<()>;
}


pub trait QProofStoreAsyncImm: QProofStoreReaderAsync + QProofStoreWriterAsyncImm {

}

impl<T: QProofStoreReaderAsync + QProofStoreWriterAsyncImm> QProofStoreAsyncImm for T {}

#[async_trait]
pub trait QWorkerGenericProverAsyncMut<S: QProofStoreReaderAsync, C: GenericConfig<D>, const D: usize>:
    QWorkerVerifyHelper<C, D>
{
    async fn worker_prove_mut(
        &mut self,
        store: &S,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
}


pub trait QWorkerGenericProverMut<S: QProofStoreReaderSync, C: GenericConfig<D>, const D: usize>:
    QWorkerVerifyHelper<C, D>
{
    fn worker_prove_mut(
        &mut self,
        store: &S,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
}


pub trait QWorkerVerifyHelper<C: GenericConfig<D>, const D: usize> {
    fn get_verifier_triplet_for_circuit_type(
        &self,
        circuit_type: ProvingJobCircuitType,
    ) -> (
        &CommonCircuitData<C::F, D>,
        &VerifierOnlyCircuitData<C, D>,
        QHashOut<C::F>,
    );
}

pub trait QWorkerCircuitSimpleWithDataSync<
    V: QWorkerVerifyHelper<C, D>,
    S: QProofStoreReaderSync,
    I: DeserializeOwned + Serialize + Clone,
    C: GenericConfig<D>,
    const D: usize,
>
{
    fn prove_q_worker_simple(
        &self,
        verify_helper: &V,
        store: &S,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
}
pub trait QWorkerCircuitStandardWithDataSync<
    V: QWorkerVerifyHelper<C, D>,
    S: QProofStoreReaderSync,
    I: DeserializeOwned + Serialize + Clone,
    C: GenericConfig<D>,
    const D: usize,
>
{
    fn prove_q_worker_standard_with_input(
        &self,
        input: &I,
        verify_helper: &V,
        store: &S,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
    fn prove_q_worker_standard(
        &self,
        verify_helper: &V,
        store: &S,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let witness_data = store.get_bytes_by_id(job_id)?;
        let input = bincode::deserialize(&witness_data)?;
        self.prove_q_worker_standard_with_input(&input, verify_helper, store, job_id)
    }
}
pub trait QWorkerCircuitAggWithDataSync<
    V: QWorkerVerifyHelper<C, D>,
    S: QProofStoreReaderSync,
    I: DeserializeOwned + Serialize + Clone,
    C: GenericConfig<D>,
    const D: usize,
>
{
    fn prove_q_worker_agg(
        &self,
        verify_helper: &V,
        store: &S,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
}

pub trait QWorkerCircuitCustomWithDataSync<
    V: QWorkerVerifyHelper<C, D>,
    S: QProofStoreReaderSync,
    C: GenericConfig<D>,
    const D: usize,
>
{
    fn prove_q_worker_custom(
        &self,
        verify_helper: &V,
        store: &S,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
}
pub trait QWorkerCircuitCompressWithDataSync<S: QProofStoreReaderSync> {
    fn prove_q_worker_compress(
        &self,
        store: &S,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<String>;
}
pub trait QWorkerCircuitMutCustomWithDataSync<
    S: QProofStoreReaderSync,
    C: GenericConfig<D>,
    const D: usize,
>
{
    fn prove_q_worker_mut_custom(
        &mut self,
        store: &S,
        job_id: QProvingJobDataID,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
}
