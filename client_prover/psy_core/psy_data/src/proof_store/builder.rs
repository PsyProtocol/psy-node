use std::collections::HashMap;

use kvq::traits::KVQPair;
use plonky2::plonk::{config::GenericConfig, proof::ProofWithPublicInputs};
use psy_client_common::job::{
    id::QProvingJobDataID,
    traits::{QProofStoreReaderAsync, QProofStoreReaderSync, QProofStoreWriterAsyncImm, QProofStoreWriterSync},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStoreBuilder {
    pub kvs: Vec<KVQPair<QProvingJobDataID, Vec<u8>>>,
    pub key_pos: HashMap<QProvingJobDataID, usize>,
    pub queue_pusher: Vec<QProvingJobDataID>,
}

impl ProofStoreBuilder {
    pub fn new() -> Self {
        Self {
            kvs: Vec::new(),
            key_pos: HashMap::new(),
            queue_pusher: Vec::new(),
        }
    }
    pub fn to_serialized_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|err| anyhow::anyhow!("{}", err))
    }
    pub fn from_serialized_bytes(data: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(data).map_err(|err| anyhow::anyhow!("{}", err))
    }
    pub async fn dump_to_async_store<PS: QProofStoreWriterAsyncImm + QProofStoreReaderAsync>(self, store: &PS) -> anyhow::Result<()> {
        store.set_bytes_by_id_batch(&self.kvs).await?;
        Ok(())
    }

    pub fn push_proving_queue(&mut self, job_id: QProvingJobDataID) -> anyhow::Result<()> {
        self.queue_pusher.push(job_id);
        Ok(())
    }
    pub fn push_proving_queue_bash(&mut self, job_ids: &[QProvingJobDataID]) -> anyhow::Result<()> {
        self.queue_pusher.extend_from_slice(job_ids);
        Ok(())
    }
    pub fn drain_queue(&mut self) -> Vec<QProvingJobDataID> {
        self.queue_pusher.drain(..).collect()
    }
}

impl QProofStoreReaderSync for ProofStoreBuilder {
    fn get_proof_by_id<C: GenericConfig<D>, const D: usize>(&self, id: QProvingJobDataID) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        match self.key_pos.get(&id) {
            Some(index) => Ok(bincode::deserialize(&self.kvs[*index].value)?),
            None => anyhow::bail!(
                "Proof not found. Wanted {}, Have: {:?}",
                hex::encode(id.to_fixed_bytes()),
                self.key_pos.keys().map(|k| hex::encode(k.to_fixed_bytes())).collect::<Vec<String>>()
            ),
        }
    }

    fn get_bytes_by_id(&self, id: QProvingJobDataID) -> anyhow::Result<Vec<u8>> {
        match self.key_pos.get(&id) {
            Some(index) => Ok(self.kvs[*index].value.to_vec()),
            None => anyhow::bail!(
                "Proof not found. Wanted {}, Have: {:?}",
                hex::encode(id.to_fixed_bytes()),
                self.key_pos.keys().map(|k| hex::encode(k.to_fixed_bytes())).collect::<Vec<String>>()
            ),
        }
    }
}

impl QProofStoreWriterSync for ProofStoreBuilder {
    fn set_proof_by_id<C: GenericConfig<D>, const D: usize>(
        &mut self,
        id: QProvingJobDataID,
        proof: &ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<()> {
        let pos = self.kvs.len();
        self.key_pos.insert(id, pos);
        self.kvs.push(KVQPair {
            key: id,
            value: bincode::serialize(proof)?,
        });
        Ok(())
    }

    fn inc_counter_by_id(&mut self, _id: QProvingJobDataID) -> anyhow::Result<u32> {
        anyhow::bail!("inc counter not supported for proof store builder");
    }

    fn set_bytes_by_id(&mut self, id: QProvingJobDataID, data: &[u8]) -> anyhow::Result<()> {
        let pos = self.kvs.len();
        self.key_pos.insert(id, pos);
        self.kvs.push(KVQPair {
            key: id,
            value: data.to_vec(),
        });
        Ok(())
    }

    fn write_next_jobs(&mut self, jobs: &[QProvingJobDataID], next_jobs: &[QProvingJobDataID]) -> anyhow::Result<()> {
        self.write_next_jobs_core(jobs, next_jobs)
    }

    fn write_multidimensional_jobs(&mut self, jobs_levels: &[Vec<QProvingJobDataID>], next_jobs: &[QProvingJobDataID]) -> anyhow::Result<()> {
        self.write_multidimensional_jobs_core(jobs_levels, next_jobs)
    }
}
