use async_trait::async_trait;
use parth_core::{
    data::serializable::QProofWitnessSerializable,
    node::realm_identifier::QRealmIdentifier,
    protocol::core_types::Q256BitHash,
    QJobIdBase,
};
use psy_data::protocol::chain_context::PendingContext;



#[async_trait]
pub trait QTempDBProofWitnessReader<Hash: Q256BitHash, JobId: QJobIdBase> {
    async fn get_tdb_proof_witness<T: QProofWitnessSerializable>(
        &self,
        rid: &QRealmIdentifier,
        context: &PendingContext<Hash>,
        job_id: JobId,
    ) -> anyhow::Result<T>;
    async fn get_tdb_proof_witness_bytes(
        &self,
        rid: &QRealmIdentifier,
        context: &PendingContext<Hash>,
        job_id: JobId,
    ) -> anyhow::Result<Vec<u8>>;
}

#[async_trait]
pub trait QTempDBProofWitnessWriter<Hash: Q256BitHash, JobId: QJobIdBase> {
    async fn set_tdb_proof_witness<T: QProofWitnessSerializable>(
        &self,
        rid: &QRealmIdentifier,
        context: &PendingContext<Hash>,
        job_id: JobId,
        witness: &T,
    ) -> anyhow::Result<()>;
    async fn set_tdb_proof_witnesses_tuple_owned<T: QProofWitnessSerializable>(
        &self,
        rid: &QRealmIdentifier,
        context: &PendingContext<Hash>,
        job_witnesses: &[(JobId, T)],
    ) -> anyhow::Result<()>;
    async fn set_tdb_proof_witnesses_tuple_owned_raw(
        &self,
        rid: &QRealmIdentifier,
        context: &PendingContext<Hash>,
        job_witnesses: Vec<(JobId, Vec<u8>)>,
    ) -> anyhow::Result<()>;
}

pub trait QTempDBProofWitnessStore<Hash: Q256BitHash, JobId: QJobIdBase>:
    QTempDBProofWitnessReader<Hash, JobId> + QTempDBProofWitnessWriter<Hash, JobId>
{
}
impl<
        T: QTempDBProofWitnessReader<Hash, JobId>
            + QTempDBProofWitnessWriter<Hash, JobId>,
        Hash: Q256BitHash,
        JobId: QJobIdBase,
    > QTempDBProofWitnessStore<Hash, JobId> for T
{
}







