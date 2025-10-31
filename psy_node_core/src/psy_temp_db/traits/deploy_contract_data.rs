use async_trait::async_trait;
use parth_core::node::realm_identifier::QRealmIdentifier;


#[async_trait]
pub trait QTempDBDeployContractDataReader {
    async fn get_deploy_contract_code_definition_raw(&self, rid: &QRealmIdentifier, unique_pending_id: u64, rand_key: &[u8; 16]) -> anyhow::Result<Option<Vec<u8>>>;
}

#[async_trait]
pub trait QTempDBDeployContractDataWriter {
    async fn set_deploy_contract_code_definition_raw(&self, rid: &QRealmIdentifier, unique_pending_id: u64, rand_key: &[u8; 16], data: Vec<u8>) -> anyhow::Result<()>;
}

pub trait QTempDBDeployContractDataStore: QTempDBDeployContractDataReader + QTempDBDeployContractDataWriter {}
impl<T: QTempDBDeployContractDataReader + QTempDBDeployContractDataWriter> QTempDBDeployContractDataStore for T {}
