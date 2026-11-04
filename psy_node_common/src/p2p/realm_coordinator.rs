use async_trait::async_trait;
use jsonrpsee::core::client::Error as JsonRpseeClientError;
use parth_core::{crypto::hash::merkle_proof::MerkleProofCore, data::hash::checkpointed_merkle_node::CheckpointedMerkleHash, protocol::core_types::QNetworkTypesConfig};
use psy_api_core::coordinator::standard_edge_rpc::CoordinatorEdgeRpcClient;
use psy_data::{guta::header_extended::GlobalUserTreeAggregatorHeaderWithTagValueAndJobType, prepared_block::realm::PsyRealmCoordinatorUpdate};
use psy_node_core::p2p::traits::realm_coordinantor::RealmCoordinatorClient;
use psy_serialize::PsyCanonicalDatabaseSerializeBaseMulti;

use crate::p2p::guta_submit::GutaSubmitError;

/// The Coordinator Edge was unreachable or did not answer in time; the request may still have reached it.
#[derive(Debug, thiserror::Error)]
#[error("coordinator RPC unavailable: {message}")]
pub struct CoordinatorRpcUnavailable {
    pub message: String,
}

impl CoordinatorRpcUnavailable {
    fn from_client_error(error: &JsonRpseeClientError) -> Option<Self> {
        match error {
            JsonRpseeClientError::Transport(_) | JsonRpseeClientError::RestartNeeded(_) | JsonRpseeClientError::RequestTimeout => {
                Some(Self { message: format!("{error:?}") })
            }
            _ => None,
        }
    }

    pub fn is_cause_of(error: &anyhow::Error) -> bool {
        error.chain().any(|cause| cause.is::<Self>())
    }
}

fn map_coordinator_rpc_error(error: JsonRpseeClientError) -> anyhow::Error {
    match CoordinatorRpcUnavailable::from_client_error(&error) {
        Some(unavailable) => anyhow::Error::new(unavailable),
        None => anyhow::anyhow!("{:?}", error),
    }
}

pub struct PsyRealmCoordinatorClientAPI<N: QNetworkTypesConfig + 'static, C: CoordinatorEdgeRpcClient<N::F, N::QHash, N::JobId, N::ZKProof>> {
    pub client: C,
    _phantom_f: std::marker::PhantomData<N::F>,
}

impl<N: QNetworkTypesConfig + 'static, C: CoordinatorEdgeRpcClient<N::F, N::QHash, N::JobId, N::ZKProof>> PsyRealmCoordinatorClientAPI<N, C> {
    pub fn new(client: C) -> Self {
        Self {
            client,
            _phantom_f: std::marker::PhantomData,
        }
    }
    pub fn get_client(&self) -> &C {
        &self.client
    }
}

#[async_trait]
impl<N: QNetworkTypesConfig + 'static, C: CoordinatorEdgeRpcClient<N::F, N::QHash, N::JobId, N::ZKProof> + Send + Sync>
    RealmCoordinatorClient<N::F, N::QHash> for PsyRealmCoordinatorClientAPI<N, C>
{
        async fn rc_get_checkpoint_tree_merkle_proof(&self, checkpoint_id: u64) -> anyhow::Result<MerkleProofCore<N::QHash>>{
            self.client.get_checkpoint_tree_merkle_proof(checkpoint_id, checkpoint_id).await.map_err(map_coordinator_rpc_error)
        }
    async fn rc_get_latest_checkpoint_id(&self) -> anyhow::Result<u64> {
        self.client.get_latest_checkpoint_id().await.map_err(map_coordinator_rpc_error)
    }
    async fn rc_wait_for_next_checkpoint(&self) -> anyhow::Result<u64> {
        let start = self.client.get_latest_checkpoint_id().await.map_err(map_coordinator_rpc_error)?;
        let mut current = start;
        while current == start {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            current = self.client.get_latest_checkpoint_id().await.map_err(map_coordinator_rpc_error)?;
        }
        Ok(current)
    }
    async fn rc_get_realm_sync_info(&self, checkpoint_id: u64, realm_id: u64) -> anyhow::Result<PsyRealmCoordinatorUpdate<N::F, N::QHash>> {
        self.client
            .get_realm_sync_info(checkpoint_id, realm_id)
            .await
            .map_err(map_coordinator_rpc_error)
    }
    async fn rc_get_checkpoint_leaves_batch(&self, start_checkpoint_id: u64, count: u32) -> anyhow::Result<Vec<N::QHash>> {
        let raw = self.client.get_checkpoint_leaves_batch_raw(start_checkpoint_id, count).await.map_err(map_coordinator_rpc_error)?;
        if raw.len() == 0 {
            return Ok(vec![]);
        }
        if raw.len() % 32 != 0 {
            return Err(anyhow::anyhow!("Invalid byte length for checkpoint leaves batch"));
        }
        Ok(N::QHash::psy_ser_deserialize_vec_of_self_owned(raw, false)?)
    }
    async fn rc_get_realm_root_and_last_modified_checkpoint(
        &self,
        checkpoint_id: u64,
        realm_id: u64,
    ) -> anyhow::Result<CheckpointedMerkleHash<N::QHash>> {
        self.client
            .get_realm_root_and_last_modified_checkpoint(checkpoint_id, realm_id)
            .await
            .map_err(map_coordinator_rpc_error)
    }
    async fn rc_submit_guta_proof(
        &self,
        input: GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<N::F, N::QHash>,
        proof: Vec<u8>,
        realm_id: u64,
        proposal: Option<Vec<u8>>,
        certificate: Option<Vec<u8>>,
    ) -> anyhow::Result<()> {
        self.client
            .submit_guta(input, proof, realm_id, proposal, certificate)
            .await
            .map_err(|error| match error {
                JsonRpseeClientError::Call(object) => GutaSubmitError::from_error_object(&object)
                    .map(anyhow::Error::from)
                    .unwrap_or_else(|| anyhow::anyhow!("GUTA submit rejected: {}", object)),
                other => match CoordinatorRpcUnavailable::from_client_error(&other) {
                    Some(unavailable) => anyhow::Error::new(unavailable),
                    None => anyhow::anyhow!("GUTA submit transport error: {other}"),
                },
            })?;
        Ok(())
    }
    async fn rc_get_contract_tree_state_heights(&self, checkpoint_id: u64, contract_ids: Vec<u64>) -> anyhow::Result<Vec<u8>> {
        self.client
            .get_contract_tree_state_heights(checkpoint_id, contract_ids)
            .await
            .map_err(map_coordinator_rpc_error)
    }
}

#[cfg(test)]
mod tests {
    use jsonrpsee::{core::client::Error as JsonRpseeClientError, types::ErrorObjectOwned};

    use super::CoordinatorRpcUnavailable;

    #[test]
    fn only_transport_restart_and_timeout_errors_are_unavailable() {
        let unavailable = [
            JsonRpseeClientError::Transport(Box::new(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))),
            JsonRpseeClientError::RequestTimeout,
        ];
        for error in &unavailable {
            assert!(CoordinatorRpcUnavailable::from_client_error(error).is_some(), "{error:?}");
        }
        let answered = [
            JsonRpseeClientError::Call(ErrorObjectOwned::owned(-32000, "rejected", None::<()>)),
            JsonRpseeClientError::Custom("bad response".to_string()),
        ];
        for error in &answered {
            assert!(CoordinatorRpcUnavailable::from_client_error(error).is_none(), "{error:?}");
        }
        let mapped = super::map_coordinator_rpc_error(JsonRpseeClientError::RequestTimeout).context("reading realm root");
        assert!(CoordinatorRpcUnavailable::is_cause_of(&mapped));
    }
}
