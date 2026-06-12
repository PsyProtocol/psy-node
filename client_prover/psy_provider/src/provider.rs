use std::{collections::HashMap, marker::PhantomData, result::Result::Ok, sync::Arc, time::Duration};

use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::PrimeField64},
    hash::hash_types::{HashOut, RichField},
    plonk::{
        circuit_data::VerifierOnlyCircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_client_common::{
    data::{alt::AltVerifierOnlyCircuitData, qhashout::QHashOut},
    job::id::QProvingJobDataIDWithRewardPath,
    traits::to_qfelts::ToQFelts,
    ups::circuits::LocalCircuitType,
};
use psy_client_data::{
    api::reward::PsyProoffMinerRewardProof,
    config::store_config::PsyHasher,
    qdata::{checkpoint::PsyBlockState, contract::ContractCodeDefinition},
    qstore::controllers::session_info::SessionCircuitInfoStore,
    traits::qdatastore::{qmetadata::QMetaDataStoreReaderSync, qtreedata::QTreeDataStoreReaderSync},
    ups::{
        start_step::UPSStartStepInput,
        start_step_register_user::UPSStartStepRegisterUserInput,
        ups_cfc_standard_step::{UPSCFCDeferredTransactionCircuitInput, UPSCFCStandardTransactionCircuitInput},
        ups_end_cap::UPSEndCapFromProofTreeGadgetInput,
    },
};
use psy_common_circuit::circuits::zk_signature3::core::PsyBasicZKSignatureInnerCircuit;
use psy_crypto::{
    common::witnesses::qrecursion::{
        header::QRecursionAggStandardHeader,
        proof_data::{AggProofRecord, QStandardBinaryTreeCircuitType, SimpleQTreeRecursionManagerInclusionProofs},
    },
    hash::{
        merkle::core::{DeltaMerkleProofCore, MerkleProofCore},
        traits::{hasher::MerkleZeroHasherWithMarkedLeaf, qhashable::QFieldHashable},
    },
    signature::secp256k1::core::PsyCompressedSecp256K1Signature,
};
use psy_vm::{
    dpn::vm::def::DPNFunctionCircuitDefinition,
    ups::circuit_manager::{PortableQTreeRecursion, PortableQTreeRecursionCircuitsData, PortableQTreeRecursionCircuitsProve, UPSCircuitManager},
    vm::cfc_input::DapenContractFunctionCircuitInput,
};
use rand::Rng;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json;

use super::request::{
    Id, QAddWithdrawalRPCRequest, QClaimDepositRPCRequest, QDeployContractRPCRequest, QGetUserIdsRPCRequest, QRegisterUserRPCRequest,
    QSubmitEndCapRPCRequest, QTokenTransferRPCRequest, RequestParams, ResponseResult, RpcRequest, RpcResponse, Version,
};
use crate::{
    request::{
        DPNSoftwareDefinedSignatureProofRPCRequest, QBlockStateRPCRequest, QGenerateBatchProofMinerRewardProofsRPCRequest,
        QGetCheckpointIdForUniquePendingIdRPCRequest, QGetContractMethodCommonDataRPCRequest, QGetFnIdRPCRequest, QLatestBlockStateRPCRequest,
        QLeftAggRightLeafRpcRequestV2, QLeftLeafRightAggRpcRequestV2, QProveContractCallRPCRequest, QProveUpsStartRPCRequest,
        QProveUpsStartRegisterUserRPCRequest, QRegisterCircuitsRPCRequest, QRegisterDPNSoftwareDefinedCircuitRPCRequest,
        QRegisterPlonky2SoftwareDefinedCircuitRPCRequest, QResolveContractFunctionByMethodIdRPCRequest,
        QResolveContractFunctionByMethodNameRPCRequest, QSecpSignatureProofRPCRequest, QSignatureMinifierProofRPCRequest, QSingleLeafRpcRequestV2,
        QTwoAggRpcRequsetV2, QTwoLeafRpcRequestV2, QUpsCfcDeferredTxRPCRequest, QUpsCfcStandardTxRPCRequest, QUpsEndCapRPCRequestV2,
        QUserSubTreeMerkleProofRPCRequest, RequestParamsV2,
    },
    session::TxStatus,
};

type TxHash = String;

#[cfg(not(target_arch = "wasm32"))]
type WaitDeadline = tokio::time::Instant;

#[cfg(target_arch = "wasm32")]
type WaitDeadline = f64;

#[cfg(not(target_arch = "wasm32"))]
fn deadline_after(timeout_secs: Option<u64>) -> Option<WaitDeadline> {
    timeout_secs.map(|secs| tokio::time::Instant::now() + Duration::from_secs(secs))
}

#[cfg(target_arch = "wasm32")]
fn deadline_after(timeout_secs: Option<u64>) -> Option<WaitDeadline> {
    timeout_secs.map(|secs| js_sys::Date::now() + (secs as f64 * 1000.0))
}

#[cfg(not(target_arch = "wasm32"))]
fn deadline_expired(deadline: Option<WaitDeadline>) -> bool {
    deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
}

#[cfg(target_arch = "wasm32")]
fn deadline_expired(deadline: Option<WaitDeadline>) -> bool {
    deadline.is_some_and(|deadline| js_sys::Date::now() >= deadline)
}

#[cfg(not(target_arch = "wasm32"))]
async fn sleep_for(duration: Duration) {
    tokio::time::sleep(duration).await;
}

#[cfg(target_arch = "wasm32")]
async fn sleep_for(duration: Duration) {
    use js_sys::{global, Function, Promise, Reflect};
    use wasm_bindgen::{closure::Closure, JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;

    let ms = duration.as_millis().min(i32::MAX as u128) as i32;
    let promise = Promise::new(&mut |resolve: Function, _reject: Function| {
        let global_obj = global();
        let resolve_for_cb = resolve.clone();
        let cb = Closure::<dyn FnMut()>::once(move || {
            let _ = resolve_for_cb.call0(&JsValue::NULL);
        });
        if let Some(set_timeout) = Reflect::get(&global_obj, &JsValue::from_str("setTimeout"))
            .ok()
            .and_then(|v| v.dyn_into::<Function>().ok())
        {
            let _ = set_timeout.call2(
                &global_obj,
                cb.as_ref().unchecked_ref(),
                &JsValue::from_f64(ms as f64),
            );
        } else {
            let _ = resolve.call0(&JsValue::NULL);
        }
        cb.forget();
    });
    let _ = JsFuture::from(promise).await;
}

#[derive(Debug, Clone)]
pub struct RpcProvider {
    pub client: Arc<Client>,
    pub realm_configs: HashMap<u64, Vec<String>>,
    pub coordinator_configs: HashMap<u64, Vec<String>>,
    pub users_per_realm: u64,
    pub current_user_id: u64,
}

impl RpcProvider {
    pub fn new_with_config_path(config_path: &str) -> anyhow::Result<Self> {
        let psy_config = psy_config::PsyConfigGoldilocks::from_file(config_path)?;
        let network_config = psy_config.get_current_network()?;
        Self::new_with_config(network_config)
    }

    pub fn new_with_config(config: &psy_config::NetworkConfigGoldilocks) -> anyhow::Result<Self> {
        tracing::trace!("start rpc provider with config: {}", serde_json::to_string_pretty(&config)?);
        assert!(config.realm_configs.len() > 0);
        assert!(config.coordinator_configs.len() > 0);
        let mut realm_configs = HashMap::new();
        let mut coordinator_configs = HashMap::new();

        config.realm_configs.iter().for_each(|realm_config| {
            assert!(realm_config.rpc_url.len() > 0);
            realm_configs.insert(realm_config.id, realm_config.rpc_url.clone());
        });
        config.coordinator_configs.iter().for_each(|coordinator_config| {
            assert!(coordinator_config.rpc_url.len() > 0);
            coordinator_configs.insert(coordinator_config.id, coordinator_config.rpc_url.clone());
        });

        // Configure HTTP client with connection timeout and connection pool settings
        // to handle high-concurrency scenarios better
        #[cfg(not(target_arch = "wasm32"))]
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(360))
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(500)
            .tcp_keepalive(Duration::from_secs(60))
            .tcp_nodelay(true)
            .http1_only() // Force HTTP/1.1 to avoid potential HTTP/2 connection issues
            .build()
            .map_err(|e| anyhow::format_err!("Failed to create HTTP client: {}", e))?;

        #[cfg(target_arch = "wasm32")]
        let client = Client::builder()
            .build()
            .map_err(|e| anyhow::format_err!("Failed to create HTTP client: {}", e))?;

        Ok(Self {
            client: Arc::new(client),
            realm_configs,
            coordinator_configs,
            users_per_realm: config.users_per_realm,
            current_user_id: 0,
        })
    }
}

macro_rules! psy_rpc_call {
    ($instance:ident, $rpc_url:expr, $rpc_params:expr) => {{
        async move {
            let request = RpcRequest {
                jsonrpc: Version::V2,
                request: $rpc_params,
                id: Id::Number(1),
            };
            let response = $instance.client.post($rpc_url).json(&request).send().await?;
            let json_response: RpcResponse<String> = response.json().await?;
            match json_response.result {
                ResponseResult::Success(s) => {
                    tracing::info!("{:?}", s);
                    Ok(())
                }
                ResponseResult::Error(e) => Err(anyhow::format_err!("psy rpc call failed `{:?}`", e)),
            }
        }
        .await
    }};
}

macro_rules! psy_rpc_call_back {
    ($instance:ident, $rpc_url:expr, $rpc_params:expr, $ret_ty: ty) => {{
        async move {
            let url_str = $rpc_url;
            let request_payload = RpcRequest {
                jsonrpc: Version::V2,
                request: $rpc_params,
                id: Id::Number(1),
            };
            let method_name = match serde_json::to_value(&request_payload.request) {
                Ok(v) => v
                    .get("method")
                    .and_then(|m| m.as_str())
                    .unwrap_or("<unknown>")
                    .to_string(),
                Err(_) => "<serialize-request-failed>".to_string(),
            };
            tracing::info!("psy rpc call: {}", url_str);
            #[cfg(not(target_arch = "wasm32"))]
            let request_builder = $instance
                .client
                .post(url_str.clone())
                .timeout(std::time::Duration::from_secs(360));
            #[cfg(target_arch = "wasm32")]
            let request_builder = $instance.client.post(url_str.clone());

            let result = request_builder
                .json(&request_payload)
                .send()
                .await;

            match result {
                Ok(response) => {
                    let status = response.status();
                    let body = response
                        .text()
                        .await
                        .map_err(|e| anyhow::anyhow!("Failed to read response body: {}", e))?;

                    match serde_json::from_str::<RpcResponse<$ret_ty>>(&body) {
                        Ok(parsed) => Ok(parsed),
                        Err(e) => {
                            tracing::error!(
                                url = %url_str,
                                method = %method_name,
                                status = %status,
                                body_len = body.len(),
                                body = %body,
                                error = %e,
                                "[RPC_DECODE_FAIL] failed to parse JSON-RPC response body"
                            );
                            Err(anyhow::anyhow!("Failed to parse JSON response: {}", e))
                        }
                    }
                }
                Err(e) => {
                    #[cfg(not(target_arch = "wasm32"))]
                    let error_msg = if e.is_connect() {
                        format!("Connection error to {}: {}", url_str, e)
                    } else if e.is_timeout() {
                        format!("Timeout error to {}: {}", url_str, e)
                    } else if e.is_request() {
                        format!("Request error to {}: {}", url_str, e)
                    } else {
                        format!("Error sending request to {}: {}", url_str.clone(), e)
                    };
                    #[cfg(target_arch = "wasm32")]
                    let error_msg = if e.is_timeout() {
                        format!("Timeout error to {}: {}", url_str, e)
                    } else if e.is_request() {
                        format!("Request error to {}: {}", url_str, e)
                    } else {
                        format!("Error sending request to {}: {}", url_str.clone(), e)
                    };
                    tracing::error!("{}", error_msg);
                    #[cfg(not(target_arch = "wasm32"))]
                    tracing::error!(
                        "Request error details: is_connect={}, is_timeout={}, is_request={}, is_decode={}",
                        e.is_connect(),
                        e.is_timeout(),
                        e.is_request(),
                        e.is_decode()
                    );
                    #[cfg(target_arch = "wasm32")]
                    tracing::error!(
                        "Request error details: is_timeout={}, is_request={}, is_body={}, is_decode={}",
                        e.is_timeout(),
                        e.is_request(),
                        e.is_body(),
                        e.is_decode()
                    );
                    Err(anyhow::anyhow!("{}", error_msg))
                }
            }
        }
        .await?
    }};
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
pub trait QUserRpcProvider {
    async fn register_user<F: RichField>(&self, req: QRegisterUserRPCRequest<F>) -> anyhow::Result<String>;
    async fn produce_block<F: RichField>(&self) -> anyhow::Result<()>;
    async fn add_withdrawal<F: RichField>(&self, req: QAddWithdrawalRPCRequest) -> anyhow::Result<()>;

    async fn claim_deposit<F: RichField>(&self, req: QClaimDepositRPCRequest) -> anyhow::Result<()>;

    async fn token_transfer<F: RichField>(&self, req: QTokenTransferRPCRequest) -> anyhow::Result<()>;

    async fn deploy_contract<F: RichField>(&self, req: QDeployContractRPCRequest<F>) -> anyhow::Result<String>;

    async fn submit_end_cap_proof<F: RichField>(&self, req: QSubmitEndCapRPCRequest<F>) -> anyhow::Result<TxHash>;
    async fn submit_end_cap_proofs<F: RichField>(&self, reqs: Vec<QSubmitEndCapRPCRequest<F>>) -> anyhow::Result<(Vec<u64>, Vec<u64>)>;
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl QUserRpcProvider for RpcProvider {
    async fn register_user<F: RichField>(&self, req: QRegisterUserRPCRequest<F>) -> anyhow::Result<String> {
        tracing::info!("register user: {:?}", req);
        let url = self.get_coordinator_url()?;

        let response = psy_rpc_call_back!(self, url, RequestParams::<F>::RegisterUser(req), String);
        match response.result {
            ResponseResult::Success(regisiter_user_uuid) => {
                tracing::debug!("registered user {}", regisiter_user_uuid);
                Ok(regisiter_user_uuid)
            }
            ResponseResult::Error(e) => {
                tracing::error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("deploy_contract rpc call failed `{:?}`", e))
            }
        }
    }
    async fn produce_block<F: RichField>(&self) -> anyhow::Result<()> {
        tracing::info!("produce block");
        let url = self.get_coordinator_url()?;
        psy_rpc_call!(self, url, RequestParams::<F>::ProduceBlock)
    }
    async fn add_withdrawal<F: RichField>(&self, _req: QAddWithdrawalRPCRequest) -> anyhow::Result<()> {
        unimplemented!()
    }

    async fn claim_deposit<F: RichField>(&self, req: QClaimDepositRPCRequest) -> anyhow::Result<()> {
        let url = self.get_coordinator_url()?;
        let response = psy_rpc_call_back!(self, url, RequestParams::<F>::ClaimDeposit(req), String);
        match response.result {
            ResponseResult::Success(_) => Ok(()),
            ResponseResult::Error(e) => {
                tracing::error!("claim_deposit RPC call failed: {:?}", e);
                Err(anyhow::format_err!("claim_deposit rpc call failed `{:?}`", e))
            }
        }
    }

    async fn token_transfer<F: RichField>(&self, _req: QTokenTransferRPCRequest) -> anyhow::Result<()> {
        unimplemented!()
    }

    async fn deploy_contract<F: RichField>(&self, req: QDeployContractRPCRequest<F>) -> anyhow::Result<String> {
        let url = self.get_coordinator_url()?;
        let response = psy_rpc_call_back!(self, url, RequestParams::<F>::DeployContract(req), String);
        match response.result {
            ResponseResult::Success(contract_uuid) => {
                tracing::debug!("deployed contract {}", contract_uuid);
                Ok(contract_uuid)
            }
            ResponseResult::Error(e) => {
                tracing::error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("deploy_contract rpc call failed `{:?}`", e))
            }
        }
    }

    async fn submit_end_cap_proof<F: RichField>(&self, req: QSubmitEndCapRPCRequest<F>) -> anyhow::Result<TxHash> {
        let rpc_url = self.get_realm_url(self.current_user_id)?;
        let response = psy_rpc_call_back!(self, rpc_url, RequestParams::<F>::SubmitEndCap(req), TxHash);
        match response.result {
            ResponseResult::Success(tx_hash) => {
                tracing::debug!("submitted end cap {}", tx_hash.to_string());
                Ok(tx_hash)
            }
            ResponseResult::Error(e) => {
                tracing::error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("submit_end_cap_proof rpc call failed `{:?}`", e))
            }
        }
    }
    async fn submit_end_cap_proofs<F: RichField>(&self, reqs: Vec<QSubmitEndCapRPCRequest<F>>) -> anyhow::Result<(Vec<u64>, Vec<u64>)> {
        let rpc_url = self.get_realm_url(self.current_user_id)?;
        let reqs = reqs.into_iter().map(|req| (req.user_ec_input, req.proof)).collect::<Vec<_>>();
        let response = psy_rpc_call_back!(self, rpc_url, RequestParams::<F>::SubmitEndCapProofs(vec![reqs]), (Vec<u64>, Vec<u64>));
        match response.result {
            ResponseResult::Success((success_user_ids, error_user_ids)) => Ok((success_user_ids, error_user_ids)),
            ResponseResult::Error(e) => Err(anyhow::format_err!("submit_end_cap_proofs rpc call failed `{:?}`", e)),
        }
    }
}

type F = GoldilocksField;
#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl RpcProvider {
    pub async fn get_user_ids_for_public_key(&self, public_key: QHashOut<F>) -> anyhow::Result<Vec<u64>> {
        tracing::info!("user: {}", public_key);
        let url = self.get_coordinator_url()?;
        let response = psy_rpc_call_back!(
            self,
            url,
            RequestParams::<F>::GetUserIds(QGetUserIdsRPCRequest(public_key, 0, 64)),
            Vec<u64>
        );
        match response.result {
            ResponseResult::Success(user_ids) => {
                tracing::info!("get user ids: {:?}", user_ids);
                match user_ids.is_empty() {
                    true => Err(anyhow::format_err!("no user ids found")),
                    false => Ok(user_ids),
                }
            }
            ResponseResult::Error(e) => Err(anyhow::format_err!("rpc call failed `{:?}`", e)),
        }
    }

    pub fn with_user_id_owned(&self, user_id: u64) -> Self {
        Self {
            client: self.client.clone(),
            realm_configs: self.realm_configs.clone(),
            coordinator_configs: self.coordinator_configs.clone(),
            users_per_realm: self.users_per_realm,
            current_user_id: user_id,
        }
    }

    pub fn set_user_id(&mut self, user_id: u64) {
        self.current_user_id = user_id;
    }

    pub async fn submit_end_cap_proofs_by_edge_id<F: RichField>(
        &self,
        reqs: Vec<QSubmitEndCapRPCRequest<F>>,
        edge_id: u64,
    ) -> anyhow::Result<(Vec<u64>, Vec<u64>)> {
        let rpc_url = self.get_realm_url_by_edge_id(self.current_user_id, edge_id)?;
        let reqs = reqs.into_iter().map(|req| (req.user_ec_input, req.proof)).collect::<Vec<_>>();
        let response = psy_rpc_call_back!(self, rpc_url, RequestParams::<F>::SubmitEndCapProofs(vec![reqs]), (Vec<u64>, Vec<u64>));
        match response.result {
            ResponseResult::Success((success_user_ids, error_user_ids)) => Ok((success_user_ids, error_user_ids)),
            ResponseResult::Error(e) => Err(anyhow::format_err!("submit_end_cap_proofs rpc call failed `{:?}`", e)),
        }
    }
}

// Async version of with_user_id
#[maybe_async::async_impl]
impl RpcProvider {
    pub async fn with_user_id<T, F, Fut>(&mut self, user_id: u64, f: F) -> T
    where
        F: FnOnce(&mut Self) -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let original_user_id = self.current_user_id;
        self.current_user_id = user_id;
        let result = f(self).await;
        self.current_user_id = original_user_id;
        result
    }
}

// Sync version of with_user_id
#[maybe_async::sync_impl]
impl RpcProvider {
    pub fn with_user_id<T, F>(&mut self, user_id: u64, f: F) -> T
    where
        F: FnOnce(&mut Self) -> T,
    {
        let original_user_id = self.current_user_id;
        self.current_user_id = user_id;
        let result = f(self);
        self.current_user_id = original_user_id;
        result
    }
}

impl psy_client_data::qstore::imm::cmd_processor::QUserIdManager for RpcProvider {
    fn get_user_id(&self) -> u64 {
        self.current_user_id
    }

    fn set_user_id(&mut self, user_id: u64) {
        self.current_user_id = user_id;
    }
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl RpcProvider {
    pub async fn get_realm_latest_block_state(&self) -> anyhow::Result<psy_client_data::qdata::checkpoint::PsyBlockState> {
        tracing::info!("Fetching latest realm block state");
        let rpc_url = self.get_realm_url(self.current_user_id)?;
        let input = QLatestBlockStateRPCRequest {};
        let response = psy_rpc_call_back!(self, rpc_url, RequestParams::<GoldilocksField>::GetLatestBlockState(input), PsyBlockState);
        match response.result {
            ResponseResult::Success(block_state) => {
                tracing::debug!(
                    block_state = %serde_json::to_string_pretty(&block_state).unwrap(),
                    "Successfully fetched block state"
                );
                Ok(block_state)
            }
            ResponseResult::Error(e) => {
                tracing::error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_realm_latest_block_state rpc call failed `{:?}`", e))
            }
        }
    }

    pub async fn get_realm_block_state(&self, checkpoint_id: u64) -> anyhow::Result<psy_client_data::qdata::checkpoint::PsyBlockState> {
        tracing::info!("Fetching realm block state at checkpoint {}", checkpoint_id);
        let rpc_url = self.get_realm_url(self.current_user_id)?;
        let input = QBlockStateRPCRequest { checkpoint_id };
        let response = psy_rpc_call_back!(self, rpc_url, RequestParams::<GoldilocksField>::GetBlockState(input), PsyBlockState);
        match response.result {
            ResponseResult::Success(block_state) => {
                tracing::debug!(
                    block_state = %serde_json::to_string_pretty(&block_state).unwrap(),
                    "Successfully fetched block state"
                );
                Ok(block_state)
            }
            ResponseResult::Error(e) => {
                tracing::error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_realm_block_state rpc call failed `{:?}`", e))
            }
        }
    }

    pub async fn get_coordinator_latest_block_state(&self) -> anyhow::Result<psy_client_data::qdata::checkpoint::PsyBlockState> {
        tracing::info!("Fetching latest coordinator block state");
        let rpc_url = self.get_coordinator_url()?;
        let input = QLatestBlockStateRPCRequest {};
        let response = psy_rpc_call_back!(self, rpc_url, RequestParams::<GoldilocksField>::GetLatestBlockState(input), PsyBlockState);
        match response.result {
            ResponseResult::Success(block_state) => {
                tracing::debug!(
                    block_state = %serde_json::to_string_pretty(&block_state).unwrap(),
                    "Successfully fetched block state"
                );
                Ok(block_state)
            }
            ResponseResult::Error(e) => {
                tracing::error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_coordinator_latest_block_state rpc call failed `{:?}`", e))
            }
        }
    }

    pub async fn get_coordinator_block_state(&self, checkpoint_id: u64) -> anyhow::Result<psy_client_data::qdata::checkpoint::PsyBlockState> {
        tracing::info!("Fetching coordinator block state at checkpoint {}", checkpoint_id);
        let rpc_url = self.get_coordinator_url()?;
        let input = QBlockStateRPCRequest { checkpoint_id };
        let response = psy_rpc_call_back!(self, rpc_url, RequestParams::<GoldilocksField>::GetBlockState(input), PsyBlockState);
        match response.result {
            ResponseResult::Success(block_state) => {
                tracing::debug!(
                    block_state = %serde_json::to_string_pretty(&block_state).unwrap(),
                    "Successfully fetched block state"
                );
                Ok(block_state)
            }
            ResponseResult::Error(e) => {
                tracing::error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_coordinator_block_state rpc call failed `{:?}`", e))
            }
        }
    }

    pub async fn get_user_sub_tree_merkle_proof_inner(
        &self,
        rpc_url: &str,
        checkpoint_id: u64,
        root_level: u8,
        leaf_level: u8,
        leaf_index: u64,
    ) -> anyhow::Result<MerkleProofCore<QHashOut<GoldilocksField>>> {
        let input = QUserSubTreeMerkleProofRPCRequest {
            checkpoint_id,
            root_level,
            leaf_level,
            leaf_index,
        };
        let response = psy_rpc_call_back!(
            self,
            rpc_url,
            RequestParams::<GoldilocksField>::GetUserSubTreeMerkleProof(input),
            MerkleProofCore<QHashOut<GoldilocksField>>
        );
        match response.result {
            ResponseResult::Success(merkle_proof) => {
                tracing::debug!(
                    checkpoint_id = checkpoint_id,
                    root_level = root_level,
                    leaf_level = leaf_level,
                    leaf_index = leaf_index,
                    merkle_proof = %serde_json::to_string_pretty(&merkle_proof).unwrap(),
                    "Successfully fetched merkle proof"
                );
                Ok(merkle_proof)
            }
            ResponseResult::Error(e) => {
                tracing::error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_user_sub_tree_merkle_proof rpc call failed `{:?}`", e))
            }
        }
    }

    pub async fn get_claim_amount(&self, checkpoint_id: u64, user_id: u64, claim_user_id: u64) -> anyhow::Result<u64> {
        let contract_id = 0;
        let height = 32;
        let sender_total_sent_index = 3 + user_id * 2;
        let sender_total_sent_slot = sender_total_sent_index / 4;
        let sender_total_sent_slot_index = sender_total_sent_index % 4;
        let amount_claimed_index = 3 + claim_user_id * 2 + 1;
        let amount_claimed_slot = amount_claimed_index / 4;
        let amount_claimed_slot_index = amount_claimed_index % 4;
        let user_total_sent = self
            .get_user_contract_state_tree_leaf_hash(checkpoint_id, claim_user_id, contract_id, height, sender_total_sent_slot)
            .await?
            .to_qfelts()[(sender_total_sent_slot_index) as usize]
            .to_canonical_u64();
        let amount_claimed = self
            .get_user_contract_state_tree_leaf_hash(checkpoint_id, user_id, contract_id, height, amount_claimed_slot)
            .await?
            .to_qfelts()[(amount_claimed_slot_index) as usize]
            .to_canonical_u64();

        if amount_claimed > user_total_sent {
            return Err(anyhow::format_err!(
                "amount claimed {} is greater than user total sent {}",
                amount_claimed,
                user_total_sent
            ));
        }

        Ok(user_total_sent - amount_claimed)
    }

    /// Read the withdrawal tree root from contract #3 storage.
    ///
    /// Storage layout of `PsyWithdrawalTreeContract` (packed, 4 felts per
    /// slot):   slot 0: `[root[0], root[1], root[2], root[3]]`
    ///   slot 1: `[root[4], root[5], root[6], root[7]]`
    pub async fn get_proposed_withdrawal_tree_root(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<String> {
        const WITHDRAWAL_TREE_CONTRACT_ID: u32 = 3;
        const CONTRACT_STATE_TREE_HEIGHT: u8 = 32;

        let slot0 = self
            .get_user_contract_state_tree_leaf_hash(checkpoint_id, user_id, WITHDRAWAL_TREE_CONTRACT_ID, CONTRACT_STATE_TREE_HEIGHT, 0)
            .await?;
        let slot1 = self
            .get_user_contract_state_tree_leaf_hash(checkpoint_id, user_id, WITHDRAWAL_TREE_CONTRACT_ID, CONTRACT_STATE_TREE_HEIGHT, 1)
            .await?;

        let s0 = slot0.0.elements;
        let s1 = slot1.0.elements;
        let root_felts = [s0[0], s0[1], s0[2], s0[3], s1[0], s1[1], s1[2], s1[3]];
        let mut out = [0u8; 32];
        for (i, f) in root_felts.iter().enumerate() {
            let v = f.to_canonical_u64() as u32;
            out[i * 4..(i + 1) * 4].copy_from_slice(&v.to_be_bytes());
        }
        Ok(format!("0x{}", hex::encode(out)))
    }

    /// Read the withdrawal tree contract's `next_index` (= chain_counts[0] for chain 0).
    /// This tells us how many withdrawals have already been appended to chain 0.
    /// The `next_index` field is stored at storage slot 2 (1 QHashOut slot).
    pub async fn get_withdrawal_tree_next_index(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<u64> {
        const WITHDRAWAL_TREE_CONTRACT_ID: u32 = 3;
        const CONTRACT_STATE_TREE_HEIGHT: u8 = 32;
        const NEXT_INDEX_SLOT: u64 = 2;

        let slot = self
            .get_user_contract_state_tree_leaf_hash(checkpoint_id, user_id, WITHDRAWAL_TREE_CONTRACT_ID, CONTRACT_STATE_TREE_HEIGHT, NEXT_INDEX_SLOT)
            .await?;
        let elements = slot.0.elements;
        Ok(elements[0].to_canonical_u64())
    }

    pub async fn is_endcap_included_at_checkpoint(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        end_user_leaf_hash: QHashOut<GoldilocksField>,
    ) -> anyhow::Result<bool> {
        let user_leaf_data = self.get_user_leaf_data(checkpoint_id, user_id).await?;
        Ok(user_leaf_data.qfhash::<PsyHasher>() == end_user_leaf_hash)
    }

    pub async fn wait_next_checkpoint(
        &self,
        checkpoint_before: u64,
        deadline: Option<WaitDeadline>,
        poll_interval_secs: u64,
    ) -> anyhow::Result<u64> {
        loop {
            let coordinator_latest = self.get_coordinator_latest_block_state().await?.checkpoint_id;
            if coordinator_latest > checkpoint_before {
                return Ok(coordinator_latest);
            }

            if deadline_expired(deadline) {
                anyhow::bail!(
                    "timeout waiting next checkpoint: checkpoint_before={} coordinator_latest={}",
                    checkpoint_before,
                    coordinator_latest
                );
            }

            sleep_for(Duration::from_secs(poll_interval_secs)).await;
        }
    }

    pub async fn wait_for_endcap_inclusion(
        &self,
        user_id: u64,
        end_user_leaf_hash: QHashOut<GoldilocksField>,
        checkpoint_before: u64,
        timeout_secs: Option<u64>,
        poll_interval_secs: u64,
    ) -> anyhow::Result<u64> {
        let deadline = deadline_after(timeout_secs);
        let mut latest = self
            .wait_next_checkpoint(checkpoint_before, deadline, poll_interval_secs)
            .await?;

        loop {
            for checkpoint_id in checkpoint_before..=latest {
                match self
                    .is_endcap_included_at_checkpoint(checkpoint_id, user_id, end_user_leaf_hash)
                    .await
                {
                    Ok(true) => return Ok(checkpoint_id),
                    Ok(false) => {}
                    Err(err) => {
                        tracing::warn!(
                            user_id,
                            checkpoint_id,
                            checkpoint_before,
                            latest,
                            error = %err,
                            "endcap inclusion checkpoint check failed; retrying"
                        );
                        break;
                    }
                }
            }

            if deadline_expired(deadline) {
                anyhow::bail!(
                    "timeout waiting endcap inclusion: user_id={} end_user_leaf_hash={} checkpoint_before={} latest={}",
                    user_id,
                    end_user_leaf_hash,
                    checkpoint_before,
                    latest
                );
            }

            sleep_for(Duration::from_secs(poll_interval_secs)).await;
            latest = self.get_coordinator_latest_block_state().await?.checkpoint_id;
        }
    }

    pub async fn get_tx_status(&self, user_id: u64, nonce: u64) -> anyhow::Result<TxStatus> {
        tracing::info!("Fetching tx status user_id: {}, nonce: {}", user_id, nonce);
        let latest_checkpoint_id = self.get_latest_block_state().await?.checkpoint_id;
        let expected_nonce = match self.get_user_leaf_data(latest_checkpoint_id, user_id).await {
            Ok(user_leaf) => user_leaf.nonce.to_canonical_u64() + 1,
            Err(_) => 1,
        };
        tracing::debug!("get user {} tx status at nonce {}, expected_nonce {}", user_id, nonce, expected_nonce);

        if nonce != expected_nonce {
            tracing::warn!(
                "nonce {} != expected_nonce {} for user {}, tx state is stale",
                nonce,
                expected_nonce,
                user_id
            );
            Ok(TxStatus::Stale)
        } else {
            Ok(TxStatus::Submittable)
        }
        // let rpc_url = self.get_realm_url(user_id)?;

        // let input = QGetTxStatusRPCRequest { user_id, nonce };
        // let response = psy_rpc_call_back!(self, rpc_url,
        // RequestParams::<PsyFelt>::GetTxStatus(input), TxStatus);
        // match response.result {
        //     ResponseResult::Success(status) => {
        //         tracing::info!(
        //             "Successfully fetched tx status user_id: {}, nonce: {},
        // status: {:?}",             user_id,
        //             nonce,
        //             status
        //         );
        //         Ok(status)
        //     }
        //     ResponseResult::Error(e) => {
        //         tracing::error!("RPC call failed: {:?}", e);
        //         Err(anyhow::format_err!("get_tx_status rpc call failed
        // `{:?}`", e))     }
        // }
    }

    pub const fn get_realm_id(&self, user_id: u64) -> u64 {
        user_id / self.users_per_realm
    }

    pub fn get_realm_url(&self, user_id: u64) -> anyhow::Result<&String> {
        let realm_id = self.get_realm_id(user_id);
        tracing::trace!("get realm url for user id {}, realm id {}", user_id, realm_id);

        self.get_realm_url_by_realm_id(realm_id)
    }

    pub fn get_realm_url_by_realm_id(&self, realm_id: u64) -> anyhow::Result<&String> {
        let realm_urls = self
            .realm_configs
            .get(&realm_id)
            .ok_or(anyhow::format_err!("realm id `{}` not found, please check the config", realm_id))?;
        let random_index = rand::thread_rng().gen_range(0..realm_urls.len());

        Ok(&realm_urls[random_index])
    }

    pub fn get_realm_url_by_edge_id(&self, user_id: u64, edge_id: u64) -> anyhow::Result<&String> {
        let realm_id = self.get_realm_id(user_id);
        tracing::trace!("get realm url for user id {}, realm id {}", user_id, realm_id);

        let realm_urls = self
            .realm_configs
            .get(&realm_id)
            .ok_or(anyhow::format_err!("realm id `{}` not found, please check the config", realm_id))?;

        Ok(realm_urls.get(edge_id as usize).unwrap_or_else(|| &realm_urls[0]))
    }

    pub fn get_coordinator_url(&self) -> anyhow::Result<String> {
        let coordinator_urls = self
            .coordinator_configs
            .get(&0)
            .ok_or(anyhow::format_err!("coordinator id `{}` not found, please check the config", 0))?;
        let random_index = rand::thread_rng().gen_range(0..coordinator_urls.len());
        // Normalize URL by removing trailing slash to avoid potential issues with
        // reqwest
        let url = coordinator_urls[random_index].clone();
        Ok(url)
    }

    async fn get_checkpoint_id_for_unique_pending_id_inner(&self, url: String, unique_pending_id: u64) -> anyhow::Result<Option<u64>> {
        tracing::info!("get_checkpoint_id_for_unique_pending_id with url {}: {}", url, unique_pending_id);
        let response = psy_rpc_call_back!(
            self,
            &url,
            RequestParams::<F>::GetCheckpointIdForUniquePendingId(QGetCheckpointIdForUniquePendingIdRPCRequest { unique_pending_id }),
            Option<u64>
        );
        match response.result {
            ResponseResult::Success(checkpoint_id) => {
                tracing::info!("get checkpoint_id: {:?}", checkpoint_id);
                Ok(checkpoint_id)
            }
            ResponseResult::Error(e) => Err(anyhow::format_err!("rpc call failed `{:?}`", e)),
        }
    }

    async fn generate_batch_proof_miner_reward_proofs_inner(
        &self,
        url: String,
        unique_pending_id: u64,
        job_ids: Vec<QProvingJobDataIDWithRewardPath>,
    ) -> anyhow::Result<Vec<PsyProoffMinerRewardProof<QHashOut<GoldilocksField>>>> {
        tracing::info!("generate_batch_proof_miner_reward_proofs with url {}: {}", url, unique_pending_id);
        let response = psy_rpc_call_back!(
            self,
            &url,
            RequestParams::<F>::GenerateBatchProofMinerRewardProofs(QGenerateBatchProofMinerRewardProofsRPCRequest { unique_pending_id, job_ids }),
            Vec<PsyProoffMinerRewardProof<QHashOut<GoldilocksField>>>
        );
        match response.result {
            ResponseResult::Success(proofs) => Ok(proofs),
            ResponseResult::Error(e) => Err(anyhow::format_err!("rpc call failed `{:?}`", e)),
        }
    }

    pub async fn get_coordinator_checkpoint_id_for_unique_pending_id(&self, unique_pending_id: u64) -> anyhow::Result<Option<u64>> {
        self.get_checkpoint_id_for_unique_pending_id_inner(self.get_coordinator_url()?, unique_pending_id)
            .await
    }

    pub async fn generate_coordinator_batch_proof_miner_reward_proofs(
        &self,
        unique_pending_id: u64,
        job_ids: Vec<QProvingJobDataIDWithRewardPath>,
    ) -> anyhow::Result<Vec<PsyProoffMinerRewardProof<QHashOut<GoldilocksField>>>> {
        self.generate_batch_proof_miner_reward_proofs_inner(self.get_coordinator_url()?, unique_pending_id, job_ids)
            .await
    }

    pub async fn get_realm_checkpoint_id_for_unique_pending_id(&self, unique_pending_id: u64) -> anyhow::Result<Option<u64>> {
        self.get_checkpoint_id_for_unique_pending_id_inner(self.get_realm_url(self.current_user_id)?.to_string(), unique_pending_id)
            .await
    }

    pub async fn get_realm_checkpoint_id_for_unique_pending_id_by_realm_id(
        &self,
        realm_id: u64,
        unique_pending_id: u64,
    ) -> anyhow::Result<Option<u64>> {
        self.get_checkpoint_id_for_unique_pending_id_inner(self.get_realm_url_by_realm_id(realm_id)?.to_string(), unique_pending_id)
            .await
    }

    pub async fn generate_realm_batch_proof_miner_reward_proofs(
        &self,
        unique_pending_id: u64,
        job_ids: Vec<QProvingJobDataIDWithRewardPath>,
    ) -> anyhow::Result<Vec<PsyProoffMinerRewardProof<QHashOut<GoldilocksField>>>> {
        self.generate_batch_proof_miner_reward_proofs_inner(self.get_realm_url(self.current_user_id)?.to_string(), unique_pending_id, job_ids)
            .await
    }

    pub async fn generate_realm_batch_proof_miner_reward_proofs_by_realm_id(
        &self,
        realm_id: u64,
        unique_pending_id: u64,
        job_ids: Vec<QProvingJobDataIDWithRewardPath>,
    ) -> anyhow::Result<Vec<PsyProoffMinerRewardProof<QHashOut<GoldilocksField>>>> {
        self.generate_batch_proof_miner_reward_proofs_inner(self.get_realm_url_by_realm_id(realm_id)?.to_string(), unique_pending_id, job_ids)
            .await
    }
}

// Re-export NetworkConfig from psy_config
pub use psy_config::{CoordinatorConfig, NetworkConfig, RealmConfig};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoreConfig {
    pub coordinator_store_path: String,
    pub realm_store_path: String,
}

pub type Config = psy_config::PsyConfigGoldilocks;

// type C = PoseidonGoldilocksConfig;
// const D: usize = 2;
// type F = <C as GenericConfig<D>>::F;

#[derive(Clone, Debug)]
pub struct ProveProxyRpcProvider<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub client: Arc<Client>,
    pub proof_proxy_url: String,
    pub common_circuits_data: LocalCommonCircuitsData<C::F>,
    pub zk_sign_inner_circuit: PsyBasicZKSignatureInnerCircuit<C, D>,
    pub _marker: PhantomData<C>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct QCommonCircuitData<F: RichField> {
    pub fingerprint: QHashOut<F>,
    pub verifier_config: AltVerifierOnlyCircuitData<F>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct LocalCommonCircuitsData<F: RichField> {
    pub ups_start: QCommonCircuitData<F>,
    pub ups_start_register_user: QCommonCircuitData<F>,
    pub ups_cfc_standard_tx: QCommonCircuitData<F>,
    pub ups_cfc_deferred_tx: QCommonCircuitData<F>,
    pub ups_end_cap: QCommonCircuitData<F>,
    pub zk_circuit: QCommonCircuitData<F>,
    pub secp_circuit: QCommonCircuitData<F>,

    pub ups_circuit_whitelist_root: QHashOut<F>,
    pub ups_start_whitelist_proof: MerkleProofCore<QHashOut<F>>,
    pub ups_start_register_user_whitelist_proof: MerkleProofCore<QHashOut<F>>,
    pub ups_cfc_standard_tx_whitelist_proof: MerkleProofCore<QHashOut<F>>,
    pub ups_cfc_deferred_tx_whitelist_proof: MerkleProofCore<QHashOut<F>>,

    // proof_tree_agg_circuits data
    pub single_leaf_circuit: QCommonCircuitData<F>,
    pub two_leaf_circuit: QCommonCircuitData<F>,
    pub two_agg_circuit: QCommonCircuitData<F>,
    pub left_leaf_right_agg_circuit: QCommonCircuitData<F>,
    pub left_agg_right_leaf_circuit: QCommonCircuitData<F>,
    pub leaf_circuit_config_id: u64,
    pub leaf_verifier_data_cap_height: usize,
    pub agg_verifier_data_cap_height: usize,

    pub circuit_inclusion_proofs: SimpleQTreeRecursionManagerInclusionProofs<F>,
}

// Async version of new_with_config
#[maybe_async::async_impl]
impl<C: GenericConfig<D> + 'static, const D: usize> ProveProxyRpcProvider<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub async fn new_with_config(proof_proxy_url: String) -> anyhow::Result<Self> {
        let client = Client::new();

        let response = client
            .post(&proof_proxy_url)
            .json(&RpcRequest {
                jsonrpc: Version::V2,
                request: RequestParams::<C::F>::GetCircuitsData(),
                id: Id::Number(1),
            })
            .send()
            .await?
            .json::<RpcResponse<String>>()
            .await?;

        let common_circuits_data = match response.result {
            ResponseResult::Success(common_circuits_data) => {
                tracing::info!("get common_circuits_data");
                serde_json::from_str(&common_circuits_data)?
            }
            ResponseResult::Error(e) => return Err(anyhow::format_err!("rpc call failed `{:?}`", e)),
        };

        Ok(Self {
            client: Arc::new(client),
            common_circuits_data,
            zk_sign_inner_circuit: PsyBasicZKSignatureInnerCircuit::new(),
            proof_proxy_url,
            _marker: PhantomData,
        })
    }
}

// Sync version of new_with_config
#[maybe_async::sync_impl]
impl<C: GenericConfig<D> + 'static, const D: usize> ProveProxyRpcProvider<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new_with_config(proof_proxy_url: String) -> anyhow::Result<Self> {
        let blocking_client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(360))
            .build()
            .map_err(|e| anyhow::format_err!("Failed to create blocking client: {}", e))?;

        let response = blocking_client
            .post(&proof_proxy_url)
            .json(&RpcRequest {
                jsonrpc: Version::V2,
                request: RequestParams::<C::F>::GetCircuitsData(),
                id: Id::Number(1),
            })
            .send()
            .map_err(|e| anyhow::format_err!("Failed to send request: {}", e))?
            .json::<RpcResponse<String>>()
            .map_err(|e| anyhow::format_err!("Failed to parse JSON response: {}", e))?;

        let common_circuits_data = match response.result {
            ResponseResult::Success(common_circuits_data) => {
                tracing::info!("get common_circuits_data");
                serde_json::from_str(&common_circuits_data)?
            }
            ResponseResult::Error(e) => return Err(anyhow::format_err!("rpc call failed `{:?}`", e)),
        };

        let client = Client::new();
        Ok(Self {
            client: Arc::new(client),
            common_circuits_data,
            zk_sign_inner_circuit: PsyBasicZKSignatureInnerCircuit::new(),
            proof_proxy_url,
            _marker: PhantomData,
        })
    }
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl<C: GenericConfig<D> + 'static, const D: usize> UPSCircuitManager<C, D> for ProveProxyRpcProvider<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    async fn register_info(&self, info_store: &mut SessionCircuitInfoStore<C::F>) {
        info_store.register_circuit(
            LocalCircuitType::UPSStart.into(),
            self.common_circuits_data.ups_start.fingerprint,
            self.common_circuits_data.ups_start.verifier_config.clone(),
        );
        info_store.register_circuit(
            LocalCircuitType::UPSStartRegisterUser.into(),
            self.common_circuits_data.ups_start_register_user.fingerprint,
            self.common_circuits_data.ups_start_register_user.verifier_config.clone(),
        );
        info_store.register_circuit(
            LocalCircuitType::UPSCFCStandard.into(),
            self.common_circuits_data.ups_cfc_standard_tx.fingerprint,
            self.common_circuits_data.ups_cfc_standard_tx.verifier_config.clone(),
        );
        info_store.register_circuit(
            LocalCircuitType::UPSCFCDeferred.into(),
            self.common_circuits_data.ups_cfc_deferred_tx.fingerprint,
            self.common_circuits_data.ups_cfc_deferred_tx.verifier_config.clone(),
        );
        info_store.register_circuit(
            LocalCircuitType::UPSEndCap.into(),
            self.common_circuits_data.ups_end_cap.fingerprint,
            self.common_circuits_data.ups_end_cap.verifier_config.clone(),
        );
        info_store.register_circuit(
            LocalCircuitType::UPSEndCap.into(),
            self.common_circuits_data.ups_end_cap.fingerprint,
            self.common_circuits_data.ups_end_cap.verifier_config.clone(),
        );

        info_store.register_whitelist_merkle_proof(
            LocalCircuitType::UPSStart.into(),
            self.common_circuits_data.ups_start_whitelist_proof.clone(),
        );
        info_store.register_whitelist_merkle_proof(
            LocalCircuitType::UPSStartRegisterUser.into(),
            self.common_circuits_data.ups_start_register_user_whitelist_proof.clone(),
        );
        info_store.register_whitelist_merkle_proof(
            LocalCircuitType::UPSCFCStandard.into(),
            self.common_circuits_data.ups_cfc_standard_tx_whitelist_proof.clone(),
        );
        info_store.register_whitelist_merkle_proof(
            LocalCircuitType::UPSCFCDeferred.into(),
            self.common_circuits_data.ups_cfc_deferred_tx_whitelist_proof.clone(),
        );

        info_store.register_circuit(
            LocalCircuitType::PTAggSingle.into(),
            self.common_circuits_data.single_leaf_circuit.fingerprint,
            self.common_circuits_data.single_leaf_circuit.verifier_config.clone(),
        );
        info_store.register_circuit(
            LocalCircuitType::PTAggTwoLeaf.into(),
            self.common_circuits_data.two_leaf_circuit.fingerprint,
            self.common_circuits_data.two_leaf_circuit.verifier_config.clone(),
        );
        info_store.register_circuit(
            LocalCircuitType::PTAggTwoAgg.into(),
            self.common_circuits_data.two_agg_circuit.fingerprint,
            self.common_circuits_data.two_agg_circuit.verifier_config.clone(),
        );
        info_store.register_circuit(
            LocalCircuitType::PTAggLeftAggRightLeaf.into(),
            self.common_circuits_data.left_agg_right_leaf_circuit.fingerprint,
            self.common_circuits_data.left_agg_right_leaf_circuit.verifier_config.clone(),
        );
        info_store.register_circuit(
            LocalCircuitType::PTAggLeftLeafRightAgg.into(),
            self.common_circuits_data.left_leaf_right_agg_circuit.fingerprint,
            self.common_circuits_data.left_leaf_right_agg_circuit.verifier_config.clone(),
        );

        info_store.register_whitelist_merkle_proof(
            LocalCircuitType::PTAggSingle.into(),
            self.common_circuits_data
                .circuit_inclusion_proofs
                .single_leaf_circuit_merkle_proof
                .clone(),
        );
        info_store.register_whitelist_merkle_proof(
            LocalCircuitType::PTAggTwoLeaf.into(),
            self.common_circuits_data.circuit_inclusion_proofs.two_leaf_circuit_merkle_proof.clone(),
        );
        info_store.register_whitelist_merkle_proof(
            LocalCircuitType::PTAggTwoAgg.into(),
            self.common_circuits_data.circuit_inclusion_proofs.two_agg_circuit_merkle_proof.clone(),
        );
        info_store.register_whitelist_merkle_proof(
            LocalCircuitType::PTAggLeftAggRightLeaf.into(),
            self.common_circuits_data
                .circuit_inclusion_proofs
                .left_agg_right_leaf_circuit_merkle_proof
                .clone(),
        );
        info_store.register_whitelist_merkle_proof(
            LocalCircuitType::PTAggLeftLeafRightAgg.into(),
            self.common_circuits_data
                .circuit_inclusion_proofs
                .left_leaf_right_agg_circuit_merkle_proof
                .clone(),
        );
    }

    async fn prove_ups_start(&self, input: &UPSStartStepInput<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        tracing::info!("prove ups start: {}", serde_json::to_string_pretty(&input)?);
        let response = psy_rpc_call_back!(
            self,
            &self.proof_proxy_url,
            RequestParams::<C::F>::ProveUpsStart(QProveUpsStartRPCRequest {
                input: input.clone(),
            }),
            ProofWithPublicInputs<C::F, C, D>
        );
        match response.result {
            ResponseResult::Success(proof) => {
                tracing::info!("get proof: {}", serde_json::to_string_pretty(&proof.public_inputs)?);
                Ok(proof)
            }
            ResponseResult::Error(e) => Err(anyhow::format_err!("rpc call failed `{:?}`", e)),
        }
    }

    async fn prove_ups_start_register_user(&self, input: &UPSStartStepRegisterUserInput<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        tracing::info!("prove ups start register user: {}", serde_json::to_string_pretty(&input)?);
        let response = psy_rpc_call_back!(
            self,
            &self.proof_proxy_url,
            RequestParams::<C::F>::ProveUpsStartRegisterUser(QProveUpsStartRegisterUserRPCRequest {
                input: input.clone(),
            }),
            ProofWithPublicInputs<C::F, C, D>
        );
        match response.result {
            ResponseResult::Success(proof) => {
                tracing::info!("get proof: {}", serde_json::to_string_pretty(&proof.public_inputs)?);
                Ok(proof)
            }
            ResponseResult::Error(e) => Err(anyhow::format_err!("rpc call failed `{:?}`", e)),
        }
    }

    async fn register_contract_circuits(&self, contract_id: u64, contract_code: &ContractCodeDefinition) -> anyhow::Result<()> {
        tracing::info!("register contract {} circuits", contract_id);
        let response = psy_rpc_call_back!(
            self,
            &self.proof_proxy_url,
            RequestParams::<C::F>::RegisterCircuits(QRegisterCircuitsRPCRequest {
                contract_id,
                contract_code: contract_code.clone(),
            }),
            ()
        );
        match response.result {
            ResponseResult::Success(_) => Ok(()),
            ResponseResult::Error(e) => Err(anyhow::format_err!("rpc call failed `{:?}`", e)),
        }
    }

    async fn get_fn_id(&self, contract_id: u64, method_name: String) -> anyhow::Result<u64> {
        tracing::info!("get method `{}` of contract {}", method_name, contract_id);
        let response = psy_rpc_call_back!(
            self,
            &self.proof_proxy_url,
            RequestParams::<C::F>::GetFnId(QGetFnIdRPCRequest { contract_id, method_name }),
            u64
        );
        match response.result {
            ResponseResult::Success(method_id) => {
                tracing::info!("get fn id `{}` of contract {}", method_id, contract_id);
                Ok(method_id)
            }
            ResponseResult::Error(e) => Err(anyhow::format_err!("rpc call failed `{:?}`", e)),
        }
    }

    async fn resolve_contract_function_by_method_name(
        &self,
        contract_id: u64,
        contract_code: &ContractCodeDefinition,
        method_name: String,
    ) -> anyhow::Result<(u64, DPNFunctionCircuitDefinition)> {
        tracing::info!("resolve method `{}` of contract {}", method_name, contract_id);
        let response = psy_rpc_call_back!(
            self,
            &self.proof_proxy_url,
            RequestParams::<C::F>::ResolveContractFunctionByMethodName(QResolveContractFunctionByMethodNameRPCRequest {
                contract_id,
                contract_code: contract_code.clone(),
                method_name
            }),
            (u64, DPNFunctionCircuitDefinition)
        );
        match response.result {
            ResponseResult::Success((fn_id, circuit_def)) => {
                tracing::info!("get fn id `{}` of contract {}", fn_id, contract_id);
                Ok((fn_id, circuit_def))
            }
            ResponseResult::Error(e) => Err(anyhow::format_err!("rpc call failed `{:?}`", e)),
        }
    }

    async fn resolve_contract_function_by_method_id(
        &self,
        contract_id: u64,
        contract_code: &ContractCodeDefinition,
        method_id: u32,
    ) -> anyhow::Result<(u64, DPNFunctionCircuitDefinition)> {
        tracing::info!("resolve method `{}` of contract {}", method_id, contract_id);
        let response = psy_rpc_call_back!(
            self,
            &self.proof_proxy_url,
            RequestParams::<C::F>::ResolveContractFunctionByMethodId(QResolveContractFunctionByMethodIdRPCRequest {
                contract_id,
                contract_code: contract_code.clone(),
                method_id
            }),
            (u64, DPNFunctionCircuitDefinition)
        );
        match response.result {
            ResponseResult::Success((fn_id, circuit_def)) => {
                tracing::info!("get fn id `{}` of contract {}", fn_id, contract_id);
                Ok((fn_id, circuit_def))
            }
            ResponseResult::Error(e) => Err(anyhow::format_err!("rpc call failed `{:?}`", e)),
        }
    }

    async fn get_contract_method_common_data(&self, contract_id: u64, fn_id: u32) -> anyhow::Result<(QHashOut<C::F>, VerifierOnlyCircuitData<C, D>)> {
        tracing::info!("get method `{}` common data of contract {}", fn_id, contract_id);
        let response = psy_rpc_call_back!(
            self,
            &self.proof_proxy_url,
            RequestParams::<C::F>::GetContractMethodCommonData(QGetContractMethodCommonDataRPCRequest { contract_id, fn_id }),
            QCommonCircuitData<C::F>
        );
        match response.result {
            ResponseResult::Success(data) => {
                tracing::info!(
                    "get fn id `{}` of contract {}, fingerprint: {}, common data: {}",
                    fn_id,
                    contract_id,
                    data.fingerprint.to_string(),
                    serde_json::to_string(&data.verifier_config)?,
                );
                Ok((data.fingerprint, data.verifier_config.to_verifier_data()))
            }
            ResponseResult::Error(e) => Err(anyhow::format_err!("rpc call failed `{:?}`", e)),
        }
    }

    async fn prove_contract_call(
        &self,
        contract_id: u64,
        fn_id: u32,
        input: &DapenContractFunctionCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        tracing::info!("prove contract call: {}", serde_json::to_string_pretty(&input)?);
        let response = psy_rpc_call_back!(
            self,
            &self.proof_proxy_url,
            RequestParams::<C::F>::ProveContractCall(QProveContractCallRPCRequest {
                contract_id,
                fn_id,
                input: input.clone(),
            }),
            ProofWithPublicInputs<C::F, C, D>
        );
        match response.result {
            ResponseResult::Success(proof) => {
                tracing::info!("get proof: {}", serde_json::to_string_pretty(&proof.public_inputs)?);
                Ok(proof)
            }
            ResponseResult::Error(e) => Err(anyhow::format_err!("rpc call failed `{:?}`", e)),
        }
    }

    async fn prove_ups_cfc_standard_tx(
        &self,
        input: &UPSCFCStandardTransactionCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        tracing::info!("prove ups cfc standard tx: {}", serde_json::to_string_pretty(&input)?);
        let response = psy_rpc_call_back!(
            self,
            &self.proof_proxy_url,
            RequestParams::<C::F>::UpsCfcStandardTx(QUpsCfcStandardTxRPCRequest {
                input: input.clone(),
            }),
            ProofWithPublicInputs<C::F, C, D>
        );
        match response.result {
            ResponseResult::Success(proof) => {
                tracing::info!("get proof: {}", serde_json::to_string_pretty(&proof.public_inputs)?);
                Ok(proof)
            }
            ResponseResult::Error(e) => Err(anyhow::format_err!("rpc call failed `{:?}`", e)),
        }
    }

    async fn prove_ups_cfc_deferred_tx(
        &self,
        input: &UPSCFCDeferredTransactionCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        tracing::info!("prove ups cfc deferred tx: {}", serde_json::to_string_pretty(&input)?);
        let response = psy_rpc_call_back!(
            self,
            &self.proof_proxy_url,
            RequestParams::<C::F>::UpsCfcDeferredTx(QUpsCfcDeferredTxRPCRequest {
                input: input.clone(),
            }),
            ProofWithPublicInputs<C::F, C, D>
        );
        match response.result {
            ResponseResult::Success(proof) => {
                tracing::info!("get proof: {}", serde_json::to_string_pretty(&proof.public_inputs)?);
                Ok(proof)
            }
            ResponseResult::Error(e) => Err(anyhow::format_err!("rpc call failed `{:?}`", e)),
        }
    }

    async fn prove_zk_sign(&self, private_key: QHashOut<C::F>, sig_hash: QHashOut<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        tracing::info!("prove_zk_sign: {}", sig_hash.to_string());
        let inner_proof = self.zk_sign_inner_circuit.prove_base(private_key, sig_hash)?;
        let inner_proof_str = serde_json::to_string(&inner_proof)?;

        let response = psy_rpc_call_back!(
            self,
            &self.proof_proxy_url,
            RequestParams::<C::F>::ZKSignatureMinifierProof(QSignatureMinifierProofRPCRequest {
                inner_proof: inner_proof_str,
            }),
            ProofWithPublicInputs<C::F, C, D>
        );
        match response.result {
            ResponseResult::Success(proof) => {
                tracing::info!("get proof: {}", serde_json::to_string_pretty(&proof.public_inputs)?);
                Ok(proof)
            }
            ResponseResult::Error(e) => Err(anyhow::format_err!("rpc call failed `{:?}`", e)),
        }
    }

    async fn prove_secp_sign(&self, signature: PsyCompressedSecp256K1Signature) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        tracing::info!("prove_secp_sign: {}", serde_json::to_string_pretty(&signature)?);
        let response = psy_rpc_call_back!(
            self,
            &self.proof_proxy_url,
            RequestParams::<C::F>::SECPSignatureProof(QSecpSignatureProofRPCRequest {
                signature,
            }),
            ProofWithPublicInputs<C::F, C, D>
        );
        match response.result {
            ResponseResult::Success(proof) => {
                tracing::info!("get proof: {}", serde_json::to_string_pretty(&proof.public_inputs)?);
                Ok(proof)
            }
            ResponseResult::Error(e) => Err(anyhow::format_err!("rpc call failed `{:?}`", e)),
        }
    }

    async fn register_dpn_software_defined_circuit(
        &self,
        fn_def: psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition,
        contract_id: u64,
        contract_state_tree_height: u8,
        session_proof_tree_height: u8,
        force_four_align: bool,
    ) -> anyhow::Result<QHashOut<C::F>> {
        tracing::info!("register_dpn_software_defined_circuit: ");
        let request = QRegisterDPNSoftwareDefinedCircuitRPCRequest {
            fn_def,
            contract_id,
            contract_state_tree_height,
            session_proof_tree_height,
            force_four_align,
        };
        let response = psy_rpc_call_back!(
            self,
            &self.proof_proxy_url,
            RequestParams::<C::F>::RegisterDPNSoftwareDefinedCircuit(request),
            QHashOut<C::F>
        );
        match response.result {
            ResponseResult::Success(fingerprint) => {
                tracing::info!("get sdc fingerprint: {}", fingerprint.to_string());
                Ok(fingerprint)
            }
            ResponseResult::Error(e) => Err(anyhow::format_err!("rpc call failed `{:?}`", e)),
        }
    }

    async fn register_plonky2_software_defined_circuit(&self, contract_state_tree_height: u8, input_len: usize) -> anyhow::Result<QHashOut<C::F>> {
        tracing::info!("register_plonky2_software_defined_circuit: ");
        let request = QRegisterPlonky2SoftwareDefinedCircuitRPCRequest {
            contract_state_tree_height,
            input_len,
        };
        let response = psy_rpc_call_back!(
            self,
            &self.proof_proxy_url,
            RequestParams::<C::F>::RegisterPlonky2SoftwareDefinedCircuit(request),
            QHashOut<C::F>
        );
        match response.result {
            ResponseResult::Success(fingerprint) => {
                tracing::info!("get plonky2 sdc fingerprint: {}", fingerprint.to_string());
                Ok(fingerprint)
            }
            ResponseResult::Error(e) => Err(anyhow::format_err!("rpc call failed `{:?}`", e)),
        }
    }

    async fn prove_dpn_software_defined_sign(
        &self,
        fingerprint: QHashOut<C::F>,
        private_key: QHashOut<C::F>,
        input: psy_vm::ups::signature::DPNSoftwareDefinedSignatureInput,
        sig_hash: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        tracing::info!("prove_dpn_software_defined_sign:");
        let response = psy_rpc_call_back!(
            self,
            &self.proof_proxy_url,
            RequestParams::<C::F>::DPNSoftwareDefinedSignatureProof(DPNSoftwareDefinedSignatureProofRPCRequest {
                fingerprint,
                private_key,
                input,
                sig_hash,
            }),
            ProofWithPublicInputs<C::F, C, D>
        );
        match response.result {
            ResponseResult::Success(proof) => {
                tracing::info!("get proof: {}", serde_json::to_string_pretty(&proof.public_inputs)?);
                Ok(proof)
            }
            ResponseResult::Error(e) => Err(anyhow::format_err!("rpc call failed `{:?}`", e)),
        }
    }

    async fn prove_plonky2_software_defined_sign(
        &self,
        _fingerprint: QHashOut<C::F>,
        _private_key: QHashOut<C::F>,
        _input: psy_vm::ups::signature::Plonky2SoftwareDefinedSignatureInput,
        _sig_hash: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        tracing::info!("prove_plonky2_software_defined_sign:");
        // Now that we have StateReaderResults which can be serialized, this can be
        // implemented For now, return an error until the RPC request is
        // implemented
        Err(anyhow::format_err!("plonky2 software defined sign not yet implemented over RPC"))
    }

    async fn prove_ups_end_cap(
        &self,
        _circuit_info: &SessionCircuitInfoStore<C::F>,
        end_cap_from_proof_tree_input: &UPSEndCapFromProofTreeGadgetInput<C::F>,
        agg_proof_record: &AggProofRecord<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        tracing::info!("prove ups end cap: {}", serde_json::to_string_pretty(&end_cap_from_proof_tree_input)?);
        let response = psy_rpc_call_back!(
            self,
            &self.proof_proxy_url,
            RequestParamsV2::<C, D>::UpsEndCap(QUpsEndCapRPCRequestV2 {
                end_cap_from_proof_tree_input: end_cap_from_proof_tree_input.clone(),
                circuit_type: agg_proof_record.circuit_type,
                fingerprint: agg_proof_record.fingerprint,
                agg_header: agg_proof_record.agg_header,
                proof: agg_proof_record.proof.clone(),
            }),
            ProofWithPublicInputs<C::F, C, D>
        );
        match response.result {
            ResponseResult::Success(proof) => {
                tracing::info!("get proof: {}", serde_json::to_string_pretty(&proof.public_inputs)?);
                Ok(proof)
            }
            ResponseResult::Error(e) => Err(anyhow::format_err!("rpc call failed `{:?}`", e)),
        }
    }

    async fn ups_start_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        Ok(self.common_circuits_data.ups_start.fingerprint)
    }

    async fn ups_start_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        Ok(self.common_circuits_data.ups_start.verifier_config.clone().to_verifier_data())
    }

    async fn ups_start_register_user_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        Ok(self.common_circuits_data.ups_start_register_user.fingerprint)
    }

    async fn ups_start_register_user_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        Ok(self
            .common_circuits_data
            .ups_start_register_user
            .verifier_config
            .clone()
            .to_verifier_data())
    }

    async fn ups_cfc_standard_tx_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        Ok(self.common_circuits_data.ups_cfc_standard_tx.fingerprint)
    }

    async fn ups_cfc_standard_tx_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        Ok(self.common_circuits_data.ups_cfc_standard_tx.verifier_config.clone().to_verifier_data())
    }

    async fn ups_cfc_deferred_tx_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        Ok(self.common_circuits_data.ups_cfc_deferred_tx.fingerprint)
    }

    async fn ups_cfc_deferred_tx_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        Ok(self
            .common_circuits_data
            .ups_cfc_deferred_tx
            .verifier_config
            .clone()
            .to_verifier_data::<C, D>())
    }

    async fn ups_end_cap_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        Ok(self.common_circuits_data.ups_end_cap.fingerprint)
    }

    async fn ups_end_cap_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        Ok(self.common_circuits_data.ups_end_cap.verifier_config.to_verifier_data())
    }

    async fn ups_circuit_whitelist_root(&self) -> anyhow::Result<QHashOut<C::F>> {
        Ok(self.common_circuits_data.ups_circuit_whitelist_root)
    }

    async fn zk_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        Ok(self.common_circuits_data.zk_circuit.fingerprint)
    }

    async fn zk_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        Ok(self.common_circuits_data.zk_circuit.verifier_config.clone().to_verifier_data())
    }

    async fn secp_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>> {
        Ok(self.common_circuits_data.secp_circuit.fingerprint)
    }

    async fn secp_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        Ok(self.common_circuits_data.secp_circuit.verifier_config.clone().to_verifier_data())
    }
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl<C: GenericConfig<D>, const D: usize> PortableQTreeRecursionCircuitsData<C, D> for ProveProxyRpcProvider<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    async fn single_leaf_circuit_fingerprint(&self) -> QHashOut<C::F> {
        self.common_circuits_data.single_leaf_circuit.fingerprint
    }
    async fn two_leaf_circuit_fingerprint(&self) -> QHashOut<C::F> {
        self.common_circuits_data.two_leaf_circuit.fingerprint
    }
    async fn two_agg_circuit_fingerprint(&self) -> QHashOut<C::F> {
        self.common_circuits_data.two_agg_circuit.fingerprint
    }
    async fn left_leaf_right_agg_circuit_fingerprint(&self) -> QHashOut<C::F> {
        self.common_circuits_data.left_leaf_right_agg_circuit.fingerprint
    }
    async fn left_agg_right_leaf_circuit_fingerprint(&self) -> QHashOut<C::F> {
        self.common_circuits_data.left_agg_right_leaf_circuit.fingerprint
    }
    async fn single_leaf_circuit_verifier_config(&self) -> VerifierOnlyCircuitData<C, D> {
        self.common_circuits_data.single_leaf_circuit.verifier_config.clone().to_verifier_data()
    }
    async fn two_leaf_circuit_verifier_config(&self) -> VerifierOnlyCircuitData<C, D> {
        self.common_circuits_data.two_leaf_circuit.verifier_config.clone().to_verifier_data()
    }
    async fn two_agg_circuit_verifier_config(&self) -> VerifierOnlyCircuitData<C, D> {
        self.common_circuits_data.two_agg_circuit.verifier_config.clone().to_verifier_data()
    }
    async fn left_leaf_right_agg_circuit_verifier_config(&self) -> VerifierOnlyCircuitData<C, D> {
        self.common_circuits_data
            .left_leaf_right_agg_circuit
            .verifier_config
            .clone()
            .to_verifier_data()
    }
    async fn left_agg_right_leaf_circuit_verifier_config(&self) -> VerifierOnlyCircuitData<C, D> {
        self.common_circuits_data
            .left_agg_right_leaf_circuit
            .verifier_config
            .clone()
            .to_verifier_data()
    }
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl<C: GenericConfig<D> + 'static, const D: usize> PortableQTreeRecursionCircuitsProve<C, D> for ProveProxyRpcProvider<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    async fn get_verifier_data_by_type(&self, circuit_type: QStandardBinaryTreeCircuitType) -> VerifierOnlyCircuitData<C, D> {
        match circuit_type {
            QStandardBinaryTreeCircuitType::None => {
                panic!("tried to get verifier data for a circuit with type None")
            }
            QStandardBinaryTreeCircuitType::SingleLeaf => self.common_circuits_data.single_leaf_circuit.verifier_config.clone().to_verifier_data(),
            QStandardBinaryTreeCircuitType::TwoLeaf => self.common_circuits_data.two_leaf_circuit.verifier_config.clone().to_verifier_data(),
            QStandardBinaryTreeCircuitType::TwoAgg => self.common_circuits_data.two_agg_circuit.verifier_config.clone().to_verifier_data(),
            QStandardBinaryTreeCircuitType::LeftLeafRightAgg => self
                .common_circuits_data
                .left_leaf_right_agg_circuit
                .verifier_config
                .clone()
                .to_verifier_data(),
            QStandardBinaryTreeCircuitType::LeftAggRightLeaf => self
                .common_circuits_data
                .left_agg_right_leaf_circuit
                .verifier_config
                .clone()
                .to_verifier_data(),
            QStandardBinaryTreeCircuitType::Root => {
                panic!("tried to get verifier data for a circuit with type Root")
            }
        }
    }
    async fn prove_single_leaf_circuit(
        &self,
        agg_circuit_whitelist_root: QHashOut<C::F>,
        single_insert_leaf_proof: &DeltaMerkleProofCore<QHashOut<C::F>>,
        single_proof: &ProofWithPublicInputs<C::F, C, D>,
        single_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        tracing::info!(
            "prove single leaf circuit: {}",
            serde_json::to_string_pretty(&agg_circuit_whitelist_root)?
        );
        // todo fix bug
        let response = psy_rpc_call_back!(
            self,
            &self.proof_proxy_url,
            RequestParamsV2::<C,D>::SingleLeaf(QSingleLeafRpcRequestV2 {
                agg_circuit_whitelist_root,
                single_insert_leaf_proof: single_insert_leaf_proof.clone(),
                single_proof: single_proof.clone(),
                single_verifier_data: single_verifier_data.into(),
            }),
            ProofWithPublicInputs<C::F, C, D>
        );
        match response.result {
            ResponseResult::Success(proof) => {
                tracing::info!("get proof: {}", serde_json::to_string_pretty(&proof.public_inputs)?);
                Ok(proof)
            }
            ResponseResult::Error(e) => Err(anyhow::format_err!("rpc call failed `{:?}`", e)),
        }
    }
    async fn prove_two_leaf_circuit(
        &self,
        agg_circuit_whitelist_root: QHashOut<C::F>,
        left_insert_leaf_proof: &DeltaMerkleProofCore<QHashOut<C::F>>,
        left_proof: &ProofWithPublicInputs<C::F, C, D>,
        left_verifier_data: &VerifierOnlyCircuitData<C, D>,
        right_insert_leaf_proof: &DeltaMerkleProofCore<QHashOut<C::F>>,
        right_proof: &ProofWithPublicInputs<C::F, C, D>,
        right_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        tracing::info!("prove two leaf circuit: {}", serde_json::to_string_pretty(&agg_circuit_whitelist_root)?);
        let response = psy_rpc_call_back!(
            self,
            &self.proof_proxy_url,
            RequestParamsV2::<C,D>::TwoLeaf(QTwoLeafRpcRequestV2{
                agg_circuit_whitelist_root,
                left_insert_leaf_proof: left_insert_leaf_proof.clone(),
                left_proof: left_proof.clone(),
                left_verifier_data: left_verifier_data.into(),
                right_insert_leaf_proof: right_insert_leaf_proof.clone(),
                right_proof: right_proof.clone(),
                right_verifier_data: right_verifier_data.into(),
            }),
            ProofWithPublicInputs<C::F, C, D>
        );
        match response.result {
            ResponseResult::Success(proof) => {
                tracing::info!("get proof: {}", serde_json::to_string_pretty(&proof.public_inputs)?);
                Ok(proof)
            }
            ResponseResult::Error(e) => Err(anyhow::format_err!("rpc call failed `{:?}`", e)),
        }
    }
    async fn prove_two_agg_circuit(
        &self,
        left_agg_whitelist_merkle_proof: &MerkleProofCore<QHashOut<C::F>>,
        left_agg_proof_header: &QRecursionAggStandardHeader<C::F>,
        left_proof: &ProofWithPublicInputs<C::F, C, D>,
        left_verifier_data: &VerifierOnlyCircuitData<C, D>,
        right_agg_whitelist_merkle_proof: &MerkleProofCore<QHashOut<C::F>>,
        right_agg_proof_header: &QRecursionAggStandardHeader<C::F>,
        right_proof: &ProofWithPublicInputs<C::F, C, D>,
        right_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        tracing::info!("prove two agg circuit:");
        let response = psy_rpc_call_back!(
            self,
            &self.proof_proxy_url,
            RequestParamsV2::<C,D>::TwoAgg(QTwoAggRpcRequsetV2{
                left_agg_whitelist_merkle_proof: left_agg_whitelist_merkle_proof.clone(),
                left_agg_proof_header: left_agg_proof_header.clone(),
                left_proof: left_proof.clone(),
                left_verifier_data: left_verifier_data.into(),
                right_agg_whitelist_merkle_proof: right_agg_whitelist_merkle_proof.clone(),
                right_agg_proof_header: right_agg_proof_header.clone(),
                right_proof: right_proof.clone(),
                right_verifier_data: right_verifier_data.into(),
            }),
            ProofWithPublicInputs<C::F, C, D>
        );
        match response.result {
            ResponseResult::Success(proof) => {
                tracing::info!("get proof: {}", serde_json::to_string_pretty(&proof.public_inputs)?);
                Ok(proof)
            }
            ResponseResult::Error(e) => Err(anyhow::format_err!("rpc call failed `{:?}`", e)),
        }
    }
    async fn prove_left_leaf_right_agg_circuit(
        &self,
        left_insert_leaf_proof: &DeltaMerkleProofCore<QHashOut<C::F>>,
        left_proof: &ProofWithPublicInputs<C::F, C, D>,
        left_verifier_data: &VerifierOnlyCircuitData<C, D>,
        right_agg_whitelist_merkle_proof: &MerkleProofCore<QHashOut<C::F>>,
        right_agg_proof_header: &QRecursionAggStandardHeader<C::F>,
        right_proof: &ProofWithPublicInputs<C::F, C, D>,
        right_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        tracing::info!("prove leaf leaf right agg circuit:");
        let response = psy_rpc_call_back!(
            self,
            &self.proof_proxy_url,
            RequestParamsV2::<C, D>::LeftLeafRightAgg(QLeftLeafRightAggRpcRequestV2{
                left_insert_leaf_proof: left_insert_leaf_proof.clone(),
                left_proof: left_proof.clone(),
                left_verifier_data: left_verifier_data.into(),
                right_agg_whitelist_merkle_proof: right_agg_whitelist_merkle_proof.clone(),
                right_agg_proof_header: right_agg_proof_header.clone(),
                right_proof: right_proof.clone(),
                right_verifier_data: right_verifier_data.into(),
            }),
            ProofWithPublicInputs<C::F, C, D>
        );
        match response.result {
            ResponseResult::Success(proof) => {
                tracing::info!("get proof: {}", serde_json::to_string_pretty(&proof.public_inputs)?);
                Ok(proof)
            }
            ResponseResult::Error(e) => Err(anyhow::format_err!("rpc call failed `{:?}`", e)),
        }
    }
    async fn prove_left_agg_right_leaf_circuit(
        &self,
        left_agg_whitelist_merkle_proof: &MerkleProofCore<QHashOut<C::F>>,
        left_agg_proof_header: &QRecursionAggStandardHeader<C::F>,
        left_proof: &ProofWithPublicInputs<C::F, C, D>,
        left_verifier_data: &VerifierOnlyCircuitData<C, D>,
        right_insert_leaf_proof: &DeltaMerkleProofCore<QHashOut<C::F>>,
        right_proof: &ProofWithPublicInputs<C::F, C, D>,
        right_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        tracing::info!("prove left agg right leaf circuit:");
        let response = psy_rpc_call_back!(
            self,
            &self.proof_proxy_url,
            RequestParamsV2::<C,D>::LeftAggRightLeaf(QLeftAggRightLeafRpcRequestV2{
                left_agg_whitelist_merkle_proof: left_agg_whitelist_merkle_proof.clone(),
                left_agg_proof_header: left_agg_proof_header.clone(),
                left_proof: left_proof.clone(),
                left_verifier_data: left_verifier_data.into(),
                right_insert_leaf_proof: right_insert_leaf_proof.clone(),
                right_proof: right_proof.clone(),
                right_verifier_data: right_verifier_data.into(),
            }),
            ProofWithPublicInputs<C::F, C, D>
        );
        match response.result {
            ResponseResult::Success(proof) => {
                tracing::info!("get proof: {}", serde_json::to_string_pretty(&proof.public_inputs)?);
                Ok(proof)
            }
            ResponseResult::Error(e) => Err(anyhow::format_err!("rpc call failed `{:?}`", e)),
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl<C: GenericConfig<D> + 'static, const D: usize> PortableQTreeRecursion<C, D> for ProveProxyRpcProvider<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    async fn circuit_inclusion_proofs(&self) -> &SimpleQTreeRecursionManagerInclusionProofs<C::F> {
        &self.common_circuits_data.circuit_inclusion_proofs
    }
}
