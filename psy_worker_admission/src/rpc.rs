use std::sync::Arc;

use jsonrpsee::{core::RpcResult, proc_macros::rpc, types::ErrorObjectOwned, RpcModule};
use serde::{Deserialize, Serialize};

use crate::{protocol::*, redis_store::RedisAdmissionStore, service::*, AdmissionError as Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionInfo {
    pub protocol_version: u16,
    pub mode: String,
    pub task_enforcement: bool,
    pub scope: AdmissionScope,
    pub algorithm: String,
    pub policy_version: u32,
    pub base_bits: u16,
}

#[rpc(server, client, namespace = "psy_worker")]
pub trait WorkerAdmissionRpc {
    #[method(name = "get_admission_info")]
    async fn get_admission_info(&self) -> RpcResult<AdmissionInfo>;
    #[method(name = "get_admission_status")]
    async fn get_admission_status(&self, auth: RequestAuth) -> RpcResult<AdmissionStatus>;
    #[method(name = "get_pow_challenge")]
    async fn get_pow_challenge(&self, auth: RequestAuth) -> RpcResult<ChallengeResponse>;
    #[method(name = "submit_pow")]
    async fn submit_pow(&self, auth: RequestAuth, solution: PowSolution) -> RpcResult<ActivationResponse>;
    #[method(name = "get_request_status")]
    async fn get_request_status(&self, auth: RequestAuth, request_id: RequestId) -> RpcResult<RequestStatusResponse>;
}

#[derive(Clone)]
pub struct AdmissionRpc { service: AdmissionService }

impl AdmissionRpc {
    pub fn new(service: AdmissionService) -> Self { Self { service } }
}

fn rpc_error(error: Error) -> ErrorObjectOwned {
    let retry_after_ms = match &error {
        Error::Cooldown { retry_after_ms } | Error::RateLimited { retry_after_ms } => Some(retry_after_ms.to_string()),
        _ => None,
    };
    // Stable categories, no URLs, database internals or credentials in errors.
    let code = match &error {
        Error::InvalidRequest | Error::InvalidSignature => -32100,
        Error::RequestExpired => -32101,
        Error::AdmissionStale => -32102,
        Error::PowRequired => -32103,
        Error::AlreadyActive => -32104,
        Error::Cooldown { .. } => -32105,
        Error::ChallengeStale => -32106,
        Error::ChallengeExpired => -32107,
        Error::InvalidPow => -32108,
        Error::RateLimited { .. } => -32109,
        Error::RequestConflict => -32110,
        Error::StoreUnavailable | Error::StateCorrupt | Error::ConfigMismatch => -32111,
        Error::Capacity => -32112,
        Error::UnsupportedProtocol => -32113,
        Error::LeaseStale => -32114,
        Error::LeaseBusy => -32115,
        Error::InflightLimit => -32116,
        Error::JobAlreadyAccepted => -32117,
    };
    ErrorObjectOwned::owned(code, error.to_string(), Some(serde_json::json!({
        "category": error.to_string(), "retry_after_ms": retry_after_ms,
    })))
}

#[jsonrpsee::core::async_trait]
impl WorkerAdmissionRpcServer for AdmissionRpc {
    async fn get_admission_info(&self) -> RpcResult<AdmissionInfo> {
        Ok(AdmissionInfo { protocol_version: 1, mode: "observe".into(), task_enforcement: false,
            scope: self.service.scope().clone(), algorithm: "sha256".into(),
            policy_version: self.service.policy().version, base_bits: self.service.policy().base_bits })
    }
    async fn get_admission_status(&self, auth: RequestAuth) -> RpcResult<AdmissionStatus> {
        self.service.get_status(auth).await.map_err(rpc_error)
    }
    async fn get_pow_challenge(&self, auth: RequestAuth) -> RpcResult<ChallengeResponse> {
        self.service.get_challenge(auth).await.map_err(rpc_error)
    }
    async fn submit_pow(&self, auth: RequestAuth, solution: PowSolution) -> RpcResult<ActivationResponse> {
        self.service.submit_pow(auth, solution).await.map_err(rpc_error)
    }
    async fn get_request_status(&self, auth: RequestAuth, request_id: RequestId) -> RpcResult<RequestStatusResponse> {
        self.service.get_request_status(auth, request_id).await.map_err(rpc_error)
    }
}

/// Off by default. A future enforced rollout must not be selectable before the
/// task lease/outbox implementation exists. Both edge types call this helper.
pub async fn observe_rpc_from_env(node_type: u8, realm_id: u32, realm_sub_id: u16) -> Result<Option<RpcModule<AdmissionRpc>>> {
    let value = |key: &str| std::env::var(key).map_err(|_| Error::InvalidRequest);
    let mode = match std::env::var("PSY_WORKER_ADMISSION_MODE") {
        Ok(mode) => mode,
        Err(std::env::VarError::NotPresent) => "off".into(),
        Err(_) => return Err(Error::InvalidRequest),
    };
    validate_mode(&mode)?;
    if mode == "off" { return Ok(None); }
    let network_id = serde_json::from_value(serde_json::Value::String(value("PSY_WORKER_ADMISSION_NETWORK_ID")?)).map_err(|_| Error::InvalidRequest)?;
    let admission_epoch = serde_json::from_value(serde_json::Value::String(value("PSY_WORKER_ADMISSION_EPOCH")?)).map_err(|_| Error::InvalidRequest)?;
    let base_bits = value("PSY_WORKER_ADMISSION_BASE_BITS")?.parse().map_err(|_| Error::InvalidRequest)?;
    let scope = AdmissionScope { network_id, admission_epoch, node_type, realm_id, realm_sub_id };
    let policy = AdmissionPolicy::for_base_bits(base_bits);
    let store = RedisAdmissionStore::connect(&value("PSY_WORKER_ADMISSION_REDIS_URL")?, &scope, &policy).await?;
    let service = AdmissionService::new(scope, policy, Arc::new(store))?;
    Ok(Some(AdmissionRpc::new(service).into_rpc()))
}

pub fn validate_mode(mode: &str) -> Result<()> {
    match mode { "off" | "observe" => Ok(()), _ => Err(Error::UnsupportedProtocol) }
}
