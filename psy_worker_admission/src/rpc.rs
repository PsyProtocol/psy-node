use std::sync::Arc;

use jsonrpsee::{core::RpcResult, proc_macros::rpc, types::ErrorObjectOwned, RpcModule};
use serde::{Deserialize, Serialize};

use crate::{flow::*, lease::*, protocol::*, redis_store::RedisAdmissionStore, service::*, AdmissionError as Error, LeaseService, Result};

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimTaskResponse {
    pub claim: ClaimRecord,
    pub lease: LeaseRecord,
    /// The legacy work response with child proofs, for the prover.
    pub task: serde_json::Value,
}

/// V2 task protocol. Signed method 5 claims, method 6 submits.
#[rpc(server, client, namespace = "psy_worker")]
pub trait WorkerTaskRpc {
    #[method(name = "claim_task_v2")]
    async fn claim_task_v2(&self, auth: RequestAuth, request: ClaimRequest) -> RpcResult<ClaimTaskResponse>;
    #[method(name = "submit_proof_v2")]
    async fn submit_proof_v2(&self, auth: RequestAuth, submission: ProofSubmission, proof: HexBytes) -> RpcResult<SubmitOutcome>;
}

pub struct TaskRpc<Q, P> { flow: TaskFlow<Q, P> }

impl<Q, P> TaskRpc<Q, P> {
    pub fn new(flow: TaskFlow<Q, P>) -> Self { Self { flow } }
}

#[jsonrpsee::core::async_trait]
impl<Q: TaskQueue + 'static, P: ProofPipeline + 'static> WorkerTaskRpcServer for TaskRpc<Q, P> {
    async fn claim_task_v2(&self, auth: RequestAuth, request: ClaimRequest) -> RpcResult<ClaimTaskResponse> {
        let task = self.flow.claim(auth, request).await.map_err(rpc_error)?;
        let body = serde_json::from_slice(&task.payload).map_err(|_| rpc_error(Error::TaskInfrastructure))?;
        Ok(ClaimTaskResponse { claim: task.claim, lease: task.lease, task: body })
    }
    async fn submit_proof_v2(&self, auth: RequestAuth, submission: ProofSubmission, proof: HexBytes) -> RpcResult<SubmitOutcome> {
        self.flow.submit(auth, submission, proof.0).await.map_err(rpc_error)
    }
}

/// Admission settings shared by every edge of one scope, read from the environment.
#[derive(Debug, Clone)]
pub struct AdmissionEnv {
    pub scope: AdmissionScope,
    pub policy: AdmissionPolicy,
    redis_url: String,
    /// `PSY_WORKER_ADMISSION_TASKS=v2`: also serve the V2 task protocol.
    pub tasks_v2: bool,
}

impl AdmissionEnv {
    /// None when admission is off, the default.
    pub fn from_env(node_type: u8, realm_id: u32, realm_sub_id: u16) -> Result<Option<Self>> {
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
        let tasks_v2 = match std::env::var("PSY_WORKER_ADMISSION_TASKS").as_deref() {
            Err(std::env::VarError::NotPresent) | Ok("off") => false,
            Ok("v2") => true,
            _ => return Err(Error::UnsupportedProtocol),
        };
        let scope = AdmissionScope { network_id, admission_epoch, node_type, realm_id, realm_sub_id };
        scope.validate()?;
        Ok(Some(Self { scope, policy: AdmissionPolicy::for_base_bits(base_bits), redis_url: value("PSY_WORKER_ADMISSION_REDIS_URL")?, tasks_v2 }))
    }
    pub async fn connect(&self) -> Result<RedisAdmissionStore> {
        RedisAdmissionStore::connect(&self.redis_url, &self.scope, &self.policy).await
    }
    pub fn admission_rpc(&self, store: RedisAdmissionStore) -> Result<RpcModule<AdmissionRpc>> {
        Ok(AdmissionRpc::new(AdmissionService::new(self.scope.clone(), self.policy.clone(), Arc::new(store))?).into_rpc())
    }
    pub fn lease_service(&self, store: RedisAdmissionStore) -> Result<LeaseService> {
        LeaseService::new(self.scope.clone(), self.policy.clone(), Arc::new(store))
    }
}

/// Reclaim, keep alive and publish forever. Errors are logged, never fatal:
/// a stalled loop only delays reclaiming, it cannot grant anything.
pub async fn run_maintenance<Q: TaskQueue + 'static, P: ProofPipeline + 'static>(flow: TaskFlow<Q, P>, interval: std::time::Duration) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        match flow.maintain(256).await {
            Ok(report) if report != MaintenanceReport::default() => tracing::info!(?report, "worker task maintenance"),
            Ok(_) => {}
            Err(error) => tracing::warn!(%error, "worker task maintenance failed"),
        }
    }
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
        Error::NoWork => -32118,
        Error::TaskInfrastructure => -32119,
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
/// task lease/outbox implementation is validated. Both edge types call this helper.
pub async fn observe_rpc_from_env(node_type: u8, realm_id: u32, realm_sub_id: u16) -> Result<Option<RpcModule<AdmissionRpc>>> {
    let Some(env) = AdmissionEnv::from_env(node_type, realm_id, realm_sub_id)? else { return Ok(None) };
    Ok(Some(env.admission_rpc(env.connect().await?)?))
}

pub fn validate_mode(mode: &str) -> Result<()> {
    match mode { "off" | "observe" => Ok(()), _ => Err(Error::UnsupportedProtocol) }
}
