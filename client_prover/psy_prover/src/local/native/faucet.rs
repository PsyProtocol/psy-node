use std::{env, str::FromStr, sync::Arc};

use base64::Engine;
use dashmap::{DashMap, DashSet};
use jsonrpsee::{core::async_trait, proc_macros::rpc, types::ErrorObjectOwned};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use psy_client_common::{
    args::{ContractCallArgs, ContractCallData},
    data::qhashout::QHashOut,
};
use psy_client_data::traits::qdatastore::qmetadata::QMetaDataStoreReaderSync;

use crate::session::WalletSession;

type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;
const D: usize = 2;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PsyFaucetClaimRequest {
    pub recipient_user_id: u64,
    #[serde(default)]
    pub recipient_public_key: Option<String>,
    #[serde(default)]
    pub turnstile_token: Option<String>,
    #[serde(default)]
    pub turnstile_state: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PsyFaucetClaimResponse {
    pub tx_hash: String,
    pub operator_user_id: u64,
    pub amount: String,
    pub checkpoint_id: u64,
    pub window_id: u64,
    pub already_submitted: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PsyFaucetPublicConfig {
    pub enabled: bool,
    pub faucet_contract_id: u64,
    pub faucet_method_name: String,
    pub amount: String,
    pub window_checkpoints: u64,
    pub operator_user_ids: Vec<u64>,
    pub turnstile_required: bool,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct PsyFaucetOperatorsConfig {
    faucet_contract_id: u64,
    faucet_method_name: String,
    faucet_method_id: u32,
    faucet_per_claim_amount: String,
    sd_key_expected_tx_count: u64,
    sd_key_allowed_contract_ids: Option<Vec<u64>>,
    sd_key_allowed_method_ids: Option<Vec<u32>>,
    operators: Vec<PsyFaucetOperatorConfig>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct PsyFaucetOperatorConfig {
    user_id: String,
    address: String,
    private_key: String,
    fingerprint: String,
    sign_type: String,
}

#[derive(Debug, Clone)]
struct PsyFaucetOperator {
    user_id: u64,
    public_key: QHashOut<F>,
}

#[derive(Debug, Clone)]
struct PsyFaucetClaimRecord {
    tx_hash: String,
    operator_user_id: u64,
    amount: String,
}

struct PsyFaucetService {
    config: PsyFaucetOperatorsConfig,
    operators: Vec<PsyFaucetOperator>,
    // No outer lock: after `from_env` finishes the (&mut self) setup, every
    // runtime method we call (`exec_contract_call`, `st_provider` reads) takes
    // `&self`, and the per-user state lives in DashMaps keyed by operator
    // public key. Concurrent claims for different operators touch disjoint
    // entries, so a shared `Arc<WalletSession>` lets them prove in parallel.
    // Same-operator mutual exclusion is handled by `operator_locks` below.
    wallet_session: Arc<WalletSession>,
    claim_records: DashMap<(u64, u64), PsyFaucetClaimRecord>,
    recipient_locks: DashSet<u64>,
    operator_locks: DashSet<u64>,
    window_checkpoints: u64,
    turnstile_secret: Option<String>,
    require_turnstile: bool,
    turnstile_action: Option<String>,
    turnstile_allowed_hostnames: Vec<String>,
    http_client: reqwest::Client,
}

#[derive(Debug, serde::Deserialize)]
struct TurnstileVerifyResponse {
    success: bool,
    #[serde(default, rename = "error-codes")]
    error_codes: Vec<String>,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    cdata: Option<String>,
}

fn rpc_error(message: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(1, message.into(), None::<String>)
}

fn rpc_error_with_data(message: impl Into<String>, data: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(1, message.into(), Some(data.into()))
}

fn parse_bool_env(name: &str, default_value: bool) -> bool {
    env::var(name)
        .ok()
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(default_value)
}

fn parse_u64_env(name: &str, default_value: u64) -> anyhow::Result<u64> {
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(value.trim().parse()?),
        _ => Ok(default_value),
    }
}

fn parse_csv_env(name: &str) -> Vec<String> {
    env::var(name)
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_default()
}

fn is_already_claimed_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("faucet already claimed") || lower.contains("already claimed for wi")
}

impl PsyFaucetService {
    async fn from_env(rpc_config: psy_config::NetworkConfigGoldilocks) -> anyhow::Result<Option<Arc<Self>>> {
        let config_json = match env::var("PSY_FAUCET_OPERATORS_JSON").ok().filter(|value| !value.trim().is_empty()) {
            Some(value) => value,
            None => {
                let Some(encoded) = env::var("PSY_FAUCET_OPERATORS_JSON_B64").ok().filter(|value| !value.trim().is_empty()) else {
                    tracing::info!("psy faucet server mode disabled: PSY_FAUCET_OPERATORS_JSON is not set");
                    return Ok(None);
                };
                let bytes = base64::engine::general_purpose::STANDARD.decode(encoded.trim())?;
                String::from_utf8(bytes)?
            }
        };

        let config: PsyFaucetOperatorsConfig = serde_json::from_str(&config_json)?;
        anyhow::ensure!(!config.operators.is_empty(), "PSY_FAUCET_OPERATORS_JSON has no operators");
        anyhow::ensure!(
            !config.faucet_per_claim_amount.trim().is_empty(),
            "PSY_FAUCET_OPERATORS_JSON.faucetPerClaimAmount is empty"
        );
        config.faucet_per_claim_amount.parse::<u64>()?;

        let turnstile_secret = env::var("PSY_FAUCET_TURNSTILE_SECRET").ok().filter(|value| !value.trim().is_empty());
        let require_turnstile = parse_bool_env("PSY_FAUCET_REQUIRE_TURNSTILE", turnstile_secret.is_some());
        anyhow::ensure!(
            !require_turnstile || turnstile_secret.is_some(),
            "PSY_FAUCET_REQUIRE_TURNSTILE=1 requires PSY_FAUCET_TURNSTILE_SECRET"
        );
        let turnstile_action = env::var("PSY_FAUCET_TURNSTILE_ACTION")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let turnstile_allowed_hostnames = parse_csv_env("PSY_FAUCET_TURNSTILE_ALLOWED_HOSTNAMES");
        let window_checkpoints = parse_u64_env("PSY_FAUCET_WINDOW_CHECKPOINTS", 120)?;
        anyhow::ensure!(window_checkpoints > 0, "PSY_FAUCET_WINDOW_CHECKPOINTS must be > 0");

        // Faucet is now a standalone RPC service. Keep rpc_config.prove_proxy_url
        // intact so WalletSession can send CPU-heavy proving work to stateless
        // prove-proxy replicas instead of proving locally.
        let mut wallet_session = WalletSession::new(&rpc_config).await?;
        let allowed_contract_ids: Vec<u64> = config
            .sd_key_allowed_contract_ids
            .clone()
            .unwrap_or_else(|| vec![config.faucet_contract_id]);
        let allowed_method_ids: Vec<u32> = config.sd_key_allowed_method_ids.clone().unwrap_or_else(|| vec![config.faucet_method_id]);
        let fingerprint = wallet_session
            .register_sd_key_circuit(&allowed_contract_ids, &allowed_method_ids, config.sd_key_expected_tx_count)
            .await?;

        let mut operators = Vec::with_capacity(config.operators.len());
        for operator in &config.operators {
            anyhow::ensure!(
                operator.sign_type == "sd-key" || operator.sign_type == "SDKeySign",
                "faucet operator {} uses unsupported signType {}; server faucet requires sd-key",
                operator.user_id,
                operator.sign_type
            );
            if operator.fingerprint != fingerprint.to_string() {
                anyhow::bail!(
                    "faucet operator {} fingerprint mismatch: config {}, generated {}",
                    operator.user_id,
                    operator.fingerprint,
                    fingerprint
                );
            }

            let user_id = operator.user_id.parse::<u64>()?;
            let private_key = QHashOut::<F>::from_str(&operator.private_key)?;
            let operator_fingerprint = QHashOut::<F>::from_str(&operator.fingerprint)?;
            let expected_public_key = QHashOut::<F>::from_str(&operator.address)?;
            let public_key = wallet_session.add_user_with_user_id(private_key, operator_fingerprint, user_id).await?;
            anyhow::ensure!(
                public_key == expected_public_key,
                "faucet operator {} public key mismatch: config {}, generated {}",
                user_id,
                expected_public_key,
                public_key
            );
            operators.push(PsyFaucetOperator { user_id, public_key });
        }

        tracing::info!(
            operator_count = operators.len(),
            faucet_contract_id = config.faucet_contract_id,
            faucet_method_name = %config.faucet_method_name,
            amount = %config.faucet_per_claim_amount,
            window_checkpoints,
            require_turnstile,
            turnstile_action = ?turnstile_action,
            turnstile_allowed_hostnames = ?turnstile_allowed_hostnames,
            prove_proxy_urls = ?rpc_config.prove_proxy_url,
            "psy faucet server mode enabled"
        );

        Ok(Some(Arc::new(Self {
            config,
            operators,
            wallet_session: Arc::new(wallet_session),
            claim_records: DashMap::new(),
            recipient_locks: DashSet::new(),
            operator_locks: DashSet::new(),
            window_checkpoints,
            turnstile_secret,
            require_turnstile,
            turnstile_action,
            turnstile_allowed_hostnames,
            http_client: reqwest::Client::new(),
        })))
    }

    fn public_config(&self) -> PsyFaucetPublicConfig {
        PsyFaucetPublicConfig {
            enabled: true,
            faucet_contract_id: self.config.faucet_contract_id,
            faucet_method_name: self.config.faucet_method_name.clone(),
            amount: self.config.faucet_per_claim_amount.clone(),
            window_checkpoints: self.window_checkpoints,
            operator_user_ids: self.operators.iter().map(|operator| operator.user_id).collect(),
            turnstile_required: self.require_turnstile,
        }
    }

    async fn verify_turnstile(&self, token: Option<&str>, expected_cdata: Option<&str>) -> Result<(), ErrorObjectOwned> {
        let Some(secret) = self.turnstile_secret.as_deref() else {
            if self.require_turnstile {
                return Err(rpc_error("faucet Turnstile verification is required but not configured"));
            }
            return Ok(());
        };

        let Some(token) = token.map(str::trim).filter(|value| !value.is_empty()) else {
            if self.require_turnstile {
                return Err(rpc_error("missing Turnstile token"));
            }
            return Ok(());
        };

        let response = self
            .http_client
            .post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
            .form(&[("secret", secret), ("response", token)])
            .send()
            .await
            .map_err(|err| rpc_error_with_data("Turnstile verification request failed", err.to_string()))?;
        let status = response.status();
        let body = response
            .json::<TurnstileVerifyResponse>()
            .await
            .map_err(|err| rpc_error_with_data("Turnstile verification response decode failed", err.to_string()))?;
        if !status.is_success() || !body.success {
            return Err(rpc_error_with_data(
                "Turnstile verification failed",
                format!("status={} errors={:?}", status, body.error_codes),
            ));
        }
        if let Some(expected_action) = self.turnstile_action.as_deref() {
            if body.action.as_deref() != Some(expected_action) {
                return Err(rpc_error_with_data(
                    "Turnstile verification failed",
                    format!("unexpected action: {:?}", body.action),
                ));
            }
        }
        if !self.turnstile_allowed_hostnames.is_empty() {
            let hostname = body.hostname.clone().unwrap_or_default().to_ascii_lowercase();
            if !self.turnstile_allowed_hostnames.iter().any(|allowed| allowed == &hostname) {
                return Err(rpc_error_with_data(
                    "Turnstile verification failed",
                    format!("unexpected hostname: {:?}", body.hostname),
                ));
            }
        }
        if let Some(expected_cdata) = expected_cdata.map(str::trim).filter(|value| !value.is_empty()) {
            if body.cdata.as_deref() != Some(expected_cdata) {
                return Err(rpc_error_with_data("Turnstile verification failed", "Turnstile state mismatch"));
            }
        }
        Ok(())
    }

    // Turnstile-gated entry, used by the public web frontend and the hosted
    // wallet verification page.
    async fn claim(&self, input: PsyFaucetClaimRequest) -> Result<PsyFaucetClaimResponse, ErrorObjectOwned> {
        self.verify_turnstile(input.turnstile_token.as_deref(), input.turnstile_state.as_deref())
            .await?;
        self.claim_for_recipient(input).await
    }

    async fn claim_for_recipient(&self, input: PsyFaucetClaimRequest) -> Result<PsyFaucetClaimResponse, ErrorObjectOwned> {
        let recipient_user_id = input.recipient_user_id;
        if self.recipient_locks.insert(recipient_user_id) {
            let result = self.claim_locked(input).await;
            self.recipient_locks.remove(&recipient_user_id);
            result
        } else {
            Err(rpc_error("faucet claim already in progress for this recipient"))
        }
    }

    async fn claim_locked(&self, input: PsyFaucetClaimRequest) -> Result<PsyFaucetClaimResponse, ErrorObjectOwned> {
        let checkpoint_id = self
            .wallet_session
            .st_provider
            .get_latest_block_state()
            .await
            .map_err(|err| rpc_error_with_data("failed to fetch latest checkpoint", err.to_string()))?
            .checkpoint_id;
        let window_id = checkpoint_id / self.window_checkpoints;
        let claim_key = (input.recipient_user_id, window_id);
        if let Some(record) = self.claim_records.get(&claim_key) {
            return Ok(PsyFaucetClaimResponse {
                tx_hash: record.tx_hash.clone(),
                operator_user_id: record.operator_user_id,
                amount: record.amount.clone(),
                checkpoint_id,
                window_id,
                already_submitted: true,
            });
        }

        let amount = self
            .config
            .faucet_per_claim_amount
            .parse::<u64>()
            .map_err(|err| rpc_error_with_data("invalid faucet amount", err.to_string()))?;
        let start_index = if self.operators.is_empty() {
            return Err(rpc_error("no faucet operators configured"));
        } else {
            (input.recipient_user_id as usize) % self.operators.len()
        };

        let mut last_already_claimed: Option<String> = None;
        let mut last_error: Option<String> = None;
        let mut tried_operator = false;
        for offset in 0..self.operators.len() {
            let operator = &self.operators[(start_index + offset) % self.operators.len()];
            if !self.operator_locks.insert(operator.user_id) {
                continue;
            }
            tried_operator = true;

            let submit_result = self.submit_with_operator(operator, input.recipient_user_id, amount).await;
            self.operator_locks.remove(&operator.user_id);

            match submit_result {
                Ok(tx_hash) => {
                    let record = PsyFaucetClaimRecord {
                        tx_hash: tx_hash.clone(),
                        operator_user_id: operator.user_id,
                        amount: self.config.faucet_per_claim_amount.clone(),
                    };
                    self.claim_records.insert(claim_key, record);
                    return Ok(PsyFaucetClaimResponse {
                        tx_hash,
                        operator_user_id: operator.user_id,
                        amount: self.config.faucet_per_claim_amount.clone(),
                        checkpoint_id,
                        window_id,
                        already_submitted: false,
                    });
                }
                Err(err) if is_already_claimed_error(&err) => {
                    last_already_claimed = Some(err);
                    continue;
                }
                Err(err) => {
                    last_error = Some(err);
                    break;
                }
            }
        }

        if let Some(err) = last_error {
            return Err(rpc_error_with_data("faucet operator submit failed", err));
        }
        if !tried_operator {
            return Err(rpc_error("all faucet operators are busy; retry shortly"));
        }
        Err(rpc_error_with_data(
            "faucet already claimed in the current window",
            last_already_claimed.unwrap_or_else(|| "all faucet operators are busy".to_string()),
        ))
    }

    async fn submit_with_operator(&self, operator: &PsyFaucetOperator, recipient_user_id: u64, amount: u64) -> Result<String, String> {
        let call_data = ContractCallData::new(vec![ContractCallArgs {
            contract_id: self.config.faucet_contract_id,
            method_name: self.config.faucet_method_name.clone(),
            inputs: vec![recipient_user_id, amount],
        }]);

        // Proving is CPU-bound and `exec_contract_call` runs it inline (no
        // internal spawn_blocking, unlike the dedicated prove_* RPCs). Drive it
        // on the blocking pool so several concurrent operator claims don't
        // saturate the async worker threads and stall the jsonrpsee event loop.
        let session = self.wallet_session.clone();
        let public_key = operator.public_key;
        let handle = tokio::runtime::Handle::current();
        let tx_hash = tokio::task::spawn_blocking(move || handle.block_on(session.exec_contract_call(public_key, call_data)))
            .await
            .map_err(|join_err| format!("faucet submit task panicked: {join_err}"))?
            .map_err(|err| err.to_string())?;
        Ok(tx_hash.to_string())
    }
}

pub struct PsyFaucetServerProvider {
    faucet: Arc<PsyFaucetService>,
}

impl PsyFaucetServerProvider {
    pub async fn new_with_config(rpc_config: psy_config::NetworkConfigGoldilocks) -> anyhow::Result<Self> {
        let Some(faucet) = PsyFaucetService::from_env(rpc_config).await? else {
            anyhow::bail!("PSY_FAUCET_OPERATORS_JSON or PSY_FAUCET_OPERATORS_JSON_B64 must be set for faucet-server");
        };
        Ok(Self { faucet })
    }
}

#[rpc(server, client, namespace = "psy")]
pub trait PsyFaucetRpc {
    #[method(name = "get_psy_faucet_config")]
    async fn get_psy_faucet_config(&self) -> Result<PsyFaucetPublicConfig, ErrorObjectOwned>;

    #[method(name = "claim_faucet")]
    async fn claim_faucet(&self, input: PsyFaucetClaimRequest) -> Result<PsyFaucetClaimResponse, ErrorObjectOwned>;
}

#[async_trait]
impl PsyFaucetRpcServer for PsyFaucetServerProvider {
    async fn get_psy_faucet_config(&self) -> Result<PsyFaucetPublicConfig, ErrorObjectOwned> {
        Ok(self.faucet.public_config())
    }

    async fn claim_faucet(&self, input: PsyFaucetClaimRequest) -> Result<PsyFaucetClaimResponse, ErrorObjectOwned> {
        self.faucet.claim(input).await
    }
}
