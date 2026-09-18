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
    #[serde(alias = "sdkKeyExpectedTxCount")]
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
                operator.sign_type == "sd-key" || operator.sign_type == "sdk-key" || operator.sign_type == "SDKeySign",
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::sync::Mutex;

    use psy_client_data::config::store_config::PsyHasher;
    use psy_crypto::{hash::traits::qhashable::QFieldHashable, signature::zk::data::ZKPublicKeyInfo};
    use psy_ups_circuit::signature::sd_key::get_sd_key_public_key_param;

    use super::*;

    static FAUCET_ENV_LOCK: Mutex<()> = Mutex::new(());

    const FAUCET_ENV_NAMES: &[&str] = &[
        "PSY_FAUCET_OPERATORS_JSON",
        "PSY_FAUCET_OPERATORS_JSON_B64",
        "PSY_FAUCET_TURNSTILE_SECRET",
        "PSY_FAUCET_REQUIRE_TURNSTILE",
        "PSY_FAUCET_TURNSTILE_ACTION",
        "PSY_FAUCET_TURNSTILE_ALLOWED_HOSTNAMES",
        "PSY_FAUCET_WINDOW_CHECKPOINTS",
    ];

    struct FaucetEnvGuard(Vec<(&'static str, Option<String>)>);

    impl FaucetEnvGuard {
        fn cleared() -> Self {
            let previous = FAUCET_ENV_NAMES.iter().map(|&name| (name, env::var(name).ok())).collect();
            for name in FAUCET_ENV_NAMES {
                env::remove_var(name);
            }
            Self(previous)
        }
    }

    impl Drop for FaucetEnvGuard {
        fn drop(&mut self) {
            for (name, value) in &self.0 {
                match value {
                    Some(value) => env::set_var(name, value),
                    None => env::remove_var(name),
                }
            }
        }
    }

    fn test_network_config() -> psy_config::NetworkConfigGoldilocks {
        serde_json::from_value(serde_json::json!({
            "magic": "1",
            "users_per_realm": 8,
            "global_user_tree_height": 8,
            "realm_user_tree_height": 4,
            "group_realm_height": 4,
            "realm_configs": [],
            "coordinator_configs": [],
            "prove_proxy_url": [],
            "faucet_rpc_url": [],
            "nostr_relay_url": "ws://127.0.0.1:1",
            "native_currency": "PSY",
            "native_currency_decimal": 18,
            "native_currency_name": "Psy",
            "fees": {
                "register_user_fee": 0,
                "deploy_contract_fee": 0,
                "guta_fee": 0,
                "da_fee": 0
            }
        }))
        .unwrap()
    }

    fn valid_operators_json() -> serde_json::Value {
        serde_json::json!({
            "faucetContractId": 3,
            "faucetMethodName": "claim",
            "faucetMethodId": 4,
            "faucetPerClaimAmount": "500",
            "sdKeyExpectedTxCount": 2,
            "operators": [{
                "userId": "7",
                "address": "address",
                "privateKey": "key",
                "fingerprint": "fingerprint",
                "signType": "sd-key"
            }]
        })
    }

    fn env_name(suffix: &str) -> String {
        format!("PSY_PROVER_FAUCET_TEST_{}_{}", std::process::id(), suffix)
    }

    #[test]
    fn environment_parsers_handle_defaults_and_normalization() {
        let bool_name = env_name("BOOL");
        let number_name = env_name("NUMBER");
        let csv_name = env_name("CSV");

        env::remove_var(&bool_name);
        env::remove_var(&number_name);
        env::remove_var(&csv_name);
        assert!(parse_bool_env(&bool_name, true));
        assert_eq!(parse_u64_env(&number_name, 17).unwrap(), 17);
        assert!(parse_csv_env(&csv_name).is_empty());

        for truthy in ["1", " true ", "YES", "On"] {
            env::set_var(&bool_name, truthy);
            assert!(parse_bool_env(&bool_name, false));
        }
        env::set_var(&bool_name, "no");
        assert!(!parse_bool_env(&bool_name, true));

        env::set_var(&number_name, " 42 ");
        assert_eq!(parse_u64_env(&number_name, 0).unwrap(), 42);
        env::set_var(&number_name, " ");
        assert_eq!(parse_u64_env(&number_name, 9).unwrap(), 9);
        env::set_var(&number_name, "invalid");
        assert!(parse_u64_env(&number_name, 0).is_err());

        env::set_var(&csv_name, " One, two ,,THREE ");
        assert_eq!(parse_csv_env(&csv_name), vec!["one", "two", "three"]);

        env::remove_var(bool_name);
        env::remove_var(number_name);
        env::remove_var(csv_name);
    }

    #[test]
    fn already_claimed_detection_is_case_insensitive_and_specific() {
        assert!(is_already_claimed_error("Faucet already claimed"));
        assert!(is_already_claimed_error("ALREADY CLAIMED FOR WINDOW 4"));
        assert!(!is_already_claimed_error("operator is busy"));
    }

    #[test]
    fn rpc_error_helpers_set_message_and_optional_data() {
        let plain = rpc_error("plain failure");
        assert_eq!(plain.code(), 1);
        assert_eq!(plain.message(), "plain failure");
        assert!(plain.data().is_none());

        let detailed = rpc_error_with_data("detailed failure", "reason");
        assert_eq!(detailed.code(), 1);
        assert_eq!(detailed.message(), "detailed failure");
        assert_eq!(detailed.data().map(|data| data.get()), Some("\"reason\""));
    }

    #[test]
    fn request_and_turnstile_payloads_apply_serde_defaults() {
        let request: PsyFaucetClaimRequest = serde_json::from_value(serde_json::json!({
            "recipient_user_id": 8
        }))
        .unwrap();
        assert_eq!(request.recipient_user_id, 8);
        assert!(request.recipient_public_key.is_none());
        assert!(request.turnstile_token.is_none());
        assert!(request.turnstile_state.is_none());

        let response: TurnstileVerifyResponse = serde_json::from_value(serde_json::json!({
            "success": false,
            "error-codes": ["invalid-input-response"]
        }))
        .unwrap();
        assert!(!response.success);
        assert_eq!(response.error_codes, vec!["invalid-input-response"]);
        assert!(response.hostname.is_none());
        assert!(response.action.is_none());
        assert!(response.cdata.is_none());
    }

    #[test]
    fn operator_config_accepts_sdk_key_expected_count_alias() {
        let config: PsyFaucetOperatorsConfig = serde_json::from_value(serde_json::json!({
            "faucetContractId": 3,
            "faucetMethodName": "claim",
            "faucetMethodId": 4,
            "faucetPerClaimAmount": "500",
            "sdkKeyExpectedTxCount": 2,
            "operators": [{
                "userId": "7",
                "address": "address",
                "privateKey": "key",
                "fingerprint": "fingerprint",
                "signType": "sd-key"
            }]
        }))
        .unwrap();

        assert_eq!(config.faucet_contract_id, 3);
        assert_eq!(config.faucet_method_name, "claim");
        assert_eq!(config.faucet_method_id, 4);
        assert_eq!(config.faucet_per_claim_amount, "500");
        assert_eq!(config.sd_key_expected_tx_count, 2);
        assert!(config.sd_key_allowed_contract_ids.is_none());
        assert!(config.sd_key_allowed_method_ids.is_none());
        assert_eq!(config.operators.len(), 1);
        assert_eq!(config.operators[0].user_id, "7");
        assert_eq!(config.operators[0].address, "address");
        assert_eq!(config.operators[0].private_key, "key");
        assert_eq!(config.operators[0].fingerprint, "fingerprint");
        assert_eq!(config.operators[0].sign_type, "sd-key");
    }

    #[tokio::test]
    async fn from_env_returns_none_when_faucet_is_not_configured() {
        let _lock = FAUCET_ENV_LOCK.lock().unwrap();
        let _env = FaucetEnvGuard::cleared();

        assert!(PsyFaucetService::from_env(test_network_config()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn from_env_rejects_invalid_configuration_before_wallet_setup() {
        let _lock = FAUCET_ENV_LOCK.lock().unwrap();
        let _env = FaucetEnvGuard::cleared();

        env::set_var("PSY_FAUCET_OPERATORS_JSON_B64", "not-base64!");
        assert!(PsyFaucetService::from_env(test_network_config())
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("Invalid"));

        env::remove_var("PSY_FAUCET_OPERATORS_JSON_B64");
        env::set_var("PSY_FAUCET_OPERATORS_JSON", "not-json");
        assert!(PsyFaucetService::from_env(test_network_config()).await.is_err());

        let mut config = valid_operators_json();
        config["operators"] = serde_json::json!([]);
        env::set_var("PSY_FAUCET_OPERATORS_JSON", config.to_string());
        assert!(PsyFaucetService::from_env(test_network_config())
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("has no operators"));

        let mut config = valid_operators_json();
        config["faucetPerClaimAmount"] = serde_json::json!("  ");
        env::set_var("PSY_FAUCET_OPERATORS_JSON", config.to_string());
        assert!(PsyFaucetService::from_env(test_network_config())
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("faucetPerClaimAmount is empty"));

        let mut config = valid_operators_json();
        config["faucetPerClaimAmount"] = serde_json::json!("five hundred");
        env::set_var("PSY_FAUCET_OPERATORS_JSON", config.to_string());
        assert!(PsyFaucetService::from_env(test_network_config()).await.is_err());

        env::set_var("PSY_FAUCET_OPERATORS_JSON", valid_operators_json().to_string());
        env::set_var("PSY_FAUCET_REQUIRE_TURNSTILE", "true");
        assert!(PsyFaucetService::from_env(test_network_config())
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("requires PSY_FAUCET_TURNSTILE_SECRET"));

        env::set_var("PSY_FAUCET_REQUIRE_TURNSTILE", "false");
        env::set_var("PSY_FAUCET_WINDOW_CHECKPOINTS", "0");
        assert!(PsyFaucetService::from_env(test_network_config())
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("must be > 0"));
    }

    #[tokio::test]
    async fn from_env_decodes_base64_configuration_before_validation() {
        let _lock = FAUCET_ENV_LOCK.lock().unwrap();
        let _env = FaucetEnvGuard::cleared();
        let config = serde_json::json!({
            "faucetContractId": 3,
            "faucetMethodName": "claim",
            "faucetMethodId": 4,
            "faucetPerClaimAmount": "500",
            "sdKeyExpectedTxCount": 2,
            "operators": []
        });
        env::set_var(
            "PSY_FAUCET_OPERATORS_JSON_B64",
            base64::engine::general_purpose::STANDARD.encode(config.to_string()),
        );

        assert!(PsyFaucetService::from_env(test_network_config())
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("has no operators"));
    }

    #[tokio::test]
    async fn faucet_server_provider_requires_operator_configuration() {
        let _lock = FAUCET_ENV_LOCK.lock().unwrap();
        let _env = FaucetEnvGuard::cleared();

        let error = PsyFaucetServerProvider::new_with_config(test_network_config()).await.err().unwrap();
        assert!(error.to_string().contains("PSY_FAUCET_OPERATORS_JSON"));
    }

    /// The per-operator identity checks run before any chain access: an
    /// unsupported sign type is rejected first, then a config fingerprint that
    /// differs from the deterministic sd-key circuit fingerprint of
    /// (contract, method, tx count).
    #[tokio::test]
    async fn from_env_rejects_operator_identity_mismatches() {
        let _lock = FAUCET_ENV_LOCK.lock().unwrap();
        let _env = FaucetEnvGuard::cleared();

        env::set_var("PSY_FAUCET_OPERATORS_JSON", valid_operators_json().to_string());
        let error = PsyFaucetService::from_env(crate::test_support::dead_network_config())
            .await
            .err()
            .unwrap();
        // the fixture's placeholder fingerprint never matches the computed
        // sd-key fingerprint
        assert!(error.to_string().contains("fingerprint mismatch"), "unexpected error: {error}");

        let mut config = valid_operators_json();
        config["operators"][0]["signType"] = serde_json::json!("secp256k1");
        env::set_var("PSY_FAUCET_OPERATORS_JSON", config.to_string());
        let error = PsyFaucetService::from_env(crate::test_support::dead_network_config())
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("unsupported signType"), "unexpected error: {error}");
    }

    #[tokio::test]
    async fn from_env_builds_the_wallet_and_circuit_before_the_chain_lookup_fails() {
        let _lock = FAUCET_ENV_LOCK.lock().unwrap();
        let _env = FaucetEnvGuard::cleared();

        // the sd-key circuit fingerprint is deterministic for a given
        // (contract_ids, method_ids, tx_count) triple, so the shared offline
        // session can precompute what from_env will register
        let shared = crate::test_support::shared_offline_wallet_session().await;
        let fingerprint = shared.write().register_sd_key_circuit(&[3], &[4], 2).await.unwrap();

        let private_key = QHashOut::<F>::from_values(11, 12, 13, 14);
        let address = ZKPublicKeyInfo {
            fingerprint,
            public_key_param: get_sd_key_public_key_param(&private_key),
        }
        .qfhash::<PsyHasher>()
        .to_string();

        let mut config = valid_operators_json();
        config["operators"][0]["address"] = serde_json::json!(address);
        config["operators"][0]["privateKey"] = serde_json::json!(private_key.to_string());
        config["operators"][0]["fingerprint"] = serde_json::json!(fingerprint.to_string());
        env::set_var("PSY_FAUCET_OPERATORS_JSON", config.to_string());

        // the offline session initializes, the sd-key circuit registers with a
        // matching fingerprint, and the operator user lookup then fails on the
        // dead RPC registration index
        let error = PsyFaucetService::from_env(crate::test_support::dead_network_config())
            .await
            .err()
            .unwrap();
        let message = error.to_string();
        assert!(
            message.contains("not registered for explicit user_id") || message.contains("connection refused"),
            "unexpected from_env failure: {message}"
        );
    }

    fn offline_service(
        wallet_session: Arc<WalletSession>,
        turnstile_secret: Option<&str>,
        require_turnstile: bool,
        turnstile_action: Option<&str>,
        turnstile_allowed_hostnames: &[&str],
    ) -> PsyFaucetService {
        let config: PsyFaucetOperatorsConfig = serde_json::from_value(valid_operators_json()).unwrap();
        PsyFaucetService {
            config,
            operators: vec![PsyFaucetOperator {
                user_id: 7,
                public_key: QHashOut::ZERO,
            }],
            wallet_session,
            claim_records: DashMap::new(),
            recipient_locks: DashSet::new(),
            operator_locks: DashSet::new(),
            window_checkpoints: 10,
            turnstile_secret: turnstile_secret.map(str::to_string),
            require_turnstile,
            turnstile_action: turnstile_action.map(str::to_string),
            turnstile_allowed_hostnames: turnstile_allowed_hostnames.iter().map(|hostname| hostname.to_string()).collect(),
            http_client: reqwest::Client::new(),
        }
    }

    fn claim_request(recipient_user_id: u64) -> PsyFaucetClaimRequest {
        PsyFaucetClaimRequest {
            recipient_user_id,
            recipient_public_key: None,
            turnstile_token: None,
            turnstile_state: None,
        }
    }

    #[tokio::test]
    async fn faucet_service_offline_claim_and_config_surfaces() {
        let wallet_session = Arc::new(
            WalletSession::new(&crate::test_support::dead_network_config())
                .await
                .expect("offline wallet session should initialize"),
        );
        let service = offline_service(wallet_session.clone(), None, false, None, &[]);

        let public_config = service.public_config();
        assert!(public_config.enabled);
        assert_eq!(public_config.faucet_contract_id, 3);
        assert_eq!(public_config.faucet_method_name, "claim");
        assert_eq!(public_config.amount, "500");
        assert_eq!(public_config.window_checkpoints, 10);
        assert_eq!(public_config.operator_user_ids, vec![7]);
        assert!(!public_config.turnstile_required);

        // turnstile is skipped entirely when unconfigured and not required
        assert!(service.verify_turnstile(None, None).await.is_ok());
        assert!(service.verify_turnstile(Some("  "), None).await.is_ok());

        // a recipient already mid-claim is rejected before any chain access
        service.recipient_locks.insert(8);
        let busy = service.claim_for_recipient(claim_request(8)).await.err().unwrap();
        assert!(busy.message().contains("already in progress"));
        assert!(service.recipient_locks.contains(&8));
        service.recipient_locks.remove(&8);

        // with the lock free, the claim proceeds until the dead-RPC checkpoint
        // fetch fails
        let checkpoint = service.claim(claim_request(8)).await.err().unwrap();
        assert!(checkpoint.message().contains("failed to fetch latest checkpoint"));

        // a configured secret without a token is rejected before any HTTP call
        let secreted = offline_service(wallet_session.clone(), Some("secret"), true, None, &[]);
        let missing = secreted.verify_turnstile(None, None).await.err().unwrap();
        assert!(missing.message().contains("missing Turnstile token"));
        let lenient = offline_service(wallet_session.clone(), Some("secret"), false, None, &[]);
        assert!(lenient.verify_turnstile(None, None).await.is_ok());
        // a configured-but-optional secret with a blank token skips the HTTP
        // verification entirely
        assert!(lenient.verify_turnstile(Some(" "), None).await.is_ok());

        // required-but-unconfigured turnstile is rejected up front
        let requiring = offline_service(wallet_session, None, true, None, &[]);
        let unconfigured = requiring.verify_turnstile(None, None).await.err().unwrap();
        assert!(unconfigured.message().contains("required but not configured"));

        let rpc = PsyFaucetServerProvider { faucet: Arc::new(requiring) };
        let config = rpc.get_psy_faucet_config().await.unwrap();
        assert!(config.turnstile_required);
        let error = rpc.claim_faucet(claim_request(9)).await.err().unwrap();
        assert!(error.message().contains("required but not configured"));
    }

    /// `claim_locked` walks every branch once the checkpoint fetch succeeds:
    /// the recorded-claim replay, the busy-operator bail-out, the failed
    /// operator submit, and the no-operators guard. The loopback chain serves
    /// the latest block state (checkpoint 33, window size 10 → window 3); the
    /// fixture operator's zero key is unregistered, so its submit fails.
    #[tokio::test]
    async fn faucet_claim_paths_walk_every_branch_against_the_offline_chain() {
        use crate::session::session::offline_trace_pipeline_tests as offline;

        let (port, _rpc_seen, responses) = offline::spawn_offline_rpc().await;
        let wallet_session = Arc::new(
            WalletSession::new(&offline::loopback_network_config(port))
                .await
                .expect("offline wallet session should initialize"),
        );
        let chain = offline::build_offline_chain(
            QHashOut::ZERO,
            vec![offline::seeded_helper_contract(), offline::seeded_token_contract()],
        );
        offline::set_offline_responses(&responses, &chain).expect("offline chain rules must install");

        let mut service = offline_service(wallet_session, None, false, None, &[]);

        // a previously recorded claim for this window replays instead of
        // re-submitting
        service.claim_records.insert(
            (8, 3),
            PsyFaucetClaimRecord {
                tx_hash: "recorded-tx".to_string(),
                operator_user_id: 7,
                amount: "500".to_string(),
            },
        );
        let replayed = service.claim(claim_request(8)).await.unwrap();
        assert!(replayed.already_submitted);
        assert_eq!(replayed.tx_hash, "recorded-tx");
        assert_eq!(replayed.window_id, 3);
        assert_eq!(replayed.operator_user_id, 7);

        // every operator already mid-submit: nothing is tried
        service.operator_locks.insert(7);
        let busy = service.claim_for_recipient(claim_request(9)).await.err().unwrap();
        assert!(busy.message().contains("all faucet operators are busy"));
        service.operator_locks.remove(&7);

        // the unregistered operator key fails the contract call, surfacing as
        // the operator-submit error
        let failed = service.claim(claim_request(10)).await.err().unwrap();
        assert!(failed.message().contains("faucet operator submit failed"));

        // with no operators at all the service refuses up front
        service.operators.clear();
        let empty = service.claim(claim_request(11)).await.err().unwrap();
        assert!(empty.message().contains("no faucet operators configured"));
    }

    /// A fully valid operator config boots the faucet against the offline
    /// chain: `from_env` registers the sd-key circuit, resolves the operator
    /// through the (shadowed) registration index, and `run_psy_faucet_server`
    /// serves the public config RPC before the test aborts the server task.
    #[tokio::test]
    async fn from_env_boots_the_faucet_server_against_the_offline_chain() {
        use psy_client_common::args::PsyFaucetServerArgs;

        use crate::session::session::offline_trace_pipeline_tests as offline;

        let _lock = FAUCET_ENV_LOCK.lock().unwrap();
        let _env = FaucetEnvGuard::cleared();

        let (port, _rpc_seen, responses) = offline::spawn_offline_rpc().await;

        // the sd-key fingerprint is deterministic, so the shared offline
        // session can precompute what from_env will register for
        // contract 3 / method 4 / tx_count 2
        let shared = crate::test_support::shared_offline_wallet_session().await;
        let fingerprint = shared.write().register_sd_key_circuit(&[3], &[4], 2).await.unwrap();

        let private_key = QHashOut::<F>::from_values(11, 12, 13, 14);
        let public_key = ZKPublicKeyInfo {
            fingerprint,
            public_key_param: get_sd_key_public_key_param(&private_key),
        }
        .qfhash::<PsyHasher>();

        let chain = offline::build_offline_chain(
            public_key,
            vec![offline::seeded_helper_contract(), offline::seeded_token_contract()],
        );
        offline::set_offline_responses(&responses, &chain).expect("offline chain rules must install");
        offline::set_offline_chain_rpc_rules(&responses, &chain, public_key).expect("offline chain rpc rules must install");
        // shadow the registration index: the operator key resolves to the
        // fixture user, so add_user_with_user_id accepts the explicit hint
        responses.lock().insert(
            0,
            offline::OfflineRpcRule {
                method: "psy_get_user_ids_for_public_key".to_string(),
                params: None,
                response: serde_json::json!({ "result": [offline::OFFLINE_USER_ID] }),
            },
        );

        let mut config = valid_operators_json();
        config["operators"][0]["userId"] = serde_json::json!("2");
        config["operators"][0]["address"] = serde_json::json!(public_key.to_string());
        config["operators"][0]["privateKey"] = serde_json::json!(private_key.to_string());
        config["operators"][0]["fingerprint"] = serde_json::json!(fingerprint.to_string());
        env::set_var("PSY_FAUCET_OPERATORS_JSON", config.to_string());

        let network = serde_json::to_value(offline::loopback_network_config(port)).unwrap();
        let file_config = serde_json::json!({ "networks": { "local": network }, "defaultNetwork": "local" });
        let config_path = std::env::temp_dir().join(format!("psy-prover-faucet-live-{}.json", std::process::id()));
        std::fs::write(&config_path, file_config.to_string()).unwrap();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let faucet_port = listener.local_addr().unwrap().port();
        drop(listener);

        let args = PsyFaucetServerArgs {
            listen_addr: format!("127.0.0.1:{faucet_port}"),
            rpc_config: config_path.to_string_lossy().into_owned(),
        };
        let task = tokio::spawn(crate::run_psy_faucet_server(args));

        // poll until the JSON-RPC service answers; that only happens once
        // from_env built the faucet against the offline chain
        let client = reqwest::Client::new();
        let mut served = String::new();
        for _ in 0..240 {
            if let Ok(response) = client
                .post(format!("http://127.0.0.1:{faucet_port}"))
                .header("content-type", "application/json")
                .body(r#"{"jsonrpc":"2.0","id":1,"method":"psy_get_psy_faucet_config","params":[]}"#.to_string())
                .timeout(std::time::Duration::from_secs(2))
                .send()
                .await
            {
                if let Ok(body) = response.text().await {
                    served = body;
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        assert!(served.contains("\"faucet_method_name\""), "faucet server should serve its public config, got: {}", served);
        assert!(!task.is_finished());
        task.abort();
        let _ = std::fs::remove_file(&config_path);
    }

    /// A registered operator drives `claim` end-to-end against the offline
    /// chain: a successful canned submit completes the claim and records it
    /// for the window, while the chain's already-claimed rejection for a new
    /// recipient surfaces through the already-claimed arm after proving.
    #[tokio::test]
    async fn faucet_claim_completes_and_reports_window_already_claimed() {
        use crate::session::session::offline_trace_pipeline_tests as offline;

        let (port, _rpc_seen, responses) = offline::spawn_offline_rpc().await;
        let mut wallet_session = WalletSession::new(&offline::loopback_network_config(port)).await.expect("offline wallet session should initialize");
        let pk_info = wallet_session
            .wallet
            .add_zk_private_key(QHashOut::from_values(931, 932, 933, 934))
            .await
            .unwrap();
        let public_key = pk_info.qfhash::<PsyHasher>();

        let chain = offline::build_offline_chain(
            public_key,
            vec![
                offline::seeded_helper_contract(),
                offline::seeded_token_contract(),
                offline::seeded_faucet_contract(),
            ],
        );
        offline::set_offline_responses(&responses, &chain).expect("offline chain rules must install");
        offline::set_offline_chain_rpc_rules(&responses, &chain, public_key).expect("offline chain rpc rules must install");

        // shadow the canned submit rejection with a success: the client
        // discards the RPC's tx hash, so any TxHash-shaped result works
        responses.lock().insert(
            0,
            offline::OfflineRpcRule {
                method: "psy_submit_user_end_cap".to_string(),
                params: None,
                response: serde_json::json!({ "result": serde_json::to_value(&QHashOut::<F>::ZERO).unwrap() }),
            },
        );

        let mut service = offline_service(Arc::new(wallet_session), None, false, None, &[]);
        service.operators[0] = PsyFaucetOperator {
            user_id: offline::OFFLINE_USER_ID,
            public_key,
        };

        // the operator proves the claim call and the submit succeeds: the
        // response reports a fresh claim for this window and records it
        let completed = service.claim(claim_request(12)).await.unwrap();
        assert!(!completed.already_submitted);
        assert_eq!(completed.window_id, 3);
        assert_eq!(completed.operator_user_id, offline::OFFLINE_USER_ID);
        assert_eq!(completed.amount, "500");
        assert!(!completed.tx_hash.is_empty());
        assert!(service.claim_records.get(&(12, 3)).is_some());

        // a new recipient in the same window hits the chain's already-claimed
        // rejection, which the service reports after trying every operator
        responses.lock().insert(
            0,
            offline::OfflineRpcRule {
                method: "psy_submit_user_end_cap".to_string(),
                params: None,
                response: serde_json::json!({ "error": { "code": -32603, "message": "faucet already claimed for this window" } }),
            },
        );
        let rejected = service.claim(claim_request(13)).await.err().unwrap();
        assert!(rejected.message().contains("faucet already claimed in the current window"));
    }
}
