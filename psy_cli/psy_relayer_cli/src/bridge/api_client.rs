use alloy_primitives::{Address, U256};
use alloy_provider::Provider;
use alloy_rpc_types_eth::TransactionRequest;
use alloy_sol_types::{sol, SolCall};
use anyhow::Context;
use std::collections::HashMap;
use std::time::Duration;
use std::{fs, path::PathBuf, str::FromStr};

sol! {
    function l1ChainIndex() external view returns (uint8);
}

pub async fn eth_call_u256<P: Provider, Call: SolCall<Return = U256>>(
    provider: &P,
    to: Address,
    call: Call,
) -> anyhow::Result<U256> {
    let tx = TransactionRequest::default().to(to).input(call.abi_encode().into());
    let raw = provider.call(tx).await.context("eth_call failed")?;
    Call::abi_decode_returns(&raw).context("failed to decode eth_call return")
}

#[derive(Debug, serde::Deserialize)]
pub struct DeployedContracts {
    #[serde(default)]
    pub protocol: Option<DeployedProtocol>,
    pub core: HashMap<String, String>,
    pub contracts: HashMap<String, String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct DeployedProtocol {
    pub chain: DeployedProtocolChain,
}

#[derive(Debug, serde::Deserialize)]
pub struct DeployedProtocolChain {
    #[serde(rename = "l1ChainIndex")]
    pub l1_chain_index: u8,
}

#[derive(Debug, serde::Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

pub async fn get_services_json<T: serde::de::DeserializeOwned>(
    http: &reqwest::Client,
    url: &str,
    label: &'static str,
) -> anyhow::Result<T> {
    let response = http.get(url).send().await?.error_for_status()?;
    let status = response.status();
    let body = response.text().await?;
    match serde_json::from_str::<T>(&body) {
        Ok(parsed) => Ok(parsed),
        Err(err) => {
            tracing::error!(
                url = %url,
                label,
                status = %status,
                body_len = body.len(),
                body = %body,
                error = %err,
                "[SERVICES_DECODE_FAIL] failed to decode services HTTP response"
            );
            Err(anyhow::anyhow!("Failed to parse {} response: {}", label, err))
        }
    }
}

pub fn build_default_http_client() -> anyhow::Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .build()
        .context("failed to build default HTTP client")
}

pub fn resolve_deployments_file(deployments_network: &str, file_name: &str) -> PathBuf {
    if let Ok(base) = std::env::var("PSY_DEPLOYMENTS_DIR") {
        return PathBuf::from(base).join(deployments_network).join(file_name);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../psy-contracts/deployments")
        .join(deployments_network)
        .join(file_name)
}

pub fn load_deployed_contracts(deployments_network: &str) -> anyhow::Result<DeployedContracts> {
    let path = resolve_deployments_file(deployments_network, "deployed-contracts.json");
    let raw = fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))
}

pub fn resolve_contract_address_from_deployments(
    deployments_network: &str,
    contract_name: &str,
) -> anyhow::Result<Address> {
    let path = resolve_deployments_file(deployments_network, "deployed-contracts.json");
    let deployed = load_deployed_contracts(deployments_network)?;
    let addr = deployed
        .core
        .get(contract_name)
        .or_else(|| deployed.contracts.get(contract_name))
        .ok_or_else(|| anyhow::anyhow!("{} not found in {}", contract_name, path.display()))?;
    Address::from_str(addr)
        .with_context(|| format!("invalid {} address in {}: {}", contract_name, path.display(), addr))
}

pub async fn resolve_l1_chain_index<P: Provider>(
    provider: &P,
    deployments_network: &str,
    state_manager: Address,
) -> anyhow::Result<u8> {
    let deployed = load_deployed_contracts(deployments_network)?;
    let expected = deployed
        .protocol
        .as_ref()
        .map(|p| p.chain.l1_chain_index)
        .unwrap_or(0);
    let tx = TransactionRequest::default().to(state_manager).input(l1ChainIndexCall {}.abi_encode().into());
    let raw = provider.call(tx).await.context("StateManager.l1ChainIndex eth_call failed")?;
    let onchain = l1ChainIndexCall::abi_decode_returns(&raw).context("failed to decode StateManager.l1ChainIndex return")?;
    anyhow::ensure!(
        onchain == expected,
        "l1ChainIndex mismatch for {}: deployment={} onchain={} state_manager={}",
        deployments_network,
        expected,
        onchain,
        state_manager
    );
    Ok(onchain)
}
