use std::time::Duration;

use alloy_network::EthereumWallet;
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_client::ClientBuilder;
use alloy_transport::layers::RetryBackoffLayer;
use anyhow::{Context, Result};
use url::Url;

const L1_HTTP_TIMEOUT_SECS: u64 = 15;
const L1_HTTP_RETRY_ATTEMPTS: u32 = 3;
const L1_HTTP_INITIAL_BACKOFF_MS: u64 = 100;
const DEFAULT_L1_HTTP_COMPUTE_UNITS_PER_SECOND: u64 = 600;

fn l1_http_compute_units_per_second() -> u64 {
    std::env::var("L1_HTTP_CU_PER_SEC")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_L1_HTTP_COMPUTE_UNITS_PER_SECOND)
}

fn build_rpc_client(rpc_url: Url) -> Result<alloy_rpc_client::RpcClient> {
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(L1_HTTP_TIMEOUT_SECS))
        .build()
        .context("failed to build reqwest client for L1 RPC")?;
    let retry_layer = RetryBackoffLayer::new(
        L1_HTTP_RETRY_ATTEMPTS,
        L1_HTTP_INITIAL_BACKOFF_MS,
        l1_http_compute_units_per_second(),
    );
    Ok(ClientBuilder::default().layer(retry_layer).http_with_client(client, rpc_url))
}

pub fn connect_l1_readonly(rpc_url: Url) -> Result<impl Provider> {
    let client = build_rpc_client(rpc_url)?;
    Ok(ProviderBuilder::new().connect_client(client))
}

pub fn connect_l1_with_wallet(rpc_url: Url, wallet: EthereumWallet) -> Result<impl Provider> {
    let client = build_rpc_client(rpc_url)?;
    Ok(ProviderBuilder::new().wallet(wallet).connect_client(client))
}
