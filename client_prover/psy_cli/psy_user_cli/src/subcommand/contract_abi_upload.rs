use psy_client_data::{
    config::store_config::{PsyHasher, F},
    qblock::cmds::deploy_contract::{QBCDeployContract, QBCDeployContractV2},
};
use psy_crypto::hash::tx_hash::compute_deploy_contract_content_hash;
use serde_json::json;

const MAX_CONTRACT_ABI_JSON_BYTES: usize = 2 * 1024 * 1024;

pub fn deploy_contract_content_hash(deploy_contract: &QBCDeployContract<F>) -> anyhow::Result<String> {
    let deploy_with_root = deploy_contract.clone().into_with_whitelist_root::<PsyHasher>()?;
    let content_hash = compute_deploy_contract_content_hash(
        &deploy_with_root.deployer.to_le_bytes(),
        &deploy_with_root.function_whitelist_root.to_le_bytes(),
        deploy_with_root.code_definition.state_tree_height as u64,
    );
    Ok(hex::encode(content_hash))
}

fn resolve_services_url(network: &psy_config::NetworkConfigGoldilocks) -> anyhow::Result<String> {
    if let Some(urls) = &network.api_services_url {
        if let Some(first) = urls.first() {
            return Ok(first.trim_end_matches('/').to_string());
        }
    }
    anyhow::bail!("no psy-services URL configured in api_services_url")
}

pub async fn upload_contract_abi(
    network: &psy_config::NetworkConfigGoldilocks,
    deploy_contract: &QBCDeployContractV2<F>,
    abi_json: &str,
) -> anyhow::Result<String> {
    if abi_json.len() > MAX_CONTRACT_ABI_JSON_BYTES {
        anyhow::bail!(
            "contract ABI JSON is too large: {} bytes > {} bytes",
            abi_json.len(),
            MAX_CONTRACT_ABI_JSON_BYTES
        );
    }

    let abi_value: serde_json::Value = serde_json::from_str(abi_json)?;
    let content_hash = deploy_contract_content_hash(&deploy_contract.deploy_contract)?;
    let services_url = resolve_services_url(network)?;
    let url = format!("{}/api/v1/contract/abi/pending", services_url);

    let response = reqwest::Client::new()
        .post(&url)
        .json(&json!({
            "content_hash": content_hash,
            "abi": abi_value,
        }))
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("failed to upload contract ABI to psy-services: HTTP {} {}", status, body);
    }

    Ok(content_hash)
}
