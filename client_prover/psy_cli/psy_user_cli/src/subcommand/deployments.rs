use std::{collections::HashMap, fs, path::PathBuf};

use anyhow::Context;

#[derive(serde::Deserialize)]
struct DeployedContractsSummary {
    core: Option<HashMap<String, String>>,
    proxies: Option<HashMap<String, String>>,
}

#[derive(serde::Deserialize)]
struct AddressArtifact {
    address: String,
}

pub(crate) fn resolve_deployments_file(deployments_network: &str, file_name: &str) -> PathBuf {
    if let Ok(base) = std::env::var("PSY_DEPLOYMENTS_DIR") {
        return PathBuf::from(base).join(deployments_network).join(file_name);
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // psy-contracts is a sibling repository of psy-node; fall back to the
    // legacy nested checkout when the sibling is absent. A missing deployment
    // file stays a hard error at the caller.
    let sibling = manifest_dir.join("../../../../psy-contracts/deployments");
    let nested = manifest_dir.join("../../../psy-contracts/deployments");
    let base = if sibling.is_dir() { sibling } else { nested };
    base.join(deployments_network).join(file_name)
}

pub(crate) fn resolve_proxy_or_core_address(
    deployments_network: &str,
    proxy_key: &str,
    core_key: &str,
    artifact_file: &str,
) -> anyhow::Result<String> {
    let summary_path = resolve_deployments_file(deployments_network, "deployed-contracts.json");
    if let Ok(raw) = fs::read_to_string(&summary_path) {
        if let Ok(summary) = serde_json::from_str::<DeployedContractsSummary>(&raw) {
            if let Some(addr) = summary.proxies.as_ref().and_then(|m| m.get(proxy_key).cloned()) {
                return Ok(addr);
            }
            if let Some(addr) = summary.core.as_ref().and_then(|m| m.get(core_key).cloned()) {
                return Ok(addr);
            }
        }
    }

    let artifact_path = resolve_deployments_file(deployments_network, artifact_file);
    let raw = fs::read_to_string(&artifact_path).with_context(|| format!("failed to read {}", artifact_path.display()))?;
    let artifact: AddressArtifact = serde_json::from_str(&raw).with_context(|| format!("failed to parse {}", artifact_path.display()))?;
    Ok(artifact.address)
}
