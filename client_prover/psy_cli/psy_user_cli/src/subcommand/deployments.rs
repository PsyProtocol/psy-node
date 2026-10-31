use std::{collections::HashMap, fs, path::{Path, PathBuf}};

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
    default_deployments_root(Path::new(env!("CARGO_MANIFEST_DIR"))).join(deployments_network).join(file_name)
}

fn default_deployments_root(manifest_dir: &Path) -> PathBuf {
    // psy-contracts is a sibling repository of psy-node; fall back to the
    // legacy nested checkout when the sibling is absent. A missing deployment
    // file stays a hard error at the caller.
    let sibling = manifest_dir.join("../../../../psy-contracts/deployments");
    let nested = manifest_dir.join("../../../psy-contracts/deployments");
    if sibling.is_dir() { sibling } else { nested }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sibling_resolution_retains_nested_fallback_but_never_falls_back_per_file() -> anyhow::Result<()> {
        let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!("psy-deployments-{}-{nonce}", std::process::id()));
        fs::create_dir(&root)?;
        let result = (|| -> anyhow::Result<()> {
            let manifest = root.join("node/client_prover/psy_cli/psy_user_cli");
            fs::create_dir_all(&manifest)?;
            let nested = manifest.join("../../../psy-contracts/deployments");
            fs::create_dir_all(nested.join("sepolia"))?;
            fs::write(nested.join("sepolia/Bridge.json"), "{}")?;
            assert_eq!(default_deployments_root(&manifest), nested);

            let sibling = manifest.join("../../../../psy-contracts/deployments");
            fs::create_dir_all(&sibling)?;
            assert_eq!(default_deployments_root(&manifest), sibling);
            assert!(!default_deployments_root(&manifest).join("sepolia/Bridge.json").exists());
            Ok(())
        })();
        fs::remove_dir_all(root)?;
        result
    }
}
