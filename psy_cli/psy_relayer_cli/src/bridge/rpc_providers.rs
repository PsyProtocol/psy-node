use anyhow::{ensure, Result};
use serde::Deserialize;

use crate::bridge::{constants::DEFAULT_L1_RPC_URL, daemon::DaemonFinalizeConfig};

pub(crate) const DEFAULT_PRIORITY_WEIGHT: i32 = psy_rpc_pool::DEFAULT_PRIORITY_WEIGHT;

fn default_priority_weight() -> i32 {
    DEFAULT_PRIORITY_WEIGHT
}

/// One L1 RPC provider. `name` appears in logs; the URL never does.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub(crate) struct RpcProviderConfig {
    #[serde(default)]
    pub name: String,
    pub url: String,
    #[serde(default = "default_priority_weight")]
    pub priority_weight: i32,
}

/// `providers` wins when non-empty. Otherwise each URL becomes a weight-10
/// provider, so declaration order is the preference. Blank and repeated URLs
/// are dropped, keeping the first occurrence.
pub(crate) fn resolve_rpc_providers(
    label: &str,
    providers: &[RpcProviderConfig],
    urls: &[String],
) -> Result<Vec<RpcProviderConfig>> {
    let source: Vec<RpcProviderConfig> = if providers.is_empty() {
        urls.iter()
            .map(|url| RpcProviderConfig {
                name: String::new(),
                url: url.clone(),
                priority_weight: DEFAULT_PRIORITY_WEIGHT,
            })
            .collect()
    } else {
        providers.to_vec()
    };
    let mut resolved: Vec<RpcProviderConfig> = Vec::with_capacity(source.len());
    for mut provider in source {
        provider.url = provider.url.trim().to_string();
        if provider.url.is_empty() || resolved.iter().any(|kept| kept.url == provider.url) {
            continue;
        }
        if provider.name.trim().is_empty() {
            provider.name = format!("{label}-rpc-{}", resolved.len());
        }
        resolved.push(provider);
    }
    ensure!(!resolved.is_empty(), "{label} has no L1 RPC provider");
    Ok(resolved)
}

pub(crate) fn finalize_rpc_providers(
    label: &str,
    finalize: &DaemonFinalizeConfig,
) -> Result<Vec<RpcProviderConfig>> {
    let urls: Vec<String> = [
        Some(finalize.l1_rpc_url.clone().unwrap_or_else(|| DEFAULT_L1_RPC_URL.to_string())),
        finalize.l1_rpc_fallback_url.clone(),
    ]
    .into_iter()
    .flatten()
    .collect();
    resolve_rpc_providers(label, &finalize.l1_rpc_providers, &urls)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(name: &str, url: &str, weight: i32) -> RpcProviderConfig {
        RpcProviderConfig { name: name.into(), url: url.into(), priority_weight: weight }
    }

    #[test]
    fn explicit_providers_win_over_urls() {
        let resolved = resolve_rpc_providers(
            "sepolia",
            &[p("alchemy", "https://a", 11), p("infura", "https://i", 10)],
            &["https://ignored".into()],
        ).unwrap();
        assert_eq!(resolved, vec![p("alchemy", "https://a", 11), p("infura", "https://i", 10)]);
    }

    #[test]
    fn urls_become_weight_ten_providers_in_order_with_generated_names() {
        let resolved = resolve_rpc_providers(
            "sepolia", &[], &["https://z".into(), "https://a".into()],
        ).unwrap();
        assert_eq!(resolved, vec![p("sepolia-rpc-0", "https://z", 10), p("sepolia-rpc-1", "https://a", 10)]);
    }

    #[test]
    fn blank_and_duplicate_urls_are_dropped_keeping_first() {
        let resolved = resolve_rpc_providers(
            "bsc", &[], &[" https://a ".into(), "".into(), "https://a".into(), "https://b".into()],
        ).unwrap();
        assert_eq!(resolved, vec![p("bsc-rpc-0", "https://a", 10), p("bsc-rpc-1", "https://b", 10)]);
    }

    #[test]
    fn empty_list_is_an_error() {
        assert!(resolve_rpc_providers("base", &[], &[" ".into()]).is_err());
    }

    #[test]
    fn provider_table_parses_with_default_weight_and_optional_name() {
        #[derive(Deserialize)]
        struct Wrapper { rpc_providers: Vec<RpcProviderConfig> }
        let raw = r#"
[[rpc_providers]]
name = "alchemy"
url = "https://a"
priority_weight = 11

[[rpc_providers]]
url = "https://i"
"#;
        let wrapper: Wrapper = toml::from_str(raw).unwrap();
        assert_eq!(wrapper.rpc_providers, vec![p("alchemy", "https://a", 11), p("", "https://i", 10)]);
    }

    #[test]
    fn legacy_finalize_urls_map_to_primary_then_fallback() {
        let finalize = DaemonFinalizeConfig {
            l1_rpc_url: Some("https://z".into()),
            l1_rpc_fallback_url: Some("https://a".into()),
            ..DaemonFinalizeConfig::default()
        };
        let resolved = finalize_rpc_providers("l1", &finalize).unwrap();
        assert_eq!(resolved, vec![p("l1-rpc-0", "https://z", 10), p("l1-rpc-1", "https://a", 10)]);
    }
}
