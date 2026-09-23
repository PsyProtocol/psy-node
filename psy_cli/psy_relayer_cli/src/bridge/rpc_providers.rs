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
    for (index, mut provider) in source.into_iter().enumerate() {
        provider.url = provider.url.trim().to_string();
        if provider.url.is_empty() {
            continue;
        }
        if resolved.iter().any(|kept| kept.url == provider.url) {
            // Never log the URL: it can embed an API key.
            let dropped_name = if provider.name.trim().is_empty() {
                format!("unnamed entry {index}")
            } else {
                provider.name.trim().to_string()
            };
            tracing::warn!(
                label,
                dropped_provider = %dropped_name,
                "duplicate RPC provider URL dropped; keeping the first occurrence"
            );
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

/// Warns when `rpc_urls` is configured but ignored because `providers` takes
/// precedence (see `resolve_rpc_providers`).
///
/// Callers must pass the caller's own raw, user-supplied `providers`/`urls`
/// pair, not values already produced by a prior `resolve_rpc_providers` call.
/// `finalize_rpc_providers` is invoked downstream (via `L1Client::from_finalize_config`)
/// with a `DaemonFinalizeConfig` whose `l1_rpc_url`/`l1_rpc_providers` were
/// already filled in by `L1Config::effective_config` from a successful
/// resolution; checking there would fire on every normal multi-provider
/// config, not just a real conflict. Emit this once, from the chain-level
/// `L1Config` resolution in `effective_config` (or the legacy single-chain
/// path when the user set both), where `providers`/`urls` still reflect
/// distinct user input.
pub(crate) fn warn_if_rpc_urls_ignored(label: &str, providers: &[RpcProviderConfig], urls: &[String]) {
    if !providers.is_empty() && !urls.is_empty() {
        tracing::warn!(label, "rpc_urls is ignored because rpc_providers is set");
    }
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

    #[test]
    fn duplicate_named_and_unnamed_entries_are_dropped_and_return_value_is_unchanged() {
        // Second "alchemy" entry repeats the first URL; the third (blank name)
        // repeats the "infura" URL. Both must be dropped, and the returned
        // list must be exactly the same as before the warning was added.
        let resolved = resolve_rpc_providers(
            "sepolia",
            &[
                p("alchemy", "https://a", 11),
                p("infura", "https://i", 10),
                p("alchemy", "https://a", 9),
                p("", "https://i", 9),
            ],
            &[],
        )
        .unwrap();
        assert_eq!(resolved, vec![p("alchemy", "https://a", 11), p("infura", "https://i", 10)]);
    }

    #[test]
    fn warn_if_rpc_urls_ignored_does_not_affect_resolve_rpc_providers_return_value() {
        // `providers` and `urls` both non-empty: resolve_rpc_providers must
        // still return exactly the providers list (urls ignored), regardless
        // of whether warn_if_rpc_urls_ignored is also called on the same
        // inputs.
        let providers = [p("alchemy", "https://a", 11), p("infura", "https://i", 10)];
        let urls = ["https://ignored".to_string()];
        warn_if_rpc_urls_ignored("sepolia", &providers, &urls);
        let resolved = resolve_rpc_providers("sepolia", &providers, &urls).unwrap();
        assert_eq!(resolved, vec![p("alchemy", "https://a", 11), p("infura", "https://i", 10)]);
    }

    #[test]
    fn warn_if_rpc_urls_ignored_is_a_no_op_when_either_side_is_empty() {
        // Normal configs (only providers, or only urls) must never be flagged.
        warn_if_rpc_urls_ignored("sepolia", &[p("alchemy", "https://a", 11)], &[]);
        warn_if_rpc_urls_ignored("sepolia", &[], &["https://a".to_string()]);
        warn_if_rpc_urls_ignored("sepolia", &[], &[]);
    }

    #[test]
    fn finalize_rpc_providers_after_effective_config_derived_state_still_resolves() {
        // Mirrors L1Client::from_finalize_config being called on a
        // DaemonFinalizeConfig that L1Config::effective_config already
        // patched: l1_rpc_url set to the first provider's URL and
        // l1_rpc_providers set to the full resolved list. This must keep
        // resolving to the same single-provider list (the derived l1_rpc_url
        // duplicates providers[0] and is dropped), without needing the
        // rpc_urls-ignored warning to fire here (it must not fire from
        // finalize_rpc_providers at all; see warn_if_rpc_urls_ignored docs).
        let providers = vec![p("alchemy", "https://a", 11), p("infura", "https://i", 10)];
        let finalize = DaemonFinalizeConfig {
            l1_rpc_url: Some(providers[0].url.clone()),
            l1_rpc_fallback_url: None,
            l1_rpc_providers: providers.clone(),
            ..DaemonFinalizeConfig::default()
        };
        let resolved = finalize_rpc_providers("l1", &finalize).unwrap();
        assert_eq!(resolved, providers);
    }
}
