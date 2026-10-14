use std::{fs, path::Path, str::FromStr};

use anyhow::{anyhow, bail, Context, Result};
use plonky2::{field::{goldilocks_field::GoldilocksField, types::Field}, hash::poseidon::PoseidonPermutation};
use psy_client_common::{
    args::SignType,
    data::{base_types::hash256::Hash256, qhashout::QHashOut},
};
use psy_crypto::{
    hash::traits::qhashable::QFieldHashable,
    signature::{
        secp256k1::wallet::{get_secp_public_key, hash_no_pad_compressed_public_key},
        zk::{data::ZKPublicKeyInfo, wallet::SimplePsyPrivateKey},
    },
};
use psy_client_data::config::store_config::PsyHasher;
use psy_client_data::dpn::sd_key::SDKeyTransactionInfo;
use psy_prover::wallet::memory_wallet::{get_eth_personal_secp256k1_fingerprint, get_secp256k1_fingerprint, get_zk_fingerprint};
use psy_provider::wallet::secp_wallet::Wallet;
use psy_ups_circuit::signature::sd_key_dpn::get_sd_key_public_key_param;
use psy_ups_circuit::signature::sd_key_dpn::SDKeyDpnCircuitGadget;
use psy_vm::{dpn::vm::def::DPNFunctionCircuitDefinition, ups::sd_key::{SDKeyCallRule, SDKeyComparison, SDKeyInputTotalLimit, SDKeyTransactionInputRelation}};
use psy_ups_circuit::signature::sd_key_plonky2::get_sdc_public_key_param;
use serde::{Deserialize, Serialize};

pub use psy_client_common::args::WalletSourceArgs;

#[derive(Serialize, Deserialize)]
pub struct WalletKeyInfo {
    pub sign_type: SignType,
    pub private_key: QHashOut<GoldilocksField>,
    pub fingerprint: QHashOut<GoldilocksField>,
    pub public_key_param: QHashOut<GoldilocksField>,
    pub public_key_hash: QHashOut<GoldilocksField>,
    pub generated: bool,
}

/// Human-readable policy accepted by `--sd-key-definition`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComposedSDKeyPolicyFile {
    per_transaction: SDKeyCallRule,
    #[serde(default)]
    ordered: Vec<SDKeyCallRule>,
    #[serde(default)]
    totals: Vec<SDKeyInputTotalLimit>,
    #[serde(default)]
    cross_transaction: Vec<SDKeyTransactionInputRelation>,
    min_tx_count: u64,
    max_tx_count: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompiledSDKeyDefinitionFile {
    function: DPNFunctionCircuitDefinition,
    config: psy_client_data::dpn::sd_key::SDKeyConfig,
}

pub fn load_sd_key_dpn_definition(args: &WalletSourceArgs) -> Result<(DPNFunctionCircuitDefinition, psy_client_data::dpn::sd_key::SDKeyConfig)> {
    if let Some(path) = &args.sd_key_definition {
        anyhow::ensure!(
            args.sd_key_allowed_contract_id.is_empty()
                && args.sd_key_allowed_method_id.is_empty()
                && args.sd_key_min_tx_count.is_none()
                && args.sd_key_max_tx_count.is_none(),
            "--sd-key-definition cannot be combined with allow-method or transaction-count flags"
        );
        return load_sd_key_dpn_definition_from_file(path);
    }
    let (min, max) = args.sd_key_tx_count_range();
    psy_vm::ups::sd_key::build_allow_method_policy_range(
        &args.sd_key_allowed_contract_id,
        &args.sd_key_allowed_method_id,
        min,
        max,
    )
}

pub fn load_sd_key_dpn_definition_from_file(path: &str) -> Result<(DPNFunctionCircuitDefinition, psy_client_data::dpn::sd_key::SDKeyConfig)> {
    let contents = fs::read_to_string(path).with_context(|| format!("read SD key policy file {path}"))?;
    parse_sd_key_dpn_definition_json(&contents, path)
}

fn parse_sd_key_dpn_definition_json(contents: &str, path: &str) -> Result<(DPNFunctionCircuitDefinition, psy_client_data::dpn::sd_key::SDKeyConfig)> {
    let value: serde_json::Value = serde_json::from_str(&contents).with_context(|| format!("parse SD key policy file {path}"))?;
    if value.get("function").is_some() || value.get("config").is_some() {
        let definition: CompiledSDKeyDefinitionFile = serde_json::from_value(value)
            .with_context(|| format!("decode compiled SD key definition {path}"))?;
        return Ok((definition.function, definition.config));
    }
    let policy: ComposedSDKeyPolicyFile = serde_json::from_value(value)
        .with_context(|| format!("decode composed SD key policy {path}"))?;
    psy_vm::ups::sd_key::build_composed_sd_key_policy_with_relations(
        &policy.per_transaction,
        &policy.ordered,
        &policy.totals,
        &policy.cross_transaction,
        policy.min_tx_count,
        policy.max_tx_count,
    )
}

#[cfg(test)]
mod policy_tests {
    use psy_vm::ups::sd_key::SDKeyCallRule;
    use super::{
        build_sd_key_policy_template, check_sd_key_policy_json, describe_sd_key_policy_json, parse_policy_call_spec,
        parse_sd_key_dpn_definition_json, MethodSpec, PolicySimCall, SdKeyPolicyTemplateKind,
    };

    #[test]
    fn composed_json_builds_range_and_rejects_typos() {
        let json = r#"{
            "per_transaction": {"All": [{"Contract": 7}, {"Any": [{"Method": 10}, {"Method": 20}]}]},
            "ordered": [{"Method": 10}, {"Method": 20}],
            "totals": [{"word": 0, "max_per_tx": 100, "max_total": 250}],
            "min_tx_count": 2,
            "max_tx_count": 3
        }"#;
        let (_, config) = parse_sd_key_dpn_definition_json(json, "test.json").unwrap();
        let policy = config.transaction_count_policy.unwrap();
        assert_eq!((policy.min_tx_count, policy.max_tx_count), (2, 3));
        assert_eq!(policy.composed.unwrap().totals.len(), 1);
        let invalid = json.replace("max_total", "max_totla");
        assert!(parse_sd_key_dpn_definition_json(&invalid, "test.json").is_err());
    }

    #[test]
    fn composed_json_accepts_contract_method_and_input_rule_for_every_call() {
        let json = r#"{
            "per_transaction": {"All": [
                {"Contract": 5},
                {"Method": 10},
                {"Input": {"word": 0, "comparison": "Lte", "value": 100}}
            ]},
            "ordered": [],
            "totals": [],
            "min_tx_count": 1,
            "max_tx_count": 3
        }"#;
        let (_, config) = parse_sd_key_dpn_definition_json(json, "every-call.json").unwrap();
        let policy = config.transaction_count_policy.unwrap();
        assert_eq!((policy.min_tx_count, policy.max_tx_count), (1, 3));
        let composed = policy.composed.unwrap();
        assert!(matches!(composed.per_transaction, SDKeyCallRule::All(ref rules) if rules.len() == 3));
    }

    #[test]
    fn composed_json_parses_not_for_conditional_input_rules() {
        let json = r#"{
            "per_transaction": {"Any": [
                {"Not": {"All": [{"Contract": 5}, {"Method": 10}]}},
                {"Input": {"word": 0, "comparison": "Lte", "value": 100}}
            ]},
            "ordered": [],
            "totals": [],
            "min_tx_count": 1,
            "max_tx_count": 3
        }"#;
        let (_, config) = parse_sd_key_dpn_definition_json(json, "conditional.json").unwrap();
        let rule = config.transaction_count_policy.unwrap().composed.unwrap().per_transaction;
        assert!(matches!(rule, SDKeyCallRule::Any(children) if matches!(children.first(), Some(SDKeyCallRule::Not(_)))));
    }

    #[test]
    fn composed_json_accepts_if_then_and_cross_transaction_relations() {
        let json = r#"{
            "per_transaction": {"IfThen": {
                "condition": {"All": [{"Contract": 5}, {"Method": 10}]},
                "then": {"Input": {"word": 0, "comparison": "Lte", "value": 100}}
            }},
            "ordered": [], "totals": [],
            "cross_transaction": [{"left_slot": 0, "left_word": 1, "comparison": "Lte", "right_slot": 1, "right_word": 1}],
            "min_tx_count": 2, "max_tx_count": 3
        }"#;
        let (_, config) = parse_sd_key_dpn_definition_json(json, "if-then.json").unwrap();
        let composed = config.transaction_count_policy.unwrap().composed.unwrap();
        assert!(matches!(composed.per_transaction, SDKeyCallRule::IfThen { .. }));
        assert_eq!(composed.cross_transaction.len(), 1);
        let invalid = json.replace("\"left_slot\": 0", "\"left_slot\": 2");
        assert!(parse_sd_key_dpn_definition_json(&invalid, "invalid-slots.json").is_err());
    }

    #[test]
    fn templates_round_trip_through_the_loader() {
        for (kind, ordered_len, totals_len) in [
            (SdKeyPolicyTemplateKind::AllowMethod, 0, 0),
            (SdKeyPolicyTemplateKind::SpendingLimit, 0, 1),
            (SdKeyPolicyTemplateKind::Sequence, 2, 0),
        ] {
            let json = build_sd_key_policy_template(kind, 7, &[10, 20], 0, 100, 300, None, None).unwrap();
            let (_, config) = parse_sd_key_dpn_definition_json(&json, "template").unwrap();
            let policy = config.transaction_count_policy.unwrap();
            let composed = policy.composed.unwrap();
            assert_eq!(composed.ordered.len(), ordered_len);
            assert_eq!(composed.totals.len(), totals_len);
            assert_eq!(policy.min_tx_count, policy.max_tx_count);
        }
        // sequence defaults its count range to the method count
        let json = build_sd_key_policy_template(SdKeyPolicyTemplateKind::Sequence, 7, &[10, 20], 0, 0, 0, None, None).unwrap();
        let (_, config) = parse_sd_key_dpn_definition_json(&json, "template").unwrap();
        let policy = config.transaction_count_policy.unwrap();
        assert_eq!((policy.min_tx_count, policy.max_tx_count), (2, 2));
        // a count below the sequence length cannot be emitted
        assert!(build_sd_key_policy_template(SdKeyPolicyTemplateKind::Sequence, 7, &[10, 20], 0, 0, 0, Some(1), None).is_err());
    }

    #[test]
    fn policy_check_reports_and_rejects() {
        let json = build_sd_key_policy_template(SdKeyPolicyTemplateKind::SpendingLimit, 7, &[10, 20], 0, 100, 300, Some(1), Some(3)).unwrap();
        // shrink the session bound so the aggregate path can fire on its own
        let json = json.replace("\"max_total\": 300", "\"max_total\": 150");
        let calls = |pairs: &[(u64, u32, &[u64])]| {
            pairs
                .iter()
                .map(|(contract, method, inputs)| PolicySimCall { contract_id: *contract, method_id: *method, inputs: inputs.to_vec() })
                .collect::<Vec<_>>()
        };
        let lines = check_sd_key_policy_json(&json, "t", &calls(&[(7, 10, &[60]), (7, 20, &[80, 7])])).unwrap();
        assert!(lines.iter().any(|line| line.contains("allowed")));
        assert!(lines.iter().any(|line| line.contains("total word 0: sum 140 <= 150")));
        let over_total = check_sd_key_policy_json(&json, "t", &calls(&[(7, 10, &[100]), (7, 20, &[60, 7])]));
        assert!(over_total.unwrap_err().to_string().contains("sums to 160 across transactions, above limit 150"));
        let over_per_tx = check_sd_key_policy_json(&json, "t", &calls(&[(7, 10, &[200])]));
        assert!(over_per_tx.unwrap_err().to_string().contains("denies transaction 0"));
        let wrong_method = check_sd_key_policy_json(&json, "t", &calls(&[(7, 30, &[0])]));
        assert!(wrong_method.unwrap_err().to_string().contains("denies transaction 0"));
        let out_of_range = check_sd_key_policy_json(&json, "t", &[]);
        assert!(out_of_range.unwrap_err().to_string().contains("outside policy range"));
    }

    #[test]
    fn describe_renders_rules_totals_and_names() {
        let json = build_sd_key_policy_template(SdKeyPolicyTemplateKind::SpendingLimit, 7, &[10, 20], 0, 100, 300, Some(1), Some(3)).unwrap();
        let text = describe_sd_key_policy_json(&json, "t", None).unwrap();
        assert!(text.contains("transactions per session: 1..=3"));
        assert!(text.contains("every transaction must satisfy: call contract 7 and (method 10 or method 20) and calldata word 0 <= 100"));
        assert!(text.contains("session totals:"));
        assert!(text.contains("at most 100 per transaction, at most 300 in total"));
        let mut names = std::collections::HashMap::new();
        names.insert(10u32, "main".to_string());
        let annotated = describe_sd_key_policy_json(&json, "t", Some(&names)).unwrap();
        assert!(annotated.contains("method 10 (`main`)"));
    }

    #[test]
    fn policy_check_simulates_the_default_caller_for_user_initiated_calls() {
        let default_caller = psy_config::network_constants::DEFAULT_CALLER_CONTRACT_ID_U64;
        let json = format!(
            r#"{{
            "per_transaction": {{"All": [{{"Contract": 7}}, {{"Method": 10}}, {{"Caller": {default_caller}}}]}},
            "ordered": [],
            "totals": [],
            "min_tx_count": 1,
            "max_tx_count": 2
        }}"#
        );
        let calls = vec![PolicySimCall { contract_id: 7, method_id: 10, inputs: vec![0] }];
        check_sd_key_policy_json(&json, "t", &calls).unwrap();
        let cross_contract_only = json.replace(&format!("{{\"Caller\": {default_caller}}}"), "{\"Caller\": 5}");
        let error = check_sd_key_policy_json(&cross_contract_only, "t", &calls).unwrap_err();
        assert!(error.to_string().contains("denies transaction 0"));
    }

    #[test]
    fn call_specs_parse_ids_names_and_inputs() {
        assert_eq!(
            parse_policy_call_spec("7:10:60,7").unwrap(),
            super::PolicyCallSpec { contract_id: 7, method: MethodSpec::Id(10), inputs: vec![60, 7] }
        );
        assert_eq!(
            parse_policy_call_spec("7:main").unwrap(),
            super::PolicyCallSpec { contract_id: 7, method: MethodSpec::Name("main".to_string()), inputs: vec![] }
        );
        assert!(parse_policy_call_spec("7").is_err());
        assert!(parse_policy_call_spec("7:10:x").is_err());
    }

    #[test]
    fn method_name_walk_scopes_resolves_and_rejects() {
        use serde_json::json;

        // All's Contract leaf scopes the names inside it; Any does not scope;
        // ordered rules have no contract context of their own.
        let mut policy = json!({
            "per_transaction": {"All": [
                {"Contract": 7},
                {"Any": [{"Method": "buy"}, {"Method": "sell"}]},
                {"Method": "ping"}
            ]},
            "ordered": [{"Method": "ping"}],
            "totals": [],
            "min_tx_count": 1,
            "max_tx_count": 3
        });
        let mut seen = Vec::new();
        super::visit_policy_file_method_names(&mut policy, &mut |context, method| {
            seen.push((context, method.as_str().unwrap_or_default().to_string()));
            *method = serde_json::Value::from(42u32);
        });
        assert_eq!(
            seen,
            vec![
                (Some(7), "buy".to_string()),
                (Some(7), "sell".to_string()),
                (Some(7), "ping".to_string()),
                (None, "ping".to_string()),
            ]
        );
        assert_eq!(policy["per_transaction"]["All"][1]["Any"][0]["Method"], serde_json::json!(42));

        // a bare rule without an enclosing Contract reports no context
        let mut unscoped = json!({"Any": [{"Method": "buy"}]});
        let mut contexts = Vec::new();
        super::visit_method_names(&mut unscoped, None, &mut |context, _| contexts.push(context));
        assert_eq!(contexts, vec![None]);

        // numeric Methods are left alone
        let mut numeric = json!({"All": [{"Contract": 7}, {"Method": 10}]});
        let mut visits = 0;
        super::visit_method_names(&mut numeric, None, &mut |_, _| visits += 1);
        assert_eq!(visits, 0);
        assert_eq!(numeric["All"][1]["Method"], serde_json::json!(10));

        // Not forwards the inherited context, and an All group inside Not
        // supplies its own contract context to nested method names.
        let mut negated = json!({
            "Not": {"All": [{"Contract": 9}, {"Method": "transfer"}]}
        });
        let mut resolved = Vec::new();
        super::visit_method_names(&mut negated, None, &mut |context, method| {
            resolved.push((context, method.as_str().unwrap_or_default().to_string()));
            *method = serde_json::Value::from(77u32);
        });
        assert_eq!(resolved, vec![(Some(9), "transfer".to_string())]);
        assert_eq!(negated["Not"]["All"][1]["Method"], serde_json::json!(77));
    }
}

pub fn sd_key_dpn_fingerprint_from_file(path: &str) -> Result<QHashOut<GoldilocksField>> {
    let (function, config) = load_sd_key_dpn_definition_from_file(path)?;
    Ok(SDKeyDpnCircuitGadget::build_from_dpn_function(&function, &config)?.get_fingerprint())
}

pub fn sd_key_dpn_fingerprint(args: &WalletSourceArgs) -> Result<QHashOut<GoldilocksField>> {
    let (function, config) = load_sd_key_dpn_definition(args)?;
    Ok(SDKeyDpnCircuitGadget::build_from_dpn_function(&function, &config)?.get_fingerprint())
}

/// Starter shapes for `sd-key-policy-template`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SdKeyPolicyTemplateKind {
    /// Fixed allowlist of (contract, method) pairs.
    AllowMethod,
    /// Allowlist plus a per-call bound and a session total on one calldata word.
    SpendingLimit,
    /// The methods must appear in the given order.
    Sequence,
}

/// Build a starter composed policy file. The result round-trips through the
/// policy loader, so a template can never be emitted in a state the wallet
/// would reject.
#[allow(clippy::too_many_arguments)]
pub fn build_sd_key_policy_template(
    kind: SdKeyPolicyTemplateKind,
    contract: u64,
    methods: &[u32],
    word: u32,
    max_per_tx: u64,
    max_total: u64,
    min_tx_count: Option<u64>,
    max_tx_count: Option<u64>,
) -> Result<String> {
    anyhow::ensure!(!methods.is_empty(), "template needs at least one method");
    let methods_any = SDKeyCallRule::Any(methods.iter().map(|id| SDKeyCallRule::Method(*id)).collect());
    let (per_transaction, ordered, totals, default_min) = match kind {
        SdKeyPolicyTemplateKind::AllowMethod => (
            SDKeyCallRule::All(vec![SDKeyCallRule::Contract(contract), methods_any]),
            vec![],
            vec![],
            1,
        ),
        SdKeyPolicyTemplateKind::SpendingLimit => (
            SDKeyCallRule::All(vec![
                SDKeyCallRule::Contract(contract),
                methods_any,
                SDKeyCallRule::Input { word, comparison: SDKeyComparison::Lte, value: max_per_tx },
            ]),
            vec![],
            vec![SDKeyInputTotalLimit { word, max_per_tx, max_total }],
            1,
        ),
        SdKeyPolicyTemplateKind::Sequence => (
            SDKeyCallRule::All(vec![SDKeyCallRule::Contract(contract), methods_any]),
            methods.iter().map(|id| SDKeyCallRule::Method(*id)).collect(),
            vec![],
            methods.len() as u64,
        ),
    };
    let min = min_tx_count.unwrap_or(default_min);
    let max = max_tx_count.unwrap_or(min);
    let json = serde_json::to_string_pretty(&ComposedSDKeyPolicyFile {
        per_transaction,
        ordered,
        totals,
        cross_transaction: vec![],
        min_tx_count: min,
        max_tx_count: max,
    })?;
    parse_sd_key_dpn_definition_json(&json, "template")?;
    Ok(json)
}

/// A method referenced either by numeric id or by on-chain function name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MethodSpec {
    Id(u32),
    Name(String),
}

impl MethodSpec {
    pub fn parse(spec: &str) -> MethodSpec {
        match spec.parse::<u32>() {
            Ok(id) => MethodSpec::Id(id),
            Err(_) => MethodSpec::Name(spec.to_string()),
        }
    }
}

/// One simulated transaction for `sd-key-policy-check`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicySimCall {
    pub contract_id: u64,
    pub method_id: u32,
    pub inputs: Vec<u64>,
}

/// A parsed `--call` spec before method names are resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyCallSpec {
    pub contract_id: u64,
    pub method: MethodSpec,
    pub inputs: Vec<u64>,
}

/// Parse a `contract_id:method` or `contract_id:method:word0,word1,...` spec,
/// where `method` is a numeric method id or an on-chain function name.
pub fn parse_policy_call_spec(spec: &str) -> Result<PolicyCallSpec> {
    let parts: Vec<&str> = spec.split(':').collect();
    anyhow::ensure!(
        parts.len() == 2 || parts.len() == 3,
        "policy call must look like `contract_id:method` or `contract_id:method:word0,word1,...`, got `{spec}`"
    );
    let contract_id = parts[0].parse::<u64>().with_context(|| format!("parse contract id in `{spec}`"))?;
    let inputs = match parts.get(2) {
        Some(words) if !words.is_empty() => words
            .split(',')
            .map(|word| word.parse::<u64>().with_context(|| format!("parse calldata word in `{spec}`")))
            .collect::<Result<Vec<_>>>()?,
        _ => vec![],
    };
    Ok(PolicyCallSpec { contract_id, method: MethodSpec::parse(parts[1]), inputs })
}

async fn contract_method_names(provider: &psy_provider::provider::RpcProvider, contract_id: u64) -> Result<Vec<(u32, String)>> {
    use psy_client_data::traits::qdatastore::qmetadata::QMetaDataStoreReaderSync;
    let code = provider.get_contract_code_definition(contract_id).await?;
    Ok(code
        .functions
        .iter()
        .filter_map(|func| {
            psy_vm::dpn::contract::cfc_code_definition_to_dapen_fc(func)
                .ok()
                .map(|fc| (func.method_id, fc.name))
        })
        .collect())
}

/// Resolve `--call` specs to numeric calls. Specs that only use numeric
/// method ids stay offline; resolving names requires `rpc_config` and reads
/// the contract code definitions from the chain.
pub async fn resolve_policy_sim_calls(rpc_config: Option<&str>, specs: Vec<PolicyCallSpec>) -> Result<Vec<PolicySimCall>> {
    if specs.iter().all(|spec| matches!(spec.method, MethodSpec::Id(_))) {
        return Ok(specs
            .into_iter()
            .map(|spec| PolicySimCall {
                contract_id: spec.contract_id,
                method_id: match spec.method {
                    MethodSpec::Id(id) => id,
                    MethodSpec::Name(_) => unreachable!("checked above"),
                },
                inputs: spec.inputs,
            })
            .collect());
    }
    let path = rpc_config.ok_or_else(|| anyhow!("--rpc-config is required to resolve method names in --call"))?;
    let provider = psy_provider::provider::RpcProvider::new_with_config_path(path)?;
    let mut names: std::collections::HashMap<u64, Vec<(u32, String)>> = std::collections::HashMap::new();
    let mut calls = Vec::with_capacity(specs.len());
    for spec in specs {
        let method_id = match spec.method {
            MethodSpec::Id(id) => id,
            MethodSpec::Name(name) => {
                let contract = names.entry(spec.contract_id).or_insert_with(Vec::new);
                if contract.is_empty() {
                    *contract = contract_method_names(&provider, spec.contract_id).await?;
                }
                contract
                    .iter()
                    .find(|(_, function)| *function == name)
                    .map(|(id, _)| *id)
                    .ok_or_else(|| anyhow!("method `{name}` is not found in contract {}", spec.contract_id))?
            }
        };
        calls.push(PolicySimCall { contract_id: spec.contract_id, method_id, inputs: spec.inputs });
    }
    Ok(calls)
}

/// Resolve method specs for one contract (template `--methods`).
pub async fn resolve_policy_methods(rpc_config: Option<&str>, contract_id: u64, methods: &[MethodSpec]) -> Result<Vec<u32>> {
    if methods.iter().all(|method| matches!(method, MethodSpec::Id(_))) {
        return Ok(methods
            .iter()
            .map(|method| match method {
                MethodSpec::Id(id) => *id,
                MethodSpec::Name(_) => unreachable!("checked above"),
            })
            .collect());
    }
    let path = rpc_config.ok_or_else(|| anyhow!("--rpc-config is required to resolve method names in --methods"))?;
    let provider = psy_provider::provider::RpcProvider::new_with_config_path(path)?;
    let names = contract_method_names(&provider, contract_id).await?;
    methods
        .iter()
        .map(|method| match method {
            MethodSpec::Id(id) => Ok(*id),
            MethodSpec::Name(name) => names
                .iter()
                .find(|(_, function)| function == name)
                .map(|(id, _)| *id)
                .ok_or_else(|| anyhow!("method `{name}` is not found in contract {contract_id}")),
        })
        .collect()
}

/// Build a method_id -> function name table from the given contracts' code
/// definitions, for annotating `sd-key-policy-describe` output.
pub async fn method_name_map(rpc_config: Option<&str>, contracts: &[u64]) -> Result<std::collections::HashMap<u32, String>> {
    let mut map = std::collections::HashMap::new();
    if contracts.is_empty() {
        return Ok(map);
    }
    let path = rpc_config.ok_or_else(|| anyhow!("--rpc-config is required to annotate method names"))?;
    let provider = psy_provider::provider::RpcProvider::new_with_config_path(path)?;
    for contract_id in contracts {
        for (method_id, name) in contract_method_names(&provider, *contract_id).await? {
            map.entry(method_id).or_insert(name);
        }
    }
    Ok(map)
}

/// Walk a policy-file rule tree, invoking `visit` for every `Method` entry
/// written as a string. A `Contract` leaf among the direct children of an
/// `All` group scopes the names inside that group; `Any` and `Not` forward the
/// current context to their children.
fn visit_method_names(rule: &mut serde_json::Value, context: Option<u64>, visit: &mut impl FnMut(Option<u64>, &mut serde_json::Value)) {
    let Some(map) = rule.as_object_mut() else { return };
    if map.len() != 1 {
        return;
    }
    if let Some(children) = map.get_mut("All").and_then(|value| value.as_array_mut()) {
        let scoped = context.or_else(|| children.iter().find_map(|child| child.get("Contract").and_then(serde_json::Value::as_u64)));
        for child in children {
            visit_method_names(child, scoped, visit);
        }
        return;
    }
    if let Some(children) = map.get_mut("Any").and_then(|value| value.as_array_mut()) {
        for child in children {
            visit_method_names(child, context, visit);
        }
        return;
    }
    if let Some(child) = map.get_mut("Not") {
        visit_method_names(child, context, visit);
        return;
    }
    if let Some(conditional) = map.get_mut("IfThen").and_then(|value| value.as_object_mut()) {
        if let Some(condition) = conditional.get_mut("condition") { visit_method_names(condition, context, visit); }
        if let Some(then_rule) = conditional.get_mut("then") { visit_method_names(then_rule, context, visit); }
        return;
    }
    if let Some(method) = map.get_mut("Method") {
        if method.is_string() {
            visit(context, method);
        }
    }
}

/// Visit every string `Method` in a composed policy file's rule roots.
fn visit_policy_file_method_names(file: &mut serde_json::Value, visit: &mut impl FnMut(Option<u64>, &mut serde_json::Value)) {
    if let Some(rule) = file.get_mut("per_transaction") {
        visit_method_names(rule, None, visit);
    }
    if let Some(ordered) = file.get_mut("ordered").and_then(|value| value.as_array_mut()) {
        for rule in ordered {
            visit_method_names(rule, None, visit);
        }
    }
}

/// Resolve `Method` names in a composed policy file against on-chain contract
/// code definitions and return the canonical numeric policy JSON, plus a log
/// line per resolved name. The result is what should be registered, proven,
/// and fingerprinted: resolving once keeps the policy's meaning stable across
/// contract updates.
pub async fn resolve_sd_key_policy_names(
    contents: &str,
    rpc_config: Option<&str>,
    explicit_contract: Option<u64>,
) -> Result<(String, Vec<String>)> {
    let mut value: serde_json::Value = serde_json::from_str(contents).with_context(|| "parse SD key policy file")?;
    anyhow::ensure!(
        value.get("function").is_none() && value.get("config").is_none(),
        "sd-key-policy-resolve applies to composed policy files, not compiled definitions"
    );
    let mut requests: Vec<(Option<u64>, String)> = Vec::new();
    visit_policy_file_method_names(&mut value, &mut |context, method| {
        let context = context.or(explicit_contract);
        let name = method.as_str().unwrap_or_default().to_string();
        if !requests.contains(&(context, name.clone())) {
            requests.push((context, name));
        }
    });
    if requests.is_empty() {
        return Ok((contents.to_string(), Vec::new()));
    }
    let path = rpc_config.ok_or_else(|| anyhow!("--rpc-config is required to resolve method names in the policy"))?;
    let provider = psy_provider::provider::RpcProvider::new_with_config_path(path)?;
    let mut names: std::collections::HashMap<u64, Vec<(u32, String)>> = std::collections::HashMap::new();
    for (context, name) in &requests {
        let Some(contract_id) = context else {
            anyhow::bail!("method `{name}` has no contract context; add a Contract rule to its All group or pass --contract");
        };
        if !names.contains_key(contract_id) {
            names.insert(*contract_id, contract_method_names(&provider, *contract_id).await?);
        }
        if !names[contract_id].iter().any(|(_, function)| function == name) {
            anyhow::bail!("method `{name}` is not found in contract {contract_id}");
        }
    }
    let mut log = Vec::new();
    visit_policy_file_method_names(&mut value, &mut |context, method| {
        let context = context.or(explicit_contract);
        let name = method.as_str().unwrap_or_default().to_string();
        let contract_id = context.expect("validated while collecting requests");
        let method_id = names[&contract_id]
            .iter()
            .find(|(_, function)| *function == name)
            .map(|(id, _)| *id)
            .expect("validated while collecting requests");
        log.push(format!("method `{name}` (contract {contract_id}) resolved to method_id {method_id}"));
        *method = serde_json::Value::from(method_id);
    });
    let json = serde_json::to_string_pretty(&value)?;
    parse_sd_key_dpn_definition_json(&json, "resolved policy")?;
    Ok((json, log))
}

fn sim_call_infos(calls: &[PolicySimCall]) -> (Vec<SDKeyTransactionInfo<GoldilocksField>>, Vec<Vec<GoldilocksField>>) {
    let pairs: Vec<_> = calls
        .iter()
        .map(|call| {
            (
                SDKeyTransactionInfo {
                    contract_id: GoldilocksField::from_canonical_u64(call.contract_id),
                    method_id: GoldilocksField::from_canonical_u32(call.method_id),
                    // Simulated transactions are user-initiated, so the caller
                    // is the default caller contract, exactly like the prover
                    // fills top-level session calls.
                    caller_contract_id: GoldilocksField::from_canonical_u64(
                        psy_config::network_constants::DEFAULT_CALLER_CONTRACT_ID_U64,
                    ),
                    inputs_length: GoldilocksField::from_canonical_u64(call.inputs.len() as u64),
                    inputs_hash: Default::default(),
                },
                call.inputs.iter().map(|value| GoldilocksField::from_canonical_u64(*value)).collect::<Vec<_>>(),
            )
        })
        .collect();
    (pairs.iter().map(|(info, _)| *info).collect(), pairs.into_iter().map(|(_, words)| words).collect())
}

/// Evaluate a policy file against simulated transactions offline, before the
/// key is registered. Runs the same native evaluation the prover performs
/// before proving, plus the transaction count range.
pub fn check_sd_key_policy(path: &str, calls: &[PolicySimCall]) -> Result<Vec<String>> {
    let contents = fs::read_to_string(path).with_context(|| format!("read SD key policy file {path}"))?;
    check_sd_key_policy_json(&contents, path, calls)
}

pub fn check_sd_key_policy_json(contents: &str, path: &str, calls: &[PolicySimCall]) -> Result<Vec<String>> {
    let (function, config) = parse_sd_key_dpn_definition_json(contents, path)?;
    let policy = config
        .transaction_count_policy
        .as_ref()
        .ok_or_else(|| anyhow!("SD key definition `{path}` has no transaction policy to check calls against"))?;
    anyhow::ensure!(
        calls.len() >= policy.min_tx_count as usize && calls.len() <= policy.max_tx_count as usize,
        "{} transactions outside policy range {}..={}",
        calls.len(),
        policy.min_tx_count,
        policy.max_tx_count
    );
    let mut lines = Vec::new();
    if let Some(composed) = &policy.composed {
        let (infos, inputs) = sim_call_infos(calls);
        composed.check_transaction_infos(&infos, &inputs)?;
        for (index, call) in calls.iter().enumerate() {
            lines.push(format!("tx {index}: contract {} method {} inputs {:?} - allowed", call.contract_id, call.method_id, call.inputs));
        }
        for total in &composed.totals {
            let sum: u128 = calls.iter().map(|call| *call.inputs.get(total.word as usize).unwrap_or(&0) as u128).sum();
            lines.push(format!("total word {}: sum {} <= {} - ok", total.word, sum, total.max_total));
        }
    } else if !policy.allowed_calls.is_empty() {
        for (index, call) in calls.iter().enumerate() {
            let allowed = policy.allowed_calls.iter().any(|pair| {
                pair.contract_id == call.contract_id
                    && pair.method_id == call.method_id
                    // simulated calls are user-initiated: the default caller
                    && pair
                        .caller_contract_id
                        .map(|caller| caller == psy_config::network_constants::DEFAULT_CALLER_CONTRACT_ID_U64)
                        .unwrap_or(true)
            });
            anyhow::ensure!(allowed, "tx {index}: contract {} method {} is not in the allowed call list", call.contract_id, call.method_id);
            lines.push(format!("tx {index}: contract {} method {} inputs {:?} - allowed", call.contract_id, call.method_id, call.inputs));
        }
    }
    lines.push(format!("policy check passed (function `{}`)", function.name));
    Ok(lines)
}

fn method_label(method_id: u32, names: Option<&std::collections::HashMap<u32, String>>) -> String {
    match names.and_then(|names| names.get(&method_id)) {
        Some(name) => format!("{method_id} (`{name}`)"),
        None => format!("{method_id}"),
    }
}

fn describe_call_rule(rule: &SDKeyCallRule, names: Option<&std::collections::HashMap<u32, String>>) -> String {
    match rule {
        SDKeyCallRule::All(children) => children.iter().map(|child| wrap_call_rule(child, names)).collect::<Vec<_>>().join(" and "),
        SDKeyCallRule::Any(children) => children.iter().map(|child| wrap_call_rule(child, names)).collect::<Vec<_>>().join(" or "),
        SDKeyCallRule::Not(child) => format!("not ({})", describe_call_rule(child, names)),
        SDKeyCallRule::IfThen { condition, then } => format!("if {} then {}", wrap_call_rule(condition, names), wrap_call_rule(then, names)),
        SDKeyCallRule::Contract(id) => format!("call contract {id}"),
        SDKeyCallRule::Method(id) => format!("method {}", method_label(*id, names)),
        SDKeyCallRule::Caller(id) => format!("called by contract {id}"),
        SDKeyCallRule::Input { word, comparison, value } => format!(
            "calldata word {word} {} {value}",
            match comparison {
                SDKeyComparison::Eq => "==",
                SDKeyComparison::Lt => "<",
                SDKeyComparison::Lte => "<=",
                SDKeyComparison::Gt => ">",
                SDKeyComparison::Gte => ">=",
            }
        ),
    }
}

fn wrap_call_rule(child: &SDKeyCallRule, names: Option<&std::collections::HashMap<u32, String>>) -> String {
    match child {
        SDKeyCallRule::All(_) | SDKeyCallRule::Any(_) | SDKeyCallRule::Not(_) | SDKeyCallRule::IfThen { .. } => format!("({})", describe_call_rule(child, names)),
        _ => describe_call_rule(child, names),
    }
}

/// Render what a policy file authorizes, in words, plus its fingerprint.
/// `names` optionally annotates method ids with on-chain function names.
pub fn describe_sd_key_policy(path: &str, names: Option<&std::collections::HashMap<u32, String>>) -> Result<String> {
    let contents = fs::read_to_string(path).with_context(|| format!("read SD key policy file {path}"))?;
    let mut text = describe_sd_key_policy_json(&contents, path, names)?;
    text.push_str(&format!("fingerprint: {}\n", sd_key_dpn_fingerprint_from_file(path)?));
    Ok(text)
}

pub fn describe_sd_key_policy_json(contents: &str, path: &str, names: Option<&std::collections::HashMap<u32, String>>) -> Result<String> {
    let (function, config) = parse_sd_key_dpn_definition_json(contents, path)?;
    let mut out = format!("function: {} (method_id {})\n", function.name, function.method_id);
    out += &format!("introspectable transactions: {}\n", config.num_introspectable_transactions);
    match &config.transaction_count_policy {
        None => out += "authorization: defined by the compiled function (no transaction policy)\n",
        Some(policy) => {
            out += &format!("transactions per session: {}..={}\n", policy.min_tx_count, policy.max_tx_count);
            if !policy.allowed_calls.is_empty() {
                out += "every transaction must call one of:\n";
                for call in &policy.allowed_calls {
                    let caller = call.caller_contract_id.map(|id| format!(", called by contract {id}")).unwrap_or_default();
                    out += &format!("  - contract {} method {}{}\n", call.contract_id, method_label(call.method_id, names), caller);
                }
            }
            if let Some(composed) = &policy.composed {
                let describe = |rule: &SDKeyCallRule| describe_call_rule(rule, names);
                out += &format!("every transaction must satisfy: {}\n", describe(&composed.per_transaction));
                if !composed.ordered.is_empty() {
                    out += "leading transactions are further constrained, in order:\n";
                    for (index, rule) in composed.ordered.iter().enumerate() {
                        out += &format!("  slot {index}: {}\n", describe(rule));
                    }
                }
                if !composed.totals.is_empty() {
                    out += "session totals:\n";
                    for total in &composed.totals {
                        out += &format!(
                            "  - calldata word {}: at most {} per transaction, at most {} in total\n",
                            total.word, total.max_per_tx, total.max_total
                        );
                    }
                }
                if !composed.cross_transaction.is_empty() {
                    out += "cross-transaction calldata comparisons:\n";
                    for relation in &composed.cross_transaction {
                        let op = match relation.comparison {
                            SDKeyComparison::Eq => "==", SDKeyComparison::Lt => "<", SDKeyComparison::Lte => "<=",
                            SDKeyComparison::Gt => ">", SDKeyComparison::Gte => ">=",
                        };
                        out += &format!("  - tx {} word {} {op} tx {} word {}\n", relation.left_slot, relation.left_word, relation.right_slot, relation.right_word);
                    }
                }
            }
        }
    }
    Ok(out)
}

pub fn load_wallet_key_info(args: &WalletSourceArgs, allow_generate: bool) -> Result<WalletKeyInfo> {
    match args.sign_type {
        SignType::ZKSign => {
            let (private_key, generated) = load_or_create_key(args, allow_generate)?;
            let fingerprint = get_zk_fingerprint::<GoldilocksField>();
            let priv_key_obj = SimplePsyPrivateKey::new(private_key);
            let public_key_param = priv_key_obj.get_public_key_param::<PsyHasher>();
            let public_key_hash = ZKPublicKeyInfo {
                fingerprint,
                public_key_param,
            }
            .qfhash::<PsyHasher>();
            Ok(WalletKeyInfo {
                sign_type: SignType::ZKSign,
                private_key,
                fingerprint,
                public_key_param,
                public_key_hash,
                generated,
            })
        }
        SignType::SECP256K1Sign => {
            let (private_key, generated) = load_or_create_key(args, allow_generate)?;
            let fingerprint = get_secp256k1_fingerprint::<GoldilocksField>();
            let public_key_param =
                hash_no_pad_compressed_public_key::<GoldilocksField, PoseidonPermutation<GoldilocksField>>(get_secp_public_key(private_key)?);
            let public_key_hash = ZKPublicKeyInfo {
                fingerprint,
                public_key_param,
            }
            .qfhash::<PsyHasher>();
            Ok(WalletKeyInfo {
                sign_type: SignType::SECP256K1Sign,
                private_key,
                fingerprint,
                public_key_param,
                public_key_hash,
                generated,
            })
        }
        SignType::EthPersonalSECP256K1Sign => {
            let (private_key, generated) = load_or_create_key(args, allow_generate)?;
            let fingerprint = get_eth_personal_secp256k1_fingerprint::<GoldilocksField>();
            let public_key_param =
                hash_no_pad_compressed_public_key::<GoldilocksField, PoseidonPermutation<GoldilocksField>>(get_secp_public_key(private_key)?);
            let public_key_hash = ZKPublicKeyInfo {
                fingerprint,
                public_key_param,
            }
            .qfhash::<PsyHasher>();
            Ok(WalletKeyInfo {
                sign_type: SignType::EthPersonalSECP256K1Sign,
                private_key,
                fingerprint,
                public_key_param,
                public_key_hash,
                generated,
            })
        }
        SignType::SDKeyDpnSign => {
            let (private_key, generated) = load_or_create_key(args, allow_generate)?;
            let fingerprint = match (&args.fingerprint, &args.sd_key_definition) {
                (Some(value), Some(_)) => {
                    let supplied = QHashOut::<GoldilocksField>::from_str(value)?;
                    let configured = sd_key_dpn_fingerprint(args)?;
                    anyhow::ensure!(supplied == configured, "SD key fingerprint does not match policy file");
                    supplied
                }
                (Some(value), None) => QHashOut::<GoldilocksField>::from_str(value)?,
                (None, Some(_)) => sd_key_dpn_fingerprint(args)?,
                (None, None) => bail!("sd-key sign needs --fingerprint or --sd-key-definition"),
            };
            let public_key_param = get_sd_key_public_key_param(&private_key);
            let public_key_hash = ZKPublicKeyInfo {
                fingerprint,
                public_key_param,
            }
            .qfhash::<PsyHasher>();
            Ok(WalletKeyInfo {
                sign_type: SignType::SDKeyDpnSign,
                private_key,
                fingerprint,
                public_key_param,
                public_key_hash,
                generated,
            })
        }
        SignType::SDKeyPlonky2Sign => {
            let (private_key, generated) = load_or_create_key(args, allow_generate)?;
            let fingerprint = QHashOut::<GoldilocksField>::from_str(
                args.fingerprint.as_ref().ok_or_else(|| anyhow!("sd-key sign need fingerprint"))?,
            )?;
            let public_key_param = get_sdc_public_key_param(&private_key);
            let public_key_hash = ZKPublicKeyInfo { fingerprint, public_key_param }.qfhash::<PsyHasher>();
            Ok(WalletKeyInfo {
                sign_type: SignType::SDKeyPlonky2Sign,
                private_key,
                fingerprint,
                public_key_param,
                public_key_hash,
                generated,
            })
        }
    }
}

fn load_or_create_key(args: &WalletSourceArgs, allow_generate: bool) -> Result<(QHashOut<GoldilocksField>, bool)> {
    if let Some(raw) = &args.private_key {
        return Ok((parse_qhash(raw)?, false));
    }
    if let Some(path) = &args.keystore_path {
        match Wallet::load(None, Some(Path::new(path)), args.wallet_password.as_deref()) {
            Ok(wallet) => return Ok((parse_qhash(&wallet.private_key_hex())?, false)),
            Err(_) if allow_generate => {
                let wallet = Wallet::new()?;
                wallet.save(Path::new(path), args.wallet_password.as_deref())?;
                return Ok((parse_qhash(&wallet.private_key_hex())?, true));
            }
            Err(e) => return Err(e),
        }
    }
    if allow_generate {
        Ok((QHashOut::<GoldilocksField>::rand(), true))
    } else {
        bail!("--private-key or --keystore-path is required");
    }
}

fn parse_qhash(value: &str) -> Result<QHashOut<GoldilocksField>> {
    let normalized = value.trim().trim_start_matches("0x");
    let hash = Hash256::from_hex_string(normalized).map_err(|e| anyhow!("failed to parse private key: {}", e))?;
    Ok(QHashOut::from(hash))
}
