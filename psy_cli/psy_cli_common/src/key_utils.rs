use std::{fs, path::Path, str::FromStr};

use anyhow::{anyhow, bail, Context, Result};
use plonky2::{field::goldilocks_field::GoldilocksField, hash::poseidon::PoseidonPermutation};
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
use psy_prover::wallet::memory_wallet::{get_eth_personal_secp256k1_fingerprint, get_secp256k1_fingerprint, get_zk_fingerprint};
use psy_provider::wallet::secp_wallet::Wallet;
use psy_ups_circuit::signature::sd_key_dpn::get_sd_key_public_key_param;
use psy_ups_circuit::signature::sd_key_dpn::SDKeyDpnCircuitGadget;
use psy_vm::{dpn::vm::def::DPNFunctionCircuitDefinition, ups::sd_key::{SDKeyCallRule, SDKeyInputTotalLimit}};
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
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ComposedSDKeyPolicyFile {
    per_transaction: SDKeyCallRule,
    #[serde(default)]
    ordered: Vec<SDKeyCallRule>,
    #[serde(default)]
    totals: Vec<SDKeyInputTotalLimit>,
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
    psy_vm::ups::sd_key::build_composed_sd_key_policy_with_totals(
        &policy.per_transaction,
        &policy.ordered,
        &policy.totals,
        policy.min_tx_count,
        policy.max_tx_count,
    )
}

#[cfg(test)]
mod policy_tests {
    use super::parse_sd_key_dpn_definition_json;

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
}

pub fn sd_key_dpn_fingerprint_from_file(path: &str) -> Result<QHashOut<GoldilocksField>> {
    let (function, config) = load_sd_key_dpn_definition_from_file(path)?;
    Ok(SDKeyDpnCircuitGadget::build_from_dpn_function(&function, &config)?.get_fingerprint())
}

pub fn sd_key_dpn_fingerprint(args: &WalletSourceArgs) -> Result<QHashOut<GoldilocksField>> {
    let (function, config) = load_sd_key_dpn_definition(args)?;
    Ok(SDKeyDpnCircuitGadget::build_from_dpn_function(&function, &config)?.get_fingerprint())
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
