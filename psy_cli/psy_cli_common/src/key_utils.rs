use std::{path::Path, str::FromStr};

use anyhow::{anyhow, bail, Result};
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
use psy_prover::wallet::memory_wallet::{get_secp256k1_fingerprint, get_zk_fingerprint};
use psy_provider::wallet::secp_wallet::Wallet;
use psy_ups_circuit::signature::sd_key::get_sd_key_public_key_param;
use psy_ups_circuit::signature::software_defined::get_sdc_public_key_param;
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
        SignType::SoftwareDefinedDPNSign => {
            let (private_key, generated) = load_or_create_key(args, allow_generate)?;
            let fingerprint = QHashOut::<GoldilocksField>::from_str(
                args.fingerprint
                    .as_ref()
                    .ok_or_else(|| anyhow!("software defined dpn sign need fingerprint"))?,
            )?;
            let public_key_param = get_sdc_public_key_param::<GoldilocksField>(&private_key);
            let public_key_hash = ZKPublicKeyInfo {
                fingerprint,
                public_key_param,
            }
            .qfhash::<PsyHasher>();
            Ok(WalletKeyInfo {
                sign_type: SignType::SoftwareDefinedDPNSign,
                private_key,
                fingerprint,
                public_key_param,
                public_key_hash,
                generated,
            })
        }
        SignType::SoftwareDefinedPlonky2Sign => {
            let (private_key, generated) = load_or_create_key(args, allow_generate)?;
            let fingerprint = QHashOut::<GoldilocksField>::from_str(
                args.fingerprint
                    .as_ref()
                    .ok_or_else(|| anyhow!("software defined plonky2 sign need fingerprint"))?,
            )?;
            let public_key_param = get_sdc_public_key_param::<GoldilocksField>(&private_key);
            let public_key_hash = ZKPublicKeyInfo {
                fingerprint,
                public_key_param,
            }
            .qfhash::<PsyHasher>();
            Ok(WalletKeyInfo {
                sign_type: SignType::SoftwareDefinedPlonky2Sign,
                private_key,
                fingerprint,
                public_key_param,
                public_key_hash,
                generated,
            })
        }
        SignType::SDKeySign => {
            let (private_key, generated) = load_or_create_key(args, allow_generate)?;
            let fingerprint = QHashOut::<GoldilocksField>::from_str(
                args.fingerprint
                    .as_ref()
                    .ok_or_else(|| anyhow!("sd-key sign need fingerprint"))?,
            )?;
            let public_key_param = get_sd_key_public_key_param(&private_key);
            let public_key_hash = ZKPublicKeyInfo {
                fingerprint,
                public_key_param,
            }
            .qfhash::<PsyHasher>();
            Ok(WalletKeyInfo {
                sign_type: SignType::SDKeySign,
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
