use std::str::FromStr;

use nostr_sdk::prelude::{Keys, ToBech32};
use psy_client_common::{data::qhashout::QHashOut, ups::circuits::LocalCircuitType};
use psy_client_data::config::store_config::F;
use psy_crypto::{
    hash::traits::hasher::PoseidonHasher,
    shield_address::derive_shield_address,
    signature::zk::wallet::SimplePsyPrivateKey,
};
use psy_prover::session::WalletSession;
use sha2::{Digest, Sha256};

use crate::{
    result::{CommandResult, ShieldAddressResult},
    subcommand::args::DeriveShieldArgs,
};

const NOSTR_PREFIX: &[u8] = b"psy-privacy-v0-nostr";

fn pad64(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let mut normalized_key = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        normalized_key[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized_key[..key.len()].copy_from_slice(key);
    }

    let mut outer_pad = [0x5cu8; BLOCK_SIZE];
    let mut inner_pad = [0x36u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        outer_pad[i] ^= normalized_key[i];
        inner_pad[i] ^= normalized_key[i];
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_hash);
    outer.finalize().into()
}

fn derive_nostr_npub(private_key: &str, random0: u64, random1: u64) -> anyhow::Result<String> {
    let private_key_bytes = hex::decode(private_key.trim_start_matches("0x"))?;
    let mut data = Vec::with_capacity(NOSTR_PREFIX.len() + 16);
    data.extend_from_slice(NOSTR_PREFIX);
    data.extend_from_slice(&pad64(random0));
    data.extend_from_slice(&pad64(random1));

    let nostr_secret = hmac_sha256(&private_key_bytes, &data);
    let nostr_secret_hex = hex::encode(nostr_secret);
    let keys = Keys::parse(&nostr_secret_hex)?;
    Ok(keys.public_key().to_bech32()?)
}

pub async fn run(args: DeriveShieldArgs) -> anyhow::Result<CommandResult> {
    match (&args.private_key, args.user_id) {
        (Some(private_key), None) => run_from_private_key(args.rpc_config, private_key, args.random0, args.random1).await,
        (None, Some(user_id)) => run_from_user_id(user_id, args.random0, args.random1),
        _ => anyhow::bail!("exactly one of --private-key or --user-id is required"),
    }
}

async fn run_from_private_key(rpc_config: String, private_key: &str, random0: u64, random1: u64) -> anyhow::Result<CommandResult> {
    let psy_config = psy_config::PsyConfigGoldilocks::from_file(&rpc_config)?;
    let rpc_config = psy_config.get_current_network()?.clone();

    let receiver_sk = QHashOut::<F>::from_str(private_key).map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?;
    let wallet_session = WalletSession::new(&rpc_config).await?;
    let zk_sig_fingerprint = wallet_session
        .circuit_info
        .get_circuit_info_by_id(LocalCircuitType::SimpleZKSignature.into())?
        .fingerprint;
    let receiver_public_key = SimplePsyPrivateKey::new(receiver_sk).get_public_key_for_fingerprint::<PoseidonHasher>(zk_sig_fingerprint);
    let receiver_user_id = wallet_session
        .st_provider
        .get_user_ids_for_public_key(receiver_public_key)
        .await?
        .first()
        .copied()
        .ok_or_else(|| anyhow::anyhow!("No user id found for receiver public key"))?;

    let shield_address = derive_shield_address(receiver_user_id, random0, random1);
    let nostr_npub = derive_nostr_npub(private_key, random0, random1)?;
    print_shield(receiver_user_id, shield_address, Some(&nostr_npub));
    Ok(CommandResult::ShieldAddress(ShieldAddressResult {
        public_key: Some(receiver_public_key),
        user_id: receiver_user_id,
        shield_address,
        nostr_npub: Some(nostr_npub),
    }))
}

fn run_from_user_id(user_id: u64, random0: u64, random1: u64) -> anyhow::Result<CommandResult> {
    let shield_address = derive_shield_address(user_id, random0, random1);
    print_shield(user_id, shield_address, None);
    Ok(CommandResult::ShieldAddress(ShieldAddressResult {
        public_key: None,
        user_id,
        shield_address,
        nostr_npub: None,
    }))
}

fn print_shield(user_id: u64, shield_address: QHashOut<F>, nostr_npub: Option<&str>) {
    println!("user_id: {}", user_id);
    println!("shield_address: {}", shield_address);
    if let Some(nostr_npub) = nostr_npub {
        println!("nostr_npub: {}", nostr_npub);
        println!("private_address: {}#{}", shield_address, nostr_npub);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subcommand::{args::DeriveShieldArgs, Cli};
    use clap::Parser;

    fn parse(argv: &[&str]) -> Result<DeriveShieldArgs, clap::error::Error> {
        let mut args = vec!["psy_user_cli"];
        args.extend(argv);
        match Cli::try_parse_from(args)?.command {
            crate::subcommand::Commands::DeriveShield(args) => Ok(args),
            _ => panic!("expected DeriveShield"),
        }
    }

    #[test]
    fn parse_rejects_missing_identity() {
        assert!(parse(&["derive-shield", "--random0", "1", "--random1", "2"]).is_err());
    }

    #[test]
    fn parse_rejects_both_identities() {
        assert!(parse(&[
            "derive-shield",
            "--private-key",
            "aa",
            "--user-id",
            "7",
            "--random0",
            "1",
            "--random1",
            "2",
        ])
        .is_err());
    }

    #[test]
    fn parse_accepts_user_id_without_rpc() {
        let args = parse(&["derive-shield", "--user-id", "7", "--random0", "1", "--random1", "2"]).unwrap();
        assert_eq!(args.user_id, Some(7));
        assert!(args.private_key.is_none());
    }

    #[test]
    fn parse_accepts_private_key() {
        let args = parse(&["derive-shield", "--private-key", "aa", "--random0", "1", "--random1", "2"]).unwrap();
        assert_eq!(args.private_key.as_deref(), Some("aa"));
        assert!(args.user_id.is_none());
    }

    #[test]
    fn user_id_path_matches_crypto_helper() {
        let result = run_from_user_id(7, 1, 2).unwrap();
        match result {
            CommandResult::ShieldAddress(value) => {
                assert_eq!(value.user_id, 7);
                assert_eq!(value.shield_address, derive_shield_address(7, 1, 2));
                assert!(value.public_key.is_none());
                assert!(value.nostr_npub.is_none());
            }
            _ => panic!("expected ShieldAddress"),
        }
    }

}
