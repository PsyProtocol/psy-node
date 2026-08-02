use std::str::FromStr;

use nostr_sdk::prelude::{Keys, ToBech32};
use plonky2::field::types::Field;
use psy_client_common::{data::qhashout::QHashOut, ups::circuits::LocalCircuitType};
use psy_client_data::config::store_config::F;
use psy_crypto::{
    hash::traits::hasher::{FieldQHasher, PoseidonHasher},
    signature::zk::wallet::SimplePsyPrivateKey,
};
use psy_prover::session::WalletSession;
use sha2::{Digest, Sha256};

use crate::{
    result::{CommandResult, NoteOwnerResult},
    subcommand::args::DeriveNoteOwnerArgs,
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

pub async fn run(args: DeriveNoteOwnerArgs) -> anyhow::Result<CommandResult> {
    let psy_config = psy_config::PsyConfigGoldilocks::from_file(&args.rpc_config)?;
    let rpc_config = psy_config.get_current_network()?.clone();

    let receiver_sk = QHashOut::<F>::from_str(&args.private_key).map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?;
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

    let note_owner = PoseidonHasher::q_hash_many(&[
        F::from_canonical_u64(receiver_user_id),
        F::from_canonical_u64(1337),
        F::from_canonical_u64(args.random0),
        F::from_canonical_u64(args.random1),
    ]);

    println!("public_key: {}", receiver_public_key);
    println!("user_id: {}", receiver_user_id);
    println!("random0: {}", args.random0);
    println!("random1: {}", args.random1);
    println!("note_owner: {}", note_owner);
    let nostr_npub = derive_nostr_npub(&args.private_key, args.random0, args.random1)?;
    println!("nostr_npub: {}", nostr_npub);
    println!("private_address: {}#{}", note_owner, nostr_npub);
    Ok(CommandResult::NoteOwner(NoteOwnerResult {
        public_key: receiver_public_key,
        user_id: receiver_user_id,
        note_owner,
        nostr_npub,
    }))
}
