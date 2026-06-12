use std::str::FromStr;

use plonky2::field::types::Field;
use psy_client_common::{data::qhashout::QHashOut, ups::circuits::LocalCircuitType};
use psy_client_data::config::store_config::F;
use psy_crypto::{
    hash::traits::hasher::{FieldQHasher, PoseidonHasher},
    signature::zk::wallet::SimplePsyPrivateKey,
};
use psy_prover::session::WalletSession;

use crate::subcommand::args::DeriveNoteOwnerArgs;

pub async fn run(args: DeriveNoteOwnerArgs) -> anyhow::Result<()> {
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
    Ok(())
}
