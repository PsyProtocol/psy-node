use std::{path::Path, str::FromStr};

use anyhow::Context;
use plonky2::field::goldilocks_field::GoldilocksField;
use psy_client_common::{
    args::{ContractCallArgs, ContractCallData},
    data::qhashout::QHashOut,
    setup_logging,
};
use psy_client_data::traits::qdatastore::qmetadata::QMetaDataStoreReaderSync;
use psy_config::PsyConfigGoldilocks;
use psy_prover::session::WalletSession;
use psy_provider::provider::QUserRpcProvider;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    setup_logging()?;
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let cfg_path = repo_root.join("client_prover/config.json");
    let keys_path = repo_root.join("private_keys.json");

    let psy_config = PsyConfigGoldilocks::from_file(&cfg_path.to_string_lossy())?;
    let rpc_config = psy_config.get_current_network()?.clone();
    let keys: Vec<String> = serde_json::from_str(&std::fs::read_to_string(keys_path)?)?;
    let user0_sk = QHashOut::<GoldilocksField>::from_str(&keys[0])?;
    let user1_sk = QHashOut::<GoldilocksField>::from_str(&keys[1])?;

    let mut wallet_session = WalletSession::new(&rpc_config).await?;
    let user0_pk = wallet_session.get_zk_public_key(user0_sk).await?;
    let user1_pk = wallet_session.get_zk_public_key(user1_sk).await?;
    let user0 = wallet_session.add_user(user0_sk, user0_pk.fingerprint).await?;
    let user1 = wallet_session.add_user(user1_sk, user1_pk.fingerprint).await?;
    let user0_ids = wallet_session.st_provider.get_user_ids_for_public_key(user0).await?;
    let user1_ids = wallet_session.st_provider.get_user_ids_for_public_key(user1).await?;
    let user0_id = *user0_ids.first().context("user0 id missing")?;
    let user1_id = *user1_ids.first().context("user1 id missing")?;

    println!("user0_id={} user1_id={}", user0_id, user1_id);

    run_case(
        &mut wallet_session,
        user0,
        user0_id,
        "single",
        ContractCallData::new(vec![ContractCallArgs {
            contract_id: 0,
            method_name: "simple_mint".to_string(),
            inputs: vec![100],
        }]),
        false,
    )
    .await?;

    run_case(
        &mut wallet_session,
        user0,
        user0_id,
        "multicall",
        ContractCallData::new(vec![
            ContractCallArgs {
                contract_id: 0,
                method_name: "simple_mint".to_string(),
                inputs: vec![101],
            },
            ContractCallArgs {
                contract_id: 0,
                method_name: "simple_mint".to_string(),
                inputs: vec![202],
            },
        ]),
        false,
    )
    .await?;
    run_case(
        &mut wallet_session,
        user0,
        user0_id,
        "deferred-transfer",
        ContractCallData::new(vec![ContractCallArgs {
            contract_id: 0,
            method_name: "simple_transfer".to_string(),
            inputs: vec![user1_id, 500],
        }]),
        false,
    )
    .await?;

    run_case(
        &mut wallet_session,
        user1,
        user1_id,
        "deferred-claim",
        ContractCallData::new(vec![ContractCallArgs {
            contract_id: 0,
            method_name: "simple_claim".to_string(),
            inputs: vec![user0_id],
        }]),
        false,
    )
    .await?;

    println!("phase1 verify complete");
    Ok(())
}

async fn run_case(
    wallet_session: &mut WalletSession,
    user_pk: QHashOut<GoldilocksField>,
    user_id: u64,
    label: &str,
    call_data: ContractCallData,
    expect_deferred: bool,
) -> anyhow::Result<()> {
    let before = wallet_session.st_provider.get_latest_block_state().await?.checkpoint_id;
    let trace = wallet_session.generate_tx_trace(user_pk, call_data).await?;
    let deferred_count = trace
        .steps
        .iter()
        .map(|s| match s {
            psy_prover::trace::TraceStep::Standard(c) | psy_prover::trace::TraceStep::BurnFee(c) => c.deferred.len(),
            _ => 0,
        })
        .sum::<usize>();
    println!("{} trace steps={} deferred={}", label, trace.steps.len(), deferred_count);
    if expect_deferred && deferred_count == 0 {
        anyhow::bail!("{} expected deferred steps", label);
    }
    let tx_hash = wallet_session.prove_tx_trace(user_pk, &trace).await?;
    let cp = wallet_session
        .st_provider
        .wait_for_endcap_inclusion(user_id, tx_hash, before, Some(600), 1)
        .await?;
    println!("{} tx_hash={} included_checkpoint={}", label, tx_hash, cp);
    Ok(())
}
