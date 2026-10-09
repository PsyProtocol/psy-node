use plonky2::field::goldilocks_field::GoldilocksField as F;
use psy_cli_common::key_utils::load_wallet_key_info;
use psy_client_common::args::{ContractCallData, WalletSessionArgs};
use psy_client_data::traits::qdatastore::qmetadata::QMetaDataStoreReaderSync;
use psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT;
use psy_prover::{session::WalletSession, trace::GeneratedTxTraceJson};

use crate::result::{write_json_atomically, CommandResult, TxTraceResult};

#[derive(clap::Args)]
pub struct GenerateTxTraceArgs {
    #[command(flatten)]
    pub session: WalletSessionArgs,
    #[arg(long, required = true)]
    pub output: String,
}

pub async fn run(args: GenerateTxTraceArgs) -> anyhow::Result<CommandResult> {
    let rpc_config = {
        let psy_config = psy_config::PsyConfigGoldilocks::from_file(&args.session.rpc_config)?;
        psy_config.get_current_network()?.clone()
    };
    let info = load_wallet_key_info(&args.session.wallet, false)?;
    let contract_call_data: ContractCallData = args.session.to_contract_call_data()?;
    let mut wallet_session = WalletSession::new(&rpc_config).await?;
    match args.session.wallet.sign_type {
        psy_client_common::args::SignType::SDKeyPlonky2Sign => {
            let fingerprint = wallet_session
                .wallet
                .register_sd_key_plonky2_circuit(MAX_CONTRACT_STATE_TREE_HEIGHT, 0)
                .await?;
            anyhow::ensure!(
                info.fingerprint == fingerprint,
                "software-defined-plonky2 fingerprint mismatch: expected={}, actual={}",
                info.fingerprint,
                fingerprint,
            );
        }
        psy_client_common::args::SignType::SDKeyDpnSign => {
            let (min_tx_count, max_tx_count) = args.session.wallet.sd_key_tx_count_range();
            let (function, config) = psy_vm::ups::sd_key::build_allow_method_policy_range(
                &args.session.wallet.sd_key_allowed_contract_id,
                &args.session.wallet.sd_key_allowed_method_id,
                min_tx_count,
                max_tx_count,
            )?;
            let fingerprint = wallet_session.register_sd_key_dpn_circuit(function, config).await?;
            anyhow::ensure!(
                info.fingerprint == fingerprint,
                "sd-key fingerprint mismatch: expected={}, actual={}",
                info.fingerprint,
                fingerprint,
            );
        }
        _ => {}
    };
    let user_pk_hash = wallet_session.add_user(info.private_key, info.fingerprint).await?;
    let trace = wallet_session.generate_tx_trace(user_pk_hash, contract_call_data.clone()).await?;
    let envelope = GeneratedTxTraceJson::from_trace(&trace, serde_json::to_value(&contract_call_data)?)?;
    write_json_atomically(std::path::Path::new(&args.output), &envelope)?;
    tracing::info!("trace envelope saved to {}", args.output);
    println!("generated tx trace: tx_hash={}, output={}", envelope.tx_hash, args.output);

    Ok(CommandResult::TxTrace(TxTraceResult {
        user_id: envelope.user_id,
        pk_hash: envelope.pk_hash,
        sig_hash: envelope.sig_hash,
        tx_hash: envelope.tx_hash,
        tx_count: envelope.tx_count,
        output_path: Some(args.output),
    }))
}
