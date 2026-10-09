use base64::Engine as _;
use psy_cli_common::key_utils::load_wallet_key_info;
use psy_client_common::args::SignType;
use psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT;
use psy_prover::session::WalletSession;
use psy_prover::wallet::memory_wallet::SdKeyCircuitDefinition;
use psy_provider::provider::RpcProvider;
use psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition;

use crate::result::{CommandResult, TransactionResult, TransactionStatus};

#[derive(clap::Args)]
pub struct ProveTxTraceArgs {
    #[command(flatten)]
    pub session: psy_client_common::args::WalletSessionArgs,
    #[arg(long, default_value = "trace.json")]
    pub input: String,
    #[arg(long)]
    pub output: Option<String>,
    #[arg(long)]
    pub wait: bool,
}

pub async fn run(args: ProveTxTraceArgs) -> anyhow::Result<CommandResult> {
    let psy_config = psy_config::PsyConfigGoldilocks::from_file(&args.session.rpc_config)?;
    let rpc_config = psy_config.get_current_network()?.clone();
    let network = psy_config.current_network_name().to_string();
    let envelope_json = std::fs::read_to_string(&args.input)?;
    let envelope: psy_prover::trace::GeneratedTxTraceJson = serde_json::from_str(&envelope_json)?;
    let trace: psy_prover::trace::TxTrace = match envelope.trace.encoding.as_str() {
        "json" => serde_json::from_str(&envelope.trace.payload)?,
        "bincode-base64" => {
            let payload = base64::engine::general_purpose::STANDARD
                .decode(&envelope.trace.payload)
                .map_err(|error| anyhow::anyhow!("failed to decode trace payload: {}", error))?;
            bincode::deserialize(&payload)?
        }
        other => anyhow::bail!("unsupported trace payload encoding: {}", other),
    };
    tracing::info!(
        "loaded trace from {} (steps: {}, encoding: {})",
        args.input,
        trace.steps.len(),
        envelope.trace.encoding,
    );
    let provider = RpcProvider::new_with_config(&rpc_config)?;
    let info = load_wallet_key_info(&args.session.wallet, false)?;
    let checkpoint_before = provider.get_coordinator_latest_block_state().await?.checkpoint_id;
    let mut wallet_session = WalletSession::new(&rpc_config).await?;
    match args.session.wallet.sign_type {
        SignType::SDKeyPlonky2Sign => {
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
        SignType::SDKeyDpnSign => {
            let source = trace
                .steps
                .iter()
                .rev()
                .find_map(|step| match step {
                    psy_prover::trace::TraceStep::ZkSign(step) => Some(&step.sign_circuit_source),
                    _ => None,
                })
                .ok_or_else(|| anyhow::anyhow!("trace is missing terminal ZkSign step for sd-key proving"))?;
            let definition = match source {
                psy_prover::trace::TraceSignCircuitSource::SdKeyDpn { function_def, config } => SdKeyCircuitDefinition::Dpn {
                    function: bincode::deserialize(function_def)?,
                    config: config.clone(),
                },
                psy_prover::trace::TraceSignCircuitSource::SdKeyPlonky2 {
                    contract_state_tree_height,
                    input_len,
                } => SdKeyCircuitDefinition::Plonky2 {
                    contract_state_tree_height: *contract_state_tree_height,
                    input_len: *input_len,
                },
                _ => anyhow::bail!("trace is missing an SD-key signing circuit"),
            };
            let fingerprint = match definition {
                SdKeyCircuitDefinition::Dpn { function, config } => wallet_session.wallet.register_sd_key_dpn_circuit(function, config).await?,
                SdKeyCircuitDefinition::Plonky2 { contract_state_tree_height, input_len } => {
                    wallet_session.wallet.register_sd_key_plonky2_circuit(contract_state_tree_height, input_len).await?
                }
            };
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
    let tx_hash = wallet_session.prove_tx_trace(user_pk_hash, &trace).await?;
    let end_user_leaf_hash = trace.finalization.submit_end_cap_input.core.state_transition.end_user_leaf_hash;
    let proved = psy_prover::trace::ProvedTxResultJson::new(
        envelope.sig_hash,
        tx_hash.to_string(),
        None,
        "submitted".to_string(),
    );
    let rendered = serde_json::to_string_pretty(&proved)?;
    println!("{}", rendered);
    if let Some(path) = &args.output {
        std::fs::write(path, rendered.as_bytes())?;
    }
    let (status, confirmed_checkpoint) = if args.wait {
        let checkpoint = provider
            .wait_for_endcap_inclusion(trace.meta.user_id, end_user_leaf_hash, checkpoint_before, Some(180), 1)
            .await?;
        (TransactionStatus::Confirmed, Some(checkpoint))
    } else {
        (TransactionStatus::Submitted, None)
    };
    Ok(CommandResult::Transaction(TransactionResult {
        transaction_hash: tx_hash,
        user_id: Some(trace.meta.user_id),
        status,
        confirmed_checkpoint,
        network,
    }))
}
