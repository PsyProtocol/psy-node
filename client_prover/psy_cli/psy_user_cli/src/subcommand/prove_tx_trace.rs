use base64::Engine as _;
use psy_cli_common::key_utils::load_wallet_key_info;
use psy_client_common::args::SignType;
use psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT;
use psy_prover::session::WalletSession;
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
        SignType::SoftwareDefinedPlonky2Sign => {
            let fingerprint = wallet_session
                .wallet
                .register_plonky2_software_defined_circuit(MAX_CONTRACT_STATE_TREE_HEIGHT, 0)
                .await?;
            anyhow::ensure!(
                info.fingerprint == fingerprint,
                "software-defined-plonky2 fingerprint mismatch: expected={}, actual={}",
                info.fingerprint,
                fingerprint,
            );
        }
        SignType::SoftwareDefinedDPNSign => {
            let user_sdc: DPNFunctionCircuitDefinition = serde_json::from_str(&std::fs::read_to_string("sdc.json")?)?;
            let fingerprint = wallet_session.wallet.register_psy_software_defined_circuit(user_sdc, false).await?;
            anyhow::ensure!(
                info.fingerprint == fingerprint,
                "software-defined-dpn fingerprint mismatch: expected={}, actual={}",
                info.fingerprint,
                fingerprint,
            );
        }
        SignType::SDKeySign => {
            let source = trace
                .steps
                .iter()
                .rev()
                .find_map(|step| match step {
                    psy_prover::trace::TraceStep::ZkSign(step) => Some(&step.sign_circuit_source),
                    _ => None,
                })
                .ok_or_else(|| anyhow::anyhow!("trace is missing terminal ZkSign step for sd-key proving"))?;
            let psy_prover::trace::TraceSignCircuitSource::SdKey {
                allowed_contract_ids,
                allowed_method_ids,
                expected_tx_count,
            } = source
            else {
                anyhow::bail!("sd-key trace is missing TraceSignCircuitSource::SdKey");
            };
            let fingerprint = wallet_session
                .register_sd_key_circuit(allowed_contract_ids, allowed_method_ids, *expected_tx_count)
                .await?;
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
