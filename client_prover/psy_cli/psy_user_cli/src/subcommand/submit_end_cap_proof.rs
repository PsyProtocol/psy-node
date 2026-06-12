use plonky2::field::goldilocks_field::GoldilocksField as F;
use psy_cli_common::key_utils::load_wallet_key_info;
use psy_client_common::{
    args::{SignType, WalletSessionArgs},
    data::qhashout::QHashOut,
};
use psy_client_data::traits::qdatastore::qmetadata::QMetaDataStoreReaderSync;
use psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT;
use psy_prover::session::WalletSession;
use psy_provider::provider::RpcProvider;
use psy_vm::dpn::{contract::cfc_code_definition_to_dapen_fc, vm::def::DPNFunctionCircuitDefinition};

use psy_client_common::args::ContractCallArgs;

fn allowed_contract_method_pairs(allowed_contract_ids: &[u64], allowed_method_ids: &[u64]) -> anyhow::Result<Vec<(u64, u64)>> {
    if allowed_contract_ids.is_empty() {
        anyhow::bail!("sdk-key sign needs at least one --sdk-key-allowed-contract-id");
    }
    if allowed_method_ids.is_empty() {
        anyhow::bail!("sdk-key sign needs at least one --sdk-key-allowed-method-id");
    }

    if allowed_contract_ids.len() == allowed_method_ids.len() {
        return Ok(allowed_contract_ids
            .iter()
            .copied()
            .zip(allowed_method_ids.iter().copied())
            .collect());
    }
    if allowed_contract_ids.len() == 1 {
        return Ok(allowed_method_ids
            .iter()
            .copied()
            .map(|method_id| (allowed_contract_ids[0], method_id))
            .collect());
    }
    if allowed_method_ids.len() == 1 {
        return Ok(allowed_contract_ids
            .iter()
            .copied()
            .map(|contract_id| (contract_id, allowed_method_ids[0]))
            .collect());
    }

    anyhow::bail!(
        "sdk-key allowed contract_id and method_id lists must have the same length, or one list must contain exactly one value"
    );
}

async fn validate_sdk_key_allowed_calls(
    provider: &RpcProvider,
    contract_calls: &[ContractCallArgs],
    allowed_contract_ids: &[u64],
    allowed_method_ids: &[u64],
    expected_tx_count: u64,
) -> anyhow::Result<()> {
    let allowed_pairs = allowed_contract_method_pairs(allowed_contract_ids, allowed_method_ids)?;

    for (call_index, call) in contract_calls.iter().enumerate() {
        let contract_code = provider.get_contract_code_definition(call.contract_id).await?;
        let method = contract_code
            .functions
            .iter()
            .find_map(|func| {
                cfc_code_definition_to_dapen_fc(func)
                    .ok()
                    .filter(|dapen_fc| dapen_fc.name == call.method_name)
                    .map(|_| func.method_id as u64)
            })
            .ok_or_else(|| anyhow::anyhow!("method `{}` is not found in contract {}", call.method_name, call.contract_id))?;

        if !allowed_pairs.contains(&(call.contract_id, method)) {
            anyhow::bail!(
                "SDK key policy denied call_index={} contract_id={} method_name={} method_id={}; expected_tx_count={}; allowed_pairs={:?}",
                call_index,
                call.contract_id,
                call.method_name,
                method,
                expected_tx_count,
                allowed_pairs
            );
        }
    }

    Ok(())
}

pub async fn run(args: WalletSessionArgs) -> anyhow::Result<()> {
    let psy_config = psy_config::PsyConfigGoldilocks::from_file(&args.rpc_config)?;
    let rpc_config = psy_config.get_current_network()?.clone();
    let provider = RpcProvider::new_with_config(&rpc_config)?;
    let wait_until_confirmation = args.wait_until_confirmation;
    let info = load_wallet_key_info(&args.wallet, false)?;
    let user_id = provider
        .get_user_ids_for_public_key(info.public_key_hash)
        .await?
        .first()
        .copied()
        .ok_or_else(|| anyhow::anyhow!("No user id found for sender public key"))?;
    let checkpoint_before = provider.get_coordinator_latest_block_state().await?.checkpoint_id;

    let end_user_leaf_hash = run_with_end_user_leaf_hash(args).await?;
    tracing::info!("endcap submitted! end_user_leaf_hash: {}", end_user_leaf_hash);

    if wait_until_confirmation {
        let confirmed_checkpoint =
            provider
                .wait_for_endcap_inclusion(user_id, end_user_leaf_hash, checkpoint_before, Some(180), 1)
                .await?;
        tracing::info!(
            checkpoint_id = confirmed_checkpoint,
            user_id,
            end_user_leaf_hash = %end_user_leaf_hash,
            "endcap included"
        );
        return Ok(());
    }

    Ok(())
}

pub async fn run_with_end_user_leaf_hash(args: WalletSessionArgs) -> anyhow::Result<QHashOut<F>> {
    let psy_config = psy_config::PsyConfigGoldilocks::from_file(&args.rpc_config)?;
    let rpc_config = psy_config.get_current_network()?.clone();

    let mut wallet_session = WalletSession::new(&rpc_config).await?;
    let info = load_wallet_key_info(&args.wallet, false)?;
    let contract_call_data = args.to_contract_call_data()?;

    match args.wallet.sign_type {
        SignType::SoftwareDefinedPlonky2Sign => {
            let fingerprint = wallet_session
                .wallet
                .register_plonky2_software_defined_circuit(MAX_CONTRACT_STATE_TREE_HEIGHT, 0)
                .await?;

            if let Some(mut _circuit) = wallet_session.wallet.get_plonky2_software_defined_circuit_mut(&fingerprint) {
                // add custom constraints here
                // state_reader must do the same thing while generating
                // witnesses
            }

            assert_eq!(info.fingerprint, fingerprint, "software-defined-plonky2-sign key fingerprint mismatch");
        }
        SignType::SoftwareDefinedDPNSign => {
            let user_sdc: DPNFunctionCircuitDefinition = serde_json::from_str(&std::fs::read_to_string("sdc.json")?)?;
            let fingerprint = wallet_session.wallet.register_psy_software_defined_circuit(user_sdc, false).await?;
            assert_eq!(info.fingerprint, fingerprint, "software-defined-dpn-sign key fingerprint mismatch");
        }
        SignType::SDKKeySign => {
            let allowed_contract_ids = &args.wallet.sdk_key_allowed_contract_id;
            if allowed_contract_ids.is_empty() {
                anyhow::bail!("sdk-key sign needs at least one --sdk-key-allowed-contract-id");
            }
            let allowed_method_ids = &args.wallet.sdk_key_allowed_method_id;
            if allowed_method_ids.is_empty() {
                anyhow::bail!("sdk-key sign needs at least one --sdk-key-allowed-method-id");
            }
            let expected_tx_count = args.wallet.sdk_key_expected_tx_count;
            validate_sdk_key_allowed_calls(
                &wallet_session.st_provider,
                &contract_call_data.contract_calls,
                allowed_contract_ids,
                allowed_method_ids,
                expected_tx_count,
            )
            .await?;
            let fingerprint = wallet_session
                .register_sdk_key_circuit(allowed_contract_ids, allowed_method_ids, expected_tx_count)
                .await?;
            assert_eq!(info.fingerprint, fingerprint, "sdk-key fingerprint mismatch");
        }
        _ => {}
    };
    let user_pk_hash = wallet_session.add_user(info.private_key, info.fingerprint).await?;
    wallet_session.exec_contract_call(user_pk_hash, contract_call_data).await
}
