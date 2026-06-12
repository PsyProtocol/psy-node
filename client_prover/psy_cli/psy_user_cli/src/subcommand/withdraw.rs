use psy_cli_common::key_utils::load_wallet_key_info;
use psy_client_common::args::{ContractCallArgs, ContractCallData, SignType};
use psy_config::{network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT, TOKEN_CONTRACT_ID};
use psy_prover::session::WalletSession;
use psy_provider::provider::RpcProvider;
use psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition;

use super::args::WithdrawArgs;

/// Parse a 32-byte hex string into 8 u32 words (big-endian word order).
fn parse_hash_hex_u32x8(hex_str: &str) -> anyhow::Result<[u32; 8]> {
    let raw = hex_str.trim().trim_start_matches("0x").trim_start_matches("0X");
    anyhow::ensure!(raw.len() == 64, "hash hex must be 64 hex chars (32 bytes), got {}: {}", raw.len(), raw);
    let bytes = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&raw[i..i+2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|e| anyhow::anyhow!("hex decode error: {}", e))?;
    anyhow::ensure!(bytes.len() == 32, "hash hex must decode to 32 bytes, got {}", bytes.len());
    let mut words = [0u32; 8];
    for (i, chunk) in bytes.chunks_exact(4).enumerate() {
        words[i] = u32::from_be_bytes(chunk.try_into().unwrap());
    }
    Ok(words)
}

fn u64_to_u32x8_be(value: u64) -> [u32; 8] {
    [0, 0, 0, 0, 0, 0, (value >> 32) as u32, (value & 0xffff_ffff) as u32]
}

pub async fn run(args: WithdrawArgs) -> anyhow::Result<()> {
    let psy_config = psy_config::PsyConfigGoldilocks::from_file(&args.rpc_config)?;
    let rpc_config = psy_config.get_current_network()?.clone();
    let provider = RpcProvider::new_with_config(&rpc_config)?;

    // 1. Parse hex inputs → 8 u32 felts each
    let token_address = parse_hash_hex_u32x8(&args.token_address)?;
    let amount = u64_to_u32x8_be(args.amount);
    let recipient = parse_hash_hex_u32x8(&args.recipient)?;

    // 2. Build contract call inputs withdraw(destination_chain_id,
    //    token_address[8], amount[8], recipient[8], nonce) = 26 felts total
    let mut inputs: Vec<u64> = Vec::with_capacity(26);
    inputs.push(args.destination_chain_id);
    inputs.extend(token_address.into_iter().map(|x| x as u64));
    inputs.extend(amount.into_iter().map(|x| x as u64));
    inputs.extend(recipient.into_iter().map(|x| x as u64));
    inputs.push(args.nonce);

    let contract_call = ContractCallArgs {
        contract_id: TOKEN_CONTRACT_ID as u64, // token contract
        method_name: "withdraw".to_string(),
        inputs,
    };
    let contract_call_data = ContractCallData::new(vec![contract_call]);

    // 3. Create wallet session and submit transaction
    let mut wallet_session = WalletSession::new(&rpc_config).await?;
    let info = load_wallet_key_info(&args.wallet, false)?;

    match args.wallet.sign_type {
        SignType::SoftwareDefinedPlonky2Sign => {
            let fingerprint = wallet_session
                .wallet
                .register_plonky2_software_defined_circuit(MAX_CONTRACT_STATE_TREE_HEIGHT, 0)
                .await?;
            assert_eq!(info.fingerprint, fingerprint, "software-defined-plonky2-sign key fingerprint mismatch");
        }
        SignType::SoftwareDefinedDPNSign => {
            let user_sdc: DPNFunctionCircuitDefinition = serde_json::from_str(&std::fs::read_to_string("sdc.json")?)?;
            let fingerprint = wallet_session.wallet.register_psy_software_defined_circuit(user_sdc, false).await?;
            assert_eq!(info.fingerprint, fingerprint, "software-defined-dpn-sign key fingerprint mismatch");
        }
        _ => {}
    };

    let user_pk_hash = wallet_session.add_user(info.private_key, info.fingerprint).await?;
    let user_id = provider
        .get_user_ids_for_public_key(info.public_key_hash)
        .await?
        .first()
        .copied()
        .ok_or_else(|| anyhow::anyhow!("No user id found for sender public key"))?;
    let checkpoint_before = provider.get_coordinator_latest_block_state().await?.checkpoint_id;
    let tx_hash = wallet_session.exec_contract_call(user_pk_hash, contract_call_data).await?;

    tracing::info!(
        destination_chain_id = args.destination_chain_id,
        amount = args.amount,
        nonce = args.nonce,
        "withdraw tx submitted! hash: {}",
        tx_hash.to_string()
    );
    let confirmed_checkpoint = provider
        .wait_for_endcap_inclusion(user_id, tx_hash, checkpoint_before, Some(180), 1)
        .await?;
    tracing::info!(
        checkpoint_id = confirmed_checkpoint,
        user_id,
        end_user_leaf_hash = %tx_hash,
        "withdraw tx included"
    );

    Ok(())
}
