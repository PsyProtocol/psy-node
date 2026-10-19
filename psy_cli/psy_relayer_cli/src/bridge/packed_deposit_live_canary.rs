//! Explicitly invoked deployment canary. It consumes only deposits already in
//! the daemon's persisted range and never changes daemon/L2 state or setup.
use super::*;

fn bounded_end(chain: u8, before: u32, durable_target: u32) -> anyhow::Result<u32> {
    ensure!(matches!(chain, 1 | 2), "canary is limited to BSC/Base");
    ensure!(before < durable_target, "no canary work in the durable range");
    Ok(before.saturating_add(32).min(durable_target))
}

#[test]
fn canary_cannot_exceed_one_call_or_the_existing_range() {
    assert_eq!(bounded_end(1, 675, 745).unwrap(), 707);
    assert_eq!(bounded_end(2, 100, 110).unwrap(), 110);
    assert_eq!(bounded_end(2, u32::MAX - 2, u32::MAX).unwrap(), u32::MAX);
    assert!(bounded_end(0, 0, 32).is_err());
    assert!(bounded_end(1, 745, 745).is_err());
    assert!(bounded_end(2, 111, 110).is_err());
}

#[tokio::test]
#[ignore = "MANUAL LIVE TRANSACTION: requires stopped daemon, explicit confirmation and existing durable work"]
async fn submit_one_existing_range_call() -> anyhow::Result<()> {
    ensure!(env::var("PSY_PACKED_CANARY_CONFIRM").as_deref() == Ok("existing-durable-range-only"),
        "manual canary authorization missing");
    let chain_index: u8 = env::var("PSY_PACKED_CANARY_CHAIN")?.parse()?;
    ensure!(matches!(chain_index, 1 | 2), "canary is limited to BSC/Base");
    let stopped = std::process::Command::new("systemctl")
        .args(["show", "parth-relayer.service", "-p", "MainPID", "--value"]).output()?;
    ensure!(stopped.status.success() && std::str::from_utf8(&stopped.stdout)?.trim() == "0",
        "main relayer must be stopped for the canary");
    ensure!(env::var("PSY_SYSTEM_PROXY_CONCURRENCY").as_deref() == Ok("3"), "proof pool configuration drift");
    let config_path = Path::new("/etc/parth/bridge-relayer.toml");
    let config_bytes = fs::read(config_path)?;
    let config = load_config(config_path)?;
    let state_path = config.proof_dir.as_ref().context("missing proof directory")?
        .join("daemon_state_multichain.toml");
    let state_bytes = fs::read(&state_path)?;
    let state: MultichainDaemonState = toml::from_str(std::str::from_utf8(&state_bytes)?)?;
    let range = state.pending_finalization_range.context("no persisted pending range")?;
    let chains = configured_chains(&config)?;
    let chain = chains.iter().find(|chain| chain.chain_index == chain_index).context("chain not configured")?;
    let effective = chain.effective_config(&config)?;
    let packed = effective.finalize.packed_deposit.as_ref().context("packed canary is not configured")?;
    ensure!(packed.max_calls_per_tx == 1 && packed.max_gas_per_tx == 15_000_000,
        "canary requires single-call/15M configuration");
    let rpc = effective.finalize.l1_rpc_url.as_ref().context("missing chain RPC")?;
    let l1 = crate::bridge::l1_provider::connect_l1_readonly(rpc.parse()?)?;
    ensure!(l1.get_chain_id().await? == if chain_index == 1 {97} else {84532}, "wrong canary chain ID");
    let bridge: Address = resolve_bridge_address(&effective)?.parse()?;
    packed.validate_bridge(&l1, bridge).await?;
    let before = fetch_proved_deposit_count(&l1, bridge).await?;
    let l2 = RpcProvider::new_with_config_path(&config.rpc_config)?;
    let durable_target = u32::try_from(fetch_deposit_tree_next_index(&l2, range.to_checkpoint, u64::from(chain_index)).await?)?;
    let end = bounded_end(chain_index, before, durable_target)?;
    let proxy = resolve_system_prove_proxy_url(&effective)?;
    verify_system_prove_proxy(&proxy).await?;
    ensure!(fs::read(config_path)? == config_bytes && fs::read(&state_path)? == state_bytes,
        "configuration or durable range changed before canary");
    submit_deposit_batch_appends_with_l1_rpc(&effective, rpc, end, Some(&proxy)).await?;
    let after = fetch_proved_deposit_count(&l1, bridge).await?;
    ensure!(after == end, "canary cursor mismatch");
    ensure!(fs::read(config_path)? == config_bytes && fs::read(&state_path)? == state_bytes,
        "canary must preserve configuration and durable state");
    println!("PACKED_CANARY_RESULT {}", serde_json::json!({"chain_index":chain_index,
        "proved_before":before,"proved_after":after,"durable_target":durable_target,
        "checkpoint":range.to_checkpoint,"deposits":after-before,"passed":true}));
    Ok(())
}
