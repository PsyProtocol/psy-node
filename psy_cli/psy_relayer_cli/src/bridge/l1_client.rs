use std::{path::Path, str::FromStr, time::Duration};

use alloy_consensus::{BlockHeader, Transaction};
use alloy_eips::eip2718::Encodable2718;
use alloy_network::{EthereumWallet, NetworkWallet, TransactionBuilder};
use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types_eth::{BlockNumberOrTag, TransactionReceipt, TransactionRequest};
use alloy_sol_types::SolCall;
use anyhow::{Context, ensure};
use psy_client_data::bridge_aggregate::NetworkConfig;
use url::Url;

use crate::bridge::{
    claim_withdrawals,
    constants::{DEFAULT_L1_RPC_URL, L1_TX_SEND_TIMEOUT_SECS},
    daemon::{
        fetch_l1_last_finalized_checkpoint, resolve_bridge_address, AggregateLimits,
        BridgeProposeDaemonConfig, DaemonFinalizeConfig,
    },
    finalize_bridge,
    l1_provider::connect_l1_readonly,
    l1_signer::load_l1_wallet,
};

const L1_RETRY_MAX_ATTEMPTS: usize = 10;
const L1_RETRY_BASE_DELAY_SECS: u64 = 1;
const L1_RETRY_MAX_DELAY_SECS: u64 = 60;

#[derive(Clone, Debug)]
pub struct L1Client {
    rpc_urls: Vec<String>,
    wallet: Option<EthereumWallet>,
}

impl L1Client {
    pub fn from_finalize_config(finalize: &DaemonFinalizeConfig) -> Self {
        let primary = finalize
            .l1_rpc_url
            .clone()
            .unwrap_or_else(|| DEFAULT_L1_RPC_URL.to_string());
        let mut rpc_urls = vec![primary];
        if let Some(fallback) = finalize.l1_rpc_fallback_url.as_deref() {
            let fallback = fallback.trim();
            if !fallback.is_empty() && !rpc_urls.iter().any(|url| url == fallback) {
                rpc_urls.push(fallback.to_string());
            }
        }
        Self { rpc_urls, wallet: None }
    }

    pub(crate) fn bind(config: &BridgeProposeDaemonConfig) -> anyhow::Result<Self> {
        let endpoint = config
            .finalize
            .l1_rpc_url
            .as_deref()
            .context("aggregate sender requires one configured L1 RPC URL")?;
        let wallet = load_l1_wallet(
            config.finalize.private_key.as_deref(),
            config.finalize.keystore_path.as_deref().map(Path::new),
            config.finalize.password_env.as_deref(),
            None,
            "aggregate L1 signer",
        )?;
        Self::bind_endpoint(endpoint, wallet)
    }

    pub(crate) fn bind_endpoint(endpoint: &str, wallet: EthereumWallet) -> anyhow::Result<Self> {
        endpoint
            .parse::<Url>()
            .with_context(|| format!("invalid L1 rpc url: {endpoint}"))?;
        Ok(Self { rpc_urls: vec![endpoint.to_string()], wallet: Some(wallet) })
    }

    /// Retry an L1 operation across all configured RPC URLs.
    /// `f` is called once per URL; the first success is returned.
    pub async fn with_retry<T, F, Fut>(
        &self,
        label: &str,
        max_attempts: usize,
        f: F,
    ) -> anyhow::Result<T>
    where
        F: Fn(&str) -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<T>>,
    {
        if self.rpc_urls.is_empty() {
            anyhow::bail!("no L1 RPC URLs configured for {label}");
        }

        let mut last_err = None;
        for attempt in 1..=max_attempts.max(1) {
            for (index, l1_rpc_url) in self.rpc_urls.iter().enumerate() {
                match f(l1_rpc_url).await {
                    Ok(value) => {
                        if attempt > 1 || index > 0 {
                            tracing::warn!(
                                l1_rpc_url = %l1_rpc_url,
                                label = %label,
                                attempt,
                                "L1 RPC retry/fallback succeeded"
                            );
                        }
                        return Ok(value);
                    }
                    Err(err) => {
                        tracing::warn!(
                            l1_rpc_url = %l1_rpc_url,
                            label = %label,
                            attempt,
                            error = %err,
                            error_debug = ?err,
                            "L1 RPC failed"
                        );
                        last_err = Some(err);
                    }
                }
            }

            if attempt < max_attempts {
                let delay_secs = (L1_RETRY_BASE_DELAY_SECS << (attempt.saturating_sub(1).min(5)))
                    .min(L1_RETRY_MAX_DELAY_SECS);
                tracing::warn!(
                    label = %label,
                    attempt,
                    next_attempt = attempt + 1,
                    delay_secs,
                    "all L1 RPC attempts failed; backing off before retry"
                );
                tokio::time::sleep(Duration::from_secs(delay_secs)).await;
            }
        }

        match last_err {
            Some(err) => anyhow::bail!(
                "L1 operation '{}' failed after {} attempts: {}",
                label,
                max_attempts,
                err
            ),
            None => anyhow::bail!("L1 operation '{}' failed after {} attempts", label, max_attempts),
        }
    }

    pub async fn last_finalized_checkpoint(&self, state_manager: Address) -> anyhow::Result<u64> {
        self.with_retry("last_finalized_checkpoint", L1_RETRY_MAX_ATTEMPTS, |url| {
            let owned = url.to_string();
            async move {
                let l1_provider = connect_l1_readonly(
                    owned.parse()
                        .with_context(|| format!("invalid L1 rpc url: {owned}"))?,
                )?;
                fetch_l1_last_finalized_checkpoint(&l1_provider, state_manager).await
            }
        })
        .await
    }

    pub async fn claim_withdrawals(
        &self,
        withdrawals: &[propose_withdrawals::PendingWithdrawal],
        config: &BridgeProposeDaemonConfig,
        to_checkpoint: u64,
    ) -> anyhow::Result<claim_withdrawals::BatchWithdrawalsReport> {
        let bridge = Address::from_str(&resolve_bridge_address(config)?)?;
        let approved = super::regen_groth16_keystore::load_aggregate_setup_config(&config.aggregate_setup_config)?;
        let network = psy_client_data::bridge_aggregate::NetworkConfig::decode(&hex::decode(approved.network_config)?)?;
        let url = self.rpc_urls.first().context("no L1 RPC URL configured for pending withdrawals")?;
        let report = claim_withdrawals::claim_pending_withdrawals(
            withdrawals, url, bridge, &network,
            config.finalize.private_key.as_deref(),
            config.finalize.keystore_path.as_deref().map(Path::new),
            config.finalize.password_env.as_deref().unwrap_or("WALLET_PASSWORD"),
        ).await?;
        tracing::info!(to_checkpoint, requested = report.requested,
            submitted_count = report.submitted_count, already_claimed_count = report.already_claimed_count,
            resolved = report.resolved_leaf_hashes.len(), "pending withdrawal settlement finished");
        Ok(report)
    }

    pub(crate) async fn preflight_aggregate(
        &self,
        network: &NetworkConfig,
        chain_index: u8,
        destination: Address,
        calldata: Bytes,
        limits: &AggregateLimits,
    ) -> anyhow::Result<TransactionRequest> {
        let chain = network
            .chains
            .iter()
            .find(|chain| chain.chain_index == chain_index)
            .context("configured chain index not found")?;
        let chain_limits = limits.chain(chain_index)?;
        let (budget, expected) = aggregate_destination(&calldata, chain, limits)?;
        ensure!(destination == expected, "aggregate destination does not match configured chain");
        ensure!(
            calldata.len() as u64 <= budget,
            "aggregate calldata exceeds saved byte budget"
        );
        let wallet = self.wallet.as_ref().context("aggregate sender is not bound")?;
        let provider = self.bound_provider()?;
        let chain_id = provider.get_chain_id().await.context("read L1 chain id failed")?;
        ensure!(
            U256::from(chain_id) == U256::from_be_slice(&chain.chain_id),
            "L1 chain id does not match configured destination"
        );
        let block = provider
            .get_block_by_number(BlockNumberOrTag::Latest)
            .await
            .context("read current block failed")?
            .context("current block unavailable")?;
        let block_gas = block.header.gas_limit();
        let room = block_gas
            .checked_sub(chain_limits.block_gas_reserve)
            .context("current block gas does not exceed saved reserve")?;
        let gas = chain_limits.tx_gas_limit.min(room);
        ensure!(gas > 0, "aggregate gas ceiling is zero");
        let from = wallet.default_signer_address();
        let estimated = TransactionRequest::default()
            .from(from)
            .to(destination)
            .value(U256::ZERO)
            .input(calldata.clone().into())
            .gas_limit(gas);
        let estimate = provider
            .estimate_gas(estimated)
            .await
            .context("aggregate gas estimate failed")?;
        ensure!(estimate <= gas, "aggregate gas estimate exceeds saved ceiling");
        let nonce = provider
            .get_transaction_count(from)
            .await
            .context("read sender nonce failed")?;
        let fees = provider
            .estimate_eip1559_fees()
            .await
            .context("read transaction fees failed")?;
        let tx = TransactionRequest::default()
            .from(from)
            .to(destination)
            .value(U256::ZERO)
            .input(calldata.clone().into())
            .gas_limit(gas)
            .nonce(nonce)
            .with_chain_id(chain_id)
            .max_fee_per_gas(fees.max_fee_per_gas)
            .max_priority_fee_per_gas(fees.max_priority_fee_per_gas);
        let unsigned = tx.clone().build_unsigned().context("prepared aggregate transaction is incomplete")?;
        ensure!(
            prepared_fields(&tx, from, destination, &calldata, gas)
                && tx.nonce == Some(nonce)
                && tx.chain_id == Some(chain_id)
                && tx.max_fee_per_gas == Some(fees.max_fee_per_gas)
                && tx.max_priority_fee_per_gas == Some(fees.max_priority_fee_per_gas)
                && unsigned.kind() == alloy_primitives::TxKind::Call(destination)
                && unsigned.value() == U256::ZERO
                && unsigned.input() == calldata.as_ref()
                && unsigned.gas_limit() == gas
                && unsigned.nonce() == nonce
                && unsigned.chain_id() == Some(chain_id),
            "prepared aggregate transaction fields changed"
        );
        Ok(tx)
    }

    pub(crate) async fn broadcast_prepared(
        &self,
        tx: TransactionRequest,
    ) -> anyhow::Result<B256> {
        let from = tx.from.context("prepared aggregate transaction has no sender")?;
        let to = tx.to.and_then(|kind| kind.into_to()).context("prepared aggregate transaction has no destination")?;
        let value = tx.value.context("prepared aggregate transaction has no value")?;
        let input = tx.input.input().context("prepared aggregate transaction has no calldata")?.clone();
        let gas = tx.gas.context("prepared aggregate transaction has no gas")?;
        let nonce = tx.nonce.context("prepared aggregate transaction has no nonce")?;
        let chain_id = tx.chain_id.context("prepared aggregate transaction has no chain id")?;
        let max_fee = tx.max_fee_per_gas.context("prepared aggregate transaction has no max fee")?;
        let priority = tx.max_priority_fee_per_gas.context("prepared aggregate transaction has no priority fee")?;
        ensure!(value == U256::ZERO && gas > 0, "prepared aggregate transaction is not executable");
        let wallet = self.wallet.as_ref().context("aggregate sender is not bound")?;
        ensure!(wallet.default_signer_address() == from, "broadcast signer does not match prepared sender");
        let unsigned = tx.build_unsigned().context("prepared aggregate transaction is incomplete")?;
        ensure!(
            unsigned.kind() == alloy_primitives::TxKind::Call(to)
                && unsigned.value() == value
                && unsigned.input() == input.as_ref()
                && unsigned.gas_limit() == gas
                && unsigned.nonce() == nonce
                && unsigned.chain_id() == Some(chain_id)
                && unsigned.max_fee_per_gas() == max_fee
                && unsigned.max_priority_fee_per_gas() == Some(priority),
            "unsigned aggregate transaction differs from prepared transaction"
        );
        let envelope = wallet.sign_transaction_from(from, unsigned).await.context("sign prepared aggregate transaction failed")?;
        ensure!(
            envelope.kind() == alloy_primitives::TxKind::Call(to)
                && envelope.value() == value
                && envelope.input() == input.as_ref()
                && envelope.gas_limit() == gas
                && envelope.nonce() == nonce
                && envelope.chain_id() == Some(chain_id)
                && envelope.max_fee_per_gas() == max_fee
                && envelope.max_priority_fee_per_gas() == Some(priority),
            "signed aggregate transaction differs from prepared transaction"
        );
        let provider = self.bound_provider()?;
        let pending = tokio::time::timeout(
            Duration::from_secs(L1_TX_SEND_TIMEOUT_SECS),
            provider.send_raw_transaction(&envelope.encoded_2718()),
        )
        .await
        .context("aggregate send timed out")?
        .context("aggregate send failed")?;
        Ok(*pending.tx_hash())
    }

    fn bound_provider(&self) -> anyhow::Result<impl Provider> {
        let url = self.rpc_urls.first().context("aggregate sender has no endpoint")?;
        Ok(ProviderBuilder::new().connect_http(
            url.parse().with_context(|| format!("invalid L1 rpc url: {url}"))?,
        ))
    }
}

fn aggregate_destination(
    calldata: &Bytes,
    chain: &psy_client_data::bridge_aggregate::ChainConfig,
    limits: &AggregateLimits,
) -> anyhow::Result<(u64, Address)> {
    let selector = calldata.get(..4).context("aggregate calldata has no selector")?;
    if selector == finalize_bridge::applyDepositAggregateCall::SELECTOR.as_slice() {
        Ok((limits.max_a_calldata_bytes, Address::from(chain.bridge)))
    } else if selector == finalize_bridge::finalizeCheckpointAggregateCall::SELECTOR.as_slice() {
        Ok((limits.max_b_calldata_bytes, Address::from(chain.state_manager)))
    } else {
        anyhow::bail!("unknown aggregate calldata selector")
    }
}

fn prepared_fields(
    tx: &TransactionRequest,
    from: Address,
    destination: Address,
    calldata: &Bytes,
    gas: u64,
) -> bool {
    tx.from == Some(from)
        && tx.to == Some(alloy_primitives::TxKind::Call(destination))
        && tx.value == Some(U256::ZERO)
        && tx.input.input() == Some(calldata)
        && tx.gas == Some(gas)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{transaction::SignerRecoverable, TxEnvelope};
    use alloy_eips::eip2718::Decodable2718;
    use alloy_primitives::TxKind;
    use alloy_rpc_types_eth::{Block, BlockTransactions, Header};
    use alloy_signer_local::PrivateKeySigner;
    use psy_client_data::bridge_aggregate::ChainConfig;
    use serde_json::{json, Value};
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    const KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const CHAIN: u8 = 0;

    fn chain() -> ChainConfig {
        ChainConfig {
            chain_index: CHAIN,
            chain_id: U256::from(1u64).to_be_bytes(),
            bridge: [0x11; 20],
            state_manager: [0x22; 20],
            bootstrap_id: 0,
            bootstrap_root: [1, 2, 3, 4],
        }
    }

    fn network() -> NetworkConfig {
        NetworkConfig {
            version: 1,
            network_magic: 0,
            bridge_user_id: psy_client_data::bridge_aggregate::BRIDGE_USER_ID,
            circuit_set_hash: [7; 32],
            chains: vec![chain()],
            ethereum_index: CHAIN,
            reward_payer: [3; 20],
            reward_token: [4; 20],
            reward_per_claim: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            reward_token_decimals: 18,
            reward_cutover: 0,
            reward_end_exclusive: 100,
            max_deposits: 1024,
            max_withdrawals: 1024,
            max_rewards: 1024,
        }
    }

    fn limits(tx_gas_limit: u64, block_gas_reserve: u64) -> AggregateLimits {
        AggregateLimits {
            max_deposits: 1,
            reserved_withdrawals: 0,
            reserved_rewards: 0,
            max_a_calldata_bytes: 10_000,
            max_b_calldata_bytes: 10_000,
            chains: vec![crate::bridge::daemon::ChainLimits {
                chain_index: CHAIN,
                max_deposits: 1,
                reserved_withdrawals: 0,
                tx_gas_limit,
                block_gas_reserve,
            }],
        }
    }

    fn calldata() -> Bytes {
        finalize_bridge::apply_deposit_aggregate_call([U256::from(1u8); 8], Bytes::from_static(&[9, 8, 7]))
    }

    fn block(gas_limit: u64) -> Block {
        Block {
            header: Header {
                hash: B256::repeat_byte(1),
                inner: alloy_consensus::Header {
                    gas_limit,
                    gas_used: 1,
                    number: 7,
                    timestamp: 8,
                    base_fee_per_gas: Some(1),
                    ..Default::default()
                },
                total_difficulty: None,
                size: None,
            },
            transactions: BlockTransactions::Hashes(Vec::new()),
            uncles: Vec::new(),
            withdrawals: None,
        }
    }

    fn sender() -> (L1Client, Address) {
        let signer = PrivateKeySigner::from_str(KEY).unwrap();
        let address = signer.address();
        let client = L1Client::bind_endpoint("http://127.0.0.1:1", EthereumWallet::from(signer)).unwrap();
        (client, address)
    }

    async fn serve(mut requests: Vec<Value>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            for expected in requests.drain(..) {
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = BufReader::new(socket);
                let mut line = String::new();
                let mut length = 0usize;
                loop {
                    line.clear();
                    assert!(socket.read_line(&mut line).await.unwrap() > 0);
                    if line == "\r\n" { break; }
                    if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("content-length") {
                            length = value.trim().parse().unwrap();
                        }
                    }
                }
                let mut body = vec![0; length];
                socket.read_exact(&mut body).await.unwrap();
                let actual: Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(actual["method"], expected["method"], "{}", actual);
                assert_eq!(actual["params"], expected["params"], "{}", actual);
                let mut response = json!({"jsonrpc":"2.0","id":actual["id"]});
                response["result"] = expected["result"].clone();
                let encoded = response.to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    encoded.len(), encoded
                );
                socket.get_mut().write_all(response.as_bytes()).await.unwrap();
            }
        });
        url
    }

    fn estimate_params(from: Address, to: Address, input: &Bytes, gas: u64) -> Value {
        json!([TransactionRequest::default().from(from).to(to).value(U256::ZERO).input(input.clone().into()).gas_limit(gas), "pending"])
    }

    fn fee_history() -> Value {
        json!({"method":"eth_feeHistory","params":["0xa","latest",[20.0]],"result":json!({
            "baseFeePerGas":["0x1","0x1"],"gasUsedRatio":[0.5],"oldestBlock":"0x1","reward":[["0x2"]]
        })})
    }

    #[tokio::test]
    async fn preflight_sets_exact_fields_and_operator_ceiling() {
        let (mut client, from) = sender();
        let input = calldata();
        let to = Address::from(chain().bridge);
        client.rpc_urls = vec![serve(vec![
            json!({"method":"eth_chainId","params":[],"result":"0x1"}),
            json!({"method":"eth_getBlockByNumber","params":["latest", false],"result":block(1_000)}),
            json!({"method":"eth_estimateGas","params":estimate_params(from, to, &input, 300),"result":"0x64"}),
            json!({"method":"eth_getTransactionCount","params":[from, "latest"],"result":"0x4"}),
            fee_history(),
        ]).await];
        let tx = tokio::time::timeout(Duration::from_secs(5), client.preflight_aggregate(
            &network(), CHAIN, to, input.clone(), &limits(300, 100),
        )).await.unwrap().unwrap();
        assert!(prepared_fields(&tx, from, to, &input, 300));
        assert_eq!(tx.nonce, Some(4));
        assert_eq!(tx.chain_id, Some(1));
        assert_eq!(tx.max_fee_per_gas, Some(4));
        assert_eq!(tx.max_priority_fee_per_gas, Some(2));
    }

    #[tokio::test]
    async fn preflight_rejects_estimate_above_block_room_before_broadcast() {
        let (mut client, from) = sender();
        let input = calldata();
        let to = Address::from(chain().bridge);
        client.rpc_urls = vec![serve(vec![
            json!({"method":"eth_chainId","params":[],"result":"0x1"}),
            json!({"method":"eth_getBlockByNumber","params":["latest", false],"result":block(150)}),
            json!({"method":"eth_estimateGas","params":estimate_params(from, to, &input, 50),"result":"0x33"}),
        ]).await];
        let error = client.preflight_aggregate(&network(), CHAIN, to, input, &limits(1_000, 100)).await.unwrap_err();
        assert!(error.to_string().contains("exceeds saved ceiling"), "{error}");
    }

    #[tokio::test]
    async fn preflight_rejects_unknown_selector_without_rpc() {
        let (client, _) = sender();
        let error = client.preflight_aggregate(
            &network(), CHAIN, Address::from(chain().bridge), Bytes::from_static(&[1, 2, 3, 4]), &limits(300, 100),
        ).await.unwrap_err();
        assert!(error.to_string().contains("unknown aggregate calldata selector"), "{error}");
    }

    #[tokio::test]
    async fn broadcast_sends_the_signed_prepared_transaction_once() {
        let (mut client, from) = sender();
        let input = calldata();
        let to = Address::from(chain().bridge);
        let tx = TransactionRequest::default()
            .from(from)
            .to(to)
            .value(U256::ZERO)
            .input(input.clone().into())
            .gas_limit(300)
            .nonce(4)
            .with_chain_id(1)
            .max_fee_per_gas(4)
            .max_priority_fee_per_gas(2);
        let (raw_tx, raw_rx) = tokio::sync::oneshot::channel();
        let mut raw_tx = Some(raw_tx);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        client.rpc_urls = vec![format!("http://{}", listener.local_addr().unwrap())];
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = BufReader::new(socket);
            let mut line = String::new();
            let mut length = 0usize;
            loop {
                line.clear();
                assert!(socket.read_line(&mut line).await.unwrap() > 0);
                if line == "\r\n" { break; }
                if let Some((name, value)) = line.split_once(':') {
                    if name.eq_ignore_ascii_case("content-length") { length = value.trim().parse().unwrap(); }
                }
            }
            let mut body = vec![0; length];
            socket.read_exact(&mut body).await.unwrap();
            let actual: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(actual["method"], "eth_sendRawTransaction");
            raw_tx.take().unwrap().send(actual["params"][0].as_str().unwrap().to_string()).unwrap();
            let encoded = json!({"jsonrpc":"2.0","id":actual["id"],"result":format!("{:#x}", B256::repeat_byte(9))}).to_string();
            let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", encoded.len(), encoded);
            socket.get_mut().write_all(response.as_bytes()).await.unwrap();
        });
        let hash = tokio::time::timeout(Duration::from_secs(5), client.broadcast_prepared(tx)).await.unwrap().unwrap();
        assert_eq!(hash, B256::repeat_byte(9));
        let raw = raw_rx.await.unwrap();
        let envelope = TxEnvelope::decode_2718(&mut hex::decode(raw.trim_start_matches("0x")).unwrap().as_slice()).unwrap();
        assert_eq!(envelope.kind(), TxKind::Call(to));
        assert_eq!(envelope.value(), U256::ZERO);
        assert_eq!(envelope.input(), input.as_ref());
        assert_eq!(envelope.gas_limit(), 300);
        assert_eq!(envelope.nonce(), 4);
        assert_eq!(envelope.chain_id(), Some(1));
        assert_eq!(envelope.max_fee_per_gas(), 4);
        assert_eq!(envelope.max_priority_fee_per_gas(), Some(2));
    }

    #[test]
    fn selector_budget_uses_the_matching_destination() {
        let chain = chain();
        let limits = limits(1, 1);
        let deposit = calldata();
        let checkpoint = finalize_bridge::finalize_checkpoint_aggregate_call([U256::from(2u8); 8], Bytes::new());
        assert_eq!(aggregate_destination(&deposit, &chain, &limits).unwrap(), (10_000, Address::from(chain.bridge)));
        assert_eq!(aggregate_destination(&checkpoint, &chain, &limits).unwrap(), (10_000, Address::from(chain.state_manager)));
    }
}


