//! Opt-in BSC Testnet fees. No node-specific URL detection or implicit legacy fallback.
use std::{fmt, str::FromStr, time::Duration};

use alloy_provider::Provider;
use alloy_rpc_types_eth::{BlockNumberOrTag, TransactionRequest};
use anyhow::{ensure, Context, Result};
use serde::Deserialize;

// The live RPC pool allows 15s per attempt and 30s per logical request. Let
// its failover finish; the old candidate's 4s cutoff cancelled it too early.
const FEE_RPC_TIMEOUT: Duration = Duration::from_secs(35);
const FEE_PREPARATION_TIMEOUT: Duration = Duration::from_secs(70);

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BscFeePolicy {
    pub expected_chain_id: u64,
    pub min_priority_fee_wei: u64,
    pub max_priority_fee_wei: u64,
    pub max_fee_per_gas_wei: u64,
}

impl BscFeePolicy {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.expected_chain_id == 97, "BSC fee policy requires EVM chain ID 97");
        ensure!(self.min_priority_fee_wei > 0, "minimum priority fee must be positive");
        ensure!(self.min_priority_fee_wei <= self.max_priority_fee_wei,
            "minimum priority fee exceeds priority fee cap");
        ensure!(self.max_priority_fee_wei <= self.max_fee_per_gas_wei,
            "priority fee cap exceeds max fee cap");
        Ok(())
    }
}

impl FromStr for BscFeePolicy {
    type Err = String;
    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let policy: Self = serde_json::from_str(value).map_err(|e| e.to_string())?;
        policy.validate().map_err(|e| e.to_string())?;
        Ok(policy)
    }
}

/// Pre-broadcast refusal, distinct from a broadcast with an unknown outcome.
#[derive(Debug)]
pub struct FeePolicyError(String);

impl fmt::Display for FeePolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "L1 fee policy refused transaction: {}", self.0)
    }
}
impl std::error::Error for FeePolicyError {}

/// No transaction has been broadcast; a later round may retry preparation.
#[derive(Debug)]
pub struct FeeSourceError(pub(crate) &'static str);

impl fmt::Display for FeeSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "L1 fee source unavailable: {}", self.0)
    }
}
impl std::error::Error for FeeSourceError {}

pub fn is_fee_preparation_error(error: &anyhow::Error) -> bool {
    error.downcast_ref::<FeePolicyError>().is_some()
        || error.downcast_ref::<FeeSourceError>().is_some()
}

fn calculate_fees(
    policy: &BscFeePolicy,
    base_fee: u128,
    priority_suggestion: Option<u128>,
    rewards: &[Vec<u128>],
) -> Result<(u128, u128)> {
    policy.validate()?;
    let mut samples: Vec<u128> = rewards.iter().filter_map(|row| row.first().copied())
        .filter(|fee| *fee > 0).collect();
    samples.sort_unstable();
    let history_tip = samples.get(samples.len() / 2).copied();
    let suggested_tip = priority_suggestion.filter(|fee| *fee > 0).max(history_tip)
        .ok_or(FeeSourceError("no positive priority suggestion or history; refusing unprotected fallback"))?;
    let tip = suggested_tip.max(u128::from(policy.min_priority_fee_wei));
    ensure!(tip <= u128::from(policy.max_priority_fee_wei), "required priority fee exceeds configured cap");
    let max_fee = base_fee.checked_mul(2).and_then(|v| v.checked_add(tip))
        .context("EIP-1559 fee arithmetic overflow")?;
    ensure!(max_fee <= u128::from(policy.max_fee_per_gas_wei), "required max fee exceeds configured cap");
    Ok((tip, max_fee))
}

fn fill_or_validate(
    tx: &mut TransactionRequest,
    policy: &BscFeePolicy,
    tip: u128,
    max_fee: u128,
) -> Result<()> {
    ensure!(tx.gas_price.is_none(), "BSC guarded EIP-1559 policy does not accept legacy gasPrice");
    ensure!(tx.transaction_type.is_none() || tx.transaction_type == Some(2),
        "BSC guarded EIP-1559 policy requires transaction type 2");
    match (tx.max_priority_fee_per_gas, tx.max_fee_per_gas) {
        (None, None) => {
            tx.max_priority_fee_per_gas = Some(tip);
            tx.max_fee_per_gas = Some(max_fee);
        }
        (Some(explicit_tip), Some(explicit_max)) => {
            ensure!(explicit_tip >= tip && explicit_tip <= u128::from(policy.max_priority_fee_wei),
                "explicit priority fee is outside current policy bounds");
            // Retain the same base-fee budget when an explicit tip is higher.
            let required = (max_fee - tip).checked_add(explicit_tip).context("explicit fee overflow")?;
            ensure!(explicit_max >= required && explicit_max <= u128::from(policy.max_fee_per_gas_wei),
                "explicit max fee is outside current policy bounds");
        }
        _ => anyhow::bail!("both EIP-1559 fee fields must be supplied together"),
    }
    tx.transaction_type = Some(2);
    Ok(())
}

/// Both fees are filled before Alloy's GasFiller and WalletFiller run. A missing
/// policy is a strict no-op, including zero additional RPCs for other chains.
pub async fn prepare_l1_fees<P: Provider>(
    provider: &P,
    tx: &mut TransactionRequest,
    policy: Option<&BscFeePolicy>,
) -> Result<()> {
    let Some(policy) = policy else { return Ok(()); };
    let result = tokio::time::timeout(FEE_PREPARATION_TIMEOUT, async {
        policy.validate()?;
        // Check the provider before asking it to estimate or sign anything.
        let chain_id = tokio::time::timeout(FEE_RPC_TIMEOUT, provider.get_chain_id()).await
            .map_err(|_| FeeSourceError("eth_chainId timed out"))?
            .map_err(|_| FeeSourceError("eth_chainId failed"))?;
        ensure!(chain_id == policy.expected_chain_id, "RPC chain ID does not match BSC policy");
        ensure!(tx.chain_id.is_none() || tx.chain_id == Some(chain_id), "transaction chain ID mismatch");
        let (block, priority, history) = tokio::join!(
            tokio::time::timeout(FEE_RPC_TIMEOUT, provider.get_block_by_number(BlockNumberOrTag::Latest)),
            tokio::time::timeout(FEE_RPC_TIMEOUT, provider.get_max_priority_fee_per_gas()),
            tokio::time::timeout(FEE_RPC_TIMEOUT, provider.get_fee_history(10, BlockNumberOrTag::Latest, &[20.0])),
        );
        let base_fee = block.map_err(|_| FeeSourceError("eth_getBlockByNumber timed out"))?
            .map_err(|_| FeeSourceError("eth_getBlockByNumber failed"))?
            .and_then(|b| b.header.base_fee_per_gas)
            .ok_or(FeeSourceError("latest block has no EIP-1559 base fee"))?;
        let rewards = history.ok().and_then(|r| r.ok()).and_then(|h| h.reward).unwrap_or_default();
        let suggestion = priority.ok().and_then(|r| r.ok()).filter(|fee| *fee > 0);
        let (tip, max_fee) = calculate_fees(policy, base_fee.into(), suggestion, &rewards)?;
        fill_or_validate(tx, policy, tip, max_fee)?;
        tx.chain_id = Some(chain_id);
        tracing::info!(chain_id, policy = "bsc_guarded_eip1559", base_fee_wei = base_fee,
            priority_rpc_wei = ?suggestion, history_rows = rewards.len(),
            max_priority_fee_wei = ?tx.max_priority_fee_per_gas,
            max_fee_per_gas_wei = ?tx.max_fee_per_gas, gas_limit = ?tx.gas,
            nonce = ?tx.nonce, transaction_type = 2, "prepared L1 transaction fees");
        Ok::<_, anyhow::Error>(())
    }).await;
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) if error.downcast_ref::<FeeSourceError>().is_some() => Err(error),
        Ok(Err(error)) => Err(FeePolicyError(error.to_string()).into()),
        Err(_) => Err(FeeSourceError("fee preparation timed out after 70 seconds").into()),
    }
}

#[cfg(test)]
mod tests;
