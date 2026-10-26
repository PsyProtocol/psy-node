//! Shared deposit-log fetching utilities for the bridge daemon and prover.
//!
//! Provides a 2-step bulk-fetch strategy without one RPC call per deposit:
//!
//! 1. A topic-filtered `get_logs` for `from_index` — resolves the exact L1 block
//!    where the first relevant deposit exists (minimal data transfer).
//! 2. An unfiltered `get_logs` from that block onward bulk-fetches deposits,
//!    then filters by index range in memory.
//!
//! Both steps use bounded block ranges so an aging deployment does not send
//! arbitrarily large `eth_getLogs` requests. One head snapshot bounds the scan.

use std::collections::HashMap;

use alloy_primitives::{Address, B256};
use alloy_provider::Provider;
use alloy_rpc_types_eth::{BlockNumberOrTag, Filter};
use alloy_sol_types::{sol, SolEvent};
use anyhow::Context;

const MAX_LOG_BLOCKS_PER_QUERY: u64 = 50_000;

sol! {
    /// Emitted by the bridge contract when a deposit is recorded.
    event DepositRecorded(
        uint32 indexed index,
        bytes32 shieldAddress,
        address indexed token,
        bytes32 l2TokenContractId,
        uint256 amount,
        uint8 chainIndex,
        bytes32 noteCommitment,
        bytes32 leafHash
    );
}

/// Encodes a `u32` as an indexed event topic by placing the value in the last 4 bytes
/// of a 32-byte `B256` (ABI-encoded uint256 layout for indexed arguments).
pub fn indexed_u32_topic(value: u32) -> B256 {
    let mut bytes = [0u8; 32];
    bytes[28..32].copy_from_slice(&value.to_be_bytes());
    B256::from(bytes)
}

/// Bulk-fetches `DepositRecorded` logs in the index range `[from_index, to_index_exclusive)`.
///
/// Returns a `HashMap` keyed by deposit index, guaranteed to contain every index in the
/// range. Returns an error if any index is missing (out-of-sync L1 state).
///
/// # Performance
///
/// Recent deposits normally need two log requests. Long histories are split into
/// requests spanning at most 50,000 blocks; collection stops when all requested
/// indices have been found. Providers with stricter limits may still reject a request.
pub async fn bulk_fetch_deposit_records(
    provider: &impl Provider,
    bridge: Address,
    from_block: BlockNumberOrTag,
    from_index: u32,
    to_index_exclusive: u32,
) -> anyhow::Result<HashMap<u32, DepositRecorded>> {
    if from_index >= to_index_exclusive {
        return Ok(HashMap::new());
    }

    let latest_block = provider
        .get_block_number()
        .await
        .context("failed to fetch latest L1 block before reading deposits")?;
    let search_start = match from_block {
        BlockNumberOrTag::Number(block) => block,
        BlockNumberOrTag::Earliest => 0,
        BlockNumberOrTag::Latest => latest_block,
        tag => provider
            .get_block_by_number(tag)
            .await
            .with_context(|| format!("failed to resolve deposit log start block {tag}"))?
            .with_context(|| format!("deposit log start block {tag} not found"))?
            .header
            .number,
    };

    // Locate the first requested index without scanning an unbounded block range.
    let mut first_block = None;
    for (start, end) in bounded_block_ranges(search_start, latest_block) {
        let logs = provider
            .get_logs(
                &Filter::new()
                    .address(bridge)
                    .event_signature(DepositRecorded::SIGNATURE_HASH)
                    .topic1(indexed_u32_topic(from_index))
                    .from_block(start)
                    .to_block(end),
            )
            .await
            .with_context(|| {
                format!("failed to fetch DepositRecorded(from_index={from_index}) in blocks {start}..={end}")
            })?;
        if let Some(block) = logs.iter().filter_map(|log| log.block_number).min() {
            first_block = Some(block);
            break;
        }
    }
    let first_block = first_block.with_context(|| {
        format!("DepositRecorded(from_index={from_index}) not found on L1 - index out of sync")
    })?;

    let mut result = HashMap::new();
    for (start, end) in bounded_block_ranges(first_block, latest_block) {
        let logs = provider
            .get_logs(
                &Filter::new()
                    .address(bridge)
                    .event_signature(DepositRecorded::SIGNATURE_HASH)
                    .from_block(start)
                    .to_block(end),
            )
            .await
            .with_context(|| {
                format!("failed to fetch DepositRecorded logs in blocks {start}..={end}")
            })?;
        for log in &logs {
            let decoded = log
                .log_decode::<DepositRecorded>()
                .context("failed to decode DepositRecorded log")?;
            let event = decoded.data();
            let idx = event.index;
            if idx < from_index || idx >= to_index_exclusive {
                continue;
            }
            anyhow::ensure!(
                !result.contains_key(&idx),
                "duplicate DepositRecorded log for index {}",
                idx
            );
            result.insert(idx, DepositRecorded {
                index: event.index,
                shieldAddress: event.shieldAddress,
                token: event.token,
                l2TokenContractId: event.l2TokenContractId,
                amount: event.amount,
                chainIndex: event.chainIndex,
                noteCommitment: event.noteCommitment,
                leafHash: event.leafHash,
            });
        }
        if result.len() == (to_index_exclusive - from_index) as usize {
            break;
        }
    }

    // Ensure every index in the range was found (contiguous deposits).
    for idx in from_index..to_index_exclusive {
        anyhow::ensure!(
            result.contains_key(&idx),
            "missing DepositRecorded log for index {}",
            idx
        );
    }

    Ok(result)
}

fn bounded_block_ranges(start: u64, end: u64) -> impl Iterator<Item = (u64, u64)> {
    let mut next = (start <= end).then_some(start);
    std::iter::from_fn(move || {
        let start = next?;
        let range_end = start.saturating_add(MAX_LOG_BLOCKS_PER_QUERY - 1).min(end);
        next = range_end.checked_add(1).filter(|&n| n <= end);
        Some((start, range_end))
    })
}

#[cfg(test)]
#[path = "deposit_logs_tests.rs"]
mod tests;
