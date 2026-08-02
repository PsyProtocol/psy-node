//! Shared deposit-log fetching utilities for the bridge daemon and prover.
//!
//! Provides an optimized 2-step bulk-fetch strategy that reduces L1 RPC calls
//! from O(N) (one `eth_getLogs` per deposit index) to O(1) — two calls total:
//!
//! 1. A topic-filtered `get_logs` for `from_index` — resolves the exact L1 block
//!    where the first relevant deposit exists (minimal data transfer).
//! 2. An unfiltered `get_logs` from that block onward — bulk-fetches all deposit
//!    events in one call, then filters by index range in memory.

use std::collections::HashMap;

use alloy_primitives::{Address, B256};
use alloy_provider::Provider;
use alloy_rpc_types_eth::{BlockNumberOrTag, Filter};
use alloy_sol_types::{sol, SolEvent};
use anyhow::Context;

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
/// Exactly **2** `eth_getLogs` calls regardless of the range size, instead of N individual
/// calls. The first call is lightweight (topic-filtered, returns at most 1 log). The second
/// call fetches all records from the resolved block to `latest`.
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

    // --- Step 1: find the block containing from_index ---
    let first_logs = provider
        .get_logs(
            &Filter::new()
                .address(bridge)
                .event_signature(DepositRecorded::SIGNATURE_HASH)
                .topic1(indexed_u32_topic(from_index))
                .from_block(from_block)
                .to_block(BlockNumberOrTag::Latest),
        )
        .await
        .with_context(|| {
            format!(
                "failed to fetch DepositRecorded(from_index={}) from block {:?}",
                from_index, from_block
            )
        })?;
    let first_block = first_logs
        .iter()
        .filter_map(|l| l.block_number)
        .min()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "DepositRecorded(from_index={}) not found on L1 — index out of sync",
                from_index
            )
        })?;

    // --- Step 2: bulk-fetch all logs from first_block onward ---
    let logs = provider
        .get_logs(
            &Filter::new()
                .address(bridge)
                .event_signature(DepositRecorded::SIGNATURE_HASH)
                .from_block(BlockNumberOrTag::Number(first_block))
                .to_block(BlockNumberOrTag::Latest),
        )
        .await
        .with_context(|| {
            format!(
                "failed to fetch DepositRecorded logs from block {}",
                first_block
            )
        })?;

    // --- Step 3: decode & filter by index range ---
    let mut result = HashMap::new();
    for log in &logs {
        let decoded = log
            .log_decode::<DepositRecorded>()
            .with_context(|| "failed to decode DepositRecorded log")?;
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
