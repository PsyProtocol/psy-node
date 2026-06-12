pub const DEFAULT_L1_RPC_URL: &str = "http://127.0.0.1:8545";
pub const DEFAULT_DEPLOYMENTS_NETWORK: &str = "localhost";
pub const BRIDGE_USER_ID_U64: u64 = 524288;
pub const BRIDGE_USER_ID_U32: u32 = 524288;

/// Target gas budget for one L1 Multicall3 aggregate3 transaction.
pub const L1_MULTICALL_GAS_BUDGET: u64 = 20_000_000;
/// Fallback per-Groth16-call gas if L1 gas estimation fails.
pub const L1_GROTH16_CALL_GAS_FALLBACK: u64 = 1_500_000;

/// Timeout (seconds) when polling for realm checkpoint advancement.
pub const REALM_CHECKPOINT_POLL_TIMEOUT_SECS: u64 = 180;
/// Polling interval (seconds) when waiting for realm checkpoint advancement.
pub const REALM_CHECKPOINT_POLL_INTERVAL_SECS: u64 = 5;
/// Timeout (seconds) for a single L1 transaction submission RPC call.
pub const L1_TX_SEND_TIMEOUT_SECS: u64 = 30;
/// Timeout (seconds) for waiting on an L1 transaction receipt.
pub const L1_TX_RECEIPT_TIMEOUT_SECS: u64 = 180;
/// Timeout (seconds) for one deposit batchAppend phase in the daemon.
pub const BRIDGE_APPEND_TIMEOUT_SECS: u64 = 300;
/// Timeout (seconds) for one bridge prove phase in the daemon.
pub const BRIDGE_PROVE_TIMEOUT_SECS: u64 = 900;
/// Timeout (seconds) for one bridge finalize phase in the daemon.
pub const BRIDGE_FINALIZE_TIMEOUT_SECS: u64 = 300;
/// Timeout (seconds) for one withdrawal-claim phase in the daemon.
pub const BRIDGE_CLAIM_TIMEOUT_SECS: u64 = 300;

/// Default path to the software-defined DPN circuit JSON.
pub const DEFAULT_SDC_PATH: &str = "sdc.json";

/// Contract ID of the deposit tree precompile on L2.
pub const DEPOSIT_TREE_CONTRACT_ID: u32 = 2;
/// Contract ID of the withdrawal tree precompile on L2.
pub const WITHDRAWAL_TREE_CONTRACT_ID: u32 = 3;

// ── L1 / contract layout constants ───────────────────────────────────────────

/// L1 chain index used in bridge proofs.
pub const L1_CHAIN_INDEX: u8 = 0;

/// Base storage slot for the deposit tree's chain root (PsyDepositTreeContract).
pub const DEPOSIT_TREE_CHAIN_ROOT_SLOT_BASE: u64 = 16451;
/// Base storage slot for the deposit tree's aggregate root.
pub const DEPOSIT_TREE_AGG_SLOT_BASE: u64 = DEPOSIT_TREE_CHAIN_ROOT_SLOT_BASE + 256 * 2;
/// Base storage slot for the withdrawal tree's chain root (PsyWithdrawalTreeContract).
pub const WITHDRAWAL_TREE_CHAIN_ROOT_SLOT_BASE: u64 = 16451;
/// Base storage slot for the withdrawal tree's aggregate root.
pub const WITHDRAWAL_TREE_AGG_SLOT_BASE: u64 = WITHDRAWAL_TREE_CHAIN_ROOT_SLOT_BASE + 256 * 2;
/// Height of the top-level Merkle tree used in keccak proofs for StateManager.finalize.
pub const TOP_TREE_HEIGHT: usize = 8;

/// Max concurrent Groth16 proof requests to prove proxy (1 = sequential).
pub const MAX_CONCURRENT_PROXY_PROOFS: usize = 1;
