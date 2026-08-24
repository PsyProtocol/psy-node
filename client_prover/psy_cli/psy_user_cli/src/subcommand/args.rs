use clap::{Args, Subcommand};
use plonky2::field::goldilocks_field::GoldilocksField;
pub use psy_client_common::args::WalletSourceArgs;
use psy_client_common::{args::SignType, data::qhashout::QHashOut};
use serde::{Deserialize, Serialize};

#[derive(Clone, Args)]
pub struct WalletArgs {
    #[command(subcommand)]
    pub command: WalletCommands,
}

#[derive(Clone, Subcommand)]
pub enum WalletCommands {
    /// Create a new wallet
    Create {
        #[arg(long, help = "Output path for the wallet")]
        output: Option<String>,
        #[arg(long, help = "Password for the wallet")]
        password: Option<String>,
        #[command(flatten)]
        wallet: WalletSourceArgs,
    },
    /// Load and display wallet info
    Load {
        #[command(flatten)]
        wallet: WalletSourceArgs,
    },
    /// List accounts in keystore directory
    List {
        #[arg(long, help = "Keystore directory path")]
        keystore_dir: Option<String>,
    },
    /// Generate a random wallet
    Random {
        #[clap(long, default_value = "zk")]
        sign_type: SignType,
    },
    /// Display wallet information
    Info {
        #[command(flatten)]
        wallet: WalletSourceArgs,
    },
    /// Print SD key fingerprint for an allow-method policy
    SdKeyFingerprint {
        #[arg(long, action = clap::ArgAction::Append, required = true)]
        allowed_contract_id: Vec<u64>,
        #[arg(long, action = clap::ArgAction::Append, required = true)]
        allowed_method_id: Vec<u32>,
        #[arg(long, default_value_t = 2)]
        expected_tx_count: u64,
    },
}

#[derive(Clone, Args, Serialize, Deserialize)]
pub struct RegisterUserArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[command(flatten)]
    pub wallet: WalletSourceArgs,
}

#[derive(Clone, Args)]
pub struct DeployContractArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    /// Wallet source: `--private-key` remains compatible, while keystore
    /// sources use `--keystore-path` and optional `--wallet-password`.
    #[command(flatten)]
    pub wallet: WalletSourceArgs,
    #[clap(long)]
    pub contract_path: String,
    #[clap(long, env)]
    pub output_path: Option<String>,
    #[clap(long, env)]
    pub is_deploy: bool,
}

#[derive(Clone, Args, Serialize, Deserialize)]
pub struct UpdateContractArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[clap(long, env)]
    pub private_key: String,
    #[clap(long, short, default_value = "zk")]
    pub sign_type: SignType,
    #[clap(long, env)]
    pub fingerprint: Option<String>,
    #[clap(long)]
    pub contract_id: u64,
    #[clap(long)]
    pub contract_path: String,
    /// ABI JSON of the currently deployed contract layout. When omitted the old
    /// ABI is assumed to match the new ABI in the compilation artifact supplied
    /// to `--contract-path`.
    #[clap(long)]
    pub old_abi_path: Option<String>,
    /// ABI JSON produced for the updated contract. When omitted the new ABI is
    /// read from the compilation artifact supplied to `--contract-path`.
    #[clap(long)]
    pub new_abi_path: Option<String>,
    #[clap(long, env)]
    pub output_path: Option<String>,
    #[clap(long, env)]
    pub is_update: bool,
}

#[derive(Clone, Args, Serialize, Deserialize)]
pub struct SubmitEndCapArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[clap(long, short)]
    pub private_key: String,
    #[arg(long, default_value = "0", env)]
    pub contract_id: u64,
    #[arg(long, default_value = "main", env)]
    pub method_name: String,
    #[arg(long, env)]
    pub inputs: Vec<u64>,
    #[clap(long, default_value = "zk")]
    pub sign_type: SignType,
    #[clap(long)]
    pub sign_inputs: Vec<u64>,
}

#[derive(Clone, Args)]
pub struct UserIdArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[arg(long, default_value = "0d47fda4480f045506b085ba6921fc86d8cc6feb1b533292db4b1a3af8f89eab", env)]
    pub pub_key: QHashOut<GoldilocksField>,
}

#[derive(Clone, Args)]
pub struct UserEventDataArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[arg(long, env)]
    pub checkpoint_id: u64,
    #[arg(long, env)]
    pub user_id: u64,
    #[arg(long, env)]
    pub event_index: u64,
}

#[derive(Clone, Args)]
pub struct UserLeafArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[arg(long, help = "User public key (queries coordinator)", conflicts_with = "user_id")]
    pub pub_key: Option<QHashOut<GoldilocksField>>,
    #[arg(long, help = "User ID (queries corresponding realm)", conflicts_with = "pub_key")]
    pub user_id: Option<u64>,
    #[arg(long, default_value = "100", env)]
    pub checkpoint_id: u64,
}

// Tree-related args
#[derive(Clone, Args)]
pub struct UserContractStateTreeRootArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[arg(long, env)]
    pub checkpoint_id: u64,
    #[arg(long, env)]
    pub user_id: u64,
    #[arg(long, env)]
    pub contract_id: u32,
}

#[derive(Clone, Args)]
pub struct UserContractStateTreeLeafHashArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[arg(long, env)]
    pub checkpoint_id: u64,
    #[arg(long, env)]
    pub user_id: u64,
    #[arg(long, env)]
    pub contract_id: u32,
    #[arg(long, env)]
    pub leaf_id: u64,
}

#[derive(Clone, Args)]
pub struct UserContractStateIMTLeafPreimageArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[arg(long, env)]
    pub checkpoint_id: u64,
    #[arg(long, env)]
    pub user_id: u64,
    #[arg(long, env)]
    pub contract_id: u64,
    #[arg(long, env)]
    pub leaf_index: u64,
}

#[derive(Clone, Args)]
pub struct UserContractStateTreeMerkleProofArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[arg(long, env)]
    pub checkpoint_id: u64,
    #[arg(long, env)]
    pub user_id: u64,
    #[arg(long, env)]
    pub contract_id: u32,
    #[arg(long, env)]
    pub leaf_id: u64,
}

#[derive(Clone, Args)]
pub struct UserContractTreeRootArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[arg(long, env)]
    pub checkpoint_id: u64,
    #[arg(long, env)]
    pub user_id: u64,
}

#[derive(Clone, Args)]
pub struct UserContractTreeLeafHashArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[arg(long, env)]
    pub checkpoint_id: u64,
    #[arg(long, env)]
    pub user_id: u64,
    #[arg(long, env)]
    pub contract_id: u32,
}

#[derive(Clone, Args)]
pub struct UserContractTreeMerkleProofArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[arg(long, env)]
    pub checkpoint_id: u64,
    #[arg(long, env)]
    pub user_id: u64,
    #[arg(long, env)]
    pub contract_id: u32,
}

#[derive(Clone, Args)]
pub struct UserRegistrationTreeRootArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[arg(long, env)]
    pub checkpoint_id: u64,
}

#[derive(Clone, Args)]
pub struct UserRegistrationTreeLeafHashArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[arg(long, env)]
    pub checkpoint_id: u64,
    #[arg(long, env)]
    pub registration_id: u64,
}

#[derive(Clone, Args)]
pub struct UserRegistrationTreeMerkleProofArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[arg(long, env)]
    pub checkpoint_id: u64,
    #[arg(long, env)]
    pub registration_id: u64,
}

#[derive(Clone, Args)]
pub struct UserTreeRootArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[arg(long, env)]
    pub checkpoint_id: u64,
}

#[derive(Clone, Args)]
pub struct UserTreeLeafHashArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[arg(long, env)]
    pub checkpoint_id: u64,
    #[arg(long, env)]
    pub user_id: u64,
}

#[derive(Clone, Args)]
pub struct UserTreeMerkleProofArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[arg(long, env)]
    pub checkpoint_id: u64,
    #[arg(long, env)]
    pub user_id: u64,
}

#[derive(Clone, Args)]
pub struct UserSubTreeMerkleProofArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[arg(long, env)]
    pub checkpoint_id: u64,
    #[arg(long, env)]
    pub root_level: u8,
    #[arg(long, env)]
    pub leaf_level: u8,
    #[arg(long, env)]
    pub leaf_index: u64,
}

#[derive(Clone, Args)]
pub struct ContractFunctionTreeRootArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[arg(long, env)]
    pub checkpoint_id: u64,
    #[arg(long, env)]
    pub contract_id: u32,
}

#[derive(Clone, Args)]
pub struct ContractFunctionTreeLeafHashArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[arg(long, env)]
    pub checkpoint_id: u64,
    #[arg(long, env)]
    pub contract_id: u32,
    #[arg(long, env)]
    pub function_id: u32,
}

#[derive(Clone, Args)]
pub struct ContractFunctionTreeMerkleProofArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[arg(long, env)]
    pub checkpoint_id: u64,
    #[arg(long, env)]
    pub contract_id: u32,
    #[arg(long, env)]
    pub function_id: u32,
}

#[derive(Clone, Args)]
pub struct ContractTreeRootArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[arg(long, env)]
    pub checkpoint_id: u64,
}

#[derive(Clone, Args)]
pub struct ContractTreeLeafHashArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[arg(long, env)]
    pub checkpoint_id: u64,
    #[arg(long, env)]
    pub contract_id: u32,
}

#[derive(Clone, Args)]
pub struct ContractTreeMerkleProofArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[arg(long, env)]
    pub checkpoint_id: u64,
    #[arg(long, env)]
    pub contract_id: u32,
}

#[derive(Clone, Args)]
pub struct WithdrawalTreeRootArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[arg(long, env)]
    pub checkpoint_id: u64,
}

#[derive(Clone, Args)]
pub struct LatestCheckpointTreeRootArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
}

#[derive(Clone, Args)]
pub struct CheckpointTreeRootArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[arg(long, env)]
    pub checkpoint_id: u64,
}

#[derive(Clone, Args)]
pub struct CheckpointTreeLeafHashArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[arg(long, env)]
    pub checkpoint_id: u64,
    #[arg(long, env)]
    pub leaf_checkpoint_id: u64,
}

#[derive(Clone, Args)]
pub struct CheckpointTreeMerkleProofArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[arg(long, env)]
    pub checkpoint_id: u64,
    #[arg(long, env)]
    pub leaf_checkpoint_id: u64,
}

// Metadata-related args
#[derive(Clone, Args)]
pub struct ContractLeafDataArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[arg(long, env)]
    pub contract_id: u64,
}

#[derive(Clone, Args)]
pub struct CheckpointLeafDataArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[arg(long, env)]
    pub checkpoint_id: u64,
}

#[derive(Clone, Args)]
pub struct ContractCodeDefinitionArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[arg(long, env)]
    pub contract_id: u64,
}

#[derive(Clone, Args)]
pub struct LatestBlockStateArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
}

#[derive(Clone, Args)]
pub struct BlockStateArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[arg(long, env)]
    pub checkpoint_id: u64,
}

#[derive(Clone, Args, Serialize, Deserialize)]
pub struct ClaimAmountArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,

    #[clap(long)]
    pub checkpoint_id: Option<u64>,

    #[clap(long)]
    pub user_id: u64,

    #[clap(long)]
    pub claim_user_id: u64,
}

#[derive(Clone, Args, Serialize, Deserialize)]
pub struct TxGetStatusArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,

    #[clap(long, alias = "from-checkpoint", alias = "checkpoint-id")]
    pub start_checkpoint_id: u64,

    #[clap(long)]
    pub to_checkpoint: Option<u64>,

    #[clap(long)]
    pub user_id: u64,

    #[clap(long, alias = "tx-hash")]
    pub end_user_leaf_hash: String,
}

#[derive(Clone, Args)]
pub struct TxArgs {
    #[command(subcommand)]
    pub command: TxCommands,
}

#[derive(Clone, Subcommand)]
pub enum TxCommands {
    GetStatus(TxGetStatusArgs),
}

#[derive(Clone, Copy, Debug, clap::ValueEnum, Serialize, Deserialize)]
pub enum RpcProviderType {
    Coordinator,
    Realm,
}

#[derive(Clone, Args, Serialize, Deserialize)]
pub struct GetCheckpointIdForUniquePendingIdArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[clap(long)]
    pub unique_pending_id: u64,
    #[clap(long, value_enum, default_value = "coordinator")]
    pub provider_type: RpcProviderType,
}

#[derive(Clone, Args, Serialize, Deserialize)]
pub struct GenerateBatchProofMinerRewardProofsArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[clap(long)]
    pub unique_pending_id: u64,
    #[clap(long, value_enum, default_value = "coordinator")]
    pub provider_type: RpcProviderType,
    /// Path to JSON file containing job IDs
    #[clap(long, default_value = "reward_jobs.json")]
    pub jobs_file: String,
    /// Path to output file for proofs
    #[clap(long, default_value = "reward_proofs.json")]
    pub output_file: String,
}

#[derive(Clone, Args, Serialize, Deserialize)]
pub struct ClaimRewardsArgs {
    #[clap(env, long, default_value = "config.json", env)]
    pub rpc_config: String,
    #[command(flatten)]
    pub wallet: WalletSourceArgs,
    /// Path to JSON file containing job IDs
    #[clap(long, default_value = "worker.backup")]
    pub jobs_file: String,
}

#[derive(Clone, Args, Serialize, Deserialize)]
pub struct GetPsySdcFingerprintArgs {
    #[clap(long, default_value = "sdc.json")]
    pub sdc_path: String,
}

// ─── PSY Compiler CLI Args ──────────────────────────────────────────────────

#[derive(Clone, Args)]
pub struct CompileArgs {
    /// Path to .psy.rs source file or crate root directory
    #[clap(long)]
    pub source: String,

    /// Output directory for compiled artifacts
    #[clap(long)]
    pub output_dir: Option<String>,

    /// Only generate ABI JSON (skip code generation)
    #[clap(long)]
    pub abi_only: bool,

    /// Type-check only (no code generation)
    #[clap(long)]
    pub check: bool,

    /// Treat source as a multi-file crate (root file = lib.psy.rs)
    #[clap(long)]
    pub is_crate: bool,
}

#[derive(Clone, Args)]
pub struct CompileAndDeployArgs {
    /// Path to .psy.rs source file or crate root directory
    #[clap(long)]
    pub source: String,

    #[clap(env, long, default_value = "config.json")]
    pub rpc_config: String,

    #[clap(long, env)]
    pub private_key: String,

    #[clap(long, short, default_value = "zk")]
    pub sign_type: SignType,

    #[clap(long, env)]
    pub fingerprint: Option<String>,

    /// Output directory for compiled artifacts
    #[clap(long)]
    pub output_dir: Option<String>,

    /// Compile only, don't deploy to coordinator
    #[clap(long)]
    pub dry_run: bool,

    /// Treat source as a multi-file crate
    #[clap(long)]
    pub is_crate: bool,
}

#[derive(Clone, Args)]
pub struct SimulateArgs {
    /// Contract method name to simulate
    #[clap(long)]
    pub method: String,

    /// Input values (felts) for the method
    #[clap(long)]
    pub inputs: Vec<u64>,

    /// Path to .psy.rs source file (compile on-the-fly)
    #[clap(long)]
    pub source: Option<String>,

    /// Path to pre-compiled circuit_defs.json
    #[clap(long)]
    pub circuit_defs_path: Option<String>,

    /// Path to ABI JSON file (for field name resolution)
    #[clap(long)]
    pub abi_path: Option<String>,

    /// Executing user ID
    #[clap(long, default_value = "1")]
    pub user_id: u64,

    /// Contract ID
    #[clap(long)]
    pub contract_id: Option<u64>,

    /// Checkpoint ID
    #[clap(long)]
    pub checkpoint_id: Option<u64>,

    /// Nonce
    #[clap(long)]
    pub nonce: Option<u64>,

    /// Output format: json, table, minimal
    #[clap(long)]
    pub format: Option<String>,

    /// Treat source as a multi-file crate
    #[clap(long)]
    pub is_crate: bool,
}

#[derive(Clone, Args, Serialize, Deserialize)]
pub struct PrivateClaimArgs {
    #[clap(env, long, default_value = "config.json")]
    pub rpc_config: String,
    #[clap(long, short = 'p')]
    pub private_key: String,
    #[clap(long, default_value = "0")]
    pub contract_id: u64,
    #[clap(long)]
    pub note_proof: Option<String>,
    #[clap(long)]
    pub nostr_secret_key: Option<String>,
    #[clap(long, default_value = "wss://relay.nostr.band")]
    pub nostr_relay: String,
    #[clap(long, default_value = "20")]
    pub nostr_timeout_secs: u64,
    #[clap(long, default_value_t = 0)]
    pub random0: u64,
    #[clap(long, default_value_t = 0)]
    pub random1: u64,
}

#[derive(Clone, Args, Serialize, Deserialize)]
pub struct PrivateTransferArgs {
    #[clap(env, long, default_value = "config.json")]
    pub rpc_config: String,
    #[clap(long, short = 'p')]
    pub private_key: String,
    #[clap(long, default_value = "0")]
    pub contract_id: u64,
    #[clap(long, default_value = "zk")]
    pub sign_type: SignType,
    #[clap(long)]
    pub amount: u64,
    #[clap(long, alias = "owner")]
    pub receiver: Option<String>,
    #[clap(long, default_value = "2147483649")]
    pub note_root_slot: u64,
    #[clap(long, default_value_t = u64::MAX)]
    pub checkpoint_id: u64,
    #[clap(long, default_value = "note_proof.json")]
    pub output: String,
    #[clap(long)]
    pub nostr_recipient_pubkey: Option<String>,
    #[clap(long, default_value = "wss://relay.nostr.band")]
    pub nostr_relay: String,
}

#[derive(Clone, Args)]
pub struct ClaimDepositArgs {
    #[clap(env, long, default_value = "config.json")]
    pub rpc_config: String,
    #[command(flatten)]
    pub wallet: WalletSourceArgs,

    /// L1 RPC URL for fetching provedDepositCount from the Bridge contract
    #[arg(long, env, default_value = "http://127.0.0.1:8545")]
    pub l1_rpc_url: String,

    #[arg(long, env)]
    pub token_l1_address: String,
    #[arg(long, env)]
    pub amount: u64,
    #[arg(long, env)]
    pub source_chain_index: u32,
    #[arg(long, env)]
    pub user_id: u64,
    #[arg(long, env)]
    pub deposit_index: u64,
    /// Checkpoint ID for proof context. Auto-detects from user leaf if omitted.
    #[arg(long, env)]
    pub checkpoint_id: Option<u64>,
    #[arg(long, env)]
    pub r0: u64,
    #[arg(long, env)]
    pub r1: u64,
    /// Optional per-deposit note secret for local sanity-check only. The claim
    /// path consumes the sender-generated deposit proof and does not require
    /// raw secrets to submit.
    #[arg(long = "note-secret", env)]
    pub note_secret: Option<String>,
    /// Optional per-deposit nullifier secret for local sanity-check only. Must
    /// be passed together with --note-secret when used.
    #[arg(long, env)]
    pub nullifier_secret: Option<String>,
    /// Sender-generated DepositInclusion proof JSON file.
    #[arg(long = "deposit-proof", env)]
    pub deposit_proof: String,
}

#[derive(Clone, Args)]
pub struct BatchClaimArgs {
    #[clap(env, long, default_value = "config.json")]
    pub rpc_config: String,
    #[command(flatten)]
    pub wallet: WalletSourceArgs,
    #[arg(long)]
    pub input: String,
    #[arg(long)]
    pub trace_out: Option<String>,
    #[arg(long)]
    pub generate_only: bool,
    #[arg(long)]
    pub wait: bool,
}

#[derive(Clone, Args)]
pub struct WithdrawArgs {
    #[clap(env, long, default_value = "config.json")]
    pub rpc_config: String,
    #[command(flatten)]
    pub wallet: WalletSourceArgs,

    /// Destination bridge chain index (0-255), not the EVM chainId.
    /// Legacy alias: --destination-chain-id (same meaning: chain index, not EVM
    /// chainId)
    #[arg(long = "destination-chain-index", alias = "destination-chain-id", env = "DESTINATION_CHAIN_INDEX")]
    pub destination_chain_index: u64,
    /// L1 token contract address (20-byte EVM address or 32-byte hex; 20-byte
    /// inputs are auto-left-padded to bytes32)
    #[arg(long, env)]
    pub token_address: String,
    /// Amount to withdraw
    #[arg(long, env)]
    pub amount: u64,
    /// L1 recipient address (20-byte EVM address or 32-byte hex; 20-byte
    /// inputs are auto-left-padded to bytes32)
    #[arg(long, env)]
    pub recipient: String,
    /// User-chosen nonce (bytes32 hex, 256-bit, unique per destination chain)
    #[arg(long, env)]
    pub nonce: String,
    /// L1 RPC URL (e.g. http://localhost:8545)
    #[arg(long, env, default_value = "http://127.0.0.1:8545")]
    pub l1_rpc_url: String,
    /// Override L2 contract ID to call withdraw on (default: auto-detect from
    /// Router)
    #[arg(long, env)]
    pub contract_id: Option<u64>,
}

#[derive(Clone, Args, Serialize, Deserialize)]
pub struct DeriveNoteOwnerArgs {
    #[clap(env, long, default_value = "config.json")]
    pub rpc_config: String,
    #[clap(long, short = 'p')]
    pub private_key: String,
    #[clap(long, default_value_t = 0)]
    pub random0: u64,
    #[clap(long, default_value_t = 0)]
    pub random1: u64,
}

#[derive(Clone, Args)]
pub struct DepositArgs {
    /// L1 RPC URL (e.g. http://localhost:8545)
    #[clap(long, env, default_value = "http://127.0.0.1:8545")]
    pub l1_rpc_url: String,
    /// L1 private key for signing the deposit tx
    #[clap(long, short = 'p')]
    pub private_key: String,
    /// Router contract address (0x-prefixed hex)
    #[clap(long, env)]
    pub router_address: String,
    /// Token address (0x-prefixed, 20-byte). Use 0x0 for native ETH.
    #[clap(long, env)]
    pub token: String,
    /// Amount to deposit (wei)
    #[clap(long, env)]
    pub amount: String,
    /// Shield address (32-byte hex, 0x-prefixed). If omitted, auto-computed
    /// from --r0 and --r1.
    #[clap(long, env, default_value = "")]
    pub shield_address: String,
    /// Random value r0 for deriving shield address (requires --r1 and
    /// --user-id)
    #[clap(long, env)]
    pub r0: Option<u64>,
    /// Random value r1 for deriving shield address (requires --r0 and
    /// --user-id)
    #[clap(long, env)]
    pub r1: Option<u64>,
    /// User ID on L2 (required with --r0, --r1)
    #[clap(long, env)]
    pub user_id: Option<u64>,
    /// Note commitment recorded on L1 (32-byte hex, 0x-prefixed). For
    /// claimable deposits this is hash(nullifier_secret, raw note_secret).
    /// If --note-secret and --nullifier-secret are provided, this is optional
    /// and will be derived. If both are provided, an explicit value is checked
    /// against the derived commitment.
    #[clap(long = "note-commitment", env = "NOTE_COMMITMENT")]
    pub note_commitment: Option<String>,
    /// Per-deposit note secret as four comma-separated u64 limbs, e.g.
    /// "1,2,3,4". Used to derive note_commitment and publish the optional
    /// recipient Nostr backup.
    #[clap(long = "note-secret", env = "NOTE_SECRET")]
    pub note_secret: Option<String>,
    /// Per-deposit nullifier secret as four comma-separated u64 limbs.
    #[clap(long = "nullifier-secret", env = "NULLIFIER_SECRET")]
    pub nullifier_secret: Option<String>,
    /// Recipient Nostr npub for publishing the deposit backup. Requires both
    /// --note-secret and --nullifier-secret.
    #[clap(long = "recipient-npub", env = "RECIPIENT_NPUB")]
    pub recipient_npub: Option<String>,
    /// Nostr relay used for the optional deposit backup.
    #[clap(long, env, default_value = "wss://relay.nostr.band")]
    pub nostr_relay: String,
    /// L2 token contract id included as a sender-side metadata hint in the
    /// optional Nostr backup. The claim path refreshes proof data from
    /// services, but the hint lets Activity display the correct token early.
    #[clap(long = "l2-token-contract-id", env, default_value = "4")]
    pub l2_token_contract_id: String,
    /// Psy source chain index included in the optional Nostr backup.
    #[clap(long = "source-chain-index", env, default_value_t = 0)]
    pub source_chain_index: u32,
    /// RPC config path (for looking up L2 addresses)
    #[clap(long, env, default_value = "config.json")]
    pub rpc_config: String,
    /// Optional file path to write the generated DepositInclusion proof JSON
    /// that claim_deposit later consumes with --deposit-proof.
    #[clap(long = "deposit-proof-output", env = "DEPOSIT_PROOF_OUTPUT")]
    pub deposit_proof_output: Option<String>,
}

#[derive(Clone, Args)]
pub struct ClaimWithdrawalArgs {
    /// Psy RPC config file (for network name → deployment lookup)
    #[clap(env, long, default_value = "config.json")]
    pub rpc_config: String,
    /// psy-services URL
    #[clap(long, env, default_value = "http://localhost:3000")]
    pub services_url: String,
    /// L1 RPC URL
    #[clap(long, env, default_value = "http://127.0.0.1:8545")]
    pub l1_rpc_url: String,
    /// L1 private key (required to submit the claim tx)
    #[clap(long, short = 'p')]
    pub private_key: String,
    /// L1 recipient address (20-byte EVM address or 32-byte hex; 20-byte
    /// inputs are auto-left-padded to bytes32)
    #[clap(long, env)]
    pub recipient: String,
    /// L1 token address (20-byte EVM address or 32-byte hex; 20-byte inputs
    /// are auto-left-padded to bytes32)
    #[clap(long, env)]
    pub token_address: String,
    /// Withdrawal amount (wei)
    #[clap(long, env)]
    pub amount: String,
    /// Withdrawal nonce (bytes32 hex preferred; decimal is accepted and
    /// normalized to bytes32)
    #[clap(long, env)]
    pub nonce: String,
    /// Destination bridge chain index (0-255), not the EVM chainId.
    /// Legacy alias: --destination-chain-id (same meaning: chain index, not EVM
    /// chainId)
    #[clap(long = "destination-chain-index", alias = "destination-chain-id", env = "DESTINATION_CHAIN_INDEX")]
    pub destination_chain_index: u64,
    /// Sender user id on L2; pass this to disambiguate identical withdrawals.
    #[clap(long, env)]
    pub sender_user_id: Option<u64>,
    /// Prove-proxy URL for Groth16 proof generation (optional; if omitted, just
    /// prints the proof)
    #[clap(long, env)]
    pub prove_proxy_url: Option<String>,
    /// Prove-proxy bearer token (optional)
    #[clap(long, env)]
    pub prove_proxy_token: Option<String>,
}
