use std::path::PathBuf;

use clap::{command, Parser, Subcommand};
use psy_client_common::args::{ExportKeyStoreArgs, ProverArgs, PsyFaucetServerArgs, WalletSessionArgs};

pub mod args;
pub mod compile;
pub mod compile_deploy;
pub mod contract_abi_upload;
pub mod deploy_contract;
pub mod faucet_server;
pub mod local_prover;
#[cfg(feature = "gnark-wrap")]
pub mod prove_proxy;
pub mod simulate;
pub mod update_contract;

cfg_if::cfg_if! {
    if #[cfg(not(target_arch = "wasm32"))] {
        pub mod wallet;
        pub mod register_user;
        pub mod submit_end_cap_proof;
        pub mod batch_claim;
        pub mod claim_amount;
        pub mod claim_deposit;
        pub mod deposit;
        pub mod deployments;
        pub mod claim_withdrawal;
        pub mod withdraw;
        pub mod tx;
        pub mod get_checkpoint_id_for_unique_pending_id;
        pub mod generate_batch_proof_miner_reward_proofs;
        pub mod claim_rewards;
        pub mod get_user_id;
        pub mod get_psy_sdc_fingerprint;
        pub mod get_user_endcap_common_data;
        pub mod note_proof_common;
        pub mod private_claim;
        pub mod private_transfer;
        pub mod shield_address;
        pub mod export_private_key;
        pub mod generate_tx_trace;
        pub mod prove_tx_trace;
    }
}

#[derive(Parser)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
    /// Atomically write the command's secret-free structured result.
    #[arg(global = true, long = "result-file", value_name = "PATH")]
    pub result_file: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum Commands {
    Wallet(crate::subcommand::args::WalletArgs),
    RegisterUser(crate::subcommand::args::RegisterUserArgs),

    DeployContract(crate::subcommand::args::DeployContractArgs),
    UpdateContract(crate::subcommand::args::UpdateContractArgs),
    Call(WalletSessionArgs),

    GetUserId(crate::subcommand::args::UserIdArgs),
    GetUserEventData(crate::subcommand::args::UserEventDataArgs),
    GetUserLeaf(crate::subcommand::args::UserLeafArgs),

    // Tree commands
    GetUserContractStateTreeRoot(crate::subcommand::args::UserContractStateTreeRootArgs),
    GetUserContractStateTreeLeafHash(crate::subcommand::args::UserContractStateTreeLeafHashArgs),
    GetUserContractStateIMTLeafPreimage(crate::subcommand::args::UserContractStateIMTLeafPreimageArgs),
    GetUserContractStateTreeMerkleProof(crate::subcommand::args::UserContractStateTreeMerkleProofArgs),

    GetUserContractTreeRoot(crate::subcommand::args::UserContractTreeRootArgs),
    GetUserContractTreeLeafHash(crate::subcommand::args::UserContractTreeLeafHashArgs),
    GetUserContractTreeMerkleProof(crate::subcommand::args::UserContractTreeMerkleProofArgs),

    GetUserRegistrationTreeRoot(crate::subcommand::args::UserRegistrationTreeRootArgs),
    GetUserRegistrationTreeLeafHash(crate::subcommand::args::UserRegistrationTreeLeafHashArgs),
    GetUserRegistrationTreeMerkleProof(crate::subcommand::args::UserRegistrationTreeMerkleProofArgs),

    GetUserTreeRoot(crate::subcommand::args::UserTreeRootArgs),
    GetUserTreeLeafHash(crate::subcommand::args::UserTreeLeafHashArgs),
    GetUserTreeMerkleProof(crate::subcommand::args::UserTreeMerkleProofArgs),
    GetUserSubTreeMerkleProof(crate::subcommand::args::UserSubTreeMerkleProofArgs),

    GetContractFunctionTreeRoot(crate::subcommand::args::ContractFunctionTreeRootArgs),
    GetContractFunctionTreeLeafHash(crate::subcommand::args::ContractFunctionTreeLeafHashArgs),
    GetContractFunctionTreeMerkleProof(crate::subcommand::args::ContractFunctionTreeMerkleProofArgs),

    GetContractTreeRoot(crate::subcommand::args::ContractTreeRootArgs),
    GetContractTreeLeafHash(crate::subcommand::args::ContractTreeLeafHashArgs),
    GetContractTreeMerkleProof(crate::subcommand::args::ContractTreeMerkleProofArgs),

    GetWithdrawalTreeRoot(crate::subcommand::args::WithdrawalTreeRootArgs),

    GetLatestCheckpointTreeRoot(crate::subcommand::args::LatestCheckpointTreeRootArgs),
    GetCheckpointTreeRoot(crate::subcommand::args::CheckpointTreeRootArgs),
    GetCheckpointTreeLeafHash(crate::subcommand::args::CheckpointTreeLeafHashArgs),
    GetCheckpointTreeMerkleProof(crate::subcommand::args::CheckpointTreeMerkleProofArgs),

    // Metadata commands
    GetContractLeafData(crate::subcommand::args::ContractLeafDataArgs),
    GetCheckpointLeafData(crate::subcommand::args::CheckpointLeafDataArgs),
    GetContractCodeDefinition(crate::subcommand::args::ContractCodeDefinitionArgs),
    GetLatestBlockState(crate::subcommand::args::LatestBlockStateArgs),
    GetBlockState(crate::subcommand::args::BlockStateArgs),

    // local proving
    LocalProver(ProverArgs),
    #[cfg(feature = "gnark-wrap")]
    ProveProxy(psy_client_common::args::ProveProxyArgs),
    FaucetServer(PsyFaucetServerArgs),

    // claim amount
    GetClaimAmount(crate::subcommand::args::ClaimAmountArgs),
    BatchClaim(crate::subcommand::args::BatchClaimArgs),
    Tx(crate::subcommand::args::TxArgs),
    // batch proof miner rewards
    GetCheckpointIdForUniquePendingId(crate::subcommand::args::GetCheckpointIdForUniquePendingIdArgs),
    GenerateBatchProofMinerRewardProofs(crate::subcommand::args::GenerateBatchProofMinerRewardProofsArgs),
    // v2 rewards claiming
    ClaimRewards(crate::subcommand::args::ClaimRewardsArgs),

    GetPsySdcFingerprint(crate::subcommand::args::GetPsySdcFingerprintArgs),

    GetUserEndCapCommonData,

    // PSY compiler commands
    /// Compile a .psy.rs contract source file
    Compile(crate::subcommand::args::CompileArgs),
    /// Compile and deploy a contract in one step
    CompileAndDeploy(crate::subcommand::args::CompileAndDeployArgs),
    /// Simulate a contract method execution (no proofs)
    Simulate(crate::subcommand::args::SimulateArgs),
    /// Generate a transaction trace without proving (outputs a JSON trace file
    /// that prove-tx-trace can consume).
    GenerateTxTrace(crate::subcommand::generate_tx_trace::GenerateTxTraceArgs),
    /// Prove a previously generated transaction trace and submit the end-cap
    /// proof.
    ProveTxTrace(crate::subcommand::prove_tx_trace::ProveTxTraceArgs),
    /// Execute private transfer flow and generate note proof payload.
    PrivateTransfer(crate::subcommand::args::PrivateTransferArgs),
    /// Claim a private note from generated proof payload.
    PrivateClaim(crate::subcommand::args::PrivateClaimArgs),
    /// Derive note owner hash from receiver pubkey and binding.
    DeriveNoteOwner(crate::subcommand::args::DeriveNoteOwnerArgs),
    /// Claim a bridge deposit on L2. Requires the deposit proof from
    /// psy-services.
    ClaimDeposit(crate::subcommand::args::ClaimDepositArgs),
    /// Withdraw tokens from L2 to L1 via the bridge.
    Withdraw(crate::subcommand::args::WithdrawArgs),
    /// Deposit tokens from L1 to L2 via the Router contract.
    Deposit(crate::subcommand::args::DepositArgs),
    /// Claim a withdrawal on L1. Fetches the Merkle proof from psy-services
    /// and optionally generates a Groth16 proof + submits to L1 Bridge.
    ClaimWithdrawal(crate::subcommand::args::ClaimWithdrawalArgs),

    ExportPrivateKey(ExportKeyStoreArgs),
}
