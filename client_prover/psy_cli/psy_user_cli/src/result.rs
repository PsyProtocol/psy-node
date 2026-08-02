//! Structured, secret-free JSON results for `--result-file`.

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::Result;
use plonky2::field::goldilocks_field::GoldilocksField as F;
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::{
    dpn::event::PsyUserEventRecord,
    qdata::{
        checkpoint::{PsyBlockState, PsyCheckpointLeaf},
        contract::{ContractCodeDefinition, PsyContractLeaf},
        imt_contract_state::IMTContractStateLeaf,
        user::PsyUserLeaf,
    },
};
use psy_crypto::hash::merkle::core::MerkleProofCore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployResult {
    pub contract_id: Option<u64>,
    pub tx_hash: String,
    pub network: String,
    pub status: DeployStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeployStatus {
    Submitted,
    Confirmed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletCreateResult {
    pub keystore_path: Option<String>,
    pub public_key_hash: QHashOut<F>,
    pub created: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletInfoResult {
    pub public_key_hash: QHashOut<F>,
    pub keystore_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetUserIdResult {
    pub public_key_hash: QHashOut<F>,
    pub user_id: Option<u64>,
    pub status: UserRegistrationStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserRegistrationStatus {
    Registered,
    NotRegistered,
    Pending,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterUserResult {
    pub public_key_hash: QHashOut<F>,
    pub user_id: Option<u64>,
    pub transaction_hash: Option<String>,
    pub status: UserRegistrationStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionResult {
    pub transaction_hash: QHashOut<F>,
    pub user_id: Option<u64>,
    pub status: TransactionStatus,
    pub confirmed_checkpoint: Option<u64>,
    pub network: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionStatus {
    Submitted,
    Confirmed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L1TransactionResult {
    pub transaction_hash: Option<String>,
    pub status: L1TransactionStatus,
    pub chain_id: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum L1TransactionStatus {
    Confirmed,
    NotFound,
    AlreadyClaimed,
    ProofOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeRootResult {
    pub root: QHashOut<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeafHashResult {
    pub leaf_hash: QHashOut<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProofResult {
    pub merkle_proof: MerkleProofCore<QHashOut<F>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeafPreimageResult {
    pub leaf_preimage: IMTContractStateLeaf<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventResult {
    pub event: PsyUserEventRecord<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LeafData {
    Contract(PsyContractLeaf<F>),
    Checkpoint(PsyCheckpointLeaf<F>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeafDataResult {
    pub data: LeafData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeDefinitionResult {
    pub code_definition: ContractCodeDefinition,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockStateResult {
    pub block_state: PsyBlockState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserLeafResult {
    pub user_id: u64,
    pub query_method: String,
    pub leaf_data: PsyUserLeaf<F>,
    pub leaf_hash: QHashOut<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintResult {
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointIdResult {
    pub checkpoint_id: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimAmountResult {
    pub claim_amount: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResult {
    pub status: TransactionStatus,
    pub user_id: u64,
    pub end_user_leaf_hash: QHashOut<F>,
    pub checkpoint_id: u64,
    pub from_checkpoint: u64,
    pub latest_checkpoint: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteOwnerResult {
    pub public_key: QHashOut<F>,
    pub user_id: u64,
    pub note_owner: QHashOut<F>,
    pub nostr_npub: String,
}

/// Public headers only. The trace payload, call data, witnesses, proofs, note
/// secrets, and nullifier secrets cannot be represented in this result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxTraceResult {
    pub user_id: String,
    pub pk_hash: String,
    pub sig_hash: String,
    pub tx_hash: String,
    pub tx_count: u64,
    pub output_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofsResult {
    pub count: usize,
    pub output_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenericResult {
    pub command: String,
    pub success: bool,
}

pub enum CommandResult {
    Deploy(DeployResult),
    WalletCreate(WalletCreateResult),
    WalletInfo(WalletInfoResult),
    GetUserId(GetUserIdResult),
    RegisterUser(RegisterUserResult),
    Transaction(TransactionResult),
    L1Transaction(L1TransactionResult),
    TreeRoot(TreeRootResult),
    LeafHash(LeafHashResult),
    MerkleProof(MerkleProofResult),
    LeafPreimage(LeafPreimageResult),
    Event(EventResult),
    LeafData(LeafDataResult),
    CodeDefinition(CodeDefinitionResult),
    BlockState(BlockStateResult),
    UserLeaf(UserLeafResult),
    Fingerprint(FingerprintResult),
    CheckpointId(CheckpointIdResult),
    ClaimAmount(ClaimAmountResult),
    TxStatus(StatusResult),
    NoteOwner(NoteOwnerResult),
    TxTrace(TxTraceResult),
    Proofs(ProofsResult),
    Generic(GenericResult),
}

impl CommandResult {
    pub fn generic(command: &str) -> Self {
        Self::Generic(GenericResult {
            command: command.to_string(),
            success: true,
        })
    }

    pub fn write_to_file(&self, path: &Path) -> Result<()> {
        match self {
            Self::Deploy(v) => write_json_atomically(path, v),
            Self::WalletCreate(v) => write_json_atomically(path, v),
            Self::WalletInfo(v) => write_json_atomically(path, v),
            Self::GetUserId(v) => write_json_atomically(path, v),
            Self::RegisterUser(v) => write_json_atomically(path, v),
            Self::Transaction(v) => write_json_atomically(path, v),
            Self::L1Transaction(v) => write_json_atomically(path, v),
            Self::TreeRoot(v) => write_json_atomically(path, v),
            Self::LeafHash(v) => write_json_atomically(path, v),
            Self::MerkleProof(v) => write_json_atomically(path, v),
            Self::LeafPreimage(v) => write_json_atomically(path, v),
            Self::Event(v) => write_json_atomically(path, v),
            Self::LeafData(v) => write_json_atomically(path, v),
            Self::CodeDefinition(v) => write_json_atomically(path, v),
            Self::BlockState(v) => write_json_atomically(path, v),
            Self::UserLeaf(v) => write_json_atomically(path, v),
            Self::Fingerprint(v) => write_json_atomically(path, v),
            Self::CheckpointId(v) => write_json_atomically(path, v),
            Self::ClaimAmount(v) => write_json_atomically(path, v),
            Self::TxStatus(v) => write_json_atomically(path, v),
            Self::NoteOwner(v) => write_json_atomically(path, v),
            Self::TxTrace(v) => write_json_atomically(path, v),
            Self::Proofs(v) => write_json_atomically(path, v),
            Self::Generic(v) => write_json_atomically(path, v),
        }
    }
}

/// Removes stale success before execution and removes the target on every error
/// path until `commit` publishes the new result.
pub struct ResultFileGuard {
    path: Option<PathBuf>,
    committed: bool,
}

impl ResultFileGuard {
    pub fn prepare(path: Option<PathBuf>) -> Result<Self> {
        if let Some(path) = path.as_deref() {
            remove_if_exists(path)?;
        }
        Ok(Self { path, committed: false })
    }

    pub fn commit(mut self, result: &CommandResult) -> Result<()> {
        if let Some(path) = self.path.as_deref() {
            result.write_to_file(path)?;
        }
        self.committed = true;
        Ok(())
    }
}

impl Drop for ResultFileGuard {
    fn drop(&mut self) {
        if !self.committed {
            if let Some(path) = self.path.as_deref() {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

fn remove_if_exists(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub fn write_json_atomically<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    use std::{
        fs::{self, OpenOptions},
        io::Write,
    };

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("result.json");
    let temp_path = parent.join(format!(
        ".{}.tmp.{}.{}",
        file_name,
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let json = serde_json::to_vec_pretty(value)?;
    let outcome: Result<()> = (|| {
        let mut file = OpenOptions::new().write(true).create_new(true).open(&temp_path)?;
        file.write_all(&json)?;
        file.write_all(b"\n")?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp_path, path)?;
        // Rename already published the success; directory sync is best-effort.
        let _ = fs::File::open(parent).and_then(|directory| directory.sync_all());
        Ok(())
    })();
    if outcome.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "psy-user-cli-result-{}-{}-{}",
            label,
            std::process::id(),
            TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn tx_trace_result_contains_only_public_headers_and_output_path() {
        let value = serde_json::to_value(TxTraceResult {
            user_id: "7".into(),
            pk_hash: "public-key".into(),
            sig_hash: "signature-hash".into(),
            tx_hash: "transaction-hash".into(),
            tx_count: 3,
            output_path: Some("trace.json".into()),
        })
        .unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(object.len(), 6);
        for forbidden in [
            "trace",
            "call_data",
            "private_key",
            "mnemonic",
            "password",
            "sign_witness",
            "cfc_witness",
            "note_secret",
            "nullifier_secret",
            "proof",
        ] {
            assert!(!object.contains_key(forbidden));
        }
    }

    #[test]
    fn typed_tree_root_result_serializes_its_payload() {
        let dir = temp_dir("tree-root");
        let path = dir.join("result.json");
        let root = QHashOut::<F>::from_values(1, 2, 3, 4);
        CommandResult::TreeRoot(TreeRootResult { root }).write_to_file(&path).unwrap();

        let value: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(value, serde_json::to_value(TreeRootResult { root }).unwrap());
        assert!(value.get("root").is_some());
        assert!(value.get("command").is_none());

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failed_command_cannot_leave_stale_success() {
        let dir = temp_dir("stale");
        let path = dir.join("result.json");
        std::fs::write(&path, br#"{"success":true}"#).unwrap();
        {
            let _guard = ResultFileGuard::prepare(Some(path.clone())).unwrap();
            assert!(!path.exists());
            std::fs::write(&path, br#"{"success":true}"#).unwrap();
        }
        assert!(!path.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn atomic_write_failure_removes_its_temp_file() {
        let dir = temp_dir("temp-cleanup");
        let target_directory = dir.join("result.json");
        std::fs::create_dir(&target_directory).unwrap();
        write_json_atomically(&target_directory, &serde_json::json!({"success": true})).unwrap_err();
        let leftovers = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(".result.json.tmp."))
            .count();
        assert_eq!(leftovers, 0);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
