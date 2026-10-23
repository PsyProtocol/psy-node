//! Wire types of the Reader's internal HTTP/JSON API.
//!
//! Field names are the JSON names. All hashes are display hex (P6).
//! Exactly-one-of rules are documented here and enforced by the server.

use serde::{Deserialize, Serialize};

/// Request header that carries the caller's [`Lane`].
pub const LANE_HEADER: &str = "x-psy-lane";

/// Maximum page size of a paged query.
pub const MAX_PAGE: u32 = 1000;
/// Maximum number of nullifiers in one [`WithdrawalClaimsRequest`].
pub const MAX_NULLIFIERS: usize = 1000;
/// Number of rows of each kind in an [`ExplorerResponse`].
pub const FEED_LEN: usize = 100;
/// Maximum number of rows in a [`DepositsByTxResponse`].
pub const MAX_BY_TX: usize = 10;
/// Depth of the deposit tree; a proof has this many siblings.
pub const TREE_DEPTH: u8 = 32;

/// The view a response was read from.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Revision {
    pub epoch: u64,
    pub seq: u64,
    pub as_of_unix_ms: u64,
}

/// Admission lane of a request, sent in [`LANE_HEADER`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lane {
    BridgeProgress,
    ClaimProof,
    Interactive,
    Background,
}

impl Lane {
    pub const ALL: [Lane; 4] = [Lane::BridgeProgress, Lane::ClaimProof, Lane::Interactive, Lane::Background];

    /// The wire name, identical to the serde name.
    pub fn as_str(self) -> &'static str {
        match self {
            Lane::BridgeProgress => "bridge_progress",
            Lane::ClaimProof => "claim_proof",
            Lane::Interactive => "interactive",
            Lane::Background => "background",
        }
    }

    /// Parses a wire name; `None` for anything else.
    pub fn parse(s: &str) -> Option<Lane> {
        Lane::ALL.into_iter().find(|l| l.as_str() == s)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DepositRow {
    pub id: String,
    pub chain_id: u64,
    pub chain_index: u64,
    pub deposit_index: u64,
    pub chain_local_deposit_index: u64,
    pub shield_address: String,
    pub token: String,
    pub l2_token_contract_id: String,
    pub amount: String,
    pub note_commitment: String,
    pub leaf_hash: String,
    pub block_number: u64,
    pub block_timestamp: u64,
    pub tx_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WithdrawalClaimRow {
    pub id: String,
    pub chain_id: u64,
    pub nullifier: String,
    pub recipient: String,
    pub token: String,
    pub amount: String,
    pub block_number: u64,
    pub tx_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FinalizedBatchRow {
    pub id: String,
    pub chain_id: u64,
    pub finalized_checkpoint_id: String,
    pub deposit_tree_root: String,
    pub withdrawal_tree_root: String,
    pub block_number: u64,
    pub tx_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusResponse {
    pub revision: Revision,
    pub ready: bool,
    pub chains: Vec<ChainStatus>,
    pub envio_chains: Vec<EnvioChainStatus>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChainStatus {
    pub chain_index: u64,
    pub chain_id: u64,
    pub ready: bool,
    pub not_ready_reason: Option<String>,
    pub deposit_count: u64,
    pub committed_count: u64,
    pub envio_tree_count: u64,
    pub envio_tree_root: String,
    pub tree_root: String,
    pub last_verified_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnvioChainStatus {
    pub chain_id: u64,
    pub progress_block: u64,
    pub max_reorg_depth: u64,
    pub safe_block: u64,
    pub committed_safe_block: u64,
    pub ready: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DepositsByAddressQuery {
    pub shield_address: String,
    pub chain_id: u64,
    pub chain_index: Option<u64>,
    pub limit: u32,
    pub offset: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DepositsByAddressResponse {
    pub revision: Revision,
    pub total: u64,
    /// `"{epoch}-{total}-{last_deposit_index}"`, or `"{epoch}-0-none"` when
    /// there are no rows. It changes only when this query's result can change.
    pub list_tag: String,
    pub rows: Vec<DepositRow>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DepositByIndexQuery {
    pub chain_index: u64,
    pub chain_id: u64,
    pub deposit_index: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DepositByIndexResponse {
    pub revision: Revision,
    pub deposit: Option<DepositRow>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DepositsByTxQuery {
    pub tx_hash: String,
    pub chain_index: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DepositsByTxResponse {
    pub revision: Revision,
    pub rows: Vec<DepositRow>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrefixQuery {
    pub chain_index: u64,
    pub chain_id: u64,
    pub target_deposit_count: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrefixResponse {
    pub revision: Revision,
    pub chain_local_count: u64,
    pub has_foreign_deposits: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithdrawalClaimsRequest {
    pub chain_id: u64,
    pub nullifiers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WithdrawalClaimsResponse {
    pub revision: Revision,
    pub claims: Vec<WithdrawalClaimRow>,
}

/// Takes exactly one of `count` (chain-local) or `target_deposit_count` +
/// `chain_id` (global, resolved through the prefix probe in the same view).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeRootQuery {
    pub chain_index: u64,
    pub count: Option<u64>,
    pub target_deposit_count: Option<u64>,
    pub chain_id: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TreeRootResponse {
    pub revision: Revision,
    pub chain_local_count: u64,
    pub has_foreign_deposits: bool,
    pub root: String,
}

/// Takes exactly one of `count` (chain-local) or `target_deposit_count` +
/// `chain_id` (global, resolved through the prefix probe in the same view),
/// and exactly one of `leaf` (chain-local) or `deposit_index` + `chain_id`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimProofQuery {
    pub chain_index: u64,
    pub leaf: Option<u64>,
    pub deposit_index: Option<u64>,
    pub chain_id: Option<u64>,
    pub count: Option<u64>,
    pub target_deposit_count: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimProofResponse {
    pub revision: Revision,
    pub chain_local_count: u64,
    pub has_foreign_deposits: bool,
    pub deposit: Option<DepositRow>,
    /// `null` when the deposit is absent or when
    /// `leaf_index >= chain_local_count`.
    pub proof: Option<DepositProof>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DepositProof {
    pub leaf_index: u64,
    pub leaf_hash: String,
    /// Exactly [`TREE_DEPTH`] (32) entries, bottom-up. The leaf is not included.
    pub siblings: Vec<String>,
    pub root: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExplorerQuery {
    pub chain_id: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExplorerResponse {
    pub revision: Revision,
    pub deposits: Vec<DepositRow>,
    pub batches: Vec<FinalizedBatchRow>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    BadRequest,
    Unauthorized,
    CountNotIndexed,
    NotReady,
    Overloaded,
    Timeout,
    SchemaMismatch,
    Unavailable,
    Internal,
}

impl ErrorCode {
    pub const ALL: [ErrorCode; 9] = [
        ErrorCode::BadRequest,
        ErrorCode::Unauthorized,
        ErrorCode::CountNotIndexed,
        ErrorCode::NotReady,
        ErrorCode::Overloaded,
        ErrorCode::Timeout,
        ErrorCode::SchemaMismatch,
        ErrorCode::Unavailable,
        ErrorCode::Internal,
    ];

    /// The wire name, identical to the serde name.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::Unauthorized => "unauthorized",
            ErrorCode::CountNotIndexed => "count_not_indexed",
            ErrorCode::NotReady => "not_ready",
            ErrorCode::Overloaded => "overloaded",
            ErrorCode::Timeout => "timeout",
            ErrorCode::SchemaMismatch => "schema_mismatch",
            ErrorCode::Unavailable => "unavailable",
            ErrorCode::Internal => "internal",
        }
    }

    pub fn http_status(self) -> u16 {
        match self {
            ErrorCode::BadRequest => 400,
            ErrorCode::Unauthorized => 401,
            ErrorCode::CountNotIndexed => 409,
            ErrorCode::NotReady
            | ErrorCode::Overloaded
            | ErrorCode::Timeout
            | ErrorCode::SchemaMismatch
            | ErrorCode::Unavailable => 503,
            ErrorCode::Internal => 500,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: ErrorCode,
    pub message: String,
    pub retry_after_seconds: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_map_to_http_status() {
        assert_eq!(ErrorCode::BadRequest.http_status(), 400);
        assert_eq!(ErrorCode::Unauthorized.http_status(), 401);
        assert_eq!(ErrorCode::CountNotIndexed.http_status(), 409);
        for c in [ErrorCode::NotReady, ErrorCode::Overloaded, ErrorCode::Timeout, ErrorCode::SchemaMismatch, ErrorCode::Unavailable] {
            assert_eq!(c.http_status(), 503);
        }
        assert_eq!(ErrorCode::Internal.http_status(), 500);
    }

    #[test]
    fn wire_names_are_snake_case_and_stable() {
        let body = ErrorBody { code: ErrorCode::CountNotIndexed, message: "m".into(), retry_after_seconds: Some(1) };
        assert_eq!(serde_json::to_string(&body).unwrap(), r#"{"code":"count_not_indexed","message":"m","retry_after_seconds":1}"#);
        assert_eq!(serde_json::to_string(&Lane::BridgeProgress).unwrap(), r#""bridge_progress""#);
    }

    #[test]
    fn a_missing_deposit_serializes_as_null() {
        let r = DepositByIndexResponse { revision: Revision { epoch: 1, seq: 2, as_of_unix_ms: 3 }, deposit: None };
        assert_eq!(serde_json::to_string(&r).unwrap(), r#"{"revision":{"epoch":1,"seq":2,"as_of_unix_ms":3},"deposit":null}"#);
    }

    #[test]
    fn unknown_query_fields_are_rejected() {
        let ok = r#"{"chain_id":1}"#;
        assert!(serde_json::from_str::<ExplorerQuery>(ok).is_ok());
        let typo = r#"{"chain_id":1,"chain_idx":2}"#;
        assert!(serde_json::from_str::<ExplorerQuery>(typo).is_err());
        let tree = r#"{"chain_index":0,"count":5,"chain_idx":2}"#;
        assert!(serde_json::from_str::<TreeRootQuery>(tree).is_err());
        let claims = r#"{"chain_id":1,"nullifiers":[],"nullifier":[]}"#;
        assert!(serde_json::from_str::<WithdrawalClaimsRequest>(claims).is_err());
        assert!(serde_json::from_str::<WithdrawalClaimsRequest>(r#"{"chain_id":1,"nullifiers":[]}"#).is_ok());
    }

    #[test]
    fn lane_and_code_names_match_serde() {
        for lane in Lane::ALL {
            assert_eq!(serde_json::to_value(lane).unwrap(), serde_json::Value::String(lane.as_str().into()));
            assert_eq!(Lane::parse(lane.as_str()), Some(lane));
        }
        assert_eq!(Lane::parse("bogus"), None);
        for code in ErrorCode::ALL {
            assert_eq!(serde_json::to_value(code).unwrap(), serde_json::Value::String(code.as_str().into()));
        }
        // ALL lists every variant: this match fails to compile if one is added.
        for code in ErrorCode::ALL {
            match code {
                ErrorCode::BadRequest | ErrorCode::Unauthorized | ErrorCode::CountNotIndexed | ErrorCode::NotReady
                | ErrorCode::Overloaded | ErrorCode::Timeout | ErrorCode::SchemaMismatch | ErrorCode::Unavailable
                | ErrorCode::Internal => {}
            }
        }
    }
}
