//! How many times a withdrawal claim is retried before it is given up on.
//!
//! Every failure used to mean "retry next round, forever". The pending set is
//! durable, so a withdrawal that could never be claimed was re-attempted every
//! round and across restarts — and an attempt asks prove-proxy for a Groth16
//! batch proof. One bad withdrawal burned prover time indefinitely. That is
//! what happened in production, with a withdrawal whose recipient was all
//! zeroes and whose destination chain index was not ours; Bridge.sol reverts
//! both before it touches the token, so no number of retries could have helped.
//!
//! The rule is a count and nothing else: try, retry twice, give up. Only an
//! `AttemptSpent` outcome spends one of those three. A terminal payload is
//! retired on sight, and a hold (operator state, or a claim transaction whose
//! landing is unknown) spends nothing.
//!
//! Giving up is not discarding. The funds are genuinely stuck and need a
//! person, so the withdrawal and its last failure reason move to a retired set
//! and are logged at error level.
//!
//! Two things make a plain count safe enough without any backoff:
//!
//! * A round already absorbs short outages on its own. `claim_withdrawals`
//!   polls psy-services for the claim proof 12 times at 5s intervals before it
//!   reports failure, so a minute of unavailability costs no attempts at all.
//! * Waiting for bridge liquidity, a proof, a fee quote, or an operator change
//!   is reported as a hold rather than a failure, so a withdrawal parked behind
//!   one of those does not spend its attempts while it waits.

use std::collections::HashMap;

use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

use crate::bridge::claim_withdrawals::ClaimCode;

/// Is `saved` the same claim as `withdrawal`?
///
/// The pending queue is keyed by the full leaf hash and the leaf binds the
/// payload. `event_id` is append ordering on the source chain, not claim
/// content: an imported row carries `0` where a replayed event carries the
/// real index, so it is not a content difference and is not compared.
pub fn same_claim(saved: &crate::bridge::propose_withdrawals::PendingWithdrawal, withdrawal: &crate::bridge::propose_withdrawals::PendingWithdrawal) -> bool {
    saved.destination_chain_index == withdrawal.destination_chain_index
        && saved.sender_user_id == withdrawal.sender_user_id
        && saved.contract_id == withdrawal.contract_id
        && saved.token_address == withdrawal.token_address
        && saved.amount == withdrawal.amount
        && saved.recipient == withdrawal.recipient
        && saved.nonce == withdrawal.nonce
        && saved.leaf_hash == withdrawal.leaf_hash
}

/// Attempts before a claim is retired: the first try plus two retries.
pub const CLAIM_MAX_ATTEMPTS: u32 = 3;

/// Why a leaf is held out of the claim batch without spending an attempt.
///
/// `None` is a leaf with no hold. `OperatorPending` names the chain condition
/// that has to clear. `ReceiptUnknown` names the one transaction whose landing
/// is unresolved; `tx_hash: None` means the send never produced a hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClaimHold {
    None,
    OperatorPending(ClaimCode),
    ReceiptUnknown { tx_hash: Option<B256> },
}

impl Default for ClaimHold {
    fn default() -> Self {
        Self::None
    }
}

/// The one durable record per leaf. Attempts, the last reason, and any hold
/// live here and nowhere else.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimAttempts {
    #[serde(default)]
    pub attempts: u32,
    /// Why the last attempt failed, carried into the retired set so whoever
    /// picks it up has something to work from.
    #[serde(default)]
    pub last_reason: String,
    /// Absent in rows written before holds existed, which decode as no hold.
    #[serde(default)]
    pub hold: ClaimHold,
}

impl Default for ClaimAttempts {
    fn default() -> Self {
        Self { attempts: 0, last_reason: String::new(), hold: ClaimHold::None }
    }
}

/// A withdrawal that has used up its attempts, or whose payload can never
/// succeed. Nothing retries these.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetiredClaim<W> {
    pub withdrawal: W,
    pub attempts: u32,
    pub last_reason: String,
    pub retired_at_unix: u64,
}

pub fn is_exhausted(state: &ClaimAttempts) -> bool {
    state.attempts >= CLAIM_MAX_ATTEMPTS
}

/// Should this withdrawal be handed to the claim path again?
///
/// A hold is not exhaustion: the leaf stays pending, but it is not due until
/// the hold is cleared by the send gate.
pub fn is_retriable(state: Option<&ClaimAttempts>) -> bool {
    match state {
        Some(state) => !is_exhausted(state) && matches!(state.hold, ClaimHold::None),
        None => true,
    }
}

pub fn record_failure(
    attempts: &mut HashMap<String, ClaimAttempts>,
    leaf_hash: &str,
    reason: &str,
) -> ClaimAttempts {
    let entry = attempts.entry(leaf_hash.to_string()).or_default();
    entry.attempts = entry.attempts.saturating_add(1);
    entry.last_reason = reason.to_string();
    entry.hold = ClaimHold::None;
    entry.clone()
}

/// Record the chain condition that keeps this leaf out of the batch.
///
/// The attempt count is untouched: an operator hold is not a failed claim.
pub fn hold_for_operator(
    attempts: &mut HashMap<String, ClaimAttempts>,
    leaf_hash: &str,
    code: ClaimCode,
) {
    let entry = attempts.entry(leaf_hash.to_string()).or_default();
    entry.hold = ClaimHold::OperatorPending(code);
    entry.last_reason = code.label().to_string();
}

/// Record the one transaction whose landing this leaf is waiting on.
///
/// `tx_hash: None` is a send that produced no hash. That leaf stays held and
/// is never retried: there is no transaction to reconcile. A later report that
/// also has no hash must not erase one already recorded.
pub fn hold_for_receipt(
    attempts: &mut HashMap<String, ClaimAttempts>,
    leaf_hash: &str,
    tx_hash: Option<B256>,
) {
    let entry = attempts.entry(leaf_hash.to_string()).or_default();
    let kept = tx_hash.or(match entry.hold {
        ClaimHold::ReceiptUnknown { tx_hash } => tx_hash,
        _ => None,
    });
    entry.hold = ClaimHold::ReceiptUnknown { tx_hash: kept };
    entry.last_reason = ClaimCode::ReceiptUnknown.label().to_string();
}

/// Drop a hold without touching the attempt count, once its condition cleared
/// or its transaction was reconciled.
pub fn release_hold(attempts: &mut HashMap<String, ClaimAttempts>, leaf_hash: &str) {
    if let Some(entry) = attempts.get_mut(leaf_hash) {
        entry.hold = ClaimHold::None;
        if entry.attempts == 0 && entry.last_reason.is_empty() {
            attempts.remove(leaf_hash);
        }
    }
}

/// Forget a withdrawal's history, after it is claimed or retired.
pub fn clear(attempts: &mut HashMap<String, ClaimAttempts>, leaf_hash: &str) {
    attempts.remove(leaf_hash);
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_withdrawal_that_has_never_failed_is_retriable() {
        assert!(is_retriable(None));
    }

    #[test]
    fn the_first_try_and_two_retries_are_allowed_and_no_more() {
        let mut attempts = HashMap::new();
        for n in 1..CLAIM_MAX_ATTEMPTS {
            record_failure(&mut attempts, "leaf", "nope");
            assert!(is_retriable(attempts.get("leaf")), "gave up after {n} attempt(s)");
        }
        record_failure(&mut attempts, "leaf", "nope");
        assert_eq!(attempts["leaf"].attempts, CLAIM_MAX_ATTEMPTS);
        assert!(!is_retriable(attempts.get("leaf")));
    }

    #[test]
    fn the_last_reason_is_kept_for_whoever_has_to_look() {
        let mut attempts = HashMap::new();
        record_failure(&mut attempts, "leaf", "first");
        record_failure(&mut attempts, "leaf", "second");
        assert_eq!(attempts["leaf"].last_reason, "second");
    }

    #[test]
    fn a_successful_claim_forgets_the_history() {
        let mut attempts = HashMap::new();
        record_failure(&mut attempts, "leaf", "transient");
        clear(&mut attempts, "leaf");
        assert!(is_retriable(attempts.get("leaf")));
    }

    #[test]
    fn a_hold_keeps_the_leaf_out_without_spending_an_attempt() {
        let mut attempts = HashMap::new();
        record_failure(&mut attempts, "leaf", "first");
        hold_for_operator(&mut attempts, "leaf", ClaimCode::RegistrationPaused);
        assert_eq!(attempts["leaf"].attempts, 1, "a hold must not count");
        assert!(!is_retriable(attempts.get("leaf")), "a held leaf is not due");

        release_hold(&mut attempts, "leaf");
        assert!(is_retriable(attempts.get("leaf")));
        assert_eq!(attempts["leaf"].attempts, 1, "releasing a hold keeps the history");
    }

    #[test]
    fn a_receipt_hold_without_a_hash_is_not_due() {
        let mut attempts = HashMap::new();
        hold_for_receipt(&mut attempts, "leaf", None);
        assert!(!is_retriable(attempts.get("leaf")));
        assert_eq!(attempts["leaf"].attempts, 0);
    }

    #[test]
    fn a_later_hashless_hold_keeps_the_recorded_hash() {
        let mut attempts = HashMap::new();
        let hash = B256::repeat_byte(0x11);
        hold_for_receipt(&mut attempts, "leaf", Some(hash));
        hold_for_receipt(&mut attempts, "leaf", None);
        assert!(matches!(
            attempts["leaf"].hold,
            ClaimHold::ReceiptUnknown { tx_hash: Some(kept) } if kept == hash
        ));
    }

    #[test]
    fn a_row_written_before_holds_existed_decodes_as_no_hold() {
        let old = r#"{"attempts":2,"last_reason":"proof late"}"#;
        let state: ClaimAttempts = serde_json::from_str(old).unwrap();
        assert_eq!(state.hold, ClaimHold::None);
        assert!(is_retriable(Some(&state)));
    }
}
