//! Agent accounts backed by Software-Defined Keys (SDKeys).
//!
//! Psy's agent model (https://psy.xyz/ai-agents) is that an agent's *key is a ZK
//! circuit defining its operational logic* — the guardrail lives inside the
//! identity rather than in code wrapped around it. This module builds the
//! **mandate**: the set of (contract, method) capabilities compiled into that
//! circuit.
//!
//! Why this is stronger than the policy engine in `policy.rs`: `policy.rs` is an
//! off-chain gate that *declines* to sign a disallowed call, and is only as
//! strong as the process boundary around it. A mandate is enforced by the
//! circuit, so a call outside it is **unprovable** — there is no valid proof to
//! submit, and the guarantee survives compromise of this process. The two are
//! complementary: the mandate fixes *what kinds of call* are possible at all, the
//! policy engine bounds *how much value* may move (which the circuit cannot yet
//! express — see `Mandate::LIMITS_NOTE`).
//!
//! ## Semantics of the underlying circuit (verified against
//! `psy_prover::wallet::memory_wallet::build_allow_method_sd_key_circuit`)
//!
//! * The circuit asserts, for every call in the transaction, that its
//!   `(contract_id, method_id)` is one of the allowed pairs.
//! * `expected_tx_count` is `num_introspectable_transactions`: the number of
//!   contract calls in ONE signed transaction, and it is connected by
//!   **equality** (`connect(get_tx_count(), expected_tx_count)`) — not an upper
//!   bound. A transaction with a different number of calls cannot satisfy the
//!   circuit. It is therefore a transaction *shape*, not a lifetime budget.
//! * Pair construction in the engine is positional when the two lists are the
//!   same length, so we always emit equal-length parallel vectors: the pairs we
//!   ask for are exactly the pairs compiled in.
//!
//! Because the identity is derived from `(private_key, circuit_fingerprint)`, a
//! different mandate is a different account. Widening an agent's powers means
//! minting a new account, which is the intended property: an agent's authority
//! cannot be edited in place.

use std::collections::BTreeSet;

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};

/// One capability: permission to call `method_name` on `contract_id`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Capability {
    pub contract_id: u64,
    pub method_name: String,
    pub method_id: u32,
}

/// The mandate compiled into an agent's identity circuit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Mandate {
    /// Exactly what the agent may call. Anything else is unprovable.
    pub capabilities: Vec<Capability>,
    /// Number of contract calls per transaction, enforced by EQUALITY.
    pub calls_per_transaction: u64,
    /// The circuit fingerprint — this is the mandate's public, auditable identity.
    pub circuit_fingerprint: String,
}

impl Mandate {
    /// What the circuit cannot express today. Kept next to the data so callers
    /// that surface a mandate also surface its limits.
    pub const LIMITS_NOTE: &'static str = "The circuit constrains which (contract, method) calls are possible and how many \
         calls a transaction contains. It does NOT constrain amounts, recipients or \
         expiry — those remain operational limits enforced by this server's policy \
         engine, not by the chain.";

    /// Parallel vectors in the shape the engine's pair builder expects.
    pub fn as_engine_inputs(&self) -> (Vec<u64>, Vec<u32>) {
        self.capabilities.iter().map(|c| (c.contract_id, c.method_id)).unzip()
    }
}

/// A requested capability before its method id has been resolved on-chain.
#[derive(Clone, Debug)]
pub struct CapabilityRequest {
    pub contract_id: u64,
    pub method_name: String,
}

/// Parse `["0:simple_transfer", "4:simple_claim"]` into capability requests.
///
/// The `contract_id:method_name` form keeps the pairing explicit — a bare list of
/// contracts plus a bare list of methods would be ambiguous about which method
/// belongs to which contract, and the engine would silently cross-product it.
pub fn parse_capability_requests(specs: &[String]) -> Result<Vec<CapabilityRequest>> {
    if specs.is_empty() {
        bail!("a mandate needs at least one capability, e.g. \"0:simple_transfer\"");
    }
    let mut out = Vec::with_capacity(specs.len());
    for spec in specs {
        let (contract, method) = spec
            .split_once(':')
            .ok_or_else(|| anyhow!("capability `{spec}` must be `contract_id:method_name`, e.g. \"0:simple_transfer\""))?;
        let contract_id: u64 = contract
            .trim()
            .parse()
            .map_err(|_| anyhow!("capability `{spec}` has a non-numeric contract id `{contract}`"))?;
        let method_name = method.trim();
        if method_name.is_empty() {
            bail!("capability `{spec}` has an empty method name");
        }
        out.push(CapabilityRequest { contract_id, method_name: method_name.to_string() });
    }
    Ok(out)
}

/// Drop duplicate capabilities, preserving first-seen order.
///
/// Duplicates would enlarge the circuit without widening authority, and two
/// requests that differ only by repetition should yield the same account rather
/// than two identities with the same powers.
pub fn dedupe(capabilities: Vec<Capability>) -> Vec<Capability> {
    let mut seen = BTreeSet::new();
    capabilities
        .into_iter()
        .filter(|c| seen.insert((c.contract_id, c.method_id)))
        .collect()
}

/// Reject a mandate the circuit builder would refuse, with a better message than
/// the engine's, and before any network or proving work is done.
pub fn validate(capabilities: &[Capability], calls_per_transaction: u64) -> Result<()> {
    if capabilities.is_empty() {
        bail!("a mandate needs at least one capability");
    }
    if calls_per_transaction == 0 {
        bail!("calls_per_transaction must be at least 1");
    }
    if calls_per_transaction > u32::MAX as u64 {
        bail!("calls_per_transaction {calls_per_transaction} exceeds the u32 range the circuit supports");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(contract_id: u64, method_id: u32) -> Capability {
        Capability { contract_id, method_name: format!("m{method_id}"), method_id }
    }

    #[test]
    fn parses_contract_method_pairs() {
        let reqs = parse_capability_requests(&["0:simple_transfer".into(), " 4 : simple_claim ".into()]).unwrap();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].contract_id, 0);
        assert_eq!(reqs[0].method_name, "simple_transfer");
        assert_eq!(reqs[1].contract_id, 4);
        assert_eq!(reqs[1].method_name, "simple_claim", "surrounding whitespace must be trimmed");
    }

    #[test]
    fn rejects_malformed_capabilities() {
        assert!(parse_capability_requests(&[]).is_err(), "empty mandate");
        assert!(parse_capability_requests(&["simple_transfer".into()]).is_err(), "missing contract id");
        assert!(parse_capability_requests(&["x:simple_transfer".into()]).is_err(), "non-numeric contract id");
        assert!(parse_capability_requests(&["0:".into()]).is_err(), "empty method name");
    }

    /// The engine pairs positionally when the two lists are the same length, so
    /// the vectors we emit must line up index-for-index with our capabilities.
    #[test]
    fn engine_inputs_are_positionally_paired() {
        let mandate = Mandate {
            capabilities: vec![cap(0, 3), cap(4, 7)],
            calls_per_transaction: 1,
            circuit_fingerprint: "fp".into(),
        };
        let (contracts, methods) = mandate.as_engine_inputs();
        assert_eq!(contracts, vec![0, 4]);
        assert_eq!(methods, vec![3, 7]);
        assert_eq!(contracts.len(), methods.len(), "equal lengths keep the engine on its zip path");
    }

    #[test]
    fn dedupe_preserves_order_and_removes_repeats() {
        let out = dedupe(vec![cap(0, 3), cap(4, 7), cap(0, 3)]);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].method_id, 3);
        assert_eq!(out[1].method_id, 7);
    }

    #[test]
    fn validate_rejects_what_the_circuit_would() {
        assert!(validate(&[], 1).is_err(), "no capabilities");
        assert!(validate(&[cap(0, 3)], 0).is_err(), "zero calls");
        assert!(validate(&[cap(0, 3)], u32::MAX as u64 + 1).is_err(), "beyond u32");
        assert!(validate(&[cap(0, 3)], 1).is_ok());
    }
}

#[cfg(test)]
mod fingerprint_derivation {
    //! Diagnostic: recover the parameters a deployed SDKey account was minted
    //! with, by searching for the ones that reproduce its recorded fingerprint.
    //! Ignored by default (each circuit build takes ~10s).
    use psy_prover::wallet::memory_wallet::get_allow_method_sd_key_fingerprint;

    const OPERATOR_FINGERPRINT: &str = "ade963d92bbf8772d671fd90a15e00e34897fc3ef6733dc588e1976ebfd222e0";

    #[test]
    #[ignore]
    fn recover_faucet_operator_params() {
        let contract_id = 5u64;
        let method_id = 3375543263u32;
        for tx_count in 1u64..=8 {
            let fp = get_allow_method_sd_key_fingerprint(&[contract_id], &[method_id], tx_count)
                .expect("circuit builds")
                .to_string();
            let fp = fp.trim_start_matches("0x").to_string();
            let hit = fp == OPERATOR_FINGERPRINT;
            println!("tx_count={tx_count} -> {fp}{}", if hit { "   <== MATCH" } else { "" });
            if hit {
                return;
            }
        }
        println!("no tx_count in 1..=8 reproduces {OPERATOR_FINGERPRINT} for contract {contract_id} method {method_id}");
    }
}
