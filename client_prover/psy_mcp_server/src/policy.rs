//! Spending-policy gate — "agents pay, humans control."
//!
//! The human sets a policy (per-tx / daily / total caps, recipient + method
//! allowlists, session TTL) up front; the agent presents a short-TTL session
//! token to every fund-moving tool. `authorize()` enforces every check BELOW
//! the model — a prompt-injected agent cannot exceed its budget or pay a
//! non-allowlisted recipient because the guard is not in the model's
//! discretion. Mirrors the shipped policy engines
//! (mode-a-web-wallet-bridge/src/agent/policy, psy-agent-pay) adapted to the
//! native WalletSession, whose key is held by the session process and never
//! exposed to the agent.
//!
//! Amounts are in Nano (the chain's raw unit) throughout.

use std::collections::HashMap;

use rand::RngCore;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn day_index() -> u64 {
    now_secs() / 86_400
}

#[derive(Clone, Debug)]
pub struct Limits {
    pub per_transaction: u64,
    pub per_day: u64,
    pub total_budget: Option<u64>,
}

impl Default for Limits {
    fn default() -> Self {
        // Conservative defaults (Nano). 1 PSY = 1e9 Nano.
        Self {
            per_transaction: 5_000_000_000,
            per_day: 50_000_000_000,
            total_budget: None,
        }
    }
}

#[derive(Clone, Debug)]
struct Policy {
    agent_id: String,
    limits: Limits,
    allowed_recipients: Vec<String>, // empty = any
    allowed_methods: Vec<String>,
    active: bool,
    spent_today: u64,
    spent_total: u64,
    last_day: u64,
}

#[derive(Clone, Debug)]
struct Session {
    policy_id: String,
    expires_at: u64,
}

/// Returned on a successful `authorize()`. The fields identify the approving
/// policy/agent for callers that log or audit the decision.
#[derive(Debug)]
#[allow(dead_code)]
pub struct Authorization {
    pub policy_id: String,
    pub agent_id: String,
}

pub struct PolicyEngine {
    policies: HashMap<String, Policy>,
    sessions: HashMap<String, Session>,
}

fn rand_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
            sessions: HashMap::new(),
        }
    }

    pub fn create_policy(&mut self, agent_id: &str, limits: Limits, allowed_recipients: Vec<String>, allowed_methods: Vec<String>) -> String {
        let id = rand_hex(8);
        let methods = if allowed_methods.is_empty() {
            vec!["simple_transfer".into(), "private_transfer".into(), "simple_claim".into()]
        } else {
            allowed_methods
        };
        self.policies.insert(
            id.clone(),
            Policy {
                agent_id: agent_id.to_string(),
                limits,
                allowed_recipients,
                allowed_methods: methods,
                active: true,
                spent_today: 0,
                spent_total: 0,
                last_day: day_index(),
            },
        );
        id
    }

    pub fn issue_session(&mut self, policy_id: &str, ttl_minutes: u64) -> anyhow::Result<(String, u64)> {
        let policy = self.policies.get(policy_id).ok_or_else(|| anyhow::anyhow!("policy not found"))?;
        if !policy.active {
            anyhow::bail!("policy is paused");
        }
        let token = rand_hex(32);
        let expires_at = now_secs() + ttl_minutes * 60;
        self.sessions.insert(
            token.clone(),
            Session {
                policy_id: policy_id.to_string(),
                expires_at,
            },
        );
        Ok((token, expires_at))
    }

    pub fn pause(&mut self, policy_id: &str) -> bool {
        if let Some(p) = self.policies.get_mut(policy_id) {
            p.active = false;
            true
        } else {
            false
        }
    }
    pub fn resume(&mut self, policy_id: &str) -> bool {
        if let Some(p) = self.policies.get_mut(policy_id) {
            p.active = true;
            true
        } else {
            false
        }
    }
    pub fn revoke(&mut self, token: &str) -> bool {
        self.sessions.remove(token).is_some()
    }

    fn rollover(policy: &mut Policy) {
        let today = day_index();
        if policy.last_day != today {
            policy.spent_today = 0;
            policy.last_day = today;
        }
    }

    /// Non-mutating budget view for `check_budget`.
    pub fn budget(&mut self, token: &str) -> Option<(u64, Option<u64>, u64)> {
        let policy_id = self.sessions.get(token)?.policy_id.clone();
        let policy = self.policies.get_mut(&policy_id)?;
        Self::rollover(policy);
        let remaining_day = policy.limits.per_day.saturating_sub(policy.spent_today);
        let remaining_total = policy.limits.total_budget.map(|t| t.saturating_sub(policy.spent_total));
        Some((remaining_day, remaining_total, policy.limits.per_transaction))
    }

    /// Authorize a spend below the model. Records the spend on approval;
    /// returns a human-readable reason on any denial. This is the security
    /// boundary.
    pub fn authorize(&mut self, token: &str, recipient: &str, amount: u64, method: &str) -> anyhow::Result<Authorization> {
        let session = self.sessions.get(token).ok_or_else(|| anyhow::anyhow!("invalid session token"))?.clone();
        if now_secs() > session.expires_at {
            self.sessions.remove(token);
            anyhow::bail!("session expired");
        }
        let policy = self
            .policies
            .get_mut(&session.policy_id)
            .ok_or_else(|| anyhow::anyhow!("policy not found"))?;
        if !policy.active {
            anyhow::bail!("policy paused by owner");
        }
        if !policy.allowed_methods.iter().any(|m| m == method) {
            anyhow::bail!("method `{method}` not allowed (allowed: {})", policy.allowed_methods.join(", "));
        }
        if !policy.allowed_recipients.is_empty() && !policy.allowed_recipients.iter().any(|r| r == recipient) {
            anyhow::bail!("recipient `{recipient}` not in the allowlist");
        }
        Self::rollover(policy);
        if amount > policy.limits.per_transaction {
            anyhow::bail!("amount {amount} exceeds per-transaction cap {}", policy.limits.per_transaction);
        }
        if policy.spent_today + amount > policy.limits.per_day {
            anyhow::bail!(
                "would exceed the daily cap ({} + {amount} > {})",
                policy.spent_today,
                policy.limits.per_day
            );
        }
        if let Some(total) = policy.limits.total_budget {
            if policy.spent_total + amount > total {
                anyhow::bail!("would exceed the total budget ({} + {amount} > {total})", policy.spent_total);
            }
        }
        policy.spent_today += amount;
        policy.spent_total += amount;
        Ok(Authorization {
            policy_id: session.policy_id.clone(),
            agent_id: policy.agent_id.clone(),
        })
    }
}
