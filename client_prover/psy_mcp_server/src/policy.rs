//! Spending-policy gate — "agents pay, humans control."
//!
//! The human sets a policy (per-tx / daily / monthly / total caps, recipient +
//! method allowlists, session TTL) up front; the agent presents a short-TTL
//! session token to every fund-moving tool. `authorize()` enforces every check
//! BELOW the model — a prompt-injected agent cannot exceed its budget or pay a
//! non-allowlisted recipient because the guard is not in the model's discretion.
//! Mirrors the shipped policy engines (mode-a-web-wallet-bridge/src/agent/policy,
//! psy-agent-pay) adapted to the native WalletSession, whose key is held by the
//! session process and never exposed to the agent.
//!
//! Every authorized spend is also recorded in an in-memory ring (`spend_log`),
//! so an owner can answer "what did my agent actually do" from the server that
//! made the decisions rather than from the indexer, which only sees settled
//! transactions and never sees an intent that was denied or failed to submit.
//!
//! Amounts are in Nano (the chain's raw unit) throughout.

use anyhow::anyhow;
use rand::RngCore;
use std::collections::{HashMap, VecDeque};

/// Recipient sentinel for operations that move funds INTO this wallet (claims,
/// deposits). They are gated for pause/method/cap purposes but are deliberately
/// exempt from the recipient allowlist: the allowlist answers "who may receive
/// this agent's money", and the answer for a claim is "nobody — it is ours".
/// Without this exemption, setting any allowlist would silently break claiming.
pub const SELF_RECIPIENT: &str = "self";

/// Upper bound on payments in one batch. Not a protocol limit — a conservative
/// cap so a runaway caller cannot queue an unbounded run of on-chain payments
/// behind a single approval. Raise it with evidence, not by assumption.
pub const MAX_BATCH_PAYMENTS: usize = 10;

/// How many authorized spends the audit ring keeps. Bounded on purpose: this is
/// process memory on a long-running server, and the ring is an audit aid, not
/// the ledger — the chain is.
const SPEND_LOG_CAPACITY: usize = 100;

const DAY_SECS: u64 = 86_400;
/// The "monthly" window is 30 days, tracked as a tumbling bucket exactly like
/// the daily one (see `month_index`). Calendar months are not used: they would
/// need a date library and would make the reset moment depend on the timezone.
const MONTH_SECS: u64 = 30 * DAY_SECS;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn day_index() -> u64 {
    now_secs() / DAY_SECS
}

/// Same mechanism as `day_index`, at 30-day granularity: the counter resets when
/// the bucket changes, so a policy can never spend more than `per_month` within
/// any one bucket. It is a tumbling window, not a trailing-30-days one — an
/// exact rolling window would need unbounded spend history, and the bounded
/// audit ring must not become a budget's source of truth.
fn month_index() -> u64 {
    now_secs() / MONTH_SECS
}

/// Canonical form of a recipient identifier, so that an owner writing
/// "Psy-00001234" and a tool passing user id `1234` mean the same principal.
///
/// Handles the four shapes a Psy payee is named by:
///   * URL (an x402 seller)      → bare host, port kept (`localhost:8402` and
///     `localhost:9999` are different sellers)
///   * `Psy-00001234` / `01234`  → the decimal user id, `1234`
///   * `0x<hex>` shielded address → the bare lowercase hex
///   * anything else              → trimmed + lowercased
pub fn normalize_recipient(raw: &str) -> String {
    let s = raw.trim().to_ascii_lowercase();
    if s.is_empty() {
        return s;
    }
    if let Some((_scheme, rest)) = s.split_once("://") {
        let host = rest.split(['/', '?', '#']).next().unwrap_or("");
        // Strip any userinfo (`user:pass@host`) — the host is the identity.
        let host = host.rsplit_once('@').map(|(_, h)| h).unwrap_or(host);
        return host.trim_end_matches('.').to_string();
    }
    if let Some(digits) = s.strip_prefix("psy-") {
        if let Ok(n) = digits.parse::<u128>() {
            return n.to_string();
        }
    }
    // Re-emit numbers canonically so "0001234" and "1234" collapse together.
    if let Ok(n) = s.parse::<u128>() {
        return n.to_string();
    }
    if let Some(hex) = s.strip_prefix("0x") {
        if !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return hex.to_string();
        }
    }
    s
}

/// Nano → a short human amount, for the sentences `describe()` writes.
fn fmt_psy(nano: u64) -> String {
    let whole = nano / 1_000_000_000;
    let frac = nano % 1_000_000_000;
    if frac == 0 {
        format!("{whole} PSY")
    } else {
        format!("{whole}.{} PSY", format!("{frac:09}").trim_end_matches('0'))
    }
}

/// The single source of truth for "why a spend is refused". Returns the exact
/// human, PSY-denominated sentence (or None if the spend is allowed). Both the
/// live gate and the blocked-attempt recorder call this, so the reason the
/// caller sees and the reason the owner reviews are always identical. The
/// caller must have run `rollover` first. Checks run in a fixed order —
/// paused, method, recipient, per-payment, daily, 30-day, total — and the cap
/// keywords are load-bearing (callers/tests branch on them).
fn denial_reason(policy: &Policy, recipients: &[&str], amount: u64, method: &str) -> Option<String> {
    let primary = recipients.first().copied().unwrap_or("");
    if !policy.active {
        return Some("policy paused by owner".to_string());
    }
    if !policy.allowed_methods.iter().any(|m| m == method) {
        return Some(format!("method `{method}` not allowed (allowed: {})", policy.allowed_methods.join(", ")));
    }
    // `self` is not a payee (see SELF_RECIPIENT): claims and deposits move funds
    // inward and are gated by the caps and the method list instead.
    if let Some(allowed) = policy.allowed_recipients.as_ref() {
        let inbound = recipients.iter().all(|r| *r == SELF_RECIPIENT);
        if !inbound {
            let permitted = recipients
                .iter()
                .map(|r| normalize_recipient(r))
                .any(|r| allowed.iter().any(|a| *a == r));
            if !permitted {
                return Some(format!(
                    "recipient `{primary}` is not on this policy's allowlist ({} approved recipient(s)); ask the owner to add it",
                    allowed.len()
                ));
            }
        }
    }
    if amount > policy.limits.per_transaction {
        return Some(format!(
            "this payment of {} is over the {} per-transaction cap",
            fmt_psy(amount),
            fmt_psy(policy.limits.per_transaction)
        ));
    }
    if let Some(day_sum) = policy.spent_today.checked_add(amount) {
        if day_sum > policy.limits.per_day {
            return Some(format!(
                "would exceed the daily cap: {} on top of {} already spent today is over the {} limit ({} left today)",
                fmt_psy(amount),
                fmt_psy(policy.spent_today),
                fmt_psy(policy.limits.per_day),
                fmt_psy(policy.limits.per_day.saturating_sub(policy.spent_today))
            ));
        }
    } else {
        return Some("this payment would overflow the daily spend counter".to_string());
    }
    if let Some(month) = policy.limits.per_month {
        if let Some(month_sum) = policy.spent_this_month.checked_add(amount) {
            if month_sum > month {
                return Some(format!(
                    "would exceed the 30-day cap: {} on top of {} already spent this period is over the {} limit ({} left this period)",
                    fmt_psy(amount),
                    fmt_psy(policy.spent_this_month),
                    fmt_psy(month),
                    fmt_psy(month.saturating_sub(policy.spent_this_month))
                ));
            }
        } else {
            return Some("this payment would overflow the 30-day spend counter".to_string());
        }
    }
    if let Some(total) = policy.limits.total_budget {
        if let Some(total_sum) = policy.spent_total.checked_add(amount) {
            if total_sum > total {
                return Some(format!(
                    "would exceed the total budget: {} on top of {} already spent is over the {} lifetime limit ({} left)",
                    fmt_psy(amount),
                    fmt_psy(policy.spent_total),
                    fmt_psy(total),
                    fmt_psy(total.saturating_sub(policy.spent_total))
                ));
            }
        } else {
            return Some("this payment would overflow the lifetime spend counter".to_string());
        }
    }
    None
}

/// What an empty method list means AT CREATION: everything the wallet can do.
///
/// Deny-by-default is right, but a default that omits the wallet's own
/// capabilities makes those tools permanently unusable rather than merely
/// restricted. Claims (`simple_claim`, `private_claim`) only fold in funds
/// already addressed to this wallet; the spend caps still apply to the rest.
///
/// Shared with the creation-widening check so the two cannot drift: if this
/// list grows, a new policy claiming the new method is still compared against
/// what existing policies actually grant.
pub fn default_methods() -> Vec<String> {
    vec![
        "simple_transfer".into(),
        "private_transfer".into(),
        "simple_claim".into(),
        "private_claim".into(),
        "withdraw".into(),
        "deposit".into(),
        "claim_deposit".into(),
        // Distinct from simple_transfer so an owner can allow direct transfers
        // while forbidding agent-driven paid fetches (or the reverse), and so
        // the audit trail tells them apart.
        "x402_fetch".into(),
    ]
}

/// The authority-bearing fields of a policy, copied out so the widening check
/// is a pure function of two values and can be tested without an engine, a
/// keystore or a chain.
#[derive(Clone, Debug)]
pub struct AuthoritySnapshot {
    pub per_transaction: u64,
    pub per_day: u64,
    pub per_month: Option<u64>,
    pub total_budget: Option<u64>,
    /// Already normalized. `None` = any recipient.
    pub allowed_recipients: Option<Vec<String>>,
    pub allowed_methods: Vec<String>,
}

/// A requested partial edit, in `update_policy`'s own vocabulary: `None` =
/// leave alone, `Some(None)` = remove that limit, an empty method list =
/// unchanged.
#[derive(Clone, Debug, Default)]
pub struct AuthorityEdit {
    pub per_transaction: Option<u64>,
    pub per_day: Option<u64>,
    pub per_month: Option<Option<u64>>,
    pub total_budget: Option<Option<u64>>,
    pub allowed_recipients: Option<Option<Vec<String>>>,
    pub allowed_methods: Vec<String>,
}

/// Does `edit` grant more than `cur` already grants? If so, one sentence naming
/// every way it does, in the owner's units.
///
/// This is the line between "the agent tidied its own limits" and the
/// escalation chain: raise the caps, drop the 30-day and lifetime ceilings,
/// clear the allow-list, and a policy that read as "5 PSY to two approved
/// payees" becomes "anything to anyone" in a single call. Every clause below
/// is one link in it.
///
/// Deliberately asymmetric: ADDING a ceiling where there was none, or an
/// allow-list where there was none, is narrowing and never needs approval.
pub fn widening_reason(cur: &AuthoritySnapshot, edit: &AuthorityEdit) -> Option<String> {
    let mut reasons: Vec<String> = Vec::new();

    if let Some(v) = edit.per_transaction {
        if v > cur.per_transaction {
            reasons.push(format!(
                "raises the per-payment cap from {} to {}",
                fmt_psy(cur.per_transaction),
                fmt_psy(v)
            ));
        }
    }
    if let Some(v) = edit.per_day {
        if v > cur.per_day {
            reasons.push(format!(
                "raises the daily cap from {} to {}",
                fmt_psy(cur.per_day),
                fmt_psy(v)
            ));
        }
    }
    // For the two optional ceilings, REMOVING one is the widest possible move —
    // wider than any number — so it is checked before the numeric comparison.
    if let Some(requested) = edit.per_month {
        match (cur.per_month, requested) {
            (Some(c), None) => reasons.push(format!("removes the {} 30-day ceiling", fmt_psy(c))),
            (Some(c), Some(v)) if v > c => reasons.push(format!(
                "raises the 30-day cap from {} to {}",
                fmt_psy(c),
                fmt_psy(v)
            )),
            _ => {}
        }
    }
    if let Some(requested) = edit.total_budget {
        match (cur.total_budget, requested) {
            (Some(c), None) => reasons.push(format!("removes the {} lifetime ceiling", fmt_psy(c))),
            (Some(c), Some(v)) if v > c => reasons.push(format!(
                "raises the lifetime budget from {} to {}",
                fmt_psy(c),
                fmt_psy(v)
            )),
            _ => {}
        }
    }
    if let Some(requested) = &edit.allowed_recipients {
        match (&cur.allowed_recipients, requested) {
            // The single most dangerous edit in the whole surface.
            (Some(c), None) => reasons.push(format!(
                "removes the allow-list of {} approved recipient(s), letting it pay anyone",
                c.len()
            )),
            (Some(c), Some(new)) => {
                // Compare normalized, exactly as the gate will at spend time —
                // otherwise "Psy-00001234" reads as a new payee next to "1234"
                // and the check fires on a spelling change.
                let added = new
                    .iter()
                    .map(|s| normalize_recipient(s))
                    .filter(|n| !c.iter().any(|e| e == n))
                    .count();
                if added > 0 {
                    reasons.push(format!("approves {added} new recipient(s)"));
                }
            }
            // No allow-list today: any list at all is a restriction.
            (None, _) => {}
        }
    }
    if !edit.allowed_methods.is_empty() {
        let added: Vec<&str> = edit
            .allowed_methods
            .iter()
            .filter(|m| !cur.allowed_methods.iter().any(|c| c == *m))
            .map(|m| m.as_str())
            .collect();
        if !added.is_empty() {
            reasons.push(format!("allows new action(s): {}", added.join(", ")));
        }
    }

    if reasons.is_empty() {
        None
    } else {
        Some(reasons.join("; "))
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Limits {
    pub per_transaction: u64,
    pub per_day: u64,
    /// 30-day cap. `None` = only the daily and total caps apply.
    pub per_month: Option<u64>,
    pub total_budget: Option<u64>,
}

impl Default for Limits {
    fn default() -> Self {
        // Conservative defaults (Nano). 1 PSY = 1e9 Nano.
        Self {
            per_transaction: 5_000_000_000,
            per_day: 50_000_000_000,
            per_month: None,
            total_budget: None,
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct Policy {
    agent_id: String,
    /// The on-chain user id this policy governs.
    ///
    /// A policy is a budget for ONE wallet. Without this it was a budget for
    /// "whatever wallet this process happens to have loaded" — and
    /// `create_wallet(mode="load")` swaps that globally, so a policy's caps AND
    /// its spent counters would silently transfer to a different identity.
    ///
    /// `#[serde(default)]` keeps every policy written before this readable;
    /// `None` means "not yet bound" and is bound on first use rather than
    /// treated as permission to govern anything.
    #[serde(default)]
    bound_user_id: Option<u64>,
    limits: Limits,
    /// `None` = any recipient. `Some(list)` = only these (normalized); an empty
    /// list therefore means "no outbound payments at all", which is a coherent
    /// thing for an owner to ask for and is why this is not just a Vec.
    allowed_recipients: Option<Vec<String>>,
    allowed_methods: Vec<String>,
    active: bool,
    spent_today: u64,
    spent_this_month: u64,
    spent_total: u64,
    last_day: u64,
    last_month: u64,
}

#[derive(Clone, Debug)]
struct Session {
    policy_id: String,
    expires_at: u64,
    /// Lifetime spend cap for THIS session token, in nano. `None` = uncapped
    /// (still bound by the policy's per-day/per-month/total caps).
    session_budget: Option<u64>,
    /// Amount already authorized against this session. Checked and incremented
    /// under the same lock as the policy counters, so concurrent spends from
    /// one token cannot both pass on stale state.
    session_spent: u64,
}

/// Returned on a successful `authorize()`. The fields identify the approving
/// policy/agent for callers that log or audit the decision.
#[derive(Debug)]
#[allow(dead_code)]
pub struct Authorization {
    pub policy_id: String,
    pub agent_id: String,
    /// The session this spend was charged to. `refund` uses it to hand the
    /// session-lifetime budget back alongside the policy counters — without
    /// it, a spend that failed AFTER the gate (balance refusal, chain error)
    /// would permanently eat the session cap.
    pub session_token: String,
    /// The spend-log rows this authorization created. `refund` uses these to
    /// mark exactly those rows, rather than guessing from an amount.
    pub spend_ids: Vec<u64>,
}

/// One authorized spend, as recorded at the moment of the decision.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpendRecord {
    /// Stable within this process run; lets a refund mark the exact rows it
    /// undid instead of matching on amount.
    pub id: u64,
    /// True once the spend was refunded because it never moved any money. The
    /// row is KEPT rather than deleted — an owner should see that the agent
    /// tried — but it must not read as a completed payment, which is what a
    /// failed batch used to look like: N rows identical to real ones next to a
    /// budget meter showing nothing spent.
    pub refunded: bool,
    /// Unix seconds when the spend was authorized.
    pub timestamp: u64,
    /// Filled in when the log is read, so a human reading the tool output does
    /// not have to subtract unix timestamps to see "4 minutes ago".
    pub age_seconds: u64,
    pub policy_id: String,
    pub agent_id: String,
    pub method: String,
    /// As the tool passed it (not normalized), so it reads the way the owner
    /// would recognise it.
    pub recipient: String,
    /// Nano-denominated amount; the wire name is plain `amount` — the unit is
    /// documented in the tool description, not repeated in every field name.
    /// (DeniedRecord next door already does this; without the rename the
    /// struct-level camelCase leaks `amountNano`, which no other tool emits.)
    #[serde(rename = "amount")]
    pub amount_nano: u64,
}

/// One BLOCKED attempt, recorded at the moment a spend was refused. This is the
/// trust half of the audit trail: the owner sees not only what the agent did,
/// but what it TRIED and why your rules stopped it. `reason` is the same
/// human, PSY-denominated sentence the caller received.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeniedRecord {
    pub timestamp: u64,
    pub age_seconds: u64,
    pub policy_id: String,
    pub agent_id: String,
    pub method: String,
    pub recipient: String,
    /// Nano-denominated amount; the wire name is plain `amount` — the unit is
    /// documented in the tool description, not repeated in every field name.
    #[serde(rename = "amount")]
    pub amount_nano: u64,
    pub reason: String,
}

/// A policy in the terms an owner (or an agent being onboarded) reads.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyDescription {
    pub policy_id: String,
    pub agent_id: String,
    pub active: bool,
    /// `rename` keeps these camelCase too — the struct-level `rename_all` would
    /// otherwise leak the "Nano" unit suffix into the wire name (`perTransactionNano`),
    /// which would break the "camelCase, no Nano suffix" scheme every other tool uses.
    #[serde(rename = "perTransaction")]
    pub per_transaction_nano: u64,
    #[serde(rename = "perDay")]
    pub per_day_nano: u64,
    #[serde(rename = "perMonth")]
    pub per_month_nano: Option<u64>,
    #[serde(rename = "totalBudget")]
    pub total_budget_nano: Option<u64>,
    #[serde(rename = "spentToday")]
    pub spent_today_nano: u64,
    #[serde(rename = "spentThisMonth")]
    pub spent_this_month_nano: u64,
    #[serde(rename = "spentTotal")]
    pub spent_total_nano: u64,
    #[serde(rename = "remainingDay")]
    pub remaining_day_nano: u64,
    #[serde(rename = "remainingMonth")]
    pub remaining_month_nano: Option<u64>,
    #[serde(rename = "remainingTotal")]
    pub remaining_total_nano: Option<u64>,
    /// `None` = any recipient is payable. `Some(n)` = only n approved ones. The
    /// list itself is deliberately not returned: the agent needs to know it is
    /// constrained, not to be handed a directory of payees to try.
    pub allowed_recipient_count: Option<usize>,
    pub allowed_methods: Vec<String>,
    pub active_sessions: usize,
    /// Time left on the longest-lived live session for this policy.
    pub session_expires_in_seconds: Option<u64>,
    /// The whole thing as one sentence — the agent-onboarding surface.
    pub summary: String,
}

/// Remaining headroom, for `check_budget`.
#[derive(Clone, Debug)]
pub struct BudgetView {
    pub remaining_day: u64,
    pub remaining_month: Option<u64>,
    pub remaining_total: Option<u64>,
    /// How much has been spent (the other side of each remaining_*). The
    /// denial messages report these; check_budget must too, or an owner cannot
    /// reconcile the gate's "already spent 228 PSY" against anything.
    pub spent_today: u64,
    pub spent_this_month: u64,
    pub spent_total: u64,
    pub per_transaction: u64,
    /// True when the owner has paused this policy. Every remaining_* figure is
    /// then 0: a paused policy has no headroom, whatever its caps say.
    pub paused: bool,
}

/// An exclusive advisory lock over a keystore directory's policy file.
///
/// Held for the duration of one read-modify-write. `flock` is released when the
/// file handle drops, including on panic and on process death, so a crashed
/// server cannot wedge the other one.
struct PolicyFileLock(Option<std::fs::File>);

impl PolicyFileLock {
    fn acquire(dir: &std::path::Path) -> Self {
        use fs2::FileExt;
        let _ = std::fs::create_dir_all(dir);
        // A dedicated lock file, never the data file: locking the data file
        // itself would race with the tmp+rename that replaces it.
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join("policies.lock"));
        match file {
            Ok(f) => {
                // Blocking: a spend waiting on the owner's pause is correct
                // ordering, and every critical section here is a few file ops.
                if f.lock_exclusive().is_err() {
                    tracing::warn!("policy lock unavailable; proceeding without cross-process serialization");
                    return Self(None);
                }
                Self(Some(f))
            }
            Err(e) => {
                tracing::warn!("could not open the policy lock file ({e}); proceeding unserialized");
                Self(None)
            }
        }
    }
}

impl Drop for PolicyFileLock {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            use fs2::FileExt;
            let _ = FileExt::unlock(&f);
        }
    }
}

pub struct PolicyEngine {
    /// Monotonic id for spend-log rows. Process-local: the log is an in-memory
    /// ring, so ids only need to be unique for the lifetime of an Authorization.
    next_spend_id: u64,
    policies: HashMap<String, Policy>,
    sessions: HashMap<String, Session>,
    spend_log: VecDeque<SpendRecord>,
    /// Blocked attempts, newest last, capped like the spend log. In-memory: the
    /// owner watches a live agent, and a restart revokes the agent anyway.
    denied_log: VecDeque<DeniedRecord>,
    /// Where policies (with their spent counters) are persisted. `None` in
    /// unit tests. Sessions are deliberately NOT persisted: a restart revokes
    /// them, which fails toward re-authorization, never toward extra spend.
    persist_dir: Option<std::path::PathBuf>,
    /// The on-chain user id of the wallet this PROCESS currently has loaded.
    /// Process-local and never persisted: it describes the running server, not
    /// the policy store. `None` before any wallet is loaded.
    current_user_id: Option<u64>,
    /// Whether reloads should retain only policies belonging to the initial
    /// wallet. Disabled after an in-process wallet swap so bind_or_reject can
    /// report the identity mismatch instead of pretending the policy vanished.
    hide_foreign_on_reload: bool,
    /// Policy ids bound to OTHER wallets, hidden from this process's view by
    /// hide_foreign_policies. Tracked so the count can be surfaced to the
    /// owner ("2 more policies belong to other wallets on this volume") when
    /// the sole-policy fast path does not apply.
    foreign_hidden: Vec<String>,
    /// Set when a policy file existed but could not be used. Without it, an
    /// empty policy set is ambiguous — and the creation gate's bootstrap
    /// exemption reads emptiness as "brand new server, nothing to compare
    /// against", which would turn a corrupt file into a way to mint an
    /// unlimited policy with no owner token.
    lost_policies: bool,
    /// How many rows each ring has DROPPED. The rings are capped, so a short
    /// list is ambiguous — and a denial costs the agent nothing (no funds, no
    /// chain, no budget), so ~101 refused calls used to flush the evidence of
    /// what it tried while the reader still reported "nothing has been
    /// blocked". A counter cannot be gamed in the attacker's favour: flooding
    /// only makes it louder.
    spend_log_dropped: u64,
    denied_log_dropped: u64,
}

fn rand_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

impl PolicyEngine {
    /// True when a policy file EXISTED and could not be used. An empty policy
    /// set then means "we lost them", not "this server is new" — a distinction
    /// the creation gate depends on, because its bootstrap exemption keys off
    /// emptiness.
    #[allow(dead_code)]
    pub fn lost_policies(&self) -> bool {
        self.lost_policies
    }

    pub fn new() -> Self {
        Self {
            current_user_id: None,
            hide_foreign_on_reload: false,
            foreign_hidden: Vec::new(),
            spend_log_dropped: 0,
            denied_log_dropped: 0,
            lost_policies: false, next_spend_id: 1, policies: HashMap::new(), sessions: HashMap::new(), spend_log: VecDeque::new(), denied_log: VecDeque::new(), persist_dir: None }
    }

    /// An engine whose policies — including spent counters — survive restarts.
    /// Without this, `total_budget` (the lifetime cap) resets on every crash,
    /// so a crash-looping server would grant a fresh budget each loop.
    pub fn load_or_new(dir: &std::path::Path) -> Self {
        let mut engine = Self::new();
        engine.persist_dir = Some(dir.to_path_buf());
        let path = dir.join("policies.json");
        // Read BYTES, not a String. read_to_string fails before any parse for a
        // file that is not valid UTF-8 — which is exactly what a torn write or
        // bit rot produces — and that error used to land in a silent
        // `Err(_) => {}` treated as "first run". The next save() then renamed a
        // fresh file over it: counters gone, evidence gone, nothing logged. A
        // damaged file is the MORE likely corruption, and it was the half this
        // quarantine did not cover.
        match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<HashMap<String, Policy>>(&bytes) {
                Ok(policies) => engine.policies = policies,
                Err(e) => {
                    Self::quarantine(dir, &path, &format!("could not parse it ({e})"));
                    engine.lost_policies = true;
                }
            },
            // A genuinely absent file is the only benign case.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            // Unreadable for any other reason — permissions, EIO, it is a
            // directory. We cannot tell whether it holds live counters, so we
            // must not let the next save() replace it.
            Err(e) => {
                Self::quarantine(dir, &path, &format!("could not read it ({e})"));
                engine.lost_policies = true;
            }
        }
        engine
    }


    /// Move an unusable policy file aside, so starting with no policies never
    /// costs the owner the record of what their budgets were. A random suffix
    /// (not a timestamp) because two quarantines in the same second would
    /// otherwise rename over each other and destroy the earlier evidence.
    fn quarantine(dir: &std::path::Path, path: &std::path::Path, why: &str) {
        let target = dir.join(format!("policies.corrupt-{}.json", rand_hex(8)));
        match std::fs::rename(path, &target) {
            Ok(()) => tracing::error!(
                "{path:?}: {why}; moved it to {target:?} and started with NO policies — \
                 spent counters are reset until it is restored"
            ),
            Err(mv) => tracing::error!(
                "{path:?}: {why}, and it could not be quarantined ({mv}); \
                 starting with NO policies — spent counters are reset"
            ),
        }
    }

    /// Atomic 0600 write, same discipline as the keystore. Failures are logged,
    /// not fatal: refusing to spend because the DISK is full would brick the
    /// wallet, and the counters are still correct in memory.
    /// Run a mutation as a CROSS-PROCESS transaction: lock, re-read the latest
    /// on-disk policies, apply, persist, unlock.
    ///
    /// Two servers legitimately share one keystore directory — the owner
    /// dashboard spawns its own MCP child, and the agent host spawns another —
    /// and each loaded `policies.json` ONCE at startup and wrote the whole map
    /// back on every change. Their read-modify-write cycles therefore lost each
    /// other's updates, in the two directions that matter most:
    ///
    ///   * the owner clicks Pause, the dashboard's process writes
    ///     `active:false`, and the agent's process — still holding
    ///     `active:true` in memory — rewrites it on its very next spend. The
    ///     emergency stop was undone by the party it was meant to stop.
    ///   * each process tracked `spent_today` independently and last-writer-won,
    ///     so a 50 PSY/day cap permitted 100.
    ///
    /// The file was already written atomically (random tmp + rename), which
    /// prevents a TORN write; it did nothing about a LOST UPDATE. This closes
    /// that: the check and the commit happen against the same freshly-read
    /// state, inside one exclusive lock.
    ///
    /// Failing to take the lock is not fatal — the mutation still proceeds
    /// against local state. Refusing to spend because a lock file could not be
    /// created would brick the wallet, and the pre-existing behaviour was to
    /// have no lock at all.
    fn with_persisted<T>(&mut self, f: impl FnOnce(&mut Self) -> T) -> T {
        let Some(dir) = self.persist_dir.clone() else {
            // No persistence configured (unit tests): nothing to race with.
            return f(self);
        };
        let _guard = PolicyFileLock::acquire(&dir);
        self.reload_policies();
        let out = f(self);
        self.save();
        out
    }

    /// May this session act AT ALL right now — without recording a spend?
    ///
    /// For a tool that does real work before (or instead of) paying, the
    /// session must be checked BEFORE that work, or the owner's stop controls
    /// do not stop it. `x402_fetch` is the case: it fetched the URL and could
    /// return a remote body into model context, and only validated the session
    /// at the payment step far below — so Pause and Revoke left it running as a
    /// fetcher.
    ///
    /// Deliberately does NOT go through `authorize`: that records a spend, and a
    /// zero-amount row for every fetch (including a dry run, which pays nothing)
    /// would put non-payments in the owner's audit trail.
    ///
    /// Reuses `denial_reason` — the single source the live gate uses — so the
    /// paused / method checks cannot drift, and it costs no counters. The
    /// recipient and amount gates are NOT applied here: the payment step still
    /// applies them with the real values, which are not known yet.
    pub fn check_can_act(&mut self, token: &str, method: &str) -> anyhow::Result<()> {
        let _guard = self.lock_and_reload();
        let session = self.resolve_session_or_record(token, "", 0, method)?;
        if let Some(reason) = self.bind_or_reject(&session.policy_id) {
            anyhow::bail!("{reason}");
        }
        let policy = self
            .policies
            .get(&session.policy_id)
            .expect("resolve_session_or_record guarantees the policy exists");
        // SELF_RECIPIENT keeps the allow-list out of it: this is a capability
        // check, and the real recipient is decided by the 402 challenge later.
        if let Some(reason) = denial_reason(policy, &[SELF_RECIPIENT], 0, method) {
            let agent_id = policy.agent_id.clone();
            let policy_id = session.policy_id.clone();
            self.record_denial(&policy_id, &agent_id, "", 0, method, &reason);
            anyhow::bail!("{reason}");
        }
        Ok(())
    }

    /// Tell the engine which wallet this process now has loaded.
    ///
    /// Called after every successful load / register / mint. A policy is a
    /// budget for one identity, and this is the only thing that lets the engine
    /// notice when the identity underneath it has changed.
    pub fn set_current_user(&mut self, user_id: u64) {
        let first_identity = self.current_user_id.is_none();
        let identity_changed = self.current_user_id.is_some_and(|current| current != user_id);
        self.current_user_id = Some(user_id);
        // Hide only on the FIRST identity of this process — the boot-time view
        // of a shared keystore volume. A mid-process identity swap (load of
        // another backup) keeps every policy visible on purpose: the swap may
        // legitimately be the owner returning to another wallet, and the
        // refusal for a mismatched policy must NAME both wallets
        // (bind_or_reject), not make the policy vanish with a confusing
        // "no longer exists".
        if first_identity {
            self.hide_foreign_on_reload = true;
            self.hide_foreign_policies();
        } else if identity_changed {
            self.hide_foreign_on_reload = false;
            // The boot-time view may already have removed this wallet's policy
            // from memory. Restore the complete persisted map so authorization
            // can reach bind_or_reject and name the mismatched identities.
            self.reload_policies();
        }
    }

    /// Bug #4: containers sharing the keystore volume share one policies.json,
    /// so wallet B's boot sees wallet A's policies. Execution already refuses
    /// them (bind_or_reject) but the owner-only no-id tools trip on
    /// "several policies exist" and one wallet's budget caps are
    /// metadata-visible to another. HIDE rather than move: the file is the
    /// single source of truth, stays untouched (both containers keep saving
    /// the whole map — the other wallet's counters never regress), and each
    /// process simply cannot see what is not its own.
    fn hide_foreign_policies(&mut self) {
        let Some(current) = self.current_user_id else { return };
        self.foreign_hidden = self
            .policies
            .iter()
            .filter(|(_, p)| matches!(p.bound_user_id, Some(b) if b != current))
            .map(|(id, _)| id.clone())
            .collect();
        if !self.foreign_hidden.is_empty() {
            let n = self.foreign_hidden.len();
            self.policies.retain(|_, p| !matches!(p.bound_user_id, Some(b) if b != current));
            tracing::debug!("hiding {n} policies bound to other wallets; owner tools see only this wallet's policies");
        }
    }

    /// Refuse a spend whose policy governs a DIFFERENT wallet than the one
    /// loaded, and bind an unbound policy on first use.
    ///
    /// `create_wallet(mode="load")` replaces the process's wallet globally, and
    /// nothing tied a policy to an identity — so an agent could point at another
    /// of the owner's key backups and operate a richer wallet under the caps
    /// (and against the spent counters) sized for the first. The counters cut
    /// both ways: wallet B inherits A's exhausted budget, or resets it.
    ///
    /// Binding lazily rather than refusing on `None` keeps every policy written
    /// before this usable: the first spend after the upgrade stamps the identity
    /// it is actually governing, and every spend after that is checked.
    fn bind_or_reject(&mut self, policy_id: &str) -> Option<String> {
        let Some(current) = self.current_user_id else {
            // No wallet loaded: the spend cannot execute anyway, and refusing
            // here would replace a clear error with a confusing one.
            return None;
        };
        let Some(policy) = self.policies.get_mut(policy_id) else { return None };
        match policy.bound_user_id {
            Some(bound) if bound != current => Some(format!(
                "this policy governs Psy-{bound:08} but the server currently has Psy-{current:08} loaded — \
                 a policy is a budget for one wallet, and its limits and spent counters do not transfer. \
                 Load the wallet this policy was created for, or ask the owner for a policy for this one."
            )),
            Some(_) => None,
            None => {
                policy.bound_user_id = Some(current);
                None
            }
        }
    }

    /// Take the cross-process lock and refresh from disk, returning the guard.
    ///
    /// The caller holds the guard for the rest of its scope, so the CHECK and
    /// the COMMIT (record_spend's save) happen inside one critical section
    /// against one freshly-read state. Without this, a spend authorized against
    /// stale memory could be committed on top of the owner's pause.
    fn lock_and_reload(&mut self) -> PolicyFileLock {
        let Some(dir) = self.persist_dir.clone() else { return PolicyFileLock(None) };
        let guard = PolicyFileLock::acquire(&dir);
        self.reload_policies();
        guard
    }

    /// Replace the in-memory policy map with what is on disk RIGHT NOW.
    ///
    /// Only `policies` is persisted, so only `policies` is replaced; sessions
    /// and the audit rings are process-local by design and must survive.
    ///
    /// A missing file means "no policies yet" and is normal on a fresh server.
    /// An UNREADABLE or unparseable one is left alone deliberately: `load_or_new`
    /// already quarantines that case and sets `lost_policies`, and silently
    /// emptying the map here would hand the next `create_wallet` the
    /// bootstrap exemption on a server that actually has policies.
    fn reload_policies(&mut self) {
        let Some(dir) = self.persist_dir.as_ref() else { return };
        let path = dir.join("policies.json");
        match std::fs::read(&path) {
            Ok(bytes) => {
                if let Ok(policies) = serde_json::from_slice::<HashMap<String, Policy>>(&bytes) {
                    self.policies = policies;
                    // The disk holds EVERY wallet's policies (see save). Re-apply
                    // the boot-time view so the reload cannot resurrect what the
                    // owner's tools must not see — including a foreign policy
                    // created AFTER boot, when nothing was hidden yet.
                    if self.hide_foreign_on_reload {
                        self.hide_foreign_policies();
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {}
        }
    }

    fn save(&self) {
        let Some(dir) = self.persist_dir.as_ref() else { return };
        let path = dir.join("policies.json");
        // MERGE, not replace: containers sharing this volume each see only
        // their own wallet's policies (hide_foreign_policies), so writing this
        // process's map outright would DELETE every other wallet's budgets on
        // disk. Read the full file, overlay this view's entries, keep the
        // strangers'. Self-view always wins on conflict, so a counter update
        // lands; a stranger's entry is passed through untouched.
        let mut full: HashMap<String, Policy> = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let mine = &self.policies;
        // Always write the merged map: when the disk was empty `full` is
        // exactly `mine` after the overlay above, so the common single-wallet
        // case is unchanged; when it was not, strangers ride along.
        for (id, p) in mine {
            full.insert(id.clone(), p.clone());
        }
        // A FIXED tmp name with truncate lets two servers sharing a keystore dir
        // interleave and rename a half-written file into place. The keystore
        // uses a random suffix + create_new for exactly this reason; match it.
        // A RANDOM suffix, matching the keystore. pid+seconds is not unique:
        // two containers sharing a mounted keystore volume both see pid 1, and
        // pids are reused within a second. A collision made create_new fail, so
        // the counter update was silently dropped (warn-only) — and the cleanup
        // below then deleted the OTHER writer's in-flight tmp, losing both.
        let tmp = dir.join(format!("policies.json.tmp.{}", rand_hex(8)));
        let write = (|| -> anyhow::Result<()> {
            std::fs::create_dir_all(dir)?;
            {
                use std::io::Write;
                let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
                }
                f.write_all(serde_json::to_string_pretty(&full)?.as_bytes())?;
                f.sync_all()?;
            }
            std::fs::rename(&tmp, &path)?;
            // fsync the DIRECTORY too, or the rename itself can be lost on a
            // crash and the budgets silently roll back to an older file.
            if let Ok(d) = std::fs::File::open(dir) {
                let _ = d.sync_all();
            }
            Ok(())
        })();
        if let Err(e) = write {
            let _ = std::fs::remove_file(&tmp);
            tracing::warn!("could not persist policies to {path:?}: {e:#}");
        }
    }

    pub fn create_policy(
        &mut self,
        agent_id: &str,
        limits: Limits,
        allowed_recipients: Option<Vec<String>>,
        allowed_methods: Vec<String>,
    ) -> String {
        let id = rand_hex(8);
        let methods = if allowed_methods.is_empty() { default_methods() } else { allowed_methods };
        // Normalize once, at write time: the hot path then compares two already
        // canonical strings, and an owner's "Psy-00001234" can never drift away
        // from the "1234" a tool passes.
        let allowed_recipients =
            allowed_recipients.map(|r| r.iter().map(|s| normalize_recipient(s)).collect::<Vec<_>>());
        self.policies.insert(
            id.clone(),
            Policy {
                agent_id: agent_id.to_string(),
                // Stamp the identity this policy is for at creation, when we
                // know it. A policy created before a wallet is loaded binds on
                // first spend instead.
                bound_user_id: self.current_user_id,
                limits,
                allowed_recipients,
                allowed_methods: methods,
                active: true,
                spent_today: 0,
                spent_this_month: 0,
                spent_total: 0,
                last_day: day_index(),
                last_month: month_index(),
            },
        );
        self.save();
        id
    }

    pub fn issue_session(&mut self, policy_id: &str, ttl_minutes: u64, max_session_total: Option<u64>) -> anyhow::Result<(String, u64)> {
        // Reload first: the paused check below is only meaningful against the
        // CURRENT state. Without this, a process holding stale memory would mint
        // a session for a policy the owner has already paused. The spend would
        // still be refused (authorize reloads too), but handing out a token that
        // cannot be used is its own confusion.
        let _guard = self.lock_and_reload();
        let policy = self.policies.get(policy_id).ok_or_else(|| anyhow::anyhow!("policy not found"))?;
        if !policy.active {
            anyhow::bail!("policy is paused");
        }
        let token = rand_hex(32);
        // Clamp to 24h: a year-long session defeats revocation in practice,
        // and unclamped math overflows on absurd inputs.
        let ttl_minutes = ttl_minutes.min(24 * 60);
        let expires_at = now_secs().saturating_add(ttl_minutes.saturating_mul(60));
        // The session cap can never exceed what the policy itself allows over
        // the session's whole life; clamp it to the tightest of the owner's
        // own ceilings so no session is broader than its policy.
        let session_budget = max_session_total.map(|requested| {
            let mut cap = requested;
            if let Some(day) = policy.limits.per_day.checked_mul(ttl_minutes / 1440 + 1) { cap = cap.min(day); }
            if let Some(month) = policy.limits.per_month.and_then(|m| m.checked_mul(ttl_minutes / (1440 * 30) + 1)) { cap = cap.min(month); }
            if let Some(total) = policy.limits.total_budget { cap = cap.min(total.saturating_sub(policy.spent_total)); }
            cap
        });
        self.sessions.insert(token.clone(), Session { policy_id: policy_id.to_string(), expires_at, session_budget, session_spent: 0 });
        Ok((token, expires_at))
    }

    /// Give back headroom for an authorized spend that never settled — a
    /// hostile seller or a flaky prover must not be able to burn the daily
    /// budget with transactions that moved no money. The spend-log entry is
    /// deliberately KEPT: the log records authorization decisions, and the
    /// caller reports the failure itself.
    pub fn refund(&mut self, auth: &Authorization, amount: u64) {
        // Locked like the spend it undoes: giving budget back is a counter
        // mutation, and an unserialized one can be lost the same way.
        let _guard = self.lock_and_reload();
        // Idempotent: a caller that refunds the same authorization twice must
        // not hand back the budget twice. If every row this authorization
        // created is already refunded, the counters were already restored.
        if !auth.spend_ids.is_empty() {
            let already = auth
                .spend_ids
                .iter()
                .all(|id| self.spend_log.iter().any(|r| r.id == *id && r.refunded));
            if already {
                return;
            }
        }
        for record in self.spend_log.iter_mut() {
            if auth.spend_ids.contains(&record.id) {
                record.refunded = true;
            }
        }
        // The session-lifetime budget moved with the policy counters when the
        // spend was authorized; it must move back with them too, or one
        // balance-refused transfer permanently eats the session cap.
        if let Some(s) = self.sessions.get_mut(&auth.session_token) {
            s.session_spent = s.session_spent.saturating_sub(amount);
        }
        if let Some(policy) = self.policies.get_mut(&auth.policy_id) {
            policy.spent_today = policy.spent_today.saturating_sub(amount);
            policy.spent_this_month = policy.spent_this_month.saturating_sub(amount);
            policy.spent_total = policy.spent_total.saturating_sub(amount);
            self.save();
        }
    }

    pub fn pause(&mut self, policy_id: &str) -> bool {
        // Transactional: reload first, so pausing does not silently revert a
        // change the other process made, and save inside the lock so the other
        // process cannot rewrite active:true from stale memory.
        self.with_persisted(|e| {
            if let Some(p) = e.policies.get_mut(policy_id) { p.active = false; true } else { false }
        })
    }
    pub fn resume(&mut self, policy_id: &str) -> bool {
        self.with_persisted(|e| {
            if let Some(p) = e.policies.get_mut(policy_id) { p.active = true; true } else { false }
        })
    }

    /// Owner edit of an existing policy's limits and allow-lists. This is what
    /// the human dashboard's policy editor writes. It REPLACES the limits, the
    /// recipient allow-list (normalized, same as create), and — only when a
    /// non-empty list is given — the method list; the spent counters, active
    /// flag and any live sessions are untouched, so tightening a limit binds
    /// immediately without revoking the agent. Persisted like every other
    /// counter change. Gate this at the tool layer behind the owner token.
    /// `allowed_recipients`: `None` = LEAVE UNCHANGED (an omitted field must
    /// never silently widen the policy — that turned a "tighten my budget" save
    /// into "pay anyone"); `Some(None)` = clear the list (pay anyone), the
    /// explicit opt-in; `Some(Some(list))` = replace it.
    /// Apply a PARTIAL edit to a policy. Every field is "omit = leave alone".
    ///
    /// This used to take a whole `Limits` and assign it wholesale, which made
    /// every edit a full replacement of something the caller may not have been
    /// thinking about. The dashboard's Permissions page has no lifetime-budget
    /// field and never sent one, so tightening a DAILY limit silently deleted
    /// the lifetime cap — the same trap already fixed once for the recipient
    /// allow-list, still open for the caps. Requiring both caps on every call
    /// also meant an owner editing only the allow-list had to resend numbers
    /// they were not changing, and any stale value silently became the new
    /// budget.
    ///
    /// So: `None` means untouched. For the two OPTIONAL caps that also need a
    /// "remove the limit" operation, the double option distinguishes absent
    /// (`None`) from explicitly cleared (`Some(None)`) — the same convention
    /// `allowed_recipients` already uses.
    /// Would CREATING this policy grant more authority than the agent already
    /// has under some existing policy?
    ///
    /// Gating `update_policy` alone leaves the same escalation one step to the
    /// left: `create_wallet` accepts caps as arguments and mints a policy from
    /// them, and `mode="load"` reloads the SAME key (wallet.rs `load`), so an
    /// agent that names a published key env var gets a brand-new uncapped
    /// policy over the owner's live wallet, then `issue_session` to spend it —
    /// without ever calling `update_policy`.
    ///
    /// The rule: a new policy is fine if SOME existing policy already grants at
    /// least this much. That keeps the honest cases working — the very first
    /// creation on a fresh server (nothing exists to compare against, and this
    /// IS the owner's setup), and re-creating an equivalent policy on every
    /// dashboard restart — while refusing a policy that reaches beyond every
    /// authority the owner has actually granted.
    pub fn creation_widens(
        &self,
        limits: &Limits,
        allowed_recipients: &Option<Vec<String>>,
        allowed_methods: &[String],
    ) -> Option<String> {
        // Nothing to compare against: this is the bootstrap, and refusing it
        // would make the server unusable rather than safe.
        //
        // But ONLY when the set is empty because nothing was ever created. If a
        // policy file existed and could not be read or parsed, the set is empty
        // because we LOST it — and treating that as a fresh server would let a
        // corrupt file (disk full, EIO, a permissions change, a torn write)
        // become the way to mint an unlimited policy with no owner token. The
        // gate would be defeated not by beating it but by emptying the set it
        // compares against.
        if self.policies.is_empty() && !self.lost_policies {
            return None;
        }
        if self.policies.is_empty() {
            return Some(
                "this server started with NO usable policy file (it was quarantined), so there is \
                 nothing to check this against — the previous limits and spent counters are gone"
                    .to_string(),
            );
        }
        let edit = AuthorityEdit {
            per_transaction: Some(limits.per_transaction),
            per_day: Some(limits.per_day),
            per_month: Some(limits.per_month),
            total_budget: Some(limits.total_budget),
            allowed_recipients: Some(allowed_recipients.clone()),
            // Empty means "everything" at creation time, which is the widest
            // method set there is — spell it out so the comparison sees it.
            allowed_methods: if allowed_methods.is_empty() {
                default_methods()
            } else {
                allowed_methods.to_vec()
            },
        };
        let mut closest: Option<String> = None;
        for policy in self.policies.values() {
            let current = AuthoritySnapshot {
                per_transaction: policy.limits.per_transaction,
                per_day: policy.limits.per_day,
                per_month: policy.limits.per_month,
                total_budget: policy.limits.total_budget,
                allowed_recipients: policy.allowed_recipients.clone(),
                allowed_methods: policy.allowed_methods.clone(),
            };
            match widening_reason(&current, &edit) {
                // Some policy already grants at least this much — allowed.
                None => return None,
                Some(reason) => {
                    if closest.as_ref().is_none_or(|c| reason.len() < c.len()) {
                        closest = Some(reason);
                    }
                }
            }
        }
        closest
    }

    /// Would this edit grant MORE authority than the policy grants today?
    ///
    /// Returns the owner-readable reason if so. Callers use it to decide who is
    /// allowed to make the edit: narrowing is safe for anyone (an agent that
    /// tightens its own leash costs nobody anything, and an owner tightening
    /// theirs must never be blocked), widening is the escalation.
    pub fn update_widens(
        &self,
        policy_id: &str,
        per_transaction: Option<u64>,
        per_day: Option<u64>,
        per_month: Option<Option<u64>>,
        total_budget: Option<Option<u64>>,
        allowed_recipients: &Option<Option<Vec<String>>>,
        allowed_methods: &[String],
    ) -> anyhow::Result<Option<String>> {
        let policy = self
            .policies
            .get(policy_id)
            .ok_or_else(|| anyhow::anyhow!("policy `{policy_id}` not found"))?;
        let current = AuthoritySnapshot {
            per_transaction: policy.limits.per_transaction,
            per_day: policy.limits.per_day,
            per_month: policy.limits.per_month,
            total_budget: policy.limits.total_budget,
            allowed_recipients: policy.allowed_recipients.clone(),
            allowed_methods: policy.allowed_methods.clone(),
        };
        let edit = AuthorityEdit {
            per_transaction,
            per_day,
            per_month,
            total_budget,
            allowed_recipients: allowed_recipients.clone(),
            allowed_methods: allowed_methods.to_vec(),
        };
        Ok(widening_reason(&current, &edit))
    }

    pub fn update_policy(
        &mut self,
        policy_id: &str,
        per_transaction: Option<u64>,
        per_day: Option<u64>,
        per_month: Option<Option<u64>>,
        total_budget: Option<Option<u64>>,
        allowed_recipients: Option<Option<Vec<String>>>,
        allowed_methods: Vec<String>,
    ) -> anyhow::Result<()> {
        let _guard = self.lock_and_reload();
        let policy = self
            .policies
            .get_mut(policy_id)
            .ok_or_else(|| anyhow::anyhow!("policy not found"))?;
        if let Some(v) = per_transaction {
            policy.limits.per_transaction = v;
        }
        if let Some(v) = per_day {
            policy.limits.per_day = v;
        }
        if let Some(v) = per_month {
            policy.limits.per_month = v;
        }
        if let Some(v) = total_budget {
            policy.limits.total_budget = v;
        }
        if let Some(recipients) = allowed_recipients {
            policy.allowed_recipients =
                recipients.map(|r| r.iter().map(|s| normalize_recipient(s)).collect::<Vec<_>>());
        }
        if !allowed_methods.is_empty() {
            policy.allowed_methods = allowed_methods;
        }
        self.save();
        Ok(())
    }
    /// Explicitly clear named caps (rmcp cannot deliver JSON null, so "pass
    /// null to clear" is impossible — this is the supported way to remove a cap).
    pub fn remove_limits(&mut self, policy_id: &str, names: &[String]) -> anyhow::Result<()> {
        // Called with the policy lock ALREADY held (update_policy); do not
        // re-lock. lock_and_reload inside would deadlock.
        let policy = self
            .policies
            .get_mut(policy_id)
            .ok_or_else(|| anyhow::anyhow!("policy not found"))?;
        for name in names {
            match name.as_str() {
                "perMonth" | "per_month" | "per_month_nano" => policy.limits.per_month = None,
                "totalBudget" | "total_budget" | "total_budget_nano" => policy.limits.total_budget = None,
                "allowedRecipients" | "allowed_recipients" => policy.allowed_recipients = None,
                _ => return Err(anyhow::anyhow!("unknown limit: {name}")),
            }
        }
        self.save();
        Ok(())
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
        let this_month = month_index();
        if policy.last_month != this_month {
            policy.spent_this_month = 0;
            policy.last_month = this_month;
        }
    }

    /// Budget view for `check_budget`.
    /// What this session may still spend.
    ///
    /// Reloads first, and reports a PAUSED policy as having no headroom. It
    /// previously ignored `active` entirely, so a paused policy answered with
    /// its full caps — the agent then planned spends it could not make, and the
    /// owner reading check_budget saw a live budget on a policy they had just
    /// stopped. The gate refused those spends, so no money moved; the number was
    /// simply a lie about what was possible.
    pub fn budget(&mut self, token: &str) -> Option<BudgetView> {
        // Cross-process freshness, same as the spend path: the pause may have
        // been made by the owner's dashboard process.
        let _guard = self.lock_and_reload();
        let policy_id = self.sessions.get(token)?.policy_id.clone();
        let policy = self.policies.get_mut(&policy_id)?;
        Self::rollover(policy);
        let paused = !policy.active;
        if paused {
            return Some(BudgetView {
                remaining_day: 0,
                remaining_month: policy.limits.per_month.map(|_| 0),
                remaining_total: policy.limits.total_budget.map(|_| 0),
                spent_today: policy.spent_today,
                spent_this_month: policy.spent_this_month,
                spent_total: policy.spent_total,
                per_transaction: policy.limits.per_transaction,
                paused: true,
            });
        }
        Some(BudgetView {
            remaining_day: policy.limits.per_day.saturating_sub(policy.spent_today),
            remaining_month: policy.limits.per_month.map(|m| m.saturating_sub(policy.spent_this_month)),
            remaining_total: policy.limits.total_budget.map(|t| t.saturating_sub(policy.spent_total)),
            spent_today: policy.spent_today,
            spent_this_month: policy.spent_this_month,
            spent_total: policy.spent_total,
            per_transaction: policy.limits.per_transaction,
            paused: false,
        })
    }

    /// The single policy, when there is exactly one — so the common
    /// one-wallet-one-agent case needs no id passed around.
    pub fn sole_policy_id(&self) -> Option<String> {
        if self.policies.len() == 1 { self.policies.keys().next().cloned() } else { None }
    }

    pub fn policy_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.policies.keys().cloned().collect();
        ids.sort();
        ids
    }

    /// Resolve a session token to its policy, for tools that hold only a token.
    pub fn policy_id_for_session(&self, token: &str) -> Option<String> {
        self.sessions.get(token).map(|s| s.policy_id.clone())
    }

    /// The policy in human terms. Read-only for the owner: no session needed,
    /// nothing is spent. Takes `&mut self` only to roll the spend windows over
    /// before reporting them, so the numbers are not a day stale.
    pub fn describe(&mut self, policy_id: &str) -> anyhow::Result<PolicyDescription> {
        let now = now_secs();
        let live: Vec<u64> = self
            .sessions
            .values()
            .filter(|s| s.policy_id == policy_id && s.expires_at > now)
            .map(|s| s.expires_at - now)
            .collect();
        let policy = self
            .policies
            .get_mut(policy_id)
            .ok_or_else(|| anyhow::anyhow!("policy `{policy_id}` not found"))?;
        Self::rollover(policy);

        let remaining_day = policy.limits.per_day.saturating_sub(policy.spent_today);
        let remaining_month =
            policy.limits.per_month.map(|m| m.saturating_sub(policy.spent_this_month));
        let remaining_total =
            policy.limits.total_budget.map(|t| t.saturating_sub(policy.spent_total));
        let session_expires_in_seconds = live.iter().copied().max();
        let allowed_recipient_count = policy.allowed_recipients.as_ref().map(|r| r.len());

        // One sentence an agent can be onboarded with, in the same order an
        // owner thinks about it: per payment, per day, per month, to whom, how.
        let mut summary = format!(
            "This agent may spend up to {} per payment, {} per day",
            fmt_psy(policy.limits.per_transaction),
            fmt_psy(policy.limits.per_day),
        );
        if let Some(m) = policy.limits.per_month {
            summary.push_str(&format!(", {} per 30 days", fmt_psy(m)));
        }
        if let Some(t) = policy.limits.total_budget {
            summary.push_str(&format!(", {} in total for the lifetime of this policy", fmt_psy(t)));
        }
        summary.push_str(&match allowed_recipient_count {
            None => ", to any recipient".to_string(),
            Some(0) => ", to NO approved recipients (outbound payments are blocked; claims still work)".to_string(),
            Some(1) => ", to 1 approved recipient".to_string(),
            Some(n) => format!(", to {n} approved recipients"),
        });
        summary.push_str(&format!(", via methods {}.", policy.allowed_methods.join(", ")));
        if !policy.active {
            summary.push_str(" The policy is PAUSED by the owner — every spend is denied until resume_policy.");
        }
        match session_expires_in_seconds {
            Some(secs) => summary.push_str(&format!(" Session expires in {} minutes.", secs.div_ceil(60))),
            None => summary.push_str(" No live session — the agent cannot spend until the owner calls issue_session."),
        }
        summary.push_str(" Owner can pause_policy at any time.");

        Ok(PolicyDescription {
            policy_id: policy_id.to_string(),
            agent_id: policy.agent_id.clone(),
            active: policy.active,
            per_transaction_nano: policy.limits.per_transaction,
            per_day_nano: policy.limits.per_day,
            per_month_nano: policy.limits.per_month,
            total_budget_nano: policy.limits.total_budget,
            spent_today_nano: policy.spent_today,
            spent_this_month_nano: policy.spent_this_month,
            spent_total_nano: policy.spent_total,
            remaining_day_nano: remaining_day,
            remaining_month_nano: remaining_month,
            remaining_total_nano: remaining_total,
            allowed_recipient_count,
            allowed_methods: policy.allowed_methods.clone(),
            active_sessions: live.len(),
            session_expires_in_seconds,
            summary,
        })
    }

    /// The authorized spends this server approved, newest first. Owner-side
    /// audit: it reflects DECISIONS, which is why it is kept here and not read
    /// back from the indexer (a spend can be authorized and then fail to
    /// submit — the indexer would never show it, but the owner should see it).
    pub fn spend_log(&self, limit: usize, policy_id: Option<&str>) -> Vec<SpendRecord> {
        let now = now_secs();
        self.spend_log
            .iter()
            .rev()
            .filter(|r| policy_id.is_none_or(|id| r.policy_id == id))
            .take(limit)
            .map(|r| {
                let mut r = r.clone();
                r.age_seconds = now.saturating_sub(r.timestamp);
                r
            })
            .collect()
    }

    /// How many entries the in-memory ring still holds (capped) — readers use
    /// this so a truncated view cannot be mistaken for a complete history.
    pub fn spend_log_len(&self) -> usize {
        self.spend_log.len()
    }

    /// The blocked attempts, newest first — what the agent TRIED and why your
    /// rules stopped it. Owner-side; pairs with `spend_log` to form the full
    /// "what did my agent do" picture.
    pub fn denied_log(&self, limit: usize, policy_id: Option<&str>) -> Vec<DeniedRecord> {
        let now = now_secs();
        self.denied_log
            .iter()
            .rev()
            .filter(|r| policy_id.is_none_or(|id| r.policy_id == id))
            .take(limit)
            .map(|r| {
                let mut r = r.clone();
                r.age_seconds = now.saturating_sub(r.timestamp);
                r
            })
            .collect()
    }

    /// Resolve a session, RECORDING a blocked attempt when it cannot be used.
    ///
    /// The session-level refusals used to bail before `record_denial` ever ran,
    /// so the single highest-signal scenario in the product — the owner hits
    /// Revoke and the agent keeps hammering `transfer` — produced ZERO rows in
    /// `get_blocked`, and the tool then told the owner "Nothing has been
    /// blocked — every attempt so far was within your rules." An attempt the
    /// wallet refused is exactly what the owner needs to see, whether the
    /// refusal came from a cap or from a dead token.
    ///
    /// The reasons are human and say what to do, matching the policy-level
    /// ones. `policy_id` is "-" when the token names no policy we can find;
    /// `get_blocked`'s filter already surfaces those rows.
    fn resolve_session_or_record(
        &mut self,
        token: &str,
        primary: &str,
        amount: u64,
        method: &str,
    ) -> anyhow::Result<Session> {
        let found = self.sessions.get(token).cloned();
        let (policy_id, agent_id, reason) = match found {
            None => (
                "-".to_string(),
                "-".to_string(),
                "this session token is not valid — it was revoked, or the server restarted \
                 (a restart revokes every session). Ask the owner for a new one."
                    .to_string(),
            ),
            Some(s) if now_secs() > s.expires_at => {
                self.sessions.remove(token);
                let agent = self
                    .policies
                    .get(&s.policy_id)
                    .map(|p| p.agent_id.clone())
                    .unwrap_or_else(|| "-".to_string());
                (
                    s.policy_id.clone(),
                    agent,
                    "this session expired — ask the owner to issue a new one with issue_session"
                        .to_string(),
                )
            }
            Some(s) if !self.policies.contains_key(&s.policy_id) => {
                let pid = s.policy_id.clone();
                (
                    pid.clone(),
                    "-".to_string(),
                    format!("the policy this session was issued under ({pid}) no longer exists on this server"),
                )
            }
            Some(s) => return Ok(s),
        };
        self.record_denial(&policy_id, &agent_id, primary, amount, method, &reason);
        anyhow::bail!("{reason}")
    }

    fn record_denial(&mut self, policy_id: &str, agent_id: &str, recipient: &str, amount: u64, method: &str, reason: &str) {
        self.denied_log.push_back(DeniedRecord {
            timestamp: now_secs(),
            age_seconds: 0,
            policy_id: policy_id.to_string(),
            agent_id: agent_id.to_string(),
            method: method.to_string(),
            recipient: recipient.to_string(),
            amount_nano: amount,
            reason: reason.to_string(),
        });
        while self.denied_log.len() > SPEND_LOG_CAPACITY {
            // Plain FIFO, deliberately. This used to prefer dropping a
            // zero-amount refusal so a row naming a real amount would survive —
            // but `amount` is chosen by the CALLER, so a flood of amount=1
            // denials matched nothing, `position` returned None, and eviction
            // fell through to `unwrap_or(0)`: exact FIFO, with the protected
            // high-value row (the oldest) evicted FIRST. The heuristic degraded
            // precisely when it was under attack.
            //
            // Any ranking over a field the agent controls is gameable by
            // construction. The only non-gameable key is arrival order, so the
            // honest move is to stop pretending the ring can be defended and
            // make its lossiness legible instead — hence the counter.
            self.denied_log.pop_front();
            self.denied_log_dropped = self.denied_log_dropped.saturating_add(1);
        }
    }


    /// Trim the spend ring, protecting the owner's record of REAL payments.
    ///
    /// Plain FIFO made the audit trail agent-erasable. Every authorization
    /// writes a row — including the amount-0 claim gates and refunded attempts,
    /// neither of which moved money and neither of which needs funds or chain
    /// success. So roughly a hundred deliberately-failed calls evicted every
    /// genuine payment from the only history the owner has, and the dashboard
    /// Activity page reads exactly this log.
    ///
    /// So when the ring is over capacity, drop the oldest row that did NOT move
    /// money first — a zero-amount gate, or an attempt that was refunded. Only
    /// when every row is a real payment does the oldest real one go, which is
    /// the honest bounded-memory behaviour.
    fn evict_spend_log(log: &mut VecDeque<SpendRecord>, dropped: &mut u64) {
        while log.len() > SPEND_LOG_CAPACITY {
            let victim = log
                .iter()
                .position(|r| r.amount_nano == 0 || r.refunded)
                .unwrap_or(0);
            log.remove(victim);
            *dropped = dropped.saturating_add(1);
        }
    }

    /// Rows the spend ring has dropped. Non-zero means `spend_log` is a
    /// TRUNCATED view, which a reader must not present as a full history.
    pub fn spend_log_dropped(&self) -> u64 {
        self.spend_log_dropped
    }

    /// Rows the denied ring has dropped — see `record_denial` for why this is
    /// the honest answer rather than a cleverer eviction rule.
    pub fn denied_log_dropped(&self) -> u64 {
        self.denied_log_dropped
    }

    /// How many blocked attempts the ring still holds.
    pub fn denied_log_len(&self) -> usize {
        self.denied_log.len()
    }

    fn record_spend(&mut self, auth: &Authorization, recipient: &str, amount: u64, method: &str) -> u64 {
        // A successful authorization changed the spent counters — persist them
        // so a restart cannot re-grant the lifetime budget.
        self.save();
        let id = self.next_spend_id;
        self.next_spend_id = self.next_spend_id.wrapping_add(1);
        self.spend_log.push_back(SpendRecord {
            id,
            refunded: false,
            timestamp: now_secs(),
            age_seconds: 0,
            policy_id: auth.policy_id.clone(),
            agent_id: auth.agent_id.clone(),
            method: method.to_string(),
            recipient: recipient.to_string(),
            amount_nano: amount,
        });
        Self::evict_spend_log(&mut self.spend_log, &mut self.spend_log_dropped);
        id
    }

    /// Authorize a spend below the model. Records the spend on approval; returns
    /// a human-readable reason on any denial. This is the security boundary.
    pub fn authorize(&mut self, token: &str, recipient: &str, amount: u64, method: &str) -> anyhow::Result<Authorization> {
        self.authorize_aliases(token, &[recipient], amount, method)
    }

    /// Same gate, for a payee the caller knows by more than one identifier — the
    /// x402 case, where one request yields both the seller's HOST and the user
    /// id its 402 challenge demands payment to. Both names come from the same
    /// response, so allowlisting either one is an owner approving that payee;
    /// an attacker-controlled host still fails on the host AND on its own id.
    pub fn authorize_aliases(
        &mut self,
        token: &str,
        recipients: &[&str],
        amount: u64,
        method: &str,
    ) -> anyhow::Result<Authorization> {
        // Held until this function returns: the paused/limit CHECK below and the
        // counter COMMIT in record_spend must see, and write, the same state.
        let _guard = self.lock_and_reload();
        let primary = recipients.first().copied().unwrap_or("");
        let session = self.resolve_session_or_record(token, primary, amount, method)?;
        // A policy governs ONE wallet. If the process has swapped identity under
        // it, refuse — and record the attempt, since it is exactly the shape of
        // an agent pointing at another of the owner's key backups.
        if let Some(reason) = self.bind_or_reject(&session.policy_id) {
            let agent = self.policies.get(&session.policy_id).map(|p| p.agent_id.clone()).unwrap_or_default();
            self.record_denial(&session.policy_id, &agent, primary, amount, method, &reason);
            anyhow::bail!("{reason}");
        }
        let policy = self
            .policies
            .get_mut(&session.policy_id)
            .expect("resolve_session_or_record guarantees the policy exists");
        let agent_id = policy.agent_id.clone();
        let policy_id = session.policy_id.clone();
        Self::rollover(policy);
        // Every gate — paused / method / recipient / the four caps — is computed
        // once (denial_reason) so the exact human, PSY-denominated sentence the
        // caller receives is ALSO recorded as a blocked attempt the owner can
        // review. The reason strings and their order are unchanged, so callers
        // and tests that branch on the cap keywords still work.
        if let Some(reason) = denial_reason(policy, recipients, amount, method) {
            self.record_denial(&policy_id, &agent_id, primary, amount, method, &reason);
            anyhow::bail!("{reason}");
        }
        // Session-lifetime cap: judged on the SAME locked state as the policy
        // counters, and committed below together with them — two spends racing
        // through one token both see the post-first-commit total.
        if let Some(budget) = session.session_budget {
            let projected = session.session_spent.saturating_add(amount);
            if projected > budget {
                let reason = format!(
                    "this payment of {} would exhaust the session: {} already authorized this session, the session cap is {} ({} left)",
                    fmt_psy(amount), fmt_psy(session.session_spent), fmt_psy(budget), fmt_psy(budget.saturating_sub(session.session_spent))
                );
                self.record_denial(&policy_id, &agent_id, primary, amount, method, &reason);
                anyhow::bail!("{reason}");
            }
        }
        let policy = self.policies.get_mut(&policy_id).expect("policy present after denial check");
        policy.spent_today = policy
            .spent_today
            .checked_add(amount)
            .ok_or_else(|| anyhow!("daily spend counter would overflow"))?;
        policy.spent_this_month = policy
            .spent_this_month
            .checked_add(amount)
            .ok_or_else(|| anyhow!("monthly spend counter would overflow"))?;
        policy.spent_total = policy
            .spent_total
            .checked_add(amount)
            .ok_or_else(|| anyhow!("lifetime spend counter would overflow"))?;
        // Commit the session-lifetime counter together with the policy ones —
        // the cap above was judged on this same locked state.
        if let Some(s) = self.sessions.get_mut(token) {
            s.session_spent = s.session_spent.saturating_add(amount);
        }
        let mut auth = Authorization {
            policy_id: session.policy_id.clone(),
            agent_id: policy.agent_id.clone(),
            session_token: token.to_string(),
            spend_ids: Vec::new(),
        };
        let id = self.record_spend(&auth, primary, amount, method);
        auth.spend_ids.push(id);
        Ok(auth)
    }

    /// Authorize a BATCH of payments as one all-or-nothing decision.
    ///
    /// The reason this cannot be a loop over `authorize()`: that method commits
    /// the spend as a side effect of approving it. Looping would charge the
    /// agent's daily, 30-day and lifetime budgets for the first K payments and
    /// then refuse payment K+1, leaving budget consumed by payments that never
    /// happened and that the owner can never account for.
    ///
    /// So the whole batch is evaluated against a scratch copy of the policy
    /// first, and the real counters move only if every leg passes. On any
    /// refusal nothing is spent and nothing is committed.
    ///
    /// A refused leg does NOT advance the scratch counters — it would not have
    /// spent anything — so later legs are judged against the budget that would
    /// really be left, and one over-cap payment cannot cascade into a page of
    /// spurious refusals for everything behind it.
    ///
    /// Unlike the Mode-A wallet's batch, a repeated recipient is allowed here:
    /// that rule exists there to catch a human typing the same payee twice,
    /// whereas an agent paying one payee for two separate items is ordinary.
    /// The caps still bound the total either way.
    pub fn authorize_batch(
        &mut self,
        token: &str,
        legs: &[(&str, u64)],
        method: &str,
    ) -> anyhow::Result<Authorization> {
        let _guard = self.lock_and_reload();
        // Resolve the session BEFORE the shape checks, so a refusal of either
        // kind is recorded rather than vanishing.
        let batch_primary = legs.first().map(|(r, _)| *r).unwrap_or("");
        let batch_total: u64 = legs.iter().map(|(_, a)| *a).fold(0u64, |x, y| x.saturating_add(y));
        let session = self.resolve_session_or_record(token, batch_primary, batch_total, method)?;
        if let Some(reason) = self.bind_or_reject(&session.policy_id) {
            let agent = self.policies.get(&session.policy_id).map(|p| p.agent_id.clone()).unwrap_or_default();
            self.record_denial(&session.policy_id, &agent, batch_primary, batch_total, method, &reason);
            anyhow::bail!("{reason}");
        }
        let policy_id = session.policy_id.clone();
        let agent_for_shape = self
            .policies
            .get(&policy_id)
            .map(|p| p.agent_id.clone())
            .unwrap_or_else(|| "-".to_string());

        if legs.is_empty() {
            let reason = "a batch payment needs at least one payment in it".to_string();
            self.record_denial(&policy_id, &agent_for_shape, "", 0, method, &reason);
            anyhow::bail!("{reason}");
        }
        if legs.len() > MAX_BATCH_PAYMENTS {
            let reason = format!(
                "nothing was sent. a batch can hold up to {MAX_BATCH_PAYMENTS} payments, this one has {}",
                legs.len()
            );
            self.record_denial(&policy_id, &agent_for_shape, batch_primary, batch_total, method, &reason);
            anyhow::bail!("{reason}");
        }
        {
            let policy = self
                .policies
                .get_mut(&policy_id)
                .expect("resolve_session_or_record guarantees the policy exists");
            Self::rollover(policy);
        }
        let policy = self.policies.get(&policy_id).expect("policy present after rollover").clone();
        let agent_id = policy.agent_id.clone();

        let mut scratch = policy;
        // Session-lifetime cap applies to the batch as a whole — the same
        // all-or-nothing rule as the policy caps: a batch that would exhaust the
        // session is refused before any leg commits.
        if let Some(budget) = session.session_budget {
            let projected = session.session_spent.saturating_add(batch_total);
            if projected > budget {
                let reason = format!(
                    "nothing was sent. this batch of {} would exhaust the session: {} already authorized this session, the session cap is {} ({} left)",
                    fmt_psy(batch_total), fmt_psy(session.session_spent), fmt_psy(budget), fmt_psy(budget.saturating_sub(session.session_spent))
                );
                self.record_denial(&policy_id, &agent_id, batch_primary, batch_total, method, &reason);
                anyhow::bail!("{reason}");
            }
        }
        let mut denials: Vec<(usize, String, u64, String)> = Vec::new();
        for (i, (recipient, amount)) in legs.iter().enumerate() {
            if let Some(reason) = denial_reason(&scratch, &[*recipient], *amount, method) {
                denials.push((i, (*recipient).to_string(), *amount, reason));
                continue;
            }
            scratch.spent_today = scratch
                .spent_today
                .checked_add(*amount)
                .expect("denial_reason already verified this addition does not overflow");
            scratch.spent_this_month = scratch
                .spent_this_month
                .checked_add(*amount)
                .expect("denial_reason already verified this addition does not overflow");
            scratch.spent_total = scratch
                .spent_total
                .checked_add(*amount)
                .expect("denial_reason already verified this addition does not overflow");
        }

        if !denials.is_empty() {
            // Record each refusal so the owner sees it in the blocked-attempts
            // view, exactly as they would for a single refused payment.
            for (_, recipient, amount, reason) in &denials {
                self.record_denial(&policy_id, &agent_id, recipient, *amount, method, reason);
            }
            let detail = denials
                .iter()
                .map(|(i, recipient, amount, reason)| {
                    format!("payment {} of {} to {recipient} — {reason}", i + 1, fmt_psy(*amount))
                })
                .collect::<Vec<_>>()
                .join("; ");
            anyhow::bail!(
                "nothing was sent. {} of {} payments in this batch were refused: {detail}",
                denials.len(),
                legs.len()
            );
        }

        let committed = (scratch.spent_today, scratch.spent_this_month, scratch.spent_total);
        {
            let policy = self.policies.get_mut(&policy_id).expect("policy present after denial check");
            policy.spent_today = committed.0;
            policy.spent_this_month = committed.1;
            policy.spent_total = committed.2;
        }
        if let Some(s) = self.sessions.get_mut(token) {
            s.session_spent = s.session_spent.saturating_add(batch_total);
        }
        let mut auth = Authorization { policy_id: policy_id.clone(), agent_id, session_token: token.to_string(), spend_ids: Vec::new() };
        for (recipient, amount) in legs {
            let id = self.record_spend(&auth, recipient, *amount, method);
            auth.spend_ids.push(id);
        }
        Ok(auth)
    }
}

/// Test-only clock/session manipulation. Time-dependent gates (the tumbling
/// day/30-day buckets, the session TTL) cannot be exercised by sleeping, so
/// tests move the stored bucket instead of the wall clock. Compiled out of the
/// shipped binary.
#[cfg(test)]
impl PolicyEngine {
    /// Make every policy's stored day bucket look like yesterday, so the next
    /// `rollover()` treats the following call as happening on a new day.
    pub fn force_day_rollover_for_test(&mut self) {
        for p in self.policies.values_mut() {
            p.last_day = p.last_day.saturating_sub(1);
        }
    }

    /// Same for the 30-day bucket. A new period is always also a new day, so
    /// both are moved.
    pub fn force_period_rollover_for_test(&mut self) {
        for p in self.policies.values_mut() {
            p.last_day = p.last_day.saturating_sub(1);
            p.last_month = p.last_month.saturating_sub(1);
        }
    }

    /// Age a session past its expiry without sleeping.
    pub fn expire_session_for_test(&mut self, token: &str) {
        if let Some(s) = self.sessions.get_mut(token) {
            s.expires_at = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A policy with wide caps, so a test that is not about caps never trips one.
    fn open_limits() -> Limits {
        Limits {
            per_transaction: 1_000_000_000_000,
            per_day: 1_000_000_000_000,
            per_month: None,
            total_budget: None,
        }
    }

    /// Engine with one policy and one live session; returns (engine, policy, token).
    fn engine_with(limits: Limits, recipients: Option<Vec<String>>) -> (PolicyEngine, String, String) {
        let mut e = PolicyEngine::new();
        let pid = e.create_policy("agent-1", limits, recipients, vec![]);
        let (token, _) = e.issue_session(&pid, 60, None).unwrap();
        (e, pid, token)
    }

    // ── recipient allowlist ───────────────────────────────────────────

    #[test]
    fn no_allowlist_permits_any_recipient() {
        let (mut e, _, t) = engine_with(open_limits(), None);
        assert!(e.authorize(&t, "1234", 1, "simple_transfer").is_ok());
        assert!(e.authorize(&t, "0xdeadbeef", 1, "private_transfer").is_ok());
    }

    #[test]
    fn allowlist_permits_listed_and_denies_the_rest() {
        let (mut e, _, t) = engine_with(open_limits(), Some(vec!["1234".into(), "5678".into()]));
        assert!(e.authorize(&t, "1234", 1, "simple_transfer").is_ok());
        let err = e.authorize(&t, "9999", 1, "simple_transfer").unwrap_err().to_string();
        assert!(err.contains("9999"), "the denial must name the attempted recipient: {err}");
        assert!(err.contains('2'), "the denial states the allowlist SIZE: {err}");
        assert!(!err.contains("5678"), "the denial must not leak the allowlist itself: {err}");
    }

    #[test]
    fn an_empty_allowlist_blocks_every_outbound_payment() {
        // Some(vec![]) is a real instruction ("pay nobody"), distinct from None.
        let (mut e, _, t) = engine_with(open_limits(), Some(vec![]));
        assert!(e.authorize(&t, "1234", 1, "simple_transfer").is_err());
        // ...but funds coming IN are unaffected.
        assert!(e.authorize(&t, SELF_RECIPIENT, 0, "simple_claim").is_ok());
    }

    #[test]
    fn claims_are_never_blocked_by_the_recipient_allowlist() {
        let (mut e, _, t) = engine_with(open_limits(), Some(vec!["1234".into()]));
        assert!(e.authorize(&t, SELF_RECIPIENT, 0, "simple_claim").is_ok());
        assert!(e.authorize(&t, SELF_RECIPIENT, 0, "private_claim").is_ok());
        assert!(e.authorize(&t, SELF_RECIPIENT, 0, "claim_deposit").is_ok());
    }

    #[test]
    fn allowlist_matches_across_identifier_spellings() {
        let (mut e, _, t) = engine_with(
            open_limits(),
            Some(vec![
                "Psy-00001234".into(),
                "0xDEADBEEF".into(),
                "https://api.example.com/paid/thing".into(),
            ]),
        );
        assert!(e.authorize(&t, "1234", 1, "simple_transfer").is_ok(), "Psy-id entry vs raw user id");
        assert!(e.authorize(&t, "deadbeef", 1, "private_transfer").is_ok(), "0x-prefixed vs bare hex");
        assert!(
            e.authorize_aliases(&t, &["999", "api.example.com"], 1, "simple_transfer").is_ok(),
            "an x402 host alias satisfies a URL entry even though the payee id is unlisted"
        );
        assert!(
            e.authorize_aliases(&t, &["999", "evil.example.com"], 1, "simple_transfer").is_err(),
            "a different host with an unlisted payee id is still denied"
        );
    }

    #[test]
    fn normalization_collapses_equivalent_spellings() {
        assert_eq!(normalize_recipient("Psy-00001234"), "1234");
        assert_eq!(normalize_recipient(" psy-1234 "), "1234");
        assert_eq!(normalize_recipient("Psy-00000000"), "0");
        assert_eq!(normalize_recipient("0001234"), "1234");
        assert_eq!(normalize_recipient("0xDeAdBeEf"), "deadbeef");
        assert_eq!(normalize_recipient("https://api.example.com/v1/x?y=1"), "api.example.com");
        assert_eq!(normalize_recipient("http://user:pw@API.example.com/x"), "api.example.com");
        assert_eq!(
            normalize_recipient("http://localhost:8402/paid"),
            "localhost:8402",
            "the port distinguishes two local sellers and must survive"
        );
        assert_eq!(normalize_recipient("Psy-abc"), "psy-abc", "a non-numeric Psy id is left alone");
    }

    // ── monthly budget ────────────────────────────────────────────────

    #[test]
    fn monthly_cap_denies_once_the_period_is_exhausted() {
        // Whole-PSY amounts so the denial (which speaks PSY, not Nano) reads
        // naturally and the human-facing figures are asserted directly.
        const PSY: u64 = 1_000_000_000;
        let limits = Limits { per_month: Some(150 * PSY), ..open_limits() };
        let (mut e, _, t) = engine_with(limits, None);
        assert!(e.authorize(&t, "1", 100 * PSY, "simple_transfer").is_ok());
        let err = e.authorize(&t, "1", 100 * PSY, "simple_transfer").unwrap_err().to_string();
        assert!(err.contains("30-day cap"), "{err}");
        assert!(err.contains("100 PSY") && err.contains("150 PSY"), "states attempt and limit in PSY: {err}");
        assert!(e.authorize(&t, "1", 50 * PSY, "simple_transfer").is_ok(), "exactly at the cap is allowed");
    }

    #[test]
    fn no_monthly_cap_means_only_the_daily_one_applies() {
        let limits = Limits { per_day: 100, per_month: None, ..open_limits() };
        let (mut e, _, t) = engine_with(limits, None);
        assert!(e.authorize(&t, "1", 100, "simple_transfer").is_ok());
        assert!(e.authorize(&t, "1", 1, "simple_transfer").is_err(), "daily cap still binds");
    }

    #[test]
    fn monthly_window_rolls_over_when_the_bucket_changes() {
        let limits = Limits { per_month: Some(100), ..open_limits() };
        let (mut e, pid, t) = engine_with(limits, None);
        e.authorize(&t, "1", 100, "simple_transfer").unwrap();
        assert!(e.authorize(&t, "1", 1, "simple_transfer").is_err(), "exhausted within the period");

        // Pretend the wall clock crossed into the next 30-day bucket (and the
        // next day) — the same thing `rollover` sees at midnight/period end.
        {
            let p = e.policies.get_mut(&pid).unwrap();
            p.last_month -= 1;
            p.last_day -= 1;
        }
        assert!(e.authorize(&t, "1", 100, "simple_transfer").is_ok(), "a new period restores the budget");
        let d = e.describe(&pid).unwrap();
        assert_eq!(d.spent_this_month_nano, 100, "the new period counts only its own spend");
        assert_eq!(d.spent_total_nano, 200, "the lifetime total never rolls over");
    }

    #[test]
    fn month_index_advances_exactly_every_thirty_days() {
        // Guards the constant itself: a typo here would silently widen budgets.
        assert_eq!(MONTH_SECS, 30 * DAY_SECS);
        assert_eq!(2_592_000 / DAY_SECS, 30);
    }

    // ── describe ──────────────────────────────────────────────────────

    #[test]
    fn describe_reads_as_a_human_sentence() {
        let limits = Limits {
            per_transaction: 100_000_000,       // 0.1 PSY
            per_day: 1_000_000_000,             // 1 PSY
            per_month: Some(20_000_000_000),    // 20 PSY
            total_budget: None,
        };
        let (mut e, pid, _t) = engine_with(
            limits,
            Some(vec!["1".into(), "2".into(), "3".into()]),
        );
        let d = e.describe(&pid).unwrap();
        assert!(d.summary.contains("0.1 PSY per payment"), "{}", d.summary);
        assert!(d.summary.contains("1 PSY per day"), "{}", d.summary);
        assert!(d.summary.contains("20 PSY per 30 days"), "{}", d.summary);
        assert!(d.summary.contains("3 approved recipients"), "{}", d.summary);
        assert!(d.summary.contains("simple_transfer"), "the method list is named: {}", d.summary);
        assert!(d.summary.contains("Session expires in 60 minutes"), "{}", d.summary);
        assert!(d.summary.contains("pause_policy"), "{}", d.summary);
        assert_eq!(d.allowed_recipient_count, Some(3));
        assert_eq!(d.active_sessions, 1);
        assert_eq!(d.remaining_month_nano, Some(20_000_000_000));
    }

    #[test]
    fn describe_says_when_there_is_no_session_and_when_paused() {
        let mut e = PolicyEngine::new();
        let pid = e.create_policy("agent-1", open_limits(), None, vec![]);
        let d = e.describe(&pid).unwrap();
        assert!(d.summary.contains("No live session"), "{}", d.summary);
        assert!(d.summary.contains("to any recipient"), "{}", d.summary);
        assert_eq!(d.allowed_recipient_count, None);

        e.pause(&pid);
        let d = e.describe(&pid).unwrap();
        assert!(d.summary.contains("PAUSED"), "{}", d.summary);
        assert!(!d.active);
        assert!(e.describe("nope").is_err(), "an unknown policy id is an error, not an empty policy");
    }

    #[test]
    fn describe_reflects_spend_as_it_happens() {
        let limits = Limits { per_day: 1_000, per_month: Some(2_000), total_budget: Some(3_000), ..open_limits() };
        let (mut e, pid, t) = engine_with(limits, None);
        e.authorize(&t, "1", 400, "simple_transfer").unwrap();
        let d = e.describe(&pid).unwrap();
        assert_eq!(d.spent_today_nano, 400);
        assert_eq!(d.remaining_day_nano, 600);
        assert_eq!(d.remaining_month_nano, Some(1_600));
        assert_eq!(d.remaining_total_nano, Some(2_600));
    }

    #[test]
    fn amount_formatting_is_readable() {
        assert_eq!(fmt_psy(0), "0 PSY");
        assert_eq!(fmt_psy(1_000_000_000), "1 PSY");
        assert_eq!(fmt_psy(100_000_000), "0.1 PSY");
        assert_eq!(fmt_psy(1_500_000_000), "1.5 PSY");
        assert_eq!(fmt_psy(1), "0.000000001 PSY");
    }

    // ── spend log ─────────────────────────────────────────────────────

    #[test]
    fn spend_log_records_authorized_spends_newest_first() {
        let (mut e, pid, t) = engine_with(open_limits(), None);
        e.authorize(&t, "1234", 10, "simple_transfer").unwrap();
        e.authorize(&t, "0xdead", 20, "private_transfer").unwrap();
        let log = e.spend_log(10, None);
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].method, "private_transfer", "newest first");
        assert_eq!(log[0].amount_nano, 20);
        assert_eq!(log[0].recipient, "0xdead", "recorded as the tool passed it");
        assert_eq!(log[1].method, "simple_transfer");
        assert_eq!(log[0].policy_id, pid);
        assert_eq!(log[0].agent_id, "agent-1");
        assert!(log[0].timestamp > 0);
    }

    #[test]
    fn denied_spends_are_not_recorded_as_spends() {
        let (mut e, _, t) = engine_with(Limits { per_transaction: 5, ..open_limits() }, None);
        assert!(e.authorize(&t, "1", 500, "simple_transfer").is_err());
        assert!(e.authorize(&t, "1", 1, "nope_method").is_err());
        assert_eq!(e.spend_log(10, None).len(), 0, "the log is a record of what WAS allowed");
    }

    #[test]
    fn spend_log_is_capped_and_keeps_the_newest() {
        let (mut e, _, t) = engine_with(open_limits(), None);
        for i in 0..(SPEND_LOG_CAPACITY as u64 + 25) {
            e.authorize(&t, "1", i, "simple_transfer").unwrap();
        }
        assert_eq!(e.spend_log_len(), SPEND_LOG_CAPACITY, "the ring is bounded");
        let log = e.spend_log(1_000, None);
        assert_eq!(log.len(), SPEND_LOG_CAPACITY);
        assert_eq!(log[0].amount_nano, SPEND_LOG_CAPACITY as u64 + 24, "newest survives");
        assert_eq!(log[SPEND_LOG_CAPACITY - 1].amount_nano, 25, "oldest 25 were dropped");
    }

    #[test]
    fn spend_log_filters_by_policy_and_honours_the_limit() {
        let mut e = PolicyEngine::new();
        let a = e.create_policy("agent-a", open_limits(), None, vec![]);
        let b = e.create_policy("agent-b", open_limits(), None, vec![]);
        let (ta, _) = e.issue_session(&a, 60, None).unwrap();
        let (tb, _) = e.issue_session(&b, 60, None).unwrap();
        e.authorize(&ta, "1", 1, "simple_transfer").unwrap();
        e.authorize(&tb, "1", 2, "simple_transfer").unwrap();
        e.authorize(&ta, "1", 3, "simple_transfer").unwrap();
        assert_eq!(e.spend_log(10, Some(&a)).len(), 2);
        assert_eq!(e.spend_log(10, Some(&b)).len(), 1);
        assert_eq!(e.spend_log(1, None).len(), 1, "limit applies to the newest end");
        assert_eq!(e.spend_log(1, None)[0].amount_nano, 3);
    }

    // ── the existing gates must not have moved ────────────────────────

    #[test]
    fn existing_gates_still_deny() {
        let limits = Limits { per_transaction: 100, per_day: 150, ..open_limits() };
        let (mut e, pid, t) = engine_with(limits, None);
        assert!(e.authorize("not-a-token", "1", 1, "simple_transfer").is_err(), "unknown session");
        assert!(e.authorize(&t, "1", 101, "simple_transfer").is_err(), "per-transaction cap");
        assert!(e.authorize(&t, "1", 1, "sudo_drain").is_err(), "method allowlist");
        e.authorize(&t, "1", 100, "simple_transfer").unwrap();
        assert!(e.authorize(&t, "1", 100, "simple_transfer").is_err(), "daily cap");
        e.pause(&pid);
        assert!(e.authorize(&t, "1", 1, "simple_transfer").is_err(), "paused");
        e.resume(&pid);
        assert!(e.authorize(&t, "1", 1, "simple_transfer").is_ok());
        assert!(e.revoke(&t));
        assert!(e.authorize(&t, "1", 1, "simple_transfer").is_err(), "revoked");
    }

    #[test]
    fn an_expired_session_is_denied_and_dropped() {
        let mut e = PolicyEngine::new();
        let pid = e.create_policy("agent-1", open_limits(), None, vec![]);
        let (t, _) = e.issue_session(&pid, 60, None).unwrap();
        e.sessions.get_mut(&t).unwrap().expires_at = now_secs() - 1;
        assert!(e.authorize(&t, "1", 1, "simple_transfer").unwrap_err().to_string().contains("expired"));
        assert!(e.policy_id_for_session(&t).is_none(), "an expired token is removed, not left to leak");
        assert_eq!(e.describe(&pid).unwrap().active_sessions, 0);
    }

    #[test]
    fn policies_and_counters_survive_a_restart() {
        let dir = std::env::temp_dir().join(format!("psy-mcp-policy-test-{}", rand_hex(6)));
        let mut e = PolicyEngine::load_or_new(&dir);
        let pid = e.create_policy("a", Limits { per_transaction: 100, per_day: 1000, per_month: None, total_budget: Some(150) }, None, vec![]);
        let (t, _) = e.issue_session(&pid, 10, None).unwrap();
        e.authorize(&t, "9", 100, "simple_transfer").unwrap();

        // "Restart": a fresh engine over the same directory.
        let mut e2 = PolicyEngine::load_or_new(&dir);
        let (t2, _) = e2.issue_session(&pid, 10, None).unwrap();
        let err = e2.authorize(&t2, "9", 100, "simple_transfer").unwrap_err().to_string();
        assert!(err.contains("total budget"), "lifetime budget must survive the restart, got: {err}");
        assert!(e2.authorize(&t2, "9", 50, "simple_transfer").is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn update_policy_tightens_a_limit_in_place_without_touching_spend_or_session() {
        const PSY: u64 = 1_000_000_000;
        let mut e = PolicyEngine::new();
        let pid = e.create_policy("shopper",
            Limits { per_transaction: 10 * PSY, per_day: 100 * PSY, per_month: None, total_budget: None },
            None, vec![]);
        let (t, _) = e.issue_session(&pid, 60, None).unwrap();
        // Spend a little, then the owner tightens the per-payment cap.
        e.authorize(&t, "1908736", 3 * PSY, "simple_transfer").unwrap();
        e.update_policy(&pid, Some(2 * PSY), Some(100 * PSY), None, None,
            Some(Some(vec!["Psy-01908736".into()])), vec![]).unwrap();
        // The SAME live session now binds to the new cap immediately...
        let err = e.authorize(&t, "1908736", 5 * PSY, "simple_transfer").unwrap_err().to_string();
        assert!(err.contains("per-transaction cap"), "the tightened cap binds on the live session: {err}");
        // ...the recipient allow-list took effect (normalized)...
        assert!(e.authorize(&t, "1908736", 1 * PSY, "simple_transfer").is_ok(), "approved recipient still works");
        assert!(e.authorize(&t, "630784", 1 * PSY, "simple_transfer").is_err(), "an unlisted recipient is now refused");
        // ...and the already-spent counter was preserved across the edit.
        assert_eq!(e.describe(&pid).unwrap().spent_today_nano, 4 * PSY, "3 + 1 authorized (the two denials cost nothing); the edit kept the counter");
        assert!(e.update_policy("no-such-policy", None, None, None, None, None, vec![]).is_err());
    }

    #[test]
    fn an_omitted_allowlist_leaves_it_untouched_and_only_an_explicit_null_clears_it() {
        // The dashboard's "tighten my daily budget" save sends no recipient
        // field. That must NEVER widen the policy to "pay anyone" — the whole
        // point of the allow-list is that it survives unrelated edits.
        const PSY: u64 = 1_000_000_000;
        let mut e = PolicyEngine::new();
        let pid = e.create_policy("shopper",
            Limits { per_transaction: 5 * PSY, per_day: 50 * PSY, per_month: None, total_budget: None },
            Some(vec!["1908736".into()]), vec![]);
        let (t, _) = e.issue_session(&pid, 60, None).unwrap();

        // Budget-only edit: recipients omitted (None).
        e.update_policy(&pid, Some(2 * PSY), Some(10 * PSY), None, None, None, vec![]).unwrap();
        assert_eq!(e.describe(&pid).unwrap().allowed_recipient_count, Some(1), "the allow-list survived an unrelated edit");
        assert!(e.authorize(&t, "630784", 1 * PSY, "simple_transfer").is_err(), "an unlisted payee is still refused");

        // Explicit clear: Some(None) → pay anyone.
        e.update_policy(&pid, Some(2 * PSY), Some(10 * PSY), None, None, Some(None), vec![]).unwrap();
        assert_eq!(e.describe(&pid).unwrap().allowed_recipient_count, None, "an explicit null clears the list");
        assert!(e.authorize(&t, "630784", 1 * PSY, "simple_transfer").is_ok(), "now anyone may be paid");
    }

    #[test]
    fn blocked_attempts_are_recorded_with_the_reason_the_caller_saw() {
        const PSY: u64 = 1_000_000_000;
        let mut e = PolicyEngine::new();
        let pid = e.create_policy("shopper",
            Limits { per_transaction: 5 * PSY, per_day: 50 * PSY, per_month: None, total_budget: None },
            Some(vec!["1908736".into()]), vec![]);
        let (t, _) = e.issue_session(&pid, 60, None).unwrap();
        // An over-cap attempt to an approved payee, and an approved-size attempt
        // to an UNapproved payee — both refused, both recorded.
        let over = e.authorize(&t, "1908736", 8 * PSY, "simple_transfer").unwrap_err().to_string();
        let off = e.authorize(&t, "630784", 1 * PSY, "simple_transfer").unwrap_err().to_string();
        assert!(over.contains("per-transaction cap"));
        assert!(off.contains("allowlist"));
        let blocked = e.denied_log(10, None);
        assert_eq!(blocked.len(), 2, "both blocked attempts recorded");
        // Newest first: the allowlist denial is [0].
        assert_eq!(blocked[0].amount_nano, 1 * PSY);
        assert!(blocked[0].reason.contains("allowlist"), "the recorded reason matches what the caller saw");
        assert_eq!(blocked[1].amount_nano, 8 * PSY);
        assert!(blocked[1].reason.contains("per-transaction cap"));
        // A successful spend is NOT in the blocked log.
        e.authorize(&t, "1908736", 2 * PSY, "simple_transfer").unwrap();
        assert_eq!(e.denied_log(10, None).len(), 2, "an allowed spend does not add a blocked row");
    }

    #[test]
    fn refund_restores_headroom_but_not_the_log() {
        let mut e = PolicyEngine::new();
        let pid = e.create_policy("a", Limits { per_transaction: 100, per_day: 100, per_month: Some(100), total_budget: Some(100) }, None, vec![]);
        let (t, _) = e.issue_session(&pid, 10, None).unwrap();
        let auth = e.authorize(&t, "9", 100, "simple_transfer").unwrap();
        assert!(e.authorize(&t, "9", 1, "simple_transfer").is_err(), "budget exhausted");
        e.refund(&auth, 100);
        assert!(e.authorize(&t, "9", 100, "simple_transfer").is_ok(), "headroom restored");
        assert_eq!(e.spend_log(10, None).len(), 2, "both decisions stay on the log");
    }

    #[test]
    fn sole_policy_id_is_only_unambiguous_with_one_policy() {
        let mut e = PolicyEngine::new();
        assert!(e.sole_policy_id().is_none(), "no policy at all");
        let a = e.create_policy("agent-a", open_limits(), None, vec![]);
        assert_eq!(e.sole_policy_id(), Some(a.clone()));
        let b = e.create_policy("agent-b", open_limits(), None, vec![]);
        assert!(e.sole_policy_id().is_none(), "ambiguous — the caller must name one");
        assert_eq!(e.policy_ids().len(), 2);
        assert!(e.policy_ids().contains(&b));
    }

    // ── widening vs tightening ────────────────────────────────────────
    //
    // The rule that decides WHO may make an edit. Ungated, an agent reads its
    // own policy id from describe_policy and rewrites its own limits; these
    // tests pin down every link in that chain, and equally that an owner
    // tightening their own policy is never obstructed.

    fn shape() -> AuthoritySnapshot {
        AuthoritySnapshot {
            per_transaction: 5_000_000_000,
            per_day: 50_000_000_000,
            per_month: Some(100_000_000_000),
            total_budget: Some(500_000_000_000),
            allowed_recipients: Some(vec!["1234".into(), "5678".into()]),
            allowed_methods: vec!["simple_transfer".into(), "simple_claim".into()],
        }
    }

    #[test]
    fn an_empty_edit_widens_nothing() {
        assert!(widening_reason(&shape(), &AuthorityEdit::default()).is_none());
    }

    #[test]
    fn tightening_every_field_at_once_is_never_a_widening() {
        let edit = AuthorityEdit {
            per_transaction: Some(1),
            per_day: Some(2),
            per_month: Some(Some(3)),
            total_budget: Some(Some(4)),
            allowed_recipients: Some(Some(vec!["1234".into()])),
            allowed_methods: vec!["simple_claim".into()],
        };
        assert!(
            widening_reason(&shape(), &edit).is_none(),
            "an owner tightening their own policy must never be gated"
        );
    }

    #[test]
    fn raising_a_cap_widens() {
        let e = AuthorityEdit { per_transaction: Some(6_000_000_000), ..Default::default() };
        let r = widening_reason(&shape(), &e).expect("raising the per-payment cap widens");
        assert!(r.contains("per-payment"), "{r}");
        assert!(r.contains("6 PSY"), "the owner is told the new figure: {r}");

        let e = AuthorityEdit { per_day: Some(50_000_000_001), ..Default::default() };
        assert!(widening_reason(&shape(), &e).is_some(), "one Nano over the daily cap still widens");
    }

    #[test]
    fn setting_a_cap_to_its_current_value_is_not_a_widening() {
        let e = AuthorityEdit {
            per_transaction: Some(5_000_000_000),
            per_day: Some(50_000_000_000),
            ..Default::default()
        };
        assert!(widening_reason(&shape(), &e).is_none(), "a no-op resave must not need the owner");
    }

    #[test]
    fn removing_an_optional_ceiling_widens_even_though_no_number_grew() {
        let e = AuthorityEdit { total_budget: Some(None), ..Default::default() };
        let r = widening_reason(&shape(), &e).expect("dropping the lifetime ceiling widens");
        assert!(r.contains("lifetime"), "{r}");

        let e = AuthorityEdit { per_month: Some(None), ..Default::default() };
        assert!(widening_reason(&shape(), &e).is_some(), "dropping the 30-day ceiling widens");
    }

    #[test]
    fn adding_a_ceiling_where_there_was_none_is_tightening() {
        let mut cur = shape();
        cur.per_month = None;
        cur.total_budget = None;
        let e = AuthorityEdit {
            per_month: Some(Some(1_000)),
            total_budget: Some(Some(1_000)),
            ..Default::default()
        };
        assert!(
            widening_reason(&cur, &e).is_none(),
            "an owner adding the ceiling that was missing must not be blocked by the gate meant to protect them"
        );
    }

    #[test]
    fn clearing_the_allowlist_widens() {
        let e = AuthorityEdit { allowed_recipients: Some(None), ..Default::default() };
        let r = widening_reason(&shape(), &e).expect("pay-anyone is the widest edit there is");
        assert!(r.contains("anyone"), "{r}");
    }

    #[test]
    fn approving_a_new_recipient_widens_but_removing_one_does_not() {
        let e = AuthorityEdit {
            allowed_recipients: Some(Some(vec!["1234".into(), "5678".into(), "9999".into()])),
            ..Default::default()
        };
        assert!(widening_reason(&shape(), &e).is_some(), "a third payee is new authority");

        let e = AuthorityEdit {
            allowed_recipients: Some(Some(vec!["1234".into()])),
            ..Default::default()
        };
        assert!(widening_reason(&shape(), &e).is_none(), "dropping a payee is tightening");
    }

    #[test]
    fn a_respelled_recipient_is_not_mistaken_for_a_new_one() {
        // The stored list is normalized; the owner types what they recognise.
        let e = AuthorityEdit {
            allowed_recipients: Some(Some(vec!["Psy-00001234".into(), "5678".into()])),
            ..Default::default()
        };
        assert!(
            widening_reason(&shape(), &e).is_none(),
            "re-saving the same allow-list in owner spelling must not read as a widening"
        );
    }

    #[test]
    fn an_allowlist_where_there_was_none_is_tightening() {
        let mut cur = shape();
        cur.allowed_recipients = None; // pay anyone — the default
        let e = AuthorityEdit {
            allowed_recipients: Some(Some(vec!["1234".into()])),
            ..Default::default()
        };
        assert!(widening_reason(&cur, &e).is_none(), "narrowing from anyone to one payee");
    }

    #[test]
    fn allowing_a_new_method_widens_and_names_it() {
        let e = AuthorityEdit { allowed_methods: vec!["withdraw".into()], ..Default::default() };
        let r = widening_reason(&shape(), &e).expect("withdraw was not previously allowed");
        assert!(r.contains("withdraw"), "the owner must see WHICH action: {r}");
    }

    #[test]
    fn an_empty_method_list_means_unchanged_not_everything() {
        // create_policy reads empty as "all methods"; update_policy reads it as
        // "leave alone". The widening check must follow update's meaning, or
        // every allow-list-only edit would be gated as if it granted all eight.
        let e = AuthorityEdit {
            allowed_recipients: Some(Some(vec!["1234".into()])),
            ..Default::default()
        };
        assert!(widening_reason(&shape(), &e).is_none());
    }

    #[test]
    fn a_narrowed_method_set_is_tightening() {
        let e = AuthorityEdit { allowed_methods: vec!["simple_claim".into()], ..Default::default() };
        assert!(widening_reason(&shape(), &e).is_none(), "dropping simple_transfer is tightening");
    }

    #[test]
    fn the_full_escalation_chain_is_reported_in_one_sentence() {
        // Exactly the call a compromised model would make.
        let e = AuthorityEdit {
            per_transaction: Some(u64::MAX),
            per_day: Some(u64::MAX),
            per_month: Some(None),
            total_budget: Some(None),
            allowed_recipients: Some(None),
            allowed_methods: vec!["withdraw".into()],
        };
        let r = widening_reason(&shape(), &e).expect("this is the attack");
        for expected in ["per-payment", "daily", "30-day", "lifetime", "anyone", "withdraw"] {
            assert!(r.contains(expected), "the refusal must name `{expected}`: {r}");
        }
    }

    #[test]
    fn the_engine_agrees_with_the_pure_rule_and_reports_an_unknown_policy() {
        let mut e = PolicyEngine::new();
        let id = e.create_policy("a", open_limits(), Some(vec!["1234".into()]), vec!["simple_transfer".into()]);

        assert!(e.update_widens(&id, None, None, None, None, &None, &[]).unwrap().is_none());
        assert!(
            e.update_widens(&id, None, None, None, None, &Some(None), &[]).unwrap().is_some(),
            "clearing the allow-list through the engine widens too"
        );
        assert!(
            e.update_widens("nope", None, None, None, None, &None, &[]).is_err(),
            "an unknown policy is an argument error, not a silent permit"
        );
    }


    // ── creating a policy is the same escalation, one step left ───────
    //
    // Gating update_policy alone leaves create_wallet/mint_agent_account able
    // to mint a fresh wide policy over the SAME wallet (mode="load" reloads the
    // same key), then issue_session and spend. These pin that shut without
    // breaking the two honest cases: the first-ever creation, and re-creating
    // an equivalent policy on every dashboard restart.

    fn narrow() -> (Limits, Option<Vec<String>>, Vec<String>) {
        (
            Limits {
                per_transaction: 1_000_000_000,
                per_day: 2_000_000_000,
                per_month: Some(10_000_000_000),
                total_budget: Some(20_000_000_000),
            },
            Some(vec!["1234".into()]),
            vec!["simple_transfer".into()],
        )
    }

    #[test]
    fn the_first_policy_on_a_fresh_server_is_always_allowed() {
        let e = PolicyEngine::new();
        let (l, r, m) = narrow();
        assert!(
            e.creation_widens(&l, &r, &m).is_none(),
            "with nothing to compare against, refusing would make the server unusable rather than safe"
        );
        // Even a wide-open one: this IS the owner's setup call.
        assert!(e.creation_widens(&open_limits(), &None, &[]).is_none());
    }

    #[test]
    fn a_second_policy_may_not_reach_beyond_the_first() {
        let mut e = PolicyEngine::new();
        let (l, r, m) = narrow();
        e.create_policy("a", l, r, m);

        let wide = Limits {
            per_transaction: u64::MAX,
            per_day: u64::MAX,
            per_month: None,
            total_budget: None,
        };
        let reason = e
            .creation_widens(&wide, &None, &["simple_transfer".into()])
            .expect("this is the create_wallet bypass");
        assert!(reason.contains("per-payment"), "{reason}");
        assert!(reason.contains("anyone"), "{reason}");
    }

    #[test]
    fn recreating_an_equivalent_policy_is_allowed() {
        // The dashboard calls create_wallet on EVERY boot with the same
        // defaults; policies persist, so this must not start failing.
        let mut e = PolicyEngine::new();
        let (l, r, m) = narrow();
        e.create_policy("a", l.clone(), r.clone(), m.clone());
        assert!(e.creation_widens(&l, &r, &m).is_none());
    }

    #[test]
    fn a_narrower_second_policy_is_allowed() {
        let mut e = PolicyEngine::new();
        let (l, r, m) = narrow();
        e.create_policy("a", l, r, m);
        let tighter = Limits {
            per_transaction: 1,
            per_day: 1,
            per_month: Some(1),
            total_budget: Some(1),
        };
        assert!(e.creation_widens(&tighter, &Some(vec![]), &["simple_transfer".into()]).is_none());
    }

    #[test]
    fn it_is_enough_that_ONE_existing_policy_already_grants_this_much() {
        let mut e = PolicyEngine::new();
        let (l, r, m) = narrow();
        e.create_policy("tight", l, r, m);
        e.create_policy("loose", open_limits(), None, vec!["simple_transfer".into()]);
        let mid = Limits {
            per_transaction: 5_000_000_000,
            per_day: 5_000_000_000,
            per_month: None,
            total_budget: None,
        };
        assert!(
            e.creation_widens(&mid, &None, &["simple_transfer".into()]).is_none(),
            "the owner already granted at least this much somewhere"
        );
    }

    #[test]
    fn an_empty_method_list_at_creation_is_compared_as_ALL_methods() {
        // create_policy expands empty to the full set, so the check must too —
        // otherwise the widest possible method grant slips through as "unchanged".
        let mut e = PolicyEngine::new();
        let (l, r, _) = narrow();
        e.create_policy("a", l.clone(), r.clone(), vec!["simple_transfer".into()]);
        let reason = e
            .creation_widens(&l, &r, &[])
            .expect("empty means every method, including withdraw");
        assert!(reason.contains("withdraw"), "{reason}");
    }

    #[test]
    fn deploy_contract_is_denied_by_default_and_gated_once_allowed() {
        // Deploying puts code on chain and spends the wallet's fee. It must be
        // OFF for a fresh policy (default_methods has no deploy_contract) and
        // only become callable when the owner explicitly adds it.
        let mut e = PolicyEngine::new();
        e.set_current_user(111);
        let default_id = e.create_policy("a", open_limits(), None, vec![]);
        let (tok, _) = e.issue_session(&default_id, 60, None).unwrap();
        let err = e
            .authorize(&tok, "", 1_000_000_000, "deploy_contract")
            .expect_err("deploy_contract must not be in the default method set");
        assert!(err.to_string().contains("not allowed"), "{err}");

        // Owner explicitly allows it: one policy instance per method set.
        let mut e2 = PolicyEngine::new();
        e2.set_current_user(111);
        let id = e2.create_policy("a", open_limits(), None, vec!["deploy_contract".into()]);
        let (tok, _) = e2.issue_session(&id, 60, None).unwrap();
        let _auth = e2
            .authorize(&tok, "", 1_000_000_000, "deploy_contract")
            .expect("allowed method + within caps must pass");
        // authorize already recorded the fee as a spend (same as transfer).
        let d = e2.describe(&id).unwrap();
        assert_eq!(d.spent_today_nano, 1_000_000_000, "the deploy fee is a recorded spend");
    }

    #[test]
    fn default_methods_is_what_create_policy_actually_applies() {
        let mut e = PolicyEngine::new();
        let id = e.create_policy("a", open_limits(), None, vec![]);
        let d = e.describe(&id).unwrap();
        assert_eq!(d.allowed_methods, default_methods(), "the two must not drift");
    }

    #[test]
    fn session_total_cap_binds_across_spends_and_batches() {
        let mut e = PolicyEngine::new();
        let pid = e.create_policy("capped", Limits { per_transaction: 1_000_000_000_000, per_day: 1_000_000_000_000, per_month: None, total_budget: None }, None, vec![]);
        let (t, _) = e.issue_session(&pid, 60, Some(1_000_000_000)).unwrap();
        // First spend fits.
        e.authorize(&t, "1", 600_000_000, "simple_transfer").unwrap();
        // Second would exceed the session total — refused even though the
        // policy itself is open.
        let err = e.authorize(&t, "1", 600_000_000, "simple_transfer").unwrap_err();
        assert!(err.to_string().contains("exhaust the session"), "got: {err}");
        // The refused spend did not consume the session: exactly the remaining
        // 0.4 still passes.
        e.authorize(&t, "1", 400_000_000, "simple_transfer").unwrap();
        // And now the session is spent to the cap, one more nano is refused.
        assert!(e.authorize(&t, "1", 1, "simple_transfer").is_err());

        // A batch that would blow the remaining budget is refused whole.
        let (t2, _) = e.issue_session(&pid, 60, Some(1_000_000_000)).unwrap();
        let err = e
            .authorize_batch(&t2, &[("1", 900_000_000), ("2", 200_000_000)], "simple_transfer")
            .unwrap_err();
        assert!(err.to_string().contains("exhaust the session"), "got: {err}");
        // Nothing from the refused batch was charged.
        e.authorize(&t2, "1", 1_000_000_000, "simple_transfer").unwrap();
    }

    #[test]
    fn session_without_cap_is_bound_only_by_policy() {
        let mut e = PolicyEngine::new();
        let pid = e.create_policy("uncapped", Limits { per_transaction: 1_000_000_000_000, per_day: 1_000_000_000_000, per_month: None, total_budget: None }, None, vec![]);
        let (t, _) = e.issue_session(&pid, 60, None).unwrap();
        e.authorize(&t, "1", 5_000_000_000, "simple_transfer").unwrap();
        e.authorize(&t, "1", 5_000_000_000, "simple_transfer").unwrap();
    }

    #[test]
    fn refund_restores_the_session_budget_too() {
        // The exact shape of the live incident: a batch passes the policy and
        // session gates, then the balance pre-flight refuses it. refund() is
        // called — and must hand the SESSION budget back, not just the policy
        // counters, or every later in-cap spend is refused with "already
        // authorized this session" for money that never moved.
        let mut e = PolicyEngine::new();
        let pid = e.create_policy("capped", Limits { per_transaction: 1_000_000_000_000, per_day: 1_000_000_000_000, per_month: None, total_budget: None }, None, vec![]);
        let (t, _) = e.issue_session(&pid, 60, Some(900_000_000)).unwrap();

        let auth = e
            .authorize_batch(&t, &[("1", 450_000_000), ("2", 450_000_000)], "simple_transfer")
            .unwrap();
        e.refund(&auth, 900_000_000); // the balance gate refuses it after the policy gate

        // The full session budget is available again.
        e.authorize(&t, "1", 900_000_000, "simple_transfer").unwrap();
        // ...and is now genuinely exhausted.
        assert!(e.authorize(&t, "1", 1, "simple_transfer").is_err());

        // Same for a single transfer that fails after the gate.
        let (t2, _) = e.issue_session(&pid, 60, Some(1_000_000_000)).unwrap();
        let auth2 = e.authorize(&t2, "1", 800_000_000, "simple_transfer").unwrap();
        e.refund(&auth2, 800_000_000);
        e.authorize(&t2, "1", 1_000_000_000, "simple_transfer").unwrap();
    }

    #[test]
    fn foreign_policies_are_hidden_from_this_wallets_view() {
        // One shared keystore volume, two wallets. Each container must see and
        // no-id-resolve only its own policies; the file stays whole so the
        // other wallet's counters are never touched.
        let dir = std::env::temp_dir().join(format!("psy-pol-hide-{}", rand_hex(8)));
        let _ = std::fs::create_dir_all(&dir);
        let mut e = PolicyEngine::load_or_new(&dir);
        e.set_current_user(1);
        let a_policy = e.create_policy("agent-a", Limits { per_transaction: 1, per_day: 1, per_month: None, total_budget: None }, None, vec![]);
        let (ta, _) = e.issue_session(&a_policy, 60, None).unwrap();
        e.authorize(&ta, "9", 1, "simple_transfer").unwrap();
        drop(e);
        // B boots on the same volume: sees NOTHING of A's, sole-policy works.
        let mut b = PolicyEngine::load_or_new(&dir);
        b.set_current_user(2);
        assert!(b.policies.is_empty(), "A's policies must be hidden from B");
        let b_policy = b.create_policy("agent-b", Limits { per_transaction: 1, per_day: 1, per_month: None, total_budget: None }, None, vec![]);
        let (tb, _) = b.issue_session(&b_policy, 60, None).unwrap();
        b.authorize(&tb, "9", 1, "simple_transfer").unwrap();
        // B's save persists the WHOLE map (both wallets) — A's counters intact.
        drop(b);
        let mut a = PolicyEngine::load_or_new(&dir);
        a.set_current_user(1);
        let ids = a.policy_ids();
        assert_eq!(ids.len(), 1, "A sees only its own; got {ids:?}");
        assert!(ids.contains(&a_policy));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
