//! Production Test Matrix — **stress** row.
//!
//! Covers: multiple agents, concurrent payments, long-running operation.
//!
//! `PolicyEngine` has no interior synchronisation — every method takes `&mut
//! self`, and `main.rs` wraps it in one `Arc<std::sync::Mutex<_>>` shared by
//! every tool handler. That wrapper is the thing under test here: the caps are
//! the wallet's only defence against a swarm of agents, and a cap that holds
//! for one caller but leaks under N is not a cap.
//!
//! Every test asserts a conservation property rather than a timing, so none of
//! them is flaky: the sum of what was authorized must equal what the counters
//! say, and neither may ever exceed the ceiling the owner set.

#[path = "../src/policy.rs"]
mod policy;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex};

use policy::{Limits, PolicyEngine};

type Shared = Arc<Mutex<PolicyEngine>>;

fn wide() -> Limits {
    Limits { per_transaction: u64::MAX / 4, per_day: u64::MAX / 4, per_month: None, total_budget: None }
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    std::env::temp_dir().join(format!("psy-mcp-prod-matrix-{tag}-{nanos}"))
}

/// Run `threads` workers that each call `body` `iterations` times, all released
/// from a barrier so the contention is real rather than sequential.
fn hammer(threads: usize, iterations: usize, body: impl Fn(usize, usize) + Send + Sync + 'static) {
    let body = Arc::new(body);
    let barrier = Arc::new(Barrier::new(threads));
    let handles: Vec<_> = (0..threads)
        .map(|t| {
            let body = Arc::clone(&body);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                for i in 0..iterations {
                    body(t, i);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("no worker may panic — a panic here poisons the shared policy mutex");
    }
}

// ─────────────────── STRESS-01 · concurrent payments, one agent ──────────────

#[test]
fn stress_01_a_daily_cap_holds_exactly_under_concurrent_authorize() {
    // 16 threads race to spend 1 Nano at a time against a 1_000 Nano day. The
    // cap must be hit exactly: not 999 (a lost update denying real headroom),
    // and never 1_001 (a lost update spending money the owner did not allow).
    const CAP: u64 = 1_000;
    let mut engine = PolicyEngine::new();
    let pid = engine.create_policy("swarm", Limits { per_transaction: 1, per_day: CAP, per_month: None, total_budget: None }, None, vec![]);
    let (token, _) = engine.issue_session(&pid, 60).unwrap();
    let shared: Shared = Arc::new(Mutex::new(engine));

    let granted = Arc::new(AtomicU64::new(0));
    {
        let (shared, granted, token) = (Arc::clone(&shared), Arc::clone(&granted), token.clone());
        hammer(16, 500, move |_, _| {
            if shared.lock().unwrap().authorize(&token, "204800", 1, "simple_transfer").is_ok() {
                granted.fetch_add(1, Ordering::Relaxed);
            }
        });
    }

    let granted = granted.load(Ordering::Relaxed);
    assert_eq!(granted, CAP, "exactly the daily cap must be authorized across 8000 concurrent attempts");
    let spent = shared.lock().unwrap().describe(&pid).unwrap().spent_today_nano;
    assert_eq!(spent, granted, "the counter must equal what was actually handed out — no lost updates");
    assert!(shared.lock().unwrap().authorize(&token, "204800", 1, "simple_transfer").is_err(), "and the cap stays closed afterwards");
}

#[test]
fn stress_01b_a_lifetime_budget_holds_under_mixed_amounts() {
    // Varying amounts make an off-by-one in the accumulator visible: the
    // authorized total must land exactly on the budget or just under it,
    // never over.
    const BUDGET: u64 = 100_000;
    let mut engine = PolicyEngine::new();
    let pid = engine.create_policy(
        "swarm",
        Limits { per_transaction: 997, per_day: u64::MAX / 4, per_month: Some(BUDGET), total_budget: Some(BUDGET) },
        None,
        vec![],
    );
    let (token, _) = engine.issue_session(&pid, 60).unwrap();
    let shared: Shared = Arc::new(Mutex::new(engine));

    let total = Arc::new(AtomicU64::new(0));
    {
        let (shared, total, token) = (Arc::clone(&shared), Arc::clone(&total), token.clone());
        hammer(12, 400, move |t, i| {
            let amount = 1 + ((t * 400 + i) as u64 % 997);
            if shared.lock().unwrap().authorize(&token, "204800", amount, "simple_transfer").is_ok() {
                total.fetch_add(amount, Ordering::Relaxed);
            }
        });
    }

    let total = total.load(Ordering::Relaxed);
    assert!(total <= BUDGET, "authorized {total} against a {BUDGET} lifetime budget — the cap leaked");
    let d = shared.lock().unwrap().describe(&pid).unwrap();
    assert_eq!(d.spent_total_nano, total, "lifetime counter must match the authorized sum exactly");
    assert_eq!(d.spent_this_month_nano, total, "and so must the 30-day counter");
    assert_eq!(d.remaining_total_nano, Some(BUDGET - total));
}

// ─────────────────── STRESS-02 · multiple agents, one wallet ─────────────────

#[test]
fn stress_02_concurrent_agents_cannot_spend_each_others_budgets() {
    // Four agents, four policies, one shared engine. Each has its own 250 Nano
    // day. The failure this catches is cross-policy contamination: an agent
    // whose own budget is exhausted borrowing another's headroom, or one
    // agent's spend being charged to a neighbour.
    const AGENTS: usize = 4;
    const PER_AGENT: u64 = 250;
    let mut engine = PolicyEngine::new();
    let mut policies = Vec::new();
    for a in 0..AGENTS {
        let pid = engine.create_policy(
            &format!("agent-{a}"),
            Limits { per_transaction: 1, per_day: PER_AGENT, per_month: None, total_budget: None },
            None,
            vec![],
        );
        let (token, _) = engine.issue_session(&pid, 60).unwrap();
        policies.push((pid, token));
    }
    let shared: Shared = Arc::new(Mutex::new(engine));

    let granted: Arc<Vec<AtomicU64>> = Arc::new((0..AGENTS).map(|_| AtomicU64::new(0)).collect());
    {
        let (shared, granted, policies) = (Arc::clone(&shared), Arc::clone(&granted), policies.clone());
        hammer(AGENTS * 3, 400, move |t, _| {
            let a = t % AGENTS;
            if shared.lock().unwrap().authorize(&policies[a].1, "204800", 1, "simple_transfer").is_ok() {
                granted[a].fetch_add(1, Ordering::Relaxed);
            }
        });
    }

    let mut engine = shared.lock().unwrap();
    for (a, (pid, _)) in policies.iter().enumerate() {
        let got = granted[a].load(Ordering::Relaxed);
        assert_eq!(got, PER_AGENT, "agent-{a} must get exactly its own budget, got {got}");
        let d = engine.describe(pid).unwrap();
        assert_eq!(d.agent_id, format!("agent-{a}"), "policies must not be cross-wired");
        assert_eq!(d.spent_today_nano, PER_AGENT, "agent-{a}'s counter must hold only its own spend");
    }
    // The audit log must attribute every spend to the agent that made it.
    for (a, (pid, _)) in policies.iter().enumerate() {
        let log = engine.spend_log(usize::MAX, Some(pid));
        assert!(log.iter().all(|r| r.agent_id == format!("agent-{a}")), "the spend log mixed agents together");
    }
}

#[test]
fn stress_02b_a_revoked_agent_stops_mid_swarm_without_disturbing_the_others() {
    // The emergency stop under load: one agent is revoked while three others
    // keep spending. Its spend must stop at the revocation and the others must
    // be unaffected — a revoke that took the whole engine down would be as bad
    // as one that did nothing.
    let mut engine = PolicyEngine::new();
    let mut tokens = Vec::new();
    let mut pids = Vec::new();
    for a in 0..4 {
        let pid = engine.create_policy(&format!("agent-{a}"), wide(), None, vec![]);
        let (t, _) = engine.issue_session(&pid, 60).unwrap();
        tokens.push(t);
        pids.push(pid);
    }
    let shared: Shared = Arc::new(Mutex::new(engine));
    let victim = tokens[0].clone();

    let after_revoke = Arc::new(AtomicU64::new(0));
    let revoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let (shared, tokens, after_revoke, revoked) =
            (Arc::clone(&shared), tokens.clone(), Arc::clone(&after_revoke), Arc::clone(&revoked));
        let victim = victim.clone();
        hammer(8, 300, move |t, i| {
            if t == 0 && i == 100 {
                shared.lock().unwrap().revoke(&victim);
                revoked.store(true, Ordering::SeqCst);
            }
            let idx = t % 4;
            let ok = shared.lock().unwrap().authorize(&tokens[idx], "204800", 1, "simple_transfer").is_ok();
            if idx == 0 && ok && revoked.load(Ordering::SeqCst) {
                after_revoke.fetch_add(1, Ordering::Relaxed);
            }
        });
    }

    assert_eq!(
        after_revoke.load(Ordering::Relaxed),
        0,
        "the revoked agent authorized a spend after its token was revoked"
    );
    let mut engine = shared.lock().unwrap();
    for pid in pids.iter().skip(1) {
        assert!(engine.describe(pid).unwrap().spent_today_nano > 0, "the surviving agents kept working");
    }
}

// ───────────────── STRESS-03 · authorize / refund interleaving ───────────────

#[test]
fn stress_03_refunds_racing_authorizations_never_mint_or_lose_budget() {
    // Models the real failure path: a payment is authorized, the settle fails,
    // the caller refunds — all while other agents' payments are in flight. The
    // invariant is exact conservation: spent == authorized - refunded, and the
    // cap is never exceeded at any point.
    const CAP: u64 = 50_000;
    let mut engine = PolicyEngine::new();
    let pid = engine.create_policy(
        "swarm",
        Limits { per_transaction: 100, per_day: CAP, per_month: None, total_budget: Some(CAP) },
        None,
        vec![],
    );
    let (token, _) = engine.issue_session(&pid, 60).unwrap();
    let shared: Shared = Arc::new(Mutex::new(engine));

    let net = Arc::new(AtomicU64::new(0));
    let peak_ok = Arc::new(std::sync::atomic::AtomicBool::new(true));
    {
        let (shared, net, peak_ok, token) =
            (Arc::clone(&shared), Arc::clone(&net), Arc::clone(&peak_ok), token.clone());
        hammer(10, 500, move |t, i| {
            let amount = 1 + ((t + i) as u64 % 100);
            let mut e = shared.lock().unwrap();
            if let Ok(auth) = e.authorize(&token, "204800", amount, "simple_transfer") {
                net.fetch_add(amount, Ordering::SeqCst);
                // Every third settle "fails" and is refunded under the same lock
                // the next authorize will take.
                if (t + i) % 3 == 0 {
                    e.refund(&auth, amount);
                    net.fetch_sub(amount, Ordering::SeqCst);
                }
                if net.load(Ordering::SeqCst) > CAP {
                    peak_ok.store(false, Ordering::SeqCst);
                }
            }
        });
    }

    assert!(peak_ok.load(Ordering::SeqCst), "the outstanding spend went over the cap at some point during the race");
    let net = net.load(Ordering::SeqCst);
    let d = shared.lock().unwrap().describe(&pid).unwrap();
    assert_eq!(d.spent_today_nano, net, "daily counter drifted from authorized-minus-refunded");
    assert_eq!(d.spent_total_nano, net, "lifetime counter drifted from authorized-minus-refunded");
    assert!(net <= CAP, "net spend {net} exceeded the {CAP} cap");
}

#[test]
fn stress_03b_check_budget_is_advisory_but_authorize_is_still_exact() {
    // `check_budget` and `authorize` take the shared lock separately, so an
    // agent that reads its headroom and then spends it can always be beaten to
    // it by another agent. That race is by design — the gate, not the read, is
    // the security boundary. What must hold is that acting on a stale read can
    // never spend more than the cap.
    const CAP: u64 = 2_000;
    let mut engine = PolicyEngine::new();
    let pid = engine.create_policy("swarm", Limits { per_transaction: 10, per_day: CAP, per_month: None, total_budget: None }, None, vec![]);
    let (token, _) = engine.issue_session(&pid, 60).unwrap();
    let shared: Shared = Arc::new(Mutex::new(engine));

    let granted = Arc::new(AtomicU64::new(0));
    let stale_reads = Arc::new(AtomicU64::new(0));
    {
        let (shared, granted, stale_reads, token) =
            (Arc::clone(&shared), Arc::clone(&granted), Arc::clone(&stale_reads), token.clone());
        hammer(12, 300, move |_, _| {
            let headroom = shared.lock().unwrap().budget(&token).map(|b| b.remaining_day).unwrap_or(0);
            // Deliberately act on the possibly-stale read.
            if headroom >= 10 {
                if shared.lock().unwrap().authorize(&token, "204800", 10, "simple_transfer").is_ok() {
                    granted.fetch_add(10, Ordering::Relaxed);
                } else {
                    stale_reads.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
    }

    assert_eq!(granted.load(Ordering::Relaxed), CAP, "the gate must still land exactly on the cap");
    let d = shared.lock().unwrap().describe(&pid).unwrap();
    assert_eq!(d.remaining_day_nano, 0);
    // The stale-read count is informational; the point is that it costs nothing
    // but a denial. Assert only that denials, if any, were denials.
    assert!(d.spent_today_nano <= CAP);
}

// ────────────────────── STRESS-04 · long-running operation ───────────────────

#[test]
fn stress_04_a_long_running_server_stays_bounded_and_exact() {
    // A server that runs for weeks does hundreds of thousands of gate calls.
    // The audit ring must stay bounded (it is process memory, not the ledger)
    // and the counters must not drift by a single Nano over the run.
    const ROUNDS: u64 = 60_000;
    let mut engine = PolicyEngine::new();
    let pid = engine.create_policy(
        "long-runner",
        Limits { per_transaction: 10, per_day: u64::MAX / 4, per_month: None, total_budget: None },
        None,
        vec![],
    );
    let (token, _) = engine.issue_session(&pid, 60).unwrap();

    let mut expected = 0u64;
    for i in 0..ROUNDS {
        let amount = 1 + (i % 10);
        let auth = engine.authorize(&token, "204800", amount, "simple_transfer").expect("headroom is effectively unlimited");
        expected += amount;
        if i % 7 == 0 {
            engine.refund(&auth, amount);
            expected -= amount;
        }
    }

    assert_eq!(engine.describe(&pid).unwrap().spent_today_nano, expected, "counters drifted over {ROUNDS} rounds");
    assert_eq!(engine.spend_log_len(), 100, "the audit ring must stay at its capacity, not grow with the run");
    let log = engine.spend_log(usize::MAX, None);
    assert_eq!(log.len(), 100, "and a reader can never be handed more than the ring holds");
    assert!(log[0].age_seconds < 3_600, "ages are computed at read time, so the newest entry reads as recent");
}

// ───────────────── STRESS-05 · durability under concurrency ──────────────────

#[test]
fn stress_05_persisted_counters_match_memory_after_a_concurrent_run() {
    // Every authorize writes policies.json (temp file → fsync → rename). Under
    // concurrency the risk is a torn or stale file: the process survives, but a
    // later restart re-grants budget that was already spent. Assert the file a
    // restart would read equals what memory says.
    let dir = temp_dir("durability");
    const CAP: u64 = 5_000;
    let mut engine = PolicyEngine::load_or_new(&dir);
    let pid = engine.create_policy(
        "swarm",
        Limits { per_transaction: 5, per_day: u64::MAX / 4, per_month: None, total_budget: Some(CAP) },
        None,
        vec![],
    );
    let (token, _) = engine.issue_session(&pid, 60).unwrap();
    let shared: Shared = Arc::new(Mutex::new(engine));

    {
        let (shared, token) = (Arc::clone(&shared), token.clone());
        hammer(8, 400, move |_, _| {
            let _ = shared.lock().unwrap().authorize(&token, "204800", 5, "simple_transfer");
        });
    }

    let in_memory = shared.lock().unwrap().describe(&pid).unwrap().spent_total_nano;
    assert_eq!(in_memory, CAP, "the lifetime budget must be exactly consumed");

    // "Restart" and confirm the budget is not re-granted.
    let mut restarted = PolicyEngine::load_or_new(&dir);
    let d = restarted.describe(&pid).unwrap();
    assert_eq!(d.spent_total_nano, in_memory, "the persisted counter disagrees with memory — a restart would re-grant budget");
    assert_eq!(d.remaining_total_nano, Some(0));
    let (t2, _) = restarted.issue_session(&pid, 60).unwrap();
    assert!(restarted.authorize(&t2, "204800", 1, "simple_transfer").is_err(), "and nothing is spendable after the restart");
    std::fs::remove_dir_all(&dir).ok();
}
