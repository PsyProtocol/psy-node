#!/usr/bin/env python3
"""The earn-and-spend loop: an agent that sells work and buys its inputs.

    customer ──pays──▶  ANALYST agent  ──pays──▶  data vendor
                          (earns 0.05)             (spends 0.02)

Three wallets, three real Psy accounts, one margin. The analyst sells a report
over x402; fulfilling that request costs it a paid upstream lookup, which it
buys with the money it just earned — under a policy its owner set once, with a
key it never exposes.

Why this shape is the interesting one:

  * The analyst is a full economic actor, not just a spender. Most agent wallets
    only do the buying half; `x402_verify` is what makes the selling half work
    without the seller running a prover.
  * Its authority is bounded from below the model. The per-payment cap and daily
    budget are enforced in Rust, so a hostile 402 challenge cannot talk its way
    into a larger payment.
  * The payments are private. Amount and counterparty are visible to the two
    parties, not to everyone watching a public ledger — which is what makes
    "who does this agent buy from, and how much" not a competitor's business.

Run:
    PSY_CONFIG=/path/to/config.json \\
    PSY_MCP_SERVER=/path/to/psy-mcp-server \\
    PSY_KEY_ANALYST=<hex> PSY_KEY_CUSTOMER=<hex> PSY_KEY_VENDOR=<hex> \\
    python3 run_loop.py

Omit the keys to mint fresh accounts (needs a live chain; registration waits for
a checkpoint).

Everything up to settlement works against a stalled chain; the payments
themselves need checkpoints to be advancing.
"""
from __future__ import annotations

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcp_client import McpClient          # noqa: E402
from paid_api import PaidResource         # noqa: E402

BIN = os.environ.get("PSY_MCP_SERVER", "target/release/psy-mcp-server")
CONFIG = os.environ.get("PSY_CONFIG", "config.json")
KEYDIR = os.environ.get("PSY_MCP_KEYSTORE_DIR", "./.psy-mcp-keys")

REPORT_PRICE = 50_000_000      # 0.05 PSY — what the analyst charges
LOOKUP_PRICE = 20_000_000      # 0.02 PSY — what its data costs it
# The analyst's owner allows single payments up to 0.1 PSY and 1 PSY a day.
# Deliberately larger than the lookup and smaller than anything alarming.
PER_TX_CAP = 100_000_000
DAILY_CAP = 1_000_000_000


def bold(s):  return f"\033[1m{s}\033[0m"
def dim(s):   return f"\033[2m{s}\033[0m"
def green(s): return f"\033[32m{s}\033[0m"
def red(s):   return f"\033[31m{s}\033[0m"


class Agent:
    """One wallet, driven over MCP exactly as an agent runtime would.

    Pass `key_env` (the NAME of the environment variable holding the key) to
    reattach an existing account — which is what a real deployment does.
    Generating an account per run would mint a new on-chain identity every
    time and, on a slow chain, spend five minutes waiting for it to confirm.
    The key itself never crosses the MCP boundary: the server reads it from
    its own environment, so it never lands in any model's context.
    """

    def __init__(self, label: str, per_tx: int, daily: int, key_env: str | None = None):
        self.label = label
        # The example's sellers listen on 127.0.0.1, which the server's SSRF
        # guard refuses by default — opt in explicitly, as any local dev does.
        env = dict(os.environ, PSY_CONFIG=CONFIG, PSY_MCP_KEYSTORE_DIR=KEYDIR,
                   PSY_MCP_X402_ALLOW_PRIVATE="1")
        self.c = McpClient([BIN], env=env)
        self.c.send("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                   "clientInfo": {"name": label, "version": "1"}}, timeout=300)
        self.c.notify("notifications/initialized")
        args = {"agent_id": label, "perTransaction": per_tx, "perDay": daily}
        use_load = key_env is not None and os.environ.get(key_env)
        args.update({"mode": "load", "private_key_env": key_env} if use_load else {"mode": "generate"})
        w = self.c.call_tool("create_wallet", args, timeout=1800)
        if w.get("status") != "ok":
            raise SystemExit(
                f"{label}: could not open a wallet: {w.get('error', w)}\n"
                "  Set PSY_KEY_ANALYST / PSY_KEY_CUSTOMER / PSY_KEY_VENDOR to reuse\n"
                "  existing accounts — minting new ones needs the chain to be advancing.")
        self.user_id = w["userId"]
        self.psy_id = w["psyId"]
        self.session = self.c.call_tool(
            "issue_session", {"policy_id": w["policyId"], "ttl_minutes": 60}, timeout=120)["token"]
        print(f"  {bold(label):<22} {self.psy_id}  "
              f"{dim(f'cap {per_tx/1e9:g} PSY/payment, {daily/1e9:g} PSY/day')}")

    def fund(self):
        r = self.c.call_tool("claim_faucet", {}, timeout=600)
        return r.get("operatorUserId") if r.get("status") == "ok" else None

    def claim_from(self, sender):
        """Claim from a sender, WAITING for the claimable to exist first.

        A faucet grant settles a checkpoint or two after the request; claiming
        immediately fails in-circuit with "no tokens to claim from this sender".
        The claimable read is cheap — poll it, then prove once.
        """
        for i in range(40):
            r = self.c.call_tool("get_claimable", {"sender_user_id": sender}, timeout=300)
            if (r.get("claimableNano") or 0) > 0:
                break
            print(dim(f"      waiting for the grant to settle… ({i})"))
            time.sleep(10)
        return self.c.call_tool(
            "claim_all", {"session": self.session, "sender_user_ids": [sender]}, timeout=1800)

    def wait_balance(self, at_least, token="PSY"):
        """Wait until the spendable balance covers `at_least`.

        A claim's proof is accepted before its checkpoint settles, so money you
        just claimed is not spendable for a checkpoint or two. Paying into that
        window fails in-circuit with "insufficient balance".
        """
        for i in range(40):
            r = self.c.call_tool("get_balance", {"token": token}, timeout=300)
            if (r.get("balanceNano") or 0) >= at_least:
                return r["balanceNano"]
            print(dim(f"      waiting for the balance to settle… ({i})"))
            time.sleep(10)
        return 0

    def buy(self, url, ceiling=None):
        args = {"session": self.session, "url": url}
        if ceiling is not None:
            args["max_amount_nano"] = ceiling
        return self.c.call_tool("x402_fetch", args, timeout=1800)

    def verify(self, header, price):
        r = self.c.call_tool("x402_verify",
                             {"x_payment": header, "expected_amount_nano": price}, timeout=600)
        return bool(r.get("valid")), r

    def balance_events(self):
        return self.c.call_tool("get_activity", {"limit": 10}, timeout=300)

    def close(self):
        self.c.close()


def main() -> int:
    print(bold("\nThree agents\n"))
    analyst = Agent("analyst (sells)", PER_TX_CAP, DAILY_CAP, "PSY_KEY_ANALYST")
    customer = Agent("customer (buys)", 500_000_000, 5_000_000_000, "PSY_KEY_CUSTOMER")
    vendor = Agent("data vendor", 10_000_000, 100_000_000, "PSY_KEY_VENDOR")

    # ── the vendor's paid lookup, and the analyst's paid report ──────────
    vendor_api = PaidResource(
        name="Market tick data", price_nano=LOOKUP_PRICE, pay_to=vendor.psy_id,
        verify=lambda h: vendor.verify(h, LOOKUP_PRICE),
        fulfil=lambda: "TICKS 41.20 41.55 41.03 42.10",
        port=8411,
    )

    def produce_report() -> str:
        """Fulfilling a sale costs money: the analyst buys its input first.

        This is the whole point of the example — earning and spending are the
        same loop, and the spend is gated by the same policy as any other.
        """
        print(dim("      analyst needs upstream data to answer…"))
        bought = analyst.buy(vendor_api.url, ceiling=PER_TX_CAP)
        if bought.get("status") != "ok" or not bought.get("paid"):
            return f"REPORT (degraded — upstream unavailable: {bought.get('error', 'unknown')})"
        print(f"      {green('analyst paid the vendor')} "
              f"{bought['amountNano']/1e9:g} PSY  tx {str(bought.get('txHash'))[:16]}…")
        return f"REPORT: based on {bought.get('body','')[:34]} → outlook stable"

    analyst_api = PaidResource(
        name="Analyst report", price_nano=REPORT_PRICE, pay_to=analyst.psy_id,
        verify=lambda h: analyst.verify(h, REPORT_PRICE),
        fulfil=produce_report,
        port=8410,
    )
    vendor_api.start()
    analyst_api.start()

    # ── fund the customer, who is the only one who needs outside money ───
    print(bold("\nFunding the customer\n"))
    op = customer.fund()
    if op is None:
        print(red("  faucet refused — the loop needs a funded customer"))
    else:
        print(f"  grant requested from operator {op}; claiming…")
        r = customer.claim_from(op)
        print(("  " + green("claimed")) if r.get("status") == "ok"
              else "  " + red(f"claim failed: {r.get('error')}"))

    # ── the loop ─────────────────────────────────────────────────────────
    print(bold("\nThe loop\n"))
    bal = customer.wait_balance(REPORT_PRICE)
    print(f"  customer holds {bal/1e9:g} PSY; requesting the report…")
    got = customer.buy(analyst_api.url, ceiling=200_000_000)

    print()
    for line in analyst_api.log:
        print(f"    analyst api  {line}")
    for line in vendor_api.log:
        print(f"    vendor api   {line}")

    print(bold("\nOutcome\n"))
    if got.get("status") == "ok" and got.get("paid"):
        earned, spent = REPORT_PRICE, LOOKUP_PRICE
        print(f"  {green('report delivered')}: {got.get('body','')[:60]}")
        print(f"  analyst earned {earned/1e9:g} PSY, spent {spent/1e9:g} PSY, "
              f"margin {bold(f'{(earned-spent)/1e9:g} PSY')}")
    else:
        print(f"  {red('loop did not close')}: {got.get('error', got)}")
        print(dim("  (settlement needs the chain to be advancing; everything up to"))
        print(dim("   the payment — challenge, policy gate, verification — still ran)"))

    # ── the guardrail, shown rather than asserted ────────────────────────
    print(bold("\nThe policy is not a prompt\n"))
    greedy = PaidResource(
        name="Overpriced feed", price_nano=900_000_000, pay_to=vendor.psy_id,
        verify=lambda h: (True, {}), fulfil=lambda: "should never be reached", port=8412)
    greedy.start()
    r = analyst.buy(greedy.url)
    print(f"  a 0.9 PSY challenge against a 0.1 PSY cap → {red(r.get('error', 'ALLOWED?!'))}")
    greedy.stop()

    for a in (analyst, customer, vendor):
        a.close()
    analyst_api.stop()
    vendor_api.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
