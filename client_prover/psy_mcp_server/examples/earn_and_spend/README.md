# Earn and spend

A reference implementation of the loop that makes an agent an economic actor
rather than a spender:

```
customer ──pays 0.05──▶  ANALYST agent  ──pays 0.02──▶  data vendor
                          margin 0.03
```

The analyst **sells** a report over x402. Fulfilling the request costs it a paid
upstream lookup, which it **buys** with what it just earned — under a policy its
owner set once, with a key it never exposes to the model.

## Why this loop and not "agent pays for an API"

Three things only line up here:

* **Both halves of x402.** Most agent wallets can only buy. `x402_verify` lets
  the analyst sell without running a prover — verification is a read against the
  indexer, so an ordinary web backend can take Psy payments.
* **The guardrail is below the model.** The per-payment cap and daily budget are
  enforced in Rust. A hostile 402 challenge cannot talk its way into a larger
  payment, and the example ends by demonstrating exactly that.
* **The payments are private.** Which vendors an agent buys from, and for how
  much, is visible to the counterparties — not to everyone reading a public
  ledger.

## Files

| File | What it is |
|---|---|
| `run_loop.py` | The loop: three agents, two paid endpoints, one margin |
| `paid_api.py` | A paywalled endpoint that settles with a Psy wallet — the "earn" side |
| `mcp_client.py` | Minimal MCP client (JSON-RPC over stdio), as an agent runtime would speak |

## Running it

```bash
PSY_CONFIG=/path/to/config.json \
PSY_MCP_SERVER=/path/to/psy-mcp-server \
PSY_KEY_ANALYST=<hex> PSY_KEY_CUSTOMER=<hex> PSY_KEY_VENDOR=<hex> \
python3 run_loop.py
```

Omit the keys to mint fresh accounts. Reattaching existing ones is what a real
deployment does — generating per run mints a new on-chain identity each time and
waits for it to confirm.

**Requirements:** three *registered* Psy accounts and a chain that is advancing.
The loop's sellers listen on localhost, so the runner sets
`PSY_MCP_X402_ALLOW_PRIVATE=1` — the server otherwise refuses to fetch
private/internal addresses (SSRF guard).
Registration and every payment need a checkpoint; on a stalled chain the loop
stops at the first spend and says so.

## What is verified, and what needs a live chain

Verified against staging, and independent of settlement:

* the 402 challenge is parsed, and an unknown scheme is refused rather than paid
* the caller's own `max_amount_nano` refuses an over-priced resource before any spend
* the policy gate refuses a payment above the owner's cap
* `x402_verify` accepts a real payment, and rejects a fabricated transaction, a
  payment made to someone else, one whose header inflates the amount, and one
  that does not cover the price

Needs an advancing chain:

* the payments themselves (each is a real recursive proof, ~13–50 s)
* minting new agent accounts

## Reading the output

The example prints the two servers' own logs, so the refusals are visible as the
servers issuing them rather than as narration. The final section deliberately
sends the analyst at a 0.9 PSY resource with a 0.1 PSY cap: the payment is
refused by the policy engine, not by the server, and not by anything the model
could be persuaded to skip.
