#!/usr/bin/env python3
"""End-to-end smoke test for the mandatory prepare/execute confirmation flow.

Drives a real psy-mcp-server binary over stdio MCP and checks, in order:

  1. tools/list advertises prepare_*/execute_* pairs and NO raw transaction
     route (transfer, claim_batch, x402_fetch, …) and keeps read-only tools.
  2. A direct call to a raw transaction route is refused.
  3. prepare_* stores the exact arguments, redacts only credentials
     (session/owner_token/private_key*) in the human-review summary, and
     returns a one-time confirmation token with a short TTL.
  4. execute_* with a wrong owner token is refused and does not consume it.
  5. execute_* rejects smuggled transaction fields — parameters are fixed by
     prepare and cannot be re-passed or modified.
  6. execute_* with the right owner token dispatches into the real tool; the
     fake session then dies at the policy gate (no funds can move — the smoke
     run never needs a real session, wallet, or balance).
  7. The confirmation token is single-use.
  8. An unknown token is refused.

The run uses a throwaway keystore directory and a random owner token, so it
never touches real wallets, policies, or the installed owner token.

Usage:
    python3 scripts/smoke_confirmation_flow.py [binary] [config.json]

    binary  defaults to PSY_MCP_SERVER_BIN, then <workspace>/target/release/
            psy-mcp-server relative to this script.
    config  defaults to PSY_CONFIG, then ~/.psy/config.json.

Exit status 0 = all checks passed.
"""

import json
import os
import secrets
import select
import subprocess
import sys
import tempfile
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_BIN = os.path.join(SCRIPT_DIR, "..", "..", "..", "target", "release", "psy-mcp-server")
DEFAULT_CONFIG = os.path.expanduser(os.environ.get("PSY_CONFIG", "~/.psy/config.json"))

BIN = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("PSY_MCP_SERVER_BIN", DEFAULT_BIN)
CONFIG = os.argv[2] if len(sys.argv) > 2 else DEFAULT_CONFIG
OWNER = "smoke-owner-" + secrets.token_hex(12)

for path, what in ((BIN, "binary"), (CONFIG, "config")):
    if not os.path.exists(path):
        sys.exit(f"missing {what}: {path}")

workdir = tempfile.mkdtemp(prefix="psy-mcp-smoke-")
env = dict(os.environ)
env.update({
    "PSY_CONFIG": CONFIG,
    "PSY_MCP_KEYSTORE_DIR": os.path.join(workdir, "keys"),
    "PSY_MCP_OWNER_TOKEN": OWNER,
})
proc = subprocess.Popen(
    [BIN, "--config", CONFIG],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    env=env, text=True,
)

RAW_TRANSACTION_TOOLS = [
    "transfer", "transfer_batch", "claim_all", "deposit", "withdraw",
    "claim_batch", "private_transfer", "private_claim", "claim_deposit",
    "x402_fetch", "call_contract", "psyup_deploy", "create_wallet",
    "mint_agent_account", "claim_faucet", "retry_deposit_delivery",
]


def send(obj):
    proc.stdin.write(json.dumps(obj) + "\n")
    proc.stdin.flush()


def recv(want_id, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        ready, _, _ = select.select([proc.stdout], [], [], 1)
        if not ready:
            continue
        line = proc.stdout.readline()
        if not line:
            raise RuntimeError("server closed stdout")
        message = json.loads(line)
        if message.get("id") == want_id:
            return message
    raise TimeoutError(f"no response for id {want_id}")


_next_id = 1


def call(tool, arguments):
    global _next_id
    request_id = _next_id
    _next_id += 1
    send({"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
          "params": {"name": tool, "arguments": arguments}})
    return json.loads(recv(request_id)["result"]["content"][0]["text"])


send({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
    "protocolVersion": "2025-03-26", "capabilities": {},
    "clientInfo": {"name": "smoke-confirmation", "version": "0"}}})
assert "result" in recv(0), "initialize failed"
send({"jsonrpc": "2.0", "method": "notifications/initialized"})

# 1. tools/list: raw transaction routes hidden, prepare_/execute_ pairs present
send({"jsonrpc": "2.0", "id": 100, "method": "tools/list", "params": {}})
tools = [t["name"] for t in recv(100)["result"]["tools"]]
leaked = [name for name in RAW_TRANSACTION_TOOLS if name in tools]
assert not leaked, f"raw routes leaked: {leaked}"
for name in ("transfer", "claim_batch", "x402_fetch"):
    assert f"prepare_{name}" in tools and f"execute_{name}" in tools, f"missing pair for {name}"
assert "wallet_status" in tools and "get_balance" in tools, "read-only tools disappeared"
print(f"[1] tools/list OK: {len(tools)} tools, no raw transaction routes")

# 2. direct raw call refused
result = call("transfer", {"amount": 1, "to_user_id": 2, "session": "x"})
assert result["status"] == "error" and "prepare_transfer" in result["error"], result
print(f"[2] direct transfer refused: {result['error'][:60]}…")

# 3. prepare_transfer stores args, redacts session, returns a ticket
result = call("prepare_transfer", {
    "amount": 1234567890, "to_user_id": 42, "token": "PSY", "session": "SECRET-SESSION"})
assert result["status"] == "prepared" and result["submitted"] is False, result
ticket = result["confirmation_token"]
assert result["transaction"]["session"] == "[redacted]", result["transaction"]
assert result["transaction"]["amount"] == 1234567890
assert result["transaction"]["to_user_id"] == 42
print(f"[3] prepare_transfer OK: ticket {ticket[:8]}…, expires in {result['expiresInSeconds']}s")

# 4. execute with WRONG owner token refused, ticket survives
result = call("execute_transfer", {"confirmation_token": ticket, "owner_token": "wrong"})
assert result["status"] == "error" and result["gate"] == "owner", result
print(f"[4] execute with wrong owner token refused: {result['error'][:60]}…")

# 5. execute rejects smuggled transaction fields
result = call("execute_transfer", {"confirmation_token": ticket, "owner_token": OWNER, "amount": 1})
assert result["status"] == "error" and result["gate"] == "confirmation", result
print("[5] execute with smuggled amount refused")

# 6. execute with the right owner token dispatches; the fake session dies at policy
result = call("execute_transfer", {"confirmation_token": ticket, "owner_token": OWNER})
assert result["status"] == "error" and "policy denied" in result["error"], result
print(f"[6] execute dispatched into the real tool, policy denied the fake session: {result['error'][:70]}…")

# 7. the ticket is single-use
result = call("execute_transfer", {"confirmation_token": ticket, "owner_token": OWNER})
assert result["status"] == "error" and "already-consumed" in result["error"], result
print("[7] second execute on the same ticket refused")

# 8. unknown ticket
result = call("execute_withdraw", {"confirmation_token": "deadbeef", "owner_token": OWNER})
assert result["status"] == "error" and "confirmation" in json.dumps(result), result
print("[8] unknown ticket refused")

proc.terminate()
print("ALL SMOKE CHECKS PASSED")
