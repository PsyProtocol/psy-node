#!/usr/bin/env python3
"""Owner dashboard bridge for the Psy MCP agent wallet.

This is the human's *local* control process. It spawns the real
`psy-mcp-server`, speaks its actual MCP tools over stdio (nothing is faked),
loads the owner's wallet + policy once, and exposes a tiny localhost HTTP API
that the dashboard (index.html) renders. Because it runs on the owner's own
machine it holds PSY_MCP_OWNER_TOKEN and is therefore allowed to call the
owner-only control tools (pause / resume / revoke / update_policy) that the
agent itself cannot.

Every value the dashboard shows comes from a real tool call:
  /api/state  -> get_user_info + describe_policy + check_budget + get_spend_log
  /api/pause  -> pause_policy        (no token needed — the brake is never gated)
  /api/resume -> resume_policy       (owner token)
  /api/revoke -> revoke_session      (kills the agent's spending session)
  /api/policy -> update_policy       (owner token; body is PSY, converted to Nano)

Run:
    PSY_MCP_SERVER=../../../target/release/psy-mcp-server \\
    PSY_CONFIG=/tmp/psy-mcp-config-stgproxy.json \\
    PSY_MCP_KEYSTORE_DIR=/tmp/psy-dash/keys \\
    PSY_MCP_DASH_KEY_FILE=/tmp/psy-demo-2026/mcp/keys/wallet-65e0169bfffd-1785750552.json \\
    PSY_MCP_OWNER_TOKEN=owner-secret \\
    PSY_MCP_AGENT_NAME="Shopping Assistant" \\
    python3 server.py            # then open http://127.0.0.1:8781
"""
from __future__ import annotations

import json
import os
import secrets
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "examples", "earn_and_spend"))
from mcp_client import McpClient  # noqa: E402

NANO = 1_000_000_000
BIN = os.environ.get("PSY_MCP_SERVER", os.path.join(HERE, "..", "..", "target", "release", "psy-mcp-server"))
CONFIG = os.environ.get("PSY_CONFIG", "/tmp/psy-mcp-config-stgproxy.json")
KEYDIR = os.environ.get("PSY_MCP_KEYSTORE_DIR", os.path.join(HERE, ".dash-keys"))
KEYFILE = os.environ.get("PSY_MCP_DASH_KEY_FILE", "")
# The owner token is what separates the owner from the agent. The server
# refuses to WIDEN a policy when none is configured, because in that mode it
# cannot tell the two apart — which would leave this dashboard, the owner's own
# control panel, unable to raise a limit or approve a payee.
#
# This process spawns its MCP child, so it can settle that by construction:
# with nothing configured, mint a token, pass it to the child we start, and
# hold it here. The agent's server is a DIFFERENT process (Claude Desktop
# spawns its own) and never sees this value, so the distinction the gate needs
# now exists without the owner having to configure anything.
#
# An explicitly configured token always wins — that is the deployment where the
# owner shares one token across both processes deliberately.
OWNER_TOKEN = os.environ.get("PSY_MCP_OWNER_TOKEN", "") or secrets.token_hex(32)
OWNER_TOKEN_IS_LOCAL = not os.environ.get("PSY_MCP_OWNER_TOKEN", "")
AGENT_NAME = os.environ.get("PSY_MCP_AGENT_NAME", "Your Agent")
PORT = int(os.environ.get("PSY_MCP_DASH_PORT", "8781"))


class Bridge:
    """Owns the one MCP subprocess + the loaded policy. Serialized: the MCP
    server is single-session, so every tool call goes through one lock."""

    def __init__(self):
        self._lock = threading.Lock()
        self.policy_id = None
        self.session = None
        self.psy_id = None
        self.user_id = None
        self.boot_error = None
        self.boot_error_detail = None
        env = dict(os.environ, PSY_CONFIG=CONFIG, PSY_MCP_KEYSTORE_DIR=KEYDIR,
                   PSY_MCP_X402_ALLOW_PRIVATE="1")
        env["PSY_MCP_OWNER_TOKEN"] = OWNER_TOKEN
        # The SPAWN belongs inside the try. It used to sit outside it, so the
        # single most likely boot failure — the server binary not built, or
        # built to a different path — raised FileNotFoundError during
        # construction and killed the process outright. The owner got a Python
        # traceback in a terminal and a dead page, which is the exact opposite
        # of the "keep serving so the UI can show an honest error" this block
        # promises.
        self.c = None
        try:
            if not os.path.exists(BIN):
                raise FileNotFoundError(
                    f"the agent server binary was not found at {BIN} "
                    "(build it, or set PSY_MCP_SERVER to its path)"
                )
            self.c = McpClient([BIN], env=env)
            self.c.send("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                       "clientInfo": {"name": "owner-dashboard", "version": "1"}}, timeout=300)
            self.c.notify("notifications/initialized")
            self._boot()
        except Exception as e:  # keep serving so the UI can show an honest error
            # The raw exception is kept as DETAIL, never as the sentence the
            # owner reads. A Python traceback string is not an explanation, and
            # it was being rendered as the entire headline.
            self.boot_error = "Can't reach your agent's controls."
            self.boot_error_detail = str(e)

    def _tok(self, args):
        return dict(args, owner_token=OWNER_TOKEN)

    def _boot(self):
        args = {"agent_id": AGENT_NAME,
                "perTransaction": 5 * NANO, "perDay": 50 * NANO}
        if KEYFILE and os.path.exists(KEYFILE):
            args.update({"mode": "load", "key_file": KEYFILE})
        else:
            args.update({"mode": "generate"})
        w = self.c.call_tool("create_wallet", self._tok(args), timeout=1800)
        if w.get("status") != "ok" and "policyId" not in w:
            self.boot_error = "Your agent's wallet could not be loaded."
            self.boot_error_detail = w.get("error", json.dumps(w))
            return
        self.policy_id = w.get("policyId")
        self.psy_id = w.get("psyId")
        self.user_id = w.get("userId")
        # The wallet + a draft policy exist, but the agent CANNOT SPEND until the
        # owner completes onboarding (configures limits and authorizes it) — that
        # is what issue_session does. We leave session=None so the dashboard opens
        # on the guided setup wizard. The demo path skips straight to a live agent.
        if os.environ.get("PSY_MCP_DASH_DEMO_SEED") == "1":
            s = self.c.call_tool("issue_session", self._tok({"policy_id": self.policy_id, "ttl_minutes": 720}), timeout=120)
            self.session = s.get("token")
            self._seed()

    def create(self, body):
        """Finish onboarding: apply the owner's chosen limits/recipients/actions
        and AUTHORIZE the agent (issue the spending session). After this the
        agent can spend, within these rules."""
        with self._lock:
            if not self.policy_id:
                return {"error": "no wallet loaded"}
            upd = self._apply_policy(body)
            if isinstance(upd, dict) and upd.get("error"):
                return upd
            s = self.c.call_tool("issue_session", self._tok({"policy_id": self.policy_id, "ttl_minutes": 720}), timeout=120)
            self.session = s.get("token")
            return {"ok": True, "authorized": bool(self.session)}

    def _seed(self):
        """DEMO ONLY (flag-gated): make two GENUINE over-limit attempts so the
        Activity page shows how blocked activity renders. These are real denials
        by the real policy engine — no money moves, nothing is fabricated."""
        try:
            setup = self.c.call_tool("update_policy", self._tok({
                "policy_id": self.policy_id, "perTransaction": 5 * NANO, "perDay": 50 * NANO,
                "allowedRecipients": ["Psy-01908736"]}), timeout=120)
            # If the allow-list did not install, the policy still says "pay
            # anyone" and the second attempt below would be a REAL send. Bail.
            if not isinstance(setup, dict) or setup.get("updated") is None:
                print("[dashboard] demo seed skipped: could not install the allow-list", flush=True)
                return
            # over the per-payment cap, to an APPROVED payee:
            self.c.call_tool("transfer", {"session": self.session, "to_user_id": 1908736, "amount": 8 * NANO}, timeout=60)
            # right size, to an UNAPPROVED payee:
            self.c.call_tool("transfer", {"session": self.session, "to_user_id": 630784, "amount": 1 * NANO}, timeout=60)
        except Exception:
            pass

    # ── read ────────────────────────────────────────────────────────────
    def state(self):
        with self._lock:
            if self.boot_error and not self.policy_id:
                return {"ok": False, "error": self.boot_error,
                        "errorDetail": getattr(self, "boot_error_detail", None),
                        "agentName": AGENT_NAME}
            desc = self.c.call_tool("describe_policy", {"policy_id": self.policy_id}, timeout=120)
            budget = self.c.call_tool("check_budget", {"session": self.session}, timeout=120) if self.session else {}
            log = self.c.call_tool("get_spend_log", {"limit": 100}, timeout=120)
            blocked = self.c.call_tool("get_blocked", {"limit": 100}, timeout=120)
            return {
                "ok": True,
                "needsSetup": self.session is None,   # onboarding not yet completed
                "agentName": AGENT_NAME,
                "psyId": self.psy_id,
                "policyId": self.policy_id,
                # NOT bool(OWNER_TOKEN): this process now always has one. What the
                # banner is about is whether the AGENT's server — a different
                # process, spawned by the agent host, sharing this keystore and
                # its policies.json — is also gated. Only a token the owner
                # configured in the environment reaches both. A locally minted
                # one protects this dashboard's edits and nothing else, so
                # reporting it as "protection on" would be a lie the owner acts
                # on.
                "ownerTokenSet": not OWNER_TOKEN_IS_LOCAL,
                "policy": desc.get("policy", {}),     # present even during setup, to pre-fill the wizard
                "summary": desc.get("summary", ""),
                "budget": budget,
                "activity": log.get("entries", []),
                "activityRetained": log.get("retained", 0),
                # The rings are capped, so a short list is ambiguous. The tools
                # now report what they DROPPED; passing it through is what lets
                # the page say "older rows have aged out" instead of implying
                # the list is the whole story.
                "activityDropped": log.get("dropped", 0),
                "blockedDropped": blocked.get("dropped", 0),
                "blocked": blocked.get("entries", []),
            }

    # ── control ─────────────────────────────────────────────────────────
    def pause(self):
        with self._lock:
            return self.c.call_tool("pause_policy", {"policy_id": self.policy_id}, timeout=60)

    def resume(self):
        with self._lock:
            return self.c.call_tool("resume_policy", self._tok({"policy_id": self.policy_id}), timeout=60)

    def revoke(self):
        with self._lock:
            if not self.session:
                return {"error": "no active session"}
            r = self.c.call_tool("revoke_session", {"session": self.session}, timeout=60)
            self.session = None
            return r

    def _apply_policy(self, body):
        """Build update_policy args from a PSY-denominated body and call it.
        Shared by the onboarding wizard (create) and the editor (update)."""
        args = {"policy_id": self.policy_id,
                "perTransaction": int(round(float(body["perPaymentPsy"]) * NANO)),
                "perDay": int(round(float(body["perDayPsy"]) * NANO))}
        if body.get("perMonthPsy") not in (None, ""):
            args["perMonth"] = int(round(float(body["perMonthPsy"]) * NANO))
        if body.get("totalPsy") not in (None, ""):
            args["totalBudget"] = int(round(float(body["totalPsy"]) * NANO))
        # Omitting the key leaves the allow-list UNCHANGED (server-side rule), so
        # a budget-only edit can never silently widen the policy to "pay anyone".
        if body.get("clearRecipients"):
            args["allowedRecipients"] = None          # explicit: pay anyone
        elif isinstance(body.get("recipients"), list) and body["recipients"]:
            args["allowedRecipients"] = [r for r in body["recipients"] if str(r).strip()]
        if isinstance(body.get("methods"), list) and body["methods"]:
            args["allowed_methods"] = body["methods"]
        return self.c.call_tool("update_policy", self._tok(args), timeout=120)

    def update(self, body):
        with self._lock:
            return self._apply_policy(body)


BRIDGE = Bridge()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_a):  # quiet
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, (bytes, bytearray)) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if not self._same_origin():
            return self._send(403, {"error": "cross-site request refused"})
        if self.path in ("/", "/index.html"):
            with open(os.path.join(HERE, "index.html"), "rb") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        if self.path == "/api/state":
            # A tool timeout must surface as an error the UI can show, not kill
            # the handler thread and look like "the bridge is down".
            try:
                return self._send(200, BRIDGE.state())
            except Exception as e:
                return self._send(200, {
                    "ok": False,
                    "error": "Can't reach your agent's controls.",
                    "errorDetail": str(e),
                })
        return self._send(404, {"error": "not found"})

    def _same_origin(self):
        """Reject cross-site POSTs (CSRF). Binding to 127.0.0.1 stops a remote
        attacker from READING this API, but any page the owner happens to visit
        can still POST to it — enough to pause the agent or rewrite its limits.
        A browser always sends Origin on cross-origin POSTs, so requiring it to
        match our own host closes that. Non-browser callers (curl, scripts) send
        no Origin at all and are still allowed — this is the owner's machine."""
        origin = self.headers.get("Origin")
        if origin is not None and origin not in {f"http://127.0.0.1:{PORT}", f"http://localhost:{PORT}"}:
            return False
        # Also pin Host: a rebound DNS name resolving to 127.0.0.1 would carry
        # the attacker's hostname here, so this closes DNS rebinding for reads
        # and writes alike.
        host = (self.headers.get("Host") or "").strip()
        return host in {f"127.0.0.1:{PORT}", f"localhost:{PORT}"}

    def do_POST(self):
        if not self._same_origin():
            return self._send(403, {"error": "cross-site request refused"})
        n = int(self.headers.get("Content-Length", 0) or 0)
        body = json.loads(self.rfile.read(n) or b"{}") if n else {}
        try:
            if self.path == "/api/pause":
                return self._send(200, BRIDGE.pause())
            if self.path == "/api/resume":
                return self._send(200, BRIDGE.resume())
            if self.path == "/api/revoke":
                return self._send(200, BRIDGE.revoke())
            if self.path == "/api/policy":
                return self._send(200, BRIDGE.update(body))
            if self.path == "/api/create":
                return self._send(200, BRIDGE.create(body))
        except Exception as e:
            return self._send(200, {"error": str(e)})
        return self._send(404, {"error": "not found"})


if __name__ == "__main__":
    if BRIDGE.boot_error and not BRIDGE.policy_id:
        print(f"[dashboard] booted with an error (UI will show it): {BRIDGE.boot_error}", flush=True)
    else:
        print(f"[dashboard] agent '{AGENT_NAME}' = {BRIDGE.psy_id}, policy {BRIDGE.policy_id}", flush=True)
    print(f"[dashboard] open http://127.0.0.1:{PORT}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
