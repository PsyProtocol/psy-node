"""Drive the real psy_mcp_server over stdio as an AI agent would, and emit a
transcript suitable for recording.

This speaks actual MCP (JSON-RPC 2.0 over stdio) to the real binary — every tool
call below hits WalletSession and, for spends, produces a real Plonky2 proof.
Nothing is simulated; the policy denial at the end is the server refusing the
agent, not a scripted line.
"""
import json
import subprocess
import sys
import threading
import queue
import time


class McpClient:
    def __init__(self, cmd, env=None, cwd=None):
        self.proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1, env=env, cwd=cwd,
        )
        self._id = 0
        self._q = queue.Queue()
        self.stderr_lines = []
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()

    def _read_stdout(self):
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                self._q.put(json.loads(line))
            except json.JSONDecodeError:
                pass

    def _read_stderr(self):
        for line in self.proc.stderr:
            self.stderr_lines.append(line.rstrip())

    def send(self, method, params=None, timeout=600):
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                resp = self._q.get(timeout=2)
            except queue.Empty:
                if self.proc.poll() is not None:
                    raise RuntimeError(f"server exited: {self.stderr_lines[-6:]}")
                continue
            if resp.get("id") == self._id:
                return resp
        raise TimeoutError(f"{method} timed out after {timeout}s")

    def notify(self, method, params=None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def call_tool(self, name, args=None, timeout=900):
        resp = self.send("tools/call", {"name": name, "arguments": args or {}}, timeout=timeout)
        result = resp.get("result", {})
        content = result.get("content", [])
        text = content[0].get("text", "") if content else json.dumps(resp.get("error", {}))
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"raw": text}

    def close(self):
        try:
            self.proc.terminate()
        except Exception:
            pass


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else "./target/release/psy-mcp-server"
    config = sys.argv[2] if len(sys.argv) > 2 else "/tmp/psy-staging-proxy-config-694.json"
    import os
    env = dict(os.environ, PSY_CONFIG=config, PSY_MCP_KEYSTORE_DIR="/tmp/psy-demo-2026/mcp/keys")

    print("→ starting psy-mcp-server (real WalletSession)…", flush=True)
    c = McpClient([binary], env=env)
    init = c.send("initialize", {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "psy-demo-agent", "version": "1.0"},
    }, timeout=300)
    server = init.get("result", {}).get("serverInfo", {})
    print(f"✓ connected: {server.get('name')} v{server.get('version')}", flush=True)
    c.notify("notifications/initialized")

    tools = c.send("tools/list", {}, timeout=60).get("result", {}).get("tools", [])
    print(f"✓ {len(tools)} tools exposed: " + ", ".join(t["name"] for t in tools), flush=True)

    print("\n[1] Human creates the agent's wallet with a spending policy", flush=True)
    w = c.call_tool("create_wallet", {
        "mode": "generate",
        "agent_id": "demo-agent",
        "perTransaction": 2_000_000_000,
        "perDay": 5_000_000_000,
    })
    print(json.dumps(w, indent=2)[:700], flush=True)
    if w.get("status") != "ok":
        print("create_wallet failed; stopping", flush=True)
        c.close()
        return 1

    print("\n[2] Human issues a short-lived session token to the agent", flush=True)
    s = c.call_tool("issue_session", {"policy_id": w["policyId"], "ttl_minutes": 30})
    print(json.dumps(s, indent=2)[:400], flush=True)
    token = s.get("token")

    print("\n[3] Agent checks how much it is allowed to spend", flush=True)
    print(json.dumps(c.call_tool("check_budget", {"session": token}), indent=2), flush=True)

    print("\n[4] Agent reads live chain state", flush=True)
    print(json.dumps(c.call_tool("get_chain_status"), indent=2), flush=True)
    print(json.dumps(c.call_tool("get_user_info"), indent=2), flush=True)

    print("\n[5] Agent attempts a payment ABOVE the human's per-transaction cap", flush=True)
    over = c.call_tool("transfer", {"session": token, "to_user_id": 262144, "amount_nano": 9_000_000_000})
    print(json.dumps(over, indent=2)[:500], flush=True)

    print("\n[6] Owner pauses the policy — all agent spending freezes", flush=True)
    print(json.dumps(c.call_tool("pause_policy", {"policy_id": w["policyId"]}), indent=2), flush=True)
    blocked = c.call_tool("transfer", {"session": token, "to_user_id": 262144, "amount_nano": 1_000_000_000})
    print(json.dumps(blocked, indent=2)[:400], flush=True)
    print(json.dumps(c.call_tool("resume_policy", {"policy_id": w["policyId"]}), indent=2), flush=True)

    print("\n--- server log tail ---", flush=True)
    for line in c.stderr_lines[-12:]:
        print("  " + line[:160], flush=True)
    c.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
