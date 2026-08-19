#!/usr/bin/env python3
import json
import os
import re
import urllib.error
import urllib.request
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return int(raw)


def eth_to_wei_hex(amount: str) -> str:
    wei = int(Decimal(amount) * Decimal(10**18))
    return hex(wei)


PORT = env_int("LOCAL_CF_ETH_FAUCET_PORT", 8555)
RPC_URL = os.environ.get("LOCAL_CF_ETH_FAUCET_RPC_URL") or os.environ.get(
    "LOCAL_STAGING_L1_RPC_URL",
    f"http://127.0.0.1:{os.environ.get('LOCAL_STAGING_L1_RPC_PORT', '8545')}",
)
TARGET_BALANCE_ETH = os.environ.get("LOCAL_CF_ETH_FAUCET_BALANCE_ETH", "10")
TARGET_BALANCE_WEI_HEX = eth_to_wei_hex(TARGET_BALANCE_ETH)
PUBLIC_RPC_URL = os.environ.get("LOCAL_CF_ETH_FAUCET_PUBLIC_RPC_URL") or os.environ.get(
    "LOCAL_CF_L1_RPC_URL"
)
if not PUBLIC_RPC_URL:
    public_rpc_host = os.environ.get("LOCAL_CF_L1_RPC_HOST", "rpc-local.psy-protocol.xyz")
    PUBLIC_RPC_URL = f"https://{public_rpc_host}"
PUBLIC_CHAIN_NAME = os.environ.get("LOCAL_CF_ETH_FAUCET_CHAIN_NAME", "Psy Localhost L1")
PUBLIC_CHAIN_ID = env_int("LOCAL_STAGING_L1_CHAIN_ID", 31338)
PUBLIC_CHAIN_ID_HEX = hex(PUBLIC_CHAIN_ID)


def rpc(method: str, params: list):
    payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }
    ).encode()
    req = urllib.request.Request(
        RPC_URL,
        data=payload,
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.URLError as exc:
        raise RuntimeError(f"RPC request failed: {exc}") from exc
    if data.get("error"):
        raise RuntimeError(data["error"].get("message") or str(data["error"]))
    return data.get("result")


def html() -> bytes:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Psy Local ETH Faucet</title>
  <style>
    :root {{
      color-scheme: light;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: #111827;
      background: #f7f8fb;
    }}
    body {{
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 24px;
    }}
    main {{
      width: min(100%, 480px);
      background: #fff;
      border: 1px solid #e5e7eb;
      border-radius: 8px;
      box-shadow: 0 12px 36px rgba(15, 23, 42, 0.08);
      padding: 24px;
    }}
    h1 {{
      margin: 0 0 8px;
      font-size: 24px;
      line-height: 1.2;
    }}
    p {{
      margin: 0 0 18px;
      color: #4b5563;
      line-height: 1.5;
    }}
    .row {{
      display: flex;
      gap: 10px;
      margin-bottom: 14px;
    }}
    .row button {{
      margin-top: 0;
    }}
    .secondary {{
      background: #fff;
      color: #111827;
      border: 1px solid #d1d5db;
    }}
    label {{
      display: block;
      font-size: 13px;
      font-weight: 600;
      margin-bottom: 8px;
    }}
    input {{
      width: 100%;
      box-sizing: border-box;
      border: 1px solid #d1d5db;
      border-radius: 6px;
      padding: 11px 12px;
      font: inherit;
      outline: none;
    }}
    input:focus {{
      border-color: #2563eb;
      box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.14);
    }}
    button {{
      width: 100%;
      border: 0;
      border-radius: 6px;
      background: #111827;
      color: #fff;
      font: inherit;
      font-weight: 650;
      padding: 12px 14px;
      margin-top: 14px;
      cursor: pointer;
    }}
    button:disabled {{
      cursor: wait;
      opacity: 0.68;
    }}
    .hint {{
      margin-top: 8px;
      font-size: 12px;
      color: #6b7280;
    }}
    pre {{
      margin: 14px 0 0;
      white-space: pre-wrap;
      word-break: break-word;
      background: #f3f4f6;
      border-radius: 6px;
      padding: 12px;
      font-size: 13px;
      line-height: 1.45;
      min-height: 20px;
    }}
  </style>
</head>
<body>
  <main>
    <h1>Psy Local ETH Faucet</h1>
    <p>Connect MetaMask or paste an address to top it up to {TARGET_BALANCE_ETH} ETH on the shared local Anvil chain.</p>
    <div class="row">
      <button id="connect" type="button" class="secondary">Connect MetaMask</button>
      <button id="switch" type="button" class="secondary">Switch Localhost</button>
    </div>
    <form id="form">
      <label for="address">Wallet address</label>
      <input id="address" name="address" placeholder="0x..." autocomplete="off" spellcheck="false" />
      <div class="hint">Network: {PUBLIC_CHAIN_NAME} · chainId {PUBLIC_CHAIN_ID} · RPC {PUBLIC_RPC_URL}</div>
      <button id="submit" type="submit">Top up ETH</button>
    </form>
    <pre id="result">Ready.</pre>
  </main>
  <script>
    const basePath = window.location.pathname.startsWith('/eth-faucet') ? '/eth-faucet' : '';
    const form = document.getElementById('form');
    const address = document.getElementById('address');
    const result = document.getElementById('result');
    const submit = document.getElementById('submit');
    const connect = document.getElementById('connect');
    const switchNetwork = document.getElementById('switch');
    const chain = {{
      chainId: {json.dumps(PUBLIC_CHAIN_ID_HEX)},
      chainName: {json.dumps(PUBLIC_CHAIN_NAME)},
      nativeCurrency: {{ name: 'Ether', symbol: 'ETH', decimals: 18 }},
      rpcUrls: [{json.dumps(PUBLIC_RPC_URL)}],
    }};

    async function ensureLocalhostNetwork() {{
      if (!window.ethereum) throw new Error('MetaMask is not available');
      try {{
        await window.ethereum.request({{
          method: 'wallet_switchEthereumChain',
          params: [{{ chainId: chain.chainId }}],
        }});
      }} catch (error) {{
        if (error && error.code === 4902) {{
          await window.ethereum.request({{
            method: 'wallet_addEthereumChain',
            params: [chain],
          }});
          return;
        }}
        throw error;
      }}
    }}

    async function connectWallet() {{
      if (!window.ethereum) throw new Error('MetaMask is not available');
      const accounts = await window.ethereum.request({{ method: 'eth_requestAccounts' }});
      if (!accounts || !accounts[0]) throw new Error('No account selected');
      address.value = accounts[0];
      try {{
        await ensureLocalhostNetwork();
        result.textContent = `Connected ${{accounts[0]}} on Localhost.`;
      }} catch (error) {{
        result.textContent = `Connected ${{accounts[0]}}, but network switch failed: ${{error.message || error}}`;
      }}
    }}

    connect.addEventListener('click', async () => {{
      connect.disabled = true;
      result.textContent = 'Connecting MetaMask...';
      try {{
        await connectWallet();
      }} catch (error) {{
        result.textContent = `Error: ${{error.message || error}}`;
      }} finally {{
        connect.disabled = false;
      }}
    }});

    switchNetwork.addEventListener('click', async () => {{
      switchNetwork.disabled = true;
      result.textContent = 'Switching MetaMask network...';
      try {{
        await ensureLocalhostNetwork();
        result.textContent = 'MetaMask is using Localhost.';
      }} catch (error) {{
        result.textContent = `Error: ${{error.message || error}}`;
      }} finally {{
        switchNetwork.disabled = false;
      }}
    }});

    if (window.ethereum) {{
      window.ethereum.request({{ method: 'eth_accounts' }}).then((accounts) => {{
        if (accounts && accounts[0]) address.value = accounts[0];
      }}).catch(() => {{}});
      window.ethereum.on?.('accountsChanged', (accounts) => {{
        if (accounts && accounts[0]) address.value = accounts[0];
      }});
    }}

    form.addEventListener('submit', async (event) => {{
      event.preventDefault();
      submit.disabled = true;
      result.textContent = 'Requesting local ETH...';
      try {{
        const resp = await fetch(`${{basePath}}/faucet`, {{
          method: 'POST',
          headers: {{ 'content-type': 'application/json' }},
          body: JSON.stringify({{ address: address.value.trim() }}),
        }});
        const body = await resp.json();
        if (!resp.ok || !body.ok) throw new Error(body.error || 'faucet failed');
        result.textContent = `Ready: ${{body.address}} now has at least ${{body.target_balance_eth}} ETH on Localhost.`;
      }} catch (error) {{
        result.textContent = `Error: ${{error.message || error}}`;
      }} finally {{
        submit.disabled = false;
      }}
    }});
  </script>
</body>
</html>
""".encode()


class Handler(BaseHTTPRequestHandler):
    server_version = "PsyLocalEthFaucet/1.0"

    def log_message(self, fmt: str, *args):
        print(f"{self.address_string()} - {fmt % args}", flush=True)

    def send_json(self, status: int, body: dict):
        encoded = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("access-control-allow-origin", "*")
        self.send_header("access-control-allow-methods", "GET, POST, OPTIONS")
        self.send_header("access-control-allow-headers", "content-type")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_OPTIONS(self):
        self.send_json(200, {"ok": True})

    def do_GET(self):
        if self.path in {"/health", "/eth-faucet/health"}:
            self.send_json(
                200,
                {
                    "ok": True,
                    "rpc_url": RPC_URL,
                    "public_rpc_url": PUBLIC_RPC_URL,
                    "target_balance_eth": TARGET_BALANCE_ETH,
                },
            )
            return
        encoded = html()
        self.send_response(200)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self):
        if self.path not in {"/faucet", "/eth-faucet/faucet"}:
            self.send_json(404, {"ok": False, "error": "not found"})
            return
        try:
            length = int(self.headers.get("content-length", "0"))
            body = json.loads(self.rfile.read(length).decode() or "{}")
            address = str(body.get("address", "")).strip()
            if not ADDRESS_RE.match(address):
                self.send_json(400, {"ok": False, "error": "invalid address"})
                return
            current_balance = rpc("eth_getBalance", [address, "latest"])
            if int(current_balance, 16) < int(TARGET_BALANCE_WEI_HEX, 16):
                rpc("anvil_setBalance", [address, TARGET_BALANCE_WEI_HEX])
            self.send_json(
                200,
                {
                    "ok": True,
                    "address": address,
                    "target_balance_eth": TARGET_BALANCE_ETH,
                    "target_balance_wei_hex": TARGET_BALANCE_WEI_HEX,
                },
            )
        except Exception as exc:
            self.send_json(500, {"ok": False, "error": str(exc)})


if __name__ == "__main__":
    print(
        f"[eth-faucet] listening on 127.0.0.1:{PORT}, rpc={RPC_URL}, target={TARGET_BALANCE_ETH} ETH",
        flush=True,
    )
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
