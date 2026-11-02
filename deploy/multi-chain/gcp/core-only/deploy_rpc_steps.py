#!/usr/bin/env python3
"""Step 56: put the self-hosted L1 nodes first on the gateway's private RPC proxy.

Guardian, Services, Envio and the Relayer all reach L1 through that proxy, so the order is set in one place. The proxy
and its retained wrappers live on the gateway; this step adds the local-first wrapper and proves it took effect. It
restarts the proxy only when the installed wrapper differs. Records the settled state, never a credential.
"""
import base64
import hashlib
import json
from pathlib import Path

from deploy_prepare_steps import file_sha256, require
from deploy_remote import Step, wait_until

GATEWAY_HOST = "gcp-gateway"
UNIT = "psy-private-alchemy-20261027.service"
PROXY_DIR = "/opt/psy-private-alchemy-20261027"
TARGET = f"{PROXY_DIR}/local-first-20261102.py"
RETAINED_WRAPPER = f"{PROXY_DIR}/local-fallback-20261101.py"
DROP_IN_DIR = f"/etc/systemd/system/{UNIT}.d"
DROP_IN = f"{DROP_IN_DIR}/91-local-first-20261102.conf"
DROP_IN_TEXT = f"[Service]\nExecStart=\nExecStart=/usr/bin/python3 -I -B {TARGET}\n"
SOURCE = Path(__file__).resolve().with_name("l1_rpc_local_first.py")
CHAINS = ("sepolia", "bscTestnet", "baseSepolia")
COMMAND_SECONDS = 60
FRESH_POLL_SECONDS = 5
FRESH_WAIT_SECONDS = 90
# Long enough for one periodic report, short enough to skip reports of the process a restart replaced.
JOURNAL_WINDOW = "-70 seconds"
READ_STATE = """import hashlib, json, sys
def sha(path):
    try:
        return hashlib.sha256(open(path, 'rb').read()).hexdigest()
    except FileNotFoundError:
        return None
print(json.dumps(dict(target=sha(sys.argv[1]), retained=sha(sys.argv[2]), drop_in=sha(sys.argv[3]))))
"""
INSTALL = """import base64, json, os, sys
args = json.loads(sys.stdin.readline())
for path, text, mode in ((args['target'], args['source'], 0o755), (args['drop_in'], args['drop_in_text'], 0o644)):
    temporary = path + '.new'
    with open(temporary, 'wb') as file:
        file.write(base64.b64decode(text))
    os.chmod(temporary, mode)
    os.replace(temporary, path)
"""


def text_sha256(text):
    return hashlib.sha256(text.encode()).hexdigest()


def read_installed(ctx):
    output = ctx.remote.run_root_text(GATEWAY_HOST, ["/usr/bin/python3", "-I", "-c", READ_STATE, TARGET,
                                                     RETAINED_WRAPPER, DROP_IN], COMMAND_SECONDS)
    return json.loads(output)


def is_installed(state):
    return state["target"] == file_sha256(SOURCE) and state["drop_in"] == text_sha256(DROP_IN_TEXT)


def rpc_check(ctx):
    state = read_installed(ctx)
    require(state["retained"] is not None, f"the gateway lacks the retained proxy wrapper {RETAINED_WRAPPER}")
    pinned = f"WRAPPER_SHA256 = '{state['retained']}'"
    require(pinned in SOURCE.read_text(), "l1_rpc_local_first.py pins another retained wrapper")


def rpc_apply(ctx):
    if is_installed(read_installed(ctx)):
        return
    arguments = {"target": TARGET, "drop_in": DROP_IN,
                 "source": base64.b64encode(SOURCE.read_bytes()).decode(),
                 "drop_in_text": base64.b64encode(DROP_IN_TEXT.encode()).decode()}
    ctx.remote.run_root_text(GATEWAY_HOST, ["/usr/bin/python3", "-I", "-c", INSTALL], COMMAND_SECONDS,
                             stdin_text=json.dumps(arguments) + "\n")
    ctx.remote.run_root_text(GATEWAY_HOST, ["/usr/bin/systemctl", "daemon-reload"], COMMAND_SECONDS)
    ctx.remote.run_root_text(GATEWAY_HOST, ["/usr/bin/systemctl", "restart", UNIT], COMMAND_SECONDS)


def read_freshness(ctx):
    """The last word per chain from this process's journal; a chain with no report is not fresh."""
    output = ctx.remote.run_root_text(GATEWAY_HOST, ["/usr/bin/journalctl", "-u", UNIT, "--no-pager", "-o", "cat",
                                                     "--since", JOURNAL_WINDOW], COMMAND_SECONDS)
    fresh = {}
    for line in output.splitlines():
        if line.startswith("{") and '"local_fresh"' in line:
            row = json.loads(line)
            fresh[row["chain"]] = row["local_fresh"]
    return fresh


def rpc_verify(ctx):
    require(is_installed(read_installed(ctx)), "the gateway does not hold the local-first wrapper")
    state = {}
    def is_ready():
        state.update(read_freshness(ctx))
        return all(state.get(chain) is True for chain in CHAINS)
    wait_until(is_ready, lambda: None, FRESH_POLL_SECONDS, FRESH_WAIT_SECONDS, "local L1 nodes")
    return {"local_fresh": state, "wrapper_sha256": file_sha256(SOURCE)}


RPC_STEPS = {"ensure_l1_rpc_routing": Step("ensure_l1_rpc_routing", rpc_check, rpc_apply, rpc_verify, cutover=False)}
