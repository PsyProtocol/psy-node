#!/usr/bin/env python3
"""Acceptance helpers: the private gateway tunnel, the deposit pause window and the EVM reads of the three chains.

A window opens deposits on one chain, never on two at once, and the pause comes back on every exit, including an
exception or Ctrl-C. If the pause cannot be restored the error names the chain and carries the original failure.
Reads and sends use the private gateway port of each chain (a tunnel to the signer host), never the public route:
the public route can lag one block behind an administrator transaction.
"""
import base64
from contextlib import contextmanager
import hashlib
import json
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request

import deploy_bridge_steps as bridge_steps
import deploy_prepare_steps as prepare
import fresh_l1
import release_lock
from deploy_remote import wait_until

PYTHON = "/usr/bin/python3"
GATEWAY_PORTS = {chain: fresh_l1.NETWORKS[chain][2] for chain in release_lock.CHAINS}
LOCAL_PORT_OFFSET = 10000
CHAIN_INDEX = {chain: fresh_l1.NETWORKS[chain][1] for chain in release_lock.CHAINS}
PAUSED, OPEN = [1, 0, 1], [0, 0, 0]
PAUSE_FEE_CAP_GWEI = 5
ADMIN_SECONDS = 1500
LOCK_PATH = "/run/psy-admin-pause.lock"
LOCK_WAIT_SECONDS = 600
PENDING_POLLS, PENDING_POLL_MS = 30, 2000
REPAUSE_ATTEMPTS = 3
REPAUSE_PAUSE_SECONDS = 5
FLAG_POLL_SECONDS = 3
FLAG_WAIT_SECONDS = 60
RPC_SECONDS = 30
TUNNEL_WAIT_SECONDS = 30
# Router and Bridge selectors (cast sig) and the two deposit reverts the window must see.
DEPOSIT_SELECTOR = "0x7dcc9f07"
GET_PAUSE_FLAGS, PENDING_COUNT, PROVED_COUNT, BALANCE_OF = "0xfeee6b4f", "0x52c2d373", "0x939497f0", "0x70a08231"
REVERT_PAUSED, REVERT_ZERO_AMOUNT = "0xeb225a73", "0x1f2a2005"
ZERO_ADDRESS = "0x" + "0" * 40
OPEN_CHAINS = []


def require(condition, message):
    if not condition:
        raise ValueError(message)


def local_url(chain):
    return f"http://127.0.0.1:{GATEWAY_PORTS[chain] + LOCAL_PORT_OFFSET}"


def word(value):
    return f"{int(value, 16) if isinstance(value, str) else value:064x}"


def address_word(address):
    return address.lower().removeprefix("0x").rjust(64, "0")


def json_rpc(url, method, params, timeout=RPC_SECONDS):
    """(result, error) of one JSON-RPC call; a transport failure raises."""
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout) as response:
            answer = json.loads(response.read())
    except urllib.error.HTTPError as error:
        with error:
            answer = json.loads(error.read() or b"{}")
    return answer.get("result"), answer.get("error")


@contextmanager
def gateway_tunnel(ctx, host=None):
    """ssh -L to the private gateway ports of the three chains on the signer host; closed on every exit."""
    host = host or bridge_steps.signer_host(ctx)
    forwards = [(GATEWAY_PORTS[chain] + LOCAL_PORT_OFFSET, GATEWAY_PORTS[chain]) for chain in release_lock.CHAINS]
    process = subprocess.Popen(ctx.remote.tunnel_argv(host, forwards), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
    try:
        def listening():
            for local, _ in forwards:
                with socket.socket() as probe:
                    probe.settimeout(1)
                    if probe.connect_ex(("127.0.0.1", local)) != 0:
                        return False
            return True
        wait_until(listening, lambda: "the gateway tunnel exited" if process.poll() is not None else None, 1,
                   TUNNEL_WAIT_SECONDS, "gateway tunnel")
        yield forwards
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def admin_request(ctx, chain, target, execute, documents):
    core = documents[chain]["core"]
    budget, _ = prepare.gas_budget(ctx, chain)
    return {"chain": chain, "target": target, "execute": execute, "signer": ctx.lock["l1"]["signer"],
            "chain_id": fresh_l1.NETWORKS[chain][0],
            "port": GATEWAY_PORTS[chain], "bridge": core["Bridge"], "acl": core["PsyACLManager"],
            "tokens": [ZERO_ADDRESS, core["PsyToken"], core["USDTToken"]], "keystore": prepare.SIGNER_KEYSTORE_FILE,
            "env_file": fresh_l1.WALLET_ENV, "node": bridge_steps.NODE_PATH,
            "ethers": f"{bridge_steps.bundle_dir(ctx)}/contracts/node_modules/ethers",
            "max_gas": int(budget["maxGasPerTransaction"]), "max_fee_gwei": PAUSE_FEE_CAP_GWEI,
            "lock_path": LOCK_PATH, "lock_wait_seconds": LOCK_WAIT_SECONDS, "pending_polls": PENDING_POLLS,
            "pending_poll_ms": PENDING_POLL_MS}


def run_admin(ctx, chain, target, execute, documents=None):
    """Run the pinned pause tool on the signer host; returns its report, raises with the reason it printed."""
    from deploy_public_steps import l1_documents
    prepare.check_tool_hash(ctx, "admin_pause.py")
    source = (prepare.TOOLS_DIR / "admin_pause.py").read_text()
    raw = json.dumps(admin_request(ctx, chain, target, execute, documents or l1_documents(ctx)), sort_keys=True).encode()
    output = ctx.remote.run_root_text(bridge_steps.signer_host(ctx), [PYTHON, "-I", "-B", "/dev/stdin", "--request-base64",
                                      base64.b64encode(raw).decode(), "--request-sha256", hashlib.sha256(raw).hexdigest()],
                                      ADMIN_SECONDS, stdin_text=source, show_stderr=True)
    report = json.loads(output.strip().splitlines()[-1]) if output.strip() else {}
    require(report.get("ok") is True, f"{chain}: the pause tool did not report success")
    return report


class WindowSignal(BaseException):
    """SIGTERM or SIGHUP during a window: unwinds like Ctrl-C so the pause is restored."""


def raise_window_signal(signum, frame):
    raise WindowSignal(signal.Signals(signum).name)


def restore_pause(ctx, chain, admin, sleep=time.sleep):
    """Pause again, with a few attempts; a further interrupt during an attempt only costs that attempt."""
    last = None
    for attempt in range(REPAUSE_ATTEMPTS):
        try:
            report = admin(ctx, chain, 1, True)
            if report.get("flags") == [PAUSED] * 3:
                return report
            last = f"read-back flags {report.get('flags')}"
        except BaseException as error:
            last = f"{type(error).__name__}: {error}"
        if attempt + 1 < REPAUSE_ATTEMPTS:
            try:
                sleep(REPAUSE_PAUSE_SECONDS)
            except BaseException:
                pass
    raise RuntimeError(f"{chain}: deposits are still OPEN, pause them by hand now ({last})")


@contextmanager
def window_signals():
    """Route SIGTERM and SIGHUP into the exception path; outside the main thread the handlers stay as they are."""
    previous = {}
    try:
        for number in (signal.SIGTERM, signal.SIGHUP):
            previous[number] = signal.signal(number, raise_window_signal)
    except ValueError:
        pass
    try:
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


@contextmanager
def unpaused_chain(ctx, chain, admin=None, sleep=time.sleep):
    """Unpause one chain, yield, and restore and read back the pause on any exit; the original error stays visible.

    The guarded region starts before the unpause is sent: a timeout, a bad read-back or an interrupt after the
    broadcast still ends in a re-pause attempt, which is harmless when the chain never opened.
    """
    admin = admin or run_admin
    if OPEN_CHAINS:
        raise RuntimeError(f"{OPEN_CHAINS[0]} is still unpaused; windows open one chain at a time")
    OPEN_CHAINS.append(chain)
    original = None
    with window_signals():
        try:
            opened = admin(ctx, chain, 0, True)
            require(opened.get("flags") == [OPEN] * 3, f"{chain}: the unpause was not read back as open")
            yield opened
        except BaseException as error:
            original = error
            raise
        finally:
            try:
                restore_pause(ctx, chain, admin, sleep)
                OPEN_CHAINS.remove(chain)
            except RuntimeError as failure:
                if original is not None:
                    raise RuntimeError(f"{failure}; the window ended with {type(original).__name__}: {original}") from original
                raise


def unpaused_chains(ctx, admin=None):
    """Chains whose deposits are not paused right now, from a read-only run of the tool."""
    admin = admin or run_admin
    return [chain for chain in release_lock.CHAINS if admin(ctx, chain, 1, False).get("flagsBefore") != [PAUSED] * 3]


def read_flags(chain, bridge, token):
    result, error = json_rpc(local_url(chain), "eth_call", [{"to": bridge, "data": GET_PAUSE_FLAGS + address_word(token)}, "latest"])
    require(error is None and isinstance(result, str) and len(result) == 2 + 3 * 64, f"{chain}: pause flags could not be read")
    return [int(result[2 + 64 * index:2 + 64 * (index + 1)], 16) for index in range(3)]


def read_count(chain, bridge, selector):
    result, error = json_rpc(local_url(chain), "eth_call", [{"to": bridge, "data": selector}, "latest"])
    require(error is None and isinstance(result, str), f"{chain}: deposit count could not be read")
    return int(result, 16)


def read_balance(chain, asset, owner):
    result, error = json_rpc(local_url(chain), "eth_call", [{"to": asset, "data": BALANCE_OF + address_word(owner)}, "latest"])
    require(error is None and isinstance(result, str), f"{chain}: balance could not be read")
    return int(result, 16)


def estimate_deposit(chain, wallet, router, asset, amount):
    """(revert selector or None, gas or None) of an eth_estimateGas for Router.deposit; no transaction is sent."""
    data = DEPOSIT_SELECTOR + address_word(asset) + word(amount) + "11" * 32 + "22" * 32
    result, error = json_rpc(local_url(chain), "eth_estimateGas", [{"from": wallet, "to": router, "data": data}])
    if error is None:
        return None, int(result, 16)
    detail = error.get("data")
    return (detail[:10] if isinstance(detail, str) else str(error.get("message", ""))[:10]), None


def expect_revert(chain, wallet, router, asset, amount, selector, label):
    revert, _ = estimate_deposit(chain, wallet, router, asset, amount)
    require(revert == selector, f"{chain}: the {label} deposit was not rejected with {selector} (got {revert})")


def wait_for_flags(chain, bridge, asset, wanted):
    """Two reads in a row, a few seconds apart: the gateway answers consistently before anything is sent."""
    state = {"previous": None}

    def agreed():
        flags = read_flags(chain, bridge, asset)
        done = flags == wanted and state["previous"] == wanted
        state["previous"] = flags
        return done
    wait_until(agreed, lambda: None, FLAG_POLL_SECONDS, FLAG_WAIT_SECONDS, f"{chain} pause flags")


def run_window(ctx, chain, documents, wallet, deposit, admin=None):
    """Illegal deposit while paused, unpause, illegal deposit while open, one legal deposit, pause again; one chain."""
    core = documents[chain]["core"]
    bridge, router, asset = core["Bridge"], core["Router"], core["USDTToken"]
    require(read_flags(chain, bridge, asset) == PAUSED, f"{chain}: the window needs a paused chain to start")
    expect_revert(chain, wallet, router, asset, 1_000_000, REVERT_PAUSED, "illegal paused")
    with unpaused_chain(ctx, chain, admin):
        wait_for_flags(chain, bridge, asset, OPEN)
        expect_revert(chain, wallet, router, asset, 0, REVERT_ZERO_AMOUNT, "illegal open")
        deposited = deposit()
    require(read_flags(chain, bridge, asset) == PAUSED, f"{chain}: the pause was not restored")
    return deposited
