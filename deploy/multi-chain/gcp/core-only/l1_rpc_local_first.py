"""Prefer the self-hosted node for reads. Alchemy covers staleness, pruning and outages."""
import hashlib
import importlib.util
import json
from pathlib import Path
import threading
import time

WRAPPER = Path('/opt/psy-private-alchemy-20261027/local-fallback-20261101.py')
WRAPPER_SHA256 = '25ab955d4ebe1391606460953e91b3ebff78a2e73487c6c8d14d44bf5248cb06'
MAX_HEAD_AGE = {'sepolia': 60, 'bscTestnet': 15, 'baseSepolia': 15}
PROBE_EVERY = 5
PROBE_TIMEOUT = 3
GOOD_PROBES_TO_RETURN = 2
REPORT_EVERY = 60
# Off until a real transaction has been seen to propagate from each local node.
SEND_VIA_LOCAL = False
# A pruned node answers these with null, which a caller reads as "does not exist".
NULL_MEANS_UNKNOWN = frozenset(('eth_getTransactionReceipt', 'eth_getTransactionByHash', 'eth_getBlockByNumber',
                                'eth_getBlockByHash', 'eth_getTransactionByBlockNumberAndIndex',
                                'eth_getTransactionByBlockHashAndIndex'))

class LocalState:
    def __init__(self):
        self.fresh = False
        self.good = 0
        self.reason = 'not probed'
        self.lock = threading.Lock()
        self.counts = {}

    def count(self, key):
        with self.lock:
            self.counts[key] = self.counts.get(key, 0) + 1

    def drain(self):
        with self.lock:
            counts, self.counts = self.counts, {}
        return counts

def is_final_error(error):
    message = error.get('message', '').lower()
    return error.get('code') == 3 or 'revert' in message

def local_answer_is_final(rows, result, batch):
    replies = {(type(row['id']).__name__, row['id']): row for row in (result if batch else [result])}
    for row in rows:
        reply = replies[(type(row['id']).__name__, row['id'])]
        if 'error' in reply:
            if not is_final_error(reply['error']):
                return False
        elif reply['result'] is None and row['method'] in NULL_MEANS_UNKNOWN:
            return False
    return True

def probe_reason(call, chain, chain_id, now):
    """Returns None when the node can serve this chain, otherwise a short public reason."""
    replies = call(json.dumps([
        {'jsonrpc': '2.0', 'id': 1, 'method': 'eth_chainId', 'params': []},
        {'jsonrpc': '2.0', 'id': 2, 'method': 'net_peerCount', 'params': []},
        {'jsonrpc': '2.0', 'id': 3, 'method': 'eth_getBlockByNumber', 'params': ['latest', False]}]).encode())
    rows = {row['id']: row.get('result') for row in replies}
    if not rows.get(1) or int(rows[1], 16) != chain_id:
        return 'wrong chain'
    if not rows.get(2) or int(rows[2], 16) < 1:
        return 'no peers'
    if not rows.get(3):
        return 'no head'
    if now - int(rows[3]['timestamp'], 16) > MAX_HEAD_AGE[chain]:
        return 'stale head'
    return None

def update(state, chain, reason):
    was_fresh = state.fresh
    if reason:
        state.good = 0
        state.fresh = False
    else:
        state.good += 1
        state.fresh = state.fresh or state.good >= GOOD_PROBES_TO_RETURN
    state.reason = reason
    if state.fresh != was_fresh:
        print(json.dumps({'chain': chain, 'local_fresh': state.fresh, 'reason': reason}), flush=True)

def install(module, local_urls):
    """Replaces module.forward. Returns the per-chain states so main can start the probes."""
    states = {chain: LocalState() for chain in module.CHAINS}
    base_forward = module.forward
    def forward(chain, providers, body):
        rows, batch = module.requests(body)
        state = states[chain]
        local = next(row for row in providers if row['label'] == 'local')
        remote = [row for row in providers if row is not local]
        fresh = state.fresh
        if not all(row['method'] in module.READ_METHODS for row in rows):
            # base_forward sends to the first candidate only and never replays a send.
            use_local = SEND_VIA_LOCAL and fresh
            state.count('send_local' if use_local else 'send_remote')
            return base_forward(chain, [local] if use_local else remote, body)
        if not SEND_VIA_LOCAL and any(row['method'] == 'eth_getTransactionCount' for row in rows):
            # The nonce must come from the node that takes the sends: a lagging node hands out a used one.
            state.count('read_nonce_remote')
            return base_forward(chain, remote + [local], body)
        if not fresh:
            state.count('read_while_stale')
            return base_forward(chain, remote + [local], body)
        try:
            result = module.checked_response(module.upstream(local['url'], body), rows, batch)
            if local_answer_is_final(rows, result, batch):
                state.count('read_local')
                return result
            state.count('read_fallback_answer')
        except Exception:
            state.count('read_fallback_failure')
        return base_forward(chain, remote, body)
    module.forward = forward
    return states

def probe_loop(module, chain, url, state):
    chain_id = module.CHAINS[chain][0]
    def call(body):
        return module.upstream_transport(url, body)
    while True:
        try:
            reason = probe_reason(call, chain, chain_id, time.time())
        except Exception as error:
            reason = type(error).__name__
        update(state, chain, reason)
        time.sleep(PROBE_EVERY)

def report_loop(states):
    while True:
        time.sleep(REPORT_EVERY)
        for chain, state in states.items():
            print(json.dumps({'chain': chain, 'local_fresh': state.fresh, 'reason': state.reason,
                              'counts': state.drain()}), flush=True)

def load_wrapper(path=WRAPPER):
    if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != WRAPPER_SHA256:
        raise RuntimeError('private proxy wrapper mismatch')
    spec = importlib.util.spec_from_file_location('psy_local_fallback', path)
    wrapper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(wrapper)
    return wrapper

def start(module, local_urls):
    states = install(module, local_urls)
    for chain, state in states.items():
        threading.Thread(target=probe_loop, args=(module, chain, local_urls[chain], state), daemon=True).start()
    threading.Thread(target=report_loop, args=(states,), daemon=True).start()
    return states

if __name__ == '__main__':
    wrapper = load_wrapper()
    private_proxy = wrapper.load_private_proxy()
    start(private_proxy, wrapper.LOCAL)
    private_proxy.main()
