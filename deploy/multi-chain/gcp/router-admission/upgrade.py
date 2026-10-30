"""Root-only Router upgrade custody adapter; no credentials in files or diagnostics."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import signal
import stat
import subprocess

HERE = Path('/opt/psy-router-admission-20261030')
KEY = Path('/var/lib/parth/.psy/keystore/bridge-relayer-dev')
HELPER = Path('/var/tmp/psy-r3-l1-helper-20261027/fresh_l1.py')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['audit', 'queue', 'reconcile', 'activate', 'idle'])
    parser.add_argument('chain', choices=['sepolia', 'bscTestnet', 'baseSepolia'])
    parser.add_argument('--relayer-quiesced', action='store_true')
    args = parser.parse_args()
    assert os.geteuid() == 0 and os.uname().nodename.startswith('faucet')
    writing = args.mode in ('queue', 'activate')
    assert not writing or args.relayer_quiesced
    for name in ('upgrade.py', 'upgrade.cjs', 'Router.json', 'manifest.json'):
        info = (HERE / name).lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
    with Path('/var/lib/psy-deposit-acceptance-r3-20261027/.admin.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        request = dict(mode=args.mode, chain=args.chain, relayerQuiesced=args.relayer_quiesced)
        if writing:
            assert hashlib.sha256(HELPER.read_bytes()).hexdigest() == '51900aebfd3b01b0ed5110c1db81d1d58fc46657f1c02568175700dfb720c6aa'
            assert hashlib.sha256(KEY.read_bytes()).hexdigest() == '2a100a28748685bcba8a9abf8dd6c4e15361d6e5ec306b72b6a32e45d838c184'
            spec = importlib.util.spec_from_file_location('r3_custody', HELPER)
            helper = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(helper)
            request.update(encrypted=KEY.read_text(), password=helper.secret_env(['/etc/parth/relayer.env'])['WALLET_PASSWORD'])
        process = subprocess.Popen(['/opt/psy-l1-bundles/node-v22.23.4', str(HERE / 'upgrade.cjs')],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            env={'PATH': '/usr/bin:/bin', 'HOME': '/root'}, start_new_session=True)
        try:
            out, _ = process.communicate(json.dumps(request), timeout=460)
            value = json.loads(out)
            print(json.dumps(value))
            if process.returncode or value.get('ok') is not True:
                raise SystemExit(1)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.communicate()


if __name__ == '__main__':
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        main()
    except Exception:
        print(json.dumps(dict(ok=False, noRetry=True, preserveEvidence=True)))
        raise SystemExit(1)
