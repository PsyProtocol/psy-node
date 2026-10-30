"""Serialize authorized Router governance operations with the live L1 signer."""
import argparse
import datetime
import fcntl
import json
import os
from pathlib import Path
import subprocess

UNIT = 'psy-core-relayer-r3.service'
CHAINS = ('sepolia', 'bscTestnet', 'baseSepolia')
HERE = Path(__file__).resolve().parent


def remote(role, command, timeout=500):
    address, alias, host = {
        'admin': ('10.148.0.33', '136.110.35.53', 'gcp-faucet'),
        'relayer': ('10.148.0.31', '35.187.246.102', 'gcp-coordinator-worker'),
    }[role]
    result = subprocess.run(['ssh', '-J', 'gcp-gateway', '-o', 'Hostname='+address,
        '-o', 'HostKeyAlias='+alias, '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
        '-o', 'ConnectTimeout=20', host, command], capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(role+' operation failed: retain hold, reconcile transactions before signer reuse')
    return result.stdout.strip()


def state():
    return dict(line.split('=', 1) for line in remote('relayer',
        'systemctl show '+UNIT+' -p ActiveState -p MainPID').splitlines())


def admin(mode, chain):
    suffix = ' --relayer-quiesced' if mode in ('queue', 'activate') else ''
    value = json.loads(remote('admin', 'sudo -n python3 -I -B /opt/psy-router-admission-20261030-r2/upgrade.py '+mode+' '+chain+suffix))
    assert value['ok'] is True
    print(json.dumps(value), flush=True)
    return value


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    descriptor = os.open(HERE, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['audit', 'queue', 'activate', 'recover'])
    args = parser.parse_args()
    with (HERE / '.control.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        hold = HERE / 'signing-hold.json'
        if args.mode == 'audit':
            for chain in CHAINS:
                admin('audit', chain)
            return
        if args.mode != 'recover':
            assert not hold.exists(), 'Existing hold requires recover, not another signing run'
            for chain in CHAINS:
                audit = admin('audit', chain)
                if args.mode == 'activate':
                    assert audit['active'] or audit['activateReady'], 'Timelock not ready; Relayer remains running'
            assert state()['ActiveState'] == 'active'
            save(hold, dict(mode=args.mode, at=datetime.datetime.now(datetime.timezone.utc).isoformat()))
            remote('relayer', 'sudo -n systemctl stop '+UNIT, timeout=340)
        else:
            assert hold.exists()
        assert state() == dict(ActiveState='inactive', MainPID='0')
        results = []
        for chain in CHAINS:
            assert state() == dict(ActiveState='inactive', MainPID='0')
            results.append(admin('reconcile' if args.mode == 'recover' else args.mode, chain))
        for chain in CHAINS:
            admin('reconcile', chain)
            admin('idle', chain)
        remote('relayer', 'sudo -n systemctl start '+UNIT, timeout=120)
        assert state()['ActiveState'] == 'active'
        at = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        save(HERE / (args.mode+'-completed-'+at+'.json'), dict(results=results, relayerRestored=True))
        hold.rename(HERE / ('signing-hold-released-'+at+'.json'))


if __name__ == '__main__':
    os.umask(0o077)
    main()
