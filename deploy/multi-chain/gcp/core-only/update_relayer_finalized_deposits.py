#!/usr/bin/env python3
"""State-preserving R3 Relayer-only binary update; never regenerate inputs."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import time

UNIT = 'psy-core-relayer-r3.service'
BASE = Path('/opt/psy-core-relayer/releases/core-testnet-20261027-r3')
STATE = Path('/var/lib/psy-core-relayer/core-testnet-20261027-r3')
DROP = Path('/etc/systemd/system') / (UNIT + '.d') / '50-finalized-deposits.conf'
BASE_SOURCE = '3d31758738f833a7eea6f9ff7fd680a69a0d9a44'
INPUTS = {
    'psy_relayer_cli': 'dcf38ef139daeb805c8f53bee7f8d016974a00d4a35411af4213a760743661f5',
    'relayer_exec.py': '98befed16fc38214bf7c6c444158b4a4c61d77035eec2352261e66f9386e6fb6',
    'daemon.toml': '47888c4ba0c7bf82e38b7c919ebbba1f45518d1ede0b2c2e7b0a21203441bb0d',
    'rpc.json': '8540aaa89b978c2a040f1bb2f506313feeff9f307d491292e1984dc368de5d4c',
    'canonical.json': 'c8ee7c97e1158cd09e8fee5167f80f838f6048084028f3f9e80e239aac24e8d0',
}

def digest(value):
    return hashlib.sha256(value).hexdigest()

def read_regular(path, root_owned=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        assert stat.S_ISREG(info.st_mode) and not info.st_mode & 0o022, 'unsafe package file'
        assert not root_owned or info.st_uid == 0, 'installed file is not root-owned'
        return stream.read()

def trusted_directory(path):
    for directory in (path, *path.parents):
        info = directory.lstat()
        assert stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, 'unsafe installed directory'

def validate_switch_state(mode, current, has_dropin):
    if mode == 'rollback':
        assert has_dropin, 'rollback requires the exact owned override'
        assert (current['ActiveState'] == 'active' and int(current['MainPID']) > 0
                or current['ActiveState'] in ('inactive', 'failed') and current['MainPID'] == '0')
    else:
        assert current['ActiveState'] == 'active' and int(current['MainPID']) > 0

def write(path, value, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, mode)

def command(*args, timeout=120):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
    assert result.returncode == 0, f'command failed: {Path(args[0]).name}; preserve audit and inspect service'
    return result.stdout.strip()

def properties():
    text = command('systemctl', 'show', UNIT, '-p', 'ActiveState', '-p', 'MainPID', '-p', 'ExecStart', '-p', 'DropInPaths')
    return dict(line.split('=', 1) for line in text.splitlines())

def validate_manifest(value):
    assert value['schema_version'] == 1 and value['network'] == 'testnet'
    assert value['base_source_commit'] == BASE_SOURCE
    assert re.fullmatch('[0-9a-f]{40}', value['source_commit'])
    assert value['source_commit'] != BASE_SOURCE
    assert re.fullmatch('[0-9a-f]{64}', value['binary_sha256'])
    assert value['preserve'] == ['genesis', 'config', 'keys', 'database', 'proofs', 'other-services']

def render_wrapper(original, target):
    assert digest(original) == INPUTS['relayer_exec.py']
    text = original.decode()
    old_release = '    release = Path(__file__).absolute().parent'
    old_binary = '    argv = [str(release / "psy_relayer_cli"), "--config", str(release / "daemon.toml")]'
    assert text.count(old_release) == 1 and text.count(old_binary) == 1
    text = text.replace(old_release, f'    release = Path({str(BASE)!r})')
    text = text.replace(old_binary, f'    argv = [{str(target / "psy_relayer_cli")!r}, "--config", str(release / "daemon.toml")]')
    compile(text, 'relayer_exec.py', 'exec')
    return text.encode()

def wait_binary(expected):
    for _ in range(30):
        state = properties()
        pid = int(state['MainPID'])
        if state['ActiveState'] == 'active' and pid:
            try:
                if digest(Path(f'/proc/{pid}/exe').read_bytes()) == expected:
                    return pid
            except FileNotFoundError:
                pass
        time.sleep(2)
    raise RuntimeError('running executable did not match; preserve state, do not restore database')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', required=True, choices=['prepare', 'activate', 'rollback'])
    parser.add_argument('--package', required=True, type=Path)
    parser.add_argument('--manifest-sha256', required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and os.uname().nodename.startswith('coordinator-worker.')
    os.umask(0o077)
    fd = os.open('/run/lock/psy-relayer-finality-update.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(fd, 'a+') as lock:
        info = os.fstat(lock.fileno())
        assert stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        apply(args)

def apply(args):
    raw = read_regular(args.package / 'manifest.json')
    assert digest(raw) == args.manifest_sha256
    value = json.loads(raw)
    validate_manifest(value)
    binary = read_regular(args.package / 'psy_relayer_cli')
    assert binary.startswith(b'\x7fELF') and digest(binary) == value['binary_sha256']
    trusted_directory(BASE)
    for name, expected in INPUTS.items():
        assert digest(read_regular(BASE / name, root_owned=True)) == expected, f'R3 input changed: {name}'
    target = Path('/opt/psy-core-relayer/hotfixes') / value['source_commit']
    wrapper = render_wrapper(read_regular(BASE / 'relayer_exec.py'), target)
    dropin = f'[Service]\nExecStart=\nExecStart=/usr/bin/python3 -I -B {target}/relayer_exec.py\n'.encode()
    if args.mode == 'prepare':
        target.mkdir(mode=0o755, parents=True, exist_ok=True)
        for directory in (target.parent, target):
            info = directory.lstat()
            assert stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
            os.chmod(directory, 0o755)
        trusted_directory(target)
        for name, data, mode in [('psy_relayer_cli', binary, 0o755), ('relayer_exec.py', wrapper, 0o644), ('manifest.json', raw, 0o644)]:
            file = target / name
            if file.exists():
                assert read_regular(file, root_owned=True) == data, 'immutable prepared release differs'
            else:
                write(file, data, mode)
        print(json.dumps(dict(prepared=True, started=False, source=value['source_commit'])))
        return
    trusted_directory(target)
    assert read_regular(target / 'psy_relayer_cli', root_owned=True) == binary
    assert read_regular(target / 'relayer_exec.py', root_owned=True) == wrapper
    current = properties()
    assert current['DropInPaths'] in ('', str(DROP)), 'unowned unit overrides present'
    if DROP.exists():
        trusted_directory(DROP.parent)
        assert read_regular(DROP, root_owned=True) == dropin
        assert str(target / 'relayer_exec.py') in current['ExecStart']
    else:
        assert str(BASE / 'relayer_exec.py') in current['ExecStart']
    expected_before = value['binary_sha256'] if DROP.exists() else INPUTS['psy_relayer_cli']
    validate_switch_state(args.mode, current, DROP.exists())
    if int(current['MainPID']) > 0:
        assert digest(Path(f"/proc/{current['MainPID']}/exe").read_bytes()) == expected_before
    audit = Path('/var/backups/psy-core-relayer-finality') / str(time.time_ns())
    audit.mkdir(mode=0o700, parents=True)
    write(audit / 'before.json', json.dumps(dict(manifest_sha256=args.manifest_sha256, unit=current, mode=args.mode)).encode(), 0o600)
    command('systemctl', 'stop', UNIT, timeout=340)
    stopped = properties()
    assert stopped['ActiveState'] == 'inactive' and stopped['MainPID'] == '0'
    shutil.copyfile(STATE / 'db/relayer.redb', audit / 'relayer.redb')
    os.chmod(audit / 'relayer.redb', 0o600)
    if args.mode == 'activate':
        DROP.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        if not DROP.exists():
            candidate = DROP.with_suffix('.candidate')
            write(candidate, dropin, 0o644)
            os.replace(candidate, DROP)
        expected = value['binary_sha256']
    else:
        assert DROP.exists() and read_regular(DROP, root_owned=True) == dropin
        write(audit / 'removed-override.conf', dropin, 0o600)
        DROP.unlink()
        expected = INPUTS['psy_relayer_cli']
    command('systemctl', 'daemon-reload')
    command('systemctl', 'reset-failed', UNIT)
    command('systemctl', 'start', UNIT)
    pid = wait_binary(expected)
    for name, expected_input in INPUTS.items():
        assert digest(read_regular(BASE / name, root_owned=True)) == expected_input
    result = dict(ok=True, mode=args.mode, source=value['source_commit'], pid=pid, binary_sha256=expected,
                  retained_state=str(STATE), audit=str(audit), other_services_changed=False)
    write(audit / 'after.json', json.dumps(result).encode(), 0o600)
    print(json.dumps(result))

if __name__ == '__main__':
    main()
