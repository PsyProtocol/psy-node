"""State-preserving per-unit rollout of the reviewed PR30 Realm hotfix."""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

BASE = Path('/opt/psy-core/releases/core-testnet-20261027-r3/bin/psy_node_cli')
BASE_SHA = 'bc5419fd8ef89eb6cdef3dfbd29f4f6a232bcb4920ec97809a995a1bc225b7e9'
PROCESSOR = Path('/opt/psy-core/hotfixes/realm-sync-5f4f5c90/psy_node_cli')
PROCESSOR_SHA = 'c695772c59e04a50aa48f61197efe11b4f73861752310028fe41252d5403e7f1'
NEW = Path('/opt/psy-core/hotfixes/realm-pr30-61c1636b/psy_node_cli')
DROPIN = '80-realm-pr30-20261029.conf'
PREVIOUS = '70-realm-replay-20261028.conf'
ROOT = Path('/var/backups/psy-realm-pr30-20261029')
WORKING = '/opt/psy-core/releases/core-testnet-20261027-r3'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def run(*args, timeout=30):
    return subprocess.check_output(args, text=True, stderr=subprocess.PIPE, timeout=timeout).strip()


def digest(path):
    require(path.is_file() and not path.is_symlink(), 'regular nonsymlink file required')
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    sync_directory(path.parent)


def plan(unit, fragment):
    match = re.fullmatch(r'psy-core-r3-realm-([01])-v([123])-(edge|processor)\.service', unit)
    require(match is not None, 'only the twelve R3 Realm units are permitted')
    realm, validator, role = match.groups()
    address = ({'0': '10.148.0.36', '1': '10.148.0.35'}[realm] if role == 'edge'
               else {'1': '10.148.0.37', '2': '10.148.0.42', '3': '10.148.0.43'}[validator])
    starts = [line for line in fragment.splitlines() if line.startswith('ExecStart=')]
    require(len(starts) == 1 and starts[0].count(str(BASE)) == 1, 'unexpected base launch command')
    require('"--network" "psy-public-testnet"' in starts[0], 'wrong network')
    require('"--proving-backend" "plonky2-poseidon-goldilocks"' in starts[0], 'wrong prover')
    expected_role = 'start-realm-edge' if role == 'edge' else 'start-realm-processor'
    require('"' + expected_role + '"' in starts[0], 'wrong unit role')
    override = '[Service]\nExecStart=\n' + starts[0].replace(str(BASE), str(NEW), 1) + '\n'
    prior = '' if role == 'edge' else '[Service]\nExecStart=\n' + starts[0].replace(str(BASE), str(PROCESSOR), 1) + '\n'
    return address, (BASE if role == 'edge' else PROCESSOR), (BASE_SHA if role == 'edge' else PROCESSOR_SHA), override, prior


def properties(unit):
    result = run('systemctl', 'show', unit, '-p', 'MainPID', '-p', 'ActiveState', '-p', 'FragmentPath',
                 '-p', 'DropInPaths', '-p', 'WorkingDirectory', '-p', 'InvocationID', '-p', 'NRestarts')
    return dict(row.split('=', 1) for row in result.splitlines() if '=' in row)


def assert_running(unit, path, sha):
    props = properties(unit)
    require(props['ActiveState'] == 'active' and int(props['MainPID']) > 0, 'unit is not running')
    exe = Path('/proc') / props['MainPID'] / 'exe'
    require(exe.resolve(strict=True) == path, 'wrong running executable')
    require(hashlib.sha256(exe.read_bytes()).hexdigest() == sha, 'wrong running binary hash')
    return props


def wait_running(unit, path, sha):
    deadline = time.monotonic() + 30
    while True:
        try:
            return assert_running(unit, path, sha)
        except (ValueError, FileNotFoundError, ProcessLookupError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.2)


def peers(unit):
    result = run('systemctl', 'list-units', '--all', '--plain', '--no-legend', 'psy-core-*.service')
    return {line.split()[0]: properties(line.split()[0])['MainPID'] for line in result.splitlines()
            if line.split()[0] != unit}


def install(candidate, sha):
    for directory in (NEW.parent.parent, NEW.parent):
        if not directory.exists():
            directory.mkdir(mode=0o755)
            directory.chmod(0o755)
            sync_directory(directory.parent)
        st = directory.stat()
        require(not directory.is_symlink() and st.st_uid == 0 and not st.st_mode & 0o022, 'unsafe install directory')
        require(st.st_mode & 0o005 == 0o005, 'runtime user cannot traverse install directory')
    if NEW.exists():
        require(digest(NEW) == sha, 'immutable release path already has different bytes')
        return
    temporary = NEW.with_suffix('.installing')
    with candidate.open('rb') as source, temporary.open('xb') as target:
        shutil.copyfileobj(source, target)
        target.flush()
        os.fsync(target.fileno())
    temporary.chmod(0o755)
    require(digest(temporary) == sha, 'candidate changed during copy')
    temporary.rename(NEW)
    sync_directory(NEW.parent)


def ensure_original_configuration(fragment, contents, previous, prior, old, old_sha):
    require(fragment.read_text() == contents, 'base unit changed; hold stopped for inspection')
    if prior:
        require(previous.read_text() == prior, 'previous override changed; hold stopped for inspection')
    require(digest(old) == old_sha, 'rollback binary changed; hold stopped for inspection')


def ensure_loaded_configuration(unit, fragment, overrides):
    props = properties(unit)
    require(props['FragmentPath'] == str(fragment) and props['WorkingDirectory'] == WORKING, 'loaded unit changed; hold stopped')
    require(props['DropInPaths'].split() == sorted(str(path) for path in overrides), 'loaded overrides changed; hold stopped')
    for path, expected in overrides.items():
        require(path.read_text() == expected, 'override bytes changed; hold stopped')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('check', 'activate', 'rollback'))
    parser.add_argument('--unit', required=True)
    parser.add_argument('--candidate', default='/var/tmp/psy-realm-pr30-61c1636b/psy_node_cli')
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    require(os.geteuid() == 0, 'root required')
    require(re.fullmatch(r'[0-9a-f]{64}', args.sha256) is not None, 'invalid SHA256')
    # Validate the unit name before using it as a filesystem path.
    require(re.fullmatch(r'psy-core-r3-realm-[01]-v[123]-(edge|processor)\.service', args.unit) is not None, 'invalid unit')
    fragment = Path('/etc/systemd/system') / args.unit
    contents = fragment.read_text()
    address, old, old_sha, expected, prior = plan(args.unit, contents)
    addresses = json.loads(run('ip', '-j', 'address', 'show'))
    require(any(info.get('local') == address for interface in addresses for info in interface['addr_info']), 'wrong host')
    require(digest(BASE) == BASE_SHA and digest(old) == old_sha, 'rollback binary mismatch')
    dropin = fragment.with_name(fragment.name + '.d') / DROPIN
    previous = dropin.with_name(PREVIOUS)
    allowed = []
    if prior:
        require(previous.read_text() == prior, 'previous processor override changed')
        allowed.append(str(previous))
    if dropin.exists():
        require(dropin.read_text() == expected, 'unexpected owned override')
        allowed.append(str(dropin))
    props = properties(args.unit)
    require(props['FragmentPath'] == str(fragment) and props['WorkingDirectory'] == WORKING, 'unit identity changed')
    require(props['DropInPaths'].split() == sorted(allowed), 'unexpected overrides')
    if args.action != 'rollback':
        require(digest(Path(args.candidate)) == args.sha256, 'candidate hash mismatch')
    with Path('/run/lock/psy-realm-pr30-20261029.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.action == 'check':
            assert_running(args.unit, old, old_sha)
            print(json.dumps(dict(ok=True, unit=args.unit, phase='preflight', previous_sha256=old_sha)))
            return
        if args.action == 'activate' and dropin.exists():
            current = assert_running(args.unit, NEW, args.sha256)
            print(json.dumps(dict(ok=True, unit=args.unit, phase='already-active', pid=current['MainPID'])))
            return
        assert_running(args.unit, NEW if args.action == 'rollback' else old, args.sha256 if args.action == 'rollback' else old_sha)
        require(args.action != 'rollback' or dropin.exists(), 'no owned override to roll back')
        untouched = peers(args.unit)
        ROOT.mkdir(mode=0o700, exist_ok=True)
        audit = ROOT / (args.unit + '-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ'))
        audit.mkdir(mode=0o700)
        shutil.copy2(fragment, audit / 'original.service')
        if prior:
            shutil.copy2(previous, audit / PREVIOUS)
        save(audit / 'before.json', dict(unit=args.unit, action=args.action, properties=props, peers=untouched))
        if args.action == 'activate':
            install(Path(args.candidate), args.sha256)
        stop_attempted = False
        try:
            stop_attempted = True
            run('systemctl', 'stop', args.unit, timeout=330)
            require(properties(args.unit)['MainPID'] == '0', 'stop incomplete')
            require(fragment.read_text() == contents, 'base unit changed during operation')
            if prior:
                require(previous.read_text() == prior, 'previous override changed during operation')
            if args.action == 'activate':
                dropin.parent.mkdir(mode=0o755, exist_ok=True)
                temporary = dropin.with_suffix('.tmp')
                with temporary.open('x') as stream:
                    stream.write(expected)
                    stream.flush()
                    os.fsync(stream.fileno())
                temporary.rename(dropin)
            else:
                shutil.copy2(dropin, audit / DROPIN)
                dropin.unlink()
            sync_directory(dropin.parent)
            run('systemctl', 'daemon-reload')
            ensure_original_configuration(fragment, contents, previous, prior, old, old_sha)
            overrides = {previous: prior} if prior else {}
            if args.action == 'activate':
                overrides[dropin] = expected
            ensure_loaded_configuration(args.unit, fragment, overrides)
            run('systemctl', 'reset-failed', args.unit)
            run('systemctl', 'start', args.unit, timeout=90)
            current = wait_running(args.unit, NEW if args.action == 'activate' else old, args.sha256 if args.action == 'activate' else old_sha)
            require(peers(args.unit) == untouched, 'unrelated process changed; stop rollout')
            result = dict(ok=True, unit=args.unit, action=args.action, pid=current['MainPID'], audit=str(audit), sha256=args.sha256 if args.action == 'activate' else old_sha)
            save(audit / 'result.json', result)
            print(json.dumps(result))
        except Exception:
            restored = False
            cleanup_error = None
            try:
                if stop_attempted:
                    run('systemctl', 'stop', args.unit, timeout=330)
                    require(properties(args.unit)['MainPID'] == '0', 'cleanup stop incomplete')
                    ensure_original_configuration(fragment, contents, previous, prior, old, old_sha)
                    if dropin.exists():
                        require(dropin.read_text() == expected, 'refuse to remove an unknown override')
                        shutil.copy2(dropin, audit / 'failed-override.conf')
                        dropin.unlink()
                        sync_directory(dropin.parent)
                    run('systemctl', 'daemon-reload')
                    ensure_original_configuration(fragment, contents, previous, prior, old, old_sha)
                    ensure_loaded_configuration(args.unit, fragment, {previous: prior} if prior else {})
                    run('systemctl', 'reset-failed', args.unit)
                    run('systemctl', 'start', args.unit, timeout=90)
                    wait_running(args.unit, old, old_sha)
                    restored = True
            except Exception as error:
                cleanup_error = type(error).__name__
            finally:
                save(audit / 'failure.json', dict(old_binary_restored=restored, cleanup_error=cleanup_error,
                                                manual_inspection_required=not restored))
            raise


if __name__ == '__main__':
    os.umask(0o077)
    main()
