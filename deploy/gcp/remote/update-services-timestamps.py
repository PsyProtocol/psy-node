#!/usr/bin/env python3
"""Pinned Services-only timestamp release; no indexer restart/config rewrite."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time
import urllib.request

BASE = '7c1e1f61673949bb7343529d4dd51d66f631d236'
COMMIT = '6ce3c2ac1d739312ea346a6e774123031ea5b860'
SHA = '93f183431c127025ead2ab832a57b369e33375560343b19bd1519ed3f60bdd6f'
OLD_SHA = '1b01ae685f5c8bc3fe2ee4ca969826c66ea2ec784bc90654c658cb2a93c3e49e'
OLD = Path('/opt/parth/psy-services/releases/7c1e1f616739-ced23fcb58b5')
NEW = Path('/opt/parth/psy-services/releases/6ce3c2ac1d73-timestamps-93f18343')
CURRENT = Path('/opt/parth/psy-services/current')
ENV = Path('/etc/parth/psy-services.env')
STAGED = Path('/tmp/psy-services-timestamps-staged/psy-services')
AUDIT = Path('/var/lib/parth-services-maintenance/20260928-timestamps')
UNIT = 'parth-psy-services.service'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args):
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f'{args[0]} failed; inspect on host')
    return result.stdout.strip()


def state(unit):
    return dict(line.split('=', 1) for line in run([
        'systemctl', 'show', unit, '-p', 'MainPID', '-p', 'ActiveState']).splitlines())


def other_units():
    units = json.loads(run(['systemctl', 'list-units', '--all', '--no-pager',
                           '--output=json', 'parth-*.service']))
    return {item['unit']: state(item['unit']) for item in units if item['unit'] != UNIT}


def atomic(path, content, mode, uid=0, gid=0):
    temp = path.with_name(path.name + '.timestamp-next')
    with temp.open('xb') as f:
        f.write(content)
    temp.chmod(mode)
    os.chown(temp, uid, gid)
    temp.replace(path)


def link(home):
    temp = CURRENT.with_name('current.timestamp-next')
    temp.symlink_to(home)
    temp.replace(CURRENT)


def ready(expected_sha):
    for _ in range(60):
        try:
            process = state(UNIT)
            if process['ActiveState'] == 'active' and int(process['MainPID']) > 0:
                exe = Path('/proc') / process['MainPID'] / 'exe'
                if digest(exe) == expected_sha:
                    with urllib.request.urlopen('http://127.0.0.1:3000/health', timeout=3) as response:
                        if response.status == 200:
                            return process
        except (OSError, ValueError):
            pass
        time.sleep(2)
    raise RuntimeError('Services executable/health verification timed out')


def main():
    if os.geteuid() != 0 or socket.gethostname().split('.')[0] != 'cp-ce':
        raise RuntimeError('Run as root on cp-ce only')
    if CURRENT.resolve() != OLD or NEW.exists() or AUDIT.exists():
        raise RuntimeError('Unexpected release or previous attempt; inspect before retry')
    baseline = state(UNIT)
    if baseline['ActiveState'] != 'active' or digest(Path('/proc') / baseline['MainPID'] / 'exe') != OLD_SHA:
        raise RuntimeError('Running baseline mismatch')
    if digest(STAGED) != SHA:
        raise RuntimeError('Candidate binary mismatch')
    old_manifest = (OLD / 'BUILD-MANIFEST.env').read_text()
    if f'PSY_SERVICES_COMMIT={BASE}\n' not in old_manifest:
        raise RuntimeError('Baseline manifest mismatch')
    env_bytes = ENV.read_bytes()
    old_line = f'PSY_SERVICES_HOME={OLD}\n'.encode()
    if env_bytes.count(old_line) != 1:
        raise RuntimeError('Unexpected Services path configuration')
    env_stat = ENV.stat()
    protected = {str(p): digest(p) for p in Path('/etc/parth').glob('*.env') if p != ENV}
    node_home = str(Path('/opt/parth/current').resolve())
    units_before = other_units()
    os.umask(0o077)
    AUDIT.mkdir(parents=True)
    (AUDIT / 'services.env.before').write_bytes(env_bytes)
    (AUDIT / 'before.json').write_text(json.dumps({'units': units_before, 'protected': protected,
        'node_home': node_home, 'service': baseline}, indent=2))
    shutil.copytree(OLD, NEW, symlinks=True)
    # copytree preserves modes but not ownership, including a protected 0700 root.
    for source in [OLD, *OLD.rglob('*')]:
        target = NEW / source.relative_to(OLD)
        original = source.lstat()
        os.chown(target, original.st_uid, original.st_gid, follow_symlinks=False)
    # This release is assembled from verified binaries, not the old tar bundle.
    (NEW / '.bundle.sha256').unlink(missing_ok=True)
    binary = NEW / 'target/release/psy-services'
    binary_stat = binary.stat()
    atomic(binary, STAGED.read_bytes(), 0o755, binary_stat.st_uid, binary_stat.st_gid)
    manifest = old_manifest.replace(f'PSY_SERVICES_COMMIT={BASE}', f'PSY_SERVICES_COMMIT={COMMIT}')
    lines = []
    for line in manifest.splitlines():
        if line.startswith('PSY_SERVICES_BRANCH='):
            line = 'PSY_SERVICES_BRANCH=fix/envio-deposit-timestamps-20260928'
        elif line.startswith('PSY_SERVICES_BINARY_SHA256='):
            line = 'PSY_SERVICES_BINARY_SHA256=' + SHA
        elif line.startswith('SOURCE_COMMIT_TIMESTAMP='):
            continue
        lines.append(line)
    lines.extend(['PSY_INDEXER_COMMIT=' + BASE, 'PSY_SERVICES_PARENT_COMMIT=' + BASE,
                  'RELEASE_KIND=services-only-deposit-timestamps'])
    atomic(NEW / 'BUILD-MANIFEST.env', ('\n'.join(lines) + '\n').encode(), 0o644)
    # Retain the protected release mode and verify access as the actual service user.
    NEW.chmod(OLD.stat().st_mode & 0o777)
    run(['runuser', '-u', 'parth', '--', 'test', '-x', str(binary)])
    if digest(NEW / 'target/release/psy-indexer') != digest(OLD / 'target/release/psy-indexer'):
        raise RuntimeError('Indexer bytes changed unexpectedly')
    changed = False
    try:
        atomic(ENV, env_bytes.replace(old_line, f'PSY_SERVICES_HOME={NEW}\n'.encode()),
               env_stat.st_mode & 0o777, env_stat.st_uid, env_stat.st_gid)
        changed = True
        link(NEW)
        run(['systemctl', 'restart', UNIT])
        process = ready(SHA)
        if any(digest(Path(p)) != value for p, value in protected.items()):
            raise RuntimeError('Unrelated env changed')
        if other_units() != units_before or str(Path('/opt/parth/current').resolve()) != node_home:
            raise RuntimeError('Other processes or node release changed; inspect')
        result = {'commit': COMMIT, 'binary_sha256': SHA, 'release': str(NEW),
                  'service': process, 'other_units_unchanged': True,
                  'rollback_release': str(OLD), 'indexers_restarted': False}
        (AUDIT / 'result.json').write_text(json.dumps(result, indent=2))
        print(json.dumps(result))
    except Exception:
        if changed:
            atomic(ENV, env_bytes, env_stat.st_mode & 0o777, env_stat.st_uid, env_stat.st_gid)
            if CURRENT.resolve() != OLD:
                link(OLD)
            run(['systemctl', 'restart', UNIT])
            ready(OLD_SHA)
        raise RuntimeError('Rollout failed; previous Services restored; inspect protected evidence') from None


if __name__ == '__main__':
    main()
