#!/usr/bin/env python3
"""Fixed-role SSH backup reader; no rsync/rrsync server or client options.

Protocol v2 pages a fixed-role directory with bounded memory. Name cursors are
comparisons only, never client-selected paths. Selected files are manifest
indexes. Recent-file pages alternate with historical pages. A completed
historical sweep wraps to revisit late arrivals and changed files.
No v1 fallback is permitted; upgrade requires a coordinated operator handoff.
"""
import argparse
import base64
from contextlib import contextmanager
import fcntl
import grp
import hashlib
import heapq
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import subprocess
import sys
import tarfile
import time

CONFIG = Path('/etc/psy-indexer-r3-mirror')
STATE = Path('/var/lib/psy-indexer-r3-mirror')
BACKUPS = '/var/lib/psy-core/core-testnet-20261027-r3/checkpoints'
PROGRAM = Path('/usr/local/libexec/psy-indexer-r3-mirror.py')
HOSTS = {
    'cp': ('10.148.0.25', 'AAAAC3NzaC1lZDI1NTE5AAAAIJstOeTBzGI7x1kTNmXCjmBdPlt9fYRYj02jCYadYR8S', ['coordinator_0_0']),
    'v2': ('10.148.0.42', 'AAAAC3NzaC1lZDI1NTE5AAAAIM9PZNDNv23rwH0GDV6rqH7Ff6GZ+wv/axJqpXUbDQqQ', ['realm_0_2', 'realm_1_2']),
    'v3': ('10.148.0.43', 'AAAAC3NzaC1lZDI1NTE5AAAAIKiFB2MptvcjniVu9ySN1jBd/a5fZJiJ+5/sDsjKQ2CV', ['realm_0_3', 'realm_1_3']),
}
REQUEST = 'psy-indexer-backup-read-v1 '
MAX_JSON = 32 * 1024 * 1024
PAGE_FILES = 128
PAGE_STATE = '.mirror-page.json'
MAX_FILE = 64 * 1024**2
MAX_BATCH = 64 * 1024**2
MAX_BATCH_FILES = 128
QUIET_NS = 30 * 1000000000
BACKUP_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,239}\.backup', re.ASCII)

def require(ok, message):
    if not ok:
        raise RuntimeError(message)

def run(args, timeout=30):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    require(result.returncode == 0, f'command failed: {Path(args[0]).name}, exit={result.returncode}')
    return result.stdout.strip()

def host(ip):
    require(os.geteuid() == 0 and ip in run(['/usr/bin/hostname', '-I']).split(), 'wrong host/user')

def trusted(path, directory=False):
    for parent in path.parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, 'unsafe parent')
    info = path.lstat()
    require(info.st_uid == 0 and not info.st_mode & 0o022, 'unsafe owner/mode')
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
            'unsafe file type')

def write_new(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())

def public_key(raw):
    fields = raw.decode('ascii').strip().split()
    require(len(fields) in (2, 3) and fields[0] == 'ssh-ed25519', 'not an Ed25519 public key')
    blob = base64.b64decode(fields[1], validate=True)
    require(len(blob) == 51 and blob[:19] == b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20', 'bad public key encoding')
    return 'ssh-ed25519 ' + fields[1]

def authorize_line(key, name):
    require(name in HOSTS, 'unknown source')
    command = f'sudo -n --preserve-env=SSH_ORIGINAL_COMMAND /usr/bin/python3 -I -B {PROGRAM} serve --source {name}'
    return f'from="10.148.0.37",restrict,command="{command}" {key} psy-indexer-r3-mirror\n'.encode()


@contextmanager
def deadline(seconds=55):
    def expired(signum, frame):
        raise TimeoutError('mirror deadline exceeded')
    previous = signal.signal(signal.SIGALRM, expired)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def read_json(stream):
    raw = stream.readline(MAX_JSON + 1)
    require(len(raw) <= MAX_JSON and raw.endswith(b'\n'), 'invalid protocol frame')
    return json.loads(raw)


def write_json(stream, value):
    raw = json.dumps(value, separators=(',', ':')).encode() + b'\n'
    require(len(raw) <= MAX_JSON, 'protocol frame too large')
    stream.write(raw)
    stream.flush()


def open_source(role):
    path = Path(BACKUPS) / role / 'guta_updates_backup'
    require(path.is_absolute() and '..' not in path.parts, 'invalid source root')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        # Each component is opened relative to the preceding held directory, never re-resolved.
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def backup_stat(info):
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'backup must be a regular single-link file')
    require(0 <= info.st_size <= MAX_FILE and info.st_mtime_ns >= 0, 'backup size/time unsupported')


def validate_window(after, ceiling):
    require(isinstance(after, str) and (after == '' or BACKUP_NAME.fullmatch(after)), 'invalid page cursor')
    require(ceiling is None or isinstance(ceiling, str) and
            (ceiling == '' or BACKUP_NAME.fullmatch(ceiling)), 'invalid page ceiling')
    require(after == '' if ceiling is None else after <= ceiling, 'invalid page window')


def source_page(fd, after, ceiling, lane='history'):
    validate_window(after, ceiling)
    require(lane in ('recent', 'history'), 'invalid page lane')
    require(lane == 'history' or after == '' and ceiling is None, 'invalid recent window')
    cutoff = time.time_ns() - QUIET_NS
    highest = ''

    def candidates():
        nonlocal highest
        # scandir and nsmallest retain only one page, not the full directory listing.
        with os.scandir(fd) as directory:
            for entry in directory:
                name = entry.name
                if not name.endswith('.backup'):
                    continue
                require(BACKUP_NAME.fullmatch(name) is not None, 'invalid backup name')
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                backup_stat(info)
                # Quiescence is not a commit proof; indexers own that check.
                if info.st_mtime_ns > cutoff:
                    continue
                highest = max(highest, name)
                if name > after and (ceiling is None or name <= ceiling):
                    yield {'name': name, 'size': info.st_size, 'mtime_ns': info.st_mtime_ns}

    if lane == 'recent':
        entries = heapq.nlargest(PAGE_FILES, candidates(), key=lambda entry: (entry['mtime_ns'], entry['name']))
        entries.sort(key=lambda entry: entry['name'])
    else:
        entries = heapq.nsmallest(PAGE_FILES + 1, candidates(), key=lambda entry: entry['name'])
    return {'lane': lane, 'after': after, 'ceiling': highest if ceiling is None else ceiling,
            'has_more': len(entries) > PAGE_FILES, 'files': entries[:PAGE_FILES]}


def validate_manifest(value, role, window):
    require(isinstance(value, dict) and set(value) == {'version', 'role', 'files', 'after', 'ceiling', 'has_more', 'lane'} and
            type(value['version']) is int and value['version'] == 2 and value['role'] == role,
            'wrong manifest')
    validate_window(value['after'], value['ceiling'])
    require(value['lane'] == window['lane'] and value['lane'] in ('recent', 'history'), 'page lane changed')
    require(value['ceiling'] is not None and value['after'] == window['after'] and
            (window['ceiling'] is None or value['ceiling'] == window['ceiling']), 'page window changed')
    require(type(value['has_more']) is bool, 'invalid page continuation')
    require(value['lane'] != 'recent' or not value['has_more'], 'invalid recent continuation')
    entries = value['files']
    require(isinstance(entries, list) and len(entries) <= PAGE_FILES, 'invalid file list')
    names = set()
    previous = value['after']
    for entry in entries:
        require(isinstance(entry, dict) and set(entry) == {'name', 'size', 'mtime_ns'}, 'invalid entry')
        name = entry['name']
        require(isinstance(name, str) and BACKUP_NAME.fullmatch(name) is not None and name not in names,
                'invalid or duplicate backup name')
        names.add(name)
        require(previous < name <= value['ceiling'], 'page not ordered or outside window')
        previous = name
        require(type(entry['size']) is int and 0 <= entry['size'] <= MAX_FILE and
                type(entry['mtime_ns']) is int and 0 <= entry['mtime_ns'] < 2**63, 'invalid size/time')
    require(not value['has_more'] or len(entries) == PAGE_FILES, 'short continuing page')
    return entries


def load_window(fd, role):
    try:
        leaf = os.open(PAGE_STATE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    except FileNotFoundError:
        return {'after': '', 'ceiling': None, 'lane': 'recent'}
    with os.fdopen(leaf, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 4096, 'unsafe page state')
        raw = stream.read(4097)
    require(len(raw) <= 4096, 'page state too large')
    value = json.loads(raw)
    require(isinstance(value, dict) and set(value) == {'version', 'role', 'after', 'ceiling', 'lane'} and
            type(value['version']) is int and value['version'] == 2 and value['role'] == role, 'wrong page state')
    validate_window(value['after'], value['ceiling'])
    require(value['lane'] in ('recent', 'history'), 'invalid page lane')
    return {'after': value['after'], 'ceiling': value['ceiling'], 'lane': value['lane']}


def save_window(fd, role, after, ceiling, lane):
    validate_window(after, ceiling)
    require(lane in ('recent', 'history'), 'invalid page lane')
    temporary = '.mirror-page-' + secrets.token_hex(16)
    leaf = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        with os.fdopen(leaf, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            write_json(stream, {'version': 2, 'role': role, 'after': after, 'ceiling': ceiling, 'lane': lane})
            os.fsync(stream.fileno())
        os.replace(temporary, PAGE_STATE, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        try:
            os.unlink(temporary, dir_fd=fd)
        except FileNotFoundError:
            pass


def selected_entries(entries, indexes):
    require(isinstance(indexes, list) and len(indexes) <= min(len(entries), MAX_BATCH_FILES), 'invalid selection')
    require(all(type(index) is int and 0 <= index < len(entries) for index in indexes), 'invalid selection index')
    require(indexes == sorted(set(indexes)), 'selection must be sorted and unique')
    selected = [entries[index] for index in indexes]
    require(sum(entry['size'] for entry in selected) <= MAX_BATCH, 'batch too large')
    return selected


def send_backups(fd, entries, output):
    with tarfile.open(fileobj=output, mode='w|', format=tarfile.PAX_FORMAT) as archive:
        for entry in entries:
            leaf = os.open(entry['name'], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY, dir_fd=fd)
            with os.fdopen(leaf, 'rb') as stream:
                info = os.fstat(stream.fileno())
                backup_stat(info)
                require((info.st_size, info.st_mtime_ns) == (entry['size'], entry['mtime_ns']), 'backup changed')
                member = tarfile.TarInfo(entry['name'])
                member.size, member.mode = info.st_size, 0o640
                archive.addfile(member, stream)
                after = os.fstat(stream.fileno())
                require((after.st_size, after.st_mtime_ns, after.st_ctime_ns) ==
                        (info.st_size, info.st_mtime_ns, info.st_ctime_ns), 'backup changed during read')


def serve(name):
    host(HOSTS[name][0])
    command = os.environ.get('SSH_ORIGINAL_COMMAND', '')
    allowed = {REQUEST + role: role for role in HOSTS[name][2]}
    require(command in allowed, 'command not allowed')
    role = allowed[command]
    with deadline():
        fd = open_source(role)
        try:
            write_json(sys.stdout.buffer, {'version': 2, 'role': role})
            window = read_json(sys.stdin.buffer)
            require(isinstance(window, dict) and set(window) == {'after', 'ceiling', 'lane'}, 'invalid page request')
            page = source_page(fd, window['after'], window['ceiling'], window['lane'])
            entries = page['files']
            write_json(sys.stdout.buffer, {'version': 2, 'role': role, **page})
            selected = selected_entries(entries, read_json(sys.stdin.buffer))
            require(sys.stdin.buffer.read(1) == b'', 'unexpected trailing request')
            send_backups(fd, selected, sys.stdout.buffer)
            sys.stdout.buffer.flush()
        finally:
            os.close(fd)

def prepare_key():
    host('10.148.0.37')
    require(not CONFIG.exists(), 'key directory already exists; never regenerate')
    CONFIG.mkdir(mode=0o700)
    run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'psy-indexer-r3-mirror', '-f', str(CONFIG / 'id_ed25519')])
    known = ''.join(f'{ip} ssh-ed25519 {key}\n' for ip, key, _ in HOSTS.values())
    write_new(CONFIG / 'known_hosts', known.encode())
    print(public_key((CONFIG / 'id_ed25519.pub').read_bytes()))

def source_access(name, key_file):
    host(HOSTS[name][0])
    trusted(key_file)
    key = public_key(key_file.read_bytes())
    require(os.access('/usr/bin/python3', os.X_OK), 'python3 missing')
    require(not PROGRAM.exists(), 'source helper already exists; inspect before retry')
    for role in HOSTS[name][2]:
        fd = open_source(role)
        try:
            source_page(fd, '', None)
        finally:
            os.close(fd)
    PROGRAM.parent.mkdir(mode=0o755, exist_ok=True)
    trusted(PROGRAM.parent, directory=True)
    keys = Path('/home/ubuntu/.ssh/authorized_keys')
    home = Path('/home/ubuntu').stat()
    for path in (Path('/home/ubuntu'), keys.parent):
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == home.st_uid and not info.st_mode & 0o022, 'unsafe SSH home')
    fd = os.open(keys, os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW)
    with os.fdopen(fd, 'r+b') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == home.st_uid
                and not info.st_mode & 0o022, 'unsafe authorized_keys')
        old = stream.read()
        require(key.split()[1].encode() not in old, 'key already present; inspect before retry')
        audit = Path('/var/lib/psy-indexer-mirror-access-20261027-r3')
        audit.mkdir(mode=0o700)
        write_new(audit / 'authorized_keys.before', old)
        addition = (b'' if not old or old.endswith(b'\n') else b'\n') + authorize_line(key, name)
        write_new(audit / 'added-key-line', addition)
        write_new(PROGRAM, Path(__file__).read_bytes(), 0o700)
        stream.write(addition)
        stream.flush()
        os.fsync(stream.fileno())
        stream.seek(0)
        require(stream.read() == old + addition, 'authorized_keys concurrent drift')
    print(json.dumps({'host': HOSTS[name][0], 'read_only_key_added': True, 'allowed_source': '10.148.0.37', 'backup_root': BACKUPS}))

def sync_command(name, role):
    require(name in HOSTS and role in HOSTS[name][2], 'role not allowed on source')
    ip = HOSTS[name][0]
    return ['/usr/bin/ssh', '-F', '/dev/null', '-i', str(CONFIG / 'id_ed25519'),
            '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
            '-o', 'StrictHostKeyChecking=yes', '-o', f'UserKnownHostsFile={CONFIG}/known_hosts',
            f'ubuntu@{ip}', REQUEST + role]


def receive_backups(process, destination, role, gid):
    fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = []
    try:
        greeting = read_json(process.stdout)
        require(isinstance(greeting, dict) and set(greeting) == {'version', 'role'} and
                type(greeting['version']) is int and greeting['version'] == 2 and greeting['role'] == role,
                'unsupported source protocol')
        window = load_window(fd, role)
        request = dict(window) if window['lane'] == 'history' else {'after': '', 'ceiling': None, 'lane': 'recent'}
        write_json(process.stdin, request)
        page = read_json(process.stdout)
        entries = validate_manifest(page, role, request)
        indexes, total, examined = [], 0, 0
        for index, entry in enumerate(entries):
            try:
                info = os.stat(entry['name'], dir_fd=fd, follow_symlinks=False)
                backup_stat(info)
                require(info.st_uid == os.geteuid() and not info.st_mode & 0o022, 'unsafe destination file')
            except FileNotFoundError:
                info = None
            if info is None or (info.st_size, info.st_mtime_ns, info.st_gid, stat.S_IMODE(info.st_mode)) != \
                    (entry['size'], entry['mtime_ns'], gid, 0o640):
                if len(indexes) == MAX_BATCH_FILES or total + entry['size'] > MAX_BATCH:
                    break
                indexes.append(index)
                total += entry['size']
            examined = index + 1
        selected = selected_entries(entries, indexes)
        write_json(process.stdin, indexes)
        process.stdin.close()
        with tarfile.open(fileobj=process.stdout, mode='r|') as archive:
            for entry in selected:
                member = archive.next()
                require(member is not None and member.type == tarfile.REGTYPE and member.name == entry['name'] and
                        member.size == entry['size'], 'unexpected archive member')
                name = '.mirror-' + secrets.token_hex(16)
                out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
                temporary.append((name, entry['name']))
                with os.fdopen(out, 'wb') as stream, archive.extractfile(member) as incoming:
                    remaining = member.size
                    while remaining:
                        chunk = incoming.read(min(65536, remaining))
                        require(bool(chunk), 'short backup')
                        stream.write(chunk)
                        remaining -= len(chunk)
                    stream.flush()
                    os.fchmod(stream.fileno(), 0o640)
                    os.fchown(stream.fileno(), os.geteuid(), gid)
                    os.utime(stream.fileno(), ns=(entry['mtime_ns'], entry['mtime_ns']))
                    os.fsync(stream.fileno())
            require(archive.next() is None, 'extra archive member')
        # Never publish a partial/failed producer stream, even if its tar prefix was valid.
        require(process.wait(timeout=5) == 0, 'source transfer failed')
        for name, target in temporary:
            os.replace(name, target, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
        if window['lane'] == 'recent':
            after, ceiling = window['after'], window['ceiling']
        elif examined == len(entries) and not page['has_more']:
            after, ceiling = '', None
        else:
            after = entries[examined - 1]['name'] if examined else window['after']
            ceiling = page['ceiling']
        save_window(fd, role, after, ceiling, 'history' if window['lane'] == 'recent' else 'recent')
        return len(selected)
    finally:
        for name, _ in temporary:
            try:
                os.unlink(name, dir_fd=fd)
            except FileNotFoundError:
                pass
        os.close(fd)


def sync_one(name, role, gid):
    destination = STATE / name / 'checkpoints' / role / 'guta_updates_backup'
    trusted(destination, directory=True)
    process = subprocess.Popen(sync_command(name, role), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        with deadline():
            return receive_backups(process, destination, role, gid)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        if not process.stdin.closed:
            process.stdin.close()
        process.stdout.close()

def install():
    host('10.148.0.37')
    trusted(CONFIG, directory=True)
    trusted(CONFIG / 'id_ed25519')
    trusted(CONFIG / 'known_hosts')
    require(os.access('/usr/bin/ssh', os.X_OK), 'ssh missing')
    require(not STATE.exists() and not PROGRAM.exists(), 'installation already exists')
    gid = grp.getgrnam('psy-core').gr_gid
    STATE.mkdir(mode=0o750)
    os.chmod(STATE, 0o750)
    os.chown(STATE, 0, gid)
    for name, (_, _, roles) in HOSTS.items():
        for role in roles:
            dest = STATE / name / 'checkpoints' / role / 'guta_updates_backup'
            dest.mkdir(parents=True, mode=0o750)
            for parent in (dest, *dest.parents):
                if parent == STATE:
                    break
                os.chmod(parent, 0o750)
                os.chown(parent, 0, gid)
    PROGRAM.parent.mkdir(mode=0o755, exist_ok=True)
    trusted(PROGRAM.parent, directory=True)
    write_new(PROGRAM, Path(__file__).read_bytes(), 0o700)
    unit = f'''[Unit]
Description=Read-only backup mirror for r3 indexers
After=network-online.target
[Service]
Type=oneshot
User=root
UMask=0027
ExecStart=/usr/bin/python3 -I -B {PROGRAM} sync
TimeoutStartSec=300
NoNewPrivileges=true
CapabilityBoundingSet=CAP_CHOWN
AmbientCapabilities=
SystemCallFilter=~@mount
MemoryMax=512M
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths={STATE}
IPAddressDeny=any
IPAddressAllow=10.148.0.25/32 10.148.0.42/32 10.148.0.43/32
'''
    timer = '''[Unit]
Description=Refresh r3 indexer read-only backup mirrors
[Timer]
OnBootSec=30s
OnUnitInactiveSec=10s
AccuracySec=1s
Unit=psy-indexer-r3-mirror.service
[Install]
WantedBy=timers.target
'''
    write_new(Path('/etc/systemd/system/psy-indexer-r3-mirror.service'), unit.encode(), 0o644)
    write_new(Path('/etc/systemd/system/psy-indexer-r3-mirror.timer'), timer.encode(), 0o644)
    print(json.dumps({'installed': True, 'started': False, 'enabled': False}))

def sync():
    host('10.148.0.37')
    trusted(CONFIG, directory=True)
    trusted(CONFIG / 'id_ed25519')
    trusted(CONFIG / 'known_hosts')
    trusted(STATE, directory=True)
    gid = grp.getgrnam('psy-core').gr_gid
    lock = os.open(STATE / '.sync-lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for name, (_, _, roles) in HOSTS.items():
            for role in roles:
                sync_one(name, role, gid)
    finally:
        os.close(lock)
    print(json.dumps({'synced_sources': list(HOSTS), 'source_deletion': False, 'atomic_file_publication': True}))

def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare-key', 'source-access', 'install', 'sync', 'serve'])
    parser.add_argument('--source', choices=list(HOSTS))
    parser.add_argument('--public-key', type=Path)
    args = parser.parse_args()
    if args.action in ('serve', 'source-access'):
        require(args.source is not None, 'source required')
    if args.action == 'source-access':
        require(args.public_key is not None, 'public key required')
    if args.action == 'prepare-key': prepare_key()
    elif args.action == 'source-access': source_access(args.source, args.public_key)
    elif args.action == 'install': install()
    elif args.action == 'serve': serve(args.source)
    else: sync()

if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'ok': False, 'error': type(error).__name__, 'action': 'Preserve partial state; no blind retry'}), file=sys.stderr)
        raise SystemExit(1)
