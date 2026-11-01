#!/usr/bin/env python3
"""Fence, open and reopen public ingress with Caddy maintenance routes: stage, check, apply.

Hosts and the maintenance tag come from the release lock. Stage renders a candidate
Caddyfile and checks its native adaptation; check validates it and with --apply writes
the source and bind files, then reloads Caddy. Only listed hosts change. No restart.
The bind-write transaction is adapted from the reviewed R2 Caddy apply helper.
"""
import argparse
import base64
import copy
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys

SOURCE = Path('/opt/nostr-relay/Caddyfile')
BODY = 'Testnet maintenance. Please retry shortly.'
PHASES = ('fence', 'open', 'open-faucet')
PASSIVE_HANDLERS = frozenset(('headers', 'encode', 'subroute', 'vars', 'log_append'))
FILES = ('original.Caddyfile', 'original-bind.Caddyfile', 'original.json', 'candidate.Caddyfile', 'candidate.json')
FENCE_LINES = ('    route {{\n', '        header Content-Type "text/plain; charset=utf-8"\n', '        header Retry-After 60\n',
               '        respond "{body}" 503\n', '    }}\n')


def require(ok, message='Caddy scope, identity or concurrent-change check failed'):
    if not ok:
        raise ValueError(message)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_release_lock(encoded_lock, expected_sha256):
    raw = base64.b64decode(encoded_lock, validate=True)
    require(sha(raw) == expected_sha256, 'release lock hash mismatch')
    return json.loads(raw)


def read_ingress(lock):
    ingress = lock['ingress']
    hosts = ingress['fenced_hosts'] + ingress['faucet_hosts']
    require(all(isinstance(host, str) and re.fullmatch(r'[a-z0-9.-]+', host) for host in hosts) and len(set(hosts)) == len(hosts),
            'ingress hosts must be distinct DNS names')
    require(isinstance(ingress['maintenance_tag'], str) and re.fullmatch(r'[a-z0-9-]+', ingress['maintenance_tag']),
            'maintenance tag must be lowercase words')
    return ingress


def marker_of(ingress, host):
    return ingress['maintenance_tag'] + ('-faucet' if host in ingress['faucet_hosts'] else '')


def target_hosts(phase, ingress):
    require(phase in PHASES, 'unknown phase')
    return {'fence': ingress['fenced_hosts'] + ingress['faucet_hosts'], 'open': ingress['fenced_hosts'],
            'open-faucet': ingress['faucet_hosts']}[phase]


def run(args, raw=None):
    return subprocess.run(args, input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=45, check=True).stdout


def caddy(operation, raw, adapter=True):
    args = ['docker', 'exec', '-i', 'nostr-caddy', 'caddy', operation, '--config', '/dev/stdin']
    return run(args + (['--adapter', 'caddyfile'] if adapter else []), raw)


def adapt(raw):
    return json.loads(caddy('adapt', raw))


def live():
    return json.loads(run(['docker', 'exec', 'nostr-caddy', 'wget', '-qO-', 'http://127.0.0.1:2019/config/']))


def objects(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from objects(child)


def normalized(value):
    value = copy.deepcopy(value)
    groups = {}
    for obj in objects(value):
        if obj.get('handler') == 'file_server' and obj.get('hide') in (['./-'], ['/dev/stdin'], ['/etc/caddy/Caddyfile']):
            obj['hide'] = ['CADDY_ADAPTER_CONFIG_PATH']
        # The adapter allocates group numbers even for a single handle. Preserve
        # the complete equivalence relation, not its incidental numeric labels.
        if isinstance(obj.get('group'), str) and re.fullmatch(r'group\d+', obj['group']):
            obj['group'] = groups.setdefault(obj['group'], 'group' + str(len(groups)))
    return value


def routes(config):
    return config['apps']['http']['servers']['srv0']['routes']


def route_of(config, host):
    found = [r for r in routes(config) if r.get('match') == [{'host': [host]}]]
    require(len(found) == 1, 'host route not found exactly once: ' + host)
    return found[0]


def contains_gate(route):
    return any(o.get('handler') == 'static_response' and o.get('status_code') == 503 and o.get('body') == BODY
               for o in objects(route))


def find_gate(node, is_unconditional=True):
    """True when the 503 is reached before any handler that could answer, False when something else can answer
    first or the gate sits behind a matcher, None when the node holds neither."""
    if isinstance(node, list):
        for child in node:
            found = find_gate(child, is_unconditional)
            if found is not None:
                return found
        return None
    if not isinstance(node, dict):
        return None
    if node.get('handler') == 'static_response' and node.get('status_code') == 503 and node.get('body') == BODY:
        return is_unconditional
    if 'handler' not in node:
        return find_gate(node.get('handle'), is_unconditional and 'match' not in node)
    if node['handler'] not in PASSIVE_HANDLERS:
        return False
    return find_gate(node.get('routes'), is_unconditional)


def has_gate(route):
    return find_gate(route['handle']) is True


def masked(config, hosts):
    config = copy.deepcopy(normalized(config))
    for route in routes(config):
        if route.get('match') in [[{'host': [host]}] for host in hosts]:
            route.clear()
    return config


def fence_text(marker):
    lines = [line.format(body=BODY) for line in FENCE_LINES]
    return '    # BEGIN ' + marker + '\n' + ''.join(lines) + '    # END ' + marker + '\n'


def block_span(text, host):
    openings = list(re.finditer('(?m)^' + re.escape(host) + r' \{\n', text))
    require(len(openings) == 1, 'site block not found exactly once: ' + host)
    start = openings[0].end()
    end = re.compile(r'\n\}(?:\n|$)').search(text, start)
    require(end is not None, 'site block is not closed: ' + host)
    return start, end.start() + 1


def set_fence(text, host, marker, tag, should_fence):
    start, end = block_span(text, host)
    fence = fence_text(marker)
    has = text.startswith(fence, start)
    require(text.count('# BEGIN ' + tag, start, end) == int(has), 'unexpected maintenance marker in ' + host)
    if has == should_fence:
        return text
    return text[:start] + fence + text[start:] if should_fence else text[:start] + text[start + len(fence):]


def fenced_hosts_in(text, ingress):
    hosts = ingress['fenced_hosts'] + ingress['faucet_hosts']
    fenced = [h for h in hosts if text.startswith(fence_text(marker_of(ingress, h)), block_span(text, h)[0])]
    require(text.count('# BEGIN ' + ingress['maintenance_tag']) == len(fenced), 'maintenance marker outside the listed hosts')
    return fenced


def render(raw, current, phase, ingress):
    targets = target_hosts(phase, ingress)
    text = raw.decode()
    baseline = normalized(adapt(raw))
    require(baseline == normalized(current), 'runtime config differs from the Caddyfile source')
    fenced_hosts_in(text, ingress)
    for host in targets:
        text = set_fence(text, host, marker_of(ingress, host), ingress['maintenance_tag'], phase == 'fence')
    fenced_hosts_in(text, ingress)
    candidate = text.encode()
    adapted = adapt(candidate)
    require(masked(adapted, targets) == masked(baseline, targets), 'candidate changes a route outside the target hosts')
    gated = [host for host in targets if (has_gate if phase == 'fence' else contains_gate)(route_of(adapted, host))]
    require(gated == (targets if phase == 'fence' else []), 'candidate maintenance routes differ from the phase')
    return candidate, adapted


def trusted(path, directory=False):
    require(path.is_absolute() and '..' not in path.parts)
    for parent in path.parents:
        st = parent.lstat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022)
    st = path.lstat()
    require(st.st_uid == 0 and not st.st_mode & 0o022)
    require(stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode) and st.st_nlink == 1)
    return st


def instance():
    template = '{"id":{{json .Id}},"state":{{json .State}},"mounts":{{json .Mounts}},"cmd":{{json .Config.Cmd}}}'
    info = json.loads(run(['docker', 'inspect', '--format', template, 'nostr-caddy']))
    require(info['state']['Running'] is True and not info['state']['Restarting'])
    require(info['cmd'] == ['caddy', 'run', '--config', '/etc/caddy/Caddyfile', '--adapter', 'caddyfile'])
    mounts = [m for m in info['mounts'] if m['Destination'] == '/etc/caddy/Caddyfile']
    require(len(mounts) == 1 and mounts[0]['Type'] == 'bind' and mounts[0]['Source'] == str(SOURCE) and mounts[0]['RW'] is False)
    return [info['id'], info['state']['Pid'], info['state']['StartedAt']]


def bind_path(inst):
    require(type(inst[1]) is int and inst[1] > 0)
    return Path(f'/proc/{inst[1]}/root/etc/caddy/Caddyfile')


def read_bind(inst, readonly=True):
    rows = [r.split() for r in Path(f'/proc/{inst[1]}/mountinfo').read_text().splitlines()
            if r.split()[4] == '/etc/caddy/Caddyfile']
    require(len(rows) == 1 and set(rows[0][5].split(',')) == {'ro' if readonly else 'rw', 'relatime'})
    st = bind_path(inst).lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022)
    return [st.st_dev, st.st_ino], bind_path(inst).read_bytes()


def snapshot():
    st = trusted(SOURCE)
    inst = instance()
    identity, mounted = read_bind(inst)
    result = {'instance': inst, 'source_identity': [st.st_dev, st.st_ino], 'bind_identity': identity}
    return result, SOURCE.read_bytes(), mounted, live()


def write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def check_snapshot(report, source, mounted, current, readonly=True):
    require(instance() == report['instance'])
    st = trusted(SOURCE)
    require([st.st_dev, st.st_ino] == report['source_identity'] and SOURCE.read_bytes() == source)
    require(read_bind(report['instance'], readonly) == (report['bind_identity'], mounted))
    require(live() == current and instance() == report['instance'])


@contextmanager
def writable_bind(report):
    inst = report['instance']
    fd = None
    try:
        require(instance() == inst and read_bind(inst)[0] == report['bind_identity'])
        run(['nsenter', '--target', str(inst[1]), '--mount', '--root', '--wdns=/', '--',
             '/bin/mount', '-o', 'remount,bind,relatime,rw', 'none', '/etc/caddy/Caddyfile'])
        require(instance() == inst and read_bind(inst, False)[0] == report['bind_identity'])
        fd = os.open(bind_path(inst), os.O_RDWR | os.O_NOFOLLOW)
        st = os.fstat(fd)
        require([st.st_dev, st.st_ino] == report['bind_identity'])
        if report['bind_identity'] != report['source_identity']:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield fd
    finally:
        if fd is not None:
            os.close(fd)
        require(instance() == inst)
        run(['nsenter', '--target', str(inst[1]), '--mount', '--root', '--wdns=/', '--',
             '/bin/mount', '-o', 'remount,bind,relatime,ro', 'none', '/etc/caddy/Caddyfile'])
        require(read_bind(inst)[0] == report['bind_identity'])


def write_in_place(fd, raw):
    os.lseek(fd, 0, os.SEEK_SET)
    remaining = memoryview(raw)
    while remaining:
        count = os.write(fd, remaining)
        require(count > 0)
        remaining = remaining[count:]
    os.ftruncate(fd, len(raw))
    os.fsync(fd)


def stage(args, ingress):
    before, raw, mounted, current = snapshot()
    candidate, config = render(raw, current, args.phase, ingress)
    require(snapshot() == (before, raw, mounted, current))
    files = dict(zip(FILES, (raw, mounted, encoded(current), candidate, encoded(config))))
    report = dict(before, phase=args.phase, files={n: sha(b) for n, b in files.items()}, applied=False,
                  is_unchanged=candidate == raw, native_adapt_verified=True, native_validate_verified=False)
    if args.output:
        trusted(args.output.parent, directory=True)
        args.output.mkdir(mode=0o700)
        for name, content in dict(files, **{'report.json': encoded(report)}).items():
            write_new(args.output / name, content)
        sync_directory(args.output)
        sync_directory(args.output.parent)
    return dict(report, report_sha256=sha(encoded(report)))


class Terminated(Exception):
    pass


def raise_terminated(signum, frame):
    raise Terminated('terminated by signal')


def execute(args, ingress):
    trusted(args.stage, directory=True)
    require(stat.S_IMODE(args.stage.stat().st_mode) == 0o700)
    files = {}
    for name in (*FILES, 'report.json'):
        st = trusted(args.stage / name)
        require(stat.S_IMODE(st.st_mode) == 0o600)
        files[name] = (args.stage / name).read_bytes()
    require(sha(files['report.json']) == args.report_sha256)
    report = json.loads(files['report.json'])
    require(report['files'] == {n: sha(files[n]) for n in FILES})
    require(report['phase'] in PHASES and report['applied'] is False)
    old, new = json.loads(files['original.json']), json.loads(files['candidate.json'])
    source, mounted, candidate = files['original.Caddyfile'], files['original-bind.Caddyfile'], files['candidate.Caddyfile']
    require(render(source, old, report['phase'], ingress) == (candidate, new))
    check_snapshot(report, source, mounted, old)
    caddy('validate', candidate)
    check_snapshot(report, source, mounted, old)
    if report['is_unchanged']:
        return {'result': 'ALREADY_IN_STATE', 'phase': report['phase']}
    if not args.apply:
        return {'result': 'CHECKED_NOT_APPLIED', 'phase': report['phase'], 'native_validate_verified': True}
    fd = os.open(SOURCE, os.O_RDWR | os.O_NOFOLLOW)
    previous_handler = signal.signal(signal.SIGTERM, raise_terminated)
    try:
        st = os.fstat(fd)
        require([st.st_dev, st.st_ino] == report['source_identity'])
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        check_snapshot(report, source, mounted, old)
        attempt = args.stage / 'apply-attempt'
        attempt.mkdir(mode=0o700)
        sync_directory(args.stage)
        changed = False
        try:
            with writable_bind(report) as bind_fd:
                check_snapshot(report, source, mounted, old, False)
                changed = True
                write_in_place(fd, candidate)
                write_in_place(bind_fd, candidate)
            check_snapshot(report, candidate, candidate, old)
            caddy('validate', candidate)
            check_snapshot(report, candidate, candidate, old)
            caddy('reload', candidate)
            check_snapshot(report, candidate, candidate, new)
            result = {'result': 'APPLIED', 'phase': report['phase'], 'bind_readonly_restored': True}
        except BaseException as error:
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            restored = False
            if changed:
                try:
                    now, now_bind, now_live = SOURCE.read_bytes(), read_bind(report['instance'])[1], live()
                    require(now in (source, candidate) and now_bind in (mounted, candidate) and now_live in (old, new))
                    with writable_bind(report) as bind_fd:
                        check_snapshot(report, now, now_bind, now_live, False)
                        write_in_place(fd, source)
                        write_in_place(bind_fd, mounted)
                    # Exact source/bind/runtime baselines, not a reload of stale Caddyfile.
                    caddy('validate', encoded(old), adapter=False)
                    caddy('reload', encoded(old), adapter=False)
                    check_snapshot(report, source, mounted, old)
                    restored = True
                except BaseException:
                    pass
            result = {'result': 'FAILED', 'error_type': type(error).__name__, 'source_write_attempted': changed,
                      'restored': restored, 'manual_recovery_required': not restored}
        write_new(attempt / 'result.json', encoded(result))
        sync_directory(attempt)
        return result
    finally:
        signal.signal(signal.SIGTERM, previous_handler)
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release-lock-base64', required=True)
    parser.add_argument('--release-lock-sha256', required=True)
    commands = parser.add_subparsers(dest='command', required=True)
    p = commands.add_parser('stage')
    p.add_argument('--phase', choices=PHASES, required=True)
    p.add_argument('--output', type=Path, help='Omit for read-only adapt and inspect; never applies')
    p = commands.add_parser('check')
    p.add_argument('--stage', type=Path, required=True)
    p.add_argument('--report-sha256', required=True)
    p.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        require(os.geteuid() == 0)
        ingress = read_ingress(read_release_lock(args.release_lock_base64, args.release_lock_sha256))
        result = stage(args, ingress) if args.command == 'stage' else execute(args, ingress)
    except BaseException as error:
        trace, lines = error.__traceback__, []
        while trace:
            if trace.tb_frame.f_code.co_filename == __file__:
                lines.append(trace.tb_lineno)
            trace = trace.tb_next
        result = {'result': 'FAILED', 'source_lines': lines, 'error_type': type(error).__name__,
                  'detail': 'Inspect the stage; no blind retry or container restart'}
        if isinstance(error, ValueError):
            result['reason'] = str(error)
    print(json.dumps(result, sort_keys=True), file=sys.stderr if result.get('result') == 'FAILED' else sys.stdout)
    return 1 if result.get('result') == 'FAILED' else 0


if __name__ == '__main__':
    raise SystemExit(main())
