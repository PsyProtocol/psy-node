#!/usr/bin/env python3
"""Stage/check/apply R3 routing fences with separate Faucet/private approvals.

Adapt-only inspect is read-only. Staging writes only a NEW private directory.
Check provisions Caddy validation, but never reloads or writes either source.
Apply is main-only; exclude other Caddy operators throughout. No container restart.
The bind-write transaction is adapted from the reviewed R2 Caddy apply helper.
"""
import argparse
import copy
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

SOURCE = Path('/opt/nostr-relay/Caddyfile')
FAUCETS = ('faucet-stg.psy-protocol.xyz', 'faucet.psy-protocol.xyz')
PRIVATE_HOST = 'services-stg.psy-protocol.xyz'
PRIVATE_PATHS = ['/api/v1/wallet/private-claimable', '/api/v1/wallet/private-claimable/*']
PRIVATE_OPEN_SOURCE_SHA256 = '5138e1c3e41c20d72ad1790727cc13218d0e695c4f80ecec790904ed3420557d'
OLD, NEW = '10.148.0.31:29998', '10.148.0.32:29998'
BODY = 'Testnet maintenance. Please retry shortly.\n'
HEADERS = {'Content-Type': ['text/plain; charset=utf-8'], 'Retry-After': ['60']}
TAGS = ('psy-r3-private-claimable-maintenance', 'psy-r3-maintenance')
FILES = ('original.Caddyfile', 'original-bind.Caddyfile', 'original.json',
         'candidate.Caddyfile', 'candidate.json', 'gate-evidence.json')


def require(ok):
    if not ok:
        raise ValueError('Caddy scope, identity or concurrent-change check failed')


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


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
        if obj.get('handler') == 'file_server' and obj.get('hide') in (['./-'], ['/dev/stdin']):
            obj['hide'] = ['CADDY_ADAPTER_CONFIG_PATH']
        # The adapter allocates group numbers even for a single handle. Preserve
        # the complete equivalence relation, not its incidental numeric labels.
        if isinstance(obj.get('group'), str) and re.fullmatch(r'group\d+', obj['group']):
            obj['group'] = groups.setdefault(obj['group'], 'group' + str(len(groups)))
    return value


def differences(left, right, path=''):
    if left == right:
        return []
    if type(left) is type(right) and isinstance(left, (dict, list)):
        a = left if isinstance(left, dict) else dict(enumerate(left))
        b = right if isinstance(right, dict) else dict(enumerate(right))
        return [p for k in a.keys() | b.keys() for p in differences(a.get(k), b.get(k), path + '/' + str(k))]
    return [path]


def response():
    return {'handler': 'static_response', 'status_code': 503, 'body': BODY, 'headers': HEADERS}


def top_gate(private):
    match = {'host': [PRIVATE_HOST] if private else list(FAUCETS)}
    if private:
        match['path'] = PRIVATE_PATHS
    return {'@id': TAGS[0 if private else 1], 'match': [match], 'handle': [response()], 'terminal': True}


def subroute(routes):
    return [{'handler': 'subroute', 'routes': routes}]


def nested_gate(private, host=None):
    gate = {'handle': subroute([{'handle': [
        {'handler': 'headers', 'response': {'set': HEADERS}},
        {k: v for k, v in response().items() if k != 'headers'}]}])}
    gate['match'] = [{'path': PRIVATE_PATHS}] if private else [{'host': [host]}]
    return gate


def routes(config):
    return config['apps']['http']['servers']['srv0']['routes']


def site(config, host):
    found = [r for r in routes(config) if r.get('match') == [{'host': [host]}]]
    require(len(found) == 1 and set(found[0]) == {'match', 'handle', 'terminal'} and found[0]['terminal'] is True)
    require(len(found[0]['handle']) == 1 and found[0]['handle'][0]['handler'] == 'subroute')
    return found[0]


def block(text, host):
    # Deliberately not a general Caddyfile parser: exact top-level boundaries,
    # followed by native adaptation and whole-config structural comparison.
    opening = host + ' {\n'
    require(text.count(opening) == 1)
    start = text.index(opening) + len(opening)
    end = text.index('\n}\n', start)
    return start, end, text[start:end] + '\n'


def gate_text(private, host=None):
    matcher = ('path ' + ' '.join(PRIVATE_PATHS)) if private else ('host ' + host)
    return ('        @psy_r3_fence ' + matcher + '\n        route @psy_r3_fence {\n'
            '            header {\n                Content-Type "text/plain; charset=utf-8"\n'
            '                Retry-After 60\n            }\n'
            '            respond "' + BODY + '" 503\n        }\n')


def wrap_text(body, private, host):
    prefix = ''
    if private:
        anchor = '    @not_private_claimable not path '
        require(body.count(anchor) == 1)
        cut = body.index(anchor)
        prefix, body = body[:cut], body[cut:]
    return prefix + '    # BEGIN psy-r3-fence\n    route {\n' + gate_text(private, host) + (
        '        handle {\n' + body + '        }\n    }\n    # END psy-r3-fence\n')


def render(raw, current, phase):
    require(phase in ('prepare', 'open', 'private-open'))
    if phase == 'private-open':
        require(sha(raw) == PRIVATE_OPEN_SOURCE_SHA256)
    text = raw.decode()
    baseline = normalized(adapt(raw))
    expected = copy.deepcopy(baseline)
    if phase == 'prepare':
        require('psy-r3-fence' not in text)
        stripped = copy.deepcopy(current)
        require(routes(stripped)[:2] == [top_gate(True), top_gate(False)])
        del routes(stripped)[:2]
        require(normalized(stripped) == baseline)
        for host in (*FAUCETS, PRIVATE_HOST):
            route = site(expected, host)
            start, end, body = block(text, host)
            if host in FAUCETS:
                proxies = [o for o in objects(route) if o.get('handler') == 'reverse_proxy']
                require(len(proxies) == 1 and proxies[0]['upstreams'] == [{'dial': OLD}])
                proxies[0]['upstreams'] = [{'dial': NEW}]
                needle = '    reverse_proxy ' + OLD + ' {\n'
                require(body.count(needle) == 1)
                body = body.replace(needle, '    reverse_proxy ' + NEW + ' {\n')
            route['handle'] = subroute([{'handle': subroute([
                nested_gate(host == PRIVATE_HOST, host), {'handle': route['handle']}])}])
            text = text[:start] + wrap_text(body, host == PRIVATE_HOST, host).rstrip('\n') + text[end:]
    elif phase == 'private-open':
        require(baseline == normalized(current))
        route = site(expected, PRIVATE_HOST)
        inner = route['handle'][0]['routes'][0]['handle'][0]['routes']
        require(len(inner) == 2 and inner[0] == nested_gate(True) and set(inner[1]) == {'handle'})
        require(route['handle'] == subroute([{'handle': subroute(inner)}]))
        route['handle'] = inner[1]['handle']
        start, end, body = block(text, PRIVATE_HOST)
        marker = '    # BEGIN psy-r3-fence\n'
        require(body.count(marker) == 1)
        cut = body.index(marker)
        prefix = marker + '    route {\n' + gate_text(True) + '        handle {\n'
        suffix = '        }\n    }\n    # END psy-r3-fence\n'
        wrapped = body[cut:]
        require(wrapped.startswith(prefix) and wrapped.endswith(suffix))
        restored = body[:cut] + wrapped[len(prefix):-len(suffix)]
        require(wrap_text(restored, True, PRIVATE_HOST) == body)
        text = text[:start] + restored.rstrip('\n') + text[end:]
    else:
        require(baseline == normalized(current))
        # Check the private fence exactly; it is never removed or generalized.
        private_site = site(expected, PRIVATE_HOST)
        private = private_site['handle'][0]['routes'][0]['handle'][0]['routes']
        require(len(private) == 2 and private[0] == nested_gate(True))
        require(private_site['handle'] == subroute([{'handle': subroute(private)}]))
        for host in FAUCETS:
            route = site(expected, host)
            wrapped = route['handle'][0]['routes']
            inner = wrapped[0]['handle'][0]['routes']
            require(len(wrapped) == 1 and len(inner) == 2 and inner[0] == nested_gate(False, host))
            require(set(inner[1]) == {'handle'})
            route['handle'] = inner[1]['handle']
            proxies = [o for o in objects(route) if o.get('handler') == 'reverse_proxy']
            require(len(proxies) == 1 and proxies[0]['upstreams'] == [{'dial': NEW}])
            start, end, body = block(text, host)
            prefix = '    # BEGIN psy-r3-fence\n    route {\n' + gate_text(False, host) + '        handle {\n'
            suffix = '        }\n    }\n    # END psy-r3-fence\n'
            require(body.startswith(prefix) and body.endswith(suffix))
            text = text[:start] + body[len(prefix):-len(suffix)].rstrip('\n') + text[end:]
    candidate = text.encode()
    adapted = adapt(candidate)
    mismatch = differences(normalized(adapted), expected)
    if mismatch:
        error = ValueError('candidate adaptation differs')
        error.paths = mismatch
        raise error
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


def validate_gate(evidence, phase, source):
    require(phase in ('open', 'private-open'))
    gate = json.loads(evidence)
    require(gate['approved_by_main'] is True and gate['prepared_caddyfile_sha256'] == sha(source))
    if phase == 'private-open':
        require(sha(source) == PRIVATE_OPEN_SOURCE_SHA256
                and gate['action'] == 'open-r3-private-claimable'
                and set(gate) == {'action', 'approved_by_main', 'prepared_caddyfile_sha256',
                                  'ingestion_evidence_sha256', 'claim_evidence_sha256'})
        fields = ('ingestion_evidence_sha256', 'claim_evidence_sha256')
    else:
        require(gate['action'] == 'open-r3-faucet')
        fields = ('grant_evidence_sha256',)
    require(all(type(gate[field]) is str and re.fullmatch('[0-9a-f]{64}', gate[field]) for field in fields))


def stage(args):
    before, raw, mounted, current = snapshot()
    candidate, config = render(raw, current, args.phase)
    evidence = b'null'
    if args.phase in ('open', 'private-open'):
        require(args.gate_evidence is not None and args.gate_evidence_sha256 is not None)
        trusted(args.gate_evidence)
        evidence = args.gate_evidence.read_bytes()
        require(sha(evidence) == args.gate_evidence_sha256)
        validate_gate(evidence, args.phase, raw)
    else:
        require(args.gate_evidence is None and args.gate_evidence_sha256 is None)
    require(snapshot() == (before, raw, mounted, current))
    files = dict(zip(FILES, (raw, mounted, encoded(current), candidate, encoded(config), evidence)))
    report = dict(before, phase=args.phase, files={n: sha(b) for n, b in files.items()}, applied=False,
                  native_adapt_verified=True, native_validate_verified=False,
                  private_fence_retained=args.phase != 'private-open')
    if args.output:
        trusted(args.output.parent, directory=True)
        args.output.mkdir(mode=0o700)
        for name, content in dict(files, **{'report.json': encoded(report)}).items():
            write_new(args.output / name, content)
        sync_directory(args.output)
        sync_directory(args.output.parent)
    return dict(report, report_sha256=sha(encoded(report)))


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


def execute(args):
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
    require(report['phase'] in ('prepare', 'open', 'private-open') and report['applied'] is False)
    require(not args.apply or report['phase'] != 'open' or args.open_confirmed)
    require(not args.apply or report['phase'] != 'private-open' or getattr(args, 'private_open_confirmed', False))
    require(report['private_fence_retained'] is (report['phase'] != 'private-open'))
    old, new = json.loads(files['original.json']), json.loads(files['candidate.json'])
    source, mounted, candidate = files['original.Caddyfile'], files['original-bind.Caddyfile'], files['candidate.Caddyfile']
    require(render(source, old, report['phase']) == (candidate, new))
    if report['phase'] in ('open', 'private-open'):
        validate_gate(files['gate-evidence.json'], report['phase'], source)
    check_snapshot(report, source, mounted, old)
    caddy('validate', candidate)
    check_snapshot(report, source, mounted, old)
    if not args.apply:
        return {'result': 'CHECKED_NOT_APPLIED', 'phase': report['phase'], 'native_validate_verified': True}
    fd = os.open(SOURCE, os.O_RDWR | os.O_NOFOLLOW)
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
        except BaseException:
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
            result = {'result': 'FAILED', 'source_write_attempted': changed, 'restored': restored,
                      'manual_recovery_required': True}
        write_new(attempt / 'result.json', encoded(result))
        sync_directory(attempt)
        return result
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    p = commands.add_parser('stage')
    p.add_argument('--phase', choices=('prepare', 'open', 'private-open'), required=True)
    p.add_argument('--output', type=Path, help='Omit for read-only adapt/inspect; never applies')
    p.add_argument('--gate-evidence', type=Path)
    p.add_argument('--gate-evidence-sha256')
    p = commands.add_parser('check')
    p.add_argument('--stage', type=Path, required=True)
    p.add_argument('--report-sha256', required=True)
    p.add_argument('--apply', action='store_true')
    p.add_argument('--open-confirmed', action='store_true')
    p.add_argument('--private-open-confirmed', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        require(os.geteuid() == 0)
        result = stage(args) if args.command == 'stage' else execute(args)
    except BaseException as error:
        trace, lines = error.__traceback__, []
        while trace:
            if trace.tb_frame.f_code.co_filename == __file__:
                lines.append(trace.tb_lineno)
            trace = trace.tb_next
        result = {'result': 'FAILED', 'source_lines': lines, 'error_type': type(error).__name__,
                  'detail': 'Inspect private stage; no blind retry or container restart'}
        if hasattr(error, 'paths'):
            result['different_paths'] = error.paths
    print(json.dumps(result, sort_keys=True))
    return 1 if result.get('result') == 'FAILED' else 0


if __name__ == '__main__':
    raise SystemExit(main())
