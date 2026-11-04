"""Synthetic config/transaction checks. No Docker, SSH, mounts or real reloads."""
import base64
import copy
from contextlib import contextmanager
import io
import json
import os
from pathlib import Path
import re
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import caddy_ingress as c

WRITABLE_BIND = c.writable_bind
LOCK_INGRESS = {'fenced_hosts': ['coordinator.example.test', 'services.example.test'],
                'faucet_hosts': ['faucet.example.test'], 'retired_hosts': ['indexer.example.test'],
                'maintenance_tag': 'maintenance-test'}
INGRESS = LOCK_INGRESS
OTHER_HOSTS = ('rpc-eth.example.test', 'nostr.example.test')


def site_text(host, upstream):
    extra = '    log {\n        output stderr\n    }\n' if host.startswith('services') else ''
    return host + ' {\n' + extra + '    encode zstd gzip\n    reverse_proxy ' + upstream + ' {\n    }\n}\n\n'


def fixture_text():
    hosts = (*INGRESS['fenced_hosts'], *INGRESS['faucet_hosts'], *OTHER_HOSTS)
    return ''.join(site_text(host, '10.0.0.%d:8000' % (index + 1)) for index, host in enumerate(hosts)).encode()


def adapt_text(raw):
    """Stand-in for native adaptation: one route per site block, with a 503 handler when fenced."""
    found = re.findall(r'(?ms)^(\S+) \{\n(.*?)\n\}$', raw.decode())
    table = []
    for host, body in found:
        handlers = [{'handler': 'reverse_proxy', 'upstreams': [{'dial': re.search(r'reverse_proxy (\S+)', body).group(1)}]}]
        if 'respond "%s" 503' % c.BODY in body:
            handlers.insert(0, {'handler': 'static_response', 'status_code': 503, 'body': c.BODY})
        table.append({'match': [{'host': [host]}], 'terminal': True,
                      'handle': [{'handler': 'subroute', 'routes': [{'handle': handlers}]}]})
    return {'apps': {'http': {'servers': {'srv0': {'listen': [':443'], 'routes': table}}}}, 'logging': {'logs': {}}}


class RenderTests(unittest.TestCase):
    def setUp(self):
        self.raw = fixture_text()
        self.enterContext(patch.object(c, 'adapt', side_effect=adapt_text))

    def render(self, raw, phase):
        return c.render(raw, adapt_text(raw), phase, INGRESS)

    def fenced(self):
        return self.render(self.raw, 'fence')[0]

    def block(self, raw, host):
        start, end = c.block_span(raw.decode(), host)
        return raw.decode()[start:end]

    def test_fence_returns_503_for_each_listed_host(self):
        candidate, config = self.render(self.raw, 'fence')
        for host in (*INGRESS['fenced_hosts'], *INGRESS['faucet_hosts']):
            with self.subTest(host=host):
                self.assertTrue(c.has_gate(c.route_of(config, host)))
                self.assertTrue(self.block(candidate, host).startswith(c.fence_text(c.marker_of(INGRESS, host))))
        self.assertEqual(candidate.count(b'# BEGIN maintenance-test'), 3)
        self.assertEqual(candidate.count(b'# BEGIN maintenance-test-faucet'), 1)

    def test_fence_leaves_l1_rpc_routes_unchanged(self):
        candidate, config = self.render(self.raw, 'fence')
        before = adapt_text(self.raw)
        for host in OTHER_HOSTS:
            with self.subTest(host=host):
                self.assertEqual(c.route_of(config, host), c.route_of(before, host))
                self.assertEqual(self.block(candidate, host), self.block(self.raw, host))
        self.assertEqual(config['logging'], before['logging'])

    def test_open_removes_only_tagged_route(self):
        fenced = self.fenced()
        candidate, config = self.render(fenced, 'open')
        for host in INGRESS['fenced_hosts']:
            with self.subTest(host=host):
                self.assertFalse(c.has_gate(c.route_of(config, host)))
                self.assertEqual(self.block(candidate, host), self.block(self.raw, host))
        for host in (*INGRESS['faucet_hosts'], *OTHER_HOSTS):
            self.assertEqual(self.block(candidate, host), self.block(fenced, host))

    def test_open_keeps_faucet_hosts_fenced(self):
        candidate, config = self.render(self.fenced(), 'open')
        for host in INGRESS['faucet_hosts']:
            self.assertTrue(c.has_gate(c.route_of(config, host)))
        self.assertEqual(c.fenced_hosts_in(candidate.decode(), INGRESS), INGRESS['faucet_hosts'])

    def test_open_faucet_removes_only_faucet_fence(self):
        fenced = self.fenced()
        candidate, config = self.render(fenced, 'open-faucet')
        for host in INGRESS['faucet_hosts']:
            self.assertFalse(c.has_gate(c.route_of(config, host)))
            self.assertEqual(self.block(candidate, host), self.block(self.raw, host))
        for host in INGRESS['fenced_hosts']:
            self.assertTrue(c.has_gate(c.route_of(config, host)))
            self.assertEqual(self.block(candidate, host), self.block(fenced, host))
        opened, _ = self.render(self.render(fenced, 'open')[0], 'open-faucet')
        self.assertEqual(opened, self.raw)

    def test_open_refuses_when_unknown_route_changed(self):
        fenced = self.fenced()
        drifted = adapt_text(fenced)
        c.route_of(drifted, OTHER_HOSTS[0])['handle'][0]['routes'][0]['handle'][0]['upstreams'] = [{'dial': '10.9.9.9:1'}]
        with self.assertRaisesRegex(ValueError, 'runtime config differs'):
            c.render(fenced, drifted, 'open', INGRESS)
        stray = fenced.replace(b'rpc-eth.example.test {\n', b'rpc-eth.example.test {\n    # BEGIN maintenance-test\n')
        with self.assertRaisesRegex(ValueError, 'maintenance marker'):
            self.render(stray, 'open')
        edited = fenced.replace(b'Retry-After 60', b'Retry-After 5', 1)
        with self.assertRaisesRegex(ValueError, 'maintenance marker'):
            self.render(edited, 'open')

    def test_fence_refuses_missing_duplicate_or_changed_route(self):
        with self.assertRaisesRegex(ValueError, 'not found exactly once'):
            self.render(self.raw + site_text('faucet.example.test', '10.1.1.1:1').encode(), 'fence')
        with self.assertRaisesRegex(ValueError, 'not found exactly once'):
            self.render(self.raw.replace(b'services.example.test {', b'services2.example.test {'), 'fence')
        drifted = adapt_text(self.raw)
        c.route_of(drifted, 'coordinator.example.test')['terminal'] = False
        with self.assertRaisesRegex(ValueError, 'runtime config differs'):
            c.render(self.raw, drifted, 'fence', INGRESS)

    def test_candidate_that_changes_other_routes_or_lacks_a_gate_is_refused(self):
        broken = adapt_text(self.fenced())
        c.route_of(broken, OTHER_HOSTS[1])['terminal'] = False
        with patch.object(c, 'adapt', side_effect=[adapt_text(self.raw), broken]):
            with self.assertRaisesRegex(ValueError, 'outside the target hosts'):
                self.render(self.raw, 'fence')
        with patch.object(c, 'adapt', side_effect=[adapt_text(self.raw), adapt_text(self.raw)]):
            with self.assertRaisesRegex(ValueError, 'differ from the phase'):
                self.render(self.raw, 'fence')

    def test_fence_is_idempotent(self):
        once, config = self.render(self.raw, 'fence')
        twice, again = c.render(once, config, 'fence', INGRESS)
        self.assertEqual(once, twice)
        self.assertEqual(config, again)

    def test_open_on_open_hosts_changes_nothing(self):
        self.assertEqual(self.render(self.raw, 'open')[0], self.raw)
        self.assertEqual(self.render(self.raw, 'open-faucet')[0], self.raw)

    def test_half_written_fence_is_refused(self):
        fenced = self.fenced().decode()
        torn = fenced.replace('    # END maintenance-test\n', '', 1).encode()
        with self.assertRaisesRegex(ValueError, 'maintenance marker'):
            self.render(torn, 'fence')

    def test_group_normalization_preserves_membership_and_other_fields(self):
        a = [{'group': 'group0'}, {'group': 'group0'}, {'group': 'group2'}]
        b = [{'group': 'group8'}, {'group': 'group8'}, {'group': 'group9'}]
        self.assertEqual(c.normalized(a), c.normalized(b))
        b[1]['group'] = 'group9'
        self.assertNotEqual(c.normalized(a), c.normalized(b))
        self.assertNotEqual(c.normalized({'@id': 'keep-me'}), c.normalized({}))

    def test_hide_path_of_every_start_mode_is_equivalent_but_other_paths_are_not(self):
        def hidden(path):
            return {'handler': 'file_server', 'hide': [path]}
        modes = ('./-', '/dev/stdin', '/etc/caddy/Caddyfile')
        self.assertEqual(len({json.dumps(c.normalized(hidden(path))) for path in modes}), 1)
        self.assertNotEqual(c.normalized(hidden('/etc/caddy/Caddyfile')), c.normalized(hidden('/srv/other')))

    def test_plain_start_runtime_matches_the_stdin_adaptation(self):
        def with_file_server(config, path):
            c.route_of(config, OTHER_HOSTS[1])['handle'][0]['routes'][0]['handle'].append({'handler': 'file_server', 'hide': [path]})
            return config
        runtime = with_file_server(adapt_text(self.raw), '/etc/caddy/Caddyfile')
        with patch.object(c, 'adapt', side_effect=lambda raw: with_file_server(adapt_text(raw), '/dev/stdin')):
            candidate, _ = c.render(self.raw, runtime, 'fence', INGRESS)
        self.assertIn(b'# BEGIN maintenance-test', candidate)

    def test_logging_or_other_top_level_drift_is_refused(self):
        drifted = adapt_text(self.raw)
        drifted['logging'] = {'logs': {'added': {}}}
        with self.assertRaisesRegex(ValueError, 'runtime config differs'):
            c.render(self.raw, drifted, 'fence', INGRESS)
        broken = adapt_text(self.fenced())
        broken['logging'] = {}
        with patch.object(c, 'adapt', side_effect=[adapt_text(self.raw), broken]):
            with self.assertRaisesRegex(ValueError, 'outside the target hosts'):
                self.render(self.raw, 'fence')

    def test_fence_that_a_handle_route_or_matcher_can_bypass_is_refused(self):
        for kind in ('handle-before', 'matcher'):
            candidate = adapt_text(self.fenced())
            route = c.route_of(candidate, INGRESS['fenced_hosts'][0])
            routes = route['handle'][0]['routes']
            if kind == 'handle-before':
                routes.insert(0, {'match': [{'path': ['/x']}], 'handle': [{'handler': 'reverse_proxy'}]})
            else:
                routes[0]['match'] = [{'path': ['/y']}]
            with self.subTest(kind=kind), patch.object(c, 'adapt', side_effect=[adapt_text(self.raw), candidate]):
                with self.assertRaisesRegex(ValueError, 'differ from the phase'):
                    self.render(self.raw, 'fence')

    def test_open_refuses_a_leftover_gate_that_is_not_in_first_position(self):
        fenced = self.fenced()
        leftover = adapt_text(fenced)
        with patch.object(c, 'adapt', side_effect=[adapt_text(fenced), leftover]):
            with self.assertRaisesRegex(ValueError, 'differ from the phase'):
                self.render(fenced, 'open')

    def test_every_phase_removes_the_retired_indexer_site_and_nothing_else(self):
        raw = fixture_text() + site_text('indexer.example.test', '10.0.0.24:38081').encode()
        raw += site_text('other-indexer.example.test', '10.0.0.24:28081').encode()
        for phase in ('fence', 'open', 'open-faucet'):
            with self.subTest(phase=phase):
                candidate, config = c.render(raw, adapt_text(raw), phase, INGRESS)
                self.assertNotIn(b'indexer.example.test {', candidate.replace(b'other-indexer.example.test {', b''))
                self.assertIn('reverse_proxy 10.0.0.24:28081 {', self.block(candidate, 'other-indexer.example.test'))
                self.assertNotIn('indexer.example.test', c.hosts_in(config))
                self.assertEqual(c.hosts_in(config), c.hosts_in(adapt_text(raw)) - {'indexer.example.test'})
        fenced, config = c.render(raw, adapt_text(raw), 'fence', INGRESS)
        again, _ = c.render(fenced, config, 'fence', INGRESS)
        self.assertEqual(again, fenced)
        opened, _ = c.render(fenced, config, 'open', INGRESS)
        self.assertNotIn(b'\nindexer.example.test {', b'\n' + opened)

    def test_group_labels_of_a_removed_retired_route_do_not_shift_the_others(self):
        def route(host, group):
            return {'match': [{'host': [host]}], 'handle': [{'handler': 'subroute', 'routes': [{'group': group, 'handle': []}]}]}
        baseline = {'apps': {'http': {'servers': {'srv0': {'routes': [route('indexer.example.test', 'group0'),
                                                                      route('a.example.test', 'group1')]}}}}}
        candidate = {'apps': {'http': {'servers': {'srv0': {'routes': [route('a.example.test', 'group0')]}}}}}
        self.assertEqual(c.masked(baseline, ['indexer.example.test']), c.masked(candidate, ['indexer.example.test']))
        changed = {'apps': {'http': {'servers': {'srv0': {'routes': [route('b.example.test', 'group0')]}}}}}
        self.assertNotEqual(c.masked(baseline, ['indexer.example.test']), c.masked(changed, ['indexer.example.test']))

    def test_a_retired_host_inside_a_shared_site_block_is_refused(self):
        raw = fixture_text() + b'indexer.example.test, indexer-stg.example.test {\n    reverse_proxy 10.0.0.24:38081 {\n    }\n}\n'
        shared = adapt_text(raw)
        shared['apps']['http']['servers']['srv0']['routes'].append({'match': [{'host': ['indexer.example.test']}], 'terminal': True,
                                                                     'handle': []})
        with patch.object(c, 'adapt', side_effect=[shared, shared]):
            with self.assertRaisesRegex(ValueError, 'retired host still has a route'):
                c.render(raw, shared, 'fence', INGRESS)

    def test_a_foreign_maintenance_block_is_refused_by_name(self):
        foreign = self.raw.replace(b'coordinator.example.test {\n', b'coordinator.example.test {\n    # BEGIN other-team-maintenance\n'
                                   b'    respond "down" 503\n    # END other-team-maintenance\n', 1)
        for phase in ('fence', 'open'):
            with self.subTest(phase=phase), self.assertRaisesRegex(ValueError, 'foreign maintenance block other-team-maintenance'):
                c.render(foreign, adapt_text(foreign), phase, INGRESS)

    def test_ingress_comes_from_a_hash_checked_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            raw = json.dumps({'ingress': LOCK_INGRESS}).encode()
            encoded_lock = base64.b64encode(raw).decode()
            self.assertEqual(c.read_ingress(c.read_release_lock(encoded_lock, c.sha(raw))), LOCK_INGRESS)
            with_envio = json.dumps({'ingress': LOCK_INGRESS, 'hosts': {'gcp-postgres': '10.0.0.24'}, 'envio': {'indexer_port': 29899}}).encode()
            self.assertEqual(c.read_ingress(c.read_release_lock(base64.b64encode(with_envio).decode(), c.sha(with_envio))), LOCK_INGRESS)
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                c.read_release_lock(encoded_lock, c.sha(raw + b' '))
        for bad in (dict(LOCK_INGRESS, maintenance_tag='Bad Tag'), dict(LOCK_INGRESS, faucet_hosts=['coordinator.example.test']),
                    dict(LOCK_INGRESS, fenced_hosts=['a b']), dict(LOCK_INGRESS, retired_hosts=['coordinator.example.test'])):
            with self.assertRaises(ValueError):
                c.read_ingress({'ingress': bad})


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source, self.bind = self.root / 'Caddyfile', self.root / 'mounted-file'
        self.source.write_bytes(b'source')
        self.bind.write_bytes(b'older bound inode')
        self.current = {'old': True}
        self.new = {'candidate': True}
        self.inst = ['container-id', 42, 'started-at']
        self.commands = []
        self.fail_reload = False
        self.external_change = False
        self.enterContext(patch.object(c, 'SOURCE', self.source))
        self.enterContext(patch.object(c, 'trusted', side_effect=lambda path, **kw: path.lstat()))
        self.enterContext(patch.object(c, 'instance', return_value=self.inst))
        self.enterContext(patch.object(c, 'live', side_effect=lambda: copy.deepcopy(self.current)))
        self.enterContext(patch.object(c, 'read_bind', side_effect=lambda inst, readonly=True:
                                     ([self.bind.stat().st_dev, self.bind.stat().st_ino], self.bind.read_bytes())))
        self.enterContext(patch.object(c, 'render', return_value=(b'candidate', self.new)))
        self.enterContext(patch.object(c, 'caddy', side_effect=self.command))
        self.enterContext(patch.object(c, 'writable_bind', side_effect=self.writable))
        self.stage = self.root / 'stage'
        self.stage_args = SimpleNamespace(phase='fence', output=self.stage)
        result = c.stage(self.stage_args, INGRESS)
        self.args = SimpleNamespace(stage=self.stage, report_sha256=result['report_sha256'], apply=False)

    @contextmanager
    def writable(self, report):
        fd = os.open(self.bind, os.O_RDWR)
        try:
            yield fd
        finally:
            os.close(fd)

    def command(self, operation, raw, adapter=True):
        self.commands.append((operation, adapter))
        if operation == 'reload':
            self.current = copy.deepcopy(self.new) if adapter else json.loads(raw)
            if self.external_change:
                self.source.write_bytes(b'other operator')
                self.current = {'other_operator': True}
                raise RuntimeError('sensitive diagnostic')
            if self.fail_reload:
                self.fail_reload = False
                raise RuntimeError('sensitive diagnostic')

    def test_check_never_writes_remounts_or_reloads(self):
        with patch.object(c, 'writable_bind') as remount:
            result = c.execute(self.args, INGRESS)
            remount.assert_not_called()
        self.assertEqual(result['result'], 'CHECKED_NOT_APPLIED')
        self.assertEqual(self.commands, [('validate', True)])
        self.assertEqual(self.source.read_bytes(), b'source')
        self.assertFalse((self.stage / 'apply-attempt').exists())

    def test_apply_preserves_both_inodes_and_keeps_originals(self):
        before = self.source.stat().st_ino, self.bind.stat().st_ino
        self.args.apply = True
        self.assertEqual(c.execute(self.args, INGRESS)['result'], 'APPLIED')
        self.assertEqual(before, (self.source.stat().st_ino, self.bind.stat().st_ino))
        self.assertEqual(self.source.read_bytes(), b'candidate')
        self.assertEqual(self.bind.read_bytes(), b'candidate')
        self.assertEqual((self.stage / 'original-bind.Caddyfile').read_bytes(), b'older bound inode')
        self.assertEqual((self.stage / 'report.json').stat().st_mode & 0o777, 0o600)

    def test_reload_failure_restores_exact_three_way_baseline(self):
        self.args.apply = self.fail_reload = True
        result = c.execute(self.args, INGRESS)
        self.assertEqual(result['result'], 'FAILED')
        self.assertTrue(result['restored'])
        self.assertEqual(self.source.read_bytes(), b'source')
        self.assertEqual(self.bind.read_bytes(), b'older bound inode')
        self.assertEqual(self.current, {'old': True})
        self.assertNotIn('sensitive', json.dumps(result))

    def test_drift_not_overwritten_by_rollback(self):
        self.args.apply = self.external_change = True
        result = c.execute(self.args, INGRESS)
        self.assertFalse(result['restored'])
        self.assertEqual(self.source.read_bytes(), b'other operator')
        self.assertEqual(self.current, {'other_operator': True})

    def test_tampered_stage_or_live_drift_fails_before_reload(self):
        for kind in ('stage', 'live'):
            with self.subTest(kind=kind):
                if kind == 'stage':
                    (self.stage / 'candidate.Caddyfile').write_bytes(b'tampered')
                else:
                    (self.stage / 'candidate.Caddyfile').write_bytes(b'candidate')
                    self.current = {'parallel_change': True}
                with self.assertRaises(ValueError):
                    c.execute(self.args, INGRESS)
        self.assertEqual(self.commands, [])

    def test_stage_is_create_only(self):
        with self.assertRaises(FileExistsError):
            c.stage(self.stage_args, INGRESS)

    def test_real_bind_context_restores_readonly_after_body_failure(self):
        report = json.loads((self.stage / 'report.json').read_bytes())
        with patch.object(c, 'bind_path', return_value=self.bind), patch.object(c, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'synthetic'):
                with WRITABLE_BIND(report):
                    raise RuntimeError('synthetic')
        self.assertEqual([call.args[0][-3] for call in run.call_args_list],
                         ['remount,bind,relatime,rw', 'remount,bind,relatime,ro'])

    def test_real_bind_context_rejects_wrong_opened_inode_and_restores_readonly(self):
        report = json.loads((self.stage / 'report.json').read_bytes())
        with patch.object(c, 'bind_path', return_value=self.source), patch.object(c, 'run') as run:
            with self.assertRaises(ValueError):
                with WRITABLE_BIND(report):
                    self.fail('wrong inode accepted')
        self.assertEqual(run.call_args_list[-1].args[0][-3], 'remount,bind,relatime,ro')

    def test_sigterm_during_apply_rolls_back_and_restores_the_handler(self):
        import signal
        self.args.apply = True
        before = signal.getsignal(signal.SIGTERM)
        original = self.command
        def terminate(operation, raw, adapter=True):
            if operation == 'reload' and adapter:
                signal.raise_signal(signal.SIGTERM)
            return original(operation, raw, adapter)
        with patch.object(c, 'caddy', side_effect=terminate):
            result = c.execute(self.args, INGRESS)
        self.assertEqual((result['result'], result['error_type'], result['restored']), ('FAILED', 'Terminated', True))
        self.assertEqual(self.source.read_bytes(), b'source')
        self.assertEqual(self.bind.read_bytes(), b'older bound inode')
        self.assertIs(signal.getsignal(signal.SIGTERM), before)

    def test_stage_that_changes_nothing_is_not_applied_again(self):
        self.args.apply = True
        with patch.object(c, 'render', return_value=(b'source', self.new)):
            result = c.stage(SimpleNamespace(phase='open', output=self.root / 'noop'), INGRESS)
            self.assertTrue(result['is_unchanged'])
            args = SimpleNamespace(stage=self.root / 'noop', report_sha256=result['report_sha256'], apply=True)
            self.assertEqual(c.execute(args, INGRESS)['result'], 'ALREADY_IN_STATE')
        self.assertEqual(self.source.read_bytes(), b'source')
        self.assertNotIn('reload', [operation for operation, _ in self.commands])

    def test_failure_is_reported_on_stderr_with_exit_status_one(self):
        argv = ['caddy_ingress.py', '--release-lock-base64', 'e30=', '--release-lock-sha256', 'a' * 64, 'stage', '--phase', 'fence']
        with patch('sys.argv', argv), patch.object(os, 'geteuid', return_value=0), patch.object(os, 'umask'), \
                patch('sys.stderr', new=io.StringIO()) as stderr, patch('sys.stdout', new=io.StringIO()) as stdout:
            self.assertEqual(c.main(), 1)
        self.assertIn('hash mismatch', stderr.getvalue())
        self.assertEqual(stdout.getvalue(), '')


if __name__ == '__main__':
    unittest.main()
