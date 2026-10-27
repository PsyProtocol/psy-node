"""Synthetic config/transaction checks. No Docker, SSH, mounts or real reloads."""
import copy
from contextlib import contextmanager
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import caddy_r3 as c

WRITABLE_BIND = c.writable_bind

def fixture():
    text, routes = '', []
    for host in (*c.FAUCETS, c.PRIVATE_HOST, 'services.psy-protocol.xyz',
                 'nostr.psy-protocol.xyz', 'rpc-eth-stg.psy-protocol.xyz'):
        upstream = c.OLD if host in c.FAUCETS else '10.148.0.38:3001'
        prefix = '    log {\n        output stderr\n    }\n    @not_private_claimable not path /private\n' if host == c.PRIVATE_HOST else ''
        text += host + ' {\n' + prefix + '    reverse_proxy ' + upstream + ' {\n    }\n}\n\n'
        routes.append({'match': [{'host': [host]}], 'terminal': True,
                       'handle': c.subroute([{'handle': [{'handler': 'reverse_proxy', 'upstreams': [{'dial': upstream}]}]}])})
    base = {'apps': {'http': {'servers': {'srv0': {'listen': [':443'], 'routes': routes}}}},
            'logging': {'logs': {'fixture': {'writer': {'output': 'stderr'}}}}}
    live = copy.deepcopy(base)
    c.routes(live)[:0] = [c.top_gate(True), c.top_gate(False)]
    prepared = copy.deepcopy(base)
    for host in (*c.FAUCETS, c.PRIVATE_HOST):
        route = c.site(prepared, host)
        if host in c.FAUCETS:
            route['handle'][0]['routes'][0]['handle'][0]['upstreams'] = [{'dial': c.NEW}]
        # Native Caddy adapt structure, checked separately against the actual host.
        route['handle'] = [{'handler': 'subroute', 'routes': [{'handle': [{
            'handler': 'subroute', 'routes': [c.nested_gate(host == c.PRIVATE_HOST, host),
                                             {'handle': route['handle']}]}]}]}]
    opened = copy.deepcopy(prepared)
    for host in c.FAUCETS:
        route = c.site(opened, host)
        route['handle'] = route['handle'][0]['routes'][0]['handle'][0]['routes'][1]['handle']
    return text.encode(), base, live, prepared, opened


class RenderTests(unittest.TestCase):
    def setUp(self):
        self.raw, self.base, self.live, self.prepared, self.opened = fixture()

    def prepare(self):
        with patch.object(c, 'adapt', side_effect=[self.base, self.prepared]):
            return c.render(self.raw, self.live, 'prepare')

    def test_prepare_keeps_both_fences_and_only_two_new_upstreams(self):
        raw, config = self.prepare()
        self.assertEqual(raw.count(c.NEW.encode()), 2)
        self.assertNotIn(c.OLD.encode(), raw)
        self.assertEqual(raw.count(b'# BEGIN psy-r3-fence'), 3)
        self.assertIn(b'    log {\n        output stderr\n    }', raw)
        for host in ('nostr.psy-protocol.xyz', 'rpc-eth-stg.psy-protocol.xyz'):
            self.assertEqual(c.site(config, host), c.site(self.base, host))

    def test_open_removes_only_faucet_fences_keeps_private_and_upstream(self):
        prepared_raw, _ = self.prepare()
        with patch.object(c, 'adapt', side_effect=[self.prepared, self.opened]):
            opened_raw, config = c.render(prepared_raw, self.prepared, 'open')
        self.assertEqual(opened_raw.count(b'# BEGIN psy-r3-fence'), 1)
        self.assertEqual(opened_raw.count(c.NEW.encode()), 2)
        self.assertEqual(c.site(config, c.PRIVATE_HOST), c.site(self.prepared, c.PRIVATE_HOST))
        for host in c.FAUCETS:
            self.assertEqual(c.block(opened_raw.decode(), host)[2],
                             c.block(self.raw.decode(), host)[2].replace(c.OLD, c.NEW))

    def test_extra_runtime_change_or_missing_gate_refused(self):
        for kind in ('other', 'missing', 'private-path', 'status'):
            bad = copy.deepcopy(self.live)
            if kind == 'other':
                bad['logging']['logs']['fixture']['writer']['output'] = 'file'
            elif kind == 'missing':
                c.routes(bad).pop(1)
            elif kind == 'private-path':
                c.routes(bad)[0]['match'][0]['path'].append('/api/*')
            else:
                c.routes(bad)[0]['handle'][0]['status_code'] = 200
            with self.subTest(kind=kind), patch.object(c, 'adapt', return_value=self.base):
                with self.assertRaises(ValueError):
                    c.render(self.raw, bad, 'prepare')

    def test_native_candidate_changes_to_other_routes_or_logging_refused(self):
        for kind in ('logging', 'rpc', 'private'):
            bad = copy.deepcopy(self.prepared)
            if kind == 'logging':
                bad['logging'] = {}
            elif kind == 'rpc':
                c.site(bad, 'rpc-eth-stg.psy-protocol.xyz')['terminal'] = False
            else:
                c.site(bad, c.PRIVATE_HOST)['handle'][0]['routes'][0]['handle'][0]['routes'][0]['match'][0]['path'] = ['/*']
            with self.subTest(kind=kind), patch.object(c, 'adapt', side_effect=[self.base, bad]):
                with self.assertRaises(ValueError):
                    c.render(self.raw, self.live, 'prepare')

    def test_repeated_prepare_and_open_before_prepare_refused(self):
        raw, _ = self.prepare()
        with patch.object(c, 'adapt', return_value=self.prepared):
            with self.assertRaises(ValueError):
                c.render(raw, self.prepared, 'prepare')
        with patch.object(c, 'adapt', return_value=self.base):
            with self.assertRaises(ValueError):
                c.render(self.raw, self.live, 'open')

    def test_group_normalization_preserves_membership_and_other_fields(self):
        a = [{'group': 'group0'}, {'group': 'group0'}, {'group': 'group2'}]
        b = [{'group': 'group8'}, {'group': 'group8'}, {'group': 'group9'}]
        self.assertEqual(c.normalized(a), c.normalized(b))
        b[1]['group'] = 'group9'
        self.assertNotEqual(c.normalized(a), c.normalized(b))
        self.assertNotEqual(c.normalized({'@id': 'keep-me'}), c.normalized({}))

    def private_source(self):
        prepared_raw, _ = self.prepare()
        with patch.object(c, 'adapt', side_effect=[self.prepared, self.opened]):
            opened_raw, _ = c.render(prepared_raw, self.prepared, 'open')
        expected = copy.deepcopy(self.opened)
        c.site(expected, c.PRIVATE_HOST)['handle'] = c.site(self.base, c.PRIVATE_HOST)['handle']
        return opened_raw, expected

    def test_private_open_restores_exact_service_body_and_preserves_everything_else(self):
        raw, expected = self.private_source()
        with patch.object(c, 'PRIVATE_OPEN_SOURCE_SHA256', c.sha(raw)), \
                patch.object(c, 'adapt', side_effect=[self.opened, expected]):
            candidate, config = c.render(raw, self.opened, 'private-open')
        self.assertEqual(candidate, self.raw.replace(c.OLD.encode(), c.NEW.encode()))
        self.assertEqual(c.block(candidate.decode(), c.PRIVATE_HOST)[2], c.block(self.raw.decode(), c.PRIVATE_HOST)[2])
        for route in c.routes(self.opened):
            host = route['match'][0]['host'][0]
            if host != c.PRIVATE_HOST:
                self.assertEqual(c.site(config, host), route)
                self.assertEqual(c.block(candidate.decode(), host)[2], c.block(raw.decode(), host)[2])
        self.assertEqual(config['logging'], self.opened['logging'])
        self.assertNotIn(b'psy-r3-fence', candidate)

    def test_private_open_rejects_unreviewed_source_before_adapt(self):
        raw, _ = self.private_source()
        with patch.object(c, 'PRIVATE_OPEN_SOURCE_SHA256', c.sha(raw)), patch.object(c, 'adapt') as adapt:
            with self.assertRaises(ValueError):
                c.render(raw + b'\n', self.opened, 'private-open')
            adapt.assert_not_called()

    def test_private_open_rejects_matcher_drift_missing_gate_and_runtime_drift(self):
        raw, _ = self.private_source()
        for kind in ('path', 'status', 'missing', 'runtime'):
            bad = copy.deepcopy(self.opened)
            inner = c.site(bad, c.PRIVATE_HOST)['handle'][0]['routes'][0]['handle'][0]['routes']
            if kind == 'path':
                inner[0]['match'][0]['path'] = ['/api/*']
            elif kind == 'status':
                inner[0]['handle'][0]['routes'][0]['handle'][1]['status_code'] = 200
            elif kind == 'missing':
                inner.pop(0)
            else:
                bad['logging'] = {}
            with self.subTest(kind=kind), patch.object(c, 'PRIVATE_OPEN_SOURCE_SHA256', c.sha(raw)), \
                    patch.object(c, 'adapt', return_value=self.opened if kind == 'runtime' else bad):
                with self.assertRaises(ValueError):
                    c.render(raw, bad, 'private-open')

    def test_private_open_rejects_candidate_faucet_alias_nostr_or_logging_changes(self):
        raw, expected = self.private_source()
        for host in (*c.FAUCETS, 'services.psy-protocol.xyz', 'nostr.psy-protocol.xyz', 'rpc-eth-stg.psy-protocol.xyz', None):
            bad = copy.deepcopy(expected)
            if host:
                c.site(bad, host)['terminal'] = False
            else:
                bad['logging'] = {}
            with self.subTest(host=host), patch.object(c, 'PRIVATE_OPEN_SOURCE_SHA256', c.sha(raw)), \
                    patch.object(c, 'adapt', side_effect=[self.opened, bad]):
                with self.assertRaises(ValueError):
                    c.render(raw, self.opened, 'private-open')


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
        self.stage_args = SimpleNamespace(phase='prepare', output=self.stage,
                                         gate_evidence=None, gate_evidence_sha256=None)
        result = c.stage(self.stage_args)
        self.args = SimpleNamespace(stage=self.stage, report_sha256=result['report_sha256'], apply=False, open_confirmed=False)

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
            result = c.execute(self.args)
            remount.assert_not_called()
        self.assertEqual(result['result'], 'CHECKED_NOT_APPLIED')
        self.assertEqual(self.commands, [('validate', True)])
        self.assertEqual(self.source.read_bytes(), b'source')
        self.assertFalse((self.stage / 'apply-attempt').exists())

    def test_apply_preserves_both_inodes_and_keeps_private_originals(self):
        before = self.source.stat().st_ino, self.bind.stat().st_ino
        self.args.apply = True
        self.assertEqual(c.execute(self.args)['result'], 'APPLIED')
        self.assertEqual(before, (self.source.stat().st_ino, self.bind.stat().st_ino))
        self.assertEqual(self.source.read_bytes(), b'candidate')
        self.assertEqual(self.bind.read_bytes(), b'candidate')
        self.assertEqual((self.stage / 'original-bind.Caddyfile').read_bytes(), b'older bound inode')
        self.assertEqual((self.stage / 'report.json').stat().st_mode & 0o777, 0o600)

    def test_reload_failure_restores_exact_three_way_baseline(self):
        self.args.apply = self.fail_reload = True
        result = c.execute(self.args)
        self.assertEqual(result['result'], 'FAILED')
        self.assertTrue(result['restored'])
        self.assertEqual(self.source.read_bytes(), b'source')
        self.assertEqual(self.bind.read_bytes(), b'older bound inode')
        self.assertEqual(self.current, {'old': True})
        self.assertNotIn('sensitive', json.dumps(result))

    def test_drift_not_overwritten_by_rollback(self):
        self.args.apply = self.external_change = True
        result = c.execute(self.args)
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
                    c.execute(self.args)
        self.assertEqual(self.commands, [])

    def test_open_needs_hash_bound_main_evidence_and_apply_confirmation(self):
        self.stage_args.output = self.root / 'open-stage'
        self.stage_args.phase = 'open'
        with self.assertRaises(ValueError):
            c.stage(self.stage_args)
        evidence = self.root / 'gate.json'
        evidence.write_bytes(c.encoded({'action': 'open-r3-faucet', 'approved_by_main': True,
                                       'prepared_caddyfile_sha256': c.sha(b'source'), 'grant_evidence_sha256': 'a' * 64}))
        self.stage_args.gate_evidence = evidence
        self.stage_args.gate_evidence_sha256 = c.sha(evidence.read_bytes())
        report = c.stage(self.stage_args)
        args = SimpleNamespace(stage=self.stage_args.output, report_sha256=report['report_sha256'],
                               apply=True, open_confirmed=False)
        with self.assertRaises(ValueError):
            c.execute(args)
        self.assertEqual(self.commands, [])
        args.open_confirmed = True
        self.assertEqual(c.execute(args)['result'], 'APPLIED')

    def test_stage_is_create_only(self):
        with self.assertRaises(FileExistsError):
            c.stage(self.stage_args)

    def private_approval(self):
        return {'action': 'open-r3-private-claimable', 'approved_by_main': True,
                'prepared_caddyfile_sha256': c.sha(b'source'),
                'ingestion_evidence_sha256': 'b' * 64, 'claim_evidence_sha256': 'c' * 64}

    def stage_private(self, approval):
        evidence = self.root / 'private-approval.json'
        evidence.write_bytes(c.encoded(approval))
        self.stage_args.phase = 'private-open'
        self.stage_args.output = self.root / 'private-stage'
        self.stage_args.gate_evidence = evidence
        self.stage_args.gate_evidence_sha256 = c.sha(evidence.read_bytes())
        return c.stage(self.stage_args)

    def test_private_stage_requires_claim_and_ingestion_not_faucet_grant(self):
        invalid = []
        good = self.private_approval()
        for key, value in (('approved_by_main', False), ('action', 'open-r3-faucet'),
                           ('prepared_caddyfile_sha256', 'd' * 64), ('ingestion_evidence_sha256', 'bad'),
                           ('claim_evidence_sha256', 'c' * 64 + '\n'), ('claim_evidence_sha256', True)):
            invalid.append(dict(good, **{key: value}))
        for key in ('ingestion_evidence_sha256', 'claim_evidence_sha256'):
            missing = dict(good)
            del missing[key]
            missing['grant_evidence_sha256'] = 'a' * 64
            invalid.append(missing)
        invalid.append(dict(good, grant_evidence_sha256='a' * 64))
        with patch.object(c, 'PRIVATE_OPEN_SOURCE_SHA256', c.sha(b'source')):
            for approval in invalid:
                with self.subTest(approval=approval), self.assertRaises(ValueError):
                    self.stage_private(approval)
                self.assertFalse((self.root / 'private-stage').exists())
        self.assertEqual(self.commands, [])

    def test_private_open_requires_its_own_apply_confirmation(self):
        with patch.object(c, 'PRIVATE_OPEN_SOURCE_SHA256', c.sha(b'source')):
            report = self.stage_private(self.private_approval())
            self.assertFalse(report['private_fence_retained'])
            args = SimpleNamespace(stage=self.stage_args.output, report_sha256=report['report_sha256'],
                                   apply=True, open_confirmed=True, private_open_confirmed=False)
            with self.assertRaises(ValueError):
                c.execute(args)
            self.assertEqual(self.commands, [])
            args.private_open_confirmed = True
            self.assertEqual(c.execute(args)['result'], 'APPLIED')

    def test_private_check_revalidates_evidence_action_even_with_rehashed_stage(self):
        with patch.object(c, 'PRIVATE_OPEN_SOURCE_SHA256', c.sha(b'source')):
            self.stage_private(self.private_approval())
            root = self.stage_args.output
            evidence = dict(self.private_approval(), action='open-r3-faucet')
            (root / 'gate-evidence.json').write_bytes(c.encoded(evidence))
            report = json.loads((root / 'report.json').read_bytes())
            report['files']['gate-evidence.json'] = c.sha(c.encoded(evidence))
            (root / 'report.json').write_bytes(c.encoded(report))
            args = SimpleNamespace(stage=root, report_sha256=c.sha(c.encoded(report)), apply=False,
                                   open_confirmed=False, private_open_confirmed=False)
            with self.assertRaises(ValueError):
                c.execute(args)
        self.assertEqual(self.commands, [])

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


if __name__ == '__main__':
    unittest.main()
