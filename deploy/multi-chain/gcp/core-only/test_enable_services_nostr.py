from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import enable_services_nostr as tool
import install_services


class NostrEnableTests(unittest.TestCase):
    def baseline(self):
        config = tool.encode({'nostr': {'enabled': False, 'lookback_seconds': 0,
                                       'relay_url': tool.RELAY_URL}, 'unchanged': {'value': 7}})
        manifest = tool.encode({'group': 'services', 'input_manifest_sha256': 'retained-input',
                               'files': {'services.json': tool.sha(config),
                                         'units/' + tool.UNIT: tool.UNIT_SHA,
                                         'psy-services': 'unchanged-binary'}})
        return config, manifest

    def new_files(self):
        config, manifest = self.baseline()
        with patch.multiple(tool, OLD_CONFIG=tool.sha(config), OLD_MANIFEST=tool.sha(manifest)):
            new_config, new_manifest = tool.transition(config, manifest)
        return config, manifest, new_config, new_manifest

    def test_only_two_fields_and_one_inventory_entry_change(self):
        config, manifest, updated, sealed = self.new_files()
        old, new = json.loads(config), json.loads(updated)
        self.assertEqual(new['nostr'], {'enabled': True, 'lookback_seconds': 172800,
                                       'relay_url': tool.RELAY_URL})
        new['nostr'] = old['nostr']
        self.assertEqual(new, old)
        old, new = json.loads(manifest), json.loads(sealed)
        transition = new.pop('configuration_transition')
        self.assertEqual(transition['previous_manifest_sha256'], tool.sha(manifest))
        self.assertEqual(new['files'].pop('services.json'), tool.sha(updated))
        old['files'].pop('services.json')
        self.assertEqual(new, old)

    def test_changed_baseline_and_already_enabled_refused(self):
        config, manifest = self.baseline()
        with self.assertRaisesRegex(ValueError, 'frozen'):
            tool.transition(config, manifest)
        altered = json.loads(config)
        for value in [True, 0]:
            altered['nostr']['enabled'] = value
            raw = tool.encode(altered)
            with patch.multiple(tool, OLD_CONFIG=tool.sha(raw), OLD_MANIFEST=tool.sha(manifest)):
                with self.assertRaisesRegex(ValueError, 'baseline'):
                    tool.transition(raw, manifest)

    def evidence(self):
        return {'observed_at_unix': 1000, 'host': '10.148.0.29',
                'container_id': tool.RELAY_ID, 'image': tool.RELAY_IMAGE,
                'config_sha256': tool.RELAY_CONFIG,
                'database': str(tool.RELAY_ROOT / 'data/nostr.db'),
                'event_count': 0, 'relay_url': tool.RELAY_URL}

    def read_evidence(self, value, now=1020):
        raw = tool.encode(value)
        path = Mock()
        path.stat.return_value = SimpleNamespace(st_mode=0o100600, st_uid=0)
        path.read_bytes.return_value = raw
        with patch.object(tool.time, 'time', return_value=now):
            return tool.read_evidence(Mock(), path, tool.sha(raw))

    def test_empty_recent_relay_evidence_accepted(self):
        self.assertEqual(json.loads(self.read_evidence(self.evidence())), self.evidence())

    def test_stale_future_or_nonempty_evidence_refused(self):
        for now in [999, 1121]:
            with self.assertRaisesRegex(ValueError, 'stale|future'):
                self.read_evidence(self.evidence(), now)
        for count in [1, False, '0']:
            value = self.evidence(); value['event_count'] = count
            with self.assertRaisesRegex(ValueError, 'identity|empty'):
                self.read_evidence(value)

    def test_foreign_relay_and_url_refused(self):
        for key in ['container_id', 'image', 'database', 'relay_url', 'config_sha256']:
            value = self.evidence(); value[key] = 'foreign'
            with self.assertRaisesRegex(ValueError, 'identity'):
                self.read_evidence(value)

    def test_observer_opens_existing_database_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'data').mkdir()
            (root / 'config.toml').write_bytes(b'public config')
            dbpath = root / 'data/nostr.db'
            with closing(sqlite3.connect(dbpath)) as db:
                db.execute('CREATE TABLE event(id INTEGER)')
                db.commit()
            before = dbpath.read_bytes()
            with patch.multiple(tool, RELAY_ROOT=root, RELAY_CONFIG=tool.sha(b'public config')), \
                    patch.object(tool.os, 'geteuid', return_value=0), \
                    patch.object(tool.subprocess, 'check_output', return_value='10.148.0.29'), \
                    patch.object(tool, 'relay_container', return_value={'State': {'Pid': 123}}):
                value = tool.observe_relay()
            self.assertEqual(value['event_count'], 0)
            self.assertEqual(dbpath.read_bytes(), before)

    def fixture(self, root):
        config, manifest, new_config, new_manifest = self.new_files()
        (root / 'services.json').write_bytes(config)
        (root / 'manifest.json').write_bytes(manifest)
        helper = Mock()
        helper.write_new.side_effect = install_services.write_new
        helper.unit_status.return_value = {'ActiveState': 'inactive', 'MainPID': '0'}
        helper.load_package.return_value = ({'group': 'services'}, {})
        activation = Mock()
        activation.process.return_value = {'pid': 10}
        activation.wait_process.return_value = {'pid': 11}
        values = (helper, activation, {}, {'pid': 10}, tool.encode(self.evidence()),
                  config, manifest, new_config, new_manifest)
        args = SimpleNamespace(apply=False, new_manifest_sha256=tool.sha(new_manifest),
                               relay_evidence=Path('/root/evidence.json'), relay_evidence_sha256='pin')
        return args, values

    def test_check_is_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); args, values = self.fixture(root)
            with patch.object(tool, 'preflight', return_value=values), patch.object(tool.subprocess, 'run') as run:
                result = tool.enable(args)
            self.assertFalse(result['applied'])
            run.assert_not_called()
            values[0].write_new.assert_not_called()

    def test_preflight_reuses_pinned_checks_and_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); args, values = self.fixture(root)
            helper, activation = values[:2]
            helper.load_package.return_value = ({'group': 'services'}, {'credentials': '/etc/private'})
            helper.read_credentials.return_value = {'PSY_JWT_SECRET': 'not-printed'}
            activation.preflight.return_value = [tool.UNIT]
            with patch.multiple(tool, RELEASE=root, BACKUP=root / 'backup', STATE=root / 'absent'), \
                    patch.object(tool.os, 'geteuid', return_value=0), \
                    patch.object(tool, 'load_module', side_effect=[helper, activation]) as load, \
                    patch.object(tool, 'read_evidence', return_value=b'evidence'), \
                    patch.object(tool, 'transition', return_value=values[-2:]), \
                    patch.object(tool.subprocess, 'run') as run:
                tool.preflight(args)
            self.assertEqual(load.call_args_list[0].args, ('install_services', tool.INSTALLER_SHA))
            self.assertEqual(load.call_args_list[1].args, ('activate_services', tool.ACTIVATION_SHA))
            helper.load_package.assert_called_once_with(root, tool.OLD_MANIFEST)
            activation.preflight.assert_called_once()
            self.assertIn('guard', run.call_args.args[0])
            self.assertNotIn('systemctl', run.call_args.args[0])

    def test_existing_cursor_directory_refuses_before_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); args, values = self.fixture(root)
            helper, activation = values[:2]
            helper.load_package.return_value = ({'group': 'services'}, {})
            activation.preflight.return_value = [tool.UNIT]
            with patch.multiple(tool, RELEASE=root, STATE=root), \
                    patch.object(tool.os, 'geteuid', return_value=0), \
                    patch.object(tool, 'load_module', side_effect=[helper, activation]), \
                    patch.object(tool.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'state must not exist'):
                    tool.preflight(args)
            run.assert_not_called()

    def test_apply_requires_checked_new_seal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); args, values = self.fixture(root)
            args.apply = True; args.new_manifest_sha256 = 'wrong'
            with patch.object(tool, 'preflight', return_value=values), patch.object(tool.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'new seal'):
                    tool.enable(args)
            run.assert_not_called()
            values[0].write_new.assert_not_called()

    def test_apply_preserves_history_and_only_restarts_services(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); args, values = self.fixture(root); args.apply = True
            backup = root / 'outside-release-backup'
            with patch.multiple(tool, RELEASE=root, BACKUP=backup, STATE=root / 'missing-state'), \
                    patch.object(tool, 'preflight', return_value=values), \
                    patch.object(tool, 'read_evidence'), patch.object(tool.subprocess, 'run') as run:
                result = tool.enable(args)
            self.assertEqual((backup / 'services.json.before').read_bytes(), values[5])
            self.assertEqual((backup / 'manifest.json.before').read_bytes(), values[6])
            self.assertEqual((root / 'services.json').read_bytes(), values[7])
            self.assertEqual((root / 'manifest.json').read_bytes(), values[8])
            self.assertEqual([c.args[0] for c in run.call_args_list],
                             [['systemctl', 'stop', tool.UNIT], ['systemctl', 'start', tool.UNIT]])
            self.assertTrue(result['applied'])
            self.assertFalse(result['nostr_ingestion_accepted'])

    def test_partial_replace_never_starts_or_rolls_back(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); args, values = self.fixture(root); args.apply = True
            real_replace = tool.replace_file
            def fail_second(helper, path, raw):
                if path.name == 'manifest.json':
                    raise OSError('simulated failure')
                real_replace(helper, path, raw)
            with patch.multiple(tool, RELEASE=root, BACKUP=root / 'backup', STATE=root / 'missing-state'), \
                    patch.object(tool, 'preflight', return_value=values), patch.object(tool, 'read_evidence'), \
                    patch.object(tool, 'replace_file', side_effect=fail_second), \
                    patch.object(tool.subprocess, 'run') as run:
                with self.assertRaises(OSError):
                    tool.enable(args)
            self.assertEqual([c.args[0] for c in run.call_args_list], [['systemctl', 'stop', tool.UNIT]])
            self.assertEqual((root / 'manifest.json').read_bytes(), values[6])
            self.assertTrue((root / 'backup/manifest.json.before').exists())

    def test_process_change_refuses_before_stop(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); args, values = self.fixture(root); args.apply = True
            values[1].process.return_value = {'pid': 99}
            with patch.multiple(tool, RELEASE=root, BACKUP=root / 'backup'), \
                    patch.object(tool, 'preflight', return_value=values), patch.object(tool.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'process changed'):
                    tool.enable(args)
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
