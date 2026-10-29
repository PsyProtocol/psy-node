from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import update_unit as rollout


class PlanTests(unittest.TestCase):
    def fragment(self, role):
        return ('[Service]\nExecStart="' + str(rollout.BASE) + '" "start-realm-' + role +
                '" "--network" "psy-public-testnet" "--proving-backend" "plonky2-poseidon-goldilocks"\n')

    def test_edge_retains_base_as_rollback(self):
        address, old, sha, override, prior = rollout.plan('psy-core-r3-realm-0-v2-edge.service', self.fragment('edge'))
        self.assertEqual((address, old, sha, prior), ('10.148.0.36', rollout.BASE, rollout.BASE_SHA, ''))
        self.assertIn(str(rollout.NEW), override)

    def test_processor_retains_previous_hotfix(self):
        address, old, sha, override, prior = rollout.plan('psy-core-r3-realm-1-v3-processor.service', self.fragment('processor'))
        self.assertEqual((address, old, sha), ('10.148.0.43', rollout.PROCESSOR, rollout.PROCESSOR_SHA))
        self.assertIn(str(rollout.PROCESSOR), prior)
        self.assertIn(str(rollout.NEW), override)

    def test_reject_coordinator(self):
        with self.assertRaises(ValueError):
            rollout.plan('psy-core-r3-coordinator-edge.service', self.fragment('edge'))

    def test_reject_wrong_role(self):
        with self.assertRaises(ValueError):
            rollout.plan('psy-core-r3-realm-0-v1-edge.service', self.fragment('processor'))

    def test_reject_wrong_network(self):
        with self.assertRaises(ValueError):
            rollout.plan('psy-core-r3-realm-0-v1-edge.service', self.fragment('edge').replace('psy-public-testnet', 'localhost'))

    def test_reject_jtmb(self):
        with self.assertRaises(ValueError):
            rollout.plan('psy-core-r3-realm-0-v1-edge.service', self.fragment('edge').replace('plonky2-poseidon-goldilocks', 'jtmb'))


class LifecycleTests(unittest.TestCase):
    def exercise(self, failure):
        role = 'processor' if failure == 'prior-drift' else 'edge'
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory)
            system = root / 'etc/systemd/system'
            system.mkdir(parents=True)
            locks = root / 'run/lock'
            locks.mkdir(parents=True)
            unit = 'psy-core-r3-realm-0-v1-' + role + '.service'
            base, previous_binary, new, candidate = (root / name for name in ('base', 'previous', 'new', 'candidate'))
            base.write_bytes(b'base')
            previous_binary.write_bytes(b'previous')
            candidate.write_bytes(b'new')
            fragment = system / unit
            contents = ('[Service]\nExecStart="' + str(base) + '" "start-realm-' + role +
                        '" "--network" "psy-public-testnet" "--proving-backend" "plonky2-poseidon-goldilocks"\n')
            fragment.write_text(contents)
            dropin = fragment.with_name(unit + '.d') / rollout.DROPIN
            prior = dropin.with_name(rollout.PREVIOUS)
            if role == 'processor':
                prior.parent.mkdir()
                prior.write_text('[Service]\nExecStart=\n' + contents.splitlines()[1].replace(str(base), str(previous_binary)) + '\n')
            def translate_path(*parts):
                value = Path(*parts)
                if str(value).startswith('/etc/systemd/system') or str(value).startswith('/run/lock'):
                    return root / value.relative_to('/')
                return value
            state = {'MainPID': '11', 'ActiveState': 'active', 'FragmentPath': str(fragment),
                     'WorkingDirectory': rollout.WORKING, 'DropInPaths': str(prior) if role == 'processor' else ''}
            calls = []
            starts = 0
            stops = 0
            def run(*args, **kwargs):
                nonlocal starts, stops
                calls.append(args)
                if args[:2] == ('ip', '-j'):
                    address = '10.148.0.37' if role == 'processor' else '10.148.0.36'
                    return json.dumps([{'addr_info': [{'local': address}]}])
                if args[:2] == ('systemctl', 'stop'):
                    stops += 1
                    if failure == 'stop-timeout':
                        raise subprocess.TimeoutExpired(args, 330)
                    state.update(MainPID='0', ActiveState='inactive')
                    if stops == 1 and failure == 'base-drift':
                        fragment.write_text(contents + 'Environment=UNREVIEWED=1\n')
                    if stops == 1 and failure == 'prior-drift':
                        prior.write_text(prior.read_text() + 'Environment=UNREVIEWED=1\n')
                    if stops == 1 and failure == 'extra-dropin':
                        dropin.parent.mkdir(exist_ok=True)
                        (dropin.parent / '90-unreviewed.conf').write_text('[Service]\nEnvironment=UNREVIEWED=1\n')
                if args[:2] == ('systemctl', 'start'):
                    starts += 1
                    if starts == 1 and failure == 'start-failure':
                        raise subprocess.CalledProcessError(1, args)
                    state.update(MainPID='22', ActiveState='active')
                return ''
            def properties(_):
                result = dict(state)
                result['DropInPaths'] = ' '.join(str(path) for path in sorted(dropin.parent.glob('*.conf')))
                return result
            values = {'BASE': base, 'BASE_SHA': hashlib.sha256(b'base').hexdigest(),
                      'PROCESSOR': previous_binary, 'PROCESSOR_SHA': hashlib.sha256(b'previous').hexdigest(),
                      'NEW': new, 'ROOT': root / 'backups', 'Path': translate_path,
                      'properties': properties, 'run': run, 'peers': lambda _: {'other': '1'},
                      'assert_running': lambda *args: dict(state), 'install': lambda *args: None}
            for key, value in values.items():
                stack.enter_context(patch.object(rollout, key, value))
            stack.enter_context(patch.object(rollout.os, 'geteuid', return_value=0))
            stack.enter_context(patch('sys.argv', ['update_unit.py', 'activate', '--unit', unit,
                                               '--candidate', str(candidate), '--sha256', hashlib.sha256(b'new').hexdigest()]))
            wait = stack.enter_context(patch.object(rollout, 'wait_running', return_value=dict(state)))
            with self.assertRaises((ValueError, subprocess.SubprocessError)):
                rollout.main()
            report = json.loads(next((root / 'backups').glob('*/failure.json')).read_text())
            if failure == 'start-failure':
                self.assertEqual(starts, 2)
                self.assertTrue(report['old_binary_restored'])
                self.assertFalse(dropin.exists())
                wait.assert_called_with(unit, base, hashlib.sha256(b'base').hexdigest())
            else:
                self.assertEqual(starts, 0)
                self.assertFalse(report['old_binary_restored'])
                self.assertTrue(report['manual_inspection_required'])
            self.assertFalse(any(args[:2] == ('systemctl', 'start') and args[2] != unit for args in calls))

    def test_base_drift_holds_stopped_without_restart(self):
        self.exercise('base-drift')

    def test_previous_override_drift_holds_stopped_without_restart(self):
        self.exercise('prior-drift')

    def test_failed_start_restores_previous_binary(self):
        self.exercise('start-failure')

    def test_extra_override_holds_stopped_without_restart(self):
        self.exercise('extra-dropin')

    def test_stop_timeout_does_not_start_a_second_process(self):
        self.exercise('stop-timeout')


class IMTProfileTests(unittest.TestCase):
    SHA = '349cdc3d5548e15d9a026f98690df3b3f997fa54edcb636bde8af090752235fe'

    def profile(self, unit, sha=None):
        stack = ExitStack()
        self.addCleanup(stack.close)
        for name in ('PROCESSOR', 'PROCESSOR_SHA', 'NEW', 'DROPIN', 'PREVIOUS', 'ROOT', 'EXTRA_PRIORS'):
            stack.enter_context(patch.object(rollout, name, getattr(rollout, name)))
        directory = stack.enter_context(tempfile.TemporaryDirectory())
        fragment = Path(directory) / unit
        fragment.write_text('[Service]\nExecStart="' + str(rollout.BASE) +
                            '" "start-realm-processor" "--network" "psy-public-testnet" '
                            '"--proving-backend" "plonky2-poseidon-goldilocks"\n')
        rollout.configure_profile('imt-coverage', unit, fragment, sha or self.SHA)
        return fragment

    def test_processor_retains_both_prior_overrides(self):
        unit = 'psy-core-r3-realm-0-v3-processor.service'
        fragment = self.profile(unit)
        address, old, sha, override, prior = rollout.plan(unit, fragment.read_text())
        self.assertEqual(address, '10.148.0.43')
        self.assertEqual(str(old), '/opt/psy-core/hotfixes/realm-pr30-61c1636b/psy_node_cli')
        self.assertEqual(sha, 'aba982032894347c13fd767c1fdebf8427a3d5e85feeee119569131918cb5338')
        self.assertEqual(rollout.PREVIOUS, '80-realm-pr30-20261029.conf')
        self.assertEqual(rollout.DROPIN, '90-realm-imt-20261029.conf')
        self.assertIn(str(rollout.NEW), override)
        self.assertIn(str(old), prior)
        path, contents = next(iter(rollout.EXTRA_PRIORS.items()))
        self.assertEqual(path.name, '70-realm-replay-20261028.conf')
        self.assertIn('/opt/psy-core/hotfixes/realm-sync-5f4f5c90/psy_node_cli', contents)

    def test_reject_edge(self):
        with self.assertRaises(ValueError):
            self.profile('psy-core-r3-realm-0-v1-edge.service')

    def test_reject_other_artifact(self):
        with self.assertRaises(ValueError):
            self.profile('psy-core-r3-realm-1-v2-processor.service', 'a' * 64)

    def test_earlier_override_drift_is_detected(self):
        unit = 'psy-core-r3-realm-0-v3-processor.service'
        fragment = self.profile(unit)
        _, _, _, _, prior = rollout.plan(unit, fragment.read_text())
        earlier = next(iter(rollout.EXTRA_PRIORS))
        earlier.parent.mkdir()
        earlier.write_text('unreviewed earlier override')
        previous = earlier.with_name(rollout.PREVIOUS)
        previous.write_text(prior)
        with patch.object(rollout, 'digest', return_value=rollout.PROCESSOR_SHA):
            with self.assertRaisesRegex(ValueError, 'earlier override changed'):
                rollout.ensure_original_configuration(fragment, fragment.read_text(), previous, prior,
                                                       rollout.PROCESSOR, rollout.PROCESSOR_SHA)


class MetadataProfileTests(unittest.TestCase):
    SHA = 'c69e077fd4a51dc6678eb845a1615f9b2254ad0dfe80bd3f2544d1c0674c5633'

    def profile(self, unit, previous_imt=False, sha=None):
        stack = ExitStack()
        self.addCleanup(stack.close)
        for name in ('PROCESSOR', 'PROCESSOR_SHA', 'NEW', 'DROPIN', 'PREVIOUS', 'ROOT', 'EXTRA_PRIORS'):
            stack.enter_context(patch.object(rollout, name, getattr(rollout, name)))
        directory = stack.enter_context(tempfile.TemporaryDirectory())
        fragment = Path(directory) / unit
        fragment.write_text('[Service]\nExecStart="' + str(rollout.BASE) +
                            '" "start-realm-processor" "--network" "psy-public-testnet" '
                            '"--proving-backend" "plonky2-poseidon-goldilocks"\n')
        if previous_imt:
            dropin = fragment.with_name(unit + '.d') / '90-realm-imt-20261029.conf'
            dropin.parent.mkdir()
            dropin.write_text('[Service]\nExecStart=\n' + fragment.read_text().splitlines()[1].replace(
                str(rollout.BASE), '/opt/psy-core/hotfixes/realm-imt-67634280/psy_node_cli') + '\n')
        rollout.configure_profile('imt-metadata', unit, fragment, sha or self.SHA)
        return fragment

    def test_pr30_parent_and_earlier_override_are_retained(self):
        unit = 'psy-core-r3-realm-0-v1-processor.service'
        fragment = self.profile(unit)
        _, old, sha, override, prior = rollout.plan(unit, fragment.read_text())
        self.assertEqual(str(old), '/opt/psy-core/hotfixes/realm-pr30-61c1636b/psy_node_cli')
        self.assertEqual(sha, 'aba982032894347c13fd767c1fdebf8427a3d5e85feeee119569131918cb5338')
        self.assertEqual(rollout.PREVIOUS, '80-realm-pr30-20261029.conf')
        self.assertEqual(rollout.DROPIN, '95-realm-imt-metadata-20261029.conf')
        self.assertEqual({path.name for path in rollout.EXTRA_PRIORS}, {'70-realm-replay-20261028.conf'})
        self.assertIn(str(old), prior)
        self.assertIn('/opt/psy-core/hotfixes/realm-imt-metadata-ea07ffad/psy_node_cli', override)

    def test_imt_parent_and_both_earlier_overrides_are_retained(self):
        unit = 'psy-core-r3-realm-0-v3-processor.service'
        fragment = self.profile(unit, previous_imt=True)
        _, old, sha, _, prior = rollout.plan(unit, fragment.read_text())
        self.assertEqual(str(old), '/opt/psy-core/hotfixes/realm-imt-67634280/psy_node_cli')
        self.assertEqual(sha, IMTProfileTests.SHA)
        self.assertEqual(rollout.PREVIOUS, '90-realm-imt-20261029.conf')
        self.assertEqual({path.name for path in rollout.EXTRA_PRIORS},
                         {'70-realm-replay-20261028.conf', '80-realm-pr30-20261029.conf'})
        previous = fragment.with_name(unit + '.d') / rollout.PREVIOUS
        self.assertEqual(previous.read_text(), prior)

    def test_reject_edge(self):
        with self.assertRaises(ValueError):
            self.profile('psy-core-r3-realm-1-v1-edge.service')

    def test_reject_other_artifact(self):
        with self.assertRaises(ValueError):
            self.profile('psy-core-r3-realm-1-v1-processor.service', sha='b' * 64)

    def test_imt_override_drift_blocks_rollback(self):
        unit = 'psy-core-r3-realm-0-v2-processor.service'
        fragment = self.profile(unit, previous_imt=True)
        _, old, sha, _, prior = rollout.plan(unit, fragment.read_text())
        for path, contents in rollout.EXTRA_PRIORS.items():
            path.write_text(contents)
        previous = fragment.with_name(unit + '.d') / rollout.PREVIOUS
        previous.write_text(prior + 'Environment=UNREVIEWED=1\n')
        with patch.object(rollout, 'digest', return_value=sha):
            with self.assertRaisesRegex(ValueError, 'previous override changed'):
                rollout.ensure_original_configuration(fragment, fragment.read_text(), previous, prior, old, sha)


if __name__ == '__main__':
    unittest.main()
