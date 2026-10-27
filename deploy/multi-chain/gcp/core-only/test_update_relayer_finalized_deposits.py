import importlib.util
from pathlib import Path
import unittest
import tempfile

SPEC=importlib.util.spec_from_file_location('update_relayer_finalized_deposits',Path(__file__).with_name('update_relayer_finalized_deposits.py'))
update=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(update)

class UpdateTests(unittest.TestCase):
    def manifest(self):
        return dict(schema_version=1, network='testnet', base_source_commit=update.BASE_SOURCE,
                    source_commit='ab'*20, binary_sha256='cd'*32,
                    preserve=['genesis','config','keys','database','proofs','other-services'])

    def test_valid_manifest(self):
        update.validate_manifest(self.manifest())

    def test_wrong_cohort_and_paths_rejected(self):
        for field,value in [('network','localhost'),('base_source_commit','00'*20),('source_commit','../evil'),('source_commit',update.BASE_SOURCE),('binary_sha256','bad'),('preserve',[])]:
            with self.subTest(field=field,value=value),self.assertRaises(AssertionError):
                update.validate_manifest({**self.manifest(),field:value})

    def test_wrapper_retains_r3_inputs_and_changes_only_executable(self):
        original=Path(__file__).with_name('relayer_exec.py').read_bytes()
        target=Path('/opt/psy-core-relayer/hotfixes')/('ab'*20)
        generated=update.render_wrapper(original,target).decode()
        self.assertIn(str(update.BASE),generated)
        self.assertIn(str(target/'psy_relayer_cli'),generated)
        self.assertIn('CREDENTIALS_DIRECTORY',generated)
        self.assertIn('PSY_CORE_RELAYER_L1_PASSWORD',generated)
        self.assertIn('release / "canonical.json"',generated)
        self.assertIn('release / "home"',generated)
        compile(generated,'relayer_exec.py','exec')

    def test_changed_base_wrapper_rejected(self):
        with self.assertRaises(AssertionError):
            update.render_wrapper(b'changed',Path('/opt/test'))

    def test_rollback_accepts_failed_or_stopped_owned_release(self):
        for state in ('inactive','failed'):
            update.validate_switch_state('rollback',dict(ActiveState=state,MainPID='0'),True)
        for state in ('activating','deactivating'):
            with self.assertRaises(AssertionError):
                update.validate_switch_state('rollback',dict(ActiveState=state,MainPID='0'),True)
        with self.assertRaises(AssertionError):
            update.validate_switch_state('rollback',dict(ActiveState='failed',MainPID='0'),False)

    def test_activate_requires_running_service(self):
        for state in ('inactive','failed'):
            with self.assertRaises(AssertionError):
                update.validate_switch_state('activate',dict(ActiveState=state,MainPID='0'),False)
        update.validate_switch_state('activate',dict(ActiveState='active',MainPID='12'),False)

    def test_symlink_package_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            file=Path(root)/'file';file.write_bytes(b'data');file.chmod(0o600)
            link=Path(root)/'link';link.symlink_to(file)
            with self.assertRaises(OSError):
                update.read_regular(link)

    def test_installed_files_require_root_ownership(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        import stat
        with tempfile.TemporaryDirectory() as root:
            file=Path(root)/'file';file.write_bytes(b'data');file.chmod(0o600)
            with patch.object(update.os,'fstat',return_value=SimpleNamespace(st_mode=stat.S_IFREG|0o644,st_uid=1234)):
                with self.assertRaises(AssertionError):
                    update.read_regular(file,root_owned=True)

if __name__=='__main__':
    unittest.main()
