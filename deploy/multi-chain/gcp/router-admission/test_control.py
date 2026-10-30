import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('router_control', Path(__file__).with_name('control.py'))
control = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(control)


class ControlTests(unittest.TestCase):
    def test_early_activation_does_not_stop_relayer_or_create_signing_hold(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(control, 'HERE', Path(directory)), \
                 mock.patch.object(control, 'admin', return_value={'active': False, 'activateReady': False}), \
                 mock.patch.object(control, 'remote') as remote, \
                 mock.patch.object(sys, 'argv', ['control.py', 'activate']):
                with self.assertRaisesRegex(AssertionError, 'Timelock not ready'):
                    control.main()
                remote.assert_not_called()
                self.assertFalse((Path(directory) / 'signing-hold.json').exists())

    def test_unknown_transaction_recovery_keeps_signing_hold_and_does_not_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            hold = Path(directory) / 'signing-hold.json'
            hold.write_text('{}')
            with mock.patch.object(control, 'HERE', Path(directory)), \
                 mock.patch.object(control, 'state', return_value={'ActiveState': 'inactive', 'MainPID': '0'}), \
                 mock.patch.object(control, 'admin', side_effect=RuntimeError('unknown receipt')), \
                 mock.patch.object(control, 'remote') as remote, \
                 mock.patch.object(sys, 'argv', ['control.py', 'recover']):
                with self.assertRaisesRegex(RuntimeError, 'unknown receipt'):
                    control.main()
                remote.assert_not_called()
                self.assertTrue(hold.exists())


if __name__ == '__main__':
    unittest.main()
