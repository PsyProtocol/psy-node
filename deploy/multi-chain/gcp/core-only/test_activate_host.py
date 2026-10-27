import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("activate_host", HERE / "activate_host.py")
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


class ActivateTests(unittest.TestCase):
    def setUp(self):
        self.host = "gcp-cp-ce"
        self.units = a.h.host_inventory(self.host)[0]
        self.manifest = {"host": self.host, "private_ip": a.h.HOSTS[self.host],
                         "files": {"bin/psy_node_cli": "a" * 64}}
        self.calls = []
        self.active = set()
        self.listed = ""
        self.jobs = ""
        self.bad_ip = False
        self.override = False

    def show(self, name):
        return {"Id": name, "LoadState": "loaded", "ActiveState": "active" if name in self.active else "inactive",
                "MainPID": "123" if name in self.active else "0", "UnitFileState": "enabled",
                "FragmentPath": str(a.h.UNITS / name), "DropInPaths": "/unexpected" if self.override else "",
                "NeedDaemonReload": "no"}

    def command(self, argv):
        self.calls.append(argv)
        if argv[0] == "ip":
            return json.dumps([{"addr_info": [{"local": "127.0.0.1" if self.bad_ip else self.manifest["private_ip"]}]}])
        if argv[1] == "list-units":
            return self.listed
        if argv[1] == "list-jobs":
            return self.jobs
        if argv[1] == "enable":
            self.active.add(argv[-1])
            return ""
        raise AssertionError(argv)

    def run_activation(self, phase="processors", apply=True):
        with patch.object(a.os, "geteuid", return_value=0), \
                patch.object(a.h, "read_package", return_value=(self.manifest, {})), \
                patch.object(a, "installed"), patch.object(a, "show", side_effect=self.show), \
                patch.object(a.h, "command", side_effect=self.command), \
                patch.object(a, "process", side_effect=lambda n, digest: {"unit": n, "pid": 123, "exe_sha256": digest}):
            return a.activate(Path("/unused-private-package"), phase, apply)

    def test_exact_role_selection_for_all_six_hosts(self):
        for host in a.h.HOSTS:
            self.manifest.update(host=host, private_ip=a.h.HOSTS[host])
            units = a.h.host_inventory(host)[0]
            for phase in ("processors", "edges"):
                expected = sorted(n for n in units if n.endswith("processor.service") == (phase == "processors"))
                self.calls.clear()
                self.active.clear()
                if not expected:
                    with self.assertRaisesRegex(ValueError, "no units"):
                        self.run_activation(phase)
                    continue
                result = self.run_activation(phase)
                self.assertEqual(result["units"], expected)
                self.assertEqual([c for c in self.calls if c[1] == "enable"],
                                 [["systemctl", "enable", "--now", n] for n in expected])
                self.assertFalse(result["checkpoint_progress_verified"] or result["deployment_ready"])

    def test_check_only_does_not_enable_or_start(self):
        self.assertFalse(self.run_activation(apply=False)["started"])
        self.assertFalse(any(c[1] == "enable" for c in self.calls))

    def test_repeat_apply_only_enables_existing_same_executable(self):
        first = self.run_activation()
        self.calls.clear()
        result = self.run_activation()
        self.assertTrue(result["processes"][0]["already_active"])
        self.assertIn(["systemctl", "enable", first["units"][0]], self.calls)
        self.assertFalse(any("--now" in c or "restart" in c for c in self.calls))

    def test_old_running_queued_wrong_host_and_dropin_block_before_writes(self):
        for case in ("old", "queued", "ip", "dropin"):
            self.calls.clear()
            self.active = {"psy-core-r2-coordinator-processor.service"} if case == "old" else set()
            self.listed = "psy-core-r2-coordinator-processor.service loaded active running\n" if case == "old" else ""
            self.jobs = "12 psy-core-r2-coordinator-processor.service start waiting" if case == "queued" else ""
            self.bad_ip, self.override = case == "ip", case == "dropin"
            with self.subTest(case=case), self.assertRaises(ValueError):
                self.run_activation()
            self.assertFalse(any(c[1] == "enable" for c in self.calls))

    def test_installed_files_must_exist_match_bytes_and_permissions(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "config.json"
            path.write_bytes(b"approved")
            path.chmod(0o644)
            files = {path: (b"approved", 0o644, os.getuid(), os.getgid())}
            with patch.object(a.h, "get_runtime_user", return_value=(123, 123)), \
                    patch.object(a.h, "build_paths", return_value=(files, {})):
                a.installed({})
                path.write_bytes(b"changed")
                with self.assertRaises(ValueError):
                    a.installed({})
                path.write_bytes(b"approved")
                path.chmod(0o666)
                with self.assertRaises(ValueError):
                    a.installed({})
                path.unlink()
                with self.assertRaises(FileNotFoundError):
                    a.installed({})

    def test_proc_hash_path_and_pid_are_checked(self):
        name = sorted(self.units)[0]
        self.active.add(name)
        digest = a.hashlib.sha256(b"binary").hexdigest()
        with patch.object(a, "show", side_effect=self.show), \
                patch.object(a.os, "readlink", return_value=str(a.h.RELEASE / "bin/psy_node_cli")), \
                patch.object(Path, "open", side_effect=lambda *args, **kwargs: io.BytesIO(b"binary")):
            self.assertEqual(a.process(name, digest)["pid"], 123)
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                a.process(name, "0" * 64)
            with patch.object(a.os, "readlink", return_value="/old/binary"), self.assertRaises(ValueError):
                a.process(name, digest)
            with patch.object(a, "show", side_effect=[self.show(name), {"MainPID": "124", "ActiveState": "active"}]), self.assertRaises(ValueError):
                a.process(name, digest)

    def test_cli_reports_safe_require_errors_but_not_other_exception_contents(self):
        for error, detail in ((a.h.InstallError("target IP mismatch"), "target IP mismatch"),
                              (OSError("PRIVATE_PAYLOAD_SENTINEL"), "OSError"),
                              (ValueError("PRIVATE_PAYLOAD_SENTINEL"), "ValueError")):
            output = io.StringIO()
            with self.subTest(error=type(error).__name__), \
                    patch("sys.argv", ["activate_host.py", "--package", "/unused", "--phase", "processors"]), \
                    patch.object(a, "activate", side_effect=error), patch("sys.stdout", output):
                with self.assertRaises(SystemExit) as caught:
                    a.main()
            self.assertIn(detail, str(caught.exception))
            self.assertIn("no rollback attempted; inspect", str(caught.exception))
            self.assertNotIn("PRIVATE_PAYLOAD_SENTINEL", str(caught.exception) + output.getvalue())
            self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
