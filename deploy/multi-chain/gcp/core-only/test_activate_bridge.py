import hashlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
loader = importlib.util.spec_from_file_location("activate_bridge", HERE / "activate_bridge.py")
a = importlib.util.module_from_spec(loader)
loader.loader.exec_module(a)


class ActivateTests(unittest.TestCase):
    def setUp(self):
        self.spec = {"hostname": "signer.example", "address": "172.30.0.1", "guardian_id": 1,
                     "service_user": "psy-guardian-1", "l1_documents": {"synthetic": {}},
                     "binary": {"sha256": "a" * 64}, "custody_keystore_sha256": hashlib.sha256(b"cipher").hexdigest()}
        self.network = {"magic": a.g.MAGIC, "guardian_initial_member_hashes": ["1", "2", "3"],
                        "guardian_configs": [{"rpc_url": f"http://172.30.0.{i}:9700"} for i in (1, 2, 3)]}
        self.files = {"rpc.json": json.dumps({"networks": {"testnet": self.network}}).encode()}
        self.name = "psy-guardian-r3-1.service"
        self.release, self.state = a.g.RELEASES / "guardian-1", a.g.STATES / "guardian-1"
        self.data = (self.spec, self.files, self.network, self.release, self.state, self.name,
                     ["psy-guardian-1.service", "psy-guardian-r2-1.service"], {"psy-guardian-r2-1.service"}, {"psy-guardian-1.service"})
        self.value = {"Id": self.name, "LoadState": "loaded", "ActiveState": "inactive", "MainPID": "0",
                      "Job": "", "FragmentPath": str(a.g.UNITS / self.name), "DropInPaths": "",
                      "NeedDaemonReload": "no", "UnitFileState": "enabled"}

    def test_context_uses_pinned_planners_and_requires_documents_and_root(self):
        with patch.object(a.os, "geteuid", return_value=0), \
                patch.object(a.g, "load_plan", return_value=(self.spec, self.files, self.network, 9700)):
            data = a.context("guardian", Path("/spec"), "a" * 64)
            self.assertEqual(data[5], self.name)
            self.assertNotIn(self.name, data[6])
            self.assertIn("psy-guardian-r3-2.service", data[6])
            self.assertEqual(data[7], {"psy-guardian-r2-1.service"})
            self.spec["l1_documents"] = {}
            with self.assertRaisesRegex(ValueError, "documents pending"):
                a.context("guardian", Path("/spec"), "a" * 64)
        with patch.object(a.os, "geteuid", return_value=1000), self.assertRaisesRegex(ValueError, "root"):
            a.context("relayer", Path("/spec"), "a" * 64)
        self.spec["l1_documents"] = {"synthetic": {}}
        with patch.object(a.os, "geteuid", return_value=0), \
                patch.object(a.r, "load_plan", return_value=(self.spec, self.files, 9700)):
            data = a.context("relayer", Path("/spec"), "a" * 64)
            self.assertEqual(data[5], "psy-core-relayer-r3.service")
            self.assertEqual(data[7], {"psy-core-relayer-r2.service"})

    def test_preflight_checks_installed_bytes_identity_and_unit_source(self):
        public = {"node_source": a.g.KEY_SOURCE, "guardian_id": 1, "public_key_hash": "1"}
        def read(path, **kwargs):
            if path.name == "rpc.json":
                return self.files["rpc.json"]
            if path.name.endswith(".service"):
                return b"unit"
            if path.name.endswith(".keystore.json"):
                return b"cipher"
            if path.name == "public.json":
                return json.dumps(public).encode()
            if path.name.endswith(".cred"):
                return b"encrypted"
            raise AssertionError(path)
        with patch.object(a.socket, "gethostname", return_value=self.spec["hostname"]), \
                patch.object(a.os, "uname", return_value=SimpleNamespace(machine="x86_64")), \
                patch.object(a.g, "command", return_value=json.dumps([{"addr_info": [{"local": self.spec["address"]}]}])), \
                patch.object(a.g, "inactive_units") as old, patch.object(a.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=123, pw_gid=123)), \
                patch.object(a.g, "trusted_directory"), patch.object(a.g, "read", side_effect=read), \
                patch.object(Path, "stat", return_value=SimpleNamespace(st_uid=0, st_mode=0o644)), \
                patch.object(a.g, "unit", return_value=b"unit"), patch.object(a, "show", side_effect=lambda _: dict(self.value)):
            self.assertFalse(a.preflight("guardian", self.data))
            old.assert_called_with(self.data[6], self.data[7], self.data[8])
            for field, value in (("DropInPaths", "/unsafe"), ("NeedDaemonReload", "yes"), ("Job", "12"), ("ActiveState", "failed")):
                previous = self.value[field]
                self.value[field] = value
                with self.subTest(field=field), self.assertRaises(ValueError):
                    a.preflight("guardian", self.data)
                self.value[field] = previous
            with patch.object(a.g, "read", return_value=b"changed"), self.assertRaisesRegex(ValueError, "artifact mismatch"):
                a.preflight("guardian", self.data)
            with patch.object(a.g, "inactive_units", side_effect=ValueError("old signer active")), self.assertRaises(ValueError):
                a.preflight("guardian", self.data)

    def test_read_only_and_already_active_never_restart(self):
        for apply, active in ((False, False), (True, True)):
            with patch.object(a, "context", return_value=self.data), patch.object(a, "preflight", return_value=active), \
                    patch.object(a, "process", return_value=123), patch.object(a, "show", return_value=self.value), \
                    patch.object(a.g, "command") as command, patch.object(a, "dependencies") as deps:
                result = a.activate("guardian", Path("/spec"), "a" * 64, apply)
                self.assertFalse(result["checkpoint_progress_verified"] or result["l1_finalization_verified"])
                if apply:
                    command.assert_called_once_with(["systemctl", "enable", self.name])
                else:
                    command.assert_not_called()
                deps.assert_not_called()

    def test_relayer_requires_dependencies_before_any_enable(self):
        with patch.object(a, "context", return_value=self.data), patch.object(a, "preflight", return_value=False), \
                patch.object(a, "dependencies", side_effect=ValueError("not ready")), patch.object(a.g, "command") as command:
            with self.assertRaisesRegex(ValueError, "not ready"):
                a.activate("relayer", Path("/spec"), "a" * 64, True)
            command.assert_not_called()

    def test_readiness_schema_magic_account_and_services(self):
        ready = {"schema_version": 3, "user_id": 524288, "network_magic": int(a.g.MAGIC, 16), "runtime_initialized": True, "halted": False}
        services = {"status": "ready", "details": {"database": {"status": "healthy"}, "cache": {"status": "healthy"}}}
        self.files["daemon.toml"] = b"synthetic"
        with patch.object(a.r, "validate_daemon", return_value={"services_url": "http://172.30.0.10:3001"}), \
                patch.object(a, "get_json", side_effect=lambda origin, path: ready if path == "/v1/ready" else services):
            a.dependencies(self.data)
            for field, bad in (("schema_version", 2), ("user_id", 1), ("network_magic", 0), ("runtime_initialized", False), ("halted", True)):
                before = ready[field]
                ready[field] = bad
                with self.subTest(field=field), self.assertRaises(ValueError):
                    a.dependencies(self.data)
                ready[field] = before
            services["details"]["database"]["status"] = "unhealthy"
            with self.assertRaisesRegex(ValueError, "Services"):
                a.dependencies(self.data)

    def test_new_start_exec_grace_is_bounded_and_failed_is_terminal(self):
        for case in ("transition", "permanent", "failed"):
            clock, attempts = [0.0], [0]
            def process(*args):
                attempts[0] += 1
                if case != "transition" or attempts[0] == 1:
                    raise ValueError("unexpected signer executable")
                return 123
            with self.subTest(case=case), patch.object(a, "context", return_value=self.data), \
                    patch.object(a, "preflight", return_value=False), patch.object(a, "process", side_effect=process), \
                    patch.object(a, "show", return_value={**self.value, "ActiveState": "failed" if case == "failed" else "active"}), \
                    patch.object(a.g, "command") as command, patch.object(a.time, "monotonic", side_effect=lambda: clock[0]), \
                    patch.object(a.time, "sleep", side_effect=lambda n: clock.__setitem__(0, clock[0] + n)):
                if case == "transition":
                    self.assertEqual(a.activate("guardian", Path("/spec"), "a" * 64, True)["pid"], 123)
                else:
                    with self.assertRaises(ValueError):
                        a.activate("guardian", Path("/spec"), "a" * 64, True)
                    self.assertEqual(clock[0], 15 if case == "permanent" else 0)
                command.assert_called_once_with(["systemctl", "enable", "--now", self.name])

    def test_process_checks_exact_path_hash_and_pid(self):
        value = {"ActiveState": "active", "MainPID": "123"}
        binary = self.release / "psy_relayer_cli"
        digest = hashlib.sha256(b"binary").hexdigest()
        with patch.object(a, "show", return_value=value), patch.object(a.os, "readlink", return_value=str(binary)), \
                patch.object(Path, "open", side_effect=lambda *args, **kwargs: io.BytesIO(b"binary")):
            self.assertEqual(a.process(self.name, binary, digest), 123)
            with self.assertRaises(ValueError):
                a.process(self.name, binary, "0" * 64)
            with patch.object(a.os, "readlink", return_value="/old/runtime"), self.assertRaises(ValueError):
                a.process(self.name, binary, digest)
            with patch.object(a, "show", side_effect=[value, {"ActiveState": "active", "MainPID": "124"}]), self.assertRaises(ValueError):
                a.process(self.name, binary, digest)

    def test_helper_hash_checked_before_exec_and_cli_hides_os_error(self):
        with patch.object(Path, "read_bytes", return_value=b'raise RuntimeError("DO_NOT_EXECUTE")'), self.assertRaises(SystemExit):
            a.helper("install_guardian", "0" * 64)
        with patch("sys.argv", ["activate_bridge.py", "--role", "relayer", "--spec", "/spec", "--spec-sha256", "a" * 64]), \
                patch.object(a, "activate", side_effect=OSError("PRIVATE_SENTINEL")):
            with self.assertRaises(SystemExit) as error:
                a.main()
        self.assertNotIn("PRIVATE_SENTINEL", str(error.exception))
        self.assertIn("OSError", str(error.exception))


if __name__ == "__main__":
    unittest.main()
