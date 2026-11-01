import hashlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import test_release_lock

HERE = Path(__file__).resolve().parent
loader = importlib.util.spec_from_file_location("activate_bridge", HERE / "activate_bridge.py")
a = importlib.util.module_from_spec(loader)
loader.loader.exec_module(a)
LOCK = test_release_lock.build_test_lock()
for tool in ("install_guardian.py", "install_relayer.py"):
    LOCK["tool_sha256"][tool] = hashlib.sha256((HERE / tool).read_bytes()).hexdigest()
a.load_helpers(LOCK)


class ActivateTests(unittest.TestCase):
    def setUp(self):
        self.spec = {"hostname": "signer.example", "address": "172.30.0.1", "guardian_id": 1,
                     "service_user": "psy-guardian-1", "l1_documents": {"synthetic": {}},
                     "binary": {"sha256": "a" * 64}, "custody_keystore_sha256": hashlib.sha256(b"cipher").hexdigest()}
        self.guardian = a.g.load_release(LOCK)
        self.network = {"magic": self.guardian.magic, "guardian_initial_member_hashes": ["1", "2", "3"],
                        "guardian_configs": [{"rpc_url": f"http://172.30.0.{i}:9700"} for i in (1, 2, 3)]}
        self.files = {"rpc.json": json.dumps({"networks": {"testnet": self.network}}).encode()}
        self.name = self.guardian.unit_name(1)
        self.release, self.state = self.guardian.releases / "guardian-1", self.guardian.states / "guardian-1"
        self.data = (self.spec, self.files, self.network, self.release, self.state, self.name,
                     ["psy-guardian-1.service", "psy-guardian-previous-1.service"], set(), {"psy-guardian-1.service"},
                     self.guardian)
        self.value = {"Id": self.name, "LoadState": "loaded", "ActiveState": "inactive", "MainPID": "0",
                      "Job": "", "FragmentPath": str(a.g.UNITS / self.name), "DropInPaths": "",
                      "NeedDaemonReload": "no", "UnitFileState": "enabled"}

    def test_context_uses_pinned_planners_and_requires_documents_and_root(self):
        previous = ["psy-guardian-1.service", "psy-guardian-previous-2.service", self.guardian.unit_name(1)]
        with patch.object(a.os, "geteuid", return_value=0), \
                patch.object(a.g, "guardian_unit_names", return_value=previous), \
                patch.object(a.g, "load_plan", return_value=(self.spec, self.files, self.network, 9700)) as plan:
            data = a.context("guardian", Path("/spec"), "a" * 64, LOCK)
            plan.assert_called_once_with(Path("/spec"), "a" * 64, self.guardian)
            self.assertEqual(data[5], self.name)
            self.assertNotIn(self.name, data[6])
            self.assertEqual(data[6], ["psy-guardian-1.service", "psy-guardian-previous-2.service"])
            self.assertEqual(data[7], set())
            self.spec["l1_documents"] = {}
            with self.assertRaisesRegex(ValueError, "documents pending"):
                a.context("guardian", Path("/spec"), "a" * 64, LOCK)
        with patch.object(a.os, "geteuid", return_value=1000), self.assertRaisesRegex(ValueError, "root"):
            a.context("relayer", Path("/spec"), "a" * 64, LOCK)
        self.spec["l1_documents"] = {"synthetic": {}}
        with patch.object(a.os, "geteuid", return_value=0), \
                patch.object(a.r, "relayer_unit_names", return_value=["psy-core-relayer-previous.service", LOCK["units"]["relayer"]]), \
                patch.object(a.r, "load_plan", return_value=(self.spec, self.files, 9700)):
            data = a.context("relayer", Path("/spec"), "a" * 64, LOCK)
            self.assertEqual(data[5], LOCK["units"]["relayer"])
            self.assertEqual(data[6], ["psy-core-relayer-previous.service"])
            self.assertEqual(data[7], set())
            self.assertEqual(data[3], Path(LOCK["paths"]["relayer"]["release"]))

    def test_activate_bridge_loads_siblings_by_lock_hash(self):
        for tool, name in (("install_guardian.py", "install_guardian"), ("install_relayer.py", "install_relayer")):
            lock = json.loads(json.dumps(LOCK))
            lock["tool_sha256"][tool] = "0" * 64
            with self.subTest(tool=tool), patch.object(Path, "read_bytes", return_value=(HERE / tool).read_bytes()):
                with self.assertRaisesRegex(SystemExit, "hash mismatch"):
                    a.load_helpers(lock)
        with patch.object(Path, "read_bytes", return_value=b'raise RuntimeError("DO_NOT_EXECUTE")'), self.assertRaises(SystemExit):
            a.helper("install_relayer", LOCK["tool_sha256"]["install_relayer.py"])
        self.assertIs(a.r.g, a.g)

    def test_release_lock_is_hash_checked_before_it_is_parsed(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "lock.json"
            path.write_text("{}")
            with self.assertRaisesRegex(SystemExit, "release lock hash mismatch"):
                a.read_release_lock(path, "0" * 64)
            self.assertEqual(a.read_release_lock(path, hashlib.sha256(b"{}").hexdigest()), {})

    def test_preflight_checks_installed_bytes_identity_and_unit_source(self):
        public = {"node_source": self.guardian.key_source, "guardian_id": 1, "public_key_hash": "1"}
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
                result = a.activate("guardian", Path("/spec"), "a" * 64, LOCK, apply)
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
                a.activate("relayer", Path("/spec"), "a" * 64, LOCK, True)
            command.assert_not_called()

    def test_relayer_start_refused_until_guardians_and_services_ready(self):
        ready = {"schema_version": 3, "user_id": 524288, "network_magic": int(self.guardian.magic, 16),
                 "runtime_initialized": True, "halted": False}
        services = {"status": "ready", "details": {"database": {"status": "healthy"}, "cache": {"status": "healthy"}}}
        self.files["daemon.toml"] = b"synthetic"
        for broken, reason in (("guardian", "Guardian not ready"), ("services", "Services")):
            guardians = {**ready, "halted": True} if broken == "guardian" else ready
            backend = {**services, "status": "starting"} if broken == "services" else services
            with self.subTest(broken=broken), patch.object(a, "context", return_value=self.data), \
                    patch.object(a, "preflight", return_value=False), \
                    patch.object(a.r, "validate_daemon", return_value={"services_url": "http://172.30.0.10:3001"}), \
                    patch.object(a, "get_json", side_effect=lambda origin, path: guardians if path == "/v1/ready" else backend), \
                    patch.object(a.g, "command") as command:
                with self.assertRaisesRegex(ValueError, reason):
                    a.activate("relayer", Path("/spec"), "a" * 64, LOCK, True)
                command.assert_not_called()

    def test_guardian_readiness_checked_from_relayer_host(self):
        ready = {"schema_version": 3, "user_id": 524288, "network_magic": str(int(self.guardian.magic, 16)),
                 "runtime_initialized": True, "halted": False}
        rpc = json.dumps({"networks": {"testnet": self.network}}).encode()
        asked = []
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "rpc.json"
            path.write_bytes(rpc)
            sha = hashlib.sha256(rpc).hexdigest()
            with patch.object(a, "get_json", side_effect=lambda origin, route: asked.append((origin, route)) or ready):
                self.assertEqual(a.readiness(path, sha), {"role": "guardian-readiness", "guardians_ready": 3})
                self.assertEqual(asked, [(f"http://172.30.0.{i}:9700", "/v1/ready") for i in (1, 2, 3)])
                with self.assertRaisesRegex(ValueError, "hash mismatch"):
                    a.readiness(path, "f" * 64)
            ready["halted"] = True
            with patch.object(a, "get_json", return_value=ready), self.assertRaisesRegex(ValueError, "Guardian not ready"):
                a.readiness(path, sha)

    def test_readiness_schema_magic_account_and_services(self):
        ready = {"schema_version": 3, "user_id": 524288, "network_magic": int(self.guardian.magic, 16), "runtime_initialized": True, "halted": False}
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
                    self.assertEqual(a.activate("guardian", Path("/spec"), "a" * 64, LOCK, True)["pid"], 123)
                else:
                    with self.assertRaises(ValueError):
                        a.activate("guardian", Path("/spec"), "a" * 64, LOCK, True)
                    self.assertEqual(clock[0], 15 if case == "permanent" else 0)
                command.assert_called_once_with(["systemctl", "enable", "--now", self.name])

    def test_live_readiness_magic_numeric_and_decimal_string(self):
        ready = json.loads('{"schema_version":3,"user_id":524288,"network_magic":1384803358401154921,"runtime_initialized":true,"halted":false}')
        services = {"status": "ready", "details": {"database": {"status": "healthy"}, "cache": {"status": "healthy"}}}
        self.files["daemon.toml"] = b"synthetic"
        with patch.object(a.r, "validate_daemon", return_value={"services_url": "http://172.30.0.10:3001"}), \
                patch.object(a, "get_json", side_effect=lambda origin, path: ready if path == "/v1/ready" else services):
            for value in (1384803358401154921, "1384803358401154921"):
                ready["network_magic"] = value
                a.dependencies(self.data)
            for value in (True, False, 1384803358401154921.0, "+1384803358401154921", " 1384803358401154921", "1384803358401154921\n", "0x1337CF514544CF69", "١٣٨٤٨٠٣٣٥٨٤٠١١٥٤٩٢١", "1384803358401154922", None):
                ready["network_magic"] = value
                with self.subTest(value=value), self.assertRaises(ValueError):
                    a.dependencies(self.data)

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
        with tempfile.TemporaryDirectory() as root:
            lock = Path(root) / "lock.json"
            lock.write_text(json.dumps(LOCK))
            common = ["activate_bridge.py", "--release-lock", str(lock), "--release-lock-sha256",
                      hashlib.sha256(lock.read_bytes()).hexdigest()]
            with patch("sys.argv", common + ["--role", "relayer", "--spec", "/spec", "--spec-sha256", "a" * 64]), \
                    patch.object(a, "activate", side_effect=OSError("PRIVATE_SENTINEL")):
                with self.assertRaises(SystemExit) as error:
                    a.main()
            self.assertNotIn("PRIVATE_SENTINEL", str(error.exception))
            self.assertIn("OSError", str(error.exception))
            with patch("sys.argv", common + ["--role", "guardian-readiness", "--spec", "/spec"]), \
                    patch.object(a, "readiness") as readiness, self.assertRaisesRegex(SystemExit, "RPC config and its hash only"):
                a.main()
            readiness.assert_not_called()
            with patch("sys.argv", common[:-1] + ["0" * 64, "--role", "relayer", "--spec", "/s", "--spec-sha256", "a" * 64]), \
                    self.assertRaisesRegex(SystemExit, "release lock hash mismatch"):
                a.main()


if __name__ == "__main__":
    unittest.main()
