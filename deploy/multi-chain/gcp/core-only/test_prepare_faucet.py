"""Offline synthetic-fixture tests; no operator material, network or systemd changes."""
from contextlib import ExitStack
import copy
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import prepare_faucet as faucet
import release_lock
import test_release_lock

ALIAS = "fixture-host"
REAL_SAFE_PARENTS = faucet.safe_parents


def operators_file(count=100, key="synthetic-key"):
    rows = [{"userId": str(index), "address": f"0xaddr{index}", "privateKey": key + str(index),
             "fingerprint": "fp", "signType": "sd"} for index in range(count)]
    return faucet.encode({"faucetContractId": 5, "operators": rows})


class FaucetTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.var_lib = self.root / "var-lib"
        self.var_lib.mkdir()
        self.units = self.root / "units"
        self.units.mkdir()
        self.stack.enter_context(patch.object(faucet, "VAR_LIB", self.var_lib))
        self.stack.enter_context(patch.object(faucet, "UNITS", self.units))
        self.stack.enter_context(patch.object(faucet, "safe_parents"))
        self.binary, self.canonical, self.rpc = (self.root / name for name in ("binary", "canonical", "rpc"))
        self.binary.write_bytes(b"synthetic-binary")
        self.canonical.write_bytes(b"synthetic-canonical")
        self.rpc.write_bytes(json.dumps({"defaultNetwork": "testnet",
                                         "networks": {"testnet": {"magic": "0x1337CF514544CF69"}}}).encode())
        self.operators = self.root / "operators.json"
        self.operators.write_bytes(operators_file())
        self.operators.chmod(0o600)
        self.lock = test_release_lock.build_test_lock()
        self.write_lock()
        self.package = self.root / "package"

    def write_lock(self, **faucet_changes):
        lock = self.lock
        lock["hosts"][ALIAS] = "192.0.2.10"
        lock["binaries"]["psy_user_cli"] = faucet.digest(self.binary.read_bytes())
        lock["inputs"]["canonical_config"] = faucet.digest(self.canonical.read_bytes())
        lock["faucet"].update({"operators_sha256": faucet.digest(self.operators.read_bytes()), **faucet_changes})
        lock["paths"]["faucet"] = {"release": str(self.root / "release"), "config": str(self.root / "custody"),
                                   "state": str(self.var_lib / "faucet-state")}
        lock["tool_sha256"]["prepare_faucet.py"] = faucet.digest(Path(faucet.__file__).read_bytes())
        path = self.root / "release-lock.json"
        path.write_text(json.dumps(lock))
        path.chmod(0o600)
        self.lock_path, self.lock_sha256 = path, faucet.digest(path.read_bytes())
        self.release = faucet.read_release_lock(path, self.lock_sha256)

    def args(self):
        return SimpleNamespace(binary=self.binary, canonical=self.canonical, rpc=self.rpc,
                               rpc_sha256=faucet.digest(self.rpc.read_bytes()), operators=self.operators,
                               host=ALIAS, release_lock=self.lock_path, output=self.package)

    def prepare(self):
        result = faucet.prepare(self.release, self.args())
        return result["manifest_sha256"]

    def read(self, sha, need_operators=True):
        return faucet.read_package(self.release, self.package, sha, need_operators)

    def test_prepare_package_fresh_paths_and_batch_settings_kept(self):
        sha = self.prepare()
        manifest, files = self.read(sha)
        self.assertFalse(manifest["public_switch_allowed"])
        self.assertEqual(manifest["operator_count"], 100)
        unit = files[self.release.unit].decode()
        for value in ("MemoryMax=28G", "MemorySwapMax=0", "Restart=on-failure", "RAYON_NUM_THREADS=4",
                      "PSY_FAUCET_WINDOW_CHECKPOINTS=120", "PSY_FAUCET_REQUIRE_TURNSTILE=0",
                      "MALLOC_CONF=narenas:16", "User=faucet-account", "LoadCredentialEncrypted=operators.json:",
                      "StateDirectory=faucet-state", str(self.release.state),
                      "--release-lock-sha256 " + self.lock_sha256, "--spec-sha256 " + faucet.digest(files["host.json"])):
            self.assertIn(value, unit)
        self.assertNotIn("MemoryHigh=", unit)
        self.assertEqual(stat.S_IMODE(self.package.stat().st_mode), 0o700)
        with self.assertRaises(FileExistsError):
            self.prepare()

    def test_batch_setting_preserved(self):
        # Keys of the live batch10 unit: caps, threads, window and turnstile switch carry over unchanged.
        unit = faucet.unit_text(self.release, "0" * 64).decode()
        live = ("Environment=PSY_NETWORK=testnet", "Environment=RUST_LOG=info,psy_provider=warn",
                "Environment=RAYON_NUM_THREADS=4", "Environment=PSY_FAUCET_REQUIRE_TURNSTILE=0",
                "Environment=PSY_FAUCET_WINDOW_CHECKPOINTS=120", "MemoryMax=28G", "MemorySwapMax=0",
                "Restart=on-failure", "RestartSec=10", "LimitNOFILE=65536", "KillSignal=SIGINT", "TimeoutStopSec=180",
                "Environment=MALLOC_CONF=narenas:16,dirty_decay_ms:1000,muzzy_decay_ms:1000")
        for line in live:
            self.assertIn(line + "\n", unit)

    def test_restart_never_hits_the_start_limit(self):
        # A Realm outage once failed three starts in five minutes and the start limit left the faucet down for hours.
        unit = faucet.unit_text(self.release, "0" * 64).decode()
        for line in ("StartLimitIntervalSec=0", "RestartSteps=5", "RestartMaxDelaySec=300"):
            self.assertIn(line + "\n", unit)
        self.assertNotIn("StartLimitBurst=", unit)

    def test_operator_set_hash_matches_lock(self):
        self.prepare()
        other = self.root / "other-operators.json"
        other.write_bytes(operators_file(key="other-key"))
        other.chmod(0o600)
        args = self.args()
        args.operators, args.output = other, self.root / "package-2"
        with self.assertRaisesRegex(ValueError, "operator set hash differs from the lock"):
            faucet.prepare(self.release, args)
        self.assertFalse(args.output.exists())
        self.operators.write_bytes(operators_file(count=99))
        self.operators.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "operator set hash differs|operator count"):
            faucet.prepare(self.release, dict_args(self.args(), output=self.root / "package-3"))
        pinned = dict(self.lock["faucet"], operators_sha256="")
        self.lock["faucet"] = pinned
        path = self.root / "unpinned.json"
        path.write_text(json.dumps(self.lock))
        path.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "not pinned"):
            faucet.read_release_lock(path, faucet.digest(path.read_bytes()))

    def test_operators_hash_command_prints_hash_and_count_only(self):
        result = faucet.main(["operators-sha256", "--operators", str(self.operators)])
        self.assertEqual(result, {"operators_sha256": self.lock["faucet"]["operators_sha256"], "operators": 100})
        self.assertNotIn("synthetic-key", json.dumps(result))

    def test_lock_writer_stores_the_computed_hash(self):
        lock_path = self.root / "write-release-lock.json"
        lock = copy.deepcopy(self.lock)
        lock["faucet"]["operators_sha256"] = ""
        lock_path.write_text(json.dumps(lock))
        release_lock.write_faucet_operators(lock_path, self.operators)
        self.assertEqual(json.loads(lock_path.read_text())["faucet"]["operators_sha256"],
                         faucet.digest(self.operators.read_bytes()))

    def test_pins_tampering_inventory_and_symlinks_fail(self):
        sha = self.prepare()
        for name in ("psy_user_cli", "host.json", self.release.unit, "prepare_faucet.py", "operators.json"):
            path = self.package / name
            original = path.read_bytes()
            path.write_bytes(original + b"\n")
            with self.assertRaises(ValueError):
                self.read(sha)
            path.write_bytes(original)
        extra = self.package / "unexpected"
        extra.write_bytes(b"synthetic")
        with self.assertRaises(ValueError):
            self.read(sha)
        extra.unlink()
        link = self.root / "link"
        link.symlink_to(self.binary)
        with self.assertRaises(OSError):
            faucet.read_file(link)
        with self.assertRaises(ValueError):
            self.read("0" * 64)

    def test_parent_check_accepts_sticky_shared_directories_only(self):
        shared = self.root / "shared"
        shared.mkdir()
        package = shared / "package"
        package.mkdir()
        shared.chmod(0o1777)
        REAL_SAFE_PARENTS(package, os.getuid())
        shared.chmod(0o777)
        with self.assertRaisesRegex(ValueError, "unsafe parent"):
            REAL_SAFE_PARENTS(package, os.getuid())
        shared.chmod(0o755)

    def test_private_listener_and_exact_spec_only(self):
        for addr in ("0.0.0.0:29998", "8.8.8.8:29998", "127.0.0.1:29998", "192.0.2.10:9999", "192.0.2.11:29998"):
            with self.assertRaises(ValueError):
                faucet.validate_spec(self.release, faucet.encode({"hostname": ALIAS, "listen_addr": addr}))
        with self.assertRaises(ValueError):
            faucet.validate_spec(self.release, faucet.encode({"hostname": "bad\nhost", "listen_addr": "192.0.2.10:29998"}))

    def test_any_active_enabled_pid_or_queued_faucet_unit_rejected(self):
        stopped = {"LoadState": "loaded", "ActiveState": "inactive", "MainPID": "0",
                   "UnitFileState": "disabled", "Job": ""}
        with patch.object(Path, "iterdir", return_value=[]), \
                patch.object(faucet, "faucet_unit_names", return_value=["psy-faucet-old.service", self.release.unit]):
            with patch.object(faucet, "unit_state", return_value=stopped):
                faucet.check_stopped(self.release)
            for field, value in (("ActiveState", "active"), ("MainPID", "123"),
                                 ("UnitFileState", "enabled"), ("Job", "1")):
                with patch.object(faucet, "unit_state", return_value=dict(stopped, **{field: value})):
                    with self.assertRaises(ValueError):
                        faucet.check_stopped(self.release)

    def test_unit_listing_covers_old_faucet_names_and_the_new_unit(self):
        listing = SimpleNamespace(returncode=0, stderr="", stdout="psy-faucet-old.service loaded inactive dead x\n")
        with patch.object(faucet.subprocess, "run", return_value=listing) as run:
            names = faucet.faucet_unit_names(self.release)
        self.assertEqual(names, sorted({"psy-faucet-old.service", self.release.unit}))
        self.assertTrue(all("psy-faucet-*" in call.args[0] and "parth-faucet-*" in call.args[0]
                            for call in run.call_args_list))

    def test_wrong_host_rejected_before_anything_is_created(self):
        spec = {"hostname": ALIAS}
        with patch.object(faucet.os, "geteuid", return_value=0), \
                patch.object(faucet.os, "uname", return_value=SimpleNamespace(machine="x86_64")), \
                patch.object(faucet.socket, "gethostname", return_value="other-host"):
            with self.assertRaisesRegex(ValueError, "wrong hostname"):
                faucet.check_host(self.release, spec)

    def activation_args(self, sha):
        return SimpleNamespace(package=self.package, package_sha256=sha, request_sha256="a" * 64,
                               report_path=self.root / "report.json")

    def run_activation(self, sha, *, unit=None):
        """Run activate with the host, systemd and credential calls replaced; returns the recorded commands."""
        account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        calls = []

        def fake_run(*argv, data=None):
            calls.append(argv)
            if argv[:3] == ("systemd-creds", "--name=operators.json", "encrypt"):
                return b"sealed:" + data
            if argv[:3] == ("systemd-creds", "--name=operators.json", "decrypt"):
                return data[len(b"sealed:"):]
            return b""
        real_read = faucet.read_file
        with patch.object(faucet, "check_host", return_value=account), patch.object(faucet, "check_stopped"), \
                patch.object(faucet.os, "chown"), patch.object(faucet.os, "geteuid", return_value=0), \
                patch.object(faucet, "run", side_effect=fake_run), \
                patch.object(faucet, "read_file", side_effect=lambda path, owner=None, private=False: real_read(path, None, private)) as read, \
                patch.object(faucet, "wait_stable", return_value=4242), \
                patch.object(faucet, "running_binary_sha256", return_value=self.release.binary_sha256):
            result = faucet.activate(self.release, self.activation_args(sha))
        return result, calls, read

    def test_bootstrap_does_not_read_previous_custody(self):
        old = self.root / "old-custody"
        old.mkdir()
        (old / "operators.cred").write_bytes(b"previous-release-ciphertext")
        sha = self.prepare()
        result, calls, read = self.run_activation(sha)
        self.assertFalse(hasattr(faucet, "OLD_CUSTODY"))
        touched = {Path(call.args[0]) for call in read.call_args_list}
        self.assertFalse(any(old in path.parents for path in touched))
        self.assertEqual(self.read_sealed(), b"sealed:" + self.operators.read_bytes())
        self.assertEqual(result["pid"], 4242)

    def read_sealed(self):
        return (self.release.custody / "operators.cred").read_bytes()

    def test_activate_seals_deletes_staged_file_then_starts_and_reports(self):
        sha = self.prepare()
        result, calls, _ = self.run_activation(sha)
        self.assertFalse((self.package / "operators.json").exists())
        order = [call[:2] for call in calls if call[0] == "systemctl"]
        self.assertEqual(order, [("systemctl", "daemon-reload"), ("systemctl", "enable")])
        self.assertIn(("systemctl", "enable", "--now", self.release.unit), calls)
        report = json.loads((self.root / "report.json").read_text())
        self.assertEqual(set(report), {"lock_sha256", "request_sha256", "unit", "pid", "binary_sha256",
                                       "operators_sha256"})
        self.assertEqual(report["lock_sha256"], self.lock_sha256)
        self.assertEqual(report["operators_sha256"], self.lock["faucet"]["operators_sha256"])
        self.assertEqual(self.read_sealed().count(b"synthetic-key"), 100)  # sealed by the fake, not written plain
        self.assertFalse(any(b"synthetic-key" in path.read_bytes() for path in self.release.release.iterdir()))

    def test_rerun_of_an_installed_host_does_not_install_again(self):
        sha = self.prepare()
        self.run_activation(sha)
        before = self.read_sealed()
        _, calls, _ = self.run_activation(sha)
        self.assertEqual(self.read_sealed(), before)
        self.assertNotIn(("systemctl", "daemon-reload"), calls)
        self.assertIn(("systemctl", "enable", "--now", self.release.unit), calls)

    def test_partial_installation_is_refused(self):
        sha = self.prepare()
        self.release.custody.mkdir()
        with self.assertRaisesRegex(ValueError, "partial installation"):
            self.run_activation(sha)

    def test_installed_file_that_differs_from_the_package_is_refused(self):
        sha = self.prepare()
        self.run_activation(sha)
        (self.release.release / "canonical.json").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "installed file differs"):
            self.run_activation(sha)

    def test_wrapper_passes_the_in_flight_limit_and_nothing_else_unknown(self):
        self.release.release.mkdir()
        spec = faucet.encode({"hostname": ALIAS, "listen_addr": "192.0.2.10:29998"})
        (self.release.release / "host.json").write_bytes(spec)
        credentials = self.root / "credentials"
        credentials.mkdir()
        (credentials / "operators.json").write_bytes(self.operators.read_bytes())
        environment = {"CREDENTIALS_DIRECTORY": str(credentials), "PSY_NETWORK": "testnet",
                       "PSY_FAUCET_BATCH_MAX_IN_FLIGHT": "2", "UNRELATED": "x"}
        real_read = faucet.read_file
        with patch.dict(os.environ, environment, clear=True), patch.object(faucet.os, "execve") as execve, \
                patch.object(faucet.os, "geteuid", return_value=os.getuid() or 1), \
                patch.object(faucet.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=os.getuid() or 1)), \
                patch.object(faucet.socket, "gethostname", return_value=ALIAS), \
                patch.object(faucet, "read_file", side_effect=lambda path, owner=None, private=False: real_read(path, None, private)):
            faucet.run_faucet(self.release, SimpleNamespace(spec_sha256=faucet.digest(spec)))
        passed = execve.call_args.args[2]
        self.assertEqual(passed["PSY_FAUCET_BATCH_MAX_IN_FLIGHT"], "2")
        self.assertNotIn("UNRELATED", passed)

    def test_credential_failure_leaves_no_release_or_state(self):
        sha = self.prepare()
        manifest, files = self.read(sha)
        with patch.object(faucet, "check_host"), patch.object(faucet, "seal_operators", side_effect=ValueError("fixture")):
            with self.assertRaises(ValueError):
                faucet.install(self.release, manifest, files, sha)
        self.assertFalse(self.release.release.exists())
        self.assertFalse(self.release.state.exists())


def dict_args(args, **changes):
    for name, value in changes.items():
        setattr(args, name, value)
    return args


if __name__ == "__main__":
    unittest.main()
