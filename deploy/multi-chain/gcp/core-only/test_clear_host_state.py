"""clear_host_state tests: real deletes inside temporary directories, host commands faked."""
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import clear_host_state as tool
import test_release_lock

HOST = "gcp-test-host"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def completed(stdout="", returncode=0):
    return subprocess.CompletedProcess([], returncode, stdout, "")


class FakeSystem:
    """Stands in for systemctl and docker; records every call."""

    def __init__(self, active=(), containers=(), files=(), enabled=()):
        self.active, self.containers, self.calls = set(active), set(containers), []
        self.files, self.enabled, self.reload_code = set(files), set(enabled), 0

    def __call__(self, argv, timeout=120):
        self.calls.append(list(argv))
        tool_name, verb = argv[0].rsplit("/", 1)[-1], argv[1]
        if tool_name == "systemctl" and verb == "list-units":
            return completed("".join(f"{unit} loaded active running x\n" for unit in sorted(self.active)))
        if tool_name == "systemctl" and verb == "list-unit-files":
            return completed("".join(f"{unit} enabled enabled\n" for unit in sorted(self.files | self.enabled | self.active)))
        if tool_name == "systemctl" and verb == "disable":
            unit = argv[-1]
            if unit not in self.files | self.enabled | self.active:
                return completed("", 1)
            self.active.discard(unit)
            self.enabled.discard(unit)
            return completed()
        if tool_name == "systemctl" and verb == "is-enabled":
            return completed("enabled\n" if argv[-1] in self.enabled else "disabled\n", 0 if argv[-1] in self.enabled else 1)
        if tool_name == "systemctl" and verb == "stop":
            self.active -= set(argv[3:])
        if tool_name == "systemctl" and verb == "daemon-reload":
            return completed("", self.reload_code)
        if tool_name == "docker" and verb == "ps":
            return completed("".join(f"{name}\n" for name in sorted(self.containers)))
        if tool_name == "docker" and verb == "rm":
            self.containers.discard(argv[-1])
        return completed()


DEFAULT_CLEARABLE = list(tool.CLEARABLE)


class ClearHostStateTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.lock = test_release_lock.build_test_lock()
        self.lock_raw = json.dumps(self.lock).encode()
        patcher = patch.object(tool, "CLEARABLE", [re.compile(re.escape(str(self.root)) + r"/(old|data)/.+|"
                                                              + re.escape(str(self.root)) + r"/old")])
        patcher.start()
        self.addCleanup(patcher.stop)
        self.system = FakeSystem()
        self.keep = self.root / "keep"
        self.keep.mkdir()
        (self.keep / "signer.key").write_bytes(b"secret-bytes")
        self.retained = [self.keep]
        (self.root / "old").mkdir()
        (self.root / "data").mkdir()

    def retained_document(self, secret=(), infrastructure=()):
        paths = [{"host": HOST, "path": str(path), "kind": "secret"} for path in secret]
        paths += [{"host": HOST, "path": str(path), "kind": "infrastructure"} for path in infrastructure]
        return json.dumps({"paths": paths}).encode()

    def run_tool(self, clear, *, apply=False, allow=(), stop=(), keep_units=(), containers=(), secret=None,
                 infrastructure=(), mounts=(), retained_raw=None, extra=()):
        secret = [self.keep] if secret is None else secret
        retained_raw = retained_raw or self.retained_document(secret, infrastructure)
        argv = ["--host", HOST, "--release-lock", "inline:" + self.lock_raw.decode(),
                "--release-lock-sha256", sha(self.lock_raw), "--retained-paths", "inline:" + retained_raw.decode(),
                "--retained-paths-sha256", sha(retained_raw), "--clear-paths", json.dumps([str(p) for p in clear]),
                "--clear-allow", json.dumps([str(p) for p in allow]), "--stop-units", json.dumps(list(stop)),
                "--keep-units", json.dumps(list(keep_units)), "--containers", json.dumps(list(containers))]
        if apply:
            argv.append("--apply")
        argv += list(extra)
        out = io.StringIO()
        with redirect_stdout(out):
            code = tool.main(argv, run=self.system, read_mounts=lambda: list(mounts))
        return code, json.loads(out.getvalue())

    def make(self, relative, content=b"x"):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def test_clear_removes_listed_path_and_keeps_its_parent(self):
        target = self.make("old/release/a.txt").parent
        sibling = self.make("old/other/b.txt")
        code, report = self.run_tool([target], apply=True)
        self.assertEqual(code, 0, report)
        self.assertFalse(target.exists())
        self.assertTrue(sibling.exists() and (self.root / "old").is_dir())
        self.assertEqual(report["cleared"], [str(target)])

    def test_clear_refuses_retained_path(self):
        code, report = self.run_tool([self.keep], apply=True, secret=[self.keep])
        self.assertEqual(code, 2)
        self.assertTrue(any("retained" in reason for reason in report["refused"]), report)
        self.assertTrue((self.keep / "signer.key").exists())

    def test_clear_refuses_parent_of_retained_path(self):
        parent = self.root / "old"
        inner = self.make("old/keep/signer.key").parent
        code, report = self.run_tool([parent], apply=True, secret=[inner])
        self.assertEqual(code, 2)
        self.assertTrue((inner / "signer.key").exists())
        self.assertTrue(any("retained" in reason for reason in report["refused"]), report)

    def test_clear_refuses_symlink_into_retained_path(self):
        link = self.root / "old" / "link"
        link.symlink_to(self.keep)
        code, report = self.run_tool([link], apply=True)
        self.assertEqual(code, 2)
        self.assertTrue(any("symlink" in reason for reason in report["refused"]), report)
        self.assertTrue(link.is_symlink() and (self.keep / "signer.key").exists())

    def test_clear_refuses_target_reached_through_a_symlinked_parent(self):
        (self.root / "old" / "inner").mkdir()
        alias = self.root / "data" / "alias"
        alias.symlink_to(self.root / "old" / "inner")
        self.make("old/inner/file.txt")
        code, report = self.run_tool([alias / "file.txt"], apply=True)
        self.assertEqual(code, 2)
        self.assertTrue(any("symlink" in reason for reason in report["refused"]), report)
        self.assertTrue((self.root / "old" / "inner" / "file.txt").exists())

    def test_clear_never_follows_a_symlink_inside_a_target(self):
        target = self.make("old/tree/file.txt").parent
        outside = self.root / "elsewhere"
        outside.mkdir()
        (outside / "survivor.txt").write_text("x")
        (target / "dirlink").symlink_to(outside)
        code, report = self.run_tool([target], apply=True)
        self.assertEqual(code, 0, report)
        self.assertFalse(target.exists())
        self.assertTrue((outside / "survivor.txt").exists())

    def test_clear_refuses_path_outside_allowlist(self):
        with patch.object(tool, "CLEARABLE", DEFAULT_CLEARABLE):
            for path in ("/etc/passwd", "/home/ubuntu/x", "/var/lib/parth", "/", "/etc/systemd/system",
                         "/var/lib/psy", "/opt"):
                with self.subTest(path=path):
                    code, report = self.run_tool([path], secret=[])
                    self.assertEqual(code, 2)
                    self.assertTrue(any("clearable" in reason for reason in report["refused"]), report)

    def test_default_allowlist_accepts_the_known_shapes(self):
        for path in ("/etc/systemd/system/psy-x.service", "/etc/psy-core/core-1/config.json", "/opt/psy-bridge-reader",
                     "/opt/psy-core/releases/r1", "/opt/nostr-relay/data", "/var/lib/parth/scylla",
                     "/var/lib/parth-realm0-edge", "/var/lib/psy-core/r1"):
            with self.subTest(path=path):
                self.assertTrue(any(p.fullmatch(path) for p in DEFAULT_CLEARABLE))

    def test_clear_refuses_a_path_of_the_new_release(self):
        new = self.lock["paths"]["core"]["state"]
        with patch.object(tool, "CLEARABLE", [re.compile(".*")]):
            code, report = self.run_tool([new], secret=[])
        self.assertEqual(code, 2)
        self.assertTrue(any("new release" in reason for reason in report["refused"]), report)

    def test_clear_refuses_the_bridge_reader_paths_of_the_new_release(self):
        reader = self.lock["bridge_reader"]
        for path in (reader["release"], reader["config"], str(Path(reader["client_token_file"]).parent), "/opt/psy-bridge-reader"):
            with self.subTest(path=path), patch.object(tool, "CLEARABLE", [re.compile(".*")]):
                code, report = self.run_tool([path], secret=[])
                self.assertEqual(code, 2)
                self.assertTrue(any("new release" in reason for reason in report["refused"]), report)

    def test_scan_refuses_the_whole_host_on_a_nested_operators_file(self):
        first = self.make("old/a/plain.txt").parent
        second = self.make("old/b/deep/er/operators.json", b"private").parent.parent.parent
        code, report = self.run_tool([first, second], apply=True)
        self.assertEqual(code, 2)
        self.assertTrue(any("operators.json" in reason for reason in report["refused"]), report)
        self.assertTrue((first / "plain.txt").exists(), "an unrelated target must not be cleared either")
        self.assertTrue((second / "deep/er/operators.json").exists())
        self.assertNotIn("private", json.dumps(report))

    def test_scan_matches_every_key_like_name(self):
        for name in ("keystore", "mnemonic.txt", "wallet.dat", "x.pem", "node.key", "api-keys", "db-password",
                     "jwt.json", "l1-password.cred", "credential.secret", "Operator.JSON", "passphrase"):
            with self.subTest(name=name):
                target = self.make(f"old/t/{name}").parent
                code, report = self.run_tool([target])
                self.assertEqual(code, 2, name)
                self.assertTrue(any("key-like" in reason for reason in report["refused"]))

    def test_scan_allows_an_explicitly_allowed_path_only(self):
        hit = self.make("old/t/old-cohort-groth16.key")
        target = hit.parent
        self.make("old/t/operators.json")
        code, report = self.run_tool([target], allow=[hit])
        self.assertEqual(code, 2, "the second key-like file is not allowed")
        (target / "operators.json").unlink()
        code, report = self.run_tool([target], allow=[hit], apply=True)
        self.assertEqual(code, 0, report)
        self.assertFalse(target.exists())

    def test_allow_entry_must_sit_inside_a_clear_target(self):
        target = self.make("old/t/plain.txt").parent
        code, report = self.run_tool([target], allow=[self.root / "data" / "x.key"])
        self.assertEqual(code, 2)
        self.assertIn("strictly inside", report["error"])

    def test_clear_refuses_a_mount_point_at_or_below_a_target(self):
        target = self.make("old/mounted/file.txt").parent
        for mount in (target, target / "nested"):
            with self.subTest(mount=str(mount)):
                code, report = self.run_tool([target], apply=True, mounts=[str(mount)])
                self.assertEqual(code, 2)
                self.assertTrue(any("mount point" in reason for reason in report["refused"]), report)
        self.assertTrue(target.exists())

    def test_entries_that_vanish_during_the_scan_are_not_a_refusal(self):
        target = self.make("old/live/a/file.txt").parent.parent
        real = os.scandir

        def vanishing(path):
            if str(path).endswith("/a"):
                raise FileNotFoundError(2, "gone")
            return real(path)

        with patch.object(tool.os, "scandir", vanishing):
            code, report = self.run_tool([target])
        self.assertEqual(code, 0, report)

    def test_a_mount_point_above_the_target_is_fine(self):
        target = self.make("old/inside/file.txt").parent
        code, report = self.run_tool([target], apply=True, mounts=[str(self.root)])
        self.assertEqual(code, 0, report)

    def test_dry_run_changes_nothing_and_reports_the_plan(self):
        target = self.make("old/t/file.txt").parent
        code, report = self.run_tool([target, self.root / "old" / "gone"])
        self.assertEqual(code, 0)
        self.assertTrue(target.exists())
        self.assertEqual(report["cleared"], [str(target)])
        self.assertEqual(report["absent"], [str(self.root / "old" / "gone")])
        self.assertFalse(report["applied"])
        self.assertEqual(self.system.calls, [self.system.calls[0]], "only the unit listing may run")

    def test_retained_secret_hashes_equal_before_and_after(self):
        (self.keep / "sub").mkdir()
        (self.keep / "sub" / "b.key").write_bytes(b"more")
        target = self.make("old/t/file.txt").parent
        code, report = self.run_tool([target], apply=True, secret=[self.keep / "signer.key", self.keep / "sub"])
        self.assertEqual(code, 0, report)
        by_path = {item["path"]: item for item in report["retained"]}
        self.assertEqual(by_path[str(self.keep / "signer.key")]["sha256"], sha(b"secret-bytes"))
        for item in report["retained"]:
            self.assertEqual(item["sha256"], item["sha256_after"])
        self.assertEqual(by_path[str(self.keep / "sub")]["kind"], "directory")
        self.assertTrue(report["retained_unchanged"])
        self.assertNotIn("secret-bytes", json.dumps(report))

    def test_listing_hash_sees_mtime_and_stops_at_depth_three(self):
        directory = self.keep / "sub"
        deep = directory / "a" / "b" / "c" / "d"
        deep.mkdir(parents=True)
        (directory / "k").write_bytes(b"aaaa")
        first = tool.listing_hash(str(directory))
        os.utime(directory / "k", ns=(1, 1))
        self.assertNotEqual(tool.listing_hash(str(directory)), first)
        settled = tool.listing_hash(str(directory))
        (deep / "late.txt").write_bytes(b"x")
        self.assertEqual(tool.listing_hash(str(directory)), settled, "a change below depth 3 is not listed")
        (directory / "a" / "b" / "new.txt").write_bytes(b"x")
        self.assertNotEqual(tool.listing_hash(str(directory)), settled)

    def test_infrastructure_paths_are_checked_for_existence_only(self):
        node = self.root / "node-data"
        node.mkdir()
        (node / "chain.db").write_bytes(b"a")
        target = self.make("old/t/file.txt").parent
        code, report = self.run_tool([target], apply=True, infrastructure=[node, self.root / "absent-node"])
        self.assertEqual(code, 0, report)
        by_path = {item["path"]: item for item in report["retained"]}
        self.assertEqual(by_path[str(node)]["kind"], "directory")
        self.assertIsNone(by_path[str(node)]["sha256"])
        self.assertEqual(by_path[str(self.root / "absent-node")]["kind"], "missing")

    def test_an_infrastructure_path_that_disappears_fails_the_run(self):
        node = self.root / "node-data"
        node.mkdir()
        target = self.make("old/t/file.txt").parent
        original = tool.delete_tree

        def delete_and_lose(path):
            original(path)
            node.rmdir()

        with patch.object(tool, "delete_tree", delete_and_lose):
            code, report = self.run_tool([target], apply=True, infrastructure=[node])
        self.assertNotEqual(code, 0)
        self.assertFalse(report["retained_unchanged"])

    def test_report_carries_the_request_digest_and_lock_hash(self):
        target = self.make("old/t/file.txt").parent
        code, report = self.run_tool([target])
        retained_raw = self.retained_document([self.keep])
        plan = {"clear": [str(target)], "allow": [], "stop": [], "keep": [], "containers": []}
        self.assertEqual(report["request_sha256"], tool.request_digest(HOST, plan, sha(retained_raw), sha(self.lock_raw)))
        self.assertEqual(report["lock_sha256"], sha(self.lock_raw))
        other = tool.request_digest(HOST, {**plan, "clear": [str(target) + "x"]}, sha(retained_raw), sha(self.lock_raw))
        self.assertNotEqual(report["request_sha256"], other)

    def test_directory_listing_hash_uses_names_and_sizes_not_contents(self):
        directory = self.keep / "sub"
        directory.mkdir()
        (directory / "k").write_bytes(b"aaaa")
        first = tool.listing_hash(str(directory))
        (directory / "k").write_bytes(b"bbbb")
        os.utime(directory / "k", ns=(1, 1))
        first = tool.listing_hash(str(directory))
        (directory / "k").write_bytes(b"cccc")
        os.utime(directory / "k", ns=(1, 1))
        self.assertEqual(tool.listing_hash(str(directory)), first)
        (directory / "k").write_bytes(b"bbbbb")
        self.assertNotEqual(tool.listing_hash(str(directory)), first)

    def test_a_changed_retained_secret_fails_the_run(self):
        target = self.make("old/t/file.txt").parent
        original = tool.delete_tree

        def delete_and_damage(path):
            original(path)
            (self.keep / "signer.key").write_bytes(b"tampered")

        with patch.object(tool, "delete_tree", delete_and_damage):
            code, report = self.run_tool([target], apply=True)
        self.assertNotEqual(code, 0)
        self.assertFalse(report["retained_unchanged"])
        self.assertIn("retained secret changed", report["error"])

    def test_missing_retained_path_is_reported_as_missing(self):
        code, report = self.run_tool([], secret=[self.root / "absent"])
        self.assertEqual(report["retained"][0]["kind"], "missing")

    def disables(self):
        return [call for call in self.system.calls if call[1] == "disable"]

    def test_stop_uses_only_listed_units(self):
        self.system.active = {"psy-old.service", "psy-other.service", "unrelated.service"}
        code, report = self.run_tool([], apply=True, stop=["psy-old.service"], keep_units=["psy-other.service"])
        self.assertEqual(code, 0, report)
        self.assertEqual(self.disables(), [["/usr/bin/systemctl", "disable", "--now", "--", "psy-old.service"]])
        self.assertEqual(self.system.active, {"psy-other.service", "unrelated.service"})

    def test_stop_never_touches_retained_units(self):
        self.system.active = {"psy-forward.service", "psy-old.service"}
        code, report = self.run_tool([], apply=True, stop=["psy-old.service"], keep_units=["psy-forward.service"])
        self.assertEqual(code, 0)
        self.assertIn("psy-forward.service", self.system.active)
        code, report = self.run_tool([], stop=["psy-forward.service"], keep_units=["psy-forward.service"])
        self.assertEqual(code, 2)
        self.assertIn("both stopped and kept", report["error"])

    def test_unlisted_business_unit_is_reported(self):
        self.system.active = {"psy-old.service", "parth-surprise.service", "ssh.service"}
        code, report = self.run_tool([], stop=["psy-old.service"])
        self.assertEqual(report["unlisted_active"], ["parth-surprise.service"])
        self.assertEqual(report["active_listed"], ["psy-old.service"])

    def test_an_unlisted_active_unit_blocks_a_clear_but_not_a_stop(self):
        self.system.active = {"psy-old.service", "parth-surprise.service"}
        target = self.make("old/t/file.txt").parent
        code, report = self.run_tool([target], apply=True, stop=["psy-old.service"])
        self.assertEqual(code, 2)
        self.assertTrue(any("parth-surprise.service" in reason for reason in report["refused"]), report)
        self.assertTrue(target.exists() and "psy-old.service" in self.system.active)
        code, report = self.run_tool([], apply=True, stop=["psy-old.service"])
        self.assertEqual(code, 0)
        self.assertEqual(report["unlisted_active"], ["parth-surprise.service"])

    def test_a_refused_dry_run_still_lists_what_exists_and_what_is_absent(self):
        present = self.make("old/t/operators.json").parent
        code, report = self.run_tool([present, self.root / "old" / "gone"])
        self.assertEqual(code, 2)
        self.assertEqual(report["cleared"], [str(present)])
        self.assertEqual(report["absent"], [str(self.root / "old" / "gone")])
        self.assertTrue(present.exists())

    def test_exit_zero_with_report_still_reports_the_refusal(self):
        code, report = self.run_tool(["/etc/passwd"], extra=["--exit-zero-with-report"], secret=[])
        self.assertEqual(code, 0)
        self.assertTrue(report["refused"] and report["error"])

    def test_stopping_a_stopped_unit_is_a_no_op(self):
        code, report = self.run_tool([], apply=True, stop=["psy-old.service"])
        self.assertEqual(code, 0)
        self.assertEqual(report["stopped"], [])
        self.assertFalse(self.disables(), "a unit that does not exist is skipped")

    def test_unit_that_stays_active_fails_the_run(self):
        self.system.active = {"psy-stubborn.service"}
        original = self.system.__call__

        def refuse_stop(argv, timeout=120):
            if argv[1] == "disable":
                self.system.calls.append(list(argv))
                return completed()
            return original(argv, timeout)

        self.system = refuse_stop
        self.system.calls, self.system.active = [], {"psy-stubborn.service"}
        code, report = self.run_tool([], apply=True, stop=["psy-stubborn.service"])
        self.assertEqual(code, 2)
        self.assertIn("still active", report["error"])

    def test_containers_are_removed_by_exact_name_and_missing_ones_skipped(self):
        self.system.containers = {"scylla-server", "other-container"}
        code, report = self.run_tool([], apply=True, containers=["scylla-server", "gone"])
        self.assertEqual(code, 0, report)
        self.assertEqual(report["containers_removed"], ["scylla-server"])
        self.assertEqual(self.system.containers, {"other-container"})
        removed = [call for call in self.system.calls if call[1] == "rm"]
        self.assertEqual(removed, [["/usr/bin/docker", "rm", "-f", "--", "scylla-server"]])

    def test_no_docker_call_without_containers(self):
        self.run_tool([], apply=True)
        self.assertFalse([call for call in self.system.calls if call[0].endswith("docker")])

    def test_removing_unit_files_reloads_systemd(self):
        unit_root = self.root / "old" / "systemd"
        unit = self.make("old/systemd/psy-x.service")
        with patch.object(tool, "SYSTEMD_ROOT", str(unit_root)):
            self.run_tool([unit], apply=True)
        self.assertTrue([call for call in self.system.calls if call[1] == "daemon-reload"])

    def test_second_apply_is_a_no_op(self):
        target = self.make("old/t/file.txt").parent
        self.assertEqual(self.run_tool([target], apply=True)[0], 0)
        code, report = self.run_tool([target], apply=True)
        self.assertEqual(code, 0, report)
        self.assertEqual(report["cleared"], [])
        self.assertEqual(report["absent"], [str(target)])

    def test_inputs_are_hash_checked_before_anything_is_read(self):
        argv = ["--host", HOST, "--release-lock", "inline:{}", "--release-lock-sha256", "0" * 64,
                "--retained-paths", "inline:{}", "--retained-paths-sha256", "0" * 64]
        out = io.StringIO()
        with redirect_stdout(out):
            code = tool.main(argv, run=self.system, read_mounts=lambda: [])
        self.assertEqual(code, 2)
        self.assertIn("hash mismatch", json.loads(out.getvalue())["error"])

    def test_retained_slice_for_another_host_is_refused(self):
        raw = json.dumps({"paths": [{"host": "other", "path": str(self.keep), "kind": "secret"}]}).encode()
        code, report = self.run_tool([], retained_raw=raw)
        self.assertEqual(code, 2)
        self.assertIn("another host", report["error"])

    def test_result_file_is_written_atomically_when_asked(self):
        target = self.make("old/t/file.txt").parent
        result = self.root / "result.json"
        retained_raw = self.retained_document([self.keep])
        argv = ["--host", HOST, "--release-lock", "inline:" + self.lock_raw.decode(), "--release-lock-sha256",
                sha(self.lock_raw), "--retained-paths", "inline:" + retained_raw.decode(), "--retained-paths-sha256",
                sha(retained_raw), "--clear-paths", json.dumps([str(target)]), "--result", str(result), "--apply"]
        with redirect_stdout(io.StringIO()):
            self.assertEqual(tool.main(argv, run=self.system, read_mounts=lambda: []), 0)
        self.assertEqual(json.loads(result.read_text())["cleared"], [str(target)])
        self.assertFalse(result.with_name("result.json.tmp").exists())

    def test_tool_runs_with_isolated_standard_library_only(self):
        source = Path(tool.__file__).read_text()
        imports = set(re.findall(r"^(?:import|from) (\w+)", source, re.MULTILINE))
        self.assertTrue(imports <= {"argparse", "hashlib", "json", "os", "pathlib", "re", "stat", "subprocess", "sys"})

    # ---- fix round 1
    def test_timers_and_sockets_are_valid_stop_names_and_stop_before_their_services(self):
        self.system.active = {"psy-a.service", "psy-a.timer", "psy-a.socket", "psy-b.service"}
        code, report = self.run_tool([], apply=True, stop=["psy-a.service", "psy-b.service", "psy-a.socket", "psy-a.timer"])
        self.assertEqual(code, 0, report)
        order = [call[-1] for call in self.disables()]
        self.assertEqual(order[:2], ["psy-a.timer", "psy-a.socket"])
        self.assertEqual(sorted(order[2:]), ["psy-a.service", "psy-b.service"])
        self.assertEqual(self.system.active, set())

    def test_active_units_are_listed_for_services_timers_and_sockets(self):
        self.run_tool([], stop=["psy-a.timer"])
        listing = next(call for call in self.system.calls if call[1] == "list-units")
        self.assertIn("--type=service,timer,socket", listing)

    def test_an_unlisted_active_timer_or_socket_is_reported(self):
        self.system.active = {"parth-fires.timer", "psy-late.socket", "psy-kept.timer"}
        code, report = self.run_tool([], keep_units=["psy-kept.timer"])
        self.assertEqual(report["unlisted_active"], ["parth-fires.timer", "psy-late.socket"])
        self.assertEqual(report["active_kept"], ["psy-kept.timer"])

    def test_the_name_rule_is_the_same_in_the_tool_and_the_validator(self):
        import release_lock
        self.assertEqual(tool.UNIT_NAME.pattern, release_lock.UNIT_NAME.pattern)
        for name in ("psy-x.service", "psy-x.timer", "psy-x.socket", "parth-worker@coordinator-0.service"):
            self.assertTrue(tool.UNIT_NAME.fullmatch(name), name)
        for name in ("psy-x.target", "psy-x", "a/b.service", ""):
            self.assertFalse(tool.UNIT_NAME.fullmatch(name), name)

    def test_a_real_shaped_entry_passes_plan_and_validator(self):
        import release_lock
        entry = {"stop": ["psy-indexer-r3-mirror.timer", "psy-indexer-r3-mirror.service", "psy-core-client.socket"],
                 "containers": [], "retain": ["/etc/ssh"], "clear": ["/opt/psy-old/x"]}
        retired, retained = test_release_lock.build_test_retirement()
        retired["hosts"]["gcp-scylla"].update(entry)
        retained["paths"] = [item for item in retained["paths"] if item["host"] != "gcp-scylla"] + [
            {"host": "gcp-scylla", "path": "/etc/ssh", "kind": "secret"}]
        retired["hosts"]["gcp-scylla"]["retain"] = ["/etc/ssh"]
        release_lock.validate_retirement(retired, retained)
        code, report = self.run_tool([], stop=entry["stop"])
        self.assertEqual(code, 0, report)

    def test_listed_units_are_disabled_with_now_and_never_left_enabled(self):
        self.system.active = {"psy-old.service"}
        self.system.enabled = {"psy-old.service", "psy-idle.service"}
        self.system.files = {"psy-idle.service"}
        code, report = self.run_tool([], apply=True, stop=["psy-old.service", "psy-idle.service"])
        self.assertEqual(code, 0, report)
        self.assertEqual(sorted(call[-1] for call in self.disables()), ["psy-idle.service", "psy-old.service"])
        self.assertTrue(all(call[2] == "--now" for call in self.disables()))
        self.assertEqual(self.system.enabled, set())
        self.assertEqual(sorted(report["disabled"]), ["psy-idle.service", "psy-old.service"])

    def test_a_unit_that_stays_enabled_fails_the_run(self):
        self.system.enabled = {"psy-old.service"}
        original = self.system.__call__

        def keep_enabled(argv, timeout=120):
            if argv[1] == "disable":
                return completed()
            return original(argv, timeout)

        self.system = keep_enabled
        self.system.calls, self.system.enabled, self.system.active = [], {"psy-old.service"}, set()
        self.system.files = {"psy-old.service"}
        code, report = self.run_tool([], apply=True, stop=["psy-old.service"])
        self.assertEqual(code, 2)
        self.assertIn("still enabled", report["error"])

    def test_dangling_wants_links_of_cleared_units_are_removed_and_others_kept(self):
        unit_root = self.root / "old" / "systemd"
        unit = self.make("old/systemd/psy-x.service")
        other = self.make("old/systemd/psy-keep.service")
        wants = unit_root / "multi-user.target.wants"
        wants.mkdir()
        (wants / "psy-x.service").symlink_to(unit)
        (wants / "psy-keep.service").symlink_to(other)
        (wants / "unrelated.service").symlink_to(self.root / "nowhere.service")
        with patch.object(tool, "SYSTEMD_ROOT", str(unit_root)):
            code, report = self.run_tool([unit], apply=True)
        self.assertEqual(code, 0, report)
        self.assertFalse(os.path.lexists(wants / "psy-x.service"))
        self.assertTrue(os.path.lexists(wants / "psy-keep.service"))
        self.assertTrue(os.path.lexists(wants / "unrelated.service"), "only links to a cleared unit go")
        self.assertEqual(report["wants_links_removed"], 1)

    def test_a_retained_symlink_whose_real_file_is_inside_a_clear_target_is_refused(self):
        real = self.make("old/rel/deep/signer.bin", b"KEY")
        link = self.keep / "signer"
        link.symlink_to(real)
        code, report = self.run_tool([self.root / "old" / "rel"], apply=True, secret=[link])
        self.assertEqual(code, 2)
        self.assertTrue(real.exists())
        self.assertTrue(any("retained" in reason for reason in report["refused"]), report)

    def test_a_retained_directory_holding_a_symlink_into_a_clear_target_is_refused(self):
        real = self.make("old/rel2/k.bin", b"KEY")
        directory = self.root / "keep2"
        directory.mkdir()
        (directory / "k").symlink_to(real)
        code, report = self.run_tool([self.root / "old" / "rel2"], apply=True, secret=[directory])
        self.assertEqual(code, 2)
        self.assertTrue(real.exists())
        self.assertTrue(any("symlink into the clear target" in reason for reason in report["refused"]), report)

    def test_a_retained_secret_symlink_is_hashed_through_the_link(self):
        outside = self.root / "outside.bin"
        outside.write_bytes(b"real-bytes")
        link = self.keep / "via-link"
        link.symlink_to(outside)
        code, report = self.run_tool([], secret=[link])
        item = report["retained"][0]
        self.assertEqual((item["kind"], item["sha256"]), ("file", sha(b"real-bytes")))

    def test_every_secret_marker_name_is_refused_by_the_name_walk(self):
        for name in ("id_ed25519", "id_rsa", "wg0.conf", ".ssh", ".env", "seed.txt", "validator-1.json",
                     "p2p-identity.bin", "UTC--2026-01-01T00-00-00--abc", "signer.bin", "privkey", "x.pem",
                     "node.key", "operators.json", "credential.secret", "l1-password.cred"):
            with self.subTest(name=name):
                target = self.root / "old" / "walk"
                if target.exists():
                    import shutil
                    shutil.rmtree(target)
                (target / name).parent.mkdir(parents=True, exist_ok=True)
                (target / name).mkdir() if name == ".ssh" else (target / name).write_bytes(b"x")
                code, report = self.run_tool([target])
                self.assertEqual(code, 2, name)

    def test_the_name_walk_does_not_refuse_ordinary_release_names(self):
        for name in ("psy_node_cli", "config.json", "genesis.json", "manifest.json", "build.json", "hotfix.service",
                     "relayer_exec.py", "monkey.txt", "checkpoints"):
            with self.subTest(name=name):
                target = self.make(f"old/ok/{name}").parent
                code, report = self.run_tool([target])
                self.assertEqual(code, 0, (name, report))

    def test_secret_markers_of_the_validator_are_all_covered_by_the_name_walk(self):
        import release_lock
        samples = {"keystore": "keystore", "/keys": "keys", ".key": "a.key", ".cred": "x.cred", "operator": "operator.json",
                   "/wireguard": "wireguard", "id_ed25519": "id_ed25519", "credential": "credential.secret",
                   "/.ssh": ".ssh", "/etc/ssh": "ssh_host_ed25519_key", ".psy": ".psy"}
        self.assertEqual(set(samples), set(release_lock.SECRET_MARKERS) - {"/etc/ssh"} | {"/etc/ssh"})
        for marker, name in samples.items():
            with self.subTest(marker=marker):
                self.assertTrue(tool.SECRET_NAME.search(name), name)

    def test_an_allow_entry_equal_to_a_clear_target_is_refused(self):
        target = self.make("old/t2/operators.json").parent
        code, report = self.run_tool([target], allow=[target], apply=True)
        self.assertEqual(code, 2)
        self.assertIn("strictly inside", report["error"])
        self.assertTrue(target.exists())

    def test_an_allow_subtree_exempts_names_below_it_only(self):
        target = self.make("old/t3/node_modules/pkg/jwt-helper.js").parent.parent.parent
        self.make("old/t3/other/operators.json")
        code, report = self.run_tool([target], allow=[target / "node_modules"])
        self.assertEqual(code, 2)
        self.assertTrue(all("operators.json" in reason for reason in report["refused"]), report)

    def test_nested_clear_entries_are_refused(self):
        outer = self.make("old/n/a/b.txt").parent.parent
        code, report = self.run_tool([outer, outer / "a"], apply=True)
        self.assertEqual(code, 2)
        self.assertIn("nested", report["error"])
        self.assertTrue(outer.exists())

    def test_glob_characters_are_refused_in_clear_and_retained_paths(self):
        self.make("old/g/w@1.service")
        for bad in ("w@*.service", "w@?.service", "w@[1].service"):
            with self.subTest(bad=bad):
                code, report = self.run_tool([self.root / "old" / "g" / bad], apply=True)
                self.assertEqual(code, 2)
                self.assertIn("glob", report["error"])
        code, report = self.run_tool([], secret=[self.root / "keep*"])
        self.assertEqual(code, 2)
        self.assertIn("glob", report["error"])

    def test_daemon_reload_runs_when_the_plan_touches_the_unit_directory_even_if_a_delete_fails(self):
        unit_root = self.root / "old" / "systemd"
        first = self.make("old/systemd/psy-x.service")
        second = self.make("old/systemd/psy-y.service")
        original = tool.delete_tree

        def fail_second(path):
            if path.endswith("psy-y.service"):
                raise OSError(16, "busy")
            original(path)

        with patch.object(tool, "SYSTEMD_ROOT", str(unit_root)), patch.object(tool, "delete_tree", fail_second):
            code, report = self.run_tool([first, second], apply=True)
        self.assertNotEqual(code, 0)
        self.assertTrue([call for call in self.system.calls if call[1] == "daemon-reload"])
        with patch.object(tool, "SYSTEMD_ROOT", str(unit_root)):
            code, report = self.run_tool([first, second], apply=True)
        self.assertEqual(code, 0, report)
        self.assertEqual(len([call for call in self.system.calls if call[1] == "daemon-reload"]), 2)

    def test_a_failed_daemon_reload_fails_the_run(self):
        unit_root = self.root / "old" / "systemd"
        unit = self.make("old/systemd/psy-x.service")
        self.system.reload_code = 1
        with patch.object(tool, "SYSTEMD_ROOT", str(unit_root)):
            code, report = self.run_tool([unit], apply=True)
        self.assertEqual(code, 2)
        self.assertIn("daemon-reload", report["error"])

    def test_infrastructure_paths_are_only_lstat_checked(self):
        node = self.root / "node-data"
        node.mkdir()
        (node / "chain.db").write_bytes(b"a")
        with patch.object(tool, "listing_hash", side_effect=AssertionError("walked")), \
                patch.object(tool, "walk_names", side_effect=AssertionError("walked")):
            code, report = self.run_tool([], infrastructure=[node])
        self.assertEqual(code, 0, report)

    def test_host_address_must_be_local_when_given(self):
        with patch.object(tool, "local_addresses", return_value={"10.0.0.5"}):
            code, report = self.run_tool([], extra=["--address", "10.0.0.5"])
            self.assertEqual(code, 0, report)
            code, report = self.run_tool([], extra=["--address", "10.0.0.9"])
        self.assertEqual(code, 2)
        self.assertIn("not an address of this machine", report["error"])

    def test_local_addresses_come_from_the_kernel_table(self):
        table = """Main:
  +-- 10.148.0.0/24 3 0 4
     |-- 10.148.0.25
        /32 host LOCAL
     |-- 10.148.0.255
        /32 link BROADCAST
  |-- 127.0.0.1
     /32 host LOCAL
"""
        self.assertEqual(tool.local_addresses(lambda: table), {"10.148.0.25", "127.0.0.1"})

    def test_skip_retained_hash_reports_no_hashes(self):
        with patch.object(tool, "hash_secret", side_effect=AssertionError("hashed")):
            code, report = self.run_tool([], extra=["--skip-retained-hash"])
        self.assertEqual(code, 0, report)
        self.assertEqual(report["retained"], [])

    def test_the_unprivileged_skip_flag_cannot_be_combined_with_apply(self):
        target = self.make("old/t/file.txt").parent
        code, report = self.run_tool([target], apply=True, extra=["--skip-retained-hash"])
        self.assertEqual(code, 2)
        self.assertIn("dry run", report["error"])
        self.assertTrue(target.exists())

    def test_result_file_is_private_and_owned_by_the_directory_owner(self):
        target = self.make("old/t/file.txt").parent
        result = self.root / "result.json"
        retained_raw = self.retained_document([self.keep])
        argv = ["--host", HOST, "--release-lock", "inline:" + self.lock_raw.decode(), "--release-lock-sha256",
                sha(self.lock_raw), "--retained-paths", "inline:" + retained_raw.decode(), "--retained-paths-sha256",
                sha(retained_raw), "--clear-paths", json.dumps([str(target)]), "--result", str(result), "--apply"]
        with redirect_stdout(io.StringIO()):
            tool.main(argv, run=self.system, read_mounts=lambda: [])
        self.assertEqual(stat.S_IMODE(os.stat(result).st_mode), 0o600)
        self.assertEqual(os.stat(result).st_uid, os.stat(self.root).st_uid)

    def test_a_secret_that_is_missing_is_reported_as_missing_and_the_run_fails_on_apply(self):
        target = self.make("old/t/file.txt").parent
        code, report = self.run_tool([target], apply=True, secret=[self.root / "absent-secret"])
        self.assertNotEqual(code, 0)
        self.assertTrue(any("retained secret is missing" in reason for reason in report["refused"]), report)
        self.assertTrue(target.exists(), "nothing is deleted when a retained secret is missing")


if __name__ == "__main__":
    unittest.main()
