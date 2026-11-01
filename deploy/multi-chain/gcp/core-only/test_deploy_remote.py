import atexit
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import unittest.mock

import deploy_remote
from deploy_remote import OperatorPending, Remote, RemoteError, wait_until


KEY_DIR = tempfile.mkdtemp()
atexit.register(shutil.rmtree, KEY_DIR, True)
KEY_FILES = {name: str(Path(KEY_DIR) / name) for name in ("jump", "inner", "oper")}
for _path in KEY_FILES.values():
    Path(_path).write_text("fixture\n")
ACCESS = {
    "known_hosts": "/priv/known_hosts",
    "hosts": {
        "jump": {"ssh": "ubuntu@203.0.113.1", "identity": KEY_FILES["jump"], "jump": None, "sudo": "passwordless"},
        "inner": {"ssh": "ubuntu@10.0.0.2", "identity": KEY_FILES["inner"], "jump": "jump", "sudo": "passwordless"},
        "oper": {"ssh": "ubuntu@10.0.0.3", "identity": KEY_FILES["oper"], "jump": "jump", "sudo": "operator"},
    },
}
LOCK = {"hosts": {"inner": "10.0.0.2", "oper": "10.0.0.3"}}


class FakeRunner:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.calls = []
        self.result = (returncode, self.as_bytes(stdout), self.as_bytes(stderr))

    @staticmethod
    def as_bytes(value):
        return value if isinstance(value, bytes) else value.encode()

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        if isinstance(self.result, Exception):
            raise self.result
        return subprocess.CompletedProcess(argv, self.result[0], self.result[1], self.result[2])


def remote_with(runner, access=ACCESS):
    return Remote(access, LOCK, runner=runner)


def script_of(runner, index=0):
    return runner.calls[index][1]["input"].decode()


class RemoteTests(unittest.TestCase):
    def test_ssh_uses_explicit_bash(self):
        runner = FakeRunner(stdout="ok")
        remote_with(runner).run_script("inner", "echo hi\n", 30)
        argv, kwargs = runner.calls[0]
        self.assertEqual(argv[0], "ssh")
        self.assertEqual(argv[-3:], ["ubuntu@10.0.0.2", "/usr/bin/bash", "-s"])
        self.assertEqual(kwargs["input"], b"echo hi\n")
        self.assertEqual(kwargs["timeout"], 30)

    def test_ssh_options_are_strict_and_use_access_known_hosts(self):
        runner = FakeRunner()
        remote_with(runner).run_script("inner", "true", 30)
        argv = runner.calls[0][0]
        self.assertEqual(argv[1:3], ["-F", "/dev/null"])
        self.assertIn("GlobalKnownHostsFile=/dev/null", argv)
        for option in ("BatchMode=yes", "ConnectTimeout=15", "StrictHostKeyChecking=yes",
                       "UserKnownHostsFile=/priv/known_hosts", "IdentitiesOnly=yes"):
            self.assertIn(option, argv)
        self.assertNotIn("StrictHostKeyChecking=no", " ".join(argv))
        self.assertEqual(argv[argv.index("-i") + 1], KEY_FILES["inner"])

    def test_jump_host_comes_from_access(self):
        runner = FakeRunner()
        remote = remote_with(runner)
        remote.run_script("inner", "true", 30)
        remote.run_script("jump", "true", 30)
        direct = runner.calls[1][0]
        proxied = runner.calls[0][0]
        proxy = [a for a in proxied if a.startswith("ProxyCommand=")]
        self.assertEqual(len(proxy), 1)
        self.assertIn("ubuntu@203.0.113.1", proxy[0])
        self.assertIn(KEY_FILES["jump"], proxy[0])
        self.assertIn("-W %h:%p", proxy[0])
        self.assertIn("-F /dev/null", proxy[0])
        self.assertFalse([a for a in direct if a.startswith("ProxyCommand=")])

    def test_unknown_host_is_refused_before_running(self):
        runner = FakeRunner()
        with self.assertRaisesRegex(RemoteError, "not in the access file: ghost"):
            remote_with(runner).run_script("ghost", "true", 30)
        self.assertEqual(runner.calls, [])

    def test_bad_access_is_rejected_at_construction(self):
        broken = {"known_hosts": "/k", "hosts": {"a": {"ssh": "u@h", "identity": KEY_FILES["jump"], "jump": "nope",
                                                       "sudo": "passwordless"}}}
        with self.assertRaisesRegex(ValueError, "jump"):
            Remote(broken, LOCK)
        no_jump = {"known_hosts": "/k", "hosts": {"a": {"ssh": "u@h", "identity": KEY_FILES["jump"], "sudo": "passwordless"}}}
        with self.assertRaisesRegex(ValueError, "jump is required"):
            Remote(no_jump, LOCK)
        with self.assertRaisesRegex(ValueError, "known_hosts"):
            Remote({"hosts": ACCESS["hosts"]}, LOCK)
        bad_sudo = {"known_hosts": "/k", "hosts": {"a": {"ssh": "u@h", "identity": KEY_FILES["jump"], "jump": None,
                                                         "sudo": "maybe"}}}
        with self.assertRaisesRegex(ValueError, "sudo"):
            Remote(bad_sudo, LOCK)

    def test_missing_identity_file_is_refused_at_construction(self):
        missing = json.loads(json.dumps(ACCESS))
        missing["hosts"]["jump"]["identity"] = "/nonexistent/key"
        with self.assertRaisesRegex(ValueError, "jump: identity file not found"):
            Remote(missing, LOCK)

    def test_read_text_cap_counts_raw_bytes(self):
        # Invalid bytes decode to 3-byte replacement characters; the cap must see the raw count.
        raw = b"\xff" * (deploy_remote.MAX_READ_BYTES + 1)
        with self.assertRaisesRegex(RemoteError, "exceeds"):
            remote_with(FakeRunner(stdout=raw)).read_text("inner", "/x")
        remote_with(FakeRunner(stdout=b"\xff" * 10)).read_text("inner", "/x")

    def test_swapped_jumped_target_fails_construction(self):
        swapped = json.loads(json.dumps(ACCESS))
        swapped["hosts"]["inner"]["ssh"] = "ubuntu@10.9.9.9"
        with self.assertRaisesRegex(ValueError, "inner: target differs"):
            Remote(swapped, LOCK)

    def test_jumped_target_may_match_the_topology_address(self):
        access = json.loads(json.dumps(ACCESS))
        access["hosts"]["extra"] = {"ssh": "ubuntu@10.0.0.7", "identity": KEY_FILES["jump"], "jump": "jump", "sudo": "passwordless"}
        with self.assertRaisesRegex(ValueError, "extra: target differs"):
            Remote(access, LOCK)
        Remote(access, LOCK, topology_hosts={"extra": "10.0.0.7"})
        with self.assertRaisesRegex(ValueError, "extra: target differs"):
            Remote(access, LOCK, topology_hosts={"extra": "10.0.0.8"})

    def test_direct_hosts_are_not_compared(self):
        Remote(ACCESS, {"hosts": {"jump": "198.51.100.1", "inner": "10.0.0.2", "oper": "10.0.0.3"}})

    def test_missing_aliases_lists_what_the_access_file_lacks(self):
        remote = remote_with(FakeRunner())
        self.assertEqual(remote.missing_aliases(["inner", "x", "y"]), ["x", "y"])

    def test_sudo_mode_reports_the_access_file_value(self):
        remote = remote_with(FakeRunner())
        self.assertEqual((remote.sudo_mode("inner"), remote.sudo_mode("oper")), ("passwordless", "operator"))
        with self.assertRaises(RemoteError):
            remote.sudo_mode("unknown")

    def test_operator_host_refuses_run_root(self):
        runner = FakeRunner(stdout="{}")
        with self.assertRaisesRegex(RemoteError, "operator host oper"):
            remote_with(runner).run_root_json("oper", ["/usr/bin/true"], 30)
        self.assertEqual(runner.calls, [])

    def test_run_root_json_runs_sudo_with_quoted_argv(self):
        runner = FakeRunner(stdout='{"ok": true}\n')
        result = remote_with(runner).run_root_json("inner", ["/usr/bin/python3", "-I", "a b;rm"], 60)
        self.assertEqual(result, {"ok": True})
        self.assertIn("/usr/bin/python3 -I 'a b;rm'", script_of(runner))

    def test_run_root_json_wraps_the_command_in_a_remote_timeout(self):
        runner = FakeRunner(stdout="{}")
        remote_with(runner).run_root_json("inner", ["/usr/bin/true"], 120)
        script = script_of(runner)
        # timeout must run as root, inside sudo, and the script must not exec it away.
        self.assertIn("\nsudo -n -- /usr/bin/timeout --signal=TERM --kill-after=30 120 /usr/bin/true\n", script)
        self.assertNotIn("exec", script)
        self.assertGreater(runner.calls[0][1]["timeout"], 120 + 30)

    def test_remote_limit_exit_codes_read_as_timeouts(self):
        for code in (124, 137):
            with self.assertRaisesRegex(RemoteError, f"inner: timed out on the remote \\(exit {code}\\)") as caught:
                remote_with(FakeRunner(returncode=code)).run_root_json("inner", ["x"], 30)
            self.assertEqual(caught.exception.exit_code, code)
        with self.assertRaisesRegex(RemoteError, "exit 124: "):
            remote_with(FakeRunner(returncode=124)).run_script("inner", "x", 30)

    def test_run_root_json_withholds_stderr_unless_asked(self):
        for show, expected in ((False, "details withheld"), (True, "visible diagnostic")):
            runner = FakeRunner(returncode=2, stderr="visible diagnostic\n")
            with self.assertRaises(RemoteError) as caught:
                remote_with(runner).run_root_json("inner", ["x"], 30, show_stderr=show)
            self.assertIn(expected, str(caught.exception))
        self.assertNotIn("visible diagnostic", str(RemoteError("h: exit 2: details withheld")))

    def test_bare_keys_and_bearer_credentials_are_redacted_from_a_failure_tail(self):
        key = "ab" * 32
        for line in (key, "0x" + key, f"cast failed with {key} in argv", "Authorization: Bearer abc.def", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig"):
            runner = FakeRunner(returncode=1, stderr=f"first line\n{line}\nlast line\n")
            with self.subTest(line=line[:12]), self.assertRaises(RemoteError) as caught:
                remote_with(runner).run_root_text("inner", ["x"], 30)
            self.assertNotIn(key, str(caught.exception))
            self.assertNotIn("abc.def", str(caught.exception))
            self.assertNotIn("eyJhbGci", str(caught.exception))
            self.assertIn("first line", str(caught.exception))
        short = FakeRunner(returncode=1, stderr="exit reason " + "ab" * 31 + "\n")
        with self.assertRaisesRegex(RemoteError, "exit reason"):
            remote_with(short).run_root_text("inner", ["x"], 30)

    def test_failure_reason_is_shown_by_default_and_falls_back_to_stdout(self):
        runner = FakeRunner(returncode=1, stdout='{"component": "valkey", "error": "write refused", "ok": false}\n')
        with self.assertRaisesRegex(RemoteError, "write refused"):
            remote_with(runner).run_root_text("inner", ["x"], 30)
        runner = FakeRunner(returncode=1, stdout="from stdout", stderr="from stderr")
        with self.assertRaisesRegex(RemoteError, "from stderr") as caught:
            remote_with(runner).run_root_json("inner", ["x"], 30)
        self.assertNotIn("from stdout", str(caught.exception))
        leaky = FakeRunner(returncode=1, stdout='{"error": "bad", "password": "hunter2"}\n')
        with self.assertRaises(RemoteError) as caught:
            remote_with(leaky).run_root_text("inner", ["x"], 30)
        self.assertNotIn("hunter2", str(caught.exception))

    def test_run_root_text_sends_stdin_as_a_here_document_under_the_remote_timeout(self):
        runner = FakeRunner(stdout="[]")
        text = remote_with(runner).run_root_text("inner", ["/usr/bin/python3", "-I", "/dev/stdin"], 60,
                                                 stdin_text="print(1)")
        script = script_of(runner)
        self.assertEqual(text, "[]")
        self.assertIn("sudo -n -- /usr/bin/timeout --signal=TERM --kill-after=30 60 /usr/bin/python3 -I /dev/stdin "
                      "<<'PSY_ROOT_STDIN_END'\nprint(1)\nPSY_ROOT_STDIN_END\n", script)

    def test_run_root_text_maps_remote_timeout_exits_and_refuses_operator_hosts(self):
        with self.assertRaisesRegex(RemoteError, "timed out on the remote"):
            remote_with(FakeRunner(returncode=124)).run_root_text("inner", ["x"], 30, stdin_text="a")
        with self.assertRaisesRegex(RemoteError, "operator host oper"):
            remote_with(FakeRunner()).run_root_text("oper", ["x"], 30)
        with self.assertRaisesRegex(ValueError, "collides"):
            remote_with(FakeRunner()).run_root_text("inner", ["x"], 30, stdin_text="PSY_ROOT_STDIN_END")

    @unittest.skipUnless(Path("/usr/bin/timeout").exists() and Path("/usr/bin/python3").exists(), "needs coreutils")
    def test_here_document_script_runs_in_real_bash_with_stdin_as_the_program(self):
        runner = FakeRunner(stdout="[]")
        remote_with(runner).run_root_text("inner", ["/usr/bin/python3", "-I", "-B", "/dev/stdin", "status"], 20,
                                          stdin_text="import json, sys\nprint(json.dumps(sys.argv[1:]))\n")
        fake_bin = Path(tempfile.mkdtemp(dir=KEY_DIR))
        (fake_bin / "sudo").write_text('#!/bin/sh\nshift 2\nexec "$@"\n')
        (fake_bin / "sudo").chmod(0o755)
        done = subprocess.run(["/usr/bin/bash", "-s"], input=script_of(runner).encode(), capture_output=True,
                              env={"PATH": f"{fake_bin}:/usr/bin"}, timeout=30)
        self.assertEqual((done.returncode, done.stdout.decode().strip()), (0, '["status"]'))

    def test_run_root_json_rejects_duplicate_keys(self):
        with self.assertRaisesRegex(RemoteError, "JSON object"):
            remote_with(FakeRunner(stdout='{"a": 1, "a": 2}')).run_root_json("inner", ["x"], 30)

    def test_timeout_must_be_a_positive_int(self):
        remote = remote_with(FakeRunner(stdout="{}"))
        for bad in (None, 0, -1, 1.5, True):
            with self.assertRaises(ValueError):
                remote.run_script("inner", "true", bad)
            with self.assertRaises(ValueError):
                remote.run_root_json("inner", ["x"], bad)

    def test_nonzero_remote_exit_raises_with_host(self):
        runner = FakeRunner(returncode=7, stderr="boom\n")
        with self.assertRaises(RemoteError) as caught:
            remote_with(runner).run_script("inner", "false", 30)
        self.assertIn("inner", str(caught.exception))
        self.assertEqual((caught.exception.host, caught.exception.exit_code), ("inner", 7))
        self.assertNotIsInstance(caught.exception, deploy_remote.RemoteConnectionError)
        self.assertIn("exit 7", str(caught.exception))
        self.assertIn("boom", str(caught.exception))

    def test_timeout_raises_with_host_and_no_exit_code(self):
        runner = FakeRunner()
        runner.result = subprocess.TimeoutExpired(["ssh"], 5)
        with self.assertRaisesRegex(RemoteError, "inner.*timed out after 5") as caught:
            remote_with(runner).run_script("inner", "sleep 9", 5)
        self.assertEqual((caught.exception.host, caught.exception.exit_code), ("inner", None))

    def test_exit_255_is_a_connection_error(self):
        with self.assertRaises(deploy_remote.RemoteConnectionError) as caught:
            remote_with(FakeRunner(returncode=255, stderr="ssh: connect timed out")).run_script("inner", "x", 30)
        self.assertEqual((caught.exception.host, caught.exception.exit_code), ("inner", 255))
        self.assertIsInstance(caught.exception, RemoteError)

    def test_stray_bytes_never_fail_a_call(self):
        self.assertEqual(remote_with(FakeRunner(stdout=b"ok\xff\xfe")).run_script("inner", "x", 30), "ok\ufffd\ufffd")
        with self.assertRaisesRegex(RemoteError, "exit 1: bad"):
            remote_with(FakeRunner(returncode=1, stderr=b"bad\xff\xfe")).run_script("inner", "x", 30)
        with self.assertRaisesRegex(RemoteError, "JSON object"):
            remote_with(FakeRunner(stdout=b"\xff")).run_root_json("inner", ["x"], 30)

    def test_script_is_sent_as_utf8_bytes(self):
        runner = FakeRunner()
        remote_with(runner).run_script("inner", "echo \u00e9\n", 30)
        self.assertEqual(runner.calls[0][1]["input"], "echo \u00e9\n".encode())

    def test_invalid_json_result_raises(self):
        for text in ("not json", "[1, 2]", ""):
            with self.assertRaisesRegex(RemoteError, "inner.*JSON object"):
                remote_with(FakeRunner(stdout=text)).run_root_json("inner", ["/usr/bin/true"], 30)

    def test_invalid_json_does_not_echo_stdout(self):
        with self.assertRaises(RemoteError) as caught:
            remote_with(FakeRunner(stdout="password=hunter2-stdout")).run_root_json("inner", ["x"], 30)
        self.assertNotIn("hunter2", str(caught.exception))

    def test_stderr_tail_is_bounded_and_redacts_secret_lines(self):
        stderr = ("noise\n" * 500 + "login password=hunter2\nfetch https://user:pw123@example.test/x\n"
                  "api_token: abcdef\nMNEMONIC words here\nplain last line\n")
        with self.assertRaises(RemoteError) as caught:
            remote_with(FakeRunner(returncode=1, stderr=stderr)).run_script("inner", "x", 30)
        text = str(caught.exception)
        for leaked in ("hunter2", "pw123", "abcdef", "words here"):
            self.assertNotIn(leaked, text)
        self.assertIn("plain last line", text)
        self.assertLess(len(text), deploy_remote.ERROR_TAIL_CHARS + 200)

    def test_copy_files_uses_same_options_and_destination(self):
        runner = FakeRunner()
        remote_with(runner).copy_files("inner", [Path("/tmp/a.py"), Path("/tmp/b.tar")], "/opt/stage")
        argv = runner.calls[0][0]
        self.assertEqual(argv[0], "scp")
        self.assertIn("StrictHostKeyChecking=yes", argv)
        self.assertIn("UserKnownHostsFile=/priv/known_hosts", argv)
        self.assertTrue([a for a in argv if a.startswith("ProxyCommand=") and "ubuntu@203.0.113.1" in a])
        self.assertEqual(argv[-3:], ["/tmp/a.py", "/tmp/b.tar", "ubuntu@10.0.0.2:/opt/stage"])
        self.assertEqual(argv[1:3], ["-q", "-F"])
        self.assertEqual(runner.calls[0][1]["timeout"], deploy_remote.COPY_TIMEOUT_SECONDS)

    def test_copy_files_timeout_is_a_keyword(self):
        runner = FakeRunner()
        remote_with(runner).copy_files("inner", [Path("/tmp/a")], "/opt/s", timeout_seconds=99)
        self.assertEqual(runner.calls[0][1]["timeout"], 99)

    def test_copy_files_refuses_empty_sources_and_option_like_paths(self):
        runner = FakeRunner()
        remote = remote_with(runner)
        with self.assertRaisesRegex(ValueError, "no files"):
            remote.copy_files("inner", [], "/opt/stage")
        with self.assertRaisesRegex(ValueError, "absolute"):
            remote.copy_files("inner", [Path("/tmp/a")], "relative/dir")
        with self.assertRaisesRegex(ValueError, "absolute"):
            remote.copy_files("inner", [Path("rel/a.py")], "/opt/stage")
        with self.assertRaisesRegex(ValueError, "absolute"):
            remote.copy_files("inner", [Path("-oProxyCommand=x")], "/opt/stage")
        self.assertEqual(runner.calls, [])

    def test_read_text_cats_the_quoted_path(self):
        runner = FakeRunner(stdout="content")
        self.assertEqual(remote_with(runner).read_text("inner", "/etc/a b"), "content")
        self.assertIn("head -c 4194305 -- '/etc/a b'", script_of(runner))

    def test_read_text_is_utf8_faithful_and_size_capped(self):
        self.assertEqual(remote_with(FakeRunner(stdout="caf\u00e9\n")).read_text("inner", "/x"), "caf\u00e9\n")
        big = "a" * (deploy_remote.MAX_READ_BYTES + 1)
        with self.assertRaisesRegex(RemoteError, "exceeds"):
            remote_with(FakeRunner(stdout=big)).read_text("inner", "/x")


class LocalBashRunner:
    """Runs the script an ssh call would feed to bash -s in a real local bash, so the command shape is exercised."""

    def __init__(self):
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        return subprocess.run(["/usr/bin/bash", "-s"], input=kwargs["input"], capture_output=True, timeout=30)


class OperatorCommandTests(unittest.TestCase):
    def test_passwordless_host_runs_the_command_in_a_real_bash(self):
        marker = Path(KEY_DIR) / "ran"
        command = f"echo hello | grep -q hello && touch {marker}"
        self.assertTrue(deploy_remote.run_operator_command(remote_with(LocalBashRunner()), "inner", command))
        self.assertTrue(marker.exists())

    def test_a_failing_command_surfaces_instead_of_passing_as_pending(self):
        with self.assertRaisesRegex(RemoteError, "exit 1"):
            deploy_remote.run_operator_command(remote_with(LocalBashRunner()), "inner", "echo nope | grep -q yes && true")

    def test_operator_host_is_left_to_a_human(self):
        runner = LocalBashRunner()
        self.assertFalse(deploy_remote.run_operator_command(remote_with(runner), "oper", "true"))
        self.assertEqual(runner.calls, [])
        with self.assertRaises(OperatorPending) as pending:
            deploy_remote.settle_operator_command(remote_with(runner), "oper", "true", "/r.json", lambda: False)
        self.assertEqual((pending.exception.host, pending.exception.result_path), ("oper", "/r.json"))


class OperatorPendingTests(unittest.TestCase):
    def test_carries_fields_and_message(self):
        pending = OperatorPending("x1", "sudo /opt/i --sha256 abc", "/var/lib/r.json")
        self.assertEqual((pending.host, pending.command, pending.result_path), ("x1", "sudo /opt/i --sha256 abc",
                                                                                "/var/lib/r.json"))
        self.assertIn("x1", str(pending))

    def test_allows_valid_commands_with_secret_words_in_names_or_paths(self):
        for command in ("python3 -I prepare_faucet.py bootstrap --start-private",
                        "sudo /opt/x/prepare_relayer_credential.py --release-sha256 abc123",
                        "sudo /opt/x/install.py /etc/psy-faucet/credential.secret --sha256 abc",
                        "sudo install.py --private-ip 10.0.0.1 --token-address 0xabc",
                        "sudo fresh_l1.py deploy --secret-env /etc/parth/relayer.env",
                        "sudo fresh_l1.py deploy --secret-env=/etc/parth/relayer.env"):
            OperatorPending("x1", command, "/r.json")

    def test_refuses_commands_carrying_a_secret(self):
        for command in ("run --password abc", "run --password=abc", "run --url https://u:pw@host/x",
                        "run API_TOKEN=abc", "run --private-key=00", "run 'unbalanced", "run --private-key=0",
                        "run --private-key-hex 00", "run --private-keys 00", "run --secret-env abc",
                        "run --credential-path relative.txt", "run --passphrase=x"):
            with self.assertRaisesRegex(ValueError, "secret"):
                OperatorPending("x1", command, "/r.json")


class WaitUntilTests(unittest.TestCase):
    def setUp(self):
        self.sleeps = []
        self.now = [0.0]
        self.patches = [
            unittest.mock.patch.object(deploy_remote.time, "sleep", lambda s: (self.sleeps.append(s),
                                                                              self.now.__setitem__(0, self.now[0] + s))),
            unittest.mock.patch.object(deploy_remote.time, "monotonic", lambda: self.now[0]),
        ]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)

    def test_returns_when_ready(self):
        states = iter([False, False, True])
        wait_until(lambda: next(states), lambda: None, 5, 60, "svc")
        self.assertEqual(self.sleeps, [5, 5])

    def test_reads_failure_every_round(self):
        reads = []
        states = iter([False, False, True])
        wait_until(lambda: next(states), lambda: reads.append(1), 5, 60, "svc")
        self.assertEqual(len(reads), 3)

    def test_wait_until_raises_on_logged_failure_before_timeout(self):
        with self.assertRaisesRegex(RuntimeError, "svc.*panic: bad"):
            wait_until(lambda: False, lambda: "panic: bad", 5, 600, "svc")
        self.assertEqual(self.sleeps, [])

    def test_failure_after_some_rounds_still_raises(self):
        lines = iter([None, None, "boom"])
        with self.assertRaisesRegex(RuntimeError, "boom"):
            wait_until(lambda: False, lambda: next(lines), 5, 600, "svc")
        self.assertEqual(self.sleeps, [5, 5])

    def test_raises_on_timeout_with_label(self):
        with self.assertRaisesRegex(TimeoutError, "checkpoint stall.*20"):
            wait_until(lambda: False, lambda: None, 5, 20, "checkpoint stall")
        self.assertLessEqual(self.now[0], 20)

    def test_wait_until_rejects_poll_over_30_seconds(self):
        with self.assertRaises(ValueError):
            wait_until(lambda: True, lambda: None, 31, 60, "svc")
        with self.assertRaises(ValueError):
            wait_until(lambda: True, lambda: None, 0, 60, "svc")

    def test_failure_text_is_redacted(self):
        with self.assertRaises(RuntimeError) as caught:
            wait_until(lambda: False, lambda: "login password=hunter2", 5, 60, "svc")
        self.assertNotIn("hunter2", str(caught.exception))


MUST_REFUSE_RESULTS = (
    {"private_key": "v"}, {"privateKey": "v"}, {"Secret": "v"}, {"db_password": "v"}, {"api_token": "v"},
    {"apiToken": "v"}, {"mnemonic": "v"}, {"credential_path": "/etc/x"}, {"cookie": "v"}, {"access_token": "v"},
    {"token": "v"}, {"private_key_hex": "v"}, {"privateKeyHex": "v"}, {"private_keys": [1, 2]},
    {"privateKeys": [1]}, {"passwd": "v"}, {"passphrase": "v"}, {"x": {"y": [{"private_keys": 1}]}},
    {"env": ["private_key_hex=0xabc"]}, {"env": ["PRIVATE_KEYS=[1,2]"]}, {"env": ["private-key: 0xabc"]},
    {"env": ["--private-key=0xabc"]}, {"env": ["DB_PASSWORD=x"]}, {"stderr": "api_token: x"},
    {"pem": "-----BEGIN PRIVATE KEY-----"}, {"pem": "-----BEGIN RSA PRIVATE KEY-----"},
    {"a": ["x", "postgres://u:p@h/db"]}, {"DB_PASSWORD=hunter2": 1}, {"postgres://u:p@h/db": 1},
    {"env": ["passphrase=x"]},
)
MUST_PASS_RESULTS = (
    {"credential_sha256": "a"}, {"secrets_copied": True}, {"contains_credentials": True}, {"secrets_copied": None},
    {"private_key_files_opened": 3}, {"private_keys_mode": "0600"}, {"private_ip": "10.0.0.1"},
    {"deposit_tokens": 2}, {"token_address": "0xabc"}, {"tokens": 3}, {"key_count": 3}, {"password": False},
    {"path": "/etc/psy-faucet/credential.secret"}, {"a": "https://host.example/path", "n": 3},
    {"note": "checkpoint: 5 reached", "unit": "psy-core.service"},
)


class SecretFindingTests(unittest.TestCase):
    def test_must_refuse_table(self):
        for value in MUST_REFUSE_RESULTS:
            self.assertIsNotNone(deploy_remote.find_secret(value), value)

    def test_must_pass_table(self):
        for value in MUST_PASS_RESULTS:
            self.assertIsNone(deploy_remote.find_secret(value), value)

    def test_scan_cost_is_linear(self):
        import time
        text = "a-" * 10 + ("a" * 1000 + " ") * 1000
        started = time.monotonic()
        deploy_remote.find_secret({"x": text})
        self.assertLess(time.monotonic() - started, 2.0)
        started = time.monotonic()
        deploy_remote.find_secret({"x": "a" * 20000})
        self.assertLess(time.monotonic() - started, 2.0)

    def test_unsafe_key_location_does_not_echo_the_key(self):
        self.assertNotIn("hunter2", deploy_remote.find_secret({"o": {"DB_PASSWORD=hunter2": 1}}))

    def test_find_secret_returns_location_not_value(self):
        where = deploy_remote.find_secret({"outer": {"password": "hunter2"}})
        self.assertNotIn("hunter2", where)
        self.assertIn("outer.password", where)
        where = deploy_remote.find_secret({"env": ["DB_PASSWORD=hunter2"]})
        self.assertNotIn("hunter2", where)

    def test_key_words_split_on_punctuation_and_camel_case(self):
        self.assertEqual(deploy_remote.key_words("apiTokenX-y.z"), ["api", "token", "x", "y", "z"])
        self.assertEqual(deploy_remote.key_words("DB_PASSWORD"), ["db", "password"])


if __name__ == "__main__":
    unittest.main()
