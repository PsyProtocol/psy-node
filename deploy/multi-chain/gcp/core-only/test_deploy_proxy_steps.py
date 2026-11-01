import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
import unittest.mock

import deploy_prepare_steps as prepare
import deploy_proxy_steps as proxy
import release_lock
import test_deploy_prepare_steps as base
from deploy_remote import OperatorPending, RemoteConnectionError, RemoteError, find_secret

HOSTS = {"system": "arc99x1", "user": "arc99x3"}
STEP = proxy.PROXY_STEPS["start_proxies"]
REAL_MANIFEST = Path(os.environ.get("PSY_REAL_RUNTIME_MANIFEST", "/nonexistent"))


class FakeRemote:
    """Records stage and RPC traffic; reports and unit states are set per role by the test."""

    def __init__(self, workspace):
        self.ws = workspace
        self.reports, self.copies, self.scripts, self.rpc = {}, [], [], []
        self.pids, self.restarts, self.answers, self.binary_hashes = {}, {}, {}, {}
        self.panicked = set()
        self.activations = []
        self.copy_failure = None

    def missing_aliases(self, aliases):
        return []

    sudo = "operator"

    def sudo_mode(self, host):
        return self.sudo

    on_activate = None

    def run_script(self, host, script, timeout):
        self.scripts.append((host, script))
        role = next(name for name, alias in HOSTS.items() if alias == host)
        if " activate " in script and "sha256sum -c -" in script:
            self.activations.append(role)
            if self.on_activate:
                self.on_activate(role)
            return ""
        if script.startswith("systemctl show"):
            return f"ActiveState=active\nMainPID={self.pids.get(role, 0)}\nNRestarts={self.restarts.get(role, 0)}\n"
        if "echo missing" in script:
            if role not in self.reports:
                return "missing\n"
            return "present\n" + (self.reports[role] if isinstance(self.reports[role], str) else json.dumps(self.reports[role]))
        if "sha256sum --" in script:
            return self.binary_hashes.get(role, self.ws.lock["binaries"]["psy_user_cli"]) + "  /installed\n"
        if script.startswith("journalctl"):
            return "panic\n" if role in self.panicked else ""
        if "curl" in script:
            body = json.loads(script.split("<<'PSY_PROXY_BODY_END'\n", 1)[1].rsplit("\nPSY_PROXY_BODY_END", 1)[0])
            self.rpc.append((role, body["method"]))
            return json.dumps(self.answers[role](body))
        return ""

    def copy_files(self, host, sources, destination, *, timeout_seconds=0):
        if self.copy_failure:
            raise self.copy_failure
        self.copies.append((host, [Path(source).name for source in sources], destination))


class ProxyStepTests(base.PrepareTestCase):
    def setUp(self):
        super().setUp()
        ws = self.ws
        ws.lock["hosts"].update({"arc99x1": "10.250.0.13", "arc99x3": "10.250.0.12"})
        ws.lock["groth16"]["setup_manifest_sha256"] = "5" * 64
        self.lock_hash = "a" * 64
        output = ws.root / "proxy-out"
        for role, address, port in (("system", "10.250.0.13", 9998), ("user", "10.250.0.12", 9999)):
            package = output / role
            package.mkdir(parents=True)
            (package / "package.json").write_text(json.dumps(
                {"installer_sha256": ws.lock["tool_sha256"]["prepare_proxies.py"], "role": role}))
            (package / "rpc-endpoints.json").write_text(json.dumps(
                {"placement": {role: {"host": role + ".example", "listen_addr": f"{address}:{port}"}}}))
        (ws.state_dir / "prepare_packages.json").write_text(json.dumps({"proxy": str(output)}))
        self.remote = FakeRemote(ws)
        self.ctx = ws.context(self.remote)

    def request(self, role):
        nonce = json.loads((self.ws.state_dir / "start_proxies.json").read_text())["requests"][role]["nonce"]
        return proxy.request_digest(self.ctx, role, nonce)

    def good_report(self, host_role, **changes):
        document = {"lock_sha256": self.lock_hash, "request_sha256": self.request(host_role), "role": host_role,
                    "unit": self.ws.lock["units"]["proxy_prefix"] + host_role + ".service",
                    "pid": 4000 + len(host_role), "binary_sha256": self.ws.lock["binaries"]["psy_user_cli"]}
        document.update(changes)
        self.remote.pids[host_role] = document["pid"] if isinstance(document["pid"], int) else 1
        return document

    def pending(self):
        with self.assertRaises(OperatorPending) as raised:
            STEP.apply(self.ctx)
        return raised.exception

    def test_passwordless_hosts_take_the_command_through_the_remote(self):
        self.remote.sudo = "passwordless"
        self.remote.on_activate = lambda role: self.remote.reports.__setitem__(role, self.good_report(role))
        STEP.check(self.ctx)
        STEP.apply(self.ctx)
        self.assertEqual(self.remote.activations, ["system", "user"])
        STEP.apply(self.ctx)
        self.assertEqual(self.remote.activations, ["system", "user"])

    def test_pending_command_contains_lock_hash(self):
        STEP.check(self.ctx)
        pending = self.pending()
        self.assertEqual(pending.host, "arc99x1")
        self.assertIn(self.lock_hash, pending.command)
        self.assertIn(" activate ", pending.command)
        self.assertIn(self.request("system"), pending.command)
        self.assertEqual(pending.result_path, proxy.report_path(self.ctx, "system"))
        self.assertIn(" && sudo /usr/bin/python3 -I -B ", pending.command)
        self.assertIsNone(find_secret({"command": pending.command}))
        self.assertEqual([copy[0] for copy in self.remote.copies], ["arc99x1", "arc99x1"])
        self.assertTrue(any("psy-proxy-stage" in script for _, script in self.remote.scripts))

    def test_rerun_without_result_stays_pending(self):
        first = self.pending()
        copies = len(self.remote.copies)
        second = self.pending()
        self.assertEqual((second.host, second.command), (first.host, first.command))
        self.assertEqual(len(self.remote.copies), copies)

    def test_rerun_validates_operator_result_then_checks_rpc(self):
        self.pending()
        self.remote.reports["system"] = self.good_report("system")
        user = self.pending()
        self.assertEqual(user.host, "arc99x3")
        staged = len(self.remote.copies)
        self.remote.reports["user"] = self.good_report("user")
        STEP.apply(self.ctx)
        self.assertEqual(len(self.remote.copies), staged)
        for role in proxy.PROXY_ROLES:
            self.remote.answers[role] = self.rpc_answers(role)
        with unittest.mock.patch.object(proxy, "wait_until", side_effect=lambda ready, failure, *a: ready()):
            report = STEP.verify(self.ctx)
        self.assertEqual(sorted(report["proxies"]), ["system", "user"])
        self.assertIsNone(find_secret(report))
        self.assertEqual(set(self.remote.rpc), set([
            ("system", "psy_get_prove_proxy_role"), ("system", "psy_get_circuits_data"),
            ("user", "psy_get_prove_proxy_role"), ("user", "psy_prove_bridge_agg_groth16")]))
        self.assertFalse(any("proof" in name for name in report["proxies"]["system"]))

    def rpc_answers(self, role):
        def answer(body):
            method = body["method"]
            if method == "psy_get_prove_proxy_role":
                return {"result": {"role": role, "user_methods": role == "user", "system_methods": role == "system"}}
            if method == proxy.WRONG_ROLE_METHODS[role]:
                return {"error": {"code": -32601, "message": "not found"}}
            return {"result": "unexpected"}
        return answer

    def test_validated_host_is_never_staged_or_read_again(self):
        self.pending()
        self.remote.reports["system"] = self.good_report("system")
        self.pending()
        self.remote.copies.clear()
        self.remote.scripts.clear()
        self.pending()
        self.assertEqual([copy for copy in self.remote.copies if copy[0] == "arc99x1"], [])
        self.assertFalse(any(host == "arc99x1" and "echo missing" in script for host, script in self.remote.scripts))

    def test_stale_or_foreign_results_show_the_command_again(self):
        first = self.pending()
        for field, value in (("request_sha256", "0" * 64), ("lock_sha256", "b" * 64), ("role", "user"),
                             ("unit", "other.service"), ("binary_sha256", "c" * 64), ("pid", 0), ("pid", "7")):
            self.remote.reports["system"] = self.good_report("system", **{field: value})
            with self.subTest(field=field, value=value):
                self.assertEqual(self.pending().command, first.command)
        for broken in ({**self.good_report("system"), "extra": 1}, "not json"):
            self.remote.reports["system"] = broken
            self.assertEqual(self.pending().command, first.command)
        self.remote.reports["system"] = self.good_report("system")
        self.remote.restarts["system"] = 2
        self.assertEqual(self.pending().command, first.command)
        self.remote.restarts["system"] = 0
        self.remote.binary_hashes["system"] = "d" * 64
        self.assertEqual(self.pending().command, first.command)
        progress = json.loads((self.ws.state_dir / "start_proxies.json").read_text())
        self.assertEqual(progress["validated"], {})
        self.remote.binary_hashes.clear()
        self.assertEqual(self.pending().host, "arc99x3")

    def test_result_of_an_earlier_attempt_cannot_satisfy_a_new_request(self):
        self.pending()
        old = self.good_report("system")
        (self.ws.state_dir / "start_proxies.json").unlink()
        fresh = self.pending()
        self.remote.reports["system"] = old
        self.assertEqual(self.pending().command, fresh.command)
        self.assertEqual(json.loads((self.ws.state_dir / "start_proxies.json").read_text())["validated"], {})

    def test_validated_host_is_checked_live_and_never_restarted(self):
        self.prepare_verified()
        scripts = len(self.remote.scripts)
        STEP.apply(self.ctx)
        self.assertTrue(all("enable" not in script and "restart" not in script for _, script in self.remote.scripts[scripts:]))
        self.remote.restarts["user"] = 1
        with self.assertRaisesRegex(ValueError, "user: unit is not active.*nothing was restarted"):
            STEP.apply(self.ctx)
        self.remote.restarts["user"] = 0
        self.remote.binary_hashes["system"] = "e" * 64
        with self.assertRaisesRegex(ValueError, "system: installed binary differs"):
            STEP.apply(self.ctx)

    def test_command_checks_the_tool_hash_before_sudo(self):
        pending = self.pending()
        tool = self.ws.lock["tool_sha256"]["prepare_proxies.py"]
        head, tail = pending.command.split(" && ", 1)
        self.assertTrue(head.startswith(f"echo '{tool}  ") and head.endswith("| sha256sum -c -"))
        self.assertTrue(tail.startswith("sudo /usr/bin/python3 -I -B "))

    def test_stage_happens_before_the_request_is_recorded_and_pending_raised(self):
        self.remote.copy_failure = RemoteError("copy failed", host="arc99x1", exit_code=1)
        with self.assertRaises(RemoteError):
            STEP.apply(self.ctx)
        self.assertFalse((self.ws.state_dir / "start_proxies.json").exists())
        self.remote.copy_failure = None
        self.pending()
        self.assertTrue(self.remote.copies)

    def test_connection_loss_is_not_read_as_a_missing_result(self):
        self.pending()
        with unittest.mock.patch.object(self.remote, "run_script",
                                        side_effect=RemoteConnectionError("down", host="arc99x1", exit_code=255)):
            with self.assertRaises(RemoteConnectionError):
                STEP.apply(self.ctx)

    def test_progress_of_another_lock_is_refused(self):
        self.pending()
        path = self.ws.state_dir / "start_proxies.json"
        document = json.loads(path.read_text())
        document["lock_sha256"] = "d" * 64
        path.write_text(json.dumps(document))
        with self.assertRaisesRegex(ValueError, "another release lock"):
            STEP.apply(self.ctx)

    def prepare_verified(self):
        self.pending()
        self.remote.reports["system"] = self.good_report("system")
        self.pending()
        self.remote.reports["user"] = self.good_report("user")
        STEP.apply(self.ctx)

    def verify(self):
        with unittest.mock.patch.object(proxy, "wait_until", side_effect=lambda ready, failure, *a: ready()):
            return STEP.verify(self.ctx)

    def test_startup_panic_stops_the_wait(self):
        self.prepare_verified()
        self.remote.panicked.add("system")
        self.remote.answers = {"system": lambda body: (_ for _ in ()).throw(RemoteError("refused", host="arc99x1", exit_code=7)),
                               "user": self.rpc_answers("user")}
        with self.assertRaisesRegex(RuntimeError, "startup failure"):
            with unittest.mock.patch.object(proxy.time if hasattr(proxy, "time") else __import__("time"), "sleep"):
                STEP.verify(self.ctx)

    def test_verify_checks_role_and_opposite_method(self):
        self.prepare_verified()
        wrong_role = {"result": {"role": "user", "user_methods": True, "system_methods": False}}
        self.remote.answers = {"system": lambda body: wrong_role, "user": self.rpc_answers("user")}
        with self.assertRaisesRegex(ValueError, "role answer differs"):
            self.verify()
        serving_both = self.rpc_answers("system")
        self.remote.answers["system"] = lambda body: (
            {"result": "served"} if body["method"] == proxy.WRONG_ROLE_METHODS["system"] else serving_both(body))
        with self.assertRaisesRegex(ValueError, "opposite-role method is served"):
            self.verify()

    def test_check_cross_checks_hosts_against_the_placement(self):
        STEP.check(self.ctx)
        self.ws.lock["hosts"]["arc99x3"] = "10.250.0.99"
        with self.assertRaisesRegex(ValueError, "user placement listens on an address that is not arc99x3"):
            STEP.check(self.ctx)
        self.ws.lock["hosts"]["arc99x3"] = "10.250.0.12"
        STEP.check(self.ctx)

    def test_check_requires_pinned_setup_and_reviewed_tool(self):
        self.ws.lock["groth16"]["setup_manifest_sha256"] = ""
        with self.assertRaisesRegex(ValueError, "setup_manifest_sha256 is not pinned"):
            STEP.check(self.ctx)
        self.ws.lock["groth16"]["setup_manifest_sha256"] = "5" * 64
        approval = self.ws.root / "proxy-out" / "user" / "package.json"
        approval.write_text(json.dumps({"installer_sha256": "e" * 64}))
        with self.assertRaisesRegex(ValueError, "user package installer differs"):
            STEP.check(self.ctx)

    def test_step_is_a_cutover_step_named_for_the_table(self):
        self.assertTrue(STEP.cutover)
        self.assertEqual(list(proxy.PROXY_STEPS), ["start_proxies"])


def real_shaped_manifest(binary_hash, relayer_hash, config_hash, runtime):
    """Shape of build_runtime.py output, including the library table keyed by absolute local paths."""
    return {"binaries": {"psy_dev_cli": "1" * 64, "psy_node_cli": "2" * 64, "psy_relayer_cli": relayer_hash,
                         "psy_user_cli": binary_hash, "psy_worker_cli": "3" * 64},
            "build_network": "none", "network": "testnet", "network_magic": "0x1337CF514544CF69",
            "config_sha256": config_hash, "local_circuits_sha256": "4" * 64, "source_commit": runtime,
            "source_directory": "/home/someone/psy-node-runtime", "environment": {"CARGO_HOME": "/home/someone/.cargo"},
            "release_libraries": {f"/home/someone/target/release/deps/{name}-0123.rlib": "5" * 64
                                  for name in ("libaddr2line", "librpassword", "libsecret_service", "libtokio")}}


class ProxyPackageBuilderTests(base.PrepareTestCase):
    def setUp(self):
        super().setUp()
        ws = self.ws
        self.build_dir = ws.root / "build"
        self.build_dir.mkdir()
        self.binary = self.build_dir / "psy_user_cli"
        self.binary.write_bytes(b"user cli")
        ws.lock["binaries"]["psy_user_cli"] = base.sha(b"user cli")
        ws.lock["groth16"]["setup_manifest_sha256"] = "5" * 64
        ws.put_file("config", b"config", pin=lambda digest: None)
        ws.put_file("groth16_setup_manifest", b"setup", pin=lambda digest: None)
        self.manifest = real_shaped_manifest(base.sha(b"user cli"), "6" * 64, base.sha(b"config"),
                                             ws.lock["sources"]["runtime"])
        (self.build_dir / "manifest.json").write_text(json.dumps(self.manifest))
        (ws.state_dir / "rebuild_binaries.json").write_text(json.dumps({"build_dir": str(self.build_dir)}))
        ws.set_artifacts(proxy_packages={"rpc_endpoints_sha256": "6" * 64})
        self.inputs = {"rpc_endpoints": str(ws.root / "rpc.json"), "setup_dir": str(ws.root / "setup"),
                       "verifier_dir": str(ws.root / "verifiers"), "output": str(ws.root / "proxy-out")}
        ws.local["packages"] = {"proxy": self.inputs}
        ws.write_local()

    def test_proxy_builder_is_registered_after_core(self):
        names = [builder.name for builder in prepare.PACKAGE_BUILDERS]
        self.assertEqual(names[:2], ["core", "proxy"])

    def test_build_packages_both_roles_from_the_lock(self):
        calls = []
        def runner(argv, timeout=None):
            calls.append(argv)
            Path(argv[argv.index("--output") + 1]).mkdir()
            return base.done(0, "{}")
        with unittest.mock.patch.object(prepare, "run_local", runner):
            output = prepare.proxy_build(self.ws.context(), self.inputs)
        self.assertEqual(sorted(path.name for path in output.iterdir()), ["system", "user"])
        system, user = calls
        self.assertEqual(system[system.index("--setup-manifest-sha256") + 1], "5" * 64)
        self.assertEqual(system[system.index("--rpc-endpoints-sha256") + 1], "6" * 64)
        self.assertNotIn("--setup-dir", user)
        self.assertEqual(system[system.index("--source-commit") + 1], self.ws.lock["sources"]["runtime"])
        self.assertEqual(system[system.index("--release-lock-sha256") + 1], "a" * 64)

    def test_the_tool_receives_a_narrow_build_document_that_passes_its_secret_scan(self):
        calls = []
        def runner(argv, timeout=None):
            calls.append(argv)
            Path(argv[argv.index("--output") + 1]).mkdir()
            return base.done(0, "{}")
        with unittest.mock.patch.object(prepare, "run_local", runner):
            prepare.proxy_build(self.ws.context(), self.inputs)
        build_file = Path(calls[0][calls[0].index("--binary-manifest") + 1])
        self.assertEqual(calls[0][calls[0].index("--binary-manifest-sha256") + 1], base.sha(build_file.read_bytes()))
        document = json.loads(build_file.read_text())
        self.assertEqual(sorted(document), ["binaries", "config_sha256", "local_circuits_sha256", "network", "source_commit"])
        self.assertNotIn("/home/", json.dumps(document))
        tool = importlib.util.spec_from_file_location("prepare_proxies", Path(prepare.__file__).with_name("prepare_proxies.py"))
        module = importlib.util.module_from_spec(tool)
        tool.loader.exec_module(module)
        with self.assertRaises(module.ProxyError):
            module.validate_public(self.manifest)
        module.validate_public(document)
        self.assertEqual(document["binaries"]["psy_user_cli"], self.manifest["binaries"]["psy_user_cli"])

    @unittest.skipUnless(REAL_MANIFEST.is_file(), "set PSY_REAL_RUNTIME_MANIFEST to a real runtime build record")
    def test_real_runtime_build_record_narrows_to_a_valid_document(self):
        document = prepare.narrow_build_document(json.loads(REAL_MANIFEST.read_text()))
        tool = importlib.util.spec_from_file_location("prepare_proxies", Path(prepare.__file__).with_name("prepare_proxies.py"))
        module = importlib.util.module_from_spec(tool)
        tool.loader.exec_module(module)
        module.validate_public(document)
        with self.assertRaises(module.ProxyError):
            module.validate_public(json.loads(REAL_MANIFEST.read_text()))

    def test_build_refuses_unpinned_endpoints_and_changed_binary(self):
        pins = json.loads((self.ws.release_dir / "artifacts.json").read_text())["proxy_packages"]
        self.ws.set_artifacts(proxy_packages={})
        with self.assertRaisesRegex(ValueError, "rpc_endpoints_sha256 is not pinned"):
            prepare.proxy_check(self.ws.context(), self.inputs)
        self.ws.set_artifacts(proxy_packages=pins)
        self.binary.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "user binary differs from the lock"):
            prepare.proxy_build(self.ws.context(), self.inputs)
        self.assertFalse((self.ws.root / "proxy-out.partial").exists())

    def test_proxy_verify_reads_each_role_package_back(self):
        output = self.ws.root / "proxy-out"
        for role in prepare.PROXY_ROLES:
            (output / role).mkdir(parents=True)
            (output / role / "package.json").write_text(json.dumps(
                {"installer_sha256": self.ws.lock["tool_sha256"]["prepare_proxies.py"]}))
        calls = []
        def runner(argv, timeout=None):
            calls.append(argv)
            return base.done(0, "{}")
        with unittest.mock.patch.object(prepare, "run_local", runner):
            reports = prepare.proxy_verify(self.ws.context(), self.inputs, output)
        self.assertEqual(sorted(reports), ["system", "user"])
        self.assertEqual([call[3] for call in calls], ["verify", "verify"])
        self.assertEqual(reports["user"]["package_sha256"], base.sha((output / "user" / "package.json").read_bytes()))
        (output / "user" / "package.json").write_text(json.dumps({"installer_sha256": "f" * 64}))
        with unittest.mock.patch.object(prepare, "run_local", runner), \
                self.assertRaisesRegex(ValueError, "user package installer differs"):
            prepare.proxy_verify(self.ws.context(), self.inputs, output)
        with unittest.mock.patch.object(prepare, "run_local", return_value=base.done(1, "", "boom")), \
                self.assertRaises(RuntimeError):
            prepare.proxy_verify(self.ws.context(), self.inputs, output)
        (output / "extra").mkdir()
        with self.assertRaisesRegex(ValueError, "roles differ"):
            prepare.proxy_verify(self.ws.context(), self.inputs, output)


if __name__ == "__main__":
    unittest.main()
