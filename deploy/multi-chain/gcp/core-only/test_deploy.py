import atexit
import contextlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock

import deploy
import deploy_remote
from deploy_remote import DeployContext, OperatorPending, Step
import test_release_lock

HERE = Path(__file__).resolve().parent
KEY_DIR = tempfile.mkdtemp()
atexit.register(shutil.rmtree, KEY_DIR, True)
KEY_FILE = str(Path(KEY_DIR) / "key")
Path(KEY_FILE).write_text("fixture\n")
ACCESS = {
    "known_hosts": "/priv/known_hosts",
    "hosts": {alias: {"ssh": f"ubuntu@10.0.0.{index}", "identity": KEY_FILE, "jump": None, "sudo": "passwordless"}
              for index, alias in enumerate(("gcp-test-cp", "gcp-test-services"), start=2)},
}


def noop(ctx):
    return None


def make_step(name, **overrides):
    fields = {"check": noop, "apply": noop, "verify": lambda ctx: {"ok": True}}
    fields.update(overrides)
    return Step(name=name, **fields)


def build_workspace(root, access=None, lock_edit=None):
    release_dir = root / "release"
    private_dir = root / "private"
    release_dir.mkdir()
    private_dir.mkdir()
    lock = test_release_lock.build_test_lock(release_dir, private_dir)
    if lock_edit:
        lock_edit(lock)
    (release_dir / "release-lock.json").write_text(json.dumps(lock))
    access_file = root / "access.json"
    access_file.write_text(json.dumps(ACCESS if access is None else access))
    run_dir = root / "run"
    run_dir.mkdir()
    steps_file = root / "steps.tsv"
    steps_file.write_text("50\tpy:alpha\tplain\n51\tpy:fake\tplain\n60\tpy-cutover:cutover_alpha\tcutover\n")
    return release_dir, private_dir, access_file, run_dir, steps_file


class DeployTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.calls = []

    def argv(self, step, *extra, workspace=None):
        release_dir, private_dir, access_file, run_dir, steps_file = (
            workspace or build_workspace(Path(tempfile.mkdtemp(dir=self.root))))
        self.run_dir, self.private_dir = run_dir, private_dir
        return [step, "--release-dir", str(release_dir), "--access", str(access_file), "--run-dir", str(run_dir),
                "--private-dir", str(private_dir), "--steps-file", str(steps_file), *extra]

    def run_main(self, argv, registry, environ=None):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                unittest.mock.patch.dict(os.environ, environ or {}):
            code = deploy.main(argv, registry=registry)
        return code, out.getvalue(), err.getvalue()

    @staticmethod
    def table_registry():
        return {"alpha": make_step("alpha"), "fake": make_step("fake"),
                "cutover_alpha": make_step("cutover_alpha", cutover=True)}

    def recording(self, name, **overrides):
        def record(label):
            return lambda ctx: self.calls.append(label)
        return make_step(name, check=record("check"), apply=record("apply"),
                         verify=lambda ctx: (self.calls.append("verify"), {"ok": True})[1], **overrides)

    def test_unknown_step_exits_nonzero(self):
        code, _, err = self.run_main(self.argv("nope"), {"known": make_step("known")})
        self.assertEqual(code, 2)
        self.assertIn("no registered step: nope", err)

    def test_empty_registry_fails_clearly(self):
        code, _, err = self.run_main(self.argv("verify_release"), {})
        self.assertEqual(code, 2)
        self.assertIn("no registered step: verify_release", err)

    def test_success_runs_check_apply_verify_in_order(self):
        step = self.recording("alpha")
        code, _, _ = self.run_main(self.argv("alpha"), {"alpha": step})
        self.assertEqual(code, 0)
        self.assertEqual(self.calls, ["check", "apply", "verify"])

    def test_check_failure_skips_apply(self):
        def failing_check(ctx):
            self.calls.append("check")
            raise RuntimeError("precondition missing")
        step = make_step("alpha", check=failing_check, apply=lambda ctx: self.calls.append("apply"))
        code, _, err = self.run_main(self.argv("alpha"), {"alpha": step})
        self.assertEqual(code, 1)
        self.assertEqual(self.calls, ["check"])
        self.assertIn("precondition missing", err)
        self.assertFalse((self.run_dir / "alpha.json").exists())

    def test_verify_failure_is_step_failure(self):
        def failing_verify(ctx):
            raise RuntimeError("not healthy")
        code, _, err = self.run_main(self.argv("alpha"), {"alpha": make_step("alpha", verify=failing_verify)})
        self.assertEqual(code, 1)
        self.assertIn("not healthy", err)
        self.assertFalse((self.run_dir / "alpha.json").exists())

    def test_operator_pending_prints_command_and_exits_3(self):
        def pending(ctx):
            raise OperatorPending("x1", "sudo /opt/stage/install.py --sha256 abc123", "/var/lib/stage/result.json")
        code, out, _ = self.run_main(self.argv("alpha"), {"alpha": make_step("alpha", apply=pending)})
        self.assertEqual(code, 3)
        self.assertIn("sudo /opt/stage/install.py --sha256 abc123", out)
        self.assertIn("x1", out)
        self.assertIn("/var/lib/stage/result.json", out)
        self.assertFalse((self.run_dir / "alpha.json").exists())

    def test_verify_result_written_without_secret_fields(self):
        step = make_step("alpha", verify=lambda ctx: {"checkpoint": 5, "hosts": ["a"]})
        code, _, _ = self.run_main(self.argv("alpha"), {"alpha": step})
        self.assertEqual(code, 0)
        path = self.run_dir / "alpha.json"
        self.assertEqual(json.loads(path.read_text()), {"checkpoint": 5, "hosts": ["a"]})
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_verify_result_with_secret_key_or_url_is_refused_not_stripped(self):
        for result in ({"nested": {"db_password": "x"}}, {"urls": ["postgres://user:pw@h/db"]},
                       {"signer": {"Private_Key": "1"}}):
            code, _, err = self.run_main(self.argv("alpha"), {"alpha": make_step("alpha", verify=lambda ctx, r=result: r)})
            self.assertEqual(code, 1)
            self.assertIn("verify result refused", err)
            self.assertNotIn("pw@h", err)
            self.assertFalse((self.run_dir / "alpha.json").exists())

    def test_verify_must_return_a_dict(self):
        code, _, err = self.run_main(self.argv("alpha"), {"alpha": make_step("alpha", verify=lambda ctx: None)})
        self.assertEqual(code, 1)
        self.assertIn("dict", err)

    def test_context_has_required_fields_and_private_state_dir(self):
        seen = {}
        def check(ctx):
            seen["ctx"] = ctx
        code, _, _ = self.run_main(self.argv("alpha"), {"alpha": make_step("alpha", check=check)})
        ctx = seen["ctx"]
        self.assertIsInstance(ctx, DeployContext)
        self.assertEqual(ctx.state_dir, self.private_dir / "state")
        self.assertEqual(ctx.state_dir.stat().st_mode & 0o777, 0o700)
        self.assertEqual(ctx.run_dir, self.run_dir)
        self.assertEqual(len(ctx.lock_sha256), 64)
        self.assertEqual(ctx.lock["release_id"], "core-testnet-20260101-sd192")
        self.assertIsInstance(ctx.remote, deploy_remote.Remote)

    def test_alias_missing_from_access_fails_before_any_step_runs(self):
        access = {"known_hosts": "/k", "hosts": {"gcp-test-cp": ACCESS["hosts"]["gcp-test-cp"]}}
        workspace = build_workspace(self.root, access=access)
        code, _, err = self.run_main(self.argv("alpha", workspace=workspace), {"alpha": self.recording("alpha")})
        self.assertEqual(code, 1)
        self.assertIn("gcp-test-services", err)
        self.assertEqual(self.calls, [])

    def test_incomplete_lock_fails_a_step_that_requires_complete(self):
        workspace = build_workspace(self.root, lock_edit=lambda lock: lock["sources"].update(services=""))
        code, _, err = self.run_main(self.argv("alpha", workspace=workspace), {"alpha": self.recording("alpha")})
        self.assertEqual(code, 1)
        self.assertIn("release lock incomplete", err)
        self.assertEqual(self.calls, [])

    def test_incomplete_lock_is_accepted_by_a_partial_step(self):
        workspace = build_workspace(self.root, lock_edit=lambda lock: lock["sources"].update(services=""))
        step = self.recording("alpha", requires_complete=False)
        code, _, _ = self.run_main(self.argv("alpha", workspace=workspace), {"alpha": step})
        self.assertEqual(code, 0)

    def test_lock_that_fails_validation_stops_everything(self):
        workspace = build_workspace(self.root, lock_edit=lambda lock: lock.update(release_id="other"))
        code, _, err = self.run_main(self.argv("alpha", workspace=workspace), {"alpha": self.recording("alpha")})
        self.assertEqual(code, 1)
        self.assertEqual(self.calls, [])

    def test_plan_validates_but_runs_no_phase(self):
        registry = {**self.table_registry(), "alpha": self.recording("alpha")}
        code, out, _ = self.run_main(self.argv("alpha", "--plan"), registry)
        self.assertEqual(code, 0)
        self.assertEqual(self.calls, [])
        self.assertIn("alpha", out)

    def test_plan_reports_steps_tsv_entries_without_a_module(self):
        workspace = build_workspace(self.root)
        code, _, err = self.run_main(self.argv("alpha", "--plan", workspace=workspace), {"alpha": make_step("alpha")})
        self.assertEqual(code, 1)
        self.assertIn("no registered module for step: fake, cutover_alpha", err)

    def test_plan_passes_when_the_whole_table_is_registered(self):
        registry = self.table_registry()
        code, _, _ = self.run_main(self.argv("alpha", "--plan"), registry)
        self.assertEqual(code, 0)

    def test_plan_with_a_missing_step_table_is_an_error(self):
        workspace = build_workspace(self.root)
        workspace[4].unlink()
        code, _, err = self.run_main(self.argv("alpha", "--plan", workspace=workspace),
                                     {"alpha": make_step("alpha")})
        self.assertEqual(code, 1)
        self.assertIn("step table not found", err)

    def test_plan_of_an_unknown_step_or_bad_lock_fails(self):
        registry = self.table_registry()
        self.assertEqual(self.run_main(self.argv("nope", "--plan"), registry)[0], 2)
        workspace = build_workspace(self.root, lock_edit=lambda lock: lock.update(release_id="other"))
        self.assertEqual(self.run_main(self.argv("alpha", "--plan", workspace=workspace), registry)[0], 1)

    def test_missing_steps_tsv_module_is_a_named_gap(self):
        tsv = Path(self.root) / "gap.tsv"
        tsv.write_text("50\tpy:alpha\td\n51\tpy:beta\td\n")
        self.assertEqual(deploy.unregistered_steps(tsv, {"alpha": make_step("alpha")}), ["beta"])

    def test_merge_steps_rejects_duplicates(self):
        with self.assertRaisesRegex(ValueError, "duplicate step: alpha"):
            deploy.merge_steps([{"alpha": make_step("alpha")}, {"alpha": make_step("alpha")}])

    def test_merge_steps_rejects_key_name_mismatch(self):
        with self.assertRaisesRegex(ValueError, "step name differs from its key"):
            deploy.merge_steps([{"alpha": make_step("beta")}])

    def test_registry_loads_modules_and_fails_on_duplicate_names(self):
        module_dir = Path(self.root) / "mods"
        module_dir.mkdir()
        body = ("from deploy_remote import Step\n_n = lambda ctx: None\n"
                "{0}_STEPS = {{'dup': Step('dup', _n, _n, lambda ctx: {{}})}}\n")
        (module_dir / "mod_one.py").write_text(body.format("ONE"))
        (module_dir / "mod_two.py").write_text(body.format("TWO"))
        sys.path.insert(0, str(module_dir))
        self.addCleanup(lambda: sys.path.remove(str(module_dir)))
        self.addCleanup(lambda: [sys.modules.pop(n, None) for n in ("mod_one", "mod_two")])
        self.assertEqual(set(deploy.build_registry(("mod_one",))), {"dup"})
        with self.assertRaisesRegex(ValueError, "duplicate step: dup"):
            deploy.build_registry(("mod_one", "mod_two"))

    def test_default_registry_builds_from_the_shipped_module_list(self):
        registry = deploy.build_registry()
        self.assertEqual(set(registry), {step.name for step in registry.values()})
        self.assertEqual(deploy.build_registry(()), {})

    def test_apply_failure_skips_verify(self):
        def failing_apply(ctx):
            raise RuntimeError("apply broke")
        step = make_step("alpha", apply=failing_apply, verify=lambda ctx: self.calls.append("verify") or {})
        code, _, err = self.run_main(self.argv("alpha"), {"alpha": step})
        self.assertEqual(code, 1)
        self.assertEqual(self.calls, [])
        self.assertIn("apply broke", err)

    def test_system_exit_from_a_step_is_a_failure_not_success_or_pending(self):
        for phase in ("check", "apply", "verify"):
            for status in (0, 3, 1, "message"):
                def leave(ctx, status=status):
                    raise SystemExit(status)
                step = make_step("alpha", **{phase: leave})
                code, out, err = self.run_main(self.argv("alpha"), {"alpha": step})
                self.assertEqual(code, 1, (phase, status))
                self.assertNotIn("PENDING", out)
                self.assertIn("exited with status", err)
                self.assertFalse((self.run_dir / "alpha.json").exists())

    def test_verify_is_not_skipped_silently_after_system_exit_zero_from_apply(self):
        def leave(ctx):
            raise SystemExit(0)
        step = make_step("alpha", apply=leave, verify=lambda ctx: self.calls.append("verify") or {})
        self.assertEqual(self.run_main(self.argv("alpha"), {"alpha": step})[0], 1)
        self.assertEqual(self.calls, [])

    def test_error_text_is_redacted(self):
        for error in (subprocess.CalledProcessError(1, ["x", "--password=hunter2"]),
                      subprocess.TimeoutExpired(["x", "token=hunter2"], 5),
                      RuntimeError("login failed password=hunter2")):
            def boom(ctx, error=error):
                raise error
            code, _, err = self.run_main(self.argv("alpha"), {"alpha": make_step("alpha", apply=boom)})
            self.assertEqual(code, 1)
            self.assertNotIn("hunter2", err)

    def test_unwritable_run_dir_fails_before_check(self):
        workspace = build_workspace(self.root)
        shutil.rmtree(workspace[3])
        step = self.recording("alpha")
        code, _, err = self.run_main(self.argv("alpha", workspace=workspace), {"alpha": step})
        self.assertEqual(code, 1)
        self.assertEqual(self.calls, [])
        self.assertIn("run directory", err)

    def test_cutover_step_refuses_without_both_confirmations(self):
        step = self.recording("cutover_alpha", cutover=True)
        workspace = build_workspace(self.root)
        gates = deploy.CUTOVER_CONFIRMATIONS
        env_without = {name: "" for name in gates}
        for environ in (env_without, {gates[0]: "1", gates[1]: ""}, {gates[0]: "", gates[1]: "1"},
                        {gates[0]: "1", gates[1]: "yes"}):
            code, _, err = self.run_main(self.argv("cutover_alpha", workspace=workspace),
                                         {"cutover_alpha": step}, environ=environ)
            self.assertEqual(code, 1, environ)
            self.assertIn("CONFIRM_FULL_FRESH_DEPLOY", err)
        self.assertEqual(self.calls, [])
        code, _, _ = self.run_main(self.argv("cutover_alpha", workspace=workspace), {"cutover_alpha": step},
                                   environ={name: "1" for name in gates})
        self.assertEqual(code, 0)
        self.assertEqual(self.calls, ["check", "apply", "verify"])

    def test_cutover_plan_needs_no_confirmation_and_prepare_step_needs_none(self):
        registry = self.table_registry()
        gates = {name: "" for name in deploy.CUTOVER_CONFIRMATIONS}
        self.assertEqual(self.run_main(self.argv("cutover_alpha", "--plan"), registry, environ=gates)[0], 0)
        self.assertEqual(self.run_main(self.argv("alpha"), registry, environ=gates)[0], 0)

    def test_table_type_must_agree_with_the_cutover_flag(self):
        # a cutover step registered as plain, and a plain step registered as cutover, are both refused
        for name, flag in (("cutover_alpha", False), ("alpha", True)):
            step = self.recording(name, cutover=flag)
            code, _, err = self.run_main(self.argv(name), {name: step}, environ={
                var: "1" for var in deploy.CUTOVER_CONFIRMATIONS})
            self.assertEqual(code, 1)
            self.assertIn("differs from the cutover flag", err)
            self.assertEqual(self.calls, [])
        registry = {**self.table_registry(), "alpha": make_step("alpha", cutover=True)}
        code, _, err = self.run_main(self.argv("alpha", "--plan"), registry)
        self.assertEqual(code, 1)
        self.assertIn("differs from the cutover flag of: alpha", err)

    def test_module_exiting_at_import_is_a_failure(self):
        with unittest.mock.patch.object(deploy, "build_registry", side_effect=SystemExit(0)):
            code, _, err = self.run_main(self.argv("alpha"), None)
        self.assertEqual(code, 1)
        self.assertIn("exited with status 0", err)

    def test_refusal_message_is_redacted(self):
        code, _, err = self.run_main(self.argv("alpha"), {"alpha": make_step(
            "alpha", verify=lambda ctx: {"nested": {"db_password": "hunter2"}, "DB_PASSWORD=hunter2": 1})})
        self.assertEqual(code, 1)
        self.assertNotIn("hunter2", err)
        self.assertNotIn("db_password", err)

    def test_step_missing_from_the_step_table_is_refused(self):
        workspace = build_workspace(self.root)
        code, _, err = self.run_main(self.argv("ghost", workspace=workspace), {"ghost": make_step("ghost")})
        self.assertEqual(code, 1)
        self.assertIn("not in the step table", err)

    def test_swapped_jump_target_stops_before_any_step(self):
        access = json.loads(json.dumps(ACCESS))
        access["hosts"]["gcp-test-services"].update(jump="gcp-test-cp", ssh="ubuntu@10.9.9.9")
        workspace = build_workspace(self.root, access=access)
        code, _, err = self.run_main(self.argv("alpha", workspace=workspace), {"alpha": self.recording("alpha")})
        self.assertEqual(code, 1)
        self.assertEqual(self.calls, [])
        self.assertIn("target differs", err)

    def test_operator_pending_from_a_separately_imported_module_exits_3_through_the_cli(self):
        # deploy.py runs as __main__, so a step module must raise the class owned by deploy_remote.
        bundle = Path(self.root) / "bundle"
        bundle.mkdir()
        for name in ("deploy_remote.py", "release_lock.py"):
            shutil.copy(HERE / name, bundle / name)
        source = (HERE / "deploy.py").read_text()
        injected, count = re.subn(r"(?m)^STEP_MODULES = .*$", 'STEP_MODULES = ("fake_step_module",)', source)
        self.assertEqual(count, 1)
        (bundle / "deploy.py").write_text(injected)
        (bundle / "fake_step_module.py").write_text(
            "from deploy_remote import OperatorPending, Step\n"
            "def _noop(ctx):\n    return None\n"
            "def _apply(ctx):\n    raise OperatorPending('x1', 'sudo /opt/i.py --sha256 abc', '/r.json')\n"
            "FAKE_STEPS = {'fake': Step('fake', _noop, _apply, lambda ctx: {})}\n")
        workspace = build_workspace(self.root)
        argv = [sys.executable, "-u", str(bundle / "deploy.py"), "fake", "--release-dir", str(workspace[0]),
                "--access", str(workspace[2]), "--run-dir", str(workspace[3]), "--private-dir", str(workspace[1]), "--steps-file", str(workspace[4])]
        env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
        done = subprocess.run(argv, capture_output=True, text=True, cwd=bundle, env=env, timeout=60)
        self.assertEqual(done.returncode, 3, done.stdout + done.stderr)
        self.assertIn("sudo /opt/i.py --sha256 abc", done.stdout)


if __name__ == "__main__":
    unittest.main()
