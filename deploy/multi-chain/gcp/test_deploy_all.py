"""deploy_all.sh step types and PENDING handling, run against a stub tree; no SSH."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "deploy_all.sh"
SD192_STEPS = HERE / "fresh-192-20261030" / "steps.tsv"

STUB_DEPLOY = """#!/usr/bin/env python3
import json, os, sys
with open(os.path.join(os.environ["STUB_LOG_DIR"], "calls.jsonl"), "a") as f:
    f.write(json.dumps({"argv": sys.argv[1:], "regen": "REGENERATE_GENESIS" in os.environ,
        "leaked": [k for k in ("REGENERATE_GENESIS", "PARTH_ALLOW_GENESIS_OVERWRITE") if k in os.environ],
        "confirm": "CONFIRM_FULL_FRESH_DEPLOY" in os.environ}) + "\\n")
step = sys.argv[1]
print("stub " + step)
sys.exit(int(os.environ.get("STUB_EXIT_" + step, "0")))
"""

PY_TABLE = (
    "50\tpy:verify_release\tverify\n"
    "51\tpy:check_hosts\tcheck\n"
    "60\tpy-cutover:fence_ingress\tfence\n"
    "62\tpy-cutover:stop_operator_hosts\toperator\n"
    "63\tpy-cutover:clear_node_state\tclear\n"
)
CONFIRMS = {
    "CONFIRM_MULTICHAIN_REPLACES_CURRENT_STAGING": "1",
    "CONFIRM_FULL_FRESH_DEPLOY": "1",
}


EXPECTED_PAIRS = (
    ("50", "py:verify_release"), ("51", "py:rebuild_binaries"), ("52", "py:verify_artifacts"),
    ("53", "py:prepare_packages"), ("54", "py:plan_bridge_packages"), ("55", "py:check_hosts"),
    ("60", "py-cutover:fence_ingress"), ("61", "py-cutover:stop_services"),
    ("62", "py-cutover:stop_operator_hosts"), ("63", "py-cutover:clear_node_state"),
    ("64", "py-cutover:rebuild_databases"), ("65", "py-cutover:start_core"),
    ("66", "py-cutover:start_workers"), ("67", "py-cutover:gate_l2_stability"),
    ("68", "py-cutover:start_proxies"), ("69", "py-cutover:deploy_l1"),
    ("70", "py-cutover:prepare_bridge_packages"), ("71", "py-cutover:start_guardians"),
    ("72", "py-cutover:start_envio"), ("73", "py-cutover:start_services"),
    ("74", "py-cutover:start_relayer"), ("75", "py-cutover:open_ingress"),
    ("76", "py-cutover:start_faucet"), ("80", "py:accept_entrypoints"),
    ("81", "py:accept_p2p_rotation"), ("82", "py:accept_faucet_batch"),
    ("83", "py:accept_five_withdrawals"), ("84", "py:accept_three_chains"),
    ("85", "py:deploy_monitoring"),
)


class World:
    def __init__(self, root, steps_text, shell=False):
        self.root = Path(root)
        self.gcp = self.root / "deploy" / "multi-chain" / "gcp"
        self.release = self.root / "release"
        self.logs = self.root / "logs"
        for d in (self.gcp, self.release, self.logs, self.root / "deploy/gcp/lib",
                  self.root / "deploy/gcp/fresh-staging"):
            d.mkdir(parents=True, exist_ok=True)
        shutil.copy(SCRIPT, self.gcp / "deploy_all.sh")
        (self.gcp / "config.env").write_text("")
        (self.gcp / "source-versions.env").write_text("")
        (self.root / "deploy/gcp/lib/multichain.sh").write_text("multichain_require_runtime() { :; }\n")
        marker = '#!/usr/bin/env bash\necho "$(basename "$0") $*" >> "$STUB_LOG_DIR/shell.log"\n'
        for name in ("prepare-sources.sh", "preflight.sh", "deploy-monitoring.sh"):
            (self.gcp / name).write_text(marker)
        (self.root / "deploy/gcp/fresh-staging/preflight.sh").write_text(marker)
        if shell:
            (self.root / "deploy/gcp/fresh-staging/01_one.sh").write_text(marker)
            (self.root / "deploy/gcp/fresh-staging/32_deploy_monitoring.sh").write_text(
                '#!/usr/bin/env bash\necho monitoring-step\nexit "${STUB_EXIT_32:-0}"\n')
        self.steps = self.root / "steps.tsv"
        self.steps.write_text(steps_text)
        (self.gcp / "core-only").mkdir(exist_ok=True)
        (self.gcp / "core-only" / "deploy.py").write_text(STUB_DEPLOY)
        self.access = self.root / "access.conf"
        self.access.write_text("")
        self.private = self.root / "private"
        self.private.mkdir(exist_ok=True)

    def env(self, extra=None, confirm=False, configured=True):
        # Confirmations are only ever set here, in the invoking environment.
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(("DEPLOY_", "CONFIRM_", "GCP_", "SKIP_", "STUB_"))
               and k not in ("DRY_RUN", "REGENERATE_GENESIS")}
        env.update(STUB_LOG_DIR=str(self.logs), DEPLOY_STEPS_FILE=str(self.steps),
                   DEPLOY_RELEASE_DIR=str(self.release),
                   GCP_DEPLOY_CONFIG=str(self.gcp / "config.env"))
        if configured:
            env.update(DEPLOY_ACCESS_FILE=str(self.access), DEPLOY_PRIVATE_DIR=str(self.private))
        if confirm:
            env.update(CONFIRMS)
        env.update(extra or {})
        return env

    def run(self, *args, **kw):
        before = set(self.run_dirs())
        result = subprocess.run(["bash", str(self.gcp / "deploy_all.sh"), *args], env=self.env(**kw),
                                capture_output=True, text=True, cwd=self.root, timeout=60)
        created = set(self.run_dirs()) - before
        self.last_run_dir = created.pop() if created else None
        return result

    def calls(self):
        import json
        path = self.logs / "calls.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines()]

    def called_steps(self):
        return [c["argv"][0] for c in self.calls()]

    def run_dirs(self):
        base = self.gcp / "runtime" / "runs"
        return sorted(base.iterdir()) if base.exists() else []

    def status_rows(self, run_dir=None):
        run_dir = run_dir or self.last_run_dir
        rows = (run_dir / "status.tsv").read_text().splitlines()[1:]
        return [r.split("\t") for r in rows]


class DeployAllPythonStepTests(unittest.TestCase):
    def world(self, steps=PY_TABLE, **kw):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return World(tmp.name, steps, **kw)

    def test_plan_lists_py_steps_without_ssh(self):
        w = self.world()
        fake_bin = w.root / "bin"
        fake_bin.mkdir()
        for tool in ("ssh", "scp"):
            (fake_bin / tool).write_text('#!/bin/sh\ntouch "$STUB_LOG_DIR/ssh-used"\nexit 1\n')
            (fake_bin / tool).chmod(0o755)
        r = w.run("--plan", extra={"PATH": f"{fake_bin}:{os.environ['PATH']}"}, configured=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        for step in ("50", "60", "62", "63"):
            self.assertRegex(r.stdout, rf"(?m)^{step}  ")
        self.assertFalse((w.logs / "ssh-used").exists())
        self.assertEqual(w.calls(), [])
        self.assertEqual(w.run_dirs(), [])

    def test_cutover_step_requires_both_confirmations(self):
        w = self.world()
        for extra in ({}, {"CONFIRM_FULL_FRESH_DEPLOY": "1"},
                      {"CONFIRM_MULTICHAIN_REPLACES_CURRENT_STAGING": "1"}):
            for args in (["--from", "60"], ["--only", "62"], ["--from", "62"], ["--until", "62"]):
                r = w.run(*args, extra=extra)
                self.assertEqual(r.returncode, 1, (args, extra, r.stderr))
                self.assertIn("CONFIRM_FULL_FRESH_DEPLOY", r.stderr)
            r = w.run(extra={**extra, "SKIP_STEPS": "50 51"})
            self.assertEqual(r.returncode, 1, (extra, r.stderr))
        self.assertEqual(w.calls(), [])
        self.assertEqual(w.run_dirs(), [])

    def test_prepare_step_runs_without_confirmations(self):
        w = self.world()
        r = w.run("--until", "51")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(w.called_steps(), ["verify_release", "check_hosts"])
        self.assertEqual(w.calls()[0]["argv"], [
            "verify_release", "--release-dir", str(w.release), "--access", str(w.access),
            "--run-dir", str(w.last_run_dir), "--private-dir", str(w.private)])

    def test_py_exit_3_records_pending_and_stops(self):
        w = self.world()
        r = w.run("--from", "60", confirm=True, extra={"STUB_EXIT_stop_operator_hosts": "3"})
        self.assertEqual(r.returncode, 3, r.stderr)
        self.assertEqual(w.called_steps(), ["fence_ingress", "stop_operator_hosts"])
        rows = w.status_rows()
        self.assertEqual([x[:3] for x in rows if x[0] == "62"], [["62", "STARTED", ""], ["62", "PENDING", "3"]])
        self.assertIn("--from 62", r.stderr)

    def test_py_exit_1_records_failed_and_stops(self):
        w = self.world()
        r = w.run("--from", "60", confirm=True, extra={"STUB_EXIT_fence_ingress": "1"})
        self.assertEqual(r.returncode, 1)
        self.assertEqual(w.called_steps(), ["fence_ingress"])
        self.assertEqual([x[:3] for x in w.status_rows() if x[0] == "60"][-1], ["60", "FAILED", "1"])

    def test_from_resumes_at_pending_step(self):
        w = self.world()
        r = w.run(confirm=True, extra={"STUB_EXIT_stop_operator_hosts": "3"})
        self.assertEqual(r.returncode, 3)
        first = w.called_steps()
        self.assertEqual(first, ["verify_release", "check_hosts", "fence_ingress", "stop_operator_hosts"])
        r = w.run("--from", "62", confirm=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(w.called_steps()[len(first):], ["stop_operator_hosts", "clear_node_state"])
        rows = w.status_rows()
        self.assertEqual([x[0] for x in rows], ["62", "62", "63", "63"])
        self.assertEqual([x[1] for x in rows], ["STARTED", "SUCCEEDED", "STARTED", "SUCCEEDED"])

    def test_from_after_failure_reruns_only_that_step_onward(self):
        w = self.world()
        w.run(confirm=True, extra={"STUB_EXIT_fence_ingress": "7"})
        r = w.run("--from", "60", confirm=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(w.called_steps()[-3:], ["fence_ingress", "stop_operator_hosts", "clear_node_state"])
        self.assertEqual(w.called_steps().count("verify_release"), 1)

    def test_py_run_skips_shell_preflight_and_sources(self):
        w = self.world()
        r = w.run(confirm=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse((w.logs / "shell.log").exists())
        self.assertTrue(all(not c["regen"] for c in w.calls()))
        self.assertEqual(len(w.calls()), 5)

    def test_unknown_step_type_fails_without_running_anything(self):
        for line in ("50\tbogus:thing\tx\n", "50\tshell:touch pwned\tx\n", "50\tpy-:thing\tx\n"):
            w = self.world(steps=line)
            r = w.run("--plan")
            self.assertNotEqual(r.returncode, 0, line)
            self.assertIn("unknown step type", r.stderr)
            self.assertEqual(w.calls(), [])

    def test_step_name_is_one_literal_argument(self):
        for name in ("a b", "a;touch pwned", "$(touch pwned)", "../x", "a\"b", "Up", "-x", ""):
            w = self.world(steps=f"50\tpy:{name}\tx\n")
            r = w.run("--plan")
            self.assertNotEqual(r.returncode, 0, name)
            self.assertIn("invalid step name", r.stderr)
            self.assertFalse((w.root / "pwned").exists())
            self.assertEqual(w.calls(), [])

    def test_step_table_with_description_metacharacters_is_inert(self):
        w = self.world(steps="50\tpy:verify_release\t$(touch pwned); `touch pwned`\n")
        r = w.run()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse((w.root / "pwned").exists())
        self.assertEqual(len(w.calls()[0]["argv"]), 9)

    def test_mixed_py_and_shell_steps_reject(self):
        w = self.world(steps="01\t01_one.sh\told\n50\tpy:verify_release\tnew\n", shell=True)
        r = w.run("--plan")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("cannot mix", r.stderr)

    def test_duplicate_step_id_rejects(self):
        w = self.world(steps="50\tpy:verify_release\ta\n50\tpy:check_hosts\tb\n")
        r = w.run("--plan")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("duplicate step ID", r.stderr)

    def test_missing_private_inputs_name_the_variable(self):
        w = self.world()
        for var in ("DEPLOY_ACCESS_FILE", "DEPLOY_PRIVATE_DIR"):
            other = {"DEPLOY_ACCESS_FILE": str(w.access), "DEPLOY_PRIVATE_DIR": str(w.private)}
            other.pop(var)
            r = w.run("--only", "50", extra=other, configured=False)
            self.assertEqual(r.returncode, 1)
            self.assertIn(var, r.stderr)
        self.assertEqual(w.calls(), [])

    def test_release_dir_defaults_to_step_table_directory(self):
        w = self.world()
        (w.root / "tabledir").mkdir()
        shutil.move(w.steps, w.root / "tabledir" / "steps.tsv")
        env = {"DEPLOY_STEPS_FILE": str(w.root / "tabledir" / "steps.tsv"), "DEPLOY_RELEASE_DIR": ""}
        r = w.run("--only", "50", extra=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(w.calls()[0]["argv"][2], str(w.root / "tabledir"))

    def test_confirmations_in_config_env_do_not_satisfy_cutover(self):
        w = self.world()
        (w.gcp / "config.env").write_text(
            "CONFIRM_MULTICHAIN_REPLACES_CURRENT_STAGING=1\nCONFIRM_FULL_FRESH_DEPLOY=1\n")
        r = w.run("--only", "60")
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertEqual(w.calls(), [])
        r = w.run("--only", "50")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(w.calls()[0]["confirm"])

    def test_config_env_values_do_not_reach_deploy_py(self):
        w = self.world()
        (w.gcp / "config.env").write_text(
            "REGENERATE_GENESIS=1\nPARTH_ALLOW_GENESIS_OVERWRITE=1\n")
        r = w.run("--only", "50")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(w.calls()[0]["leaked"], [])

    def test_py_run_prints_no_shell_table_notices(self):
        w = self.world()
        (w.gcp / "config.env").write_text("DEPLOY_MONITORING=0\n")
        r = w.run(confirm=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        for text in ("E2E", "monitoring", "source pins", "prove host"):
            self.assertNotIn(text, r.stdout + r.stderr)

    def test_failed_deploy_l1_warns_that_transactions_may_exist(self):
        w = self.world(steps="69\tpy-cutover:deploy_l1\tl1\n")
        r = w.run(confirm=True, extra={"STUB_EXIT_deploy_l1": "1"})
        self.assertEqual(r.returncode, 1)
        self.assertIn("L1 transactions may already exist", r.stderr)
        self.assertIn("rerunning step 69", r.stderr)

    def test_missing_deploy_py_fails_before_running(self):
        w = self.world()
        (w.gcp / "core-only" / "deploy.py").unlink()
        r = w.run("--only", "50")
        self.assertEqual(r.returncode, 1)
        self.assertIn("core-only/deploy.py", r.stderr)


class DeployAllShellStepTests(unittest.TestCase):
    def test_legacy_step_table_behavior_unchanged(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        w = World(tmp.name, "01\t01_one.sh\tone\n32\t32_deploy_monitoring.sh\tmonitoring\n", shell=True)
        r = w.run(extra={"STUB_EXIT_32": "3"}, confirm=True, configured=False)
        self.assertEqual(r.returncode, 3, r.stderr)
        self.assertIn("PENDING 32: finish offsite monitoring installation, then run "
                      "deploy-monitoring.sh --status", r.stderr)
        rows = w.status_rows()
        self.assertEqual([x[:3] for x in rows], [["01", "STARTED", ""], ["01", "SUCCEEDED", "0"],
                                                 ["32", "STARTED", ""], ["32", "PENDING", "3"]])
        shell_log = (w.logs / "shell.log").read_text()
        for name in ("prepare-sources.sh", "preflight.sh"):
            self.assertIn(name, shell_log)

    def test_shell_step_exit_3_other_than_32_stays_failed(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        w = World(tmp.name, "32\t32_deploy_monitoring.sh\tmonitoring\n", shell=True)
        (w.root / "deploy/gcp/fresh-staging/01_one.sh").write_text("#!/usr/bin/env bash\nexit 3\n")
        w.steps.write_text("01\t01_one.sh\tone\n")
        r = w.run(confirm=True, configured=False)
        self.assertEqual(r.returncode, 3)
        self.assertEqual(w.status_rows()[-1][:3], ["01", "FAILED", "3"])

    def test_shell_confirmations_still_required(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        w = World(tmp.name, "01\t01_one.sh\tone\n", shell=True)
        r = w.run(configured=False)
        self.assertEqual(r.returncode, 1)
        self.assertIn("This profile reuses the current staging GCP hosts", r.stderr)

    def test_default_shell_plan_lists_known_steps(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("DEPLOY_", "GCP_"))}
        r = subprocess.run(["bash", str(SCRIPT), "--plan"], env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(r.stdout, r"(?m)^32  Deploy Psy Notifier last")


class Sd192StepTableTests(unittest.TestCase):
    def test_table_pins_every_id_type_and_name(self):
        rows = [line.split("\t")[:2] for line in SD192_STEPS.read_text().splitlines()
                if line and line[0].isdigit()]
        self.assertEqual(rows, [list(p) for p in EXPECTED_PAIRS])
        self.assertEqual(len(rows), 29)

    def test_plan_with_the_real_table_needs_no_private_inputs(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("DEPLOY_", "GCP_"))}
        env["DEPLOY_STEPS_FILE"] = str(SD192_STEPS)
        r = subprocess.run(["bash", str(SCRIPT), "--plan"], env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(r.stdout, r"(?m)^76  ")


if __name__ == "__main__":
    unittest.main()
