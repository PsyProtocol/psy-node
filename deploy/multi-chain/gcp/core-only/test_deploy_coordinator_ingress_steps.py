import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import deploy
import deploy_coordinator_ingress_steps as steps

TOPOLOGY = json.loads((Path(__file__).resolve().parents[1] / "fresh-192-20261030" / "topology.json").read_text())


class FakeRemote:
    def __init__(self, state):
        self.state, self.calls = state, []

    def run_root_text(self, host, argv, timeout, *, stdin_text=None, show_stderr=True):
        self.calls.append((host, argv[3] if len(argv) > 3 else argv[0], stdin_text))
        if argv[3] == steps.READ_STATE:
            return json.dumps(self.state)
        return ""


class Context:
    def __init__(self, remote):
        self.remote = remote


def installed_state(text, **changes):
    state = {"installed": True, "site": hashlib.sha256(text.encode()).hexdigest(), "enabled": True, "default": False,
             "active": "active", "enabled_unit": "enabled", "config_ok": True}
    return {**state, **changes}


class SiteTextTests(unittest.TestCase):
    def test_site_spreads_over_the_three_edges_on_the_private_ingress_only(self):
        text = steps.site_text(TOPOLOGY)
        self.assertIn("    listen 10.148.0.25:15369;\n", text)
        self.assertEqual([line.strip() for line in text.splitlines() if line.strip().startswith("server 10.")],
                         [f"server 10.148.0.25:{port} max_fails=2 fail_timeout=15s;" for port in (15370, 15371, 15372)])
        self.assertIn("allow 10.0.0.0/8;\n    deny all;", text)
        self.assertIn("proxy_next_upstream error timeout;", text)
        self.assertNotIn("non_idempotent", text)
        self.assertEqual([line.strip() for line in text.splitlines() if "listen" in line], ["listen 10.148.0.25:15369;"])
        self.assertIn("client_max_body_size 512m;", text)


class IngressStepTests(unittest.TestCase):
    def setUp(self):
        patcher = patch.object(steps.health, "read_topology", return_value=TOPOLOGY)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.text = steps.site_text(TOPOLOGY)

    def test_apply_writes_the_reviewed_site_only_when_it_differs(self):
        remote = FakeRemote(installed_state(self.text))
        steps.ingress_apply(Context(remote))
        self.assertEqual([call[1] for call in remote.calls], [steps.READ_STATE])
        remote = FakeRemote({"installed": False, "site": None, "enabled": False, "default": True, "active": "inactive",
                             "enabled_unit": "", "config_ok": False})
        steps.ingress_apply(Context(remote))
        host, script, stdin = remote.calls[-1]
        self.assertEqual((host, script), (steps.COORDINATOR_HOST, steps.INSTALL))
        arguments = json.loads(stdin)
        self.assertEqual(base64.b64decode(arguments["text"]).decode(), self.text)
        self.assertEqual((arguments["site"], arguments["enabled"], arguments["default"]),
                         (steps.SITE, steps.ENABLED, steps.DEFAULT_SITE))

    def test_verify_refuses_every_drift(self):
        self.assertEqual(steps.ingress_verify(Context(FakeRemote(installed_state(self.text))))["site_sha256"],
                         hashlib.sha256(self.text.encode()).hexdigest())
        for change in ({"site": "0" * 64}, {"enabled": False}, {"default": True}, {"active": "failed"},
                       {"enabled_unit": "disabled"}, {"config_ok": False}, {"installed": False}):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "coordinator ingress"):
                steps.ingress_verify(Context(FakeRemote(installed_state(self.text, **change))))

    def test_read_state_script_reports_a_host_without_the_site(self):
        with tempfile.TemporaryDirectory() as root:
            site = Path(root, "available")
            enabled, default = Path(root, "enabled"), Path(root, "default")
            output = subprocess.run(["python3", "-I", "-c", steps.READ_STATE, str(site), str(enabled), str(default)],
                                    capture_output=True, text=True, check=True).stdout
            state = json.loads(output)
            self.assertEqual((state["site"], state["enabled"], state["default"]), (None, False, False))
            site.write_text(self.text)
            enabled.symlink_to(site)
            default.write_text("x")
            state = json.loads(subprocess.run(["python3", "-I", "-c", steps.READ_STATE, str(site), str(enabled),
                                               str(default)], capture_output=True, text=True, check=True).stdout)
            self.assertEqual((state["site"], state["enabled"], state["default"]),
                             (hashlib.sha256(self.text.encode()).hexdigest(), True, True))

    def test_install_script_refuses_a_foreign_policy_rc_and_reports_command_errors(self):
        self.assertIn("os.path.lexists('/usr/sbin/policy-rc.d')", steps.INSTALL)
        self.assertIn("'apt-get', 'update'", steps.INSTALL)
        self.assertNotIn("check=True, capture_output=True", steps.INSTALL)
        compile(steps.INSTALL, "install", "exec")

    def test_step_is_registered_before_the_cutover(self):
        step = steps.COORDINATOR_INGRESS_STEPS["install_coordinator_ingress"]
        self.assertFalse(step.cutover)
        self.assertIn("deploy_coordinator_ingress_steps", deploy.STEP_MODULES)
        self.assertIn("install_coordinator_ingress", deploy.build_registry())
