#!/usr/bin/env python3
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

import test_four_node as shared

HERE = Path(__file__).resolve().parent
network = shared.load("network_acceptance", HERE / "network-acceptance.py")
delivery = shared.load("prepare_delivery", HERE / "prepare-delivery.py")


class PreparationTests(unittest.TestCase):
    def test_probe_placement_privileges_and_lifetime(self):
        plan = network.fixtures("c0ffee00")
        pods = [x for x in plan["fixtures"] if x["kind"] == "Pod"]
        self.assertEqual(len(pods), 6)
        self.assertEqual({p["spec"]["nodeSelector"]["kubernetes.io/hostname"] for p in pods}, set(network.WORKERS))
        for p in pods:
            spec = p["spec"]
            self.assertFalse(spec["automountServiceAccountToken"])
            self.assertEqual(spec["serviceAccountName"], "probe")
            self.assertTrue(spec["securityContext"]["runAsNonRoot"])
            self.assertEqual(spec["restartPolicy"], "Never")
            self.assertLessEqual(spec["activeDeadlineSeconds"], 1800)
            self.assertIn("@sha256:", spec["containers"][0]["image"])
            self.assertNotIn("hostNetwork", spec)
            self.assertNotIn("tolerations", spec)

    def test_network_policy_tests_both_namespace_and_label(self):
        plan = network.fixtures("c0ffee00")
        allow = next(p for p in plan["policies"] if p["metadata"]["name"] == "allow-http-ingress")
        peer = allow["spec"]["ingress"][0]["from"]
        self.assertEqual(len(peer), 1)
        self.assertEqual(peer[0]["namespaceSelector"]["matchLabels"], {"kubernetes.io/metadata.name": plan["namespaces"][1]})
        self.assertEqual(peer[0]["podSelector"]["matchLabels"], {"role": "client"})
        self.assertEqual(len(plan["allowed"]), 3)
        self.assertEqual({ns for ns, _ in plan["denied"]}, set(plan["namespaces"]))
        # Both decoys get HTTP egress, so an ingress failure cannot be attributed
        # to a missing client-egress rule.
        egress = [p for p in plan["policies"] if p["metadata"]["name"] in {"allow-http-egress", "allow-decoy-egress"}]
        self.assertEqual({p["metadata"]["namespace"] for p in egress}, set(plan["namespaces"]))

    def test_default_deny_and_dns_are_scoped_to_fixtures(self):
        plan = network.fixtures("c0ffee00")
        self.assertEqual({p["metadata"]["namespace"] for p in plan["policies"]}, set(plan["namespaces"]))
        deny = [p for p in plan["policies"] if p["metadata"]["name"] == "default-deny"]
        self.assertEqual(len(deny), 2)
        for p in deny:
            self.assertEqual(p["spec"]["ingress"], [])
            self.assertEqual(p["spec"]["egress"], [])
        for p in [p for p in plan["policies"] if p["metadata"]["name"] == "allow-dns"]:
            self.assertEqual({x["protocol"] for x in p["spec"]["egress"][0]["ports"]}, {"TCP", "UDP"})

    def test_gateway_grant_names_only_test_service(self):
        plan = network.fixtures("c0ffee00")
        grant, route = plan["ingress"]
        self.assertEqual(grant["spec"]["to"], [{"group": "", "kind": "Service", "name": "http"}])
        self.assertEqual(route["metadata"]["namespace"], "psy-platform")
        self.assertEqual(route["spec"]["rules"][0]["backendRefs"][0]["namespace"], plan["namespaces"][0])
        with self.assertRaises(ValueError):
            network.fixtures("x; touch /tmp/injection")

    def test_unconfirmed_acceptance_has_zero_cluster_calls(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(subprocess, "run") as run:
            out = Path(tmp) / "evidence"
            with self.assertRaisesRegex(ValueError, "not confirmed"):
                network.run_live({"execution_enabled": False}, out)
            run.assert_not_called()
            self.assertFalse(out.exists())

    def test_existing_evidence_refused_before_cluster_calls(self):
        cfg = {"execution_enabled": True, "topology": "local-control-plane", "workers": network.WORKERS, "ingress_vip": "192.168.5.217"}
        with tempfile.TemporaryDirectory() as tmp, patch.object(subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "exists"):
                network.run_live(cfg, Path(tmp))
            run.assert_not_called()

    def test_exec_auth_http_errors_do_not_prove_isolation(self):
        def response(code, stderr):
            return subprocess.CompletedProcess([], code, "", stderr)
        self.assertTrue(network.network_timeout(response(1, "wget: download timed out")))
        for p in [response(1, "error: unable to upgrade connection: timed out"), response(1, "wget: server returned error: HTTP/1.1 404 Not Found"), response(1, "wget: bad address 'http.test'"), response(0, "wget: download timed out")]:
            self.assertFalse(network.network_timeout(p))

    def test_live_orchestration_and_negative_controls_with_fake_cluster(self):
        plan = network.fixtures("c0ffee00")
        cfg = {"execution_enabled": True, "topology": "local-control-plane", "workers": network.WORKERS, "ingress_vip": "192.168.5.217"}
        state = {"policies": False}
        def create(items):
            if any(x["kind"] == "ServiceAccount" for x in items):
                state["accounts"] = True
            if any(x["kind"] == "Pod" for x in items):
                self.assertTrue(state.get("accounts"))
            if items[0]["kind"] == "NetworkPolicy":
                state["policies"] = True
        def kubectl(*args, **kwargs):
            if "--ignore-not-found" in args:
                return subprocess.CompletedProcess(args, 0, "", "")
            if "get" in args and "pod" in args:
                pod = args[args.index("pod") + 1]
                node = next(x["spec"]["nodeSelector"]["kubernetes.io/hostname"] for x in plan["fixtures"] if x["kind"] == "Pod" and x["metadata"]["name"] == pod)
                return subprocess.CompletedProcess(args, 0, json.dumps({"spec": {"nodeName": node}}), "")
            if "get" in args and "service" in args:
                return subprocess.CompletedProcess(args, 0, '{"spec":{"clusterIP":"10.43.1.2"}}', "")
            if "wget" in args:
                if state["policies"] and args[3].startswith("denied-"):
                    return subprocess.CompletedProcess(args, 1, "", "wget: download timed out")
                return subprocess.CompletedProcess(args, 0, plan["body"], "")
            return subprocess.CompletedProcess(args, 0, "", "")
        response = types.SimpleNamespace(status=200, read=lambda _: plan["body"].encode())
        @contextlib.contextmanager
        def opened(request, timeout):
            self.assertEqual(request.get_header("Host"), "c0ffee00.psy-lab.invalid")
            yield response
        with tempfile.TemporaryDirectory() as tmp, patch.object(network.uuid, "uuid4", return_value=types.SimpleNamespace(hex="c0ffee001234")), patch.object(network, "kubectl", side_effect=kubectl), patch.object(network, "create", side_effect=create), patch.object(subprocess, "run"), patch.object(network.urllib.request, "build_opener", return_value=types.SimpleNamespace(open=opened)):
            out = Path(tmp) / "evidence"
            network.run_live(cfg, out)
            result = json.loads((out / "result.json").read_text())
            self.assertTrue(result["passed"])
            self.assertEqual(len(result["checks"]), 3)
            self.assertEqual((out / "result.json").stat().st_mode & 0o777, 0o600)

    def test_offline_plan_requires_no_cluster_or_config(self):
        p = subprocess.run([sys.executable, str(HERE / "network-acceptance.py"), "--plan"], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout)["run_id"], "plan")

    def test_delivery_rejects_bad_asset_before_creating_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            assets, out = Path(tmp), Path(tmp) / "delivery"
            (assets / "ubuntu.img").write_bytes(b"wrong image")
            with self.assertRaisesRegex(ValueError, "Asset mismatch"):
                delivery.assemble(shared.inventory(), assets, out, "a" * 40)
            self.assertFalse(out.exists())

    def test_delivery_role_boundaries_hashes_and_guest_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            assets = Path(tmp) / "assets"
            assets.mkdir()
            lock = {}
            for name in ("ubuntu.img", "k3s"):
                (assets / name).write_text(name + " fixture")
                lock[name] = {"sha256": shared.lab.digest(assets / name)}
            out = Path(tmp) / "delivery"
            with patch.object(shared.lab, "LOCK", lock), patch.object(shared.lab, "charts"), contextlib.redirect_stdout(io.StringIO()):
                delivery.assemble(shared.inventory(), assets, out, "a" * 40)
            for role in ("local", "x2", "x3", "x4"):
                package = out / "host-packages" / role
                host = json.loads((package / "host.json").read_text())
                self.assertEqual(len(host["nodes"]), 1)
                self.assertEqual(host["nodes"][0]["host"], role)
                self.assertFalse(host["confirmed"])
                self.assertTrue((package / "guest/install-k3s.sh").is_file())
                self.assertEqual((package / "guest/k3s").read_text(), "k3s fixture")
                for line in (package / "SHA256SUMS").read_text().splitlines():
                    wanted, name = line.split("  ", 1)
                    self.assertEqual(shared.lab.digest(package / name), wanted)
                self.assertFalse(list(package.rglob("*token*")))
            with patch.object(shared.lab, "LOCK", lock), self.assertRaisesRegex(ValueError, "already exists"):
                delivery.assemble(shared.inventory(), assets, out, "a" * 40)


if __name__ == "__main__":
    unittest.main(verbosity=2)
