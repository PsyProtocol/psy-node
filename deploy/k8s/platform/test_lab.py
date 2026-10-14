#!/usr/bin/env python3
import base64
from contextlib import contextmanager
import copy
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import lab


def inventory(confirmed=False):
    value = json.loads((lab.HERE / "inventory.example.json").read_text())
    wire = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + bytes(range(32))
    value["ssh_public_key"] = "ssh-ed25519 " + base64.b64encode(wire).decode() + " fixture"
    value["network_confirmed"] = value["storage_confirmed"] = confirmed
    return value


@contextmanager
def working(path):
    old = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(old)


class LabTests(unittest.TestCase):
    def test_host_pool_must_exist_and_be_fully_traversable(self):
        spec = importlib.util.spec_from_file_location("create_vms", lab.HERE / "create-vms.py")
        creator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(creator)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested/os"
            with patch("subprocess.run") as run, self.assertRaises(SystemExit):
                creator.check_pool(str(path), "fixture-qemu")
            run.assert_not_called()
            self.assertFalse(path.parent.exists())
            path.mkdir(parents=True)
            with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 1)), self.assertRaises(SystemExit):
                creator.check_pool(str(path), "fixture-qemu")
            before = path.stat().st_mode
            with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0)) as run:
                creator.check_pool(str(path), "fixture-qemu")
            run.assert_called_once_with(["runuser", "-u", "fixture-qemu", "--", "test", "-x", str(path)])
            self.assertEqual(path.stat().st_mode, before)

    def invalid(self, edit):
        cfg = inventory()
        edit(cfg)
        with self.assertRaises(ValueError):
            lab.validate(cfg)

    def test_accepts_platform_profile(self):
        cfg = lab.validate(inventory())
        self.assertEqual(sum(n["memory_gib"] for n in cfg["nodes"]), 52)

    def test_rejects_network_collisions(self):
        for edit in [lambda c: c.update(api_vip=c["nodes"][0]["ip"]),
                     lambda c: c.update(pod_cidr="10.250.0.0/16"),
                     lambda c: c["nodes"][0].update(ip="192.168.5.35"),
                     lambda c: c.update(service_cidr="10.42.0.0/16"),
                     lambda c: c.update(ingress_vip="192.168.6.217")]:
            self.invalid(edit)

    def test_rejects_bad_identity_and_paths(self):
        for edit in [lambda c: c["hosts"]["x2"].update(ssh="-oProxyCommand=oops"),
                     lambda c: c["hosts"]["x2"].update(os_pool="/home/psy/../k8s"),
                     lambda c: c["nodes"][0].update(name="production"),
                     lambda c: c["nodes"][0].update(mac=c["nodes"][1]["mac"]),
                     lambda c: c.update(ssh_public_key="-----BEGIN OPENSSH PRIVATE KEY-----")]:
            self.invalid(edit)

    def test_rejects_memory_oversubscription(self):
        self.invalid(lambda c: c["nodes"][1].update(memory_gib=44))
        self.invalid(lambda c: c["hosts"]["x4"].update(minimum_available_memory_gib=24))

    def test_only_x4_worker_has_data_disk(self):
        self.invalid(lambda c: c["nodes"][0].update(data_gib=256))
        self.invalid(lambda c: c["nodes"][-1].pop("data_gib"))

    def test_render_safe_bundles_and_identical_server_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "rendered"
            cfg = inventory(True)
            lab.render(cfg, out)
            flags = []
            for node in cfg["nodes"]:
                p = out / "nodes" / node["name"]
                conf = json.loads((p / "config.yaml").read_text())
                self.assertNotIn("token", conf)
                self.assertEqual((p / "install-k3s.sh").stat().st_mode & 0o777, 0o700)
                if node["role"] == "server":
                    flags.append({k: conf[k] for k in ["disable", "cluster-cidr", "service-cidr", "cluster-dns", "secrets-encryption"]})
                    self.assertIn("node-taint", conf)
                if node.get("data_gib"):
                    self.assertEqual(conf["data-dir"], "/srv/psy-lab/k3s")
                else:
                    self.assertNotIn("data-dir", conf)
            self.assertEqual(flags[0], flags[1])
            self.assertEqual(flags[1], flags[2])
            for host in ("x2", "x3", "x4"):
                xml = (out / "hosts" / host / ("psy-lab-cp-" + host + ".xml")).read_text()
                self.assertIn(cfg["hosts"][host]["os_pool"], xml)
                self.assertNotIn("/mnt/psy-k8s-lab", xml)

    def test_unconfirmed_scripts_fail_before_any_command(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "bundle"
            lab.render(inventory(), out)
            for script, argument in [("bootstrap-vip.sh", "--bootstrap"), ("install-platform.sh", "--install"), ("verify-platform.sh", "")]:
                result = subprocess.run(["bash", str(out / "platform" / script), argument], capture_output=True, text=True)
                self.assertEqual(result.returncode, 1)
                self.assertIn("Example inventory", result.stderr)

    def test_render_cannot_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                lab.render(inventory(), Path(directory))

    def test_local_pvs_retain_and_monitoring_is_not_kubeadm(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "bundle"
            lab.render(inventory(), out)
            storage = json.loads((out / "platform/storage.json").read_text())["items"]
            for pv in [s for s in storage if s["kind"] == "PersistentVolume"]:
                self.assertEqual(pv["spec"]["persistentVolumeReclaimPolicy"], "Retain")
                self.assertEqual(pv["spec"]["nodeAffinity"]["required"]["nodeSelectorTerms"][0]["matchExpressions"][0]["values"], ["psy-lab-work-x4"])
            values = json.loads((out / "platform/prometheus-values.json").read_text())
            for key in ("kubeEtcd", "kubeControllerManager", "kubeScheduler", "kubeProxy"):
                self.assertFalse(values[key]["enabled"])
            self.assertEqual(values["prometheus"]["prometheusSpec"]["retention"], "7d")

    def test_guest_scripts_refuse_on_physical_host(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "bundle"
            lab.render(inventory(True), out)
            result = subprocess.run(["bash", str(out / "nodes/psy-lab-work-x4/initialize-data.sh"), "--initialize-empty-virtual-disk"], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)

    def test_cluster_gate_blocks_wrong_endpoint_and_node_set(self):
        spec = importlib.util.spec_from_file_location("check_cluster", lab.HERE / "check-cluster.py")
        checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(checker)
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory)
            kube = p / "kubeconfig"
            kube.write_text("fixture")
            kube.chmod(0o600)
            (p / "api-vip").write_text("192.168.5.216\n")
            (p / "expected-nodes.json").write_text(json.dumps({n["name"]: {"ip": n["ip"], "role": n["role"]} for n in inventory()["nodes"]}))
            with working(p), patch.dict(os.environ, {"KUBECONFIG": str(kube)}):
                wrong = json.dumps({"clusters": [{"cluster": {"server": "https://production:6443"}}]})
                with patch("subprocess.check_output", return_value=wrong), self.assertRaises(SystemExit):
                    checker.check()
                right = json.dumps({"clusters": [{"cluster": {"server": "https://192.168.5.216:6443"}}]})
                with patch("subprocess.check_output", side_effect=[right, '{"items":[]}']), self.assertRaises(SystemExit):
                    checker.check()

    def test_lock_versions_match_build_candidates(self):
        self.assertIn(lab.VERSIONS["k3s"].replace("+", "%2B"), lab.LOCK["k3s"]["url"])
        self.assertIn(lab.VERSIONS["metallb_chart"], lab.LOCK["metallb.tgz"]["url"])
        self.assertIn(lab.VERSIONS["kube_prometheus_stack_chart"], lab.LOCK["prometheus.tgz"]["url"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
