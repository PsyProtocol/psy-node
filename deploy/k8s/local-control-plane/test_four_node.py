#!/usr/bin/env python3
"""Topology, kubeconfig targeting and non-root VM construction regression checks."""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent / "platform"), str(HERE / "host-setup")]
import lab
import host_setup


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


creator = load("create_vm", HERE / "create-vm.py")
checker = load("cluster_checker", lab.HERE / "check-cluster.py")


def inventory(confirmed=False):
    cfg = json.loads((HERE / "inventory.example.json").read_text())
    wire = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + bytes(range(32))
    cfg["ssh_public_key"] = "ssh-ed25519 " + base64.b64encode(wire).decode() + " fixture"
    cfg["network_confirmed"] = cfg["storage_confirmed"] = confirmed
    return cfg


class FourNodeTests(unittest.TestCase):
    def invalid(self, edit):
        cfg = inventory()
        edit(cfg)
        with self.assertRaises(ValueError):
            lab.validate(cfg)

    def test_four_node_budget_and_physical_targets(self):
        cfg = lab.validate(inventory())
        self.assertEqual(len(cfg["nodes"]), 4)
        self.assertEqual(sum(n["memory_gib"] for n in cfg["nodes"]), 48)
        self.assertEqual(lab.first_server(cfg)["name"], "psy-lab-cp-local")

    def test_no_x1_or_remote_control_plane(self):
        for edit in (lambda c: c["hosts"].update(x1=c["hosts"]["x2"]),
                     lambda c: c["nodes"][1].update(role="server"),
                     lambda c: c["nodes"][0].update(host="x2"),
                     lambda c: c["hosts"]["local"].update(ssh="arc99x1"),
                     lambda c: c["nodes"][0].update(name="psy-lab-cp-x2")):
            self.invalid(edit)

    def test_direct_api_and_host_ip_collision_guards(self):
        for edit in (lambda c: c.update(api_address="192.168.5.216"),
                     lambda c: c.update(api_vip="192.168.5.216"),
                     lambda c: c["nodes"][1].update(ip="192.168.5.20"),
                     lambda c: c.update(ingress_vip=c["api_address"]),
                     lambda c: c.update(service_cidr="172.20.0.0/16")):
            self.invalid(edit)

    def test_data_mount_is_distinct_from_prepared_leaf(self):
        self.invalid(lambda c: c["hosts"]["x4"].update(data_pool="/mnt/psy-k8s-lab"))
        self.invalid(lambda c: c["hosts"]["x4"].update(data_mount="/home/psy"))

    def test_render_direct_bootstrap_and_no_kube_vip(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp, "bundle")
            cfg = inventory(True)
            lab.render(cfg, out)
            self.assertFalse((out / "platform/kube-vip.json").exists())
            self.assertFalse((out / "platform/bootstrap-vip.sh").exists())
            self.assertTrue((out / "platform/check-bootstrap.sh").exists())
            self.assertEqual((out / "platform/api-vip").read_text().strip(), cfg["api_address"])
            for node in cfg["nodes"]:
                conf = json.loads((out / "nodes" / node["name"] / "config.yaml").read_text())
                if node["role"] == "server":
                    self.assertTrue(conf["cluster-init"])
                    self.assertNotIn("server", conf)
                    self.assertIn("node-taint", conf)
                    self.assertIn("psy.local/control-only=true:NoSchedule", conf["node-taint"])
                else:
                    self.assertNotIn("cluster-init", conf)
                    self.assertEqual(conf["server"], "https://192.168.5.210:6443")
                host = out / "hosts" / node["host"]
                self.assertEqual(len(list(host.glob("*.xml"))), 1)
                self.assertTrue((host / "host_setup.py").exists())
                creator.check_xml(host / (node["name"] + ".xml"), node, cfg["hosts"][node["host"]])
            values = json.loads((out / "platform/prometheus-values.json").read_text())
            self.assertEqual(values["prometheus-node-exporter"]["nodeSelector"], {"psy.local/role": "worker"})

    def test_unconfirmed_platform_scripts_refuse(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp, "bundle")
            lab.render(inventory(), out)
            for script in ("check-bootstrap.sh", "install-platform.sh", "verify-platform.sh"):
                p = subprocess.run(["bash", str(out / "platform" / script)], capture_output=True, text=True)
                self.assertEqual(p.returncode, 1)
                self.assertIn("Example inventory", p.stderr)

    def test_creator_plan_has_no_mutations_and_rejects_x1(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp, "bundle")
            lab.render(inventory(), out)
            script = out / "hosts/local/create-vms.py"
            p = subprocess.run([sys.executable, str(script), "--create", "local"], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertFalse(json.loads(p.stdout)["mutations"])
            self.assertFalse(list(out.rglob("*.qcow2")))
            p = subprocess.run([sys.executable, str(script), "--create", "x1", "--apply"], capture_output=True)
            self.assertEqual(p.returncode, 2)

    def test_creator_rejects_root_wrong_host_and_unconfirmed_before_helpers(self):
        cfg = inventory()
        cfg = {**cfg["hosts"]["local"], "nodes": [cfg["nodes"][0]], "confirmed": False}
        with patch.object(host_setup, "identity", return_value=host_setup.HOSTS["local"]), patch.object(creator, "run") as run:
            with patch.object(os, "geteuid", return_value=0), self.assertRaisesRegex(ValueError, "ordinary"):
                creator.preflight("local", cfg)
            bad = copy.deepcopy(cfg)
            bad["expected_hostname"] = "arc99x1"
            with self.assertRaisesRegex(ValueError, "does not match"):
                creator.preflight("local", bad)
            with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 1)), self.assertRaisesRegex(ValueError, "not confirmed"):
                creator.preflight("local", cfg)
            run.assert_not_called()

    def test_xml_rejects_production_paths_and_passthrough(self):
        cfg = inventory()
        node = cfg["nodes"][0]
        host = cfg["hosts"]["local"]
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, "vm.xml")
            root = ET.fromstring(lab.vm_xml(node, host))
            root.find("./devices/disk/source").set("file", "/opt/parth/state.qcow2")
            path.write_text(ET.tostring(root, encoding="unicode"))
            with self.assertRaisesRegex(ValueError, "dedicated lab paths"):
                creator.check_xml(path, node, host)
            root = ET.fromstring(lab.vm_xml(node, host))
            ET.SubElement(root.find("devices"), "hostdev")
            path.write_text(ET.tostring(root, encoding="unicode"))
            with self.assertRaisesRegex(ValueError, "passthrough"):
                creator.check_xml(path, node, host)

    def test_cluster_gate_accepts_four_and_rejects_extra_nodes(self):
        cfg = inventory()
        nodes = [{"metadata": {"name": n["name"], "labels": {"psy.local/lab": "psy-k8s-local", "psy.local/role": "control-plane" if n["role"] == "server" else "worker"}},
                  "status": {"addresses": [{"type": "InternalIP", "address": n["ip"]}], "conditions": [{"type": "Ready", "status": "True"}]}} for n in cfg["nodes"]]
        nodes[0]["spec"] = {"taints": [{"key": "node-role.kubernetes.io/control-plane", "value": "true", "effect": "NoSchedule"}, {"key": "psy.local/control-only", "value": "true", "effect": "NoSchedule"}]}
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp, "bundle")
            lab.render(cfg, out)
            kube = Path(temp, "kubeconfig")
            kube.write_text("fixture")
            kube.chmod(0o600)
            old = Path.cwd()
            os.chdir(out / "platform")
            try:
                view = json.dumps({"clusters": [{"cluster": {"server": "https://192.168.5.210:6443"}}]})
                with patch.dict(os.environ, KUBECONFIG=str(kube)):
                    for bootstrap, items in ((True, nodes[:1]), (False, nodes)):
                        with patch.object(subprocess, "check_output", side_effect=[view, json.dumps({"items": items})]):
                            checker.check(bootstrap)
                    with patch.object(subprocess, "check_output", side_effect=[view, json.dumps({"items": nodes + [nodes[0]]})]):
                        # Duplicate records also must not pass the exact-node gate.
                        with self.assertRaises(SystemExit):
                            checker.check()
                    wrong = copy.deepcopy(nodes)
                    wrong[0]["spec"]["taints"].pop()
                    with patch.object(subprocess, "check_output", side_effect=[view, json.dumps({"items": wrong})]), self.assertRaises(SystemExit):
                        checker.check()
            finally:
                os.chdir(old)


if __name__ == "__main__":
    unittest.main(verbosity=2)
