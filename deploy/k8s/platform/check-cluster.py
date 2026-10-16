#!/usr/bin/env python3
"""Read-only kubeconfig/node identity gate, copied into a rendered platform bundle."""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys


def check(bootstrap=False):
    config = Path(os.environ.get("KUBECONFIG", ""))
    if not config.is_absolute() or not config.is_file() or config.is_symlink():
        sys.exit("Explicit absolute KUBECONFIG file required")
    if stat.S_IMODE(config.stat().st_mode) != 0o600:
        sys.exit("Kubeconfig must be mode 600")
    def kubectl(*args):
        return json.loads(subprocess.check_output(["kubectl", *args], text=True))
    view = kubectl("config", "view", "--minify", "-o", "json")
    server = view["clusters"][0]["cluster"]["server"]
    vip = Path("api-vip").read_text().strip()
    expected = json.loads(Path("expected-nodes.json").read_text())
    first = "psy-lab-cp-local" if "psy-lab-cp-local" in expected else "psy-lab-cp-x2"
    wanted = {first} if bootstrap else set(expected)
    endpoint = expected[first]["ip"] if bootstrap else vip
    if server != "https://" + endpoint + ":6443":
        sys.exit("Wrong API endpoint; refusing to use this kubeconfig")
    nodes = kubectl("get", "nodes", "-o", "json")["items"]
    if len(nodes) != len(wanted) or {n["metadata"]["name"] for n in nodes} != wanted:
        sys.exit("Unexpected cluster node set; expected the isolated lab only")
    for node in nodes:
        name = node["metadata"]["name"]
        labels = node["metadata"]["labels"]
        role = "control-plane" if expected[name]["role"] == "server" else "worker"
        ips = {a["address"] for a in node["status"]["addresses"] if a["type"] == "InternalIP"}
        ready = any(c["type"] == "Ready" and c["status"] == "True" for c in node["status"]["conditions"])
        if labels.get("psy.local/lab") != "psy-k8s-local" or labels.get("psy.local/role") != role or ips != {expected[name]["ip"]} or not ready:
            sys.exit("Node identity/readiness mismatch: " + name)
        if name == "psy-lab-cp-local":
            taints = {(t["key"], t.get("value"), t["effect"]) for t in node.get("spec", {}).get("taints", [])}
            required = {("node-role.kubernetes.io/control-plane", "true", "NoSchedule"), ("psy.local/control-only", "true", "NoSchedule")}
            if not required.issubset(taints):
                sys.exit("Local control-plane scheduling taints missing")
    print("Confirmed isolated lab node identities and API endpoint")


if __name__ == "__main__":
    check(bootstrap=len(sys.argv) == 2 and sys.argv[1] == "--bootstrap")
