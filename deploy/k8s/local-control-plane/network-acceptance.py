#!/usr/bin/env python3
"""Scoped live DNS/HTTP/NetworkPolicy/Gateway checks; --plan is offline only."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.request
import uuid

# Official BusyBox 1.37.0 linux/amd64 manifest, resolved from Docker Hub 2026-10-16.
IMAGE = "docker.io/library/busybox@sha256:66a6306db78bf2dbf3487f293aa8d6990d8e506fdffab9cc43fe422becf886e4"
WORKERS = ["psy-lab-work-" + role for role in ("x2", "x3", "x4")]


def require(ok, why):
    if not ok:
        raise ValueError(why)


def obj(kind, name, ns=None, spec=None, api="v1"):
    value = {"apiVersion": api, "kind": kind, "metadata": {"name": name}}
    if ns:
        value["metadata"]["namespace"] = ns
    if spec is not None:
        value["spec"] = spec
    return value


def fixtures(run):
    require(bool(re.fullmatch(r"(?:[0-9a-f]{8}|plan)", run)), "Invalid run ID")
    server, client = "psy-lab-net-" + run, "psy-lab-client-" + run
    body = "psy-lab-acceptance-" + run
    labels = {"psy.local/acceptance-run": run}
    namespaces = [obj("Namespace", name) for name in (server, client)]
    for ns in namespaces:
        ns["metadata"]["labels"] = {**labels, "pod-security.kubernetes.io/enforce": "restricted", "pod-security.kubernetes.io/enforce-version": "v1.35"}
    accounts = [obj("ServiceAccount", "probe", name) for name in (server, client)]
    for account in accounts:
        account["automountServiceAccountToken"] = False
    def pod(name, namespace, role, worker):
        container = {"name": "probe", "image": IMAGE, "command": ["sleep", "3600"], "resources": {"requests": {"cpu": "5m", "memory": "8Mi"}, "limits": {"cpu": "100m", "memory": "32Mi"}}, "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}}
        value = obj("Pod", name, namespace, {"serviceAccountName": "probe", "automountServiceAccountToken": False, "activeDeadlineSeconds": 1800, "restartPolicy": "Never", "nodeSelector": {"psy.local/role": "worker", "kubernetes.io/hostname": worker}, "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "runAsGroup": 1000, "fsGroup": 1000, "seccompProfile": {"type": "RuntimeDefault"}}, "containers": [container]})
        value["metadata"]["labels"] = {**labels, "role": role}
        return value
    http = pod("http", server, "http", WORKERS[2])
    http["spec"]["volumes"] = [{"name": "www", "emptyDir": {"sizeLimit": "1Mi"}}]
    http["spec"]["containers"][0].update({"command": ["sh", "-c", f"printf '%s' {body} > /www/index.html; exec httpd -f -p 8080 -h /www"], "volumeMounts": [{"name": "www", "mountPath": "/www"}], "readinessProbe": {"httpGet": {"path": "/", "port": 8080}, "periodSeconds": 2}})
    pods = [http] + [pod("probe-" + role, client, "client", worker) for role, worker in zip(("x2", "x3", "x4"), WORKERS)]
    pods += [pod("denied-label", client, "other", WORKERS[0]), pod("denied-namespace", server, "client", WORKERS[1])]
    service = obj("Service", "http", server, {"type": "ClusterIP", "selector": {**labels, "role": "http"}, "ports": [{"port": 8080, "targetPort": 8080}]})
    def peer(namespace, role):
        # Both selectors are in ONE peer: namespace AND Pod identity are required.
        return {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": namespace}}, "podSelector": {"matchLabels": {"role": role}}}
    def policy(name, namespace, selector, **directions):
        return obj("NetworkPolicy", name, namespace, {"podSelector": {"matchLabels": selector}, "policyTypes": [key.title() for key in directions], **directions}, "networking.k8s.io/v1")
    policies = []
    for namespace in (server, client):
        policies += [policy("default-deny", namespace, {}, ingress=[], egress=[]),
                     policy("allow-dns", namespace, {}, egress=[{"to": [peer("kube-system", "UNUSED")], "ports": [{"protocol": p, "port": 53} for p in ("UDP", "TCP")]}])]
        policies[-1]["spec"]["egress"][0]["to"][0]["podSelector"] = {"matchLabels": {"k8s-app": "kube-dns"}}
    port = [{"protocol": "TCP", "port": 8080}]
    policies += [policy("allow-http-ingress", server, {"role": "http"}, ingress=[{"from": [peer(client, "client")], "ports": port}, {"from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "psy-platform"}}, "podSelector": {"matchLabels": {"app.kubernetes.io/name": "traefik"}}}], "ports": port}]),
                 policy("allow-http-egress", client, {}, egress=[{"to": [peer(server, "http")], "ports": port}]),
                 policy("allow-decoy-egress", server, {"role": "client"}, egress=[{"to": [peer(server, "http")], "ports": port}])]
    # Decoys have working DNS and permitted egress, so ingress selector rejection
    # is tested independently of unrelated DNS or client-egress failures.
    grant = obj("ReferenceGrant", "acceptance", server, {"from": [{"group": "gateway.networking.k8s.io", "kind": "HTTPRoute", "namespace": "psy-platform"}], "to": [{"group": "", "kind": "Service", "name": "http"}]}, "gateway.networking.k8s.io/v1beta1")
    route = obj("HTTPRoute", "psy-lab-acceptance-" + run, "psy-platform", {"parentRefs": [{"name": "traefik-gateway"}], "hostnames": [run + ".psy-lab.invalid"], "rules": [{"matches": [{"path": {"type": "PathPrefix", "value": "/"}}], "backendRefs": [{"name": "http", "namespace": server, "port": 8080}]}]}, "gateway.networking.k8s.io/v1")
    route["metadata"]["labels"] = labels
    probes = [(client, "probe-" + role) for role in ("x2", "x3", "x4")]
    decoys = [(client, "denied-label"), (server, "denied-namespace")]
    return {"run_id": run, "namespaces": [server, client], "body": body, "fixtures": namespaces + accounts + pods + [service], "policies": policies, "ingress": [grant, route], "allowed": probes, "denied": decoys}


def kubectl(*args, data=None, check=True):
    return subprocess.run(["kubectl", *args], input=data, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180, check=check)


def create(items):
    kubectl("create", "-f", "-", data=json.dumps({"apiVersion": "v1", "kind": "List", "items": items}))


def fetch(namespace, pod, address):
    return kubectl("-n", namespace, "exec", pod, "--", "wget", "-q", "-T", "3", "-O", "-", address, check=False)


def network_timeout(response):
    return response.returncode == 1 and bool(re.search(r"wget:.*timed out", response.stderr, re.IGNORECASE))


def wait_until(action, why, seconds=60):
    end = time.monotonic() + seconds
    while True:
        if action():
            return
        require(time.monotonic() < end, why)
        time.sleep(1)


def run_live(config, directory):
    require(config.get("execution_enabled") is True, "Network/storage not confirmed; no cluster calls made")
    require(config.get("topology") == "local-control-plane", "Only the four-node lab is supported")
    require(config.get("workers") == WORKERS, "Expected exactly x2/x3/x4 workers")
    ingress = str(ipaddress.IPv4Address(config["ingress_vip"]))
    require(not directory.exists(), "Evidence directory exists; use a fresh run")
    # Reuse endpoint/node identity/taint and platform checks before any mutation.
    subprocess.run([sys.executable, "check-cluster.py"], check=True, timeout=60)
    subprocess.run(["bash", "verify-platform.sh"], check=True, timeout=1800)
    directory.mkdir(parents=True, mode=0o700)
    plan = fixtures(uuid.uuid4().hex[:8])
    (directory / "fixtures.json").write_text(json.dumps(plan, indent=2) + "\n")
    result = {"run_id": plan["run_id"], "passed": False, "checks": [], "cleanup": {"namespaces": plan["namespaces"], "httproute_namespace": "psy-platform", "httproute": "psy-lab-acceptance-" + plan["run_id"]}}
    def record(name):
        result["checks"].append(name)
    try:
        for ns in plan["namespaces"]:
            require(not kubectl("get", "namespace", ns, "--ignore-not-found", "-o", "json").stdout.strip(), "Namespace exists; refusing to reuse it")
        require(not kubectl("-n", "psy-platform", "get", "httproute", result["cleanup"]["httproute"], "--ignore-not-found", "-o", "json").stdout.strip(), "Route exists; refusing to reuse it")
        # Do not race namespace default-ServiceAccount creation on a new cluster.
        create([p for p in plan["fixtures"] if p["kind"] in {"Namespace", "ServiceAccount"}])
        create([p for p in plan["fixtures"] if p["kind"] not in {"Namespace", "ServiceAccount"}])
        for ns in plan["namespaces"]:
            kubectl("-n", ns, "wait", "--for=condition=Ready", "pod", "--all", "--timeout=120s")
        for item in plan["fixtures"]:
            if item["kind"] == "Pod":
                actual = json.loads(kubectl("-n", item["metadata"]["namespace"], "get", "pod", item["metadata"]["name"], "-o", "json").stdout)
                require(actual["spec"]["nodeName"] == item["spec"]["nodeSelector"]["kubernetes.io/hostname"], "Unexpected probe placement")
        service = json.loads(kubectl("-n", plan["namespaces"][0], "get", "service", "http", "-o", "json").stdout)
        direct = "http://" + str(ipaddress.IPv4Address(service["spec"]["clusterIP"])) + ":8080/"
        dns = "http://http." + plan["namespaces"][0] + ".svc.cluster.local:8080/"
        for ns, pod in plan["allowed"] + plan["denied"]:
            response = fetch(ns, pod, dns)
            require(response.returncode == 0 and response.stdout == plan["body"], "Baseline DNS/HTTP failed: " + pod)
        record("all five clients pass DNS and HTTP before policies")
        create(plan["policies"])
        # Wait for policy propagation; allowed paths must also remain healthy.
        for ns, pod in plan["allowed"]:
            wait_until(lambda ns=ns, pod=pod: (lambda p: p.returncode == 0 and p.stdout == plan["body"])(fetch(ns, pod, dns)), "Allowed path failed: " + pod)
        for ns, pod in plan["denied"]:
            kubectl("-n", ns, "exec", pod, "--", "nslookup", "http." + plan["namespaces"][0] + ".svc.cluster.local")
            def denied(ns=ns, pod=pod):
                response = fetch(ns, pod, direct)
                # exec/setup/auth failures are not evidence of network isolation.
                return network_timeout(response)
            wait_until(denied, "Forbidden path was not blocked: " + pod)
            for _ in range(2):
                require(denied(), "Forbidden path changed state: " + pod)
        for ns, pod in plan["allowed"]:
            response = fetch(ns, pod, direct)
            require(response.returncode == 0 and response.stdout == plan["body"], "Positive control failed after denial tests")
        record("namespace AND Pod selector permit three workers and deny both decoys; DNS remains healthy")
        create(plan["ingress"])
        host = plan["run_id"] + ".psy-lab.invalid"
        # Ignore operator proxy env vars: exercise the actual LAN LoadBalancer VIP.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        def entrypoint():
            try:
                request = urllib.request.Request("http://" + ingress + "/", headers={"Host": host})
                with opener.open(request, timeout=4) as response:
                    return response.status == 200 and response.read(256).decode() == plan["body"]
            except OSError:
                return False
        wait_until(entrypoint, "LAN ingress VIP/HTTPRoute failed")
        record("operator LAN VIP -> Traefik -> cross-namespace HTTPRoute backend succeeds under policy")
        result["passed"] = True
        print("Network acceptance passed; fixtures retained. Cleanup names are in result.json")
    except Exception as exc:
        result["error"] = str(exc)
        raise
    finally:
        (directory / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        for path in directory.iterdir():
            path.chmod(0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--run", action="store_true")
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    os.chdir(Path(__file__).resolve().parent)
    if args.plan:
        print(json.dumps(fixtures("plan"), indent=2))
        return
    require(args.evidence is not None and args.evidence.is_absolute(), "Explicit absolute --evidence directory required")
    run_live(json.loads(Path("network-acceptance.json").read_text()), args.evidence)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as exc:
        sys.exit(str(exc))
