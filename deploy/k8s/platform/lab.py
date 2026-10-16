#!/usr/bin/env python3
"""Offline construction renderer and read-only host preflight; stdlib only."""
import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import struct
import sys
import tarfile
import urllib.request
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
LOCK = json.loads((HERE / "assets.lock.json").read_text())["assets"]
VERSIONS = json.loads((HERE.parent / "build/versions.json").read_text())["platform_candidates"]


def digest(path):
    with open(path, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def local_control(config):
    return config.get("topology", "three-host-ha") == "local-control-plane"


def first_server(config):
    name = "psy-lab-cp-local" if local_control(config) else "psy-lab-cp-x2"
    matches = [n for n in config["nodes"] if n["name"] == name and n["role"] == "server"]
    require(len(matches) == 1, "missing/duplicate first control node")
    return matches[0]


def api_address(config):
    return config["api_address"] if local_control(config) else config["api_vip"]


def validate(config):
    require(config["lab"] == "psy-k8s-local", "only the isolated psy-k8s-local lab is supported")
    for key in ("network_confirmed", "storage_confirmed"):
        require(type(config[key]) is bool, f"{key} must be boolean")
    require(config.get("topology", "three-host-ha") in {"three-host-ha", "local-control-plane"}, "unknown topology")
    single = local_control(config)
    require(set(config["hosts"]) == ({"local", "x2", "x3", "x4"} if single else {"x2", "x3", "x4"}), "unexpected physical host set; x1 is excluded")
    require(len(config["nodes"]) == (4 if single else 6), "unexpected VM count")
    require(all(n["host"] in config["hosts"] and n["role"] in {"server", "agent"} for n in config["nodes"]), "invalid node host/role")
    lan = ipaddress.IPv4Network(config["lan_cidr"])
    networks = [lan] + [ipaddress.IPv4Network(config[k]) for k in ("pod_cidr", "service_cidr")]
    networks += [ipaddress.IPv4Network(c) for c in config["reserved_cidrs"]]
    for i, net in enumerate(networks):
        require(all(not net.overlaps(other) for other in networks[i+1:]), "overlapping LAN/Pod/Service/reserved CIDRs")
    svc = networks[2]
    require(svc.num_addresses >= 32, "service CIDR too small")
    if single:
        require("api_vip" not in config and config["api_address"] == first_server(config)["ip"], "single control plane uses its own VM IP, without API VIP")
    addresses = [n["ip"] for n in config["nodes"]] + ([] if single else [config["api_vip"]]) + [config["ingress_vip"], config["gateway"]]
    require(len(addresses) == len(set(addresses)), "duplicate node/VIP/gateway IP")
    for addr in addresses:
        addr = ipaddress.IPv4Address(addr)
        require(addr in lan and addr not in (lan.network_address, lan.broadcast_address), "IP outside usable LAN")
    require(config["dns"], "at least one DNS IP required")
    for dns in config["dns"]:
        ipaddress.IPv4Address(dns)
    key = config["ssh_public_key"]
    require(bool(re.fullmatch(r"(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256) [A-Za-z0-9+/=]+(?: [^\r\n]*)?", key)), "dedicated SSH public key required")
    try:
        blob = base64.b64decode(key.split()[1], validate=True)
        length = struct.unpack(">I", blob[:4])[0]
        require(blob[4:4+length].decode() == key.split()[0] and len(blob) > 4 + length + 16, "invalid SSH public key wire encoding")
    except (ValueError, struct.error, UnicodeError) as exc:
        raise ValueError("invalid SSH public key wire encoding") from exc
    require(not set(addresses[:-1]) & {"192.168.5.20", "192.168.5.35", "192.168.5.41", "192.168.5.43"}, "lab IP collides with existing physical host")
    names, macs = set(), set()
    for host, spec in config["hosts"].items():
        if single:
            from_host = {"local": ("arch3900x", "peter", "/home/peter/git/bridge_zilong/k8s-local-control-plane/vm"),
                         **{h: ("arc99" + h, "psy", "/home/psy/k8s-lab/os") for h in ("x2", "x3", "x4")}}[host]
            require((spec.get("expected_hostname"), spec.get("operator"), spec["os_pool"]) == from_host, "host identity/operator/pool does not match operator setup")
            require(spec["ssh"] == ("local" if host == "local" else "arc99" + host) and spec["bridge"] == "br0", "unexpected host transport/bridge")
            if host == "x4":
                layouts = {"/mnt/psy-k8s-lab": "/mnt/psy-k8s-lab/vm-data", "/data": "/data/psy-k8s-lab/vm-data"}
                require(spec.get("data_mount") in layouts and spec.get("data_pool") == layouts[spec["data_mount"]], "x4 needs the prepared mounted disk and pool leaf")
                if spec["data_mount"] == "/data":
                    require(spec.get("data_uuid") == "d6d4015e-098a-4d6d-842d-6304bc015132" and spec.get("data_serial") == "2113C4462901", "Observed /data SSD UUID/serial required")
        require(bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", spec["ssh"])), "invalid host SSH alias")
        require(bool(re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", spec["bridge"])), "invalid bridge name")
        if "expected_hostname" in spec:
            require(bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", spec["expected_hostname"])), "invalid expected physical hostname")
        for field in ("qemu_user", "qemu_group"):
            if field in spec:
                require(bool(re.fullmatch(r"[A-Za-z0-9_-]+", spec[field])), "invalid qemu account")
        require(type(spec["minimum_available_memory_gib"]) is int and spec["minimum_available_memory_gib"] > 0, "memory reserve required")
        for field in ("os_pool", "data_pool"):
            if field in spec:
                p = spec[field]
                require(bool(re.fullmatch(r"/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+", p)), "unsafe pool path")
                require(".." not in Path(p).parts and len(Path(p).parts) >= 3, "pool needs a dedicated directory")
                require("k8s" in p and not p.startswith(("/etc/", "/dev/", "/var/lib/parth")), "pool must be dedicated to k8s")
        require("data_pool" not in spec or host == "x4", "only x4 owns a data pool")
        nodes = [n for n in config["nodes"] if n["host"] == host]
        if single:
            require(len(nodes) == 1 and nodes[0]["role"] == ("server" if host == "local" else "agent"), "local needs one server; x2/x3/x4 each need one agent")
        else:
            require({n["role"] for n in nodes} == {"server", "agent"} and len(nodes) == 2, "each host needs one server and one agent")
        total = sum(n["memory_gib"] for n in nodes)
        require(total <= {"local": 16, "x2": 24, "x3": 48, "x4": 48}[host], "VM memory exceeds host budget")
        require(spec["minimum_available_memory_gib"] >= total + 2, "host needs 2 GiB free beyond VM allocation")
    for n in config["nodes"]:
        expected = f"psy-lab-{'cp' if n['role'] == 'server' else 'work'}-{n['host']}"
        require(n["name"] == expected and n["name"] not in names, "unexpected/duplicate VM name")
        require(bool(re.fullmatch(r"52:54:00:(?:[0-9a-f]{2}:){2}[0-9a-f]{2}", n["mac"])) and n["mac"] not in macs, "invalid/duplicate MAC")
        for field, low, high in (("cpus", 2, 12), ("memory_gib", 4, 44), ("os_gib", 40, 160)):
            require(type(n[field]) is int and low <= n[field] <= high, f"invalid {field}")
        require(n.get("data_gib", 0) == 0 or (n["host"] == "x4" and n["role"] == "agent" and type(n["data_gib"]) is int and 256 <= n["data_gib"] <= 2048), "only work-x4 has a new data disk")
        names.add(n["name"])
        macs.add(n["mac"])
    require(next(n for n in config["nodes"] if n["name"] == "psy-lab-work-x4").get("data_gib", 0) >= 256, "x4 data disk required")
    require("data_pool" in config["hosts"]["x4"], "x4 data pool required")
    return config


def write(path, value, executable=False):
    if not isinstance(value, str):
        value = json.dumps(value, indent=2) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open("x") as stream:
        stream.write(value)
    path.chmod(0o700 if executable else 0o600)


def shell_prelude(config):
    ready = config["network_confirmed"] and config["storage_confirmed"]
    return '#!/usr/bin/env bash\nset -euo pipefail\numask 077\ncd -- "$(dirname -- "$0")"\n' + ("" if ready else 'echo "Example inventory: confirm network/storage and render again" >&2\nexit 1\n')


def guest_guard(config, node, stamp):
    return shell_prelude(config) + f'''[[ $EUID == 0 ]] || {{ echo "Run in the new VM with sudo" >&2; exit 1; }}
[[ $(systemd-detect-virt) == kvm ]] || {{ echo "KVM guest required" >&2; exit 1; }}
[[ $(hostname -s) == {shlex.quote(node['name'])} ]] || exit 1
[[ $(cat /etc/psy-k8s-lab) == {shlex.quote(stamp + ':' + node['name'])} ]] || exit 1
'''


def vm_xml(node, host):
    root = ET.Element("domain", type="kvm")
    ET.SubElement(root, "name").text = node["name"]
    ET.SubElement(root, "memory", unit="GiB").text = str(node["memory_gib"])
    ET.SubElement(root, "vcpu").text = str(node["cpus"])
    os_xml = ET.SubElement(root, "os")
    ET.SubElement(os_xml, "type", arch="x86_64", machine="q35").text = "hvm"
    ET.SubElement(os_xml, "boot", dev="hd")
    ET.SubElement(root, "features").append(ET.Element("acpi"))
    ET.SubElement(root, "cpu", mode="host-passthrough", check="none")
    ET.SubElement(root, "on_poweroff").text = "destroy"
    ET.SubElement(root, "on_reboot").text = "restart"
    ET.SubElement(root, "on_crash").text = "destroy"
    devices = ET.SubElement(root, "devices")
    for target, path, fmt, device in (
        ("vda", f"{host['os_pool']}/{node['name']}.qcow2", "qcow2", "disk"),
        ("sda", f"{host['os_pool']}/{node['name']}-seed.iso", "raw", "cdrom"),
        *(([("vdb", f"{host.get('data_pool')}/{node['name']}-data.qcow2", "qcow2", "disk")]) if node.get("data_gib") else []),
    ):
        disk = ET.SubElement(devices, "disk", type="file", device=device)
        ET.SubElement(disk, "driver", name="qemu", type=fmt)
        ET.SubElement(disk, "source", file=path)
        ET.SubElement(disk, "target", dev=target, bus="sata" if device == "cdrom" else "virtio")
        if device == "cdrom":
            ET.SubElement(disk, "readonly")
        if target == "vdb":
            ET.SubElement(disk, "serial").text = "psy-lab-data"
    iface = ET.SubElement(devices, "interface", type="bridge")
    ET.SubElement(iface, "mac", address=node["mac"])
    ET.SubElement(iface, "source", bridge=host["bridge"])
    ET.SubElement(iface, "model", type="virtio")
    console = ET.SubElement(devices, "console", type="pty")
    ET.SubElement(console, "target", type="serial", port="0")
    ET.indent(root)
    return ET.tostring(root, encoding="unicode") + "\n"


def object_(kind, name, spec=None, namespace=None, api="v1", **extra):
    obj = {"apiVersion": api, "kind": kind, "metadata": {"name": name}}
    if namespace:
        obj["metadata"]["namespace"] = namespace
    if spec is not None:
        obj["spec"] = spec
    obj.update(extra)
    return obj


def kube_vip(config):
    ns, name = "kube-system", "psy-lab-kube-vip"
    labels = {"app": name}
    rules = [{"apiGroups": ["coordination.k8s.io"], "resources": ["leases"], "verbs": ["get", "list", "watch", "create", "update", "patch"]},
             {"apiGroups": [""], "resources": ["nodes"], "verbs": ["get", "list", "watch"]}]
    values = {"vip_arp": "true", "port": "6443", "vip_interface": "eth0", "vip_subnet": "32", "cp_enable": "true", "cp_namespace": ns, "svc_enable": "false",
              "vip_ddns": "false", "vip_leaderelection": "true", "vip_leaseduration": "5", "vip_renewdeadline": "3", "vip_retryperiod": "1", "address": config["api_vip"]}
    env = [{"name": k, "value": v} for k, v in values.items()]
    env.append({"name": "vip_nodename", "valueFrom": {"fieldRef": {"fieldPath": "spec.nodeName"}}})
    return [object_("ServiceAccount", name, namespace=ns),
            object_("Role", name, namespace=ns, api="rbac.authorization.k8s.io/v1", rules=[rules[0]]),
            object_("RoleBinding", name, namespace=ns, api="rbac.authorization.k8s.io/v1", roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": name}, subjects=[{"kind": "ServiceAccount", "name": name, "namespace": ns}]),
            object_("ClusterRole", name, api="rbac.authorization.k8s.io/v1", rules=[rules[1]]),
            object_("ClusterRoleBinding", name, api="rbac.authorization.k8s.io/v1", roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": name}, subjects=[{"kind": "ServiceAccount", "name": name, "namespace": ns}]),
            object_("DaemonSet", name, {"selector": {"matchLabels": labels}, "template": {"metadata": {"labels": labels}, "spec": {
                "serviceAccountName": name, "hostNetwork": True, "dnsPolicy": "ClusterFirstWithHostNet", "nodeSelector": {"node-role.kubernetes.io/control-plane": "true"},
                "tolerations": [{"key": "node-role.kubernetes.io/control-plane", "operator": "Exists", "effect": "NoSchedule"}],
                "containers": [{"name": "kube-vip", "image": "ghcr.io/kube-vip/kube-vip:" + VERSIONS["kube_vip"], "args": ["manager"], "env": env,
                                "resources": {"requests": {"cpu": "50m", "memory": "64Mi"}, "limits": {"memory": "128Mi"}},
                                "securityContext": {"capabilities": {"add": ["NET_ADMIN", "NET_RAW"]}}}]}}}, namespace=ns, api="apps/v1")]


def platform_files(config, out):
    workers = {"psy.local/role": "worker"}
    spread = {"podAntiAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": [{"labelSelector": {"matchLabels": {"app.kubernetes.io/name": "traefik"}}, "topologyKey": "kubernetes.io/hostname"}]}}
    if not local_control(config):
        write(out / "kube-vip.json", {"apiVersion": "v1", "kind": "List", "items": kube_vip(config)})
    namespaces = [object_("Namespace", ns) for ns in ("psy-platform", "psy-data", "psy-chain", "psy-compute", "psy-app", "psy-observe", "metallb-system")]
    # MetalLB speaker/node-exporter need host network privileges; no global restricted PSA.
    for obj in namespaces:
        obj["metadata"]["labels"] = {"psy.local/lab": config["lab"]}
    write(out / "namespaces.json", {"apiVersion": "v1", "kind": "List", "items": namespaces})
    write(out / "metallb-values.json", {"controller": {"nodeSelector": workers, "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"memory": "256Mi"}}}, "speaker": {"nodeSelector": workers, "frr": {"enabled": False}}, "frrk8s": {"enabled": False}})
    write(out / "metallb-pool.json", {"apiVersion": "v1", "kind": "List", "items": [
        object_("IPAddressPool", "psy-lab-ingress", {"addresses": [config["ingress_vip"] + "/32"], "autoAssign": False}, namespace="metallb-system", api="metallb.io/v1beta1"),
        object_("L2Advertisement", "psy-lab-ingress", {"ipAddressPools": ["psy-lab-ingress"], "nodeSelectors": [{"matchLabels": workers}], "interfaces": ["eth0"]}, namespace="metallb-system", api="metallb.io/v1beta1")]})
    write(out / "traefik-values.json", {"deployment": {"replicas": 3}, "nodeSelector": workers, "affinity": spread,
          "updateStrategy": {"type": "RollingUpdate", "rollingUpdate": {"maxUnavailable": 1, "maxSurge": 0}},
          "podDisruptionBudget": {"enabled": True, "minAvailable": 2}, "providers": {"kubernetesGateway": {"enabled": True}, "kubernetesIngress": {"enabled": False}},
          "gateway": {"enabled": True}, "service": {"annotations": {"metallb.io/address-pool": "psy-lab-ingress", "metallb.io/loadBalancerIPs": config["ingress_vip"]}, "spec": {"externalTrafficPolicy": "Local"}},
          "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"memory": "256Mi"}}})
    storage = [object_("StorageClass", "psy-lab-local", api="storage.k8s.io/v1", provisioner="kubernetes.io/no-provisioner", reclaimPolicy="Retain", volumeBindingMode="WaitForFirstConsumer")]
    for name, gib in (("prometheus", 50), ("alertmanager", 2), ("grafana", 2)):
        storage.append(object_("PersistentVolume", "psy-lab-" + name, {"capacity": {"storage": f"{gib}Gi"}, "accessModes": ["ReadWriteOnce"], "volumeMode": "Filesystem", "storageClassName": "psy-lab-local", "persistentVolumeReclaimPolicy": "Retain",
            "local": {"path": "/srv/psy-lab/" + name}, "nodeAffinity": {"required": {"nodeSelectorTerms": [{"matchExpressions": [{"key": "kubernetes.io/hostname", "operator": "In", "values": ["psy-lab-work-x4"]}]}]}}}))
        if name == "grafana":
            storage[-1]["spec"]["claimRef"] = {"namespace": "psy-observe", "name": "psy-lab-grafana"}
    storage.append(object_("PersistentVolumeClaim", "psy-lab-grafana", {"storageClassName": "psy-lab-local", "volumeName": "psy-lab-grafana", "accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "2Gi"}}}, namespace="psy-observe"))
    write(out / "storage.json", {"apiVersion": "v1", "kind": "List", "items": storage})
    def claim(size):
        return {"volumeClaimTemplate": {"spec": {"storageClassName": "psy-lab-local", "accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": size}}}}}
    # K3s embeds etcd/scheduler/controller/proxy: kubeadm selectors are incorrect.
    monitoring = {k: {"enabled": False} for k in ("kubeEtcd", "kubeControllerManager", "kubeScheduler", "kubeProxy")}
    monitoring.update({"defaultRules": {"rules": {"etcd": False, "kubeControllerManager": False, "kubeSchedulerAlerting": False, "kubeSchedulerRecording": False, "kubeProxy": False}},
        "grafana": {"nodeSelector": {"kubernetes.io/hostname": "psy-lab-work-x4"}, "admin": {"existingSecret": "psy-lab-grafana-admin", "userKey": "admin-user", "passwordKey": "admin-password"}, "persistence": {"enabled": True, "existingClaim": "psy-lab-grafana"}},
        "prometheusOperator": {"nodeSelector": workers}, "kube-state-metrics": {"nodeSelector": workers},
        "prometheus-node-exporter": {"tolerations": [{"operator": "Exists", "effect": "NoSchedule"}]},
        "prometheus": {"prometheusSpec": {"replicas": 1, "nodeSelector": {"kubernetes.io/hostname": "psy-lab-work-x4"}, "retention": "7d", "retentionSize": "35GB", "storageSpec": claim("50Gi"), "resources": {"requests": {"cpu": "500m", "memory": "2Gi"}, "limits": {"memory": "4Gi"}}}},
        "alertmanager": {"alertmanagerSpec": {"replicas": 1, "nodeSelector": {"kubernetes.io/hostname": "psy-lab-work-x4"}, "storage": claim("2Gi")}}})
    if local_control(config):
        monitoring["prometheus-node-exporter"]["nodeSelector"] = workers
    write(out / "prometheus-values.json", monitoring)


def render(config, destination):
    config = validate(config)
    require(not destination.exists(), "output already exists; use a new directory (no overwrite)")
    destination.mkdir(parents=True, mode=0o700)
    stamp = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
    write(destination / "inventory.json", config)
    write(destination / "inventory.sha256", stamp + "\n")
    shutil.copyfile(HERE / "assets.lock.json", destination / "assets.lock.json")
    (destination / "assets.lock.json").chmod(0o600)
    for host, spec in config["hosts"].items():
        host_dir = destination / "hosts" / host
        write(host_dir / "host.json", {**spec, "nodes": [n for n in config["nodes"] if n["host"] == host], "confirmed": config["network_confirmed"] and config["storage_confirmed"]})
        creator = HERE.parent / "local-control-plane/create-vm.py" if local_control(config) else HERE / "create-vms.py"
        write(host_dir / "create-vms.py", creator.read_text(), True)
        if local_control(config):
            write(host_dir / "host_setup.py", (HERE.parent / "local-control-plane/host-setup/host_setup.py").read_text())
    first = first_server(config)
    for node in config["nodes"]:
        name = node["name"]
        path = destination / "nodes" / name
        host_dir = destination / "hosts" / node["host"]
        write(host_dir / (name + ".xml"), vm_xml(node, config["hosts"][node["host"]]))
        write(host_dir / (name + "-meta.json"), {"instance-id": stamp + ":" + name, "local-hostname": name})
        write(host_dir / (name + "-user.yaml"), "#cloud-config\n" + json.dumps({"hostname": name, "manage_etc_hosts": True, "ssh_pwauth": False, "disable_root": True, "users": [{"name": "ubuntu", "groups": ["sudo"], "sudo": ["ALL=(ALL) NOPASSWD:ALL"], "shell": "/bin/bash", "lock_passwd": True, "ssh_authorized_keys": [config["ssh_public_key"]]}], "write_files": [{"path": "/etc/psy-k8s-lab", "permissions": "0600", "content": stamp + ":" + name + "\n"}], "package_update": True, "packages": ["qemu-guest-agent", "curl", "ca-certificates", "open-iscsi"], "runcmd": [["systemctl", "enable", "--now", "qemu-guest-agent"]]}, indent=2) + "\n")
        write(host_dir / (name + "-network.json"), {"version": 2, "ethernets": {"eth0": {"match": {"macaddress": node["mac"]}, "set-name": "eth0", "dhcp4": False, "addresses": [f"{node['ip']}/{ipaddress.IPv4Network(config['lan_cidr']).prefixlen}"], "routes": [{"to": "default", "via": config["gateway"]}], "nameservers": {"addresses": config["dns"]}}}})
        cfg = {"node-name": name, "node-ip": node["ip"], "flannel-iface": "eth0", "token-file": "/etc/rancher/k3s/lab-token", "node-label": ["psy.local/lab=" + config["lab"], "psy.local/host=" + node["host"], "psy.local/role=" + ("control-plane" if node["role"] == "server" else "worker")], "kubelet-arg": ["fail-swap-on=true"]}
        if node["role"] == "server":
            cfg.update({"disable": ["traefik", "servicelb", "local-storage"], "secrets-encryption": True, "write-kubeconfig-mode": "0600", "cluster-cidr": config["pod_cidr"], "service-cidr": config["service_cidr"], "cluster-dns": str(ipaddress.IPv4Network(config["service_cidr"]).network_address + 10), "tls-san": [api_address(config)], "node-taint": ["node-role.kubernetes.io/control-plane=true:NoSchedule"], "etcd-snapshot-retention": 5, "etcd-snapshot-schedule-cron": "0 */6 * * *"})
        if node == first:
            cfg["cluster-init"] = True
        else:
            cfg["server"] = "https://" + api_address(config) + ":6443"
        if node.get("data_gib"):
            cfg["data-dir"] = "/srv/psy-lab/k3s"
        if local_control(config) and node["role"] == "server":
            # K3s CoreDNS/metrics-server tolerate the standard control-plane taint.
            # This dedicated taint keeps even those addons off the operator host.
            cfg["node-taint"].append("psy.local/control-only=true:NoSchedule")
        write(path / "config.yaml", cfg)  # JSON is a YAML subset.
        unit = f'''[Unit]
Description=Psy isolated lab K3s {node['role']}
After=network-online.target
Wants=network-online.target
{('RequiresMountsFor=/srv/psy-lab' if node.get('data_gib') else '')}

[Service]
Type=notify
KillMode=process
Delegate=yes
LimitNOFILE=1048576
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
TimeoutStartSec=300
Restart=always
RestartSec=5
ExecStartPre=/sbin/modprobe br_netfilter
ExecStartPre=/sbin/modprobe overlay
ExecStart=/usr/local/bin/k3s {node['role']} --config /etc/rancher/k3s/config.yaml

[Install]
WantedBy=multi-user.target
'''
        write(path / "psy-lab-k3s.service", unit)
        guard = guest_guard(config, node, stamp)
        write(path / "install-k3s.sh", guard + f'''[[ $# == 1 ]] || {{ echo "Usage: sudo ./install-k3s.sh /path/to/token-file" >&2; exit 1; }}
[[ -f $1 && ! -L $1 ]] || exit 1
[[ $(stat -c '%a' "$1") == 600 && $(stat -c '%u' "$1") == 0 ]] || {{ echo "token must be root-owned mode 600" >&2; exit 1; }}
[[ $(wc -c < "$1") -ge 32 ]] || {{ echo "token too short" >&2; exit 1; }}
for existing in /etc/rancher/k3s /var/lib/rancher/k3s /usr/local/bin/k3s /etc/systemd/system/k3s.service /etc/systemd/system/k3s-agent.service /etc/systemd/system/psy-lab-k3s.service; do
  [[ ! -e $existing ]] || {{ echo "Existing K3s path: $existing; inspect before resuming" >&2; exit 1; }}
done
[[ $(swapon --noheadings | wc -l) == 0 ]] || {{ echo "Guest swap must be off" >&2; exit 1; }}
{('mountpoint -q /srv/psy-lab\n[[ $(findmnt -n -o LABEL /srv/psy-lab) == psy-lab-data ]] || exit 1' if node.get('data_gib') else '')}
echo '{LOCK['k3s']['sha256']}  k3s' | sha256sum --check --status
install -d -m 700 /etc/rancher/k3s
install -m 600 "$1" /etc/rancher/k3s/lab-token
install -m 600 config.yaml /etc/rancher/k3s/config.yaml
install -m 755 k3s /usr/local/bin/k3s
install -m 644 psy-lab-k3s.service /etc/systemd/system/psy-lab-k3s.service
printf '%s\\n' 'net.ipv4.ip_forward=1' 'net.bridge.bridge-nf-call-iptables=1' > /etc/sysctl.d/90-psy-lab.conf
modprobe br_netfilter
sysctl --system > /dev/null
systemctl daemon-reload
systemctl enable --now psy-lab-k3s
echo 'Installed; use systemctl status psy-lab-k3s and k3s kubectl get nodes'
''', True)
        if node.get("data_gib"):
            write(path / "initialize-data.sh", guard + (HERE / "initialize-data.sh").read_text(), True)
    plat = destination / "platform"
    platform_files(config, plat)
    for script in ("bootstrap-vip.sh", "install-platform.sh", "verify-platform.sh"):
        if local_control(config) and script == "bootstrap-vip.sh":
            write(plat / "check-bootstrap.sh", shell_prelude(config) + 'python3 check-cluster.py --bootstrap\nkubectl get --raw=/readyz\necho "Control plane Ready; join the three workers with the SAME lab token"\n', True)
            continue
        write(plat / script, shell_prelude(config) + (HERE / script).read_text(), True)
    write(plat / "check-cluster.py", (HERE / "check-cluster.py").read_text(), True)
    write(plat / "verify-assets.py", (HERE / "verify-assets.py").read_text(), True)
    write(plat / "assets.lock.json", json.loads((HERE / "assets.lock.json").read_text()))
    write(plat / "expected-nodes.json", {n["name"]: {"ip": n["ip"], "role": n["role"]} for n in config["nodes"]})
    write(plat / "api-vip", api_address(config) + "\n")
    write(plat / "ingress-vip", config["ingress_vip"] + "\n")
    write(plat / "server-ips.json", [n["ip"] for n in config["nodes"] if n["role"] == "server"])
    if local_control(config):
        write(plat / "network-acceptance.py", (HERE.parent / "local-control-plane/network-acceptance.py").read_text(), True)
        write(plat / "network-acceptance.json", {"topology": "local-control-plane", "execution_enabled": config["network_confirmed"] and config["storage_confirmed"], "workers": ["psy-lab-work-" + role for role in ("x2", "x3", "x4")], "ingress_vip": config["ingress_vip"]})
    print(json.dumps({"output": str(destination), "inventory_sha256": stamp, "execution_enabled": config["network_confirmed"] and config["storage_confirmed"]}))


def fetch(destination, include_vm):
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name, spec in LOCK.items():
        if spec.get("large_vm_image") and not include_vm:
            continue
        path = destination / name
        if not path.exists():
            part = destination / (name + ".part")
            require(not part.exists(), f"partial file exists: {part}; inspect it first")
            with urllib.request.urlopen(spec["url"], timeout=120) as response, part.open("xb") as stream:
                shutil.copyfileobj(response, stream)
            require(digest(part) == spec["sha256"], f"checksum mismatch: {name}")
            part.rename(path)
        require(digest(path) == spec["sha256"], f"checksum mismatch: {name}")
        path.chmod(0o700 if name == "k3s" else 0o600)
        print(f"verified {name}")
    # Extract just the verified Helm executable, never arbitrary tar members.
    with tarfile.open(destination / "helm.tgz") as archive:
        with archive.extractfile("linux-amd64/helm") as source, (destination / "helm").open("wb") as target:
            shutil.copyfileobj(source, target)
    (destination / "helm").chmod(0o700)


def charts(output, assets):
    for name in ("helm.tgz", "metallb.tgz", "traefik.tgz", "prometheus.tgz", "gateway-api.yaml"):
        require(digest(assets / name) == LOCK[name]["sha256"], f"asset mismatch: {name}")
    with tarfile.open(assets / "helm.tgz") as archive:
        require(hashlib.sha256(archive.extractfile("linux-amd64/helm").read()).hexdigest() == digest(assets / "helm"), "Helm executable mismatch")
    for name, ns in (("metallb", "metallb-system"), ("traefik", "psy-platform"), ("prometheus", "psy-observe")):
        result = subprocess.run([str(assets / "helm"), "template", "psy-lab-" + name, str(assets / (name + ".tgz")), "--namespace", ns, "--kube-version", "1.35.9", "--include-crds", "-f", str(output / "platform" / (name + "-values.json"))], check=True, stdout=subprocess.PIPE)
        write(output / "platform" / (name + "-rendered.yaml"), result.stdout.decode())
    for name in ("metallb.tgz", "traefik.tgz", "prometheus.tgz", "gateway-api.yaml", "helm", "helm.tgz"):
        target = output / "platform" / name
        require(not target.exists(), f"asset already copied: {target}")
        shutil.copyfile(assets / name, target)
        target.chmod(0o700 if name == "helm" else 0o600)
    print("Charts rendered with pinned Helm; API/server validation remains a live acceptance gate")


def preflight(config):
    validate(config)
    if local_control(config):
        return four_host_preflight(config)
    # Read-only, no credentials, process arguments, service logs or environment dumps.
    for host, spec in config["hosts"].items():
        probe = '''import json,os,pathlib,shutil,subprocess,pwd,grp
def run(args):
 try:
  p=subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
  return {"exit":p.returncode,"stdout":p.stdout.strip(),"stderr":p.stderr.strip()}
 except (OSError,subprocess.TimeoutExpired) as exc:
  return {"exit":127,"stdout":"","stderr":str(exc)}
def parent(p):
 p=pathlib.Path(p)
 while not p.exists(): p=p.parent
 return str(p)
'''
        pools = [spec["os_pool"]] + ([spec["data_pool"]] if "data_pool" in spec else [])
        probe += "pools=" + repr(pools) + "\n"
        probe += '''print(json.dumps({"hostname":pathlib.Path("/proc/sys/kernel/hostname").read_text().strip(),"os_release":pathlib.Path("/etc/os-release").read_text(),"qemu_accounts":[p.pw_name for p in pwd.getpwall() if p.pw_name in ["qemu","libvirt-qemu"]],"qemu_groups":[g.gr_name for g in grp.getgrall() if g.gr_name in ["qemu","libvirt-qemu","kvm"]],"kvm":os.access("/dev/kvm",os.R_OK|os.W_OK),"meminfo":pathlib.Path("/proc/meminfo").read_text(),"routes":run(["ip","-j","route"]),"links":run(["ip","-j","link"]),"disks":run(["lsblk","-J","-o","NAME,SIZE,FSTYPE,MOUNTPOINTS"]),"helpers":{t:shutil.which(t) for t in ["virsh","qemu-img","cloud-localds"]},"pools":{p:{"existing_parent":parent(p),"free_gib":shutil.disk_usage(parent(p)).free//2**30,"mount":run(["findmnt","-J","-T",parent(p)])} for p in pools}},indent=2))
'''
        result = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", spec["ssh"], "python3 -"], input=probe, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        report = json.loads(result.stdout) if result.returncode == 0 else None
        checks = {}
        if report:
            mem = dict(line.split(":", 1) for line in report["meminfo"].splitlines())
            links = json.loads(report["links"]["stdout"]) if report["links"]["exit"] == 0 else []
            checks = {"kvm_access": report["kvm"], "helpers": all(report["helpers"].values()), "available_ram": int(mem["MemAvailable"].split()[0]) / 2**20 >= spec["minimum_available_memory_gib"],
                      "bridge_exists": any(n["ifname"] == spec["bridge"] for n in links),
                      "os_pool_exists": report["pools"][spec["os_pool"]]["existing_parent"] == spec["os_pool"],
                      "os_pool_capacity": report["pools"][spec["os_pool"]]["free_gib"] >= sum(n["os_gib"] for n in config["nodes"] if n["host"] == host) + 16}
            report["checks"] = checks
        print(json.dumps({"host": host, "ssh": spec["ssh"], "exit": result.returncode, "report": report, "stderr": result.stderr}, indent=2))
        require(result.returncode == 0, "SSH preflight failed")


def four_host_preflight(config):
    """Collect every host before returning failure; never install or modify hosts."""
    source = (HERE.parent / "local-control-plane/host-setup/host_setup.py").read_text()
    ready = True
    for role, spec in config["hosts"].items():
        probe = "import types,io,contextlib,json,shutil,pathlib\nsetup=types.ModuleType('host_setup_probe')\n"
        probe += "exec(" + repr(source) + ",setup.__dict__)\n"
        probe += "role=" + repr(role) + "\nspec=" + repr(spec) + "\n"
        probe += '''cfg=setup.identity(role)
output=io.StringIO()
with contextlib.redirect_stdout(output): setup.check(cfg)
report=json.loads(output.getvalue())
mem=dict(line.split(':',1) for line in pathlib.Path('/proc/meminfo').read_text().splitlines())
report['available_memory_gib']=int(mem['MemAvailable'].split()[0])/2**20
report['checks']['memory_capacity']=report['available_memory_gib']>=spec['minimum_available_memory_gib']
report['routes']=json.loads(setup.run('ip','-j','route'))
if role=='x4':
 mount=pathlib.Path(spec['data_mount']); pool=pathlib.Path(spec['data_pool'])
 mounted=mount.is_mount() and not mount.is_symlink()
 report['checks']['new_data_mount']=mounted
 report['checks']['new_data_pool']=pool.is_dir() and not pool.is_symlink() and mounted and pool.stat().st_dev==mount.stat().st_dev
 disks=setup.backing_disks(mount) if mounted else set()
 report['checks']['new_data_disk']=bool(disks) and disks.isdisjoint(setup.backing_disks('/')) and disks.isdisjoint(setup.backing_disks('/home'))
 report['checks']['new_data_capacity']=mounted and shutil.disk_usage(mount).free>=288*2**30
 if spec.get('data_uuid'):
  report['checks']['new_data_uuid']=mounted and setup.run('findmnt','-n','-o','UUID','-T',str(mount))==spec['data_uuid']
  report['checks']['new_data_serial']=len(disks)==1 and setup.run('lsblk','-dn','-o','SERIAL','/dev/'+next(iter(disks)))==spec['data_serial']
print(json.dumps(report))
'''
        command = [sys.executable, "-"] if role == "local" else ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", spec["ssh"], "python3 -"]
        result = subprocess.run(command, input=probe, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        report = json.loads(result.stdout) if result.returncode == 0 else None
        passed = report is not None and all(report["checks"].values())
        ready = ready and passed
        print(json.dumps({"host": role, "ready": passed, "report": report, "stderr": result.stderr}, indent=2))
    require(ready, "Host preparation incomplete; inspect failed checks above. No host changes made")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for cmd in ("plan", "render", "preflight"):
        p = sub.add_parser(cmd)
        p.add_argument("--inventory", type=Path, required=True)
        if cmd == "render":
            p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("fetch")
    p.add_argument("--assets", type=Path, required=True)
    p.add_argument("--include-vm-image", action="store_true")
    p = sub.add_parser("charts")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--assets", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "fetch":
        fetch(args.assets.resolve(), args.include_vm_image)
    elif args.command == "charts":
        charts(args.output.resolve(), args.assets.resolve())
    else:
        config = validate(json.loads(args.inventory.read_text()))
        if args.command == "plan":
            print(json.dumps({"lab": config["lab"], "execution_enabled": config["network_confirmed"] and config["storage_confirmed"], "nodes": config["nodes"], "minimum_os_free_gib_per_host": {h: sum(n["os_gib"] for n in config["nodes"] if n["host"] == h) + 16 for h in config["hosts"]}, "x4_data_free_gib": next(n["data_gib"] for n in config["nodes"] if n.get("data_gib")) + 32}, indent=2))
        elif args.command == "render":
            render(config, args.output.resolve())
        else:
            preflight(config)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as exc:
        sys.exit(str(exc))
