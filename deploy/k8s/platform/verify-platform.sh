# Appended after the generated inventory readiness guard.
python3 check-cluster.py
kubectl -n kube-system rollout status deployment/coredns --timeout=5m
kubectl -n kube-system rollout status deployment/metrics-server --timeout=5m
if [[ -f kube-vip.json ]]; then
  kubectl -n kube-system rollout status daemonset/psy-lab-kube-vip --timeout=5m
fi
kubectl -n metallb-system rollout status deployment/psy-lab-metallb-controller --timeout=5m
kubectl -n metallb-system rollout status daemonset/psy-lab-metallb-speaker --timeout=5m
kubectl -n psy-platform rollout status deployment/psy-lab-traefik --timeout=5m
python3 - <<'PY'
import json,subprocess
from pathlib import Path
def get(ns,kind,name):
 return json.loads(subprocess.check_output(["kubectl","-n",ns,"get",kind,name,"-o","json"]))
def check(ok,why):
 if not ok: raise SystemExit(why)
expected=json.loads(Path("expected-nodes.json").read_text())
single="psy-lab-cp-local" in expected
counts=[("metallb-system","psy-lab-metallb-speaker",3),("psy-observe","psy-lab-prometheus-prometheus-node-exporter",3 if single else len(expected))]
if Path("kube-vip.json").exists(): counts.append(("kube-system","psy-lab-kube-vip",3))
for ns,name,count in counts:
 ds=get(ns,"daemonset",name)
 check(ds["status"].get("desiredNumberScheduled")==count and ds["status"].get("numberReady")==count,"Wrong ready count: "+name)
if single:
 pods=json.loads(subprocess.check_output(["kubectl","get","pods","--all-namespaces","--field-selector","spec.nodeName=psy-lab-cp-local","-o","json"]))["items"]
 check(not pods,"Control plane must have no scheduled Pods")
service=get("psy-platform","service","psy-lab-traefik")
check({x.get("ip") for x in service["status"].get("loadBalancer",{}).get("ingress",[])}=={Path("ingress-vip").read_text().strip()},"Application VIP not allocated")
pods=json.loads(subprocess.check_output(["kubectl","-n","psy-platform","get","pods","-l","app.kubernetes.io/name=traefik","-o","json"]))["items"]
check(len(pods)==3 and len({p["spec"]["nodeName"] for p in pods})==3,"Traefik must spread over three workers")
gateway=get("psy-platform","gateway","traefik-gateway")
check(any(c["type"]=="Programmed" and c["status"]=="True" for c in gateway.get("status",{}).get("conditions",[])),"Gateway is not Programmed")
pvcs=json.loads(subprocess.check_output(["kubectl","-n","psy-observe","get","pvc","-o","json"]))["items"]
check(len(pvcs)==3 and all(p["status"]["phase"]=="Bound" for p in pvcs),"Expected three bound monitoring PVCs")
pods=json.loads(subprocess.check_output(["kubectl","-n","psy-observe","get","pods","-o","json"]))["items"]
for p in pods:
 if p["status"].get("phase")=="Succeeded": continue
 check(any(c["type"]=="Ready" and c["status"]=="True" for c in p["status"].get("conditions",[])),"Monitoring pod not Ready: "+p["metadata"]["name"])
print("Platform scheduling/storage/VIP checks passed; perform LAN HTTP and failover tests separately")
PY
