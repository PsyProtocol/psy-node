# Appended after the generated inventory readiness guard.
[[ $# == 1 && $1 == --install ]] || { echo 'Usage: KUBECONFIG=/abs/lab.yaml ./install-platform.sh --install' >&2; exit 1; }
python3 check-cluster.py
python3 verify-assets.py
kubectl apply -f namespaces.json
kubectl apply -f storage.json
kubectl apply --server-side -f gateway-api.yaml
kubectl wait --for=condition=Established crd/gatewayclasses.gateway.networking.k8s.io crd/gateways.gateway.networking.k8s.io crd/httproutes.gateway.networking.k8s.io --timeout=120s
./helm upgrade --install psy-lab-metallb metallb.tgz --namespace metallb-system -f metallb-values.json --wait --timeout 10m
kubectl wait --for=condition=Established crd/ipaddresspools.metallb.io crd/l2advertisements.metallb.io --timeout=120s
kubectl apply -f metallb-pool.json
./helm upgrade --install psy-lab-traefik traefik.tgz --namespace psy-platform -f traefik-values.json --wait --timeout 10m
# Generate admin credentials on the operator machine and stream through stdin;
# never persist the password in a rendered bundle, command argument or log.
if ! kubectl -n psy-observe get secret psy-lab-grafana-admin >/dev/null 2>&1; then
  python3 - <<'PY' | kubectl apply -f - >/dev/null
import base64,json,secrets
print(json.dumps({"apiVersion":"v1","kind":"Secret","metadata":{"name":"psy-lab-grafana-admin","namespace":"psy-observe"},"type":"Opaque","data":{"admin-user":base64.b64encode(b"admin").decode(),"admin-password":base64.b64encode(secrets.token_urlsafe(32).encode()).decode()}}))
PY
fi
./helm upgrade --install psy-lab-prometheus prometheus.tgz --namespace psy-observe -f prometheus-values.json --wait --timeout 15m
kubectl -n psy-observe wait --for=condition=Ready pod -l app.kubernetes.io/name=prometheus --timeout=10m
kubectl -n psy-observe wait --for=condition=Ready pod -l app.kubernetes.io/name=alertmanager --timeout=10m
./verify-platform.sh
