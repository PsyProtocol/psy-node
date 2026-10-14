# Appended after the generated inventory readiness guard.
[[ $# == 1 && $1 == --bootstrap ]] || { echo 'Use first server direct-IP kubeconfig, then ./bootstrap-vip.sh --bootstrap' >&2; exit 1; }
python3 check-cluster.py --bootstrap
kubectl apply -f kube-vip.json
kubectl -n kube-system rollout status daemonset/psy-lab-kube-vip --timeout=5m
vip=$(cat api-vip)
# --server overrides only the endpoint; existing kubeconfig still verifies TLS.
kubectl --server="https://$vip:6443" get --raw=/readyz
echo 'VIP Ready; join cp-x3, then cp-x4, then the three workers using the SAME token'
