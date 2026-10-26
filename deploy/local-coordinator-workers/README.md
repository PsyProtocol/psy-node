# Local Coordinator Workers

Run two coordinator proof workers on the local workstation to share staging load
with the cloud `gcp-coordinator-worker` VM.

The workers use the same coordinator worker private key as staging genesis user
0. They connect to cloud Scylla, NATS, and Redis through SSH local port
forwards via `gcp-cp-ce`, and call the public coordinator edge URL.

```sh
bash deploy/local-coordinator-workers/prepare-local-coordinator-workers.sh
bash deploy/local-coordinator-workers/install-systemd-user-services.sh
bash deploy/local-coordinator-workers/start-systemd-user-services.sh
```

Logs:

```sh
journalctl --user -u parth-local-coordinator-worker-tunnel.service -f
journalctl --user -u 'parth-local-coordinator-worker@*.service' -f
```

Stop:

```sh
bash deploy/local-coordinator-workers/stop-systemd-user-services.sh
```

The local worker services are intentionally opt-in. They are not started by the
cloud fresh deploy scripts.
