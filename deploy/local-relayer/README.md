# Local Relayer

Prepare a self-contained local runtime directory for the staging bridge relayer:

```bash
cd "$WORKSPACE_HOME/psy-node-deploy-unified"
bash deploy/local-relayer/prepare-local-relayer.sh
```

The generated runtime is written to:

```bash
dist/local-relayer
```

Run it with secrets supplied by environment variables:

```bash
cd dist/local-relayer
export BRIDGE_RELAYER_L2_PRIVATE_KEY="<genesis user 2 private key>"
export WALLET_PASSWORD="<L1 keystore password>"
./run.sh
```

Install it as a local systemd user service:

```bash
bash deploy/local-relayer/install-systemd-user-service.sh
editor ~/.config/parth-local-relayer/env
systemctl --user start parth-local-relayer.service
journalctl --user -u parth-local-relayer.service -f
```

Set the bridge relayer L2 key from `private_keys.json[2]`, verify it resolves
to `BRIDGE_USER_ID=524288`, and restart the user service:

```bash
bash deploy/local-relayer/set-bridge-key.sh
```

If the service should keep running after you log out:

```bash
loginctl enable-linger "$USER"
```

For a clean test, stop the cloud relayer first:

```bash
ssh gcp-realm-worker-1 'sudo systemctl stop parth-relayer.service'
```

Running multiple active relayers against the same bridge is not recommended because they can race on L2 append/finalize work and L1 transaction submission.
