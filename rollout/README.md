# Two-process prove-proxy rollout

Runtime: `3a81f59e0cf9333fc2ad4aefda7c83787660c9ab`.
Supersedes the earlier single-process role=all plan. Do not use the original
untracked 02/03 rollout prototypes.

## Topology

| Caller | Gateway | arc99x3 service | Role |
| --- | --- | --- | --- |
| Wallet / Faucet, existing prove-stg URL | 10.148.0.32:19999 | parth-prove-proxy@user on 10.250.0.12:9999 | user |
| Relayer system_prove_proxy_url | 10.148.0.32:19998 | parth-prove-proxy@system on 10.250.0.12:9998 | system |

Two independent PIDs, circuit caches, restart policies and journals. Both use
the same immutable binary and the existing config/keystores. They are not
dispatcher/workers. Old parth-offsite-prove-proxy is disabled and stopped
before either new process starts, avoiding triple-process startup memory.
Splitting roles does not establish a hard memory bound.

Optional per-role files `/etc/parth/prove-proxy-user.env` and
`/etc/parth/prove-proxy-system.env` can override RPC_CONFIG and
PROVE_PROXY_ROLE_LISTEN_ADDR when moving a role to another host.
No role env override is needed for the current topology.

## Order

1. Build: `BOOKWORM_BUILD_GITHUB_SSH_KEY=$HOME/.ssh/id_ed25519 bash rollout/build-relayer-only.sh`
2. Stage: `bash rollout/stage-role-release.sh relayer` and `bash rollout/stage-role-release.sh proxy`.
3. Upload gateway-system-proxy.sh to gcp-gateway, then run it with sudo and
   argument deploy. This adds only the private 19998 listener; no WireGuard,
   existing forwarding, DNS or Caddy change. Socket ingress permits only
   gcp-faucet 10.148.0.33 and the gateway itself. Check host support for the
   systemd IP filter and keep cloud firewall restrictions in place.
4. User runs on arc99x3:
   `bash ~/prove-proxy-role-3a81f59e/remote-proxy.sh deploy`.
   This is now a forwarding entry to remote-proxy-split.sh, NOT role=all.
5. Verify both local roles, separate PIDs, opposite-role -32601 responses,
   and the system endpoint from gcp-faucet.
6. Activate on gcp-faucet:
   `sudo bash ~/prove-proxy-role-3a81f59e/remote-relayer.sh deploy`.
   It refuses activation until the dedicated system endpoint is ready.

While step 4 runs, user proving is temporarily unavailable. Between steps 4
and 6 the old relayer still calls the user port for system proofs, so bridge
proofs will fail/retry. Complete step 6 promptly after readiness; do not
claim full bridge availability before it completes. Coordinate a maintenance
window or stop only the old relayer during this interval.

## Preservation and rollback

No genesis, keystore, node release symlink, old proxy binary/wrapper/env,
database, worker, frontend or wallet is replaced by the split installer.
It installs a new binary under /opt/parth/prove-proxy-role-releases/3a81f59e,
a new systemd template, and disables the old single-process service.
The mount dependencies and existing service user/sandbox settings are retained.

Both remote installers support verify and rollback. Proxy rollback stops and
disables both new units, restores the old enabled state, and starts the
unmodified old service. Relayer rollback restores its paired binary/config.
If both upgrades were applied, roll back relayer and proxy in the same
maintenance operation: the old relayer cannot bridge through user-only while
the new relayer cannot use a stopped system port.

## Verification

Run `bash rollout/test-split-role.sh` and ShellCheck before staging.
Remote proxy verify checks both capabilities, different PIDs and disallowed
method boundaries without generating proofs. Deployment checks preserved
genesis/config/binary/env checksums. Relayer requires a handshake in the new
systemd invocation, stable PID, and unchanged env/genesis/TOML.

These checks do not replace user proof and three-chain bridge E2E tests.
The 2026-09-15 Alchemy monthly quota errors are an independent blocker to
bridge E2E, not something fixed by role splitting.

The build enforces the runtime commit, genesis submodule commit and Cargo.lock;
out/TOOLCHAIN.txt records the Bookworm compiler. out-arch is the supplied,
checksum-verified Arch artifact. Binary directories are intentionally ignored.
