# Role rollout on the existing multichain testnet

Runtime: `3a81f59e0cf9333fc2ad4aefda7c83787660c9ab`.
Use the guarded scripts below, not the original `02-*` / `03-relayer.sh`
in-place rollout prototypes. Those prototypes are retained for reference.

1. `BOOKWORM_BUILD_GITHUB_SSH_KEY=$HOME/.ssh/id_ed25519 bash rollout/build-relayer-only.sh`
2. `bash rollout/stage-role-release.sh relayer`
3. `bash rollout/stage-role-release.sh proxy`
4. On arc99x3: `bash ~/prove-proxy-role-3a81f59e/remote-proxy.sh deploy`
5. After proxy is ready, on gcp-faucet:
   `sudo bash ~/prove-proxy-role-3a81f59e/remote-relayer.sh deploy`

Step 4 requests interactive sudo. Uploading does not stop any service.
Relayer deploy refuses to touch the old binary/config unless the private
gateway returns role=all, user_methods=true and system_methods=true.
Do not activate the relayer first: its startup handshake rejects the old proxy.

Both remote scripts support `verify` and `rollback`. They lock rollout state,
keep a paired root-only backup under `/opt/parth/role-rollouts`, stop only the
target unit before atomic replacement, and roll back on failed readiness.
Rollback after both upgrades must restore the relayer first, then the proxy.
Proxy readiness may take 20 minutes; do not repeatedly restart while it loads.
The state directory records the matching backup; no latest-glob selection is used.

Existing release symlinks, genesis, keystores, L1 addresses, private keys,
WireGuard, database and worker services are not replaced. Proxy changes its
binary, wrapper and only the PROVE_PROXY_ROLE env setting. Relayer changes
only its binary and the current localhost network's system_prove_proxy_url
to `http://10.148.0.32:19999`. It does not reload or rewrite systemd units.
The old general BUILD-MANIFEST remains a baseline manifest, not a claim that
these two replaced binaries are still at its original commit. Rollout records
and the staged checksums identify this overlay release.

After deployment check the role from the proxy, gateway and public endpoint;
check the new relayer invocation contains `system prove proxy verified`, then
run real user proofs and bridge flows for all three chains. A successful
handshake alone is not a bridge E2E pass. On 2026-09-15 the old relayer was
reporting Alchemy monthly-capacity errors; role upgrades do not fix RPC quotas.

Arch binary provenance: supplied out-arch artifact, checksum verified, --role
advertised. Relayer is built from a clean pinned checkout in Bookworm, with
Cargo.lock enforced and compiler version saved in out/TOOLCHAIN.txt.
