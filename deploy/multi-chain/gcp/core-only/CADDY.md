# Caddy maintenance routing

`caddy_ingress.py` fences and reopens public ingress on the Caddy host. The hosts and
the tag come from `ingress` in the release lock: `fenced_hosts`, `faucet_hosts` and
`maintenance_tag`. L1 RPC routes, Nostr and every host not listed are never touched.
The tool changes no upstream, header, log setting or TLS setting, and never restarts
Caddy or its container.

## Phases

```text
unfenced source + runtime
    -> fence        fenced_hosts and faucet_hosts return 503
    -> open         fenced_hosts return to the backend, faucet_hosts stay 503
    -> open-faucet  faucet_hosts return to the backend
```

A fence is one marked block at the top of a site block. The marker is
`# BEGIN <tag>` for `fenced_hosts` and `# BEGIN <tag>-faucet` for `faucet_hosts`.
The block holds a `route` that answers 503 with `Retry-After: 60` and a plain
text body. Removing the block restores the original bytes exactly.
Every phase is idempotent: a phase that finds its hosts already in the target
state reports `ALREADY_IN_STATE` and writes nothing.

## Commands

The tool runs as root on the Caddy host (`gcp-nostr`, source `/opt/nostr-relay/Caddyfile`),
loaded from stdin so the executed bytes are the ones hashed in `tool_sha256`.
Every command takes the lock as base64 plus its hash, so nothing is written to the host to read it:

```sh
python3 -I -B /dev/stdin --release-lock-base64 LOCK --release-lock-sha256 HASH stage --phase fence
python3 -I -B /dev/stdin --release-lock-base64 LOCK --release-lock-sha256 HASH stage --phase fence --output STAGE
python3 -I -B /dev/stdin --release-lock-base64 LOCK --release-lock-sha256 HASH check --stage STAGE --report-sha256 REPORT
python3 -I -B /dev/stdin --release-lock-base64 LOCK --release-lock-sha256 HASH check --stage STAGE --report-sha256 REPORT --apply
```

- `stage` without `--output` is read-only: it renders the candidate and checks its
  native adaptation. With `--output` it creates a new 0700 directory holding the
  original Caddyfile, the original bound file, the original runtime config, the
  candidate and its adapted config, and a report. Prints `report_sha256`.
- `check` re-renders from the stored originals, requires the same candidate, runs
  `caddy validate`, and compares source, bound file and runtime with the stage.
- `check --apply` repeats the checks under the host file lock, remounts only the
  bound Caddyfile read-write inside the container, writes both existing inodes,
  restores read-only, validates again and runs `caddy reload`.
- SIGTERM during apply (including the step's `timeout` limit) raises, so the same restore runs.
- A failure after the first write restores the exact source, bound file and runtime
  config and reports `restored`. Unknown or third-party changes are not overwritten;
  the result then says `manual_recovery_required`. Failures print JSON on stderr and exit 1.

## Refusals

Stage refuses, and writes nothing, when:

- the runtime config differs from the native adaptation of the source (an unknown
  route or setting changed);
- a listed host block is missing or appears twice;
- a maintenance marker sits outside the listed hosts, or a fence is partial or edited;
- the candidate changes any route outside the target hosts, or the target routes do
  not match the phase (503 present after `fence`, absent after `open` or `open-faucet`).

## Deploy steps

`deploy_ingress_steps.py` runs these phases as steps `fence_ingress` and `open_ingress`.
`open_faucet(ctx)` runs the `open-faucet` phase for the Faucet step. Step verification
requests every route from outside (coordinator and realm routes must return an integer
JSON-RPC result; other routes must answer below 500 without the maintenance body), then
runs the read-only `prepare_bridge_forwarders.py check-backends` on the gateway: 11 forwarder sockets active, none failed,
and every backend answering. The forwarders are retained, so
the gateway keeps its own installed topology file. The lock pins it as
`ingress.forwarder_topology_sha256`, and the edges and proxies it names must equal the release
topology and `lock.hosts`. Sockets must be active and services not failed: a socket-activated
forwarder is legitimately inactive after a reboot. `check-host` stays for a fresh install.

The Caddyfile and its bind-mounted copy are written in place, because the container's
single-file bind mount needs the inode unchanged. A failure restores both; a kill
between the two writes can leave a torn file and needs the stage's originals.

Each phase ends with a reload, and each reload drops the Nostr WebSockets; Services
reconnects. Expect three disconnects over a deploy (fence, open, open-faucet).

Rules for the operator: never run `deploy/gcp/remote/update-caddy-entrypoints.sh` (its full
template can discard parallel configuration and its stale-bind branch recreates the container);
exclude every parallel Caddy writer while a phase runs; never reuse a stage directory, and stage
again after any drift. Each step records the candidate hash in `ingress-<phase>.json` and the
next phase refuses a Caddyfile that no longer hashes to it, so an ordinary edit plus reload
between phases is refused and needs a review.

Kill window: SIGKILL or power loss between the first in-place write and the restore leaves the
source and bound files differing from the runtime, which still holds the old config. Recover
from the stage directory STAGE (originals are kept there, mode 0600):

```sh
cat STAGE/original.Caddyfile > /opt/nostr-relay/Caddyfile
# compare the bound copy with the source; if it differs, remount it read-write in the container,
# write it in place, and remount it read-only, as the tool's writable_bind does
cmp /opt/nostr-relay/Caddyfile /proc/CADDY_PID/root/etc/caddy/Caddyfile
nsenter --target CADDY_PID --mount --root --wdns=/ -- /bin/mount -o remount,bind,relatime,rw none /etc/caddy/Caddyfile
cat STAGE/original-bind.Caddyfile > /proc/CADDY_PID/root/etc/caddy/Caddyfile
nsenter --target CADDY_PID --mount --root --wdns=/ -- /bin/mount -o remount,bind,relatime,ro none /etc/caddy/Caddyfile
```

Then run `stage` without `--output`; it must report the phase as changeable again before any retry.

Caddy stays up across the cutover: the fence is in the source file, so it survives a
relay rebuild and a container restart; after a plain restart the runtime config is the same as the
adaptation of the source (the tool treats all three config-path spellings as equal).
