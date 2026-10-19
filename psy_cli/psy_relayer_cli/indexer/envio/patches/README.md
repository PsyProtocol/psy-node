# Envio patches

## fresh-reorg-parent.py

Envio 2.32.10's RPC source (`node_modules/envio/src/sources/RpcSource.res`)
builds the reorg guard of every fetch range from the parent block
`fromBlock - 1`, read through a block cache keyed by block number. The cache is
replaced only after a reorg has been detected (`getBlockHashes`), so the parent
of a new range is the cached block of the old fork and a reorg of an already
fetched block goes unnoticed while Envio runs. A restart empties the cache and
then detects it. `tests/reorg/run-reorg-test.cjs` scenario 2a reproduces this.

The patch adds one branch: with `PSY_ENVIO_FRESH_REORG_PARENT=1` the parent
block is read from the RPC (`getKnownBlockWithBackoff`, the cache's own loader)
instead of the cache. Without the variable the upstream expression runs
unchanged. Nothing else changes: the guard comparison, rollback and the cache
for event blocks are upstream code.

| Property | Behaviour |
|---|---|
| Version | Refuses any Envio other than 2.32.10 |
| Anchors | Edits `RpcSource.res` and `RpcSource.res.js`; each anchor must occur exactly once |
| Idempotent | A second run leaves both files unchanged |
| Rebuild-safe | `--check` accepts both the edited JS and the JS the ReScript compiler emits from the patched source |
| pnpm store | Files are replaced by rename, so hard-linked copies in the store and in other projects keep upstream bytes |
| Other patches | Applies in any order with the ordered-failover patch (`SourceManager.res`) and the RPC polling patch (`RpcSource.res`, different anchors); the result is byte-identical in every order |

### Applying

`pnpm install` runs it as this package's `postinstall` script. By hand:

```bash
python3 patches/fresh-reorg-parent.py <envio-home>          # apply
python3 patches/fresh-reorg-parent.py <envio-home> --check  # verify only
```

`<envio-home>` is this directory (or a release copy of it). Both
`node_modules/envio` and `generated/node_modules/envio` are patched when they
resolve to different packages.

### Deployment

1. Build as before: `pnpm install` (applies the patch), `envio codegen`
   (its own `pnpm install` runs the hook again; it then recompiles the patched
   source), then `--check`. `pnpm install --ignore-scripts` skips the patch;
   `python3` must be on the build host.
2. Add `--check` next to the existing Envio patch checks, for example in the
   systemd unit's `ExecStartPre`, so a rebuilt or reinstalled release without
   the patch refuses to start.
3. Set `PSY_ENVIO_FRESH_REORG_PARENT=1` in Envio's environment file.
4. Keep `confirmed_block_threshold` above the number of blocks a chain
   produces in one polling interval plus the reorg depth to tolerate. Envio
   compares the parent only while it is within the threshold of the head that
   the fetch saw; an older parent is skipped, patched or not, and a restart
   does not detect it either (test scenario 3c).

### Cost

At most one extra `eth_getBlockByNumber` (without transactions) per fetch
round per partition. The upstream read was normally a cache hit. At the head
with 12 s polling that is at most 5 calls per minute, 7,200 per day, per chain
and partition. During historical sync it is one call per block range. The read
retries with the loader's uncapped doubling backoff, so an RPC that answers
`null` for that block (a node behind its pool) stalls the fetch until it does.

### Test

```bash
ENVIO_PG_HOST=127.0.0.1 ENVIO_PG_PORT=<throwaway pg> ENVIO_PG_USER=postgres ENVIO_PG_PASSWORD=... \
  REORG_TEST_NODE_BIN_DIR=<node 22 bin dir> node tests/reorg/run-reorg-test.cjs
```
