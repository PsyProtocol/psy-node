# Wallet R2 candidate plan

This plan stages wallet `3bb5d09c794176a019b05a8c066527a5bd4283d3`,
built from the pinned local SDK archive associated by the established build
report with source commit `310cd961bb479619069f12ca71c32e133066e2ad`,
without uploading that SDK archive and without pushing the wallet branch or
triggering its workflow. The archive itself contains compiler provenance but
does not contain an authenticated SDK source-commit field; its authoritative
identity for this operation is its SHA-256.

## Collision and compatibility findings

The public `wallet-release.json` already advertises version `0.4.28` from
wallet commit `27ca518dc2d970e411bd43b399f78b8c86dcbb73`, with ZIP SHA-256
`ba641a460ec9e2ae410971acd87e28f99ab182b0eb53eab5c31c371d6b0854d1`.
The new `0.4.28` ZIP has SHA-256
`3e754e5f8844f436cc06b2fafde4b146515ed66165554feed35ae416619cbb3d`.
The commit-qualified candidate object was absent (HTTP 404) when checked on
2026-09-18, so the shared latest pointer must not be overwritten first.

The SDK WASM reports stage `testnet` and magic `0x1337cf514544cf69`, matching
the wallet Genesis testnet profile. The wallet mainnet profile uses the
different magic `0x1337cf514544c069`. This artifact must not be treated as a
mainnet SDK build.

The current wallet workflow cannot reproduce this candidate unchanged: it is
still pinned to SDK `4146f805...`, compiler `e3aed304...`, and the corresponding
old archive URL and hash. A future reviewed workflow-only change needs these
values:

- SDK commit: `310cd961bb479619069f12ca71c32e133066e2ad`
- compiler commit: `bb79f3ff335d36560b8b6eae880c8404d662d27c`
- SDK archive SHA-256:
  `3b19b24d9c2608670e55e03d741f9aa3df85a0a6df4716afd2136681f36d3643`

No workflow edit or push is part of this candidate publication.

## Commands

Local validation and candidate metadata generation only:

```bash
deploy/multi-chain/gcp/prepare-wallet-r2-release.sh --prepare
```

After review, upload only the immutable ZIP and its candidate metadata:

```bash
export CLOUDFLARE_ACCOUNT_ID='...'
export CLOUDFLARE_API_TOKEN='...'
deploy/multi-chain/gcp/prepare-wallet-r2-release.sh --upload-candidate
```

Credentials remain in the environment for Wrangler; do not put them in command
arguments, files, shell history, or reports. The candidate namespace includes
the full wallet commit, the SDK source identifier recorded by the build report,
stage, and ZIP hash. Its metadata key is not `wallet-release.json`.

The helper clears `CF_ENV_FILE` and explicitly forces `R2_SKIP_UPLOAD=0` and
`R2_SKIP_VERIFY=0` in both upload modes. After the existing publisher returns,
the helper independently downloads and compares `walletCommit`, `sha256`,
`zipUrl`, `sizeBytes`, and `network`, then downloads and hashes the public ZIP.

After the SDK-compatible backend has been deployed and the immutable candidate
has passed acceptance, switch the shared latest metadata separately:

```bash
export CONFIRM_BACKEND_DEPLOYED=1
deploy/multi-chain/gcp/prepare-wallet-r2-release.sh --promote-latest
```

Promotion first reads and validates the public candidate metadata. The existing
publisher then idempotently writes the same immutable ZIP before replacing
`wallet-release.json`, and verifies the public ZIP hash. There is no separate
R2 index object in the current wallet publisher; `wallet-release.json` is the
latest-release index consumed by clients.
