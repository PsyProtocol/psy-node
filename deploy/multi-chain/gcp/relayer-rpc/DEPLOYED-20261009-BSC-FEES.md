# Relayer BSC fee hotfix: live artifact and branch integration

This supersedes the live Relayer identity in `DEPLOYED-20261008.md`, not the
other components or full-cohort source manifest. This branch synchronization
does not deploy, rebuild the chain, or authorize a restart.

## Live artifact

- Exact source: `d1f0e4fc3b69d9bed90c1e829d4928cc68125bc8` on the published
  `fix/relayer-bsc-fee-live-20261008` branch, based on `db37dce5`.
- Host/unit: `gcp-faucet`, `parth-relayer.service`.
- Activated: 2026-10-09 09:09 UTC+8.
- Release: `/opt/parth-relayer-fee-releases/20261009-bsc-fees`.
- Binary SHA256:
  `1152584f5b1db2399c3713865776f25e4433a5c5c046151184db2a739320bd7e`.
- Drop-in: `/etc/systemd/system/parth-relayer.service.d/96-bsc-fees-20261009.conf`.
- Backup: `/var/lib/parth-relayer-fee-backups/20261009-bsc-fees`.
- Config: `/etc/parth/bridge-relayer.toml`, SHA256:
  `8b30a04c1314d3e96fbe60820de7f2a86878c6c2081893da5971ddbb6ec50819`.

The old 95 RPC-pool override and `/opt/parth/current` were preserved. The
integrated stable/deployment branches include other component changes and must
not be described as the exact source of this deployed binary. No Genesis,
circuit, ABI, dependency pin, or other component was changed by this hotfix.

## Required private configuration

The existing BSC `[[chains]]` entry alone has this policy:

```toml
[chains.fee_policy]
expected_chain_id = 97
min_priority_fee_wei = 1000000000
max_priority_fee_wei = 1000000000
max_fee_per_gas_wei = 1000000000
```

These are the approved recovery limits, not a permanent market fee assumption.
Quotes exceeding the caps defer sending rather than being clamped. Do not
increase the budget without approval or apply this policy to Sepolia/Base.
Preserve the named RPC pool order and private URLs from the previous record.

**Deployment configuration support:** `multichain_relayer_chains_json` now adds
the policy above for canonical BSC Testnet chain ID 97 only. Existing RPC-only
`RELAYER_CHAINS_JSON` overrides inherit it. An explicit `fee_policy` on that BSC
entry is validated and preserved, allowing approved budget changes without
changing shared Services/Envio/public RPC configuration. Explicit null or invalid
policies fail; they never disable protection silently. Other chains cannot carry
this policy. Runtime manifest and network identity checks remain enforced.

`write-relayer-config.sh` validates the entire chain list before touching the
output and writes `fee_policy` as a TOML inline table under its owning chain.
Direct multichain writer calls with BSC but no policy are rejected; use the
generator to upgrade older RPC-only inputs. Fees must be positive plain decimal
JSON integers no larger than 9007199254740991 (jq exact-integer limit), with
minimum <= priority cap <= total cap. Missing/unknown fields are rejected.
Single-chain config generation remains unchanged and is not covered by this
multichain deployment support.

The generator is declarative: it does not read the current remote TOML to infer
custom budgets. Before a later rollout, compare its parsed output against the
live config and explicitly include any approved non-default BSC budget in
`RELAYER_CHAINS_JSON`. These script changes do not themselves alter the live
configuration, deploy a binary, or authorize higher spending. Keep the existing
verified config for binary-only updates. Code alone does not enable the policy.

The historical full-cohort `source-versions.env` is not a valid source
selection for rebuilding this component hotfix; pin the reviewed Relayer source
explicitly (d1f0e4fc or a reviewed descendant/backport with fee support).
No global runtime pin is advanced by this integration.

Offline checks (synthetic credentials, temporary files, no live RPC):

```bash
python3 deploy/gcp/tests/test_relayer_rpc_config.py
bash deploy/gcp/tests/test-multichain-relayer-rpc-order.sh
```

## Recovery and acceptance evidence

Original BSC nonce 46012 had both type-2 fee fields at 1 wei and no receipt.
Deposit receipt waiting blocked the multichain round at checkpoint 198845.
After stopping the signer and verifying the original request, an authorized
same-nonce/same-business replacement succeeded at 1 gwei:

`0xb25e82cb1037f6abda3c80b771f76b2483e58f255ddbdc402a671f88bcd8772a`

BSC block 135690696, fee 0.003239834 tBNB, provedDepositCount 166 -> 167.
The new Relayer then finalized successive batches on all three chains; BSC
nonces 46013-46015 also succeeded at 1 gwei. At 11:02 UTC+8 all three chains
reported checkpoint 205992 versus L2 206002. Independent IMT/withdrawal errors
remain separate investigations; this is not a blanket business-health verdict.

## Limits and rollback

Read `psy_cli/psy_relayer_cli/BSC-FEE-POLICY.md`. Deposit receipt waiting still
has no total deadline, and existing atomic state replacement does not fsync.
Do not claim general pending-transaction recovery is solved. Reconcile any
in-flight transaction before a restart or rollback; never restore historical
daemon state or repeat the nonce-46012 recovery. The previous binary lacks the
fee protection and is not a safe unattended rollback target.

Detailed evidence and agent handoff are in the sibling psy-memory repository:
`issues/relayer-bsc-one-wei-pending-20261008/`.
