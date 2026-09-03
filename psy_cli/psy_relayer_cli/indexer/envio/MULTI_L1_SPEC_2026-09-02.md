# Envio one-indexer multi-L1

Date: 2026-09-02 (updated 2026-09-03 for three-chain pairing with `multi_chain`)
Status: approved for implementation
Repo: `PsyProtocol/psy-node` (`psy_cli/psy_relayer_cli/indexer/envio`)
Pairs with: `psy-services` `feat/multi-chain-l1-registry`
  (`doc/MULTI_CHAIN_L1_REGISTRY_SPEC_2026-09-02.md`)

## Goal

One Envio/HyperIndex process indexes every L1 attached to a single Psy L2.
psy-services talks to **one** GraphQL URL and isolates queries by protocol
`chain_index` plus EVM `chain_id`.

## Non-goals

- Changing Poseidon tree entity ids to include `chain_id`
- One Envio deployment per L1
- psy-services / relayer / wallet code (separate workstreams)
- Allocating `l1ChainIndex` values (L1 deploy config)

## Identity

| Field | Meaning | Example |
|-------|---------|---------|
| `chain_id` | EVM id from Envio `event.chainId` | local `31337`/`31338`/`31339`; Sepolia `11155111`, BSC `97`, Base Sepolia `84532` |
| `chain_index` | Protocol slot from `StateManager.l1ChainIndex` | ETH family `0`, BSC `1`, Base `2` |

`chain_index` must be unique across every network this indexer watches.
Never store EVM id `97` as `chain_index`. Target pairing with `psy-node`
`multi_chain` / locSetupV4 is three networks: ETH, BSC, Base.

Tree ids stay protocol-scoped so they match L2 `set_chain_root(chain_index, …)`
and psy-services `DepositTreeNode` lookups:

```
DepositTreeMeta.id = "{chain_index}"
DepositTreeNode.id = "{chain_index}:{level}:{node_index}"
Deposit.id         = "{chain_id}-{global_deposit_index}"
WithdrawalClaim.id = "{chain_id}-{nullifier}"
FinalizedBatch.id  = "{chain_id}-{checkpointId}"
```

## Configuration

`config.template.yaml` remains the local single-network template.

`config.multi-l1.template.yaml` matches `origin/multi_chain`'s rendered
indexer: three `networks` (ETH / BSC / Base), shared top-level contract
ABI/handlers, distinct addresses and RPCs. locSetupV4 substitutes
`${ETH_*}` / `${BSC_*}` / `${BASE_*}`.

## Collision guard

`DepositTreeMeta` records the owning `chain_id`. On `DepositRecorded`:

1. Load meta `id = "{chainIndex}"`.
2. If meta exists and `meta.chain_id` is set and differs from
   `event.chainId`, **throw** (do not append a leaf).
3. Otherwise append the helper-tree leaf and write meta with `chain_id`.

Legacy rows with unset `chain_id` are claimed by the first event after
upgrade.

This does not fix a protocol-level duplicate `l1ChainIndex` (L2
`chain_roots[256]` would still collide). It fails the indexer loudly
instead of silently merging Poseidon trees.

## Schema

- `Deposit.chain_local_deposit_index` already exists in `schema.graphql`;
  `schema.ts` must list it.
- `DepositTreeMeta.chain_id` is added (owning EVM id).

## psy-services pairing

All `l1_chains[].graphql_url` values may be the same Hasura endpoint.
Each entry still has its own `chain_index`, `chain_id`, `eth_rpc_url`,
and `state_manager`.
