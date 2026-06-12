# psy-privacy-bridge Refactor RFC (Phase 2 Proposal)

## Scope
This RFC documents architecture debt only. No implementation changes are included in this phase. Goal: reduce conditional branching growth in network selection, bridge tracking, and tx status rendering while keeping `psy_bridge` and `psy-privacy-bridge` decoupled.

## A. Multi-Source Network Truth Drift

### Current problem
Network/runtime resolution is fragmented across multiple sources:
- `psy-contracts/protocol-config/index.ts` (`activeNetworks`, chain metadata)
- `psy-genesis/config.json` (`networks.*` runtime RPC/service URLs)
- `psy-contracts/deployments/*/deployed-contracts.json` (addresses)
- Browser storage (`services/transactions.ts`, `@bridge/lib/shieldDeposits`) for local activity state

Practical impact: every new environment or fallback requires edits in `services/chainConfig.ts`, `bridge/lib/chains.ts`, bridge page rendering, and tracker logic. Divergence causes silent misrouting (wrong RPC domain, wrong addresses, stale activity visibility).

### Proposed direction
Freeze one runtime object at app bootstrap and make downstream modules read-only consumers:

```ts
type RuntimeNetwork = {
  protocolNetwork: 'localhost' | 'sepolia' | 'ethereum'
  runtimeName: 'localhost' | 'sepolia' | 'mainnet'
  l1Label: string
  config: NetworkConfig
  deploymentNetwork: 'localhost' | 'sepolia' | 'ethereum'
  l1RpcUrls: string[]
  servicesUrl: string
  indexerUrl: string
}

export function getRuntimeNetwork(): RuntimeNetwork
```

Rules:
- Resolution and fallback happen once.
- UI/state/tracking modules do not branch on raw env names.
- `testnet` remains alias input only; internal model uses `sepolia`.

### Risk
Medium. Touches `chainConfig.ts`, `chains.ts`, and all direct callers of URL helpers.

### Effort
~1.5–2.0 engineer-days.

---

## B. Single-direction reuse, independent orchestration (No shared package)

### Constraint (user decision)
Do **not** merge `psy_bridge` and `psy-privacy-bridge` into a shared `bridge-core` package.

### Current problem
`psy-privacy-bridge` correctly imports pure helpers from `@bridge/lib/*`, but also reimplements orchestration in `services/depositTracking.ts`, overlapping with behavior in `psy_bridge/src/store.ts` (`fetchClaimL2Deposits`, `refreshSelectedDepositProofReady`). This creates logic drift and duplicated bugfix work.

### Proposed direction
Keep architecture strictly one-way:
1. `psy_bridge` remains an independent reference app.
2. `psy-privacy-bridge` may import only **pure functions** from `@bridge/lib/*`:
   - `fetchDepositsByTxHash`
   - `fetchDepositClaimProof`
   - `isDepositClaimed`
   - `claimL2Deposit`
   - shield note helpers
3. `psy-privacy-bridge` keeps its own scheduler/orchestration (`depositTracking.ts`, workers, UI state); it must not import `@bridge/store` or reuse `psy_bridge` store orchestration.
4. Add lint guard (or CI grep rule) to block `@bridge/store` imports from `psy-privacy-bridge`.

### Risk
Low to medium. Mostly boundary enforcement and small call-site changes.

### Effort
~1.0 engineer-day.

---

## C. Implicit transaction state machine

### Current problem
Transaction progression is encoded via Cartesian combinations of:
- `type`
- `status`
- `metadata.pendingStage`
- `metadata.depositIndex`
- `metadata.proof`
- chain-derived facts

Observed in `components/StateTimeline.tsx`, `services/depositTracking.ts`, `pages/TransactionDetailPage.tsx`, and activity rendering. Adding one stage requires edits in multiple `if/else` blocks and regressions are easy.

### Proposed direction
Introduce explicit FSM module:

```ts
type DepositState =
  | 'awaiting_index'
  | 'relaying'
  | 'proof_pending'
  | 'ready'
  | 'claiming'
  | 'claimed'

interface TxStateMachine {
  current(tx: Transaction, facts: RuntimeFacts): DepositState | WithdrawState | TransferState
  allowedActions(state: string): Array<'claim' | 'retry' | 'none'>
  transition(tx: Transaction, event: TxEvent): Transaction
}
```

UI asks only `currentState` + `allowedActions`; status labels become table-driven, not branch-driven.

### Risk
Medium-high. Impacts timeline, activity rows, detail page actions, and worker updates.

### Effort
~2.0–3.0 engineer-days.

---

## Rollout proposal
1. Land boundary guard for B first (no orchestration imports from `@bridge/store`).
2. Introduce frozen runtime object for A behind feature flag; migrate read sites incrementally.
3. Add FSM for deposit path first (highest churn), then withdraw/transfer.

## Expected outcome
- New network/token/stage additions become table updates instead of multi-file branch edits.
- `psy_bridge` and `psy-privacy-bridge` remain independent applications.
- Bridge/deposit UI stops regressing from hidden state coupling.
