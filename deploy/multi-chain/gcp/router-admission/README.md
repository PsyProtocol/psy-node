# Router Deposit Mapping Admission Upgrade

This procedure updates only the L1 Router implementation, keeping its proxy address,
storage, mappings, ownership, Bridge, Gateways, Genesis and L2 binaries unchanged.
It does not resolve historical deposit index 1535 or provide cancellation/refunds.

## Policy and Preconditions

- Reject a deposit before forwarding to a Gateway when its token/ID mapping is not
  bidirectional. Also reject the all-zero native token/ID tuple: two default mapping
  values are not proof of configuration.
- Preserve valid ERC20 ID0 (PSY), ID4 (pUSDT), and correctly configured nonzero native
  IDs. This is a mapping guard, **not a hardcoded two-token allowlist or permanent
  ban on native assets**. The existing three-chain native deposit pause stays on.
  Do not remove it or configure a new native mapping as part of this operation.
- Live baseline contracts: `aee3b39ed08f4f4838b63207df3ee5fbb55c53bc`.
  Candidate: `394153fa7b4eb1b5f041131d15036a38321620f0`, repository
  `PsyProtocol/psy-contracts`, branch `fix/router-deposit-mapping-20261030`.
- The baseline Router runtime must match every live implementation byte-for-byte.
  The package builder verifies compiler metadata/source and unchanged storage layout.
- On all three chains ProxyAdmin is owned by ExecutorWithTimelock, controlled by
  the existing administrator. Delay is **172800 seconds (48 hours)**, grace period
  **604800 seconds (7 days)**. Never bypass it via ownership or address-provider edits.
- The live ProxyAdmin is the hardhat-deploy variant whose empty-data path uses
  **`upgrade(address,address)`**. Do not substitute `upgradeAndCall(..., "0x")`:
  the real-state fork showed that path reverts during action execution.

## Build and Test

Use a clean contracts checkout at the exact candidate and frozen dependencies:

```bash
pnpm install --frozen-lockfile
pnpm exec hardhat test
```

The release ran 83 Hardhat tests. Four negative regressions failed against the old
Router because it accepted the bad deposits; all six Router tests pass after the
fix. The isolated real-state Sepolia fork additionally verified Timelock ownership,
early-execution rejection, state-preserving upgrade, bad deposit rejection, and
successful PSY/pUSDT deposits. Fork funding used local impersonation of token owners;
it did not assume the live administrator can mint PSY, and sent no real transactions.

Collect read-only chain audits with the supplied `audit.cjs`, running it on the
administrator VM using its existing protected loopback RPCs. For example, from the
script directory (repeat with bscTestnet/baseSepolia and their respective filenames):

```bash
ssh -J gcp-gateway -o Hostname=10.148.0.33 -o HostKeyAlias=136.110.35.53 \
  -o BatchMode=yes gcp-faucet \
  'sudo -n /opt/psy-l1-bundles/node-v22.23.4 - sepolia' \
  < audit.cjs > sepolia-governance.json
```

Retain `Router-before.json` from the exact baseline build.
Files consumed by `package.cjs` are `sepolia-governance.json`,
`bsc-governance.json`, `base-governance.json`, containing public identity/mapping
snapshots and implementation bytecode. Never add private RPC URLs or keys to them.

```bash
node deploy/multi-chain/gcp/router-admission/package.cjs \
  /absolute/path/to/psy-contracts /absolute/path/to/audit /absolute/path/to/new-bundle
```

Install the generated four package files as root-owned, non-writable-by-others files
under `/opt/psy-router-admission-20261030-r2` on `gcp-faucet` (`10.148.0.33`). Verify
their SHA256SUMS after transfer. Create root-only evidence directory
`/var/lib/psy-router-admission-20261030-r2` with mode0700. Do not overwrite a prior package
or its evidence. The custody adapter reuses the existing encrypted keystore, trusted
secret reader and administrator lock; it writes no plaintext keys or passwords.

## Queue Now, Activate After the Timelock

Run the controller from a private writable copy of this directory. It writes only
operational signing holds and completion records beside itself. Node deployment
script updates do not automatically broadcast transactions.

```bash
python3 -B control.py audit
python3 -B control.py queue
```

`queue` audits all chains before stopping the actual `psy-core-relayer-r3.service`
on `10.148.0.31`. While that signer is quiesced, it deploys one implementation per
chain and queues one exact ProxyAdmin upgrade per Timelock. Before every broadcast
it saves the signed transaction hash, nonce and public unsigned fields, then verifies
canonical receipts with at least10 block confirmations per transaction. These are
testnet confirmation counts, not a claim of L1 `finalized`. Immediately before signer
release it revalidates every retained receipt and checks no nonce is pending.
This is not an eight-hour/48-hour shutdown:
Relayer is restored after the queue transaction receipts, not after the Timelock.

Each chain has its own exact execution timestamp in its retained proposal and queue
result. The implementation is **not active** merely because the queue succeeded.
After all three timestamps have elapsed, and before the seven-day grace expires:

```bash
python3 -B control.py audit
python3 -B control.py activate
```

Early activation is rejected before stopping Relayer. Activation rechecks the frozen
proxy/admin/Timelock/mapping/pause state, implementation bytecode and exact calldata;
it cannot turn this job into a general-purpose contract upgrade. It does not change
the Timelock delay. No automatic future execution is installed by this procedure.

Gas price ceiling is1gwei; fixed deployment gas is8,000,000 on Sepolia and2,000,000
on BSC/Base; queueing stays400,000 and activation500,000. Before stopping Relayer,
the audit requires an online creation `eth_call` at the exact chain budget to return
the reviewed runtime bytes. Nonce, balance, fees, code identity and governance state
remain checked online. A refusal stops before signing; do not blindly raise caps.

The first job used2,000,000 on all chains based on an isolated-EVM deployment cost
of787,738. Its Sepolia deployment mined status0 and consumed the full limit, while
the real RPC had estimated5,436,007. The old Router was unchanged and no proposal was
queued. The failed hash is075462754871665289fdd60ccf16c0a84be5b5aac1ef1a8e236e9c82eca7970b.
Recovery verified>=10 confirmations, the consumed nonce and idle signer, then restored
Relayer. Subsequent real-chain creation calls returned the exact reviewed runtime at
8m on Sepolia and2m on BSC/Base. This r2 job uses new package/evidence directories;
it never deletes, retries, or reuses the failed first job's intent/nonce. The exact
EVM gas-schedule cause was not established; a debug trace was unavailable.

## Recovery and Acceptance

On an unknown receipt or command failure, keep the signing hold and evidence.
Do not rerun `queue`/`activate` as a retry or start another signer. First reconcile:

```bash
python3 -B control.py recover
```

Recovery does not rebroadcast unknown transactions. It checks retained hashes and
canonical outcomes, including confirmed status-0 failures: those are reported as
known failures, never retried, and do not permanently strand the shared signer.
Pending, reorged or insufficiently confirmed receipts still keep the hold. Recovery
then resumes Relayer only when signer reuse is safe. A partially
queued rollout is not a completed three-chain queue; explicitly report each chain.

After activation, verify each proxy's implementation slot and runtime hash, unchanged
owner/provider/mappings, native pause still enabled, and known PSY/pUSDT behavior.
Use negative `eth_call` to confirm native ID0 and unknown tokens fail with
`InvalidTokenMapping`, without broadcasting invalid deposits. Check Relayer restarted
and continues its prior work. Historical1535 remains a separate unresolved incident.
No rollback is automatic: reverting Router requires a separately reviewed Timelock
action and would reintroduce the admission defect. Do not alter Bridge counts/roots.

Operational tests:

```bash
NODE_PATH=/absolute/path/to/psy-contracts/node_modules node upgrade.test.cjs
python3 -B -m unittest discover -s . -p 'test_*.py'
```

The focused tests cover calldata/hash binding and controller early-activation/unknown
receipt safety. They do not replace live identity checks or complete broadcast/crash
fault injection. Published execution records belong in psy-memory and the existing
deploy/testnet release record, not in frontend application source.
