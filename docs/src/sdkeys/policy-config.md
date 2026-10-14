# Configuring a composed SD key policy

Save a JSON file such as `sd-key-policy.json`:

```json
{
  "per_transaction": {
    "All": [
      { "Contract": 7 },
      { "Any": [{ "Method": 10 }, { "Method": 20 }] },
      { "Input": { "word": 0, "comparison": "Lte", "value": 100 } }
    ]
  },
  "ordered": [{ "Method": 10 }, { "Method": 20 }],
  "totals": [{ "word": 0, "max_per_tx": 100, "max_total": 250 }],
  "min_tx_count": 2,
  "max_tx_count": 3
}
```

`per_transaction` applies to every transaction. `ordered` constrains the
first transactions in order; it cannot contain more entries than
`min_tx_count`. `All` and `Any` can contain nested rules. Available leaf rules
are `Contract`, `Method`, `Caller`, and `Input`. `Input.comparison` accepts
`Eq`, `Lt`, `Lte`, `Gt`, or `Gte`.

`totals` sums the selected calldata word across the actual transactions. It
does not read an ABI or know that a word is an amount. Confirm that every
allowed method uses the same word and units before treating it as a spending
limit. Each total also requires that word to exist in every transaction.

Inspect the fingerprint before using the policy:

```bash
psy_user_cli wallet sd-key-policy-fingerprint --definition sd-key-policy.json
```

Pass the same file to wallet and transaction commands with
`--sign-type sd-key-dpn --sd-key-definition sd-key-policy.json`. If
`--fingerprint` is omitted, the wallet derives it from this file. If it is
supplied, the wallet checks that it matches. Use the same file for proving and
submission so the registered circuit matches the wallet key.

Before proving, the prover re-evaluates the policy against the actual
transactions and reports the violating transaction index, rule, or exceeded
total instead of failing later with an unsatisfied circuit constraint.

## Templates, checks, and reading a policy

Generate a starter policy file instead of writing JSON by hand:

```bash
psy_user_cli wallet sd-key-policy-template --kind spending-limit \
  --contract 7 --methods 10,20 --word 0 --max-per-tx 100 --max-total 300 \
  --min-tx-count 1 --max-tx-count 3 --output sd-key-policy.json
```

`--kind` accepts `allow-method` (fixed call allowlist), `spending-limit`
(adds a per-call bound and a session total on one calldata word), and
`sequence` (the methods must appear in the given order). Omitted count
flags default to the smallest range the template supports; every generated
file round-trips through the policy loader, so a template can never be
emitted in a state the wallet would reject.

Simulate transactions against a policy before registering the key:

```bash
psy_user_cli wallet sd-key-policy-check --definition sd-key-policy.json \
  --call 7:10:60 --call 7:20:80,7
```

Each `--call` is `contract:method` optionally followed by
`:word0,word1,...` calldata. The check runs the same native evaluation
the prover performs before proving, plus the transaction count range.
Method may be a numeric id or an on-chain function name; names require
`--rpc-config` and are resolved from the contract's code definition,
while numeric ids keep the check fully offline. The simulated caller is
the default caller contract (0), matching user-initiated transactions.
`--methods` on the template command accepts names the same way.

Inspect what a key authorizes, in words:

```bash
psy_user_cli wallet sd-key-policy-describe --definition sd-key-policy.json
```

It prints the transaction count range, the rule every transaction must
satisfy, ordered slot constraints, session totals, and the fingerprint.
With `--rpc-config --contract 7` it also annotates method ids with the
on-chain function names from that contract.

## Writing restrictions with method names

Policy files may write `Method` rules as on-chain function names instead
of numeric ids. A name is resolved against the contract named by a
`Contract` rule in the same `All` group; names outside such a group, like
ordered-slot rules, use the `--contract` flag:

```json
{
  "per_transaction": {
    "All": [
      { "Contract": 7 },
      { "Any": [{ "Method": "buy" }, { "Method": "sell" }] }
    ]
  },
  "ordered": [{ "Method": "buy" }],
  "totals": [],
  "min_tx_count": 1,
  "max_tx_count": 2
}
```

Resolve the names once, against the chain, and register the numeric
result:

```bash
psy_user_cli wallet sd-key-policy-resolve --definition names.json \
  --rpc-config rpc.json --output sd-key-policy.json
```

Resolving is deliberately a separate, one-time step: the numeric policy
is self-contained and offline, and its fingerprint cannot drift when a
contract is later updated on-chain. Register, prove, check, and
fingerprint the resolved file, not the name-bearing one.

`--sd-key-definition` also accepts the compiled JSON format containing
`function` and `config` fields.
