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

`--sd-key-definition` also accepts the compiled JSON format containing
`function` and `config` fields.
