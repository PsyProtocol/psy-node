# Realm P2P validators

Realm P2P is the standard Realm launcher path. Validator membership and public routing identity come from `PSY_CONFIG_PATH`, which defaults to `psy-genesis/config.json`. Selection is bound to the node's `config.network`: `LocalDevnet` selects `localhost`, `PsyPublicTestnet` selects `sepolia`, and `PsyMainnet` selects `ethereum`; other mappings fail closed. If `PSY_NETWORK` is present, it must equal that canonical key. The Coordinator admission endpoint remains HTTP and verifies validator certificates; there is no Coordinator libp2p submission path.

## Network config

Each network contains:

```json
{
  "p2p": { "checkpoints_per_epoch": 10 },
  "realm_configs": [{
    "id": 0,
    "validators": [{
      "validator_user_id": 0,
      "processor_node_id": "<38-byte NodeId hex>",
      "bls_public_key": "<48-byte BLS public key hex>",
      "processor_addresses": ["/ip4/127.0.0.1/tcp/41001/p2p/<peer>"],
      "edge_nodes": [{
        "node_id": "<38-byte NodeId hex>",
        "addresses": ["/ip4/127.0.0.1/tcp/41101/p2p/<peer>"]
      }]
    }, {
      "validator_user_id": 262144,
      "processor_node_id": "<38-byte NodeId hex>",
      "bls_public_key": "<48-byte BLS public key hex>",
      "processor_addresses": ["/ip4/127.0.0.1/tcp/41002/p2p/<peer>"],
      "edge_nodes": [{
        "node_id": "<38-byte NodeId hex>",
        "addresses": ["/ip4/127.0.0.1/tcp/41102/p2p/<peer>"]
      }]
    }]
  }]
}
```

Local-devnet example above uses reserved Strategy5 user ids for Realm 0 subs `1`/`2` (`0` and `262144`); Realm 1 uses `1048576` and `1572864`.

The validator sub-id is not stored. It is the validator's one-based array position. This preserves existing port and database namespaces (`realm_{id}_{sub}`). `validator_user_id` must lie in the owning Realm's half-open user range. Local-devnet genesis pre-places dedicated ZK validator accounts at registrations `0`, `1`, `3`, `4` for realms `0..1` (Strategy5 GROUP=1), keeps registration `2` as the bridge relayer (`user_id` `524288`), and has the launcher bind `(realm_id, sub_id)` to those reserved validator accounts rather than picking ordinary faucet users. Realm 0 sub 1 is intentionally registration `0` / `user_id` `0`.

## Fail-closed startup

A processor derives its public NodeId from its local Ed25519 identity key and requires exactly one match in both the selected Realm array and Genesis. Its own sub-id is the selected validator's one-based array position; no sub-id is supplied at startup. An edge similarly derives its owning validator sub-id by requiring exactly one exact local NodeId match in the selected validator's `edge_nodes` arrays. A processor's local BLS secret must derive the configured public key. Duplicate NodeIds, BLS keys, or validator user IDs, invalid identities, more than 64 validators, and out-of-range user IDs reject startup or Genesis construction.

The first `edge_nodes` element is the scheduled validator's primary EndCap endpoint. Secondary edges share the validator position but forward EndCaps to that primary edge; only configured edge NodeIds may send forwarded EndCaps.

Only local secret and listen parameters are supplied at startup. Peer addresses, validator rotation, proposer identities, and certificate keys are read from the network selected by `config.network` in `PSY_CONFIG_PATH`. Before constructing the network, each node removes every bootnode address whose `/p2p` PeerId is its own while preserving all remote processor and edge addresses. `init-realm-p2p-keys` writes local secret files and updates a complete runtime network config at `local_checkpoints/realm_p2p/config.json`; it does not create a second validator input.

Realm rollback loads the same processor config and resolves the one-based sub-id through the same local Ed25519 identity and public-network lookup before checking `--realm-sub-id`, validating a plan, or selecting database and backup paths. A missing `PSY_CONFIG_PATH` target, missing identity key, network mismatch, or non-unique NodeId match aborts rollback rather than falling back to sub-id zero.

## Launcher behavior

The standard launcher always creates or loads two ordered validators per Realm, writes the runtime network config, injects the same ordered public identities into `genesis.json`, exports `PSY_CONFIG_PATH` to child nodes, and starts processor and edge P2P listeners. Array positions 1 and 2 retain the established ports and DB namespaces.
