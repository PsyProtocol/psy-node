//! Key backup format tests. Account names are required by the current format;
//! backups written before that schema change are intentionally rejected.

#[allow(dead_code, unused_imports)]
#[path = "../src/agent_account.rs"]
mod agent_account;
#[allow(dead_code, unused_imports)]
#[path = "../src/keystore.rs"]
mod keystore;

use keystore::KeyBackup;

#[test]
fn a_pre_existing_backup_without_a_name_is_rejected() {
    // Exactly the shape written before this change.
    let json = r#"{
        "kind": "psy-wallet-key-v1",
        "private_key": "0xabc123",
        "fingerprint": "deadbeef",
        "created_at": 1786029233
    }"#;
    let error = serde_json::from_str::<KeyBackup>(json).err().expect("a backup without an account name must be rejected");
    assert!(error.to_string().contains("name"));
}

#[test]
fn a_null_mandate_is_treated_as_absent() {
    let json = r#"{
        "kind": "psy-wallet-key-v1", "private_key": "0x1", "fingerprint": "f",
        "name": "Wallet", "created_at": 1, "mandate": null
    }"#;
    let b: KeyBackup = serde_json::from_str(json).expect("null must not be a parse error");
    assert!(b.mandate.is_none());
}

#[test]
fn a_mandate_round_trips_with_everything_a_reload_needs() {
    // The reload rebuilds the circuit from these fields; the fingerprint alone
    // is not enough to re-register it.
    let json = r#"{
        "kind": "psy-wallet-key-v1", "private_key": "0x1", "fingerprint": "f",
        "name": "Agent account", "created_at": 1,
        "mandate": {
            "capabilities": [{"contract_id": 0, "method_name": "simple_transfer", "method_id": 3}],
            "calls_per_transaction": 1,
            "circuit_fingerprint": "abc"
        }
    }"#;
    let b: KeyBackup = serde_json::from_str(json).expect("agent-account backups must load");
    let m = b.mandate.clone().expect("mandate present");
    assert_eq!(m.calls_per_transaction, 1);
    assert_eq!(m.circuit_fingerprint, "abc");
    assert_eq!(m.capabilities.len(), 1);
    assert_eq!(m.capabilities[0].contract_id, 0);
    assert_eq!(m.capabilities[0].method_id, 3);

    // and survives a write/read cycle unchanged
    let again: KeyBackup = serde_json::from_str(&serde_json::to_string(&b).unwrap()).unwrap();
    assert_eq!(again.mandate.unwrap().circuit_fingerprint, "abc");
}

#[test]
fn an_ordinary_backup_serializes_without_a_mandate_key() {
    // Ordinary wallets omit only the optional mandate field.
    let b = KeyBackup {
        kind: KeyBackup::KIND.to_string(),
        private_key: "0x1".into(),
        fingerprint: "f".into(),
        name: "Wallet".into(),
        created_at: 1,
        network: Some("testnet".into()),
        mandate: None,
        default_shield_address: None,
        nostr_pub: None,
    };
    let s = serde_json::to_string(&b).unwrap();
    assert!(!s.contains("mandate"), "an ordinary wallet's backup gains no new field: {s}");
}
