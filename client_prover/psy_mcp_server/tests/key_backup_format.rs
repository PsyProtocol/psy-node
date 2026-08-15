//! The key backup gained a `mandate` field so a minted agent account can be
//! restored after a restart. Every backup written before that must keep
//! loading, or the change strands the wallets it was meant to protect.

#[allow(dead_code, unused_imports)]
#[path = "../src/agent_account.rs"]
mod agent_account;
#[allow(dead_code, unused_imports)]
#[path = "../src/keystore.rs"]
mod keystore;

use keystore::KeyBackup;

#[test]
fn a_pre_existing_backup_without_a_mandate_still_parses() {
    // Exactly the shape written before this change.
    let json = r#"{
        "kind": "psy-wallet-key-v1",
        "private_key": "0xabc123",
        "fingerprint": "deadbeef",
        "created_at": 1786029233
    }"#;
    let b: KeyBackup = serde_json::from_str(json).expect("old backups must still load");
    assert_eq!(b.private_key, "0xabc123");
    assert!(b.mandate.is_none(), "absent means an ordinary wallet, not an agent account");
}

#[test]
fn a_null_mandate_is_treated_as_absent() {
    let json = r#"{
        "kind": "psy-wallet-key-v1", "private_key": "0x1", "fingerprint": "f",
        "created_at": 1, "mandate": null
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
        "created_at": 1,
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
    // skip_serializing_if keeps the old shape byte-identical for old wallets.
    let b = KeyBackup {
        kind: KeyBackup::KIND.to_string(),
        private_key: "0x1".into(),
        fingerprint: "f".into(),
        created_at: 1,
        mandate: None,
    };
    let s = serde_json::to_string(&b).unwrap();
    assert!(!s.contains("mandate"), "an ordinary wallet's backup gains no new field: {s}");
}
