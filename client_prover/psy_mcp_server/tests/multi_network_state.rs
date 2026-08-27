//! Multi-network state must never collide even when chain-local identifiers
//! (user id, deposit index, or note commitment) are identical.

#[allow(dead_code, unused_imports)]
#[path = "../src/agent_account.rs"]
mod agent_account;
#[allow(dead_code, unused_imports)]
#[path = "../src/keystore.rs"]
mod keystore;
#[allow(dead_code, unused_imports)]
#[path = "../src/l1.rs"]
mod l1;
#[allow(dead_code, unused_imports)]
#[path = "../src/network.rs"]
mod network;
#[allow(dead_code, unused_imports)]
#[path = "../src/policy.rs"]
mod policy;
#[allow(dead_code, unused_imports)]
#[path = "../src/wallet.rs"]
mod wallet;

use policy::{Limits, PolicyEngine};

fn temp_root() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("psy-mcp-multi-network-{}", rand::random::<u64>()))
}

#[test]
fn identical_claim_ids_are_persisted_in_different_network_subtrees() {
    let root = temp_root();
    let make_deposit = |network: &str| wallet::DepositNote {
        network: Some(network.to_string()),
        note_secret: [1, 2, 3, 4],
        nullifier_secret: [5, 6, 7, 8],
        shield_address_hex: "0000000000000001:0000000000000002:0000000000000003:0000000000000004".into(),
        l1_token_address: "0x0000000000000000000000000000000000000001".into(),
        l2_token_contract_id: 0,
        amount_base_units: 10,
        source_chain_index: 1,
        expected_deposit_index: 42,
        l1_tx_hash: None,
        claimed: false,
        delivered: false,
        deposit_proof_json: None,
        nostr_event_ids: Vec::new(),
    };

    let a = make_deposit("network-a").persist(&root).unwrap();
    let b = make_deposit("network-b").persist(&root).unwrap();
    assert_ne!(a, b);
    assert!(a.ends_with("networks/network-a/deposits/deposit-42.json"));
    assert!(b.ends_with("networks/network-b/deposits/deposit-42.json"));

    let commitment = [9, 10, 11, 12];
    let note_a = wallet::PrivateNoteRecovery::path_in(&root, "network-a", &commitment).unwrap();
    let note_b = wallet::PrivateNoteRecovery::path_in(&root, "network-b", &commitment).unwrap();
    assert_ne!(note_a, note_b);
    assert!(note_a.starts_with(root.join("networks/network-a/private-notes")));
    assert!(note_b.starts_with(root.join("networks/network-b/private-notes")));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn spend_and_denied_logs_retain_their_network() {
    let limits = Limits {
        per_transaction: 100,
        per_day: 100,
        per_month: None,
        total_budget: None,
    };
    let mut engine = PolicyEngine::new();

    engine.set_current_wallet("network-a", 7);
    let policy_a = engine.create_policy("a", limits.clone(), None, vec!["simple_transfer".into()]);
    let (token_a, _) = engine.issue_session(&policy_a, 60, None).unwrap();
    engine.authorize(&token_a, "8", 1, "simple_transfer").unwrap();

    engine.set_current_wallet("network-b", 7);
    let policy_b = engine.create_policy("b", limits, None, vec!["simple_transfer".into()]);
    let (token_b, _) = engine.issue_session(&policy_b, 60, None).unwrap();
    engine.authorize(&token_b, "8", 1, "simple_transfer").unwrap();
    let _ = engine.authorize(&token_b, "8", 101, "simple_transfer");

    let spends = engine.spend_log(10, None);
    // Logs are returned newest first.
    assert_eq!(
        spends.iter().map(|r| r.network.as_deref()).collect::<Vec<_>>(),
        vec![Some("network-b"), Some("network-a")]
    );
    let denied = engine.denied_log(10, None);
    assert_eq!(denied.last().and_then(|r| r.network.as_deref()), Some("network-b"));
}

#[test]
fn wallet_backup_discovery_finds_all_root_wallet_files() {
    let root = temp_root();
    std::fs::create_dir_all(root.join("nested")).unwrap();
    std::fs::write(root.join("wallet-testnet-a.json"), "{}").unwrap();
    std::fs::write(root.join("wallet-testnet-b.json"), "{}").unwrap();
    std::fs::write(root.join("policies.json"), "{}").unwrap();
    std::fs::write(root.join("nested/wallet-mainnet-c.json"), "{}").unwrap();

    let found = keystore::discover_key_files_in(&root).unwrap();
    let names = found
        .iter()
        .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert_eq!(names, vec!["wallet-testnet-a.json", "wallet-testnet-b.json"]);

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn active_wallets_survive_restart_and_are_partitioned_by_network() {
    let root = temp_root();
    keystore::persist_active_wallet_in(&root, "network-a", "pk-a").unwrap();
    keystore::persist_active_wallet_in(&root, "network-b", "pk-b").unwrap();

    let restored = keystore::load_active_wallets_in(&root).unwrap();
    assert_eq!(restored.get("network-a").map(String::as_str), Some("pk-a"));
    assert_eq!(restored.get("network-b").map(String::as_str), Some("pk-b"));

    keystore::persist_active_wallet_in(&root, "network-a", "pk-a-2").unwrap();
    let restored = keystore::load_active_wallets_in(&root).unwrap();
    assert_eq!(restored.get("network-a").map(String::as_str), Some("pk-a-2"));
    assert_eq!(restored.get("network-b").map(String::as_str), Some("pk-b"));

    std::fs::remove_dir_all(root).unwrap();
}
