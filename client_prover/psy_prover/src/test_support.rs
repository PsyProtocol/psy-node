//! Shared helpers for offline tests.
//!
//! [`dead_network_config`] points every realm/coordinator RPC endpoint at a
//! closed local port, so RPC calls fail fast with connection refused instead
//! of touching the network. [`shared_offline_wallet_session`] keeps one
//! process-wide [`WalletSession`] because building the local circuit manager
//! is expensive and every test binary only needs it once.

use std::sync::Arc;

use parking_lot::RwLock;
use tokio::sync::OnceCell;

use crate::session::WalletSession;

pub(crate) fn dead_network_config() -> psy_config::NetworkConfigGoldilocks {
    serde_json::from_value(serde_json::json!({
        "magic": "1",
        "users_per_realm": 8,
        "global_user_tree_height": 8,
        "realm_user_tree_height": 4,
        "group_realm_height": 4,
        "realm_configs": [{"id": 0, "rpc_url": ["http://127.0.0.1:1"]}],
        "coordinator_configs": [{"id": 0, "rpc_url": ["http://127.0.0.1:1"]}],
        "prove_proxy_url": [],
        "faucet_rpc_url": [],
        "nostr_relay_url": "ws://127.0.0.1:1",
        "native_currency": "PSY",
        "native_currency_decimal": 18,
        "native_currency_name": "Psy",
        "fees": {
            "register_user_fee": 0,
            "deploy_contract_fee": 0,
            "guta_fee": 0,
            "da_fee": 0
        }
    }))
    .expect("dead network config must deserialize")
}

static SHARED_WALLET_SESSION: OnceCell<Arc<RwLock<WalletSession>>> = OnceCell::const_new();

/// The process-wide offline `WalletSession`, shared behind the same
/// `RwLock` type the RPC server wraps it in.
pub(crate) async fn shared_offline_wallet_session() -> Arc<RwLock<WalletSession>> {
    SHARED_WALLET_SESSION
        .get_or_init(|| async {
            let session = WalletSession::new(&dead_network_config())
                .await
                .expect("offline wallet session should initialize");
            Arc::new(RwLock::new(session))
        })
        .await
        .clone()
}
