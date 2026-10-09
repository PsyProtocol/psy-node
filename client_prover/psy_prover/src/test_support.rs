//! Shared helpers for offline tests.
//!
//! [`dead_network_config`] points every realm/coordinator RPC endpoint at a
//! closed local port, so RPC calls fail fast with connection refused instead
//! of touching the network. [`shared_offline_wallet_session`] keeps one
//! process-wide [`WalletSession`] because building the local circuit manager
//! is expensive and every test binary only needs it once.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use parking_lot::RwLock;
use tokio::sync::OnceCell;

use crate::session::WalletSession;

static FAUCET_ENV_LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn lock_faucet_env() -> MutexGuard<'static, ()> {
    FAUCET_ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

const FAUCET_ENV_NAMES: &[&str] = &[
    "PSY_FAUCET_OPERATORS_JSON",
    "PSY_FAUCET_OPERATORS_JSON_B64",
    "PSY_FAUCET_TURNSTILE_SECRET",
    "PSY_FAUCET_REQUIRE_TURNSTILE",
    "PSY_FAUCET_TURNSTILE_ACTION",
    "PSY_FAUCET_TURNSTILE_ALLOWED_HOSTNAMES",
    "PSY_FAUCET_WINDOW_CHECKPOINTS",
];

pub(crate) struct FaucetEnvGuard(Vec<(&'static str, Option<String>)>);

impl FaucetEnvGuard {
    pub(crate) fn cleared() -> Self {
        let previous = FAUCET_ENV_NAMES.iter().map(|&name| (name, std::env::var(name).ok())).collect();
        for name in FAUCET_ENV_NAMES {
            std::env::remove_var(name);
        }
        Self(previous)
    }
}

impl Drop for FaucetEnvGuard {
    fn drop(&mut self) {
        for (name, value) in &self.0 {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }
}

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
