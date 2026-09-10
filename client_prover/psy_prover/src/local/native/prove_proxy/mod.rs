//! prove-proxy: wallet-facing (user) and relayer-facing (system) proving RPCs.
//!
//! `user` and `system` are separate `#[rpc]` traits so a process can register
//! exactly one family; see `assemble_rpc_module` (Task 3).

pub mod user;

#[cfg(feature = "gnark-wrap")]
pub mod system;
#[cfg(feature = "gnark-wrap")]
pub mod types;

use jsonrpsee::{
    proc_macros::rpc,
    server::{Methods, RpcModule},
    types::ErrorObjectOwned,
};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use psy_client_common::args::ProveProxyRole;

pub(crate) type C = PoseidonGoldilocksConfig;
pub(crate) type F = <C as GenericConfig<D>>::F;
pub(crate) const D: usize = 2;

/// Answer of `psy_get_prove_proxy_role`. Lets deploy scripts and operators
/// confirm which pool an instance belongs to without probing proof methods.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ProveProxyRoleInfo {
    pub role: String,
    pub user_methods: bool,
    pub system_methods: bool,
}

#[rpc(server, client, namespace = "psy")]
pub trait ProveProxyInfoRpc {
    #[method(name = "get_prove_proxy_role")]
    async fn get_prove_proxy_role(&self) -> Result<ProveProxyRoleInfo, ErrorObjectOwned>;
}

struct RoleInfoProvider(ProveProxyRole);

#[jsonrpsee::core::async_trait]
impl ProveProxyInfoRpcServer for RoleInfoProvider {
    async fn get_prove_proxy_role(&self) -> Result<ProveProxyRoleInfo, ErrorObjectOwned> {
        Ok(ProveProxyRoleInfo {
            role: self.0.as_str().to_string(),
            user_methods: self.0.serves_user(),
            system_methods: self.0.serves_system(),
        })
    }
}

/// Builds the server module for `role`. Constructors for families the role
/// does not serve are never invoked, so a `user` process never builds bridge
/// circuits and a `system` process never builds the UPS circuit manager.
pub fn assemble_rpc_module<U, S>(role: ProveProxyRole, make_user: U, make_system: S) -> anyhow::Result<RpcModule<()>>
where
    U: FnOnce() -> anyhow::Result<Methods>,
    S: FnOnce() -> anyhow::Result<Methods>,
{
    let mut module = RpcModule::new(());
    module.merge(RoleInfoProvider(role).into_rpc())?;
    if role.serves_user() {
        module.merge(make_user()?)?;
    }
    if role.serves_system() {
        module.merge(make_system()?)?;
    }
    Ok(module)
}
