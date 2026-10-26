use std::sync::atomic::{AtomicBool, Ordering};

use jsonrpsee::server::RpcModule;
use psy_client_common::args::ProveProxyRole;
use psy_prover::local::native::prove_proxy::{assemble_rpc_module, ProveProxyRoleInfo};

fn marker(name: &'static str) -> jsonrpsee::server::Methods {
    let mut m = RpcModule::new(());
    m.register_method(name, |_, _, _| "ok").unwrap();
    m.into()
}

fn names(module: &RpcModule<()>) -> Vec<&'static str> {
    let mut v: Vec<_> = module.method_names().collect();
    v.sort();
    v
}

#[test]
fn user_role_registers_only_user_family() {
    let user_called = AtomicBool::new(false);
    let system_called = AtomicBool::new(false);
    let module = assemble_rpc_module(
        ProveProxyRole::User,
        || { user_called.store(true, Ordering::SeqCst); Ok(marker("psy_user_marker")) },
        || { system_called.store(true, Ordering::SeqCst); Ok(marker("psy_system_marker")) },
    )
    .unwrap();
    assert!(user_called.load(Ordering::SeqCst));
    assert!(!system_called.load(Ordering::SeqCst), "system constructor must not run in user role");
    assert_eq!(names(&module), vec!["psy_get_prove_proxy_role", "psy_user_marker"]);
}

#[test]
fn system_role_registers_only_system_family() {
    let user_called = AtomicBool::new(false);
    let module = assemble_rpc_module(
        ProveProxyRole::System,
        || { user_called.store(true, Ordering::SeqCst); Ok(marker("psy_user_marker")) },
        || Ok(marker("psy_system_marker")),
    )
    .unwrap();
    assert!(!user_called.load(Ordering::SeqCst), "user constructor must not run in system role");
    assert_eq!(names(&module), vec!["psy_get_prove_proxy_role", "psy_system_marker"]);
}

#[test]
fn all_role_registers_both() {
    let module = assemble_rpc_module(
        ProveProxyRole::All,
        || Ok(marker("psy_user_marker")),
        || Ok(marker("psy_system_marker")),
    )
    .unwrap();
    assert_eq!(names(&module), vec!["psy_get_prove_proxy_role", "psy_system_marker", "psy_user_marker"]);
}

#[test]
fn constructor_error_propagates() {
    let err = assemble_rpc_module(
        ProveProxyRole::System,
        || Ok(marker("psy_user_marker")),
        || Err(anyhow::anyhow!("gnark keystore missing")),
    )
    .err()
    .expect("must fail");
    assert!(err.to_string().contains("gnark keystore missing"));
}

#[tokio::test]
async fn role_info_reports_role() {
    let module = assemble_rpc_module(ProveProxyRole::System, || Ok(marker("psy_user_marker")), || Ok(marker("psy_system_marker"))).unwrap();
    let info: ProveProxyRoleInfo = module.call("psy_get_prove_proxy_role", jsonrpsee::rpc_params![]).await.unwrap();
    assert_eq!(info.role, "system");
    assert!(!info.user_methods);
    assert!(info.system_methods);
}
