pub mod compile_bridge;
pub mod session;
pub use session::*;
pub mod utils;
pub use utils::*;

#[cfg(not(target_arch = "wasm32"))]
pub async fn sleep(dur: std::time::Duration) {
    tokio::time::sleep(dur).await;
}

#[cfg(target_arch = "wasm32")]
pub async fn sleep(dur: std::time::Duration) {
    use js_sys::{global, Function, Promise, Reflect};
    use wasm_bindgen::{closure::Closure, JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;

    let ms = dur.as_millis() as i32;

    let promise = Promise::new(&mut |resolve: Function, _reject: Function| {
        let global_obj = global();
        let resolve_for_cb = resolve.clone();
        let cb = Closure::<dyn FnMut()>::once(move || {
            let _ = resolve_for_cb.call0(&JsValue::NULL);
        });
        if let Some(set_timeout) = Reflect::get(&global_obj, &JsValue::from_str("setTimeout"))
            .ok()
            .and_then(|v| v.dyn_into::<Function>().ok())
        {
            let _ = set_timeout.call2(&global_obj, cb.as_ref().unchecked_ref(), &JsValue::from_f64(ms as f64));
        } else {
            let _ = resolve.call0(&JsValue::NULL);
        }
        cb.forget();
    });

    let _ = JsFuture::from(promise).await;
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use plonky2::field::goldilocks_field::GoldilocksField;

    type F = GoldilocksField;

    const BASIC_CONTRACT: &str = r#"
        #[contract]
        pub struct TestContract {
            pub value: Felt,
        }

        #[contract_implementation]
        impl TestContract {
            #[contract_method]
            pub fn set_value(&mut self, ctx: &ChainContext, new_value: Felt) {
                self.value = new_value;
            }
        }
    "#;

    #[tokio::test]
    async fn sleep_elapses_at_least_the_requested_duration() {
        let start = std::time::Instant::now();
        super::sleep(std::time::Duration::from_millis(20)).await;
        assert!(start.elapsed() >= std::time::Duration::from_millis(20));
    }

    #[tokio::test]
    async fn session_reports_public_keys_for_every_builtin_signature_type() {
        let session = crate::test_support::shared_offline_wallet_session().await;
        let session = session.read();
        let private_key = psy_client_common::data::qhashout::QHashOut::<F>::from_values(31, 32, 33, 34);

        let zk = session.get_zk_public_key(private_key).await.unwrap();
        let secp = session.get_secp_public_key(private_key).await.unwrap();
        let eth_personal = session.get_eth_personal_secp_public_key(private_key).await.unwrap();

        assert_ne!(zk.public_key_param, secp.public_key_param);
        assert_eq!(secp.public_key_param, eth_personal.public_key_param);
        assert_ne!(secp.fingerprint, eth_personal.fingerprint);
    }

    #[tokio::test]
    async fn session_signing_helpers_fail_fast_on_unknown_users() {
        let session = crate::test_support::shared_offline_wallet_session().await;
        let session = session.read();
        let unregistered = psy_client_common::data::qhashout::QHashOut::<F>::ZERO;

        let error = session
            .sign(unregistered, psy_client_common::args::DPNSoftwareDefinedCallData::default())
            .await
            .unwrap_err();
        assert!(!error.to_string().is_empty());
        let error = session
            .sign_inner(unregistered, psy_client_common::args::DPNSoftwareDefinedCallData::default())
            .await
            .unwrap_err();
        assert!(!error.to_string().is_empty());
        let error = session
            .sign_imt(unregistered, psy_client_common::args::DPNSoftwareDefinedCallData::default())
            .await
            .unwrap_err();
        assert!(!error.to_string().is_empty());

        // external-proof insertion requires an active proving session
        let wallet = &session.wallet;
        let proof = wallet
            .prove_zk_sign(
                psy_client_common::data::qhashout::QHashOut::<F>::from_values(41, 42, 43, 44),
                unregistered,
            )
            .await
            .unwrap();
        let verifier = wallet.zk_circuit_verifier_config().await.unwrap();
        let error = session
            .add_external_proof(unregistered, unregistered, proof.clone(), verifier.clone())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("not found"));
        let error = session
            .add_external_proof_with_siblings(unregistered, unregistered, proof, verifier)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("not found"));
    }

    #[tokio::test]
    async fn session_builds_contract_update_commands_locally() {
        let session = crate::test_support::shared_offline_wallet_session().await;
        let session = session.read();

        let output = psy_compiler::compile(BASIC_CONTRACT).expect("compilation should succeed");
        let deployer = psy_client_common::data::qhashout::QHashOut::<F>::ZERO;

        // the no-ABI deploy entry point is a guarded stub
        let error = session.deploy_contract(deployer, output.circuit_definitions.clone()).await.unwrap_err();
        assert!(error.to_string().contains("requires ABI"));

        // update commands are built locally; the chain submission then fails
        // on the dead RPC
        let update_cmd = session.get_update_contract_cmd(42, deployer, output.circuit_definitions.clone()).unwrap();
        assert_eq!(update_cmd.contract_id, 42);

        let error = session.update_contract(42, deployer, output.circuit_definitions).await.unwrap_err();
        assert!(!error.to_string().is_empty());

        // the JSON-ABI deploy variant validates its input and reuses the
        // local layout-aware builder
        let error = session
            .get_layout_aware_deploy_contract_cmd_from_json(deployer, Vec::new(), "not json")
            .unwrap_err();
        assert!(error.to_string().contains("invalid contract ABI JSON"));
    }
}
