pub mod coordinator_edge;
pub mod inspect_realm_rollback_readiness;
pub mod startup_plonky2_scylla;
pub mod scylla_helper;
pub mod startup_edge_plonky2_scylla;
pub mod startup_edge_jtmb_scylla;
pub mod startup_processor_jtmb_scylla;

#[cfg(test)]
mod realm_edge_branch_exact_startup_contract_tests {
    fn assert_single_fail_closed_composition(source: &str) {
        let setup = source
            .find("setup_realm_edge_scylla_startup_composition::<")
            .unwrap();
        let function_start = source[..setup].rfind("async fn ").unwrap();
        let realm_function = &source[function_start..];
        let function_end = realm_function
            .find("\ntype ")
            .unwrap_or(realm_function.len());
        let source = &realm_function[..function_end];
        assert_eq!(
            source
                .matches("setup_realm_edge_scylla_startup_composition::<")
                .count(),
            1
        );
        assert_eq!(source.matches("composition.into_legacy_db()?").count(), 1);
        assert_eq!(
            source
                .matches(".into_branch_exact_ingress(")
                .count(),
            1
        );
        assert_eq!(
            source
                .matches("install_durable_user_update_ingress")
                .count(),
            1
        );
        assert_eq!(
            source
                .matches("RealmUserUpdateVerifierRegistry::try_new")
                .count(),
            1
        );
        assert_eq!(
            source
                .matches("realm_user_update_verifier_profile(config.network)")
                .count(),
            1
        );
        assert_eq!(
            source
                .matches("setup_nats_psy_queue_from_connection_str")
                .count(),
            1
        );
        let prepare = source
            .find("setup_realm_edge_scylla_startup_composition::<")
            .unwrap();
        let sealed = source.find(".into_branch_exact_ingress").unwrap();
        let install = source
            .find("install_durable_user_update_ingress")
            .unwrap();
        let legacy_handler = source.find("let handler = RealmEdgeHandler").unwrap();
        assert!(prepare < sealed && sealed < legacy_handler && legacy_handler < install);
        assert!(source.contains("Arc::clone(&proof_verifier)"));
        assert!(source.contains("Arc::clone(&nats_queue)"));
        for forbidden in [
            "ScyllaRealmEdgeStartupAuthorization",
            "prepare_realm_edge_durable_publisher",
            "ScyllaRealmUserUpdateDurableRouter",
            "RealmUserUpdatePublishPort",
            "Session",
            "RecoverableNatsStreamSegment",
        ] {
            assert!(
                !source.contains(forbidden),
                "CLI bypassed the common composition with {forbidden}"
            );
        }
    }

    #[test]
    fn plonky2_and_jtmb_share_one_default_off_edge_composition() {
        assert_single_fail_closed_composition(include_str!(
            "startup_edge_plonky2_scylla.rs"
        ));
        assert_single_fail_closed_composition(include_str!(
            "startup_edge_jtmb_scylla.rs"
        ));
    }
}
