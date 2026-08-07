use psy_node_core::store::realm_imt_mutation_graph::{
    RealmImtBaselineNodeKey, RealmImtMutationGraphError,
    RealmImtPredecessorReadRequest,
};
use psy_node_scylla::rollback::{
    CqlKeyspaceName, RealmImtPredecessorBindValue as V,
    RealmImtPredecessorBinding, RealmImtPredecessorCheckpointOutOfRange,
    RealmImtPredecessorQueries, RealmImtPredecessorQueryId,
    REALM_IMT_PREDECESSOR_CONCURRENT_LIMIT,
};

fn request(
    key: RealmImtBaselineNodeKey,
    height: u8,
) -> RealmImtPredecessorReadRequest {
    RealmImtPredecessorReadRequest::try_new(key, height).unwrap()
}

#[test]
fn query_catalog_uses_the_three_registered_production_schemas() {
    let keyspace = CqlKeyspaceName::try_new("psy_state").unwrap();
    let queries = RealmImtPredecessorQueries::new(&keyspace);
    assert_eq!(
        queries.render_golden(),
        include_str!("golden/realm_imt_predecessor_queries_v1.txt"),
    );
    assert_eq!(
        queries.all().map(|query| query.id()),
        [
            RealmImtPredecessorQueryId::GlobalUser,
            RealmImtPredecessorQueryId::UserContract,
            RealmImtPredecessorQueryId::ContractState,
        ],
    );
    for query in queries.all() {
        assert!(query.cql().contains("psy_state."));
        assert!(query.cql().contains("checkpoint_id <= ? LIMIT 1"));
        assert!(!query.cql().contains("ALLOW FILTERING"));
    }
    assert_eq!(REALM_IMT_PREDECESSOR_CONCURRENT_LIMIT, 512);
}

#[test]
fn typed_bindings_have_stable_real_driver_order() {
    let global = RealmImtPredecessorBinding::try_new(
        40,
        request(RealmImtBaselineNodeKey::GlobalUser { level: 3, index: 6 }, 8),
    )
    .unwrap();
    assert_eq!(global.query_id(), RealmImtPredecessorQueryId::GlobalUser);
    assert_eq!(global.bind_values(), vec![V::TinyInt(3), V::BigInt(6), V::BigInt(40)]);

    let user_contract = RealmImtPredecessorBinding::try_new(
        40,
        request(
            RealmImtBaselineNodeKey::UserContract {
                user_id: 17,
                level: 4,
                index: 9,
            },
            12,
        ),
    )
    .unwrap();
    assert_eq!(user_contract.query_id(), RealmImtPredecessorQueryId::UserContract);
    assert_eq!(
        user_contract.bind_values(),
        vec![V::BigInt(17), V::TinyInt(4), V::BigInt(9), V::BigInt(40)],
    );

    let contract_state = RealmImtPredecessorBinding::try_new(
        40,
        request(
            RealmImtBaselineNodeKey::ContractState {
                user_id: 17,
                contract_id: 23,
                level: 5,
                index: 12,
            },
            16,
        ),
    )
    .unwrap();
    assert_eq!(contract_state.query_id(), RealmImtPredecessorQueryId::ContractState);
    assert_eq!(
        contract_state.bind_values(),
        vec![
            V::BigInt(17),
            V::BigInt(23),
            V::TinyInt(5),
            V::BigInt(12),
            V::BigInt(40),
        ],
    );
}

#[test]
fn checkpoint_ordering_and_tree_height_fail_closed() {
    let valid = request(
        RealmImtBaselineNodeKey::GlobalUser { level: 1, index: 0 },
        2,
    );
    assert_eq!(
        RealmImtPredecessorBinding::try_new(u64::MAX, valid),
        Err(RealmImtPredecessorCheckpointOutOfRange(u64::MAX)),
    );

    let key = RealmImtBaselineNodeKey::ContractState {
        user_id: 1,
        contract_id: 2,
        level: 4,
        index: 0,
    };
    assert_eq!(
        RealmImtPredecessorReadRequest::try_new(key, 3),
        Err(RealmImtMutationGraphError::InvalidPredecessorReadHeight {
            key,
            tree_height: 3,
        }),
    );
    assert!(RealmImtPredecessorReadRequest::try_new(key, 64).is_err());
    assert!(matches!(
        RealmImtPredecessorReadRequest::try_new(
            RealmImtBaselineNodeKey::GlobalUser { level: 2, index: 4 },
            8,
        ),
        Err(RealmImtMutationGraphError::MerklePositionOutOfRange { .. })
    ));
}

#[test]
fn prototype_is_not_wired_into_production_setup_or_processor() {
    for source in [
        include_str!("../src/psy_setup.rs"),
        include_str!("../src/core_db.rs"),
    ] {
        assert!(!source.contains("RealmImtPredecessorAdapter"));
        assert!(!source.contains("RealmImtPredecessorReadPlan"));
    }
}
