use parth_core::node::realm_identifier::QRealmIdentifier;
use psy_node_core::{
    psy_temp_db::{tt_get_guta_in_flight_key, GutaInFlightRecord, QTempDBGutaInFlightStore},
    store::traits::temp_db::QTempDatabaseRawKVWriterBase,
};
use psy_node_store_memory::temp_store::InMemoryTempStore;

fn store() -> InMemoryTempStore {
    InMemoryTempStore::new("guta_in_flight_test".to_string(), 1, 2)
}

fn rid() -> QRealmIdentifier {
    QRealmIdentifier::new(1, 2)
}

fn record(old: u8, new: u8, accepted_at_checkpoint_id: u64) -> GutaInFlightRecord {
    GutaInFlightRecord { old_realm_root: [old; 32], new_realm_root: [new; 32], accepted_at_checkpoint_id }
}

#[tokio::test]
async fn no_record_until_one_is_claimed() -> anyhow::Result<()> {
    let store = store();
    assert!(store.get_guta_in_flight(&rid(), 0).await?.is_none());

    assert!(store.claim_guta_in_flight(&rid(), 0, None, &record(1, 2, 5)).await?);
    let (stored, raw) = store.get_guta_in_flight(&rid(), 0).await?.expect("claimed record");
    assert_eq!(stored, record(1, 2, 5));
    assert_eq!(raw, record(1, 2, 5).to_bytes().to_vec());
    Ok(())
}

#[tokio::test]
async fn a_claim_against_a_stale_observation_is_refused() -> anyhow::Result<()> {
    let store = store();
    assert!(store.claim_guta_in_flight(&rid(), 0, None, &record(1, 2, 5)).await?);

    // a second claimer that read "no record" lost the race
    assert!(!store.claim_guta_in_flight(&rid(), 0, None, &record(1, 3, 6)).await?);
    // so did one that read an older record
    let older = record(9, 9, 1).to_bytes();
    assert!(!store.claim_guta_in_flight(&rid(), 0, Some(&older), &record(1, 3, 6)).await?);
    assert_eq!(store.get_guta_in_flight(&rid(), 0).await?.unwrap().0, record(1, 2, 5));

    // a claimer that read the current record replaces it
    let current = record(1, 2, 5).to_bytes();
    assert!(store.claim_guta_in_flight(&rid(), 0, Some(&current), &record(1, 3, 8)).await?);
    assert_eq!(store.get_guta_in_flight(&rid(), 0).await?.unwrap().0, record(1, 3, 8));
    Ok(())
}

#[tokio::test]
async fn records_of_different_realms_are_independent() -> anyhow::Result<()> {
    let store = store();
    assert!(store.claim_guta_in_flight(&rid(), 0, None, &record(1, 2, 5)).await?);
    assert!(store.claim_guta_in_flight(&rid(), 1, None, &record(7, 8, 5)).await?);
    assert_eq!(store.get_guta_in_flight(&rid(), 0).await?.unwrap().0, record(1, 2, 5));
    assert_eq!(store.get_guta_in_flight(&rid(), 1).await?.unwrap().0, record(7, 8, 5));
    // the coordinator realm identifier is part of the key too
    assert!(store.get_guta_in_flight(&QRealmIdentifier::new(1, 3), 0).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn a_malformed_stored_record_is_an_error() -> anyhow::Result<()> {
    let store = store();
    let key = tt_get_guta_in_flight_key(1, 2, 0);
    store.qtdb_raw_kv_put_value(&key, &[0u8; 10]).await?;
    assert!(store.get_guta_in_flight(&rid(), 0).await.is_err());
    Ok(())
}
