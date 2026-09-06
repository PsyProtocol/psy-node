use super::realm_rotation_config_from_network;
use serde_json::json;

#[test]
fn realm_rotation_config_requires_uniform_validator_counts() -> anyhow::Result<()> {
    let mut network = json!({
        "p2p": {"checkpoints_per_epoch": 37},
        "realm_configs": [
            {"id": 0, "validators": [{}, {}]},
            {"id": 1, "validators": [{}, {}]}
        ]
    });
    let rotation = realm_rotation_config_from_network(&network)?;
    assert_eq!(rotation.checkpoints_per_epoch, psy_config::CHECKPOINTS_PER_EPOCH);
    assert_eq!(rotation.validator_sub_ids, vec![1, 2]);
    network["realm_configs"][1]["validators"].as_array_mut().unwrap().push(json!({}));
    assert!(realm_rotation_config_from_network(&network).unwrap_err().to_string().contains("identical"));
    Ok(())
}

#[test]
fn realm_rotation_config_rejects_missing_validators() {
    for network in [
        json!({}),
        json!({"p2p": {"checkpoints_per_epoch": 10}, "realm_configs": []}),
        json!({"p2p": {"checkpoints_per_epoch": 10}, "realm_configs": [{"validators": []}]}),
    ] {
        assert!(realm_rotation_config_from_network(&network).is_err());
    }
}

#[test]
fn realm_rotation_ignores_runtime_checkpoint_period() {
    let mut network = json!({"realm_configs": [{"id": 0, "validators": [{}, {}]}]});
    for p2p in [json!(null), json!({"checkpoints_per_epoch": 0}), json!({"checkpoints_per_epoch": psy_config::CHECKPOINTS_PER_EPOCH + 1})] {
        network["p2p"] = p2p;
        let rotation = realm_rotation_config_from_network(&network).unwrap();
        assert_eq!(rotation.checkpoints_per_epoch, psy_config::CHECKPOINTS_PER_EPOCH);
        assert_eq!(rotation.validator_sub_ids, vec![1, 2]);
    }
}
