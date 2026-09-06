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
    assert_eq!(rotation.checkpoints_per_epoch, 37);
    assert_eq!(rotation.validator_sub_ids, vec![1, 2]);
    network["realm_configs"][1]["validators"].as_array_mut().unwrap().push(json!({}));
    assert!(realm_rotation_config_from_network(&network).unwrap_err().to_string().contains("identical"));
    Ok(())
}

#[test]
fn realm_rotation_config_rejects_missing_or_disabled_rotation() {
    for network in [
        json!({}),
        json!({"p2p": {"checkpoints_per_epoch": 0}, "realm_configs": [{"validators": [{}, {}]}]}),
        json!({"p2p": {"checkpoints_per_epoch": 10}, "realm_configs": []}),
        json!({"p2p": {"checkpoints_per_epoch": 10}, "realm_configs": [{"validators": []}]}),
    ] {
        assert!(realm_rotation_config_from_network(&network).is_err());
    }
}
