use std::{fs, path::Path};

use anyhow::Context;
use jsonrpsee::{
    core::client::ClientT,
    http_client::{HttpClient, HttpClientBuilder},
    rpc_params,
};
use parth_core::PHash;
use psy_api_core::coordinator::rollback_admin::{
    ROLLBACK_ADMIN_ABORT_REQUEST_VERSION, ROLLBACK_ADMIN_START_REQUEST_VERSION,
    RollbackAdminAbortRequest, RollbackAdminAbortResponse, RollbackAdminExecutionMode,
    RollbackAdminStartRequest, RollbackAdminStartResponse, RollbackAdminStatus,
};

const ROLLBACK_STATUS_METHOD: &str = "psy_admin_get_rollback_status";
const ROLLBACK_START_METHOD: &str = "psy_admin_start_rollback";
const ROLLBACK_ABORT_METHOD: &str = "psy_admin_abort_rollback";

fn client(url: &str) -> anyhow::Result<HttpClient> {
    HttpClientBuilder::default()
        .build(url)
        .with_context(|| format!("build Coordinator rollback client for {url}"))
}

fn read_json(path: &Path) -> anyhow::Result<String> {
    fs::read_to_string(path)
        .with_context(|| format!("read rollback request file {}", path.display()))
}

pub(crate) fn decode_start_request(
    bytes: &str,
) -> anyhow::Result<RollbackAdminStartRequest<PHash>> {
    let request: RollbackAdminStartRequest<PHash> =
        serde_json::from_str(bytes).context("decode strict rollback start request JSON")?;
    if request.request_version != ROLLBACK_ADMIN_START_REQUEST_VERSION {
        anyhow::bail!(
            "rollback start request version must be {}",
            ROLLBACK_ADMIN_START_REQUEST_VERSION
        );
    }
    if request.execution_mode != RollbackAdminExecutionMode::InPlace {
        anyhow::bail!("first-release rollback only supports IN_PLACE execution");
    }
    Ok(request)
}

pub(crate) fn decode_abort_request(bytes: &str) -> anyhow::Result<RollbackAdminAbortRequest> {
    let request: RollbackAdminAbortRequest =
        serde_json::from_str(bytes).context("decode strict rollback abort request JSON")?;
    if request.request_version != ROLLBACK_ADMIN_ABORT_REQUEST_VERSION {
        anyhow::bail!(
            "rollback abort request version must be {}",
            ROLLBACK_ADMIN_ABORT_REQUEST_VERSION
        );
    }
    Ok(request)
}

pub(crate) async fn status(url: &str) -> anyhow::Result<RollbackAdminStatus<PHash>> {
    client(url)?
        .request(ROLLBACK_STATUS_METHOD, rpc_params![])
        .await
        .context("request Coordinator rollback status")
}

pub(crate) async fn start(
    url: &str,
    request_file: &Path,
) -> anyhow::Result<RollbackAdminStartResponse<PHash>> {
    let request = decode_start_request(&read_json(request_file)?)?;
    client(url)?
        .request(ROLLBACK_START_METHOD, rpc_params![request])
        .await
        .context("submit explicit Coordinator rollback request")
}

pub(crate) async fn abort(
    url: &str,
    request_file: &Path,
) -> anyhow::Result<RollbackAdminAbortResponse<PHash>> {
    let request = decode_abort_request(&read_json(request_file)?)?;
    client(url)?
        .request(ROLLBACK_ABORT_METHOD, rpc_params![request])
        .await
        .context("submit explicit Coordinator rollback abort")
}

#[cfg(test)]
mod tests {
    use psy_data::protocol::canonical_chain::{
        CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef, NetworkId,
    };

    use super::*;

    #[test]
    fn rollback_cli_uses_the_namespaced_server_methods() {
        assert_eq!(ROLLBACK_STATUS_METHOD, "psy_admin_get_rollback_status");
        assert_eq!(ROLLBACK_START_METHOD, "psy_admin_start_rollback");
        assert_eq!(ROLLBACK_ABORT_METHOD, "psy_admin_abort_rollback");
    }

    #[test]
    fn start_request_is_strict_in_place_v2() {
        let value = serde_json::to_value(RollbackAdminStartRequest {
            request_version: 2,
            expected_revision: 7,
            expected_canonical_ref: CanonicalChainRef::new(
                NetworkId::try_from_chain_id(1).unwrap(),
                ChainEpoch::new(0),
                CheckpointRef::new(
                    CheckpointId::new(3),
                    CheckpointHash::from_last_chain_hash(PHash::from_values(1, 2, 3, 4)),
                ),
            ),
            target_checkpoint_id: 1,
            target_checkpoint_hash: PHash::from_values(5, 6, 7, 8),
            orphan_write_max_timestamp_us: 100,
            delete_fence_timestamp_us: 200,
            new_branch_write_timestamp_us: 300,
            execution_mode: RollbackAdminExecutionMode::InPlace,
            topology_revision: 1,
            topology_digest_hex: "aa".repeat(32),
        })
        .unwrap();
        assert!(decode_start_request(&value.to_string()).is_ok());

        let mut snapshot = value.clone();
        snapshot["execution_mode"] = serde_json::json!("SNAPSHOT_REPLAY");
        assert!(decode_start_request(&snapshot.to_string()).is_err());

        let mut unknown = value;
        unknown["unexpected"] = serde_json::json!(true);
        assert!(decode_start_request(&unknown.to_string()).is_err());
    }

    #[test]
    fn abort_request_is_strict_v1() {
        let value = serde_json::json!({
            "request_version": 1,
            "expected_revision": 9,
            "expected_chain_epoch": 1,
            "expected_plan_digest_hex": "bb".repeat(32),
            "reason_code": 7,
        });
        assert!(decode_abort_request(&value.to_string()).is_ok());
        let mut stale = value;
        stale["request_version"] = serde_json::json!(2);
        assert!(decode_abort_request(&stale.to_string()).is_err());
    }
}
