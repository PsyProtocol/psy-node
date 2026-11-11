use async_trait::async_trait;
use parth_core::node::realm_identifier::QRealmIdentifier;

#[async_trait]
pub trait QTempDBSubmitStatusReader {
    async fn get_submitted_status_for_pending(&self, rid: &QRealmIdentifier, unique_pending_id: u64, user_or_realm_id: u64) -> anyhow::Result<u64>;
    /// Raw deploy outcome guard value if held: [target checkpoint id u64 LE | nonce]; empty counts as absent. Resolves when the target checkpoint commits, not on a generation flip.
    async fn get_deploy_uncertain_outcome(
        &self,
        rid: &QRealmIdentifier,
        deployer: u64,
        deploy_content_hash: &[u8; 32],
    ) -> anyhow::Result<Option<Vec<u8>>>;
}

#[async_trait]
pub trait QTempDBSubmitStatusWriter {
    async fn set_submitted_status_for_pending(&self, rid: &QRealmIdentifier, unique_pending_id: u64, user_or_realm_id: u64, status: u64) -> anyhow::Result<()>;
    async fn put_submitted_status_if_absent(
        &self,
        rid: &QRealmIdentifier,
        unique_pending_id: u64,
        user_or_realm_id: u64,
        status: u64,
    ) -> anyhow::Result<bool>;
    /// Edge-side admission for contract code updates: at most one update per
    /// contract per gathering generation; own key family because the id is a contract id.
    async fn put_contract_update_submitted_if_absent(
        &self,
        rid: &QRealmIdentifier,
        unique_pending_id: u64,
        contract_id: u64,
    ) -> anyhow::Result<bool>;
    /// Best-effort release of the admission slot when a claimed submission fails before
    /// its queue item is confirmed delivered, so a same-generation retry is not locked out.
    async fn clear_contract_update_submitted(
        &self,
        rid: &QRealmIdentifier,
        unique_pending_id: u64,
        contract_id: u64,
    ) -> anyhow::Result<()>;
    /// Claims the deploy guard via CAS: `observed` must still hold (recycle) or be absent (fresh claim); false means it changed concurrently. Holds until the target checkpoint commits or `release_deploy_uncertain_outcome`.
    async fn claim_deploy_uncertain_outcome(
        &self,
        rid: &QRealmIdentifier,
        deployer: u64,
        deploy_content_hash: &[u8; 32],
        observed: Option<&[u8]>,
        new_value: &[u8],
    ) -> anyhow::Result<bool>;
    /// Releases the guard on a definite non-delivery, only if it still holds exactly `owned_value`, so a release never deletes a concurrently recycled guard.
    async fn release_deploy_uncertain_outcome(
        &self,
        rid: &QRealmIdentifier,
        deployer: u64,
        deploy_content_hash: &[u8; 32],
        owned_value: &[u8],
    ) -> anyhow::Result<bool>;
}

pub trait QTempDBSubmitStatusStore: QTempDBSubmitStatusReader + QTempDBSubmitStatusWriter {}
impl<T: QTempDBSubmitStatusReader + QTempDBSubmitStatusWriter> QTempDBSubmitStatusStore for T {}





