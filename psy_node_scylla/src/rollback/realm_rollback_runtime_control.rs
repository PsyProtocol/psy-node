//! Realm-side prepare-only view of the Coordinator rollback control store.
//!
//! The Realm process receives an explicit Coordinator namespace from its
//! operator.  It never guesses the namespace and never exposes canonical-head
//! mutation or raw report writes.

use std::sync::Arc;

use async_trait::async_trait;
use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::NetworkId,
    chain_context::AuthorityScope,
};
use psy_node_core::store::{
    canonical_head::{CanonicalHeadReadState, StoredCanonicalHead},
    rollback_control::RollbackControlState,
    rollback_runtime_rebuild::{
        RealmRollbackRuntimeControl, RollbackRuntimeRebuildReport,
        SelectedRealmRollbackRuntimeRebuild,
    },
};
use scylla::client::session::Session;

use super::{
    canonical_head_prototype::ScyllaCanonicalHeadStore,
    rollback_runtime_rebuild_store::ScyllaRollbackRuntimeRebuildStore,
    CanonicalHeadNoTabletKeyspace, CqlKeyspaceName,
};

pub struct ScyllaRealmRollbackRuntimeControl {
    canonical_head: Arc<ScyllaCanonicalHeadStore>,
    runtime_rebuild: Arc<ScyllaRollbackRuntimeRebuildStore>,
}

impl ScyllaRealmRollbackRuntimeControl {
    /// Prepare statements against an explicitly configured, already deployed
    /// Coordinator namespace.  No keyspace or table is created here.
    pub async fn prepare(
        session: Arc<Session>,
        coordinator_keyspace: &str,
    ) -> anyhow::Result<Self> {
        let data = CqlKeyspaceName::try_new(coordinator_keyspace.to_owned())?;
        let control = CanonicalHeadNoTabletKeyspace::try_new(format!(
            "{}_no_tablet",
            coordinator_keyspace
        ))?;
        Ok(Self {
            canonical_head: Arc::new(
                ScyllaCanonicalHeadStore::prepare(session.clone(), control).await?,
            ),
            runtime_rebuild: Arc::new(
                ScyllaRollbackRuntimeRebuildStore::prepare(session, &data).await?,
            ),
        })
    }

    async fn read_head<Hash: Q256BitHash>(
        &self,
        network: NetworkId,
    ) -> anyhow::Result<Option<StoredCanonicalHead<Hash>>> {
        Ok(match self.canonical_head.read(network).await? {
            CanonicalHeadReadState::Uninitialized => None,
            CanonicalHeadReadState::Current(head) => Some(head),
        })
    }

    fn phase_matches_selected<Hash: Q256BitHash>(
        current: &StoredCanonicalHead<Hash>,
        selected: &SelectedRealmRollbackRuntimeRebuild<Hash>,
    ) -> bool {
        let selected_request = match selected.verifying_head().rollback_control() {
            RollbackControlState::Verifying(request) => request,
            _ => return false,
        };
        match current.rollback_control() {
            RollbackControlState::Verifying(request)
            | RollbackControlState::AllRealmsReady(request) => {
                request == selected_request
                    && current.canonical_ref().network_id()
                        == selected.directive().target().network_id()
                    && current.canonical_ref().chain_epoch()
                        == selected.directive().target().chain_epoch()
            }
            RollbackControlState::Idle => {
                current.canonical_ref() == selected.directive().target()
            }
            _ => false,
        }
    }
}

#[async_trait]
impl<Hash: Q256BitHash> RealmRollbackRuntimeControl<Hash>
    for ScyllaRealmRollbackRuntimeControl
{
    async fn read_realm_rollback_control_head(
        &self,
        network: NetworkId,
    ) -> anyhow::Result<CanonicalHeadReadState<Hash>> {
        Ok(match self.read_head(network).await? {
            None => CanonicalHeadReadState::Uninitialized,
            Some(head) => CanonicalHeadReadState::Current(head),
        })
    }

    async fn read_selected_realm_runtime_rebuild(
        &self,
        network: NetworkId,
        authority: AuthorityScope,
    ) -> anyhow::Result<Option<SelectedRealmRollbackRuntimeRebuild<Hash>>> {
        if !matches!(authority, AuthorityScope::Realm { .. }) {
            anyhow::bail!("Realm rollback runtime control requires Realm authority")
        }
        let Some(first_head) = self.read_head(network).await? else {
            return Ok(None);
        };
        if !matches!(first_head.rollback_control(), RollbackControlState::Verifying(_)) {
            return Ok(None);
        }
        let Some(directive) = self
            .runtime_rebuild
            .read_selected_directive(first_head, authority)
            .await?
        else {
            return Ok(None);
        };
        let Some(second_head) = self.read_head(network).await? else {
            anyhow::bail!("Coordinator canonical head disappeared while selecting Realm rebuild")
        };
        if second_head != first_head {
            anyhow::bail!("Coordinator canonical head changed while selecting Realm rebuild")
        }
        Ok(Some(SelectedRealmRollbackRuntimeRebuild::try_from_storage(
            second_head,
            directive,
        )?))
    }

    async fn persist_realm_runtime_rebuild_report(
        &self,
        selected: SelectedRealmRollbackRuntimeRebuild<Hash>,
        report: RollbackRuntimeRebuildReport<Hash>,
    ) -> anyhow::Result<()> {
        self.runtime_rebuild
            .revalidate_directive(selected.directive())
            .await?;
        let Some(before) = self
            .read_head(selected.directive().target().network_id())
            .await?
        else {
            anyhow::bail!("Coordinator canonical head disappeared before Realm report")
        };
        if !Self::phase_matches_selected(&before, &selected) {
            anyhow::bail!("Coordinator rollback phase changed before Realm report")
        }
        self.runtime_rebuild
            .persist_and_revalidate_report(*selected.directive(), report)
            .await?;
        let Some(after) = self
            .read_head(selected.directive().target().network_id())
            .await?
        else {
            anyhow::bail!("Coordinator canonical head disappeared after Realm report")
        };
        if !Self::phase_matches_selected(&after, &selected) {
            anyhow::bail!("Coordinator rollback phase changed incompatibly after Realm report")
        }
        Ok(())
    }

    async fn is_realm_runtime_rebuild_published(
        &self,
        selected: SelectedRealmRollbackRuntimeRebuild<Hash>,
    ) -> anyhow::Result<bool> {
        self.runtime_rebuild
            .revalidate_directive(selected.directive())
            .await?;
        let Some(current) = self
            .read_head(selected.directive().target().network_id())
            .await?
        else {
            anyhow::bail!("Coordinator canonical head disappeared after Realm rebuild")
        };
        if !Self::phase_matches_selected(&current, &selected) {
            anyhow::bail!("Coordinator rollback phase no longer matches Realm rebuild")
        }
        Ok(matches!(current.rollback_control(), RollbackControlState::Idle))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn realm_control_is_prepare_only_and_brackets_reports() {
        let source = include_str!("realm_rollback_runtime_control.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(!source.contains("create_schema"));
        assert!(!source.contains("compare_and_set"));
        assert!(!source.contains("persist_directive"));
        let select = source.find("let Some(first_head)").unwrap();
        let directive = source.find(".read_selected_directive(first_head, authority)").unwrap();
        let second = source.find("let Some(second_head)").unwrap();
        assert!(select < directive && directive < second);
        let persist = source.find(".persist_and_revalidate_report(").unwrap();
        let before = source[..persist].rfind("let Some(before)").unwrap();
        let after = source[persist..].find("let Some(after)").unwrap() + persist;
        assert!(before < persist && persist < after);
    }
}
