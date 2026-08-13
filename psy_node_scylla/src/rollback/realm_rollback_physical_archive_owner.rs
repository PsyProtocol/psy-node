//! Storage-selected Realm participant archive owner.
//!
//! The owner resolves a product rollback height into Realm-local target and
//! source chain references, scans the complete committed suffix, exact-reads
//! every hot row through the production family adapters, persists immutable
//! before-images, and repeats the whole selection/readback fence.  Its result
//! remains pre-barrier and cannot delete, restore, rotate, or publish a head.

#![allow(dead_code)]

use std::{collections::BTreeMap, error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::NetworkId,
    chain_context::AuthorityScope,
};
use psy_node_core::store::{
    authority_commit::AuthorityTimestampKey,
    authority_local_head::{AuthorityLocalHeadReadState, StoredAuthorityLocalHead},
    rollback_participant_plan::RollbackParticipantPlan,
};
use scylla::client::session::Session;
use sha2::{Digest, Sha256};

use super::{
    BranchExactDeploymentNoTabletKeyspace, CqlKeyspaceName,
    PendingQueueArtifactDataKeyspace, ScyllaAuthorityLocalHeadStore,
    branch_exact_dual_write_executor::{
        BranchExactDualWriteExecutionError, RealmRollbackNarrowObservedRow,
        ScyllaBranchExactDualWriteAdapter,
    },
    realm_full_commit_scylla::RealmFullCommitScyllaExecutor,
    realm_rollback_commit_inventory_store::{
        ScyllaRealmRollbackCommitInventoryStore,
        VerifiedRealmRollbackCommittedSuffixEntry,
    },
    realm_rollback_physical_archive_store::{
        PersistedRealmRollbackParticipantCompletion,
        RealmRollbackPhysicalArchiveStoreError,
        ScyllaRealmRollbackPhysicalArchiveStore,
    },
    realm_rollback_physical_before_image::{
        RealmRollbackPhysicalBeforeImage, RealmRollbackPhysicalBeforeImageError,
    },
    realm_rollback_physical_catalog::{
        RealmRollbackPhysicalCatalog, RealmRollbackPhysicalCatalogEntry,
        RealmRollbackPhysicalKey,
    },
    realm_rollback_participant_completion::{
        RealmRollbackParticipantCompletion,
        RealmRollbackParticipantCompletionError,
    },
};

const PARTICIPANT_DATASET_DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.realm-physical-archive-participant.v1\0";

/// Non-Clone proof of a complete two-pass Realm archive.  Persistence of a
/// durable participant completion and the global all-participant barrier are
/// deliberately later capabilities.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct RealmRollbackPhysicalParticipantArchiveReceipt<Hash> {
    participant_plan_digest: [u8; 32],
    authority: AuthorityScope,
    source_head: StoredAuthorityLocalHead<Hash>,
    target_chain: psy_data::protocol::canonical_chain::CanonicalChainRef<Hash>,
    catalog_digest: [u8; 32],
    entry_count: u64,
    delete_count: u64,
    restore_count: u64,
    dataset_digest: [u8; 32],
    archive_store_fingerprint: [u8; 32],
}

impl<Hash> RealmRollbackPhysicalParticipantArchiveReceipt<Hash> {
    pub(super) const fn authority(&self) -> AuthorityScope { self.authority }
    pub(super) const fn entry_count(&self) -> u64 { self.entry_count }
    pub(super) const fn dataset_digest(&self) -> &[u8; 32] { &self.dataset_digest }
}

pub(super) struct ScyllaRealmRollbackPhysicalArchiveOwner {
    session: Arc<Session>,
    inventory: Arc<ScyllaRealmRollbackCommitInventoryStore>,
    local_head: Arc<ScyllaAuthorityLocalHeadStore>,
    typed: RealmFullCommitScyllaExecutor,
    narrow: ScyllaBranchExactDualWriteAdapter,
    archive: ScyllaRealmRollbackPhysicalArchiveStore,
}

impl ScyllaRealmRollbackPhysicalArchiveOwner {
    pub(super) async fn prepare(
        session: Arc<Session>,
        inventory: Arc<ScyllaRealmRollbackCommitInventoryStore>,
        local_head: Arc<ScyllaAuthorityLocalHeadStore>,
        narrow: ScyllaBranchExactDualWriteAdapter,
        source_keyspace: CqlKeyspaceName,
        archive_keyspace: CqlKeyspaceName,
    ) -> Result<Self, RealmRollbackPhysicalArchiveOwnerError> {
        let typed = RealmFullCommitScyllaExecutor::prepare_with_consistency(
            &session,
            source_keyspace,
            scylla::statement::Consistency::Quorum,
        ).await.map_err(backend)?;
        let archive = ScyllaRealmRollbackPhysicalArchiveStore::prepare(
            session.clone(), archive_keyspace,
        ).await?;
        Ok(Self { session, inventory, local_head, typed, narrow, archive })
    }

    /// Convenience preparation from the same sidecar keyspaces used by the
    /// normal commit inventory.  Schema materialization is intentionally not
    /// performed here.
    pub(super) async fn prepare_inventory(
        session: Arc<Session>,
        control: BranchExactDeploymentNoTabletKeyspace,
        data: PendingQueueArtifactDataKeyspace,
    ) -> Result<Arc<ScyllaRealmRollbackCommitInventoryStore>, RealmRollbackPhysicalArchiveOwnerError> {
        Ok(Arc::new(
            ScyllaRealmRollbackCommitInventoryStore::prepare(session, control, data).await
                .map_err(backend)?,
        ))
    }

    pub(super) async fn archive_selected_realm<Hash: Q256BitHash>(
        &mut self,
        network: NetworkId,
        authority: AuthorityScope,
        plan: &RollbackParticipantPlan<Hash>,
    ) -> Result<RealmRollbackPhysicalParticipantArchiveReceipt<Hash>, RealmRollbackPhysicalArchiveOwnerError> {
        require_realm_in_plan(network, authority, plan)?;
        let source_head = self.read_local_head::<Hash>(network, authority).await?;
        let source_chain = *source_head.head().chain();
        if source_chain.network_id() != network
            || source_chain.chain_epoch() != plan.target().chain_epoch()
            || source_chain.checkpoint().checkpoint_id().get()
                != plan.expected_head().canonical_ref().checkpoint().checkpoint_id().get()
        {
            return Err(RealmRollbackPhysicalArchiveOwnerError::SourceHeadMismatch);
        }
        let target_entry = self.inventory.read_committed_height(
            authority,
            network,
            source_chain.chain_epoch(),
            plan.target().checkpoint().checkpoint_id().get(),
        ).await.map_err(backend)?;
        let target_chain = *target_entry.inventory().candidate().canonical_chain();
        let suffix = self.inventory.scan_committed_suffix(
            authority, target_chain, source_chain,
        ).await.map_err(backend)?;
        let catalog = RealmRollbackPhysicalCatalog::try_from_selected(
            suffix, Some(&target_entry),
        )?;
        let entry_count = u64::try_from(catalog.entries().len())
            .map_err(|_| RealmRollbackPhysicalArchiveOwnerError::LengthOverflow)?;
        let mut first = participant_dataset_hasher(
            plan.digest(), authority, &source_head, &target_chain.to_canonical_bytes(),
            catalog.digest(), entry_count, catalog.delete_count(), catalog.restore_count(),
            self.archive.fingerprint(),
        );
        let mut narrow_cache = BTreeMap::new();
        for (index, entry) in catalog.entries().iter().enumerate() {
            let image = self.observe_image(plan.digest(), &catalog, entry, &mut narrow_cache).await?;
            let receipt = self.archive.persist_and_readback(image).await?;
            update_dataset(&mut first, index, receipt.before_image())?;
        }
        let dataset_digest: [u8; 32] = first.finalize().into();

        self.require_sources_unchanged(plan, authority, &source_head, &target_entry, &catalog).await?;
        narrow_cache.clear();
        let mut second = participant_dataset_hasher(
            plan.digest(), authority, &source_head, &target_chain.to_canonical_bytes(),
            catalog.digest(), entry_count, catalog.delete_count(), catalog.restore_count(),
            self.archive.fingerprint(),
        );
        for (index, entry) in catalog.entries().iter().enumerate() {
            let image = self.observe_image(plan.digest(), &catalog, entry, &mut narrow_cache).await?;
            self.archive.revalidate_image_exact(&image).await?;
            update_dataset(&mut second, index, &image)?;
        }
        if <[u8; 32]>::from(second.finalize()) != dataset_digest {
            return Err(RealmRollbackPhysicalArchiveOwnerError::DatasetChanged);
        }
        self.require_sources_unchanged(plan, authority, &source_head, &target_entry, &catalog).await?;

        Ok(RealmRollbackPhysicalParticipantArchiveReceipt {
            participant_plan_digest: *plan.digest(),
            authority,
            source_head,
            target_chain,
            catalog_digest: *catalog.digest(),
            entry_count,
            delete_count: catalog.delete_count(),
            restore_count: catalog.restore_count(),
            dataset_digest,
            archive_store_fingerprint: *self.archive.fingerprint(),
        })
    }

    /// Freshly reselect every source/archive row and compare it with the
    /// affine result. No missing archive row is created by this path.
    pub(super) async fn revalidate_participant_receipt<Hash: Q256BitHash>(
        &mut self,
        network: NetworkId,
        plan: &RollbackParticipantPlan<Hash>,
        receipt: &RealmRollbackPhysicalParticipantArchiveReceipt<Hash>,
    ) -> Result<(), RealmRollbackPhysicalArchiveOwnerError> {
        let current = self.select_revalidated_archive(network, receipt.authority, plan).await?;
        if current != *receipt {
            return Err(RealmRollbackPhysicalArchiveOwnerError::ParticipantReceiptChanged);
        }
        Ok(())
    }

    /// Durably publish a participant completion only after a fresh full
    /// source/archive pass. Errors after the immutable LWT are
    /// commit-indeterminate; callers must recover or retry this same request.
    pub(super) async fn persist_participant_completion<Hash: Q256BitHash>(
        &mut self,
        network: NetworkId,
        plan: &RollbackParticipantPlan<Hash>,
        receipt: &RealmRollbackPhysicalParticipantArchiveReceipt<Hash>,
    ) -> Result<PersistedRealmRollbackParticipantCompletion<Hash>, RealmRollbackPhysicalArchiveOwnerError> {
        self.revalidate_participant_receipt(network, plan, receipt).await?;
        let completion = completion_from_receipt(receipt)?;
        let persisted = self.archive.persist_participant_completion(completion).await?;
        self.revalidate_participant_receipt(network, plan, receipt).await?;
        self.archive.revalidate_participant_completion(&persisted).await?;
        Ok(persisted)
    }

    /// Restart path: derive the only acceptable completion from freshly
    /// selected hot/archive state, then require that exact immutable row.
    pub(super) async fn recover_participant_completion<Hash: Q256BitHash>(
        &mut self,
        network: NetworkId,
        authority: AuthorityScope,
        plan: &RollbackParticipantPlan<Hash>,
    ) -> Result<PersistedRealmRollbackParticipantCompletion<Hash>, RealmRollbackPhysicalArchiveOwnerError> {
        let selected = self.select_revalidated_archive(network, authority, plan).await?;
        let expected = completion_from_receipt(&selected)?;
        let current = self.archive.read_participant_completion_exact(&expected).await?
            .ok_or(RealmRollbackPhysicalArchiveOwnerError::CompletionMissing)?;
        if current != expected {
            return Err(RealmRollbackPhysicalArchiveOwnerError::CompletionChanged);
        }
        let persisted = PersistedRealmRollbackParticipantCompletion::from_recovered(
            *self.archive.fingerprint(), current,
        );
        let after = self.select_revalidated_archive(network, authority, plan).await?;
        if after != selected {
            return Err(RealmRollbackPhysicalArchiveOwnerError::ParticipantReceiptChanged);
        }
        self.archive.revalidate_participant_completion(&persisted).await?;
        Ok(persisted)
    }

    async fn select_revalidated_archive<Hash: Q256BitHash>(
        &mut self,
        network: NetworkId,
        authority: AuthorityScope,
        plan: &RollbackParticipantPlan<Hash>,
    ) -> Result<RealmRollbackPhysicalParticipantArchiveReceipt<Hash>, RealmRollbackPhysicalArchiveOwnerError> {
        require_realm_in_plan(network, authority, plan)?;
        let source_head = self.read_local_head::<Hash>(network, authority).await?;
        let source_chain = *source_head.head().chain();
        if source_chain.network_id() != network
            || source_chain.chain_epoch() != plan.target().chain_epoch()
            || source_chain.checkpoint().checkpoint_id().get()
                != plan.expected_head().canonical_ref().checkpoint().checkpoint_id().get()
        {
            return Err(RealmRollbackPhysicalArchiveOwnerError::SourceHeadMismatch);
        }
        let target_entry = self.inventory.read_committed_height(
            authority,
            network,
            source_chain.chain_epoch(),
            plan.target().checkpoint().checkpoint_id().get(),
        ).await.map_err(backend)?;
        let target_chain = *target_entry.inventory().candidate().canonical_chain();
        let suffix = self.inventory.scan_committed_suffix(authority, target_chain, source_chain)
            .await.map_err(backend)?;
        let catalog = RealmRollbackPhysicalCatalog::try_from_selected(suffix, Some(&target_entry))?;
        let entry_count = u64::try_from(catalog.entries().len())
            .map_err(|_| RealmRollbackPhysicalArchiveOwnerError::LengthOverflow)?;
        let mut dataset = participant_dataset_hasher(
            plan.digest(), authority, &source_head, &target_chain.to_canonical_bytes(),
            catalog.digest(), entry_count, catalog.delete_count(), catalog.restore_count(),
            self.archive.fingerprint(),
        );
        let mut narrow_cache = BTreeMap::new();
        for (index, entry) in catalog.entries().iter().enumerate() {
            let image = self.observe_image(plan.digest(), &catalog, entry, &mut narrow_cache).await?;
            self.archive.revalidate_image_exact(&image).await?;
            update_dataset(&mut dataset, index, &image)?;
        }
        let dataset_digest: [u8; 32] = dataset.finalize().into();
        self.require_sources_unchanged(plan, authority, &source_head, &target_entry, &catalog).await?;
        Ok(RealmRollbackPhysicalParticipantArchiveReceipt {
            participant_plan_digest: *plan.digest(),
            authority,
            source_head,
            target_chain,
            catalog_digest: *catalog.digest(),
            entry_count,
            delete_count: catalog.delete_count(),
            restore_count: catalog.restore_count(),
            dataset_digest,
            archive_store_fingerprint: *self.archive.fingerprint(),
        })
    }

    async fn observe_image<Hash: Q256BitHash>(
        &self,
        plan_digest: &[u8; 32],
        catalog: &RealmRollbackPhysicalCatalog<Hash>,
        entry: &RealmRollbackPhysicalCatalogEntry,
        narrow_cache: &mut BTreeMap<usize, Vec<RealmRollbackNarrowObservedRow>>,
    ) -> Result<RealmRollbackPhysicalBeforeImage<Hash>, RealmRollbackPhysicalArchiveOwnerError> {
        match entry.key() {
            RealmRollbackPhysicalKey::Typed(_) => {
                let put = entry.current_put().ok_or(RealmRollbackPhysicalArchiveOwnerError::CatalogMismatch)?;
                let observed = self.typed.read_inventory_put_physical_exact(&self.session, put).await.map_err(backend)?;
                RealmRollbackPhysicalBeforeImage::try_from_typed(*plan_digest, catalog, entry, &observed)
                    .map_err(Into::into)
            }
            RealmRollbackPhysicalKey::Narrow { kind, primary_key, .. } => {
                if !narrow_cache.contains_key(&entry.source_index()) {
                    let source = catalog.suffix().entries().get(entry.source_index())
                        .ok_or(RealmRollbackPhysicalArchiveOwnerError::CatalogMismatch)?;
                    let rows = self.narrow.read_inventory_exact(
                        source.inventory().narrow_intent(), source.inventory().timestamp(),
                    ).await?;
                    narrow_cache.insert(entry.source_index(), rows);
                }
                let observed = narrow_cache.get(&entry.source_index())
                    .and_then(|rows| rows.iter().find(|row| row.kind() == *kind && row.primary_key() == primary_key))
                    .ok_or(RealmRollbackPhysicalArchiveOwnerError::CatalogMismatch)?;
                RealmRollbackPhysicalBeforeImage::try_from_narrow(*plan_digest, catalog, entry, observed)
                    .map_err(Into::into)
            }
        }
    }

    async fn require_sources_unchanged<Hash: Q256BitHash>(
        &self,
        plan: &RollbackParticipantPlan<Hash>,
        authority: AuthorityScope,
        source_head: &StoredAuthorityLocalHead<Hash>,
        target: &VerifiedRealmRollbackCommittedSuffixEntry<Hash>,
        catalog: &RealmRollbackPhysicalCatalog<Hash>,
    ) -> Result<(), RealmRollbackPhysicalArchiveOwnerError> {
        if self.read_local_head::<Hash>(
            plan.target().network_id(), authority,
        ).await? != *source_head {
            return Err(RealmRollbackPhysicalArchiveOwnerError::SourceChanged);
        }
        let current_target = self.inventory.read_committed_height(
            authority,
            plan.target().network_id(),
            source_head.head().chain().chain_epoch(),
            plan.target().checkpoint().checkpoint_id().get(),
        ).await.map_err(backend)?;
        if current_target != *target {
            return Err(RealmRollbackPhysicalArchiveOwnerError::SourceChanged);
        }
        self.inventory.revalidate_committed_suffix(catalog.suffix()).await.map_err(backend)?;
        Ok(())
    }

    async fn read_local_head<Hash: Q256BitHash>(
        &self,
        network: NetworkId,
        authority: AuthorityScope,
    ) -> Result<StoredAuthorityLocalHead<Hash>, RealmRollbackPhysicalArchiveOwnerError> {
        match self.local_head.read(AuthorityTimestampKey::new(network, authority)).await.map_err(backend)? {
            AuthorityLocalHeadReadState::Current(current) => Ok(current),
            AuthorityLocalHeadReadState::Uninitialized => Err(RealmRollbackPhysicalArchiveOwnerError::LocalHeadMissing),
        }
    }
}

fn require_realm_in_plan<Hash: Q256BitHash>(
    network: NetworkId,
    authority: AuthorityScope,
    plan: &RollbackParticipantPlan<Hash>,
) -> Result<(), RealmRollbackPhysicalArchiveOwnerError> {
    let AuthorityScope::Realm { realm_id, realm_sub_id } = authority else {
        return Err(RealmRollbackPhysicalArchiveOwnerError::RealmRequired);
    };
    if plan.expected_head().canonical_ref().network_id() != network
        || plan.target().network_id() != network
        || !plan.realms().iter().any(|realm| {
            realm.realm_id() == realm_id && realm.realm_sub_id() == realm_sub_id
        })
    {
        return Err(RealmRollbackPhysicalArchiveOwnerError::ParticipantNotPlanned);
    }
    Ok(())
}

fn participant_dataset_hasher<Hash: Q256BitHash>(
    plan_digest: &[u8; 32],
    authority: AuthorityScope,
    source_head: &StoredAuthorityLocalHead<Hash>,
    target_chain_bytes: &[u8],
    catalog_digest: &[u8; 32],
    entry_count: u64,
    delete_count: u64,
    restore_count: u64,
    store_fingerprint: &[u8; 32],
) -> Sha256 {
    let AuthorityScope::Realm { realm_id, realm_sub_id } = authority else { unreachable!() };
    let mut hasher = Sha256::new();
    hasher.update(PARTICIPANT_DATASET_DIGEST_DOMAIN);
    hasher.update(plan_digest);
    hasher.update(realm_id.to_be_bytes());
    hasher.update(realm_sub_id.to_be_bytes());
    hasher.update(source_head.revision().get().to_be_bytes());
    hasher.update(source_head.encode_canonical());
    hasher.update((target_chain_bytes.len() as u64).to_be_bytes());
    hasher.update(target_chain_bytes);
    hasher.update(catalog_digest);
    hasher.update(entry_count.to_be_bytes());
    hasher.update(delete_count.to_be_bytes());
    hasher.update(restore_count.to_be_bytes());
    hasher.update(store_fingerprint);
    hasher
}

fn completion_from_receipt<Hash: Q256BitHash>(
    receipt: &RealmRollbackPhysicalParticipantArchiveReceipt<Hash>,
) -> Result<RealmRollbackParticipantCompletion<Hash>, RealmRollbackPhysicalArchiveOwnerError> {
    RealmRollbackParticipantCompletion::try_from_selected(
        receipt.participant_plan_digest,
        receipt.authority,
        receipt.source_head.clone(),
        receipt.target_chain,
        receipt.catalog_digest,
        receipt.entry_count,
        receipt.delete_count,
        receipt.restore_count,
        receipt.dataset_digest,
        receipt.archive_store_fingerprint,
    ).map_err(Into::into)
}

fn update_dataset<Hash: Q256BitHash>(
    hasher: &mut Sha256,
    index: usize,
    image: &RealmRollbackPhysicalBeforeImage<Hash>,
) -> Result<(), RealmRollbackPhysicalArchiveOwnerError> {
    hasher.update(u64::try_from(index).map_err(|_| RealmRollbackPhysicalArchiveOwnerError::LengthOverflow)?.to_be_bytes());
    hasher.update(image.slot());
    hasher.update(image.digest());
    Ok(())
}

fn backend(error: impl fmt::Display) -> RealmRollbackPhysicalArchiveOwnerError {
    RealmRollbackPhysicalArchiveOwnerError::Backend(error.to_string())
}

#[derive(Debug)]
pub(super) enum RealmRollbackPhysicalArchiveOwnerError {
    Backend(String),
    RealmRequired,
    ParticipantNotPlanned,
    LocalHeadMissing,
    SourceHeadMismatch,
    SourceChanged,
    CatalogMismatch,
    DatasetChanged,
    ParticipantReceiptChanged,
    CompletionMissing,
    CompletionChanged,
    LengthOverflow,
    BeforeImage(RealmRollbackPhysicalBeforeImageError),
    Catalog(super::realm_rollback_physical_catalog::RealmRollbackPhysicalCatalogError),
    Archive(RealmRollbackPhysicalArchiveStoreError),
    Completion(RealmRollbackParticipantCompletionError),
    Narrow(BranchExactDualWriteExecutionError),
}

impl From<RealmRollbackPhysicalBeforeImageError> for RealmRollbackPhysicalArchiveOwnerError {
    fn from(value: RealmRollbackPhysicalBeforeImageError) -> Self { Self::BeforeImage(value) }
}
impl From<super::realm_rollback_physical_catalog::RealmRollbackPhysicalCatalogError> for RealmRollbackPhysicalArchiveOwnerError {
    fn from(value: super::realm_rollback_physical_catalog::RealmRollbackPhysicalCatalogError) -> Self { Self::Catalog(value) }
}
impl From<RealmRollbackPhysicalArchiveStoreError> for RealmRollbackPhysicalArchiveOwnerError {
    fn from(value: RealmRollbackPhysicalArchiveStoreError) -> Self { Self::Archive(value) }
}
impl From<RealmRollbackParticipantCompletionError> for RealmRollbackPhysicalArchiveOwnerError {
    fn from(value: RealmRollbackParticipantCompletionError) -> Self { Self::Completion(value) }
}
impl From<BranchExactDualWriteExecutionError> for RealmRollbackPhysicalArchiveOwnerError {
    fn from(value: BranchExactDualWriteExecutionError) -> Self { Self::Narrow(value) }
}
impl fmt::Display for RealmRollbackPhysicalArchiveOwnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Realm rollback archive owner error: {self:?}")
    }
}
impl Error for RealmRollbackPhysicalArchiveOwnerError {}

#[cfg(test)]
mod tests {
    #[test]
    fn owner_is_pre_barrier_and_never_deletes_or_publishes() {
        let source = include_str!("realm_rollback_physical_archive_owner.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in ["execute_delete", "execute_restore", "cross_archive_barrier", "publish_head", "seal_rotation"] {
            assert!(!production.contains(forbidden));
        }
        assert!(production.contains("read_committed_height"));
        assert!(production.contains("persist_and_readback"));
        assert!(production.contains("revalidate_image_exact"));
    }
}
