//! The Realm's rollback control plane (design-r1 §6.3).
//!
//! Three tables where the Coordinator has nine, and the difference is the point.
//! §6 gives one authority over the chain's head: barriers are LWTs on the
//! Coordinator's control row and Realms read them.  A Realm therefore publishes
//! no head, establishes no floor, and keeps no commit source -- creating any of
//! those would put a second place where a head could be declared, which I10
//! forbids.
//!
//! What it keeps is its own manifest and its own allocator, and both already have
//! room: `authority_manifest` is partitioned by `authority_scope` and
//! `authority_commit_timestamp` by authority kind plus realm id, so a Realm's
//! rows sit beside the Coordinator's at the same height without colliding.

use std::sync::Arc;

use parth_core::{
    crypto::hash::traits::MerkleZeroHasher,
    protocol::core_types::{Q256BitHash, QHashBase},
};
use psy_node_core::store::commit_window::CommitWindowClock;

use crate::core::ScyllaCoreStore;

use super::{
    AuthorityTimestampNoTabletKeyspace, ManifestArtifactNoTabletKeyspace, ManifestNoTabletKeyspace,
    ScyllaAuthorityManifestStore, ScyllaAuthorityTimestampStore, ScyllaManifestArtifactStore,
    ScyllaRealmCommitPlanner, ScyllaVerificationJournal,
};

/// Every control table a Realm creates.  Shorter than the Coordinator's list on
/// purpose -- see the module note.
pub const REALM_ROLLBACK_CONTROL_TABLES: &[&str] = &[
    super::AUTHORITY_COMMIT_TIMESTAMP_TABLE,
    super::AUTHORITY_MANIFEST_TABLE,
    super::AUTHORITY_MANIFEST_ARTIFACT_TABLE,
];

/// Generic in the chain's hash, because the participant view it holds reads the
/// Coordinator's head and a head is hashed.  The rest of the plane is
/// hash-agnostic and used to make the whole struct so; that was only true while
/// it could not watch a rollback.
pub struct RealmRollbackControlPlane<Hash: Q256BitHash + QHashBase> {
    authority_timestamp: Arc<ScyllaAuthorityTimestampStore>,
    manifest: Arc<ScyllaAuthorityManifestStore>,
    manifest_artifact: Arc<ScyllaManifestArtifactStore>,
    commit_window: Arc<CommitWindowClock>,
    journal: Option<Arc<ScyllaVerificationJournal>>,
    /// How this Realm watches the rollback it is a participant in.
    ///
    /// Reads the Coordinator's control row and files this Realm's receipts, and
    /// deliberately cannot advance a phase: §6.2 puts every barrier on the
    /// Coordinator.  Present only when the Coordinator's keyspace was named,
    /// because a Realm that cannot see the control row must not guess at a
    /// phase -- it would either freeze a chain nobody asked to freeze, or keep
    /// committing through one that was.
    participant_view: Option<Arc<super::ScyllaRollbackParticipantView<Hash>>>,
    /// Lives in this Realm's own keyspace, not the Coordinator's: it records
    /// what *this* Realm believes, and only this Realm may write it.
    sync_epoch: Arc<super::ScyllaRealmSyncEpochStore>,
}

impl<Hash: Q256BitHash + QHashBase> RealmRollbackControlPlane<Hash> {
    /// The Realm's participant view, when the Coordinator's keyspace is known.
    pub fn participant_view(&self) -> Option<&super::ScyllaRollbackParticipantView<Hash>> {
        self.participant_view.as_deref()
    }

    /// Create then prepare, for a Realm bringing a keyspace up.
    /// `network_chain_id` is taken rather than assumed.  The Coordinator's
    /// receipt and history tables are partitioned by it, and a Realm that
    /// guessed would file its evidence where the barrier never looks -- which
    /// reads as a participant that never responded, not as a misconfiguration.
    pub async fn setup<Hasher: MerkleZeroHasher<Hash>>(
        store: &ScyllaCoreStore<Hash, Hasher>,
        network_chain_id: i64,
    ) -> anyhow::Result<Self> {
        let no_tablet = store.no_tablet_keyspace.clone();
        ScyllaAuthorityTimestampStore::create_schema(
            &store.session,
            &AuthorityTimestampNoTabletKeyspace::try_new(&no_tablet)?,
        )
        .await?;
        ScyllaAuthorityManifestStore::create_tables(
            &store.session,
            &ManifestNoTabletKeyspace::try_new(&no_tablet)?,
        )
        .await?;
        ScyllaManifestArtifactStore::create_tables(
            &store.session,
            &ManifestArtifactNoTabletKeyspace::try_new(&no_tablet)?,
        )
        .await?;
        super::ScyllaRealmSyncEpochStore::create_table(&store.session, &no_tablet).await?;
        store.session.await_schema_agreement().await?;

        let mut control = Self {
            authority_timestamp: Arc::new(
                ScyllaAuthorityTimestampStore::prepare(
                    store.session.clone(),
                    AuthorityTimestampNoTabletKeyspace::try_new(&no_tablet)?,
                )
                .await?,
            ),
            manifest: Arc::new(
                ScyllaAuthorityManifestStore::prepare(
                    store.session.clone(),
                    &ManifestNoTabletKeyspace::try_new(&no_tablet)?,
                )
                .await?,
            ),
            manifest_artifact: Arc::new(
                ScyllaManifestArtifactStore::prepare(
                    store.session.clone(),
                    &ManifestArtifactNoTabletKeyspace::try_new(&no_tablet)?,
                )
                .await?,
            ),
            commit_window: store.commit_window.clone(),
            journal: None,
            participant_view: None,
            sync_epoch: Arc::new(
                super::ScyllaRealmSyncEpochStore::prepare(
                    store.session.clone(),
                    &no_tablet,
                    network_chain_id,
                )
                .await?,
            ),
        };

        // Watching the rollback needs the Coordinator's keyspace, because that
        // is where the control row and the receipt table live (§6.2).  A Realm
        // deployed without it still commits and records normally; it simply
        // cannot take part in a coordinated rollback, and saying so by absence
        // is better than defaulting to a keyspace name that might belong to
        // another network on the same cluster.
        if let Ok(coordinator_no_tablet) =
            std::env::var("PSY_ROLLBACK_COORDINATOR_NO_TABLET_KEYSPACE")
        {
            super::ScyllaRollbackParticipantView::<Hash>::create_table(
                &store.session,
                &coordinator_no_tablet,
            )
            .await?;
            let head_reader = super::ScyllaCanonicalHeadStore::prepare(
                store.session.clone(),
                super::CanonicalHeadNoTabletKeyspace::try_new(&coordinator_no_tablet)?,
            )
            .await?;
            control.participant_view = Some(Arc::new(
                super::ScyllaRollbackParticipantView::prepare(
                    store.session.clone(),
                    &coordinator_no_tablet,
                    network_chain_id,
                    Arc::new(head_reader),
                )
                .await?,
            ));
        }

        if std::env::var("PSY_ROLLBACK_VERIFICATION_JOURNAL").is_ok() {
            ScyllaVerificationJournal::create_table(&store.session, &store.keyspace).await?;
            control.journal = Some(Arc::new(
                ScyllaVerificationJournal::prepare(store.session.clone(), &store.keyspace).await?,
            ));
        }
        Ok(control)
    }

    /// The capability bundle a Realm processor takes.
    ///
    /// Handed out whole, like the Coordinator's, so §0.2 D3 holds on this side
    /// too: there is no way to obtain the state store without it.
    pub fn recording(
        &self,
    ) -> psy_node_core::store::realm_commit_recording::RealmCommitRecording<Hash> {
        psy_node_core::store::realm_commit_recording::RealmCommitRecording::new(
            self.authority_timestamp.clone(),
            Arc::new(ScyllaRealmCommitPlanner::new()),
            self.manifest.clone(),
            self.manifest_artifact.clone(),
            self.commit_window.clone(),
            self.journal.clone().map(|journal| {
                journal
                    as Arc<dyn psy_node_core::store::verification_journal::CommitVerificationJournal>
            }),
        )
        .with_participant_view(self.participant_view.clone().map(|view| {
            view as Arc<
                dyn psy_node_core::store::rollback_coordination::RollbackParticipantView<Hash>,
            >
        }))
        .with_sync_epoch_store(Some(self.sync_epoch.clone()
            as Arc<dyn psy_node_core::store::realm_sync_epoch::RealmSyncEpochStore>))
    }
}
