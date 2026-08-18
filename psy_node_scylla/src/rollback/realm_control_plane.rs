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

use parth_core::{crypto::hash::traits::MerkleZeroHasher, protocol::core_types::QHashBase};
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

pub struct RealmRollbackControlPlane {
    authority_timestamp: Arc<ScyllaAuthorityTimestampStore>,
    manifest: Arc<ScyllaAuthorityManifestStore>,
    manifest_artifact: Arc<ScyllaManifestArtifactStore>,
    commit_window: Arc<CommitWindowClock>,
    journal: Option<Arc<ScyllaVerificationJournal>>,
}

impl RealmRollbackControlPlane {
    /// Create then prepare, for a Realm bringing a keyspace up.
    pub async fn setup<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>>(
        store: &ScyllaCoreStore<Hash, Hasher>,
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
        };

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
    pub fn recording<Hash: parth_core::protocol::core_types::Q256BitHash>(
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
    }
}
