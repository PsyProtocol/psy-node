use parth_core::protocol::core_types::QNetworkTypesConfig;
use psy_data::{
    prepared_block::realm::PsyRealmCoordinatorUpdate,
    protocol::{
        canonical_chain::{CanonicalChainRef, NetworkId},
        chain_context::{
            AuthorityObservation, AuthorityScope, AuthorityStateCheckpointId,
            AuthorityStateRoot, PendingContext, WorkProcCheckpointUniqueId,
            WorkUniquePendingId,
        },
    },
};
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    p2p::traits::realm_coordinantor::RealmCoordinatorClient,
    psy_core_db::traits::full::{
        PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter,
        PsyRealmProcessorStore,
    },
    psy_temp_db::StandardProcessorTempDBStoreBase,
    queue::{
        ephemeral::QStandardEphemeralQueueSubscriber,
        worker_queue::QStandardWorkerQueuePublisher,
    },
    store::traits::proof_store::QParthProofStore,
};

use super::PsyRealmDatabaseProcessor;

impl<
        N: QNetworkTypesConfig,
        S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash>
            + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash>
            + Send
            + Sync,
        GUTAUpdateQueue: QStandardEphemeralQueueSubscriber,
        ProofWorkQueue: QStandardWorkerQueuePublisher,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
        ProofStore: QParthProofStore,
        FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
        CoordinatorClient: RealmCoordinatorClient<N::F, N::QHash> + Send + Sync,
    >
    PsyRealmDatabaseProcessor<
        N,
        S,
        STagTreeRewards,
        GUTAUpdateQueue,
        ProofWorkQueue,
        TempDatabase,
        ProofStore,
        FileSystem,
        CoordinatorClient,
    >
where
    N::HasherBase: 'static + Send + Sync,
{
    pub(crate) fn validate_realm_sync_context(
        &self,
        update: &PsyRealmCoordinatorUpdate<N::F, N::QHash>,
    ) -> anyhow::Result<()> {
        let expected_network = NetworkId::try_from_chain_id(self.state.chain_id)?;
        if update.canonical_chain_ref.network_id() != expected_network {
            anyhow::bail!(
                "REALM_SYNC_NETWORK_MISMATCH:expected={},actual={}",
                expected_network.chain_id(),
                update.canonical_chain_ref.network_id().chain_id()
            );
        }
        let canonical_checkpoint = update
            .canonical_chain_ref
            .checkpoint()
            .checkpoint_id()
            .get();
        if canonical_checkpoint != update.checkpoint_sync_info.checkpoint_id {
            anyhow::bail!(
                "REALM_SYNC_CANONICAL_CHECKPOINT_MISMATCH:canonical={},metadata={}",
                canonical_checkpoint,
                update.checkpoint_sync_info.checkpoint_id
            );
        }
        Ok(())
    }

    pub(crate) async fn publish_realm_authority_observation(
        &self,
        chain: CanonicalChainRef<N::QHash>,
        state_checkpoint_id: u64,
        state_root: N::QHash,
    ) -> anyhow::Result<AuthorityObservation<N::QHash>> {
        let realm_id = u32::try_from(self.state.realm_id_u64)
            .map_err(|_| anyhow::anyhow!("realm_id exceeds authority-scope u32"))?;
        let realm_sub_id = u16::try_from(self.state.realm_sub_id_u64)
            .map_err(|_| anyhow::anyhow!("realm_sub_id exceeds authority-scope u16"))?;
        let observation = AuthorityObservation::try_new(
            chain,
            AuthorityScope::Realm {
                realm_id,
                realm_sub_id,
            },
            AuthorityStateCheckpointId::new(state_checkpoint_id),
            AuthorityStateRoot::from_local_state_root(state_root),
        )?;

        self.db
            .set_realm_authority_observation(&observation)
            .await?;
        let persisted = self
            .db
            .get_realm_authority_observation()
            .await?
            .ok_or_else(|| anyhow::anyhow!("REALM_AUTHORITY_OBSERVATION_UNINITIALIZED_AFTER_WRITE"))?;
        if persisted != observation {
            anyhow::bail!("REALM_AUTHORITY_OBSERVATION_READ_AFTER_WRITE_MISMATCH");
        }
        Ok(observation)
    }

    pub(crate) async fn publish_current_pending_context(&self) -> anyhow::Result<()> {
        let observation = self
            .db
            .get_realm_authority_observation()
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "REALM_PENDING_CONTEXT_UNINITIALIZED: authority observation is missing"
                )
            })?;
        let expected_authority = AuthorityScope::Realm {
            realm_id: u32::try_from(self.state.realm_id_u64)
                .map_err(|_| anyhow::anyhow!("realm_id exceeds authority-scope u32"))?,
            realm_sub_id: u16::try_from(self.state.realm_sub_id_u64)
                .map_err(|_| anyhow::anyhow!("realm_sub_id exceeds authority-scope u16"))?,
        };
        if observation.authority() != expected_authority {
            anyhow::bail!(
                "REALM_PENDING_CONTEXT_AUTHORITY_MISMATCH: expected={expected_authority:?}, actual={:?}",
                observation.authority()
            );
        }

        let context = PendingContext::new(
            *observation.chain(),
            expected_authority,
            WorkUniquePendingId::new(self.state.processing_unique_pending_id),
            WorkProcCheckpointUniqueId::from_u128(
                self.state.processing_proc_checkpoint_unique_id,
            ),
        );
        self.temp_db
            .set_current_pending_context(&self.state.realm_identifier, &context)
            .await?;
        let persisted = self
            .temp_db
            .get_current_pending_context(&self.state.realm_identifier)
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!("REALM_PENDING_CONTEXT_UNINITIALIZED_AFTER_WRITE")
            })?;
        if persisted != context {
            anyhow::bail!("REALM_PENDING_CONTEXT_READ_AFTER_WRITE_MISMATCH");
        }
        Ok(())
    }
}
