
use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
use parth_core::{
    QCoreProcCheckpointUniqueId, QProvingJobDataIDWithRewardPath, data::{self, hash::merkle_node_key::SimpleMerkleNodeKey}, node::realm_identifier::QRealmIdentifier, protocol::core_types::QNetworkTypesConfig
};
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::{
    guta::header_extended::GlobalUserTreeAggregatorHeaderWithTagValueAndJobID,
    v1::{
        common_api::PsyProoffMinerRewardProof,
        qdata::{
            contract::{DashMapContractHeightCache, PsyDeployContractQueueItem},
            public_key::PZKPublicKeyInfo,
        },
    },
};
use psy_io::tokio::{TokioFileLike, TokioLikeFileSystem};
use psy_node_core::{
    psy_core_db::traits::full::{
        PsyCoordinatorEdgeAPIStoreReader, PsyCoordinatorProcessorStore, PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter,
    },
    psy_temp_db::{StandardEdgeAPITempDBStoreBase, StandardProcessorTempDBStoreBase},
    queue::{
        ephemeral::{QStandardEphemeralQueuePublisher, QStandardEphemeralQueueSubscriber},
        worker_queue::{QStandardWorkerQueuePublisher, QStandardWorkerQueueSubscriber},
    },
    store::traits::proof_store::QParthProofStore,
};

use crate::{
    backup::coordinator::load_coordinator_memory_trees_from_db,
    constants::queue::{
        PQ_COORDINATOR_DEPLOY_CONTRACT_QUEUE_TOPIC_ID, PQ_COORDINATOR_REGISTER_USER_PUBLIC_KEY_QUEUE_TOPIC_ID,
        PQ_COORDINATOR_SUBMIT_REALM_GUTA_UPDATE_QUEUE_TOPIC_ID,
    },
    coordinator::processor::{
        PsyCoordinatorProcessor, data::CoordinatorProcessorInitData, db::{DatabaseCheckState, PsyCoordinatorDatabaseProcessor}, gatherers::{
            coordinator_guta_update_gatherer::{
                CoordinatorGUTAUpdateGatherer, CoordinatorGUTAUpdateGathererConfig, CoordinatorGUTAUpdateGathererOutput,
            },
            deploy_contract_gatherer::{DeployContractGatherer, DeployContractGathererConfig, DeployContractGathererOutput},
            register_user_gatherer::{RegisterUserGatherer, RegisterUserGathererConfig, RegisterUserGathererOutput},
        }
    },
    queue::gatherer::EphemeralQueueGathererWithTree,
};

impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        S: PsyCoordinatorProcessorStore<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
        RegisterUserQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
        DeployContractQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
        ProofWorkQueue: QStandardWorkerQueuePublisher + Send + Sync,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
        ProofStore: QParthProofStore,
        FileSystem: TokioLikeFileSystem+ Send + Sync + 'static,
    >
    PsyCoordinatorProcessor<
        N,
        S,
        STagTreeRewards,
        GUTAUpdateQueue,
        RegisterUserQueue,
        DeployContractQueue,
        ProofWorkQueue,
        TempDatabase,
        ProofStore,
        FileSystem,
    >
{
    pub async fn ensure_backup_restored_if_necessary(
        &mut self,
    ) -> anyhow::Result<()>{

        let database_check_state = self.db.get_database_check_state().await?;
        if database_check_state == DatabaseCheckState::NeedsRecovery {
            tracing::info!("Restoring coordinator processor state from backup...");
        }


        Ok(())
    }
}