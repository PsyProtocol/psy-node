use std::sync::Arc;

use qp_core::common::compression::gzip::GZipHelper;
use qp_core::common::crypto::secp256k1::verify_secp256k1_signature;
use qp_core::common::data;
use qp_core::common::data::core::secp256k1::QPSecp256K1CompressedPublicKey;
use qp_core::common::data::protocol::core::{QPEdgeWorkerJobResponse, QPEdgeWorkerSubmitJobRequest, QPEdgeWorkerSubmitJobResponse};
use qp_core::common::data::protocol::job::QPWorkerJobDataID;
use qp_core::common::data::realm::core::{QPDataFormatType, RealmEdgeRegisterUserMessageForProcessor, RealmEdgeUpdateUserDataMessageForProcessor, RealmEdgeUserAtUniqueCheckpointKey};
use qp_core::common::data::realm::edge_api::{RealmEdgeAPIGetHistoricalUserMerkleProofRequest};
use qp_core::common::data::signature::{QPSignatureActionType, QPSignaturePreimage};
use qp_core::common::job_manager::{QPJobManagerEdge, QPRequestJobFailedReason};
use qp_core::common::traits::realm::{QPRealmEdgeCacheDatabaseClient, QPRealmEdgeRealmCoreDatabaseClient, QPRealmStoreTempSubmittedCompressedUserDataDatabaseRealmEdgeClient, QPRealmUpdateQueueClientForRealmEdge};
use qp_core::common::data::{core::merkle::merkle_proof::MerkleProofCore, realm::edge_api::{RealmEdgeAPIGetHistoricalUserDataRequest, RealmEdgeAPIGetLastFinalizedCheckpointIdResponse, RealmEdgeAPIGetLatestUserDataRequest, RealmEdgeAPIGetRealmInfoResponse, RealmEdgeAPIGetUserDataResponse, RealmEdgeAPIGetUserDataWithMerkleProofResponse, RealmEdgeAPIGetUserMerkleProofRequest, RealmEdgeAPIGetUserMerkleProofResponse, RealmEdgeAPIRegisterUserRequest, RealmEdgeAPIRegisterUserResponse, RealmEdgeAPISubmitUserDataRequest, RealmEdgeAPISubmitUserDataResponse}};
use qp_core::crypto::hash::sha256::CoreSha256Hasher;

pub const COMPRESS_JOB_MAX_TIMEOUT_MS: u64 = 15000; // 15 seconds


fn ensure_valid_signature_for_submit_update_data(update: &RealmEdgeAPISubmitUserDataRequest, real_last_updated_checkpoint_id: u64, public_key: &QPSecp256K1CompressedPublicKey) -> anyhow::Result<()> {


    if update.checkpoint_id != real_last_updated_checkpoint_id {
        anyhow::bail!("checkpoint id {} in signature does not match the latest checkpoint id {}", update.checkpoint_id, real_last_updated_checkpoint_id);
    }

    let preimage = QPSignaturePreimage{
        action_type: QPSignatureActionType::SignDataUpdate,
        user_id: update.user_id,
        checkpoint_id: update.checkpoint_id,
        new_data_hash: CoreSha256Hasher::hash_bytes(&update.data),
    };

    let computed_hash = preimage.to_signature_hash();

    if !verify_secp256k1_signature(&public_key, &computed_hash, &update.signature) {
        anyhow::bail!("invalid signature for user {}", update.user_id);
    }

    Ok(())
}
pub struct QPRealmEdgeNodeLogic<
    CacheDB: QPRealmEdgeCacheDatabaseClient,
    TSCDB: QPRealmStoreTempSubmittedCompressedUserDataDatabaseRealmEdgeClient,
    CoreDB: QPRealmEdgeRealmCoreDatabaseClient,
    UpdateQueue: QPRealmUpdateQueueClientForRealmEdge,
    JobManager: QPJobManagerEdge,

>{
    pub realm_id: u64,
    pub cache_db: Arc<CacheDB>,
    pub tsc_db: Arc<TSCDB>,
    pub core_db: Arc<CoreDB>,
    pub update_queue: Arc<UpdateQueue>,
    pub job_manager: Arc<JobManager>,
}

impl<
        CacheDB: QPRealmEdgeCacheDatabaseClient,
        TSCDB: QPRealmStoreTempSubmittedCompressedUserDataDatabaseRealmEdgeClient,
        CoreDB: QPRealmEdgeRealmCoreDatabaseClient,
        UpdateQueue: QPRealmUpdateQueueClientForRealmEdge,
        JobManager: QPJobManagerEdge
> QPRealmEdgeNodeLogic<CacheDB, TSCDB, CoreDB, UpdateQueue, JobManager>{
    pub fn new(
        realm_id: u64,
        cache_db: Arc<CacheDB>,
        tsc_db: Arc<TSCDB>,
        core_db: Arc<CoreDB>,
        update_queue: Arc<UpdateQueue>,
        job_manager: Arc<JobManager>,
    ) -> Self {
        Self {
            realm_id,
            cache_db,
            tsc_db,
            core_db,
            update_queue,
            job_manager,
        }
    }
}

impl<
        CacheDB: QPRealmEdgeCacheDatabaseClient,
        TSCDB: QPRealmStoreTempSubmittedCompressedUserDataDatabaseRealmEdgeClient,
        CoreDB: QPRealmEdgeRealmCoreDatabaseClient,
        UpdateQueue: QPRealmUpdateQueueClientForRealmEdge,
        JobManager: QPJobManagerEdge
> QPRealmEdgeNodeLogic<CacheDB, TSCDB, CoreDB, UpdateQueue, JobManager>
{
    /// Retrieves a merkle proof for a user's data leaf at a specific checkpoint in time.
    /// The proof is from the global user tree root to the user leaf.
    pub async fn get_historical_user_merkle_proof(&self, request: &RealmEdgeAPIGetHistoricalUserMerkleProofRequest) -> anyhow::Result<RealmEdgeAPIGetUserMerkleProofResponse> {


        let latest_user_data_record = self.core_db.get_finalized_user_data_record(request.user_id, request.max_checkpoint_id).await?;


        let root_merkle_proof = self.core_db.get_realm_root_to_global_user_tree_merkle_proof(latest_user_data_record.checkpoint_id).await?;
        let user_leaf_merkle_proof = self.core_db.get_user_merkle_proof_in_realm(request.user_id, latest_user_data_record.checkpoint_id).await?;

        let new_siblings = Vec::with_capacity(root_merkle_proof.siblings.len() + user_leaf_merkle_proof.siblings.len());
        let new_index = (user_leaf_merkle_proof.index << root_merkle_proof.siblings.len()) | root_merkle_proof.index;
        let full_merkle_proof = MerkleProofCore {
            index: new_index,
            siblings: new_siblings,
            root: root_merkle_proof.root,
            value: user_leaf_merkle_proof.value,
        };
        Ok(RealmEdgeAPIGetUserMerkleProofResponse {
            merkle_proof: full_merkle_proof,
        })
    }
    
    /// Retrieves the latest merkle proof for a user's data leaf.
    pub async fn get_latest_user_merkle_proof(&self, request: &RealmEdgeAPIGetUserMerkleProofRequest) -> anyhow::Result<RealmEdgeAPIGetUserMerkleProofResponse> {
        let latest_checkpoint_id = self.core_db.get_latest_global_state().await?.checkpoint_id;

        let root_merkle_proof = self.core_db.get_realm_root_to_global_user_tree_merkle_proof(latest_checkpoint_id).await?;
        let user_leaf_merkle_proof = self.core_db.get_user_merkle_proof_in_realm(request.user_id, latest_checkpoint_id).await?;

        let new_siblings = Vec::with_capacity(root_merkle_proof.siblings.len() + user_leaf_merkle_proof.siblings.len());
        let new_index = (user_leaf_merkle_proof.index << root_merkle_proof.siblings.len()) | root_merkle_proof.index;
        let full_merkle_proof = MerkleProofCore {
            index: new_index,
            siblings: new_siblings,
            root: root_merkle_proof.root,
            value: user_leaf_merkle_proof.value,
        };
        Ok(RealmEdgeAPIGetUserMerkleProofResponse {
            merkle_proof: full_merkle_proof,
        })
    }

    /// Gets the most recent checkpoint ID that has been finalized for the realm.
    pub async fn get_last_finalized_checkpoint_id(&self) -> anyhow::Result<RealmEdgeAPIGetLastFinalizedCheckpointIdResponse>{
        let latest_checkpoint_id = self.core_db.get_latest_global_state().await?.checkpoint_id;
        Ok(RealmEdgeAPIGetLastFinalizedCheckpointIdResponse {
            checkpoint_id: latest_checkpoint_id,
        })
    }
    
    /// Gets core information about the realm, including its ID, last finalized checkpoint, and root hash.
    pub async fn get_realm_info(&self) -> anyhow::Result<RealmEdgeAPIGetRealmInfoResponse>{
        let latest_checkpoint_id = self.core_db.get_latest_global_state().await?.checkpoint_id;
        let latest_checkpoint_root = self.core_db.get_realm_root_hash_at_checkpoint(latest_checkpoint_id).await?;
        
        Ok(RealmEdgeAPIGetRealmInfoResponse {
            realm_id: self.realm_id,
            checkpoint_id: latest_checkpoint_id,
            root_hash: latest_checkpoint_root,
        })
    }
    
    /// Retrieves a user's data as it existed at or before a specified checkpoint ID.
    pub async fn get_historical_user_data(&self, request: &RealmEdgeAPIGetHistoricalUserDataRequest) -> anyhow::Result<RealmEdgeAPIGetUserDataResponse>{
        let user_data_record = self.core_db.get_finalized_user_data_record(request.user_id, request.max_checkpoint_id).await?;
        let compressed_data = self.core_db.get_compressed_user_data(request.user_id, user_data_record.checkpoint_id).await?;

        let data = match request.format {
            data::realm::core::QPDataFormatType::Raw => GZipHelper::decompress_data(&compressed_data)?,
            data::realm::core::QPDataFormatType::CompressedGzip => compressed_data,
        };
        Ok(RealmEdgeAPIGetUserDataResponse {
            user_id: request.user_id,
            checkpoint_id: request.max_checkpoint_id,
            public_key: user_data_record.public_key,
            format: request.format,
            user_data_hash: user_data_record.data_hash,
            user_leaf_hash: user_data_record.get_user_leaf_hash(),
            data: data,
        })
    }
    
    /// Retrieves the latest version of a user's data.
    pub async fn get_latest_user_data(&self, user_id: u64) -> anyhow::Result<RealmEdgeAPIGetUserDataResponse>{
        let user_data_record = self.core_db.get_latest_user_data_record(user_id).await?;
        let compressed_data = self.core_db.get_compressed_user_data(user_id, user_data_record.checkpoint_id).await?;

        let data = GZipHelper::decompress_data(&compressed_data)?;
        Ok(RealmEdgeAPIGetUserDataResponse {
            user_id: user_id,
            checkpoint_id: user_data_record.checkpoint_id,
            public_key: user_data_record.public_key,
            format: QPDataFormatType::Raw,
            user_data_hash: user_data_record.data_hash,
            user_leaf_hash: user_data_record.get_user_leaf_hash(),
            data: data,
        })
    }
    
    /// Retrieves a user's data and its corresponding merkle proof for a specific historical checkpoint.
    pub async fn get_historical_user_data_with_proof(&self, request: &RealmEdgeAPIGetHistoricalUserDataRequest) -> anyhow::Result<RealmEdgeAPIGetUserDataWithMerkleProofResponse> {
        let user_data_record = self.core_db.get_finalized_user_data_record(request.user_id, request.max_checkpoint_id).await?;
        let compressed_data = self.core_db.get_compressed_user_data(request.user_id, user_data_record.checkpoint_id).await?;

        let data = match request.format {
            data::realm::core::QPDataFormatType::Raw => GZipHelper::decompress_data(&compressed_data)?,
            data::realm::core::QPDataFormatType::CompressedGzip => compressed_data,
        };

        let root_merkle_proof = self.core_db.get_realm_root_to_global_user_tree_merkle_proof(user_data_record.checkpoint_id).await?;
        let user_leaf_merkle_proof = self.core_db.get_user_merkle_proof_in_realm(request.user_id, user_data_record.checkpoint_id).await?;

        let new_siblings = Vec::with_capacity(root_merkle_proof.siblings.len() + user_leaf_merkle_proof.siblings.len());
        let new_index = (user_leaf_merkle_proof.index << root_merkle_proof.siblings.len()) | root_merkle_proof.index;
        let full_merkle_proof = MerkleProofCore {
            index: new_index,
            siblings: new_siblings,
            root: root_merkle_proof.root,
            value: user_leaf_merkle_proof.value,
        };

        Ok(RealmEdgeAPIGetUserDataWithMerkleProofResponse {
            user_id: request.user_id,
            checkpoint_id: request.max_checkpoint_id,
            public_key: user_data_record.public_key,
            format: request.format,
            user_data_hash: user_data_record.data_hash,
            user_leaf_hash: user_data_record.get_user_leaf_hash(),
            data: data,
            merkle_proof: full_merkle_proof,
        })
    }

    /// Retrieves the latest version of a user's data along with its corresponding merkle proof.
    pub async fn get_latest_user_data_with_proof(&self, request: &RealmEdgeAPIGetLatestUserDataRequest) -> anyhow::Result<RealmEdgeAPIGetUserDataWithMerkleProofResponse> {
        let user_data_record = self.core_db.get_latest_user_data_record(request.user_id).await?;
        let compressed_data = self.core_db.get_compressed_user_data(request.user_id, user_data_record.checkpoint_id).await?;

        let data = match request.format {
            QPDataFormatType::Raw => GZipHelper::decompress_data(&compressed_data)?,
            QPDataFormatType::CompressedGzip => compressed_data,
        };

        let latest_checkpoint_id = self.core_db.get_latest_global_state().await?.checkpoint_id;
        let root_merkle_proof = self.core_db.get_realm_root_to_global_user_tree_merkle_proof(latest_checkpoint_id).await?;
        let user_leaf_merkle_proof = self.core_db.get_user_merkle_proof_in_realm(request.user_id, latest_checkpoint_id).await?;

        let new_siblings = Vec::with_capacity(root_merkle_proof.siblings.len() + user_leaf_merkle_proof.siblings.len());
        let new_index = (user_leaf_merkle_proof.index << root_merkle_proof.siblings.len()) | root_merkle_proof.index;
        let full_merkle_proof = MerkleProofCore {
            index: new_index,
            siblings: new_siblings,
            root: root_merkle_proof.root,
            value: user_leaf_merkle_proof.value,
        };

        Ok(RealmEdgeAPIGetUserDataWithMerkleProofResponse {
            user_id: request.user_id,
            checkpoint_id: user_data_record.checkpoint_id,
            public_key: user_data_record.public_key,
            format: request.format,
            user_data_hash: user_data_record.data_hash,
            user_leaf_hash: user_data_record.get_user_leaf_hash(),
            data: data,
            merkle_proof: full_merkle_proof,
        })
    }

    /// Submits new data for an existing user. The data must be signed by the user's registered key.
    pub async fn submit_user_data(&self, request: &RealmEdgeAPISubmitUserDataRequest) -> anyhow::Result<RealmEdgeAPISubmitUserDataResponse> {
        if request.data.len() > 10 * 1024 * 1024 || request.data.len() == 0 {
            anyhow::bail!("data size {} exceeds maximum allowed size of 10 MB", request.data.len());
        }
        let latest_unique_checkpoint_id = self.core_db.get_current_unique_checkpoint_id().await?;

        let unique_user_checkpoint_id = RealmEdgeUserAtUniqueCheckpointKey{
            unique_checkpoint_id: latest_unique_checkpoint_id,
            user_id: request.user_id,
        };
        let submission_marker = self.cache_db.get_user_submission_marker(&unique_user_checkpoint_id).await?;
        if submission_marker != 0 {
            anyhow::bail!("user {} has already submitted data for the current checkpoint", request.user_id);
        }
        

        let random_marker = rand::random::<u64>();
        self.cache_db.put_user_submission_marker(&unique_user_checkpoint_id, random_marker).await?;

        let user_latest = self.core_db.get_latest_user_data_record(request.user_id).await?;
        if user_latest.checkpoint_id != request.checkpoint_id {
            anyhow::bail!("user {} last updated checkpoint id {} does not match the checkpoint id {} in the signature", request.user_id, user_latest.checkpoint_id, request.checkpoint_id);
        }
        ensure_valid_signature_for_submit_update_data(request, user_latest.checkpoint_id, &user_latest.public_key)?;


        let job_id = QPWorkerJobDataID::compress_gzip_job_input(unique_user_checkpoint_id.unique_checkpoint_id.checkpoint_id, self.realm_id as u32, rand::random::<u32>(), request.user_id as u32);
        self.cache_db.put_raw_user_data_for_job_id(job_id.get_input_witness_id(), &request.data).await?;

        
        let current_random_marker_race = self.cache_db.get_user_submission_marker(&unique_user_checkpoint_id).await?;
        if current_random_marker_race != random_marker {
            anyhow::bail!("user {} submission errored due to a race condition, please try again", request.user_id);
        }
        self.update_queue.enqueue_update_user_data_message_for_processor(unique_user_checkpoint_id.unique_checkpoint_id, &RealmEdgeUpdateUserDataMessageForProcessor { 
            user_id: request.user_id,
            job_id,
            public_key: user_latest.public_key,
        }).await?;
        Ok(RealmEdgeAPISubmitUserDataResponse {
            has_error: false,
        })

    }
    
    /// Registers a new user with the realm, setting their public key and initial data.
    /// This will fail if the user ID is already taken.
    pub async fn register_user(&self, request: &RealmEdgeAPIRegisterUserRequest) -> anyhow::Result<RealmEdgeAPIRegisterUserResponse>{
        if request.initial_data.len() > 10 * 1024 * 1024 || request.initial_data.len() == 0 {
            anyhow::bail!("data size {} exceeds maximum allowed size of 10 MB", request.initial_data.len());
        }
       
        let latest_unique_checkpoint_id = self.core_db.get_current_unique_checkpoint_id().await?;

        let unique_user_checkpoint_id = RealmEdgeUserAtUniqueCheckpointKey{
            unique_checkpoint_id: latest_unique_checkpoint_id,
            user_id: request.user_id,
        };
        let existing_user = self.core_db.user_exists(request.user_id).await?;
        if existing_user {
            anyhow::bail!("user id {} is already registered", request.user_id);
        }
        let submission_marker = self.cache_db.get_user_submission_marker(&unique_user_checkpoint_id).await?;
        if submission_marker != 0 {
            anyhow::bail!("user {} has already submitted data for the current checkpoint", request.user_id);
        }
        let random_marker = rand::random::<u64>();
        self.cache_db.put_user_submission_marker(&unique_user_checkpoint_id, random_marker).await?;
        let job_id = QPWorkerJobDataID::compress_gzip_job_input(unique_user_checkpoint_id.unique_checkpoint_id.checkpoint_id, self.realm_id as u32, rand::random::<u32>(), request.user_id as u32);
        self.cache_db.put_raw_user_data_for_job_id(job_id.get_input_witness_id(), &request.initial_data).await?;


        let current_random_marker = self.cache_db.get_user_submission_marker(&unique_user_checkpoint_id).await?;
        if current_random_marker != random_marker {
            anyhow::bail!("user {} submission errored due to a race condition, please try again", request.user_id);
        }

        let existing_user = self.core_db.user_exists(request.user_id).await?;
        if existing_user {
            anyhow::bail!("user id {} is already registered", request.user_id);
        }
        self.update_queue.enqueue_register_user_message_for_processor(
            unique_user_checkpoint_id.unique_checkpoint_id, 
            &RealmEdgeRegisterUserMessageForProcessor 
            {
                user_id: request.user_id,
                job_id: job_id,
                public_key: request.public_key,
            }).await?;
        Ok(RealmEdgeAPIRegisterUserResponse {
            has_error: false,
        })

    }


    pub async fn request_proving_job_for_worker(&self, worker_id: u64) -> anyhow::Result<QPEdgeWorkerJobResponse>{
        let job_response = self.job_manager.request_job_id_for_worker_id(worker_id, COMPRESS_JOB_MAX_TIMEOUT_MS).await?;
        let wip_checkpoint_id = self.core_db.get_work_in_progress_checkpoint_id().await?;
        if job_response.failed_reason != QPRequestJobFailedReason::Success {
            //anyhow::bail!("failed to get job for worker id {}, reason: {}", worker_id, job_response.failed_reason);
            tracing::error!("failed to get job for worker id {}, reason: {}", worker_id, job_response.failed_reason);
            Ok(QPEdgeWorkerJobResponse {
                job_response,
                wip_checkpoint_id,
                data: Vec::new(),
            })
        }else{
            let raw_data = self.cache_db.get_raw_user_data_for_job_id(job_response.job_id.get_input_witness_id()).await?;
            Ok(QPEdgeWorkerJobResponse {
                job_response,
                wip_checkpoint_id,
                data: raw_data,
            })
        }

    }

    /// Reports the result of work performed by a worker node (the compressed user data).
    pub async fn submit_completed_job(&self, request: &QPEdgeWorkerSubmitJobRequest) -> anyhow::Result<QPEdgeWorkerSubmitJobResponse>{
        
        let current_wip_checkpoint_id = self.core_db.get_work_in_progress_checkpoint_id().await?;
        if current_wip_checkpoint_id != request.wip_checkpoint_id {
            //anyhow::bail!("the work in progress checkpoint id {} in the request does not match the current work in progress checkpoint id {}", request.wip_checkpoint_id, current_wip_checkpoint_id);
            return Ok(QPEdgeWorkerSubmitJobResponse {
                has_error: true,
                error_message: format!("the work in progress checkpoint id {} in the request does not match the current work in progress checkpoint id {}", request.wip_checkpoint_id, current_wip_checkpoint_id),
            });
        }
        if request.data.len() > 10 * 1024 * 1024 || request.data.len() == 0 {
            //anyhow::bail!("compressed data size {} exceeds maximum allowed size of 10 MB", request.data.len());
            return Ok(QPEdgeWorkerSubmitJobResponse {
                has_error: true,
                error_message: format!("compressed data size {} exceeds maximum allowed size of 10 MB", request.data.len()),
            });
        }

        self.tsc_db.put_compressed_data_from_worker(request.job_id.get_output_id(), &request.data).await?;
        self.tsc_db.increment_submitted_jobs_counter(current_wip_checkpoint_id).await?;
        self.job_manager.submit_job_result(request.worker_id, request.job_id.get_output_id()).await?;
        Ok(QPEdgeWorkerSubmitJobResponse { has_error: false, error_message: "ok".to_string() })
    }
}
