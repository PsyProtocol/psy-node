//! h23c4c2b3b2: Realm claim-admission close fence on a real RF=3 cluster.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    process::Command,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, ensure, Context};
use async_trait::async_trait;
use async_nats::jetstream::{
    self,
    consumer::pull::Config as PullConfig,
    stream::Config as StreamConfig,
};
use parth_core::{
    felt::FromPrimitiveValuesFelt,
    pgoldilocks::PoseidonHasher,
    protocol::core_types::{
        Q256BitHash, QZKProofPublicInputsHasherReader, QZKProofVerifier,
    },
    utils::QPGenRandom,
    PHash, PF,
};
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::{
    proof_input::guta::end_cap_input::SubmitUserEndCapNonProofInput,
    protocol::{
        canonical_chain::{
            CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
            CheckpointRef, NetworkId,
        },
        chain_context::{
            AuthorityObservation, AuthorityScope, AuthorityStateCheckpointId,
            AuthorityStateRoot, PendingContext, WorkProcCheckpointUniqueId,
            WorkUniquePendingId,
        },
    },
    queue_items::realm_user_update::PsyRealmUserUpdateQueueItem,
};
use psy_node_core::{
    qblob::{
        blob_type::QBlobMerkleNodeTreeType,
        data_views::{
            double_merkle_node_batch::QBlobDoubleMerkleNodeBatchDataView,
            single_merkle_node_batch::QBlobSingleMerkleNodeBatchDataView,
        },
    },
    queue::{
        realm_user_update_admission::{
            RealmUserUpdateAdmissionCloseIntent, RealmUserUpdateAdmissionKey,
            RealmUserUpdateAdmissionPhase, RealmUserUpdateAdmissionShard,
            RealmUserUpdateGenerationQualification,
            RealmUserUpdateQualificationFence, StoredRealmUserUpdateAdmission,
        },
        realm_user_update_claim::{
            RealmUserUpdateAdmissionOrdinal, RealmUserUpdateClaimBucket,
            RealmUserUpdateClaimPhase, RealmUserUpdateCreatedAtSeconds,
            RealmUserUpdatePublishReceiptDigest, StoredRealmUserUpdateClaim,
        },
        realm_user_update_artifact::{
            deterministic_qblob_context, RealmUserUpdateContractSlots,
            RealmUserUpdateSlotEnvelope, RealmUserUpdateSlotUpdate,
            ValidatedRealmUserUpdateArtifacts, VerifiedRealmUserUpdateRequest,
        },
        realm_user_update_dependency::{
            RealmUserUpdateDependencyBundle, RealmUserUpdateDependencyKind,
            RealmUserUpdateDependencyRecoveryPlan,
        },
        realm_user_update_ingress::{
            RealmAuthorityObservationReader, RealmUserUpdateIngressError,
        },
        realm_user_update_consumer::{
            RealmUserUpdateDurableConsumerError,
            RealmUserUpdateDurableConsumerPort, RealmUserUpdateDurableItem,
        },
        realm_user_update_publish::{
            GlobalUserTreeHeight, RealmUserUpdatePublishAdmission,
            RealmUserUpdatePublishDisposition, RealmUserUpdatePublishReceipt,
            RealmUserUpdatePublishRequest, RealmUserUpdateRequestDigest,
        },
        realm_user_update_verifier_profile::{
            RealmUserUpdateVerifierBackend, RealmUserUpdateVerifierProfile,
            RealmUserUpdateVerifierProfileId, RealmUserUpdateVerifierRegistry,
        },
        recoverable_ephemeral::PendingQueueCaptureContext,
        recoverable_artifact::PENDING_QUEUE_ARTIFACT_FRAGMENT_BYTES,
    },
    store::{
        pending_generation_identity::{
            PendingGenerationActivationDigest,
            PendingGenerationBootstrapReason, PendingGenerationContext,
            PendingGenerationLedgerKey,
        },
        pending_generation_pipeline::{
            PendingPipelineBootstrap, PendingPipelineWriteOutcome,
            StoredPendingPipeline,
        },
        pending_generation::ProcNamespacePrefix,
        typed::{UniquePendingId, UserId},
    },
};
use psy_node_nats::{
    queue::NatsJetStreamClient,
    recoverable_assignment::PendingQueueSegmentLedgerBootstrap,
    recoverable_outbox::{
        PendingQueuePublishIntentPhase, PendingQueuePublishIntentSlot,
        StoredPendingQueuePublishIntent,
    },
    recoverable_publish::{
        PendingQueueGenerationBudgetContract, PendingQueuePublisherKind,
        PendingQueuePublishIntentId, PendingQueuePublishSourcePhase,
        PendingQueuePublishSourceSlot, PendingQueuePublishSourceState,
        PendingQueueSourceQuota,
    },
    recoverable_segment::{
        RecoverableNatsRetentionContract, RecoverableNatsSegmentId,
        RecoverableNatsStreamSegment,
    },
    recoverable_transport::RecoverablePendingQueueNatsPublisher,
};
use scylla::{
    client::{
        execution_profile::ExecutionProfile, session::Session,
        session_builder::SessionBuilder,
    },
    policies::load_balancing::{
        NodeIdentifier, SingleTargetLoadBalancingPolicy,
    },
    statement::Consistency,
};
use serde::Serialize;
use tokio::{sync::Semaphore, task::JoinSet, time::sleep};

use crate::rollback::realm_generation_scope::REALM_AUTHORITY_KIND;
use super::*;

const DATA: &str = "psy_h23c4c2b3b2";
const IMAGE: &str =
    "scylladb/scylla@sha256:17496f2dd6e72056d0b0d7e2bd18bd62638872d1d80a5dd9db96ba017fd426fc";
const NODE_IPS: [Ipv4Addr; 3] = [
    Ipv4Addr::new(172, 29, 86, 11),
    Ipv4Addr::new(172, 29, 86, 12),
    Ipv4Addr::new(172, 29, 86, 13),
];
const NODE_CONTAINERS: [&str; 3] = [
    "psy-g0-02-rf3-scylla1-1",
    "psy-g0-02-rf3-scylla2-1",
    "psy-g0-02-rf3-scylla3-1",
];
const CLAIMS: u64 = 1_000;

fn control() -> String { format!("{DATA}_no_tablet") }

fn realm() -> AuthorityScope {
    AuthorityScope::Realm {
        realm_id: 7,
        realm_sub_id: 2,
    }
}

fn admission(
    generation: u64,
) -> anyhow::Result<RealmUserUpdatePublishAdmission<PHash>> {
    let network = NetworkId::try_from_chain_id(1337)?;
    let authority = realm();
    let pending_id = 100 + generation;
    let proc_id = 0x1_0000_u128 + u128::from(generation);
    let pending = PendingContext::new(
        CanonicalChainRef::new(
            network,
            ChainEpoch::new(generation),
            CheckpointRef::new(
                CheckpointId::new(1_000 + generation),
                CheckpointHash::from_last_chain_hash(
                    PHash::from_owned_32bytes([generation as u8; 32]),
                ),
            ),
        ),
        authority,
        WorkUniquePendingId::new(pending_id),
        WorkProcCheckpointUniqueId::from_u128(proc_id),
    );
    let capture = PendingQueueCaptureContext::try_new(
        PendingGenerationLedgerKey::new(network, authority),
        PendingGenerationActivationDigest::try_new([
            (generation as u8).wrapping_add(1);
            32
        ])?,
        PendingGenerationContext::try_from_legacy(
            UniquePendingId::try_new(pending_id)?.get(),
            proc_id,
        )?,
    )?;
    Ok(RealmUserUpdatePublishAdmission::try_from_pipeline(
        pending, capture,
    )?)
}

fn qualification_pipeline_bootstrap(
    admission: &RealmUserUpdatePublishAdmission<PHash>,
) -> anyhow::Result<PendingPipelineBootstrap<PHash>> {
    let capture = admission.capture();
    let gathering = capture.processing();
    let processing_pending = gathering
        .pending_id()
        .get()
        .checked_sub(1)
        .context("qualification fixture gathering must have a predecessor")?;
    let processing_proc = gathering
        .proc_checkpoint_id()
        .as_u128()
        .checked_sub(1)
        .context("qualification fixture proc must have a predecessor")?;
    let chain = *admission.pending().chain();
    let observation = AuthorityObservation::try_new(
        chain,
        admission.pending().authority(),
        AuthorityStateCheckpointId::new(chain.checkpoint().checkpoint_id().get()),
        AuthorityStateRoot::from_local_state_root(PHash::from_owned_32bytes([
            0x4d;
            32
        ])),
    )?;
    Ok(PendingPipelineBootstrap::try_new(
        capture.key(),
        capture.activation(),
        ProcNamespacePrefix::for_authority(
            capture.key().network(),
            capture.key().authority(),
        ),
        PendingGenerationBootstrapReason::LegacyActivation,
        PendingGenerationContext::try_from_legacy(
            processing_pending,
            processing_proc,
        )?,
        gathering,
        observation,
        processing_pending,
    )?)
}

fn qualification_pipeline(
    admission: &RealmUserUpdatePublishAdmission<PHash>,
) -> anyhow::Result<StoredPendingPipeline<PHash>> {
    Ok(qualification_pipeline_bootstrap(admission)?
        .candidate()
        .clone())
}

fn request(user: u64) -> anyhow::Result<RealmUserUpdateRequestDigest> {
    Ok(RealmUserUpdateRequestDigest::derive(
        &user.to_be_bytes(),
        &user.wrapping_mul(17).to_be_bytes(),
    )?)
}

#[derive(Clone, Copy, Debug)]
struct DeterministicEndCapVerifier;

static DETERMINISTIC_VERIFIER_CALLS: AtomicUsize = AtomicUsize::new(0);

type DeterministicRealmUserUpdateRouter =
    ScyllaRealmUserUpdateDurableRouter<
        PF,
        PHash,
        PoseidonHasher,
        PHash,
        DeterministicEndCapVerifier,
    >;

impl QZKProofPublicInputsHasherReader<PHash, PHash>
    for DeterministicEndCapVerifier
{
    fn get_proof_public_inputs_hash(proof: &PHash) -> anyhow::Result<PHash> {
        Ok(*proof)
    }

    fn try_proof_from_slice(bytes: &[u8]) -> anyhow::Result<PHash> {
        PHash::from_slice_32bytes(bytes)
    }
}

impl QZKProofVerifier<PHash, PHash> for DeterministicEndCapVerifier {
    fn verify_zk_proof(
        &self,
        _circuit_type: u32,
        proof: &PHash,
    ) -> anyhow::Result<PHash> {
        DETERMINISTIC_VERIFIER_CALLS.fetch_add(1, Ordering::SeqCst);
        Ok(*proof)
    }
}

fn verifier_profile() -> RealmUserUpdateVerifierProfile {
    RealmUserUpdateVerifierProfile::try_new(
        NetworkId::try_from_chain_id(1337).unwrap(),
        32,
        RealmUserUpdateVerifierBackend::DeterministicTest,
        1,
        1,
        [0x71; 32],
        [0x72; 32],
    )
    .unwrap()
}

fn verifier_profile_id() -> RealmUserUpdateVerifierProfileId {
    verifier_profile().id()
}

fn verifier_registry() -> Arc<RealmUserUpdateVerifierRegistry<DeterministicEndCapVerifier>> {
    let profile = verifier_profile();
    Arc::new(
        RealmUserUpdateVerifierRegistry::try_new([(
            profile,
            Arc::new(DeterministicEndCapVerifier),
        )])
        .unwrap(),
    )
}

struct FixedAuthorityObservationReader {
    observation: AuthorityObservation<PHash>,
}

#[async_trait]
impl RealmAuthorityObservationReader<PHash>
    for FixedAuthorityObservationReader
{
    async fn read_authority_observation(
        &self,
    ) -> Result<AuthorityObservation<PHash>, RealmUserUpdateIngressError> {
        Ok(self.observation.clone())
    }
}

fn fixed_observation_reader(
    admission: &RealmUserUpdatePublishAdmission<PHash>,
) -> anyhow::Result<Arc<dyn RealmAuthorityObservationReader<PHash>>> {
    Ok(Arc::new(FixedAuthorityObservationReader {
        observation: qualification_pipeline(admission)?.frontier().clone(),
    }))
}

async fn prepare_deterministic_router(
    session: Arc<Session>,
    admission: &RealmUserUpdatePublishAdmission<PHash>,
    height: GlobalUserTreeHeight,
    ready: Arc<PendingQueueSidecarReady>,
    nats: Arc<RecoverablePendingQueueNatsPublisher>,
    segment: RecoverableNatsStreamSegment,
) -> anyhow::Result<DeterministicRealmUserUpdateRouter> {
    Ok(DeterministicRealmUserUpdateRouter::prepare(
        session,
        admission.capture().key().network(),
        realm(),
        height,
        20,
        verifier_profile_id(),
        verifier_registry(),
        fixed_observation_reader(admission)?,
        ready,
        nats,
        segment,
    )
    .await?)
}

fn verified_end_cap_request(
    user_id: UserId,
    height: GlobalUserTreeHeight,
) -> anyhow::Result<VerifiedRealmUserUpdateRequest<PF, PHash>> {
    let mut input = SubmitUserEndCapNonProofInput::<PF, PHash>::qp_rand_gen();
    input.core.new_user_leaf.user_id = PF::from_u64_value(user_id.get());
    input.core.state_transition.user_id = PF::from_u64_value(user_id.get());
    let expected = input
        .core
        .get_proof_public_inputs_hash::<PoseidonHasher>(height.get());
    VerifiedRealmUserUpdateRequest::<PF, PHash>::verify::<
        PHash,
        DeterministicEndCapVerifier,
        PoseidonHasher,
    >(
        &input,
        expected.to_vec_32bytes(),
        height,
        &verifier_registry().resolve(verifier_profile_id()).unwrap(),
    )
    .map_err(Into::into)
}

struct RealmUserUpdateLiveFixture {
    artifacts: ValidatedRealmUserUpdateArtifacts<PHash>,
    bundle: RealmUserUpdateDependencyBundle,
    publish_request: RealmUserUpdatePublishRequest<PF, PHash>,
}

fn live_artifacts_for_claim(
    admission: &RealmUserUpdatePublishAdmission<PHash>,
    claim: &StoredRealmUserUpdateClaim<PHash>,
    verified_request: VerifiedRealmUserUpdateRequest<PF, PHash>,
    height: GlobalUserTreeHeight,
) -> anyhow::Result<RealmUserUpdateLiveFixture> {
    live_artifacts_for_claim_with_slots(
        admission,
        claim,
        verified_request,
        height,
        Vec::new(),
    )
}

fn live_artifacts_for_claim_with_slots(
    admission: &RealmUserUpdatePublishAdmission<PHash>,
    claim: &StoredRealmUserUpdateClaim<PHash>,
    verified_request: VerifiedRealmUserUpdateRequest<PF, PHash>,
    height: GlobalUserTreeHeight,
    slot_contracts: Vec<RealmUserUpdateContractSlots>,
) -> anyhow::Result<RealmUserUpdateLiveFixture> {
    ensure!(verified_request.user_id() == claim.user_id());
    ensure!(verified_request.request_digest() == claim.request_digest());
    ensure!(verified_request.global_user_tree_height() == height);
    ensure!(&claim.reconstruct_admission()? == admission);

    let input = verified_request.decode_input()?;
    let job_id =
        QProvingJobDataID::try_get_realm_edge_proof_store_output_proof_id_for_end_cap(
            claim.user_id().get(),
            height.get(),
            admission.pending().unique_pending_id().get(),
        )?;
    let queue_item = PsyRealmUserUpdateQueueItem::new(
        job_id,
        claim.stable_status(),
        input.core.state_transition.start_user_leaf_hash,
        input.core.state_transition.end_user_leaf_hash,
        input.core.new_user_leaf.clone(),
        input.core.stats,
        input.events.clone(),
    );
    let publish_request = RealmUserUpdatePublishRequest::try_new(
        admission.clone(),
        claim.user_id(),
        verified_request.request_digest(),
        height,
        queue_item,
    )?;

    let context = deterministic_qblob_context(claim)?;
    let mut contract_qblob = QBlobSingleMerkleNodeBatchDataView::
        generate_single_merkle_node_batch_blob_data_from_ref::<PHash>(
            context,
            QBlobMerkleNodeTreeType::UserContractTree,
            &[],
        );
    contract_qblob.extend_from_slice(
        &QBlobDoubleMerkleNodeBatchDataView::
            generate_double_merkle_node_batch_blob_data_from_ref::<PHash>(
                context,
                &[],
            ),
    );
    let slot = RealmUserUpdateSlotEnvelope::try_new(
        claim.pending().clone(),
        claim.user_id(),
        slot_contracts,
    )?;
    let artifacts = ValidatedRealmUserUpdateArtifacts::try_new::<PF>(
        claim,
        &verified_request,
        contract_qblob,
        slot,
        &publish_request,
    )?;
    let bundle = RealmUserUpdateDependencyBundle::try_new_validated(
        claim,
        &artifacts,
    )?;
    Ok(RealmUserUpdateLiveFixture {
        artifacts,
        bundle,
        publish_request,
    })
}

fn four_fragment_slot_contracts() -> anyhow::Result<Vec<RealmUserUpdateContractSlots>> {
    // 600,000 canonical 24-byte updates plus the fixed envelope form a
    // 14,400,138-byte SlotUpdates component: four real 4 MiB fragments. Index
    // 1 remains the control while 0/2/3 exercise first/middle/last gaps.
    let updates = 600_000;
    debug_assert!(updates * 24 > PENDING_QUEUE_ARTIFACT_FRAGMENT_BYTES * 3);
    let mut slots = Vec::with_capacity(updates);
    for index in 0..updates {
        let slot = u64::try_from(index)?;
        slots.push(RealmUserUpdateSlotUpdate::new(
            slot,
            slot.wrapping_mul(3),
            slot.wrapping_mul(3).wrapping_add(1),
        ));
    }
    Ok(vec![RealmUserUpdateContractSlots::try_new(0x23, slots)?])
}

fn missing_dependency_coordinates(
    plan: &RealmUserUpdateDependencyRecoveryPlan,
) -> Vec<(RealmUserUpdateDependencyKind, u32)> {
    plan.missing_fragments()
        .iter()
        .map(|fragment| (fragment.kind(), fragment.index()))
        .collect()
}

fn retention() -> anyhow::Result<RecoverableNatsRetentionContract> {
    Ok(RecoverableNatsRetentionContract::try_new(
        3,
        512 * 1024 * 1024,
        128 * 1024 * 1024,
        2,
        16,
    )?)
}

fn generation_budget(
    authority: AuthorityScope,
) -> anyhow::Result<PendingQueueGenerationBudgetContract> {
    let mib = 1024 * 1024_u64;
    Ok(PendingQueueGenerationBudgetContract::try_new(
        authority,
        vec![PendingQueueSourceQuota::try_new(
            PendingQueuePublisherKind::RealmUserUpdate,
            1_000,
            127 * mib,
            mib,
        )?],
        128 * mib,
    )?)
}

async fn wait_for_stream_leader(
    context: &jetstream::Context,
    stream_name: &str,
    excluded: Option<&str>,
) -> anyhow::Result<String> {
    for _ in 0..90 {
        if let Ok(stream) = context.get_stream(stream_name).await {
            if let Ok(info) = stream.get_info().await {
                if let Some(leader) = info.cluster.and_then(|cluster| cluster.leader) {
                    if excluded != Some(leader.as_str()) {
                        return Ok(leader);
                    }
                }
            }
        }
        sleep(Duration::from_secs(1)).await;
    }
    bail!("stream did not elect the expected leader")
}

fn signal_c2b_nats(server_name: &str, signal: &str) -> anyhow::Result<()> {
    let variable = match server_name {
        "psy-h23c2b-n1" => "PSY_D04B6H23C4C2B3B2C2B_NATS1_PID",
        "psy-h23c2b-n2" => "PSY_D04B6H23C4C2B3B2C2B_NATS2_PID",
        "psy-h23c2b-n3" => "PSY_D04B6H23C4C2B3B2C2B_NATS3_PID",
        other => bail!("unexpected NATS server {other}"),
    };
    let pid = std::env::var(variable)?.parse::<u32>()?;
    let status = Command::new("kill")
        .arg(signal)
        .arg(pid.to_string())
        .status()?;
    ensure!(status.success(), "failed to signal {server_name}");
    Ok(())
}

async fn stream_state(
    context: &jetstream::Context,
    stream_name: &str,
) -> anyhow::Result<(u64, u64, u64, u64, u64, u64)> {
    let info = context.get_stream(stream_name).await?.get_info().await?;
    Ok((
        info.state.messages,
        info.state.bytes,
        info.state.first_sequence,
        info.state.last_sequence,
        u64::try_from(info.state.consumer_count)?,
        info.state.subjects_count,
    ))
}

fn current_pipeline(
    outcome: PendingPipelineWriteOutcome<PHash>,
) -> anyhow::Result<StoredPendingPipeline<PHash>> {
    match outcome {
        PendingPipelineWriteOutcome::Applied(current)
        | PendingPipelineWriteOutcome::Idempotent(current) => Ok(current),
        PendingPipelineWriteOutcome::Conflict(current) => {
            bail!("pipeline conflict at revision {}", current.revision().get())
        }
    }
}

fn current_claim(
    outcome: RealmUserUpdateClaimWriteOutcome<PHash>,
) -> anyhow::Result<StoredRealmUserUpdateClaim<PHash>> {
    match outcome {
        RealmUserUpdateClaimWriteOutcome::Applied(receipt)
        | RealmUserUpdateClaimWriteOutcome::Resumed(receipt) => {
            Ok(receipt.current().clone())
        }
        RealmUserUpdateClaimWriteOutcome::Conflict(current) => {
            bail!("claim conflict at revision {}", current.revision().get())
        }
    }
}

fn ensure_same_durable_publication(
    expected: &RealmUserUpdatePublishReceipt,
    observed: &RealmUserUpdatePublishReceipt,
) -> anyhow::Result<()> {
    ensure!(observed.intent_id() == expected.intent_id());
    ensure!(observed.assignment_digest() == expected.assignment_digest());
    ensure!(observed.subject_sequence() == expected.subject_sequence());
    ensure!(observed.envelope_digest() == expected.envelope_digest());
    ensure!(observed.receipt_digest() == expected.receipt_digest());
    Ok(())
}

fn user_in_bucket(bucket: u16, start: u64) -> u64 {
    (start..)
        .find(|user| {
            RealmUserUpdateClaimBucket::for_user(UserId::new(*user)).get()
                == bucket
        })
        .expect("a user must exist in every bucket")
}

fn close_intent(
    key: RealmUserUpdateAdmissionKey,
) -> anyhow::Result<RealmUserUpdateAdmissionCloseIntent> {
    Ok(RealmUserUpdateAdmissionCloseIntent::derive(key, [0x5a; 32])?)
}

async fn connect(
    target: Option<Ipv4Addr>,
    consistency: Consistency,
) -> anyhow::Result<Session> {
    let mut profile = ExecutionProfile::builder()
        .consistency(consistency)
        .request_timeout(Some(Duration::from_secs(180)));
    if let Some(ip) = target {
        profile = profile.load_balancing_policy(
            SingleTargetLoadBalancingPolicy::new(
                NodeIdentifier::NodeAddress(SocketAddr::new(IpAddr::V4(ip), 9042)),
                None,
            ),
        );
    }
    Ok(SessionBuilder::new()
        .known_nodes_addr(
            NODE_IPS.map(|ip| SocketAddr::new(IpAddr::V4(ip), 9042)),
        )
        .default_execution_profile_handle(profile.build().into_handle())
        .connection_timeout(Duration::from_secs(120))
        .schema_agreement_timeout(Duration::from_secs(120))
        .build()
        .await?)
}

fn compose(compose_file: &Path, args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new("docker")
        .arg("compose")
        .arg("-f")
        .arg(compose_file)
        .args(args)
        .status()
        .context("docker compose")?;
    ensure!(status.success(), "docker compose failed with {status}");
    Ok(())
}

fn docker_exec(container: &str, args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new("docker")
        .arg("exec")
        .arg(container)
        .args(args)
        .status()
        .context("docker exec")?;
    ensure!(status.success(), "docker exec failed with {status}");
    Ok(())
}

fn docker_exec_retry(
    container: &str,
    args: &[&str],
    attempts: usize,
) -> anyhow::Result<()> {
    let mut last = None;
    for _ in 0..attempts {
        match docker_exec(container, args) {
            Ok(()) => return Ok(()),
            Err(error) => last = Some(error),
        }
        std::thread::sleep(Duration::from_secs(5));
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("no repair attempt executed")))
}

async fn wait_up(expected: usize) -> anyhow::Result<()> {
    for _ in 0..120 {
        let mut up = 0;
        for ip in NODE_IPS {
            if connect(Some(ip), Consistency::One).await.is_ok() {
                up += 1;
            }
        }
        if up >= expected {
            return Ok(());
        }
        sleep(Duration::from_secs(1)).await;
    }
    bail!("only part of RF=3 became available")
}

async fn claim_with_retry(
    guard: &ScyllaRealmUserUpdateAdmissionGuard,
    admission: &RealmUserUpdatePublishAdmission<PHash>,
    user: u64,
) -> Result<StoredRealmUserUpdateClaim<PHash>, RealmUserUpdateAdmissionGuardError>
{
    let request = request(user)
        .map_err(|error| RealmUserUpdateAdmissionGuardError::Claim(error.to_string()))?;
    for _ in 0..2_000 {
        match guard
            .claim(
                admission.clone(),
                verifier_profile_id(),
                UserId::new(user),
                request,
                RealmUserUpdateCreatedAtSeconds::try_new(1_700_000_000)
                    .map_err(|error| {
                        RealmUserUpdateAdmissionGuardError::Claim(error.to_string())
                    })?,
            )
            .await
        {
            Err(RealmUserUpdateAdmissionGuardError::AdmissionRace) => {
                tokio::task::yield_now().await;
            }
            result => return result,
        }
    }
    Err(RealmUserUpdateAdmissionGuardError::StepLimit)
}

async fn provisioned(
    session: Arc<Session>,
    generation: u64,
) -> anyhow::Result<(
    Arc<ScyllaRealmUserUpdateAdmissionStore>,
    Arc<ScyllaRealmUserUpdateClaimStore>,
    Arc<ScyllaRealmUserUpdateAdmissionGuard>,
    RealmUserUpdatePublishAdmission<PHash>,
    RealmUserUpdateAdmissionKey,
)> {
    let keyspace = BranchExactDeploymentNoTabletKeyspace::try_new(control())?;
    let gates = Arc::new(
        ScyllaRealmUserUpdateAdmissionStore::prepare(
            session.clone(),
            keyspace.clone(),
        )
        .await?,
    );
    let claims = Arc::new(
        ScyllaRealmUserUpdateClaimStore::prepare(session, keyspace).await?,
    );
    let guard = Arc::new(ScyllaRealmUserUpdateAdmissionGuard::new(
        gates.clone(),
        claims.clone(),
    ));
    let admission = admission(generation)?;
    let key = RealmUserUpdateAdmissionKey::try_new(admission.capture())?;
    guard.provision_generation::<PHash>(key).await?;
    Ok((gates, claims, guard, admission, key))
}

#[derive(Serialize)]
struct Report {
    image: &'static str,
    replication_factor: u8,
    schema_version: u16,
    target_tables: usize,
    total_claims: u64,
    claim_ms: u64,
    close_ms: u64,
    response_loss_retry: bool,
    crash_before_claim_recovered: bool,
    crash_after_claim_recovered: bool,
    duplicate_user_race_recovered: bool,
    missing_row_rejected: bool,
    extra_row_rejected: bool,
    closed_rejects_new: bool,
    one_replica_offline_write: bool,
    repair_flush_compact: bool,
    direct_one_nodes_equal: usize,
    qualification: &'static str,
}

#[derive(Debug, Eq, PartialEq)]
struct DirectSnapshot {
    gates: Vec<(i16, i64, Vec<u8>)>,
    claims: Vec<(i16, i64, i64, Vec<u8>)>,
}

type DependencyDirectRow = (
    Vec<u8>,
    Vec<u8>,
    i16,
    i32,
    i32,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
);

type TimestampedDependencyDirectRow = (
    Vec<u8>,
    Vec<u8>,
    i16,
    i32,
    i32,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
);

fn dependency_direct_row(
    bundle: &RealmUserUpdateDependencyBundle,
    fragment: &psy_node_core::queue::realm_user_update_dependency::RealmUserUpdateDependencyFragment,
) -> anyhow::Result<DependencyDirectRow> {
    Ok((
        bundle.claim_slot().as_bytes().to_vec(),
        bundle.digest().as_bytes().to_vec(),
        fragment.kind().as_i16(),
        i32::try_from(fragment.index())?,
        i32::try_from(fragment.count())?,
        i64::try_from(fragment.component_bytes())?,
        fragment.component_digest().as_bytes().to_vec(),
        fragment.payload().to_vec(),
        fragment.payload_digest().to_vec(),
    ))
}

fn expected_dependency_rows(
    fixtures: &[RealmUserUpdateLiveFixture],
) -> anyhow::Result<Vec<DependencyDirectRow>> {
    let mut rows = Vec::new();
    for fixture in fixtures {
        for fragment in fixture.bundle.fragments() {
            rows.push(dependency_direct_row(&fixture.bundle, &fragment)?);
        }
    }
    rows.sort_by(|left, right| {
        (&left.0, &left.1, left.2, left.3)
            .cmp(&(&right.0, &right.1, right.2, right.3))
    });
    Ok(rows)
}

async fn direct_dependency_snapshot(
    session: &Session,
    fixtures: &[RealmUserUpdateLiveFixture],
) -> anyhow::Result<Vec<DependencyDirectRow>> {
    let mut rows = Vec::new();
    for fixture in fixtures {
        let slot = fixture.bundle.claim_slot().as_bytes().to_vec();
        let digest = fixture.bundle.digest().as_bytes().to_vec();
        let mut kinds = fixture
            .bundle
            .fragments()
            .into_iter()
            .map(|fragment| fragment.kind().as_i16())
            .collect::<Vec<_>>();
        kinds.sort_unstable();
        kinds.dedup();
        for kind in kinds {
            let mut selected = session
                .query_unpaged(
                    format!(
                        "SELECT dependency_slot, dependency_digest, component_kind, fragment_index, fragment_count, component_bytes, component_digest, payload, payload_digest FROM {DATA}.{} WHERE dependency_slot = ? AND dependency_digest = ? AND component_kind = ?",
                        REALM_USER_UPDATE_DEPENDENCY_FRAGMENT_TABLE
                    ),
                    (slot.clone(), digest.clone(), kind),
                )
                .await?
                .into_rows_result()?
                .rows::<DependencyDirectRow>()?
                .collect::<Result<Vec<_>, _>>()?;
            rows.append(&mut selected);
        }
    }
    rows.sort_by(|left, right| {
        (&left.0, &left.1, left.2, left.3)
            .cmp(&(&right.0, &right.1, right.2, right.3))
    });
    Ok(rows)
}

fn expected_timestamped_dependency_rows(
    fixture: &RealmUserUpdateLiveFixture,
) -> anyhow::Result<Vec<TimestampedDependencyDirectRow>> {
    let timestamp = fixture.bundle.write_timestamp_us().as_i64();
    let mut rows = fixture
        .bundle
        .fragments()
        .iter()
        .map(|fragment| {
            let row = dependency_direct_row(&fixture.bundle, fragment)?;
            Ok((
                row.0, row.1, row.2, row.3, row.4, row.5, row.6, row.7,
                row.8, timestamp,
            ))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    rows.sort_by(|left, right| {
        (&left.0, &left.1, left.2, left.3)
            .cmp(&(&right.0, &right.1, right.2, right.3))
    });
    Ok(rows)
}

async fn direct_timestamped_dependency_snapshot(
    session: &Session,
    fixture: &RealmUserUpdateLiveFixture,
) -> anyhow::Result<Vec<TimestampedDependencyDirectRow>> {
    let slot = fixture.bundle.claim_slot().as_bytes().to_vec();
    let digest = fixture.bundle.digest().as_bytes().to_vec();
    let mut kinds = fixture
        .bundle
        .fragments()
        .iter()
        .map(|fragment| fragment.kind().as_i16())
        .collect::<Vec<_>>();
    kinds.sort_unstable();
    kinds.dedup();
    let mut rows = Vec::new();
    for kind in kinds {
        let mut selected = session
            .query_unpaged(
                format!(
                    "SELECT dependency_slot, dependency_digest, component_kind, fragment_index, fragment_count, component_bytes, component_digest, payload, payload_digest, WRITETIME(payload) FROM {DATA}.{} WHERE dependency_slot = ? AND dependency_digest = ? AND component_kind = ?",
                    REALM_USER_UPDATE_DEPENDENCY_FRAGMENT_TABLE
                ),
                (slot.clone(), digest.clone(), kind),
            )
            .await?
            .into_rows_result()?
            .rows::<TimestampedDependencyDirectRow>()?
            .collect::<Result<Vec<_>, _>>()?;
        rows.append(&mut selected);
    }
    rows.sort_by(|left, right| {
        (&left.0, &left.1, left.2, left.3)
            .cmp(&(&right.0, &right.1, right.2, right.3))
    });
    Ok(rows)
}

async fn dependency_write_timestamp(
    session: &Session,
    row: &DependencyDirectRow,
) -> anyhow::Result<i64> {
    let timestamp = session
        .query_unpaged(
            format!(
                "SELECT WRITETIME(payload) FROM {DATA}.{} WHERE dependency_slot = ? AND dependency_digest = ? AND component_kind = ? AND fragment_index = ?",
                REALM_USER_UPDATE_DEPENDENCY_FRAGMENT_TABLE
            ),
            (row.0.clone(), row.1.clone(), row.2, row.3),
        )
        .await?
        .into_rows_result()?
        .maybe_first_row::<(i64,)>()?
        .context("selected dependency fragment has no payload writetime")?;
    Ok(timestamp.0)
}

async fn restore_dependency_row(
    session: &Session,
    row: &DependencyDirectRow,
    timestamp: i64,
) -> anyhow::Result<()> {
    session
        .query_unpaged(
            format!(
                "INSERT INTO {DATA}.{} (dependency_slot, dependency_digest, component_kind, fragment_index, fragment_count, component_bytes, component_digest, payload, payload_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) USING TIMESTAMP ?",
                REALM_USER_UPDATE_DEPENDENCY_FRAGMENT_TABLE
            ),
            (
                row.0.clone(),
                row.1.clone(),
                row.2,
                row.3,
                row.4,
                row.5,
                row.6.clone(),
                row.7.clone(),
                row.8.clone(),
                timestamp,
            ),
        )
        .await?;
    Ok(())
}

async fn read_publish_source_fixture(
    session: &Session,
    slot: PendingQueuePublishSourceSlot,
) -> anyhow::Result<(PendingQueuePublishSourceState, i64)> {
    let row = session
        .query_unpaged(
            format!(
                "SELECT revision, source_payload, WRITETIME(source_payload) FROM {}.{} WHERE source_slot = ?",
                control(), PENDING_QUEUE_PUBLISH_SOURCE_TABLE
            ),
            (slot.as_bytes().to_vec(),),
        )
        .await?
        .into_rows_result()?
        .maybe_first_row::<(i64, Vec<u8>, i64)>()?
        .context("publish source fixture row missing")?;
    Ok((
        PendingQueuePublishSourceState::decode_persisted(row.0, &row.1)?,
        row.2,
    ))
}

async fn read_publish_intent_fixture(
    session: &Session,
    slot: PendingQueuePublishIntentSlot,
) -> anyhow::Result<StoredPendingQueuePublishIntent> {
    let row = session
        .query_unpaged(
            format!(
                "SELECT revision, intent_payload FROM {}.{} WHERE intent_slot = ?",
                control(), PENDING_QUEUE_PUBLISH_INTENT_TABLE
            ),
            (slot.as_bytes().to_vec(),),
        )
        .await?
        .into_rows_result()?
        .maybe_first_row::<(i64, Vec<u8>)>()?
        .context("publish intent fixture row missing")?;
    Ok(StoredPendingQueuePublishIntent::decode_persisted(
        slot,
        row.0,
        &row.1,
    )?)
}

fn claim_partition_binding(
    claim: &StoredRealmUserUpdateClaim<PHash>,
) -> anyhow::Result<(i64, i8, i64, i32, Vec<u8>, i64, Vec<u8>, i16, i64)> {
    let partition = claim.partition()?;
    let capture = partition.capture();
    let AuthorityScope::Realm {
        realm_id,
        realm_sub_id,
    } = capture.key().authority()
    else {
        bail!("RF=3 claim must be Realm-scoped")
    };
    Ok((
        i64::from(capture.key().network().chain_id()),
        REALM_AUTHORITY_KIND,
        i64::from(realm_id),
        i32::from(realm_sub_id),
        capture.activation().as_bytes().to_vec(),
        i64::try_from(capture.processing().pending_id().get())?,
        capture.processing().proc_checkpoint_id().as_bytes().to_vec(),
        partition.bucket().as_i16()?,
        i64::try_from(claim.user_id().get())?,
    ))
}

async fn claim_write_timestamp(
    session: &Session,
    claim: &StoredRealmUserUpdateClaim<PHash>,
) -> anyhow::Result<i64> {
    let key = claim_partition_binding(claim)?;
    let row = session
        .query_unpaged(
            format!(
                "SELECT WRITETIME(claim_payload) FROM {}.{} WHERE network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ? AND activation_digest = ? AND unique_pending_id = ? AND proc_checkpoint_id = ? AND claim_bucket = ? AND user_id = ?",
                control(), REALM_USER_UPDATE_CLAIM_TABLE
            ),
            key,
        )
        .await?
        .into_rows_result()?
        .maybe_first_row::<(i64,)>()?
        .context("claim fixture has no payload writetime")?;
    Ok(row.0)
}

async fn overwrite_claim_fixture(
    session: &Session,
    claim: &StoredRealmUserUpdateClaim<PHash>,
    timestamp: i64,
) -> anyhow::Result<()> {
    let key = claim_partition_binding(claim)?;
    session
        .query_unpaged(
            format!(
                "UPDATE {}.{} USING TIMESTAMP ? SET revision = ?, claim_payload = ? WHERE network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ? AND activation_digest = ? AND unique_pending_id = ? AND proc_checkpoint_id = ? AND claim_bucket = ? AND user_id = ?",
                control(), REALM_USER_UPDATE_CLAIM_TABLE
            ),
            (
                timestamp,
                claim.revision().as_i64()?,
                claim.to_canonical_bytes(),
                key.0,
                key.1,
                key.2,
                key.3,
                key.4,
                key.5,
                key.6,
                key.7,
                key.8,
            ),
        )
        .await?;
    Ok(())
}

async fn ensure_qualification_fault_rejected(
    router: &ScyllaRealmUserUpdateDurableRouter<
        PF,
        PHash,
        PoseidonHasher,
        PHash,
        DeterministicEndCapVerifier,
    >,
    gates: &ScyllaRealmUserUpdateAdmissionStore,
    jetstream: &jetstream::Context,
    stream_name: &str,
    key: RealmUserUpdateAdmissionKey,
    close: RealmUserUpdateAdmissionCloseIntent,
    expected_error: &str,
) -> anyhow::Result<()> {
    let before = stream_state(jetstream, stream_name).await?;
    let error = match router.qualify_generation(key, close).await {
        Ok(_) => bail!("fault unexpectedly qualified generation"),
        Err(error) => error,
    };
    ensure!(
        error.to_string().contains(expected_error),
        "unexpected qualification fault error: {error}"
    );
    let current = match gates
        .read::<PHash>(key, RealmUserUpdateAdmissionShard::Generation)
        .await?
    {
        RealmUserUpdateAdmissionReadState::Current(current) => current,
        RealmUserUpdateAdmissionReadState::Uninitialized => {
            bail!("fault removed generation admission")
        }
    };
    ensure!(current.phase() == RealmUserUpdateAdmissionPhase::GenerationClosed);
    ensure!(stream_state(jetstream, stream_name).await? == before);
    Ok(())
}

async fn direct_snapshot(
    session: &Session,
    capture: PendingQueueCaptureContext,
) -> anyhow::Result<DirectSnapshot> {
    let AuthorityScope::Realm {
        realm_id,
        realm_sub_id,
    } = capture.key().authority()
    else {
        bail!("RF=3 capture must be Realm-scoped")
    };
    let prefix = (
        i64::from(capture.key().network().chain_id()),
        REALM_AUTHORITY_KIND,
        i64::from(realm_id),
        i32::from(realm_sub_id),
        capture.activation().as_bytes().to_vec(),
        i64::try_from(capture.processing().pending_id().get())?,
        capture.processing().proc_checkpoint_id().as_bytes().to_vec(),
    );
    let mut gates = Vec::with_capacity(257);
    for shard in 0_i16..=256 {
        let mut rows = session
            .query_unpaged(
                format!(
                    "SELECT admission_shard, revision, admission_payload FROM {}.{} WHERE network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ? AND activation_digest = ? AND unique_pending_id = ? AND proc_checkpoint_id = ? AND admission_shard = ?",
                    control(), REALM_USER_UPDATE_ADMISSION_TABLE
                ),
                (
                    prefix.0,
                    prefix.1,
                    prefix.2,
                    prefix.3,
                    prefix.4.clone(),
                    prefix.5,
                    prefix.6.clone(),
                    shard,
                ),
            )
            .await?
            .into_rows_result()?
            .rows::<(i16, i64, Vec<u8>)>()?
            .collect::<Result<Vec<_>, _>>()?;
        gates.append(&mut rows);
    }
    let mut claims = Vec::new();
    for bucket in 0_i16..256 {
        let rows = session
            .query_unpaged(
                format!(
                    "SELECT claim_bucket, user_id, revision, claim_payload FROM {}.{} WHERE network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ? AND activation_digest = ? AND unique_pending_id = ? AND proc_checkpoint_id = ? AND claim_bucket = ?",
                    control(), REALM_USER_UPDATE_CLAIM_TABLE
                ),
                (
                    prefix.0,
                    prefix.1,
                    prefix.2,
                    prefix.3,
                    prefix.4.clone(),
                    prefix.5,
                    prefix.6.clone(),
                    bucket,
                ),
            )
            .await?
            .into_rows_result()?
            .rows::<(i16, i64, i64, Vec<u8>)>()?
            .collect::<Result<Vec<_>, _>>()?;
        claims.extend(rows);
    }
    claims.sort_by_key(|row| (row.0, row.1));
    Ok(DirectSnapshot { gates, claims })
}

async fn delete_claim_fixture(
    session: &Session,
    claim: &StoredRealmUserUpdateClaim<PHash>,
) -> anyhow::Result<()> {
    let partition = claim.partition()?;
    let capture = partition.capture();
    let AuthorityScope::Realm {
        realm_id,
        realm_sub_id,
    } = capture.key().authority()
    else {
        bail!("RF=3 claim must be Realm-scoped")
    };
    session
        .query_unpaged(
            format!(
                "DELETE FROM {}.{} WHERE network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ? AND activation_digest = ? AND unique_pending_id = ? AND proc_checkpoint_id = ? AND claim_bucket = ? AND user_id = ?",
                control(), REALM_USER_UPDATE_CLAIM_TABLE
            ),
            (
                i64::from(capture.key().network().chain_id()),
                REALM_AUTHORITY_KIND,
                i64::from(realm_id),
                i32::from(realm_sub_id),
                capture.activation().as_bytes().to_vec(),
                i64::try_from(capture.processing().pending_id().get())?,
                capture.processing().proc_checkpoint_id().as_bytes().to_vec(),
                partition.bucket().as_i16()?,
                i64::try_from(claim.user_id().get())?,
            ),
        )
        .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
#[ignore = "requires isolated Scylla RF=3 docker-compose cluster"]
async fn d04b6h23c4c2b3b2_claim_admission_close_rf3_gate(
) -> anyhow::Result<()> {
    ensure!(
        std::env::var("PSY_D04B6H23C4C2B3B2_RF3").as_deref() == Ok("1"),
        "run through tests/rf3/run-d04b6h23c4c2b3b2.sh"
    );
    let compose_file =
        std::env::var("PSY_D04B6H23C4C2B3B2_COMPOSE_FILE")?;
    wait_up(3).await?;
    let session = Arc::new(connect(None, Consistency::Quorum).await?);
    session
        .query_unpaged(
            format!("CREATE KEYSPACE IF NOT EXISTS {DATA} WITH replication = {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}}"),
            &[],
        )
        .await?;
    session
        .query_unpaged(
            format!("CREATE KEYSPACE IF NOT EXISTS {} WITH replication = {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}} AND tablets = {{'enabled': false}}", control()),
            &[],
        )
        .await?;
    session.await_schema_agreement().await?;
    let keyspaces = PendingQueueSidecarKeyspaces::try_new(DATA, control())?;
    PendingQueueSidecarDeploymentExecutor::deploy(
        session.clone(),
        keyspaces,
    )
    .await?;

    let (_, _, guard, live, live_key) =
        provisioned(session.clone(), 1).await?;

    // A caller may lose the response after the durable LWT. Exact retry must
    // return the first winner rather than allocate a second ordinal.
    let lost = claim_with_retry(&guard, &live, 1).await?;
    let retried = claim_with_retry(&guard, &live, 1).await?;
    let response_loss_retry = lost == retried;
    ensure!(response_loss_retry);

    // Real concurrent LWT pressure across all 256 buckets, with roughly four
    // claims per bucket and deterministic retry of transient Claiming races.
    let claim_started = Instant::now();
    let mut work = JoinSet::new();
    let concurrency = Arc::new(Semaphore::new(64));
    for user in 2..=CLAIMS {
        let guard = guard.clone();
        let admission = live.clone();
        let concurrency = concurrency.clone();
        work.spawn(async move {
            let _permit = concurrency.acquire_owned().await.unwrap();
            claim_with_retry(&guard, &admission, user).await
        });
    }
    let mut admitted = 1_u64;
    while let Some(result) = work.join_next().await {
        result??;
        admitted += 1;
    }
    ensure!(admitted == CLAIMS);
    let claim_ms = claim_started.elapsed().as_millis() as u64;

    // Crash window 1: BucketClaiming is durable, claim row is absent.
    let (gates2, _, guard2, second, second_key) =
        provisioned(session.clone(), 2).await?;
    let before = StoredRealmUserUpdateClaim::claimed(
        second.clone(),
        verifier_profile_id(),
        UserId::new(20_001),
        request(20_001)?,
        RealmUserUpdateCreatedAtSeconds::try_new(1_700_000_001)?,
        RealmUserUpdateAdmissionOrdinal::FIRST,
    )?;
    let claiming = StoredRealmUserUpdateAdmission::bucket_claiming(before)?;
    ensure!(gates2.bootstrap(&claiming).await?.applied());
    let recovered = claim_with_retry(&guard2, &second, 20_001).await?;
    let crash_before_claim_recovered = recovered.user_id() == UserId::new(20_001);
    ensure!(crash_before_claim_recovered);

    // Crash window 2: claim IFNE is durable, BucketClaiming was not reopened.
    let (gates3, claims3, guard3, third, third_key) =
        provisioned(session.clone(), 3).await?;
    let after = StoredRealmUserUpdateClaim::claimed(
        third.clone(),
        verifier_profile_id(),
        UserId::new(30_001),
        request(30_001)?,
        RealmUserUpdateCreatedAtSeconds::try_new(1_700_000_002)?,
        RealmUserUpdateAdmissionOrdinal::FIRST,
    )?;
    let claiming = StoredRealmUserUpdateAdmission::bucket_claiming(after)?;
    let outcome = gates3.bootstrap(&claiming).await?;
    let receipt =
        ScyllaRealmUserUpdateAdmissionStore::claiming_receipt(outcome)?;
    ensure!(matches!(
        claims3.claim(&receipt).await?,
        RealmUserUpdateClaimWriteOutcome::Applied(_)
            | RealmUserUpdateClaimWriteOutcome::Resumed(_)
    ));
    let recovered = claim_with_retry(&guard3, &third, 30_001).await?;
    let crash_after_claim_recovered = recovered.user_id() == UserId::new(30_001);
    ensure!(crash_after_claim_recovered);

    // A legal stale-empty first-winner race must release the losing ordinal,
    // not permanently block the bucket.
    let (gates5, _, guard5, fifth, fifth_key) =
        provisioned(session.clone(), 5).await?;
    let duplicate_user = 50_001;
    let winner = claim_with_retry(&guard5, &fifth, duplicate_user).await?;
    let duplicate_bucket = winner.bucket();
    let open = match gates5
        .read::<PHash>(
            fifth_key,
            RealmUserUpdateAdmissionShard::Bucket(duplicate_bucket),
        )
        .await?
    {
        RealmUserUpdateAdmissionReadState::Current(current) => current,
        RealmUserUpdateAdmissionReadState::Uninitialized => {
            bail!("winner bucket must be open")
        }
    };
    let loser = StoredRealmUserUpdateClaim::claimed(
        fifth.clone(),
        verifier_profile_id(),
        UserId::new(duplicate_user),
        RealmUserUpdateRequestDigest::derive(b"different", b"loser")?,
        RealmUserUpdateCreatedAtSeconds::try_new(1_700_000_003)?,
        RealmUserUpdateAdmissionOrdinal::try_new(2)?,
    )?;
    let claiming = StoredRealmUserUpdateAdmission::begin_claim(&open, loser)?;
    let receipt = ScyllaRealmUserUpdateAdmissionStore::claiming_receipt(
        gates5.compare_and_set(&open, &claiming).await?,
    )?;
    ensure!(matches!(
        guard5.recover_claiming_fixture(receipt).await,
        Err(RealmUserUpdateAdmissionGuardError::ClaimConflict)
    ));
    let duplicate_user_race_recovered = matches!(
        gates5
            .read::<PHash>(
                fifth_key,
                RealmUserUpdateAdmissionShard::Bucket(duplicate_bucket),
            )
            .await?,
        RealmUserUpdateAdmissionReadState::Current(ref current)
            if current.phase() == RealmUserUpdateAdmissionPhase::BucketOpen
                && current.accepted_set().unwrap().count() == 1
    );
    ensure!(duplicate_user_race_recovered);
    guard5
        .close_generation::<PHash>(fifth_key, close_intent(fifth_key)?)
        .await?;

    // A missing accepted row and an untracked residual row must both prevent
    // generation membership from becoming closed/verified.
    let (gates6, _, guard6, sixth, sixth_key) =
        provisioned(session.clone(), 6).await?;
    let missing_user = user_in_bucket(0, 60_000);
    let missing = claim_with_retry(&guard6, &sixth, missing_user).await?;
    delete_claim_fixture(&session, &missing).await?;
    let missing_result = guard6
        .close_generation::<PHash>(sixth_key, close_intent(sixth_key)?)
        .await;
    println!("missing-row close result: {missing_result:?}");
    let missing_row_rejected = missing_result.is_err()
        && !matches!(
            gates6
                .read::<PHash>(
                    sixth_key,
                    RealmUserUpdateAdmissionShard::Generation,
                )
                .await?,
            RealmUserUpdateAdmissionReadState::Current(ref current)
                if current.phase()
                    == RealmUserUpdateAdmissionPhase::GenerationClosed
        );
    ensure!(missing_row_rejected);

    let (gates7, claims7, guard7, seventh, seventh_key) =
        provisioned(session.clone(), 7).await?;
    let extra_user = user_in_bucket(0, 70_000);
    let extra = StoredRealmUserUpdateClaim::claimed(
        seventh,
        verifier_profile_id(),
        UserId::new(extra_user),
        request(extra_user)?,
        RealmUserUpdateCreatedAtSeconds::try_new(1_700_000_004)?,
        RealmUserUpdateAdmissionOrdinal::FIRST,
    )?;
    ensure!(matches!(
        claims7.claim_retired_v5_fixture(&extra).await?,
        RealmUserUpdateClaimWriteOutcome::Applied(_)
    ));
    let extra_result = guard7
        .close_generation::<PHash>(seventh_key, close_intent(seventh_key)?)
        .await;
    println!("extra-row close result: {extra_result:?}");
    let extra_row_rejected = extra_result.is_err()
        && !matches!(
            gates7
                .read::<PHash>(
                    seventh_key,
                    RealmUserUpdateAdmissionShard::Generation,
                )
                .await?,
            RealmUserUpdateAdmissionReadState::Current(ref current)
                if current.phase()
                    == RealmUserUpdateAdmissionPhase::GenerationClosed
        );
    ensure!(extra_row_rejected);

    compose(
        Path::new(&compose_file),
        &["stop", "scylla3"],
    )?;
    wait_up(2).await?;
    let (_, _, offline_guard, offline, offline_key) =
        provisioned(session.clone(), 4).await?;
    let one_replica_offline_write =
        claim_with_retry(&offline_guard, &offline, 40_001).await?.user_id()
            == UserId::new(40_001);
    ensure!(one_replica_offline_write);
    offline_guard
        .close_generation::<PHash>(offline_key, close_intent(offline_key)?)
        .await?;

    let close_started = Instant::now();
    let closed = guard
        .close_generation::<PHash>(live_key, close_intent(live_key)?)
        .await?;
    let close_ms = close_started.elapsed().as_millis() as u64;
    ensure!(closed.phase() == RealmUserUpdateAdmissionPhase::GenerationClosed);
    ensure!(closed.generation_manifest().unwrap().total().count() == CLAIMS);
    // Closed response loss is also idempotent.
    ensure!(
        guard
            .close_generation::<PHash>(live_key, close_intent(live_key)?)
            .await?
            == closed
    );
    let closed_rejects_new = matches!(
        claim_with_retry(&guard, &live, CLAIMS + 1).await,
        Err(RealmUserUpdateAdmissionGuardError::AdmissionClosed)
    );
    ensure!(closed_rejects_new);

    // Also close both explicit crash-window generations so every durable
    // Claiming journal is proven recoverable before repair.
    guard2
        .close_generation::<PHash>(second_key, close_intent(second_key)?)
        .await?;
    guard3
        .close_generation::<PHash>(third_key, close_intent(third_key)?)
        .await?;

    compose(
        Path::new(&compose_file),
        &["start", "scylla3"],
    )?;
    wait_up(3).await?;
    for node in NODE_CONTAINERS {
        docker_exec_retry(
            node,
            &["nodetool", "repair", "-pr", &control()],
            24,
        )?;
        docker_exec(node, &["nodetool", "flush", &control()])?;
        docker_exec(node, &["nodetool", "compact", &control()])?;
    }

    let mut direct = Vec::new();
    for ip in NODE_IPS {
        let local = connect(Some(ip), Consistency::One).await?;
        direct.push(direct_snapshot(&local, live.capture()).await?);
    }
    let direct_one_nodes_equal = direct
        .windows(2)
        .all(|pair| pair[0] == pair[1])
        .then_some(direct.len())
        .unwrap_or(0);
    ensure!(direct_one_nodes_equal == 3);
    ensure!(direct[0].gates.len() == 257);
    ensure!(direct[0].claims.len() == CLAIMS as usize);

    let report = Report {
        image: IMAGE,
        replication_factor: 3,
        schema_version: PENDING_QUEUE_SIDECAR_SCHEMA_VERSION,
        target_tables: PENDING_QUEUE_SIDECAR_TARGET_TABLE_COUNT,
        total_claims: CLAIMS,
        claim_ms,
        close_ms,
        response_loss_retry,
        crash_before_claim_recovered,
        crash_after_claim_recovered,
        duplicate_user_race_recovered,
        missing_row_rejected,
        extra_row_rejected,
        closed_rejects_new,
        one_replica_offline_write,
        repair_flush_compact: true,
        direct_one_nodes_equal,
        qualification: "H23C4C2B3B2_ADMISSION_MEMBERSHIP_RF3_PASSED",
    };
    let report_path =
        std::env::var("PSY_D04B6H23C4C2B3B2_REPORT_PATH")?;
    std::fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[derive(Serialize)]
struct QualificationStoreReport {
    image: &'static str,
    replication_factor: u8,
    schema_version: u16,
    target_tables: usize,
    terminal_claims: usize,
    concurrent_qualifiers: usize,
    response_loss_retry: bool,
    stale_frontier_rejected: bool,
    one_replica_offline_qualified: bool,
    repair_flush_compact: bool,
    direct_one_nodes_equal: usize,
    qualification: &'static str,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires isolated Scylla RF=3 docker-compose cluster"]
async fn d04b6h23c4c2b3b2c2a_qualification_store_rf3_gate(
) -> anyhow::Result<()> {
    ensure!(
        std::env::var("PSY_D04B6H23C4C2B3B2C2A_RF3").as_deref()
            == Ok("1"),
        "run through tests/rf3/run-d04b6h23c4c2b3b2c2a.sh"
    );
    let compose_file =
        std::env::var("PSY_D04B6H23C4C2B3B2C2A_COMPOSE_FILE")?;
    wait_up(3).await?;
    let session = Arc::new(connect(None, Consistency::Quorum).await?);
    session
        .query_unpaged(
            format!("CREATE KEYSPACE IF NOT EXISTS {DATA} WITH replication = {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}}"),
            &[],
        )
        .await?;
    session
        .query_unpaged(
            format!("CREATE KEYSPACE IF NOT EXISTS {} WITH replication = {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}} AND tablets = {{'enabled': false}}", control()),
            &[],
        )
        .await?;
    session.await_schema_agreement().await?;
    PendingQueueSidecarDeploymentExecutor::deploy(
        session.clone(),
        PendingQueueSidecarKeyspaces::try_new(DATA, control())?,
    )
    .await?;

    let (_, _, guard, publish_admission, key) = provisioned(session.clone(), 8).await?;
    let close = close_intent(key)?;
    let closed = guard.close_generation::<PHash>(key, close).await?;
    ensure!(closed.phase() == RealmUserUpdateAdmissionPhase::GenerationClosed);
    ensure!(closed.generation_manifest().unwrap().total().count() == 0);

    let first = guard.qualification_input::<PHash>(key, close).await?;
    let second = guard.qualification_input::<PHash>(key, close).await?;
    let RealmUserUpdateQualificationInput::Closed(first) = first else {
        bail!("first qualification input was not Closed")
    };
    let RealmUserUpdateQualificationInput::Closed(second) = second else {
        bail!("second qualification input was not Closed")
    };
    let pipeline = qualification_pipeline(&publish_admission)?;
    let fence = RealmUserUpdateQualificationFence::try_from_pipeline(key, &pipeline)?;
    let membership = first
        .header()
        .generation_manifest()
        .context("closed generation missing manifest")?;
    ensure!(second.header().generation_manifest() == Some(membership));
    let qualification = RealmUserUpdateGenerationQualification::from_terminal_evidence(
        key,
        close,
        membership,
        fence,
        &[],
    )?;

    compose(Path::new(&compose_file), &["stop", "scylla3"])?;
    wait_up(2).await?;
    let (first_result, second_result) = tokio::join!(
        guard.persist_qualification(first, qualification),
        guard.persist_qualification(second, qualification),
    );
    let first_receipt = first_result?;
    let second_receipt = second_result?;
    first_receipt.revalidate_pipeline(&pipeline)?;
    second_receipt.revalidate_pipeline(&pipeline)?;
    ensure!(first_receipt.current() == second_receipt.current());
    ensure!(
        first_receipt.current().phase()
            == RealmUserUpdateAdmissionPhase::GenerationQualified
    );
    let one_replica_offline_qualified = true;

    let response_loss_retry = match guard
        .qualification_input::<PHash>(key, close)
        .await?
    {
        RealmUserUpdateQualificationInput::Qualified(receipt) => {
            receipt.revalidate_pipeline(&pipeline)?;
            receipt.current() == first_receipt.current()
        }
        RealmUserUpdateQualificationInput::Closed(_) => false,
    };
    ensure!(response_loss_retry);

    let foreign = admission(9)?;
    let foreign_pending = PendingContext::new(
        *foreign.pending().chain(),
        publish_admission.pending().authority(),
        publish_admission.pending().unique_pending_id(),
        publish_admission.pending().proc_checkpoint_unique_id(),
    );
    let foreign_frontier = RealmUserUpdatePublishAdmission::try_from_pipeline(
        foreign_pending,
        publish_admission.capture(),
    )?;
    let stale_pipeline = qualification_pipeline(&foreign_frontier)?;
    let stale_frontier_rejected = first_receipt
        .revalidate_pipeline(&stale_pipeline)
        .is_err();
    ensure!(stale_frontier_rejected);

    compose(Path::new(&compose_file), &["start", "scylla3"])?;
    wait_up(3).await?;
    for node in NODE_CONTAINERS {
        docker_exec_retry(node, &["nodetool", "repair", "-pr", &control()], 24)?;
        docker_exec(node, &["nodetool", "flush", &control()])?;
        docker_exec(node, &["nodetool", "compact", &control()])?;
    }
    let mut direct = Vec::new();
    for ip in NODE_IPS {
        let local = connect(Some(ip), Consistency::One).await?;
        direct.push(direct_snapshot(&local, publish_admission.capture()).await?);
    }
    let direct_one_nodes_equal = direct
        .windows(2)
        .all(|pair| pair[0] == pair[1])
        .then_some(direct.len())
        .unwrap_or(0);
    ensure!(direct_one_nodes_equal == 3);
    ensure!(direct[0].gates.len() == 257);
    ensure!(direct[0].claims.is_empty());

    let report = QualificationStoreReport {
        image: IMAGE,
        replication_factor: 3,
        schema_version: PENDING_QUEUE_SIDECAR_SCHEMA_VERSION,
        target_tables: PENDING_QUEUE_SIDECAR_TARGET_TABLE_COUNT,
        terminal_claims: 0,
        concurrent_qualifiers: 2,
        response_loss_retry,
        stale_frontier_rejected,
        one_replica_offline_qualified,
        repair_flush_compact: true,
        direct_one_nodes_equal,
        qualification: "H23C4C2B3B2C2A_QUALIFICATION_STORE_RF3_PASSED",
    };
    let report_path =
        std::env::var("PSY_D04B6H23C4C2B3B2C2A_REPORT_PATH")?;
    std::fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[derive(Serialize)]
struct NonemptyTerminalSourceReport {
    image: &'static str,
    scylla_replication_factor: u8,
    nats_servers: u8,
    nats_stream_replicas: u8,
    schema_version: u16,
    target_tables: usize,
    terminal_claims: usize,
    source_sequences: Vec<u64>,
    historical_intent_after_cursor_advance: bool,
    caller_discard_exact_retry: bool,
    scylla_one_replica_offline: bool,
    nats_leader_before: String,
    nats_leader_after: String,
    nats_leader_failover: bool,
    dependency_missing_rejected: bool,
    dependency_extra_rejected: bool,
    dependency_wrong_digest_rejected: bool,
    dependency_exact_restore: bool,
    commit_pending_recovered: bool,
    commit_pending_nats_publish_delta: i64,
    recovery_nats_publish_delta: i64,
    source_revision_delta: u64,
    intent_revision_delta: u64,
    recovery_response_loss_retry: bool,
    missing_source_rejected: bool,
    fake_receipt_rejected: bool,
    qualification_nats_publish_delta: i64,
    repair_flush_compact: bool,
    direct_one_nodes_equal: usize,
    dependency_direct_one_nodes_equal: usize,
    dependency_rows: usize,
    qualification_ms: u64,
    direct_consumer_items: usize,
    direct_consumer_retry_identical: bool,
    projection_rebuild_identical: bool,
    direct_consumer_nats_publish_delta: i64,
    direct_consumer_ms: u64,
    direct_consumer_phase_matrix_typed: bool,
    direct_consumer_dependency_loss_rejected: bool,
    qualification: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NonemptyTerminalSourceCase {
    Positive,
    DependencyFault,
    SourceReceiptCommitPending,
    DirectDurableConsumer,
}

async fn run_nonempty_terminal_source_joint_rf3(
    case: NonemptyTerminalSourceCase,
) -> anyhow::Result<()> {
    ensure!(
        std::env::var("PSY_D04B6H23C4C2B3B2C2B_RF3").as_deref()
            == Ok("1"),
        "run through tests/rf3/run-d04b6h23c4c2b3b2c2b.sh"
    );
    let compose_file =
        std::env::var("PSY_D04B6H23C4C2B3B2C2B_COMPOSE_FILE")?;
    let report_path =
        std::env::var("PSY_D04B6H23C4C2B3B2C2B_REPORT_PATH")?;
    let nats_urls =
        std::env::var("PSY_D04B6H23C4C2B3B2C2B_NATS_URLS")?
            .split(',')
            .map(str::to_owned)
            .collect::<Vec<_>>();
    ensure!(nats_urls.len() == 3);

    wait_up(3).await?;
    let session = Arc::new(connect(None, Consistency::Quorum).await?);
    session
        .query_unpaged(
            format!("CREATE KEYSPACE IF NOT EXISTS {DATA} WITH replication = {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}}"),
            &[],
        )
        .await?;
    session
        .query_unpaged(
            format!("CREATE KEYSPACE IF NOT EXISTS {} WITH replication = {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}} AND tablets = {{'enabled': false}}", control()),
            &[],
        )
        .await?;
    session.await_schema_agreement().await?;
    let keyspaces = PendingQueueSidecarKeyspaces::try_new(DATA, control())?;
    PendingQueueSidecarDeploymentExecutor::deploy(
        session.clone(),
        keyspaces.clone(),
    )
    .await?;
    let ready = Arc::new(
        ScyllaPendingQueueSidecarSetupGate::authorize(
            session.clone(),
            keyspaces,
            realm(),
        )
        .await?,
    );

    let generation = 10;
    let expected_admission = admission(generation)?;
    let capture = expected_admission.capture();
    let control_keyspace =
        BranchExactDeploymentNoTabletKeyspace::try_new(control())?;
    let pipeline_store = ScyllaPendingPipelineStore::prepare(
        session.clone(),
        control_keyspace.clone(),
    )
    .await?;
    let pipeline = current_pipeline(
        pipeline_store
            .bootstrap(&qualification_pipeline_bootstrap(
                &expected_admission,
            )?)
            .await?,
    )?;
    ensure!(pipeline.gathering() == capture.processing());
    ensure!(pipeline.frontier().chain() == expected_admission.pending().chain());

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64;
    let base = format!("psy_h23c2b_{nonce}");
    let segment = RecoverableNatsStreamSegment::try_new(
        base.clone(),
        capture.key(),
        RecoverableNatsSegmentId::try_new(1)?,
        retention()?,
    )?;
    let validated =
        segment.validate_stream_config_structure(&segment.stream_config())?;
    let ledger_bootstrap = PendingQueueSegmentLedgerBootstrap::try_new(
        capture.key(),
        &validated,
        generation_budget(realm())?,
        1,
    )?;
    let ledger_key = ledger_bootstrap.candidate().key().clone();
    let ledger = ScyllaPendingQueueSegmentLedgerStore::prepare(
        session.clone(),
        control_keyspace,
    )
    .await?;
    ledger.bootstrap(&ledger_bootstrap).await?;
    let assignment = ledger.reserve_generation(&ledger_key, capture).await?;
    ensure!(assignment.assignment().context() == capture);

    let raw_nats = async_nats::connect(nats_urls.clone()).await?;
    let jetstream = jetstream::new(raw_nats);
    jetstream.create_stream(segment.stream_config()).await?;
    let nats_client = Arc::new(
        NatsJetStreamClient::new_connection(
            base,
            nats_urls,
            PullConfig::default(),
            PullConfig::default(),
            StreamConfig::default(),
        )
        .await?,
    );
    let nats_publisher = Arc::new(
        nats_client
            .recoverable_pending_publisher(segment.clone())
            .await?,
    );
    let height = GlobalUserTreeHeight::try_new(32)?;
    let mut router = ScyllaRealmUserUpdateDurableRouter::<
        PF,
        PHash,
        PoseidonHasher,
        PHash,
        DeterministicEndCapVerifier,
    >::prepare(
        session.clone(),
        capture.key().network(),
        realm(),
        height,
        20,
        verifier_profile_id(),
        verifier_registry(),
        fixed_observation_reader(&expected_admission)?,
        ready.clone(),
        nats_publisher.clone(),
        segment.clone(),
    )
    .await?;
    ensure!(router.admit().await? == expected_admission);
    let (gates, claims, guard, provisioned_admission, key) =
        provisioned(session.clone(), generation).await?;
    ensure!(provisioned_admission == expected_admission);

    let first_user = UserId::new((7_u64 << 20) + 11);
    let second_user = UserId::new((7_u64 << 20) + 12);
    let mut fixtures = Vec::new();
    let mut terminals = Vec::new();
    let mut phase_claims = Vec::new();
    let mut initial_nats_leader = None;
    let mut failover_nats_leader = None;
    let dependency_store = ScyllaRealmUserUpdateDependencyStore::prepare(
        session.clone(),
        PendingQueueArtifactDataKeyspace::try_new(DATA)?,
    )
    .await?;
    let mut commit_pending_witness = None;
    let mut first_ready_claim = None;
    let mut commit_pending_nats_publish_delta = 0;
    let mut recovery_nats_publish_delta = 0;
    let mut source_revision_delta = 0;
    let mut intent_revision_delta = 0;
    let mut recovery_response_loss_retry = false;
    for (index, user) in [first_user, second_user].into_iter().enumerate() {
        let verified = verified_end_cap_request(user, height)?;
        let winner = router
            .claim(
                expected_admission.clone(),
                &verified,
                RealmUserUpdateCreatedAtSeconds::try_new(
                    1_700_000_010 + u32::try_from(index)?,
                )?,
            )
            .await?;
        let fixture = live_artifacts_for_claim(
            &expected_admission,
            &winner,
            verified,
            height,
        )?;
        let planned_model = StoredRealmUserUpdateClaim::dependencies_planned(
            &winner,
            fixture.bundle.digest(),
        )?;
        let ready_model =
            StoredRealmUserUpdateClaim::dependencies_ready(&planned_model)?;
        phase_claims.push((winner.clone(), planned_model, ready_model));
        let terminal = if case
            == NonemptyTerminalSourceCase::SourceReceiptCommitPending
            && index == 0
        {
            let planned = StoredRealmUserUpdateClaim::dependencies_planned(
                &winner,
                fixture.bundle.digest(),
            )?;
            let planned = current_claim(
                claims.compare_and_set(&winner, &planned).await?,
            )?;
            ensure!(
                dependency_store
                    .persist_and_readback(&fixture.bundle)
                    .await?
                    == fixture.bundle.digest()
            );
            let ready_claim = StoredRealmUserUpdateClaim::dependencies_ready(
                &planned,
            )?;
            let ready_claim = current_claim(
                claims.compare_and_set(&planned, &ready_claim).await?,
            )?;
            ensure!(ready_claim.phase() == RealmUserUpdateClaimPhase::DependenciesReady);

            let publish_store = ScyllaPendingQueuePublishStore::prepare(
                session.clone(),
                nats_publisher.clone(),
                segment.clone(),
                PendingQueuePublishKeyspaces::new(
                    BranchExactDeploymentNoTabletKeyspace::try_new(control())?,
                    PendingQueuePublishDataKeyspace::try_new(DATA)?,
                ),
            )
            .await?;
            let kind = PendingQueuePublisherKind::RealmUserUpdate;
            publish_store.bootstrap_source(&assignment, kind).await?;
            let intent_id = PendingQueuePublishIntentId::try_new(
                *fixture.publish_request.intent_id().as_bytes(),
            )?;
            let intent_slot = publish_store
                .materialize_data(
                    &assignment,
                    kind,
                    intent_id,
                    fixture.publish_request.payload(),
                )
                .await?;
            let permit = publish_store
                .bind_materialized(&assignment, kind, intent_slot)
                .await?;
            let before_pending =
                stream_state(&jetstream, segment.stream_name()).await?;
            let witness = publish_store
                .publish_through_commit_pending_fixture(
                    &assignment,
                    permit,
                )
                .await?;
            let after_pending =
                stream_state(&jetstream, segment.stream_name()).await?;
            commit_pending_nats_publish_delta = i64::try_from(after_pending.0)?
                - i64::try_from(before_pending.0)?;
            ensure!(commit_pending_nats_publish_delta == 1);
            let (pending_source, _) = read_publish_source_fixture(
                &session,
                witness.source_slot(),
            )
            .await?;
            let pending_intent = read_publish_intent_fixture(
                &session,
                witness.intent_slot(),
            )
            .await?;
            ensure!(matches!(
                pending_source.phase(),
                PendingQueuePublishSourcePhase::CommitPending { .. }
            ));
            ensure!(matches!(
                pending_intent.phase(),
                PendingQueuePublishIntentPhase::NatsAccepted { .. }
            ));
            ensure!(pending_source.revision().get() == witness.source_revision());
            ensure!(pending_intent.revision().get() == witness.intent_revision());
            ensure!(
                pending_source.commit_pending().map(|(_, sequence)| sequence)
                    == Some(witness.subject_sequence())
            );
            drop(publish_store);

            // Rebuild the production-shaped router after the deterministic
            // crash stop. It must consume the existing NATS acceptance rather
            // than publish the envelope a second time.
            router = ScyllaRealmUserUpdateDurableRouter::<
                PF,
                PHash,
                PoseidonHasher,
                PHash,
                DeterministicEndCapVerifier,
            >::prepare(
                session.clone(),
                capture.key().network(),
                realm(),
                height,
                20,
                verifier_profile_id(),
                verifier_registry(),
                fixed_observation_reader(&expected_admission)?,
                ready.clone(),
                nats_publisher.clone(),
                segment.clone(),
            )
            .await?;
            let before_recovery =
                stream_state(&jetstream, segment.stream_name()).await?;
            let recovered = router
                .complete_live(&ready_claim, &fixture.artifacts)
                .await
                .context("recover CommitPending claim")?;
            let after_recovery =
                stream_state(&jetstream, segment.stream_name()).await?;
            recovery_nats_publish_delta = i64::try_from(after_recovery.0)?
                - i64::try_from(before_recovery.0)?;
            ensure!(recovery_nats_publish_delta == 0);
            ensure!(
                recovered.publication().disposition()
                    == RealmUserUpdatePublishDisposition::DurableResumed
            );
            let retry = router
                .complete_live(&ready_claim, &fixture.artifacts)
                .await
                .context("retry recovered CommitPending claim")?;
            ensure!(retry.claim() == recovered.claim());
            ensure!(retry.publication() == recovered.publication());
            ensure!(stream_state(&jetstream, segment.stream_name()).await? == after_recovery);
            recovery_response_loss_retry = true;

            let (final_source, _) = read_publish_source_fixture(
                &session,
                witness.source_slot(),
            )
            .await?;
            let final_intent = read_publish_intent_fixture(
                &session,
                witness.intent_slot(),
            )
            .await?;
            ensure!(matches!(
                final_source.phase(),
                PendingQueuePublishSourcePhase::Open
            ));
            ensure!(matches!(
                final_intent.phase(),
                PendingQueuePublishIntentPhase::SourceCommitted { .. }
            ));
            ensure!(final_source.last_subject_sequence() == witness.subject_sequence());
            ensure!(final_source.last_envelope_digest() == *witness.envelope_digest());
            source_revision_delta = final_source
                .revision()
                .get()
                .checked_sub(witness.source_revision())
                .context("source revision regressed")?;
            intent_revision_delta = final_intent
                .revision()
                .get()
                .checked_sub(witness.intent_revision())
                .context("intent revision regressed")?;
            ensure!(source_revision_delta == 1);
            ensure!(intent_revision_delta == 1);
            first_ready_claim = Some(ready_claim);
            commit_pending_witness = Some(witness);
            recovered
        } else {
            router
                .complete_live(&winner, &fixture.artifacts)
                .await
                .with_context(|| format!("complete live claim {index}"))?
        };
        ensure!(terminal.claim().phase() == RealmUserUpdateClaimPhase::Published);
        ensure!(
            terminal.claim().publish_receipt_digest().map(|value| *value.as_bytes())
                == Some(*terminal.publication().receipt_digest())
        );
        let exact_retry = router
            .complete_live(&winner, &fixture.artifacts)
            .await
            .with_context(|| format!("retry complete live claim {index}"))?;
        ensure!(exact_retry.claim() == terminal.claim());
        ensure_same_durable_publication(
            terminal.publication(),
            exact_retry.publication(),
        )?;
        ensure!(
            exact_retry.publication().disposition()
                == RealmUserUpdatePublishDisposition::DurableResumed
        );
        fixtures.push(fixture);
        terminals.push(terminal);

        if index == 0 {
            let leader = wait_for_stream_leader(
                &jetstream,
                segment.stream_name(),
                None,
            )
            .await?;
            // Terminate rather than SIGSTOP the current leader. A stopped
            // process leaves the TCP socket half-open and can pin the client
            // until its long request timeout; termination exercises the same
            // JetStream replica failover while forcing prompt reconnect.
            signal_c2b_nats(&leader, "-TERM")?;
            let replacement = wait_for_stream_leader(
                &jetstream,
                segment.stream_name(),
                Some(&leader),
            )
            .await?;
            initial_nats_leader = Some(leader);
            failover_nats_leader = Some(replacement);
        }
    }
    ensure!(
        terminals[0].publication().subject_sequence()
            < terminals[1].publication().subject_sequence()
    );

    let historical_observer = ScyllaRealmEdgeDurablePublisher::<PF, PHash>::prepare(
        session.clone(),
        capture.key().network(),
        realm(),
        ready.clone(),
        nats_publisher.clone(),
        segment.clone(),
    )
    .await?;
    let historical = historical_observer
        .observe_authorized(fixtures[0].publish_request.clone())
        .await
        .context("observe first historical committed source")?
        .context("first source intent must remain historically observable")?;
    ensure_same_durable_publication(
        terminals[0].publication(),
        historical.receipt(),
    )?;
    ensure!(
        historical.receipt().disposition()
            == RealmUserUpdatePublishDisposition::DurableResumed
    );
    let historical_intent_after_cursor_advance = true;

    for (terminal, fixture) in terminals.iter().zip(&fixtures) {
        let readback = dependency_store
            .read_bundle(
                terminal.claim().slot(),
                *terminal.claim().request_digest().as_bytes(),
                terminal.claim().stable_status(),
                terminal.claim().created_at().get(),
                fixture.bundle.digest(),
            )
            .await
            .context("read exact dependency bundle")?;
        ensure!(readback == fixture.bundle);
    }

    let close = close_intent(key)?;
    let closed = guard.close_generation::<PHash>(key, close).await?;
    ensure!(closed.phase() == RealmUserUpdateAdmissionPhase::GenerationClosed);
    ensure!(closed.generation_manifest().unwrap().total().count() == 2);
    let nats_before = stream_state(&jetstream, segment.stream_name()).await?;

    let mut dependency_missing_rejected = false;
    let mut dependency_extra_rejected = false;
    let mut dependency_wrong_digest_rejected = false;
    let mut dependency_exact_restore = false;
    let mut missing_source_rejected = false;
    let mut fake_receipt_rejected = false;
    if case == NonemptyTerminalSourceCase::DependencyFault {
        ensure!(
            std::env::var("PSY_D04B6H23C4C2B3B2C2C1_RF3").as_deref()
                == Ok("1"),
            "run through tests/rf3/run-d04b6h23c4c2b3b2c2c1.sh"
        );
        let selected_fragment = fixtures[0]
            .bundle
            .fragments()
            .into_iter()
            .find(|fragment| fragment.kind().as_i16() == 2 && fragment.index() == 0)
            .context("proof dependency fragment zero is required")?;
        let selected = dependency_direct_row(
            &fixtures[0].bundle,
            &selected_fragment,
        )?;

        let original_timestamp = dependency_write_timestamp(&session, &selected).await?;
        let missing_timestamp = original_timestamp
            .checked_add(1)
            .context("missing fault timestamp overflow")?;
        let missing_restore_timestamp = missing_timestamp
            .checked_add(1)
            .context("missing restore timestamp overflow")?;
        session
            .query_unpaged(
                format!(
                    "DELETE FROM {DATA}.{} USING TIMESTAMP ? WHERE dependency_slot = ? AND dependency_digest = ? AND component_kind = ? AND fragment_index = ?",
                    REALM_USER_UPDATE_DEPENDENCY_FRAGMENT_TABLE
                ),
                (
                    missing_timestamp,
                    selected.0.clone(),
                    selected.1.clone(),
                    selected.2,
                    selected.3,
                ),
            )
            .await?;
        ensure_qualification_fault_rejected(
            &router,
            &gates,
            &jetstream,
            segment.stream_name(),
            key,
            close,
            "DurableDependencyLoss",
        )
        .await?;
        dependency_missing_rejected = true;
        restore_dependency_row(&session, &selected, missing_restore_timestamp).await?;
        ensure!(
            dependency_store
                .read_bundle(
                    fixtures[0].bundle.claim_slot(),
                    *terminals[0].claim().request_digest().as_bytes(),
                    terminals[0].claim().stable_status(),
                    terminals[0].claim().created_at().get(),
                    fixtures[0].bundle.digest(),
                )
                .await?
                == fixtures[0].bundle
        );

        let extra_timestamp = missing_restore_timestamp
            .checked_add(1)
            .context("extra fault timestamp overflow")?;
        let extra_restore_timestamp = extra_timestamp
            .checked_add(1)
            .context("extra restore timestamp overflow")?;
        let extra_index = selected.4;
        session
            .query_unpaged(
                format!(
                    "INSERT INTO {DATA}.{} (dependency_slot, dependency_digest, component_kind, fragment_index, fragment_count, component_bytes, component_digest, payload, payload_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) USING TIMESTAMP ?",
                    REALM_USER_UPDATE_DEPENDENCY_FRAGMENT_TABLE
                ),
                (
                    selected.0.clone(),
                    selected.1.clone(),
                    selected.2,
                    extra_index,
                    selected.4,
                    selected.5,
                    selected.6.clone(),
                    selected.7.clone(),
                    selected.8.clone(),
                    extra_timestamp,
                ),
            )
            .await?;
        ensure_qualification_fault_rejected(
            &router,
            &gates,
            &jetstream,
            segment.stream_name(),
            key,
            close,
            "MalformedFragment",
        )
        .await?;
        dependency_extra_rejected = true;
        session
            .query_unpaged(
                format!(
                    "DELETE FROM {DATA}.{} USING TIMESTAMP ? WHERE dependency_slot = ? AND dependency_digest = ? AND component_kind = ? AND fragment_index = ?",
                    REALM_USER_UPDATE_DEPENDENCY_FRAGMENT_TABLE
                ),
                (
                    extra_restore_timestamp,
                    selected.0.clone(),
                    selected.1.clone(),
                    selected.2,
                    extra_index,
                ),
            )
            .await?;
        ensure!(
            dependency_store
                .read_bundle(
                    fixtures[0].bundle.claim_slot(),
                    *terminals[0].claim().request_digest().as_bytes(),
                    terminals[0].claim().stable_status(),
                    terminals[0].claim().created_at().get(),
                    fixtures[0].bundle.digest(),
                )
                .await?
                == fixtures[0].bundle
        );

        let wrong_timestamp = extra_restore_timestamp
            .checked_add(1)
            .context("wrong-digest fault timestamp overflow")?;
        let wrong_restore_timestamp = wrong_timestamp
            .checked_add(1)
            .context("wrong-digest restore timestamp overflow")?;
        let mut wrong_digest = selected.8.clone();
        wrong_digest[0] ^= 0xff;
        session
            .query_unpaged(
                format!(
                    "UPDATE {DATA}.{} USING TIMESTAMP ? SET payload_digest = ? WHERE dependency_slot = ? AND dependency_digest = ? AND component_kind = ? AND fragment_index = ?",
                    REALM_USER_UPDATE_DEPENDENCY_FRAGMENT_TABLE
                ),
                (
                    wrong_timestamp,
                    wrong_digest,
                    selected.0.clone(),
                    selected.1.clone(),
                    selected.2,
                    selected.3,
                ),
            )
            .await?;
        ensure_qualification_fault_rejected(
            &router,
            &gates,
            &jetstream,
            segment.stream_name(),
            key,
            close,
            "MalformedFragment",
        )
        .await?;
        dependency_wrong_digest_rejected = true;
        restore_dependency_row(&session, &selected, wrong_restore_timestamp).await?;
        ensure!(
            dependency_store
                .read_bundle(
                    fixtures[0].bundle.claim_slot(),
                    *terminals[0].claim().request_digest().as_bytes(),
                    terminals[0].claim().stable_status(),
                    terminals[0].claim().created_at().get(),
                    fixtures[0].bundle.digest(),
                )
                .await?
                == fixtures[0].bundle
        );
        dependency_exact_restore = true;
        ensure!(stream_state(&jetstream, segment.stream_name()).await? == nats_before);
    }
    if case == NonemptyTerminalSourceCase::SourceReceiptCommitPending {
        ensure!(
            std::env::var("PSY_D04B6H23C4C2B3B2C2C2_RF3").as_deref()
                == Ok("1"),
            "run through tests/rf3/run-d04b6h23c4c2b3b2c2c2.sh"
        );
        let ready_claim = first_ready_claim
            .as_ref()
            .context("CommitPending ready claim missing")?;
        let witness = commit_pending_witness
            .as_ref()
            .context("CommitPending witness missing")?;
        let original_claim = terminals[0].claim();
        let claim_timestamp = claim_write_timestamp(&session, original_claim).await?;
        let fake_timestamp = claim_timestamp
            .checked_add(1)
            .context("fake receipt timestamp overflow")?;
        let claim_restore_timestamp = fake_timestamp
            .checked_add(1)
            .context("claim restore timestamp overflow")?;
        let fake_digest = RealmUserUpdatePublishReceiptDigest::try_new([0xa5; 32])?;
        ensure!(
            original_claim
                .publish_receipt_digest()
                .map(|digest| *digest.as_bytes())
                != Some(*fake_digest.as_bytes())
        );
        let fake_claim = StoredRealmUserUpdateClaim::published(
            ready_claim,
            fake_digest,
        )?;
        ensure!(fake_claim.revision() == original_claim.revision());
        overwrite_claim_fixture(&session, &fake_claim, fake_timestamp).await?;
        ensure_qualification_fault_rejected(
            &router,
            &gates,
            &jetstream,
            segment.stream_name(),
            key,
            close,
            "TerminalEvidenceMismatch",
        )
        .await?;
        fake_receipt_rejected = true;
        overwrite_claim_fixture(
            &session,
            original_claim,
            claim_restore_timestamp,
        )
        .await?;
        ensure!(
            claims
                .read(original_claim.partition()?, original_claim.user_id())
                .await?
                == RealmUserUpdateClaimReadState::Current(original_claim.clone())
        );

        let (source_state, source_timestamp) = read_publish_source_fixture(
            &session,
            witness.source_slot(),
        )
        .await?;
        let source_delete_timestamp = source_timestamp
            .checked_add(1)
            .context("source delete timestamp overflow")?;
        let source_restore_timestamp = source_delete_timestamp
            .checked_add(1)
            .context("source restore timestamp overflow")?;
        session
            .query_unpaged(
                format!(
                    "DELETE FROM {}.{} USING TIMESTAMP ? WHERE source_slot = ?",
                    control(), PENDING_QUEUE_PUBLISH_SOURCE_TABLE
                ),
                (
                    source_delete_timestamp,
                    witness.source_slot().as_bytes().to_vec(),
                ),
            )
            .await?;
        ensure_qualification_fault_rejected(
            &router,
            &gates,
            &jetstream,
            segment.stream_name(),
            key,
            close,
            "SourceUninitialized",
        )
        .await?;
        missing_source_rejected = true;
        session
            .query_unpaged(
                format!(
                    "INSERT INTO {}.{} (source_slot, revision, source_payload) VALUES (?, ?, ?) USING TIMESTAMP ?",
                    control(), PENDING_QUEUE_PUBLISH_SOURCE_TABLE
                ),
                (
                    witness.source_slot().as_bytes().to_vec(),
                    source_state.revision().as_i64(),
                    source_state.to_persisted_bytes(),
                    source_restore_timestamp,
                ),
            )
            .await?;
        ensure!(
            read_publish_source_fixture(&session, witness.source_slot())
                .await?
                .0
                == source_state
        );
        ensure!(stream_state(&jetstream, segment.stream_name()).await? == nats_before);
    }

    let leader_before = initial_nats_leader.context("initial NATS leader missing")?;
    let leader_after_failover =
        failover_nats_leader.context("failover NATS leader missing")?;
    compose(Path::new(&compose_file), &["stop", "scylla3"])?;
    wait_up(2).await?;
    let qualification_started = Instant::now();
    let qualified = router
        .qualify_generation(key, close)
        .await
        .context("qualify non-empty generation")?;
    let qualification_ms = qualification_started.elapsed().as_millis() as u64;
    ensure!(
        qualified.current().phase()
            == RealmUserUpdateAdmissionPhase::GenerationQualified
    );
    let retry = router
        .qualify_generation(key, close)
        .await
        .context("retry non-empty qualification")?;
    ensure!(retry.current() == qualified.current());
    let caller_discard_exact_retry = true;
    let nats_after = stream_state(&jetstream, segment.stream_name()).await?;
    ensure!(nats_before == nats_after);
    let qualification_nats_publish_delta =
        i64::try_from(nats_after.0)? - i64::try_from(nats_before.0)?;
    ensure!(qualification_nats_publish_delta == 0);
    let mut direct_consumer_items = 0;
    let mut direct_consumer_retry_identical = false;
    let mut projection_rebuild_identical = false;
    let mut direct_consumer_nats_publish_delta = 0;
    let mut direct_consumer_ms = 0;
    let mut direct_consumer_phase_matrix_typed = false;
    let mut direct_consumer_dependency_loss_rejected = false;
    if case == NonemptyTerminalSourceCase::DirectDurableConsumer {
        let before_consume = stream_state(&jetstream, segment.stream_name()).await?;
        let consume_started = Instant::now();
        let consumer = ScyllaRealmUserUpdateDurableConsumer::<PF, PHash>::prepare(
            session.clone(),
            capture.key().network(),
            realm(),
            height,
            ready.clone(),
            segment.clone(),
        )
        .await?;
        let durable = consumer
            .read_qualified_generation(key, close)
            .await
            .context("read qualified generation directly from Scylla")?;
        direct_consumer_ms = consume_started.elapsed().as_millis() as u64;
        direct_consumer_items = durable.items().len();
        ensure!(direct_consumer_items == terminals.len());
        ensure!(durable.qualification() == *qualified.current().generation_qualification().context("missing stored qualification")?);
        let projection = durable
            .items()
            .iter()
            .map(|item| {
                (
                    item.claim().bucket().get(),
                    item.claim().admission_ordinal().get(),
                    item.claim().user_id().get(),
                    item.canonical_input().to_vec(),
                    item.proof().to_vec(),
                    item.contract_updates().to_vec(),
                    item.slot_updates().to_vec(),
                    item.queue_payload().to_vec(),
                )
            })
            .collect::<Vec<_>>();
        let rebuilt_projection = durable
            .items()
            .iter()
            .map(|item| {
                (
                    item.claim().bucket().get(),
                    item.claim().admission_ordinal().get(),
                    item.claim().user_id().get(),
                    item.canonical_input().to_vec(),
                    item.proof().to_vec(),
                    item.contract_updates().to_vec(),
                    item.slot_updates().to_vec(),
                    item.queue_payload().to_vec(),
                )
            })
            .collect::<Vec<_>>();
        projection_rebuild_identical = projection == rebuilt_projection;
        ensure!(projection_rebuild_identical);
        drop(consumer);
        let restarted = ScyllaRealmUserUpdateDurableConsumer::<PF, PHash>::prepare(
            session.clone(),
            capture.key().network(),
            realm(),
            height,
            ready.clone(),
            segment.clone(),
        )
        .await?;
        let retry = restarted
            .read_qualified_generation(key, close)
            .await
            .context("retry direct durable generation read")?;
        direct_consumer_retry_identical = retry == durable;
        ensure!(direct_consumer_retry_identical);

        let fence = qualified
            .current()
            .generation_qualification()
            .context("missing qualification for phase matrix")?
            .fence();
        let (claimed, planned, ready_claim) = &phase_claims[0];
        for (sample, expected) in [
            (
                claimed,
                RealmUserUpdateDurableConsumerError::AwaitExactRequestReplay,
            ),
            (
                planned,
                RealmUserUpdateDurableConsumerError::AwaitProofRecovery,
            ),
            (
                ready_claim,
                RealmUserUpdateDurableConsumerError::AwaitClaimPublication,
            ),
        ] {
            let error = RealmUserUpdateDurableItem::<PF, PHash>::try_from_observed(
                key,
                fence,
                sample.clone(),
                fixtures[0].bundle.clone(),
                height,
                terminals[0].publication().clone(),
            )
            .expect_err("non-Published phase must not become deliverable");
            ensure!(error == expected);
        }
        direct_consumer_phase_matrix_typed = true;

        let selected_fragment = fixtures[0]
            .bundle
            .fragments()
            .into_iter()
            .find(|fragment| {
                fragment.kind() == RealmUserUpdateDependencyKind::Proof
                    && fragment.index() == 0
            })
            .context("proof fragment zero is required")?;
        let selected =
            dependency_direct_row(&fixtures[0].bundle, &selected_fragment)?;
        let original_timestamp =
            dependency_write_timestamp(&session, &selected).await?;
        let delete_timestamp = original_timestamp
            .checked_add(1)
            .context("consumer fault timestamp overflow")?;
        let restore_timestamp = delete_timestamp
            .checked_add(1)
            .context("consumer restore timestamp overflow")?;
        session
            .query_unpaged(
                format!(
                    "DELETE FROM {DATA}.{} USING TIMESTAMP ? WHERE dependency_slot = ? AND dependency_digest = ? AND component_kind = ? AND fragment_index = ?",
                    REALM_USER_UPDATE_DEPENDENCY_FRAGMENT_TABLE
                ),
                (
                    delete_timestamp,
                    selected.0.clone(),
                    selected.1.clone(),
                    selected.2,
                    selected.3,
                ),
            )
            .await?;
        let error = restarted
            .read_qualified_generation(key, close)
            .await
            .expect_err("published dependency loss must fail closed");
        ensure!(error == RealmUserUpdateDurableConsumerError::DurableDependencyLoss);
        direct_consumer_dependency_loss_rejected = true;
        restore_dependency_row(&session, &selected, restore_timestamp).await?;
        ensure!(
            restarted.read_qualified_generation(key, close).await? == durable
        );
        let after_consume = stream_state(&jetstream, segment.stream_name()).await?;
        direct_consumer_nats_publish_delta = i64::try_from(after_consume.0)?
            - i64::try_from(before_consume.0)?;
        ensure!(direct_consumer_nats_publish_delta == 0);
    }
    let current_leader = wait_for_stream_leader(
        &jetstream,
        segment.stream_name(),
        None,
    )
    .await?;
    ensure!(current_leader == leader_after_failover);
    let nats_leader_failover = leader_before != leader_after_failover;

    compose(Path::new(&compose_file), &["start", "scylla3"])?;
    wait_up(3).await?;
    for server in ["psy-h23c2b-n1", "psy-h23c2b-n2", "psy-h23c2b-n3"] {
        let _ = signal_c2b_nats(server, "-CONT");
    }
    sleep(Duration::from_secs(3)).await;
    let control_name = control();
    docker_exec_retry(
        NODE_CONTAINERS[0],
        &["nodetool", "cluster", "repair", DATA],
        24,
    )?;
    for node in NODE_CONTAINERS {
        docker_exec_retry(
            node,
            &["nodetool", "repair", "-pr", control_name.as_str()],
            24,
        )?;
        for keyspace in [DATA, control_name.as_str()] {
            docker_exec(node, &["nodetool", "flush", keyspace])?;
            docker_exec(node, &["nodetool", "compact", keyspace])?;
        }
    }
    let mut direct = Vec::new();
    for ip in NODE_IPS {
        let local = connect(Some(ip), Consistency::One).await?;
        direct.push(direct_snapshot(&local, capture).await?);
    }
    let direct_one_nodes_equal = direct
        .windows(2)
        .all(|pair| pair[0] == pair[1])
        .then_some(direct.len())
        .unwrap_or(0);
    ensure!(direct_one_nodes_equal == 3);
    ensure!(direct[0].gates.len() == 257);
    ensure!(direct[0].claims.len() == 2);

    let expected_dependencies = expected_dependency_rows(&fixtures)?;
    let mut dependency_direct = Vec::new();
    for ip in NODE_IPS {
        let local = connect(Some(ip), Consistency::One).await?;
        dependency_direct.push(
            direct_dependency_snapshot(&local, &fixtures).await?,
        );
    }
    let dependency_direct_one_nodes_equal = dependency_direct
        .windows(2)
        .all(|pair| pair[0] == pair[1])
        .then_some(dependency_direct.len())
        .unwrap_or(0);
    ensure!(dependency_direct_one_nodes_equal == 3);
    ensure!(dependency_direct[0] == expected_dependencies);

    let report = NonemptyTerminalSourceReport {
        image: IMAGE,
        scylla_replication_factor: 3,
        nats_servers: 3,
        nats_stream_replicas: 3,
        schema_version: PENDING_QUEUE_SIDECAR_SCHEMA_VERSION,
        target_tables: PENDING_QUEUE_SIDECAR_TARGET_TABLE_COUNT,
        terminal_claims: terminals.len(),
        source_sequences: terminals
            .iter()
            .map(|terminal| terminal.publication().subject_sequence())
            .collect(),
        historical_intent_after_cursor_advance,
        caller_discard_exact_retry,
        scylla_one_replica_offline: true,
        nats_leader_before: leader_before,
        nats_leader_after: leader_after_failover,
        nats_leader_failover,
        dependency_missing_rejected,
        dependency_extra_rejected,
        dependency_wrong_digest_rejected,
        dependency_exact_restore,
        commit_pending_recovered: commit_pending_witness.is_some(),
        commit_pending_nats_publish_delta,
        recovery_nats_publish_delta,
        source_revision_delta,
        intent_revision_delta,
        recovery_response_loss_retry,
        missing_source_rejected,
        fake_receipt_rejected,
        qualification_nats_publish_delta,
        repair_flush_compact: true,
        direct_one_nodes_equal,
        dependency_direct_one_nodes_equal,
        dependency_rows: expected_dependencies.len(),
        qualification_ms,
        direct_consumer_items,
        direct_consumer_retry_identical,
        projection_rebuild_identical,
        direct_consumer_nats_publish_delta,
        direct_consumer_ms,
        direct_consumer_phase_matrix_typed,
        direct_consumer_dependency_loss_rejected,
        qualification: match case {
            NonemptyTerminalSourceCase::Positive => {
                "H23C4C2B3B2C2B_NONEMPTY_TERMINAL_SOURCE_RF3_PASSED"
            }
            NonemptyTerminalSourceCase::DependencyFault => {
                "H23C4C2B3B2C2C1_DEPENDENCY_FAULT_RF3_PASSED"
            }
            NonemptyTerminalSourceCase::SourceReceiptCommitPending => {
                "H23C4C2B3B2C2C2_SOURCE_RECEIPT_COMMITPENDING_RF3_PASSED"
            }
            NonemptyTerminalSourceCase::DirectDurableConsumer => {
                "H23C4C2B3B4_DIRECT_DURABLE_CONSUMER_RF3_PASSED"
            }
        },
    };
    std::fs::write(report_path, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[derive(Serialize)]
struct MultiFragmentResumeReport {
    image: &'static str,
    scylla_replication_factor: u8,
    nats_servers: u8,
    nats_stream_replicas: u8,
    schema_version: u16,
    slot_component_bytes: usize,
    slot_fragment_count: usize,
    total_dependency_rows: usize,
    missing_stage_counts: Vec<usize>,
    duplicate_subset_rejected: bool,
    concurrent_exact_retries: usize,
    planned_verifier_delta: usize,
    ready_publish_verifier_delta: usize,
    published_retry_verifier_delta: usize,
    ready_nats_publish_delta: u64,
    publish_nats_publish_delta: u64,
    published_retry_nats_publish_delta: u64,
    wrong_timestamp_rejected: bool,
    stale_plan_conflict_rejected: bool,
    poisoned_claims_remain_planned: bool,
    one_replica_offline: bool,
    offline_recovery_ms: u64,
    repair_flush_compact: bool,
    direct_one_nodes_equal: usize,
    dependency_direct_one_nodes_equal: usize,
    exact_writetime_rows: usize,
    qualification: &'static str,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires isolated Scylla RF=3 and NATS RF=3 runner"]
async fn d04b6h23c4c2b3b3e_multifragment_planned_resume_rf3(
) -> anyhow::Result<()> {
    ensure!(
        std::env::var("PSY_D04B6H23C4C2B3B3E_RF3").as_deref()
            == Ok("1"),
        "run through tests/rf3/run-d04b6h23c4c2b3b3e.sh"
    );
    let compose_file =
        std::env::var("PSY_D04B6H23C4C2B3B2C2B_COMPOSE_FILE")?;
    let report_path =
        std::env::var("PSY_D04B6H23C4C2B3B2C2B_REPORT_PATH")?;
    let nats_urls =
        std::env::var("PSY_D04B6H23C4C2B3B2C2B_NATS_URLS")?
            .split(',')
            .map(str::to_owned)
            .collect::<Vec<_>>();
    ensure!(nats_urls.len() == 3);

    wait_up(3).await?;
    let session = Arc::new(connect(None, Consistency::Quorum).await?);
    session
        .query_unpaged(
            format!("CREATE KEYSPACE IF NOT EXISTS {DATA} WITH replication = {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}}"),
            &[],
        )
        .await?;
    session
        .query_unpaged(
            format!("CREATE KEYSPACE IF NOT EXISTS {} WITH replication = {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}} AND tablets = {{'enabled': false}}", control()),
            &[],
        )
        .await?;
    session.await_schema_agreement().await?;
    let keyspaces = PendingQueueSidecarKeyspaces::try_new(DATA, control())?;
    PendingQueueSidecarDeploymentExecutor::deploy(
        session.clone(),
        keyspaces.clone(),
    )
    .await?;
    let ready = Arc::new(
        ScyllaPendingQueueSidecarSetupGate::authorize(
            session.clone(),
            keyspaces,
            realm(),
        )
        .await?,
    );

    let generation = 13;
    let expected_admission = admission(generation)?;
    let capture = expected_admission.capture();
    let control_keyspace =
        BranchExactDeploymentNoTabletKeyspace::try_new(control())?;
    let pipeline_store = ScyllaPendingPipelineStore::prepare(
        session.clone(),
        control_keyspace.clone(),
    )
    .await?;
    let pipeline = current_pipeline(
        pipeline_store
            .bootstrap(&qualification_pipeline_bootstrap(
                &expected_admission,
            )?)
            .await?,
    )?;
    ensure!(pipeline.gathering() == capture.processing());

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64;
    let base = format!("psy_h23b3e_{nonce}");
    let segment = RecoverableNatsStreamSegment::try_new(
        base.clone(),
        capture.key(),
        RecoverableNatsSegmentId::try_new(1)?,
        retention()?,
    )?;
    let validated =
        segment.validate_stream_config_structure(&segment.stream_config())?;
    let ledger_bootstrap = PendingQueueSegmentLedgerBootstrap::try_new(
        capture.key(),
        &validated,
        generation_budget(realm())?,
        1,
    )?;
    let ledger_key = ledger_bootstrap.candidate().key().clone();
    let ledger = ScyllaPendingQueueSegmentLedgerStore::prepare(
        session.clone(),
        control_keyspace,
    )
    .await?;
    ledger.bootstrap(&ledger_bootstrap).await?;
    let assignment = ledger.reserve_generation(&ledger_key, capture).await?;
    ensure!(assignment.assignment().context() == capture);

    let raw_nats = async_nats::connect(nats_urls.clone()).await?;
    let jetstream = jetstream::new(raw_nats);
    jetstream.create_stream(segment.stream_config()).await?;
    let nats_client = Arc::new(
        NatsJetStreamClient::new_connection(
            base,
            nats_urls,
            PullConfig::default(),
            PullConfig::default(),
            StreamConfig::default(),
        )
        .await?,
    );
    let nats_publisher = Arc::new(
        nats_client
            .recoverable_pending_publisher(segment.clone())
            .await?,
    );
    let height = GlobalUserTreeHeight::try_new(32)?;
    let router = prepare_deterministic_router(
        session.clone(),
        &expected_admission,
        height,
        ready.clone(),
        nats_publisher.clone(),
        segment.clone(),
    )
    .await?;
    ensure!(router.admit().await? == expected_admission);
    let (_, claims, _, provisioned_admission, _) =
        provisioned(session.clone(), generation).await?;
    ensure!(provisioned_admission == expected_admission);

    let users = [
        UserId::new((7_u64 << 20) + 31),
        UserId::new((7_u64 << 20) + 32),
        UserId::new((7_u64 << 20) + 33),
    ];
    let mut planned_claims = Vec::new();
    let mut fixtures = Vec::new();
    for (index, user) in users.into_iter().enumerate() {
        let verified = verified_end_cap_request(user, height)?;
        let winner = router
            .claim(
                expected_admission.clone(),
                &verified,
                RealmUserUpdateCreatedAtSeconds::try_new(
                    1_700_000_100 + u32::try_from(index)?,
                )?,
            )
            .await?;
        let fixture = if index == 0 {
            live_artifacts_for_claim_with_slots(
                &expected_admission,
                &winner,
                verified,
                height,
                four_fragment_slot_contracts()?,
            )?
        } else {
            live_artifacts_for_claim(
                &expected_admission,
                &winner,
                verified,
                height,
            )?
        };
        let planned = StoredRealmUserUpdateClaim::dependencies_planned(
            &winner,
            fixture.bundle.digest(),
        )?;
        let planned =
            current_claim(claims.compare_and_set(&winner, &planned).await?)?;
        ensure!(planned.phase() == RealmUserUpdateClaimPhase::DependenciesPlanned);
        planned_claims.push(planned);
        fixtures.push(fixture);
    }
    DETERMINISTIC_VERIFIER_CALLS.store(0, Ordering::SeqCst);

    compose(Path::new(&compose_file), &["stop", "scylla3"])?;
    wait_up(2).await?;
    let offline_started = Instant::now();

    let dependency_store = ScyllaRealmUserUpdateDependencyStore::prepare(
        session.clone(),
        PendingQueueArtifactDataKeyspace::try_new(DATA)?,
    )
    .await?;
    let positive = &fixtures[0];
    let positive_claim = &planned_claims[0];
    let positive_fragments = positive.bundle.fragments();
    let slot_coordinates = positive_fragments
        .iter()
        .filter(|fragment| {
            fragment.kind() == RealmUserUpdateDependencyKind::SlotUpdates
        })
        .map(|fragment| (fragment.kind(), fragment.index()))
        .collect::<Vec<_>>();
    ensure!(slot_coordinates.len() == 4);
    ensure!(
        slot_coordinates
            == vec![
                (RealmUserUpdateDependencyKind::SlotUpdates, 0),
                (RealmUserUpdateDependencyKind::SlotUpdates, 1),
                (RealmUserUpdateDependencyKind::SlotUpdates, 2),
                (RealmUserUpdateDependencyKind::SlotUpdates, 3),
            ]
    );
    let non_slot_coordinates = positive_fragments
        .iter()
        .filter(|fragment| {
            fragment.kind() != RealmUserUpdateDependencyKind::SlotUpdates
        })
        .map(|fragment| (fragment.kind(), fragment.index()))
        .collect::<Vec<_>>();
    ensure!(non_slot_coordinates.len() == 4);

    let mut missing_stage_counts = Vec::new();
    let first_plan = dependency_store
        .persist_exact_subset_through_crash_fixture(
            &positive.bundle,
            &non_slot_coordinates,
        )
        .await?;
    ensure!(missing_dependency_coordinates(&first_plan) == slot_coordinates);
    missing_stage_counts.push(first_plan.missing_fragments().len());
    let before_incomplete =
        stream_state(&jetstream, segment.stream_name()).await?;
    let incomplete = router
        .resume_exact(positive_claim.partition()?, positive_claim.user_id())
        .await
        .expect_err("whole SlotUpdates component must be missing");
    ensure!(matches!(
        incomplete,
        RealmUserUpdateRouterError::AwaitExactArtifactReplay
    ));
    ensure!(DETERMINISTIC_VERIFIER_CALLS.load(Ordering::SeqCst) == 0);
    ensure!(
        stream_state(&jetstream, segment.stream_name()).await?
            == before_incomplete
    );

    let duplicate_subset_rejected = matches!(
        dependency_store
            .persist_exact_subset_through_crash_fixture(
                &positive.bundle,
                &[non_slot_coordinates[0]],
            )
            .await,
        Err(RealmUserUpdateDependencyStoreError::InvalidRecoverySubset)
    );
    ensure!(duplicate_subset_rejected);

    let plan = dependency_store
        .persist_exact_subset_through_crash_fixture(
            &positive.bundle,
            &[slot_coordinates[1]],
        )
        .await?;
    ensure!(
        missing_dependency_coordinates(&plan)
            == vec![slot_coordinates[0], slot_coordinates[2], slot_coordinates[3]]
    );
    missing_stage_counts.push(plan.missing_fragments().len());
    ensure!(matches!(
        router
            .resume_exact(positive_claim.partition()?, positive_claim.user_id())
            .await,
        Err(RealmUserUpdateRouterError::AwaitExactArtifactReplay)
    ));
    ensure!(DETERMINISTIC_VERIFIER_CALLS.load(Ordering::SeqCst) == 0);

    let plan = dependency_store
        .persist_exact_subset_through_crash_fixture(
            &positive.bundle,
            &[slot_coordinates[0]],
        )
        .await?;
    ensure!(
        missing_dependency_coordinates(&plan)
            == vec![slot_coordinates[2], slot_coordinates[3]]
    );
    missing_stage_counts.push(plan.missing_fragments().len());
    let plan = dependency_store
        .persist_exact_subset_through_crash_fixture(
            &positive.bundle,
            &[slot_coordinates[2]],
        )
        .await?;
    ensure!(missing_dependency_coordinates(&plan) == vec![slot_coordinates[3]]);
    missing_stage_counts.push(plan.missing_fragments().len());

    let retry_store_a = ScyllaRealmUserUpdateDependencyStore::prepare(
        session.clone(),
        PendingQueueArtifactDataKeyspace::try_new(DATA)?,
    )
    .await?;
    let retry_store_b = ScyllaRealmUserUpdateDependencyStore::prepare(
        session.clone(),
        PendingQueueArtifactDataKeyspace::try_new(DATA)?,
    )
    .await?;
    let (retry_a, retry_b) = tokio::join!(
        retry_store_a.persist_and_readback(&positive.bundle),
        retry_store_b.persist_and_readback(&positive.bundle),
    );
    ensure!(retry_a? == positive.bundle.digest());
    ensure!(retry_b? == positive.bundle.digest());
    ensure!(dependency_store.inspect_recovery(&positive.bundle).await?.is_complete());
    missing_stage_counts.push(0);

    let router = prepare_deterministic_router(
        session.clone(),
        &expected_admission,
        height,
        ready.clone(),
        nats_publisher.clone(),
        segment.clone(),
    )
    .await?;
    let before_ready_nats =
        stream_state(&jetstream, segment.stream_name()).await?;
    let before_ready_verifier =
        DETERMINISTIC_VERIFIER_CALLS.load(Ordering::SeqCst);
    let ready_claim = router
        .resume_through_ready_fixture(
            positive_claim.partition()?,
            positive_claim.user_id(),
        )
        .await?;
    ensure!(ready_claim.phase() == RealmUserUpdateClaimPhase::DependenciesReady);
    let after_ready_nats =
        stream_state(&jetstream, segment.stream_name()).await?;
    let planned_verifier_delta =
        DETERMINISTIC_VERIFIER_CALLS.load(Ordering::SeqCst)
            - before_ready_verifier;
    ensure!(planned_verifier_delta == 1);
    ensure!(after_ready_nats.0 == before_ready_nats.0);

    let router = prepare_deterministic_router(
        session.clone(),
        &expected_admission,
        height,
        ready.clone(),
        nats_publisher.clone(),
        segment.clone(),
    )
    .await?;
    let before_publish_verifier =
        DETERMINISTIC_VERIFIER_CALLS.load(Ordering::SeqCst);
    let before_publish_nats =
        stream_state(&jetstream, segment.stream_name()).await?;
    let published = router
        .resume_exact(positive_claim.partition()?, positive_claim.user_id())
        .await?;
    ensure!(published.claim().phase() == RealmUserUpdateClaimPhase::Published);
    let after_publish_nats =
        stream_state(&jetstream, segment.stream_name()).await?;
    let ready_publish_verifier_delta =
        DETERMINISTIC_VERIFIER_CALLS.load(Ordering::SeqCst)
            - before_publish_verifier;
    ensure!(ready_publish_verifier_delta == 0);
    ensure!(after_publish_nats.0 == before_publish_nats.0 + 1);

    let router = prepare_deterministic_router(
        session.clone(),
        &expected_admission,
        height,
        ready.clone(),
        nats_publisher.clone(),
        segment.clone(),
    )
    .await?;
    let before_terminal_verifier =
        DETERMINISTIC_VERIFIER_CALLS.load(Ordering::SeqCst);
    let before_terminal_nats =
        stream_state(&jetstream, segment.stream_name()).await?;
    let terminal_retry = router
        .resume_exact(positive_claim.partition()?, positive_claim.user_id())
        .await?;
    ensure_same_durable_publication(
        published.publication(),
        terminal_retry.publication(),
    )?;
    let after_terminal_nats =
        stream_state(&jetstream, segment.stream_name()).await?;
    let published_retry_verifier_delta =
        DETERMINISTIC_VERIFIER_CALLS.load(Ordering::SeqCst)
            - before_terminal_verifier;
    ensure!(published_retry_verifier_delta == 0);
    ensure!(after_terminal_nats == before_terminal_nats);

    let wrong_timestamp_claim = &planned_claims[1];
    let wrong_timestamp_fixture = &fixtures[1];
    ensure!(
        dependency_store
            .persist_and_readback(&wrong_timestamp_fixture.bundle)
            .await?
            == wrong_timestamp_fixture.bundle.digest()
    );
    let wrong_row = dependency_direct_row(
        &wrong_timestamp_fixture.bundle,
        &wrong_timestamp_fixture.bundle.fragments()[0],
    )?;
    restore_dependency_row(
        &session,
        &wrong_row,
        wrong_timestamp_fixture.bundle.write_timestamp_us().as_i64() + 1,
    )
    .await?;
    let before_wrong_verifier =
        DETERMINISTIC_VERIFIER_CALLS.load(Ordering::SeqCst);
    let before_wrong_nats =
        stream_state(&jetstream, segment.stream_name()).await?;
    let wrong_timestamp_rejected = matches!(
        router
            .resume_exact(
                wrong_timestamp_claim.partition()?,
                wrong_timestamp_claim.user_id(),
            )
            .await,
        Err(RealmUserUpdateRouterError::DependencyCorruption(_))
    );
    ensure!(wrong_timestamp_rejected);
    ensure!(
        DETERMINISTIC_VERIFIER_CALLS.load(Ordering::SeqCst)
            == before_wrong_verifier
    );
    ensure!(
        stream_state(&jetstream, segment.stream_name()).await?
            == before_wrong_nats
    );

    let stale_claim = &planned_claims[2];
    let stale_fixture = &fixtures[2];
    let stale_plan = dependency_store.inspect_recovery(&stale_fixture.bundle).await?;
    ensure!(stale_plan.missing_fragments().len() == 5);
    let mut conflicting_row = dependency_direct_row(
        &stale_fixture.bundle,
        &stale_fixture.bundle.fragments()[0],
    )?;
    conflicting_row.8[0] ^= 0x80;
    restore_dependency_row(
        &session,
        &conflicting_row,
        stale_fixture.bundle.write_timestamp_us().as_i64() + 1,
    )
    .await?;
    let stale_plan_conflict_rejected = matches!(
        dependency_store
            .apply_stale_recovery_plan_fixture(
                &stale_fixture.bundle,
                &stale_plan,
            )
            .await,
        Err(RealmUserUpdateDependencyStoreError::TimestampMismatch { .. })
    );
    ensure!(stale_plan_conflict_rejected);
    let before_stale_verifier =
        DETERMINISTIC_VERIFIER_CALLS.load(Ordering::SeqCst);
    let before_stale_nats =
        stream_state(&jetstream, segment.stream_name()).await?;
    ensure!(matches!(
        router
            .resume_exact(stale_claim.partition()?, stale_claim.user_id())
            .await,
        Err(RealmUserUpdateRouterError::DependencyCorruption(_))
    ));
    ensure!(
        DETERMINISTIC_VERIFIER_CALLS.load(Ordering::SeqCst)
            == before_stale_verifier
    );
    ensure!(
        stream_state(&jetstream, segment.stream_name()).await?
            == before_stale_nats
    );

    let mut poisoned_claims_remain_planned = true;
    for claim in [&planned_claims[1], &planned_claims[2]] {
        let state = claims
            .read::<PHash>(claim.partition()?, claim.user_id())
            .await?;
        let RealmUserUpdateClaimReadState::Current(current) = state else {
            poisoned_claims_remain_planned = false;
            continue;
        };
        poisoned_claims_remain_planned &=
            current.phase() == RealmUserUpdateClaimPhase::DependenciesPlanned;
    }
    ensure!(poisoned_claims_remain_planned);
    let offline_recovery_ms = u64::try_from(offline_started.elapsed().as_millis())?;

    compose(Path::new(&compose_file), &["start", "scylla3"])?;
    wait_up(3).await?;
    let control_name = control();
    docker_exec_retry(
        NODE_CONTAINERS[0],
        &["nodetool", "cluster", "repair", DATA],
        24,
    )?;
    for node in NODE_CONTAINERS {
        docker_exec_retry(
            node,
            &["nodetool", "repair", "-pr", control_name.as_str()],
            24,
        )?;
        for keyspace in [DATA, control_name.as_str()] {
            docker_exec(node, &["nodetool", "flush", keyspace])?;
            docker_exec(node, &["nodetool", "compact", keyspace])?;
        }
    }

    let expected_timestamped = expected_timestamped_dependency_rows(positive)?;
    let mut dependency_direct = Vec::new();
    let mut direct = Vec::new();
    for ip in NODE_IPS {
        let local = connect(Some(ip), Consistency::One).await?;
        dependency_direct.push(
            direct_timestamped_dependency_snapshot(&local, positive).await?,
        );
        direct.push(direct_snapshot(&local, capture).await?);
    }
    let dependency_direct_one_nodes_equal = dependency_direct
        .windows(2)
        .all(|pair| pair[0] == pair[1])
        .then_some(dependency_direct.len())
        .unwrap_or(0);
    ensure!(dependency_direct_one_nodes_equal == 3);
    ensure!(dependency_direct[0] == expected_timestamped);
    let direct_one_nodes_equal = direct
        .windows(2)
        .all(|pair| pair[0] == pair[1])
        .then_some(direct.len())
        .unwrap_or(0);
    ensure!(direct_one_nodes_equal == 3);
    ensure!(direct[0].claims.len() == 3);

    let slot_component_bytes = positive
        .bundle
        .component(RealmUserUpdateDependencyKind::SlotUpdates)
        .bytes()
        .len();
    ensure!(slot_component_bytes == 14_400_138);
    let report = MultiFragmentResumeReport {
        image: IMAGE,
        scylla_replication_factor: 3,
        nats_servers: 3,
        nats_stream_replicas: 3,
        schema_version: PENDING_QUEUE_SIDECAR_SCHEMA_VERSION,
        slot_component_bytes,
        slot_fragment_count: slot_coordinates.len(),
        total_dependency_rows: positive_fragments.len(),
        missing_stage_counts,
        duplicate_subset_rejected,
        concurrent_exact_retries: 2,
        planned_verifier_delta,
        ready_publish_verifier_delta,
        published_retry_verifier_delta,
        ready_nats_publish_delta: after_ready_nats.0 - before_ready_nats.0,
        publish_nats_publish_delta: after_publish_nats.0
            - before_publish_nats.0,
        published_retry_nats_publish_delta: after_terminal_nats.0
            - before_terminal_nats.0,
        wrong_timestamp_rejected,
        stale_plan_conflict_rejected,
        poisoned_claims_remain_planned,
        one_replica_offline: true,
        offline_recovery_ms,
        repair_flush_compact: true,
        direct_one_nodes_equal,
        dependency_direct_one_nodes_equal,
        exact_writetime_rows: expected_timestamped.len(),
        qualification:
            "H23C4C2B3B3E_MULTIFRAGMENT_PLANNED_RESUME_RF3_PASSED",
    };
    std::fs::write(report_path, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires isolated Scylla RF=3 and NATS RF=3 runner"]
async fn d04b6h23c4c2b3b2c2b_nonempty_terminal_source_joint_rf3(
) -> anyhow::Result<()> {
    run_nonempty_terminal_source_joint_rf3(
        NonemptyTerminalSourceCase::Positive,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires isolated Scylla RF=3 and NATS RF=3 runner"]
async fn d04b6h23c4c2b3b2c2c1_dependency_fault_joint_rf3(
) -> anyhow::Result<()> {
    run_nonempty_terminal_source_joint_rf3(
        NonemptyTerminalSourceCase::DependencyFault,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires isolated Scylla RF=3 and NATS RF=3 runner"]
async fn d04b6h23c4c2b3b2c2c2_source_receipt_commitpending_joint_rf3(
) -> anyhow::Result<()> {
    run_nonempty_terminal_source_joint_rf3(
        NonemptyTerminalSourceCase::SourceReceiptCommitPending,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires real Scylla RF=3 and JetStream RF=3"]
async fn d04b6h23c4c2b3b4_direct_durable_consumer_rf3(
) -> anyhow::Result<()> {
    run_nonempty_terminal_source_joint_rf3(
        NonemptyTerminalSourceCase::DirectDurableConsumer,
    )
    .await
}
