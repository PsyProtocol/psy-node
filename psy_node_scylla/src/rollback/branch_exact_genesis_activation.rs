//! Explicit Genesis-native activation of the Realm branch-exact runtime.
//!
//! This is an operator path, not a serving fallback.  It composes the existing
//! durable stores in their required order and never fabricates a legacy export:
//! schema -> live empty audit -> timestamp -> writer -> local head -> pending
//! pipeline -> target-primary cutover.

use std::sync::Arc;

use anyhow::{bail, Context};
use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::chain_context::{AuthorityObservation, AuthorityScope};
use psy_node_core::{
    queue::realm_user_update_verifier_profile::RealmUserUpdateVerifierProfileId,
    store::{
        authority_commit::{
            AuthorityTimestampBootstrap, AuthorityTimestampBootstrapReason,
            AuthorityTimestampKey,
        },
        authority_local_head::{
            AuthorityLocalHeadBootstrap, AuthorityLocalHeadBootstrapReason,
            AuthorityLocalHeadReadState, AuthorityStorageBindingGeneration,
            AuthorityStorageBindingRef, AuthorityStorageNamespaceId,
        },
        branch_exact_schema::BranchExactSchemaMaterializationPlan,
        canonical_head::{CanonicalHeadBootstrap, CanonicalHeadBootstrapProfile},
        manifest_lifecycle::AuthorityHeadView,
        manifest_record::AuthorityManifestDigest,
        pending_generation::ProcNamespacePrefix,
        pending_generation_identity::{
            PendingGenerationActivationDigest, PendingGenerationContext,
            PendingGenerationLedgerKey,
        },
        pending_generation_pipeline::{
            PendingPipelineBootstrap, PendingPipelineWriteOutcome,
        },
        timestamp::CommitWriteTimestampUs,
    },
};
use scylla::client::session::Session;
use sha2::{Digest, Sha256};

use super::{
    resume_genesis_branch_exact_schema_deployment,
    AuthorityLocalHeadNoTabletKeyspace, AuthorityTimestampNoTabletKeyspace,
    BranchExactCutoverAuthorityKey, BranchExactCutoverBinding,
    BranchExactCutoverBootstrap,
    BranchExactCutoverGeneration, BranchExactCutoverPhase,
    BranchExactCutoverReadState,
    BranchExactCutoverWriteOutcome, BranchExactDeploymentNoTabletKeyspace,
    BranchExactExpectedTopology, BranchExactSchemaMaterializationRequest,
    BranchExactSchemaSetupRequest, BranchExactShadowAuditExecutionOutcome,
    BranchExactShadowAuditGeneration, BranchExactShadowAuditReadState,
    BranchExactShadowAuditState, BranchExactWriterActivationOutcome,
    BranchExactWriterActivationPlan, BranchExactWriterGeneration,
    BranchExactWriterVerifierProfile,
    CqlKeyspaceName,
    ScyllaAuthorityLocalHeadStore, ScyllaAuthorityTimestampStore,
    ScyllaBranchExactCutoverStore, ScyllaBranchExactSchemaSetupGate,
    ScyllaBranchExactShadowAuditExecutor, ScyllaBranchExactShadowAuditStore,
    ScyllaBranchExactShadowReader, ScyllaBranchExactWriterActivationExecutor,
    ScyllaBranchExactWriterLifecycleStore, ScyllaPendingPipelineStore,
    PendingQueueArtifactDataKeyspace,
    realm_rollback_genesis_anchor::RealmRollbackGenesisAnchor,
    realm_rollback_commit_inventory_store::ScyllaRealmRollbackCommitInventoryStore,
};

const GENESIS_EVIDENCE_DOMAIN: &[u8] =
    b"psy/rollback/realm-genesis-branch-exact-evidence/v1";
const GENESIS_STORAGE_DOMAIN: &[u8] =
    b"psy/rollback/realm-genesis-branch-exact-storage/v1";
const GENESIS_GENERATION: u64 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RealmGenesisBranchExactActivationSummary {
    generation: u64,
    binding_digest: [u8; 32],
    writer_activation_digest: [u8; 32],
}

impl RealmGenesisBranchExactActivationSummary {
    pub(crate) const fn generation(&self) -> u64 { self.generation }
    pub(crate) const fn binding_digest(&self) -> &[u8; 32] { &self.binding_digest }
    pub(crate) const fn writer_activation_digest(&self) -> &[u8; 32] {
        &self.writer_activation_digest
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn activate_realm_genesis_branch_exact<Hash>(
    session: Arc<Session>,
    targeted_sessions: &[Arc<Session>],
    data_keyspace: CqlKeyspaceName,
    control_keyspace: BranchExactDeploymentNoTabletKeyspace,
    expected_topology: BranchExactExpectedTopology,
    genesis: AuthorityObservation<Hash>,
    genesis_l2_block_state: Vec<u8>,
    verifier_profile: RealmUserUpdateVerifierProfileId,
) -> anyhow::Result<RealmGenesisBranchExactActivationSummary>
where
    Hash: Q256BitHash,
{
    let authority = genesis.authority();
    let AuthorityScope::Realm { .. } = authority else {
        bail!("Genesis branch-exact activation is Realm-only");
    };
    if genesis.chain().chain_epoch().get() != 0
        || genesis.chain().checkpoint().checkpoint_id().get() != 0
        || genesis.state_checkpoint_id().get() != 0
    {
        bail!("Genesis branch-exact activation requires the exact checkpoint-0 observation");
    }

    // Materialize every control table before recording the deployment
    // topology attestation. Scylla's schema version changes whenever another
    // table is created, so adding these tables after BACKFILL_VERIFIED would
    // make a clean restart reconstruct a different deployment receipt.
    create_control_schema(&session, &control_keyspace).await?;

    let cutover_key = BranchExactCutoverAuthorityKey::try_new(
        genesis.chain().network_id(),
        authority,
    )?;
    let cutover_store = ScyllaBranchExactCutoverStore::prepare(
        Arc::clone(&session),
        control_keyspace.clone(),
    )
    .await?;
    if let BranchExactCutoverReadState::Current(current) =
        cutover_store.read::<Hash>(cutover_key).await?
    {
        let binding = current.binding();
        if binding.generation().get() != GENESIS_GENERATION
            || binding.authority() != authority
            || binding.watermark().canonical_chain() != genesis.chain()
            || current.phase() != BranchExactCutoverPhase::TargetPrimaryDualWrite
        {
            bail!("durable Genesis branch-exact activation conflicts with requested Genesis");
        }
        let initial_timestamp = CommitWriteTimestampUs::try_from_i128(1)?;
        let target_head = genesis_local_head_bootstrap(genesis, initial_timestamp)?
            .candidate()
            .clone();
        let target_pipeline = genesis_pipeline_bootstrap(
            genesis,
            binding.writer_activation_digest_bytes(),
        )?
        .candidate()
        .clone();
        persist_genesis_rollback_anchor(
            Arc::clone(&session),
            &data_keyspace,
            &control_keyspace,
            genesis,
            genesis_l2_block_state,
            target_head,
            target_pipeline,
        )
        .await?;
        return Ok(RealmGenesisBranchExactActivationSummary {
            generation: binding.generation().get(),
            binding_digest: *binding.digest().as_bytes(),
            writer_activation_digest: *binding.writer_activation_digest_bytes(),
        });
    }

    let canonical_bootstrap = CanonicalHeadBootstrap::try_new(
        CanonicalHeadBootstrapProfile::GenesisNative,
        *genesis.chain(),
    )?;
    let materialization = BranchExactSchemaMaterializationPlan::try_new(
        &canonical_bootstrap,
        authority,
        None,
    )?;
    let request = BranchExactSchemaMaterializationRequest::try_new(
        data_keyspace.clone(),
        materialization,
    )?;
    let backfill = resume_genesis_branch_exact_schema_deployment(
        Arc::clone(&session),
        targeted_sessions,
        control_keyspace.clone(),
        &request,
        expected_topology,
    )
    .await?;
    let ready = ScyllaBranchExactSchemaSetupGate::authorize(
        Arc::clone(&session),
        data_keyspace.as_str(),
        control_keyspace.as_str(),
        authority,
        &BranchExactSchemaSetupRequest::new(backfill.clone()),
    )
    .await?;

    let reader = ScyllaBranchExactShadowReader::<Hash>::prepare_from_ready(
        Arc::clone(&session),
        data_keyspace.as_str(),
        &ready,
    )
    .await?;
    let shadow_store = ScyllaBranchExactShadowAuditStore::prepare(
        Arc::clone(&session),
        control_keyspace.clone(),
    )
    .await?;
    let shadow = match ScyllaBranchExactShadowAuditExecutor::run_genesis_empty(
        &shadow_store,
        &reader,
        &ready,
        BranchExactShadowAuditGeneration::try_new(GENESIS_GENERATION)?,
    )
    .await?
    {
        BranchExactShadowAuditExecutionOutcome::Verified(receipt)
        | BranchExactShadowAuditExecutionOutcome::Idempotent(receipt) => receipt,
    };

    let timestamp_key = AuthorityTimestampKey::new(genesis.chain().network_id(), authority);
    let timestamp_store = ScyllaAuthorityTimestampStore::prepare(
        Arc::clone(&session),
        AuthorityTimestampNoTabletKeyspace::try_new(
            control_keyspace.as_str().to_owned(),
        )?,
    )
    .await?;
    let initial_timestamp = CommitWriteTimestampUs::try_from_i128(1)?;
    timestamp_store
        .bootstrap(AuthorityTimestampBootstrap::new(
            timestamp_key,
            initial_timestamp,
            AuthorityTimestampBootstrapReason::GenesisNative,
        ))
        .await?;
    let observed_timestamp = timestamp_store
        .read_observed(timestamp_key)
        .await?
        .context("Genesis authority timestamp disappeared after bootstrap")?;

    let writer_plan = BranchExactWriterActivationPlan::try_genesis_realm(
        BranchExactWriterGeneration::try_new(GENESIS_GENERATION)?,
        &ready,
        &shadow,
        *genesis.chain(),
        observed_timestamp,
        BranchExactWriterVerifierProfile::Realm(verifier_profile),
    )?;
    let writer_store = ScyllaBranchExactWriterLifecycleStore::prepare(
        Arc::clone(&session),
        control_keyspace.clone(),
    )
    .await?;
    let writer = match ScyllaBranchExactWriterActivationExecutor::activate(
        &writer_store,
        &shadow_store,
        writer_plan.clone(),
    )
    .await?
    {
        BranchExactWriterActivationOutcome::Activated(writer)
        | BranchExactWriterActivationOutcome::Idempotent(writer) => writer,
    };

    let consumed = match shadow_store.read(writer_plan.shadow_audit_slot()).await? {
        BranchExactShadowAuditReadState::Current(stored) => match stored.state() {
            BranchExactShadowAuditState::Consumed(receipt)
                if receipt.writer_activation_digest() == writer_plan.digest() =>
            {
                receipt.clone()
            }
            _ => bail!("Genesis shadow audit was not consumed by the selected writer"),
        },
        BranchExactShadowAuditReadState::Uninitialized => {
            bail!("Genesis shadow audit disappeared after writer activation")
        }
    };

    let local_head = bootstrap_local_head(
        Arc::clone(&session),
        &control_keyspace,
        genesis,
        initial_timestamp,
    )
    .await?;
    let target_pipeline = bootstrap_pending_pipeline(
        Arc::clone(&session),
        &data_keyspace,
        &control_keyspace,
        genesis,
        writer_plan.digest().as_bytes(),
        initial_timestamp,
    )
    .await?;

    persist_genesis_rollback_anchor(
        Arc::clone(&session),
        &data_keyspace,
        &control_keyspace,
        genesis,
        genesis_l2_block_state,
        local_head.clone(),
        target_pipeline,
    )
    .await?;

    let binding = BranchExactCutoverBinding::try_from_current(
        BranchExactCutoverGeneration::try_new(GENESIS_GENERATION)?,
        &writer,
        &consumed,
        &local_head,
    )?;
    let cutover_bootstrap = BranchExactCutoverBootstrap::seal_genesis_target(binding);
    let selected = match cutover_store.bootstrap(&cutover_bootstrap).await? {
        BranchExactCutoverWriteOutcome::Applied(selected)
        | BranchExactCutoverWriteOutcome::Idempotent(selected)
        | BranchExactCutoverWriteOutcome::Conflict(selected) => selected,
    };
    if &selected != cutover_bootstrap.candidate() {
        bail!("Genesis branch-exact cutover conflicts with the durable route");
    }
    let BranchExactCutoverReadState::Current(readback) =
        cutover_store.read::<Hash>(cutover_key).await?
    else {
        bail!("Genesis branch-exact cutover disappeared after bootstrap");
    };
    if readback != selected {
        bail!("Genesis branch-exact cutover readback mismatch");
    }

    Ok(RealmGenesisBranchExactActivationSummary {
        generation: readback.binding().generation().get(),
        binding_digest: *readback.binding().digest().as_bytes(),
        writer_activation_digest: *writer_plan.digest().as_bytes(),
    })
}

async fn create_control_schema(
    session: &Session,
    control_keyspace: &BranchExactDeploymentNoTabletKeyspace,
) -> anyhow::Result<()> {
    ScyllaBranchExactShadowAuditStore::create_schema(session, control_keyspace).await?;
    ScyllaBranchExactWriterLifecycleStore::create_schema(session, control_keyspace).await?;
    ScyllaBranchExactCutoverStore::create_schema(session, control_keyspace).await?;
    ScyllaPendingPipelineStore::create_schema(session, control_keyspace).await?;
    let timestamp = AuthorityTimestampNoTabletKeyspace::try_new(
        control_keyspace.as_str().to_owned(),
    )?;
    ScyllaAuthorityTimestampStore::create_schema(session, &timestamp).await?;
    let head = AuthorityLocalHeadNoTabletKeyspace::try_new(
        control_keyspace.as_str().to_owned(),
    )?;
    ScyllaAuthorityLocalHeadStore::create_schema(session, &head).await?;
    Ok(())
}

async fn bootstrap_local_head<Hash: Q256BitHash>(
    session: Arc<Session>,
    control_keyspace: &BranchExactDeploymentNoTabletKeyspace,
    genesis: AuthorityObservation<Hash>,
    timestamp: CommitWriteTimestampUs,
) -> anyhow::Result<psy_node_core::store::authority_local_head::StoredAuthorityLocalHead<Hash>> {
    let bootstrap = genesis_local_head_bootstrap(genesis, timestamp)?;
    let store = ScyllaAuthorityLocalHeadStore::prepare(
        session,
        AuthorityLocalHeadNoTabletKeyspace::try_new(
            control_keyspace.as_str().to_owned(),
        )?,
    )
    .await?;
    store.bootstrap(&bootstrap).await?;
    let AuthorityLocalHeadReadState::Current(readback) = store.read(bootstrap.key()).await?
    else {
        bail!("Genesis authority-local head disappeared after bootstrap");
    };
    if &readback != bootstrap.candidate() {
        bail!("Genesis authority-local head conflicts with the durable row");
    }
    Ok(readback)
}

fn genesis_local_head_bootstrap<Hash: Q256BitHash>(
    genesis: AuthorityObservation<Hash>,
    timestamp: CommitWriteTimestampUs,
) -> anyhow::Result<AuthorityLocalHeadBootstrap<Hash>> {
    let canonical = genesis.to_canonical_bytes();
    let mut manifest = Sha256::new();
    manifest.update(GENESIS_EVIDENCE_DOMAIN);
    manifest.update(canonical);
    let manifest = AuthorityManifestDigest::from_persisted(manifest.finalize().into());
    let mut namespace = Sha256::new();
    namespace.update(GENESIS_STORAGE_DOMAIN);
    namespace.update(canonical);
    let binding = AuthorityStorageBindingRef::new(
        AuthorityStorageBindingGeneration::try_new(GENESIS_GENERATION)?,
        AuthorityStorageNamespaceId::from_verified_namespace_id(namespace.finalize().into()),
    );
    Ok(AuthorityLocalHeadBootstrap::seal(
        AuthorityLocalHeadBootstrapReason::GenesisNative,
        AuthorityHeadView::try_from_observed(
            AuthorityTimestampKey::new(genesis.chain().network_id(), genesis.authority()),
            *genesis.chain(),
            genesis.state_checkpoint_id(),
            *genesis.state_root(),
        )?,
        timestamp,
        manifest,
        binding,
    ))
}

async fn bootstrap_pending_pipeline<Hash: Q256BitHash>(
    session: Arc<Session>,
    _data_keyspace: &CqlKeyspaceName,
    control_keyspace: &BranchExactDeploymentNoTabletKeyspace,
    genesis: AuthorityObservation<Hash>,
    activation_digest: &[u8; 32],
    _timestamp: CommitWriteTimestampUs,
) -> anyhow::Result<psy_node_core::store::pending_generation_pipeline::StoredPendingPipeline<Hash>> {
    let bootstrap = genesis_pipeline_bootstrap(genesis, activation_digest)?;
    let store = ScyllaPendingPipelineStore::prepare(
        session,
        control_keyspace.clone(),
    )
    .await?;
    let current = match store.bootstrap(&bootstrap).await? {
        PendingPipelineWriteOutcome::Applied(current)
        | PendingPipelineWriteOutcome::Idempotent(current)
        | PendingPipelineWriteOutcome::Conflict(current) => current,
    };
    if current != *bootstrap.candidate() {
        bail!("Genesis pending pipeline conflicts with the expected Ready(1,2) state");
    }
    Ok(current)
}

fn genesis_pipeline_bootstrap<Hash: Q256BitHash>(
    genesis: AuthorityObservation<Hash>,
    activation_digest: &[u8; 32],
) -> anyhow::Result<PendingPipelineBootstrap<Hash>> {
    let prefix = ProcNamespacePrefix::for_authority(
        genesis.chain().network_id(),
        genesis.authority(),
    );
    let processing = PendingGenerationContext::try_from_legacy(
        1,
        prefix
            .derive_proc_id(psy_node_core::store::typed::UniquePendingId::try_new(1)?)
            .as_u128(),
    )?;
    let gathering = PendingGenerationContext::try_from_legacy(
        2,
        prefix
            .derive_proc_id(psy_node_core::store::typed::UniquePendingId::try_new(2)?)
            .as_u128(),
    )?;
    Ok(PendingPipelineBootstrap::try_new_ready_genesis(
        PendingGenerationLedgerKey::new(
            genesis.chain().network_id(),
            genesis.authority(),
        ),
        PendingGenerationActivationDigest::try_new(*activation_digest)?,
        prefix,
        processing,
        gathering,
        genesis,
    )?)
}

async fn persist_genesis_rollback_anchor<Hash: Q256BitHash>(
    session: Arc<Session>,
    data_keyspace: &CqlKeyspaceName,
    control_keyspace: &BranchExactDeploymentNoTabletKeyspace,
    genesis: AuthorityObservation<Hash>,
    genesis_l2_block_state: Vec<u8>,
    target_head: psy_node_core::store::authority_local_head::StoredAuthorityLocalHead<Hash>,
    target_pipeline: psy_node_core::store::pending_generation_pipeline::StoredPendingPipeline<Hash>,
) -> anyhow::Result<()> {
    let store = ScyllaRealmRollbackCommitInventoryStore::prepare(
        session,
        control_keyspace.clone(),
        PendingQueueArtifactDataKeyspace::try_new(data_keyspace.as_str().to_owned())?,
    )
    .await?;
    let anchor = RealmRollbackGenesisAnchor::try_new(
        genesis,
        genesis_l2_block_state,
        target_head,
        target_pipeline,
        store.genesis_anchor_fingerprint(),
    )?;
    let persisted = store.persist_genesis_anchor(anchor.clone()).await?;
    if persisted != anchor {
        bail!("Genesis rollback anchor exact readback mismatch");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use parth_core::PHash;
    use psy_data::protocol::{
        canonical_chain::{
            CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
            CheckpointRef, NetworkId,
        },
        chain_context::{AuthorityStateCheckpointId, AuthorityStateRoot},
    };

    use super::*;

    fn genesis() -> AuthorityObservation<PHash> {
        AuthorityObservation::try_new(
            CanonicalChainRef::new(
                NetworkId::try_from_chain_id(1337).unwrap(),
                ChainEpoch::new(0),
                CheckpointRef::new(
                    CheckpointId::new(0),
                    CheckpointHash::from_last_chain_hash(PHash::from_values(1, 2, 3, 4)),
                ),
            ),
            AuthorityScope::Realm {
                realm_id: 0,
                realm_sub_id: 0,
            },
            AuthorityStateCheckpointId::new(0),
            AuthorityStateRoot::from_local_state_root(PHash::from_values(5, 6, 7, 8)),
        )
        .unwrap()
    }

    #[test]
    fn genesis_anchor_roundtrips_exact_initial_head_pipeline_and_singletons() {
        let genesis = genesis();
        let timestamp = CommitWriteTimestampUs::try_from_i128(1).unwrap();
        let head = genesis_local_head_bootstrap(genesis, timestamp)
            .unwrap()
            .candidate()
            .clone();
        let pipeline = genesis_pipeline_bootstrap(genesis, &[9; 32])
            .unwrap()
            .candidate()
            .clone();
        let anchor = RealmRollbackGenesisAnchor::try_new(
            genesis,
            vec![11, 12, 13],
            head,
            pipeline,
            [17; 32],
        )
        .unwrap();
        let decoded = RealmRollbackGenesisAnchor::decode_persisted(
            anchor.canonical_bytes(),
        )
        .unwrap();
        assert_eq!(decoded, anchor);
        assert_eq!(decoded.target_puts().len(), 3);
        assert_eq!(decoded.target_pipeline().processed_pending_id(), 0);
    }

    #[test]
    fn genesis_anchor_rejects_outer_digest_tamper() {
        let genesis = genesis();
        let timestamp = CommitWriteTimestampUs::try_from_i128(1).unwrap();
        let anchor = RealmRollbackGenesisAnchor::try_new(
            genesis,
            vec![11, 12, 13],
            genesis_local_head_bootstrap(genesis, timestamp)
                .unwrap()
                .candidate()
                .clone(),
            genesis_pipeline_bootstrap(genesis, &[9; 32])
                .unwrap()
                .candidate()
                .clone(),
            [17; 32],
        )
        .unwrap();
        let mut bytes = anchor.canonical_bytes().to_vec();
        bytes[20] ^= 1;
        assert!(RealmRollbackGenesisAnchor::<PHash>::decode_persisted(&bytes).is_err());
    }
}
