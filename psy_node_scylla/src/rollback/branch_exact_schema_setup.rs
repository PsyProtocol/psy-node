//! Default-off production setup gate for the branch-exact migration schema.
//!
//! This module only proves that one authority's target schema and durable
//! backfill lifecycle are ready, then prepares read statements behind an
//! opaque token. It does not expose a reader, writer, cutover, Session, or
//! schema-creation capability.

use std::{error::Error, fmt, sync::Arc};

use psy_node_core::store::{
    branch_exact_schema::AuthorityScope,
    canonical_head::CanonicalHeadBootstrapProfile,
};
use scylla::{
    client::session::Session,
    statement::{prepared::PreparedStatement, Consistency},
};
use sha2::{Digest, Sha256};

use super::{
    BranchExactBackfillDatasetDigest, BranchExactBackfillReceiptDigest,
    BranchExactBackfillVerifiedReceipt,
    BranchExactDeploymentLifecyclePhase,
    BranchExactDeploymentLifecycleReadState,
    BranchExactDeploymentNoTabletKeyspace,
    BranchExactDeploymentRevision, BranchExactDeploymentSlotId,
    BranchExactQueries, BranchExactQuery, BranchExactQueryId,
    BranchExactSchemaFingerprint, BranchExactSchemaInspection,
    BranchExactSchemaMaterializer, CqlKeyspaceName,
    ScyllaBranchExactDeploymentLifecycleStore,
};

const BRANCH_EXACT_SETUP_READY_DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/branch-exact-schema-setup-ready/v1";

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum BranchExactSchemaSetupMode {
    #[default]
    Disabled,
    RequireVerified(BranchExactSchemaSetupRequest),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactSchemaSetupRequest {
    expected_receipt: BranchExactBackfillVerifiedReceipt,
}

impl BranchExactSchemaSetupRequest {
    pub fn new(expected_receipt: BranchExactBackfillVerifiedReceipt) -> Self {
        Self { expected_receipt }
    }

    pub const fn expected_receipt(&self) -> &BranchExactBackfillVerifiedReceipt {
        &self.expected_receipt
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BranchExactPreparedInventoryCounts {
    pub logical: usize,
    pub physical: usize,
    pub key_domains: usize,
}

impl BranchExactPreparedInventoryCounts {
    pub const DISABLED: Self = Self {
        logical: 32,
        physical: 35,
        key_domains: 39,
    };
    pub const COORDINATOR_READY: Self = Self {
        logical: 34,
        physical: 37,
        key_domains: 41,
    };
    pub const REALM_READY: Self = Self {
        logical: 35,
        physical: 38,
        key_domains: 42,
    };

    pub const fn for_authority(authority: AuthorityScope) -> Self {
        match authority {
            AuthorityScope::Coordinator => Self::COORDINATOR_READY,
            AuthorityScope::Realm { .. } => Self::REALM_READY,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BranchExactSchemaReadyDigest([u8; 32]);

impl BranchExactSchemaReadyDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactSchemaReadyView {
    digest: BranchExactSchemaReadyDigest,
    slot: BranchExactDeploymentSlotId,
    lifecycle_revision: BranchExactDeploymentRevision,
    authority: AuthorityScope,
    keyspace: CqlKeyspaceName,
    profile: CanonicalHeadBootstrapProfile,
    schema_fingerprint: BranchExactSchemaFingerprint,
    dataset_digest: BranchExactBackfillDatasetDigest,
    backfill_receipt_digest: BranchExactBackfillReceiptDigest,
    prepared_inventory: BranchExactPreparedInventoryCounts,
}

impl BranchExactSchemaReadyView {
    pub const fn digest(&self) -> BranchExactSchemaReadyDigest {
        self.digest
    }

    pub const fn slot(&self) -> BranchExactDeploymentSlotId {
        self.slot
    }

    pub const fn lifecycle_revision(&self) -> BranchExactDeploymentRevision {
        self.lifecycle_revision
    }

    pub const fn authority(&self) -> AuthorityScope {
        self.authority
    }

    pub const fn keyspace(&self) -> &CqlKeyspaceName {
        &self.keyspace
    }

    pub const fn profile(&self) -> CanonicalHeadBootstrapProfile {
        self.profile
    }

    pub const fn schema_fingerprint(&self) -> BranchExactSchemaFingerprint {
        self.schema_fingerprint
    }

    pub const fn dataset_digest(&self) -> BranchExactBackfillDatasetDigest {
        self.dataset_digest
    }

    pub const fn backfill_receipt_digest(&self) -> BranchExactBackfillReceiptDigest {
        self.backfill_receipt_digest
    }

    pub const fn prepared_inventory(&self) -> BranchExactPreparedInventoryCounts {
        self.prepared_inventory
    }
}

#[allow(dead_code)]
struct PreparedBranchExactSchemaSetup {
    forward_read: PreparedStatement,
    reverse_read: PreparedStatement,
    proof_read: Option<PreparedStatement>,
}

/// Opaque setup capability. Private fields and the absence of read/write
/// methods prevent setup readiness from becoming serving authority.
pub struct BranchExactSchemaReady {
    view: BranchExactSchemaReadyView,
    _prepared: PreparedBranchExactSchemaSetup,
}

impl fmt::Debug for BranchExactSchemaReady {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BranchExactSchemaReady")
            .field("view", &self.view)
            .finish_non_exhaustive()
    }
}

impl BranchExactSchemaReady {
    pub const fn view(&self) -> &BranchExactSchemaReadyView {
        &self.view
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactSchemaSetupOutcome {
    Disabled,
    Ready(BranchExactSchemaReadyView),
    Idempotent(BranchExactSchemaReadyView),
}

pub struct ScyllaBranchExactSchemaSetupGate;

impl ScyllaBranchExactSchemaSetupGate {
    pub async fn authorize(
        session: Arc<Session>,
        standard_keyspace: &str,
        no_tablet_keyspace: &str,
        expected_authority: AuthorityScope,
        request: &BranchExactSchemaSetupRequest,
    ) -> Result<BranchExactSchemaReady, BranchExactSchemaSetupError> {
        let receipt = request.expected_receipt();
        let plan = receipt.plan();
        let deployment = plan.deployment();
        let intent = deployment.intent();
        if intent.authority() != expected_authority {
            return Err(BranchExactSchemaSetupError::AuthorityMismatch {
                expected: expected_authority,
                actual: intent.authority(),
            });
        }
        if intent.keyspace().as_str() != standard_keyspace {
            return Err(BranchExactSchemaSetupError::KeyspaceMismatch {
                expected: standard_keyspace.to_owned(),
                actual: intent.keyspace().as_str().to_owned(),
            });
        }

        let control_keyspace = BranchExactDeploymentNoTabletKeyspace::try_new(
            no_tablet_keyspace.to_owned(),
        )
        .map_err(|error| BranchExactSchemaSetupError::Lifecycle(error.to_string()))?;
        let lifecycle = ScyllaBranchExactDeploymentLifecycleStore::prepare(
            session.clone(),
            control_keyspace,
        )
        .await
        .map_err(|error| BranchExactSchemaSetupError::Lifecycle(error.to_string()))?;
        let slot = BranchExactDeploymentSlotId::from_intent(intent);
        let before = require_exact_backfill_verified(
            lifecycle
                .read(slot)
                .await
                .map_err(|error| BranchExactSchemaSetupError::Lifecycle(error.to_string()))?,
            receipt,
        )?;

        let inspection = BranchExactSchemaMaterializer::inspect_schema(
            &session,
            intent.keyspace(),
            expected_authority,
        )
        .await
        .map_err(|error| BranchExactSchemaSetupError::Schema(error.to_string()))?;
        let BranchExactSchemaInspection::Exact { fingerprint } = inspection else {
            return Err(BranchExactSchemaSetupError::SchemaNotExact);
        };
        if fingerprint != deployment.schema_fingerprint() {
            return Err(BranchExactSchemaSetupError::SchemaFingerprintMismatch);
        }

        let queries = BranchExactQueries::new(intent.keyspace());
        let prepared = PreparedBranchExactSchemaSetup {
            forward_read: prepare_read(
                &session,
                queries.get(BranchExactQueryId::ReadBranchToPending),
            )
            .await?,
            reverse_read: prepare_read(
                &session,
                queries.get(BranchExactQueryId::ReadPendingToBranch),
            )
            .await?,
            proof_read: match expected_authority {
                AuthorityScope::Coordinator => None,
                AuthorityScope::Realm { .. } => Some(
                    prepare_read(
                        &session,
                        queries.get(BranchExactQueryId::ReadPendingRewardProof),
                    )
                    .await?,
                ),
            },
        };

        let after = require_exact_backfill_verified(
            lifecycle
                .read(slot)
                .await
                .map_err(|error| BranchExactSchemaSetupError::Lifecycle(error.to_string()))?,
            receipt,
        )?;
        if before != after {
            return Err(BranchExactSchemaSetupError::LifecycleChangedDuringSetup);
        }

        let prepared_inventory =
            BranchExactPreparedInventoryCounts::for_authority(expected_authority);
        let view = BranchExactSchemaReadyView {
            digest: ready_digest(
                slot,
                before.revision(),
                expected_authority,
                intent.keyspace(),
                intent.profile(),
                fingerprint,
                plan.dataset_digest(),
                receipt.digest(),
                prepared_inventory,
            ),
            slot,
            lifecycle_revision: before.revision(),
            authority: expected_authority,
            keyspace: intent.keyspace().clone(),
            profile: intent.profile(),
            schema_fingerprint: fingerprint,
            dataset_digest: plan.dataset_digest(),
            backfill_receipt_digest: receipt.digest(),
            prepared_inventory,
        };
        Ok(BranchExactSchemaReady {
            view,
            _prepared: prepared,
        })
    }
}

fn require_exact_backfill_verified(
    state: BranchExactDeploymentLifecycleReadState,
    expected: &BranchExactBackfillVerifiedReceipt,
) -> Result<super::StoredBranchExactDeploymentLifecycle, BranchExactSchemaSetupError> {
    let BranchExactDeploymentLifecycleReadState::Current(stored) = state else {
        return Err(BranchExactSchemaSetupError::LifecycleUninitialized);
    };
    let super::BranchExactDeploymentLifecycleState::BackfillVerified(actual) =
        stored.state()
    else {
        return Err(BranchExactSchemaSetupError::LifecycleNotBackfillVerified(
            stored.state().phase(),
        ));
    };
    if actual != expected {
        return Err(BranchExactSchemaSetupError::BackfillReceiptMismatch);
    }
    Ok(stored)
}

async fn prepare_read(
    session: &Session,
    query: &BranchExactQuery,
) -> Result<PreparedStatement, BranchExactSchemaSetupError> {
    let mut prepared = session
        .prepare(query.cql())
        .await
        .map_err(|error| BranchExactSchemaSetupError::Prepare(error.to_string()))?;
    prepared.set_consistency(Consistency::Quorum);
    prepared.set_is_idempotent(true);
    Ok(prepared)
}

#[allow(clippy::too_many_arguments)]
fn ready_digest(
    slot: BranchExactDeploymentSlotId,
    revision: BranchExactDeploymentRevision,
    authority: AuthorityScope,
    keyspace: &CqlKeyspaceName,
    profile: CanonicalHeadBootstrapProfile,
    schema_fingerprint: BranchExactSchemaFingerprint,
    dataset_digest: BranchExactBackfillDatasetDigest,
    receipt_digest: BranchExactBackfillReceiptDigest,
    inventory: BranchExactPreparedInventoryCounts,
) -> BranchExactSchemaReadyDigest {
    let mut hasher = Sha256::new();
    hasher.update(BRANCH_EXACT_SETUP_READY_DIGEST_DOMAIN);
    hasher.update(slot.as_bytes());
    hasher.update(revision.get().to_be_bytes());
    match authority {
        AuthorityScope::Coordinator => hasher.update([1, 0, 0, 0, 0, 0, 0]),
        AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } => {
            hasher.update([2]);
            hasher.update(realm_id.to_be_bytes());
            hasher.update(realm_sub_id.to_be_bytes());
        }
    }
    hasher.update((keyspace.as_str().len() as u64).to_be_bytes());
    hasher.update(keyspace.as_str().as_bytes());
    hasher.update([match profile {
        CanonicalHeadBootstrapProfile::GenesisNative => 1,
        CanonicalHeadBootstrapProfile::PostGenesisFloor => 2,
    }]);
    hasher.update(schema_fingerprint.as_bytes());
    hasher.update(dataset_digest.as_bytes());
    hasher.update(receipt_digest.as_bytes());
    hasher.update((inventory.logical as u64).to_be_bytes());
    hasher.update((inventory.physical as u64).to_be_bytes());
    hasher.update((inventory.key_domains as u64).to_be_bytes());
    BranchExactSchemaReadyDigest(hasher.finalize().into())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactSchemaSetupError {
    AuthorityMismatch {
        expected: AuthorityScope,
        actual: AuthorityScope,
    },
    KeyspaceMismatch { expected: String, actual: String },
    Lifecycle(String),
    LifecycleUninitialized,
    LifecycleNotBackfillVerified(BranchExactDeploymentLifecyclePhase),
    BackfillReceiptMismatch,
    Schema(String),
    SchemaNotExact,
    SchemaFingerprintMismatch,
    LifecycleChangedDuringSetup,
    Prepare(String),
    AlreadyInitializedWithDifferentReceipt,
}

impl fmt::Display for BranchExactSchemaSetupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for BranchExactSchemaSetupError {}

#[cfg(test)]
mod tests {
    use parth_core::PHash;
    use psy_data::protocol::canonical_chain::{
        CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
        CheckpointRef, NetworkId,
    };
    use psy_node_core::store::{
        branch_exact_schema::{
            AuthorityScope, BranchExactSchemaMaterializationPlan,
        },
        canonical_head::{CanonicalHeadBootstrap, CanonicalHeadBootstrapProfile},
    };

    use super::*;
    use crate::rollback::{
        branch_exact_schema_fingerprint, BranchExactBackfillPlan,
        BranchExactBackfillReadbackObservation,
        BranchExactDeploymentIntent, BranchExactDeploymentLifecycleBootstrap,
        BranchExactExpectedTopology, BranchExactNodeSchemaPostflight,
        BranchExactSchemaMaterializationRequest,
        BranchExactSchemaOnlyReceipt, BranchExactScyllaNodeId,
        BranchExactScyllaSchemaVersion, BranchExactTopologyAttestation,
        BranchExactVerifiedDeploymentReceipt,
        SealedBranchExactBackfillPlanCas,
        SealedBranchExactBackfillVerifiedCas,
        SealedBranchExactSchemaVerifiedCas,
        StoredBranchExactDeploymentLifecycle,
    };

    fn request(
        keyspace: &str,
        authority: AuthorityScope,
    ) -> BranchExactSchemaMaterializationRequest {
        let bootstrap = CanonicalHeadBootstrap::try_new(
            CanonicalHeadBootstrapProfile::GenesisNative,
            CanonicalChainRef::new(
                NetworkId::try_from_chain_id(1337).unwrap(),
                ChainEpoch::new(0),
                CheckpointRef::new(
                    CheckpointId::new(0),
                    CheckpointHash::from_last_chain_hash(PHash::from_values(
                        1, 2, 3, 4,
                    )),
                ),
            ),
        )
        .unwrap();
        let plan = BranchExactSchemaMaterializationPlan::try_new(
            &bootstrap, authority, None,
        )
        .unwrap();
        BranchExactSchemaMaterializationRequest::try_new(
            CqlKeyspaceName::try_new(keyspace).unwrap(),
            plan,
        )
        .unwrap()
    }

    fn verified_deployment(
        request: &BranchExactSchemaMaterializationRequest,
    ) -> BranchExactVerifiedDeploymentReceipt {
        let authority = request.plan().authority();
        let fingerprint = branch_exact_schema_fingerprint(authority);
        let schema = BranchExactSchemaOnlyReceipt::from_verified_parts_for_deployment(
            request,
            fingerprint,
        );
        let topology = BranchExactExpectedTopology::try_new(
            [1_u8, 2, 3]
                .map(|value| BranchExactScyllaNodeId::try_new([value; 16]).unwrap())
                .to_vec(),
        )
        .unwrap();
        let observations = topology
            .nodes()
            .iter()
            .copied()
            .map(|node| {
                BranchExactNodeSchemaPostflight::try_new(
                    node,
                    BranchExactScyllaSchemaVersion::try_new([9; 16]).unwrap(),
                    BranchExactSchemaInspection::Exact { fingerprint },
                )
                .unwrap()
            })
            .collect();
        let attestation = BranchExactTopologyAttestation::try_new(
            &schema,
            topology.clone(),
            observations,
        )
        .unwrap();
        BranchExactVerifiedDeploymentReceipt::try_new(
            BranchExactDeploymentIntent::new(request, topology),
            attestation,
        )
        .unwrap()
    }

    fn lifecycle_states(
        keyspace: &str,
    ) -> (
        StoredBranchExactDeploymentLifecycle,
        StoredBranchExactDeploymentLifecycle,
        StoredBranchExactDeploymentLifecycle,
        StoredBranchExactDeploymentLifecycle,
        BranchExactBackfillVerifiedReceipt,
    ) {
        let request = request(keyspace, AuthorityScope::Coordinator);
        let deployment = verified_deployment(&request);
        let intent = BranchExactDeploymentLifecycleBootstrap::new(
            deployment.intent().clone(),
        )
        .candidate()
        .clone();
        let schema = SealedBranchExactSchemaVerifiedCas::try_new(
            &intent,
            deployment.clone(),
        )
        .unwrap()
        .candidate()
        .clone();
        let plan = BranchExactBackfillPlan::genesis_empty(
            &request,
            deployment,
        )
        .unwrap();
        let planned = SealedBranchExactBackfillPlanCas::try_new(&schema, plan.clone())
            .unwrap()
            .candidate()
            .clone();
        let observation = BranchExactBackfillReadbackObservation::new(
            plan.digest(),
            plan.dataset_digest(),
            0,
            0,
            0,
        );
        let final_state = SealedBranchExactBackfillVerifiedCas::try_new(
            &planned,
            observation,
        )
        .unwrap()
        .candidate()
        .clone();
        let receipt = match final_state.state() {
            super::super::BranchExactDeploymentLifecycleState::BackfillVerified(
                receipt,
            ) => receipt.clone(),
            _ => unreachable!(),
        };
        (intent, schema, planned, final_state, receipt)
    }

    #[test]
    fn setup_is_default_off_and_inventory_profiles_are_exact() {
        assert_eq!(
            BranchExactSchemaSetupMode::default(),
            BranchExactSchemaSetupMode::Disabled
        );
        assert_eq!(
            BranchExactPreparedInventoryCounts::DISABLED,
            BranchExactPreparedInventoryCounts {
                logical: 32,
                physical: 35,
                key_domains: 39,
            }
        );
        assert_eq!(
            BranchExactPreparedInventoryCounts::for_authority(
                AuthorityScope::Coordinator
            ),
            BranchExactPreparedInventoryCounts::COORDINATOR_READY
        );
        assert_eq!(
            BranchExactPreparedInventoryCounts::for_authority(
                AuthorityScope::Realm {
                    realm_id: 7,
                    realm_sub_id: 2,
                }
            ),
            BranchExactPreparedInventoryCounts::REALM_READY
        );
    }

    #[test]
    fn request_cannot_be_built_from_a_bool_or_bare_digest() {
        fn constructor_contract(
            constructor: fn(
                BranchExactBackfillVerifiedReceipt,
            ) -> BranchExactSchemaSetupRequest,
        ) -> usize {
            std::mem::size_of_val(&constructor)
        }
        assert_eq!(
            constructor_contract(BranchExactSchemaSetupRequest::new),
            std::mem::size_of::<fn(
                BranchExactBackfillVerifiedReceipt,
            ) -> BranchExactSchemaSetupRequest>()
        );
        assert_eq!(
            BranchExactSchemaSetupMode::default(),
            BranchExactSchemaSetupMode::Disabled
        );
    }

    #[test]
    fn static_plan_types_remain_separate_from_runtime_readiness() {
        let bootstrap = CanonicalHeadBootstrap::try_new(
            CanonicalHeadBootstrapProfile::GenesisNative,
            CanonicalChainRef::new(
                NetworkId::try_from_chain_id(1337).unwrap(),
                ChainEpoch::new(0),
                CheckpointRef::new(
                    CheckpointId::new(0),
                    CheckpointHash::from_last_chain_hash(PHash::from_values(
                        1, 2, 3, 4,
                    )),
                ),
            ),
        )
        .unwrap();
        let plan = BranchExactSchemaMaterializationPlan::try_new(
            &bootstrap,
            AuthorityScope::Coordinator,
            None,
        )
        .unwrap();
        assert_eq!(plan.authority(), AuthorityScope::Coordinator);
        assert_eq!(
            BranchExactPreparedInventoryCounts::DISABLED.logical,
            32
        );
    }

    #[test]
    fn every_nonfinal_lifecycle_phase_fails_closed() {
        let (intent, schema, planned, final_state, receipt) =
            lifecycle_states("psy_h20_phase");
        assert_eq!(
            require_exact_backfill_verified(
                BranchExactDeploymentLifecycleReadState::Uninitialized,
                &receipt,
            ),
            Err(BranchExactSchemaSetupError::LifecycleUninitialized)
        );
        for (stored, phase) in [
            (intent, BranchExactDeploymentLifecyclePhase::Intent),
            (schema, BranchExactDeploymentLifecyclePhase::SchemaVerified),
            (
                planned,
                BranchExactDeploymentLifecyclePhase::BackfillPlanned,
            ),
        ] {
            assert_eq!(
                require_exact_backfill_verified(
                    BranchExactDeploymentLifecycleReadState::Current(stored),
                    &receipt,
                ),
                Err(
                    BranchExactSchemaSetupError::LifecycleNotBackfillVerified(
                        phase
                    )
                )
            );
        }
        assert_eq!(
            require_exact_backfill_verified(
                BranchExactDeploymentLifecycleReadState::Current(
                    final_state.clone()
                ),
                &receipt,
            ),
            Ok(final_state)
        );
    }

    #[test]
    fn final_lifecycle_requires_the_entire_expected_receipt() {
        let (_, _, _, first_final, first_receipt) =
            lifecycle_states("psy_h20_exact");
        let (_, _, _, _, other_receipt) =
            lifecycle_states("psy_h20_other");
        assert_eq!(
            require_exact_backfill_verified(
                BranchExactDeploymentLifecycleReadState::Current(first_final),
                &other_receipt,
            ),
            Err(BranchExactSchemaSetupError::BackfillReceiptMismatch)
        );
        assert_ne!(first_receipt, other_receipt);
    }
}
