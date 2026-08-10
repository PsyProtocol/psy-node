//! Immutable, driver-independent artifacts required to resume one durable
//! Realm user update after an Edge crash.

use std::{collections::BTreeMap, error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use sha2::{Digest, Sha256};

use super::{
    realm_user_update_artifact::ValidatedRealmUserUpdateArtifacts,
    realm_user_update_claim::{
        RealmUserUpdateClaimPhase, RealmUserUpdateClaimSlot,
        RealmUserUpdateDependencyDigest, StoredRealmUserUpdateClaim,
    },
    recoverable_artifact::PENDING_QUEUE_ARTIFACT_FRAGMENT_BYTES,
};

const DEPENDENCY_DOMAIN: &[u8] =
    b"psy/rollback/realm-user-update-dependency/v1";
const COMPONENT_DOMAIN: &[u8] =
    b"psy/rollback/realm-user-update-dependency-component/v1";
const WRITE_TIMESTAMP_DOMAIN: &[u8] =
    b"psy/rollback/realm-user-update-dependency-write-timestamp/v1";
pub const REALM_USER_UPDATE_DEPENDENCY_COMPONENT_COUNT: usize = 5;
pub const MAX_REALM_USER_UPDATE_DEPENDENCY_BYTES: usize = 256 * 1024 * 1024;

/// Explicit CQL timestamp derived from immutable durable bundle identity.
/// Every crash retry of the same bundle receives the same value; callers
/// cannot substitute a wall-clock timestamp at the storage boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RealmUserUpdateDependencyWriteTimestampUs(i64);

impl RealmUserUpdateDependencyWriteTimestampUs {
    pub fn derive(
        claim_slot: RealmUserUpdateClaimSlot,
        dependency_digest: RealmUserUpdateDependencyDigest,
        created_at_seconds: u32,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(WRITE_TIMESTAMP_DOMAIN);
        hasher.update(claim_slot.as_bytes());
        hasher.update(dependency_digest.as_bytes());
        let offset = u32::from_be_bytes(
            hasher.finalize()[..4]
                .try_into()
                .expect("fixed digest prefix"),
        ) % 1_000_000;
        Self(i64::from(created_at_seconds) * 1_000_000 + i64::from(offset))
    }

    pub const fn as_i64(self) -> i64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum RealmUserUpdateDependencyKind {
    CanonicalInput = 1,
    Proof = 2,
    ContractUpdates = 3,
    SlotUpdates = 4,
    QueuePayload = 5,
}

impl RealmUserUpdateDependencyKind {
    pub const ALL: [Self; REALM_USER_UPDATE_DEPENDENCY_COMPONENT_COUNT] = [
        Self::CanonicalInput,
        Self::Proof,
        Self::ContractUpdates,
        Self::SlotUpdates,
        Self::QueuePayload,
    ];

    pub fn try_from_i16(value: i16) -> Result<Self, RealmUserUpdateDependencyError> {
        match value {
            1 => Ok(Self::CanonicalInput),
            2 => Ok(Self::Proof),
            3 => Ok(Self::ContractUpdates),
            4 => Ok(Self::SlotUpdates),
            5 => Ok(Self::QueuePayload),
            _ => Err(RealmUserUpdateDependencyError::UnknownKind(value)),
        }
    }

    pub const fn as_i16(self) -> i16 {
        self as i16
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RealmUserUpdateComponentDigest([u8; 32]);

impl RealmUserUpdateComponentDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmUserUpdateDependencyComponent {
    kind: RealmUserUpdateDependencyKind,
    bytes: Vec<u8>,
    digest: RealmUserUpdateComponentDigest,
}

impl RealmUserUpdateDependencyComponent {
    pub fn try_new(
        kind: RealmUserUpdateDependencyKind,
        bytes: Vec<u8>,
    ) -> Result<Self, RealmUserUpdateDependencyError> {
        if bytes.is_empty() {
            return Err(RealmUserUpdateDependencyError::EmptyComponent(kind));
        }
        if bytes.len() > MAX_REALM_USER_UPDATE_DEPENDENCY_BYTES {
            return Err(RealmUserUpdateDependencyError::PayloadTooLarge);
        }
        let digest = component_digest(kind, &bytes);
        Ok(Self { kind, bytes, digest })
    }

    pub const fn kind(&self) -> RealmUserUpdateDependencyKind {
        self.kind
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub const fn digest(&self) -> RealmUserUpdateComponentDigest {
        self.digest
    }
}

/// One exact five-component dependency set. Component order is canonical and
/// cannot be supplied dynamically by callers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmUserUpdateDependencyBundle {
    claim_slot: RealmUserUpdateClaimSlot,
    request_digest: [u8; 32],
    stable_status: u64,
    created_at_seconds: u32,
    components: [RealmUserUpdateDependencyComponent;
        REALM_USER_UPDATE_DEPENDENCY_COMPONENT_COUNT],
    digest: RealmUserUpdateDependencyDigest,
}

impl RealmUserUpdateDependencyBundle {
    fn try_new<Hash: Q256BitHash>(
        claim: &StoredRealmUserUpdateClaim<Hash>,
        canonical_input: Vec<u8>,
        proof: Vec<u8>,
        contract_updates: Vec<u8>,
        slot_updates: Vec<u8>,
        queue_payload: Vec<u8>,
    ) -> Result<Self, RealmUserUpdateDependencyError> {
        if !matches!(
            claim.phase(),
            RealmUserUpdateClaimPhase::Claimed
                | RealmUserUpdateClaimPhase::DependenciesPlanned
                | RealmUserUpdateClaimPhase::DependenciesReady
                | RealmUserUpdateClaimPhase::Published
        ) {
            return Err(RealmUserUpdateDependencyError::ClaimNotOpen);
        }
        let total = canonical_input
            .len()
            .checked_add(proof.len())
            .and_then(|value| value.checked_add(contract_updates.len()))
            .and_then(|value| value.checked_add(slot_updates.len()))
            .and_then(|value| value.checked_add(queue_payload.len()))
            .ok_or(RealmUserUpdateDependencyError::PayloadTooLarge)?;
        if total > MAX_REALM_USER_UPDATE_DEPENDENCY_BYTES {
            return Err(RealmUserUpdateDependencyError::PayloadTooLarge);
        }
        let components = [
            RealmUserUpdateDependencyComponent::try_new(
                RealmUserUpdateDependencyKind::CanonicalInput,
                canonical_input,
            )?,
            RealmUserUpdateDependencyComponent::try_new(
                RealmUserUpdateDependencyKind::Proof,
                proof,
            )?,
            RealmUserUpdateDependencyComponent::try_new(
                RealmUserUpdateDependencyKind::ContractUpdates,
                contract_updates,
            )?,
            RealmUserUpdateDependencyComponent::try_new(
                RealmUserUpdateDependencyKind::SlotUpdates,
                slot_updates,
            )?,
            RealmUserUpdateDependencyComponent::try_new(
                RealmUserUpdateDependencyKind::QueuePayload,
                queue_payload,
            )?,
        ];
        let request_digest = *claim.request_digest().as_bytes();
        let recomputed_request = super::realm_user_update_publish::RealmUserUpdateRequestDigest::derive(
            components[0].bytes(),
            components[1].bytes(),
        )
        .map_err(|_| RealmUserUpdateDependencyError::RequestMismatch)?;
        if recomputed_request != claim.request_digest() {
            return Err(RealmUserUpdateDependencyError::RequestMismatch);
        }
        let stable_status = claim.stable_status();
        let created_at_seconds = claim.created_at().get();
        let digest = dependency_digest(
            claim.slot(),
            &request_digest,
            stable_status,
            created_at_seconds,
            &components,
        )?;
        Ok(Self {
            claim_slot: claim.slot(),
            request_digest,
            stable_status,
            created_at_seconds,
            components,
            digest,
        })
    }

    /// Build the persistable dependency set only from artifacts that already
    /// passed the typed input/QBlob/slot/queue validation boundary.
    pub fn try_new_validated<Hash: Q256BitHash>(
        claim: &StoredRealmUserUpdateClaim<Hash>,
        artifacts: &ValidatedRealmUserUpdateArtifacts<Hash>,
    ) -> Result<Self, RealmUserUpdateDependencyError> {
        if claim.slot() != artifacts.claim_slot()
            || claim.created_at().get() != artifacts.created_at_seconds()
            || claim.pending() != artifacts.pending()
            || claim.user_id() != artifacts.user_id()
            || claim.request_digest() != artifacts.request_digest()
        {
            return Err(RealmUserUpdateDependencyError::RequestMismatch);
        }
        Self::try_new(
            claim,
            artifacts.canonical_input().to_vec(),
            artifacts.proof().to_vec(),
            artifacts.contract_updates().to_vec(),
            artifacts.slot_updates().to_vec(),
            artifacts.queue_payload().to_vec(),
        )
    }

    pub fn reconstruct(
        claim_slot: RealmUserUpdateClaimSlot,
        request_digest: [u8; 32],
        stable_status: u64,
        created_at_seconds: u32,
        components: Vec<RealmUserUpdateDependencyComponent>,
        expected_digest: RealmUserUpdateDependencyDigest,
    ) -> Result<Self, RealmUserUpdateDependencyError> {
        if components.len() != REALM_USER_UPDATE_DEPENDENCY_COMPONENT_COUNT {
            return Err(RealmUserUpdateDependencyError::ComponentSetMismatch);
        }
        let components: [RealmUserUpdateDependencyComponent;
            REALM_USER_UPDATE_DEPENDENCY_COMPONENT_COUNT] = components
            .try_into()
            .map_err(|_| RealmUserUpdateDependencyError::ComponentSetMismatch)?;
        for (expected, actual) in RealmUserUpdateDependencyKind::ALL
            .into_iter()
            .zip(components.iter())
        {
            if expected != actual.kind() {
                return Err(RealmUserUpdateDependencyError::ComponentSetMismatch);
            }
        }
        let recomputed_request = super::realm_user_update_publish::RealmUserUpdateRequestDigest::derive(
            components[0].bytes(),
            components[1].bytes(),
        )
        .map_err(|_| RealmUserUpdateDependencyError::RequestMismatch)?;
        if recomputed_request.as_bytes() != &request_digest
            || stable_status == 0
            || stable_status != recomputed_request.stable_status()
            || created_at_seconds == 0
        {
            return Err(RealmUserUpdateDependencyError::RequestMismatch);
        }
        let digest = dependency_digest(
            claim_slot,
            &request_digest,
            stable_status,
            created_at_seconds,
            &components,
        )?;
        if digest != expected_digest {
            return Err(RealmUserUpdateDependencyError::DigestMismatch);
        }
        Ok(Self {
            claim_slot,
            request_digest,
            stable_status,
            created_at_seconds,
            components,
            digest,
        })
    }

    pub const fn claim_slot(&self) -> RealmUserUpdateClaimSlot {
        self.claim_slot
    }

    pub const fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }

    pub const fn stable_status(&self) -> u64 { self.stable_status }

    pub const fn created_at_seconds(&self) -> u32 { self.created_at_seconds }

    pub const fn digest(&self) -> RealmUserUpdateDependencyDigest {
        self.digest
    }

    pub fn write_timestamp_us(&self) -> RealmUserUpdateDependencyWriteTimestampUs {
        RealmUserUpdateDependencyWriteTimestampUs::derive(
            self.claim_slot,
            self.digest,
            self.created_at_seconds,
        )
    }

    pub fn component(
        &self,
        kind: RealmUserUpdateDependencyKind,
    ) -> &RealmUserUpdateDependencyComponent {
        &self.components[(kind as usize) - 1]
    }

    pub fn fragments(&self) -> Vec<RealmUserUpdateDependencyFragment> {
        let mut output = Vec::new();
        for component in &self.components {
            let count = component.bytes().len().div_ceil(PENDING_QUEUE_ARTIFACT_FRAGMENT_BYTES);
            for (index, bytes) in component
                .bytes()
                .chunks(PENDING_QUEUE_ARTIFACT_FRAGMENT_BYTES)
                .enumerate()
            {
                output.push(RealmUserUpdateDependencyFragment {
                    kind: component.kind(),
                    index: u32::try_from(index).expect("bounded dependency fragment index"),
                    count: u32::try_from(count).expect("bounded dependency fragment count"),
                    component_bytes: u64::try_from(component.bytes().len())
                        .expect("bounded dependency bytes"),
                    component_digest: component.digest(),
                    payload: bytes.to_vec(),
                    payload_digest: Sha256::digest(bytes).into(),
                });
            }
        }
        output
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmUserUpdateDependencyFragment {
    kind: RealmUserUpdateDependencyKind,
    index: u32,
    count: u32,
    component_bytes: u64,
    component_digest: RealmUserUpdateComponentDigest,
    payload: Vec<u8>,
    payload_digest: [u8; 32],
}

/// Deterministic repair plan for an interrupted immutable-fragment write.
/// Only an exact subset of the expected bundle is repairable; any duplicate,
/// extra coordinate, or different full row fails closed instead of being
/// overwritten. The constructor is intentionally the classifier below.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmUserUpdateDependencyRecoveryPlan {
    missing: Vec<RealmUserUpdateDependencyFragment>,
}

impl RealmUserUpdateDependencyRecoveryPlan {
    pub fn is_complete(&self) -> bool { self.missing.is_empty() }

    pub fn missing_fragments(&self) -> &[RealmUserUpdateDependencyFragment] {
        &self.missing
    }
}

pub fn plan_realm_user_update_dependency_recovery(
    expected: &RealmUserUpdateDependencyBundle,
    observed: Vec<RealmUserUpdateDependencyFragment>,
) -> Result<RealmUserUpdateDependencyRecoveryPlan, RealmUserUpdateDependencyError> {
    let expected_fragments = expected.fragments();
    let expected_by_coordinate = expected_fragments
        .iter()
        .map(|fragment| ((fragment.kind(), fragment.index()), fragment))
        .collect::<BTreeMap<_, _>>();
    let mut observed_by_coordinate = BTreeMap::new();
    for fragment in observed {
        let coordinate = (fragment.kind(), fragment.index());
        if observed_by_coordinate
            .insert(coordinate, fragment.clone())
            .is_some()
        {
            return Err(RealmUserUpdateDependencyError::DuplicateFragment);
        }
        let Some(expected_fragment) = expected_by_coordinate.get(&coordinate)
        else {
            return Err(RealmUserUpdateDependencyError::UnexpectedFragment);
        };
        if **expected_fragment != fragment {
            return Err(RealmUserUpdateDependencyError::ConflictingFragment);
        }
    }
    let missing = expected_fragments
        .into_iter()
        .filter(|fragment| {
            !observed_by_coordinate.contains_key(&(fragment.kind(), fragment.index()))
        })
        .collect();
    Ok(RealmUserUpdateDependencyRecoveryPlan { missing })
}

impl RealmUserUpdateDependencyFragment {
    pub const fn kind(&self) -> RealmUserUpdateDependencyKind { self.kind }
    pub const fn index(&self) -> u32 { self.index }
    pub const fn count(&self) -> u32 { self.count }
    pub const fn component_bytes(&self) -> u64 { self.component_bytes }
    pub const fn component_digest(&self) -> RealmUserUpdateComponentDigest { self.component_digest }
    pub fn payload(&self) -> &[u8] { &self.payload }
    pub const fn payload_digest(&self) -> &[u8; 32] { &self.payload_digest }

    pub fn decode(
        kind: RealmUserUpdateDependencyKind,
        index: i32,
        count: i32,
        component_bytes: i64,
        component_digest: Vec<u8>,
        payload: Vec<u8>,
        payload_digest: Vec<u8>,
    ) -> Result<Self, RealmUserUpdateDependencyError> {
        let index = u32::try_from(index).map_err(|_| RealmUserUpdateDependencyError::MalformedFragment)?;
        let count = u32::try_from(count).map_err(|_| RealmUserUpdateDependencyError::MalformedFragment)?;
        let component_bytes = u64::try_from(component_bytes).map_err(|_| RealmUserUpdateDependencyError::MalformedFragment)?;
        let component_digest: [u8; 32] = component_digest.try_into().map_err(|_| RealmUserUpdateDependencyError::MalformedFragment)?;
        let payload_digest: [u8; 32] = payload_digest.try_into().map_err(|_| RealmUserUpdateDependencyError::MalformedFragment)?;
        if count == 0 || index >= count || payload.is_empty()
            || payload.len() > PENDING_QUEUE_ARTIFACT_FRAGMENT_BYTES
            || component_bytes == 0
            || <[u8; 32]>::from(Sha256::digest(&payload)) != payload_digest
        {
            return Err(RealmUserUpdateDependencyError::MalformedFragment);
        }
        Ok(Self {
            kind,
            index,
            count,
            component_bytes,
            component_digest: RealmUserUpdateComponentDigest(component_digest),
            payload,
            payload_digest,
        })
    }
}

pub fn reconstruct_component(
    kind: RealmUserUpdateDependencyKind,
    mut fragments: Vec<RealmUserUpdateDependencyFragment>,
) -> Result<RealmUserUpdateDependencyComponent, RealmUserUpdateDependencyError> {
    fragments.sort_by_key(RealmUserUpdateDependencyFragment::index);
    let first = fragments.first().ok_or(RealmUserUpdateDependencyError::MissingFragment)?;
    let count = usize::try_from(first.count()).map_err(|_| RealmUserUpdateDependencyError::MalformedFragment)?;
    if fragments.len() != count {
        return Err(RealmUserUpdateDependencyError::MissingFragment);
    }
    let mut bytes = Vec::new();
    for (expected_index, fragment) in fragments.iter().enumerate() {
        if fragment.kind() != kind
            || fragment.index() as usize != expected_index
            || fragment.count() != first.count()
            || fragment.component_bytes() != first.component_bytes()
            || fragment.component_digest() != first.component_digest()
        {
            return Err(RealmUserUpdateDependencyError::FragmentSetMismatch);
        }
        bytes.extend_from_slice(fragment.payload());
    }
    if bytes.len() as u64 != first.component_bytes() {
        return Err(RealmUserUpdateDependencyError::FragmentSetMismatch);
    }
    let component = RealmUserUpdateDependencyComponent::try_new(kind, bytes)?;
    if component.digest() != first.component_digest() {
        return Err(RealmUserUpdateDependencyError::DigestMismatch);
    }
    Ok(component)
}

fn component_digest(kind: RealmUserUpdateDependencyKind, bytes: &[u8]) -> RealmUserUpdateComponentDigest {
    let mut hasher = Sha256::new();
    hasher.update(COMPONENT_DOMAIN);
    hasher.update([kind as u8]);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    RealmUserUpdateComponentDigest(hasher.finalize().into())
}

fn dependency_digest(
    claim_slot: RealmUserUpdateClaimSlot,
    request_digest: &[u8; 32],
    stable_status: u64,
    created_at_seconds: u32,
    components: &[RealmUserUpdateDependencyComponent;
        REALM_USER_UPDATE_DEPENDENCY_COMPONENT_COUNT],
) -> Result<RealmUserUpdateDependencyDigest, RealmUserUpdateDependencyError> {
    let mut hasher = Sha256::new();
    hasher.update(DEPENDENCY_DOMAIN);
    hasher.update(claim_slot.as_bytes());
    hasher.update(request_digest);
    hasher.update(stable_status.to_be_bytes());
    hasher.update(created_at_seconds.to_be_bytes());
    for component in components {
        hasher.update([component.kind() as u8]);
        hasher.update((component.bytes().len() as u64).to_be_bytes());
        hasher.update(component.digest().as_bytes());
    }
    RealmUserUpdateDependencyDigest::try_new(hasher.finalize().into())
        .map_err(|_| RealmUserUpdateDependencyError::EmptyDigest)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealmUserUpdateDependencyError {
    ClaimNotOpen,
    RequestMismatch,
    EmptyComponent(RealmUserUpdateDependencyKind),
    EmptyDigest,
    PayloadTooLarge,
    UnknownKind(i16),
    ComponentSetMismatch,
    MissingFragment,
    MalformedFragment,
    FragmentSetMismatch,
    DigestMismatch,
    DuplicateFragment,
    UnexpectedFragment,
    ConflictingFragment,
}

impl fmt::Display for RealmUserUpdateDependencyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RealmUserUpdateDependencyError {}

#[cfg(test)]
mod tests {
    use parth_core::PHash;
    use psy_data::protocol::{
        canonical_chain::{CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef, NetworkId},
        chain_context::{AuthorityScope, PendingContext, WorkProcCheckpointUniqueId, WorkUniquePendingId},
    };

    use super::*;
    use crate::{
        queue::{realm_user_update_claim::RealmUserUpdateCreatedAtSeconds, realm_user_update_publish::{RealmUserUpdatePublishAdmission, RealmUserUpdateRequestDigest}, recoverable_ephemeral::PendingQueueCaptureContext},
        store::{pending_generation_identity::{PendingGenerationActivationDigest, PendingGenerationContext, PendingGenerationLedgerKey}, typed::{UniquePendingId, UserId}},
    };

    fn claim(input: &[u8], proof: &[u8]) -> StoredRealmUserUpdateClaim<PHash> {
        let chain = CanonicalChainRef::new(NetworkId::try_from_chain_id(1337).unwrap(), ChainEpoch::new(2), CheckpointRef::new(CheckpointId::new(7), CheckpointHash::from_last_chain_hash(PHash::from_owned_32bytes([8; 32]))));
        let authority = AuthorityScope::Realm { realm_id: 1, realm_sub_id: 2 };
        let pending = PendingContext::new(chain, authority, WorkUniquePendingId::new(9), WorkProcCheckpointUniqueId::from_u128(10));
        let generation = PendingGenerationContext::try_from_legacy(UniquePendingId::try_new(9).unwrap().get(), 10).unwrap();
        let capture = PendingQueueCaptureContext::try_new(PendingGenerationLedgerKey::new(chain.network_id(), authority), PendingGenerationActivationDigest::try_new([3; 32]).unwrap(), generation).unwrap();
        StoredRealmUserUpdateClaim::claimed(RealmUserUpdatePublishAdmission::try_from_pipeline(pending, capture).unwrap(), crate::queue::realm_user_update_verifier_profile::RealmUserUpdateVerifierProfileId::try_from_persisted([0xA5; 32]).unwrap(), UserId::new(11), RealmUserUpdateRequestDigest::derive(input, proof).unwrap(), RealmUserUpdateCreatedAtSeconds::try_new(12).unwrap(), crate::queue::realm_user_update_claim::RealmUserUpdateAdmissionOrdinal::FIRST).unwrap()
    }

    #[test]
    fn five_components_fragment_and_reconstruct_exactly() {
        let input = vec![1; PENDING_QUEUE_ARTIFACT_FRAGMENT_BYTES + 3];
        let proof = vec![2; 17];
        let bundle = RealmUserUpdateDependencyBundle::try_new(&claim(&input, &proof), input, proof, vec![3; 19], vec![4; 23], vec![5; 29]).unwrap();
        let fragments = bundle.fragments();
        assert_eq!(fragments.len(), 6);
        let write_timestamp = bundle.write_timestamp_us();
        assert!(write_timestamp.as_i64() >= 12_000_000);
        assert!(write_timestamp.as_i64() < 13_000_000);
        let components = RealmUserUpdateDependencyKind::ALL.into_iter().map(|kind| reconstruct_component(kind, fragments.iter().filter(|fragment| fragment.kind() == kind).cloned().rev().collect()).unwrap()).collect();
        let reconstructed = RealmUserUpdateDependencyBundle::reconstruct(bundle.claim_slot(), *bundle.request_digest(), bundle.stable_status(), bundle.created_at_seconds(), components, bundle.digest()).unwrap();
        assert_eq!(reconstructed.write_timestamp_us(), write_timestamp);
        assert_eq!(reconstructed, bundle);
    }

    #[test]
    fn missing_extra_or_changed_component_fails_closed() {
        let input = vec![1; 9];
        let proof_bytes = vec![2; 9];
        let bundle = RealmUserUpdateDependencyBundle::try_new(&claim(&input, &proof_bytes), input, proof_bytes, vec![3; 9], vec![4; 9], vec![5; 9]).unwrap();
        let mut proof = bundle.fragments().into_iter().filter(|fragment| fragment.kind() == RealmUserUpdateDependencyKind::Proof).collect::<Vec<_>>();
        proof[0].payload[0] ^= 1;
        assert!(reconstruct_component(RealmUserUpdateDependencyKind::Proof, proof).is_err());
        assert!(RealmUserUpdateDependencyBundle::reconstruct(bundle.claim_slot(), *bundle.request_digest(), bundle.stable_status(), bundle.created_at_seconds(), Vec::new(), bundle.digest()).is_err());
    }

    #[test]
    fn interrupted_fragment_recovery_only_fills_an_exact_missing_subset() {
        let input = vec![1; PENDING_QUEUE_ARTIFACT_FRAGMENT_BYTES + 3];
        let proof = vec![2; 17];
        let bundle = RealmUserUpdateDependencyBundle::try_new(
            &claim(&input, &proof),
            input,
            proof,
            vec![3; 19],
            vec![4; 23],
            vec![5; 29],
        )
        .unwrap();
        let expected = bundle.fragments();
        let observed = expected
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != 1)
            .map(|(_, fragment)| fragment.clone())
            .rev()
            .collect();
        let plan = plan_realm_user_update_dependency_recovery(&bundle, observed)
            .unwrap();
        assert!(!plan.is_complete());
        assert_eq!(plan.missing_fragments(), &expected[1..2]);
        assert!(plan_realm_user_update_dependency_recovery(
            &bundle,
            expected.clone(),
        )
        .unwrap()
        .is_complete());

        let mut duplicate = expected.clone();
        duplicate.push(expected[0].clone());
        assert_eq!(
            plan_realm_user_update_dependency_recovery(&bundle, duplicate),
            Err(RealmUserUpdateDependencyError::DuplicateFragment),
        );

        let mut conflicting = expected.clone();
        conflicting[0].payload[0] ^= 1;
        conflicting[0].payload_digest = Sha256::digest(&conflicting[0].payload).into();
        assert_eq!(
            plan_realm_user_update_dependency_recovery(&bundle, conflicting),
            Err(RealmUserUpdateDependencyError::ConflictingFragment),
        );

        let mut unexpected = expected;
        unexpected[0].index = unexpected[0].count;
        assert_eq!(
            plan_realm_user_update_dependency_recovery(&bundle, unexpected),
            Err(RealmUserUpdateDependencyError::UnexpectedFragment),
        );
    }

    #[test]
    fn raw_five_byte_components_are_not_a_public_bundle_constructor() {
        let source = include_str!("realm_user_update_dependency.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("fn try_new<Hash: Q256BitHash>("));
        assert!(!production.contains("pub fn try_new<Hash: Q256BitHash>("));
        assert!(production.contains("pub fn try_new_validated<Hash: Q256BitHash>("));
    }
}
