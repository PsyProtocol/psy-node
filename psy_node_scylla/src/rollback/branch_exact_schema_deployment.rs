//! Typed full-topology postflight and durable deployment payloads.
//!
//! This module does not persist a row or grant a reader/writer cutover
//! capability. It closes the semantic prerequisite for that row: a VERIFIED
//! deployment must attest the exact operator-declared Scylla host-id set, not
//! merely whichever nodes were reachable when `await_schema_agreement()` ran.

use std::{error::Error, fmt};

use psy_node_core::store::{
    branch_exact_schema::{
        AuthorityScope, BranchExactMaterializationPlanDigest,
        BRANCH_EXACT_SCHEMA_VERSION,
    },
    canonical_head::CanonicalHeadBootstrapProfile,
};
use scylla::client::session::Session;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    BranchExactSchemaFingerprint, BranchExactSchemaInspection,
    BranchExactSchemaMaterializationRequest, BranchExactSchemaMaterializer,
    BranchExactSchemaOnlyReceipt, CqlKeyspaceName,
};

pub const BRANCH_EXACT_DEPLOYMENT_CODEC_VERSION: u16 = 1;
pub const INSPECT_LOCAL_SCHEMA_POSTFLIGHT_CQL: &str =
    "SELECT host_id, schema_version FROM system.local";
pub const INSPECT_LOCAL_HOST_ID_CQL: &str = "SELECT host_id FROM system.local";

const MIN_EXPECTED_TOPOLOGY_NODES: usize = 3;
const MAX_EXPECTED_TOPOLOGY_NODES: usize = u16::MAX as usize;
const INTENT_PAYLOAD_KIND: u8 = 1;
const VERIFIED_PAYLOAD_KIND: u8 = 2;
const INTENT_DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/branch-exact-deployment-intent/v1";
const TOPOLOGY_DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/branch-exact-expected-topology/v1";
const ATTESTATION_DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/branch-exact-topology-attestation/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BranchExactScyllaNodeId([u8; 16]);

impl BranchExactScyllaNodeId {
    pub fn try_new(bytes: [u8; 16]) -> Result<Self, BranchExactDeploymentError> {
        if bytes == [0; 16] {
            return Err(BranchExactDeploymentError::NilNodeId);
        }
        Ok(Self(bytes))
    }

    pub fn from_uuid(value: Uuid) -> Result<Self, BranchExactDeploymentError> {
        Self::try_new(*value.as_bytes())
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BranchExactScyllaSchemaVersion([u8; 16]);

impl BranchExactScyllaSchemaVersion {
    pub fn try_new(bytes: [u8; 16]) -> Result<Self, BranchExactDeploymentError> {
        if bytes == [0; 16] {
            return Err(BranchExactDeploymentError::NilSchemaVersion);
        }
        Ok(Self(bytes))
    }

    pub fn from_uuid(value: Uuid) -> Result<Self, BranchExactDeploymentError> {
        Self::try_new(*value.as_bytes())
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BranchExactExpectedTopologyDigest([u8; 32]);

impl BranchExactExpectedTopologyDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactExpectedTopology {
    nodes: Vec<BranchExactScyllaNodeId>,
    digest: BranchExactExpectedTopologyDigest,
}

impl BranchExactExpectedTopology {
    pub fn try_new(
        mut nodes: Vec<BranchExactScyllaNodeId>,
    ) -> Result<Self, BranchExactDeploymentError> {
        // One node is reserved for the explicitly guarded LocalDevnet
        // functional path. Production callers require at least three; two is
        // never a valid topology in either mode.
        if nodes.len() != 1 && nodes.len() < MIN_EXPECTED_TOPOLOGY_NODES {
            return Err(BranchExactDeploymentError::TopologyTooSmall {
                actual: nodes.len(),
                minimum: MIN_EXPECTED_TOPOLOGY_NODES,
            });
        }
        if nodes.len() > MAX_EXPECTED_TOPOLOGY_NODES {
            return Err(BranchExactDeploymentError::TopologyTooLarge {
                actual: nodes.len(),
                maximum: MAX_EXPECTED_TOPOLOGY_NODES,
            });
        }
        nodes.sort_unstable();
        if nodes.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(BranchExactDeploymentError::DuplicateExpectedNode);
        }
        let digest = expected_topology_digest(&nodes);
        Ok(Self { nodes, digest })
    }

    /// Explicit single-replica topology for LocalDevnet functional testing.
    /// Production callers must use `try_new`, whose minimum remains three
    /// distinct replicas.
    pub(crate) fn local_devnet_single(node: BranchExactScyllaNodeId) -> Self {
        let nodes = vec![node];
        let digest = expected_topology_digest(&nodes);
        Self { nodes, digest }
    }

    pub fn nodes(&self) -> &[BranchExactScyllaNodeId] {
        &self.nodes
    }

    pub const fn digest(&self) -> BranchExactExpectedTopologyDigest {
        self.digest
    }
}

/// Read the identity of one operator-targeted node before DDL.  The returned
/// identity is later closed by the full schema postflight; it is not schema
/// readiness evidence by itself.
pub async fn inspect_branch_exact_local_node_id(
    targeted_session: &Session,
) -> anyhow::Result<BranchExactScyllaNodeId> {
    let host_id = targeted_session
        .query_unpaged(INSPECT_LOCAL_HOST_ID_CQL, &[])
        .await?
        .into_rows_result()?
        .single_row::<(Uuid,)>()?
        .0;
    Ok(BranchExactScyllaNodeId::from_uuid(host_id)?)
}

fn expected_topology_digest(
    nodes: &[BranchExactScyllaNodeId],
) -> BranchExactExpectedTopologyDigest {
    let mut hasher = Sha256::new();
    hasher.update(TOPOLOGY_DIGEST_DOMAIN);
    hasher.update(BRANCH_EXACT_DEPLOYMENT_CODEC_VERSION.to_be_bytes());
    hasher.update((nodes.len() as u32).to_be_bytes());
    for node in nodes {
        hasher.update(node.as_bytes());
    }
    BranchExactExpectedTopologyDigest(hasher.finalize().into())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BranchExactNodeSchemaPostflight {
    node_id: BranchExactScyllaNodeId,
    schema_version: BranchExactScyllaSchemaVersion,
    schema_fingerprint: BranchExactSchemaFingerprint,
}

impl BranchExactNodeSchemaPostflight {
    pub fn try_new(
        node_id: BranchExactScyllaNodeId,
        schema_version: BranchExactScyllaSchemaVersion,
        inspection: BranchExactSchemaInspection,
    ) -> Result<Self, BranchExactDeploymentError> {
        let BranchExactSchemaInspection::Exact { fingerprint } = inspection else {
            return Err(BranchExactDeploymentError::NodeSchemaNotExact);
        };
        Ok(Self {
            node_id,
            schema_version,
            schema_fingerprint: fingerprint,
        })
    }

    pub const fn node_id(&self) -> BranchExactScyllaNodeId {
        self.node_id
    }

    pub const fn schema_version(&self) -> BranchExactScyllaSchemaVersion {
        self.schema_version
    }

    pub const fn schema_fingerprint(&self) -> BranchExactSchemaFingerprint {
        self.schema_fingerprint
    }
}

/// Inspect one node through a caller-supplied single-target Session.
///
/// The function deliberately does not construct the Session: deployment code
/// must target each expected host independently. Reusing one load-balanced
/// Session yields duplicate host ids and cannot satisfy topology attestation.
pub async fn inspect_branch_exact_local_node_postflight(
    targeted_session: &Session,
    keyspace: &CqlKeyspaceName,
    authority: AuthorityScope,
) -> anyhow::Result<BranchExactNodeSchemaPostflight> {
    let row = targeted_session
        .query_unpaged(INSPECT_LOCAL_SCHEMA_POSTFLIGHT_CQL, &[])
        .await?
        .into_rows_result()?
        .single_row::<(Uuid, Uuid)>()?;
    let inspection = BranchExactSchemaMaterializer::inspect_schema(
        targeted_session,
        keyspace,
        authority,
    )
    .await?;
    Ok(BranchExactNodeSchemaPostflight::try_new(
        BranchExactScyllaNodeId::from_uuid(row.0)?,
        BranchExactScyllaSchemaVersion::from_uuid(row.1)?,
        inspection,
    )?)
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BranchExactDeploymentIntentDigest([u8; 32]);

impl BranchExactDeploymentIntentDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactDeploymentIntent {
    keyspace: CqlKeyspaceName,
    authority: AuthorityScope,
    profile: CanonicalHeadBootstrapProfile,
    schema_version: u16,
    plan_digest: BranchExactMaterializationPlanDigest,
    expected_topology: BranchExactExpectedTopology,
    digest: BranchExactDeploymentIntentDigest,
}

impl BranchExactDeploymentIntent {
    pub fn new(
        request: &BranchExactSchemaMaterializationRequest,
        expected_topology: BranchExactExpectedTopology,
    ) -> Self {
        let plan = request.plan();
        let mut intent = Self {
            keyspace: request.keyspace().clone(),
            authority: plan.authority(),
            profile: plan.profile(),
            schema_version: plan.schema_version(),
            plan_digest: plan.digest(),
            expected_topology,
            digest: BranchExactDeploymentIntentDigest([0; 32]),
        };
        intent.digest = intent_digest(&intent);
        intent
    }

    pub const fn keyspace(&self) -> &CqlKeyspaceName {
        &self.keyspace
    }

    pub const fn authority(&self) -> AuthorityScope {
        self.authority
    }

    pub const fn profile(&self) -> CanonicalHeadBootstrapProfile {
        self.profile
    }

    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub const fn plan_digest(&self) -> BranchExactMaterializationPlanDigest {
        self.plan_digest
    }

    pub const fn expected_topology(&self) -> &BranchExactExpectedTopology {
        &self.expected_topology
    }

    pub const fn digest(&self) -> BranchExactDeploymentIntentDigest {
        self.digest
    }

    pub fn matches_request(
        &self,
        request: &BranchExactSchemaMaterializationRequest,
    ) -> bool {
        self.keyspace == *request.keyspace()
            && self.authority == request.plan().authority()
            && self.profile == request.plan().profile()
            && self.schema_version == request.plan().schema_version()
            && self.plan_digest == request.plan().digest()
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        encode_intent(self)
    }

    pub fn decode_persisted(
        bytes: &[u8],
    ) -> Result<Self, BranchExactDeploymentError> {
        decode_intent(bytes)
    }
}

fn intent_digest(intent: &BranchExactDeploymentIntent) -> BranchExactDeploymentIntentDigest {
    let mut hasher = Sha256::new();
    hasher.update(INTENT_DIGEST_DOMAIN);
    hasher.update(encode_intent(intent));
    BranchExactDeploymentIntentDigest(hasher.finalize().into())
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BranchExactTopologyAttestationDigest([u8; 32]);

impl BranchExactTopologyAttestationDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactTopologyAttestation {
    keyspace: CqlKeyspaceName,
    authority: AuthorityScope,
    profile: CanonicalHeadBootstrapProfile,
    schema_version: u16,
    plan_digest: BranchExactMaterializationPlanDigest,
    expected_topology: BranchExactExpectedTopology,
    agreed_schema_version: BranchExactScyllaSchemaVersion,
    schema_fingerprint: BranchExactSchemaFingerprint,
    digest: BranchExactTopologyAttestationDigest,
}

impl BranchExactTopologyAttestation {
    pub fn try_new(
        receipt: &BranchExactSchemaOnlyReceipt,
        expected_topology: BranchExactExpectedTopology,
        mut observations: Vec<BranchExactNodeSchemaPostflight>,
    ) -> Result<Self, BranchExactDeploymentError> {
        observations.sort_unstable_by_key(|observation| observation.node_id());
        if observations.windows(2).any(|pair| pair[0].node_id() == pair[1].node_id()) {
            return Err(BranchExactDeploymentError::DuplicateObservedNode);
        }
        let observed_nodes = observations
            .iter()
            .map(BranchExactNodeSchemaPostflight::node_id)
            .collect::<Vec<_>>();
        if observed_nodes != expected_topology.nodes {
            return Err(BranchExactDeploymentError::ObservedTopologyMismatch);
        }
        let agreed_schema_version = observations
            .first()
            .ok_or(BranchExactDeploymentError::ObservedTopologyMismatch)?
            .schema_version();
        if observations
            .iter()
            .any(|observation| observation.schema_version() != agreed_schema_version)
        {
            return Err(BranchExactDeploymentError::SchemaVersionDisagreement);
        }
        if observations.iter().any(|observation| {
            observation.schema_fingerprint() != receipt.schema_fingerprint()
        }) {
            return Err(BranchExactDeploymentError::SchemaFingerprintMismatch);
        }
        let mut attestation = Self {
            keyspace: receipt.keyspace().clone(),
            authority: receipt.authority(),
            profile: receipt.profile(),
            schema_version: receipt.schema_version(),
            plan_digest: receipt.plan_digest(),
            expected_topology,
            agreed_schema_version,
            schema_fingerprint: receipt.schema_fingerprint(),
            digest: BranchExactTopologyAttestationDigest([0; 32]),
        };
        attestation.digest = attestation_digest(
            attestation.plan_digest,
            &attestation.keyspace,
            attestation.authority,
            attestation.profile,
            attestation.schema_version,
            attestation.expected_topology.digest(),
            attestation.agreed_schema_version,
            attestation.schema_fingerprint,
        );
        Ok(attestation)
    }

    pub const fn agreed_schema_version(&self) -> BranchExactScyllaSchemaVersion {
        self.agreed_schema_version
    }

    pub const fn schema_fingerprint(&self) -> BranchExactSchemaFingerprint {
        self.schema_fingerprint
    }

    pub const fn digest(&self) -> BranchExactTopologyAttestationDigest {
        self.digest
    }
}

fn attestation_digest(
    plan_digest: BranchExactMaterializationPlanDigest,
    keyspace: &CqlKeyspaceName,
    authority: AuthorityScope,
    profile: CanonicalHeadBootstrapProfile,
    schema_version: u16,
    topology_digest: BranchExactExpectedTopologyDigest,
    agreed_schema_version: BranchExactScyllaSchemaVersion,
    schema_fingerprint: BranchExactSchemaFingerprint,
) -> BranchExactTopologyAttestationDigest {
    let mut hasher = Sha256::new();
    hasher.update(ATTESTATION_DIGEST_DOMAIN);
    hasher.update(BRANCH_EXACT_DEPLOYMENT_CODEC_VERSION.to_be_bytes());
    hasher.update(plan_digest.as_bytes());
    update_len_prefixed(&mut hasher, keyspace.as_str().as_bytes());
    update_authority(&mut hasher, authority);
    hasher.update([encode_profile(profile)]);
    hasher.update(schema_version.to_be_bytes());
    hasher.update(topology_digest.as_bytes());
    hasher.update(agreed_schema_version.as_bytes());
    hasher.update(schema_fingerprint.as_bytes());
    BranchExactTopologyAttestationDigest(hasher.finalize().into())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactVerifiedDeploymentReceipt {
    intent: BranchExactDeploymentIntent,
    agreed_schema_version: BranchExactScyllaSchemaVersion,
    schema_fingerprint: BranchExactSchemaFingerprint,
    attestation_digest: BranchExactTopologyAttestationDigest,
}

impl BranchExactVerifiedDeploymentReceipt {
    pub fn try_new(
        intent: BranchExactDeploymentIntent,
        attestation: BranchExactTopologyAttestation,
    ) -> Result<Self, BranchExactDeploymentError> {
        if intent.keyspace != attestation.keyspace
            || intent.authority != attestation.authority
            || intent.profile != attestation.profile
            || intent.schema_version != attestation.schema_version
            || intent.plan_digest != attestation.plan_digest
            || intent.expected_topology != attestation.expected_topology
        {
            return Err(BranchExactDeploymentError::IntentAttestationMismatch);
        }
        Ok(Self {
            intent,
            agreed_schema_version: attestation.agreed_schema_version,
            schema_fingerprint: attestation.schema_fingerprint,
            attestation_digest: attestation.digest,
        })
    }

    pub const fn intent(&self) -> &BranchExactDeploymentIntent {
        &self.intent
    }

    pub const fn agreed_schema_version(&self) -> BranchExactScyllaSchemaVersion {
        self.agreed_schema_version
    }

    pub const fn schema_fingerprint(&self) -> BranchExactSchemaFingerprint {
        self.schema_fingerprint
    }

    pub const fn attestation_digest(&self) -> BranchExactTopologyAttestationDigest {
        self.attestation_digest
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let intent = self.intent.to_canonical_bytes();
        let mut output = Vec::with_capacity(2 + 1 + 4 + intent.len() + 16 + 32 + 32);
        output.extend_from_slice(&BRANCH_EXACT_DEPLOYMENT_CODEC_VERSION.to_be_bytes());
        output.push(VERIFIED_PAYLOAD_KIND);
        output.extend_from_slice(&(intent.len() as u32).to_be_bytes());
        output.extend_from_slice(&intent);
        output.extend_from_slice(self.agreed_schema_version.as_bytes());
        output.extend_from_slice(self.schema_fingerprint.as_bytes());
        output.extend_from_slice(self.attestation_digest.as_bytes());
        output
    }

    pub fn decode_persisted(
        bytes: &[u8],
    ) -> Result<Self, BranchExactDeploymentError> {
        let mut decoder = Decoder::new(bytes);
        decoder.expect_header(VERIFIED_PAYLOAD_KIND)?;
        let intent_len = decoder.read_u32()? as usize;
        let intent = BranchExactDeploymentIntent::decode_persisted(
            decoder.read_exact(intent_len)?,
        )?;
        let agreed_schema_version = BranchExactScyllaSchemaVersion::try_new(
            decoder.read_array()?,
        )?;
        let schema_fingerprint = BranchExactSchemaFingerprint::from_persisted(
            decoder.read_array()?,
        );
        let persisted_attestation = BranchExactTopologyAttestationDigest(
            decoder.read_array()?,
        );
        decoder.finish()?;
        let expected_attestation = attestation_digest(
            intent.plan_digest,
            &intent.keyspace,
            intent.authority,
            intent.profile,
            intent.schema_version,
            intent.expected_topology.digest(),
            agreed_schema_version,
            schema_fingerprint,
        );
        if persisted_attestation != expected_attestation {
            return Err(BranchExactDeploymentError::AttestationDigestMismatch);
        }
        Ok(Self {
            intent,
            agreed_schema_version,
            schema_fingerprint,
            attestation_digest: expected_attestation,
        })
    }
}

fn encode_intent(intent: &BranchExactDeploymentIntent) -> Vec<u8> {
    let keyspace = intent.keyspace.as_str().as_bytes();
    let mut output = Vec::with_capacity(
        2 + 1 + 2 + 1 + 7 + 1 + keyspace.len() + 32 + 2
            + intent.expected_topology.nodes.len() * 16,
    );
    output.extend_from_slice(&BRANCH_EXACT_DEPLOYMENT_CODEC_VERSION.to_be_bytes());
    output.push(INTENT_PAYLOAD_KIND);
    output.extend_from_slice(&intent.schema_version.to_be_bytes());
    output.push(encode_profile(intent.profile));
    encode_authority(&mut output, intent.authority);
    output.push(keyspace.len() as u8);
    output.extend_from_slice(keyspace);
    output.extend_from_slice(intent.plan_digest.as_bytes());
    output.extend_from_slice(&(intent.expected_topology.nodes.len() as u16).to_be_bytes());
    for node in &intent.expected_topology.nodes {
        output.extend_from_slice(node.as_bytes());
    }
    output
}

fn decode_intent(bytes: &[u8]) -> Result<BranchExactDeploymentIntent, BranchExactDeploymentError> {
    let mut decoder = Decoder::new(bytes);
    decoder.expect_header(INTENT_PAYLOAD_KIND)?;
    let schema_version = decoder.read_u16()?;
    if schema_version != BRANCH_EXACT_SCHEMA_VERSION {
        return Err(BranchExactDeploymentError::UnsupportedSchemaVersion(
            schema_version,
        ));
    }
    let profile = decode_profile(decoder.read_u8()?)?;
    let authority = decode_authority(&mut decoder)?;
    let keyspace_len = decoder.read_u8()? as usize;
    let keyspace = std::str::from_utf8(decoder.read_exact(keyspace_len)?)
        .map_err(|_| BranchExactDeploymentError::InvalidKeyspaceEncoding)?;
    let keyspace = CqlKeyspaceName::try_new(keyspace.to_owned())
        .map_err(|_| BranchExactDeploymentError::InvalidKeyspaceEncoding)?;
    let plan_digest = BranchExactMaterializationPlanDigest::from_persisted(
        decoder.read_array()?,
    );
    let count = decoder.read_u16()? as usize;
    let mut nodes = Vec::with_capacity(count);
    for _ in 0..count {
        nodes.push(BranchExactScyllaNodeId::try_new(decoder.read_array()?)?);
    }
    decoder.finish()?;
    let expected_topology = BranchExactExpectedTopology::try_new(nodes)?;
    let mut intent = BranchExactDeploymentIntent {
        keyspace,
        authority,
        profile,
        schema_version,
        plan_digest,
        expected_topology,
        digest: BranchExactDeploymentIntentDigest([0; 32]),
    };
    intent.digest = intent_digest(&intent);
    Ok(intent)
}

fn encode_profile(profile: CanonicalHeadBootstrapProfile) -> u8 {
    match profile {
        CanonicalHeadBootstrapProfile::GenesisNative => 1,
        CanonicalHeadBootstrapProfile::PostGenesisFloor => 2,
    }
}

fn decode_profile(value: u8) -> Result<CanonicalHeadBootstrapProfile, BranchExactDeploymentError> {
    match value {
        1 => Ok(CanonicalHeadBootstrapProfile::GenesisNative),
        2 => Ok(CanonicalHeadBootstrapProfile::PostGenesisFloor),
        _ => Err(BranchExactDeploymentError::UnknownProfile(value)),
    }
}

fn encode_authority(output: &mut Vec<u8>, authority: AuthorityScope) {
    match authority {
        AuthorityScope::Coordinator => output.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0]),
        AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } => {
            output.push(2);
            output.extend_from_slice(&realm_id.to_be_bytes());
            output.extend_from_slice(&realm_sub_id.to_be_bytes());
        }
    }
}

fn decode_authority(decoder: &mut Decoder<'_>) -> Result<AuthorityScope, BranchExactDeploymentError> {
    match decoder.read_u8()? {
        1 => {
            if decoder.read_exact(6)? != [0; 6] {
                return Err(BranchExactDeploymentError::MalformedAuthority);
            }
            Ok(AuthorityScope::Coordinator)
        }
        2 => Ok(AuthorityScope::Realm {
            realm_id: decoder.read_u32()?,
            realm_sub_id: decoder.read_u16()?,
        }),
        _ => Err(BranchExactDeploymentError::MalformedAuthority),
    }
}

fn update_authority(hasher: &mut Sha256, authority: AuthorityScope) {
    let mut encoded = Vec::with_capacity(7);
    encode_authority(&mut encoded, authority);
    hasher.update(encoded);
}

fn update_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u32).to_be_bytes());
    hasher.update(bytes);
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn expect_header(&mut self, kind: u8) -> Result<(), BranchExactDeploymentError> {
        let version = self.read_u16()?;
        if version != BRANCH_EXACT_DEPLOYMENT_CODEC_VERSION {
            return Err(BranchExactDeploymentError::UnknownCodecVersion(version));
        }
        let actual_kind = self.read_u8()?;
        if actual_kind != kind {
            return Err(BranchExactDeploymentError::UnexpectedPayloadKind(actual_kind));
        }
        Ok(())
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], BranchExactDeploymentError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(BranchExactDeploymentError::TruncatedPayload)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(BranchExactDeploymentError::TruncatedPayload)?;
        self.offset = end;
        Ok(value)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], BranchExactDeploymentError> {
        Ok(self
            .read_exact(N)?
            .try_into()
            .expect("exact decoder slice length"))
    }

    fn read_u8(&mut self) -> Result<u8, BranchExactDeploymentError> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, BranchExactDeploymentError> {
        Ok(u16::from_be_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> Result<u32, BranchExactDeploymentError> {
        Ok(u32::from_be_bytes(self.read_array()?))
    }

    fn finish(self) -> Result<(), BranchExactDeploymentError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(BranchExactDeploymentError::TrailingBytes)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactDeploymentError {
    NilNodeId,
    NilSchemaVersion,
    TopologyTooSmall { actual: usize, minimum: usize },
    TopologyTooLarge { actual: usize, maximum: usize },
    DuplicateExpectedNode,
    DuplicateObservedNode,
    ObservedTopologyMismatch,
    NodeSchemaNotExact,
    SchemaVersionDisagreement,
    SchemaFingerprintMismatch,
    IntentAttestationMismatch,
    UnknownCodecVersion(u16),
    UnexpectedPayloadKind(u8),
    UnsupportedSchemaVersion(u16),
    UnknownProfile(u8),
    MalformedAuthority,
    InvalidKeyspaceEncoding,
    TruncatedPayload,
    TrailingBytes,
    AttestationDigestMismatch,
}

impl fmt::Display for BranchExactDeploymentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for BranchExactDeploymentError {}

#[cfg(test)]
mod tests {
    use parth_core::PHash;
    use psy_data::protocol::canonical_chain::{
        CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
        CheckpointRef, NetworkId,
    };
    use psy_node_core::store::{
        branch_exact_schema::BranchExactSchemaMaterializationPlan,
        canonical_head::{
            CanonicalHeadBootstrap, CanonicalHeadBootstrapProfile,
        },
    };

    use super::*;
    use crate::rollback::{
        branch_exact_schema_fingerprint,
        BranchExactSchemaMaterializationRequest,
    };

    fn node(value: u8) -> BranchExactScyllaNodeId {
        BranchExactScyllaNodeId::try_new([value; 16]).unwrap()
    }

    fn schema_version(value: u8) -> BranchExactScyllaSchemaVersion {
        BranchExactScyllaSchemaVersion::try_new([value; 16]).unwrap()
    }

    fn authority() -> AuthorityScope {
        AuthorityScope::Realm {
            realm_id: 7,
            realm_sub_id: 2,
        }
    }

    fn request(keyspace: &str) -> BranchExactSchemaMaterializationRequest {
        let bootstrap = CanonicalHeadBootstrap::try_new(
            CanonicalHeadBootstrapProfile::GenesisNative,
            CanonicalChainRef::new(
                NetworkId::try_from_chain_id(1337).unwrap(),
                ChainEpoch::new(0),
                CheckpointRef::new(
                    CheckpointId::new(0),
                    CheckpointHash::from_last_chain_hash(PHash::ZERO),
                ),
            ),
        )
        .unwrap();
        let plan = BranchExactSchemaMaterializationPlan::try_new(
            &bootstrap,
            authority(),
            None,
        )
        .unwrap();
        BranchExactSchemaMaterializationRequest::try_new(
            CqlKeyspaceName::try_new(keyspace).unwrap(),
            plan,
        )
        .unwrap()
    }

    fn topology() -> BranchExactExpectedTopology {
        BranchExactExpectedTopology::try_new(vec![node(3), node(1), node(2)])
            .unwrap()
    }

    fn receipt(
        request: &BranchExactSchemaMaterializationRequest,
    ) -> BranchExactSchemaOnlyReceipt {
        BranchExactSchemaOnlyReceipt::from_verified_parts_for_deployment(
            request,
            branch_exact_schema_fingerprint(authority()),
        )
    }

    fn observations(
        version: BranchExactScyllaSchemaVersion,
    ) -> Vec<BranchExactNodeSchemaPostflight> {
        [node(1), node(2), node(3)]
            .into_iter()
            .map(|node_id| {
                BranchExactNodeSchemaPostflight::try_new(
                    node_id,
                    version,
                    BranchExactSchemaInspection::Exact {
                        fingerprint: branch_exact_schema_fingerprint(authority()),
                    },
                )
                .unwrap()
            })
            .collect()
    }

    #[test]
    fn expected_topology_is_sorted_unique_and_order_independent() {
        let first = topology();
        let second = BranchExactExpectedTopology::try_new(vec![
            node(2),
            node(3),
            node(1),
        ])
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.nodes(), &[node(1), node(2), node(3)]);
        assert_eq!(first.digest(), second.digest());
        assert_eq!(
            BranchExactExpectedTopology::try_new(vec![node(1), node(2)]),
            Err(BranchExactDeploymentError::TopologyTooSmall {
                actual: 2,
                minimum: 3,
            })
        );
        assert_eq!(
            BranchExactExpectedTopology::try_new(vec![node(1), node(1), node(2)]),
            Err(BranchExactDeploymentError::DuplicateExpectedNode)
        );
        assert_eq!(
            BranchExactExpectedTopology::try_new(vec![
                node(1);
                MAX_EXPECTED_TOPOLOGY_NODES + 1
            ]),
            Err(BranchExactDeploymentError::TopologyTooLarge {
                actual: MAX_EXPECTED_TOPOLOGY_NODES + 1,
                maximum: MAX_EXPECTED_TOPOLOGY_NODES,
            })
        );
    }

    #[test]
    fn node_postflight_requires_exact_schema() {
        assert_eq!(
            BranchExactNodeSchemaPostflight::try_new(
                node(1),
                schema_version(7),
                BranchExactSchemaInspection::Absent,
            ),
            Err(BranchExactDeploymentError::NodeSchemaNotExact)
        );
        assert_eq!(
            BranchExactScyllaNodeId::try_new([0; 16]),
            Err(BranchExactDeploymentError::NilNodeId)
        );
        assert_eq!(
            BranchExactScyllaSchemaVersion::try_new([0; 16]),
            Err(BranchExactDeploymentError::NilSchemaVersion)
        );
    }

    #[test]
    fn full_topology_attestation_is_exact_and_order_independent() {
        let request = request("psy_h13_realm");
        let receipt = receipt(&request);
        let first = BranchExactTopologyAttestation::try_new(
            &receipt,
            topology(),
            observations(schema_version(7)),
        )
        .unwrap();
        let mut reversed = observations(schema_version(7));
        reversed.reverse();
        let second = BranchExactTopologyAttestation::try_new(
            &receipt,
            topology(),
            reversed,
        )
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.digest(), second.digest());
    }

    #[test]
    fn missing_extra_duplicate_disagreement_and_wrong_fingerprint_fail_closed() {
        let request = request("psy_h13_fail_closed");
        let receipt = receipt(&request);

        let mut missing = observations(schema_version(7));
        missing.pop();
        assert_eq!(
            BranchExactTopologyAttestation::try_new(
                &receipt,
                topology(),
                missing,
            ),
            Err(BranchExactDeploymentError::ObservedTopologyMismatch)
        );

        let mut duplicate = observations(schema_version(7));
        duplicate[2] = duplicate[1];
        assert_eq!(
            BranchExactTopologyAttestation::try_new(
                &receipt,
                topology(),
                duplicate,
            ),
            Err(BranchExactDeploymentError::DuplicateObservedNode)
        );

        let mut extra = observations(schema_version(7));
        extra.push(BranchExactNodeSchemaPostflight::try_new(
            node(4),
            schema_version(7),
            BranchExactSchemaInspection::Exact {
                fingerprint: branch_exact_schema_fingerprint(authority()),
            },
        ).unwrap());
        assert_eq!(
            BranchExactTopologyAttestation::try_new(
                &receipt,
                topology(),
                extra,
            ),
            Err(BranchExactDeploymentError::ObservedTopologyMismatch)
        );

        let mut disagreement = observations(schema_version(7));
        disagreement[2] = BranchExactNodeSchemaPostflight::try_new(
            node(3),
            schema_version(8),
            BranchExactSchemaInspection::Exact {
                fingerprint: branch_exact_schema_fingerprint(authority()),
            },
        ).unwrap();
        assert_eq!(
            BranchExactTopologyAttestation::try_new(
                &receipt,
                topology(),
                disagreement,
            ),
            Err(BranchExactDeploymentError::SchemaVersionDisagreement)
        );

        let mut wrong_fingerprint = observations(schema_version(7));
        wrong_fingerprint[2] = BranchExactNodeSchemaPostflight::try_new(
            node(3),
            schema_version(7),
            BranchExactSchemaInspection::Exact {
                fingerprint: branch_exact_schema_fingerprint(
                    AuthorityScope::Coordinator,
                ),
            },
        ).unwrap();
        assert_eq!(
            BranchExactTopologyAttestation::try_new(
                &receipt,
                topology(),
                wrong_fingerprint,
            ),
            Err(BranchExactDeploymentError::SchemaFingerprintMismatch)
        );
    }

    #[test]
    fn intent_binds_request_keyspace_plan_and_topology() {
        let primary_request = request("psy_h13_intent");
        let intent = BranchExactDeploymentIntent::new(&primary_request, topology());
        assert!(intent.matches_request(&primary_request));
        let other_request = request("psy_h13_other");
        assert!(!intent.matches_request(&other_request));
        let primary_attestation = BranchExactTopologyAttestation::try_new(
            &receipt(&primary_request),
            topology(),
            observations(schema_version(7)),
        )
        .unwrap();
        assert_eq!(
            BranchExactVerifiedDeploymentReceipt::try_new(
                BranchExactDeploymentIntent::new(&other_request, topology()),
                primary_attestation,
            ),
            Err(BranchExactDeploymentError::IntentAttestationMismatch)
        );
        assert_eq!(
            BranchExactDeploymentIntent::decode_persisted(
                &intent.to_canonical_bytes()
            )
            .unwrap(),
            intent
        );
    }

    #[test]
    fn verified_receipt_round_trips_and_tamper_fails() {
        let request = request("psy_h13_verified");
        let intent = BranchExactDeploymentIntent::new(&request, topology());
        let attestation = BranchExactTopologyAttestation::try_new(
            &receipt(&request),
            topology(),
            observations(schema_version(7)),
        )
        .unwrap();
        let verified = BranchExactVerifiedDeploymentReceipt::try_new(
            intent,
            attestation,
        )
        .unwrap();
        let encoded = verified.to_canonical_bytes();
        assert_eq!(
            BranchExactVerifiedDeploymentReceipt::decode_persisted(&encoded)
                .unwrap(),
            verified
        );

        let mut tampered = encoded.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert_eq!(
            BranchExactVerifiedDeploymentReceipt::decode_persisted(&tampered),
            Err(BranchExactDeploymentError::AttestationDigestMismatch)
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            BranchExactVerifiedDeploymentReceipt::decode_persisted(&trailing),
            Err(BranchExactDeploymentError::TrailingBytes)
        );
    }

    #[test]
    fn persisted_intent_rejects_malformed_payloads() {
        let request = request("psy_h13_codec");
        let intent = BranchExactDeploymentIntent::new(&request, topology());
        let encoded = intent.to_canonical_bytes();
        assert_eq!(
            BranchExactDeploymentIntent::decode_persisted(&encoded[..2]),
            Err(BranchExactDeploymentError::TruncatedPayload)
        );
        let mut unknown = encoded.clone();
        unknown[1] = 2;
        assert_eq!(
            BranchExactDeploymentIntent::decode_persisted(&unknown),
            Err(BranchExactDeploymentError::UnknownCodecVersion(2))
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            BranchExactDeploymentIntent::decode_persisted(&trailing),
            Err(BranchExactDeploymentError::TrailingBytes)
        );
    }

    #[test]
    fn local_postflight_query_has_no_dynamic_or_filtering_surface() {
        assert_eq!(
            INSPECT_LOCAL_SCHEMA_POSTFLIGHT_CQL,
            "SELECT host_id, schema_version FROM system.local"
        );
        assert!(!INSPECT_LOCAL_SCHEMA_POSTFLIGHT_CQL.contains("ALLOW FILTERING"));
    }
}
