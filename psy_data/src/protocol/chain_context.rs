//! Versioned, driver-independent chain contexts for the rollback epoch fence.
//!
//! These types freeze the semantic identity shared by future RPC, NATS, proof,
//! provider, and cache adapters. They deliberately do not execute I/O and are
//! not wired into current production handlers yet.

use std::{error::Error, fmt};

use parth_core::{
    protocol::core_types::Q256BitHash, QJobIdBase, QJOB_ID_SERIALIZED_SIZE,
};
use serde::{
    de::Error as SerdeDeError, ser::SerializeStruct, Deserialize, Deserializer, Serialize,
    Serializer,
};
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata};

use super::canonical_chain::{
    CanonicalChainRef, CanonicalChainRefCodecError, CheckpointHash, CheckpointId,
    CheckpointRef, CANONICAL_CHAIN_REF_V1_LEN,
};

pub const CHAIN_CONTEXT_CODEC_VERSION: u16 = 1;

pub const AUTHORITY_OBSERVATION_MAGIC: [u8; 8] = *b"PSYAUTHO";
pub const PENDING_CONTEXT_MAGIC: [u8; 8] = *b"PSYPENDC";
pub const WORK_CONTEXT_MAGIC: [u8; 8] = *b"PSYWORKC";
pub const HISTORICAL_READ_CONTEXT_MAGIC: [u8; 8] = *b"PSYHISTC";

const CONTEXT_HEADER_LEN: usize = 10;
const AUTHORITY_SCOPE_LEN: usize = 7;
pub const AUTHORITY_OBSERVATION_V1_LEN: usize =
    CONTEXT_HEADER_LEN + CANONICAL_CHAIN_REF_V1_LEN + AUTHORITY_SCOPE_LEN + 8 + 32;
pub const PENDING_CONTEXT_V1_LEN: usize =
    CONTEXT_HEADER_LEN + CANONICAL_CHAIN_REF_V1_LEN + AUTHORITY_SCOPE_LEN + 8 + 16;
pub const WORK_CONTEXT_V1_LEN: usize = PENDING_CONTEXT_V1_LEN + QJOB_ID_SERIALIZED_SIZE;
pub const HISTORICAL_READ_CONTEXT_V1_LEN: usize =
    CONTEXT_HEADER_LEN + CANONICAL_CHAIN_REF_V1_LEN + 8 + 32;

/// Opaque, canonical wire token for one [`WorkContext`].
///
/// Workers must echo this token unchanged when submitting a proof. Only the
/// node Edge decodes it and compares every field with the atomically published
/// current [`PendingContext`]. Keeping the fixed-size canonical bytes in the
/// wire type also prevents JSON/RPC clients from constructing a partial
/// context or silently defaulting a newly added field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, ts_rs::TS)]
#[cfg_attr(
    feature = "serialize_rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
#[cfg_attr(
    feature = "serialize_speedy",
    derive(speedy::Readable, speedy::Writable)
)]
pub struct WorkContextToken {
    #[ts(type = "Array<number>")]
    bytes: [u8; WORK_CONTEXT_V1_LEN],
}

impl WorkContextToken {
    pub fn from_work_context<Hash: Q256BitHash, JobId: QJobIdBase>(
        context: &WorkContext<Hash, JobId>,
    ) -> Self {
        Self {
            bytes: context.to_canonical_bytes(),
        }
    }

    pub const fn as_bytes(&self) -> &[u8; WORK_CONTEXT_V1_LEN] {
        &self.bytes
    }

    pub fn decode<Hash: Q256BitHash, JobId: QJobIdBase>(
        &self,
    ) -> Result<WorkContext<Hash, JobId>, ChainContextCodecError> {
        WorkContext::from_canonical_bytes(&self.bytes)
    }

    pub fn try_from_canonical_bytes<Hash: Q256BitHash, JobId: QJobIdBase>(
        bytes: [u8; WORK_CONTEXT_V1_LEN],
    ) -> Result<Self, ChainContextCodecError> {
        WorkContext::<Hash, JobId>::from_canonical_bytes(&bytes)?;
        Ok(Self { bytes })
    }
}

impl Serialize for WorkContextToken {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("WorkContextToken", 1)?;
        state.serialize_field("bytes", self.bytes.as_slice())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for WorkContextToken {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            bytes: Vec<u8>,
        }

        let wire = Wire::deserialize(deserializer)?;
        let bytes: [u8; WORK_CONTEXT_V1_LEN] = wire.bytes.try_into().map_err(|bytes: Vec<u8>| {
            D::Error::custom(format_args!(
                "work-context token must contain exactly {WORK_CONTEXT_V1_LEN} bytes, got {}",
                bytes.len()
            ))
        })?;
        Ok(Self { bytes })
    }
}

const AUTHORITY_KIND_COORDINATOR: u8 = 1;
const AUTHORITY_KIND_REALM: u8 = 2;

/// A required protocol version that only decodes the current context schema.
///
/// It is private inside public envelopes, has no `Default`, and cannot be
/// constructed from an arbitrary integer by callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ChainContextCodecVersion;

impl ChainContextCodecVersion {
    const fn current() -> Self {
        Self
    }
}

impl Serialize for ChainContextCodecVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u16(CHAIN_CONTEXT_CODEC_VERSION)
    }
}

impl<'de> Deserialize<'de> for ChainContextCodecVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let version = u16::deserialize(deserializer)?;
        if version != CHAIN_CONTEXT_CODEC_VERSION {
            return Err(D::Error::custom(format_args!(
                "unsupported chain-context codec version {version}"
            )));
        }
        Ok(Self)
    }
}

/// Exact storage authority scope.
///
/// A Realm includes both current routing dimensions. There is no packed bare
/// `u64` authority identifier that could silently lose `realm_sub_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthorityScope {
    Coordinator,
    Realm { realm_id: u32, realm_sub_id: u16 },
}

impl AuthorityScope {
    fn to_canonical_bytes(self) -> [u8; AUTHORITY_SCOPE_LEN] {
        let mut bytes = [0u8; AUTHORITY_SCOPE_LEN];
        match self {
            Self::Coordinator => bytes[0] = AUTHORITY_KIND_COORDINATOR,
            Self::Realm {
                realm_id,
                realm_sub_id,
            } => {
                bytes[0] = AUTHORITY_KIND_REALM;
                bytes[1..5].copy_from_slice(&realm_id.to_le_bytes());
                bytes[5..7].copy_from_slice(&realm_sub_id.to_le_bytes());
            }
        }
        bytes
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ChainContextCodecError> {
        debug_assert_eq!(bytes.len(), AUTHORITY_SCOPE_LEN);
        match bytes[0] {
            AUTHORITY_KIND_COORDINATOR => {
                if bytes[1..].iter().any(|byte| *byte != 0) {
                    return Err(ChainContextCodecError::NonCanonicalCoordinatorScope);
                }
                Ok(Self::Coordinator)
            }
            AUTHORITY_KIND_REALM => Ok(Self::Realm {
                realm_id: u32::from_le_bytes(bytes[1..5].try_into().expect("fixed slice")),
                realm_sub_id: u16::from_le_bytes(bytes[5..7].try_into().expect("fixed slice")),
            }),
            kind => Err(ChainContextCodecError::UnknownAuthorityKind(kind)),
        }
    }
}

/// Last checkpoint height at which an authority's logical state changed.
///
/// This is not the Coordinator's current head and is intentionally not
/// interchangeable with [`CheckpointId`].
///
/// ```compile_fail
/// use psy_data::protocol::{canonical_chain::CheckpointId, chain_context::AuthorityStateCheckpointId};
/// let _: CheckpointId = AuthorityStateCheckpointId::new(7);
/// ```
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct AuthorityStateCheckpointId(u64);

impl AuthorityStateCheckpointId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Authority-local state root, distinct from a Coordinator checkpoint hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuthorityStateRoot<Hash>(Hash);

impl<Hash> AuthorityStateRoot<Hash> {
    pub const fn from_local_state_root(root: Hash) -> Self {
        Self(root)
    }

    pub const fn as_inner(&self) -> &Hash {
        &self.0
    }

    pub fn into_inner(self) -> Hash {
        self.0
    }
}

/// Pending namespace carried by messages and proof work.
///
/// ```compile_fail
/// use psy_data::protocol::{canonical_chain::CheckpointId, chain_context::WorkUniquePendingId};
/// let _: CheckpointId = WorkUniquePendingId::new(7);
/// ```
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct WorkUniquePendingId(u64);

impl WorkUniquePendingId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Exact proc namespace. Canonical bytes use the same big-endian UUID-like
/// representation as the typed storage prototype.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorkProcCheckpointUniqueId([u8; 16]);

impl WorkProcCheckpointUniqueId {
    pub const fn from_u128(value: u128) -> Self {
        Self(value.to_be_bytes())
    }

    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub const fn as_u128(self) -> u128 {
        u128::from_be_bytes(self.0)
    }
}

impl Serialize for WorkProcCheckpointUniqueId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for WorkProcCheckpointUniqueId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        if encoded.len() != 32 {
            return Err(D::Error::custom("proc checkpoint unique ID must be 16-byte hex"));
        }
        let mut bytes = [0u8; 16];
        hex::decode_to_slice(&encoded, &mut bytes)
            .map_err(|_| D::Error::custom("proc checkpoint unique ID must be canonical hex"))?;
        if hex::encode(bytes) != encoded {
            return Err(D::Error::custom(
                "proc checkpoint unique ID must use lowercase canonical hex",
            ));
        }
        Ok(Self(bytes))
    }
}

/// Stable observation of one authority's materialized state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct AuthorityObservation<Hash> {
    chain: CanonicalChainRef<Hash>,
    authority: AuthorityScope,
    state_checkpoint_id: AuthorityStateCheckpointId,
    state_root: AuthorityStateRoot<Hash>,
}

impl<Hash> AuthorityObservation<Hash> {
    pub fn try_new(
        chain: CanonicalChainRef<Hash>,
        authority: AuthorityScope,
        state_checkpoint_id: AuthorityStateCheckpointId,
        state_root: AuthorityStateRoot<Hash>,
    ) -> Result<Self, ChainContextValidationError> {
        validate_authority_state_checkpoint(&chain, authority, state_checkpoint_id)?;
        Ok(Self {
            chain,
            authority,
            state_checkpoint_id,
            state_root,
        })
    }

    pub const fn chain(&self) -> &CanonicalChainRef<Hash> {
        &self.chain
    }

    pub const fn authority(&self) -> AuthorityScope {
        self.authority
    }

    pub const fn state_checkpoint_id(&self) -> AuthorityStateCheckpointId {
        self.state_checkpoint_id
    }

    pub const fn state_root(&self) -> &AuthorityStateRoot<Hash> {
        &self.state_root
    }
}

impl<'de, Hash: Deserialize<'de>> Deserialize<'de> for AuthorityObservation<Hash> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire<Hash> {
            chain: CanonicalChainRef<Hash>,
            authority: AuthorityScope,
            state_checkpoint_id: AuthorityStateCheckpointId,
            state_root: AuthorityStateRoot<Hash>,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::try_new(
            wire.chain,
            wire.authority,
            wire.state_checkpoint_id,
            wire.state_root,
        )
        .map_err(D::Error::custom)
    }
}

impl<Hash: Q256BitHash> AuthorityObservation<Hash> {
    pub fn to_canonical_bytes(&self) -> [u8; AUTHORITY_OBSERVATION_V1_LEN] {
        let mut bytes = [0u8; AUTHORITY_OBSERVATION_V1_LEN];
        write_header(&mut bytes, AUTHORITY_OBSERVATION_MAGIC);
        bytes[10..75].copy_from_slice(&self.chain.to_canonical_bytes());
        bytes[75..82].copy_from_slice(&self.authority.to_canonical_bytes());
        bytes[82..90].copy_from_slice(&self.state_checkpoint_id.get().to_le_bytes());
        bytes[90..122].copy_from_slice(&self.state_root.0.into_owned_32bytes());
        bytes
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ChainContextCodecError> {
        validate_header(bytes, AUTHORITY_OBSERVATION_MAGIC, AUTHORITY_OBSERVATION_V1_LEN)?;
        let chain = CanonicalChainRef::from_canonical_bytes(&bytes[10..75])?;
        let authority = AuthorityScope::from_canonical_bytes(&bytes[75..82])?;
        let state_checkpoint_id = AuthorityStateCheckpointId::new(u64::from_le_bytes(
            bytes[82..90].try_into().expect("fixed slice"),
        ));
        let state_root = AuthorityStateRoot::from_local_state_root(Hash::from_owned_32bytes(
            bytes[90..122].try_into().expect("fixed slice"),
        ));
        Self::try_new(chain, authority, state_checkpoint_id, state_root).map_err(Into::into)
    }
}

impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for AuthorityObservation<Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = AUTHORITY_OBSERVATION_V1_LEN;
}

impl<Hash: Q256BitHash> FallbackPsySerializeCanonical for AuthorityObservation<Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        AUTHORITY_OBSERVATION_V1_LEN
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.to_canonical_bytes())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let bytes: [u8; AUTHORITY_OBSERVATION_V1_LEN] = reader.psy_read_bytes_fixed()?;
        Ok(Self::from_canonical_bytes(&bytes)?)
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
impl<Hash: Q256BitHash, C: speedy::Context> speedy::Writable<C>
    for AuthorityObservation<Hash>
{
    fn write_to<T: ?Sized + speedy::Writer<C>>(
        &self,
        writer: &mut T,
    ) -> Result<(), C::Error> {
        writer.write_bytes(&self.to_canonical_bytes())
    }

    fn bytes_needed(&self) -> Result<usize, C::Error> {
        Ok(AUTHORITY_OBSERVATION_V1_LEN)
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
impl<'a, Hash: Q256BitHash, C: speedy::Context> speedy::Readable<'a, C>
    for AuthorityObservation<Hash>
{
    fn read_from<T: speedy::Reader<'a, C>>(reader: &mut T) -> Result<Self, C::Error> {
        let mut bytes = [0u8; AUTHORITY_OBSERVATION_V1_LEN];
        reader.read_bytes(&mut bytes)?;
        Self::from_canonical_bytes(&bytes)
            .map_err(|error| speedy::Error::custom(error).into())
    }

    fn minimum_bytes_needed() -> usize {
        AUTHORITY_OBSERVATION_V1_LEN
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    AuthorityObservation,
    { Hash: Q256BitHash } => { Hash }
);

#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical
    for AuthorityObservation<Hash>
{
}

/// Required context for one pending/proc namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingContext<Hash> {
    codec_version: ChainContextCodecVersion,
    chain: CanonicalChainRef<Hash>,
    authority: AuthorityScope,
    unique_pending_id: WorkUniquePendingId,
    proc_checkpoint_unique_id: WorkProcCheckpointUniqueId,
}

impl<Hash> PendingContext<Hash> {
    pub const fn new(
        chain: CanonicalChainRef<Hash>,
        authority: AuthorityScope,
        unique_pending_id: WorkUniquePendingId,
        proc_checkpoint_unique_id: WorkProcCheckpointUniqueId,
    ) -> Self {
        Self {
            codec_version: ChainContextCodecVersion::current(),
            chain,
            authority,
            unique_pending_id,
            proc_checkpoint_unique_id,
        }
    }

    pub const fn chain(&self) -> &CanonicalChainRef<Hash> {
        &self.chain
    }

    pub const fn authority(&self) -> AuthorityScope {
        self.authority
    }

    pub const fn unique_pending_id(&self) -> WorkUniquePendingId {
        self.unique_pending_id
    }

    pub const fn proc_checkpoint_unique_id(&self) -> WorkProcCheckpointUniqueId {
        self.proc_checkpoint_unique_id
    }
}

impl<Hash: Q256BitHash> PendingContext<Hash> {
    pub fn to_canonical_bytes(&self) -> [u8; PENDING_CONTEXT_V1_LEN] {
        let mut bytes = [0u8; PENDING_CONTEXT_V1_LEN];
        write_header(&mut bytes, PENDING_CONTEXT_MAGIC);
        bytes[10..75].copy_from_slice(&self.chain.to_canonical_bytes());
        bytes[75..82].copy_from_slice(&self.authority.to_canonical_bytes());
        bytes[82..90].copy_from_slice(&self.unique_pending_id.get().to_le_bytes());
        bytes[90..106].copy_from_slice(self.proc_checkpoint_unique_id.as_bytes());
        bytes
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ChainContextCodecError> {
        validate_header(bytes, PENDING_CONTEXT_MAGIC, PENDING_CONTEXT_V1_LEN)?;
        Ok(Self::new(
            CanonicalChainRef::from_canonical_bytes(&bytes[10..75])?,
            AuthorityScope::from_canonical_bytes(&bytes[75..82])?,
            WorkUniquePendingId::new(u64::from_le_bytes(
                bytes[82..90].try_into().expect("fixed slice"),
            )),
            WorkProcCheckpointUniqueId::from_bytes(
                bytes[90..106].try_into().expect("fixed slice"),
            ),
        ))
    }
}

/// Complete opaque proof-work token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct WorkContext<Hash, JobId> {
    codec_version: ChainContextCodecVersion,
    chain: CanonicalChainRef<Hash>,
    authority: AuthorityScope,
    unique_pending_id: WorkUniquePendingId,
    proc_checkpoint_unique_id: WorkProcCheckpointUniqueId,
    job_id: JobId,
}

impl<Hash, JobId: QJobIdBase> WorkContext<Hash, JobId> {
    pub fn try_new(
        chain: CanonicalChainRef<Hash>,
        authority: AuthorityScope,
        unique_pending_id: WorkUniquePendingId,
        proc_checkpoint_unique_id: WorkProcCheckpointUniqueId,
        job_id: JobId,
    ) -> Result<Self, ChainContextValidationError> {
        if !job_id.is_valid() {
            return Err(ChainContextValidationError::InvalidJobId);
        }
        Ok(Self {
            codec_version: ChainContextCodecVersion::current(),
            chain,
            authority,
            unique_pending_id,
            proc_checkpoint_unique_id,
            job_id,
        })
    }

    pub const fn chain(&self) -> &CanonicalChainRef<Hash> {
        &self.chain
    }

    pub const fn authority(&self) -> AuthorityScope {
        self.authority
    }

    pub const fn unique_pending_id(&self) -> WorkUniquePendingId {
        self.unique_pending_id
    }

    pub const fn proc_checkpoint_unique_id(&self) -> WorkProcCheckpointUniqueId {
        self.proc_checkpoint_unique_id
    }

    pub const fn job_id(&self) -> &JobId {
        &self.job_id
    }
}

impl<Hash: PartialEq, JobId: QJobIdBase> WorkContext<Hash, JobId> {
    /// Verify that the non-job portion of this token still names the exact
    /// atomically published pending namespace.
    pub fn ensure_matches_pending_context(
        &self,
        current: &PendingContext<Hash>,
    ) -> Result<(), ChainContextValidationError> {
        if self.chain != current.chain
            || self.authority != current.authority
            || self.unique_pending_id != current.unique_pending_id
            || self.proc_checkpoint_unique_id != current.proc_checkpoint_unique_id
        {
            return Err(ChainContextValidationError::StaleWorkContext);
        }
        Ok(())
    }
}

impl<'de, Hash, JobId> Deserialize<'de> for WorkContext<Hash, JobId>
where
    Hash: Deserialize<'de>,
    JobId: QJobIdBase,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire<Hash, JobId> {
            codec_version: ChainContextCodecVersion,
            chain: CanonicalChainRef<Hash>,
            authority: AuthorityScope,
            unique_pending_id: WorkUniquePendingId,
            proc_checkpoint_unique_id: WorkProcCheckpointUniqueId,
            job_id: JobId,
        }

        let wire = Wire::deserialize(deserializer)?;
        let _ = wire.codec_version;
        Self::try_new(
            wire.chain,
            wire.authority,
            wire.unique_pending_id,
            wire.proc_checkpoint_unique_id,
            wire.job_id,
        )
        .map_err(D::Error::custom)
    }
}

impl<Hash: Q256BitHash, JobId: QJobIdBase> WorkContext<Hash, JobId> {
    pub fn to_canonical_bytes(&self) -> [u8; WORK_CONTEXT_V1_LEN] {
        let mut bytes = [0u8; WORK_CONTEXT_V1_LEN];
        write_header(&mut bytes, WORK_CONTEXT_MAGIC);
        bytes[10..75].copy_from_slice(&self.chain.to_canonical_bytes());
        bytes[75..82].copy_from_slice(&self.authority.to_canonical_bytes());
        bytes[82..90].copy_from_slice(&self.unique_pending_id.get().to_le_bytes());
        bytes[90..106].copy_from_slice(self.proc_checkpoint_unique_id.as_bytes());
        bytes[106..130].copy_from_slice(&self.job_id.to_bytes_fixed());
        bytes
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ChainContextCodecError> {
        validate_header(bytes, WORK_CONTEXT_MAGIC, WORK_CONTEXT_V1_LEN)?;
        let job_bytes = bytes[106..130].try_into().expect("fixed slice");
        let job_id = JobId::from_bytes_fixed(&job_bytes)
            .map_err(|_| ChainContextCodecError::InvalidJobIdEncoding)?;
        Self::try_new(
            CanonicalChainRef::from_canonical_bytes(&bytes[10..75])?,
            AuthorityScope::from_canonical_bytes(&bytes[75..82])?,
            WorkUniquePendingId::new(u64::from_le_bytes(
                bytes[82..90].try_into().expect("fixed slice"),
            )),
            WorkProcCheckpointUniqueId::from_bytes(
                bytes[90..106].try_into().expect("fixed slice"),
            ),
            job_id,
        )
        .map_err(Into::into)
    }
}

/// Exact current-chain plus historical-target selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct HistoricalReadContext<Hash> {
    codec_version: ChainContextCodecVersion,
    expected_chain: CanonicalChainRef<Hash>,
    target: CheckpointRef<Hash>,
}

impl<Hash: PartialEq> HistoricalReadContext<Hash> {
    pub fn try_new(
        expected_chain: CanonicalChainRef<Hash>,
        target: CheckpointRef<Hash>,
    ) -> Result<Self, ChainContextValidationError> {
        validate_historical_target(&expected_chain, &target)?;
        Ok(Self {
            codec_version: ChainContextCodecVersion::current(),
            expected_chain,
            target,
        })
    }

    pub const fn expected_chain(&self) -> &CanonicalChainRef<Hash> {
        &self.expected_chain
    }

    pub const fn target(&self) -> &CheckpointRef<Hash> {
        &self.target
    }
}

impl<'de, Hash> Deserialize<'de> for HistoricalReadContext<Hash>
where
    Hash: Deserialize<'de> + PartialEq,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire<Hash> {
            codec_version: ChainContextCodecVersion,
            expected_chain: CanonicalChainRef<Hash>,
            target: CheckpointRef<Hash>,
        }

        let wire = Wire::deserialize(deserializer)?;
        let _ = wire.codec_version;
        Self::try_new(wire.expected_chain, wire.target).map_err(D::Error::custom)
    }
}

impl<Hash: Q256BitHash> HistoricalReadContext<Hash> {
    pub fn to_canonical_bytes(&self) -> [u8; HISTORICAL_READ_CONTEXT_V1_LEN] {
        let mut bytes = [0u8; HISTORICAL_READ_CONTEXT_V1_LEN];
        write_header(&mut bytes, HISTORICAL_READ_CONTEXT_MAGIC);
        bytes[10..75].copy_from_slice(&self.expected_chain.to_canonical_bytes());
        bytes[75..83].copy_from_slice(&self.target.checkpoint_id().get().to_le_bytes());
        bytes[83..115].copy_from_slice(
            &self
                .target
                .checkpoint_hash()
                .as_inner()
                .into_owned_32bytes(),
        );
        bytes
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ChainContextCodecError> {
        validate_header(
            bytes,
            HISTORICAL_READ_CONTEXT_MAGIC,
            HISTORICAL_READ_CONTEXT_V1_LEN,
        )?;
        Self::try_new(
            CanonicalChainRef::from_canonical_bytes(&bytes[10..75])?,
            CheckpointRef::new(
                CheckpointId::new(u64::from_le_bytes(
                    bytes[75..83].try_into().expect("fixed slice"),
                )),
                CheckpointHash::from_last_chain_hash(Hash::from_owned_32bytes(
                    bytes[83..115].try_into().expect("fixed slice"),
                )),
            ),
        )
        .map_err(Into::into)
    }
}

/// Versioned RPC mutation/admission request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalRequest<Hash, Payload> {
    codec_version: ChainContextCodecVersion,
    expected_chain: CanonicalChainRef<Hash>,
    payload: Payload,
}

impl<Hash, Payload> CanonicalRequest<Hash, Payload> {
    pub const fn new(expected_chain: CanonicalChainRef<Hash>, payload: Payload) -> Self {
        Self {
            codec_version: ChainContextCodecVersion::current(),
            expected_chain,
            payload,
        }
    }

    pub const fn expected_chain(&self) -> &CanonicalChainRef<Hash> {
        &self.expected_chain
    }

    pub const fn payload(&self) -> &Payload {
        &self.payload
    }

    pub fn into_parts(self) -> (CanonicalChainRef<Hash>, Payload) {
        (self.expected_chain, self.payload)
    }
}

/// Versioned RPC historical request. The target is always an exact
/// `CheckpointRef`, never a bare reusable height.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalReadRequest<Hash, Payload> {
    context: HistoricalReadContext<Hash>,
    payload: Payload,
}

impl<'de, Hash, Payload> Deserialize<'de> for HistoricalReadRequest<Hash, Payload>
where
    Hash: Deserialize<'de> + PartialEq,
    Payload: Deserialize<'de>,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(
            deny_unknown_fields,
            bound(deserialize = "Hash: Deserialize<'de> + PartialEq, Payload: Deserialize<'de>")
        )]
        struct Wire<Hash, Payload> {
            context: HistoricalReadContext<Hash>,
            payload: Payload,
        }

        let wire = Wire::deserialize(deserializer)?;
        Ok(Self::new(wire.context, wire.payload))
    }
}

impl<Hash, Payload> HistoricalReadRequest<Hash, Payload> {
    pub const fn new(context: HistoricalReadContext<Hash>, payload: Payload) -> Self {
        Self { context, payload }
    }

    pub const fn context(&self) -> &HistoricalReadContext<Hash> {
        &self.context
    }

    pub const fn payload(&self) -> &Payload {
        &self.payload
    }
}

/// Versioned chain-state response. The observation and value are one logical
/// response and must be produced by the stable read protocol in the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalResponse<Hash, Value> {
    codec_version: ChainContextCodecVersion,
    observed: AuthorityObservation<Hash>,
    value: Value,
}

impl<Hash, Value> CanonicalResponse<Hash, Value> {
    pub const fn new(observed: AuthorityObservation<Hash>, value: Value) -> Self {
        Self {
            codec_version: ChainContextCodecVersion::current(),
            observed,
            value,
        }
    }

    pub const fn observed(&self) -> &AuthorityObservation<Hash> {
        &self.observed
    }

    pub const fn value(&self) -> &Value {
        &self.value
    }
}

/// Versioned NATS message. The pending context is encoded in the payload even
/// when the physical subject also contains a proc identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalMessage<Hash, Payload> {
    context: PendingContext<Hash>,
    payload: Payload,
}

impl<Hash, Payload> CanonicalMessage<Hash, Payload> {
    pub const fn new(context: PendingContext<Hash>, payload: Payload) -> Self {
        Self { context, payload }
    }

    pub const fn context(&self) -> &PendingContext<Hash> {
        &self.context
    }

    pub const fn payload(&self) -> &Payload {
        &self.payload
    }
}

fn validate_authority_state_checkpoint<Hash>(
    chain: &CanonicalChainRef<Hash>,
    authority: AuthorityScope,
    state_checkpoint_id: AuthorityStateCheckpointId,
) -> Result<(), ChainContextValidationError> {
    let head = chain.checkpoint().checkpoint_id().get();
    let state = state_checkpoint_id.get();
    if state > head {
        return Err(ChainContextValidationError::StateCheckpointAhead { head, state });
    }
    if authority == AuthorityScope::Coordinator && state != head {
        return Err(
            ChainContextValidationError::CoordinatorStateCheckpointMismatch { head, state },
        );
    }
    Ok(())
}

fn validate_historical_target<Hash: PartialEq>(
    expected_chain: &CanonicalChainRef<Hash>,
    target: &CheckpointRef<Hash>,
) -> Result<(), ChainContextValidationError> {
    let head = expected_chain.checkpoint().checkpoint_id().get();
    let target_height = target.checkpoint_id().get();
    if target_height > head {
        return Err(ChainContextValidationError::HistoricalTargetAhead {
            head,
            target: target_height,
        });
    }
    if target_height == head && target != expected_chain.checkpoint() {
        return Err(ChainContextValidationError::SameHeightTargetHashMismatch {
            checkpoint_id: head,
        });
    }
    Ok(())
}

fn write_header<const N: usize>(bytes: &mut [u8; N], magic: [u8; 8]) {
    bytes[0..8].copy_from_slice(&magic);
    bytes[8..10].copy_from_slice(&CHAIN_CONTEXT_CODEC_VERSION.to_le_bytes());
}

fn validate_header(
    bytes: &[u8],
    magic: [u8; 8],
    expected_len: usize,
) -> Result<(), ChainContextCodecError> {
    if bytes.len() < CONTEXT_HEADER_LEN {
        return Err(ChainContextCodecError::Truncated {
            expected: expected_len,
            actual: bytes.len(),
        });
    }
    if bytes[0..8] != magic {
        return Err(ChainContextCodecError::InvalidMagic);
    }
    let version = u16::from_le_bytes(bytes[8..10].try_into().expect("fixed slice"));
    if version != CHAIN_CONTEXT_CODEC_VERSION {
        return Err(ChainContextCodecError::UnsupportedVersion(version));
    }
    if bytes.len() < expected_len {
        return Err(ChainContextCodecError::Truncated {
            expected: expected_len,
            actual: bytes.len(),
        });
    }
    if bytes.len() > expected_len {
        return Err(ChainContextCodecError::TrailingBytes {
            expected: expected_len,
            actual: bytes.len(),
        });
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainContextValidationError {
    StateCheckpointAhead { head: u64, state: u64 },
    CoordinatorStateCheckpointMismatch { head: u64, state: u64 },
    HistoricalTargetAhead { head: u64, target: u64 },
    SameHeightTargetHashMismatch { checkpoint_id: u64 },
    InvalidJobId,
    StaleWorkContext,
}

impl fmt::Display for ChainContextValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StateCheckpointAhead { head, state } => {
                write!(formatter, "authority state checkpoint {state} is ahead of chain head {head}")
            }
            Self::CoordinatorStateCheckpointMismatch { head, state } => write!(
                formatter,
                "Coordinator state checkpoint {state} does not equal chain head {head}"
            ),
            Self::HistoricalTargetAhead { head, target } => {
                write!(formatter, "historical target {target} is ahead of chain head {head}")
            }
            Self::SameHeightTargetHashMismatch { checkpoint_id } => write!(
                formatter,
                "historical target hash differs from current head at checkpoint {checkpoint_id}"
            ),
            Self::InvalidJobId => formatter.write_str("work context contains an invalid job ID"),
            Self::StaleWorkContext => {
                formatter.write_str("work context does not match the current pending namespace")
            }
        }
    }
}

impl Error for ChainContextValidationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainContextCodecError {
    InvalidMagic,
    UnsupportedVersion(u16),
    Truncated { expected: usize, actual: usize },
    TrailingBytes { expected: usize, actual: usize },
    UnknownAuthorityKind(u8),
    NonCanonicalCoordinatorScope,
    InvalidJobIdEncoding,
    CanonicalChain(CanonicalChainRefCodecError),
    Validation(ChainContextValidationError),
}

impl fmt::Display for ChainContextCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => formatter.write_str("invalid chain-context magic"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported chain-context codec version {version}")
            }
            Self::Truncated { expected, actual } => {
                write!(formatter, "truncated chain context: expected {expected} bytes, got {actual}")
            }
            Self::TrailingBytes { expected, actual } => {
                write!(formatter, "trailing chain-context bytes: expected {expected} bytes, got {actual}")
            }
            Self::UnknownAuthorityKind(kind) => write!(formatter, "unknown authority kind {kind}"),
            Self::NonCanonicalCoordinatorScope => {
                formatter.write_str("Coordinator authority scope has non-zero reserved Realm bytes")
            }
            Self::InvalidJobIdEncoding => formatter.write_str("invalid work-context job ID encoding"),
            Self::CanonicalChain(error) => write!(formatter, "invalid canonical chain reference: {error}"),
            Self::Validation(error) => write!(formatter, "invalid chain context: {error}"),
        }
    }
}

impl Error for ChainContextCodecError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CanonicalChain(error) => Some(error),
            Self::Validation(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CanonicalChainRefCodecError> for ChainContextCodecError {
    fn from(value: CanonicalChainRefCodecError) -> Self {
        Self::CanonicalChain(value)
    }
}

impl From<ChainContextValidationError> for ChainContextCodecError {
    fn from(value: ChainContextValidationError) -> Self {
        Self::Validation(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parth_core::{protocol::core_types::Q256BitHash, PHash};
    use psy_core::{
        constants::chain_id::PsyChainNetworkType,
        job::job_id::{
            ProvingJobCircuitType, ProvingJobDataType, QJobTopic, QProvingJobDataID,
        },
    };
    use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

    const GOLDEN_VECTORS: &str = include_str!("../../tests/golden/chain_context_vectors_v1.txt");

    fn golden(name: &str) -> &str {
        GOLDEN_VECTORS
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .find_map(|line| {
                let (key, value) = line.split_once('=')?;
                (key == name).then_some(value)
            })
            .unwrap_or_else(|| panic!("missing chain-context golden vector {name}"))
    }

    fn checkpoint_ref(checkpoint_id: u64, hash: PHash) -> CheckpointRef<PHash> {
        CheckpointRef::new(
            CheckpointId::new(checkpoint_id),
            CheckpointHash::from_last_chain_hash(hash),
        )
    }

    fn chain(checkpoint_id: u64, hash: PHash) -> CanonicalChainRef<PHash> {
        CanonicalChainRef::new(
            PsyChainNetworkType::PsyMainnet.into(),
            super::super::canonical_chain::ChainEpoch::new(42),
            checkpoint_ref(checkpoint_id, hash),
        )
    }

    fn job_id() -> QProvingJobDataID {
        QProvingJobDataID {
            topic: QJobTopic::GenerateStandardProof,
            goal_id: 0x1122_3344_5566_7788,
            circuit_type: ProvingJobCircuitType::BatchDeployContractsAggregate,
            group_id: 0x1122_3344,
            sub_group_id: 0x5566_7788,
            task_index: 0x99aa_bbcc,
            data_type: ProvingJobDataType::StandardProof,
            data_index: 1,
        }
    }

    fn pending() -> PendingContext<PHash> {
        PendingContext::new(
            chain(367, PHash::from_values(1, 2, 3, 4)),
            AuthorityScope::Realm {
                realm_id: 7,
                realm_sub_id: 3,
            },
            WorkUniquePendingId::new(0x0102_0304_0506_0708),
            WorkProcCheckpointUniqueId::from_u128(
                0x0011_2233_4455_6677_8899_aabb_ccdd_eeff,
            ),
        )
    }

    fn work() -> WorkContext<PHash, QProvingJobDataID> {
        let pending = pending();
        WorkContext::try_new(
            *pending.chain(),
            pending.authority(),
            pending.unique_pending_id(),
            pending.proc_checkpoint_unique_id(),
            job_id(),
        )
        .unwrap()
    }

    #[test]
    fn canonical_context_codecs_match_golden_and_round_trip() {
        let observation = AuthorityObservation::try_new(
            chain(367, PHash::from_values(1, 2, 3, 4)),
            AuthorityScope::Realm {
                realm_id: 7,
                realm_sub_id: 3,
            },
            AuthorityStateCheckpointId::new(360),
            AuthorityStateRoot::from_local_state_root(PHash::from_values(5, 6, 7, 8)),
        )
        .unwrap();
        let historical = HistoricalReadContext::try_new(
            chain(367, PHash::from_values(1, 2, 3, 4)),
            checkpoint_ref(300, PHash::from_values(9, 10, 11, 12)),
        )
        .unwrap();

        let cases = [
            (
                "authority_observation_realm_7_3_state_360",
                hex::encode(observation.to_canonical_bytes()),
            ),
            (
                "pending_context_realm_7_3_pending_0102030405060708",
                hex::encode(pending().to_canonical_bytes()),
            ),
            (
                "work_context_realm_7_3_pending_0102030405060708",
                hex::encode(work().to_canonical_bytes()),
            ),
            (
                "historical_context_head_367_target_300",
                hex::encode(historical.to_canonical_bytes()),
            ),
        ];
        for (name, actual) in cases {
            assert_eq!(actual, golden(name), "golden mismatch for {name}");
        }

        assert_eq!(
            AuthorityObservation::from_canonical_bytes(&observation.to_canonical_bytes()).unwrap(),
            observation
        );
        assert_eq!(
            PendingContext::from_canonical_bytes(&pending().to_canonical_bytes()).unwrap(),
            pending()
        );
        assert_eq!(
            WorkContext::from_canonical_bytes(&work().to_canonical_bytes()).unwrap(),
            work()
        );
        assert_eq!(
            HistoricalReadContext::from_canonical_bytes(&historical.to_canonical_bytes()).unwrap(),
            historical
        );
    }

    #[test]
    fn authority_observation_database_codec_is_the_protocol_codec() {
        let observation = AuthorityObservation::try_new(
            chain(367, PHash::from_values(1, 2, 3, 4)),
            AuthorityScope::Realm {
                realm_id: 7,
                realm_sub_id: 3,
            },
            AuthorityStateCheckpointId::new(360),
            AuthorityStateRoot::from_local_state_root(PHash::from_values(5, 6, 7, 8)),
        )
        .unwrap();
        let encoded = observation.psy_ser_to_bytes_vec().unwrap();
        assert_eq!(encoded, observation.to_canonical_bytes());
        assert_eq!(
            AuthorityObservation::<PHash>::psy_ser_from_slice(&encoded).unwrap(),
            observation
        );

        let mut corrupt = encoded;
        corrupt[0] ^= 0xff;
        assert!(AuthorityObservation::<PHash>::psy_ser_from_slice(&corrupt).is_err());
    }

    #[test]
    fn json_envelopes_are_required_versioned_and_round_trip() {
        let request = CanonicalRequest::new(
            chain(367, PHash::from_values(1, 2, 3, 4)),
            serde_json::json!({"user_id": 9}),
        );
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["codec_version"], CHAIN_CONTEXT_CODEC_VERSION);
        assert!(json.get("expected_chain").is_some());
        assert_eq!(
            serde_json::from_value::<CanonicalRequest<PHash, serde_json::Value>>(json.clone())
                .unwrap(),
            request
        );

        let mut missing_version = json.clone();
        missing_version.as_object_mut().unwrap().remove("codec_version");
        assert!(serde_json::from_value::<CanonicalRequest<PHash, serde_json::Value>>(
            missing_version
        )
        .is_err());
        let mut unknown_version = json.clone();
        unknown_version["codec_version"] = serde_json::json!(2);
        assert!(serde_json::from_value::<CanonicalRequest<PHash, serde_json::Value>>(
            unknown_version
        )
        .is_err());
        let mut unknown_field = json;
        unknown_field["epoch"] = serde_json::json!(42);
        assert!(serde_json::from_value::<CanonicalRequest<PHash, serde_json::Value>>(
            unknown_field
        )
        .is_err());
    }

    #[test]
    fn historical_response_and_message_json_are_strict_and_round_trip() {
        let current = chain(367, PHash::from_values(1, 2, 3, 4));
        let historical = HistoricalReadRequest::new(
            HistoricalReadContext::try_new(
                current,
                checkpoint_ref(300, PHash::from_values(9, 10, 11, 12)),
            )
            .unwrap(),
            serde_json::json!({"user_id": 9}),
        );
        let historical_json = serde_json::to_value(&historical).unwrap();
        assert_eq!(
            serde_json::from_value::<HistoricalReadRequest<PHash, serde_json::Value>>(
                historical_json.clone()
            )
            .unwrap(),
            historical
        );
        let mut historical_without_version = historical_json.clone();
        historical_without_version["context"]
            .as_object_mut()
            .unwrap()
            .remove("codec_version");
        assert!(serde_json::from_value::<
            HistoricalReadRequest<PHash, serde_json::Value>,
        >(historical_without_version)
        .is_err());
        let mut historical_with_unknown = historical_json;
        historical_with_unknown["target_height"] = serde_json::json!(300);
        assert!(serde_json::from_value::<
            HistoricalReadRequest<PHash, serde_json::Value>,
        >(historical_with_unknown)
        .is_err());

        let observation = AuthorityObservation::try_new(
            current,
            AuthorityScope::Coordinator,
            AuthorityStateCheckpointId::new(367),
            AuthorityStateRoot::from_local_state_root(PHash::from_values(5, 6, 7, 8)),
        )
        .unwrap();
        let response = CanonicalResponse::new(observation, serde_json::json!({"value": 1}));
        let response_json = serde_json::to_value(&response).unwrap();
        assert_eq!(
            serde_json::from_value::<CanonicalResponse<PHash, serde_json::Value>>(
                response_json.clone()
            )
            .unwrap(),
            response
        );
        let mut response_without_version = response_json;
        response_without_version
            .as_object_mut()
            .unwrap()
            .remove("codec_version");
        assert!(
            serde_json::from_value::<CanonicalResponse<PHash, serde_json::Value>>(
                response_without_version
            )
            .is_err()
        );

        let message = CanonicalMessage::new(pending(), serde_json::json!({"checkpoint_id": 367}));
        let message_json = serde_json::to_value(&message).unwrap();
        assert_eq!(
            serde_json::from_value::<CanonicalMessage<PHash, serde_json::Value>>(
                message_json.clone()
            )
            .unwrap(),
            message
        );
        let mut message_without_version = message_json;
        message_without_version["context"]
            .as_object_mut()
            .unwrap()
            .remove("codec_version");
        assert!(
            serde_json::from_value::<CanonicalMessage<PHash, serde_json::Value>>(
                message_without_version
            )
            .is_err()
        );

        let mut observation_with_unknown = serde_json::to_value(observation).unwrap();
        observation_with_unknown["local_checkpoint"] = serde_json::json!(367);
        assert!(serde_json::from_value::<AuthorityObservation<PHash>>(
            observation_with_unknown
        )
        .is_err());
    }

    #[test]
    fn work_json_uses_required_context_and_hex_proc_id() {
        let value = serde_json::to_value(work()).unwrap();
        assert_eq!(value["codec_version"], 1);
        assert_eq!(
            value["proc_checkpoint_unique_id"],
            "00112233445566778899aabbccddeeff"
        );
        assert_eq!(
            serde_json::from_value::<WorkContext<PHash, QProvingJobDataID>>(value.clone())
                .unwrap(),
            work()
        );
        let mut bad_proc = value;
        bad_proc["proc_checkpoint_unique_id"] = serde_json::json!("01");
        assert!(serde_json::from_value::<WorkContext<PHash, QProvingJobDataID>>(bad_proc).is_err());
        let mut uppercase_proc = serde_json::to_value(work()).unwrap();
        uppercase_proc["proc_checkpoint_unique_id"] =
            serde_json::json!("00112233445566778899AABBCCDDEEFF");
        assert!(
            serde_json::from_value::<WorkContext<PHash, QProvingJobDataID>>(uppercase_proc)
                .is_err()
        );
    }

    #[test]
    fn authority_observation_enforces_local_progress_invariants() {
        let current = chain(367, PHash::from_values(1, 2, 3, 4));
        let root = AuthorityStateRoot::from_local_state_root(PHash::from_values(5, 6, 7, 8));
        assert!(AuthorityObservation::try_new(
            current,
            AuthorityScope::Coordinator,
            AuthorityStateCheckpointId::new(367),
            root,
        )
        .is_ok());
        assert_eq!(
            AuthorityObservation::try_new(
                current,
                AuthorityScope::Coordinator,
                AuthorityStateCheckpointId::new(366),
                root,
            ),
            Err(ChainContextValidationError::CoordinatorStateCheckpointMismatch {
                head: 367,
                state: 366,
            })
        );
        assert_eq!(
            AuthorityObservation::try_new(
                current,
                AuthorityScope::Realm {
                    realm_id: 7,
                    realm_sub_id: 3,
                },
                AuthorityStateCheckpointId::new(368),
                root,
            ),
            Err(ChainContextValidationError::StateCheckpointAhead {
                head: 367,
                state: 368,
            })
        );
    }

    #[test]
    fn historical_context_rejects_future_and_same_height_other_hash() {
        let current = chain(367, PHash::from_values(1, 2, 3, 4));
        assert_eq!(
            HistoricalReadContext::try_new(
                current,
                checkpoint_ref(368, PHash::from_values(1, 2, 3, 4)),
            ),
            Err(ChainContextValidationError::HistoricalTargetAhead {
                head: 367,
                target: 368,
            })
        );
        assert_eq!(
            HistoricalReadContext::try_new(
                current,
                checkpoint_ref(367, PHash::from_values(5, 6, 7, 8)),
            ),
            Err(ChainContextValidationError::SameHeightTargetHashMismatch {
                checkpoint_id: 367,
            })
        );
    }

    #[test]
    fn codecs_reject_unknown_version_length_tail_and_authority() {
        let encoded = pending().to_canonical_bytes();
        for cut in 0..PENDING_CONTEXT_V1_LEN {
            assert!(PendingContext::<PHash>::from_canonical_bytes(&encoded[..cut]).is_err());
        }
        let mut tail = encoded.to_vec();
        tail.push(0);
        assert!(matches!(
            PendingContext::<PHash>::from_canonical_bytes(&tail),
            Err(ChainContextCodecError::TrailingBytes { .. })
        ));
        let mut version = encoded;
        version[8..10].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(
            PendingContext::<PHash>::from_canonical_bytes(&version),
            Err(ChainContextCodecError::UnsupportedVersion(2))
        );
        let mut authority = encoded;
        authority[75] = 99;
        assert_eq!(
            PendingContext::<PHash>::from_canonical_bytes(&authority),
            Err(ChainContextCodecError::UnknownAuthorityKind(99))
        );
        let mut coordinator_reserved = encoded;
        coordinator_reserved[75] = AUTHORITY_KIND_COORDINATOR;
        coordinator_reserved[76] = 1;
        assert_eq!(
            PendingContext::<PHash>::from_canonical_bytes(&coordinator_reserved),
            Err(ChainContextCodecError::NonCanonicalCoordinatorScope)
        );
    }

    #[test]
    fn every_work_context_field_changes_canonical_bytes() {
        let base = work();
        let encoded = base.to_canonical_bytes();
        let changed_chain = WorkContext::try_new(
            chain(367, PHash::from_values(5, 6, 7, 8)),
            base.authority(),
            base.unique_pending_id(),
            base.proc_checkpoint_unique_id(),
            *base.job_id(),
        )
        .unwrap();
        assert_ne!(changed_chain.to_canonical_bytes(), encoded);
        let changed_pending = WorkContext::try_new(
            *base.chain(),
            base.authority(),
            WorkUniquePendingId::new(base.unique_pending_id().get() + 1),
            base.proc_checkpoint_unique_id(),
            *base.job_id(),
        )
        .unwrap();
        assert_ne!(changed_pending.to_canonical_bytes(), encoded);
        let changed_proc = WorkContext::try_new(
            *base.chain(),
            base.authority(),
            base.unique_pending_id(),
            WorkProcCheckpointUniqueId::from_u128(base.proc_checkpoint_unique_id().as_u128() + 1),
            *base.job_id(),
        )
        .unwrap();
        assert_ne!(changed_proc.to_canonical_bytes(), encoded);
        let changed_authority = WorkContext::try_new(
            *base.chain(),
            AuthorityScope::Realm {
                realm_id: 8,
                realm_sub_id: 3,
            },
            base.unique_pending_id(),
            base.proc_checkpoint_unique_id(),
            *base.job_id(),
        )
        .unwrap();
        assert_ne!(changed_authority.to_canonical_bytes(), encoded);
        let mut other_job = *base.job_id();
        other_job.goal_id += 1;
        let changed_job = WorkContext::try_new(
            *base.chain(),
            base.authority(),
            base.unique_pending_id(),
            base.proc_checkpoint_unique_id(),
            other_job,
        )
        .unwrap();
        assert_ne!(changed_job.to_canonical_bytes(), encoded);
        assert_eq!(
            WorkContext::try_new(
                *base.chain(),
                base.authority(),
                base.unique_pending_id(),
                base.proc_checkpoint_unique_id(),
                QProvingJobDataID::new_invalid_job_id(),
            ),
            Err(ChainContextValidationError::InvalidJobId)
        );
    }

    #[test]
    fn opaque_work_context_token_round_trips_and_rejects_malformed_wire_data() {
        let expected = work();
        let token = WorkContextToken::from_work_context(&expected);
        assert_eq!(
            token
                .decode::<PHash, QProvingJobDataID>()
                .expect("canonical token must decode"),
            expected
        );

        let json = serde_json::to_value(token).unwrap();
        let decoded: WorkContextToken = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(decoded, token);

        let mut short = json.clone();
        short["bytes"].as_array_mut().unwrap().pop();
        assert!(serde_json::from_value::<WorkContextToken>(short).is_err());

        let mut unknown_version = *token.as_bytes();
        unknown_version[8..10].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(
            WorkContextToken::try_from_canonical_bytes::<PHash, QProvingJobDataID>(
                unknown_version
            ),
            Err(ChainContextCodecError::UnsupportedVersion(2))
        );
    }

    #[test]
    fn work_context_requires_the_exact_current_pending_namespace() {
        let work = work();
        let current = pending();
        assert_eq!(work.ensure_matches_pending_context(&current), Ok(()));

        let stale_contexts = [
            PendingContext::new(
                chain(367, PHash::from_values(9, 2, 3, 4)),
                current.authority(),
                current.unique_pending_id(),
                current.proc_checkpoint_unique_id(),
            ),
            PendingContext::new(
                *current.chain(),
                AuthorityScope::Realm {
                    realm_id: 8,
                    realm_sub_id: 3,
                },
                current.unique_pending_id(),
                current.proc_checkpoint_unique_id(),
            ),
            PendingContext::new(
                *current.chain(),
                current.authority(),
                WorkUniquePendingId::new(current.unique_pending_id().get() + 1),
                current.proc_checkpoint_unique_id(),
            ),
            PendingContext::new(
                *current.chain(),
                current.authority(),
                current.unique_pending_id(),
                WorkProcCheckpointUniqueId::from_u128(
                    current.proc_checkpoint_unique_id().as_u128() + 1,
                ),
            ),
        ];
        for stale in stale_contexts {
            assert_eq!(
                work.ensure_matches_pending_context(&stale),
                Err(ChainContextValidationError::StaleWorkContext)
            );
        }
    }

    #[test]
    fn fixed_lengths_and_hash_semantics_are_explicit() {
        assert_eq!(AUTHORITY_OBSERVATION_V1_LEN, 122);
        assert_eq!(PENDING_CONTEXT_V1_LEN, 106);
        assert_eq!(WORK_CONTEXT_V1_LEN, 130);
        assert_eq!(HISTORICAL_READ_CONTEXT_V1_LEN, 115);
        assert_eq!(
            work().chain().checkpoint().checkpoint_hash().as_inner().into_owned_32bytes(),
            PHash::from_values(1, 2, 3, 4).into_owned_32bytes()
        );
    }
}
