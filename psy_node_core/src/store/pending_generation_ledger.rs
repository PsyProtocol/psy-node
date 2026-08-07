//! Durable processing/gathering pending-generation rotation.
//!
//! The legacy pending counter and this row intentionally live in different
//! tables. A counter increment that cannot be durably attached here is an
//! abandoned hole; it is never inferred, reclaimed, or reused. Queue/work
//! publication is authorized only by an exact readback of this row.

use std::{error::Error, fmt};

use psy_data::protocol::{
    canonical_chain::NetworkId,
    chain_context::AuthorityScope,
};

use super::{
    pending_generation::{ProcNamespacePrefix, ReservedPendingGeneration},
    typed::{ProcCheckpointUniqueId, UniquePendingId},
};

pub const PENDING_GENERATION_LEDGER_MAGIC: [u8; 8] = *b"PSYPGLED";
pub const PENDING_GENERATION_LEDGER_CODEC_VERSION: u16 = 1;
pub const PENDING_GENERATION_LEDGER_V1_LEN: usize =
    8 + 2 + 4 + 1 + 4 + 2 + 32 + 8 + 1 + (8 + 16) * 2;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingGenerationLedgerKey {
    network: NetworkId,
    authority: AuthorityScope,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingGenerationActivationDigest([u8; 32]);

impl PendingGenerationActivationDigest {
    pub fn try_new(bytes: [u8; 32]) -> Result<Self, PendingGenerationLedgerError> {
        if bytes == [0; 32] {
            Err(PendingGenerationLedgerError::EmptyActivationDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl PendingGenerationLedgerKey {
    pub const fn new(network: NetworkId, authority: AuthorityScope) -> Self {
        Self { network, authority }
    }

    pub const fn network(self) -> NetworkId {
        self.network
    }

    pub const fn authority(self) -> AuthorityScope {
        self.authority
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PendingGenerationLedgerRevision(u64);

impl PendingGenerationLedgerRevision {
    pub const fn try_new(
        value: u64,
    ) -> Result<Self, PendingGenerationLedgerError> {
        if value <= i64::MAX as u64 {
            Ok(Self(value))
        } else {
            Err(PendingGenerationLedgerError::RevisionOutOfRange(value))
        }
    }

    pub const fn try_from_i64(
        value: i64,
    ) -> Result<Self, PendingGenerationLedgerError> {
        if value < 0 {
            Err(PendingGenerationLedgerError::NegativeRevision(value))
        } else {
            Ok(Self(value as u64))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn as_i64(self) -> i64 {
        self.0 as i64
    }

    const fn next(self) -> Result<Self, PendingGenerationLedgerError> {
        match self.0.checked_add(1) {
            Some(next) if next <= i64::MAX as u64 => Ok(Self(next)),
            _ => Err(PendingGenerationLedgerError::RevisionOverflow),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingGenerationContext {
    pending_id: UniquePendingId,
    proc_checkpoint_id: ProcCheckpointUniqueId,
}

impl PendingGenerationContext {
    pub fn try_from_legacy(
        pending_id: u64,
        proc_checkpoint_id: u128,
    ) -> Result<Self, PendingGenerationLedgerError> {
        let pending_id = UniquePendingId::try_new(pending_id)
            .map_err(|_| PendingGenerationLedgerError::PendingOutOfRange(pending_id))?;
        if (pending_id.get() == 0) != (proc_checkpoint_id == 0) {
            return Err(PendingGenerationLedgerError::InconsistentZeroContext);
        }
        Ok(Self {
            pending_id,
            proc_checkpoint_id: ProcCheckpointUniqueId::from_u128(
                proc_checkpoint_id,
            ),
        })
    }

    pub const fn pending_id(self) -> UniquePendingId {
        self.pending_id
    }

    pub const fn proc_checkpoint_id(self) -> ProcCheckpointUniqueId {
        self.proc_checkpoint_id
    }

    fn from_reservation(reservation: ReservedPendingGeneration) -> Self {
        Self {
            pending_id: reservation.pending_id(),
            proc_checkpoint_id: reservation.proc_checkpoint_id(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum PendingGenerationBootstrapReason {
    Genesis = 1,
    LegacyActivation = 2,
}

impl PendingGenerationBootstrapReason {
    fn try_from_u8(value: u8) -> Result<Self, PendingGenerationLedgerError> {
        match value {
            1 => Ok(Self::Genesis),
            2 => Ok(Self::LegacyActivation),
            other => Err(PendingGenerationLedgerError::UnknownBootstrapReason(
                other,
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoredPendingGenerationLedger {
    key: PendingGenerationLedgerKey,
    revision: PendingGenerationLedgerRevision,
    activation_digest: PendingGenerationActivationDigest,
    proc_namespace_prefix: ProcNamespacePrefix,
    bootstrap_reason: PendingGenerationBootstrapReason,
    processing: PendingGenerationContext,
    gathering: PendingGenerationContext,
}

impl StoredPendingGenerationLedger {
    pub const fn key(&self) -> PendingGenerationLedgerKey {
        self.key
    }

    pub const fn revision(&self) -> PendingGenerationLedgerRevision {
        self.revision
    }

    pub const fn bootstrap_reason(&self) -> PendingGenerationBootstrapReason {
        self.bootstrap_reason
    }

    pub const fn activation_digest(&self) -> PendingGenerationActivationDigest {
        self.activation_digest
    }

    pub const fn proc_namespace_prefix(&self) -> ProcNamespacePrefix {
        self.proc_namespace_prefix
    }

    pub const fn processing(&self) -> PendingGenerationContext {
        self.processing
    }

    pub const fn gathering(&self) -> PendingGenerationContext {
        self.gathering
    }

    pub fn canonical_payload(
        &self,
    ) -> [u8; PENDING_GENERATION_LEDGER_V1_LEN] {
        encode_payload(self)
    }

    pub fn decode_persisted(
        partition_key: PendingGenerationLedgerKey,
        revision: i64,
        payload: &[u8],
    ) -> Result<Self, PendingGenerationLedgerError> {
        if payload.len() != PENDING_GENERATION_LEDGER_V1_LEN {
            return Err(PendingGenerationLedgerError::InvalidPayloadLength(
                payload.len(),
            ));
        }
        let mut cursor = 0;
        let magic = take_array::<8>(payload, &mut cursor);
        if magic != PENDING_GENERATION_LEDGER_MAGIC {
            return Err(PendingGenerationLedgerError::InvalidMagic);
        }
        let version = u16::from_be_bytes(take_array::<2>(payload, &mut cursor));
        if version != PENDING_GENERATION_LEDGER_CODEC_VERSION {
            return Err(PendingGenerationLedgerError::UnknownCodecVersion(version));
        }
        let network = NetworkId::try_from_chain_id(u32::from_be_bytes(
            take_array::<4>(payload, &mut cursor),
        ))
        .map_err(|_| PendingGenerationLedgerError::UnknownNetwork)?;
        let authority_kind = payload[cursor];
        cursor += 1;
        let realm_id = u32::from_be_bytes(take_array::<4>(payload, &mut cursor));
        let realm_sub_id =
            u16::from_be_bytes(take_array::<2>(payload, &mut cursor));
        let authority = decode_authority(authority_kind, realm_id, realm_sub_id)?;
        let key = PendingGenerationLedgerKey::new(network, authority);
        if key != partition_key {
            return Err(PendingGenerationLedgerError::PartitionPayloadMismatch);
        }
        let activation_digest = PendingGenerationActivationDigest::try_new(
            take_array::<32>(payload, &mut cursor),
        )?;
        let prefix_value =
            u64::from_be_bytes(take_array::<8>(payload, &mut cursor));
        let proc_namespace_prefix = ProcNamespacePrefix::try_new(prefix_value)
            .map_err(|_| PendingGenerationLedgerError::InvalidProcNamespacePrefix)?;
        let bootstrap_reason =
            PendingGenerationBootstrapReason::try_from_u8(payload[cursor])?;
        cursor += 1;
        let processing = decode_context(payload, &mut cursor)?;
        let gathering = decode_context(payload, &mut cursor)?;
        debug_assert_eq!(cursor, payload.len());
        validate_order(processing, gathering)?;
        Ok(Self {
            key,
            revision: PendingGenerationLedgerRevision::try_from_i64(revision)?,
            activation_digest,
            proc_namespace_prefix,
            bootstrap_reason,
            processing,
            gathering,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingGenerationLedgerBootstrap {
    candidate: StoredPendingGenerationLedger,
    candidate_payload: [u8; PENDING_GENERATION_LEDGER_V1_LEN],
}

impl PendingGenerationLedgerBootstrap {
    pub fn try_new(
        key: PendingGenerationLedgerKey,
        activation_digest: PendingGenerationActivationDigest,
        proc_namespace_prefix: ProcNamespacePrefix,
        reason: PendingGenerationBootstrapReason,
        processing: PendingGenerationContext,
        gathering: PendingGenerationContext,
    ) -> Result<Self, PendingGenerationLedgerError> {
        validate_order(processing, gathering)?;
        match reason {
            PendingGenerationBootstrapReason::Genesis
                if processing.pending_id().get() != 0
                    || gathering.pending_id().get() != 0 =>
            {
                return Err(PendingGenerationLedgerError::GenesisMustBeZero)
            }
            PendingGenerationBootstrapReason::LegacyActivation
                if gathering.pending_id().get() == 0 =>
            {
                return Err(
                    PendingGenerationLedgerError::LegacyActivationMustBePositive,
                )
            }
            PendingGenerationBootstrapReason::LegacyActivation
                if processing.pending_id().get()
                    >= gathering.pending_id().get() =>
            {
                return Err(
                    PendingGenerationLedgerError::LegacyPipelineNotPrimed,
                )
            }
            _ => {}
        }
        let candidate = StoredPendingGenerationLedger {
            key,
            revision: PendingGenerationLedgerRevision::try_new(0)?,
            activation_digest,
            proc_namespace_prefix,
            bootstrap_reason: reason,
            processing,
            gathering,
        };
        Ok(Self {
            candidate_payload: candidate.canonical_payload(),
            candidate,
        })
    }

    pub const fn candidate(&self) -> &StoredPendingGenerationLedger {
        &self.candidate
    }

    pub const fn candidate_payload(
        &self,
    ) -> &[u8; PENDING_GENERATION_LEDGER_V1_LEN] {
        &self.candidate_payload
    }

    pub fn classify(
        &self,
        applied: bool,
        current: StoredPendingGenerationLedger,
    ) -> PendingGenerationLedgerWriteOutcome {
        classify(applied, self.candidate, current)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SealedPendingGenerationRotation {
    expected: StoredPendingGenerationLedger,
    candidate: StoredPendingGenerationLedger,
    expected_payload: [u8; PENDING_GENERATION_LEDGER_V1_LEN],
    candidate_payload: [u8; PENDING_GENERATION_LEDGER_V1_LEN],
}

impl SealedPendingGenerationRotation {
    pub fn try_new(
        expected: StoredPendingGenerationLedger,
        reserved: ReservedPendingGeneration,
    ) -> Result<Self, PendingGenerationLedgerError> {
        let next = PendingGenerationContext::from_reservation(reserved);
        if next.proc_checkpoint_id().as_u128() == 0 {
            return Err(PendingGenerationLedgerError::ZeroProcNamespace);
        }
        if next.proc_checkpoint_id()
            != expected
                .proc_namespace_prefix
                .derive_proc_id(next.pending_id())
        {
            return Err(PendingGenerationLedgerError::ProcNamespacePrefixMismatch);
        }
        if next.pending_id().get() <= expected.gathering.pending_id().get() {
            return Err(PendingGenerationLedgerError::PendingNotMonotonic {
                previous: expected.gathering.pending_id().get(),
                candidate: next.pending_id().get(),
            });
        }
        if next.proc_checkpoint_id() == expected.gathering.proc_checkpoint_id()
            || next.proc_checkpoint_id()
                == expected.processing.proc_checkpoint_id()
        {
            return Err(PendingGenerationLedgerError::ProcIdNotRotated);
        }
        let candidate = StoredPendingGenerationLedger {
            key: expected.key,
            revision: expected.revision.next()?,
            activation_digest: expected.activation_digest,
            proc_namespace_prefix: expected.proc_namespace_prefix,
            bootstrap_reason: expected.bootstrap_reason,
            processing: expected.gathering,
            gathering: next,
        };
        Ok(Self {
            expected_payload: expected.canonical_payload(),
            candidate_payload: candidate.canonical_payload(),
            expected,
            candidate,
        })
    }

    pub const fn expected(&self) -> &StoredPendingGenerationLedger {
        &self.expected
    }

    pub const fn candidate(&self) -> &StoredPendingGenerationLedger {
        &self.candidate
    }

    pub const fn expected_payload(
        &self,
    ) -> &[u8; PENDING_GENERATION_LEDGER_V1_LEN] {
        &self.expected_payload
    }

    pub const fn candidate_payload(
        &self,
    ) -> &[u8; PENDING_GENERATION_LEDGER_V1_LEN] {
        &self.candidate_payload
    }

    pub fn classify(
        &self,
        applied: bool,
        current: StoredPendingGenerationLedger,
    ) -> PendingGenerationLedgerWriteOutcome {
        classify(applied, self.candidate, current)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingGenerationLedgerReadState {
    Uninitialized,
    Current(StoredPendingGenerationLedger),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingGenerationLedgerWriteOutcome {
    Applied(StoredPendingGenerationLedger),
    Idempotent(StoredPendingGenerationLedger),
    Conflict(StoredPendingGenerationLedger),
}

fn classify(
    applied: bool,
    candidate: StoredPendingGenerationLedger,
    current: StoredPendingGenerationLedger,
) -> PendingGenerationLedgerWriteOutcome {
    if applied && current == candidate {
        PendingGenerationLedgerWriteOutcome::Applied(current)
    } else if current == candidate {
        PendingGenerationLedgerWriteOutcome::Idempotent(current)
    } else {
        PendingGenerationLedgerWriteOutcome::Conflict(current)
    }
}

fn encode_payload(
    state: &StoredPendingGenerationLedger,
) -> [u8; PENDING_GENERATION_LEDGER_V1_LEN] {
    let mut bytes = Vec::with_capacity(PENDING_GENERATION_LEDGER_V1_LEN);
    bytes.extend_from_slice(&PENDING_GENERATION_LEDGER_MAGIC);
    bytes.extend_from_slice(&PENDING_GENERATION_LEDGER_CODEC_VERSION.to_be_bytes());
    bytes.extend_from_slice(&state.key.network().chain_id().to_be_bytes());
    let (kind, realm_id, realm_sub_id) = encode_authority(state.key.authority());
    bytes.push(kind);
    bytes.extend_from_slice(&realm_id.to_be_bytes());
    bytes.extend_from_slice(&realm_sub_id.to_be_bytes());
    bytes.extend_from_slice(state.activation_digest.as_bytes());
    bytes.extend_from_slice(&state.proc_namespace_prefix.get().to_be_bytes());
    bytes.push(state.bootstrap_reason as u8);
    encode_context(&mut bytes, state.processing);
    encode_context(&mut bytes, state.gathering);
    bytes.try_into().expect("fixed pending ledger payload")
}

fn encode_context(bytes: &mut Vec<u8>, context: PendingGenerationContext) {
    bytes.extend_from_slice(&context.pending_id().get().to_be_bytes());
    bytes.extend_from_slice(context.proc_checkpoint_id().as_bytes());
}

fn decode_context(
    payload: &[u8],
    cursor: &mut usize,
) -> Result<PendingGenerationContext, PendingGenerationLedgerError> {
    let pending = u64::from_be_bytes(take_array::<8>(payload, cursor));
    let proc_id = u128::from_be_bytes(take_array::<16>(payload, cursor));
    PendingGenerationContext::try_from_legacy(pending, proc_id)
}

fn validate_order(
    processing: PendingGenerationContext,
    gathering: PendingGenerationContext,
) -> Result<(), PendingGenerationLedgerError> {
    if processing.pending_id().get() > gathering.pending_id().get() {
        return Err(PendingGenerationLedgerError::ContextOrderInvalid);
    }
    if processing.pending_id() == gathering.pending_id()
        && processing != gathering
    {
        return Err(PendingGenerationLedgerError::SamePendingDifferentProc);
    }
    if processing.pending_id() != gathering.pending_id()
        && processing.proc_checkpoint_id() == gathering.proc_checkpoint_id()
    {
        return Err(PendingGenerationLedgerError::DuplicateProcNamespace);
    }
    Ok(())
}

fn encode_authority(authority: AuthorityScope) -> (u8, u32, u16) {
    match authority {
        AuthorityScope::Coordinator => (1, 0, 0),
        AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } => (2, realm_id, realm_sub_id),
    }
}

fn decode_authority(
    kind: u8,
    realm_id: u32,
    realm_sub_id: u16,
) -> Result<AuthorityScope, PendingGenerationLedgerError> {
    match (kind, realm_id, realm_sub_id) {
        (1, 0, 0) => Ok(AuthorityScope::Coordinator),
        (1, _, _) => Err(PendingGenerationLedgerError::CoordinatorRealmIdsNonZero),
        (2, realm_id, realm_sub_id) => Ok(AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        }),
        (other, _, _) => Err(PendingGenerationLedgerError::UnknownAuthorityKind(other)),
    }
}

fn take_array<const N: usize>(payload: &[u8], cursor: &mut usize) -> [u8; N] {
    let end = *cursor + N;
    let value = payload[*cursor..end]
        .try_into()
        .expect("payload length checked before decoding");
    *cursor = end;
    value
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingGenerationLedgerError {
    RevisionOutOfRange(u64),
    NegativeRevision(i64),
    RevisionOverflow,
    PendingOutOfRange(u64),
    InconsistentZeroContext,
    InvalidPayloadLength(usize),
    InvalidMagic,
    UnknownCodecVersion(u16),
    UnknownBootstrapReason(u8),
    UnknownNetwork,
    EmptyActivationDigest,
    InvalidProcNamespacePrefix,
    UnknownAuthorityKind(u8),
    CoordinatorRealmIdsNonZero,
    PartitionPayloadMismatch,
    ContextOrderInvalid,
    SamePendingDifferentProc,
    DuplicateProcNamespace,
    GenesisMustBeZero,
    LegacyActivationMustBePositive,
    LegacyPipelineNotPrimed,
    PendingNotMonotonic { previous: u64, candidate: u64 },
    ProcIdNotRotated,
    ZeroProcNamespace,
    ProcNamespacePrefixMismatch,
}

impl fmt::Display for PendingGenerationLedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for PendingGenerationLedgerError {}

#[cfg(test)]
mod tests {
    use super::*;
    use psy_core::constants::chain_id::PsyChainNetworkType;

    fn key() -> PendingGenerationLedgerKey {
        PendingGenerationLedgerKey::new(
            NetworkId::from_network_type(PsyChainNetworkType::PsyMainnet),
            AuthorityScope::Realm {
                realm_id: 3,
                realm_sub_id: 4,
            },
        )
    }

    fn context(pending: u64, proc_id: u128) -> PendingGenerationContext {
        PendingGenerationContext::try_from_legacy(pending, proc_id).unwrap()
    }

    fn activation() -> PendingGenerationActivationDigest {
        PendingGenerationActivationDigest::try_new([0xa5; 32]).unwrap()
    }

    fn prefix() -> ProcNamespacePrefix {
        ProcNamespacePrefix::try_new(0x1234).unwrap()
    }

    #[test]
    fn bootstrap_round_trip_and_partition_binding_are_fail_closed() {
        let bootstrap = PendingGenerationLedgerBootstrap::try_new(
            key(),
            activation(),
            prefix(),
            PendingGenerationBootstrapReason::LegacyActivation,
            context(8, 80),
            context(9, 90),
        )
        .unwrap();
        let decoded = StoredPendingGenerationLedger::decode_persisted(
            key(),
            0,
            bootstrap.candidate_payload(),
        )
        .unwrap();
        assert_eq!(&decoded, bootstrap.candidate());
        assert_eq!(
            StoredPendingGenerationLedger::decode_persisted(
                PendingGenerationLedgerKey::new(
                    NetworkId::from_network_type(
                        PsyChainNetworkType::PsyPublicTestnet,
                    ),
                    key().authority(),
                ),
                0,
                bootstrap.candidate_payload(),
            ),
            Err(PendingGenerationLedgerError::PartitionPayloadMismatch)
        );
        let mut trailing = bootstrap.candidate_payload().to_vec();
        trailing.push(0);
        assert!(StoredPendingGenerationLedger::decode_persisted(
            key(),
            0,
            &trailing,
        )
        .is_err());
    }

    #[test]
    fn rotation_shifts_gathering_and_allows_counter_holes() {
        let bootstrap = PendingGenerationLedgerBootstrap::try_new(
            key(),
            activation(),
            prefix(),
            PendingGenerationBootstrapReason::LegacyActivation,
            context(8, 80),
            context(9, 90),
        )
        .unwrap();
        let reserved =
            ReservedPendingGeneration::try_from_prefix(12, prefix()).unwrap();
        let rotation = SealedPendingGenerationRotation::try_new(
            *bootstrap.candidate(),
            reserved,
        )
        .unwrap();
        assert_eq!(rotation.candidate().processing(), context(9, 90));
        assert_eq!(
            rotation.candidate().gathering(),
            context(12, (prefix().get() as u128) << 64 | 12)
        );
        assert_eq!(rotation.candidate().revision().get(), 1);
        assert_eq!(
            StoredPendingGenerationLedger::decode_persisted(
                key(),
                1,
                rotation.candidate_payload(),
            )
            .unwrap(),
            *rotation.candidate()
        );
    }

    #[test]
    fn stale_retry_is_idempotent_but_competing_rotation_conflicts() {
        let bootstrap = PendingGenerationLedgerBootstrap::try_new(
            key(),
            activation(),
            prefix(),
            PendingGenerationBootstrapReason::LegacyActivation,
            context(8, 80),
            context(9, 90),
        )
        .unwrap();
        let first = SealedPendingGenerationRotation::try_new(
            *bootstrap.candidate(),
            ReservedPendingGeneration::try_from_prefix(10, prefix()).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            first.classify(false, *first.candidate()),
            PendingGenerationLedgerWriteOutcome::Idempotent(_)
        ));
        let competing = SealedPendingGenerationRotation::try_new(
            *bootstrap.candidate(),
            ReservedPendingGeneration::try_from_prefix(11, prefix()).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            first.classify(false, *competing.candidate()),
            PendingGenerationLedgerWriteOutcome::Conflict(_)
        ));
    }

    #[test]
    fn malformed_zero_order_proc_reuse_and_overflow_are_rejected() {
        assert_eq!(
            PendingGenerationContext::try_from_legacy(0, 1),
            Err(PendingGenerationLedgerError::InconsistentZeroContext)
        );
        assert!(PendingGenerationLedgerBootstrap::try_new(
            key(),
            activation(),
            prefix(),
            PendingGenerationBootstrapReason::LegacyActivation,
            context(9, 90),
            context(8, 80),
        )
        .is_err());
        assert_eq!(
            PendingGenerationLedgerBootstrap::try_new(
                key(),
                activation(),
                prefix(),
                PendingGenerationBootstrapReason::LegacyActivation,
                context(8, 80),
                context(9, 80),
            ),
            Err(PendingGenerationLedgerError::DuplicateProcNamespace)
        );
        let bootstrap = PendingGenerationLedgerBootstrap::try_new(
            key(),
            activation(),
            prefix(),
            PendingGenerationBootstrapReason::LegacyActivation,
            context(8, 80),
            context(9, 90),
        )
        .unwrap();
        assert_eq!(
            SealedPendingGenerationRotation::try_new(
                *bootstrap.candidate(),
                ReservedPendingGeneration::try_new(10, 90).unwrap(),
            ),
            Err(PendingGenerationLedgerError::ProcNamespacePrefixMismatch)
        );
        let mut max = *bootstrap.candidate();
        max.revision = PendingGenerationLedgerRevision::try_new(i64::MAX as u64)
            .unwrap();
        assert_eq!(
            SealedPendingGenerationRotation::try_new(
                max,
                ReservedPendingGeneration::try_from_prefix(10, prefix()).unwrap(),
            ),
            Err(PendingGenerationLedgerError::RevisionOverflow)
        );
    }
}
