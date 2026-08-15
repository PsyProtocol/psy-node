//! Immutable Realm checkpoint-0 target evidence.
//!
//! Genesis is not a normal full commit and therefore has no COMMITTED
//! inventory marker.  This small anchor records only the mutable values and
//! control evidence that a destructive rollback needs in order to restore
//! checkpoint zero.  It is not a snapshot and exposes no delete, restore, or
//! head mutation capability.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::chain_context::{AuthorityObservation, AuthorityScope};
use psy_node_core::store::{
    authority_commit::AuthorityTimestampKey,
    authority_local_head::{
        AuthorityLocalHeadBootstrapReason, StoredAuthorityLocalHead,
    },
    pending_generation_identity::{
        PendingGenerationBootstrapReason, PendingGenerationLedgerKey,
    },
    pending_generation_pipeline::{PendingProcessingPhase, StoredPendingPipeline},
    timestamp::CommitWriteTimestampUs,
    typed::{
        LatestInfoSlot, LogicalMutation, MutationOperation, MutationValue,
        TypedTableKey, U64SingletonSlot,
    },
};
use sha2::{Digest, Sha256};

use super::{SealedTimestampedPut, TimestampedWriteKind, seal_commit_put};

const MAGIC: &[u8; 8] = b"PSYRRGA1";
const VERSION: u16 = 1;
const MAX_BYTES: usize = 128 * 1024;
const SLOT_DOMAIN: &[u8] = b"psy.rollback.realm-genesis-anchor-slot.v1\0";
const DIGEST_DOMAIN: &[u8] = b"psy.rollback.realm-genesis-anchor.v1\0";
const GENESIS_WRITE_TIMESTAMP_US: i64 = 1;
const GENESIS_WRITER_REVISION: u64 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RealmRollbackGenesisAnchor<Hash> {
    genesis: AuthorityObservation<Hash>,
    target_head: StoredAuthorityLocalHead<Hash>,
    target_pipeline: StoredPendingPipeline<Hash>,
    target_writer_revision: u64,
    target_puts: Vec<SealedTimestampedPut>,
    store_fingerprint: [u8; 32],
    slot: [u8; 32],
    digest: [u8; 32],
    canonical_bytes: Vec<u8>,
}

impl<Hash: Q256BitHash> RealmRollbackGenesisAnchor<Hash> {
    pub(super) fn try_new(
        genesis: AuthorityObservation<Hash>,
        genesis_l2_block_state: Vec<u8>,
        target_head: StoredAuthorityLocalHead<Hash>,
        target_pipeline: StoredPendingPipeline<Hash>,
        store_fingerprint: [u8; 32],
    ) -> Result<Self, RealmRollbackGenesisAnchorError> {
        let timestamp = CommitWriteTimestampUs::try_from_i128(
            i128::from(GENESIS_WRITE_TIMESTAMP_US),
        )
        .map_err(|_| RealmRollbackGenesisAnchorError::InvalidTimestamp)?;
        let target_puts = genesis_target_puts(&genesis, genesis_l2_block_state, timestamp)?;
        Self::try_from_parts(
            genesis,
            target_head,
            target_pipeline,
            GENESIS_WRITER_REVISION,
            target_puts,
            store_fingerprint,
        )
    }

    fn try_from_parts(
        genesis: AuthorityObservation<Hash>,
        target_head: StoredAuthorityLocalHead<Hash>,
        target_pipeline: StoredPendingPipeline<Hash>,
        target_writer_revision: u64,
        mut target_puts: Vec<SealedTimestampedPut>,
        store_fingerprint: [u8; 32],
    ) -> Result<Self, RealmRollbackGenesisAnchorError> {
        let AuthorityScope::Realm { .. } = genesis.authority() else {
            return Err(RealmRollbackGenesisAnchorError::RealmRequired);
        };
        if genesis.chain().chain_epoch().get() != 0
            || genesis.chain().checkpoint().checkpoint_id().get() != 0
            || genesis.state_checkpoint_id().get() != 0
            || store_fingerprint == [0; 32]
            || target_writer_revision != GENESIS_WRITER_REVISION
        {
            return Err(RealmRollbackGenesisAnchorError::BindingMismatch);
        }
        let head_key = AuthorityTimestampKey::new(
            genesis.chain().network_id(),
            genesis.authority(),
        );
        let pipeline_key = PendingGenerationLedgerKey::new(
            genesis.chain().network_id(),
            genesis.authority(),
        );
        if target_head.revision().get() != 0
            || target_head.bootstrap_reason()
                != AuthorityLocalHeadBootstrapReason::GenesisNative
            || target_head.commit_write_timestamp().as_i64()
                != GENESIS_WRITE_TIMESTAMP_US
            || target_head.storage_binding().generation().get() != 1
            || target_head.head().key() != head_key
            || target_head.head().chain() != genesis.chain()
            || target_head.head().state_checkpoint() != genesis.state_checkpoint_id()
            || target_head.head().state_root() != genesis.state_root()
            || target_pipeline.revision().get() != 2
            || target_pipeline.key() != pipeline_key
            || target_pipeline.frontier() != &genesis
            || target_pipeline.bootstrap_reason()
                != PendingGenerationBootstrapReason::Genesis
            || target_pipeline.derived_start_pending_id() != 1
            || target_pipeline.processing().pending_id().get() != 1
            || target_pipeline.gathering().pending_id().get() != 2
            || !matches!(target_pipeline.phase(), PendingProcessingPhase::Ready)
            || target_pipeline.processed_pending_id() != 0
            || target_pipeline.blocked_reason().is_some()
        {
            return Err(RealmRollbackGenesisAnchorError::BindingMismatch);
        }
        target_puts.sort_by(|left, right| {
            left.resolved().locator_bytes().cmp(right.resolved().locator_bytes())
        });
        validate_target_puts(&genesis, &target_puts)?;
        let slot = anchor_slot(&genesis);
        let mut anchor = Self {
            genesis,
            target_head,
            target_pipeline,
            target_writer_revision,
            target_puts,
            store_fingerprint,
            slot,
            digest: [0; 32],
            canonical_bytes: Vec::new(),
        };
        let body = anchor.encode_without_digest()?;
        anchor.digest = anchor_digest(&body);
        anchor.canonical_bytes = body;
        anchor.canonical_bytes.extend_from_slice(&anchor.digest);
        if anchor.canonical_bytes.len() > MAX_BYTES {
            return Err(RealmRollbackGenesisAnchorError::PayloadTooLarge);
        }
        Ok(anchor)
    }

    pub(super) fn decode_persisted(
        bytes: &[u8],
    ) -> Result<Self, RealmRollbackGenesisAnchorError> {
        if bytes.len() < 32 || bytes.len() > MAX_BYTES {
            return Err(RealmRollbackGenesisAnchorError::Malformed);
        }
        let body_len = bytes.len() - 32;
        if anchor_digest(&bytes[..body_len]) != bytes[body_len..] {
            return Err(RealmRollbackGenesisAnchorError::DigestMismatch);
        }
        let mut cursor = Cursor::new(&bytes[..body_len]);
        if cursor.take(8)? != MAGIC {
            return Err(RealmRollbackGenesisAnchorError::InvalidMagic);
        }
        let version = cursor.u16()?;
        if version != VERSION {
            return Err(RealmRollbackGenesisAnchorError::UnknownVersion(version));
        }
        let store_fingerprint = cursor.array32()?;
        let genesis = AuthorityObservation::from_canonical_bytes(cursor.bytes()?)
            .map_err(|_| RealmRollbackGenesisAnchorError::Malformed)?;
        let head_revision = i64::try_from(cursor.u64()?)
            .map_err(|_| RealmRollbackGenesisAnchorError::Malformed)?;
        let target_head = StoredAuthorityLocalHead::decode_persisted(
            AuthorityTimestampKey::new(genesis.chain().network_id(), genesis.authority()),
            head_revision,
            cursor.bytes()?,
        )
        .map_err(|_| RealmRollbackGenesisAnchorError::Malformed)?;
        let pipeline_revision = i64::try_from(cursor.u64()?)
            .map_err(|_| RealmRollbackGenesisAnchorError::Malformed)?;
        let target_pipeline = StoredPendingPipeline::decode_persisted(
            PendingGenerationLedgerKey::new(
                genesis.chain().network_id(),
                genesis.authority(),
            ),
            pipeline_revision,
            cursor.bytes()?,
        )
        .map_err(|_| RealmRollbackGenesisAnchorError::Malformed)?;
        let target_writer_revision = cursor.u64()?;
        let put_count = cursor.u16()? as usize;
        if put_count != 3 {
            return Err(RealmRollbackGenesisAnchorError::TargetPutSetMismatch);
        }
        let mut target_puts = Vec::with_capacity(put_count);
        for _ in 0..put_count {
            target_puts.push(
                SealedTimestampedPut::decode_realm_commit_inventory_canonical(
                    cursor.bytes()?,
                )
                .map_err(|_| RealmRollbackGenesisAnchorError::Malformed)?,
            );
        }
        let encoded_slot = cursor.array32()?;
        if !cursor.is_empty() {
            return Err(RealmRollbackGenesisAnchorError::TrailingBytes);
        }
        let decoded = Self::try_from_parts(
            genesis,
            target_head,
            target_pipeline,
            target_writer_revision,
            target_puts,
            store_fingerprint,
        )?;
        if decoded.slot != encoded_slot || decoded.canonical_bytes != bytes {
            return Err(RealmRollbackGenesisAnchorError::NonCanonicalEncoding);
        }
        Ok(decoded)
    }

    fn encode_without_digest(&self) -> Result<Vec<u8>, RealmRollbackGenesisAnchorError> {
        let mut out = Vec::with_capacity(4096);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_be_bytes());
        out.extend_from_slice(&self.store_fingerprint);
        encode_bytes(&mut out, &self.genesis.to_canonical_bytes())?;
        out.extend_from_slice(&self.target_head.revision().get().to_be_bytes());
        encode_bytes(&mut out, &self.target_head.encode_canonical())?;
        out.extend_from_slice(&self.target_pipeline.revision().get().to_be_bytes());
        encode_bytes(&mut out, &self.target_pipeline.canonical_payload())?;
        out.extend_from_slice(&self.target_writer_revision.to_be_bytes());
        out.extend_from_slice(
            &u16::try_from(self.target_puts.len())
                .map_err(|_| RealmRollbackGenesisAnchorError::PayloadTooLarge)?
                .to_be_bytes(),
        );
        for put in &self.target_puts {
            encode_bytes(&mut out, put.canonical_bytes())?;
        }
        out.extend_from_slice(&self.slot);
        Ok(out)
    }

    pub(super) const fn genesis(&self) -> &AuthorityObservation<Hash> { &self.genesis }
    pub(super) const fn authority(&self) -> AuthorityScope { self.genesis.authority() }
    pub(super) const fn target_head(&self) -> &StoredAuthorityLocalHead<Hash> {
        &self.target_head
    }
    pub(super) const fn target_pipeline(&self) -> &StoredPendingPipeline<Hash> {
        &self.target_pipeline
    }
    pub(super) const fn target_writer_revision(&self) -> u64 {
        self.target_writer_revision
    }
    pub(super) fn target_puts(&self) -> &[SealedTimestampedPut] { &self.target_puts }
    pub(super) const fn store_fingerprint(&self) -> &[u8; 32] {
        &self.store_fingerprint
    }
    pub(super) const fn slot(&self) -> &[u8; 32] { &self.slot }
    pub(super) const fn digest(&self) -> &[u8; 32] { &self.digest }
    pub(super) fn canonical_bytes(&self) -> &[u8] { &self.canonical_bytes }
}

fn genesis_target_puts<Hash: Q256BitHash>(
    genesis: &AuthorityObservation<Hash>,
    block_state: Vec<u8>,
    timestamp: CommitWriteTimestampUs,
) -> Result<Vec<SealedTimestampedPut>, RealmRollbackGenesisAnchorError> {
    let intents = [
        LogicalMutation::Put {
            key: TypedTableKey::U64Singleton(U64SingletonSlot::LatestCheckpoint),
            value: MutationValue::CqlU64(0),
        },
        LogicalMutation::Put {
            key: TypedTableKey::LatestInfo(LatestInfoSlot::LatestL2BlockState),
            value: MutationValue::PsyCanonicalBytes(block_state),
        },
        LogicalMutation::Put {
            key: TypedTableKey::LatestInfo(LatestInfoSlot::RealmAuthorityObservation),
            value: MutationValue::PsyCanonicalBytes(
                genesis.to_canonical_bytes().to_vec(),
            ),
        },
    ];
    intents
        .into_iter()
        .map(|intent| {
            seal_commit_put(intent, timestamp)
                .map_err(|_| RealmRollbackGenesisAnchorError::TargetPutSetMismatch)
        })
        .collect()
}

fn validate_target_puts<Hash: Q256BitHash>(
    genesis: &AuthorityObservation<Hash>,
    puts: &[SealedTimestampedPut],
) -> Result<(), RealmRollbackGenesisAnchorError> {
    if puts.len() != 3
        || puts.iter().any(|put| {
            put.timestamp().as_i64() != GENESIS_WRITE_TIMESTAMP_US
                || put.write_kind() != TimestampedWriteKind::AuthorityCommit
                || !matches!(put.resolved().mutation().operation(), MutationOperation::Put(_))
        })
    {
        return Err(RealmRollbackGenesisAnchorError::TargetPutSetMismatch);
    }
    let block_state = puts
        .iter()
        .find_map(|put| match (
            put.resolved().mutation().key(),
            put.resolved().mutation().operation(),
        ) {
            (
                TypedTableKey::LatestInfo(LatestInfoSlot::LatestL2BlockState),
                MutationOperation::Put(MutationValue::PsyCanonicalBytes(bytes)),
            ) => Some(bytes.clone()),
            _ => None,
        })
        .ok_or(RealmRollbackGenesisAnchorError::TargetPutSetMismatch)?;
    let timestamp = CommitWriteTimestampUs::try_from_i128(
        i128::from(GENESIS_WRITE_TIMESTAMP_US),
    )
    .map_err(|_| RealmRollbackGenesisAnchorError::InvalidTimestamp)?;
    let mut expected = genesis_target_puts(genesis, block_state, timestamp)?;
    expected.sort_by(|left, right| {
        left.resolved().locator_bytes().cmp(right.resolved().locator_bytes())
    });
    if expected != puts {
        return Err(RealmRollbackGenesisAnchorError::TargetPutSetMismatch);
    }
    Ok(())
}

fn anchor_slot<Hash: Q256BitHash>(genesis: &AuthorityObservation<Hash>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SLOT_DOMAIN);
    hasher.update(genesis.to_canonical_bytes());
    hasher.finalize().into()
}

fn anchor_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn encode_bytes(
    out: &mut Vec<u8>,
    bytes: &[u8],
) -> Result<(), RealmRollbackGenesisAnchorError> {
    out.extend_from_slice(
        &u32::try_from(bytes.len())
            .map_err(|_| RealmRollbackGenesisAnchorError::PayloadTooLarge)?
            .to_be_bytes(),
    );
    out.extend_from_slice(bytes);
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self { Self { bytes, offset: 0 } }
    fn take(&mut self, len: usize) -> Result<&'a [u8], RealmRollbackGenesisAnchorError> {
        let end = self.offset.checked_add(len).ok_or(RealmRollbackGenesisAnchorError::Malformed)?;
        let value = self.bytes.get(self.offset..end).ok_or(RealmRollbackGenesisAnchorError::Malformed)?;
        self.offset = end;
        Ok(value)
    }
    fn u16(&mut self) -> Result<u16, RealmRollbackGenesisAnchorError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, RealmRollbackGenesisAnchorError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, RealmRollbackGenesisAnchorError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn array32(&mut self) -> Result<[u8; 32], RealmRollbackGenesisAnchorError> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    fn bytes(&mut self) -> Result<&'a [u8], RealmRollbackGenesisAnchorError> {
        let len = self.u32()? as usize;
        self.take(len)
    }
    fn is_empty(&self) -> bool { self.offset == self.bytes.len() }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RealmRollbackGenesisAnchorError {
    RealmRequired,
    BindingMismatch,
    InvalidTimestamp,
    TargetPutSetMismatch,
    PayloadTooLarge,
    Malformed,
    InvalidMagic,
    UnknownVersion(u16),
    DigestMismatch,
    TrailingBytes,
    NonCanonicalEncoding,
}

impl fmt::Display for RealmRollbackGenesisAnchorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Realm rollback Genesis anchor error: {self:?}")
    }
}

impl Error for RealmRollbackGenesisAnchorError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchor_is_not_a_snapshot_or_mutation_capability() {
        let source = include_str!("realm_rollback_genesis_anchor.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in ["execute_delete", "execute_restore", "publish_head", "snapshot_rows"] {
            assert!(!production.contains(forbidden));
        }
    }
}
