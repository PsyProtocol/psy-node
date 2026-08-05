//! Canonical chain identity shared by rollback control, storage metadata, and
//! future RPC/message envelopes.
//!
//! The checkpoint hash in this module is the Coordinator's `last_chain_hash`.
//! It is deliberately distinct from a checkpoint-tree root or a Realm-local
//! state root, even though all three currently use the same 256-bit hash
//! representation.

use std::{error::Error, fmt};

use parth_core::{
    crypto::hash::traits::MerkleHasher,
    protocol::core_types::{Q256BitHash, QZKProofPublicInputsHasherReader},
};
use psy_core::constants::chain_id::PsyChainNetworkType;

/// Domain separator for the V1 canonical-chain-reference codec.
pub const CANONICAL_CHAIN_REF_MAGIC: [u8; 8] = *b"PSYCCREF";
/// Current canonical-chain-reference codec version.
pub const CANONICAL_CHAIN_REF_CODEC_VERSION: u16 = 1;
/// V1 hash semantics: Coordinator checkpoint proof public-input hash, also
/// stored in memory as `last_chain_hash`.
pub const CHECKPOINT_HASH_KIND_LAST_CHAIN_HASH: u8 = 1;
/// Every supported Coordinator checkpoint hash has a fixed 256-bit encoding.
pub const CHECKPOINT_HASH_LEN: u16 = 32;
/// Exact byte length of a V1 [`CanonicalChainRef`] encoding.
pub const CANONICAL_CHAIN_REF_V1_LEN: usize = 65;

/// Dense protocol checkpoint height.
///
/// It is intentionally not interchangeable with [`ChainEpoch`]:
///
/// ```compile_fail
/// use psy_data::protocol::canonical_chain::{ChainEpoch, CheckpointId};
/// let _: CheckpointId = ChainEpoch::new(7);
/// ```
///
/// It intentionally has no `Default` fallback:
///
/// ```compile_fail
/// use psy_data::protocol::canonical_chain::CheckpointId;
/// let _: CheckpointId = Default::default();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CheckpointId(u64);

impl CheckpointId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Monotonic canonical-branch generation fence.
///
/// A chain epoch is neither a checkpoint height nor an authority-local state
/// version. It only changes when canonical history is formally rewound.
///
/// ```compile_fail
/// use psy_data::protocol::canonical_chain::{ChainEpoch, CheckpointId};
/// let _: ChainEpoch = CheckpointId::new(7);
/// ```
///
/// ```compile_fail
/// use psy_data::protocol::canonical_chain::ChainEpoch;
/// let _: ChainEpoch = Default::default();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainEpoch(u64);

impl ChainEpoch {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Validated Psy network identity.
///
/// This wraps the existing authoritative [`PsyChainNetworkType`] instead of
/// defining a second numbering scheme. Its canonical numeric encoding is
/// exactly `PsyChainNetworkType::get_chain_id()`.
///
/// ```compile_fail
/// use psy_data::protocol::canonical_chain::{CheckpointId, NetworkId};
/// let _: NetworkId = CheckpointId::new(7);
/// ```
///
/// ```compile_fail
/// use psy_data::protocol::canonical_chain::NetworkId;
/// let _: NetworkId = 7u64;
/// ```
///
/// ```compile_fail
/// use psy_data::protocol::canonical_chain::NetworkId;
/// let _: NetworkId = Default::default();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NetworkId(PsyChainNetworkType);

impl NetworkId {
    pub const fn from_network_type(network: PsyChainNetworkType) -> Self {
        Self(network)
    }

    pub const fn network_type(self) -> PsyChainNetworkType {
        self.0
    }

    pub fn chain_id(self) -> u32 {
        self.0.get_chain_id()
    }

    pub fn try_from_chain_id(chain_id: u32) -> Result<Self, CanonicalChainRefCodecError> {
        PsyChainNetworkType::try_from_chain_id(chain_id)
            .map(Self)
            .map_err(|_| CanonicalChainRefCodecError::UnknownNetworkId(chain_id))
    }
}

impl From<PsyChainNetworkType> for NetworkId {
    fn from(value: PsyChainNetworkType) -> Self {
        Self::from_network_type(value)
    }
}

/// A Coordinator checkpoint commitment with `last_chain_hash` semantics.
///
/// There is deliberately no `From<Hash>` implementation. Callers must state
/// that the value came from the Coordinator's `last_chain_hash` or from a
/// checkpoint proof public input. Consequently a raw tree root cannot be
/// passed to [`CheckpointRef::new`] by accident:
///
/// ```compile_fail
/// use psy_data::protocol::canonical_chain::{CheckpointId, CheckpointRef};
/// let checkpoint_tree_root: parth_core::PHash = Default::default();
/// let _ = CheckpointRef::new(CheckpointId::new(4), checkpoint_tree_root);
/// ```
///
/// The semantic hash wrapper also has no default identity:
///
/// ```compile_fail
/// use psy_data::protocol::canonical_chain::CheckpointHash;
/// let _: CheckpointHash<parth_core::PHash> = Default::default();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CheckpointHash<Hash>(Hash);

impl<Hash> CheckpointHash<Hash> {
    /// Wrap a value already known by the Coordinator as `last_chain_hash`.
    pub const fn from_last_chain_hash(last_chain_hash: Hash) -> Self {
        Self(last_chain_hash)
    }

    /// Wrap the public-input hash extracted from a saved checkpoint proof.
    pub const fn from_proof_public_inputs_hash(public_inputs_hash: Hash) -> Self {
        Self(public_inputs_hash)
    }

    pub const fn as_inner(&self) -> &Hash {
        &self.0
    }

    pub fn into_inner(self) -> Hash {
        self.0
    }
}

/// Exact identity of one checkpoint occurrence on a branch.
///
/// ```compile_fail
/// use psy_data::protocol::canonical_chain::CheckpointRef;
/// let _: CheckpointRef<parth_core::PHash> = Default::default();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CheckpointRef<Hash> {
    checkpoint_id: CheckpointId,
    checkpoint_hash: CheckpointHash<Hash>,
}

impl<Hash> CheckpointRef<Hash> {
    pub const fn new(checkpoint_id: CheckpointId, checkpoint_hash: CheckpointHash<Hash>) -> Self {
        Self {
            checkpoint_id,
            checkpoint_hash,
        }
    }

    pub const fn checkpoint_id(&self) -> CheckpointId {
        self.checkpoint_id
    }

    pub const fn checkpoint_hash(&self) -> &CheckpointHash<Hash> {
        &self.checkpoint_hash
    }

    pub fn into_parts(self) -> (CheckpointId, CheckpointHash<Hash>) {
        (self.checkpoint_id, self.checkpoint_hash)
    }
}

/// Canonical branch identity at one exact checkpoint occurrence.
///
/// ```compile_fail
/// use psy_data::protocol::canonical_chain::CanonicalChainRef;
/// let _: CanonicalChainRef<parth_core::PHash> = Default::default();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CanonicalChainRef<Hash> {
    network_id: NetworkId,
    chain_epoch: ChainEpoch,
    checkpoint: CheckpointRef<Hash>,
}

impl<Hash> CanonicalChainRef<Hash> {
    pub const fn new(network_id: NetworkId, chain_epoch: ChainEpoch, checkpoint: CheckpointRef<Hash>) -> Self {
        Self {
            network_id,
            chain_epoch,
            checkpoint,
        }
    }

    pub const fn network_id(&self) -> NetworkId {
        self.network_id
    }

    pub const fn chain_epoch(&self) -> ChainEpoch {
        self.chain_epoch
    }

    pub const fn checkpoint(&self) -> &CheckpointRef<Hash> {
        &self.checkpoint
    }
}

impl<Hash: Q256BitHash> CanonicalChainRef<Hash> {
    /// Encode V1 without serde/bincode layout dependencies.
    ///
    /// Layout (all integers little-endian):
    ///
    /// ```text
    /// magic[8] | version:u16 | network_chain_id:u32 | chain_epoch:u64
    /// | checkpoint_id:u64 | hash_kind:u8 | hash_len:u16 | checkpoint_hash[32]
    /// ```
    pub fn to_canonical_bytes(&self) -> [u8; CANONICAL_CHAIN_REF_V1_LEN] {
        let mut encoded = [0u8; CANONICAL_CHAIN_REF_V1_LEN];
        encoded[0..8].copy_from_slice(&CANONICAL_CHAIN_REF_MAGIC);
        encoded[8..10].copy_from_slice(&CANONICAL_CHAIN_REF_CODEC_VERSION.to_le_bytes());
        encoded[10..14].copy_from_slice(&self.network_id.chain_id().to_le_bytes());
        encoded[14..22].copy_from_slice(&self.chain_epoch.get().to_le_bytes());
        encoded[22..30].copy_from_slice(&self.checkpoint.checkpoint_id.get().to_le_bytes());
        encoded[30] = CHECKPOINT_HASH_KIND_LAST_CHAIN_HASH;
        encoded[31..33].copy_from_slice(&CHECKPOINT_HASH_LEN.to_le_bytes());
        encoded[33..65].copy_from_slice(&self.checkpoint.checkpoint_hash.0.into_owned_32bytes());
        encoded
    }

    /// Decode V1 and reject unknown versions, invalid hash semantics, truncated
    /// input, and trailing bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CanonicalChainRefCodecError> {
        if bytes.len() < 10 {
            return Err(CanonicalChainRefCodecError::Truncated {
                expected: CANONICAL_CHAIN_REF_V1_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[0..8] != CANONICAL_CHAIN_REF_MAGIC {
            return Err(CanonicalChainRefCodecError::InvalidMagic);
        }

        let version = u16::from_le_bytes([bytes[8], bytes[9]]);
        if version != CANONICAL_CHAIN_REF_CODEC_VERSION {
            return Err(CanonicalChainRefCodecError::UnsupportedVersion(version));
        }
        if bytes.len() < CANONICAL_CHAIN_REF_V1_LEN {
            return Err(CanonicalChainRefCodecError::Truncated {
                expected: CANONICAL_CHAIN_REF_V1_LEN,
                actual: bytes.len(),
            });
        }
        if bytes.len() > CANONICAL_CHAIN_REF_V1_LEN {
            return Err(CanonicalChainRefCodecError::TrailingBytes {
                expected: CANONICAL_CHAIN_REF_V1_LEN,
                actual: bytes.len(),
            });
        }

        let network_chain_id = u32::from_le_bytes(bytes[10..14].try_into().expect("fixed slice"));
        let network_id = NetworkId::try_from_chain_id(network_chain_id)?;
        let chain_epoch = ChainEpoch::new(u64::from_le_bytes(bytes[14..22].try_into().expect("fixed slice")));
        let checkpoint_id = CheckpointId::new(u64::from_le_bytes(bytes[22..30].try_into().expect("fixed slice")));

        let hash_kind = bytes[30];
        if hash_kind != CHECKPOINT_HASH_KIND_LAST_CHAIN_HASH {
            return Err(CanonicalChainRefCodecError::UnsupportedHashKind(hash_kind));
        }
        let hash_len = u16::from_le_bytes(bytes[31..33].try_into().expect("fixed slice"));
        if hash_len != CHECKPOINT_HASH_LEN {
            return Err(CanonicalChainRefCodecError::InvalidHashLength(hash_len));
        }
        let checkpoint_hash = Hash::from_owned_32bytes(bytes[33..65].try_into().expect("fixed slice"));

        Ok(Self::new(
            network_id,
            chain_epoch,
            CheckpointRef::new(
                checkpoint_id,
                CheckpointHash::from_last_chain_hash(checkpoint_hash),
            ),
        ))
    }
}

/// Derive the exact genesis commitment used by the current Coordinator and
/// genesis checkpoint-state-transition circuit:
/// `H(H(checkpoint_tree_root, checkpoint_leaf_hash), genesis_fingerprint)`.
pub fn genesis_checkpoint_hash<Hash, Hasher>(
    checkpoint_tree_root: Hash,
    checkpoint_leaf_hash: Hash,
    genesis_checkpoint_state_transition_fingerprint: Hash,
) -> CheckpointHash<Hash>
where
    Hash: Copy,
    Hasher: MerkleHasher<Hash>,
{
    let root_leaf_hash = Hasher::two_to_one(&checkpoint_tree_root, &checkpoint_leaf_hash);
    CheckpointHash::from_last_chain_hash(Hasher::two_to_one(
        &root_leaf_hash,
        &genesis_checkpoint_state_transition_fingerprint,
    ))
}

/// Derive the exact non-genesis commitment used by the current checkpoint
/// transition circuit:
///
/// `H(parent, H(H(checkpoint_tree_root, checkpoint_leaf_hash), fingerprint))`.
pub fn checkpoint_hash_from_previous<Hash, Hasher>(
    parent_checkpoint_hash: CheckpointHash<Hash>,
    checkpoint_tree_root: Hash,
    checkpoint_leaf_hash: Hash,
    checkpoint_state_transition_circuit_fingerprint: Hash,
) -> CheckpointHash<Hash>
where
    Hash: Copy,
    Hasher: MerkleHasher<Hash>,
{
    let root_leaf_hash = Hasher::two_to_one(&checkpoint_tree_root, &checkpoint_leaf_hash);
    let step_hash = Hasher::two_to_one(
        &root_leaf_hash,
        &checkpoint_state_transition_circuit_fingerprint,
    );
    CheckpointHash::from_last_chain_hash(Hasher::two_to_one(
        parent_checkpoint_hash.as_inner(),
        &step_hash,
    ))
}

/// Recover checkpoint identity from a stored proof using the same verifier
/// public-input reader used by Coordinator startup/reset.
pub fn checkpoint_hash_from_saved_proof_bytes<Hash, Proof, Verifier>(
    proof_bytes: &[u8],
) -> anyhow::Result<CheckpointHash<Hash>>
where
    Verifier: QZKProofPublicInputsHasherReader<Hash, Proof>,
{
    let proof = Verifier::try_proof_from_slice(proof_bytes)?;
    Ok(CheckpointHash::from_proof_public_inputs_hash(
        Verifier::get_proof_public_inputs_hash(&proof)?,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalChainRefCodecError {
    InvalidMagic,
    UnsupportedVersion(u16),
    UnknownNetworkId(u32),
    UnsupportedHashKind(u8),
    InvalidHashLength(u16),
    Truncated { expected: usize, actual: usize },
    TrailingBytes { expected: usize, actual: usize },
}

impl fmt::Display for CanonicalChainRefCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => formatter.write_str("invalid canonical-chain-reference magic"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported canonical-chain-reference codec version {version}")
            }
            Self::UnknownNetworkId(network_id) => write!(formatter, "unknown Psy network chain ID {network_id}"),
            Self::UnsupportedHashKind(hash_kind) => write!(formatter, "unsupported checkpoint hash kind {hash_kind}"),
            Self::InvalidHashLength(hash_len) => write!(formatter, "invalid checkpoint hash length {hash_len}"),
            Self::Truncated { expected, actual } => {
                write!(formatter, "truncated canonical-chain-reference: expected {expected} bytes, got {actual}")
            }
            Self::TrailingBytes { expected, actual } => {
                write!(formatter, "trailing canonical-chain-reference bytes: expected {expected} bytes, got {actual}")
            }
        }
    }
}

impl Error for CanonicalChainRefCodecError {}

#[cfg(test)]
mod tests {
    use super::*;
    use parth_core::{
        pgoldilocks::PoseidonHasher,
        protocol::core_types::QZKProofPublicInputsHasherReader,
        PHash,
    };
    use crate::protocol::checkpoint_transition_hash::{
        CheckpointStateHashTransition, CheckpointStateTransitionPublicInputs,
    };

    const GOLDEN_VECTORS: &str = include_str!("../../tests/golden/canonical_chain_vectors_v1.txt");

    fn golden(name: &str) -> &str {
        GOLDEN_VECTORS
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .find_map(|line| {
                let (key, value) = line.split_once('=')?;
                (key == name).then_some(value)
            })
            .unwrap_or_else(|| panic!("missing canonical-chain golden vector {name}"))
    }

    fn checkpoint_ref(hash: PHash) -> CheckpointRef<PHash> {
        CheckpointRef::new(
            CheckpointId::new(367),
            CheckpointHash::from_last_chain_hash(hash),
        )
    }

    fn canonical_ref(
        network: PsyChainNetworkType,
        epoch: u64,
        checkpoint_id: u64,
        checkpoint_hash: PHash,
    ) -> CanonicalChainRef<PHash> {
        CanonicalChainRef::new(
            NetworkId::from(network),
            ChainEpoch::new(epoch),
            CheckpointRef::new(
                CheckpointId::new(checkpoint_id),
                CheckpointHash::from_last_chain_hash(checkpoint_hash),
            ),
        )
    }

    #[test]
    fn same_height_different_hash_is_a_different_checkpoint_ref() {
        assert_ne!(
            checkpoint_ref(PHash::from_values(1, 2, 3, 4)),
            checkpoint_ref(PHash::from_values(5, 6, 7, 8)),
        );
    }

    #[test]
    fn canonical_codec_has_stable_field_order_and_round_trips() {
        let chain = canonical_ref(
            PsyChainNetworkType::PsyMainnet,
            42,
            367,
            PHash::from_values(1, 2, 3, 4),
        );
        let first = chain.to_canonical_bytes();
        let second = chain.to_canonical_bytes();
        assert_eq!(first, second);
        assert_eq!(
            hex::encode(first),
            golden("canonical_mainnet_epoch_42_checkpoint_367_hash_1_2_3_4"),
        );
        assert_eq!(CanonicalChainRef::<PHash>::from_canonical_bytes(&first).unwrap(), chain);
    }

    #[test]
    fn every_identity_field_changes_the_encoding() {
        let hash = PHash::from_values(1, 2, 3, 4);
        let base = canonical_ref(PsyChainNetworkType::PsyMainnet, 42, 367, hash).to_canonical_bytes();
        assert_ne!(
            canonical_ref(PsyChainNetworkType::PsyPublicTestnet, 42, 367, hash).to_canonical_bytes(),
            base,
        );
        assert_ne!(canonical_ref(PsyChainNetworkType::PsyMainnet, 43, 367, hash).to_canonical_bytes(), base);
        assert_ne!(canonical_ref(PsyChainNetworkType::PsyMainnet, 42, 368, hash).to_canonical_bytes(), base);
        assert_ne!(
            canonical_ref(PsyChainNetworkType::PsyMainnet, 42, 367, PHash::from_values(5, 6, 7, 8))
                .to_canonical_bytes(),
            base,
        );
    }

    #[test]
    fn decoder_fails_closed_for_version_length_and_tail_errors() {
        let encoded = canonical_ref(
            PsyChainNetworkType::PsyMainnet,
            42,
            367,
            PHash::from_values(1, 2, 3, 4),
        )
        .to_canonical_bytes();

        let mut unknown_version = encoded;
        unknown_version[8..10].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(
            CanonicalChainRef::<PHash>::from_canonical_bytes(&unknown_version),
            Err(CanonicalChainRefCodecError::UnsupportedVersion(2)),
        );
        for cut in 0..CANONICAL_CHAIN_REF_V1_LEN {
            assert!(
                CanonicalChainRef::<PHash>::from_canonical_bytes(&encoded[..cut]).is_err(),
                "truncated prefix {cut} must fail closed",
            );
        }
        let mut with_tail = encoded.to_vec();
        with_tail.push(0);
        assert_eq!(
            CanonicalChainRef::<PHash>::from_canonical_bytes(&with_tail),
            Err(CanonicalChainRefCodecError::TrailingBytes {
                expected: CANONICAL_CHAIN_REF_V1_LEN,
                actual: 66,
            }),
        );
        let mut invalid_hash_len = encoded;
        invalid_hash_len[31..33].copy_from_slice(&31u16.to_le_bytes());
        assert_eq!(
            CanonicalChainRef::<PHash>::from_canonical_bytes(&invalid_hash_len),
            Err(CanonicalChainRefCodecError::InvalidHashLength(31)),
        );

        let mut invalid_magic = encoded;
        invalid_magic[0] ^= 1;
        assert_eq!(
            CanonicalChainRef::<PHash>::from_canonical_bytes(&invalid_magic),
            Err(CanonicalChainRefCodecError::InvalidMagic),
        );

        let mut invalid_hash_kind = encoded;
        invalid_hash_kind[30] = CHECKPOINT_HASH_KIND_LAST_CHAIN_HASH + 1;
        assert_eq!(
            CanonicalChainRef::<PHash>::from_canonical_bytes(&invalid_hash_kind),
            Err(CanonicalChainRefCodecError::UnsupportedHashKind(2)),
        );

        let mut invalid_network = encoded;
        invalid_network[10..14].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            CanonicalChainRef::<PHash>::from_canonical_bytes(&invalid_network),
            Err(CanonicalChainRefCodecError::UnknownNetworkId(u32::MAX)),
        );
    }

    #[test]
    fn network_codec_uses_authoritative_chain_id() {
        for network in [
            PsyChainNetworkType::LocalDevnet,
            PsyChainNetworkType::PsyTeamDevnet,
            PsyChainNetworkType::InternalDevnet,
            PsyChainNetworkType::InternalTestnet,
            PsyChainNetworkType::InternalPreProduction,
            PsyChainNetworkType::PsyPublicCanary,
            PsyChainNetworkType::PsyPublicTestnet,
            PsyChainNetworkType::PsyMainnet,
        ] {
            let typed = NetworkId::from(network);
            assert_eq!(typed.chain_id(), network.get_chain_id());
            assert_eq!(NetworkId::try_from_chain_id(typed.chain_id()).unwrap(), typed);
        }
        assert_eq!(
            NetworkId::try_from_chain_id(u32::MAX),
            Err(CanonicalChainRefCodecError::UnknownNetworkId(u32::MAX)),
        );
    }

    #[test]
    fn genesis_hash_matches_current_rule_and_golden() {
        type Hasher = PoseidonHasher;
        let root = PHash::from_values(5, 6, 7, 8);
        let leaf = PHash::from_values(9, 10, 11, 12);
        let fingerprint = PHash::from_values(13, 14, 15, 16);
        let actual = genesis_checkpoint_hash::<_, Hasher>(root, leaf, fingerprint).into_inner();
        let current_rule = CheckpointStateTransitionPublicInputs {
            checkpoint_transition: CheckpointStateHashTransition {
                old_checkpoint_tree_root: root,
                new_checkpoint_tree_root: root,
                old_checkpoint_leaf_hash: leaf,
                new_checkpoint_leaf_hash: leaf,
            },
            genesis_checkpoint_state_transition_hash: PHash::from_values(17, 18, 19, 20),
            checkpoint_state_transition_circuit_fingerprint: PHash::from_values(21, 22, 23, 24),
        }
        .get_chain_0_from_genesis_leaf::<Hasher>(&fingerprint);
        assert_eq!(actual, current_rule);
        assert_eq!(
            hex::encode(actual.into_owned_32bytes()),
            golden("genesis_poseidon_root_5_6_7_8_leaf_9_10_11_12_fp_13_14_15_16"),
        );
    }

    #[test]
    fn non_genesis_hash_matches_current_rule_and_golden() {
        type Hasher = PoseidonHasher;
        let parent = PHash::from_values(1, 2, 3, 4);
        let root = PHash::from_values(5, 6, 7, 8);
        let leaf = PHash::from_values(9, 10, 11, 12);
        let fingerprint = PHash::from_values(13, 14, 15, 16);
        let actual = checkpoint_hash_from_previous::<_, Hasher>(
            CheckpointHash::from_last_chain_hash(parent),
            root,
            leaf,
            fingerprint,
        )
        .into_inner();
        let current_rule = CheckpointStateTransitionPublicInputs {
            checkpoint_transition: CheckpointStateHashTransition {
                old_checkpoint_tree_root: PHash::from_values(17, 18, 19, 20),
                new_checkpoint_tree_root: root,
                old_checkpoint_leaf_hash: PHash::from_values(21, 22, 23, 24),
                new_checkpoint_leaf_hash: leaf,
            },
            genesis_checkpoint_state_transition_hash: PHash::from_values(25, 26, 27, 28),
            checkpoint_state_transition_circuit_fingerprint: fingerprint,
        }
        .get_chain_hash_from_previous::<Hasher>(&parent);
        assert_eq!(actual, current_rule);
        assert_eq!(
            hex::encode(actual.into_owned_32bytes()),
            golden("non_genesis_poseidon_parent_1_2_3_4_root_5_6_7_8_leaf_9_10_11_12_fp_13_14_15_16"),
        );
    }

    #[test]
    fn every_non_genesis_preimage_component_is_bound() {
        type Hasher = PoseidonHasher;
        let parent = PHash::from_values(1, 2, 3, 4);
        let root = PHash::from_values(5, 6, 7, 8);
        let leaf = PHash::from_values(9, 10, 11, 12);
        let fingerprint = PHash::from_values(13, 14, 15, 16);
        let derive = |parent, root, leaf, fingerprint| {
            checkpoint_hash_from_previous::<_, Hasher>(
                CheckpointHash::from_last_chain_hash(parent),
                root,
                leaf,
                fingerprint,
            )
            .into_inner()
        };
        let base = derive(parent, root, leaf, fingerprint);
        assert_ne!(base, derive(PHash::from_values(17, 18, 19, 20), root, leaf, fingerprint));
        assert_ne!(base, derive(parent, PHash::from_values(17, 18, 19, 20), leaf, fingerprint));
        assert_ne!(base, derive(parent, root, PHash::from_values(17, 18, 19, 20), fingerprint));
        assert_ne!(base, derive(parent, root, leaf, PHash::from_values(17, 18, 19, 20)));
    }

    #[derive(Clone, Copy)]
    struct MockSavedProof(PHash);

    struct MockSavedProofVerifier;

    impl QZKProofPublicInputsHasherReader<PHash, MockSavedProof> for MockSavedProofVerifier {
        fn get_proof_public_inputs_hash(proof: &MockSavedProof) -> anyhow::Result<PHash> {
            Ok(proof.0)
        }

        fn try_proof_from_slice(bytes: &[u8]) -> anyhow::Result<MockSavedProof> {
            Ok(MockSavedProof(PHash::from_slice_32bytes(bytes)?))
        }
    }

    #[test]
    fn saved_proof_public_inputs_recover_the_derived_checkpoint_hash() {
        type Hasher = PoseidonHasher;
        let expected = checkpoint_hash_from_previous::<_, Hasher>(
            CheckpointHash::from_last_chain_hash(PHash::from_values(1, 2, 3, 4)),
            PHash::from_values(5, 6, 7, 8),
            PHash::from_values(9, 10, 11, 12),
            PHash::from_values(13, 14, 15, 16),
        );
        let proof_bytes = expected.as_inner().into_owned_32bytes();
        let recovered = checkpoint_hash_from_saved_proof_bytes::<
            PHash,
            MockSavedProof,
            MockSavedProofVerifier,
        >(&proof_bytes)
        .unwrap();
        assert_eq!(recovered, expected);
    }
}
