//! Durable identity for the verifier that authorized a Realm UserEndCap.
//!
//! A concrete Rust verifier type is not a durable identity: its verifying key,
//! common circuit data or proof codec may change without changing the type
//! name.  This module commits those protocol inputs into a canonical artifact
//! and gives recovery code an exact historical lookup key.

use std::{collections::BTreeMap, error::Error, fmt, sync::Arc};

use psy_data::protocol::canonical_chain::NetworkId;
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"PSYRUVPF";
const CODEC_VERSION: u16 = 1;
const PROFILE_DOMAIN: &[u8] = b"psy/rollback/realm-user-update-verifier-profile/v1";
const USER_END_CAP_CIRCUIT: u32 = 6;

/// Stable verifier backend/configuration family. A new backend or field/config
/// combination must receive a new explicit discriminator.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum RealmUserUpdateVerifierBackend {
    Plonky2PoseidonGoldilocksD2 = 1,
    JtmbPoseidonGoldilocks = 2,
    DeterministicTest = 65_535,
}

impl RealmUserUpdateVerifierBackend {
    fn decode(value: u16) -> Result<Self, RealmUserUpdateVerifierProfileError> {
        match value {
            1 => Ok(Self::Plonky2PoseidonGoldilocksD2),
            2 => Ok(Self::JtmbPoseidonGoldilocks),
            65_535 => Ok(Self::DeterministicTest),
            _ => Err(RealmUserUpdateVerifierProfileError::UnknownBackend(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RealmUserUpdateVerifierProfileId([u8; 32]);

impl RealmUserUpdateVerifierProfileId {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn try_from_persisted(
        bytes: [u8; 32],
    ) -> Result<Self, RealmUserUpdateVerifierProfileError> {
        if bytes == [0; 32] {
            Err(RealmUserUpdateVerifierProfileError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }
}

/// Canonical protocol facts needed to choose the exact historical verifier.
///
/// The two 32-byte commitments are backend-produced canonical commitments;
/// callers must not derive them from Rust type names, debug output or paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmUserUpdateVerifierProfile {
    network: NetworkId,
    global_user_tree_height: u8,
    backend: RealmUserUpdateVerifierBackend,
    public_input_layout_version: u16,
    proof_codec_version: u16,
    verifier_fingerprint: [u8; 32],
    common_data_fingerprint: [u8; 32],
    id: RealmUserUpdateVerifierProfileId,
}

impl RealmUserUpdateVerifierProfile {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        network: NetworkId,
        global_user_tree_height: u8,
        backend: RealmUserUpdateVerifierBackend,
        public_input_layout_version: u16,
        proof_codec_version: u16,
        verifier_fingerprint: [u8; 32],
        common_data_fingerprint: [u8; 32],
    ) -> Result<Self, RealmUserUpdateVerifierProfileError> {
        if global_user_tree_height == 0 {
            return Err(RealmUserUpdateVerifierProfileError::InvalidTreeHeight);
        }
        if public_input_layout_version == 0 || proof_codec_version == 0 {
            return Err(RealmUserUpdateVerifierProfileError::InvalidSemanticVersion);
        }
        if verifier_fingerprint == [0; 32] || common_data_fingerprint == [0; 32] {
            return Err(RealmUserUpdateVerifierProfileError::EmptyDigest);
        }
        let mut profile = Self {
            network,
            global_user_tree_height,
            backend,
            public_input_layout_version,
            proof_codec_version,
            verifier_fingerprint,
            common_data_fingerprint,
            id: RealmUserUpdateVerifierProfileId([0; 32]),
        };
        profile.id = profile.compute_id()?;
        Ok(profile)
    }

    pub const fn id(&self) -> RealmUserUpdateVerifierProfileId {
        self.id
    }

    pub const fn network(&self) -> NetworkId {
        self.network
    }

    pub const fn global_user_tree_height(&self) -> u8 {
        self.global_user_tree_height
    }

    pub const fn backend(&self) -> RealmUserUpdateVerifierBackend {
        self.backend
    }

    pub const fn public_input_layout_version(&self) -> u16 {
        self.public_input_layout_version
    }

    pub const fn proof_codec_version(&self) -> u16 {
        self.proof_codec_version
    }

    pub const fn verifier_fingerprint(&self) -> &[u8; 32] {
        &self.verifier_fingerprint
    }

    pub const fn common_data_fingerprint(&self) -> &[u8; 32] {
        &self.common_data_fingerprint
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = self.encode_without_id();
        bytes.extend_from_slice(self.id.as_bytes());
        bytes
    }

    pub fn from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<Self, RealmUserUpdateVerifierProfileError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.take(8)? != MAGIC {
            return Err(RealmUserUpdateVerifierProfileError::InvalidMagic);
        }
        let version = decoder.u16()?;
        if version != CODEC_VERSION {
            return Err(RealmUserUpdateVerifierProfileError::UnknownCodecVersion(version));
        }
        let network = NetworkId::try_from_chain_id(decoder.u32()?)
            .map_err(|_| RealmUserUpdateVerifierProfileError::UnknownNetwork)?;
        let global_user_tree_height = decoder.u8()?;
        let circuit = decoder.u32()?;
        if circuit != USER_END_CAP_CIRCUIT {
            return Err(RealmUserUpdateVerifierProfileError::WrongCircuit(circuit));
        }
        let backend = RealmUserUpdateVerifierBackend::decode(decoder.u16()?)?;
        let public_input_layout_version = decoder.u16()?;
        let proof_codec_version = decoder.u16()?;
        let verifier_fingerprint = decoder.array32()?;
        let common_data_fingerprint = decoder.array32()?;
        let id = RealmUserUpdateVerifierProfileId::try_from_persisted(decoder.array32()?)?;
        if !decoder.done() {
            return Err(RealmUserUpdateVerifierProfileError::TrailingBytes);
        }
        let profile = Self::try_new(
            network,
            global_user_tree_height,
            backend,
            public_input_layout_version,
            proof_codec_version,
            verifier_fingerprint,
            common_data_fingerprint,
        )?;
        if profile.id != id {
            return Err(RealmUserUpdateVerifierProfileError::DigestMismatch);
        }
        Ok(profile)
    }

    fn encode_without_id(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(119);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.network.chain_id().to_be_bytes());
        bytes.push(self.global_user_tree_height);
        bytes.extend_from_slice(&USER_END_CAP_CIRCUIT.to_be_bytes());
        bytes.extend_from_slice(&(self.backend as u16).to_be_bytes());
        bytes.extend_from_slice(&self.public_input_layout_version.to_be_bytes());
        bytes.extend_from_slice(&self.proof_codec_version.to_be_bytes());
        bytes.extend_from_slice(&self.verifier_fingerprint);
        bytes.extend_from_slice(&self.common_data_fingerprint);
        bytes
    }

    fn compute_id(
        &self,
    ) -> Result<RealmUserUpdateVerifierProfileId, RealmUserUpdateVerifierProfileError> {
        let mut hasher = Sha256::new();
        hasher.update(PROFILE_DOMAIN);
        hasher.update(self.encode_without_id());
        RealmUserUpdateVerifierProfileId::try_from_persisted(hasher.finalize().into())
    }
}

/// A verifier handle may only leave a registry together with the exact
/// canonical profile that named it. The registry is immutable after creation,
/// which makes concurrent recovery deterministic.
pub struct BoundRealmUserUpdateVerifier<Verifier> {
    profile: RealmUserUpdateVerifierProfile,
    verifier: Arc<Verifier>,
}

impl<Verifier> Clone for BoundRealmUserUpdateVerifier<Verifier> {
    fn clone(&self) -> Self {
        Self {
            profile: self.profile.clone(),
            verifier: Arc::clone(&self.verifier),
        }
    }
}

impl<Verifier> BoundRealmUserUpdateVerifier<Verifier> {
    pub const fn profile(&self) -> &RealmUserUpdateVerifierProfile {
        &self.profile
    }

    pub const fn profile_id(&self) -> RealmUserUpdateVerifierProfileId {
        self.profile.id()
    }

    pub fn verifier(&self) -> &Arc<Verifier> {
        &self.verifier
    }
}

pub struct RealmUserUpdateVerifierRegistry<Verifier> {
    entries: BTreeMap<RealmUserUpdateVerifierProfileId, BoundRealmUserUpdateVerifier<Verifier>>,
}

impl<Verifier> RealmUserUpdateVerifierRegistry<Verifier> {
    pub fn try_new(
        entries: impl IntoIterator<Item = (RealmUserUpdateVerifierProfile, Arc<Verifier>)>,
    ) -> Result<Self, RealmUserUpdateVerifierProfileError> {
        let mut resolved = BTreeMap::new();
        for (profile, verifier) in entries {
            let id = profile.id();
            if resolved
                .insert(id, BoundRealmUserUpdateVerifier { profile, verifier })
                .is_some()
            {
                return Err(RealmUserUpdateVerifierProfileError::DuplicateProfile(id));
            }
        }
        if resolved.is_empty() {
            return Err(RealmUserUpdateVerifierProfileError::EmptyRegistry);
        }
        Ok(Self { entries: resolved })
    }

    pub fn resolve(
        &self,
        id: RealmUserUpdateVerifierProfileId,
    ) -> Result<BoundRealmUserUpdateVerifier<Verifier>, RealmUserUpdateVerifierProfileError> {
        self.entries
            .get(&id)
            .cloned()
            .ok_or(RealmUserUpdateVerifierProfileError::UnknownProfile(id))
    }

    pub fn contains(&self, id: RealmUserUpdateVerifierProfileId) -> bool {
        self.entries.contains_key(&id)
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], RealmUserUpdateVerifierProfileError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(RealmUserUpdateVerifierProfileError::MalformedPayload)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(RealmUserUpdateVerifierProfileError::MalformedPayload)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, RealmUserUpdateVerifierProfileError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, RealmUserUpdateVerifierProfileError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, RealmUserUpdateVerifierProfileError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn array32(&mut self) -> Result<[u8; 32], RealmUserUpdateVerifierProfileError> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    fn done(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealmUserUpdateVerifierProfileError {
    EmptyDigest,
    InvalidTreeHeight,
    InvalidSemanticVersion,
    InvalidMagic,
    UnknownCodecVersion(u16),
    UnknownBackend(u16),
    UnknownNetwork,
    WrongCircuit(u32),
    MalformedPayload,
    TrailingBytes,
    DigestMismatch,
    EmptyRegistry,
    DuplicateProfile(RealmUserUpdateVerifierProfileId),
    UnknownProfile(RealmUserUpdateVerifierProfileId),
}

impl fmt::Display for RealmUserUpdateVerifierProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RealmUserUpdateVerifierProfileError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(backend: RealmUserUpdateVerifierBackend) -> RealmUserUpdateVerifierProfile {
        RealmUserUpdateVerifierProfile::try_new(
            NetworkId::try_from_chain_id(1337).unwrap(),
            32,
            backend,
            1,
            1,
            [7; 32],
            [8; 32],
        )
        .unwrap()
    }

    #[test]
    fn canonical_profile_is_deterministic_and_fail_closed() {
        let profile = profile(RealmUserUpdateVerifierBackend::Plonky2PoseidonGoldilocksD2);
        let bytes = profile.to_canonical_bytes();
        assert_eq!(bytes.len(), 121);
        assert_eq!(
            hex::encode(profile.id().as_bytes()),
            "995a2751f18b723730c56192c6104a67214929c3664ca9110b8f173b4d5108fc"
        );
        assert_eq!(
            RealmUserUpdateVerifierProfile::from_canonical_bytes(&bytes).unwrap(),
            profile
        );
        assert_eq!(profile.to_canonical_bytes(), bytes);

        let mut tampered = bytes.clone();
        tampered[30] ^= 1;
        assert_eq!(
            RealmUserUpdateVerifierProfile::from_canonical_bytes(&tampered),
            Err(RealmUserUpdateVerifierProfileError::DigestMismatch)
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            RealmUserUpdateVerifierProfile::from_canonical_bytes(&trailing),
            Err(RealmUserUpdateVerifierProfileError::TrailingBytes)
        );
    }

    #[test]
    fn every_protocol_fact_changes_the_profile_id() {
        let base = profile(RealmUserUpdateVerifierBackend::Plonky2PoseidonGoldilocksD2);
        let variants = [
            RealmUserUpdateVerifierProfile::try_new(
                NetworkId::try_from_chain_id(0).unwrap(), 32, base.backend(), 1, 1, [7; 32], [8; 32],
            ).unwrap(),
            RealmUserUpdateVerifierProfile::try_new(
                base.network(), 31, base.backend(), 1, 1, [7; 32], [8; 32],
            ).unwrap(),
            RealmUserUpdateVerifierProfile::try_new(
                base.network(), 32, RealmUserUpdateVerifierBackend::JtmbPoseidonGoldilocks, 1, 1, [7; 32], [8; 32],
            ).unwrap(),
            RealmUserUpdateVerifierProfile::try_new(
                base.network(), 32, base.backend(), 2, 1, [7; 32], [8; 32],
            ).unwrap(),
            RealmUserUpdateVerifierProfile::try_new(
                base.network(), 32, base.backend(), 1, 2, [7; 32], [8; 32],
            ).unwrap(),
            RealmUserUpdateVerifierProfile::try_new(
                base.network(), 32, base.backend(), 1, 1, [9; 32], [8; 32],
            ).unwrap(),
            RealmUserUpdateVerifierProfile::try_new(
                base.network(), 32, base.backend(), 1, 1, [7; 32], [9; 32],
            ).unwrap(),
        ];
        for variant in variants {
            assert_ne!(variant.id(), base.id());
        }
    }

    #[test]
    fn malformed_profile_and_invalid_protocol_facts_fail_closed() {
        let profile = profile(RealmUserUpdateVerifierBackend::Plonky2PoseidonGoldilocksD2);
        let bytes = profile.to_canonical_bytes();

        for end in 0..bytes.len() {
            assert!(RealmUserUpdateVerifierProfile::from_canonical_bytes(&bytes[..end]).is_err());
        }
        let mut unknown_codec = bytes.clone();
        unknown_codec[8..10].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            RealmUserUpdateVerifierProfile::from_canonical_bytes(&unknown_codec),
            Err(RealmUserUpdateVerifierProfileError::UnknownCodecVersion(2))
        );
        let mut wrong_circuit = bytes.clone();
        wrong_circuit[15..19].copy_from_slice(&7_u32.to_be_bytes());
        assert_eq!(
            RealmUserUpdateVerifierProfile::from_canonical_bytes(&wrong_circuit),
            Err(RealmUserUpdateVerifierProfileError::WrongCircuit(7))
        );
        let mut unknown_backend = bytes;
        unknown_backend[19..21].copy_from_slice(&3_u16.to_be_bytes());
        assert_eq!(
            RealmUserUpdateVerifierProfile::from_canonical_bytes(&unknown_backend),
            Err(RealmUserUpdateVerifierProfileError::UnknownBackend(3))
        );

        assert_eq!(
            RealmUserUpdateVerifierProfile::try_new(
                NetworkId::try_from_chain_id(1337).unwrap(),
                0,
                RealmUserUpdateVerifierBackend::Plonky2PoseidonGoldilocksD2,
                1,
                1,
                [7; 32],
                [8; 32],
            ),
            Err(RealmUserUpdateVerifierProfileError::InvalidTreeHeight)
        );
        assert_eq!(
            RealmUserUpdateVerifierProfileId::try_from_persisted([0; 32]),
            Err(RealmUserUpdateVerifierProfileError::EmptyDigest)
        );
    }

    #[test]
    fn resolver_is_exact_and_unknown_profiles_fail_closed() {
        let a = profile(RealmUserUpdateVerifierBackend::DeterministicTest);
        let b = RealmUserUpdateVerifierProfile::try_new(
            a.network(), 32, a.backend(), 1, 2, [7; 32], [8; 32],
        ).unwrap();
        let registry = RealmUserUpdateVerifierRegistry::try_new([(a.clone(), Arc::new(11_u8))]).unwrap();
        let bound = registry.resolve(a.id()).unwrap();
        assert_eq!(bound.profile(), &a);
        assert_eq!(**bound.verifier(), 11);
        assert_eq!(
            registry.resolve(b.id()).err(),
            Some(RealmUserUpdateVerifierProfileError::UnknownProfile(b.id()))
        );
        assert_eq!(
            RealmUserUpdateVerifierRegistry::<u8>::try_new([]).err(),
            Some(RealmUserUpdateVerifierProfileError::EmptyRegistry)
        );
        assert_eq!(
            RealmUserUpdateVerifierRegistry::try_new([
                (a.clone(), Arc::new(11_u8)),
                (a.clone(), Arc::new(12_u8)),
            ])
            .err(),
            Some(RealmUserUpdateVerifierProfileError::DuplicateProfile(a.id()))
        );
    }
}
