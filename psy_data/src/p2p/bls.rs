//! IETF BLS12-381 min-pk suite (`blst::min_pk`) for Vote signatures and genesis proof of possession.

use super::codec::{write_fixed, ProtocolEncode, ProtocolReader};
use super::domains::{PROOF_OF_POSSESSION_BLS_DST, VOTE_BLS_DST};
use super::error::{ProtocolError, ProtocolResult};
use super::limits::{BLS_PUBLIC_KEY_LEN, BLS_SECRET_KEY_LEN, BLS_SIGNATURE_LEN};
use blst::min_pk::{
    AggregateSignature, PublicKey as BlstPublicKey, SecretKey as BlstSecretKey,
    Signature as BlstSignature,
};
use blst::BLST_ERROR;

/// Compressed BLS12-381 G1 public key (48 bytes, min-pk).
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct BlsPublicKey {
    bytes: [u8; BLS_PUBLIC_KEY_LEN],
}

impl std::fmt::Debug for BlsPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BlsPublicKey({})", hex::encode(self.bytes))
    }
}

impl BlsPublicKey {
    /// Strict decode + `KeyValidate` (on-curve, not infinity, subgroup).
    pub fn from_bytes(bytes: &[u8]) -> ProtocolResult<Self> {
        if bytes.len() != BLS_PUBLIC_KEY_LEN {
            return Err(ProtocolError::InvalidLength {
                what: "BlsPublicKey",
                got: bytes.len(),
                expected: BLS_PUBLIC_KEY_LEN,
            });
        }
        // Reject non-compressed encodings early; blst also checks the compression flag.
        if bytes[0] & 0x80 == 0 {
            return Err(ProtocolError::InvalidBlsPublicKey);
        }
        BlstPublicKey::key_validate(bytes).map_err(|_| ProtocolError::InvalidBlsPublicKey)?;
        let mut arr = [0u8; BLS_PUBLIC_KEY_LEN];
        arr.copy_from_slice(bytes);
        Ok(Self { bytes: arr })
    }

    /// Decode from a protocol reader (exactly 48 opaque bytes) with KeyValidate.
    pub fn protocol_decode(reader: &mut ProtocolReader<'_>) -> ProtocolResult<Self> {
        let bytes = reader.read_fixed::<BLS_PUBLIC_KEY_LEN>()?;
        Self::from_bytes(&bytes)
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8; BLS_PUBLIC_KEY_LEN] {
        &self.bytes
    }

    #[inline]
    pub fn to_bytes(&self) -> [u8; BLS_PUBLIC_KEY_LEN] {
        self.bytes
    }

    fn inner(&self) -> ProtocolResult<BlstPublicKey> {
        BlstPublicKey::from_bytes(&self.bytes).map_err(|_| ProtocolError::InvalidBlsPublicKey)
    }

    /// Verify an IETF BLS proof of possession for this public key.
    pub fn verify_proof_of_possession(&self, proof_of_possession: &BlsSignature) -> ProtocolResult<()> {
        let pk = self.inner()?;
        let sig = proof_of_possession.inner()?;
        let err = sig.verify(
            true,
            self.bytes.as_slice(),
            PROOF_OF_POSSESSION_BLS_DST,
            &[],
            &pk,
            true,
        );
        if err != BLST_ERROR::BLST_SUCCESS {
            return Err(ProtocolError::InvalidProofOfPossession);
        }
        Ok(())
    }
}

impl ProtocolEncode for BlsPublicKey {
    fn protocol_encode(&self, out: &mut Vec<u8>) {
        write_fixed(out, &self.bytes);
    }
}

/// Compressed BLS12-381 G2 signature (96 bytes, min-pk).
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct BlsSignature {
    bytes: [u8; BLS_SIGNATURE_LEN],
}

impl std::fmt::Debug for BlsSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BlsSignature({})", hex::encode(self.bytes))
    }
}

impl BlsSignature {
    /// Strict decode with group check (`sig_validate`).
    pub fn from_bytes(bytes: &[u8]) -> ProtocolResult<Self> {
        if bytes.len() != BLS_SIGNATURE_LEN {
            return Err(ProtocolError::InvalidLength {
                what: "BlsSignature",
                got: bytes.len(),
                expected: BLS_SIGNATURE_LEN,
            });
        }
        if bytes[0] & 0x80 == 0 {
            return Err(ProtocolError::InvalidBlsSignature);
        }
        BlstSignature::from_bytes(bytes)
            .map_err(|_| ProtocolError::InvalidBlsSignature)?
            .validate(true /* sig_groupcheck */)
            .map_err(|_| ProtocolError::InvalidBlsSignature)?;
        let mut arr = [0u8; BLS_SIGNATURE_LEN];
        arr.copy_from_slice(bytes);
        Ok(Self { bytes: arr })
    }

    /// Decode without requiring the infinite/identity point rejection beyond group check.
    /// Used when reconstructing aggregate signatures that have already been group-checked.
    pub fn protocol_decode(reader: &mut ProtocolReader<'_>) -> ProtocolResult<Self> {
        let bytes = reader.read_fixed::<BLS_SIGNATURE_LEN>()?;
        Self::from_bytes(&bytes)
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8; BLS_SIGNATURE_LEN] {
        &self.bytes
    }

    #[inline]
    pub fn to_bytes(&self) -> [u8; BLS_SIGNATURE_LEN] {
        self.bytes
    }

    fn inner(&self) -> ProtocolResult<BlstSignature> {
        BlstSignature::from_bytes(&self.bytes).map_err(|_| ProtocolError::InvalidBlsSignature)
    }

    /// Verify a single Vote signature under [`VOTE_BLS_DST`].
    pub fn verify_vote(&self, message: &[u8], public_key: &BlsPublicKey) -> ProtocolResult<()> {
        let sig = self.inner()?;
        let pk = public_key.inner()?;
        let err = sig.verify(true, message, VOTE_BLS_DST, &[], &pk, true);
        if err != BLST_ERROR::BLST_SUCCESS {
            return Err(ProtocolError::BlsVerifyFailed);
        }
        Ok(())
    }

    /// `FastAggregateVerify` over one message and many public keys under [`VOTE_BLS_DST`].
    pub fn fast_aggregate_verify(
        &self,
        message: &[u8],
        public_keys: &[BlsPublicKey],
    ) -> ProtocolResult<()> {
        if public_keys.is_empty() {
            return Err(ProtocolError::EmptyAggregate);
        }
        let sig = self.inner()?;
        let pks: ProtocolResult<Vec<BlstPublicKey>> =
            public_keys.iter().map(|pk| pk.inner()).collect();
        let pks = pks?;
        let pk_refs: Vec<&BlstPublicKey> = pks.iter().collect();
        let err = sig.fast_aggregate_verify(true, message, VOTE_BLS_DST, &pk_refs);
        if err != BLST_ERROR::BLST_SUCCESS {
            return Err(ProtocolError::BlsVerifyFailed);
        }
        Ok(())
    }
}

impl ProtocolEncode for BlsSignature {
    fn protocol_encode(&self, out: &mut Vec<u8>) {
        write_fixed(out, &self.bytes);
    }
}

/// BLS secret key (32-byte nonzero scalar < subgroup order).
pub struct BlsSecretKey {
    inner: BlstSecretKey,
}

impl std::fmt::Debug for BlsSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BlsSecretKey([redacted])")
    }
}

impl BlsSecretKey {
    /// Generate from 32+ bytes of IKM (HKDF keygen).
    pub fn key_gen(ikm: &[u8]) -> ProtocolResult<Self> {
        if ikm.len() < 32 {
            return Err(ProtocolError::InvalidBlsSecretKey);
        }
        let inner =
            BlstSecretKey::key_gen(ikm, &[]).map_err(|_| ProtocolError::InvalidBlsSecretKey)?;
        Ok(Self { inner })
    }

    /// Decode a 32-byte big-endian scalar via `blst::SecretKey::from_bytes`.
    pub fn from_bytes(bytes: &[u8]) -> ProtocolResult<Self> {
        if bytes.len() != BLS_SECRET_KEY_LEN {
            return Err(ProtocolError::InvalidLength {
                what: "BlsSecretKey",
                got: bytes.len(),
                expected: BLS_SECRET_KEY_LEN,
            });
        }
        let inner =
            BlstSecretKey::from_bytes(bytes).map_err(|_| ProtocolError::InvalidBlsSecretKey)?;
        Ok(Self { inner })
    }

    /// Serialize as 32-byte big-endian scalar (`to_bytes`).
    pub fn to_bytes(&self) -> [u8; BLS_SECRET_KEY_LEN] {
        self.inner.to_bytes()
    }

    /// Derive the corresponding public key and run KeyValidate on the compressed form.
    pub fn public_key(&self) -> BlsPublicKey {
        let pk = self.inner.sk_to_pk();
        let bytes = pk.to_bytes();
        BlsPublicKey::from_bytes(&bytes).expect("sk_to_pk output always KeyValidates")
    }

    /// Sign an arbitrary message under [`VOTE_BLS_DST`].
    pub fn sign_vote(&self, message: &[u8]) -> BlsSignature {
        let sig = self.inner.sign(message, VOTE_BLS_DST, &[]);
        let bytes = sig.to_bytes();
        BlsSignature {
            bytes,
        }
    }

    /// Produce an IETF BLS proof of possession over the compressed public key.
    pub fn proof_of_possession(&self) -> BlsSignature {
        let pk_bytes = self.public_key().to_bytes();
        let sig = self.inner.sign(&pk_bytes, PROOF_OF_POSSESSION_BLS_DST, &[]);
        BlsSignature {
            bytes: sig.to_bytes(),
        }
    }
}

/// Aggregate one or more Vote signatures (group-checked).
pub fn aggregate_signatures(signatures: &[BlsSignature]) -> ProtocolResult<BlsSignature> {
    if signatures.is_empty() {
        return Err(ProtocolError::EmptyAggregate);
    }
    let sigs: ProtocolResult<Vec<BlstSignature>> = signatures.iter().map(|s| s.inner()).collect();
    let sigs = sigs?;
    let refs: Vec<&BlstSignature> = sigs.iter().collect();
    let agg = AggregateSignature::aggregate(&refs, true /* groupcheck */)
        .map_err(|_| ProtocolError::InvalidBlsSignature)?;
    let bytes = agg.to_signature().to_bytes();
    BlsSignature::from_bytes(&bytes)
}

/// Validate a public key and its one-time proof of possession (genesis ceremony).
pub fn validate_key_with_proof_of_possession(
    public_key: &BlsPublicKey,
    proof_of_possession: &BlsSignature,
) -> ProtocolResult<()> {
    // KeyValidate already ran in BlsPublicKey::from_bytes; re-run for explicitness.
    BlstPublicKey::key_validate(public_key.as_bytes())
        .map_err(|_| ProtocolError::InvalidBlsPublicKey)?;
    public_key.verify_proof_of_possession(proof_of_possession)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sk(seed: u8) -> BlsSecretKey {
        BlsSecretKey::key_gen(&[seed; 32]).unwrap()
    }

    #[test]
    fn key_lengths_and_key_validate() {
        let sk = sk(7);
        let pk = sk.public_key();
        assert_eq!(pk.as_bytes().len(), 48);
        assert_eq!(sk.to_bytes().len(), 32);
        // Round-trip public key
        let pk2 = BlsPublicKey::from_bytes(pk.as_bytes()).unwrap();
        assert_eq!(pk, pk2);
        // Reject wrong length
        assert!(BlsPublicKey::from_bytes(&[0u8; 47]).is_err());
        assert!(BlsSignature::from_bytes(&[0u8; 95]).is_err());
        // Reject all-zero (infinity / bad encoding)
        assert!(BlsPublicKey::from_bytes(&[0u8; 48]).is_err());
    }

    #[test]
    fn proof_of_possession_roundtrip() {
        let secret_key = sk(9);
        let pk = secret_key.public_key();
        let proof_of_possession = secret_key.proof_of_possession();
        assert_eq!(proof_of_possession.as_bytes().len(), 96);
        validate_key_with_proof_of_possession(&pk, &proof_of_possession).unwrap();

        // Wrong key rejects proof of possession
        let other = sk(10).public_key();
        assert!(validate_key_with_proof_of_possession(&other, &proof_of_possession).is_err());
    }

    #[test]
    fn vote_sign_and_fast_aggregate_verify() {
        let msg = b"vote-message-bytes";
        let sk1 = sk(1);
        let sk2 = sk(2);
        let sk3 = sk(3);
        let pk1 = sk1.public_key();
        let pk2 = sk2.public_key();
        let pk3 = sk3.public_key();

        let s1 = sk1.sign_vote(msg);
        let s2 = sk2.sign_vote(msg);
        let s3 = sk3.sign_vote(msg);
        s1.verify_vote(msg, &pk1).unwrap();

        let agg = aggregate_signatures(&[s1, s2, s3]).unwrap();
        assert_eq!(agg.as_bytes().len(), 96);
        agg.fast_aggregate_verify(msg, &[pk1, pk2, pk3]).unwrap();

        // Wrong message fails
        assert!(agg
            .fast_aggregate_verify(b"other", &[pk1, pk2, pk3])
            .is_err());
        // Wrong set fails
        assert!(agg.fast_aggregate_verify(msg, &[pk1, pk2]).is_err());
    }

    #[test]
    fn public_key_protocol_encode_is_raw_48() {
        let pk = sk(4).public_key();
        let enc = pk.protocol_encode_to_vec();
        assert_eq!(enc, pk.as_bytes());
    }

    #[test]
    fn rejects_uncompressed_and_wrong_length_encodings() {
        // A compressed BLS public key has the high bit set (0x80) in byte 0.
        // Flipping it to clear must be rejected before any group check.
        let pk = sk(1).public_key();
        let mut uncompressed = pk.to_bytes();
        uncompressed[0] &= 0x7f;
        assert!(BlsPublicKey::from_bytes(&uncompressed).is_err());
        // Wrong-length inputs rejected.
        assert!(BlsPublicKey::from_bytes(&[0u8; 47]).is_err());
        assert!(BlsPublicKey::from_bytes(&[0u8; 49]).is_err());
        assert!(BlsSignature::from_bytes(&[0u8; 95]).is_err());
        assert!(BlsSignature::from_bytes(&[0u8; 97]).is_err());
        // All-zero (infinity / bad encoding) rejected.
        assert!(BlsPublicKey::from_bytes(&[0u8; 48]).is_err());
        assert!(BlsSignature::from_bytes(&[0u8; 96]).is_err());
    }

    #[test]
    fn secret_key_requires_at_least_32_bytes_of_ikm() {
        assert!(BlsSecretKey::key_gen(&[1u8; 31]).is_err());
        assert!(BlsSecretKey::key_gen(&[]).is_err());
        // Exactly 32 bytes works.
        assert!(BlsSecretKey::key_gen(&[2u8; 32]).is_ok());
        // Wrong-length scalar bytes rejected by from_bytes.
        assert!(BlsSecretKey::from_bytes(&[0u8; 31]).is_err());
        assert!(BlsSecretKey::from_bytes(&[0u8; 33]).is_err());
    }

    #[test]
    fn aggregate_rejects_empty_and_single_and_verify_threshold_semantics() {
        let msg = b"vote-message-bytes";
        let s1 = sk(1).sign_vote(msg);
        // Empty aggregate is an explicit error (not the identity signature).
        assert!(matches!(aggregate_signatures(&[]).unwrap_err(), ProtocolError::EmptyAggregate));
        // Single-signature aggregate is valid and verifies against that one key.
        let pk1 = sk(1).public_key();
        let agg = aggregate_signatures(&[s1]).unwrap();
        agg.fast_aggregate_verify(msg, &[pk1]).unwrap();
        // Threshold-style: 2-of-2 aggregate verifies against both keys, but NOT
        // against only one of them (proves the aggregate binds the full signer set).
        let s2 = sk(2).sign_vote(msg);
        let pk2 = sk(2).public_key();
        let agg2 = aggregate_signatures(&[s1, s2]).unwrap();
        agg2.fast_aggregate_verify(msg, &[pk1, pk2]).unwrap();
        assert!(agg2.fast_aggregate_verify(msg, &[pk1]).is_err());
        // A signature over a different message does NOT verify.
        assert!(agg2.fast_aggregate_verify(b"other", &[pk1, pk2]).is_err());
    }
}
