//! Checkpoint-bound validator leaf record and Poseidon leaf hash.

use super::bls::BlsPublicKey;
use super::codec::{
    digest_to_field_limbs, sha256, write_fixed, write_u16, write_u32, write_u64, ProtocolEncode,
    ProtocolReader,
};
use super::domains::{DOMAIN_VALIDATOR_LEAF, DOMAIN_VALIDATOR_LEAF_FELT};
use super::error::{ProtocolError, ProtocolResult};
use super::node_id::NodeId;
use parth_core::crypto::hash::traits::FieldQHasher;
use parth_core::felt::FromPrimitiveValuesFelt;
use parth_core::pgoldilocks::PoseidonHasher;
use parth_core::{PHash, PF};

/// Validator-tree leaf payload.
///
/// `realm_id` / `realm_sub_id` come from leaf index `(realm_id << 8) | realm_sub_id`
/// and are not stored in the record.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ValidatorLeaf {
    pub validator_user_id: u64,
    pub node_id: NodeId,
    pub bls_public_key: BlsPublicKey,
}

impl ValidatorLeaf {
    pub fn new(validator_user_id: u64, node_id: NodeId, bls_public_key: BlsPublicKey) -> Self {
        Self {
            validator_user_id,
            node_id,
            bls_public_key,
        }
    }

    pub fn protocol_decode(reader: &mut ProtocolReader<'_>) -> ProtocolResult<Self> {
        let validator_user_id = reader.read_u64()?;
        let node_id = NodeId::protocol_decode(reader)?;
        let bls_public_key = BlsPublicKey::protocol_decode(reader)?;
        Ok(Self {
            validator_user_id,
            node_id,
            bls_public_key,
        })
    }

    /// `protocol_encode(DOMAIN_VALIDATOR_LEAF, chain_id, realm_id, realm_sub_id,
    ///                  validator_user_id, node_id, bls_public_key)`.
    pub fn construction_bytes(&self, chain_id: u32, realm_id: u32, realm_sub_id: u16) -> Vec<u8> {
        let mut out = Vec::new();
        write_fixed(&mut out, &DOMAIN_VALIDATOR_LEAF);
        write_u32(&mut out, chain_id);
        write_u32(&mut out, realm_id);
        write_u16(&mut out, realm_sub_id);
        write_u64(&mut out, self.validator_user_id);
        self.node_id.protocol_encode(&mut out);
        self.bls_public_key.protocol_encode(&mut out);
        out
    }

    /// Poseidon leaf hash. Errors if a SHA-256 digest limb is non-canonical Goldilocks.
    pub fn leaf_hash(&self) -> ProtocolResult<[u8; 32]> {
        let node_id_hash = sha256(self.node_id.as_raw());
        let bls_hash = sha256(self.bls_public_key.as_bytes());
        let node_limbs = digest_to_field_limbs(&node_id_hash)?;
        let bls_limbs = digest_to_field_limbs(&bls_hash)?;

        let elements = [
            PF::from_u64_value(DOMAIN_VALIDATOR_LEAF_FELT),
            PF::from_u64_value(self.validator_user_id),
            PF::from_u64_value(node_limbs[0]),
            PF::from_u64_value(node_limbs[1]),
            PF::from_u64_value(node_limbs[2]),
            PF::from_u64_value(node_limbs[3]),
            PF::from_u64_value(bls_limbs[0]),
            PF::from_u64_value(bls_limbs[1]),
            PF::from_u64_value(bls_limbs[2]),
            PF::from_u64_value(bls_limbs[3]),
        ];
        let hash: PHash = PoseidonHasher::q_hash_many(&elements);
        Ok(hash.to_le_bytes())
    }

    #[inline]
    pub fn tree_index(realm_id: u32, realm_sub_id: u16) -> ProtocolResult<u64> {
        if realm_sub_id > u8::MAX as u16 {
            return Err(ProtocolError::Message(
                "realm_sub_id exceeds 8-bit validator-tree range",
            ));
        }
        Ok(((realm_id as u64) << 8) | realm_sub_id as u64)
    }
}

impl ProtocolEncode for ValidatorLeaf {
    fn protocol_encode(&self, out: &mut Vec<u8>) {
        write_u64(out, self.validator_user_id);
        self.node_id.protocol_encode(out);
        self.bls_public_key.protocol_encode(out);
    }
}

#[cfg(test)]
mod tests {
    use super::super::bls::BlsSecretKey;
    use super::super::codec::GOLDILOCKS_MODULUS;
    use super::*;
    use libp2p_identity::Keypair;
    use rand::RngCore;

    fn sample_ed25519_keypair() -> Keypair {
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        Keypair::ed25519_from_bytes(&mut secret).expect("32-byte seed yields Ed25519 Keypair")
    }

    fn sample_leaf() -> ValidatorLeaf {
        for i in 0u8..32 {
            let mut seed = [11u8; 32];
            seed[0] = i;
            let bls = BlsSecretKey::key_gen(&seed).unwrap().public_key();
            let node = NodeId::from_keypair(&sample_ed25519_keypair()).unwrap();
            let leaf = ValidatorLeaf::new(42, node, bls);
            if leaf.leaf_hash().is_ok() {
                return leaf;
            }
        }
        panic!("failed to sample leaf with field-canonical digests");
    }

    #[test]
    fn leaf_hash_deterministic_32_bytes() {
        let leaf = sample_leaf();
        let h1 = leaf.leaf_hash().unwrap();
        let h2 = leaf.leaf_hash().unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
        for i in 0..4 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&h1[i * 8..(i + 1) * 8]);
            assert!(u64::from_le_bytes(b) < GOLDILOCKS_MODULUS);
        }
    }

    #[test]
    fn construction_bytes_domain_prefix() {
        let leaf = sample_leaf();
        assert_eq!(&leaf.construction_bytes(1, 2, 3)[..8], b"PSYVLF01");
    }

    #[test]
    fn tree_index_and_payload_roundtrip() {
        assert_eq!(ValidatorLeaf::tree_index(1, 2).unwrap(), (1u64 << 8) | 2);
        assert!(ValidatorLeaf::tree_index(0, 256).is_err());
        let leaf = sample_leaf();
        let enc = leaf.protocol_encode_to_vec();
        let dec = super::super::codec::decode_exact(&enc, ValidatorLeaf::protocol_decode).unwrap();
        assert_eq!(dec, leaf);
    }
}