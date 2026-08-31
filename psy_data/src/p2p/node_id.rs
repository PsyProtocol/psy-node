//! Ed25519 libp2p `NodeId` (protocol name for PeerId).

use super::codec::{write_u32, ProtocolEncode, ProtocolReader};
use super::error::{ProtocolError, ProtocolResult};
use super::limits::{NODE_ID_ENCODED_LEN, NODE_ID_RAW_LEN};
use libp2p_identity::{Keypair, PeerId, PublicKey};

/// Fixed 38-byte raw multihash value of an Ed25519 libp2p identity.
///
/// Wire encoding is `u32_le(38) || raw_value` (42 bytes total).
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct NodeId {
    raw: [u8; NODE_ID_RAW_LEN],
}

impl std::fmt::Debug for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NodeId({})", self.to_base58())
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_base58())
    }
}

impl NodeId {
    /// Construct from a validated raw 38-byte multihash value.
    pub fn from_raw(raw: [u8; NODE_ID_RAW_LEN]) -> ProtocolResult<Self> {
        validate_ed25519_identity_multihash(&raw)?;
        // Round-trip through PeerId to reject malformed multihashes.
        let peer = PeerId::from_bytes(&raw).map_err(|_| ProtocolError::InvalidNodeId {
            reason: "PeerId::from_bytes rejected multihash",
        })?;
        let rebuilt = peer_id_to_raw38(&peer)?;
        if rebuilt != raw {
            return Err(ProtocolError::InvalidNodeId {
                reason: "non-canonical PeerId encoding",
            });
        }
        Ok(Self { raw })
    }

    /// Construct from a libp2p `PeerId`, requiring the Ed25519 identity multihash form.
    pub fn from_peer_id(peer_id: &PeerId) -> ProtocolResult<Self> {
        let raw = peer_id_to_raw38(peer_id)?;
        Self::from_raw(raw)
    }

    /// Construct from a libp2p public key (must be Ed25519).
    pub fn from_public_key(public_key: &PublicKey) -> ProtocolResult<Self> {
        if public_key.key_type() != libp2p_identity::KeyType::Ed25519 {
            return Err(ProtocolError::InvalidNodeId {
                reason: "public key is not Ed25519",
            });
        }
        Self::from_peer_id(&public_key.to_peer_id())
    }

    /// Construct from a keypair (must be Ed25519).
    pub fn from_keypair(keypair: &Keypair) -> ProtocolResult<Self> {
        Self::from_public_key(&keypair.public())
    }

    /// Decode the protocol wire form `u32_le(38) || raw38` and reject trailing bytes when
    /// `exact` is used by the caller via [`ProtocolReader::finish`].
    pub fn protocol_decode(reader: &mut ProtocolReader<'_>) -> ProtocolResult<Self> {
        let len = reader.read_u32()?;
        if len as usize != NODE_ID_RAW_LEN {
            return Err(ProtocolError::InvalidLength {
                what: "NodeId raw length prefix",
                got: len as usize,
                expected: NODE_ID_RAW_LEN,
            });
        }
        let raw = reader.read_fixed::<NODE_ID_RAW_LEN>()?;
        Self::from_raw(raw)
    }

    /// Decode an entire buffer that contains exactly one encoded `NodeId`.
    pub fn decode_exact(bytes: &[u8]) -> ProtocolResult<Self> {
        super::codec::decode_exact(bytes, Self::protocol_decode)
    }

    /// Borrow the fixed 38-byte raw multihash value.
    #[inline]
    pub fn as_raw(&self) -> &[u8; NODE_ID_RAW_LEN] {
        &self.raw
    }

    /// Copy the fixed 38-byte raw multihash value.
    #[inline]
    pub fn to_raw(&self) -> [u8; NODE_ID_RAW_LEN] {
        self.raw
    }

    /// Convert to the underlying libp2p `PeerId`.
    pub fn to_peer_id(&self) -> PeerId {
        PeerId::from_bytes(&self.raw).expect("NodeId raw value is a validated PeerId encoding")
    }

    /// Recover the Ed25519 public key embedded in this identity-multihash NodeId.
    pub fn ed25519_public_key(&self) -> ProtocolResult<PublicKey> {
        let key = libp2p_identity::ed25519::PublicKey::try_from_bytes(&self.raw[6..])
            .map_err(|_| ProtocolError::InvalidNodeId {
                reason: "embedded Ed25519 public key is invalid",
            })?;
        Ok(PublicKey::from(key))
    }

    /// Base58 text form (libp2p conventional display).
    pub fn to_base58(&self) -> String {
        self.to_peer_id().to_base58()
    }

    /// Encoded wire length (`4 + 38`).
    #[inline]
    pub const fn encoded_len() -> usize {
        NODE_ID_ENCODED_LEN
    }
}

impl ProtocolEncode for NodeId {
    fn protocol_encode(&self, out: &mut Vec<u8>) {
        write_u32(out, NODE_ID_RAW_LEN as u32);
        out.extend_from_slice(&self.raw);
    }
}

impl From<NodeId> for PeerId {
    fn from(value: NodeId) -> Self {
        value.to_peer_id()
    }
}

impl TryFrom<PeerId> for NodeId {
    type Error = ProtocolError;

    fn try_from(value: PeerId) -> Result<Self, Self::Error> {
        Self::from_peer_id(&value)
    }
}

impl TryFrom<&PeerId> for NodeId {
    type Error = ProtocolError;

    fn try_from(value: &PeerId) -> Result<Self, Self::Error> {
        Self::from_peer_id(value)
    }
}

fn peer_id_to_raw38(peer_id: &PeerId) -> ProtocolResult<[u8; NODE_ID_RAW_LEN]> {
    let bytes = peer_id.to_bytes();
    if bytes.len() != NODE_ID_RAW_LEN {
        return Err(ProtocolError::InvalidNodeId {
            reason: "PeerId byte length is not 38 (Phase 1 requires Ed25519 identity multihash)",
        });
    }
    let mut raw = [0u8; NODE_ID_RAW_LEN];
    raw.copy_from_slice(&bytes);
    validate_ed25519_identity_multihash(&raw)?;
    Ok(raw)
}

/// Ed25519 identity multihash layout:
/// `0x00` (identity) || `0x24` (36-byte digest) || protobuf(PublicKey{type=Ed25519, data=32})
/// where protobuf is `0x08 0x01 0x12 0x20 || pk32`.
fn validate_ed25519_identity_multihash(raw: &[u8; NODE_ID_RAW_LEN]) -> ProtocolResult<()> {
    // multihash header
    if raw[0] != 0x00 {
        return Err(ProtocolError::InvalidNodeId {
            reason: "NodeId multihash code is not identity (0x00)",
        });
    }
    if raw[1] != 0x24 {
        return Err(ProtocolError::InvalidNodeId {
            reason: "NodeId multihash digest length is not 0x24",
        });
    }
    // protobuf PublicKey
    if raw[2] != 0x08 || raw[3] != 0x01 {
        return Err(ProtocolError::InvalidNodeId {
            reason: "NodeId key type is not protobuf Ed25519 (field1=1)",
        });
    }
    if raw[4] != 0x12 || raw[5] != 0x20 {
        return Err(ProtocolError::InvalidNodeId {
            reason: "NodeId protobuf public-key data field is not 32 bytes",
        });
    }
    // Remaining 32 bytes are the raw Ed25519 public key; PeerId round-trip validates them.
    let _ = &raw[6..38];
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::codec::ProtocolEncode;
    use super::*;
    use rand::RngCore;

    fn sample_ed25519_keypair() -> Keypair {
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        Keypair::ed25519_from_bytes(&mut secret).expect("32-byte seed yields Ed25519 Keypair")
    }

    #[test]
    fn ed25519_node_id_is_38_bytes_and_encodes_with_length_prefix() {
        let kp = sample_ed25519_keypair();
        let node = NodeId::from_keypair(&kp).expect("ed25519 keypair yields NodeId");
        assert_eq!(node.as_raw().len(), 38);
        assert_eq!(node.as_raw()[0], 0x00);
        assert_eq!(node.as_raw()[1], 0x24);
        assert_eq!(node.as_raw()[2], 0x08);
        assert_eq!(node.as_raw()[3], 0x01);
        assert_eq!(node.as_raw()[4], 0x12);
        assert_eq!(node.as_raw()[5], 0x20);

        let encoded = node.protocol_encode_to_vec();
        assert_eq!(encoded.len(), NODE_ID_ENCODED_LEN);
        assert_eq!(&encoded[..4], &38u32.to_le_bytes());
        assert_eq!(&encoded[4..], node.as_raw());

        let decoded = NodeId::decode_exact(&encoded).unwrap();
        assert_eq!(decoded, node);
        assert_eq!(decoded.to_peer_id(), kp.public().to_peer_id());

        assert!(node.ed25519_public_key().unwrap().verify(b"edge-delegation", &kp.sign(b"edge-delegation").unwrap()));
    }

    #[test]
    fn rejects_wrong_length_prefix() {
        let kp = sample_ed25519_keypair();
        let node = NodeId::from_keypair(&kp).unwrap();
        let mut bad = Vec::new();
        write_u32(&mut bad, 37);
        bad.extend_from_slice(&node.as_raw()[..37]);
        let err = NodeId::decode_exact(&bad).unwrap_err();
        assert!(matches!(
            err,
            ProtocolError::InvalidLength {
                expected: 38,
                ..
            }
        ));
    }

    #[test]
    fn rejects_non_ed25519_key_type_bytes() {
        // identity multihash with RSA key type tag (0)
        let mut raw = [0u8; 38];
        raw[0] = 0x00;
        raw[1] = 0x24;
        raw[2] = 0x08;
        raw[3] = 0x00; // RSA
        raw[4] = 0x12;
        raw[5] = 0x20;
        let err = NodeId::from_raw(raw).unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidNodeId { .. }));
    }

    #[test]
    fn distinct_keypairs_yield_distinct_node_ids_and_round_trip_via_peer_id() {
        let a = sample_ed25519_keypair();
        let b = sample_ed25519_keypair();
        let node_a = NodeId::from_keypair(&a).unwrap();
        let node_b = NodeId::from_keypair(&b).unwrap();
        assert_ne!(node_a, node_b);
        assert_ne!(node_a.to_peer_id(), b.public().to_peer_id());
        // Source mismatch: a NodeId derived from keypair A must NOT match a
        // peer identity built from keypair B.
        assert!(NodeId::from_peer_id(&b.public().to_peer_id()).unwrap() != node_a);
        // Round-trip PeerId -> NodeId -> PeerId is stable.
        assert_eq!(NodeId::from_peer_id(&node_a.to_peer_id()).unwrap(), node_a);
    }

    #[test]
    fn rejects_sha256_multihash_code_instead_of_identity() {
        // A SHA-2-256 multihash (code 0x12) is a valid PeerId encoding but is
        // NOT an Ed25519 identity multihash — must be rejected.
        let mut raw = [0u8; 38];
        raw[0] = 0x12; // sha2-256 multihash code (not identity 0x00)
        raw[1] = 0x20; // 32-byte digest length
        assert!(NodeId::from_raw(raw).is_err());
    }

    #[test]
    fn rejects_wrong_multihash_digest_length() {
        // identity multihash must declare a 0x24 (36-byte) digest; a 0x20
        // (32-byte) digest length is rejected even if the key-type tag is Ed25519.
        let mut raw = [0u8; 38];
        raw[0] = 0x00; // identity code
        raw[1] = 0x20; // wrong digest length
        raw[2] = 0x08;
        raw[3] = 0x01; // Ed25519 key type tag
        raw[4] = 0x12;
        raw[5] = 0x20;
        assert!(NodeId::from_raw(raw).is_err());
    }

    #[test]
    fn protocol_decode_rejects_trailing_bytes_and_wrong_length_prefix() {
        let kp = sample_ed25519_keypair();
        let node = NodeId::from_keypair(&kp).unwrap();
        let mut trailing = node.protocol_encode_to_vec();
        trailing.push(0xff);
        assert!(NodeId::decode_exact(&trailing).is_err());
        // A length prefix claiming 39 bytes is rejected even if enough bytes follow.
        let mut bad = Vec::new();
        write_u32(&mut bad, NODE_ID_RAW_LEN as u32 + 1);
        bad.extend_from_slice(node.as_raw());
        assert!(NodeId::decode_exact(&bad).is_err());
    }
}
