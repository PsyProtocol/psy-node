//! Frozen protocol domain separation tags (exactly 8 bytes each).

/// Validator leaf record / Poseidon domain (`PSYVLF01`).
pub const DOMAIN_VALIDATOR_LEAF: [u8; 8] = *b"PSYVLF01";

/// Proposal identity domain (`PSYPRP01`).
pub const DOMAIN_PROPOSAL: [u8; 8] = *b"PSYPRP01";

/// Vote message domain (`PSYVOT01`).
pub const DOMAIN_VOTE: [u8; 8] = *b"PSYVOT01";

/// EndCap forward identity domain (`PSYECF01`).
pub const DOMAIN_END_CAP_FORWARD: [u8; 8] = *b"PSYECF01";

/// `DOMAIN_VALIDATOR_LEAF` interpreted as little-endian `u64` for Poseidon.
pub const DOMAIN_VALIDATOR_LEAF_FELT: u64 = u64::from_le_bytes(DOMAIN_VALIDATOR_LEAF);

/// IETF BLS12-381 min-pk ciphersuite DST for Vote signatures.
pub const VOTE_BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// IETF BLS12-381 min-pk proof-of-possession DST used only at genesis construction.
pub const PROOF_OF_POSSESSION_BLS_DST: &[u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
