//! Realm P2P protocol module.
//!
//! Frozen wire types, `protocol_encode`, Ed25519 `NodeId`, BLS12-381 min-pk
//! Vote crypto, domains, and limits. No serde/bincode protocol codecs.

pub mod bls;
pub mod codec;
pub mod domains;
pub mod end_cap;
pub mod error;
pub mod limits;
pub mod messages;
pub mod node_id;
pub mod validator_leaf;
pub mod validator_tree;

pub use bls::{
    aggregate_signatures, validate_key_with_proof_of_possession, BlsPublicKey, BlsSecretKey,
    BlsSignature,
};
pub use codec::{
    decode_exact, digest_to_field_limbs, field_from_le_bytes, sha256, validate_goldilocks_limb,
    validate_hash32_canonical, write_bool, write_bytes_u32, write_fixed, write_u16, write_u32,
    write_u64, write_u8, ProtocolEncode, ProtocolReader, GOLDILOCKS_MODULUS,
};
pub use domains::{
    DOMAIN_END_CAP_FORWARD, DOMAIN_PROPOSAL, DOMAIN_VALIDATOR_LEAF, DOMAIN_VALIDATOR_LEAF_FELT,
    DOMAIN_VOTE, PROOF_OF_POSSESSION_BLS_DST, VOTE_BLS_DST,
};
pub use end_cap::*;
pub use error::{ProtocolError, ProtocolResult};
pub use limits::*;
pub use messages::{
    bitmap_get, bitmap_set, compute_end_cap_id, compute_proposal_id, encode_proposal_body,
    proposal_from_parts, vote_message, Certificate, DirectBodyRequest, DirectBodyResponse,
    EndCapForwardHeader, EndCapForwardResponse, Proposal, ProposalPart, RealmFinalizeOutputBytes,
    RealmFinalizeSubmitCode, RealmFinalizeSubmitRequest, RealmFinalizeSubmitResponse, Vote,
};
pub use node_id::NodeId;
pub use validator_leaf::ValidatorLeaf;
pub use validator_tree::{
    authenticate_validator_preimage, build_validator_tree_genesis, empty_validator_tree_root,
    realm_validator_indexes, require_realm_validator_count, validator_tree_root_from_genesis,
    ValidatorLeafPreimage, ValidatorTreeGenesis,
};
