//! Frozen Phase 1 protocol limits and runtime constants.

/// Gossipsub envelope maximum transmit size.
pub const GOSSIPSUB_MAX_TRANSMIT_SIZE: usize = 65_536;

/// Maximum Proposal chunk payload bytes (60 KiB).
pub const MAX_PROPOSAL_CHUNK_BYTES: usize = 61_440;

/// Exact finalizer public-output encoding length.
pub const MAX_FINALIZER_OUTPUT_BYTES: usize = 410;

/// Maximum finalizer proof bytes (256 KiB).
pub const MAX_FINALIZER_PROOF_BYTES: usize = 262_144;

/// Maximum current Realm backup bytes (100 MiB).
pub const MAX_BACKUP_BYTES: usize = 104_857_600;

/// Maximum proposal body size:
/// three u32 length prefixes plus output, proof, and backup maxima.
pub const MAX_PROPOSAL_BODY_BYTES: usize =
    3 * 4 + MAX_FINALIZER_OUTPUT_BYTES + MAX_FINALIZER_PROOF_BYTES + MAX_BACKUP_BYTES;

/// `ceil(MAX_PROPOSAL_BODY_BYTES / MAX_PROPOSAL_CHUNK_BYTES)`.
pub const MAX_PROPOSAL_PARTS: u32 =
    MAX_PROPOSAL_BODY_BYTES.div_ceil(MAX_PROPOSAL_CHUNK_BYTES) as u32;

/// Maximum direct body-range response payload.
pub const DIRECT_REQUEST_MAX_BYTES: u32 = 61_440;

/// Maximum EndCap forward stream total (header + input + proof).
pub const MAX_END_CAP_FORWARD_BYTES: usize = 536_870_912;

/// Fixed Proposal metadata wire length (218 bytes).
pub const PROPOSAL_WIRE_BYTES: usize = 218;

/// Fixed Vote wire length.
pub const VOTE_WIRE_BYTES: usize = 130;

/// Fixed Certificate wire length.
pub const CERTIFICATE_WIRE_BYTES: usize = 208;

/// Fixed Realm finalize-submit prefix before the variable proof section:
/// `output[410] || Proposal[218] || Certificate[208]`.
pub const REALM_FINALIZE_SUBMIT_PREFIX_WIRE_BYTES: usize =
    MAX_FINALIZER_OUTPUT_BYTES + PROPOSAL_WIRE_BYTES + CERTIFICATE_WIRE_BYTES;

/// Minimum Realm finalize-submit request length:
/// prefix + `proof_len(4) + 1 proof byte`.
pub const REALM_FINALIZE_SUBMIT_MIN_REQUEST_BYTES: usize =
    REALM_FINALIZE_SUBMIT_PREFIX_WIRE_BYTES + 4 + 1;

/// Maximum Realm finalize-submit request length:
/// prefix + `proof_len(4) + MAX_FINALIZER_PROOF_BYTES`.
pub const REALM_FINALIZE_SUBMIT_MAX_REQUEST_BYTES: usize =
    REALM_FINALIZE_SUBMIT_PREFIX_WIRE_BYTES + 4 + MAX_FINALIZER_PROOF_BYTES;

/// Exact Realm finalize-submit response length.
pub const REALM_FINALIZE_SUBMIT_RESPONSE_WIRE_BYTES: usize = 1;

/// Fixed DirectBodyRequest wire length.
pub const DIRECT_BODY_REQUEST_WIRE_BYTES: usize = 44;

/// EndCapForwardHeader wire length (56 bytes):
/// `chain_id(4) + realm_id(4) + checkpoint_id(8) + end_cap_id(32)
/// + end_cap_input_len(4) + proof_len(4)`.
pub const END_CAP_FORWARD_HEADER_WIRE_BYTES: usize = 56;

/// Exact one-byte EndCapForwardResponse status length.
pub const END_CAP_FORWARD_RESPONSE_WIRE_BYTES: usize = 1;

/// NodeId raw multihash value length (Ed25519 identity multihash).
pub const NODE_ID_RAW_LEN: usize = 38;

/// NodeId protocol_encode length: `u32_le(38) || raw`.
pub const NODE_ID_ENCODED_LEN: usize = 4 + NODE_ID_RAW_LEN;

/// BLS min-pk compressed public key length.
pub const BLS_PUBLIC_KEY_LEN: usize = 48;

/// BLS min-pk compressed signature length.
pub const BLS_SIGNATURE_LEN: usize = 96;

/// BLS secret key scalar length.
pub const BLS_SECRET_KEY_LEN: usize = 32;

/// Maximum occupied validators per Realm.
pub const MAX_VALIDATORS_PER_REALM: usize = 64;

/// Minimum occupied validators per Realm.
pub const MIN_VALIDATORS_PER_REALM: usize = 1;

/// Maximum in-flight proposals retained per Realm.
pub const MAX_IN_FLIGHT_PROPOSALS: usize = 2;

/// Maximum concurrent direct body exchanges.
pub const MAX_CONCURRENT_DIRECT_EXCHANGES: usize = 64;

/// Direct request exchange timeout (seconds).
pub const DIRECT_REQUEST_TIMEOUT_SECS: u64 = 30;

/// Proposal reassembly timeout (seconds).
pub const PROPOSAL_REASSEMBLY_TIMEOUT_SECS: u64 = 1_800;

/// Maintenance tick interval (seconds).
pub const MAINTENANCE_TICK_SECS: u64 = 5;

/// Range-request retry interval (seconds).
pub const RANGE_REQUEST_RETRY_INTERVAL_SECS: u64 = 5;

/// EndCap forward timeout (seconds).
pub const END_CAP_FORWARD_TIMEOUT_SECS: u64 = 1_800;

/// Realm finalize submission timeout (seconds).
pub const REALM_FINALIZE_SUBMIT_TIMEOUT_SECS: u64 = 120;

/// Maximum concurrent Realm finalize submissions.
pub const MAX_CONCURRENT_REALM_FINALIZE_SUBMITS: usize = 8;

/// Replication threshold: `ceil(n / 2)`.
#[inline]
pub const fn replication_threshold(n: usize) -> usize {
    n.div_ceil(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposal_body_and_parts_match_spec() {
        assert_eq!(MAX_PROPOSAL_BODY_BYTES, 105_120_166);
        assert_eq!(MAX_PROPOSAL_PARTS, 1_711);
        assert_eq!(PROPOSAL_WIRE_BYTES, 218);
        assert_eq!(VOTE_WIRE_BYTES, 130);
        assert_eq!(CERTIFICATE_WIRE_BYTES, 208);
        assert_eq!(END_CAP_FORWARD_HEADER_WIRE_BYTES, 56);
        assert_eq!(REALM_FINALIZE_SUBMIT_PREFIX_WIRE_BYTES, 836);
        assert_eq!(replication_threshold(1), 1);
        assert_eq!(replication_threshold(2), 1);
        assert_eq!(replication_threshold(3), 2);
        assert_eq!(replication_threshold(4), 2);
    }
}
