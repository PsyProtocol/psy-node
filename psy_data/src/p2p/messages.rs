//! Phase 1 consensus, direct-transfer, and Realm-finalize messages.
//!
//! Wire grammar follows `protocol_encode` (see [`super::codec`]):
//! - integers are fixed-width little-endian,
//! - `[u8; N]` is raw bytes with no length prefix,
//! - variable bytes are `u32_le(len) || bytes` with the frozen limit,
//! - enum tags are one `u8`,
//! - decoders reject unknown tags, invalid crypto encodings, out-of-limit
//!   lengths, and trailing bytes.

use super::bls::BlsSignature;
use super::codec::{
    decode_exact, sha256, validate_hash32_canonical, write_bool, write_bytes_u32, write_fixed,
    write_u16, write_u32, write_u64, write_u8, ProtocolEncode, ProtocolReader,
};
use super::domains::{DOMAIN_END_CAP_FORWARD, DOMAIN_PROPOSAL, DOMAIN_VOTE};
use super::error::{ProtocolError, ProtocolResult};
use super::limits::{
    CERTIFICATE_WIRE_BYTES, DIRECT_BODY_REQUEST_WIRE_BYTES, DIRECT_REQUEST_MAX_BYTES,
    END_CAP_FORWARD_HEADER_WIRE_BYTES, END_CAP_FORWARD_RESPONSE_WIRE_BYTES, MAX_BACKUP_BYTES,
    MAX_FINALIZER_OUTPUT_BYTES, MAX_FINALIZER_PROOF_BYTES, MAX_PROPOSAL_BODY_BYTES,
    MAX_PROPOSAL_CHUNK_BYTES, MAX_PROPOSAL_PARTS, PROPOSAL_WIRE_BYTES,
    VOTE_WIRE_BYTES,
};

/// Canonical fixed-size Realm finalizer public output (exactly 410 bytes).
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RealmFinalizeOutputBytes([u8; MAX_FINALIZER_OUTPUT_BYTES]);

impl RealmFinalizeOutputBytes {
    /// Exact wire length.
    pub const WIRE_BYTES: usize = MAX_FINALIZER_OUTPUT_BYTES;

    pub fn new(bytes: [u8; MAX_FINALIZER_OUTPUT_BYTES]) -> Self {
        Self(bytes)
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8; MAX_FINALIZER_OUTPUT_BYTES] {
        &self.0
    }

    #[inline]
    pub fn to_bytes(&self) -> [u8; MAX_FINALIZER_OUTPUT_BYTES] {
        self.0
    }

    pub fn protocol_decode(reader: &mut ProtocolReader<'_>) -> ProtocolResult<Self> {
        Ok(Self(reader.read_fixed::<MAX_FINALIZER_OUTPUT_BYTES>()?))
    }

    pub fn decode_exact(bytes: &[u8]) -> ProtocolResult<Self> {
        decode_exact(bytes, Self::protocol_decode)
    }
}

impl TryFrom<Vec<u8>> for RealmFinalizeOutputBytes {
    type Error = ProtocolError;

    fn try_from(bytes: Vec<u8>) -> ProtocolResult<Self> {
        if bytes.len() != MAX_FINALIZER_OUTPUT_BYTES {
            return Err(ProtocolError::InvalidLength {
                what: "RealmFinalizeOutputBytes",
                got: bytes.len(),
                expected: MAX_FINALIZER_OUTPUT_BYTES,
            });
        }
        let mut arr = [0u8; MAX_FINALIZER_OUTPUT_BYTES];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl AsRef<[u8]> for RealmFinalizeOutputBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl ProtocolEncode for RealmFinalizeOutputBytes {
    fn protocol_encode(&self, out: &mut Vec<u8>) {
        write_fixed(out, &self.0);
    }
}

/// Pre-commit Proposal metadata (exactly 214 wire bytes).
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Proposal {
    pub chain_id: u64,
    pub realm_id: u32,
    pub base_checkpoint_id: u64,
    pub proposer_sub_id: u16,
    pub validator_tree_root: [u8; 32],
    pub proposal_id: [u8; 32],
    pub public_output_hash: [u8; 32],
    pub finalizer_proof_hash: [u8; 32],
    pub backup_hash: [u8; 32],
    pub body_hash: [u8; 32],
}

impl Proposal {
    /// Exact wire length (214 bytes).
    pub const WIRE_BYTES: usize = PROPOSAL_WIRE_BYTES;

    pub fn protocol_decode(reader: &mut ProtocolReader<'_>) -> ProtocolResult<Self> {
        Ok(Self {
            chain_id: reader.read_u64()?,
            realm_id: reader.read_u32()?,
            base_checkpoint_id: reader.read_u64()?,
            proposer_sub_id: reader.read_u16()?,
            validator_tree_root: reader.read_bytes_32()?,
            proposal_id: reader.read_bytes_32()?,
            public_output_hash: reader.read_bytes_32()?,
            finalizer_proof_hash: reader.read_bytes_32()?,
            backup_hash: reader.read_bytes_32()?,
            body_hash: reader.read_bytes_32()?,
        })
    }

    pub fn decode_exact(bytes: &[u8]) -> ProtocolResult<Self> {
        decode_exact(bytes, Self::protocol_decode)
    }

    /// Recompute `proposal_id` from the canonical fields.
    pub fn compute_proposal_id(&self) -> [u8; 32] {
        compute_proposal_id(
            self.chain_id,
            self.realm_id,
            self.base_checkpoint_id,
            self.proposer_sub_id,
            &self.validator_tree_root,
            &self.public_output_hash,
            &self.finalizer_proof_hash,
            &self.backup_hash,
            &self.body_hash,
        )
    }
}

impl ProtocolEncode for Proposal {
    fn protocol_encode(&self, out: &mut Vec<u8>) {
        write_u64(out, self.chain_id);
        write_u32(out, self.realm_id);
        write_u64(out, self.base_checkpoint_id);
        write_u16(out, self.proposer_sub_id);
        write_fixed(out, &self.validator_tree_root);
        write_fixed(out, &self.proposal_id);
        write_fixed(out, &self.public_output_hash);
        write_fixed(out, &self.finalizer_proof_hash);
        write_fixed(out, &self.backup_hash);
        write_fixed(out, &self.body_hash);
    }
}

/// `proposal_id = SHA-256(protocol_encode(DOMAIN_PROPOSAL, chain_id, realm_id,
///     base_checkpoint_id, proposer_sub_id, validator_tree_root,
///     public_output_hash, finalizer_proof_hash, backup_hash, body_hash))`.
pub fn compute_proposal_id(
    chain_id: u64,
    realm_id: u32,
    base_checkpoint_id: u64,
    proposer_sub_id: u16,
    validator_tree_root: &[u8; 32],
    public_output_hash: &[u8; 32],
    finalizer_proof_hash: &[u8; 32],
    backup_hash: &[u8; 32],
    body_hash: &[u8; 32],
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(8 + 8 + 4 + 8 + 2 + 5 * 32);
    write_fixed(&mut buf, &DOMAIN_PROPOSAL);
    write_u64(&mut buf, chain_id);
    write_u32(&mut buf, realm_id);
    write_u64(&mut buf, base_checkpoint_id);
    write_u16(&mut buf, proposer_sub_id);
    write_fixed(&mut buf, validator_tree_root);
    write_fixed(&mut buf, public_output_hash);
    write_fixed(&mut buf, finalizer_proof_hash);
    write_fixed(&mut buf, backup_hash);
    write_fixed(&mut buf, body_hash);
    sha256(&buf)
}

/// Construct a `Proposal` with its canonical `proposal_id` computed.
pub fn proposal_from_parts(
    chain_id: u64,
    realm_id: u32,
    base_checkpoint_id: u64,
    proposer_sub_id: u16,
    validator_tree_root: [u8; 32],
    public_output_hash: [u8; 32],
    finalizer_proof_hash: [u8; 32],
    backup_hash: [u8; 32],
    body_hash: [u8; 32],
) -> Proposal {
    let proposal_id = compute_proposal_id(
        chain_id,
        realm_id,
        base_checkpoint_id,
        proposer_sub_id,
        &validator_tree_root,
        &public_output_hash,
        &finalizer_proof_hash,
        &backup_hash,
        &body_hash,
    );
    Proposal {
        chain_id,
        realm_id,
        base_checkpoint_id,
        proposer_sub_id,
        validator_tree_root,
        proposal_id,
        public_output_hash,
        finalizer_proof_hash,
        backup_hash,
        body_hash,
    }
}

/// Encode the proposal body: `u32_le(410) || output || u32_le(proof) || proof
/// || u32_le(state_updates) || state_updates || worker_tag[32]`.
///
/// `finalizer_output` must be exactly 410 bytes; `finalizer_proof` and
/// `state_updates` must not exceed their frozen maxima. `state_updates` is
/// the canonical encoding of `PsyPreparedRealmBlockStateUpdates`. The trailing
/// 32-byte finalizer worker reward tag lets every validator recompute the
/// circuit reward root R63 from the actual output before voting.
pub fn encode_proposal_body(
    finalizer_output: &[u8],
    finalizer_proof: &[u8],
    state_updates: &[u8],
    finalizer_worker_tag: &[u8; 32],
) -> ProtocolResult<Vec<u8>> {
    if finalizer_output.len() != MAX_FINALIZER_OUTPUT_BYTES {
        return Err(ProtocolError::InvalidLength {
            what: "finalizer output",
            got: finalizer_output.len(),
            expected: MAX_FINALIZER_OUTPUT_BYTES,
        });
    }
    if finalizer_proof.len() > MAX_FINALIZER_PROOF_BYTES {
        return Err(ProtocolError::LengthLimit {
            what: "finalizer proof",
            got: finalizer_proof.len() as u64,
            max: MAX_FINALIZER_PROOF_BYTES as u64,
        });
    }
    if state_updates.len() > MAX_BACKUP_BYTES {
        return Err(ProtocolError::LengthLimit {
            what: "state updates",
            got: state_updates.len() as u64,
            max: MAX_BACKUP_BYTES as u64,
        });
    }
    let mut body = Vec::with_capacity(
        3 * 4 + 32 + finalizer_output.len() + finalizer_proof.len() + state_updates.len(),
    );
    write_bytes_u32(&mut body, finalizer_output)?;
    write_bytes_u32(&mut body, finalizer_proof)?;
    write_bytes_u32(&mut body, state_updates)?;
    body.extend_from_slice(finalizer_worker_tag);
    Ok(body)
}

/// Strictly decode a proposal body into `(output, proof, state_updates,
/// worker_tag)` with exact component limits and no trailing bytes.
pub fn decode_proposal_body(body: &[u8]) -> ProtocolResult<(Vec<u8>, Vec<u8>, Vec<u8>, [u8; 32])> {
    decode_exact(body, |reader| {
        let output = reader.read_bytes_u32("finalizer output", MAX_FINALIZER_OUTPUT_BYTES as u32)?;
        if output.len() != MAX_FINALIZER_OUTPUT_BYTES {
            return Err(ProtocolError::InvalidLength {
                what: "finalizer output",
                got: output.len(),
                expected: MAX_FINALIZER_OUTPUT_BYTES,
            });
        }
        let proof = reader.read_bytes_u32("finalizer proof", MAX_FINALIZER_PROOF_BYTES as u32)?;
        let state_updates = reader.read_bytes_u32("state updates", MAX_BACKUP_BYTES as u32)?;
        let worker_tag = reader.read_fixed::<32>()?;
        validate_hash32_canonical(&worker_tag)?;
        Ok((output, proof, state_updates, worker_tag))
    })
}


/// Chunked Proposal gossip frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProposalPart {
    /// Full metadata plus reassembly bounds (`Start` tag 0).
    Start {
        proposal: Proposal,
        total_parts: u32,
        body_len: u64,
    },
    /// One byte-range of the proposal body (`Chunk` tag 1).
    Chunk {
        proposal_id: [u8; 32],
        offset: u64,
        data: Vec<u8>,
    },
}

impl ProposalPart {
    pub const TAG_START: u8 = 0;
    pub const TAG_CHUNK: u8 = 1;

    pub fn protocol_decode(reader: &mut ProtocolReader<'_>) -> ProtocolResult<Self> {
        match reader.read_u8()? {
            Self::TAG_START => {
                let proposal = Proposal::protocol_decode(reader)?;
                let total_parts = reader.read_u32()?;
                if total_parts == 0 {
                    return Err(ProtocolError::Message(
                        "ProposalPart::Start total_parts must be at least 1",
                    ));
                }
                if total_parts > MAX_PROPOSAL_PARTS {
                    return Err(ProtocolError::LengthLimit {
                        what: "ProposalPart::Start total_parts",
                        got: total_parts as u64,
                        max: MAX_PROPOSAL_PARTS as u64,
                    });
                }
                let body_len = reader.read_u64()?;
                if body_len == 0 {
                    return Err(ProtocolError::Message(
                        "ProposalPart::Start body_len must be at least 1",
                    ));
                }
                if body_len > MAX_PROPOSAL_BODY_BYTES as u64 {
                    return Err(ProtocolError::LengthLimit {
                        what: "ProposalPart::Start body_len",
                        got: body_len,
                        max: MAX_PROPOSAL_BODY_BYTES as u64,
                    });
                }
                Ok(ProposalPart::Start {
                    proposal,
                    total_parts,
                    body_len,
                })
            }
            Self::TAG_CHUNK => {
                let proposal_id = reader.read_bytes_32()?;
                let offset = reader.read_u64()?;
                let data = reader.read_bytes_u32("chunk data", MAX_PROPOSAL_CHUNK_BYTES as u32)?;
                if data.is_empty() {
                    return Err(ProtocolError::Message(
                        "ProposalPart::Chunk data must not be empty",
                    ));
                }
                Ok(ProposalPart::Chunk {
                    proposal_id,
                    offset,
                    data,
                })
            }
            tag => Err(ProtocolError::UnknownTag {
                ty: "ProposalPart",
                tag,
            }),
        }
    }

    pub fn decode_exact(bytes: &[u8]) -> ProtocolResult<Self> {
        decode_exact(bytes, Self::protocol_decode)
    }
}

impl ProtocolEncode for ProposalPart {
    fn protocol_encode(&self, out: &mut Vec<u8>) {
        match self {
            ProposalPart::Start {
                proposal,
                total_parts,
                body_len,
            } => {
                write_u8(out, Self::TAG_START);
                proposal.protocol_encode(out);
                write_u32(out, *total_parts);
                write_u64(out, *body_len);
            }
            ProposalPart::Chunk {
                proposal_id,
                offset,
                data,
            } => {
                write_u8(out, Self::TAG_CHUNK);
                write_fixed(out, proposal_id);
                write_u64(out, *offset);
                debug_assert!(data.len() <= MAX_PROPOSAL_CHUNK_BYTES);
                write_u32(out, data.len() as u32);
                write_fixed(out, data);
            }
        }
    }
}

/// Vote wire object (exactly 130 bytes).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Vote {
    pub proposal_id: [u8; 32],
    pub signer_sub_id: u16,
    pub signature: BlsSignature,
}

impl Vote {
    /// Exact wire length (130 bytes).
    pub const WIRE_BYTES: usize = VOTE_WIRE_BYTES;

    pub fn new(proposal_id: [u8; 32], signer_sub_id: u16, signature: BlsSignature) -> Self {
        Self {
            proposal_id,
            signer_sub_id,
            signature,
        }
    }

    pub fn protocol_decode(reader: &mut ProtocolReader<'_>) -> ProtocolResult<Self> {
        Ok(Self {
            proposal_id: reader.read_bytes_32()?,
            signer_sub_id: reader.read_u16()?,
            signature: BlsSignature::protocol_decode(reader)?,
        })
    }

    pub fn decode_exact(bytes: &[u8]) -> ProtocolResult<Self> {
        decode_exact(bytes, Self::protocol_decode)
    }
}

impl ProtocolEncode for Vote {
    fn protocol_encode(&self, out: &mut Vec<u8>) {
        write_fixed(out, &self.proposal_id);
        write_u16(out, self.signer_sub_id);
        self.signature.protocol_encode(out);
    }
}

/// `vote_message = protocol_encode(DOMAIN_VOTE, chain_id, realm_id,
///     validator_tree_root, proposal_id)`.
pub fn vote_message(
    chain_id: u64,
    realm_id: u32,
    validator_tree_root: &[u8; 32],
    proposal_id: &[u8; 32],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + 8 + 4 + 32 + 32);
    write_fixed(&mut buf, &DOMAIN_VOTE);
    write_u64(&mut buf, chain_id);
    write_u32(&mut buf, realm_id);
    write_fixed(&mut buf, validator_tree_root);
    write_fixed(&mut buf, proposal_id);
    buf
}

/// Certificate wire object (exactly 204 bytes).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Certificate {
    pub chain_id: u64,
    pub realm_id: u32,
    pub validator_tree_root: [u8; 32],
    pub proposal_id: [u8; 32],
    /// Bit `s` <=> `realm_sub_id = s` signed.
    pub signer_bitmap: [u8; 32],
    pub aggregated_signature: BlsSignature,
}

impl Certificate {
    /// Exact wire length (204 bytes).
    pub const WIRE_BYTES: usize = CERTIFICATE_WIRE_BYTES;

    /// Number of set signer bits.
    pub fn popcount(&self) -> usize {
        self.signer_bitmap
            .iter()
            .map(|byte| byte.count_ones() as usize)
            .sum()
    }

    /// Ascending set `realm_sub_id`s.
    pub fn signer_sub_ids(&self) -> Vec<u16> {
        let mut out = Vec::new();
        for sub_id in 0u16..256 {
            if bitmap_get(&self.signer_bitmap, sub_id) {
                out.push(sub_id);
            }
        }
        out
    }

    /// The exact signed message for this Certificate's signers.
    pub fn vote_message(&self) -> Vec<u8> {
        vote_message(
            self.chain_id,
            self.realm_id,
            &self.validator_tree_root,
            &self.proposal_id,
        )
    }

    pub fn protocol_decode(reader: &mut ProtocolReader<'_>) -> ProtocolResult<Self> {
        Ok(Self {
            chain_id: reader.read_u64()?,
            realm_id: reader.read_u32()?,
            validator_tree_root: reader.read_bytes_32()?,
            proposal_id: reader.read_bytes_32()?,
            signer_bitmap: reader.read_bytes_32()?,
            aggregated_signature: BlsSignature::protocol_decode(reader)?,
        })
    }

    pub fn decode_exact(bytes: &[u8]) -> ProtocolResult<Self> {
        decode_exact(bytes, Self::protocol_decode)
    }
}

impl ProtocolEncode for Certificate {
    fn protocol_encode(&self, out: &mut Vec<u8>) {
        write_u64(out, self.chain_id);
        write_u32(out, self.realm_id);
        write_fixed(out, &self.validator_tree_root);
        write_fixed(out, &self.proposal_id);
        write_fixed(out, &self.signer_bitmap);
        self.aggregated_signature.protocol_encode(out);
    }
}


/// Stable one-byte Realm finalize submission result code (`Accepted = 0` ..
/// `Internal = 10`).
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RealmFinalizeSubmitCode {
    Accepted = 0,
    UnauthorizedSource = 1,
    NotScheduledProposer = 2,
    CheckpointUnavailable = 3,
    InvalidOutput = 4,
    InvalidProposal = 5,
    InvalidCertificate = 6,
    InvalidProof = 7,
    AlreadyClaimed = 8,
    Busy = 9,
    Internal = 10,
}

impl std::fmt::Display for RealmFinalizeSubmitCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Accepted => "accepted",
            Self::UnauthorizedSource => "unauthorized source",
            Self::NotScheduledProposer => "not scheduled proposer",
            Self::CheckpointUnavailable => "checkpoint unavailable",
            Self::InvalidOutput => "invalid output",
            Self::InvalidProposal => "invalid proposal",
            Self::InvalidCertificate => "invalid certificate",
            Self::InvalidProof => "invalid proof",
            Self::AlreadyClaimed => "already claimed",
            Self::Busy => "busy",
            Self::Internal => "internal",
        })
    }
}

impl RealmFinalizeSubmitCode {
    pub fn from_u8(value: u8) -> ProtocolResult<Self> {
        match value {
            0 => Ok(Self::Accepted),
            1 => Ok(Self::UnauthorizedSource),
            2 => Ok(Self::NotScheduledProposer),
            3 => Ok(Self::CheckpointUnavailable),
            4 => Ok(Self::InvalidOutput),
            5 => Ok(Self::InvalidProposal),
            6 => Ok(Self::InvalidCertificate),
            7 => Ok(Self::InvalidProof),
            8 => Ok(Self::AlreadyClaimed),
            9 => Ok(Self::Busy),
            10 => Ok(Self::Internal),
            tag => Err(ProtocolError::UnknownTag {
                ty: "RealmFinalizeSubmitCode",
                tag,
            }),
        }
    }
}


#[inline]
pub fn bitmap_get(bitmap: &[u8; 32], sub_id: u16) -> bool {
    let idx = sub_id as usize;
    if idx >= 256 {
        return false;
    }
    (bitmap[idx / 8] & (1u8 << (idx % 8))) != 0
}

#[inline]
pub fn bitmap_set(bitmap: &mut [u8; 32], sub_id: u16) {
    let idx = sub_id as usize;
    if idx >= 256 {
        return;
    }
    bitmap[idx / 8] |= 1u8 << (idx % 8);
}

/// Direct proposal-body range request (exactly 44 bytes).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectBodyRequest {
    pub proposal_id: [u8; 32],
    pub offset: u64,
    pub max_bytes: u32,
}

impl DirectBodyRequest {
    /// Exact wire length (44 bytes).
    pub const WIRE_BYTES: usize = DIRECT_BODY_REQUEST_WIRE_BYTES;

    pub fn protocol_decode(reader: &mut ProtocolReader<'_>) -> ProtocolResult<Self> {
        let proposal_id = reader.read_bytes_32()?;
        let offset = reader.read_u64()?;
        let max_bytes = reader.read_u32()?;
        if max_bytes == 0 || max_bytes > DIRECT_REQUEST_MAX_BYTES {
            return Err(ProtocolError::LengthLimit {
                what: "DirectBodyRequest.max_bytes",
                got: max_bytes as u64,
                max: DIRECT_REQUEST_MAX_BYTES as u64,
            });
        }
        Ok(Self {
            proposal_id,
            offset,
            max_bytes,
        })
    }

    pub fn decode_exact(bytes: &[u8]) -> ProtocolResult<Self> {
        decode_exact(bytes, Self::protocol_decode)
    }
}

impl ProtocolEncode for DirectBodyRequest {
    fn protocol_encode(&self, out: &mut Vec<u8>) {
        write_fixed(out, &self.proposal_id);
        write_u64(out, self.offset);
        write_u32(out, self.max_bytes);
    }
}

/// Direct proposal-body range response (`53 + data.len()` bytes).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectBodyResponse {
    pub offset: u64,
    pub data: Vec<u8>,
    pub eof: bool,
    pub body_len: u64,
    pub body_hash: [u8; 32],
}

impl DirectBodyResponse {
    pub fn protocol_decode(reader: &mut ProtocolReader<'_>) -> ProtocolResult<Self> {
        let offset = reader.read_u64()?;
        let data = reader.read_bytes_u32("DirectBodyResponse.data", DIRECT_REQUEST_MAX_BYTES)?;
        let eof = reader.read_bool()?;
        let body_len = reader.read_u64()?;
        if body_len > MAX_PROPOSAL_BODY_BYTES as u64 {
            return Err(ProtocolError::LengthLimit {
                what: "DirectBodyResponse.body_len",
                got: body_len,
                max: MAX_PROPOSAL_BODY_BYTES as u64,
            });
        }
        let body_hash = reader.read_bytes_32()?;
        Ok(Self {
            offset,
            data,
            eof,
            body_len,
            body_hash,
        })
    }

    pub fn decode_exact(bytes: &[u8]) -> ProtocolResult<Self> {
        decode_exact(bytes, Self::protocol_decode)
    }
}

impl ProtocolEncode for DirectBodyResponse {
    fn protocol_encode(&self, out: &mut Vec<u8>) {
        write_u64(out, self.offset);
        write_bytes_u32(out, &self.data).expect("DirectBodyResponse data length fits u32");
        write_bool(out, self.eof);
        write_u64(out, self.body_len);
        write_fixed(out, &self.body_hash);
    }
}

/// EndCap forward stream header (exactly 60 bytes):
/// `chain_id(8) + realm_id(4) + checkpoint_id(8) + end_cap_id(32)
/// + end_cap_input_len(4) + proof_len(4)`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct EndCapForwardHeader {
    pub chain_id: u64,
    pub realm_id: u32,
    pub checkpoint_id: u64,
    pub end_cap_id: [u8; 32],
    pub end_cap_input_len: u32,
    pub proof_len: u32,
}

impl EndCapForwardHeader {
    /// Exact wire length (60 bytes).
    pub const WIRE_BYTES: usize = END_CAP_FORWARD_HEADER_WIRE_BYTES;

    pub fn protocol_decode(reader: &mut ProtocolReader<'_>) -> ProtocolResult<Self> {
        Ok(Self {
            chain_id: reader.read_u64()?,
            realm_id: reader.read_u32()?,
            checkpoint_id: reader.read_u64()?,
            end_cap_id: reader.read_bytes_32()?,
            end_cap_input_len: reader.read_u32()?,
            proof_len: reader.read_u32()?,
        })
    }

    pub fn decode_exact(bytes: &[u8]) -> ProtocolResult<Self> {
        decode_exact(bytes, Self::protocol_decode)
    }
}

impl ProtocolEncode for EndCapForwardHeader {
    fn protocol_encode(&self, out: &mut Vec<u8>) {
        write_u64(out, self.chain_id);
        write_u32(out, self.realm_id);
        write_u64(out, self.checkpoint_id);
        write_fixed(out, &self.end_cap_id);
        write_u32(out, self.end_cap_input_len);
        write_u32(out, self.proof_len);
    }
}

/// `end_cap_id = SHA-256(protocol_encode(DOMAIN_END_CAP_FORWARD, chain_id,
///     realm_id, checkpoint_id, sha256(input), sha256(proof)))`.
pub fn compute_end_cap_id(
    chain_id: u64,
    realm_id: u32,
    checkpoint_id: u64,
    end_cap_input_hash: &[u8; 32],
    end_cap_proof_hash: &[u8; 32],
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(8 + 8 + 4 + 8 + 32 + 32);
    write_fixed(&mut buf, &DOMAIN_END_CAP_FORWARD);
    write_u64(&mut buf, chain_id);
    write_u32(&mut buf, realm_id);
    write_u64(&mut buf, checkpoint_id);
    write_fixed(&mut buf, end_cap_input_hash);
    write_fixed(&mut buf, end_cap_proof_hash);
    sha256(&buf)
}

/// Exact one-byte EndCap forward response: `accepted:bool`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct EndCapForwardResponse {
    accepted: bool,
}

impl EndCapForwardResponse {
    /// Exact wire length (1 byte).
    pub const WIRE_BYTES: usize = END_CAP_FORWARD_RESPONSE_WIRE_BYTES;

    pub const fn new(accepted: bool) -> Self {
        Self { accepted }
    }

    pub const fn is_accepted(&self) -> bool {
        self.accepted
    }

    pub fn protocol_decode(reader: &mut ProtocolReader<'_>) -> ProtocolResult<Self> {
        Ok(Self::new(reader.read_bool()?))
    }

    pub fn decode_exact(bytes: &[u8]) -> ProtocolResult<Self> {
        decode_exact(bytes, Self::protocol_decode)
    }
}

impl ProtocolEncode for EndCapForwardResponse {
    fn protocol_encode(&self, out: &mut Vec<u8>) {
        write_bool(out, self.accepted);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::bls::{aggregate_signatures, BlsSecretKey};
    use super::super::domains::{DOMAIN_END_CAP_FORWARD, DOMAIN_PROPOSAL};
    use super::super::codec::{sha256, validate_hash32_canonical, write_fixed, write_u16, write_u32, write_u64, GOLDILOCKS_MODULUS};
    use super::super::limits::{
        CERTIFICATE_WIRE_BYTES, DIRECT_BODY_REQUEST_WIRE_BYTES, DIRECT_REQUEST_MAX_BYTES,
        END_CAP_FORWARD_HEADER_WIRE_BYTES, MAX_BACKUP_BYTES, MAX_FINALIZER_OUTPUT_BYTES,
        MAX_FINALIZER_PROOF_BYTES, MAX_PROPOSAL_BODY_BYTES, MAX_PROPOSAL_CHUNK_BYTES,
        MAX_PROPOSAL_PARTS, PROPOSAL_WIRE_BYTES, VOTE_WIRE_BYTES,
    };

    use psy_core::constants::chain_id::PSY_CHAIN_ID_LOCAL_DEVNET as NETWORK_MAGIC;

    fn sample_proposal() -> Proposal {
        proposal_from_parts(
            NETWORK_MAGIC,
            2,
            99,
            3,
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            [0x44; 32],
            [0x55; 32],
        )
    }

    #[test]
    fn proposal_wire_size_and_identity() {
        let p = sample_proposal();
        let enc = p.protocol_encode_to_vec();
        assert_eq!(enc.len(), PROPOSAL_WIRE_BYTES);
        assert_eq!(enc.len(), 214);
        assert_eq!(&enc[..8], &NETWORK_MAGIC.to_le_bytes());
        assert!(Proposal::decode_exact(&enc[..210]).is_err());
        assert_eq!(p.proposal_id, p.compute_proposal_id());
        assert_eq!(Proposal::decode_exact(&enc).unwrap(), p);

        // proposal_id is the domain-prefixed SHA-256 of the fields sans proposal_id.
        let mut expected = Vec::new();
        write_fixed(&mut expected, &DOMAIN_PROPOSAL);
        write_u64(&mut expected, NETWORK_MAGIC);
        write_u32(&mut expected, 2);
        write_u64(&mut expected, 99);
        write_u16(&mut expected, 3);
        write_fixed(&mut expected, &[0x11; 32]);
        write_fixed(&mut expected, &[0x22; 32]);
        write_fixed(&mut expected, &[0x33; 32]);
        write_fixed(&mut expected, &[0x44; 32]);
        write_fixed(&mut expected, &[0x55; 32]);
        assert_eq!(p.proposal_id, sha256(&expected));
        let legacy = [&expected[..8], &0u32.to_le_bytes(), &expected[16..]].concat();
        assert_ne!(p.proposal_id, sha256(&legacy));

        let mut other = p.clone();
        other.backup_hash = [0x66; 32];
        assert_ne!(other.compute_proposal_id(), p.proposal_id);
        other = p.clone();
        other.chain_id ^= 1u64 << 32;
        assert_ne!(other.compute_proposal_id(), p.proposal_id);

        let mut trailing = enc;
        trailing.push(0);
        assert!(Proposal::decode_exact(&trailing).is_err());
        assert!(Proposal::decode_exact(&trailing[..trailing.len() - 2]).is_err());
    }

    #[test]
    fn end_cap_forward_header_wire_size() {
        let hdr = EndCapForwardHeader {
            chain_id: NETWORK_MAGIC,
            realm_id: 2,
            checkpoint_id: 3,
            end_cap_id: [7; 32],
            end_cap_input_len: 1000,
            proof_len: 2000,
        };
        let enc = hdr.protocol_encode_to_vec();
        assert_eq!(enc.len(), END_CAP_FORWARD_HEADER_WIRE_BYTES);
        assert_eq!(enc.len(), 60);
        assert_eq!(&enc[..8], &NETWORK_MAGIC.to_le_bytes());
        assert!(EndCapForwardHeader::decode_exact(&enc[..56]).is_err());
        assert_eq!(EndCapForwardHeader::decode_exact(&enc).unwrap(), hdr);
        let mut trailing = enc;
        trailing.push(0);
        assert!(EndCapForwardHeader::decode_exact(&trailing).is_err());

        assert_eq!(EndCapForwardResponse::new(true).protocol_encode_to_vec(), vec![0x01]);
        assert_eq!(EndCapForwardResponse::new(false).protocol_encode_to_vec(), vec![0x00]);
        assert!(EndCapForwardResponse::new(true).is_accepted());
        assert!(!EndCapForwardResponse::new(false).is_accepted());
        assert!(EndCapForwardResponse::decode_exact(&[0x02]).is_err());
        assert!(EndCapForwardResponse::decode_exact(&[0x01, 0x00]).is_err());
    }

    #[test]
    fn proposal_body_sections_with_worker_tag() {
        let output = vec![0xAA; MAX_FINALIZER_OUTPUT_BYTES];
        let proof = vec![0xBB; 100];
        let state_updates = vec![0xCC; 200];
        let worker_tag = [0x42u8; 32];
        let body = encode_proposal_body(&output, &proof, &state_updates, &worker_tag).unwrap();
        assert_eq!(body.len(), 12 + 32 + MAX_FINALIZER_OUTPUT_BYTES + 100 + 200);
        assert_eq!(&body[0..4], &(MAX_FINALIZER_OUTPUT_BYTES as u32).to_le_bytes());
        assert_eq!(&body[4..4 + MAX_FINALIZER_OUTPUT_BYTES], output.as_slice());
        assert_eq!(&body[414..418], &100u32.to_le_bytes());
        assert_eq!(&body[418..518], proof.as_slice());
        assert_eq!(&body[518..522], &200u32.to_le_bytes());
        assert_eq!(&body[522..722], state_updates.as_slice());
        assert_eq!(&body[722..], &worker_tag);

        let (out2, proof2, state_updates2, tag2) = decode_proposal_body(&body).unwrap();
        assert_eq!(out2, output);
        assert_eq!(proof2, proof);
        assert_eq!(state_updates2, state_updates);
        assert_eq!(tag2, worker_tag);

        assert!(encode_proposal_body(&output[..MAX_FINALIZER_OUTPUT_BYTES - 1], &proof, &state_updates, &worker_tag).is_err());
        assert!(encode_proposal_body(&output, &vec![0u8; MAX_FINALIZER_PROOF_BYTES + 1], &state_updates, &worker_tag).is_err());
        assert!(encode_proposal_body(&output, &proof, &vec![0u8; MAX_BACKUP_BYTES + 1], &worker_tag).is_err());
        let mut trailing = body;
        trailing.push(0);
        assert!(decode_proposal_body(&trailing).is_err());
    }

    #[test]
    fn decode_proposal_body_rejects_noncanonical_worker_tag() {
        let output = vec![0xAA; MAX_FINALIZER_OUTPUT_BYTES];
        let proof = vec![0xBB; 8];
        let state_updates = vec![0xCC; 8];
        // Largest allowed canonical limb is one below the Goldilocks modulus.
        let mut max_limb_tag = [0u8; 32];
        max_limb_tag[24..32].copy_from_slice(&(GOLDILOCKS_MODULUS - 1).to_le_bytes());
        validate_hash32_canonical(&max_limb_tag).expect("modulus - 1 limb is canonical");
        let body = encode_proposal_body(&output, &proof, &state_updates, &max_limb_tag).unwrap();
        let (_, _, _, tag) = decode_proposal_body(&body).unwrap();
        assert_eq!(tag, max_limb_tag);

        let mut noncanonical_tag = max_limb_tag;
        noncanonical_tag[24..32].copy_from_slice(&GOLDILOCKS_MODULUS.to_le_bytes());
        let bad_body = encode_proposal_body(&output, &proof, &state_updates, &noncanonical_tag).unwrap();
        assert!(matches!(
            decode_proposal_body(&bad_body),
            Err(ProtocolError::NonCanonicalField { .. })
        ));
    }

    #[test]
    fn proposal_body_maximum_includes_worker_tag() {
        let output = vec![0xAA; MAX_FINALIZER_OUTPUT_BYTES];
        let proof = vec![0xBB; MAX_FINALIZER_PROOF_BYTES];
        let state_updates = vec![0xCC; MAX_BACKUP_BYTES];
        let worker_tag = [0x42u8; 32];
        let body = encode_proposal_body(&output, &proof, &state_updates, &worker_tag).unwrap();
        assert_eq!(body.len(), MAX_PROPOSAL_BODY_BYTES);
        let (out2, proof2, state_updates2, tag2) = decode_proposal_body(&body).unwrap();
        assert_eq!(out2.len(), MAX_FINALIZER_OUTPUT_BYTES);
        assert_eq!(proof2.len(), MAX_FINALIZER_PROOF_BYTES);
        assert_eq!(state_updates2.len(), MAX_BACKUP_BYTES);
        assert_eq!(tag2, worker_tag);
    }

    #[test]
    fn bitmap_helpers() {
        let mut bitmap = [0u8; 32];
        for s in [0u16, 1, 7, 8, 63, 64, 127, 128, 255] {
            assert!(!bitmap_get(&bitmap, s));
            bitmap_set(&mut bitmap, s);
            assert!(bitmap_get(&bitmap, s));
        }
        // 255 is bit 7 of the final byte; byte 0 carries bits 0, 1, and 7.
        assert_eq!(bitmap[31], 0x80);
        assert_eq!(bitmap[0], 0x83);
        // sub-IDs at or above 256 are out of range and ignored.
        bitmap_set(&mut bitmap, 256);
        assert!(!bitmap_get(&bitmap, 256));
        assert!(!bitmap_get(&bitmap, 300));
    }

    #[test]
    fn vote_and_certificate_wire_sizes() {
        let p = sample_proposal();
        let msg = vote_message(NETWORK_MAGIC, 2, &p.validator_tree_root, &p.proposal_id);
        assert_eq!(&msg[..8], b"PSYVOT01");
        assert_eq!(msg.len(), 8 + 8 + 4 + 32 + 32);
        assert_eq!(&msg[8..16], &NETWORK_MAGIC.to_le_bytes());

        let sks: Vec<_> = (1u8..=3)
            .map(|s| BlsSecretKey::key_gen(&[s; 32]).unwrap())
            .collect();
        let sigs: Vec<_> = sks.iter().map(|sk| sk.sign_vote(&msg)).collect();
        let agg = aggregate_signatures(&sigs).unwrap();
        let pks: Vec<_> = sks.iter().map(|sk| sk.public_key()).collect();
        agg.fast_aggregate_verify(&msg, &pks).unwrap();

        let vote = Vote::new(p.proposal_id, 5, sigs[0]);
        let venc = vote.protocol_encode_to_vec();
        assert_eq!(venc.len(), VOTE_WIRE_BYTES);
        assert_eq!(venc.len(), 130);
        Vote::decode_exact(&venc)
            .unwrap()
            .signature
            .verify_vote(&msg, &pks[0])
            .unwrap();

        let mut bitmap = [0u8; 32];
        bitmap_set(&mut bitmap, 1);
        bitmap_set(&mut bitmap, 2);
        bitmap_set(&mut bitmap, 4);
        let cert = Certificate {
            chain_id: NETWORK_MAGIC,
            realm_id: 2,
            validator_tree_root: p.validator_tree_root,
            proposal_id: p.proposal_id,
            signer_bitmap: bitmap,
            aggregated_signature: agg,
        };
        let cenc = cert.protocol_encode_to_vec();
        assert_eq!(cenc.len(), CERTIFICATE_WIRE_BYTES);
        assert_eq!(cenc.len(), 204);
        assert_eq!(&cenc[..8], &NETWORK_MAGIC.to_le_bytes());
        assert!(Certificate::decode_exact(&cenc[..200]).is_err());
        let mut trailing = cenc.clone();
        trailing.push(0);
        assert!(Certificate::decode_exact(&trailing).is_err());
        let dec = Certificate::decode_exact(&cenc).unwrap();
        assert_eq!(dec, cert);
        assert_eq!(dec.popcount(), 3);
        assert_eq!(dec.signer_sub_ids(), vec![1, 2, 4]);
        assert_eq!(dec.vote_message(), msg);
        let mut other = dec;
        other.chain_id ^= 1u64 << 32;
        assert!(other.aggregated_signature.fast_aggregate_verify(&other.vote_message(), &pks).is_err());
    }

    #[test]
    fn proposal_part_strict_decode() {
        let p = sample_proposal();
        let start = ProposalPart::Start {
            proposal: p.clone(),
            total_parts: 2,
            body_len: 100,
        };
        let enc = start.protocol_encode_to_vec();
        assert_eq!(enc[0], ProposalPart::TAG_START);
        assert_eq!(enc.len(), 1 + PROPOSAL_WIRE_BYTES + 4 + 8);
        assert_eq!(ProposalPart::decode_exact(&enc).unwrap(), start);

        // total_parts / body_len bounds are enforced before allocation.
        let zero_parts = ProposalPart::Start {
            proposal: p.clone(),
            total_parts: 0,
            body_len: 100,
        };
        assert!(ProposalPart::decode_exact(&zero_parts.protocol_encode_to_vec()).is_err());
        let too_many = ProposalPart::Start {
            proposal: p.clone(),
            total_parts: MAX_PROPOSAL_PARTS + 1,
            body_len: 100,
        };
        assert!(ProposalPart::decode_exact(&too_many.protocol_encode_to_vec()).is_err());
        let zero_len = ProposalPart::Start {
            proposal: p.clone(),
            total_parts: 1,
            body_len: 0,
        };
        assert!(ProposalPart::decode_exact(&zero_len.protocol_encode_to_vec()).is_err());
        let too_big = ProposalPart::Start {
            proposal: p.clone(),
            total_parts: 1,
            body_len: MAX_PROPOSAL_BODY_BYTES as u64 + 1,
        };
        assert!(ProposalPart::decode_exact(&too_big.protocol_encode_to_vec()).is_err());

        let chunk = ProposalPart::Chunk {
            proposal_id: p.proposal_id,
            offset: 0,
            data: vec![7u8; 16],
        };
        let cenc = chunk.protocol_encode_to_vec();
        assert_eq!(cenc[0], ProposalPart::TAG_CHUNK);
        assert_eq!(ProposalPart::decode_exact(&cenc).unwrap(), chunk);

        let empty = ProposalPart::Chunk {
            proposal_id: p.proposal_id,
            offset: 0,
            data: vec![],
        };
        assert!(ProposalPart::decode_exact(&empty.protocol_encode_to_vec()).is_err());
        // Oversized chunk data: hand-craft the wire bytes (encoding an
        // over-limit struct is a sender-side invariant violation).
        let mut big = ProposalPart::Chunk {
            proposal_id: p.proposal_id,
            offset: 0,
            data: vec![1u8; MAX_PROPOSAL_CHUNK_BYTES],
        }
        .protocol_encode_to_vec();
        big.extend_from_slice(&[2u8]);
        let declared_len = (MAX_PROPOSAL_CHUNK_BYTES + 1) as u32;
        big[41..45].copy_from_slice(&declared_len.to_le_bytes());
        assert!(ProposalPart::decode_exact(&big).is_err());
        assert!(matches!(
            ProposalPart::decode_exact(&[2u8]).unwrap_err(),
            ProtocolError::UnknownTag {
                ty: "ProposalPart",
                tag: 2
            }
        ));
    }

    #[test]
    fn direct_body_roundtrip() {
        let p = sample_proposal();
        let req = DirectBodyRequest {
            proposal_id: p.proposal_id,
            offset: 0,
            max_bytes: DIRECT_REQUEST_MAX_BYTES,
        };
        let enc = req.protocol_encode_to_vec();
        assert_eq!(enc.len(), DIRECT_BODY_REQUEST_WIRE_BYTES);
        assert_eq!(enc.len(), 44);
        assert_eq!(DirectBodyRequest::decode_exact(&enc).unwrap(), req);
        let zero_max = DirectBodyRequest {
            proposal_id: p.proposal_id,
            offset: 0,
            max_bytes: 0,
        };
        assert!(DirectBodyRequest::decode_exact(&zero_max.protocol_encode_to_vec()).is_err());
        let over_max = DirectBodyRequest {
            proposal_id: p.proposal_id,
            offset: 0,
            max_bytes: DIRECT_REQUEST_MAX_BYTES + 1,
        };
        assert!(DirectBodyRequest::decode_exact(&over_max.protocol_encode_to_vec()).is_err());

        let resp = DirectBodyResponse {
            offset: 0,
            data: vec![9u8; 32],
            eof: true,
            body_len: 32,
            body_hash: [2; 32],
        };
        let renc = resp.protocol_encode_to_vec();
        assert_eq!(renc.len(), 53 + 32);
        assert_eq!(DirectBodyResponse::decode_exact(&renc).unwrap(), resp);

    }

    #[test]
    fn end_cap_id_domain_hash() {
        let input = b"end cap input bytes";
        let proof = b"proof bytes";
        let input_hash = sha256(input);
        let proof_hash = sha256(proof);
        let id = compute_end_cap_id(NETWORK_MAGIC, 2, 3, &input_hash, &proof_hash);
        let mut expected = Vec::new();
        write_fixed(&mut expected, &DOMAIN_END_CAP_FORWARD);
        write_u64(&mut expected, NETWORK_MAGIC);
        write_u32(&mut expected, 2);
        write_u64(&mut expected, 3);
        write_fixed(&mut expected, &input_hash);
        write_fixed(&mut expected, &proof_hash);
        assert_eq!(id, sha256(&expected));
        let legacy = [&expected[..8], &0u32.to_le_bytes(), &expected[16..]].concat();
        assert_ne!(id, sha256(&legacy));
        assert_ne!(id, compute_end_cap_id(NETWORK_MAGIC, 2, 4, &input_hash, &proof_hash));
        assert_ne!(id, compute_end_cap_id(NETWORK_MAGIC, 2, 3, &proof_hash, &input_hash));
        assert_ne!(id, compute_end_cap_id(NETWORK_MAGIC ^ (1u64 << 32), 2, 3, &input_hash, &proof_hash));
    }
}
