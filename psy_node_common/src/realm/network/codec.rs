//! libp2p `request_response::Codec` implementations for the slim Realm P2P
//! protocols.
//!
//! Three request/response protocols are wired:
//! - `/psy/realm/proposal-body/1` — bounded proposal body range exchange.
//! - `/psy/realm/end-cap-forward/1` — EndCap forward stream (56-byte header
//!   followed by `end_cap_input_len` input bytes and `proof_len` proof bytes).
//! - `/psy/realm/finalize-submit/1` — validator-to-coordinator finalize
//!   submission (`output[410] || Proposal[218] || Certificate[208] || proof`).
//!
//! All codecs are memory-backed and use only `futures` AsyncRead/AsyncWrite
//! (no tempfile / tokio-fs backing) so the slim port stays free of the heavy
//! durable-inbox machinery.

use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response::Codec;
use libp2p::swarm::StreamProtocol;
use psy_data::p2p::{
    Certificate, DirectBodyRequest, DirectBodyResponse, EndCapForwardHeader,
    EndCapForwardResponse, Proposal, ProtocolEncode, RealmFinalizeOutputBytes,
    RealmFinalizeSubmitRequest, RealmFinalizeSubmitResponse, CERTIFICATE_WIRE_BYTES,
    DIRECT_BODY_REQUEST_WIRE_BYTES, DIRECT_REQUEST_MAX_BYTES, END_CAP_FORWARD_HEADER_WIRE_BYTES,
    END_CAP_FORWARD_RESPONSE_WIRE_BYTES, MAX_END_CAP_FORWARD_BYTES, MAX_FINALIZER_OUTPUT_BYTES,
    MAX_FINALIZER_PROOF_BYTES, PROPOSAL_WIRE_BYTES, REALM_FINALIZE_SUBMIT_PREFIX_WIRE_BYTES,
    REALM_FINALIZE_SUBMIT_RESPONSE_WIRE_BYTES,
};
use std::{fmt, io};

pub const DIRECT_BODY_PROTOCOL_ID: &str = "/psy/realm/proposal-body/1";
pub const END_CAP_FORWARD_PROTOCOL_ID: &str = "/psy/realm/end-cap-forward/1";
pub const REALM_FINALIZE_SUBMIT_PROTOCOL_ID: &str = "/psy/realm/finalize-submit/1";

const DIRECT_BODY_RESPONSE_OVERHEAD: usize = 53;

// ---------------------------------------------------------------------------
// Realm finalize-submit
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
pub struct RealmFinalizeSubmitCodec;

#[async_trait]
impl Codec for RealmFinalizeSubmitCodec {
    type Protocol = StreamProtocol;
    type Request = RealmFinalizeSubmitRequest;
    type Response = RealmFinalizeSubmitResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut prefix = [0u8; REALM_FINALIZE_SUBMIT_PREFIX_WIRE_BYTES];
        io.read_exact(&mut prefix).await?;
        let output_end = MAX_FINALIZER_OUTPUT_BYTES;
        let proposal_end = output_end + PROPOSAL_WIRE_BYTES;
        let output =
            RealmFinalizeOutputBytes::decode_exact(&prefix[..output_end]).map_err(invalid_data)?;
        let proposal = Proposal::decode_exact(&prefix[output_end..proposal_end])
            .map_err(invalid_data)?;
        let certificate = Certificate::decode_exact(&prefix[proposal_end..])
            .map_err(invalid_data)?;
        let proof_len = read_u32_len(io, MAX_FINALIZER_PROOF_BYTES, "Realm finalize proof").await?;
        if proof_len == 0 {
            return Err(invalid_data("Realm finalize proof is empty"));
        }
        let proof = read_exact_alloc(io, proof_len, "Realm finalize proof").await?;
        let mut trailing = [0u8; 1];
        if io.read(&mut trailing).await? != 0 {
            return Err(invalid_data("trailing bytes after Realm finalize-submit request"));
        }
        RealmFinalizeSubmitRequest::new(output, proposal, certificate, proof).map_err(invalid_data)
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let bytes = read_to_end_bounded(io, REALM_FINALIZE_SUBMIT_RESPONSE_WIRE_BYTES).await?;
        RealmFinalizeSubmitResponse::decode_exact(&bytes).map_err(invalid_data)
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let (output, proposal, certificate, proof) = request.into_parts();
        let mut prefix = Vec::with_capacity(REALM_FINALIZE_SUBMIT_PREFIX_WIRE_BYTES);
        output.protocol_encode(&mut prefix);
        proposal.protocol_encode(&mut prefix);
        certificate.protocol_encode(&mut prefix);
        if prefix.len() != REALM_FINALIZE_SUBMIT_PREFIX_WIRE_BYTES {
            return Err(invalid_data("invalid Realm finalize-submit prefix length"));
        }
        io.write_all(&prefix).await?;
        io.write_all(&(proof.len() as u32).to_le_bytes()).await?;
        io.write_all(&proof).await?;
        io.close().await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = response.protocol_encode_to_vec();
        if bytes.len() != REALM_FINALIZE_SUBMIT_RESPONSE_WIRE_BYTES {
            return Err(invalid_data("invalid Realm finalize-submit response length"));
        }
        write_all_and_close(io, &bytes).await
    }
}

// ---------------------------------------------------------------------------
// Direct proposal-body range
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
pub struct DirectBodyCodec;

#[async_trait]
impl Codec for DirectBodyCodec {
    type Protocol = StreamProtocol;
    type Request = DirectBodyRequest;
    type Response = DirectBodyResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let bytes = read_to_end_bounded(io, DIRECT_BODY_REQUEST_WIRE_BYTES).await?;
        DirectBodyRequest::decode_exact(&bytes).map_err(invalid_data)
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let max = DIRECT_BODY_RESPONSE_OVERHEAD + DIRECT_REQUEST_MAX_BYTES as usize;
        let bytes = read_to_end_bounded(io, max).await?;
        DirectBodyResponse::decode_exact(&bytes).map_err(invalid_data)
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = request.protocol_encode_to_vec();
        if bytes.len() != DIRECT_BODY_REQUEST_WIRE_BYTES {
            return Err(invalid_data("invalid direct-body request length"));
        }
        write_all_and_close(io, &bytes).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        if response.data.len() > DIRECT_REQUEST_MAX_BYTES as usize {
            return Err(invalid_data("direct-body response exceeds maximum"));
        }
        write_all_and_close(io, &response.protocol_encode_to_vec()).await
    }
}

// ---------------------------------------------------------------------------
// EndCap forward
// ---------------------------------------------------------------------------

/// Memory-backed EndCap forward request: the 56-byte header plus the raw
/// input and proof bytes. The codec validates header/payload length
/// consistency and the global `MAX_END_CAP_FORWARD_BYTES` bound before
/// accepting a request.
#[derive(Clone)]
pub struct EndCapForwardRequest {
    pub header: EndCapForwardHeader,
    pub input: Vec<u8>,
    pub proof: Vec<u8>,
}

impl EndCapForwardRequest {
    pub fn new(
        header: EndCapForwardHeader,
        input: Vec<u8>,
        proof: Vec<u8>,
    ) -> io::Result<Self> {
        validate_end_cap_forward_lengths(&header, input.len(), proof.len())?;
        Ok(Self { header, input, proof })
    }

    pub fn encoded_len(&self) -> usize {
        END_CAP_FORWARD_HEADER_WIRE_BYTES + self.input.len() + self.proof.len()
    }
}

impl fmt::Debug for EndCapForwardRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EndCapForwardRequest")
            .field("header", &self.header)
            .field("input_len", &self.input.len())
            .field("proof_len", &self.proof.len())
            .finish()
    }
}

#[derive(Clone, Default)]
pub struct EndCapForwardCodec;

#[async_trait]
impl Codec for EndCapForwardCodec {
    type Protocol = StreamProtocol;
    type Request = EndCapForwardRequest;
    type Response = EndCapForwardResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut header_bytes = [0u8; END_CAP_FORWARD_HEADER_WIRE_BYTES];
        io.read_exact(&mut header_bytes).await?;
        let header = EndCapForwardHeader::decode_exact(&header_bytes).map_err(invalid_data)?;
        let input_len = header.end_cap_input_len as usize;
        let proof_len = header.proof_len as usize;
        validate_end_cap_forward_lengths(&header, input_len, proof_len)?;
        let input = read_exact_alloc(io, input_len, "EndCap forward input").await?;
        let proof = read_exact_alloc(io, proof_len, "EndCap forward proof").await?;
        let mut trailing = [0u8; 1];
        if io.read(&mut trailing).await? != 0 {
            return Err(invalid_data("trailing bytes after EndCap forward payload"));
        }
        Ok(EndCapForwardRequest { header, input, proof })
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let bytes = read_to_end_bounded(io, END_CAP_FORWARD_RESPONSE_WIRE_BYTES).await?;
        EndCapForwardResponse::decode_exact(&bytes).map_err(invalid_data)
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        validate_end_cap_forward_lengths(
            &request.header,
            request.input.len(),
            request.proof.len(),
        )?;
        io.write_all(&request.header.protocol_encode_to_vec()).await?;
        io.write_all(&request.input).await?;
        io.write_all(&request.proof).await?;
        io.close().await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = response.protocol_encode_to_vec();
        if bytes.len() != END_CAP_FORWARD_RESPONSE_WIRE_BYTES {
            return Err(invalid_data("invalid EndCap forward response length"));
        }
        write_all_and_close(io, &bytes).await
    }
}

fn validate_end_cap_forward_lengths(
    header: &EndCapForwardHeader,
    actual_input_len: usize,
    actual_proof_len: usize,
) -> io::Result<()> {
    if header.end_cap_input_len as usize != actual_input_len
        || header.proof_len as usize != actual_proof_len
    {
        return Err(invalid_data(
            "EndCap forward header length does not match payload",
        ));
    }
    let payload_len = actual_input_len
        .checked_add(actual_proof_len)
        .ok_or_else(|| invalid_data("EndCap forward payload length overflow"))?;
    let total = END_CAP_FORWARD_HEADER_WIRE_BYTES
        .checked_add(payload_len)
        .ok_or_else(|| invalid_data("EndCap forward length overflow"))?;
    if total > MAX_END_CAP_FORWARD_BYTES {
        return Err(invalid_data("EndCap forward exceeds maximum"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Shared bounded read/write helpers
// ---------------------------------------------------------------------------

async fn read_u32_len<T>(io: &mut T, max: usize, what: &'static str) -> io::Result<usize>
where
    T: AsyncRead + Unpin + Send,
{
    let mut bytes = [0u8; 4];
    io.read_exact(&mut bytes).await?;
    let length = u32::from_le_bytes(bytes) as usize;
    if length > max {
        return Err(invalid_data(format!("{what} length exceeds {max}")));
    }
    Ok(length)
}

async fn read_exact_alloc<T>(io: &mut T, length: usize, what: &'static str) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| io::Error::new(io::ErrorKind::OutOfMemory, format!("{what} allocation failed")))?;
    bytes.resize(length, 0);
    if length > 0 {
        io.read_exact(&mut bytes).await?;
    }
    Ok(bytes)
}

async fn read_to_end_bounded<T>(io: &mut T, max: usize) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut bytes = Vec::new();
    io.take((max as u64).saturating_add(1)).read_to_end(&mut bytes).await?;
    if bytes.len() > max {
        return Err(invalid_data("protocol frame exceeds maximum"));
    }
    Ok(bytes)
}

async fn write_all_and_close<T>(io: &mut T, bytes: &[u8]) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
{
    io.write_all(bytes).await?;
    io.close().await
}

fn invalid_data(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}