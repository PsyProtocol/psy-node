use thiserror::Error;

/// Protocol decode / validation failure.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("unexpected end of input while reading {context}")]
    UnexpectedEof { context: &'static str },

    #[error("trailing bytes remain after decoding ({remaining} byte(s))")]
    TrailingBytes { remaining: usize },

    #[error("invalid boolean encoding 0x{value:02x}")]
    InvalidBool { value: u8 },

    #[error("unknown enum tag {tag} for {ty}")]
    UnknownTag { ty: &'static str, tag: u8 },

    #[error("{what} length {got} exceeds maximum {max}")]
    LengthLimit {
        what: &'static str,
        got: u64,
        max: u64,
    },

    #[error("{what} has invalid length {got}, expected {expected}")]
    InvalidLength {
        what: &'static str,
        got: usize,
        expected: usize,
    },

    #[error("invalid NodeId: {reason}")]
    InvalidNodeId { reason: &'static str },

    #[error("field element limb 0x{value:016x} is not reduced Goldilocks")]
    NonCanonicalField { value: u64 },

    #[error("invalid BLS public key")]
    InvalidBlsPublicKey,

    #[error("invalid BLS signature")]
    InvalidBlsSignature,

    #[error("invalid BLS secret key")]
    InvalidBlsSecretKey,

    #[error("BLS proof of possession verification failed")]
    InvalidProofOfPossession,

    #[error("BLS aggregate verification failed")]
    BlsVerifyFailed,

    #[error("empty BLS aggregate input")]
    EmptyAggregate,

    #[error("integer overflow while computing {context}")]
    Overflow { context: &'static str },

    #[error("{0}")]
    Message(&'static str),
}

impl ProtocolError {
    pub fn unexpected_eof(context: &'static str) -> Self {
        Self::UnexpectedEof { context }
    }
}

/// Convenience result alias for protocol operations.
pub type ProtocolResult<T> = Result<T, ProtocolError>;
