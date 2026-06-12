#![cfg(not(target_arch = "wasm32"))]

use thiserror::Error;

#[derive(Error, Debug)]
pub enum WalletError {
    #[error("Failed to parse keystore")]
    ParseKeystoreError,

    #[error("Invalid seed")]
    InvalidSeed,

    #[error("Invalid password")]
    InvalidPassword,

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Secp256k1 error: {0}")]
    Secp256k1Error(#[from] secp256k1::Error),

    #[error("Hex decode error: {0}")]
    HexError(#[from] hex::FromHexError),

    #[error("Encryption/Decryption failed")]
    CryptoError,
}
