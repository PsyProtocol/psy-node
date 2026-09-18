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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn fixed_errors_have_actionable_messages() {
        assert_eq!(WalletError::ParseKeystoreError.to_string(), "Failed to parse keystore");
        assert_eq!(WalletError::InvalidSeed.to_string(), "Invalid seed");
        assert_eq!(WalletError::InvalidPassword.to_string(), "Invalid password");
        assert_eq!(WalletError::CryptoError.to_string(), "Encryption/Decryption failed");
    }

    #[test]
    fn source_errors_are_preserved_in_display_output() {
        let io = WalletError::from(std::io::Error::new(std::io::ErrorKind::NotFound, "missing wallet"));
        assert!(io.to_string().contains("missing wallet"));

        let json = WalletError::from(serde_json::from_str::<serde_json::Value>("{").unwrap_err());
        assert!(json.to_string().starts_with("Serialization error:"));

        let secp = WalletError::from(secp256k1::SecretKey::from_slice(&[]).unwrap_err());
        assert!(secp.to_string().starts_with("Secp256k1 error:"));

        let hex = WalletError::from(hex::decode("zz").unwrap_err());
        assert!(hex.to_string().starts_with("Hex decode error:"));
    }
}
