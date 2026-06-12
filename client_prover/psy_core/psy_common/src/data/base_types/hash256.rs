use std::{fmt::Display, ops};

use hex::FromHexError;
use kvq::traits::KVQSerializable;
use plonky2::{field::secp256k1_scalar::Secp256K1Scalar, hash::hash_types::RichField};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use ts_rs::TS;

use crate::data::qhashout::QHashOut;

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone, Copy, Debug, Eq, Hash, PartialOrd, Ord, TS)]
#[ts(export)]
pub struct Hash256(
    #[serde_as(as = "serde_with::hex::Hex")]
    #[ts(as = "String")]
    pub [u8; 32],
);
impl Default for Hash256 {
    fn default() -> Self {
        Self([0u8; 32])
    }
}

impl ops::BitXor<Hash256> for Hash256 {
    type Output = Hash256;

    fn bitxor(self, rhs: Hash256) -> Hash256 {
        Hash256(core::array::from_fn(|i| self.0[i] ^ rhs.0[i]))
    }
}

impl Hash256 {
    pub const ZERO: Self = Self([0u8; 32]);
    pub fn from_hex_string(s: &str) -> Result<Self, FromHexError> {
        let bytes = hex::decode(s)?;
        assert_eq!(bytes.len(), 32);
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(Self(array))
    }
    pub fn to_hex_string(&self) -> String {
        hex::encode(&self.0)
    }
    pub fn rand() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Hash256(bytes)
    }
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&x| x == 0)
    }
    pub fn reversed(&self) -> Self {
        Hash256(core::array::from_fn(|i| self.0[31 - i]))
    }
    pub fn to_le_u64_x4(&self) -> [u64; 4] {
        [
            u64::from_le_bytes([self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6], self.0[7]]),
            u64::from_le_bytes([
                self.0[8], self.0[9], self.0[10], self.0[11], self.0[12], self.0[13], self.0[14], self.0[15],
            ]),
            u64::from_le_bytes([
                self.0[16], self.0[17], self.0[18], self.0[19], self.0[20], self.0[21], self.0[22], self.0[23],
            ]),
            u64::from_le_bytes([
                self.0[24], self.0[25], self.0[26], self.0[27], self.0[28], self.0[29], self.0[30], self.0[31],
            ]),
        ]
    }
}

impl From<Hash256> for Secp256K1Scalar {
    fn from(value: Hash256) -> Self {
        let mut data = value.0;
        data.reverse();
        let u64_result: [u64; 4] = core::array::from_fn(|i| {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&data[i * 8..(i + 1) * 8]);
            u64::from_le_bytes(bytes)
        });
        let scalar = Secp256K1Scalar(u64_result);
        scalar
    }
}

impl Display for Hash256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}
impl TryFrom<&str> for Hash256 {
    type Error = FromHexError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Hash256::from_hex_string(value)
    }
}
impl TryFrom<String> for Hash256 {
    type Error = FromHexError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Hash256::from_hex_string(&value)
    }
}

impl KVQSerializable for Hash256 {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.0.to_vec())
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 32 {
            anyhow::bail!("expected 32 bytes for deserializing Hash256, got {} bytes", bytes.len());
        }
        let mut inner_data = [0u8; 32];
        inner_data.copy_from_slice(bytes);
        Ok(Hash256(inner_data))
    }
}

impl<F: RichField> From<QHashOut<F>> for Hash256 {
    fn from(value: QHashOut<F>) -> Self {
        let mut data = [0u8; 32];
        for i in 0..4 {
            let u64 = value.0.elements[i].to_canonical_u64();
            data[i * 8..(i + 1) * 8].copy_from_slice(&u64.to_le_bytes());
        }
        data.reverse();
        Self(data)
    }
}

impl<F: RichField> From<Hash256> for QHashOut<F> {
    fn from(value: Hash256) -> Self {
        let mut data = value.0;
        data.reverse();

        let mut elements = [F::ZERO; 4];
        for i in 0..4 {
            let bytes = &data[i * 8..(i + 1) * 8];
            let u64_val = u64::from_le_bytes(bytes.try_into().unwrap());
            elements[i] = F::from_noncanonical_u64(u64_val);
        }
        QHashOut(plonky2::hash::hash_types::HashOut { elements })
    }
}

#[cfg(test)]
mod tests {
    use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};
    use serde_json;

    use super::*;
    use crate::data::qhashout::QHashOut;

    #[test]
    fn test_qhashout_hash256_conversion_consistency() {
        let original_elements = [
            GoldilocksField::from_canonical_u64(0x1234567890abcdef),
            GoldilocksField::from_canonical_u64(0xfedcba0987654321),
            GoldilocksField::from_canonical_u64(0x1122334455667788),
            GoldilocksField::from_canonical_u64(0x8877665544332211),
        ];
        let original_qhashout = QHashOut(plonky2::hash::hash_types::HashOut { elements: original_elements });

        let json_str = serde_json::to_string(&original_qhashout).unwrap();
        println!("QHashOut JSON: {}", json_str);
        let qhashout_from_json: QHashOut<GoldilocksField> = serde_json::from_str(&json_str).unwrap();
        let array1 = qhashout_from_json.0.elements;

        let hash256: Hash256 = original_qhashout.into();
        let hex_str = hash256.to_hex_string();
        println!("Hash256 hex: {}", hex_str);
        let qhashout_from_hash256: QHashOut<GoldilocksField> = hash256.into();
        let array2 = qhashout_from_hash256.0.elements;

        let hex_from_json = json_str.trim_matches('"');
        let hash256_from_hex = Hash256::from_hex_string(hex_from_json).unwrap();
        let qhashout_from_hex: QHashOut<GoldilocksField> = hash256_from_hex.into();
        let array3 = qhashout_from_hex.0.elements;

        println!("Original elements: {:?}", original_elements);
        println!("From JSON: {:?}", array1);
        println!("From Hash256 conversion: {:?}", array2);
        println!("From hex string: {:?}", array3);

        assert_eq!(array1, array2, "JSON deserialization and Hash256 conversion should yield same result");
        assert_eq!(array1, array3, "JSON deserialization and direct hex parsing should yield same result");
        assert_eq!(array2, array3, "Hash256 conversion and direct hex parsing should yield same result");
        assert_eq!(original_elements, array1, "Conversion result should equal original data");
    }

    #[test]
    fn test_round_trip_conversion() {
        let original = QHashOut(plonky2::hash::hash_types::HashOut {
            elements: [
                GoldilocksField::from_canonical_u64(0x0123456789abcdef),
                GoldilocksField::from_canonical_u64(0xfedcba9876543210),
                GoldilocksField::from_canonical_u64(0xaabbccddeeff0011),
                GoldilocksField::from_canonical_u64(0x1100ffeeddccbbaa),
            ],
        });

        let hash256: Hash256 = original.into();
        let back_to_qhashout: QHashOut<GoldilocksField> = hash256.into();

        assert_eq!(
            original.0.elements, back_to_qhashout.0.elements,
            "Round-trip conversion should preserve data"
        );
    }

    #[test]
    fn debug_secp_constants() {
        let old_sk_hex = "17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a";
        let old_sig_hash_hex = "83955402ec7f375d1d6e8f3bf59753fe0af1e7c62bb4b662716a2524d3e2d186";

        let sk_json = format!("\"{}\"", old_sk_hex);
        let sig_hash_json = format!("\"{}\"", old_sig_hash_hex);

        let sk_qhashout: QHashOut<GoldilocksField> = serde_json::from_str(&sk_json).unwrap();
        let sig_hash_qhashout: QHashOut<GoldilocksField> = serde_json::from_str(&sig_hash_json).unwrap();

        let sk_hash256_new: Hash256 = sk_qhashout.into();
        let sig_hash_hash256_new: Hash256 = sig_hash_qhashout.into();

        let sk_hash256_old = Hash256::from_hex_string(old_sk_hex).unwrap();
        let sig_hash_hash256_old = Hash256::from_hex_string(old_sig_hash_hex).unwrap();

        println!("=== SK Analysis ===");
        println!("QHashOut elements: {:?}", sk_qhashout.0.elements);
        println!("OLD Hash256 bytes: {:?}", &sk_hash256_old.0[..8]);
        println!("NEW Hash256 bytes: {:?}", &sk_hash256_new.0[..8]);
        println!("OLD sk hex: {}", old_sk_hex);
        println!("NEW sk hex: {}", sk_hash256_new.to_hex_string());

        let new_sk_hex_reversed = {
            let mut bytes = sk_hash256_old.0;
            bytes.reverse();
            hex::encode(&bytes)
        };
        println!("Suggested NEW sk hex: {}", new_sk_hex_reversed);

        println!("=== Sig Hash Analysis ===");
        println!("OLD sig_hash hex: {}", old_sig_hash_hex);
        println!("NEW sig_hash hex: {}", sig_hash_hash256_new.to_hex_string());

        let new_sig_hash_hex_reversed = {
            let mut bytes = sig_hash_hash256_old.0;
            bytes.reverse();
            hex::encode(&bytes)
        };
        println!("Suggested NEW sig_hash hex: {}", new_sig_hash_hex_reversed);
    }

    #[test]
    fn generate_secp_test_data() {
        use k256::ecdsa::{
            signature::hazmat::{PrehashSigner, PrehashVerifier},
            SigningKey,
        };

        let sk_hex = "5aac24884c203b2aafa07063f464d67fbb4e41c6677fc8a70cbe8e66c275c917";
        let sig_hash_hex = "86d1e2d324256a7162b6b42bc6e7f10afe5397f53b8f6e1d5d377fec02549583";

        let sk_hash256 = Hash256::from_hex_string(sk_hex).unwrap();
        let sig_hash_hash256 = Hash256::from_hex_string(sig_hash_hex).unwrap();

        let key_pair = SigningKey::from_slice(&sk_hash256.0).unwrap();
        let pk = key_pair.verifying_key();

        let signature: k256::ecdsa::Signature = key_pair.sign_prehash(&sig_hash_hash256.0).unwrap();

        let verification_result = pk.verify_prehash(&sig_hash_hash256.0, &signature);

        println!("SK hex: {}", sk_hex);
        println!("Sig hash hex: {}", sig_hash_hex);
        println!("Public key: {:?}", pk.to_encoded_point(false).to_bytes());
        println!("Signature r: {:?}", signature.r().to_bytes());
        println!("Signature s: {:?}", signature.s().to_bytes());
        println!("Verification result: {:?}", verification_result);

        assert!(verification_result.is_ok(), "Signature verification should pass");
    }
}
