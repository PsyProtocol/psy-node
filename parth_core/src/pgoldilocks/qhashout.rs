use std::{fmt::Display, str::FromStr};

use anyhow::ensure;
use ts_rs::TS;
use crate::{crypto::hash::traits::{FromU64x4, HashTo4Felts, RandomHash, ToU64x4, ZeroableHash}, data::{hash::hash256::Hash256, serializable::{QPDSerializable, QPDSerializableFixed}}, felt::{QFelt64, ToQFelts}, protocol::core_types::QHashBase, utils::QPGenRandom};
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, Sample},
    }, hash::hash_types::{HashOut, HashOutTarget, RichField}, iop::target::Target, plonk::config::GenericHashOut
};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::serde_as;


#[derive(Clone, Debug, PartialEq, Eq, Copy, Hash, TS)]
#[pderive::non_serde_serialize]
#[ts(export, concrete(F = GoldilocksField))]
pub struct QHashOut<F: Field>(pub HashOut<F>);

impl<F: QFelt64 + Field> PartialOrd for QHashOut<F> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let self_felts = [
            self.0.elements[0].to_u64_value(),
            self.0.elements[1].to_u64_value(),
            self.0.elements[2].to_u64_value(),
            self.0.elements[3].to_u64_value(),
        ];
        let other_felts = [
            other.0.elements[0].to_u64_value(),
            other.0.elements[1].to_u64_value(),
            other.0.elements[2].to_u64_value(),
            other.0.elements[3].to_u64_value(),
        ];
        self_felts.partial_cmp(&other_felts)
    }
}
impl<F: QFelt64 + Field> Ord for QHashOut<F> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let self_felts = [
            self.0.elements[0].to_u64_value(),
            self.0.elements[1].to_u64_value(),
            self.0.elements[2].to_u64_value(),
            self.0.elements[3].to_u64_value(),
        ];
        let other_felts = [
            other.0.elements[0].to_u64_value(),
            other.0.elements[1].to_u64_value(),
            other.0.elements[2].to_u64_value(),
            other.0.elements[3].to_u64_value(),
        ];
        self_felts.cmp(&other_felts)
    }
}

pub type GoldilocksHashOut = QHashOut<GoldilocksField>;

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct SerializableHashOut(#[serde_as(as = "serde_with::hex::Hex")] pub Vec<u8>);

impl<F: RichField> Serialize for QHashOut<F> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = GenericHashOut::to_bytes(&self.0);
        bytes.reverse();
        let raw = SerializableHashOut(bytes);

        raw.serialize(serializer)
    }
}

impl<'de, F: RichField> Deserialize<'de> for QHashOut<F> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = SerializableHashOut::deserialize(deserializer)?;
        let mut bytes = raw.0;
        if bytes.len() > 32 {
            return Err(serde::de::Error::custom("too long hexadecimal sequence"));
        }
        bytes.reverse();
        bytes.resize(32, 0);

        Ok(QHashOut(<HashOut<F> as GenericHashOut<F>>::from_bytes(
            &bytes,
        )))
    }
}

impl<F: RichField> QPDSerializableFixed for QHashOut<F> {
    fn get_fixed_size() -> usize {
        32
    }
}
impl<F: RichField> QPDSerializable for QHashOut<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.to_le_bytes().to_vec())
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        Self::from_le_bytes(bytes)
    }
}
impl<F: Field> Default for QHashOut<F> {
    fn default() -> Self {
        QHashOut(HashOut::ZERO)
    }
}

impl<F: Field> From<QHashOut<F>> for HashOut<F> {
    fn from(value: QHashOut<F>) -> Self {
        value.0
    }
}
impl<F: Field> From<HashOut<F>> for QHashOut<F> {
    fn from(value: HashOut<F>) -> Self {
        QHashOut(value)
    }
}

impl<F: RichField> TryFrom<&[F]> for QHashOut<F> {
    type Error = anyhow::Error;

    fn try_from(elements: &[F]) -> Result<Self, Self::Error> {
        ensure!(elements.len() == 4);
        Ok(Self(HashOut {
            elements: elements.try_into().unwrap(),
        }))
    }
}

impl<F: RichField> TryFrom<&[u64; 4]> for QHashOut<F> {
    type Error = anyhow::Error;

    fn try_from(elements: &[u64; 4]) -> Result<Self, Self::Error> {
        Ok(Self(HashOut {
            elements: [
                F::from_noncanonical_u64(elements[0]),
                F::from_noncanonical_u64(elements[1]),
                F::from_noncanonical_u64(elements[2]),
                F::from_noncanonical_u64(elements[3]),
            ],
        }))
    }
}
impl<F: RichField> Display for QHashOut<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_string(self)
            .map(|v| v.replace('\"', ""))
            .unwrap();

        write!(f, "{}", s)
    }
}

impl<F: RichField> FromStr for QHashOut<F> {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let json = "\"".to_string() + s + "\"";

        serde_json::from_str(&json)
    }
}

impl<F: RichField> GenericHashOut<F> for QHashOut<F> {
    fn to_bytes(&self) -> Vec<u8> {
        GenericHashOut::to_bytes(&self.0)
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        QHashOut(<HashOut<F> as GenericHashOut<F>>::from_bytes(bytes))
    }

    fn to_vec(&self) -> Vec<F> {
        self.0.to_vec()
    }
}
impl<F: RichField> QHashOut<F> {
    pub const ZERO: Self = Self(HashOut::<F>::ZERO);

    pub fn from_string_or_panic(s: &str) -> Self {
        let json = "\"".to_string() + s + "\"";

        serde_json::from_str(&json).unwrap()
    }
    pub fn rand() -> Self {
        Self(HashOut::rand())
    }
    pub fn from_values(a: u64, b: u64, c: u64, d: u64) -> Self {
        Self(HashOut {
            elements: [
                F::from_noncanonical_u64(a),
                F::from_noncanonical_u64(b),
                F::from_noncanonical_u64(c),
                F::from_noncanonical_u64(d),
            ],
        })
    }
    pub fn from_felt_slice(slice: &[F]) -> Self {
        Self(HashOut {
            elements: [slice[0], slice[1], slice[2], slice[3]],
        })
    }
    pub fn from_le_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        ensure!(bytes.len() == 32, "Invalid byte length for HashOut");
        let elements_0 = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let elements_1 = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let elements_2 = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        let elements_3 = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
        Ok(Self::from_values(elements_0, elements_1, elements_2, elements_3))
    }
    pub fn to_le_bytes(&self) -> [u8; 32] {
        let mut result = [0u8; 32];
        result[0..8].copy_from_slice(&self.0.elements[0].to_canonical_u64().to_le_bytes());
        result[8..16].copy_from_slice(&self.0.elements[1].to_canonical_u64().to_le_bytes());
        result[16..24].copy_from_slice(&self.0.elements[2].to_canonical_u64().to_le_bytes());
        result[24..32].copy_from_slice(&self.0.elements[3].to_canonical_u64().to_le_bytes());
        result
    }
    pub fn from_hash256_le(hash: Hash256) -> Self {
        let u64_x4 = hash.to_le_u64_x4();
        Self(HashOut {
            elements: [
                F::from_noncanonical_u64(u64_x4[0]),
                F::from_noncanonical_u64(u64_x4[1]),
                F::from_noncanonical_u64(u64_x4[2]),
                F::from_noncanonical_u64(u64_x4[3]),
            ],
        })
    }
    pub fn to_string_le(&self) -> String {
        hex::encode(self.to_le_bytes())
    }
}


impl<F: RichField> RandomHash for QHashOut<F> {
    fn rand_hash() -> Self {
        Self::rand()
    }
}

impl<F: RichField> QPGenRandom for QHashOut<F> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self::rand()
    }
}


impl<F: Field> ToQFelts<F> for HashOut<F> {
    fn to_qfelts(&self) -> Vec<F> {
        self.elements.to_vec()
    }

    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != 4 {
            panic!("Invalid number of elements for HashOut");
        }
        Self {
            elements: [felts[0], felts[1], felts[2], felts[3]],
        }
    }
}
impl<F: RichField> ToQFelts<F> for QHashOut<F> {
    fn to_qfelts(&self) -> Vec<F> {
        self.0.elements.to_vec()
    }
    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != 4 {
            panic!("Invalid number of elements for QHashOut");
        }
        QHashOut(
            HashOut {elements: [felts[0], felts[1], felts[2], felts[3]]}
        )
    }
}
impl ToQFelts<Target> for HashOutTarget {
    fn to_qfelts(&self) -> Vec<Target> {
        self.elements.to_vec()
    }
    fn from_qfelts(felts: &[Target]) -> Self {
        if felts.len() != 4 {
            panic!("Invalid number of elements for QHashOut");
        }
        HashOutTarget {elements: [felts[0], felts[1], felts[2], felts[3]]}
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::goldilocks_field::GoldilocksField as F;
    #[test]
    fn test_qhashout_serde_str() {
        let h = QHashOut::<F>::from_values(1, 2, 3, 4);
        let s = serde_json::to_string(&h).unwrap();
        println!("Serialized: {}", s);
        let h2: QHashOut<F> = serde_json::from_str(&s).unwrap();
        assert_eq!(h, h2);
    }
    #[test]
    fn test_qhashout_byte_order(){
        let h = QHashOut::<F>::from_values(0x0102030405060708, 0x1112131415161718, 0x2122232425262728, 0x3132333435363738);
        let known_le_serialization: [u8; 32] = [
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
            0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
            0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21,
            0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31,
        ];
        let bytes = h.to_le_bytes();
        assert_eq!(bytes, known_le_serialization);
        let bincode_bytes = bincode::serialize(&h).unwrap();
        assert_eq!(bincode_bytes, known_le_serialization);
        let h2: QHashOut<F> = bincode::deserialize(&bincode_bytes).unwrap();
        assert_eq!(h, h2);


    }
}
impl<F: RichField> ZeroableHash for QHashOut<F> {
    fn get_zero_value() -> Self {
        Self::ZERO
    }
}
impl<F: RichField> ToU64x4 for QHashOut<F> {
    fn to_u64x4(&self) -> [u64; 4] {
        [
            self.0.elements[0].to_canonical_u64(),
            self.0.elements[1].to_canonical_u64(),
            self.0.elements[2].to_canonical_u64(),
            self.0.elements[3].to_canonical_u64(),
        ]
    }
}
impl<F: RichField> HashTo4Felts<F> for QHashOut<F> {
    fn to_4_felts(&self) -> [F; 4] {
        self.0.elements
    }
    
    fn from_4_felts(felts: [F; 4]) -> Self {
        QHashOut(HashOut { elements: felts })
    }
}
impl<F: RichField> FromU64x4 for QHashOut<F> {
    fn from_u64x4(data: [u64; 4]) -> Self {
        Self::from_values(data[0], data[1], data[2], data[3])
    }
}
impl<F: RichField + QFelt64> QHashBase for QHashOut<F> {}
